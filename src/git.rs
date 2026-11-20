//! Safe, hardened Git subprocess interface.
//!
//! # Module Contract & Representation Invariants
//!
//! - **Meaning of `GitRepo`:** Handle to an existing SHA-1 Git repository rooted at
//!   `(git_dir, common_dir)` accessed through a verified real `git` binary `real_git`
//!   (never our own wrapper script), plus its `.git/shallow` boundary set `shallow`
//!   and an optional persistent `git cat-file --batch` child `batch`.
//! - **Invariant `I(repo)`:**
//!   1. `repo.real_git` points to a non-wrapper executable (`!is_our_wrapper(&repo.real_git)`).
//!   2. The repository's `--show-object-format` was verified to equal `"sha1"` at `open()`.
//!   3. Every subprocess spawned via `repo.cmd()` or `ensure_batch()` carries
//!      `--no-replace-objects`, `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_NO_LAZY_FETCH=1`,
//!      so `refs/replace/*` grafts are ignored and partial clones fail fast as missing
//!      objects instead of hanging on network fetches.
//!   4. `repo.batch == Some(b)` iff `b` is at a clean request/response frame boundary
//!      on `git cat-file --batch` stdout. If any read or parse error ever occurs inside
//!      `read_object`, `self.batch` is immediately dropped (`None`) so a subsequent call
//!      cannot read desynchronized bytes from the stream!

use crate::cache::Oid;
use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ObjKind {
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        match b {
            b"blob" => Ok(Self::Blob),
            b"tree" => Ok(Self::Tree),
            b"commit" => Ok(Self::Commit),
            b"tag" => Ok(Self::Tag),
            other => Err(format!(
                "unknown git object type: {:?}",
                String::from_utf8_lossy(other)
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

pub const WRAPPER_MARKER: &str = "# git-buttress transparent git wrapper";

/// Locate the real stock `git` executable on the system, skipping any
/// `git-buttress` wrapper script that may sit earlier on `$PATH`.
pub fn resolve_real_git() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("GIT_BUTTRESS_REAL_GIT") {
        let p = PathBuf::from(&explicit);
        if p.is_file() && !is_our_wrapper(&p) {
            return Ok(p);
        }
    }
    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            let candidate = dir.join("git");
            if candidate.is_file() && !is_our_wrapper(&candidate) {
                return Ok(candidate);
            }
        }
    }
    for fallback in ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"] {
        let p = PathBuf::from(fallback);
        if p.is_file() && !is_our_wrapper(&p) {
            return Ok(p);
        }
    }
    Err("could not locate real `git` executable on PATH".into())
}

pub fn is_our_wrapper(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 256];
    let Ok(n) = f.read(&mut head) else {
        return false;
    };
    if let Ok(s) = std::str::from_utf8(&head[..n]) {
        s.contains(WRAPPER_MARKER)
    } else {
        false
    }
}

pub fn hex_to_oid(hex: &[u8]) -> Result<Oid, String> {
    if hex.len() != 40 {
        return Err(format!("expected 40-hex SHA-1 OID, got len {}", hex.len()));
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let hi = hex_nibble(hex[2 * i])?;
        let lo = hex_nibble(hex[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

pub fn hex_to_32(hex: &[u8]) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64-hex digest, got len {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(hex[2 * i])?;
        let lo = hex_nibble(hex[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

#[inline]
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(format!("invalid lowercase hex byte: 0x{b:02x}")),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize]);
        s.push(LUT[(b & 0x0f) as usize]);
    }
    // Safe: LUT is ASCII
    unsafe { String::from_utf8_unchecked(s) }
}

/// Abstract read-only object source so unit/adversarial tests can override
/// arbitrary objects in memory to simulate SHA1DC collisions!
pub trait ObjectStore {
    fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String>;
    fn shallow_commits(&self) -> &HashSet<Oid>;
}

pub struct GitRepo {
    pub real_git: PathBuf,
    pub cwd: PathBuf,
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
    shallow: HashSet<Oid>,
    batch: Option<BatchCatFile>,
}

struct BatchCatFile {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    line_buf: Vec<u8>,
}

impl Drop for BatchCatFile {
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        // Closing stdin happens when fields drop; reap child cleanly:
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl GitRepo {
    /// Contract:
    /// - `requires`: `cwd` (or process current directory if `None`) is inside a SHA-1 Git repository or bare repo.
    /// - `ensures`: on `Ok(r)`, `I(r)` holds (`r.real_git` is not our wrapper, object-format is `"sha1"`,
    ///   and `r.shallow` contains all valid 40-hex OIDs in `r.common_dir/shallow`).
    ///   Returns `Err` if outside a Git repo, if `git` is missing, or if `--show-object-format != "sha1"`.
    /// - `writes`: nothing on disk.
    pub fn open(cwd: Option<&Path>) -> Result<Self, String> {
        let real_git = resolve_real_git()?;
        let cwd = match cwd {
            Some(p) => p.to_path_buf(),
            None => env::current_dir().map_err(|e| format!("current_dir: {e}"))?,
        };
        let out = Command::new(&real_git)
            .current_dir(&cwd)
            .args([
                "--no-replace-objects",
                "rev-parse",
                "--git-dir",
                "--git-common-dir",
                "--show-object-format",
            ])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .map_err(|e| format!("failed to run git: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        let gd_raw = PathBuf::from(lines.next().ok_or("missing --git-dir")?);
        let cd_raw = PathBuf::from(lines.next().ok_or("missing --git-common-dir")?);
        let obj_fmt = lines.next().unwrap_or("sha1").trim();
        if obj_fmt != "sha1" {
            return Err(format!(
                "repository uses object-format={obj_fmt:?}; git-buttress v1 targets SHA-1 Git repositories"
            ));
        }
        let git_dir = if gd_raw.is_absolute() { gd_raw } else { cwd.join(gd_raw) };
        let common_dir = if cd_raw.is_absolute() { cd_raw } else { cwd.join(cd_raw) };
        let shallow = load_shallow_set(&common_dir);

        Ok(Self {
            real_git,
            cwd,
            git_dir,
            common_dir,
            shallow,
            batch: None,
        })
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(&self.real_git);
        c.current_dir(&self.cwd);
        c.arg("--no-replace-objects");
        c.env("GIT_NO_REPLACE_OBJECTS", "1");
        c.env("GIT_NO_LAZY_FETCH", "1");
        c
    }

    pub fn run<I, S>(&self, args: I, input: Option<&[u8]>) -> Result<Output, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = self.cmd();
        let arg_vec: Vec<_> = args.into_iter().map(|s| s.as_ref().to_os_string()).collect();
        c.args(&arg_vec);
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        if input.is_some() {
            c.stdin(Stdio::piped());
        }
        let mut child = c.spawn().map_err(|e| format!("spawn git: {e}"))?;
        if let Some(bytes) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(bytes).map_err(|e| format!("write git stdin: {e}"))?;
            }
        }
        let out = child.wait_with_output().map_err(|e| format!("wait git: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if err.is_empty() {
                format!("git {:?} exited with {}", arg_vec, out.status)
            } else {
                err
            });
        }
        Ok(out)
    }

    pub fn rev_parse(&self, rev: &str) -> Result<Oid, String> {
        let out = self.run(["rev-parse", "--verify", rev], None)?;
        hex_to_oid(out.stdout.trim_ascii())
    }

    pub fn try_rev_parse(&self, rev: &str) -> Option<Oid> {
        let out = self
            .cmd()
            .args(["rev-parse", "--verify", "--quiet", rev])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        hex_to_oid(out.stdout.trim_ascii()).ok()
    }

    pub fn config_get(&self, key: &str) -> Option<String> {
        let out = self
            .cmd()
            .args(["config", "--get", key])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub fn config_bool(&self, key: &str, default: bool) -> bool {
        let out = self
            .cmd()
            .args(["config", "--bool", "--get", key])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output();
        match out {
            Ok(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).trim().eq_ignore_ascii_case("true")
            }
            _ => default,
        }
    }

    fn ensure_batch(&mut self) -> Result<&mut BatchCatFile, String> {
        if self.batch.is_none() {
            let mut child = self
                .cmd()
                .args(["cat-file", "--batch"])
                .env("GIT_OPTIONAL_LOCKS", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("spawn git cat-file --batch: {e}"))?;
            let stdin = BufWriter::new(child.stdin.take().unwrap());
            let stdout = BufReader::with_capacity(256 * 1024, child.stdout.take().unwrap());
            self.batch = Some(BatchCatFile {
                child,
                stdin,
                stdout,
                line_buf: Vec::with_capacity(128),
            });
        }
        Ok(self.batch.as_mut().unwrap())
    }

    pub fn write_commit_object(&self, raw: &[u8]) -> Result<Oid, String> {
        let out = self.run(["hash-object", "-t", "commit", "-w", "--stdin"], Some(raw))?;
        hex_to_oid(out.stdout.trim_ascii())
    }
}

impl ObjectStore for GitRepo {
    /// Contract:
    /// - `requires`: `I(self)`
    /// - `ensures`: preserves `I(self)` on BOTH `Ok` and `Err` (clearing `self.batch = None` on any stream/parse error).
    ///   Returns `Ok(Some((kind, raw)))` with the exact uncompressed Git object payload (without `<type> <size>\0`
    ///   loose header) when `oid` exists locally, `Ok(None)` when `oid` is absent locally, or `Err` on I/O failure.
    /// - `writes`: `self.batch` (spawns or advances `git cat-file --batch` stream; no repository state modified).
    fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String> {
        let res = self.read_object_inner(oid);
        if res.is_err() {
            // Frame-safety invariant: drop the batch child on ANY stream/parse error so a future
            // `read_object` call cannot read leftover payload bytes as a header line!
            self.batch = None;
        }
        res
    }

    fn shallow_commits(&self) -> &HashSet<Oid> {
        &self.shallow
    }
}

impl GitRepo {
    fn read_object_inner(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String> {
        let b = self.ensure_batch()?;
        let hex = to_hex(oid);
        b.stdin
            .write_all(hex.as_bytes())
            .and_then(|_| b.stdin.write_all(b"\n"))
            .and_then(|_| b.stdin.flush())
            .map_err(|e| format!("cat-file write: {e}"))?;

        b.line_buf.clear();
        let n = b
            .stdout
            .read_until(b'\n', &mut b.line_buf)
            .map_err(|e| format!("cat-file read header: {e}"))?;
        if n == 0 {
            return Err("git cat-file --batch closed unexpectedly".into());
        }
        let header = b.line_buf.trim_ascii_end();
        let mut parts = header.split(|&c| c == b' ');
        let _oid_part = parts.next().ok_or("malformed cat-file header")?;
        let second = parts.next().ok_or("malformed cat-file header")?;
        if second == b"missing" {
            return Ok(None);
        }
        let kind = ObjKind::from_bytes(second)?;
        let size_bytes = parts.next().ok_or("missing size in cat-file header")?;
        let size: usize = std::str::from_utf8(size_bytes)
            .map_err(|_| "non-utf8 size")?
            .parse()
            .map_err(|_| "invalid object size")?;

        let mut payload = vec![0u8; size];
        b.stdout
            .read_exact(&mut payload)
            .map_err(|e| format!("cat-file read payload: {e}"))?;
        let mut lf = [0u8; 1];
        b.stdout
            .read_exact(&mut lf)
            .map_err(|e| format!("cat-file read trailing LF: {e}"))?;
        if lf[0] != b'\n' {
            return Err("cat-file missing trailing LF".into());
        }
        Ok(Some((kind, payload)))
    }
}

fn load_shallow_set(common_dir: &Path) -> HashSet<Oid> {
    let mut set = HashSet::new();
    let Ok(text) = fs::read_to_string(common_dir.join("shallow")) else {
        return set;
    };
    for line in text.lines() {
        if let Ok(oid) = hex_to_oid(line.trim().as_bytes()) {
            set.insert(oid);
        }
    }
    set
}
