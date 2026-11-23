//! Safe, hardened Git subprocess interface.
//!
//! # Module Contract & Representation Invariants
//!
//! - **Meaning of `GitRepo`:** Handle to an existing SHA-1 Git repository accessed through
//!   a verified executable `real_git` (never our own wrapper script), plus its `.git/shallow`
//!   boundary set `shallow` and persistent `git cat-file --batch` streams (`batch` and `batch_check`).
//! - **Invariant `I_repo(repo)`:**
//!   1. `is_executable_non_wrapper(&repo.real_git)` holds (canonical absolute path).
//!   2. The repository's `--show-object-format` was explicitly returned and equaled `"sha1"` at `open()`.
//!   3. Every subprocess spawned via `repo` (including `open()`) carries `--no-replace-objects`,
//!      `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_NO_LAZY_FETCH=1`.
//!   4. `repo.batch` and `repo.batch_check` sit at exact response boundaries; on any frame/I/O
//!      error, the stream is immediately reset to `None`.
//!   5. Large blobs are streamed in 64 KiB chunks via `hash_blob_streaming` rather than allocating
//!      multi-gigabyte buffers in RAM, while non-blob objects (`commit`, `tree`, `tag`) enforce a
//!      strict 64 MiB frame cap (`MAX_METADATA_OBJECT_BYTES`).

use crate::cache::{Dig, Oid};
use crate::protocol::ContextKeys;
use blake3_servil_core::Mode;
use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

pub const MAX_METADATA_OBJECT_BYTES: usize = 64 << 20; // 64 MiB cap for commit/tree/tag objects

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

pub const WRAPPER_MARKER: &[u8] = b"# git-buttress transparent git wrapper";

/// Locate the real stock `git` executable on the system, skipping any
/// `git-buttress` wrapper script that may sit earlier on `$PATH`.
pub fn resolve_real_git() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("GIT_BUTTRESS_REAL_GIT") {
        let p = PathBuf::from(&explicit);
        if is_executable_file(&p) && !is_our_wrapper(&p) {
            return Ok(fs::canonicalize(&p).unwrap_or(p));
        }
    }
    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            let candidate = dir.join("git");
            if is_executable_file(&candidate) && !is_our_wrapper(&candidate) {
                return Ok(fs::canonicalize(&candidate).unwrap_or(candidate));
            }
        }
    }
    for fallback in ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"] {
        let p = PathBuf::from(fallback);
        if is_executable_file(&p) && !is_our_wrapper(&p) {
            return Ok(fs::canonicalize(&p).unwrap_or(p));
        }
    }
    Err("could not locate real `git` executable on PATH".into())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Byte-level wrapper marker check (never fails open on non-UTF-8 binary files).
pub fn is_our_wrapper(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 256];
    let Ok(n) = f.read(&mut head) else {
        return false;
    };
    head[..n]
        .windows(WRAPPER_MARKER.len())
        .any(|w| w == WRAPPER_MARKER)
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
    unsafe { String::from_utf8_unchecked(s) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreErrorKind {
    /// Object is absent in a shallow/partial clone (`missing`).
    Missing,
    /// Repository / subprocess / corrupt-pack / size-limit operational error.
    CorruptOrIo,
}

#[derive(Clone, Debug)]
pub struct StoreError {
    pub kind: StoreErrorKind,
    pub message: String,
}

impl StoreError {
    pub fn io(msg: impl Into<String>) -> Self {
        Self {
            kind: StoreErrorKind::CorruptOrIo,
            message: msg.into(),
        }
    }
}

/// Abstract read-only object source so unit/adversarial tests can override
/// arbitrary objects in memory to simulate SHA1DC collisions!
pub trait ObjectStore {
    fn has_object(&mut self, oid: &Oid) -> Result<bool, StoreError>;
    fn object_info(&mut self, oid: &Oid) -> Result<Option<(ObjKind, u64)>, StoreError> {
        let Some((kind, raw)) = self.read_object(oid)? else {
            return Ok(None);
        };
        Ok(Some((kind, raw.len() as u64)))
    }
    fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, StoreError>;
    fn hash_blob(&mut self, oid: &Oid, keys: &ContextKeys) -> Result<Option<(ObjKind, Dig)>, StoreError> {
        let Some((kind, raw)) = self.read_object(oid)? else {
            return Ok(None);
        };
        if kind != ObjKind::Blob {
            return Ok(Some((kind, [0u8; 32])));
        }
        Ok(Some((ObjKind::Blob, keys.hash_file(&raw))))
    }
    fn shallow_commits(&self) -> &HashSet<Oid>;
}

pub struct GitRepo {
    real_git: PathBuf,
    cwd: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
    global_git_args: Vec<OsString>,
    shallow: HashSet<Oid>,
    batch: Option<BatchCatFile>,
    batch_check: Option<BatchCatFile>,
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl GitRepo {
    pub fn open(cwd: Option<&Path>) -> Result<Self, String> {
        Self::open_with_global_args(cwd, &[])
    }

    pub fn open_with_global_args(cwd: Option<&Path>, global_args: &[OsString]) -> Result<Self, String> {
        let real_git = resolve_real_git()?;
        let cwd = match cwd {
            Some(p) => p.to_path_buf(),
            None => env::current_dir().map_err(|e| format!("current_dir: {e}"))?,
        };
        let mut c = Command::new(&real_git);
        c.current_dir(&cwd);
        c.args(global_args);
        c.args([
            "--no-replace-objects",
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
            "--show-object-format",
        ]);
        c.env("GIT_NO_REPLACE_OBJECTS", "1");
        c.env("GIT_NO_LAZY_FETCH", "1");
        c.env("GIT_OPTIONAL_LOCKS", "0");

        let out = c.output().map_err(|e| format!("failed to run git: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        // Parse lines cleanly requiring all 3 outputs explicitly!
        let lines: Vec<&[u8]> = out
            .stdout
            .strip_suffix(b"\n")
            .unwrap_or(&out.stdout)
            .split(|&b| b == b'\n')
            .collect();
        if lines.len() < 3 {
            return Err("unexpected rev-parse output during repository discovery".into());
        }
        let obj_fmt = std::str::from_utf8(lines[lines.len() - 1])
            .map_err(|_| "non-UTF-8 object format")?
            .trim();
        if obj_fmt != "sha1" {
            return Err(format!(
                "repository uses object-format={obj_fmt:?}; git-buttress v1 targets SHA-1 Git repositories"
            ));
        }
        let gd_raw = bytes_to_pathbuf(lines[0])?;
        let cd_raw = bytes_to_pathbuf(lines[1])?;
        let git_dir = fs::canonicalize(&gd_raw).unwrap_or(gd_raw);
        let common_dir = fs::canonicalize(&cd_raw).unwrap_or(cd_raw);
        let shallow = load_shallow_set(&common_dir)?;

        Ok(Self {
            real_git,
            cwd,
            git_dir,
            common_dir,
            global_git_args: global_args.to_vec(),
            shallow,
            batch: None,
            batch_check: None,
        })
    }

    #[inline]
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    #[inline]
    pub fn common_dir(&self) -> &Path {
        &self.common_dir
    }

    #[inline]
    pub fn real_git(&self) -> &Path {
        &self.real_git
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(&self.real_git);
        c.current_dir(&self.cwd);
        c.args(&self.global_git_args);
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
        if let Some(bytes) = input
            && let Some(mut stdin) = child.stdin.take()
            && let Err(e) = stdin.write_all(bytes)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("write git stdin: {e}"));
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

    /// Resolve a revision without implicit cyclic-tag peeling hangs: uses `--end-of-options`!
    pub fn rev_parse(&self, rev: &str) -> Result<Oid, String> {
        let out = self.run(["rev-parse", "--verify", "--end-of-options", rev], None)?;
        hex_to_oid(out.stdout.trim_ascii())
    }

    pub fn try_rev_parse(&self, rev: &str) -> Option<Oid> {
        let out = self
            .cmd()
            .args(["rev-parse", "--verify", "--quiet", "--end-of-options", rev])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        hex_to_oid(out.stdout.trim_ascii()).ok()
    }

    /// Read a Git config string, distinguishing "key unset" (exit code 1) from corrupt config / I/O error!
    pub fn config_get_strict(&self, key: &str) -> Result<Option<String>, String> {
        let out = self
            .cmd()
            .args(["config", "--get", key])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .map_err(|e| format!("git config {key}: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_string())),
            Some(1) => Ok(None),
            _ => Err(format!(
                "git config {key} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }

    pub fn config_bool_strict(&self, key: &str, default: bool) -> Result<bool, String> {
        let out = self
            .cmd()
            .args(["config", "--bool", "--get", key])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .map_err(|e| format!("git config {key}: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("true")),
            Some(1) => Ok(default),
            _ => Err(format!(
                "invalid boolean config {key}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }

    fn ensure_batch(&mut self) -> Result<&mut BatchCatFile, StoreError> {
        if self.batch.is_none() {
            let mut child = self
                .cmd()
                .args(["cat-file", "--batch"])
                .env("GIT_OPTIONAL_LOCKS", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| StoreError::io(format!("spawn git cat-file --batch: {e}")))?;
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

    fn ensure_batch_check(&mut self) -> Result<&mut BatchCatFile, StoreError> {
        if self.batch_check.is_none() {
            let mut child = self
                .cmd()
                .args(["cat-file", "--batch-check"])
                .env("GIT_OPTIONAL_LOCKS", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| StoreError::io(format!("spawn git cat-file --batch-check: {e}")))?;
            let stdin = BufWriter::new(child.stdin.take().unwrap());
            let stdout = BufReader::with_capacity(64 * 1024, child.stdout.take().unwrap());
            self.batch_check = Some(BatchCatFile {
                child,
                stdin,
                stdout,
                line_buf: Vec::with_capacity(128),
            });
        }
        Ok(self.batch_check.as_mut().unwrap())
    }

    pub fn write_commit_object(&self, raw: &[u8]) -> Result<Oid, String> {
        let out = self.run(["hash-object", "-t", "commit", "-w", "--stdin"], Some(raw))?;
        hex_to_oid(out.stdout.trim_ascii())
    }

    fn object_info_inner(&mut self, oid: &Oid) -> Result<Option<(ObjKind, u64)>, StoreError> {
        let hex = to_hex(oid);
        let b = self.ensure_batch_check()?;
        b.stdin
            .write_all(hex.as_bytes())
            .and_then(|_| b.stdin.write_all(b"\n"))
            .and_then(|_| b.stdin.flush())
            .map_err(|e| StoreError::io(format!("cat-file --batch-check write: {e}")))?;
        b.line_buf.clear();
        let n = b
            .stdout
            .read_until(b'\n', &mut b.line_buf)
            .map_err(|e| StoreError::io(format!("cat-file --batch-check read: {e}")))?;
        if n == 0 {
            return Err(StoreError::io("git cat-file --batch-check closed unexpectedly"));
        }
        let header = b
            .line_buf
            .strip_suffix(b"\n")
            .ok_or_else(|| StoreError::io("cat-file --batch-check missing LF"))?;
        let parts: Vec<&[u8]> = header.split(|&c| c == b' ').collect();
        if parts.len() < 2 || parts[0] != hex.as_bytes() {
            return Err(StoreError::io("cat-file --batch-check echoed unexpected OID"));
        }
        if parts.len() == 2 && parts[1] == b"missing" {
            return Ok(None);
        }
        if parts.len() != 3 {
            return Err(StoreError::io("malformed cat-file --batch-check header"));
        }
        let kind = ObjKind::from_bytes(parts[1]).map_err(StoreError::io)?;
        let size: u64 = std::str::from_utf8(parts[2])
            .map_err(|_| StoreError::io("non-utf8 size in --batch-check"))?
            .parse()
            .map_err(|_| StoreError::io("invalid object size in --batch-check"))?;
        Ok(Some((kind, size)))
    }

    fn read_object_inner(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, StoreError> {
        let hex = to_hex(oid);
        let b = self.ensure_batch()?;
        b.stdin
            .write_all(hex.as_bytes())
            .and_then(|_| b.stdin.write_all(b"\n"))
            .and_then(|_| b.stdin.flush())
            .map_err(|e| StoreError::io(format!("cat-file write: {e}")))?;

        b.line_buf.clear();
        let n = b
            .stdout
            .read_until(b'\n', &mut b.line_buf)
            .map_err(|e| StoreError::io(format!("cat-file read header: {e}")))?;
        if n == 0 {
            return Err(StoreError::io("git cat-file --batch closed unexpectedly"));
        }
        let header = b
            .line_buf
            .strip_suffix(b"\n")
            .ok_or_else(|| StoreError::io("cat-file header missing LF"))?;
        let parts: Vec<&[u8]> = header.split(|&c| c == b' ').collect();
        if parts.len() < 2 || parts[0] != hex.as_bytes() {
            return Err(StoreError::io("cat-file echoed unexpected OID"));
        }
        if parts.len() == 2 && parts[1] == b"missing" {
            return Ok(None);
        }
        if parts.len() != 3 {
            return Err(StoreError::io("malformed cat-file header"));
        }
        let kind = ObjKind::from_bytes(parts[1]).map_err(StoreError::io)?;
        let size: usize = std::str::from_utf8(parts[2])
            .map_err(|_| StoreError::io("non-utf8 size"))?
            .parse()
            .map_err(|_| StoreError::io("invalid object size"))?;
        if size > MAX_METADATA_OBJECT_BYTES {
            return Err(StoreError::io(format!(
                "{} object {} exceeds {} MiB in-memory read cap ({size} bytes; blobs must use hash_blob)",
                kind.as_str(),
                hex,
                MAX_METADATA_OBJECT_BYTES >> 20
            )));
        }

        let mut payload = vec![0u8; size];
        b.stdout
            .read_exact(&mut payload)
            .map_err(|e| StoreError::io(format!("cat-file read payload: {e}")))?;
        let mut lf = [0u8; 1];
        b.stdout
            .read_exact(&mut lf)
            .map_err(|e| StoreError::io(format!("cat-file read trailing LF: {e}")))?;
        if lf[0] != b'\n' {
            return Err(StoreError::io("cat-file missing trailing LF"));
        }
        Ok(Some((kind, payload)))
    }

    fn hash_blob_streaming_inner(
        &mut self,
        oid: &Oid,
        keys: &ContextKeys,
    ) -> Result<Option<(ObjKind, Dig)>, StoreError> {
        let hex = to_hex(oid);
        let b = self.ensure_batch()?;
        b.stdin
            .write_all(hex.as_bytes())
            .and_then(|_| b.stdin.write_all(b"\n"))
            .and_then(|_| b.stdin.flush())
            .map_err(|e| StoreError::io(format!("cat-file write: {e}")))?;

        b.line_buf.clear();
        let n = b
            .stdout
            .read_until(b'\n', &mut b.line_buf)
            .map_err(|e| StoreError::io(format!("cat-file read header: {e}")))?;
        if n == 0 {
            return Err(StoreError::io("git cat-file --batch closed unexpectedly"));
        }
        let header = b
            .line_buf
            .strip_suffix(b"\n")
            .ok_or_else(|| StoreError::io("cat-file header missing LF"))?;
        let parts: Vec<&[u8]> = header.split(|&c| c == b' ').collect();
        if parts.len() < 2 || parts[0] != hex.as_bytes() {
            return Err(StoreError::io("cat-file echoed unexpected OID"));
        }
        if parts.len() == 2 && parts[1] == b"missing" {
            return Ok(None);
        }
        if parts.len() != 3 {
            return Err(StoreError::io("malformed cat-file header"));
        }
        let kind = ObjKind::from_bytes(parts[1]).map_err(StoreError::io)?;
        let size: u64 = std::str::from_utf8(parts[2])
            .map_err(|_| StoreError::io("non-utf8 size"))?
            .parse()
            .map_err(|_| StoreError::io("invalid object size"))?;

        // Drain exact `size` bytes in 64 KiB chunks into a streaming BLAKE3 Hasher!
        let mut hasher =
            blake3_servil_core::convenience::Hasher::new(Mode::DeriveKeyWith(&keys.file), Some(size));
        let mut buf = [0u8; 65536];
        let mut rem = size;
        while rem > 0 {
            let take = (rem.min(buf.len() as u64)) as usize;
            b.stdout
                .read_exact(&mut buf[..take])
                .map_err(|e| StoreError::io(format!("cat-file stream read: {e}")))?;
            if kind == ObjKind::Blob {
                hasher.update(&buf[..take]);
            }
            rem -= take as u64;
        }
        let mut lf = [0u8; 1];
        b.stdout
            .read_exact(&mut lf)
            .map_err(|e| StoreError::io(format!("cat-file read trailing LF: {e}")))?;
        if lf[0] != b'\n' {
            return Err(StoreError::io("cat-file missing trailing LF"));
        }
        if kind != ObjKind::Blob {
            return Ok(Some((kind, [0u8; 32])));
        }
        Ok(Some((ObjKind::Blob, *hasher.finalize().as_bytes())))
    }
}

impl ObjectStore for GitRepo {
    fn has_object(&mut self, oid: &Oid) -> Result<bool, StoreError> {
        Ok(self.object_info(oid)?.is_some())
    }

    fn object_info(&mut self, oid: &Oid) -> Result<Option<(ObjKind, u64)>, StoreError> {
        let res = self.object_info_inner(oid);
        if res.is_err() {
            self.batch_check = None;
        }
        res
    }

    fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, StoreError> {
        let res = self.read_object_inner(oid);
        if res.is_err() {
            self.batch = None;
        }
        res
    }

    fn hash_blob(&mut self, oid: &Oid, keys: &ContextKeys) -> Result<Option<(ObjKind, Dig)>, StoreError> {
        let res = self.hash_blob_streaming_inner(oid, keys);
        if res.is_err() {
            self.batch = None;
        }
        res
    }

    fn shallow_commits(&self) -> &HashSet<Oid> {
        &self.shallow
    }
}

fn bytes_to_pathbuf(bytes: &[u8]) -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        let s = std::str::from_utf8(bytes).map_err(|_| "non-UTF-8 path")?;
        Ok(PathBuf::from(s))
    }
}

/// Match upstream Git `shallow.c:setup_alternate_shallow`: `GIT_SHALLOW_FILE` replaces
/// `$GIT_COMMON_DIR/shallow` (and an empty `GIT_SHALLOW_FILE=""` means no shallow file!).
fn load_shallow_set(common_dir: &Path) -> Result<HashSet<Oid>, String> {
    let mut set = HashSet::new();
    let shallow_path = match env::var_os("GIT_SHALLOW_FILE") {
        Some(alt) if alt.is_empty() => return Ok(set),
        Some(alt) => PathBuf::from(alt),
        None => common_dir.join("shallow"),
    };
    let bytes = match fs::read(&shallow_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
        Err(e) => {
            return Err(format!(
                "failed to read shallow file {}: {e}",
                shallow_path.display()
            ));
        }
    };
    for line in bytes.split(|&b| b == b'\n') {
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        let oid = hex_to_oid(trimmed)
            .map_err(|e| format!("corrupt shallow file {}: {e}", shallow_path.display()))?;
        set.insert(oid);
    }
    Ok(set)
}
