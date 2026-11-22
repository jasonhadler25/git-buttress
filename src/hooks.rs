//! Zero-friction setup (`enable` / `disable`), transparent `git` wrapper,
//! `post-commit` sealing, and `reference-transaction` tag minting + fetch/clone/pull verification.

use crate::cache::{Dig, DigestCache, Oid};
use crate::git::{
    GitRepo, ObjKind, ObjectStore, WRAPPER_MARKER, hex_to_oid, is_our_wrapper, resolve_real_git,
    to_hex,
};
use crate::protocol::{
    CheckOutcome, CommitClass, ContextKeys, Engine, VerifyError, VerifyErrorKind, ct_eq,
    parse_ref_embedded_b3, split_headers_body, strip_blake3_and_sig_headers,
    verify_target_with_engine,
};
use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingPolicy {
    Silent,
    Warn,
    Error,
}

impl MissingPolicy {
    pub fn from_repo(repo: &GitRepo, cli_override: Option<&str>) -> Result<Self, String> {
        let raw = match cli_override {
            Some(s) => s.to_string(),
            None => repo
                .config_get_strict("buttress.missing")?
                .unwrap_or_else(|| "silent".into()),
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "silent" | "ignore" | "none" => Ok(Self::Silent),
            "warn" | "warning" => Ok(Self::Warn),
            "error" | "strict" | "fail" => Ok(Self::Error),
            other => Err(format!(
                "invalid buttress.missing policy {other:?} (expected silent, warn, or error)"
            )),
        }
    }
}

/// Exclusive mode-0700 RAII temporary directory for safe SSH signing (`M7` fix).
struct PrivateTempDir(PathBuf);

impl PrivateTempDir {
    fn create(prefix: &str) -> Result<Self, String> {
        let base = env::temp_dir();
        let pid = std::process::id();
        for attempt in 0u64..1000 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let candidate = base.join(format!("{prefix}-{pid}-{nanos}-{attempt}"));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&candidate) {
                Ok(()) => return Ok(Self(candidate)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create private temp dir: {e}")),
            }
        }
        Err("could not allocate exclusive temporary directory".into())
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Sign a commit or tag payload using `explicit_key` (e.g. from `git commit -S<key>`) or the
/// repository's configured `user.signingkey`, validating non-empty signature armor
/// (`[GNUPG:] SIG_CREATED` for OpenPGP, SSH armor for SSH).
pub fn sign_payload(
    repo: &GitRepo,
    payload: &[u8],
    explicit_key: Option<&str>,
) -> Result<Vec<u8>, String> {
    let fmt = repo
        .config_get_strict("gpg.format")?
        .unwrap_or_else(|| "openpgp".into())
        .to_ascii_lowercase();
    let key = match explicit_key.filter(|k| !k.is_empty()) {
        Some(k) => Some(k.to_string()),
        None => repo.config_get_strict("user.signingkey")?,
    };

    if fmt == "ssh" {
        let Some(key_str) = key else {
            return Err("gpg.format=ssh requires user.signingkey to be set".into());
        };
        let key_path = expand_tilde(&key_str);
        let tmp = PrivateTempDir::create("git-buttress-sig")?;
        let payload_file = tmp.0.join("payload");
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&payload_file)
                .map_err(|e| format!("create payload file: {e}"))?;
            f.write_all(payload)
                .map_err(|e| format!("write payload: {e}"))?;
        }
        let ssh_prog = repo
            .config_get_strict("gpg.ssh.program")?
            .unwrap_or_else(|| "ssh-keygen".into());
        let out = Command::new(&ssh_prog)
            .arg("-Y")
            .arg("sign")
            .arg("-n")
            .arg("git")
            .arg("-f")
            .arg(&key_path)
            .arg(&payload_file)
            .output()
            .map_err(|e| format!("run {ssh_prog}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{ssh_prog} sign failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let sig_file = tmp.0.join("payload.sig");
        let mut sig = fs::read(&sig_file).map_err(|e| format!("read ssh signature: {e}"))?;
        while sig.last() == Some(&b'\n') || sig.last() == Some(&b'\r') {
            sig.pop();
        }
        if !sig.starts_with(b"-----BEGIN SSH SIGNATURE-----")
            || !sig.ends_with(b"-----END SSH SIGNATURE-----")
        {
            return Err("ssh-keygen produced malformed or empty SSH signature".into());
        }
        return Ok(sig);
    }

    if fmt == "openpgp" {
        let gpg_prog = match repo.config_get_strict("gpg.openpgp.program")? {
            Some(p) => p,
            None => repo
                .config_get_strict("gpg.program")?
                .unwrap_or_else(|| "gpg".into()),
        };
        let mut cmd = Command::new(&gpg_prog);
        cmd.args(["--status-fd=2", "-bsa"]);
        if let Some(ref k) = key {
            cmd.args(["-u", k]);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("run {gpg_prog}: {e}"))?;
        let mut stdin = child.stdin.take().unwrap();
        let payload_vec = payload.to_vec();
        // Write stdin on a helper thread so large payloads never deadlock against child stdout/stderr!
        let writer = std::thread::spawn(move || stdin.write_all(&payload_vec));
        let out = child.wait_with_output().map_err(|e| format!("wait {gpg_prog}: {e}"))?;
        let write_res = writer.join().map_err(|_| "gpg stdin thread panicked")?;
        if let Err(e) = write_res {
            return Err(format!("write gpg stdin: {e}"));
        }
        let stderr_str = String::from_utf8_lossy(&out.stderr);
        let saw_sig_created = stderr_str
            .lines()
            .any(|l| l.starts_with("[GNUPG:] SIG_CREATED "));
        if !out.status.success() || !saw_sig_created {
            return Err(format!(
                "{gpg_prog} failed to create OpenPGP signature: {}",
                stderr_str.trim()
            ));
        }
        let mut sig = out.stdout;
        while sig.last() == Some(&b'\n') || sig.last() == Some(&b'\r') {
            sig.pop();
        }
        if sig.is_empty() {
            return Err(format!("{gpg_prog} returned empty signature output"));
        }
        return Ok(sig);
    }

    Err(format!("unsupported gpg.format={fmt:?}"))
}

fn format_gpgsig_header(sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sig.len() + 32);
    for (i, line) in sig.split(|&c| c == b'\n').enumerate() {
        if i == 0 {
            out.extend_from_slice(b"gpgsig ");
        } else {
            out.push(b' ');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Ok(home) = env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(s)
}

/// Capture exact `HEAD` state (`Some(symbolic_ref_bytes)` or `None` if detached) + resolved OID
/// *before* hashing/signing so `seal_head` never updates the wrong branch on a concurrent checkout (`H5` fix).
fn read_head_state(repo: &GitRepo) -> Result<(Option<Vec<u8>>, Oid), String> {
    let sym_out = repo
        .cmd()
        .args(["symbolic-ref", "-q", "HEAD"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|e| format!("git symbolic-ref: {e}"))?;
    let sym_ref = match sym_out.status.code() {
        Some(0) => {
            let b = sym_out
                .stdout
                .strip_suffix(b"\n")
                .unwrap_or(&sym_out.stdout)
                .to_vec();
            if b.is_empty() {
                return Err("git symbolic-ref returned empty ref".into());
            }
            Some(b)
        }
        Some(1) => None, // Detached HEAD
        _ => {
            return Err(format!(
                "git symbolic-ref HEAD failed: {}",
                String::from_utf8_lossy(&sym_out.stderr).trim()
            ));
        }
    };
    let head_oid = match sym_ref {
        Some(ref r) => {
            let r_str = std::str::from_utf8(r).map_err(|_| "non-UTF-8 branch ref on HEAD")?;
            repo.rev_parse(r_str)?
        }
        None => repo.rev_parse("HEAD")?,
    };
    Ok((sym_ref, head_oid))
}

/// Seal `HEAD` safely (`H5`, `H6`, `H7` fixes):
/// - Captures `(sym_ref, head_oid)` up front before hashing/signing.
/// - Refuses to overwrite a commit whose existing `Sealed` headers contradict the store (`H6`).
/// - Honors `force_sign` and explicit `-S<key>` even if `HEAD` was already unsigned-`Sealed` (`H6`, `R2-H4`).
/// - When signing (`want_sign`), uses `Engine::new_verifier` (memory-only) AND verifies all
///   reachable ancestor seals on every parent BEFORE stamping a cryptographic signature (`R2-H4`).
/// - Re-reads and verifies the stored commit object from Git before advancing `HEAD` (`H7`).
pub fn seal_head(repo: &mut GitRepo, force_sign: bool, quiet: bool) -> Result<(Oid, Dig), String> {
    seal_head_with_key(repo, force_sign, None, quiet)
}

pub fn seal_head_with_key(
    repo: &mut GitRepo,
    force_sign: bool,
    explicit_sign_key: Option<&str>,
    quiet: bool,
) -> Result<(Oid, Dig), String> {
    let (sym_ref, head_oid) = read_head_state(repo)?;
    if env::var_os("GIT_BUTTRESS_INTERNAL_OP").as_deref() == Some(OsStr::new("seal-head")) {
        return Ok((head_oid, [0u8; 32]));
    }

    let keys = ContextKeys::new();

    // Peek commit class & signature state from fresh store first
    let head_pc = {
        let mut fresh_eng = Engine::new_verifier(repo, &keys);
        fresh_eng
            .load_commit(head_oid)
            .map_err(|e| format!("parse HEAD: {}", e.message))?
    };

    let want_sign = force_sign || explicit_sign_key.is_some() || head_pc.has_gpgsig;

    // If `HEAD` already carries `Sealed` lines, verify them against a fresh memory-only Engine FIRST!
    // If they contradict the store, NEVER silently overwrite tampering evidence (`H6` fix)!
    if let CommitClass::Sealed {
        expected_tree,
        ref expected_parents,
    } = head_pc.class
    {
        let mut verify_eng = Engine::new_verifier(repo, &keys);
        let actual_tree = verify_eng
            .digest_tree(head_pc.tree)
            .map_err(|e| format!("hash tree: {}", e.message))?;
        if !ct_eq(&actual_tree, &expected_tree) {
            return Err(format!(
                "HEAD ({}) carries a buttress-tree header that DOES NOT MATCH repository contents! Refusing to overwrite tampering evidence.",
                to_hex(&head_oid)
            ));
        }
        for (&p, exp_p) in head_pc.parents.iter().zip(expected_parents.iter()) {
            let (pd, _) = verify_eng
                .digest_commit(p)
                .map_err(|e| format!("hash parent {}: {}", to_hex(&p), e.message))?;
            if !ct_eq(&pd, exp_p) {
                return Err(format!(
                    "HEAD ({}) carries a buttress-parent header that DOES NOT MATCH parent {}! Refusing to overwrite tampering evidence.",
                    to_hex(&head_oid),
                    to_hex(&p)
                ));
            }
        }
        if !force_sign && explicit_sign_key.is_none() || (head_pc.has_gpgsig && explicit_sign_key.is_none()) {
            let d = keys.hash_sealed_commit(&head_pc.raw);
            if !want_sign {
                let mut dc = DigestCache::load_from_git_dir(repo.common_dir());
                dc.put_commit(head_oid, d);
                dc.flush();
            }
            return Ok((head_oid, d));
        }
    }

    // When signing, verify reachable ancestor seals on every parent using a fresh memory-only
    // verifier BEFORE stamping a cryptographic signature (`R2-H4` fix)!
    if want_sign && !head_pc.parents.is_empty() {
        let mut anc_eng = Engine::new_verifier(repo, &keys);
        for &p in &head_pc.parents {
            if let Err(e) = verify_target_with_engine(&mut anc_eng, p, None, None, true)
                && matches!(
                    e.kind,
                    VerifyErrorKind::Mismatch | VerifyErrorKind::StoreFailure
                )
            {
                return Err(format!(
                    "refusing to sign HEAD: parent {} failed BLAKE3 ancestry verification: {}",
                    to_hex(&p),
                    e.message
                ));
            }
        }
    }

    // Never trust unauthenticated disk cache when signing!
    let cache = if want_sign {
        DigestCache::memory_only()
    } else {
        DigestCache::load_from_git_dir(repo.common_dir())
    };

    let unsigned_payload = {
        let mut engine = Engine::new(repo, &keys, cache);

        let tree_dig = engine
            .digest_tree(head_pc.tree)
            .map_err(|e| format!("hash tree: {}", e.message))?;
        let mut parent_digs = Vec::with_capacity(head_pc.parents.len());
        for &p in &head_pc.parents {
            let (pd, _) = engine
                .digest_commit(p)
                .map_err(|e| format!("hash parent {}: {}", to_hex(&p), e.message))?;
            parent_digs.push(pd);
        }
        engine.flush_cache();

        let (header_bytes, body_bytes) = split_headers_body(&head_pc.raw);
        let mut lines = strip_blake3_and_sig_headers(header_bytes);
        lines.push(
            format!(
                "buttress-tree blake3 {} {}",
                to_hex(&head_pc.tree),
                to_hex(&tree_dig)
            )
            .into_bytes(),
        );
        for pd in &parent_digs {
            lines.push(format!("buttress-parent blake3 {}", to_hex(pd)).into_bytes());
        }

        let mut unsigned = Vec::with_capacity(head_pc.raw.len() + 256);
        for line in &lines {
            unsigned.extend_from_slice(line);
            unsigned.push(b'\n');
        }
        unsigned.push(b'\n');
        unsigned.extend_from_slice(body_bytes);
        unsigned
    };

    let final_raw = if want_sign {
        let sig = sign_payload(repo, &unsigned_payload, explicit_sign_key)?;
        let (h_bytes, b_bytes) = split_headers_body(&unsigned_payload);
        let mut signed = Vec::with_capacity(unsigned_payload.len() + sig.len() + 32);
        signed.extend_from_slice(h_bytes);
        signed.push(b'\n');
        signed.extend_from_slice(&format_gpgsig_header(&sig));
        signed.push(b'\n');
        signed.extend_from_slice(b_bytes);
        signed
    } else {
        unsigned_payload
    };

    let new_oid = repo.write_commit_object(&final_raw)?;
    // Re-read the stored object from Git (`H7` fix) to verify SHA-1 collision didn't shadow our write!
    let (stored_kind, stored_raw) = repo
        .read_object(&new_oid)
        .map_err(|e| e.message)?
        .ok_or_else(|| format!("written commit {} missing from store", to_hex(&new_oid)))?;
    if stored_kind != ObjKind::Commit || stored_raw != final_raw {
        return Err(format!(
            "SHA-1 object collision detected writing commit {}: stored bytes differ from sealed commit!",
            to_hex(&new_oid)
        ));
    }
    let sealed_dig = keys.hash_sealed_commit(&stored_raw);

    // Sanitize reflog message (strip NUL and control chars — `L2` fix)
    let (_, body) = split_headers_body(&final_raw);
    let raw_subj = String::from_utf8_lossy(body)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|&c| !c.is_control())
        .take(160)
        .collect::<String>();
    let reflog = format!("commit (buttress): {raw_subj}");

    // Verify HEAD's symbolic/detached identity has not changed since `read_head_state`, then CAS!
    let (cur_sym, cur_oid) = read_head_state(repo)?;
    if cur_sym != sym_ref || cur_oid != head_oid {
        return Err("HEAD changed concurrently while sealing commit; aborting ref update".into());
    }

    let mut stdin_tx = Vec::new();
    stdin_tx.extend_from_slice(b"option no-deref\0");
    match sym_ref {
        Some(ref branch_bytes) => {
            stdin_tx.extend_from_slice(b"update ");
            stdin_tx.extend_from_slice(branch_bytes);
            stdin_tx.push(0);
            stdin_tx.extend_from_slice(to_hex(&new_oid).as_bytes());
            stdin_tx.push(0);
            stdin_tx.extend_from_slice(to_hex(&head_oid).as_bytes());
            stdin_tx.push(0);
        }
        None => {
            stdin_tx.extend_from_slice(b"update HEAD\0");
            stdin_tx.extend_from_slice(to_hex(&new_oid).as_bytes());
            stdin_tx.push(0);
            stdin_tx.extend_from_slice(to_hex(&head_oid).as_bytes());
            stdin_tx.push(0);
        }
    }

    let scoped_token = format!(
        "seal-head:{}:{}",
        to_hex(&head_oid),
        to_hex(&new_oid)
    );
    let mut cmd = repo.cmd();
    cmd.env("GIT_BUTTRESS_INTERNAL_TX", &scoped_token);
    cmd.args(["update-ref", "-m", &reflog, "--stdin", "-z"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn update-ref: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&stdin_tx)
        .map_err(|e| format!("write update-ref stdin: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait update-ref: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    if !want_sign {
        let mut cache = DigestCache::load_from_git_dir(repo.common_dir());
        cache.put_commit(new_oid, sealed_dig);
        cache.flush();
    }

    if !quiet {
        eprintln!(
            "buttress: sealed {} -> {} (blake3: {})",
            &to_hex(&head_oid)[..12],
            &to_hex(&new_oid)[..12],
            &to_hex(&sealed_dig)[..16]
        );
    }
    Ok((new_oid, sealed_dig))
}

/// One parsed record from Git `reference-transaction` stdin: `(old_token, new_token, refname)`.
type RefUpdate = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Strictly parse Git `reference-transaction` stdin at the byte level (`H1` fix):
/// Every line MUST be `<old-token> <new-token> <refname>\n` separated by single ASCII `0x20` spaces.
/// Propagates I/O errors and rejects malformed lines instead of silently truncating!
fn parse_transaction_stdin(mut reader: impl Read) -> Result<Vec<RefUpdate>, String> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .map_err(|e| format!("buttress: failed reading reference-transaction stdin: {e}"))?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let body = raw
        .strip_suffix(b"\n")
        .ok_or_else(|| "buttress: truncated reference-transaction line (missing LF)".to_string())?;
    let mut out = Vec::new();
    for line in body.split(|&c| c == b'\n') {
        let sp1 = line
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| "buttress: malformed reference-transaction record (missing first space)".to_string())?;
        let rest = &line[sp1 + 1..];
        let sp2 = rest
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| "buttress: malformed reference-transaction record (missing second space)".to_string())?;
        let old_tok = &line[..sp1];
        let new_tok = &rest[..sp2];
        let ref_bytes = &rest[sp2 + 1..];
        if old_tok.is_empty() || new_tok.is_empty() || ref_bytes.is_empty() || ref_bytes.contains(&0) {
            return Err("buttress: malformed reference-transaction record (empty or NUL field)".into());
        }
        out.push((old_tok.to_vec(), new_tok.to_vec(), ref_bytes.to_vec()));
    }
    Ok(out)
}

/// Check if an incoming single-ref transaction matches an exact scoped internal token
/// (`seal-head:<old>:<new>` or `autotag:<ref>:<new>`) rather than a blanket env-var bypass (`H1` fix).
fn is_scoped_internal_tx(updates: &[RefUpdate]) -> bool {
    let Ok(tok) = env::var("GIT_BUTTRESS_INTERNAL_TX") else {
        return false;
    };
    if updates.len() != 1 {
        return false;
    }
    let (old_b, new_b, ref_b) = &updates[0];
    if let Some(rest) = tok.strip_prefix("seal-head:")
        && let Some((exp_old, exp_new)) = rest.split_once(':')
    {
        return old_b == exp_old.as_bytes() && new_b == exp_new.as_bytes();
    }
    if let Some(rest) = tok.strip_prefix("autotag:")
        && let Some((exp_ref, exp_new)) = rest.rsplit_once(':')
    {
        return ref_b == exp_ref.as_bytes() && new_b == exp_new.as_bytes();
    }
    false
}

/// Handle Git's `reference-transaction` hook (`preparing`, `prepared`, `committed`, `aborted`).
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if phase != "prepared" && phase != "committed" {
        return Ok(());
    }

    let updates = parse_transaction_stdin(std::io::stdin().lock())?;
    if updates.is_empty() || is_scoped_internal_tx(&updates) {
        return Ok(());
    }

    // Distinguish "outside a Git repo / non-SHA-1 repo" from operational failures inside a SHA-1 repo (`H1` fix)
    let mut repo = match GitRepo::open(None) {
        Ok(r) => r,
        Err(msg) if msg.contains("object-format=") || msg.contains("not a git repository") => {
            return Ok(());
        }
        Err(msg) => {
            return Err(format!("buttress: repository open failed in hook: {msg}"));
        }
    };
    if repo.config_bool_strict("buttress.disabled", false)? {
        return Ok(());
    }

    let zero = b"0000000000000000000000000000000000000000";

    if phase == "prepared" {
        let keys = ContextKeys::new();
        let policy = MissingPolicy::from_repo(&repo, None)?;

        // Only pair exact companion tag names: `refs/tags/<X>` is excused from `NoEvidence`
        // iff `refs/tags/<X>+blake3-<hex>` with the SAME `<new-oid>` is in this transaction (`M3` fix)!
        let mut paired_plain_tags: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
        for (_, new_b, ref_b) in &updates {
            if let Ok(ref_s) = std::str::from_utf8(ref_b)
                && let Some(rest) = ref_s.strip_prefix("refs/tags/")
                && let Some((base_tag, _)) = rest.split_once("+blake3-")
                && parse_ref_embedded_b3(ref_s).ok().flatten().is_some()
            {
                paired_plain_tags.insert((
                    format!("refs/tags/{base_tag}").into_bytes(),
                    new_b.clone(),
                ));
            }
        }

        // Share a single fresh-memory `Engine` across the entire transaction (`H11` fix)!
        let mut engine = Engine::new(&mut repo, &keys, DigestCache::memory_only());

        for (_, new_b, ref_b) in &updates {
            if new_b == zero {
                continue;
            }
            if new_b.starts_with(b"ref:") {
                // Reject symbolic refs carrying `+blake3-` unless resolved; check `+blake3-` syntax if present
                if ref_b.windows(8).any(|w| w == b"+blake3-") {
                    return Err("buttress: symbolic ref cannot carry a +blake3- digest pin".into());
                }
                continue;
            }

            let oid = hex_to_oid(new_b).map_err(|e| {
                format!(
                    "buttress: invalid new OID in reference-transaction on {}: {e}",
                    String::from_utf8_lossy(ref_b)
                )
            })?;

            let ref_utf8 = std::str::from_utf8(ref_b).ok();
            if ref_utf8.is_none() && ref_b.windows(8).any(|w| w == b"+blake3-") {
                return Err("buttress: non-UTF-8 ref containing '+blake3-' rejected".into());
            }
            let has_b3_name = match ref_utf8 {
                Some(s) => parse_ref_embedded_b3(s)
                    .map_err(|e| format!("buttress: {}", e.message))?
                    .is_some(),
                None => false,
            };

            let is_checked_namespace = has_b3_name
                || ref_b.starts_with(b"refs/remotes/")
                || ref_b.starts_with(b"refs/tags/")
                || ref_b.starts_with(b"refs/heads/")
                || ref_b == b"FETCH_HEAD";
            if !is_checked_namespace {
                continue;
            }

            // Note: DO NOT enforce `buttress.missing=error` on local `refs/heads/*` in `prepared`
            // because stock `git commit` updates `HEAD`/branch FIRST and then invokes `post-commit`
            // (`seal_head`)! Still enforce Mismatch on `refs/heads/*`, and enforce `missing=error`
            // on `refs/remotes/*`, `refs/tags/*`, and `+blake3-` refs (`R2-H3` fix)!
            let is_local_branch_update = ref_b.starts_with(b"refs/heads/") && !has_b3_name;

            let ref_display = String::from_utf8_lossy(ref_b);
            match verify_target_with_engine(&mut engine, oid, ref_utf8, None, true) {
                Ok(CheckOutcome::Match { shallow_stops, .. }) => {
                    if shallow_stops > 0 {
                        match policy {
                            MissingPolicy::Error if !is_local_branch_update => {
                                return Err(format!(
                                    "buttress: {} stopped at {shallow_stops} shallow boundary parent(s) (buttress.missing=error)",
                                    sanitize_for_tty(&ref_display)
                                ));
                            }
                            MissingPolicy::Warn => {
                                eprintln!(
                                    "buttress: warning: {} verified partially ({shallow_stops} shallow boundary parent(s) skipped)",
                                    sanitize_for_tty(&ref_display)
                                );
                            }
                            _ => {}
                        }
                    }
                }
                Ok(CheckOutcome::NoEvidence { shallow_stops, .. }) => {
                    if shallow_stops > 0 && policy == MissingPolicy::Warn {
                        eprintln!(
                            "buttress: warning: {} had {shallow_stops} shallow boundary parent(s) skipped",
                            sanitize_for_tty(&ref_display)
                        );
                    }
                    let is_paired_plain_tag =
                        paired_plain_tags.contains(&(ref_b.clone(), new_b.clone()));
                    if !is_paired_plain_tag && !is_local_branch_update {
                        match policy {
                            MissingPolicy::Silent => {}
                            MissingPolicy::Warn => {
                                eprintln!(
                                    "buttress: warning: {} ({}) has no BLAKE3 buttress evidence",
                                    sanitize_for_tty(&ref_display),
                                    &to_hex(&oid)[..12]
                                );
                            }
                            MissingPolicy::Error => {
                                return Err(format!(
                                    "buttress: error: {} ({}) has no BLAKE3 buttress evidence (buttress.missing=error)",
                                    sanitize_for_tty(&ref_display),
                                    &to_hex(&oid)[..12]
                                ));
                            }
                        }
                    }
                }
                Err(VerifyError {
                    kind: VerifyErrorKind::Mismatch,
                    message,
                }) => {
                    return Err(format!(
                        "buttress: MISMATCH on {}\n  {message}",
                        sanitize_for_tty(&ref_display)
                    ));
                }
                Err(VerifyError {
                    kind: VerifyErrorKind::StoreFailure,
                    message,
                }) => {
                    return Err(format!(
                        "buttress: STORE FAILURE checking {}: {message}",
                        sanitize_for_tty(&ref_display)
                    ));
                }
                Err(VerifyError {
                    kind: VerifyErrorKind::Incomplete,
                    message,
                }) => {
                    if has_b3_name
                        || policy == MissingPolicy::Error
                        || message.contains("pinned target")
                    {
                        return Err(format!(
                            "buttress: incomplete objects for {}: {message}",
                            sanitize_for_tty(&ref_display)
                        ));
                    }
                    eprintln!(
                        "buttress: note: could not fully check {} ({message})",
                        sanitize_for_tty(&ref_display)
                    );
                }
            }
        }
        return Ok(());
    }

    // phase == "committed": opt-in `buttress.autotag` (`H9` & `H7` fixes: fresh memory engine,
    // shared `verify_target_with_engine` peeler, and create-only `--no-deref` CAS with zero old OID!)
    let auto_tag = repo.config_bool_strict("buttress.autotag", false)?;
    if !auto_tag {
        return Ok(());
    }
    if updates
        .iter()
        .any(|(_, _, r)| r.starts_with(b"refs/remotes/"))
    {
        return Ok(());
    }
    if let Ok(action) = env::var("GIT_REFLOG_ACTION") {
        let a = action.to_ascii_lowercase();
        if a.starts_with("clone") || a.starts_with("fetch") || a.starts_with("pull") {
            return Ok(());
        }
    }

    let keys = ContextKeys::new();
    for (_old_b, new_b, ref_b) in &updates {
        if new_b == zero || new_b.starts_with(b"ref:") {
            continue;
        }
        let Ok(refname) = std::str::from_utf8(ref_b) else {
            continue;
        };
        let Some(tag_name) = refname.strip_prefix("refs/tags/") else {
            continue;
        };
        if tag_name.contains("+blake3-") {
            continue;
        }
        let Ok(oid) = hex_to_oid(new_b) else {
            continue;
        };

        // Compute & validate FULL non-shallow target digest (`allow_shallow=false`) using a fresh
        // memory-only Engine so we NEVER mint a `+blake3-` pin for an incomplete shallow history (`R2-H2` fix)!
        let target_dig = {
            let mut eng = Engine::new(&mut repo, &keys, DigestCache::memory_only());
            match verify_target_with_engine(&mut eng, oid, None, None, false) {
                Ok(CheckOutcome::Match { digest, .. })
                | Ok(CheckOutcome::NoEvidence { digest, .. }) => digest,
                Err(e) => {
                    eprintln!(
                        "buttress: refusing to mint +blake3- tag for {}: {}",
                        sanitize_for_tty(tag_name),
                        e.message
                    );
                    continue;
                }
            }
        };

        let companion = format!("refs/tags/{tag_name}+blake3-{}", to_hex(&target_dig));
        if repo.try_rev_parse(&companion) == Some(oid) {
            continue;
        }
        // Create-only atomic transaction (`old == zero`, `option no-deref`) so we NEVER clobber
        // an existing conflicting pin or dereference a symref (`H9` fix)!
        let new_hex = to_hex(&oid);
        let mut tx = Vec::new();
        tx.extend_from_slice(b"option no-deref\0create ");
        tx.extend_from_slice(companion.as_bytes());
        tx.push(0);
        tx.extend_from_slice(new_hex.as_bytes());
        tx.push(0);

        let scoped_tok = format!("autotag:{companion}:{new_hex}");
        let mut cmd = repo.cmd();
        cmd.env("GIT_BUTTRESS_INTERNAL_TX", &scoped_tok);
        cmd.args(["update-ref", "--stdin", "-z"]);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Ok(mut child) = cmd.spawn() {
            let _ = child.stdin.take().unwrap().write_all(&tx);
            if let Ok(o) = child.wait_with_output() {
                if o.status.success() {
                    eprintln!(
                        "buttress: also created tag {tag_name}+blake3-{}",
                        to_hex(&target_dig)
                    );
                } else {
                    eprintln!(
                        "buttress: warning: could not create {companion}: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Sanitize untrusted Git text before printing to terminal stderr/stdout (`L2` fix).
pub fn sanitize_for_tty(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
        .collect()
}

/// Transparent `git` wrapper execution (`git-buttress __wrap-git <args...>`), preserving
/// raw `OsString` arguments (never panicking on non-UTF-8 paths!) and guarding against
/// wrapper recursion (`H8` & `M5` fixes).
pub fn run_git_wrapper_os(args: &[OsString]) -> i32 {
    let depth: u32 = env::var("GIT_BUTTRESS_WRAP_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let real_git = match resolve_real_git() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("git-buttress wrapper: {e}");
            return 127;
        }
    };
    if depth >= 4 {
        return exec_or_spawn_os(&real_git, args, depth + 1);
    }

    let (subcmd_idx, global_args, cfg_overrides) = split_git_global_args(args);
    let subcmd = subcmd_idx.and_then(|i| args[i].to_str());

    match subcmd {
        Some("commit") => wrap_git_commit(&real_git, args, subcmd_idx.unwrap(), &global_args, &cfg_overrides, depth),
        Some("fsck") => wrap_git_fsck(&real_git, args, &global_args, &cfg_overrides, depth),
        _ => exec_or_spawn_os(&real_git, args, depth + 1),
    }
}

/// Split leading global `git` options (`args[..subcmd_idx]`) so post-actions replay the
/// **exact** global argv (`-C`, `--git-dir`, `--work-tree`, `-c`, `--namespace`, etc.) (`H8` fix)!
fn split_git_global_args(args: &[OsString]) -> (Option<usize>, Vec<OsString>, Vec<String>) {
    let mut i = 0;
    let mut global = Vec::new();
    let mut cfg_overrides = Vec::new();
    while i < args.len() {
        let a = &args[i];
        let Some(s) = a.to_str() else {
            return (None, global, cfg_overrides);
        };
        if s == "--" {
            return (None, global, cfg_overrides);
        }
        if !s.starts_with('-') {
            return (Some(i), global, cfg_overrides);
        }
        if matches!(
            s,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--config-env"
        ) {
            global.push(a.clone());
            if i + 1 < args.len() {
                if s == "-c"
                    && let Some(kv) = args[i + 1].to_str()
                {
                    cfg_overrides.push(kv.to_string());
                }
                global.push(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if let Some(rest) = s.strip_prefix("-c")
            && !rest.is_empty()
        {
            cfg_overrides.push(rest.to_string());
        }
        global.push(a.clone());
        i += 1;
    }
    (None, global, cfg_overrides)
}

fn has_cli_disabled(cfg_overrides: &[String]) -> Option<bool> {
    let mut res: Option<bool> = None;
    for kv in cfg_overrides {
        if let Some((k, v)) = kv.split_once('=') {
            if k.trim().eq_ignore_ascii_case("buttress.disabled") {
                res = Some(matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "true" | "yes" | "on" | "1"
                ));
            }
        } else if kv.trim().eq_ignore_ascii_case("buttress.disabled") {
            res = Some(true);
        }
    }
    res
}

fn cli_missing_override(cfg_overrides: &[String]) -> Option<String> {
    let mut res = None;
    for kv in cfg_overrides {
        if let Some((k, v)) = kv.split_once('=')
            && k.trim().eq_ignore_ascii_case("buttress.missing")
        {
            res = Some(v.trim().to_string());
        }
    }
    res
}

#[derive(Default)]
struct CommitFlagScan {
    is_preview_or_quiet: bool,
    no_verify: bool,
    explicit_sign_key: Option<String>,
}

/// Scan `git commit` options respecting `--` and option-value arguments so values like
/// `git commit -m -n` are never misread as flags (`R2-M5`), and `-S<key>` / `--gpg-sign=<key>`
/// is preserved when re-signing the sealed commit (`R2-H4`).
fn scan_commit_flags(commit_args: &[OsString]) -> CommitFlagScan {
    let mut out = CommitFlagScan::default();
    let mut i = 0;
    while i < commit_args.len() {
        let Some(s) = commit_args[i].to_str() else {
            i += 1;
            continue;
        };
        if s == "--" {
            break;
        }
        if s.starts_with("--dry-run")
            || s.starts_with("--short")
            || s.starts_with("--porcelain")
            || s.starts_with("--long")
            || s == "--null"
            || s == "-z"
            || s == "-h"
            || s == "--help"
            || s == "-q"
            || s == "--quiet"
        {
            out.is_preview_or_quiet = true;
            i += 1;
            continue;
        }
        if s == "--no-verify" {
            out.no_verify = true;
            i += 1;
            continue;
        }
        if s == "--no-gpg-sign" {
            out.explicit_sign_key = None;
            i += 1;
            continue;
        }
        if let Some(k) = s.strip_prefix("--gpg-sign=") {
            out.explicit_sign_key = if k.is_empty() {
                None
            } else {
                Some(k.to_string())
            };
            i += 1;
            continue;
        }
        if s == "--gpg-sign" {
            i += 1;
            continue;
        }
        if s.starts_with('-') && !s.starts_with("--") && s.len() >= 2 {
            for (idx, ch) in s[1..].char_indices() {
                if matches!(ch, 'q' | 'z' | 'h') {
                    out.is_preview_or_quiet = true;
                } else if ch == 'n' {
                    out.no_verify = true;
                } else if ch == 'S' {
                    let rest = &s[1 + idx + ch.len_utf8()..];
                    if !rest.is_empty() {
                        out.explicit_sign_key = Some(rest.to_string());
                    }
                    break;
                } else if matches!(ch, 'm' | 'F' | 'c' | 'C' | 'u' | 't') {
                    let at_end = idx + ch.len_utf8() == s.len() - 1;
                    if at_end && ch != 'u' {
                        i += 1;
                    }
                    break;
                }
            }
            i += 1;
            continue;
        }
        if matches!(
            s,
            "-m" | "--message"
                | "-F"
                | "--file"
                | "-c"
                | "--reedit-message"
                | "-C"
                | "--reuse-message"
                | "-t"
                | "--template"
                | "--fixup"
                | "--squash"
                | "--author"
                | "--date"
                | "--cleanup"
                | "--trailer"
                | "--pathspec-from-file"
        ) {
            i += 2;
            continue;
        }
        i += 1;
    }
    out
}

/// Read `HEAD` reflog line count so `wrap_git_commit` ONLY seals or prints a summary if
/// `real_git commit` ACTUALLY created a new commit entry (`H8.1` fix — immune to any preview flag)!
fn head_reflog_marker(repo: &GitRepo) -> Option<(Option<Oid>, Vec<u8>)> {
    let oid = repo.try_rev_parse("HEAD");
    let log_bytes = fs::read(repo.git_dir().join("logs/HEAD")).unwrap_or_default();
    Some((oid, log_bytes))
}

fn wrap_git_commit(
    real_git: &Path,
    args: &[OsString],
    subcmd_idx: usize,
    global_args: &[OsString],
    cfg_overrides: &[String],
    depth: u32,
) -> i32 {
    let commit_args = &args[subcmd_idx + 1..];
    let scanned = scan_commit_flags(commit_args);
    if scanned.is_preview_or_quiet || has_cli_disabled(cfg_overrides) == Some(true) {
        return exec_or_spawn_os(real_git, args, depth + 1);
    }

    let before_repo = GitRepo::open_with_global_args(None, global_args).ok();
    let before_marker = before_repo.as_ref().and_then(head_reflog_marker);
    let was_unborn = before_marker
        .as_ref()
        .is_some_and(|(oid, _)| oid.is_none());

    let mut patched: Vec<OsString> = Vec::with_capacity(args.len() + 1);
    patched.extend_from_slice(&args[..=subcmd_idx]);
    patched.push(OsString::from("-q"));
    patched.extend_from_slice(&args[subcmd_idx + 1..]);

    let mut commit_cmd = Command::new(real_git);
    commit_cmd
        .args(&patched)
        .env("GIT_BUTTRESS_REAL_GIT", real_git)
        .env("GIT_BUTTRESS_WRAP_DEPTH", (depth + 1).to_string());
    if let Some(ref k) = scanned.explicit_sign_key {
        commit_cmd.env("GIT_BUTTRESS_SIGN_KEY", k);
    }
    let status = commit_cmd.status();
    let code = match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("git-buttress: failed to execute git: {e}");
            return 127;
        }
    };
    if code != 0 {
        return code;
    }

    let mut repo = match GitRepo::open_with_global_args(None, global_args) {
        Ok(r) => r,
        Err(msg) if msg.contains("object-format=") || msg.contains("not a git repository") => {
            return 0;
        }
        Err(e) => {
            eprintln!("git-buttress: commit succeeded, but reopening repository failed: {e}");
            return 1;
        }
    };

    // Only seal/summarize if `HEAD` or `logs/HEAD` ACTUALLY changed (proving a commit occurred)!
    let after_marker = head_reflog_marker(&repo);
    if before_marker.is_some() && before_marker == after_marker {
        return 0;
    }

    let disabled = match has_cli_disabled(cfg_overrides) {
        Some(b) => b,
        None => match repo.config_bool_strict("buttress.disabled", false) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("git-buttress: commit created, but config error prevented sealing: {e}");
                return 1;
            }
        },
    };

    let final_oid = if !disabled && !scanned.no_verify {
        match seal_head_with_key(&mut repo, false, scanned.explicit_sign_key.as_deref(), true) {
            Ok((oid, _)) => oid,
            Err(e) => {
                eprintln!("git-buttress: stock commit was created, but BLAKE3 sealing failed: {e}");
                return 1;
            }
        }
    } else {
        match repo.rev_parse("HEAD") {
            Ok(o) => o,
            Err(_) => return 0,
        }
    };

    print_commit_summary_for(&repo, &final_oid, was_unborn);
    0
}

fn print_commit_summary_for(repo: &GitRepo, commit_oid: &Oid, was_unborn: bool) {
    let oid_hex = to_hex(commit_oid);
    let branch = repo
        .cmd()
        .args(["symbolic-ref", "--short", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| sanitize_for_tty(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_else(|| "detached HEAD".into());
    let short_sha = repo
        .cmd()
        .args(["rev-parse", "--short", &oid_hex])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| oid_hex[..7].to_string());
    let subject = repo
        .cmd()
        .args(["log", "-1", "--format=%s", &oid_hex])
        .output()
        .ok()
        .map(|o| sanitize_for_tty(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_default();
    let has_parent = repo.try_rev_parse(&format!("{oid_hex}^")).is_some();

    if was_unborn || !has_parent {
        println!("[{branch} (root-commit) {short_sha}] {subject}");
    } else {
        println!("[{branch} {short_sha}] {subject}");
    }

    if let Ok(out) = repo
        .cmd()
        .args(["diff-tree", "--stat", "--summary", "--root", &oid_hex])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for (idx, line) in text.lines().enumerate() {
            if idx > 0 {
                println!("{}", sanitize_for_tty(line));
            }
        }
    }
}

fn wrap_git_fsck(
    real_git: &Path,
    args: &[OsString],
    global_args: &[OsString],
    cfg_overrides: &[String],
    depth: u32,
) -> i32 {
    let status = Command::new(real_git)
        .args(args)
        .env("GIT_BUTTRESS_REAL_GIT", real_git)
        .env("GIT_BUTTRESS_WRAP_DEPTH", (depth + 1).to_string())
        .status();
    let code = match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("git-buttress: failed to execute git: {e}");
            return 127;
        }
    };
    if code != 0 {
        return code;
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return 0;
    }
    let mut repo = match GitRepo::open_with_global_args(None, global_args) {
        Ok(r) => r,
        Err(msg) if msg.contains("object-format=") => {
            eprintln!("buttress fsck: skipped (non-SHA-1 repository)");
            return 0;
        }
        Err(e) => {
            eprintln!("buttress fsck: error opening repository: {e}");
            return 1;
        }
    };
    let disabled = match has_cli_disabled(cfg_overrides) {
        Some(b) => b,
        None => match repo.config_bool_strict("buttress.disabled", false) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("buttress fsck: invalid config: {e}");
                return 1;
            }
        },
    };
    if disabled {
        return 0;
    }
    let cli_missing = cli_missing_override(cfg_overrides);
    match fsck_all_refs(&mut repo, cli_missing.as_deref()) {
        Ok((matched, partial, no_ev)) => {
            if partial > 0 {
                eprintln!(
                    "buttress fsck: {matched} ref(s) verified with BLAKE3, {partial} ref(s) partially verified (shallow), {no_ev} ref(s) without buttress lines"
                );
            } else {
                eprintln!(
                    "buttress fsck: {matched} ref(s) verified with BLAKE3, {no_ev} ref(s) without buttress lines"
                );
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn exec_or_spawn_os(real_git: &Path, args: &[OsString], next_depth: u32) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(real_git)
            .args(args)
            .env("GIT_BUTTRESS_REAL_GIT", real_git)
            .env("GIT_BUTTRESS_WRAP_DEPTH", next_depth.to_string())
            .exec();
        eprintln!("git-buttress: exec {:?} failed: {err}", real_git);
        127
    }
    #[cfg(not(unix))]
    {
        Command::new(real_git)
            .args(args)
            .env("GIT_BUTTRESS_REAL_GIT", real_git)
            .env("GIT_BUTTRESS_WRAP_DEPTH", next_depth.to_string())
            .status()
            .map(|s| s.code().unwrap_or(1))
            .unwrap_or(127)
    }
}

/// Exhaustive, fail-closed ref audit (`H3` & `M3` fixes):
/// - Uses `git for-each-ref --format=%(objectname) %(refname)%00` (exit 0 on empty repo,
///   byte-exact NUL-delimited refnames, propagates any ref/repo error!).
/// - Also checks detached `HEAD` if present!
/// - Shares a single `Engine` (`H11` fix) so multi-ref repos don't re-walk shared history.
pub fn fsck_all_refs(
    repo: &mut GitRepo,
    policy_override: Option<&str>,
) -> Result<(usize, usize, usize), String> {
    let policy = MissingPolicy::from_repo(repo, policy_override)?;
    // 1. Validate ref-database structural integrity FIRST (`git refs verify` — `R2-H1` fix)!
    repo.run(["refs", "verify"], None)
        .map_err(|e| format!("buttress fsck: ref database verification failed: {e}"))?;

    let out = repo.run(["for-each-ref", "--format=%(objectname) %(refname)%00"], None)?;
    if !out.stderr.is_empty() {
        return Err(format!(
            "buttress fsck: ref enumeration reported warnings/broken refs: {}",
            sanitize_for_tty(String::from_utf8_lossy(&out.stderr).trim())
        ));
    }

    let mut refs: Vec<(Oid, Vec<u8>)> = Vec::new();
    for rec in out.stdout.split(|&b| b == 0) {
        if rec.is_empty() || rec == b"\n" {
            continue;
        }
        let rec = rec.strip_prefix(b"\n").unwrap_or(rec);
        let sp = rec
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| "malformed for-each-ref output".to_string())?;
        let oid = hex_to_oid(&rec[..sp])?;
        let ref_bytes = rec[sp + 1..].to_vec();
        refs.push((oid, ref_bytes));
    }

    // Check HEAD explicitly (`R2-H1` fix: distinguish symbolic unborn branch vs detached vs corrupt HEAD!)
    let sym_out = repo
        .cmd()
        .args(["symbolic-ref", "-q", "HEAD"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|e| format!("buttress fsck: symbolic-ref HEAD: {e}"))?;
    match sym_out.status.code() {
        Some(0) => {
            // Symbolic HEAD: either resolves (already in `for-each-ref`) or is a valid unborn branch!
            let sym_name = String::from_utf8_lossy(&sym_out.stdout).trim().to_string();
            if !sym_name.starts_with("refs/heads/") {
                return Err(format!("buttress fsck: symbolic HEAD points outside refs/heads/: {}", sanitize_for_tty(&sym_name)));
            }
        }
        Some(1) => {
            // Detached HEAD: MUST resolve to a valid commit/object OID!
            let head_oid = repo
                .rev_parse("HEAD")
                .map_err(|e| format!("buttress fsck: corrupt detached HEAD: {e}"))?;
            refs.push((head_oid, b"HEAD".to_vec()));
        }
        _ => {
            return Err(format!(
                "buttress fsck: corrupt HEAD: {}",
                sanitize_for_tty(String::from_utf8_lossy(&sym_out.stderr).trim())
            ));
        }
    }

    // Exact companion tag pairing (`refs/tags/<X>` paired only with `refs/tags/<X>+blake3-...` at same OID)
    let mut paired_plain_tags: HashSet<(Vec<u8>, Oid)> = HashSet::new();
    for (oid, ref_b) in &refs {
        if let Ok(ref_s) = std::str::from_utf8(ref_b)
            && let Some(rest) = ref_s.strip_prefix("refs/tags/")
            && let Some((base_tag, _)) = rest.split_once("+blake3-")
            && parse_ref_embedded_b3(ref_s).ok().flatten().is_some()
        {
            paired_plain_tags.insert((format!("refs/tags/{base_tag}").into_bytes(), *oid));
        }
    }

    let keys = ContextKeys::new();
    let mut engine = Engine::new_verifier(repo, &keys);
    let mut matched_refs = 0usize;
    let mut partial_refs = 0usize;
    let mut no_evidence_refs = 0usize;

    for (oid, ref_b) in &refs {
        let ref_utf8 = std::str::from_utf8(ref_b).ok();
        if ref_utf8.is_none() && ref_b.windows(8).any(|w| w == b"+blake3-") {
            return Err("buttress: non-UTF-8 ref containing '+blake3-' rejected".into());
        }
        let ref_display = sanitize_for_tty(&String::from_utf8_lossy(ref_b));

        match verify_target_with_engine(&mut engine, *oid, ref_utf8, None, true) {
            Ok(CheckOutcome::Match { shallow_stops, .. }) => {
                if shallow_stops > 0 {
                    match policy {
                        MissingPolicy::Error => {
                            return Err(format!(
                                "buttress: {ref_display} stopped at {shallow_stops} shallow boundary parent(s) (buttress.missing=error)"
                            ));
                        }
                        MissingPolicy::Warn => {
                            eprintln!(
                                "buttress: warning: {ref_display} verified partially ({shallow_stops} shallow boundary parent(s) skipped)"
                            );
                        }
                        MissingPolicy::Silent => {}
                    }
                    partial_refs += 1;
                } else {
                    matched_refs += 1;
                }
            }
            Ok(CheckOutcome::NoEvidence { shallow_stops, .. }) => {
                no_evidence_refs += 1;
                if shallow_stops > 0 && policy == MissingPolicy::Warn {
                    eprintln!(
                        "buttress: warning: {ref_display} had {shallow_stops} shallow boundary parent(s) skipped"
                    );
                }
                if !paired_plain_tags.contains(&(ref_b.clone(), *oid)) {
                    match policy {
                        MissingPolicy::Silent => {}
                        MissingPolicy::Warn => {
                            eprintln!(
                                "buttress: warning: {ref_display} ({}) has no BLAKE3 buttress evidence",
                                &to_hex(oid)[..12]
                            );
                        }
                        MissingPolicy::Error => {
                            return Err(format!(
                                "buttress: error: {ref_display} ({}) has no BLAKE3 buttress evidence",
                                &to_hex(oid)[..12]
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                let label = match e.kind {
                    VerifyErrorKind::Mismatch => "MISMATCH",
                    VerifyErrorKind::Incomplete => "INCOMPLETE",
                    VerifyErrorKind::StoreFailure => "STORE FAILURE",
                };
                return Err(format!("buttress: {label} on {ref_display}: {}", e.message));
            }
        }
    }

    Ok((matched_refs, partial_refs, no_evidence_refs))
}

/// Standard Git hooks (`githooks(5)`), EXCLUDING `push-to-checkout` and `proc-receive` whose
/// mere presence as executable files alters Git's built-in server/worktree semantics (`R2-H5` fix)!
const FORWARDED_GIT_HOOKS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "post-receive",
    "post-update",
    "reference-transaction",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];

/// Detect whether the installed Git supports native config-based multi-hooks (`git hook list` /
/// `[hook "<name>"]`, Git 2.56+), which lets `git-buttress` integrate cleanly WITHOUT touching
/// `core.hooksPath` (eliminating conflicts with `git-lfs`, `pre-commit`, `husky`, etc.)!
pub fn supports_native_config_hooks(real_git: &Path) -> bool {
    let Ok(out) = Command::new(real_git).args(["hook", "list", "-h"]).output() else {
        return false;
    };
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    combined.contains("usage: git hook list")
}

fn cleanup_legacy_hooks_dir(real_git: &Path, global: bool, hooks_dir: &Path) -> Result<(), String> {
    let canonical_hooks_dir = fs::canonicalize(hooks_dir).unwrap_or_else(|_| hooks_dir.to_path_buf());
    let state_file = hooks_dir.join(".buttress-prev-hooks-path");
    let current_cfg = read_git_config_path(real_git, Some(global), "core.hooksPath");
    let points_to_ours = current_cfg
        .as_ref()
        .map(|p| {
            let cp = fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
            cp == canonical_hooks_dir
        })
        .unwrap_or(false);

    if points_to_ours {
        let prev = fs::read_to_string(&state_file)
            .ok()
            .map(|s| s.trim_end_matches('\n').to_string())
            .filter(|s| !s.is_empty());
        let mut cmd = Command::new(real_git);
        cmd.arg("config");
        if global {
            cmd.arg("--global");
        } else {
            cmd.arg("--local");
        }
        match prev {
            Some(ref p) => {
                let out = cmd
                    .args(["core.hooksPath", p])
                    .output()
                    .map_err(|e| format!("restore core.hooksPath: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "failed restoring prior core.hooksPath: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
            None => {
                let _ = cmd.args(["--unset", "core.hooksPath"]).output();
            }
        }
    }

    if hooks_dir.is_dir() {
        for &h in FORWARDED_GIT_HOOKS {
            let _ = fs::remove_file(hooks_dir.join(h));
        }
        let _ = fs::remove_file(&state_file);
        let _ = fs::remove_dir(hooks_dir);
    }
    Ok(())
}

/// Install hooks cleanly:
/// - On Git 2.56+ (`git hook list`), configures native `[hook "buttress-*"]` entries WITHOUT
///   touching `core.hooksPath` (so `git-lfs`, `pre-commit`, `husky`, and repo `.git/hooks/*`
///   work natively side-by-side!). Migrates cleanly off any older `git-buttress` `core.hooksPath`.
/// - On older Git, installs reversible `core.hooksPath` forwarding stubs with saved prior state.
pub fn enable_buttress(
    global: bool,
    wrapper_dir: Option<&Path>,
    no_wrapper: bool,
) -> Result<EnableReport, String> {
    let self_exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("locate git-buttress executable: {e}"))?;
    let real_git = resolve_real_git()?;

    let hooks_dir = if global {
        let home = env::var("HOME").map_err(|_| "HOME is not set")?;
        PathBuf::from(home).join(".config").join("git-buttress").join("hooks")
    } else {
        let repo = GitRepo::open(None)?;
        repo.common_dir().join("buttress-hooks")
    };

    let exe_str = self_exe
        .to_str()
        .ok_or("git-buttress executable path is not valid UTF-8")?;
    let real_git_str = real_git
        .to_str()
        .ok_or("real git executable path is not valid UTF-8")?;

    let use_native = supports_native_config_hooks(&real_git)
        && env::var_os("GIT_BUTTRESS_FORCE_LEGACY_HOOKSPATH").is_none();

    let report_hooks_dir = if use_native {
        // Migrate cleanly off any legacy `core.hooksPath` directory we previously installed.
        cleanup_legacy_hooks_dir(&real_git, global, &hooks_dir)?;

        let scope_flag = if global { "--global" } else { "--local" };
        let exe_q = posix_single_quote(exe_str);
        let pc_cmd = format!("{exe_q} seal-head --quiet");
        let tx_cmd = format!("{exe_q} __hook-reference-transaction");

        if !global {
            let _ = Command::new(&real_git)
                .args(["config", "--local", "buttress.disabled", "false"])
                .output();
        }
        for (key, val, replace_all) in [
            ("hook.buttress-post-commit.event", "post-commit", true),
            ("hook.buttress-post-commit.command", pc_cmd.as_str(), false),
            ("hook.buttress-post-commit.enabled", "true", false),
            ("hook.buttress-reference-transaction.event", "reference-transaction", true),
            ("hook.buttress-reference-transaction.command", tx_cmd.as_str(), false),
            ("hook.buttress-reference-transaction.enabled", "true", false),
        ] {
            let mut c = Command::new(&real_git);
            c.args(["config", scope_flag]);
            if replace_all {
                c.arg("--replace-all");
            }
            let out = c
                .args([key, val])
                .output()
                .map_err(|e| format!("git config {key}: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "git config {key} failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        None
    } else {
        fs::create_dir_all(&hooks_dir).map_err(|e| format!("create hooks dir: {e}"))?;
        let canonical_hooks_dir = fs::canonicalize(&hooks_dir).unwrap_or_else(|_| hooks_dir.clone());

        let state_file = hooks_dir.join(".buttress-prev-hooks-path");
        let current_cfg_hooks = read_git_config_path(&real_git, Some(global), "core.hooksPath");
        let is_already_ours = current_cfg_hooks
            .as_ref()
            .map(|p| {
                let cp = fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
                cp == canonical_hooks_dir
            })
            .unwrap_or(false);

        let saved_prev_hooks: Option<String> = if is_already_ours {
            fs::read_to_string(&state_file)
                .ok()
                .map(|s| s.trim_end_matches('\n').to_string())
                .filter(|s| !s.is_empty())
        } else {
            let p = current_cfg_hooks;
            write_atomic_regular(&state_file, p.as_deref().unwrap_or("").as_bytes(), 0o644)?;
            p
        };

        let global_buttress_hooks = env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config").join("git-buttress").join("hooks"))
            .map(|p| fs::canonicalize(&p).unwrap_or(p));
        let prev_hooks: Option<String> = if saved_prev_hooks.is_some() || global {
            saved_prev_hooks
        } else {
            read_git_config_path(&real_git, None, "core.hooksPath").filter(|p| {
                let cp = fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
                cp != canonical_hooks_dir && global_buttress_hooks.as_ref() != Some(&cp)
            })
        };

        let hooks_dir_str = hooks_dir
            .to_str()
            .ok_or("hooks directory path is not valid UTF-8")?;

        for &hook_name in FORWARDED_GIT_HOOKS {
            let script = match hook_name {
                "post-commit" => format!(
                    "#!/bin/sh\n{fwd}{exe} seal-head --quiet\n",
                    fwd = forward_hook_no_stdin(
                        prev_hooks.as_deref(),
                        hook_name,
                        real_git_str,
                        &canonical_hooks_dir
                    ),
                    exe = posix_single_quote(exe_str),
                ),
                "reference-transaction" => format!(
                    "#!/bin/sh\n{fwd}",
                    fwd = forward_reference_transaction(
                        prev_hooks.as_deref(),
                        real_git_str,
                        exe_str,
                        &canonical_hooks_dir
                    ),
                ),
                other => format!(
                    "#!/bin/sh\n{fwd}exit 0\n",
                    fwd = forward_hook_passthrough_stdin(
                        prev_hooks.as_deref(),
                        other,
                        real_git_str,
                        &canonical_hooks_dir
                    ),
                ),
            };
            write_atomic_regular(&hooks_dir.join(hook_name), script.as_bytes(), 0o755)?;
        }

        let mut cfg_cmd = Command::new(&real_git);
        cfg_cmd.arg("config");
        if global {
            cfg_cmd.arg("--global");
        } else {
            cfg_cmd.args(["--local", "buttress.disabled", "false"]);
            let _ = cfg_cmd.output();
            cfg_cmd = Command::new(&real_git);
            cfg_cmd.args(["config", "--local"]);
        }
        let out = cfg_cmd
            .args(["core.hooksPath", hooks_dir_str])
            .output()
            .map_err(|e| format!("git config core.hooksPath: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git config failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Some(hooks_dir)
    };

    let mut installed_wrapper: Option<PathBuf> = None;
    let mut installed_subcmd: Option<PathBuf> = None;
    if !no_wrapper && (global || wrapper_dir.is_some()) {
        let bin_dir = match wrapper_dir {
            Some(d) => d.to_path_buf(),
            None => {
                let home = env::var("HOME").map_err(|_| "HOME is not set")?;
                PathBuf::from(home).join(".local").join("bin")
            }
        };
        fs::create_dir_all(&bin_dir).map_err(|e| format!("create {}: {e}", bin_dir.display()))?;

        let subcmd_dest = bin_dir.join("git-buttress");
        if subcmd_dest != self_exe && fs::symlink_metadata(&subcmd_dest).is_err() {
            #[cfg(unix)]
            {
                if std::os::unix::fs::symlink(&self_exe, &subcmd_dest).is_ok() {
                    installed_subcmd = Some(subcmd_dest);
                }
            }
        }

        let git_dest = bin_dir.join("git");
        let can_install_wrapper = match fs::symlink_metadata(&git_dest) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Ok(meta) if meta.file_type().is_file() && is_our_wrapper(&git_dest) => true,
            _ => false, // Refuse to overwrite symlinks (even dangling) or unrelated binaries!
        };
        if can_install_wrapper {
            let marker = std::str::from_utf8(WRAPPER_MARKER).unwrap();
            let script = format!(
                "#!/bin/sh\n{marker}\nexport GIT_BUTTRESS_REAL_GIT={real}\nexec {exe} __wrap-git \"$@\"\n",
                real = posix_single_quote(real_git_str),
                exe = posix_single_quote(exe_str)
            );
            write_atomic_regular(&git_dest, script.as_bytes(), 0o755)?;
            installed_wrapper = Some(git_dest);
        }
    }

    Ok(EnableReport {
        hooks_dir: report_hooks_dir,
        native_hooks: use_native,
        wrapper_path: installed_wrapper,
        subcmd_path: installed_subcmd,
    })
}

/// Reversibly disable `git-buttress` (`H10` fix):
/// - Removes native `[hook "buttress-*"]` config sections (and disables global native hooks locally).
/// - Restores any saved prior `core.hooksPath` (if `core.hooksPath` currently points to our `hooks_dir`),
///   never clobbering an unrelated `core.hooksPath`.
/// - For `--local`, sets `buttress.disabled = true` so a global wrapper/hook also respects local disable!
/// - Removes generated hook scripts and our `git` wrapper script cleanly.
pub fn disable_buttress(global: bool, wrapper_dir: Option<&Path>) -> Result<(), String> {
    let real_git = resolve_real_git()?;
    let hooks_dir = if global {
        let home = env::var("HOME").map_err(|_| "HOME is not set")?;
        PathBuf::from(home).join(".config").join("git-buttress").join("hooks")
    } else {
        let repo = GitRepo::open(None)?;
        repo.common_dir().join("buttress-hooks")
    };

    let scope_flag = if global { "--global" } else { "--local" };
    for section in [
        "hook.buttress-post-commit",
        "hook.buttress-reference-transaction",
    ] {
        let _ = Command::new(&real_git)
            .args(["config", scope_flag, "--remove-section", section])
            .output();
    }

    cleanup_legacy_hooks_dir(&real_git, global, &hooks_dir)?;

    if !global {
        // Set local `buttress.disabled = true` AND disable global native hooks in this repo!
        let _ = Command::new(&real_git)
            .args(["config", "--local", "buttress.disabled", "true"])
            .output();
        for key in [
            "hook.buttress-post-commit.enabled",
            "hook.buttress-reference-transaction.enabled",
        ] {
            let _ = Command::new(&real_git)
                .args(["config", "--local", key, "false"])
                .output();
        }
    }

    if global || wrapper_dir.is_some() {
        let bin_dir = match wrapper_dir {
            Some(d) => d.to_path_buf(),
            None => {
                let home = env::var("HOME").map_err(|_| "HOME is not set")?;
                PathBuf::from(home).join(".local").join("bin")
            }
        };
        let git_dest = bin_dir.join("git");
        if let Ok(meta) = fs::symlink_metadata(&git_dest)
            && meta.file_type().is_file()
            && is_our_wrapper(&git_dest)
        {
            fs::remove_file(&git_dest)
                .map_err(|e| format!("remove {}: {e}", git_dest.display()))?;
        }
    }
    Ok(())
}

pub struct EnableReport {
    pub hooks_dir: Option<PathBuf>,
    pub native_hooks: bool,
    pub wrapper_path: Option<PathBuf>,
    pub subcmd_path: Option<PathBuf>,
}

/// Quote an arbitrary string as a literal POSIX `sh` single-quoted token (`'...'` with `'` -> `'\''`).
pub fn posix_single_quote(s: &str) -> String {
    assert!(!s.contains('\0'), "POSIX shell token cannot contain NUL");
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn read_git_config_path(real_git: &Path, scope_global: Option<bool>, key: &str) -> Option<String> {
    let mut c = Command::new(real_git);
    c.arg("config");
    match scope_global {
        Some(true) => {
            c.arg("--global");
        }
        Some(false) => {
            c.arg("--local");
        }
        None => {}
    }
    let out = c.args(["--get", "--path", key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn forward_hook_no_stdin(
    prev_dir: Option<&str>,
    hook_name: &str,
    real_git_str: &str,
    _our_canonical_hooks_dir: &Path,
) -> String {
    let real_q = posix_single_quote(real_git_str);
    let guard_var = format!(
        "GIT_BUTTRESS_FWD_{}",
        hook_name.to_ascii_uppercase().replace('-', "_")
    );
    let find_local = format!(
        "COMMON_DIR=$({real_q} rev-parse --git-common-dir 2>/dev/null || true)\n\
         if [ -n \"$COMMON_DIR\" ] && [ -x \"$COMMON_DIR/hooks/{hook_name}\" ]; then\n\
           {guard_var}=1 \"$COMMON_DIR/hooks/{hook_name}\" \"$@\" || exit $?\n\
         fi\n"
    );
    match prev_dir {
        // Match stock Git semantics (`R2-H5` fix): when a prior `core.hooksPath` was configured,
        // dispatch ONLY to that directory — do NOT fall back to `$COMMON_DIR/hooks`, which would
        // unexpectedly re-enable hooks the user had disabled via `core.hooksPath`!
        Some(d) => {
            let p_q = posix_single_quote(&format!("{}/{hook_name}", d.trim_end_matches('/')));
            format!(
                "if [ -z \"${{{guard_var}:-}}\" ] && [ -x {p_q} ]; then\n\
                   {guard_var}=1 {p_q} \"$@\" || exit $?\n\
                 fi\n"
            )
        }
        None => format!(
            "if [ -z \"${{{guard_var}:-}}\" ]; then\n\
               {find_local}\
             fi\n"
        ),
    }
}

fn forward_hook_passthrough_stdin(
    prev_dir: Option<&str>,
    hook_name: &str,
    real_git_str: &str,
    _our_canonical_hooks_dir: &Path,
) -> String {
    let real_q = posix_single_quote(real_git_str);
    let guard_var = format!(
        "GIT_BUTTRESS_FWD_{}",
        hook_name.to_ascii_uppercase().replace('-', "_")
    );
    let find_local = format!(
        "COMMON_DIR=$({real_q} rev-parse --git-common-dir 2>/dev/null || true)\n\
         if [ -n \"$COMMON_DIR\" ] && [ -x \"$COMMON_DIR/hooks/{hook_name}\" ]; then\n\
           export {guard_var}=1\n\
           exec \"$COMMON_DIR/hooks/{hook_name}\" \"$@\"\n\
         fi\n"
    );
    match prev_dir {
        Some(d) => {
            let p_q = posix_single_quote(&format!("{}/{hook_name}", d.trim_end_matches('/')));
            format!(
                "if [ -z \"${{{guard_var}:-}}\" ] && [ -x {p_q} ]; then\n\
                   export {guard_var}=1; exec {p_q} \"$@\"\n\
                 fi\n"
            )
        }
        None => format!(
            "if [ -z \"${{{guard_var}:-}}\" ]; then\n\
               {find_local}\
             fi\n"
        ),
    }
}

/// Binary-safe stdin replay via `mktemp` file (preserves exact bytes & trailing newlines, unlike `$(cat)`!).
fn forward_reference_transaction(
    prev_dir: Option<&str>,
    real_git_str: &str,
    exe_str: &str,
    _our_canonical_hooks_dir: &Path,
) -> String {
    let real_q = posix_single_quote(real_git_str);
    let exe_q = posix_single_quote(exe_str);
    let find_prev = match prev_dir {
        Some(d) => {
            let p_q = posix_single_quote(&format!(
                "{}/reference-transaction",
                d.trim_end_matches('/')
            ));
            format!(
                "PREV_HOOK=\"\"\n\
                 if [ -z \"${{GIT_BUTTRESS_FWD_REFTX:-}}\" ] && [ -x {p_q} ]; then PREV_HOOK={p_q}; fi"
            )
        }
        None => format!(
            "PREV_HOOK=\"\"\n\
             if [ -z \"${{GIT_BUTTRESS_FWD_REFTX:-}}\" ]; then\n\
               COMMON_DIR=$({real_q} rev-parse --git-common-dir 2>/dev/null || true)\n\
               if [ -n \"$COMMON_DIR\" ] && [ -x \"$COMMON_DIR/hooks/reference-transaction\" ]; then PREV_HOOK=\"$COMMON_DIR/hooks/reference-transaction\"; fi\n\
             fi"
        ),
    };
    format!(
        "{find_prev}\n\
         if [ -n \"$PREV_HOOK\" ] && [ -x \"$PREV_HOOK\" ]; then\n\
           TMPF=$(mktemp \"${{TMPDIR:-/tmp}}/buttress-reftx.XXXXXX\") || exit 1\n\
           cat > \"$TMPF\" || {{ rm -f \"$TMPF\"; exit 1; }}\n\
           GIT_BUTTRESS_FWD_REFTX=1 \"$PREV_HOOK\" \"$@\" < \"$TMPF\" || {{ RC=$?; rm -f \"$TMPF\"; exit $RC; }}\n\
           {exe_q} __hook-reference-transaction \"$@\" < \"$TMPF\"\n\
           RC=$?; rm -f \"$TMPF\"; exit $RC\n\
         else\n\
           exec {exe_q} __hook-reference-transaction \"$@\"\n\
         fi\n"
    )
}

/// Write a regular file atomically via exclusive temp file + `rename` (never follows symlinks at `dest`!).
fn write_atomic_regular(dest: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    let parent = dest.parent().ok_or("destination has no parent directory")?;
    let pid = std::process::id();
    for attempt in 0u32..500 {
        let tmp = parent.join(format!(
            ".buttress-tmp-{pid}-{attempt}-{}",
            dest.file_name().and_then(|n| n.to_str()).unwrap_or("f")
        ));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        match opts.open(&tmp) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(content) {
                    let _ = fs::remove_file(&tmp);
                    return Err(format!("write {}: {e}", tmp.display()));
                }
                let mut perms = f
                    .metadata()
                    .map_err(|e| format!("stat {}: {e}", tmp.display()))?
                    .permissions();
                perms.set_mode(mode);
                let _ = fs::set_permissions(&tmp, perms);
                drop(f);
                fs::rename(&tmp, dest).map_err(|e| {
                    let _ = fs::remove_file(&tmp);
                    format!("rename {} -> {}: {e}", tmp.display(), dest.display())
                })?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create temp file {}: {e}", tmp.display())),
        }
    }
    Err(format!("could not create atomic temp file for {}", dest.display()))
}
