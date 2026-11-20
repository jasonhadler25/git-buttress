//! Zero-friction setup (`enable` / `disable`), transparent `git` wrapper,
//! `post-commit` sealing, and `reference-transaction` tag minting + fetch/clone/pull verification.
//!
//! # Module Contract & Safety Invariants
//!
//! 1. **Shell-injection-free hook & wrapper generation:** All paths interpolated into
//!    POSIX `#!/bin/sh` scripts (`post-commit`, `reference-transaction`, `~/.local/bin/git`)
//!    MUST pass through `posix_single_quote()` (`'...'` with `'` -> `'\''`), so paths
//!    containing spaces, `$`, `` ` ``, `"`, `\`, or `;` never execute unintended shell code.
//! 2. **Atomic compare-and-swap on `seal_head`:** `seal_head` updates the symbolic target
//!    of `HEAD` (when on a branch) or `HEAD` with `--no-deref` (when detached), passing
//!    both `<new_oid>` and `<expected_old_oid>` to `git update-ref` so concurrent ref
//!    updates fail closed instead of clobbering.
//! 3. **Fail-closed incoming ref verification (`reference-transaction` `prepared`):**
//!    Every non-deletion, non-symbolic ref update on `refs/remotes/*`, `refs/tags/*`, or
//!    any ref containing `"+blake3-"` is verified with `DigestCache::memory_only()` before
//!    Git commits the ref transaction. Any `Mismatch` returns `Err` (exit 1), causing Git
//!    to abort the ref transaction cleanly.
//! 4. **Tag companion minting (`committed` phase):** Companion `refs/tags/<name>+blake3-<dig>`
//!    is minted on both tag creation (`old == 0`) and forced tag update (`git tag -f`),
//!    peeling annotated tag chains with cycle detection, and never firing on remote fetches.

use crate::cache::{Dig, DigestCache, Oid};
use crate::git::{GitRepo, ObjKind, ObjectStore, WRAPPER_MARKER, hex_to_oid, resolve_real_git, to_hex};
use crate::protocol::{
    CheckOutcome, CommitClass, ContextKeys, Engine, VerifyError, VerifyErrorKind,
    parse_ref_embedded_b3, split_headers_body, strip_blake3_and_sig_headers, verify_target,
};
use std::env;
use std::fs;
use std::io::{BufRead, Write};
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
            None => repo.config_get("buttress.missing").unwrap_or_else(|| "silent".into()),
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

/// Sign a commit or tag payload using the repository's configured SSH or OpenPGP key.
pub fn sign_payload(repo: &GitRepo, payload: &[u8]) -> Result<Vec<u8>, String> {
    let fmt = repo
        .config_get("gpg.format")
        .unwrap_or_else(|| "openpgp".into())
        .to_ascii_lowercase();
    let key = repo.config_get("user.signingkey");

    if fmt == "ssh" {
        let Some(key_str) = key else {
            return Err("gpg.format=ssh requires user.signingkey to be set".into());
        };
        let key_path = expand_tilde(&key_str);
        let tmp_dir = env::temp_dir().join(format!(
            "git-buttress-sig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&tmp_dir).map_err(|e| format!("create temp dir: {e}"))?;
        let payload_file = tmp_dir.join("payload");
        fs::write(&payload_file, payload).map_err(|e| format!("write payload: {e}"))?;
        let ssh_prog = repo
            .config_get("gpg.ssh.program")
            .unwrap_or_else(|| "ssh-keygen".into());
        let out = Command::new(&ssh_prog)
            .args([
                "-Y",
                "sign",
                "-n",
                "git",
                "-f",
                &key_path,
                payload_file.to_str().unwrap(),
            ])
            .output();
        let sig_file = tmp_dir.join("payload.sig");
        let sig_bytes = fs::read(&sig_file);
        let _ = fs::remove_dir_all(&tmp_dir);
        let out = out.map_err(|e| format!("run {ssh_prog}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{ssh_prog} sign failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let mut sig = sig_bytes.map_err(|e| format!("read ssh signature: {e}"))?;
        while sig.last() == Some(&b'\n') {
            sig.pop();
        }
        return Ok(sig);
    }

    if fmt == "openpgp" {
        let gpg_prog = repo
            .config_get("gpg.openpgp.program")
            .or_else(|| repo.config_get("gpg.program"))
            .unwrap_or_else(|| "gpg".into());
        let mut cmd = Command::new(&gpg_prog);
        cmd.args(["--status-fd=2", "-bsa"]);
        if let Some(ref k) = key {
            cmd.args(["-u", k]);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("run {gpg_prog}: {e}"))?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload)
            .map_err(|e| format!("write gpg stdin: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("wait gpg: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{gpg_prog} sign failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let mut sig = out.stdout;
        while sig.last() == Some(&b'\n') {
            sig.pop();
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

fn expand_tilde(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    s.to_string()
}

/// Idempotently seal `HEAD` in place (used by `post-commit` and `git buttress seal-head`).
pub fn seal_head(repo: &mut GitRepo, force_sign: bool, quiet: bool) -> Result<(Oid, Dig), String> {
    if env::var_os("GIT_BUTTRESS_INTERNAL").is_some() {
        let h = repo.rev_parse("HEAD")?;
        return Ok((h, [0u8; 32]));
    }

    let head_oid = repo.rev_parse("HEAD")?;
    let keys = ContextKeys::new();
    let cache = DigestCache::load_from_git_dir(&repo.common_dir);

    let (new_raw, commit_dig, already_sealed) = {
        let mut engine = Engine::new(repo, &keys, cache);
        let pc = engine
            .load_commit(head_oid)
            .map_err(|e| format!("parse HEAD: {}", e.message))?;

        if let CommitClass::Sealed {
            expected_tree,
            ref expected_parents,
        } = pc.class
        {
            let actual_tree = engine
                .digest_tree(pc.tree)
                .map_err(|e| format!("hash tree: {}", e.message))?;
            let mut parents_ok = expected_parents.len() == pc.parents.len();
            if parents_ok {
                for (&p, exp_p) in pc.parents.iter().zip(expected_parents.iter()) {
                    let (pd, _) = engine
                        .digest_commit(p)
                        .map_err(|e| format!("hash parent: {}", e.message))?;
                    if pd != *exp_p {
                        parents_ok = false;
                        break;
                    }
                }
            }
            if actual_tree == expected_tree && parents_ok {
                let d = keys.hash_sealed_commit(&pc.raw);
                engine.cache.put_commit(head_oid, d);
                engine.cache.flush();
                return Ok((head_oid, d));
            }
        }

        let tree_dig = engine
            .digest_tree(pc.tree)
            .map_err(|e| format!("hash tree: {}", e.message))?;
        let mut parent_digs = Vec::with_capacity(pc.parents.len());
        for &p in &pc.parents {
            let (pd, _) = engine
                .digest_commit(p)
                .map_err(|e| format!("hash parent {}: {}", to_hex(&p), e.message))?;
            parent_digs.push(pd);
        }
        engine.cache.flush();

        let (header_bytes, body_bytes) = split_headers_body(&pc.raw);
        let mut lines = strip_blake3_and_sig_headers(header_bytes);
        lines.push(
            format!("buttress-tree blake3 {} {}", to_hex(&pc.tree), to_hex(&tree_dig)).into_bytes(),
        );
        for pd in &parent_digs {
            lines.push(format!("buttress-parent blake3 {}", to_hex(pd)).into_bytes());
        }

        let mut unsigned = Vec::with_capacity(pc.raw.len() + 256);
        for line in &lines {
            unsigned.extend_from_slice(line);
            unsigned.push(b'\n');
        }
        unsigned.push(b'\n');
        unsigned.extend_from_slice(body_bytes);

        let want_sign = force_sign || pc.has_gpgsig;
        (unsigned, want_sign, false)
    };
    let _ = already_sealed;

    let (unsigned_payload, want_sign) = (new_raw, commit_dig);
    let final_raw = if want_sign {
        let sig = sign_payload(repo, &unsigned_payload)?;
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
    let sealed_dig = keys.hash_sealed_commit(&final_raw);

    let (_, body) = split_headers_body(&final_raw);
    let subj = String::from_utf8_lossy(body)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let reflog = format!("commit (buttress): {subj}");

    // Atomic compare-and-swap on the exact target ref (branch ref if symbolic, else `--no-deref HEAD`)
    let sym_target = repo
        .cmd()
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let mut cmd = repo.cmd();
    cmd.env("GIT_BUTTRESS_INTERNAL", "1");
    cmd.args(["update-ref", "-m", &reflog]);
    if let Some(ref target_ref) = sym_target {
        cmd.args([target_ref.as_str(), &to_hex(&new_oid), &to_hex(&head_oid)]);
    } else {
        cmd.args(["--no-deref", "HEAD", &to_hex(&new_oid), &to_hex(&head_oid)]);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("git update-ref: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let mut cache = DigestCache::load_from_git_dir(&repo.common_dir);
    cache.put_commit(new_oid, sealed_dig);
    cache.flush();

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

/// Handle Git's `reference-transaction` hook (`preparing`, `prepared`, `committed`, `aborted`).
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if env::var_os("GIT_BUTTRESS_INTERNAL").is_some() {
        return Ok(());
    }
    if phase != "prepared" && phase != "committed" {
        return Ok(());
    }

    let stdin = std::io::stdin();
    let updates: Vec<(String, String, String)> = stdin
        .lock()
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let old = it.next()?.to_string();
            let new = it.next()?.to_string();
            let refname = it.next()?.to_string();
            Some((old, new, refname))
        })
        .collect();

    if updates.is_empty() {
        return Ok(());
    }

    let Ok(mut repo) = GitRepo::open(None) else {
        return Ok(());
    };
    if repo.config_bool("buttress.disabled", false) {
        return Ok(());
    }

    let zero = "0000000000000000000000000000000000000000";

    if phase == "prepared" {
        // Verify incoming remote updates (`clone`, `fetch`, `pull`) and any `+blake3-` ref!
        let keys = ContextKeys::new();
        let policy = MissingPolicy::from_repo(&repo, None)?;

        // Collect which target OIDs also have a `+blake3-` tag in this same transaction so we don't
        // falsely warn about the plain companion `v2.4.0` tag arriving alongside `v2.4.0+blake3-...`.
        let mut targets_with_b3_tag = std::collections::HashSet::new();
        for (_, new_s, refname) in &updates {
            if new_s != zero
                && !new_s.starts_with("ref:")
                && parse_ref_embedded_b3(refname).ok().flatten().is_some()
            {
                targets_with_b3_tag.insert(new_s.clone());
            }
        }

        let mut verified_oids = std::collections::HashSet::new();

        for (_, new_s, refname) in &updates {
            if new_s == zero || new_s.starts_with("ref:") {
                continue;
            }
            let has_b3_name = match parse_ref_embedded_b3(refname) {
                Ok(opt) => opt.is_some(),
                Err(e) => {
                    return Err(format!("buttress: {}", e.message));
                }
            };
            let is_remote_ref = refname.starts_with("refs/remotes/");
            let is_tag_ref = refname.starts_with("refs/tags/");

            if !has_b3_name && !is_remote_ref && !is_tag_ref {
                continue;
            }

            let Ok(oid) = hex_to_oid(new_s.as_bytes()) else {
                continue;
            };

            // For local `git tag v2.4.0` where no `+blake3-` name is present and target is already local:
            // still verify if sealed, so tagging a corrupted object fails immediately!
            if !has_b3_name && verified_oids.contains(&oid) {
                continue;
            }

            match verify_target(&mut repo, &keys, oid, Some(refname), None, true) {
                Ok(CheckOutcome::Match { .. }) => {
                    verified_oids.insert(oid);
                }
                Ok(CheckOutcome::NoEvidence { .. }) => {
                    verified_oids.insert(oid);
                    if !targets_with_b3_tag.contains(new_s) {
                        match policy {
                            MissingPolicy::Silent => {}
                            MissingPolicy::Warn => {
                                eprintln!(
                                    "buttress: warning: {refname} ({}) has no BLAKE3 buttress evidence",
                                    &new_s[..12]
                                );
                            }
                            MissingPolicy::Error => {
                                return Err(format!(
                                    "buttress: error: {refname} ({}) has no BLAKE3 buttress evidence (buttress.missing=error)",
                                    &new_s[..12]
                                ));
                            }
                        }
                    }
                }
                Err(VerifyError {
                    kind: VerifyErrorKind::Mismatch,
                    message,
                }) => {
                    return Err(format!("buttress: MISMATCH on {refname}\n  {message}"));
                }
                Err(VerifyError {
                    kind: VerifyErrorKind::Incomplete,
                    message,
                }) => {
                    // During partial clone (`--filter=blob:none`), warn clearly and fail if +blake3- was explicitly pinned.
                    if has_b3_name || policy == MissingPolicy::Error {
                        return Err(format!(
                            "buttress: incomplete objects for {refname}: {message}"
                        ));
                    }
                    eprintln!("buttress: note: could not fully check {refname} ({message})");
                }
            }
        }
        return Ok(());
    }

    // phase == "committed":
    // When the user creates a plain tag `refs/tags/<name>` locally (not during fetch/clone!),
    // automatically mint the companion tag `refs/tags/<name>+blake3-<64-hex>`!
    let auto_tag = repo.config_bool("buttress.autotag", true);
    if !auto_tag {
        return Ok(());
    }
    // Heuristic: if `refs/remotes/*` is also in this transaction (or `FETCH_HEAD` is being fetched),
    // this transaction came from `fetch` / `clone` / `pull`, NOT `git tag`!
    if updates.iter().any(|(_, _, r)| r.starts_with("refs/remotes/")) {
        return Ok(());
    }
    // Also skip if Git is running `fetch`, `clone`, or `pull` (check GIT_REFLOG_ACTION).
    if let Ok(action) = env::var("GIT_REFLOG_ACTION") {
        let a = action.to_ascii_lowercase();
        if a.starts_with("clone") || a.starts_with("fetch") || a.starts_with("pull") {
            return Ok(());
        }
    }

    let keys = ContextKeys::new();
    for (_old_s, new_s, refname) in &updates {
        if new_s == zero || new_s.starts_with("ref:") {
            continue;
        }
        let Some(tag_name) = refname.strip_prefix("refs/tags/") else {
            continue;
        };
        if tag_name.contains("+blake3-") {
            continue;
        }
        let Ok(oid) = hex_to_oid(new_s.as_bytes()) else {
            continue;
        };
        // Compute the target object's BLAKE3 digest (peeling annotated tags with cycle guard)
        let target_dig = {
            let mut cur_oid = oid;
            let mut seen_tags = std::collections::HashSet::new();
            seen_tags.insert(cur_oid);
            loop {
                let Some((kind, raw)) = repo.read_object(&cur_oid)? else {
                    return Ok(());
                };
                if kind == ObjKind::Tag {
                    let (next_oid, _, _) =
                        crate::protocol::parse_annotated_tag(&raw).map_err(|e| e.message)?;
                    if !seen_tags.insert(next_oid) {
                        return Err(format!("buttress: cyclic tag chain at {}", to_hex(&next_oid)));
                    }
                    cur_oid = next_oid;
                } else {
                    let cache = DigestCache::load_from_git_dir(&repo.common_dir);
                    let mut engine = Engine::new(&mut repo, &keys, cache);
                    let d = match kind {
                        ObjKind::Commit => {
                            engine
                                .digest_commit(cur_oid)
                                .map_err(|e| e.message)?
                                .0
                        }
                        ObjKind::Tree => engine.digest_tree(cur_oid).map_err(|e| e.message)?,
                        ObjKind::Blob => engine.digest_blob(cur_oid).map_err(|e| e.message)?,
                        ObjKind::Tag => unreachable!(),
                    };
                    engine.cache.flush();
                    break d;
                }
            }
        };

        let companion = format!("refs/tags/{tag_name}+blake3-{}", to_hex(&target_dig));
        if repo.try_rev_parse(&companion) == Some(oid) {
            continue;
        }
        let mut cmd = repo.cmd();
        cmd.env("GIT_BUTTRESS_INTERNAL", "1");
        let out = cmd.args(["update-ref", &companion, new_s]).output();
        if let Ok(o) = out {
            if o.status.success() {
                eprintln!(
                    "buttress: also created tag {tag_name}+blake3-{}",
                    to_hex(&target_dig)
                );
            }
        }
    }

    Ok(())
}

/// Transparent `git` wrapper execution (`git-buttress __wrap-git <args...>`).
///
/// Eliminates the `post-commit` summary-ID mismatch on `git commit` AND makes
/// plain `git fsck` run `git buttress fsck` right after stock `git fsck`!
pub fn run_git_wrapper(args: &[String]) -> i32 {
    let real_git = match resolve_real_git() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("git-buttress wrapper: {e}");
            return 127;
        }
    };

    // Parse leading global git options (`-C <dir>`, `-c k=v`, `--git-dir=...`, etc.)
    let (subcmd_idx, work_dir, git_dir_ovr, cfg_overrides) = find_git_subcommand(args);
    let subcmd = subcmd_idx.map(|i| args[i].as_str());

    match subcmd {
        Some("commit") => wrap_git_commit(
            &real_git,
            args,
            subcmd_idx.unwrap(),
            work_dir.as_deref(),
            git_dir_ovr.as_deref(),
            &cfg_overrides,
        ),
        Some("fsck") => wrap_git_fsck(
            &real_git,
            args,
            work_dir.as_deref(),
            git_dir_ovr.as_deref(),
            &cfg_overrides,
        ),
        _ => exec_or_spawn(&real_git, args),
    }
}

/// Parse leading global `git` flags before the subcommand name, tracking `-C <dir>`,
/// `--git-dir`, and `-c k=v` overrides so wrapper post-actions inspect the exact same
/// repository and configuration that stock `git` operated on!
fn find_git_subcommand(args: &[String]) -> (Option<usize>, Option<PathBuf>, Option<PathBuf>, Vec<String>) {
    let mut i = 0;
    let mut cwd: Option<PathBuf> = None;
    let mut git_dir_override: Option<PathBuf> = None;
    let mut config_overrides: Vec<String> = Vec::new();
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return (None, cwd, git_dir_override, config_overrides);
        }
        if !a.starts_with('-') {
            return (Some(i), cwd, git_dir_override, config_overrides);
        }
        if a == "-C" {
            if i + 1 < args.len() {
                let p = PathBuf::from(&args[i + 1]);
                cwd = Some(match cwd {
                    Some(base) if p.is_relative() => base.join(p),
                    _ => p,
                });
                i += 2;
                continue;
            }
        } else if let Some(rest) = a.strip_prefix("-C") {
            if !rest.is_empty() {
                let p = PathBuf::from(rest);
                cwd = Some(match cwd {
                    Some(base) if p.is_relative() => base.join(p),
                    _ => p,
                });
                i += 1;
                continue;
            }
        } else if a == "-c" {
            if i + 1 < args.len() {
                config_overrides.push(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if let Some(rest) = a.strip_prefix("-c") {
            if !rest.is_empty() {
                config_overrides.push(rest.to_string());
                i += 1;
                continue;
            }
        } else if a == "--git-dir" {
            if i + 1 < args.len() {
                git_dir_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
                continue;
            }
        } else if let Some(rest) = a.strip_prefix("--git-dir=") {
            git_dir_override = Some(PathBuf::from(rest));
            i += 1;
            continue;
        } else if matches!(
            a,
            "--work-tree" | "--namespace" | "--super-prefix" | "--config-env"
        ) {
            i += 2;
            continue;
        }
        i += 1;
    }
    (None, cwd, git_dir_override, config_overrides)
}

fn commit_args_suppress_or_preview(commit_args: &[String]) -> (bool, bool) {
    // Returns `(user_passed_quiet, skip_summary_intercept)`
    let mut user_quiet = false;
    let mut i = 0;
    while i < commit_args.len() {
        let a = commit_args[i].as_str();
        if a == "--" {
            break;
        }
        if matches!(
            a,
            "--dry-run"
                | "--short"
                | "--porcelain"
                | "--long"
                | "-z"
                | "-h"
                | "--help"
                | "--no-verify"
                | "-n"
        ) {
            return (user_quiet, true);
        }
        if a == "-q" || a == "--quiet" {
            user_quiet = true;
        } else if a.starts_with('-') && !a.starts_with("--") && a.len() > 2 {
            // Combined short flags like `-qam` or `-am`: stop scanning if `-m` or `-F` consumes rest
            for ch in a[1..].chars() {
                if ch == 'q' {
                    user_quiet = true;
                }
                if ch == 'n' || ch == 'h' {
                    return (user_quiet, true);
                }
                if matches!(ch, 'm' | 'F' | 'c' | 'C' | 'u') {
                    break;
                }
            }
            if a.ends_with('m') || a.ends_with('F') || a.ends_with('c') || a.ends_with('C') {
                i += 2;
                continue;
            }
        } else if matches!(
            a,
            "-m" | "--message"
                | "-F"
                | "--file"
                | "-c"
                | "--reedit-message"
                | "-C"
                | "--reuse-message"
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
    (user_quiet, false)
}

fn has_cli_disabled(cfg_overrides: &[String]) -> Option<bool> {
    let mut res: Option<bool> = None;
    for kv in cfg_overrides {
        if let Some((k, v)) = kv.split_once('=') {
            if k.trim().eq_ignore_ascii_case("buttress.disabled") {
                let v = v.trim();
                res = Some(matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "yes" | "on" | "1"
                ));
            }
        } else if kv.trim().eq_ignore_ascii_case("buttress.disabled") {
            // In Git `-c section.key` without `=` means boolean `true`
            res = Some(true);
        }
    }
    res
}

fn resolve_target_repo(work_dir: Option<&Path>, git_dir_ovr: Option<&Path>) -> Option<GitRepo> {
    if let Some(gd) = git_dir_ovr {
        let base = work_dir
            .map(PathBuf::from)
            .or_else(|| env::current_dir().ok())?;
        let full_gd = if gd.is_absolute() {
            gd.to_path_buf()
        } else {
            base.join(gd)
        };
        GitRepo::open(Some(&full_gd)).ok()
    } else {
        let d = work_dir
            .map(PathBuf::from)
            .or_else(|| env::current_dir().ok())?;
        GitRepo::open(Some(&d)).ok()
    }
}

fn wrap_git_commit(
    real_git: &Path,
    args: &[String],
    subcmd_idx: usize,
    work_dir: Option<&Path>,
    git_dir_ovr: Option<&Path>,
    cfg_overrides: &[String],
) -> i32 {
    let commit_args = &args[subcmd_idx + 1..];
    let (user_quiet, skip_intercept) = commit_args_suppress_or_preview(commit_args);
    if skip_intercept || user_quiet || has_cli_disabled(cfg_overrides) == Some(true) {
        return exec_or_spawn(real_git, args);
    }

    let old_head = resolve_target_repo(work_dir, git_dir_ovr).and_then(|r| r.try_rev_parse("HEAD"));

    // Inject `-q` right after `commit` so stock Git doesn't print the pre-seal short SHA!
    let mut patched = Vec::with_capacity(args.len() + 1);
    patched.extend_from_slice(&args[..=subcmd_idx]);
    patched.push("-q".to_string());
    patched.extend_from_slice(&args[subcmd_idx + 1..]);

    let status = Command::new(real_git)
        .args(&patched)
        .env("GIT_BUTTRESS_REAL_GIT", real_git)
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

    // Ensure HEAD is sealed (covers repos using local hooks that didn't call our global post-commit)
    // and print the exact Git commit summary with the true sealed SHA!
    if let Some(mut repo) = resolve_target_repo(work_dir, git_dir_ovr) {
        let disabled = has_cli_disabled(cfg_overrides)
            .unwrap_or_else(|| repo.config_bool("buttress.disabled", false));
        if !disabled {
            let _ = seal_head(&mut repo, false, true);
        }
        print_commit_summary(&repo, old_head.is_none());
    }
    0
}

fn print_commit_summary(repo: &GitRepo, was_unborn: bool) {
    let branch = repo
        .cmd()
        .args(["symbolic-ref", "--short", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "detached HEAD".into());
    let short_sha = repo
        .cmd()
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let subject = repo
        .cmd()
        .args(["log", "-1", "--format=%s", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let parent_count = repo
        .try_rev_parse("HEAD^")
        .is_some();

    if was_unborn || !parent_count {
        println!("[{branch} (root-commit) {short_sha}] {subject}");
    } else {
        println!("[{branch} {short_sha}] {subject}");
    }

    if let Ok(out) = repo
        .cmd()
        .args(["diff-tree", "--stat", "--summary", "--root", "HEAD"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for (idx, line) in text.lines().enumerate() {
            if idx > 0 {
                println!("{line}");
            }
        }
    }
}

fn wrap_git_fsck(
    real_git: &Path,
    args: &[String],
    work_dir: Option<&Path>,
    git_dir_ovr: Option<&Path>,
    cfg_overrides: &[String],
) -> i32 {
    let status = Command::new(real_git)
        .args(args)
        .env("GIT_BUTTRESS_REAL_GIT", real_git)
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
    // Do not run buttress check if the user only asked for `git fsck -h`
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return 0;
    }
    let Some(mut repo) = resolve_target_repo(work_dir, git_dir_ovr) else {
        return 0;
    };
    let disabled = has_cli_disabled(cfg_overrides)
        .unwrap_or_else(|| repo.config_bool("buttress.disabled", false));
    if disabled {
        return 0;
    }
    match fsck_all_refs(&mut repo, None) {
        Ok((matched, _)) => {
            if matched > 0 {
                eprintln!("buttress fsck: {matched} ref(s) verified with BLAKE3");
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn exec_or_spawn(real_git: &Path, args: &[String]) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(real_git)
            .args(args)
            .env("GIT_BUTTRESS_REAL_GIT", real_git)
            .exec();
        eprintln!("git-buttress: exec {:?} failed: {err}", real_git);
        127
    }
    #[cfg(not(unix))]
    {
        Command::new(real_git)
            .args(args)
            .env("GIT_BUTTRESS_REAL_GIT", real_git)
            .status()
            .map(|s| s.code().unwrap_or(1))
            .unwrap_or(127)
    }
}

/// Audit all refs in the repository (`git buttress fsck` and wrapped `git fsck`).
pub fn fsck_all_refs(
    repo: &mut GitRepo,
    policy_override: Option<&str>,
) -> Result<(usize, usize), String> {
    let policy = MissingPolicy::from_repo(repo, policy_override)?;
    let out = repo.run(["show-ref"], None);
    let refs: Vec<(Oid, String)> = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let oid = hex_to_oid(it.next()?.as_bytes()).ok()?;
                let name = it.next()?.to_string();
                Some((oid, name))
            })
            .collect(),
        Err(_) => Vec::new(), // Empty repository with no refs
    };

    let keys = ContextKeys::new();
    let mut matched_refs = 0usize;
    let mut no_evidence_refs = 0usize;

    let b3_tagged_oids: std::collections::HashSet<Oid> = refs
        .iter()
        .filter(|(_, name)| parse_ref_embedded_b3(name).ok().flatten().is_some())
        .map(|(oid, _)| *oid)
        .collect();

    for (oid, refname) in &refs {
        match verify_target(repo, &keys, *oid, Some(refname), None, true) {
            Ok(CheckOutcome::Match { .. }) => {
                matched_refs += 1;
            }
            Ok(CheckOutcome::NoEvidence { .. }) => {
                no_evidence_refs += 1;
                if !b3_tagged_oids.contains(oid) {
                    match policy {
                        MissingPolicy::Silent => {}
                        MissingPolicy::Warn => {
                            eprintln!(
                                "buttress: warning: {refname} ({}) has no BLAKE3 buttress evidence",
                                &to_hex(oid)[..12]
                            );
                        }
                        MissingPolicy::Error => {
                            return Err(format!(
                                "buttress: error: {refname} ({}) has no BLAKE3 buttress evidence",
                                &to_hex(oid)[..12]
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!("buttress: {} on {refname}: {}", match e.kind {
                    VerifyErrorKind::Mismatch => "MISMATCH",
                    VerifyErrorKind::Incomplete => "INCOMPLETE",
                }, e.message));
            }
        }
    }

    Ok((matched_refs, no_evidence_refs))
}

/// Install hooks (and optionally the transparent `git` wrapper) for `--global` or `--local`.
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
        repo.common_dir.join("buttress-hooks")
    };
    fs::create_dir_all(&hooks_dir).map_err(|e| format!("create hooks dir: {e}"))?;

    // Check if there was a previous core.hooksPath we should chain to (with `--path` tilde expansion!)
    let prev_hooks = read_git_config_path(&real_git, global, "core.hooksPath")
        .filter(|p| Path::new(p) != hooks_dir);

    let exe_str = self_exe
        .to_str()
        .ok_or("git-buttress executable path is not valid UTF-8")?;
    let real_git_str = real_git
        .to_str()
        .ok_or("real git executable path is not valid UTF-8")?;
    let hooks_dir_str = hooks_dir
        .to_str()
        .ok_or("hooks directory path is not valid UTF-8")?;

    write_hook_script(
        &hooks_dir.join("post-commit"),
        &format!(
            "#!/bin/sh\n{chain}{exe} seal-head --quiet\n",
            chain = chain_snippet(prev_hooks.as_deref(), "post-commit"),
            exe = posix_single_quote(exe_str)
        ),
    )?;
    write_hook_script(
        &hooks_dir.join("reference-transaction"),
        &format!(
            "#!/bin/sh\n{chain}exec {exe} __hook-reference-transaction \"$@\"\n",
            chain = chain_snippet_stdin(prev_hooks.as_deref(), "reference-transaction"),
            exe = posix_single_quote(exe_str)
        ),
    )?;

    // Configure core.hooksPath
    let mut cfg_cmd = Command::new(&real_git);
    cfg_cmd.arg("config");
    if global {
        cfg_cmd.arg("--global");
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

        // Symlink/copy `git-buttress` onto `bin_dir` if not already there
        let subcmd_dest = bin_dir.join("git-buttress");
        if subcmd_dest != self_exe {
            let _ = fs::remove_file(&subcmd_dest);
            #[cfg(unix)]
            {
                let _ = std::os::unix::fs::symlink(&self_exe, &subcmd_dest);
            }
            installed_subcmd = Some(subcmd_dest);
        }

        let git_dest = bin_dir.join("git");
        if !git_dest.exists() || crate::git::is_our_wrapper(&git_dest) {
            let script = format!(
                "#!/bin/sh\n{WRAPPER_MARKER}\nexport GIT_BUTTRESS_REAL_GIT={real}\nexec {exe} __wrap-git \"$@\"\n",
                real = posix_single_quote(real_git_str),
                exe = posix_single_quote(exe_str)
            );
            write_hook_script(&git_dest, &script)?;
            installed_wrapper = Some(git_dest);
        }
    }

    Ok(EnableReport {
        hooks_dir,
        wrapper_path: installed_wrapper,
        subcmd_path: installed_subcmd,
    })
}

pub fn disable_buttress(global: bool, wrapper_dir: Option<&Path>) -> Result<(), String> {
    let real_git = resolve_real_git()?;
    let mut cmd = Command::new(&real_git);
    cmd.arg("config");
    if global {
        cmd.arg("--global");
    }
    let _ = cmd.args(["--unset", "core.hooksPath"]).output();

    if global || wrapper_dir.is_some() {
        let bin_dir = match wrapper_dir {
            Some(d) => d.to_path_buf(),
            None => {
                let home = env::var("HOME").map_err(|_| "HOME is not set")?;
                PathBuf::from(home).join(".local").join("bin")
            }
        };
        let git_dest = bin_dir.join("git");
        if crate::git::is_our_wrapper(&git_dest) {
            let _ = fs::remove_file(&git_dest);
        }
    }
    Ok(())
}

pub struct EnableReport {
    pub hooks_dir: PathBuf,
    pub wrapper_path: Option<PathBuf>,
    pub subcmd_path: Option<PathBuf>,
}

/// Quote an arbitrary string as a literal POSIX `sh` single-quoted token (`'...'` with `'` -> `'\''`).
///
/// Contract:
/// - `requires`: `!s.contains('\0')` (POSIX paths/argv cannot contain NUL).
/// - `ensures`: POSIX `sh` evaluates the returned token to the exact literal string `s` with zero
///   parameter expansion, command substitution, word splitting, or globbing.
/// - `writes`: nothing.
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

fn read_git_config_path(real_git: &Path, global: bool, key: &str) -> Option<String> {
    let mut c = Command::new(real_git);
    c.arg("config");
    if global {
        c.arg("--global");
    }
    let out = c.args(["--get", "--path", key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn chain_snippet(prev_dir: Option<&str>, hook_name: &str) -> String {
    match prev_dir {
        Some(d) => {
            let hook_path = format!("{}/{hook_name}", d.trim_end_matches('/'));
            let q = posix_single_quote(&hook_path);
            format!("if [ -x {q} ]; then {q} \"$@\" || exit $?; fi\n")
        }
        None => String::new(),
    }
}

fn chain_snippet_stdin(prev_dir: Option<&str>, hook_name: &str) -> String {
    match prev_dir {
        Some(d) => {
            let hook_path = format!("{}/{hook_name}", d.trim_end_matches('/'));
            let q = posix_single_quote(&hook_path);
            format!(
                "INPUT=$(cat)\nif [ -x {q} ]; then printf '%s\\n' \"$INPUT\" | {q} \"$@\" || exit $?; fi\nprintf '%s\\n' \"$INPUT\" | "
            )
        }
        None => String::new(),
    }
}

fn write_hook_script(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    let mut perms = fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}
