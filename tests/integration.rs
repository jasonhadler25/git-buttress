//! Comprehensive integration & adversarial test suite for `git-buttress`.

use git_buttress::cache::Oid;
use git_buttress::git::{GitRepo, ObjKind, ObjectStore, hex_to_oid, to_hex};
use git_buttress::protocol::{
    CheckOutcome, ContextKeys, Engine, VerifyErrorKind, verify_target,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempSandbox {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    real_git: PathBuf,
    buttress_bin: PathBuf,
}

impl TempSandbox {
    fn new() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = env::temp_dir().join(format!(
            "git-buttress-test-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();

        let real_git = git_buttress::git::resolve_real_git().unwrap();
        let buttress_bin = PathBuf::from(env!("CARGO_BIN_EXE_git-buttress"));

        // Configure isolated global git user in `home/.gitconfig`
        let st = Command::new(&real_git)
            .env("HOME", &home)
            .args(["config", "--global", "user.name", "Maya"])
            .status()
            .unwrap();
        assert!(st.success());
        let st = Command::new(&real_git)
            .env("HOME", &home)
            .args(["config", "--global", "user.email", "maya@example.com"])
            .status()
            .unwrap();
        assert!(st.success());
        let st = Command::new(&real_git)
            .env("HOME", &home)
            .args(["config", "--global", "init.defaultBranch", "main"])
            .status()
            .unwrap();
        assert!(st.success());
        let st = Command::new(&real_git)
            .env("HOME", &home)
            .args(["config", "--global", "protocol.file.allow", "always"])
            .status()
            .unwrap();
        assert!(st.success());

        Self {
            root,
            home,
            bin,
            real_git,
            buttress_bin,
        }
    }

    fn path_with_wrapper(&self) -> String {
        let orig = env::var("PATH").unwrap_or_default();
        format!("{}:{orig}", self.bin.display())
    }

    fn run_buttress(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        Command::new(&self.buttress_bin)
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("PATH", self.path_with_wrapper())
            .env("GIT_BUTTRESS_REAL_GIT", &self.real_git)
            .args(args)
            .output()
            .unwrap()
    }

    /// Run `git` resolved through `$HOME/.local/bin:$PATH` (just as Maya's shell does!).
    fn run_user_git(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        let git_in_bin = self.bin.join("git");
        let exe = if git_in_bin.exists() {
            &git_in_bin
        } else {
            &self.real_git
        };
        Command::new(exe)
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("PATH", self.path_with_wrapper())
            .args(args)
            .output()
            .unwrap()
    }

    /// Run unmodified stock `git` WITHOUT Maya's HOME/hooks (simulates a stock teammate!).
    fn run_stock_git(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        let stock_home = self.root.join("stock-home");
        fs::create_dir_all(&stock_home).unwrap();
        Command::new(&self.real_git)
            .current_dir(cwd)
            .env("HOME", &stock_home)
            .args(["-c", "user.name=Teammate", "-c", "user.email=tm@example.com"])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for TempSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Overlay `ObjectStore` that substitutes arbitrary objects by SHA-1 OID in memory
/// to simulate an attacker with a practical SHA1DC second-preimage / collision exploit!
struct PoisonedStore<'a> {
    inner: &'a mut GitRepo,
    overrides: HashMap<Oid, (ObjKind, Vec<u8>)>,
    forced_shallow: Option<HashSet<Oid>>,
}

impl<'a> ObjectStore for PoisonedStore<'a> {
    fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String> {
        if let Some(v) = self.overrides.get(oid) {
            return Ok(Some(v.clone()));
        }
        self.inner.read_object(oid)
    }

    fn shallow_commits(&self) -> &HashSet<Oid> {
        match self.forced_shallow {
            Some(ref s) => s,
            None => self.inner.shallow_commits(),
        }
    }
}

#[test]
fn spec_empty_vectors_and_domain_separation() {
    let keys = ContextKeys::new();
    assert_eq!(
        to_hex(&keys.hash_file(b"")),
        "0b0663e8d56ab3231c8e4bde914f42429b08f1edb19a237ef496eb1a3316c55c"
    );
    assert_eq!(
        to_hex(&keys.hash_dir(b"")),
        "acf91ceb6e37c08b51530bf4cc86ae17daaf716f9f2284a1e0ce94c7001a68cd"
    );
    // Domain separation: identical input bytes yield completely unrelated digests across all 4 contexts
    let d_f = keys.hash_file(b"same");
    let d_d = keys.hash_dir(b"same");
    let d_c = keys.hash_sealed_commit(b"same");
    let d_p = keys.hash_plain_commit(b"same");
    let uniq: HashSet<_> = [d_f, d_d, d_c, d_p].into_iter().collect();
    assert_eq!(uniq.len(), 4);
}

#[test]
fn maya_dana_sam_readme_story_end_to_end() {
    let sb = TempSandbox::new();
    let maya_repo = sb.root.join("acme-tls");
    fs::create_dir_all(&maya_repo).unwrap();

    // 1. Maya enables git-buttress globally ONCE
    let out = sb.run_buttress(&maya_repo, &["enable", "--global"]);
    assert!(out.status.success(), "enable failed: {:?}", out);
    assert!(sb.bin.join("git").is_file(), "wrapper should be installed");

    // 2. Maya uses ONLY plain `git` commands!
    assert!(sb.run_user_git(&maya_repo, &["init"]).status.success());
    fs::create_dir_all(maya_repo.join("src")).unwrap();
    fs::write(maya_repo.join("src/verify.c"), "int verify(void) { return 1; }\n").unwrap();
    assert!(sb.run_user_git(&maya_repo, &["add", "src/verify.c"]).status.success());

    let commit_out = sb.run_user_git(&maya_repo, &["commit", "-m", "Release 2.4.0"]);
    assert!(commit_out.status.success(), "commit failed: {:?}", commit_out);
    let summary_stdout = String::from_utf8_lossy(&commit_out.stdout);

    // Verify NO stale-SHA quirk: the short SHA printed by `git commit` MUST equal actual HEAD!
    let actual_short = String::from_utf8_lossy(
        &sb.run_user_git(&maya_repo, &["rev-parse", "--short", "HEAD"])
            .stdout,
    )
    .trim()
    .to_string();
    assert!(
        summary_stdout.contains(&actual_short),
        "printed summary {summary_stdout:?} must contain true sealed short SHA {actual_short:?}"
    );

    // Stock `git fsck --full --strict` passes AND wrapper runs `buttress fsck`!
    let fsck_out = sb.run_user_git(&maya_repo, &["fsck", "--full", "--strict"]);
    assert!(fsck_out.status.success(), "fsck failed: {:?}", fsck_out);
    assert!(
        String::from_utf8_lossy(&fsck_out.stderr).contains("buttress fsck:"),
        "wrapped `git fsck` should also run buttress fsck"
    );

    // 3. Maya runs plain `git tag v2.4.0` -> companion `v2.4.0+blake3-<64hex>` tag is minted!
    let tag_out = sb.run_user_git(&maya_repo, &["tag", "v2.4.0"]);
    assert!(tag_out.status.success());
    let tags = String::from_utf8_lossy(&sb.run_user_git(&maya_repo, &["tag", "-l"]).stdout)
        .lines()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    assert!(tags.contains(&"v2.4.0".to_string()));
    let b3_tag = tags
        .iter()
        .find(|t| t.starts_with("v2.4.0+blake3-"))
        .expect("companion +blake3- tag must be created")
        .clone();

    // `git describe --tags` still returns clean `v2.4.0`!
    let desc = String::from_utf8_lossy(&sb.run_user_git(&maya_repo, &["describe", "--tags"]).stdout)
        .trim()
        .to_string();
    assert_eq!(desc, "v2.4.0");

    // 4. Stock teammate commits without git-buttress, then Maya commits again -> covers teammate!
    fs::write(maya_repo.join("src/extra.c"), "int extra(void) { return 2; }\n").unwrap();
    assert!(sb.run_stock_git(&maya_repo, &["add", "src/extra.c"]).status.success());
    assert!(sb.run_stock_git(&maya_repo, &["commit", "-m", "Teammate plain commit"]).status.success());

    fs::write(maya_repo.join("src/verify.c"), "int verify(void) { return 3; }\n").unwrap();
    assert!(sb.run_user_git(&maya_repo, &["commit", "-am", "Maya follow-up"]).status.success());

    let check_out = sb.run_buttress(&maya_repo, &["check", "HEAD"]);
    assert!(check_out.status.success());
    let check_txt = String::from_utf8_lossy(&check_out.stdout);
    assert!(
        check_txt.contains("2 carrying lines, 1 plain covered"),
        "unexpected check output: {check_txt}"
    );

    // 5. Sam clones clean repo by `+blake3-` tag -> succeeds!
    let sam_clean = sb.root.join("sam-clean");
    let clone_ok = sb.run_user_git(
        &sb.root,
        &["clone", "--branch", &b3_tag, maya_repo.to_str().unwrap(), sam_clean.to_str().unwrap()],
    );
    assert!(
        clone_ok.status.success(),
        "clean clone by +blake3- tag should succeed: {:?}",
        clone_ok
    );

    // 6. Now poison a mirror: create a fake tag with the SAME `+blake3-` tag name pointing to a
    //    different commit (simulating an attacker who forged SHA1DC or retargeted the mirror ref)!
    let mirror = sb.root.join("poisoned-mirror");
    assert!(
        sb.run_stock_git(
            &sb.root,
            &["clone", "--bare", maya_repo.to_str().unwrap(), mirror.to_str().unwrap()]
        )
        .status
        .success()
    );
    // Point the `+blake3-` tag in the poisoned mirror at the teammate's commit instead of Release 2.4.0
    let wrong_commit = String::from_utf8_lossy(
        &sb.run_stock_git(&maya_repo, &["rev-parse", "HEAD^"]).stdout,
    )
    .trim()
    .to_string();
    assert!(
        sb.run_stock_git(
            &mirror,
            &["update-ref", &format!("refs/tags/{b3_tag}"), &wrong_commit]
        )
        .status
        .success()
    );

    // Sam tries `git clone --branch v2.4.0+blake3-...` from the poisoned mirror -> ABORTED before checkout!
    let sam_evil = sb.root.join("sam-evil");
    let clone_evil = sb.run_user_git(
        &sb.root,
        &[
            "clone",
            "--branch",
            &b3_tag,
            mirror.to_str().unwrap(),
            sam_evil.to_str().unwrap(),
        ],
    );
    assert!(
        !clone_evil.status.success(),
        "poisoned clone MUST fail in reference-transaction hook!"
    );
    let stderr = String::from_utf8_lossy(&clone_evil.stderr);
    assert!(
        stderr.contains("MISMATCH"),
        "expected MISMATCH in stderr, got: {stderr}"
    );
    assert!(
        !sam_evil.exists(),
        "Git must abort clone and remove target directory before writing working tree!"
    );
}

#[test]
fn rebase_cherry_pick_amend_and_ssh_signing() {
    let sb = TempSandbox::new();
    let repo_dir = sb.root.join("repo");
    fs::create_dir_all(&repo_dir).unwrap();
    assert!(sb.run_buttress(&repo_dir, &["enable", "--global"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["init"]).status.success());

    // Configure Ed25519 SSH commit signing
    let key_path = sb.root.join("id_ed25519");
    let allowed = sb.root.join("allowed_signers");
    assert!(
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f", key_path.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    let pubkey = fs::read_to_string(sb.root.join("id_ed25519.pub")).unwrap();
    fs::write(&allowed, format!("maya@example.com {}", pubkey.trim())).unwrap();
    assert!(sb.run_user_git(&repo_dir, &["config", "gpg.format", "ssh"]).status.success());
    assert!(
        sb.run_user_git(&repo_dir, &["config", "user.signingkey", key_path.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        sb.run_user_git(
            &repo_dir,
            &["config", "gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()]
        )
        .status
        .success()
    );

    // Signed commit via plain `git commit -S` -> post-commit seals AND re-signs covering buttress lines!
    fs::write(repo_dir.join("a.txt"), "base\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "a.txt"]).status.success());
    let sc = sb.run_user_git(&repo_dir, &["commit", "-S", "-m", "Signed base"]);
    assert!(sc.status.success(), "signed commit failed: {:?}", sc);

    // Stock `git verify-commit HEAD` MUST verify the signature over the buttress headers!
    let vc = sb.run_stock_git(&repo_dir, &["verify-commit", "HEAD"]);
    assert!(
        vc.status.success(),
        "stock git verify-commit failed: {:?}",
        vc
    );
    let raw = String::from_utf8_lossy(
        &sb.run_stock_git(&repo_dir, &["cat-file", "commit", "HEAD"]).stdout,
    )
    .to_string();
    assert!(raw.contains("\nbuttress-tree blake3 "));

    // Stock user (no hooks) runs `git commit --amend` changing a.txt -> stale header ignored cleanly!
    fs::write(repo_dir.join("a.txt"), "amended by stock user\n").unwrap();
    assert!(
        sb.run_stock_git(&repo_dir, &["commit", "--amend", "-am", "Stock amend"])
            .status
            .success()
    );
    // Missing=silent exits 0; missing=error exits 2 (NoEvidence, NOT Mismatch!)
    assert_eq!(
        sb.run_buttress(&repo_dir, &["check", "HEAD", "--missing", "silent"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        sb.run_buttress(&repo_dir, &["check", "HEAD", "--missing", "error"])
            .status
            .code(),
        Some(2)
    );

    // Branch + multi-commit `git rebase` with hooks enabled seals EVERY rebased commit!
    assert!(sb.run_buttress(&repo_dir, &["seal-head", "--quiet"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["checkout", "-b", "feat"]).status.success());
    fs::write(repo_dir.join("f1.txt"), "1\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "f1.txt"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["commit", "-m", "f1"]).status.success());
    fs::write(repo_dir.join("f2.txt"), "2\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "f2.txt"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["commit", "-m", "f2"]).status.success());

    assert!(sb.run_user_git(&repo_dir, &["checkout", "main"]).status.success());
    fs::write(repo_dir.join("m.txt"), "m\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "m.txt"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["commit", "-m", "main advance"]).status.success());

    assert!(sb.run_user_git(&repo_dir, &["checkout", "feat"]).status.success());
    let rb = sb.run_user_git(&repo_dir, &["rebase", "main"]);
    assert!(rb.status.success(), "rebase failed: {:?}", rb);

    let chk = sb.run_buttress(&repo_dir, &["check", "HEAD"]);
    assert!(chk.status.success());
    assert!(
        String::from_utf8_lossy(&chk.stdout).contains("4 carrying lines, 0 plain covered"),
        "every commit across rebase should carry valid buttress lines: {}",
        String::from_utf8_lossy(&chk.stdout)
    );
}

#[test]
fn adversarial_sha1dc_collision_and_shallow_boundary_tests() {
    let sb = TempSandbox::new();
    let repo_dir = sb.root.join("adv");
    fs::create_dir_all(&repo_dir).unwrap();

    // Commit 0: plain pre-buttress commit (with `old.txt` that will be deleted before buttress is enabled)
    assert!(sb.run_stock_git(&repo_dir, &["init", "-b", "main"]).status.success());
    fs::write(repo_dir.join("old.txt"), "ancient clean file\n").unwrap();
    assert!(sb.run_stock_git(&repo_dir, &["add", "old.txt"]).status.success());
    assert!(sb.run_stock_git(&repo_dir, &["commit", "-m", "Ancient root"]).status.success());
    let old_blob_oid = hex_to_oid(
        sb.run_stock_git(&repo_dir, &["rev-parse", "HEAD:old.txt"])
            .stdout
            .trim_ascii(),
    )
    .unwrap();

    // Enable buttress; Commit 1 removes `old.txt` and adds `app.sh`; Commit 2 updates `tip.txt`
    assert!(sb.run_buttress(&repo_dir, &["enable", "--global"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["rm", "old.txt"]).status.success());
    fs::write(repo_dir.join("app.sh"), "echo safe\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "app.sh"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["commit", "-m", "Buttressed 1"]).status.success());
    let c1_oid = hex_to_oid(
        sb.run_user_git(&repo_dir, &["rev-parse", "HEAD"])
            .stdout
            .trim_ascii(),
    )
    .unwrap();
    let c1_tree_oid = hex_to_oid(
        sb.run_user_git(&repo_dir, &["rev-parse", "HEAD^{tree}"])
            .stdout
            .trim_ascii(),
    )
    .unwrap();

    fs::write(repo_dir.join("tip.txt"), "clean tip\n").unwrap();
    assert!(sb.run_user_git(&repo_dir, &["add", "tip.txt"]).status.success());
    assert!(sb.run_user_git(&repo_dir, &["commit", "-m", "Buttressed 2"]).status.success());
    let tip_oid = hex_to_oid(
        sb.run_user_git(&repo_dir, &["rev-parse", "HEAD"])
            .stdout
            .trim_ascii(),
    )
    .unwrap();
    let tip_blob_oid = hex_to_oid(
        sb.run_user_git(&repo_dir, &["rev-parse", "HEAD:tip.txt"])
            .stdout
            .trim_ascii(),
    )
    .unwrap();

    let keys = ContextKeys::new();
    let mut repo = GitRepo::open(Some(&repo_dir)).unwrap();
    let tip_b3 = {
        let mut eng = Engine::new(
            &mut repo,
            &keys,
            git_buttress::cache::DigestCache::memory_only(),
        );
        eng.digest_commit(tip_oid).unwrap().0
    };

    // Baseline clean check
    let clean = verify_target(&mut repo, &keys, tip_oid, None, Some(tip_b3), true).unwrap();
    assert!(matches!(
        clean,
        CheckOutcome::Match {
            sealed_checked: 2,
            plain_covered: 1,
            ..
        }
    ));

    // Attack 1: SHA1DC twin blob in tip tree
    {
        let mut overrides = HashMap::new();
        overrides.insert(tip_blob_oid, (ObjKind::Blob, b"BACKDOOR\n".to_vec()));
        let mut evil = PoisonedStore {
            inner: &mut repo,
            overrides,
            forced_shallow: None,
        };
        let err = verify_target(&mut evil, &keys, tip_oid, None, Some(tip_b3), true).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    }

    // Attack 2: SHA1DC twin blob in deleted ancient pre-buttress history
    {
        let mut overrides = HashMap::new();
        overrides.insert(old_blob_oid, (ObjKind::Blob, b"ANCIENT BACKDOOR\n".to_vec()));
        let mut evil = PoisonedStore {
            inner: &mut repo,
            overrides,
            forced_shallow: None,
        };
        let err = verify_target(&mut evil, &keys, tip_oid, None, Some(tip_b3), true).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    }

    // Attack 3: Flipped mode `100644` -> `100755` in Commit 1's tree (same SHA-1)
    let (_, c1_tree_raw) = repo.read_object(&c1_tree_oid).unwrap().unwrap();
    let (_, c1_raw) = repo.read_object(&c1_oid).unwrap().unwrap();
    {
        let mut forged_tree = Vec::new();
        assert!(c1_tree_raw.starts_with(b"100644 app.sh\0"));
        forged_tree.extend_from_slice(b"100755 app.sh\0");
        forged_tree.extend_from_slice(&c1_tree_raw[b"100644 app.sh\0".len()..]);
        let mut overrides = HashMap::new();
        overrides.insert(c1_tree_oid, (ObjKind::Tree, forged_tree));
        let mut evil = PoisonedStore {
            inner: &mut repo,
            overrides,
            forced_shallow: None,
        };
        let err = verify_target(&mut evil, &keys, tip_oid, None, Some(tip_b3), true).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    }

    // Attack 4: Stripped buttress headers on ancestor Commit 1 (downgrade attempt)
    {
        let stripped: Vec<u8> = c1_raw
            .split(|&c| c == b'\n')
            .filter(|l| !l.starts_with(b"buttress-"))
            .collect::<Vec<_>>()
            .join(&b'\n');
        let mut overrides = HashMap::new();
        overrides.insert(c1_oid, (ObjKind::Commit, stripped));
        let mut evil = PoisonedStore {
            inner: &mut repo,
            overrides,
            forced_shallow: None,
        };
        let err = verify_target(&mut evil, &keys, tip_oid, None, Some(tip_b3), true).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    }

    // Attack 5: Zero-padded octal mode `040000` in legacy Git tree is parsed as directory (not file!)
    {
        // Check parse_tree_entries handles 6-digit `040000`
        let mut synthetic = Vec::new();
        synthetic.extend_from_slice(b"040000 subdir\0");
        synthetic.extend_from_slice(&[0x11u8; 20]);
        let parsed = git_buttress::protocol::parse_tree_entries(&synthetic).unwrap();
        assert_eq!(parsed[0].1, git_buttress::protocol::MODE_DIR);
    }

    // Attack 6: Shallow-boundary bug fix check!
    // If SOME OTHER commit is in `.git/shallow`, a missing parent on `tip_oid` (which is NOT in
    // `.git/shallow`) MUST NOT be excused — it must fail with Incomplete!
    {
        struct MissingParentStore<'b> {
            inner: &'b mut GitRepo,
            missing: Oid,
            shallow: HashSet<Oid>,
        }
        impl<'b> ObjectStore for MissingParentStore<'b> {
            fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String> {
                if *oid == self.missing {
                    return Ok(None);
                }
                self.inner.read_object(oid)
            }
            fn shallow_commits(&self) -> &HashSet<Oid> {
                &self.shallow
            }
        }
        let mut unrelated_shallow = HashSet::new();
        unrelated_shallow.insert([0x99u8; 20]); // NOT tip_oid!
        let mut bad_shallow = MissingParentStore {
            inner: &mut repo,
            missing: c1_oid,
            shallow: unrelated_shallow,
        };
        let err =
            verify_target(&mut bad_shallow, &keys, tip_oid, None, Some(tip_b3), true).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::Incomplete);

        // Whereas if `tip_oid` ITSELF is the declared shallow boundary, `--allow-shallow` succeeds and counts 1 stop:
        let mut declared_shallow = HashSet::new();
        declared_shallow.insert(tip_oid);
        let mut good_shallow = MissingParentStore {
            inner: &mut repo,
            missing: c1_oid,
            shallow: declared_shallow,
        };
        let ok =
            verify_target(&mut good_shallow, &keys, tip_oid, None, Some(tip_b3), true).unwrap();
        assert!(matches!(
            ok,
            CheckOutcome::Match {
                shallow_stops: 1,
                ..
            }
        ));
    }
}

#[test]
fn contract_obligations_found_during_dbc_pass() {
    let keys = ContextKeys::new();

    // 1. split_headers_body: leading `\n` (empty header block) and header-only commit with trailing spaces
    assert_eq!(
        git_buttress::protocol::split_headers_body(b"\nbody\n"),
        (&b""[..], &b"body\n"[..])
    );
    assert_eq!(
        git_buttress::protocol::split_headers_body(b"tree 0000000000000000000000000000000000000000   \n"),
        (&b"tree 0000000000000000000000000000000000000000   "[..], &b""[..])
    );

    // 2. Duplicate `tree ` header in commit MUST fail closed as Mismatch (not last-wins!)
    let dup_tree = b"tree 1111111111111111111111111111111111111111\ntree 2222222222222222222222222222222222222222\n\nmsg\n";
    let err = git_buttress::protocol::parse_commit([0xaa; 20], dup_tree.to_vec()).unwrap_err();
    assert_eq!(err.kind, VerifyErrorKind::Mismatch);

    // 3. Tree parser: overflow octal (>7 digits), empty name, and `/` in entry name MUST be rejected
    let mut bad_octal = b"777777777777777 f\0".to_vec();
    bad_octal.extend_from_slice(&[0x11; 20]);
    assert!(git_buttress::protocol::parse_tree_entries(&bad_octal).is_err());

    let mut empty_name = b"100644 \0".to_vec();
    empty_name.extend_from_slice(&[0x11; 20]);
    assert!(git_buttress::protocol::parse_tree_entries(&empty_name).is_err());

    let mut slash_name = b"100644 a/b\0".to_vec();
    slash_name.extend_from_slice(&[0x11; 20]);
    assert!(git_buttress::protocol::parse_tree_entries(&slash_name).is_err());

    // 4. Duplicate `+blake3-` segment in ref name MUST be rejected; `^{}` peel suffix MUST work
    let d_hex = "0b0663e8d56ab3231c8e4bde914f42429b08f1edb19a237ef496eb1a3316c55c";
    let bad_ref = format!("refs/tags/v1+blake3-{d_hex}+blake3-acf91ceb6e37c08b51530bf4cc86ae17daaf716f9f2284a1e0ce94c7001a68cd");
    assert!(git_buttress::protocol::parse_ref_embedded_b3(&bad_ref).is_err());
    let peeled_ref = format!("refs/tags/v1+blake3-{d_hex}^{{}}");
    assert_eq!(
        to_hex(&git_buttress::protocol::parse_ref_embedded_b3(&peeled_ref).unwrap().unwrap()),
        d_hex
    );

    // 5. Cyclic tree and cyclic annotated-tag chain MUST terminate with Mismatch (no infinite loop!)
    struct MapStore {
        objs: HashMap<Oid, (ObjKind, Vec<u8>)>,
        shallow: HashSet<Oid>,
    }
    impl ObjectStore for MapStore {
        fn read_object(&mut self, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String> {
            Ok(self.objs.get(oid).cloned())
        }
        fn shallow_commits(&self) -> &HashSet<Oid> {
            &self.shallow
        }
    }

    let t_oid = [0x44u8; 20];
    let mut cyc_tree = b"40000 loop\0".to_vec();
    cyc_tree.extend_from_slice(&t_oid);
    let mut store = MapStore {
        objs: HashMap::from([(t_oid, (ObjKind::Tree, cyc_tree))]),
        shallow: HashSet::new(),
    };
    let err = verify_target(&mut store, &keys, t_oid, None, None, true).unwrap_err();
    assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    assert!(err.message.contains("cycle"));

    // Cyclic tag A -> B -> A and tag `type` mismatch
    let tag_a = [0x55u8; 20];
    let tag_b = [0x66u8; 20];
    let tag_a_raw = format!("object {}\ntype tag\ntag a\n\nm\n", to_hex(&tag_b)).into_bytes();
    let tag_b_raw = format!("object {}\ntype tag\ntag b\n\nm\n", to_hex(&tag_a)).into_bytes();
    store.objs.insert(tag_a, (ObjKind::Tag, tag_a_raw));
    store.objs.insert(tag_b, (ObjKind::Tag, tag_b_raw));
    let err = verify_target(&mut store, &keys, tag_a, None, None, true).unwrap_err();
    assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    assert!(err.message.contains("cycle"));

    let blob_oid = [0x77u8; 20];
    store.objs.insert(blob_oid, (ObjKind::Blob, b"hi".to_vec()));
    let lying_tag = [0x88u8; 20];
    let lying_raw = format!("object {}\ntype commit\ntag lie\n\nm\n", to_hex(&blob_oid)).into_bytes();
    store.objs.insert(lying_tag, (ObjKind::Tag, lying_raw));
    let err = verify_target(&mut store, &keys, lying_tag, None, None, true).unwrap_err();
    assert_eq!(err.kind, VerifyErrorKind::Mismatch);
    assert!(err.message.contains("declared target type"));

    // 6. DigestCache torn-record repair: corrupting `.git/buttress-cache.bin` with 17 trailing junk
    //    bytes MUST be truncated back to a 53-byte boundary before appending new entries!
    let sb = TempSandbox::new();
    let gd = sb.root.join("cache-test");
    fs::create_dir_all(&gd).unwrap();
    let oid1 = [0x01u8; 20];
    let dig1 = [0xaa; 32];
    let oid2 = [0x02u8; 20];
    let dig2 = [0xbb; 32];
    {
        let mut c = git_buttress::cache::DigestCache::load_from_git_dir(&gd);
        c.put_blob(oid1, dig1);
        c.flush();
    }
    // Simulate a torn crash mid-record by appending 17 garbage bytes
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(gd.join("buttress-cache.bin"))
            .unwrap();
        f.write_all(&[0xffu8; 17]).unwrap();
    }
    {
        let mut c = git_buttress::cache::DigestCache::load_from_git_dir(&gd);
        assert_eq!(c.blobs.get(&oid1), Some(&dig1));
        c.put_tree(oid2, dig2);
        c.flush();
    }
    {
        let c = git_buttress::cache::DigestCache::load_from_git_dir(&gd);
        assert_eq!(c.blobs.get(&oid1), Some(&dig1));
        assert_eq!(c.trees.get(&oid2), Some(&dig2), "post-crash record must stay 53-byte aligned!");
    }

    // 7. POSIX shell quoting with hostile characters (`$`, `'`, spaces, backticks) & `git tag -f`
    let hostile_home = sb.root.join("hostile 'home' $(touch PWNED) `id`");
    let hostile_bin = hostile_home.join(".local/bin");
    fs::create_dir_all(&hostile_bin).unwrap();
    let repo_dir = sb.root.join("tagf-repo");
    fs::create_dir_all(&repo_dir).unwrap();
    assert!(
        Command::new(&sb.real_git)
            .env("HOME", &hostile_home)
            .args(["config", "--global", "user.name", "M"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&sb.real_git)
            .env("HOME", &hostile_home)
            .args(["config", "--global", "user.email", "m@e"])
            .status()
            .unwrap()
            .success()
    );
    let en = Command::new(&sb.buttress_bin)
        .current_dir(&repo_dir)
        .env("HOME", &hostile_home)
        .args(["enable", "--global"])
        .output()
        .unwrap();
    assert!(en.status.success(), "enable in hostile HOME failed: {:?}", en);

    let h_git = hostile_bin.join("git");
    let h_path = format!("{}:{}", hostile_bin.display(), env::var("PATH").unwrap_or_default());
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["init", "-b", "main"])
            .status()
            .unwrap()
            .success()
    );
    fs::write(repo_dir.join("x"), "1\n").unwrap();
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["add", "x"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["commit", "-m", "c1"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !sb.root.join("PWNED").exists() && !repo_dir.join("PWNED").exists(),
        "shell metacharacters in HOME must never execute!"
    );

    // Test `git tag v1` then `git tag -f v1` on a new commit mints updated companion tag!
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["tag", "v1"])
            .status()
            .unwrap()
            .success()
    );
    fs::write(repo_dir.join("x"), "2\n").unwrap();
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["commit", "-am", "c2"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["tag", "-f", "v1"])
            .status()
            .unwrap()
            .success()
    );
    let head_b3 = String::from_utf8_lossy(
        &Command::new(&sb.buttress_bin)
            .current_dir(&repo_dir)
            .args(["id", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let tags_after = String::from_utf8_lossy(
        &Command::new(&h_git)
            .current_dir(&repo_dir)
            .env("HOME", &hostile_home)
            .env("PATH", &h_path)
            .args(["tag", "-l"])
            .output()
            .unwrap()
            .stdout,
    )
    .to_string();
    assert!(
        tags_after.contains(&format!("v1+blake3-{head_b3}")),
        "git tag -f must mint companion tag for new commit: {tags_after}"
    );
}
