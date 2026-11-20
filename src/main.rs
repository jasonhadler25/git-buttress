use git_buttress::cache::DigestCache;
use git_buttress::git::{GitRepo, ObjKind, ObjectStore, hex_to_32, to_hex};
use git_buttress::hooks::{
    MissingPolicy, disable_buttress, enable_buttress, fsck_all_refs, run_git_wrapper,
    run_reference_transaction_hook, seal_head,
};
use git_buttress::protocol::{
    CheckOutcome, CommitClass, ContextKeys, Engine, VerifyError, parse_annotated_tag,
    split_headers_body, verify_target,
};
use std::env;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
git-buttress — BLAKE3 Merkle integrity spine for standard Git repositories

USAGE:
  git buttress enable [--global | --local] [--bin-dir <dir>] [--no-wrapper]
  git buttress disable [--global | --local] [--bin-dir <dir>]
  git buttress check [<rev>] [--expect <64-hex>] [--missing silent|warn|error] [--no-shallow]
  git buttress fsck [--missing silent|warn|error]
  git buttress id [<rev>]
  git buttress log [-n <count>] [<rev>]
  git buttress seal-head [--sign] [--quiet]
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "__wrap-git" => {
            let code = run_git_wrapper(&args[1..]);
            exit_code_from_status(code)
        }
        "__hook-reference-transaction" => {
            let phase = args.get(1).map(|s| s.as_str()).unwrap_or("");
            match run_reference_transaction_hook(phase) {
                Ok(()) => ExitCode::SUCCESS,
                Err(msg) => {
                    eprintln!("{msg}");
                    ExitCode::from(1)
                }
            }
        }
        cmd => match dispatch(cmd, &args[1..]) {
            Ok(code) => exit_code_from_status(code),
            Err(err) => {
                eprintln!("git-buttress: error: {err}");
                ExitCode::from(1)
            }
        },
    }
}

/// Contract:
/// - `requires`: true
/// - `ensures`: returns `ExitCode::SUCCESS` iff `code == 0`; any non-zero `i32` (including `256` or negative)
///   maps to a non-zero `ExitCode` (never wraps mod 256 to `0`!).
fn exit_code_from_status(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else if (1..=255).contains(&code) {
        ExitCode::from(code as u8)
    } else {
        ExitCode::from(1)
    }
}

fn dispatch(cmd: &str, rest: &[String]) -> Result<i32, String> {
    match cmd {
        "enable" => cmd_enable(rest),
        "disable" => cmd_disable(rest),
        "id" => cmd_id(rest),
        "check" | "verify" => cmd_check(rest),
        "fsck" => cmd_fsck(rest),
        "log" => cmd_log(rest),
        "seal-head" => cmd_seal_head(rest),
        "-V" | "--version" | "version" => {
            println!(
                "git-buttress {} (blake3-servil {})",
                env!("CARGO_PKG_VERSION"),
                blake3_servil::BUILD_VERSION
            );
            Ok(0)
        }
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

fn cmd_enable(args: &[String]) -> Result<i32, String> {
    let mut global = false;
    let mut local = false;
    let mut bin_dir: Option<&Path> = None;
    let mut no_wrapper = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--global" => global = true,
            "--local" => local = true,
            "--no-wrapper" => no_wrapper = true,
            "--bin-dir" => {
                i += 1;
                let dir = args.get(i).ok_or("--bin-dir requires a path")?;
                bin_dir = Some(Path::new(dir));
            }
            other => return Err(format!("unknown option for enable: {other}")),
        }
        i += 1;
    }
    if global && local {
        return Err("cannot pass both --global and --local".into());
    }
    if !global && !local {
        global = true;
    }
    let rep = enable_buttress(global, bin_dir, no_wrapper)?;
    let scope = if global { "global" } else { "repository" };
    println!(
        "Configured {scope} Git hooks for git-buttress at {}",
        rep.hooks_dir.display()
    );
    if let Some(ref wp) = rep.wrapper_path {
        let dir = wp.parent().unwrap_or(Path::new(""));
        println!("Installed transparent `git` wrapper at {}", wp.display());
        let path_var = env::var("PATH").unwrap_or_default();
        let first_git_is_ours = env::split_paths(&path_var)
            .find(|d| d.join("git").is_file())
            .is_some_and(|d| d == dir);
        if !first_git_is_ours {
            println!(
                "Note: prepend `{}` to your PATH so `git commit` and `git fsck` use the wrapper seamlessly.",
                dir.display()
            );
        }
    }
    let _ = rep.subcmd_path;
    Ok(0)
}

fn cmd_disable(args: &[String]) -> Result<i32, String> {
    let mut global = false;
    let mut local = false;
    let mut bin_dir: Option<&Path> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--global" => global = true,
            "--local" => local = true,
            "--bin-dir" => {
                i += 1;
                let dir = args.get(i).ok_or("--bin-dir requires a path")?;
                bin_dir = Some(Path::new(dir));
            }
            other => return Err(format!("unknown option for disable: {other}")),
        }
        i += 1;
    }
    if global && local {
        return Err("cannot pass both --global and --local".into());
    }
    if !global && !local {
        global = true;
    }
    disable_buttress(global, bin_dir)?;
    println!("Disabled git-buttress ({})", if global { "global" } else { "local" });
    Ok(0)
}

fn cmd_id(args: &[String]) -> Result<i32, String> {
    if args.len() > 1 {
        return Err(format!("unexpected extra argument: {:?}", args[1]));
    }
    if let Some(first) = args.first() {
        if first.starts_with('-') {
            return Err(format!("unknown option for id: {first}"));
        }
    }
    let rev = args.first().map(|s| s.as_str()).unwrap_or("HEAD");
    let mut repo = GitRepo::open(None)?;
    let mut oid = repo.rev_parse(rev)?;
    let keys = ContextKeys::new();
    let mut seen_tags = std::collections::HashSet::new();
    seen_tags.insert(oid);

    loop {
        let (kind, raw) = repo
            .read_object(&oid)?
            .ok_or_else(|| format!("missing object {}", to_hex(&oid)))?;
        match kind {
            ObjKind::Tag => {
                let (next_oid, _, _) = parse_annotated_tag(&raw).map_err(|e| e.message)?;
                if !seen_tags.insert(next_oid) {
                    return Err(format!("cycle in annotated tag chain at {}", to_hex(&next_oid)));
                }
                oid = next_oid;
            }
            ObjKind::Commit => {
                let mut engine = Engine::new(&mut repo, &keys, DigestCache::memory_only());
                let (d, _) = engine.digest_commit(oid).map_err(|e| e.message)?;
                println!("{}", to_hex(&d));
                return Ok(0);
            }
            ObjKind::Tree => {
                let mut engine = Engine::new(&mut repo, &keys, DigestCache::memory_only());
                let d = engine.digest_tree(oid).map_err(|e| e.message)?;
                println!("{}", to_hex(&d));
                return Ok(0);
            }
            ObjKind::Blob => {
                let mut engine = Engine::new(&mut repo, &keys, DigestCache::memory_only());
                let d = engine.digest_blob(oid).map_err(|e| e.message)?;
                println!("{}", to_hex(&d));
                return Ok(0);
            }
        }
    }
}

fn cmd_check(args: &[String]) -> Result<i32, String> {
    let mut rev: Option<&str> = None;
    let mut expect_hex: Option<&str> = None;
    let mut missing_arg: Option<&str> = None;
    let mut allow_shallow = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--expect" => {
                i += 1;
                expect_hex = Some(args.get(i).ok_or("--expect requires a 64-hex digest")?);
            }
            "--missing" => {
                i += 1;
                missing_arg = Some(
                    args.get(i)
                        .ok_or("--missing requires silent, warn, or error")?,
                );
            }
            "--no-shallow" => allow_shallow = false,
            s if s.starts_with('-') => return Err(format!("unknown option: {s}")),
            s => {
                if rev.is_some() {
                    return Err(format!("unexpected extra revision argument: {s}"));
                }
                rev = Some(s);
            }
        }
        i += 1;
    }

    let rev_str = rev.unwrap_or("HEAD");
    let expect = match expect_hex {
        Some(h) => Some(hex_to_32(h.as_bytes())?),
        None => None,
    };

    let mut repo = GitRepo::open(None)?;
    let policy = MissingPolicy::from_repo(&repo, missing_arg)?;
    let oid = repo.rev_parse(rev_str)?;
    let keys = ContextKeys::new();

    match verify_target(&mut repo, &keys, oid, Some(rev_str), expect, allow_shallow) {
        Ok(CheckOutcome::Match {
            target_oid,
            digest,
            sealed_checked,
            plain_covered,
            shallow_stops,
        }) => {
            println!("MATCH {}", to_hex(&target_oid));
            println!("  blake3:         {}", to_hex(&digest));
            println!(
                "  commits:        {} carrying lines, {} plain covered",
                sealed_checked, plain_covered
            );
            if shallow_stops > 0 {
                println!(
                    "  incomplete:     stopped at {} shallow boundary parent(s)",
                    shallow_stops
                );
            }
            Ok(0)
        }
        Ok(CheckOutcome::NoEvidence { target_oid, digest }) => match policy {
            MissingPolicy::Silent => Ok(0),
            MissingPolicy::Warn => {
                eprintln!(
                    "NO EVIDENCE for {} (computed blake3: {})",
                    to_hex(&target_oid),
                    to_hex(&digest)
                );
                Ok(0)
            }
            MissingPolicy::Error => {
                eprintln!(
                    "NO EVIDENCE for {} (computed blake3: {})",
                    to_hex(&target_oid),
                    to_hex(&digest)
                );
                Ok(2)
            }
        },
        Err(VerifyError { kind, message }) => {
            let label = match kind {
                git_buttress::protocol::VerifyErrorKind::Mismatch => "MISMATCH",
                git_buttress::protocol::VerifyErrorKind::Incomplete => "INCOMPLETE",
            };
            eprintln!("{label}: {message}");
            Ok(1)
        }
    }
}

fn cmd_fsck(args: &[String]) -> Result<i32, String> {
    let mut missing_arg: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--missing" => {
                i += 1;
                missing_arg = Some(
                    args.get(i)
                        .ok_or("--missing requires silent, warn, or error")?,
                );
            }
            other => return Err(format!("unknown option for fsck: {other}")),
        }
        i += 1;
    }
    let mut repo = GitRepo::open(None)?;
    let (matched, no_ev) = fsck_all_refs(&mut repo, missing_arg)?;
    println!(
        "buttress fsck: {matched} ref(s) verified, {no_ev} ref(s) without buttress lines"
    );
    Ok(0)
}

fn cmd_log(args: &[String]) -> Result<i32, String> {
    let mut count = 15usize;
    let mut rev: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--max-count" => {
                i += 1;
                count = args
                    .get(i)
                    .ok_or("-n requires a number")?
                    .parse()
                    .map_err(|_| "invalid -n count")?;
            }
            s if s.starts_with("-n") => {
                count = s[2..].parse().map_err(|_| "invalid -n count")?;
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown option for log: {s}"));
            }
            s => {
                if rev.is_some() {
                    return Err(format!("unexpected extra revision argument for log: {s}"));
                }
                rev = Some(s);
            }
        }
        i += 1;
    }
    let rev = rev.unwrap_or("HEAD");

    let mut repo = GitRepo::open(None)?;
    let out = repo.run(["rev-list", &format!("-n{count}"), rev], None)?;
    let oids: Vec<_> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| git_buttress::git::hex_to_oid(l.trim().as_bytes()).ok())
        .collect();

    let keys = ContextKeys::new();
    let mut engine = Engine::new(&mut repo, &keys, DigestCache::memory_only());
    for oid in oids {
        let pc = engine.load_commit(oid).map_err(|e| e.message)?;
        let (dig, _) = engine.digest_commit(oid).map_err(|e| e.message)?;
        let tag = match pc.class {
            CommitClass::Sealed { .. } => "buttressed",
            CommitClass::Plain => "plain     ",
            CommitClass::Stale => "stale-amnd",
        };
        let sig = if pc.has_gpgsig { " [sig]" } else { "" };
        let (_, body) = split_headers_body(&pc.raw);
        let subj = String::from_utf8_lossy(body)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!(
            "{}  b3:{}  [{}]{}  {}",
            &to_hex(&oid)[..12],
            &to_hex(&dig)[..16],
            tag,
            sig,
            subj
        );
    }
    Ok(0)
}

fn cmd_seal_head(args: &[String]) -> Result<i32, String> {
    let mut sign = false;
    let mut quiet = false;
    for a in args {
        match a.as_str() {
            "--sign" | "-S" => sign = true,
            "--quiet" | "-q" => quiet = true,
            other => return Err(format!("unknown option for seal-head: {other}")),
        }
    }
    let mut repo = GitRepo::open(None)?;
    if repo.config_bool("buttress.disabled", false) {
        return Ok(0);
    }
    seal_head(&mut repo, sign, quiet)?;
    Ok(0)
}
