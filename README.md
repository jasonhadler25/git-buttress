# git-buttress

**Install once, keep typing plain `git`, and give your repositories an
invisible second spine made of BLAKE3.**

Nothing visible changes on GitHub, in `git log`, or in your tag list. Teammates
and users don't have to install or change a thing. Anyone with `git-buttress`
checks it automatically.

---

## Why? How Git checks your files today

Every commit ID in Git is a **SHA-1** fingerprint computed from that commit
and, through it, every file and history step behind it. Whenever you clone,
pull, sign a commit, or pin a version, Git relies on one rule: *different
contents produce a different SHA-1 ID.*

SHA-1 is old and weakened. Today Git uses **SHA1DC**, a variant that detects
known collision techniques, so Git is not visibly broken right now. The catch
is that cryptographic hashes only ever get weaker—and an attacker who finds a
way past SHA1DC does **not** have to publish a paper first.

`git-buttress` tucks a second fingerprint—computed with **BLAKE3**—inside new
commits in a header slot stock Git already stores, transfers, signs, and
ignores.

---

## How it works in real life: Maya and Sam

### 1. Today: Maya enables it once—and nothing visible changes anywhere

Maya maintains `acme-tls`. Two teammates work with her; neither of them
installs `git-buttress`, and neither ever notices she did.

Maya runs one setup command on her laptop:

```text
$ git buttress enable --global
Configured global Git hooks for git-buttress at ~/.config/git-buttress/hooks
Installed transparent `git` wrapper at ~/.local/bin/git
```

From that moment on, she never types `git buttress` again. She uses plain `git`
(or her editor's Git button):

```text
$ git add src/verify.c
$ git commit -m "Release 2.4.0"
[main 9f3c1a2] Release 2.4.0
 1 file changed, 14 insertions(+)

$ git tag -a v2.4.0 -m "Release 2.4.0"
$ git push --follow-tags
```

Look at what changed on GitHub: **nothing.** Commit `9f3c1a2` looks ordinary,
tag `v2.4.0` is just `v2.4.0`, and downstream users keep depending on `v2.4.0`
without changing a character.

Behind the scenes, commit `9f3c1a2` carries hidden BLAKE3 fingerprints of the
entire directory tree and parent history. When her teammates push plain commits
and Maya later makes another commit, her commit automatically covers their
plain commits too:

```text
... ──► [old history] ──► [9f3c1a2 Maya] ──► [a18d0e4 teammate] ──► [c4027b1 Maya]
                            has BLAKE3          plain commit          has BLAKE3
                                                                    (covers all of ←)
```

---

### 2. Years later: a silent SHA1DC exploit is uncovered in the wild

One Tuesday morning, an incident report drops:

> *While investigating a supply-chain compromise, responders discovered
> malicious files and trees in public Git mirrors whose **SHA1DC hashes match
> the SHA1DC hashes of legitimate objects**. An innocent-looking file had been
> contributed months earlier, and its malicious twin—sharing the exact same
> SHA1DC hash—was swapped into mirrors afterward. Forensics show the capability
> was used privately for at least 18 months before discovery.*

Notice why that last sentence is terrifying: **nobody can assume that a SHA-1
commit ID they wrote down last month—or last year—is safe**, because the
attacker may already have planted a twin with the exact same SHA1DC hash.

```text
                    SHA1DC ID      BLAKE3
Maya's real file    83a1d0...      4c91e7...
Mirror's twin file  83a1d0...      9902b1...   ← different!
                    ▲
              stock Git checks only this
```

Sam is an engineer who uses `acme-tls`. Look at what happens with stock Git
alone on a poisoned mirror:

```text
$ git fsck --full
                    # silent — every SHA1DC hash matches!
```

Now look at what happens because Maya had `git-buttress` enabled when she made
commit `9f3c1a2`—even though nobody ever used special tag names:

1. **Against a collision swap (on *any* clone, even a brand-new one!):** When
   Maya committed the innocent file months ago, commit `9f3c1a2` baked in the
   innocent file's **BLAKE3** fingerprint. The attacker swapped the file for
   its SHA1DC collision twin on the mirror, *without* being able to rewrite the
   already-published commit `9f3c1a2`. As soon as Sam clones or runs `git fsck`:

   ```text
   $ git clone https://mirror.example/acme-tls.git
   Cloning into 'acme-tls'...
   buttress: MISMATCH on refs/remotes/origin/main
     MISMATCH at commit 9f3c1a2... (directory cda7b79...):
       directory expected: a75286bbdeff3459...
       directory actual:   09f13c82bd4177aa...
   fatal: in 'prepared' phase, update aborted by the reference-transaction hook
   ```

   Git aborts the clone before writing a single file to Sam's working directory.

2. **On Sam's existing laptop clone or CI cache:** Sam already holds genuine
   commit headers from earlier `git pull`s. If a compromised server later serves
   a poisoned historical object during `git fetch`/`git pull` or a `git fsck`
   audit, Sam's local `buttress-tree` and `buttress-parent` lines catch it
   immediately.

3. **If Maya signs commits with SSH/GPG (`git commit -S`) and Sam verifies her
   key (`git verify-commit`):** Without `git-buttress`, a Git commit signature
   only signs SHA-1 hashes—so swapping a file for a SHA1DC twin **leaves
   `git verify-commit` completely green!** With `git-buttress`, Maya's normal
   SSH signature automatically covers the BLAKE3 fingerprints inside the commit
   header, so verifying her signature + `git buttress check` protects even
   brand-new users against a total SHA-1 break.

4. **Sorting clean backups from poisoned mirrors:** Maya has five mirrors and
   laptops all reporting `HEAD = 9f3c1a2`. Running `git fsck` immediately shows
   which copies match the BLAKE3 spine (`MATCH`, all 412 commits verified) and
   which copy holds the swapped twin (`MISMATCH`)—so she can migrate cleanly to
   whatever Git ships next.

---

## Optional Layer 2: Self-verifying `+blake3-` release tags

What if an attacker goes even further than collisions—what if they have a full
**second-preimage** break that lets them forge a brand-new replacement commit
object with the exact SHA-1 `9f3c1a2` (stripping or rewriting the BLAKE3 lines),
*and* Maya doesn't use SSH commit signing, *and* Dana is cloning for the very
first time?

For maintainers who want downstream dependency pins to survive even that
worst-case scenario, `git-buttress` supports an opt-in companion tag setting:

```sh
git config --global buttress.autotag true
```

When opted in, running `git tag v2.4.0` keeps normal `v2.4.0` **and** also
creates a companion tag whose name carries the release's BLAKE3 commit
fingerprint (`git describe --tags` still prefers the short `v2.4.0`):

```toml
# Standard Cargo.toml dependency (still works everywhere):
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0" }

# Optional belt-and-suspenders pin (valid Git tag & SemVer build metadata):
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0+blake3-71e4b908fa2c03d19e5b44a2c8f01d6e3a7792b504c1e8f3a6d902b7e1c45f80" }
```

To stock Git and Cargo it's just an ordinary tag name; to any machine running
`git-buttress`, cloning or fetching that tag automatically enforces the
embedded 256-bit BLAKE3 digest.

---

## Build & Quickstart

```sh
cargo build --release
export PATH="$HOME/.local/bin:$PWD/target/release:$PATH"
git buttress enable --global

# Verify this repository itself:
git fsck --full --strict
git buttress log
```

Run the full integration and adversarial SHA1DC-collision test suite:

```sh
cargo test --release
```

---

## Honest scope & sharp edges

* **How `git commit` and `git fsck` stay seamless:** `git buttress enable`
  configures global Git hooks (`post-commit` for commit/rebase/cherry-pick
  sealing and `reference-transaction` for `clone`/`fetch`/`pull` verification,
  forwarding all 28 standard Git hooks to any prior `core.hooksPath` or
  `.git/hooks/`) **plus** a tiny transparent `git` wrapper in `~/.local/bin/git`.
  On `git commit`, `post-commit` rewrites the new local commit with BLAKE3
  headers via `git update-ref` compare-and-swap while the wrapper holds `-q` so
  terminal output prints only the final `[branch <sealed-sha>]` summary; on
  `git fsck`, it runs stock `git fsck` followed automatically by
  `git buttress fsck`. (`refs/replace/*` grafts are ignored during verification;
  do not rely on `refs/replace` when consuming verified repositories.)
* **Configurable policy when BLAKE3 lines are absent:** Mixed teams work out of
  the box because `buttress.missing` defaults to `silent` (mismatch is *always*
  a hard error). Set `git config --global buttress.missing warn` or `error` when
  you want unbuttressed refs flagged or rejected.
* **Not magic without a prior foothold:** Against a full second-preimage break
  where an attacker controls the server and you clone for the very first time
  using only an unsigned branch name (`main`) with no prior clone, commit
  signature, or `+blake3-` tag, that server can hand you any internally
  consistent history it likes—just as with stock Git today.

---

## Repository Contents

* [`src/`](src/) & [`Cargo.toml`](Cargo.toml) — Rust implementation of
  `git-buttress` built on [`blake3-servil`](https://github.com/servil-software-factory/BLAKE3).
* [`CONTRACTS.md`](CONTRACTS.md) — Design-by-Contract (Hoare/Meyer/Ode-style)
  specifications, representation invariants, and trust boundaries for every
  module, stateful type, hook, wrapper, and CLI subcommand.
* [`tests/integration.rs`](tests/integration.rs) — End-to-end tests of the
  invisible commit/clone workflow, opt-in `+blake3-` tags, SSH signing,
  `rebase`/`amend`, shallow boundaries, contract edge cases, and simulated
  SHA1DC collision/second-preimage attacks.
* [`BUTTRESS.md`](BUTTRESS.md) — Specification of `git-buttress` (wire headers,
  BLAKE3 context-string derivations, verification rules, safety argument, test
  vectors, and full Linux-kernel benchmark numbers: **1 min 18 s** for all 1.5M
  commits / 141 GB of files).
* [`buttress-vectors.py`](buttress-vectors.py) — 60-line standalone reference
  script computing every digest in `BUTTRESS.md` using only stock `git` and
  `b3sum`.
