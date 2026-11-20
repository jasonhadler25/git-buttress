# git-buttress

**Install once, keep typing plain `git`, and give your repositories a second
spine made of BLAKE3.**

Old Git carries it without noticing. Anyone with `git-buttress` checks it
automatically.

> **Status:** Design & specification preview ([`BUTTRESS.md`](BUTTRESS.md)).
> The terminal sessions below show the target user experience; the earlier
> prototype in this repository (`git-b3`) is being updated to match.

---

## Why? How Git checks your files today

Every commit ID in Git is a **SHA-1** fingerprint computed from that commit
and, through it, every file and history step behind it. Whenever you clone,
pull, or pin a commit ID, Git relies on one rule: *different contents produce a
different SHA-1 ID.*

SHA-1 is old and weakened. Today Git uses **SHA1DC**, a variant that detects
known collision techniques, so Git is not visibly broken right now. The catch
is that cryptographic hashes only ever get weaker—and an attacker who finds a
way past SHA1DC does **not** have to publish a paper first.

`git-buttress` tucks a second fingerprint—computed with **BLAKE3**—inside new
commits and release tags, in places stock Git already stores, transfers, and
ignores.

---

## How it works in real life: Maya, Dana, and Sam

### 1. Today: Maya installs once and keeps typing plain `git`

Maya maintains `acme-tls`. Two teammates work with her; neither of them
installs `git-buttress`, and neither ever has to.

Maya runs one setup command on her laptop:

```text
$ git buttress enable --global
Configured global Git hooks for git-buttress (commit, tag, fetch, pull, clone).
```

From that moment on, she never types `git buttress` again. She uses plain `git`
(or her editor's Git button):

```text
$ git add src/verify.c
$ git commit -m "Release 2.4.0"
[main 9f3c1a2] Release 2.4.0
 1 file changed, 14 insertions(+)

$ git tag v2.4.0
buttress: also created tag v2.4.0+blake3-71e4b908fa2c03d19e5b44a2c8f01d6e3a7792b504c1e8f3a6d902b7e1c45f80

$ git push --follow-tags
```

Behind the scenes, two quiet things happened:

1. Her commit `9f3c1a2` now carries hidden BLAKE3 fingerprints of the entire
   directory tree and parent history. On GitHub it looks completely ordinary.
   When her teammates push plain commits and Maya later makes another commit,
   her commit automatically covers their plain commits too:

   ```text
   ... ──► [old history] ──► [9f3c1a2 Maya] ──► [a18d0e4 teammate] ──► [c4027b1 Maya]
                               has BLAKE3          plain commit          has BLAKE3
                                                                       (covers all of ←)
   ```

2. When she ran `git tag v2.4.0`, `git-buttress` also created a companion tag
   whose name embeds the release's BLAKE3 fingerprint (`v2.4.0+blake3-71e4...`
   — valid Git tag syntax and valid SemVer build metadata). It shows up right
   on GitHub's Tags page and in `git ls-remote --tags` without Maya running any
   extra command to look up an ID.

---

### 2. Today: Dana upgrades `acme-tls` the exact same way she always does

Dana maintains an application that depends on `acme-tls`. She does **not** have
`git-buttress` installed either. Look at how she records the dependency in her
`Cargo.toml` (or Nix flake, Go module, or release script), compared to what she
already writes today:

```toml
# Without git-buttress:
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0" }

# Copy-pasted from acme-tls's tags list:
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0+blake3-71e4b908fa2c03d19e5b44a2c8f01d6e3a7792b504c1e8f3a6d902b7e1c45f80" }
```

No new file format, no extra sidecar file, no special plugin required for Cargo
or Git: to stock Git it's just a tag name. Dana commits her `Cargo.toml` and
moves on with her life.

---

### 3. Years later: a silent SHA1DC exploit is uncovered in the wild

One Tuesday morning, an incident report drops:

> *While investigating a supply-chain compromise, responders discovered
> malicious commits and files in public Git mirrors whose **SHA1DC hashes match
> the SHA1DC hashes of legitimate objects**. Forensics show the capability was
> used privately for at least 18 months before discovery.*

Notice why that last sentence is terrifying: **nobody can assume that a SHA-1
commit ID they wrote down last month—or last year—is safe**, because the
attacker may already have planted a twin with the exact same SHA-1.

```text
                    SHA1DC ID      BLAKE3
Maya's real file    83a1d0...      4c91e7...
Mirror's twin file  83a1d0...      9902b1...   ← different!
                    ▲
              stock Git checks only this
```

Sam is an engineer building Dana's application against a mirror that was
quietly poisoned months ago. Look at what happens with stock Git alone:

```text
$ git fsck --full
                    # silent — every SHA1DC hash matches!
```

Now look at what happens because Sam ran `git buttress enable --global` once on
his machine—when he runs plain `git pull`, plain `git clone`, or `git buttress fsck`:

```text
$ git clone --branch v2.4.0+blake3-71e4b908fa2c03d19e5b44a2c8f01d6e3a7792b504c1e8f3a6d902b7e1c45f80 \
    https://mirror.example/acme-tls.git
Cloning into 'acme-tls'...
buttress: MISMATCH on tag v2.4.0+blake3-71e4b908...
  directory expected: a75286bbdeff3459...
  directory actual:   09f13c82bd4177aa...
fatal: in 'prepared' phase, update aborted by the reference-transaction hook
```

Git aborts the clone before writing a single file to Sam's working directory.

Why couldn't the attacker fool Sam?

* **If the attacker swapped only a file** for a SHA1DC twin, the BLAKE3
  fingerprint inside commit `9f3c1a2` catches it.
* **If the attacker also forged a twin of commit `9f3c1a2` itself** with
  rewritten BLAKE3 lines (or stripped the lines out), its BLAKE3 commit
  fingerprint no longer equals `71e4b908...`—the value sitting right inside
  Dana's `Cargo.toml` tag name (or in Sam's earlier clean clone on his laptop).
  To get past that check, the attacker would have to break **BLAKE3**.

---

### 4. Recovery: telling clean backups from poisoned ones

Maya now faces three mirrors and two developer laptops that **all report the
exact same SHA-1 commit ID `9f3c1a2`**. Without `git-buttress`, she would have
no automated way to know whether an 18-month-old subtle twin is hiding deep in
her 50,000-file history.

With the BLAKE3 tag name from Dana's `Cargo.toml` (or an old release email),
she checks each copy:

```text
mirror-a: MISMATCH at commit 41b09e2 (src/asn1.c)
mirror-b: MATCH (all 412 commits and every file verified)
laptop:   MATCH (all 412 commits and every file verified)
```

`mirror-b` and her laptop are mathematically proven to hold the exact bytes she
shipped, all the way back to the first commit of the project—ready to migrate
cleanly to whatever Git ships next.

---

## Honest scope & sharp edges

* **One tiny quirk on `git commit`:** Git has no hook that modifies raw commit
  headers *before* Git prints `[main <short-id>]`, so `post-commit` seals the
  commit a millisecond afterward, updating its local SHA-1 before you push.
* **`git fsck` itself isn't hookable in stock Git:** Automatic checking runs on
  every `git clone`, `git fetch`, and `git pull` (via Git's
  `reference-transaction` hook); for an on-demand full-repo audit of an
  already-cloned disk directory, run `git buttress fsck`.
* **Not magic without a prior foothold:** If you clone from a dishonest server
  for the very first time using only a plain branch name (`main`), with no
  `+blake3-...` tag and no prior local clone, that server can hand you any
  internally consistent history it likes—just as with stock Git today.
  `git-buttress` ensures that **any** foothold you or your users already hold
  still protects you even if SHA1DC falls.

---

## Repository Contents

* [`BUTTRESS.md`](BUTTRESS.md) — Draft specification of `git-buttress` (wire
  headers, BLAKE3 context-string derivations, verification rules, safety
  argument, test vectors, and full Linux-kernel benchmark numbers: **1 min 18 s**
  for all 1.5M commits / 141 GB of files).
* [`buttress-vectors.py`](buttress-vectors.py) — 60-line standalone reference
  script computing every digest in `BUTTRESS.md` using only stock `git` and
  `b3sum`.
* [`git-b3`](git-b3), [`SPEC.md`](SPEC.md), [`test_git_b3.py`](test_git_b3.py)
  — Working v0.1 prototype and adversarial test suite from the earlier design
  iteration.
