# git-b3

**Smuggle BLAKE3 Merkle integrity into standard Git repositories — with zero
breakage for stock Git, GitHub, GitLab, `git fsck --strict`, or
`git verify-commit`.**

```text
[2005 legacy P0] ─► ... ─► [2026 legacy P999] ─► [C1 (git-b3)] ─► [L1 (stock git)] ─► [C2 (git-b3)]
                                                       │                                    │
                                        retroactively seals ALL                   seals L1 and stops
                                        legacy commits/trees/blobs                at C1 in O(1) steps!
```

## Why?

Git’s SHA-256 transition creates an incompatible object store and wire format
that cannot push to existing SHA-1 repositories. `git-b3` takes a different
approach:

- **Blobs and trees are untouched** — zero working-tree pollution, zero
  packfile/protocol changes.
- **Commits smuggle `blake3-tree` and `blake3-parent` extra headers** (invisible
  in `git log` / GitHub UI, accepted by `git fsck --full --strict`, and
  **automatically signed by stock `git commit -S` (SSH/GPG)**!).
- **Annotated/signed tags smuggle a `Blake3-Object:` trailer** in the tag body
  (covered by `git tag -s` and valid under `git mktag` / `git fsck --strict`).
- **One new `git-b3` commit retroactively seals all legacy SHA-1 history**
  without changing a single historical SHA-1 commit ID.
- **Resilient even to a total SHA-1 / SHA1DC second-preimage break:** any
  forged blob, symlink, executable bit, directory entry, commit message, or
  ancestor is detected immediately by recomputing BLAKE3 over the raw objects.
- **Handles stock `git commit --amend` safely:** pairing each BLAKE3 digest
  with its target SHA-1 distinguishes benign stock-Git amends (which blindly
  copy unknown commit headers) from SHA-1 collision attacks.

## Quickstart

`git-b3` is a single, zero-dependency Python 3 executable (uses native
`blake3` if installed via `pip install blake3`, otherwise falls back to its
built-in C2SP-compliant pure-Python BLAKE3 implementation).

```sh
# 1. Put git-b3 on your PATH (or run ./git-b3 directly)
chmod +x git-b3

# 2. Verify THIS repository itself (it is dogfooded with git-b3 commits!)
./git-b3 verify
./git-b3 log

# 3. Create a sealed commit (use -S to sign with SSH/GPG)
git add file.txt
./git-b3 commit -m "Add feature"

# 4. Or install a post-commit hook so even plain `git commit` seals automatically
./git-b3 install-hook

# 5. Create a signed annotated tag with a Blake3-Object trailer
./git-b3 tag -s v1.0.0 -m "Release v1.0.0"
./git-b3 verify v1.0.0 --require-signature
```

## Verify Independently with Stock `git` + `b3sum`

For any blob or any `sealed` commit, you don't even need `git-b3` to check the
hash:

```sh
(printf 'git-b3-blob-v1\0'; git cat-file blob <oid>) | b3sum
(printf 'git-b3-commit-v1\0'; git cat-file commit HEAD) | b3sum
```

## Running the Test Suite

```sh
python3 -m unittest test_git_b3.py -v
```

The test suite includes:
- Pure-Python BLAKE3 cross-checked against `b3sum` (when installed) and known
  vectors across chunk/tree boundaries;
- `git fsck --full --strict --dangling`, SSH-signed commits (`git verify-commit`),
  and signed tags (`git verify-tag`);
- Mixed stock-Git + `git-b3` history, merge commits, stock `git commit --amend`
  stale-header handling, `git cherry-pick` / `git rebase`, `post-commit` hook
  sealing, and `--depth=1` shallow clones;
- **Six simulated SHA-1 second-preimage / collision attacks** (evil blob in tip
  tree, evil blob in legacy history, flipped executable bit, forged ancestor
  commit message, forged stale-amend downgrade, and tampered tag target).

## Documentation

- [`SPEC.md`](SPEC.md) — Normative C2SP-style specification of `git-b3` v1.
- [`git-b3`](git-b3) — Standalone zero-dependency implementation.
- [`test_git_b3.py`](test_git_b3.py) — Full automated & adversarial test suite.
