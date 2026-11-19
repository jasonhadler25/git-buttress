---
description: Backwards-compatible BLAKE3 Merkle integrity overlay smuggled into standard Git commits and tags
---

# git-b3

## 1. Introduction

This document specifies **git-b3** (version 1), a backwards-compatible protocol
for embedding [BLAKE3][] Merkle integrity commitments into standard SHA-1 Git
repositories without modifying Git's blob format, tree format, packfile format,
wire protocol, or historical commit IDs.

**git-b3** is designed so that:

* **Zero breakage for existing Git:** Every commit and tag produced by `git-b3`
  passes `git fsck --full --strict`, pushes cleanly to GitHub/GitLab/stock Git
  servers, remains invisible in `git log` / `git show` / web UIs, and verifies
  under stock `git verify-commit` and `git verify-tag`.
* **Total SHA-1 / SHA1DC break resilience:** Even if an adversary can compute
  arbitrary SHA-1 collisions and second preimages in constant time, a verifier
  holding any BLAKE3 root of trust (a signed `git-b3` commit, a signed `git-b3`
  tag, an out-of-band pinned BLAKE3 commit ID, or a previously verified local
  commit) detects any tampering with any blob, symlink, executable bit,
  directory entry, commit message, or historical ancestor.
* **Retroactive sealing of legacy history:** A single `git-b3` commit on top of
  an existing SHA-1 repository cryptographically seals the entire reachable
  legacy history (every ancestor commit, tree, and blob) without rewriting any
  historical SHA-1 commit IDs.
* **Mixed-team & shallow-clone friendly:** Teammates on unmodified stock Git
  can commit, merge, rebase, cherry-pick, and even amend commits on the same
  repository without breaking `git-b3`, and `--depth=1` shallow clones of a
  sealed commit verify in $O(1)$ commits.

## 2. Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] ([RFC 2119][],
[RFC 8174][]) when, and only when, they appear in all capitals, as shown here.

`BLAKE3(x)` denotes the standard unkeyed 256-bit (32-byte) BLAKE3 hash of byte
sequence `x` as specified in [BLAKE3][]. `||` denotes byte concatenation.
`u32_le(n)` and `u64_le(n)` denote unsigned 32-bit and 64-bit little-endian
integers. `hex(b)` denotes lowercase hexadecimal encoding (`[0-9a-f]`).

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[BLAKE3]: https://c2sp.org/BLAKE3

## 3. Domain-Separated BLAKE3 Object Hashing

All four object domains use distinct null-terminated ASCII prefixes so blobs,
trees, sealed commits, and legacy commits can never collide with one another.

### 3.1. Blobs (`B3Blob`)

For a Git blob with raw uncompressed content `raw` (as returned by
`git cat-file blob <oid>`, excluding Git's loose-object `"blob <len>\0"`
framing):

    B3Blob(raw) = BLAKE3("git-b3-blob-v1\x00" || raw)

### 3.2. Trees (`B3Tree`)

For a Git tree object whose entries in Git's canonical sorted order are
`(mode_i, name_i, sha1_i)` (where `mode_i` is the normalized ASCII octal mode
without leading zero—e.g. `40000`, `100644`, `100755`, `120000`, `160000`—and
`sha1_i` is the 20-byte child OID):

    B3Tree(T) = BLAKE3("git-b3-tree-v1\x00" || E_1 || E_2 || ... || E_m)

where each encoded entry `E_i` is:

    E_i = mode_i || 0x20 || name_i || 0x00 || child_hash_i

and `child_hash_i` is:

* `B3Tree(sha1_i)` (32 bytes) if `mode_i == "40000"` (subtree);
* `sha1_i` (20 raw bytes) if `mode_i == "160000"` (submodule gitlink, so tree
  hashing does not require external submodules to be cloned);
* `B3Blob(blob(sha1_i))` (32 bytes) for all other modes (`100644`, `100755`,
  `120000`).

Because `mode_i` contains no space (`0x20`), `name_i` contains no NUL (`0x00`),
and `mode_i` uniquely determines whether `child_hash_i` is 20 or 32 bytes, the
encoding `E_1 || ... || E_m` is injective.

## 4. Smuggled Commit Headers

### 4.1. Syntax

A `git-b3` commit embeds extra commit headers in the Git commit header block
(after `committer` and before `gpgsig`, if present):

    blake3-tree <40-hex-tree-sha1> <64-hex-b3-tree>
    blake3-parent <40-hex-parent1-sha1> <64-hex-b3-parent1>
    blake3-parent <40-hex-parent2-sha1> <64-hex-b3-parent2>
    ...

Where:

* `<40-hex-*-sha1>` MUST match `[0-9a-f]{40}`.
* `<64-hex-b3-*>` MUST match `[0-9a-f]{64}`.
* A root commit (zero `parent` headers) has zero `blake3-parent` headers.
* A merge commit with `k` `parent` headers has `k` `blake3-parent` headers in
  the exact same order as the `parent` headers.
* When the commit is signed (`git commit -S` or `git b3 commit -S`), the
  `blake3-tree` and `blake3-parent` headers MUST be included in the signed
  payload covered by `gpgsig`.

### 4.2. Commit Classification (`sealed`, `legacy`, `stale`)

Why each header pairs the target SHA-1 with its BLAKE3 hash: stock Git's
`git commit --amend` strips `gpgsig` and `gpgsig-sha256`, but **blindly copies**
all other extra commit headers onto the amended commit—even when the tree
changes. Pairing `<sha1>` with `<b3>` distinguishes benign stock-Git amends
from SHA-1 collision attacks with zero false positives and zero security loss.

Given a commit object with raw bytes `raw`, `tree` OID `T`, and ordered
`parent` OIDs `[P_1, ..., P_k]`, parse top-level (non-continuation) header
lines before the first `\n\n`:

1. If any `blake3-tree` or `blake3-parent` line does not match
   `^<key> [0-9a-f]{40} [0-9a-f]{64}$`, the commit is **malformed** (MUST
   reject).
2. If there is more than one `blake3-tree` line, or zero `blake3-tree` lines
   with one or more `blake3-parent` lines, the commit is **malformed** (MUST
   reject).
3. If there are zero `blake3-tree` lines and zero `blake3-parent` lines, the
   commit is classified as **`legacy`**.
4. Otherwise (exactly one `blake3-tree <t_sha1> <t_b3>` line and `m`
   `blake3-parent <p_i_sha1> <p_i_b3>` lines):
   * If `t_sha1 == T`, `m == k`, and `p_i_sha1 == P_i` for all `1 <= i <= k`,
     the commit is classified as **`sealed`**.
   * Otherwise (e.g., copied onto a modified tree by stock `git commit --amend`),
     the commit is classified as **`stale`**.

### 4.3. Commit Hashing (`B3Commit`)

* If commit `C` is **`sealed`**:

      B3Commit(C) = BLAKE3("git-b3-commit-v1\x00" || C.raw)

  Because `C.raw` already embeds `B3Tree(C.tree)` and `B3Commit(P_i)` for every
  parent, `B3Commit(C)` is $O(1)$ and does not require parent objects to
  compute (enabling `--depth=1` shallow clones).

* If commit `C` is **`legacy`** or **`stale`**:

      B3Commit(C) = BLAKE3(
        "git-b3-legacy-v1\x00"
        || u64_le(len(C.raw)) || C.raw
        || B3Tree(C.tree)
        || u32_le(k)
        || B3Commit(P_1) || ... || B3Commit(P_k)
      )

  Recursion terminates immediately at any **`sealed`** ancestor (or at root
  commits where `k == 0`).

Notice that **`sealed`** and **`legacy`/`stale`** commits use disjoint domain
prefixes (`git-b3-commit-v1\x00` vs `git-b3-legacy-v1\x00`), so an adversary
cannot confuse one with the other.

## 5. Annotated and Signed Tags

Git's `fsck_tag_standalone()` rejects unknown extra headers in tag objects
(`FSCK_MSG_EXTRA_HEADER_ENTRY`). Therefore, `git-b3` annotated and signed tags
place a trailer line in the tag message body (before any PGP/SSH signature
block):

    Blake3-Object: <40-hex-target-sha1> <64-hex-target-b3>

For a commit target `C`, `<64-hex-target-b3>` is `hex(B3Commit(C))`. The
trailer is covered automatically by standard `git tag -s` signatures and passes
`git mktag`, `git fsck --strict`, and `git verify-tag`.

## 6. Verification Algorithm

A verifier MUST NOT trust any unauthenticated on-disk BLAKE3 cache when
verifying; it MUST read and hash the raw Git objects from the repository
object store (in-memory memoization within a single verification run is
permitted).

To verify a revision `R` with optional expected ID `expect_b3` and optional
`require_signature`:

1. **Tag handling:** If `R` resolves to an annotated tag, parse its
   `Blake3-Object: <t_sha1> <t_b3>` trailer. Reject if missing, malformed,
   duplicated, or if `<t_sha1>` does not equal the tag's `object` header. If
   `require_signature` is set, verify the tag signature via `git verify-tag`.
   If `expect_b3` was also supplied, verify `expect_b3 == t_b3`. Proceed to
   verify target `<t_sha1>` with `expect_b3 = t_b3`.
2. **Root commit check:** Parse commit `C_0`.
   * If `require_signature` is set and no tag signature was already verified,
     `C_0` MUST be `sealed` (a signature on a `legacy` or `stale` commit only
     signs SHA-1 hashes!) and MUST pass `git verify-commit`.
   * If `C_0` is not `sealed` and `expect_b3` is absent, MUST reject (fail
     closed).
   * Compute `B3Commit(C_0)`. If `expect_b3` is present, verify
     `B3Commit(C_0) == expect_b3` in constant time.
3. **Graph walk:** Maintain a queue of reachable `sealed` commits (starting
   with `C_0` if `sealed`, plus any `sealed` ancestors discovered underneath a
   `legacy`/`stale` `C_0`). For each `sealed` commit `C`:
   * Recompute `B3Tree(C.tree)` from raw tree and blob objects and verify
     constant-time equality with `C`'s `blake3-tree` header.
   * For each `(P_i, expected_p_b3)` in `C`'s `blake3-parent` headers:
     * If `P_i` is absent because `C` is at a shallow clone boundary, stop at
       that boundary if shallow clones are permitted; otherwise reject.
     * Compute `B3Commit(P_i)` and verify constant-time equality with
       `expected_p_b3`.
     * Enqueue `P_i` (if `sealed`) and every `sealed` ancestor discovered
       underneath `P_i` (if `P_i` was `legacy`/`stale`).

## 7. Security Considerations

* **Root of trust:** Once SHA-1 is broken, SHA-1 commit IDs and unsigned refs
  are not roots of trust. Verifiers MUST anchor verification in at least one
  of: a verified signature on a `sealed` commit (`gpgsig`), a verified
  signature on a `git-b3` tag (`Blake3-Object:`), an out-of-band pinned
  `B3Commit` ID (`--expect`), or fast-forward reachability from a previously
  trusted local commit.
* **SHA-1 collisions in `.git/objects`:** Even if a malicious remote serves a
  SHA-1-colliding blob or tree `X'` with `SHA1(X') == SHA1(X)`, the verifier
  hashes the actual bytes read from `.git/objects` with BLAKE3 and rejects `X'`,
  turning silent forgery into a detected denial of service.
* **Submodules (`160000` gitlinks):** In v1, `B3Tree` commits to the 20-byte
  gitlink SHA-1 so parent repositories can be verified without cloning
  submodules. Repositories that require SHA-1-independent submodule pinning can
  verify each submodule independently via its own `B3Commit` ID or add a future
  `blake3-gitlink` header.

## Appendix A: Quick Shell Verification One-Liners

For any blob `<oid>` or any `sealed` commit `<oid>`, anyone with stock `git`
and `b3sum` can independently check `B3Blob` and `B3Commit`:

    (printf 'git-b3-blob-v1\0'; git cat-file blob <oid>) | b3sum
    (printf 'git-b3-commit-v1\0'; git cat-file commit <oid>) | b3sum

Empty blob (`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`):

    B3Blob("") = 30ffb0f8445581c9d2f5243d9c4162ede4c25db813b5dd61e970fde0289fdcfa

Empty tree (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`):

    B3Tree(empty) = 3eea7e58fa5554c1eb42888e1b6bd14c205be9bbe6687a0a105f69a6fa9fd1f6
