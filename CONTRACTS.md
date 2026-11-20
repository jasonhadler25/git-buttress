# Design-by-Contract Specification (`git-buttress`)

This document states the **abstract meanings**, **representation invariants**,
**trust boundaries**, and **Hoare/Meyer/Ode-style operation contracts**
(`requires` / `ensures` / `writes`) for the `git-buttress` crate (`src/*.rs`)
and command-line executable (`git-buttress`).

It is intended both to hold the implementation to an explicit specification and
to give independent auditors a crisp, falsifiable set of obligations to check
against the code. Any undocumented precondition that the code relies on, or any
postcondition/invariant that an operation fails to establish or preserve, is a
defect.

---

## 1. Global Model, Pure Primitives, and Threat Model

### 1.1. Cryptographic Primitive

Let `dk(ctx: str, msg: [u8]) -> [u8; 32]` denote the first 32 bytes of standard
BLAKE3 in `DeriveKey` mode (`c2sp.org/BLAKE3`) with UTF-8 context string `ctx`
and message bytes `msg`.

The four domain-separated contexts (`src/protocol.rs`) are:

```text
CTX_FILE   = "git-buttress 2026-11-20 file"
CTX_DIR    = "git-buttress 2026-11-20 directory"
CTX_COMMIT = "git-buttress 2026-11-20 commit"
CTX_PLAIN  = "git-buttress 2026-11-20 plain commit"
```

### 1.2. Abstract Object Store (`ObjectStore`)

An `ObjectStore` `S` models a partial map:

```text
objects(S) : Oid ([u8; 20]) -> Option<(ObjKind, Vec<u8>)>
shallow(S) : Set<Oid>
```

**Threat model:** In a SHA-1 / SHA1DC compromise, an adversary can supply
arbitrary `(ObjKind, Vec<u8>)` under any 20-byte `Oid` (including SHA-1
collisions, second preimages, cyclic trees/commits/tags, malformed headers,
and `refs/replace/*` grafts). A verifier has **reliance** only on:

1. BLAKE3's collision and second-preimage resistance across `dk(ctx, msg)`;
2. Any expected 32-byte BLAKE3 digest `expect` supplied by the caller (via
   `--expect <64-hex>`, a `+blake3-<64-hex>` ref name, an annotated tag's
   `Buttress-Object:` trailer, or a previously verified local ref).

### 1.3. Pure Mathematical Digest Functions (`spec_*`)

Over an acyclic subgraph in `objects(S)`:

* **Blob (`spec_file`):** For `objects(S)[oid] == Some((Blob, raw))`:
  ```text
  spec_file(S, oid) = dk(CTX_FILE, raw)
  ```
* **Directory (`spec_dir`):** For `objects(S)[oid] == Some((Tree, raw))` whose
  well-formed entries are `[(mode_i, octal_i, name_i, child_i)]`:
  ```text
  spec_dir(S, oid) = dk(CTX_DIR, concat_i(mode_i || 0x20 || name_i || 0x00 || child_bytes_i))
  ```
  where:
  * `octal_i == 0o040000` => `child_bytes_i = spec_dir(S, child_i)` (32 bytes)
  * `octal_i == 0o160000` => `child_bytes_i = child_i` (20 raw bytes; submodule pointer)
  * otherwise => `child_bytes_i = spec_file(S, child_i)` (32 bytes)
* **Commit (`spec_commit`):** For `objects(S)[oid] == Some((Commit, raw))`
  classified by `parse_commit(oid, raw)` as `pc` with `k = pc.parents.len()`
  (`k <= u32::MAX`):
  * If `pc.class == Sealed { .. }`:
    ```text
    spec_commit(S, oid) = dk(CTX_COMMIT, raw)
    ```
  * If `pc.class in {Plain, Stale}` and `oid` is not truncated at a missing
    shallow parent:
    ```text
    spec_commit(S, oid) = dk(
      CTX_PLAIN,
      spec_dir(S, pc.tree)
      || u32_le(k)
      || spec_commit(S, pc.parents[0]) || ... || spec_commit(S, pc.parents[k - 1])
      || raw
    )
    ```

---

## 2. Crate & Trust-Boundary Invariants

1. **TB-1 (Read-path cache isolation):** No verification operation
   (`verify_target`, `fsck_all_refs`, `run_reference_transaction_hook("prepared")`,
   `cmd_check`, `cmd_fsck`, `cmd_id`, `cmd_log`) ever opens, reads, or writes
   `.git/buttress-cache.bin`. All construct `DigestCache::memory_only()`.
2. **TB-2 (Git graft & lazy-fetch isolation):** Every `git` subprocess spawned
   by `GitRepo` passes `--no-replace-objects` and sets
   `GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`.
3. **TB-3 (Wrapper non-recursion):** `resolve_real_git()` skips any file whose
   leading 256 bytes contain `WRAPPER_MARKER`, preventing `git-buttress` and
   `~/.local/bin/git` from invoking each other in a loop even if
   `GIT_BUTTRESS_REAL_GIT` is unset or corrupted to point at the wrapper.
4. **TB-4 (Dependency note — `blake3-servil` 0.9.1):** `Cargo.toml` depends on
   `blake3-servil` `0.9.1` with default features (`std` only; `zeroize` is
   **not** enabled). Every hash call in `git-buttress` uses
   `convenience::hash_with(Mode::DeriveKeyWith(&ContextKey), slice)`—never
   `Zeroize` and never `throughput::update_each`—so GHSA-v237-j9h9-8pf7 does not
   affect `git-buttress`.

---

## 3. Module `cache` (`src/cache.rs`)

### Type `DigestCache`

* **Meaning:** `(blobs, trees, commits, pending, disk_path)` where the three
  maps hold memoized `(Oid -> Dig)` entries.
* **Invariant `I_cache(c)`:**
  1. `c.disk_path.is_none() ==> c.pending.is_empty()`.
  2. Every `(kind, oid, dig)` in `c.pending` has `kind in {1, 2, 3}` and the
     corresponding map (`blobs`, `trees`, or `commits`) maps `oid` to `dig`.

```text
contract DigestCache::memory_only() -> DigestCache
  requires true
  ensures  I_cache(ret) and ret.disk_path == None and ret.blobs/trees/commits/pending all empty
  writes   —

contract DigestCache::load_from_git_dir(git_dir: &Path) -> DigestCache
  requires true
  ensures  I_cache(ret) and ret.disk_path == Some(git_dir.join("buttress-cache.bin"))
           and ret.pending.is_empty();
           if file begins with b"BTRSC001", loads floor((len - 8) / 53) complete records
           (later records for the same (kind, oid) overwrite earlier ones; unknown kind bytes ignored);
           missing/unreadable/bad-magic files yield empty maps without error
  writes   —

contract DigestCache::put_{blob,tree,commit}(self: &mut DigestCache, oid: Oid, dig: Dig)
  requires I_cache(self)
  ensures  I_cache(self) and map.contains_key(&oid);
           if old(!map.contains_key(&oid)), map[&oid] == dig and (if disk_path.is_some(), appended to pending)
  writes   self.{blobs|trees|commits}, self.pending

contract DigestCache::flush(self: &mut DigestCache)
  requires I_cache(self)
  ensures  I_cache(self) and self.pending.is_empty();
           if self.disk_path == Some(p) and !old(self.pending).is_empty(), best-effort writes records
           after repairing any missing header or truncating any torn (len - 8) % 53 != 0 tail on p
  writes   self.pending, filesystem[p]
```

---

## 4. Module `git` (`src/git.rs`)

### Trait implementations & Functions

```text
contract hex_to_oid(hex: &[u8]) -> Result<Oid, String>
  requires true
  ensures  Ok(oid) <==> hex.len() == 40 and all bytes in b'0'..=b'9' | b'a'..=b'f' (strict lowercase);
           to_hex(&oid).as_bytes() == hex
  writes   —

contract hex_to_32(hex: &[u8]) -> Result<[u8; 32], String>
  requires true
  ensures  Ok(dig) <==> hex.len() == 64 and all bytes in b'0'..=b'9' | b'a'..=b'f' (strict lowercase);
           to_hex(&dig).as_bytes() == hex
  writes   —

contract to_hex(bytes: &[u8]) -> String
  requires true
  ensures  ret.len() == 2 * bytes.len() and all chars in '0'..='9' | 'a'..='f'
  writes   —

contract resolve_real_git() -> Result<PathBuf, String>
  requires true
  ensures  Ok(p) ==> p.is_file() and !is_our_wrapper(&p)
  writes   —
```

### Type `GitRepo`

* **Invariant `I_repo(r)`:**
  1. `!is_our_wrapper(&r.real_git)`.
  2. Repository object format was verified to be `"sha1"` at `open`.
  3. `r.batch == Some(b)` only when `b`'s `git cat-file --batch` stdout sits at
     an exact response boundary (never mid-payload).
  4. `Drop` on `BatchCatFile` flushes, kills, and reaps the child `git` process
     (no zombie processes).

```text
contract GitRepo::open(cwd: Option<&Path>) -> Result<GitRepo, String>
  requires true
  ensures  Ok(r) ==> I_repo(r) and repository at cwd (or current_dir) has object-format == "sha1"
  writes   —

contract <GitRepo as ObjectStore>::read_object(self: &mut GitRepo, oid: &Oid) -> Result<Option<(ObjKind, Vec<u8>)>, String>
  requires I_repo(self)
  ensures  I_repo(self) on BOTH Ok and Err (on Err, self.batch is reset to None);
           Ok(Some((kind, raw))) ==> exact uncompressed Git object stored for oid (ignoring refs/replace);
           Ok(None) ==> oid is absent locally
  writes   self.batch
```

---

## 5. Module `protocol` (`src/protocol.rs`)

### Pure Parsers

```text
contract split_headers_body(raw: &[u8]) -> (&[u8], &[u8])
  requires true
  ensures  if raw.starts_with(b"\n"): ret == (&b""[..], &raw[1..]);
           else if earliest b"\n\n" is at pos: ret == (&raw[..pos], &raw[pos+2..]);
           else: ret == (raw.strip_suffix(b"\n").unwrap_or(raw), &b""[..])
  writes   —

contract parse_commit(oid: Oid, raw: Vec<u8>) -> Result<ParsedCommit, VerifyError>
  requires true
  ensures  ignores continuation lines starting with b' ';
           Err(Mismatch) if:
             - != 1 `tree ` line, or invalid 40-hex lowercase OID on `tree ` or `parent `;
             - `buttress-tree` or `buttress-parent` has empty value or invalid alg token (`![a-z][a-z0-9-]*`);
             - `blake3` line has wrong field count or non-lowercase-hex OID/digest;
             - > 1 `buttress-tree blake3` lines, or >= 1 `buttress-parent blake3` with 0 `buttress-tree blake3`;
             - 1 `buttress-tree blake3` with bt_tree == tree and b3_parents.len() != parents.len();
           Ok(pc) with:
             - Sealed { expected_tree, expected_parents } iff 1 `buttress-tree blake3` with bt_tree == tree
               and expected_parents.len() == parents.len();
             - Stale iff 1 `buttress-tree blake3` with bt_tree != tree (and all blake3 lines syntactically valid);
             - Plain iff 0 `buttress-tree blake3` and 0 `buttress-parent blake3` lines;
           non-`blake3` valid-alg `buttress-*` lines are ignored
  writes   —

contract parse_tree_entries(raw: &[u8]) -> Result<Vec<(&[u8], u32, &[u8], Oid)>, VerifyError>
  requires true
  ensures  Ok(v) <==> raw is exact concatenation of `mode || b" " || name || b"\0" || child` where
           1 <= mode.len() <= 7, mode in [b'0'..=b'7']+, !name.is_empty(), !name.contains(0), !name.contains(b'/'),
           and child.len() == 20; Err(Mismatch) otherwise
  writes   —

contract parse_ref_embedded_b3(ref_or_name: &str) -> Result<Option<Dig>, VerifyError>
  requires true
  ensures  0 occurrences of "+blake3-" ==> Ok(None);
           >= 2 occurrences of "+blake3-" ==> Err(Mismatch);
           1 occurrence ==> parses segment after "+blake3-" (stripping "^{}", stopping at '+', '/', '^', '~')
             as 64 lowercase hex chars: Ok(Some(dig)) or Err(Mismatch)
  writes   —

contract parse_annotated_tag(raw: &[u8]) -> Result<(Oid, ObjKind, Option<Dig>), VerifyError>
  requires true
  ensures  parses `object <40-hex>` and `type <kind>` from tag header, strips trailing PGP/SSH signature block
           from body, and scans remaining lines for `Buttress-Object: <alg> ...`:
           - non-`blake3` valid `<alg>` lines ignored;
           - > 1 `blake3` trailers, malformed `blake3` trailer, or trailer OID != header `object` ==> Err(Mismatch);
           - returns Ok((target_oid, target_kind, optional_blake3_digest))
  writes   —
```

### Verification (`verify_target`)

```text
contract verify_target<S: ObjectStore>(
  store: &mut S,
  keys: &ContextKeys,
  start_oid: Oid,
  ref_hint: Option<&str>,
  explicit_expect: Option<Dig>,
  allow_shallow: bool,
) -> Result<CheckOutcome, VerifyError>
  requires true
  ensures
    1. Uses DigestCache::memory_only() (never touches disk cache).
    2. Combines expectations from `explicit_expect`, `parse_ref_embedded_b3(ref_hint)`, and any peeled
       annotated tag `Buttress-Object: blake3` trailers; if any two present expectations disagree,
       returns Err(Mismatch). Also verifies every peeled tag's declared `type` matches the actual object
       kind in `store`, and rejects cyclic tag chains with Err(Mismatch).
    3. For Blob/Tree target:
       - If effective `expect == Some(exp)`: returns Ok(Match) iff `spec_{file|dir}(store, target) == exp`,
         else Err(Mismatch) (or Err(Incomplete) if objects missing).
       - If effective `expect == None`: returns Ok(NoEvidence) after computing `spec_{file|dir}` (still
         catching malformed/missing objects in the target).
    4. For Commit target `C_0`:
       - Computes `(root_dig, initial_sealed) = digest_commit(C_0)`.
       - If `expect == Some(exp)` and `root_dig != exp`: returns Err(Mismatch).
       - If `expect == None` and `C_0` is not `Sealed`: returns Ok(NoEvidence).
       - Otherwise walks BFS over every reachable `Sealed` commit `C` (starting from `C_0` if `Sealed`
         plus `initial_sealed`, and adding `Sealed` parents and `Sealed` ancestors beneath `Plain`/`Stale`
         parents):
         a) Verifies `spec_dir(store, C.tree) == C.expected_tree` in constant time, else Err(Mismatch).
         b) For each `(P_i, exp_p_dig)`:
            - If `P_i` is missing in `store` AND `C in store.shallow_commits()`:
              if `allow_shallow` increments `shallow_stops` and continues; else returns Err(Incomplete).
            - Otherwise computes `actual_p = digest_commit(P_i)` and verifies `actual_p == exp_p_dig`
              in constant time, else Err(Mismatch).
       - Returns Ok(Match { target_oid: C_0, digest: root_dig, sealed_checked, plain_covered, shallow_stops }).
  writes store (via read_object only)
```

---

## 6. Module `hooks` (`src/hooks.rs`) & CLI (`src/main.rs`)

### Key Hook & Wrapper Contracts

```text
contract posix_single_quote(s: &str) -> String
  requires !s.contains('\0')
  ensures  POSIX sh parses `ret` as a single literal word equal to `s` (no `$`, backtick, `\`, glob, or splitting)
  writes   —

contract seal_head(repo: &mut GitRepo, force_sign: bool, quiet: bool) -> Result<(Oid, Dig), String>
  requires I_repo(repo) and HEAD resolves to an existing commit `head_oid`
  ensures
    - If `GIT_BUTTRESS_INTERNAL` is set in env: no-op, returns `(head_oid, [0; 32])`.
    - If `head_oid` is already `Sealed` AND its `buttress-tree` and `buttress-parent` digests match
      recomputed `digest_tree` / `digest_commit`: leaves `HEAD` unchanged (idempotent) and returns `(head_oid, dig)`.
    - Otherwise builds a new commit preserving all non-`buttress-*-blake3`, non-`gpgsig*` headers and exact body,
      appending valid `buttress-tree blake3` and `buttress-parent blake3` lines, re-signing if `force_sign || old.has_gpgsig`,
      and atomically updating the current branch ref (or `--no-deref HEAD` if detached) from `head_oid` to `new_oid`
      with `GIT_BUTTRESS_INTERNAL=1`.
  writes repo object store, current branch ref / HEAD, `.git/buttress-cache.bin`, stderr (if !quiet)

contract run_reference_transaction_hook(phase: &str) -> Result<(), String>
  requires stdin contains Git reference-transaction lines `<old-oid> <new-oid> <refname>`
  ensures
    - If `GIT_BUTTRESS_INTERNAL` set, `phase not in {"prepared", "committed"}`, outside a SHA-1 Git repo,
      or `buttress.disabled == true`: returns Ok(()).
    - When `phase == "prepared"`: verifies every non-zero, non-symbolic update on `refs/remotes/*`,
      `refs/tags/*`, or any ref containing `"+blake3-"` via `verify_target(..., allow_shallow=true)`:
      * `Mismatch` ==> Err (aborts Git's ref transaction before refs/worktree commit).
      * `Incomplete` ==> Err if ref has `"+blake3-"` or `buttress.missing == error`, else stderr note.
      * `NoEvidence` ==> respects `buttress.missing` (`silent` / `warn` / `error`), suppressing warnings on
        a plain tag when a companion `+blake3-` tag for the same OID is in the same transaction.
    - When `phase == "committed"`: if `buttress.autotag` is explicitly `true` (default `false`) and
      transaction is local (no `refs/remotes/*` updates and `GIT_REFLOG_ACTION` not `clone`/`fetch`/`pull`),
      for each created/updated plain tag `refs/tags/<T>` without `"+blake3-"`, peels to target object,
      computes its BLAKE3 digest `D`, and updates `refs/tags/<T>+blake3-<hex(D)>` to `<new-oid>` with
      `GIT_BUTTRESS_INTERNAL=1`.
  writes repo refs & `.git/buttress-cache.bin` (only in `committed` phase), stderr
```

### CLI Exit-Code Contracts (`src/main.rs`)

`exit_code_from_status(code)` maps `0 -> 0`, `1..=255 -> code as u8`, and any
other non-zero `i32` (such as `256` or `-1`) to `1`—never wrapping non-zero
codes to `0`.

| Command | Exit `0` | Exit `1` | Exit `2` |
|---|---|---|---|
| `git buttress check [<rev>]` | `Match`, or `NoEvidence` with `missing in {silent, warn}` | `Mismatch`, `Incomplete`, or invalid CLI/rev | `NoEvidence` with `--missing error` (`buttress.missing=error`) |
| `git buttress fsck` | All refs `Match` (or `NoEvidence` under `silent`/`warn`) | Any ref `Mismatch`, `Incomplete`, or `--missing error` on `NoEvidence` | — |
| `git buttress id [<rev>]` | Prints `<64-hex>\n` to stdout | Missing/malformed/cyclic object or invalid args | — |
| `git buttress enable` / `disable` | Hooks (& optional wrapper) configured/removed | Invalid flags (`--global` + `--local`) or I/O error | — |
| `git buttress seal-head` | `HEAD` is sealed (or `buttress.disabled=true`) | Not in repo, signing failure, or CAS failure | — |
