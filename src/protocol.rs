//! Core `git-buttress` protocol (implements `BUTTRESS.md` to the byte).
//!
//! # Module Contract
//!
//! - **Pure mathematical specification (`spec_digest_*`):**
//!   Let `dk(ctx, msg)` be 32-byte BLAKE3 derive-key output over UTF-8 `ctx` and bytes `msg`.
//!   - `spec_file(raw) = dk(CTX_FILE, raw)`
//!   - `spec_dir(entries) = dk(CTX_DIR, concat_i(mode_i || " " || name_i || "\0" || child_i))`
//!     where `child_i` is `spec_dir(sub)` (32B) if `octal(mode_i) == 0o040000`, raw 20-byte `oid_i`
//!     if `octal(mode_i) == 0o160000`, else `spec_file(blob)` (32B).
//!   - `spec_commit(C)`:
//!     - If `C` is `Sealed`, `dk(CTX_COMMIT, C.raw)`.
//!     - If `C` is `Plain` or `Stale`,
//!       `dk(CTX_PLAIN, spec_dir(C.tree) || u32_le(k) || spec_commit(P_1) || ... || spec_commit(P_k) || C.raw)`.
//! - **Engine invariant `I(eng)`:**
//!   1. Every entry in `eng.parsed[oid]` equals `parse_commit(oid, raw)` for the object returned by `eng.store`.
//!   2. When initialized with `DigestCache::memory_only()`, every cached digest in `eng.cache` equals
//!      the `spec_*` value computed directly from `eng.store` in the current run.
//!   3. Commit parent counts are bounded to `u32::MAX` (`try_from`) so `u32_le(k)` never truncates.
//!   4. Tree traversal tracks `in_progress_trees` to detect malformed cyclic tree objects cleanly with
//!      `VerifyErrorKind::Mismatch` rather than looping forever.

use crate::cache::{Dig, DigestCache, Oid, OidMap};
use crate::git::{ObjKind, ObjectStore, hex_to_32, hex_to_oid, to_hex};
use blake3_servil::throughput::context_key;
use blake3_servil::{ContextKey, Mode, convenience};
use std::collections::{HashSet, VecDeque};

pub const CTX_FILE: &str = "git-buttress 2026-11-20 file";
pub const CTX_DIR: &str = "git-buttress 2026-11-20 directory";
pub const CTX_COMMIT: &str = "git-buttress 2026-11-20 commit";
pub const CTX_PLAIN: &str = "git-buttress 2026-11-20 plain commit";

pub const HEADER_TREE_PREFIX: &[u8] = b"buttress-tree ";
pub const HEADER_PARENT_PREFIX: &[u8] = b"buttress-parent ";
pub const TAG_TRAILER_PREFIX: &str = "Buttress-Object: ";

pub struct ContextKeys {
    pub file: ContextKey,
    pub dir: ContextKey,
    pub commit: ContextKey,
    pub plain: ContextKey,
}

impl ContextKeys {
    pub fn new() -> Self {
        blake3_servil::initialize();
        Self {
            file: context_key(CTX_FILE),
            dir: context_key(CTX_DIR),
            commit: context_key(CTX_COMMIT),
            plain: context_key(CTX_PLAIN),
        }
    }

    #[inline]
    pub fn hash_file(&self, bytes: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.file), bytes).as_bytes()
    }

    #[inline]
    pub fn hash_dir(&self, encoded_entries: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.dir), encoded_entries).as_bytes()
    }

    #[inline]
    pub fn hash_sealed_commit(&self, raw_commit: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.commit), raw_commit).as_bytes()
    }

    #[inline]
    pub fn hash_plain_commit(&self, payload: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.plain), payload).as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitClass {
    /// Carries valid `buttress-tree blake3` matching `tree` and `buttress-parent blake3`
    /// matching `parent` count.
    Sealed {
        expected_tree: Dig,
        expected_parents: Vec<Dig>,
    },
    /// No `blake3` buttress lines at all.
    Plain,
    /// Leftover lines from e.g. stock `git commit --amend` (`buttress-tree` SHA-1 != `tree`).
    /// Treated as a plain commit per BUTTRESS.md §4.
    Stale,
}

#[derive(Clone, Debug)]
pub struct ParsedCommit {
    pub oid: Oid,
    pub raw: Vec<u8>,
    pub tree: Oid,
    pub parents: Vec<Oid>,
    pub class: CommitClass,
    pub has_gpgsig: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyErrorKind {
    Mismatch,
    Incomplete,
}

#[derive(Debug)]
pub struct VerifyError {
    pub kind: VerifyErrorKind,
    pub message: String,
}

impl VerifyError {
    pub fn mismatch(msg: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::Mismatch,
            message: msg.into(),
        }
    }
    pub fn incomplete(msg: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::Incomplete,
            message: msg.into(),
        }
    }
}

/// Split raw commit/tag object bytes at the header/body boundary (`\n\n` or single-`\n` header-only).
///
/// Contract:
/// - `requires`: true
/// - `ensures`:
///   - If `raw` begins with `b'\n'` (empty header block), returns `(&b""[..], &raw[1..])`.
///   - Else if `raw` contains `b"\n\n"` at earliest byte index `pos`, returns `(&raw[..pos], &raw[pos + 2..])`.
///   - Else (header-only object with no body), strips at most a single trailing `b'\n'` (never spaces/tabs)
///     and returns `(header_without_final_lf, &b""[..])`.
/// - `writes`: nothing (pure slice view).
pub fn split_headers_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(rest) = raw.strip_prefix(b"\n") {
        (&[], rest)
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw.strip_suffix(b"\n").unwrap_or(raw), b"")
    }
}

fn is_valid_alg_token(alg: &[u8]) -> bool {
    !alg.is_empty()
        && alg[0].is_ascii_lowercase()
        && alg
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Parse a Git commit and classify its `blake3` buttress lines per `BUTTRESS.md` §§2, 4.
///
/// Contract:
/// - `requires`: `raw` is the uncompressed payload of commit `oid`.
/// - `ensures`:
///   - Returns `Err(Mismatch)` if `raw` has zero or >1 `tree` headers, any invalid hex `tree`/`parent` OID,
///     an invalid algorithm token on a `buttress-*` header, >1 `buttress-tree blake3` lines, `buttress-parent blake3`
///     without `buttress-tree blake3`, malformed `blake3` arguments, or (`bt_tree == tree` and `b3_parents.len() != parents.len()`).
///   - Returns `Ok(pc)` with `pc.class == Sealed` iff there is 1 `buttress-tree blake3 <tree> <d>` with `<tree> == pc.tree`
///     and `pc.parents.len()` `buttress-parent blake3` lines.
///   - Returns `Ok(pc)` with `pc.class == Stale` iff there is 1 `buttress-tree blake3 <other> <d>` with `<other> != pc.tree`
///     and every `buttress-parent blake3` line is syntactically well-formed.
///   - Returns `Ok(pc)` with `pc.class == Plain` iff there are 0 `buttress-tree blake3` and 0 `buttress-parent blake3` lines.
/// - `writes`: nothing.
pub fn parse_commit(oid: Oid, raw: Vec<u8>) -> Result<ParsedCommit, VerifyError> {
    let (header_bytes, _) = split_headers_body(&raw);
    let mut tree: Option<Oid> = None;
    let mut parents: Vec<Oid> = Vec::new();
    let mut b3_trees: Vec<(Oid, Dig)> = Vec::new();
    let mut b3_parents: Vec<Dig> = Vec::new();
    let mut has_gpgsig = false;

    for line in header_bytes.split(|&c| c == b'\n') {
        if line.is_empty() || line.starts_with(b" ") {
            // Continuation line of a multi-line header (e.g. gpgsig, mergetag)
            continue;
        }
        if let Some(rest) = line.strip_prefix(b"tree ") {
            if tree.is_some() {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: duplicate tree header",
                    to_hex(&oid)
                )));
            }
            let t = hex_to_oid(rest).map_err(|e| {
                VerifyError::mismatch(format!("commit {}: invalid tree line: {e}", to_hex(&oid)))
            })?;
            tree = Some(t);
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            let p = hex_to_oid(rest).map_err(|e| {
                VerifyError::mismatch(format!("commit {}: invalid parent line: {e}", to_hex(&oid)))
            })?;
            parents.push(p);
        } else if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            has_gpgsig = true;
        } else if line == b"buttress-tree" || line == b"buttress-parent" {
            return Err(VerifyError::mismatch(format!(
                "commit {}: empty buttress header",
                to_hex(&oid)
            )));
        } else if let Some(rest) = line.strip_prefix(HEADER_TREE_PREFIX) {
            let parts: Vec<&[u8]> = rest.split(|&c| c == b' ').collect();
            if parts.is_empty() || !is_valid_alg_token(parts[0]) {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: malformed buttress-tree algorithm",
                    to_hex(&oid)
                )));
            }
            if parts[0] != b"blake3" {
                // Unknown/other algorithm: skip per BUTTRESS.md §2
                continue;
            }
            if parts.len() != 3 {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: malformed buttress-tree blake3 line",
                    to_hex(&oid)
                )));
            }
            let t_oid = hex_to_oid(parts[1]).map_err(|e| {
                VerifyError::mismatch(format!(
                    "commit {}: invalid tree ID in buttress-tree: {e}",
                    to_hex(&oid)
                ))
            })?;
            let dig = hex_to_32(parts[2]).map_err(|e| {
                VerifyError::mismatch(format!(
                    "commit {}: invalid digest in buttress-tree: {e}",
                    to_hex(&oid)
                ))
            })?;
            b3_trees.push((t_oid, dig));
        } else if let Some(rest) = line.strip_prefix(HEADER_PARENT_PREFIX) {
            let parts: Vec<&[u8]> = rest.split(|&c| c == b' ').collect();
            if parts.is_empty() || !is_valid_alg_token(parts[0]) {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: malformed buttress-parent algorithm",
                    to_hex(&oid)
                )));
            }
            if parts[0] != b"blake3" {
                continue;
            }
            if parts.len() != 2 {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: malformed buttress-parent blake3 line (expected `<alg> <digest>`)",
                    to_hex(&oid)
                )));
            }
            let dig = hex_to_32(parts[1]).map_err(|e| {
                VerifyError::mismatch(format!(
                    "commit {}: invalid digest in buttress-parent: {e}",
                    to_hex(&oid)
                ))
            })?;
            b3_parents.push(dig);
        }
    }

    let tree = tree.ok_or_else(|| {
        VerifyError::mismatch(format!("commit {}: missing tree header", to_hex(&oid)))
    })?;

    let class = match b3_trees.len() {
        0 => {
            if !b3_parents.is_empty() {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: buttress-parent present without buttress-tree",
                    to_hex(&oid)
                )));
            }
            CommitClass::Plain
        }
        1 => {
            let (bt_tree, bt_dig) = b3_trees[0];
            if bt_tree != tree {
                // Leftover lines from stock `git commit --amend` changing files
                CommitClass::Stale
            } else if b3_parents.len() != parents.len() {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: expected {} buttress-parent lines, found {}",
                    to_hex(&oid),
                    parents.len(),
                    b3_parents.len()
                )));
            } else {
                CommitClass::Sealed {
                    expected_tree: bt_dig,
                    expected_parents: b3_parents,
                }
            }
        }
        _ => {
            return Err(VerifyError::mismatch(format!(
                "commit {}: multiple buttress-tree blake3 lines",
                to_hex(&oid)
            )));
        }
    };

    Ok(ParsedCommit {
        oid,
        raw,
        tree,
        parents,
        class,
        has_gpgsig,
    })
}

/// Parse raw Git tree entries: `(mode_bytes, octal_mode, name_bytes, child_oid)`.
///
/// Contract:
/// - `requires`: true
/// - `ensures`: on `Ok(entries)`, `raw` is the exact concatenation of `mode_bytes || b" " || name || b"\0" || child`
///   for each entry, where `1 <= mode_bytes.len() <= 7` of ASCII `'0'..='7'` (no `u32` overflow), `name` is non-empty
///   and contains no NUL (`0x00`) or `'/'` (`0x2f`), and `child` is 20 bytes. Returns `Err(Mismatch)` on any violation.
/// - `writes`: nothing.
pub fn parse_tree_entries(raw: &[u8]) -> Result<Vec<(&[u8], u32, &[u8], Oid)>, VerifyError> {
    let mut entries = Vec::new();
    let mut i = 0;
    let n = raw.len();
    while i < n {
        let rel_sp = raw[i..]
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| VerifyError::mismatch("malformed tree: missing space"))?;
        let sp = i + rel_sp;
        let mode_bytes = &raw[i..sp];
        if mode_bytes.is_empty()
            || mode_bytes.len() > 7
            || !mode_bytes.iter().all(|&c| (b'0'..=b'7').contains(&c))
        {
            return Err(VerifyError::mismatch("malformed tree: invalid octal mode"));
        }
        let octal = mode_bytes
            .iter()
            .fold(0u32, |acc, &c| (acc << 3) | ((c - b'0') as u32));
        let rel_nul = raw[sp + 1..]
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| VerifyError::mismatch("malformed tree: missing NUL"))?;
        let nul = sp + 1 + rel_nul;
        if nul + 21 > n {
            return Err(VerifyError::mismatch("malformed tree: truncated child OID"));
        }
        let name = &raw[sp + 1..nul];
        if name.is_empty() || name.contains(&b'/') {
            return Err(VerifyError::mismatch("malformed tree: empty or slash-containing entry name"));
        }
        let child: Oid = raw[nul + 1..nul + 21].try_into().unwrap();
        entries.push((mode_bytes, octal, name, child));
        i = nul + 21;
    }
    Ok(entries)
}

pub const MODE_DIR: u32 = 0o040000;
pub const MODE_GITLINK: u32 = 0o160000;

pub struct Engine<'a, S: ObjectStore> {
    pub store: &'a mut S,
    pub keys: &'a ContextKeys,
    pub cache: DigestCache,
    pub parsed: OidMap<ParsedCommit>,
}

impl<'a, S: ObjectStore> Engine<'a, S> {
    pub fn new(store: &'a mut S, keys: &'a ContextKeys, cache: DigestCache) -> Self {
        Self {
            store,
            keys,
            cache,
            parsed: OidMap::default(),
        }
    }

    pub fn load_commit(&mut self, oid: Oid) -> Result<ParsedCommit, VerifyError> {
        if let Some(pc) = self.parsed.get(&oid) {
            return Ok(pc.clone());
        }
        let (kind, raw) = self
            .store
            .read_object(&oid)
            .map_err(VerifyError::incomplete)?
            .ok_or_else(|| VerifyError::incomplete(format!("missing commit object {}", to_hex(&oid))))?;
        if kind != ObjKind::Commit {
            return Err(VerifyError::mismatch(format!(
                "expected commit for {}, found {}",
                to_hex(&oid),
                kind.as_str()
            )));
        }
        let pc = parse_commit(oid, raw)?;
        self.parsed.insert(oid, pc.clone());
        Ok(pc)
    }

    pub fn digest_blob(&mut self, oid: Oid) -> Result<Dig, VerifyError> {
        if let Some(&d) = self.cache.blobs.get(&oid) {
            return Ok(d);
        }
        let (kind, raw) = self
            .store
            .read_object(&oid)
            .map_err(VerifyError::incomplete)?
            .ok_or_else(|| VerifyError::incomplete(format!("missing blob object {}", to_hex(&oid))))?;
        if kind != ObjKind::Blob {
            return Err(VerifyError::mismatch(format!(
                "expected blob for {}, found {}",
                to_hex(&oid),
                kind.as_str()
            )));
        }
        let d = self.keys.hash_file(&raw);
        self.cache.put_blob(oid, d);
        Ok(d)
    }

    /// Compute `spec_dir(root_oid)` iteratively with cycle detection.
    ///
    /// Contract:
    /// - `requires`: `I(self)`
    /// - `ensures`: on `Ok(d)`, `d == spec_dir(root_oid)` and `self.cache.trees[&root_oid] == d`.
    ///   Returns `Err(Incomplete)` if any reachable tree or blob is missing from `self.store`,
    ///   or `Err(Mismatch)` on wrong object type, malformed tree syntax, or a tree cycle.
    /// - `writes`: `self.store`, `self.cache.trees`, `self.cache.blobs`.
    pub fn digest_tree(&mut self, root_oid: Oid) -> Result<Dig, VerifyError> {
        if let Some(&d) = self.cache.trees.get(&root_oid) {
            return Ok(d);
        }
        // Iterative post-order traversal with explicit cycle detection
        let mut stack: Vec<(Oid, Option<Vec<u8>>)> = vec![(root_oid, None)];
        let mut in_progress: HashSet<Oid> = HashSet::new();

        while let Some((oid, raw_opt)) = stack.pop() {
            if self.cache.trees.contains_key(&oid) {
                in_progress.remove(&oid);
                continue;
            }
            let raw = match raw_opt {
                Some(r) => r,
                None => {
                    if !in_progress.insert(oid) {
                        return Err(VerifyError::mismatch(format!(
                            "cycle in directory tree at {}",
                            to_hex(&oid)
                        )));
                    }
                    let (kind, r) = self
                        .store
                        .read_object(&oid)
                        .map_err(VerifyError::incomplete)?
                        .ok_or_else(|| {
                            VerifyError::incomplete(format!("missing tree object {}", to_hex(&oid)))
                        })?;
                    if kind != ObjKind::Tree {
                        return Err(VerifyError::mismatch(format!(
                            "expected tree for {}, found {}",
                            to_hex(&oid),
                            kind.as_str()
                        )));
                    }
                    r
                }
            };
            let entries = parse_tree_entries(&raw)?;
            let mut missing_subtrees = Vec::new();
            for &(_, octal, _, child) in &entries {
                if octal == MODE_DIR && !self.cache.trees.contains_key(&child) {
                    if in_progress.contains(&child) {
                        return Err(VerifyError::mismatch(format!(
                            "cycle in directory tree: {} -> {}",
                            to_hex(&oid),
                            to_hex(&child)
                        )));
                    }
                    missing_subtrees.push(child);
                }
            }
            if !missing_subtrees.is_empty() {
                stack.push((oid, Some(raw)));
                for sub in missing_subtrees.into_iter().rev() {
                    stack.push((sub, None));
                }
                continue;
            }

            in_progress.remove(&oid);
            let mut buf = Vec::with_capacity(raw.len() + entries.len() * 12);
            for (mode_bytes, octal, name, child) in entries {
                buf.extend_from_slice(mode_bytes);
                buf.push(b' ');
                buf.extend_from_slice(name);
                buf.push(0);
                if octal == MODE_DIR {
                    buf.extend_from_slice(&self.cache.trees[&child]);
                } else if octal == MODE_GITLINK {
                    buf.extend_from_slice(&child);
                } else {
                    let bd = self.digest_blob(child)?;
                    buf.extend_from_slice(&bd);
                }
            }
            let d = self.keys.hash_dir(&buf);
            self.cache.put_tree(oid, d);
        }
        Ok(self.cache.trees[&root_oid])
    }

    /// Compute `commit_digest(root_oid)` per `BUTTRESS.md` §3, returning `(digest, sealed_ancestors_reached)`.
    ///
    /// Contract:
    /// - `requires`: `I(self)`
    /// - `ensures`: on `Ok((d, sealed_ancs))`, `d == spec_commit(root_oid)` and `sealed_ancs` contains
    ///   every `Sealed` commit directly bounding any `Plain`/`Stale` ancestor walk under `root_oid`
    ///   (or `[root_oid]` if `root_oid` was already cached and `Sealed`).
    ///   Returns `Err(Incomplete)` if an unsealed commit sits on a `.git/shallow` boundary with missing
    ///   parents or if any required object is missing; returns `Err(Mismatch)` on malformed objects or cycles.
    /// - `writes`: `self.store`, `self.cache`, `self.parsed`.
    pub fn digest_commit(&mut self, root_oid: Oid) -> Result<(Dig, Vec<Oid>), VerifyError> {
        let mut discovered_sealed = Vec::new();
        if let Some(&d) = self.cache.commits.get(&root_oid) {
            let pc = self.load_commit(root_oid)?;
            if matches!(pc.class, CommitClass::Sealed { .. }) {
                discovered_sealed.push(root_oid);
            }
            return Ok((d, discovered_sealed));
        }

        let mut stack: Vec<(Oid, bool)> = vec![(root_oid, false)];
        let mut in_progress: HashSet<Oid> = HashSet::new();

        while let Some((cur, expanded)) = stack.pop() {
            if self.cache.commits.contains_key(&cur) {
                continue;
            }
            let pc = self.load_commit(cur)?;
            if matches!(pc.class, CommitClass::Sealed { .. }) {
                let d = self.keys.hash_sealed_commit(&pc.raw);
                self.cache.put_commit(cur, d);
                if cur != root_oid {
                    discovered_sealed.push(cur);
                }
                continue;
            }

            if !expanded {
                if !in_progress.insert(cur) {
                    return Err(VerifyError::mismatch(format!(
                        "cycle in commit graph at {}",
                        to_hex(&cur)
                    )));
                }
                stack.push((cur, true));
                let cur_is_shallow = self.store.shallow_commits().contains(&cur);
                for &p in pc.parents.iter().rev() {
                    if !self.cache.commits.contains_key(&p) {
                        if self.store.read_object(&p).map_err(VerifyError::incomplete)?.is_none() {
                            return Err(VerifyError::incomplete(if cur_is_shallow {
                                format!(
                                    "shallow boundary at plain commit {} cuts across unsealed history (missing parent {})",
                                    to_hex(&cur),
                                    to_hex(&p)
                                )
                            } else {
                                format!("missing commit object {}", to_hex(&p))
                            }));
                        }
                        stack.push((p, false));
                    } else {
                        let ppc = self.load_commit(p)?;
                        if matches!(ppc.class, CommitClass::Sealed { .. }) {
                            discovered_sealed.push(p);
                        }
                    }
                }
            } else {
                in_progress.remove(&cur);
                let k_u32 = u32::try_from(pc.parents.len())
                    .map_err(|_| VerifyError::mismatch("commit has > u32::MAX parents"))?;
                let tree_dig = self.digest_tree(pc.tree)?;
                let mut buf = Vec::with_capacity(32 + 4 + pc.parents.len() * 32 + pc.raw.len());
                buf.extend_from_slice(&tree_dig);
                buf.extend_from_slice(&k_u32.to_le_bytes());
                for p in &pc.parents {
                    buf.extend_from_slice(&self.cache.commits[p]);
                }
                buf.extend_from_slice(&pc.raw);
                let d = self.keys.hash_plain_commit(&buf);
                self.cache.put_commit(cur, d);
            }
        }

        Ok((self.cache.commits[&root_oid], discovered_sealed))
    }
}

/// Extract `+blake3-<64-hex>` embedded in a tag or ref name, e.g.
/// `refs/tags/v2.4.0+blake3-71e4...` or `v2.4.0+blake3-71e4...`.
///
/// Contract:
/// - `requires`: true
/// - `ensures`:
///   - If `ref_or_name` contains zero occurrences of `"+blake3-"`, returns `Ok(None)`.
///   - If `ref_or_name` contains `>= 2` occurrences of `"+blake3-"`, returns `Err(Mismatch)`
///     (prevents duplicate-segment confusion such as `v1+blake3-<good>+blake3-<evil>`).
///   - If `ref_or_name` contains exactly 1 `"+blake3-"`, parses the token up to the next `'+'` or `'/'`
///     (or `^{}` peel suffix) as 64 lowercase hex chars (`[0-9a-f]{64}`), returning `Ok(Some(dig))` or `Err(Mismatch)`.
/// - `writes`: nothing.
pub fn parse_ref_embedded_b3(ref_or_name: &str) -> Result<Option<Dig>, VerifyError> {
    let mut matches = ref_or_name.match_indices("+blake3-");
    let Some((idx, _)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(VerifyError::mismatch(format!(
            "duplicate +blake3- segments in ref {ref_or_name:?}"
        )));
    }
    let rest = &ref_or_name[idx + "+blake3-".len()..];
    let rest = rest.strip_suffix("^{}").unwrap_or(rest);
    let token = rest.split(['+', '/', '^', '~']).next().unwrap_or(rest);
    let dig = hex_to_32(token.as_bytes()).map_err(|e| {
        VerifyError::mismatch(format!(
            "malformed +blake3- digest in ref {ref_or_name:?}: {e}"
        ))
    })?;
    Ok(Some(dig))
}

/// Parse optional `Buttress-Object: blake3 <target-sha1> <64-hex>` trailer from an annotated tag.
pub fn parse_annotated_tag(raw: &[u8]) -> Result<(Oid, ObjKind, Option<Dig>), VerifyError> {
    let (header, body) = split_headers_body(raw);
    let mut target_oid: Option<Oid> = None;
    let mut target_kind: Option<ObjKind> = None;
    for line in header.split(|&c| c == b'\n') {
        if let Some(rest) = line.strip_prefix(b"object ") {
            target_oid = Some(
                hex_to_oid(rest)
                    .map_err(|e| VerifyError::mismatch(format!("tag bad object header: {e}")))?,
            );
        } else if let Some(rest) = line.strip_prefix(b"type ") {
            target_kind = Some(ObjKind::from_bytes(rest).map_err(VerifyError::mismatch)?);
        }
    }
    let target_oid = target_oid.ok_or_else(|| VerifyError::mismatch("tag missing object line"))?;
    let target_kind = target_kind.ok_or_else(|| VerifyError::mismatch("tag missing type line"))?;

    let body_str = String::from_utf8_lossy(body);
    let mut unsigned_body = body_str.as_ref();
    for marker in ["-----BEGIN PGP SIGNATURE-----", "-----BEGIN SSH SIGNATURE-----"] {
        if let Some(pos) = unsigned_body.find(marker) {
            unsigned_body = &unsigned_body[..pos];
            break;
        }
    }

    let mut found: Vec<Dig> = Vec::new();
    for line in unsigned_body.lines() {
        if let Some(rest) = line.strip_prefix(TAG_TRAILER_PREFIX) {
            let parts: Vec<&str> = rest.trim().split(' ').collect();
            if parts.is_empty() || !is_valid_alg_token(parts[0].as_bytes()) {
                return Err(VerifyError::mismatch("malformed Buttress-Object trailer"));
            }
            if parts[0] != "blake3" {
                continue;
            }
            if parts.len() != 3 {
                return Err(VerifyError::mismatch(
                    "malformed Buttress-Object blake3 trailer",
                ));
            }
            let t_oid = hex_to_oid(parts[1].as_bytes())
                .map_err(|e| VerifyError::mismatch(format!("bad tag trailer OID: {e}")))?;
            if t_oid != target_oid {
                return Err(VerifyError::mismatch(
                    "tag Buttress-Object OID does not match tag object header",
                ));
            }
            let dig = hex_to_32(parts[2].as_bytes())
                .map_err(|e| VerifyError::mismatch(format!("bad tag trailer digest: {e}")))?;
            found.push(dig);
        }
    }
    if found.len() > 1 {
        return Err(VerifyError::mismatch("duplicate Buttress-Object blake3 trailers"));
    }
    Ok((target_oid, target_kind, found.into_iter().next()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Match {
        target_oid: Oid,
        digest: Dig,
        sealed_checked: usize,
        plain_covered: usize,
        shallow_stops: usize,
    },
    NoEvidence {
        target_oid: Oid,
        digest: Dig,
    },
}

#[inline]
fn ct_eq(a: &Dig, b: &Dig) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Full verification per `BUTTRESS.md` §5.
/// NEVER reads any on-disk cache: recomputes every digest from raw stored objects.
pub fn verify_target<S: ObjectStore>(
    store: &mut S,
    keys: &ContextKeys,
    start_oid: Oid,
    ref_hint: Option<&str>,
    explicit_expect: Option<Dig>,
    allow_shallow: bool,
) -> Result<CheckOutcome, VerifyError> {
    let ref_expect = match ref_hint {
        Some(r) => parse_ref_embedded_b3(r)?,
        None => None,
    };
    if let (Some(a), Some(b)) = (explicit_expect, ref_expect) {
        if !ct_eq(&a, &b) {
            return Err(VerifyError::mismatch(format!(
                "--expect ({}) disagrees with ref name digest ({})",
                to_hex(&a),
                to_hex(&b)
            )));
        }
    }
    let mut expect = explicit_expect.or(ref_expect);

    let (mut cur_kind, raw) = store
        .read_object(&start_oid)
        .map_err(VerifyError::incomplete)?
        .ok_or_else(|| VerifyError::incomplete(format!("missing object {}", to_hex(&start_oid))))?;
    let mut target_oid = start_oid;

    // Peel annotated tag(s), guarding against cyclic tag chains!
    let mut raw_cur = raw;
    let mut seen_tags: HashSet<Oid> = HashSet::new();
    seen_tags.insert(start_oid);
    while cur_kind == ObjKind::Tag {
        let (next_oid, decl_kind, trailer_dig) = parse_annotated_tag(&raw_cur)?;
        if let (Some(exp), Some(td)) = (expect, trailer_dig) {
            if !ct_eq(&exp, &td) {
                return Err(VerifyError::mismatch(format!(
                    "tag Buttress-Object ({}) disagrees with expected digest ({})",
                    to_hex(&td),
                    to_hex(&exp)
                )));
            }
        }
        if expect.is_none() {
            expect = trailer_dig;
        }
        target_oid = next_oid;
        let (actual_kind, r2) = store
            .read_object(&target_oid)
            .map_err(VerifyError::incomplete)?
            .ok_or_else(|| {
                VerifyError::incomplete(format!("missing tagged object {}", to_hex(&target_oid)))
            })?;
        if actual_kind != decl_kind {
            return Err(VerifyError::mismatch(format!(
                "tag declared target type {}, but object {} is {}",
                decl_kind.as_str(),
                to_hex(&target_oid),
                actual_kind.as_str()
            )));
        }
        cur_kind = actual_kind;
        if cur_kind == ObjKind::Tag {
            if !seen_tags.insert(target_oid) {
                return Err(VerifyError::mismatch(format!(
                    "cycle in annotated tag chain at {}",
                    to_hex(&target_oid)
                )));
            }
            raw_cur = r2;
        }
    }

    let mut engine = Engine::new(store, keys, DigestCache::memory_only());

    match cur_kind {
        ObjKind::Blob => {
            let actual = engine.digest_blob(target_oid)?;
            match expect {
                Some(exp) if ct_eq(&actual, &exp) => Ok(CheckOutcome::Match {
                    target_oid,
                    digest: actual,
                    sealed_checked: 0,
                    plain_covered: 0,
                    shallow_stops: 0,
                }),
                Some(exp) => Err(VerifyError::mismatch(format!(
                    "MISMATCH on blob {}:\n  expected: {}\n  actual:   {}",
                    to_hex(&target_oid),
                    to_hex(&exp),
                    to_hex(&actual)
                ))),
                None => Ok(CheckOutcome::NoEvidence {
                    target_oid,
                    digest: actual,
                }),
            }
        }
        ObjKind::Tree => {
            let actual = engine.digest_tree(target_oid)?;
            match expect {
                Some(exp) if ct_eq(&actual, &exp) => Ok(CheckOutcome::Match {
                    target_oid,
                    digest: actual,
                    sealed_checked: 0,
                    plain_covered: 0,
                    shallow_stops: 0,
                }),
                Some(exp) => Err(VerifyError::mismatch(format!(
                    "MISMATCH on directory {}:\n  expected: {}\n  actual:   {}",
                    to_hex(&target_oid),
                    to_hex(&exp),
                    to_hex(&actual)
                ))),
                None => Ok(CheckOutcome::NoEvidence {
                    target_oid,
                    digest: actual,
                }),
            }
        }
        ObjKind::Commit => {
            let root_pc = engine.load_commit(target_oid)?;
            let root_is_sealed = matches!(root_pc.class, CommitClass::Sealed { .. });

            let (root_dig, initial_sealed) = engine.digest_commit(target_oid)?;

            if let Some(exp) = expect {
                if !ct_eq(&root_dig, &exp) {
                    return Err(VerifyError::mismatch(format!(
                        "MISMATCH on commit {}:\n  expected: {}\n  actual:   {}",
                        to_hex(&target_oid),
                        to_hex(&exp),
                        to_hex(&root_dig)
                    )));
                }
            } else if !root_is_sealed {
                return Ok(CheckOutcome::NoEvidence {
                    target_oid,
                    digest: root_dig,
                });
            }

            let mut queue: VecDeque<Oid> = VecDeque::new();
            let mut seen_sealed: HashSet<Oid> = HashSet::new();
            if root_is_sealed {
                seen_sealed.insert(target_oid);
                queue.push_back(target_oid);
            }
            for sc in initial_sealed {
                if seen_sealed.insert(sc) {
                    queue.push_back(sc);
                }
            }

            let mut shallow_stops = 0usize;

            while let Some(cur) = queue.pop_front() {
                let pc = engine.load_commit(cur)?;
                let CommitClass::Sealed {
                    expected_tree,
                    expected_parents,
                } = pc.class
                else {
                    unreachable!("only sealed commits enter verification queue");
                };

                let actual_tree = engine.digest_tree(pc.tree)?;
                if !ct_eq(&actual_tree, &expected_tree) {
                    return Err(VerifyError::mismatch(format!(
                        "MISMATCH at commit {} (directory {}):\n  directory expected: {}\n  directory actual:   {}",
                        to_hex(&cur),
                        to_hex(&pc.tree),
                        to_hex(&expected_tree),
                        to_hex(&actual_tree)
                    )));
                }

                let cur_is_shallow_boundary = engine.store.shallow_commits().contains(&cur);
                for (&p_oid, exp_p_dig) in pc.parents.iter().zip(expected_parents.iter()) {
                    if cur_is_shallow_boundary
                        && engine
                            .store
                            .read_object(&p_oid)
                            .map_err(VerifyError::incomplete)?
                            .is_none()
                    {
                        if allow_shallow {
                            shallow_stops += 1;
                            continue;
                        }
                        return Err(VerifyError::incomplete(format!(
                            "commit {} stops at shallow boundary (missing parent {})",
                            to_hex(&cur),
                            to_hex(&p_oid)
                        )));
                    }

                    let (actual_p_dig, under_sealed) = engine.digest_commit(p_oid)?;
                    if !ct_eq(&actual_p_dig, exp_p_dig) {
                        return Err(VerifyError::mismatch(format!(
                            "MISMATCH at parent {} of commit {}:\n  parent expected: {}\n  parent actual:   {}",
                            to_hex(&p_oid),
                            to_hex(&cur),
                            to_hex(exp_p_dig),
                            to_hex(&actual_p_dig)
                        )));
                    }
                    let p_pc = engine.load_commit(p_oid)?;
                    if matches!(p_pc.class, CommitClass::Sealed { .. }) && seen_sealed.insert(p_oid)
                    {
                        queue.push_back(p_oid);
                    }
                    for sc in under_sealed {
                        if seen_sealed.insert(sc) {
                            queue.push_back(sc);
                        }
                    }
                }
            }

            let plain_covered = engine
                .parsed
                .values()
                .filter(|pc| !matches!(pc.class, CommitClass::Sealed { .. }))
                .count();

            Ok(CheckOutcome::Match {
                target_oid,
                digest: root_dig,
                sealed_checked: seen_sealed.len(),
                plain_covered,
                shallow_stops,
            })
        }
        ObjKind::Tag => unreachable!("peeled above"),
    }
}

/// Strip existing `buttress-tree blake3`, `buttress-parent blake3`, and `gpgsig*` lines
/// from raw commit header bytes, preserving all other headers (including unknown algorithms).
pub fn strip_blake3_and_sig_headers(header_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut kept: Vec<Vec<u8>> = Vec::new();
    let mut skip_continuation = false;
    for line in header_bytes.split(|&c| c == b'\n') {
        if line.starts_with(b" ") {
            if !skip_continuation {
                kept.push(line.to_vec());
            }
            continue;
        }
        skip_continuation = false;
        if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            skip_continuation = true;
            continue;
        }
        if line.starts_with(b"buttress-tree blake3 ")
            || line.starts_with(b"buttress-parent blake3 ")
        {
            continue;
        }
        kept.push(line.to_vec());
    }
    kept
}
