//! Core `git-buttress` protocol (implements `BUTTRESS.md` to the byte).

use crate::cache::{Dig, DigestCache, Oid, OidMap};
use crate::git::{ObjKind, ObjectStore, StoreError, StoreErrorKind, hex_to_32, hex_to_oid, to_hex};
use blake3_servil::throughput::context_key;
use blake3_servil::{ContextKey, Mode, convenience};
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;

pub const CTX_FILE: &str = "git-buttress 2026-11-20 file";
pub const CTX_DIR: &str = "git-buttress 2026-11-20 directory";
pub const CTX_COMMIT: &str = "git-buttress 2026-11-20 commit";
pub const CTX_PLAIN: &str = "git-buttress 2026-11-20 plain commit";

pub const HEADER_TREE_PREFIX: &[u8] = b"buttress-tree ";
pub const HEADER_PARENT_PREFIX: &[u8] = b"buttress-parent ";
pub const TAG_TRAILER_PREFIX: &[u8] = b"Buttress-Object: ";

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
    pub raw: Rc<[u8]>,
    pub tree: Oid,
    pub parents: Vec<Oid>,
    pub class: CommitClass,
    pub has_gpgsig: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyErrorKind {
    /// Cryptographic digest mismatch, malformed Git/buttress syntax, or graph cycle.
    Mismatch,
    /// Missing object at a shallow or partial-clone boundary.
    Incomplete,
    /// Corrupt object store, subprocess crash, or I/O error (never excused by `--allow-shallow` or `silent`).
    StoreFailure,
}

#[derive(Clone, Debug)]
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
    pub fn store_failure(msg: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::StoreFailure,
            message: msg.into(),
        }
    }
    pub fn from_store(e: StoreError) -> Self {
        match e.kind {
            StoreErrorKind::Missing => Self::incomplete(e.message),
            StoreErrorKind::CorruptOrIo => Self::store_failure(e.message),
        }
    }
}

/// Split raw commit/tag object bytes at the header/body boundary (`\n\n` or single-`\n` header-only).
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

/// Parse a Git commit matching stock Git's canonical leading `tree` + consecutive `parent`
/// header order (`commit.c:parse_commit_buffer`) and classify its `blake3` buttress lines.
pub fn parse_commit(oid: Oid, raw: Vec<u8>) -> Result<ParsedCommit, VerifyError> {
    let (header_bytes, _) = split_headers_body(&raw);
    if header_bytes.contains(&0) {
        return Err(VerifyError::mismatch(format!(
            "commit {}: NUL byte in commit header",
            to_hex(&oid)
        )));
    }

    let mut lines = header_bytes.split(|&c| c == b'\n').peekable();

    // 1. Leading line MUST be `tree <40-hex>` (matches Git `commit.c` / `fsck.c`)
    let Some(first_line) = lines.next() else {
        return Err(VerifyError::mismatch(format!(
            "commit {}: empty commit header",
            to_hex(&oid)
        )));
    };
    let Some(tree_rest) = first_line.strip_prefix(b"tree ") else {
        return Err(VerifyError::mismatch(format!(
            "commit {}: first header must be 'tree <oid>'",
            to_hex(&oid)
        )));
    };
    let tree = hex_to_oid(tree_rest).map_err(|e| {
        VerifyError::mismatch(format!("commit {}: invalid tree line: {e}", to_hex(&oid)))
    })?;

    // 2. Immediately consecutive `parent <40-hex>` lines
    let mut parents: Vec<Oid> = Vec::new();
    while let Some(&next_line) = lines.peek() {
        if let Some(p_rest) = next_line.strip_prefix(b"parent ") {
            lines.next();
            let p = hex_to_oid(p_rest).map_err(|e| {
                VerifyError::mismatch(format!("commit {}: invalid parent line: {e}", to_hex(&oid)))
            })?;
            parents.push(p);
        } else {
            break;
        }
    }

    // 3. Remaining headers: reject out-of-order `tree`/`parent`, reject continuations on single-line
    //    `buttress-*` headers, and classify `blake3` buttress lines!
    let mut b3_trees: Vec<(Oid, Dig)> = Vec::new();
    let mut b3_parents: Vec<Dig> = Vec::new();
    let mut has_gpgsig = false;
    let mut prev_was_single_line_buttress = false;

    for line in lines {
        if line.is_empty() {
            return Err(VerifyError::mismatch(format!(
                "commit {}: unexpected empty line inside header block",
                to_hex(&oid)
            )));
        }
        if line.starts_with(b" ") {
            if prev_was_single_line_buttress {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: illegal continuation line after single-line buttress header",
                    to_hex(&oid)
                )));
            }
            continue;
        }
        prev_was_single_line_buttress = false;

        if line.starts_with(b"tree ") || line == b"tree" {
            return Err(VerifyError::mismatch(format!(
                "commit {}: duplicate or out-of-order tree header",
                to_hex(&oid)
            )));
        }
        if line.starts_with(b"parent ") || line == b"parent" {
            return Err(VerifyError::mismatch(format!(
                "commit {}: out-of-order parent header",
                to_hex(&oid)
            )));
        }
        if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            has_gpgsig = true;
        } else if line == b"buttress-tree"
            || line == b"buttress-parent"
            || line.starts_with(b"buttress-tree\t")
            || line.starts_with(b"buttress-parent\t")
        {
            return Err(VerifyError::mismatch(format!(
                "commit {}: malformed buttress header",
                to_hex(&oid)
            )));
        } else if let Some(rest) = line.strip_prefix(HEADER_TREE_PREFIX) {
            prev_was_single_line_buttress = true;
            let parts: Vec<&[u8]> = rest.split(|&c| c == b' ').collect();
            if parts.is_empty() || !is_valid_alg_token(parts[0]) {
                return Err(VerifyError::mismatch(format!(
                    "commit {}: malformed buttress-tree algorithm",
                    to_hex(&oid)
                )));
            }
            if parts[0] != b"blake3" {
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
            prev_was_single_line_buttress = true;
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
                    "commit {}: malformed buttress-parent blake3 line",
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
        raw: Rc::from(raw),
        tree,
        parents,
        class,
        has_gpgsig,
    })
}

/// Parse raw Git tree entries: `(mode_bytes, octal_mode, name_bytes, child_oid)`.
/// Enforces unique entry names (no duplicates, `.`, `..`, `.git`, empty, or `/`).
pub fn parse_tree_entries(raw: &[u8]) -> Result<Vec<(&[u8], u32, &[u8], Oid)>, VerifyError> {
    let mut entries = Vec::new();
    let mut seen_names: HashSet<&[u8]> = HashSet::new();
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
        if !matches!(octal, 0o040000 | 0o100644 | 0o100664 | 0o100755 | 0o120000 | 0o160000) {
            return Err(VerifyError::mismatch(format!(
                "malformed tree: unsupported entry mode 0o{octal:o}"
            )));
        }
        let rel_nul = raw[sp + 1..]
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| VerifyError::mismatch("malformed tree: missing NUL"))?;
        let nul = sp + 1 + rel_nul;
        if nul + 21 > n {
            return Err(VerifyError::mismatch("malformed tree: truncated child OID"));
        }
        let name = &raw[sp + 1..nul];
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.eq_ignore_ascii_case(b".git")
            || name.contains(&b'/')
        {
            return Err(VerifyError::mismatch(
                "malformed tree: invalid or reserved entry name",
            ));
        }
        if !seen_names.insert(name) {
            return Err(VerifyError::mismatch("malformed tree: duplicate entry name"));
        }
        let child: Oid = raw[nul + 1..nul + 21].try_into().unwrap();
        entries.push((mode_bytes, octal, name, child));
        i = nul + 21;
    }
    Ok(entries)
}

pub const MODE_DIR: u32 = 0o040000;
pub const MODE_GITLINK: u32 = 0o160000;

/// Encapsulated Merkle calculation & verification state over a snapshot `ObjectStore`.
pub struct Engine<'a, S: ObjectStore> {
    store: &'a mut S,
    keys: &'a ContextKeys,
    cache: DigestCache,
    parsed: OidMap<ParsedCommit>,
    /// Memoized sealed frontier directly reachable beneath each plain/stale commit,
    /// so `digest_commit` returns identical `(digest, frontier)` whether cold or warm!
    plain_frontiers: OidMap<Vec<Oid>>,
    verified_seals: HashSet<Oid>,
    /// Sealed commits whose entire reachable ancestry verified with ZERO shallow skips
    /// on this snapshot, allowing multi-ref `fsck` / `prepared` runs to avoid O(refs * history) re-walks!
    transitively_verified: HashSet<Oid>,
}

impl<'a, S: ObjectStore> Engine<'a, S> {
    pub fn new(store: &'a mut S, keys: &'a ContextKeys, cache: DigestCache) -> Self {
        Self {
            store,
            keys,
            cache,
            parsed: OidMap::new(),
            plain_frontiers: OidMap::new(),
            verified_seals: HashSet::new(),
            transitively_verified: HashSet::new(),
        }
    }

    /// Construct a verification-only `Engine` guaranteed by construction to use an isolated
    /// in-memory cache (`TB-1`).
    pub fn new_verifier(store: &'a mut S, keys: &'a ContextKeys) -> Self {
        Self::new(store, keys, DigestCache::memory_only())
    }

    pub fn flush_cache(&mut self) {
        self.cache.flush();
    }

    pub fn parsed_commits(&self) -> &OidMap<ParsedCommit> {
        &self.parsed
    }

    pub fn load_commit(&mut self, oid: Oid) -> Result<ParsedCommit, VerifyError> {
        if let Some(pc) = self.parsed.get(&oid) {
            return Ok(pc.clone());
        }
        let (kind, raw) = self
            .store
            .read_object(&oid)
            .map_err(VerifyError::from_store)?
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
        if let Some(d) = self.cache.get_blob(&oid) {
            return Ok(d);
        }
        let (kind, dig) = self
            .store
            .hash_blob(&oid, self.keys)
            .map_err(VerifyError::from_store)?
            .ok_or_else(|| VerifyError::incomplete(format!("missing blob object {}", to_hex(&oid))))?;
        if kind != ObjKind::Blob {
            return Err(VerifyError::mismatch(format!(
                "expected blob for {}, found {}",
                to_hex(&oid),
                kind.as_str()
            )));
        }
        self.cache.put_blob(oid, dig);
        Ok(dig)
    }

    pub fn digest_tree(&mut self, root_oid: Oid) -> Result<Dig, VerifyError> {
        if let Some(d) = self.cache.get_tree(&root_oid) {
            return Ok(d);
        }
        let mut stack: Vec<(Oid, Option<Vec<u8>>)> = vec![(root_oid, None)];
        let mut in_progress: HashSet<Oid> = HashSet::new();

        while let Some((oid, raw_opt)) = stack.pop() {
            if self.cache.get_tree(&oid).is_some() {
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
                        .map_err(VerifyError::from_store)?
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
                if octal == MODE_DIR && self.cache.get_tree(&child).is_none() {
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
                    buf.extend_from_slice(&self.cache.get_tree(&child).unwrap());
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
        Ok(self.cache.get_tree(&root_oid).unwrap())
    }

    /// Compute `commit_digest(root_oid)` per `BUTTRESS.md` §3, returning
    /// `(digest, sealed_boundary_commits_beneath_root)`.
    ///
    /// Cache-temperature invariant: returns the exact same `(digest, frontier)` whether
    /// `self` is cold or warm!
    pub fn digest_commit(&mut self, root_oid: Oid) -> Result<(Dig, Vec<Oid>), VerifyError> {
        if let Some(d) = self.cache.get_commit(&root_oid) {
            if let Some(frontier) = self.plain_frontiers.get(&root_oid) {
                return Ok((d, frontier.clone()));
            }
            let pc = self.load_commit(root_oid)?;
            if matches!(pc.class, CommitClass::Sealed { .. }) {
                return Ok((d, Vec::new()));
            }
            // Disk-cache hit on a plain commit where frontier wasn't populated in RAM yet:
            // fall through to compute/populate frontier if needed, or return `d` when only digest wanted.
        }

        let root_pc = self.load_commit(root_oid)?;
        if matches!(root_pc.class, CommitClass::Sealed { .. }) {
            let d = self.keys.hash_sealed_commit(&root_pc.raw);
            self.cache.put_commit(root_oid, d);
            return Ok((d, Vec::new()));
        }

        let mut stack: Vec<(Oid, bool)> = vec![(root_oid, false)];
        let mut in_progress: HashSet<Oid> = HashSet::new();

        while let Some((cur, expanded)) = stack.pop() {
            if self.cache.get_commit(&cur).is_some() && self.plain_frontiers.contains_key(&cur) {
                continue;
            }
            let pc = self.load_commit(cur)?;
            if matches!(pc.class, CommitClass::Sealed { .. }) {
                let d = self.keys.hash_sealed_commit(&pc.raw);
                self.cache.put_commit(cur, d);
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
                    if self.cache.get_commit(&p).is_none() || !self.plain_frontiers.contains_key(&p) {
                        let p_exists = self.store.has_object(&p).map_err(VerifyError::from_store)?;
                        if !p_exists {
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
                        let ppc = self.load_commit(p)?;
                        if matches!(ppc.class, CommitClass::Sealed { .. }) {
                            let pd = self.keys.hash_sealed_commit(&ppc.raw);
                            self.cache.put_commit(p, pd);
                        } else {
                            stack.push((p, false));
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

                let mut frontier_set: HashSet<Oid> = HashSet::new();
                let mut frontier_vec: Vec<Oid> = Vec::new();
                for &p in &pc.parents {
                    buf.extend_from_slice(&self.cache.get_commit(&p).unwrap());
                    let ppc = self.load_commit(p)?;
                    if matches!(ppc.class, CommitClass::Sealed { .. }) {
                        if frontier_set.insert(p) {
                            frontier_vec.push(p);
                        }
                    } else if let Some(pf) = self.plain_frontiers.get(&p) {
                        for &sc in pf {
                            if frontier_set.insert(sc) {
                                frontier_vec.push(sc);
                            }
                        }
                    }
                }
                buf.extend_from_slice(&pc.raw);
                let d = self.keys.hash_plain_commit(&buf);
                self.cache.put_commit(cur, d);
                self.plain_frontiers.insert(cur, frontier_vec);
            }
        }

        let d = self.cache.get_commit(&root_oid).unwrap();
        let f = self.plain_frontiers.get(&root_oid).cloned().unwrap_or_default();
        Ok((d, f))
    }
}

/// Extract `+blake3-<64-hex>` embedded in a canonical ref/tag name (never a `^`/`~` revision walk!).
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
    // Reject revision-traversal suffixes (`~`, `^1`, `^{tree}`, `:path`) on a pinned ref name so a pin's
    // digest can never be accidentally checked against a derived ancestor/subtree! Only exact `^{}` tag-peel is allowed.
    let rest = rest.strip_suffix("^{}").unwrap_or(rest);
    if rest.contains(['^', '~', ':']) {
        return Err(VerifyError::mismatch(format!(
            "revision traversal operator on +blake3- ref {ref_or_name:?} is ambiguous; pass the exact ref name"
        )));
    }
    let token = rest.split(['+', '/']).next().unwrap_or(rest);
    let dig = hex_to_32(token.as_bytes()).map_err(|e| {
        VerifyError::mismatch(format!(
            "malformed +blake3- digest in ref {ref_or_name:?}: {e}"
        ))
    })?;
    Ok(Some(dig))
}

/// Parse an annotated tag strictly matching upstream Git `tag.c:parse_tag_buffer` & `fsck_tag_standalone`:
///   Line 1 MUST be `object <40-hex>`
///   Line 2 MUST be `type <blob|tree|commit|tag>`
///   Line 3 MUST be `tag <non-empty-name>`
///   Optional Line 4 `tagger ...`, and NO duplicate/unknown extra headers!
/// Also strips only a genuine terminal PGP/SSH signature block from the body and parses
/// `Buttress-Object: <alg> <target-sha1> <64-hex>` at the byte level.
pub fn parse_annotated_tag(raw: &[u8]) -> Result<(Oid, ObjKind, Option<Dig>), VerifyError> {
    let (header, body) = split_headers_body(raw);
    if header.contains(&0) {
        return Err(VerifyError::mismatch("annotated tag: NUL byte in header"));
    }
    let mut lines = header.split(|&c| c == b'\n');

    // Line 1: `object <40-hex>`
    let line1 = lines
        .next()
        .ok_or_else(|| VerifyError::mismatch("annotated tag: empty header"))?;
    let obj_hex = line1
        .strip_prefix(b"object ")
        .ok_or_else(|| VerifyError::mismatch("annotated tag: first line must be 'object <oid>'"))?;
    let target_oid = hex_to_oid(obj_hex)
        .map_err(|e| VerifyError::mismatch(format!("annotated tag: invalid object OID: {e}")))?;

    // Line 2: `type <kind>`
    let line2 = lines
        .next()
        .ok_or_else(|| VerifyError::mismatch("annotated tag: missing 'type' line"))?;
    let type_bytes = line2
        .strip_prefix(b"type ")
        .ok_or_else(|| VerifyError::mismatch("annotated tag: second line must be 'type <kind>'"))?;
    let target_kind = ObjKind::from_bytes(type_bytes).map_err(VerifyError::mismatch)?;

    // Line 3: `tag <non-empty-name>`
    let line3 = lines
        .next()
        .ok_or_else(|| VerifyError::mismatch("annotated tag: missing 'tag' line"))?;
    let tag_name = line3
        .strip_prefix(b"tag ")
        .ok_or_else(|| VerifyError::mismatch("annotated tag: third line must be 'tag <name>'"))?;
    if tag_name.is_empty() {
        return Err(VerifyError::mismatch("annotated tag: empty tag name"));
    }

    // Optional `tagger ...` and optional `gpgsig`/`gpgsig-sha256` header, rejecting any extra/duplicate headers!
    let mut saw_tagger = false;
    let mut in_gpgsig = false;
    for rem_line in lines {
        if in_gpgsig && rem_line.starts_with(b" ") {
            continue;
        }
        in_gpgsig = false;
        if !saw_tagger && rem_line.starts_with(b"tagger ") {
            saw_tagger = true;
            continue;
        }
        if rem_line.starts_with(b"gpgsig ") || rem_line.starts_with(b"gpgsig-sha256 ") {
            in_gpgsig = true;
            continue;
        }
        return Err(VerifyError::mismatch(
            "annotated tag: unexpected or duplicate header line (violates Git fsck_tag)",
        ));
    }

    let unsigned_body = strip_terminal_signature_block(body);

    let mut found: Vec<Dig> = Vec::new();
    for raw_line in unsigned_body.split(|&c| c == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line == b"Buttress-Object:"
            || (line.starts_with(b"Buttress-Object:") && !line.starts_with(TAG_TRAILER_PREFIX))
        {
            return Err(VerifyError::mismatch(
                "malformed Buttress-Object trailer spacing",
            ));
        }
        if let Some(rest) = line.strip_prefix(TAG_TRAILER_PREFIX) {
            let parts: Vec<&[u8]> = rest.split(|&c| c == b' ').collect();
            if parts.is_empty() || !is_valid_alg_token(parts[0]) {
                return Err(VerifyError::mismatch("malformed Buttress-Object algorithm"));
            }
            if parts[0] != b"blake3" {
                continue;
            }
            if parts.len() != 3 {
                return Err(VerifyError::mismatch(
                    "malformed Buttress-Object blake3 trailer (expected `<alg> <oid> <digest>`)",
                ));
            }
            let t_oid = hex_to_oid(parts[1])
                .map_err(|e| VerifyError::mismatch(format!("bad tag trailer OID: {e}")))?;
            if t_oid != target_oid {
                return Err(VerifyError::mismatch(
                    "tag Buttress-Object OID does not match tag object header",
                ));
            }
            let dig = hex_to_32(parts[2])
                .map_err(|e| VerifyError::mismatch(format!("bad tag trailer digest: {e}")))?;
            found.push(dig);
        }
    }
    if found.len() > 1 {
        return Err(VerifyError::mismatch(
            "duplicate Buttress-Object blake3 trailers",
        ));
    }
    Ok((target_oid, target_kind, found.into_iter().next()))
}

/// Strip ONLY a genuine line-anchored terminal PGP/SSH/CMS signature block at the very end of `body`
/// (matching Git `gpg-interface.c:parse_signature`), so prose mentioning `-----BEGIN PGP SIGNATURE-----`
/// earlier in a tag message never truncates the body!
fn strip_terminal_signature_block(body: &[u8]) -> &[u8] {
    const BLOCKS: &[(&[u8], &[u8])] = &[
        (
            b"-----BEGIN PGP SIGNATURE-----",
            b"-----END PGP SIGNATURE-----",
        ),
        (
            b"-----BEGIN SSH SIGNATURE-----",
            b"-----END SSH SIGNATURE-----",
        ),
        (
            b"-----BEGIN PGP MESSAGE-----",
            b"-----END PGP MESSAGE-----",
        ),
        (
            b"-----BEGIN SIGNED MESSAGE-----",
            b"-----END SIGNED MESSAGE-----",
        ),
    ];

    let trimmed = body.trim_ascii_end();
    for &(begin_marker, end_marker) in BLOCKS {
        if !trimmed.ends_with(end_marker) {
            continue;
        }
        // Find the last line-anchored `begin_marker` prior to the terminal `end_marker`
        let mut search_end = trimmed.len() - end_marker.len();
        while let Some(rel) = trimmed[..search_end]
            .windows(begin_marker.len())
            .rposition(|w| w == begin_marker)
        {
            let at_line_start = rel == 0 || trimmed[rel - 1] == b'\n';
            let after = rel + begin_marker.len();
            let valid_line_end =
                after == trimmed.len() || trimmed[after] == b'\n' || trimmed[after] == b'\r';
            if at_line_start && valid_line_end {
                return &body[..rel];
            }
            if rel == 0 {
                break;
            }
            search_end = rel;
        }
    }
    body
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
        ancestors_sealed_checked: usize,
        shallow_stops: usize,
    },
}

#[inline]
pub fn ct_eq(a: &Dig, b: &Dig) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Shared, memoized verifier across one or more refs in a single repository snapshot (`fsck` / `prepared` hook).
pub fn verify_target<S: ObjectStore>(
    store: &mut S,
    keys: &ContextKeys,
    start_oid: Oid,
    ref_hint: Option<&str>,
    explicit_expect: Option<Dig>,
    allow_shallow: bool,
) -> Result<CheckOutcome, VerifyError> {
    let mut engine = Engine::new(store, keys, DigestCache::memory_only());
    verify_target_with_engine(
        &mut engine,
        start_oid,
        ref_hint,
        explicit_expect,
        allow_shallow,
    )
}

/// Verify a target using an existing fresh-memory `Engine` so multi-ref `fsck` and `prepared`
/// hook runs reuse verified subgraphs instead of re-traversing history `O(refs * commits)` times!
pub fn verify_target_with_engine<S: ObjectStore>(
    engine: &mut Engine<'_, S>,
    start_oid: Oid,
    ref_hint: Option<&str>,
    explicit_expect: Option<Dig>,
    allow_shallow: bool,
) -> Result<CheckOutcome, VerifyError> {
    assert!(
        engine.cache.is_memory_only(),
        "TB-1 violation: verify_target_with_engine requires a memory-only DigestCache!"
    );
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

    // Check object type via `object_info` FIRST so direct blobs (or tagged blobs) NEVER allocate
    // a multi-GB Vec in RAM and NEVER stream-hash twice (`R2-H7` & Astra `round2_contract` fix)!
    let (mut cur_kind, _) = engine
        .store
        .object_info(&start_oid)
        .map_err(VerifyError::from_store)?
        .ok_or_else(|| VerifyError::incomplete(format!("missing object {}", to_hex(&start_oid))))?;
    let mut target_oid = start_oid;

    if cur_kind == ObjKind::Tag {
        let (k_init, mut raw_cur) = engine
            .store
            .read_object(&start_oid)
            .map_err(VerifyError::from_store)?
            .ok_or_else(|| {
                VerifyError::incomplete(format!("missing object {}", to_hex(&start_oid)))
            })?;
        if k_init != ObjKind::Tag {
            return Err(VerifyError::store_failure("inconsistent object type for start tag"));
        }
        let mut seen_tags: HashSet<Oid> = HashSet::new();
        seen_tags.insert(start_oid);
        while cur_kind == ObjKind::Tag {
            let (next_oid, decl_kind, trailer_dig) = parse_annotated_tag(&raw_cur)?;
            if decl_kind == ObjKind::Tag && trailer_dig.is_some() {
                return Err(VerifyError::mismatch(
                    "Buttress-Object trailer on a tag-to-tag object is ambiguous; attach trailer to the tag naming the non-tag target",
                ));
            }
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

            let (actual_kind, _) = engine
                .store
                .object_info(&target_oid)
                .map_err(VerifyError::from_store)?
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
                let (_, r2) = engine
                    .store
                    .read_object(&target_oid)
                    .map_err(VerifyError::from_store)?
                    .ok_or_else(|| {
                        VerifyError::incomplete(format!(
                            "missing tagged object {}",
                            to_hex(&target_oid)
                        ))
                    })?;
                raw_cur = r2;
            }
        }
    }

    // `R2-H2` fix: Compute `pinned_expect` AFTER peeling tags so trailer-only pins ALSO enforce
    // full non-shallow coverage!
    let effective_allow_shallow = allow_shallow && expect.is_none();

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
                    ancestors_sealed_checked: 0,
                    shallow_stops: 0,
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
                    ancestors_sealed_checked: 0,
                    shallow_stops: 0,
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
            }

            // CRITICAL (H2 fix): Walk and verify ALL reachable sealed ancestors EVEN when `root_pc`
            // is Plain/Stale with `expect == None`! Contradictory ancestor evidence MUST ALWAYS
            // raise `Err(Mismatch)` rather than being hidden behind an early `NoEvidence` return!
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
                // If `cur` and its ENTIRE reachable ancestry already verified cleanly with zero
                // shallow skips on this Engine snapshot, skip re-walking its ancestors (`R2-H7` fix)!
                if engine.transitively_verified.contains(&cur) {
                    continue;
                }
                let already_verified_in_run = engine.verified_seals.contains(&cur);
                let pc = engine.load_commit(cur)?;
                let CommitClass::Sealed {
                    expected_tree,
                    expected_parents,
                } = pc.class
                else {
                    unreachable!("only sealed commits enter verification queue");
                };

                if !already_verified_in_run {
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
                }

                let cur_is_shallow_boundary = engine.store.shallow_commits().contains(&cur);
                let mut cur_had_shallow_skip = false;
                for (&p_oid, exp_p_dig) in pc.parents.iter().zip(expected_parents.iter()) {
                    if cur_is_shallow_boundary
                        && !engine.store.has_object(&p_oid).map_err(VerifyError::from_store)?
                    {
                        if effective_allow_shallow {
                            shallow_stops += 1;
                            cur_had_shallow_skip = true;
                            continue;
                        }
                        let pin_note = if expect.is_some() {
                            " (pinned target requires complete history)"
                        } else {
                            ""
                        };
                        return Err(VerifyError::incomplete(format!(
                            "commit {} stops at shallow boundary (missing parent {}){pin_note}",
                            to_hex(&cur),
                            to_hex(&p_oid)
                        )));
                    }

                    let (actual_p_dig, under_sealed) = engine.digest_commit(p_oid).map_err(|e| {
                        if expect.is_some() && e.kind == VerifyErrorKind::Incomplete {
                            VerifyError::incomplete(format!(
                                "{} (pinned target requires complete history)",
                                e.message
                            ))
                        } else {
                            e
                        }
                    })?;
                    if !already_verified_in_run && !ct_eq(&actual_p_dig, exp_p_dig) {
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

                if !cur_had_shallow_skip {
                    engine.verified_seals.insert(cur);
                }
            }

            // Every sealed commit in `seen_sealed` now had itself AND all reachable ancestors
            // verified without error; if `shallow_stops == 0`, their entire closures are complete!
            if shallow_stops == 0 {
                engine.transitively_verified.extend(seen_sealed.iter().copied());
            }

            if expect.is_none() && !root_is_sealed {
                return Ok(CheckOutcome::NoEvidence {
                    target_oid,
                    digest: root_dig,
                    ancestors_sealed_checked: seen_sealed.len(),
                    shallow_stops,
                });
            }

            // Count ONLY plain/stale commits reachable from `target_oid` (never polluted by earlier refs on shared Engine! `R2-Low` fix)
            let mut plain_covered = 0usize;
            let mut p_queue: VecDeque<Oid> = VecDeque::from([target_oid]);
            let mut p_seen: HashSet<Oid> = HashSet::from([target_oid]);
            while let Some(c) = p_queue.pop_front() {
                let Some(pc) = engine.parsed.get(&c) else {
                    continue;
                };
                if !matches!(pc.class, CommitClass::Sealed { .. }) {
                    plain_covered += 1;
                }
                for &p in &pc.parents {
                    if engine.parsed.contains_key(&p) && p_seen.insert(p) {
                        p_queue.push_back(p);
                    }
                }
            }

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
/// (including any continuation lines) from raw commit header bytes.
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
        if line.starts_with(b"gpgsig ")
            || line.starts_with(b"gpgsig-sha256 ")
            || line.starts_with(b"buttress-tree blake3 ")
            || line.starts_with(b"buttress-parent blake3 ")
        {
            skip_continuation = true;
            continue;
        }
        kept.push(line.to_vec());
    }
    kept
}
