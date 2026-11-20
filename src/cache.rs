//! Binary append-only object digest cache: `.git/buttress-cache.bin`.
//!
//! # Module Contract & Security Boundary
//!
//! - **Meaning (`meaning(c)`):** Three partial maps `(blobs, trees, commits)` from
//!   20-byte SHA-1 `Oid` to 32-byte BLAKE3 `Dig`, plus an append queue `pending`
//!   and optional backing file path `disk_path`.
//! - **Trust boundary:** Disk cache files live in `.git/buttress-cache.bin` and are
//!   **unauthenticated** performance hints used *exclusively* during commit/tag
//!   writing (`seal_head` and `buttress.autotag`). Every verification code path
//!   (`verify_target`, `check`, `fsck`, `reference-transaction` `prepared` phase)
//!   MUST construct `DigestCache::memory_only()`, where `disk_path == None` and no
//!   disk bytes are ever read or written.
//! - **Representation invariant `I(c)`:**
//!   1. If `c.disk_path.is_none()`, then `c.pending.is_empty()` holds at all times.
//!   2. Every `(kind, oid, dig)` in `c.pending` has `kind in {1, 2, 3}` and is
//!      already present with value `dig` in the corresponding in-memory map.
//! - **Atomicity / crash tolerance:** Each record is 53 bytes (`kind: u8 || oid: [u8; 20] || dig: [u8; 32]`)
//!   following an 8-byte magic header `b"BTRSC001"`. If a previous process crashed
//!   mid-append leaving `(file_len - 8) % 53 != 0`, `load_from_git_dir` ignores the
//!   trailing partial tail and `flush()` truncates the file back to the clean
//!   `8 + 53 * k` boundary before appending new records (preventing permanent
//!   53-byte frame misalignment!).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher as StdHasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub type Oid = [u8; 20];
pub type Dig = [u8; 32];

const MAGIC: &[u8; 8] = b"BTRSC001";
const REC_LEN: usize = 1 + 20 + 32;

const KIND_BLOB: u8 = 1;
const KIND_TREE: u8 = 2;
const KIND_COMMIT: u8 = 3;

#[derive(Default)]
pub struct OidHasher(u64);

/// Hashes 20-byte uniformly distributed Git OIDs by reading their leading 8 bytes
/// (falling back to FNV-style mixing on shorter slices); preserves `StdHasher` determinism.
impl StdHasher for OidHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, b: &[u8]) {
        if b.len() >= 8 {
            self.0 = u64::from_le_bytes(b[..8].try_into().unwrap());
        } else {
            for &x in b {
                self.0 = self.0.wrapping_mul(0x100000001b3) ^ (x as u64);
            }
        }
    }
}

pub type OidMap<V> = HashMap<Oid, V, BuildHasherDefault<OidHasher>>;

pub struct DigestCache {
    pub blobs: OidMap<Dig>,
    pub trees: OidMap<Dig>,
    pub commits: OidMap<Dig>,
    pending: Vec<(u8, Oid, Dig)>,
    disk_path: Option<PathBuf>,
}

impl DigestCache {
    /// Contract:
    /// - `requires`: true
    /// - `ensures`: returns `c` with empty maps, `c.pending.is_empty()`, and `c.disk_path == None`.
    /// - `writes`: nothing (pure allocation).
    pub fn memory_only() -> Self {
        Self {
            blobs: OidMap::default(),
            trees: OidMap::default(),
            commits: OidMap::default(),
            pending: Vec::new(),
            disk_path: None,
        }
    }

    /// Contract:
    /// - `requires`: `git_dir` is a repository common git directory (may or may not contain `buttress-cache.bin`).
    /// - `ensures`: returns `c` satisfying `I(c)` with `c.disk_path == Some(git_dir.join("buttress-cache.bin"))`
    ///   and `c.pending.is_empty()`. Any missing, corrupt-magic, or trailing partial record is ignored without error.
    /// - `writes`: nothing on disk.
    pub fn load_from_git_dir(git_dir: &Path) -> Self {
        let path = git_dir.join("buttress-cache.bin");
        let mut cache = Self::memory_only();
        cache.disk_path = Some(path.clone());

        let Ok(mut f) = File::open(&path) else {
            return cache;
        };
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_err() || buf.len() < MAGIC.len() || &buf[..8] != MAGIC {
            return cache;
        }
        let body = &buf[8..];
        let count = body.len() / REC_LEN;
        for i in 0..count {
            let rec = &body[i * REC_LEN..(i + 1) * REC_LEN];
            let kind = rec[0];
            let oid: Oid = rec[1..21].try_into().unwrap();
            let dig: Dig = rec[21..53].try_into().unwrap();
            match kind {
                KIND_BLOB => {
                    cache.blobs.insert(oid, dig);
                }
                KIND_TREE => {
                    cache.trees.insert(oid, dig);
                }
                KIND_COMMIT => {
                    cache.commits.insert(oid, dig);
                }
                _ => {}
            }
        }
        cache
    }

    /// Contract:
    /// - `requires`: `I(self)`
    /// - `ensures`: `I(self)` and `self.blobs.get(&oid) == Some(&dig)` (or previous value if already cached;
    ///   first-write-wins for a given `oid` within a session, overwritten on reload if re-inserted).
    /// - `writes`: `self.blobs`, `self.pending` (only when `self.disk_path.is_some()`).
    #[inline]
    pub fn put_blob(&mut self, oid: Oid, dig: Dig) {
        if self.blobs.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_BLOB, oid, dig));
        }
    }

    /// Contract: same as `put_blob` on `self.trees`.
    #[inline]
    pub fn put_tree(&mut self, oid: Oid, dig: Dig) {
        if self.trees.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_TREE, oid, dig));
        }
    }

    /// Contract: same as `put_blob` on `self.commits`.
    #[inline]
    pub fn put_commit(&mut self, oid: Oid, dig: Dig) {
        if self.commits.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_COMMIT, oid, dig));
        }
    }

    /// Contract:
    /// - `requires`: `I(self)`
    /// - `ensures`: `I(self)` and `self.pending.is_empty()`. If `self.disk_path == Some(p)` and
    ///   `old(self.pending)` was non-empty, best-effort persists `old(self.pending)` onto `p`
    ///   at a clean `8 + 53 * k` record boundary (repairing any bad header or torn trailing bytes first).
    /// - `writes`: `self.pending`, filesystem at `self.disk_path` (when `Some`).
    pub fn flush(&mut self) {
        let Some(ref path) = self.disk_path else {
            return;
        };
        if self.pending.is_empty() {
            return;
        }
        // Check existing file header & alignment so a torn write never misaligns subsequent records!
        let existing_valid_len: Option<u64> = (|| {
            let mut f = OpenOptions::new().read(true).write(true).open(path).ok()?;
            let len = f.metadata().ok()?.len();
            if len < MAGIC.len() as u64 {
                return None;
            }
            let mut hdr = [0u8; 8];
            f.read_exact(&mut hdr).ok()?;
            if &hdr != MAGIC {
                return None;
            }
            let body_len = len - MAGIC.len() as u64;
            let clean_len = MAGIC.len() as u64 + (body_len / REC_LEN as u64) * REC_LEN as u64;
            if clean_len != len {
                f.set_len(clean_len).ok()?;
            }
            Some(clean_len)
        })();

        let need_rewrite = existing_valid_len.is_none();
        let mut out = Vec::with_capacity(
            (if need_rewrite { MAGIC.len() } else { 0 }) + self.pending.len() * REC_LEN,
        );
        if need_rewrite {
            out.extend_from_slice(MAGIC);
        }
        for &(k, ref o, ref d) in &self.pending {
            out.push(k);
            out.extend_from_slice(o);
            out.extend_from_slice(d);
        }
        let res = if need_rewrite {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
        } else {
            OpenOptions::new().append(true).open(path)
        };
        if let Ok(mut f) = res {
            let _ = f.write_all(&out);
        }
        self.pending.clear();
    }
}
