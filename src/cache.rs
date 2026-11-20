//! Binary append-only object digest cache: `.git/buttress-cache.bin`.
//!
//! Used ONLY during commit/tag creation to make incremental commits O(changed
//! files). Verification (`check` / `fsck` / `reference-transaction`) NEVER
//! reads this file!
//!
//! Layout:
//!   - 8-byte header: `b"BTRSC001"`
//!   - N * 53-byte records:
//!       kind: u8 (1 = blob, 2 = tree, 3 = commit)
//!       oid:  [u8; 20]
//!       dig:  [u8; 32]

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
    pub fn memory_only() -> Self {
        Self {
            blobs: OidMap::default(),
            trees: OidMap::default(),
            commits: OidMap::default(),
            pending: Vec::new(),
            disk_path: None,
        }
    }

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

    #[inline]
    pub fn put_blob(&mut self, oid: Oid, dig: Dig) {
        if self.blobs.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_BLOB, oid, dig));
        }
    }

    #[inline]
    pub fn put_tree(&mut self, oid: Oid, dig: Dig) {
        if self.trees.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_TREE, oid, dig));
        }
    }

    #[inline]
    pub fn put_commit(&mut self, oid: Oid, dig: Dig) {
        if self.commits.insert(oid, dig).is_none() && self.disk_path.is_some() {
            self.pending.push((KIND_COMMIT, oid, dig));
        }
    }

    pub fn flush(&mut self) {
        let Some(ref path) = self.disk_path else {
            return;
        };
        if self.pending.is_empty() {
            return;
        }
        let need_magic = match std::fs::metadata(path) {
            Ok(m) => m.len() < MAGIC.len() as u64,
            Err(_) => true,
        };
        let mut out = Vec::with_capacity(
            (if need_magic { MAGIC.len() } else { 0 }) + self.pending.len() * REC_LEN,
        );
        let res = if need_magic {
            out.extend_from_slice(MAGIC);
            for &(k, ref o, ref d) in &self.pending {
                out.push(k);
                out.extend_from_slice(o);
                out.extend_from_slice(d);
            }
            OpenOptions::new().create(true).write(true).truncate(true).open(path)
        } else {
            for &(k, ref o, ref d) in &self.pending {
                out.push(k);
                out.extend_from_slice(o);
                out.extend_from_slice(d);
            }
            OpenOptions::new().append(true).open(path)
        };
        if let Ok(mut f) = res {
            let _ = f.write_all(&out);
        }
        self.pending.clear();
    }
}
