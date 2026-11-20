//! Binary append-only object digest cache: `.git/buttress-cache.bin`.
//!
//! # Module Contract & Security Boundary
//!
//! - **Meaning (`meaning(c)`):** Three partial maps `(blobs, trees, commits)` from
//!   20-byte SHA-1 `Oid` to 32-byte BLAKE3 `Dig`, plus an append queue `pending`
//!   and optional backing file path `disk_path`.
//! - **Trust boundary:** Disk cache files live in `.git/buttress-cache.bin` and are
//!   **unauthenticated** performance hints used *only* for unsigned incremental
//!   bookkeeping. Every verification code path (`verify_target`, `check`, `fsck`,
//!   `reference-transaction` `prepared` phase) AND every cryptographic attestation
//!   (commit signing and `+blake3-` companion tag minting) MUST construct
//!   `DigestCache::memory_only()`, where `disk_path == None` and no disk bytes are
//!   ever read or written.
//! - **Representation invariant `I_cache(c)`:**
//!   1. `c.disk_path.is_none() ==> c.pending.is_empty()`.
//!   2. Consistent last-write-wins semantics across memory and disk: whenever
//!      `put_{blob,tree,commit}(oid, dig)` sets `map[oid] == dig` and either `oid`
//!      was previously absent OR had a *different* value, `(kind, oid, dig)` is
//!      appended to `c.pending` (when `c.disk_path.is_some()`), so reloading after
//!      `flush()` yields the exact same maps as in memory!
//!   3. Maps are private so external callers cannot mutate them out of sync with
//!      `pending`.
//! - **Keyed SipHash (DoS-safe):** Uses standard `HashMap` with Rust's randomized
//!   SipHash rather than an unkeyed prefix hasher, preventing hash-flooding O(N^2)
//!   degradation under adversarial SHA-1 OIDs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub type Oid = [u8; 20];
pub type Dig = [u8; 32];

const MAGIC: &[u8; 8] = b"BTRSC001";
const REC_LEN: usize = 1 + 20 + 32;

const KIND_BLOB: u8 = 1;
const KIND_TREE: u8 = 2;
const KIND_COMMIT: u8 = 3;

pub type OidMap<V> = HashMap<Oid, V>;

pub struct DigestCache {
    blobs: OidMap<Dig>,
    trees: OidMap<Dig>,
    commits: OidMap<Dig>,
    pending: Vec<(u8, Oid, Dig)>,
    disk_path: Option<PathBuf>,
}

impl DigestCache {
    /// Contract:
    /// - `requires`: true
    /// - `ensures`: returns `c` satisfying `I_cache(c)` with empty maps, `c.pending.is_empty()`,
    ///   and `c.disk_path == None`.
    /// - `writes`: nothing.
    pub fn memory_only() -> Self {
        Self {
            blobs: OidMap::new(),
            trees: OidMap::new(),
            commits: OidMap::new(),
            pending: Vec::new(),
            disk_path: None,
        }
    }

    #[inline]
    pub fn is_memory_only(&self) -> bool {
        self.disk_path.is_none()
    }

    /// Contract:
    /// - `requires`: `git_dir` is a repository common git directory.
    /// - `ensures`: returns `c` satisfying `I_cache(c)` with `c.disk_path == Some(git_dir.join("buttress-cache.bin"))`
    ///   and `c.pending.is_empty()`. Refuses symlinks/non-regular files; ignores missing, bad-magic,
    ///   oversized (> 256 MiB), or trailing partial records without error.
    /// - `writes`: nothing on disk.
    pub fn load_from_git_dir(git_dir: &Path) -> Self {
        let path = git_dir.join("buttress-cache.bin");
        let mut cache = Self::memory_only();
        cache.disk_path = Some(path.clone());

        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            return cache;
        };
        if !meta.file_type().is_file() || meta.len() > (256 << 20) {
            return cache;
        }
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
    pub fn get_blob(&self, oid: &Oid) -> Option<Dig> {
        self.blobs.get(oid).copied()
    }

    #[inline]
    pub fn get_tree(&self, oid: &Oid) -> Option<Dig> {
        self.trees.get(oid).copied()
    }

    #[inline]
    pub fn get_commit(&self, oid: &Oid) -> Option<Dig> {
        self.commits.get(oid).copied()
    }

    /// Contract:
    /// - `requires`: `I_cache(self)`
    /// - `ensures`: `I_cache(self)` and `self.get_blob(&oid) == Some(dig)` (last-write-wins both in memory
    ///   and on `pending` when `disk_path.is_some()`, so `flush` + `load_from_git_dir` round-trips identically).
    /// - `writes`: `self.blobs`, `self.pending`.
    #[inline]
    pub fn put_blob(&mut self, oid: Oid, dig: Dig) {
        if self.blobs.insert(oid, dig) != Some(dig) && self.disk_path.is_some() {
            self.pending.push((KIND_BLOB, oid, dig));
        }
    }

    /// Contract: same as `put_blob` on `self.trees`.
    #[inline]
    pub fn put_tree(&mut self, oid: Oid, dig: Dig) {
        if self.trees.insert(oid, dig) != Some(dig) && self.disk_path.is_some() {
            self.pending.push((KIND_TREE, oid, dig));
        }
    }

    /// Contract: same as `put_blob` on `self.commits`.
    #[inline]
    pub fn put_commit(&mut self, oid: Oid, dig: Dig) {
        if self.commits.insert(oid, dig) != Some(dig) && self.disk_path.is_some() {
            self.pending.push((KIND_COMMIT, oid, dig));
        }
    }

    /// Contract:
    /// - `requires`: `I_cache(self)`
    /// - `ensures`: `I_cache(self)` and `self.pending.is_empty()`. Uses a single owned file handle
    ///   (refusing symlinks) to verify/repair `BTRSC001` and `8 + 53 * k` alignment and write
    ///   `old(self.pending)` at the clean end-of-records offset.
    /// - `writes`: `self.pending`, filesystem at `self.disk_path` (when `Some`).
    pub fn flush(&mut self) {
        let Some(ref path) = self.disk_path else {
            return;
        };
        if self.pending.is_empty() {
            return;
        }
        // Refuse to follow symlinks on cache path
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_file() {
                self.pending.clear();
                return;
            }
        }

        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc_o_nofollow());
        }

        if let Ok(mut f) = opts.open(path) {
            let valid_offset: Option<u64> = (|| {
                let len = f.metadata().ok()?.len();
                if len < MAGIC.len() as u64 {
                    return None;
                }
                let mut hdr = [0u8; 8];
                f.seek(SeekFrom::Start(0)).ok()?;
                f.read_exact(&mut hdr).ok()?;
                if &hdr != MAGIC {
                    return None;
                }
                let clean_len =
                    MAGIC.len() as u64 + ((len - MAGIC.len() as u64) / REC_LEN as u64) * REC_LEN as u64;
                if clean_len != len {
                    f.set_len(clean_len).ok()?;
                }
                Some(clean_len)
            })();

            let mut out = Vec::with_capacity(MAGIC.len() + self.pending.len() * REC_LEN);
            match valid_offset {
                Some(off) => {
                    for &(k, ref o, ref d) in &self.pending {
                        out.push(k);
                        out.extend_from_slice(o);
                        out.extend_from_slice(d);
                    }
                    if f.seek(SeekFrom::Start(off)).is_ok() {
                        let _ = f.write_all(&out);
                    }
                }
                None => {
                    out.extend_from_slice(MAGIC);
                    for &(k, ref o, ref d) in &self.pending {
                        out.push(k);
                        out.extend_from_slice(o);
                        out.extend_from_slice(d);
                    }
                    if f.set_len(0).is_ok() && f.seek(SeekFrom::Start(0)).is_ok() {
                        let _ = f.write_all(&out);
                    }
                }
            }
        }
        self.pending.clear();
    }
}

#[cfg(target_os = "macos")]
const fn libc_o_nofollow() -> i32 {
    0x0100
}
#[cfg(target_os = "linux")]
const fn libc_o_nofollow() -> i32 {
    0o0400000
}
#[cfg(all(unix, not(target_os = "macos"), not(target_os = "linux")))]
const fn libc_o_nofollow() -> i32 {
    0
}
