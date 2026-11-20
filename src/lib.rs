//! Crate `git_buttress`: BLAKE3 Merkle integrity spine smuggled into standard SHA-1 Git commits and tags.
//!
//! # Crate-Level Contract & Trust Boundaries
//!
//! See [`CONTRACTS.md`](../CONTRACTS.md) for the complete Design-by-Contract (Hoare/Meyer/Ode-style)
//! specification of every module, type invariant, public function, hook, wrapper, and CLI subcommand,
//! and [`BUTTRESS.md`](../BUTTRESS.md) for the wire protocol specification.
//!
//! - [`protocol`]: Pure deterministic cryptographic parsing, Merkle tree/commit derivation, and verification.
//! - [`git`]: Hardened subprocess wrapper over stock `git` (`--no-replace-objects`, `GIT_NO_LAZY_FETCH=1`,
//!   stream-desync-safe `cat-file --batch`, non-recursive real-`git` discovery).
//! - [`cache`]: Unauthenticated write-side-only append cache (`.git/buttress-cache.bin`), never read by verifiers.
//! - [`hooks`]: `enable`/`disable`, POSIX-quoted hook scripts (`post-commit`, `reference-transaction`), and
//!   transparent `git` wrapper (`commit` summary sync + `fsck` chaining).

pub mod cache;
pub mod git;
pub mod hooks;
pub mod protocol;
