# git buttress

**Draft, 2026-11-20.** The context strings in section 3 are provisional;
changing them changes every digest in this document.

## 1. What it is

Git names every file, directory and commit by a SHA-1 hash. git buttress adds
BLAKE3 digests of the same things to new commits, in lines that Git already
carries and ignores. Old Git stores, copies and pushes them. A reader who
wants to can recompute them and compare.

Nothing else changes: not the files, not the directories, not the IDs of
existing commits, not the network protocol.

## 2. The two lines

A commit made with git buttress has these extra lines in its header:

    buttress-tree blake3 <tree-id> <digest>
    buttress-parent blake3 <digest>

* `<tree-id>` is 40 lowercase hex characters: the value of the commit's own
  `tree` line.
* `<digest>` is 64 lowercase hex characters.
* There is one `buttress-parent` line for each `parent` line, in the same
  order. A first commit has none.
* A writer puts the lines after the `committer` line and, if the commit is
  signed, adds them before signing, so the signature covers them.
* A reader looks at header lines that do not begin with a space, wherever
  they are in the header.

`blake3` names the algorithm. This document defines only `blake3`. A reader
skips lines whose algorithm it does not implement.

Example (a real commit of github.com/jasonhadler25/hashset, with the two
lines added):

    tree 90c9a260ae4584953a6c62f075868e69c9fa5fbb
    parent 3e7178d62f0450add99fb24c9a9df67c90fd9352
    author jasonhadler25 <jasonhadler25@users.noreply.github.com> 1795062191 -0800
    committer jasonhadler25 <jasonhadler25@users.noreply.github.com> 1795062191 -0800
    buttress-tree blake3 90c9a260ae4584953a6c62f075868e69c9fa5fbb a75286bbdeff34599303a1850e756ec9e23b303ff5fe13b6fc10472f8467687f
    buttress-parent blake3 47d94ceee1cbe424964472bd63f308eab32b258a60298c6689a04f5d390b7d7a

    Add SMUGGLING.md essay and MiniSHAKE128 (eprint 2026/2363) examples

**Why the tree line repeats the tree ID and the parent line does not.**
Stock `git commit --amend` copies header lines it does not know onto the
amended commit, even when the files changed. The copied `buttress-tree`
line would then describe the old directory. The repeated ID lets a reader
see that (it no longer equals the `tree` line) and ignore the line instead
of raising a false alarm. An amend keeps the same parents, so a copied
`buttress-parent` line is still right and needs no such marker.

## 3. The digests

Every digest is BLAKE3 in its key-derivation mode: 32 bytes of output from a
fixed context string and an input. The context string keeps the four kinds
of digest apart, so that, for example, a file can never have the digest of a
directory.

| Digest of | Context string | Input |
|---|---|---|
| a file | `git-buttress 2026-11-20 file` | the file's bytes as Git stores them |
| a directory | `git-buttress 2026-11-20 directory` | its entries, below |
| a commit that carries lines | `git-buttress 2026-11-20 commit` | the commit's bytes |
| a plain commit | `git-buttress 2026-11-20 plain commit` | below |

**Directory.** Take Git's stored directory, entry by entry, in the stored
order. Each entry contributes:

    <mode as stored> 0x20 <name> 0x00 <child>

where `<child>` depends on the mode read as an octal number:

* `040000`, a directory: that directory's 32-byte digest;
* `160000`, a submodule: the 20-byte ID exactly as stored;
* anything else (a file, an executable, a symbolic link): the 32-byte digest
  of the stored bytes.

This is Git's own directory format with each child's SHA-1 replaced by its
digest.

**Commit that carries lines.** The input is the commit's bytes, exactly as
`git cat-file commit` prints them. Those bytes already contain the digest of
its directory and of each parent.

**Plain commit** (one without lines). The input is:

    <digest of its directory, 32 bytes>
    <number of parents, 4 bytes, little-endian>
    <digest of each parent, 32 bytes each, in order>
    <the commit's bytes>

Each parent's digest is computed by whichever of the two commit rules
applies to it. This walks back until it meets a commit that carries lines,
or a first commit. That is how one new commit covers all the history behind
it.

## 4. Which commits carry lines

Looking only at `blake3` lines:

* **No buttress lines:** a plain commit.
* **One `buttress-tree` line whose tree ID equals the `tree` line, and as
  many `buttress-parent` lines as `parent` lines:** the commit carries lines.
* **One `buttress-tree` line whose tree ID differs from the `tree` line:**
  leftover lines from an amend. All its buttress lines are ignored and it is
  a plain commit.
* **Anything else** (two `buttress-tree` lines, `buttress-parent` lines
  without a `buttress-tree` line, the wrong number of `buttress-parent`
  lines, a line that does not match section 2): malformed. A reader reports
  a mismatch.

## 5. Checking

To check a commit, a reader starts there and, for every commit it reaches
that carries lines:

1. recomputes the digest of its directory from the stored files and
   compares it with the `buttress-tree` line;
2. recomputes the digest of each parent and compares it with the matching
   `buttress-parent` line;
3. goes on to the parents, and through plain commits to whatever lies
   behind them.

The reader may also be given a digest of the starting commit that came from
somewhere else: a release note, a colleague, its own earlier check.

There are three results:

* **mismatch:** a comparison failed, or a commit is malformed. Always an
  error.
* **match:** every comparison succeeded, and the starting commit carries
  lines or equals the digest given.
* **no evidence:** the starting commit is plain and no digest was given.
  A setting chooses what this does: nothing (the default), a warning, or an
  error.

A reader that cannot read an object it needs (a shallow or partial clone)
says which part it could not check. It never reports that part as a match.

A reader recomputes from the objects Git stores. It does not rely on a
cache it cannot check.

## 6. Check it yourself

With stock `git` and `b3sum`:

    git cat-file blob <id>   | b3sum --derive-key 'git-buttress 2026-11-20 file'
    git cat-file commit <id> | b3sum --derive-key 'git-buttress 2026-11-20 commit'

The second line is for a commit that carries lines. `buttress-vectors.py`
(about 60 lines, the same two programs) computes every digest in this
document.

| Thing | Digest |
|---|---|
| empty file | `0b0663e8d56ab3231c8e4bde914f42429b08f1edb19a237ef496eb1a3316c55c` |
| empty directory | `acf91ceb6e37c08b51530bf4cc86ae17daaf716f9f2284a1e0ce94c7001a68cd` |
| hashset `reference/hashset.py` (file `36fcc37c…`) | `8f85e3e27a527a0eec1d562d3b1d41f654494a6819c948a4938d8242d5ea8bda` |
| hashset `reference/test_hashset.py` (file `f537c9f8…`) | `c95d2038d6413f1c6c91b40737fa64048ea0421fc0a251b0ff1b485b8a08b914` |
| hashset `reference/` (directory `HEAD:reference`) | `b25d8ae7fa3892d96751bdf532f2791b3883130fb3db3c8f8cb3015511d5f227` |
| hashset top directory `90c9a260…` | `a75286bbdeff34599303a1850e756ec9e23b303ff5fe13b6fc10472f8467687f` |
| hashset first commit `3e7178d6…` (plain) | `47d94ceee1cbe424964472bd63f308eab32b258a60298c6689a04f5d390b7d7a` |
| hashset commit `d2aeab29…` (plain) | `30b952d287b8b8eeb79c39a64db7260ab7fed2d1895e5a24c1cbe9396515f9e6` |
| the example commit in section 2 (539 bytes, Git ID `3e012b28160bc9d0c48beb5ac5c0e428d10ec8b0`) | `54538914c22fce7eb013e773fe5914d5d1fca0bb3058933aff2f3f57d82ec855` |

## 7. Why two different histories cannot share a digest

Assume nobody can find two different (context, input) pairs with the same
BLAKE3 output.

* **Files.** Same digest, same bytes.
* **Directories.** The input can be split back into its entries in only one
  way: a mode contains no space, a name contains no zero byte, and the mode
  fixes the length of the child field (20 or 32 bytes). So the same digest
  means the same list of modes, names and children. Each child that is a
  file or directory is then the same, by the same argument one level down.
* **Commits that carry lines.** Same digest, same bytes, so the same
  directory digest and parent digests.
* **Plain commits.** The input begins with fields of known length and ends
  with the commit's bytes, so it too splits in only one way.
* **Across kinds.** The context strings differ, so a digest of one kind
  never equals a digest of another.

So a digest of a commit fixes every byte of every file, every name and mode,
every commit message, and the whole shape of the history behind it.

## 8. What it does not do

* **It detects; it does not repair or prevent.** Git still finds objects by
  SHA-1. A reader learns that something differs, not what the right bytes
  were.
* **The lines are evidence of what the writer's copy held.** A reader that
  only follows a branch name, and accepts commits without lines, learns
  nothing when the lines are missing. Section 5's given digest and its
  setting for "no evidence" are the two answers to that.
* **Submodules.** The digest covers the pointer to a submodule, not the
  submodule's contents.
* **Commits made by other tools have no lines.** `git rebase` and
  `git cherry-pick` drop them (tested). A forge's squash and rebase merges
  make new commits on the server and are expected to drop them too (not
  tested on a forge). Such commits are plain, and the next commit that
  carries lines covers them.
* **Only `blake3` is defined.** SHA-256 has no key-derivation mode, so a
  `sha256` line would need its own construction, not yet written.

## 9. Cost

Measured with these rules on the whole history of the Linux kernel
(1,507,472 commits, 7.3 million directories, 3.2 million file versions,
141 GB of file contents) on an Apple M6 with 12 cores and 16 GB:

| | Total |
|---|---|
| blake3-servil branch `next` (a278fa63), its streaming Pipeline, 8 Git processes reading files | 1 min 18 s |
| the same with 1 Git process reading files | 2 min 49 s |
| for comparison: Git alone reading every object with one process, no hashing | 2 min 0 s |

In the fastest run: listing the objects 5 s, files 22 s, directories 50 s,
commits 2 s. Git alone takes 23 s to read the files with 8 processes and
30 s to read the directories with one, so hashing the files added nothing
measurable. Every commit was treated as a plain commit.

This is the one-time cost of the first commit that carries lines in a
repository of that size; a repository of a few thousand commits takes a
fraction of a second. After that, a commit hashes only what changed.

Two cautions. The measuring program held up to 8.3 GB of directories in
memory while they waited for their subdirectories; it needs a better
reading order before it suits a smaller machine. And branch `next` is
unreleased code. An earlier, simpler program on release 0.9.1 (one Git
process, a temporary file) took 6 min 19 s to 6 min 48 s.

For scale: the bench-hashes project publishes, for the same machine model
and a collection shaped like Git's objects, 0.18 ns per byte for
blake3-servil on one thread and 1.11 ns per byte for SHA-1 with collision
detection, the kind of SHA-1 Git uses.

## 10. Not decided yet

* The final context strings.
* Whether and how tags, tag names and branch names carry digests.
* A line in the commit message that survives a forge's squash or rebase
  merge.
* The construction for a `sha256` line.
* The tool's commands and the name of the "no evidence" setting.
* The prototype (`git-b3` 0.1.0) still implements the previous draft: other
  line names, a label prefix where this draft uses context strings, and a
  length field in the plain-commit rule.
