#!/usr/bin/env python3
"""Compute git buttress draft digests with stock `git` and `b3sum` only.

Read-only: it never writes to the repository it is run in.
Usage: buttress-vectors.py <commit-ish>   (run inside a Git repository)
"""
import functools, struct, subprocess, sys

sys.setrecursionlimit(1_000_000)

APP = "git-buttress 2026-11-20 "
CTX_FILE, CTX_DIR = APP + "file", APP + "directory"
CTX_COMMIT, CTX_PLAIN = APP + "commit", APP + "plain commit"

def git(*a, data=None):
    return subprocess.run(["git", *a], input=data, stdout=subprocess.PIPE, check=True).stdout

def dk(ctx, data):
    out = subprocess.run(["b3sum", "--derive-key", ctx, "--no-names"], input=data, stdout=subprocess.PIPE, check=True).stdout
    return bytes.fromhex(out.decode().strip())

@functools.cache
def file_digest(oid):
    return dk(CTX_FILE, git("cat-file", "blob", oid))

@functools.cache
def dir_digest(oid):
    raw, i, buf = git("cat-file", "tree", oid), 0, b""
    while i < len(raw):
        sp = raw.index(b" ", i); nul = raw.index(0, sp)
        mode, name, child = raw[i:sp], raw[sp + 1:nul], raw[nul + 1:nul + 21]
        i = nul + 21
        kind = int(mode, 8)
        if kind == 0o040000: d = dir_digest(child.hex())
        elif kind == 0o160000: d = child                      # submodule: the 20-byte ID as stored
        else: d = file_digest(child.hex())
        buf += mode + b" " + name + b"\0" + d
    return dk(CTX_DIR, buf)

def links(raw):
    head = raw.split(b"\n\n", 1)[0].split(b"\n")
    tree = [l[5:].decode() for l in head if l.startswith(b"tree ")][0]
    parents = [l[7:].decode() for l in head if l.startswith(b"parent ")]
    bt = [l.split(b" ") for l in head if l.startswith(b"buttress-tree blake3 ")]
    bp = [l.split(b" ") for l in head if l.startswith(b"buttress-parent blake3 ")]
    return tree, parents, bt, bp

@functools.cache
def commit_digest(oid):
    raw = git("cat-file", "commit", oid)
    tree, parents, bt, bp = links(raw)
    if len(bt) == 1 and bt[0][2].decode() == tree:           # carries current lines
        assert len(bp) == len(parents), "malformed"
        return dk(CTX_COMMIT, raw)
    return dk(CTX_PLAIN, dir_digest(tree) + struct.pack("<I", len(parents))
              + b"".join(commit_digest(p) for p in parents) + raw)

if __name__ == "__main__":
    c = git("rev-parse", sys.argv[1] + "^{commit}").decode().strip()
    raw = git("cat-file", "commit", c)
    tree, parents, _, _ = links(raw)
    print("empty file     ", dk(CTX_FILE, b"").hex())
    print("empty directory", dk(CTX_DIR, b"").hex())
    print("commit         ", c)
    print("  directory    ", tree, dir_digest(tree).hex())
    for p in parents: print("  parent       ", p, commit_digest(p).hex())
    print("  digest       ", commit_digest(c).hex())
    head, body = raw.split(b"\n\n", 1)
    lines = [f"buttress-tree blake3 {tree} {dir_digest(tree).hex()}"] + [f"buttress-parent blake3 {commit_digest(p).hex()}" for p in parents]
    new = head + b"\n" + "\n".join(lines).encode() + b"\n\n" + body
    print("--- the same commit, had it been made with buttress lines ---")
    sys.stdout.write(new.decode(errors="replace"))
    print("--- its Git ID:", git("hash-object", "-t", "commit", "--stdin", data=new).decode().strip(), " size:", len(new))
    print("--- its digest:", dk(CTX_COMMIT, new).hex())
