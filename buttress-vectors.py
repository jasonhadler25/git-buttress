#!/usr/bin/env python3
"""Reference vector calculator for well-formed, complete, acyclic SHA-1 Git fixtures.

Uses only stock `git` (with `--no-replace-objects` and `GIT_NO_LAZY_FETCH=1`) and `b3sum`.
Read-only: never writes objects or refs to the repository.
Usage: buttress-vectors.py <commit-ish>
"""
import functools, os, re, struct, subprocess, sys

sys.setrecursionlimit(1_000_000)

APP = "git-buttress 2026-11-20 "
CTX_FILE, CTX_DIR = APP + "file", APP + "directory"
CTX_COMMIT, CTX_PLAIN = APP + "commit", APP + "plain commit"
HEX40 = re.compile(rb"^[0-9a-f]{40}$")
HEX64 = re.compile(rb"^[0-9a-f]{64}$")
ALG_RE = re.compile(rb"^[a-z][a-z0-9-]*$")
ENV = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0"}

def git(*a, data=None):
    return subprocess.run(["git", "--no-replace-objects", *a], input=data, stdout=subprocess.PIPE, check=True, env=ENV).stdout

def read_typed(expect_kind, oid):
    kind = git("cat-file", "-t", oid).strip().decode()
    if kind != expect_kind:
        raise ValueError(f"expected {expect_kind} for {oid}, got {kind}")
    return git("cat-file", expect_kind, oid)

def dk(ctx, data):
    out = subprocess.run(["b3sum", "--derive-key", ctx, "--no-names"], input=data, stdout=subprocess.PIPE, check=True).stdout
    return bytes.fromhex(out.decode().strip())

@functools.cache
def file_digest(oid):
    return dk(CTX_FILE, read_typed("blob", oid))

@functools.cache
def dir_digest(oid):
    raw, i, parts, seen = read_typed("tree", oid), 0, [], set()
    while i < len(raw):
        sp = raw.index(b" ", i); nul = raw.index(0, sp)
        if nul + 21 > len(raw): raise ValueError("truncated tree entry")
        mode, name, child = raw[i:sp], raw[sp + 1:nul], raw[nul + 1:nul + 21]
        i = nul + 21
        if not (1 <= len(mode) <= 7 and all(48 <= c <= 55 for c in mode)): raise ValueError("bad mode")
        kind = int(mode, 8)
        if kind not in (0o040000, 0o100644, 0o100664, 0o100755, 0o120000, 0o160000): raise ValueError("unsupported mode")
        if not name or name in (b".", b"..") or name.lower() == b".git" or b"/" in name or name in seen:
            raise ValueError("bad or duplicate tree entry name")
        seen.add(name)
        if kind == 0o040000: d = dir_digest(child.hex())
        elif kind == 0o160000: d = child
        else: d = file_digest(child.hex())
        parts.append(mode + b" " + name + b"\0" + d)
    return dk(CTX_DIR, b"".join(parts))

def split_headers_body(raw):
    if raw.startswith(b"\n"): return b"", raw[1:]
    pos = raw.find(b"\n\n")
    if pos != -1: return raw[:pos], raw[pos + 2:]
    return (raw[:-1] if raw.endswith(b"\n") else raw), b""

def parse_commit_links(raw):
    hdr, _ = split_headers_body(raw)
    if b"\0" in hdr or not hdr: raise ValueError("invalid commit header")
    lines = hdr.split(b"\n")
    if not lines[0].startswith(b"tree ") or not HEX40.match(lines[0][5:]): raise ValueError("missing leading tree")
    tree = lines[0][5:].decode()
    idx, parents = 1, []
    while idx < len(lines) and lines[idx].startswith(b"parent "):
        p = lines[idx][7:]
        if not HEX40.match(p): raise ValueError("bad parent oid")
        parents.append(p.decode()); idx += 1
    bt, bp, prev_single = [], [], False
    for line in lines[idx:]:
        if line.startswith(b" "):
            if prev_single: raise ValueError("continuation on single-line buttress header")
            continue
        prev_single = False
        if line.startswith((b"tree ", b"parent ")) or line in (b"tree", b"parent", b"buttress-tree", b"buttress-parent"):
            raise ValueError("malformed header")
        if line.startswith(b"buttress-tree "):
            prev_single = True; parts = line[14:].split(b" ")
            if not parts or not ALG_RE.match(parts[0]): raise ValueError("bad alg")
            if parts[0] == b"blake3":
                if len(parts) != 3 or not HEX40.match(parts[1]) or not HEX64.match(parts[2]): raise ValueError("bad buttress-tree")
                bt.append((parts[1].decode(), parts[2].decode()))
        elif line.startswith(b"buttress-parent "):
            prev_single = True; parts = line[16:].split(b" ")
            if not parts or not ALG_RE.match(parts[0]): raise ValueError("bad alg")
            if parts[0] == b"blake3":
                if len(parts) != 2 or not HEX64.match(parts[1]): raise ValueError("bad buttress-parent")
                bp.append(parts[1].decode())
    if len(bt) > 1 or (len(bt) == 0 and bp): raise ValueError("malformed buttress headers")
    sealed = len(bt) == 1 and bt[0][0] == tree
    if sealed and len(bp) != len(parents): raise ValueError("wrong buttress-parent count")
    return tree, parents, sealed

@functools.cache
def commit_digest(oid):
    raw = read_typed("commit", oid)
    tree, parents, sealed = parse_commit_links(raw)
    if sealed:
        return dk(CTX_COMMIT, raw)
    return dk(CTX_PLAIN, dir_digest(tree) + struct.pack("<I", len(parents))
              + b"".join(commit_digest(p) for p in parents) + raw)

if __name__ == "__main__":
    fmt = git("rev-parse", "--show-object-format").decode().strip()
    if fmt != "sha1": raise SystemExit(f"unsupported object format: {fmt}")
    c = git("rev-parse", "--verify", "--end-of-options", sys.argv[1] + "^{commit}").decode().strip()
    raw = read_typed("commit", c)
    tree, parents, sealed = parse_commit_links(raw)
    print("empty file     ", dk(CTX_FILE, b"").hex())
    print("empty directory", dk(CTX_DIR, b"").hex())
    print("commit         ", c, "(sealed)" if sealed else "(plain)")
    print("  directory    ", tree, dir_digest(tree).hex())
    for p in parents: print("  parent       ", p, commit_digest(p).hex())
    print("  digest       ", commit_digest(c).hex())
