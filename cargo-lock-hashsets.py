#!/usr/bin/env python3
"""Hashsets for the crates in Cargo.lock, kept in Cargo.lock's own [metadata] table.

  cargo-lock-hashsets.py            check each .crate file cargo fetched against its hashset
  cargo-lock-hashsets.py --write    compute the hashsets and write them into Cargo.lock

Each package from a registry gets one entry, named the way old Cargo.lock files named checksums:

  "hashset <name> <version> (<source>)" = "blake3-<base32>.sha256-<base32>"

Both digests are of the package's .crate file as cargo downloaded it. Cargo keeps [metadata]
entries it does not know through every rewrite of Cargo.lock, and checks none of them: it checks
only `checksum`, the same SHA-256 in hex. Run `cargo fetch --locked` first. Needs `b3sum`.
"""
import base64, glob, hashlib, os, subprocess, sys, tomllib

LOCK = "Cargo.lock"

def b32(raw):
    return base64.b32encode(raw).decode().rstrip("=").lower()

def crate_file(name, version):
    home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    hits = glob.glob(os.path.join(home, "registry", "cache", "*", f"{name}-{version}.crate"))
    if not hits:
        sys.exit(f"{name} {version}: no .crate file under {home}/registry/cache (run `cargo fetch --locked`)")
    return hits[0]

def digests(path):
    b3 = subprocess.run(["b3sum", "--no-names", path], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    return bytes.fromhex(b3), hashlib.sha256(open(path, "rb").read()).digest()

lock_text = open(LOCK).read()
lock = tomllib.loads(lock_text)
want = {}
for p in lock["package"]:
    source = p.get("source", "")
    if not source.startswith("registry+"):
        continue
    blake3, sha256 = digests(crate_file(p["name"], p["version"]))
    if sha256.hex() != p["checksum"]:
        sys.exit(f"{p['name']} {p['version']}: the .crate file does not match Cargo.lock's checksum")
    want[f"hashset {p['name']} {p['version']} ({source})"] = f"blake3-{b32(blake3)}.sha256-{b32(sha256)}"

metadata = lock.get("metadata", {})
if sys.argv[1:] == ["--write"]:
    kept = {k: v for k, v in metadata.items() if not k.startswith("hashset ")}
    packages = lock_text.split("\n[metadata]\n")[0].rstrip("\n") + "\n"
    lines = "".join(f'"{k}" = "{v}"\n' for k, v in sorted({**kept, **want}.items()))
    open(LOCK, "w").write(packages + "\n[metadata]\n" + lines)
    print(f"wrote {len(want)} hashsets to {LOCK}")
elif sys.argv[1:]:
    sys.exit(__doc__)
else:
    have = {k: v for k, v in metadata.items() if k.startswith("hashset ")}
    wrong = sorted(k for k in want.keys() | have.keys() if want.get(k) != have.get(k))
    for k in wrong:
        print("missing, stale or wrong:", k)
    if wrong:
        sys.exit(1)
    print(f"{len(want)} crates match their hashsets in {LOCK}")
