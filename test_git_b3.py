"""Comprehensive test suite for git-b3, including simulated SHA-1 collision attacks."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent / "git-b3"


def _load_git_b3():
    loader = importlib.machinery.SourceFileLoader("git_b3", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader("git_b3", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["git_b3"] = mod
    loader.exec_module(mod)
    return mod


gb = _load_git_b3()


def run_cmd(cmd: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def run_b3(args: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd([sys.executable, str(SCRIPT_PATH), *args], cwd=cwd, check=check)


class TestPureBlake3(unittest.TestCase):
    def test_known_domain_vectors(self) -> None:
        self.assertEqual(
            gb.blake3_digest(b"git-b3-blob-v1\x00").hex(),
            "30ffb0f8445581c9d2f5243d9c4162ede4c25db813b5dd61e970fde0289fdcfa",
        )
        self.assertEqual(
            gb.blake3_digest(b"git-b3-tree-v1\x00").hex(),
            "3eea7e58fa5554c1eb42888e1b6bd14c205be9bbe6687a0a105f69a6fa9fd1f6",
        )

    def test_matches_b3sum_if_installed(self) -> None:
        if shutil.which("b3sum") is None:
            self.skipTest("b3sum not installed")
        for n in (0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3073, 10000):
            data = bytes((i * 131 + 7) & 0xFF for i in range(n))
            ref = subprocess.run(
                ["b3sum", "--no-names"], input=data, stdout=subprocess.PIPE, check=True
            ).stdout.decode().strip()
            h = gb.PureBlake3Hasher()
            h.update(data[: n // 2])
            h.update(data[n // 2 :])
            self.assertEqual(h.digest().hex(), ref, f"mismatch at len={n}")


class TestGitB3EndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self._td.name) / "repo"
        self.repo_dir.mkdir()
        run_cmd(["git", "init", "-b", "main"], self.repo_dir)
        run_cmd(["git", "config", "user.name", "Alice"], self.repo_dir)
        run_cmd(["git", "config", "user.email", "alice@example.com"], self.repo_dir)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _setup_ssh_signing(self) -> Path:
        key_path = Path(self._td.name) / "id_ed25519"
        allowed = Path(self._td.name) / "allowed_signers"
        run_cmd(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], self.repo_dir)
        pub = Path(f"{key_path}.pub").read_text(encoding="utf-8").strip()
        allowed.write_text(f"alice@example.com {pub}\n", encoding="utf-8")
        run_cmd(["git", "config", "gpg.format", "ssh"], self.repo_dir)
        run_cmd(["git", "config", "user.signingkey", str(key_path)], self.repo_dir)
        run_cmd(["git", "config", "gpg.ssh.allowedSignersFile", str(allowed)], self.repo_dir)
        return key_path

    def test_mixed_legacy_and_sealed_history_with_merge_and_fsck(self) -> None:
        # 1. Two legacy commits made with stock unmodified Git
        (self.repo_dir / "a.txt").write_text("legacy 1\n", encoding="utf-8")
        run_cmd(["git", "add", "a.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Legacy commit 1"], self.repo_dir)

        (self.repo_dir / "sub").mkdir()
        (self.repo_dir / "sub" / "b.txt").write_text("legacy 2\n", encoding="utf-8")
        run_cmd(["git", "add", "sub/b.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Legacy commit 2"], self.repo_dir)

        # Unsealed HEAD must fail verify (fail closed)
        res_fail = run_b3(["verify"], self.repo_dir, check=False)
        self.assertNotEqual(res_fail.returncode, 0)

        # 2. First git-b3 commit retroactively seals all legacy history!
        (self.repo_dir / "c.txt").write_text("sealed 1\n", encoding="utf-8")
        run_cmd(["git", "add", "c.txt"], self.repo_dir)
        run_b3(["commit", "-m", "First sealed commit"], self.repo_dir)

        # 3. Teammate on stock Git commits on top
        (self.repo_dir / "d.txt").write_text("stock teammate\n", encoding="utf-8")
        run_cmd(["git", "add", "d.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Stock teammate commit"], self.repo_dir)

        # 4. Second git-b3 commit seals the teammate commit and links into sealed #1
        (self.repo_dir / "e.txt").write_text("sealed 2\n", encoding="utf-8")
        run_cmd(["git", "add", "e.txt"], self.repo_dir)
        run_b3(["commit", "-m", "Second sealed commit"], self.repo_dir)

        # Stock git fsck --full --strict must pass with zero errors
        run_cmd(["git", "fsck", "--full", "--strict", "--dangling"], self.repo_dir)

        # Verify succeeds and reports 2 sealed + 3 legacy commits
        repo = gb.GitRepo(self.repo_dir)
        try:
            vr = gb.verify_repo(repo, "HEAD")
            self.assertEqual(vr.sealed_commits, 2)
            self.assertEqual(vr.legacy_commits, 3)
        finally:
            repo.close()

    def test_ssh_signed_commit_and_signed_tag(self) -> None:
        self._setup_ssh_signing()
        (self.repo_dir / "hello.txt").write_text("signed content\n", encoding="utf-8")
        run_cmd(["git", "add", "hello.txt"], self.repo_dir)
        run_b3(["commit", "-S", "-m", "Signed sealed commit"], self.repo_dir)

        # Stock git verify-commit & fsck pass!
        run_cmd(["git", "fsck", "--full", "--strict"], self.repo_dir)
        run_cmd(["git", "verify-commit", "HEAD"], self.repo_dir)

        # git-b3 verify --require-signature passes!
        run_b3(["verify", "HEAD", "--require-signature"], self.repo_dir)

        # Create signed annotated tag with Blake3-Object trailer
        run_b3(["tag", "-s", "v1.0.0", "-m", "Release v1.0.0"], self.repo_dir)
        run_cmd(["git", "fsck", "--full", "--strict"], self.repo_dir)
        run_cmd(["git", "verify-tag", "v1.0.0"], self.repo_dir)
        run_b3(["verify", "v1.0.0", "--require-signature"], self.repo_dir)

    def test_stock_amend_stale_header_detection(self) -> None:
        (self.repo_dir / "f.txt").write_text("v1\n", encoding="utf-8")
        run_cmd(["git", "add", "f.txt"], self.repo_dir)
        run_b3(["commit", "-m", "Sealed v1"], self.repo_dir)

        # Stock `git commit --amend -m` (message-only): tree & parents unchanged -> stays sealed!
        run_cmd(["git", "commit", "--amend", "-m", "Sealed v1 (typo fix)"], self.repo_dir)
        repo = gb.GitRepo(self.repo_dir)
        try:
            pc = gb.Blake3Calculator(repo).get_parsed_commit(repo.rev_parse("HEAD"))
            self.assertEqual(pc.status, "sealed")
            gb.verify_repo(repo, "HEAD")
        finally:
            repo.close()

        # Stock `git commit --amend` modifying a file -> stale header detected, treated as legacy!
        (self.repo_dir / "f.txt").write_text("v2 amended by stock git\n", encoding="utf-8")
        run_cmd(["git", "add", "f.txt"], self.repo_dir)
        run_cmd(["git", "commit", "--amend", "-m", "Amended v2"], self.repo_dir)
        repo = gb.GitRepo(self.repo_dir)
        try:
            pc = gb.Blake3Calculator(repo).get_parsed_commit(repo.rev_parse("HEAD"))
            self.assertEqual(pc.status, "stale")
        finally:
            repo.close()

        # Next git-b3 commit seals the stale-amended commit cleanly!
        (self.repo_dir / "g.txt").write_text("v3\n", encoding="utf-8")
        run_cmd(["git", "add", "g.txt"], self.repo_dir)
        run_b3(["commit", "-m", "Reseal after stock amend"], self.repo_dir)
        run_b3(["verify", "HEAD"], self.repo_dir)

    def test_post_commit_hook_seals_plain_git_commit(self) -> None:
        run_b3(["install-hook"], self.repo_dir)
        (self.repo_dir / "auto.txt").write_text("auto-sealed\n", encoding="utf-8")
        run_cmd(["git", "add", "auto.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Plain git commit"], self.repo_dir)

        run_cmd(["git", "fsck", "--full", "--strict"], self.repo_dir)
        run_b3(["verify", "HEAD"], self.repo_dir)

    def test_shallow_clone_depth_1_verifies_in_o1(self) -> None:
        (self.repo_dir / "a.txt").write_text("one\n", encoding="utf-8")
        run_cmd(["git", "add", "a.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Legacy root"], self.repo_dir)

        (self.repo_dir / "b.txt").write_text("two\n", encoding="utf-8")
        run_cmd(["git", "add", "b.txt"], self.repo_dir)
        run_b3(["commit", "-m", "Sealed tip"], self.repo_dir)
        tip_b3 = run_b3(["id", "HEAD"], self.repo_dir).stdout.strip()

        shallow_dir = Path(self._td.name) / "shallow"
        run_cmd(
            ["git", "clone", "--depth=1", f"file://{self.repo_dir}", str(shallow_dir)],
            self.repo_dir,
        )
        run_b3(["verify", "HEAD", "--expect", tip_b3], shallow_dir)
        # With --no-shallow it must fail
        res_strict = run_b3(["verify", "HEAD", "--no-shallow"], shallow_dir, check=False)
        self.assertNotEqual(res_strict.returncode, 0)

    def test_simulated_sha1_second_preimage_attacks(self) -> None:
        """Simulate an attacker with a total SHA-1 preimage oracle substituting objects."""
        # Build history: legacy_root -> sealed_1 -> sealed_2
        (self.repo_dir / "legacy.txt").write_text("trusted legacy file\n", encoding="utf-8")
        run_cmd(["git", "add", "legacy.txt"], self.repo_dir)
        run_cmd(["git", "commit", "-m", "Legacy root"], self.repo_dir)
        legacy_blob_sha1 = run_cmd(["git", "rev-parse", "HEAD:legacy.txt"], self.repo_dir).stdout.strip()

        # Remove legacy.txt in sealed_1 so legacy_blob_sha1 ONLY exists in pre-upgrade history!
        run_cmd(["git", "rm", "legacy.txt"], self.repo_dir)
        (self.repo_dir / "app.py").write_text("print('safe')\n", encoding="utf-8")
        run_cmd(["git", "add", "app.py"], self.repo_dir)
        run_b3(["commit", "-m", "Sealed 1"], self.repo_dir)
        sealed1_sha1 = run_cmd(["git", "rev-parse", "HEAD"], self.repo_dir).stdout.strip()
        sealed1_tree_sha1 = run_cmd(["git", "rev-parse", "HEAD^{tree}"], self.repo_dir).stdout.strip()

        (self.repo_dir / "tip.txt").write_text("trusted tip\n", encoding="utf-8")
        run_cmd(["git", "add", "tip.txt"], self.repo_dir)
        run_b3(["commit", "-m", "Sealed 2"], self.repo_dir)
        tip_sha1 = run_cmd(["git", "rev-parse", "HEAD"], self.repo_dir).stdout.strip()
        tip_blob_sha1 = run_cmd(["git", "rev-parse", "HEAD:tip.txt"], self.repo_dir).stdout.strip()
        tip_b3 = run_b3(["id", "HEAD"], self.repo_dir).stdout.strip()

        # Helper to run verify_repo with an adversarial object_reader that substitutes
        # one object's bytes while keeping its exact SHA-1 OID (simulating SHA-1 preimage!).
        def verify_with_override(target_oid: str, fake_type: str, fake_bytes: bytes) -> None:
            real_repo = gb.GitRepo(self.repo_dir)
            try:
                def evil_reader(oid: str) -> tuple[str, bytes]:
                    if oid == target_oid:
                        return fake_type, fake_bytes
                    return real_repo.read_object(oid)

                evil_repo = gb.GitRepo(self.repo_dir, object_reader=evil_reader)
                gb.verify_repo(evil_repo, tip_sha1, expect_b3_hex=tip_b3)
            finally:
                real_repo.close()

        # Attack 1: Evil blob in tip commit's tree (same SHA-1)
        with self.assertRaisesRegex(gb.VerificationError, "TREE CORRUPTION"):
            verify_with_override(tip_blob_sha1, "blob", b"EVIL BACKDOOR\n")

        # Attack 2: Evil blob in 10-year-old legacy pre-upgrade commit (same SHA-1)
        with self.assertRaisesRegex(gb.VerificationError, "HISTORY CORRUPTION"):
            verify_with_override(legacy_blob_sha1, "blob", b"EVIL LEGACY BACKDOOR\n")

        # Attack 3: Flipped executable mode (100644 -> 100755) in sealed_1's tree
        real = gb.GitRepo(self.repo_dir)
        try:
            _, s1_tree_raw = real.read_object(sealed1_tree_sha1)
            _, s1_commit_raw = real.read_object(sealed1_sha1)
        finally:
            real.close()
        evil_tree = s1_tree_raw.replace(b"100644 app.py\x00", b"100755 app.py\x00", 1)
        self.assertNotEqual(evil_tree, s1_tree_raw)
        with self.assertRaisesRegex(gb.VerificationError, "TREE CORRUPTION"):
            verify_with_override(sealed1_tree_sha1, "tree", evil_tree)

        # Attack 4: Forged commit message in ancestor commit sealed_1 (same SHA-1)
        evil_commit = s1_commit_raw.replace(b"Sealed 1", b"Forged 1")
        with self.assertRaisesRegex(gb.VerificationError, "HISTORY CORRUPTION"):
            verify_with_override(sealed1_sha1, "commit", evil_commit)

        # Attack 5: Attacker strips blake3-tree from ancestor sealed_1 to downgrade it
        evil_stripped = b"\n".join(
            l for l in s1_commit_raw.split(b"\n") if not l.startswith(b"blake3-")
        )
        with self.assertRaisesRegex(gb.VerificationError, "HISTORY CORRUPTION"):
            verify_with_override(sealed1_sha1, "commit", evil_stripped)

        # Attack 6: Attacker replaces tagged commit with colliding commit (same SHA-1)
        run_b3(["tag", "v1", "-m", "Release 1"], self.repo_dir)
        real = gb.GitRepo(self.repo_dir)
        try:
            _, tip_raw = real.read_object(tip_sha1)
        finally:
            real.close()
        evil_tip = tip_raw.replace(b"Sealed 2", b"Evil tip")
        with self.assertRaisesRegex(gb.VerificationError, "BLAKE3 mismatch"):
            verify_with_override(tip_sha1, "commit", evil_tip)


if __name__ == "__main__":
    unittest.main()
