import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "conformance" / "check-contract-change.py"


class CheckContractChangeTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="carrick-contract-test-")
        self.repo = Path(self.tmp_dir)

        # Initialize git repo
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Agent"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "agent@carrick.test"], cwd=self.repo, check=True)

        # Set up minimal registry
        contracts_dir = self.repo / "conformance-contracts" / "contracts"
        contracts_dir.mkdir(parents=True)
        shutil.copy(
            REPO_ROOT / "conformance-contracts" / "contracts" / "futex-contention.toml",
            contracts_dir / "futex-contention.toml",
        )
        shutil.copy(
            REPO_ROOT / "conformance-contracts" / "surfaces.toml",
            self.repo / "conformance-contracts" / "surfaces.toml",
        )

        # Create the surface files referenced in surfaces.toml
        self.guest_file = self.repo / "crates" / "carrick-kernel" / "src" / "dispatch" / "futex.rs"
        self.guest_file.parent.mkdir(parents=True, exist_ok=True)
        self.guest_file.write_text("// initial futex implementation\n", encoding="utf-8")

        self.vm_free_binding_file = (
            self.repo / "crates" / "carrick-kernel-example" / "tests" / "semantics" / "futex_contention.rs"
        )
        self.vm_free_binding_file.parent.mkdir(parents=True, exist_ok=True)
        self.vm_free_binding_file.write_text("// vm_free binding\n", encoding="utf-8")

        # Initial commit (base)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=self.repo, check=True)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def run_check(self, base_sha=None, head_sha=None):
        base = base_sha or self.base_sha
        head = head_sha or "HEAD"
        cmd = [sys.executable, str(SCRIPT_PATH), "--root", str(self.repo), "--base", base, "--head", head]
        return subprocess.run(cmd, cwd=self.repo, capture_output=True, text=True)

    def test_1_modified_guest_file_without_evidence_exits_1(self):
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify guest file"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("crates/carrick-kernel/src/dispatch/futex.rs", res.stderr)
        self.assertIn("kernel.futex.contention", res.stderr)

    def test_2_modified_guest_file_plus_registered_binding_exits_0(self):
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        self.vm_free_binding_file.write_text("// modified vm_free binding\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify guest and binding"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_3_byte_identical_rename_detected_with_M_exits_0(self):
        new_path = self.guest_file.parent / "futex_renamed.rs"
        subprocess.run(["git", "mv", str(self.guest_file), str(new_path)], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "rename guest file byte-identical"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_4_renamed_and_edited_guest_file_exits_1(self):
        new_path = self.guest_file.parent / "futex_renamed.rs"
        subprocess.run(["git", "mv", str(self.guest_file), str(new_path)], cwd=self.repo, check=True)
        new_path.write_text("// renamed and edited content\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "rename and edit guest file"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)

    def test_5_new_unclassified_path_under_crates_exits_1(self):
        new_unclassified = self.repo / "crates" / "unclassified" / "new_file.rs"
        new_unclassified.parent.mkdir(parents=True, exist_ok=True)
        new_unclassified.write_text("// new unclassified\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "add unclassified file"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("unclassified", res.stderr)

    def test_6_broad_exemption_glob_exits_1(self):
        self.guest_file.write_text("// modified futex\n", encoding="utf-8")
        head_sha = "2" * 40
        exemption = f"""schema = "carrick.conformance-exemption.v1"
base = "{self.base_sha}"
head = "{head_sha}"
paths = ["crates/carrick-kernel/*"]
contracts = ["kernel.futex.contention"]
rationale = "This rationale is long enough to satisfy forty characters requirement."
"""
        exempt_dir = self.repo / "docs" / "conformance-exemptions"
        exempt_dir.mkdir(parents=True, exist_ok=True)
        (exempt_dir / "exemption.toml").write_text(exemption, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify with glob exemption"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("glob", res.stderr.lower())

    def test_7_exemption_missing_base_head_revisions_exits_1(self):
        self.guest_file.write_text("// modified futex\n", encoding="utf-8")
        exemption = """schema = "carrick.conformance-exemption.v1"
base = "abc"
paths = ["crates/carrick-kernel/src/dispatch/futex.rs"]
contracts = ["kernel.futex.contention"]
rationale = "This rationale is long enough to satisfy forty characters requirement."
"""
        exempt_dir = self.repo / "docs" / "conformance-exemptions"
        exempt_dir.mkdir(parents=True, exist_ok=True)
        (exempt_dir / "exemption.toml").write_text(exemption, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify with bad exemption revisions"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)

    def test_8_exemption_saying_only_performance_out_of_scope_exits_1(self):
        self.guest_file.write_text("// modified futex\n", encoding="utf-8")
        head_sha = "2" * 40
        exemption = f"""schema = "carrick.conformance-exemption.v1"
base = "{self.base_sha}"
head = "{head_sha}"
paths = ["crates/carrick-kernel/src/dispatch/futex.rs"]
contracts = ["kernel.futex.contention"]
rationale = "performance out of scope"
"""
        exempt_dir = self.repo / "docs" / "conformance-exemptions"
        exempt_dir.mkdir(parents=True, exist_ok=True)
        (exempt_dir / "exemption.toml").write_text(exemption, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify with bad rationale"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)

    def test_9_exact_reviewed_exemption_for_classified_paths_exits_0(self):
        self.guest_file.write_text("// modified futex\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify guest file"], cwd=self.repo, check=True)
        head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        exemption = f"""schema = "carrick.conformance-exemption.v1"
base = "{self.base_sha}"
head = "{head_sha}"
paths = ["crates/carrick-kernel/src/dispatch/futex.rs"]
contracts = ["kernel.futex.contention"]
rationale = "Byte-preserving ownership move; contract behavior and work units are unchanged."
"""
        exempt_dir = self.repo / "docs" / "conformance-exemptions"
        exempt_dir.mkdir(parents=True, exist_ok=True)
        (exempt_dir / "exemption.toml").write_text(exemption, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "--amend", "-m", "modify guest with valid exemption"], cwd=self.repo, check=True)
        new_head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        # Update exemption with amended head_sha
        (exempt_dir / "exemption.toml").write_text(
            exemption.replace(head_sha, new_head_sha), encoding="utf-8"
        )
        subprocess.run(["git", "commit", "-am", "update exemption with exact head sha"], cwd=self.repo, check=True)
        final_head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        (exempt_dir / "exemption.toml").write_text(
            exemption.replace(head_sha, final_head_sha), encoding="utf-8"
        )
        subprocess.run(["git", "commit", "-am", "final exemption head"], cwd=self.repo, check=True)
        active_head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        (exempt_dir / "exemption.toml").write_text(
            exemption.replace(head_sha, active_head_sha), encoding="utf-8"
        )
        subprocess.run(["git", "commit", "--amend", "--no-edit"], cwd=self.repo, check=True)
        committed_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        res = self.run_check(head_sha=committed_head)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
