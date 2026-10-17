import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
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

        kernel_cargo = self.repo / "crates" / "carrick-kernel" / "Cargo.toml"
        kernel_cargo.write_text(
            '[package]\nname = "carrick-kernel"\nversion = "0.1.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (self.repo / "crates" / "carrick-kernel" / "src" / "lib.rs").write_text(
            "pub mod dispatch;\n", encoding="utf-8"
        )
        (self.repo / "crates" / "carrick-kernel" / "src" / "dispatch" / "mod.rs").write_text(
            "pub mod futex;\n", encoding="utf-8"
        )

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

    def use_single_contract_surface(self):
        (self.repo / "conformance-contracts" / "surfaces.toml").write_text(
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/futex.rs"\n'
            'contracts = ["kernel.futex.contention"]\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "conformance-contracts/surfaces.toml"], cwd=self.repo, check=True)
        diff_res = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=self.repo)
        if diff_res.returncode != 0:
            subprocess.run(["git", "commit", "-m", "use single contract surface"], cwd=self.repo, check=True)
            self.base_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
            ).stdout.strip()

    def commit_reviewed_exemption(self):
        self.use_single_contract_surface()
        self.guest_file.write_text("// reviewed documentation change\n")
        subprocess.run(["git", "commit", "-am", "review source change"], cwd=self.repo, check=True)
        reviewed_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        directory = self.repo / "docs" / "conformance-exemptions"
        directory.mkdir(parents=True)
        (directory / "reviewed.toml").write_text(
            'schema = "carrick.conformance-exemption.v1"\n'
            f'base = "{self.base_sha}"\n'
            f'head = "{reviewed_head}"\n'
            'paths = ["crates/carrick-kernel/src/dispatch/futex.rs"]\n'
            'contracts = ["kernel.futex.contention"]\n'
            'rationale = "Only the reviewed documentation changed; guest behavior and work remain identical."\n'
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "record exact reviewed revision"], cwd=self.repo, check=True)
        return reviewed_head

    def test_committed_exemption_covers_unchanged_reviewed_source(self):
        self.commit_reviewed_exemption()
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_hosted_pr_merge_requires_the_actual_base_and_unchanged_reviewed_source(self):
        reviewed_head = self.commit_reviewed_exemption()
        pr_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        subprocess.run(["git", "checkout", "-b", "advanced-main", self.base_sha], cwd=self.repo, check=True)
        (self.repo / "README.md").write_text("Main advanced independently of the reviewed source.\n")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "advance actual PR base"], cwd=self.repo, check=True)
        pr_base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        subprocess.run(["git", "checkout", "-b", "github-pr-merge", pr_head], cwd=self.repo, check=True)
        subprocess.run(["git", "merge", "--no-ff", "advanced-main", "-m", "GitHub PR merge head"], cwd=self.repo, check=True)
        merge_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

        # Hosted CI uses event.pull_request.base.sha and github.sha, rather
        # than the branch's historical base. The same merge head exposes it.
        historical = self.run_check(base_sha=self.base_sha, head_sha=merge_head)
        self.assertEqual(historical.returncode, 0, msg=historical.stderr)
        hosted = self.run_check(base_sha=pr_base, head_sha=merge_head)
        self.assertEqual(hosted.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", hosted.stderr)

        receipt = self.repo / "docs" / "conformance-exemptions" / "reviewed.toml"
        receipt.write_text(receipt.read_text().replace(self.base_sha, pr_base).replace(reviewed_head, merge_head))
        subprocess.run(["git", "commit", "-am", "review actual base and exact source"], cwd=self.repo, check=True)
        pr_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        subprocess.run(["git", "checkout", "-b", "github-pr-merge-refreshed", pr_base], cwd=self.repo, check=True)
        subprocess.run(["git", "merge", "--no-ff", pr_head, "-m", "GitHub refreshed PR merge head"], cwd=self.repo, check=True)
        merge_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        hosted = self.run_check(base_sha=pr_base, head_sha=merge_head)
        self.assertEqual(hosted.returncode, 0, msg=hosted.stderr)

        self.guest_file.write_text("fn changed_after_review() {}\n")
        subprocess.run(["git", "commit", "-am", "change reviewed source after PR review"], cwd=self.repo, check=True)
        hosted = self.run_check(base_sha=pr_base)
        self.assertEqual(hosted.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", hosted.stderr)

    def test_committed_exemption_refuses_later_source_edit(self):
        self.commit_reviewed_exemption()
        self.guest_file.write_text("fn changed_guest_behavior() {}\n")
        subprocess.run(["git", "commit", "-am", "change source after review"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", result.stderr)

    def test_committed_exemption_refuses_nonancestor_review(self):
        self.commit_reviewed_exemption()
        receipt_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        subprocess.run(["git", "checkout", "--detach", self.base_sha], cwd=self.repo, check=True)
        subprocess.run(["git", "checkout", receipt_head, "--", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "same source in unrelated history"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", result.stderr)

    def test_committed_exemption_refuses_rewritten_review(self):
        reviewed_head = self.commit_reviewed_exemption()
        subprocess.run(["git", "reset", "--soft", reviewed_head], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "--amend", "-m", "rewrite reviewed head"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", result.stderr)

    def test_one_later_edit_invalidates_the_entire_receipt(self):
        reviewed_head = self.commit_reviewed_exemption()
        receipt = self.repo / "docs" / "conformance-exemptions" / "reviewed.toml"
        receipt.write_text(receipt.read_text().replace(
            'paths = ["crates/carrick-kernel/src/dispatch/futex.rs"]',
            'paths = ["crates/carrick-kernel/src/dispatch/futex.rs", "conformance-contracts/surfaces.toml"]',
        ))
        surfaces = self.repo / "conformance-contracts" / "surfaces.toml"
        surfaces.write_text(surfaces.read_text() + "\n# later edit\n")
        subprocess.run(["git", "commit", "-am", "change one reviewed path"], cwd=self.repo, check=True)
        unchanged = subprocess.run(
            ["git", "diff", "--quiet", reviewed_head, "HEAD", "--", str(self.guest_file)],
            cwd=self.repo, check=False,
        )
        self.assertEqual(unchanged.returncode, 0)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", result.stderr)

    def test_committed_exemption_does_not_cover_another_surface(self):
        self.commit_reviewed_exemption()
        other = self.guest_file.with_name("other.rs")
        other.write_text("fn changed_guest_behavior() {}\n")
        surfaces = self.repo / "conformance-contracts" / "surfaces.toml"
        surfaces.write_text(
            surfaces.read_text()
            + '\n[[surfaces]]\npath = "crates/carrick-kernel/src/dispatch/other.rs"\n'
            + 'contracts = ["kernel.futex.contention"]\n'
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "change another surface"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("other.rs", result.stderr)

    def test_descriptor_with_unrelated_filename_is_evidence(self):
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        directory = self.repo / "conformance-contracts" / "contracts"
        descriptor = directory / "reviewed-contract.toml"
        (directory / "futex-contention.toml").rename(descriptor)
        descriptor.write_text(descriptor.read_text() + "\n# reviewed evidence update\n")
        self.guest_file.write_text("// changed futex implementation\n")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "update declared contract"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_lookalike_filename_is_not_contract_evidence(self):
        self.use_single_contract_surface()
        self.guest_file.write_text("// changed futex implementation\n")
        lookalike = self.repo / "docs" / "contention.toml"
        lookalike.parent.mkdir()
        lookalike.write_text("# unrelated document\n")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "unrelated lookalike"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("kernel.futex.contention", result.stderr)

    def test_1_modified_guest_file_without_evidence_exits_1(self):
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify guest file"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("crates/carrick-kernel/src/dispatch/futex.rs", res.stderr)
        self.assertIn("kernel.futex.contention", res.stderr)

    def test_2_modified_guest_file_plus_registered_binding_exits_0(self):
        self.seed_gated_futex_contracts()
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        self.vm_free_binding_file.write_text("#[test]\nfn futex_contention_contract() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify guest and binding"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_registered_plural_unit_test_file_is_evidence(self):
        self.use_single_contract_surface()
        (self.repo / "crates" / "carrick-kernel" / "src" / "dispatch" / "mod.rs").write_text(
            "pub mod futex;\n#[cfg(test)]\nmod futex_tests;\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "crates/carrick-kernel/src/dispatch/mod.rs"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "declare mod futex_tests in dispatch/mod.rs"], cwd=self.repo, check=True)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        unit_path = "crates/carrick-kernel/src/dispatch/futex_tests.rs"
        unit = self.repo / unit_path
        unit.write_text(
            "#[test] fn checks_futex() { assert_eq!(super::futex::futex_plural_item(), 1); }\n",
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts/surfaces.toml").open("a", encoding="utf-8") as mapping:
            mapping.write(
                f'\n[[surfaces]]\npath = "{unit_path}"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel::dispatch::futex_tests::checks_futex"',
            ),
            encoding="utf-8",
        )
        self.guest_file.write_text("pub fn futex_plural_item() -> u32 { 1 }\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify guest and unit binding"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_registered_rust_tests_module_is_evidence(self):
        self.use_single_contract_surface()
        unit_path = "crates/carrick-kernel/src/dispatch/futex/tests.rs"
        unit = self.repo / unit_path
        unit.parent.mkdir(parents=True)
        unit.write_text(
            "#[test] fn checks_futex() { assert_eq!(super::futex_mod_item(), 1); }\n",
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts/surfaces.toml").open("a", encoding="utf-8") as mapping:
            mapping.write(
                f'\n[[surfaces]]\npath = "{unit_path}"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel::dispatch::futex::tests::checks_futex"',
            ),
            encoding="utf-8",
        )
        self.guest_file.write_text(
            "#[cfg(test)]\nmod tests;\npub fn futex_mod_item() -> u32 { 1 }\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify guest and Rust tests module"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_3_byte_identical_rename_detected_with_M_exits_0(self):
        new_path = self.guest_file.parent / "futex_renamed.rs"
        subprocess.run(["git", "mv", str(self.guest_file), str(new_path)], cwd=self.repo, check=True)
        surfaces_toml = self.repo / "conformance-contracts" / "surfaces.toml"
        surfaces_toml.write_text(
            surfaces_toml.read_text(encoding="utf-8").replace(
                "crates/carrick-kernel/src/dispatch/futex.rs",
                "crates/carrick-kernel/src/dispatch/futex_renamed.rs",
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "conformance-contracts/surfaces.toml"], cwd=self.repo, check=True)
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

    def test_new_fixture_publisher_paths_are_host_tooling(self):
        for relative in (
            "crates/carrick-xtask/src/fixtures.rs",
            "crates/carrick-xtask/src/fixtures/archive.rs",
        ):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// host fixture publication and verification\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "add host fixture publisher"], cwd=self.repo, check=True)

        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

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
        git_env = dict(os.environ, GIT_COMMITTER_DATE="2026-09-19T12:00:00", GIT_AUTHOR_DATE="2026-09-19T12:00:00")
        subprocess.run(["git", "commit", "--amend", "--no-edit"], cwd=self.repo, check=True, env=git_env)
        active_head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        (exempt_dir / "exemption.toml").write_text(
            exemption.replace(head_sha, active_head_sha), encoding="utf-8"
        )
        subprocess.run(["git", "commit", "--amend", "--no-edit"], cwd=self.repo, check=True, env=git_env)
        committed_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        res = self.run_check(head_sha=committed_head)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def seed_extractable_futex(self):
        self.use_single_contract_surface()
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\n'
                'path = "crates/carrick-kernel/src/dispatch/waiter.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        self.guest_file.write_text(
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n\n"
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed extractable futex"], cwd=self.repo, check=True)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        return self.guest_file.with_name("waiter.rs")

    def test_pure_move_into_new_module_passes(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "// attached module comment\n"
            "#[cfg(not(test))]\n"
            "pub(crate) mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "use core::cmp::max;\n\n"
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "pure move park_waiter to waiter module"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/futex.rs (4 moved lines)",
            res.stdout,
        )
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/waiter.rs (4 moved lines)",
            res.stdout,
        )

    def test_move_plus_reindentation_passes(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "mod waiter;\n"
            "use waiter::indented_helper;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n"
            "}\n\n"
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn indented_helper(val: i32) -> i32 {\n"
            "    let stepped = val + 1;\n"
            "    stepped\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move and unindent helper"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/futex.rs (4 moved lines)",
            res.stdout,
        )
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/waiter.rs (4 moved lines)",
            res.stdout,
        )

    def test_move_with_one_identifier_changed_fails(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let renamed_next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move with renamed identifier"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res.stderr)

    def test_move_plus_added_non_declaration_line_in_either_file_fails(self):
        waiter_file = self.seed_extractable_futex()
        # Case 1: non-declaration line added in source file (futex.rs)
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n"
            "pub const EXTRA_IN_SOURCE: i32 = 1;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move plus non-decl in source"], cwd=self.repo, check=True)

        res_source = self.run_check()
        self.assertEqual(res_source.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res_source.stderr)

        # Case 2: non-declaration line added in destination file (waiter.rs)
        subprocess.run(["git", "reset", "--hard", self.base_sha], cwd=self.repo, check=True)
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n"
            "pub const EXTRA_IN_DEST: i32 = 2;\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move plus non-decl in dest"], cwd=self.repo, check=True)

        res_dest = self.run_check()
        self.assertEqual(res_dest.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res_dest.stderr)

    def test_duplicated_line_with_wrong_multiplicity_fails(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        # `let next = val + 1;` removed once, added twice
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    let next = val + 1;\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "duplicate moved line"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res.stderr)

    def test_deletion_with_no_matching_addition_fails(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        # Missing `let next = val + 1;` in destination
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "drop one line during move"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res.stderr)

    def test_existing_byte_identical_rename_still_passes(self):
        self.seed_extractable_futex()
        renamed = self.guest_file.with_name("futex_byte_identical.rs")
        subprocess.run(["git", "mv", str(self.guest_file), str(renamed)], cwd=self.repo, check=True)
        surfaces_toml = self.repo / "conformance-contracts" / "surfaces.toml"
        surfaces_toml.write_text(
            surfaces_toml.read_text(encoding="utf-8").replace(
                "crates/carrick-kernel/src/dispatch/futex.rs",
                "crates/carrick-kernel/src/dispatch/futex_byte_identical.rs",
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "conformance-contracts/surfaces.toml"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "byte-identical rename of seeded futex"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_cross_file_reorder_of_moved_lines_fails(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n"
            "}\n\n"
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    lock();\n"
            "    drop(guard);\n"
            "    use_it(val)\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed ordered statements"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        # Same line multiset, but `drop(guard);` and `use_it(val)` are reordered.
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    lock();\n"
            "    use_it(val)\n"
            "    drop(guard);\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move with reordered lines"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res.stderr)

    def test_block_split_across_two_destination_files_passes(self):
        waiter_file = self.seed_extractable_futex()
        waiter_two_file = self.guest_file.with_name("waiter_two.rs")
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\n'
                'path = "crates/carrick-kernel/src/dispatch/waiter_two.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        self.guest_file.write_text(
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        first_waiter(1) + second_waiter(2)\n"
            "    }\n"
            "}\n\n"
            "pub fn first_waiter(val: i32) -> i32 {\n"
            "    let a = val + 1;\n"
            "    a\n"
            "}\n\n"
            "pub fn second_waiter(val: i32) -> i32 {\n"
            "    let b = val + 2;\n"
            "    b\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed two adjacent extractable blocks"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub mod waiter_two;\n"
            "pub use waiter::first_waiter;\n"
            "pub use waiter_two::second_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        first_waiter(1) + second_waiter(2)\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn first_waiter(val: i32) -> i32 {\n"
            "    let a = val + 1;\n"
            "    a\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_two_file.write_text(
            "pub fn second_waiter(val: i32) -> i32 {\n"
            "    let b = val + 2;\n"
            "    b\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "split hunk across two destination files"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/futex.rs (8 moved lines)",
            res.stdout,
        )
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/waiter.rs (4 moved lines)",
            res.stdout,
        )
        self.assertIn(
            "move-covered: crates/carrick-kernel/src/dispatch/waiter_two.rs (4 moved lines)",
            res.stdout,
        )

    def test_block_interleaved_with_non_declaration_added_line_fails(self):
        waiter_file = self.seed_extractable_futex()
        self.guest_file.write_text(
            "pub mod waiter;\n"
            "pub use waiter::park_waiter;\n\n"
            "pub struct Futex;\n\n"
            "impl Futex {\n"
            "    pub fn entry() -> i32 {\n"
            "        park_waiter(1)\n"
            "    }\n\n"
            "    pub fn indented_helper(val: i32) -> i32 {\n"
            "        let stepped = val + 1;\n"
            "        stepped\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        waiter_file.write_text(
            "pub fn park_waiter(val: i32) -> i32 {\n"
            "    let next = val + 1;\n"
            "    interleaved_side_effect();\n"
            "    next\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "interleave non-decl line in moved block"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn("has no gated bound test for changed surface", res.stderr)

    def seed_gated_futex_contracts(self):
        shutil.copy(
            REPO_ROOT / "conformance-contracts" / "contracts" / "futex-requeue.toml",
            self.repo / "conformance-contracts" / "contracts" / "futex-requeue.toml",
        )
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.parent.mkdir(parents=True, exist_ok=True)
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        lib_rs = self.repo / "crates" / "carrick-kernel-example" / "src" / "lib.rs"
        lib_rs.parent.mkdir(parents=True, exist_ok=True)
        lib_rs.write_text(
            "pub mod contracts;\n"
            "pub use contracts::{futex_contention_contract, futex_requeue_contract};\n",
            encoding="utf-8",
        )
        contracts_rs = self.repo / "crates" / "carrick-kernel-example" / "src" / "contracts.rs"
        contracts_rs.write_text(
            "pub fn futex_contention_contract() {}\n"
            "pub fn futex_requeue_contract() {}\n",
            encoding="utf-8",
        )
        contracts_test = self.repo / "crates" / "carrick-kernel-example" / "tests" / "contracts.rs"
        contracts_test.parent.mkdir(parents=True, exist_ok=True)
        contracts_test.write_text(
            "#[test]\nfn futex_contention_contract_is_semantically_exact_and_linear() {\n"
            "    carrick_kernel_example::futex_contention_contract();\n"
            "}\n\n"
            "#[test]\nfn futex_requeue_contract_is_semantically_exact_and_linear() {\n"
            "    carrick_kernel_example::futex_requeue_contract();\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed gated futex contracts and tests"], cwd=self.repo, check=True)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

    def test_honest_refactor_multi_contract_with_existing_gated_bound_tests_passes(self):
        self.seed_gated_futex_contracts()
        self.guest_file.write_text("pub fn refactored_futex_dispatch() -> i32 { 42 }\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "honest refactor touching multi-contract surface"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.contention: carrick-kernel-example::futex_contention_contract",
            res.stdout,
        )
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.requeue: carrick-kernel-example::futex_requeue_contract",
            res.stdout,
        )

    def seed_resolution_case(self, files, binding):
        self.use_single_contract_surface()
        self.guest_file.write_text("pub fn changed_futex() -> u64 { 1 }\n", encoding="utf-8")
        for path, source in files.items():
            target = self.repo / "crates" / "carrick-kernel" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        contract = self.repo / "conformance-contracts/contracts/futex-contention.toml"
        contract.write_text(
            'schema_version = 1\nid = "kernel.futex.contention"\n'
            'title = "Futex contention"\n[bindings]\n'
            f'vm_free = "{binding}"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "seed resolution case"],
                       cwd=self.repo, check=True, capture_output=True)
        self.base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        self.guest_file.write_text("pub fn changed_futex() -> u64 { 2 }\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "change guest surface"],
                       cwd=self.repo, check=True, capture_output=True)

    def test_inline_test_module_follows_out_of_line_child(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\nmod witness;\n",
                "src/witness.rs": "#[cfg(test)] mod tests { mod native_floor; }\n",
                "src/witness/tests/native_floor.rs": "#[test] fn bound_test() {}\n",
            },
            "carrick-kernel::witness::tests::native_floor::bound_test",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        child = self.repo / "crates/carrick-kernel/src/witness/tests/native_floor.rs"
        child.write_text('#![cfg(feature = "never_enabled")]\n#[test] fn bound_test() {}\n')
        subprocess.run(["git", "commit", "-am", "disable inline child"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_reexported_path_test_module_resolves(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\nmod personality;\npub use personality::{sched};\n",
                "src/personality.rs": '#[path = "sched.rs"] pub mod sched;\n',
                "src/sched.rs": '#[cfg(test)] #[path = "sched/tests.rs"] mod tests;\n',
                "src/sched/tests.rs": "#[test] fn bound_test() {}\n",
            },
            "carrick-kernel::sched::tests::bound_test",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        root = self.repo / "crates/carrick-kernel/src/lib.rs"
        root.write_text(
            'mod dispatch;\nmod personality;\n'
            '#[cfg(feature = "never_enabled")] pub use personality::{sched};\n'
        )
        subprocess.run(["git", "commit", "-am", "disable reexport"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_module_reexport_spellings_and_cycles(self):
        for export in (
            "pub use self::personality::sched;",
            "pub use crate::personality::sched as sched;",
            "pub use personality::*;",
        ):
            with self.subTest(export=export):
                self.seed_resolution_case(
                    {
                        "src/lib.rs": f"mod dispatch;\nmod personality;\n{export}\n",
                        "src/personality.rs": "pub mod sched;\n",
                        "src/personality/sched.rs": "#[cfg(test)] mod tests {\n"
                                                   "#[test] fn bound_test() {} }\n",
                    },
                    "carrick-kernel::sched::tests::bound_test",
                )
                result = self.run_check()
                self.assertEqual(result.returncode, 0, msg=result.stderr)
        root = self.repo / "crates/carrick-kernel/src/lib.rs"
        root.write_text("mod dispatch;\nmod personality;\npub use personality::*;\n")
        module = self.repo / "crates/carrick-kernel/src/personality.rs"
        module.write_text("pub use crate::personality::*;\n")
        subprocess.run(["git", "commit", "-am", "cyclic reexport cannot resolve"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_declared_module_does_not_fall_back_through_glob_reexports(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\nmod witness;\npub use witness::*;\n",
                "src/witness.rs": "#[cfg(test)] mod tests {}\npub use crate::witness::*;\n",
            },
            "carrick-kernel::witness::tests::missing",
        )
        spec = importlib.util.spec_from_file_location("contract_checker", SCRIPT_PATH)
        checker = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = checker
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(checker)
        view = checker.RepoView(self.repo, "HEAD")
        with patch.object(checker, "_find_use_reexports",
                          wraps=checker._find_use_reexports) as reexports:
            self.assertIsNone(checker.resolve_binding_at_view(
                view, "carrick-kernel::witness::tests::missing"
            ))
        self.assertEqual(reexports.call_count, 1)

    def test_path_attribute_does_not_use_nonexistent_file_relative_fallback(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\nmod witness;\n",
                "src/witness.rs": '#[cfg(test)] #[path = "missing.rs"] mod tests;\n',
                "src/witness/missing.rs": "#[test] fn bound_test() {}\n",
            },
            "carrick-kernel::witness::tests::bound_test",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 1, msg=result.stdout)

    def test_annotated_binding_including_control_resolves(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\n#[cfg(test)] mod tests;\n",
                "src/tests.rs": '#[cfg(feature = "conformance-metrics")]\n'
                                "#[test] fn cost_contract() {}\n"
                                "#[test] fn revocation_control() {}\n",
            },
            "carrick-kernel::tests::cost_contract (conformance-metrics), "
            "plus revocation controls including revocation_control",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("carrick-kernel::tests::revocation_control", result.stdout)
        tests = self.repo / "crates/carrick-kernel/src/tests.rs"
        tests.write_text(tests.read_text().replace(
            "#[test] fn revocation_control", '#[cfg(feature = "never_enabled")]\n'
            "#[test] fn revocation_control"
        ))
        subprocess.run(["git", "commit", "-am", "disable supplemental control"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_annotated_binding_semicolon_control_resolves(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\n#[cfg(test)] mod tests;\n",
                "src/tests.rs": '#[cfg(feature = "conformance-metrics")]\n'
                                "#[test] fn cost_contract() {}\n"
                                "#[test] fn host_execution_control() {}\n",
            },
            "carrick-kernel::tests::cost_contract (conformance-metrics); "
            "host_execution_control supplies supplemental host execution semantics",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("carrick-kernel::tests::host_execution_control", result.stdout)
        tests = self.repo / "crates/carrick-kernel/src/tests.rs"
        tests.write_text(tests.read_text().replace(
            "#[test] fn host_execution_control", "#[test] #[ignore] fn host_execution_control"
        ))
        subprocess.run(["git", "commit", "-am", "ignore supplemental control"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_contract_called_through_one_local_helper_resolves(self):
        self.seed_gated_futex_contracts()
        tests = self.repo / "crates/carrick-kernel-example/tests/contracts.rs"
        tests.write_text(
            "fn observations() { carrick_kernel_example::futex_contention_contract(); }\n"
            "#[test] fn bound_test() { observations(); }\n"
            "#[test] fn requeue() { carrick_kernel_example::futex_requeue_contract(); }\n"
        )
        subprocess.run(["git", "commit", "-am", "call contract through one helper"],
                       cwd=self.repo, check=True, capture_output=True)
        self.base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        self.guest_file.write_text("pub fn changed_futex() -> u64 { 2 }\n")
        subprocess.run(["git", "commit", "-am", "change guest surface"],
                       cwd=self.repo, check=True, capture_output=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        tests.write_text(tests.read_text().replace("bound_test() { observations(); }",
                                                  "bound_test() { assert!(true); }"))
        subprocess.run(["git", "commit", "-am", "stop calling helper"],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertEqual(self.run_check().returncode, 1)

    def test_helper_implementation_must_overlap_the_bound_test_cfg(self):
        self.seed_gated_futex_contracts()
        tests = self.repo / "crates/carrick-kernel-example/tests/contracts.rs"
        for macos_calls_contract in (True, False):
            helper_bodies = (
                ("", "carrick_kernel_example::futex_contention_contract();")
                if macos_calls_contract else
                ("carrick_kernel_example::futex_contention_contract();", "")
            )
            for reverse in (False, True):
                with self.subTest(macos_calls_contract=macos_calls_contract, reverse=reverse):
                    helpers = [
                        f'#[cfg(target_os = "{os_name}")]\nfn observations() {{ {body} }}\n'
                        for os_name, body in zip(("linux", "macos"), helper_bodies)
                    ]
                    tests.write_text(
                        "".join(reversed(helpers) if reverse else helpers)
                        + '#[cfg(target_os = "linux")]\n'
                        "#[test] fn bound_test() { observations(); }\n"
                        "#[test] fn requeue() { carrick_kernel_example::futex_requeue_contract(); }\n"
                    )
                    self.guest_file.write_text(
                        f"pub fn changed_futex() -> u64 {{ {int(reverse)} }}\n"
                    )
                    subprocess.run(["git", "commit", "-am", "test conditional helper variants"],
                                   cwd=self.repo, check=True, capture_output=True)
                    result = self.run_check()
                    self.assertEqual(result.returncode, int(macos_calls_contract),
                                     msg=f"{result.stdout}\n{result.stderr}")

    def test_conditional_inline_modules_are_distinct_resolution_scopes(self):
        for first_cfg in ('all(test, target_os = "macos")',
                          'all(test, feature = "never_enabled")'):
            with self.subTest(first_cfg=first_cfg):
                self.seed_resolution_case(
                    {
                        "src/lib.rs": "mod dispatch;\n"
                                      f"#[cfg({first_cfg})] mod tests {{\n"
                                      "#[test] fn other_witness() {} }\n"
                                      '#[cfg(all(test, target_os = "linux"))] mod tests {\n'
                                      "#[test] fn bound_test() {} }\n",
                    },
                    "carrick-kernel::tests::bound_test",
                )
                result = self.run_check()
                self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_called_local_helper_can_reference_changed_surface(self):
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\n#[cfg(test)] mod tests;\n",
                "src/tests.rs": "fn helper() { changed_futex(); }\n"
                                "#[test] fn bound_test() { helper(); }\n",
            },
            "carrick-kernel::tests::bound_test",
        )
        # Make this an added binding so the relevance check must inspect the helper.
        contract = "conformance-contracts/contracts/futex-contention.toml"
        base_contract = (self.repo / contract).read_text()
        (self.repo / contract).write_text(base_contract.replace(
            'vm_free = "carrick-kernel::tests::bound_test"', 'docker = "probe:futex"'
        ))
        subprocess.run(["git", "commit", "-am", "remove binding before addition"],
                       cwd=self.repo, check=True, capture_output=True)
        self.base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        (self.repo / contract).write_text(base_contract)
        self.guest_file.write_text("pub fn changed_futex() -> u64 { 3 }\n")
        subprocess.run(["git", "commit", "-am", "add relevant helper binding"],
                       cwd=self.repo, check=True, capture_output=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        tests = self.repo / "crates/carrick-kernel/src/tests.rs"
        for source in (
            '#[cfg(feature = "never_enabled")] fn helper() { changed_futex(); }\n'
            "#[test] fn bound_test() { helper(); }\n",
            "fn helper() { changed_futex(); }\n"
            "#[test] fn bound_test() { other::helper(); }\n",
            "fn helper() { changed_futex(); }\nfn indirect() { helper(); }\n"
            "#[test] fn bound_test() { indirect(); }\n",
        ):
            with self.subTest(source=source):
                tests.write_text(source)
                subprocess.run(["git", "commit", "-am", "exclude inactive or indirect helper"],
                               cwd=self.repo, check=True, capture_output=True)
                result = self.run_check()
                self.assertEqual(result.returncode, 1, msg=result.stdout)

    def test_contract_without_any_gated_bound_test_fails(self):
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\ncontracts = { lane = "manual", reason = "not gated in CI" }\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "mark test lane manual"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn changed_futex() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify surface with manual-only bound test"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1)
        self.assertIn(
            "error: contract kernel.futex.contention has no gated bound test for changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bound_test_missing_at_head_fails(self):
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        contracts_test = self.repo / "crates" / "carrick-kernel-example" / "tests" / "contracts.rs"
        contracts_test.write_text("// test function removed\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "remove bound test function"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn changed_futex() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify surface when bound test missing at HEAD"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1)
        self.assertIn(
            "error: contract kernel.futex.contention has no gated bound test for changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_gaming_added_unrelated_binding_fails(self):
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        unrelated_crate = self.repo / "crates" / "carrick-vmm-hvf"
        (unrelated_crate / "src").mkdir(parents=True, exist_ok=True)
        (unrelated_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-vmm-hvf"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        (unrelated_crate / "src" / "lib.rs").write_text("pub mod unrelated;\n", encoding="utf-8")
        (unrelated_crate / "src" / "unrelated.rs").write_text(
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn completely_unrelated_test() {\n        assert_eq!(1 + 1, 2);\n    }\n}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed contract without vm_free binding"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn futex_wake_waiters() -> i32 { 1 }\n", encoding="utf-8")
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-vmm-hvf::unrelated::tests::completely_unrelated_test"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "game contract gate by adding unrelated binding"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-vmm-hvf::unrelated::tests::completely_unrelated_test added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_added_binding_referencing_changed_item_passes(self):
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.parent.mkdir(parents=True, exist_ok=True)
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        semantics_main = self.repo / "crates" / "carrick-kernel-example" / "tests" / "semantics" / "main.rs"
        semantics_main.parent.mkdir(parents=True, exist_ok=True)
        semantics_main.write_text("mod futex_contention;\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed contract without vm_free binding"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn futex_wake_waiters() -> i32 { 1 }\n", encoding="utf-8")
        self.vm_free_binding_file.write_text(
            "#[test]\nfn futex_contention_contract() {\n    let _ = futex_wake_waiters();\n}\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-kernel-example::semantics::futex_contention::futex_contention_contract"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "add binding referencing changed surface item"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.contention: carrick-kernel-example::semantics::futex_contention::futex_contention_contract",
            res.stdout,
        )

    def test_bypass_bfake_production_fn_in_surface_file_fails(self):
        """Repro Bfake (P0-1): binding a production fn in the surface file itself via a fake `::tests::` segment must fail."""
        self.use_single_contract_surface()
        self.guest_file.write_text("pub(crate) fn dispatch_futex_pi() -> i32 { 0 }\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed production fn in futex.rs"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text(
            "pub(crate) fn dispatch_futex_pi() -> i32 { 1 }\n// modified\n", encoding="utf-8"
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel-example::futex_contention_contract; carrick-kernel::dispatch::futex::tests::dispatch_futex_pi"',
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "attempt Bfake bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: contract kernel.futex.contention has no gated bound test for changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bypass_c_comment_and_keyword_chain_prose_match_fails(self):
        """Repro C (P0-2): comments (`// This fn is ...`) and keyword chains (`pub const fn`, `static mut`) must not match unrelated tests."""
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        gic_crate = self.repo / "crates" / "carrick-vmm-hvf"
        (gic_crate / "src").mkdir(parents=True, exist_ok=True)
        (gic_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-vmm-hvf"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "signed-hvf"\n',
            encoding="utf-8",
        )
        (gic_crate / "src" / "lib.rs").write_text("pub mod gic;\n", encoding="utf-8")
        (gic_crate / "src" / "gic.rs").write_text(
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn mpidr_carries_res1_and_sgi_addressable_affinity() {\n"
            "        // Affinity is checked with const and mut locals.\n"
            "        const X: u32 = 1;\n"
            "        let mut y = X;\n"
            "        y += 1;\n"
            "        assert_eq!(y, 2);\n"
            "    }\n}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed gic test"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text(
            "// This fn is the threaded entry.\n"
            "const _: () = ();\n"
            "pub const fn futex_real_const_helper() -> u32 { 7 }\n"
            "static mut FUTEX_REAL_COUNTER: u32 = 0;\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-vmm-hvf::gic::tests::mpidr_carries_res1_and_sgi_addressable_affinity"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "attempt Repro C bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-vmm-hvf::gic::tests::mpidr_carries_res1_and_sgi_addressable_affinity added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bypass_d_dropping_contract_from_surface_in_same_pr_fails(self):
        """Repro D (P1-4a): removing a contract from a surface in surfaces.toml in the same PR must fail."""
        self.guest_file.write_text("pub fn modified_futex() {}\n", encoding="utf-8")
        (self.repo / "conformance-contracts" / "surfaces.toml").write_text(
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/futex.rs"\n'
            'contracts = []\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "drop contracts from surfaces.toml"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("crates/carrick-kernel/src/dispatch/futex.rs", res.stderr)

    def test_bypass_e_modified_rename_to_unmapped_path_fails(self):
        """Repro E (P1-4b): R<100 rename of a guest file to an unmapped path must fail as unclassified."""
        self.guest_file.write_text(
            "".join(f"pub fn line_{i}() -> usize {{ {i} }}\n" for i in range(40)),
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "seed 40-line futex.rs"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        new_path = self.guest_file.with_name("futex_impl.rs")
        subprocess.run(["git", "mv", str(self.guest_file), str(new_path)], cwd=self.repo, check=True)
        new_path.write_text(
            new_path.read_text(encoding="utf-8") + "pub fn added_behavior() {}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "R<100 rename to unmapped futex_impl.rs"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("unclassified", res.stderr)
        self.assertIn("crates/carrick-kernel/src/dispatch/futex_impl.rs", res.stderr)

    def test_bypass_f_ignored_test_in_non_ignored_lane_fails(self):
        """Repro F (P0-3): an #[ignore]d test in a lane that does not pass --ignored must be rejected."""
        self.use_single_contract_surface()
        self.guest_file.write_text("pub fn futex_wake_waiters() -> i32 { 1 }\n", encoding="utf-8")
        unit_test = self.guest_file.with_name("futex_tests.rs")
        unit_test.write_text(
            "#[test]\n#[ignore = \"never runs in CI\"]\nfn futex_witness_never_runs() {\n"
            "    let _ = futex_wake_waiters();\n"
            "    panic!(\"never executed\");\n"
            "}\n",
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts/surfaces.toml").open("a", encoding="utf-8") as mapping:
            mapping.write(
                '\n[[surfaces]]\npath = "crates/carrick-kernel/src/dispatch/futex_tests.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel::dispatch::futex_tests::futex_witness_never_runs"',
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "bind #[ignore] test"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: contract kernel.futex.contention has no gated bound test for changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_ignored_test_in_signed_recipe_passing_ignored_passes(self):
        """P0-3 positive control: an #[ignore]d test matched by a CI-invoked justfile recipe that passes --ignored counts."""
        self.use_single_contract_surface()
        wf_dir = self.repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "ci.yml").write_text(
            "name: ci\njobs:\n  signed:\n    steps:\n      - run: just test-hvf-trap-engine\n",
            encoding="utf-8",
        )
        (self.repo / "justfile").write_text(
            "test-hvf-trap-engine:\n"
            "    ./scripts/test-signed.sh carrick-vmm-hvf trap_engine_hvf_ --ignored --nocapture\n",
            encoding="utf-8",
        )
        hvf_dir = self.repo / "crates" / "carrick-vmm-hvf"
        (hvf_dir / "tests").mkdir(parents=True, exist_ok=True)
        (hvf_dir / "Cargo.toml").write_text(
            '[package]\nname = "carrick-vmm-hvf"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "signed-hvf"\n',
            encoding="utf-8",
        )
        (hvf_dir / "tests" / "trap_engine_hvf.rs").write_text(
            "#[test]\n#[ignore = \"requires signed HVF execution through just test-hvf-trap-engine\"]\n"
            "fn trap_engine_hvf_boots_and_handles_getpid() {\n"
            "    let _ = futex_wake_waiters();\n"
            "}\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'embed = "carrick-vmm-hvf::trap_engine_hvf::trap_engine_hvf_boots_and_handles_getpid"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed trap_engine_hvf ignored lane"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn futex_wake_waiters() -> i32 { 1 }\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "edit futex with trap_engine_hvf ignored test"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.contention: carrick-vmm-hvf::trap_engine_hvf::trap_engine_hvf_boots_and_handles_getpid",
            res.stdout,
        )

    def test_missing_or_malformed_cargo_toml_fails_closed(self):
        """P1-2: missing Cargo.toml or malformed test-lanes table must fail closed."""
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick]\ntest-lanes = "not-a-table"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "malformed test-lanes"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn changed_futex() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "modify surface with malformed test-lanes"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("has no gated bound test", res.stderr)

    def test_lib_or_mod_change_does_not_admit_unrelated_subtree_test(self):
        """P1-3: editing lib.rs or mod.rs must not admit an unrelated test in the crate that references no changed item."""
        lib_path = "crates/carrick-kernel/src/lib.rs"
        other_mod_path = "crates/carrick-kernel/src/other.rs"
        other_test_path = "crates/carrick-kernel/src/other/tests.rs"
        (self.repo / other_test_path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / other_mod_path).write_text(
            "#[cfg(test)]\nmod tests;\n",
            encoding="utf-8",
        )
        (self.repo / other_test_path).write_text(
            "#[test]\nfn unrelated_other_unit_test() { assert_eq!(2 + 2, 4); }\n",
            encoding="utf-8",
        )
        (self.repo / "conformance-contracts" / "surfaces.toml").write_text(
            f'[[surfaces]]\npath = "{lib_path}"\ncontracts = ["kernel.futex.contention"]\n'
            f'[[surfaces]]\npath = "{other_mod_path}"\ncontracts = ["kernel.futex.contention"]\n'
            f'[[surfaces]]\npath = "{other_test_path}"\ncontracts = ["kernel.futex.contention"]\n',
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed lib.rs surface and unrelated unit test"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        (self.repo / lib_path).write_text(
            "pub mod dispatch;\npub mod other;\npub fn newly_added_root_fn() -> u32 { 99 }\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-kernel::other::tests::unrelated_other_unit_test"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "edit lib.rs and bind unrelated unit test"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-kernel::other::tests::unrelated_other_unit_test added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/lib.rs",
            res.stderr,
        )

    def test_multi_surface_honest_added_binding_for_x_preserves_y_with_existing_evidence(self):
        """P2: an honest added binding for surface X must not fail contract C on surface Y when Y has pre-existing evidence."""
        self.seed_gated_futex_contracts()
        surface_y = self.guest_file.with_name("other_futex.rs")
        surface_y.write_text("pub fn existing_other_futex() -> i32 { 1 }\n", encoding="utf-8")
        (self.guest_file.parent / "mod.rs").write_text(
            "pub mod futex;\npub mod other_futex;\n#[cfg(test)]\nmod futex_tests;\n",
            encoding="utf-8",
        )
        unit_test = self.guest_file.with_name("futex_tests.rs")
        unit_test.write_text("", encoding="utf-8")
        (self.repo / "conformance-contracts" / "surfaces.toml").write_text(
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/futex.rs"\n'
            'contracts = ["kernel.futex.contention"]\n'
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/other_futex.rs"\n'
            'contracts = ["kernel.futex.contention"]\n'
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/futex_tests.rs"\n'
            'contracts = ["kernel.futex.contention"]\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed two surfaces sharing kernel.futex.contention"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        # Modify both surfaces, and add a new unit test binding that references futex.rs's new item
        self.guest_file.write_text("pub fn new_futex_x_item() -> i32 { 2 }\n", encoding="utf-8")
        surface_y.write_text("pub fn existing_other_futex() -> i32 { 3 }\n", encoding="utf-8")
        unit_test.write_text(
            "#[test]\nfn test_new_futex_x_item() { let _ = new_futex_x_item(); }\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel-example::futex_contention_contract; carrick-kernel::dispatch::futex_tests::test_new_futex_x_item"',
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify both surfaces and add binding for X"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_dirty_worktree_not_read_as_head(self):
        """P2: files must be read from the git tree at HEAD, not uncommitted worktree edits."""
        self.use_single_contract_surface()
        self.guest_file.write_text("pub fn futex_changed() -> i32 { 1 }\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "commit without resolvable bound test"], cwd=self.repo, check=True)

        # Write a valid test in the dirty worktree WITHOUT committing it
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.parent.mkdir(parents=True, exist_ok=True)
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        contracts_rs = self.repo / "crates" / "carrick-kernel-example" / "src" / "contracts.rs"
        contracts_rs.parent.mkdir(parents=True, exist_ok=True)
        contracts_rs.write_text("pub fn futex_contention_contract() {}\n", encoding="utf-8")
        contracts_test = self.repo / "crates" / "carrick-kernel-example" / "tests" / "contracts.rs"
        contracts_test.parent.mkdir(parents=True, exist_ok=True)
        contracts_test.write_text(
            "#[test]\nfn runs_futex() { futex_contention_contract(); }\n", encoding="utf-8"
        )

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("has no gated bound test", res.stderr)

    def test_real_tree_futex_comment_edit_passes_and_gic_gaming_fails(self):
        """Real-tree verification: comment-only edit to dispatch/futex.rs passes via carrick-kernel-example::futex_*_contract, and GIC-for-futex fails."""
        for rel in (
            "crates/carrick-kernel/Cargo.toml",
            "crates/carrick-kernel/src/dispatch/futex.rs",
            "crates/carrick-kernel-example/Cargo.toml",
            "crates/carrick-kernel-example/src/lib.rs",
            "crates/carrick-kernel-example/src/contracts.rs",
            "crates/carrick-kernel-example/tests/contracts.rs",
            "crates/carrick-vmm-hvf/Cargo.toml",
            "crates/carrick-vmm-hvf/src/lib.rs",
            "crates/carrick-vmm-hvf/src/gic.rs",
            "conformance-contracts/contracts/futex-contention.toml",
            "conformance-contracts/contracts/futex-requeue.toml",
            "conformance-contracts/surfaces.toml",
        ):
            dst = self.repo / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO_ROOT / rel, dst)

        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed real-tree futex and gic files"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        # 1. Comment-only edit to dispatch/futex.rs must pass via carrick-kernel-example::futex_*_contract
        self.guest_file.write_text(
            self.guest_file.read_text(encoding="utf-8") + "// This fn is the threaded entry.\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "comment-only edit on real futex.rs"], cwd=self.repo, check=True)
        res_pass = self.run_check(base_sha=base_sha)
        self.assertEqual(res_pass.returncode, 0, msg=f"stdout: {res_pass.stdout}, stderr: {res_pass.stderr}")
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.contention: carrick-kernel-example::futex_contention_contract",
            res_pass.stdout,
        )
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.requeue: carrick-kernel-example::futex_requeue_contract",
            res_pass.stdout,
        )

        # 2. Replacing futex bindings with the unrelated GIC test must fail
        for cfile in ("futex-contention.toml", "futex-requeue.toml"):
            p = self.repo / "conformance-contracts" / "contracts" / cfile
            txt = p.read_text(encoding="utf-8")
            txt = re.sub(r'^vm_free = .*$', 'vm_free = "carrick-vmm-hvf::gic::tests::mpidr_carries_res1_and_sgi_addressable_affinity"', txt, flags=re.M)
            txt = re.sub(r'^embed = .*$', '', txt, flags=re.M)
            p.write_text(txt, encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "attempt GIC-test-for-futex bypass"], cwd=self.repo, check=True)
        res_fail = self.run_check(base_sha=base_sha)
        self.assertEqual(res_fail.returncode, 1, msg=f"stdout: {res_fail.stdout}, stderr: {res_fail.stderr}")
        self.assertIn(
            "does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res_fail.stderr,
        )

    def test_bypass_g2_comment_on_decl_line_with_helper_word_match_fails(self):
        """Repro G2 (P0-1): appending a comment to `pub fn get(...)` and binding an unrelated test whose helper calls `.get()` must fail."""
        self.use_single_contract_surface()
        self.guest_file.write_text(
            "pub fn get(&self) -> Option<u64> {\n    Some(1)\n}\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        ipc_crate = self.repo / "crates" / "carrick-el1-abi"
        (ipc_crate / "src" / "ipc").mkdir(parents=True, exist_ok=True)
        (ipc_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-el1-abi"\nversion = "0.1.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (ipc_crate / "src" / "lib.rs").write_text("pub mod ipc;\n", encoding="utf-8")
        (ipc_crate / "src" / "ipc.rs").write_text("#[cfg(test)]\nmod tests;\n", encoding="utf-8")
        (ipc_crate / "src" / "ipc" / "tests.rs").write_text(
            "fn helper(c: &std::cell::Cell<u64>) -> u64 { c.get() }\n"
            "#[test]\n"
            "fn el1_ipc_backing_tokens_roundtrip_and_reject_unknown_tags() {\n"
            "    let cell = std::cell::Cell::new(1u64);\n"
            "    assert_eq!(cell.get(), 1);\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed G2 fixture"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        # Append only a trailing comment to the declaration line `pub fn get(&self)`
        self.guest_file.write_text(
            "pub fn get(&self) -> Option<u64> { // tidy\n    Some(1)\n}\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-el1-abi::ipc::tests::el1_ipc_backing_tokens_roundtrip_and_reject_unknown_tags"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "attempt Repro G2 bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-el1-abi::ipc::tests::el1_ipc_backing_tokens_roundtrip_and_reject_unknown_tags added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_changed_item_only_in_test_file_helper_outside_test_fn_body_fails(self):
        """P0-1 & P1-3: a changed identifier appearing only in a non-#[test] helper in the test file must not count."""
        self.use_single_contract_surface()
        self.guest_file.write_text("pub fn futex_real_code_change() -> u64 { 1 }\n", encoding="utf-8")
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        ipc_crate = self.repo / "crates" / "carrick-el1-abi"
        (ipc_crate / "src" / "ipc").mkdir(parents=True, exist_ok=True)
        (ipc_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-el1-abi"\nversion = "0.1.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (ipc_crate / "src" / "lib.rs").write_text("pub mod ipc;\n", encoding="utf-8")
        (ipc_crate / "src" / "ipc.rs").write_text("#[cfg(test)]\nmod tests;\n", encoding="utf-8")
        (ipc_crate / "src" / "ipc" / "tests.rs").write_text(
            "fn unused_helper() { let _ = futex_real_code_change(); }\n"
            "#[test]\n"
            "fn unrelated_test_body() {\n"
            "    assert_eq!(1, 1);\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed helper-only reference fixture"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn futex_real_code_change() -> u64 { 2 }\n", encoding="utf-8")
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-el1-abi::ipc::tests::unrelated_test_body"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "attempt helper-only reference bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-el1-abi::ipc::tests::unrelated_test_body added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bypass_g3_comment_on_decl_and_contract_pool_or_non_test_call_fails(self):
        """Repro G3 (P0-1 & P1-3): contract_fn must only match identifiers in its own body and must be called inside a #[test] body."""
        self.use_single_contract_surface()
        self.guest_file.write_text(
            "pub const fn len() -> usize {\n    0\n}\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        ex_crate = self.repo / "crates" / "carrick-kernel-example"
        (ex_crate / "src").mkdir(parents=True, exist_ok=True)
        (ex_crate / "tests").mkdir(parents=True, exist_ok=True)
        (ex_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        (ex_crate / "src" / "lib.rs").write_text(
            "pub mod contracts;\npub use contracts::inotify_watch_contract;\n",
            encoding="utf-8",
        )
        # `other_contract_fn` mentions `changed_futex_symbol`, while `inotify_watch_contract` does NOT
        (ex_crate / "src" / "contracts.rs").write_text(
            "pub fn other_contract_fn() {\n    let _ = changed_futex_symbol();\n}\n"
            "pub fn inotify_watch_contract() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        (ex_crate / "tests" / "contracts.rs").write_text(
            "use carrick_kernel_example::inotify_watch_contract;\n"
            "#[test]\nfn runs_inotify() {\n    inotify_watch_contract();\n}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed G3 fixture"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text(
            "pub const fn len() -> usize { // len\n    0\n}\n"
            "pub fn changed_futex_symbol() -> usize { 42 }\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-kernel-example::inotify_watch_contract"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "attempt Repro G3 bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: binding carrick-kernel-example::inotify_watch_contract added to kernel.futex.contention does not reference changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bypass_g4_orphan_or_cfg_disabled_module_fails(self):
        """Repro G4 (P0-2): an unreferenced orphan test file or a module gated by an unenabled feature/target_os must fail."""
        self.use_single_contract_surface()
        orphan = self.repo / "crates" / "carrick-kernel" / "src" / "dispatch" / "futex" / "tests" / "orphan.rs"
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_text(
            '#! [cfg(feature = "never_enabled")]\n#[test]\nfn portal_witness() { panic!() }\n',
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\n'
                'path = "crates/carrick-kernel/src/dispatch/futex/tests/orphan.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-kernel::dispatch::futex::tests::orphan::portal_witness"\n',
            encoding="utf-8",
        )
        self.guest_file.write_text("// comment edit on futex.rs\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "attempt Repro G4 orphan/cfg bypass"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_bypass_g5_uninvoked_or_echo_recipe_with_ignored_test_fails(self):
        """Repro G5 (P1-1): a justfile recipe not invoked by .github/workflows (or only echoing test-signed.sh --ignored) must not allow #[ignore]d tests."""
        self.use_single_contract_surface()
        (self.repo / "justfile").write_text(
            "_never_run:\n"
            '    echo "scripts/test-signed.sh carrick-vmm-hvf --ignored"\n'
            "test-hvf-trap-engine:\n"
            "    ./scripts/test-signed.sh carrick-vmm-hvf trap_engine_hvf_ --ignored --nocapture\n",
            encoding="utf-8",
        )
        hvf_crate = self.repo / "crates" / "carrick-vmm-hvf"
        (hvf_crate / "src").mkdir(parents=True, exist_ok=True)
        (hvf_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-vmm-hvf"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "signed-hvf"\n',
            encoding="utf-8",
        )
        (hvf_crate / "src" / "lib.rs").write_text("pub mod trap;\n", encoding="utf-8")
        (hvf_crate / "src" / "trap.rs").write_text(
            '#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore = "not run by CI"]\n'
            "    fn trap_engine_hvf_boots() { panic!() }\n}\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'embed = "carrick-vmm-hvf::trap::tests::trap_engine_hvf_boots"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed uninvoked justfile recipe with ignored test"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        self.guest_file.write_text("pub fn modified_futex() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "edit futex under uninvoked ignored recipe"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "error: contract kernel.futex.contention has no gated bound test for changed surface crates/carrick-kernel/src/dispatch/futex.rs",
            res.stderr,
        )

    def test_bypass_e2_deleted_surface_and_replacement_without_remap_fails(self):
        """Repro E2 (P1-2): deleting a mapped surface and adding a replacement with contracts = [] must fail."""
        self.use_single_contract_surface()
        self.guest_file.write_text("pub fn old_futex() -> i32 { 1 }\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "seed old_futex"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        zone_wait = self.guest_file.with_name("zone_wait.rs")
        subprocess.run(["git", "mv", str(self.guest_file), str(zone_wait)], cwd=self.repo, check=True)
        zone_wait.write_text(
            "".join(f"pub fn completely_new_zone_line_{i}() -> usize {{ {i} }}\n" for i in range(30)),
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\n'
                'path = "crates/carrick-kernel/src/dispatch/zone_wait.rs"\n'
                'contracts = []\n'
            )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "attempt Repro E2 D+A replacement bypass"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("crates/carrick-kernel/src/dispatch/futex.rs", res.stderr)

    def test_p2_backslash_newline_in_string_and_unresolved_added_binding_fails(self):
        """P2: backslash-continued strings must preserve line numbers, and an unresolved added binding must fail even when another valid binding exists."""
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        self.guest_file.write_text(
            'const MSG: &str = "line one \\\nline two \\\nline three";\n'
            "pub fn unchanged_fn() -> u32 { 1 }\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed backslash-continued string"], cwd=self.repo, check=True)
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, capture_output=True, text=True
        ).stdout.strip()

        # Append an unresolvable binding to a contract that ALREADY has a valid pre-existing binding
        self.guest_file.write_text(
            'const MSG: &str = "line one \\\nline two \\\nline three";\n'
            "pub fn unchanged_fn() -> u32 { 2 }\n",
            encoding="utf-8",
        )
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            contract_toml.read_text(encoding="utf-8").replace(
                'vm_free = "carrick-kernel-example::futex_contention_contract"',
                'vm_free = "carrick-kernel-example::futex_contention_contract; carrick-kernel::nonexistent::bogus_test"',
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "add unresolved binding alongside existing valid binding"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("carrick-kernel::nonexistent::bogus_test", res.stderr)

    def test_bypass_p0_1_preexisting_unresolved_binding_created_empty_at_head_fails(self):
        """P0-1: a binding present in base TOML that did not resolve at base must be treated as added at HEAD (relevance required)."""
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-vfs::serial_host::test_namespace_mutation_work"\n',
            encoding="utf-8",
        )
        vfs_crate = self.repo / "crates" / "carrick-vfs"
        (vfs_crate / "src").mkdir(parents=True, exist_ok=True)
        (vfs_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-vfs"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        (vfs_crate / "src" / "lib.rs").write_text("pub fn vfs_stub() {}\n", encoding="utf-8")
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\npath = "crates/carrick-vfs/src/lib.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed unresolved base binding"], cwd=self.repo, check=True)
        base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

        # At HEAD, create serial_host.rs with an empty test and modify the guest surface
        self.guest_file.write_text("pub fn rootfs_mutate_namespace() -> i32 { 1 }\n", encoding="utf-8")
        serial_host = vfs_crate / "tests" / "serial_host.rs"
        serial_host.parent.mkdir(parents=True, exist_ok=True)
        serial_host.write_text("#[test]\nfn test_namespace_mutation_work() {}\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "add empty test for base-unresolved binding"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("does not reference changed surface", res.stderr)

        # Positive control: when the newly created test actually references the changed item, it passes
        serial_host.write_text(
            "#[test]\nfn test_namespace_mutation_work() { let _ = rootfs_mutate_namespace(); }\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "exercise changed surface item"], cwd=self.repo, check=True)
        res_ok = self.run_check(base_sha=base_sha)
        self.assertEqual(res_ok.returncode, 0, msg=f"stdout: {res_ok.stdout}, stderr: {res_ok.stderr}")

    def test_bypass_p0_2a_test_inside_uninvoked_macro_rules_fails(self):
        """P0-2(a,c): a #[test] fn inside an uninvoked macro_rules! body (paren or bracket delimiter) must not resolve or satisfy relevance."""
        for open_d, close_d, semi in (("(", ")", ";"), ("[", "]", ";")):
            with self.subTest(delim=open_d):
                self.use_single_contract_surface()
                self.guest_file.write_text("// base futex\n", encoding="utf-8")
                contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
                contract_toml.write_text(
                    'schema_version = 1\n'
                    'id = "kernel.futex.contention"\n'
                    'title = "Futex contention"\n'
                    '[bindings]\n'
                    'docker = "probe:futex"\n',
                    encoding="utf-8",
                )
                subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
                subprocess.run(["git", "commit", "-m", "seed macro_rules test case", "--allow-empty"], cwd=self.repo, check=True)
                base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

                self.guest_file.write_text(
                    "pub fn futex_macro_target() -> i32 { 7 }\n"
                    "#[cfg(test)]\nmod tests {\n"
                    f"    macro_rules! uninvoked_tests {open_d}\n"
                    f"        () => {open_d}\n"
                    "            #[test]\n"
                    "            fn fake_macro_test() { let _ = futex_macro_target(); }\n"
                    f"        {close_d};\n"
                    f"    {close_d}{semi}\n"
                    "}\n",
                    encoding="utf-8",
                )
                contract_toml.write_text(
                    'schema_version = 1\n'
                    'id = "kernel.futex.contention"\n'
                    'title = "Futex contention"\n'
                    '[bindings]\n'
                    'vm_free = "carrick-kernel::dispatch::futex::tests::fake_macro_test"\n',
                    encoding="utf-8",
                )
                subprocess.run(["git", "commit", "-am", "add test inside uninvoked macro_rules"], cwd=self.repo, check=True)
                res = self.run_check(base_sha=base_sha)
                self.assertEqual(res.returncode, 1, msg=f"delim={open_d} stdout: {res.stdout}, stderr: {res.stderr}")

    def test_bypass_p0_2b_cfg_attr_not_test_and_scoped_inner_cfg_fails(self):
        """P0-2(b): cfg_attr(test, cfg(not(test))) and inline #![cfg(not(test))] / #![cfg_attr(test, cfg(not(test)))] must fail closed."""
        for bad_mod_src in (
            '#[cfg(test)]\nmod tests {\n    #[cfg_attr(test, cfg(not(test)))]\n    #[test]\n    fn disabled_test() {}\n}\n',
            '#[cfg(test)]\n#[cfg_attr(test, cfg(not(test)))]\nmod tests {\n    #[test]\n    fn disabled_test() {}\n}\n',
            '#[cfg(test)]\nmod tests {\n    #![cfg(not(test))]\n    #[test]\n    fn disabled_test() {}\n}\n',
            '#[cfg(test)]\nmod tests {\n    #![cfg_attr(test, cfg(not(test)))]\n    #[test]\n    fn disabled_test() {}\n}\n',
            '#[cfg(test)]\nmod tests {\n    #[cfg_attr(unknown_ci_predicate, cfg(not(test)))]\n    #[test]\n    fn disabled_test() {}\n}\n',
        ):
            with self.subTest(bad_mod_src=bad_mod_src):
                self.seed_resolution_case(
                    {
                        "src/lib.rs": "mod dispatch;\nmod witness;\n",
                        "src/witness.rs": bad_mod_src,
                    },
                    "carrick-kernel::witness::tests::disabled_test",
                )
                res = self.run_check()
                self.assertEqual(res.returncode, 1, msg=f"src={bad_mod_src!r}\nstdout: {res.stdout}\nstderr: {res.stderr}")

        # Positive control: an inner `#![cfg(not(test))]` inside an unrelated inline module does not poison sibling `mod tests`
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\nmod witness;\n",
                "src/witness.rs": (
                    "mod unrelated_disabled {\n    #![cfg(not(test))]\n}\n"
                    "#[cfg(test)]\nmod tests {\n    #[test]\n    fn enabled_test() {}\n}\n"
                ),
            },
            "carrick-kernel::witness::tests::enabled_test",
        )
        res_ok = self.run_check()
        self.assertEqual(res_ok.returncode, 0, msg=f"stdout: {res_ok.stdout}\nstderr: {res_ok.stderr}")

    def test_bypass_p1_1_added_module_or_target_binding_without_leaf_fn_fails(self):
        """P1-1: an added binding that names a module or integration target (no leaf test fn) must fail."""
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futex"\n',
            encoding="utf-8",
        )
        embed_crate = self.repo / "crates" / "carrick-embed"
        (embed_crate / "src").mkdir(parents=True, exist_ok=True)
        (embed_crate / "tests").mkdir(parents=True, exist_ok=True)
        (embed_crate / "Cargo.toml").write_text(
            '[package]\nname = "carrick-embed"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\n"*" = "host"\n',
            encoding="utf-8",
        )
        (embed_crate / "src" / "lib.rs").write_text("pub fn stub() {}\n", encoding="utf-8")
        (embed_crate / "tests" / "el1_sched.rs").write_text(
            "#[test]\nfn some_sched_test() { let _ = futex_portal_entry(); }\n",
            encoding="utf-8",
        )
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                '\n[[surfaces]]\npath = "crates/carrick-embed/src/lib.rs"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed carrick-embed el1_sched target"], cwd=self.repo, check=True)
        base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

        self.guest_file.write_text("pub fn futex_portal_entry() -> i32 { 1 }\n", encoding="utf-8")
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-embed::el1_sched"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "bind integration target without leaf fn"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_bypass_p1_2_r100_rename_of_mapped_surface_to_unmapped_path_fails(self):
        """P1-2: an R100 byte-identical rename of a mapped surface to an unmapped path must fail unless surfaces.toml carries the mapping."""
        self.use_single_contract_surface()
        new_path = self.guest_file.parent / "futex_unmapped.rs"
        subprocess.run(["git", "mv", str(self.guest_file), str(new_path)], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "R100 rename mapped surface without updating surfaces.toml"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_bypass_p1_3_gutting_only_preexisting_bound_test_in_same_pr_fails(self):
        """P1-3: gutting the only pre-existing bound test in the same PR as a surface edit must fail."""
        self.seed_resolution_case(
            {
                "src/lib.rs": "mod dispatch;\n#[cfg(test)] mod tests;\n",
                "src/tests.rs": "#[test] fn bound_test() { let _ = changed_futex(); assert_eq!(1, 1); }\n",
            },
            "carrick-kernel::tests::bound_test",
        )
        tests_rs = self.repo / "crates" / "carrick-kernel" / "src" / "tests.rs"
        tests_rs.write_text("#[test] fn bound_test() {}\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "gut pre-existing bound test in same PR"], cwd=self.repo, check=True)

        res = self.run_check()
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")

    def test_bypass_p2_1_dedicated_unit_test_file_assert_true_without_surface_ref_fails(self):
        """P2-1: an added binding in <stem>/tests/mod.rs or <stem>/tests.rs with only assert!(true) must fail relevance."""
        self.use_single_contract_surface()
        contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'docker = "probe:futex"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "seed contract without vm_free"], cwd=self.repo, check=True)
        base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

        unit_mod_path = "crates/carrick-kernel/src/dispatch/futex/tests/mod.rs"
        unit_mod = self.repo / unit_mod_path
        unit_mod.parent.mkdir(parents=True, exist_ok=True)
        unit_mod.write_text("#[test]\nfn trivial_test() { assert!(true); }\n", encoding="utf-8")
        with (self.repo / "conformance-contracts" / "surfaces.toml").open("a", encoding="utf-8") as f:
            f.write(
                f'\n[[surfaces]]\npath = "{unit_mod_path}"\n'
                'contracts = ["kernel.futex.contention"]\n'
            )
        self.guest_file.write_text(
            "#[cfg(test)]\nmod tests;\npub fn futex_real_change() -> i32 { 1 }\n",
            encoding="utf-8",
        )
        contract_toml.write_text(
            'schema_version = 1\n'
            'id = "kernel.futex.contention"\n'
            'title = "Futex contention"\n'
            '[bindings]\n'
            'vm_free = "carrick-kernel::dispatch::futex::tests::trivial_test"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "add trivial unit test in futex/tests/mod.rs"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 1, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn("does not reference changed surface", res.stderr)

    def test_bypass_p2_2_stringify_string_literal_or_local_let_binding_relevance_fails(self):
        """P2-2: mentioning a changed surface identifier only in a string literal, stringify!(), or local let binding must fail relevance."""
        for body_expr in (
            "let _ = stringify!(futex_target_fn);",
            "let futex_target_fn = 123;",
            "let mut futex_target_fn: u64 = 123;",
            'let _ = "futex_target_fn";',
        ):
            with self.subTest(body_expr=body_expr):
                self.use_single_contract_surface()
                self.guest_file.write_text("// base futex\n", encoding="utf-8")
                contract_toml = self.repo / "conformance-contracts" / "contracts" / "futex-contention.toml"
                contract_toml.write_text(
                    'schema_version = 1\n'
                    'id = "kernel.futex.contention"\n'
                    'title = "Futex contention"\n'
                    '[bindings]\n'
                    'docker = "probe:futex"\n',
                    encoding="utf-8",
                )
                subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
                subprocess.run(["git", "commit", "-m", "reset base for p2_2", "--allow-empty"], cwd=self.repo, check=True)
                base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()

                self.guest_file.write_text(
                    "pub fn futex_target_fn() -> i32 { 1 }\n"
                    f"#[cfg(test)]\nmod tests {{\n    #[test]\n    fn fake_ref() {{ {body_expr} }}\n}}\n",
                    encoding="utf-8",
                )
                contract_toml.write_text(
                    'schema_version = 1\n'
                    'id = "kernel.futex.contention"\n'
                    'title = "Futex contention"\n'
                    '[bindings]\n'
                    'vm_free = "carrick-kernel::dispatch::futex::tests::fake_ref"\n',
                    encoding="utf-8",
                )
                subprocess.run(["git", "commit", "-am", "attempt stringify/let relevance bypass"], cwd=self.repo, check=True)
                res = self.run_check(base_sha=base_sha)
                self.assertEqual(res.returncode, 1, msg=f"expr={body_expr!r}\nstdout: {res.stdout}\nstderr: {res.stderr}")
                self.assertIn("does not reference changed surface", res.stderr)


if __name__ == "__main__":
    unittest.main()
