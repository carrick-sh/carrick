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

    def use_single_contract_surface(self):
        (self.repo / "conformance-contracts" / "surfaces.toml").write_text(
            '[[surfaces]]\n'
            'path = "crates/carrick-kernel/src/dispatch/futex.rs"\n'
            'contracts = ["kernel.futex.contention"]\n'
        )

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
        unit_path = "crates/carrick-kernel/src/dispatch/futex_tests.rs"
        unit = self.repo / unit_path
        unit.write_text("#[test] fn checks_futex() {}\n", encoding="utf-8")
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
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify guest and unit binding"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_registered_rust_tests_module_is_evidence(self):
        self.use_single_contract_surface()
        unit_path = "crates/carrick-kernel/src/dispatch/futex/tests.rs"
        unit = self.repo / unit_path
        unit.parent.mkdir(parents=True)
        unit.write_text("#[test] fn checks_futex() {}\n", encoding="utf-8")
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
        self.guest_file.write_text("// modified futex implementation\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "modify guest and Rust tests module"], cwd=self.repo, check=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

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
        semantics_main = self.repo / "crates" / "carrick-kernel-example" / "tests" / "semantics" / "main.rs"
        semantics_main.parent.mkdir(parents=True, exist_ok=True)
        semantics_main.write_text("mod futex_contention;\nmod futex_requeue;\n", encoding="utf-8")
        self.vm_free_binding_file.write_text(
            "#[test]\nfn futex_contention_contract() {}\n",
            encoding="utf-8",
        )
        requeue_file = self.repo / "crates" / "carrick-kernel-example" / "tests" / "semantics" / "futex_requeue.rs"
        requeue_file.write_text(
            "#[test]\nfn futex_requeue_contract() {}\n",
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

    def test_contract_without_any_gated_bound_test_fails(self):
        self.seed_gated_futex_contracts()
        self.use_single_contract_surface()
        cargo_toml = self.repo / "crates" / "carrick-kernel-example" / "Cargo.toml"
        cargo_toml.write_text(
            '[package]\nname = "carrick-kernel-example"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[package.metadata.carrick.test-lanes]\nsemantics = { lane = "manual", reason = "not gated in CI" }\n',
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
        self.vm_free_binding_file.write_text("// test function removed\n", encoding="utf-8")
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
            'vm_free = "carrick-kernel-example::futex_contention_contract"\n'
            'docker = "probe:futexpingpong"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "add binding referencing changed surface item"], cwd=self.repo, check=True)

        res = self.run_check(base_sha=base_sha)
        self.assertEqual(res.returncode, 0, msg=f"stdout: {res.stdout}, stderr: {res.stderr}")
        self.assertIn(
            "evidenced: crates/carrick-kernel/src/dispatch/futex.rs -> kernel.futex.contention: carrick-kernel-example::futex_contention_contract",
            res.stdout,
        )


if __name__ == "__main__":
    unittest.main()

