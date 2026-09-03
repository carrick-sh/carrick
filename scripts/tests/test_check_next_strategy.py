"""Behavior tests for the conformance-next CI strategy checker."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPOSITORY_ROOT / "scripts/conformance/check-next-strategy.py"
SPEC = importlib.util.spec_from_file_location("check_next_strategy", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
STRATEGY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STRATEGY)


class CheckCiUsesPublicGateTests(unittest.TestCase):
    """Exercise workflow discovery through the checker boundary."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workflows = self.root / ".github/workflows"
        self.workflows.mkdir(parents=True)
        self.original_root = STRATEGY.ROOT
        STRATEGY.ROOT = self.root

    def tearDown(self) -> None:
        STRATEGY.ROOT = self.original_root
        self.tempdir.cleanup()

    def write_workflow(self, name: str, contents: str) -> None:
        (self.workflows / name).write_text(contents, encoding="utf-8")

    def check_error(self) -> str:
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as exit_context:
            with contextlib.redirect_stderr(stderr):
                STRATEGY.check_ci_uses_public_gate()
        self.assertEqual(exit_context.exception.code, 1)
        return stderr.getvalue()

    def test_trusted_environment_prefixed_public_gate_satisfies_hosted_split(self) -> None:
        """Would fail if public-gate detection remains confined to ci.yml."""
        self.write_workflow("ci.yml", "name: hosted\nsteps: []\n")
        self.write_workflow(
            "kernel-runtime.yml",
            "run: RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes\n",
        )

        STRATEGY.check_ci_uses_public_gate()

    def test_inline_list_item_environment_prefixed_public_gate_is_accepted(self) -> None:
        """Would fail if valid list-item run commands were ignored."""
        self.write_workflow("ci.yml", "name: hosted\nsteps: []\n")
        self.write_workflow(
            "kernel-runtime.yml",
            "- run: RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes\n",
        )

        STRATEGY.check_ci_uses_public_gate()

    def test_block_scalar_environment_prefixed_public_gate_is_accepted(self) -> None:
        """Would fail if valid block-scalar run commands were ignored."""
        self.write_workflow("ci.yml", "name: hosted\nsteps: []\n")
        self.write_workflow(
            "kernel-runtime.yml",
            "run: |\n"
            "  RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes\n",
        )

        STRATEGY.check_ci_uses_public_gate()

    def test_unrelated_block_shell_continuation_does_not_break_gate_scan(self) -> None:
        """Would fail if scanning a non-public block parsed each shell fragment."""
        self.write_workflow(
            "ci.yml",
            "run: |\n"
            "  codesign -d --entitlements - target/release/carrick 2>&1 \\\n"
            "    | grep -q com.apple.security.hypervisor\n",
        )
        self.write_workflow("kernel-runtime.yml", "run: just conformance-probes\n")

        STRATEGY.check_ci_uses_public_gate()

    def test_missing_public_gate_fails_closed(self) -> None:
        """Would fail if a workflow set without the public gate were accepted."""
        self.write_workflow("ci.yml", "name: hosted\nsteps: []\n")
        self.write_workflow("kernel-runtime.yml", "name: trusted\nsteps: []\n")

        error = self.check_error()

        self.assertIn("public just conformance-probes gate", error)

    def test_legacy_target_in_any_workflow_fails_and_names_workflow(self) -> None:
        """Would fail if legacy-target scanning skipped trusted workflows."""
        self.write_workflow("ci.yml", "name: hosted\nsteps: []\n")
        self.write_workflow(
            "kernel-runtime.yml",
            "run: just conformance-probes\n"
            "run: cargo test -p carrick-cli --test conformance conformance_probes\n",
        )

        error = self.check_error()

        self.assertIn("kernel-runtime.yml", error)
        self.assertIn("legacy carrick-cli conformance target", error)

    def test_closure_gate_alone_does_not_satisfy_public_gate(self) -> None:
        """Would fail if the closure recipe were mistaken for the public gate."""
        self.write_workflow("ci.yml", "run: just conformance-probes-closure\n")

        error = self.check_error()

        self.assertIn("public just conformance-probes gate", error)


if __name__ == "__main__":
    unittest.main()
