"""Host-only behavior tests for the signed-test argument boundary."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ARG_LIBRARY = REPOSITORY_ROOT / "scripts/lib/test-signed-args.sh"
TEST_SIGNED = REPOSITORY_ROOT / "scripts/test-signed.sh"


class SignedTestArgumentTests(unittest.TestCase):
    def call_library(self, body: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", body, "test-signed-args", str(ARG_LIBRARY), *args],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def validate_run_id(self, run_id: str) -> subprocess.CompletedProcess[str]:
        return self.call_library(
            '. "$1"; test_signed_validate_run_id "$2"',
            run_id,
        )

    def parse_args(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.call_library(
            '. "$1"; shift; test_signed_parse_libtest_args "$@" || exit $?; '
            'printf "%s|%s|%s|%s\\n" "$TEST_SIGNED_REQUESTED_FILTER" '
            '"$TEST_SIGNED_HAS_EXACT" "$TEST_SIGNED_IGNORED_ONLY" '
            '"$TEST_SIGNED_INCLUDE_IGNORED"',
            *args,
        )

    def run_script_until_external_work(self, *args: str, run_id: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            fake_git = Path(directory) / "git"
            fake_git.write_text(
                "#!/bin/sh\necho 'test reached git unexpectedly' >&2\nexit 91\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{directory}:{env['PATH']}"
            env["CARRICK_RUN_ID"] = run_id
            return subprocess.run(
                [str(TEST_SIGNED), "carrick-embed", *args],
                cwd=REPOSITORY_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_scoped_run_id_components_are_accepted(self) -> None:
        for run_id in ["embed-signed-123", "7f4e2a", "gate.arm_1"]:
            with self.subTest(run_id=run_id):
                result = self.validate_run_id(run_id)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_global_or_unsafe_run_ids_are_rejected_before_external_work(self) -> None:
        for run_id in ["--all", "unsafe:id", "unsafe/id", "two words", ""]:
            with self.subTest(run_id=run_id):
                result = self.run_script_until_external_work(run_id=run_id)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("invalid CARRICK_RUN_ID", result.stderr)
                self.assertNotIn("test reached git unexpectedly", result.stderr)

    def test_supported_receipted_libtest_grammar_is_parsed_exactly(self) -> None:
        cases = [
            ((), "|0|0|0"),
            (("captured_", "--nocapture"), "captured_|0|0|0"),
            (
                (
                    "production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ),
                "production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle|1|1|0",
            ),
            (("case_", "--include-ignored", "--show-output"), "case_|0|0|1"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.parse_args(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_skip_and_value_options_cannot_be_misclassified_as_positive_filters(self) -> None:
        for args in [
            ("--skip", "syscall_interceptor_rewrites_and_replaces"),
            ("--test-threads", "1"),
            ("--test-threads=1",),
            ("--format", "terse"),
            ("--format=json",),
            ("--", "--nocapture"),
            ("first_filter", "second_filter"),
        ]:
            with self.subTest(args=args):
                result = self.parse_args(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("unsupported receipted libtest arguments", result.stderr)

        integrated = self.run_script_until_external_work(
            "--skip",
            "syscall_interceptor_rewrites_and_replaces",
            run_id="embed-script-test",
        )
        self.assertEqual(integrated.returncode, 2, integrated.stderr)
        self.assertIn("unsupported receipted libtest arguments", integrated.stderr)
        self.assertNotIn("test reached git unexpectedly", integrated.stderr)

    def test_exact_requires_one_filter_and_ignored_modes_do_not_conflict(self) -> None:
        for args in [
            ("--exact",),
            ("case_", "--ignored", "--include-ignored"),
        ]:
            with self.subTest(args=args):
                result = self.parse_args(*args)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_failed_atomic_receipt_publication_is_not_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_mv = root / "mv"
            fake_mv.write_text("#!/bin/sh\nexit 73\n", encoding="utf-8")
            fake_mv.chmod(0o755)
            temporary_receipt = root / "receipt.tmp"
            canonical_receipt = root / "receipt.jsonl"
            temporary_receipt.write_text('{"record_type":"header"}\n', encoding="utf-8")
            env = os.environ.copy()
            env["PATH"] = f"{root}:{env['PATH']}"

            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    '. "$1"; test_signed_publish_receipt "$2" "$3" "test-signed: OK (fixture)"',
                    "test-signed-publish",
                    str(ARG_LIBRARY),
                    str(temporary_receipt),
                    str(canonical_receipt),
                ],
                cwd=REPOSITORY_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("failed to publish receipt", result.stderr)
            self.assertNotIn("test-signed: receipt ", result.stdout)
            self.assertNotIn("test-signed: OK", result.stdout)
            self.assertFalse(canonical_receipt.exists())
            self.assertTrue(temporary_receipt.exists())

    def test_success_claim_is_emitted_after_atomic_receipt_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary_receipt = root / "receipt.tmp"
            canonical_receipt = root / "receipt.jsonl"
            temporary_receipt.write_text('{"record_type":"header"}\n', encoding="utf-8")

            result = self.call_library(
                '. "$1"; test_signed_publish_receipt "$2" "$3" "test-signed: OK (fixture)"',
                str(temporary_receipt),
                str(canonical_receipt),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    f"test-signed: receipt {canonical_receipt}",
                    "test-signed: OK (fixture)",
                ],
            )
            self.assertTrue(canonical_receipt.exists())
            self.assertFalse(temporary_receipt.exists())


if __name__ == "__main__":
    unittest.main()
