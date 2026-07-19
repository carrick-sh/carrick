#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("native-x86-ltp-gate.py")
SPEC = importlib.util.spec_from_file_location("native_x86_ltp_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class NativeX86LtpGateTests(unittest.TestCase):
    def test_extracts_ordered_verdict_lines_and_counts(self) -> None:
        output = """noise
getpid01.c:32: TPASS: getpid() returns 123
case.c:9: TCONF: unavailable
case.c:10: TFAIL: mismatch
[native_run] exit=1 traps=4
"""
        lines = GATE.assertion_lines(output)
        self.assertEqual(
            lines,
            [
                "getpid01.c:32: TPASS: getpid() returns 123",
                "case.c:9: TCONF: unavailable",
                "case.c:10: TFAIL: mismatch",
            ],
        )
        self.assertEqual(
            GATE.assertion_counts(lines),
            {"TPASS": 1, "TFAIL": 1, "TBROK": 0, "TCONF": 1},
        )

    def test_local_status_is_fail_closed(self) -> None:
        empty = {marker: 0 for marker in GATE.RESULT_MARKERS}
        passed = dict(empty, TPASS=2)
        broken = dict(passed, TBROK=1)
        configured_out = dict(empty, TCONF=1)
        self.assertEqual(GATE.local_status(0, False, passed), "pass")
        self.assertEqual(GATE.local_status(0, False, broken), "ltp_failure")
        self.assertEqual(GATE.local_status(0, False, configured_out), "conf")
        self.assertEqual(GATE.local_status(32, False, configured_out), "conf")
        self.assertEqual(GATE.local_status(0, False, empty), "no_assertions")
        self.assertEqual(GATE.local_status(125, False, passed), "runner_error")
        self.assertEqual(GATE.local_status(None, True, passed), "timeout")

    def test_case_manifest_rejects_escape_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "cases.txt"
            manifest.write_text("a one/a\na two/a\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                GATE.load_cases(manifest)
            manifest.write_text("a ../escape\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stay below"):
                GATE.load_cases(manifest)


if __name__ == "__main__":
    unittest.main()
