#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "conformance" / "closure-report.py"
SPEC = importlib.util.spec_from_file_location("closure_report", MODULE_PATH)
closure_report = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(closure_report)


def scope_2127():
    return {
        "suite_count": 2127,
        "suite_names": [f"suite-{index:04d}" for index in range(2127)],
    }


def result(name, *, verdict="match", pairs=None, skipped=0, broken=0, ratio=1.0):
    return {
        "name": name,
        "verdict": verdict,
        "carrick": {
            "result": "success",
            "totals": {"n": 1, "passed": 1, "failed": 0, "broken": broken, "skipped": skipped},
        },
        "docker": {
            "result": "success",
            "totals": {"n": 1, "passed": 1, "failed": 0, "broken": 0, "skipped": 0},
        },
        "pairs": pairs or {"assertion#1": ["ok", "ok"]},
        "new_diffs": [],
        "perf": {
            "carrick_ms": int(ratio * 100),
            "oracle_ms": 100,
            "carrick_to_oracle_ratio": ratio,
        },
    }


class ClosureReportTest(unittest.TestCase):
    def test_report_requires_all_2127_unique_rows(self):
        scope = scope_2127()
        complete = [result(name) for name in scope["suite_names"]]

        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, complete[:-1])

        duplicate = complete[:-1] + [complete[0]]
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, duplicate)

    def test_report_separates_semantic_infrastructure_unexercised_and_pathological_rows(self):
        scope = scope_2127()
        scope["suite_names"][:4] = [
            "ltp-cgroup",
            "ltp-futex",
            "ltp-munmap04",
            "ltp-tracefs",
        ]
        results = [result(name) for name in scope["suite_names"][4:]] + [
            result(
                "ltp-futex",
                verdict="incomplete",
                pairs={"futex.c:42#1": ["fail", "ok"]},
            ),
            result(
                "ltp-tracefs",
                verdict="incomplete",
                broken=1,
                pairs={"tst_test.c:1#1": ["broken", "ok"]},
            ),
            result(
                "ltp-cgroup",
                verdict="incomplete",
                skipped=1,
                pairs={"cgroup.c:1#1": ["conf", "conf"]},
            ),
            result("ltp-munmap04", ratio=12.5),
        ]

        summary = closure_report.summarize(scope, results)

        self.assertEqual(summary["semantic_gaps"], ["ltp-futex"])
        self.assertEqual(summary["infrastructure_failures"], ["ltp-tracefs"])
        self.assertEqual(summary["unexercised"], ["ltp-cgroup"])
        self.assertEqual(summary["pathological"], ["ltp-munmap04"])

    def test_report_rejects_unexpected_rows_and_malformed_performance(self):
        scope = scope_2127()
        complete = [result(name) for name in scope["suite_names"]]
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, complete[:-1] + [result("unexpected")])

        malformed = complete[0]
        malformed["perf"]["carrick_to_oracle_ratio"] = "ten"
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, complete)


if __name__ == "__main__":
    unittest.main()
