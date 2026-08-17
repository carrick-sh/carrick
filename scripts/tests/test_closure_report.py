#!/usr/bin/env python3

import importlib.util
import json
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


def inventory():
    return json.loads(
        (ROOT / "conformance-probes/probe-inventory.json").read_text(encoding="utf-8")
    )


def complete_probe_log(overrides=None, extras=None):
    overrides = overrides or {}
    lines = []
    for libc in ["gnu", "musl"]:
        for name, row in sorted(inventory().items()):
            if row["class"] != "conformance":
                continue
            status = overrides.get((libc, name), "PASS")
            if row["runner"] == "generic":
                lines.append(f"CLOSURE_PROBE GENERIC {status} arm64:{libc}:{name}")
            else:
                lines.append(
                    f"CLOSURE_PROBE SCENARIO {status} arm64:{libc}:{name} "
                    f"runner={row['runner']}"
                )
    lines.extend(extras or [])
    return "\n".join(lines) + "\n"


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

        self.assertEqual(
            summary["semantic_gaps"],
            [
                {
                    "suite": "ltp-futex",
                    "assertion": "futex.c:42#1",
                    "carrick": "fail",
                    "docker": "ok",
                }
            ],
        )
        self.assertEqual(summary["infrastructure_failures"], ["ltp-tracefs"])
        self.assertEqual(
            summary["unexercised"],
            [
                {
                    "suite": "ltp-cgroup",
                    "assertion": "cgroup.c:1#1",
                    "carrick": "conf",
                    "docker": "conf",
                }
            ],
        )
        self.assertEqual(summary["pathological"], ["ltp-munmap04"])

    def test_suite_can_contribute_semantic_and_unexercised_assertions(self):
        scope = scope_2127()
        scope["suite_names"][0] = "ltp-mixed"
        results = [result(name) for name in scope["suite_names"]]
        results[0] = result(
            "ltp-mixed",
            verdict="incomplete",
            skipped=1,
            pairs={
                "mixed.c:10#1": ["fail", "ok"],
                "mixed.c:20#1": ["fail", "conf"],
            },
        )

        summary = closure_report.summarize(scope, results)

        self.assertEqual(
            [row["assertion"] for row in summary["semantic_gaps"]],
            ["mixed.c:10#1", "mixed.c:20#1"],
        )
        self.assertEqual(
            [row["assertion"] for row in summary["unexercised"]],
            ["mixed.c:20#1"],
        )

    def test_both_success_zero_assertion_suite_is_retained_as_unexercised(self):
        scope = scope_2127()
        scope["suite_names"][0] = "cpython-zero"
        results = [result(name) for name in scope["suite_names"]]
        zero = result("cpython-zero", verdict="incomplete", ratio=20.0)
        zero["carrick"]["totals"] = {
            "n": 0,
            "passed": 0,
            "failed": 0,
            "broken": 0,
            "skipped": 0,
        }
        zero["docker"]["totals"] = dict(zero["carrick"]["totals"])
        zero["pairs"] = {}
        results[0] = zero

        summary = closure_report.summarize(scope, results)

        self.assertIn(
            {
                "suite": "cpython-zero",
                "assertion": "<no assertions>",
                "carrick": "absent",
                "docker": "absent",
            },
            summary["unexercised"],
        )
        self.assertNotIn("cpython-zero", summary["verified"])
        self.assertNotIn("cpython-zero", summary["pathological"])

        malformed = [dict(row) for row in results]
        malformed_zero = dict(zero)
        malformed_zero["carrick"] = {
            "result": "success",
            "totals": {"n": 1, "passed": 1, "failed": 0, "broken": 0, "skipped": 0},
        }
        malformed[0] = malformed_zero
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, malformed)

    def test_post_assertion_process_failure_is_infrastructure_not_assertion_semantics(self):
        scope = scope_2127()
        scope["suite_names"][0] = "ltp-post-assertion"
        results = [result(name) for name in scope["suite_names"]]
        process_failure = result(
            "ltp-post-assertion",
            verdict="incomplete",
            pairs={
                "msgstress.c:10#1": ["ok", "ok"],
                "msgstress.c:20#1": ["ok", "ok"],
            },
            ratio=20.0,
        )
        equal_totals = {
            "n": 2,
            "passed": 2,
            "failed": 0,
            "broken": 0,
            "skipped": 0,
        }
        process_failure["carrick"] = {
            "result": "failure",
            "totals": dict(equal_totals),
        }
        process_failure["docker"] = {
            "result": "success",
            "totals": dict(equal_totals),
        }
        results[0] = process_failure

        summary = closure_report.summarize(scope, results)

        self.assertIn("ltp-post-assertion", summary["infrastructure_failures"])
        self.assertFalse(
            any(row["suite"] == "ltp-post-assertion" for row in summary["semantic_gaps"])
        )
        self.assertNotIn("ltp-post-assertion", summary["verified"])
        self.assertNotIn("ltp-post-assertion", summary["pathological"])

        semantic_results = list(results)
        semantic_failure = dict(process_failure)
        semantic_failure["pairs"] = {"msgstress.c:10#1": ["fail", "ok"]}
        semantic_results[0] = semantic_failure
        semantic_summary = closure_report.summarize(scope, semantic_results)
        self.assertIn(
            "msgstress.c:10#1",
            [row["assertion"] for row in semantic_summary["semantic_gaps"]],
        )
        self.assertNotIn(
            "ltp-post-assertion", semantic_summary["infrastructure_failures"]
        )

    def test_report_rejects_unexpected_rows_and_malformed_performance(self):
        scope = scope_2127()
        complete = [result(name) for name in scope["suite_names"]]
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, complete[:-1] + [result("unexpected")])

        malformed = complete[0]
        malformed["perf"]["carrick_to_oracle_ratio"] = "ten"
        with self.assertRaises(closure_report.ReportError):
            closure_report.summarize(scope, complete)

    def test_probe_log_retains_complete_red_terminal_rows(self):
        overrides = {
            ("gnu", "abortdeath"): "FAIL",
            ("gnu", "acceptsock"): "DIFF",
            ("musl", "accessx"): "ERROR",
            ("musl", "accounting"): "SKIP",
            ("gnu", "bridge_tcp_peer"): "NOTE",
        }

        summary = closure_report.validate_probe_log(
            complete_probe_log(
                overrides,
                extras=["CLOSURE_PROBE_DETAIL arm64:gnu:abortdeath line mismatch"],
            ),
            inventory(),
        )

        self.assertEqual(summary["rows"], 858)
        self.assertEqual(summary["passed"], 853)
        self.assertEqual(
            {(row["libc"], row["source"]) for row in summary["failures"]},
            {("gnu", "abortdeath"), ("gnu", "acceptsock")},
        )
        self.assertEqual(
            {(row["libc"], row["source"]) for row in summary["infrastructure_failures"]},
            {("musl", "accessx"), ("gnu", "bridge_tcp_peer")},
        )
        self.assertEqual(
            {(row["libc"], row["source"]) for row in summary["unexercised"]},
            {("musl", "accounting"), ("gnu", "bridge_tcp_peer")},
        )

    def test_probe_log_rejects_duplicate_unknown_and_standalone_terminal_rows(self):
        all_pass = complete_probe_log()
        unknown = "CLOSURE_PROBE GENERIC ERROR arm64:gnu:not_in_inventory"
        standalone = "SKIP arm64:gnu:abortdeath oracle unavailable"
        duplicate_red = [
            f"CLOSURE_PROBE GENERIC {status} arm64:gnu:abortdeath"
            for status in ["FAIL", "SKIP", "NOTE"]
        ]
        for extra in duplicate_red + [unknown, standalone]:
            with self.subTest(extra=extra):
                with self.assertRaises(closure_report.ReportError):
                    closure_report.validate_probe_log(
                        all_pass + extra + "\n", inventory()
                    )

    def test_probe_log_rejects_raw_dedicated_skip_note_and_cargo_failure(self):
        all_pass = complete_probe_log()
        forbidden = [
            "SKIP conformance_bridge_tcp_peer: target/release/carrick not built",
            "NOTE conformance_bridge_publish_tcp: Docker oracle unavailable",
            "test conformance_bridge_udp_peer ... FAILED",
        ]
        for raw_line in forbidden:
            with self.subTest(raw_line=raw_line):
                with self.assertRaises(closure_report.ReportError):
                    closure_report.validate_probe_log(
                        all_pass + raw_line + "\n", inventory()
                    )

    def test_probe_log_rejects_raw_generic_fail_and_error(self):
        all_pass = complete_probe_log()
        for raw_line in [
            "FAIL arm64:gnu:abortdeath",
            "ERROR arm64:musl:acceptsock (read probe failed)",
        ]:
            with self.subTest(raw_line=raw_line):
                with self.assertRaises(closure_report.ReportError):
                    closure_report.validate_probe_log(
                        all_pass + raw_line + "\n", inventory()
                    )

    def test_probe_log_allows_canonical_rows_and_passing_cargo_noise(self):
        log = complete_probe_log(
            extras=["test conformance_bridge_tcp_peer ... ok"]
        )

        summary = closure_report.validate_probe_log(log, inventory())

        self.assertEqual(summary["rows"], 858)
        self.assertEqual(summary["passed"], 858)

    def test_ledger_renders_assertion_and_probe_red_sections(self):
        scope = scope_2127()
        scope["suite_names"][0] = "ltp-red"
        results = [result(name) for name in scope["suite_names"]]
        results[0] = result(
            "ltp-red",
            verdict="incomplete",
            pairs={"red.c:7#1": ["fail", "conf"]},
            skipped=1,
        )
        suite_summary = closure_report.summarize(scope, results)
        probe_summary = closure_report.validate_probe_log(
            complete_probe_log({("gnu", "abortdeath"): "FAIL"}), inventory()
        )

        ledger = closure_report.render_ledger(
            scope,
            suite_summary,
            probe_summary,
            Path("results.jsonl"),
            Path("probes.log"),
        )

        self.assertIn("`red.c:7#1`", ledger)
        self.assertIn("## Probe semantic failures", ledger)
        self.assertIn("`abortdeath`", ledger)


if __name__ == "__main__":
    unittest.main()
