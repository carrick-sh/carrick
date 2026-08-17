#!/usr/bin/env python3

import importlib.util
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "conformance" / "closure-probe-scenarios.py"
SPEC = importlib.util.spec_from_file_location("closure_probe_scenarios", MODULE_PATH)
scenarios = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(scenarios)


class ClosureProbeScenarioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads(
            (ROOT / "conformance-probes/probe-inventory.json").read_text(encoding="utf-8")
        )

    def test_plan_selects_exactly_twenty_dedicated_sources_and_fourteen_runners(self):
        plan = scenarios.build_plan(self.inventory)

        self.assertEqual(len(plan.sources), 20)
        self.assertEqual(len(plan.commands), 14)
        self.assertEqual(
            {command.test_target for command in plan.commands}, {"conformance", "serve"}
        )
        self.assertEqual(
            [source.name for source in plan.sources], sorted(source.name for source in plan.sources)
        )

    def test_expected_rows_cover_every_dedicated_source_under_both_arm64_libcs(self):
        plan = scenarios.build_plan(self.inventory)
        rows = scenarios.expected_rows(plan)

        self.assertEqual(len(rows), 40)
        self.assertEqual({row.libc for row in rows}, {"musl", "gnu"})
        for source in plan.sources:
            self.assertEqual(
                [(row.libc, row.source) for row in rows if row.source == source.name],
                [("gnu", source.name), ("musl", source.name)],
            )

    def test_postcondition_rejects_missing_duplicate_and_unexpected_rows(self):
        plan = scenarios.build_plan(self.inventory)
        expected = [
            scenarios.TerminalRow(row.libc, row.source, row.runner, "PASS", "")
            for row in scenarios.expected_rows(plan)
        ]

        scenarios.validate_completed(plan, expected)
        for completed in [expected[:-1], expected + [expected[0]]]:
            with self.assertRaises(scenarios.ScenarioError):
                scenarios.validate_completed(plan, completed)

        unexpected = list(expected)
        unexpected[-1] = scenarios.TerminalRow(
            "musl", "not-in-inventory", "runner", "PASS", ""
        )
        with self.assertRaises(scenarios.ScenarioError):
            scenarios.validate_completed(plan, unexpected)

    def test_runner_classifies_an_oracle_unavailable_note_even_when_cargo_is_green(self):
        command = scenarios.RunnerCommand(
            "conformance_bridge_publish_tcp",
            "conformance",
            ("bridge_publish_tcp",),
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "running 1 test\n"
                "NOTE conformance_bridge_publish_tcp: Docker oracle unavailable\n"
                "test conformance_bridge_publish_tcp ... ok\n"
            ),
            stderr="",
        )
        with mock.patch.object(scenarios.subprocess, "run", return_value=completed):
            result = scenarios._run_command(ROOT, command, "musl")

        self.assertEqual(result.status, "NOTE")

    def test_plan_runs_later_functions_and_libcs_after_an_early_failure(self):
        plan = scenarios.build_plan(self.inventory)
        calls = []

        def fake_runner(_root, command, libc):
            calls.append((libc, command.runner))
            status = "FAIL" if len(calls) == 1 else "PASS"
            return scenarios.CommandResult(status, f"output-{len(calls)}", "synthetic")

        with redirect_stdout(StringIO()):
            rows = scenarios.run_plan(ROOT, plan, command_runner=fake_runner)

        self.assertEqual(len(calls), 28)
        self.assertEqual({libc for libc, _runner in calls}, {"gnu", "musl"})
        self.assertEqual(len(rows), 40)
        self.assertEqual(
            sum(row.status == "FAIL" for row in rows),
            len(plan.commands[0].sources),
        )
        self.assertEqual(calls[-1], ("musl", plan.commands[-1].runner))

    def test_plan_prefixes_raw_cargo_failure_output_as_nonterminal_detail(self):
        plan = scenarios.build_plan(self.inventory)

        def fake_runner(_root, command, _libc):
            return scenarios.CommandResult(
                "FAIL",
                f"test {command.runner} ... FAILED\n",
                "synthetic failure",
            )

        output = StringIO()
        with redirect_stdout(output):
            scenarios.run_plan(ROOT, plan, command_runner=fake_runner)

        rendered = output.getvalue()
        self.assertNotIn("\ntest conformance_bridge_compose_pair ... FAILED\n", rendered)
        self.assertIn(
            "CLOSURE_PROBE_DETAIL gnu:conformance_bridge_compose_pair: "
            "test conformance_bridge_compose_pair ... FAILED",
            rendered,
        )
        self.assertIn(
            "CLOSURE_PROBE SCENARIO FAIL arm64:gnu:bridge_compose_client",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
