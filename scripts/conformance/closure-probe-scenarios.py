#!/usr/bin/env python3
"""Run the inventory-owned dedicated probe scenarios for closure mode."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, namedtuple
from pathlib import Path
from typing import Any


LIBCS = ("gnu", "musl")
DEDICATED_SOURCE_COUNT = 20
DEDICATED_RUNNER_COUNT = 14
Source = namedtuple("Source", "name runner")
RunnerCommand = namedtuple("RunnerCommand", "runner test_target sources")
Plan = namedtuple("Plan", "sources commands")
CompletedRow = namedtuple("CompletedRow", "libc source runner")
CommandResult = namedtuple("CommandResult", "status output detail")
TerminalRow = namedtuple("TerminalRow", "libc source runner status detail")
TERMINAL_STATUSES = {"PASS", "FAIL", "DIFF", "SKIP", "NOTE", "ERROR"}


class ScenarioError(RuntimeError):
    """The dedicated scenario selection or execution did not close."""


def build_plan(inventory: dict[str, Any]) -> Plan:
    if not isinstance(inventory, dict):
        raise ScenarioError("probe inventory must be an object")
    sources: list[Source] = []
    for name, row in inventory.items():
        if not isinstance(row, dict):
            raise ScenarioError(f"probe row {name!r} is malformed")
        runner = row.get("runner")
        if row.get("class") == "conformance" and runner != "generic":
            if row.get("excluded") is not False or not isinstance(runner, str) or not runner:
                raise ScenarioError(f"dedicated probe row {name!r} is not runnable")
            sources.append(Source(name, runner))
    sources.sort()
    if len(sources) != DEDICATED_SOURCE_COUNT:
        raise ScenarioError(
            f"dedicated source denominator is {len(sources)}; expected {DEDICATED_SOURCE_COUNT}"
        )
    grouped: dict[str, list[str]] = {}
    for source in sources:
        grouped.setdefault(source.runner, []).append(source.name)
    commands = [
        RunnerCommand(
            runner,
            "serve" if runner == "docker_compose_shared_network_namespace_smoke" else "conformance",
            tuple(names),
        )
        for runner, names in sorted(grouped.items())
    ]
    if len(commands) != DEDICATED_RUNNER_COUNT:
        raise ScenarioError(
            f"dedicated runner denominator is {len(commands)}; expected {DEDICATED_RUNNER_COUNT}"
        )
    return Plan(tuple(sources), tuple(commands))


def expected_rows(plan: Plan) -> list[CompletedRow]:
    return sorted(
        CompletedRow(libc, source.name, source.runner)
        for libc in LIBCS
        for source in plan.sources
    )


def validate_completed(plan: Plan, completed: list[TerminalRow]) -> None:
    expected = {(row.libc, row.source, row.runner) for row in expected_rows(plan)}
    keys = [(row.libc, row.source, row.runner) for row in completed]
    duplicates = sorted(row for row, count in Counter(keys).items() if count > 1)
    actual = set(keys)
    invalid_statuses = sorted({row.status for row in completed} - TERMINAL_STATUSES)
    if duplicates or actual != expected or invalid_statuses:
        raise ScenarioError(
            "dedicated scenario postcondition failed "
            f"(rows={len(completed)}, duplicates={duplicates}, "
            f"missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}, invalid_statuses={invalid_statuses})"
        )


def _run_command(root: Path, command: RunnerCommand, libc: str) -> CommandResult:
    env = os.environ.copy()
    env.update(
        {
            "CARRICK_PROBE_MODE": "closure",
            "CARRICK_PROBE_LANE": "arm64",
            "CARRICK_EXEC_BACKEND": "hvpatch",
            "CARRICK_PROBE_SCENARIO_LIBC": libc,
        }
    )
    args = [
        "cargo",
        "test",
        "-p",
        "carrick-cli",
        "--test",
        command.test_target,
        command.runner,
        "--",
        "--exact",
        "--nocapture",
    ]
    if command.test_target == "serve":
        args.append("--ignored")
    try:
        process = subprocess.run(
            args,
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        return CommandResult("ERROR", "", f"cannot start cargo test: {error}")
    output = process.stdout + process.stderr
    if re.search(rf"\bSKIP\s+{re.escape(command.runner)}\b", output):
        return CommandResult("SKIP", output, "scenario skipped")
    if re.search(rf"\bNOTE\s+{re.escape(command.runner)}\b", output):
        return CommandResult("NOTE", output, "scenario did not have a complete oracle")
    ran_once = output.count("running 1 test") == 1
    passed = output.count(f"test {command.runner} ... ok") == 1
    failed = output.count(f"test {command.runner} ... FAILED") == 1
    if process.returncode == 0 and ran_once and passed:
        return CommandResult("PASS", output, "")
    if process.returncode != 0 and ran_once and failed:
        return CommandResult("FAIL", output, f"cargo test exited {process.returncode}")
    return CommandResult(
        "ERROR",
        output,
        f"cargo test exited {process.returncode} without exactly one terminal test result",
    )


def run_plan(
    root: Path,
    plan: Plan,
    *,
    command_runner=_run_command,
) -> list[TerminalRow]:
    completed: list[TerminalRow] = []
    for libc in LIBCS:
        for command in plan.commands:
            try:
                result = command_runner(root, command, libc)
            except Exception as error:  # fail this command closed; continue the matrix
                result = CommandResult("ERROR", "", f"command runner raised: {error}")
            if not isinstance(result, CommandResult) or result.status not in TERMINAL_STATUSES:
                result = CommandResult(
                    "ERROR",
                    "",
                    f"command runner returned a malformed result: {result!r}",
                )
            for line in result.output.splitlines():
                print(f"CLOSURE_PROBE_DETAIL {libc}:{command.runner}: {line}")
            if result.detail:
                print(
                    f"CLOSURE_PROBE_DETAIL {libc}:{command.runner}: "
                    f"terminal={result.status} detail={result.detail}"
                )
            for source in command.sources:
                row = TerminalRow(
                    libc,
                    source,
                    command.runner,
                    result.status,
                    result.detail,
                )
                completed.append(row)
                print(
                    f"CLOSURE_PROBE SCENARIO {result.status} "
                    f"arm64:{libc}:{source} runner={command.runner}"
                )
    validate_completed(plan, completed)
    return completed


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate and print the plan only")
    parser.add_argument(
        "--inventory", type=Path, default=root / "conformance-probes/probe-inventory.json"
    )
    args = parser.parse_args(argv)
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        plan = build_plan(inventory)
        if args.check:
            print(f"dedicated closure plan: {len(plan.sources)} sources, {len(plan.commands)} runners")
            return 0
        completed = run_plan(root, plan)
        red = [row for row in completed if row.status != "PASS"]
        print(
            f"dedicated closure scenarios checked: {len(completed)} arm64 libc/source rows; "
            f"{len(red)} red"
        )
        if red:
            return 1
    except (OSError, json.JSONDecodeError, ScenarioError) as error:
        print(f"closure scenario error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
