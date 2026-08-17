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


def validate_completed(plan: Plan, completed: list[CompletedRow]) -> None:
    expected = expected_rows(plan)
    duplicates = sorted(row for row, count in Counter(completed).items() if count > 1)
    if duplicates or Counter(completed) != Counter(expected):
        expected_set = set(expected)
        actual_set = set(completed)
        raise ScenarioError(
            "dedicated scenario postcondition failed "
            f"(rows={len(completed)}, duplicates={duplicates}, "
            f"missing={sorted(expected_set - actual_set)}, "
            f"unexpected={sorted(actual_set - expected_set)})"
        )


def _run_command(root: Path, command: RunnerCommand, libc: str) -> str:
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
    process = subprocess.run(
        args,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )
    output = process.stdout + process.stderr
    if process.returncode != 0:
        raise ScenarioError(
            f"scenario {command.runner} [{libc}] exited {process.returncode}:\n{output}"
        )
    if "running 1 test" not in output or f"test {command.runner} ... ok" not in output:
        raise ScenarioError(
            f"scenario {command.runner} [{libc}] did not execute exactly once:\n{output}"
        )
    if re.search(rf"\b(?:SKIP|NOTE)\s+{re.escape(command.runner)}\b", output):
        raise ScenarioError(
            f"scenario {command.runner} [{libc}] did not fully gate:\n{output}"
        )
    return output


def run_plan(root: Path, plan: Plan) -> list[CompletedRow]:
    completed: list[CompletedRow] = []
    for libc in LIBCS:
        for command in plan.commands:
            output = _run_command(root, command, libc)
            sys.stdout.write(output)
            for source in command.sources:
                row = CompletedRow(libc, source, command.runner)
                completed.append(row)
                print(
                    f"PASS CLOSURE_SCENARIO arm64:{libc}:{source} runner={command.runner}"
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
        print(f"dedicated closure scenarios checked: {len(completed)} arm64 libc/source rows")
    except (OSError, json.JSONDecodeError, ScenarioError) as error:
        print(f"closure scenario error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
