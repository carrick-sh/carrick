#!/usr/bin/env python3
"""Pin Clippy's resolved diagnostic contract for the authority fixture."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "scripts" / "tests" / "fixtures" / "host-authority-census"
OPERATION = re.compile(r"use of a disallowed method `([^`]+)`")


def capture_fixture(extra_args: list[str]) -> list[dict[str, object]]:
    """Run the pinned Clippy census and return its disallowed-method diagnostics."""
    command = [
        "cargo",
        "clippy",
        "--manifest-path",
        str(FIXTURE / "Cargo.toml"),
        "--lib",
        "--message-format=json",
        *extra_args,
        "--",
        "--force-warn",
        "clippy::disallowed_methods",
    ]
    with tempfile.TemporaryDirectory(prefix="host-authority-clippy-") as target:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = target
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        raise AssertionError(
            f"pinned Clippy fixture failed with status {result.returncode}:\n"
            f"{result.stderr}"
        )

    diagnostics: list[dict[str, object]] = []
    for line in result.stdout.splitlines():
        message = json.loads(line)
        reason = message.get("message", {}).get("code", {})
        if reason.get("code") == "clippy::disallowed_methods":
            diagnostics.append(message)
    return diagnostics


def primary_span(diagnostic: dict[str, object]) -> dict[str, object]:
    reason = diagnostic["message"]
    assert isinstance(reason, dict)
    spans = reason["spans"]
    assert isinstance(spans, list)
    primary = [span for span in spans if span.get("is_primary") is True]
    if len(primary) != 1:
        raise AssertionError(f"expected one primary span, got {primary!r}")
    return primary[0]


def operation(diagnostic: dict[str, object]) -> str:
    reason = diagnostic["message"]
    assert isinstance(reason, dict)
    message = reason["message"]
    assert isinstance(message, str)
    match = OPERATION.fullmatch(message)
    if match is None:
        raise AssertionError(f"unexpected Clippy message: {message!r}")
    return match.group(1)


def expansion_callsites(span: dict[str, object]) -> list[tuple[str, int, int]]:
    callsites: list[tuple[str, int, int]] = []
    expansion = span.get("expansion")
    while isinstance(expansion, dict):
        callsite = expansion["span"]
        callsites.append(
            (
                str(callsite["file_name"]),
                int(callsite["line_start"]),
                int(callsite["column_start"]),
            )
        )
        expansion = callsite.get("expansion")
    return callsites


class HostAuthorityClippyContractTest(unittest.TestCase):
    def test_pinned_clippy_reports_all_seven_resolved_uses(self):
        diagnostics = capture_fixture([])
        self.assertEqual(
            Counter(map(operation, diagnostics)),
            Counter(
                {
                    "std::process::id": 3,
                    "std::fs::read": 1,
                    "libc::waitpid": 1,
                    "std::thread::yield_now": 1,
                    "std::fs::metadata": 1,
                }
            ),
        )
        self.assertEqual(len(diagnostics), 7)

        by_operation: dict[str, list[dict[str, object]]] = {}
        for diagnostic in diagnostics:
            by_operation.setdefault(operation(diagnostic), []).append(
                primary_span(diagnostic)
            )

        exact_spans = [
            (
                operation(diagnostic),
                span["file_name"],
                span["line_start"],
                span["column_start"],
                span["line_end"],
                span["column_end"],
                expansion_callsites(span),
            )
            for diagnostic in diagnostics
            for span in [primary_span(diagnostic)]
        ]
        self.assertEqual(
            exact_spans,
            [
                ("std::process::id", "src/lib.rs", 11, 5, 11, 21, []),
                ("std::process::id", "src/lib.rs", 15, 5, 15, 16, []),
                ("std::fs::read", "src/lib.rs", 19, 13, 19, 28, []),
                ("libc::waitpid", "src/lib.rs", 23, 16, 23, 29, []),
                ("std::thread::yield_now", "src/lib.rs", 28, 17, 28, 39, []),
                ("std::fs::metadata", "src/lib.rs", 32, 32, 32, 49, []),
                ("std::process::id", "src/lib.rs", 37, 5, 37, 21, []),
            ],
        )

        # Clippy 1.96 attributes expression macro arguments directly to their
        # caller tokens. Even the dependency macro therefore has a primary
        # caller span and no expansion chain to normalize.
        local_macro = by_operation["std::thread::yield_now"][0]
        dependency_macro = by_operation["std::fs::metadata"][0]
        self.assertIsNone(local_macro["expansion"])
        self.assertIsNone(dependency_macro["expansion"])

        expected = [
            span
            for span in by_operation["std::process::id"]
            if span["line_start"] == 37
        ]
        self.assertEqual(len(expected), 1, "--force-warn must pierce #[expect]")


if __name__ == "__main__":
    unittest.main()
