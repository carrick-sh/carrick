#!/usr/bin/env python3
"""Validate a complete closure discovery and render its live backlog ledger."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


CLOSURE_SUITE_COUNT = 2127
PATHOLOGICAL_RATIO = 10.0
PROBE_LIBCS = ("gnu", "musl")


class ReportError(RuntimeError):
    """The discovery artifacts are incomplete, duplicated, or malformed."""


def _scope_names(scope: dict[str, Any]) -> list[str]:
    if not isinstance(scope, dict):
        raise ReportError("scope must be a JSON object")
    names = scope.get("suite_names")
    if scope.get("suite_count") != CLOSURE_SUITE_COUNT:
        raise ReportError(
            f"scope declares {scope.get('suite_count')!r} suites; expected {CLOSURE_SUITE_COUNT}"
        )
    if not isinstance(names, list) or not all(isinstance(name, str) and name for name in names):
        raise ReportError("scope suite_names must be nonempty strings")
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if len(names) != CLOSURE_SUITE_COUNT or duplicates:
        raise ReportError(
            f"scope suite names are not {CLOSURE_SUITE_COUNT} unique rows; duplicates={duplicates}"
        )
    return names


def _totals(row: dict[str, Any], side: str) -> dict[str, int]:
    try:
        result = row[side]["result"]
        totals = row[side]["totals"]
    except (KeyError, TypeError) as error:
        raise ReportError(f"result row {row.get('name')!r} lacks {side} totals") from error
    if result not in {"success", "failure", "none", "empty"}:
        raise ReportError(f"result row {row.get('name')!r} has invalid {side} result {result!r}")
    required = {"n", "passed", "failed", "broken", "skipped"}
    if not isinstance(totals, dict) or set(totals) != required:
        raise ReportError(f"result row {row.get('name')!r} has malformed {side} totals")
    if not all(type(totals[key]) is int and totals[key] >= 0 for key in required):
        raise ReportError(f"result row {row.get('name')!r} has non-count {side} totals")
    return totals


def _pair_outcomes(row: dict[str, Any]) -> list[str]:
    pairs = row.get("pairs")
    if not isinstance(pairs, dict):
        raise ReportError(f"result row {row.get('name')!r} lacks assertion pairs")
    outcomes: list[str] = []
    for assertion, pair in pairs.items():
        if not isinstance(assertion, str) or not isinstance(pair, list) or len(pair) != 2:
            raise ReportError(f"result row {row.get('name')!r} has malformed assertion pair")
        if not all(isinstance(outcome, str) for outcome in pair):
            raise ReportError(f"result row {row.get('name')!r} has non-string outcomes")
        outcomes.extend(pair)
    return outcomes


def _ratio(row: dict[str, Any]) -> float | None:
    perf = row.get("perf")
    if perf is None:
        return None
    if not isinstance(perf, dict):
        raise ReportError(f"result row {row.get('name')!r} has malformed perf data")
    ratio = perf.get("carrick_to_oracle_ratio")
    if ratio is None:
        return None
    if type(ratio) not in {int, float} or ratio < 0:
        raise ReportError(f"result row {row.get('name')!r} has malformed perf ratio")
    return float(ratio)


def summarize(scope: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate exact suite closure and partition every non-green row by cause."""

    scope_names = _scope_names(scope)
    if not isinstance(results, list) or not all(isinstance(row, dict) for row in results):
        raise ReportError("results must be a list of JSON objects")
    result_names = [row.get("name") for row in results]
    if not all(isinstance(name, str) and name for name in result_names):
        raise ReportError("every result row requires a nonempty name")
    duplicates = sorted(name for name, count in Counter(result_names).items() if count > 1)
    expected = set(scope_names)
    actual = set(result_names)
    if len(results) != CLOSURE_SUITE_COUNT or duplicates or actual != expected:
        raise ReportError(
            "results do not close the frozen suite scope "
            f"(rows={len(results)}, duplicates={duplicates}, "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
        )

    categories: dict[str, list[str]] = {
        "semantic_gaps": [],
        "infrastructure_failures": [],
        "unexercised": [],
        "pathological": [],
        "verified": [],
    }
    ratios: dict[str, float] = {}
    by_name = {row["name"]: row for row in results}
    for name in sorted(scope_names):
        row = by_name[name]
        carrick_totals = _totals(row, "carrick")
        docker_totals = _totals(row, "docker")
        outcomes = _pair_outcomes(row)
        verdict = row.get("verdict")
        if verdict not in {
            "match",
            "incomplete",
            "diff",
            "regression",
            "new",
            "carrick_crash",
            "timeout",
            "oracle_fail",
        }:
            raise ReportError(f"result row {name!r} has invalid verdict {verdict!r}")
        ratio = _ratio(row)
        if ratio is not None:
            ratios[name] = ratio

        unexercised = (
            carrick_totals["skipped"] > 0
            or docker_totals["skipped"] > 0
            or any(outcome in {"skipped", "conf", "absent"} for outcome in outcomes)
        )
        infrastructure = (
            carrick_totals["broken"] > 0
            or docker_totals["broken"] > 0
            or row["carrick"]["result"] in {"none", "empty"}
            or row["docker"]["result"] != "success"
            or any(outcome == "broken" for outcome in outcomes)
            or verdict in {"carrick_crash", "timeout", "oracle_fail"}
        )
        if unexercised:
            categories["unexercised"].append(name)
        elif infrastructure:
            categories["infrastructure_failures"].append(name)
        elif verdict != "match" or any(outcome != "ok" for outcome in outcomes):
            categories["semantic_gaps"].append(name)
        elif ratio is not None and ratio >= PATHOLOGICAL_RATIO:
            categories["pathological"].append(name)
        else:
            categories["verified"].append(name)

    categories["ratios"] = ratios
    categories["suite_count"] = len(results)
    return categories


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ReportError(f"invalid JSONL at {path}:{line_number}: {error}") from error
            if not isinstance(row, dict):
                raise ReportError(f"non-object JSONL row at {path}:{line_number}")
            rows.append(row)
    except OSError as error:
        raise ReportError(f"cannot read results {path}: {error}") from error
    return rows


GENERIC_PASS_RE = re.compile(r"^PASS arm64:(musl|gnu):([A-Za-z0-9_]+)$")
SCENARIO_PASS_RE = re.compile(
    r"^PASS CLOSURE_SCENARIO arm64:(musl|gnu):([A-Za-z0-9_]+) runner=([A-Za-z0-9_]+)$"
)


def validate_probe_log(log: str, inventory: dict[str, Any]) -> dict[str, int]:
    generic = {
        name for name, row in inventory.items() if row.get("class") == "conformance" and row.get("runner") == "generic"
    }
    dedicated = {
        name for name, row in inventory.items() if row.get("class") == "conformance" and row.get("runner") != "generic"
    }
    if len(generic) != 409 or len(dedicated) != 20:
        raise ReportError(
            f"probe inventory denominator drifted: {len(generic)} generic, {len(dedicated)} dedicated"
        )
    observed: list[tuple[str, str]] = []
    for line in log.splitlines():
        if match := GENERIC_PASS_RE.fullmatch(line.strip()):
            observed.append((match.group(1), match.group(2)))
        elif match := SCENARIO_PASS_RE.fullmatch(line.strip()):
            source = match.group(2)
            runner = match.group(3)
            if source not in dedicated or inventory[source].get("runner") != runner:
                raise ReportError(f"scenario log row disagrees with inventory: {line.strip()}")
            observed.append((match.group(1), source))
    expected = {(libc, source) for libc in PROBE_LIBCS for source in generic | dedicated}
    duplicates = sorted(row for row, count in Counter(observed).items() if count > 1)
    actual = set(observed)
    if duplicates or actual != expected:
        raise ReportError(
            "probe log does not close both arm64 libc sets "
            f"(rows={len(observed)}, duplicates={duplicates}, "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
        )
    return {
        "sources": len(generic | dedicated),
        "rows": len(observed),
        "generic_sources": len(generic),
        "dedicated_sources": len(dedicated),
    }


def _table(summary: dict[str, Any], category: str) -> str:
    names = summary[category]
    if not names:
        return "_None._\n"
    lines = ["| Suite | Mechanism cluster | Ratio |", "|---|---|---:|"]
    for name in names:
        ratio = summary["ratios"].get(name)
        lines.append(f"| `{name}` | unclustered | {ratio:.2f}x |" if ratio is not None else f"| `{name}` | unclustered | — |")
    return "\n".join(lines) + "\n"


def render_ledger(
    scope: dict[str, Any], summary: dict[str, Any], probes: dict[str, int], results_path: Path, probe_path: Path
) -> str:
    images = scope.get("images", {})
    image_lines = [
        f"- `{name}`: `{row.get('registry_digest', 'unresolved')}`"
        for name, row in sorted(images.items())
    ]
    sections = [
        "# Conformance closure ledger",
        "",
        "This is generated controller state. Update it from a complete closure run; do not hand-edit counts.",
        "",
        "## Provenance",
        "",
        f"- Source HEAD: `{scope.get('source_head', 'unknown')}`",
        f"- Signed Carrick SHA-256: `{scope.get('binary_sha256', 'unknown')}`",
        f"- Manifest SHA-256: `{scope.get('manifest_sha256', 'unknown')}`",
        f"- Raw suite artifact: `{results_path}`",
        f"- Raw probe artifact: `{probe_path}`",
        *image_lines,
        "",
        "## Machine closure",
        "",
        f"- Suites: {summary['suite_count']} unique rows",
        f"- Probe sources: {probes['sources']} ({probes['generic_sources']} generic, {probes['dedicated_sources']} dedicated)",
        f"- Probe rows: {probes['rows']} (arm64 musl + GNU)",
    ]
    for title, key in [
        ("Semantic gaps", "semantic_gaps"),
        ("Infrastructure failures", "infrastructure_failures"),
        ("Unexercised assertions", "unexercised"),
        ("Valid completing >=10x pathology", "pathological"),
    ]:
        sections.extend(["", f"## {title}", "", _table(summary, key).rstrip()])
    sections.append("")
    return "\n".join(sections)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--probe-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--probe-inventory", type=Path, default=root / "conformance-probes/probe-inventory.json"
    )
    args = parser.parse_args(argv)
    try:
        scope = json.loads(args.scope.read_text(encoding="utf-8"))
        inventory = json.loads(args.probe_inventory.read_text(encoding="utf-8"))
        summary = summarize(scope, load_jsonl(args.results))
        probes = validate_probe_log(args.probe_log.read_text(encoding="utf-8"), inventory)
        args.output.write_text(
            render_ledger(scope, summary, probes, args.results, args.probe_log), encoding="utf-8"
        )
    except (OSError, json.JSONDecodeError, ReportError) as error:
        print(f"closure report error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {args.output} from {summary['suite_count']} suites and {probes['rows']} probe rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
