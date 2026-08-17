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


def _assertion_pairs(row: dict[str, Any]) -> list[tuple[str, str, str]]:
    pairs = row.get("pairs")
    if not isinstance(pairs, dict):
        raise ReportError(f"result row {row.get('name')!r} lacks assertion pairs")
    pairs_out: list[tuple[str, str, str]] = []
    for assertion, pair in pairs.items():
        if not isinstance(assertion, str) or not isinstance(pair, list) or len(pair) != 2:
            raise ReportError(f"result row {row.get('name')!r} has malformed assertion pair")
        if not all(isinstance(outcome, str) for outcome in pair):
            raise ReportError(f"result row {row.get('name')!r} has non-string outcomes")
        pairs_out.append((assertion, pair[0], pair[1]))
    return sorted(pairs_out)


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

    categories: dict[str, Any] = {
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
        pairs = _assertion_pairs(row)
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

        post_assertion_process_failure = (
            verdict == "incomplete"
            and row["carrick"]["result"] == "failure"
            and row["docker"]["result"] == "success"
            and carrick_totals == docker_totals
            and carrick_totals["n"] > 0
            and carrick_totals["n"] == carrick_totals["passed"]
            and carrick_totals["failed"] == 0
            and carrick_totals["broken"] == 0
            and carrick_totals["skipped"] == 0
            and docker_totals["n"] > 0
            and docker_totals["n"] == docker_totals["passed"]
            and docker_totals["failed"] == 0
            and docker_totals["broken"] == 0
            and docker_totals["skipped"] == 0
            and bool(pairs)
            and len(pairs) == carrick_totals["n"]
            and len(pairs) == docker_totals["n"]
            and all(pair[1:] == ("ok", "ok") for pair in pairs)
        )
        infrastructure = (
            carrick_totals["broken"] > 0
            or docker_totals["broken"] > 0
            or row["carrick"]["result"] in {"none", "empty"}
            or row["docker"]["result"] != "success"
            or any("broken" in pair[1:] for pair in pairs)
            or verdict in {"carrick_crash", "timeout", "oracle_fail"}
            or post_assertion_process_failure
        )
        if infrastructure:
            categories["infrastructure_failures"].append(name)

        suite_has_assertion_gap = False
        suite_has_unexercised = False
        zero_assertion_success = (
            verdict == "incomplete"
            and not pairs
            and row["carrick"]["result"] == "success"
            and row["docker"]["result"] == "success"
            and all(value == 0 for value in carrick_totals.values())
            and all(value == 0 for value in docker_totals.values())
        )
        if zero_assertion_success:
            categories["unexercised"].append(
                {
                    "suite": name,
                    "assertion": "<no assertions>",
                    "carrick": "absent",
                    "docker": "absent",
                }
            )
            suite_has_unexercised = True
        for assertion, carrick_outcome, docker_outcome in pairs:
            assertion_row = {
                "suite": name,
                "assertion": assertion,
                "carrick": carrick_outcome,
                "docker": docker_outcome,
            }
            unexercised = {carrick_outcome, docker_outcome} & {
                "skipped",
                "conf",
                "absent",
            }
            if unexercised:
                categories["unexercised"].append(assertion_row)
                suite_has_unexercised = True
            semantic = "broken" not in {carrick_outcome, docker_outcome} and (
                carrick_outcome != docker_outcome
                or carrick_outcome in {"fail", "error", "xfail", "uxsuccess", "other"}
                or docker_outcome in {"fail", "error", "xfail", "uxsuccess", "other"}
            )
            if semantic:
                categories["semantic_gaps"].append(assertion_row)
                suite_has_assertion_gap = True

        valid = (
            not infrastructure
            and verdict == "match"
            and bool(pairs)
            and all(pair[1:] == ("ok", "ok") for pair in pairs)
        )
        if valid and ratio is not None and ratio >= PATHOLOGICAL_RATIO:
            categories["pathological"].append(name)
        elif valid:
            categories["verified"].append(name)
        elif (
            verdict != "match"
            and not infrastructure
            and not suite_has_assertion_gap
            and not suite_has_unexercised
        ):
            raise ReportError(
                f"result row {name!r} is non-match without an attributable assertion"
            )

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


PROBE_TERMINAL_RE = re.compile(
    r"^CLOSURE_PROBE (GENERIC|SCENARIO) (PASS|FAIL|DIFF|SKIP|NOTE|ERROR) "
    r"arm64:(musl|gnu):([A-Za-z0-9_]+)(?: runner=([A-Za-z0-9_]+))?$"
)
STANDALONE_PROBE_STATE_RE = re.compile(
    r"^(?:PASS|FAIL|DIFF|SKIP|NOTE|ERROR|XFAIL|UNEXPECTED PASS) "
    r"(?:CLOSURE_SCENARIO )?arm64:"
)
RAW_DEDICATED_STATE_RE = re.compile(r"^(?:SKIP|NOTE) ([A-Za-z0-9_]+):")
RAW_CARGO_FAILURE_RE = re.compile(r"^test ([A-Za-z0-9_]+) \.\.\. FAILED$")


def validate_probe_log(log: str, inventory: dict[str, Any]) -> dict[str, Any]:
    generic = {
        name for name, row in inventory.items() if row.get("class") == "conformance" and row.get("runner") == "generic"
    }
    dedicated = {
        name for name, row in inventory.items() if row.get("class") == "conformance" and row.get("runner") != "generic"
    }
    dedicated_runners = {inventory[name].get("runner") for name in dedicated}
    if len(generic) != 409 or len(dedicated) != 20:
        raise ReportError(
            f"probe inventory denominator drifted: {len(generic)} generic, {len(dedicated)} dedicated"
        )
    observed: list[dict[str, str]] = []
    for line in log.splitlines():
        terminal = line.strip()
        match = PROBE_TERMINAL_RE.fullmatch(terminal)
        if match:
            kind, status, libc, source, runner = match.groups()
            if kind == "GENERIC":
                if source not in generic or runner is not None:
                    raise ReportError(f"generic log row disagrees with inventory: {terminal}")
            elif (
                source not in dedicated
                or runner is None
                or inventory[source].get("runner") != runner
            ):
                raise ReportError(f"scenario log row disagrees with inventory: {terminal}")
            observed.append(
                {
                    "kind": kind.lower(),
                    "status": status,
                    "libc": libc,
                    "source": source,
                    "runner": runner or "generic",
                }
            )
        elif terminal.startswith("CLOSURE_PROBE ") or STANDALONE_PROBE_STATE_RE.match(terminal):
            raise ReportError(f"malformed or standalone probe terminal state: {terminal}")
        else:
            raw_state = RAW_DEDICATED_STATE_RE.match(terminal)
            cargo_failure = RAW_CARGO_FAILURE_RE.fullmatch(terminal)
            runner = (raw_state or cargo_failure).group(1) if raw_state or cargo_failure else None
            if runner in dedicated_runners:
                raise ReportError(f"raw dedicated probe failure state is forbidden: {terminal}")
    expected = {(libc, source) for libc in PROBE_LIBCS for source in generic | dedicated}
    keys = [(row["libc"], row["source"]) for row in observed]
    duplicates = sorted(row for row, count in Counter(keys).items() if count > 1)
    actual = set(keys)
    if duplicates or actual != expected:
        raise ReportError(
            "probe log does not close both arm64 libc sets "
            f"(rows={len(observed)}, duplicates={duplicates}, "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
        )
    failures = [row for row in observed if row["status"] in {"FAIL", "DIFF"}]
    infrastructure = [row for row in observed if row["status"] in {"ERROR", "NOTE"}]
    unexercised = [row for row in observed if row["status"] in {"SKIP", "NOTE"}]
    return {
        "sources": len(generic | dedicated),
        "rows": len(observed),
        "passed": sum(row["status"] == "PASS" for row in observed),
        "generic_sources": len(generic),
        "dedicated_sources": len(dedicated),
        "failures": failures,
        "infrastructure_failures": infrastructure,
        "unexercised": unexercised,
    }


def _suite_table(
    summary: dict[str, Any], category: str, suite_clusters: dict[str, str]
) -> str:
    names = summary[category]
    if not names:
        return "_None._\n"
    lines = ["| Suite | Mechanism cluster | Ratio |", "|---|---|---:|"]
    for name in names:
        ratio = summary["ratios"].get(name)
        cluster = suite_clusters.get(name, "unclustered")
        lines.append(
            f"| `{name}` | {cluster} | {ratio:.2f}x |"
            if ratio is not None
            else f"| `{name}` | {cluster} | — |"
        )
    return "\n".join(lines) + "\n"


def _assertion_table(
    summary: dict[str, Any], category: str, suite_clusters: dict[str, str]
) -> str:
    rows = summary[category]
    if not rows:
        return "_None._\n"
    lines = [
        "| Suite | Assertion | Carrick | Docker | Mechanism cluster |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        cluster = suite_clusters.get(row["suite"], "unclustered")
        lines.append(
            f"| `{row['suite']}` | `{row['assertion']}` | `{row['carrick']}` | "
            f"`{row['docker']}` | {cluster} |"
        )
    return "\n".join(lines) + "\n"


def _probe_table(rows: list[dict[str, str]], probe_clusters: dict[str, str]) -> str:
    if not rows:
        return "_None._\n"
    lines = [
        "| Libc | Source | Runner | Status | Mechanism cluster |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        cluster = probe_clusters.get(f"{row['libc']}:{row['source']}", "unclustered")
        lines.append(
            f"| `{row['libc']}` | `{row['source']}` | `{row['runner']}` | "
            f"`{row['status']}` | {cluster} |"
        )
    return "\n".join(lines) + "\n"


def validate_clusters(
    clusters: Any, scope: dict[str, Any], inventory: dict[str, Any]
) -> dict[str, dict[str, str]]:
    if not isinstance(clusters, dict) or set(clusters) != {"schema", "suites", "probes"}:
        raise ReportError("cluster map requires exactly schema, suites, and probes")
    if clusters["schema"] != "carrick-closure-clusters-v1":
        raise ReportError("cluster map schema is unsupported")
    suites = clusters["suites"]
    probes = clusters["probes"]
    if not isinstance(suites, dict) or not isinstance(probes, dict):
        raise ReportError("cluster suite/probe maps must be objects")
    unknown_suites = sorted(set(suites) - set(scope.get("suite_names", [])))
    expected_probes = {
        f"{libc}:{source}"
        for libc in PROBE_LIBCS
        for source, row in inventory.items()
        if row.get("class") == "conformance"
    }
    unknown_probes = sorted(set(probes) - expected_probes)
    if unknown_suites or unknown_probes:
        raise ReportError(
            f"cluster map names unknown rows (suites={unknown_suites}, probes={unknown_probes})"
        )
    cluster_names = [*suites.values(), *probes.values()]
    if not all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
        for name in cluster_names
    ):
        raise ReportError("cluster names must be nonempty lowercase kebab-case")
    return {"suites": suites, "probes": probes}


def render_ledger(
    scope: dict[str, Any],
    summary: dict[str, Any],
    probes: dict[str, Any],
    results_path: Path,
    probe_path: Path,
    clusters: dict[str, dict[str, str]] | None = None,
) -> str:
    clusters = clusters or {"suites": {}, "probes": {}}
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
        ("Semantic assertion gaps", "semantic_gaps"),
        ("Unexercised assertions", "unexercised"),
    ]:
        sections.extend(
            ["", f"## {title}", "", _assertion_table(summary, key, clusters["suites"]).rstrip()]
        )
    for title, key in [
        ("Suite infrastructure failures", "infrastructure_failures"),
        ("Valid completing >=10x pathology", "pathological"),
    ]:
        sections.extend(
            ["", f"## {title}", "", _suite_table(summary, key, clusters["suites"]).rstrip()]
        )
    for title, key in [
        ("Probe semantic failures", "failures"),
        ("Probe infrastructure failures", "infrastructure_failures"),
        ("Probe unexercised rows", "unexercised"),
    ]:
        sections.extend(
            ["", f"## {title}", "", _probe_table(probes[key], clusters["probes"]).rstrip()]
        )
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
    parser.add_argument(
        "--clusters", type=Path, default=root / "scripts/conformance/closure-clusters.json"
    )
    args = parser.parse_args(argv)
    try:
        scope = json.loads(args.scope.read_text(encoding="utf-8"))
        inventory = json.loads(args.probe_inventory.read_text(encoding="utf-8"))
        clusters = validate_clusters(
            json.loads(args.clusters.read_text(encoding="utf-8")), scope, inventory
        )
        summary = summarize(scope, load_jsonl(args.results))
        probes = validate_probe_log(args.probe_log.read_text(encoding="utf-8"), inventory)
        args.output.write_text(
            render_ledger(scope, summary, probes, args.results, args.probe_log, clusters),
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, ReportError) as error:
        print(f"closure report error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {args.output} from {summary['suite_count']} suites and {probes['rows']} probe rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
