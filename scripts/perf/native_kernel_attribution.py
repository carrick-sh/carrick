#!/usr/bin/env python3
"""Select a stable Darwin kernel stack family from two native-wall profiles.

This tool records a measurement decision only. It deliberately does not edit
the performance hypothesis ledger or create a hypothesis from the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Sequence


INPUT_SCHEMA = "carrick.dsr-profile.v1"
OUTPUT_SCHEMA = "carrick.native-kernel-attribution.v1"
PROFILE = "native-wall"
U64_MAX = (1 << 64) - 1

MIN_SYMBOLIZED_LEAVES = Fraction(19, 20)
MIN_MEAN_SHARE = Fraction(1, 10)
MAX_SHARE_DRIFT = Fraction(1, 20)
MIN_RUN_SHARE = Fraction(1, 20)
MIN_SHARED_TOP_TEN_COVERAGE = Fraction(3, 5)

PROVENANCE_FIELDS = (
    "run_id",
    "git_sha",
    "git_dirty",
    "binary_sha256",
    "command",
    "host",
)
DROP_FIELDS = (
    "principal_drops",
    "aggregation_drops",
    "dynamic_drops",
    "other_drops",
)
HEX_OFFSET = re.compile(r"\+0[xX][0-9a-fA-F]+$")


class EvidenceError(ValueError):
    """The supplied profile cannot support a measurement decision."""


@dataclass(frozen=True)
class StackSample:
    count: int
    frames: tuple[str, ...]


@dataclass(frozen=True)
class RunEvidence:
    path: pathlib.Path
    sha256: str
    provenance: dict[str, object]
    kernel_pc_count: int
    kernel_stack_count: int
    symbolized_leaf_count: int
    family_counts: dict[str, int]
    family_stacks: dict[str, tuple[StackSample, ...]]


def _fraction(value: Fraction) -> dict[str, int]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
    }


def _positive_u64(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{description} must be an integer")
    if value <= 0 or value > U64_MAX:
        raise EvidenceError(f"{description} must be a positive u64")
    return value


def _nonnegative_u64(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{description} must be an integer")
    if value < 0 or value > U64_MAX:
        raise EvidenceError(f"{description} must be a non-negative u64")
    return value


def _checked_add(left: int, right: int, description: str) -> int:
    if right > U64_MAX - left:
        raise EvidenceError(f"{description} addition exceeds u64")
    return left + right


def _mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{description} must be an object")
    return value


def _validate_provenance(row: dict[str, Any], description: str) -> dict[str, object]:
    provenance = {field: row.get(field) for field in PROVENANCE_FIELDS}
    for field in ("run_id", "git_sha", "binary_sha256", "host"):
        value = provenance[field]
        if not isinstance(value, str) or not value:
            raise EvidenceError(f"{description} {field} must be a non-empty string")
    if not isinstance(provenance["git_dirty"], bool):
        raise EvidenceError(f"{description} git_dirty must be a boolean")
    command = provenance["command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part for part in command)
    ):
        raise EvidenceError(f"{description} command must be non-empty strings")
    return provenance


def _validate_completion(
    value: Any,
    description: str,
) -> dict[str, Any]:
    completion = _mapping(value, f"{description} completion")
    if completion.get("complete") is not True:
        raise EvidenceError(f"{description} capture is incomplete")
    if completion.get("bounded") is not False:
        raise EvidenceError(f"{description} capture is bounded")
    target_exit_reason = _nonnegative_u64(
        completion.get("target_exit_reason"),
        f"{description} target exit reason",
    )
    if target_exit_reason != 1:
        raise EvidenceError(f"{description} target exit was not natural")
    if completion.get("high_cardinality_overflow") is not False:
        raise EvidenceError(f"{description} high-cardinality data overflowed")
    incomplete_pairs = _nonnegative_u64(
        completion.get("incomplete_pairs"),
        f"{description} incomplete pairs",
    )
    if incomplete_pairs != 0:
        raise EvidenceError(f"{description} has incomplete duration pairs")
    drops = _mapping(completion.get("drops"), f"{description} completion drops")
    if drops.get("interrupted") is not False:
        raise EvidenceError(f"{description} capture was interrupted")
    for field in DROP_FIELDS:
        count = _nonnegative_u64(
            drops.get(field),
            f"{description} completion drops.{field}",
        )
        if count:
            raise EvidenceError(f"{description} has nonzero {field}")
    return completion


def _normalize_symbolized_frame(frame: Any) -> str | None:
    if not isinstance(frame, str) or not frame or "\n" in frame:
        return None
    if frame.count("`") != 1:
        return None
    module, symbol = frame.split("`", 1)
    if not module or not symbol:
        return None
    normalized_symbol = HEX_OFFSET.sub("", symbol)
    if not normalized_symbol:
        return None
    return f"{module}`{normalized_symbol}"


def normalize_stack_family(frames: Sequence[str]) -> str | None:
    """Return the first four symbolized frames when the leaf is symbolized."""
    if not frames or _normalize_symbolized_frame(frames[0]) is None:
        return None
    symbolized = [
        normalized
        for frame in frames
        if (normalized := _normalize_symbolized_frame(frame)) is not None
    ]
    return " | ".join(symbolized[:4])


def _parse_jsonl(path: pathlib.Path, raw: bytes, run_number: int) -> RunEvidence:
    description = f"run {run_number}"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{description} is not UTF-8 JSONL") from error
    lines = text.splitlines()
    if not lines:
        raise EvidenceError(f"{description} profile is empty")
    if any(not line.strip() for line in lines):
        raise EvidenceError(f"{description} profile contains a blank JSONL row")

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(
                f"{description} line {line_number} is invalid JSON"
            ) from error
        if not isinstance(value, dict):
            raise EvidenceError(f"{description} line {line_number} is not an object")
        rows.append(value)

    first = rows[0]
    if first.get("schema") != INPUT_SCHEMA or first.get("profile") != PROFILE:
        raise EvidenceError(
            f"{description} is not a {INPUT_SCHEMA} {PROFILE} profile"
        )
    provenance = _validate_provenance(first, description)
    completion = _validate_completion(first.get("completion"), description)

    pc_total = 0
    stack_total = 0
    symbolized_leaf_count = 0
    family_counts: dict[str, int] = {}
    family_stacks: dict[str, list[StackSample]] = defaultdict(list)
    completion_rows = 0
    seen_pcs: set[int] = set()
    seen_stacks: set[tuple[str, ...]] = set()

    for line_number, row in enumerate(rows, 1):
        row_description = f"{description} line {line_number}"
        if row.get("schema") != INPUT_SCHEMA or row.get("profile") != PROFILE:
            raise EvidenceError(f"{row_description} schema or profile changed")
        if _validate_provenance(row, row_description) != provenance:
            raise EvidenceError(f"{row_description} provenance changed")
        if row.get("completion") != completion:
            raise EvidenceError(f"{row_description} completion changed")
        scope = _mapping(row.get("scope"), f"{row_description} scope")
        metric = _mapping(row.get("metric"), f"{row_description} metric")
        metric_type = metric.get("type")
        if not isinstance(metric_type, str):
            raise EvidenceError(f"{row_description} metric type is missing")
        if metric_type == "completion":
            completion_rows += 1

        phase = scope.get("phase")
        if phase == "cpu-kernel-pc":
            if metric_type != "exact":
                raise EvidenceError(f"{row_description} kernel PC is not exact")
            count = _positive_u64(
                metric.get("count"),
                f"{row_description} kernel PC count",
            )
            source_pc = _nonnegative_u64(
                scope.get("source_pc"),
                f"{row_description} kernel PC",
            )
            if source_pc in seen_pcs:
                raise EvidenceError(f"{row_description} duplicates a kernel PC")
            seen_pcs.add(source_pc)
            pc_total = _checked_add(pc_total, count, f"{description} kernel PC count")
        elif phase == "cpu-kernel-stack":
            if metric_type != "stack-trace":
                raise EvidenceError(f"{row_description} kernel stack is not a stack-trace")
            if "pid" in metric or "value_ns" in metric:
                raise EvidenceError(
                    f"{row_description} kernel stack has pid or value_ns"
                )
            if scope.get("pid") is not None:
                raise EvidenceError(f"{row_description} kernel stack has a scope pid")
            count = _positive_u64(
                metric.get("count"),
                f"{row_description} kernel stack count",
            )
            raw_frames = metric.get("frames")
            if (
                not isinstance(raw_frames, list)
                or not raw_frames
                or any(not isinstance(frame, str) or not frame for frame in raw_frames)
            ):
                raise EvidenceError(f"{row_description} kernel stack frames are malformed")
            frames = tuple(raw_frames)
            if frames in seen_stacks:
                raise EvidenceError(f"{row_description} duplicates a kernel stack")
            seen_stacks.add(frames)
            stack_total = _checked_add(
                stack_total,
                count,
                f"{description} kernel stack count",
            )
            family = normalize_stack_family(frames)
            if family is not None:
                symbolized_leaf_count = _checked_add(
                    symbolized_leaf_count,
                    count,
                    f"{description} symbolized leaf count",
                )
                family_counts[family] = _checked_add(
                    family_counts.get(family, 0),
                    count,
                    f"{description} family count",
                )
                family_stacks[family].append(StackSample(count, frames))

    if completion_rows != 1:
        raise EvidenceError(
            f"{description} expected one completion row, got {completion_rows}"
        )
    if pc_total == 0 or stack_total == 0:
        raise EvidenceError(f"{description} has no kernel PC/stack samples")
    if pc_total != stack_total:
        raise EvidenceError(
            f"{description} kernel PC count {pc_total} does not equal "
            f"kernel stack count {stack_total}"
        )
    return RunEvidence(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        provenance=provenance,
        kernel_pc_count=pc_total,
        kernel_stack_count=stack_total,
        symbolized_leaf_count=symbolized_leaf_count,
        family_counts=family_counts,
        family_stacks={
            family: tuple(stacks) for family, stacks in family_stacks.items()
        },
    )


def _run_document(run: RunEvidence) -> dict[str, object]:
    total = run.kernel_stack_count
    families = sorted(
        run.family_counts,
        key=lambda family: (-run.family_counts[family], family),
    )
    return {
        "run_id": run.provenance["run_id"],
        "provenance": run.provenance,
        "kernel_pc_count": run.kernel_pc_count,
        "kernel_stack_count": run.kernel_stack_count,
        "symbolized_leaf_count": run.symbolized_leaf_count,
        "symbolized_leaf_share": _fraction(
            Fraction(run.symbolized_leaf_count, total)
        ),
        "families": [
            {
                "family": family,
                "count": run.family_counts[family],
                "share": _fraction(Fraction(run.family_counts[family], total)),
            }
            for family in families
        ],
    }


def _candidate_document(
    family: str,
    runs: tuple[RunEvidence, RunEvidence],
    shared_coverage_ok: bool,
) -> tuple[dict[str, object], Fraction, int, bool]:
    counts = tuple(run.family_counts.get(family, 0) for run in runs)
    shares = tuple(
        Fraction(count, run.kernel_stack_count)
        for count, run in zip(counts, runs, strict=True)
    )
    mean_share = (shares[0] + shares[1]) / 2
    drift = abs(shares[0] - shares[1])
    total_count = _checked_add(
        counts[0],
        counts[1],
        f"family {family!r} total count",
    )
    mean_ok = mean_share >= MIN_MEAN_SHARE
    drift_ok = drift <= MAX_SHARE_DRIFT
    membership_ok = all(share >= MIN_RUN_SHARE for share in shares)
    selectable = mean_ok and drift_ok and membership_ok and shared_coverage_ok
    return (
        {
            "family": family,
            "counts": list(counts),
            "shares": [_fraction(share) for share in shares],
            "mean_share": _fraction(mean_share),
            "absolute_drift": _fraction(drift),
            "total_count": total_count,
            "gates": {
                "mean_at_least_ten_percent": mean_ok,
                "drift_at_most_five_points": drift_ok,
                "at_least_five_percent_each": membership_ok,
                "shared_top_ten_covers_sixty_percent_each": shared_coverage_ok,
            },
            "selectable": selectable,
        },
        mean_share,
        total_count,
        selectable,
    )


def _representative_stacks(
    family: str,
    runs: tuple[RunEvidence, RunEvidence],
) -> list[dict[str, object]]:
    representatives: list[dict[str, object]] = []
    for index, run in enumerate(runs, 1):
        for stack in sorted(
            run.family_stacks.get(family, ()),
            key=lambda sample: (-sample.count, sample.frames),
        ):
            representatives.append(
                {
                    "run": index,
                    "run_id": run.provenance["run_id"],
                    "count": stack.count,
                    "frames": list(stack.frames),
                }
            )
    return representatives


def _base_document(
    sources: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "schema": OUTPUT_SCHEMA,
        "result": "rejected",
        "sources": sources,
        "thresholds": {
            "minimum_symbolized_leaf_share": _fraction(MIN_SYMBOLIZED_LEAVES),
            "minimum_mean_family_share": _fraction(MIN_MEAN_SHARE),
            "maximum_per_run_share_drift": _fraction(MAX_SHARE_DRIFT),
            "minimum_per_run_family_share": _fraction(MIN_RUN_SHARE),
            "minimum_shared_top_ten_coverage": _fraction(
                MIN_SHARED_TOP_TEN_COVERAGE
            ),
        },
        "runs": [],
        "shared_top_ten": None,
        "candidates": [],
        "selected_family": None,
        "diffuse_reasons": [],
        "evidence_errors": [],
    }


def analyze_profiles(paths: Sequence[pathlib.Path]) -> dict[str, object]:
    """Analyze exactly two completed profile artifacts without using floats."""
    normalized_paths = tuple(pathlib.Path(path) for path in paths)
    sources: list[dict[str, object]] = []
    document = _base_document(sources)
    if len(normalized_paths) != 2:
        document["evidence_errors"] = ["exactly two profiles are required"]
        return document

    runs: list[RunEvidence] = []
    errors: list[str] = []
    for run_number, path in enumerate(normalized_paths, 1):
        try:
            raw = path.read_bytes()
        except OSError as error:
            sources.append({"path": str(path), "sha256": None})
            errors.append(f"run {run_number} cannot be read: {error}")
            continue
        source_hash = hashlib.sha256(raw).hexdigest()
        sources.append({"path": str(path), "sha256": source_hash})
        try:
            run = _parse_jsonl(path, raw, run_number)
        except EvidenceError as error:
            errors.append(str(error))
            continue
        runs.append(run)

    document["runs"] = [_run_document(run) for run in runs]
    if errors:
        document["evidence_errors"] = errors
        return document

    paired_runs = (runs[0], runs[1])
    if normalized_paths[0] == normalized_paths[1]:
        errors.append("profile paths must be distinct")
    if paired_runs[0].sha256 == paired_runs[1].sha256:
        errors.append("profile source hashes must be distinct")
    if paired_runs[0].provenance["run_id"] == paired_runs[1].provenance["run_id"]:
        errors.append("profile run_id values must be distinct")
    if errors:
        document["evidence_errors"] = errors
        return document

    for run_number, run in enumerate(paired_runs, 1):
        coverage = Fraction(
            run.symbolized_leaf_count,
            run.kernel_stack_count,
        )
        if coverage < MIN_SYMBOLIZED_LEAVES:
            errors.append(
                f"run {run_number} symbolized kernel leaf coverage "
                f"{coverage.numerator}/{coverage.denominator} is below "
                f"{MIN_SYMBOLIZED_LEAVES.numerator}/"
                f"{MIN_SYMBOLIZED_LEAVES.denominator}"
            )
    if errors:
        document["evidence_errors"] = errors
        return document

    top_ten = [
        tuple(
            sorted(
                run.family_counts,
                key=lambda family: (-run.family_counts[family], family),
            )[:10]
        )
        for run in paired_runs
    ]
    shared = set(top_ten[0]).intersection(top_ten[1])
    shared_counts = []
    shared_coverages = []
    for run in paired_runs:
        shared_count = 0
        for family in sorted(shared):
            shared_count = _checked_add(
                shared_count,
                run.family_counts[family],
                f"run {len(shared_counts) + 1} shared top-ten count",
            )
        shared_counts.append(shared_count)
        shared_coverages.append(Fraction(shared_count, run.kernel_stack_count))
    shared_coverage_ok = all(
        coverage >= MIN_SHARED_TOP_TEN_COVERAGE
        for coverage in shared_coverages
    )
    document["shared_top_ten"] = {
        "families": sorted(shared),
        "counts": shared_counts,
        "coverage": [_fraction(coverage) for coverage in shared_coverages],
    }

    ranked_candidates: list[
        tuple[dict[str, object], Fraction, int, bool]
    ] = []
    all_families = set(paired_runs[0].family_counts).union(
        paired_runs[1].family_counts
    )
    try:
        for family in sorted(all_families):
            ranked_candidates.append(
                _candidate_document(
                    family,
                    paired_runs,
                    shared_coverage_ok,
                )
            )
    except EvidenceError as error:
        document["evidence_errors"] = [str(error)]
        document["shared_top_ten"] = None
        return document
    ranked_candidates.sort(
        key=lambda candidate: (
            -candidate[1],
            -candidate[2],
            candidate[0]["family"],
        )
    )
    candidates = [candidate[0] for candidate in ranked_candidates]
    document["candidates"] = candidates

    diffuse_reasons: list[str] = []
    if not any(
        bool(candidate["gates"]["mean_at_least_ten_percent"])
        for candidate in candidates
    ):
        diffuse_reasons.append("no-family-has-ten-percent-mean-share")
    if not shared_coverage_ok:
        diffuse_reasons.append("shared-top-ten-coverage-below-sixty-percent")
    selectable = [candidate for candidate in candidates if candidate["selectable"]]
    if not selectable and not diffuse_reasons:
        diffuse_reasons.append("no-family-meets-stability-gates")

    if not selectable:
        document["result"] = "diffuse"
        document["diffuse_reasons"] = diffuse_reasons
        return document

    selected = dict(selectable[0])
    selected["representative_stacks"] = _representative_stacks(
        str(selected["family"]),
        paired_runs,
    )
    document["result"] = "selectable"
    document["selected_family"] = selected
    return document


def _write_atomic(path: pathlib.Path, document: dict[str, object]) -> None:
    parent = path.parent if str(path.parent) else pathlib.Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    """Run the native kernel attribution command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        type=pathlib.Path,
        help="completed native-wall JSONL profile; pass exactly twice",
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    document = analyze_profiles(args.profile)
    try:
        _write_atomic(args.output, document)
    except OSError as error:
        parser.exit(1, f"native kernel attribution output failed: {error}\n")
    return 1 if document["result"] == "rejected" else 0


if __name__ == "__main__":
    raise SystemExit(main())
