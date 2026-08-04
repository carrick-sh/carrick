#!/usr/bin/env python3
"""Reconcile and attribute Carrick's Darwin native-wall DTrace profile.

The profile deliberately measures three different quantities:

* elapsed wall-state occupancy at 197 Hz;
* on-CPU resource samples at 499 Hz; and
* exact off-CPU durations plus the heaviest voluntary-blocking stacks.

This program keeps those quantities separate and refuses to publish evidence
when capture completeness, address classification, stack coverage, or
between-run stability misses the campaign thresholds.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))
from symbolicate import atos_batch, image_text_size  # noqa: E402


SCHEMA = "carrick.dsr-profile.v1"
OUTPUT_SCHEMA = "carrick.native-wall-attribution.v1"
PROFILE = "native-wall"
WALL_HZ = 197
CPU_HZ = 499
MIN_WALL_COVERAGE = 0.99
MIN_CPU_COVERAGE = 0.85
MIN_STACK_COVERAGE = 0.80
MAX_CATEGORY_DELTA = 0.05

WALL_STATES = (
    "on-cpu",
    "runnable-descheduled",
    "all-sleeping",
    "transition",
)
CPU_CATEGORIES = (
    "translated-guest",
    "translation",
    "gateway",
    "dispatch",
    "process-setup",
    "darwin-userspace",
    "darwin-kernel",
    "other-carrick",
    "unresolved",
)
KERNEL_CLASSES = (
    "kernel-named-syscall",
    "kernel-non-syscall",
)
CATEGORY_RULES = (
    ("translation", ("carrick_dsr_aarch64", "dynasm", "translate", "emit")),
    (
        "gateway",
        ("native_darwin", "prepare", "resolve", "recover_rewrite_state"),
    ),
    ("dispatch", ("dispatch", "syscall", "carrick_host")),
    ("process-setup", ("capsule", "prepared_image", "clap", "serde", "sha2")),
)

PROVENANCE_FIELDS = (
    "run_id",
    "git_sha",
    "git_dirty",
    "binary_sha256",
    "command",
    "host",
)


@dataclass(frozen=True)
class ProfileRow:
    phase: str | None
    pid: int | None
    tid: int | None
    kind: str | None
    source_pc: int | None
    target_pc: int | None
    metric_type: str
    metric: dict[str, Any]


@dataclass(frozen=True)
class Profile:
    path: pathlib.Path
    provenance: dict[str, Any]
    completion: dict[str, Any]
    rows: tuple[ProfileRow, ...]


DROP_FIELDS = (
    "principal_drops",
    "aggregation_drops",
    "dynamic_drops",
    "dynamic_rinse_drops",
    "dynamic_dirty_drops",
    "other_drops",
)


def _require_int(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{description} must be an integer")
    return value


def _completion_failures(completion: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    drops = completion.get("drops")
    if not isinstance(drops, dict):
        return ["completion has no drop status"]
    if completion.get("complete") is not True:
        failures.append("capture is not complete")
    if completion.get("bounded") is not False:
        failures.append("capture did not complete naturally")
    if completion.get("target_exit_reason") != 1:
        failures.append("target exit reason is not natural process exit")
    if completion.get("high_cardinality_overflow") is not False:
        failures.append("capture overflowed a high-cardinality aggregation")
    if completion.get("incomplete_pairs") != 0:
        failures.append("capture contains incomplete duration pairs")
    if set(drops) != {"interrupted", *DROP_FIELDS}:
        failures.append("completion has malformed drop status fields")
        return failures
    if drops.get("interrupted") is not False:
        failures.append("capture was interrupted")
    for name in DROP_FIELDS:
        if _require_int(drops.get(name), f"completion drops.{name}") != 0:
            failures.append(f"capture has nonzero {name.replace('_', ' ')}")
    return failures


def load_profile(path: pathlib.Path) -> Profile:
    """Load one native-wall JSONL capture and reject publisher corruption."""
    raw_lines = path.read_text().splitlines()
    if not raw_lines:
        raise ValueError(f"{path}: empty profile")

    raw_rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw_lines, 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_number}: blank JSONL row")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: row is not an object")
        raw_rows.append(value)

    first = raw_rows[0]
    if first.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA!r}")
    if first.get("profile") != PROFILE:
        raise ValueError(f"{path}: expected profile {PROFILE!r}")
    provenance = {field: first.get(field) for field in PROVENANCE_FIELDS}
    completion = first.get("completion")
    if not isinstance(completion, dict):
        raise ValueError(f"{path}: completion is not an object")

    rows: list[ProfileRow] = []
    seen: set[tuple[Any, ...]] = set()
    completion_rows = 0
    for line_number, value in enumerate(raw_rows, 1):
        if value.get("schema") != SCHEMA or value.get("profile") != PROFILE:
            raise ValueError(f"{path}:{line_number}: schema or profile changed")
        if {field: value.get(field) for field in PROVENANCE_FIELDS} != provenance:
            raise ValueError(f"{path}:{line_number}: provenance changed within profile")
        if value.get("completion") != completion:
            raise ValueError(f"{path}:{line_number}: completion state changed within profile")

        scope = value.get("scope")
        metric = value.get("metric")
        if not isinstance(scope, dict) or not isinstance(metric, dict):
            raise ValueError(f"{path}:{line_number}: invalid scope or metric")
        metric_type = metric.get("type")
        if not isinstance(metric_type, str):
            raise ValueError(f"{path}:{line_number}: metric has no type")
        if metric_type == "completion":
            completion_rows += 1

        parsed = ProfileRow(
            phase=scope.get("phase"),
            pid=scope.get("pid"),
            tid=scope.get("tid"),
            kind=scope.get("kind"),
            source_pc=scope.get("source_pc"),
            target_pc=scope.get("target_pc"),
            metric_type=metric_type,
            metric=metric,
        )
        for field_name in ("pid", "tid", "source_pc", "target_pc"):
            field_value = getattr(parsed, field_name)
            if field_value is not None:
                _require_int(field_value, f"{path}:{line_number}: {field_name}")

        key: tuple[Any, ...] = (
            parsed.phase,
            parsed.pid,
            parsed.tid,
            parsed.kind,
            parsed.source_pc,
            parsed.target_pc,
            parsed.metric_type,
        )
        # Stack rows intentionally share a scope when one PID has several hot
        # blocking callsites. Their frames distinguish the publisher records;
        # every other repeated scope/type is corruption, not an additive row.
        if metric_type == "stack-trace":
            frames = metric.get("frames")
            if not isinstance(frames, list) or not frames:
                raise ValueError(f"{path}:{line_number}: stack has no frames")
            key += (tuple(frames),)
        if key in seen:
            raise ValueError(f"{path}:{line_number}: duplicate metric scope")
        seen.add(key)
        rows.append(parsed)

    if completion_rows != 1:
        raise ValueError(f"{path}: expected one completion row, got {completion_rows}")
    failures = _completion_failures(completion)
    if failures:
        raise ValueError(f"{path}: " + "; ".join(failures))
    return Profile(
        path=path,
        provenance=provenance,
        completion=completion,
        rows=tuple(rows),
    )


def classify_host_symbol(symbol: str) -> str:
    lowered = symbol.lower()
    for category, needles in CATEGORY_RULES:
        if any(needle in lowered for needle in needles):
            return category
    return "other-carrick"


def _exact_count(row: ProfileRow) -> int:
    if row.metric_type != "exact":
        raise ValueError(f"{row.phase}: expected exact metric")
    return _require_int(row.metric.get("count"), f"{row.phase}: count")


def _exact_ns(row: ProfileRow) -> int:
    if row.metric_type != "exact":
        raise ValueError(f"{row.phase}: expected exact metric")
    return _require_int(row.metric.get("total_ns"), f"{row.phase}: total_ns")


def _single(rows: list[ProfileRow], description: str) -> ProfileRow:
    if len(rows) != 1:
        raise ValueError(f"expected one {description} row, got {len(rows)}")
    return rows[0]


def _optional_total(rows: list[ProfileRow], description: str) -> int:
    if not rows:
        return 0
    return _exact_ns(_single(rows, description))


def _address_ranges(
    rows: tuple[ProfileRow, ...],
    binary: pathlib.Path,
) -> tuple[dict[int, list[tuple[int, int]]], dict[int, list[tuple[int, int]]]]:
    jit_ranges: dict[int, list[tuple[int, int]]] = defaultdict(list)
    jit_points: dict[int, dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )
    host_bases: dict[int, list[int]] = defaultdict(list)
    for row in rows:
        if row.phase == "jit-range":
            if row.pid is None or row.source_pc is None or row.target_pc is None:
                raise ValueError("jit-range row is missing pid or endpoint")
            if row.source_pc >= row.target_pc:
                raise ValueError(
                    f"pid {row.pid}: invalid JIT range "
                    f"{row.source_pc:#x}..{row.target_pc:#x}"
                )
            if _exact_count(row) <= 0:
                raise ValueError(f"pid {row.pid}: empty JIT range publication")
            jit_ranges[row.pid].append((row.source_pc, row.target_pc))
            continue
        if row.phase != "image-base" or row.pid is None or row.source_pc is None:
            continue
        if row.kind in {"jit-start", "jit-end"}:
            jit_points[row.pid][row.kind].append(row.source_pc)
        elif row.kind == "host":
            host_bases[row.pid].append(row.source_pc)

    for pid, points in jit_points.items():
        starts = sorted(set(points["jit-start"]))
        ends = sorted(set(points["jit-end"]))
        if len(starts) != len(ends):
            raise ValueError(f"pid {pid}: unmatched JIT range announcements")
        for start, end in zip(starts, ends, strict=True):
            if start >= end:
                raise ValueError(f"pid {pid}: invalid JIT range {start:#x}..{end:#x}")
            jit_ranges[pid].append((start, end))
    for pid, ranges in jit_ranges.items():
        jit_ranges[pid] = sorted(set(ranges))

    host_ranges: dict[int, list[tuple[int, int]]] = defaultdict(list)
    if host_bases:
        if not binary.exists():
            raise ValueError(f"host image announced but binary is missing: {binary}")
        size = image_text_size(binary)
        if size <= 0:
            raise ValueError(f"cannot determine __TEXT size for {binary}")
        for pid, bases in host_bases.items():
            host_ranges[pid] = [(base, base + size) for base in sorted(set(bases))]
    return dict(jit_ranges), dict(host_ranges)


def _dyld_image_ranges(
    rows: tuple[ProfileRow, ...],
) -> dict[int, list[tuple[int, int, str]]]:
    catalogs: dict[int, list[tuple[int, int, str]]] = {}
    for row in rows:
        if row.metric_type != "image-catalog":
            continue
        pid = _require_int(row.metric.get("pid"), "image catalog pid")
        if row.pid != pid:
            raise ValueError(
                f"image catalog scope pid {row.pid} does not match metric pid {pid}"
            )
        raw_ranges = row.metric.get("ranges")
        if not isinstance(raw_ranges, list) or not raw_ranges:
            raise ValueError(f"image catalog for pid {pid} has no ranges")
        ranges: list[tuple[int, int, str]] = []
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                raise ValueError(f"image catalog for pid {pid} has a non-object range")
            start = _require_int(raw_range.get("start"), "image range start")
            end = _require_int(raw_range.get("end"), "image range end")
            path = raw_range.get("path")
            if start >= end:
                raise ValueError(
                    f"image catalog for pid {pid} has invalid range "
                    f"{start:#x}..{end:#x}"
                )
            if not isinstance(path, str):
                raise ValueError(f"image catalog for pid {pid} has invalid path")
            ranges.append((start, end, path))
        if pid in catalogs:
            if catalogs[pid] != ranges:
                raise ValueError(f"conflicting image catalogs for pid {pid}")
            continue
        catalogs[pid] = ranges
    return catalogs


def _inside(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _dyld_image_path(
    address: int,
    ranges: list[tuple[int, int, str]],
) -> str | None:
    for start, end, path in ranges:
        if start <= address < end:
            return path
    return None


def _host_symbols(
    binary: pathlib.Path,
    host_ranges: dict[int, list[tuple[int, int]]],
    addresses: set[tuple[int, int]],
) -> dict[tuple[int, int], str]:
    by_base: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for pid, address in addresses:
        for start, end in host_ranges.get(pid, []):
            if start <= address < end:
                by_base[start].append((pid, address))
                break

    resolved: dict[tuple[int, int], str] = {}
    for base, pid_addresses in by_base.items():
        addresses_for_base = sorted({address for _, address in pid_addresses})
        batch = atos_batch(binary, base, addresses_for_base)
        for pid, address in pid_addresses:
            symbol = batch.get(address)
            if symbol and not symbol.lower().startswith("0x"):
                resolved[(pid, address)] = symbol
    return resolved


def _metric_bucket(samples: int, total: int) -> dict[str, int | float]:
    return {
        "samples": samples,
        "share": samples / total if total else 0.0,
    }


def summarize(profile: Profile, binary: pathlib.Path) -> dict[str, object]:
    """Turn one complete capture into separately reconciled evidence lanes."""
    rows = profile.rows
    failures: list[str] = []

    wall_rows = [row for row in rows if row.phase == "wall-state"]
    wall_sample_row = _single(
        [row for row in rows if row.phase == "wall-samples"], "wall-samples"
    )
    elapsed_row = _single([row for row in rows if row.phase == "elapsed"], "elapsed")
    live_row = _single(
        [
            row
            for row in rows
            if row.phase == "process-lifecycle" and row.kind == "live-at-end"
        ],
        "live-at-end",
    )
    wall_samples = _exact_count(wall_sample_row)
    elapsed_ns = _exact_ns(elapsed_row)
    live_at_end = _exact_count(live_row)
    wall_counts = Counter({state: 0 for state in WALL_STATES})
    for row in wall_rows:
        if row.kind not in WALL_STATES:
            failures.append(f"unknown wall state {row.kind!r}")
            continue
        wall_counts[row.kind] += _exact_count(row)
    wall_bucket_total = sum(wall_counts.values())
    expected_wall_samples = elapsed_ns * WALL_HZ / 1_000_000_000
    wall_timer_coverage = (
        min(1.0, wall_samples / expected_wall_samples)
        if expected_wall_samples > 0
        else 0.0
    )
    if wall_samples <= 0:
        failures.append("wall profile has no samples")
    if wall_bucket_total != wall_samples:
        failures.append(
            f"wall buckets total {wall_bucket_total}, expected {wall_samples}"
        )
    if wall_timer_coverage < MIN_WALL_COVERAGE:
        failures.append(
            f"wall timer coverage {wall_timer_coverage:.3%} is below 99%"
        )
    if live_at_end != 0:
        failures.append(f"{live_at_end} tracked process(es) remained live at end")

    jit_ranges, host_ranges = _address_ranges(rows, binary)
    dyld_ranges = _dyld_image_ranges(rows)
    cpu_rows = [
        row
        for row in rows
        if row.phase in {"cpu-user-pc", "cpu-kernel-pc"}
    ]
    host_addresses: set[tuple[int, int]] = set()
    for row in cpu_rows:
        if (
            row.phase == "cpu-user-pc"
            and row.pid is not None
            and row.source_pc is not None
            and _inside(row.source_pc, host_ranges.get(row.pid, []))
        ):
            host_addresses.add((row.pid, row.source_pc))
    for row in rows:
        if row.metric_type != "stack-trace" or row.pid is None:
            continue
        frames = row.metric.get("frames", [])
        for frame in frames:
            try:
                address = int(frame, 16)
            except (TypeError, ValueError):
                continue
            if _inside(address, host_ranges.get(row.pid, [])):
                host_addresses.add((row.pid, address))
    host_symbols = _host_symbols(binary, host_ranges, host_addresses)

    cpu_counts = Counter({category: 0 for category in CPU_CATEGORIES})
    kernel_counts = Counter({category: 0 for category in KERNEL_CLASSES})
    darwin_user_images: Counter[str] = Counter()
    for row in cpu_rows:
        samples = _exact_count(row)
        if row.phase == "cpu-kernel-pc":
            cpu_counts["darwin-kernel"] += samples
            if row.kind not in KERNEL_CLASSES:
                failures.append(f"unknown kernel class {row.kind!r}")
            else:
                kernel_counts[row.kind] += samples
            continue
        if row.pid is None or row.source_pc is None:
            cpu_counts["unresolved"] += samples
            continue
        if _inside(row.source_pc, jit_ranges.get(row.pid, [])):
            cpu_counts["translated-guest"] += samples
            continue
        symbol = host_symbols.get((row.pid, row.source_pc))
        if symbol is not None:
            cpu_counts[classify_host_symbol(symbol)] += samples
            continue
        if _inside(row.source_pc, host_ranges.get(row.pid, [])):
            # The exact per-process Mach-O __TEXT announcement proves
            # ownership even when atos has no symbol for a stripped thunk or
            # address between symbols. Keep it in the deliberately broad
            # Carrick bucket rather than inventing a subsystem attribution.
            cpu_counts["other-carrick"] += samples
            continue
        image_path = _dyld_image_path(
            row.source_pc,
            dyld_ranges.get(row.pid, []),
        )
        if image_path is not None:
            cpu_counts["darwin-userspace"] += samples
            darwin_user_images[image_path or "[unnamed dyld image]"] += samples
            continue
        cpu_counts["unresolved"] += samples

    total_cpu_samples = sum(cpu_counts.values())
    resolved_cpu_samples = total_cpu_samples - cpu_counts["unresolved"]
    cpu_coverage = (
        resolved_cpu_samples / total_cpu_samples if total_cpu_samples else 0.0
    )
    if total_cpu_samples == 0:
        failures.append("profile has no CPU samples")
    if cpu_coverage < MIN_CPU_COVERAGE:
        failures.append(
            f"resolved CPU coverage {cpu_coverage:.3%} is below "
            f"{MIN_CPU_COVERAGE:.0%}"
        )

    voluntary_rows = [
        row for row in rows if row.phase == "offcpu-voluntary-total"
    ]
    runnable_rows = [row for row in rows if row.phase == "offcpu-runnable-total"]
    voluntary_ns = _optional_total(voluntary_rows, "voluntary off-CPU total")
    runnable_ns = _optional_total(runnable_rows, "runnable off-CPU total")
    stacks: list[dict[str, object]] = []
    stack_total_ns = 0
    for row in rows:
        # Kernel stacks carry sampled counts and runnable stacks carry a
        # different off-CPU population. Only voluntary stacks reconcile with
        # voluntary_ns and participate in this duration coverage metric.
        if (
            row.metric_type != "stack-trace"
            or row.phase != "offcpu-voluntary-stack"
        ):
            continue
        value_ns = _require_int(row.metric.get("value_ns"), "stack value_ns")
        stack_total_ns += value_ns
        rendered_frames: list[str] = []
        for raw_frame in row.metric.get("frames", []):
            try:
                address = int(raw_frame, 16)
            except (TypeError, ValueError):
                rendered_frames.append(str(raw_frame))
                continue
            symbol = (
                host_symbols.get((row.pid, address))
                if row.pid is not None
                else None
            )
            if symbol:
                rendered_frames.append(symbol)
            elif row.pid is not None and _inside(
                address, jit_ranges.get(row.pid, [])
            ):
                rendered_frames.append(f"[translated-guest {address:#x}]")
            elif row.pid is not None and _inside(
                address, host_ranges.get(row.pid, [])
            ):
                rendered_frames.append(f"[carrick-text {address:#x}]")
            elif row.pid is not None and (
                image_path := _dyld_image_path(
                    address,
                    dyld_ranges.get(row.pid, []),
                )
            ) is not None:
                rendered_frames.append(
                    f"[darwin-userspace {image_path or '[unnamed]'} {address:#x}]"
                )
            else:
                rendered_frames.append(f"[unresolved {address:#x}]")
        stacks.append(
            {
                "pid": row.pid,
                "duration_ns": value_ns,
                "share": value_ns / voluntary_ns if voluntary_ns else 0.0,
                "frames": rendered_frames,
            }
        )
    stacks.sort(key=lambda stack: int(stack["duration_ns"]), reverse=True)
    stack_coverage = (
        min(1.0, stack_total_ns / voluntary_ns) if voluntary_ns else 1.0
    )
    if stack_coverage < MIN_STACK_COVERAGE:
        failures.append(
            f"voluntary blocking stack coverage {stack_coverage:.3%} is below 80%"
        )

    elapsed_seconds = elapsed_ns / 1_000_000_000
    estimated_cpu_seconds = total_cpu_samples / CPU_HZ
    result: dict[str, object] = {
        "schema": OUTPUT_SCHEMA,
        "profile_path": str(profile.path),
        "provenance": profile.provenance,
        "elapsed_ns": elapsed_ns,
        "average_cpu_parallelism": (
            estimated_cpu_seconds / elapsed_seconds if elapsed_seconds else 0.0
        ),
        "wall_state": {
            state: _metric_bucket(wall_counts[state], wall_samples)
            for state in WALL_STATES
        },
        "cpu": {
            **{
                category: _metric_bucket(cpu_counts[category], total_cpu_samples)
                for category in CPU_CATEGORIES
            },
            "darwin-user-images": [
                {
                    "path": path,
                    **_metric_bucket(samples, total_cpu_samples),
                }
                for path, samples in darwin_user_images.most_common()
            ],
            "kernel-classes": {
                category: _metric_bucket(kernel_counts[category], total_cpu_samples)
                for category in KERNEL_CLASSES
            },
        },
        "offcpu": {
            "voluntary_ns": voluntary_ns,
            "runnable_ns": runnable_ns,
            "top_stack_coverage": stack_coverage,
            "top_stacks": stacks,
        },
        "reconciliation": {
            "wall_samples": wall_samples,
            "wall_bucket_total": wall_bucket_total,
            "expected_wall_samples": expected_wall_samples,
            "wall_timer_coverage": wall_timer_coverage,
            "cpu_samples": total_cpu_samples,
            "resolved_cpu_samples": resolved_cpu_samples,
            "resolved_cpu_coverage": cpu_coverage,
            "live_processes_at_end": live_at_end,
            "voluntary_stack_ns": stack_total_ns,
        },
        "accepted": not failures,
        "failures": failures,
    }
    return result


def compare(a: dict[str, object], b: dict[str, object]) -> dict[str, object]:
    failures: list[str] = []
    if not a.get("accepted") or not b.get("accepted"):
        failures.append("both single-run summaries must be accepted")

    cpu_a = a["cpu"]
    cpu_b = b["cpu"]
    assert isinstance(cpu_a, dict) and isinstance(cpu_b, dict)
    dominant_a = max(
        CPU_CATEGORIES,
        key=lambda category: float(cpu_a[category]["share"]),
    )
    dominant_b = max(
        CPU_CATEGORIES,
        key=lambda category: float(cpu_b[category]["share"]),
    )
    if dominant_a != dominant_b:
        failures.append(
            f"dominant CPU category changed from {dominant_a} to {dominant_b}"
        )

    deltas: dict[str, float] = {}
    for category in CPU_CATEGORIES:
        share_a = float(cpu_a[category]["share"])
        share_b = float(cpu_b[category]["share"])
        delta = abs(share_a - share_b)
        deltas[category] = delta
        if max(share_a, share_b) >= 0.10 and delta > MAX_CATEGORY_DELTA:
            failures.append(
                f"{category} moved {delta * 100:.2f} percentage points"
            )
    kernel_deltas: dict[str, float] = {}
    kernel_a = cpu_a["kernel-classes"]
    kernel_b = cpu_b["kernel-classes"]
    assert isinstance(kernel_a, dict) and isinstance(kernel_b, dict)
    for category in KERNEL_CLASSES:
        share_a = float(kernel_a[category]["share"])
        share_b = float(kernel_b[category]["share"])
        delta = abs(share_a - share_b)
        kernel_deltas[category] = delta
        if max(share_a, share_b) >= 0.10 and delta > MAX_CATEGORY_DELTA:
            failures.append(
                f"{category} moved {delta * 100:.2f} percentage points"
            )
    return {
        "accepted": not failures,
        "dominant_category": dominant_a if dominant_a == dominant_b else None,
        "category_absolute_deltas": deltas,
        "kernel_class_absolute_deltas": kernel_deltas,
        "failures": failures,
    }


def _write_atomic(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _print_summary(summary: dict[str, object]) -> None:
    print(
        f"{summary['profile_path']}: "
        f"{int(summary['elapsed_ns']) / 1_000_000_000:.3f}s elapsed, "
        f"{float(summary['average_cpu_parallelism']):.2f} average CPUs"
    )
    wall = summary["wall_state"]
    cpu = summary["cpu"]
    assert isinstance(wall, dict) and isinstance(cpu, dict)
    print(
        "  wall: "
        + ", ".join(
            f"{state}={float(wall[state]['share']):.1%}" for state in WALL_STATES
        )
    )
    print(
        "  CPU: "
        + ", ".join(
            f"{category}={float(cpu[category]['share']):.1%}"
            for category in CPU_CATEGORIES
            if int(cpu[category]["samples"])
        )
    )
    offcpu = summary["offcpu"]
    reconciliation = summary["reconciliation"]
    assert isinstance(offcpu, dict) and isinstance(reconciliation, dict)
    print(
        f"  off-CPU: voluntary={int(offcpu['voluntary_ns']) / 1e9:.3f}s, "
        f"runnable={int(offcpu['runnable_ns']) / 1e9:.3f}s, "
        f"top-stack coverage={float(offcpu['top_stack_coverage']):.1%}"
    )
    for index, stack in enumerate(offcpu["top_stacks"][:5], 1):
        assert isinstance(stack, dict)
        frames = stack["frames"]
        assert isinstance(frames, list)
        first_frame = frames[0] if frames else "[no frame]"
        print(
            f"    {index}. {float(stack['share']):.1%} "
            f"{int(stack['duration_ns']) / 1e9:.3f}s {first_frame}"
        )
    print(
        "  reconciliation: "
        f"wall={float(reconciliation['wall_timer_coverage']):.1%}, "
        f"CPU={float(reconciliation['resolved_cpu_coverage']):.1%}, "
        f"accepted={summary['accepted']}"
    )
    for failure in summary["failures"]:
        print(f"    reject: {failure}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="append",
        required=True,
        type=pathlib.Path,
        help="native-wall JSONL profile; pass twice for stability validation",
    )
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    if len(args.profile) not in {1, 2}:
        parser.error("--profile must be passed once or twice")

    try:
        summaries = [
            summarize(load_profile(profile_path), args.binary)
            for profile_path in args.profile
        ]
    except (OSError, ValueError) as error:
        print(f"native-wall attribution rejected: {error}", file=sys.stderr)
        return 1

    for summary in summaries:
        _print_summary(summary)
    comparison = compare(summaries[0], summaries[1]) if len(summaries) == 2 else None
    accepted = all(bool(summary["accepted"]) for summary in summaries)
    if comparison is not None:
        accepted = accepted and bool(comparison["accepted"])
        print(f"stability accepted={comparison['accepted']}")
        for failure in comparison["failures"]:
            print(f"  reject: {failure}")
    if not accepted:
        print("native-wall attribution rejected; no artifact published", file=sys.stderr)
        return 1

    artifact = {
        "schema": OUTPUT_SCHEMA,
        "profiles": summaries,
        "comparison": comparison,
        "accepted": True,
    }
    _write_atomic(args.output, artifact)
    print(f"published {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
