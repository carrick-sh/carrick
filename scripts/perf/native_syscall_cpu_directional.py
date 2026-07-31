#!/usr/bin/env python3
"""Summarize and compare low-overhead native syscall CPU censuses.

The input protocol comes from ``native-syscall-cpu-directional.d``. Counts are
fixed-frequency CPU samples for a completed workload, not elapsed syscall
durations, so sleeps do not masquerade as kernel CPU. Results are directional
and deliberately never promotion-gating evidence.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import defaultdict
from collections.abc import Iterable


SCHEMA = "carrick.native-syscall-cpu-directional.v1"
COMPARISON_SCHEMA = "carrick.native-syscall-cpu-comparison.v1"
PREFIX = "SYSCALLCPU2"
VALID_REASONS = (0, 1, 2)


class SyscallCpuError(RuntimeError):
    """The directional syscall CPU census is malformed or inconsistent."""


def _fields(line: str) -> tuple[str, dict[str, str]]:
    parts = line.strip().split("|")
    if len(parts) < 3 or parts[0] != PREFIX:
        raise SyscallCpuError(f"malformed {PREFIX} record")
    fields: dict[str, str] = {}
    for item in parts[2:]:
        if "=" not in item:
            raise SyscallCpuError(f"malformed {PREFIX} field: {item!r}")
        key, value = item.split("=", 1)
        if not key or key in fields:
            raise SyscallCpuError(f"duplicate {PREFIX} field: {key!r}")
        fields[key] = value
    return parts[1], fields


def _unsigned(value: str, field: str, *, positive: bool = False) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise SyscallCpuError(f"invalid {field}: {value!r}") from error
    if parsed < 0 or (positive and parsed == 0):
        raise SyscallCpuError(f"invalid {field}: {value!r}")
    return parsed


def _share(samples: int, total: int) -> float:
    return samples / total if total else 0.0


def analyze_lines(lines: Iterable[str]) -> dict[str, object]:
    sample_hz: int | None = None
    totals: dict[str, int] = {}
    syscall_cpu: dict[tuple[str, int], int] = {}
    syscall_calls: dict[tuple[str, int], int] = {}
    completion: dict[str, int] | None = None
    saw_record = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith(PREFIX + "|"):
            continue
        saw_record = True
        record, fields = _fields(line)
        if record == "config":
            if set(fields) != {"sample_hz"}:
                raise SyscallCpuError("config record has the wrong field set")
            if sample_hz is not None:
                raise SyscallCpuError("duplicate config record")
            sample_hz = _unsigned(fields["sample_hz"], "sample_hz", positive=True)
        elif record == "total":
            if set(fields) != {"mode", "samples"}:
                raise SyscallCpuError("total record has the wrong field set")
            mode = fields["mode"]
            if mode not in ("kernel", "user"):
                raise SyscallCpuError(f"invalid sample mode: {mode!r}")
            if mode in totals:
                raise SyscallCpuError(f"duplicate {mode} total")
            totals[mode] = _unsigned(fields["samples"], "samples")
        elif record in ("syscall-cpu", "syscall-calls"):
            value_field = "cpu_ns" if record == "syscall-cpu" else "calls"
            if set(fields) != {"host", "reason", value_field}:
                raise SyscallCpuError(f"{record} record has the wrong field set")
            host = fields["host"]
            if not host or "|" in host:
                raise SyscallCpuError(f"invalid host syscall: {host!r}")
            reason = _unsigned(fields["reason"], "reason")
            if reason not in VALID_REASONS:
                raise SyscallCpuError(f"invalid futex reason: {reason}")
            destination = syscall_cpu if record == "syscall-cpu" else syscall_calls
            key = (host, reason)
            if key in destination:
                raise SyscallCpuError(
                    f"duplicate {record} record for {host} reason {reason}"
                )
            destination[key] = _unsigned(
                fields[value_field], value_field, positive=value_field == "calls"
            )
        elif record == "complete":
            if set(fields) != {"target_exit", "timed_out"}:
                raise SyscallCpuError("completion record has the wrong field set")
            if completion is not None:
                raise SyscallCpuError("duplicate completion record")
            completion = {
                "target_exit": _unsigned(fields["target_exit"], "target_exit"),
                "timed_out": _unsigned(fields["timed_out"], "timed_out"),
            }
        else:
            raise SyscallCpuError(f"unknown {PREFIX} record: {record}")

    if not saw_record:
        raise SyscallCpuError(f"no {PREFIX} records found")
    if sample_hz is None:
        raise SyscallCpuError("sample frequency is absent")
    for mode in ("kernel", "user"):
        if mode not in totals:
            raise SyscallCpuError(f"{mode} sample total is absent")

    if syscall_cpu.keys() != syscall_calls.keys():
        raise SyscallCpuError("syscall CPU and call-count keys differ")

    kernel_total = totals["kernel"]
    user_total = totals["user"]
    cpu_by_host: dict[str, int] = defaultdict(int)
    calls_by_host: dict[str, int] = defaultdict(int)
    cpu_by_reason: dict[int, int] = defaultdict(int)
    calls_by_reason: dict[int, int] = defaultdict(int)
    for (host, reason), cpu_ns in syscall_cpu.items():
        cpu_by_host[host] += cpu_ns
        calls_by_host[host] += syscall_calls[(host, reason)]
        cpu_by_reason[reason] += cpu_ns
        calls_by_reason[reason] += syscall_calls[(host, reason)]

    warnings: list[str] = []
    if completion is None:
        warnings.append("completion record is absent")
    elif completion != {"target_exit": 1, "timed_out": 0}:
        warnings.append(
            "capture did not observe one natural target exit before its timeout"
        )

    all_total = kernel_total + user_total
    samples = {"all": all_total, "kernel": kernel_total, "user": user_total}
    syscall_cpu_ns = sum(syscall_cpu.values())
    estimated_kernel_cpu_ns = kernel_total * 1_000_000_000 / sample_hz
    return {
        "schema": SCHEMA,
        "gating_eligible": False,
        "sample_hz": sample_hz,
        "completion": completion,
        "warnings": warnings,
        "samples": samples,
        "estimated_cpu_seconds": {
            mode: count / sample_hz for mode, count in samples.items()
        },
        "kernel_sample_share": _share(kernel_total, all_total),
        "syscall_cpu_ns": syscall_cpu_ns,
        "syscall_cpu_accounting_share": (
            syscall_cpu_ns / estimated_kernel_cpu_ns
            if estimated_kernel_cpu_ns
            else None
        ),
        "kernel_by_host": [
            {
                "calls": calls_by_host[host],
                "cpu_ns": cpu_ns,
                "cpu_seconds": cpu_ns / 1_000_000_000,
                "host": host,
                "share": _share(cpu_ns, syscall_cpu_ns),
            }
            for host, cpu_ns in sorted(
                cpu_by_host.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "kernel_by_reason": [
            {
                "calls": calls_by_reason[reason],
                "cpu_ns": cpu_by_reason[reason],
                "reason": reason,
                "share": _share(cpu_by_reason[reason], syscall_cpu_ns),
            }
            for reason in VALID_REASONS
            if cpu_by_reason[reason]
        ],
        "kernel_by_host_reason": [
            {
                "calls": syscall_calls[(host, reason)],
                "cpu_ns": cpu_ns,
                "host": host,
                "reason": reason,
                "share": _share(cpu_ns, syscall_cpu_ns),
            }
            for (host, reason), cpu_ns in sorted(
                syscall_cpu.items(), key=lambda item: (-item[1], item[0])
            )
        ],
    }


def _delta(baseline: int, candidate: int) -> dict[str, object]:
    difference = candidate - baseline
    return {
        "absolute": difference,
        "fraction": difference / baseline if baseline else None,
    }


def _metrics_by_host(summary: dict[str, object]) -> dict[str, dict[str, int]]:
    return {
        entry["host"]: {"calls": entry["calls"], "cpu_ns": entry["cpu_ns"]}
        for entry in summary["kernel_by_host"]
    }


def compare(
    baseline: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    if baseline["sample_hz"] != candidate["sample_hz"]:
        raise SyscallCpuError("paired captures use different sample frequencies")

    baseline_samples = baseline["samples"]
    candidate_samples = candidate["samples"]
    baseline_hosts = _metrics_by_host(baseline)
    candidate_hosts = _metrics_by_host(candidate)
    host_deltas = []
    for host in set(baseline_hosts) | set(candidate_hosts):
        baseline_metric = baseline_hosts.get(host, {"calls": 0, "cpu_ns": 0})
        candidate_metric = candidate_hosts.get(host, {"calls": 0, "cpu_ns": 0})
        difference = candidate_metric["cpu_ns"] - baseline_metric["cpu_ns"]
        host_deltas.append(
            {
                "baseline_calls": baseline_metric["calls"],
                "baseline_cpu_ns": baseline_metric["cpu_ns"],
                "candidate_calls": candidate_metric["calls"],
                "candidate_cpu_ns": candidate_metric["cpu_ns"],
                "cpu_delta_ns": difference,
                "fraction": (
                    difference / baseline_metric["cpu_ns"]
                    if baseline_metric["cpu_ns"]
                    else None
                ),
                "host": host,
            }
        )
    host_deltas.sort(
        key=lambda entry: (-abs(entry["cpu_delta_ns"]), entry["host"])
    )

    return {
        "schema": COMPARISON_SCHEMA,
        "gating_eligible": False,
        "sample_hz": baseline["sample_hz"],
        "baseline": baseline,
        "candidate": candidate,
        "sample_deltas": {
            mode: _delta(baseline_samples[mode], candidate_samples[mode])
            for mode in ("all", "kernel", "user")
        },
        "kernel_host_deltas": host_deltas,
    }


def _analyze_path(path: pathlib.Path) -> dict[str, object]:
    with path.open(encoding="utf-8", errors="strict") as stream:
        return analyze_lines(stream)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=pathlib.Path)
    mode.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--candidate", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    if (options.baseline is None) != (options.candidate is None):
        print(
            "native syscall CPU analysis failed: --baseline and --candidate must be used together",
            file=sys.stderr,
        )
        return 2
    try:
        if options.input is not None:
            result = _analyze_path(options.input)
        else:
            result = compare(
                _analyze_path(options.baseline),
                _analyze_path(options.candidate),
            )
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if options.output is None:
            sys.stdout.write(rendered)
        else:
            options.output.write_text(rendered, encoding="utf-8")
    except (OSError, UnicodeError, SyscallCpuError) as error:
        print(f"native syscall CPU analysis failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
