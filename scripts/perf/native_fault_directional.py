#!/usr/bin/env python3
"""Summarize a directionally useful Darwin native-fault page sample.

This is deliberately not promotion evidence.  It preserves the private
provider's qualified host-page values and reports sampling/completion defects,
but still publishes rankings when an otherwise parseable capture is incomplete.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import defaultdict
from collections.abc import Iterable


SCHEMA = "carrick.native-fault-directional.v1"
PREFIX = "NFAULT1"
ADDRESSED_OUTCOMES = ("as_fault", "zfod")
U64_MAX = 2**64 - 1
DARWIN_USER_ADDRESS_LIMIT = 1 << 48


class DirectionalFaultError(RuntimeError):
    """The directional census is malformed or has an unsafe address value."""


def _fields(line: str) -> tuple[str, dict[str, str]]:
    parts = line.strip().split("|")
    if len(parts) < 3 or parts[0] != PREFIX:
        raise DirectionalFaultError("malformed NFAULT1 record")
    fields: dict[str, str] = {}
    for item in parts[2:]:
        if "=" not in item:
            raise DirectionalFaultError(f"malformed NFAULT1 field: {item!r}")
        key, value = item.split("=", 1)
        if not key or key in fields:
            raise DirectionalFaultError(f"duplicate NFAULT1 field: {key!r}")
        fields[key] = value
    return parts[1], fields


def _unsigned(value: str, field: str, *, positive: bool = False) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise DirectionalFaultError(f"invalid {field}: {value!r}") from error
    if parsed < 0 or parsed > U64_MAX or (positive and parsed == 0):
        raise DirectionalFaultError(f"invalid {field}: {value!r}")
    return parsed


def _estimated(sampled: int, modulus: int, field: str) -> int:
    if sampled > U64_MAX // modulus:
        raise DirectionalFaultError(f"estimated {field} exceeds u64")
    return sampled * modulus


def _metric(
    events: int,
    distinct: int,
    reported: int | None,
    rejected: int,
    modulus: int,
) -> dict[str, object]:
    return {
        "reported_events": reported,
        "sampled_events": events,
        "rejected_address_events": rejected,
        "sampled_event_share": events / reported if reported else (1.0 if reported == 0 else None),
        "sampled_distinct_process_pages": distinct,
        "sampled_repeat_excess": events - distinct,
        "sampled_repeat_factor": events / distinct if distinct else None,
        "estimated_addressed_events": _estimated(events, modulus, "addressed events"),
        "estimated_distinct_process_pages": _estimated(
            distinct, modulus, "distinct process pages"
        ),
    }


def analyze_lines(lines: Iterable[str], *, page_size: int) -> dict[str, object]:
    if page_size <= 0 or page_size & (page_size - 1):
        raise DirectionalFaultError("page size must be a positive power of two")

    pages: dict[str, dict[tuple[int, int], int]] = {
        outcome: defaultdict(int) for outcome in ADDRESSED_OUTCOMES
    }
    rejected: dict[str, int] = defaultdict(int)
    rejected_by_pid: dict[str, dict[int, int]] = {
        outcome: defaultdict(int) for outcome in ADDRESSED_OUTCOMES
    }
    totals: dict[str, int] = defaultdict(int)
    completion: dict[str, int] | None = None
    page_sample_modulus: int | None = None
    saw_record = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith(PREFIX + "|"):
            continue
        saw_record = True
        record, fields = _fields(line)
        if record == "config":
            if set(fields) != {"page_sample_modulus"}:
                raise DirectionalFaultError("config record has the wrong field set")
            if page_sample_modulus is not None:
                raise DirectionalFaultError("duplicate config record")
            page_sample_modulus = _unsigned(
                fields["page_sample_modulus"], "page sample modulus", positive=True
            )
            if page_sample_modulus & (page_sample_modulus - 1):
                raise DirectionalFaultError(
                    "page sample modulus must be a positive power of two"
                )
        elif record == "page":
            expected = {"outcome", "pid", "page", "count"}
            if set(fields) != expected:
                raise DirectionalFaultError("page record has the wrong field set")
            outcome = fields["outcome"]
            if outcome not in ADDRESSED_OUTCOMES:
                raise DirectionalFaultError(f"unaddressed outcome in page record: {outcome}")
            pid = _unsigned(fields["pid"], "pid", positive=True)
            page = _unsigned(fields["page"], "host page")
            count = _unsigned(fields["count"], "count", positive=True)
            if (
                page == 0
                or page >= DARWIN_USER_ADDRESS_LIMIT
                or page % page_size
            ):
                rejected[outcome] += count
                rejected_by_pid[outcome][pid] += count
                continue
            pages[outcome][(pid, page)] += count
        elif record == "rejected":
            if set(fields) not in (
                {"outcome", "count"},
                {"outcome", "pid", "count"},
            ):
                raise DirectionalFaultError("rejected record has the wrong field set")
            outcome = fields["outcome"]
            if outcome not in ADDRESSED_OUTCOMES:
                raise DirectionalFaultError(
                    f"unaddressed outcome in rejected record: {outcome}"
                )
            count = _unsigned(fields["count"], "count", positive=True)
            rejected[outcome] += count
            if "pid" in fields:
                pid = _unsigned(fields["pid"], "pid", positive=True)
                rejected_by_pid[outcome][pid] += count
        elif record == "total":
            if set(fields) != {"outcome", "count"}:
                raise DirectionalFaultError("total record has the wrong field set")
            totals[fields["outcome"]] += _unsigned(fields["count"], "count")
        elif record == "complete":
            if set(fields) != {"target_exit", "timed_out"}:
                raise DirectionalFaultError("completion record has the wrong field set")
            if completion is not None:
                raise DirectionalFaultError("duplicate completion record")
            completion = {
                "target_exit": _unsigned(fields["target_exit"], "target_exit"),
                "timed_out": _unsigned(fields["timed_out"], "timed_out"),
            }
        else:
            raise DirectionalFaultError(f"unknown NFAULT1 record: {record}")

    if not saw_record:
        raise DirectionalFaultError("no NFAULT1 records found")

    warnings: list[str] = []
    if page_sample_modulus is None:
        page_sample_modulus = 1
        warnings.append(
            "page sample configuration is absent; interpreting page records as a full census"
        )
    elif page_sample_modulus > 1:
        warnings.append(
            f"page identities are a deterministic 1/{page_sample_modulus} sample"
        )

    outcomes: dict[str, dict[str, object]] = {}
    process_metrics: dict[str, dict[str, dict[str, object]]] = {}
    hot_process_pages: dict[str, list[dict[str, object]]] = {}
    for outcome in ADDRESSED_OUTCOMES:
        addressed = sum(pages[outcome].values())
        rejected_events = rejected[outcome]
        observed_lower_bound = addressed + rejected_events
        reported = totals.get(outcome, observed_lower_bound)
        if observed_lower_bound > reported:
            raise DirectionalFaultError(
                f"{outcome} sampled/rejected events exceed reported total: "
                f"{observed_lower_bound} > {reported}"
            )
        if outcome not in totals:
            warnings.append(f"{outcome} total is absent; using sampled events")
        elif page_sample_modulus == 1 and observed_lower_bound != reported:
            warnings.append(
                f"{outcome} addressed {addressed} of {reported} reported events"
            )
        if rejected_events:
            warnings.append(
                f"{outcome} quarantined {rejected_events} event"
                f"{'s' if rejected_events != 1 else ''} with zero, kernel, or "
                "unaligned page values"
            )
        outcomes[outcome] = _metric(
            addressed,
            len(pages[outcome]),
            reported,
            rejected_events,
            page_sample_modulus,
        )

        by_pid: dict[int, list[tuple[int, int]]] = defaultdict(list)
        for (pid, page), count in pages[outcome].items():
            by_pid[pid].append((page, count))
        for pid in sorted(set(by_pid) | set(rejected_by_pid[outcome])):
            entries = by_pid[pid]
            events = sum(count for _, count in entries)
            rejected_for_pid = rejected_by_pid[outcome][pid]
            process_metrics.setdefault(str(pid), {})[outcome] = _metric(
                events,
                len(entries),
                None,
                rejected_for_pid,
                page_sample_modulus,
            )
        hot_process_pages[outcome] = [
            {"pid": pid, "page": f"0x{page:x}", "count": count}
            for (pid, page), count in sorted(
                pages[outcome].items(), key=lambda item: (-item[1], item[0])
            )[:20]
        ]

    if completion is None:
        warnings.append("completion record is absent")
    elif completion["target_exit"] != 1 or completion["timed_out"] != 0:
        warnings.append(
            "capture did not observe one natural target exit before its timeout"
        )

    return {
        "schema": SCHEMA,
        "gating_eligible": False,
        "page_size": page_size,
        "page_sample_modulus": page_sample_modulus,
        "completion": completion,
        "warnings": warnings,
        "outcomes": outcomes,
        "processes": process_metrics,
        "hot_process_pages": hot_process_pages,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize a directional Carrick native-fault page census."
    )
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--page-size", type=int, default=16_384)
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        with options.input.open(encoding="utf-8", errors="strict") as stream:
            result = analyze_lines(stream, page_size=options.page_size)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if options.output is None:
            sys.stdout.write(rendered)
        else:
            options.output.write_text(rendered, encoding="utf-8")
    except (OSError, UnicodeError, DirectionalFaultError) as error:
        print(f"native fault directional analysis failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
