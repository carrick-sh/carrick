#!/usr/bin/env python3
"""Classify sampled native PCs against Carrick's translated-range catalog.

This is intentionally directional evidence. DTrace aggregates sampled
``(pid, PC)`` pairs without trying to unwind JIT frames; this analyzer joins
those PCs to the process-owned private/shared range announcements offline.
It never claims gating eligibility.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys
from collections import defaultdict
from collections.abc import Sequence


SCHEMA = "carrick.native-pc-range-directional.v1"
PROTOCOL = "PCPROFILE1"


class ProfileError(RuntimeError):
    """The directional capture is malformed or ownership is ambiguous."""


@dataclasses.dataclass(frozen=True, order=True)
class TranslatedRange:
    pid: int
    epoch: int
    kind: str
    start: int
    end: int

    def contains(self, pc: int) -> bool:
        return self.start <= pc < self.end


def _parse_fields(line: str, line_number: int) -> tuple[str, dict[str, str]]:
    parts = line.split("|")
    if len(parts) < 2 or parts[0] != PROTOCOL:
        raise ProfileError(f"line {line_number}: malformed {PROTOCOL} record")
    fields: dict[str, str] = {}
    for part in parts[2:]:
        if "=" not in part:
            raise ProfileError(f"line {line_number}: malformed field {part!r}")
        key, value = part.split("=", 1)
        if not key or key in fields:
            raise ProfileError(f"line {line_number}: duplicate or empty field {key!r}")
        fields[key] = value
    return parts[1], fields


def _integer(fields: dict[str, str], key: str, line_number: int) -> int:
    try:
        value = int(fields[key], 0)
    except KeyError as error:
        raise ProfileError(f"line {line_number}: missing {key}") from error
    except ValueError as error:
        raise ProfileError(f"line {line_number}: invalid {key}={fields[key]!r}") from error
    return value


def _range_owner(
    ranges_by_catalog: dict[tuple[int, int], list[TranslatedRange]],
    pid: int,
    epoch: int,
    pc: int,
) -> TranslatedRange | None:
    matches = [
        translated
        for translated in ranges_by_catalog.get((pid, epoch), ())
        if translated.contains(pc)
    ]
    kinds = {translated.kind for translated in matches}
    if len(kinds) > 1:
        raise ProfileError(
            f"sample pid={pid} epoch={epoch} pc=0x{pc:x} has overlapping "
            "translated ownership"
        )
    if not matches:
        return None
    return min(matches, key=lambda translated: translated.end - translated.start)


def _validate_range_ownership(
    ranges_by_catalog: dict[tuple[int, int], list[TranslatedRange]],
) -> None:
    for (pid, epoch), translated_ranges in ranges_by_catalog.items():
        ordered = sorted(translated_ranges, key=lambda item: (item.start, item.end, item.kind))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if right.start >= left.end:
                    break
                if left.kind != right.kind:
                    raise ProfileError(
                        "overlapping translated ranges for "
                        f"pid={pid} epoch={epoch}: {left.kind} "
                        f"0x{left.start:x}..0x{left.end:x} and "
                        f"{right.kind} 0x{right.start:x}..0x{right.end:x}"
                    )


def analyze_raw(path: pathlib.Path) -> dict[str, object]:
    sample_hz: int | None = None
    ranges: set[TranslatedRange] = set()
    range_reported = {"private": 0, "shared": 0}
    resets = 0
    user_samples: dict[tuple[int, int, int], int] = defaultdict(int)
    kernel_samples: dict[tuple[int, int], int] = defaultdict(int)
    completion: dict[str, int] | None = None

    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.startswith(f"{PROTOCOL}|"):
            continue
        record, fields = _parse_fields(line, line_number)
        if record == "config":
            observed_hz = _integer(fields, "sample_hz", line_number)
            if observed_hz <= 0:
                raise ProfileError(f"line {line_number}: sample_hz must be positive")
            if sample_hz is not None and sample_hz != observed_hz:
                raise ProfileError("capture reports conflicting sample frequencies")
            sample_hz = observed_hz
        elif record == "reset":
            _integer(fields, "pid", line_number)
            _integer(fields, "epoch", line_number)
            resets += 1
        elif record == "range":
            kind = fields.get("kind")
            if kind not in range_reported:
                raise ProfileError(f"line {line_number}: invalid translated range kind {kind!r}")
            pid = _integer(fields, "pid", line_number)
            epoch = _integer(fields, "epoch", line_number)
            _integer(fields, "sequence", line_number)
            start = _integer(fields, "start", line_number)
            end = _integer(fields, "end", line_number)
            if pid <= 0 or start >= end:
                raise ProfileError(
                    f"line {line_number}: invalid translated range pid={pid} "
                    f"0x{start:x}..0x{end:x}"
                )
            range_reported[kind] += 1
            ranges.add(TranslatedRange(pid, epoch, kind, start, end))
        elif record == "sample":
            kind = fields.get("kind")
            pid = _integer(fields, "pid", line_number)
            epoch = _integer(fields, "epoch", line_number)
            count = _integer(fields, "count", line_number)
            if pid <= 0 or epoch <= 0 or count <= 0:
                raise ProfileError(
                    f"line {line_number}: sample pid/epoch/count must be positive"
                )
            if kind == "user":
                pc = _integer(fields, "pc", line_number)
                if pc <= 0:
                    raise ProfileError(f"line {line_number}: user PC must be positive")
                user_samples[(pid, epoch, pc)] += count
            elif kind == "kernel":
                kernel_samples[(pid, epoch)] += count
            else:
                raise ProfileError(f"line {line_number}: invalid sample kind {kind!r}")
        elif record == "completion":
            if completion is not None:
                raise ProfileError("capture contains multiple completion records")
            completion = {
                "target_exit": _integer(fields, "target_exit", line_number),
                "timed_out": _integer(fields, "timed_out", line_number),
            }
        else:
            raise ProfileError(f"line {line_number}: unknown {PROTOCOL} record {record!r}")

    ranges_by_catalog: dict[tuple[int, int], list[TranslatedRange]] = defaultdict(list)
    for translated in ranges:
        ranges_by_catalog[(translated.pid, translated.epoch)].append(translated)
    _validate_range_ownership(ranges_by_catalog)

    bucket_counts = {"host": 0, "private_jit": 0, "shared_jit": 0}
    hot_host: list[tuple[int, int, int, int]] = []
    host_by_pc: dict[int, int] = defaultdict(int)
    translated_samples: dict[TranslatedRange, int] = defaultdict(int)
    for (pid, epoch, pc), count in user_samples.items():
        owner = _range_owner(ranges_by_catalog, pid, epoch, pc)
        if owner is None:
            bucket_counts["host"] += count
            hot_host.append((count, pid, epoch, pc))
            host_by_pc[pc] += count
        else:
            bucket_counts[f"{owner.kind}_jit"] += count
            translated_samples[owner] += count

    user_total = sum(user_samples.values())
    kernel_total = sum(kernel_samples.values())
    all_total = user_total + kernel_total
    samples = {
        "all": all_total,
        "host": bucket_counts["host"],
        "kernel": kernel_total,
        "private_jit": bucket_counts["private_jit"],
        "shared_jit": bucket_counts["shared_jit"],
        "user": user_total,
    }
    shares = {
        key: (value / all_total if all_total else 0.0)
        for key, value in samples.items()
        if key != "all"
    }

    warnings: list[str] = []
    if completion is None:
        warnings.append("capture has no completion record")
        completion = {"target_exit": 0, "timed_out": 0}
    else:
        if completion["timed_out"]:
            warnings.append("capture reached its directional timeout")
        if completion["target_exit"] != 1:
            warnings.append("target exit was not observed exactly once")
    if sample_hz is None:
        warnings.append("capture has no sample frequency record")
    if not ranges:
        warnings.append("capture has no translated range records")
    if not user_samples:
        warnings.append("capture has no user PC samples")

    hot_host_pcs = [
        {"count": count, "epoch": epoch, "pc": f"0x{pc:x}", "pid": pid}
        for count, pid, epoch, pc in sorted(hot_host, reverse=True)[:30]
    ]
    hot_host_global_pcs = [
        {"count": count, "pc": f"0x{pc:x}"}
        for pc, count in sorted(
            host_by_pc.items(), key=lambda item: item[1], reverse=True
        )[:100]
    ]
    hot_translated_ranges = [
        {
            "count": count,
            "end": f"0x{translated.end:x}",
            "epoch": translated.epoch,
            "kind": translated.kind,
            "pid": translated.pid,
            "start": f"0x{translated.start:x}",
        }
        for translated, count in sorted(
            translated_samples.items(), key=lambda item: item[1], reverse=True
        )[:30]
    ]

    return {
        "completion": completion,
        "gating_eligible": False,
        "hot_host_global_pcs": hot_host_global_pcs,
        "hot_host_pcs": hot_host_pcs,
        "hot_translated_ranges": hot_translated_ranges,
        "ranges": {
            "private_reported": range_reported["private"],
            "private_unique": sum(item.kind == "private" for item in ranges),
            "catalogs": len(ranges_by_catalog),
            "processes": len({translated.pid for translated in ranges}),
            "resets": resets,
            "shared_reported": range_reported["shared"],
            "shared_unique": sum(item.kind == "shared" for item in ranges),
        },
        "sample_hz": sample_hz,
        "samples": samples,
        "schema": SCHEMA,
        "shares": shares,
        "warnings": warnings,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = analyze_raw(arguments.input)
    except (OSError, ProfileError) as error:
        print(f"native_pc_range_directional: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
