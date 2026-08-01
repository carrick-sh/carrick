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
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Sequence


SCHEMA = "carrick.native-pc-range-directional.v2"
PROTOCOL = "PCPROFILE1"
LEAF_PROTOCOL = "PCLEAF2"
KERNEL_STACK_PROTOCOL = "PCKSTACK1"
KERNEL_STACK_BEGIN = re.compile(
    rf"^{KERNEL_STACK_PROTOCOL}\|begin\|pid=(\d+)\|epoch=(\d+)\|count=(\d+)$"
)


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


def _parse_leaf_fields(line: str, line_number: int) -> dict[str, str]:
    parts = line.split("|")
    if len(parts) < 2 or parts[0] != LEAF_PROTOCOL:
        raise ProfileError(f"line {line_number}: malformed {LEAF_PROTOCOL} record")
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            raise ProfileError(f"line {line_number}: malformed leaf field {part!r}")
        key, value = part.split("=", 1)
        if not key or key in fields:
            raise ProfileError(
                f"line {line_number}: duplicate or empty leaf field {key!r}"
            )
        fields[key] = value
    expected = {"pid", "epoch", "pc", "module", "symbol", "count"}
    if set(fields) != expected:
        missing = sorted(expected - set(fields))
        extra = sorted(set(fields) - expected)
        raise ProfileError(
            f"line {line_number}: malformed {LEAF_PROTOCOL} fields "
            f"missing={missing} extra={extra}"
        )
    if not fields["module"] or not fields["symbol"]:
        raise ProfileError(f"line {line_number}: empty leaf module or symbol")
    return fields


def _is_raw_address(value: str) -> bool:
    return re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None


def _is_raw_leaf(module: str, symbol: str) -> bool:
    module_is_raw = _is_raw_address(module)
    symbol_is_raw = _is_raw_address(symbol)
    if module_is_raw or symbol_is_raw:
        if module_is_raw and symbol_is_raw:
            return True
        raise ProfileError("host leaf has inconsistent raw module/symbol identity")
    return re.fullmatch(rf"{re.escape(module)}`0x[0-9a-fA-F]+", symbol) is not None


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
    host_range_reported = 0
    host_ranges: dict[tuple[int, int], tuple[int, int]] = {}
    resets = 0
    user_samples: dict[tuple[int, int, int], int] = defaultdict(int)
    kernel_samples: dict[tuple[int, int], int] = defaultdict(int)
    kernel_stack_samples: dict[tuple[int, int, tuple[str, ...]], int] = {}
    leaf_samples: dict[tuple[int, int, int, str, str], int] = {}
    effective_identities: list[tuple[int, int, int, int]] = []
    completion: dict[str, int] | None = None

    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    profile_lines: list[tuple[int, str]] = []
    index = 0
    while index < len(raw_lines):
        line = raw_lines[index]
        line_number = index + 1
        if line.startswith(f"{KERNEL_STACK_PROTOCOL}|begin|"):
            matched = KERNEL_STACK_BEGIN.fullmatch(line)
            if matched is None:
                raise ProfileError(
                    f"line {line_number}: malformed {KERNEL_STACK_PROTOCOL} header"
                )
            pid, epoch, count = (int(value) for value in matched.groups())
            if pid <= 0 or epoch <= 0 or count <= 0:
                raise ProfileError(
                    f"line {line_number}: kernel stack pid/epoch/count must be positive"
                )
            frames: list[str] = []
            index += 1
            while index < len(raw_lines) and raw_lines[index] != (
                f"{KERNEL_STACK_PROTOCOL}|end"
            ):
                frame = raw_lines[index].strip()
                if frame:
                    frames.append(frame)
                index += 1
            if index >= len(raw_lines):
                raise ProfileError(
                    f"line {line_number}: unterminated {KERNEL_STACK_PROTOCOL} record"
                )
            if not frames:
                raise ProfileError(
                    f"line {line_number}: kernel stack has no frames"
                )
            key = (pid, epoch, tuple(frames))
            if key in kernel_stack_samples:
                raise ProfileError(
                    f"line {line_number}: duplicate {KERNEL_STACK_PROTOCOL} record"
                )
            kernel_stack_samples[key] = count
            index += 1
            continue
        if line == f"{KERNEL_STACK_PROTOCOL}|end":
            raise ProfileError(
                f"line {line_number}: unexpected {KERNEL_STACK_PROTOCOL} terminator"
            )
        profile_lines.append((line_number, line))
        index += 1

    for line_number, line in profile_lines:
        if line.startswith(f"{LEAF_PROTOCOL}|"):
            fields = _parse_leaf_fields(line, line_number)
            pid = _integer(fields, "pid", line_number)
            epoch = _integer(fields, "epoch", line_number)
            pc = _integer(fields, "pc", line_number)
            count = _integer(fields, "count", line_number)
            if pid <= 0 or epoch <= 0 or pc <= 0 or count <= 0:
                raise ProfileError(
                    f"line {line_number}: leaf pid/epoch/pc/count must be positive"
                )
            key = (pid, epoch, pc, fields["module"], fields["symbol"])
            if key in leaf_samples:
                raise ProfileError(
                    f"line {line_number}: duplicate {LEAF_PROTOCOL} record"
                )
            leaf_samples[key] = count
            continue
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
        elif record == "identity":
            pid = _integer(fields, "pid", line_number)
            epoch = _integer(fields, "epoch", line_number)
            euid = _integer(fields, "euid", line_number)
            egid = _integer(fields, "egid", line_number)
            if pid <= 0 or epoch <= 0 or euid < 0 or egid < 0:
                raise ProfileError(
                    f"line {line_number}: invalid effective identity"
                )
            effective_identities.append((pid, epoch, euid, egid))
        elif record == "host-range":
            pid = _integer(fields, "pid", line_number)
            epoch = _integer(fields, "epoch", line_number)
            start = _integer(fields, "start", line_number)
            end = _integer(fields, "end", line_number)
            if pid <= 0 or epoch <= 0 or start <= 0 or start >= end:
                raise ProfileError(
                    f"line {line_number}: invalid host text range pid={pid} "
                    f"epoch={epoch} 0x{start:x}..0x{end:x}"
                )
            key = (pid, epoch)
            existing = host_ranges.get(key)
            if existing is not None and existing != (start, end):
                raise ProfileError(
                    "conflicting host text ranges for "
                    f"pid={pid} epoch={epoch}: "
                    f"0x{existing[0]:x}..0x{existing[1]:x} and "
                    f"0x{start:x}..0x{end:x}"
                )
            host_range_reported += 1
            host_ranges[key] = (start, end)
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
    owners: dict[tuple[int, int, int], TranslatedRange | None] = {}
    for (pid, epoch, pc), count in user_samples.items():
        owner = _range_owner(ranges_by_catalog, pid, epoch, pc)
        owners[(pid, epoch, pc)] = owner
        if owner is None:
            bucket_counts["host"] += count
            hot_host.append((count, pid, epoch, pc))
            host_by_pc[pc] += count
        else:
            bucket_counts[f"{owner.kind}_jit"] += count
            translated_samples[owner] += count

    expected_outside_keys = {
        key for key, owner in owners.items() if owner is None or owner.kind == "shared"
    }
    leaf_by_pc: dict[tuple[int, int, int], tuple[str, str, int]] = {}
    for (pid, epoch, pc, module, symbol), count in leaf_samples.items():
        key = (pid, epoch, pc)
        if key in leaf_by_pc:
            raise ProfileError(
                "multiple leaf identities for "
                f"pid={pid} epoch={epoch} pc=0x{pc:x}"
            )
        if key not in user_samples:
            raise ProfileError(
                "leaf sample has no matching user PC histogram entry for "
                f"pid={pid} epoch={epoch} pc=0x{pc:x}"
            )
        owner = owners[key]
        if owner is not None and owner.kind == "private":
            raise ProfileError(
                "leaf record unexpectedly names a private translated PC for "
                f"pid={pid} epoch={epoch} pc=0x{pc:x}"
            )
        if count != user_samples[key]:
            raise ProfileError(
                "leaf sample count does not match user PC histogram for "
                f"pid={pid} epoch={epoch} pc=0x{pc:x}: "
                f"leaf={count} user={user_samples[key]}"
            )
        leaf_by_pc[key] = (module, symbol, count)

    host_leaf_counts: Counter[tuple[str, str]] = Counter()
    host_named_samples = 0
    host_raw_samples = 0
    host_binary_raw_samples = 0
    host_binary_offsets: Counter[int] = Counter()
    shared_leaf_samples = 0
    if leaf_by_pc:
        if set(leaf_by_pc) != expected_outside_keys:
            missing = len(expected_outside_keys - set(leaf_by_pc))
            extra = len(set(leaf_by_pc) - expected_outside_keys)
            raise ProfileError(
                "leaf sample count coverage does not match outside-private PC "
                f"histogram: missing={missing} extra={extra}"
            )
        for key, (module, symbol, count) in leaf_by_pc.items():
            owner = owners[key]
            if owner is not None:
                shared_leaf_samples += count
                continue
            if _is_raw_leaf(module, symbol):
                host_raw_samples += count
                host_range = host_ranges.get((key[0], key[1]))
                if host_range is not None and host_range[0] <= key[2] < host_range[1]:
                    host_binary_raw_samples += count
                    host_binary_offsets[key[2] - host_range[0]] += count
            else:
                host_named_samples += count
                host_leaf_counts[(module, symbol)] += count

    expected_outside_samples = (
        bucket_counts["host"] + bucket_counts["shared_jit"]
    )
    observed_outside_samples = sum(
        count for _module, _symbol, count in leaf_by_pc.values()
    )
    if leaf_by_pc and observed_outside_samples != expected_outside_samples:
        raise ProfileError(
            "leaf sample count does not match outside-private population: "
            f"leaf={observed_outside_samples} expected={expected_outside_samples}"
        )

    user_total = sum(user_samples.values())
    kernel_total = sum(kernel_samples.values())
    kernel_stack_total = sum(kernel_stack_samples.values())
    kernel_stack_by_catalog: Counter[tuple[int, int]] = Counter()
    kernel_stacks_by_frames: Counter[tuple[str, ...]] = Counter()
    for (pid, epoch, frames), count in kernel_stack_samples.items():
        kernel_stack_by_catalog[(pid, epoch)] += count
        kernel_stacks_by_frames[frames] += count
    kernel_catalogs = [
        {
            "epoch": epoch,
            "kernel_samples": kernel_samples.get((pid, epoch), 0),
            "pid": pid,
            "stack_samples": kernel_stack_by_catalog.get((pid, epoch), 0),
        }
        for pid, epoch in sorted(set(kernel_samples) | set(kernel_stack_by_catalog))
    ]
    kernel_per_catalog_exact = all(
        catalog["kernel_samples"] == catalog["stack_samples"]
        for catalog in kernel_catalogs
    )
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
    if expected_outside_samples and not leaf_by_pc:
        warnings.append("capture has no PC-bound leaf records")

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
    host_leaves = [
        {
            "all_cpu_share": count / all_total if all_total else 0.0,
            "count": count,
            "host_user_share": (
                count / bucket_counts["host"] if bucket_counts["host"] else 0.0
            ),
            "module": module,
            "symbol": symbol,
        }
        for (module, symbol), count in sorted(
            host_leaf_counts.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1]),
        )
    ]
    hot_host_binary_offsets = [
        {"count": count, "offset": f"0x{offset:x}"}
        for offset, count in sorted(
            host_binary_offsets.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    kernel_stacks = [
        {"count": count, "frames": list(frames)}
        for frames, count in sorted(
            kernel_stacks_by_frames.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]

    return {
        "completion": completion,
        "gating_eligible": False,
        "effective_identity": {
            "egids": sorted({identity[3] for identity in effective_identities}),
            "euids": sorted({identity[2] for identity in effective_identities}),
            "reported": len(effective_identities),
        },
        "hot_host_global_pcs": hot_host_global_pcs,
        "hot_host_pcs": hot_host_pcs,
        "hot_translated_ranges": hot_translated_ranges,
        "host_binary_offsets": hot_host_binary_offsets,
        "host_leaves": host_leaves,
        "kernel_stack_capture": {
            "catalogs": kernel_catalogs,
            "kernel_samples": kernel_total,
            "per_catalog_exact": kernel_per_catalog_exact,
            "stack_samples": kernel_stack_total,
            "stacks": len(kernel_stacks_by_frames),
        },
        "kernel_stacks": kernel_stacks,
        "leaf_capture": {
            "expected_outside_private_samples": expected_outside_samples,
            "host_binary_raw_samples": host_binary_raw_samples,
            "host_named_samples": host_named_samples,
            "host_raw_samples": host_raw_samples,
            "observed_outside_private_samples": observed_outside_samples,
            "shared_translated_samples": shared_leaf_samples,
        },
        "host_text_ranges": {
            "process_epochs": len(host_ranges),
            "reported": host_range_reported,
            "unique": len(set(host_ranges.values())),
        },
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


def validate_strict_capture(
    result: dict[str, object], *, expected_euid: int, expected_egid: int
) -> None:
    """Reject any directional receipt that cannot prove a complete capture."""
    ranges = result["ranges"]
    host_ranges = result["host_text_ranges"]
    samples = result["samples"]
    leaf = result["leaf_capture"]
    completion = result["completion"]
    identity = result["effective_identity"]
    kernel_stack_capture = result["kernel_stack_capture"]
    assert isinstance(ranges, dict)
    assert isinstance(host_ranges, dict)
    assert isinstance(samples, dict)
    assert isinstance(leaf, dict)
    assert isinstance(completion, dict)
    assert isinstance(identity, dict)
    assert isinstance(kernel_stack_capture, dict)

    failures: list[str] = []
    if ranges["resets"] <= 0:
        failures.append("missing reset stream")
    if ranges["private_reported"] <= 0:
        failures.append("missing private-range stream")
    if ranges["shared_reported"] <= 0:
        failures.append("missing shared-range stream")
    if host_ranges["reported"] <= 0:
        failures.append("missing host-range stream")
    if samples["user"] <= 0 or samples["kernel"] <= 0:
        failures.append("missing user or kernel sample stream")
    if (
        kernel_stack_capture["stack_samples"] <= 0
        or kernel_stack_capture["stack_samples"]
        != kernel_stack_capture["kernel_samples"]
    ):
        failures.append("kernel PC/stack samples do not reconcile exactly")
    if not kernel_stack_capture["per_catalog_exact"]:
        failures.append("kernel PC/stack samples do not reconcile per-catalog")
    if (
        leaf["expected_outside_private_samples"] <= 0
        or leaf["observed_outside_private_samples"]
        != leaf["expected_outside_private_samples"]
    ):
        failures.append("PC/leaf reconciliation is not exact")
    if completion != {"target_exit": 1, "timed_out": 0}:
        failures.append("target did not exit naturally exactly once")
    warnings = result["warnings"]
    if warnings != []:
        failures.append(f"analyzer warnings are not empty: {warnings}")
    if (
        identity["reported"] <= 0
        or identity["euids"] != [expected_euid]
        or identity["egids"] != [expected_egid]
    ):
        failures.append(
            "effective identity mismatch: "
            f"expected euid={expected_euid} egid={expected_egid}, "
            f"observed euids={identity['euids']} egids={identity['egids']}"
        )
    if failures:
        raise ProfileError("strict capture failed: " + "; ".join(failures))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--expected-euid", type=int)
    parser.add_argument("--expected-egid", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = analyze_raw(arguments.input)
        if arguments.strict:
            if arguments.expected_euid is None or arguments.expected_egid is None:
                raise ProfileError(
                    "strict capture requires expected effective uid and gid"
                )
            validate_strict_capture(
                result,
                expected_euid=arguments.expected_euid,
                expected_egid=arguments.expected_egid,
            )
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
