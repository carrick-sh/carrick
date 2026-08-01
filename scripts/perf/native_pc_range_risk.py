#!/usr/bin/env python3
"""Compare authenticated V2/V3 directional owner-risk capture pairs."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import pathlib
import plistlib
import re
import subprocess
import sys
import xml.parsers.expat
from collections import Counter
from collections.abc import Sequence
from fractions import Fraction


SCHEMA = "carrick.native-pc-range-risk.v2"
CAPTURE_SCHEMA = "carrick.native-go-dtrace-capture.v2"
REGRESSION_METHOD = (
    "one-sided exact sign-flip permutation test over paired V3-V2 owner-rate "
    "deltas; alpha=0.05; capture pair is the independent unit"
)
MINIMUM_PAIRS = 5
ALPHA = Fraction(1, 20)
PREDICATES = {
    "dyld": "module in {'dyld', 'libdyld.dylib'}",
    "kernel": "samples.kernel",
    "locks": r"(?i)(?:__psynch|pthread_mutex|rawmutex|rawrwlock|lock_shared|lock_exclusive|wait_for_readers)",
    "malloc": "module == 'libsystem_malloc.dylib'",
    "mmap_fault": r"(?i)(?:mmap|vm_fault|page_fault|mach_vm|map_with_linking)",
}
LOCK_PATTERN = re.compile(PREDICATES["locks"])
MMAP_FAULT_PATTERN = re.compile(PREDICATES["mmap_fault"])


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact(path: pathlib.Path) -> dict[str, object]:
    absolute = path.resolve()
    return {
        "bytes": absolute.stat().st_size,
        "path": str(absolute),
        "sha256": _sha256(absolute),
    }


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise ValueError(
            f"identity command failed ({completed.returncode}): {argv[0]}: "
            f"{completed.stderr.strip()}"
        )
    return completed


def inspect_binary_identity(path: pathlib.Path) -> dict[str, object]:
    """Bind the exact Mach-O image used for normalized-offset symbolization."""
    binary = path.resolve(strict=True)
    otool = _run(["/usr/bin/otool", "-l", str(binary)]).stdout
    text_matches = re.findall(
        r"cmd LC_SEGMENT_64\n\s+cmdsize \d+\n\s+segname __TEXT\n"
        r"\s+vmaddr (0x[0-9a-fA-F]+)\n\s+vmsize (0x[0-9a-fA-F]+)\n"
        r"\s+fileoff (\d+)\n\s+filesize (\d+)",
        otool,
    )
    uuid_matches = re.findall(r"cmd LC_UUID\n\s+cmdsize \d+\n\s+uuid ([0-9A-Fa-f-]+)", otool)
    dof_matches = re.findall(
        r"sectname __dof_carrick\n\s+segname ([^\s]+)\n"
        r"\s+addr (0x[0-9a-fA-F]+)\n\s+size (0x[0-9a-fA-F]+)\n"
        r"\s+offset (\d+)",
        otool,
    )
    if len(text_matches) != 1 or len(uuid_matches) != 1 or len(dof_matches) != 1:
        raise ValueError("binary has ambiguous or missing __TEXT, LC_UUID, or __dof_carrick identity")
    text_vmaddr, text_vmsize, text_fileoff, text_filesize = text_matches[0]
    dof_segment, dof_addr, dof_size, dof_offset = dof_matches[0]
    codesign = _run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)]
    )
    combined = codesign.stdout + "\n" + codesign.stderr
    xml_start = combined.find("<?xml")
    xml_end = combined.find("</plist>", xml_start)
    if xml_start < 0 or xml_end < 0:
        raise ValueError("codesign did not emit XML entitlements")
    try:
        entitlements = plistlib.loads(
            combined[xml_start : xml_end + len("</plist>")].encode()
        )
    except (plistlib.InvalidFileException, xml.parsers.expat.ExpatError) as error:
        raise ValueError("codesign emitted malformed entitlements") from error
    if not isinstance(entitlements, dict) or entitlements.get(
        "com.apple.security.hypervisor"
    ) is not True:
        raise ValueError("binary lacks com.apple.security.hypervisor entitlement")
    entitlement_json = json.dumps(entitlements, sort_keys=True, separators=(",", ":"))
    return {
        **_artifact(binary),
        "macho_uuid": uuid_matches[0].upper(),
        "text": {
            "fileoff": int(text_fileoff),
            "filesize": int(text_filesize),
            "vmaddr": int(text_vmaddr, 16),
            "vmsize": int(text_vmsize, 16),
        },
        "dof": {
            "address": int(dof_addr, 16),
            "offset": int(dof_offset),
            "segment": dof_segment,
            "size": int(dof_size, 16),
        },
        "entitlements": entitlements,
        "entitlements_sha256": hashlib.sha256(entitlement_json.encode()).hexdigest(),
    }


def symbolize_host_binary_offsets(
    binary: dict[str, object], offsets: Sequence[int]
) -> dict[int, dict[str, object]]:
    """Resolve every normalized offset with one deterministic atos invocation."""
    unique = sorted(set(offsets))
    if not unique:
        return {}
    text = binary.get("text")
    path = binary.get("path")
    if not isinstance(text, dict) or not isinstance(path, str):
        raise ValueError("binary identity lacks path or __TEXT identity")
    vmaddr = text.get("vmaddr")
    vmsize = text.get("vmsize")
    if not isinstance(vmaddr, int) or not isinstance(vmsize, int):
        raise ValueError("binary identity has malformed __TEXT identity")
    for offset in unique:
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset < vmsize:
            raise ValueError(f"host binary offset is outside __TEXT: {offset!r}")
    addresses = [vmaddr + offset for offset in unique]
    argv = [
        "/usr/bin/atos",
        "-o",
        path,
        "-l",
        f"0x{vmaddr:x}",
        *(f"0x{address:x}" for address in addresses),
    ]
    completed = _run(argv)
    if completed.stderr.strip():
        raise ValueError(f"atos emitted diagnostics: {completed.stderr.strip()}")
    lines = completed.stdout.splitlines()
    if len(lines) != len(unique):
        raise ValueError("atos result cardinality does not match normalized offsets")
    resolved: dict[int, dict[str, object]] = {}
    for offset, address, line in zip(unique, addresses, lines, strict=True):
        match = re.fullmatch(r"(.+?) \(in ([^)]+)\)(?: .*)?", line.strip())
        if match is None:
            raise ValueError(f"atos left offset 0x{offset:x} unresolved or ambiguous: {line!r}")
        symbol, module = match.groups()
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", symbol) or symbol in {"???", "<unknown>"}:
            raise ValueError(f"atos left offset 0x{offset:x} unresolved: {line!r}")
        resolved[offset] = {
            "absolute_address": f"0x{address:x}",
            "atos": line.strip(),
            "module": module,
            "offset": f"0x{offset:x}",
            "symbol": symbol,
        }
    return resolved


def _parse_offsets(analysis: dict[str, object]) -> list[tuple[int, int]]:
    rows = analysis.get("host_binary_offsets", [])
    if not isinstance(rows, list):
        raise ValueError("analysis has malformed host_binary_offsets")
    parsed: list[tuple[int, int]] = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("analysis has malformed host binary offset")
        count = row.get("count")
        offset_text = row.get("offset")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            or not isinstance(offset_text, str)
        ):
            raise ValueError("analysis has malformed host binary offset")
        try:
            offset = int(offset_text, 0)
        except ValueError as error:
            raise ValueError("analysis has malformed host binary offset") from error
        if offset < 0 or offset in seen:
            raise ValueError("analysis has duplicate or negative host binary offset")
        seen.add(offset)
        parsed.append((offset, count))
    return parsed


def classify(
    analysis: dict[str, object],
    symbolizations: dict[int, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Classify named leaves plus every exact-binary raw-offset population."""
    samples = analysis.get("samples")
    leaves = analysis.get("host_leaves")
    if not isinstance(samples, dict) or not isinstance(leaves, list):
        raise ValueError("analysis is missing samples or host_leaves")
    all_samples = samples.get("all")
    kernel = samples.get("kernel")
    if (
        not isinstance(all_samples, int)
        or isinstance(all_samples, bool)
        or all_samples <= 0
        or not isinstance(kernel, int)
        or isinstance(kernel, bool)
        or kernel < 0
    ):
        raise ValueError("analysis has invalid all/kernel sample counts")
    offsets = _parse_offsets(analysis)
    mappings = symbolizations or {}
    if set(mappings) != {offset for offset, _count in offsets}:
        raise ValueError("every host_binary_offsets row must have one exact symbolization")

    counts = {name: 0 for name in PREDICATES}
    counts["kernel"] = kernel
    matching: dict[str, list[dict[str, object]]] = {
        name: [] for name in ("dyld", "locks", "malloc", "mmap_fault")
    }

    def consume(module: str, symbol: str, count: int, source: str, offset: str | None) -> None:
        searchable = f"{module}`{symbol}"
        categories: list[str] = []
        if module in {"dyld", "libdyld.dylib"}:
            categories.append("dyld")
        if module == "libsystem_malloc.dylib":
            categories.append("malloc")
        if LOCK_PATTERN.search(searchable) is not None:
            categories.append("locks")
        if MMAP_FAULT_PATTERN.search(searchable) is not None:
            categories.append("mmap_fault")
        for category in categories:
            counts[category] += count
            row: dict[str, object] = {
                "count": count,
                "module": module,
                "source": source,
                "symbol": symbol,
            }
            if offset is not None:
                row["offset"] = offset
            matching[category].append(row)

    for leaf in leaves:
        if not isinstance(leaf, dict):
            raise ValueError("analysis has a malformed host leaf")
        module, symbol, count = leaf.get("module"), leaf.get("symbol"), leaf.get("count")
        if (
            not isinstance(module, str)
            or not isinstance(symbol, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise ValueError("analysis has a malformed host leaf")
        consume(module, symbol, count, "named_leaf", None)
    persisted_symbolizations: list[dict[str, object]] = []
    for offset, count in offsets:
        mapping = mappings[offset]
        module, symbol = mapping.get("module"), mapping.get("symbol")
        if not isinstance(module, str) or not isinstance(symbol, str):
            raise ValueError("host binary offset has malformed exact symbolization")
        offset_text = f"0x{offset:x}"
        consume(module, symbol, count, "host_binary_offset", offset_text)
        persisted_symbolizations.append({**mapping, "count": count})

    kernel_stacks = analysis.get("kernel_stacks", [])
    if not isinstance(kernel_stacks, list):
        raise ValueError("analysis has malformed kernel stacks")
    normalized_stacks: list[dict[str, object]] = []
    stack_total = 0
    for stack in kernel_stacks:
        if not isinstance(stack, dict):
            raise ValueError("analysis has a malformed kernel stack")
        count, frames = stack.get("count"), stack.get("frames")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            or not isinstance(frames, list)
            or not frames
            or any(not isinstance(frame, str) or not frame for frame in frames)
        ):
            raise ValueError("analysis has a malformed kernel stack")
        stack_total += count
        normalized_stacks.append({"count": count, "frames": list(frames)})
    if stack_total != kernel:
        raise ValueError("analysis kernel PC/stack counts do not reconcile")

    categories: dict[str, dict[str, object]] = {
        name: {
            "count": count,
            "per_1000_all_samples": round(count * 1000 / all_samples, 9),
        }
        for name, count in counts.items()
    }
    categories["kernel"]["stacks"] = sorted(
        normalized_stacks, key=lambda row: (-int(row["count"]), tuple(row["frames"]))
    )
    categories["kernel"]["stack_samples"] = stack_total
    for name, rows in matching.items():
        categories[name]["leaves"] = sorted(
            rows,
            key=lambda row: (
                -int(row["count"]),
                str(row["source"]),
                str(row["module"]),
                str(row["symbol"]),
                str(row.get("offset", "")),
            ),
        )
    return {
        "all_samples": all_samples,
        "categories": categories,
        "host_binary_offset_symbolizations": persisted_symbolizations,
    }


def _aggregate(classifications: list[dict[str, object]]) -> dict[str, object]:
    if not classifications:
        raise ValueError("at least one capture classification is required")
    all_samples = sum(int(row["all_samples"]) for row in classifications)
    categories: dict[str, dict[str, object]] = {}
    for name in PREDICATES:
        count = sum(int(row["categories"][name]["count"]) for row in classifications)  # type: ignore[index]
        categories[name] = {
            "count": count,
            "per_1000_all_samples": round(count * 1000 / all_samples, 9),
        }
    return {"all_samples": all_samples, "captures": len(classifications), "categories": categories}


def _validate_analysis(analysis: dict[str, object]) -> None:
    if analysis.get("schema") != "carrick.native-pc-range-directional.v2":
        raise ValueError("capture analysis schema is not directional v2")
    if analysis.get("warnings") != []:
        raise ValueError("capture analysis has warnings")
    if analysis.get("completion") != {"target_exit": 1, "timed_out": 0}:
        raise ValueError("capture did not complete naturally")
    required = ("ranges", "host_text_ranges", "samples", "leaf_capture", "kernel_stack_capture")
    if any(not isinstance(analysis.get(key), dict) for key in required):
        raise ValueError("capture analysis is missing required stream receipts")
    ranges = analysis["ranges"]
    host_ranges = analysis["host_text_ranges"]
    samples = analysis["samples"]
    leaf = analysis["leaf_capture"]
    stacks = analysis["kernel_stack_capture"]
    assert all(isinstance(value, dict) for value in (ranges, host_ranges, samples, leaf, stacks))
    if (
        ranges.get("resets", 0) <= 0
        or ranges.get("private_reported", 0) <= 0
        or ranges.get("shared_reported", 0) <= 0
        or host_ranges.get("reported", 0) <= 0
        or samples.get("user", 0) <= 0
        or samples.get("kernel", 0) <= 0
        or leaf.get("expected_outside_private_samples", 0) <= 0
        or leaf.get("expected_outside_private_samples") != leaf.get("observed_outside_private_samples")
        or stacks.get("per_catalog_exact") is not True
        or stacks.get("kernel_samples") != stacks.get("stack_samples")
    ):
        raise ValueError("capture analysis lacks exact required streams")


def _load_capture(
    raw_path: pathlib.Path,
    analysis_path: pathlib.Path,
    capture_path: pathlib.Path,
    *,
    expected_mode: str,
    expected_arm: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    if not isinstance(analysis, dict) or not isinstance(capture, dict):
        raise ValueError("analysis and capture roots must be JSON objects")
    if capture.get("schema") != CAPTURE_SCHEMA or capture.get("status") != "passed":
        raise ValueError("capture receipt is not an authenticated passed v2 receipt")
    if capture.get("metadata_mode") != expected_mode:
        raise ValueError(f"capture metadata mode must be {expected_mode}")
    pair = capture.get("pair")
    if not isinstance(pair, dict) or pair.get("arm") != expected_arm:
        raise ValueError("capture pair arm is missing or swapped")
    expected_order = 0 if expected_arm == "control" else 1
    if pair.get("order") != expected_order:
        raise ValueError("capture pair order is not exact V2 then V3")
    artifacts = capture.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("capture receipt has no artifact bindings")
    expected_roles = {"analysis", "driver_stderr", "driver_stdout", "raw"}
    if set(artifacts) != expected_roles:
        raise ValueError("capture receipt does not bind every exact evidence stream")
    verified_artifacts: dict[str, dict[str, object]] = {}
    for role, recorded in artifacts.items():
        if not isinstance(recorded, dict) or not isinstance(recorded.get("path"), str):
            raise ValueError(f"capture receipt has malformed {role} artifact")
        current = _artifact(pathlib.Path(str(recorded["path"])))
        if current != recorded:
            raise ValueError(f"capture receipt {role} artifact drifted")
        verified_artifacts[role] = current
    for role, supplied in (("raw", raw_path), ("analysis", analysis_path)):
        if verified_artifacts.get(role) != _artifact(supplied):
            raise ValueError(f"capture receipt does not bind supplied {role} artifact")
    for determinant in ("trace_script", "analyzer"):
        recorded = capture.get(determinant)
        if not isinstance(recorded, dict) or not isinstance(recorded.get("path"), str):
            raise ValueError(f"capture receipt has malformed {determinant} identity")
        expected = _artifact(pathlib.Path(str(recorded["path"])))
        recorded_artifact = {key: recorded.get(key) for key in ("bytes", "path", "sha256")}
        if expected != recorded_artifact:
            raise ValueError(f"capture {determinant} identity drifted from disk")
    expected = capture.get("expected_effective_identity")
    observed = capture.get("observed_effective_identity")
    if (
        not isinstance(expected, dict)
        or expected.get("euid") in (None, 0)
        or observed != expected
    ):
        raise ValueError("capture receipt has an unverified or root full identity")
    _validate_analysis(analysis)
    if capture.get("natural_completion") is not True or capture.get("required_streams") != {
        "host_range": True,
        "identity": True,
        "kernel_pc_stack_per_catalog_exact": True,
        "leaf_pc_exact": True,
        "private_range": True,
        "reset": True,
        "shared_range": True,
        "user_and_kernel_samples": True,
    }:
        raise ValueError("capture receipt does not authenticate natural completion and required streams")
    return analysis, capture, verified_artifacts


def _fraction(value: Fraction) -> dict[str, object]:
    return {"decimal": float(value), "fraction": f"{value.numerator}/{value.denominator}"}


def _paired_test(
    pairs: list[tuple[str, int, dict[str, object], dict[str, object]]], name: str
) -> dict[str, object]:
    deltas: list[Fraction] = []
    rows: list[dict[str, object]] = []
    for pair_id, ordinal, v2, v3 in pairs:
        v2_count = int(v2["categories"][name]["count"])  # type: ignore[index]
        v3_count = int(v3["categories"][name]["count"])  # type: ignore[index]
        v2_all, v3_all = int(v2["all_samples"]), int(v3["all_samples"])
        delta = Fraction(v3_count, v3_all) - Fraction(v2_count, v2_all)
        deltas.append(delta)
        rows.append(
            {
                "delta": _fraction(delta),
                "delta_per_1000": float(delta * 1000),
                "ordinal": ordinal,
                "pair_id": pair_id,
                "v2": {"all": v2_all, "count": v2_count},
                "v3": {"all": v3_all, "count": v3_count},
            }
        )
    observed = sum(deltas, Fraction()) / len(deltas)
    distribution: Counter[Fraction] = Counter()
    for signs in itertools.product((-1, 1), repeat=len(deltas)):
        distribution[sum((sign * delta for sign, delta in zip(signs, deltas, strict=True)), Fraction()) / len(deltas)] += 1
    permutations = 2 ** len(deltas)
    extreme = sum(count for value, count in distribution.items() if value >= observed)
    p_value = Fraction(extreme, permutations)
    return {
        "independent_unit": "capture_pair",
        "mean_delta": _fraction(observed),
        "mean_delta_per_1000": float(observed * 1000),
        "pair_deltas": rows,
        "permutation_distribution": [
            {"count": count, "mean_delta": _fraction(value), "mean_delta_per_1000": float(value * 1000)}
            for value, count in sorted(distribution.items())
        ],
        "permutations": permutations,
        "one_sided_extreme_permutations": extreme,
        "one_sided_p_value": _fraction(p_value),
        "rule": "supported iff mean V3-V2 delta > 0 and exact one-sided p <= 0.05",
        "supported_v3_increase": observed > 0 and p_value <= ALPHA,
        "v3_larger": observed > 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ("v2", "v3"):
        parser.add_argument(f"--{arm}-raw", type=pathlib.Path, action="append", required=True)
        parser.add_argument(f"--{arm}-analysis", type=pathlib.Path, action="append", required=True)
        parser.add_argument(f"--{arm}-capture", type=pathlib.Path, action="append", required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        count = len(arguments.v2_raw)
        lengths = {
            count,
            len(arguments.v2_analysis),
            len(arguments.v2_capture),
            len(arguments.v3_raw),
            len(arguments.v3_analysis),
            len(arguments.v3_capture),
        }
        if len(lengths) != 1:
            raise ValueError("V2 and V3 raw, analysis, and capture counts must match")
        if count < MINIMUM_PAIRS:
            raise ValueError(f"at least {MINIMUM_PAIRS} independent capture pairs are required")
        binary = inspect_binary_identity(arguments.binary)
        pairs: list[tuple[str, int, dict[str, object], dict[str, object]]] = []
        v2_classifications: list[dict[str, object]] = []
        v3_classifications: list[dict[str, object]] = []
        capture_evidence: list[dict[str, object]] = []
        run_ids: set[str] = set()
        raw_hashes: set[str] = set()
        capture_hashes: set[str] = set()
        artifact_paths: set[str] = set()
        stable_determinants: dict[str, str] = {}
        ordinals: list[int] = []
        for index in range(count):
            loaded: list[tuple[dict[str, object], dict[str, object], dict[str, object]]] = []
            for mode, arm, raws, analyses, captures in (
                ("v2", "control", arguments.v2_raw, arguments.v2_analysis, arguments.v2_capture),
                ("mapped", "candidate", arguments.v3_raw, arguments.v3_analysis, arguments.v3_capture),
            ):
                loaded.append(_load_capture(raws[index], analyses[index], captures[index], expected_mode=mode, expected_arm=arm))
                capture_artifact = _artifact(captures[index])
                capture_path = str(capture_artifact["path"])
                capture_hash = str(capture_artifact["sha256"])
                if capture_path in artifact_paths or capture_hash in capture_hashes:
                    raise ValueError("capture receipts must have unique paths and hashes")
                artifact_paths.add(capture_path)
                capture_hashes.add(capture_hash)
            (v2_analysis, v2_capture, v2_artifacts), (v3_analysis, v3_capture, v3_artifacts) = loaded
            v2_pair, v3_pair = v2_capture["pair"], v3_capture["pair"]
            assert isinstance(v2_pair, dict) and isinstance(v3_pair, dict)
            if v2_pair.get("id") != v3_pair.get("id") or v2_pair.get("ordinal") != v3_pair.get("ordinal"):
                raise ValueError("V2 and V3 captures do not have exact pair identity")
            pair_id, ordinal = v2_pair.get("id"), v2_pair.get("ordinal")
            if not isinstance(pair_id, str) or not pair_id or not isinstance(ordinal, int) or isinstance(ordinal, bool):
                raise ValueError("capture pair identity is malformed")
            ordinals.append(ordinal)
            for capture, artifacts in ((v2_capture, v2_artifacts), (v3_capture, v3_artifacts)):
                if capture.get("binary") != binary:
                    raise ValueError("capture producing binary identity drifted from --binary")
                run_id = capture.get("run_id")
                if not isinstance(run_id, str) or not run_id or run_id in run_ids:
                    raise ValueError("capture run IDs must be distinct")
                run_ids.add(run_id)
                raw_hash = str(artifacts["raw"]["sha256"])
                if raw_hash in raw_hashes:
                    raise ValueError("capture raw hashes must be distinct")
                raw_hashes.add(raw_hash)
                for artifact in artifacts.values():
                    path = str(artifact["path"])
                    if path in artifact_paths:
                        raise ValueError("capture artifacts must have unique paths")
                    artifact_paths.add(path)
                for determinant in ("trace_script", "workload", "analyzer"):
                    encoded = json.dumps(capture.get(determinant), sort_keys=True)
                    existing = stable_determinants.setdefault(determinant, encoded)
                    if existing != encoded:
                        raise ValueError(f"capture {determinant} identity drifted")
            v2_overlay = dict(v2_capture.get("normalized_overlay", {}))
            v3_overlay = dict(v3_capture.get("normalized_overlay", {}))
            metadata_key = "CARRICK_DSR_SHARED_MAPPED_METADATA"
            if v2_overlay.pop(metadata_key, None) != "0" or v3_overlay.pop(metadata_key, None) is not None or v2_overlay != v3_overlay:
                raise ValueError("capture normalized overlays are not the exact V2/mapped contrast")
            v2_offsets = _parse_offsets(v2_analysis)
            v3_offsets = _parse_offsets(v3_analysis)
            v2_symbols = symbolize_host_binary_offsets(binary, [offset for offset, _ in v2_offsets])
            v3_symbols = symbolize_host_binary_offsets(binary, [offset for offset, _ in v3_offsets])
            v2_classification = classify(v2_analysis, v2_symbols)
            v3_classification = classify(v3_analysis, v3_symbols)
            v2_classifications.append(v2_classification)
            v3_classifications.append(v3_classification)
            pairs.append((pair_id, ordinal, v2_classification, v3_classification))
            capture_evidence.append({
                "candidate": {"artifacts": v3_artifacts, "receipt": _artifact(arguments.v3_capture[index])},
                "control": {"artifacts": v2_artifacts, "receipt": _artifact(arguments.v2_capture[index])},
                "ordinal": ordinal,
                "pair_id": pair_id,
            })
        if ordinals != list(range(1, count + 1)) or len(set(ordinals)) != count:
            raise ValueError("capture pair ordinals must be unique and supplied in canonical order")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"native_pc_range_risk: {error}", file=sys.stderr)
        return 2

    v2, v3 = _aggregate(v2_classifications), _aggregate(v3_classifications)
    comparisons = {name: _paired_test(pairs, name) for name in PREDICATES}
    larger = [name for name in PREDICATES if comparisons[name]["v3_larger"]]
    supported = [name for name in PREDICATES if comparisons[name]["supported_v3_increase"]]
    receipt = {
        "artifacts": {"binary": binary, "capture_pairs": capture_evidence},
        "capture_pairs": count,
        "comparisons": comparisons,
        "larger_v3_owners": larger,
        "predicates": PREDICATES,
        "regression_method": REGRESSION_METHOD,
        "schema": SCHEMA,
        "status": "failed" if supported else "passed",
        "supported_v3_owner_increases": supported,
        "v2": {**v2, "captures_detail": v2_classifications},
        "v3": {**v3, "captures_detail": v3_classifications},
    }
    arguments.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 2 if supported else 0


if __name__ == "__main__":
    raise SystemExit(main())
