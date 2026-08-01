#!/usr/bin/env python3
"""Compare hash-bound V2/V3 directional owner-risk evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
from collections.abc import Sequence


SCHEMA = "carrick.native-pc-range-risk.v1"
REGRESSION_METHOD = (
    "one-sided pooled two-proportion z test; H0 p_v3 <= p_v2; alpha=0.05"
)
ONE_SIDED_ALPHA = 0.05
ONE_SIDED_95_Z = 1.6448536269514722
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
    return {
        "bytes": path.stat().st_size,
        "path": str(path),
        "sha256": _sha256(path),
    }


def classify(analysis: dict[str, object]) -> dict[str, object]:
    """Classify the exact owner populations named by the V3 task gate."""
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

    counts = {name: 0 for name in PREDICATES}
    counts["kernel"] = kernel
    matching_leaves: dict[str, dict[tuple[str, str], int]] = {
        name: {} for name in ("dyld", "locks", "malloc", "mmap_fault")
    }

    def add_leaf(category: str, module: str, symbol: str, count: int) -> None:
        key = (module, symbol)
        matching_leaves[category][key] = (
            matching_leaves[category].get(key, 0) + count
        )

    for leaf in leaves:
        if not isinstance(leaf, dict):
            raise ValueError("analysis has a malformed host leaf")
        module = leaf.get("module")
        symbol = leaf.get("symbol")
        count = leaf.get("count")
        if (
            not isinstance(module, str)
            or not isinstance(symbol, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise ValueError("analysis has a malformed host leaf")
        searchable = f"{module}`{symbol}"
        if module in {"dyld", "libdyld.dylib"}:
            counts["dyld"] += count
            add_leaf("dyld", module, symbol, count)
        if module == "libsystem_malloc.dylib":
            counts["malloc"] += count
            add_leaf("malloc", module, symbol, count)
        if LOCK_PATTERN.search(searchable) is not None:
            counts["locks"] += count
            add_leaf("locks", module, symbol, count)
        if MMAP_FAULT_PATTERN.search(searchable) is not None:
            counts["mmap_fault"] += count
            add_leaf("mmap_fault", module, symbol, count)

    kernel_stacks = analysis.get("kernel_stacks", [])
    if not isinstance(kernel_stacks, list):
        raise ValueError("analysis has malformed kernel stacks")
    normalized_kernel_stacks: list[dict[str, object]] = []
    kernel_stack_total = 0
    for stack in kernel_stacks:
        if not isinstance(stack, dict):
            raise ValueError("analysis has a malformed kernel stack")
        stack_count = stack.get("count")
        frames = stack.get("frames")
        if (
            not isinstance(stack_count, int)
            or isinstance(stack_count, bool)
            or stack_count <= 0
            or not isinstance(frames, list)
            or not frames
            or any(not isinstance(frame, str) or not frame for frame in frames)
        ):
            raise ValueError("analysis has a malformed kernel stack")
        kernel_stack_total += stack_count
        normalized_kernel_stacks.append(
            {"count": stack_count, "frames": list(frames)}
        )
    if normalized_kernel_stacks and kernel_stack_total != kernel:
        raise ValueError("analysis kernel PC/stack counts do not reconcile")

    categories: dict[str, dict[str, object]] = {
        name: {
            "count": count,
            "per_1000_all_samples": round(count * 1000 / all_samples, 9),
        }
        for name, count in counts.items()
    }
    categories["kernel"]["stacks"] = sorted(
        normalized_kernel_stacks,
        key=lambda stack: (-int(stack["count"]), tuple(stack["frames"])),
    )
    categories["kernel"]["stack_samples"] = kernel_stack_total
    for name, leaves_by_identity in matching_leaves.items():
        categories[name]["leaves"] = [
            {"count": count, "module": module, "symbol": symbol}
            for (module, symbol), count in sorted(
                leaves_by_identity.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
    return {
        "all_samples": all_samples,
        "categories": categories,
    }


def _aggregate(classifications: list[dict[str, object]]) -> dict[str, object]:
    if not classifications:
        raise ValueError("at least one capture classification is required")
    all_samples = sum(int(item["all_samples"]) for item in classifications)
    counts = {name: 0 for name in PREDICATES}
    leaves_by_category: dict[str, dict[tuple[str, str], int]] = {
        name: {} for name in ("dyld", "locks", "malloc", "mmap_fault")
    }
    kernel_stacks: dict[tuple[str, ...], int] = {}
    for item in classifications:
        categories = item["categories"]
        assert isinstance(categories, dict)
        for name in counts:
            category = categories[name]
            assert isinstance(category, dict)
            counts[name] += int(category["count"])
            for leaf in category.get("leaves", []):
                assert isinstance(leaf, dict)
                key = (str(leaf["module"]), str(leaf["symbol"]))
                leaves_by_category[name][key] = (
                    leaves_by_category[name].get(key, 0) + int(leaf["count"])
                )
            for stack in category.get("stacks", []):
                assert isinstance(stack, dict)
                frames = tuple(str(frame) for frame in stack["frames"])
                kernel_stacks[frames] = (
                    kernel_stacks.get(frames, 0) + int(stack["count"])
                )
    categories = {
        name: {
            "count": count,
            "per_1000_all_samples": round(count * 1000 / all_samples, 9),
        }
        for name, count in counts.items()
    }
    categories["kernel"]["stacks"] = [
        {"count": count, "frames": list(frames)}
        for frames, count in sorted(
            kernel_stacks.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    categories["kernel"]["stack_samples"] = sum(kernel_stacks.values())
    for name, leaves_by_identity in leaves_by_category.items():
        categories[name]["leaves"] = [
            {"count": count, "module": module, "symbol": symbol}
            for (module, symbol), count in sorted(
                leaves_by_identity.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
    return {
        "all_samples": all_samples,
        "captures": len(classifications),
        "categories": categories,
    }


def _capture_identity(receipt: dict[str, object]) -> dict[str, object]:
    expected = receipt.get("expected_effective_identity")
    observed = receipt.get("observed_effective_identity")
    if receipt.get("status") != "passed":
        raise ValueError("capture receipt did not pass its fail-closed verifier")
    if not isinstance(expected, dict) or not isinstance(observed, dict):
        raise ValueError("capture receipt is missing effective identity")
    euid = expected.get("euid")
    egid = expected.get("egid")
    if (
        not isinstance(euid, int)
        or isinstance(euid, bool)
        or not isinstance(egid, int)
        or isinstance(egid, bool)
        or euid == 0
        or observed.get("euids") != [euid]
        or observed.get("egids") != [egid]
        or not isinstance(observed.get("reported"), int)
        or int(observed["reported"]) <= 0
    ):
        raise ValueError("capture receipt has an unverified or root effective identity")
    return {"expected": expected, "observed": observed}


def _validate_capture_artifact(
    receipt: dict[str, object], path: pathlib.Path
) -> dict[str, object]:
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("capture receipt has no artifact bindings")
    expected = _artifact(path)
    matches = [
        recorded
        for recorded in artifacts.values()
        if isinstance(recorded, dict)
        and recorded.get("bytes") == expected["bytes"]
        and recorded.get("sha256") == expected["sha256"]
    ]
    if len(matches) != 1:
        raise ValueError(f"capture receipt does not bind supplied artifact {path}")
    recorded_path = matches[0].get("path")
    if not isinstance(recorded_path, str) or not recorded_path:
        raise ValueError(f"capture receipt has malformed artifact path for {path}")
    return {**expected, "capture_recorded_path": recorded_path}


def _load_arm(
    *,
    raws: list[pathlib.Path],
    analyses: list[pathlib.Path],
    captures: list[pathlib.Path],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    if not (len(raws) == len(analyses) == len(captures)):
        raise ValueError("raw, analysis, and capture receipt counts must match")
    classifications: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    for raw_path, analysis_path, capture_path in zip(
        raws, analyses, captures, strict=True
    ):
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
        if not isinstance(analysis, dict) or not isinstance(capture, dict):
            raise ValueError("analysis and capture roots must be JSON objects")
        classifications.append(classify(analysis))
        raw_artifact = _validate_capture_artifact(capture, raw_path)
        analysis_artifact = _validate_capture_artifact(capture, analysis_path)
        artifacts.append(
            {
                "analysis": analysis_artifact,
                "capture": _artifact(capture_path),
                "identity": _capture_identity(capture),
                "raw": raw_artifact,
            }
        )
    return _aggregate(classifications), artifacts


def _compare_proportions(
    *, v2_count: int, v2_all: int, v3_count: int, v3_all: int
) -> dict[str, object]:
    v2_proportion = v2_count / v2_all
    v3_proportion = v3_count / v3_all
    delta = v3_proportion - v2_proportion
    pooled = (v2_count + v3_count) / (v2_all + v3_all)
    pooled_se = math.sqrt(
        pooled * (1.0 - pooled) * (1.0 / v2_all + 1.0 / v3_all)
    )
    if pooled_se == 0.0:
        z_score = 0.0
        p_value = 1.0
    else:
        z_score = delta / pooled_se
        p_value = 0.5 * math.erfc(z_score / math.sqrt(2.0))
    unpooled_se = math.sqrt(
        v2_proportion * (1.0 - v2_proportion) / v2_all
        + v3_proportion * (1.0 - v3_proportion) / v3_all
    )
    lower = delta - ONE_SIDED_95_Z * unpooled_se
    supported = delta > 0.0 and p_value < ONE_SIDED_ALPHA
    return {
        "delta_per_1000": round(delta * 1000, 9),
        "one_sided_95_lower_delta_per_1000": round(lower * 1000, 9),
        "one_sided_p_value": round(p_value, 12),
        "supported_v3_increase": supported,
        "v2_count": v2_count,
        "v2_per_1000": round(v2_proportion * 1000, 9),
        "v3_count": v3_count,
        "v3_larger": delta > 0.0,
        "v3_per_1000": round(v3_proportion * 1000, 9),
        "z_score": round(z_score, 9),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2-raw", type=pathlib.Path, action="append", required=True)
    parser.add_argument(
        "--v2-analysis", type=pathlib.Path, action="append", required=True
    )
    parser.add_argument(
        "--v2-capture", type=pathlib.Path, action="append", required=True
    )
    parser.add_argument("--v3-raw", type=pathlib.Path, action="append", required=True)
    parser.add_argument(
        "--v3-analysis", type=pathlib.Path, action="append", required=True
    )
    parser.add_argument(
        "--v3-capture", type=pathlib.Path, action="append", required=True
    )
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        v2, v2_artifacts = _load_arm(
            raws=arguments.v2_raw,
            analyses=arguments.v2_analysis,
            captures=arguments.v2_capture,
        )
        v3, v3_artifacts = _load_arm(
            raws=arguments.v3_raw,
            analyses=arguments.v3_analysis,
            captures=arguments.v3_capture,
        )
        if v2["captures"] != v3["captures"]:
            raise ValueError("V2 and V3 capture counts must match")
        expected_identities = {
            json.dumps(item["identity"]["expected"], sort_keys=True)
            for item in (*v2_artifacts, *v3_artifacts)
        }
        if len(expected_identities) != 1:
            raise ValueError("capture effective identities are not identical")
        artifacts = {
            "binary": _artifact(arguments.binary),
            "v2": v2_artifacts,
            "v3": v3_artifacts,
        }
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"native_pc_range_risk: {error}", file=sys.stderr)
        return 2

    v2_categories = v2["categories"]
    v3_categories = v3["categories"]
    assert isinstance(v2_categories, dict)
    assert isinstance(v3_categories, dict)
    comparisons: dict[str, dict[str, object]] = {}
    for name in PREDICATES:
        v2_category = v2_categories[name]
        v3_category = v3_categories[name]
        assert isinstance(v2_category, dict)
        assert isinstance(v3_category, dict)
        comparisons[name] = _compare_proportions(
            v2_count=int(v2_category["count"]),
            v2_all=int(v2["all_samples"]),
            v3_count=int(v3_category["count"]),
            v3_all=int(v3["all_samples"]),
        )
    larger = [name for name in PREDICATES if comparisons[name]["v3_larger"]]
    supported = [
        name
        for name in PREDICATES
        if comparisons[name]["supported_v3_increase"]
    ]
    receipt = {
        "artifacts": artifacts,
        "capture_pairs": v2["captures"],
        "comparisons": comparisons,
        "larger_v3_owners": larger,
        "predicates": PREDICATES,
        "regression_method": REGRESSION_METHOD,
        "schema": SCHEMA,
        "status": "failed" if supported else "passed",
        "supported_v3_owner_increases": supported,
        "v2": v2,
        "v3": v3,
    }
    arguments.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 2 if supported else 0


if __name__ == "__main__":
    raise SystemExit(main())
