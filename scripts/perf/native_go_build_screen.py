#!/usr/bin/env python3
"""Run exact untraced native Go-build screen and retention gates."""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import statistics
import sys
from collections.abc import Callable, Sequence

import native_go_build
import paired_stats


SCHEMA = "carrick.native-go-build-screen.v1"
C0_MS = 19_375
DEFAULT = native_go_build.VARIANT_OVERLAYS["default"]
PRECURSOR = native_go_build.VARIANT_OVERLAYS["precursor"]
CANDIDATE = native_go_build.VARIANT_OVERLAYS["candidate"]
PALINDROMIC = (
    "precursor",
    "default",
    "candidate",
    "candidate",
    "default",
    "precursor",
)
RETENTION = tuple(
    variant for _ in range(5) for variant in ("default", "candidate")
)


def median(values: Sequence[int]) -> float:
    if not values:
        raise ValueError("at least one value is required")
    return float(statistics.median(values))


def bootstrap_ratio(
    controls: Sequence[int],
    candidates: Sequence[int],
    *,
    draws: int = paired_stats.BOOTSTRAP_DRAWS,
    seed: int = paired_stats.BOOTSTRAP_SEED,
) -> dict[str, object]:
    if len(controls) != 5 or len(candidates) != 5:
        raise ValueError("bootstrap requires exactly five controls and candidates")
    if any(control <= 0 for control in controls):
        raise ValueError("paired controls must be positive")
    ratios = [candidate / control for control, candidate in zip(controls, candidates)]
    return dataclasses.asdict(
        paired_stats.paired_bootstrap(ratios, draws=draws, seed=seed)
    )


def evaluate_screen(samples: Sequence[dict[str, object]]) -> dict[str, object]:
    reasons: list[str] = []
    variants = tuple(str(row.get("variant")) for row in samples)
    if variants != PALINDROMIC:
        reasons.append("screen samples do not follow the fixed palindromic order")
    if len(samples) != len(PALINDROMIC):
        return {
            "accepted": False,
            "rejection_reasons": reasons,
            "default_drift_ratio": None,
            "candidate_default_ratio": None,
            "contemporaneous_pairs": [],
        }
    elapsed = [int(row["elapsed_ms"]) for row in samples]
    if any(value <= 0 for value in elapsed):
        reasons.append("all elapsed samples must be positive")
    defaults = [elapsed[1], elapsed[4]]
    candidates = [elapsed[2], elapsed[3]]
    precursors = [elapsed[0], elapsed[5]]
    drift = max(defaults) / min(defaults)
    if drift > 1.05:
        reasons.append("default drift exceeds 1.05")
    pairs = [
        {
            "candidate_position": 3,
            "default_position": 2,
            "ratio": candidates[0] / defaults[0],
        },
        {
            "candidate_position": 4,
            "default_position": 5,
            "ratio": candidates[1] / defaults[1],
        },
    ]
    if candidates[0] >= defaults[0]:
        reasons.append(
            "candidate position 3 did not beat paired default position 2"
        )
    if candidates[1] >= defaults[1]:
        reasons.append(
            "candidate position 4 did not beat paired default position 5"
        )
    candidate_median = median(candidates)
    default_median = median(defaults)
    precursor_median = median(precursors)
    ratio = candidate_median / default_median
    if ratio > 0.97:
        reasons.append("candidate/default median ratio exceeds 0.97")
    if candidate_median >= precursor_median:
        reasons.append("candidate median did not beat precursor median")
    if candidate_median >= C0_MS:
        reasons.append(f"candidate median is not below C0={C0_MS} ms")
    return {
        "accepted": not reasons,
        "rejection_reasons": reasons,
        "default_drift_ratio": drift,
        "candidate_default_ratio": ratio,
        "candidate_median_ms": candidate_median,
        "default_median_ms": default_median,
        "precursor_median_ms": precursor_median,
        "c0_ms": C0_MS,
        "contemporaneous_pairs": pairs,
    }


def evaluate_retention(samples: Sequence[dict[str, object]]) -> dict[str, object]:
    reasons: list[str] = []
    variants = tuple(str(row.get("variant")) for row in samples)
    if variants != RETENTION:
        reasons.append("retention samples do not alternate five controls and candidates")
    controls = [
        int(row["elapsed_ms"])
        for row in samples
        if row.get("variant") == "default"
    ]
    candidates = [
        int(row["elapsed_ms"])
        for row in samples
        if row.get("variant") == "candidate"
    ]
    if len(controls) != 5 or len(candidates) != 5:
        return {
            "accepted": False,
            "rejection_reasons": reasons,
            "candidate_median_ms": None,
            "default_median_ms": None,
            "bootstrap": None,
        }
    candidate_median = median(candidates)
    control_median = median(controls)
    ratio = candidate_median / control_median
    bootstrap = bootstrap_ratio(controls, candidates)
    if candidate_median >= control_median:
        reasons.append("candidate median is not below contemporaneous control")
    if ratio > 0.97:
        reasons.append("candidate/control median ratio exceeds 0.97")
    if float(bootstrap["one_sided_upper"]) >= 1.0:
        reasons.append("one-sided 95% bootstrap ratio is not below 1.0")
    if candidate_median >= C0_MS:
        reasons.append(f"candidate median is not below C0={C0_MS} ms")
    return {
        "accepted": not reasons,
        "rejection_reasons": reasons,
        "candidate_median_ms": candidate_median,
        "default_median_ms": control_median,
        "candidate_default_ratio": ratio,
        "bootstrap": bootstrap,
        "c0_ms": C0_MS,
    }


def publish_screen(
    output: pathlib.Path,
    samples: Sequence[dict[str, object]],
    *,
    mode: str = "screen",
    extra_reasons: Sequence[str] = (),
) -> dict[str, object]:
    result = (
        evaluate_screen(samples)
        if mode == "screen"
        else evaluate_retention(samples)
    )
    reasons = [*result["rejection_reasons"], *extra_reasons]
    payload = {
        "schema": SCHEMA,
        "mode": mode,
        **result,
        "accepted": bool(result["accepted"]) and not extra_reasons,
        "rejection_reasons": reasons,
        "samples": list(samples),
    }
    native_go_build.write_json_atomic(output, payload)
    return payload


def run_campaign(
    repo: pathlib.Path,
    mode: str,
    output: pathlib.Path,
    timeout_seconds: int,
    sample_runner: Callable[..., dict[str, object]] = native_go_build.run_sample,
) -> dict[str, object]:
    order = PALINDROMIC if mode == "screen" else RETENTION
    completed: list[dict[str, object]] = []
    try:
        for index, variant in enumerate(order, start=1):
            row = sample_runner(
                repo,
                native_go_build.ENGINE_CARRICK,
                index,
                timeout_seconds,
                environment_overlay=native_go_build.fixed_variant_overlay(variant),
            )
            completed.append({**row, "variant": variant})
    except native_go_build.SampleEvidenceError as error:
        failed_variant = order[len(completed)]
        completed.append({**error.sample, "variant": failed_variant})
        payload = publish_screen(
            output,
            completed,
            mode=mode,
            extra_reasons=(f"sample failed: {error}",),
        )
        return payload
    except Exception as error:
        payload = publish_screen(
            output,
            completed,
            mode=mode,
            extra_reasons=(f"sample failed: {error}",),
        )
        return payload
    return publish_screen(output, completed, mode=mode)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("screen", "retention"), default="screen")
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("target/perf/native-go-build-screen.json"),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=native_go_build.DEFAULT_TIMEOUT_SECONDS,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    repo = pathlib.Path(__file__).resolve().parents[2]
    result = run_campaign(
        repo, args.mode, args.output, args.timeout_seconds
    )
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
