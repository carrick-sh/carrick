#!/usr/bin/env python3
"""Deterministic, cross-language paired statistics for performance evidence."""

from __future__ import annotations

import dataclasses
import math
import statistics
from collections.abc import Sequence
from fractions import Fraction


BOOTSTRAP_DRAWS = 100_000
BOOTSTRAP_SEED = 0x4341525249434B31
MASK64 = (1 << 64) - 1
PRNG_ID = "splitmix64-v1"
SAMPLER_ID = "u64-rejection-mod-v1"
MEDIAN_RULE = "sorted-binary64-middle-or-middle-mean-v1"
QUANTILE_RULE = "nearest-rank-v1"
Z95 = 1.6448536269514722


@dataclasses.dataclass(frozen=True)
class BootstrapResult:
    prng_id: str
    sampler_id: str
    seed_hex: str
    draws: int
    median_rule: str
    quantile_rule: str
    two_sided_lower: float
    two_sided_upper: float
    one_sided_upper: float
    accepted_indices: int
    rejected_outputs: int
    first_indices: tuple[int, ...]


def splitmix64(state: int) -> tuple[int, int]:
    """Advance the specified wrapping SplitMix64 stream once."""
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    value = state
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, (value ^ (value >> 31)) & MASK64


def rejection_index(state: int, population: int) -> tuple[int, int, int]:
    """Draw an unbiased index while preserving rejected PRNG outputs."""
    if population <= 0:
        raise ValueError("population must be positive")
    modulus = 1 << 64
    limit = modulus - modulus % population
    rejected = 0
    while True:
        state, value = splitmix64(state)
        if value < limit:
            return state, value % population, rejected
        rejected += 1


def median_binary64(values: Sequence[float]) -> float:
    """Return the contract median, including a binary64 even-population mean."""
    if not values:
        raise ValueError("values must not be empty")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def nearest_rank(values: Sequence[float], probability: float) -> float:
    """Return the specified inclusive nearest-rank quantile."""
    if not values:
        raise ValueError("values must not be empty")
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be finite and within [0, 1]")
    ordered = sorted(values)
    index = max(1, math.ceil(probability * len(ordered))) - 1
    return float(ordered[index])


def paired_bootstrap(
    ratios: Sequence[float], *, draws: int = BOOTSTRAP_DRAWS, seed: int = BOOTSTRAP_SEED
) -> BootstrapResult:
    """Resample complete paired ratios with the fixed SplitMix64 stream."""
    if not ratios:
        raise ValueError("ratios must not be empty")
    if draws <= 0:
        raise ValueError("bootstrap draws must be positive")
    if not 0 <= seed <= MASK64:
        raise ValueError("bootstrap seed must be an unsigned 64-bit integer")

    state = seed
    sampled_medians: list[float] = []
    first_indices: list[int] = []
    rejected_outputs = 0
    population = len(ratios)
    for _ in range(draws):
        sampled: list[float] = []
        for _ in range(population):
            state, index, rejected = rejection_index(state, population)
            if len(first_indices) < 32:
                first_indices.append(index)
            rejected_outputs += rejected
            sampled.append(float(ratios[index]))
        sampled_medians.append(median_binary64(sampled))

    return BootstrapResult(
        prng_id=PRNG_ID,
        sampler_id=SAMPLER_ID,
        seed_hex=f"0x{seed:016x}",
        draws=draws,
        median_rule=MEDIAN_RULE,
        quantile_rule=QUANTILE_RULE,
        two_sided_lower=nearest_rank(sampled_medians, 0.025),
        two_sided_upper=nearest_rank(sampled_medians, 0.975),
        one_sided_upper=nearest_rank(sampled_medians, 0.95),
        accepted_indices=draws * population,
        rejected_outputs=rejected_outputs,
        first_indices=tuple(first_indices),
    )


def exact_one_sided_sign_probability(wins: int, trials: int) -> Fraction:
    """Return P(Binomial(trials, 0.5) >= wins) with exact integer arithmetic."""
    if trials < 0 or wins < 0 or wins > trials or trials > 127:
        raise ValueError("sign-test counts are invalid")
    numerator = sum(math.comb(trials, k) for k in range(wins, trials + 1))
    return Fraction(numerator, 1 << trials)


def exact_probability_json(value: Fraction) -> dict[str, int | float]:
    """Encode an exact probability without discarding its rational authority."""
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "probability": float(value),
    }


def ratio_resolution(ratios: Sequence[float]) -> dict[str, float | int | str]:
    """Report the controller's unrounded normal ratio-resolution diagnostic."""
    if len(ratios) < 2:
        raise ValueError("ratio resolution requires at least two ratios")
    ratio_standard_deviation = statistics.stdev(ratios)
    resolution_fraction = Z95 * ratio_standard_deviation / math.sqrt(len(ratios))
    return {
        "formula": "normal-one-sided-ratio-sd-v1",
        "n": len(ratios),
        "ratio_standard_deviation": ratio_standard_deviation,
        "z95": Z95,
        "resolution_fraction": resolution_fraction,
        "smallest_resolvable_improvement_ratio": 1 - resolution_fraction,
        "smallest_resolvable_effect_percent": 100 * resolution_fraction,
    }
