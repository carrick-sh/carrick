//! Pure summary statistics over a set of per-repetition metric values.
//!
//! p50/p95 use the nearest-rank method, matching the in-guest performance
//! probes so the harness and trace-profile output share one definition.

use anyhow::{Context, Result};

#[allow(dead_code, reason = "consumed by paired performance evidence")]
pub const PAIRED_BOOTSTRAP_DRAWS: usize = 100_000;
#[allow(dead_code, reason = "consumed by paired performance evidence")]
pub const PAIRED_BOOTSTRAP_SEED: u64 = 0x4341_5252_4943_4b31;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code, reason = "consumed by paired performance evidence")]
pub struct PairedBootstrap {
    pub two_sided_lower: f64,
    pub two_sided_upper: f64,
    pub one_sided_upper: f64,
    pub accepted_indices: u64,
    pub rejected_outputs: u64,
    pub first_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Summary {
    pub p50: f64,
    pub p95: f64,
    pub min: f64,
    pub iqr: f64,
    pub n: usize,
}

fn nearest_rank(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = (((sorted.len() as f64) * p).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

pub fn summarize(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q1 = nearest_rank(&sorted, 0.25);
    let q3 = nearest_rank(&sorted, 0.75);
    Some(Summary {
        p50: nearest_rank(&sorted, 0.50),
        p95: nearest_rank(&sorted, 0.95),
        min: sorted[0],
        iqr: q3 - q1,
        n: sorted.len(),
    })
}

#[allow(dead_code, reason = "consumed by the Task 8 overhead gate")]
pub fn is_noisy(summary: &Summary) -> bool {
    summary.p50 > 0.0 && (summary.iqr / summary.p50) > 0.10
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
#[allow(dead_code, reason = "consumed by backend-pair report evidence")]
pub struct RatioInterval {
    pub estimate: f64,
    pub lower: f64,
    pub upper: f64,
    pub resamples: usize,
}

#[allow(dead_code, reason = "consumed by backend-pair report evidence")]
pub fn bootstrap_median_ratio(
    baseline: &[f64],
    candidate: &[f64],
    seed: u64,
    resamples: usize,
) -> Option<RatioInterval> {
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    if baseline.is_empty()
        || candidate.is_empty()
        || resamples == 0
        || baseline
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || candidate
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
    {
        return None;
    }

    let baseline_median = sample_median(baseline)?;
    let candidate_median = sample_median(candidate)?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut baseline_sample = Vec::with_capacity(baseline.len());
    let mut candidate_sample = Vec::with_capacity(candidate.len());
    let mut ratios = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        baseline_sample.clear();
        candidate_sample.clear();
        for _ in 0..baseline.len() {
            baseline_sample.push(baseline[rng.random_range(0..baseline.len())]);
        }
        for _ in 0..candidate.len() {
            candidate_sample.push(candidate[rng.random_range(0..candidate.len())]);
        }
        let denominator = sample_median(&baseline_sample)?;
        if denominator <= 0.0 {
            return None;
        }
        ratios.push(sample_median(&candidate_sample)? / denominator);
    }
    ratios.sort_by(|left, right| left.total_cmp(right));
    Some(RatioInterval {
        estimate: candidate_median / baseline_median,
        lower: nearest_rank(&ratios, 0.025),
        upper: nearest_rank(&ratios, 0.975),
        resamples,
    })
}

/// Advance the fixed cross-language SplitMix64 stream once.
#[allow(dead_code, reason = "consumed by paired performance evidence")]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Draw an unbiased index while preserving rejected PRNG outputs.
#[allow(dead_code, reason = "consumed by paired performance evidence")]
fn rejection_index(state: &mut u64, population: usize) -> Result<(usize, u64)> {
    anyhow::ensure!(population > 0, "population must be positive");
    let modulus = 1_u128 << 64;
    let limit = modulus - modulus % population as u128;
    let mut rejected = 0_u64;
    loop {
        let value = splitmix64(state);
        if (value as u128) < limit {
            return Ok(((value as usize) % population, rejected));
        }
        rejected = rejected
            .checked_add(1)
            .context("rejection count overflow")?;
    }
}

/// Resample complete paired ratios using the fixed evidence stream.
#[allow(dead_code, reason = "consumed by paired performance evidence")]
pub fn paired_bootstrap(ratios: &[f64]) -> Result<PairedBootstrap> {
    anyhow::ensure!(!ratios.is_empty(), "ratios must not be empty");

    let population = ratios.len();
    let population_count = u64::try_from(population).context("population exceeds u64")?;
    let accepted_indices = u64::try_from(PAIRED_BOOTSTRAP_DRAWS)
        .context("bootstrap draws exceed u64")?
        .checked_mul(population_count)
        .context("accepted index count overflow")?;
    let mut state = PAIRED_BOOTSTRAP_SEED;
    let mut sampled = Vec::with_capacity(population);
    let mut sampled_medians = Vec::with_capacity(PAIRED_BOOTSTRAP_DRAWS);
    let mut first_indices = Vec::with_capacity(32);
    let mut rejected_outputs = 0_u64;

    for _ in 0..PAIRED_BOOTSTRAP_DRAWS {
        sampled.clear();
        for _ in 0..population {
            let (index, rejected) = rejection_index(&mut state, population)?;
            if first_indices.len() < 32 {
                first_indices.push(index);
            }
            rejected_outputs = rejected_outputs
                .checked_add(rejected)
                .context("rejected output count overflow")?;
            sampled.push(ratios[index]);
        }
        sampled_medians.push(sample_median(&sampled).context("sampled ratios must not be empty")?);
    }

    sampled_medians.sort_by(f64::total_cmp);

    Ok(PairedBootstrap {
        two_sided_lower: nearest_rank(&sampled_medians, 0.025),
        two_sided_upper: nearest_rank(&sampled_medians, 0.975),
        one_sided_upper: nearest_rank(&sampled_medians, 0.95),
        accepted_indices,
        rejected_outputs,
        first_indices,
    })
}

#[allow(dead_code, reason = "consumed by paired performance evidence")]
fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

#[allow(dead_code, reason = "consumed by paired performance evidence")]
fn binomial_coefficient(trials: u32, wins: u32) -> Result<u128> {
    let count = wins.min(trials - wins);
    let mut coefficient = 1_u128;
    for step in 1..=count {
        let mut numerator = u128::from(trials - count + step);
        let mut denominator = u128::from(step);
        let factor_gcd = greatest_common_divisor(numerator, denominator);
        numerator /= factor_gcd;
        denominator /= factor_gcd;
        let coefficient_gcd = greatest_common_divisor(coefficient, denominator);
        coefficient /= coefficient_gcd;
        denominator /= coefficient_gcd;
        anyhow::ensure!(
            denominator == 1,
            "binomial coefficient division was inexact"
        );
        coefficient = coefficient
            .checked_mul(numerator)
            .context("binomial coefficient overflow")?;
    }
    Ok(coefficient)
}

/// Return P(Binomial(trials, 0.5) >= wins) as an exact rational pair.
#[allow(dead_code, reason = "consumed by paired performance evidence")]
pub fn exact_one_sided_sign_probability(wins: u32, trials: u32) -> Result<(u128, u128)> {
    anyhow::ensure!(
        wins <= trials && trials <= 127,
        "sign-test counts are invalid"
    );
    let mut numerator = 0_u128;
    for observed_wins in wins..=trials {
        numerator = numerator
            .checked_add(binomial_coefficient(trials, observed_wins)?)
            .context("sign-test numerator overflow")?;
    }
    let denominator = 1_u128 << trials;
    let divisor = greatest_common_divisor(numerator, denominator);
    Ok((numerator / divisor, denominator / divisor))
}

#[allow(dead_code, reason = "consumed by seeded bootstrap statistics")]
pub fn sample_median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        Some((sorted[middle - 1] + sorted[middle]) / 2.0)
    } else {
        Some(sorted[middle])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct PairedStatsFixture {
        draws: usize,
        ratios: Vec<f64>,
        first_indices: Vec<usize>,
        bound_binary64_be: Vec<String>,
    }

    #[test]
    fn summarize_basic_percentiles() {
        let values: Vec<f64> = (1..=10).map(f64::from).collect();
        let summary = summarize(&values).expect("non-empty values");
        assert_eq!(summary.min, 1.0);
        assert_eq!(summary.p50, 5.0);
        assert_eq!(summary.p95, 10.0);
        assert_eq!(summary.n, 10);
        assert_eq!(summary.iqr, 8.0 - 3.0);
    }

    #[test]
    fn summarize_empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn noisy_when_spread_is_wide() {
        let tight = Summary {
            p50: 100.0,
            p95: 105.0,
            min: 99.0,
            iqr: 5.0,
            n: 8,
        };
        let wide = Summary {
            p50: 100.0,
            p95: 180.0,
            min: 90.0,
            iqr: 40.0,
            n: 8,
        };
        assert!(!is_noisy(&tight));
        assert!(is_noisy(&wide));
    }

    #[test]
    fn bootstrap_median_ratio_is_seeded_and_pinned() {
        let baseline = [100.0, 101.0, 102.0, 103.0, 104.0];
        let candidate = [99.0, 100.0, 101.0, 102.0, 103.0];
        let interval = bootstrap_median_ratio(&baseline, &candidate, 42, 2_000)
            .expect("non-empty finite samples");
        assert_eq!(interval.resamples, 2_000);
        assert!((interval.estimate - (101.0 / 102.0)).abs() < 1e-12);
        assert!((interval.lower - 0.961_538_461_538_461_6).abs() < 1e-12);
        assert!((interval.upper - 1.019_801_980_198_019_8).abs() < 1e-12);
    }

    #[test]
    fn bootstrap_median_ratio_rejects_empty_or_zero_baseline() {
        assert!(bootstrap_median_ratio(&[], &[1.0], 1, 10).is_none());
        assert!(bootstrap_median_ratio(&[0.0], &[1.0], 1, 10).is_none());
    }

    #[test]
    fn paired_bootstrap_matches_checked_in_binary64_fixture() {
        let fixture: PairedStatsFixture = serde_json::from_str(include_str!(
            "../../../scripts/perf/fixtures/paired-stats-v1.json"
        ))
        .expect("valid paired-statistics fixture");
        let result = paired_bootstrap(&fixture.ratios).expect("valid paired ratios");

        assert_eq!(result.first_indices, fixture.first_indices);
        assert_eq!(
            result.accepted_indices,
            u64::try_from(fixture.draws * fixture.ratios.len()).expect("fixture count fits u64")
        );
        assert_eq!(result.rejected_outputs, 0);
        for (actual, expected) in [
            result.two_sided_lower,
            result.two_sided_upper,
            result.one_sided_upper,
        ]
        .into_iter()
        .zip(&fixture.bound_binary64_be)
        {
            assert_eq!(
                actual.to_bits(),
                u64::from_str_radix(expected, 16).expect("fixture binary64 bits")
            );
        }
    }

    #[test]
    fn paired_bootstrap_rejects_empty_ratios() {
        assert!(paired_bootstrap(&[]).is_err());
    }

    #[test]
    fn paired_sign_probability_is_exact_and_rejects_invalid_counts() {
        assert_eq!(
            exact_one_sided_sign_probability(7, 8).expect("valid sign-test counts"),
            (9, 256)
        );
        assert_eq!(
            exact_one_sided_sign_probability(0, 8).expect("valid sign-test counts"),
            (1, 1)
        );
        assert!(exact_one_sided_sign_probability(2, 1).is_err());
        assert!(exact_one_sided_sign_probability(0, 128).is_err());
    }
}
