//! Pure summary statistics over a set of per-repetition metric values.
//!
//! p50/p95 use the nearest-rank method, matching the in-guest performance
//! probes so the harness and trace-profile output share one definition.

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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct RatioInterval {
    pub estimate: f64,
    pub lower: f64,
    pub upper: f64,
    pub resamples: usize,
}

#[cfg(test)]
pub fn bootstrap_median_ratio(
    baseline: &[f64],
    candidate: &[f64],
    seed: u64,
    resamples: usize,
) -> Option<RatioInterval> {
    use rand::{Rng, SeedableRng, rngs::StdRng};

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

#[cfg(test)]
fn sample_median(values: &[f64]) -> Option<f64> {
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
}
