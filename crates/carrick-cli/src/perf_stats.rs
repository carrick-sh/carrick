//! Pure summary statistics over a set of per-repetition metric values.
//!
//! p50/p95 use the nearest-rank method, matching the in-guest performance
//! probes so the harness and trace-profile output share one definition.
#![cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the Task 4 profile CLI")
)]

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

pub fn is_noisy(summary: &Summary) -> bool {
    summary.p50 > 0.0 && (summary.iqr / summary.p50) > 0.10
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
}
