//! Pure summary statistics over a set of per-rep metric values.
//! p50/p95 use the nearest-rank method (matches the in-guest probe), so the
//! harness and the probe speak the same percentile definition.

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Summary {
    pub p50: f64,
    pub p95: f64,
    pub min: f64,
    pub iqr: f64,
    pub n: usize,
}

/// Nearest-rank percentile of an already-collected sample set (p in [0,1]).
fn nearest_rank(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = (((sorted.len() as f64) * p).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

/// Summarize per-rep values. Returns None if empty.
pub fn summarize(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q1 = nearest_rank(&s, 0.25);
    let q3 = nearest_rank(&s, 0.75);
    Some(Summary {
        p50: nearest_rank(&s, 0.50),
        p95: nearest_rank(&s, 0.95),
        min: s[0],
        iqr: q3 - q1,
        n: s.len(),
    })
}

/// A row is NOISY if its spread is wide relative to its center: IQR/p50 > 0.10.
/// (Operationalizes the protocol's "stddev/median > 10%" using the
/// outlier-robust IQR rather than a thermal-spike-sensitive stddev.)
pub fn is_noisy(s: &Summary) -> bool {
    s.p50 > 0.0 && (s.iqr / s.p50) > 0.10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_basic_percentiles() {
        let v: Vec<f64> = (1..=10).map(|x| x as f64).collect(); // 1..10
        let s = summarize(&v).unwrap();
        assert_eq!(s.min, 1.0);
        assert_eq!(s.p50, 5.0); // nearest-rank: ceil(10*0.5)-1 = idx 4 -> value 5
        assert_eq!(s.p95, 10.0); // ceil(10*0.95)-1 = idx 9 -> value 10
        assert_eq!(s.n, 10);
        assert_eq!(s.iqr, 8.0 - 3.0); // q3=idx ceil(7.5)-1=7 ->8, q1=ceil(2.5)-1=2 ->3
    }

    #[test]
    fn summarize_empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn noisy_when_spread_wide() {
        let tight = Summary { p50: 100.0, p95: 105.0, min: 99.0, iqr: 5.0, n: 8 };
        let wide = Summary { p50: 100.0, p95: 180.0, min: 90.0, iqr: 40.0, n: 8 };
        assert!(!is_noisy(&tight));
        assert!(is_noisy(&wide));
    }
}
