//! Declarative perf-case registry. Adding a workload = adding a PerfCase entry
//! (and dropping its probe in conformance-probes/src/bin/). The runner builds
//! the probe path from `probe`, runs it under both engines, and pulls
//! `metric_key` out of each engine's parsed output as the per-rep value.

#[derive(Debug, Clone, Copy)]
pub struct PerfCase {
    /// Probe binary name in conformance-probes/.../release/ (no extension).
    pub probe: &'static str,
    pub dimension: &'static str,
    pub workload: &'static str,
    /// Key the probe prints whose value is the per-rep metric.
    pub metric_key: &'static str,
    pub unit: &'static str,
}

/// Phase 0: the marquee network case. Later phases append disk/fork/thread cases.
pub const CASES: &[PerfCase] = &[PerfCase {
    probe: "perf_net_tcp_rr",
    dimension: "network",
    workload: "tcp_rr",
    metric_key: "tcp_rr_p50_us",
    unit: "us",
}];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_nonempty_and_well_formed() {
        assert!(!CASES.is_empty());
        for c in CASES {
            assert!(!c.probe.is_empty());
            assert!(!c.metric_key.is_empty());
        }
    }
}
