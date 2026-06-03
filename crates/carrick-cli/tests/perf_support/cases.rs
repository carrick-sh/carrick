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
    /// true = a HIGHER metric is better (throughput, MB/s); false = LOWER is
    /// better (latency, us). Controls the win/lose direction of the reported
    /// carrick/docker ratio.
    pub higher_is_better: bool,
}

/// Registered workloads. Adding one = an entry here + a probe in
/// conformance-probes/src/bin/. Network = thesis-core; disk metadata is the
/// honest exception (carrick's documented cap-std amplification).
pub const CASES: &[PerfCase] = &[
    // Latency (lower better): loopback request/response round-trip.
    PerfCase {
        probe: "perf_net_tcp_rr",
        dimension: "network",
        workload: "tcp_rr",
        metric_key: "tcp_rr_p50_us",
        unit: "us",
        higher_is_better: false,
    },
    // Throughput (higher better): loopback bulk stream — exercises carrick's
    // per-call bounce-buffer memcpy vs docker's in-kernel loopback.
    PerfCase {
        probe: "perf_net_tcp_stream",
        dimension: "network",
        workload: "tcp_stream",
        metric_key: "tcp_stream_mbps",
        unit: "MB/s",
        higher_is_better: true,
    },
    // Latency (lower better): deep-path stat storm — carrick's cap-std
    // per-component openat re-walk vs docker's single in-kernel VFS walk.
    PerfCase {
        probe: "perf_disk_meta",
        dimension: "disk",
        workload: "stat_storm",
        metric_key: "stat_p50_us",
        unit: "us",
        higher_is_better: false,
    },
];

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
