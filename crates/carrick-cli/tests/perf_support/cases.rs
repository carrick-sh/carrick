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
    /// true = bind-mount `.bench-scratch` into the guest (carrick `--fs host -v`
    /// / docker `-v`) at /mnt and set `BENCH_DIR=/mnt`; native gets
    /// `BENCH_DIR=<abs .bench-scratch>`. The direct-host-FD-vs-virtiofs disk test.
    pub mount_scratch: bool,
    /// Carrick filesystem backend for this case. Most workloads use `host`; the
    /// overlay/dirty-range workload uses `memory` to exercise in-memory VFS
    /// writeback instead of raw host-fd paths.
    pub carrick_fs_mode: &'static str,
    /// true = the macOS-HOST-client ↔ guest-server CROSS-BOUNDARY test (carrick's
    /// native host socket vs docker's `-p`/vpnkit NAT). `probe` is the guest
    /// server; the host client is fixed. Dispatched to the `xboundary` module.
    pub cross_boundary: bool,
}

/// Registered workloads. Adding one = an entry here + a probe in
/// conformance-probes/src/bin/. Network = thesis-core; disk metadata is the
/// honest exception (carrick's documented cap-std amplification).
pub const CASES: &[PerfCase] = &[
    // Latency (lower better): raw guest syscall trap+dispatch floor.
    PerfCase {
        probe: "perf_trap_floor",
        dimension: "syscall",
        workload: "trap_floor",
        metric_key: "trap_p50_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): private futex wait/wake handoff.
    PerfCase {
        probe: "perf_futex_pingpong",
        dimension: "syscall",
        workload: "futex_pingpong",
        metric_key: "futex_pingpong_p50_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): blocking read wakeup on a stable pipe fd. This
    // isolates per-wait fd pinning, kqueue registration, and wake bookkeeping
    // from explicit timeout sleep.
    PerfCase {
        probe: "perf_wait_pipe_pingpong",
        dimension: "syscall",
        workload: "wait_pipe_pingpong",
        metric_key: "wait_pipe_pingpong_p50_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): many small dynamic-style writes to stdout.
    PerfCase {
        probe: "perf_stdio_burst",
        dimension: "syscall",
        workload: "stdio_burst",
        metric_key: "stdio_burst_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): many small dynamic-style writev calls to stdout.
    PerfCase {
        probe: "perf_writev_burst",
        dimension: "syscall",
        workload: "writev_burst",
        metric_key: "writev_burst_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): many small positional host-file pwritev calls.
    PerfCase {
        probe: "perf_pwritev_burst",
        dimension: "syscall",
        workload: "pwritev_burst",
        metric_key: "pwritev_burst_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): many small positional host-file preadv calls.
    PerfCase {
        probe: "perf_preadv_burst",
        dimension: "syscall",
        workload: "preadv_burst",
        metric_key: "preadv_burst_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): fresh private anonymous mmap churn without
    // touching mapped pages. This exposes runtime zero-fill/page-dirtying that
    // Linux avoids for untouched anonymous VMAs.
    PerfCase {
        probe: "perf_mmap_churn",
        dimension: "memory",
        workload: "mmap_churn",
        metric_key: "mmap_churn_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): loopback request/response round-trip.
    PerfCase {
        probe: "perf_net_tcp_rr",
        dimension: "network",
        workload: "tcp_rr",
        metric_key: "tcp_rr_p50_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
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
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
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
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): metadata/open/access storm against a large sparse
    // file. This verifies the metadata path stays payload-size independent.
    PerfCase {
        probe: "perf_large_meta",
        dimension: "disk",
        workload: "large_meta",
        metric_key: "large_meta_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Latency (lower better): build-tool-like small updates over a larger file
    // set on the in-memory overlay path. This should exercise dirty-range
    // writeback instead of host-fd paths.
    PerfCase {
        probe: "perf_overlay_small_updates",
        dimension: "disk",
        workload: "overlay_small_updates",
        metric_key: "overlay_small_updates_total_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "memory",
        cross_boundary: false,
    },
    // Throughput (higher better): bulk WRITE over a bind mount — carrick's
    // direct host FD (--fs host -v) vs docker's virtiofs VM-boundary round-trip.
    // The sharpest test of the "no virtiofs abstraction" disk thesis.
    PerfCase {
        probe: "perf_disk_vol",
        dimension: "disk",
        workload: "vol_write",
        metric_key: "disk_vol_write_mbps",
        unit: "MB/s",
        higher_is_better: true,
        mount_scratch: true,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // Throughput (higher better): bulk READ over the same bind mount.
    PerfCase {
        probe: "perf_disk_vol",
        dimension: "disk",
        workload: "vol_read",
        metric_key: "disk_vol_read_mbps",
        unit: "MB/s",
        higher_is_better: true,
        mount_scratch: true,
        carrick_fs_mode: "host",
        cross_boundary: false,
    },
    // CROSS-BOUNDARY latency (lower better): macOS-host client → guest echo
    // server RTT. carrick's guest bind is a real Darwin host socket (directly
    // reachable); docker reaches it only via -p/vpnkit NAT. The "reach" thesis.
    PerfCase {
        probe: "perf_net_xserver",
        dimension: "network",
        workload: "xboundary_rtt",
        metric_key: "xrtt_p50_us",
        unit: "us",
        higher_is_better: false,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: true,
    },
    // CROSS-BOUNDARY throughput (higher better): host↔guest echo stream.
    PerfCase {
        probe: "perf_net_xserver",
        dimension: "network",
        workload: "xboundary_stream",
        metric_key: "xstream_mbps",
        unit: "MB/s",
        higher_is_better: true,
        mount_scratch: false,
        carrick_fs_mode: "host",
        cross_boundary: true,
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
            assert!(
                matches!(c.carrick_fs_mode, "host" | "memory"),
                "unexpected carrick fs mode {} for {}",
                c.carrick_fs_mode,
                c.workload
            );
            if c.mount_scratch {
                assert_eq!(c.carrick_fs_mode, "host");
            }
        }
    }

    #[test]
    fn registry_contains_syscall_perf_surface() {
        let required = [
            ("trap_floor", "perf_trap_floor", "trap_p50_us"),
            (
                "futex_pingpong",
                "perf_futex_pingpong",
                "futex_pingpong_p50_us",
            ),
            ("stdio_burst", "perf_stdio_burst", "stdio_burst_total_us"),
            ("writev_burst", "perf_writev_burst", "writev_burst_total_us"),
            (
                "pwritev_burst",
                "perf_pwritev_burst",
                "pwritev_burst_total_us",
            ),
            ("preadv_burst", "perf_preadv_burst", "preadv_burst_total_us"),
            (
                "wait_pipe_pingpong",
                "perf_wait_pipe_pingpong",
                "wait_pipe_pingpong_p50_us",
            ),
        ];

        for (workload, probe, metric_key) in required {
            let case = CASES
                .iter()
                .find(|case| case.workload == workload)
                .unwrap_or_else(|| panic!("missing perf workload {workload}"));
            assert_eq!(case.dimension, "syscall");
            assert_eq!(case.probe, probe);
            assert_eq!(case.metric_key, metric_key);
            assert_eq!(case.unit, "us");
            assert!(!case.higher_is_better);
            assert!(!case.mount_scratch);
            assert_eq!(case.carrick_fs_mode, "host");
            assert!(!case.cross_boundary);
        }
    }

    #[test]
    fn registry_contains_memory_perf_surface() {
        let case = CASES
            .iter()
            .find(|case| case.workload == "mmap_churn")
            .expect("missing mmap_churn perf workload");
        assert_eq!(case.dimension, "memory");
        assert_eq!(case.probe, "perf_mmap_churn");
        assert_eq!(case.metric_key, "mmap_churn_total_us");
        assert_eq!(case.unit, "us");
        assert!(!case.higher_is_better);
        assert!(!case.mount_scratch);
        assert_eq!(case.carrick_fs_mode, "host");
        assert!(!case.cross_boundary);
    }

    #[test]
    fn registry_contains_disk_perf_surface() {
        let required = [
            ("stat_storm", "perf_disk_meta", "stat_p50_us", "host"),
            (
                "large_meta",
                "perf_large_meta",
                "large_meta_total_us",
                "host",
            ),
            (
                "overlay_small_updates",
                "perf_overlay_small_updates",
                "overlay_small_updates_total_us",
                "memory",
            ),
        ];

        for (workload, probe, metric_key, carrick_fs_mode) in required {
            let case = CASES
                .iter()
                .find(|case| case.workload == workload)
                .unwrap_or_else(|| panic!("missing disk perf workload {workload}"));
            assert_eq!(case.dimension, "disk");
            assert_eq!(case.probe, probe);
            assert_eq!(case.metric_key, metric_key);
            assert_eq!(case.unit, "us");
            assert!(!case.higher_is_better);
            assert_eq!(case.carrick_fs_mode, carrick_fs_mode);
            assert!(!case.cross_boundary);
        }
    }

    #[test]
    fn registered_perf_probes_have_sources() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("carrick-cli lives under crates/");
        for case in CASES {
            let source = root
                .join("conformance-probes/src/bin")
                .join(format!("{}.rs", case.probe));
            assert!(
                source.exists(),
                "missing source for registered perf probe {} at {}",
                case.probe,
                source.display()
            );
        }
    }
}
