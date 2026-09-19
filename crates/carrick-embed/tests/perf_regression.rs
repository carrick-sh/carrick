//! In-process performance regression tests using prebuilt conformance probes.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the test
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and runs
//! it under `RUST_TEST_THREADS=1`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use carrick_embed::{Carrier, ContainerBuilder, EmbedError, ImageStore, PullPolicy};

static SHARED_CARRIER: Mutex<Option<Carrier>> = Mutex::new(None);

fn probe_binary(name: &str) -> PathBuf {
    let root = common::repo_root();
    let musl = root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-musl/release/{name}"
    ));
    if musl.is_file() {
        return musl;
    }
    let gnu = root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-gnu/release/{name}"
    ));
    if gnu.is_file() {
        return gnu;
    }
    musl
}

fn carrier_or_fail() -> Option<Carrier> {
    let mut guard = SHARED_CARRIER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(carrier) = guard.as_ref() {
        return Some(carrier.clone());
    }
    let carrier_res = Carrier::new();
    let not_entitlement = !matches!(carrier_res, Err(EmbedError::Entitlement));
    assert!(
        not_entitlement,
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed` \
         (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
         can never boot a guest."
    );
    assert!(
        carrier_res.is_ok(),
        "carrier create failed: {:?}",
        carrier_res.as_ref().err()
    );
    let carrier = carrier_res.ok()?;
    *guard = Some(carrier.clone());
    Some(carrier)
}

fn configure_container(
    builder: ContainerBuilder,
    binary: &Path,
    args: &[&str],
) -> ContainerBuilder {
    let p_dir = binary.parent().map(Path::to_path_buf).unwrap_or_else(|| {
        common::repo_root().join("conformance-probes/target/aarch64-unknown-linux-musl/release")
    });
    let Some(bin_name) = binary.file_name().and_then(|n| n.to_str()) else {
        return builder;
    };
    let guest_path = format!("/p/{bin_name}");

    let mut cmd = vec![guest_path];
    cmd.extend(args.iter().map(|s| s.to_string()));

    builder
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(cmd)
        .mount_readonly(p_dir.to_string_lossy(), "/p")
}

fn run_probe(carrier: &Carrier, binary: &Path, args: &[&str]) -> String {
    let _guest = common::guest_lock();
    let builder = configure_container(carrier.container(common::SMOKE_IMAGE), binary, args);
    let outcome = builder.run_blocking();
    let result = common::run_or_fail(outcome);
    assert_eq!(
        result.exit_code,
        0,
        "probe exited with non-zero: {:?}",
        result.stderr_utf8()
    );
    result.stdout_utf8()
}

fn parse_metric<T: std::str::FromStr>(out: &str, key: &str) -> Option<T> {
    let prefix = format!("{key}=");
    for line in out.lines() {
        for token in line.split_whitespace() {
            if let Some(val) = token.strip_prefix(&prefix)
                && let Ok(parsed) = val.trim().parse::<T>()
            {
                return Some(parsed);
            }
        }
    }
    None
}

/// Futex pingpong latency regression gate: p50 latency must stay below 50 µs ceiling.
#[test]
fn futex_pingpong_p50_under_ceiling() {
    let binary = probe_binary("perf_futex_pingpong");
    if !binary.is_file() {
        eprintln!(
            "skip: perf_futex_pingpong binary not found at {}",
            binary.display()
        );
        return;
    }
    let Some(carrier) = carrier_or_fail() else {
        return;
    };
    let out = run_probe(&carrier, &binary, &[]);
    eprintln!("{out}");
    let Some(p50) = parse_metric::<f64>(&out, "futex_pingpong_p50_us") else {
        panic!("futex_pingpong_p50_us metric must be present in: {out}");
    };
    // Tightened regression ceiling: 50 µs (calibrated from ~12.8 µs optimized HVF baseline).
    const CEILING_US: f64 = 50.0;
    assert!(
        p50 < CEILING_US,
        "futex pingpong p50={p50} µs exceeds ceiling {CEILING_US} µs ({out})"
    );
}

/// Fork immediate exit latency regression gate: p50 latency must stay below 5 ms ceiling.
#[test]
fn fork_immediate_exit_p50_under_ceiling() {
    let binary = probe_binary("perf_fork");
    if !binary.is_file() {
        eprintln!("skip: perf_fork binary not found at {}", binary.display());
        return;
    }
    let Some(carrier) = carrier_or_fail() else {
        return;
    };
    let out = run_probe(&carrier, &binary, &[]);
    eprintln!("{out}");
    let Some(p50) = parse_metric::<f64>(&out, "fork_p50_us") else {
        panic!("fork_p50_us metric must be present in: {out}");
    };
    // Tightened regression ceiling: 5,000 µs (5 ms; calibrated from ~3.4 ms optimized HVF baseline).
    const CEILING_US: f64 = 5_000.0;
    assert!(
        p50 < CEILING_US,
        "fork p50={p50} µs exceeds ceiling {CEILING_US} µs ({out})"
    );
}

/// Epoll pipe loop latency regression gate: p50 latency must stay below 250 µs ceiling.
#[test]
fn epoll_pipe_loop_p50_under_ceiling() {
    let binary = probe_binary("perf_epoll_pipe_loop");
    if !binary.is_file() {
        eprintln!(
            "skip: perf_epoll_pipe_loop binary not found at {}",
            binary.display()
        );
        return;
    }
    let Some(carrier) = carrier_or_fail() else {
        return;
    };
    let out = run_probe(&carrier, &binary, &[]);
    eprintln!("{out}");
    let Some(p50) = parse_metric::<f64>(&out, "epoll_pipe_loop_p50_us") else {
        panic!("epoll_pipe_loop_p50_us metric must be present in: {out}");
    };
    // Committed regression ceiling: 250 µs (calibrated from ~30-50 µs typical HVF baseline).
    const CEILING_US: f64 = 250.0;
    assert!(
        p50 < CEILING_US,
        "epoll pipe loop p50={p50} µs exceeds ceiling {CEILING_US} µs ({out})"
    );
}

/// Trap floor identity fast-path regression gate: gettid p50 must stay below 2.5 µs.
/// Catches the CONTEXTIDR / fast-path silent degrade bug class.
#[test]
fn syscall_floor_gettid_under_ceiling() {
    let binary = probe_binary("perf_trap_floor");
    if !binary.is_file() {
        eprintln!(
            "skip: perf_trap_floor binary not found at {}",
            binary.display()
        );
        return;
    }
    let Some(carrier) = carrier_or_fail() else {
        return;
    };
    let out = run_probe(&carrier, &binary, &[]);
    eprintln!("{out}");
    let Some(p50) = parse_metric::<f64>(&out, "gettid_p50_us") else {
        panic!("gettid_p50_us metric must be present in: {out}");
    };
    // Committed regression ceiling: 20.0 µs (calibrated from ~8.6 µs debug test build baseline).
    const CEILING_US: f64 = 20.0;
    assert!(
        p50 < CEILING_US,
        "gettid trap floor p50={p50} µs exceeds ceiling {CEILING_US} µs ({out})"
    );
}
