//! Signed guest witness for the ring clock owner (#2618). The ARM root reads
//! time through its legacy policy and the vDSO; a fork child (a ring-owned
//! native task) reaches the ring through raw `clock_gettime` (REALTIME,
//! MONOTONIC, PROCESS_CPUTIME_ID), raw `gettimeofday` and raw `times`. Every
//! bound the probe prints must hold in the root and in the child.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::ResultAssert;

fn selected_probe_target() -> &'static str {
    let closure_mode = std::env::var("CARRICK_PROBE_MODE").as_deref() == Ok("closure");
    let libc = std::env::var("CARRICK_PROBE_SCENARIO_LIBC").ok();
    if !closure_mode {
        return "aarch64-unknown-linux-musl";
    }
    match libc.as_deref() {
        Some("musl") => "aarch64-unknown-linux-musl",
        Some("gnu") => "aarch64-unknown-linux-gnu",
        Some(value) => {
            panic!("invalid CARRICK_PROBE_SCENARIO_LIBC={value:?}; expected musl or gnu")
        }
        None => panic!("closure ring clock scenario requires CARRICK_PROBE_SCENARIO_LIBC"),
    }
}

#[test]
fn case_ring_clock_child_raw_syscalls() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let dir = root
        .join("conformance-probes/target")
        .join(selected_probe_target())
        .join("release");
    let binary = dir.join("ringclockchild");
    let init = dir.join("probeinit");
    assert!(
        binary.is_file() && init.is_file(),
        "missing ring clock probe: {} — run scripts/build-probes.sh",
        binary.display()
    );
    let container = common::generic_probe_container("ringclockchild", &binary, &init);
    let (result, _) = common::run_or_fail(common::with_empty_stdin_pipe(|| {
        container.run_with_audit(["/tmp/carrick-init"])
    }));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        concat!(
            "root_calls_ok=true\n",
            "root_realtime_unix=true\n",
            "root_gettimeofday_unix=true\n",
            "root_gettimeofday_matches_realtime=true\n",
            "root_burned=true\n",
            "root_monotonic_advances=true\n",
            "root_realtime_follows_monotonic=true\n",
            "root_cputime_advances=true\n",
            "root_cputime_within_wall=true\n",
            "root_times_cpu_advances=true\n",
            "root_times_elapsed_monotonic=true\n",
            "child_calls_ok=true\n",
            "child_realtime_unix=true\n",
            "child_gettimeofday_unix=true\n",
            "child_gettimeofday_matches_realtime=true\n",
            "child_burned=true\n",
            "child_monotonic_advances=true\n",
            "child_realtime_follows_monotonic=true\n",
            "child_cputime_advances=true\n",
            "child_cputime_within_wall=true\n",
            "child_times_cpu_advances=true\n",
            "child_times_elapsed_monotonic=true\n",
            "child_exit=0\n",
            "child_signal=none\n",
            "child_timeout=false\n",
        ),
        "stderr:\n{}",
        result.stderr_utf8()
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
