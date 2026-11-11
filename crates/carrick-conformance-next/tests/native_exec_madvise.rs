//! Signed guest witness for ARM native-child `madvise(MADV_DONTNEED)` (#1846).
//! A fork child `execve`s the probe again, so the new image is a ring-owned
//! native task. It discards private anonymous RW, V8 code-range (reserved,
//! committed RW, written, RX, called) and RWX ranges; Linux returns 0, keeps
//! each mapping's protection and reads the discarded pages back as zero.
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
        None => panic!("closure native madvise scenario requires CARRICK_PROBE_SCENARIO_LIBC"),
    }
}

#[test]
fn case_native_exec_child_madvise_dontneed_discards() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let dir = root
        .join("conformance-probes/target")
        .join(selected_probe_target())
        .join("release");
    let binary = dir.join("nativeexecmadvise");
    let init = dir.join("probeinit");
    assert!(
        binary.is_file() && init.is_file(),
        "missing native madvise probe: {} — run scripts/build-probes.sh",
        binary.display()
    );
    let container = common::generic_probe_container("nativeexecmadvise", &binary, &init);
    let (result, _) = common::run_or_fail(common::with_empty_stdin_pipe(|| {
        container.run_with_audit(["/tmp/carrick-init"])
    }));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    // Native Linux oracle: the same source on a real Linux kernel prints
    // exactly these lines (errno 22 is EINVAL).
    assert_eq!(
        result.stdout_utf8(),
        concat!(
            "rw_madvise_ret=0\n",
            "rw_madvise_errno=0\n",
            "rw_zero_after_discard=true\n",
            "rw_rewrite_kept=true\n",
            "code_commit_rw_ret=0\n",
            "code_commit_rw_errno=0\n",
            "code_rx_ret=0\n",
            "code_rx_errno=0\n",
            "code_first_call=4660\n",
            "code_madvise_ret=0\n",
            "code_madvise_errno=0\n",
            "code_zero_after_discard=true\n",
            "code_recommit_rw_ret=0\n",
            "code_recommit_rw_errno=0\n",
            "code_recommit_rx_ret=0\n",
            "code_recommit_rx_errno=0\n",
            "code_recommit_call=22136\n",
            "rwx_first_call=8738\n",
            "rwx_madvise_ret=0\n",
            "rwx_madvise_errno=0\n",
            "rwx_zero_after_discard=true\n",
            "rwx_rewrite_call=13107\n",
            "misaligned_madvise_ret=-1\n",
            "misaligned_madvise_errno=22\n",
            "child_exit=0\n",
            "child_signal=none\n",
            "child_timeout=false\n",
        ),
        "stderr:\n{}",
        result.stderr_utf8()
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
