//! M2-runtime proof: a static x86_64 Linux ELF runs natively on FreeBSD/amd64
//! through the REAL `SyscallDispatcher` (the same dispatcher the bhyve/KVM x86
//! VMM lanes feed) — NO VMM.
//!
//! Unlike the `carrick-dsr-x86` in-crate tests (which service syscalls with a
//! throwaway in-test servicer), this drives the production
//! `runtime::run_elf_native_dispatch` entry: it builds the real dispatcher
//! (`make_linux_dispatcher`), loads the ELF via `native_freebsd`, translates
//! it through the gateway, and routes `write`/`exit_group` through the real
//! dispatcher. The guest's stdout is captured in the dispatcher's buffer and
//! surfaced in `RunResult.stdout`. The guest is the checked-in no_std
//! static-pie fixture (source
//! `crates/carrick-dsr-x86/tests/fixtures/tinyguest.rs`).
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

fn host_avx512_xstate_enabled() -> bool {
    let leaf1 = std::arch::x86_64::__cpuid(1);
    if leaf1.ecx & (1 << 27) == 0 {
        return false;
    }
    // SAFETY: OSXSAVE above makes XGETBV(0) available.
    let xcr0 = unsafe { std::arch::x86_64::_xgetbv(0) };
    xcr0 & 0xe6 == 0xe6 && std::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 16) != 0
}

#[test]
fn native_backend_enters_dynamic_interpreter_with_linux_auxv() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/dynamic-main-x86_64-linux"
    );
    let interpreter = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/dynamic-interpreter-x86_64-linux"
    );
    let root = tempfile::tempdir().expect("dynamic fixture root");
    std::fs::create_dir(root.path().join("lib")).expect("fixture lib directory");
    std::fs::copy(
        interpreter,
        root.path().join("lib/carrick-dynamic-interpreter"),
    )
    .expect("install fixture interpreter");
    let prior_root = std::env::var_os("CARRICK_NATIVE_ROOTFS");
    // SAFETY: this integration binary's native runs are process-serialized by
    // the backend; the temporary root remains alive until the run returns.
    unsafe { std::env::set_var("CARRICK_NATIVE_ROOTFS", root.path()) };
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref());
    match prior_root {
        Some(value) => unsafe { std::env::set_var("CARRICK_NATIVE_ROOTFS", value) },
        None => unsafe { std::env::remove_var("CARRICK_NATIVE_ROOTFS") },
    }
    let result = result.expect("native x86 dynamic ELF must enter PT_INTERP");

    assert_eq!(result.exit_code, 23, "interpreter validated the entry auxv");
    assert_eq!(result.stdout, b"dynamic-elf ok\n");
}

#[test]
fn sibling_exit_group_interrupts_indefinite_private_and_shared_futex_waits() {
    let fixtures = [
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-futex-x86_64-linux"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-shared-futex-x86_64-linux"
        ),
    ];

    for fixture in fixtures {
        assert!(
            std::path::Path::new(fixture).exists(),
            "fixture missing: {fixture}"
        );
        let start = std::time::Instant::now();
        let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
            .expect("a sibling exit_group must release the initial futex waiter");

        assert_eq!(
            result.exit_code, 37,
            "the sibling's process-wide exit status must win for {fixture}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "exit_group must not wait for {fixture}'s infinite futex park"
        );
    }
}

#[test]
fn immediate_child_exit_group_does_not_deadlock_clone_publication() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-immediate-x86_64-linux"
    );
    for iteration in 0..16 {
        let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
            .expect("an immediate child exit_group must not join its waiting parent");
        assert_eq!(
            result.exit_code, 37,
            "child exit status on iteration {iteration}"
        );
    }
}

#[test]
fn native_service_fork_multithread_helper() {
    if std::env::var_os("CARRICK_NATIVE_SERVICE_FORK_MT_HELPER").is_none() {
        return;
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/native-service-fork-multithread-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("multithreaded service_fork fixture must complete");
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, b"native-service-fork-multithread ok\n");
}

#[test]
fn service_fork_repeats_while_guest_worker_uses_syscalls_and_waits() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/native-service-fork-multithread-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory multithreaded fork fixture missing: {fixture}"
    );

    let mut child =
        std::process::Command::new(std::env::current_exe().expect("native integration test path"))
            .args([
                "--exact",
                "native_service_fork_multithread_helper",
                "--nocapture",
            ])
            .env("CARRICK_NATIVE_SERVICE_FORK_MT_HELPER", "1")
            .spawn()
            .expect("launch bounded multithreaded service_fork helper");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll native fork helper") {
            assert!(status.success(), "native fork helper failed: {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("multithreaded service_fork fixture exceeded 10 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

#[test]
fn native_fork_child_output_helper() {
    if std::env::var_os("CARRICK_NATIVE_FORK_OUTPUT_HELPER").is_none() {
        return;
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/fork-child-sibling-exitgroup-output-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("fork child sibling exit_group must complete");
    assert_eq!(result.exit_code, 0);
}

#[test]
fn fork_child_sibling_exit_group_flushes_buffered_output() {
    let output =
        std::process::Command::new(std::env::current_exe().expect("integration test path"))
            .args(["--exact", "native_fork_child_output_helper", "--nocapture"])
            .env("CARRICK_NATIVE_FORK_OUTPUT_HELPER", "1")
            .output()
            .expect("launch isolated stdout-capturing helper");

    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let marker = b"fork-child-output\n";
    assert!(
        output
            .stdout
            .windows(marker.len())
            .any(|window| window == marker),
        "fork child output was lost: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == 0).count(),
        131_072,
        "fork child output was truncated by a partial host write"
    );
}

#[test]
fn native_xstate_chain_helper() {
    let Some(mode) = std::env::var_os("CARRICK_NATIVE_XSTATE_CHAIN_HELPER") else {
        return;
    };
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/xstate-chain-boundary-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("xstate chain fixture must complete");
    if mode == "unsafe" {
        assert_ne!(
            result.exit_code, 37,
            "local-only gating must remain a red negative control"
        );
    } else {
        assert_eq!(result.exit_code, 37, "guest xmm0 must survive the chain");
    }
}

#[test]
fn xstate_edge_barrier_isolates_the_unsafe_transitive_chain() {
    let run = |mode: &str, policy: Option<&str>, barrier: bool| {
        let mut command = std::process::Command::new(
            std::env::current_exe().expect("native integration test path"),
        );
        command
            .args(["--exact", "native_xstate_chain_helper", "--nocapture"])
            .env("CARRICK_NATIVE_XSTATE_CHAIN_HELPER", mode);
        if let Some(policy) = policy {
            command.env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy);
        } else {
            command.env_remove("CARRICK_NATIVE_X86_XSTATE_POLICY");
        }
        if barrier {
            command.env("CARRICK_NATIVE_X86_EDGE_BARRIER", "0x20114d->0x201138");
        }
        let output = command.output().expect("launch xstate chain helper");
        assert!(
            output.status.success(),
            "xstate helper {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run("conservative", None, false);
    run("unsafe", Some("unsafe-local-diagnostic"), false);
    run("barrier", Some("unsafe-local-diagnostic"), true);
    run("neutral-domains", Some("neutral-domains"), false);
}

#[test]
fn exit_group_asynchronously_kicks_a_sibling_spinning_in_jit_code() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-busy-x86_64-linux"
    );
    let start = std::time::Instant::now();
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("exit_group must kick a sibling with no syscall boundary");

    assert_eq!(result.exit_code, 0);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "a chained JIT spin must not hide process exit"
    );
}

#[test]
fn native_return_cache_helper() {
    if std::env::var_os("CARRICK_NATIVE_RETURN_CACHE_HELPER").is_none() {
        return;
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/return-cache-loop-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("return-cache loop must run natively");
    assert_eq!(result.exit_code, 37);
}

#[test]
fn monomorphic_returns_avoid_rust_round_trips_in_both_xstate_policies() {
    for policy in ["conservative", "neutral-domains"] {
        let output =
            std::process::Command::new(std::env::current_exe().expect("integration test path"))
                .args(["--exact", "native_return_cache_helper", "--nocapture"])
                .env("CARRICK_NATIVE_RETURN_CACHE_HELPER", "1")
                .env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy)
                .output()
                .expect("launch isolated return-cache helper");
        assert!(
            output.status.success(),
            "return-cache helper failed under {policy}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn instruction_fetch_faults_preserve_exact_boundary_and_retry() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/instruction-fetch-retry-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory instruction-fetch retry fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("checked instruction-fetch SIGSEGV/SIGBUS handlers must repair and retry");
    assert_eq!(
        result.exit_code, 0,
        "ACCERR mprotect, MAPERR fixed-map, and BUS_ADRERR backing repairs must each retry exactly"
    );
    assert_eq!(result.stdout, b"instruction-fetch retry ok\n");
    assert_eq!(
        result.traps, 23,
        "three exact signal repairs plus setup, success write, and exit_group"
    );
}

#[test]
fn blocked_instruction_fetch_sigsegv_never_enters_handler() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/blocked-instruction-fetch-segv-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory blocked instruction-fetch fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("blocked instruction-fetch SIGSEGV must terminate as a guest fault");
    assert_eq!(
        result.exit_code,
        128 + libc::SIGSEGV,
        "blocked synchronous fetch fault must terminate instead of entering its handler"
    );
    assert_eq!(
        result.traps, 5,
        "blocked fetch setup and fatal boundary receipt"
    );
}

/// An RX `MAP_SHARED` view is mutable even without write permission on that
/// VMA. Exercise all mutation paths that bypass the executable view's local
/// write hooks: a second RW mapping, positional I/O, and a synchronized fork
/// child. The checked fixture calls the same shared function after every
/// mutation, so any retained block, incoming edge, cflow plan, or return-cache
/// state can expose stale code.
#[test]
fn shared_executable_mappings_remain_permanently_ephemeral() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/shared-exec-mutation-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory shared-executable fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("shared executable mutation fixture must complete");
    assert_eq!(
        result.exit_code, 0,
        "second-view, pwrite, and fork-child mutations must all be observed"
    );
}

#[test]
fn cflow_call_stack_write_and_bus_faults_retry_exactly_once() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/cflow-call-stack-write-fault-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory cflow CALL retry fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("CALL stack-write SIGSEGV/SIGBUS handlers must repair and retry each instruction");
    assert_eq!(
        result.exit_code, 0,
        "anonymous ACCERR and truncated MAP_SHARED BUS_ADRERR calls must each retry exactly once"
    );
    assert_eq!(
        result.traps, 13,
        "setup + two signal repairs/returns + shared-file truncate/regrow + exit_group"
    );
}

#[test]
fn cflow_indirect_target_read_fault_retries_exactly_once() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/cflow-indirect-target-read-fault-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory cflow indirect-target retry fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("indirect target-read SIGSEGV handler must repair and retry the instruction");
    assert_eq!(
        result.exit_code, 0,
        "indirect CALL and RET target reads must each fault and retry exactly once"
    );
    assert_eq!(
        result.traps, 12,
        "setup + two munmaps + two handler mmap/mprotect repairs + two sigreturns + exit_group"
    );
}

#[test]
fn non_rex_x87_selectors_round_trip_and_survive_signal_frames() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/x87-selectors-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory x87 selector fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("virtual non-REX FCS/FDS fixture must complete");
    assert_eq!(
        result.exit_code, 0,
        "selector fixture stderr bytes: {:02x?}",
        result.stderr
    );
    assert_eq!(result.stdout, b"x87-selectors ok\n");
    assert_eq!(
        result.traps, 5,
        "rt_sigaction, tgkill, rt_sigreturn, success write, and exit_group"
    );
}

#[test]
fn legacy_x87_and_fxsave_transfers_are_checked_under_both_xstate_policies() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/legacy-x87-state-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory legacy x87 fixture missing: {fixture}"
    );
    for policy in ["conservative", "neutral-domains"] {
        let output =
            std::process::Command::new(std::env::current_exe().expect("native test executable"))
                .args(["--exact", "legacy_x87_state_helper", "--nocapture"])
                .env("CARRICK_LEGACY_X87_STATE_HELPER", "1")
                .env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy)
                .output()
                .expect("launch isolated legacy x87 fixture");
        assert!(
            output.status.success(),
            "legacy x87 fixture failed under {policy}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn legacy_x87_state_helper() {
    if std::env::var_os("CARRICK_LEGACY_X87_STATE_HELPER").is_none() {
        return;
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/legacy-x87-state-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("checked legacy x87 fixture must complete");
    assert_eq!(result.exit_code, 0, "stderr: {:02x?}", result.stderr);
    assert_eq!(result.stdout, b"legacy-x87-state ok\n");
    assert_eq!(result.traps, 2, "success write plus exit_group only");
}

#[test]
fn fxstate_memory_faults_and_invalid_mxcsr_retry_under_both_policies() {
    for policy in ["conservative", "neutral-domains"] {
        let output =
            std::process::Command::new(std::env::current_exe().expect("native test executable"))
                .args(["--exact", "fxstate_retry_helper", "--nocapture"])
                .env("CARRICK_FXSTATE_RETRY_HELPER", "1")
                .env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy)
                .output()
                .expect("launch isolated FXSAVE-family retry fixture");
        assert!(
            output.status.success(),
            "FXSAVE-family retry fixture failed under {policy}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn fxstate_retry_helper() {
    if std::env::var_os("CARRICK_FXSTATE_RETRY_HELPER").is_none() {
        return;
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/fxstate-retry-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("checked FXSAVE-family retry fixture must complete");
    assert_eq!(result.exit_code, 0, "stderr: {:02x?}", result.stderr);
    assert_eq!(result.stdout, b"fxstate-retry ok\n");
    assert_eq!(result.traps, 18, "setup, repairs, sigreturns, write, exit");
}

#[test]
fn native_xrstor_restores_requested_state_and_preserves_unrequested_state() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/xrstor-state-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory XRSTOR state fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("checked XRSTOR state fixture must complete");
    let expected = if host_avx512_xstate_enabled() { 37 } else { 38 };
    assert_eq!(
        result.exit_code, expected,
        "requested x87/YMM restore, absent-SSE MXCSR/XMM initialization, and host-available K/ZMM preservation"
    );
    assert_eq!(result.traps, 1, "only exit_group enters syscall dispatch");
}

#[test]
fn native_xrstor_faults_deliver_exact_retryable_memory_signal_frames() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/xrstor-retry-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory XRSTOR retry fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref()).expect(
        "XRSTOR handlers must repair protected, unmapped, file-backing, malformed-header, and alignment faults",
    );
    assert_eq!(
        result.exit_code, 0,
        "each XRSTOR site must report one handler fault and continue after its successful rt_sigreturn retry"
    );
    assert_eq!(
        result.traps, 19,
        "setup + SIGBUS action + anonymous file map/truncation + two mapping repairs + five sigreturns + exit_group"
    );
}

#[test]
fn native_xsave_checked_fixture_helper() {
    let Some(which) = std::env::var_os("CARRICK_NATIVE_XSAVE_CHECKED_HELPER") else {
        return;
    };
    let (fixture, expected_exit, expected_traps) = if which == "roundtrip" {
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../carrick-dsr-x86/tests/fixtures/xsave-roundtrip-x86_64-linux"
            ),
            if host_avx512_xstate_enabled() { 37 } else { 38 },
            1,
        )
    } else if which == "retry" {
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../carrick-dsr-x86/tests/fixtures/xsave-retry-x86_64-linux"
            ),
            0,
            18,
        )
    } else {
        panic!("unknown checked XSAVE fixture: {which:?}");
    };
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory checked XSAVE fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("checked XSAVE fixture must complete through the production dispatcher");
    assert_eq!(
        result.exit_code, expected_exit,
        "{which:?} receipt must match host CPUID+XCR0 feature availability"
    );
    assert_eq!(
        result.traps, expected_traps,
        "{which:?} must retain its exact documented syscall-trap census"
    );
}

#[test]
fn native_xsave_checked_fixtures_pass_both_xstate_policies() {
    for policy in ["conservative", "neutral-domains"] {
        for fixture in ["roundtrip", "retry"] {
            let output =
                std::process::Command::new(std::env::current_exe().expect("integration test path"))
                    .args([
                        "--exact",
                        "native_xsave_checked_fixture_helper",
                        "--nocapture",
                    ])
                    .env("CARRICK_NATIVE_XSAVE_CHECKED_HELPER", fixture)
                    .env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy)
                    .output()
                    .expect("launch isolated checked XSAVE fixture");
            assert!(
                output.status.success(),
                "checked XSAVE {fixture} failed under {policy}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn native_xstate_policy_matrix_helper() {
    let Some(case) = std::env::var_os("CARRICK_NATIVE_XSTATE_POLICY_MATRIX_CASE") else {
        return;
    };
    match case.to_string_lossy().as_ref() {
        "xrstor-state" => native_xrstor_restores_requested_state_and_preserves_unrequested_state(),
        "xrstor-retry" => native_xrstor_faults_deliver_exact_retryable_memory_signal_frames(),
        "cflow-call" => cflow_call_stack_write_and_bus_faults_retry_exactly_once(),
        "cflow-indirect" => cflow_indirect_target_read_fault_retries_exactly_once(),
        "fetch-retry" => instruction_fetch_faults_preserve_exact_boundary_and_retry(),
        "fetch-blocked" => blocked_instruction_fetch_sigsegv_never_enters_handler(),
        "translated-blocked" => blocked_translated_code_sigsegv_never_enters_handler(),
        "fork-status" => post_fork_detached_thread_sync_fault_is_waited_as_signaled(),
        "signal-xstate" => native_signal_sigreturn_restores_complete_guest_xstate(),
        other => panic!("unknown xstate policy matrix case {other}"),
    }
}

#[test]
fn native_xstate_correctness_fixtures_pass_both_policies() {
    const CASES: [&str; 9] = [
        "xrstor-state",
        "xrstor-retry",
        "cflow-call",
        "cflow-indirect",
        "fetch-retry",
        "fetch-blocked",
        "translated-blocked",
        "fork-status",
        "signal-xstate",
    ];
    for policy in ["conservative", "neutral-domains"] {
        for case in CASES {
            let output =
                std::process::Command::new(std::env::current_exe().expect("native test path"))
                    .args([
                        "--exact",
                        "native_xstate_policy_matrix_helper",
                        "--nocapture",
                    ])
                    .env("CARRICK_NATIVE_XSTATE_POLICY_MATRIX_CASE", case)
                    .env("CARRICK_NATIVE_X86_XSTATE_POLICY", policy)
                    .output()
                    .expect("launch isolated xstate policy matrix case");
            assert!(
                output.status.success(),
                "xstate case {case} failed under {policy}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn blocked_translated_code_sigsegv_never_enters_handler() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/blocked-sync-segv-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory blocked synchronous-SIGSEGV fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("blocked synchronous SIGSEGV fixture must terminate as a guest fault");
    assert_eq!(
        result.exit_code,
        128 + libc::SIGSEGV,
        "blocked synchronous SIGSEGV must terminate instead of entering its handler"
    );
    assert_eq!(
        result.traps, 2,
        "signal setup plus blocked fatal fault receipt"
    );
}

#[test]
fn post_fork_detached_thread_sync_fault_is_waited_as_signaled() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/fork-detached-sync-segv-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).is_file(),
        "mandatory fork-detached synchronous-SIGSEGV fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("guest parent must reap the detached-thread faulting fork child");
    assert_eq!(
        result.exit_code, 0,
        "wait4 must report WIFSIGNALED/SIGSEGV for the fork descendant"
    );
    assert_eq!(result.traps, 3, "fork, wait4, and exit_group receipt");
}

#[test]
fn malformed_signal_xstate_trailer_forces_guest_sigsegv() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/signal-xstate-malformed-trailer-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("malformed rt_sigreturn frame must terminate only the guest");
    assert_eq!(
        result.exit_code,
        128 + libc::SIGSEGV,
        "invalid private trailer must follow Linux force_sigsegv"
    );
}

#[test]
fn native_signal_sigreturn_restores_complete_guest_xstate() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/signal-xstate-roundtrip-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("signal handler must return through a complete x86 XSAVE frame");
    let expected = if host_avx512_xstate_enabled() { 37 } else { 38 };
    assert_eq!(
        result.exit_code, expected,
        "x87/MXCSR/YMM/virtual-PKRU and available K/ZMM state must survive sync+async signal return"
    );
    assert_eq!(
        result.traps, 9,
        "signal setup, delivery, returns, and exit receipt"
    );
}

#[test]
fn disabled_cet_rdssp_preserves_destination_and_flags() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/rdssp-disabled-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("disabled-CET RDSSP compatibility fixture must run");
    assert_eq!(
        result.exit_code, 37,
        "RDSSPD/RDSSPQ must preserve their destinations and flags"
    );
    assert_eq!(result.traps, 1, "only exit_group enters syscall dispatch");
}

#[test]
fn arch_set_fs_zero_isolates_host_tls_while_nonzero_tls_still_works() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/fsbase-zero-isolation-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("ARCH_SET_FS zero isolation fixture must reach its guest handler");
    assert_eq!(
        result.exit_code, 0,
        "nonzero guest TLS must read correctly and zero FS must fault at guest address zero"
    );
    assert_eq!(
        result.traps, 5,
        "rt_sigaction, two arch_prctl calls, rt_sigreturn, and exit_group enter dispatch"
    );
}

#[test]
fn invalid_pkru_operands_deliver_gp_and_retry_after_handler_repair() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/pkru-invalid-retry-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("invalid PKRU operands must reach a repairable synchronous handler");
    assert_eq!(
        result.exit_code, 0,
        "RDPKRU/WRPKRU must retry after the handler clears saved ECX/EDX"
    );
    assert_eq!(
        result.traps, 4,
        "rt_sigaction, two rt_sigreturns, and exit_group enter dispatch"
    );
}

#[test]
fn native_pkru_is_virtualized_without_revoking_gateway_access() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/pkru-virtual-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("virtual WRPKRU/RDPKRU must not fault the host gateway");
    assert_eq!(result.exit_code, 37, "virtual PKRU round trip");
}

#[test]
fn native_identity_syscalls_chain_without_rust_traps() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/identity-loop-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("identity loop must run natively");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.traps, 1,
        "1000 getpid + 1000 gettid calls must stay in JIT; only exit_group traps"
    );
}

#[test]
fn native_identity_fast_path_disables_live_for_seccomp() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/identity-seccomp-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("allow-all seccomp identity fixture must run");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.traps, 23,
        "prctl + seccomp + 20 identity calls + exit_group must all dispatch"
    );
}

#[test]
fn native_backend_runs_a_static_x86_elf_through_the_real_dispatcher() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).exists(),
        "fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("native x86 run must succeed");

    assert_eq!(
        result.exit_code, 21,
        "exit_group(0+1+..+6) must round-trip the real dispatcher"
    );
    assert_eq!(
        result.stdout, b"native-elf ok\n",
        "the guest's write(1, ...) must be serviced by the real dispatcher"
    );
}

/// A REAL static-pie musl conformance probe runs to completion natively: full
/// musl startup (TLS via arch_prctl, PLT indirect calls, RIP-relative rodata),
/// a `brk`-grown heap backed by the reserved guest arena, its output written,
/// and a clean exit — all through the real dispatcher. `brkheapgrow` is chosen
/// because it exercises the brk/heap arena backing and exits 0 deterministically.
///
/// Skips (does not fail) when the prebuilt probe is absent — the probe corpus
/// is a build artifact under `conformance-probes/target`, present on the
/// FreeBSD rig but not guaranteed elsewhere.
#[test]
fn native_backend_runs_a_real_musl_probe_with_a_grown_heap() {
    let probe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance-probes/target/x86_64-unknown-linux-musl/release/brkheapgrow"
    );
    if !std::path::Path::new(probe).exists() {
        eprintln!("skipping: prebuilt musl probe not present ({probe})");
        return;
    }

    let result = carrick_runtime::runtime::run_elf_native_dispatch(probe.as_ref())
        .expect("real musl probe must run to completion natively");

    assert_eq!(
        result.exit_code,
        0,
        "brkheapgrow exits 0; stdout was {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("brk_initial_nonzero=true") && out.contains("brk_grow_32mib=true"),
        "musl brk/heap must work through the real dispatcher; got {out:?}"
    );
}

/// Terminal exec ownership must retire every old-image registration before
/// replacing mappings. Exercise both ownership directions from mandatory,
/// checked-in fixtures: main execs with busy workers, and a non-leader worker
/// execs while main stays in JIT code. Authoritative sources are
/// `conformance-probes/src/bin/execthreads.rs` and `execfromthread.rs`.
#[test]
fn terminal_exec_replaces_multithreaded_image_with_one_thread() {
    let probes = [
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../carrick-dsr-x86/tests/fixtures/exec-main-retires-siblings-x86_64-linux"
            ),
            "exec_stage2_reached=true",
            "exec_thread_count_is_one=true",
            None,
        ),
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../carrick-dsr-x86/tests/fixtures/exec-worker-retires-siblings-x86_64-linux"
            ),
            "exec_from_thread_stage2_reached=true",
            "exec_from_thread_count_is_one=true",
            Some("exec_from_thread_survivor_gettid_is_getpid=true"),
        ),
    ];

    for (probe, stage2, one_thread, survivor_identity) in probes {
        assert!(
            std::path::Path::new(probe).is_file(),
            "mandatory terminal exec fixture missing: {probe}"
        );
        let result = carrick_runtime::runtime::run_elf_native_dispatch(probe.as_ref())
            .expect("terminal exec probe must install its replacement image");
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert_eq!(
            result.exit_code, 0,
            "terminal exec probe failed for {probe}: {stdout}"
        );
        assert!(
            stdout.contains(stage2) && stdout.contains(one_thread),
            "terminal exec did not reach a single-threaded stage2 for {probe}: {stdout}"
        );
        if let Some(expected) = survivor_identity {
            assert!(
                stdout.contains(expected),
                "worker exec survivor lost tgid identity after stage2 clone for {probe}: {stdout}"
            );
        }
        assert!(
            !stdout.contains("replaced_image=false"),
            "old-image thread survived terminal exec for {probe}: {stdout}"
        );
    }
}

/// Direct-branch chaining, proven end-to-end: a `#![no_std]` guest runs a
/// 50-million-iteration PURE compute loop (no syscall inside the loop, only a
/// final `exit_group`) — source `crates/carrick-dsr-x86/tests/fixtures/
/// computeloop.rs`. Two assertions together prove chaining:
///
/// - `traps == 1`: the ONLY syscall is the final exit. The loop's conditional
///   back-edge executed natively in the JIT cache every iteration; without
///   chaining each of the 50M iterations would round-trip to Rust (and the
///   test would run for many seconds).
/// - `exit_code == 192`: the low byte of `sum(3*i + 1 for i in 0..50_000_000)`
///   — the loop's control flow, register state, and flags stayed correct
///   across the entire chain.
#[test]
fn direct_branch_chaining_runs_a_compute_loop_without_round_trips() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/computeloop-x86_64-linux"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: compute-loop fixture not present ({fixture})");
        return;
    }

    let start = std::time::Instant::now();
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("chained compute loop must run to completion");
    let elapsed = start.elapsed();

    assert_eq!(
        result.traps, 1,
        "a chained 50M-iteration loop makes ONE syscall (the final exit); \
         traps={} means the back-edge round-tripped to Rust",
        result.traps
    );
    assert_eq!(
        result.exit_code, 192,
        "sum(3i+1, i in 0..50M) mod 256 == 192 — chaining preserved the loop's result"
    );
    // Not a hard perf gate (CI variance), but a chained 50M-iteration loop is
    // sub-second here; unchained it is minutes. Flag a gross regression.
    assert!(
        elapsed.as_secs() < 20,
        "chained compute loop took {elapsed:?} — chaining likely broke"
    );
}

/// A REAL std Rust binary runs to completion natively: a `Vec` of computed
/// squares, iterators, and `println!` formatting (Debug of the Vec + a sum),
/// through the real dispatcher — source
/// `crates/carrick-dsr-x86/tests/fixtures/hello_std.rs`. Exercises full musl +
/// std startup (TLS via arch_prctl, signal/sigaltstack setup, brk/mmap heap,
/// RIP-relative rodata, PLT/indirect calls, a page-spanning instruction) and
/// the buffered-stdout write path. This is the "Rust ecosystem runs natively"
/// end-to-end proof.
#[test]
fn native_backend_runs_a_real_std_rust_binary() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/hello-std-x86_64-linux"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: std Rust fixture not present ({fixture})");
        return;
    }

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("std Rust binary must run to completion natively");

    // exit(sum(n^2, n in 1..=10) % 256) = 385 % 256 = 129.
    assert_eq!(
        result.exit_code,
        129,
        "std Rust exit = 385 % 256 = 129; stdout was {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("squares=[1, 4, 9, 16, 25, 36, 49, 64, 81, 100]") && out.contains("sum=385"),
        "std Rust println! formatting must work through the dispatcher; got {out:?}"
    );
}
