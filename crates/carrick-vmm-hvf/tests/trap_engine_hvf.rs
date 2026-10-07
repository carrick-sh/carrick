//! HVF trap-engine tests that boot a real vCPU. Run ONLY through the signed
//! runner: `just test-hvf-trap-engine` (scripts/test-signed.sh).
//!
//! These moved here from `carrick-runtime/tests/trap_hvf.rs`, where they
//! returned early ("self-skipped") whenever `new_hvf_trap_engine` failed — so
//! an unsigned `cargo test`, which always dies `HV_DENIED` (0xfae94007), reported
//! them as passing without executing a single guest instruction. The `gettid`
//! EL1 fast path regressed unnoticed behind that skip.
//!
//! The contract now, mirroring carrick-embed's `EmbedError::Entitlement`:
//! - every test is `#[ignore]`d, so a bare `cargo test` / `just test` never
//!   selects it; scripts/test-signed.sh selects it with `--ignored` after
//!   signing the executable with the hypervisor entitlement;
//! - `HV_DENIED` is a hard FAILURE with its own diagnosis, never a skip;
//! - any other bring-up error is a failure too;
//! - the package's negative control
//!   (`unsigned_executable_maps_hv_denied_to_entitlement`, in the lib tests)
//!   proves an unentitled copy of a carrick-vmm-hvf test executable gets
//!   `HV_DENIED`, so a signing regression cannot pass silently either way.
//!
//! Process isolation: the HVF engine leaks its VM until process exit (never
//! run applevisor's destructors), and a later bring-up in the same process
//! boots inside that carrier, which needs a published executor bundle these
//! bare engines never publish. Each test therefore re-executes this test
//! executable for exactly itself in a fresh child process (inheriting the
//! signed executable's entitlement) and requires the child to report exactly
//! one passed test.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_guest_mem::GuestMemory;
use carrick_hal::{SyscallTrap, ThreadedEngine};
use carrick_mem::elf::SegmentPerms;
use carrick_mem::memory::{AddressSpace, IDENTITY_OFF_PID, LINUX_IDENTITY_PAGE_BASE};
use carrick_vmm_hvf::trap::{
    HvfTrapEngine, TrapBackend, TrapError, hvf_capabilities, new_hvf_trap_engine,
};
use std::process::Command;

/// Set in the child process that actually runs a test body.
const CHILD_ENV: &str = "CARRICK_TRAP_ENGINE_HVF_CHILD";

/// `HV_DENIED` as applevisor renders it (`error {:#08x}`).
const HV_DENIED_CODE: &str = "0xfae94007";

/// True when `err` is Hypervisor.framework refusing the VM because this
/// executable lacks `com.apple.security.hypervisor`.
fn is_hv_denied(err: &TrapError) -> bool {
    let text = err.to_string();
    text.contains(HV_DENIED_CODE) || text.contains("HV_DENIED")
}

/// Bring up the engine or FAIL. There is no skip path.
fn engine(image: &AddressSpace) -> HvfTrapEngine {
    match new_hvf_trap_engine(image) {
        Ok(engine) => engine,
        Err(err) if is_hv_denied(&err) => panic!(
            "HV_DENIED ({HV_DENIED_CODE}): this test executable lacks the \
             com.apple.security.hypervisor entitlement. These tests run only via \
             `just test-hvf-trap-engine` (scripts/test-signed.sh); an unsigned run is \
             a failure, never a skip. Underlying error: {err}"
        ),
        Err(err) => panic!("HVF trap-engine bring-up failed: {err}"),
    }
}

/// Run `body` in a fresh child process (one VM per process). In the parent,
/// re-execute this executable for exactly `test_name` and require the child
/// to report one passed test; in the child, run the body.
fn in_fresh_process(test_name: &str, body: fn()) {
    if std::env::var_os(CHILD_ENV).is_some() {
        body();
        return;
    }
    let exe = std::env::current_exe().expect("resolve the running test executable");
    let output = Command::new(&exe)
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, "1")
        .env("RUST_TEST_THREADS", "1")
        .output()
        .expect("spawn the per-test child process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(
        output.status.success(),
        "{test_name} failed in its child process ({}): see output above",
        output.status
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "{test_name}: child process did not report exactly one passed test"
    );
}

fn exec_segment(entry: u64, code: Vec<u8>, size: u64) -> AddressSpace {
    AddressSpace::from_segments(
        entry,
        [(
            entry,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            code,
            size,
        )],
    )
    .unwrap()
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_bare_image_parks_vcpu_at_entry() {
    in_fresh_process("trap_engine_hvf_bare_image_parks_vcpu_at_entry", || {
        // `new_hvf_trap_engine` builds the VM+vCPU, maps the image and parks the
        // vCPU at its entry in one call. This bare image installs no EL0
        // trampoline, so the vCPU parks directly at `plan.entry` (0x4000).
        let image = exec_segment(0x4000, 0xd4200000_u32.to_le_bytes().to_vec(), 4);
        let engine = engine(&image);
        assert_eq!(hvf_capabilities().backend, TrapBackend::HypervisorFramework);
        assert_eq!(engine.program_counter().unwrap(), 0x4000);
    });
}

// ---- EL1 syscall-shim identity fast path (end-to-end on real HVF) ----
// These run a 4-instruction guest under a real vCPU. With the shim, the
// identity syscall is serviced entirely at EL1 and never reaches the host; the
// FIRST host-visible trap is `exit_group` (x8=94) carrying the result in x0.
// The legacy control proves the setup is honest: without the shim, `getpid`
// DOES trap.

const SHIM_PROBE_ENTRY: u64 = 0x10000; // low user VA (EL0-executable)
// movz x8,#172 ; svc #0 ; movz x8,#94 ; svc #0  (getpid then exit_group)
const GETPID_PROBE_CODE: [u32; 4] = [0xD280_1588, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];
// movz x8,#178 ; svc #0 ; movz x8,#94 ; svc #0  (gettid then exit_group)
const GETTID_PROBE_CODE: [u32; 4] = [0xD280_1648, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];

fn probe_image(code: [u32; 4], shim: bool) -> AddressSpace {
    let bytes: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
    let base = exec_segment(SHIM_PROBE_ENTRY, bytes, 16)
        .with_el0_trampoline()
        .unwrap();
    let base = if shim {
        base.with_el1_vectors_shim()
            .and_then(|a| a.with_identity_page())
            .unwrap()
    } else {
        base.with_el1_vectors().unwrap()
    };
    base.with_stage1_page_tables()
        .and_then(|a| a.with_linux_initial_stack(vec!["t"], Vec::<&str>::new()))
        .unwrap()
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_el1_shim_services_getpid_without_a_host_trap() {
    in_fresh_process(
        "trap_engine_hvf_el1_shim_services_getpid_without_a_host_trap",
        || {
            let mut engine = engine(&probe_image(GETPID_PROBE_CODE, true));
            // Boot-stamp the identity page exactly like the runtime does.
            const SENTINEL_PID: u32 = 0xABCD;
            engine
                .write_bytes(
                    LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_PID,
                    &SENTINEL_PID.to_le_bytes(),
                )
                .unwrap();

            // The first host-visible trap must be exit_group (94), NOT getpid
            // (172), and x0 must carry the stamped pid: the EL1 handler read the
            // identity page and returned it as the syscall result.
            let frame = engine.next_syscall().unwrap().expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                94,
                "getpid (172) must NOT reach the host; first trap is exit_group"
            );
            assert_eq!(
                frame.args[0] & 0xFFFF_FFFF,
                u64::from(SENTINEL_PID),
                "fast-path getpid must return the stamped identity-page pid"
            );
        },
    );
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_legacy_vectors_trap_getpid_to_the_host() {
    in_fresh_process(
        "trap_engine_hvf_legacy_vectors_trap_getpid_to_the_host",
        || {
            // Same guest, legacy vectors (no shim): getpid MUST trap first.
            let mut engine = engine(&probe_image(GETPID_PROBE_CODE, false));
            let frame = engine.next_syscall().unwrap().expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                172,
                "without the shim, getpid must trap to the host"
            );
        },
    );
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_el1_shim_services_gettid_from_tpidr_el1() {
    in_fresh_process(
        "trap_engine_hvf_el1_shim_services_gettid_from_tpidr_el1",
        || {
            // gettid (178) is serviced at EL1 from the per-vCPU TPIDR_EL1 tid,
            // stamped through `ThreadedEngine::set_guest_thread_id` (the
            // `Aarch64Vcpu::stamp_guest_thread_id` seam; HVF writes TPIDR_EL1).
            let mut engine = engine(&probe_image(GETTID_PROBE_CODE, true));
            const SENTINEL_TID: u64 = 0x4321;
            engine.set_guest_thread_id(SENTINEL_TID).unwrap();

            let frame = engine.next_syscall().unwrap().expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                94,
                "gettid (178) must be serviced at EL1; first host trap is exit_group"
            );
            assert_eq!(
                frame.args[0], SENTINEL_TID,
                "fast-path gettid must return the per-vCPU TPIDR_EL1 tid stamped via \
                 the stamp_guest_thread_id seam"
            );
        },
    );
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_el1_shim_gettid_guard_traps_when_tpidr_el1_unstamped() {
    in_fresh_process(
        "trap_engine_hvf_el1_shim_gettid_guard_traps_when_tpidr_el1_unstamped",
        || {
            // TPIDR_EL1 left 0: the cbz guard must fall through to the host
            // trap rather than return a wrong gettid == 0.
            let mut engine = engine(&probe_image(GETTID_PROBE_CODE, true));
            let frame = engine.next_syscall().unwrap().expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                178,
                "unstamped TPIDR_EL1 must trap gettid to the host (cbz guard), not return 0"
            );
        },
    );
}
