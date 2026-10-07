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
use carrick_mem::memory::{
    AddressSpace, IDENTITY_OFF_PID, IDENTITY_OFF_SHIM_ENABLED, LINUX_IDENTITY_PAGE_BASE,
};
use carrick_vmm_hvf::hvf_aarch64_engine::{
    HvfAarch64Vmm, HvpatchPersistentExecutorFactoryAuthority, attach_task_engine,
    persistent_executor_factory_authority, split_initial_task_engine,
};
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

// ---- EL1 identity fast path, end to end on a LIVE executor vCPU ----
//
// A root from `new_hvf_trap_engine` is STAGED: it holds registers as data and
// has no vCPU until its first executor load, so `next_syscall` on it fails
// ("a staged root has none until its first executor load"). Production loads
// it onto a persistent executor; `load_on_executor` performs that same public
// sequence (the one `el1_descriptor_service.rs` uses): snapshot the root's
// CPU, take the carrier's executor factory, split the root into task state,
// create the executor's live vCPU, attach, and overlay the root's CPU.
//
// The images are the production transport shape (`with_hvf_syscall_mailbox`
// in carrick-runtime): mailbox vectors, the identity page when the fast path
// is compiled in, the syscall mailbox arena, the carrier maintenance root and
// the fd-ceiling control page.

const PROBE_ENTRY: u64 = 0x10000; // low user VA (EL0-executable)
// movz x8,#172 ; svc #0 ; movz x8,#94 ; svc #0  (getpid then exit_group)
const GETPID_PROBE_CODE: [u32; 4] = [0xD280_1588, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];
// movz x8,#178 ; svc #0 ; movz x8,#94 ; svc #0  (gettid then exit_group)
const GETTID_PROBE_CODE: [u32; 4] = [0xD280_1648, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];

const SYS_GETPID: u64 = 172;
const SYS_GETTID: u64 = 178;
const SYS_EXIT_GROUP: u64 = 94;

fn probe_image(code: [u32; 4], identity_fast_path: bool) -> AddressSpace {
    let bytes: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
    let image = exec_segment(PROBE_ENTRY, bytes, 16)
        .with_el0_trampoline()
        .and_then(|a| a.with_el1_vectors_mailbox(identity_fast_path))
        .unwrap();
    let image = if identity_fast_path {
        image.with_identity_page().unwrap()
    } else {
        image
    };
    image
        .with_syscall_mailbox_arena()
        .and_then(|a| a.with_carrier_maintenance_root())
        .and_then(|a| a.with_fd_ceiling_control())
        .and_then(|a| a.with_stage1_page_tables())
        .and_then(|a| a.with_linux_initial_stack(vec!["t"], Vec::<&str>::new()))
        .unwrap()
}

/// A root loaded onto a live persistent-executor vCPU. The executor's
/// lifecycle half and the carrier factory stay alive as long as the engine.
struct LoadedEngine {
    engine: HvfTrapEngine,
    _lifecycle: HvfAarch64Vmm,
    _factory: HvpatchPersistentExecutorFactoryAuthority,
}

/// Production's first executor load, through its public steps.
fn load_on_executor(image: &AddressSpace) -> LoadedEngine {
    let mut staged = engine(image);
    let cpu = staged
        .snapshot_guest_state_for_publication()
        .expect("snapshot the staged root CPU");
    let factory =
        persistent_executor_factory_authority(&mut staged).expect("carrier executor factory");
    let (task, staged_cpu) = split_initial_task_engine(staged);
    drop(staged_cpu);
    let (mut lifecycle, vcpu) = factory
        .create_executor_parts()
        .expect("create the executor's live vCPU");
    let mut engine = attach_task_engine(task, &mut lifecycle, vcpu);
    engine
        .overlay_task_state_on_live_executor(&cpu)
        .expect("overlay the root CPU on the live executor");
    LoadedEngine {
        engine,
        _lifecycle: lifecycle,
        _factory: factory,
    }
}

/// Publish the process identity the way `identity_page::stamp_identity_values`
/// does: close the gate, write the pid, then set the gate to `gate`.
fn stamp_identity(engine: &mut HvfTrapEngine, pid: u32, gate: u32) {
    let base = LINUX_IDENTITY_PAGE_BASE;
    engine
        .write_bytes(base + IDENTITY_OFF_SHIM_ENABLED, &0_u32.to_le_bytes())
        .unwrap();
    engine
        .write_bytes(base + IDENTITY_OFF_PID, &pid.to_le_bytes())
        .unwrap();
    engine
        .write_bytes(base + IDENTITY_OFF_SHIM_ENABLED, &gate.to_le_bytes())
        .unwrap();
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_el1_shim_services_getpid_without_a_host_trap() {
    in_fresh_process(
        "trap_engine_hvf_el1_shim_services_getpid_without_a_host_trap",
        || {
            let mut loaded = load_on_executor(&probe_image(GETPID_PROBE_CODE, true));
            const SENTINEL_PID: u32 = 0xABCD;
            stamp_identity(&mut loaded.engine, SENTINEL_PID, 1);

            // The first host-visible trap must be exit_group, NOT getpid, and
            // x0 must carry the stamped pid: EL1 read the identity page and
            // returned it as the syscall result.
            let frame = loaded
                .engine
                .next_syscall()
                .unwrap()
                .expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                SYS_EXIT_GROUP,
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
fn trap_engine_hvf_closed_identity_gate_traps_getpid_to_the_host() {
    in_fresh_process(
        "trap_engine_hvf_closed_identity_gate_traps_getpid_to_the_host",
        || {
            // Same shim-capable vectors, gate closed (how observers and
            // interceptors keep identity calls visible): getpid MUST trap.
            let mut loaded = load_on_executor(&probe_image(GETPID_PROBE_CODE, true));
            stamp_identity(&mut loaded.engine, 0xABCD, 0);
            let frame = loaded
                .engine
                .next_syscall()
                .unwrap()
                .expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                SYS_GETPID,
                "a closed identity gate must trap getpid to the host"
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
            // Mailbox vectors without the identity fast path: getpid MUST trap.
            let mut loaded = load_on_executor(&probe_image(GETPID_PROBE_CODE, false));
            let frame = loaded
                .engine
                .next_syscall()
                .unwrap()
                .expect("guest must trap");
            assert_eq!(
                frame.number.raw(),
                SYS_GETPID,
                "without the shim, getpid must trap to the host"
            );
        },
    );
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_unseeded_gettid_traps_to_the_host() {
    in_fresh_process("trap_engine_hvf_unseeded_gettid_traps_to_the_host", || {
        // gettid has no vector-level answer: the TPIDR_EL1 handler was
        // deleted (8603357b2) and EL1 serves gettid only through the
        // lifecycle venue from a seeded thread control slot. A task with
        // no seeded slot, even with an open identity gate and a stamped
        // EL0 identity, must forward gettid to the host, never return a
        // made-up tid.
        let mut loaded = load_on_executor(&probe_image(GETTID_PROBE_CODE, true));
        stamp_identity(&mut loaded.engine, 0xABCD, 1);
        loaded.engine.set_guest_thread_id(0x4321).unwrap();
        let frame = loaded
            .engine
            .next_syscall()
            .unwrap()
            .expect("guest must trap");
        assert_eq!(
            frame.number.raw(),
            SYS_GETTID,
            "an unseeded gettid must trap to the host"
        );
    });
}
