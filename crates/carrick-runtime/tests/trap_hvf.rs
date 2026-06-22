// Integration test: non-`#[test]` helpers (image builders / engine setup) aren't
// covered by clippy's allow-unwrap-in-tests heuristic, so allow unwrap/expect
// file-wide here, as the conformance integration test does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_runtime::elf::SegmentPerms;
use carrick_runtime::memory::{AddressSpace, LINUX_EL1_VECTORS_BASE};
// `program_counter()` and `set_guest_thread_id()` are methods on the
// `ThreadedEngine` trait (the shared `Aarch64EngineCore` implements it); bring the
// trait into scope so they resolve on the engine value.
use carrick_hal::ThreadedEngine;
use carrick_runtime::trap::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, GuestMappingPlan, HVF_PAGE_SIZE,
    HvfTrapEngine, TrapBackend, aarch64_exception_class, hvf_capabilities,
    is_aarch64_hvc_exception, is_aarch64_svc_exception, is_aarch64_syscall_exception,
    new_hvf_trap_engine,
};

#[test]
fn hvf_capabilities_report_compiled_backend() {
    let caps = hvf_capabilities();

    assert_eq!(caps.backend, TrapBackend::HypervisorFramework);
    assert_eq!(
        caps.available_on_this_host,
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    );
    assert_eq!(
        caps.implemented,
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    );
}

#[test]
fn guest_mapping_plan_rounds_regions_to_pages() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x210120,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            vec![0xaa; 40],
            40,
        )],
    )
    .unwrap();

    let plan = GuestMappingPlan::from_address_space(&image).unwrap();

    assert_eq!(plan.entry, 0x1000);
    assert_eq!(plan.mappings.len(), 1);
    assert_eq!(plan.mappings[0].guest_start, 0x210000);
    assert_eq!(plan.mappings[0].offset_in_mapping, 0x120);
    assert_eq!(plan.mappings[0].mapped_size, HVF_PAGE_SIZE);
    assert_eq!(plan.mappings[0].payload_size, 40);
    assert!(plan.mappings[0].perms.execute);
}

#[test]
fn guest_mapping_plan_carries_initial_stack_pointer() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x1000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            vec![0xd4, 0x20, 0x00, 0x00],
            4,
        )],
    )
    .unwrap()
    .with_linux_initial_stack(["/bin/echo".to_owned()], std::iter::empty::<String>())
    .unwrap();

    let plan = GuestMappingPlan::from_address_space(&image).unwrap();

    assert_eq!(plan.initial_stack_pointer, image.initial_stack_pointer());
    assert_eq!(plan.mappings.len(), 2);
}

#[test]
fn classifies_aarch64_svc_exception_syndrome() {
    let svc_syndrome = AARCH64_SVC_EXCEPTION_CLASS << 26;
    let brk_syndrome = 0x3c_u64 << 26;

    assert_eq!(
        aarch64_exception_class(svc_syndrome),
        AARCH64_SVC_EXCEPTION_CLASS
    );
    assert!(is_aarch64_svc_exception(svc_syndrome));
    assert!(!is_aarch64_svc_exception(brk_syndrome));
}

#[test]
fn classifies_aarch64_hvc_exception_syndrome_as_syscall() {
    let hvc_syndrome = AARCH64_HVC_EXCEPTION_CLASS << 26;
    let svc_syndrome = AARCH64_SVC_EXCEPTION_CLASS << 26;
    let brk_syndrome = 0x3c_u64 << 26;

    assert!(is_aarch64_hvc_exception(hvc_syndrome));
    assert!(!is_aarch64_hvc_exception(svc_syndrome));
    // The trap engine treats SVC (from EL0) and HVC (from our EL1 vector
    // re-trap) as the same syscall-shaped trap.
    assert!(is_aarch64_syscall_exception(svc_syndrome));
    assert!(is_aarch64_syscall_exception(hvc_syndrome));
    assert!(!is_aarch64_syscall_exception(brk_syndrome));
}

#[test]
fn with_el1_vectors_installs_hvc_then_eret_at_lower_el_sync_slot() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x1000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            vec![0xd4, 0x20, 0x00, 0x00],
            4,
        )],
    )
    .unwrap()
    .with_el1_vectors()
    .unwrap();

    assert_eq!(image.el1_vectors_base(), Some(LINUX_EL1_VECTORS_BASE));

    let region = image
        .regions()
        .iter()
        .find(|r| r.start == LINUX_EL1_VECTORS_BASE)
        .expect("EL1 vector region must be present");
    // Lower-EL/AArch64 synchronous slot is at offset 0x400. We expect
    // `hvc #2` (0xd4000042) followed by `eret` (0xd69f03e0), both stored
    // little-endian.
    let bytes = region.bytes();
    assert_eq!(
        &bytes[0x400..0x408],
        &[0x42, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x9f, 0xd6],
    );
    // Slot 0x000 ("Current EL with SP0, sync") now issues `hvc #3` (0xd4000062),
    // NOT a bare `eret`. carrick's guest only runs at EL0, so a synchronous
    // exception taken WHILE AT EL1 (i.e. in the EL1 vector trampoline) is always
    // carrick state corruption; the slot fail-louds with `hvc #3` so the host sees
    // ESR/ELR/FAR instead of the old bare `eret` that silently re-faulted at 100%
    // CPU forever. (Verified non-test layout — see carrick-mem `memory.rs`
    // `AARCH64_HVC_FAULT_OPCODE` / the current-EL sync vector slots.)
    assert_eq!(&bytes[0x000..0x004], &[0x62, 0x00, 0x00, 0xd4]);
}

#[test]
fn hvf_engine_constructor_is_real_or_platform_gated() {
    // The shared engine has no standalone `new()`; `new_hvf_trap_engine` builds
    // the VM+vCPU AND maps the image AND parks at the EL0 trampoline in one call,
    // so it needs *some* image to construct. Use a minimal one-page executable
    // segment (the same shape as `hvf_engine_maps_address_space_*`).
    let image = AddressSpace::from_segments(
        0x4000,
        [(
            0x4000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            0xd4200000_u32.to_le_bytes().to_vec(),
            4,
        )],
    )
    .unwrap();

    match new_hvf_trap_engine(&image) {
        Ok(_engine) => {
            // Backend identity is no longer observable off the engine itself
            // (post-consolidation onto `Aarch64EngineCore`); assert it via the
            // free `hvf_capabilities()` reporter instead of the old
            // `engine.backend()`.
            assert_eq!(hvf_capabilities().backend, TrapBackend::HypervisorFramework);
        }
        Err(err) => {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                // On macOS/aarch64 the only legitimate failure is at the
                // hypervisor layer — most commonly `HV_DENIED` (0xfae94007) when
                // the test binary is UNSIGNED (lacks the hypervisor entitlement),
                // i.e. the self-skip case. The shared bring-up surfaces every such
                // failure as `TrapError::Hypervisor(_)`, which Displays as
                // "hypervisor operation failed: …" (the old standalone
                // `HvfTrapEngine::new()` message that mentioned "Hypervisor.framework"
                // is gone with the consolidation).
                let message = err.to_string();
                assert!(
                    message.contains("hypervisor operation failed"),
                    "unexpected HVF error: {message}"
                );
            } else {
                assert!(err.to_string().contains("only available"));
            }
        }
    }
}

#[test]
fn hvf_engine_maps_address_space_when_backend_is_available() {
    let image = AddressSpace::from_segments(
        0x4000,
        [(
            0x4000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            0xd4200000_u32.to_le_bytes().to_vec(),
            4,
        )],
    )
    .unwrap();

    // `new_hvf_trap_engine` now builds the VM+vCPU, maps the image, and parks the
    // vCPU at its entry in one call (there is no separate `map_address_space`).
    let engine = match new_hvf_trap_engine(&image) {
        Ok(engine) => engine,
        Err(err) => {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                // Unsigned test binary (no hypervisor entitlement) -> HV_DENIED,
                // surfaced as `TrapError::Hypervisor` ("hypervisor operation
                // failed: …"); this is the self-skip case.
                assert!(
                    err.to_string().contains("hypervisor operation failed"),
                    "unexpected HVF error: {err}"
                );
            } else {
                assert!(err.to_string().contains("only available"));
            }
            return;
        }
    };

    // This bare image installs no EL0 trampoline, so the vCPU is parked directly
    // at `plan.entry` (== 0x4000); `program_counter()` reflects that.
    //
    // The old `engine.mapped_region_count()` assertion is dropped: region count is
    // no longer observable off the engine after the consolidation onto the shared
    // `Aarch64EngineCore` (the engine exposes no mapping-count accessor). The
    // GuestMappingPlan region-count itself is already covered by the
    // `guest_mapping_plan_*` tests above.
    assert_eq!(engine.program_counter().unwrap(), 0x4000);
}

// ---- EL1 syscall-shim identity fast path (end-to-end on real HVF) ----
// These run a 4-instruction guest — `getpid; exit_group` — under a real vCPU.
// With the shim, `getpid` (svc, x8=172) is serviced entirely at EL1 from the
// kernel-hole identity page and never reaches the host; the FIRST host-visible
// trap is `exit_group` (x8=94) carrying the stamped pid in x0. The legacy
// control proves the setup is honest: without the shim, `getpid` DOES trap.
// Self-skip (pass) when HVF isn't available, like the other engine tests.

const SHIM_PROBE_ENTRY: u64 = 0x10000; // low user VA (EL0-executable)
// movz x8,#172 ; svc #0 ; movz x8,#94 ; svc #0  (getpid then exit_group)
const SHIM_PROBE_CODE: [u32; 4] = [0xD280_1588, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];

fn shim_probe_code_bytes() -> Vec<u8> {
    SHIM_PROBE_CODE
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect()
}

// Build the engine FROM a fully-prepared image: `new_hvf_trap_engine` creates the
// VM+vCPU, maps the address space, and parks at the EL0 trampoline in one call
// (the old `HvfTrapEngine::new()` + `engine.map_address_space(&image)` two-step is
// gone). Returns `None` (a SKIP) when HVF is unavailable — same self-skip contract
// as the other engine tests.
fn shim_engine_or_skip(image: &AddressSpace) -> Option<HvfTrapEngine> {
    match new_hvf_trap_engine(image) {
        Ok(engine) => {
            eprintln!("[hvf-shim-test] RUN: engine created, executing guest");
            Some(engine)
        }
        // No usable HVF (CI Linux, or an unsigned macOS test binary lacking the
        // hypervisor entitlement) -> skip. Marker so a signed run can confirm the
        // assertions actually executed (not silently skipped). NOTE: HVF allows
        // ONE VM per process, so run these two tests in SEPARATE processes
        // (`--exact`) to exercise both — a shared `cargo test` run lets only the
        // first create a VM; the second skips.
        Err(_) => {
            eprintln!("[hvf-shim-test] SKIP: HVF engine unavailable");
            None
        }
    }
}

#[test]
fn el1_shim_services_getpid_at_el1_without_a_host_trap() {
    use carrick_runtime::dispatch::GuestMemory;
    use carrick_runtime::memory::{IDENTITY_OFF_PID, LINUX_IDENTITY_PAGE_BASE};
    use carrick_runtime::trap::SyscallTrap;

    let image = AddressSpace::from_segments(
        SHIM_PROBE_ENTRY,
        [(
            SHIM_PROBE_ENTRY,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            shim_probe_code_bytes(),
            16,
        )],
    )
    .unwrap()
    .with_el0_trampoline()
    .and_then(|a| a.with_el1_vectors_shim())
    .and_then(|a| a.with_identity_page())
    .and_then(|a| a.with_stage1_page_tables())
    .and_then(|a| a.with_linux_initial_stack(vec!["t"], Vec::<&str>::new()))
    .unwrap();

    let Some(mut engine) = shim_engine_or_skip(&image) else {
        return;
    };
    // Boot-stamp the identity page exactly like the runtime does.
    const SENTINEL_PID: u32 = 0xABCD;
    engine
        .write_bytes(
            LINUX_IDENTITY_PAGE_BASE + IDENTITY_OFF_PID,
            &SENTINEL_PID.to_le_bytes(),
        )
        .unwrap();

    // The first host-visible trap must be exit_group (94), NOT getpid (172):
    // getpid was answered at EL1. And x0 must carry the stamped pid, proving the
    // EL1 handler read the identity page and returned it in the syscall result.
    let frame = engine.next_syscall().unwrap().expect("guest must trap");
    assert_eq!(
        frame.number, 94,
        "getpid (172) must NOT reach the host; first trap is exit_group"
    );
    assert_eq!(
        frame.args[0] & 0xFFFF_FFFF,
        u64::from(SENTINEL_PID),
        "fast-path getpid must return the stamped identity-page pid"
    );
}

#[test]
fn el1_legacy_vectors_trap_getpid_to_the_host() {
    use carrick_runtime::trap::SyscallTrap;

    // Same guest, legacy vectors (no shim): getpid MUST trap to the host first.
    let image = AddressSpace::from_segments(
        SHIM_PROBE_ENTRY,
        [(
            SHIM_PROBE_ENTRY,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            shim_probe_code_bytes(),
            16,
        )],
    )
    .unwrap()
    .with_el0_trampoline()
    .and_then(|a| a.with_el1_vectors())
    .and_then(|a| a.with_stage1_page_tables())
    .and_then(|a| a.with_linux_initial_stack(vec!["t"], Vec::<&str>::new()))
    .unwrap();

    let Some(mut engine) = shim_engine_or_skip(&image) else {
        return;
    };
    let frame = engine.next_syscall().unwrap().expect("guest must trap");
    assert_eq!(
        frame.number, 172,
        "without the shim, getpid must trap to the host"
    );
}

// gettid (178) is per-thread: the EL1 handler reads TPIDR_EL1, which the runtime
// stamps with the thread's guest-visible tid. movz x8,#178 ; svc ; movz x8,#94 ; svc
const GETTID_PROBE_CODE: [u32; 4] = [0xD280_1648, 0xD400_0001, 0xD280_0BC8, 0xD400_0001];

fn gettid_probe_image(shim: bool) -> AddressSpace {
    let code: Vec<u8> = GETTID_PROBE_CODE
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();
    let base = AddressSpace::from_segments(
        SHIM_PROBE_ENTRY,
        [(
            SHIM_PROBE_ENTRY,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            code,
            16,
        )],
    )
    .unwrap()
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
fn el1_shim_services_gettid_from_tpidr_el1() {
    use carrick_runtime::trap::SyscallTrap;

    // gettid (178) is serviced at EL1 from the per-vCPU TPIDR_EL1 tid. On the
    // consolidated `Aarch64EngineCore`, `ThreadedEngine::set_guest_thread_id`
    // stamps that tid via the `Aarch64Vcpu::stamp_guest_thread_id` seam — HVF
    // writes TPIDR_EL1 (its `hvc` vehicle leaves it free), KVM no-ops it (its
    // sentinel vehicle uses TPIDR_EL1 as the live-x9 stash, so KVM traps gettid to
    // the host). This proves the HVF fast path: the FIRST host-visible trap must be
    // exit_group (94), NOT gettid — and x0 must carry the stamped tid, proving the
    // EL1 handler read TPIDR_EL1 and returned it as the syscall result.
    let image = gettid_probe_image(true);
    let Some(mut engine) = shim_engine_or_skip(&image) else {
        return;
    };
    // Stamp the per-vCPU tid exactly like the runtime does at thread setup.
    const SENTINEL_TID: u64 = 0x4321;
    engine.set_guest_thread_id(SENTINEL_TID).unwrap();

    let frame = engine.next_syscall().unwrap().expect("guest must trap");
    assert_eq!(
        frame.number, 94,
        "gettid (178) must be serviced at EL1; first host trap is exit_group"
    );
    assert_eq!(
        frame.args[0], SENTINEL_TID,
        "fast-path gettid must return the per-vCPU TPIDR_EL1 tid stamped via \
         the stamp_guest_thread_id seam"
    );
}

#[test]
fn el1_shim_gettid_guard_traps_when_tpidr_el1_unstamped() {
    use carrick_runtime::trap::SyscallTrap;

    // Do NOT stamp TPIDR_EL1 (left 0). The cbz guard must fall through to the
    // host trap rather than return a wrong gettid==0.
    let image = gettid_probe_image(true);
    let Some(mut engine) = shim_engine_or_skip(&image) else {
        return;
    };
    let frame = engine.next_syscall().unwrap().expect("guest must trap");
    assert_eq!(
        frame.number, 178,
        "unstamped TPIDR_EL1 must trap gettid to the host (cbz guard), not return 0"
    );
}
