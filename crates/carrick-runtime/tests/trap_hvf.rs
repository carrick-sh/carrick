// Integration test: allow unwrap/expect file-wide, as the conformance
// integration test does.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// VM-FREE host-lane suite (run by `just test`): the HVF trap surface that
// `carrick_runtime::trap` re-exports under `platform-macos` — capability
// reporting, `GuestMappingPlan` page rounding, the AArch64 exception-class
// decoders and the EL1 vector layout — checked without creating a VM.
//
// Tests that boot a real vCPU live in `carrick-vmm-hvf/tests/trap_engine_hvf.rs`
// and run only from a SIGNED executable (`just test-hvf-trap-engine`), where
// `HV_DENIED` is a failure. Nothing here may call `new_hvf_trap_engine` or
// otherwise reach `hv_vm_create`: an unsigned test binary would get
// `HV_DENIED`, and a test that tolerates that is a test that never runs.
//
// Gate the whole file so the non-macOS cross-checks (`just check-freebsd`/
// `check-linux`, which build `--all-targets`) don't try to resolve those
// macOS-only symbols.
#![cfg(feature = "platform-macos")]

use carrick_runtime::elf::SegmentPerms;
use carrick_runtime::memory::{AddressSpace, LINUX_EL1_VECTORS_BASE};
use carrick_runtime::trap::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, GuestMappingPlan, HVF_PAGE_SIZE,
    TrapBackend, aarch64_exception_class, hvf_capabilities, is_aarch64_hvc_exception,
    is_aarch64_svc_exception, is_aarch64_syscall_exception,
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
