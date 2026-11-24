//! The soft AArch64 carrier's stage-2 custody (#1236 slice D, M3): a soft
//! carrier brought up through the production entry
//! (`SoftAarch64Vmm::bring_up_with_executor`) holds a `Stage2Custody` over
//! its own `SoftStage2`, the same neutral custody HVF's carrier embeds.
//! A record published through it is the carrier's stage 2: a guest-physical
//! write through the carrier lands in the host page, and retiring the
//! record unmaps that window, after which the carrier refuses the address.
//!
//! Runs un-ignored on both x86_64 and aarch64 hosts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_aarch64::stage2::custody::{CarrierStage2RecordSpec, CarrierStage2RetireOutcome};
use carrick_aarch64::stage2::{STAGE2_PERM_READ, STAGE2_PERM_WRITE};
use carrick_hal::GuestVmBackend;
use carrick_mem::memory::{AddressSpace, El1IrqMode};
use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_softcpu_aarch64::state::CpuState;
use carrick_softcpu_aarch64::translate::TranslatedBlock;
use carrick_softcpu_aarch64_host::{GUEST_PAGE_BYTES, SoftAarch64Engine, SoftAarch64Vmm};

const CODE_VA: u64 = 0x0040_0000;
const A64_NOP: u32 = 0xd503_201f;
/// Far above every bring-up window and the alias range's first allocations.
const RECORD_IPA: u64 = 0xf0_0000_0000;

/// The witness never runs the vCPU; bring-up only needs an executor.
struct NoExecutor;

impl ExecuteBlock for NoExecutor {
    type Error = String;
    type Code = ();

    fn prepare(&mut self, _block: &TranslatedBlock) -> Result<(), Self::Error> {
        Err("the custody witness never runs the vCPU".to_owned())
    }

    fn execute(
        &mut self,
        _block: &TranslatedBlock,
        _code: &(),
        _cpu: &mut CpuState,
    ) -> Result<usize, Self::Error> {
        Err("the custody witness never runs the vCPU".to_owned())
    }
}

fn nop_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 0x2000];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let phdr = 64;
    elf[phdr..phdr + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[phdr + 4..phdr + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf[phdr + 8..phdr + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 16..phdr + 24].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[phdr + 24..phdr + 32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[phdr + 32..phdr + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 40..phdr + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[phdr + 48..phdr + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    for at in (0x1000..0x2000).step_by(4) {
        elf[at..at + 4].copy_from_slice(&A64_NOP.to_le_bytes());
    }
    elf
}

/// Bring up the soft carrier exactly as the production runner finalizes its
/// image.
fn bring_up() -> SoftAarch64Engine<NoExecutor> {
    let image = AddressSpace::load_elf_bytes_with_reader(&nop_elf(), &|_| None)
        .expect("load the witness ELF")
        .with_vdso_auxv(false)
        .with_linux_initial_stack_execfn_page_size(
            &[b"/custody".to_vec()],
            &Vec::<Vec<u8>>::new(),
            b"/custody",
            GUEST_PAGE_BYTES,
        )
        .expect("initial stack")
        .with_el0_trampoline()
        .and_then(|img| img.with_el1_vectors_mailbox_clock(true, true, El1IrqMode::Gic))
        .and_then(AddressSpace::with_identity_page)
        .and_then(AddressSpace::with_syscall_mailbox_arena)
        .and_then(AddressSpace::with_hvpatch_stage1_page_tables)
        .expect("finalize the witness image");
    SoftAarch64Vmm::bring_up_with_executor(&image, None, None, NoExecutor)
        .expect("soft carrier bring-up")
}

#[test]
fn soft_carrier_custody_publishes_and_retires_through_its_own_stage2() {
    let engine = bring_up();
    let carrier = engine.backend();
    let custody = carrier.stage2_custody();
    let generation = custody
        .live_generation()
        .expect("bring-up leaves the soft carrier's custody live");

    let host = vec![0u8; 4 * GUEST_PAGE_BYTES as usize].into_boxed_slice();
    let len = host.len();
    assert!(
        carrier.host_ptr(RECORD_IPA, len).is_none(),
        "nothing is mapped at the record's IPA before the publish"
    );

    // SAFETY: `host` outlives the record, which this test retires.
    let identity = unsafe {
        custody.publish_stage2_record(CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa: RECORD_IPA,
            len,
            host_addr: host.as_ptr() as usize,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: STAGE2_PERM_READ | STAGE2_PERM_WRITE,
            logical_owner: None,
        })
    }
    .expect("the soft carrier's custody publishes through its own stage 2");
    assert_eq!(
        custody.stage2_record_covering(RECORD_IPA, len),
        Some(identity)
    );

    // The carrier's stage 2 now translates the record's IPA to the host page.
    let written = b"soft carrier custody";
    let at = RECORD_IPA + GUEST_PAGE_BYTES + 8;
    carrier
        .write_gpa(at, written)
        .expect("a guest-physical write through the carrier");
    let offset = (GUEST_PAGE_BYTES + 8) as usize;
    assert_eq!(&host[offset..offset + written.len()], written);

    assert_eq!(
        custody.retire_stage2_record(identity),
        CarrierStage2RetireOutcome::RetiredUnmapped
    );
    assert!(custody.stage2_record_covering(RECORD_IPA, len).is_none());
    assert!(
        carrier.host_ptr(RECORD_IPA, len).is_none(),
        "a retired record's window is gone from the carrier's stage 2"
    );
    assert!(
        carrier.write_gpa(at, written).is_err(),
        "the carrier refuses a retired record's address"
    );
}
