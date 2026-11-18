//! Shared stopped-carrier helpers for the soft carrier tests: a minimal
//! static ELF, the physical frame inventory and the KVM production
//! witnesses' issued-root binding.

#![allow(dead_code)]

use std::sync::Arc;

use carrick_vmm_soft::SoftCarrier;
use carrick_x86_cpl0_host::cpl0_boot::{Cpl0BootCarrier, InitialTaskBinding};

/// A static x86-64 `ET_EXEC` whose one `R+X` `PT_LOAD` maps its own
/// headers and `code` at `0x40_0000`, entering at `code`.
pub fn static_elf(code: &[u8]) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    const HEADERS: u64 = 64 + 56;
    let size = HEADERS + code.len() as u64;
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7fELF");
    elf.extend_from_slice(&[2, 1, 1, 0]); // ELFCLASS64, little-endian, v1, SysV
    elf.extend_from_slice(&[0; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&(BASE + HEADERS).to_le_bytes()); // e_entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&size.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&size.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    elf.extend_from_slice(code);
    elf
}

pub fn inventory() -> Arc<dyn carrick_hal::PhysicalFrameInventory> {
    Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new())
        .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()))
}

/// The KVM production witnesses' stopped-carrier sequence
/// (`boot_program_carrier`): publish the retained IPC table map to the
/// kernel-issued root, bind the carrier's birth source into the kernel, and
/// bind that exact root as the initial task.
pub fn bind_issued_root(
    carrier: &mut SoftCarrier,
    root: &carrick_kernel::kernel::KernelContext,
) -> Result<(), String> {
    let owner = root
        .kernel()
        .ipc()
        .map_err(|error| format!("IPC owner: {error:?}"))?;
    let map = carrier
        .custody()
        .ipc_table_map()
        .map_err(|error| error.to_string())?;
    root.resources()
        .files()
        .publish_ipc(
            owner,
            carrick_kernel::kernel::objects::IpcTableMapBinding::Retained(map),
        )
        .map_err(|error| format!("publish exact table: {error:?}"))?;
    let source = carrier
        .custody()
        .birth_serial_source()
        .map_err(|error| error.to_string())?;
    root.kernel()
        .bind_initial_birth_source(source)
        .map_err(|error| format!("bind initial birth source: {error:?}"))?;
    carrier
        .custody_mut()
        .bind_initial_task_identity(InitialTaskBinding {
            task: root.task().key(),
            mm: carrick_hal::MmGeneration::new(root.shared().mm().id().nonzero()),
            thread: carrick_sched_core::ThreadIdentity {
                tid: carrick_el1_abi::El1TaskId::from_linux_tid(root.thread().key().tid.raw())
                    .raw(),
                serial: root.thread().key().serial.raw(),
                mm: 0,
                file_table: root.resources().files().id().raw(),
                generation: carrick_kernel::kernel::objects::ExecutionGeneration::INITIAL.raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .map_err(|error| error.to_string())
}
