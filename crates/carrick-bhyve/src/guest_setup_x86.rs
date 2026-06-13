//! x86_64 guest bring-up on bhyve — **M0 subset**: the flat-binary doorbell
//! round-trip (plan T3). The full `bring_up_x86` (carrick-owned long-mode
//! ring-3 entry from `X8664BootSysregs`) is T6; M0 deliberately rides the
//! decade-proven `vm_setup_freebsd_registers` helper to prove the backend
//! substrate (FFI structs, memory model, register access, exit/resume
//! discipline) with zero ISA-impl dependency.
//!
//! # Memory model facts (lib/libvmmapi/vmmapi.c, releng/15.1 — FreeBSD source,
//! # allowed)
//!
//! - `vm_setup_memory(len, style)` supports ONLY `VM_MMAP_ALL` in 15.1
//!   (`vm_setup_memory_domains` asserts `vms == VM_MMAP_ALL`, vmmapi.c:497).
//!   For `len` ≤ 3 GiB it creates the `VM_SYSMEM` segment AND maps it at GPA
//!   `[0, len)` itself (map_memory_segment, vmmapi.c:453-475, prot
//!   `PROT_ALL`), so the explicit `mmap_memseg(0, …)` below is an idempotent
//!   re-statement (vmmapi.c:301-314 returns 0 for an identical existing
//!   mapping) that proves the wrapper works.
//! - `vm_map_gpa` resolves host pointers ONLY inside the contiguous lowmem
//!   `[0, lowmem_size)` / highmem `[4 GiB, 4 GiB + highmem_size)` regions
//!   (vmmapi.c:607-633; `VM_LOWMEM_LIMIT` = 3 GiB, `VM_HIGHMEM_BASE` = 4 GiB,
//!   lib/libvmmapi/internal.h:68-72). Anything outside returns NULL.
//!
//! # Experiment 1 — INOUT resume discipline (spec open question 1)
//!
//! **Outcome (live on the box, FreeBSD 15.1-RC3 amd64, 2026-06-12): vm_run
//! resumption AUTO-ADVANCES past a completed INOUT — do NOT bump RIP.** The
//! M0 test resumed without touching RIP and observed the RAX sequence
//! [1, 2, 3] with no doorbell replay. Host-source cross-check (FreeBSD
//! source, allowed): the vmm kernel sets `vcpu->nextrip = vme->rip +
//! vme->inst_length` after every exit (sys/amd64/vmm/vmm.c:1172,
//! releng/15.1) and the next `vm_run` resumes at `nextrip` (vmm.c:1161);
//! `vm_restart_instruction` exists precisely to UNDO that advance
//! (vmm.c:617-619) — which is why `usr.sbin/bhyve`'s own `vmexit_inout`
//! (usr.sbin/bhyve/amd64/vmexit.c:73-94) never touches RIP. See
//! [`complete_inout`].
//!
//! # Experiment 2 — high-GPA reach (spec open question 3)
//!
//! **Outcome (live on the box, 2026-06-12): FAIL at both probe points — T6
//! must allocate GPAs compactly from a bump cursor, NOT identity-place
//! carrick's high VAs.** `vm_mmap_memseg` at GPA 256 GiB (0x40_0000_0000)
//! and ~1 TiB (0xFF_FFE0_0000) both **succeed at the kernel/EPT level**, but
//! `vm_map_gpa` returns NULL for both (they sit outside the lowmem/highmem
//! windows above), so the HOST cannot read or write guest memory placed
//! there — useless for a syscall backend. The PML4 decouples guest VA from
//! GPA for free, so carrick's guest-virtual layout is unaffected
//! (`tests/live_vcpu.rs::high_gpa_probe` pins this).

use std::ffi::c_int;

use carrick_hal::OsError;
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};

use crate::vmm::{BhyveVcpu, BhyveVm};
use crate::vmm_x86::VM_CAP_HALT_EXIT;

/// The syscall doorbell port: the `SENTINEL_GPA` analogue. The LSTAR stub's
/// `OUT %al, $0xC5` lands here (spec §6 vehicle (a)).
pub const SYSCALL_DOORBELL_PORT: u16 = 0xC5;
/// Reserved for M3 (TLB-shootdown completion / maintenance doorbell).
pub const MAINT_DOORBELL_PORT: u16 = 0xC6;

/// M0 guest RAM: 32 MiB, all lowmem (≤ 3 GiB ⇒ a single `[0, len)` sysmem
/// mapping; see the module docs).
pub const M0_MEM_SIZE: usize = 32 * 1024 * 1024;
/// GPA of the doorbell blob (and RIP at entry).
pub const M0_BLOB_GPA: u64 = 0x10_0000;
/// GPA of the identity PML4 tables (the CR3 value).
pub const M0_PML4_GPA: u64 = 0x20_0000;
/// Table-region capacity: identity-mapping 32 MiB at 4 KiB leaves needs
/// 1 PML4 + 1 PDPT + 1 PD + 16 PTs = 19 pages; 32 gives headroom.
pub const M0_PML4_CAPACITY: usize = 32 * 4096;
/// GPA of the 3-entry boot GDT image (the `gdtbase` argument).
pub const M0_GDT_GPA: u64 = 0x30_0000;
/// Initial RSP: the stack grows down from here (16 KiB of plain identity-
/// mapped RAM below it; the M0 blob never actually touches the stack).
pub const M0_STACK_TOP: u64 = 0x40_0000;
/// Stack region size (documentation of the layout; nothing is written).
pub const M0_STACK_SIZE: usize = 16 * 1024;

/// `VM_SYSMEM` segment id (dev/vmm/vmm_mem.h:22, box header).
pub const VM_SEGID_SYSMEM: c_int = 0;
/// `PROT_READ|PROT_WRITE|PROT_EXEC` (sys/mman.h). Matches the `PROT_ALL`
/// that `vm_setup_memory`'s own mapping used, so the idempotence check in
/// `vm_mmap_memseg` (vmmapi.c:305-314) accepts the re-statement.
pub const PROT_RWX: c_int = 7;

/// M0 doorbell blob (ring 0, long mode): three OUT doorbells then HLT.
/// Encodings per AMD64 APM vol. 3 / OSDev (ISA references):
/// ```text
///   b0 01      mov $1, %al
///   e6 c5      out %al, $0xC5     ; doorbell — host reads RAX, expects 1
///   b0 02      mov $2, %al
///   e6 c5      out %al, $0xC5     ; expects 2
///   b0 03      mov $3, %al
///   e6 c5      out %al, $0xC5     ; expects 3
///   f4         hlt                ; VM_CAP_HALT_EXIT → clean stop
/// ```
pub fn m0_doorbell_blob() -> Vec<u8> {
    vec![
        0xB0, 0x01, // mov $1, %al
        0xE6, 0xC5, // out %al, $0xC5
        0xB0, 0x02, // mov $2, %al
        0xE6, 0xC5, // out %al, $0xC5
        0xB0, 0x03, // mov $3, %al
        0xE6, 0xC5, // out %al, $0xC5
        0xF4, // hlt
    ]
}

/// The 3-entry long-mode boot GDT image `vm_setup_freebsd_registers` expects
/// at `gdtbase`.
///
/// **GDT answer (spec/plan T3 step 2): the helper does NOT write the GDT
/// image itself** — `vm_setup_freebsd_registers` only points GDTR at
/// `gdtbase` with limit `GUEST_GDTR_LIMIT64` = 3*8-1 = 23
/// (lib/libvmmapi/amd64/vmmapi_freebsd_machdep.c:330-335, releng/15.1; the
/// CS/SS *hidden* descriptor state is programmed directly via `vm_set_desc`,
/// access 0x209B/0x93, lines 246-278). The image itself is the caller's job:
/// bhyveload calls the sibling `vm_setup_freebsd_gdt(gdtr)`
/// (vmmapi_freebsd_machdep.c:207-213), which writes exactly these three
/// entries — null, kernel CS64 (sel 0x08, P|S|exec, L=1, DPL0), kernel data
/// (sel 0x10, P|S|data, DPL0). Transcribed verbatim from that source.
pub fn freebsd_boot_gdt() -> [u64; 3] {
    [
        0x0000_0000_0000_0000, // [0] null
        0x0020_9800_0000_0000, // [1] 0x08 kernel CS64 (vmmapi_freebsd_machdep.c:211)
        0x0000_9000_0000_0000, // [2] 0x10 kernel data (vmmapi_freebsd_machdep.c:212)
    ]
}

/// The single M0 mapping: identity 0..32 MiB, supervisor, **RWX**. `exec`
/// must be true (NX clear) on every leaf: `vm_setup_freebsd_registers`
/// programs `EFER = LME|LMA` with **no NXE**
/// (vmmapi_freebsd_machdep.c:237-239), and with `EFER.NXE = 0` PTE bit 63 is
/// RESERVED — setting it would fault every walk with a reserved-bit #PF.
pub fn m0_identity_map_spec() -> Pml4MapSpec {
    Pml4MapSpec {
        va: 0,
        gpa: 0,
        len: M0_MEM_SIZE as u64,
        user: false,
        write: true,
        exec: true,
    }
}

/// Write `bytes` into guest-physical memory at `gpa` through the
/// `vm_map_gpa` host pointer.
fn write_gpa(vm: &BhyveVm, gpa: u64, bytes: &[u8]) -> Result<(), OsError> {
    let ptr = vm.map_gpa(gpa, bytes.len()).ok_or_else(|| {
        OsError::new(format!(
            "bhyve: vm_map_gpa({gpa:#x}, {}) returned NULL (GPA outside the \
             mapped lowmem/highmem regions)",
            bytes.len()
        ))
    })?;
    // SAFETY: `ptr` spans `bytes.len()` bytes of live guest RAM (vm_map_gpa
    // verified containment); the source slice is disjoint from it.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    Ok(())
}

/// A brought-up M0 VM: the doorbell blob is loaded, the identity PML4 + boot
/// GDT are written, and the vCPU is programmed for long-mode ring-0 entry at
/// the blob with `VM_CAP_HALT_EXIT` enabled.
pub struct BroughtUpM0 {
    pub vm: BhyveVm,
    pub vcpu: BhyveVcpu,
}

/// M0 bring-up: create → memory → artifacts → `vm_setup_freebsd_registers`
/// (the bhyveload-proven long-mode entry; replaced by carrick-owned
/// programming in T6) → `VM_CAP_HALT_EXIT`.
pub fn bring_up_m0() -> Result<BroughtUpM0, OsError> {
    let mut vm = BhyveVm::create()?;
    vm.setup_memory(M0_MEM_SIZE)?;
    // Idempotent re-statement of the sysmem mapping vm_setup_memory already
    // made (module docs) — proves the mmap_memseg wrapper against the live
    // kernel.
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, M0_MEM_SIZE, PROT_RWX)?;

    // The doorbell blob at the entry point.
    write_gpa(&vm, M0_BLOB_GPA, &m0_doorbell_blob())?;

    // Identity PML4 tables (the CR3 target).
    let tables = pml4_tables(&[m0_identity_map_spec()], M0_PML4_GPA, M0_PML4_CAPACITY)
        .map_err(|e| OsError::new(format!("bhyve: M0 PML4 build failed: {e:?}")))?;
    write_gpa(&vm, M0_PML4_GPA, &tables)?;

    // The 3-entry boot GDT image the helper's GDTR will point at (see
    // freebsd_boot_gdt for why WE write it, not the helper).
    let mut gdt_bytes = Vec::with_capacity(8 * freebsd_boot_gdt().len());
    for entry in freebsd_boot_gdt() {
        gdt_bytes.extend_from_slice(&entry.to_le_bytes());
    }
    write_gpa(&vm, M0_GDT_GPA, &gdt_bytes)?;

    let mut vcpu = vm.add_vcpu()?;
    vcpu.setup_freebsd_registers(M0_BLOB_GPA, M0_PML4_GPA, M0_GDT_GPA, M0_STACK_TOP)?;
    // A stray (or, here, deliberate) `hlt` exits instead of wedging the vCPU.
    vcpu.set_capability(VM_CAP_HALT_EXIT, 1)?;

    Ok(BroughtUpM0 { vm, vcpu })
}

/// Complete a handled doorbell INOUT and prepare the vCPU to resume PAST it.
///
/// **This is a deliberate no-op** — the resume discipline experiment (module
/// docs, Experiment 1) proved live that bhyve auto-advances: the vmm kernel
/// records `nextrip = rip + inst_length` at exit time
/// (sys/amd64/vmm/vmm.c:1172) and the next `vm_run` resumes there
/// (vmm.c:1161). Bumping RIP here would SKIP an instruction — the
/// must-not-replay reasoning of KVM's `SENTINEL_STR_WIDTH` PC bump applies
/// in reverse (must-not-double-advance). The helper exists so the discipline
/// lives in exactly one place: `BhyveTrapEngine::complete_syscall` (T7)
/// reuses it, and if a future FreeBSD changes the contract only this
/// function (and the M0 test pinning it) needs to change.
pub fn complete_inout(_vcpu: &mut BhyveVcpu, _rip: u64, _inst_length: u8) -> Result<(), OsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_mem::pml4::{PML4_NX, PML4_P, PML4_US, walk_descriptors};

    /// Byte-pin the M0 blob (the `el1_vectors_sentinel_bytes` pattern):
    /// `mov $N, %al` = B0 ib; `out %al, imm8` = E6 ib; `hlt` = F4
    /// (AMD64 APM vol. 3 encodings).
    #[test]
    fn m0_doorbell_blob_bytes_pinned() {
        assert_eq!(
            m0_doorbell_blob(),
            [
                0xB0, 0x01, 0xE6, 0xC5, 0xB0, 0x02, 0xE6, 0xC5, 0xB0, 0x03, 0xE6, 0xC5, 0xF4
            ]
        );
    }

    /// The GDT image must match `vm_setup_freebsd_gdt`'s verbatim
    /// (vmmapi_freebsd_machdep.c:207-213): null, 0x0020980000000000,
    /// 0x0000900000000000.
    #[test]
    fn freebsd_boot_gdt_matches_libvmmapi_image() {
        assert_eq!(
            freebsd_boot_gdt(),
            [0, 0x0020_9800_0000_0000, 0x0000_9000_0000_0000]
        );
    }

    #[test]
    fn doorbell_ports_are_distinct() {
        assert_ne!(SYSCALL_DOORBELL_PORT, MAINT_DOORBELL_PORT);
    }

    /// The M0 identity tables build inside the reserved capacity, and the
    /// blob page's leaf is present, supervisor, and NX-CLEAR (EFER.NXE is
    /// off in the M0 helper entry — NX would be a reserved bit).
    #[test]
    fn m0_identity_tables_fit_and_keep_nx_clear() {
        let tables = pml4_tables(&[m0_identity_map_spec()], M0_PML4_GPA, M0_PML4_CAPACITY)
            .expect("M0 PML4 build");
        assert_eq!(tables.len(), M0_PML4_CAPACITY);
        for gpa in [M0_BLOB_GPA, M0_PML4_GPA, M0_GDT_GPA, M0_STACK_TOP - 0x1000] {
            let walk = walk_descriptors(&tables, M0_PML4_GPA, gpa);
            assert_ne!(walk[3] & PML4_P, 0, "leaf present for {gpa:#x}");
            assert_eq!(walk[3] & PML4_NX, 0, "NX clear for {gpa:#x} (NXE off)");
            assert_eq!(walk[3] & PML4_US, 0, "supervisor leaf for {gpa:#x}");
        }
        let _ = M0_STACK_SIZE; // layout documentation const
    }
}
