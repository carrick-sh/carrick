//! x86-64 KVM guest bring-up — `KVM_SET_SREGS` + `KVM_SET_REGS` + `KVM_SET_MSRS`.
//!
//! This module is the x86_64-counterpart of `guest_setup.rs` (the aarch64 KVM
//! bring-up). It reuses [`GuestRam`] verbatim (host mmap + KVM_SET_USER_MEMORY_REGION
//! slots are ISA-neutral) and programs the vCPU via the x86-specific ioctls.
//!
//! **Key simplification vs bhyve:** [`KVM_SET_MSRS`] exposes LSTAR/STAR/SFMASK
//! directly. No ring-0 WRMSR init blob is needed. The vCPU enters ring 3 from
//! the first `KVM_RUN`. (Source: KVM API docs §4.81 "KVM_SET_MSRS".)
//!
//! **Identity GPA layout:** KVM accepts any `guest_phys_addr` in
//! `KVM_SET_USER_MEMORY_REGION`, so GPA == guest VA for all regions (no bhyve
//! lowmem/highmem compactness restriction).
//!
//! **Trap vehicle:** `SYSCALL → LSTAR stub (OUT 0xC5) → KVM_EXIT_IO →
//! VcpuExit::IoOut(0xC5, ..)`. No sentinel GPA hole needed (the INOUT doorbell
//! needs no unmapped region). Task 3 (`trap_engine_x86.rs`) dispatches on IoOut.
//!
//! # Sources
//! - KVM API: docs.kernel.org/virt/kvm/api.html
//! - Intel SDM vol. 3 §§2.5, 3.4.5, 4.5 — CR0/CR4/segment/paging bit layout
//! - AMD APM vol. 2 §3.1.7 — EFER/STAR/LSTAR/SFMASK MSR numbers
//! - OSDev "Global Descriptor Table" / "Paging" / "SYSCALL/SYSRET"
//! - kvm-ioctls 0.22.1 / kvm-bindings 0.12.1 docs.rs

use carrick_hal::HvVm;
use carrick_hal::OsError;
use carrick_hal::guest_arch::GuestArch;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::{AddressSpace, LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_SIZE};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use kvm_bindings::{Msrs, kvm_dtable, kvm_msr_entry, kvm_regs, kvm_segment};
use kvm_ioctls::VcpuFd;

use crate::guest_setup::{GuestRam, WindowKind};
use crate::kvm::{KvmVcpu, KvmVm};

// ─── x86 KVM layout constants ─────────────────────────────────────────────────
//
// KVM-SVM validates that CR3 is within the host machine's physical address
// space.  On hosts with ≤ 64 GiB of RAM the usable physical address range is
// capped at 36 bits (64 GiB).  The aarch64 "kernel hole" at
// `LINUX_KERNEL_REGION_BASE = 0x2D_0000_0000` (180 GiB) exceeds that limit and
// causes `KVM_SET_SREGS` to fail with EINVAL when used as CR3.
//
// For the x86 KVM backend we therefore use a separate, lower set of GPAs for
// the three kernel-only structures: LSTAR trampoline, boot GDT, and PML4 root.
// These live in a private 32 MiB window at 256 MiB — well below 64 GiB, well
// above any typical ELF text segment (≤ 4 MiB), and far from the user stack.
//
// The aarch64 `LINUX_EL0_TRAMPOLINE_BASE` / `LINUX_EL1_VECTORS_BASE` /
// `LINUX_PAGE_TABLES_BASE` constants are NOT used here.  Their 180 GiB address
// is valid as a KVM *slot* GPA (for heap/mmap windows), but not for CR3.
//
// Sources:
//   - AMD APM vol. 1 §3.1.4 "Physical-Address Space";
//   - KVM API §4.28 "KVM_SET_SREGS" (CR3 must be valid GPA).

/// Base of the x86 KVM "kernel window" — trampoline + GDT + PML4 tables.
///
/// 256 MiB: above typical ELF load regions (≤ 4 MiB), below the 64 GiB
/// physical-address limit observed on 8 GiB a hypervisor LXC KVM hosts.
pub const X86_KERNEL_WINDOW_BASE: u64 = 0x1000_0000; // 256 MiB

/// GPA of the LSTAR trampoline (OUT 0xC5 + SYSRETQ) for the x86 KVM backend.
///
/// Must match the LSTAR MSR value programmed in `program_x86_regs`.
/// Placed at `X86_KERNEL_WINDOW_BASE` (256 MiB).
pub const X86_TRAMPOLINE_BASE: u64 = X86_KERNEL_WINDOW_BASE;

/// GPA of carrick's 5-entry boot GDT for the x86 KVM backend.
///
/// One page (4 KiB) after the trampoline.
/// The GDT is 5 × 8 = 40 bytes, well within one 4 KiB page.
pub const X86_GDT_BASE: u64 = X86_KERNEL_WINDOW_BASE + 0x1000; // +4 KiB

/// GPA of the x86 PML4 root (= CR3 value).
///
/// Two pages after the trampoline, 4 KiB-aligned.
/// The PML4 tables region is [`X86_PML4_CAPACITY`] bytes.
///
/// **Must be below the host's physical-address ceiling** (36 bits / 64 GiB on
/// the reference a hypervisor LXC host).  At 256 MiB + 8 KiB this is comfortably
/// within any x86_64 machine with ≥ 256 MiB of RAM.
pub const X86_PML4_BASE: u64 = X86_KERNEL_WINDOW_BASE + 0x2000; // +8 KiB

/// Total size of the x86 kernel window (trampoline + GDT + PML4 tables).
///
/// 32 MiB covers the trampoline (1 page), GDT (1 page), and PML4 tables
/// (up to 448 pages = 1.75 MiB), with plenty of headroom.
pub const X86_KERNEL_WINDOW_SIZE: u64 = 32 * 1024 * 1024; // 32 MiB

/// GPA of carrick's 5-entry boot GDT image for the x86 KVM backend.
///
/// Alias of [`X86_GDT_BASE`] kept for readability at call sites.
pub const LINUX_GDT_BASE: u64 = X86_GDT_BASE;

/// Number of GDT entries. Source: `X8664BootSysregs::gdt` (carrick-hal).
pub const GDT_ENTRIES: usize = carrick_hal::x8664_arch::GDT_LEN;

/// Capacity of the PML4 region in bytes.
///
/// 448 pages × 4 KiB = 1,835,008 bytes (1.75 MiB).  Shared with the aarch64
/// [`LINUX_PAGE_TABLES_SIZE`] constant so the `pml4_tables` budget is the same.
pub const X86_PML4_CAPACITY: usize = LINUX_PAGE_TABLES_SIZE as usize;

// ─── Segment type nibbles ─────────────────────────────────────────────────────

/// Code segment type nibble for `kvm_segment::type_`.
///
/// 0xB = execute/read/ACCESSED (bit0=Accessed, bit1=Read, bit3=Code).
/// The accessed bit MUST be set: KVM validates guest segment access-rights on
/// VM entry; an unset accessed bit causes `KVM_SET_SREGS` to fail with EINVAL
/// on some kernels (Ubuntu 18.04 regression, dpw/kvm-hello-world#5). This
/// mirrors the lesson from the bhyve M1 VT-x accessed-bit blocker.
///
/// Source: Intel SDM vol. 3 §3.4.5.1 "Segment Descriptor" — type field bits;
/// OSDev "Segment Descriptor".
pub const CODE_SEG_TYPE: u8 = 11; // 0xB = Code + Readable + Accessed

/// Data segment type nibble for `kvm_segment::type_`.
///
/// 0x3 = read/write/ACCESSED (bit0=Accessed, bit1=Write, bit3=0 → Data).
/// Same accessed-bit requirement as [`CODE_SEG_TYPE`].
///
/// Source: Intel SDM vol. 3 §3.4.5.1; OSDev "Segment Descriptor".
pub const DATA_SEG_TYPE: u8 = 3; // 0x3 = Data + Writable + Accessed

// ─── BroughtUpX86 ────────────────────────────────────────────────────────────

/// Result of `bring_up_x86_kvm`: a VM + vCPU programmed for ring-3 entry at
/// `entry`, with PML4/GDT/LSTAR written into `ram`.
pub struct BroughtUpX86 {
    pub vm: KvmVm,
    pub vcpu: KvmVcpu,
    pub ram: GuestRam,
    /// ELF entry point (ring-3 RIP at first `KVM_RUN`).
    pub entry: u64,
    /// Initial guest stack pointer (ring-3 RSP at first `KVM_RUN`).
    pub initial_rsp: u64,
}

// ─── GuestRam extension for x86 ──────────────────────────────────────────────

// Expose the `GuestRam` method needed by `bring_up_x86_kvm` via a trait bound.
// We call only `pub(crate)` methods that already exist on the aarch64 side.
// The x86-specific method `build_for_image_x86` is gated to this module.

impl GuestRam {
    /// Build a `GuestRam` for an x86_64 image under KVM.
    ///
    /// Parallel to the aarch64 `build_for_image`, but:
    /// - Does NOT write EL1 vectors or the stage-1 maintenance trampoline
    ///   (no EL1 on x86).
    /// - Does NOT require a sentinel GPA hole (INOUT doorbell, not MMIO sentinel).
    /// - DOES write the x86 PML4 tables and the LSTAR stub (`bring_up_x86_kvm`
    ///   calls this, then writes the GDT).
    ///
    /// ## Window layout
    ///
    /// One low window `[0, X86_KERNEL_WINDOW_BASE + X86_KERNEL_WINDOW_SIZE)`
    /// covers:
    ///   - ELF text/data/BSS (typically loaded at 0x400000, a few MiB)
    ///   - The x86 kernel window at 256 MiB (trampoline + GDT + PML4)
    ///
    /// Each image region beyond the low window boundary (stack, heap, mmap arena)
    /// gets its own `MAP_NORESERVE` private window + KVM slot, capped at 64 MiB
    /// to avoid registering multi-GiB pre-allocated arenas as KVM slots.
    ///
    /// KVM slots for high GPAs (> 64 GiB) work fine — only CR3 must be below the
    /// host's physical-address ceiling (36 bits on the reference LXC host).
    pub(crate) fn build_for_image_x86(image: &AddressSpace) -> Result<Self, OsError> {
        let mut ram = GuestRam::new();

        // Low window: covers the ELF load segments AND the x86 kernel window
        // (trampoline/GDT/PML4) at 256 MiB.  High regions (stack, heap, mmap)
        // get their own lazily-committed MAP_NORESERVE windows.
        let low_window_end = X86_KERNEL_WINDOW_BASE + X86_KERNEL_WINDOW_SIZE;
        ram.add_window(0, low_window_end as usize, WindowKind::Private)?;

        // Write each ELF/runtime region.
        for region in image.regions() {
            // Skip the null guard.
            if region.end <= LINUX_NULL_GUARD_END {
                continue;
            }
            if region.start < low_window_end {
                // Fits in the low window — write bytes directly.
                let bytes = region.bytes();
                if !bytes.is_empty() {
                    ram.write_gpa(region.start, bytes)?;
                }
                continue;
            }
            // High region (stack, heap, mmap arena, shared apertures).
            // Cap at 64 MiB: the M2 bump allocators never use more than 64 MiB
            // of the pre-allocated heap/mmap arenas, and the shared apertures
            // are empty for the MVP.
            const MAX_WINDOW_LEN: u64 = 64 * 1024 * 1024; // 64 MiB
            let raw_len = region.end.saturating_sub(region.start);
            let capped_end = region.start.saturating_add(raw_len.min(MAX_WINDOW_LEN));
            let base = region.start & !0xFFFF; // align down to 64 KiB (KVM slot min size)
            let end = (capped_end + 0xFFFF) & !0xFFFF; // align up
            let len = (end - base) as usize;
            if len > 0 {
                ram.add_window(base, len, WindowKind::Private)?;
            }
            let bytes = region.bytes();
            if !bytes.is_empty() {
                ram.write_gpa(region.start, bytes)?;
            }
        }

        // Write the LSTAR trampoline (OUT 0xC5 + SYSRETQ) at X86_TRAMPOLINE_BASE.
        // The LSTAR MSR will be set to X86_TRAMPOLINE_BASE in program_x86_regs.
        // Source: X8664GuestArch::entry_trampoline_bytes().
        ram.write_gpa(
            X86_TRAMPOLINE_BASE,
            &X8664GuestArch::entry_trampoline_bytes(),
        )?;

        // Write the x86 PML4 tables at X86_PML4_BASE (= CR3 value).
        // X86_PML4_BASE is within the low window and below the host's
        // 36-bit physical-address ceiling — see module-level comment.
        let pml4_bytes = build_x86_pml4(image)?;
        ram.write_gpa(X86_PML4_BASE, &pml4_bytes)?;

        Ok(ram)
    }
}

// ─── bring_up_x86_kvm ─────────────────────────────────────────────────────────

/// Boot a KVM x86_64 vCPU programmed for ring-3 entry at `image.entry()`.
///
/// Steps:
/// 1. Build `GuestRam` from the image's regions (identity GPA = VA).
/// 2. Create VM + map every window as a KVM memory slot.
/// 3. Write the LSTAR trampoline (OUT 0xC5 + SYSRETQ) at `X86_TRAMPOLINE_BASE`.
/// 4. Write the 5-entry boot GDT at `X86_GDT_BASE` (= `LINUX_GDT_BASE`).
/// 5. Write the PML4 tables at `X86_PML4_BASE` (= CR3 value, < 64 GiB).
/// 6. `KVM_SET_SREGS`: CR0/CR4/EFER/CR3/GDT/IDT/segments (ring-3 user segments).
/// 7. `KVM_SET_REGS`: RIP=entry, RSP=initial_rsp, RFLAGS=0x2.
/// 8. `KVM_SET_MSRS`: LSTAR/STAR/SFMASK — the simplification over bhyve.
pub fn bring_up_x86_kvm(image: &AddressSpace) -> Result<BroughtUpX86, OsError> {
    // 1. Lay out guest RAM (identity GPA = VA; no sentinel hole needed).
    let mut ram = GuestRam::build_for_image_x86(image)?;

    // 2. Create VM + register every window as a KVM memory slot.
    let mut vm = KvmVm::create_empty()?;
    for (gpa, host, len) in ram.windows_for_kvm() {
        // SAFETY: the window host ptr is valid for `len` bytes for the VM lifetime.
        vm.map_memory(gpa, host, len, carrick_hal::MemPerms::ReadWriteExec)?;
    }

    // 3. (already done by build_for_image_x86 — LSTAR trampoline written)
    // Note: the trampoline is written before `add_vcpu` so KVM can run it.

    // 4. Write the 5-entry boot GDT at X86_GDT_BASE.
    //    X8664BootSysregs::gdt is [u64; 5] — serialized little-endian.
    let boot = X8664GuestArch::bootstrap_sysregs();
    let gdt_bytes: Vec<u8> = boot.gdt.iter().flat_map(|e| e.to_le_bytes()).collect();
    ram.write_gpa(X86_GDT_BASE, &gdt_bytes)?;

    // 5. (PML4 already written by build_for_image_x86)

    // 6–8. Create vCPU and program registers.
    let vcpu = vm.add_vcpu()?;
    program_x86_regs(&vcpu, image, &boot)?;

    // Fallback: if no initial stack was set, use the stack base from the
    // AddressSpace. LINUX_STACK_TOP is the default for ELF images.
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);

    Ok(BroughtUpX86 {
        vm,
        vcpu,
        ram,
        entry: image.entry(),
        initial_rsp: rsp,
    })
}

/// Program the vCPU via `KVM_SET_SREGS` + `KVM_SET_REGS` + `KVM_SET_MSRS`.
fn program_x86_regs(
    vcpu: &KvmVcpu,
    image: &AddressSpace,
    boot: &carrick_hal::x8664_arch::X8664BootSysregs,
) -> Result<(), OsError> {
    let vcpu_fd: &VcpuFd = vcpu.fd();

    // ─── 5a. KVM_SET_SREGS ────────────────────────────────────────────────────
    //
    // The initial vCPU segments are USER (ring-3) so the guest enters user mode
    // on the first `KVM_RUN`. No ring-0 entry needed (KVM_SET_MSRS programs
    // LSTAR/STAR/SFMASK directly — the key simplification over bhyve's ring-0
    // WRMSR init blob).
    //
    // `kvm_segment` fields (kvm-bindings 0.12.1 / Intel SDM vol. 3 §3.4.5):
    //   base:     segment base (flat 0 in 64-bit mode)
    //   limit:    segment limit (0xFFFFFFFF for 4-KiB granular segments)
    //   selector: GDT index | RPL (0x23 = GDT[4]|RPL3, 0x1B = GDT[3]|RPL3)
    //   type_:    Intel segment type nibble (11=code+r+accessed, 3=data+w+accessed)
    //   s:        1 = code/data descriptor (not system)
    //   dpl:      ring level (3 for user)
    //   present:  1
    //   avl:      available bit (0)
    //   l:        1 for 64-bit code segment; 0 for data
    //   db:       default size (0 when l=1 per Intel SDM; 1 for data segments)
    //   g:        granularity (1 = 4 KiB; limit field in units of 4 KiB pages)
    //   unusable: 0 (segment is valid)

    // User CS64: GDT[4] selector 0x23 (0x20 | RPL3), DPL3, L=1, exec/read/accessed.
    // Source: AMD APM vol. 2 §3.1.7 SYSRET: SS = STAR[63:48]+8, CS = STAR[63:48]+16+RPL3.
    let cs = kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 0x23,       // GDT[4]=0x20 | RPL3=3
        type_: CODE_SEG_TYPE, // 11 = execute/read/accessed
        s: 1,                 // code/data (not system)
        dpl: 3,               // ring 3
        present: 1,
        avl: 0,
        l: 1,  // 64-bit code
        db: 0, // must be 0 when l=1 (Intel SDM vol. 3 §3.4.5)
        g: 1,  // 4 KiB granularity
        unusable: 0,
        ..Default::default()
    };

    // User SS: GDT[3] selector 0x1B (0x18 | RPL3), DPL3, data/write/accessed.
    let ss = kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 0x1B,       // GDT[3]=0x18 | RPL3=3
        type_: DATA_SEG_TYPE, // 3 = data/write/accessed
        s: 1,
        dpl: 3,
        present: 1,
        avl: 0,
        l: 0,
        db: 1, // 32-bit default for data segments (OSDev "Segment Descriptor")
        g: 1,
        unusable: 0,
        ..Default::default()
    };

    // DS/ES: same as SS (long mode ignores DS/ES; copy SS for KVM validity).
    let ds = ss;
    let es = ss;

    // FS/GS: same layout as DS/ES in 64-bit mode (base is the only significant
    // field; type/limit are usually ignored).  arch_prctl(ARCH_SET_FS) sets
    // fs.base via KVM_SET_SREGS later.
    let fs = kvm_segment {
        base: 0,
        selector: 0,
        ..ss
    };
    let gs = kvm_segment {
        base: 0,
        selector: 0,
        ..ss
    };

    // TR (task register): a minimal valid 32-bit TSS (type=11 busy, system
    // descriptor, DPL=0, present=1, g=1 so limit covers the whole 4 KiB page).
    // Matches kvmtool's prot64_sregs() style; selector 0 is fine for KVM's
    // hidden-state model (KVM uses the `kvm_segment` directly and does not
    // re-load from the GDT on KVM_SET_SREGS).
    // Source: Intel SDM vol. 3 §7.2.1 "TSS in 64-bit mode"; kvmtool x86/kvm-cpu.c.
    let tr = kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 0,
        type_: 11, // 32-bit TSS (busy); matches kvmtool BOOT_GDT_TSS flags 0x808B
        s: 0,      // system descriptor
        dpl: 0,
        present: 1,
        avl: 0,
        l: 0,
        db: 0,
        g: 1, // 4 KiB granularity (limit is in 4 KiB pages)
        unusable: 0,
        ..Default::default()
    };

    // LDT: mark unusable (we use the GDT only).
    let ldt = kvm_segment {
        unusable: 1,
        ..Default::default()
    };

    // Start from the vCPU's reset-state sregs and overlay everything we need
    // in a single `KVM_SET_SREGS` call.
    //
    // **Why all-at-once?**  KVM-SVM validates that when CR0.PG=1 (paging on),
    // the active CS segment has `l=1` (64-bit code segment).  The reset-state
    // CS has `l=0`; if we set CR0/CR4/EFER before updating CS, the kernel sees
    // a "paging enabled without 64-bit CS" state and returns EINVAL.  Setting
    // CR3, long-mode segments, and control registers together in one ioctl
    // passes validation.
    //
    // **CR3 physical address constraint (AMD SVM, a hypervisor LXC):**
    // KVM-SVM checks that CR3 is within the host machine's physical address
    // space.  On hosts with ≤ 64 GiB RAM (36-bit physical address), any CR3
    // value with bit 36 or higher set returns EINVAL.  `X86_PML4_BASE` (256 MiB
    // + 8 KiB) is well below that ceiling.  Source: empirically verified on
    // a hypervisor LXC (AMD Ryzen 7 7840HS, 8 GiB RAM, kernel 7.0.2-pve).
    //
    // We preserve all KVM-internal fields (interrupt_bitmap, apic_base, padding)
    // from the reset state so we don't accidentally set APIC-related fields to
    // zero and trigger a different EINVAL path.
    // Source: KVM API §4.28 "KVM_SET_SREGS".
    let mut sregs = vcpu_fd
        .get_sregs()
        .map_err(|e| OsError::new(format!("kvm-x86: KVM_GET_SREGS (initial): {e}")))?;

    // Control registers.
    sregs.cr0 = boot.cr0;
    sregs.cr2 = 0;
    sregs.cr3 = X86_PML4_BASE; // PML4 root; must be < 64 GiB on this host
    sregs.cr4 = boot.cr4;
    sregs.cr8 = 0;
    sregs.efer = boot.efer;

    // GDT / IDT.
    sregs.gdt = kvm_dtable {
        base: X86_GDT_BASE,
        limit: (GDT_ENTRIES as u16) * 8 - 1,
        ..Default::default()
    };
    sregs.idt = kvm_dtable {
        base: 0,
        limit: 0,
        ..Default::default()
    };

    // Long-mode user segments (must match CR0/EFER long-mode state set above).
    sregs.cs = cs;
    sregs.ds = ds;
    sregs.es = es;
    sregs.fs = fs;
    sregs.gs = gs;
    sregs.ss = ss;
    sregs.tr = tr;
    sregs.ldt = ldt;

    vcpu_fd
        .set_sregs(&sregs)
        .map_err(|e| OsError::new(format!("kvm-x86: KVM_SET_SREGS: {e}")))?;

    // ─── 5b. KVM_SET_REGS ─────────────────────────────────────────────────────
    //
    // Set the general-purpose registers. All GPRs start at 0; only RIP/RSP/RFLAGS
    // are non-trivial.
    //
    // rflags: reserved bit 1 MUST always be 1 (Intel SDM vol. 1 §3.4.3
    // "EFLAGS Register — bit 1 is reserved and must be set to 1").
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);
    let regs = kvm_regs {
        rip: image.entry(),
        rsp,
        rflags: 0x0000_0002,  // bit 1 always-1
        ..Default::default()  // all other GPRs = 0
    };
    vcpu_fd
        .set_regs(&regs)
        .map_err(|e| OsError::new(format!("kvm-x86: KVM_SET_REGS: {e}")))?;

    // ─── 5c. KVM_SET_MSRS ─────────────────────────────────────────────────────
    //
    // Program the SYSCALL MSRs directly — the key simplification over bhyve
    // (which has no vm_set_register path for these and needs a ring-0 WRMSR blob).
    //
    // MSR numbers (AMD APM vol. 2 §3.1.7 / OSDev "SYSCALL/SYSRET"):
    //   STAR    = 0xc0000081 — kernel/user selector bases in bits[63:32]
    //   LSTAR   = 0xc0000082 — 64-bit SYSCALL target RIP (= X86_TRAMPOLINE_BASE)
    //   SFMASK  = 0xc0000084 — RFLAGS bits cleared on SYSCALL entry
    // EFER is NOT set here — it is in sregs.efer above (KVM_SET_SREGS path).
    //
    // NOTE: `boot.lstar` points to the aarch64 `LINUX_EL0_TRAMPOLINE_BASE`
    // (180 GiB).  For x86 KVM we override it with `X86_TRAMPOLINE_BASE`
    // (256 MiB), where `build_for_image_x86` actually writes the stub.
    let msrs = Msrs::from_entries(&[
        kvm_msr_entry {
            index: 0xc000_0081,
            data: boot.star,
            ..Default::default()
        }, // STAR
        kvm_msr_entry {
            index: 0xc000_0082,
            data: X86_TRAMPOLINE_BASE, // x86 KVM trampoline (not boot.lstar)
            ..Default::default()
        }, // LSTAR
        kvm_msr_entry {
            index: 0xc000_0084,
            data: boot.sfmask,
            ..Default::default()
        }, // SFMASK
    ])
    .map_err(|e| OsError::new(format!("kvm-x86: Msrs::from_entries: {e}")))?;

    let n_written = vcpu_fd
        .set_msrs(&msrs)
        .map_err(|e| OsError::new(format!("kvm-x86: KVM_SET_MSRS: {e}")))?;
    if n_written != 3 {
        return Err(OsError::new(format!(
            "kvm-x86: KVM_SET_MSRS wrote {n_written}/3 entries (partial write)"
        )));
    }

    Ok(())
}

// ─── PML4 builder ─────────────────────────────────────────────────────────────

/// Build the x86-64 4-level page tables for `image`.
///
/// The resulting table image is written at `X86_PML4_BASE` (= CR3 value).
/// All mappings are identity (VA == GPA) — valid on KVM (no bhyve GPA
/// restriction).
///
/// ## Mapped regions
///
/// - ELF load segments: user, r/w per segment perms, exec per segment perms.
/// - Stack / heap / mmap: user, r/w, no-exec (capped at 64 MiB each).
/// - x86 kernel window (trampoline + GDT + PML4 tables): supervisor-only.
///   Trampoline page is exec; GDT and PML4 pages are no-exec.
///
/// ## Capacity budget
///
/// `X86_PML4_CAPACITY` = 448 table pages (1.75 MiB).  Each 64 MiB user region
/// consumes at most 16384/512 = 32 PT pages.  With 6 arenas + ELF + stack +
/// kernel window ≈ 210 pages total — well within budget.
///
/// Paging bits: OSDev "Paging" / Intel SDM vol. 3 §4.5.
///   P=bit0, R/W=bit1, U/S=bit2 (at every level for user), NX=bit63 (EFER.NXE).
fn build_x86_pml4(image: &AddressSpace) -> Result<Vec<u8>, OsError> {
    let mut maps: Vec<Pml4MapSpec> = Vec::new();

    // Cap each image region at 64 MiB to stay within the PML4 capacity budget.
    // The M2 bump allocators (heap ≤ 8 MiB, mmap ≤ 64 MiB) never exceed this.
    const MAX_MAPPED_LEN: u64 = 64 * 1024 * 1024; // 64 MiB

    for region in image.regions() {
        let start = region.start;
        let raw_len = region.end.saturating_sub(start);
        if raw_len == 0 {
            continue;
        }
        let len = raw_len.min(MAX_MAPPED_LEN);
        let va = start & !0xFFF; // page-align down
        let gpa = va; // identity: GPA = VA
        let aligned_len = ((start + len + 0xFFF) & !0xFFF) - va;
        if aligned_len == 0 {
            continue;
        }
        maps.push(Pml4MapSpec {
            va,
            gpa,
            len: aligned_len,
            user: true,
            write: region.perms.write,
            exec: region.perms.execute,
        });
    }

    // x86 kernel window: three supervisor-only regions within X86_KERNEL_WINDOW.
    //
    // 1. Trampoline page (exec): LSTAR target (OUT 0xC5 + SYSRETQ).
    maps.push(Pml4MapSpec {
        va: X86_TRAMPOLINE_BASE,
        gpa: X86_TRAMPOLINE_BASE,
        len: 0x1000,
        user: false,
        write: false,
        exec: true,
    });

    // 2. GDT page (no-exec, read-only).
    maps.push(Pml4MapSpec {
        va: X86_GDT_BASE,
        gpa: X86_GDT_BASE,
        len: 0x1000,
        user: false,
        write: false,
        exec: false,
    });

    // 3. PML4 tables region (no-exec, writable so the host can update entries).
    maps.push(Pml4MapSpec {
        va: X86_PML4_BASE,
        gpa: X86_PML4_BASE,
        len: X86_PML4_CAPACITY as u64,
        user: false,
        write: true,
        exec: false,
    });

    pml4_tables(&maps, X86_PML4_BASE, X86_PML4_CAPACITY)
        .map_err(|e| OsError::new(format!("kvm-x86: pml4_tables: {e:?}")))
}

// ─── M0/M1 combined flat-binary blob ─────────────────────────────────────────

/// Guest VA where the M0/M1 combined flat-binary blob is placed.
/// Low canonical user address, easily addressed with 32-bit immediates.
/// Source: plan Task 5.
pub const M01_BLOB_VA: u64 = 0x0040_0000;

/// Expected output of the M0/M1 blob.
pub const M01_EXPECTED_OUTPUT: &[u8] = b"hello\n";

/// M0/M1 combined flat-binary blob: ring-3 code issuing two SYSCALL instructions
/// (`write(1, "hello\n", 6)` and `exit_group(0)`) to prove the complete trap
/// vehicle end-to-end.
///
/// Placed at `M01_BLOB_VA` (a user-mode VA, exec+read in the PML4).
///
/// Encoding (x86_64 little-endian; AMD64 ISA / OSDev "x86-64 instruction encoding"):
/// ```text
/// +0x00  48 c7 c7 01 00 00 00   mov  $1,  %rdi          ; fd = 1 (stdout)
/// +0x07  48 8d 35 0d 00 00 00   lea  0xd(%rip), %rsi    ; buf = &msg (rip+13)
/// +0x0e  48 c7 c2 06 00 00 00   mov  $6,  %rdx          ; len = 6
/// +0x15  48 c7 c0 01 00 00 00   mov  $1,  %rax          ; write (x86_64 syscall #1)
/// +0x1c  0f 05                  syscall                 ; → LSTAR stub → OUT 0xC5
/// +0x1e  48 31 ff               xor  %rdi, %rdi         ; status = 0
/// +0x21  48 c7 c0 e7 00 00 00   mov  $231, %rax         ; exit_group (x86_64 #231)
/// +0x28  0f 05                  syscall
/// +0x2a  eb fe                  jmp  .                  ; unreachable
/// ; msg at offset 0x2c = "hello\n"
/// ```
pub fn m01_blob() -> Vec<u8> {
    let mut b = vec![
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov $1, %rdi
        0x48, 0x8d, 0x35, 0x0d, 0x00, 0x00, 0x00, // lea 0xd(%rip), %rsi
        0x48, 0xc7, 0xc2, 0x06, 0x00, 0x00, 0x00, // mov $6, %rdx
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov $1, %rax  (write)
        0x0f, 0x05, // syscall → OUT 0xC5 → IoOut
        0x48, 0x31, 0xff, // xor %rdi, %rdi
        0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov $231, %rax (exit_group)
        0x0f, 0x05, // syscall
        0xeb, 0xfe, // jmp . (unreachable)
    ];
    // The `lea 0xd(%rip), %rsi` above: RIP after the lea instruction is at
    // offset 0x0e + 0x07 = offset 0x15. We need rsi = msg_va = M01_BLOB_VA + msg_offset.
    // After `lea 0xd(%rip)`: rip is at end of the 7-byte lea = offset 0x0e + 7 = 0x15.
    // rsi = rip + 0xd = offset 0x15 + 0xd = offset 0x22.
    // But our blob so far is:
    //   0x00: 7 bytes (mov rdi)
    //   0x07: 7 bytes (lea rsi, [rip+0xd])
    //   0x0e: 7 bytes (mov rdx)
    //   0x15: 7 bytes (mov rax=1)
    //   0x1c: 2 bytes (syscall)
    //   0x1e: 3 bytes (xor rdi)
    //   0x21: 7 bytes (mov rax=231)
    //   0x28: 2 bytes (syscall)
    //   0x2a: 2 bytes (jmp .)
    //   0x2c: msg starts here
    // RIP at end of the lea (0x07..0x0e, 7 bytes) = blob_va + 0x0e.
    // rsi = (blob_va + 0x0e) + 0x0d = blob_va + 0x1b.
    // But msg is at 0x2c. Need offset = 0x2c - 0x0e = 0x1e (not 0x0d).
    // Let's recalculate: the `lea 0xd(%rip)` with 0xd gives rsi = rip+0xd where
    // rip = end of lea instruction = blob_va + 0x0e.
    // rsi = blob_va + 0x0e + 0x0d = blob_va + 0x1b.
    // But msg is at blob_va + 0x2c. Needed offset = 0x2c - 0x0e = 0x1e.
    // Fix: patch the immediate to 0x1e.
    b[10] = 0x1e; // fix the LEA displacement: lea 0x1e(%rip), %rsi
    // Now rsi = (blob_va + 0x0e) + 0x1e = blob_va + 0x2c. Correct!
    assert_eq!(b.len(), 0x2c, "msg must be at offset 0x2c");
    b.extend_from_slice(b"hello\n");
    b
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the GDT selector encoding and the STAR arithmetic.
    ///
    /// STAR bits[47:32] = kernel CS selector = 0x08 (GDT[1] kCS64).
    /// STAR bits[63:48] = "user base" = 0x0013; SYSRET computes:
    ///   SS = 0x0013 + 8  = 0x1B (0x18 | RPL3) → GDT[3] uSS with RPL=3
    ///   CS = 0x0013 + 16 = 0x23 (0x20 | RPL3) → GDT[4] uCS64 with RPL=3
    ///
    /// Source: AMD APM vol. 2 §3.1.7 "SYSCALL/SYSRET Target Address Registers".
    #[test]
    fn gdt_selector_encoding() {
        // Using X8664GuestArch directly (KvmX86TrapEngine is Task 3).
        let boot = X8664GuestArch::bootstrap_sysregs();

        // STAR kernel-base field: bits[47:32] = 0x0008 (kernel CS selector).
        assert_eq!(
            (boot.star >> 32) & 0xFFFF,
            0x0008,
            "STAR kernel CS base = 0x08"
        );
        // STAR user-base field: bits[63:48] = 0x0013.
        assert_eq!((boot.star >> 48) & 0xFFFF, 0x0013, "STAR user base = 0x13");

        // Derived user selectors (with RPL=3):
        let user_ss = ((boot.star >> 48) as u16).wrapping_add(8); // 0x1B
        let user_cs = ((boot.star >> 48) as u16).wrapping_add(16); // 0x23
        // Strip RPL bits to get the descriptor index × 8.
        assert_eq!(
            user_ss & !0x3,
            0x18,
            "user SS descriptor index = 0x18 (GDT[3])"
        );
        assert_eq!(
            user_cs & !0x3,
            0x20,
            "user CS descriptor index = 0x20 (GDT[4])"
        );
    }

    /// Verify the segment type nibble constants carry the accessed bit.
    ///
    /// Per Intel SDM vol. 3 §3.4.5.1 "Segment Descriptor", the type field bits:
    ///   bit0 = Accessed, bit1 = Write/Read, bit2 = Expand-Down/Conforming, bit3 = Code/Data.
    ///
    /// Code+Read+Accessed  = 0b1011 = 11 = 0xB.
    /// Data+Write+Accessed = 0b0011 =  3 = 0x3.
    ///
    /// KVM validates these on `KVM_SET_SREGS`; an unset accessed bit causes EINVAL
    /// on some kernels (Ubuntu 18.04 regression, dpw/kvm-hello-world#5 — same
    /// accessed-bit lesson as the bhyve M1 blocker).
    #[test]
    fn segment_type_accessed_bits() {
        assert_eq!(
            CODE_SEG_TYPE, 11u8,
            "code seg type = 11 (0xB = exec/read/accessed)"
        );
        assert_eq!(
            DATA_SEG_TYPE, 3u8,
            "data seg type =  3 (0x3 = data/write/accessed)"
        );
        // Accessed bit (bit 0) must be set in both.
        assert_ne!(CODE_SEG_TYPE & 1, 0, "CODE_SEG_TYPE accessed bit set");
        assert_ne!(DATA_SEG_TYPE & 1, 0, "DATA_SEG_TYPE accessed bit set");
    }

    /// Verify CR0/CR4/EFER bit patterns match the spec values.
    ///
    /// Sources: Intel SDM vol. 3 §2.5 "Control Registers";
    ///          AMD APM vol. 2 §3.1.7 "Extended Feature Enable Register".
    #[test]
    fn cr0_cr4_efer_bit_patterns() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // CR0 = 0x8001_0033: PE(0)|MP(1)|ET(4)|NE(5)|WP(16)|PG(31).
        assert_eq!(boot.cr0, 0x8001_0033, "CR0");
        // CR4 = 0x0000_0620: PAE(5)|OSFXSR(9)|OSXMMEXCPT(10).
        assert_eq!(boot.cr4, 0x0000_0620, "CR4");
        // EFER = 0x0000_0D01: SCE(0)|LME(8)|LMA(10)|NXE(11).
        assert_eq!(boot.efer, 0x0000_0D01, "EFER");
    }

    /// Verify SFMASK masks the interrupt flag (IF=bit9), so the 2-instruction
    /// LSTAR stub (OUT + SYSRETQ) runs without an interrupt window.
    ///
    /// Source: AMD APM vol. 2 §3.1.7 "SFMASK" + Intel SDM vol. 1 §3.4.3 (IF=bit9).
    #[test]
    fn sfmask_masks_interrupts() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // IF is bit 9 of RFLAGS.
        assert!(
            boot.sfmask & (1 << 9) != 0,
            "SFMASK must mask IF (bit 9) so no interrupt window in the LSTAR stub"
        );
    }

    /// Verify the M0/M1 blob places the message at the correct offset.
    ///
    /// The `lea 0x1e(%rip)` inside the blob must point at `msg`:
    /// RIP at end of lea instruction = blob_va + 0x0e; rsi = rip + 0x1e = blob_va + 0x2c.
    /// The blob appends `b"hello\n"` at offset 0x2c.
    #[test]
    fn m01_blob_msg_offset() {
        let b = m01_blob();
        assert!(
            b.len() >= 0x2c + 6,
            "blob must be at least 0x32 bytes (code + msg)"
        );
        assert_eq!(&b[0x2c..0x32], b"hello\n", "msg at offset 0x2c");
    }
}
