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

use carrick_hal::OsError;
#[cfg(test)]
use carrick_hal::guest_arch::GuestArch;
#[cfg(test)]
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::{AddressSpace, LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_SIZE};

use crate::guest_setup::{GuestRam, WindowKind};

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

/// Length of the LSTAR stub's `OUT imm8, %al` doorbell (`0xE6 0xC5`), in bytes.
/// A rebuilt fork-child / fresh sibling vCPU resumes at the `SYSRETQ` that
/// follows the `OUT` — `X86_TRAMPOLINE_BASE + X86_OUT_DOORBELL_LEN` — regardless
/// of whether KVM advanced RIP past the `OUT` synchronously on the parent's
/// vCPU. (The parent keeps its own vCPU and resumes via KVM's own mechanism.)
/// Source: AMD64 ISA `OUT imm8` encoding; `entry_trampoline_bytes()` (carrick-hal).
pub const X86_OUT_DOORBELL_LEN: u64 = 2;

/// Guest RIP at which a freshly-built x86 vCPU resumes after a clone/fork trap:
/// the `SYSRETQ` immediately after the LSTAR `OUT` doorbell.
pub const X86_SYSRET_RESUME: u64 = X86_TRAMPOLINE_BASE + X86_OUT_DOORBELL_LEN;

fn align_down_kvm_slot(addr: u64) -> u64 {
    addr & !0xFFFF
}

fn align_up_kvm_slot(addr: u64) -> Option<u64> {
    addr.checked_add(0xFFFF).map(|end| end & !0xFFFF)
}

fn high_region_window(
    start: u64,
    end: u64,
    shared: bool,
) -> Result<Option<(u64, usize, WindowKind)>, OsError> {
    if end <= LINUX_NULL_GUARD_END {
        return Ok(None);
    }
    let low_window_end = X86_KERNEL_WINDOW_BASE + X86_KERNEL_WINDOW_SIZE;
    if start < low_window_end {
        return Ok(None);
    }

    let base = align_down_kvm_slot(start);
    let end = align_up_kvm_slot(end)
        .ok_or_else(|| OsError::new(format!("kvm-x86: window 0x{start:x}.. overflows")))?;
    let len = usize::try_from(end.saturating_sub(base))
        .map_err(|_| OsError::new(format!("kvm-x86: window 0x{base:x}..0x{end:x} too large")))?;
    if len == 0 {
        return Ok(None);
    }
    let kind = if shared {
        WindowKind::Shared
    } else {
        WindowKind::Private
    };
    Ok(Some((base, len, kind)))
}

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

// ─── GuestRam extension for x86 ──────────────────────────────────────────────

// The x86-specific window-layout method `build_for_image_x86` is gated to this
// module; `kvm_x86_engine::bring_up` consumes it.

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
    /// Each image region beyond the low window boundary (stack, heap, mmap arena,
    /// shared apertures) gets its own `MAP_NORESERVE` window + KVM slot covering
    /// the full address-space extent. The dispatcher may hand out any address in
    /// the declared mmap arena; truncating that KVM slot makes valid mmap results
    /// fail later in syscall-path buffer checks or guest stage-2 faults.
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
            // High region (stack, heap, mmap arena, shared apertures). Back the
            // full declared extent lazily with MAP_NORESERVE: this is virtual
            // coverage, not resident memory. Go's heap reservation path can
            // quickly allocate well past 64 MiB into the mmap arena.
            if let Some((base, len, kind)) =
                high_region_window(region.start, region.end, region.shared)?
            {
                ram.add_window(base, len, kind)?;
            }
            let bytes = region.bytes();
            if !bytes.is_empty() {
                ram.write_gpa(region.start, bytes)?;
            }
        }

        // NOTE: the trampoline / GDT / PML4 byte images are written by
        // `kvm_x86_engine::bring_up` via the shared `carrick_x86::build_pml4` +
        // `write_bringup_images_via_ram` (portability S4-KVM). This function now
        // only lays out the windows + copies the ELF/runtime region bytes.
        Ok(ram)
    }
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
    use carrick_mem::memory::{LINUX_MMAP_BASE, LINUX_SHARED_FILE_BASE, mmap_arena_size};

    // NOTE: the snapshot/seed-entry tests now live in `carrick-x86`
    // (`bringup_fns::tests::seed_entry_*`) — the seed/snapshot logic moved there
    // (portability S4-KVM). These tests cover the KVM-x86 layout constants the
    // bring-up still owns.

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

    #[test]
    fn high_region_window_covers_full_mmap_arena() {
        let arena_size = mmap_arena_size();
        let (base, len, kind) =
            high_region_window(LINUX_MMAP_BASE, LINUX_MMAP_BASE + arena_size, false)
                .expect("window plan")
                .expect("mmap arena is a high region");

        assert_eq!(base, LINUX_MMAP_BASE);
        assert_eq!(len as u64, arena_size);
        assert!(
            len as u64 > 64 * 1024 * 1024,
            "x86 KVM must not truncate the mmap arena to the old 64 MiB cap"
        );
        assert_eq!(kind, WindowKind::Private);
    }

    #[test]
    fn high_region_window_preserves_shared_aperture_kind() {
        let (base, len, kind) = high_region_window(
            LINUX_SHARED_FILE_BASE,
            LINUX_SHARED_FILE_BASE + 0x20_0000,
            true,
        )
        .expect("window plan")
        .expect("shared aperture is a high region");

        assert_eq!(base, LINUX_SHARED_FILE_BASE);
        assert_eq!(len, 0x20_0000);
        assert_eq!(kind, WindowKind::Shared);
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
