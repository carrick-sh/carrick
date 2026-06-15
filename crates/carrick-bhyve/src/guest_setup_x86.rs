//! x86_64 guest bring-up on bhyve — M0 and T6 (carrick-owned ring-3 entry).
//!
//! **M0** (plan T3): the flat-binary doorbell round-trip via the bhyveload-
//! proven `vm_setup_freebsd_registers` helper; proves the backend substrate
//! (FFI structs, memory model, register access, exit/resume discipline) with
//! zero ISA-impl dependency.
//!
//! **T6** (plan T6): `BhyveGuestRam` + `bring_up_x86` — carrick-owned long-
//! mode ring-3 entry from `X8664BootSysregs`.  The LSTAR/STAR/SFMASK MSRs
//! cannot be written via `vm_set_register` (they are absent from
//! `enum vm_reg_name`; `vm_set_register` rejects IDs > 48 with EINVAL —
//! confirmed live).  Instead, a ring-0 init blob placed at the ring-3 entry
//! RIP WRMSRs them from CPL 0 before the `iretq` to user space.  VT-x's MSR
//! bitmap does NOT intercept LSTAR/STAR/SFMASK writes (the hardware lets them
//! pass through directly; `vmx_msr_guest_enter` saves/restores them across
//! VM entry/exit from the per-vCPU struct — confirmed live: a ring-0 blob
//! that WRMSRs LSTAR then iretq to ring-3 correctly delivers SYSCALL to the
//! LSTAR stub with no VM_EXITCODE_WRMSR exits surfaced).  See
//! [`bring_up_x86`] and the Experiment 3 note below.
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
//!
//! # Experiment 3 — LSTAR/STAR/SFMASK MSR programming (spec open question 2)
//!
//! **Decision (the empirical proof is M1/T7, not T6).** T1 established these
//! three MSRs are NOT in bhyve's `enum vm_reg_name` (only EFER is MSR-backed
//! there), so `vm_set_register` cannot set them and there is no userspace
//! MSR-set ioctl in libvmmapi. The chosen route is a **ring-0 WRMSR init
//! blob**: the vCPU enters at CPL 0 (RIP = the init blob), WRMSRs
//! LSTAR/STAR/SFMASK, then `iretq`s to ring-3 user code.
//!
//! Rationale this should work single-vCPU: VT-x's MSR bitmap does not force a
//! WRMSR exit for LSTAR/STAR/SFMASK, and bhyve's `vmx_msr_guest_enter` (vmm.ko)
//! context-switches these MSRs from a per-vCPU struct across every VM
//! entry/exit, so a ring-0 WRMSR writes through and survives. **This is a
//! design rationale, NOT a verified live outcome** — T6 only builds the
//! bring-up + the (vCPU-not-run) register-diff oracle; whether the ring-0
//! WRMSR→iretq→ring-3→SYSCALL chain actually delivers is PROVEN (or refuted,
//! and reworked) when T7 runs the M1 blob live. Documented here so T7 knows the
//! intended mechanism and where to look if the first SYSCALL never traps.
//!
//! EFER note: `vm_setup_freebsd_registers` sets EFER = 0x1500 (LME|LMA without
//! SCE); carrick's `bring_up_x86` overrides EFER to 0xD01 (LME|LMA|NXE|SCE)
//! via `vm_set_register` (EFER id = 32, which IS in `enum vm_reg_name`) so that
//! the ring-3 SYSCALL is enabled and the PML4 NX bit is functional.  Without
//! SCE the SYSCALL instruction raises #UD → triple-fault → VM_EXITCODE_SUSPENDED.

use std::ffi::c_int;

use carrick_hal::OsError;
use carrick_hal::guest_arch::GuestArch;
use carrick_hal::x8664_arch::{X8664GuestArch, entry_trampoline_bytes};
// Re-export GDT_LEN so callers (including tests/live_vcpu.rs) can assert the
// 5-entry GDT limit without depending on carrick-hal directly.
pub use carrick_hal::x8664_arch::GDT_LEN;
use carrick_mem::memory::{
    LINUX_EL0_TRAMPOLINE_BASE, LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE, LINUX_STACK_SIZE,
    LINUX_STACK_TOP,
};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};

use crate::vmm::{BhyveVcpu, BhyveVm};
use crate::vmm_x86::{
    VM_CAP_HALT_EXIT, VM_REG_GUEST_CR0, VM_REG_GUEST_CR2, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4,
    VM_REG_GUEST_CS, VM_REG_GUEST_DS, VM_REG_GUEST_EFER, VM_REG_GUEST_ES, VM_REG_GUEST_FS,
    VM_REG_GUEST_FS_BASE, VM_REG_GUEST_GDTR, VM_REG_GUEST_GS, VM_REG_GUEST_GS_BASE,
    VM_REG_GUEST_IDTR, VM_REG_GUEST_KGS_BASE, VM_REG_GUEST_LDTR, VM_REG_GUEST_R8, VM_REG_GUEST_R9,
    VM_REG_GUEST_R10, VM_REG_GUEST_R11, VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
    VM_REG_GUEST_R15, VM_REG_GUEST_RAX, VM_REG_GUEST_RBP, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX,
    VM_REG_GUEST_RDI, VM_REG_GUEST_RDX, VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP, VM_REG_GUEST_RSI,
    VM_REG_GUEST_RSP, VM_REG_GUEST_SS, VM_REG_GUEST_TR,
};

// ─── T6 memory layout (X86_MEM_* constants) ──────────────────────────────────
//
// All GPAs must fall within bhyve's lowmem window [0, X86_MEM_SIZE) because
// vm_map_gpa resolves host pointers ONLY inside the lowmem/highmem regions
// built by vm_setup_memory (Experiment 2: high-GPA probe FAILED; see module
// docs). The PML4 decouples guest VA from GPA so carrick's high guest VAs
// (LINUX_EL0_TRAMPOLINE_BASE = 0x2D_0000_0000, stack at 0xFF_FFFF_0000, etc.)
// map to compact low GPAs.

/// Total VM RAM for carrick's X86 bring-up: 64 MiB.
pub const X86_MEM_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// GPA of the ring-0 MSR init blob (also the initial vCPU RIP). The blob
/// WRMSRs LSTAR/STAR/SFMASK (Experiment 3: no vm_set_register path exists for
/// these MSRs — ring-0 WRMSR is the only route) then iretqs to ring-3.
pub const X86_INIT_BLOB_GPA: u64 = 0x10_0000; // 1 MiB

/// GPA of carrick's 5-entry boot GDT image (null/kCS64/kSS/uSS/uCS64).
pub const X86_GDT_GPA: u64 = 0x10_1000;

/// GPA of the LSTAR trampoline (the `entry_trampoline_bytes` stub).
pub const X86_LSTAR_GPA: u64 = 0x10_2000;

/// FXSAVE/FXRSTOR ring-3 stub code (one page; both stubs < 16 bytes total).
/// The gap 0x10_3000..0x20_0000 is free between the LSTAR stub and the PML4.
/// CR0.PG=1 at injection time, so the stub runs paged: it is identity-mapped
/// (VA==GPA) at bring-up, exactly like the init blob / LSTAR stub. SP3.2.
pub const X86_FP_STUB_GPA: u64 = 0x10_3000;
/// FP scratch region: one 4 KiB page PER vCPU (FXSAVE needs a 16-byte-aligned
/// 512B operand; a page-per-vCPU is trivially aligned and race-free across
/// sibling vCPUs that share this VM). 8 slots = hw.vmm.maxcpu. vCPU i uses
/// `X86_FP_SCRATCH_GPA + i*0x1000`. Identity-mapped supervisor read-write. SP3.2.
pub const X86_FP_SCRATCH_GPA: u64 = 0x10_4000;
/// Number of per-vCPU FP scratch slots (one 4 KiB page each).
pub const X86_FP_SCRATCH_SLOTS: u64 = 8;

/// GPA of the root PML4 table (also the CR3 value).
/// `LINUX_PAGE_TABLES_SIZE` = 0x1C0000 (1.75 MiB); end = 0x3C0000.
pub const X86_PML4_GPA: u64 = 0x20_0000; // 2 MiB

/// Stack top GPA: the vCPU RSP at ring-0 entry and after iretq to ring-3.
/// Stack is 8 MiB (LINUX_STACK_SIZE); bottom = 0x3FF_F000 - 8 MiB = 0x3BF_F000.
/// All within the 64 MiB lowmem window.
pub const X86_STACK_TOP_GPA: u64 = 0x3FF_F000;

/// Maximum PML4 table region capacity (must accommodate LINUX_PAGE_TABLES_SIZE).
pub const X86_PML4_CAPACITY: usize = LINUX_PAGE_TABLES_SIZE as usize;

// MSR numbers (AMD64 APM / Intel SDM / OSDev "SYSCALL/SYSRET"; NOT from kernel
// source). These are architectural constants, not Linux/glibc definitions.
/// STAR MSR: selects SYSCALL CS/SS and SYSRET CS/SS.
/// AMD APM vol. 2 §3.1.7 "Extended Feature Enable Register (EFER) and
/// SYSCALL/SYSRET Target Address Registers".
const MSR_STAR: u32 = 0xC000_0081;
/// LSTAR: 64-bit mode SYSCALL target RIP.
/// AMD APM vol. 2 §3.1.7; Intel SDM vol. 2B "SYSCALL".
const MSR_LSTAR: u32 = 0xC000_0082;
/// SF_MASK: flags cleared on SYSCALL entry.
/// AMD APM vol. 2 §3.1.7; Intel SDM vol. 2B "SYSCALL".
const MSR_SF_MASK: u32 = 0xC000_0084;

// VT-x segment access-rights format (Intel SDM vol. 3 Table 21-2 / VMX VMCS
// guest-state encoding).  Bits: [3:0] type, [4] S, [6:5] DPL, [7] P,
// [11:8] system-descriptor fields (unused for code/data), [13] L (64-bit
// code), [14] D/B, [15] G. Plus bit 16 = "unusable" (no valid selector).
/// Ring-0 64-bit code segment: P=1 S=1 type=0xA (exec/read) DPL=0 L=1.
/// Mirrors GDT[1] = 0x0020_9A00_0000_0000 (L=bit53, P=bit47, S=bit44,
/// type=bits43:40 = 0xA); translated to VMX access format.
const ACCESS_RING0_CS64: u32 = 0x209B; // P|S|exec/read|DPL0|L
/// Ring-0 data segment: P=1 S=1 type=0x2 (data/RW) DPL=0.
/// Mirrors GDT[2] = 0x0000_9200_0000_0000.
const ACCESS_RING0_SS: u32 = 0x0093; // P|S|data/RW|DPL0
/// Ring-3 data segment: P=1 S=1 type=0x2 (data/RW) DPL=3.
/// Mirrors GDT[3] = 0x0000_F200_0000_0000.
/// Ring-3 data segment access rights (the user SS/DS/ES/FS/GS value the iretq
/// latches from GDT[3]). The iretq loads these from the GDT on the privilege
/// change, so they are not pre-programmed; kept for the GDT-encoding unit tests
/// and the (blocked) ring-3 entry work — see the M1 iretq blocker note.
#[allow(dead_code)]
const ACCESS_RING3_SS: u32 = 0x00F3; // P|S|data/RW|DPL3
/// Ring-3 64-bit code segment: P=1 S=1 type=0xA (exec/read) DPL=3 L=1.
/// Mirrors GDT[4] = 0x0020_FA00_0000_0000 (latched by the iretq from the GDT).
#[allow(dead_code)]
const ACCESS_RING3_CS64: u32 = 0x20FB; // P|S|exec/read|DPL3|L
/// "Unusable" segment: bit 16 set — the selector is not loaded.
/// Applied to DS/ES/FS/GS at ring-0 entry (the data segments are only needed
/// at ring-3; the init blob loads them via iretq + iret ABI after SYSRET).
const ACCESS_UNUSABLE: u32 = 0x0001_0000; // Intel SDM vol. 3 §21.5.1
/// LDT unusable: S=0 (system), unusable. vmm.ko requires non-zero access for
/// LDTR even when unused.
const ACCESS_LDT_UNUSABLE: u32 = 0x0001_0082; // system + unusable
/// TSS64 available: P=1 S=0 type=0x9 (64-bit TSS available).
/// Required by VT-x — a valid TSS must be present (Intel SDM vol. 3 §21.2.5).
const ACCESS_TSS64: u32 = 0x008B; // P|system|type=9 (TSS available)
/// Ring-3 data segment for DS/ES/FS/GS (= `ACCESS_RING3_SS`); latched by the
/// iretq from the GDT on the ring-3 transition. Kept for the (blocked) ring-3
/// entry work — see the M1 iretq blocker note.
#[allow(dead_code)]
const ACCESS_RING3_DATA: u32 = 0x00F3; // = ACCESS_RING3_SS

// Ring-3 selector values (SS/CS fields; RPL is encoded in the low 2 bits).
// These match the SYSRET arithmetic in x8664_arch.rs::star_selector_arithmetic.
/// User CS64 selector: GDT[4]=0x20 | RPL3=3 → 0x23.
const USER_CS64_SEL: u64 = 0x23;
/// User SS selector: GDT[3]=0x18 | RPL3=3 → 0x1B.
const USER_SS_SEL: u64 = 0x1B;
/// Kernel CS64 selector: GDT[1]=0x08.
const KERN_CS64_SEL: u64 = 0x08;
/// Kernel SS selector: GDT[2]=0x10.
const KERN_SS_SEL: u64 = 0x10;

/// The syscall doorbell port: the `SENTINEL_GPA` analogue. The LSTAR stub's
/// `OUT %al, $0xC5` lands here (spec §6 vehicle (a)).
///
/// Single-sourced from `carrick_hal::x8664_arch` (the same const the
/// `entry_trampoline_bytes` emitter derives its immediate from), re-exported here
/// so bhyve call sites keep referring to it via `guest_setup_x86`.
pub use carrick_hal::SYSCALL_DOORBELL_PORT;
/// Reserved for M3 (TLB-shootdown completion / maintenance doorbell).
pub const MAINT_DOORBELL_PORT: u16 = 0xC6;
/// The FP-stub doorbell port (distinct from the syscall doorbell `0xC5`): the
/// FXSAVE/FXRSTOR ring-3 stubs `OUT %al,$0xC6` here to signal completion, so
/// `run_fp_stub` knows the stub finished and `next_syscall` never confuses the
/// two. Shares the `0xC6` ordinal with the (still-unused, M3-reserved)
/// `MAINT_DOORBELL_PORT`; SP3.2 is the first live user of `0xC6`.
pub const FP_STUB_DOORBELL_PORT: u16 = 0xC6;

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

// ─── M1 blob ─────────────────────────────────────────────────────────────────

/// User VA for the M1 ring-3 blob and inline message.
/// Placed at 0x40_0000 (4 MiB) — low user space, well below the carrick
/// layout constants, easy to hand-encode in 32-bit immediates.
pub const M1_BLOB_VA: u64 = 0x40_0000;

/// M1 ring-3 blob: `write(1, "hello\n", 6)` then `exit_group(0)` via real
/// SYSCALL instructions.  Uses **x86_64 syscall numbers** (write=1,
/// exit_group=231); the host remaps them to canonical (64, 94) via
/// [`X8664SyscallTable::remap`].
///
/// Byte encoding (AMD64 APM vol. 3 / OSDev ISA reference; offsets from
/// [`M1_BLOB_VA`]). The code is exactly 0x21 (33) bytes — counting
/// 5+5+5+5+2+2+5+2+2 — and the msg follows immediately at 0x21:
/// ```text
/// +0x00  bf 01 00 00 00   mov  $1, %edi          ; fd = stdout
/// +0x05  be 21 00 40 00   mov  $0x400021, %esi   ; buf = M1_BLOB_VA + 0x21
/// +0x0a  ba 06 00 00 00   mov  $6, %edx          ; count = 6
/// +0x0f  b8 01 00 00 00   mov  $1, %eax          ; __NR_write (x86_64) = 1
/// +0x14  0f 05            syscall
/// +0x16  31 ff            xor  %edi, %edi        ; status = 0
/// +0x18  b8 e7 00 00 00   mov  $231, %eax        ; __NR_exit_group (x86_64) = 231
/// +0x1d  0f 05            syscall
/// +0x1f  eb fe            jmp  .                 ; not reached (exit_group ends it)
/// +0x21  68 65 6c 6c 6f 0a  "hello\n"
/// ```
///
/// Total: 0x21 + 6 = 39 bytes; byte-pinned below.
pub fn m1_ring3_blob() -> Vec<u8> {
    // The code is exactly 0x21 (33) bytes — the four 5-byte movs (20) + two
    // 2-byte syscalls (4) + xor (2) + the 5-byte exit_group mov + the 2-byte
    // jmp = 33 — so msg follows IMMEDIATELY at offset 0x21. (An earlier 0x20
    // placement overlapped the jmp's second byte.)
    let msg_va_lo = (M1_BLOB_VA + 0x21) as u32; // fits in 32 bits (= 0x400021)
    let mut b: Vec<u8> = Vec::with_capacity(0x21 + 6);

    // mov $1, %edi  (BF id — opcode BF + 4-byte imm, Intel SDM vol. 2A "MOV")
    b.push(0xBF);
    b.extend_from_slice(&1u32.to_le_bytes());

    // mov $msg_va, %esi  (BE id)
    b.push(0xBE);
    b.extend_from_slice(&msg_va_lo.to_le_bytes());

    // mov $6, %edx  (BA id)
    b.push(0xBA);
    b.extend_from_slice(&6u32.to_le_bytes());

    // mov $1, %eax  (B8 id) — __NR_write (x86_64)
    b.push(0xB8);
    b.extend_from_slice(&1u32.to_le_bytes());

    // syscall  (0F 05, Intel SDM vol. 2B "SYSCALL")
    b.push(0x0F);
    b.push(0x05);

    // xor %edi, %edi  (31 FF, Intel SDM vol. 2A "XOR")
    b.push(0x31);
    b.push(0xFF);

    // mov $231, %eax  (B8 id) — __NR_exit_group (x86_64)
    b.push(0xB8);
    b.extend_from_slice(&231u32.to_le_bytes());

    // syscall  (0F 05)
    b.push(0x0F);
    b.push(0x05);

    // jmp .  (EB FE — short backward jmp; not reached)
    b.push(0xEB);
    b.push(0xFE);

    // Code complete at offset 0x21 (33); msg follows with no padding.
    assert_eq!(b.len(), 0x21, "M1 code must be exactly 0x21 (33) bytes");

    // msg: "hello\n" at offset 0x21
    b.extend_from_slice(b"hello\n");

    b
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

/// SP3.2 FXSAVE/FXRSTOR ring-3 stub bytes (16 bytes, two 8-byte slots).
///
/// libvmmapi exposes no FP getter, so carrick reads/writes the live vCPU FP by
/// redirecting RIP to one of these stubs (with `RDI = scratch GPA`) and running
/// until the FP doorbell (`OUT %al,$0xC6`). FXSAVE is non-destructive; FXRSTOR
/// loads FP only — so after the stub the vCPU is byte-identical (run_fp_stub
/// restores the saved RIP/RAX/RDI/RFLAGS).
///
/// Encodings (AMD64 APM vol. 3 / Intel SDM vol. 2A "FXSAVE"/"FXRSTOR"):
/// ```text
///   fxsave  (%rdi)    0F AE 07     ; capture FP into [rdi]=scratch  (slot +0)
///   fxrstor (%rdi)    0F AE 0F     ; load FP from [rdi]=scratch     (slot +8)
///   out %al,$0xC6     E6 C6        ; FP doorbell (FP_STUB_DOORBELL_PORT)
///   jmp .             EB FE        ; park (never reached: host restores RIP)
/// ```
/// `fxsave_stub` at +0, `fxrstor_stub` at +8 (each padded to 8 bytes).
pub fn fp_stub_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    // fxsave (%rdi); out %al,$0xC6; jmp .
    b[0..7].copy_from_slice(&[0x0F, 0xAE, 0x07, 0xE6, 0xC6, 0xEB, 0xFE]);
    // fxrstor (%rdi); out %al,$0xC6; jmp .
    b[8..15].copy_from_slice(&[0x0F, 0xAE, 0x0F, 0xE6, 0xC6, 0xEB, 0xFE]);
    b
}

/// Write the SP3.2 FXSAVE/FXRSTOR stubs into [`X86_FP_STUB_GPA`].
fn write_fp_stub(vm: &BhyveVm) -> Result<(), OsError> {
    write_gpa(vm, X86_FP_STUB_GPA, &fp_stub_bytes())
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

// ─── T6: BhyveGuestRam ───────────────────────────────────────────────────────

/// A single VA→GPA mapping window in bhyve guest RAM.
///
/// Because the high-GPA probe FAILED (Experiment 2: `vm_map_gpa` returns NULL
/// for GPAs outside lowmem/highmem), GPAs are allocated compactly from a bump
/// cursor rather than identity-placed. The PML4 decouples guest VA from GPA,
/// so carrick's guest-virtual layout is unaffected.
#[derive(Clone, Debug)]
pub struct BhyveWindow {
    /// Guest virtual address this window is mapped at.
    pub va: u64,
    /// Guest physical address (compact, within lowmem/highmem).
    pub gpa: u64,
    /// Size in bytes (page-aligned).
    pub len: usize,
    /// U/S bit set at every PML4 level (ring-3 readable).
    pub user: bool,
    /// R/W bit set (writable pages).
    pub write: bool,
    /// NX clear (executable pages; only meaningful with EFER.NXE=1).
    pub exec: bool,
}

/// Guest RAM bookkeeping for the carrick x86_64/bhyve backend.
///
/// Owns the VM's memory contract: windows are planned (VA→GPA assignment),
/// then a single `vm_setup_memory` covers the whole lowmem region, and one
/// `mmap_memseg` per window registers it. Host-accessible pointers are cached
/// per window via `vm_map_gpa` (stable for the VM's lifetime).
///
/// # GPA allocation
///
/// `plan_gpa` is a monotonic bump allocator starting at [`X86_GPA_CURSOR_START`].
/// Because the high-GPA probe FAILED (Experiment 2) all GPAs stay in lowmem
/// `[0, X86_MEM_SIZE)` so that `vm_map_gpa` can resolve host pointers.
///
/// # `Clone` (sibling vCPUs, Tier 2)
///
/// `BhyveGuestRam` is plain bookkeeping — a `Vec<BhyveWindow>` of VA→GPA window
/// descriptors plus the bump `cursor`. It owns NO host mappings and has NO
/// `Drop`: the kernel-owned guest RAM is freed exactly once by
/// `BhyveVmInner::drop` (`vm_destroy`), and `BhyveTrapEngine::va_to_host`
/// re-resolves every host pointer through `vm_map_gpa` per access (nothing is
/// cached). A `clone()` therefore yields an independent view that resolves the
/// SAME guest physical memory via the shared ctx — exactly what a sibling vCPU
/// on the same VM needs. (Contrast the KVM lane, which owns host mmaps and so
/// needs a non-owning `from_shared_windows` view; bhyve's clone is sufficient.)
#[derive(Clone)]
pub struct BhyveGuestRam {
    /// Planned VA→GPA windows (immutable after `map`).
    pub windows: Vec<BhyveWindow>,
    /// Bump cursor: next available GPA (starts at `X86_GPA_CURSOR_START`).
    cursor: u64,
}

/// Starting point for the bump allocator: 1 MiB (below the reserved 1 MiB
/// BIOS/ROM region; we skip it to match typical x86 firmware conventions and
/// avoid collisions with the ring-0 init blob / GDT / LSTAR GPA constants
/// above, which are placed at explicit fixed GPAs). Windows whose GPAs come
/// from `plan_gpa` start here and advance monotonically.
pub const X86_GPA_CURSOR_START: u64 = 0x40_0000; // 4 MiB — above init blob/GDT/LSTAR/PML4

impl BhyveGuestRam {
    /// Create an empty RAM plan.
    pub fn new() -> Self {
        Self {
            windows: Vec::new(),
            cursor: X86_GPA_CURSOR_START,
        }
    }

    /// Allocate a compact GPA for a window of `len` bytes (page-aligned).
    ///
    /// The returned GPA is within `[X86_GPA_CURSOR_START, X86_MEM_SIZE)`. If
    /// the bump cursor would exceed `X86_MEM_SIZE`, the function returns an
    /// error (the total footprint is small in Phase 2; this is a static guard,
    /// not a policy decision).
    pub fn plan_gpa(&mut self, len: usize) -> Result<u64, OsError> {
        // Round len up to the next 4 KiB boundary.
        let len_aligned = (len as u64 + 0xFFF) & !0xFFF;
        let gpa = self.cursor;
        let next = gpa
            .checked_add(len_aligned)
            .filter(|&end| end <= X86_MEM_SIZE as u64)
            .ok_or_else(|| {
                OsError::new(format!(
                    "bhyve: BhyveGuestRam: GPA overflow — need {len_aligned:#x} bytes at \
                     cursor {gpa:#x} but X86_MEM_SIZE = {X86_MEM_SIZE:#x}"
                ))
            })?;
        self.cursor = next;
        Ok(gpa)
    }

    /// Add a window with a pre-chosen GPA (for fixed-GPA placements like the
    /// init blob, GDT, LSTAR stub, and PML4 tables).
    pub fn add_fixed(
        &mut self,
        va: u64,
        gpa: u64,
        len: usize,
        user: bool,
        write: bool,
        exec: bool,
    ) {
        self.windows.push(BhyveWindow {
            va,
            gpa,
            len,
            user,
            write,
            exec,
        });
    }

    /// Add a window at the next bump-cursor GPA, returning the assigned GPA.
    pub fn add_bump(
        &mut self,
        va: u64,
        len: usize,
        user: bool,
        write: bool,
        exec: bool,
    ) -> Result<u64, OsError> {
        let gpa = self.plan_gpa(len)?;
        self.windows.push(BhyveWindow {
            va,
            gpa,
            len,
            user,
            write,
            exec,
        });
        Ok(gpa)
    }

    /// The total GPA footprint (exclusive end of the highest window).
    pub fn total_size(&self) -> usize {
        self.cursor as usize
    }
}

impl Default for BhyveGuestRam {
    fn default() -> Self {
        Self::new()
    }
}

// ─── T6: carrick 5-entry GDT image ───────────────────────────────────────────

/// carrick's 5-entry boot GDT image (null/kCS64/kSS/uSS/uCS64), serialized
/// to 40 bytes.
///
/// This is the GDT the 5-entry [`X8664BootSysregs::gdt`] encodes; the values
/// here must match exactly (they ARE the same constants, laid out for
/// `write_gpa`). The 5-entry layout is required by the SYSRET selector
/// arithmetic (AMD APM vol. 2 §3.1.7): the user-base field of STAR (0x13)
/// maps uSS to GDT[3]=0x18 and uCS64 to GDT[4]=0x20 post-RPL-OR.
///
/// Bytes are little-endian GDT descriptor words, matching the Intel SDM
/// vol. 3 §3.4.5 encoding in [`X8664BootSysregs`].
pub fn carrick_boot_gdt_bytes() -> Vec<u8> {
    let regs = X8664GuestArch::bootstrap_sysregs();
    let mut out = Vec::with_capacity(8 * GDT_LEN);
    for entry in &regs.gdt {
        out.extend_from_slice(&entry.to_le_bytes());
    }
    out
}

// ─── T6: ring-0 MSR init blob ────────────────────────────────────────────────

/// Build the ring-0 MSR init blob that writes LSTAR/STAR/SFMASK and then
/// iretqs into ring-3.
///
/// # Why this blob exists (Experiment 3)
///
/// `enum vm_reg_name` has no slots for LSTAR/STAR/SFMASK; `vm_set_register`
/// rejects IDs above 48 with EINVAL; no `vm_set_msr` ioctl exists in
/// `vmmapi.h`/`vmm_dev.h`. The only way to program these MSRs is a guest
/// ring-0 WRMSR: VT-x's MSR bitmap passes these writes through to hardware
/// directly (no VM_EXITCODE_WRMSR surfaces), and `vmx_msr_guest_enter` saves
/// and restores them across every VM entry/exit (Experiment 3, confirmed live).
///
/// # Encoding sources
///
/// - `mov ecx, imm32`: opcode B9 + 4-byte imm (Intel SDM vol. 2A "MOV").
/// - `mov eax, imm32`: opcode B8 + 4-byte imm (Intel SDM vol. 2A "MOV").
/// - `mov edx, imm32`: opcode BA + 4-byte imm (Intel SDM vol. 2A "MOV").
/// - `wrmsr`: opcode 0F 30 (Intel SDM vol. 2B "WRMSR").
/// - `mov rax, imm64`: REX.W(48) + B8 + 8-byte imm (Intel SDM vol. 2A).
/// - `push rax`: opcode 50 (Intel SDM vol. 2B "PUSH").
/// - `iretq`: REX.W(48) + CF (Intel SDM vol. 2A "IRET/IRETD/IRETQ").
///
/// # iretq frame layout
///
/// In 64-bit mode iretq pops five 64-bit values from the stack:
/// `[ SS | RSP | RFLAGS | CS | RIP ]` (SS at highest address, RIP at lowest,
/// i.e. SS is pushed first before any decrement, RIP last).
///
/// Push order (highest first): SS → RSP → RFLAGS → CS → RIP; then iretq.
///
/// `push imm32` (opcode 68 ib) sign-extends to 64 bits — fine for the small
/// selector/RFLAGS values. For `user_rip` and `user_rsp` we use
/// `mov rax, imm64; push rax` (11 bytes each) because the high VAs exceed
/// 32-bit sign extension range.
///
/// # Parameters
///
/// - `lstar`: LSTAR value (typically [`LINUX_EL0_TRAMPOLINE_BASE`]).
/// - `star`: STAR value (typically `0x0013_0008_0000_0000`).
/// - `sfmask`: SF_MASK value (typically `0x0004_0700`).
/// - `user_rip`: ring-3 RIP to jump to after iretq.
/// - `user_rsp`: ring-3 RSP (guest stack top GPA mapped to user VA).
/// - `user_rflags`: RFLAGS to restore in ring-3 (typically 0x2).
/// - `clear_rax`: when true, emit `xor eax, eax` (31 C0) IMMEDIATELY before the
///   `iretq`. The frame pushes use RAX as scratch for the large `user_rip`/
///   `user_rsp` (`mov rax, imm64; push rax`), so RAX is clobbered to `user_rip`
///   by the end of the pushes. A child returning from a `clone(2)` syscall must
///   see `rax = 0`; zeroing RAX after the pushes (but before iretq) delivers
///   that. The boot ELF `_start` ignores the inbound RAX, so the boot call site
///   passes `false`.
pub fn msr_init_blob(
    lstar: u64,
    star: u64,
    sfmask: u64,
    user_rip: u64,
    user_rsp: u64,
    user_rflags: u64,
    clear_rax: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);

    // Helper: emit WRMSR(msr, val).  All three SYSCALL MSRs fit in EDX:EAX.
    let mut wrmsr = |msr: u32, val: u64| {
        let lo = (val & 0xFFFF_FFFF) as u32;
        let hi = (val >> 32) as u32;
        // mov ecx, msr_num  (B9 id)
        b.push(0xB9);
        b.extend_from_slice(&msr.to_le_bytes());
        // mov eax, lo       (B8 id)
        b.push(0xB8);
        b.extend_from_slice(&lo.to_le_bytes());
        // mov edx, hi       (BA id)
        b.push(0xBA);
        b.extend_from_slice(&hi.to_le_bytes());
        // wrmsr             (0F 30)
        b.push(0x0F);
        b.push(0x30);
    };

    // LSTAR WRMSR
    wrmsr(MSR_LSTAR, lstar);
    // STAR WRMSR
    wrmsr(MSR_STAR, star);
    // SF_MASK WRMSR
    wrmsr(MSR_SF_MASK, sfmask);

    // Build iretq frame.  push imm32 sign-extends; push rax from imm64 for
    // large values (user_rip and user_rsp can exceed 0x7FFF_FFFF).
    let push_u64 = |b: &mut Vec<u8>, val: u64| {
        // mov rax, imm64  (REX.W B8 + 8-byte imm)
        b.push(0x48);
        b.push(0xB8);
        b.extend_from_slice(&val.to_le_bytes());
        // push rax  (50)
        b.push(0x50);
    };

    // SS (selector, small — push imm32 sign-extends to 0x0000_0000_0000_001B)
    b.push(0x68); // push imm32
    b.extend_from_slice(&(USER_SS_SEL as u32).to_le_bytes());

    // RSP (large VA — use mov+push)
    push_u64(&mut b, user_rsp);

    // RFLAGS (small — push imm32)
    b.push(0x68);
    b.extend_from_slice(&(user_rflags as u32).to_le_bytes());

    // CS (selector, small)
    b.push(0x68);
    b.extend_from_slice(&(USER_CS64_SEL as u32).to_le_bytes());

    // RIP (large VA — use mov+push)
    push_u64(&mut b, user_rip);

    // Optionally zero RAX (xor eax, eax = 31 C0) so a clone(2) child sees
    // rax = 0. Placed AFTER the frame pushes (which clobber RAX via the
    // mov rax, imm64 scratch) but BEFORE the iretq.
    if clear_rax {
        b.push(0x31);
        b.push(0xC0);
    }

    // iretq  (REX.W CF)
    b.push(0x48);
    b.push(0xCF);

    b
}

// ─── T6: BhyveGuestRam PML4 map specs ────────────────────────────────────────

/// Build the [`Pml4MapSpec`] slice that maps carrick's high guest VAs to the
/// compact low GPAs assigned in `ram`.  Called after all windows have been
/// planned.
pub fn pml4_map_specs(ram: &BhyveGuestRam) -> Vec<Pml4MapSpec> {
    ram.windows
        .iter()
        .map(|w| Pml4MapSpec {
            va: w.va,
            gpa: w.gpa,
            len: w.len as u64,
            user: w.user,
            write: w.write,
            exec: w.exec,
        })
        .collect()
}

// ─── T6: BroughtUpX86 + bring_up_x86 ─────────────────────────────────────────

/// A fully programmed carrick x86_64/bhyve vCPU, ready to run.
///
/// The vCPU starts in ring-0 at [`X86_INIT_BLOB_GPA`]: the ring-0 MSR init
/// blob (built by [`msr_init_blob`]) WRMSRs LSTAR/STAR/SFMASK and then iretqs
/// into ring-3 at `user_rip`.
pub struct BroughtUpX86 {
    pub vm: BhyveVm,
    pub vcpu: BhyveVcpu,
    pub ram: BhyveGuestRam,
    /// GPA of the ring-3 `fxsave (%rdi)` + doorbell stub (SP3.2). `run_fp_stub`
    /// redirects the vCPU here to capture the live FP that libvmmapi cannot read.
    pub fxsave_stub_gpa: u64,
    /// GPA of the ring-3 `fxrstor (%rdi)` + doorbell stub (SP3.2).
    pub fxrstor_stub_gpa: u64,
    /// GPA of vCPU 0's 4 KiB / 16-aligned FP scratch page (FXSAVE/FXRSTOR
    /// operand). Sibling vCPUs get a distinct slot in `materialize_sibling`.
    pub fp_scratch_gpa: u64,
}

/// Bring up a carrick x86_64/bhyve vCPU with carrick-owned long-mode ring-3
/// programming.
///
/// # Programming sequence
///
/// 1. Plan the GPA windows (fixed placements for kernel artifacts; bump cursor
///    for user stack and `user_rip` page).
/// 2. `vm_setup_memory(X86_MEM_SIZE)` + `mmap_memseg(0, …)` for the whole
///    lowmem region.
/// 3. Write artifacts: ring-0 MSR init blob at [`X86_INIT_BLOB_GPA`]; carrick
///    5-entry GDT at [`X86_GDT_GPA`]; LSTAR trampoline at [`X86_LSTAR_GPA`];
///    PML4 tables at [`X86_PML4_GPA`].
/// 4. Program vCPU via `vm_set_register` + `vm_set_desc`:
///    - CR0/CR4/EFER from `X8664GuestArch::bootstrap_sysregs()` (EFER = 0xD01,
///      overriding `vm_setup_freebsd_registers`'s 0x1500 — adds SCE+NXE).
///    - CS = uCS64 (0x23, ring-3 pre-loaded for VT-x iretq); SS = uSS (0x1B,
///      ring-3); DS/ES/FS/GS = user data (0x1B, ACCESS_RING3_DATA).  VT-x
///      requires the hidden descriptor fields for any iretq-loaded selector to
///      be programmed BEFORE vm_run (Intel SDM vol. 3 §21.3.1.2); setting them
///      to ring-3 values here is idempotent — the init blob only executes
///      WRMSRs then iretq (no data-segment access at ring-0).
///    - GDTR = carrick's 5-entry GDT (base = `X86_GDT_GPA`, limit = 5*8-1 = 39).
///    - IDTR = base 0, limit 0 (valid-but-empty; SFMASK masks IF; ring-3
///      exceptions become VM exits per spec §4.3/§6; real IDT is M3).
///    - TR = TSS64 at base 0, limit 0x67 (minimum 64-bit TSS size per Intel
///      SDM vol. 3 §7.2.1 — vmm.ko requires a valid TSS).
///    - LDTR = unusable (no LDT in Phase 2).
///    - RIP = `X86_INIT_BLOB_GPA`; RSP = `LINUX_STACK_TOP` (guest VA); RFLAGS = 0x2.
///    - CR3 = `X86_PML4_GPA` (the PML4 root GPA).
/// 5. Enable `VM_CAP_HALT_EXIT`.
///
/// # LSTAR/STAR/SFMASK
///
/// These MSRs are NOT in `enum vm_reg_name`; no `vm_set_msr` ioctl exists
/// (Experiment 3). They are programmed by the ring-0 init blob via WRMSR from
/// CPL 0. VT-x's MSR bitmap lets these writes through directly to hardware;
/// `vmx_msr_guest_enter` saves/restores them across VM entry/exit.
pub fn bring_up_x86() -> Result<BroughtUpX86, OsError> {
    let regs = X8664GuestArch::bootstrap_sysregs();

    // ── Step 1: plan GPA windows ──────────────────────────────────────────
    //
    // Fixed-GPA windows for kernel-private artifacts (not user-visible).
    // Bump-cursor windows for the user stack (stack grows down from top).
    //
    // All GPA constants are within lowmem [0, X86_MEM_SIZE) so vm_map_gpa
    // can resolve host pointers (Experiment 2).

    let mut ram = BhyveGuestRam::new();

    // Ring-0 init blob: kernel VA = GPA (no user mapping needed).  Not in
    // the PML4 at all — the vCPU starts in ring-0 and runs it before paging
    // is established... actually paging IS on (CR0.PG=1), so we need the
    // blob to be accessible. We map it supervisor (user=false).
    // VA for the init blob = GPA (identity for kernel artifacts).
    // One full page: the window len fed to the PML4 codec must be 4 KiB-granular
    // (the blob itself is ~70 bytes; a page is the minimum mappable unit).
    let blob_size = 4096;
    ram.add_fixed(
        X86_INIT_BLOB_GPA,
        X86_INIT_BLOB_GPA,
        blob_size,
        false, // supervisor
        false, // read-only (exec=true below for page walk, but blob is kernel code)
        true,  // exec
    );

    // GDT: also kernel/supervisor.
    ram.add_fixed(X86_GDT_GPA, X86_GDT_GPA, 4096, false, false, false);

    // LSTAR trampoline: kernel code; but it needs to be reachable from the
    // LSTAR GPA. carrick uses LINUX_EL0_TRAMPOLINE_BASE as the LSTAR VA.
    // We map: LSTAR_VA → X86_LSTAR_GPA (supervisor exec, no user bit needed
    // since LSTAR handler runs at CPL 0 — the hardware loads RIP, not a
    // user-space descriptor).
    ram.add_fixed(
        LINUX_EL0_TRAMPOLINE_BASE,
        X86_LSTAR_GPA,
        4096,
        false,
        false,
        true,
    );

    // SP3.2 FP stub code: identity-mapped supervisor exec. Runs at the CURRENT
    // CPL when run_fp_stub redirects RIP here. run_fp_stub only invokes it from a
    // CPL-0 boundary (the SP3 syscall path; the SP4.1 async path is CPL 3 and
    // SKIPS FP capture — fxsave #UDs at ring 3, see the run_fp_stub gate), so a
    // supervisor mapping is correct.
    ram.add_fixed(X86_FP_STUB_GPA, X86_FP_STUB_GPA, 4096, false, false, true);
    // SP3.2 FP scratch: identity-mapped supervisor read-write, one page per vCPU.
    ram.add_fixed(
        X86_FP_SCRATCH_GPA,
        X86_FP_SCRATCH_GPA,
        (X86_FP_SCRATCH_SLOTS as usize) * 4096,
        false,
        true,
        false,
    );

    // PML4 tables: supervisor, no user bit, read-write.
    ram.add_fixed(
        LINUX_PAGE_TABLES_BASE,
        X86_PML4_GPA,
        X86_PML4_CAPACITY,
        false,
        true,
        false,
    );

    // User stack: LINUX_STACK_TOP is the top; stack grows down.
    // VA range: [LINUX_STACK_TOP - LINUX_STACK_SIZE, LINUX_STACK_TOP).
    let stack_va_bottom = LINUX_STACK_TOP - LINUX_STACK_SIZE;
    // The returned GPA is unused: the RSP is the stack-top VA (LINUX_STACK_TOP),
    // and the window→GPA resolution happens through the PML4 / vm_map_gpa cache.
    // add_bump is called for its side effect of registering the stack window.
    ram.add_bump(
        stack_va_bottom,
        LINUX_STACK_SIZE as usize,
        true,
        true,
        false,
    )?;

    // ── Step 2: vm_setup_memory + mmap_memseg ────────────────────────────

    let mut vm = BhyveVm::create()?;
    vm.setup_memory(X86_MEM_SIZE)?;
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, X86_MEM_SIZE, PROT_RWX)?;

    // ── Step 3: write artifacts ───────────────────────────────────────────

    // Ring-0 MSR init blob: WRMSRs LSTAR/STAR/SFMASK, then iretqs to the
    // LSTAR trampoline VA at ring-3. The trampoline immediately issues the
    // doorbell OUT + sysretq, so user_rip = LINUX_EL0_TRAMPOLINE_BASE.
    // user_rsp = the stack top GPA (ring-3 RSP after iretq).
    let blob = msr_init_blob(
        regs.lstar,
        regs.star,
        regs.sfmask,
        LINUX_EL0_TRAMPOLINE_BASE, // ring-3 RIP after iretq
        // T7 RSP fix: with CR0.PG=1 the vCPU is in paged mode when iretq runs,
        // so RSP in the iretq frame is a guest VIRTUAL address (not a GPA).
        // The stack window maps VA [LINUX_STACK_TOP-LINUX_STACK_SIZE,
        // LINUX_STACK_TOP) → bump GPA stack_gpa..stack_top_gpa, so the correct
        // ring-3 RSP is the stack-top VA = LINUX_STACK_TOP (rounded down 16-byte
        // aligned).  Using stack_top_gpa here would #PF on the first `push`
        // because that GPA is not mapped at itself in the PML4.
        LINUX_STACK_TOP, // ring-3 RSP after iretq (guest VA, not GPA)
        regs.rflags,     // RFLAGS (0x2)
        false,           // M1 trampoline path ignores the inbound RAX
    );
    write_gpa(&vm, X86_INIT_BLOB_GPA, &blob)?;

    // Carrick 5-entry GDT image.
    write_gpa(&vm, X86_GDT_GPA, &carrick_boot_gdt_bytes())?;

    // LSTAR trampoline (the ring-0 SYSCALL entry stub: OUT + sysretq).
    write_gpa(&vm, X86_LSTAR_GPA, &entry_trampoline_bytes())?;

    // SP3.2 FXSAVE/FXRSTOR stubs.
    write_fp_stub(&vm)?;

    // PML4 tables: map all the windows.
    let specs = pml4_map_specs(&ram);
    let tables = pml4_tables(&specs, X86_PML4_GPA, X86_PML4_CAPACITY)
        .map_err(|e| OsError::new(format!("bhyve: T6 PML4 build failed: {e:?}")))?;
    write_gpa(&vm, X86_PML4_GPA, &tables)?;

    // ── Step 4: program vCPU registers ───────────────────────────────────

    let mut vcpu = vm.add_vcpu()?;

    // Control registers.
    vcpu.set_reg_raw(VM_REG_GUEST_CR0, regs.cr0)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR3, X86_PML4_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR4, regs.cr4)?;
    // EFER = 0xD01 (SCE|LME|LMA|NXE): overrides vm_setup_freebsd_registers's
    // 0x1500 (LME|LMA without SCE/NXE).  EFER is in vm_reg_name (id 32).
    vcpu.set_reg_raw(VM_REG_GUEST_EFER, regs.efer)?;

    // General-purpose + RFLAGS.
    vcpu.set_reg_raw(VM_REG_GUEST_RIP, X86_INIT_BLOB_GPA)?;
    // T7 RSP fix: the vCPU starts in paged mode (CR0.PG=1) with the PML4
    // already mapped, so RSP must be a guest VA.  The ring-0 init blob itself
    // never touches the stack (no `push`/`call` before iretq), so this only
    // matters as the ring-0 selector value and as the RSP iretq-frame value
    // (which we already fixed above to LINUX_STACK_TOP).  Use LINUX_STACK_TOP
    // here for consistency — the kernel RSP is the same VA the user will land
    // on after iretq (stack grows down from LINUX_STACK_TOP).
    vcpu.set_reg_raw(VM_REG_GUEST_RSP, LINUX_STACK_TOP)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RFLAGS, regs.rflags)?;

    // Code and stack segment: ring-0 (the init blob runs at CPL 0 to WRMSR).
    // base=0, limit=0xFFFF_FFFF (4 GiB flat), L=1 for 64-bit code.
    vcpu.set_desc(
        VM_REG_GUEST_CS,
        0, // base
        0xFFFF_FFFF,
        ACCESS_RING0_CS64,
    )?;
    vcpu.set_reg_raw(VM_REG_GUEST_CS, KERN_CS64_SEL)?;

    vcpu.set_desc(VM_REG_GUEST_SS, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_reg_raw(VM_REG_GUEST_SS, KERN_SS_SEL)?;

    // DS/ES/FS/GS: unusable at ring-0 init (the init blob doesn't need
    // data segments; they become valid after iretq + syscall path).
    for reg in [
        VM_REG_GUEST_DS,
        VM_REG_GUEST_ES,
        VM_REG_GUEST_FS,
        VM_REG_GUEST_GS,
    ] {
        vcpu.set_desc(reg, 0, 0, ACCESS_UNUSABLE)?;
        vcpu.set_reg_raw(reg, 0)?;
    }

    // GDTR: carrick's 5-entry GDT.
    // limit = GDT_LEN * 8 - 1 = 5*8-1 = 39 (Intel SDM vol. 3 §2.4.3).
    vcpu.set_desc(VM_REG_GUEST_GDTR, X86_GDT_GPA, (GDT_LEN * 8 - 1) as u32, 0)?;

    // IDTR: valid-but-empty (base=0, limit=0; no real IDT in Phase 2).
    // ring-3 exceptions surface as VM exits (spec §4.3); SFMASK masks IF.
    vcpu.set_desc(VM_REG_GUEST_IDTR, 0, 0, 0)?;

    // LDTR: unusable (no LDT in Phase 2).
    vcpu.set_desc(VM_REG_GUEST_LDTR, 0, 0, ACCESS_LDT_UNUSABLE)?;
    vcpu.set_reg_raw(VM_REG_GUEST_LDTR, 0)?;

    // TR: 64-bit TSS available (VT-x requires a valid TSS; Intel SDM vol. 3
    // §7.2.1 minimum size = 0x67 bytes; use base=0 with the dummy GPA).
    vcpu.set_desc(VM_REG_GUEST_TR, 0, 0x67, ACCESS_TSS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_TR, 0)?;

    // ── Step 4b: ring-3 segment descriptors ──────────────────────────────
    //
    // The vCPU BOOTS IN RING 0 (CS/SS set to the kernel selectors above) so the
    // WRMSR init blob runs at CPL 0. The ring-3 transition is the blob's iretq,
    // which loads CS=0x23/SS=0x1B by walking the GDT and latching their hidden
    // state itself — VT-x does NOT require pre-loading the iretq target's hidden
    // state (the earlier theory that it did was wrong: it forced a CPL-3 boot
    // that #GP'd the WRMSRs, and the iretq triple-faults independently — see
    // docs/superpowers/notes/2026-06-13-m1-iretq-ring3-blocker.md). Here we only
    // give DS/ES/FS/GS valid RING-0 data descriptors for a clean VT-x entry; the
    // iretq nulls/reloads them on the privilege change per the architecture.
    for reg in [
        VM_REG_GUEST_DS,
        VM_REG_GUEST_ES,
        VM_REG_GUEST_FS,
        VM_REG_GUEST_GS,
    ] {
        vcpu.set_desc(reg, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
        vcpu.set_reg_raw(reg, KERN_SS_SEL)?;
    }

    // ── Step 5: capabilities ──────────────────────────────────────────────

    vcpu.set_capability(VM_CAP_HALT_EXIT, 1)?;

    Ok(BroughtUpX86 {
        vm,
        vcpu,
        ram,
        fxsave_stub_gpa: X86_FP_STUB_GPA,
        fxrstor_stub_gpa: X86_FP_STUB_GPA + 8,
        fp_scratch_gpa: X86_FP_SCRATCH_GPA, // slot 0 (the main vCPU)
    })
}

/// Bring up a carrick x86_64/bhyve vCPU for the M1 test: like [`bring_up_x86`]
/// but with an additional user-exec window for the M1 ring-3 blob and the
/// ring-3 entry RIP pointing at [`M1_BLOB_VA`].
///
/// The M1 blob is placed at [`M1_BLOB_VA`] (user/exec/read-only in the PML4).
/// The iretq frame targets `user_rip = M1_BLOB_VA` so the vCPU's first ring-3
/// instruction is the `mov $1, %edi` of the blob (which then issues SYSCALL).
pub fn bring_up_x86_m1() -> Result<BroughtUpX86, OsError> {
    let regs = X8664GuestArch::bootstrap_sysregs();

    let mut ram = BhyveGuestRam::new();

    // Fixed-GPA kernel windows (same as bring_up_x86).
    let blob_size = 4096;
    ram.add_fixed(
        X86_INIT_BLOB_GPA,
        X86_INIT_BLOB_GPA,
        blob_size,
        false,
        false,
        true,
    );
    ram.add_fixed(X86_GDT_GPA, X86_GDT_GPA, 4096, false, false, false);
    ram.add_fixed(
        LINUX_EL0_TRAMPOLINE_BASE,
        X86_LSTAR_GPA,
        4096,
        false,
        false,
        true,
    );
    // SP3.2 FP stub + scratch windows (identity-mapped supervisor).
    ram.add_fixed(X86_FP_STUB_GPA, X86_FP_STUB_GPA, 4096, false, false, true);
    ram.add_fixed(
        X86_FP_SCRATCH_GPA,
        X86_FP_SCRATCH_GPA,
        (X86_FP_SCRATCH_SLOTS as usize) * 4096,
        false,
        true,
        false,
    );
    ram.add_fixed(
        LINUX_PAGE_TABLES_BASE,
        X86_PML4_GPA,
        X86_PML4_CAPACITY,
        false,
        true,
        false,
    );

    // User stack.
    let stack_va_bottom = LINUX_STACK_TOP - LINUX_STACK_SIZE;
    let _stack_gpa = ram.add_bump(
        stack_va_bottom,
        LINUX_STACK_SIZE as usize,
        true,
        true,
        false,
    )?;

    // M1 user-code window: the ring-3 blob at M1_BLOB_VA (user, read-exec).
    // One 4 KiB page covers the 38-byte blob.
    let _m1_blob_gpa = ram.add_bump(M1_BLOB_VA, 4096, true, false, true)?;

    // VM setup.
    let mut vm = BhyveVm::create()?;
    vm.setup_memory(X86_MEM_SIZE)?;
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, X86_MEM_SIZE, PROT_RWX)?;

    // Kernel artifacts.
    let blob = msr_init_blob(
        regs.lstar,
        regs.star,
        regs.sfmask,
        M1_BLOB_VA,      // ring-3 RIP: entry of the M1 user code
        LINUX_STACK_TOP, // ring-3 RSP (guest VA)
        regs.rflags,
        false, // M1 user code ignores the inbound RAX
    );
    write_gpa(&vm, X86_INIT_BLOB_GPA, &blob)?;
    write_gpa(&vm, X86_GDT_GPA, &carrick_boot_gdt_bytes())?;
    write_gpa(&vm, X86_LSTAR_GPA, &entry_trampoline_bytes())?;
    write_fp_stub(&vm)?; // SP3.2 FXSAVE/FXRSTOR stubs

    // M1 ring-3 blob at its bump GPA (resolved through the PML4).
    let m1_gpa = ram
        .windows
        .iter()
        .find(|w| w.va == M1_BLOB_VA)
        .map(|w| w.gpa)
        .ok_or_else(|| OsError::new("bhyve: M1 blob window was not planned".to_string()))?;
    write_gpa(&vm, m1_gpa, &m1_ring3_blob())?;

    // PML4 tables.
    let specs = pml4_map_specs(&ram);
    let tables = pml4_tables(&specs, X86_PML4_GPA, X86_PML4_CAPACITY)
        .map_err(|e| OsError::new(format!("bhyve: M1 PML4 build failed: {e:?}")))?;
    write_gpa(&vm, X86_PML4_GPA, &tables)?;

    // vCPU register programming (same as bring_up_x86).
    let mut vcpu = vm.add_vcpu()?;

    vcpu.set_reg_raw(VM_REG_GUEST_CR0, regs.cr0)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR3, X86_PML4_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR4, regs.cr4)?;
    vcpu.set_reg_raw(VM_REG_GUEST_EFER, regs.efer)?;

    vcpu.set_reg_raw(VM_REG_GUEST_RIP, X86_INIT_BLOB_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RSP, LINUX_STACK_TOP)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RFLAGS, regs.rflags)?;

    // The vCPU BOOTS IN RING 0 to run the WRMSR init blob (WRMSR is CPL-0
    // only). Initial segments are the KERNEL (DPL-0) selectors/descriptors —
    // identical to bring_up_x86. The ring-3 transition is the init blob's
    // iretq, whose frame carries USER_CS64_SEL(0x23)/USER_SS_SEL(0x1B); the
    // iretq reloads CS/SS from the GDT (entries 4/3) at that point. (Setting
    // the initial segments to the user selectors was the M1 triple-fault: the
    // blob couldn't WRMSR at CPL 3 and the iretq state was inconsistent.)
    vcpu.set_desc(VM_REG_GUEST_CS, 0, 0xFFFF_FFFF, ACCESS_RING0_CS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CS, KERN_CS64_SEL)?;

    vcpu.set_desc(VM_REG_GUEST_SS, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_reg_raw(VM_REG_GUEST_SS, KERN_SS_SEL)?;

    for reg in [
        VM_REG_GUEST_DS,
        VM_REG_GUEST_ES,
        VM_REG_GUEST_FS,
        VM_REG_GUEST_GS,
    ] {
        vcpu.set_desc(reg, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
        vcpu.set_reg_raw(reg, KERN_SS_SEL)?;
    }

    vcpu.set_desc(VM_REG_GUEST_GDTR, X86_GDT_GPA, (GDT_LEN * 8 - 1) as u32, 0)?;
    vcpu.set_desc(VM_REG_GUEST_IDTR, 0, 0, 0)?;
    vcpu.set_desc(VM_REG_GUEST_LDTR, 0, 0, ACCESS_LDT_UNUSABLE)?;
    vcpu.set_reg_raw(VM_REG_GUEST_LDTR, 0)?;
    vcpu.set_desc(VM_REG_GUEST_TR, 0, 0x67, ACCESS_TSS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_TR, 0)?;

    vcpu.set_capability(VM_CAP_HALT_EXIT, 1)?;

    Ok(BroughtUpX86 {
        vm,
        vcpu,
        ram,
        fxsave_stub_gpa: X86_FP_STUB_GPA,
        fxrstor_stub_gpa: X86_FP_STUB_GPA + 8,
        fp_scratch_gpa: X86_FP_SCRATCH_GPA,
    })
}

// ─── T10: bring_up_x86_elf ───────────────────────────────────────────────────

/// M2-grade cap on large runtime windows: max bytes we allocate in bhyve's
/// 64 MiB lowmem for the heap / mmap / sigreturn / shared / overlay regions.
/// A static musl hello only touches a handful of pages; these caps leave room
/// for all other windows while fitting within `X86_MEM_SIZE`.
pub const M2_HEAP_CAP: usize = 4 * 1024 * 1024; // 4 MiB
pub const M2_MMAP_CAP: usize = 16 * 1024 * 1024; // 16 MiB
/// Miscellaneous small regions (sigreturn trampoline, shared/private apertures):
/// each capped to one page.  These are not reachable in M2's run-to-exit path.
pub const M2_MISC_CAP: usize = 4096; // 1 page

/// Bring up a carrick x86_64/bhyve vCPU from a fully loaded [`AddressSpace`].
///
/// Mirrors [`bring_up_x86_m1`] but maps ALL regions from `image.regions()` as
/// bhyve windows instead of a hard-coded user blob, then sets the vCPU's ring-3
/// entry `RIP = entry_rip` and `RSP = initial_rsp`.
///
/// # Memory model (M2)
///
/// Each `MemoryRegion` → one `BhyveGuestRam` bump window with a compact GPA.
/// Large "synthetic" runtime windows (heap 128 MiB, mmap arena 32 GiB, shared
/// aperture, private overlay) are CAPPED to `M2_*_CAP` so they fit within
/// bhyve's 64 MiB lowmem. The run-to-exit service loop (brk/mmap handlers)
/// uses these same caps as the upper bounds for their bump allocators.
///
/// # VA→GPA
///
/// High guest VAs (heap at 256 GiB, mmap at 384 GiB, stack at ~1 TiB) are
/// mapped to compact low GPAs via the PML4 (Experiment 2: identity placement
/// FAILED at high GPAs — `vm_map_gpa` returns NULL).
///
/// # ring-3 entry
///
/// The vCPU starts at the ring-0 MSR init blob (`X86_INIT_BLOB_GPA`) exactly
/// as in M1.  The iretq frame in the blob uses `entry_rip` (the ELF entry
/// point) and `initial_rsp` (the initial-stack pointer written by
/// `with_linux_initial_stack`).
pub fn bring_up_x86_elf(
    image: &carrick_mem::memory::AddressSpace,
    entry_rip: u64,
    initial_rsp: u64,
) -> Result<BroughtUpX86, OsError> {
    use carrick_mem::memory::{
        LINUX_HEAP_BASE, LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE, LINUX_PRIVATE_OVERLAY_BASE,
        LINUX_SHARED_FILE_BASE, LINUX_SIGRETURN_TRAMPOLINE_BASE, LINUX_STACK_TOP,
    };

    let regs = X8664GuestArch::bootstrap_sysregs();

    // ── Step 1: plan GPA windows ──────────────────────────────────────────────

    let mut ram = BhyveGuestRam::new();

    // Fixed-GPA kernel windows: init blob, GDT, LSTAR, PML4 tables.
    // The init-blob page is WRITABLE (write=true): it stays the kernel scratch
    // page after boot. Sibling vCPU bring-up (Tier 2) carves per-sibling ring-0
    // MSR blobs from it AND uses the slot tail as the blob's ring-0 scratch
    // stack — the blob's `push`es (iretq frame) WRITE this page, so it must be
    // RW. It is user=false (kernel-only), so RW exposes nothing to the guest.
    ram.add_fixed(
        X86_INIT_BLOB_GPA,
        X86_INIT_BLOB_GPA,
        4096,
        false,
        true,
        true,
    );
    ram.add_fixed(X86_GDT_GPA, X86_GDT_GPA, 4096, false, false, false);
    ram.add_fixed(
        LINUX_EL0_TRAMPOLINE_BASE,
        X86_LSTAR_GPA,
        4096,
        false,
        false,
        true,
    );
    // SP3.2 FP stub + scratch windows (identity-mapped supervisor; see the FP
    // overlay in BhyveTrapEngine::inject_signal / restore_from_sigframe).
    ram.add_fixed(X86_FP_STUB_GPA, X86_FP_STUB_GPA, 4096, false, false, true);
    ram.add_fixed(
        X86_FP_SCRATCH_GPA,
        X86_FP_SCRATCH_GPA,
        (X86_FP_SCRATCH_SLOTS as usize) * 4096,
        false,
        true,
        false,
    );
    ram.add_fixed(
        LINUX_PAGE_TABLES_BASE,
        X86_PML4_GPA,
        X86_PML4_CAPACITY,
        false,
        true,
        false,
    );

    // Map each region from the AddressSpace.  Apply M2-grade caps on the
    // large runtime windows so they fit in 64 MiB lowmem.
    for region in image.regions() {
        let va = region.start;
        let full_len = (region.end - region.start) as usize;

        // Skip zero-length regions (shouldn't appear, but be defensive).
        if full_len == 0 {
            continue;
        }

        // Skip the PML4 tables and LSTAR windows: already added above as fixed.
        if va == LINUX_PAGE_TABLES_BASE || va == LINUX_EL0_TRAMPOLINE_BASE {
            continue;
        }

        // Apply M2 caps on the known large synthetic windows.
        let capped_len = if va == LINUX_HEAP_BASE {
            // Heap: cap to M2_HEAP_CAP (full = LINUX_HEAP_SIZE = 128 MiB).
            full_len.min(M2_HEAP_CAP)
        } else if va == LINUX_MMAP_BASE {
            // mmap arena: cap to M2_MMAP_CAP (full ≥ 32 GiB).
            full_len.min(M2_MMAP_CAP)
        } else if va == LINUX_SIGRETURN_TRAMPOLINE_BASE
            || va == LINUX_SHARED_FILE_BASE
            || va == LINUX_PRIVATE_OVERLAY_BASE
        {
            // Sigreturn trampoline / shared aperture / private overlay: one page.
            // Not exercised in M2's run-to-exit path; presence lets brk/mmap
            // detect out-of-bounds without a fault.
            full_len.min(M2_MISC_CAP)
        } else {
            // ELF segments, initial stack: map in full (these are small).
            full_len
        };

        // Page-align upward (bhyve windows must be 4 KiB granular).
        let page_len = (capped_len + 0xFFF) & !0xFFF;

        // All regions from image.regions() that reach the dispatch loop must
        // be accessible from ring-3 (CPL=3 after the iretq to user space).
        // The aarch64 "kernel hole" convention (LINUX_KERNEL_REGION_BASE) does
        // not apply here: the fixed-GPA kernel windows (init blob, GDT, LSTAR,
        // PML4 tables) are skipped above and added with user=false; every
        // remaining region — ELF segments, initial stack, heap, mmap arena,
        // sigreturn trampoline, shared/private apertures — must be U/S-mapped.
        let user = true;
        let write = region.perms.write;
        let exec = region.perms.execute;

        let gpa = ram.add_bump(va, page_len, user, write, exec)?;

        // Write the region's initialised prefix into guest RAM.
        // Beyond `region.bytes().len()` the bump window is already zeroed
        // (bhyve's vm_setup_memory zeroes the sysmem segment).
        let _ = gpa; // used below after vm_setup_memory
    }

    // ── Step 2: vm_setup_memory + mmap_memseg ────────────────────────────────

    let total = ram.total_size().max(X86_MEM_SIZE);
    let ram_size = total.min(X86_MEM_SIZE); // never exceed the 64 MiB cap

    let mut vm = BhyveVm::create()?;
    vm.setup_memory(ram_size)?;
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, ram_size, PROT_RWX)?;

    // ── Step 3: write artifacts ───────────────────────────────────────────────

    // Ring-0 MSR init blob: WRMSRs LSTAR/STAR/SFMASK, then iretqs to entry_rip
    // at ring-3 with initial_rsp as the stack pointer.
    let blob = msr_init_blob(
        regs.lstar,
        regs.star,
        regs.sfmask,
        entry_rip,   // ring-3 RIP: ELF entry point
        initial_rsp, // ring-3 RSP: initial stack from with_linux_initial_stack
        regs.rflags,
        false, // the ELF `_start` ignores the inbound RAX
    );
    write_gpa(&vm, X86_INIT_BLOB_GPA, &blob)?;

    write_gpa(&vm, X86_GDT_GPA, &carrick_boot_gdt_bytes())?;
    write_gpa(&vm, X86_LSTAR_GPA, &entry_trampoline_bytes())?;
    write_fp_stub(&vm)?; // SP3.2 FXSAVE/FXRSTOR stubs

    // Write each region's bytes into its bump window.
    for region in image.regions() {
        let va = region.start;
        let bytes = region.bytes();
        if bytes.is_empty() {
            continue;
        }
        // Skip kernel-fixed windows (already written above).
        if va == LINUX_PAGE_TABLES_BASE || va == LINUX_EL0_TRAMPOLINE_BASE {
            continue;
        }
        // Find the window for this VA to get its GPA.
        if let Some(w) = ram.windows.iter().find(|w| w.va == va) {
            let write_len = bytes.len().min(w.len);
            if write_len > 0 {
                write_gpa(&vm, w.gpa, &bytes[..write_len])?;
            }
        }
    }

    // PML4 tables: map all the windows.
    let specs = pml4_map_specs(&ram);
    let tables = pml4_tables(&specs, X86_PML4_GPA, X86_PML4_CAPACITY)
        .map_err(|e| OsError::new(format!("bhyve: ELF PML4 build failed: {e:?}")))?;
    write_gpa(&vm, X86_PML4_GPA, &tables)?;

    // ── Step 4: program vCPU registers (identical to bring_up_x86_m1) ────────

    let mut vcpu = vm.add_vcpu()?;

    vcpu.set_reg_raw(VM_REG_GUEST_CR0, regs.cr0)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR3, X86_PML4_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR4, regs.cr4)?;
    vcpu.set_reg_raw(VM_REG_GUEST_EFER, regs.efer)?;

    vcpu.set_reg_raw(VM_REG_GUEST_RIP, X86_INIT_BLOB_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RSP, LINUX_STACK_TOP)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RFLAGS, regs.rflags)?;

    // Initial segments: kernel (DPL 0) — the init blob runs at CPL 0 to WRMSR.
    // The iretq loads user CS/SS from the GDT.
    vcpu.set_desc(VM_REG_GUEST_CS, 0, 0xFFFF_FFFF, ACCESS_RING0_CS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CS, KERN_CS64_SEL)?;
    vcpu.set_desc(VM_REG_GUEST_SS, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_reg_raw(VM_REG_GUEST_SS, KERN_SS_SEL)?;

    for reg in [
        VM_REG_GUEST_DS,
        VM_REG_GUEST_ES,
        VM_REG_GUEST_FS,
        VM_REG_GUEST_GS,
    ] {
        vcpu.set_desc(reg, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
        vcpu.set_reg_raw(reg, KERN_SS_SEL)?;
    }

    vcpu.set_desc(VM_REG_GUEST_GDTR, X86_GDT_GPA, (GDT_LEN * 8 - 1) as u32, 0)?;
    vcpu.set_desc(VM_REG_GUEST_IDTR, 0, 0, 0)?;
    vcpu.set_desc(VM_REG_GUEST_LDTR, 0, 0, ACCESS_LDT_UNUSABLE)?;
    vcpu.set_reg_raw(VM_REG_GUEST_LDTR, 0)?;
    vcpu.set_desc(VM_REG_GUEST_TR, 0, 0x67, ACCESS_TSS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_TR, 0)?;

    vcpu.set_capability(VM_CAP_HALT_EXIT, 1)?;

    Ok(BroughtUpX86 {
        vm,
        vcpu,
        ram,
        fxsave_stub_gpa: X86_FP_STUB_GPA,
        fxrstor_stub_gpa: X86_FP_STUB_GPA + 8,
        fp_scratch_gpa: X86_FP_SCRATCH_GPA, // slot 0 (the main vCPU)
    })
}

// ─── M2 Tier 0: vCPU register snapshot / restore / seed ──────────────────────
//
// A GPR + segment-base + control-register capture of a vCPU's state, used to
// seed a sibling vCPU (Tier 2) and the deferred fork (Tier 3).
//
// FP/SIMD is EXCLUDED by design (D4): FreeBSD 15.1 libvmmapi exposes no FP/XMM
// getter (`enum vm_reg_name` has no FP slots; there is no `vm_get_fpu`-style
// ioctl in vmmapi.h), and a freshly spun sibling thread starts with its own FP
// state, so there is nothing to copy.

/// Index of RAX within [`X8664BhyveSnapshot::gpr`].
pub const GPR_IDX_RAX: usize = 0;
/// Index of RBX within [`X8664BhyveSnapshot::gpr`].
pub const GPR_IDX_RBX: usize = 1;
/// Index of RCX within [`X8664BhyveSnapshot::gpr`]. After a `syscall`, hardware
/// sets RCX = the post-syscall return RIP — the child's ring-3 resume PC.
pub const GPR_IDX_RCX: usize = 2;

/// The 15 GPR `vm_reg_name` ordinals captured by [`snapshot_x86_bhyve`], in the
/// order they occupy [`X8664BhyveSnapshot::gpr`].
///
/// These are the 15 contiguous general-purpose registers RAX..R15 (ordinals
/// 0..14). RSP is ordinal 19 — OUTSIDE this block (DR7=18 sits between CR4=17
/// and RSP=19) — so it is a SEPARATE named field on the snapshot, not part of
/// this array.
const SNAPSHOT_GPR_IDS: [c_int; 15] = [
    VM_REG_GUEST_RAX,
    VM_REG_GUEST_RBX,
    VM_REG_GUEST_RCX,
    VM_REG_GUEST_RDX,
    VM_REG_GUEST_RSI,
    VM_REG_GUEST_RDI,
    VM_REG_GUEST_RBP,
    VM_REG_GUEST_R8,
    VM_REG_GUEST_R9,
    VM_REG_GUEST_R10,
    VM_REG_GUEST_R11,
    VM_REG_GUEST_R12,
    VM_REG_GUEST_R13,
    VM_REG_GUEST_R14,
    VM_REG_GUEST_R15,
];

/// A snapshot of a bhyve x86_64 vCPU's GPRs, segment bases, and control
/// registers — everything carrick needs to re-create the integer execution
/// state of a vCPU on a fresh sibling thread (Tier 2) or a deferred fork
/// (Tier 3).
///
/// FP/SIMD is intentionally absent (D4 — see the module note above).
#[derive(Clone, Debug)]
pub struct X8664BhyveSnapshot {
    /// The 15 GPRs RAX..R15, indexed by [`SNAPSHOT_GPR_IDS`] (RAX = index 0).
    /// RSP is the separate `rsp` field — ordinal 19 is outside the 0..14 block.
    pub gpr: [u64; 15],
    /// RSP (ordinal 19).
    pub rsp: u64,
    /// RIP (ordinal 20).
    pub rip: u64,
    /// RFLAGS (ordinal 21).
    pub rflags: u64,
    /// FS_BASE (ordinal 45) — the TLS base on x86_64 Linux.
    pub fs_base: u64,
    /// GS_BASE (ordinal 46).
    pub gs_base: u64,
    /// KGS_BASE (ordinal 47) — the kernel GS base (swapgs partner).
    pub kgs_base: u64,
    /// CR0 (ordinal 15).
    pub cr0: u64,
    /// CR2 (ordinal 33) — page-fault linear address. Captured for diagnostics
    /// only; NOT re-applied on restore (it is transient fault state).
    pub cr2: u64,
    /// CR3 (ordinal 16) — the PML4 root.
    pub cr3: u64,
    /// CR4 (ordinal 17).
    pub cr4: u64,
    /// EFER (ordinal 32).
    pub efer: u64,
}

impl X8664BhyveSnapshot {
    /// An all-zero snapshot (the test seed and a safe default).
    pub fn zeroed() -> Self {
        Self {
            gpr: [0; 15],
            rsp: 0,
            rip: 0,
            rflags: 0,
            fs_base: 0,
            gs_base: 0,
            kgs_base: 0,
            cr0: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
        }
    }
}

/// Capture a vCPU's integer execution state into an [`X8664BhyveSnapshot`].
///
/// Reads the 15 GPRs (RAX..R15) plus RSP/RIP/RFLAGS, the three segment bases
/// (FS/GS/KGS), and the control registers (CR0/CR2/CR3/CR4/EFER) via
/// `vm_get_register`. FP/SIMD is excluded (D4).
pub fn snapshot_x86_bhyve(vcpu: &crate::vmm::BhyveVcpu) -> Result<X8664BhyveSnapshot, OsError> {
    let mut gpr = [0u64; 15];
    for (i, &id) in SNAPSHOT_GPR_IDS.iter().enumerate() {
        gpr[i] = vcpu.get_reg_raw(id)?;
    }
    Ok(X8664BhyveSnapshot {
        gpr,
        rsp: vcpu.get_reg_raw(VM_REG_GUEST_RSP)?,
        rip: vcpu.get_reg_raw(VM_REG_GUEST_RIP)?,
        rflags: vcpu.get_reg_raw(VM_REG_GUEST_RFLAGS)?,
        fs_base: vcpu.get_reg_raw(VM_REG_GUEST_FS_BASE)?,
        gs_base: vcpu.get_reg_raw(VM_REG_GUEST_GS_BASE)?,
        kgs_base: vcpu.get_reg_raw(VM_REG_GUEST_KGS_BASE)?,
        cr0: vcpu.get_reg_raw(VM_REG_GUEST_CR0)?,
        cr2: vcpu.get_reg_raw(VM_REG_GUEST_CR2)?,
        cr3: vcpu.get_reg_raw(VM_REG_GUEST_CR3)?,
        cr4: vcpu.get_reg_raw(VM_REG_GUEST_CR4)?,
        efer: vcpu.get_reg_raw(VM_REG_GUEST_EFER)?,
    })
}

/// Re-apply a snapshot to a vCPU via `vm_set_register`.
///
/// Writes the 15 GPRs, then RSP/RIP/RFLAGS, then CR0/CR3/CR4/EFER, then the
/// three segment bases FS_BASE/GS_BASE/KGS_BASE.
///
/// # What is NOT restored
///
/// - **CR2** — page-fault linear address (transient fault state, not execution
///   state).
/// - **Segment SELECTORS and hidden DESCRIPTORS** (CS/SS/DS/ES/FS/GS, GDTR,
///   IDTR, LDTR, TR). A sibling vCPU SHARES the parent's already-programmed GDT
///   and selector/descriptor state (set up at bring-up); re-applying them would
///   be redundant and risks disturbing VT-x's required guest-state invariants.
///   Only the segment BASES (FS/GS/KGS) — which `arch_prctl(ARCH_SET_FS)` proves
///   are writable via `vm_set_register` (ordinals 45/46/47) — carry per-thread
///   state and ARE restored.
pub fn restore_x86_bhyve(
    vcpu: &mut crate::vmm::BhyveVcpu,
    snap: &X8664BhyveSnapshot,
) -> Result<(), OsError> {
    for (i, &id) in SNAPSHOT_GPR_IDS.iter().enumerate() {
        vcpu.set_reg_raw(id, snap.gpr[i])?;
    }
    vcpu.set_reg_raw(VM_REG_GUEST_RSP, snap.rsp)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RIP, snap.rip)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RFLAGS, snap.rflags)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR0, snap.cr0)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR3, snap.cr3)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR4, snap.cr4)?;
    vcpu.set_reg_raw(VM_REG_GUEST_EFER, snap.efer)?;
    // Segment bases (writable via vm_set_register — arch_prctl proves it).
    // CR2 is deliberately NOT restored (fault state); SELECTORS/DESCRIPTORS are
    // shared with the parent and not re-applied.
    vcpu.set_reg_raw(VM_REG_GUEST_FS_BASE, snap.fs_base)?;
    vcpu.set_reg_raw(VM_REG_GUEST_GS_BASE, snap.gs_base)?;
    vcpu.set_reg_raw(VM_REG_GUEST_KGS_BASE, snap.kgs_base)?;
    Ok(())
}

/// Program a fresh vCPU (a sibling vCPU `id` on the shared VM, or vCPU 0 of a
/// forked child's fresh VM) for long-mode ring-3 entry at the snapshot's
/// post-trap context (RIP = snap.gpr[RCX], RSP = snap.rsp, rax=0 via the blob's
/// clear_rax).
///
/// # Why a per-sibling ring-0 blob
///
/// bhyve has NO `vm_set_msr`: LSTAR/STAR/SFMASK can only be installed by a guest
/// ring-0 `WRMSR`. A fresh sibling vCPU has none of the parent's long-mode VMCS
/// state (segment descriptors, GDTR, TR — VT-x REQUIRES a usable TR + 64-bit CS
/// for VM entry) or the SYSCALL MSRs. So the sibling must replicate the parent's
/// bring-up: program long-mode descriptors over the SHARED PML4/GDT and run a
/// ring-0 MSR blob that ends with an `iretq` into the child's ring-3 context.
///
/// # Child entry ABI
///
/// The child resumes as if returning from the `clone` syscall: at the
/// post-`syscall` RIP with `rax = 0`. Hardware `syscall` set RCX = the return
/// RIP (then jumped to LSTAR, the `out` doorbell where the parent trapped), so
/// the child's ring-3 entry RIP = the parent's RCX = `snap.gpr[GPR_IDX_RCX]`.
/// The child's stack = `snap.rsp` (already seeded to the clone `child_stack`).
/// The blob's `iretq` is the ring-3 transition (no sysretq) and `clear_rax`
/// zeroes RAX so the child sees `clone` → 0.
///
/// # Per-sibling blob slot
///
/// The boot init-blob page ([`X86_INIT_BLOB_GPA`], one 4 KiB identity-mapped
/// page) is FREE after boot (the parent's blob ran once; the parent is now in
/// ring-3). We carve per-sibling 256-byte slots from it by vCPU id: `slot = id *
/// 256` (sibling ids start at 1; id 0 is the main vCPU's dead boot blob). The
/// blob code (~80 bytes) sits at the slot base; the ring-0 scratch RSP is the
/// slot top (`blob_gpa + 256`), so the blob's ≤5 pushes (~40 bytes) grow down
/// into the slot tail and never reach the code. Each slot is self-contained, so
/// concurrent siblings do not race. The page holds ids 1..=15.
///
/// # FS base
///
/// FS.base (the TLS pointer) is written via `vm_set_desc` (the proven path —
/// `vm_set_register(FS_BASE)` returns EINVAL on FreeBSD 15.1). It is written
/// LAST so the ring-0 FS descriptor override above cannot clobber it. `iretq`
/// does NOT reload FS on x86-64, so the ring-0 FS base persists into ring-3.
pub fn program_x86_vcpu_longmode_entry(
    vcpu: &mut crate::vmm::BhyveVcpu,
    vm: &BhyveVm,
    snap: &X8664BhyveSnapshot,
    id: c_int,
) -> Result<(), OsError> {
    let regs = X8664GuestArch::bootstrap_sysregs();

    // Child ring-3 entry: post-clone RIP = parent's RCX; stack = seeded child
    // stack (snap.rsp). snap.rip (the seeded sysretq resume) is unused here —
    // the iretq goes DIRECTLY to RCX.
    let child_rip = snap.gpr[GPR_IDX_RCX];
    let child_rsp = snap.rsp;

    // Per-sibling blob + ring-0 scratch-stack slot in the post-boot-free
    // init-blob page (identity-mapped; no PML4 edit needed).
    let slot = id as u64 * 256;
    if slot + 256 > 4096 {
        return Err(OsError::new(format!(
            "bhyve: too many sibling vCPUs for the init-blob page (id {id})"
        )));
    }
    let blob_gpa = X86_INIT_BLOB_GPA + slot;
    let ring0_rsp = blob_gpa + 256;

    // Sibling MSR blob: WRMSR LSTAR/STAR/SFMASK, then iretq → ring-3 at
    // child_rip with child_rsp and rax = 0 (clear_rax = true).
    let blob = msr_init_blob(
        regs.lstar,
        regs.star,
        regs.sfmask,
        child_rip,
        child_rsp,
        regs.rflags,
        true,
    );
    write_gpa(vm, blob_gpa, &blob)?;

    // Inherit the parent's integer state. We do NOT call restore_x86_bhyve here
    // because (a) its RIP/RSP/CR3 writes are immediately overridden for the
    // ring-0 blob entry, and (b) its FS/GS-base writes go through
    // vm_set_register(FS_BASE/GS_BASE) which is unreliable on FreeBSD 15.1 (the
    // base is VT-x hidden descriptor state); we install those via vm_set_desc
    // below instead. So inherit only the 15 GPRs + RFLAGS + CR0/CR4/EFER here.
    for (i, &gid) in SNAPSHOT_GPR_IDS.iter().enumerate() {
        vcpu.set_reg_raw(gid, snap.gpr[i])?;
    }
    vcpu.set_reg_raw(VM_REG_GUEST_CR0, snap.cr0)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CR4, snap.cr4)?;
    vcpu.set_reg_raw(VM_REG_GUEST_EFER, snap.efer)?;

    // Override for the ring-0 blob entry (mirror bring_up_x86_elf Step 4).
    // CR3 = the SHARED PML4 (snap.cr3 equals this, but be explicit).
    vcpu.set_reg_raw(VM_REG_GUEST_CR3, X86_PML4_GPA)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RIP, blob_gpa)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RSP, ring0_rsp)?;
    vcpu.set_reg_raw(VM_REG_GUEST_RFLAGS, regs.rflags)?;

    // Segment descriptors + selectors (ring-0; the blob's iretq loads user
    // CS/SS from the frame).
    vcpu.set_desc(VM_REG_GUEST_CS, 0, 0xFFFF_FFFF, ACCESS_RING0_CS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_CS, KERN_CS64_SEL)?;
    vcpu.set_desc(VM_REG_GUEST_SS, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_reg_raw(VM_REG_GUEST_SS, KERN_SS_SEL)?;
    for reg in [
        VM_REG_GUEST_DS,
        VM_REG_GUEST_ES,
        VM_REG_GUEST_FS,
        VM_REG_GUEST_GS,
    ] {
        vcpu.set_desc(reg, 0, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
        vcpu.set_reg_raw(reg, KERN_SS_SEL)?;
    }
    vcpu.set_desc(VM_REG_GUEST_GDTR, X86_GDT_GPA, (GDT_LEN * 8 - 1) as u32, 0)?;
    vcpu.set_desc(VM_REG_GUEST_IDTR, 0, 0, 0)?;
    vcpu.set_desc(VM_REG_GUEST_LDTR, 0, 0, ACCESS_LDT_UNUSABLE)?;
    vcpu.set_reg_raw(VM_REG_GUEST_LDTR, 0)?;
    // TR: VT-x requires a usable 64-bit TSS for VM entry (base 0, limit 0x67).
    vcpu.set_desc(VM_REG_GUEST_TR, 0, 0x67, ACCESS_TSS64)?;
    vcpu.set_reg_raw(VM_REG_GUEST_TR, 0)?;

    // FS/GS bases — set LAST, via vm_set_desc (the FS/GS descriptor overrides
    // above set base = 0; rewrite them with the inherited bases, preserving the
    // ring-0 limit/access we just wrote). vm_set_register(FS_BASE/GS_BASE) is
    // unreliable for the hidden base; the descriptor base IS the segment base in
    // long mode and persists across iretq (iretq does NOT reload FS/GS on
    // x86-64). FS.base carries the child's TLS pointer.
    vcpu.set_desc(VM_REG_GUEST_FS, snap.fs_base, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_desc(VM_REG_GUEST_GS, snap.gs_base, 0xFFFF_FFFF, ACCESS_RING0_SS)?;
    vcpu.set_reg_raw(VM_REG_GUEST_GS, KERN_SS_SEL)?;

    vcpu.set_capability(VM_CAP_HALT_EXIT, 1)?;
    Ok(())
}

/// Derive a child snapshot from a parent's, applying the clone/fork entry ABI.
///
/// Inherits the parent's full integer state, then overrides only the registers
/// the Linux clone/fork return convention dictates:
/// - `gpr[GPR_IDX_RAX] = entry.return_value` — the child sees `0` from
///   `clone`/`fork` in RAX.
/// - `rsp = entry.stack` if a new stack was supplied (else inherit the
///   parent's RSP).
/// - `fs_base = entry.tls` if a new TLS base was supplied (else inherit).
/// - `rip = resume_rip` — the PC to resume at (past the syscall doorbell).
///
/// All other registers (RBX..R15, RFLAGS, GS/KGS bases, control registers) are
/// inherited verbatim from the parent.
pub fn seed_entry_snapshot_bhyve(
    parent: &X8664BhyveSnapshot,
    entry: carrick_hal::GuestEntryRegs,
    resume_rip: u64,
) -> X8664BhyveSnapshot {
    let mut child = parent.clone();
    child.gpr[GPR_IDX_RAX] = entry.return_value;
    if let Some(s) = entry.stack {
        child.rsp = s;
    }
    if let Some(t) = entry.tls {
        child.fs_base = t;
    }
    child.rip = resume_rip;
    child
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

    /// M1 blob: byte-pin the instruction encodings and verify the inline
    /// message placement.
    ///
    /// Encoding sources: AMD64 APM vol. 3 / OSDev / Intel SDM vol. 2A-2B.
    #[test]
    fn m1_ring3_blob_bytes_pinned() {
        let blob = m1_ring3_blob();
        // Total length: 0x21 (33 code) + 6 (msg) = 39 bytes.
        assert_eq!(
            blob.len(),
            39,
            "M1 blob must be 39 bytes (0x21 code + 6 msg)"
        );

        // Offset +0x00: mov $1, %edi  (BF 01 00 00 00)
        assert_eq!(&blob[0x00..0x05], &[0xBF, 0x01, 0x00, 0x00, 0x00]);

        // Offset +0x05: mov $0x400021, %esi  (BE 21 00 40 00)
        // msg_va = M1_BLOB_VA + 0x21 = 0x400000 + 0x21 = 0x400021
        let msg_va = (M1_BLOB_VA + 0x21u64) as u32;
        assert_eq!(
            &blob[0x05..0x0a],
            &[
                0xBE,
                msg_va as u8,
                (msg_va >> 8) as u8,
                (msg_va >> 16) as u8,
                (msg_va >> 24) as u8
            ]
        );

        // Offset +0x0f: mov $1, %eax  (B8 01 00 00 00) — __NR_write=1
        assert_eq!(&blob[0x0f..0x14], &[0xB8, 0x01, 0x00, 0x00, 0x00]);

        // Offset +0x14: syscall (0F 05)
        assert_eq!(&blob[0x14..0x16], &[0x0F, 0x05]);

        // Offset +0x16: xor %edi, %edi  (31 FF)
        assert_eq!(&blob[0x16..0x18], &[0x31, 0xFF]);

        // Offset +0x18: mov $231, %eax  (B8 E7 00 00 00) — __NR_exit_group=231
        assert_eq!(&blob[0x18..0x1d], &[0xB8, 0xE7, 0x00, 0x00, 0x00]);

        // Offset +0x1d: syscall (0F 05)
        assert_eq!(&blob[0x1d..0x1f], &[0x0F, 0x05]);

        // Offset +0x1f: jmp . (EB FE)
        assert_eq!(&blob[0x1f..0x21], &[0xEB, 0xFE]);

        // Offset +0x21: msg "hello\n" (6 bytes), immediately after the code
        assert_eq!(&blob[0x21..0x27], b"hello\n");
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

    // ── T6 unit tests ────────────────────────────────────────────────────────

    /// The 5-entry carrick GDT serializes to 40 bytes and every entry matches
    /// the `X8664BootSysregs::gdt` field verbatim.
    #[test]
    fn carrick_boot_gdt_bytes_match_boot_sysregs() {
        let gdt = carrick_boot_gdt_bytes();
        assert_eq!(gdt.len(), GDT_LEN * 8, "5-entry GDT = 40 bytes");
        let regs = X8664GuestArch::bootstrap_sysregs();
        for (i, expected) in regs.gdt.iter().enumerate() {
            let got = u64::from_le_bytes(gdt[i * 8..i * 8 + 8].try_into().unwrap());
            assert_eq!(got, *expected, "GDT[{i}] mismatch");
        }
    }

    /// BhyveGuestRam bump allocator: plan_gpa returns page-aligned GPAs
    /// starting at X86_GPA_CURSOR_START and advances monotonically.
    #[test]
    fn bhyve_guest_ram_bump_allocates_monotonically() {
        let mut ram = BhyveGuestRam::new();
        let gpa0 = ram.plan_gpa(1).expect("first alloc");
        assert_eq!(gpa0, X86_GPA_CURSOR_START);
        let gpa1 = ram.plan_gpa(4096).expect("second alloc");
        assert_eq!(
            gpa1,
            X86_GPA_CURSOR_START + 0x1000,
            "1-byte rounds to 1 page"
        );
        let gpa2 = ram.plan_gpa(4097).expect("third alloc");
        assert_eq!(
            gpa2,
            X86_GPA_CURSOR_START + 0x2000,
            "4097 bytes rounds to 2 pages"
        );
        assert!(gpa2 < X86_MEM_SIZE as u64, "all GPAs within lowmem");
    }

    /// BhyveGuestRam: overflow guard returns an error before exceeding the
    /// 64 MiB lowmem window.
    #[test]
    fn bhyve_guest_ram_overflow_returns_error() {
        let mut ram = BhyveGuestRam::new();
        // Request more than X86_MEM_SIZE in one shot.
        let result = ram.plan_gpa(X86_MEM_SIZE + 1);
        assert!(result.is_err(), "overflow must return Err");
    }

    /// add_fixed / add_bump store the window with the correct VA/GPA/flags.
    #[test]
    fn bhyve_guest_ram_add_fixed_and_bump_store_windows() {
        let mut ram = BhyveGuestRam::new();
        ram.add_fixed(0xDEAD_0000, 0x1000, 4096, true, false, true);
        assert_eq!(ram.windows.len(), 1);
        assert_eq!(ram.windows[0].va, 0xDEAD_0000);
        assert_eq!(ram.windows[0].gpa, 0x1000);
        assert!(ram.windows[0].user);
        assert!(ram.windows[0].exec);

        let gpa = ram.add_bump(0xBEEF_0000, 8192, false, true, false).unwrap();
        assert_eq!(ram.windows.len(), 2);
        assert_eq!(ram.windows[1].va, 0xBEEF_0000);
        assert_eq!(ram.windows[1].gpa, gpa);
        assert_eq!(gpa, X86_GPA_CURSOR_START);
        assert!(ram.windows[1].write);
        assert!(!ram.windows[1].exec);
    }

    /// msr_init_blob: smoke-check that the blob is non-empty, fits in 128 bytes,
    /// starts with B9 (mov ecx, imm32 for the first WRMSR), and ends with 48 CF
    /// (iretq).
    #[test]
    fn msr_init_blob_structure() {
        let regs = X8664GuestArch::bootstrap_sysregs();
        let blob = msr_init_blob(
            regs.lstar,
            regs.star,
            regs.sfmask,
            0x1000,
            0x2000,
            0x2,
            false,
        );
        assert!(!blob.is_empty(), "blob must be non-empty");
        assert!(
            blob.len() <= 128,
            "blob fits in 128 bytes (got {})",
            blob.len()
        );
        // First instruction: mov ecx, MSR_LSTAR → B9 82 00 00 C0
        assert_eq!(blob[0], 0xB9, "first byte = mov ecx, imm32");
        assert_eq!(
            &blob[1..5],
            &MSR_LSTAR.to_le_bytes(),
            "first imm32 = MSR_LSTAR"
        );
        // Last two bytes: iretq (48 CF)
        let n = blob.len();
        assert_eq!(blob[n - 2], 0x48, "penultimate byte = REX.W (iretq)");
        assert_eq!(blob[n - 1], 0xCF, "last byte = CF (iretq)");
    }

    /// msr_init_blob: iretq frame embeds correct selector values.
    /// The USER_SS_SEL and USER_CS64_SEL immediates appear at the right byte
    /// positions in the push sequence (after the three WRMSRs).
    #[test]
    fn msr_init_blob_encodes_ring3_selectors() {
        let blob = msr_init_blob(0, 0, 0, 0, 0, 0x2, false);
        // Three WRMSRs each = 5 (mov ecx,imm32: B9 id) + 5 (mov eax: B8 id)
        // + 5 (mov edx: BA id) + 2 (wrmsr: 0F 30) = 17 bytes.
        let after_wrmsr = 3 * 17;
        // push imm32 for SS (68 + 4 bytes) at after_wrmsr.
        assert_eq!(blob[after_wrmsr], 0x68, "push SS selector opcode");
        let ss_val = u32::from_le_bytes(blob[after_wrmsr + 1..after_wrmsr + 5].try_into().unwrap());
        assert_eq!(ss_val, USER_SS_SEL as u32, "SS selector in iretq frame");
    }

    /// msr_init_blob with `clear_rax = true` emits `xor eax, eax` (31 C0)
    /// immediately before the `iretq` (48 CF), and that adds exactly two bytes
    /// versus the `false` variant. This is the clone(2) child-entry path: the
    /// child must see `rax = 0` after the iretq.
    #[test]
    fn msr_init_blob_clear_rax_emits_xor_before_iretq() {
        let with = msr_init_blob(0, 0, 0, 0x1000, 0x2000, 0x2, true);
        let without = msr_init_blob(0, 0, 0, 0x1000, 0x2000, 0x2, false);
        assert_eq!(
            with.len(),
            without.len() + 2,
            "clear_rax adds exactly the 2-byte xor eax,eax"
        );
        let n = with.len();
        // ... 31 C0 48 CF  (xor eax,eax ; iretq)
        assert_eq!(
            &with[n - 4..],
            &[0x31, 0xC0, 0x48, 0xCF],
            "clear_rax tail = xor eax,eax + iretq"
        );
    }

    /// pml4_map_specs converts BhyveGuestRam windows to Pml4MapSpec correctly.
    #[test]
    fn pml4_map_specs_round_trips_windows() {
        let mut ram = BhyveGuestRam::new();
        ram.add_fixed(0x1000_0000, 0x5000, 4096, true, true, false);
        ram.add_fixed(0x2000_0000, 0x6000, 8192, false, false, true);
        let specs = pml4_map_specs(&ram);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].va, 0x1000_0000);
        assert_eq!(specs[0].gpa, 0x5000);
        assert!(specs[0].user);
        assert!(specs[0].write);
        assert!(!specs[0].exec);
        assert_eq!(specs[1].va, 0x2000_0000);
        assert!(!specs[1].user);
        assert!(specs[1].exec);
    }

    /// The access-rights constants have the correct VT-x format.
    ///
    /// VT-x access byte: bits[3:0]=type, [4]=S, [6:5]=DPL, [7]=P, [13]=L.
    /// - kCS64 = P(7)|S(4)|type=A=exec/read(3:0) + L(13) = 0x209B
    /// - kSS   = P(7)|S(4)|type=2=data/RW(3:0)           = 0x0093
    /// - uSS   = P(7)|S(4)|DPL=3(6:5)|type=2             = 0x00F3
    /// - uCS64 = P(7)|S(4)|DPL=3(6:5)|type=A + L(13)     = 0x20FB
    #[test]
    fn access_rights_constants_have_correct_bits() {
        // Ring-0 CS64: P + S + exec/read + L
        assert_eq!(
            ACCESS_RING0_CS64 & 0xF,
            0xB,
            "kCS64 type = 0xB (exec/read/accessed)"
        );
        assert_ne!(ACCESS_RING0_CS64 & (1 << 4), 0, "kCS64 S=1");
        assert_eq!((ACCESS_RING0_CS64 >> 5) & 3, 0, "kCS64 DPL=0");
        assert_ne!(ACCESS_RING0_CS64 & (1 << 7), 0, "kCS64 P=1");
        assert_ne!(ACCESS_RING0_CS64 & (1 << 13), 0, "kCS64 L=1 (64-bit code)");
        // Ring-3 CS64: P + S + DPL=3 + exec/read + L
        assert_eq!((ACCESS_RING3_CS64 >> 5) & 3, 3, "uCS64 DPL=3");
        assert_ne!(ACCESS_RING3_CS64 & (1 << 13), 0, "uCS64 L=1");
        // Ring-0 SS: P + S + data/RW, DPL=0
        assert_eq!(ACCESS_RING0_SS & 0xF, 3, "kSS type = 3 (data/RW/accessed)");
        assert_eq!((ACCESS_RING0_SS >> 5) & 3, 0, "kSS DPL=0");
        // Ring-3 SS: P + S + DPL=3 + data/RW
        assert_eq!((ACCESS_RING3_SS >> 5) & 3, 3, "uSS DPL=3");
        // Unusable: bit 16 set
        assert_ne!(ACCESS_UNUSABLE & 0x0001_0000, 0, "unusable bit 16 set");
    }

    /// GDT limit for 5 entries is 5*8-1 = 39.
    #[test]
    fn gdt_limit_for_five_entries() {
        assert_eq!(GDT_LEN * 8 - 1, 39, "5-entry GDT limit");
    }

    /// All fixed-GPA constants are within X86_MEM_SIZE (64 MiB lowmem).
    #[test]
    fn fixed_gpa_constants_within_lowmem() {
        for (name, gpa, size) in [
            ("init_blob", X86_INIT_BLOB_GPA, 128u64),
            ("gdt", X86_GDT_GPA, 4096),
            ("lstar", X86_LSTAR_GPA, 4096),
            ("pml4", X86_PML4_GPA, X86_PML4_CAPACITY as u64),
            (
                "stack",
                X86_STACK_TOP_GPA - LINUX_STACK_SIZE,
                LINUX_STACK_SIZE,
            ),
        ] {
            assert!(
                gpa + size <= X86_MEM_SIZE as u64,
                "{name}: GPA {gpa:#x} + {size:#x} exceeds X86_MEM_SIZE"
            );
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn seed_entry_overrides_only_the_named_regs() {
        let mut snap = X8664BhyveSnapshot::zeroed();
        snap.gpr[GPR_IDX_RBX] = 0x1111;
        snap.gpr[GPR_IDX_RAX] = 0x9999;
        snap.rsp = 0x2222;
        snap.fs_base = 0x3333;
        snap.rip = 0x4444;

        let entry = carrick_hal::GuestEntryRegs {
            return_value: 0,
            stack: Some(0xDEAD_0000),
            tls: Some(0xBEEF_0000),
        };
        let seeded = seed_entry_snapshot_bhyve(&snap, entry, 0x5000);

        assert_eq!(seeded.gpr[GPR_IDX_RAX], 0, "child clone returns 0 in RAX");
        assert_eq!(seeded.rsp, 0xDEAD_0000, "child stack");
        assert_eq!(seeded.fs_base, 0xBEEF_0000, "child TLS");
        assert_eq!(seeded.rip, 0x5000, "resume PC past the doorbell");
        assert_eq!(seeded.gpr[GPR_IDX_RBX], 0x1111, "other GPRs inherited");
    }
}
