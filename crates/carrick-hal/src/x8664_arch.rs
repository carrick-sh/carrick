//! `X8664GuestArch` — the x86_64 implementation of the [`GuestArch`] seam.
//!
//! This is the second `GuestArch` impl (after [`crate::aarch64_arch`]). It lives
//! in `carrick-hal` (host-OS-independent) so it compiles and unit-tests on
//! macOS, lima, and FreeBSD alike. The bhyve backend wires it through the shared
//! `X86EngineCore<BhyveVmm>` path in `carrick-vmm-bhyve`; this task establishes
//! the standalone impl validated by unit tests.
//!
//! ## Implemented surface
//!
//! - Full x86_64 `rt_sigframe` build/restore ([`build_sigframe`] /
//!   [`restore_sigframe`]) — the codec is implemented, not deferred.
//!
//! ## Phase 2 non-goals (deferred)
//!
//! - A real x86_64 vDSO: `vdso_bytes()` returns `Vec::new()` (spec §4.6). The
//!   guest libc falls back to real SYSCALL instructions per `vdso(7)`.
//! - CR3: NOT in `X8664BootSysregs` — the bhyve backend computes it from the
//!   PML4 root (the TTBR analogue), exactly as the aarch64 backend computes
//!   TTBR0_EL1 from the stage-1 tables.

use crate::guest_arch::{GuestArch, PageTableCodec, PtGranule, SyscallRemap, SyscallTable};
use crate::trap::RawSyscall;
use crate::{RegAccess, TrapError};
use carrick_guest_mem::{GuestMemory, X8664SyscallFrame};

// ─── ELF machine tag ─────────────────────────────────────────────────────────

/// `EM_X86_64` = 62. Source: x86-64 psABI (gABI supplement), §1 / `elf(5)`
/// man-page (man7.org): "A file's `e_machine` member … 62 (EM_X86_64)".
const EM_X86_64: u16 = 62;

// ─── SYSCALL doorbell port (single source of truth) ──────────────────────────

/// The I/O port the LSTAR entry stub's `out %al, $PORT` doorbell writes to. This
/// is THE single source of truth for the doorbell port across every x86 VMM
/// backend (KVM/bhyve/NVMM): the trampoline emitter ([`entry_trampoline_bytes`])
/// derives the immediate byte from this const, and each backend's trap loop
/// matches the resulting `IoOut`/`INOUT`/`EXIT_IO` exit against it.
///
/// `0xC5` is an otherwise-unused 8-bit port. The `out imm8, %al` form is used so
/// the doorbell is a single 2-byte instruction (`0xE6 PORT`) with no register
/// clobbers beyond `%al` and no stack use. Source: AMD64 ISA / Intel SDM
/// vol. 2B "OUT" (`E6 ib` — output byte to I/O port address).
pub const SYSCALL_DOORBELL_PORT: u16 = 0xC5;

// ─── Granule (same shape as aarch64 stage-1; only descriptor bits differ) ────

/// log2 page size for x86-64 4 KiB granule (Intel SDM vol. 3 §4.5 4-level paging).
const X8664_PAGE_SHIFT: u32 = 12;
/// Translation levels: PML4 → PDPT → PD → PT (Intel SDM vol. 3, §4.5).
const X8664_PT_LEVELS: u8 = 4;
/// 9-bit index per level: 512 entries × 8 bytes = one 4 KiB table.
const X8664_PT_INDEX_BITS: u32 = 9;

// ─── X8664Mmu ─────────────────────────────────────────────────────────────────

/// The x86-64 page-table descriptor codec: delegates to
/// [`carrick_mem::pml4::Pml4Manager`] and
/// [`carrick_mem::pml4::walk_descriptors`].
#[derive(Clone, Copy, Debug)]
pub struct X8664Mmu;

impl PageTableCodec for X8664Mmu {
    fn page_shift() -> u32 {
        X8664_PAGE_SHIFT
    }

    fn granule() -> PtGranule {
        PtGranule {
            page_shift: X8664_PAGE_SHIFT,
            levels: X8664_PT_LEVELS,
            index_bits: X8664_PT_INDEX_BITS,
        }
    }

    type Manager = carrick_mem::pml4::Pml4Manager;
    type Error = carrick_mem::pml4::Pml4Error;

    fn new_manager(bytes: Vec<u8>, base: u64) -> Self::Manager {
        carrick_mem::pml4::Pml4Manager::new(bytes, base)
    }

    fn walk_descriptors(bytes: &[u8], base: u64, va: u64) -> [u64; 4] {
        carrick_mem::pml4::walk_descriptors(bytes, base, va)
    }
}

// ─── X8664SyscallTable ────────────────────────────────────────────────────────

/// The x86_64 syscall-number metadata table — a thin wrapper over
/// [`carrick_abi::syscall_x86_64::lookup_x86_64`].
#[derive(Clone, Copy, Debug)]
pub struct X8664SyscallTable;

impl SyscallTable for X8664SyscallTable {
    fn name(number: u64) -> Option<&'static str> {
        carrick_abi::syscall_x86_64::lookup_x86_64(number).map(|s| s.name)
    }

    fn is_known(number: u64) -> bool {
        carrick_abi::syscall_x86_64::lookup_x86_64(number).is_some()
    }

    /// x86_64→canonical remap: delegates to the table entry's `.remap` field.
    fn remap(number: u64) -> SyscallRemap {
        match carrick_abi::syscall_x86_64::lookup_x86_64(number) {
            Some(entry) => entry.remap,
            None => SyscallRemap::Unknown,
        }
    }
}

// ─── arch_prctl(2): shared x86_64 FS/GS-base policy ──────────────────────────
//
// `arch_prctl` is the sole `SyscallRemap::Native` x86_64 syscall: it sets/reads
// the FS/GS segment base (the long-mode TLS pointer). Setting those bases is a
// per-vCPU register op the ISA-neutral `SyscallDispatcher` cannot perform, so an
// x86_64 trap engine MUST service it before the syscall reaches the dispatcher —
// where the raw x86 number 158 would otherwise collide with canonical
// `getgroups`=158 and TLS would stay unset (faulting on first access). The POLICY
// (which subfunction does what) is identical across backends; only the register
// MECHANISM differs (KVM `KVM_SET_SREGS` vs bhyve `vm_set_desc`), captured by
// [`SegmentBaseRegs`]. Both KVM's x86 trap engine and the shared bhyve x86
// engine call [`service_arch_prctl`] from their syscall path. Source:
// arch_prctl(2) man7.org.

/// The raw x86_64 `arch_prctl` syscall number (man7.org syscalls(2)).
pub const ARCH_PRCTL_X86_NR: u64 = 158;

/// Per-backend FS/GS segment-base register access — the only ISA-mechanism part
/// of `arch_prctl`. KVM implements it via `KVM_GET/SET_SREGS`; bhyve via
/// `vm_get/set_desc`. (Distinct method names avoid clashing with any inherent
/// `set_fs_base`/etc. the engines also expose.)
pub trait SegmentBaseRegs {
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), TrapError>;
    fn seg_get_fs_base(&self) -> Result<u64, TrapError>;
    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), TrapError>;
    fn seg_get_gs_base(&self) -> Result<u64, TrapError>;
}

/// Service `arch_prctl(code, addr)` — the shared policy both x86_64 backends run
/// before surfacing a syscall to the dispatcher. Returns the Linux return value
/// (`0` on success, `-EINVAL` for an unknown subfunction). The GET subfunctions
/// write the base to the user pointer; a bad pointer is swallowed (ret 0) — the
/// same behavior the per-backend standalone loops had (a `-EFAULT` fidelity gap
/// tracked separately, not introduced here). Source: arch_prctl(2) man7.org.
pub fn service_arch_prctl<E>(engine: &mut E, code: u64, addr: u64) -> Result<i64, TrapError>
where
    E: SegmentBaseRegs + carrick_guest_mem::GuestMemory,
{
    /// `ARCH_SET_GS` (arch_prctl(2)).
    const ARCH_SET_GS: u64 = 0x1001;
    /// `ARCH_SET_FS` — the musl/glibc TLS pointer.
    const ARCH_SET_FS: u64 = 0x1002;
    /// `ARCH_GET_FS`.
    const ARCH_GET_FS: u64 = 0x1003;
    /// `ARCH_GET_GS`.
    const ARCH_GET_GS: u64 = 0x1004;
    /// `-EINVAL` (asm-generic errno 22) for an unknown subfunction.
    const NEG_EINVAL: i64 = -22;
    Ok(match code {
        ARCH_SET_FS => {
            engine.seg_set_fs_base(addr)?;
            0
        }
        ARCH_GET_FS => {
            let v = engine.seg_get_fs_base()?;
            let _ = engine.write_bytes(addr, &v.to_le_bytes());
            0
        }
        ARCH_SET_GS => {
            engine.seg_set_gs_base(addr)?;
            0
        }
        ARCH_GET_GS => {
            let v = engine.seg_get_gs_base()?;
            let _ = engine.write_bytes(addr, &v.to_le_bytes());
            0
        }
        _ => NEG_EINVAL,
    })
}

// ─── X8664BootSysregs ─────────────────────────────────────────────────────────

/// Number of GDT entries in carrick's minimal long-mode descriptor table.
pub const GDT_LEN: usize = 5;

/// The x86_64 initial bring-up CPU register values for carrick's guest.
///
/// Sources (ISA references — NOT Linux kernel or glibc source): CR0/CR4 per
/// OSDev "CPU Registers x86" and Intel SDM vol. 3 §2.5; EFER per AMD APM
/// vol. 2 §3.1.7 and Intel SDM vol. 3 §2.2.1; LSTAR/STAR/SFMASK per AMD APM
/// vol. 2 §3.1.7 and OSDev "SYSCALL/SYSRET"; GDT per OSDev "GDT Tutorial"
/// and Intel SDM vol. 3 §3.4.5.
///
/// NOTE: CR3 is deliberately NOT here. The bhyve backend computes the PML4
/// root GPA from the guest RAM layout (the TTBR0_EL1 analogue) and
/// programs it directly.
#[derive(Clone, Copy, Debug)]
pub struct X8664BootSysregs {
    /// CR0 = 0x8001_0033: PE(0)|MP(1)|ET(4)|NE(5)|WP(16)|PG(31).
    /// PE enables protected mode, PG enables paging (both required for 64-bit
    /// long mode). WP makes ring-0 honor U/S+R/W to protect user mappings.
    /// Source: Intel SDM vol. 3 §2.5; OSDev "CPU Registers x86".
    pub cr0: u64,
    /// CR4 = 0x0000_0620: PAE(5)|OSFXSR(9)|OSXMMEXCPT(10).
    /// PAE is required for IA-32e (64-bit) paging (Intel SDM vol. 3 §4.1.1).
    /// OSFXSR/OSXMMEXCPT enable SSE, which musl-static uses for memcpy/strlen.
    /// Source: Intel SDM vol. 3 §2.5; OSDev "CPU Registers x86".
    pub cr4: u64,
    /// EFER = 0x0000_0D01: SCE(0)|LME(8)|LMA(10)|NXE(11).
    /// SCE enables SYSCALL/SYSRET (without it SYSCALL raises #UD, AMD APM
    /// vol. 2 §3.1.7). LME+LMA activates IA-32e long mode. NXE makes the
    /// PML4 NX bit (bit 63) effective for W^X leaf encodings (Intel SDM
    /// vol. 3 §4.6). Source: AMD APM vol. 2 §3.1.7; Intel SDM vol. 3 §2.2.1.
    pub efer: u64,
    /// LSTAR: the GPA of carrick's ring-0 SYSCALL entry stub. The hardware
    /// loads RIP from LSTAR on SYSCALL. carrick places the two-instruction
    /// stub (`out %al,$0xC5` ; `sysretq`) at
    /// `carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE`.
    /// Source: AMD APM vol. 2 §3.1.7; OSDev "SYSCALL/SYSRET".
    pub lstar: u64,
    /// STAR = 0x0013_0008_0000_0000: user-base[63:48]=0x13, kernel-base[47:32]=0x08.
    ///
    /// STAR[47:32]=0x0008: SYSCALL loads CS=0x08 (GDT[1] kCS64), SS=0x10 (GDT[2] kSS).
    /// STAR[63:48]=0x0013: SYSRET loads SS=0x1B (0x13+8=0x18|RPL3, GDT[3] uSS)
    /// and CS=0x23 (0x13+16=0x20|RPL3, GDT[4] uCS64).
    /// GDT order: null/kCS/kSS/uSS/uCS (see `gdt` field).
    /// Source: AMD APM vol. 2 §3.1.7; OSDev "SYSCALL/SYSRET".
    pub star: u64,
    /// SFMASK = 0x0004_0700: clears IF(9)|TF(8)|DF(10)|AC(18) from RFLAGS on SYSCALL.
    /// IF masked so no interrupt window opens inside the two-instruction stub.
    /// TF/DF/AC cleared for single-step, C calling convention, and alignment safety.
    /// Source: AMD APM vol. 2 §3.1.7; Intel SDM vol. 1 §3.4.3 (RFLAGS).
    pub sfmask: u64,
    /// Initial RFLAGS: 0x0000_0002 (reserved bit 1 always set per Intel SDM
    /// vol. 1 §3.4.3 "EFLAGS register — bit 1 is reserved and always 1").
    pub rflags: u64,
    /// Minimal 5-entry GDT image (SYSRET-dictated order, AMD APM vol. 2 §3.1.7):
    /// `[0]=null`, `[1]=0x08 kCS64`, `[2]=0x10 kSS`, `[3]=0x18 uSS`, `[4]=0x20 uCS64`.
    ///
    /// Long-mode descriptor bit layout per Intel SDM vol. 3 §3.4.5: bits 47=P,
    /// 46:45=DPL, 44=S, 43:40=type (0xA=exec/read, 0x2=data/RW), 53=L (64-bit
    /// code), all base/limit fields vestigial. Encoded (ACCESSED-bit set): kCS64=0x0020_9B00_0000_0000,
    /// kSS=0x0000_9300_0000_0000, uSS=0x0000_F300_0000_0000,
    /// uCS64=0x0020_FB00_0000_0000. Source: Intel SDM vol. 3 §3.4.5.
    pub gdt: [u64; GDT_LEN],
}

impl X8664BootSysregs {
    /// Build the canonical bring-up register values.
    pub fn new() -> Self {
        Self {
            // CR0: PE|MP|ET|NE|WP|PG — protected mode + paging + WP for U/S
            // bit-field integrity. 0x8001_0033 per Intel SDM vol. 3 §2.5.
            cr0: 0x8001_0033,
            // CR4: PAE(5)|OSFXSR(9)|OSXMMEXCPT(10) = 0x0620.
            // PAE required for IA-32e paging (Intel SDM vol. 3 §4.1.1).
            // OSFXSR+OSXMMEXCPT enable SSE for musl-static builtins.
            cr4: 0x0000_0620,
            // EFER: SCE(0)|LME(8)|LMA(10)|NXE(11) = 0x0D01.
            // SCE: enables SYSCALL/SYSRET (AMD APM vol. 2 §3.1.7).
            // LME+LMA: IA-32e long mode active.
            // NXE: enables PML4 NX bit (Intel SDM vol. 3 §4.6).
            efer: 0x0000_0D01,
            // LSTAR: carrick's ring-0 SYSCALL entry stub GPA.
            // The backend fills this from the RAM layout; we store the
            // canonical VM-space constant here as the architectured value.
            // Source: carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE.
            lstar: carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
            // STAR: user-base=0x0013 [63:48] | kernel-base=0x0008 [47:32].
            // SYSCALL → CS=0x08 (GDT[1]), SS=0x10 (GDT[2]).
            // SYSRET  → SS=0x1B (0x13+8, 0x18|RPL3), CS=0x23 (0x13+16, 0x20|RPL3).
            // Source: AMD APM vol. 2 §3.1.7; OSDev "SYSCALL/SYSRET".
            star: 0x0013_0008_0000_0000,
            // SFMASK: IF(9)|TF(8)|DF(10)|AC(18) = 0x0004_0700.
            // Masks IF on entry so no interrupt window opens in the stub.
            // Source: AMD APM vol. 2 §3.1.7; Intel SDM vol. 1 §3.4.3.
            sfmask: 0x0004_0700,
            // RFLAGS: reserved bit 1 always set (Intel SDM vol. 1 §3.4.3).
            rflags: 0x0000_0002,
            // GDT[5]: null / kCS64 / kSS / uSS / uCS64.
            // Encoding per Intel SDM vol. 3 §3.4.5 (see struct docs above).
            //
            // The type fields carry the ACCESSED bit set (code 0xB not 0xA,
            // data 0x3 not 0x2). When `iretq`/segment-load reads a descriptor
            // from the GDT, the resulting segment Access-Rights must be VMX-
            // valid; under NESTED VMX (bhyve-on-KVM) a loaded segment with
            // accessed=0 trips KVM's "invalid guest state" / emulation_required
            // path, which it cannot emulate for an L2 guest → synthesized
            // TRIPLE_FAULT (the M1 iretq blocker, 2026-06-13). Pre-setting
            // accessed avoids the writeback AND keeps the loaded AR valid.
            gdt: [
                // [0] null
                0x0000_0000_0000_0000,
                // [1] 0x08 kernel CS64: P=1 S=1 type=B(exec/read/ACCESSED) DPL=0 L=1
                //   byte 5 = 0x9B; bits[53]=L=1 → byte 6 = 0x20
                0x0020_9B00_0000_0000,
                // [2] 0x10 kernel SS: P=1 S=1 type=3(data/RW/ACCESSED) DPL=0
                //   byte 5 = 0x93; byte 6 = 0x00 (L=0 for data)
                0x0000_9300_0000_0000,
                // [3] 0x18 user SS: P=1 S=1 type=3(data/RW/ACCESSED) DPL=3
                //   DPL=11 → bits[46:45]=11; byte 5 = 0xF3
                0x0000_F300_0000_0000,
                // [4] 0x20 user CS64: P=1 S=1 type=B(exec/read/ACCESSED) DPL=3 L=1
                //   byte 5 = 0xFB; byte 6 = 0x20 (L=1)
                0x0020_FB00_0000_0000,
            ],
        }
    }
}

impl Default for X8664BootSysregs {
    fn default() -> Self {
        Self::new()
    }
}

// ─── LSTAR entry-trampoline bytes ─────────────────────────────────────────────

/// The two-instruction LSTAR stub that receives every `SYSCALL` from the guest.
///
/// ```text
/// E6 C5     out %al, $0xC5   ; doorbell → VM_EXITCODE_INOUT; host reads RAX
/// 48 0F 07  sysretq           ; return to ring 3 (REX.W + 0F 07)
/// ```
///
/// Rationale (spec §4.5): no stack, no register clobbers beyond the
/// architecturally ABI-dead RCX/R11 (SYSCALL/SYSRET hardware clobbers),
/// IF masked by SFMASK ⇒ no interrupt window. Single-vCPU Phase 2: no
/// swapgs, no TSS, no kernel stack needed.
///
/// Encoding sources:
///   - `out imm8, %al`: opcode E6 ib — "Output byte to I/O port address"
///     (Intel SDM vol. 2B "OUT" instruction reference).
///   - `sysretq`: REX.W (48) + 0F 07 — 64-bit SYSRET (AMD APM vol. 3
///     §2.5 "SYSRET"; Intel SDM vol. 2B "SYSRET" — REX.W selects 64-bit
///     operand size returning to 64-bit userspace).
pub fn entry_trampoline_bytes() -> Vec<u8> {
    // `out %al, $SYSCALL_DOORBELL_PORT` ; sysretq
    //
    // The port immediate is derived from the single-source const so the
    // trampoline byte and every backend's doorbell-match cannot drift apart.
    // The port is an 8-bit immediate (`out imm8, %al` = `E6 ib`); assert it fits.
    const _: () = assert!(
        SYSCALL_DOORBELL_PORT <= 0xFF,
        "SYSCALL_DOORBELL_PORT must fit in the `out imm8, %al` (E6 ib) immediate"
    );
    vec![0xE6, SYSCALL_DOORBELL_PORT as u8, 0x48, 0x0F, 0x07]
}

// ─── X8664GuestArch ──────────────────────────────────────────────────────────

/// The x86_64 [`GuestArch`] impl.
///
/// Standalone — validates by unit tests here. The bhyve backend
/// (`crates/carrick-vmm-bhyve`) wires this through `X86EngineCore<BhyveVmm>`.
/// It is host-OS-independent (pure struct + const data) so it builds on macOS,
/// lima Linux, and FreeBSD equally.
#[derive(Clone, Copy, Debug, Default)]
pub struct X8664GuestArch;

impl GuestArch for X8664GuestArch {
    type Frame = X8664SyscallFrame;
    type Mmu = X8664Mmu;
    type Table = X8664SyscallTable;
    type BootSysregs = X8664BootSysregs;

    fn decode_syscall(frame: &Self::Frame) -> (u64, [u64; 6]) {
        // Per syscall(2) (man7.org) "Architecture calling conventions",
        // x86-64 column: number in RAX; args in RDI, RSI, RDX, R10, R8, R9.
        (
            frame.rax,
            [
                frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
            ],
        )
    }

    fn elf_machine() -> u16 {
        EM_X86_64 // 62 — x86-64 psABI / elf(5) man-page
    }

    fn uname_machine() -> &'static str {
        "x86_64"
    }

    fn vdso_bytes() -> Vec<u8> {
        // No vDSO in Phase 2 (spec §4.6). AT_SYSINFO_EHDR is omitted; the
        // guest libc falls back to real SYSCALL instructions per vdso(7).
        Vec::new()
    }

    fn entry_trampoline_bytes() -> Vec<u8> {
        entry_trampoline_bytes()
    }

    fn bootstrap_sysregs() -> X8664BootSysregs {
        X8664BootSysregs::new()
    }

    fn build_sigframe<E: RegAccess + GuestMemory>(
        engine: &mut E,
        params: crate::sigframe::InjectParams,
    ) -> Result<crate::sigframe::SigframeInject, TrapError> {
        use crate::Reg;
        use carrick_abi::{X8664Fpstate, X8664Rtsigframe, X8664Sigcontext, X8664Ucontext};
        use zerocopy::IntoBytes;

        let p = params;

        // ── Snapshot the interrupted GPRs into the gregset (psABI order). ──
        let mut mc = X8664Sigcontext::empty();
        mc.r8 = engine.get_reg(Reg::R8)?;
        mc.r9 = engine.get_reg(Reg::R9)?;
        mc.r10 = engine.get_reg(Reg::R10)?;
        mc.r11 = engine.get_reg(Reg::R11)?;
        mc.r12 = engine.get_reg(Reg::R12)?;
        mc.r13 = engine.get_reg(Reg::R13)?;
        mc.r14 = engine.get_reg(Reg::R14)?;
        mc.r15 = engine.get_reg(Reg::R15)?;
        mc.rdi = engine.get_reg(Reg::Rdi)?;
        mc.rsi = engine.get_reg(Reg::Rsi)?;
        mc.rbp = engine.get_reg(Reg::Rbp)?;
        mc.rbx = engine.get_reg(Reg::Rbx)?;
        mc.rdx = engine.get_reg(Reg::Rdx)?;
        mc.rcx = engine.get_reg(Reg::Rcx)?;
        let saved_rsp = engine.get_reg(Reg::Rsp)?;
        mc.rsp = saved_rsp;
        // RAX = the syscall retval, so handler-return resumes with it visible.
        mc.rax = match p.pending_syscall_retval {
            Some(ret) => ret as u64,
            None => engine.get_reg(Reg::Rax)?,
        };
        // Resume RIP: kick path uses the live PC; syscall path uses RCX (the
        // SYSCALL instruction stashed the user return RIP there, untouched by
        // complete_syscall which only writes RAX).
        let resume_rip = match p.interrupted_pc {
            Some(pc) => pc,
            None => mc.rcx,
        };
        mc.rip = resume_rip;
        mc.eflags = p.pstate_source;
        // SA_RESTART: rewind RIP to re-execute the 2-byte `syscall` (0F 05) and
        // restore RAX = the original syscall number (the engine passes it in
        // `orig_x0`; complete_syscall clobbered RAX with the retval). Only valid
        // on the syscall-boundary path (caller guarantees interrupted_pc None).
        if p.restart_syscall {
            mc.rip = resume_rip.wrapping_sub(2);
            mc.rax = p.orig_x0;
        }
        // Ring-3 selectors (informational; rt_sigreturn restores GPRs, not segs).
        mc.cs = 0x23;
        mc.ss = 0x1b;
        mc.cr2 = p.fault_siginfo.map(|(_, addr)| addr).unwrap_or(0);

        // ── Compute the new RSP: skip the 128-byte red zone (or the alt-stack
        //    top for SA_ONSTACK), reserve the frame, and align so &pretcode ≡ 8
        //    (mod 16) at handler entry (x86-64 psABI: RSP+8 is 16-aligned at a
        //    function entry; the handler is entered as-if-CALLed). ──
        let frame_size = core::mem::size_of::<X8664Rtsigframe>() as u64;
        let base = match p.altstack {
            Some((ss_sp, ss_size)) => ss_sp.wrapping_add(ss_size),
            None => saved_rsp.wrapping_sub(128),
        };
        let new_sp = (base.wrapping_sub(frame_size) & !0xf).wrapping_sub(8);
        // fpstate pointer = the FXSAVE area's address within the frame.
        mc.fpstate = new_sp + core::mem::offset_of!(X8664Rtsigframe, fpstate) as u64;

        // ── FXSAVE area: MXCSR + XMM0–15. ──
        let mut fp = X8664Fpstate::empty();
        if p.fpsimd_enabled {
            fp.mxcsr = engine.get_fpcr()? as u32;
            let mut xmm = [0u32; 64];
            for n in 0..16u32 {
                let v = engine.get_vreg(n)?.to_le_bytes();
                let b = (n * 4) as usize;
                for j in 0..4 {
                    xmm[b + j] =
                        u32::from_le_bytes([v[j * 4], v[j * 4 + 1], v[j * 4 + 2], v[j * 4 + 3]]);
                }
            }
            fp.xmm_space = xmm;
        }

        // ── siginfo: queued > fault > SI_USER; re-stamp si_signo. ──
        let mut siginfo = match (p.queued_siginfo, p.fault_siginfo) {
            (Some(q), _) => q,
            (None, Some((si_code, si_addr))) => {
                let mut s = carrick_abi::LinuxSiginfo::empty();
                s.si_code = si_code;
                s.si_addr = si_addr;
                s
            }
            (None, None) => {
                let mut s = carrick_abi::LinuxSiginfo::empty();
                s.si_code = carrick_abi::LINUX_SI_USER;
                s
            }
        };
        siginfo.si_signo = p.signum;

        // ── ucontext. ──
        let mut uc = X8664Ucontext::empty();
        uc.uc_sigmask[0] = p.saved_sigmask;
        if let Some((ss_sp, ss_size)) = p.altstack {
            uc.uc_stack = carrick_abi::LinuxSignalStack {
                ss_sp,
                ss_flags: carrick_abi::LINUX_SS_ONSTACK as i32,
                _pad0: 0,
                ss_size,
            };
        }
        uc.uc_mcontext = mc;

        // ── Assemble + write the frame. ──
        let mut frame = X8664Rtsigframe::empty();
        // pretcode: the restorer the handler RETs to (→ rt_sigreturn). musl/glibc
        // pass an explicit sa_restorer; fall back to the fixed trampoline.
        frame.pretcode = if p.sa_restorer != 0 {
            p.sa_restorer
        } else {
            p.sigreturn_trampoline_base
        };
        frame.uc = uc;
        frame.info = siginfo;
        frame.fpstate = fp;
        engine
            .write_bytes(new_sp, frame.as_bytes())
            .map_err(|_| TrapError::SignalDeliveryFault)?;

        // ── Handler entry register state (x86-64 psABI handler ABI). ──
        engine.set_reg(Reg::Rsp, new_sp)?;
        engine.set_reg(Reg::Rdi, p.signum as u64)?; // arg0 = signum
        engine.set_reg(
            Reg::Rsi,
            new_sp + core::mem::offset_of!(X8664Rtsigframe, info) as u64,
        )?; // arg1 = &siginfo
        engine.set_reg(
            Reg::Rdx,
            new_sp + core::mem::offset_of!(X8664Rtsigframe, uc) as u64,
        )?; // arg2 = &ucontext
        engine.set_reg(Reg::Rax, 0)?;
        engine.set_reg(Reg::Rip, p.handler)?;
        // The ABI requires DF=0 at function entry; also clear TF. (bit10=DF, bit8=TF)
        let rflags = engine.get_reg(Reg::Rflags)?;
        engine.set_reg(Reg::Rflags, rflags & !((1u64 << 10) | (1u64 << 8)))?;

        Ok(crate::sigframe::SigframeInject {
            new_sp,
            saved_pc: resume_rip,
        })
    }

    fn restore_sigframe<E: RegAccess + GuestMemory>(
        engine: &mut E,
        fpsimd_enabled: bool,
    ) -> Result<crate::sigframe::SigframeRestore, TrapError> {
        use crate::Reg;
        use carrick_abi::X8664Rtsigframe;
        use zerocopy::FromBytes;

        // At rt_sigreturn the handler's `ret` already popped the 8-byte pretcode,
        // so RSP points just past it (at uc); the frame starts at RSP - 8 (the
        // x86-64 kernel does the identical `regs->sp - sizeof(long)`).
        let rsp = engine.get_reg(Reg::Rsp)?;
        let frame_sp = rsp.wrapping_sub(8);
        let size = core::mem::size_of::<X8664Rtsigframe>();
        let bytes = engine
            .read_bytes(frame_sp, size)
            .map_err(|e| TrapError::Hypervisor(format!("x86 sigframe read failed: {e}")))?;
        let frame = X8664Rtsigframe::read_from_bytes(&bytes)
            .map_err(|_| TrapError::Hypervisor("x86 sigframe decode failed".into()))?;

        // Copy nested packed fields OUT into standalone locals (cannot borrow
        // fields of a #[repr(C, packed)] value).
        let uc = frame.uc;
        let mc = uc.uc_mcontext;
        let sigmask = { uc.uc_sigmask }[0];
        let fp = frame.fpstate;

        // Validate the resume RIP is canonical (bits 47..63 sign-extended) — a
        // corrupt frame / rt_sigreturn outside a handler would otherwise resume
        // the vCPU at garbage. Replaces the aarch64 EL0-PSTATE gate.
        let rip = mc.rip;
        let top = rip >> 47;
        if top != 0 && top != 0x1_ffff {
            return Err(TrapError::Hypervisor(format!(
                "x86 rt_sigreturn: non-canonical resume RIP 0x{rip:x} (frame at 0x{frame_sp:x})"
            )));
        }

        // Restore GPRs + RIP + RSP.
        engine.set_reg(Reg::R8, mc.r8)?;
        engine.set_reg(Reg::R9, mc.r9)?;
        engine.set_reg(Reg::R10, mc.r10)?;
        engine.set_reg(Reg::R11, mc.r11)?;
        engine.set_reg(Reg::R12, mc.r12)?;
        engine.set_reg(Reg::R13, mc.r13)?;
        engine.set_reg(Reg::R14, mc.r14)?;
        engine.set_reg(Reg::R15, mc.r15)?;
        engine.set_reg(Reg::Rdi, mc.rdi)?;
        engine.set_reg(Reg::Rsi, mc.rsi)?;
        engine.set_reg(Reg::Rbp, mc.rbp)?;
        engine.set_reg(Reg::Rbx, mc.rbx)?;
        engine.set_reg(Reg::Rdx, mc.rdx)?;
        engine.set_reg(Reg::Rax, mc.rax)?;
        engine.set_reg(Reg::Rcx, mc.rcx)?;
        engine.set_reg(Reg::Rsp, mc.rsp)?;
        engine.set_reg(Reg::Rip, mc.rip)?;
        // RFLAGS: restore, force reserved bit 1 = 1, keep IF (bit 9), clear TF.
        let ef = (mc.eflags | 0x2) & !(1u64 << 8);
        engine.set_reg(Reg::Rflags, ef)?;

        // Restore MXCSR + XMM0–15 from the frame's FXSAVE area.
        if fpsimd_enabled {
            engine.set_fpcr(u64::from({ fp }.mxcsr))?;
            let xmm = fp.xmm_space;
            for n in 0..16u32 {
                let b = (n * 4) as usize;
                let mut raw = [0u8; 16];
                for j in 0..4 {
                    raw[j * 4..j * 4 + 4].copy_from_slice(&xmm[b + j].to_le_bytes());
                }
                engine.set_vreg(n, u128::from_le_bytes(raw))?;
            }
        }

        Ok(crate::sigframe::SigframeRestore {
            sigmask,
            saved_pc: mc.rip,
            frame_sp,
            magic: 0,
        })
    }
}

// ─── x86-64 syscall normalization (shared by every x86 backend) ──────────────
//
// fork(57)/vfork(58)→clone(220) desugar + the clone(220) tls↔child_tid arg-swap
// + the arch_prctl dispatch are PURE guest-ISA ABI (host/VMM-agnostic). They were
// duplicated in the KVM-x86 and bhyve `next_syscall`; hoisted here so both call
// one function. Sources (clean-room, man-pages / psABI only): clone(2) "C
// library/kernel differences" (x86-64 raw arg order; CLONE_VM=0x100,
// CLONE_VFORK=0x4000; exit-signal in the low byte), signal(7) (SIGCHLD=17),
// syscalls(2) (x86-64 fork=57/vfork=58).

/// Canonical (asm-generic / aarch64) `clone` number. x86-64 raw clone (56) and
/// fork(57)/vfork(58) all normalize to this; clone3 (435) does NOT.
pub const CANONICAL_CLONE: u64 = 220;
/// x86-64 `fork(2)` (syscalls(2)). asm-generic/aarch64 have no SYS_fork — they
/// implement fork via clone — so we desugar it to canonical clone(220)+SIGCHLD.
const X86_NR_FORK: u64 = 57;
/// x86-64 `vfork(2)` (syscalls(2)). Desugars to clone(220)+CLONE_VM|CLONE_VFORK|SIGCHLD.
const X86_NR_VFORK: u64 = 58;
/// `SIGCHLD` exit-signal (signal(7)); the low byte of the clone flags word.
const LINUX_SIGCHLD: u64 = 17;
/// `CLONE_VM` (clone(2)).
const LINUX_CLONE_VM: u64 = 0x0000_0100;
/// `CLONE_VFORK` (clone(2)).
const LINUX_CLONE_VFORK: u64 = 0x0000_4000;

/// The result of normalizing a raw x86-64 syscall into the canonical ABI.
pub enum SyscallNorm {
    /// Ready for the dispatcher: number remapped to canonical, args in
    /// asm-generic order, fork/vfork desugared to clone.
    Plain(RawSyscall),
    /// arch_prctl(SET/GET FS|GS): serviced engine-side (FS/GS base is VMM
    /// hidden state); the engine calls `service_arch_prctl(self, code, addr)`.
    ArchPrctl { code: u64, addr: u64 },
}

impl X8664GuestArch {
    /// Pure x86-64 ABI normalization shared by every x86 backend (KVM, bhyve,
    /// HVF). Folds decode + remap + fork/vfork→clone desugar + clone arg-swap +
    /// arch_prctl dispatch into one place — no host/VMM state.
    pub fn normalize_syscall(frame: &X8664SyscallFrame) -> SyscallNorm {
        let (x86_number, mut args) = X8664GuestArch::decode_syscall(frame);

        if x86_number == ARCH_PRCTL_X86_NR {
            return SyscallNorm::ArchPrctl {
                code: args[0],
                addr: args[1],
            };
        }
        if x86_number == X86_NR_FORK {
            return SyscallNorm::Plain(RawSyscall {
                number: CANONICAL_CLONE,
                args: [LINUX_SIGCHLD, 0, 0, 0, 0, 0],
            });
        }
        if x86_number == X86_NR_VFORK {
            return SyscallNorm::Plain(RawSyscall {
                number: CANONICAL_CLONE,
                args: [
                    LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            });
        }

        let canonical = match X8664SyscallTable::remap(x86_number) {
            SyscallRemap::Direct(c) => c,
            SyscallRemap::Native | SyscallRemap::Unknown => x86_number,
        };
        // x86-64 raw clone(2) arg order (flags, stack, ptid, child_tid, tls) vs
        // the asm-generic order the dispatcher binds (.., tls, child_tid): swap
        // args[3]<->args[4] for canonical clone(220) only (clone3=435 is a
        // struct-based syscall with no positional args to swap).
        if canonical == CANONICAL_CLONE {
            args.swap(3, 4);
        }
        SyscallNorm::Plain(RawSyscall {
            number: canonical,
            args,
        })
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod normalize_tests {
    use super::*;

    fn frame(rax: u64, a: [u64; 6]) -> X8664SyscallFrame {
        X8664SyscallFrame {
            rax,
            rdi: a[0],
            rsi: a[1],
            rdx: a[2],
            r10: a[3],
            r8: a[4],
            r9: a[5],
        }
    }

    #[test]
    fn fork_desugars_to_clone_sigchld() {
        // x86 fork = 57 → canonical clone(220) with flags=SIGCHLD(17), rest 0.
        match X8664GuestArch::normalize_syscall(&frame(57, [0; 6])) {
            SyscallNorm::Plain(rs) => {
                assert_eq!(rs.number, 220);
                assert_eq!(rs.args, [17, 0, 0, 0, 0, 0]);
            }
            _ => panic!("fork must be Plain(clone)"),
        }
    }

    #[test]
    fn vfork_desugars_to_clone_vm_vfork_sigchld() {
        // x86 vfork = 58 → clone(220) flags = CLONE_VM|CLONE_VFORK|SIGCHLD.
        match X8664GuestArch::normalize_syscall(&frame(58, [0; 6])) {
            SyscallNorm::Plain(rs) => {
                assert_eq!(rs.number, 220);
                assert_eq!(rs.args[0], 0x0000_0100 | 0x0000_4000 | 17);
            }
            _ => panic!("vfork must be Plain(clone)"),
        }
    }

    #[test]
    fn clone_swaps_tls_and_child_tid() {
        // x86 clone = 56 → canonical 220; raw x86 arg order
        // (flags, stack, ptid, child_tid, tls) → asm-generic (.., tls, child_tid):
        // args[3] (child_tid) and args[4] (tls) swap.
        // raw args: flags=0x11, stack=0x22, ptid=0x33, child_tid=0xC, tls=0xT
        match X8664GuestArch::normalize_syscall(&frame(56, [0x11, 0x22, 0x33, 0xC, 0x7, 0])) {
            SyscallNorm::Plain(rs) => {
                assert_eq!(rs.number, 220);
                assert_eq!(rs.args[3], 0x7, "args[3] becomes tls");
                assert_eq!(rs.args[4], 0xC, "args[4] becomes child_tid");
            }
            _ => panic!("clone must be Plain"),
        }
    }

    #[test]
    fn clone3_is_not_swapped() {
        // x86 clone3 = 435 → canonical 435 (struct-based; no positional swap).
        match X8664GuestArch::normalize_syscall(&frame(435, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])) {
            SyscallNorm::Plain(rs) => {
                assert_ne!(rs.number, 220);
                assert_eq!(rs.args[3], 0xDD, "clone3 args untouched");
                assert_eq!(rs.args[4], 0xEE);
            }
            _ => panic!("clone3 must be Plain"),
        }
    }

    #[test]
    fn arch_prctl_returns_archprctl() {
        // x86 arch_prctl = 158, args: code=0x1002 (SET_FS), addr=0xDEAD.
        match X8664GuestArch::normalize_syscall(&frame(158, [0x1002, 0xDEAD, 0, 0, 0, 0])) {
            SyscallNorm::ArchPrctl { code, addr } => {
                assert_eq!(code, 0x1002);
                assert_eq!(addr, 0xDEAD);
            }
            _ => panic!("arch_prctl must be ArchPrctl"),
        }
    }

    #[test]
    fn ordinary_syscall_is_plain_canonical() {
        // x86 write = 1 → canonical write = 64 (Direct). args pass through.
        match X8664GuestArch::normalize_syscall(&frame(1, [1, 0x100, 5, 0, 0, 0])) {
            SyscallNorm::Plain(rs) => {
                assert_eq!(rs.number, 64); // canonical write
                assert_eq!(rs.args, [1, 0x100, 5, 0, 0, 0]);
            }
            _ => panic!("write must be Plain"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_abi::syscall_x86_64::SyscallRemap;

    // ── decode mapping ───────────────────────────────────────────────────────

    #[test]
    fn decode_maps_rax_to_number_and_rdi_through_r9_to_args() {
        let frame = X8664SyscallFrame {
            rax: 1, // write
            rdi: 10,
            rsi: 11,
            rdx: 12,
            r10: 13,
            r8: 14,
            r9: 15,
        };
        let (number, args) = X8664GuestArch::decode_syscall(&frame);
        assert_eq!(number, 1);
        assert_eq!(args, [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn decode_with_all_distinct_values() {
        let frame = X8664SyscallFrame {
            rax: 231, // exit_group
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        let (number, args) = X8664GuestArch::decode_syscall(&frame);
        assert_eq!(number, 231);
        assert_eq!(args, [0u64; 6]);
    }

    // ── ELF machine tag + uname string ───────────────────────────────────────

    #[test]
    fn elf_machine_is_em_x86_64() {
        // EM_X86_64 = 62 per x86-64 psABI / elf(5) man-page.
        assert_eq!(X8664GuestArch::elf_machine(), 62);
        assert_eq!(X8664GuestArch::uname_machine(), "x86_64");
    }

    // ── vDSO empty (spec §4.6 no-vDSO decision) ───────────────────────────

    #[test]
    fn vdso_bytes_is_empty() {
        assert!(
            X8664GuestArch::vdso_bytes().is_empty(),
            "no vDSO in Phase 2 (spec §4.6); AT_SYSINFO_EHDR omitted"
        );
    }

    // ── LSTAR stub byte-exactness ─────────────────────────────────────────

    #[test]
    fn lstar_stub_bytes_are_exact() {
        // The stub MUST be exactly these 5 bytes.
        // E6 C5          → out %al, $0xC5  (opcode E6 ib, Intel SDM vol. 2B)
        // 48 0F 07       → sysretq         (REX.W + 0F 07, AMD APM vol. 3 §2.5)
        let stub = X8664GuestArch::entry_trampoline_bytes();
        assert_eq!(
            stub,
            vec![0xE6, 0xC5, 0x48, 0x0F, 0x07],
            "LSTAR stub bytes must match the spec exactly"
        );
    }

    #[test]
    fn lstar_stub_port_byte_matches_const() {
        // The single-source agreement guarantee: the trampoline's port-immediate
        // byte (stub[1]) MUST equal SYSCALL_DOORBELL_PORT. This is no longer
        // vacuous w.r.t. a hand-typed literal — the emitter derives the byte from
        // the const — but the check stays as the enforced cross-crate contract so
        // a future refactor that re-hardcodes the byte is caught here.
        let stub = X8664GuestArch::entry_trampoline_bytes();
        assert_eq!(stub[0], 0xE6, "stub[0] must be the `out imm8, %al` opcode");
        assert_eq!(
            stub[1], SYSCALL_DOORBELL_PORT as u8,
            "trampoline port byte must equal SYSCALL_DOORBELL_PORT"
        );
    }

    // ── STAR selector arithmetic (the mandated unit test) ────────────────────
    //
    // GDT order: null[0x00] / kCS[0x08] / kSS[0x10] / uSS[0x18] / uCS[0x20].
    // STAR[47:32] = 0x0008 (kernel_base):
    //   SYSCALL  → CS = kernel_base      = 0x08  (GDT[1] kCS64)
    //              SS = kernel_base + 8  = 0x10  (GDT[2] kSS)
    // STAR[63:48] = 0x0013 (user_base):
    //   SYSRET   → SS = user_base + 8   = 0x1B  (0x18|RPL3, GDT[3] uSS)
    //              CS = user_base + 16  = 0x23  (0x20|RPL3, GDT[4] uCS64)
    // Source: AMD APM vol. 2 §3.1.7 "SYSCALL and SYSRET Instructions".
    #[test]
    fn star_selector_arithmetic_is_correct() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        let star = boot.star;

        // Extract the two 16-bit selector-base fields from STAR.
        let kernel_base = ((star >> 32) & 0xFFFF) as u16; // STAR[47:32]
        let user_base = ((star >> 48) & 0xFFFF) as u16; // STAR[63:48]

        // STAR[47:32] = 0x0008: SYSCALL loads CS=0x08, SS=0x10.
        assert_eq!(kernel_base, 0x0008, "STAR[47:32] must be 0x0008");
        let syscall_cs = kernel_base;
        let syscall_ss = kernel_base + 8;
        assert_eq!(syscall_cs, 0x08, "SYSCALL CS = GDT[1] = 0x08 (kCS64)");
        assert_eq!(syscall_ss, 0x10, "SYSCALL SS = GDT[2] = 0x10 (kSS)");

        // STAR[63:48] = 0x0013: SYSRET loads SS=0x1B (0x18|RPL3),
        //   CS=0x23 (0x20|RPL3). AMD APM vol. 2 §3.1.7: SYSRET ORs RPL=3.
        assert_eq!(user_base, 0x0013, "STAR[63:48] must be 0x0013");
        let sysret_ss = user_base + 8; // = 0x1B (0x18|3)
        let sysret_cs = user_base + 16; // = 0x23 (0x20|3)
        assert_eq!(
            sysret_ss, 0x1B,
            "SYSRET SS = 0x13+8 = 0x1B (0x18|RPL3, uSS)"
        );
        assert_eq!(
            sysret_cs, 0x23,
            "SYSRET CS = 0x13+16 = 0x23 (0x20|RPL3, uCS64)"
        );
    }

    // ── CR0/CR4/EFER bit assertions ────────────────────────────────────────

    #[test]
    fn cr0_has_required_bits() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // PE (bit 0): Protected Mode Enable.
        assert_ne!(boot.cr0 & (1 << 0), 0, "CR0.PE must be set");
        // WP (bit 16): Write Protect (U/S|R/W integrity).
        assert_ne!(boot.cr0 & (1 << 16), 0, "CR0.WP must be set");
        // PG (bit 31): Paging Enable.
        assert_ne!(boot.cr0 & (1 << 31), 0, "CR0.PG must be set");
        // Full value pin.
        assert_eq!(boot.cr0, 0x8001_0033);
    }

    #[test]
    fn cr4_has_required_bits() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // PAE (bit 5): required for IA-32e/long-mode paging.
        assert_ne!(boot.cr4 & (1 << 5), 0, "CR4.PAE must be set");
        // OSFXSR (bit 9): OS SSE support (musl uses SSE).
        assert_ne!(boot.cr4 & (1 << 9), 0, "CR4.OSFXSR must be set");
        // Full value pin.
        assert_eq!(boot.cr4, 0x0000_0620);
    }

    #[test]
    fn efer_has_required_bits() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // SCE (bit 0): SYSCALL/SYSRET enable.
        assert_ne!(boot.efer & (1 << 0), 0, "EFER.SCE must be set");
        // LME (bit 8): Long Mode Enable.
        assert_ne!(boot.efer & (1 << 8), 0, "EFER.LME must be set");
        // LMA (bit 10): Long Mode Active.
        assert_ne!(boot.efer & (1 << 10), 0, "EFER.LMA must be set");
        // NXE (bit 11): No-Execute Enable (for PML4 NX bit).
        assert_ne!(boot.efer & (1 << 11), 0, "EFER.NXE must be set");
        // Full value pin.
        assert_eq!(boot.efer, 0x0000_0D01);
    }

    // ── GDT entry encodings ────────────────────────────────────────────────

    #[test]
    fn gdt_null_entry_is_zero() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        assert_eq!(boot.gdt[0], 0, "GDT[0] (null) must be zero");
    }

    #[test]
    fn gdt_kernel_cs64_encoding() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // kCS64: P=1 S=1 type=A(exec/read) DPL=0 L=1
        assert_eq!(
            boot.gdt[1], 0x0020_9B00_0000_0000,
            "GDT[1] kCS64 (accessed)"
        );
    }

    #[test]
    fn gdt_kernel_ss_encoding() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // kSS: P=1 S=1 type=2(data/RW) DPL=0
        assert_eq!(boot.gdt[2], 0x0000_9300_0000_0000, "GDT[2] kSS (accessed)");
    }

    #[test]
    fn gdt_user_ss_encoding() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // uSS: P=1 S=1 type=2(data/RW) DPL=3
        assert_eq!(boot.gdt[3], 0x0000_F300_0000_0000, "GDT[3] uSS (accessed)");
    }

    #[test]
    fn gdt_user_cs64_encoding() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // uCS64: P=1 S=1 type=A(exec/read) DPL=3 L=1
        assert_eq!(
            boot.gdt[4], 0x0020_FB00_0000_0000,
            "GDT[4] uCS64 (accessed)"
        );
    }

    // ── MMU / PML4 granule ────────────────────────────────────────────────

    #[test]
    fn mmu_granule_matches_pml4_and_aarch64_shape() {
        // Spec §4.4 symmetry: same PtGranule as aarch64 stage-1; only the
        // descriptor bits differ. Mirrors pml4.rs::granule_matches_aarch64_shape.
        assert_eq!(X8664Mmu::page_shift(), 12);
        let g = X8664Mmu::granule();
        assert_eq!(g.page_shift, 12);
        assert_eq!(g.levels, 4);
        assert_eq!(g.index_bits, 9);
    }

    #[test]
    fn mmu_codec_builds_manager_and_walks_descriptors() {
        // A zeroed table image: all non-present → translate returns None,
        // walk returns all-zero.
        let base = 0x20_0000u64;
        let bytes = vec![0u8; 4096 * 6];
        let mgr = X8664Mmu::new_manager(bytes.clone(), base);
        assert_eq!(mgr.translate(0x40_0000), None);
        assert_eq!(X8664Mmu::walk_descriptors(&bytes, base, 0x40_0000), [0; 4]);
    }

    // ── Syscall table wiring ────────────────────────────────────────────────

    #[test]
    fn syscall_table_knows_write() {
        assert!(X8664SyscallTable::is_known(1));
        assert_eq!(X8664SyscallTable::name(1), Some("write"));
        assert_eq!(X8664SyscallTable::remap(1), SyscallRemap::Direct(64));
    }

    #[test]
    fn syscall_table_knows_exit_group() {
        assert!(X8664SyscallTable::is_known(231));
        assert_eq!(X8664SyscallTable::name(231), Some("exit_group"));
        assert_eq!(X8664SyscallTable::remap(231), SyscallRemap::Direct(94));
    }

    #[test]
    fn syscall_table_arch_prctl_is_native() {
        assert_eq!(X8664SyscallTable::remap(158), SyscallRemap::Native);
    }

    #[test]
    fn syscall_table_unknown_number_is_unknown() {
        // 172 = iopl: not in our initial table, no canonical equivalent.
        assert!(!X8664SyscallTable::is_known(172));
        assert_eq!(X8664SyscallTable::remap(172), SyscallRemap::Unknown);
    }

    // ── sigframe codec exercises the real path against a no-op stub ───────
    //
    // build_sigframe / restore_sigframe ARE implemented (the full x86-64
    // rt_sigframe codec). Against `SigframeStub` — whose guest-memory backend is
    // `Unsupported` — they run the real codec and fail only at the guest-memory
    // boundary (writing/reading the frame), proving the codec is engaged rather
    // than short-circuiting with a "not implemented" stub.

    struct SigframeStub;

    impl carrick_guest_mem::GuestMemory for SigframeStub {
        fn read_bytes(
            &self,
            _a: u64,
            _l: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            Err(carrick_guest_mem::MemoryError::Unsupported)
        }
        fn write_bytes(
            &mut self,
            _a: u64,
            _b: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            Err(carrick_guest_mem::MemoryError::Unsupported)
        }
    }

    impl crate::RegAccess for SigframeStub {
        fn get_reg(&self, _: crate::Reg) -> Result<u64, crate::OsError> {
            Ok(0)
        }
        fn set_reg(&mut self, _: crate::Reg, _: u64) -> Result<(), crate::OsError> {
            Ok(())
        }
        fn get_sys_reg(&self, _: crate::SysReg) -> Result<u64, crate::OsError> {
            Ok(0)
        }
        fn set_sys_reg(&mut self, _: crate::SysReg, _: u64) -> Result<(), crate::OsError> {
            Ok(())
        }
        fn get_vreg(&self, _: u32) -> Result<u128, crate::OsError> {
            Ok(0)
        }
        fn set_vreg(&mut self, _: u32, _: u128) -> Result<(), crate::OsError> {
            Ok(())
        }
        fn get_fpcr(&self) -> Result<u64, crate::OsError> {
            Ok(0)
        }
        fn set_fpcr(&mut self, _: u64) -> Result<(), crate::OsError> {
            Ok(())
        }
        fn get_fpsr(&self) -> Result<u64, crate::OsError> {
            Ok(0)
        }
        fn set_fpsr(&mut self, _: u64) -> Result<(), crate::OsError> {
            Ok(())
        }
    }

    fn make_inject_params() -> crate::sigframe::InjectParams {
        crate::sigframe::InjectParams {
            signum: 1,
            handler: 0,
            sa_restorer: 0,
            pending_syscall_retval: None,
            interrupted_pc: None,
            altstack: None,
            saved_sigmask: 0,
            fault_siginfo: None,
            queued_siginfo: None,
            restart_syscall: false,
            pstate_source: 0,
            orig_x0: 0,
            fault_esr: 0,
            fpsimd_enabled: false,
            sigreturn_trampoline_base: 0,
        }
    }

    #[test]
    fn build_sigframe_runs_codec_and_faults_only_at_guest_memory() {
        // The codec IS implemented: it builds the frame and only fails when the
        // stub's `write_bytes` (Unsupported) refuses the guest-stack write. The
        // error therefore names the guest-memory write, NOT "not implemented".
        let result = X8664GuestArch::build_sigframe(&mut SigframeStub, make_inject_params());
        // The real codec builds the frame and tries to write it to the guest
        // stack; the stub's Unsupported `write_bytes` makes that a
        // `SignalDeliveryFault` (Linux force_sigsegv) — NOT a "not implemented"
        // stub error. That it reaches the write at all proves the codec runs.
        match result {
            Err(TrapError::SignalDeliveryFault) => {}
            Err(other) => panic!("expected SignalDeliveryFault from the codec, got {other:?}"),
            Ok(_) => panic!("codec must fail against the Unsupported memory stub"),
        }
    }

    #[test]
    fn restore_sigframe_runs_codec_and_faults_only_at_guest_memory() {
        // Symmetric to build: the codec reads the frame from the guest stack and
        // fails only at the stub's Unsupported `read_bytes`.
        let result = X8664GuestArch::restore_sigframe(&mut SigframeStub, false);
        assert!(
            result.is_err(),
            "restore_sigframe must fail against the Unsupported memory stub"
        );
        match result {
            Err(TrapError::Hypervisor(msg)) => {
                assert!(
                    !msg.contains("not implemented"),
                    "codec is implemented; error must not claim otherwise: {msg}"
                );
            }
            Err(other) => panic!("expected TrapError::Hypervisor, got {other:?}"),
            Ok(_) => panic!("codec must fail against the Unsupported memory stub"),
        }
    }

    // ── LSTAR value matches the trampoline slot ───────────────────────────

    #[test]
    fn lstar_points_to_el0_trampoline_base() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        assert_eq!(
            boot.lstar,
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
            "LSTAR must point to the carrick trampoline slot"
        );
    }

    // ── compile-shape smoke (mirrors FakeArch in guest_arch.rs) ─────────

    fn assert_is_guest_arch<A: GuestArch>() {}

    #[test]
    fn x8664_guest_arch_satisfies_the_seam() {
        assert_is_guest_arch::<X8664GuestArch>();
        assert_eq!(X8664GuestArch::uname_machine(), "x86_64");
        assert_eq!(X8664GuestArch::elf_machine(), 62);
    }
}
