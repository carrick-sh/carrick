//! The per-guest-ISA seam. One impl per guest CPU ISA (aarch64 now; x86_64 in
//! Phase 2). Selected statically as `ThreadedEngine::Arch` so the engine/runtime
//! monomorphize per ISA — no dynamic dispatch on the syscall hot path.
//!
//! Phase 1 is a behavior-preserving refactor: the aarch64 impl
//! ([`crate::aarch64_arch::Aarch64GuestArch`]) delegates to the existing
//! `carrick-mem` / `carrick-abi` / `carrick-guest-mem` code verbatim. The trait
//! grows one subsystem at a time as each is routed through it: the
//! sigframe build/restore methods (Task 4) and the initial CPU bring-up
//! register VALUES (Task 5) are now declared; only the MMU-descriptor codec
//! (T6) remains, carrying its real ctx types rather than a speculative
//! signature.

use crate::sigframe::{InjectParams, SigframeInject, SigframeRestore};
use crate::{RegAccess, TrapError};
use carrick_guest_mem::GuestMemory;

/// Encode/decode for the guest page-table descriptor format (AArch64
/// long-descriptor vs x86-64 4-level). Same operation shape per ISA. The
/// surface here is the minimal granule descriptor; the per-descriptor
/// bit helpers (AP/UXN/PXN, `set_prot_none`/`set_rw`/`map_aliased`) are
/// finalized against `carrick-mem::page_table` in a later plan task (T6).
pub trait PageTableCodec {
    /// Page-shift for the guest granule (aarch64 4 KiB granule → 12).
    fn page_shift() -> u32;
    /// Granule / index-shift parameters the walker needs.
    fn granule() -> PtGranule;
}

/// Granule parameters for one guest page-table format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtGranule {
    /// log2 of the page size (aarch64 4 KiB → 12).
    pub page_shift: u32,
    /// Number of translation levels walked (aarch64 stage-1 → 4).
    pub levels: u8,
    /// Bits consumed per translation-table index.
    pub index_bits: u32,
}

/// Per-ISA syscall-number table (number -> canonical metadata). The aarch64
/// table is today's `carrick_abi::syscall::AARCH64_SYSCALLS`, queried via
/// `lookup_aarch64`.
pub trait SyscallTable {
    /// Canonical name for a syscall number, if the table knows it.
    fn name(number: u64) -> Option<&'static str>;
    /// Whether the table has an entry for `number`.
    fn is_known(number: u64) -> bool;
}

/// The per-guest-ISA seam. One impl per guest CPU ISA, selected statically as
/// `ThreadedEngine::Arch` (monomorphized — no syscall-hot-path vtable).
pub trait GuestArch: Copy + 'static {
    /// Raw per-ISA syscall register frame (aarch64: `Aarch64SyscallFrame`).
    type Frame: Copy;
    /// Page-table descriptor codec for this ISA.
    type Mmu: PageTableCodec;
    /// Syscall-number metadata table for this ISA.
    type Table: SyscallTable;
    /// Per-ISA bundle of initial CPU bring-up register VALUES (aarch64:
    /// MAIR/TCR/SCTLR/CPACR_EL1; x86_64 in Phase 2: CR0/CR4/EFER/...). Values
    /// only — the programming procedure stays in each backend, which interleaves
    /// backend-specific registers and intentionally divergent PAN/SPAN glue.
    type BootSysregs: Copy;

    /// Decode the raw frame into `(number, args[6])`. The runtime maps this to
    /// its `SyscallRequest` (aarch64: `x8` → number, `x0..x5` → args).
    fn decode_syscall(frame: &Self::Frame) -> (u64, [u64; 6]);

    /// ELF `e_machine` tag for this ISA (aarch64: `EM_AARCH64` = 183).
    fn elf_machine() -> u16;
    /// `uname(2)` machine string for this ISA (aarch64: `"aarch64"`).
    fn uname_machine() -> &'static str;

    /// vDSO image bytes for this ISA. Computed (not a `'static` slice) — the
    /// aarch64 image is assembled at boot from `carrick-mem::vdso`, so this
    /// returns owned bytes, matching the existing API verbatim.
    fn vdso_bytes() -> Vec<u8>;
    /// Guest entry-trampoline machine code (aarch64 EL0 `svc`→`hvc` trampoline;
    /// x86_64 will be its `syscall`→exit equivalent). Computed; owned bytes for
    /// the same reason as [`GuestArch::vdso_bytes`].
    fn entry_trampoline_bytes() -> Vec<u8>;

    /// The ISA's initial CPU bring-up register values.
    fn bootstrap_sysregs() -> Self::BootSysregs;

    // The page-table descriptor codec is expressed over the engine's
    // `RegAccess` + the descriptor ctx types; its exact signatures are lifted
    // verbatim from `carrick-mem::page_table` in a later plan task (T6), kept
    // here as trait methods so the engine calls `Arch::*`. Declared once its
    // concrete ctx types are in scope.

    /// Build the `rt_sigframe` for a delivered signal: push it onto the guest
    /// user stack and redirect the vCPU to the handler. ISA-specific frame
    /// layout (aarch64 `CarrickSigframe` today; x86_64 in Phase 2). Generic over
    /// the engine because a trap engine impls both `RegAccess` and `GuestMemory`
    /// on one type, and the shared builder needs both.
    fn build_sigframe<E: RegAccess + GuestMemory>(
        engine: &mut E,
        params: InjectParams,
    ) -> Result<SigframeInject, TrapError>;

    /// Pop the `rt_sigframe` at the guest SP and restore the pre-signal register
    /// state (the `rt_sigreturn(2)` path). Counterpart to [`GuestArch::build_sigframe`].
    fn restore_sigframe<E: RegAccess + GuestMemory>(
        engine: &mut E,
        fpsimd_enabled: bool,
    ) -> Result<SigframeRestore, TrapError>;
}
