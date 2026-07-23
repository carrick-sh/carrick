//! `carrick-dsr-x86` — the x86_64 guest-ISA lane of the native (DSR)
//! backend (bring-up; M2 of the seams design,
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
//!
//! The native lane is same-ISA, so this crate targets Linux/x86_64 guests on
//! x86_64 hosts (FreeBSD/amd64 first). What exists today is the DECODE rung:
//! variable-length instruction classification over `iced-x86` (the `bad64`
//! analog), including the sensitive-instruction catalog fixed in the design
//! doc — `syscall`, `int 0x80`, `rdtsc`/`rdtscp`, `cpuid`,
//! `{rd,wr}{fs,gs}base`, and fs/gs-segment-prefixed accesses (the TLS
//! virtualization surface, x86's analog of TPIDR/X18).
//!
//! Deliberately absent until their design docs exist: the plan IR, the
//! emitter (dynasmrt x64), and the gateway — an x86 `DsrContext`/fsbase-swap
//! design has real open questions (context-register strategy, signal-window
//! phases) that must not be speculated here. Everything callable fails
//! closed with a typed error until then; the block planner cannot
//! accidentally "run" x86 guests through a half-lane.
//!
//! Key structural difference from AArch64 carried by `classify`: x86 has no
//! exclusive monitors — `lock`-prefixed RMWs copy through natively, so the
//! entire exclusive-region fusion apparatus has no analog here — and
//! instructions are variable-length, so every classification carries its
//! decoded length for the planner's stride.

pub mod block;
pub mod cflow;
pub mod decode;
pub mod emit;
pub mod fxstate;
#[cfg(test)]
mod fxstate_tests;
pub mod gateway;
pub mod legacy_x87;
mod xstate_address;
pub mod xstate_restore;
pub mod xstate_save;

pub use block::{
    BlockLimit, PlannedInst, X86Block, X86BlockError, X86BlockPlanError, X86Exit, plan_block,
    plan_block_with_reader,
};
pub use decode::{
    X86Classified, X86DecodeError, X86FxStateKind, X86InstClass, X86LegacyX87Kind,
    X86SensitiveKind, X86XstateRestoreKind, X86XstateSaveKind, classify,
};
pub use fxstate::{
    X86FxStateError, X86FxStateGpReason, X86FxStateInternalReason, X86FxStatePlan,
    X86FxStateSsReason,
};
pub use gateway::{
    X86_SIGNAL_SAFE_XFEATURES, X86DsrContext, X86DsrProfilerLayout, X86ExitStatus,
    X86IdentityStamp, X86IndirectCacheEntry, X86SnapshotXstateCapabilities,
    X86SnapshotXstateComponent, X86SnapshotXstateError, X86SnapshotXstateLayout,
    X86UcontextSnapshot, enter_translated, signal_xstate_capabilities, signal_xstate_layout,
    x86_dsr_profiler_layout,
};
pub use legacy_x87::{
    X86LegacyX87Error, X86LegacyX87GpReason, X86LegacyX87InternalReason, X86LegacyX87Plan,
    X86LegacyX87SsReason, X86X87ExceptionKind,
};
pub use xstate_restore::{
    X86GuestGsBase, X86XstateMemoryReader, X86XstateRestoreError, X86XstateRestoreGpReason,
    X86XstateRestoreInternalReason, X86XstateRestorePlan, X86XstateRestoreSsReason,
};
pub use xstate_save::{
    X86XstateMemoryWriter, X86XstateSaveError, X86XstateSaveGpReason, X86XstateSaveInternalReason,
    X86XstateSavePlan, X86XstateSaveSsReason,
};

/// x86_64 guest ISA implementation for the DSR lane seam.
pub struct X8664Isa;

impl carrick_dsr::lane::GuestIsa for X8664Isa {
    const NAME: &'static str = "x86_64";
    const USER_VA_END_EXCLUSIVE: u64 = 1u64 << 47;
    const GUEST_PAGE_SIZE: usize = 4096;
}

#[cfg(test)]
mod isa_tests {
    use super::*;
    use carrick_dsr::lane::GuestIsa;

    #[test]
    fn x8664_isa_constants() {
        assert_eq!(X8664Isa::NAME, "x86_64");
        assert_eq!(X8664Isa::USER_VA_END_EXCLUSIVE, 1u64 << 47);
        assert_eq!(X8664Isa::GUEST_PAGE_SIZE, 4096);
    }
}
