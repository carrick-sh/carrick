//! Shim: the AArch64 DSR plan/exit vocabulary moved verbatim to
//! `carrick_dsr_aarch64::types` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::types::*` call paths resolve unchanged.
//!
//! The USDT probe projections (`probe_fields`/`probe_outcome`) stay here as
//! extension traits: the arch crate must remain `usdt`-free (the proc macro
//! selects probe-asm registers by the HOST arch, breaking
//! `--target aarch64-apple-darwin` cross-checks from a non-Darwin rig), so
//! it cannot depend on `carrick-observability`.

pub(in crate::native_darwin) use carrick_dsr_aarch64::types::*;

/// Runtime-side projection of a [`NativeDsrExit`] onto the USDT probe tuple.
/// Verbatim body of the pre-extraction `NativeDsrExit::probe_fields`.
pub(in crate::native_darwin) trait NativeDsrExitProbeExt {
    fn probe_fields(self) -> (carrick_observability::probes::DsrExitKind, u64, u64, i32);
}

impl NativeDsrExitProbeExt for NativeDsrExit {
    fn probe_fields(self) -> (carrick_observability::probes::DsrExitKind, u64, u64, i32) {
        use carrick_observability::probes::DsrExitKind;

        match self {
            Self::Syscall { resume } => (DsrExitKind::Syscall, resume.raw(), 0, 1),
            Self::ResolveDirect { source, target } => {
                (DsrExitKind::DirectResolver, source.raw(), target.raw(), 2)
            }
            Self::ResolveIndirect { source, target, .. } => {
                (DsrExitKind::IndirectResolver, source.raw(), target.raw(), 3)
            }
            Self::Fault {
                guest_pc, address, ..
            } => (DsrExitKind::Fault, guest_pc.raw(), address.raw() as u64, 4),
            Self::Kick { resume, .. } => (DsrExitKind::Kick, resume.raw(), 0, 5),
            Self::Sensitive {
                guest_pc, resume, ..
            } => (DsrExitKind::Sensitive, guest_pc.raw(), resume.raw(), 6),
            Self::Unsupported { guest_pc, .. } => (DsrExitKind::Unsupported, guest_pc.raw(), 0, 7),
            Self::KickAtEntry { resume } => (DsrExitKind::Kick, resume.raw(), 0, 8),
            Self::StaleGeneration { guest_pc, .. } => (
                DsrExitKind::DirectResolver,
                guest_pc.raw(),
                guest_pc.raw(),
                2,
            ),
        }
    }
}

/// Runtime-side projection of a [`DsrError`] onto the USDT operation-outcome
/// ordinal. Verbatim body of the pre-extraction `DsrError::probe_outcome`.
pub(in crate::native_darwin) trait DsrErrorProbeExt {
    fn probe_outcome(&self) -> carrick_observability::probes::DsrOperationOutcome;
}

impl DsrErrorProbeExt for DsrError {
    fn probe_outcome(&self) -> carrick_observability::probes::DsrOperationOutcome {
        use carrick_observability::probes::DsrOperationOutcome;

        match self {
            Self::Profile(_) => DsrOperationOutcome::CachePolicy,
            Self::PcOverflow { .. } => DsrOperationOutcome::PcOverflow,
            Self::Decode { .. } => DsrOperationOutcome::Decode,
            Self::Malformed { .. } => DsrOperationOutcome::Malformed,
            Self::BlockPolicy(_) => DsrOperationOutcome::BlockPolicy,
            Self::MemoryRead { .. } => DsrOperationOutcome::MemoryRead,
            Self::UnsupportedBlockAction { .. } => DsrOperationOutcome::UnsupportedBlockAction,
            Self::Assembler(_) => DsrOperationOutcome::Assembler,
            Self::Gateway(_) => DsrOperationOutcome::Gateway,
            Self::CachePolicy(_) => DsrOperationOutcome::CachePolicy,
            Self::CacheCapacity { .. } => DsrOperationOutcome::CacheCapacity,
            Self::GenerationChanged { .. } => DsrOperationOutcome::GenerationChanged,
            Self::Host { .. } => DsrOperationOutcome::Host,
        }
    }
}
