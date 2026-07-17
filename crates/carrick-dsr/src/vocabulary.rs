//! Shared exit/census vocabulary: dependency-free data enums that both the
//! per-ISA translators and the neutral profiling census speak.
//!
//! These moved verbatim from the runtime's `native_darwin/dsr/types.rs`. They
//! are AArch64-FLAVORED today (the reference lane's sensitive catalog and its
//! exclusive-monitor fusion dispositions) but type-dependency-free; the x86
//! lane reports zero for classes that cannot occur there (x86 has no
//! exclusive monitors — `lock`-prefixed RMWs copy through natively) and
//! extends the catalog when it grows x86-only sensitive kinds.

/// The reference lane's sensitive-instruction catalog. `Exclusive` carries
/// the raw instruction word for the typed-boundary lowering. A DSR block
/// transition performs host stores, so the hardware exclusive reservation
/// cannot be carried faithfully across translated basic blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensitiveKind {
    /// AArch64 exclusive load/store lowered at a typed DSR boundary.
    Exclusive(u32),
    ReadTpidr,
    WriteTpidr,
    ReadCounter,
    ReadCtr,
    ReadDczid,
    DcZva,
    DcCvau,
    IcIvau,
}

impl SensitiveKind {
    pub const fn profile_class(self) -> crate::profile::SensitiveClass {
        match self {
            Self::Exclusive(_) => crate::profile::SensitiveClass::Exclusive,
            Self::ReadTpidr => crate::profile::SensitiveClass::ReadTpidr,
            Self::WriteTpidr => crate::profile::SensitiveClass::WriteTpidr,
            Self::ReadCounter => crate::profile::SensitiveClass::ReadCounter,
            Self::ReadCtr => crate::profile::SensitiveClass::ReadCtr,
            Self::ReadDczid => crate::profile::SensitiveClass::ReadDczid,
            Self::DcZva => crate::profile::SensitiveClass::DcZva,
            Self::DcCvau => crate::profile::SensitiveClass::DcCvau,
            Self::IcIvau => crate::profile::SensitiveClass::IcIvau,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExclusiveFusionRejection {
    NotLoad,
    VirtualizedBase,
    VirtualizedOperand,
    PageBoundary,
    ScanLimitOrNoStore,
    MismatchedStore,
    UnsupportedBodyMemoryOrSensitive,
    UnsupportedControlFlow,
    InvalidRetryEdge,
    BiasedNoSafeScratch,
    BiasedAddressFormUnsupported,
    AnalysisUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExclusiveFusionDisposition {
    FusedDirect,
    FusedBiased,
    EligibleBackendDisabled,
    Rejected(ExclusiveFusionRejection),
}
