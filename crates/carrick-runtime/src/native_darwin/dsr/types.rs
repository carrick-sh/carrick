#![allow(dead_code)] // Staged DSR contracts are consumed by Tasks 3-5.

use carrick_guest_mem::{GuestVa, HostVa};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::native_darwin) struct CodeGeneration(u64);

impl CodeGeneration {
    pub(super) const INITIAL: Self = Self(0);

    pub(super) const fn claimed(value: u64) -> Self {
        Self(value)
    }

    pub(super) fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct BlockId(u64);

impl BlockId {
    pub(super) const fn claimed(value: u64) -> Self {
        Self(value)
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub(super) struct CacheOffset(u32);

impl CacheOffset {
    pub(super) const fn published(value: u32) -> Self {
        Self(value)
    }

    pub(super) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct CacheVa(HostVa);

impl CacheVa {
    pub(super) const fn published(value: HostVa) -> Self {
        Self(value)
    }

    pub(super) const fn host(self) -> HostVa {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DirectKind {
    Branch,
    Call,
    Conditional,
    CompareZero { nonzero: bool },
    TestBit { nonzero: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirectExit {
    pub(super) kind: DirectKind,
    pub(super) target: GuestVa,
    pub(super) resume: GuestVa,
    pub(super) condition: Option<bad64::Condition>,
    pub(super) register: Option<bad64::Reg>,
    pub(super) bit: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IndirectKind {
    Branch,
    Call,
    Return,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IndirectExit {
    pub(super) kind: IndirectKind,
    pub(super) register: bad64::Reg,
    pub(super) resume: GuestVa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PcRelativeKind {
    Adr,
    Adrp,
    LiteralLoad,
    LiteralPrefetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcRelativeInst {
    pub(super) kind: PcRelativeKind,
    pub(super) target: GuestVa,
    pub(super) destination: Option<bad64::Reg>,
    pub(super) word: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryBase {
    Register(bad64::Reg),
    VirtualX18,
    VirtualX28,
    Literal(GuestVa),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryWriteback {
    None,
    PreIndex,
    PostIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryEffectiveAddress {
    Base,
    Immediate(i64),
    RegisterOffset {
        extend: MemoryIndexExtend,
        shift: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryIndexExtend {
    Uxtw,
    Sxtw,
    Uxtx,
    Sxtx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryClass {
    Scalar,
    Pair,
    Simd,
    Exclusive,
    Atomic,
    Literal,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemoryVirtualization {
    None,
    X18,
    X28,
    X18X28ReadOnly,
    X18WriteX28Read,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoryAccess {
    pub(super) word: u32,
    pub(super) op: bad64::Op,
    pub(super) base: MemoryBase,
    pub(super) effective_address: MemoryEffectiveAddress,
    pub(super) writeback: MemoryWriteback,
    pub(super) class: MemoryClass,
    pub(super) virtualization: MemoryVirtualization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_darwin) enum SensitiveKind {
    /// AArch64 exclusive load/store lowered at a typed DSR boundary.  A DSR
    /// block transition performs host stores, so the hardware reservation
    /// cannot be carried faithfully across translated basic blocks.
    Exclusive(u32),
    ReadTpidr,
    WriteTpidr,
    ReadCtr,
    ReadDczid,
    DcZva,
    DcCvau,
    IcIvau,
}

impl SensitiveKind {
    pub(in crate::native_darwin) const fn profile_class(self) -> super::profile::SensitiveClass {
        match self {
            Self::Exclusive(_) => super::profile::SensitiveClass::Exclusive,
            Self::ReadTpidr => super::profile::SensitiveClass::ReadTpidr,
            Self::WriteTpidr => super::profile::SensitiveClass::WriteTpidr,
            Self::ReadCtr => super::profile::SensitiveClass::ReadCtr,
            Self::ReadDczid => super::profile::SensitiveClass::ReadDczid,
            Self::DcZva => super::profile::SensitiveClass::DcZva,
            Self::DcCvau => super::profile::SensitiveClass::DcCvau,
            Self::IcIvau => super::profile::SensitiveClass::IcIvau,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_darwin) struct SensitiveExit {
    pub(in crate::native_darwin) kind: SensitiveKind,
    pub(in crate::native_darwin) register: Option<bad64::Reg>,
    pub(in crate::native_darwin) resume: GuestVa,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub(super) struct DsrScratchGpr(u8);

impl DsrScratchGpr {
    pub(super) fn new(index: u32) -> Option<Self> {
        (index <= 30).then_some(Self(index as u8))
    }

    pub(super) const fn index(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct BiasedExclusiveScratch {
    pub(super) address: DsrScratchGpr,
    pub(super) bias: DsrScratchGpr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExclusiveFusionRejection {
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
pub(super) enum ExclusiveFusionDisposition {
    FusedDirect,
    FusedBiased,
    EligibleBackendDisabled,
    Rejected(ExclusiveFusionRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExclusiveFusionSite {
    pub(super) guest: GuestVa,
    pub(super) word: u32,
    pub(super) disposition: ExclusiveFusionDisposition,
    pub(super) biased_scratch: Option<BiasedExclusiveScratch>,
}

/// A block-planner-recognised, provably fusible AArch64 exclusive region: an
/// exclusive load (LDXR/LDAXR family) paired with its matching exclusive
/// store (STXR/STLXR family) across a bounded, straight-line CAS/RMW
/// retry-loop body, with no hazardous instruction between them (see
/// `block::analyze_exclusive_region` for the exact fusibility predicate).
///
/// This carries the semantic data Task 2 needs to lower the region to
/// native code instead of two independent gateway traps. It deliberately
/// does NOT carry the region's own instruction sequence: that lives in the
/// usual place, `BlockPlan::instructions` (mirroring every other exit kind,
/// e.g. `PlannedExit::Direct`'s target instruction is never duplicated into
/// the exit payload either) -- see `block::analyze_exclusive_region`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_darwin) struct ExclusiveRegionExit {
    /// Guest VA of the exclusive load -- the top of the retry loop.
    pub(in crate::native_darwin) start: GuestVa,
    /// Guest VA one past the region's final instruction (the retry branch).
    pub(in crate::native_darwin) end: GuestVa,
    /// Guest VA the retry branch targets on store failure. Always equal to
    /// `start` for a recognised region; carried explicitly so Task 2's
    /// emitter does not have to re-derive the invariant.
    pub(in crate::native_darwin) retry_edge: GuestVa,
    pub(in crate::native_darwin) load_word: u32,
    pub(in crate::native_darwin) store_word: u32,
    /// Raw encoding of the loop's retry branch (the conditional that targets
    /// `retry_edge` on store failure). It sits one instruction past the store
    /// at `end - 4` and is NOT carried in `BlockPlan::instructions` (unlike the
    /// load/store/body ops), so the emitter needs it here to re-encode the
    /// retry edge natively.
    pub(in crate::native_darwin) retry_word: u32,
    /// Raw encoding of the single optional early-exit branch (the CAS
    /// compare-failure edge). `Some` iff the region body contains a conditional
    /// branch that leaves the loop before the store; the emitter re-encodes it
    /// to a CLREX-then-exit stub. `None` for a plain RMW loop with no early
    /// exit. The matching `InstAction::Direct` in `BlockPlan::instructions`
    /// carries its target/kind; this carries only the raw word the emitter
    /// re-encodes (a `PlannedInst`'s `InstAction::Direct` drops the word).
    pub(in crate::native_darwin) early_exit_word: Option<u32>,
    pub(in crate::native_darwin) fallback: SensitiveExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InstAction {
    Copy(u32),
    Memory(MemoryAccess),
    VirtualizedX18 {
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX28 {
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX18X28ReadOnly {
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX18WriteX28Read {
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX28WriteX18Read {
        word: u32,
        op: bad64::Op,
    },
    PcRelative(PcRelativeInst),
    Direct(DirectExit),
    Indirect(IndirectExit),
    Syscall {
        resume: GuestVa,
    },
    Sensitive(SensitiveExit),
    /// A fused exclusive region recognised by the block planner's bounded
    /// forward scan (`block::analyze_exclusive_region`). Not produced by
    /// `decode::classify` -- recognising a region requires multi-instruction
    /// lookahead that per-instruction decode cannot do -- so this variant
    /// exists for Task 2 to construct/consume at the block-planning layer.
    ExclusiveRegion(ExclusiveRegionExit),
    Unsupported {
        word: u32,
        op: bad64::Op,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeDsrExit {
    Syscall {
        resume: GuestVa,
    },
    ResolveDirect {
        source: GuestVa,
        target: GuestVa,
    },
    ResolveIndirect {
        source: GuestVa,
        target: GuestVa,
        link: Option<GuestVa>,
    },
    Sensitive {
        guest_pc: GuestVa,
        resume: GuestVa,
        generation: CodeGeneration,
    },
    Fault {
        guest_pc: GuestVa,
        signal: i32,
        code: i32,
        address: carrick_guest_mem::HostVa,
        rewrite_scratch: u64,
        rewrite_context_scratch: u64,
        generation_pstate_scratch: u64,
        indirect_x15_scratch: u64,
        indirect_x30_scratch: u64,
        physical_x18: u64,
        gateway_phase: u32,
        biased_guest_fault_address: u64,
    },
    Kick {
        resume: GuestVa,
        rewrite_scratch: u64,
        rewrite_context_scratch: u64,
        generation_pstate_scratch: u64,
        indirect_x15_scratch: u64,
        indirect_x30_scratch: u64,
    },
    KickAtEntry {
        resume: GuestVa,
    },
    StaleGeneration {
        guest_pc: GuestVa,
        observed: CodeGeneration,
    },
    Unsupported {
        guest_pc: GuestVa,
        word: u32,
        op: bad64::Op,
    },
}

impl NativeDsrExit {
    pub(super) const fn profile_class(&self) -> super::profile::ExitClass {
        match self {
            Self::Syscall { .. } => super::profile::ExitClass::Syscall,
            Self::ResolveDirect { .. } => super::profile::ExitClass::ResolveDirect,
            Self::ResolveIndirect { .. } => super::profile::ExitClass::ResolveIndirect,
            Self::Sensitive { .. } => super::profile::ExitClass::Sensitive,
            Self::Fault { .. } => super::profile::ExitClass::Fault,
            Self::Kick { .. } => super::profile::ExitClass::Kick,
            Self::KickAtEntry { .. } => super::profile::ExitClass::Kick,
            Self::StaleGeneration { .. } => super::profile::ExitClass::StaleGeneration,
            Self::Unsupported { .. } => super::profile::ExitClass::Unsupported,
        }
    }

    pub(super) fn probe_fields(
        self,
    ) -> (carrick_observability::probes::DsrExitKind, u64, u64, i32) {
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

#[derive(Debug, thiserror::Error)]
pub(in crate::native_darwin) enum DsrError {
    #[error("DSR profile evidence invalid: {0}")]
    Profile(#[from] super::profile::ProfileError),
    #[error("DSR PC overflow at guest PC 0x{pc:x}")]
    PcOverflow { pc: u64 },
    #[error("DSR could not decode 0x{word:08x} at guest PC 0x{pc:x}: {detail}")]
    Decode { pc: u64, word: u32, detail: String },
    #[error("DSR decoded malformed {op:?} 0x{word:08x} at guest PC 0x{pc:x}")]
    Malformed { pc: u64, word: u32, op: bad64::Op },
    #[error("DSR block policy error: {0}")]
    BlockPolicy(String),
    #[error("DSR could not read guest instruction at 0x{pc:x}: {detail}")]
    MemoryRead { pc: u64, detail: String },
    #[error(
        "DSR cannot emit {class} {op:?} 0x{word:08x} at guest PC 0x{guest_pc:x} in block 0x{block_start:x} generation {generation}"
    )]
    UnsupportedBlockAction {
        block_start: u64,
        generation: u64,
        guest_pc: u64,
        word: u32,
        op: bad64::Op,
        class: &'static str,
    },
    #[error("DSR assembler failed: {0}")]
    Assembler(String),
    #[error("DSR gateway failed: {0}")]
    Gateway(String),
    #[error("DSR cache policy error: {0}")]
    CachePolicy(String),
    #[error(
        "DSR translation cache exhausted: requested={requested} used={used} capacity={capacity}"
    )]
    CacheCapacity {
        requested: usize,
        used: usize,
        capacity: usize,
    },
    #[error(
        "DSR executable page 0x{page:x} changed generation: expected {expected:?}, observed {observed:?}"
    )]
    GenerationChanged {
        page: u64,
        expected: u64,
        observed: u64,
    },
    #[error("DSR host operation {operation} failed: {error}")]
    Host {
        operation: &'static str,
        error: std::io::Error,
    },
}

impl DsrError {
    pub(super) fn probe_outcome(&self) -> carrick_observability::probes::DsrOperationOutcome {
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
