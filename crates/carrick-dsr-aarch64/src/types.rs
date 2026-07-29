#![allow(dead_code)] // Staged DSR contracts are consumed by Tasks 3-5.

//! AArch64 DSR plan/exit vocabulary: the typed per-instruction actions the
//! decoder produces, the block-planner exit surface, and `DsrError`. Moved
//! verbatim from `carrick-runtime/src/native_darwin/dsr/types.rs`.

use carrick_guest_mem::GuestVa;

use crate::direct_binding::DirectBindingExitMetadata;

// The ISA-neutral halves live in `carrick-dsr`; re-exported here so the
// AArch64 plan/emit vocabulary keeps presenting one `types::*` surface.
// `BlockId` is staged contract surface with no runtime consumer yet (the
// pre-move definition sat under this file's `allow(dead_code)`).
#[allow(unused_imports)]
pub use carrick_dsr::ids::{BlockId, CacheOffset, CacheVa, CodeGeneration};
pub use carrick_dsr::vocabulary::{
    ExclusiveFusionDisposition, ExclusiveFusionRejection, SensitiveKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectKind {
    Branch,
    Call,
    Conditional,
    CompareZero { nonzero: bool },
    TestBit { nonzero: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectExit {
    pub kind: DirectKind,
    pub target: GuestVa,
    pub resume: GuestVa,
    pub condition: Option<bad64::Condition>,
    pub register: Option<bad64::Reg>,
    pub bit: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndirectKind {
    Branch,
    Call,
    Return,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndirectExit {
    pub kind: IndirectKind,
    pub register: bad64::Reg,
    pub resume: GuestVa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcRelativeKind {
    Adr,
    Adrp,
    LiteralLoad,
    LiteralPrefetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcRelativeInst {
    pub kind: PcRelativeKind,
    pub target: GuestVa,
    pub destination: Option<bad64::Reg>,
    pub word: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryBase {
    Register(bad64::Reg),
    VirtualX18,
    VirtualX28,
    /// The base is `gateway::RESERVED_SCRATCH`, whose physical register the
    /// memory lowering owns; the guest value comes from its context slot.
    VirtualReserved,
    Literal(GuestVa),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryWriteback {
    None,
    PreIndex,
    PostIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryEffectiveAddress {
    Base,
    Immediate(i64),
    RegisterOffset {
        extend: MemoryIndexExtend,
        shift: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryIndexExtend {
    Uxtw,
    Sxtw,
    Uxtx,
    Sxtx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryClass {
    Scalar,
    Pair,
    Simd,
    Exclusive,
    Atomic,
    Literal,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryVirtualization {
    None,
    X18,
    X28,
    X18X28ReadOnly,
    X18WriteX28Read,
    /// The access names `gateway::RESERVED_SCRATCH` somewhere -- as its base,
    /// as a transfer/index register, or both. Unlike the x18/x28 variants this
    /// is set for a base-only mention too, because the reserved register is
    /// also the lowering's own address scratch: an access naming it can never
    /// take the spill-free or compact paths.
    Reserved,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryAccess {
    pub word: u32,
    pub op: bad64::Op,
    pub base: MemoryBase,
    pub effective_address: MemoryEffectiveAddress,
    pub writeback: MemoryWriteback,
    pub class: MemoryClass,
    pub virtualization: MemoryVirtualization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterDestination {
    Gpr(u8),
    Discard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterRead {
    pub destination: CounterDestination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensitiveExit {
    pub kind: SensitiveKind,
    pub register: Option<bad64::Reg>,
    pub resume: GuestVa,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DsrScratchGpr(u8);

impl DsrScratchGpr {
    pub fn new(index: u32) -> Option<Self> {
        (index <= 30).then_some(Self(index as u8))
    }

    pub const fn index(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BiasedExclusiveScratch {
    pub address: DsrScratchGpr,
    pub bias: DsrScratchGpr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExclusiveFusionSite {
    pub guest: GuestVa,
    pub word: u32,
    pub disposition: ExclusiveFusionDisposition,
    pub biased_scratch: Option<BiasedExclusiveScratch>,
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
pub struct ExclusiveRegionExit {
    /// Guest VA of the exclusive load -- the top of the retry loop.
    pub start: GuestVa,
    /// Guest VA one past the region's final instruction (the retry branch).
    pub end: GuestVa,
    /// Guest VA the retry branch targets on store failure. Always equal to
    /// `start` for a recognised region; carried explicitly so Task 2's
    /// emitter does not have to re-derive the invariant.
    pub retry_edge: GuestVa,
    pub load_word: u32,
    pub store_word: u32,
    /// Raw encoding of the loop's retry branch (the conditional that targets
    /// `retry_edge` on store failure). It sits one instruction past the store
    /// at `end - 4` and is NOT carried in `BlockPlan::instructions` (unlike the
    /// load/store/body ops), so the emitter needs it here to re-encode the
    /// retry edge natively.
    pub retry_word: u32,
    /// Raw encoding of the single optional early-exit branch (the CAS
    /// compare-failure edge). `Some` iff the region body contains a conditional
    /// branch that leaves the loop before the store; the emitter re-encodes it
    /// to a CLREX-then-exit stub. `None` for a plain RMW loop with no early
    /// exit. The matching `InstAction::Direct` in `BlockPlan::instructions`
    /// carries its target/kind; this carries only the raw word the emitter
    /// re-encodes (a `PlannedInst`'s `InstAction::Direct` drops the word).
    pub early_exit_word: Option<u32>,
    pub fallback: SensitiveExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstAction {
    Copy(u32),
    CounterRead(CounterRead),
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
    /// A non-memory instruction naming `gateway::RESERVED_SCRATCH`. Emitted
    /// through the same parameterized virtualization the x18/x28 variants use,
    /// against `gateway::CTX_GUEST_RESERVED_SCRATCH`.
    VirtualizedReserved {
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
pub enum NativeDsrExit {
    Syscall {
        resume: GuestVa,
    },
    ResolveDirect {
        source: GuestVa,
        target: GuestVa,
        binding: DirectBindingExitMetadata,
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
    pub const fn profile_class(&self) -> carrick_dsr::profile::ExitClass {
        match self {
            Self::Syscall { .. } => carrick_dsr::profile::ExitClass::Syscall,
            Self::ResolveDirect { .. } => carrick_dsr::profile::ExitClass::ResolveDirect,
            Self::ResolveIndirect { .. } => carrick_dsr::profile::ExitClass::ResolveIndirect,
            Self::Sensitive { .. } => carrick_dsr::profile::ExitClass::Sensitive,
            Self::Fault { .. } => carrick_dsr::profile::ExitClass::Fault,
            Self::Kick { .. } => carrick_dsr::profile::ExitClass::Kick,
            Self::KickAtEntry { .. } => carrick_dsr::profile::ExitClass::Kick,
            Self::StaleGeneration { .. } => carrick_dsr::profile::ExitClass::StaleGeneration,
            Self::Unsupported { .. } => carrick_dsr::profile::ExitClass::Unsupported,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DsrError {
    #[error("DSR profile evidence invalid: {0}")]
    Profile(#[from] carrick_dsr::profile::ProfileError),
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

// The extracted cache (`carrick_dsr::cache`) reports its own typed
// `CacheError`; map each variant back onto the pre-extraction `DsrError`
// counterpart so every runtime `?` site keeps producing identical errors.
impl From<carrick_dsr::cache::CacheError> for DsrError {
    fn from(error: carrick_dsr::cache::CacheError) -> Self {
        use carrick_dsr::cache::CacheError;

        match error {
            CacheError::Policy(detail) => Self::CachePolicy(detail),
            CacheError::Capacity {
                requested,
                used,
                capacity,
            } => Self::CacheCapacity {
                requested,
                used,
                capacity,
            },
            CacheError::GenerationChanged {
                page,
                expected,
                observed,
            } => Self::GenerationChanged {
                page,
                expected,
                observed,
            },
            CacheError::Host { operation, error } => Self::Host { operation, error },
        }
    }
}
