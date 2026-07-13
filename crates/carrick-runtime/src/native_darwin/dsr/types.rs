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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
pub(in crate::native_darwin) enum SensitiveKind {
    ReadTpidr,
    WriteTpidr,
    ReadCtr,
    ReadDczid,
    DcZva,
    DcCvau,
    IcIvau,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_darwin) struct SensitiveExit {
    pub(in crate::native_darwin) kind: SensitiveKind,
    pub(in crate::native_darwin) register: Option<bad64::Reg>,
    pub(in crate::native_darwin) resume: GuestVa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InstAction {
    Copy(u32),
    VirtualizedX18 { word: u32, op: bad64::Op },
    VirtualizedX28 { word: u32, op: bad64::Op },
    VirtualizedX18X28ReadOnly { word: u32, op: bad64::Op },
    VirtualizedX18WriteX28Read { word: u32, op: bad64::Op },
    PcRelative(PcRelativeInst),
    Direct(DirectExit),
    Indirect(IndirectExit),
    Syscall { resume: GuestVa },
    Sensitive(SensitiveExit),
    Unsupported { word: u32, op: bad64::Op },
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
