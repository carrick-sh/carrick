#![allow(dead_code)]

use std::sync::atomic::AtomicU64;

use carrick_guest_mem::{GuestVa, HostVa};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation};

use super::artifact_spike::{
    ArtifactRecord, ArtifactRecording, GatewayKind, MaterializedValue, ProcessValue,
};
use super::block::{BlockPlan, PlannedExit};
use super::types::{CacheOffset, CacheVa, CodeGeneration, DsrError, InstAction};
use carrick_dsr::cache::{PublishedCode, TranslationCache};

const _: () = assert!(carrick_dsr::address::INVALID_BIASED_HOST_ADDRESS_BIT == 1 << 47);
pub const BIASED_FAST_ADDRESS_BITS: u32 = 41;
const _: () =
    assert!(carrick_dsr::address::BIASED_GUEST_APERTURE_END <= 1 << BIASED_FAST_ADDRESS_BITS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitAddressMode {
    Direct,
    Biased {
        host_bias: carrick_dsr::address::NativeHostBias,
    },
}

impl From<carrick_dsr::address::NativeAddressMode> for EmitAddressMode {
    fn from(mode: carrick_dsr::address::NativeAddressMode) -> Self {
        match mode {
            carrick_dsr::address::NativeAddressMode::Direct => Self::Direct,
            carrick_dsr::address::NativeAddressMode::Biased { host_bias } => {
                Self::Biased { host_bias }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcMapEntry {
    pub guest: GuestVa,
    pub cache: CacheOffset,
}

#[derive(Debug)]
pub struct InstructionMap {
    entries: Vec<PcMapEntry>,
}

impl InstructionMap {
    /// Validates the entry list and keeps ONLY the list.
    ///
    /// This used to build and RETAIN a `guest -> cache` and a `cache -> guest`
    /// `BTreeMap` for every emitted block. Neither lookup has a production
    /// caller -- `cache_for_guest` and `guest_for_cache` are reached only from
    /// `#[cfg(test)]` modules and the oracle -- so on a toolchain workload that
    /// translates ~1.5M blocks of ~25 entries each, that was tens of millions of
    /// B-tree inserts, and two maps retained per block, to answer questions
    /// nothing asks. Translation is the largest single phase of this lane's CPU,
    /// so dead work on the emit path is worth deleting rather than tolerating.
    ///
    /// The duplicate-offset invariant that the `inverse` map enforced as a side
    /// effect is NOT dropped. Emission appends entries in cache order, so one
    /// strict-monotonicity scan rejects both duplicates and out-of-order
    /// artifact input without allocating and sorting a second vector.
    fn new(entries: Vec<PcMapEntry>) -> Result<Self, DsrError> {
        if let Some(pair) = entries
            .windows(2)
            .find(|pair| pair[0].cache.get() >= pair[1].cache.get())
        {
            return Err(DsrError::CachePolicy(format!(
                "non-monotonic cache offsets in DSR instruction map: {} then {}",
                pair[0].cache.get(),
                pair[1].cache.get(),
            )));
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[PcMapEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<PcMapEntry> {
        self.entries
    }

    /// Linear scan; see this type's constructor for why there is no index.
    ///
    /// Returns the FIRST match, preserving the `or_insert` semantics of the map
    /// this replaced: several emitted words can share one guest PC, and the
    /// earliest is that PC's entry point in the block.
    pub fn cache_for_guest(&self, guest: GuestVa) -> Option<CacheOffset> {
        self.entries
            .iter()
            .find(|entry| entry.guest == guest)
            .map(|entry| entry.cache)
    }

    pub fn guest_for_cache(&self, cache: CacheOffset) -> Option<GuestVa> {
        self.entries
            .iter()
            .find(|entry| entry.cache == cache)
            .map(|entry| entry.guest)
    }
}

pub struct EmittedBlock {
    code: PublishedCode,
    map: InstructionMap,
    direct_links: Vec<DirectLink>,
    recovery: Vec<RecoveryEntry>,
}

struct AssembledBlock {
    words: Vec<u32>,
    map: InstructionMap,
    direct_links: Vec<DirectLink>,
    recovery: Vec<RecoveryEntry>,
}

impl AssembledBlock {
    fn publish(self, cache: &mut TranslationCache) -> Result<EmittedBlock, DsrError> {
        let mut writer = cache.begin_write(self.words.len().saturating_mul(4))?;
        writer.write_words(&self.words)?;
        let code = writer.publish()?;
        Ok(EmittedBlock {
            code,
            map: self.map,
            direct_links: self.direct_links,
            recovery: self.recovery,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationGuard {
    Absolute {
        address: u64,
        expected: CodeGeneration,
    },
    BindingIndex {
        index: u32,
        expected: CodeGeneration,
    },
}

impl GenerationGuard {
    pub fn new(current: &AtomicU64, expected: CodeGeneration) -> Self {
        Self::Absolute {
            address: current as *const AtomicU64 as u64,
            expected,
        }
    }

    pub const fn binding(index: u32, expected: CodeGeneration) -> Self {
        Self::BindingIndex { index, expected }
    }

    pub const fn expected(self) -> CodeGeneration {
        match self {
            Self::Absolute { expected, .. } | Self::BindingIndex { expected, .. } => expected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    Noop,
    RestoreGuestX17,
    RestoreGenerationGuardRegisters,
    RestoreGenerationGuard,
    RestoreIndirectRegisters,
    RestoreIndirectResolver,
    RestoreScratch {
        register: u32,
    },
    RestoreScratchInvalidBiasedLiteral {
        register: u32,
    },
    RestoreScratchCompleted {
        register: u32,
    },
    CommitVirtualizedAndRestoreScratch {
        register: u32,
        virtual_register: u32,
    },
    RestoreScratchAndContext {
        register: u32,
        context_register: u32,
    },
    RestoreScratchAndContextCompleted {
        register: u32,
        context_register: u32,
    },
    CommitVirtualizedAndRestoreScratchAndContext {
        register: u32,
        context_register: u32,
        virtual_register: u32,
    },
    RestoreDualVirtualReadOnly {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    RestoreDualVirtualReadOnlyCompleted {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    CommitDualVirtualAndRestore {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
        virtual_register: u32,
        virtual_scratch: u32,
    },
    RecoverCounterRead(CounterReadRecovery),
    RecoverBiasedMemory(BiasedMemoryRecovery),
    RecoverBiasedExclusive(BiasedExclusiveRecovery),
    RestoreDirectBinding {
        phase: DirectBindingRecoveryPhase,
        committed_link: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectBindingRecoveryPhase {
    ScratchCapture,
    CellAddress,
    TargetAcquire,
    AuthorityValidate,
    AuthorityInstall,
    ArchitecturalRestore,
    FinalBranch,
    MissExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CounterScratchDestination {
    X15,
    X16,
    X17,
}

impl CounterScratchDestination {
    pub const fn register(self) -> u32 {
        match self {
            Self::X15 => 15,
            Self::X16 => 16,
            Self::X17 => 17,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CounterReadRecovery {
    pub committed_scratch_destination: Option<CounterScratchDestination>,
    pub instruction_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BiasedExclusiveResume {
    Load,
    Exact,
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BiasedExclusiveRecovery {
    pub scratch: super::types::BiasedExclusiveScratch,
    pub resume: BiasedExclusiveResume,
}

impl RecoveryAction {
    pub const fn instruction_complete(self) -> bool {
        match self {
            Self::RestoreScratchCompleted { .. }
            | Self::RestoreScratchAndContextCompleted { .. }
            | Self::RestoreDualVirtualReadOnlyCompleted { .. }
            | Self::CommitVirtualizedAndRestoreScratch { .. }
            | Self::CommitVirtualizedAndRestoreScratchAndContext { .. }
            | Self::CommitDualVirtualAndRestore { .. } => true,
            Self::RecoverCounterRead(recovery) => recovery.instruction_complete,
            Self::RecoverBiasedMemory(recovery) => recovery.instruction_complete,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BiasedBase {
    Register(u32),
    StackPointer,
    VirtualX18,
    VirtualX28,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BiasedBaseCoordinate {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BiasedMemoryRecovery {
    pub scratch_registers: [u32; 4],
    pub scratch_count: u8,
    pub base_scratch: u32,
    pub base: BiasedBase,
    pub base_coordinate: BiasedBaseCoordinate,
    pub commit_base: bool,
    pub virtual_x18_scratch: Option<u32>,
    pub virtual_x28_scratch: Option<u32>,
    pub host_bias: carrick_dsr::address::NativeHostBias,
    pub instruction_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryEntry {
    pub cache: CacheOffset,
    pub action: RecoveryAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DirectLinkKind {
    Branch,
    Call,
    ConditionalTaken,
    ConditionalFallthrough,
    Continue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectStubEnvelope {
    pub start: CacheOffset,
    pub end: CacheOffset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectLink {
    pub slot: CacheOffset,
    pub source: GuestVa,
    pub target: GuestVa,
    pub kind: DirectLinkKind,
    pub stub: DirectStubEnvelope,
}

impl EmittedBlock {
    pub fn from_artifact_parts(
        code: PublishedCode,
        entries: Vec<PcMapEntry>,
        direct_links: Vec<DirectLink>,
        recovery: Vec<RecoveryEntry>,
    ) -> Result<Self, DsrError> {
        Ok(Self {
            code,
            map: InstructionMap::new(entries)?,
            direct_links,
            recovery,
        })
    }

    pub const fn entry(&self) -> CacheVa {
        self.code.entry()
    }

    pub const fn len(&self) -> usize {
        self.code.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.code.len() == 0
    }

    pub const fn map(&self) -> &InstructionMap {
        &self.map
    }

    pub fn direct_links(&self) -> &[DirectLink] {
        &self.direct_links
    }

    pub fn recovery(&self) -> &[RecoveryEntry] {
        &self.recovery
    }

    pub fn into_runtime_metadata(self) -> (Vec<PcMapEntry>, Vec<DirectLink>, Vec<RecoveryEntry>) {
        (self.map.into_entries(), self.direct_links, self.recovery)
    }
}

fn unsupported_action(
    plan: &BlockPlan,
    guest_pc: GuestVa,
    word: u32,
    class: &'static str,
) -> DsrError {
    let op = bad64::decode(word, guest_pc.raw())
        .map(|instruction| instruction.op())
        .unwrap_or(bad64::Op::UDF);
    DsrError::UnsupportedBlockAction {
        block_start: plan.start.raw(),
        generation: plan.generation.get(),
        guest_pc: guest_pc.raw(),
        word,
        op,
        class,
    }
}

fn current_offset(assembler: &VecAssembler<Aarch64Relocation>) -> Result<CacheOffset, DsrError> {
    u32::try_from(assembler.offset().0)
        .map(CacheOffset::published)
        .map_err(|_| DsrError::CachePolicy("emitted block exceeds u32 offsets".to_string()))
}

fn map_next(
    assembler: &VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
) -> Result<(), DsrError> {
    entries.push(PcMapEntry {
        guest,
        cache: current_offset(assembler)?,
    });
    Ok(())
}

fn emit_mov_u64(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    register: u32,
    value: MaterializedValue,
    recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    if let Some(recording) = recording {
        recording.record_mov_wide(current_offset(assembler)?, register, value)?;
    }
    let value = value.raw();
    for halfword in 0..4_u32 {
        map_next(assembler, entries, guest)?;
        let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
        let base = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        assembler.push_u32(base | (halfword << 21) | (immediate << 5) | register);
    }
    Ok(())
}

fn emit_word(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    word: u32,
) -> Result<(), DsrError> {
    map_next(assembler, entries, guest)?;
    assembler.push_u32(word);
    Ok(())
}

fn gpr_index(register: bad64::Reg) -> Option<u32> {
    let raw = register as u32;
    let first_x = bad64::Reg::X0 as u32;
    let last_x = bad64::Reg::X30 as u32;
    let first_w = bad64::Reg::W0 as u32;
    let last_w = bad64::Reg::W30 as u32;
    if (first_x..=last_x).contains(&raw) {
        Some(raw - first_x)
    } else if (first_w..=last_w).contains(&raw) {
        Some(raw - first_w)
    } else {
        None
    }
}

const fn virtual_snapshot_offset(register: u32) -> Option<u32> {
    match register {
        18 => Some(144),
        28 => Some(224),
        _ => None,
    }
}

fn emit_pc_relative_address(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    relative: super::types::PcRelativeInst,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let destination = relative.destination.ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            relative.word,
            "PC-relative instruction without destination",
        )
    })?;
    let register = gpr_index(destination).ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            relative.word,
            "PC-relative non-GPR destination",
        )
    })?;
    let scratch = if register == 17 { 16 } else { 17 };
    emit_word(
        assembler,
        entries,
        guest,
        0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch,
    )?;
    for halfword in 0..4_u32 {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreScratch { register: scratch },
        });
        let immediate = ((relative.target.raw() >> (halfword * 16)) & 0xffff) as u32;
        let base = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        emit_word(
            assembler,
            entries,
            guest,
            base | (halfword << 21) | (immediate << 5) | scratch,
        )?;
    }
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratch { register: scratch },
    });
    if let Some(offset) = virtual_snapshot_offset(register) {
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((offset / 8) << 10) | (28 << 5) | scratch,
        )?;
    } else {
        emit_word(
            assembler,
            entries,
            guest,
            0xaa00_03e0 | (scratch << 16) | register,
        )?;
    }
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchCompleted { register: scratch },
    });
    emit_word(
        assembler,
        entries,
        guest,
        0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch,
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "emission and recovery metadata must advance together"
)]
fn emit_recovering_scratch_sequence(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    target: MaterializedAddress,
    memory_word: u32,
    scratch: u32,
    commit_virtual: Option<(u32, u32)>,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let save = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch;
    let restore = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch;
    emit_word(assembler, entries, guest, save)?;
    if let Some(invalid_guest) = target.invalid_biased_guest() {
        for halfword in 0..4_u32 {
            recovery.push(RecoveryEntry {
                cache: current_offset(assembler)?,
                action: RecoveryAction::RestoreScratch { register: scratch },
            });
            let immediate = ((invalid_guest.raw() >> (halfword * 16)) & 0xffff) as u32;
            let base = if halfword == 0 {
                0xd280_0000
            } else {
                0xf280_0000
            };
            emit_word(
                assembler,
                entries,
                guest,
                base | (halfword << 21) | (immediate << 5) | scratch,
            )?;
        }
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreScratch { register: scratch },
        });
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((1200 / 8) << 10) | (28 << 5) | scratch,
        )?;
    }
    for halfword in 0..4_u32 {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreScratch { register: scratch },
        });
        let immediate = ((target.raw() >> (halfword * 16)) & 0xffff) as u32;
        let base = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        emit_word(
            assembler,
            entries,
            guest,
            base | (halfword << 21) | (immediate << 5) | scratch,
        )?;
    }
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: if target.invalid_biased_guest().is_some() {
            RecoveryAction::RestoreScratchInvalidBiasedLiteral { register: scratch }
        } else {
            RecoveryAction::RestoreScratch { register: scratch }
        },
    });
    emit_word(assembler, entries, guest, memory_word)?;
    if let Some((virtual_register, snapshot_offset)) = commit_virtual {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::CommitVirtualizedAndRestoreScratch {
                register: scratch,
                virtual_register,
            },
        });
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((snapshot_offset / 8) << 10) | (28 << 5) | scratch,
        )?;
    }
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchCompleted { register: scratch },
    });
    emit_word(assembler, entries, guest, restore)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterializedAddress {
    Guest(GuestVa),
    Host(HostVa),
    InvalidBiased { guest: GuestVa, host: HostVa },
}

impl MaterializedAddress {
    fn raw(self) -> u64 {
        match self {
            Self::Guest(address) => address.raw(),
            Self::Host(address) => address.raw() as u64,
            Self::InvalidBiased { host, .. } => host.raw() as u64,
        }
    }

    fn invalid_biased_guest(self) -> Option<GuestVa> {
        match self {
            Self::InvalidBiased { guest, .. } => Some(guest),
            Self::Guest(_) | Self::Host(_) => None,
        }
    }
}

fn emit_pc_relative_literal(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    relative: super::types::PcRelativeInst,
    target: MaterializedAddress,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let opc = relative.word >> 30;
    let vector = (relative.word >> 26) & 1 != 0;
    let destination = relative.word & 0x1f;
    let scratch = if !vector && destination == 17 { 16 } else { 17 };
    if relative.kind == super::types::PcRelativeKind::LiteralPrefetch {
        let word = 0xf980_0000 | (scratch << 5) | destination;
        return emit_recovering_scratch_sequence(
            assembler, entries, guest, target, word, scratch, None, recovery,
        );
    }

    if vector {
        let base = match opc {
            0 => 0xbd40_0000, // ldr St, [Xn]
            1 => 0xfd40_0000, // ldr Dt, [Xn]
            2 => 0x3dc0_0000, // ldr Qt, [Xn]
            _ => {
                return Err(unsupported_action(
                    plan,
                    guest,
                    relative.word,
                    "reserved SIMD literal load",
                ));
            }
        };
        let word = base | (scratch << 5) | destination;
        return emit_recovering_scratch_sequence(
            assembler, entries, guest, target, word, scratch, None, recovery,
        );
    }

    let base = match opc {
        0 => 0xb940_0000, // ldr Wt, [Xn]
        1 => 0xf940_0000, // ldr Xt, [Xn]
        2 => 0xb980_0000, // ldrsw Xt, [Xn]
        _ => {
            return Err(unsupported_action(
                plan,
                guest,
                relative.word,
                "reserved integer literal load",
            ));
        }
    };

    let virtual_destination = virtual_snapshot_offset(destination);
    let load_destination = if virtual_destination.is_some() {
        scratch
    } else {
        destination
    };
    emit_recovering_scratch_sequence(
        assembler,
        entries,
        guest,
        target,
        base | (scratch << 5) | load_destination,
        scratch,
        virtual_destination.map(|offset| (destination, offset)),
        recovery,
    )
}

#[allow(
    clippy::needless_option_as_deref,
    clippy::too_many_arguments,
    reason = "gateway emission reborrows optional recording across its fixed exit payload"
)]
fn emit_gateway_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    target: GuestVa,
    source: Option<GuestVa>,
    status: u32,
    gateway: GatewayKind,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    emit_mov_u64(
        assembler,
        entries,
        guest,
        17,
        MaterializedValue::Guest(target.raw()),
        recording.as_deref_mut(),
    )?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );
    if let Some(source) = source {
        emit_mov_u64(
            assembler,
            entries,
            guest,
            17,
            MaterializedValue::Guest(source.raw()),
            recording.as_deref_mut(),
        )?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, #1088]
        );
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; mov w17, status
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str w17, [x28, #1096]
    );
    // Load the gateway entry point from the context rather than materializing
    // it into the block: one `ldr` instead of a four-word `movz`/`movk` chain,
    // and no host code address baked into emitted bytes (guest processes
    // self-reexec with different slides, so an embedded one pins the block to
    // its emitting process).
    let gateway_offset = super::gateway::exit_address_offset(gateway);
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #gateway_offset]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
    );
    Ok(())
}

fn relocated_direct_word(
    word: u32,
    exit: super::types::DirectExit,
    virtual_scratch: Option<u32>,
) -> Result<u32, DsrError> {
    let immediate = 2_u32;
    let mut relocated = match exit.kind {
        super::types::DirectKind::Conditional | super::types::DirectKind::CompareZero { .. } => {
            (word & !0x00ff_ffe0) | (immediate << 5)
        }
        super::types::DirectKind::TestBit { .. } => (word & !0x0007_ffe0) | (immediate << 5),
        _ => {
            return Err(DsrError::BlockPolicy(format!(
                "cannot relocate non-conditional direct word 0x{word:08x}"
            )));
        }
    };
    if let Some(scratch) = virtual_scratch {
        relocated = (relocated & !0x1f) | scratch;
    }
    Ok(relocated)
}

#[allow(
    clippy::needless_option_as_deref,
    reason = "indirect exit emission reborrows optional recording across its resolver paths"
)]
fn emit_indirect_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    exit: super::types::IndirectExit,
    recovery: &mut Vec<RecoveryEntry>,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    let register = gpr_index(exit.register)
        .ok_or_else(|| unsupported_action(plan, guest, 0, "indirect exit with non-GPR target"))?;
    // Capture every scratch value before using physical x17 as the target
    // register.  A kick may land on any following resolver instruction; its
    // recovery entry must always point at a complete pre-instruction state.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, #1160]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #1120]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1128]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x30, [x28, #1168]
    );
    if let Some(offset) = virtual_snapshot_offset(register) {
        emit_word(
            assembler,
            entries,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | 18,
        )?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x18, [x28, #1080]
        );
    } else {
        // Keep ordinary guest targets out of physical x18. Darwin does not
        // reliably restore custom x18 across asynchronous signals, and V8's
        // write-fault/invalidation traffic can interrupt this two-instruction
        // window. Store the guest register directly into the context instead.
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((1080 / 8) << 10) | (28 << 5) | register,
        )?;
    }
    emit_word(assembler, entries, guest, 0xd53b_4210)?; // mrs x16, nzcv
    let register_recovery = current_offset(assembler)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #936]
    );
    recovery.push(RecoveryEntry {
        cache: register_recovery,
        action: RecoveryAction::RestoreIndirectRegisters,
    });
    let full_recovery_start = current_offset(assembler)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #1080]
    );
    let link = (exit.kind == super::types::IndirectKind::Call).then_some(exit.resume);
    if let Some(link) = link {
        emit_mov_u64(
            assembler,
            entries,
            guest,
            30,
            MaterializedValue::Guest(link.raw()),
            recording.as_deref_mut(),
        )?;
    }
    // A per-thread direct-mapped cache keeps repeated indirect calls and
    // returns inside translated code. Restore every guest-visible scratch
    // value on both hit and miss paths.
    let miss = assembler.new_dynamic_label();
    let hit = assembler.new_dynamic_label();
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, super::gateway::CTX_INDIRECT_CACHE]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x15, =>miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; eor x16, x17, x17, LSR #12
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ubfx x16, x16, #2, #super::gateway::INDIRECT_CACHE_INDEX_BITS
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, x16, LSL #super::gateway::INDIRECT_CACHE_ENTRY_SHIFT
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x15]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x16, x17
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.eq =>hit
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, #32
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x15]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x16, x17
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.ne =>miss
        ; =>hit
    );
    // The cache entry's generation belongs to the target page, not the source
    // block in the current gateway context. The target block's first-instruction
    // generation guard is the authoritative stale-code check.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15, #8]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>miss
    );
    let _ = emit_target_authority_switch(assembler, entries, guest, miss)?;
    // Keep ordinary translated targets out of custom physical x18 entirely.
    // Preserve the validated cache PC from physical x17 in the context while
    // guest x15/x16/x17 and NZCV are restored, then reload and recheck it
    // immediately before the branch.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1072]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #936]
    );
    emit_word(assembler, entries, guest, 0xd51b_4210)?; // msr nzcv, x16
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #1120]
    );
    // Keep the validated cache PC out of custom physical x18 for the final
    // branch. Every translated block restores guest x17 at entry, so ordinary
    // physical x17 can safely carry this internal edge.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #1072]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
        ; =>miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #1080]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #936]
    );
    emit_word(assembler, entries, guest, 0xd51b_4210)?; // msr nzcv, x16
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #1120]
    );
    emit_mov_u64(
        assembler,
        entries,
        guest,
        17,
        MaterializedValue::Guest(guest.raw()),
        recording.as_deref_mut(),
    )?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1088]
    );
    if let Some(link) = link {
        emit_mov_u64(
            assembler,
            entries,
            guest,
            17,
            MaterializedValue::Guest(link.raw()),
            recording.as_deref_mut(),
        )?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, #1104]
        );
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; mov w17, #1
        );
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str w17, [x28, #1112]
        );
    } else {
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str wzr, [x28, #1112]
        );
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; mov w17, #3
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str w17, [x28, #1096]
    );
    let gateway_offset = super::gateway::exit_address_offset(GatewayKind::Indirect);
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #gateway_offset]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
    );
    let resolver_end = current_offset(assembler)?;
    for offset in (full_recovery_start.get()..resolver_end.get()).step_by(4) {
        recovery.push(RecoveryEntry {
            cache: CacheOffset::published(offset),
            action: RecoveryAction::RestoreIndirectResolver,
        });
    }
    Ok(())
}

/// Validate and install the cached target's executable authority.
///
/// On entry x15 addresses the target-cache record and x17 is its executable
/// pointer. The resolver publishes the pointer, range, and generation-binding
/// table as one thread-local record while translated code is not running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetAuthorityPhases {
    install_start: CacheOffset,
}

fn emit_target_authority_switch(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    miss: dynasmrt::DynamicLabel,
) -> Result<TargetAuthorityPhases, DsrError> {
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x15, #16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x16, =>miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x17, x15
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.lo =>miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x16, #8]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x17, x15
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.hs =>miss
    );
    let install_start = current_offset(assembler)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, super::gateway::CTX_CACHE_END]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, super::gateway::CTX_CACHE_START]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x16, #16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, super::gateway::CTX_GENERATION_BINDINGS]
    );
    Ok(TargetAuthorityPhases { install_start })
}

/// Emit a direct edge that can chain through the per-thread target cache.
///
/// Immutable translation units cannot patch their branch words after dyld
/// maps them. This gives their hot direct edges the same unit-scoped chaining
/// mechanism as indirect edges: the first miss resolves and publishes the
/// target, then later executions branch directly when the target belongs to
/// the currently entered unit. The cache-range checks are the generation-
/// authority boundary; a cross-unit target always returns through the gateway.
fn record_direct_binding_phase(
    recovery: &mut Vec<RecoveryEntry>,
    start: CacheOffset,
    end: CacheOffset,
    phase: DirectBindingRecoveryPhase,
    committed_link: Option<u64>,
) -> Result<(), DsrError> {
    if start.get() > end.get() || !start.get().is_multiple_of(4) || !end.get().is_multiple_of(4) {
        return Err(DsrError::CachePolicy(format!(
            "invalid direct-binding recovery range {}..{}",
            start.get(),
            end.get()
        )));
    }
    for offset in (start.get()..end.get()).step_by(4) {
        recovery.push(RecoveryEntry {
            cache: CacheOffset::published(offset),
            action: RecoveryAction::RestoreDirectBinding {
                phase,
                committed_link,
            },
        });
    }
    Ok(())
}

fn emit_cached_direct_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    map_guest: GuestVa,
    source_guest: GuestVa,
    target: GuestVa,
    committed_link: Option<u64>,
    recovery: &mut Vec<RecoveryEntry>,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    let scratch_capture_start = current_offset(assembler)?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, #1160]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #1120]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x30, [x28, #1168]
    );
    emit_word(assembler, entries, map_guest, 0xd53b_4210)?; // mrs x16, nzcv
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #936]
    );
    record_direct_binding_phase(
        recovery,
        scratch_capture_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ScratchCapture,
        committed_link,
    )?;
    let cell_address_start = current_offset(assembler)?;
    emit_mov_u64(
        assembler,
        entries,
        map_guest,
        17,
        MaterializedValue::Guest(target.raw()),
        recording.as_deref_mut(),
    )?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );

    let miss = assembler.new_dynamic_label();
    let hit = assembler.new_dynamic_label();
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, super::gateway::CTX_INDIRECT_CACHE]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x15, =>miss
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; eor x16, x17, x17, LSR #12
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ubfx x16, x16, #2, #super::gateway::INDIRECT_CACHE_INDEX_BITS
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, x16, LSL #super::gateway::INDIRECT_CACHE_ENTRY_SHIFT
    );
    record_direct_binding_phase(
        recovery,
        cell_address_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::CellAddress,
        committed_link,
    )?;
    let target_acquire_start = current_offset(assembler)?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x15]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x16, x17
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.eq =>hit
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, #32
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x15]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cmp x16, x17
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b.ne =>miss
        ; =>hit
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15, #8]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>miss
    );
    record_direct_binding_phase(
        recovery,
        target_acquire_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::TargetAcquire,
        committed_link,
    )?;
    let authority_validate_start = current_offset(assembler)?;
    let authority = emit_target_authority_switch(assembler, entries, map_guest, miss)?;
    record_direct_binding_phase(
        recovery,
        authority_validate_start,
        authority.install_start,
        DirectBindingRecoveryPhase::AuthorityValidate,
        committed_link,
    )?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1072]
    );
    record_direct_binding_phase(
        recovery,
        authority.install_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::AuthorityInstall,
        committed_link,
    )?;
    let architectural_restore_start = current_offset(assembler)?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #936]
    );
    emit_word(assembler, entries, map_guest, 0xd51b_4210)?; // msr nzcv, x16
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #1120]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x30, [x28, #1168]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #1072]
    );
    record_direct_binding_phase(
        recovery,
        architectural_restore_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ArchitecturalRestore,
        committed_link,
    )?;
    let final_branch_start = current_offset(assembler)?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
        ; =>miss
    );
    record_direct_binding_phase(
        recovery,
        final_branch_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::FinalBranch,
        committed_link,
    )?;
    let miss_exit_start = current_offset(assembler)?;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #936]
    );
    emit_word(assembler, entries, map_guest, 0xd51b_4210)?; // msr nzcv, x16
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x16, [x28, #1120]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x30, [x28, #1168]
    );
    emit_gateway_exit(
        assembler,
        entries,
        map_guest,
        target,
        Some(source_guest),
        2,
        GatewayKind::Direct,
        recording,
    )?;
    record_direct_binding_phase(
        recovery,
        miss_exit_start,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::MissExit,
        committed_link,
    )
}

fn rewritten_virtual_word(
    word: u32,
    guest: GuestVa,
    virtual_register: u32,
) -> Option<(u32, u32, u32)> {
    let original = bad64::decode(word, guest.raw()).ok()?;
    let fields = [0_u32, 5, 10, 16];
    for scratch in (9_u32..=17).rev() {
        if super::decode::decoded_operands_mention_gpr(word, guest, scratch) {
            continue;
        }
        let replaceable = fields
            .into_iter()
            .filter(|shift| ((word >> shift) & 0x1f) == virtual_register)
            .collect::<Vec<_>>();
        for mask in 1_u32..(1_u32 << replaceable.len()) {
            let mut candidate_word = word;
            for (index, shift) in replaceable.iter().copied().enumerate() {
                if mask & (1 << index) != 0 {
                    candidate_word = (candidate_word & !(0x1f << shift)) | (scratch << shift);
                }
            }
            let Ok(candidate) = bad64::decode(candidate_word, guest.raw()) else {
                continue;
            };
            if candidate.op() != original.op() {
                continue;
            }
            if super::decode::decoded_operands_mention_gpr(candidate_word, guest, virtual_register)
            {
                continue;
            }
            let virtual_x = format!("x{virtual_register}");
            let virtual_w = format!("w{virtual_register}");
            let normalized = candidate
                .to_string()
                .replace(&format!("x{scratch}"), &virtual_x)
                .replace(&format!("w{scratch}"), &virtual_w);
            if normalized == original.to_string() {
                let context_scratch = (9_u32..=17).rev().find(|candidate| {
                    *candidate != scratch
                        && !super::decode::decoded_operands_mention_gpr(word, guest, *candidate)
                })?;
                return Some((scratch, context_scratch, candidate_word));
            }
        }
    }
    None
}

fn rewritten_dual_virtual_read_only_word(
    word: u32,
    guest: GuestVa,
) -> Option<(u32, u32, u32, u32)> {
    let original = bad64::decode(word, guest.raw()).ok()?;
    let free = (9_u32..=17)
        .rev()
        .filter(|register| !super::decode::decoded_operands_mention_gpr(word, guest, *register))
        .collect::<Vec<_>>();
    let fields = [0_u32, 5, 10, 16];
    let x18_fields = fields
        .into_iter()
        .filter(|shift| ((word >> shift) & 0x1f) == 18)
        .collect::<Vec<_>>();
    let x28_fields = fields
        .into_iter()
        .filter(|shift| ((word >> shift) & 0x1f) == 28)
        .collect::<Vec<_>>();
    for &x18_scratch in &free {
        for &x28_scratch in free.iter().filter(|candidate| **candidate != x18_scratch) {
            let context_scratch = *free
                .iter()
                .find(|candidate| **candidate != x18_scratch && **candidate != x28_scratch)?;
            for x18_mask in 1_u32..(1_u32 << x18_fields.len()) {
                for x28_mask in 1_u32..(1_u32 << x28_fields.len()) {
                    let mut candidate_word = word;
                    for (index, shift) in x18_fields.iter().copied().enumerate() {
                        if x18_mask & (1 << index) != 0 {
                            candidate_word =
                                (candidate_word & !(0x1f << shift)) | (x18_scratch << shift);
                        }
                    }
                    for (index, shift) in x28_fields.iter().copied().enumerate() {
                        if x28_mask & (1 << index) != 0 {
                            candidate_word =
                                (candidate_word & !(0x1f << shift)) | (x28_scratch << shift);
                        }
                    }
                    let Ok(candidate) = bad64::decode(candidate_word, guest.raw()) else {
                        continue;
                    };
                    if candidate.op() != original.op()
                        || super::decode::decoded_operands_mention_gpr(candidate_word, guest, 18)
                        || super::decode::decoded_operands_mention_gpr(candidate_word, guest, 28)
                    {
                        continue;
                    }
                    let normalized = candidate
                        .to_string()
                        .replace(&format!("x{x18_scratch}"), "x18")
                        .replace(&format!("w{x18_scratch}"), "w18")
                        .replace(&format!("x{x28_scratch}"), "x28")
                        .replace(&format!("w{x28_scratch}"), "w28");
                    if normalized == original.to_string() {
                        return Some((x18_scratch, x28_scratch, context_scratch, candidate_word));
                    }
                }
            }
        }
    }
    None
}

fn emit_dual_virtual(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    word: u32,
    commit_virtual: Option<u32>,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let (x18_scratch, x28_scratch, context_scratch, rewritten) =
        rewritten_dual_virtual_read_only_word(word, guest).ok_or_else(|| {
            unsupported_action(plan, guest, word, "unrewritable x18/x28 instruction")
        })?;
    for save in [
        0xf900_0000 | ((1160 / 8) << 10) | (28 << 5) | x18_scratch,
        0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | x28_scratch,
        0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | context_scratch,
    ] {
        emit_word(assembler, entries, guest, save)?;
    }
    let restore = RecoveryAction::RestoreDualVirtualReadOnly {
        x18_scratch,
        x28_scratch,
        context_scratch,
    };
    let completed_restore = RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
        x18_scratch,
        x28_scratch,
        context_scratch,
    };
    for instruction in [
        0xaa1c_03e0 | context_scratch,
        0xf940_0000 | ((144 / 8) << 10) | (context_scratch << 5) | x18_scratch,
        0xf940_0000 | ((224 / 8) << 10) | (context_scratch << 5) | x28_scratch,
        rewritten,
    ] {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: restore,
        });
        emit_word(assembler, entries, guest, instruction)?;
    }
    if let Some(virtual_register) = commit_virtual {
        let (virtual_scratch, snapshot_offset) = match virtual_register {
            18 => (x18_scratch, 144),
            28 => (x28_scratch, 224),
            _ => {
                return Err(unsupported_action(
                    plan,
                    guest,
                    word,
                    "invalid dual virtual destination",
                ));
            }
        };
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            },
        });
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((snapshot_offset / 8) << 10) | (context_scratch << 5) | virtual_scratch,
        )?;
    }
    for instruction in [
        0xf940_0000 | ((1160 / 8) << 10) | (context_scratch << 5) | x18_scratch,
        0xf940_0000 | ((1120 / 8) << 10) | (context_scratch << 5) | x28_scratch,
        0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | context_scratch,
    ] {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: completed_restore,
        });
        emit_word(assembler, entries, guest, instruction)?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "virtual-register emission carries its explicit recovery contract"
)]
fn emit_virtualized_register(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    word: u32,
    virtual_register: u32,
    snapshot_offset: u32,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let (scratch, context_scratch, rewritten) =
        rewritten_virtual_word(word, guest, virtual_register).ok_or_else(|| {
            unsupported_action(
                plan,
                guest,
                word,
                "unrewritable virtualized register instruction",
            )
        })?;
    let save = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch;
    let save_context = 0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | context_scratch;
    let mirror_context = 0xaa1c_03e0 | context_scratch;
    let load_virtual =
        0xf940_0000 | ((snapshot_offset / 8) << 10) | (context_scratch << 5) | scratch;
    let store_virtual =
        0xf900_0000 | ((snapshot_offset / 8) << 10) | (context_scratch << 5) | scratch;
    let restore = 0xf940_0000 | ((1120 / 8) << 10) | (context_scratch << 5) | scratch;
    let restore_context = 0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | context_scratch;
    emit_word(assembler, entries, guest, save)?;
    emit_word(assembler, entries, guest, save_context)?;
    emit_word(assembler, entries, guest, mirror_context)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchAndContext {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, load_virtual)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchAndContext {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, rewritten)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            register: scratch,
            context_register: context_scratch,
            virtual_register,
        },
    });
    emit_word(assembler, entries, guest, store_virtual)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchAndContextCompleted {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, restore)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchAndContextCompleted {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, restore_context)?;
    Ok(())
}

fn emit_counter_recovery_word(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    word: u32,
    action: CounterReadRecovery,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverCounterRead(action),
    });
    emit_word(assembler, entries, guest, word)
}

fn emit_counter_mov_u64(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    register: u32,
    value: u64,
    action: CounterReadRecovery,
) -> Result<(), DsrError> {
    for halfword in 0..4_u32 {
        let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
        if halfword != 0 && immediate == 0 {
            continue;
        }
        let base = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            base | (halfword << 21) | (immediate << 5) | register,
            action,
        )?;
    }
    Ok(())
}

fn emit_counter_read(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    counter: super::types::CounterRead,
    source: super::counter::HostCounterSource,
    scale: super::counter::CounterScale,
) -> Result<(), DsrError> {
    const SCRATCH: [(u32, u32); 3] = [(15, 1160), (16, 1120), (17, 1128)];
    let destination = match counter.destination {
        super::types::CounterDestination::Gpr(register) if register <= 30 => {
            Some(u32::from(register))
        }
        super::types::CounterDestination::Gpr(register) => {
            return Err(DsrError::BlockPolicy(format!(
                "counter destination x{register} is outside the architectural GPR file"
            )));
        }
        super::types::CounterDestination::Discard => None,
    };
    let scratch_destination = match destination {
        Some(15) => Some(CounterScratchDestination::X15),
        Some(16) => Some(CounterScratchDestination::X16),
        Some(17) => Some(CounterScratchDestination::X17),
        _ => None,
    };
    let pre_commit = CounterReadRecovery {
        committed_scratch_destination: None,
        instruction_complete: false,
    };
    let post_commit = CounterReadRecovery {
        committed_scratch_destination: scratch_destination,
        instruction_complete: true,
    };

    // Capturing all three physical scratch values before changing any of them
    // lets a signal/kick rebuild the exact pre-instruction guest state.
    for (register, offset) in SCRATCH {
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((offset / 8) << 10) | (28 << 5) | register,
        )?;
    }

    let retry = assembler.new_dynamic_label();
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>retry
    );
    emit_counter_mov_u64(
        assembler,
        entries,
        recovery,
        guest,
        15,
        super::counter::COMMPAGE_TIMEBASE_ADDRESS,
        pre_commit,
    )?;
    emit_counter_recovery_word(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_01f0, // ldr x16, [x15] -- offset before
        pre_commit,
    )?;
    let counter_word = super::counter::counter_word(source, 17).ok_or_else(|| {
        DsrError::BlockPolicy(format!(
            "counter source {source:?} reached inline emission without a proved word"
        ))
    })?;
    emit_counter_recovery_word(
        assembler,
        entries,
        recovery,
        guest,
        counter_word,
        pre_commit,
    )?;
    emit_counter_recovery_word(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_01ef, // ldr x15, [x15] -- offset after
        pre_commit,
    )?;
    emit_counter_recovery_word(
        assembler,
        entries,
        recovery,
        guest,
        0xca0f_0210, // eor x16, x16, x15 -- compare without changing NZCV
        pre_commit,
    )?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverCounterRead(pre_commit),
    });
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbnz x16, =>retry
    );
    emit_counter_recovery_word(
        assembler,
        entries,
        recovery,
        guest,
        0x8b0f_0231, // add x17, x17, x15 -- wrapping signed-offset adjustment
        pre_commit,
    )?;

    if scale.numerator() != 1 || scale.denominator() != 1 {
        // floor(ticks * numerator / denominator), decomposed so the
        // multiplication cannot overflow before division. Both reduced scale
        // terms are u32, so remainder * numerator fits in u64 exactly.
        emit_counter_mov_u64(
            assembler,
            entries,
            recovery,
            guest,
            15,
            u64::from(scale.denominator()),
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x9acf_0a30, // udiv x16, x17, x15 -- quotient
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x9b0f_c60f, // msub x15, x16, x15, x17 -- remainder
            pre_commit,
        )?;
        emit_counter_mov_u64(
            assembler,
            entries,
            recovery,
            guest,
            17,
            u64::from(scale.numerator()),
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x9b11_7e10, // mul x16, x16, x17
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x9b11_7def, // mul x15, x15, x17
            pre_commit,
        )?;
        emit_counter_mov_u64(
            assembler,
            entries,
            recovery,
            guest,
            17,
            u64::from(scale.denominator()),
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x9ad1_09ef, // udiv x15, x15, x17
            pre_commit,
        )?;
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0x8b0f_0211, // add x17, x16, x15
            pre_commit,
        )?;
    }

    match destination {
        Some(18) => emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0xf900_0000 | ((144 / 8) << 10) | (28 << 5) | 17,
            pre_commit,
        )?,
        Some(28) => emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0xf900_0000 | ((224 / 8) << 10) | (28 << 5) | 17,
            pre_commit,
        )?,
        Some(17) | None => {}
        Some(register) => emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0xaa11_03e0 | register, // mov Xd, x17
            pre_commit,
        )?,
    }

    // Recovery from any cleanup word performs the remaining restores itself,
    // preserves an aliased committed destination, and resumes at guest PC+4.
    for (register, offset) in SCRATCH.into_iter().rev() {
        if Some(register) == destination {
            continue;
        }
        emit_counter_recovery_word(
            assembler,
            entries,
            recovery,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | register,
            post_commit,
        )?;
    }
    Ok(())
}

const BIASED_SCRATCH_CONTEXT_OFFSETS: [u32; 4] = [1120, 1128, 1160, 1168];

fn biased_base(memory: super::types::MemoryAccess) -> Result<BiasedBase, DsrError> {
    match memory.base {
        super::types::MemoryBase::Register(register) => {
            if matches!(register, bad64::Reg::SP | bad64::Reg::WSP) {
                Ok(BiasedBase::StackPointer)
            } else {
                gpr_index(register)
                    .map(BiasedBase::Register)
                    .ok_or_else(|| {
                        DsrError::BlockPolicy(format!(
                            "biased memory base {register:?} is not a GPR or SP"
                        ))
                    })
            }
        }
        super::types::MemoryBase::VirtualX18 => Ok(BiasedBase::VirtualX18),
        super::types::MemoryBase::VirtualX28 => Ok(BiasedBase::VirtualX28),
        super::types::MemoryBase::Literal(_) => Ok(BiasedBase::None),
    }
}

fn biased_base_load_word(base: BiasedBase, destination: u32) -> Option<u32> {
    match base {
        BiasedBase::Register(register) => Some(0xaa00_03e0 | (register << 16) | destination),
        BiasedBase::StackPointer => Some(0x9100_03e0 | destination),
        BiasedBase::VirtualX18 => Some(0xf940_0000 | ((144 / 8) << 10) | (28 << 5) | destination),
        BiasedBase::VirtualX28 => Some(0xf940_0000 | ((224 / 8) << 10) | (28 << 5) | destination),
        BiasedBase::None => None,
    }
}

fn rewritten_biased_virtual_word(
    memory: super::types::MemoryAccess,
    guest: GuestVa,
) -> Result<(u32, Option<u32>, Option<u32>), DsrError> {
    match memory.virtualization {
        super::types::MemoryVirtualization::None => Ok((memory.word, None, None)),
        super::types::MemoryVirtualization::X18 => {
            let (scratch, _, word) =
                rewritten_virtual_word(memory.word, guest, 18).ok_or_else(|| {
                    DsrError::BlockPolicy("biased x18 memory operand is not rewritable".to_string())
                })?;
            Ok((word, Some(scratch), None))
        }
        super::types::MemoryVirtualization::X28 => {
            let (scratch, _, word) =
                rewritten_virtual_word(memory.word, guest, 28).ok_or_else(|| {
                    DsrError::BlockPolicy("biased x28 memory operand is not rewritable".to_string())
                })?;
            Ok((word, None, Some(scratch)))
        }
        super::types::MemoryVirtualization::X18X28ReadOnly
        | super::types::MemoryVirtualization::X18WriteX28Read => {
            let (x18, x28, _, word) = rewritten_dual_virtual_read_only_word(memory.word, guest)
                .ok_or_else(|| {
                    DsrError::BlockPolicy(
                        "biased x18/x28 memory operands are not rewritable".to_string(),
                    )
                })?;
            Ok((word, Some(x18), Some(x28)))
        }
        super::types::MemoryVirtualization::Unsupported => Err(DsrError::BlockPolicy(
            "biased memory has unsupported x18/x28 virtualization".to_string(),
        )),
    }
}

fn biased_scratch_registers(
    word: u32,
    guest: GuestVa,
    already: &[u32],
    count: usize,
) -> Option<Vec<u32>> {
    let mut selected = Vec::with_capacity(count);
    for register in (9_u32..=17)
        .rev()
        .chain((0_u32..=8).rev())
        .chain([30, 29, 27])
    {
        if already.contains(&register)
            || selected.contains(&register)
            || super::decode::decoded_operands_mention_gpr(word, guest, register)
        {
            continue;
        }
        selected.push(register);
        if selected.len() == count {
            return Some(selected);
        }
    }
    None
}

fn emit_with_biased_recovery(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    word: u32,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverBiasedMemory(action),
    });
    emit_word(assembler, entries, guest, word)
}

fn emit_biased_materialize_u64(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    register: u32,
    value: u64,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    let chunks = [
        value as u16,
        (value >> 16) as u16,
        (value >> 32) as u16,
        (value >> 48) as u16,
    ];
    let first = chunks.iter().position(|chunk| *chunk != 0).unwrap_or(0);
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xd280_0000 | ((first as u32) << 21) | ((u32::from(chunks[first])) << 5) | register,
        action,
    )?;
    for (index, chunk) in chunks.into_iter().enumerate() {
        if index == first || chunk == 0 {
            continue;
        }
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xf280_0000 | ((index as u32) << 21) | ((u32::from(chunk)) << 5) | register,
            action,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "effective-address lowering shares the biased emission and recovery context"
)]
fn emit_biased_effective_guest_address(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    memory: super::types::MemoryAccess,
    rewritten: u32,
    base_scratch: u32,
    effective_scratch: u32,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    match memory.effective_address {
        super::types::MemoryEffectiveAddress::Base => emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xaa00_03e0 | (base_scratch << 16) | effective_scratch,
            action,
        ),
        super::types::MemoryEffectiveAddress::Immediate(offset) => {
            emit_biased_materialize_u64(
                assembler,
                entries,
                recovery,
                guest,
                effective_scratch,
                offset as u64,
                action,
            )?;
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0x8b00_0000 | (effective_scratch << 16) | (base_scratch << 5) | effective_scratch,
                action,
            )
        }
        super::types::MemoryEffectiveAddress::RegisterOffset { extend, shift } => {
            if shift > 4 {
                return Err(DsrError::BlockPolicy(format!(
                    "biased register offset shift {shift} exceeds ADD extended range at guest PC 0x{:x}",
                    guest.raw()
                )));
            }
            let option = match extend {
                super::types::MemoryIndexExtend::Uxtw => 2,
                super::types::MemoryIndexExtend::Uxtx => 3,
                super::types::MemoryIndexExtend::Sxtw => 6,
                super::types::MemoryIndexExtend::Sxtx => 7,
            };
            let index = (rewritten >> 16) & 0x1f;
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0x8b20_0000
                    | (index << 16)
                    | (option << 13)
                    | (u32::from(shift) << 10)
                    | (base_scratch << 5)
                    | effective_scratch,
                action,
            )
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "biased memory lowering keeps emission and recovery metadata together"
)]
fn emit_biased_memory(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    memory: super::types::MemoryAccess,
    host_bias: carrick_dsr::address::NativeHostBias,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    if memory.class == super::types::MemoryClass::Unsupported {
        return Err(unsupported_action(
            plan,
            guest,
            memory.word,
            "memory family unsupported in biased mode",
        ));
    }
    if memory.class == super::types::MemoryClass::Exclusive {
        return Err(unsupported_action(
            plan,
            guest,
            memory.word,
            "exclusive access leaked past its typed execution boundary",
        ));
    }
    if matches!(
        memory.class,
        super::types::MemoryClass::Scalar | super::types::MemoryClass::Pair
    ) && memory.writeback != super::types::MemoryWriteback::None
        && format!("{:?}", memory.op).starts_with("LD")
        && super::decode::decoded_writeback_destination_overlaps_base(memory.word, guest)
    {
        return Err(unsupported_action(
            plan,
            guest,
            memory.word,
            "constrained writeback load overlaps its base register",
        ));
    }
    if let super::types::MemoryBase::Literal(target) = memory.base {
        let materialized = if target.raw() < carrick_dsr::address::BIASED_GUEST_LITERAL_TARGET_END {
            let host_target = target.raw().checked_add(host_bias.get()).ok_or_else(|| {
                DsrError::BlockPolicy(format!(
                    "biased literal target overflow at guest PC 0x{:x}",
                    guest.raw()
                ))
            })?;
            MaterializedAddress::Host(HostVa(usize::try_from(host_target).map_err(|_| {
                DsrError::BlockPolicy(format!(
                    "biased literal host target 0x{host_target:x} does not fit HostVa"
                ))
            })?))
        } else {
            let tag = carrick_dsr::address::INVALID_BIASED_HOST_ADDRESS_BIT;
            MaterializedAddress::InvalidBiased {
                guest: target,
                host: HostVa((tag | (target.raw() & (tag - 1))) as usize),
            }
        };
        return emit_pc_relative_literal(
            assembler,
            entries,
            plan,
            guest,
            super::types::PcRelativeInst {
                kind: if memory.op == bad64::Op::PRFM {
                    super::types::PcRelativeKind::LiteralPrefetch
                } else {
                    super::types::PcRelativeKind::LiteralLoad
                },
                target,
                destination: None,
                word: memory.word,
            },
            materialized,
            recovery,
        );
    }

    let base = biased_base(memory)?;
    let (mut rewritten, virtual_x18_scratch, virtual_x28_scratch) =
        rewritten_biased_virtual_word(memory, guest)?;
    let mut scratch_registers = [0_u32; 4];
    let mut scratch_count = 0_usize;
    for register in [virtual_x18_scratch, virtual_x28_scratch]
        .into_iter()
        .flatten()
    {
        if !scratch_registers[..scratch_count].contains(&register) {
            scratch_registers[scratch_count] = register;
            scratch_count += 1;
        }
    }
    let extra =
        biased_scratch_registers(memory.word, guest, &scratch_registers[..scratch_count], 2)
            .ok_or_else(|| {
                unsupported_action(plan, guest, memory.word, "no safe biased memory scratch")
            })?;
    let base_scratch = extra[0];
    let bias_scratch = extra[1];
    for register in extra {
        if scratch_count >= scratch_registers.len() {
            return Err(unsupported_action(
                plan,
                guest,
                memory.word,
                "biased memory needs more than four scratch registers",
            ));
        }
        scratch_registers[scratch_count] = register;
        scratch_count += 1;
    }
    rewritten = (rewritten & !(0x1f << 5)) | (base_scratch << 5);

    for (index, register) in scratch_registers[..scratch_count]
        .iter()
        .copied()
        .enumerate()
    {
        let offset = BIASED_SCRATCH_CONTEXT_OFFSETS[index];
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((offset / 8) << 10) | (28 << 5) | register,
        )?;
    }
    let mut action = BiasedMemoryRecovery {
        scratch_registers,
        scratch_count: scratch_count as u8,
        base_scratch,
        base,
        base_coordinate: BiasedBaseCoordinate::Guest,
        commit_base: false,
        virtual_x18_scratch: None,
        virtual_x28_scratch: None,
        host_bias,
        instruction_complete: false,
    };
    for (virtual_register, scratch) in [(18_u32, virtual_x18_scratch), (28, virtual_x28_scratch)] {
        if let Some(scratch) = scratch {
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0xf940_0000 | (((virtual_register * 8) / 8) << 10) | (28 << 5) | scratch,
                action,
            )?;
            if virtual_register == 18 {
                action.virtual_x18_scratch = Some(scratch);
            } else {
                action.virtual_x28_scratch = Some(scratch);
            }
        }
    }
    let load_base = biased_base_load_word(base, base_scratch).ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            memory.word,
            "biased non-literal memory has no base",
        )
    })?;
    emit_with_biased_recovery(assembler, entries, recovery, guest, load_base, action)?;
    emit_biased_effective_guest_address(
        assembler,
        entries,
        recovery,
        guest,
        memory,
        rewritten,
        base_scratch,
        bias_scratch,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (bias_scratch << 5) | 18,
        action,
    )?; // lsr x18, effective, #BIASED_FAST_ADDRESS_BITS
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb400_0052, // cbz x18, +8
        action,
    )?;
    // Publish only an address outside the flags-neutral 40-bit fast window.
    // The final aperture guard covers the ceiling-to-1-TiB sliver. Larger
    // values use the tagged host access below, which cannot alias a Darwin
    // user mapping, and recovery reports this guest value instead of the
    // deliberately invalid host FAR. Keeping the valid path store-free is
    // part of the DSR hot-path contract.
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf900_0000 | ((1200 / 8) << 10) | (28 << 5) | bias_scratch,
        action,
    )?;
    emit_with_biased_recovery(assembler, entries, recovery, guest, load_base, action)?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_0000 | ((1192 / 8) << 10) | (28 << 5) | bias_scratch,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0x8b00_0000 | (bias_scratch << 16) | (base_scratch << 5) | base_scratch,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb400_0052, // cbz x18, +8
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb251_0000 | (base_scratch << 5) | base_scratch,
        action,
    )?; // orr base, base, #1 << 47
    emit_with_biased_recovery(assembler, entries, recovery, guest, rewritten, action)?;
    action.instruction_complete = true;

    let has_writeback = memory.writeback != super::types::MemoryWriteback::None;
    if has_writeback {
        action.base_coordinate = BiasedBaseCoordinate::Host;
        action.commit_base = true;
    }
    for (virtual_register, scratch) in [(18_u32, virtual_x18_scratch), (28, virtual_x28_scratch)] {
        if let Some(scratch) = scratch {
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0xf900_0000 | (((virtual_register * 8) / 8) << 10) | (28 << 5) | scratch,
                action,
            )?;
            if virtual_register == 18 {
                action.virtual_x18_scratch = None;
            } else {
                action.virtual_x28_scratch = None;
            }
        }
    }
    if has_writeback {
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xcb00_0000 | (bias_scratch << 16) | (base_scratch << 5) | base_scratch,
            action,
        )?;
        action.base_coordinate = BiasedBaseCoordinate::Guest;
        let commit = match base {
            BiasedBase::Register(register) => 0xaa00_03e0 | (base_scratch << 16) | register,
            BiasedBase::StackPointer => 0x9100_001f | (base_scratch << 5),
            BiasedBase::VirtualX18 => 0xf900_0000 | ((144 / 8) << 10) | (28 << 5) | base_scratch,
            BiasedBase::VirtualX28 => 0xf900_0000 | ((224 / 8) << 10) | (28 << 5) | base_scratch,
            BiasedBase::None => {
                return Err(unsupported_action(
                    plan,
                    guest,
                    memory.word,
                    "biased writeback has no base",
                ));
            }
        };
        emit_with_biased_recovery(assembler, entries, recovery, guest, commit, action)?;
        action.commit_base = false;
    }
    for (index, register) in scratch_registers[..scratch_count]
        .iter()
        .copied()
        .enumerate()
        .rev()
    {
        let offset = BIASED_SCRATCH_CONTEXT_OFFSETS[index];
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | register,
            action,
        )?;
    }
    Ok(())
}

fn biased_dc_zva_base(register: bad64::Reg) -> Option<BiasedBase> {
    let register = gpr_index(register)?;
    Some(match register {
        18 => BiasedBase::VirtualX18,
        28 => BiasedBase::VirtualX28,
        _ => BiasedBase::Register(register),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "DC ZVA lowering keeps address translation and recovery metadata together"
)]
fn emit_biased_dc_zva(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    word: u32,
    register: bad64::Reg,
    host_bias: carrick_dsr::address::NativeHostBias,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let base = biased_dc_zva_base(register).ok_or_else(|| {
        unsupported_action(plan, guest, word, "dc zva source is not a rewritable GPR")
    })?;
    let scratch = biased_scratch_registers(word, guest, &[], 2)
        .ok_or_else(|| unsupported_action(plan, guest, word, "no safe dc zva scratch"))?;
    let base_scratch = scratch[0];
    let bias_scratch = scratch[1];
    let scratch_registers = [base_scratch, bias_scratch, 0, 0];

    for (index, register) in scratch.iter().copied().enumerate() {
        let offset = BIASED_SCRATCH_CONTEXT_OFFSETS[index];
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((offset / 8) << 10) | (28 << 5) | register,
        )?;
    }
    let mut action = BiasedMemoryRecovery {
        scratch_registers,
        scratch_count: 2,
        base_scratch,
        base,
        base_coordinate: BiasedBaseCoordinate::Guest,
        commit_base: false,
        virtual_x18_scratch: None,
        virtual_x28_scratch: None,
        host_bias,
        instruction_complete: false,
    };
    let load_base = biased_base_load_word(base, base_scratch).ok_or_else(|| {
        unsupported_action(plan, guest, word, "dc zva has no biased address base")
    })?;
    emit_with_biased_recovery(assembler, entries, recovery, guest, load_base, action)?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (base_scratch << 5) | 18,
        action,
    )?; // lsr x18, guest_address, #BIASED_FAST_ADDRESS_BITS
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb400_0052, // cbz x18, +8
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf900_0000 | ((1200 / 8) << 10) | (28 << 5) | base_scratch,
        action,
    )?;
    // x18 is Carrick-owned inside translated code and may have held the guest
    // address. Reload the source before applying the process's host bias.
    emit_with_biased_recovery(assembler, entries, recovery, guest, load_base, action)?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_0000 | ((1192 / 8) << 10) | (28 << 5) | bias_scratch,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0x8b00_0000 | (bias_scratch << 16) | (base_scratch << 5) | base_scratch,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb400_0052, // cbz x18, +8
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb251_0000 | (base_scratch << 5) | base_scratch,
        action,
    )?; // orr address, address, #1 << 47
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        (word & !0x1f) | base_scratch,
        action,
    )?;
    action.instruction_complete = true;

    for (index, register) in scratch.iter().copied().enumerate().rev() {
        let offset = BIASED_SCRATCH_CONTEXT_OFFSETS[index];
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | register,
            action,
        )?;
    }
    Ok(())
}

pub fn emit_block(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    mode: EmitAddressMode,
) -> Result<EmittedBlock, DsrError> {
    assemble_block_inner(plan, None, mode, None)?.publish(cache)
}

pub fn emit_block_direct(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
) -> Result<EmittedBlock, DsrError> {
    emit_block(cache, plan, EmitAddressMode::Direct)
}

pub fn emit_block_with_generation(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
    mode: EmitAddressMode,
) -> Result<EmittedBlock, DsrError> {
    assemble_block_inner(plan, Some(guard), mode, None)?.publish(cache)
}

pub fn emit_block_recording_artifact(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
    mode: EmitAddressMode,
    source_words: Vec<u32>,
) -> Result<(EmittedBlock, ArtifactRecord), DsrError> {
    let (emitted, artifact) =
        emit_block_recording_artifact_optional(cache, plan, guard, mode, source_words)?;
    let artifact = artifact.ok_or_else(|| {
        DsrError::CachePolicy("emitted block was ineligible for artifact recording".to_string())
    })?;
    Ok((emitted, artifact))
}

pub fn emit_block_recording_artifact_optional(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
    mode: EmitAddressMode,
    source_words: Vec<u32>,
) -> Result<(EmittedBlock, Option<ArtifactRecord>), DsrError> {
    let mut recording = ArtifactRecording::default();
    if let EmitAddressMode::Biased { host_bias } = mode {
        recording.bind(ProcessValue::HostBias, host_bias.get())?;
    }
    let assembled = assemble_block_inner(plan, Some(guard), mode, Some(&mut recording))?;
    let artifact = recording
        .finish(
            assembled.words.clone(),
            assembled.map.entries().to_vec(),
            assembled.recovery.clone(),
            assembled.direct_links.clone(),
            source_words,
        )
        .ok();
    let emitted = assembled.publish(cache)?;
    Ok((emitted, artifact))
}

pub fn record_portable_block_artifact(
    plan: &BlockPlan,
    generation_binding: u32,
    mode: EmitAddressMode,
    source_words: Vec<u32>,
) -> Result<ArtifactRecord, DsrError> {
    let mut recording = ArtifactRecording::default();
    if let EmitAddressMode::Biased { host_bias } = mode {
        recording.bind(ProcessValue::HostBias, host_bias.get())?;
    }
    let assembled = assemble_block_inner(
        plan,
        Some(GenerationGuard::binding(
            generation_binding,
            plan.generation,
        )),
        mode,
        Some(&mut recording),
    )?;
    recording.finish(
        assembled.words,
        assembled.map.entries().to_vec(),
        assembled.recovery,
        assembled.direct_links,
        source_words,
    )
}

pub fn emit_block_with_generation_direct(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
) -> Result<EmittedBlock, DsrError> {
    emit_block_with_generation(cache, plan, guard, EmitAddressMode::Direct)
}

/// CLREX #0xF -- clear the calling PE's local exclusive monitor.
const CLREX_WORD: u32 = 0xd503_3f5f;

/// Emit one exit edge out of a fused exclusive region. Mirrors the generic
/// `PlannedExit::Continue` epilogue (save guest x17, then a lazy direct-link to
/// `target` backed by a direct gateway exit), optionally prefixed with `CLREX`
/// when the edge leaves the region without completing the store (Hazard B). The
/// emitted words map to `guest` so a kick/fault re-enters at a guest PC whose
/// re-execution is idempotent (the store has run, or the branch is re-evaluated
/// against unchanged flags).
#[allow(
    clippy::too_many_arguments,
    reason = "the exit edge carries its complete mapping and direct-link context"
)]
fn emit_region_direct_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    direct_links: &mut Vec<DirectLink>,
    recovery: &mut Vec<RecoveryEntry>,
    map_guest: GuestVa,
    source_guest: GuestVa,
    target: GuestVa,
    clear_monitor: bool,
    recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    if clear_monitor {
        emit_word(assembler, entries, map_guest, CLREX_WORD)?;
    }
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #136]
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1128]
    );
    let slot = current_offset(assembler)?;
    emit_word(assembler, entries, map_guest, 0x1400_0001)?;
    let stub_start = current_offset(assembler)?;
    emit_cached_direct_exit(
        assembler,
        entries,
        map_guest,
        source_guest,
        target,
        None,
        recovery,
        recording,
    )?;
    direct_links.push(DirectLink {
        slot,
        source: source_guest,
        target,
        kind: DirectLinkKind::Continue,
        stub: DirectStubEnvelope {
            start: stub_start,
            end: current_offset(assembler)?,
        },
    });
    Ok(())
}

fn emit_biased_exclusive_word(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    word: u32,
    scratch: super::types::BiasedExclusiveScratch,
    resume: BiasedExclusiveResume,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery { scratch, resume }),
    });
    emit_word(assembler, entries, guest, word)
}

#[allow(
    clippy::too_many_arguments,
    reason = "biased exclusive recovery metadata advances with each emitted word"
)]
fn emit_biased_exclusive_branch(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    target: dynasmrt::DynamicLabel,
    scratch: super::types::BiasedExclusiveScratch,
    resume: BiasedExclusiveResume,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery { scratch, resume }),
    });
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>target
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "biased exclusive recovery metadata advances with each materialization word"
)]
fn emit_biased_exclusive_mov_u64(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    register: u32,
    value: MaterializedValue,
    scratch: super::types::BiasedExclusiveScratch,
    resume: BiasedExclusiveResume,
    recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    let start = current_offset(assembler)?;
    emit_mov_u64(assembler, entries, guest, register, value, recording)?;
    let end = current_offset(assembler)?;
    for offset in (start.get()..end.get()).step_by(4) {
        recovery.push(RecoveryEntry {
            cache: CacheOffset::published(offset),
            action: RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                scratch,
                resume,
            }),
        });
    }
    Ok(())
}

fn exclusive_access_width(memory: super::types::MemoryAccess) -> Result<u64, DsrError> {
    let element_width = 1_u64
        .checked_shl(memory.word >> 30)
        .ok_or_else(|| DsrError::BlockPolicy("exclusive access width overflow".to_string()))?;
    if super::decode::exclusive_shape(memory.op) == Some(super::decode::ExclusiveShape::Pair) {
        element_width
            .checked_mul(2)
            .ok_or_else(|| DsrError::BlockPolicy("exclusive pair width overflow".to_string()))
    } else {
        Ok(element_width)
    }
}

#[allow(
    clippy::needless_option_as_deref,
    clippy::too_many_arguments,
    reason = "the fused region and its recovery/exit metadata are one lowering unit"
)]
fn emit_biased_exclusive_region(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    direct_links: &mut Vec<DirectLink>,
    recovery: &mut Vec<RecoveryEntry>,
    plan: &BlockPlan,
    exit: super::types::ExclusiveRegionExit,
    scratch: super::types::BiasedExclusiveScratch,
    host_bias: carrick_dsr::address::NativeHostBias,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    let address = scratch.address.index();
    let bias = scratch.bias.index();
    let load_memory = plan
        .instructions
        .first()
        .and_then(|instruction| match instruction.action {
            InstAction::Memory(memory) => Some(memory),
            _ => None,
        })
        .ok_or_else(|| {
            DsrError::BlockPolicy("biased exclusive region has no load instruction".to_string())
        })?;
    let super::types::MemoryBase::Register(base) = load_memory.base else {
        return Err(unsupported_action(
            plan,
            exit.start,
            exit.load_word,
            "biased exclusive region has a non-register base",
        ));
    };
    let base = gpr_index(base).ok_or_else(|| {
        unsupported_action(
            plan,
            exit.start,
            exit.load_word,
            "biased exclusive region has a non-GPR base",
        )
    })?;
    let access_width = exclusive_access_width(load_memory)?;
    let access_tail = u32::try_from(access_width.saturating_sub(1)).map_err(|_| {
        DsrError::BlockPolicy("biased exclusive access tail exceeds u32".to_string())
    })?;

    let slow_restore = assembler.new_dynamic_label();
    let slow_tail = assembler.new_dynamic_label();
    let region_top = assembler.new_dynamic_label();
    let success_restore = assembler.new_dynamic_label();
    let success_tail = assembler.new_dynamic_label();

    // Both scratch values are saved before either register changes. Recovery
    // begins at the first scratch-mutating instruction, when both context
    // slots hold the complete guest state.
    emit_word(
        assembler,
        entries,
        exit.start,
        0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | address,
    )?;
    // At the second spill boundary neither scratch has changed yet. A Noop is
    // the complete recovery action until this store publishes the bias value;
    // the following scratch-mutating instruction begins typed dual restore.
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::Noop,
    });
    emit_word(
        assembler,
        entries,
        exit.start,
        0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | bias,
    )?;

    let load_resume = BiasedExclusiveResume::Load;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0xaa00_03e0 | (base << 16) | address,
        scratch,
        load_resume,
    )?;

    // Validate both the base and the inclusive access end without changing
    // NZCV. Checking the base first proves the subsequent small add cannot
    // wrap u64; checking the end rejects an access that crosses the aperture.
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (address << 5) | bias,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0xb400_0040 | bias, // cbz bias, +8
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.start,
        slow_restore,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0x9100_0000 | (access_tail << 10) | (address << 5) | bias,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (bias << 5) | bias,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0xb400_0040 | bias, // cbz bias, +8
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.start,
        slow_restore,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_mov_u64(
        assembler,
        entries,
        recovery,
        exit.start,
        bias,
        MaterializedValue::Process(ProcessValue::HostBias, host_bias.get()),
        scratch,
        load_resume,
        recording.as_deref_mut(),
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        0x8b00_0000 | (bias << 16) | (address << 5) | address,
        scratch,
        load_resume,
    )?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>region_top
    );
    let mut early_exit: Option<(
        dynasmrt::DynamicLabel,
        dynasmrt::DynamicLabel,
        GuestVa,
        GuestVa,
    )> = None;
    for instruction in &plan.instructions {
        match instruction.action {
            InstAction::Memory(memory) => {
                let rewritten = (memory.word & !(0x1f << 5)) | (address << 5);
                emit_biased_exclusive_word(
                    assembler,
                    entries,
                    recovery,
                    instruction.guest,
                    rewritten,
                    scratch,
                    BiasedExclusiveResume::Exact,
                )?;
            }
            InstAction::Copy(word) => {
                emit_biased_exclusive_word(
                    assembler,
                    entries,
                    recovery,
                    instruction.guest,
                    word,
                    scratch,
                    BiasedExclusiveResume::Exact,
                )?;
            }
            InstAction::Direct(direct) => {
                let word = exit.early_exit_word.ok_or_else(|| {
                    DsrError::BlockPolicy(format!(
                        "fused biased exclusive region has a body branch but no early-exit encoding at guest PC 0x{:x}",
                        instruction.guest.raw()
                    ))
                })?;
                let restore = assembler.new_dynamic_label();
                let tail = assembler.new_dynamic_label();
                let cont = assembler.new_dynamic_label();
                let relocated = relocated_direct_word(word, direct, None)?;
                emit_biased_exclusive_word(
                    assembler,
                    entries,
                    recovery,
                    instruction.guest,
                    relocated,
                    scratch,
                    BiasedExclusiveResume::Exact,
                )?;
                let fallthrough = GuestVa(instruction.guest.raw().checked_add(4).ok_or(
                    DsrError::PcOverflow {
                        pc: instruction.guest.raw(),
                    },
                )?);
                emit_biased_exclusive_branch(
                    assembler,
                    entries,
                    recovery,
                    fallthrough,
                    cont,
                    scratch,
                    BiasedExclusiveResume::Exact,
                )?;
                emit_biased_exclusive_branch(
                    assembler,
                    entries,
                    recovery,
                    direct.target,
                    restore,
                    scratch,
                    BiasedExclusiveResume::Exact,
                )?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; =>cont
                );
                early_exit = Some((restore, tail, instruction.guest, direct.target));
            }
            _ => {
                return Err(DsrError::BlockPolicy(format!(
                    "unexpected action in fused biased exclusive region at guest PC 0x{:x}",
                    instruction.guest.raw()
                )));
            }
        }
    }

    let store_guest = plan
        .instructions
        .last()
        .map(|instruction| instruction.guest)
        .ok_or_else(|| {
            DsrError::BlockPolicy("fused biased exclusive region has no instructions".to_string())
        })?;
    let retry_pc = GuestVa(
        store_guest
            .raw()
            .checked_add(4)
            .ok_or(DsrError::PcOverflow {
                pc: store_guest.raw(),
            })?,
    );
    let InstAction::Direct(retry_direct) = super::decode::classify(exit.retry_word, retry_pc)?
    else {
        return Err(DsrError::BlockPolicy(format!(
            "fused biased exclusive region retry branch is not direct at guest PC 0x{:x}",
            retry_pc.raw()
        )));
    };
    let retry_resume = BiasedExclusiveResume::Retry;
    let relocated_retry = relocated_direct_word(exit.retry_word, retry_direct, None)?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        retry_pc,
        relocated_retry,
        scratch,
        retry_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.end,
        success_restore,
        scratch,
        BiasedExclusiveResume::Exact,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.start,
        region_top,
        scratch,
        BiasedExclusiveResume::Exact,
    )?;

    let restore_address = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | address;
    let restore_bias = 0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | bias;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>success_restore
    );
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.end,
        restore_address,
        scratch,
        BiasedExclusiveResume::Exact,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.end,
        restore_bias,
        scratch,
        BiasedExclusiveResume::Exact,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.end,
        success_tail,
        scratch,
        BiasedExclusiveResume::Exact,
    )?;

    if let Some((restore, tail, _, target)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>restore
        );
        emit_biased_exclusive_word(
            assembler,
            entries,
            recovery,
            target,
            CLREX_WORD,
            scratch,
            BiasedExclusiveResume::Exact,
        )?;
        emit_biased_exclusive_word(
            assembler,
            entries,
            recovery,
            target,
            restore_address,
            scratch,
            BiasedExclusiveResume::Exact,
        )?;
        emit_biased_exclusive_word(
            assembler,
            entries,
            recovery,
            target,
            restore_bias,
            scratch,
            BiasedExclusiveResume::Exact,
        )?;
        emit_biased_exclusive_branch(
            assembler,
            entries,
            recovery,
            target,
            tail,
            scratch,
            BiasedExclusiveResume::Exact,
        )?;
    }

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>slow_restore
    );
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        restore_address,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        exit.start,
        restore_bias,
        scratch,
        load_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        exit.start,
        slow_tail,
        scratch,
        load_resume,
    )?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>success_tail
    );
    emit_region_direct_exit(
        assembler,
        entries,
        direct_links,
        recovery,
        exit.end,
        retry_pc,
        exit.end,
        false,
        recording.as_deref_mut(),
    )?;
    if let Some((_, tail, branch_guest, target)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>tail
        );
        emit_region_direct_exit(
            assembler,
            entries,
            direct_links,
            recovery,
            target,
            branch_guest,
            target,
            false,
            recording.as_deref_mut(),
        )?;
    }
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>slow_tail
    );
    emit_gateway_exit(
        assembler,
        entries,
        exit.start,
        exit.fallback.resume,
        Some(exit.start),
        6,
        GatewayKind::Sensitive,
        recording.as_deref_mut(),
    )
}

/// Lower a fused exclusive region to native code. The block prologue has already
/// been emitted; this emits, in one straight-line block:
///   1. the region body (`BlockPlan::instructions` = load, straight-line
///      compare/ALU ops, an optional early-exit branch, store) VERBATIM -- the
///      exclusive load and store are byte-identical guest words with no context
///      store between them (Hazard A: a store between the pair clears the
///      monitor and livelocks the guest);
///   2. the retry branch, re-encoded so store-failure loops back to the load and
///      store-success leaves to `end` (both edges are post-store, so the monitor
///      is already cleared -- no CLREX);
///   3. one exit stub per leaving edge. The store-success edge takes a plain
///      direct exit; the compare-failure early-exit edge (if any) prefixes it
///      with CLREX because the store never ran and the load's reservation is
///      still live (Hazard B).
///
/// Direct mode keeps the established verbatim lowering. Biased mode uses the
/// separately tested scratch-based lowering only for plans whose structural
/// analysis supplied a safe two-register scratch plan.
#[allow(
    clippy::needless_option_as_deref,
    clippy::too_many_arguments,
    reason = "direct and biased exclusive lowering share the planned region payload"
)]
fn emit_exclusive_region(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    direct_links: &mut Vec<DirectLink>,
    recovery: &mut Vec<RecoveryEntry>,
    plan: &BlockPlan,
    exit: super::types::ExclusiveRegionExit,
    fusion: super::types::ExclusiveFusionSite,
    mode: EmitAddressMode,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    if let EmitAddressMode::Biased { host_bias } = mode {
        let scratch = fusion.biased_scratch.ok_or_else(|| {
            unsupported_action(
                plan,
                exit.start,
                exit.load_word,
                "biased exclusive region has no scratch plan",
            )
        })?;
        return emit_biased_exclusive_region(
            assembler,
            entries,
            direct_links,
            recovery,
            plan,
            exit,
            scratch,
            host_bias,
            recording.as_deref_mut(),
        );
    }

    let region_top = assembler.new_dynamic_label();
    let success_exit = assembler.new_dynamic_label();

    // The exclusive load is the region entry (and the retry target). Placing the
    // label here -- after the prologue, at the load -- means the retry edge
    // re-enters the load WITHOUT re-running the prologue's context stores, so no
    // memory access sits between the load and the store on any iteration.
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>region_top
    );

    // The single optional early-exit branch: (stub label, guest PC, target).
    let mut early_exit: Option<(dynasmrt::DynamicLabel, GuestVa, GuestVa)> = None;

    for instruction in &plan.instructions {
        match instruction.action {
            // The exclusive load and store, and any straight-line body op, are
            // emitted byte-identically. The planner has proved the base is a
            // plain GPR (not x18/x28) and that no operand touches x18/x28, so no
            // virtualization/spill is needed -- the ONLY sound lowering, since a
            // spill would be a memory access in the reservation window.
            InstAction::Memory(memory) => {
                emit_word(assembler, entries, instruction.guest, memory.word)?;
            }
            InstAction::Copy(word) => {
                emit_word(assembler, entries, instruction.guest, word)?;
            }
            // The compare-failure edge of a CAS. Re-encode it (taken -> +8) into
            // a two-branch trampoline: not-taken continues the region body,
            // taken jumps to the CLREX-then-exit stub emitted after the retry.
            InstAction::Direct(direct) => {
                let word = exit.early_exit_word.ok_or_else(|| {
                    DsrError::BlockPolicy(format!(
                        "fused exclusive region has a body branch but no early-exit encoding at guest PC 0x{:x}",
                        instruction.guest.raw()
                    ))
                })?;
                let stub = assembler.new_dynamic_label();
                let cont = assembler.new_dynamic_label();
                let relocated = relocated_direct_word(word, direct, None)?;
                emit_word(assembler, entries, instruction.guest, relocated)?;
                map_next(assembler, entries, instruction.guest)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; b =>cont
                );
                map_next(assembler, entries, instruction.guest)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; b =>stub
                );
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; =>cont
                );
                early_exit = Some((stub, instruction.guest, direct.target));
            }
            _ => {
                return Err(DsrError::BlockPolicy(format!(
                    "unexpected action in fused exclusive region at guest PC 0x{:x}",
                    instruction.guest.raw()
                )));
            }
        }
    }

    // The store is the last emitted instruction; the retry branch sits one
    // instruction past it (at `end - 4`).
    let store_guest = plan
        .instructions
        .last()
        .map(|instruction| instruction.guest)
        .ok_or_else(|| {
            DsrError::BlockPolicy("fused exclusive region has no instructions".to_string())
        })?;
    let retry_pc = GuestVa(
        store_guest
            .raw()
            .checked_add(4)
            .ok_or(DsrError::PcOverflow {
                pc: store_guest.raw(),
            })?,
    );

    // Re-encode the retry branch (taken -> +8): store-failure loops to the load,
    // store-success leaves to `end`. Both edges execute AFTER the store, whose
    // completion (success or failure) already cleared the monitor -- no CLREX.
    let InstAction::Direct(retry_direct) = super::decode::classify(exit.retry_word, retry_pc)?
    else {
        return Err(DsrError::BlockPolicy(format!(
            "fused exclusive region retry branch is not a direct branch at guest PC 0x{:x}",
            retry_pc.raw()
        )));
    };
    let relocated_retry = relocated_direct_word(exit.retry_word, retry_direct, None)?;
    emit_word(assembler, entries, retry_pc, relocated_retry)?;
    map_next(assembler, entries, retry_pc)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>success_exit
    );
    map_next(assembler, entries, retry_pc)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>region_top
    );

    // Store-success exit: the STXR completed and cleared the monitor, so no
    // CLREX. Mapped to the retry branch's PC so a kick re-evaluates it.
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>success_exit
    );
    emit_region_direct_exit(
        assembler,
        entries,
        direct_links,
        recovery,
        exit.end,
        retry_pc,
        exit.end,
        false,
        recording.as_deref_mut(),
    )?;

    // Compare-failure exit (if the region had an early-exit branch): the store
    // never ran, so the load's reservation is still live and MUST be cleared.
    if let Some((stub, branch_guest, target)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>stub
        );
        emit_region_direct_exit(
            assembler,
            entries,
            direct_links,
            recovery,
            target,
            branch_guest,
            target,
            true,
            recording.as_deref_mut(),
        )?;
    }

    Ok(())
}

#[allow(
    clippy::needless_option_as_deref,
    reason = "block lowering reborrows optional recording across independent emission paths"
)]
fn assemble_block_inner(
    plan: &BlockPlan,
    guard: Option<GenerationGuard>,
    mode: EmitAddressMode,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<AssembledBlock, DsrError> {
    let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
    let mut entries = Vec::with_capacity(plan.instructions.len() + 8);
    let mut direct_links = Vec::new();
    let mut recovery = Vec::new();
    let entry_marker = current_offset(&assembler)?;
    map_next(&assembler, &mut entries, plan.start)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str wzr, [x28, #1152]
    );
    recovery.push(RecoveryEntry {
        cache: entry_marker,
        action: RecoveryAction::Noop,
    });
    // x17 is the internal indirect-edge register. Its guest value is saved at
    // every block exit and restored before either the generation guard or the
    // first guest instruction executes.
    let restore_x17 = current_offset(&assembler)?;
    map_next(&assembler, &mut entries, plan.start)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #136]
    );
    recovery.push(RecoveryEntry {
        cache: restore_x17,
        action: RecoveryAction::RestoreGuestX17,
    });
    let stale = guard.map(|_| assembler.new_dynamic_label());
    if let (Some(guard), Some(stale)) = (guard, stale) {
        let guard_start = current_offset(&assembler)?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x16, [x28, #1120]
        );
        recovery.push(RecoveryEntry {
            cache: guard_start,
            action: RecoveryAction::Noop,
        });
        let save_x17 = current_offset(&assembler)?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, #1128]
        );
        recovery.push(RecoveryEntry {
            cache: save_x17,
            action: RecoveryAction::Noop,
        });
        let read_pstate = current_offset(&assembler)?;
        emit_word(
            &mut assembler,
            &mut entries,
            plan.start,
            0xd53b_4210, // mrs x16, nzcv
        )?;
        recovery.push(RecoveryEntry {
            cache: read_pstate,
            action: RecoveryAction::Noop,
        });
        let save_pstate = current_offset(&assembler)?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x16, [x28, #936]
        );
        recovery.push(RecoveryEntry {
            cache: save_pstate,
            action: RecoveryAction::RestoreGenerationGuardRegisters,
        });
        let guard_ready = current_offset(&assembler)?;
        match guard {
            GenerationGuard::Absolute { address, expected } => {
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    plan.start,
                    16,
                    MaterializedValue::Process(ProcessValue::GenerationAddress, address),
                    recording.as_deref_mut(),
                )?;
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldar x16, [x16]
                );
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    plan.start,
                    17,
                    MaterializedValue::Process(ProcessValue::GenerationExpected, expected.get()),
                    recording.as_deref_mut(),
                )?;
            }
            GenerationGuard::BindingIndex { index, .. } => {
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldr x16, [x28, super::gateway::CTX_GENERATION_BINDINGS]
                );
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    plan.start,
                    17,
                    MaterializedValue::Stable(u64::from(index)),
                    recording.as_deref_mut(),
                )?;
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; add x16, x16, x17, LSL #4
                );
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldp x16, x17, [x16]
                );
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldar x16, [x16]
                );
            }
        }
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; cmp x16, x17
        );
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; b.ne =>stale
        );
        // A direct-linked chain can enter the gateway from a different block
        // than the one that began this translated run. Publish this block's
        // generation so sensitive-exit metadata is resolved against the block
        // that actually produced the exit.
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, super::gateway::CTX_GENERATION]
        );
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x16, [x28, #936]
        );
        emit_word(
            &mut assembler,
            &mut entries,
            plan.start,
            0xd51b_4210, // msr nzcv, x16
        )?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x16, [x28, #1120]
        );
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x17, [x28, #1128]
        );
        let guard_end = current_offset(&assembler)?;
        for offset in (guard_ready.get()..guard_end.get()).step_by(4) {
            recovery.push(RecoveryEntry {
                cache: CacheOffset::published(offset),
                action: RecoveryAction::RestoreGenerationGuard,
            });
        }
    }
    if let PlannedExit::ExclusiveRegion { exit, fusion, .. } = plan.exit {
        // A fused exclusive region (LDXR/LDAXR .. STXR/STLXR CAS/RMW retry loop)
        // is lowered to native code that executes in-guest without a gateway
        // trap. It bypasses the generic body/exit path entirely because the
        // load and store MUST share one emitted block with no context store
        // between them (Hazard A) and every non-completing edge MUST clear the
        // exclusive monitor (Hazard B) -- neither of which the generic path can
        // express.
        emit_exclusive_region(
            &mut assembler,
            &mut entries,
            &mut direct_links,
            &mut recovery,
            plan,
            exit,
            fusion,
            mode,
            recording.as_deref_mut(),
        )?;
    } else {
        for instruction in &plan.instructions {
            let word = match instruction.action {
            InstAction::Copy(word) => word,
            // Direct register-based emission remains byte-identical; biased
            // mode materializes host addresses before the audited operation.
            InstAction::Memory(memory) => {
                if let EmitAddressMode::Biased { host_bias } = mode {
                    emit_biased_memory(
                        &mut assembler,
                        &mut entries,
                        plan,
                        instruction.guest,
                        memory,
                        host_bias,
                        &mut recovery,
                    )?;
                    continue;
                }
                match memory.virtualization {
                    super::types::MemoryVirtualization::None => {}
                    super::types::MemoryVirtualization::X18 => {
                        emit_virtualized_register(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            18,
                            144,
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::X28 => {
                        emit_virtualized_register(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            28,
                            224,
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::X18X28ReadOnly => {
                        emit_dual_virtual(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            None,
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::X18WriteX28Read => {
                        emit_dual_virtual(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            Some(18),
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::Unsupported => {
                        return Err(unsupported_action(
                            plan,
                            instruction.guest,
                            memory.word,
                            "unsupported memory virtualization",
                        ));
                    }
                }
                if memory.base == super::types::MemoryBase::VirtualX18 {
                    emit_virtualized_register(
                        &mut assembler,
                        &mut entries,
                        plan,
                        instruction.guest,
                        memory.word,
                        18,
                        144,
                        &mut recovery,
                    )?;
                    continue;
                }
                if memory.base == super::types::MemoryBase::VirtualX28 {
                    emit_virtualized_register(
                        &mut assembler,
                        &mut entries,
                        plan,
                        instruction.guest,
                        memory.word,
                        28,
                        224,
                        &mut recovery,
                    )?;
                    continue;
                }
                if let super::types::MemoryBase::Literal(target) = memory.base {
                    emit_pc_relative_literal(
                        &mut assembler,
                        &mut entries,
                        plan,
                        instruction.guest,
                        super::types::PcRelativeInst {
                            kind: if memory.op == bad64::Op::PRFM {
                                super::types::PcRelativeKind::LiteralPrefetch
                            } else {
                                super::types::PcRelativeKind::LiteralLoad
                            },
                            target,
                            destination: None,
                            word: memory.word,
                        },
                        MaterializedAddress::Guest(target),
                        &mut recovery,
                    )?;
                    continue;
                }
                memory.word
            }
            InstAction::VirtualizedX18 { word, .. } => {
                emit_virtualized_register(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    18,
                    144,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedX28 { word, .. } => {
                emit_virtualized_register(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    28,
                    224,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedX18X28ReadOnly { word, .. } => {
                emit_dual_virtual(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    None,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedX18WriteX28Read { word, .. } => {
                emit_dual_virtual(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    Some(18),
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedX28WriteX18Read { word, .. } => {
                emit_dual_virtual(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    Some(28),
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::PcRelative(relative)
                if matches!(
                    relative.kind,
                    super::types::PcRelativeKind::Adr | super::types::PcRelativeKind::Adrp
                ) =>
            {
                emit_pc_relative_address(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    relative,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::PcRelative(relative) => {
                emit_pc_relative_literal(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    relative,
                    MaterializedAddress::Guest(relative.target),
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::CounterRead(counter) => {
                let super::counter::HostCounterPlan::Inline { source, scale } =
                    super::counter::host_counter_plan()
                else {
                    return Err(DsrError::BlockPolicy(format!(
                        "non-inline counter plan reached emission at guest PC 0x{:x}",
                        instruction.guest.raw()
                    )));
                };
                emit_counter_read(
                    &mut assembler,
                    &mut entries,
                    &mut recovery,
                    instruction.guest,
                    counter,
                    source,
                    scale,
                )?;
                continue;
            }
            InstAction::Direct(_) => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    0,
                    "direct action",
                ));
            }
            InstAction::Indirect(_) => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    0,
                    "indirect action",
                ));
            }
            InstAction::Syscall { .. }
            | InstAction::Sensitive(_)
            // `plan.instructions` never contains this today: block.rs's
            // exclusive-region recogniser (Task 1 of the fusion plan) is not
            // yet wired into `plan_block`, and even once it is, the region's
            // load/store are represented as plain `InstAction::Memory`
            // entries in `instructions` (see `try_fuse_exclusive_region`),
            // not this variant. This arm exists only so the match stays
            // exhaustive against the `InstAction` type.
            | InstAction::ExclusiveRegion(_)
            | InstAction::Unsupported { .. } => {
                return Err(DsrError::BlockPolicy(format!(
                    "terminator appeared in DSR copy stream at guest PC 0x{:x}",
                    instruction.guest.raw()
                )));
            }
        };
            map_next(&assembler, &mut entries, instruction.guest)?;
            assembler.push_u32(word);
        }

        let exit_guest = plan.exit.guest_pc();
        map_next(&assembler, &mut entries, exit_guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, #136]
        );
        map_next(&assembler, &mut entries, exit_guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, #1128]
        );
        if let PlannedExit::Syscall { resume, .. } = plan.exit {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                resume,
                None,
                1,
                GatewayKind::Syscall,
                recording.as_deref_mut(),
            )?;
        } else if let PlannedExit::Direct { word, exit, .. } = plan.exit {
            if exit.kind == super::types::DirectKind::Call {
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    30,
                    MaterializedValue::Guest(exit.resume.raw()),
                    recording.as_deref_mut(),
                )?;
            }
            if matches!(
                exit.kind,
                super::types::DirectKind::Branch | super::types::DirectKind::Call
            ) {
                let slot = current_offset(&assembler)?;
                emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
                let stub_start = current_offset(&assembler)?;
                let (kind, committed_link) = if exit.kind == super::types::DirectKind::Call {
                    (DirectLinkKind::Call, Some(exit.resume.raw()))
                } else {
                    (DirectLinkKind::Branch, None)
                };
                emit_cached_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.target,
                    committed_link,
                    &mut recovery,
                    recording.as_deref_mut(),
                )?;
                direct_links.push(DirectLink {
                    slot,
                    source: exit_guest,
                    target: exit.target,
                    kind,
                    stub: DirectStubEnvelope {
                        start: stub_start,
                        end: current_offset(&assembler)?,
                    },
                });
            } else {
                let virtual_offset = exit
                    .register
                    .and_then(gpr_index)
                    .and_then(virtual_snapshot_offset);
                if let Some(offset) = virtual_offset {
                    emit_word(
                        &mut assembler,
                        &mut entries,
                        exit_guest,
                        0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | 18,
                    )?;
                }
                emit_word(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    relocated_direct_word(word, exit, virtual_offset.map(|_| 18))?,
                )?;
                let fall_slot = current_offset(&assembler)?;
                // `b +2` skips exactly the taken-branch word below to reach the
                // fall-through stub, which stays correct however long a stub is.
                emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0002)?;
                let taken_slot = current_offset(&assembler)?;
                // A LABEL, not a hardcoded displacement. This was
                // `0x1400_0012` -- "branch forward 18 instructions" --
                // which silently encoded the length of the fall-through
                // gateway stub emitted below it.
                let taken_stub = assembler.new_dynamic_label();
                map_next(&assembler, &mut entries, exit_guest)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; b =>taken_stub
                );
                let fall_stub_start = current_offset(&assembler)?;
                emit_cached_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.resume,
                    None,
                    &mut recovery,
                    recording.as_deref_mut(),
                )?;
                direct_links.push(DirectLink {
                    slot: fall_slot,
                    source: exit_guest,
                    target: exit.resume,
                    kind: DirectLinkKind::ConditionalFallthrough,
                    stub: DirectStubEnvelope {
                        start: fall_stub_start,
                        end: current_offset(&assembler)?,
                    },
                });
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; =>taken_stub
                );
                let taken_stub_start = current_offset(&assembler)?;
                emit_cached_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.target,
                    None,
                    &mut recovery,
                    recording.as_deref_mut(),
                )?;
                direct_links.push(DirectLink {
                    slot: taken_slot,
                    source: exit_guest,
                    target: exit.target,
                    kind: DirectLinkKind::ConditionalTaken,
                    stub: DirectStubEnvelope {
                        start: taken_stub_start,
                        end: current_offset(&assembler)?,
                    },
                });
            }
        } else if let PlannedExit::Indirect { exit, .. } = plan.exit {
            emit_indirect_exit(
                &mut assembler,
                &mut entries,
                plan,
                exit_guest,
                exit,
                &mut recovery,
                recording.as_deref_mut(),
            )?;
        } else if let PlannedExit::Sensitive { word, exit, .. } = plan.exit {
            if let EmitAddressMode::Biased { host_bias } = mode
                && exit.kind == super::types::SensitiveKind::DcZva
                && let Some(register) = exit.register
                && biased_dc_zva_base(register).is_some()
            {
                emit_biased_dc_zva(
                    &mut assembler,
                    &mut entries,
                    plan,
                    exit_guest,
                    word,
                    register,
                    host_bias,
                    &mut recovery,
                )?;
                emit_region_direct_exit(
                    &mut assembler,
                    &mut entries,
                    &mut direct_links,
                    &mut recovery,
                    exit.resume,
                    exit_guest,
                    exit.resume,
                    false,
                    recording.as_deref_mut(),
                )?;
            } else {
                emit_gateway_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit.resume,
                    Some(exit_guest),
                    6,
                    GatewayKind::Sensitive,
                    recording.as_deref_mut(),
                )?;
            }
        } else if let PlannedExit::Continue { target, .. } = plan.exit {
            let slot = current_offset(&assembler)?;
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
            let stub_start = current_offset(&assembler)?;
            emit_cached_direct_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit_guest,
                target,
                None,
                &mut recovery,
                recording.as_deref_mut(),
            )?;
            direct_links.push(DirectLink {
                slot,
                source: exit_guest,
                target,
                kind: DirectLinkKind::Continue,
                stub: DirectStubEnvelope {
                    start: stub_start,
                    end: current_offset(&assembler)?,
                },
            });
        } else if let PlannedExit::Unsupported { .. } = plan.exit {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit_guest,
                Some(exit_guest),
                7,
                GatewayKind::Unsupported,
                recording.as_deref_mut(),
            )?;
        } else {
            return Err(DsrError::BlockPolicy(
                "virtualized register action escaped the DSR copy stream".to_string(),
            ));
        }
    }
    if let Some(stale) = stale {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>stale
        );
        let stale_start = current_offset(&assembler)?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x16, [x28, #936]
        );
        emit_word(
            &mut assembler,
            &mut entries,
            plan.start,
            0xd51b_4210, // msr nzcv, x16
        )?;
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x16, [x28, #1120]
        );
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x17, [x28, #1128]
        );
        let stale_end = current_offset(&assembler)?;
        for offset in (stale_start.get()..stale_end.get()).step_by(4) {
            recovery.push(RecoveryEntry {
                cache: CacheOffset::published(offset),
                action: RecoveryAction::RestoreGenerationGuard,
            });
        }
        emit_gateway_exit(
            &mut assembler,
            &mut entries,
            plan.start,
            plan.start,
            Some(plan.start),
            2,
            GatewayKind::Direct,
            recording.as_deref_mut(),
        )?;
    }
    let bytes = assembler
        .finalize()
        .map_err(|error| DsrError::Assembler(error.to_string()))?;
    if !bytes.len().is_multiple_of(4) {
        return Err(DsrError::CachePolicy(format!(
            "dynasm emitted a non-instruction byte count: {}",
            bytes.len()
        )));
    }
    let words = bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect::<Vec<_>>();
    let map = InstructionMap::new(entries)?;
    Ok(AssembledBlock {
        words,
        map,
        direct_links,
        recovery,
    })
}

// ---------------------------------------------------------------------------
// Fault/kick recovery interpreters for the emitter's `RecoveryAction`s.
// Moved verbatim from the runtime's `dsr/mod.rs` (they are pure functions of
// the snapshot and this module's recovery metadata); the runtime re-imports
// them under the old `dsr::recover_rewrite_state` paths.
// ---------------------------------------------------------------------------

pub fn recovery_resume_pc(
    guest_pc: carrick_guest_mem::GuestVa,
    recovery: Option<RecoveryAction>,
) -> Result<u64, crate::types::DsrError> {
    if recovery.is_some_and(RecoveryAction::instruction_complete) {
        guest_pc.raw().checked_add(4).ok_or_else(|| {
            crate::types::DsrError::CachePolicy(
                "DSR completed-instruction resume PC overflow".to_string(),
            )
        })
    } else {
        Ok(guest_pc.raw())
    }
}

pub fn recover_rewrite_state(
    snapshot: &mut crate::snapshot::NativeUcontextSnapshot,
    action: RecoveryAction,
    saved_scratch: u64,
    saved_context_scratch: u64,
    saved_generation_pstate: u64,
    saved_indirect_x15: u64,
    saved_indirect_x30: u64,
) -> Result<(), crate::types::DsrError> {
    if let RecoveryAction::RestoreDirectBinding { committed_link, .. } = action {
        snapshot.x[15] = saved_indirect_x15;
        snapshot.x[16] = saved_scratch;
        snapshot.x[17] = saved_context_scratch;
        snapshot.x[30] = saved_indirect_x30;
        snapshot.pstate = saved_generation_pstate;
        if let Some(committed_link) = committed_link {
            snapshot.x[30] = committed_link;
        }
        return Ok(());
    }
    if let RecoveryAction::RecoverCounterRead(recovery) = action {
        let committed = recovery
            .instruction_complete
            .then_some(recovery.committed_scratch_destination)
            .flatten()
            .map(CounterScratchDestination::register);
        for (register, saved) in [
            (15_u32, saved_indirect_x15),
            (16, saved_scratch),
            (17, saved_context_scratch),
        ] {
            if committed == Some(register) {
                continue;
            }
            let index = usize::try_from(register).map_err(|_| {
                crate::types::DsrError::CachePolicy("counter scratch index overflow".to_string())
            })?;
            snapshot.x[index] = saved;
        }
        return Ok(());
    }
    if let RecoveryAction::RecoverBiasedExclusive(recovery) = action {
        let address = usize::try_from(recovery.scratch.address.index()).map_err(|_| {
            crate::types::DsrError::CachePolicy(
                "biased exclusive address scratch overflow".to_string(),
            )
        })?;
        let bias = usize::try_from(recovery.scratch.bias.index()).map_err(|_| {
            crate::types::DsrError::CachePolicy(
                "biased exclusive bias scratch overflow".to_string(),
            )
        })?;
        snapshot.x[address] = saved_scratch;
        snapshot.x[bias] = saved_context_scratch;
        return Ok(());
    }
    if let RecoveryAction::RecoverBiasedMemory(recovery) = action {
        let saved_values = [
            saved_scratch,
            saved_context_scratch,
            saved_indirect_x15,
            saved_indirect_x30,
        ];
        let base_value = if recovery.commit_base {
            let index = usize::try_from(recovery.base_scratch).map_err(|_| {
                crate::types::DsrError::CachePolicy(
                    "biased base scratch index overflow".to_string(),
                )
            })?;
            let current = snapshot.x.get(index).copied().ok_or_else(|| {
                crate::types::DsrError::CachePolicy(format!(
                    "biased base scratch x{} is outside snapshot",
                    recovery.base_scratch
                ))
            })?;
            Some(match recovery.base_coordinate {
                // AArch64 pre/post-index writeback is modulo 2^64. The memory
                // access used a valid translated address before the update;
                // only the architectural result may wrap below the bias.
                BiasedBaseCoordinate::Host => current.wrapping_sub(recovery.host_bias.get()),
                BiasedBaseCoordinate::Guest => current,
            })
        } else {
            None
        };
        let virtual_x18 = recovery
            .virtual_x18_scratch
            .map(|register| {
                usize::try_from(register)
                    .ok()
                    .and_then(|index| snapshot.x.get(index).copied())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "biased virtual x18 scratch x{register} is outside snapshot"
                        ))
                    })
            })
            .transpose()?;
        let virtual_x28 = recovery
            .virtual_x28_scratch
            .map(|register| {
                usize::try_from(register)
                    .ok()
                    .and_then(|index| snapshot.x.get(index).copied())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "biased virtual x28 scratch x{register} is outside snapshot"
                        ))
                    })
            })
            .transpose()?;
        let scratch_count = usize::from(recovery.scratch_count);
        if scratch_count > recovery.scratch_registers.len() {
            return Err(crate::types::DsrError::CachePolicy(format!(
                "biased recovery scratch count {scratch_count} exceeds capacity"
            )));
        }
        for (register, value) in recovery.scratch_registers[..scratch_count]
            .iter()
            .copied()
            .zip(saved_values)
        {
            let index = usize::try_from(register).map_err(|_| {
                crate::types::DsrError::CachePolicy("biased scratch index overflow".to_string())
            })?;
            let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                crate::types::DsrError::CachePolicy(format!(
                    "biased scratch x{register} is outside snapshot"
                ))
            })?;
            *slot = value;
        }
        if let Some(value) = virtual_x18 {
            snapshot.x[18] = value;
        }
        if let Some(value) = virtual_x28 {
            snapshot.x[28] = value;
        }
        if let Some(value) = base_value {
            match recovery.base {
                BiasedBase::Register(register) => {
                    let index = usize::try_from(register).map_err(|_| {
                        crate::types::DsrError::CachePolicy(
                            "biased guest base index overflow".to_string(),
                        )
                    })?;
                    let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "biased guest base x{register} is outside snapshot"
                        ))
                    })?;
                    *slot = value;
                }
                BiasedBase::StackPointer => snapshot.sp = value,
                BiasedBase::VirtualX18 => snapshot.x[18] = value,
                BiasedBase::VirtualX28 => snapshot.x[28] = value,
                BiasedBase::None => {
                    return Err(crate::types::DsrError::CachePolicy(
                        "biased recovery attempted to commit a missing base".to_string(),
                    ));
                }
            }
        }
        return Ok(());
    }
    let (register, context_register) = match action {
        RecoveryAction::Noop => return Ok(()),
        RecoveryAction::RestoreGuestX17 => {
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        RecoveryAction::RestoreGenerationGuardRegisters => {
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        RecoveryAction::RestoreGenerationGuard => {
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            snapshot.pstate = saved_generation_pstate;
            return Ok(());
        }
        RecoveryAction::RestoreIndirectRegisters => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        RecoveryAction::RestoreIndirectResolver => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[16] = saved_scratch;
            snapshot.x[17] = saved_context_scratch;
            snapshot.x[30] = saved_indirect_x30;
            snapshot.pstate = saved_generation_pstate;
            return Ok(());
        }
        RecoveryAction::RestoreDualVirtualReadOnly {
            x18_scratch,
            x28_scratch,
            context_scratch,
        }
        | RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
            x18_scratch,
            x28_scratch,
            context_scratch,
        } => {
            for (register, value) in [
                (x18_scratch, saved_indirect_x15),
                (x28_scratch, saved_scratch),
                (context_scratch, saved_context_scratch),
            ] {
                let index = usize::try_from(register).map_err(|_| {
                    crate::types::DsrError::CachePolicy(
                        "dual virtual scratch index overflow".to_string(),
                    )
                })?;
                let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                    crate::types::DsrError::CachePolicy(format!(
                        "dual virtual scratch x{register} is outside snapshot"
                    ))
                })?;
                *slot = value;
            }
            return Ok(());
        }
        RecoveryAction::CommitDualVirtualAndRestore {
            x18_scratch,
            x28_scratch,
            context_scratch,
            virtual_register,
            virtual_scratch,
        } => {
            let virtual_scratch_index = usize::try_from(virtual_scratch).map_err(|_| {
                crate::types::DsrError::CachePolicy(
                    "dual virtual result index overflow".to_string(),
                )
            })?;
            let value = snapshot
                .x
                .get(virtual_scratch_index)
                .copied()
                .ok_or_else(|| {
                    crate::types::DsrError::CachePolicy(format!(
                        "dual virtual result x{virtual_scratch} is outside snapshot"
                    ))
                })?;
            let virtual_index = usize::try_from(virtual_register).map_err(|_| {
                crate::types::DsrError::CachePolicy("dual virtual destination overflow".to_string())
            })?;
            let virtual_slot = snapshot.x.get_mut(virtual_index).ok_or_else(|| {
                crate::types::DsrError::CachePolicy(format!(
                    "dual virtual destination x{virtual_register} is outside snapshot"
                ))
            })?;
            *virtual_slot = value;
            for (register, value) in [
                (x18_scratch, saved_indirect_x15),
                (x28_scratch, saved_scratch),
                (context_scratch, saved_context_scratch),
            ] {
                let index = usize::try_from(register).map_err(|_| {
                    crate::types::DsrError::CachePolicy(
                        "dual virtual scratch index overflow".to_string(),
                    )
                })?;
                let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                    crate::types::DsrError::CachePolicy(format!(
                        "dual virtual scratch x{register} is outside snapshot"
                    ))
                })?;
                *slot = value;
            }
            return Ok(());
        }
        RecoveryAction::RestoreScratch { register }
        | RecoveryAction::RestoreScratchInvalidBiasedLiteral { register }
        | RecoveryAction::RestoreScratchCompleted { register }
        | RecoveryAction::CommitVirtualizedAndRestoreScratch { register, .. } => (register, None),
        RecoveryAction::RestoreScratchAndContext {
            register,
            context_register,
        }
        | RecoveryAction::RestoreScratchAndContextCompleted {
            register,
            context_register,
        }
        | RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            register,
            context_register,
            ..
        } => (register, Some(context_register)),
        RecoveryAction::RecoverBiasedMemory(_) => {
            return Err(crate::types::DsrError::CachePolicy(
                "biased recovery escaped its typed handler".to_string(),
            ));
        }
        RecoveryAction::RecoverBiasedExclusive(_) => {
            return Err(crate::types::DsrError::CachePolicy(
                "biased exclusive recovery escaped its typed handler".to_string(),
            ));
        }
        RecoveryAction::RecoverCounterRead(_) => {
            return Err(crate::types::DsrError::CachePolicy(
                "counter recovery escaped its typed handler".to_string(),
            ));
        }
        RecoveryAction::RestoreDirectBinding { .. } => {
            return Err(crate::types::DsrError::CachePolicy(
                "direct-binding recovery escaped its typed handler".to_string(),
            ));
        }
    };
    let index = usize::try_from(register).map_err(|_| {
        crate::types::DsrError::CachePolicy("rewrite scratch index overflow".to_string())
    })?;
    let current = snapshot.x.get(index).copied().ok_or_else(|| {
        crate::types::DsrError::CachePolicy(format!(
            "rewrite scratch x{register} is outside snapshot"
        ))
    })?;
    let virtual_register = match action {
        RecoveryAction::CommitVirtualizedAndRestoreScratch {
            virtual_register, ..
        }
        | RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
            virtual_register, ..
        } => Some(virtual_register),
        _ => None,
    };
    if let Some(virtual_register) = virtual_register {
        let virtual_index = usize::try_from(virtual_register).map_err(|_| {
            crate::types::DsrError::CachePolicy("virtual register index overflow".to_string())
        })?;
        let slot = snapshot.x.get_mut(virtual_index).ok_or_else(|| {
            crate::types::DsrError::CachePolicy(format!(
                "virtual register x{virtual_register} is outside snapshot"
            ))
        })?;
        *slot = current;
    }
    snapshot.x[index] = saved_scratch;
    if let Some(context_register) = context_register {
        let context_index = usize::try_from(context_register).map_err(|_| {
            crate::types::DsrError::CachePolicy(
                "rewrite context scratch index overflow".to_string(),
            )
        })?;
        let slot = snapshot.x.get_mut(context_index).ok_or_else(|| {
            crate::types::DsrError::CachePolicy(format!(
                "rewrite context scratch x{context_register} is outside snapshot"
            ))
        })?;
        *slot = saved_context_scratch;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::block::PlannedInst;
    use super::super::types::{
        CodeGeneration, CounterDestination, CounterRead, DirectExit, DirectKind,
    };
    use super::*;

    fn copy_plan() -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x400c),
            generation: CodeGeneration::INITIAL,
            instructions: vec![
                PlannedInst {
                    guest: GuestVa(0x4000),
                    action: InstAction::Copy(0xd503_201f),
                },
                PlannedInst {
                    guest: GuestVa(0x4004),
                    action: InstAction::Copy(0x9100_0400),
                },
            ],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4008),
                resume: GuestVa(0x400c),
            },
        }
    }

    #[test]
    fn instruction_map_releases_owned_entries_without_cloning() {
        let entries = vec![
            PcMapEntry {
                guest: GuestVa(0x4000),
                cache: CacheOffset::published(0),
            },
            PcMapEntry {
                guest: GuestVa(0x4004),
                cache: CacheOffset::published(4),
            },
        ];
        let map = InstructionMap::new(entries.clone()).expect("build instruction map");
        assert_eq!(map.into_entries(), entries);
    }

    #[test]
    fn instruction_map_rejects_non_monotonic_cache_offsets() {
        let error = InstructionMap::new(vec![
            PcMapEntry {
                guest: GuestVa(0x4000),
                cache: CacheOffset::published(4),
            },
            PcMapEntry {
                guest: GuestVa(0x4004),
                cache: CacheOffset::published(0),
            },
        ])
        .expect_err("out-of-order offsets must be rejected");
        assert!(error.to_string().contains("non-monotonic cache offsets"));
    }

    #[derive(Clone, Copy)]
    struct ExpectedDirectLink {
        source: GuestVa,
        target: GuestVa,
        kind: DirectLinkKind,
        slot: u32,
        stub_start: u32,
        stub_end: u32,
        committed_link: Option<u64>,
    }

    fn direct_plan(exit: PlannedExit) -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4004),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit,
        }
    }

    fn assert_direct_links(
        case: &str,
        links: &[DirectLink],
        recovery: &[RecoveryEntry],
        expected: &[ExpectedDirectLink],
    ) {
        assert_eq!(links.len(), expected.len(), "{case}: direct-link count");
        for (link, expected) in links.iter().zip(expected) {
            assert_eq!(link.source, expected.source, "{case}: source");
            assert_eq!(link.target, expected.target, "{case}: target");
            assert_eq!(link.kind, expected.kind, "{case}: kind");
            assert_eq!(link.slot.get(), expected.slot, "{case}: slot");
            assert_eq!(
                link.stub,
                DirectStubEnvelope {
                    start: CacheOffset::published(expected.stub_start),
                    end: CacheOffset::published(expected.stub_end),
                },
                "{case}: stub envelope"
            );
            assert!(
                link.stub.start.get() < link.stub.end.get(),
                "{case}: stub envelope must be nonempty"
            );
            for offset in (link.stub.start.get()..link.stub.end.get()).step_by(4) {
                let actions = recovery
                    .iter()
                    .filter(|entry| entry.cache.get() == offset)
                    .map(|entry| entry.action)
                    .collect::<Vec<_>>();
                assert_eq!(
                    actions.len(),
                    1,
                    "{case}: offset {offset} must have exactly one recovery action"
                );
                assert!(
                    matches!(
                        actions[0],
                        RecoveryAction::RestoreDirectBinding {
                            phase: DirectBindingRecoveryPhase::ScratchCapture
                                | DirectBindingRecoveryPhase::CellAddress
                                | DirectBindingRecoveryPhase::TargetAcquire
                                | DirectBindingRecoveryPhase::AuthorityValidate
                                | DirectBindingRecoveryPhase::AuthorityInstall
                                | DirectBindingRecoveryPhase::ArchitecturalRestore
                                | DirectBindingRecoveryPhase::FinalBranch
                                | DirectBindingRecoveryPhase::MissExit,
                            committed_link,
                        } if committed_link == expected.committed_link
                    ),
                    "{case}: offset {offset} must declare a direct-binding recovery phase"
                );
            }
        }
    }

    #[test]
    fn direct_edges_record_exact_identity_and_recovery_envelopes() {
        let branch = direct_plan(PlannedExit::Direct {
            guest: GuestVa(0x4000),
            word: 0x1400_0400,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0x5000),
                resume: GuestVa(0x4004),
                condition: None,
                register: None,
                bit: None,
            },
        });
        let call = direct_plan(PlannedExit::Direct {
            guest: GuestVa(0x4000),
            word: 0x9400_0400,
            exit: DirectExit {
                kind: DirectKind::Call,
                target: GuestVa(0x5000),
                resume: GuestVa(0x4004),
                condition: None,
                register: None,
                bit: None,
            },
        });
        let conditional = direct_plan(PlannedExit::Direct {
            guest: GuestVa(0x4000),
            word: 0x5400_8000,
            exit: DirectExit {
                kind: DirectKind::Conditional,
                target: GuestVa(0x5000),
                resume: GuestVa(0x4004),
                condition: Some(bad64::Condition::EQ),
                register: None,
                bit: None,
            },
        });
        let continuation = direct_plan(PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: super::super::block::BlockLimit::InstructionLimit,
        });

        let cases = [
            (
                "branch",
                assemble_block_inner(&branch, None, EmitAddressMode::Direct, None)
                    .expect("assemble branch"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x5000),
                    kind: DirectLinkKind::Branch,
                    slot: 16,
                    stub_start: 20,
                    stub_end: 276,
                    committed_link: None,
                }],
            ),
            (
                "call",
                assemble_block_inner(&call, None, EmitAddressMode::Direct, None)
                    .expect("assemble call"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x5000),
                    kind: DirectLinkKind::Call,
                    slot: 32,
                    stub_start: 36,
                    stub_end: 292,
                    committed_link: Some(0x4004),
                }],
            ),
            (
                "conditional",
                assemble_block_inner(&conditional, None, EmitAddressMode::Direct, None)
                    .expect("assemble conditional"),
                vec![
                    ExpectedDirectLink {
                        source: GuestVa(0x4000),
                        target: GuestVa(0x4004),
                        kind: DirectLinkKind::ConditionalFallthrough,
                        slot: 20,
                        stub_start: 28,
                        stub_end: 284,
                        committed_link: None,
                    },
                    ExpectedDirectLink {
                        source: GuestVa(0x4000),
                        target: GuestVa(0x5000),
                        kind: DirectLinkKind::ConditionalTaken,
                        slot: 24,
                        stub_start: 284,
                        stub_end: 540,
                        committed_link: None,
                    },
                ],
            ),
            (
                "continue",
                assemble_block_inner(&continuation, None, EmitAddressMode::Direct, None)
                    .expect("assemble continuation"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4004),
                    target: GuestVa(0x4004),
                    kind: DirectLinkKind::Continue,
                    slot: 16,
                    stub_start: 20,
                    stub_end: 276,
                    committed_link: None,
                }],
            ),
        ];
        for (case, assembled, expected) in cases {
            assert_direct_links(
                case,
                &assembled.direct_links,
                &assembled.recovery,
                &expected,
            );
        }

        let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
        let mut entries = Vec::new();
        let mut direct_links = Vec::new();
        let mut recovery = Vec::new();
        emit_region_direct_exit(
            &mut assembler,
            &mut entries,
            &mut direct_links,
            &mut recovery,
            GuestVa(0x7010),
            GuestVa(0x7008),
            GuestVa(0x7010),
            false,
            None,
        )
        .expect("emit fused-exclusive continuation");
        let _ = assembler
            .finalize()
            .expect("finalize fused-exclusive continuation");
        assert_direct_links(
            "fused-exclusive continuation",
            &direct_links,
            &recovery,
            &[ExpectedDirectLink {
                source: GuestVa(0x7008),
                target: GuestVa(0x7010),
                kind: DirectLinkKind::Continue,
                slot: 8,
                stub_start: 12,
                stub_end: 268,
                committed_link: None,
            }],
        );
    }

    #[test]
    fn direct_binding_recovery_preserves_a_committed_call_link() {
        let committed_link = 0x5004;
        let mut snapshot = crate::snapshot::NativeUcontextSnapshot::default();
        snapshot.x[15] = 0xdead_0015;
        snapshot.x[16] = 0xdead_0016;
        snapshot.x[17] = 0xdead_0017;
        snapshot.x[30] = 0xdead_0030;
        snapshot.pstate = 0xdead_0000;

        recover_rewrite_state(
            &mut snapshot,
            RecoveryAction::RestoreDirectBinding {
                phase: DirectBindingRecoveryPhase::FinalBranch,
                committed_link: Some(committed_link),
            },
            0x16,
            0x17,
            0x6000_0000,
            0x15,
            0x30,
        )
        .expect("recover direct-binding preamble");

        assert_eq!(snapshot.x[15], 0x15);
        assert_eq!(snapshot.x[16], 0x16);
        assert_eq!(snapshot.x[17], 0x17);
        assert_eq!(snapshot.x[30], committed_link);
        assert_eq!(snapshot.pstate, 0x6000_0000);
    }

    #[test]
    fn dsr_virtual_counter_mode_one_emits_inline_machine_code() {
        let guest = GuestVa(0x3f00);
        let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
        let mut entries = Vec::new();
        let mut recovery = Vec::new();
        let scale =
            super::super::counter::CounterScale::new(1, 1).expect("identity mode-one scale");

        emit_counter_read(
            &mut assembler,
            &mut entries,
            &mut recovery,
            guest,
            CounterRead {
                destination: CounterDestination::Gpr(2),
            },
            super::super::counter::HostCounterSource::Cntvct,
            scale,
        )
        .expect("emit injected mode-one counter");
        let bytes = assembler.finalize().expect("finalize mode-one counter");
        let words = bytes
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect::<Vec<_>>();

        assert_eq!(entries.len(), words.len());
        assert!(entries.iter().all(|entry| entry.guest == guest));
        assert!(
            words.contains(
                &super::super::counter::counter_word(
                    super::super::counter::HostCounterSource::Cntvct,
                    17,
                )
                .expect("mode-one counter word")
            )
        );
        assert!(
            recovery
                .iter()
                .any(|entry| matches!(entry.action, RecoveryAction::RecoverCounterRead(_)))
        );
    }
}
