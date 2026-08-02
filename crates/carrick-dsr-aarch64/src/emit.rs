#![allow(dead_code)]

use std::sync::atomic::AtomicU64;

use carrick_guest_mem::{GuestVa, HostVa};
use dynasmrt::{DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation};

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
    /// Offset of the trusted second entry point: past the generation guard,
    /// at the words that publish this block's generation and reload guest
    /// x17. Present only on private (`Absolute`-guarded, unrecorded) blocks;
    /// patched direct links may target it because eager link severing
    /// (Phase 2a) now invalidates links when their target's page bumps.
    trusted_entry: Option<CacheOffset>,
}

struct AssembledBlock {
    instruction_bytes: Vec<u8>,
    // Existing structural emitter tests inspect words extensively. Preserve
    // that view only in this crate's test build; production must not recreate
    // the staging allocation this change removes.
    #[cfg(test)]
    words: Vec<u32>,
    map: InstructionMap,
    direct_links: Vec<DirectLink>,
    recovery: Vec<RecoveryEntry>,
    trusted_entry: Option<CacheOffset>,
}

fn direct_instruction_bytes_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

/// Publish dynasm's byte stream directly by default. The old `Vec<u32>`
/// staging allocation remains a same-binary control arm, selected only with
/// `CARRICK_DSR_DIRECT_BYTES=0`.
fn direct_instruction_bytes_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        direct_instruction_bytes_enabled_from(
            std::env::var_os("CARRICK_DSR_DIRECT_BYTES").as_deref(),
        )
    })
}

impl AssembledBlock {
    /// Materialize host-endian words only for artifact recording and tests.
    /// The production private-cache path publishes `instruction_bytes`
    /// directly and therefore avoids this allocation and full-block copy.
    fn instruction_words(&self) -> Vec<u32> {
        self.instruction_bytes
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect()
    }

    fn publish(self, cache: &mut TranslationCache) -> Result<EmittedBlock, DsrError> {
        let mut writer = cache.begin_write(self.instruction_bytes.len())?;
        if direct_instruction_bytes_enabled() {
            writer.write_instruction_bytes(&self.instruction_bytes)?;
        } else {
            let words = self.instruction_words();
            writer.write_words(&words)?;
        }
        let code = writer.publish()?;
        Ok(EmittedBlock {
            code,
            map: self.map,
            direct_links: self.direct_links,
            recovery: self.recovery,
            trusted_entry: self.trusted_entry,
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

/// Words in a binding-install trampoline: a four-word `movz`/`movk` chain, the
/// context store, and the branch to the shared block.
pub const BINDING_INSTALL_TRAMPOLINE_WORDS: usize = 6;

/// The five words that install `bindings` as the context's generation-binding
/// table. The caller appends the sixth word, a `b` to the shared block.
///
/// A loaded unit's block guards with `GenerationGuard::BindingIndex`, which
/// reads the table from `CTX_GENERATION_BINDINGS`. Only the gateway installs
/// that, so a direct branch from a private block would read whatever the
/// private entry left there. Supplying it at ENTRY cannot work -- a context
/// holds one pointer while a private context reaches blocks from N units -- so
/// it is installed here, at the EDGE, where the target's unit is statically
/// known.
///
/// `x17` is dead at an edge: the target's own guard prologue clobbers it before
/// any use.
pub fn binding_install_prologue(bindings: u64) -> [u32; BINDING_INSTALL_TRAMPOLINE_WORDS - 1] {
    let halfword = |shift: u32| u32::from(((bindings >> shift) & 0xffff) as u16) << 5;
    [
        0xd280_0011 | halfword(0),  // movz x17, bindings[15:0]
        0xf2a0_0011 | halfword(16), // movk x17, bindings[31:16], lsl #16
        0xf2c0_0011 | halfword(32), // movk x17, bindings[47:32], lsl #32
        0xf2e0_0011 | halfword(48), // movk x17, bindings[63:48], lsl #48
        // str x17, [x28, #CTX_GENERATION_BINDINGS]
        0xf900_0000 | ((super::gateway::CTX_GENERATION_BINDINGS / 8) << 10) | (28 << 5) | 17,
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    Noop,
    RestoreGuestX17,
    RestoreGenerationGuardRegisters,
    RestoreGenerationGuard,
    RestoreIndirectRegisters,
    RestoreIndirectResolver,
    /// The lean indirect exit's hot path: only x15 (slot 1160) is spilled and
    /// x17's guest value is authoritative in slot 1128 (universal exit tail).
    /// The probe is flag-free and never touches x16 or x30, so recovery
    /// restores exactly x15 and x17; `instruction_complete` stays false.
    RestoreIndirectLean,
    /// `RestoreIndirectLean` for a `blr` exit, whose link materialization
    /// clobbers x30 after the up-front spill to slot 1168: restores x15, x17,
    /// and x30.
    RestoreIndirectLeanCall,
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
    /// Both virtualized registers are written by the instruction and neither
    /// has been committed yet. Recorded at the FIRST of the two commit stores;
    /// the second store's own action commits only what remains, because the
    /// first store already wrote its context slot (which is the snapshot slot).
    CommitDualVirtualPairAndRestore {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
        first_register: u32,
        second_register: u32,
    },
    /// The reserved-resident virtualization template's commit store: the
    /// rewritten word has executed and its result for the virtualized
    /// register is in physical x19 (`gateway::RESERVED_SCRATCH`), which the
    /// signal handler preserves as `physical_reserved`. Recovery finishes the
    /// commit into the snapshot; the instruction is complete.
    CommitReservedResident {
        virtual_register: u32,
    },
    RecoverCounterRead(CounterReadRecovery),
    RecoverBiasedMemory(BiasedMemoryRecovery),
    RecoverBiasedExclusive(BiasedExclusiveRecovery),
    RestoreDirectBinding {
        phase: DirectBindingRecoveryPhase,
        capture_progress: DirectBindingCaptureProgress,
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
pub enum DirectBindingCaptureProgress {
    None,
    X15,
    X15X16,
    X15X16X30,
    Complete,
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
            | Self::CommitDualVirtualAndRestore { .. }
            | Self::CommitDualVirtualPairAndRestore { .. }
            | Self::CommitReservedResident { .. } => true,
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
    VirtualReserved,
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
    /// Set while the rewrite scratch holds the guest value of
    /// `gateway::RESERVED_SCRATCH`, so recovery commits it back to the
    /// register's context slot instead of leaving it in the scratch.
    pub virtual_reserved_scratch: Option<u32>,
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
enum DirectExitEmissionPolicy {
    PrivateGateway,
    PortableUnitAuthority,
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
            // Artifact-loaded blocks are shared-unit material; they keep
            // their guards and never expose a trusted entry.
            trusted_entry: None,
        })
    }

    /// Trusted second entry point past the generation guard, when this block
    /// has one (private Absolute-guarded blocks only).
    pub const fn trusted_entry(&self) -> Option<CacheOffset> {
        self.trusted_entry
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

/// How many `movz`/`movk` words a guest PC materialization occupies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuestPcWidth {
    /// Four words regardless of value, for a site whose shape is validated.
    Fixed,
    /// Only the halfwords the value needs.
    Narrow,
}

/// Materialize a NON-relocated guest PC in as few `movz`/`movk` words as allowed.
///
/// `emit_mov_u64` is deliberately fixed-width because a `MaterializedValue::Process`
/// site is rewritten in place later and the relocator expects four halfwords. The
/// values a gateway exit stores -- the guest target and source PCs -- are
/// `MaterializedValue::Guest`, which `record_mov_wide` skips entirely and nothing
/// ever rewrites, so they only need enough halfwords to hold the value.
///
/// This is the single largest emitted class: `dsr:x17-materialize` measured 29.1%
/// of ALL emitted words, and guest addresses on this workload occupy two to three
/// halfwords rather than four.
///
/// Restricted to the PRIVATE gateway exit on purpose. The cell-based
/// `emit_cached_direct_exit` path has its shape validated at fixed word offsets by
/// `rewrite_direct_binding_stub`, and narrowing there breaks the sidecar rewrite --
/// measured: 11 tests, all of them `sidecar_*`/`direct_binding_*`.
fn emit_guest_pc(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    register: u32,
    value: u64,
    width: GuestPcWidth,
) -> Result<(), DsrError> {
    // From halfword 0 upward so the leading instruction is always the `movz`
    // that zeroes the register; the rest are `movk`.
    let halfwords = match width {
        GuestPcWidth::Fixed => 4,
        GuestPcWidth::Narrow => 64_u32
            .saturating_sub(value.leading_zeros())
            .div_ceil(16)
            .max(1),
    };
    for halfword in 0..halfwords {
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

/// Context byte offset holding the guest value of a host-owned register, or
/// `None` for the ordinary guest registers that live in the physical file.
const fn virtual_snapshot_offset(register: u32) -> Option<u32> {
    match register {
        18 => Some(144),
        28 => Some(224),
        crate::gateway::RESERVED_SCRATCH => Some(crate::gateway::CTX_GUEST_RESERVED_SCRATCH),
        _ => None,
    }
}

/// `(register, context slot)` for the reserved address scratch.
const fn reserved_virtual_slot() -> (u32, u32) {
    (
        crate::gateway::RESERVED_SCRATCH,
        crate::gateway::CTX_GUEST_RESERVED_SCRATCH,
    )
}

/// `(register, context slot)` for a host-owned register, or a typed
/// unsupported-action error if the register has no slot.
fn virtual_slot(
    plan: &BlockPlan,
    guest: GuestVa,
    word: u32,
    register: u32,
) -> Result<(u32, u32), DsrError> {
    virtual_snapshot_offset(register)
        .map(|offset| (register, offset))
        .ok_or_else(|| unsupported_action(plan, guest, word, "virtualized register has no slot"))
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
    // Retained for signature stability and future materializations: this stub's
    // only wide values are guest PCs, which `record_mov_wide` skips because they
    // are never relocated, so there is nothing here to record today.
    _recording: Option<&mut ArtifactRecording>,
    // WIDE when this stub is embedded in `emit_cached_direct_exit`'s sidecar,
    // whose instruction shape `rewrite_direct_binding_stub` validates at fixed
    // word offsets; NARROW for a standalone private exit, where nothing pins the
    // layout.
    width: GuestPcWidth,
) -> Result<(), DsrError> {
    emit_guest_pc(assembler, entries, guest, 17, target.raw(), width)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );
    if let Some(source) = source {
        emit_guest_pc(assembler, entries, guest, 17, source.raw(), width)?;
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

/// Record `action` for every emitted word in `[start, end)`.
fn record_recovery_range(
    recovery: &mut Vec<RecoveryEntry>,
    start: CacheOffset,
    end: CacheOffset,
    action: RecoveryAction,
) {
    for offset in (start.get()..end.get()).step_by(4) {
        recovery.push(RecoveryEntry {
            cache: CacheOffset::published(offset),
            action,
        });
    }
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
    let link = (exit.kind == super::types::IndirectKind::Call).then_some(exit.resume);
    // The universal exit tail already committed guest x17 to slots 136 and
    // 1128, so physical x17 is free scratch, and physical x19
    // (`gateway::RESERVED_SCRATCH`) is carrick's for the whole of translated
    // execution — no spill or restore for either. The hot path spills exactly
    // ONE guest register, x15 (the probe pointer), plus x30 for a `blr`
    // (whose link materialization clobbers it), and its probe compares with
    // EOR/CBZ so guest NZCV is architecturally untouched end to end.
    let lean_action = if link.is_some() {
        RecoveryAction::RestoreIndirectLeanCall
    } else {
        RecoveryAction::RestoreIndirectLean
    };
    // The x15 spill carries no recovery: nothing is clobbered before it
    // retires, and slot 1160 only becomes authoritative once it does.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, #1160]
    );
    if link.is_some() {
        // x30 still holds the guest value and slot 1168 is not yet written,
        // so this word is covered by the x15/x17-only action.
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreIndirectLean,
        });
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x30, [x28, #1168]
        );
    }
    let lean_start = current_offset(assembler)?;
    if let Some(offset) = virtual_snapshot_offset(register) {
        // A virtualized target (guest x18/x19/x28) loads from its context
        // slot. Never stage it through physical x18: Darwin may clear its
        // platform register asynchronously, publishing a null target.
        emit_word(
            assembler,
            entries,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | 17,
        )?;
    } else {
        // mov x17, xN (orr x17, xzr, xN) — the target PC in the exit's own
        // Darwin-stable scratch.
        emit_word(assembler, entries, guest, 0xaa00_03f1 | (register << 16))?;
    }
    let miss = assembler.new_dynamic_label();
    let hit = assembler.new_dynamic_label();
    let slow = assembler.new_dynamic_label();
    let stale_miss = assembler.new_dynamic_label();
    let miss_exit = assembler.new_dynamic_label();
    let slow_miss = assembler.new_dynamic_label();
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
        ; eor x19, x17, x17, LSR #12
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ubfx x19, x19, #2, #super::gateway::INDIRECT_CACHE_INDEX_BITS
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, x19, LSL #super::gateway::INDIRECT_CACHE_ENTRY_SHIFT
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x19, [x15]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; eor x19, x19, x17
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x19, =>hit
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; add x15, x15, #32
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x19, [x15]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; eor x19, x19, x17
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbnz x19, =>miss
        ; =>hit
    );
    // Flavor gate: bit 0 of `reserved`. Flavor 1 (private trusted-entry
    // target) validates the target page's generation inline — the same
    // atomic the target's own guard would `ldar` — and branches straight to
    // the TRUSTED entry, skipping the guard and the authority switch (a
    // private→private hop never changes the installed cache authority).
    // Flavor 0 (`reserved == 0`) takes the slow authority-switch path below.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15, #24]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; tbz x17, #0, =>slow
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x19, [x15, #16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldar x19, [x19]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; eor x19, x19, x17, LSR #1
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbnz x19, =>stale_miss
    );
    // Non-null by fill construction: `publish_private_trusted` only writes a
    // resolved trusted-entry address.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x19, [x15, #8]
    );
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
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
    );
    // x17 and x19 arrive clobbered; the trusted entry re-materializes both
    // (its generation publish rebuilds x17, and the guard vocabulary owns
    // x19 outright).
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x19
        ; =>stale_miss
    );
    // The flavor word overwrote x17; reload the guest target PC from the
    // entry tag (x15 addresses the HIT way's entry base for either way),
    // then fall into the miss path.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15]
        ; =>miss
    );
    // Miss: stage the target (still in x17) for the resolver, restore x15,
    // and build the typed ResolveIndirect exit. Guest x16, x30 (for a
    // non-call exit) and NZCV were never touched on this route.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x15, [x28, #1160]
        ; =>miss_exit
    );
    if let Some(link) = link {
        // The architectural effect of the `blr` the resolver will complete:
        // guest x30 = the return address. The slow-path route arrives here
        // with x30 still holding the pre-call value.
        emit_mov_u64(
            assembler,
            entries,
            guest,
            30,
            MaterializedValue::Guest(link.raw()),
            recording.as_deref_mut(),
        )?;
    }
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
    // Every hot-path and miss-staging word after the spills restores exactly
    // what the lean sequence spends: x15 from 1160, x17 from 1128 (the
    // universal exit tail's store), plus x30 from 1168 for a `blr`.
    let lean_end = current_offset(assembler)?;
    record_recovery_range(recovery, lean_start, lean_end, lean_action);
    // Slow path (flavor 0): today's authority-switch machinery, relocated.
    // It may spend more — x16, NZCV — so it re-establishes the FULL spill-
    // slot discipline the RestoreIndirectRegisters/RestoreIndirectResolver
    // actions expect (1120/1128/1160/1168/936) before using them.
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>slow
    );
    let slow_lean_start = current_offset(assembler)?;
    if link.is_none() {
        // A call exit spilled x30 up front; every other kind spills it here
        // so RestoreIndirectResolver's unconditional x30 restore reads a
        // live slot. x30 still holds the guest value on this word.
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x30, [x28, #1168]
        );
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #1120]
    );
    let slow_registers_start = current_offset(assembler)?;
    record_recovery_range(recovery, slow_lean_start, slow_registers_start, lean_action);
    emit_word(assembler, entries, guest, 0xd53b_4210)?; // mrs x16, nzcv
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #936]
    );
    let slow_resolver_start = current_offset(assembler)?;
    record_recovery_range(
        recovery,
        slow_registers_start,
        slow_resolver_start,
        RecoveryAction::RestoreIndirectRegisters,
    );
    // x17 holds the flavor word here; reload the guest target PC from the
    // entry tag (valid for either hit way) and stage it for the resolver, so
    // every slow-route miss can exit without re-deriving it.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );
    // The cache entry's guarded-entry pointer; the target block's own
    // generation guard is the authoritative stale-code check on this path.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15, #8]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>slow_miss
    );
    let _ = emit_target_authority_switch(assembler, entries, guest, slow_miss)?;
    // Keep ordinary translated targets out of custom physical x18 entirely.
    // Preserve the validated cache PC from physical x17 in the context while
    // guest x15/x16 and NZCV are restored, then reload and recheck it
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
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x28, #1072]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>slow_miss
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
        ; =>slow_miss
    );
    // A slow-route miss must undo the slow prologue's extra spends (x16 and
    // NZCV) before joining the shared exit staging; 1080 is already staged.
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
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>miss_exit
    );
    let slow_end = current_offset(assembler)?;
    record_recovery_range(
        recovery,
        slow_resolver_start,
        slow_end,
        RecoveryAction::RestoreIndirectResolver,
    );
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
fn record_direct_binding_recovery(
    recovery: &mut Vec<RecoveryEntry>,
    cache: CacheOffset,
    phase: DirectBindingRecoveryPhase,
    capture_progress: DirectBindingCaptureProgress,
    committed_link: Option<u64>,
) {
    recovery.push(RecoveryEntry {
        cache,
        action: RecoveryAction::RestoreDirectBinding {
            phase,
            capture_progress,
            committed_link,
        },
    });
}

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
        record_direct_binding_recovery(
            recovery,
            CacheOffset::published(offset),
            phase,
            DirectBindingCaptureProgress::Complete,
            committed_link,
        );
    }
    Ok(())
}

const DIRECT_BINDING_STUB_WORDS: usize = 64;
const DIRECT_BINDING_CAPTURE_WORDS: usize = 5;
const DIRECT_BINDING_HIT_WORDS: usize = 22;
const DIRECT_BINDING_MISS_WORD: usize = DIRECT_BINDING_CAPTURE_WORDS + DIRECT_BINDING_HIT_WORDS;

fn record_direct_binding_sidecar_phases(
    recovery: &mut Vec<RecoveryEntry>,
    start: CacheOffset,
    end: CacheOffset,
    committed_link: Option<u64>,
) -> Result<(), DsrError> {
    let expected_end = start
        .get()
        .checked_add((DIRECT_BINDING_STUB_WORDS * 4) as u32)
        .ok_or_else(|| DsrError::CachePolicy("direct-binding recovery envelope overflow".into()))?;
    if end.get() != expected_end {
        return Err(DsrError::CachePolicy(format!(
            "direct-binding recovery envelope is {}..{}, expected {} bytes",
            start.get(),
            end.get(),
            DIRECT_BINDING_STUB_WORDS * 4
        )));
    }
    for (first_word, end_word, phase) in [
        (5, 7, DirectBindingRecoveryPhase::CellAddress),
        (7, 11, DirectBindingRecoveryPhase::TargetAcquire),
        (11, 17, DirectBindingRecoveryPhase::AuthorityValidate),
        (17, 21, DirectBindingRecoveryPhase::AuthorityInstall),
        (21, 26, DirectBindingRecoveryPhase::ArchitecturalRestore),
        (26, 27, DirectBindingRecoveryPhase::FinalBranch),
        (27, 64, DirectBindingRecoveryPhase::MissExit),
    ] {
        let phase_start = start
            .get()
            .checked_add(first_word * 4)
            .map(CacheOffset::published)
            .ok_or_else(|| {
                DsrError::CachePolicy("direct-binding recovery phase start overflow".into())
            })?;
        let phase_end = start
            .get()
            .checked_add(end_word * 4)
            .map(CacheOffset::published)
            .ok_or_else(|| {
                DsrError::CachePolicy("direct-binding recovery phase end overflow".into())
            })?;
        record_direct_binding_phase(recovery, phase_start, phase_end, phase, committed_link)?;
    }
    Ok(())
}

pub(crate) fn rewrite_direct_binding_stub(
    code: &mut [u8],
    link: DirectLink,
    ordinal: crate::direct_binding::DirectBindingOrdinal,
    data_offset: u32,
) -> Result<crate::shared_cache::DirectBindingRelocation, DsrError> {
    let start = usize::try_from(link.stub.start.get()).map_err(|_| {
        DsrError::CachePolicy("direct-binding stub start does not fit usize".to_string())
    })?;
    let end = usize::try_from(link.stub.end.get()).map_err(|_| {
        DsrError::CachePolicy("direct-binding stub end does not fit usize".to_string())
    })?;
    let stub = code.get_mut(start..end).ok_or_else(|| {
        DsrError::CachePolicy("direct-binding stub envelope is out of bounds".to_string())
    })?;
    if stub.len() != DIRECT_BINDING_STUB_WORDS * std::mem::size_of::<u32>() {
        return Err(DsrError::CachePolicy(format!(
            "direct-binding precursor instruction shape has {} bytes, expected {}",
            stub.len(),
            DIRECT_BINDING_STUB_WORDS * std::mem::size_of::<u32>()
        )));
    }
    let mut precursor = [0_u32; DIRECT_BINDING_STUB_WORDS];
    for (word, bytes) in precursor.iter_mut().zip(stub.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().map_err(|_| {
            DsrError::CachePolicy(
                "direct-binding precursor instruction shape is truncated".to_string(),
            )
        })?);
    }
    let capture = [
        0xf902_478f, // str x15, [x28, #1160]
        0xf902_3390, // str x16, [x28, #1120]
        0xf902_4b9e, // str x30, [x28, #1168]
        0xd53b_4210, // mrs x16, nzcv
        0xf901_d790, // str x16, [x28, #936]
    ];
    let authority_fixed = [
        (9, 0xf902_1f91),  // str x17, [x28, #1080]
        (10, 0xf942_3b8f), // ldr x15, [x28, #1136]
        (11, 0xb400_044f), // cbz x15, resolver
        (12, 0xca51_3230), // eor x16, x17, lsr #12
        (13, 0xd342_4210), // ubfx x16, x16, #2, #15
        (14, 0x8b10_19ef), // add x15, x15, x16, lsl #6
        (15, 0xf940_01f0), // ldr x16, [x15]
        (16, 0xeb11_021f), // cmp x16, x17
        (17, 0x5400_00a0), // b.eq probe generation
        (18, 0x9100_81ef), // add x15, x15, #32
        (19, 0xf940_01f0), // ldr x16, [x15]
        (20, 0xeb11_021f), // cmp x16, x17
        (21, 0x5400_0301), // b.ne resolver
        (22, 0xf940_05f1), // ldr x17, [x15, #8]
        (23, 0xb400_02d1), // cbz x17, resolver
        (24, 0xf940_09f0), // ldr x16, [x15, #16]
        (25, 0xb400_0290), // cbz x16, resolver
        (26, 0xf940_020f), // ldr x15, [x16]
        (27, 0xeb0f_023f), // cmp x17, x15
        (28, 0x5400_0223), // b.lo resolver
        (29, 0xf940_060f), // ldr x15, [x16, #8]
        (30, 0xeb0f_023f), // cmp x17, x15
        (31, 0x5400_01c2), // b.hs resolver
        (32, 0xf902_538f), // str x15, [x28, #1184]
        (33, 0xf940_020f), // ldr x15, [x16]
        (34, 0xf902_4f8f), // str x15, [x28, #1176]
        (35, 0xf940_0a0f), // ldr x15, [x16, #16]
        (36, 0xf902_7b8f), // str x15, [x28, #1264]
        (37, 0xf902_1b91), // str x17, [x28, #1072]
        (38, 0xf941_d790), // ldr x16, [x28, #936]
        (39, 0xd51b_4210), // msr nzcv, x16
        (40, 0xf942_478f), // ldr x15, [x28, #1160]
        (41, 0xf942_3390), // ldr x16, [x28, #1120]
        (42, 0xf942_4b9e), // ldr x30, [x28, #1168]
        (43, 0xf942_1b91), // ldr x17, [x28, #1072]
        (44, 0xd61f_0220), // br x17
        (45, 0xf941_d790), // ldr x16, [x28, #936]
        (46, 0xd51b_4210), // msr nzcv, x16
        (47, 0xf942_478f), // ldr x15, [x28, #1160]
        (48, 0xf942_3390), // ldr x16, [x28, #1120]
        (49, 0xf942_4b9e), // ldr x30, [x28, #1168]
        (54, 0xf902_1f91), // str x17, [x28, #1080]
        (59, 0xf902_2391), // str x17, [x28, #1088]
        (60, 0x5280_0051), // mov w17, #2
        (61, 0xb904_4b91), // str w17, [x28, #1096]
        (62, 0xf942_6791), // ldr x17, [x28, #1224]
        (63, 0xd61f_0220), // br x17
    ];
    if precursor[..capture.len()] != capture
        || decode_mov_wide_x17(&precursor[5..9]) != Some(link.target.raw())
        || decode_mov_wide_x17(&precursor[50..54]) != Some(link.target.raw())
        || decode_mov_wide_x17(&precursor[55..59]) != Some(link.source.raw())
        || authority_fixed
            .iter()
            .any(|(index, expected)| precursor[*index] != *expected)
    {
        return Err(DsrError::CachePolicy(
            "direct-binding precursor instruction shape or owner identity does not match the authority resolver"
                .to_string(),
        ));
    }

    let hit = [
        0x9000_000f, // adrp x15, binding-cell-page
        0x9100_01ef, // add x15, x15, binding-cell-pageoff
        0xc8df_fdf1, // ldar x17, [x15]
        0xb400_0271, // cbz x17, miss
        0xf902_8b91, // str x17, [x28, #1296]
        0xf940_0230, // ldr x16, [x17]
        0xa940_fa2f, // ldp x15, x30, [x17, #8]
        0xeb0f_021f, // cmp x16, x15
        0x5400_01c3, // b.lo miss
        0xeb1e_021f, // cmp x16, x30
        0x5400_0182, // b.hs miss
        0xf940_0e31, // ldr x17, [x17, #24]
        0xf902_7b91, // str x17, [x28, #1264]
        0x9112_6391, // add x17, x28, #1176
        0xa900_7a2f, // stp x15, x30, [x17]
        0xf902_1b90, // str x16, [x28, #1072]
        0xf851_0230, // ldur x16, [x17, #-240]
        0xd51b_4210, // msr nzcv, x16
        0xa97f_7a2f, // ldp x15, x30, [x17, #-16]
        0xf85c_8230, // ldur x16, [x17, #-56]
        0xf859_8231, // ldur x17, [x17, #-104]
        0xd61f_0220, // br x17
    ];
    let low_ordinal = ordinal.get() & 0xffff;
    let high_ordinal = ordinal.get() >> 16;
    let miss_prefix = [
        0x9000_000f,                       // adrp x15, binding-cell-page
        0x9100_01ef,                       // add x15, x15, binding-cell-pageoff
        0xf902_838f,                       // str x15, [x28, #1280]
        0x5280_0011 | (low_ordinal << 5),  // movz w17, ordinal[15:0]
        0x72a0_0011 | (high_ordinal << 5), // movk w17, ordinal[31:16], lsl #16
        0xb905_0b91,                       // str w17, [x28, #1288]
        0x5280_0031,                       // mov w17, #1
        0xb905_0f91,                       // str w17, [x28, #1292]
        0xf902_8b9f,                       // str xzr, [x28, #1296]
        0xf941_d790,                       // ldr x16, [x28, #936]
        0xd51b_4210,                       // msr nzcv, x16
        0xf942_478f,                       // ldr x15, [x28, #1160]
        0xf942_3390,                       // ldr x16, [x28, #1120]
        0xf942_4b9e,                       // ldr x30, [x28, #1168]
    ];
    let resolver = precursor[50..64].to_vec();
    let mut rewritten = vec![0xd503_201f; DIRECT_BINDING_STUB_WORDS];
    rewritten[..capture.len()].copy_from_slice(&capture);
    rewritten[DIRECT_BINDING_CAPTURE_WORDS..DIRECT_BINDING_MISS_WORD].copy_from_slice(&hit);
    let miss_prefix_end = DIRECT_BINDING_MISS_WORD + miss_prefix.len();
    rewritten[DIRECT_BINDING_MISS_WORD..miss_prefix_end].copy_from_slice(&miss_prefix);
    rewritten[miss_prefix_end..miss_prefix_end + resolver.len()].copy_from_slice(&resolver);
    for (bytes, word) in stub.chunks_exact_mut(4).zip(rewritten) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }

    let adrp_offset = link
        .stub
        .start
        .get()
        .checked_add((DIRECT_BINDING_CAPTURE_WORDS * 4) as u32)
        .ok_or_else(|| DsrError::CachePolicy("hit relocation offset overflow".to_string()))?;
    let miss_adrp_offset = link
        .stub
        .start
        .get()
        .checked_add((DIRECT_BINDING_MISS_WORD * 4) as u32)
        .ok_or_else(|| DsrError::CachePolicy("miss relocation offset overflow".to_string()))?;
    Ok(crate::shared_cache::DirectBindingRelocation {
        ordinal,
        adrp_offset,
        add_offset: adrp_offset
            .checked_add(4)
            .ok_or_else(|| DsrError::CachePolicy("hit ADD offset overflow".to_string()))?,
        miss_adrp_offset,
        miss_add_offset: miss_adrp_offset
            .checked_add(4)
            .ok_or_else(|| DsrError::CachePolicy("miss ADD offset overflow".to_string()))?,
        data_offset,
    })
}

fn decode_mov_wide_x17(words: &[u32]) -> Option<u64> {
    const IMM16_MASK: u32 = 0x001f_ffe0;
    let expected = [0xd280_0011, 0xf2a0_0011, 0xf2c0_0011, 0xf2e0_0011];
    if words.len() != expected.len() {
        return None;
    }
    let mut value = 0_u64;
    for (index, (word, expected)) in words.iter().zip(expected).enumerate() {
        if *word & !IMM16_MASK != expected {
            return None;
        }
        value |= u64::from((*word & IMM16_MASK) >> 5) << (index * 16);
    }
    Some(value)
}

#[allow(clippy::too_many_arguments)]
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
    record_direct_binding_recovery(
        recovery,
        scratch_capture_start,
        DirectBindingRecoveryPhase::ScratchCapture,
        DirectBindingCaptureProgress::None,
        committed_link,
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x15, [x28, #1160]
    );
    record_direct_binding_recovery(
        recovery,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ScratchCapture,
        DirectBindingCaptureProgress::X15,
        committed_link,
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #1120]
    );
    record_direct_binding_recovery(
        recovery,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ScratchCapture,
        DirectBindingCaptureProgress::X15X16,
        committed_link,
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x30, [x28, #1168]
    );
    record_direct_binding_recovery(
        recovery,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ScratchCapture,
        DirectBindingCaptureProgress::X15X16X30,
        committed_link,
    );
    emit_word(assembler, entries, map_guest, 0xd53b_4210)?; // mrs x16, nzcv
    record_direct_binding_recovery(
        recovery,
        current_offset(assembler)?,
        DirectBindingRecoveryPhase::ScratchCapture,
        DirectBindingCaptureProgress::X15X16X30,
        committed_link,
    );
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x16, [x28, #936]
    );
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
    let authority = emit_target_authority_switch(assembler, entries, map_guest, miss)?;
    let _ = authority.install_start;
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1072]
    );
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
    map_next(assembler, entries, map_guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
        ; =>miss
    );
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
        GuestPcWidth::Fixed,
    )?;
    record_direct_binding_sidecar_phases(
        recovery,
        scratch_capture_start,
        current_offset(assembler)?,
        committed_link,
    )
}

/// One item of a fused block's emission stream: either a guest instruction
/// from some segment's body, or the internal edge joining two segments.
///
/// A flat stream rather than a loop per segment, so every `continue` in the
/// copy-stream match keeps targeting the loop that consumes the stream.
enum EmitItem<'plan> {
    Instruction(&'plan super::block::PlannedInst),
    InternalEdge(PlannedExit),
}

/// A fused conditional's taken edge, held back until the whole fused body is
/// emitted.
///
/// The patch slot goes down inline (it has to: the conditional reaches it with
/// a fixed displacement), but the stub it branches to is emitted after the
/// terminal exit. Interleaving ~10 words of cold gateway stub between every
/// pair of segments is exactly the I-cache dilution superblock formation exists
/// to avoid.
struct PendingTakenEdge {
    guest: GuestVa,
    target: GuestVa,
    slot: CacheOffset,
    stub: dynasmrt::DynamicLabel,
    restore_guest_x17_across_stub: bool,
}

fn record_guest_x17_recovery_range(
    recovery: &mut Vec<RecoveryEntry>,
    start: CacheOffset,
    end: CacheOffset,
) {
    for offset in (start.get()..end.get()).step_by(4) {
        recovery.push(RecoveryEntry {
            cache: CacheOffset::published(offset),
            action: RecoveryAction::RestoreGuestX17,
        });
    }
}

/// Emit the internal edge of a fused conditional branch.
///
/// The guest's fall-through continues inline in the next segment; the guest's
/// taken edge leaves the block through an ordinary direct-link slot. The three
/// leading words are the same ones a non-fused conditional exit emits -- the
/// relocated conditional (taken displacement 2), then the hop, then the slot --
/// so the encoding of the guest's own branch is untouched.
fn emit_internal_fallthrough_edge(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    exit: PlannedExit,
) -> Result<PendingTakenEdge, DsrError> {
    let PlannedExit::Direct {
        guest, word, exit, ..
    } = exit
    else {
        return Err(DsrError::BlockPolicy(format!(
            "fused segment edge is not a direct branch: {exit:?}"
        )));
    };
    if !matches!(
        exit.kind,
        super::types::DirectKind::Conditional
            | super::types::DirectKind::CompareZero { .. }
            | super::types::DirectKind::TestBit { .. }
    ) {
        return Err(DsrError::BlockPolicy(format!(
            "fused segment edge is not conditional at guest PC 0x{:x}",
            guest.raw()
        )));
    }
    let fallthrough = assembler.new_dynamic_label();
    let stub = assembler.new_dynamic_label();
    let virtual_offset = exit
        .register
        .and_then(gpr_index)
        .and_then(virtual_snapshot_offset);
    if let Some(offset) = virtual_offset {
        // An internal fall-through cannot simply clobber physical x17: unlike a
        // terminal edge, the next fused segment consumes the guest's live x17.
        // Save it in both the canonical and recovery slots, use Darwin-stable
        // x17 for the virtual condition, and reload it on fall-through. Physical
        // x18 is unusable here because Darwin may clear its platform register
        // between the load and the conditional branch.
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((136 / 8) << 10) | (28 << 5) | 17,
        )?;
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | 17,
        )?;
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreGuestX17,
        });
        emit_word(
            assembler,
            entries,
            guest,
            0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | 17,
        )?;
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreGuestX17,
        });
        emit_word(
            assembler,
            entries,
            guest,
            relocated_direct_word(word, exit, Some(17))?,
        )?;
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreGuestX17,
        });
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; b =>fallthrough
        );
        let slot = current_offset(assembler)?;
        recovery.push(RecoveryEntry {
            cache: slot,
            action: RecoveryAction::RestoreGuestX17,
        });
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; b =>stub
            ; =>fallthrough
        );
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: RecoveryAction::RestoreGuestX17,
        });
        emit_word(
            assembler,
            entries,
            guest,
            0xf940_0000 | ((136 / 8) << 10) | (28 << 5) | 17,
        )?;
        return Ok(PendingTakenEdge {
            guest,
            target: exit.target,
            slot,
            stub,
            restore_guest_x17_across_stub: true,
        });
    }

    emit_word(
        assembler,
        entries,
        guest,
        relocated_direct_word(word, exit, None)?,
    )?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>fallthrough
    );
    // Taken path. Publish guest x17 before the slot, never after it: a linked
    // slot branches straight into the target block's prologue, which reloads
    // x17 from slot 136 and whose recovery entries read slot 1128. On the
    // fall-through these two stores do not run at all -- that, plus the entry
    // prologue they no longer reach, is the fusion's whole saving.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #136]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1128]
    );
    let slot = current_offset(assembler)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>stub
        ; =>fallthrough
    );
    Ok(PendingTakenEdge {
        guest,
        target: exit.target,
        slot,
        stub,
        restore_guest_x17_across_stub: false,
    })
}

/// Emit the deferred stub for one fused conditional's taken edge and register
/// its direct link.
fn emit_internal_taken_stub(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    direct_links: &mut Vec<DirectLink>,
    recovery: &mut Vec<RecoveryEntry>,
    edge: PendingTakenEdge,
    direct_exit_policy: DirectExitEmissionPolicy,
    recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>edge.stub
    );
    let stub_start = current_offset(assembler)?;
    emit_direct_exit(
        assembler,
        entries,
        edge.guest,
        edge.guest,
        edge.target,
        None,
        recovery,
        direct_exit_policy,
        recording,
    )?;
    let stub_end = current_offset(assembler)?;
    if edge.restore_guest_x17_across_stub
        && direct_exit_policy == DirectExitEmissionPolicy::PrivateGateway
    {
        record_guest_x17_recovery_range(recovery, stub_start, stub_end);
    }
    direct_links.push(DirectLink {
        slot: edge.slot,
        source: edge.guest,
        target: edge.target,
        kind: DirectLinkKind::ConditionalTaken,
        stub: DirectStubEnvelope {
            start: stub_start,
            end: stub_end,
        },
    });
    Ok(())
}

#[allow(
    clippy::needless_option_as_deref,
    clippy::too_many_arguments,
    reason = "policy chooses the compact private exit or the immutable-unit authority precursor"
)]
fn emit_direct_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    map_guest: GuestVa,
    source_guest: GuestVa,
    target: GuestVa,
    committed_link: Option<u64>,
    recovery: &mut Vec<RecoveryEntry>,
    policy: DirectExitEmissionPolicy,
    recording: Option<&mut ArtifactRecording>,
) -> Result<(), DsrError> {
    match policy {
        DirectExitEmissionPolicy::PrivateGateway => emit_gateway_exit(
            assembler,
            entries,
            map_guest,
            target,
            Some(source_guest),
            2,
            GatewayKind::Direct,
            recording,
            GuestPcWidth::Narrow,
        ),
        DirectExitEmissionPolicy::PortableUnitAuthority => emit_cached_direct_exit(
            assembler,
            entries,
            map_guest,
            source_guest,
            target,
            committed_link,
            recovery,
            recording,
        ),
    }
}

/// Rewrite every register-field mention of `virtual_register` in `word` onto
/// `scratch`, verified by a decode round-trip: the candidate must keep the
/// op, drop every `virtual_register` mention, and disassemble identically
/// after renaming the scratch back. Returns the rewritten word only.
fn rewritten_word_onto(
    word: u32,
    guest: GuestVa,
    virtual_register: u32,
    scratch: u32,
) -> Option<u32> {
    let original = bad64::decode(word, guest.raw()).ok()?;
    if super::decode::decoded_operands_mention_gpr(word, guest, scratch) {
        return None;
    }
    let fields = [0_u32, 5, 10, 16];
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
        if super::decode::decoded_operands_mention_gpr(candidate_word, guest, virtual_register) {
            continue;
        }
        let virtual_x = format!("x{virtual_register}");
        let virtual_w = format!("w{virtual_register}");
        let normalized = candidate
            .to_string()
            .replace(&format!("x{scratch}"), &virtual_x)
            .replace(&format!("w{scratch}"), &virtual_w);
        if normalized == original.to_string() {
            return Some(candidate_word);
        }
    }
    None
}

fn rewritten_virtual_word(
    word: u32,
    guest: GuestVa,
    virtual_register: u32,
) -> Option<(u32, u32, u32)> {
    for scratch in (9_u32..=17).rev() {
        if let Some(candidate_word) = rewritten_word_onto(word, guest, virtual_register, scratch) {
            let context_scratch = (9_u32..=17).rev().find(|candidate| {
                *candidate != scratch
                    && !super::decode::decoded_operands_mention_gpr(word, guest, *candidate)
            })?;
            return Some((scratch, context_scratch, candidate_word));
        }
    }
    None
}

/// Rewrite one instruction that names TWO host-owned registers onto scratch
/// registers, returning `(first_scratch, second_scratch, context_scratch,
/// rewritten_word)`.
///
/// Parameterized by the register pair rather than pinned to x18/x28: the
/// reserved address scratch is a third host-owned register, so `(18, 19)` and
/// `(19, 28)` pairs need exactly this search too.
fn rewritten_dual_virtual_read_only_word(
    word: u32,
    guest: GuestVa,
    first: u32,
    second: u32,
) -> Option<(u32, u32, u32, u32)> {
    let original = bad64::decode(word, guest.raw()).ok()?;
    let free = (9_u32..=17)
        .rev()
        .filter(|register| !super::decode::decoded_operands_mention_gpr(word, guest, *register))
        .collect::<Vec<_>>();
    let fields = [0_u32, 5, 10, 16];
    let first_fields = fields
        .into_iter()
        .filter(|shift| ((word >> shift) & 0x1f) == first)
        .collect::<Vec<_>>();
    let second_fields = fields
        .into_iter()
        .filter(|shift| ((word >> shift) & 0x1f) == second)
        .collect::<Vec<_>>();
    for &first_scratch in &free {
        for &second_scratch in free.iter().filter(|candidate| **candidate != first_scratch) {
            let context_scratch = *free
                .iter()
                .find(|candidate| **candidate != first_scratch && **candidate != second_scratch)?;
            for first_mask in 1_u32..(1_u32 << first_fields.len()) {
                for second_mask in 1_u32..(1_u32 << second_fields.len()) {
                    let mut candidate_word = word;
                    for (index, shift) in first_fields.iter().copied().enumerate() {
                        if first_mask & (1 << index) != 0 {
                            candidate_word =
                                (candidate_word & !(0x1f << shift)) | (first_scratch << shift);
                        }
                    }
                    for (index, shift) in second_fields.iter().copied().enumerate() {
                        if second_mask & (1 << index) != 0 {
                            candidate_word =
                                (candidate_word & !(0x1f << shift)) | (second_scratch << shift);
                        }
                    }
                    let Ok(candidate) = bad64::decode(candidate_word, guest.raw()) else {
                        continue;
                    };
                    if candidate.op() != original.op()
                        || super::decode::decoded_operands_mention_gpr(candidate_word, guest, first)
                        || super::decode::decoded_operands_mention_gpr(
                            candidate_word,
                            guest,
                            second,
                        )
                    {
                        continue;
                    }
                    let normalized = candidate
                        .to_string()
                        .replace(&format!("x{first_scratch}"), &format!("x{first}"))
                        .replace(&format!("w{first_scratch}"), &format!("w{first}"))
                        .replace(&format!("x{second_scratch}"), &format!("x{second}"))
                        .replace(&format!("w{second_scratch}"), &format!("w{second}"));
                    if normalized == original.to_string() {
                        return Some((
                            first_scratch,
                            second_scratch,
                            context_scratch,
                            candidate_word,
                        ));
                    }
                }
            }
        }
    }
    None
}

/// Which of a dual-virtualized instruction's two host-owned registers it
/// writes, and therefore which context slots the emitter commits after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DualCommit {
    None,
    First,
    Second,
    /// The instruction writes both. Used for pairs involving the reserved
    /// address scratch, where committing a register the instruction did not
    /// write is a no-op anyway (its scratch still holds the loaded value), so
    /// no per-shape destination analysis is needed to stay correct.
    Both,
}

/// Emit one instruction that names two host-owned registers, reading both
/// guest values out of their context slots and optionally committing one back.
///
/// `first`/`second` are `(register, context slot)`; the recovery actions this
/// records are already register-agnostic (they name the scratch registers and
/// the committed register, not x18/x28), so only this emitter and the rewrite
/// search had to be parameterized to cover pairs involving the reserved
/// address scratch.
#[allow(
    clippy::too_many_arguments,
    reason = "dual virtualization carries both register/slot pairs plus its recovery contract"
)]
fn emit_dual_virtual(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    word: u32,
    first: (u32, u32),
    second: (u32, u32),
    commit_virtual: DualCommit,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let (first_register, first_offset) = first;
    let (second_register, second_offset) = second;
    let (x18_scratch, x28_scratch, context_scratch, rewritten) =
        rewritten_dual_virtual_read_only_word(word, guest, first_register, second_register)
            .ok_or_else(|| {
                unsupported_action(plan, guest, word, "unrewritable dual-virtual instruction")
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
        0xf940_0000 | ((first_offset / 8) << 10) | (context_scratch << 5) | x18_scratch,
        0xf940_0000 | ((second_offset / 8) << 10) | (context_scratch << 5) | x28_scratch,
        rewritten,
    ] {
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action: restore,
        });
        emit_word(assembler, entries, guest, instruction)?;
    }
    let commits: &[u32] = match commit_virtual {
        DualCommit::None => &[],
        DualCommit::First => std::slice::from_ref(&first_register),
        DualCommit::Second => std::slice::from_ref(&second_register),
        DualCommit::Both => &[first_register, second_register],
    };
    for (index, virtual_register) in commits.iter().copied().enumerate() {
        let (virtual_scratch, snapshot_offset) = if virtual_register == first_register {
            (x18_scratch, first_offset)
        } else if virtual_register == second_register {
            (x28_scratch, second_offset)
        } else {
            return Err(unsupported_action(
                plan,
                guest,
                word,
                "invalid dual virtual destination",
            ));
        };
        // Only the FIRST of a two-register commit still owes both slots; by
        // the second store the first slot (a snapshot slot) already holds the
        // architectural value.
        let action = if commits.len() == 2 && index == 0 {
            RecoveryAction::CommitDualVirtualPairAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                first_register,
                second_register,
            }
        } else {
            RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            }
        };
        recovery.push(RecoveryEntry {
            cache: current_offset(assembler)?,
            action,
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

/// The reserved-resident lowering for one instruction naming one virtualized
/// register: materialize the guest value into physical x19 (carrick-owned for
/// the whole of translated execution, clobbered by every block entry's guard),
/// run the rewritten word, and commit the slot only when the word writes the
/// register.
///
/// ```text
/// [ldr x19, [x28, #slot]]   ; only when the word READS the register
/// <word, mentions -> x19>   ; the original word when the register IS x19
/// [str x19, [x28, #slot]]   ; only when the word WRITES the register
/// ```
///
/// Interruption contract: the template records no recovery entries except the
/// commit store. Every word maps to the instruction's guest PC, so a fault or
/// kick before the commit resumes at the instruction start and re-executes it
/// against the still-authoritative slot — which is why eligibility demands
/// idempotency (no written register other than the virtualized one may also
/// be read; the virtualized register itself round-trips through the slot).
/// At the commit store the word has executed, so the entry is
/// `CommitReservedResident`: complete, with the result taken from the
/// interrupted physical x19 the signal handler preserves.
struct ReservedResidentPlan {
    rewritten: u32,
    needs_load: bool,
    needs_store: bool,
}

/// GPR index for read/write tracking: `x0..x30`/`w0..w30` map to 0..30, the
/// stack pointer to 31 (it can be written back and must join the idempotency
/// check), and the zero registers to `None` (reads yield zero, writes vanish).
fn resident_gpr_index(register: bad64::Reg) -> Option<u32> {
    let raw = register as u32;
    let x0 = bad64::Reg::X0 as u32;
    let w0 = bad64::Reg::W0 as u32;
    if (x0..=x0 + 30).contains(&raw) {
        return Some(raw - x0);
    }
    if (w0..=w0 + 30).contains(&raw) {
        return Some(raw - w0);
    }
    if register == bad64::Reg::SP || register == bad64::Reg::WSP {
        return Some(31);
    }
    None
}

fn reserved_resident_plan(
    word: u32,
    guest: GuestVa,
    virtual_register: u32,
) -> Option<ReservedResidentPlan> {
    use bad64::Op;
    let decoded = bad64::decode(word, guest.raw()).ok()?;
    let op = decoded.op();
    let is_store = matches!(
        op,
        Op::STR | Op::STUR | Op::STRB | Op::STURB | Op::STRH | Op::STURH | Op::STP
    );
    let is_load = matches!(
        op,
        Op::LDR
            | Op::LDUR
            | Op::LDRB
            | Op::LDURB
            | Op::LDRH
            | Op::LDURH
            | Op::LDRSB
            | Op::LDURSB
            | Op::LDRSH
            | Op::LDURSH
            | Op::LDRSW
            | Op::LDURSW
            | Op::LDP
    );
    let is_prefetch = matches!(op, Op::PRFM | Op::PRFUM);
    let flag_only = matches!(op, Op::CMP | Op::CMN | Op::TST | Op::CCMP | Op::CCMN);
    let is_alu = flag_only
        || matches!(
            op,
            Op::MOV
                | Op::MVN
                | Op::NEG
                | Op::ADD
                | Op::ADDS
                | Op::SUB
                | Op::SUBS
                | Op::AND
                | Op::ANDS
                | Op::ORR
                | Op::ORN
                | Op::EOR
                | Op::EON
                | Op::BIC
                | Op::BICS
                | Op::LSL
                | Op::LSR
                | Op::ASR
                | Op::ROR
                | Op::MUL
                | Op::MNEG
                | Op::MADD
                | Op::MSUB
                | Op::SMULH
                | Op::UMULH
                | Op::SXTB
                | Op::SXTH
                | Op::SXTW
                | Op::UXTB
                | Op::UXTH
                | Op::UBFX
                | Op::UBFIZ
                | Op::SBFX
                | Op::SBFIZ
                | Op::CSEL
                | Op::CSINC
                | Op::CSINV
                | Op::CSNEG
                | Op::CINC
                | Op::CINV
                | Op::CNEG
                | Op::CSET
                | Op::CSETM
        );
    if !(is_store || is_load || is_prefetch || is_alu) {
        return None;
    }
    let mut reads = [false; 32];
    let mut writes = [false; 32];
    if is_alu {
        let operands = decoded.operands();
        let mut sources = operands;
        if !flag_only {
            let (destination, rest) = operands.split_first()?;
            let bad64::Operand::Reg { reg, .. } = destination else {
                return None;
            };
            if let Some(index) = resident_gpr_index(*reg) {
                writes[index as usize] = true;
            }
            sources = rest;
        }
        for operand in sources {
            match operand {
                bad64::Operand::Reg { reg, .. }
                | bad64::Operand::ShiftReg { reg, .. }
                | bad64::Operand::QualReg { reg, .. } => {
                    if let Some(index) = resident_gpr_index(*reg) {
                        reads[index as usize] = true;
                    }
                }
                bad64::Operand::Imm32 { .. }
                | bad64::Operand::Imm64 { .. }
                | bad64::Operand::Cond(_) => {}
                _ => return None,
            }
        }
    } else {
        for operand in decoded.operands() {
            match operand {
                bad64::Operand::Reg { reg, .. } | bad64::Operand::QualReg { reg, .. } => {
                    // A transfer register. Prefetch hints carry none; SIMD
                    // transfers fall through `resident_gpr_index` as `None`.
                    if let Some(index) = resident_gpr_index(*reg) {
                        if is_load {
                            writes[index as usize] = true;
                        } else {
                            reads[index as usize] = true;
                        }
                    }
                }
                bad64::Operand::MemReg(reg) | bad64::Operand::MemOffset { reg, .. } => {
                    if let Some(index) = resident_gpr_index(*reg) {
                        reads[index as usize] = true;
                    }
                }
                bad64::Operand::MemPreIdx { reg, .. }
                | bad64::Operand::MemPostIdxImm { reg, .. } => {
                    if let Some(index) = resident_gpr_index(*reg) {
                        reads[index as usize] = true;
                        writes[index as usize] = true;
                    }
                }
                bad64::Operand::MemExt { regs, .. } => {
                    for register in regs {
                        if let Some(index) = resident_gpr_index(*register) {
                            reads[index as usize] = true;
                        }
                    }
                }
                bad64::Operand::ImplSpec { .. } | bad64::Operand::Name(_) => {}
                _ => return None,
            }
        }
    }
    let virtual_index = usize::try_from(virtual_register).ok()?;
    if !reads[virtual_index] && !writes[virtual_index] {
        return None;
    }
    // Defense in depth: a word naming a second host-owned register belongs to
    // the dual emitter, and one naming SP-as-31 collides with nothing here.
    for owned in [18_u32, 28, crate::gateway::RESERVED_SCRATCH] {
        if owned != virtual_register && (reads[owned as usize] || writes[owned as usize]) {
            return None;
        }
    }
    // Idempotency: resuming at the instruction start re-executes the word, so
    // no written register other than the slot-backed virtualized one may feed
    // back into the word's inputs.
    for register in 0..32 {
        if writes[register] && register != virtual_index && reads[register] {
            return None;
        }
    }
    let rewritten = if virtual_register == crate::gateway::RESERVED_SCRATCH {
        word
    } else {
        rewritten_word_onto(
            word,
            guest,
            virtual_register,
            crate::gateway::RESERVED_SCRATCH,
        )?
    };
    Some(ReservedResidentPlan {
        rewritten,
        needs_load: reads[virtual_index],
        needs_store: writes[virtual_index],
    })
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
    if let Some(resident) = reserved_resident_plan(word, guest, virtual_register) {
        let reserved = crate::gateway::RESERVED_SCRATCH;
        if resident.needs_load {
            emit_word(
                assembler,
                entries,
                guest,
                0xf940_0000 | ((snapshot_offset / 8) << 10) | (28 << 5) | reserved,
            )?;
        }
        emit_word(assembler, entries, guest, resident.rewritten)?;
        if resident.needs_store {
            recovery.push(RecoveryEntry {
                cache: current_offset(assembler)?,
                action: RecoveryAction::CommitReservedResident { virtual_register },
            });
            emit_word(
                assembler,
                entries,
                guest,
                0xf900_0000 | ((snapshot_offset / 8) << 10) | (28 << 5) | reserved,
            )?;
        }
        return Ok(());
    }
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
        super::types::MemoryBase::VirtualReserved => Ok(BiasedBase::VirtualReserved),
        super::types::MemoryBase::Literal(_) => Ok(BiasedBase::None),
    }
}

fn biased_base_load_word(base: BiasedBase, destination: u32) -> Option<u32> {
    match base {
        BiasedBase::Register(register) => Some(0xaa00_03e0 | (register << 16) | destination),
        BiasedBase::StackPointer => Some(0x9100_03e0 | destination),
        BiasedBase::VirtualX18 => Some(0xf940_0000 | ((144 / 8) << 10) | (28 << 5) | destination),
        BiasedBase::VirtualX28 => Some(0xf940_0000 | ((224 / 8) << 10) | (28 << 5) | destination),
        BiasedBase::VirtualReserved => Some(
            0xf940_0000
                | ((crate::gateway::CTX_GUEST_RESERVED_SCRATCH / 8) << 10)
                | (28 << 5)
                | destination,
        ),
        BiasedBase::None => None,
    }
}

/// The rewrite scratches a biased access needs for its virtualized operands.
/// Each `Some(scratch)` names a register the lowering spills, loads the guest
/// value into, and stores back after the access.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BiasedVirtualRewrite {
    word: u32,
    x18: Option<u32>,
    x28: Option<u32>,
    reserved: Option<u32>,
}

fn rewritten_biased_virtual_word(
    memory: super::types::MemoryAccess,
    guest: GuestVa,
) -> Result<BiasedVirtualRewrite, DsrError> {
    let plain = BiasedVirtualRewrite {
        word: memory.word,
        ..BiasedVirtualRewrite::default()
    };
    match memory.virtualization {
        super::types::MemoryVirtualization::None => Ok(plain),
        super::types::MemoryVirtualization::X18 => {
            let (scratch, _, word) =
                rewritten_virtual_word(memory.word, guest, 18).ok_or_else(|| {
                    DsrError::BlockPolicy("biased x18 memory operand is not rewritable".to_string())
                })?;
            Ok(BiasedVirtualRewrite {
                word,
                x18: Some(scratch),
                ..plain
            })
        }
        super::types::MemoryVirtualization::X28 => {
            let (scratch, _, word) =
                rewritten_virtual_word(memory.word, guest, 28).ok_or_else(|| {
                    DsrError::BlockPolicy("biased x28 memory operand is not rewritable".to_string())
                })?;
            Ok(BiasedVirtualRewrite {
                word,
                x28: Some(scratch),
                ..plain
            })
        }
        super::types::MemoryVirtualization::Reserved => {
            // `Reserved` is set for a base-only mention too (the physical
            // register is the lowering's address scratch). A base mention is
            // already carried by `BiasedBase::VirtualReserved` and overwritten
            // with the address register, so only a mention OUTSIDE the base
            // needs an operand rewrite.
            if !super::decode::decoded_operands_mention_gpr_outside_memory_base(
                memory.word,
                guest,
                crate::gateway::RESERVED_SCRATCH,
            ) {
                return Ok(plain);
            }
            let (scratch, _, word) =
                rewritten_virtual_word(memory.word, guest, crate::gateway::RESERVED_SCRATCH)
                    .ok_or_else(|| {
                        DsrError::BlockPolicy(
                            "biased reserved-scratch memory operand is not rewritable".to_string(),
                        )
                    })?;
            Ok(BiasedVirtualRewrite {
                word,
                reserved: Some(scratch),
                ..plain
            })
        }
        super::types::MemoryVirtualization::ReservedPair { other } => {
            // Both host-owned operands are rewritten onto scratch registers,
            // exactly as for an x18/x28 pair; which slot each scratch carries
            // is decided by the caller's `virtual_snapshot_offset` lookup.
            let (reserved, other_scratch, _, word) = rewritten_dual_virtual_read_only_word(
                memory.word,
                guest,
                crate::gateway::RESERVED_SCRATCH,
                other,
            )
            .ok_or_else(|| {
                DsrError::BlockPolicy(
                    "biased reserved-pair memory operands are not rewritable".to_string(),
                )
            })?;
            let mut rewrite = BiasedVirtualRewrite {
                word,
                reserved: Some(reserved),
                ..plain
            };
            if other == 18 {
                rewrite.x18 = Some(other_scratch);
            } else {
                rewrite.x28 = Some(other_scratch);
            }
            Ok(rewrite)
        }
        super::types::MemoryVirtualization::X18X28ReadOnly
        | super::types::MemoryVirtualization::X18WriteX28Read => {
            let (x18, x28, _, word) =
                rewritten_dual_virtual_read_only_word(memory.word, guest, 18, 28).ok_or_else(
                    || {
                        DsrError::BlockPolicy(
                            "biased x18/x28 memory operands are not rewritable".to_string(),
                        )
                    },
                )?;
            Ok(BiasedVirtualRewrite {
                word,
                x18: Some(x18),
                x28: Some(x28),
                ..plain
            })
        }
        super::types::MemoryVirtualization::Unsupported => Err(DsrError::BlockPolicy(
            "biased memory has unsupported virtualization".to_string(),
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

#[allow(
    clippy::useless_conversion,
    reason = "dynasm's dynamic-register expansion adds the conversion after the required u8 cast"
)]
fn emit_biased_cbz(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    register: u32,
    target: DynamicLabel,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverBiasedMemory(action),
    });
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz X(register as u8), =>target
    );
    Ok(())
}

fn emit_biased_branch(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    recovery: &mut Vec<RecoveryEntry>,
    guest: GuestVa,
    target: DynamicLabel,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RecoverBiasedMemory(action),
    });
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; b =>target
    );
    Ok(())
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
/// One guest memory access the compact aperture-disjoint lowering accepts.
struct CompactBiasedForm {
    /// `(immr, imms)` of the bias as a 64-bit ORR logical immediate (N=1).
    bias_orr: (u32, u32),
    base: BiasedBase,
    /// Non-negative byte displacement of the access from its base.
    immediate: u64,
}

/// The compact lowering applies only when the bias is aperture-disjoint and
/// ORR-encodable (so `guest | bias == guest + bias` for every in-aperture
/// address) and the access shape keeps a base-register-only aperture check
/// sound: an immediate displacement is bounded by the reserved guard windows
/// above the aperture and below the bias, while register offsets are
/// unbounded and negative immediates would need the underflow window's
/// host-to-guest fault conversion (deferred), so both stay general.
/// Diagnostic escape hatch: `CARRICK_DSR_COMPACT_BIASED=0` forces every guest
/// memory access back onto the general lowering while keeping the identical
/// binary, bias and layout. That isolates the compact emission from the bias
/// selection when bisecting a fault, which comparing two builds cannot do.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompactBiasedPolicy {
    /// Every accepted shape, including pre/post-index writeback.
    All,
    /// Writeback forms fall back to the general lowering.
    NoWriteback,
    /// Nothing is lowered compactly.
    Off,
}

/// Is the memory lowering allowed to use `gateway::RESERVED_SCRATCH` as its
/// address register?
///
/// The RESERVATION itself is unconditional -- decode virtualizes every guest
/// mention of the register and the gateway keeps its guest value in a context
/// slot -- because the assembly and C halves of that contract cannot be
/// switched at emit time. This switch controls only whether the lowering
/// SPENDS the freed register, so `CARRICK_DSR_RESERVED_SCRATCH=1` and the
/// default differ in exactly the spill this phase exists to delete, and both
/// arms of a wall screen come from one binary.
///
/// **DEFAULT ON since 2026-07-29, after measurement and attribution.**
/// Previously opt-in; the note below is retained because it records why. Every structural gate is green -- the
/// `bad64`-asserted sequence tests, the recovery matrix's fault injection at
/// every recovery point of eight access shapes (including the reserved base,
/// negative-immediate and register-offset forms), the live compact-writeback
/// kick sweep and `just test` -- and a `/bin/sh` guest runs clean. But
/// `just conformance-native smoke` REGRESSES `go-build` with the switch on:
/// the Go toolchain faults at a wrapped address (`0xffff00a0_xxxxxxxx`, the
/// guest address less 2^48) within seconds, reproducibly but not
/// deterministically -- a first bisect over effective-address forms converged
/// on register offsets and was then refuted by re-sampling, which is the
/// signature of an asynchronous, kick-coupled failure rather than a bad
/// address computation. Shipping it on would break the default backend, so it
/// ships off until that is root-caused. Structural green is necessary, never
/// sufficient (see H008 Spike 1).
fn reserved_scratch_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // ON by default since the paired screen measured 9.7% against a
    // contemporaneous control (5/5 pairs, non-overlapping populations, zero
    // faults). `CARRICK_DSR_RESERVED_SCRATCH=0` is the escape hatch and
    // still forces the general lowering; note it does NOT undo the x19
    // reservation itself, which is unconditional.
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DSR_RESERVED_SCRATCH").as_deref()
            != Some(std::ffi::OsStr::new("0"))
    })
}

/// May the generation guard spend the two registers that are ALREADY carrick's
/// at block entry instead of borrowing guest state?
///
/// The guard has to compare two 64-bit generations, so it needs two scratch
/// registers. It used to borrow guest x16 and guest x17 and spill both, plus
/// NZCV for its `cmp` -- three stores and four reloads on the entry path of
/// every block, and the prologue is store-throughput-bound. Neither borrow is
/// necessary:
///
/// - physical x17 is DEAD at block entry (every exit stores guest x17 to
///   `snapshot.x[17]` and slot 1128; the prologue reloads it after the guard);
/// - physical x19 is host-owned for the whole of translated execution
///   (`gateway::RESERVED_SCRATCH`) -- `_carrick_dsr_enter_raw` never loads the
///   guest value into it and `carrick_native_snapshot_mcontext` never captures
///   it back;
/// - comparing with `eor`/`cbnz` rather than `cmp`/`b.ne` writes no flags.
///
/// The guard itself is unchanged in AUTHORITY: it still runs on every block
/// entry and still reads the generation cell with `ldar`. Only what it spends
/// changes.
///
/// **OPT-IN, and deliberately so.** The structural sequence test, the recovery
/// matrix's fault injection at every recovery point, the live jittered-kick
/// sweeps, `just clippy`/`just fmt-check` and a signed live guest run are all
/// green, and two adversarial reverts (borrow guest x16; compare with `cmp`)
/// each turn the live gate red. But the paired wall-time screen has NOT been
/// run, and structural green is necessary, never sufficient (see H008 Spike 1
/// and the reserved-scratch note above). It ships off until measured;
/// `CARRICK_DSR_LEAN_GUARD=1` selects it, so both arms of a screen come from
/// one binary.
pub fn lean_generation_guard_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        // ON by default: 26.4% on a paired screen (6/6 wins, non-overlapping),
        // and the gate failures that once looked lean-specific reproduced in
        // the CONTROL arm — see the attribution note above.
        // `CARRICK_DSR_LEAN_GUARD=0` is the escape hatch.
        std::env::var_os("CARRICK_DSR_LEAN_GUARD").as_deref() != Some(std::ffi::OsStr::new("0"))
    })
}

/// Can this access compute its host address entirely in the reserved register,
/// with no borrowed guest register at all?
///
/// Two exclusions, both about recovery rather than register pressure:
///
/// - A WRITEBACK form leaves the updated base in the address register after
///   the access, and the guest base is committed from there one word later.
///   The reserved register is deliberately absent from the fault/kick snapshot
///   (it is carrick's, not the guest's), so recovery at that one word could not
///   reconstruct the committed base. Writeback forms keep a borrowed,
///   snapshot-visible base scratch and their existing commit sequence.
/// - A VIRTUALIZED access needs a rewrite scratch that is spilled and restored
///   anyway, and one that names the reserved register cannot use it as the
///   address at all.
///
/// The base must also be readable as a register operand after the aperture
/// check, which rules out the context-slot bases (`x18`/`x28`/reserved) but
/// includes SP, whose `add`/extended-register forms accept `Rn = SP`.
fn reserved_biased_eligible(memory: super::types::MemoryAccess, base: BiasedBase) -> bool {
    memory.virtualization == super::types::MemoryVirtualization::None
        && memory.writeback == super::types::MemoryWriteback::None
        && matches!(base, BiasedBase::Register(_) | BiasedBase::StackPointer)
}

/// `add Xd, <Rn|SP>, Xm, uxtx #0` -- the extended-register form, so the same
/// encoder covers a GPR base and SP (which the shifted-register `add` cannot).
const fn add_extended_uxtx(destination: u32, base: BiasedBase, addend: u32) -> Option<u32> {
    let rn = match base {
        BiasedBase::Register(register) => register,
        BiasedBase::StackPointer => 31,
        _ => return None,
    };
    Some(0x8b20_0000 | (addend << 16) | (3 << 13) | (rn << 5) | destination)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the address builder carries the same emission and recovery context as its caller"
)]
fn emit_reserved_guest_address(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    memory: super::types::MemoryAccess,
    base: BiasedBase,
    recovery: &mut Vec<RecoveryEntry>,
    address: u32,
    action: BiasedMemoryRecovery,
) -> Result<(), DsrError> {
    let load_base = biased_base_load_word(base, address).ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            memory.word,
            "reserved biased memory has no base",
        )
    })?;
    match memory.effective_address {
        super::types::MemoryEffectiveAddress::Base => {
            emit_with_biased_recovery(assembler, entries, recovery, guest, load_base, action)?;
        }
        super::types::MemoryEffectiveAddress::Immediate(offset) => {
            // Stage the displacement in the RESERVED register, never in
            // physical x18. Darwin's custom-x18 ABI loses that register
            // asynchronously — measured ~897 zeroings per CPU-second, always
            // to 0 — so a four-word movz/movk chain there is a liveness
            // window wide enough to be hit constantly. A loss landing just
            // before the `lsl #48` chunk of a NEGATIVE displacement leaves
            // 0xffff_0000_0000_0000, i.e. an effective address of
            // `base - 2**48`, which is the exact fault signature this fixes.
            // `ldur x29, [sp, #-8]` sits in every Go arm64 epilogue, which is
            // why it reproduced constantly. The reserved register is dead
            // here and already carries the bias add below in the same form.
            emit_biased_materialize_u64(
                assembler,
                entries,
                recovery,
                guest,
                address,
                offset as u64,
                action,
            )?;
            let word = add_extended_uxtx(address, base, address).ok_or_else(|| {
                unsupported_action(
                    plan,
                    guest,
                    memory.word,
                    "reserved biased immediate has no register base",
                )
            })?;
            emit_with_biased_recovery(assembler, entries, recovery, guest, word, action)?;
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
            let index = (memory.word >> 16) & 0x1f;
            let rn = match base {
                BiasedBase::Register(register) => register,
                BiasedBase::StackPointer => 31,
                _ => {
                    return Err(unsupported_action(
                        plan,
                        guest,
                        memory.word,
                        "reserved biased register offset has no register base",
                    ));
                }
            };
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0x8b20_0000
                    | (index << 16)
                    | (option << 13)
                    | (u32::from(shift) << 10)
                    | (rn << 5)
                    | address,
                action,
            )?;
        }
    }
    Ok(())
}

/// The spill-free biased lowering keeps every live value in Darwin-stable
/// physical x19. The aperture check consumes the first effective-address
/// value, so only the cold invalid-address arm recomputes it for publication.
/// The in-aperture hot arm stays store-free, loses the former second `cbz`,
/// and never exposes state through Darwin's asynchronously cleared x18.
///
/// ```text
///   <effective guest address> -> x19
///   lsr x19, x19, #41
///   cbz x19, fast
/// slow:
///   <effective guest address> -> x19
///   str x19, [x28, #1200]
///   ldr x19, [x28, #1192]
///   add x19, <base>, x19
///   orr x19, x19, #1 << 47
///   b access
/// fast:
///   ldr x19, [x28, #1192]
///   add x19, <base>, x19
/// access:
///   <access, base = x19>
/// ```
#[allow(
    clippy::too_many_arguments,
    reason = "the spill-free lowering carries the same emission and recovery context as the general one"
)]
fn emit_reserved_biased_memory(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    memory: super::types::MemoryAccess,
    base: BiasedBase,
    host_bias: carrick_dsr::address::NativeHostBias,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let address = crate::gateway::RESERVED_SCRATCH;
    // Nothing is spilled, so there is no scratch to restore and no base to
    // commit; every recovery point below reduces to "resume the instruction".
    let action = BiasedMemoryRecovery {
        scratch_registers: [0; 4],
        scratch_count: 0,
        base_scratch: address,
        base,
        base_coordinate: BiasedBaseCoordinate::Guest,
        commit_base: false,
        virtual_x18_scratch: None,
        virtual_x28_scratch: None,
        virtual_reserved_scratch: None,
        host_bias,
        instruction_complete: false,
    };

    emit_reserved_guest_address(
        assembler, entries, plan, guest, memory, base, recovery, address, action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (address << 5) | address,
        action,
    )?; // lsr x19, effective, #BIASED_FAST_ADDRESS_BITS
    let fast = assembler.new_dynamic_label();
    let access = assembler.new_dynamic_label();
    emit_biased_cbz(assembler, entries, recovery, guest, address, fast, action)?;

    // Keeping the valid path store-free is part of the DSR hot-path contract:
    // only an address outside the flags-neutral fast window is published, and
    // recovery reports that guest value instead of the deliberately invalid
    // host FAR the tagged access below produces.
    emit_reserved_guest_address(
        assembler, entries, plan, guest, memory, base, recovery, address, action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf900_0000 | ((1200 / 8) << 10) | (28 << 5) | address,
        action,
    )?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_0000 | ((1192 / 8) << 10) | (28 << 5) | address,
        action,
    )?; // ldr x19, [x28, #1192]
    let bias_add = add_extended_uxtx(address, base, address).ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            memory.word,
            "reserved biased memory has no register base",
        )
    })?;
    emit_with_biased_recovery(assembler, entries, recovery, guest, bias_add, action)?;
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb251_0000 | (address << 5) | address,
        action,
    )?; // orr x19, x19, #1 << 47
    emit_biased_branch(assembler, entries, recovery, guest, access, action)?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>fast
    );
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf940_0000 | ((1192 / 8) << 10) | (28 << 5) | address,
        action,
    )?; // ldr x19, [x28, #1192]
    emit_with_biased_recovery(assembler, entries, recovery, guest, bias_add, action)?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>access
    );
    let rewritten = (memory.word & !(0x1f << 5)) | (address << 5);
    // The access is the last emitted word: there is no restore epilogue and
    // therefore no recovery point that has to report the instruction complete.
    emit_with_biased_recovery(assembler, entries, recovery, guest, rewritten, action)?;
    Ok(())
}

fn compact_biased_policy() -> CompactBiasedPolicy {
    static POLICY: std::sync::OnceLock<CompactBiasedPolicy> = std::sync::OnceLock::new();
    *POLICY.get_or_init(
        || match std::env::var("CARRICK_DSR_COMPACT_BIASED").as_deref() {
            Ok("0") => CompactBiasedPolicy::Off,
            Ok("nowriteback") => CompactBiasedPolicy::NoWriteback,
            _ => CompactBiasedPolicy::All,
        },
    )
}

fn compact_biased_form(
    memory: super::types::MemoryAccess,
    base: BiasedBase,
    host_bias: carrick_dsr::address::NativeHostBias,
) -> Option<CompactBiasedForm> {
    let policy = compact_biased_policy();
    if policy == CompactBiasedPolicy::Off {
        return None;
    }
    let bias_orr = host_bias.aperture_disjoint_orr_immediate()?;
    if memory.virtualization != super::types::MemoryVirtualization::None {
        return None;
    }
    let writeback = memory.writeback != super::types::MemoryWriteback::None;
    if writeback && policy == CompactBiasedPolicy::NoWriteback {
        return None;
    }
    match base {
        BiasedBase::Register(_) => {}
        // Stack-pointer bases cannot be ORR sources: they need one copy for
        // the aperture check and rebuild SP in whichever arm executes. They
        // never write back in this slice; virtual bases keep the general path.
        BiasedBase::StackPointer if !writeback => {}
        _ => return None,
    }
    let immediate = match memory.effective_address {
        super::types::MemoryEffectiveAddress::Base => 0,
        super::types::MemoryEffectiveAddress::Immediate(immediate) => {
            if immediate < 0 {
                return None;
            }
            let immediate = immediate as u64;
            if immediate >= carrick_dsr::address::BIASED_GUEST_UNDERFLOW_WINDOW {
                return None;
            }
            immediate
        }
        super::types::MemoryEffectiveAddress::RegisterOffset { .. } => return None,
    };
    Some(CompactBiasedForm {
        bias_orr,
        base,
        immediate,
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_compact_biased_memory(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    memory: super::types::MemoryAccess,
    host_bias: carrick_dsr::address::NativeHostBias,
    recovery: &mut Vec<RecoveryEntry>,
    form: CompactBiasedForm,
) -> Result<(), DsrError> {
    // A writeback form leaves the updated base in the scratch after the
    // access and commits the guest base from there, which recovery
    // reconstructs by reading the scratch out of the fault snapshot. The
    // reserved register is deliberately absent from that snapshot, so only
    // non-writeback accesses can own it outright; the rest keep borrowing.
    let reserved =
        reserved_scratch_enabled() && memory.writeback == super::types::MemoryWriteback::None;
    let scratch = if reserved {
        crate::gateway::RESERVED_SCRATCH
    } else {
        biased_scratch_registers(memory.word, guest, &[], 1)
            .and_then(|registers| registers.first().copied())
            .ok_or_else(|| {
                unsupported_action(plan, guest, memory.word, "no safe compact biased scratch")
            })?
    };
    let (immr, imms) = form.bias_orr;

    // Spill the single borrowed scratch. Its guest value now lives in slot
    // 1120, so re-executing from the instruction start stays idempotent and no
    // recovery action is needed until a word can clobber guest state. The
    // reserved register holds no guest value and is never spilled.
    if !reserved {
        emit_word(
            assembler,
            entries,
            guest,
            0xf900_0000 | ((BIASED_SCRATCH_CONTEXT_OFFSETS[0] / 8) << 10) | (28 << 5) | scratch,
        )?;
    }
    let mut action = BiasedMemoryRecovery {
        scratch_registers: if reserved { [0; 4] } else { [scratch, 0, 0, 0] },
        scratch_count: u8::from(!reserved),
        base_scratch: scratch,
        base: form.base,
        base_coordinate: BiasedBaseCoordinate::Guest,
        commit_base: false,
        virtual_x18_scratch: None,
        virtual_x28_scratch: None,
        virtual_reserved_scratch: None,
        host_bias,
        instruction_complete: false,
    };

    // The register whose value is the guest base for the aperture check and
    // the ORR: the base register itself, or the scratch after copying SP.
    let checked_base = match form.base {
        BiasedBase::Register(register) => register,
        BiasedBase::StackPointer => {
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0x9100_03e0 | scratch, // add xS, sp, #0
                action,
            )?;
            scratch
        }
        _ => {
            return Err(unsupported_action(
                plan,
                guest,
                memory.word,
                "compact biased memory accepted a non-register base",
            ));
        }
    };

    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (checked_base << 5) | scratch,
        action,
    )?; // lsr scratch, base, #BIASED_FAST_ADDRESS_BITS
    let fast = assembler.new_dynamic_label();
    let access = assembler.new_dynamic_label();
    emit_biased_cbz(assembler, entries, recovery, guest, scratch, fast, action)?;

    // Slow path: publish the guest effective address for fault reporting,
    // then tag the base so the access faults on an unmappable host address.
    let immediate_low = u32::try_from(form.immediate & 0xfff).map_err(|_| {
        DsrError::BlockPolicy("compact biased immediate low bits exceed u32".to_string())
    })?;
    let immediate_high = u32::try_from(form.immediate >> 12).map_err(|_| {
        DsrError::BlockPolicy("compact biased immediate high bits exceed u32".to_string())
    })?;
    let slow_base = match form.base {
        BiasedBase::Register(register) => register,
        BiasedBase::StackPointer => 31,
        _ => {
            return Err(unsupported_action(
                plan,
                guest,
                memory.word,
                "compact biased memory accepted a non-register base",
            ));
        }
    };
    if form.immediate == 0 {
        let word = match form.base {
            BiasedBase::Register(register) => 0xaa00_03e0 | (register << 16) | scratch,
            BiasedBase::StackPointer => 0x9100_03e0 | scratch,
            _ => unreachable!("compact base validated above"),
        };
        emit_with_biased_recovery(assembler, entries, recovery, guest, word, action)?;
    } else if immediate_high != 0 {
        // The first ADD reads the architectural base (including SP); the
        // second extends the same stable scratch with the low twelve bits.
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0x9140_0000 | (immediate_high << 10) | (slow_base << 5) | scratch,
            action,
        )?;
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0x9100_0000 | (immediate_low << 10) | (scratch << 5) | scratch,
            action,
        )?;
    } else {
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0x9100_0000 | (immediate_low << 10) | (slow_base << 5) | scratch,
            action,
        )?;
    }
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xf900_0000 | ((1200 / 8) << 10) | (28 << 5) | scratch,
        action,
    )?; // publish the guest effective address
    if form.base == BiasedBase::StackPointer {
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0x9100_03e0 | scratch, // add scratch, sp, #0
            action,
        )?;
    }
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb251_0000
            | (if form.base == BiasedBase::StackPointer {
                scratch
            } else {
                checked_base
            } << 5)
            | scratch,
        action,
    )?; // tagged invalid host base
    emit_biased_branch(assembler, entries, recovery, guest, access, action)?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>fast
    );
    if form.base == BiasedBase::StackPointer {
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0x9100_03e0 | scratch, // add scratch, sp, #0
            action,
        )?;
    }
    emit_with_biased_recovery(
        assembler,
        entries,
        recovery,
        guest,
        0xb240_0000
            | (immr << 16)
            | (imms << 10)
            | (if form.base == BiasedBase::StackPointer {
                scratch
            } else {
                checked_base
            } << 5)
            | scratch,
        action,
    )?; // orr scratch, base, #bias

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>access
    );
    let rewritten = (memory.word & !(0x1f << 5)) | (scratch << 5);
    emit_with_biased_recovery(assembler, entries, recovery, guest, rewritten, action)?;
    action.instruction_complete = true;

    if memory.writeback != super::types::MemoryWriteback::None {
        // The access wrote the updated HOST address back into the scratch;
        // recovery (and the emitted commit) rebuild the guest base with a
        // full-width subtract, which is exact for every wrap and overhang.
        action.base_coordinate = BiasedBaseCoordinate::Host;
        action.commit_base = true;
        let BiasedBase::Register(base_register) = form.base else {
            return Err(unsupported_action(
                plan,
                guest,
                memory.word,
                "compact biased writeback requires a register base",
            ));
        };
        // The architectural base is the final destination and is Darwin
        // stable, so it can stage the full-width bias without another
        // borrowed scratch. Recovery throughout this completed window derives
        // the final guest base from the still-live host-coordinate `scratch`,
        // overwriting any partially materialized base value.
        emit_biased_materialize_u64(
            assembler,
            entries,
            recovery,
            guest,
            base_register,
            host_bias.get(),
            action,
        )?;
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xcb00_0000 | (base_register << 16) | (scratch << 5) | base_register,
            action,
        )?; // sub xBASE, xS, xBASE
    }

    if !reserved {
        emit_with_biased_recovery(
            assembler,
            entries,
            recovery,
            guest,
            0xf940_0000 | ((BIASED_SCRATCH_CONTEXT_OFFSETS[0] / 8) << 10) | (28 << 5) | scratch,
            action,
        )?; // restore the borrowed scratch
    }
    Ok(())
}

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
    if let Some(form) = compact_biased_form(memory, base, host_bias) {
        return emit_compact_biased_memory(
            assembler, entries, plan, guest, memory, host_bias, recovery, form,
        );
    }
    if reserved_scratch_enabled() && reserved_biased_eligible(memory, base) {
        return emit_reserved_biased_memory(
            assembler, entries, plan, guest, memory, base, host_bias, recovery,
        );
    }
    let BiasedVirtualRewrite {
        word: mut rewritten,
        x18: virtual_x18_scratch,
        x28: virtual_x28_scratch,
        reserved: virtual_reserved_scratch,
    } = rewritten_biased_virtual_word(memory, guest)?;
    let mut scratch_registers = [0_u32; 4];
    let mut scratch_count = 0_usize;
    for register in [
        virtual_x18_scratch,
        virtual_x28_scratch,
        virtual_reserved_scratch,
    ]
    .into_iter()
    .flatten()
    {
        if !scratch_registers[..scratch_count].contains(&register) {
            scratch_registers[scratch_count] = register;
            scratch_count += 1;
        }
    }
    // The bias scratch holds the guest effective address and then the host
    // bias; it is dead at every recovery point, so the reserved register can
    // take that role even in the forms that still need a snapshot-visible base
    // scratch (writeback commits read the base scratch out of the snapshot).
    // That halves what this path spills.
    let borrowed = usize::from(!reserved_scratch_enabled()) + 1;
    let extra = biased_scratch_registers(
        memory.word,
        guest,
        &scratch_registers[..scratch_count],
        borrowed,
    )
    .ok_or_else(|| unsupported_action(plan, guest, memory.word, "no safe biased memory scratch"))?;
    let base_scratch = extra[0];
    let bias_scratch = if reserved_scratch_enabled() {
        crate::gateway::RESERVED_SCRATCH
    } else {
        extra[1]
    };
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
        virtual_reserved_scratch: None,
        host_bias,
        instruction_complete: false,
    };
    for (virtual_register, scratch) in [
        (18_u32, virtual_x18_scratch),
        (28, virtual_x28_scratch),
        (crate::gateway::RESERVED_SCRATCH, virtual_reserved_scratch),
    ] {
        if let Some(scratch) = scratch {
            let offset = virtual_snapshot_offset(virtual_register).ok_or_else(|| {
                DsrError::BlockPolicy(format!(
                    "biased memory virtualized x{virtual_register} has no context slot"
                ))
            })?;
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | scratch,
                action,
            )?;
            match virtual_register {
                18 => action.virtual_x18_scratch = Some(scratch),
                28 => action.virtual_x28_scratch = Some(scratch),
                _ => action.virtual_reserved_scratch = Some(scratch),
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
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (bias_scratch << 5) | base_scratch,
        action,
    )?; // lsr base_scratch, effective, #BIASED_FAST_ADDRESS_BITS
    let fast = assembler.new_dynamic_label();
    let access = assembler.new_dynamic_label();
    emit_biased_cbz(
        assembler,
        entries,
        recovery,
        guest,
        base_scratch,
        fast,
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
        0xb251_0000 | (base_scratch << 5) | base_scratch,
        action,
    )?; // orr base, base, #1 << 47
    emit_biased_branch(assembler, entries, recovery, guest, access, action)?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>fast
    );
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

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>access
    );
    emit_with_biased_recovery(assembler, entries, recovery, guest, rewritten, action)?;
    action.instruction_complete = true;

    let has_writeback = memory.writeback != super::types::MemoryWriteback::None;
    if has_writeback {
        action.base_coordinate = BiasedBaseCoordinate::Host;
        action.commit_base = true;
    }
    for (virtual_register, scratch) in [
        (18_u32, virtual_x18_scratch),
        (28, virtual_x28_scratch),
        (crate::gateway::RESERVED_SCRATCH, virtual_reserved_scratch),
    ] {
        if let Some(scratch) = scratch {
            let offset = virtual_snapshot_offset(virtual_register).ok_or_else(|| {
                DsrError::BlockPolicy(format!(
                    "biased memory virtualized x{virtual_register} has no context slot"
                ))
            })?;
            emit_with_biased_recovery(
                assembler,
                entries,
                recovery,
                guest,
                0xf900_0000 | ((offset / 8) << 10) | (28 << 5) | scratch,
                action,
            )?;
            match virtual_register {
                18 => action.virtual_x18_scratch = None,
                28 => action.virtual_x28_scratch = None,
                _ => action.virtual_reserved_scratch = None,
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
            BiasedBase::VirtualReserved => {
                0xf900_0000
                    | ((crate::gateway::CTX_GUEST_RESERVED_SCRATCH / 8) << 10)
                    | (28 << 5)
                    | base_scratch
            }
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
        crate::gateway::RESERVED_SCRATCH => BiasedBase::VirtualReserved,
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
        virtual_reserved_scratch: None,
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
        0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (base_scratch << 5) | bias_scratch,
        action,
    )?; // lsr bias_scratch, guest_address, #BIASED_FAST_ADDRESS_BITS
    let fast = assembler.new_dynamic_label();
    let access = assembler.new_dynamic_label();
    emit_biased_cbz(
        assembler,
        entries,
        recovery,
        guest,
        bias_scratch,
        fast,
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
        0xb251_0000 | (base_scratch << 5) | base_scratch,
        action,
    )?; // orr address, address, #1 << 47
    emit_biased_branch(assembler, entries, recovery, guest, access, action)?;

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>fast
    );
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

    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; =>access
    );
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
    assemble_block_inner(
        plan,
        None,
        mode,
        DirectExitEmissionPolicy::PrivateGateway,
        None,
    )?
    .publish(cache)
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
    assemble_block_inner(
        plan,
        Some(guard),
        mode,
        DirectExitEmissionPolicy::PrivateGateway,
        None,
    )?
    .publish(cache)
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
    let assembled = assemble_block_inner(
        plan,
        Some(guard),
        mode,
        DirectExitEmissionPolicy::PrivateGateway,
        Some(&mut recording),
    )?;
    let artifact = recording
        .finish(
            assembled.instruction_words(),
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
        DirectExitEmissionPolicy::PortableUnitAuthority,
        Some(&mut recording),
    )?;
    recording.finish(
        assembled.instruction_words(),
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
    policy: DirectExitEmissionPolicy,
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
    emit_direct_exit(
        assembler,
        entries,
        map_guest,
        source_guest,
        target,
        None,
        recovery,
        policy,
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
    policy: DirectExitEmissionPolicy,
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
        policy,
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
            policy,
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
        GuestPcWidth::Narrow,
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
    policy: DirectExitEmissionPolicy,
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
            policy,
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
        policy,
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
            policy,
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
    direct_exit_policy: DirectExitEmissionPolicy,
    mut recording: Option<&mut ArtifactRecording>,
) -> Result<AssembledBlock, DsrError> {
    let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
    // Count the fused segments too: a superblock maps several segments' worth
    // of words, and translation time is a real cost here -- deep fusion already
    // taxes it (see `block::SUPERBLOCK_SEGMENT_LIMIT`), so do not add
    // reallocation on top of that.
    let mut entries = Vec::with_capacity(
        plan.instructions.len()
            + plan
                .extensions
                .iter()
                .map(|extension| extension.instructions.len() + 6)
                .sum::<usize>()
            + 8,
    );
    let mut direct_links = Vec::with_capacity(plan.extensions.len() + 2);
    let mut recovery = Vec::new();
    // No `str wzr, [x28, #1152]` here any more: `gateway_aarch64.S` claims phase
    // zero as its last act before branching in, so a block does not re-claim it.
    // That store was 15.1% of all sampled JIT instructions -- one per block
    // entry, against one per GATEWAY entry now, and a direct-linked chain runs
    // many blocks per gateway entry.
    let mut trusted_entry: Option<CacheOffset> = None;
    let lean_guard = lean_generation_guard_enabled();
    let stale = guard.map(|_| assembler.new_dynamic_label());
    if !lean_guard {
        // x17 is the internal indirect-edge register. Its guest value is saved
        // at every block exit and restored before either the generation guard
        // or the first guest instruction executes.
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
    }
    if let (Some(guard), Some(stale)) = (guard, stale)
        && !lean_guard
    {
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
    if let (Some(guard), Some(stale)) = (guard, stale)
        && lean_guard
    {
        // The guard is the authoritative stale-code check, so it runs on every
        // block entry -- but it borrows NOTHING from the guest to do so.
        //
        // Physical x17 is dead here: every exit stores guest x17 to
        // `snapshot.x[17]` (and to slot 1128, which recovery reads), and the
        // reload below re-establishes it before the first guest instruction.
        // Physical x19 belongs to carrick for the whole of translated
        // execution (`gateway::RESERVED_SCRATCH`) -- `_carrick_dsr_enter_raw`
        // never loads the guest's value into it and the signal handler's
        // snapshot deliberately never captures it. Comparing with EOR/CBNZ
        // rather than CMP/B.NE writes no flags, so guest NZCV is untouched
        // too.
        //
        // Together those delete the guard's three spills and their four
        // reloads: the prologue is store-throughput-bound, and five stores
        // become two (the gateway phase, and the guard's own generation
        // publish).
        const _: () = assert!(crate::gateway::RESERVED_SCRATCH == 19);
        let guard_start = current_offset(&assembler)?;
        match guard {
            GenerationGuard::Absolute { address, expected } => {
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    plan.start,
                    crate::gateway::RESERVED_SCRATCH,
                    MaterializedValue::Process(ProcessValue::GenerationAddress, address),
                    recording.as_deref_mut(),
                )?;
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldar x19, [x19]
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
                    ; ldr x19, [x28, super::gateway::CTX_GENERATION_BINDINGS]
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
                    ; add x19, x19, x17, LSL #4
                );
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldp x19, x17, [x19]
                );
                map_next(&assembler, &mut entries, plan.start)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldar x19, [x19]
                );
            }
        }
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; eor x19, x19, x17
        );
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; cbnz x19, =>stale
        );
        // Trusted second entry point (private Absolute-guarded blocks only):
        // patched direct links land here, past the guard, because Phase 2a's
        // eager severing invalidates the links themselves when the target's
        // page bumps. The entrant's x17 holds guest x17 (dead: slots 136 and
        // 1128 are authoritative at every exit), so re-materialize this
        // block's generation into it -- the guarded fall-through rewrites the
        // identical value -- and share the publish and x17 reload below.
        if recording.is_none()
            && let GenerationGuard::Absolute { expected, .. } = guard
        {
            trusted_entry = Some(current_offset(&assembler)?);
            let mut value = expected.get();
            emit_word(
                &mut assembler,
                &mut entries,
                plan.start,
                0xd280_0011 | (((value & 0xffff) as u32) << 5),
            )?;
            let mut hw = 1_u32;
            value >>= 16;
            while value != 0 {
                let half = (value & 0xffff) as u32;
                if half != 0 {
                    emit_word(
                        &mut assembler,
                        &mut entries,
                        plan.start,
                        0xf280_0011 | (hw << 21) | (half << 5),
                    )?;
                }
                value >>= 16;
                hw += 1;
            }
        }
        // A direct-linked chain can enter the gateway from a different block
        // than the one that began this translated run. Publish this block's
        // generation so sensitive-exit metadata is resolved against the block
        // that actually produced the exit.
        map_next(&assembler, &mut entries, plan.start)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x28, super::gateway::CTX_GENERATION]
        );
        let guard_end = current_offset(&assembler)?;
        for offset in (guard_start.get()..guard_end.get()).step_by(4) {
            recovery.push(RecoveryEntry {
                cache: CacheOffset::published(offset),
                action: RecoveryAction::RestoreGuestX17,
            });
        }
    }
    if lean_guard {
        // x17 is the internal indirect-edge register, and the guard above
        // spends it. Its guest value is saved at every block exit and is
        // restored here, before the first guest instruction executes.
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
    }
    if !plan.extensions.is_empty() && matches!(plan.exit, PlannedExit::ExclusiveRegion { .. }) {
        // The planner never builds this (it refuses to fuse across or into a
        // fused exclusive region), and the region emitter owns the whole block,
        // so silently dropping the segments would emit a block that claims a
        // guest range it never translated. Fail closed instead.
        return Err(DsrError::BlockPolicy(format!(
            "fused segments cannot follow an exclusive region at guest PC 0x{:x}",
            plan.start.raw()
        )));
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
            direct_exit_policy,
            recording.as_deref_mut(),
        )?;
    } else {
        // Superblock formation: `plan.extensions` are guest blocks fused after
        // this one, each entered through its predecessor's conditional
        // fall-through (see `block::PlanExtension`). They are emitted as ONE
        // stream so the prologue above, and the guest-x17 save below, are paid
        // once for the whole chain instead of once per guest block.
        let mut items: Vec<EmitItem<'_>> = Vec::with_capacity(
            plan.instructions.len()
                + plan
                    .extensions
                    .iter()
                    .map(|extension| extension.instructions.len() + 1)
                    .sum::<usize>(),
        );
        items.extend(plan.instructions.iter().map(EmitItem::Instruction));
        let mut previous_exit = plan.exit;
        for extension in &plan.extensions {
            items.push(EmitItem::InternalEdge(previous_exit));
            items.extend(extension.instructions.iter().map(EmitItem::Instruction));
            previous_exit = extension.exit;
        }
        let mut pending_taken = Vec::with_capacity(plan.extensions.len());
        for item in items {
            let instruction = match item {
                EmitItem::Instruction(instruction) => instruction,
                EmitItem::InternalEdge(exit) => {
                    pending_taken.push(emit_internal_fallthrough_edge(
                        &mut assembler,
                        &mut entries,
                        &mut recovery,
                        exit,
                    )?);
                    continue;
                }
            };
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
                            (18, 144),
                            (28, 224),
                            DualCommit::None,
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
                            (18, 144),
                            (28, 224),
                            DualCommit::First,
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::Reserved => {
                        emit_virtualized_register(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            crate::gateway::RESERVED_SCRATCH,
                            crate::gateway::CTX_GUEST_RESERVED_SCRATCH,
                            &mut recovery,
                        )?;
                        continue;
                    }
                    super::types::MemoryVirtualization::ReservedPair { other } => {
                        emit_dual_virtual(
                            &mut assembler,
                            &mut entries,
                            plan,
                            instruction.guest,
                            memory.word,
                            reserved_virtual_slot(),
                            virtual_slot(plan, instruction.guest, memory.word, other)?,
                            DualCommit::Both,
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
                if memory.base == super::types::MemoryBase::VirtualReserved {
                    emit_virtualized_register(
                        &mut assembler,
                        &mut entries,
                        plan,
                        instruction.guest,
                        memory.word,
                        crate::gateway::RESERVED_SCRATCH,
                        crate::gateway::CTX_GUEST_RESERVED_SCRATCH,
                        &mut recovery,
                    )?;
                    continue;
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
                    (18, 144),
                    (28, 224),
                    DualCommit::None,
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
                    (18, 144),
                    (28, 224),
                    DualCommit::First,
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
                    (18, 144),
                    (28, 224),
                    DualCommit::Second,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedReserved { word, .. } => {
                emit_virtualized_register(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    crate::gateway::RESERVED_SCRATCH,
                    crate::gateway::CTX_GUEST_RESERVED_SCRATCH,
                    &mut recovery,
                )?;
                continue;
            }
            InstAction::VirtualizedReservedPair { word, other, .. } => {
                emit_dual_virtual(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    word,
                    reserved_virtual_slot(),
                    virtual_slot(plan, instruction.guest, word, other)?,
                    DualCommit::Both,
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

        // The LAST segment's exit terminates the emitted block; every earlier
        // segment's exit was consumed above as an internal edge.
        let terminal = plan.terminal_exit();
        let exit_guest = terminal.guest_pc();
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
        if let PlannedExit::Syscall { resume, .. } = terminal {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                resume,
                None,
                1,
                GatewayKind::Syscall,
                recording.as_deref_mut(),
                GuestPcWidth::Narrow,
            )?;
        } else if let PlannedExit::Direct { word, exit, .. } = terminal {
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
                emit_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.target,
                    committed_link,
                    &mut recovery,
                    direct_exit_policy,
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
                    recovery.push(RecoveryEntry {
                        cache: current_offset(&assembler)?,
                        action: RecoveryAction::RestoreGuestX17,
                    });
                    emit_word(
                        &mut assembler,
                        &mut entries,
                        exit_guest,
                        0xf940_0000 | ((offset / 8) << 10) | (28 << 5) | 17,
                    )?;
                }
                if virtual_offset.is_some() {
                    recovery.push(RecoveryEntry {
                        cache: current_offset(&assembler)?,
                        action: RecoveryAction::RestoreGuestX17,
                    });
                }
                emit_word(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    relocated_direct_word(word, exit, virtual_offset.map(|_| 17))?,
                )?;
                if virtual_offset.is_some() {
                    recovery.push(RecoveryEntry {
                        cache: current_offset(&assembler)?,
                        action: RecoveryAction::RestoreGuestX17,
                    });
                }
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
                if virtual_offset.is_some() {
                    recovery.push(RecoveryEntry {
                        cache: taken_slot,
                        action: RecoveryAction::RestoreGuestX17,
                    });
                }
                map_next(&assembler, &mut entries, exit_guest)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; b =>taken_stub
                );
                let fall_stub_start = current_offset(&assembler)?;
                emit_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.resume,
                    None,
                    &mut recovery,
                    direct_exit_policy,
                    recording.as_deref_mut(),
                )?;
                let fall_stub_end = current_offset(&assembler)?;
                if virtual_offset.is_some()
                    && direct_exit_policy == DirectExitEmissionPolicy::PrivateGateway
                {
                    record_guest_x17_recovery_range(&mut recovery, fall_stub_start, fall_stub_end);
                }
                direct_links.push(DirectLink {
                    slot: fall_slot,
                    source: exit_guest,
                    target: exit.resume,
                    kind: DirectLinkKind::ConditionalFallthrough,
                    stub: DirectStubEnvelope {
                        start: fall_stub_start,
                        end: fall_stub_end,
                    },
                });
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; =>taken_stub
                );
                let taken_stub_start = current_offset(&assembler)?;
                emit_direct_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit_guest,
                    exit.target,
                    None,
                    &mut recovery,
                    direct_exit_policy,
                    recording.as_deref_mut(),
                )?;
                let taken_stub_end = current_offset(&assembler)?;
                if virtual_offset.is_some()
                    && direct_exit_policy == DirectExitEmissionPolicy::PrivateGateway
                {
                    record_guest_x17_recovery_range(
                        &mut recovery,
                        taken_stub_start,
                        taken_stub_end,
                    );
                }
                direct_links.push(DirectLink {
                    slot: taken_slot,
                    source: exit_guest,
                    target: exit.target,
                    kind: DirectLinkKind::ConditionalTaken,
                    stub: DirectStubEnvelope {
                        start: taken_stub_start,
                        end: taken_stub_end,
                    },
                });
            }
        } else if let PlannedExit::Indirect { exit, .. } = terminal {
            emit_indirect_exit(
                &mut assembler,
                &mut entries,
                plan,
                exit_guest,
                exit,
                &mut recovery,
                recording.as_deref_mut(),
            )?;
        } else if let PlannedExit::Sensitive { word, exit, .. } = terminal {
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
                    direct_exit_policy,
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
                    GuestPcWidth::Narrow,
                )?;
            }
        } else if let PlannedExit::Continue { target, .. } = terminal {
            let slot = current_offset(&assembler)?;
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
            let stub_start = current_offset(&assembler)?;
            emit_direct_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit_guest,
                target,
                None,
                &mut recovery,
                direct_exit_policy,
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
        } else if let PlannedExit::Unsupported { .. } = terminal {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit_guest,
                Some(exit_guest),
                7,
                GatewayKind::Unsupported,
                recording.as_deref_mut(),
                GuestPcWidth::Narrow,
            )?;
        } else {
            return Err(DsrError::BlockPolicy(
                "virtualized register action escaped the DSR copy stream".to_string(),
            ));
        }
        // Held-back taken-edge stubs for the fused conditionals, out of line
        // past the terminal exit so the fall-through stream stays dense.
        for edge in pending_taken {
            emit_internal_taken_stub(
                &mut assembler,
                &mut entries,
                &mut direct_links,
                &mut recovery,
                edge,
                direct_exit_policy,
                recording.as_deref_mut(),
            )?;
        }
    }
    if let Some(stale) = stale {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>stale
        );
        // Under the lean guard there is nothing to unwind: it spent only
        // registers that are already carrick's at block entry -- dead x17 and
        // host-owned x19 -- and wrote no flags, so guest x16, guest NZCV and
        // the guest x17 in `snapshot.x[17]` are exactly what the common
        // gateway expects to find. Reloading slots 936/1120/1128 there would
        // be actively WRONG: the lean prologue never writes them, so they hold
        // whatever a previous memory lowering or gateway entry left behind.
        let stale_start = current_offset(&assembler)?;
        if !lean_guard {
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
        }
        let exit_start = current_offset(&assembler)?;
        emit_gateway_exit(
            &mut assembler,
            &mut entries,
            plan.start,
            plan.start,
            Some(plan.start),
            2,
            GatewayKind::Direct,
            recording.as_deref_mut(),
            GuestPcWidth::Narrow,
        )?;
        if lean_guard {
            // The stale edge builds its typed exit in x17, so a kick landing
            // in it still needs guest x17 rebuilt from slot 1128.
            let exit_end = current_offset(&assembler)?;
            for offset in (exit_start.get()..exit_end.get()).step_by(4) {
                recovery.push(RecoveryEntry {
                    cache: CacheOffset::published(offset),
                    action: RecoveryAction::RestoreGuestX17,
                });
            }
        }
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
    #[cfg(test)]
    let words = bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect();
    let map = InstructionMap::new(entries)?;
    Ok(AssembledBlock {
        trusted_entry,
        instruction_bytes: bytes,
        #[cfg(test)]
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

#[allow(
    clippy::too_many_arguments,
    reason = "recovery consumes every per-channel saved register the signal handler preserves"
)]
pub fn recover_rewrite_state(
    snapshot: &mut crate::snapshot::NativeUcontextSnapshot,
    action: RecoveryAction,
    saved_scratch: u64,
    saved_context_scratch: u64,
    saved_generation_pstate: u64,
    saved_indirect_x15: u64,
    saved_indirect_x30: u64,
    physical_reserved: u64,
) -> Result<(), crate::types::DsrError> {
    if let RecoveryAction::RestoreDirectBinding {
        capture_progress,
        committed_link,
        ..
    } = action
    {
        snapshot.x[17] = saved_context_scratch;
        match capture_progress {
            DirectBindingCaptureProgress::None => {}
            DirectBindingCaptureProgress::X15 => {
                snapshot.x[15] = saved_indirect_x15;
            }
            DirectBindingCaptureProgress::X15X16 => {
                snapshot.x[15] = saved_indirect_x15;
                snapshot.x[16] = saved_scratch;
            }
            DirectBindingCaptureProgress::X15X16X30 => {
                snapshot.x[15] = saved_indirect_x15;
                snapshot.x[16] = saved_scratch;
                snapshot.x[30] = saved_indirect_x30;
            }
            DirectBindingCaptureProgress::Complete => {
                snapshot.x[15] = saved_indirect_x15;
                snapshot.x[16] = saved_scratch;
                snapshot.x[30] = saved_indirect_x30;
                snapshot.pstate = saved_generation_pstate;
            }
        }
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
        let virtual_reserved = recovery
            .virtual_reserved_scratch
            .map(|register| {
                usize::try_from(register)
                    .ok()
                    .and_then(|index| snapshot.x.get(index).copied())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "biased virtual reserved scratch x{register} is outside snapshot"
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
        if let Some(value) = virtual_reserved {
            snapshot.x[crate::gateway::RESERVED_SCRATCH as usize] = value;
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
                BiasedBase::VirtualReserved => {
                    snapshot.x[crate::gateway::RESERVED_SCRATCH as usize] = value;
                }
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
        RecoveryAction::CommitReservedResident { virtual_register } => {
            let index = usize::try_from(virtual_register).map_err(|_| {
                crate::types::DsrError::CachePolicy(
                    "reserved-resident commit register overflow".to_string(),
                )
            })?;
            let slot = snapshot.x.get_mut(index).ok_or_else(|| {
                crate::types::DsrError::CachePolicy(format!(
                    "reserved-resident commit x{virtual_register} is outside snapshot"
                ))
            })?;
            *slot = physical_reserved;
            return Ok(());
        }
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
        RecoveryAction::RestoreIndirectLean => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[17] = saved_context_scratch;
            return Ok(());
        }
        RecoveryAction::RestoreIndirectLeanCall => {
            snapshot.x[15] = saved_indirect_x15;
            snapshot.x[17] = saved_context_scratch;
            snapshot.x[30] = saved_indirect_x30;
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
        RecoveryAction::CommitDualVirtualPairAndRestore {
            x18_scratch,
            x28_scratch,
            context_scratch,
            first_register,
            second_register,
        } => {
            // Read both results BEFORE the scratch restore below overwrites
            // them, then commit both, mirroring the single-register arm.
            let mut committed = [(first_register, 0_u64); 2];
            for (slot, (virtual_register, scratch)) in committed.iter_mut().zip([
                (first_register, x18_scratch),
                (second_register, x28_scratch),
            ]) {
                let index = usize::try_from(scratch)
                    .ok()
                    .filter(|index| *index < snapshot.x.len())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "dual virtual result x{scratch} is outside snapshot"
                        ))
                    })?;
                *slot = (virtual_register, snapshot.x[index]);
            }
            for (register, value) in [
                (x18_scratch, saved_indirect_x15),
                (x28_scratch, saved_scratch),
                (context_scratch, saved_context_scratch),
            ] {
                let index = usize::try_from(register)
                    .ok()
                    .filter(|index| *index < snapshot.x.len())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "dual virtual scratch x{register} is outside snapshot"
                        ))
                    })?;
                snapshot.x[index] = value;
            }
            for (virtual_register, value) in committed {
                let index = usize::try_from(virtual_register)
                    .ok()
                    .filter(|index| *index < snapshot.x.len())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(format!(
                            "dual virtual destination x{virtual_register} is outside snapshot"
                        ))
                    })?;
                snapshot.x[index] = value;
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
        CodeGeneration, CounterDestination, CounterRead, DirectExit, DirectKind, IndirectExit,
        IndirectKind,
    };
    use super::*;

    #[test]
    fn direct_instruction_bytes_are_default_on_with_an_exact_opt_out() {
        assert!(direct_instruction_bytes_enabled_from(None));
        assert!(direct_instruction_bytes_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!direct_instruction_bytes_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

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
            extensions: Vec::new(),
        }
    }

    /// Every word a guarded block emits before its first copied guest
    /// instruction: the gateway-phase publish, the generation guard, and the
    /// guest-x17 restore.
    ///
    /// The cut is the first emitted `nop`, which is `copy_plan`'s first guest
    /// instruction. A guest-PC filter could not make the cut: the prologue is
    /// deliberately mapped to `plan.start`, the same guest PC the first copied
    /// instruction carries.
    fn guarded_prologue_words(guard: GenerationGuard) -> Vec<u32> {
        let assembled = assemble_block_inner(
            &copy_plan(),
            Some(guard),
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble guarded block");
        let first_guest = assembled
            .words
            .iter()
            .position(|word| *word == 0xd503_201f)
            .expect("first copied guest instruction");
        assembled.words[..first_guest].to_vec()
    }

    /// The context byte slot a 64-bit `str Xt, [x28, #imm]` writes.
    fn context_store_slot(word: u32) -> Option<u32> {
        ((word & 0xFFC0_03E0) == 0xF900_0380).then(|| ((word >> 10) & 0xFFF) * 8)
    }

    /// The context byte slot a 64-bit `ldr Xt, [x28, #imm]` reads.
    fn context_load_slot(word: u32) -> Option<u32> {
        ((word & 0xFFC0_03E0) == 0xF940_0380).then(|| ((word >> 10) & 0xFFF) * 8)
    }

    /// One virtualized guest instruction followed by a syscall exit, with no
    /// generation guard, so the template's words sit at the front of the
    /// assembled block.
    fn single_virtual_block(word: u32) -> (AssembledBlock, BlockPlan) {
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify single-virtual fixture word");
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action,
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
            extensions: Vec::new(),
        };
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble single-virtual fixture block");
        (assembled, plan)
    }

    /// `ldrh w0, [x19, w23, uxtw #1]` — a read-only use of the reserved
    /// register as a base. The resident template is two words: materialize
    /// guest x19 into the (carrick-owned) physical x19 from its context slot,
    /// then run the original word unchanged. No spills, no store-back, and no
    /// recovery entries: every template word maps to the instruction's guest
    /// PC and resuming there re-executes it from the authoritative slot.
    #[test]
    fn reserved_resident_read_only_base_is_two_words_with_no_recovery() {
        let word = 0x7877_5A60;
        assert_eq!(
            bad64::decode(word, 0x4000)
                .expect("fixture decodes")
                .to_string(),
            "ldrh w0, [x19, w23, uxtw #0x1]"
        );
        let (assembled, _plan) = super::tests::single_virtual_block(word);
        assert_eq!(
            assembled.words[0], 0xF940_4791,
            "unguarded entry restores guest x17"
        );
        let expected = [
            0xF940_4F93, // ldr x19, [x28, #152]
            word,
        ];
        assert_eq!(
            &assembled.words[1..3],
            &expected,
            "resident read-only template words: {:#010x?}",
            &assembled.words[..4.min(assembled.words.len())]
        );
        assert_eq!(
            assembled.recovery.len(),
            1,
            "the only recovery entry is the block entry's x17 restore: {:?}",
            assembled.recovery
        );
        assert_eq!(
            assembled.recovery[0].action,
            RecoveryAction::RestoreGuestX17
        );
    }

    /// `mov x28, x26` — a write-only definition of virtualized guest x28.
    /// The resident template renames the destination onto physical x19 and
    /// commits the slot; the only recovery entry is the commit store, which
    /// is complete-with-commit (`snapshot.x[28]` takes the interrupted
    /// physical x19).
    #[test]
    fn reserved_resident_write_only_definition_commits_without_loading() {
        let word = 0xAA1A_03FC;
        assert_eq!(
            bad64::decode(word, 0x4000)
                .expect("fixture decodes")
                .to_string(),
            "mov x28, x26"
        );
        let (assembled, _plan) = super::tests::single_virtual_block(word);
        let expected = [
            0xAA1A_03F3, // mov x19, x26
            0xF900_7393, // str x19, [x28, #224]
        ];
        assert_eq!(
            &assembled.words[1..3],
            &expected,
            "resident write-only template words: {:#010x?}",
            &assembled.words[..4.min(assembled.words.len())]
        );
        assert_eq!(
            assembled.recovery.len(),
            2,
            "the entry x17 restore plus exactly the commit entry: {:?}",
            assembled.recovery
        );
        assert_eq!(
            assembled.recovery[1].action,
            RecoveryAction::CommitReservedResident {
                virtual_register: 28
            }
        );
        assert_eq!(assembled.recovery[1].cache.get(), 8);
        assert!(assembled.recovery[1].action.instruction_complete());
    }

    /// `ldr w23, [x28], #8` — mawk's bytecode fetch: virtualized guest x28 as
    /// a post-index writeback base. Load the slot, run the rewritten word,
    /// commit the updated base. Three words against the historical eight.
    #[test]
    fn reserved_resident_writeback_base_is_three_words_with_commit() {
        let word = 0xB840_8797;
        assert_eq!(
            bad64::decode(word, 0x4000)
                .expect("fixture decodes")
                .to_string(),
            "ldr w23, [x28], #0x8"
        );
        let (assembled, _plan) = super::tests::single_virtual_block(word);
        let expected = [
            0xF940_7393, // ldr x19, [x28, #224]
            0xB840_8677, // ldr w23, [x19], #8
            0xF900_7393, // str x19, [x28, #224]
        ];
        assert_eq!(
            &assembled.words[1..4],
            &expected,
            "resident writeback template words: {:#010x?}",
            &assembled.words[..5.min(assembled.words.len())]
        );
        assert_eq!(assembled.recovery.len(), 2);
        assert_eq!(
            assembled.recovery[1].action,
            RecoveryAction::CommitReservedResident {
                virtual_register: 28
            }
        );
        assert_eq!(assembled.recovery[1].cache.get(), 12);
    }

    /// `ldr x0, [x0, x19]` — the loaded destination feeds the address, so
    /// re-executing after the access is wrong. The resident template must
    /// refuse it and leave the historical spill template in place.
    #[test]
    fn reserved_resident_rejects_destination_feeding_the_address() {
        let word = 0xF873_6800;
        assert_eq!(
            bad64::decode(word, 0x4000)
                .expect("fixture decodes")
                .to_string(),
            "ldr x0, [x0, x19]"
        );
        let (assembled, _plan) = super::tests::single_virtual_block(word);
        assert_eq!(
            context_store_slot(assembled.words[1]),
            Some(1120),
            "non-idempotent words keep the spill template: {:#010x?}",
            &assembled.words[..3.min(assembled.words.len())]
        );
    }

    /// A private Absolute-guarded block exposes a trusted entry: past the
    /// guard, at a minimal-width materialization of the block's generation
    /// followed by the shared publish and guest-x17 reload. Binding-guarded
    /// (shared-unit) blocks expose none.
    #[test]
    fn trusted_entry_publishes_generation_past_the_guard() {
        let generation = std::sync::atomic::AtomicU64::new(7);
        let assembled = assemble_block_inner(
            &copy_plan(),
            Some(GenerationGuard::new(
                &generation,
                CodeGeneration::claimed(7),
            )),
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble trusted-entry block");
        let offset = assembled
            .trusted_entry
            .expect("private absolute-guarded block has a trusted entry");
        let index = offset.get() as usize / 4;
        assert_eq!(
            &assembled.words[index..index + 3],
            &[
                0xD280_00F1, // movz x17, #7
                0xF902_3F91, // str x17, [x28, #1144]
                0xF940_4791, // ldr x17, [x28, #136]
            ],
            "trusted entry words: {:#010x?}",
            &assembled.words[index..(index + 4).min(assembled.words.len())]
        );

        let bound = assemble_block_inner(
            &copy_plan(),
            Some(GenerationGuard::binding(3, CodeGeneration::claimed(7))),
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble binding-guarded block");
        assert_eq!(
            bound.trusted_entry, None,
            "shared-unit guards keep their blocks trusted-entry-free"
        );
    }

    /// A kick landing on the resident template's commit store arrives after
    /// the rewritten word executed, so recovery finishes the commit from the
    /// interrupted physical x19 and resumes past the instruction.
    #[test]
    fn commit_reserved_resident_takes_the_interrupted_physical_x19() {
        let mut snapshot = crate::snapshot::NativeUcontextSnapshot::default();
        snapshot.x[28] = 0x1111;
        recover_rewrite_state(
            &mut snapshot,
            RecoveryAction::CommitReservedResident {
                virtual_register: 28,
            },
            0xdead,
            0xdead,
            0xdead,
            0xdead,
            0xdead,
            0x4_2000,
        )
        .expect("commit reserved resident");
        assert_eq!(snapshot.x[28], 0x4_2000);
        assert!(
            RecoveryAction::CommitReservedResident {
                virtual_register: 28
            }
            .instruction_complete()
        );
    }

    /// `movk x28, #1` reads and writes its destination through the immediate
    /// insert; it is not on the resident allowlist and must fall back.
    #[test]
    fn reserved_resident_rejects_read_modify_write_movk() {
        let word = 0xF280_003C;
        assert_eq!(
            bad64::decode(word, 0x4000)
                .expect("fixture decodes")
                .to_string(),
            "movk x28, #0x1"
        );
        let (assembled, _plan) = super::tests::single_virtual_block(word);
        assert_eq!(
            context_store_slot(assembled.words[1]),
            Some(1120),
            "movk keeps the spill template: {:#010x?}",
            &assembled.words[..3.min(assembled.words.len())]
        );
    }

    #[test]
    fn virtual_indirect_target_never_crosses_darwin_x18() {
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4004),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Indirect {
                guest: GuestVa(0x4000),
                word: 0xd63f_0260, // blr x19
                exit: IndirectExit {
                    kind: IndirectKind::Call,
                    register: bad64::Reg::X19,
                    resume: GuestVa(0x4004),
                },
            },
            extensions: Vec::new(),
        };
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble virtual indirect target");
        let words = &assembled.words;

        // The virtualized target (guest x19) loads straight into
        // Darwin-stable x17 and stays there for the probe; the lean exit no
        // longer stages it through slot 1080 up front.
        let staging_index = words
            .iter()
            .position(|word| *word == 0xf940_4f91) // ldr x17, [x28, #152]
            .unwrap_or_else(|| {
                panic!("virtual indirect target must stay in Darwin-stable x17: {words:08x?}")
            });
        assert!(
            !words.contains(&0xf940_4f92), // ldr x18, [x28, #152]
            "Darwin may asynchronously clear physical x18; never stage the target there"
        );
        // The staging word and the probe words after it must restore the
        // guest's x15/x17/x30 on interruption (a blr exit spills x30 too).
        for word_index in staging_index..=staging_index + 2 {
            let offset = u32::try_from(word_index * 4).expect("test block offset");
            assert!(
                assembled.recovery.iter().any(|entry| {
                    entry.cache.get() == offset
                        && entry.action == RecoveryAction::RestoreIndirectLeanCall
                }),
                "x17 staging word {word_index} must restore guest x15/x17/x30 on interruption"
            );
        }
    }

    /// The Phase-3 lean indirect exit for a plain `br` exit: one x15 spill, a
    /// flag-free probe, the flavor gate, the inline `ldar` generation check,
    /// and a direct `br x19` to the trusted entry — with the NZCV round-trip
    /// confined to the flavor-0 slow branch.
    #[test]
    fn indirect_exit_hot_path_is_flag_free_and_branches_through_x19() {
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4004),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Indirect {
                guest: GuestVa(0x4000),
                word: 0xd61f_00a0, // br x5
                exit: IndirectExit {
                    kind: IndirectKind::Branch,
                    register: bad64::Reg::X5,
                    resume: GuestVa(0x4004),
                },
            },
            extensions: Vec::new(),
        };
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble lean indirect exit");
        let words = &assembled.words;

        // Exactly ONE unconditional spill: x15 to slot 1160. No up-front x16
        // (1120) or x30 (1168) spill on a branch exit; the universal tail
        // already owns x17's slots.
        assert_eq!(
            words
                .iter()
                .filter(|word| **word == 0xf902_478f) // str x15, [x28, #1160]
                .count(),
            1,
            "one x15 spill: {words:08x?}"
        );
        // The old up-front target staging (str x5 -> slot 1080) is gone.
        assert!(
            !words.contains(&0xf902_1f85), // str x5, [x28, #1080]
            "the target stages through x17 at the miss edge, not up front: {words:08x?}"
        );
        // mov x17, x5 stages the target for the probe.
        let staging_index = words
            .iter()
            .position(|word| *word == 0xaa05_03f1)
            .unwrap_or_else(|| panic!("target must stage into x17: {words:08x?}"));
        // Flavor gate: tbz x17, #0 to the slow branch.
        assert!(
            words
                .iter()
                .any(|word| (*word & 0xfff8_001f) == 0x3600_0011),
            "flavor gate tbz x17, #0 missing: {words:08x?}"
        );
        // Inline generation validation: ldar x19, [x19].
        assert!(
            words.contains(&0xc8df_fe73),
            "flavor-1 hit must ldar the generation atomic: {words:08x?}"
        );
        let trusted_branch = words
            .iter()
            .position(|word| *word == 0xd61f_0260) // br x19
            .unwrap_or_else(|| panic!("flavor-1 hit must branch through x19: {words:08x?}"));
        // A br exit spills x30 ONLY in the flavor-0 slow branch (for the
        // resolver recovery action's unconditional x30 restore), never on
        // the hot path.
        assert!(
            !words[..=trusted_branch].contains(&0xf902_4b9e), // str x30, [x28, #1168]
            "a br exit must not spill x30 on the hot path: {words:08x?}"
        );
        // The hot path and probe are entirely flag-free: the ONLY NZCV
        // round-trip lives in the flavor-0 slow branch, emitted after the
        // hot path's final branch.
        let mrs_indexes: Vec<usize> = words
            .iter()
            .enumerate()
            .filter(|(_, word)| **word == 0xd53b_4210)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            mrs_indexes.len(),
            1,
            "exactly one mrs x16, nzcv (slow branch): {words:08x?}"
        );
        assert!(
            mrs_indexes[0] > trusted_branch,
            "the NZCV save belongs to the slow branch after the hot path: {words:08x?}"
        );
        // Every hot-path word from the staging through the trusted branch
        // recovers with the lean action.
        for word_index in staging_index..=trusted_branch {
            let offset = u32::try_from(word_index * 4).expect("test block offset");
            assert!(
                assembled.recovery.iter().any(|entry| {
                    entry.cache.get() == offset
                        && entry.action == RecoveryAction::RestoreIndirectLean
                }),
                "hot-path word {word_index} must carry RestoreIndirectLean: {words:08x?}"
            );
        }
    }

    fn virtual_test_bit_exit(guest: GuestVa, target: GuestVa) -> PlannedExit {
        PlannedExit::Direct {
            guest,
            word: 0xb7f8_0fb3, // tbnz x19, #63, target
            exit: DirectExit {
                kind: DirectKind::TestBit { nonzero: true },
                target,
                resume: GuestVa(guest.raw() + 4),
                condition: None,
                register: Some(bad64::Reg::X19),
                bit: Some(63),
            },
        }
    }

    #[test]
    fn terminal_virtual_condition_never_crosses_darwin_x18() {
        let plan = direct_plan(virtual_test_bit_exit(GuestVa(0x4000), GuestVa(0x5000)));
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble virtual conditional exit");
        let words = &assembled.words;
        let stable_staging = [
            0xf940_4f91, // ldr x17, [x28, #152] — guest x19
            0xb7f8_0051, // tbnz x17, #63, +2
        ];
        let staging_index = words
            .windows(stable_staging.len())
            .position(|window| window == stable_staging)
            .unwrap_or_else(|| {
                panic!("virtual condition must stay in Darwin-stable x17: {words:08x?}")
            });
        assert!(
            !words.windows(2).any(|window| {
                window
                    == [
                        0xf940_4f92, // ldr x18, [x28, #152]
                        0xb7f8_0052, // tbnz x18, #63, +2
                    ]
            }),
            "Darwin may asynchronously clear physical x18 between these words"
        );
        for word_index in staging_index..=staging_index + 3 {
            let offset = u32::try_from(word_index * 4).expect("test block offset");
            assert!(
                assembled.recovery.iter().any(|entry| {
                    entry.cache.get() == offset && entry.action == RecoveryAction::RestoreGuestX17
                }),
                "x17 conditional staging word {word_index} must restore guest x17 on interruption"
            );
        }
        for link in &assembled.direct_links {
            assert!(
                matches!(
                    link.kind,
                    DirectLinkKind::ConditionalFallthrough | DirectLinkKind::ConditionalTaken
                ),
                "virtual conditional emitted unexpected link kind {:?}",
                link.kind
            );
            for offset in (link.stub.start.get()..link.stub.end.get()).step_by(4) {
                assert!(
                    assembled.recovery.iter().any(|entry| {
                        entry.cache.get() == offset
                            && entry.action == RecoveryAction::RestoreGuestX17
                    }),
                    "{:?} stub word at {offset} must restore guest x17",
                    link.kind
                );
            }
        }
    }

    #[test]
    fn fused_virtual_condition_never_crosses_darwin_x18() {
        let mut plan = fused_two_segment_plan();
        plan.exit = virtual_test_bit_exit(GuestVa(0x4004), GuestVa(0x5000));
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble fused virtual conditional edge");
        let words = &assembled.words;
        let stable_staging = [
            0xf900_4791, // str x17, [x28, #136] — canonical guest x17
            0xf902_3791, // str x17, [x28, #1128] — recovery guest x17
            0xf940_4f91, // ldr x17, [x28, #152] — guest x19
            0xb7f8_0051, // tbnz x17, #63, +2
        ];
        let staging_index = words
            .windows(stable_staging.len())
            .position(|window| window == stable_staging)
            .unwrap_or_else(|| {
                panic!("fused virtual condition must preserve and use x17: {words:08x?}")
            });
        assert!(
            !words.windows(2).any(|window| {
                window
                    == [
                        0xf940_4f92, // ldr x18, [x28, #152]
                        0xb7f8_0052, // tbnz x18, #63, +2
                    ]
            }),
            "fused virtual condition must not cross Darwin-volatile x18"
        );
        assert!(
            words[staging_index + stable_staging.len()..]
                .iter()
                .take(4)
                .any(|word| *word == 0xf940_4791),
            "fused fall-through must restore guest x17 before the next guest instruction"
        );
        let taken = assembled
            .direct_links
            .iter()
            .find(|link| link.kind == DirectLinkKind::ConditionalTaken)
            .expect("fused virtual conditional taken link");
        for offset in (taken.stub.start.get()..taken.stub.end.get()).step_by(4) {
            assert!(
                assembled.recovery.iter().any(|entry| {
                    entry.cache.get() == offset && entry.action == RecoveryAction::RestoreGuestX17
                }),
                "fused virtual taken stub word at {offset} must restore guest x17"
            );
        }
    }

    /// Anything that writes memory: the prologue is store-throughput-bound, so
    /// the store COUNT is the quantity under test, not any one opcode.
    fn is_store(word: u32) -> bool {
        bad64::decode(word, 0x4000).is_ok_and(|instruction| {
            matches!(
                instruction.op(),
                bad64::Op::STR
                    | bad64::Op::STUR
                    | bad64::Op::STP
                    | bad64::Op::STLR
                    | bad64::Op::STRB
                    | bad64::Op::STRH
            )
        })
    }

    /// The generation guard is the authoritative stale-code check and there is
    /// no link severing anywhere in the tree, so it must keep running on every
    /// block entry. What it need NOT do is spill guest state to reach two
    /// scratch registers: physical x17 is dead at block entry (its guest value
    /// lives in `snapshot.x[17]` and slot 1128, and the prologue reloads it)
    /// and physical x19 is host-owned for the whole of translated execution
    /// (`gateway::RESERVED_SCRATCH`), so the guard has two free registers
    /// without touching guest x16 or NZCV.
    ///
    /// Both arms are spelled out: the switch is read once per process, so one
    /// test binary can only observe the configuration it was started in, and a
    /// test that asserted nothing in the shipped configuration would be
    /// vacuous.
    #[test]
    fn generation_guard_spills_no_guest_register() {
        use std::sync::atomic::AtomicU64;

        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        for (name, guard) in [
            (
                "absolute",
                GenerationGuard::new(&generation, CodeGeneration::INITIAL),
            ),
            (
                "binding",
                GenerationGuard::binding(3, CodeGeneration::INITIAL),
            ),
        ] {
            let words = guarded_prologue_words(guard);
            let stores = words.iter().copied().filter(|word| is_store(*word)).count();

            // Invariant in BOTH arms: the guard runs, reads the generation
            // cell with acquire ordering, and publishes the generation it
            // matched.
            assert!(
                words.iter().any(|word| (word & 0xFFFF_FC00) == 0xC8DF_FC00),
                "{name} guard must ldar the generation cell: {words:08x?}"
            );
            assert!(
                words
                    .iter()
                    .any(|word| context_store_slot(*word) == Some(crate::gateway::CTX_GENERATION)),
                "{name} guard must publish its generation: {words:08x?}"
            );

            if crate::emit::lean_generation_guard_enabled() {
                // The spill slots the guard used to borrow: guest x16 (1120),
                // guest x17 (1128) and the guard's NZCV save (936).
                for slot in [936_u32, 1120, 1128] {
                    assert!(
                        !words
                            .iter()
                            .any(|word| context_store_slot(*word) == Some(slot)),
                        "{name} guard still spills to context slot {slot}: {words:08x?}"
                    );
                    assert!(
                        !words
                            .iter()
                            .any(|word| context_load_slot(*word) == Some(slot)),
                        "{name} guard still reloads context slot {slot}: {words:08x?}"
                    );
                }
                // A flags-free comparison leaves guest NZCV untouched, so
                // neither half of the PSTATE round trip may survive.
                assert!(
                    !words.contains(&0xd53b_4210) && !words.contains(&0xd51b_4210),
                    "{name} guard still round-trips NZCV: {words:08x?}"
                );
                // ONE store remains, and it is the guard's own generation
                // publish. The gateway-phase publish that used to sit beside it
                // moved into `gateway_aarch64.S`, which claims phase zero once
                // per GATEWAY entry instead of once per block entry.
                assert_eq!(stores, 1, "{name} lean prologue store count: {words:08x?}");
                assert!(
                    !words
                        .iter()
                        .any(|word| context_store_slot(*word)
                            == Some(crate::gateway::CTX_GATEWAY_PHASE)),
                    "{name} prologue must not re-claim the gateway phase: {words:08x?}"
                );
                // Its scratch is the host-owned reserved register, and guest
                // x16 is never named at all.
                assert!(
                    words
                        .iter()
                        .any(|word| word & 0x1f == crate::gateway::RESERVED_SCRATCH),
                    "{name} guard must compute in the reserved register: {words:08x?}"
                );
                assert!(
                    !words.iter().any(|word| word & 0x1f == 16),
                    "{name} guard must not write guest x16: {words:08x?}"
                );
            } else {
                // The inverse, so the shipped configuration still asserts
                // exactly what it does: two borrowed guest registers spilled
                // and reloaded, a PSTATE round trip, and five stores.
                for slot in [936_u32, 1120, 1128] {
                    assert!(
                        words
                            .iter()
                            .any(|word| context_store_slot(*word) == Some(slot)),
                        "{name} guard must spill context slot {slot}: {words:08x?}"
                    );
                    assert!(
                        words
                            .iter()
                            .any(|word| context_load_slot(*word) == Some(slot)),
                        "{name} guard must reload context slot {slot}: {words:08x?}"
                    );
                }
                assert!(
                    words.contains(&0xd53b_4210) && words.contains(&0xd51b_4210),
                    "{name} guard must round-trip NZCV: {words:08x?}"
                );
                assert_eq!(
                    stores, 5,
                    "{name} spilling prologue store count: {words:08x?}"
                );
                assert!(
                    !words
                        .iter()
                        .any(|word| word & 0x1f == crate::gateway::RESERVED_SCRATCH),
                    "{name} guard must leave the reserved register alone: {words:08x?}"
                );
            }
        }
    }

    pub(crate) fn biased_memory_plan(memory: super::super::types::MemoryAccess) -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4004),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(memory),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
            extensions: Vec::new(),
        }
    }

    fn assemble_biased_words(memory: super::super::types::MemoryAccess, bias: u64) -> Vec<u32> {
        let host_bias =
            carrick_dsr::address::NativeHostBias::new(bias, 0x4000).expect("aligned test bias");
        let assembled = assemble_block_inner(
            &biased_memory_plan(memory),
            None,
            EmitAddressMode::Biased { host_bias },
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble biased memory fixture");
        assembled.words
    }

    /// Only the words emitted for the memory access itself. The block's
    /// syscall exit afterwards legitimately saves guest x17 to slot 1128, so a
    /// whole-block scan could never distinguish that from a lowering spill.
    fn assemble_biased_access_words(
        memory: super::super::types::MemoryAccess,
        bias: u64,
    ) -> Vec<u32> {
        let plan = biased_memory_plan(memory);
        let assembled = assemble_biased_emission(&plan, bias);
        biased_guest_words(&assembled, plan.start)
    }

    fn assemble_biased_emission(plan: &BlockPlan, bias: u64) -> AssembledBlock {
        let host_bias =
            carrick_dsr::address::NativeHostBias::new(bias, 0x4000).expect("aligned test bias");
        assemble_block_inner(
            plan,
            None,
            EmitAddressMode::Biased { host_bias },
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble biased memory fixture")
    }

    fn biased_guest_words(assembled: &AssembledBlock, guest: GuestVa) -> Vec<u32> {
        let words = assembled
            .map
            .entries()
            .iter()
            .filter(|entry| entry.guest == guest)
            .map(|entry| {
                let index = entry.cache.get() as usize / 4;
                assembled.words[index]
            })
            .collect::<Vec<_>>();
        assert!(!words.is_empty(), "the access emitted no words");
        words
    }

    fn finalize_test_words(assembler: VecAssembler<Aarch64Relocation>) -> Vec<u32> {
        let bytes = assembler.finalize().expect("finalize test emission");
        assert!(bytes.len().is_multiple_of(4));
        bytes
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect()
    }

    fn assemble_reserved_access_words(
        memory: super::super::types::MemoryAccess,
        bias: u64,
    ) -> Vec<u32> {
        let plan = biased_memory_plan(memory);
        let host_bias =
            carrick_dsr::address::NativeHostBias::new(bias, 0x4000).expect("aligned test bias");
        let base = biased_base(memory).expect("reserved test base");
        let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
        let mut entries = Vec::new();
        let mut recovery = Vec::new();
        emit_reserved_biased_memory(
            &mut assembler,
            &mut entries,
            &plan,
            plan.start,
            memory,
            base,
            host_bias,
            &mut recovery,
        )
        .expect("emit reserved biased fixture");
        finalize_test_words(assembler)
    }

    fn assemble_compact_access_emission(
        memory: super::super::types::MemoryAccess,
        bias: u64,
    ) -> (Vec<u32>, Vec<RecoveryEntry>) {
        let plan = biased_memory_plan(memory);
        let host_bias =
            carrick_dsr::address::NativeHostBias::new(bias, 0x4000).expect("aligned test bias");
        let base = biased_base(memory).expect("compact test base");
        let immediate = match memory.effective_address {
            super::super::types::MemoryEffectiveAddress::Base => 0,
            super::super::types::MemoryEffectiveAddress::Immediate(immediate) => {
                u64::try_from(immediate).expect("non-negative compact immediate")
            }
            super::super::types::MemoryEffectiveAddress::RegisterOffset { .. } => {
                panic!("compact test fixture cannot use a register offset")
            }
        };
        let form = CompactBiasedForm {
            bias_orr: host_bias
                .aperture_disjoint_orr_immediate()
                .expect("compact test bias"),
            base,
            immediate,
        };
        let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
        let mut entries = Vec::new();
        let mut recovery = Vec::new();
        emit_compact_biased_memory(
            &mut assembler,
            &mut entries,
            &plan,
            plan.start,
            memory,
            host_bias,
            &mut recovery,
            form,
        )
        .expect("emit compact biased fixture");
        (finalize_test_words(assembler), recovery)
    }

    fn assemble_compact_access_words(
        memory: super::super::types::MemoryAccess,
        bias: u64,
    ) -> Vec<u32> {
        assemble_compact_access_emission(memory, bias).0
    }

    fn physical_x18_offenders(name: &str, words: &[u32]) -> Vec<(String, usize, u32)> {
        words
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, word)| {
                bad64::decode(word, 0x4000 + index as u64 * 4).unwrap_or_else(|error| {
                    panic!("{name} emitted undecodable word {index}=0x{word:08x}: {error}")
                });
                super::super::decode::decoded_operands_mention_gpr(
                    word,
                    GuestVa(0x4000 + index as u64 * 4),
                    18,
                )
                .then(|| (name.to_string(), index, word))
            })
            .collect()
    }

    fn biased_dc_zva_plan() -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4004),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Sensitive {
                guest: GuestVa(0x4000),
                word: 0xd50b_7420, // dc zva, x0
                exit: super::super::types::SensitiveExit {
                    kind: super::super::types::SensitiveKind::DcZva,
                    register: Some(bad64::Reg::X0),
                    resume: GuestVa(0x4004),
                },
                fusion: None,
            },
            extensions: Vec::new(),
        }
    }

    #[test]
    fn biased_lowerings_never_emit_darwin_volatile_physical_x18() {
        let compact_high_and_low_immediate = super::super::types::MemoryAccess {
            // str x0, [x1, #0x1238] -- the displacement needs both ADD
            // immediate stages in the compact slow path.
            word: 0xf900_0000 | (0x247 << 10) | (1 << 5),
            op: bad64::Op::STR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(0x1238),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let compact_writeback = super::super::types::MemoryAccess {
            word: 0xa881_7c3f, // stp xzr, xzr, [x1], #16
            op: bad64::Op::STP,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Base,
            writeback: super::super::types::MemoryWriteback::PostIndex,
            class: super::super::types::MemoryClass::Pair,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let compact_stack_pointer = super::super::types::MemoryAccess {
            word: 0xf900_07e0, // str x0, [sp, #8]
            op: bad64::Op::STR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::SP),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(8),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let reserved = super::super::types::MemoryAccess {
            word: 0xf85f_8020, // ldur x0, [x1, #-8]
            op: bad64::Op::LDUR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(-8),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let general = super::super::types::MemoryAccess {
            word: 0xf81f_8c20, // str x0, [x1, #-8]!
            op: bad64::Op::STR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(-8),
            writeback: super::super::types::MemoryWriteback::PreIndex,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let dc_zva = biased_dc_zva_plan();

        let dc_zva_emission = assemble_biased_emission(&dc_zva, 0x80_0000_0000);
        let cases = [
            (
                "compact high+low immediate",
                assemble_compact_access_words(compact_high_and_low_immediate, 0x200_0000_0000),
            ),
            (
                "compact multi-chunk writeback bias",
                assemble_compact_access_words(compact_writeback, 0x0001_fe00_0000_0000),
            ),
            (
                "compact stack pointer",
                assemble_compact_access_words(compact_stack_pointer, 0x200_0000_0000),
            ),
            (
                "reserved negative immediate",
                assemble_reserved_access_words(reserved, 0x80_0000_0000),
            ),
            (
                "general pre-index",
                assemble_biased_access_words(general, 0x80_0000_0000),
            ),
            (
                "dc zva",
                biased_guest_words(&dc_zva_emission, GuestVa(0x4000)),
            ),
        ];
        assert!(
            !contains_general_bias_load(&cases[0].1),
            "compact high+low fixture escaped to the general lowering"
        );
        assert!(
            cases[0].1.windows(2).any(|words| {
                words[0] & 0xffc0_03e0 == 0x9140_0020 && words[1] & 0xffc0_0000 == 0x9100_0000
            }),
            "compact fixture did not exercise both immediate stages: {:08x?}",
            cases[0].1
        );
        assert!(
            !contains_general_bias_load(&cases[1].1),
            "compact writeback fixture escaped to the general lowering"
        );
        assert_eq!(
            cases[1]
                .1
                .iter()
                .filter(|word| { matches!(**word & 0xff80_001f, 0xd280_0001 | 0xf280_0001) })
                .count(),
            2,
            "compact writeback must exercise a two-chunk bias: {:08x?}",
            cases[1].1
        );
        assert!(
            !contains_general_bias_load(&cases[2].1),
            "compact SP fixture escaped to the general lowering"
        );
        assert_eq!(
            cases[2]
                .1
                .iter()
                .filter(|word| **word & 0xffff_ffe0 == 0x9100_03e0)
                .count(),
            3,
            "compact SP must rebuild its base before checking, tagging, and translating: {:08x?}",
            cases[2].1
        );
        assert!(
            cases[3]
                .1
                .iter()
                .any(|word| word & 0x1f == crate::gateway::RESERVED_SCRATCH),
            "reserved fixture did not use the reserved address register"
        );
        assert!(
            !cases[3].1.iter().any(|word| {
                let slot = ((*word >> 10) & 0xfff) * 8;
                matches!(slot, 1120 | 1128 | 1160 | 1168)
                    && matches!(*word & 0xffc0_0380, 0xf900_0380 | 0xf940_0380)
            }),
            "reserved fixture must remain spill-free: {:08x?}",
            cases[3].1
        );
        assert!(
            contains_general_bias_load(&cases[4].1),
            "general fixture did not route through the context bias load"
        );
        assert!(
            cases[5].1.iter().any(|word| word & !0x1f == 0xd50b_7420),
            "dc zva fixture did not emit the host instruction"
        );

        let offenders = cases
            .iter()
            .flat_map(|(name, words)| physical_x18_offenders(name, words))
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "biased lowering emitted Darwin-volatile physical x18 operands: {offenders:08x?}"
        );
    }

    #[test]
    fn compact_multichunk_writeback_recovers_at_each_bias_materialization_boundary() {
        let memory = super::super::types::MemoryAccess {
            word: 0xa881_7c3f, // stp xzr, xzr, [x1], #16
            op: bad64::Op::STP,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Base,
            writeback: super::super::types::MemoryWriteback::PostIndex,
            class: super::super::types::MemoryClass::Pair,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        let bias = 0x0001_fe00_0000_0000;
        let (words, recovery) = assemble_compact_access_emission(memory, bias);
        let materializations = words
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, word)| matches!(*word & 0xff80_001f, 0xd280_0001 | 0xf280_0001))
            .collect::<Vec<_>>();
        assert_eq!(
            materializations.len(),
            2,
            "fixture must materialize the bias in two independent chunks: {words:08x?}"
        );

        let guest_base_after_writeback = 0x1234_0010_u64;
        let host_base_after_writeback = bias + guest_base_after_writeback;
        for (word_index, word) in materializations {
            let offset = u32::try_from(word_index * 4).expect("materialization offset");
            let action = recovery
                .iter()
                .find_map(|entry| (entry.cache.get() == offset).then_some(entry.action))
                .unwrap_or_else(|| {
                    panic!("materialization word {word_index}=0x{word:08x} has no recovery action")
                });
            let RecoveryAction::RecoverBiasedMemory(action) = action else {
                panic!(
                    "materialization word {word_index}=0x{word:08x} has wrong recovery {action:?}"
                );
            };
            assert!(action.instruction_complete);
            assert!(action.commit_base);
            assert_eq!(action.base, BiasedBase::Register(1));
            assert_eq!(action.base_coordinate, BiasedBaseCoordinate::Host);
            assert_eq!(action.scratch_count, 1);

            let scratch = usize::try_from(action.base_scratch).expect("scratch index");
            let saved_scratch = 0xfeed_face_cafe_beef;
            let mut snapshot = crate::snapshot::NativeUcontextSnapshot::default();
            snapshot.x[1] = 0xdead_0000_0000_0000 | u64::from(word_index as u32);
            snapshot.x[scratch] = host_base_after_writeback;
            recover_rewrite_state(
                &mut snapshot,
                RecoveryAction::RecoverBiasedMemory(action),
                saved_scratch,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("recover multi-chunk materialization boundary");
            assert_eq!(
                snapshot.x[1], guest_base_after_writeback,
                "partial bias chunk at word {word_index} leaked into the guest base"
            );
            assert_eq!(
                snapshot.x[scratch], saved_scratch,
                "borrowed scratch at word {word_index}"
            );
        }
    }

    #[test]
    fn biased_dc_zva_recovery_restores_every_borrowed_scratch_at_every_boundary() {
        let plan = biased_dc_zva_plan();
        let assembled = assemble_biased_emission(&plan, 0x80_0000_0000);
        let dc_offset = assembled
            .words
            .iter()
            .position(|word| word & !0x1f == 0xd50b_7420)
            .map(|index| u32::try_from(index * 4).expect("dc zva offset"))
            .expect("host dc zva word");
        let actions = assembled
            .recovery
            .iter()
            .filter_map(|entry| match entry.action {
                RecoveryAction::RecoverBiasedMemory(action) => Some((entry.cache.get(), action)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !actions.is_empty(),
            "dc zva lowering must publish typed recovery"
        );
        assert!(
            actions.windows(2).all(|pair| pair[1].0 == pair[0].0 + 4),
            "dc zva recovery must cover every post-spill word exactly once: {actions:?}"
        );
        let (first_offset, first_action) = actions.first().copied().expect("first dc zva action");
        let first_index = usize::try_from(first_offset / 4).expect("first action index");
        assert!(
            first_index >= 2,
            "dc zva recovery begins before both spills"
        );
        for (index, register) in first_action.scratch_registers[..2]
            .iter()
            .copied()
            .enumerate()
        {
            let slot = BIASED_SCRATCH_CONTEXT_OFFSETS[index];
            assert_eq!(
                assembled.words[first_index - 2 + index],
                0xf900_0000 | ((slot / 8) << 10) | (28 << 5) | register,
                "dc zva recovery must begin immediately after scratch spill {index}"
            );
        }
        let (last_offset, last_action) = actions.last().copied().expect("last dc zva action");
        let last_index = usize::try_from(last_offset / 4).expect("last action index");
        assert!(last_action.instruction_complete);
        assert_eq!(
            assembled.words[last_index],
            0xf940_0000
                | ((BIASED_SCRATCH_CONTEXT_OFFSETS[0] / 8) << 10)
                | (28 << 5)
                | last_action.scratch_registers[0],
            "dc zva recovery must extend through the final scratch restore"
        );

        for (offset, action) in actions {
            assert_eq!(
                assembled
                    .recovery
                    .iter()
                    .filter(|entry| entry.cache.get() == offset)
                    .count(),
                1,
                "dc zva offset {offset} must have exactly one recovery action"
            );
            assert_eq!(
                action.instruction_complete,
                offset > dc_offset,
                "dc zva completion transition at offset {offset}"
            );
            assert!(!action.commit_base, "dc zva never commits a guest base");
            assert_eq!(action.scratch_count, 2);
            let scratches = &action.scratch_registers[..2];
            assert_ne!(scratches[0], scratches[1]);
            assert!(
                scratches.iter().all(|register| !matches!(
                    *register,
                    18 | 28 | crate::gateway::RESERVED_SCRATCH
                )),
                "dc zva recovery borrowed forbidden scratch: {scratches:?}"
            );

            let mut snapshot = crate::snapshot::NativeUcontextSnapshot::default();
            snapshot.x[scratches[0] as usize] = 0xdead_0000_0000_0001;
            snapshot.x[scratches[1] as usize] = 0xdead_0000_0000_0002;
            recover_rewrite_state(
                &mut snapshot,
                RecoveryAction::RecoverBiasedMemory(action),
                0x1111_1111_1111_1111,
                0x2222_2222_2222_2222,
                0,
                0,
                0,
                0,
            )
            .expect("recover dc zva boundary");
            assert_eq!(snapshot.x[scratches[0] as usize], 0x1111_1111_1111_1111);
            assert_eq!(snapshot.x[scratches[1] as usize], 0x2222_2222_2222_2222);
            assert_eq!(
                recovery_resume_pc(
                    plan.start,
                    Some(RecoveryAction::RecoverBiasedMemory(action))
                )
                .expect("dc zva resume PC"),
                plan.start.raw() + u64::from(action.instruction_complete) * 4,
                "dc zva resume at offset {offset}"
            );
        }
    }

    fn subsequence_at(words: &[u32], first: u32) -> Option<usize> {
        words.iter().position(|word| *word == first)
    }

    fn contains_general_bias_load(words: &[u32]) -> bool {
        // The general lowering always loads the host bias from context slot
        // 1192 into some scratch; any 64-bit load from that slot marks it.
        words
            .iter()
            .any(|word| (word & 0xFFC0_03E0) == 0xF940_0380 && ((word >> 10) & 0xFFF) == 1192 / 8)
    }

    #[test]
    fn compact_biased_immediate_store_emits_the_orr_form() {
        // str x0, [x1, #8] under the aperture-disjoint 1<<41 bias.
        let words = assemble_biased_words(
            super::super::types::MemoryAccess {
                word: 0xf900_0420,
                op: bad64::Op::STR,
                base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
                effective_address: super::super::types::MemoryEffectiveAddress::Immediate(8),
                writeback: super::super::types::MemoryWriteback::None,
                class: super::super::types::MemoryClass::Scalar,
                virtualization: super::super::types::MemoryVirtualization::None,
            },
            0x200_0000_0000,
        );

        // No writeback, so the address register is the reserved one: no spill
        // prologue and no restore epilogue bracket the sequence.
        // Both arms are spelled out exactly; see
        // `reserved_scratch_lowering_emits_no_context_spill` for why.
        if crate::emit::reserved_scratch_enabled() {
            // No writeback, so the address register is the reserved one: no
            // spill prologue and no restore epilogue bracket the sequence.
            let start = subsequence_at(&words, 0xd369_fc33).expect("compact aperture check");
            assert_eq!(
                &words[start..start + 8],
                &[
                    0xd369_fc33, // lsr x19, x1, #41
                    0xb400_00b3, // cbz x19, +20 (to the fast orr)
                    0x9100_2033, // add x19, x1, #8 (slow: guest effective address)
                    0xf902_5b93, // str x19, [x28, #1200] (publish guest fault addr)
                    0xb251_0033, // orr x19, x1, #(1 << 47) (tagged invalid host)
                    0x1400_0002, // b +8 (over the fast orr)
                    0xb257_0033, // orr x19, x1, #(1 << 41) (host address)
                    0xf900_0660, // str x0, [x19, #8]
                ],
                "compact immediate store shape (reserved scratch)"
            );
        } else {
            let start = subsequence_at(&words, 0xf902_3391).expect("compact scratch spill");
            assert_eq!(
                &words[start..start + 10],
                &[
                    0xf902_3391, // str x17, [x28, #1120]
                    0xd369_fc31, // lsr x17, x1, #41
                    0xb400_00b1, // cbz x17, +20 (to the fast orr)
                    0x9100_2031, // add x17, x1, #8 (slow: guest effective address)
                    0xf902_5b91, // str x17, [x28, #1200] (publish guest fault addr)
                    0xb251_0031, // orr x17, x1, #(1 << 47) (tagged invalid host)
                    0x1400_0002, // b +8 (over the fast orr)
                    0xb257_0031, // orr x17, x1, #(1 << 41) (host address)
                    0xf900_0620, // str x0, [x17, #8]
                    0xf942_3391, // ldr x17, [x28, #1120]
                ],
                "compact immediate store shape (borrowed scratch)"
            );
        }
        assert!(
            !contains_general_bias_load(&words),
            "compact form must not load the bias from context"
        );
    }

    #[test]
    fn compact_biased_postindex_writeback_commits_with_full_width_sub() {
        // stp xzr, xzr, [x1], #16 — the memclr shape.
        let words = assemble_biased_words(
            super::super::types::MemoryAccess {
                word: 0xa881_7c3f,
                op: bad64::Op::STP,
                base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
                effective_address: super::super::types::MemoryEffectiveAddress::Base,
                writeback: super::super::types::MemoryWriteback::PostIndex,
                class: super::super::types::MemoryClass::Pair,
                virtualization: super::super::types::MemoryVirtualization::None,
            },
            0x200_0000_0000,
        );

        let start = subsequence_at(&words, 0xf902_3391).expect("compact scratch spill");
        assert_eq!(
            &words[start..start + 12],
            &[
                0xf902_3391, // str x17, [x28, #1120]
                0xd369_fc31, // lsr x17, x1, #41
                0xb400_00b1, // cbz x17, +20 (to the fast orr)
                0xaa01_03f1, // mov x17, x1 (slow: guest effective address)
                0xf902_5b91, // str x17, [x28, #1200]
                0xb251_0031, // orr x17, x1, #(1 << 47)
                0x1400_0002, // b +8
                0xb257_0031, // orr x17, x1, #(1 << 41)
                0xa881_7e3f, // stp xzr, xzr, [x17], #16
                0xd2c0_4001, // movz x1, #0x200, lsl #32 (the bias)
                0xcb01_0221, // sub x1, x17, x1 (exact un-bias commit)
                0xf942_3391, // ldr x17, [x28, #1120]
            ],
            "compact post-index writeback shape"
        );
    }

    #[test]
    fn reserved_scratch_lowering_emits_no_context_spill() {
        use crate::gateway::RESERVED_SCRATCH;

        let words = assemble_biased_access_words(
            super::super::types::MemoryAccess {
                word: 0xf900_0420, // str x0, [x1, #8]
                op: bad64::Op::STR,
                base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
                effective_address: super::super::types::MemoryEffectiveAddress::Immediate(8),
                writeback: super::super::types::MemoryWriteback::None,
                class: super::super::types::MemoryClass::Scalar,
                virtualization: super::super::types::MemoryVirtualization::None,
            },
            0x80_0000_0000,
        );
        let spills = words
            .iter()
            .filter(|word| {
                let is_ctx =
                    (*word & 0xFFC0_03E0) == 0xF900_0380 || (*word & 0xFFC0_03E0) == 0xF940_0380;
                let slot = ((*word >> 10) & 0xFFF) * 8;
                is_ctx && matches!(slot, 1120 | 1128 | 1160 | 1168)
            })
            .count();
        // Both arms are spelled out: the reserved switch is read once per
        // process, so one test binary can only observe the configuration it
        // was started in, and a test that asserted nothing in the default
        // configuration would be vacuous.
        if crate::emit::reserved_scratch_enabled() {
            // No store or load targeting the memory-scratch slots may remain.
            assert_eq!(spills, 0, "scratch spill survived: {words:08x?}");
            assert!(
                words.iter().any(|word| word & 0x1F == RESERVED_SCRATCH),
                "the lowering must compute into the reserved register"
            );
        } else {
            // The inverse, so the default configuration still asserts exactly
            // what it does: one borrowed base scratch, spilled and restored,
            // and no use of the reserved register as an address.
            assert_eq!(
                spills, 4,
                "two borrowed scratches must each spill and restore"
            );
            assert!(
                !words.iter().any(|word| word & 0x1F == RESERVED_SCRATCH),
                "the reserved register must stay unused while the switch is off"
            );
        }
    }

    #[test]
    fn negative_immediates_and_sub_aperture_biases_keep_the_general_form() {
        let negative = super::super::types::MemoryAccess {
            word: 0xf85f_8020, // ldur x0, [x1, #-8]
            op: bad64::Op::LDUR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(-8),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        assert!(
            contains_general_bias_load(&assemble_biased_words(negative, 0x200_0000_0000)),
            "negative immediates stay on the general path"
        );

        let positive = super::super::types::MemoryAccess {
            word: 0xf900_0420,
            op: bad64::Op::STR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address: super::super::types::MemoryEffectiveAddress::Immediate(8),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        };
        assert!(
            contains_general_bias_load(&assemble_biased_words(positive, 0x80_0000_0000)),
            "sub-aperture biases stay on the general path"
        );
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
            extensions: Vec::new(),
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
                            capture_progress: _,
                            committed_link,
                        } if committed_link == expected.committed_link
                    ),
                    "{case}: offset {offset} must declare a direct-binding recovery phase"
                );
            }
        }
    }

    fn expected_sidecar_recovery_phase(word: u32) -> DirectBindingRecoveryPhase {
        match word {
            0..=4 => DirectBindingRecoveryPhase::ScratchCapture,
            5..=6 => DirectBindingRecoveryPhase::CellAddress,
            7..=10 => DirectBindingRecoveryPhase::TargetAcquire,
            11..=16 => DirectBindingRecoveryPhase::AuthorityValidate,
            17..=20 => DirectBindingRecoveryPhase::AuthorityInstall,
            21..=25 => DirectBindingRecoveryPhase::ArchitecturalRestore,
            26 => DirectBindingRecoveryPhase::FinalBranch,
            27..=63 => DirectBindingRecoveryPhase::MissExit,
            _ => panic!("sidecar recovery word is outside the fixed envelope: {word}"),
        }
    }

    fn check_direct_binding_recovery(
        link: DirectLink,
        recovery: &[RecoveryEntry],
        committed_link: Option<u64>,
    ) -> Result<(), String> {
        let original = crate::snapshot::NativeUcontextSnapshot {
            x: std::array::from_fn(|index| 0x1000_0000_0000_0000 | index as u64),
            pstate: 0xa000_0000,
            ..crate::snapshot::NativeUcontextSnapshot::default()
        };
        for offset in (link.stub.start.get()..link.stub.end.get()).step_by(4) {
            let actions = recovery
                .iter()
                .filter(|entry| entry.cache.get() == offset)
                .map(|entry| entry.action)
                .collect::<Vec<_>>();
            if actions.len() != 1 {
                return Err(format!(
                    "offset {offset} has {} recovery entries, expected exactly one",
                    actions.len()
                ));
            }
            let RecoveryAction::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link: action_link,
            } = actions[0]
            else {
                return Err(format!(
                    "offset {offset} is not direct-binding recovery: {:?}",
                    actions[0]
                ));
            };
            let word = (offset - link.stub.start.get()) / 4;
            let expected_phase = expected_sidecar_recovery_phase(word);
            if phase != expected_phase {
                return Err(format!(
                    "offset {offset} word {word} has phase {phase:?}, expected {expected_phase:?}"
                ));
            }
            if action_link != committed_link {
                return Err(format!(
                    "offset {offset} has committed link {action_link:?}, expected {committed_link:?}"
                ));
            }

            let mut interrupted = original;
            interrupted.x[15] = 0xdead_0000_0000_0015;
            interrupted.x[16] = 0xdead_0000_0000_0016;
            interrupted.x[17] = 0xdead_0000_0000_0017;
            interrupted.x[30] = 0xdead_0000_0000_0030;
            interrupted.pstate = 0x5000_0000;
            let (saved_x15, saved_x16, saved_x30, saved_nzcv) = match capture_progress {
                DirectBindingCaptureProgress::None => (
                    0xdead_1000_0000_0015,
                    0xdead_1000_0000_0016,
                    0xdead_1000_0000_0030,
                    0xdead_1000_0000_0000,
                ),
                DirectBindingCaptureProgress::X15 => (
                    original.x[15],
                    0xdead_1000_0000_0016,
                    0xdead_1000_0000_0030,
                    0xdead_1000_0000_0000,
                ),
                DirectBindingCaptureProgress::X15X16 => (
                    original.x[15],
                    original.x[16],
                    0xdead_1000_0000_0030,
                    0xdead_1000_0000_0000,
                ),
                DirectBindingCaptureProgress::X15X16X30 => (
                    original.x[15],
                    original.x[16],
                    original.x[30],
                    0xdead_1000_0000_0000,
                ),
                DirectBindingCaptureProgress::Complete => (
                    original.x[15],
                    original.x[16],
                    original.x[30],
                    original.pstate,
                ),
            };
            if capture_progress == DirectBindingCaptureProgress::None {
                interrupted.x[15] = original.x[15];
            }
            if matches!(
                capture_progress,
                DirectBindingCaptureProgress::None | DirectBindingCaptureProgress::X15
            ) {
                interrupted.x[16] = original.x[16];
            }
            if !matches!(
                capture_progress,
                DirectBindingCaptureProgress::X15X16X30 | DirectBindingCaptureProgress::Complete
            ) {
                interrupted.x[30] = original.x[30];
            }
            if capture_progress != DirectBindingCaptureProgress::Complete {
                interrupted.pstate = original.pstate;
            }

            recover_rewrite_state(
                &mut interrupted,
                actions[0],
                saved_x16,
                original.x[17],
                saved_nzcv,
                saved_x15,
                saved_x30,
                0,
            )
            .map_err(|error| format!("offset {offset} recovery failed: {error}"))?;
            let expected_x30 = committed_link.unwrap_or(original.x[30]);
            if interrupted.x[15] != original.x[15]
                || interrupted.x[16] != original.x[16]
                || interrupted.x[17] != original.x[17]
                || interrupted.x[30] != expected_x30
                || interrupted.pstate != original.pstate
            {
                return Err(format!(
                    "offset {offset} did not recover x15/x16/x17/x30/NZCV exactly"
                ));
            }
            let resume = recovery_resume_pc(link.source, Some(actions[0]))
                .map_err(|error| format!("offset {offset} resume failed: {error}"))?;
            if resume != link.source.raw() {
                return Err(format!(
                    "offset {offset} resumes at 0x{resume:x}, expected source 0x{:x}",
                    link.source.raw()
                ));
            }
        }
        Ok(())
    }

    fn direct_edge_cases(policy: DirectExitEmissionPolicy) -> Vec<(&'static str, AssembledBlock)> {
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
        vec![
            (
                "branch",
                assemble_block_inner(&branch, None, EmitAddressMode::Direct, policy, None)
                    .expect("assemble branch recovery fixture"),
            ),
            (
                "call",
                assemble_block_inner(&call, None, EmitAddressMode::Direct, policy, None)
                    .expect("assemble call recovery fixture"),
            ),
            (
                "conditional",
                assemble_block_inner(&conditional, None, EmitAddressMode::Direct, policy, None)
                    .expect("assemble conditional recovery fixture"),
            ),
            (
                "continue",
                assemble_block_inner(&continuation, None, EmitAddressMode::Direct, policy, None)
                    .expect("assemble continuation recovery fixture"),
            ),
        ]
    }

    #[test]
    fn direct_binding_recovery_covers_every_sidecar_boundary_and_edge_class() {
        let mut kinds = std::collections::BTreeSet::new();
        for (case, emitted) in direct_edge_cases(DirectExitEmissionPolicy::PortableUnitAuthority) {
            for link in &emitted.direct_links {
                kinds.insert(link.kind as u8);
                assert_eq!(link.source.raw() & 3, 0, "{case}: exact source PC");
                assert_eq!(link.target.raw() & 3, 0, "{case}: exact target PC");
                let committed_link = (link.kind == DirectLinkKind::Call)
                    .then_some(link.source.raw().checked_add(4).expect("call link"));
                check_direct_binding_recovery(*link, &emitted.recovery, committed_link)
                    .unwrap_or_else(|error| panic!("{case} {:?}: {error}", link.kind));
            }
        }
        assert_eq!(
            kinds.len(),
            5,
            "branch, call, conditional taken/fall-through, and Continue must all be covered"
        );
    }

    #[test]
    fn direct_binding_recovery_gate_rejects_first_authority_store_hole() {
        let emitted = direct_edge_cases(DirectExitEmissionPolicy::PortableUnitAuthority)
            .into_iter()
            .next()
            .expect("branch recovery fixture")
            .1;
        let link = emitted.direct_links[0];
        let first_authority_store = link.stub.start.get() + 17 * 4;
        let mut recovery = emitted.recovery.to_vec();
        recovery.retain(|entry| entry.cache.get() != first_authority_store);
        let error = check_direct_binding_recovery(link, &recovery, None)
            .expect_err("missing first authority-store recovery entry must fail");
        assert!(
            error.contains("expected exactly one"),
            "unexpected coverage failure: {error}"
        );
    }

    #[test]
    fn private_direct_edges_use_compact_gateway_stubs() {
        // The stub is no longer a FIXED size: it stores two guest PCs, and each is
        // materialized in only the `movz`/`movk` halfwords its value needs
        // (`GuestPcWidth::Narrow`). 56 bytes is the worst case, when both PCs
        // occupy all four halfwords; these fixtures use low guest addresses and
        // land at 32, a 43% reduction. `dsr:x17-materialize` was measured at
        // 29.1% of ALL emitted words, so this is the largest emitted class.
        //
        // The SIDECAR path keeps the fixed four-word form
        // (`GuestPcWidth::Fixed`), because `rewrite_direct_binding_stub`
        // validates its instruction shape at fixed word offsets.
        const PRIVATE_DIRECT_GATEWAY_STUB_WORST_CASE_BYTES: u32 = 56;
        const PRIVATE_DIRECT_GATEWAY_STUB_FIXTURE_BYTES: u32 = 32;

        let mut kinds = std::collections::BTreeSet::new();
        for (case, emitted) in direct_edge_cases(DirectExitEmissionPolicy::PrivateGateway) {
            for link in emitted.direct_links {
                kinds.insert(link.kind as u8);
                let bytes = link.stub.end.get() - link.stub.start.get();
                assert!(
                    bytes <= PRIVATE_DIRECT_GATEWAY_STUB_WORST_CASE_BYTES,
                    "{case} {:?}: private direct stub exceeds the worst case: {bytes}",
                    link.kind,
                );
                assert_eq!(
                    bytes, PRIVATE_DIRECT_GATEWAY_STUB_FIXTURE_BYTES,
                    "{case} {:?}: private direct edge must use the compact direct gateway",
                    link.kind,
                );
            }
        }
        assert_eq!(
            kinds.len(),
            5,
            "branch, call, conditional taken/fall-through, and Continue must be compact"
        );

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
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("emit private fused-exclusive continuation");
        let _ = assembler
            .finalize()
            .expect("finalize private fused-exclusive continuation");
        let link = direct_links
            .into_iter()
            .next()
            .expect("fused-exclusive continuation direct link");
        assert_eq!(link.kind, DirectLinkKind::Continue);
        assert_eq!(
            link.stub.end.get() - link.stub.start.get(),
            PRIVATE_DIRECT_GATEWAY_STUB_FIXTURE_BYTES,
            "fused-exclusive continuation: private direct edge must use the compact direct gateway"
        );
    }

    /// A two-segment fused plan: `nop` / `b.ne 0x5000` / `nop` / `svc #0`.
    fn fused_two_segment_plan() -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4010),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Copy(0xd503_201f),
            }],
            exit: PlannedExit::Direct {
                guest: GuestVa(0x4004),
                // b.ne +0xffc (0x4004 -> 0x5000)
                word: 0x5400_7fe1,
                exit: DirectExit {
                    kind: DirectKind::Conditional,
                    target: GuestVa(0x5000),
                    resume: GuestVa(0x4008),
                    condition: Some(bad64::Condition::NE),
                    register: None,
                    bit: None,
                },
            },
            extensions: vec![super::super::block::PlanExtension {
                entry: GuestVa(0x4008),
                instructions: vec![PlannedInst {
                    guest: GuestVa(0x4008),
                    action: InstAction::Copy(0xd503_201f),
                }],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(0x400c),
                    resume: GuestVa(0x4010),
                },
            }],
        }
    }

    /// The fused fall-through must cost exactly two executed words, and must
    /// NOT save guest x17 -- that save, and the whole entry prologue it feeds,
    /// is what fusion removes.
    #[test]
    fn fused_segment_edge_falls_through_in_two_words_without_saving_guest_x17() {
        let plan = fused_two_segment_plan();
        let assembled = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .expect("assemble fused block");
        let words = &assembled.words;

        // Anchor on the relocated conditional rather than a fixed index: the
        // entry prologue's length is the lean/spilling guard's business, and
        // this test is about the EDGE.
        let edge = words
            .iter()
            // The guest's own conditional, relocated to a taken displacement of
            // 2 -- byte-identical to what a non-fused conditional exit emits.
            .position(|word| *word == 0x5400_0041)
            .expect("relocated conditional, taken -> +2");
        assert_eq!(words[edge - 1], 0xd503_201f, "segment 0 body precedes it");
        // Fall-through hop, then the taken path: two x17 stores and the patch
        // slot. The hop must clear all three.
        assert_eq!(
            words[edge + 1],
            0x1400_0004,
            "fall-through must branch over the taken prologue and the slot"
        );
        assert_eq!(
            &words[edge + 2..edge + 4],
            [0xf900_4791, 0xf902_3791],
            "the x17 saves belong to the TAKEN path only"
        );
        assert_eq!(
            words[edge + 4] & 0xfc00_0000,
            0x1400_0000,
            "taken patch slot is a `b`"
        );
        // ... and the hop lands on segment 1's copied `nop`.
        assert_eq!(
            words[edge + 5],
            0xd503_201f,
            "segment 1 body follows the edge"
        );
        // Only then the terminal exit's own x17 saves.
        assert_eq!(
            words[edge + 6],
            0xf900_4791,
            "terminal exit saves guest x17"
        );

        // One fused edge, one link, and NO fall-through link: the fall-through
        // is an internal branch that must never be patched.
        let kinds: Vec<DirectLinkKind> = assembled
            .direct_links
            .iter()
            .map(|link| link.kind)
            .collect();
        assert_eq!(kinds, vec![DirectLinkKind::ConditionalTaken]);
        let link = assembled.direct_links[0];
        assert_eq!(
            link.slot.get() as usize,
            (edge + 4) * 4,
            "the link's slot is the emitted patch-slot word"
        );
        assert_eq!(link.source, GuestVa(0x4004));
        assert_eq!(link.target, GuestVa(0x5000));
        assert!(
            link.stub.start.get() as usize > (edge + 7) * 4,
            "the taken stub is deferred past the terminal exit, not inlined \
             between the segments (stub starts at {})",
            link.stub.start.get()
        );
    }

    /// The point of the whole exercise: N guest blocks, ONE generation guard.
    #[test]
    fn fused_block_emits_a_single_generation_guard() {
        let guard = GenerationGuard::BindingIndex {
            index: 3,
            expected: CodeGeneration::INITIAL,
        };
        let count_acquires = |plan: &BlockPlan| {
            let assembled = assemble_block_inner(
                plan,
                Some(guard),
                EmitAddressMode::Direct,
                DirectExitEmissionPolicy::PrivateGateway,
                None,
            )
            .expect("assemble guarded block");
            assembled
                .words
                .iter()
                // `ldar x19, [x19]` / `ldar x16, [x16]`: the guard's acquire.
                .filter(|word| (*word & 0xffff_fc00) == 0xc8df_fc00)
                .count()
        };
        let mut unfused = fused_two_segment_plan();
        unfused.extensions.clear();
        unfused.end = GuestVa(0x4008);
        assert_eq!(count_acquires(&unfused), 1);
        assert_eq!(
            count_acquires(&fused_two_segment_plan()),
            1,
            "a fused block must pay ONE guard for both guest blocks"
        );
    }

    /// The planner never builds this, and the region emitter owns the whole
    /// block, so a fused plan carrying one must fail rather than silently drop
    /// the segments and publish a guest range it never translated.
    #[test]
    fn fused_segments_after_an_exclusive_region_are_rejected() {
        let mut plan = fused_two_segment_plan();
        let PlannedExit::Direct { guest, word, .. } = plan.exit else {
            unreachable!("fixture exit is a direct branch")
        };
        plan.exit = PlannedExit::Unsupported {
            guest,
            word,
            op: bad64::Op::B_NE,
        };
        let error = assemble_block_inner(
            &plan,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PrivateGateway,
            None,
        )
        .err()
        .expect("a non-conditional fused edge must be rejected");
        assert!(
            format!("{error:?}").contains("not a direct branch"),
            "unexpected error: {error:?}"
        );
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
                assemble_block_inner(
                    &branch,
                    None,
                    EmitAddressMode::Direct,
                    DirectExitEmissionPolicy::PortableUnitAuthority,
                    None,
                )
                .expect("assemble branch"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x5000),
                    kind: DirectLinkKind::Branch,
                    slot: 12,
                    stub_start: 16,
                    stub_end: 272,
                    committed_link: None,
                }],
            ),
            (
                "call",
                assemble_block_inner(
                    &call,
                    None,
                    EmitAddressMode::Direct,
                    DirectExitEmissionPolicy::PortableUnitAuthority,
                    None,
                )
                .expect("assemble call"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x5000),
                    kind: DirectLinkKind::Call,
                    slot: 28,
                    stub_start: 32,
                    stub_end: 288,
                    committed_link: Some(0x4004),
                }],
            ),
            (
                "conditional",
                assemble_block_inner(
                    &conditional,
                    None,
                    EmitAddressMode::Direct,
                    DirectExitEmissionPolicy::PortableUnitAuthority,
                    None,
                )
                .expect("assemble conditional"),
                vec![
                    ExpectedDirectLink {
                        source: GuestVa(0x4000),
                        target: GuestVa(0x4004),
                        kind: DirectLinkKind::ConditionalFallthrough,
                        slot: 16,
                        stub_start: 24,
                        stub_end: 280,
                        committed_link: None,
                    },
                    ExpectedDirectLink {
                        source: GuestVa(0x4000),
                        target: GuestVa(0x5000),
                        kind: DirectLinkKind::ConditionalTaken,
                        slot: 20,
                        stub_start: 280,
                        stub_end: 536,
                        committed_link: None,
                    },
                ],
            ),
            (
                "continue",
                assemble_block_inner(
                    &continuation,
                    None,
                    EmitAddressMode::Direct,
                    DirectExitEmissionPolicy::PortableUnitAuthority,
                    None,
                )
                .expect("assemble continuation"),
                vec![ExpectedDirectLink {
                    source: GuestVa(0x4004),
                    target: GuestVa(0x4004),
                    kind: DirectLinkKind::Continue,
                    slot: 12,
                    stub_start: 16,
                    stub_end: 272,
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
            DirectExitEmissionPolicy::PortableUnitAuthority,
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
    fn direct_binding_capture_prefix_recovers_only_committed_scratch() {
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
        let assembled = assemble_block_inner(
            &branch,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PortableUnitAuthority,
            None,
        )
        .expect("assemble direct branch");
        let stub = assembled.direct_links[0].stub;
        let live_x15 = 0x1500_0015;
        let live_x16 = 0x1600_0016;
        let live_x17 = 0x1700_0017;
        let live_x30 = 0x3000_0030;
        let live_nzcv = 0x6000_0000;
        let stale_x15 = 0xdead_0015;
        let stale_x16 = 0xdead_0016;
        let stale_x30 = 0xdead_0030;
        let stale_nzcv = 0xdead_0000;
        let cases = [
            (
                "before x15 capture",
                0,
                DirectBindingCaptureProgress::None,
                stale_x15,
                stale_x16,
                stale_x30,
                live_x16,
            ),
            (
                "after x15 capture",
                4,
                DirectBindingCaptureProgress::X15,
                live_x15,
                stale_x16,
                stale_x30,
                live_x16,
            ),
            (
                "after x16 capture",
                8,
                DirectBindingCaptureProgress::X15X16,
                live_x15,
                live_x16,
                stale_x30,
                live_x16,
            ),
            (
                "after x30 capture",
                12,
                DirectBindingCaptureProgress::X15X16X30,
                live_x15,
                live_x16,
                live_x30,
                live_x16,
            ),
            (
                "after nzcv read",
                16,
                DirectBindingCaptureProgress::X15X16X30,
                live_x15,
                live_x16,
                live_x30,
                live_nzcv,
            ),
        ];

        for (case, delta, expected_progress, saved_x15, saved_x16, saved_x30, interrupted_x16) in
            cases
        {
            let action = assembled
                .recovery
                .iter()
                .find(|entry| entry.cache.get() == stub.start.get() + delta)
                .unwrap_or_else(|| panic!("{case}: capture recovery entry"))
                .action;
            assert_eq!(
                action,
                RecoveryAction::RestoreDirectBinding {
                    phase: DirectBindingRecoveryPhase::ScratchCapture,
                    capture_progress: expected_progress,
                    committed_link: None,
                },
                "{case}: typed capture progress"
            );
            let mut snapshot = crate::snapshot::NativeUcontextSnapshot::default();
            snapshot.x[15] = live_x15;
            snapshot.x[16] = interrupted_x16;
            snapshot.x[17] = live_x17;
            snapshot.x[30] = live_x30;
            snapshot.pstate = live_nzcv;

            recover_rewrite_state(
                &mut snapshot,
                action,
                saved_x16,
                live_x17,
                stale_nzcv,
                saved_x15,
                saved_x30,
                0,
            )
            .unwrap_or_else(|error| panic!("{case}: recover capture prefix: {error}"));

            assert_eq!(snapshot.x[15], live_x15, "{case}: x15");
            assert_eq!(snapshot.x[16], live_x16, "{case}: x16");
            assert_eq!(snapshot.x[17], live_x17, "{case}: x17");
            assert_eq!(snapshot.x[30], live_x30, "{case}: x30");
            assert_eq!(snapshot.pstate, live_nzcv, "{case}: NZCV");
        }
    }

    #[test]
    fn sidecar_v1_hit_path_is_exactly_twenty_two_instructions() {
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
        let assembled = assemble_block_inner(
            &branch,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PortableUnitAuthority,
            None,
        )
        .expect("assemble direct branch");
        let link = assembled.direct_links[0];
        let mut code = assembled
            .words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();

        let relocation = rewrite_direct_binding_stub(
            &mut code,
            link,
            crate::direct_binding::DirectBindingOrdinal::claimed(7),
            56,
        )
        .expect("rewrite sidecar stub");
        assert_eq!(relocation.adrp_offset, link.stub.start.get() + 20);
        assert_eq!(relocation.add_offset, link.stub.start.get() + 24);
        assert_eq!(relocation.miss_adrp_offset, link.stub.start.get() + 108);
        assert_eq!(relocation.miss_add_offset, link.stub.start.get() + 112);
        assert_eq!(relocation.data_offset, 56);

        let hit_start = usize::try_from(relocation.adrp_offset).expect("hit start");
        let hit_end = hit_start + 22 * std::mem::size_of::<u32>();
        let hit_words = code[hit_start..hit_end]
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("instruction word")))
            .collect::<Vec<_>>();
        assert_eq!(
            hit_words,
            vec![
                0x9000_000f, // adrp x15, binding-cell-page
                0x9100_01ef, // add x15, x15, binding-cell-pageoff
                0xc8df_fdf1, // ldar x17, [x15]
                0xb400_0271, // cbz x17, miss
                0xf902_8b91, // str x17, [x28, #1296]
                0xf940_0230, // ldr x16, [x17]
                0xa940_fa2f, // ldp x15, x30, [x17, #8]
                0xeb0f_021f, // cmp x16, x15
                0x5400_01c3, // b.lo miss
                0xeb1e_021f, // cmp x16, x30
                0x5400_0182, // b.hs miss
                0xf940_0e31, // ldr x17, [x17, #24]
                0xf902_7b91, // str x17, [x28, #1264]
                0x9112_6391, // add x17, x28, #1176
                0xa900_7a2f, // stp x15, x30, [x17]
                0xf902_1b90, // str x16, [x28, #1072]
                0xf851_0230, // ldur x16, [x17, #-240]
                0xd51b_4210, // msr nzcv, x16
                0xa97f_7a2f, // ldp x15, x30, [x17, #-16]
                0xf85c_8230, // ldur x16, [x17, #-56]
                0xf859_8231, // ldur x17, [x17, #-104]
                0xd61f_0220, // br x17
            ]
        );

        let stub_start = usize::try_from(link.stub.start.get()).expect("stub start");
        let capture_words = code[stub_start..hit_start]
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("capture word")))
            .collect::<Vec<_>>();
        assert_eq!(
            capture_words,
            vec![
                0xf902_478f,
                0xf902_3390,
                0xf902_4b9e,
                0xd53b_4210,
                0xf901_d790,
            ],
            "scratch capture must remain before the 22-word hit path"
        );

        let miss_start = usize::try_from(relocation.miss_adrp_offset).expect("miss start");
        let miss_end = miss_start + 28 * std::mem::size_of::<u32>();
        let miss_words = code[miss_start..miss_end]
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("miss word")))
            .collect::<Vec<_>>();
        assert_eq!(
            miss_words,
            vec![
                0x9000_000f, // adrp x15, binding-cell-page
                0x9100_01ef, // add x15, x15, binding-cell-pageoff
                0xf902_838f, // str x15, [x28, #1280]
                0x5280_00f1, // movz w17, #7
                0x72a0_0011, // movk w17, #0, lsl #16
                0xb905_0b91, // str w17, [x28, #1288]
                0x5280_0031, // mov w17, #1
                0xb905_0f91, // str w17, [x28, #1292]
                0xf902_8b9f, // str xzr, [x28, #1296]
                0xf941_d790, // ldr x16, [x28, #936]
                0xd51b_4210, // msr nzcv, x16
                0xf942_478f, // ldr x15, [x28, #1160]
                0xf942_3390, // ldr x16, [x28, #1120]
                0xf942_4b9e, // ldr x30, [x28, #1168]
                0xd28a_0011, // mov x17, #0x5000
                0xf2a0_0011,
                0xf2c0_0011,
                0xf2e0_0011,
                0xf902_1f91, // str x17, [x28, #1080]
                0xd288_0011, // mov x17, #0x4000
                0xf2a0_0011,
                0xf2c0_0011,
                0xf2e0_0011,
                0xf902_2391, // str x17, [x28, #1088]
                0x5280_0051, // mov w17, #2
                0xb904_4b91, // str w17, [x28, #1096]
                0xf942_6791, // ldr x17, [x28, #1224]
                0xd61f_0220, // br x17
            ],
            "miss path must publish typed identity, restore state, and reuse the direct resolver"
        );
        assert!(
            code[miss_end..usize::try_from(link.stub.end.get()).expect("stub end")]
                .chunks_exact(4)
                .all(|bytes| bytes == 0xd503_201f_u32.to_le_bytes()),
            "unused envelope words must remain unreachable NOP padding"
        );
    }

    #[test]
    fn sidecar_rewrite_rejects_an_envelope_with_the_wrong_instruction_shape() {
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
        let assembled = assemble_block_inner(
            &branch,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PortableUnitAuthority,
            None,
        )
        .expect("assemble direct branch");
        let link = assembled.direct_links[0];
        let mut code = assembled
            .words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let stub_start = usize::try_from(link.stub.start.get()).expect("stub start");
        code[stub_start..stub_start + 4].copy_from_slice(&0xd503_201f_u32.to_le_bytes());

        let error = rewrite_direct_binding_stub(
            &mut code,
            link,
            crate::direct_binding::DirectBindingOrdinal::claimed(0),
            0,
        )
        .expect_err("wrong precursor shape must reject");
        assert!(
            error
                .to_string()
                .contains("direct-binding precursor instruction shape"),
            "unexpected error: {error}"
        );
    }

    fn assert_shape_valid_owner_identity_mismatch_rejects(case: &str, mov_word: usize) {
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
        let assembled = assemble_block_inner(
            &branch,
            None,
            EmitAddressMode::Direct,
            DirectExitEmissionPolicy::PortableUnitAuthority,
            None,
        )
        .expect("assemble direct branch");
        let link = assembled.direct_links[0];
        let mut code = assembled
            .words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let word_offset =
            usize::try_from(link.stub.start.get()).expect("stub start") + mov_word * 4;
        let original = u32::from_le_bytes(
            code[word_offset..word_offset + 4]
                .try_into()
                .expect("MOV-wide word"),
        );
        code[word_offset..word_offset + 4].copy_from_slice(&(original ^ (1 << 5)).to_le_bytes());

        let error = match rewrite_direct_binding_stub(
            &mut code,
            link,
            crate::direct_binding::DirectBindingOrdinal::claimed(0),
            0,
        ) {
            Err(error) => error,
            Ok(_) => panic!("{case}: shape-valid wrong identity must reject"),
        };
        assert!(
            error
                .to_string()
                .contains("direct-binding precursor instruction shape"),
            "{case}: unexpected error: {error}"
        );
    }

    #[test]
    fn sidecar_rewrite_rejects_shape_valid_first_target_identity_mismatch() {
        assert_shape_valid_owner_identity_mismatch_rejects("first target identity", 5);
    }

    #[test]
    fn sidecar_rewrite_rejects_shape_valid_second_target_identity_mismatch() {
        assert_shape_valid_owner_identity_mismatch_rejects("second target identity", 50);
    }

    #[test]
    fn sidecar_rewrite_rejects_shape_valid_source_identity_mismatch() {
        assert_shape_valid_owner_identity_mismatch_rejects("source identity", 55);
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
                capture_progress: DirectBindingCaptureProgress::Complete,
                committed_link: Some(committed_link),
            },
            0x16,
            0x17,
            0x6000_0000,
            0x15,
            0x30,
            0,
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
