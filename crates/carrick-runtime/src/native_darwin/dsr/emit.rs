#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;

use carrick_guest_mem::{GuestVa, HostVa};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation};

use super::block::{BlockPlan, PlannedExit};
use super::cache::{PublishedCode, TranslationCache};
use super::types::{CacheOffset, CacheVa, CodeGeneration, DsrError, InstAction};

const _: () = assert!(super::super::address::INVALID_BIASED_HOST_ADDRESS_BIT == 1 << 47);
const BIASED_FAST_ADDRESS_BITS: u32 = 41;
const _: () =
    assert!(super::super::address::BIASED_GUEST_APERTURE_END <= 1 << BIASED_FAST_ADDRESS_BITS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EmitAddressMode {
    Direct,
    Biased {
        host_bias: super::super::address::NativeHostBias,
    },
}

impl From<super::super::address::NativeAddressMode> for EmitAddressMode {
    fn from(mode: super::super::address::NativeAddressMode) -> Self {
        match mode {
            super::super::address::NativeAddressMode::Direct => Self::Direct,
            super::super::address::NativeAddressMode::Biased { host_bias } => {
                Self::Biased { host_bias }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcMapEntry {
    pub(super) guest: GuestVa,
    pub(super) cache: CacheOffset,
}

#[derive(Debug)]
pub(super) struct InstructionMap {
    entries: Vec<PcMapEntry>,
    forward: BTreeMap<GuestVa, CacheOffset>,
    inverse: BTreeMap<CacheOffset, GuestVa>,
}

impl InstructionMap {
    fn new(entries: Vec<PcMapEntry>) -> Result<Self, DsrError> {
        let mut forward = BTreeMap::new();
        let mut inverse = BTreeMap::new();
        for entry in &entries {
            forward.entry(entry.guest).or_insert(entry.cache);
            if inverse.insert(entry.cache, entry.guest).is_some() {
                return Err(DsrError::CachePolicy(format!(
                    "duplicate cache offset in DSR instruction map: {}",
                    entry.cache.get()
                )));
            }
        }
        Ok(Self {
            entries,
            forward,
            inverse,
        })
    }

    pub(super) fn entries(&self) -> &[PcMapEntry] {
        &self.entries
    }

    pub(super) fn cache_for_guest(&self, guest: GuestVa) -> Option<CacheOffset> {
        self.forward.get(&guest).copied()
    }

    pub(super) fn guest_for_cache(&self, cache: CacheOffset) -> Option<GuestVa> {
        self.inverse.get(&cache).copied()
    }
}

pub(super) struct EmittedBlock {
    code: PublishedCode,
    map: InstructionMap,
    direct_links: Vec<DirectLink>,
    recovery: Vec<RecoveryEntry>,
}

#[derive(Clone, Copy)]
pub(super) struct GenerationGuard {
    address: u64,
    expected: CodeGeneration,
}

impl GenerationGuard {
    pub(super) fn new(current: &AtomicU64, expected: CodeGeneration) -> Self {
        Self {
            address: current as *const AtomicU64 as u64,
            expected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryAction {
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
    RecoverBiasedMemory(BiasedMemoryRecovery),
    RecoverBiasedExclusive(BiasedExclusiveRecovery),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BiasedExclusiveResume {
    Load,
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BiasedExclusiveRecovery {
    pub(super) scratch: super::types::BiasedExclusiveScratch,
    pub(super) resume: BiasedExclusiveResume,
}

impl RecoveryAction {
    pub(super) const fn instruction_complete(self) -> bool {
        match self {
            Self::RestoreScratchCompleted { .. }
            | Self::RestoreScratchAndContextCompleted { .. }
            | Self::RestoreDualVirtualReadOnlyCompleted { .. }
            | Self::CommitVirtualizedAndRestoreScratch { .. }
            | Self::CommitVirtualizedAndRestoreScratchAndContext { .. }
            | Self::CommitDualVirtualAndRestore { .. } => true,
            Self::RecoverBiasedMemory(recovery) => recovery.instruction_complete,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BiasedBase {
    Register(u32),
    StackPointer,
    VirtualX18,
    VirtualX28,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BiasedBaseCoordinate {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BiasedMemoryRecovery {
    pub(super) scratch_registers: [u32; 4],
    pub(super) scratch_count: u8,
    pub(super) base_scratch: u32,
    pub(super) base: BiasedBase,
    pub(super) base_coordinate: BiasedBaseCoordinate,
    pub(super) commit_base: bool,
    pub(super) virtual_x18_scratch: Option<u32>,
    pub(super) virtual_x28_scratch: Option<u32>,
    pub(super) host_bias: super::super::address::NativeHostBias,
    pub(super) instruction_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoveryEntry {
    pub(super) cache: CacheOffset,
    pub(super) action: RecoveryAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirectLink {
    pub(super) slot: CacheOffset,
    pub(super) target: GuestVa,
}

impl EmittedBlock {
    pub(super) const fn entry(&self) -> CacheVa {
        self.code.entry()
    }

    pub(super) const fn len(&self) -> usize {
        self.code.len()
    }

    pub(super) const fn map(&self) -> &InstructionMap {
        &self.map
    }

    pub(super) fn direct_links(&self) -> &[DirectLink] {
        &self.direct_links
    }

    pub(super) fn recovery(&self) -> &[RecoveryEntry] {
        &self.recovery
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
    value: u64,
) -> Result<(), DsrError> {
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

fn emit_gateway_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    target: GuestVa,
    source: Option<GuestVa>,
    status: u32,
    gateway: u64,
) -> Result<(), DsrError> {
    emit_mov_u64(assembler, entries, guest, 17, target.raw())?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1080]
    );
    if let Some(source) = source {
        emit_mov_u64(assembler, entries, guest, 17, source.raw())?;
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
    emit_mov_u64(assembler, entries, guest, 17, gateway)?;
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

fn emit_indirect_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    exit: super::types::IndirectExit,
    recovery: &mut Vec<RecoveryEntry>,
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
        emit_mov_u64(assembler, entries, guest, 30, link.raw())?;
    }
    // A per-thread direct-mapped cache keeps repeated indirect calls and
    // returns inside translated code. Restore every guest-visible scratch
    // value on both hit and miss paths.
    let miss = assembler.new_dynamic_label();
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
        ; ldar x16, [x15]
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
    );
    // The cache entry's generation belongs to the target page, not the source
    // block in the current gateway context. The target block's first-instruction
    // generation guard is the authoritative stale-code check.
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x15, #16]
    );
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; cbz x17, =>miss
    );
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
    emit_mov_u64(assembler, entries, guest, 17, guest.raw())?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x28, #1088]
    );
    if let Some(link) = link {
        emit_mov_u64(assembler, entries, guest, 17, link.raw())?;
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
    emit_mov_u64(
        assembler,
        entries,
        guest,
        17,
        super::gateway::indirect_exit_address(),
    )?;
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
    host_bias: super::super::address::NativeHostBias,
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
        let materialized = if target.raw() < super::super::address::BIASED_GUEST_LITERAL_TARGET_END
        {
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
            let tag = super::super::address::INVALID_BIASED_HOST_ADDRESS_BIT;
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
    let load_base = match base {
        BiasedBase::Register(register) => 0xaa00_03e0 | (register << 16) | base_scratch,
        BiasedBase::StackPointer => 0x9100_03e0 | base_scratch,
        BiasedBase::VirtualX18 => 0xf940_0000 | ((144 / 8) << 10) | (28 << 5) | base_scratch,
        BiasedBase::VirtualX28 => 0xf940_0000 | ((224 / 8) << 10) | (28 << 5) | base_scratch,
        BiasedBase::None => {
            return Err(unsupported_action(
                plan,
                guest,
                memory.word,
                "biased non-literal memory has no base",
            ));
        }
    };
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

pub(super) fn emit_block(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    mode: EmitAddressMode,
) -> Result<EmittedBlock, DsrError> {
    emit_block_inner(cache, plan, None, mode)
}

pub(super) fn emit_block_direct(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
) -> Result<EmittedBlock, DsrError> {
    emit_block(cache, plan, EmitAddressMode::Direct)
}

pub(super) fn emit_block_with_generation(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
    mode: EmitAddressMode,
) -> Result<EmittedBlock, DsrError> {
    emit_block_inner(cache, plan, Some(guard), mode)
}

pub(super) fn emit_block_with_generation_direct(
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
fn emit_region_direct_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    direct_links: &mut Vec<DirectLink>,
    guest: GuestVa,
    target: GuestVa,
    clear_monitor: bool,
) -> Result<(), DsrError> {
    if clear_monitor {
        emit_word(assembler, entries, guest, CLREX_WORD)?;
    }
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
    direct_links.push(DirectLink { slot, target });
    emit_word(assembler, entries, guest, 0x1400_0001)?;
    emit_gateway_exit(
        assembler,
        entries,
        guest,
        target,
        Some(guest),
        2,
        super::gateway::direct_exit_address(),
    )
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
    value: u64,
    scratch: super::types::BiasedExclusiveScratch,
    resume: BiasedExclusiveResume,
) -> Result<(), DsrError> {
    let start = current_offset(assembler)?;
    emit_mov_u64(assembler, entries, guest, register, value)?;
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
    host_bias: super::super::address::NativeHostBias,
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
        host_bias.get(),
        scratch,
        load_resume,
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
                    exit.start,
                    rewritten,
                    scratch,
                    load_resume,
                )?;
            }
            InstAction::Copy(word) => {
                emit_biased_exclusive_word(
                    assembler,
                    entries,
                    recovery,
                    exit.start,
                    word,
                    scratch,
                    load_resume,
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
                    exit.start,
                    relocated,
                    scratch,
                    load_resume,
                )?;
                emit_biased_exclusive_branch(
                    assembler,
                    entries,
                    recovery,
                    exit.start,
                    cont,
                    scratch,
                    load_resume,
                )?;
                emit_biased_exclusive_branch(
                    assembler,
                    entries,
                    recovery,
                    exit.start,
                    restore,
                    scratch,
                    load_resume,
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
        retry_pc,
        success_restore,
        scratch,
        retry_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        retry_pc,
        region_top,
        scratch,
        retry_resume,
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
        retry_pc,
        restore_address,
        scratch,
        retry_resume,
    )?;
    emit_biased_exclusive_word(
        assembler,
        entries,
        recovery,
        retry_pc,
        restore_bias,
        scratch,
        retry_resume,
    )?;
    emit_biased_exclusive_branch(
        assembler,
        entries,
        recovery,
        retry_pc,
        success_tail,
        scratch,
        retry_resume,
    )?;

    if let Some((restore, tail, _, _)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>restore
        );
        emit_biased_exclusive_word(
            assembler,
            entries,
            recovery,
            exit.start,
            CLREX_WORD,
            scratch,
            load_resume,
        )?;
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
            tail,
            scratch,
            load_resume,
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
    emit_region_direct_exit(assembler, entries, direct_links, retry_pc, exit.end, false)?;
    if let Some((_, tail, branch_guest, target)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>tail
        );
        emit_region_direct_exit(
            assembler,
            entries,
            direct_links,
            branch_guest,
            target,
            false,
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
        super::gateway::sensitive_exit_address(),
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
/// Direct mode keeps the established verbatim lowering. Biased mode has a
/// separately tested scratch-based lowering, but the production planner still
/// selects `BiasedDisabled`, so that path is emitted only by focused tests until
/// its runtime recovery handler is enabled in the next task.
#[allow(
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
    emit_region_direct_exit(assembler, entries, direct_links, retry_pc, exit.end, false)?;

    // Compare-failure exit (if the region had an early-exit branch): the store
    // never ran, so the load's reservation is still live and MUST be cleared.
    if let Some((stub, branch_guest, target)) = early_exit {
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; =>stub
        );
        emit_region_direct_exit(assembler, entries, direct_links, branch_guest, target, true)?;
    }

    Ok(())
}

fn emit_block_inner(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: Option<GenerationGuard>,
    mode: EmitAddressMode,
) -> Result<EmittedBlock, DsrError> {
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
        emit_mov_u64(&mut assembler, &mut entries, plan.start, 16, guard.address)?;
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
            guard.expected.get(),
        )?;
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
                super::gateway::syscall_exit_address(),
            )?;
        } else if let PlannedExit::Direct { word, exit, .. } = plan.exit {
            if exit.kind == super::types::DirectKind::Call {
                emit_mov_u64(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    30,
                    exit.resume.raw(),
                )?;
            }
            if matches!(
                exit.kind,
                super::types::DirectKind::Branch | super::types::DirectKind::Call
            ) {
                let slot = current_offset(&assembler)?;
                direct_links.push(DirectLink {
                    slot,
                    target: exit.target,
                });
                emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
                emit_gateway_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit.target,
                    Some(exit_guest),
                    2,
                    super::gateway::direct_exit_address(),
                )?;
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
                direct_links.push(DirectLink {
                    slot: fall_slot,
                    target: exit.resume,
                });
                emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0002)?;
                let taken_slot = current_offset(&assembler)?;
                direct_links.push(DirectLink {
                    slot: taken_slot,
                    target: exit.target,
                });
                emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0012)?;
                emit_gateway_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit.resume,
                    Some(exit_guest),
                    2,
                    super::gateway::direct_exit_address(),
                )?;
                emit_gateway_exit(
                    &mut assembler,
                    &mut entries,
                    exit_guest,
                    exit.target,
                    Some(exit_guest),
                    2,
                    super::gateway::direct_exit_address(),
                )?;
            }
        } else if let PlannedExit::Indirect { exit, .. } = plan.exit {
            emit_indirect_exit(
                &mut assembler,
                &mut entries,
                plan,
                exit_guest,
                exit,
                &mut recovery,
            )?;
        } else if let PlannedExit::Sensitive { exit, .. } = plan.exit {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit.resume,
                Some(exit_guest),
                6,
                super::gateway::sensitive_exit_address(),
            )?;
        } else if let PlannedExit::Continue { target, .. } = plan.exit {
            let slot = current_offset(&assembler)?;
            direct_links.push(DirectLink { slot, target });
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                target,
                Some(exit_guest),
                2,
                super::gateway::direct_exit_address(),
            )?;
        } else if let PlannedExit::Unsupported { .. } = plan.exit {
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit_guest,
                Some(exit_guest),
                7,
                super::gateway::unsupported_exit_address(),
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
            super::gateway::direct_exit_address(),
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
    let mut writer = cache.begin_write(bytes.len())?;
    writer.write_words(&words)?;
    let code = writer.publish()?;
    Ok(EmittedBlock {
        code,
        map,
        direct_links,
        recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::super::block::{BlockLimit, PlannedInst};
    use super::super::types::{
        CodeGeneration, DirectExit, DirectKind, IndirectExit, IndirectKind, MemoryAccess,
        MemoryBase, MemoryClass, MemoryWriteback, PcRelativeInst, PcRelativeKind, SensitiveExit,
        SensitiveKind,
    };
    use super::*;

    #[derive(Clone, Copy)]
    struct EmissionComponentSummary {
        p50_us: f64,
        p95_us: f64,
        min_us: f64,
    }

    fn format_emission_component(name: &str, summary: EmissionComponentSummary) -> String {
        format!(
            "{name}_p50_us={:.3}\n{name}_p95_us={:.3}\n{name}_min_us={:.3}",
            summary.p50_us, summary.p95_us, summary.min_us
        )
    }

    #[cfg(target_arch = "aarch64")]
    fn read_counter() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntvct_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[cfg(target_arch = "aarch64")]
    fn counter_frequency() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntfrq_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[cfg(target_arch = "aarch64")]
    fn measure_emission_component(
        samples: usize,
        batch: usize,
        logical_operations: usize,
        mut operation: impl FnMut(),
    ) -> EmissionComponentSummary {
        for _ in 0..128 {
            operation();
        }
        let mut ticks = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = read_counter();
            for _ in 0..batch {
                operation();
            }
            ticks.push(read_counter().wrapping_sub(start));
        }
        ticks.sort_unstable();
        let frequency = counter_frequency() as f64;
        let divisor = (batch * logical_operations) as f64;
        let to_us = |value: u64| value as f64 * 1_000_000.0 / frequency / divisor;
        let rank = |percentile: f64| {
            let index = (((ticks.len() as f64) * percentile).ceil() as usize)
                .saturating_sub(1)
                .min(ticks.len() - 1);
            to_us(ticks[index])
        };
        EmissionComponentSummary {
            p50_us: rank(0.50),
            p95_us: rank(0.95),
            min_us: to_us(ticks[0]),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn assert_valid_component(summary: EmissionComponentSummary) {
        assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
        assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
        assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
    }

    #[test]
    fn emission_component_output_has_stable_machine_keys() {
        let summary = EmissionComponentSummary {
            p50_us: 0.101,
            p95_us: 0.202,
            min_us: 0.050,
        };
        assert_eq!(
            format_emission_component("dynasm_default", summary),
            "dynasm_default_p50_us=0.101\ndynasm_default_p95_us=0.202\ndynasm_default_min_us=0.050"
        );
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
        }
    }

    fn emitted_words_for_all_gateway_exits() -> Vec<Vec<u32>> {
        let syscall = copy_plan();

        let mut direct = copy_plan();
        direct.exit = PlannedExit::Direct {
            guest: GuestVa(0x4008),
            word: 0x1400_0002,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0x4010),
                resume: GuestVa(0x400c),
                condition: None,
                register: None,
                bit: None,
            },
        };

        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd61f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };

        let mut sensitive = copy_plan();
        sensitive.exit = PlannedExit::Sensitive {
            guest: GuestVa(0x4008),
            word: 0xd53b_d040,
            exit: SensitiveExit {
                kind: SensitiveKind::ReadTpidr,
                register: Some(bad64::Reg::X0),
                resume: GuestVa(0x400c),
            },
            fusion: None,
        };

        let mut continuation = copy_plan();
        continuation.instructions.truncate(1);
        continuation.end = GuestVa(0x4004);
        continuation.exit = PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: BlockLimit::InstructionLimit,
        };

        let mut unsupported = copy_plan();
        unsupported.exit = PlannedExit::Unsupported {
            guest: GuestVa(0x4008),
            word: 0,
            op: bad64::Op::UDF,
        };

        let mut cache = TranslationCache::new(128 * 1024).expect("allocate exit emission cache");
        [
            syscall,
            direct,
            indirect,
            sensitive,
            continuation,
            unsupported,
        ]
        .into_iter()
        .map(|plan| {
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit gateway exit");
            (0..emitted.len() / 4)
                .map(|index| unsafe {
                    std::ptr::read_unaligned(
                        (emitted.entry().host().raw() + index * 4) as *const u32,
                    )
                })
                .collect()
        })
        .collect()
    }

    #[test]
    fn carrick_owned_emitted_blocks_contain_no_brk_transport() {
        for words in emitted_words_for_all_gateway_exits() {
            assert!(words.iter().all(|word| word & 0xffe0_001f != 0xd420_0000));
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    #[ignore = "explicit opt-in native DSR emission component benchmark"]
    fn dsr_emission_component_benchmark() {
        const WORDS: [u32; 64] = [0xd503_201f; 64];
        let bytes = WORDS
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();

        let bad64_decode = measure_emission_component(20_000, 16, 1, || {
            std::hint::black_box(
                bad64::decode(std::hint::black_box(0xf940_0280), 0x4000)
                    .expect("decode benchmark word"),
            );
        });
        let dynasm_default = measure_emission_component(4_000, 16, 1, || {
            let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
            for word in WORDS {
                assembler.push_u32(word);
            }
            std::hint::black_box(assembler.finalize().expect("finalize default assembler"));
        });
        let dynasm_reserved = measure_emission_component(4_000, 16, 1, || {
            let mut assembler = VecAssembler::<Aarch64Relocation>::new_with_capacity(
                0,
                WORDS.len() * 4,
                0,
                0,
                2,
                0,
                4,
            );
            for word in WORDS {
                assembler.push_u32(word);
            }
            std::hint::black_box(assembler.finalize().expect("finalize reserved assembler"));
        });
        let reshape_words = measure_emission_component(20_000, 16, 1, || {
            std::hint::black_box(
                bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>(),
            );
        });
        let copy_bytes = measure_emission_component(20_000, 16, 1, || {
            let mut destination = [0_u8; WORDS.len() * 4];
            destination.copy_from_slice(&bytes);
            std::hint::black_box(destination);
        });

        let measure_jit_window = |logical_blocks: usize| {
            let mut cache =
                TranslationCache::new(32 * 1024 * 1024).expect("allocate emission benchmark cache");
            let words = WORDS.repeat(logical_blocks);
            measure_emission_component(2_000, 1, logical_blocks, || {
                let mut writer = cache
                    .begin_write(words.len() * std::mem::size_of::<u32>())
                    .expect("begin benchmark cache write");
                writer.write_words(&words).expect("write benchmark words");
                std::hint::black_box(writer.publish().expect("publish benchmark words"));
            })
        };
        let jit_window_1 = measure_jit_window(1);
        let jit_window_4 = measure_jit_window(4);
        let jit_window_16 = measure_jit_window(16);

        let generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
        let plan = copy_plan();
        let mut cache = TranslationCache::new(32 * 1024 * 1024)
            .expect("allocate full emission benchmark cache");
        let full_guarded_emit = measure_emission_component(4_000, 1, 1, || {
            std::hint::black_box(
                emit_block_with_generation_direct(
                    &mut cache,
                    &plan,
                    GenerationGuard::new(&generation, CodeGeneration::INITIAL),
                )
                .expect("emit guarded benchmark block"),
            );
        });

        for (name, summary) in [
            ("bad64_decode", bad64_decode),
            ("dynasm_default", dynasm_default),
            ("dynasm_reserved", dynasm_reserved),
            ("reshape_words", reshape_words),
            ("copy_bytes", copy_bytes),
            ("jit_window_1", jit_window_1),
            ("jit_window_4", jit_window_4),
            ("jit_window_16", jit_window_16),
            ("full_guarded_emit", full_guarded_emit),
        ] {
            assert_valid_component(summary);
            println!("{}", format_emission_component(name, summary));
        }
        println!("pure_samples=20000");
        println!("dynasm_samples=4000");
        println!("jit_samples=2000");
        println!("full_emit_samples=4000");
    }

    #[test]
    fn dsr_emit_copy_only_block_decodes_back_with_exact_maps() {
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &copy_plan()).expect("emit copy-only block");
        assert_eq!(emitted.len(), 72);
        let original_words = [0xd503_201f, 0x9100_0400];
        let entry_word =
            unsafe { std::ptr::read_unaligned(emitted.entry().host().raw() as *const u32) };
        assert_eq!(
            bad64::decode(entry_word, emitted.entry().host().raw() as u64)
                .expect("decode entry marker")
                .op(),
            bad64::Op::STR
        );
        for (index, original_word) in original_words.into_iter().enumerate() {
            let offset = (index + 2) * 4;
            let pointer = (emitted.entry().host().raw() + offset) as *const u32;
            let word = unsafe { std::ptr::read_unaligned(pointer) };
            let decoded = bad64::decode(word, emitted.entry().host().raw() as u64 + offset as u64)
                .expect("decode emitted instruction");
            let original = bad64::decode(original_word, 0x4000 + index as u64 * 4)
                .expect("decode original instruction");
            assert_eq!(decoded.op(), original.op());
            assert_eq!(decoded.operands(), original.operands());
        }

        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4000)),
            Some(CacheOffset::published(0))
        );
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(4)),
            Some(GuestVa(0x4000))
        );
        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4004)),
            Some(CacheOffset::published(12))
        );
        for entry in emitted.map().entries() {
            assert_eq!(entry.cache.get() % 4, 0);
            assert_eq!(
                emitted.map().guest_for_cache(entry.cache),
                Some(entry.guest)
            );
        }
    }

    #[test]
    fn dsr_direct_memory_action_emits_the_original_word() {
        let word = 0xf940_0020;
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(MemoryAccess {
                    word,
                    op: bad64::Op::LDR,
                    base: MemoryBase::Register(bad64::Reg::X1),
                    effective_address: super::super::types::MemoryEffectiveAddress::Base,
                    writeback: MemoryWriteback::None,
                    class: MemoryClass::Scalar,
                    virtualization: super::super::types::MemoryVirtualization::None,
                }),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit direct memory block");
        let pointer = (emitted.entry().host().raw() + 8) as *const u32;
        assert_eq!(unsafe { std::ptr::read_unaligned(pointer) }, word);
    }

    #[test]
    fn direct_memory_emission_is_word_identical() {
        let word = 0xf940_0020;
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify direct memory"),
        }];
        plan.end = GuestVa(0x4008);
        plan.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Direct)
            .expect("emit direct memory block");
        let words = (0..emitted.len() / 4).map(|index| unsafe {
            std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
        });
        assert!(words.into_iter().any(|emitted_word| emitted_word == word));
    }

    #[test]
    fn biased_in_range_memory_skips_fault_address_publication_store() {
        let word = 0xf940_0020; // ldr x0, [x1]
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify biased memory"),
        }];
        plan.end = GuestVa(0x4008);
        plan.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let host_bias =
            super::super::super::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("valid bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit biased memory block");
        let words: Vec<u32> = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect();
        let store_masked = 0xf900_0000 | ((1200 / 8) << 10) | (28 << 5);
        let store = words
            .iter()
            .position(|word| word & !0x1f == store_masked)
            .expect("biased invalid path publishes exact guest fault address");
        assert_eq!(
            words.get(store.wrapping_sub(1)).copied(),
            Some(0xb400_0052),
            "cbz must skip the publication store for every in-range access"
        );
    }

    #[test]
    fn direct_memory_emission_matches_full_copy_block_bytes() {
        let word = 0xf940_0020;
        let mut memory = copy_plan();
        memory.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify direct memory"),
        }];
        memory.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let mut copy = memory.clone();
        copy.instructions[0].action = InstAction::Copy(word);
        let mut memory_cache =
            TranslationCache::new(16 * 1024).expect("allocate direct memory cache");
        let mut copy_cache = TranslationCache::new(16 * 1024).expect("allocate direct copy cache");
        let memory_emitted = emit_block(&mut memory_cache, &memory, EmitAddressMode::Direct)
            .expect("emit typed direct memory");
        let copy_emitted = emit_block(&mut copy_cache, &copy, EmitAddressMode::Direct)
            .expect("emit copied direct memory");
        assert_eq!(memory_emitted.len(), copy_emitted.len());
        let memory_bytes = unsafe {
            std::slice::from_raw_parts(
                memory_emitted.entry().host().raw() as *const u8,
                memory_emitted.len(),
            )
        };
        let copy_bytes = unsafe {
            std::slice::from_raw_parts(
                copy_emitted.entry().host().raw() as *const u8,
                copy_emitted.len(),
            )
        };
        assert_eq!(memory_bytes, copy_bytes);
    }

    #[test]
    fn biased_memory_rejects_unsupported_families() {
        let word = 0x8598_5f6f;
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify unsupported SVE memory"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        assert!(matches!(
            emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias },),
            Err(DsrError::UnsupportedBlockAction { .. })
        ));
    }

    #[test]
    fn biased_memory_scratch_selection_handles_x16_x17_operands() {
        for word in [
            0xf940_0030, // ldr x16, [x1]
            0xf900_0031, // str x17, [x1]
            0xf940_0200, // ldr x0, [x16]
            0xf940_0220, // ldr x0, [x17]
        ] {
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify x16/x17 memory fixture"),
            }];
            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct host bias");
            let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
            emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
                .unwrap_or_else(|error| panic!("0x{word:08x} did not lower: {error}"));
        }
    }

    #[test]
    fn biased_constrained_writeback_load_overlap_fails_closed() {
        for word in [
            0xf840_8421, // ldr x1, [x1], #8
            0xa8c1_0821, // ldp x1, x2, [x1], #16
        ] {
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify constrained writeback load"),
            }];
            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct host bias");
            let mut cache = TranslationCache::new(16 * 1024).expect("allocate overlap cache");
            assert!(matches!(
                emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias },),
                Err(DsrError::UnsupportedBlockAction { .. })
            ));
        }
    }

    #[test]
    fn biased_simd_pair_writeback_does_not_alias_gpr_base_by_register_number() {
        let word = 0xadc1_0821; // ldp q1, q2, [x1, #32]!
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify Go cgo SIMD pair load"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate SIMD pair cache");
        emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("SIMD pair destination numbering must not overlap its GPR base");
    }

    #[test]
    fn biased_simd_post_index_does_not_alias_gpr_base_by_register_number() {
        let word = 0x4cdf_2c00; // ld1 {v0.2d-v3.2d}, [x0], #64
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify Go SIMD post-index load"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate SIMD cache");
        emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("SIMD destination numbering must not overlap its GPR base");
    }

    #[test]
    fn biased_recovery_offsets_transition_once_from_retry_to_resume() {
        let word = 0xf81f_8c20; // str x0, [x1, #-8]!
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify writeback store"),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
        };
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate recovery cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit writeback recovery matrix");
        let actions = emitted
            .recovery()
            .iter()
            .filter_map(|entry| match entry.action {
                RecoveryAction::RecoverBiasedMemory(recovery) => Some(recovery),
                _ => None,
            })
            .collect::<Vec<_>>();
        let first_complete = actions
            .iter()
            .position(|action| action.instruction_complete)
            .expect("post-memory recovery exists");
        assert!(first_complete > 0);
        assert!(
            actions[..first_complete]
                .iter()
                .all(|action| !action.instruction_complete && !action.commit_base)
        );
        assert!(
            actions[first_complete..]
                .iter()
                .all(|action| action.instruction_complete)
        );
        assert!(actions.iter().any(|action| {
            action.commit_base && action.base_coordinate == BiasedBaseCoordinate::Host
        }));
        assert!(actions.iter().any(|action| {
            action.commit_base && action.base_coordinate == BiasedBaseCoordinate::Guest
        }));
        assert!(!actions.last().expect("last recovery").commit_base);
    }

    #[test]
    fn biased_dual_virtual_cleanup_does_not_recommit_restored_scratch() {
        let word = 0xf940_0392; // ldr x18, [x28]
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify dual virtual load"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit dual virtual load");
        let final_actions = emitted
            .recovery()
            .iter()
            .filter_map(|entry| match entry.action {
                RecoveryAction::RecoverBiasedMemory(recovery) => Some(recovery),
                _ => None,
            })
            .rev()
            .take(4)
            .collect::<Vec<_>>();
        assert_eq!(final_actions.len(), 4);
        assert!(final_actions.iter().all(|action| {
            action.instruction_complete
                && action.virtual_x18_scratch.is_none()
                && action.virtual_x28_scratch.is_none()
        }));
    }

    #[test]
    fn dsr_direct_unsupported_memory_action_emits_the_original_word() {
        let word = 0x8598_5f6f;
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify direct SVE memory");
        assert!(matches!(
            action,
            InstAction::Memory(memory) if memory.class == MemoryClass::Unsupported
        ));
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
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit direct SVE memory block");
        let pointer = (emitted.entry().host().raw() + 8) as *const u32;
        assert_eq!(unsafe { std::ptr::read_unaligned(pointer) }, word);
    }

    #[test]
    fn dsr_direct_unsupported_memory_keeps_virtual_index_rewrite() {
        let word = 0xa452_48af;
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify direct SVE x18-index memory");
        assert!(matches!(
            action,
            InstAction::Memory(memory)
                if memory.class == MemoryClass::Unsupported
                    && memory.virtualization
                        == super::super::types::MemoryVirtualization::X18
        ));
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
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        emit_block_direct(&mut cache, &plan).expect("emit direct SVE x18-index memory block");
    }

    #[test]
    fn dsr_generation_guard_has_recovery_for_every_interruptible_instruction() {
        use std::sync::atomic::AtomicU64;

        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_with_generation_direct(
            &mut cache,
            &copy_plan(),
            GenerationGuard::new(&generation, CodeGeneration::INITIAL),
        )
        .expect("emit guarded block");
        let words = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect::<Vec<_>>();
        let first_guest = words
            .iter()
            .position(|word| *word == 0xd503_201f)
            .expect("first copied guest instruction");
        for index in 0..first_guest {
            let offset = CacheOffset::published((index * 4) as u32);
            assert!(
                emitted.recovery().iter().any(|entry| entry.cache == offset),
                "generation-guard instruction at cache offset {} has no recovery metadata",
                offset.get()
            );
        }
    }

    #[test]
    fn dsr_emit_relocates_pc_relative_address_subset() {
        let mut plan = copy_plan();
        plan.instructions[0].action = InstAction::PcRelative(PcRelativeInst {
            kind: PcRelativeKind::Adr,
            target: GuestVa(0x5000),
            destination: Some(bad64::Reg::X0),
            word: 0x1000_8000,
        });
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit relocated ADR");
        assert!(emitted.len() > 36);
    }

    #[test]
    fn dsr_emit_direct_link_and_indirect_resolver_exit() {
        let mut direct = copy_plan();
        direct.exit = PlannedExit::Direct {
            guest: GuestVa(0x4008),
            word: 0x1400_0002,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0x4010),
                resume: GuestVa(0x400c),
                condition: None,
                register: None,
                bit: None,
            },
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &direct).expect("emit direct link");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4010));

        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd61f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };
        let emitted =
            emit_block_direct(&mut cache, &indirect).expect("emit indirect resolver exit");
        assert!(emitted.direct_links().is_empty());
    }

    #[test]
    fn dsr_return_publishes_guest_lr_without_physical_x18_staging() {
        let mut plan = copy_plan();
        plan.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd65f_03c0,
            exit: IndirectExit {
                kind: IndirectKind::Return,
                register: bad64::Reg::X30,
                resume: GuestVa(0x400c),
            },
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate return cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit return resolver");
        let words = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect::<Vec<_>>();
        let direct_lr_store = 0xf900_0000 | ((1080 / 8) << 10) | (28 << 5) | 30; // str x30, [x28, #1080]

        assert!(
            words.contains(&direct_lr_store),
            "return resolver must publish guest x30 directly"
        );
        assert!(
            !words.contains(&0xaa1e_03f2),
            "return resolver must not stage guest x30 through physical x18"
        );
    }

    #[test]
    fn dsr_every_emitted_instruction_has_a_guest_pc_mapping() {
        let mut plans = vec![copy_plan()];
        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd63f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Call,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };
        plans.push(indirect);

        let mut cache = TranslationCache::new(32 * 1024).expect("allocate translation cache");
        for plan in plans {
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit mapped block");
            for offset in (0..emitted.len()).step_by(4) {
                let offset = CacheOffset::published(offset as u32);
                assert!(
                    emitted.map().guest_for_cache(offset).is_some(),
                    "emitted instruction at cache offset {} has no guest PC mapping",
                    offset.get()
                );
            }
        }
    }

    #[test]
    fn dsr_indirect_resolver_recovery_is_contiguous_after_scratch_mutation() {
        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd65f_03c0,
            exit: IndirectExit {
                kind: IndirectKind::Return,
                register: bad64::Reg::X30,
                resume: GuestVa(0x400c),
            },
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &indirect).expect("emit indirect resolver");
        let resolver = emitted
            .recovery()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.action,
                    RecoveryAction::RestoreIndirectRegisters
                        | RecoveryAction::RestoreIndirectResolver
                )
            })
            .collect::<Vec<_>>();
        assert!(
            matches!(
                resolver.first().map(|entry| entry.action),
                Some(RecoveryAction::RestoreIndirectRegisters)
            ),
            "resolver must publish its partial recovery point first"
        );
        assert!(
            resolver
                .iter()
                .skip(1)
                .all(|entry| entry.action == RecoveryAction::RestoreIndirectResolver),
            "every instruction after the scratch snapshot must have full recovery"
        );
        assert!(
            resolver
                .windows(2)
                .all(|pair| pair[1].cache.get() == pair[0].cache.get() + 4),
            "resolver recovery metadata must cover every instruction without gaps"
        );
        assert!(
            emitted
                .recovery()
                .iter()
                .any(|entry| entry.action == RecoveryAction::RestoreGuestX17),
            "internal x17 edges need a target-entry recovery point"
        );
    }

    #[test]
    fn dsr_emit_continue_exit_is_a_lazy_direct_link() {
        let mut plan = copy_plan();
        plan.instructions.truncate(1);
        plan.end = GuestVa(0x4004);
        plan.exit = PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: BlockLimit::InstructionLimit,
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit bounded block");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4004));
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(12)),
            Some(GuestVa(0x4004))
        );
    }

    mod exclusive_region_emission {
        use super::super::super::types::{
            BiasedExclusiveScratch, DsrScratchGpr, ExclusiveFusionDisposition, ExclusiveFusionSite,
            ExclusiveRegionExit,
        };
        use super::*;

        // ldaxr w0, [x1] / cmp w0, w2 / stlxr w3, w4, [x1] -- verified encodings
        // shared with the block planner's fusion tests.
        const LDAXR_W0_X1: u32 = 0x885f_fc20;
        const CMP_W0_W2: u32 = 0x6b02_001f;
        const STLXR_W3_W4_X1: u32 = 0x8803_fc24;
        const CLREX: u32 = 0xd503_3f5f;

        struct TestEmittedBlock {
            _cache: TranslationCache,
            emitted: EmittedBlock,
        }

        impl std::ops::Deref for TestEmittedBlock {
            type Target = EmittedBlock;

            fn deref(&self) -> &Self::Target {
                &self.emitted
            }
        }

        fn encode_b_cond(pc: GuestVa, target: GuestVa, cond: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x5400_0000 | (imm19 << 5) | cond
        }

        fn encode_cbnz_w(pc: GuestVa, target: GuestVa, rt: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x3500_0000 | (imm19 << 5) | rt
        }

        fn with_base_register(word: u32, register: u32) -> u32 {
            (word & !(0x1f << 5)) | (register << 5)
        }

        /// Build the `ExclusiveRegion` `BlockPlan` the planner would produce for
        /// the straight-line region `words` (load .. store) with the given retry
        /// and optional early-exit encodings.
        fn region_plan(
            start: GuestVa,
            words: &[u32],
            retry_word: u32,
            early_exit_word: Option<u32>,
        ) -> BlockPlan {
            let mut instructions = Vec::new();
            for (index, &word) in words.iter().enumerate() {
                let guest = GuestVa(start.raw() + (index as u64) * 4);
                let action = if let Some((_, memory)) =
                    super::super::super::decode::classify_exclusive(word, guest)
                        .expect("classify region exclusive")
                {
                    InstAction::Memory(memory)
                } else {
                    super::super::super::decode::classify(word, guest)
                        .expect("classify region body")
                };
                instructions.push(PlannedInst { guest, action });
            }
            let store_guest = GuestVa(start.raw() + ((words.len() - 1) as u64) * 4);
            let retry_pc = GuestVa(store_guest.raw() + 4);
            let end = GuestVa(retry_pc.raw() + 4);
            BlockPlan {
                start,
                end,
                generation: CodeGeneration::INITIAL,
                instructions,
                exit: PlannedExit::ExclusiveRegion {
                    guest: start,
                    word: words[0],
                    exit: ExclusiveRegionExit {
                        start,
                        end,
                        retry_edge: start,
                        load_word: words[0],
                        store_word: *words.last().unwrap(),
                        retry_word,
                        early_exit_word,
                        fallback: SensitiveExit {
                            kind: SensitiveKind::Exclusive(words[0]),
                            register: None,
                            resume: GuestVa(start.raw() + 4),
                        },
                    },
                    fusion: ExclusiveFusionSite {
                        guest: start,
                        word: words[0],
                        disposition: ExclusiveFusionDisposition::FusedDirect,
                        biased_scratch: None,
                    },
                },
            }
        }

        fn emitted_words(emitted: &EmittedBlock) -> Vec<u32> {
            (0..emitted.len() / 4)
                .map(|index| unsafe {
                    std::ptr::read_unaligned(
                        (emitted.entry().host().raw() + index * 4) as *const u32,
                    )
                })
                .collect()
        }

        fn emit_test_biased_cas() -> Result<TestEmittedBlock, DsrError> {
            let start = GuestVa(0x4000);
            let branch = encode_b_cond(GuestVa(0x4008), GuestVa(0x4014), 1);
            let retry = encode_cbnz_w(GuestVa(0x4010), start, 3);
            let mut plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );
            let scratch = BiasedExclusiveScratch {
                address: DsrScratchGpr::new(17).expect("x17 scratch"),
                bias: DsrScratchGpr::new(16).expect("x16 scratch"),
            };
            let PlannedExit::ExclusiveRegion { fusion, .. } = &mut plan.exit else {
                panic!("test plan must be an exclusive region");
            };
            fusion.disposition = ExclusiveFusionDisposition::FusedBiased;
            fusion.biased_scratch = Some(scratch);

            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct test host bias");
            let mut cache = TranslationCache::new(16 * 1024).expect("allocate cache");
            let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })?;
            Ok(TestEmittedBlock {
                _cache: cache,
                emitted,
            })
        }

        fn word_touches_memory(word: u32, pc: u64) -> bool {
            bad64::decode(word, pc).is_ok_and(|inst| {
                inst.operands().iter().any(|operand| {
                    matches!(
                        operand,
                        bad64::Operand::MemReg(_)
                            | bad64::Operand::MemOffset { .. }
                            | bad64::Operand::MemPreIdx { .. }
                            | bad64::Operand::MemPostIdxImm { .. }
                            | bad64::Operand::MemPostIdxReg(_)
                            | bad64::Operand::MemExt { .. }
                    )
                })
            })
        }

        #[test]
        fn biased_region_rewrites_only_the_exclusive_base_and_keeps_pair_clean() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
            let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
            let load = words
                .iter()
                .position(|word| *word == rewritten_load)
                .expect("rewritten load");
            let store = words
                .iter()
                .position(|word| *word == rewritten_store)
                .expect("rewritten store");
            assert!(!words.contains(&LDAXR_W0_X1));
            assert!(!words.contains(&STLXR_W3_W4_X1));
            for (offset, word) in words[load + 1..store].iter().copied().enumerate() {
                let pc = emitted.entry().host().raw() as u64 + ((load + 1 + offset) * 4) as u64;
                assert!(
                    !word_touches_memory(word, pc),
                    "memory word 0x{word:08x} inside pair"
                );
            }
        }

        #[test]
        fn biased_region_recovery_covers_every_post_spill_instruction() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let save_address = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | 17;
            let save_bias = 0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | 16;
            let first_spill = words
                .iter()
                .position(|word| *word == save_address)
                .expect("address scratch spill");
            assert_eq!(words[first_spill + 1], save_bias);
            assert!(emitted.recovery().iter().any(|entry| {
                entry.cache.get() == ((first_spill + 1) * 4) as u32
                    && entry.action == RecoveryAction::Noop
            }));
            let offsets = emitted
                .recovery()
                .iter()
                .filter(|entry| matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_)))
                .map(|entry| entry.cache.get())
                .collect::<Vec<_>>();
            assert!(
                offsets.len() > 4,
                "prelude, pair, retry, and restores need recovery"
            );
            assert_eq!(offsets[0], ((first_spill + 2) * 4) as u32);
            assert!(offsets.windows(2).all(|pair| pair[1] == pair[0] + 4));
            assert!(offsets.iter().all(|offset| {
                emitted
                    .recovery()
                    .iter()
                    .find(|entry| entry.cache.get() == *offset)
                    .is_some_and(|entry| !entry.action.instruction_complete())
            }));

            let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
            let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
            let load = words
                .iter()
                .position(|word| *word == rewritten_load)
                .expect("rewritten load");
            let store = words
                .iter()
                .position(|word| *word == rewritten_store)
                .expect("rewritten store");
            for index in [load, store] {
                let offset = CacheOffset::published((index * 4) as u32);
                assert_eq!(emitted.map().guest_for_cache(offset), Some(GuestVa(0x4000)));
                assert!(emitted.recovery().iter().any(|entry| {
                    entry.cache == offset
                        && matches!(
                            entry.action,
                            RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                                resume: BiasedExclusiveResume::Load,
                                ..
                            })
                        )
                }));
            }
            let retry = words[store + 1..]
                .iter()
                .enumerate()
                .find_map(|(offset, word)| {
                    let index = store + 1 + offset;
                    bad64::decode(
                        *word,
                        emitted.entry().host().raw() as u64 + (index * 4) as u64,
                    )
                    .ok()
                    .filter(|instruction| instruction.op() == bad64::Op::CBNZ)
                    .map(|_| index)
                })
                .expect("rewritten retry branch");
            let retry_offset = CacheOffset::published((retry * 4) as u32);
            assert_eq!(
                emitted.map().guest_for_cache(retry_offset),
                Some(GuestVa(0x4010))
            );
            assert!(emitted.recovery().iter().any(|entry| {
                entry.cache == retry_offset
                    && matches!(
                        entry.action,
                        RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                            resume: BiasedExclusiveResume::Retry,
                            ..
                        })
                    )
            }));
        }

        #[test]
        fn biased_region_slow_stub_restores_scratches_before_sensitive_exit() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let base = emitted.entry().host().raw() as u64;
            let lsr_address = 0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (17 << 5) | 16;
            let validation = words
                .iter()
                .position(|word| *word == lsr_address)
                .expect("address aperture validation");
            let slow_branch = validation + 2;
            let slow_pc = base + (slow_branch * 4) as u64;
            let InstAction::Direct(slow) =
                super::super::super::decode::classify(words[slow_branch], GuestVa(slow_pc))
                    .expect("decode slow branch")
            else {
                panic!("invalid-address edge must branch to its restore stub");
            };
            let slow_restore =
                usize::try_from((slow.target.raw() - base) / 4).expect("slow restore index");
            let restore_address = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | 17;
            let restore_bias = 0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | 16;
            assert_eq!(
                &words[slow_restore..slow_restore + 2],
                &[restore_address, restore_bias]
            );

            let tail_branch = slow_restore + 2;
            let tail_pc = base + (tail_branch * 4) as u64;
            let InstAction::Direct(tail) =
                super::super::super::decode::classify(words[tail_branch], GuestVa(tail_pc))
                    .expect("decode slow-tail branch")
            else {
                panic!("restored slow edge must branch to the sensitive tail");
            };
            let slow_tail =
                usize::try_from((tail.target.raw() - base) / 4).expect("slow tail index");
            let status_six = 0x5280_0000 | (6 << 5) | 17;
            let status = words[slow_tail..]
                .iter()
                .position(|word| *word == status_six)
                .map(|offset| slow_tail + offset)
                .expect("status-6 sensitive exit");
            let target_store = 0xf900_0000 | ((1080 / 8) << 10) | (28 << 5) | 17;
            let target = words[slow_tail..status]
                .iter()
                .position(|word| *word == target_store)
                .map(|offset| slow_tail + offset)
                .expect("sensitive exit target store");
            let target_value = [
                0xd280_0000 | (0x4004 << 5) | 17,
                0xf280_0000 | (1 << 21) | 17,
                0xf280_0000 | (2 << 21) | 17,
                0xf280_0000 | (3 << 21) | 17,
            ];
            assert_eq!(
                &words[target - target_value.len()..target],
                &target_value,
                "slow sensitive exit target must use the published fallback resume PC"
            );
            let source_store = 0xf900_0000 | ((1088 / 8) << 10) | (28 << 5) | 17;
            let source = words[..status]
                .iter()
                .rposition(|word| *word == source_store)
                .expect("sensitive exit source store");
            let source_value = [
                0xd280_0000 | (0x4000 << 5) | 17,
                0xf280_0000 | (1 << 21) | 17,
                0xf280_0000 | (2 << 21) | 17,
                0xf280_0000 | (3 << 21) | 17,
            ];
            assert_eq!(
                &words[source - source_value.len()..source],
                &source_value,
                "slow sensitive exit source must be the original load PC"
            );
        }

        /// (a) A minimal fused region (`ldxr; stxr; cbnz`) emits the exclusive
        /// load and store verbatim and ADJACENT -- proving no block prologue or
        /// context store lands between them (Hazard A).
        #[test]
        fn emits_load_and_store_verbatim_and_adjacent() {
            let start = GuestVa(0x4000);
            let store_pc = GuestVa(0x4004);
            let retry_pc = GuestVa(0x4008);
            let retry = encode_cbnz_w(retry_pc, start, 3);
            let plan = region_plan(start, &[LDAXR_W0_X1, STLXR_W3_W4_X1], retry, None);

            let mut cache = TranslationCache::new(16 * 1024).expect("allocate cache");
            let emitted =
                emit_block_direct(&mut cache, &plan).expect("emit fused minimal exclusive region");
            let words = emitted_words(&emitted);

            let load_index = words
                .iter()
                .position(|&word| word == LDAXR_W0_X1)
                .expect("emitted stream must contain the exclusive load verbatim");
            assert_eq!(
                words[load_index + 1],
                STLXR_W3_W4_X1,
                "the exclusive store must immediately follow the load (no instruction between)"
            );
            let _ = store_pc;
            assert!(
                !words.contains(&CLREX),
                "a region with no early-exit edge has no non-completing exit, so no CLREX"
            );
        }

        /// (b) The canonical CAS region emits exactly one CLREX -- on the
        /// compare-failure early-exit edge (Hazard B) -- and NOTHING that
        /// touches memory sits between the exclusive load and store.
        #[test]
        fn emits_clrex_on_the_compare_failure_edge_only() {
            let start = GuestVa(0x4000);
            let branch_pc = GuestVa(0x4008);
            let store_pc = GuestVa(0x400c);
            let retry_pc = GuestVa(0x4010);
            let out_pc = GuestVa(0x4014);
            let branch = encode_b_cond(branch_pc, out_pc, 1);
            let retry = encode_cbnz_w(retry_pc, start, 3);
            let plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );

            let mut cache = TranslationCache::new(16 * 1024).expect("allocate cache");
            let emitted =
                emit_block_direct(&mut cache, &plan).expect("emit fused canonical CAS region");
            let words = emitted_words(&emitted);

            assert_eq!(
                words.iter().filter(|&&word| word == CLREX).count(),
                1,
                "exactly one CLREX, on the single non-completing (compare-failure) edge"
            );

            let load_index = words
                .iter()
                .position(|&word| word == LDAXR_W0_X1)
                .expect("emitted stream must contain the exclusive load verbatim");
            let store_index = words
                .iter()
                .position(|&word| word == STLXR_W3_W4_X1)
                .expect("emitted stream must contain the exclusive store verbatim");
            assert!(store_index > load_index);
            for (offset, &word) in words[load_index + 1..store_index].iter().enumerate() {
                let pc =
                    emitted.entry().host().raw() as u64 + ((load_index + 1 + offset) * 4) as u64;
                assert!(
                    !word_touches_memory(word, pc),
                    "no memory access may sit between LDXR and STXR (Hazard A): 0x{word:08x}"
                );
            }
            let _ = store_pc;

            // Both exit edges leave to guest VAs via the direct-link resolver.
            let targets: std::collections::BTreeSet<_> = emitted
                .direct_links()
                .iter()
                .map(|link| link.target)
                .collect();
            assert!(
                targets.contains(&out_pc),
                "an exit edge resolves to `end`/`out`"
            );
        }

        /// Every emitted word must be a valid AArch64 instruction, and the two
        /// re-encoded region branches (the compare-failure and retry edges) must
        /// stay the same op family and branch to their block-local trampoline
        /// (taken -> PC+8), never to the original guest displacement.
        #[test]
        fn re_encoded_region_branches_decode_and_target_their_trampolines() {
            let start = GuestVa(0x4000);
            let branch = encode_b_cond(GuestVa(0x4008), GuestVa(0x4014), 1);
            let retry = encode_cbnz_w(GuestVa(0x4010), start, 3);
            let plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );

            let mut cache = TranslationCache::new(16 * 1024).expect("allocate cache");
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit fused CAS region");
            let base = emitted.entry().host().raw() as u64;
            let words = emitted_words(&emitted);

            for (index, &word) in words.iter().enumerate() {
                let pc = base + (index * 4) as u64;
                assert!(
                    bad64::decode(word, pc).is_ok(),
                    "emitted word 0x{word:08x} at +{} must decode",
                    index * 4
                );
            }

            // Re-encoded branch decodes to the same op and, when taken, jumps to
            // its own PC+8 trampoline (not the original guest displacement).
            let relocated_target = |word: u32, pc: u64| -> Option<GuestVa> {
                match super::super::super::decode::classify(word, GuestVa(pc)) {
                    Ok(InstAction::Direct(direct)) => Some(direct.target),
                    _ => None,
                }
            };
            let assert_branch_targets_trampoline = |op: bad64::Op| {
                let (pc, word) = words
                    .iter()
                    .enumerate()
                    .find_map(|(index, &word)| {
                        let pc = base + (index * 4) as u64;
                        bad64::decode(word, pc)
                            .ok()
                            .filter(|inst| inst.op() == op)
                            .map(|_| (pc, word))
                    })
                    .unwrap_or_else(|| panic!("re-encoded {op:?} branch must be present"));
                assert_eq!(
                    relocated_target(word, pc),
                    Some(GuestVa(pc + 8)),
                    "re-encoded {op:?} branch must target its +8 trampoline"
                );
            };
            // The compare-failure edge (b.ne) and the retry edge (cbnz).
            assert_branch_targets_trampoline(bad64::Op::B_NE);
            assert_branch_targets_trampoline(bad64::Op::CBNZ);
        }

        /// (d) The biased path never fuses; if an exclusive `Memory` action ever
        /// reaches biased emission the `:1442` tripwire must still fire.
        #[test]
        fn biased_exclusive_memory_tripwire_still_fires() {
            let word = LDAXR_W0_X1;
            let (_, memory) =
                super::super::super::decode::classify_exclusive(word, GuestVa(0x4000))
                    .expect("classify exclusive")
                    .expect("exclusive load");
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(memory),
            }];
            plan.end = GuestVa(0x4008);
            plan.exit = PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            };
            let bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct test host bias");
            let mut cache = TranslationCache::new(16 * 1024).expect("allocate cache");
            let result = emit_block(
                &mut cache,
                &plan,
                EmitAddressMode::Biased { host_bias: bias },
            );
            match result {
                Err(DsrError::UnsupportedBlockAction { .. }) => {}
                Err(other) => {
                    panic!("biased exclusive emission failed with the wrong error: {other:?}")
                }
                Ok(_) => panic!("biased exclusive emission must trip the :1442 tripwire"),
            }
        }
    }
}
