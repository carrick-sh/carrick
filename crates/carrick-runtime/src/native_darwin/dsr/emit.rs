#![allow(dead_code)] // Emitted blocks enter the context gateway in Task 5.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;

use carrick_guest_mem::GuestVa;
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation};

use super::block::{BlockPlan, PlannedExit};
use super::cache::{PublishedCode, TranslationCache};
use super::types::{CacheOffset, CacheVa, CodeGeneration, DsrError, InstAction};

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
    CommitVirtualizedAndRestoreScratch {
        register: u32,
        virtual_register: u32,
    },
    RestoreScratchAndContext {
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
    CommitDualVirtualAndRestore {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
        virtual_register: u32,
        virtual_scratch: u32,
    },
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
        action: RecoveryAction::RestoreScratch { register: scratch },
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
    target: GuestVa,
    memory_word: u32,
    scratch: u32,
    commit_virtual: Option<(u32, u32)>,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let save = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch;
    let restore = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | scratch;
    emit_word(assembler, entries, guest, save)?;
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
        action: RecoveryAction::RestoreScratch { register: scratch },
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
        action: RecoveryAction::RestoreScratch { register: scratch },
    });
    emit_word(assembler, entries, guest, restore)?;
    Ok(())
}

fn emit_pc_relative_literal(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    relative: super::types::PcRelativeInst,
    recovery: &mut Vec<RecoveryEntry>,
) -> Result<(), DsrError> {
    let opc = relative.word >> 30;
    let vector = (relative.word >> 26) & 1 != 0;
    let destination = relative.word & 0x1f;
    let scratch = if !vector && destination == 17 { 16 } else { 17 };
    if relative.kind == super::types::PcRelativeKind::LiteralPrefetch {
        let word = 0xf980_0000 | (scratch << 5) | destination;
        return emit_recovering_scratch_sequence(
            assembler,
            entries,
            guest,
            relative.target,
            word,
            scratch,
            None,
            recovery,
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
            assembler,
            entries,
            guest,
            relative.target,
            word,
            scratch,
            None,
            recovery,
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
        relative.target,
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
            action: restore,
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
        action: RecoveryAction::RestoreScratchAndContext {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, restore)?;
    recovery.push(RecoveryEntry {
        cache: current_offset(assembler)?,
        action: RecoveryAction::RestoreScratchAndContext {
            register: scratch,
            context_register: context_scratch,
        },
    });
    emit_word(assembler, entries, guest, restore_context)?;
    Ok(())
}

pub(super) fn emit_block(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
) -> Result<EmittedBlock, DsrError> {
    emit_block_inner(cache, plan, None)
}

pub(super) fn emit_block_with_generation(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: GenerationGuard,
) -> Result<EmittedBlock, DsrError> {
    emit_block_inner(cache, plan, Some(guard))
}

fn emit_block_inner(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
    guard: Option<GenerationGuard>,
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
    for instruction in &plan.instructions {
        let word = match instruction.action {
            InstAction::Copy(word) => word,
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
        CodeGeneration, DirectExit, DirectKind, IndirectExit, IndirectKind, PcRelativeInst,
        PcRelativeKind, SensitiveExit, SensitiveKind,
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
            let emitted = emit_block(&mut cache, &plan).expect("emit gateway exit");
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
                emit_block_with_generation(
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
        let emitted = emit_block(&mut cache, &copy_plan()).expect("emit copy-only block");
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
    fn dsr_generation_guard_has_recovery_for_every_interruptible_instruction() {
        use std::sync::atomic::AtomicU64;

        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block_with_generation(
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
        let emitted = emit_block(&mut cache, &plan).expect("emit relocated ADR");
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
        let emitted = emit_block(&mut cache, &direct).expect("emit direct link");
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
        let emitted = emit_block(&mut cache, &indirect).expect("emit indirect resolver exit");
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
        let emitted = emit_block(&mut cache, &plan).expect("emit return resolver");
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
            let emitted = emit_block(&mut cache, &plan).expect("emit mapped block");
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
        let emitted = emit_block(&mut cache, &indirect).expect("emit indirect resolver");
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
        let emitted = emit_block(&mut cache, &plan).expect("emit bounded block");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4004));
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(12)),
            Some(GuestVa(0x4004))
        );
    }
}
