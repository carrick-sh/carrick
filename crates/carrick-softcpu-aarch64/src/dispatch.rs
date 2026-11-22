//! The dispatcher: split and translate the block at `cpu.pc`, run it through
//! an `ExecuteBlock` (the host launch, implemented outside this crate on an
//! arm64 host), map the exit index back to a guest exit, run its handler, and
//! repeat under a block budget. Resident blocks are reused only after checking
//! the current execute translation and the memory owner's code generation.
use crate::exception::{Exception, take_exception};
use crate::handler::{
    self, CodeGeneration, Event, ExclusiveMonitor, GuestMemory, InlineRam, MemoryFault, Outcome,
};
use crate::mmu::{self, AccessClass, PermissionMode, Stage1Error, Stage1Registers};
use crate::state::{CpuState, ExceptionLevel, ProgramCounter, VirtualAddress};
use crate::translate::{
    BlockExit, BlockLimits, CODE_PAGE_BYTES, ExitReason, GuestInstruction, InstructionClass,
    Terminator, TranslateError, TranslatedBlock, emit_block_for_run, split_block_for_run,
};
use alloc::{sync::Arc, vec::Vec};
use carrick_guest_arch::{FrameGpa, Gpa, GuestVa};
use carrick_mmu_core::stage1::{LeafAccess, Stage1Leaf};
use carrick_softmmu::ExtentTableId;
use carrick_softmmu::block_cache::{
    BlockCache, CodeBytes, CodeFootprint, ResidencyBudget, ResidencyCensus, ResidentBlocks,
};
use carrick_softmmu::physical_tlb::PhysicalTlb;
use core::fmt;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU8, Ordering};

/// Permission-checked virtual page tags and RAM loans, live for one launch.
#[derive(Default)]
pub struct BlockMemory<'a> {
    pub read: Option<GuestVa>,
    pub write: Option<GuestVa>,
    pub ram: InlineRam<'a>,
}

/// Checkpoint bound even for a path with no pending event or helper exit.
pub const CHAIN_QUANTUM: u64 = 256;

/// Asynchronous requests for a single run seat. A timer provider asserts the
/// IRQ request when its deadline is reached; the dispatcher owns delivery.
#[derive(Default)]
pub struct RunControl(AtomicU8);

impl RunControl {
    const KICK: u8 = 1;
    const IRQ: u8 = 2;

    pub fn kick(&self) {
        self.0.fetch_or(Self::KICK, Ordering::Release);
    }

    pub fn request_irq(&self) {
        self.0.fetch_or(Self::IRQ, Ordering::Release);
    }

    /// Whether a kick or IRQ request is outstanding, without taking it: a
    /// parked provider probes this after enrolling for its wake.
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire) & (Self::KICK | Self::IRQ) != 0
    }

    fn take(&self, mask: u8) -> bool {
        self.0.load(Ordering::Acquire) & mask != 0
            && self.0.fetch_and(!mask, Ordering::AcqRel) & mask != 0
    }
}

/// The remaining guest step budget and the requests this launch can service.
pub struct ChainBudget<'a> {
    pub steps: u64,
    pub pending: Option<&'a AtomicU8>,
    pub poll_mask: u8,
}

/// Exit of the final block. The intermediate successful edges have already
/// retired their entire blocks and spent one step apiece.
pub struct ChainExit<C> {
    pub exit: usize,
    pub last: Option<Arc<ResidentBlock<C>>>,
    pub preceding_blocks: u64,
    pub preceding_instructions: u64,
    pub indirect_target: ProgramCounter,
}

impl<C> ChainExit<C> {
    pub fn single(exit: usize, pc: ProgramCounter) -> Self {
        Self {
            exit,
            last: None,
            preceding_blocks: 0,
            preceding_instructions: 0,
            indirect_target: pc,
        }
    }
}

/// Prepares translated code and runs it against the CPU's architectural state.
/// The implementation owns executable memory; this crate never executes it.
pub trait ExecuteBlock {
    type Error;
    /// Its footprint is charged to the owner's [`ResidencyBudget`].
    type Code: CodeFootprint;

    /// Whether the dispatcher may keep prepared blocks resident.
    fn retain_blocks(&self) -> bool {
        true
    }

    /// Whether to cache stage-1 translations on providers with a local seat.
    fn retain_stage1(&self) -> bool {
        true
    }

    fn inline_memory(&self) -> bool {
        false
    }

    fn execute_with_memory(
        &mut self,
        block: &TranslatedBlock,
        code: &Self::Code,
        cpu: &mut CpuState,
        _memory: BlockMemory<'_>,
    ) -> Result<usize, Self::Error> {
        self.execute(block, code, cpu)
    }

    fn chain_blocks(&self) -> bool {
        false
    }

    /// The dispatcher admits links only after checking the current execute
    /// translation and code generation. All admitted links share one regime.
    fn link_block(&mut self, _resident: &Arc<ResidentBlock<Self::Code>>) {}

    /// Revoke links to a frame, or all links at a regime or TLBI boundary.
    fn unlink(&mut self, _frame: Option<FrameGpa>) {}

    fn execute_chain(
        &mut self,
        block: &TranslatedBlock,
        code: &Self::Code,
        cpu: &mut CpuState,
        memory: BlockMemory<'_>,
        _budget: ChainBudget<'_>,
    ) -> Result<ChainExit<Self::Code>, Self::Error> {
        let exit = self.execute_with_memory(block, code, cpu, memory)?;
        Ok(ChainExit::single(exit, cpu.pc))
    }

    fn prepare(&mut self, block: &TranslatedBlock) -> Result<Self::Code, Self::Error>;

    /// Run the code prepared for `block`, update `cpu` on success, and return the
    /// index into the block's exit table.
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        code: &Self::Code,
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error>;
}

/// Why `run` returned. `cpu` holds the exact state at that point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop<E> {
    /// A host request interrupted execution at a guest block boundary.
    Kicked,
    /// The block budget was spent; `cpu.pc` is the next block.
    Budget,
    /// The first word of a block could not be fetched.
    Fetch(VirtualAddress),
    /// A handler event the dispatcher does not absorb, at the instruction's PC.
    Event {
        instruction: GuestInstruction,
        event: Event,
    },
    Translate(TranslateError),
    /// The host launch failed, or returned an exit index outside the table.
    Execute(E),
    BadExit(usize),
}

/// Guest-engine work performed during one bounded run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunWork {
    pub retired_instructions: u64,
    /// Host launch attempts.
    pub dispatches: u64,
    /// Guest blocks that ran to a valid exit, including native chain edges.
    pub executed_blocks: u64,
    /// Calls to split and decode a block.
    pub decoded_blocks: u64,
    /// Calls to emit a decoded block.
    pub emitted_blocks: u64,
    pub stage1_walks: u64,
    /// Exits into a scalar, pair, atomic or cache-zero memory handler.
    pub memory_exits: u64,
}

impl RunWork {
    /// Add another bounded run's work to this running total.
    pub fn accumulate(&mut self, other: Self) {
        let Self {
            retired_instructions,
            dispatches,
            executed_blocks,
            decoded_blocks,
            emitted_blocks,
            stage1_walks,
            memory_exits,
        } = other;
        self.retired_instructions = self
            .retired_instructions
            .saturating_add(retired_instructions);
        self.dispatches = self.dispatches.saturating_add(dispatches);
        self.executed_blocks = self.executed_blocks.saturating_add(executed_blocks);
        self.decoded_blocks = self.decoded_blocks.saturating_add(decoded_blocks);
        self.emitted_blocks = self.emitted_blocks.saturating_add(emitted_blocks);
        self.stage1_walks = self.stage1_walks.saturating_add(stage1_walks);
        self.memory_exits = self.memory_exits.saturating_add(memory_exits);
    }
}

/// The result of a bounded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<E> {
    /// Budget steps, including instruction aborts taken before a launch.
    pub blocks: u64,
    pub work: RunWork,
    pub undefined_el0_deliveries: u64,
    pub pc: ProgramCounter,
    pub stop: Stop<E>,
}

impl<E: fmt::Debug> fmt::Display for Report<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boots to PC={:#x} after {} blocks (EL0 undefined deliveries: {}) / ",
            self.pc.0, self.blocks, self.undefined_el0_deliveries
        )?;
        match self.stop {
            Stop::Kicked => write!(f, "stops at a host kick"),
            Stop::Budget => write!(f, "stops at the block budget"),
            Stop::Fetch(a) => write!(f, "fails at: instruction fetch from {:#x}", a.0),
            Stop::Event {
                instruction: i,
                event: Event::MmuEnable { value },
            } => write!(
                f,
                "fails at: SCTLR_EL1.M enable at PC={:#x} (word {:#010x}, value {:#x})",
                i.pc().0,
                i.word(),
                value.0
            ),
            Stop::Event {
                instruction: i,
                event: Event::MemoryFault(m),
            } => write!(
                f,
                "fails at: unmapped guest access {:#x} at PC={:#x} (word {:#010x}, {:?})",
                m.address.0,
                i.pc().0,
                i.word(),
                i.instruction()
            ),
            Stop::Event {
                instruction: i,
                event,
            } => write!(
                f,
                "fails at: {:?} at PC={:#x} (word {:#010x}, {:?})",
                event,
                i.pc().0,
                i.word(),
                i.class()
            ),
            Stop::Translate(e) => write!(f, "fails at: translation {e:?}"),
            Stop::Execute(ref e) => write!(f, "fails at: host launch {e:?}"),
            Stop::BadExit(i) => write!(f, "fails at: exit index {i} outside the block"),
        }
    }
}

/// Events the dispatcher absorbs and continues past.
fn absorbed(event: Event) -> bool {
    matches!(
        event,
        Event::Tlbi(_)
            | Event::Ic(_)
            | Event::IcFrame(_)
            | Event::Hint(crate::Hint::Sev | crate::Hint::Sevl)
    )
}

fn fetch_address(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    pc: ProgramCounter,
) -> Result<Gpa, Stage1Error> {
    mmu::translate(
        cpu,
        memory,
        pc.0,
        LeafAccess::Execute,
        AccessClass::Ordinary,
    )
    .map(Gpa::new)
}

fn read_word(memory: &mut impl GuestMemory, pa: Gpa) -> Result<u32, MemoryFault> {
    let mut bytes = [0; 4];
    memory.fetch(VirtualAddress(pa.raw()), &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockKey {
    pc: u64,
    registers: Stage1Registers,
    el1: bool,
}

impl BlockKey {
    fn for_cpu(cpu: &CpuState) -> Self {
        Self {
            pc: cpu.pc.0,
            registers: Stage1Registers::for_cpu(cpu),
            el1: cpu.pstate.el == ExceptionLevel::El1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CodeIdentity {
    frame: FrameGpa,
    generation: CodeGeneration,
}

pub struct ResidentBlock<C> {
    identity: CodeIdentity,
    prepared: (TranslatedBlock, C),
}

impl<C> ResidentBlock<C> {
    pub fn frame(&self) -> FrameGpa {
        self.identity.frame
    }

    pub fn prepared(&self) -> (&TranslatedBlock, &C) {
        (&self.prepared.0, &self.prepared.1)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CacheContext {
    domain: ExtentTableId,
    limits: BlockLimits,
    chaining: bool,
    inline_memory: bool,
}

/// The AArch64 soft CPU's resident code budget. CPython startup touches
/// ~78k distinct blocks, but its hot set fits well inside this bound under
/// use-aware eviction (#2717). Each block owns one page-rounded executable
/// mapping, so the byte budget binds first only for blocks over 4 KiB; the
/// block count also keeps the per-block mappings far below the host's
/// mapping-count limit.
pub const AARCH64_RESIDENCY: ResidencyBudget = ResidencyBudget::use_aware(
    ResidentBlocks::new(NonZeroUsize::new(16 * 1024).unwrap()),
    CodeBytes::new(64 << 20),
);

/// Compiled code kept resident across [`run_controlled`] calls, so provider
/// exits and quanta do not discard the hot set. It holds code only: every
/// call starts with no stage-1 translations and no native links, and every
/// reuse rechecks the current execute translation and code generation. Code
/// survives a call only for memory that names its inventory
/// ([`GuestMemory::code_cache_domain`]); a different inventory, block limit,
/// chaining mode or inline-memory mode starts empty.
pub struct DispatchCache<C> {
    context: Option<CacheContext>,
    blocks: BlockCache<BlockKey, Arc<ResidentBlock<C>>>,
}

impl<C> Default for DispatchCache<C> {
    fn default() -> Self {
        Self::new(AARCH64_RESIDENCY)
    }
}

impl<C> DispatchCache<C> {
    pub fn new(budget: ResidencyBudget) -> Self {
        Self {
            context: None,
            blocks: BlockCache::new(budget),
        }
    }

    /// Resident code now, and its high-water mark.
    pub fn census(&self) -> ResidencyCensus {
        self.blocks.census()
    }

    /// Drop all resident code.
    pub fn clear(&mut self) {
        self.context = None;
        self.blocks.clear();
    }
}

struct MeasuredMemory<'a, M> {
    inner: &'a mut M,
    walks: u64,
    retain_stage1: bool,
    tlb: Option<PhysicalTlb<Stage1Registers, PermissionMode>>,
    last_read: Option<GuestVa>,
    last_write: Option<GuestVa>,
    code_writes: Option<Vec<FrameGpa>>,
    code_write_failed: bool,
}

impl<M: GuestMemory> MeasuredMemory<'_, M> {
    fn inline_ram(
        &mut self,
        cpu: &CpuState,
        code_frame: FrameGpa,
        monitor: &ExclusiveMonitor,
    ) -> BlockMemory<'_> {
        let Some(tlb) = self.tlb.as_mut() else {
            return BlockMemory::default();
        };
        let regime = Stage1Registers::for_cpu(cpu);
        let mut probe = |page, access| {
            tlb.probe(
                regime,
                page,
                access,
                PermissionMode::for_access(cpu, access, AccessClass::Ordinary),
            )
            .map(Gpa::to_frame_gpa)
        };
        let read = self
            .last_read
            .and_then(|page| probe(page, LeafAccess::Read));
        let write = self
            .last_write
            .filter(|_| !monitor.is_open())
            .and_then(|page| probe(page, LeafAccess::Write))
            .filter(|frame| *frame != code_frame);
        BlockMemory {
            read: self.last_read,
            write: self.last_write,
            ram: self.inner.inline_ram(read, write),
        }
    }
}

impl<M: GuestMemory> GuestMemory for MeasuredMemory<'_, M> {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.inner.read(address, bytes)
    }

    fn fetch(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.inner.fetch(address, bytes)
    }

    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        if let Some(frames) = &mut self.code_writes
            && !bytes.is_empty()
            && let Some(last) = address.0.checked_add(bytes.len() as u64 - 1)
        {
            // Only tracked pages can have links. Notify after the owner has
            // handled the write and while no emitted code is running.
            let first = address.0 & !(CODE_PAGE_BYTES - 1);
            let last = last & !(CODE_PAGE_BYTES - 1);
            frames.extend(
                (first..=last)
                    .step_by(CODE_PAGE_BYTES as usize)
                    .map(FrameGpa::new)
                    .filter(|frame| self.inner.code_generation(*frame).is_some()),
            );
        }
        let result = self.inner.write(address, bytes);
        self.code_write_failed |= result.is_err();
        result
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.inner.code_generation(frame)
    }

    fn invalidate_code_frame(&mut self, frame: FrameGpa) -> Result<bool, MemoryFault> {
        let result = self.inner.invalidate_code_frame(frame);
        self.code_write_failed |= result.is_err();
        result
    }

    fn translate_stage1(
        &mut self,
        cpu: &CpuState,
        va: GuestVa,
        access: LeafAccess,
        class: AccessClass,
    ) -> Result<Gpa, Stage1Error> {
        let mode = PermissionMode::for_access(cpu, access, class);
        if self.retain_stage1 {
            if class == AccessClass::Ordinary {
                let page = Some(GuestVa::new(va.raw() & !(CODE_PAGE_BYTES - 1)));
                match access {
                    LeafAccess::Read => self.last_read = page,
                    LeafAccess::Write => self.last_write = page,
                    LeafAccess::Execute => {}
                }
            }
            let tlb = self.tlb.get_or_insert_with(PhysicalTlb::default);
            if let Some(pa) = tlb.probe(Stage1Registers::for_cpu(cpu), va, access, mode) {
                return Ok(pa);
            }
        }
        let leaf = mmu::walk(cpu, self, va.raw(), access, class)?;
        let pa = Gpa::from_frame_gpa(leaf.output());
        if let Some(tlb) = &mut self.tlb {
            tlb.fill(va, access, mode, pa);
        }
        Ok(pa)
    }

    fn record_stage1_walk(&mut self) {
        self.walks += 1;
        self.inner.record_stage1_walk();
    }
}

/// Run at most `budget` blocks from `cpu.pc`.
pub fn run<X: ExecuteBlock>(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    executor: &mut X,
    limits: BlockLimits,
    budget: u64,
) -> Report<X::Error> {
    // A plain run keeps code only for its own duration.
    let mut cache = DispatchCache::new(AARCH64_RESIDENCY);
    run_inner(
        cpu, monitor, memory, executor, limits, budget, None, &mut cache,
    )
}

/// Like [`run`], with asynchronous requests serviced at block boundaries.
/// Masked IRQs remain pending across calls until the guest unblocks them.
/// `cache` carries compiled code from one call to the next.
#[allow(clippy::too_many_arguments)]
pub fn run_controlled<X: ExecuteBlock>(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    executor: &mut X,
    limits: BlockLimits,
    budget: u64,
    control: &RunControl,
    cache: &mut DispatchCache<X::Code>,
) -> Report<X::Error> {
    run_inner(
        cpu,
        monitor,
        memory,
        executor,
        limits,
        budget,
        Some(control),
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_inner<X: ExecuteBlock>(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    executor: &mut X,
    limits: BlockLimits,
    budget: u64,
    control: Option<&RunControl>,
    residency: &mut DispatchCache<X::Code>,
) -> Report<X::Error> {
    let retain_blocks = executor.retain_blocks();
    let retain_stage1 = executor.retain_stage1() && memory.stage1_is_local();
    let chaining = retain_blocks && retain_stage1 && executor.chain_blocks();
    let mut chain_regime = None;
    if chaining {
        executor.unlink(None);
    }
    let mut blocks = 0;
    let mut work = RunWork::default();
    let memory = &mut MeasuredMemory {
        retain_stage1,
        inner: memory,
        walks: 0,
        tlb: None,
        last_read: None,
        last_write: None,
        code_writes: chaining.then(Vec::new),
        code_write_failed: false,
    };
    let inline_memory = memory.retain_stage1 && executor.inline_memory();
    let context = if retain_blocks {
        memory.inner.code_cache_domain().map(|domain| CacheContext {
            domain,
            limits,
            chaining,
            inline_memory,
        })
    } else {
        None
    };
    if context.is_none() || residency.context != context {
        residency.blocks.clear();
    }
    residency.context = context;
    let cache = &mut residency.blocks;
    let initial_undefined = cpu.undefined_el0_deliveries;
    let stop = loop {
        if blocks >= budget {
            break Stop::Budget;
        }
        if let Some(control) = control
            && control.take(RunControl::KICK)
        {
            break Stop::Kicked;
        }
        // D1.13.4: an unmasked IRQ is taken at the next instruction
        // boundary, from the provider's line or the GIC CPU interface.
        if !cpu.pstate.daif.irq_masked()
            && (control.is_some_and(|control| control.take(RunControl::IRQ)) || cpu.irq_pending())
        {
            monitor.clear();
            take_exception(cpu, Exception::Irq);
        }
        // DDI0487G.a D1.12.4: PC alignment precedes instruction aborts
        // and illegal execution state, so both checks precede block fetch.
        if !cpu.pc.0.is_multiple_of(4) {
            take_exception(cpu, Exception::PcAlignment);
        } else if cpu.pstate.il {
            take_exception(cpu, Exception::IllegalExecutionState);
        }
        // D5.8: an instruction abort on the block's first word is taken at
        // that PC; later words that fault end the block before them, and
        // fault as the first word of the next block.
        let pa = match fetch_address(cpu, memory, cpu.pc) {
            Ok(pa) => pa,
            Err(Stage1Error::Abort(fault)) => match mmu::fault_exception(fault) {
                Some(exception) => {
                    // A taken abort spends one budget step, so a vector that
                    // itself faults cannot spin without bound.
                    take_exception(cpu, exception);
                    blocks += 1;
                    continue;
                }
                None => break Stop::Fetch(VirtualAddress(cpu.pc.0)),
            },
            Err(_) => break Stop::Fetch(VirtualAddress(cpu.pc.0)),
        };
        let key = BlockKey::for_cpu(cpu);
        if chaining {
            let regime = BlockKey { pc: 0, ..key };
            if chain_regime
                .replace(regime)
                .is_some_and(|previous| previous != regime)
            {
                executor.unlink(None);
            }
        }
        let frame = Gpa::new(pa.raw() & !(CODE_PAGE_BYTES - 1)).to_frame_gpa();
        let code = if retain_blocks {
            memory
                .code_generation(frame)
                .map(|generation| CodeIdentity { frame, generation })
        } else {
            None
        };
        let uncached;
        let cached = cache.get(&key);
        let (resident, (block, executable)) =
            if let Some(resident) = cached.filter(|r| Some(r.identity) == code) {
                (Some(resident), resident.prepared())
            } else {
                if chaining && let Some(stale) = cached {
                    executor.unlink(Some(stale.identity.frame));
                }
                let Ok(first) = read_word(memory, pa) else {
                    break Stop::Fetch(VirtualAddress(cpu.pc.0));
                };
                work.decoded_blocks += 1;
                let mut fetched_whole_block = true;
                let guest = split_block_for_run(
                    cpu.pc,
                    limits,
                    cpu.pstate.el,
                    inline_memory && mmu::enabled(cpu),
                    |pc| {
                        let word = if pc == cpu.pc {
                            Some(first)
                        } else {
                            fetch_address(cpu, memory, pc)
                                .ok()
                                .and_then(|pa| read_word(memory, pa).ok())
                        };
                        fetched_whole_block &= word.is_some();
                        word
                    },
                );
                work.emitted_blocks += 1;
                let block = match emit_block_for_run(&guest, chaining) {
                    Ok(block) => block,
                    Err(error) => break Stop::Translate(error),
                };
                let executable = match executor.prepare(&block) {
                    Ok(code) => code,
                    Err(error) => break Stop::Execute(error),
                };
                let prepared = (block, executable);
                let identity = if retain_blocks && fetched_whole_block {
                    memory
                        .inner
                        .mark_code_page(frame)
                        .map(|generation| CodeIdentity { frame, generation })
                } else {
                    None
                };
                if let Some(identity) = identity {
                    let bytes = prepared.1.code_bytes();
                    let resident =
                        cache.insert(key, Arc::new(ResidentBlock { identity, prepared }), bytes);
                    (Some(resident), resident.prepared())
                } else {
                    uncached = prepared;
                    (None, (&uncached.0, &uncached.1))
                }
            };
        if chaining && let Some(resident) = resident {
            executor.link_block(resident);
        }
        work.dispatches += 1;
        // Every successor inherits these loans. The memory owner refuses
        // writable loans to all tracked code, including other linked pages.
        let chain_exit = chaining && !matches!(block.terminator(), Terminator::Handler(_));
        let inline_ram =
            if block.has_inline_memory() || (chain_exit && inline_memory && mmu::enabled(cpu)) {
                memory.inline_ram(cpu, frame, monitor)
            } else {
                BlockMemory::default()
            };
        let result = if chain_exit {
            let poll_mask = RunControl::KICK
                | if cpu.pstate.daif.irq_masked() {
                    0
                } else {
                    RunControl::IRQ
                };
            executor.execute_chain(
                block,
                executable,
                cpu,
                inline_ram,
                ChainBudget {
                    steps: if resident.is_some() {
                        (budget - blocks).min(CHAIN_QUANTUM)
                    } else {
                        1
                    },
                    pending: control.map(|control| &control.0),
                    poll_mask,
                },
            )
        } else {
            executor
                .execute_with_memory(block, executable, cpu, inline_ram)
                .map(|exit| ChainExit::single(exit, cpu.pc))
        };
        let result = match result {
            Ok(result) => result,
            Err(e) => break Stop::Execute(e),
        };
        blocks += 1 + result.preceding_blocks;
        work.executed_blocks += result.preceding_blocks;
        work.retired_instructions += result.preceding_instructions;
        let block = result.last.as_ref().map_or(block, |last| last.prepared().0);
        let index = result.exit;
        let Some(exit) = block.exits().get(index).copied() else {
            break Stop::BadExit(index);
        };
        work.executed_blocks += 1;
        let instructions = block.guest().instructions().len() as u64;
        match exit {
            BlockExit::Continue(pc) => {
                work.retired_instructions += instructions;
                cpu.pc = pc;
            }
            BlockExit::Indirect => {
                work.retired_instructions += instructions;
                cpu.pc = result.indirect_target;
            }
            BlockExit::Handler(i) => {
                // The generated block retires the prefix before the handler.
                work.retired_instructions += i.pc().0.wrapping_sub(block.guest().start().0) / 4;
                if i.class() == InstructionClass::Exit(ExitReason::Memory)
                    || matches!(i.instruction(), crate::Instruction::DataCacheZero(_))
                {
                    work.memory_exits += 1;
                }
                cpu.pc = i.pc();
                let outcome = handler::execute(cpu, monitor, memory, &i);
                if let Some(frames) = &mut memory.code_writes {
                    for frame in frames.drain(..) {
                        executor.unlink(Some(frame));
                    }
                    if core::mem::take(&mut memory.code_write_failed) {
                        executor.unlink(None);
                    }
                }
                match outcome {
                    Outcome::Continue => {
                        work.retired_instructions += 1;
                        // A flat access bypasses the TLB. Drop the previous
                        // regime now, even if the guest later restores its
                        // exact register values before re-enabling stage 1.
                        if memory.tlb.is_some() && !mmu::enabled(cpu) {
                            memory.tlb = None;
                        }
                    }
                    Outcome::Fault => {}
                    Outcome::Event(event) => {
                        match event {
                            Event::Ic(_) => {
                                cache.clear();
                                if chaining {
                                    executor.unlink(None);
                                }
                            }
                            Event::IcFrame(frame) if chaining => executor.unlink(Some(frame)),
                            Event::Tlbi(_) => {
                                if chaining {
                                    executor.unlink(None);
                                }
                                // One local seat. A full flush also covers every
                                // cached 4 KiB subpage of a large stage-1 leaf.
                                if let Some(tlb) = &mut memory.tlb {
                                    tlb.invalidate();
                                }
                            }
                            _ => {}
                        }
                        if matches!(
                            event,
                            Event::ProviderExit(_)
                                | Event::Tlbi(_)
                                | Event::Ic(_)
                                | Event::IcFrame(_)
                                | Event::Hint(_)
                        ) {
                            work.retired_instructions += 1;
                        }
                        if !absorbed(event) {
                            break Stop::Event {
                                instruction: i,
                                event,
                            };
                        }
                    }
                }
            }
        }
    };
    if chaining {
        executor.unlink(None);
    }
    if context.is_none() {
        // Without an inventory identity the code is not valid past this call.
        residency.clear();
    }
    work.stage1_walks = memory.walks;
    Report {
        blocks,
        work,
        undefined_el0_deliveries: cpu.undefined_el0_deliveries.wrapping_sub(initial_undefined),
        pc: cpu.pc,
        stop,
    }
}

#[cfg(test)]
mod tests {
    //! Dispatcher tests. `GuestSemantics` is a test-only `ExecuteBlock` double
    //! that applies a block's guest meaning for a tiny instruction subset; it
    //! exists only to drive the dispatcher's exit mapping and is never a
    //! product path (the product launch runs the emitted host words).
    extern crate std;
    use super::*;
    use crate::state::{ExceptionLevel, StackSelect};
    use crate::translate::{BlockFrame, Terminator, frame};
    use crate::{
        AddSubtract, ArithmeticOperand, Branch, Condition, Instruction, MoveWideOperation,
    };
    use std::collections::BTreeMap;

    struct GuestSemantics;

    fn gpr(frame: &BlockFrame, r: crate::OperandRegister) -> u64 {
        match r {
            crate::OperandRegister::Gpr(g) => frame.slots[usize::from(g.number())],
            crate::OperandRegister::Zr => 0,
            crate::OperandRegister::Sp => frame.slots[(frame::GUEST_SP / 8) as usize],
        }
    }
    fn set(frame: &mut BlockFrame, r: crate::OperandRegister, v: u64) {
        match r {
            crate::OperandRegister::Gpr(g) => frame.slots[usize::from(g.number())] = v,
            crate::OperandRegister::Zr => {}
            crate::OperandRegister::Sp => frame.slots[(frame::GUEST_SP / 8) as usize] = v,
        }
    }

    impl ExecuteBlock for GuestSemantics {
        type Error = &'static str;
        type Code = ();
        fn prepare(&mut self, _: &TranslatedBlock) -> Result<(), Self::Error> {
            Ok(())
        }

        fn execute(
            &mut self,
            block: &TranslatedBlock,
            _: &(),
            cpu: &mut CpuState,
        ) -> Result<usize, &'static str> {
            let mut frame = BlockFrame::from_cpu(cpu);
            let f = &mut frame;
            let nzcv = (frame::NZCV / 8) as usize;
            for i in block.guest().instructions() {
                match i.instruction() {
                    Instruction::MoveWide(m) => {
                        let shift = u32::from(m.shift.value());
                        let imm = u64::from(m.immediate) << shift;
                        let v = match m.operation {
                            MoveWideOperation::Zero => imm,
                            MoveWideOperation::Keep => (gpr(f, m.rd) & !(0xffff << shift)) | imm,
                            MoveWideOperation::Not => !imm,
                        };
                        set(f, m.rd, v);
                    }
                    Instruction::Arithmetic(a) => {
                        let ArithmeticOperand::Immediate(imm) = a.operand else {
                            return Err("double: register operands");
                        };
                        let n = gpr(f, a.rn);
                        let r = match a.op {
                            AddSubtract::Add => n.wrapping_add(imm.value()),
                            AddSubtract::Subtract => n.wrapping_sub(imm.value()),
                        };
                        if a.set_flags {
                            let z = u64::from(r == 0) << 30;
                            let neg = (r >> 63) << 31;
                            let c = u64::from(match a.op {
                                AddSubtract::Add => r < n,
                                AddSubtract::Subtract => n >= imm.value(),
                            }) << 29;
                            f.slots[nzcv] = neg | z | c;
                        }
                        set(f, a.rd, r);
                    }
                    Instruction::Hint(crate::Hint::Nop) | Instruction::Barrier(_) => {}
                    _ if i.class().terminates() => {}
                    _ => return Err("double: instruction outside its subset"),
                }
            }
            let index = match block.terminator() {
                Terminator::Handler(e) | Terminator::Jump(e) | Terminator::Fallthrough(e) => e,
                Terminator::Conditional { fallthrough, taken } => {
                    let Some(Instruction::Branch(Branch::Conditional { condition, .. })) =
                        block.guest().terminator().map(|t| t.instruction())
                    else {
                        return Err("double: only B.cond");
                    };
                    let z = f.slots[nzcv] & (1 << 30) != 0;
                    match condition {
                        Condition::Eq if z => taken,
                        Condition::Ne if !z => taken,
                        Condition::Eq | Condition::Ne => fallthrough,
                        _ => return Err("double: only EQ/NE"),
                    }
                }
            };
            frame.store_to(cpu);
            Ok(index)
        }
    }

    /// Lies about its exit index, to witness the dispatcher's bounds check.
    struct WrongExit;
    impl ExecuteBlock for WrongExit {
        type Error = ();
        type Code = ();
        fn prepare(&mut self, _: &TranslatedBlock) -> Result<(), ()> {
            Ok(())
        }
        fn execute(&mut self, b: &TranslatedBlock, _: &(), _: &mut CpuState) -> Result<usize, ()> {
            Ok(b.exits().len())
        }
    }

    #[derive(Default)]
    struct Flat(BTreeMap<u64, u8>);
    impl Flat {
        fn code(&mut self, at: u64, words: &[u32]) {
            for (i, w) in words.iter().enumerate() {
                for (j, b) in w.to_le_bytes().iter().enumerate() {
                    self.0.insert(at + 4 * i as u64 + j as u64, *b);
                }
            }
        }
    }
    impl GuestMemory for Flat {
        fn read(&mut self, a: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *self.0.get(&(a.0 + i as u64)).ok_or(MemoryFault {
                    address: VirtualAddress(a.0 + i as u64),
                })?;
            }
            Ok(())
        }
        fn write(&mut self, a: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
            for (i, b) in bytes.iter().enumerate() {
                self.0.insert(a.0 + i as u64, *b);
            }
            Ok(())
        }
    }

    const ENTRY: u64 = 0x4000;
    const VBAR: u64 = 0x8000;

    fn el1() -> CpuState {
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(VBAR);
        cpu.pc = ProgramCounter(ENTRY);
        cpu
    }

    fn go<X: ExecuteBlock>(
        cpu: &mut CpuState,
        m: &mut Flat,
        x: &mut X,
        budget: u64,
    ) -> Report<X::Error> {
        run(
            cpu,
            &mut ExclusiveMonitor::default(),
            m,
            x,
            BlockLimits::default(),
            budget,
        )
    }

    #[test]
    fn run_work_distinguishes_retired_instructions_from_memory_exits() {
        let mut m = Flat::default();
        // movz x1, #0; ldr x2, [x1]; hvc #2
        m.code(ENTRY, &[0xd280_0001, 0xf940_0022, 0xd400_0042]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::MemoryFault(_),
                ..
            }
        ));
        assert_eq!(r.blocks, 1);
        assert_eq!(
            r.work,
            RunWork {
                retired_instructions: 1,
                dispatches: 1,
                executed_blocks: 1,
                decoded_blocks: 1,
                emitted_blocks: 1,
                stage1_walks: 0,
                memory_exits: 1,
            }
        );

        m.code(0, &[42, 0]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(r.work.retired_instructions, 3);
        assert_eq!(r.work.memory_exits, 1);

        // A fault delivered to the guest vector never retired.
        m.code(ENTRY, &[0xd280_0001, 0]);
        m.code(VBAR + 0x200, &[0xd400_0042]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(r.work.retired_instructions, 2);
    }

    /// D1.13.4: the GIC's IRQ output is taken at a block boundary while
    /// `PSTATE.I` is clear, at the lower-EL AArch64 IRQ vector with the
    /// interrupted PC; while masked it waits and the thread runs on.
    #[test]
    fn gic_timer_interrupt_preempts_el0_only_when_unmasked() {
        let mut m = Flat::default();
        // nop; hvc #2 (at EL0: undefined), and hvc #2 at the IRQ vector.
        m.code(ENTRY, &[0xd503_201f, 0xd400_0042]);
        m.code(VBAR + 0x480, &[0xd400_0042]);
        let mut cpu = el1();
        cpu.pstate.el = ExceptionLevel::El0;
        cpu.pstate.sp = StackSelect::El0;
        cpu.gic.enable(crate::gic::VIRTUAL_TIMER_INTID, 0x80);
        cpu.gic.configure(0xf0, true);
        cpu.named.cntvcval = crate::state::SystemValue(10);
        cpu.named.cntvctl = crate::state::SystemValue(1);
        cpu.named.cntvct = crate::state::SystemValue(10);
        cpu.pstate.daif = crate::state::InterruptMasks(2);
        let masked = go(&mut cpu.clone(), &mut m, &mut GuestSemantics, 1);
        assert!(matches!(masked.stop, Stop::Budget));

        cpu.pstate.daif = crate::state::InterruptMasks(0);
        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(cpu.el1.elr, ProgramCounter(ENTRY));
        assert_eq!(cpu.pstate.el, ExceptionLevel::El1);
        assert!(cpu.pstate.daif.irq_masked());
        // Taken, not acknowledged: the GIC still signals it.
        assert!(cpu.irq_pending());
    }

    #[test]
    fn report_counts_each_el0_undefined_delivery_once_per_run() {
        let mut cpu = el1();
        cpu.pstate.el = ExceptionLevel::El0;
        cpu.pstate.sp = StackSelect::El0;
        let mut memory = Flat::default();
        // Masked LSE instruction. The EL1 vector executes an unrelated
        // provider exit, which must not affect the EL0 counter.
        memory.code(ENTRY, &[0xf821_0002]);
        memory.code(VBAR + 0x400, &[0xd400_0002]);
        let first = go(&mut cpu, &mut memory, &mut GuestSemantics, 4);
        assert_eq!(first.undefined_el0_deliveries, 1);
        assert_eq!(cpu.el1.elr, ProgramCounter(ENTRY));
        assert_eq!(cpu.el1.esr.0, 0x0200_0000);
        let second = go(&mut cpu, &mut memory, &mut GuestSemantics, 4);
        assert_eq!(second.undefined_el0_deliveries, 0);
    }

    #[test]
    fn loop_svc_vector_and_hvc_reach_the_provider_exit() {
        let mut m = Flat::default();
        // movz x0, #3 ; loop: subs x0, x0, #1 ; b.ne loop ; svc #0
        m.code(ENTRY, &[0xd2800060, 0xf1000400, 0x54ffffe1, 0xd4000001]);
        // EL1h synchronous vector: movz x1, #7 ; hvc #2
        m.code(VBAR + 0x200, &[0xd28000e1, 0xd4000042]);
        let mut cpu = el1();
        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 100);
        // Blocks: [movz,subs,b.ne] + 2x[subs,b.ne] + [svc] + [movz,hvc].
        assert_eq!(r.blocks, 5);
        let Stop::Event {
            instruction,
            event: Event::ProviderExit(exit),
        } = r.stop
        else {
            panic!("{r}");
        };
        assert_eq!(
            (instruction.pc().0, exit.immediate.value()),
            (VBAR + 0x204, 2)
        );
        assert_eq!(r.pc, ProgramCounter(VBAR + 0x208));
        assert_eq!(cpu.el1.elr, ProgramCounter(ENTRY + 16));
        let x = |n| cpu.read_operand(crate::OperandRegister::field(n, false)).0;
        assert_eq!((x(0), x(1)), (0, 7));
        assert_eq!(cpu.pstate.nzcv & 0b0100, 0b0100, "Z from the last subs");
    }

    #[test]
    fn budget_fetch_and_mmu_enable_stop_with_exact_pcs() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0x14000000]); // b . (self loop)
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 3);
        assert_eq!(
            (r.blocks, r.pc, r.stop),
            (3, ProgramCounter(ENTRY), Stop::Budget)
        );

        let r = go(&mut el1(), &mut Flat::default(), &mut GuestSemantics, 3);
        assert_eq!(r.stop, Stop::Fetch(VirtualAddress(ENTRY)));
        assert_eq!(
            std::format!("{r}"),
            "boots to PC=0x4000 after 0 blocks (EL0 undefined deliveries: 0) / fails at: instruction fetch from 0x4000"
        );

        let mut m = Flat::default();
        // movz x0, #1 ; msr sctlr_el1, x0
        m.code(ENTRY, &[0xd2800020, 0xd5181000]);
        let mut cpu = el1();
        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 10);
        assert_eq!(
            std::format!("{r}"),
            "boots to PC=0x4004 after 1 blocks (EL0 undefined deliveries: 0) / fails at: SCTLR_EL1.M enable at \
             PC=0x4004 (word 0xd5181000, value 0x1)"
        );
        assert_eq!(cpu.el1.sctlr.0, 0);
    }

    #[test]
    fn an_exit_index_outside_the_table_is_a_launch_defect() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0xd4000001]);
        let r = go(&mut el1(), &mut m, &mut WrongExit, 10);
        assert_eq!(r.stop, Stop::BadExit(1));
        assert_eq!(r.pc, ProgramCounter(ENTRY));
    }

    #[test]
    fn misaligned_pc_takes_priority_over_illegal_execution_state() {
        for (el, sp, offset, mode) in [
            (ExceptionLevel::El0, StackSelect::El0, 0x400, 0),
            (ExceptionLevel::El1, StackSelect::El0, 0, 4),
            (ExceptionLevel::El1, StackSelect::El1, 0x200, 5),
        ] {
            let mut cpu = el1();
            cpu.pc = ProgramCounter(ENTRY + 2);
            cpu.pstate.el = el;
            cpu.pstate.sp = sp;
            cpu.pstate.il = true;
            let mut m = Flat::default();
            m.code(VBAR + offset, &[0xd4000002]); // hvc #0
            let r = go(&mut cpu, &mut m, &mut GuestSemantics, 1);
            assert!(
                matches!(
                    r.stop,
                    Stop::Event {
                        event: Event::ProviderExit(_),
                        ..
                    }
                ),
                "{r}"
            );
            assert_eq!(cpu.el1.esr.0, 0x8a00_0000);
            assert_eq!(cpu.el1.far.0, ENTRY + 2);
            assert_eq!(cpu.el1.elr.0, ENTRY + 2);
            assert_eq!(cpu.el1.spsr.0, (1 << 20) | mode);
            assert!(!cpu.pstate.il);
        }
    }

    #[test]
    fn restored_il_takes_an_exception_before_the_next_guest_instruction() {
        for (saved_mode, vector, expected_mode) in [
            (1 << 20, 0x400, 0), // legal EL0t return with SPSR.IL set
            (8, 0x200, 5),       // illegal EL2t return retains EL1h
        ] {
            let mut cpu = el1();
            cpu.el1.spsr = crate::state::SavedPstate(saved_mode);
            cpu.el1.elr = ProgramCounter(ENTRY + 4);
            let mut m = Flat::default();
            m.code(ENTRY, &[0xd69f03e0, 0xd28000e0]); // eret; movz x0, #7
            m.code(VBAR + vector, &[0xd4000002]); // hvc #0
            let r = go(&mut cpu, &mut m, &mut GuestSemantics, 2);
            assert!(
                matches!(
                    r.stop,
                    Stop::Event {
                        event: Event::ProviderExit(_),
                        ..
                    }
                ),
                "{r}"
            );
            assert_eq!(cpu.el1.esr.0, 0x3a00_0000);
            assert_eq!(cpu.el1.elr.0, ENTRY + 4);
            assert_eq!(cpu.el1.spsr.0 & 0x10_001f, (1 << 20) | expected_mode);
            assert_eq!(
                cpu.read_operand(crate::OperandRegister::field(0, false)).0,
                0
            );
            assert!(!cpu.pstate.il);
        }
    }

    #[test]
    fn svc_and_eret_restore_the_origin_and_signal_one_local_event() {
        for (el, sp, offset, mode) in [
            (ExceptionLevel::El0, StackSelect::El0, 0x400, 0),
            (ExceptionLevel::El1, StackSelect::El0, 0, 4),
            (ExceptionLevel::El1, StackSelect::El1, 0x200, 5),
        ] {
            let mut cpu = el1();
            cpu.pstate.el = el;
            cpu.pstate.sp = sp;
            cpu.pstate.nzcv = 0xa;
            cpu.pstate.daif.0 = 5;
            cpu.pstate.uao = true;
            let initial = cpu.pstate;
            // Permit WFE so a second wait reports a suspension at either EL.
            cpu.el1.sctlr.0 = 1 << 18;
            let mut m = Flat::default();
            m.code(ENTRY, &[0xd40000e1, 0xd503205f, 0xd503205f]); // svc #7; wfe; wfe
            m.code(VBAR + offset, &[0xd69f03e0]); // eret

            let entry = go(&mut cpu, &mut m, &mut GuestSemantics, 1);
            assert_eq!(entry.pc, ProgramCounter(VBAR + offset));
            assert_eq!(cpu.el1.esr.0, 0x5600_0007);
            assert_eq!(cpu.el1.elr.0, ENTRY + 4);
            assert_eq!(cpu.el1.spsr.0, 0xa080_0140 | mode);
            assert_eq!(cpu.pstate.sp, StackSelect::El1);
            assert_eq!(cpu.pstate.daif.0, 15);
            assert!(cpu.pstate.pan);
            assert!(!cpu.pstate.uao);

            let returned = go(&mut cpu, &mut m, &mut GuestSemantics, 3);
            assert_eq!(cpu.pstate, initial);
            let Stop::Event {
                instruction,
                event: Event::Hint(crate::Hint::Wfe),
            } = returned.stop
            else {
                panic!("{returned}");
            };
            assert_eq!(instruction.pc().0, ENTRY + 8);
            assert_eq!(returned.pc.0, ENTRY + 12);
        }
    }

    #[test]
    fn isb_retires_and_starts_a_new_dispatch_at_the_next_word() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0xd503_3fdf, 0xd400_0002]); // isb; hvc #0
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 2);
        assert_eq!((r.blocks, r.pc), (2, ProgramCounter(ENTRY + 8)));
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
    }

    #[test]
    fn tlbi_is_absorbed_and_execution_continues() {
        let mut m = Flat::default();
        // tlbi vmalle1 ; hvc #0
        m.code(ENTRY, &[0xd508871f, 0xd4000002]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert_eq!(r.blocks, 2);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
    }

    #[test]
    fn production_el0_entry_trampoline_drops_to_el0_and_enters_lower_el_svc_vector() {
        use crate::state::{InterruptMasks, SavedPstate};
        let trampoline = carrick_mem::memory::el0_trampoline_bytes();
        let words: std::vec::Vec<u32> = trampoline
            .chunks_exact(4)
            .take(8)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        let tramp_base = carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
        let user_entry = 0x21_0120;
        let mut m = Flat::default();
        m.code(tramp_base, &words);
        // Unmodified EL0 SVC #0 at user entry.
        m.code(user_entry, &[0xd400_0001]);
        // Current-EL sync fault vector (hvc #3) vs Lower-EL sync vector (hvc #2).
        m.code(VBAR + 0x200, &[0xd400_0062]);
        m.code(VBAR + 0x400, &[0xd400_0042]);

        let mut cpu = el1();
        cpu.pc = ProgramCounter(tramp_base);
        cpu.pstate.daif = InterruptMasks::ALL;
        cpu.el1.elr = ProgramCounter(user_entry);
        // SPSR_EL1 = EL0t with DAIF masked (0x3c0), matching StagedCpu::initial_root.
        cpu.el1.spsr = SavedPstate(0x3c0);

        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 16);
        let Stop::Event {
            instruction,
            event: Event::ProviderExit(exit),
        } = r.stop
        else {
            panic!("{r}");
        };
        assert_eq!(
            (instruction.pc().0, exit.immediate.value()),
            (VBAR + 0x400, 2),
            "expected lower-EL SVC vector (HVC #2), got ESR={:#x} ELR={:#x}: {r}",
            cpu.el1.esr.0,
            cpu.el1.elr.0
        );
        assert_eq!(cpu.el1.elr, ProgramCounter(user_entry + 4));
        assert_eq!(cpu.el1.esr.0, (0x15 << 26) | (1 << 25));
    }
}
