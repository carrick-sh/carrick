//! The stopped soft CPL0 carrier: the shared neutral boot
//! ([`prepare_boot`], [`install_boot_memory`], [`BootCpuState`],
//! [`BootstrapCustody`]) over one [`SoftMachine`], and the soft
//! [`Cpl0BootCarrier`] the shared initial-MM admission
//! ([`carrick_x86_cpl0_host::cpl0_boot::load_guest_mm`]) drives.
//!
//! M1 is single-vCPU (#2397): only physical slot 0 exists.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_el1_abi::CurrentTask;
use carrick_hal::{PhysicalFrameInventory, TrapError, VcpuExit};
use carrick_softcpu_x86::{
    EmitError, GuestCpuidView, SoftAccessKind, SoftMachine, SoftMachineExit, SoftMemoryFault,
    X86Exception, read_guest_bytes,
};
use carrick_softmmu::PAGE_SIZE_4K;
use carrick_x86::cpl0_entry::{CpuBinding, DIRECT_VA, PublishedApicId, PublishedApicIds};
use carrick_x86::{SegmentDescriptor, SegmentDpl, X86Reg, X86Seg, X86Vcpu};
use carrick_x86_cpl0_host::carrier_cpu::{
    CarrierChildBindings, CarrierCpu, OwnedCpuIo, claim_carrier_cpu_io,
};
use carrick_x86_cpl0_host::cpl0_boot::retained_slots::RetainedCarrierSlots;
use carrick_x86_cpl0_host::cpl0_boot::{
    BINDING_OFFSET, BootCpuState, BootMemory, BootstrapCustody, Cpl0BootCarrier, KernelEntry,
    LAYOUT, META_GPA, PreparedBoot, ProductionWorkerParts, ROUTES_OFFSET, fail,
    install_boot_memory, prepare_boot,
};

use crate::backend::{SoftCpuBackend, SoftRunContext};
use crate::cpu::{SoftBootVcpu, SoftCpuView, apply_boot_cpu_state};
use crate::memory::{SoftCarrierMemory, SoftVm};

/// Soft TSC frequency published to the CPUID view and the CPU binding.
pub const SOFT_TSC_HZ: u64 = 2_000_000_000;

/// The single-vCPU clock has a progress floor of 100 ns per executed block.
const SOFT_TSC_TICKS_PER_BLOCK: NonZeroU64 = NonZeroU64::new(SOFT_TSC_HZ / 10_000_000).unwrap();

/// The CPUID view every soft carrier CPU presents. M1 is single-vCPU
/// (#2397): each soft CPU reports APIC ID 0 until the APIC cluster lands.
pub fn soft_cpuid() -> GuestCpuidView {
    GuestCpuidView::x86_64_v3()
        .with_apic_id(0)
        .with_tsc(carrick_x86::TscCrystalRatio::from_hz(SOFT_TSC_HZ))
}

/// Production worker parts over soft CPUs and the soft slot table.
pub type SoftWorkerParts = ProductionWorkerParts<SoftCpuIo, SoftVm>;
/// The sealed soft carrier CPU I/O the shared custody owns.
pub type SoftCpuIo = OwnedCpuIo<SoftCpuBackend>;

/// The ring image and stopped-carrier shape to boot.
#[derive(Clone)]
pub struct SoftBootImage<'a> {
    pub elf: &'a [u8],
    /// Per-slot CPL3 fixture code mapped at `USER_CODE` (empty: none).
    pub programs: [&'a [u8]; 2],
    /// Production boot: an initial guest-MM extent of this many bytes.
    pub initial_extent_bytes: Option<usize>,
    /// The image is the test-support fixture build.
    pub fixture_image: bool,
    /// The production IPC window authority, as KVM's `boot_production` takes.
    pub ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
}

/// Why a soft run stopped without a carrier exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SoftStop {
    /// The soft CPU stopped on an unemulated instruction.
    Unsupported(SoftMachineExit),
    /// Exception delivery escalated past `#DF`.
    TripleFault(X86Exception),
    /// The block budget ran out with no host exit.
    StepBudget { rip: u64 },
    /// Translation or JIT failure inside the soft CPU at instruction `va`.
    Emit { va: u64, detail: String },
    /// The host kicked the run between blocks.
    Kicked,
}

/// What the soft CPU did on its most recent run: the observation the
/// boot probe reports from.
#[derive(Clone, Debug, Default)]
pub struct SoftRunTrace {
    /// Basic blocks retired across every run (the soft CPU does not count
    /// instructions).
    pub blocks: u64,
    /// The last carrier exit, with its `RAX`.
    pub last_exit: Option<(SoftMachineExit, u64)>,
    /// A run that stopped without a carrier exit.
    pub stop: Option<SoftStop>,
    /// Exception deliveries into the ring's fault stubs
    /// (`interrupted rip -> stub rip`).
    pub deliveries: Vec<(u64, u64)>,
    /// Start RIPs of the most recent blocks, oldest first (at most
    /// [`RECENT_BLOCKS`]).
    pub recent: std::collections::VecDeque<u64>,
}

impl SoftRunTrace {
    /// The `n` block RIPs most frequent in [`Self::recent`], with their
    /// counts, hottest first: where a run that stopped without an exit
    /// was spending its blocks.
    pub fn hot_blocks(&self, n: usize) -> Vec<(u64, usize)> {
        let mut counts = std::collections::BTreeMap::<u64, usize>::new();
        for &rip in &self.recent {
            *counts.entry(rip).or_default() += 1;
        }
        let mut hot: Vec<_> = counts.into_iter().collect();
        hot.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        hot.truncate(n);
        hot
    }
}

/// Guest addresses derived from the exact fixture and production ring ELFs.
pub struct SoftRunMarkers {
    /// The first worker's spawn begins each round (RBX = 1 in TWO_LIVE).
    pub spawn: u64,
    pub irq_return: Range<u64>,
    pub rearm: u64,
    pub rotate: u64,
}

#[derive(Clone, Copy, Default)]
struct RunPoint {
    wall: Duration,
    blocks: u64,
    jit_emissions: u64,
    timer: carrick_softcpu_x86::apic::TimerRecognition,
    rearms: u64,
    rotations: u64,
    hlt_waits: u64,
    hlt_wall: Duration,
}

impl RunPoint {
    fn write_since(self, start: Self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wall_ms = millis(self.wall - start.wall);
        let blocks = self.blocks - start.blocks;
        writeln!(
            out,
            "wall_ms={wall_ms:.3} blocks={blocks} jit_emissions={} timer={} deferred={} deferred_blocks={} \
             rearms={} rotations={} hlt_waits={} hlt_ms={:.3}",
            self.jit_emissions - start.jit_emissions,
            self.timer.deliveries - start.timer.deliveries,
            self.timer.deferred_deliveries - start.timer.deferred_deliveries,
            self.timer.deferred_blocks - start.timer.deferred_blocks,
            self.rearms - start.rearms,
            self.rotations - start.rotations,
            self.hlt_waits - start.hlt_waits,
            millis(self.hlt_wall - start.hlt_wall),
        )
    }
}

fn millis(wall: Duration) -> f64 {
    wall.as_secs_f64() * 1000.0
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObservedThread {
    task: u64,
    generation: u64,
}

impl ObservedThread {
    fn read(task: &CurrentTask) -> Self {
        Self {
            task: task.execution.task.load(Ordering::Acquire),
            generation: task.mm.thread_generation.load(Ordering::Acquire),
        }
    }
}

/// The fixture's terminal report over the existing [`SoftRunTrace`].
#[derive(Default)]
pub struct SoftRunSummary {
    rounds: Vec<RunPoint>,
    intervals: Vec<(RunPoint, String)>,
    last: RunPoint,
    terminal: Option<String>,
    user_blocks: BTreeMap<ObservedThread, u64>,
}

impl std::fmt::Display for SoftRunSummary {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wall_seconds = self.last.wall.as_secs_f64();
        let blocks_per_second = if wall_seconds > 0.0 {
            self.last.blocks as f64 / wall_seconds
        } else {
            0.0
        };
        writeln!(
            out,
            "soft TWO_LIVE rounds_started={} blocks_per_second={blocks_per_second:.0}",
            self.rounds.len()
        )?;
        write!(out, "  total ")?;
        self.last.write_since(RunPoint::default(), out)?;

        if let Some(&first) = self.rounds.first() {
            write!(out, "  before round 1 ")?;
            first.write_since(RunPoint::default(), out)?;
        }
        for (index, &start) in self.rounds.iter().enumerate() {
            let end = self.rounds.get(index + 1).copied().unwrap_or(self.last);
            write!(out, "  round {} ", index + 1)?;
            end.write_since(start, out)?;
        }
        let mut previous = RunPoint::default();
        for (index, (end, exit)) in self.intervals.iter().enumerate() {
            write!(out, "  carrier interval {} {exit} ", index + 1)?;
            end.write_since(previous, out)?;
            previous = *end;
        }
        for (thread, blocks) in &self.user_blocks {
            writeln!(
                out,
                "  user task={:#x} generation={} blocks={blocks}",
                thread.task, thread.generation,
            )?;
        }
        if let Some(terminal) = &self.terminal {
            writeln!(out, "  terminal {terminal}")?;
        }
        Ok(())
    }
}

struct FixtureTrace {
    summary: Arc<Mutex<SoftRunSummary>>,
    markers: SoftRunMarkers,
    started: Instant,
    boot_emissions: u64,
    rearms: u64,
    rotations: u64,
    last_observed_block: u64,
    current_thread: Option<ObservedThread>,
    user_blocks: u64,
    thread_blocks: BTreeMap<ObservedThread, u64>,
}

impl FixtureTrace {
    fn point(&self, machine: &SoftMachine<SoftCarrierMemory>) -> RunPoint {
        let counters = machine.counters().copied().unwrap_or_default();
        RunPoint {
            wall: self.started.elapsed(),
            blocks: counters.blocks,
            jit_emissions: machine.cpu().emission_count() - self.boot_emissions,
            timer: machine
                .context()
                .lapic()
                .timer_recognition()
                .unwrap_or_default(),
            rearms: self.rearms,
            rotations: self.rotations,
            hlt_waits: counters.hlt_waits,
            hlt_wall: counters.hlt_wall,
        }
    }

    /// Commit the accumulated blocks when the published user task changes or
    /// the carrier stops. The hot user loop only increments a local counter.
    fn flush_user_blocks(&mut self) {
        if let Some(thread) = self.current_thread {
            *self.thread_blocks.entry(thread).or_default() += std::mem::take(&mut self.user_blocks);
        }
    }

    fn observe_block(
        &mut self,
        machine: &SoftMachine<SoftCarrierMemory>,
        task: Option<&CurrentTask>,
    ) {
        let Some(counters) = machine.counters() else {
            return;
        };
        if counters.blocks == self.last_observed_block {
            return;
        }
        self.last_observed_block = counters.blocks;
        let Some((fetch, cpl)) = counters.last_fetch else {
            return;
        };
        if cpl == 3
            && let Some(task) = task
        {
            let thread = ObservedThread::read(task);
            if self.current_thread != Some(thread) {
                self.flush_user_blocks();
                self.current_thread = Some(thread);
            }
            self.user_blocks += 1;
        }
        if cpl == 3
            && fetch == self.markers.spawn
            && machine.context().gpr[carrick_softcpu_x86::reg::RBX] == 1
        {
            if let Ok(mut summary) = self.summary.lock() {
                // Timestamp immediately after the marked block executes.
                summary.rounds.push(self.point(machine));
            }
        } else if cpl == 0 && self.markers.irq_return.contains(&fetch) {
            // The marked callees are reached only by their direct calls from
            // signal_irq_return. Birth enqueue uses the same rotation callee
            // from elsewhere and must not inflate this count.
            let next = machine.context().rip;
            self.rearms += u64::from(next == self.markers.rearm);
            self.rotations += u64::from(next == self.markers.rotate);
        }
    }
}

/// How many recent block RIPs a [`SoftRunTrace`] keeps.
pub const RECENT_BLOCKS: usize = 512;

/// Observes `(before_cpl, after_cpl, highest_isr_vector)` after each retired
/// soft block so a deterministic witness can inject an inter-CPU claim window
/// across one interrupt without modifying the production CPL0 image.
pub type SoftStepObserver = Box<dyn FnMut(u8, u8, Option<u8>) + Send>;

/// One soft CPU's block loop: runs its [`SoftMachine`] to the next carrier
/// exit under a block budget and an optional kick, and records the
/// [`SoftRunTrace`]. The stopped carrier and the worker backend share it.
pub struct SoftRunner {
    machine: SoftMachine<SoftCarrierMemory>,
    max_blocks: u64,
    trace: SoftRunTrace,
    step_observer: Option<SoftStepObserver>,
    fixture_trace: Option<FixtureTrace>,
}

impl SoftRunner {
    pub fn new(mut machine: SoftMachine<SoftCarrierMemory>, max_blocks: u64) -> Self {
        machine.set_block_tsc_clock(SOFT_TSC_TICKS_PER_BLOCK);
        Self {
            machine,
            max_blocks,
            trace: SoftRunTrace::default(),
            step_observer: None,
            fixture_trace: None,
        }
    }

    pub fn trace(&self) -> &SoftRunTrace {
        &self.trace
    }

    pub fn machine(&self) -> &SoftMachine<SoftCarrierMemory> {
        &self.machine
    }

    pub fn machine_mut(&mut self) -> &mut SoftMachine<SoftCarrierMemory> {
        &mut self.machine
    }

    pub(crate) fn has_fixture_trace(&self) -> bool {
        self.fixture_trace.is_some()
    }

    pub(crate) fn record_fixture_exit(
        &mut self,
        slot: carrick_guest_arch::CpuId,
        task: Option<&CurrentTask>,
        result: &Result<VcpuExit, TrapError>,
        guest_wall: Duration,
    ) {
        let Some(fixture) = &mut self.fixture_trace else {
            return;
        };
        let summary = Arc::clone(&fixture.summary);
        let Ok(mut summary) = summary.lock() else {
            return;
        };
        fixture.flush_user_blocks();
        summary.user_blocks.clone_from(&fixture.thread_blocks);
        let point = fixture.point(&self.machine);
        let interval = match result {
            Ok(VcpuExit::IoOut { port, data }) => format!("out({port:#x}, {data:02x?})"),
            Ok(VcpuExit::Halt) => "hlt".to_owned(),
            Ok(VcpuExit::Kicked) => "kicked".to_owned(),
            Ok(_) => "other carrier exit".to_owned(),
            Err(error) => format!("error({error})"),
        };
        summary.last = point;
        summary.intervals.push((
            point,
            format!("{interval} guest_ms={:.3}", millis(guest_wall)),
        ));

        let cpu = self.machine.context();
        let fetch = self
            .machine
            .counters()
            .and_then(|counters| counters.last_fetch)
            .map_or_else(
                || "none".to_owned(),
                |(rip, cpl)| format!("{rip:#x}/cpl{cpl}"),
            );
        let task = task.map(ObservedThread::read);
        let hot = self.trace.hot_blocks(8);
        summary.terminal = Some(format!(
            "rip={:#x} cpl={} IF={} last_fetch={fetch} slot={} task_and_generation={task:?} \
             budget_blocks={} stop={:?} hot_recent={hot:x?}",
            cpu.rip,
            cpu.cpl,
            (cpu.rflags >> 9) & 1,
            slot.raw(),
            self.trace.blocks,
            self.trace.stop,
        ));
    }

    pub(crate) fn refresh_memory(&mut self) -> Result<(), TrapError> {
        let (cpu, memory) = self.machine.parts_mut();
        if memory.refresh()? {
            // Includes the execute plane. Cached blocks re-authenticate
            // the mapped frame and its code generation on their next entry.
            cpu.context_mut().flush_tlb();
        }
        Ok(())
    }

    pub(crate) fn admit_current_root(&mut self) -> Result<(), TrapError> {
        let root = self.machine.context().cr3 & !(PAGE_SIZE_4K - 1);
        self.machine.mem_mut().admit_root(root)
    }

    /// Run to the next carrier exit (port I/O or `HLT`). `None` is a stop
    /// without one, recorded in [`SoftRunTrace::stop`]; a `kicked` flag
    /// raised before a block stops the run as [`SoftStop::Kicked`].
    pub fn run(&mut self, kicked: Option<&AtomicBool>) -> Option<SoftMachineExit> {
        self.run_with_task(kicked, None)
    }

    pub(crate) fn run_with_task(
        &mut self,
        kicked: Option<&AtomicBool>,
        task: Option<&CurrentTask>,
    ) -> Option<SoftMachineExit> {
        let stubs = DIRECT_VA + carrick_x86::fault_stub_base(LAYOUT)
            ..DIRECT_VA + carrick_x86::fault_tss_base(LAYOUT);
        self.trace.last_exit = None;
        self.trace.stop = None;
        if let Err(error) = self.machine.mem_mut().invalidate_host_writes() {
            self.trace.stop = Some(SoftStop::Emit {
                va: self.machine.context().rip,
                detail: error.to_string(),
            });
            return None;
        }
        loop {
            if kicked.is_some_and(|kick| kick.swap(false, Ordering::AcqRel)) {
                self.trace.stop = Some(SoftStop::Kicked);
                return None;
            }
            if self.trace.blocks >= self.max_blocks {
                self.trace.stop = Some(SoftStop::StepBudget {
                    rip: self.machine.context().rip,
                });
                return None;
            }
            let before = self.machine.context().rip;
            let before_cpl = self.machine.context().cpl;
            let cr3 = self.machine.context().cr3;
            if self.trace.recent.len() == RECENT_BLOCKS {
                self.trace.recent.pop_front();
            }
            self.trace.recent.push_back(before);
            let step = self
                .machine
                .step_with_kick(&|| kicked.is_some_and(|kick| kick.load(Ordering::Acquire)));
            self.trace.blocks += 1;
            if step.is_ok()
                && let Some(fixture) = &mut self.fixture_trace
            {
                fixture.observe_block(&self.machine, task);
            }
            let exit = match step {
                Err(error) => {
                    self.trace.stop = Some(SoftStop::Emit {
                        va: emit_va(&error),
                        detail: format!("{error:?}"),
                    });
                    return None;
                }
                Ok(None) => {
                    let rip = self.machine.context().rip;
                    // The trusted ring can switch to a new address space without
                    // a doorbell. MOV CR3 has already performed privilege checks
                    // and flushed the TLB. Admit the selected retained frame
                    // before the next instruction fetch or interrupt delivery.
                    if (cr3 ^ self.machine.context().cr3) >= PAGE_SIZE_4K
                        && let Err(error) = self.admit_current_root()
                    {
                        self.trace.stop = Some(SoftStop::Emit {
                            va: rip,
                            detail: error.to_string(),
                        });
                        return None;
                    }
                    if stubs.contains(&rip) && !stubs.contains(&before) {
                        self.trace.deliveries.push((before, rip));
                    }
                    if let Some(observer) = self.step_observer.as_mut() {
                        let ctx = self.machine.context();
                        observer(before_cpl, ctx.cpl, ctx.lapic().highest_isr_vector());
                    }
                    continue;
                }
                Ok(Some(exit)) => exit,
            };
            match exit {
                SoftMachineExit::Hlt { .. }
                    if kicked.is_some_and(|kick| kick.swap(false, Ordering::AcqRel)) =>
                {
                    self.trace.stop = Some(SoftStop::Kicked);
                    return None;
                }
                SoftMachineExit::IoOut { .. }
                | SoftMachineExit::IoIn { .. }
                | SoftMachineExit::Hlt { .. } => {
                    let rax = self.machine.context().gpr[carrick_softcpu_x86::reg::RAX];
                    self.trace.last_exit = Some((exit, rax));
                    return Some(exit);
                }
                SoftMachineExit::UnhandledSensitive { .. } => {
                    self.trace.stop = Some(SoftStop::Unsupported(exit));
                }
                SoftMachineExit::TripleFault { last_exception } => {
                    self.trace.stop = Some(SoftStop::TripleFault(last_exception));
                }
                SoftMachineExit::StepBudgetExhausted { rip, .. } => {
                    self.trace.stop = Some(SoftStop::StepBudget { rip });
                }
            }
            return None;
        }
    }
}

/// A stopped soft CPL0 carrier. The machine's memory view retains its own
/// `Arc` of every backing it places, so it never
/// depends on this carrier's custody for liveness.
pub struct SoftCarrier {
    runner: SoftRunner,
    custody: BootstrapCustody<SoftVm>,
    entry: u64,
    /// The backings every soft CPU of this carrier places.
    /// The stopped boot state of physical slot 1, programmed onto the
    /// worker hand-off's second soft CPU.
    peer: BootCpuState,
    hardware_interrupts: bool,
    production: bool,
}

impl SoftCarrier {
    /// Boot `image` on one stopped soft CPU through the shared neutral
    /// preparation, memory installation and CPU state, in the KVM carrier's
    /// order. `max_blocks` bounds every later run.
    pub fn boot(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: SoftBootImage<'_>,
        max_blocks: u64,
    ) -> Result<Self, TrapError> {
        let production = image.initial_extent_bytes.is_some();
        let prepared = prepare_boot(
            &*frame_inventory,
            image.elf,
            image.programs,
            false,
            image.initial_extent_bytes,
            image.fixture_image,
            image.ipc,
        )?;
        let vm = SoftVm::new();
        let BootMemory {
            memory,
            files,
            kernel_region,
            initial_extent,
        } = install_boot_memory(
            vm.clone(),
            &*frame_inventory,
            &prepared,
            false,
            image.initial_extent_bytes,
        )?;
        SoftVm::publish_backings(RetainedCarrierSlots::new(&memory)?)?;
        let PreparedBoot {
            ram,
            plan,
            boot,
            hardware_interrupts,
            kernel_pod_storage,
            ..
        } = prepared;
        let cpuid = soft_cpuid();
        let view = SoftCarrierMemory::new(&vm, LAYOUT.pml4_base)?;
        let mut machine = SoftMachine::new(view, Box::new(cpuid))
            .map_err(|error| fail(format!("soft CPU: {error:?}")))?;
        let slot = carrick_guest_arch::CpuId::new(0);
        let state = BootCpuState::new(plan.entry, &boot, slot, hardware_interrupts, production)?;
        let peer = BootCpuState::new(
            plan.entry,
            &boot,
            carrick_guest_arch::CpuId::new(1),
            hardware_interrupts,
            production,
        )?;
        apply_boot_cpu_state(
            machine.context_mut(),
            &cpuid,
            &state,
            hardware_interrupts,
            production,
        )?;
        let hz = machine.context().tsc_hz();
        if hz == 0 {
            return Err(fail("soft CPU reported no usable TSC frequency"));
        }
        let binding = ram
            .host_ptr(META_GPA + BINDING_OFFSET, size_of::<CpuBinding>())
            .ok_or_else(|| fail("CPU binding backing"))?
            .cast::<CpuBinding>();
        // SAFETY: the CPU is stopped and `prepare_boot` initialized this
        // retained binding; atomic publication precedes guest entry.
        unsafe { (*binding).tsc_hz.store(hz, Ordering::Release) };
        if hardware_interrupts {
            let apic = machine.context().lapic().apic_id();
            let routes = ram
                .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
                .ok_or_else(|| fail("APIC route table backing"))?
                .cast::<PublishedApicIds>();
            // SAFETY: stopped bootstrap initialized this retained table; no
            // guest or host reader exists before publication completes.
            let routes = unsafe { &*routes };
            // M1 is single-vCPU (#2397): only slot 0 is created and published.
            if !routes.publish(slot, PublishedApicId(apic)) {
                return Err(fail("invalid APIC slot publication"));
            }
        }
        Ok(Self {
            runner: SoftRunner::new(machine, max_blocks),
            custody: BootstrapCustody::new(
                memory,
                ram,
                initial_extent,
                kernel_region,
                files,
                frame_inventory,
                kernel_pod_storage,
            )?,
            entry: plan.entry,
            peer,
            hardware_interrupts,
            production,
        })
    }

    /// The ring image's entry point.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn trace(&self) -> &SoftRunTrace {
        self.runner.trace()
    }

    pub fn machine(&self) -> &SoftMachine<SoftCarrierMemory> {
        self.runner.machine()
    }

    pub(crate) fn machine_mut(&mut self) -> &mut SoftMachine<SoftCarrierMemory> {
        self.runner.machine_mut()
    }

    /// Override the soft vCPU's per-block TSC progress floor and future run
    /// block ceiling before handing slot 0 to worker custody.
    pub fn set_execution_clock(&mut self, ticks_per_block: NonZeroU64, max_blocks: u64) {
        self.runner
            .machine_mut()
            .set_block_tsc_clock(ticks_per_block);
        self.runner.max_blocks = max_blocks;
    }

    /// Observe `(before_cpl, after_cpl, highest_isr_vector)` after each soft
    /// block retired on slot 0.
    pub fn set_step_observer(&mut self, observer: SoftStepObserver) {
        self.runner.step_observer = Some(observer);
    }

    /// Collect a summary for a marked fixture after initial-MM admission.
    pub fn observe_fixture(&mut self, markers: SoftRunMarkers) -> Arc<Mutex<SoftRunSummary>> {
        let summary = Arc::new(Mutex::new(SoftRunSummary::default()));
        self.runner.machine.observe_run();
        self.runner.fixture_trace = Some(FixtureTrace {
            summary: Arc::clone(&summary),
            markers,
            started: Instant::now(),
            boot_emissions: self.runner.machine.cpu().emission_count(),
            rearms: 0,
            rotations: 0,
            last_observed_block: 0,
            current_thread: None,
            user_blocks: 0,
            thread_blocks: BTreeMap::new(),
        });
        summary
    }

    /// Read `dst.len()` bytes at guest `va` through slot 0's translation in
    /// its current mode.
    pub fn read_guest_bytes(&mut self, va: u64, dst: &mut [u8]) -> Result<(), SoftMemoryFault> {
        let (cpu, memory) = self.runner.machine_mut().parts_mut();
        read_guest_bytes(cpu.context_mut(), memory, va, dst, SoftAccessKind::Read)
    }

    /// Hand both physical CPUs to production worker custody, as KVM's
    /// `Cpl0Carrier::into_worker_parts` does: slot 0 is the stopped root CPU
    /// whose image becomes the issued root's state; slot 1 is a second soft
    /// CPU in its stopped boot state. M1 is single-vCPU (#2397): the idle
    /// peer is not started, so the root runs with no peer in the zone.
    pub fn into_worker_parts(mut self) -> Result<SoftWorkerParts, TrapError> {
        let root_state = self
            .custody
            .worker_root_state(&carrick_x86::snapshot(&SoftCpuView(
                self.runner.machine().context(),
            ))?)?;
        let run = |slot| SoftRunContext {
            ram: Arc::clone(self.custody.ram()),
            actual_run: Arc::clone(self.custody.actual_run()),
            file_execution: Arc::clone(self.custody.file_execution()),
            slot: carrick_guest_arch::CpuId::new(slot),
            maintenance_root: self.custody.maintenance_root(),
        };
        let [first_run, second_run] = [run(0), run(1)];
        let maintenance_root = self
            .custody
            .maintenance_root()
            .ok_or_else(|| fail("soft production run has no maintenance root"))?;
        // The ring switches to this custody-issued root without exiting to
        // the host. Admit it in both CPU views before either can run.
        self.runner
            .machine_mut()
            .mem_mut()
            .admit_root(maintenance_root.address().raw())?;
        let cpuid = soft_cpuid();
        let mut view = SoftCarrierMemory::new(self.custody.memory().vm(), LAYOUT.pml4_base)?;
        view.admit_root(maintenance_root.address().raw())?;
        let mut peer = SoftMachine::new(view, Box::new(cpuid))
            .map_err(|error| fail(format!("soft peer CPU: {error:?}")))?;
        apply_boot_cpu_state(
            peer.context_mut(),
            &cpuid,
            &self.peer,
            self.hardware_interrupts,
            self.production,
        )?;
        let max_blocks = self.runner.max_blocks;
        let Self {
            runner, custody, ..
        } = self;
        let children = CarrierChildBindings::default();
        let first = CarrierCpu::new_with_maintenance(
            claim_carrier_cpu_io(SoftCpuBackend::new(runner, cpuid, first_run)),
            children.clone(),
            Some(maintenance_root),
        )?;
        let second = CarrierCpu::new_with_maintenance(
            claim_carrier_cpu_io(SoftCpuBackend::new(
                SoftRunner::new(peer, max_blocks),
                cpuid,
                second_run,
            )),
            children,
            Some(maintenance_root),
        )?;
        Ok(SoftWorkerParts::new([first, second], custody, root_state))
    }

    /// Run slot 0 to its next carrier exit (port I/O or `HLT`), or until it
    /// stops without one (recorded in [`SoftRunTrace::stop`]).
    pub fn run(&mut self) -> Option<SoftMachineExit> {
        if let Some(mm) = NonZeroU64::new(self.custody.initial_mm_key())
            && let Some(context) = self.custody.memory().root(mm)
            && let Err(error) = self
                .runner
                .machine_mut()
                .mem_mut()
                .admit_root(context.root.address().raw())
        {
            self.runner.trace.stop = Some(SoftStop::Emit {
                va: self.runner.machine().context().rip,
                detail: error.to_string(),
            });
            return None;
        }
        self.runner.run(None)
    }
}

impl Cpl0BootCarrier for SoftCarrier {
    type Memory = SoftVm;

    fn custody(&self) -> &BootstrapCustody<SoftVm> {
        &self.custody
    }

    fn custody_mut(&mut self) -> &mut BootstrapCustody<SoftVm> {
        &mut self.custody
    }

    fn cpu_count(&self) -> usize {
        1
    }

    fn cpu_gpr(&self, index: usize, reg: X86Reg) -> Result<u64, TrapError> {
        if index != 0 {
            return Err(fail("unknown soft CPU"));
        }
        let ctx = self.runner.machine().context();
        Ok(match reg {
            X86Reg::Cr3 => ctx.cr3,
            X86Reg::Rax => ctx.gpr[carrick_softcpu_x86::reg::RAX],
            X86Reg::Rip => ctx.rip,
            _ => return Err(fail("soft boot register")),
        })
    }

    fn enter_kernel(&mut self, index: usize, entry: KernelEntry) -> Result<(), TrapError> {
        if index != 0 {
            return Err(fail("unknown soft CPU"));
        }
        let ctx = self.runner.machine_mut().context_mut();
        // The shared X86Vcpu setters own the soft segment and MSR encodings.
        let cpuid = soft_cpuid();
        let mut vcpu = SoftBootVcpu::new(ctx, &cpuid);
        vcpu.set_segment(X86Seg::Cs, SegmentDescriptor::code64(SegmentDpl::Kernel))?;
        vcpu.set_segment(
            X86Seg::Ss,
            SegmentDescriptor::flat_data(SegmentDpl::Kernel, 0),
        )?;
        vcpu.set_gs_base(entry.gs_base)?;
        vcpu.set_gpr(X86Reg::Rip, entry.rip)?;
        vcpu.set_gpr(X86Reg::Rdi, entry.rdi)?;
        vcpu.set_gpr(X86Reg::Rsp, entry.rsp)?;
        vcpu.set_gpr(X86Reg::Rflags, 2)?;
        self.runner
            .machine_mut()
            .context_mut()
            .set_kernel_gs_base(0)
            .map_err(|_| fail("production user GS initialization"))
    }

    fn run_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError> {
        if index != 0 {
            return Err(fail("unknown soft CPU"));
        }
        match self.run() {
            Some(SoftMachineExit::IoOut {
                port, size, value, ..
            }) => Ok(VcpuExit::IoOut {
                port,
                data: value.to_le_bytes()[..usize::from(size)].to_vec(),
            }),
            Some(SoftMachineExit::Hlt { .. }) => Ok(VcpuExit::Halt),
            Some(exit) => Err(fail(format!("soft carrier exit {exit:?}"))),
            None => Err(fail(format!(
                "soft carrier stopped: {:?}",
                self.runner.trace().stop
            ))),
        }
    }

    fn append_debug_state(&self, index: usize, detail: &mut String) {
        if index == 0 {
            let ctx = self.runner.machine().context();
            detail.push_str(&format!(
                " (soft rip={:#x} cpl={} cr3={:#x} rax={:#x} blocks={})",
                ctx.rip,
                ctx.cpl,
                ctx.cr3,
                ctx.gpr[carrick_softcpu_x86::reg::RAX],
                self.runner.trace().blocks
            ));
        }
    }
}

const fn emit_va(error: &EmitError) -> u64 {
    match *error {
        EmitError::EncodeFailed { va, .. }
        | EmitError::HostJit { va, .. }
        | EmitError::ForeignInventory { va }
        | EmitError::InventoryTerminal { va } => va,
    }
}
