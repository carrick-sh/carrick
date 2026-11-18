//! The stopped soft CPL0 carrier: the shared neutral boot
//! ([`prepare_boot`], [`install_boot_memory`], [`BootCpuState`],
//! [`BootstrapCustody`]) over one [`SoftMachine`], and the soft
//! [`Cpl0BootCarrier`] the shared initial-MM admission
//! ([`carrick_x86_cpl0_host::cpl0_boot::load_guest_mm`]) drives.
//!
//! M1 is single-vCPU (#2397): only physical slot 0 exists.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_hal::{PhysicalFrameInventory, TrapError, VcpuExit};
use carrick_softcpu_x86::{EmitError, GuestCpuidView, SoftMachine, SoftMachineExit, X86Exception};
use carrick_x86::cpl0_entry::{CpuBinding, DIRECT_VA, PublishedApicId, PublishedApicIds};
use carrick_x86::{SegmentDescriptor, SegmentDpl, X86Reg, X86Seg, X86Vcpu};
use carrick_x86_cpl0_host::carrier_cpu::{
    CarrierChildBindings, CarrierCpu, OwnedCpuIo, claim_carrier_cpu_io,
};
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

/// How many recent block RIPs a [`SoftRunTrace`] keeps.
pub const RECENT_BLOCKS: usize = 512;

/// One soft CPU's block loop: runs its [`SoftMachine`] to the next carrier
/// exit under a block budget and an optional kick, and records the
/// [`SoftRunTrace`]. The stopped carrier and the worker backend share it.
pub struct SoftRunner {
    machine: SoftMachine<SoftCarrierMemory>,
    max_blocks: u64,
    trace: SoftRunTrace,
}

impl SoftRunner {
    pub fn new(machine: SoftMachine<SoftCarrierMemory>, max_blocks: u64) -> Self {
        Self {
            machine,
            max_blocks,
            trace: SoftRunTrace::default(),
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

    /// Run to the next carrier exit (port I/O or `HLT`). `None` is a stop
    /// without one, recorded in [`SoftRunTrace::stop`]; a `kicked` flag
    /// raised before a block stops the run as [`SoftStop::Kicked`].
    pub fn run(&mut self, kicked: Option<&AtomicBool>) -> Option<SoftMachineExit> {
        let stubs = DIRECT_VA + carrick_x86::fault_stub_base(LAYOUT)
            ..DIRECT_VA + carrick_x86::fault_tss_base(LAYOUT);
        self.trace.last_exit = None;
        self.trace.stop = None;
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
            if self.trace.recent.len() == RECENT_BLOCKS {
                self.trace.recent.pop_front();
            }
            self.trace.recent.push_back(before);
            let step = self.machine.step();
            self.trace.blocks += 1;
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
                    if stubs.contains(&rip) && !stubs.contains(&before) {
                        self.trace.deliveries.push((before, rip));
                    }
                    continue;
                }
                Ok(Some(exit)) => exit,
            };
            match exit {
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

/// A stopped soft CPL0 carrier. Field order is drop order: the machine
/// translates through registrations the custody's `CarrierMemory` owns.
pub struct SoftCarrier {
    runner: SoftRunner,
    custody: BootstrapCustody<SoftVm>,
    entry: u64,
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
        let PreparedBoot {
            ram,
            plan,
            boot,
            hardware_interrupts,
            kernel_pod_storage,
            ..
        } = prepared;
        let cpuid = soft_cpuid();
        let mut machine = SoftMachine::new(
            SoftCarrierMemory::new(&vm, LAYOUT.pml4_base)?,
            Box::new(cpuid),
        )
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

    pub fn machine_mut(&mut self) -> &mut SoftMachine<SoftCarrierMemory> {
        self.runner.machine_mut()
    }

    /// Hand both physical CPUs to production worker custody, as KVM's
    /// `Cpl0Carrier::into_worker_parts` does: slot 0 is the stopped root CPU
    /// whose image becomes the issued root's state; slot 1 is a second soft
    /// CPU in its stopped boot state. M1 is single-vCPU (#2397): the idle
    /// peer is not started, so the root runs with no peer in the zone.
    pub fn into_worker_parts(self) -> Result<SoftWorkerParts, TrapError> {
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
        let cpuid = soft_cpuid();
        let mut peer = SoftMachine::new(
            SoftCarrierMemory::new(self.custody.memory().vm(), LAYOUT.pml4_base)?,
            Box::new(cpuid),
        )
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
