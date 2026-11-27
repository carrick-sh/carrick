//! The soft carrier CPU behind the shared [`CarrierCpuBackend`] seam.
//!
//! [`SoftCpuBackend`] is one physical CPL0 CPU of a production carrier: the
//! shared [`carrick_x86_cpl0_host::carrier_cpu::CarrierCpu`] custody, the
//! [`carrick_x86_cpl0_host::cpl0_boot::ProductionCpuFactory`] leases and
//! their doorbell and forward services run over it exactly as they run over
//! a KVM vCPU. A run enters through the shared
//! [`run_production_member`] admission (file execution, shootdown table,
//! actual-run flag) and executes soft blocks until the next carrier exit or
//! an armed kick.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use carrick_guest_arch::{CpuId, RootGpa};
use carrick_hal::{TrapError, VcpuExit};
use carrick_softcpu_x86::{ApicNode, MsrIndex, SoftMachineExit};
use carrick_x86::cpl0_entry::ShootdownTable;
use carrick_x86::{GuestCpuidView, SegmentDescriptor, SegmentDpl, X86Reg, X86Seg, X86Vcpu};
use carrick_x86_cpl0_host::carrier_cpu::{CarrierCpuBackend, FixtureWatchdog};
use carrick_x86_cpl0_host::cpl0_boot::{
    META_GPA, ProductionMemberCpu, SHOOTDOWN_OFFSET, StoppedCpu, fail, run_production_member,
};
use carrick_x86_cpl0_host::guest_ram::GuestRam;

use crate::carrier::{SoftRunner, SoftStop};
use crate::cpu::{SoftBootVcpu, SoftCpuView};

/// A host kick for one soft CPU: raised from any thread, observed by the
/// CPU between blocks and while it is enrolled in an HLT wait.
#[derive(Clone, Default)]
pub struct SoftKick(Arc<SoftKickState>);

#[derive(Default)]
struct SoftKickState {
    pending: AtomicBool,
    node: Mutex<Weak<ApicNode>>,
}

impl carrick_hal::VcpuKick for SoftKick {
    fn kick(&self) {
        self.0.pending.store(true, Ordering::Release);
        if let Ok(node) = self.0.node.lock()
            && let Some(node) = node.upgrade()
        {
            node.kick();
        }
    }
}

/// Bounds a fixture's guest interval in wall-clock time. The soft CPU is
/// stopped between blocks by its block budget, so the watchdog only reports.
pub struct SoftWatchdog {
    started: Instant,
}

/// The guest interval a fixture run may take before it is a deadline.
const SOFT_FIXTURE_DEADLINE: Duration = Duration::from_secs(30);

impl FixtureWatchdog for SoftWatchdog {
    fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }
    fn during_guest<T>(&self, run: impl FnOnce() -> T) -> T {
        run()
    }
    fn expired(&self) -> bool {
        self.started.elapsed() > SOFT_FIXTURE_DEADLINE
    }
}

/// The physical run authority a worker CPU retains from the carrier's
/// custody: the shootdown table's RAM, the shared actual-run flags, the
/// file-execution admission, its slot and the boot maintenance root.
#[derive(Clone)]
pub struct SoftRunContext {
    pub ram: Arc<GuestRam>,
    pub actual_run: Arc<[AtomicU32; 2]>,
    pub file_execution: Arc<RwLock<()>>,
    pub slot: CpuId,
    pub maintenance_root: Option<RootGpa>,
}

/// One soft CPL0 CPU and its production run context.
pub struct SoftCpuBackend {
    runner: SoftRunner,
    cpuid: GuestCpuidView,
    run: SoftRunContext,
    kick: Option<SoftKick>,
}

impl SoftCpuBackend {
    pub fn new(runner: SoftRunner, cpuid: GuestCpuidView, run: SoftRunContext) -> Self {
        Self {
            runner,
            cpuid,
            run,
            kick: None,
        }
    }

    fn vcpu(&mut self) -> SoftBootVcpu<'_> {
        SoftBootVcpu::new(self.runner.machine_mut().context_mut(), &self.cpuid)
    }

    fn require_primary(&self) -> Result<(), TrapError> {
        if self.run.slot != CpuId::new(0) {
            return Err(TrapError::UnsupportedPlatform);
        }
        Ok(())
    }
}

impl ProductionMemberCpu for SoftCpuBackend {
    fn stopped(&self) -> Result<StoppedCpu, TrapError> {
        // The soft CPU delivers an event in one step between blocks, so a
        // stopped soft CPU never has one in flight.
        let ctx = self.runner.machine().context();
        Ok(StoppedCpu::classify(
            ctx.cpl,
            ctx.cs.selector,
            ctx.rip,
            ctx.rflags,
            ctx.interrupt_shadow,
            None,
        ))
    }

    fn end_user_interrupt_shadow(&mut self) -> Result<(), TrapError> {
        self.runner.machine_mut().context_mut().interrupt_shadow = false;
        Ok(())
    }

    fn queue_reentry_kick(&mut self) -> Result<(), TrapError> {
        self.runner
            .machine_mut()
            .inject_interrupt(carrick_x86::interrupts::KICK_VECTOR);
        Ok(())
    }

    fn run_guest(&mut self) -> Result<VcpuExit, TrapError> {
        self.require_primary()?;
        self.runner.refresh_memory()?;
        self.runner.admit_current_root()?;
        let kick = self.kick.clone();
        let exit = self.runner.run(kick.as_ref().map(|kick| &kick.0.pending));
        match exit {
            Some(SoftMachineExit::IoOut {
                port, size, value, ..
            }) => Ok(VcpuExit::IoOut {
                port,
                data: value.to_le_bytes()[..usize::from(size)].to_vec(),
            }),
            Some(SoftMachineExit::Hlt { .. }) => Ok(VcpuExit::Halt),
            Some(exit) => Err(fail(format!("soft carrier exit {exit:?}"))),
            None => match &self.runner.trace().stop {
                Some(SoftStop::Kicked) => Ok(VcpuExit::Kicked),
                stop => {
                    let ctx = self.runner.machine().context();
                    let trace = self.runner.trace();
                    let hot: Vec<_> = trace
                        .hot_blocks(8)
                        .into_iter()
                        .map(|(rip, count)| format!("{rip:#x} x {count}"))
                        .collect();
                    Err(fail(format!(
                        "soft carrier stopped: {stop:?} (rip={:#x} cpl={} cr3={:#x} blocks={} \
                         hot of last {}: [{}])",
                        ctx.rip,
                        ctx.cpl,
                        ctx.cr3,
                        trace.blocks,
                        trace.recent.len(),
                        hot.join(", ")
                    )))
                }
            },
        }
    }
}

impl CarrierCpuBackend for SoftCpuBackend {
    type KickHandle = SoftKick;
    type Watchdog = SoftWatchdog;

    fn for_current_thread_kick() -> Self::KickHandle {
        SoftKick::default()
    }

    fn read_image(&self) -> Result<carrick_x86::X86VcpuSnapshot, TrapError> {
        carrick_x86::snapshot(&SoftCpuView(self.runner.machine().context()))
    }

    /// Install a task image's dynamic state. The boot-programmed GDT, IDT,
    /// TR, xAPIC base and syscall MSRs persist in the soft context; CS and
    /// SS follow the image's privilege as the STAR selectors name them.
    fn write_image(&mut self, image: &carrick_x86::X86VcpuSnapshot) -> Result<(), TrapError> {
        let supervisor = image.rip
            >= carrick_hal::guest_arch::UserVaCeiling::for_abi(carrick_abi::LinuxGuestAbi::X86_64)
                .exclusive_end();
        let star = self.runner.machine().context().msrs().star();
        let mut vcpu = self.vcpu();
        vcpu.set_gpr(X86Reg::Cr0, image.cr0)?;
        vcpu.set_gpr(X86Reg::Cr4, image.cr4)?;
        vcpu.set_gpr(X86Reg::Efer, image.efer)?;
        vcpu.set_gpr(X86Reg::Cr3, image.cr3)?;
        let (privilege, cs, ss) = if supervisor {
            let cs = ((star >> 32) & 0xffff) as u16;
            (SegmentDpl::Kernel, cs, cs.wrapping_add(8))
        } else {
            let base = ((star >> 48) & 0xffff) as u16 | 3;
            (
                SegmentDpl::User,
                base.wrapping_add(16),
                base.wrapping_add(8),
            )
        };
        vcpu.set_segment(
            X86Seg::Cs,
            SegmentDescriptor::code64(privilege).with_selector(cs),
        )?;
        vcpu.set_segment(
            X86Seg::Ss,
            SegmentDescriptor::flat_data(privilege, 0).with_selector(ss),
        )?;
        const GPRS: [X86Reg; 16] = [
            X86Reg::Rax,
            X86Reg::Rbx,
            X86Reg::Rcx,
            X86Reg::Rdx,
            X86Reg::Rsi,
            X86Reg::Rdi,
            X86Reg::Rbp,
            X86Reg::Rsp,
            X86Reg::R8,
            X86Reg::R9,
            X86Reg::R10,
            X86Reg::R11,
            X86Reg::R12,
            X86Reg::R13,
            X86Reg::R14,
            X86Reg::R15,
        ];
        for (value, reg) in image.gprs.iter().zip(GPRS) {
            vcpu.set_gpr(reg, *value)?;
        }
        vcpu.set_gpr(X86Reg::Rip, image.rip)?;
        vcpu.set_gpr(X86Reg::Rsp, image.rsp)?;
        vcpu.set_gpr(X86Reg::Rflags, image.rflags)?;
        vcpu.set_fs_base(image.fs_base)?;
        vcpu.set_gs_base(image.gs_base)?;
        let xsave = image
            .xsave
            .ok_or_else(|| fail("soft carrier image lacks its XSAVE area"))?;
        vcpu.set_xsave(&xsave)?;
        self.runner.machine_mut().context_mut().halted = false;
        Ok(())
    }

    fn run(&mut self) -> Result<VcpuExit, TrapError> {
        // A parked M1 peer has a custody record for the shared two-slot
        // factory, but its extent table cannot participate in execution.
        self.require_primary()?;
        let ram = Arc::clone(&self.run.ram);
        let table = ram
            .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
            .ok_or_else(|| fail("retained shootdown table backing"))?
            .cast::<ShootdownTable>();
        // SAFETY: the retained RAM owns this aligned table for the worker's
        // lifetime; the guest and the host access only its atomics.
        let table = unsafe { &*table };
        let slot = self.run.slot.raw() as usize;
        let actual_run = Arc::clone(&self.run.actual_run);
        let execution = Arc::clone(&self.run.file_execution);
        run_production_member(self, table, slot, Some(&actual_run[slot]), &execution)
    }

    /// A soft `OUT` exit already advanced RIP past the instruction.
    fn complete_pending_io(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    fn arm_run_kick(&mut self, kick: &Self::KickHandle) -> Result<(), TrapError> {
        *kick
            .0
            .node
            .lock()
            .map_err(|_| fail("soft kick node lock"))? =
            Arc::downgrade(&self.runner.machine().apic_node());
        self.kick = Some(kick.clone());
        Ok(())
    }

    fn disarm_run_kick(kick: &Self::KickHandle) {
        if let Ok(mut node) = kick.0.node.lock() {
            *node = Weak::new();
        }
    }

    fn physical_slot(&self) -> Option<CpuId> {
        Some(self.run.slot)
    }

    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        SoftCpuView(self.runner.machine().context()).get_gpr(reg)
    }

    fn read_msr(&self, msr: u32) -> Result<u64, TrapError> {
        let ctx = self.runner.machine().context();
        ctx.msrs()
            .read(
                MsrIndex::new(msr),
                carrick_softcpu_x86::MsrCapabilities::from_cpuid(&self.cpuid),
            )
            .map_err(|_| fail(format!("soft MSR {msr:#x} unreadable")))
    }

    fn write_msr(&mut self, msr: u32, value: u64) -> Result<(), TrapError> {
        self.vcpu().write_msr(MsrIndex::new(msr), value)
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        Ok(self.runner.machine().context().fs_base())
    }

    fn set_fs_base(&mut self, address: u64) -> Result<(), TrapError> {
        self.vcpu().set_fs_base(address)
    }
}
