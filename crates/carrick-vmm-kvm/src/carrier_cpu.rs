use carrick_hal::guest_arch_binding::{
    GuestArchBinding,
    core_arch::{FrameGpa, RootGpa, TaskIdentity},
};
use carrick_hal::threaded::X86_TASK_RESUME_PAYLOAD_LEN;
use carrick_hal::{HvVcpu, HvVm, TrapError, VcpuExit};
use carrick_x86::{BringupLayout, X86Vcpu, X86VcpuSnapshot, arch_context::X86ArchContext};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Scalar last-stopped image and live phase. Readers never alias a `VcpuFd`.
#[derive(Default)]
pub(crate) struct CarrierCpuDebug {
    phase: AtomicU8,
    task_serial: AtomicU64,
    task_execution: AtomicU64,
    gprs: [AtomicU64; 16],
    rip: AtomicU64,
    rsp: AtomicU64,
    rflags: AtomicU64,
    rax: AtomicU64,
    cr3: AtomicU64,
    cr0: AtomicU64,
    cr4: AtomicU64,
    efer: AtomicU64,
    fs_base: AtomicU64,
    gs_base: AtomicU64,
}

impl CarrierCpuDebug {
    fn image(&self, image: &X86VcpuSnapshot) {
        for (slot, value) in self.gprs.iter().zip(image.gprs.iter()) {
            slot.store(*value, Ordering::Relaxed);
        }
        self.rip.store(image.rip, Ordering::Relaxed);
        self.rsp.store(image.rsp, Ordering::Relaxed);
        self.rflags.store(image.rflags, Ordering::Relaxed);
        self.rax.store(image.gprs[0], Ordering::Relaxed);
        self.cr3.store(image.cr3, Ordering::Release);
        self.cr0.store(image.cr0, Ordering::Relaxed);
        self.cr4.store(image.cr4, Ordering::Relaxed);
        self.efer.store(image.efer, Ordering::Relaxed);
        self.fs_base.store(image.fs_base, Ordering::Relaxed);
        self.gs_base.store(image.gs_base, Ordering::Relaxed);
    }

    fn bound(&self, task: TaskIdentity) {
        self.task_serial
            .store(task.task.raw().get(), Ordering::Relaxed);
        self.task_execution
            .store(task.execution.raw().get(), Ordering::Release);
    }

    pub(crate) fn render(&self, slot: usize) -> String {
        let phase = match self.phase.load(Ordering::Acquire) {
            1 => "running",
            2 => "stopped",
            3 => "halted",
            4 => "poisoned",
            _ => "idle",
        };
        format!(
            "cpu={slot} phase={phase} bound_task_serial={} bound_execution={} last_stopped_rip={:#x} last_stopped_rsp={:#x} last_stopped_rflags={:#x} last_stopped_rax={:#x} last_stopped_cr0={:#x} last_stopped_cr3={:#x} last_stopped_cr4={:#x} last_stopped_efer={:#x} last_stopped_fs={:#x} last_stopped_gs={:#x} last_stopped_gprs={:?}",
            self.task_serial.load(Ordering::Relaxed),
            self.task_execution.load(Ordering::Relaxed),
            self.rip.load(Ordering::Relaxed),
            self.rsp.load(Ordering::Relaxed),
            self.rflags.load(Ordering::Relaxed),
            self.rax.load(Ordering::Relaxed),
            self.cr0.load(Ordering::Relaxed),
            self.cr3.load(Ordering::Acquire),
            self.cr4.load(Ordering::Relaxed),
            self.efer.load(Ordering::Relaxed),
            self.fs_base.load(Ordering::Relaxed),
            self.gs_base.load(Ordering::Relaxed),
            std::array::from_fn::<_, 16, _>(|index| self.gprs[index].load(Ordering::Relaxed)),
        )
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Physical I/O for an exclusively owned stopped CPU. Only the in-crate driver
/// and deterministic unit-test driver implement this sealed surface.
pub trait CarrierCpuIo: sealed::Sealed {
    fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError>;
    fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError>;
    fn run(&mut self) -> Result<VcpuExit, TrapError>;
    fn complete_pending_io(&mut self) -> Result<(), TrapError>;
}

/// Owns a fresh VM and vCPU. The vCPU handle never escapes this boundary.
pub struct KvmCpuIo {
    vcpu: crate::KvmVcpu,
    _vm: crate::KvmVm,
    layout: BringupLayout,
    production_run: Option<crate::cpl0_boot::ProductionRunContext>,
    production_static: Option<ProductionCpuStatic>,
}

struct ProductionCpuStatic {
    sregs: kvm_bindings::kvm_sregs,
    lstar: u64,
    star: u64,
    sfmask: u64,
}
impl sealed::Sealed for KvmCpuIo {}
impl CarrierCpuIo for KvmCpuIo {
    fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
        carrick_x86::snapshot(&self.vcpu)
    }
    fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
        // Share the existing grouped KVM restore, including its pending-SYSRET
        // segment choice. No page-table owner exists here; diagnostic walks are
        // unknown, not evidence of live translation or authenticated ownership.
        crate::kvm_x86_engine::restore_kvm_vcpu(
            &mut self.vcpu,
            self.layout,
            image,
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
        )?;
        if let Some(static_state) = &self.production_static {
            let mut sregs = self
                .vcpu
                .fd()
                .get_sregs()
                .map_err(|error| boundary_error(&error.to_string()))?;
            sregs.gdt = static_state.sregs.gdt;
            sregs.idt = static_state.sregs.idt;
            sregs.tr = crate::kvm_x86_engine::KvmSegment::from(
                carrick_x86::SegmentDescriptor::tss64_busy(static_state.sregs.tr.base)
                    .with_selector(static_state.sregs.tr.selector),
            )
            .0;
            sregs.ldt = static_state.sregs.ldt;
            sregs.apic_base = static_state.sregs.apic_base;
            self.vcpu
                .fd()
                .set_sregs(&sregs)
                .map_err(|error| boundary_error(&error.to_string()))?;
            self.vcpu
                .set_syscall_msrs(static_state.lstar, static_state.star, static_state.sfmask)
                .map_err(|error| boundary_error(&error.to_string()))?;
        }
        Ok(())
    }
    fn run(&mut self) -> Result<VcpuExit, TrapError> {
        if let Some(context) = &self.production_run {
            context.run(&mut self.vcpu)
        } else {
            Ok(HvVcpu::run(&mut self.vcpu)?)
        }
    }
    fn complete_pending_io(&mut self) -> Result<(), TrapError> {
        self.vcpu
            .complete_pending_io_exit()
            .map_err(|error| boundary_error(&error.to_string()))
    }
}

/// A stopped guest task and the reason its vCPU exited. The vCPU remains
/// loaded: KVM may still owe completion of an I/O exit on its next entry.
/// Physical doorbells remain distinct from the authenticated syscall trap.
#[derive(Debug)]
pub struct StoppedTaskExit {
    /// A maintenance-root work crossing has no task address context to save.
    pub state: Option<X86ArchContext>,
    pub exit: CarrierRunExit,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CarrierRunExit {
    SyscallTrap,
    Halt,
    Kick,
    FaultDoorbellWord(u32),
    FaultException { syndrome: u64, far: u64 },
    PhysicalDoorbell { port: u16, data: Vec<u8> },
}

impl CarrierRunExit {
    fn from_raw(raw: VcpuExit) -> Result<Self, TrapError> {
        match raw {
            VcpuExit::IoOut {
                port: carrick_x86::cpl0_entry::FORWARD_PORT,
                data,
            } => {
                if data.len() != 1 {
                    return Err(boundary_error("syscall doorbell width"));
                }
                Ok(Self::SyscallTrap)
            }
            VcpuExit::IoOut {
                port: carrick_x86::FAULT_DOORBELL_PORT,
                data,
            } => {
                let word: [u8; 4] = data
                    .try_into()
                    .map_err(|_| boundary_error("fault doorbell word width"))?;
                Ok(Self::FaultDoorbellWord(u32::from_le_bytes(word)))
            }
            VcpuExit::IoOut { port, data } => Ok(Self::PhysicalDoorbell { port, data }),
            VcpuExit::Exception { syndrome, far } => Ok(Self::FaultException { syndrome, far }),
            VcpuExit::Halt => Ok(Self::Halt),
            VcpuExit::Kicked => Ok(Self::Kick),
            VcpuExit::MmioWrite { .. } => Err(boundary_error("unexpected CPL0 MMIO exit")),
        }
    }
}

enum Custody {
    Idle,
    Loaded {
        binding: GuestArchBinding,
        resume: [u8; X86_TASK_RESUME_PAYLOAD_LEN],
        pending_io: bool,
    },
    // A partial ioctl or failed readback cannot advertise detach or allow reuse.
    Poisoned,
}

/// Live descendants belong to the carrier, independently of which CPU served
/// their birth or currently holds the root task's executor lease.
#[derive(Clone, Default)]
pub(crate) struct CarrierChildBindings(
    std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<RootGpa, GuestArchBinding>>>,
);

impl CarrierChildBindings {
    fn get(&self, root: RootGpa) -> Result<Option<GuestArchBinding>, TrapError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| boundary_error("child binding authority poisoned"))?
            .get(&root)
            .copied())
    }
}

pub struct KvmCarrierCpu<I: CarrierCpuIo = KvmCpuIo> {
    io: I,
    neutral: X86VcpuSnapshot,
    custody: Custody,
    root_binding: Option<GuestArchBinding>,
    child_bindings: CarrierChildBindings,
    maintenance_root: Option<RootGpa>,
    debug: Option<Arc<CarrierCpuDebug>>,
}
impl KvmCarrierCpu<KvmCpuIo> {
    /// A scheduler fixture stops inside the native kernel, potentially after
    /// it left every user MM. That boundary has no task CPU image to capture.
    pub(crate) fn fixture_run_until_kick(
        &mut self,
        task: TaskIdentity,
    ) -> Result<CarrierRunExit, TrapError> {
        if !matches!(self.custody, Custody::Loaded { binding, .. } if binding.task() == task) {
            return Err(boundary_error(
                "native fixture requires its loaded executor",
            ));
        }
        let result = self.io.run().and_then(CarrierRunExit::from_raw);
        match result {
            Ok(CarrierRunExit::Kick) => {
                if let Custody::Loaded { pending_io, .. } = &mut self.custody {
                    *pending_io = false;
                }
                Ok(CarrierRunExit::Kick)
            }
            other => {
                self.custody = Custody::Poisoned;
                Err(boundary_error(&format!(
                    "native scheduler fixture expected a kick: {other:?}"
                )))
            }
        }
    }

    pub(crate) fn arm_idle_kick(&mut self, kick: &crate::KvmKickHandle) -> Result<(), TrapError> {
        self.audit_unloaded_peer()?;
        self.io.vcpu.arm_run_kick(kick);
        Ok(())
    }

    pub(crate) fn arm_loaded_kick(
        &mut self,
        task: TaskIdentity,
        kick: &crate::KvmKickHandle,
    ) -> Result<(), TrapError> {
        if !matches!(self.custody, Custody::Loaded { binding, .. } if binding.task() == task) {
            return Err(boundary_error(
                "loaded kick requires its exact task generation",
            ));
        }
        self.io.vcpu.arm_run_kick(kick);
        Ok(())
    }
    /// Run the carrier's physical peer while no host task lease is claimed.
    /// This lane has no Linux task identity; only physical doorbells may be
    /// served until the in-guest scheduler hands a task back to the host.
    pub(crate) fn run_idle_peer(&mut self) -> Result<CarrierRunExit, TrapError> {
        self.audit_unloaded_peer()?;
        if self.physical_slot() != Some(carrick_guest_arch::CpuId::new(1)) {
            return Err(boundary_error(
                "only the physical peer has idle guest entry",
            ));
        }
        if let Some(debug) = &self.debug {
            debug.phase.store(1, Ordering::Release);
        }
        let result = self.io.run().and_then(CarrierRunExit::from_raw);
        if let Some(debug) = &self.debug {
            debug.phase.store(
                if matches!(&result, Ok(CarrierRunExit::Halt)) {
                    3
                } else {
                    2
                },
                Ordering::Release,
            );
        }
        result
    }

    pub(crate) fn with_idle_peer_vcpu<R>(
        &mut self,
        service: impl FnOnce(&mut crate::KvmVcpu) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        self.audit_unloaded_peer()?;
        if self.physical_slot() != Some(carrick_guest_arch::CpuId::new(1)) {
            return Err(boundary_error("physical idle service requires peer slot"));
        }
        service(&mut self.io.vcpu)
    }

    pub(crate) fn audit_unloaded_peer(&self) -> Result<(), TrapError> {
        if self.physical_slot() != Some(carrick_guest_arch::CpuId::new(1))
            || !matches!(self.custody, Custody::Idle)
        {
            return Err(boundary_error("physical peer owns a host task"));
        }
        Ok(())
    }
    /// Lend the stopped production vCPU to its physical crossing service.
    /// The caller supplies the exact task generation that was loaded before
    /// KVM_RUN; a physical slot cannot manufacture a Linux task identity.
    pub(crate) fn with_stopped_vcpu<R>(
        &mut self,
        task: TaskIdentity,
        service: impl FnOnce(&mut crate::KvmVcpu) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        if !matches!(self.custody, Custody::Loaded { binding, .. } if binding.task() == task) {
            return Err(boundary_error(
                "physical service requires its loaded task generation",
            ));
        }
        service(&mut self.io.vcpu)
    }
    pub(crate) fn registered_task_binding(
        &self,
        root_gpa: RootGpa,
    ) -> Result<GuestArchBinding, TrapError> {
        if let Custody::Loaded { binding, .. } = self.custody
            && binding.context().root == root_gpa
        {
            return Ok(binding);
        }
        if let Some(binding) = self.root_binding
            && binding.context().root == root_gpa
        {
            return Ok(binding);
        }
        self.child_bindings
            .get(root_gpa)?
            .ok_or_else(|| boundary_error("unregistered forward CR3"))
    }
    pub(crate) fn with_forward_vcpu<R>(
        &mut self,
        task: TaskIdentity,
        service: impl FnOnce(&mut crate::KvmVcpu, GuestArchBinding) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        if self.physical_slot() == Some(carrick_guest_arch::CpuId::new(1))
            && matches!(self.custody, Custody::Idle)
        {
            self.audit_unloaded_peer()?;
        } else if !matches!(self.custody, Custody::Loaded { .. }) {
            return Err(boundary_error(
                "physical service requires its loaded task generation",
            ));
        }
        let active = if self.io.production_run.is_some() {
            let live_root = self.io.vcpu.get_gpr(carrick_x86::X86Reg::Cr3)? & !0xfff;
            let root_gpa = RootGpa::page_aligned(FrameGpa::new(live_root))
                .ok_or_else(|| boundary_error("unaligned forward CR3"))?;
            let active = self.registered_task_binding(root_gpa)?;
            if active.task() != task {
                return Err(boundary_error(
                    "physical service requires its loaded task generation",
                ));
            }
            active
        } else {
            let Custody::Loaded { binding, .. } = self.custody else {
                return Err(boundary_error(
                    "physical service requires its loaded task generation",
                ));
            };
            if binding.task() != task {
                return Err(boundary_error(
                    "physical service requires its loaded task generation",
                ));
            }
            binding
        };
        service(&mut self.io.vcpu, active)
    }
    pub fn physical_slot(&self) -> Option<carrick_guest_arch::CpuId> {
        self.io
            .production_run
            .as_ref()
            .map(crate::cpl0_boot::ProductionRunContext::physical_slot)
    }
    /// M1 hardware witness only: no backing registration or guest execution.
    /// Carrier VM/backing admission and a running boundary belong to M2/M3/M5.
    pub fn create_stopped(layout: BringupLayout) -> Result<Self, TrapError> {
        let mut vm =
            crate::KvmVm::create_empty().map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let mut vcpu = vm
            .add_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        carrick_x86::program_longmode_entry(&mut vcpu, layout, 0x1000, 0x2000)?;
        Self::new(KvmCpuIo {
            vcpu,
            _vm: vm,
            layout,
            production_run: None,
            production_static: None,
        })
    }

    pub(crate) fn from_production(
        vcpu: crate::KvmVcpu,
        vm: crate::KvmVm,
        layout: BringupLayout,
        production_run: crate::cpl0_boot::ProductionRunContext,
        root_binding: GuestArchBinding,
        child_bindings: CarrierChildBindings,
    ) -> Result<Self, TrapError> {
        let static_state = ProductionCpuStatic {
            sregs: vcpu
                .fd()
                .get_sregs()
                .map_err(|error| boundary_error(&error.to_string()))?,
            lstar: vcpu
                .read_msr(0xc000_0082)
                .map_err(|error| boundary_error(&error.to_string()))?,
            star: vcpu
                .read_msr(0xc000_0081)
                .map_err(|error| boundary_error(&error.to_string()))?,
            sfmask: vcpu
                .read_msr(0xc000_0084)
                .map_err(|error| boundary_error(&error.to_string()))?,
        };
        let maintenance_root = production_run
            .maintenance_root
            .ok_or_else(|| boundary_error("worker production run has no maintenance root"))?;
        let mut cpu = Self::new_with_children(
            KvmCpuIo {
                vcpu,
                _vm: vm,
                layout,
                production_run: Some(production_run),
                production_static: Some(static_state),
            },
            child_bindings,
        )?;
        cpu.root_binding = Some(root_binding);
        cpu.maintenance_root = Some(maintenance_root);
        Ok(cpu)
    }
}
impl<I: CarrierCpuIo> KvmCarrierCpu<I> {
    fn new(io: I) -> Result<Self, TrapError> {
        Self::new_with_children(io, CarrierChildBindings::default())
    }
    fn new_with_children(io: I, child_bindings: CarrierChildBindings) -> Result<Self, TrapError> {
        let neutral = io.read_image()?;
        if neutral.xsave.is_none() {
            return Err(boundary_error("carrier CPU requires complete V1 XSAVE"));
        }
        Ok(Self {
            io,
            neutral,
            custody: Custody::Idle,
            root_binding: None,
            child_bindings,
            maintenance_root: None,
            debug: None,
        })
    }
    pub(crate) fn attach_debug(&mut self, debug: Arc<CarrierCpuDebug>) {
        debug.image(&self.neutral);
        self.debug = Some(debug);
    }
    pub fn register_child_binding(&mut self, binding: GuestArchBinding) -> Result<(), TrapError> {
        let mut children = self
            .child_bindings
            .0
            .lock()
            .map_err(|_| boundary_error("child binding authority poisoned"))?;
        let root = binding.context().root;
        if children.get(&root).is_some_and(|old| *old != binding) {
            return Err(boundary_error(
                "live child root already has another binding",
            ));
        }
        children.insert(root, binding);
        Ok(())
    }
    pub fn unregister_child_binding(
        &mut self,
        root: RootGpa,
    ) -> Result<Option<GuestArchBinding>, TrapError> {
        Ok(self
            .child_bindings
            .0
            .lock()
            .map_err(|_| boundary_error("child binding authority poisoned"))?
            .remove(&root))
    }
    pub fn clear_child_bindings(&mut self) -> Result<(), TrapError> {
        self.child_bindings
            .0
            .lock()
            .map_err(|_| boundary_error("child binding authority poisoned"))?
            .clear();
        Ok(())
    }
    /// Read-only template, never a task or MM owner capability.
    pub fn neutral_image(&self) -> &X86VcpuSnapshot {
        &self.neutral
    }
    pub fn load(&mut self, context: X86ArchContext) -> Result<(), TrapError> {
        self.audit_idle()?;
        let binding = context.binding();
        binding.validate_x86(context.state())?;
        let mut resume = [0; X86_TASK_RESUME_PAYLOAD_LEN];
        resume.copy_from_slice(context.state().resume_payload());
        let expected = context.hardware_image();
        self.custody = Custody::Poisoned;
        self.io.write_image(&expected)?;
        audit_image(&self.io.read_image()?, &expected)?;
        if let Some(debug) = &self.debug {
            debug.image(&expected);
            debug.bound(binding.task());
            debug.phase.store(2, Ordering::Release);
        }
        self.custody = Custody::Loaded {
            binding,
            resume,
            pending_io: false,
        };
        Ok(())
    }
    /// Run one exclusively loaded task until the next physical exit. A failed
    /// KVM run or malformed exit poisons custody; a successful boundary copies
    /// the complete architectural image before handing it to task policy.
    /// The vCPU remains loaded until the caller settles any pending KVM I/O.
    pub fn run_loaded(&mut self, task: TaskIdentity) -> Result<StoppedTaskExit, TrapError> {
        if !matches!(self.custody, Custody::Loaded { binding, .. } if binding.task() == task) {
            return Err(boundary_error(
                "carrier run requires its exact loaded task generation",
            ));
        }
        if let Some(debug) = &self.debug {
            debug.phase.store(1, Ordering::Release);
        }
        let raw = match self.io.run() {
            Ok(exit) => exit,
            Err(error) => {
                if let Some(debug) = &self.debug {
                    debug.phase.store(4, Ordering::Release);
                }
                self.custody = Custody::Poisoned;
                return Err(error);
            }
        };
        let pending_io = matches!(raw, VcpuExit::IoOut { .. });
        let exit = match CarrierRunExit::from_raw(raw) {
            Ok(exit) => exit,
            Err(error) => {
                self.custody = Custody::Poisoned;
                return Err(error);
            }
        };
        let (binding, resume) = match self.custody {
            Custody::Loaded {
                binding, resume, ..
            } => (binding, resume),
            _ => return Err(boundary_error("carrier run lost loaded task custody")),
        };
        let image = match self.io.read_image() {
            Ok(image) => image,
            Err(error) => {
                self.custody = Custody::Poisoned;
                return Err(error);
            }
        };
        if let Some(debug) = &self.debug {
            debug.image(&image);
            debug.phase.store(
                if matches!(&exit, CarrierRunExit::Halt) {
                    3
                } else {
                    2
                },
                Ordering::Release,
            );
        }
        if let CarrierRunExit::PhysicalDoorbell { port, .. } = &exit {
            // Exit work can be published after the last child has left its
            // process root. Only the boot-published maintenance root may
            // serve that work; it is never a task snapshot or a child MM.
            if *port == carrick_x86::cpl0_entry::WORK_PORT
                && self
                    .maintenance_root
                    .is_some_and(|root| root.address().raw() == image.cr3)
            {
                self.custody = Custody::Loaded {
                    binding,
                    resume,
                    pending_io,
                };
                return Ok(StoppedTaskExit { state: None, exit });
            }
        }
        let target_binding = match &exit {
            // CPL0 schedules descendants in-zone without changing the
            // executor's loaded task. Every physical crossing uses the
            // registered live root, not just child retirement. The service
            // independently authenticates its CPL0 binding and generation.
            CarrierRunExit::PhysicalDoorbell { port, .. } => {
                let root_gpa = RootGpa::page_aligned(FrameGpa::new(image.cr3 & !0xfff))
                    .ok_or_else(|| {
                        self.custody = Custody::Poisoned;
                        boundary_error("unaligned physical crossing CR3")
                    })?;
                if root_gpa == binding.context().root
                    && *port != carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT
                {
                    binding
                } else {
                    let child = self.child_bindings.get(root_gpa).inspect_err(|_| {
                        self.custody = Custody::Poisoned;
                    })?;
                    match child {
                        Some(child) => child,
                        None => {
                            self.custody = Custody::Poisoned;
                            return Err(boundary_error(&format!(
                                "unregistered {} CR3: root {:#x}, port {port:#x}, rip {:#x}",
                                if *port == carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT {
                                    "child retire"
                                } else {
                                    "physical crossing"
                                },
                                root_gpa.address().raw(),
                                image.rip,
                            )));
                        }
                    }
                }
            }
            CarrierRunExit::SyscallTrap => {
                let root_gpa = RootGpa::page_aligned(FrameGpa::new(image.cr3 & !0xfff))
                    .ok_or_else(|| {
                        self.custody = Custody::Poisoned;
                        boundary_error("unaligned forward CR3")
                    })?;
                if root_gpa == binding.context().root {
                    binding
                } else {
                    let child = self.child_bindings.get(root_gpa).inspect_err(|_| {
                        self.custody = Custody::Poisoned;
                    })?;
                    match child {
                        Some(child) => child,
                        None => {
                            self.custody = Custody::Poisoned;
                            return Err(boundary_error(&format!(
                                "unregistered forward CR3: root {:#x}, rip {:#x}",
                                root_gpa.address().raw(),
                                image.rip,
                            )));
                        }
                    }
                }
            }
            _ => binding,
        };
        let state = match X86ArchContext::capture(target_binding, &image, resume).map_err(|error| {
                let context = target_binding.context();
                boundary_error(&format!(
                    "stopped CPU image after {exit:?}: {error}; expected root {:#x}, actual CR3 {:#x}, RSP {:#x}, saved GPR7 {:#x}, expected MM {}, context {}",
                    context.root.address().raw(), image.cr3, image.rsp, image.gprs[7],
                    context.mm.raw(), context.generation.raw()
                ))
            }) {
            Ok(state) => state,
            Err(error) => {
                self.custody = Custody::Poisoned;
                return Err(error);
            }
        };
        self.custody = Custody::Loaded {
            binding,
            resume,
            pending_io,
        };
        Ok(StoppedTaskExit {
            state: Some(state),
            exit,
        })
    }
    pub fn save_and_detach(&mut self, task: TaskIdentity) -> Result<X86ArchContext, TrapError> {
        let (binding, resume, pending_io) = match self.custody {
            Custody::Loaded {
                binding,
                resume,
                pending_io,
            } if binding.task() == task => (binding, resume, pending_io),
            _ => {
                return Err(boundary_error(
                    "carrier detach requires its exact loaded task generation",
                ));
            }
        };
        // Until the read/save/reset/audit transaction completes the CPU is
        // poisoned, even if a read or a checked snapshot fails before a write.
        self.custody = Custody::Poisoned;
        if pending_io {
            self.io.complete_pending_io()?;
        }
        let saved = X86ArchContext::capture(binding, &self.io.read_image()?, resume)?;
        self.io.write_image(&self.neutral)?;
        audit_image(&self.io.read_image()?, &self.neutral)?;
        self.custody = Custody::Idle;
        if let Some(debug) = &self.debug {
            debug.image(&self.neutral);
            debug.task_serial.store(0, Ordering::Relaxed);
            debug.task_execution.store(0, Ordering::Release);
            debug.phase.store(0, Ordering::Release);
        }
        Ok(saved)
    }
    pub fn audit_idle(&self) -> Result<(), TrapError> {
        if !matches!(self.custody, Custody::Idle) {
            return Err(boundary_error(
                "carrier CPU still owns a task or failed detach",
            ));
        }
        audit_image(&self.io.read_image()?, &self.neutral)
    }
}
fn boundary_error(message: &str) -> TrapError {
    TrapError::Hypervisor(message.into())
}
fn audit_image(actual: &X86VcpuSnapshot, expected: &X86VcpuSnapshot) -> Result<(), TrapError> {
    if actual.gprs != expected.gprs
        || actual.rip != expected.rip
        || actual.rsp != expected.rsp
        || actual.rflags != expected.rflags
        || actual.cr0 != expected.cr0
        || actual.cr3 != expected.cr3
        || actual.cr4 != expected.cr4
        || actual.efer != expected.efer
        || actual.fs_base != expected.fs_base
        || actual.gs_base != expected.gs_base
        || actual.xsave != expected.xsave
    {
        return Err(boundary_error(
            "carrier CPU readback differs from its complete expected image",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_hal::guest_arch_binding::core_arch::*;
    use carrick_hal::threaded::{X86_TASK_RESUME_MAGIC, X86TaskCpuStateV1};
    use std::cell::Cell;
    use std::num::NonZeroU64;
    use std::rc::Rc;

    struct TestIo {
        image: X86VcpuSnapshot,
    }
    impl sealed::Sealed for TestIo {}
    impl CarrierCpuIo for TestIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            self.image = image.clone();
            Ok(())
        }
        fn run(&mut self) -> Result<VcpuExit, TrapError> {
            self.image.gprs[0] = 0xabc;
            Ok(VcpuExit::IoOut {
                port: carrick_x86::cpl0_entry::FORWARD_PORT,
                data: vec![0],
            })
        }
        fn complete_pending_io(&mut self) -> Result<(), TrapError> {
            Ok(())
        }
    }
    fn context_with_root(tag: u64, root: RootGpa) -> X86ArchContext {
        let nz = |v| NonZeroU64::new(v).unwrap();
        let binding = GuestArchBinding::x86(
            TaskIdentity {
                carrier: CarrierGeneration::new(nz(1)),
                task: TaskSerial::new(nz(tag)),
                execution: ExecutionGeneration::new(nz(tag + 10)),
            },
            AddressContext {
                root,
                mm: MmGeneration::new(nz(tag + 20)),
                generation: ContextGeneration::new(nz(tag + 30)),
            },
        );
        let mut resume = [0u8; X86_TASK_RESUME_PAYLOAD_LEN];
        // All pending-PC/syscall/SYSRET/fork flags are exercised, not just GPRs.
        for (slot, value) in [
            15,
            tag << 16,
            39,
            172,
            tag << 20,
            0x202,
            0,
            X86_TASK_RESUME_MAGIC,
        ]
        .into_iter()
        .enumerate()
        {
            resume[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut gprs = [tag; 16];
        gprs[7] = tag << 24;
        let state = X86TaskCpuStateV1::new(
            gprs,
            tag << 16,
            0x202,
            gprs[7],
            0x8000_0031,
            root.address().raw(),
            0x40620,
            0xd01,
            tag << 28,
            tag << 32,
            binding.context().mm.raw().get(),
            binding.context().generation.raw().get(),
            vec![tag as u8; carrick_x86::XSAVE_LEN],
            resume.to_vec(),
        )
        .unwrap();
        X86ArchContext::new(binding, state).unwrap()
    }
    fn context(tag: u64) -> X86ArchContext {
        let root = RootGpa::page_aligned(FrameGpa::new(tag << 12)).unwrap();
        context_with_root(tag, root)
    }

    #[test]
    fn two_task_contexts_preserve_registers_tls_xsave_and_resume() {
        let a = context(2);
        let b = context(3);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: context(1).hardware_image(),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        let saved_a = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(saved_a.state(), a.state());
        cpu.audit_idle().unwrap();
        cpu.load(b.clone()).unwrap();
        let saved_b = cpu.save_and_detach(b.binding().task()).unwrap();
        assert_eq!(saved_b.state(), b.state());
        assert_ne!(saved_a.state().cr3(), saved_b.state().cr3());
        assert_ne!(saved_a.state().fs_base(), saved_b.state().fs_base());
        assert_ne!(saved_a.state().gs_base(), saved_b.state().gs_base());
        assert_ne!(saved_a.state().xsave(), saved_b.state().xsave());
        cpu.load(saved_a).unwrap();
        assert_eq!(
            cpu.save_and_detach(a.binding().task()).unwrap().state(),
            a.state()
        );
        cpu.audit_idle().unwrap();
    }
    #[test]
    fn run_returns_typed_trap_with_stopped_complete_task_image() {
        let a = context(2);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: context(1).hardware_image(),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        let stopped = cpu.run_loaded(a.binding().task()).unwrap();
        assert_eq!(stopped.exit, CarrierRunExit::SyscallTrap);
        assert_eq!(stopped.state.as_ref().unwrap().binding(), a.binding());
        assert_eq!(stopped.state.as_ref().unwrap().state().gprs()[0], 0xabc);
        assert_eq!(
            stopped.state.as_ref().unwrap().state().xsave(),
            a.state().xsave()
        );
        assert!(cpu.audit_idle().is_err());
        let detached = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(detached.state().gprs()[0], 0xabc);
        cpu.audit_idle().unwrap();
    }
    struct ChildRetireIo {
        image: X86VcpuSnapshot,
        child_image: X86VcpuSnapshot,
        port: u16,
    }
    impl sealed::Sealed for ChildRetireIo {}
    impl CarrierCpuIo for ChildRetireIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            self.image = image.clone();
            Ok(())
        }
        fn run(&mut self) -> Result<VcpuExit, TrapError> {
            self.image = self.child_image.clone();
            let data = if self.port == carrick_x86::cpl0_entry::FORWARD_PORT {
                vec![0]
            } else {
                vec![0, 0, 0, 0]
            };
            Ok(VcpuExit::IoOut {
                port: self.port,
                data,
            })
        }
        fn complete_pending_io(&mut self) -> Result<(), TrapError> {
            Ok(())
        }
    }
    #[test]
    fn child_owner_grant_on_root_executor_is_a_physical_boundary() {
        let root = context(1);
        let child = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: root.hardware_image(),
            child_image: child.hardware_image(),
            port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        cpu.register_child_binding(child.binding()).unwrap();
        // CPL0 may schedule the child without a host task handoff. This is
        // physical service, not a trap belonging to the executor's root MM.
        let stopped = cpu.run_loaded(root.binding().task()).unwrap();
        assert_eq!(stopped.state.as_ref().unwrap().binding(), child.binding());
        assert_eq!(
            stopped.state.as_ref().unwrap().state().cr3(),
            child.binding().context().root.address().raw()
        );
    }

    #[test]
    fn maintenance_root_work_crossing_does_not_require_a_task_root() {
        let root = context(1);
        let maintenance = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: root.hardware_image(),
            child_image: maintenance.hardware_image(),
            port: carrick_x86::cpl0_entry::WORK_PORT,
        })
        .unwrap();
        cpu.maintenance_root = Some(maintenance.binding().context().root);
        cpu.load(root.clone()).unwrap();
        let stopped = cpu.run_loaded(root.binding().task()).unwrap();
        assert!(stopped.state.is_none());
        assert_eq!(
            stopped.exit,
            CarrierRunExit::PhysicalDoorbell {
                port: carrick_x86::cpl0_entry::WORK_PORT,
                data: vec![0, 0, 0, 0],
            }
        );
    }

    #[test]
    fn maintenance_root_cannot_authenticate_other_physical_crossings() {
        let root = context(1);
        let maintenance = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: root.hardware_image(),
            child_image: maintenance.hardware_image(),
            port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
        })
        .unwrap();
        cpu.maintenance_root = Some(maintenance.binding().context().root);
        cpu.load(root.clone()).unwrap();
        assert!(
            cpu.run_loaded(root.binding().task())
                .unwrap_err()
                .to_string()
                .contains("unregistered physical crossing CR3")
        );
    }

    #[test]
    fn unregistered_owner_grant_root_is_not_an_execution_authority() {
        let root = context(1);
        let child = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: root.hardware_image(),
            child_image: child.hardware_image(),
            port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        assert!(
            cpu.run_loaded(root.binding().task())
                .unwrap_err()
                .to_string()
                .contains("unregistered physical crossing CR3")
        );
    }

    #[test]
    fn child_retiring_on_vcpu_loaded_with_root_succeeds() {
        let root = context(1);
        let child = context(2);
        let child_root = child.binding().context().root;
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: context(1).hardware_image(),
            child_image: child.hardware_image(),
            port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        cpu.register_child_binding(child.binding()).unwrap();
        let stopped = cpu.run_loaded(root.binding().task()).unwrap();
        assert_eq!(
            stopped.exit,
            CarrierRunExit::PhysicalDoorbell {
                port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                data: vec![0, 0, 0, 0],
            }
        );
        assert_eq!(stopped.state.as_ref().unwrap().binding(), child.binding());
        assert_eq!(
            stopped.state.as_ref().unwrap().state().cr3(),
            child_root.address().raw()
        );
    }
    #[test]
    fn unregistered_child_retire_cr3_refuses_with_typed_error() {
        let root = context(1);
        let unregistered_child = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: context(1).hardware_image(),
            child_image: unregistered_child.hardware_image(),
            port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
        })
        .unwrap();
        // Do NOT register unregistered_child
        cpu.load(root.clone()).unwrap();
        let err = cpu.run_loaded(root.binding().task()).unwrap_err();
        assert!(
            err.to_string().contains("unregistered child retire CR3"),
            "unexpected error: {err:?}"
        );
        assert!(matches!(cpu.custody, Custody::Poisoned));
    }
    #[test]
    fn unregistered_forward_cr3_refuses_with_typed_error() {
        let root = context(1);
        let unregistered_child = context(2);
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: context(1).hardware_image(),
            child_image: unregistered_child.hardware_image(),
            port: carrick_x86::cpl0_entry::FORWARD_PORT,
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        let err = cpu.run_loaded(root.binding().task()).unwrap_err();
        assert!(
            err.to_string().contains("unregistered forward CR3"),
            "unexpected error: {err:?}"
        );
        assert!(matches!(cpu.custody, Custody::Poisoned));
    }
    #[test]
    fn retired_child_root_reuse_rejects_stale_binding() {
        let root = context(1);
        let child1 = context(2);
        let child1_root = child1.binding().context().root;
        let mut cpu = KvmCarrierCpu::new(ChildRetireIo {
            image: context(1).hardware_image(),
            child_image: child1.hardware_image(),
            port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        cpu.register_child_binding(child1.binding()).unwrap();
        let stopped = cpu.run_loaded(root.binding().task()).unwrap();
        assert_eq!(stopped.state.as_ref().unwrap().binding(), child1.binding());

        // Unregister retired child1
        let unregistered = cpu.unregister_child_binding(child1_root).unwrap();
        assert_eq!(unregistered, Some(child1.binding()));

        // Subsequent retire with child1's root must be refused as unregistered
        let err = cpu.run_loaded(root.binding().task()).unwrap_err();
        assert!(
            err.to_string().contains("unregistered child retire CR3"),
            "unexpected error: {err:?}"
        );

        // Register child2 reusing child1_root with distinct task identity
        let child2 = context_with_root(3, child1_root);
        let mut cpu2 = KvmCarrierCpu::new(ChildRetireIo {
            image: context(1).hardware_image(),
            child_image: child2.hardware_image(),
            port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
        })
        .unwrap();
        cpu2.load(root.clone()).unwrap();
        cpu2.register_child_binding(child2.binding()).unwrap();
        let stopped = cpu2.run_loaded(root.binding().task()).unwrap();
        assert_eq!(stopped.state.as_ref().unwrap().binding(), child2.binding());
        assert_ne!(stopped.state.as_ref().unwrap().binding(), child1.binding());
    }
    #[test]
    fn save_and_detach_preserves_live_carrier_child_bindings() {
        let root = context(1);
        let child = context(2);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: root.hardware_image(),
        })
        .unwrap();
        cpu.load(root.clone()).unwrap();
        cpu.register_child_binding(child.binding()).unwrap();
        assert_eq!(
            cpu.child_bindings
                .get(child.binding().context().root)
                .unwrap(),
            Some(child.binding())
        );
        cpu.save_and_detach(root.binding().task()).unwrap();
        cpu.audit_idle().unwrap();
        assert_eq!(
            cpu.child_bindings
                .get(child.binding().context().root)
                .unwrap(),
            Some(child.binding())
        );
    }

    #[test]
    fn peer_birth_survives_root_executor_detach_and_root_reuse_refuses_collision() {
        let root = context(1);
        let child = context(2);
        let bindings = CarrierChildBindings::default();
        let mut peer = KvmCarrierCpu::new_with_children(
            TestIo {
                image: root.hardware_image(),
            },
            bindings.clone(),
        )
        .unwrap();
        let mut cpu = KvmCarrierCpu::new_with_children(
            ChildRetireIo {
                image: root.hardware_image(),
                child_image: child.hardware_image(),
                port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
            },
            bindings,
        )
        .unwrap();
        peer.register_child_binding(child.binding()).unwrap();
        let collision = context_with_root(3, child.binding().context().root);
        assert!(peer.register_child_binding(collision.binding()).is_err());
        cpu.load(root.clone()).unwrap();
        cpu.save_and_detach(root.binding().task()).unwrap();
        cpu.audit_idle().unwrap();
        cpu.load(root.clone()).unwrap();
        let stopped = cpu.run_loaded(root.binding().task()).unwrap();
        assert_eq!(stopped.state.as_ref().unwrap().binding(), child.binding());
    }
    struct PendingIo {
        image: X86VcpuSnapshot,
        pending: bool,
        completions: Rc<Cell<usize>>,
    }
    impl sealed::Sealed for PendingIo {}
    impl CarrierCpuIo for PendingIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            if self.pending {
                return Err(boundary_error("pending PIO reached task image restore"));
            }
            self.image = image.clone();
            Ok(())
        }
        fn run(&mut self) -> Result<VcpuExit, TrapError> {
            self.pending = true;
            Ok(VcpuExit::IoOut {
                port: carrick_x86::cpl0_entry::FORWARD_PORT,
                data: vec![0],
            })
        }
        fn complete_pending_io(&mut self) -> Result<(), TrapError> {
            if !self.pending {
                return Err(boundary_error("PIO completion without pending exit"));
            }
            self.pending = false;
            self.image.rip += 2;
            self.completions.set(self.completions.get() + 1);
            Ok(())
        }
    }
    #[test]
    fn detach_consumes_pending_pio_once_before_a_different_task_loads() {
        let a = context(2);
        let b = context(3);
        let completions = Rc::new(Cell::new(0));
        let mut cpu = KvmCarrierCpu::new(PendingIo {
            image: context(1).hardware_image(),
            pending: false,
            completions: Rc::clone(&completions),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        let stopped = cpu.run_loaded(a.binding().task()).unwrap();
        assert_eq!(
            stopped.state.as_ref().unwrap().state().rip(),
            a.state().rip()
        );
        let saved = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(saved.state().rip(), a.state().rip() + 2);
        assert_eq!(completions.get(), 1);
        cpu.load(b.clone()).unwrap();
        cpu.save_and_detach(b.binding().task()).unwrap();
        assert_eq!(completions.get(), 1);
    }
    #[test]
    fn malformed_forward_doorbell_cannot_become_a_physical_exit() {
        assert!(
            CarrierRunExit::from_raw(VcpuExit::IoOut {
                port: carrick_x86::cpl0_entry::FORWARD_PORT,
                data: vec![0, 0],
            })
            .is_err()
        );
    }
    #[test]
    fn wrong_task_generation_cannot_detach_or_overwrite_a_loaded_cpu() {
        let a = context(2);
        let b = context(3);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: context(1).hardware_image(),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        let mut stale = a.binding().task();
        stale.execution = b.binding().task().execution;
        assert!(cpu.save_and_detach(stale).is_err());
        assert!(cpu.load(b).is_err());
        assert!(cpu.audit_idle().is_err());
        assert_eq!(
            cpu.save_and_detach(a.binding().task()).unwrap().state(),
            a.state()
        );
    }

    #[test]
    fn save_captures_live_register_and_vector_changes() {
        let a = context(2);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: context(1).hardware_image(),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        cpu.io.image.gprs[0] = 0x1234;
        cpu.io.image.xsave.as_mut().unwrap()[carrick_x86::XSAVE_AVX_OFFSET] = 0xee;
        let saved = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(saved.state().gprs()[0], 0x1234);
        assert_eq!(saved.state().xsave()[carrick_x86::XSAVE_AVX_OFFSET], 0xee);
        assert_eq!(saved.state().resume_payload(), a.state().resume_payload());
        cpu.audit_idle().unwrap();
    }

    #[test]
    fn stale_mm_root_or_missing_fp_cannot_produce_a_detach_receipt() {
        for break_image in [
            |s: &mut X86VcpuSnapshot| s.cr3 = 0xdead_0000,
            |s: &mut X86VcpuSnapshot| s.xsave = None,
            |s: &mut X86VcpuSnapshot| s.gprs[7] ^= 8,
        ] {
            let a = context(2);
            let mut cpu = KvmCarrierCpu::new(TestIo {
                image: context(1).hardware_image(),
            })
            .unwrap();
            cpu.load(a.clone()).unwrap();
            break_image(&mut cpu.io.image);
            assert!(cpu.save_and_detach(a.binding().task()).is_err());
            assert!(cpu.audit_idle().is_err());
            assert!(cpu.load(context(3)).is_err());
        }
    }

    // Supplementary kernel.el1.task-load-entry / execution-generation custody
    // witness, not the ARM no-maintenance-exit contract. Fail exactly one read
    // so a later refusal proves custody, rather than a permanently broken IO.
    #[derive(Default)]
    struct IoCalls {
        reads: Cell<usize>,
        writes: Cell<usize>,
    }
    impl IoCalls {
        fn assert_budget(&self, reads: usize, writes: usize) {
            assert_eq!((self.reads.get(), self.writes.get()), (reads, writes));
        }
    }
    struct ReadFaultIo {
        image: X86VcpuSnapshot,
        calls: Rc<IoCalls>,
        fail_read: usize,
    }
    impl ReadFaultIo {
        fn new(fail_read: usize) -> Self {
            Self {
                image: context(1).hardware_image(),
                calls: Rc::default(),
                fail_read,
            }
        }
    }
    impl sealed::Sealed for ReadFaultIo {}
    impl CarrierCpuIo for ReadFaultIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            let read = self.calls.reads.get() + 1;
            self.calls.reads.set(read);
            if read == self.fail_read {
                return Err(boundary_error("injected read failure"));
            }
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            self.calls.writes.set(self.calls.writes.get() + 1);
            self.image = image.clone();
            Ok(())
        }
        fn run(&mut self) -> Result<VcpuExit, TrapError> {
            Err(boundary_error("read-fault test driver cannot run"))
        }
        fn complete_pending_io(&mut self) -> Result<(), TrapError> {
            Err(boundary_error("read-fault test driver cannot complete IO"))
        }
    }
    fn assert_read_failure<T>(result: Result<T, TrapError>) {
        match result {
            Err(TrapError::Hypervisor(message)) => assert_eq!(message, "injected read failure"),
            _ => panic!("the failed read must refuse to return a CPU or detach receipt"),
        }
    }
    fn read_fault_tasks() -> [X86ArchContext; 2] {
        let a = context(2);
        let b = context(3);
        // Same carrier/task serial, distinct execution and MM generations.
        let binding = GuestArchBinding::x86(
            TaskIdentity {
                task: a.binding().task().task,
                ..b.binding().task()
            },
            b.binding().context(),
        );
        [a, X86ArchContext::new(binding, b.state().clone()).unwrap()]
    }
    fn assert_poisoned_without_io(
        cpu: &mut KvmCarrierCpu<ReadFaultIo>,
        tasks: &[X86ArchContext; 2],
        reads: usize,
        writes: usize,
    ) {
        for task in tasks {
            assert!(
                cpu.load(task.clone()).is_err(),
                "failed transaction must refuse later load reuse"
            );
            cpu.io.calls.assert_budget(reads, writes);
            assert!(
                cpu.save_and_detach(task.binding().task()).is_err(),
                "failed transaction must not manufacture a detach receipt"
            );
            cpu.io.calls.assert_budget(reads, writes);
        }
        assert!(cpu.audit_idle().is_err());
        cpu.io.calls.assert_budget(reads, writes);
    }

    #[test]
    fn initial_capture_read_failure_refuses_cpu_without_writes_or_retries() {
        let io = ReadFaultIo::new(1);
        let calls = Rc::clone(&io.calls);
        assert_read_failure(KvmCarrierCpu::new(io));
        // Construction consists solely of the initial capture.
        calls.assert_budget(1, 0);
    }

    #[test]
    fn idle_read_failure_refuses_before_mutation_and_preserves_reuse() {
        for through_load in [false, true] {
            let mut cpu = KvmCarrierCpu::new(ReadFaultIo::new(2)).unwrap();
            let [a, b] = read_fault_tasks();
            cpu.io.calls.assert_budget(1, 0);
            if through_load {
                assert_read_failure(cpu.load(a.clone()));
            } else {
                assert_read_failure(cpu.audit_idle());
            }
            // Capture + failed idle audit; no task image was installed.
            cpu.io.calls.assert_budget(2, 0);
            assert!(matches!(cpu.custody, Custody::Idle));
            audit_image(&cpu.io.image, cpu.neutral_image()).unwrap();
            // Retry is a new caller operation after a pre-mutation refusal.
            for (turn, expected) in [a, b].into_iter().enumerate() {
                cpu.load(expected.clone()).unwrap();
                cpu.io.calls.assert_budget(4 + 4 * turn, 1 + 2 * turn);
                let saved = cpu.save_and_detach(expected.binding().task()).unwrap();
                assert_eq!(saved.binding(), expected.binding());
                assert_eq!(saved.state(), expected.state());
                cpu.io.calls.assert_budget(6 + 4 * turn, 2 + 2 * turn);
            }
        }
    }

    #[test]
    fn post_load_read_failure_poisoning_blocks_both_task_generations_without_io() {
        let tasks = read_fault_tasks();
        for task in &tasks {
            let mut cpu = KvmCarrierCpu::new(ReadFaultIo::new(3)).unwrap();
            assert_read_failure(cpu.load(task.clone()));
            // Capture + idle audit + failed load readback, one task write.
            cpu.io.calls.assert_budget(3, 1);
            audit_image(&cpu.io.image, &task.hardware_image()).unwrap();
            assert_poisoned_without_io(&mut cpu, &tasks, 3, 1);
        }
    }

    #[test]
    fn pre_detach_read_failure_poisoning_blocks_both_task_generations_without_io() {
        let tasks = read_fault_tasks();
        for task in &tasks {
            let mut cpu = KvmCarrierCpu::new(ReadFaultIo::new(4)).unwrap();
            cpu.load(task.clone()).unwrap();
            cpu.io.calls.assert_budget(3, 1);
            assert_read_failure(cpu.save_and_detach(task.binding().task()));
            // Successful capture/load + failed snapshot; no reset write.
            cpu.io.calls.assert_budget(4, 1);
            audit_image(&cpu.io.image, &task.hardware_image()).unwrap();
            assert_poisoned_without_io(&mut cpu, &tasks, 4, 1);
        }
    }

    #[test]
    fn post_reset_read_failure_neutral_image_cannot_authorize_reuse_or_detach() {
        let tasks = read_fault_tasks();
        for task in &tasks {
            let mut cpu = KvmCarrierCpu::new(ReadFaultIo::new(5)).unwrap();
            cpu.load(task.clone()).unwrap();
            cpu.io.calls.assert_budget(3, 1);
            assert_read_failure(cpu.save_and_detach(task.binding().task()));
            // Capture/load + snapshot + failed reset audit, task + reset writes.
            cpu.io.calls.assert_budget(5, 2);
            audit_image(&cpu.io.image, cpu.neutral_image()).unwrap();
            assert_poisoned_without_io(&mut cpu, &tasks, 5, 2);
        }
    }

    struct FaultIo {
        image: X86VcpuSnapshot,
        writes: usize,
        corrupt_on: usize,
        field: u8,
    }
    impl sealed::Sealed for FaultIo {}
    impl CarrierCpuIo for FaultIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            self.image = image.clone();
            self.writes += 1;
            if self.writes == self.corrupt_on {
                match self.field {
                    0 => self.image.cr3 ^= 0x1000,
                    1 => self.image.fs_base ^= 8,
                    2 => self.image.gs_base ^= 8,
                    3 => self.image.xsave.as_mut().unwrap()[carrick_x86::XSAVE_AVX_OFFSET] ^= 1,
                    _ => return Err(boundary_error("injected partial restore failure")),
                }
            }
            Ok(())
        }
        fn run(&mut self) -> Result<VcpuExit, TrapError> {
            Err(boundary_error("restore-fault test driver cannot run"))
        }
        fn complete_pending_io(&mut self) -> Result<(), TrapError> {
            Err(boundary_error(
                "restore-fault test driver cannot complete IO",
            ))
        }
    }
    #[test]
    fn root_tls_fp_or_partial_restore_failure_poison_custody() {
        for corrupt_on in [1, 2] {
            for field in 0..5 {
                let a = context(2);
                let mut cpu = KvmCarrierCpu::new(FaultIo {
                    image: context(1).hardware_image(),
                    writes: 0,
                    corrupt_on,
                    field,
                })
                .unwrap();
                let loaded = cpu.load(a.clone());
                if corrupt_on == 1 {
                    assert!(loaded.is_err());
                } else {
                    loaded.unwrap();
                    assert!(cpu.save_and_detach(a.binding().task()).is_err());
                }
                assert!(cpu.audit_idle().is_err());
                assert!(cpu.load(context(3)).is_err());
                assert!(cpu.save_and_detach(a.binding().task()).is_err());
            }
        }
    }
}
