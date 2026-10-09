//! Stopped CPU custody and one running boundary for the carrier.
use carrick_hal::guest_arch_binding::{GuestArchBinding, core_arch::TaskIdentity};
use carrick_hal::threaded::X86_TASK_RESUME_PAYLOAD_LEN;
use carrick_hal::{HvVcpu, HvVm, TrapError, VcpuExit};
use carrick_x86::{BringupLayout, X86VcpuSnapshot, arch_context::X86ArchContext};

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
        )
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
    pub state: X86ArchContext,
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

pub struct KvmCarrierCpu<I: CarrierCpuIo = KvmCpuIo> {
    io: I,
    neutral: X86VcpuSnapshot,
    custody: Custody,
}
impl KvmCarrierCpu<KvmCpuIo> {
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
        })
    }

    pub(crate) fn from_production(
        vcpu: crate::KvmVcpu,
        vm: crate::KvmVm,
        layout: BringupLayout,
        production_run: crate::cpl0_boot::ProductionRunContext,
    ) -> Result<Self, TrapError> {
        Self::new(KvmCpuIo {
            vcpu,
            _vm: vm,
            layout,
            production_run: Some(production_run),
        })
    }
}
impl<I: CarrierCpuIo> KvmCarrierCpu<I> {
    fn new(io: I) -> Result<Self, TrapError> {
        let neutral = io.read_image()?;
        if neutral.xsave.is_none() {
            return Err(boundary_error("carrier CPU requires complete V1 XSAVE"));
        }
        Ok(Self {
            io,
            neutral,
            custody: Custody::Idle,
        })
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
        let raw = match self.io.run() {
            Ok(exit) => exit,
            Err(error) => {
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
        let state = match self
            .io
            .read_image()
            .and_then(|image| X86ArchContext::capture(binding, &image, resume))
        {
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
        Ok(StoppedTaskExit { state, exit })
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
    fn context(tag: u64) -> X86ArchContext {
        let nz = |v| NonZeroU64::new(v).unwrap();
        let root = RootGpa::page_aligned(FrameGpa::new(tag << 12)).unwrap();
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
        assert_eq!(stopped.state.binding(), a.binding());
        assert_eq!(stopped.state.state().gprs()[0], 0xabc);
        assert_eq!(stopped.state.state().xsave(), a.state().xsave());
        assert!(cpu.audit_idle().is_err());
        let detached = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(detached.state().gprs()[0], 0xabc);
        cpu.audit_idle().unwrap();
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
        assert_eq!(stopped.state.state().rip(), a.state().rip());
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
