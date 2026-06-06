//! KvmTrapEngine: drives a `KvmVcpu` to implement the `carrick-hal`
//! `SyscallTrap` contract. `next_syscall` runs KVM_RUN until the EL1 vector's
//! sentinel store surfaces as `VcpuExit::MmioWrite { gpa: SENTINEL_GPA, .. }`,
//! reads x0..x5,x8 into an `Aarch64SyscallFrame`, and returns it.
use carrick_abi::LinuxSiginfo;
use carrick_guest_mem::Aarch64SyscallFrame;
use carrick_hal::{ForkOutcome, HvVcpu, Reg, SyscallTrap, TrapError, VcpuExit};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup::{BroughtUp, GuestRam, SENTINEL_GPA, bring_up};
use crate::kvm::{KvmVcpu, KvmVm};

pub struct KvmTrapEngine {
    _vm: KvmVm,
    vcpu: KvmVcpu,
    ram: GuestRam,
}

impl KvmTrapEngine {
    /// Bring up the guest from a freestanding ELF image and return an engine
    /// parked at the EL1 trampoline (first `next_syscall` runs into EL0).
    pub fn new(image: &AddressSpace) -> Result<Self, TrapError> {
        let BroughtUp {
            vm,
            vcpu,
            ram,
            entry: _,
        } = bring_up(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(Self {
            _vm: vm,
            vcpu,
            ram,
        })
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (e.g. a
    /// `write(2)` buffer the guest passed). Backed by the same host RAM the
    /// vCPU sees, so guest writes are visible.
    pub fn read_guest(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        self.ram
            .read(gpa, len)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
}

// NOTE: KvmTrapEngine implements the `carrick-hal` SyscallTrap contract; the
// MVP drives it from `crate::run_elf`, reading the trapped write(2) buffer out
// of the live guest RAM via `read_guest`. Pairing it with the full
// carrick-runtime dispatcher (SplitView @ runtime.rs:3701) is the full-Linux-
// backend spec's job — that path needs ~200 macOS-isms ported off the dispatch
// layer first (see run_elf.rs).

impl SyscallTrap for KvmTrapEngine {
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        // One KVM_RUN per call; the outer run loop calls `next_syscall`
        // repeatedly. Classify the exit and return.
        match self
            .vcpu
            .run()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?
        {
            VcpuExit::MmioWrite { gpa, .. } if gpa == SENTINEL_GPA => {
                // The EL0 `svc` re-entered EL1 and hit the sentinel store.
                // The hardware already set ELR_EL1 = (svc addr + 4) on the
                // exception, and the EL1 vector's own `eret` (after the
                // sentinel store) consumes it — so we do NOT touch the PC
                // here; we just read the syscall frame.
                Ok(Some(self.read_frame()?))
            }
            VcpuExit::MmioWrite { gpa, data, len } => Err(TrapError::UnexpectedExit {
                reason: format!("MMIO at non-sentinel gpa=0x{gpa:x} data=0x{data:x} len={len}"),
            }),
            // A bare kick or halt with no pending syscall: the contract is to
            // return `None` so the run loop can run signal delivery and resume.
            VcpuExit::Halt | VcpuExit::Kicked => Ok(None),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::UnexpectedException {
                syndrome,
                virtual_address: far,
                physical_address: far,
            }),
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu
            .reg(Reg::Pc)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write the syscall result into x0. The guest resume PC is already
        // correct: ELR_EL1 (= svc+4) was latched by the exception and is
        // restored by the EL1 vector's `eret`. We must NOT advance it again,
        // or the instruction after the `svc` would be skipped.
        self.vcpu
            .set_reg(Reg::X(0), return_value as u64)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
        _fault_siginfo: Option<(i32, u64)>,
        _queued_siginfo: Option<LinuxSiginfo>,
        _restart_syscall: bool,
    ) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }
}

impl KvmTrapEngine {
    fn read_frame(&self) -> Result<Aarch64SyscallFrame, TrapError> {
        let g = |n: u32| {
            self.vcpu
                .reg(Reg::X(n))
                .map_err(|e| TrapError::Hypervisor(e.to_string()))
        };
        Ok(Aarch64SyscallFrame {
            x0: g(0)?,
            x1: g(1)?,
            x2: g(2)?,
            x3: g(3)?,
            x4: g(4)?,
            x5: g(5)?,
            x8: g(8)?,
        })
    }
}
