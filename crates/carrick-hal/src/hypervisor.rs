//! The raw hypervisor layer: a backend-agnostic vCPU/VM surface where it removes
//! real backend duplication.
//!
//! KVM implements these in `carrick-vmm-kvm`; bhyve implements them where the
//! raw VM/vCPU shape fits its libvmmapi surface. HVF adoption is intentionally
//! not a goal by itself: `HvfTrapEngine` drives `applevisor` directly because
//! its lifecycle and vCPU coordination are currently better expressed at the
//! engine level (`SyscallTrap` / `ThreadedEngine`) than through this raw trait.
//! Treat this module as an adapter seam, not the required portability boundary.

use crate::error::{MemPerms, OsError, Reg, SysReg};
use carrick_mem::memory::AddressSpace;

pub trait HvVm: Sized {
    type Vcpu: HvVcpu;
    fn create(mem: &AddressSpace) -> Result<Self, OsError>;
    fn map_memory(
        &mut self,
        gpa: u64,
        host: *mut u8,
        len: usize,
        perms: MemPerms,
    ) -> Result<(), OsError>;
    fn add_vcpu(&mut self) -> Result<Self::Vcpu, OsError>;
    fn destroy(self) -> Result<(), OsError>;
}

pub trait HvVcpu {
    fn run(&mut self) -> Result<VcpuExit, OsError>;
    fn reg(&self, r: Reg) -> Result<u64, OsError>;
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError>;
    /// Program an AArch64 system register (VBAR_EL1, TTBR0_EL1, TCR/MAIR/SCTLR).
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError>;
    /// Force the vCPU out of `run()` from another thread (abstracts
    /// `hv_vcpus_exit` / KVM signal-kick).
    fn kick(&self) -> Result<(), OsError>;
}

/// Why the vCPU stopped running. The MMIO-sentinel trap vehicle surfaces as
/// `MmioWrite { gpa: SENTINEL, .. }`. The INOUT doorbell (x86 KVM backend)
/// surfaces as `IoOut { port: SYSCALL_DOORBELL_PORT, .. }`.
pub enum VcpuExit {
    MmioWrite {
        gpa: u64,
        data: u64,
        len: u8,
    },
    Exception {
        syndrome: u64,
        far: u64,
    },
    Kicked,
    Halt,
    /// x86-64 KVM backend only: `OUT port, al` exited as `KVM_EXIT_IO`.
    /// `port` is the doorbell port (0xC5 for the SYSCALL trap vehicle).
    /// `data` is the slice KVM provides (1 byte for `OUT imm8, %al`).
    /// Source: KVM API §4.35 "KVM_EXIT_IO" + kvm-ioctls `VcpuExit::IoOut`.
    IoOut {
        port: u16,
        data: Vec<u8>,
    },
}
