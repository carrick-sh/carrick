//! The raw hypervisor layer: a backend-agnostic vCPU/VM surface.
//!
//! KVM implements these in `carrick-linux`. HVF adoption is deferred —
//! `HvfTrapEngine` keeps driving `applevisor` directly — so on macOS these
//! traits are defined but unimplemented in this spec.

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
/// `MmioWrite { gpa: SENTINEL, .. }`.
pub enum VcpuExit {
    MmioWrite { gpa: u64, data: u64, len: u8 },
    Exception { syndrome: u64, far: u64 },
    Kicked,
    Halt,
}
