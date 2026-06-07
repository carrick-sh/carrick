//! The minimal hypervisor-specific surface the shared threaded run-loop drives.
//! `SyscallTrap` (per-syscall) stays separate; this carries the per-thread /
//! fork / kick / futex lifecycle so single-threaded backends are unaffected.
use std::time::Duration;

use crate::error::{OsError, Reg, SysReg};
use crate::trap::{SyscallTrap, TrapError};

pub type ThreadId = i32;

/// Cross-thread "force this vCPU out of the guest" primitive.
/// HVF: `hv_vcpus_exit`. KVM: `pthread_kill(tid, KICK_SIGNAL)` -> `KVM_RUN` EINTR.
pub trait VcpuKick: Send + Sync + Clone {
    fn kick(&self);
    /// Whether the target vCPU is currently inside guest execution (the
    /// `in_guest` SeqCst flag the run loop maintains around `next_syscall`).
    fn target_in_guest(&self) -> bool;
}

/// Object-safe `VcpuKick` for storage in the registry (the `Clone` bound on
/// `VcpuKick` is not object-safe, so the registry stores boxed handles).
pub trait VcpuKickDyn: Send + Sync {
    fn kick(&self);
    fn target_in_guest(&self) -> bool;
}
impl<T: VcpuKick> VcpuKickDyn for T {
    fn kick(&self) {
        VcpuKick::kick(self)
    }
    fn target_in_guest(&self) -> bool {
        VcpuKick::target_in_guest(self)
    }
}

/// The process-wide registry of live vCPUs the run loop kicks/counts. Held as
/// `Arc<dyn VcpuRegistry>` so the shared loop never names a concrete kicker.
pub trait VcpuRegistry: Send + Sync {
    fn register(&self, tid: ThreadId, handle: Box<dyn VcpuKickDyn>);
    fn unregister(&self, tid: ThreadId);
    fn kick(&self, tid: ThreadId);
    fn kick_all_except(&self, except: ThreadId);
    fn any_other_in_guest(&self, except: ThreadId) -> bool;
    fn set_in_guest(&self, tid: ThreadId, in_guest: bool);
    fn count(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexOutcome {
    Woken,
    TimedOut,
    Interrupted,
}

/// The private + shared futex backend. HVF: parking-lot `FutexTable` (private) +
/// `os_sync_wait_on_address` (shared). KVM: real host `SYS_futex` for both.
pub trait PlatformFutex: Send + Sync {
    fn private_wait(
        &self,
        addr: u64,
        val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome;
    fn private_wake(&self, addr: u64, n: u32) -> u32;
    fn shared_wait(
        &self,
        host_addr: usize,
        val: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64;
    fn shared_wake(&self, host_addr: usize, n: u32) -> i64;
    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32);
}

/// Get/set the registers + V-regs the sigframe builder needs. Each engine
/// already exposes `Reg`/`SysReg` get/set; this names the FP/SIMD regs too.
pub trait RegAccess {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError>;
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError>;
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError>;
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError>;
    fn get_vreg(&self, n: u32) -> Result<u128, OsError>;
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError>;
    fn get_fpcr(&self) -> Result<u64, OsError>;
    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError>;
    fn get_fpsr(&self) -> Result<u64, OsError>;
    fn set_fpsr(&mut self, v: u64) -> Result<(), OsError>;
}

/// The bound the shared threaded loop is generic over. A backend is its own
/// trap vehicle + register access + per-thread/fork lifecycle.
pub trait ThreadedEngine: SyscallTrap + RegAccess + Send {
    type KickHandle: VcpuKick + 'static;
    type SiblingSpec: Send;

    fn kick_handle(&self) -> Self::KickHandle;
    fn wait_for_vcpu_slot();
    fn build_sibling_spec(&self, stack: u64, tls: u64) -> Result<Self::SiblingSpec, TrapError>;
    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError>
    where
        Self: Sized;
    fn release_vcpu_for_fork(&mut self) -> Result<(), TrapError> {
        Ok(())
    }
    fn rebuild_vcpu_after_fork(&mut self) -> Result<(), TrapError> {
        Ok(())
    }
    fn publish_vm_for_siblings(&mut self) -> Result<(), TrapError> {
        Ok(())
    }
    fn destroy_vcpu_on_thread_exit(&mut self) {}
}
