//! The minimal hypervisor-specific surface the shared threaded run-loop drives.
//! `SyscallTrap` (per-syscall) stays separate; this carries the per-thread /
//! fork / kick / futex lifecycle so single-threaded backends are unaffected.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use carrick_guest_mem::GuestMemory;

use crate::error::{OsError, Reg, SysReg};
use crate::trap::{ForkOutcome, SyscallTrap, TrapError};

pub type ThreadId = i32;

/// Cross-thread "force this vCPU out of the guest" primitive.
/// HVF: `hv_vcpus_exit`. KVM: `pthread_kill(tid, KICK_SIGNAL)` -> `KVM_RUN` EINTR.
pub trait VcpuKick: Send + Sync + Clone {
    fn kick(&self);
    /// Whether the target vCPU is currently inside guest execution (the
    /// `in_guest` SeqCst flag the run loop maintains around `next_syscall`).
    fn target_in_guest(&self) -> bool;
    /// The backend's raw vCPU id if the vCPU is still live, for bulk-kick paths
    /// that force several vCPUs out at once (HVF `hv_vcpus_exit(ids, count)`).
    /// `None` once the vCPU is destroyed (a stale id is then skipped). Backends
    /// with no bulk-kick primitive return `None` and rely on per-handle `kick`.
    fn raw_vcpu_id(&self) -> Option<u64> {
        None
    }
}

/// Object-safe `VcpuKick` for storage in the registry (the `Clone` bound on
/// `VcpuKick` is not object-safe, so the registry stores boxed handles).
pub trait VcpuKickDyn: Send + Sync {
    fn kick(&self);
    fn target_in_guest(&self) -> bool;
    fn raw_vcpu_id(&self) -> Option<u64>;
}
impl<T: VcpuKick> VcpuKickDyn for T {
    fn kick(&self) {
        VcpuKick::kick(self)
    }
    fn target_in_guest(&self) -> bool {
        VcpuKick::target_in_guest(self)
    }
    fn raw_vcpu_id(&self) -> Option<u64> {
        VcpuKick::raw_vcpu_id(self)
    }
}

/// The process-wide registry of live vCPUs the run loop kicks/counts. Held as
/// `Arc<dyn VcpuRegistry>` so the shared loop never names a concrete kicker.
pub trait VcpuRegistry: Send + Sync {
    fn register(&self, tid: ThreadId, handle: Box<dyn VcpuKickDyn>);
    /// Register (and return) this thread's "currently in `hv_vcpu_run`" flag.
    /// The shared loop sets it true immediately before entering the guest and
    /// false immediately after, forming a Dekker handshake with the fork /
    /// page-table-edit coordinators (which set their quiesce flag and read this
    /// — SeqCst on both sides guarantees at least one observes the other).
    fn register_in_guest(&self, tid: ThreadId) -> Arc<AtomicBool>;
    fn unregister(&self, tid: ThreadId);
    fn kick(&self, tid: ThreadId);
    /// Kick every registered vCPU (including the caller's, if registered). The
    /// process-directed signal pump uses this to nudge every in-guest thread to
    /// re-check pending at its next safe point.
    fn kick_all(&self);
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
    /// Wake every private-futex waiter so it re-checks its interrupt predicate
    /// (a process-directed signal became pending, or a fork/exec quiesce was
    /// requested). Does not consume the futex word; a spurious wake just costs a
    /// re-check.
    fn notify_signal_pending(&self);
    /// Wake the private-futex waiter parked for `tid` (a thread-directed signal).
    fn notify_signal_pending_for(&self, tid: ThreadId);
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
/// trap vehicle + register access + guest memory + per-thread/fork lifecycle.
/// `GuestMemory` is a supertrait so the shared loop can `write_bytes` to the
/// guest (tid stamps, clone parent/child-tid writes) through the engine.
pub trait ThreadedEngine: SyscallTrap + RegAccess + GuestMemory + Send {
    type KickHandle: VcpuKick + 'static;
    type SiblingSpec: Send;

    fn kick_handle(&self) -> Self::KickHandle;
    fn wait_for_vcpu_slot();
    fn build_sibling_spec(&self, stack: u64, tls: u64) -> Result<Self::SiblingSpec, TrapError>;
    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError>
    where
        Self: Sized;
    /// The guest PC of a freshly materialized sibling vCPU (trace diagnostics).
    fn program_counter(&self) -> Result<u64, TrapError>;
    /// Set the guest user stack pointer (`SP_EL0`) on a vfork child that was
    /// given an explicit `child_stack` by `clone`.
    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError>;
    /// Stamp the running guest thread's guest-visible tid into the vCPU (the
    /// EL1 `gettid` fast path). No-op unless the syscall shim is enabled.
    fn set_guest_thread_id(&self, tid: u64) -> Result<(), TrapError>;
    /// `vfork(2)` variant of [`SyscallTrap::fork`]: the child SHARES the
    /// parent's guest RAM (`CLONE_VM`) and the parent is suspended until the
    /// child execve's/exits. Defaults to a plain `fork` for backends without a
    /// distinct shared-RAM path.
    fn fork_vfork(&mut self) -> Result<ForkOutcome, TrapError> {
        self.fork()
    }
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
    /// Construct a FRESH vCPU-kick registry for the CHILD side of a guest
    /// `fork(2)`. `libc::fork` replicates only the calling thread, so the child
    /// must drop the parent's kicker (no phantom siblings). Returned as the
    /// object-safe trait type the shared loop holds so the core never names the
    /// concrete kicker. The child rebuilds its private-futex backend separately
    /// via the `PlatformFutexFactory` (over a fresh `FutexTable`) so the two
    /// stay over the SAME table (the notify-signal-pending consistency invariant).
    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry>;
}

/// A token produced by [`HostForkCoordinator::prepare_host_fork`] and traded
/// back in to one of the `restart_after_*` methods. Plain data (no
/// hypervisor-specific state): it records whether a signal pump was running so
/// the post-fork restart can recreate one only when needed.
pub struct PreparedHostFork {
    pub had_signal_pump: bool,
}

/// Coordinates carrick-owned HOST state that must not be left mid-flight across
/// a real host `fork(2)` — principally the process-directed signal-pump daemon
/// thread, which `fork(2)` would otherwise strand (it carries only the calling
/// thread into the child). The shared threaded loop drives it through this
/// object-safe trait so the loop never names the concrete `ForkCoordinator`.
///
/// The registry / futex arguments are the object-safe [`VcpuRegistry`] /
/// [`PlatformFutex`] the loop already holds; the concrete impl restarts its pump
/// against them.
pub trait HostForkCoordinator: Send + Sync {
    /// Start the process-directed signal pump (idempotent) against the given
    /// registry + futex, if one is not already running.
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>);
    /// Stop + join the signal pump before `libc::fork`, returning a token that
    /// records whether a pump was running.
    fn prepare_host_fork(&self) -> PreparedHostFork;
    /// Parent-side post-fork restart: recreate the pump if one was running OR if
    /// the parent now needs one to deliver a child-exit signal.
    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
        child_exit_needs_signal_pump: bool,
    );
    /// Child-side post-fork restart: recreate the pump only if the parent had one.
    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    );
    /// Error-path restart (fork failed): recreate the pump if one was running.
    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    );
}
