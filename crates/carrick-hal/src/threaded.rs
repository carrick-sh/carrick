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
}

/// Object-safe `VcpuKick` for storage in the registry (the `Clone` bound on
/// `VcpuKick` is not object-safe, so the registry stores boxed handles).
pub trait VcpuKickDyn: Send + Sync {
    fn kick(&self);
}
impl<T: VcpuKick> VcpuKickDyn for T {
    fn kick(&self) {
        VcpuKick::kick(self)
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

/// The platform-NEUTRAL [`VcpuRegistry`] implementation, shared by every backend.
///
/// It is two maps — per-tid kick handles and per-tid "currently in-guest" flags
/// — plus the SeqCst Dekker handshake the fork / page-table-edit coordinators
/// rely on. The only platform-specific piece is the kick MECHANISM, which is
/// already behind [`VcpuKickDyn`] (HVF `hv_vcpus_exit`, KVM `pthread_kill`,
/// bhyve `_umtx_op`/`vm_suspend_cpu`), so the registry itself names no backend.
/// Kicks are per-handle (`kick_all` calls each handle's `kick()`); a backend that
/// batched (HVF's old bulk `hv_vcpus_exit(ids)`) is behavior-equivalent — N
/// single-id exits force the same vCPUs out, at the same infrequent quiesce
/// points — so the bulk fast path is dropped in favour of one shared registry.
///
/// A backend that needs setup at construction (e.g. KVM installing its
/// SIGRTMIN kick-signal handler) wraps this in a thin newtype whose `new()` does
/// the setup and delegates the trait. This struct is only ever driven through
/// [`VcpuRegistry`], so it intentionally has no inherent kick API.
#[derive(Default)]
pub struct GenericVcpuRegistry {
    handles: std::sync::Mutex<std::collections::HashMap<ThreadId, Box<dyn VcpuKickDyn>>>,
    in_guest: std::sync::Mutex<std::collections::HashMap<ThreadId, Arc<AtomicBool>>>,
}

impl GenericVcpuRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_handles(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<ThreadId, Box<dyn VcpuKickDyn>>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_in_guest(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<ThreadId, Arc<AtomicBool>>> {
        self.in_guest.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl VcpuRegistry for GenericVcpuRegistry {
    fn register(&self, tid: ThreadId, handle: Box<dyn VcpuKickDyn>) {
        self.lock_handles().insert(tid, handle);
    }

    fn register_in_guest(&self, tid: ThreadId) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        self.lock_in_guest().insert(tid, Arc::clone(&flag));
        flag
    }

    fn unregister(&self, tid: ThreadId) {
        self.lock_handles().remove(&tid);
        self.lock_in_guest().remove(&tid);
    }

    fn kick(&self, tid: ThreadId) {
        if let Some(h) = self.lock_handles().get(&tid) {
            h.kick();
        }
    }

    fn kick_all(&self) {
        for h in self.lock_handles().values() {
            h.kick();
        }
    }

    fn kick_all_except(&self, except: ThreadId) {
        for (tid, h) in self.lock_handles().iter() {
            if *tid != except {
                h.kick();
            }
        }
    }

    fn any_other_in_guest(&self, except: ThreadId) -> bool {
        self.lock_in_guest()
            .iter()
            .any(|(tid, f)| *tid != except && f.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn set_in_guest(&self, tid: ThreadId, in_guest: bool) {
        if let Some(flag) = self.lock_in_guest().get(&tid) {
            flag.store(in_guest, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn count(&self) -> usize {
        self.lock_handles().len()
    }
}

#[cfg(test)]
mod generic_registry_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct CountingHandle(Arc<AtomicU64>);
    impl VcpuKickDyn for CountingHandle {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn register_unregister_count() {
        let r = GenericVcpuRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(1, Box::new(CountingHandle(Arc::new(AtomicU64::new(0)))));
        r.register(2, Box::new(CountingHandle(Arc::new(AtomicU64::new(0)))));
        assert_eq!(r.count(), 2);
        r.unregister(1);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn kick_all_except_skips_caller() {
        let r = GenericVcpuRegistry::new();
        let c1 = Arc::new(AtomicU64::new(0));
        let c2 = Arc::new(AtomicU64::new(0));
        r.register(1, Box::new(CountingHandle(Arc::clone(&c1))));
        r.register(2, Box::new(CountingHandle(Arc::clone(&c2))));
        r.kick_all_except(1);
        assert_eq!(c1.load(Ordering::SeqCst), 0, "caller must not be kicked");
        assert_eq!(c2.load(Ordering::SeqCst), 1, "the other vCPU is kicked");
        r.kick_all();
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn in_guest_flag_handshake() {
        let r = GenericVcpuRegistry::new();
        let _flag = r.register_in_guest(1);
        r.register_in_guest(2);
        assert!(!r.any_other_in_guest(1));
        r.set_in_guest(2, true);
        assert!(r.any_other_in_guest(1), "tid 2 is in-guest");
        assert!(!r.any_other_in_guest(2), "except self → false");
        r.set_in_guest(2, false);
        assert!(!r.any_other_in_guest(1));
    }
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
    /// The upper 128 bits of YMM\[n\] (the AVX `YMM_Hi` XSAVE component). Used by
    /// the x86 signal frame to preserve a thread's AVX upper halves across a
    /// signal+sigreturn — the FXSAVE area `get_vreg` reads holds only the low
    /// 128 bits (XMM). DEFAULT 0: a backend without AVX state (aarch64's 128-bit
    /// V-regs are fully covered by `get_vreg`) has no upper half to report.
    fn get_ymm_hi(&self, _n: u32) -> Result<u128, OsError> {
        Ok(0)
    }
    /// Set the upper 128 bits of YMM\[n\]. DEFAULT no-op (no AVX state).
    fn set_ymm_hi(&mut self, _n: u32, _v: u128) -> Result<(), OsError> {
        Ok(())
    }
    fn get_fpcr(&self) -> Result<u64, OsError>;
    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError>;
    fn get_fpsr(&self) -> Result<u64, OsError>;
    fn set_fpsr(&mut self, v: u64) -> Result<(), OsError>;

    /// Save the FP/SIMD state for an x86 signal frame in one shot: MXCSR, the 16
    /// XMM low halves (`[u32; 64]`, the FXSAVE `xmm_space` layout), and the 16
    /// AVX `YMM_Hi` upper halves (256 bytes). The DEFAULT loops the per-register
    /// getters (correct for any backend, e.g. aarch64); the x86 engine overrides
    /// it with a SINGLE `KVM_GET_XSAVE` — the XSAVE area carries MXCSR + XMM in
    /// its legacy FXSAVE region AND `YMM_Hi` in its AVX region. The per-register
    /// path costs ~33 host ioctls per signal DELIVERY, a throughput cliff under a
    /// signal flood (CPython `test_stress_delivery_simultaneous`).
    fn save_fpsimd_frame(&mut self) -> Result<(u32, [u32; 64], [u8; 256]), OsError> {
        let mxcsr = self.get_fpcr()? as u32;
        let mut xmm = [0u32; 64];
        let mut ymm_hi = [0u8; 256];
        for n in 0..16u32 {
            let v = self.get_vreg(n)?.to_le_bytes();
            let b = (n * 4) as usize;
            for j in 0..4 {
                xmm[b + j] =
                    u32::from_le_bytes([v[j * 4], v[j * 4 + 1], v[j * 4 + 2], v[j * 4 + 3]]);
            }
            let off = n as usize * 16;
            ymm_hi[off..off + 16].copy_from_slice(&self.get_ymm_hi(n)?.to_le_bytes());
        }
        Ok((mxcsr, xmm, ymm_hi))
    }

    /// Restore the FP/SIMD state from an x86 signal frame (inverse of
    /// [`RegAccess::save_fpsimd_frame`]). DEFAULT loops the per-register setters;
    /// the x86 engine overrides with ONE `KVM_GET_XSAVE` + ONE `KVM_SET_XSAVE`,
    /// replacing ~80 per-register ioctls per signal RETURN.
    fn restore_fpsimd_frame(
        &mut self,
        mxcsr: u32,
        xmm: &[u32; 64],
        ymm_hi: &[u8; 256],
    ) -> Result<(), OsError> {
        self.set_fpcr(u64::from(mxcsr))?;
        for n in 0..16u32 {
            let b = (n * 4) as usize;
            let mut raw = [0u8; 16];
            for j in 0..4 {
                raw[j * 4..j * 4 + 4].copy_from_slice(&xmm[b + j].to_le_bytes());
            }
            self.set_vreg(n, u128::from_le_bytes(raw))?;
            let off = n as usize * 16;
            let mut hi = [0u8; 16];
            hi.copy_from_slice(&ymm_hi[off..off + 16]);
            self.set_ymm_hi(n, u128::from_le_bytes(hi))?;
        }
        Ok(())
    }
}

/// Read the aarch64 Linux syscall-argument frame — `x0..x5` (the 6 args) + `x8`
/// (the syscall number) — from a vCPU via a register getter.
///
/// Both aarch64 backends (HVF, KVM) extract the IDENTICAL frame on every `svc`
/// trap; this single-sources the register set so it lives in ONE place, a step
/// toward the `Aarch64EngineCore` symmetry with `carrick_x86` (F7). Takes a
/// `get` closure rather than `&impl RegAccess` because HVF reads inside its inner
/// engine (which is not itself the `RegAccess` impl). Each backend maps the
/// [`OsError`] to its own `TrapError` at the call site.
pub fn read_aarch64_syscall_frame(
    mut get: impl FnMut(Reg) -> Result<u64, OsError>,
) -> Result<carrick_guest_mem::Aarch64SyscallFrame, OsError> {
    Ok(carrick_guest_mem::Aarch64SyscallFrame {
        x0: get(Reg::X(0))?,
        x1: get(Reg::X(1))?,
        x2: get(Reg::X(2))?,
        x3: get(Reg::X(3))?,
        x4: get(Reg::X(4))?,
        x5: get(Reg::X(5))?,
        x8: get(Reg::X(8))?,
    })
}

/// The bound the shared threaded loop is generic over. A backend is its own
/// trap vehicle + register access + guest memory + per-thread/fork lifecycle.
/// `GuestMemory` is a supertrait so the shared loop can `write_bytes` to the
/// guest (tid stamps, clone parent/child-tid writes) through the engine.
/// ISA-neutral entry register deltas for a freshly-created guest execution
/// context — a `clone(CLONE_THREAD)` sibling thread or a `fork(2)` child.
///
/// Each backend maps these named fields onto its ISA registers when seeding a
/// vCPU snapshot, so adding an architecture is "map three named values onto my
/// register file," not "reimplement entry seeding." `None` means "inherit the
/// parent's value" (a fork child inherits stack+tls via COW; a clone sibling
/// supplies fresh ones).
///
/// | field          | aarch64       | x86_64      |
/// |----------------|---------------|-------------|
/// | `return_value` | `X0`          | `RAX`       |
/// | `stack`        | `SP_EL0`      | `RSP`       |
/// | `tls`          | `TPIDR_EL0`   | `FS.base`   |
///
/// The resume PC is intentionally NOT here — it is backend-derived (aarch64
/// `ELR_EL1`; x86_64 the `SYSRETQ` after the doorbell), not caller-supplied.
#[derive(Clone, Copy, Debug, Default)]
pub struct GuestEntryRegs {
    pub return_value: u64,
    pub stack: Option<u64>,
    pub tls: Option<u64>,
}

pub trait ThreadedEngine: SyscallTrap + RegAccess + GuestMemory + Send {
    /// The guest CPU ISA this engine runs. Fixed per process (the guest ISA
    /// equals the host ISA), so it is an associated type — monomorphized per
    /// ISA, no syscall-hot-path vtable. Aarch64 today; x86_64 in Phase 2.
    type Arch: crate::guest_arch::GuestArch;
    type KickHandle: VcpuKick + 'static;
    type SiblingSpec: Send;

    fn kick_handle(&self) -> Self::KickHandle;
    fn wait_for_vcpu_slot();
    /// Live concurrent-vCPU budget N for the admission scheduler (the M:N pool).
    /// `usize::MAX` (the default) means "no carrick-side cap" — HVF (its own
    /// `vcpu_gate` stays in Phase 1) and KVM; bhyve returns `hw.vmm.maxcpu`.
    fn vcpu_budget() -> usize {
        usize::MAX
    }
    /// Whether this backend RECLAIMS a guest thread's vCPU slot when the thread
    /// blocks (the M:N reclaim-on-block). `false` (default) keeps Phase-1
    /// lifetime-binding — HVF/KVM until Phase 3. bhyve returns `true`.
    fn reclaims(&self) -> bool {
        false
    }
    /// Whether this backend's reclaim DESTROYS the vCPU (so its kick handle goes
    /// dead and the runtime must unregister it from the VcpuRegistry before the
    /// block and re-register on wake). `true` for HVF (destroy/recreate; raw
    /// hv_vcpu_destroy does not drop applevisor's liveness Weak, so a stale handle
    /// would lie `is_valid`); `false` for bhyve (pool-swap keeps the vCPU alive).
    fn reclaim_refreshes_kicker(&self) -> bool {
        false
    }
    /// Save THIS thread's full guest CPU state (GPRs + RSP/RFLAGS + FS/GS base +
    /// FP/AVX) before releasing its vCPU slot at a block point. Only ever called by
    /// the owning host thread, only when [`reclaims`](Self::reclaims). Opaque,
    /// backend-serialized bytes round-tripped to [`rebind_to_slot`](Self::rebind_to_slot).
    /// `&mut self`: HVF DESTROYS its vCPU inside this call (snapshot then
    /// hv_vcpu_destroy); bhyve/KVM read registers and ignore the extra mutability.
    fn save_guest_state(&mut self) -> Vec<u8> {
        Vec::new()
    }
    /// Re-bind this engine to `slot`'s vCPU and restore `state` into it — called by
    /// the owning thread when it re-acquires a (possibly different) slot after a
    /// block. Only when [`reclaims`](Self::reclaims).
    fn rebind_to_slot(&mut self, slot: crate::SlotId, state: &[u8]) -> Result<(), TrapError> {
        let _ = (slot, state);
        Ok(())
    }
    fn build_sibling_spec(&self, entry: GuestEntryRegs) -> Result<Self::SiblingSpec, TrapError>;
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
