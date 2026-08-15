//! The minimal hypervisor-specific surface the shared threaded run-loop drives.
//! `SyscallTrap` (per-syscall) stays separate; this carries the per-thread /
//! fork / kick / futex lifecycle so single-threaded backends are unaffected.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use carrick_guest_mem::GuestMemory;
pub use carrick_guest_mem::{HostVa, SharedFutexLocation};

use crate::error::{OsError, Reg, SysReg};
use crate::trap::{ForkOutcome, SyscallTrap, TrapError};

/// The process-local thread/vCPU **registry key**.
///
/// This is the key a guest thread is filed under in every per-process table:
/// the vCPU kick registry, the `ThreadRegistry`, the private-futex park
/// tokens, and the per-thread signal bookkeeping. It is NOT a host thread
/// identity (that axis is the mach-port `ThreadPort`) and NOT the
/// guest-visible tid (the runtime's `guest_visible_tid` derives that from this
/// key at the `gettid`//proc seam).
///
/// The field is private and there is deliberately NO general
/// `From<i32>`/`from_raw` (docs/typed-interfaces-audit.md P1.3): construction
/// goes through the named semantic constructors below, and the raw value
/// escapes only at wire/libc/probe boundaries via [`ThreadId::raw`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(i32);

impl ThreadId {
    /// The "no thread context" sentinel — numeric 0, exactly the value the raw
    /// `i32` code used (`ctx_tid` returns it when a syscall is dispatched with
    /// no thread context). Compares unequal to every real registry key.
    pub const NONE: ThreadId = ThreadId(0);

    /// The MAIN guest thread's registry key, deliberately seeded from this
    /// process's host pid. This is the identity the tree relies on:
    /// main-key == host pid == ns-base pid, which is what lets
    /// `guest_visible_tid` reconcile the main thread's key to the guest's
    /// ns-pid and lets guest-supplied tids index the registry untranslated.
    pub fn main_from_host_pid() -> Self {
        Self(std::process::id() as i32)
    }

    /// [`ThreadId::main_from_host_pid`] for a caller that already holds the
    /// host-pid VALUE (e.g. captured around a fork boundary). The argument is
    /// a HOST pid by contract — never a guest/ns pid.
    pub fn main_from_host_pid_value(host_pid: i32) -> Self {
        Self(host_pid)
    }

    /// A GUEST-SUPPLIED tid (ns domain: `tgkill`/`tkill` targets,
    /// `/proc/<tid>` lookups, `F_SETOWN_EX` ids) entering the registry-key
    /// space UNTRANSLATED.
    ///
    /// Convention: this works today because the main thread's key == host pid
    /// == ns-base pid, and worker keys are handed to the guest untranslated —
    /// so the guest hands back exactly the registry key. This constructor
    /// NAMES that crossing without changing it: no translation, no checks.
    pub fn from_guest_supplied_tid(tid: i32) -> Self {
        Self(tid)
    }

    /// A registry key ROUND-TRIPPING back from one of carrick's own raw-`i32`
    /// wire tables (the signal-core pending/xsig tables, whose publish sites
    /// exported the key with [`ThreadId::raw`]). Re-enters the value unchanged
    /// — this is NOT a general `from_raw`: only use it where the value's
    /// provenance is a prior `raw()` export of a registry key.
    pub fn from_wire_key(raw: i32) -> Self {
        Self(raw)
    }

    /// A key allocated by the thread registry's monotonic counter
    /// (`ThreadRegistry::register_child`'s `next_tid.fetch_add`). Only the
    /// registry allocation path should construct through this.
    pub fn from_registry_allocation(raw: i32) -> Self {
        Self(raw)
    }

    /// A synthetic registry key for TESTS (concurrency harnesses that
    /// fabricate worker keys like `100 + w`). Not for production code.
    pub fn synthetic_for_tests(raw: i32) -> Self {
        Self(raw)
    }

    /// The raw key value, escaping to a wire/libc/probe boundary (signal-core
    /// pending tables, USDT probes, guest tid byte writes, park tokens).
    pub fn raw(self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Serializes as the bare `i32` key (diagnostics/event-ring payloads keep
/// their pre-newtype wire shape).
impl serde::Serialize for ThreadId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

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
    /// Bounded timeout diagnostics only: registered vCPU identities and their
    /// current in-guest handshake state. Ordinary coordination must use the
    /// scalar predicates above rather than snapshots.
    fn debug_registered_vcpus(&self) -> Vec<(ThreadId, bool)> {
        Vec::new()
    }
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

    fn debug_registered_vcpus(&self) -> Vec<(ThreadId, bool)> {
        let handles = self.lock_handles();
        let in_guest = self.lock_in_guest();
        let mut snapshot: Vec<_> = handles
            .keys()
            .copied()
            .map(|tid| {
                let active = in_guest
                    .get(&tid)
                    .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst));
                (tid, active)
            })
            .collect();
        snapshot.sort_by_key(|(tid, _)| tid.raw());
        snapshot
    }
}

#[cfg(test)]
mod generic_registry_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn t(raw: i32) -> ThreadId {
        ThreadId::synthetic_for_tests(raw)
    }

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
        r.register(t(1), Box::new(CountingHandle(Arc::new(AtomicU64::new(0)))));
        r.register(t(2), Box::new(CountingHandle(Arc::new(AtomicU64::new(0)))));
        assert_eq!(r.count(), 2);
        r.unregister(t(1));
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn kick_all_except_skips_caller() {
        let r = GenericVcpuRegistry::new();
        let c1 = Arc::new(AtomicU64::new(0));
        let c2 = Arc::new(AtomicU64::new(0));
        r.register(t(1), Box::new(CountingHandle(Arc::clone(&c1))));
        r.register(t(2), Box::new(CountingHandle(Arc::clone(&c2))));
        r.kick_all_except(t(1));
        assert_eq!(c1.load(Ordering::SeqCst), 0, "caller must not be kicked");
        assert_eq!(c2.load(Ordering::SeqCst), 1, "the other vCPU is kicked");
        r.kick_all();
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn in_guest_flag_handshake() {
        let r = GenericVcpuRegistry::new();
        let _flag = r.register_in_guest(t(1));
        r.register_in_guest(t(2));
        assert!(!r.any_other_in_guest(t(1)));
        r.set_in_guest(t(2), true);
        assert!(r.any_other_in_guest(t(1)), "tid 2 is in-guest");
        assert!(!r.any_other_in_guest(t(2)), "except self → false");
        r.set_in_guest(t(2), false);
        assert!(!r.any_other_in_guest(t(1)));
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
        location: SharedFutexLocation,
        waiter_key: usize,
        val: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
        wait_enrolled: &dyn Fn(),
    ) -> i64;
    fn shared_wake(&self, location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64;
    fn shared_requeue(
        &self,
        _from: SharedFutexLocation,
        _from_key: usize,
        _to: SharedFutexLocation,
        _to_key: usize,
        _wake: u32,
        _requeue: u32,
    ) -> (u32, u32) {
        (0, 0)
    }
    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32);
    /// Wake every private-futex waiter so it re-checks its interrupt predicate
    /// (a process-directed signal became pending, or a fork/exec quiesce was
    /// requested). Does not consume the futex word; a spurious wake just costs a
    /// re-check.
    fn notify_signal_pending(&self);
    /// Wake the private-futex waiter parked for `tid` (a thread-directed signal).
    fn notify_signal_pending_for(&self, tid: ThreadId);
}

/// One standard-format XSAVE component range reported by CPUID leaf 0xD.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86XstateComponent {
    pub offset: u32,
    pub size: u32,
}

impl X86XstateComponent {
    pub const fn new(offset: u32, size: u32) -> Self {
        Self { offset, size }
    }

    pub fn end(self) -> Option<usize> {
        usize::try_from(self.offset)
            .ok()?
            .checked_add(usize::try_from(self.size).ok()?)
    }
}

/// Cached x86 user-xstate geometry used by the signal-frame codec. Component 9
/// (PKRU) is deliberately absent for the native lane: its guest value is a
/// Carrick virtual scalar and must never reach hardware XRSTOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86XstateCapabilities {
    pub supported_features: u64,
    pub standard_size: u32,
    pub mxcsr_mask: u32,
    pub components: [X86XstateComponent; 64],
}

impl X86XstateCapabilities {
    /// Compatibility geometry for x86 VMM backends whose existing batch seam
    /// carries the legacy area and AVX YMM_Hi component.
    pub const fn legacy_avx() -> Self {
        let mut components = [X86XstateComponent { offset: 0, size: 0 }; 64];
        components[2] = X86XstateComponent::new(576, 256);
        Self {
            supported_features: 0x7,
            standard_size: 832,
            mxcsr_mask: 0x0000_ffbf,
            components,
        }
    }

    pub fn component(self, number: u32) -> Option<X86XstateComponent> {
        let index = usize::try_from(number).ok()?;
        let component = *self.components.get(index)?;
        (component.size != 0).then_some(component)
    }

    /// Exact standard-format extent required by a supported feature subset.
    pub fn standard_size_for(self, features: u64) -> Option<usize> {
        if features & !self.supported_features != 0 || features & 0x3 != 0x3 {
            return None;
        }
        let mut end = carrick_abi::X8664_XSAVE_MIN_LEN;
        for number in 2..64u32 {
            if features & (1u64 << number) == 0 {
                continue;
            }
            end = end.max(self.component(number)?.end()?);
        }
        (end <= carrick_abi::X8664_XSAVE_AREA_MAX_LEN).then_some(end)
    }
}

/// Complete standard-format x86 signal state passed through one architecture-
/// specific batch seam. The byte vector begins with the 512-byte legacy area
/// and includes the 64-byte standard XSAVE header and every advertised
/// component at its CPUID leaf 0xD offset. Linux magic words and Carrick's PKRU
/// trailer are frame metadata and are not part of this image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X86SignalXstate {
    pub bytes: Vec<u8>,
    pub xfeatures: u64,
    pub virtual_pkru: u32,
    pub virtual_x87_fcs: u16,
    pub virtual_x87_fds: u16,
}

/// Get/set the registers + FP/SIMD state the shared sigframe builders need.
///
/// This is a sigframe/trap-loop adapter, not a claim that every guest ISA has
/// every [`Reg`] / [`SysReg`] variant. Narrower native engine traits translate
/// into this shape at the shared boundary.
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

    /// Capabilities for the x86 batch signal-state seam. Non-x86 callers never
    /// invoke this default; legacy x86 VMMs retain their AVX-era geometry.
    fn x86_xstate_capabilities(&self) -> Result<X86XstateCapabilities, OsError> {
        Ok(X86XstateCapabilities::legacy_avx())
    }

    /// Export all authoritative guest xstate in standard format. Native x86
    /// overrides this with a direct snapshot copy using cached CPUID geometry.
    fn save_x86_signal_xstate(&mut self) -> Result<X86SignalXstate, OsError> {
        let (mxcsr, xmm, ymm_hi) = self.save_fpsimd_frame()?;
        let caps = self.x86_xstate_capabilities()?;
        let size = usize::try_from(caps.standard_size).map_err(|_| OsError::from_raw(libc::EIO))?;
        if !(832..=carrick_abi::X8664_XSAVE_AREA_MAX_LEN).contains(&size) {
            return Err(OsError::from_raw(libc::EIO));
        }
        let mut bytes = vec![0u8; size];
        bytes[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        bytes[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        bytes[28..32].copy_from_slice(&caps.mxcsr_mask.to_le_bytes());
        for (index, word) in xmm.iter().enumerate() {
            let offset = 160 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes[512..520].copy_from_slice(&0x7u64.to_le_bytes());
        bytes[576..832].copy_from_slice(&ymm_hi);
        Ok(X86SignalXstate {
            bytes,
            xfeatures: 0x7,
            virtual_pkru: 0,
            virtual_x87_fcs: carrick_abi::LINUX_X8664_USER_CS,
            virtual_x87_fds: carrick_abi::LINUX_X8664_USER_DS,
        })
    }

    /// Import a fully validated standard-format image. Native x86 overrides
    /// this to commit one temporary complete snapshot plus virtual PKRU.
    fn restore_x86_signal_xstate(&mut self, state: &X86SignalXstate) -> Result<(), OsError> {
        if state.bytes.len() < carrick_abi::X8664_XSAVE_MIN_LEN {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let mut mxcsr_bytes = [0u8; 4];
        mxcsr_bytes.copy_from_slice(&state.bytes[24..28]);
        let mxcsr = u32::from_le_bytes(mxcsr_bytes);
        let mut xmm = [0u32; 64];
        for (index, word) in xmm.iter_mut().enumerate() {
            let offset = 160 + index * 4;
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&state.bytes[offset..offset + 4]);
            *word = u32::from_le_bytes(bytes);
        }
        let mut ymm_hi = [0u8; 256];
        if state.xfeatures & (1 << 2) != 0 {
            let end = 832usize;
            if state.bytes.len() < end {
                return Err(OsError::from_raw(libc::EINVAL));
            }
            ymm_hi.copy_from_slice(&state.bytes[576..end]);
        }
        self.restore_fpsimd_frame(mxcsr, &xmm, &ymm_hi)
    }

    /// Save the legacy x86 FP/SIMD subset. Kept for existing VMM adapters; new
    /// signal codecs use [`RegAccess::save_x86_signal_xstate`].
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

/// Select the PSTATE to save into an aarch64 signal frame.
///
/// The two aarch64 backends agree on the rule: the KICK path (a host signal
/// interrupted the guest mid-EL0, so `interrupted_pc` is set) saves the LIVE EL0
/// PSTATE; the SYSCALL/eret path (`interrupted_pc == None`) saves `SPSR_EL1`,
/// where the `svc` latched the EL0 PSTATE. Single-sourced here (F7).
///
/// `live_pstate` lets a caller that ALREADY read the live PSTATE (HVF reads it
/// for its EL-discrimination) reuse it instead of re-reading; `None` reads it
/// fresh (KVM).
pub fn aarch64_signal_pstate_source(
    interrupted_pc: Option<u64>,
    live_pstate: Option<u64>,
    get: impl Fn(Reg) -> Result<u64, OsError>,
) -> Result<u64, OsError> {
    if interrupted_pc.is_some() {
        match live_pstate {
            Some(p) => Ok(p),
            None => get(Reg::Pstate),
        }
    } else {
        get(Reg::SpsrEl1)
    }
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

/// Minimal architecture-neutral register set recorded when a guest thread
/// enters a host-backed blocking wait. This is deliberately small enough for
/// the always-on event ring and crash bundles: instruction, stack, and return
/// linkage are sufficient to symbolize the park site without saving a core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestWaitRegisters {
    pub pc: u64,
    pub sp: u64,
    /// AArch64 X30. Architectures without a link register report zero.
    pub lr: u64,
}

/// Complete AArch64 EL0 architectural state captured at a crash-generation
/// safe point.  This is intentionally separate from the best-effort wait
/// diagnostic above: a core publisher must fail closed if any field is absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch64CoreRegisters {
    pub gprs: [u64; 31],
    pub sp_el0: u64,
    pub pc: u64,
    pub pstate: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub tpidr_el0: u64,
    pub vregs: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

/// Runtime authority used by a backend when a private stage-1 write fault (or
/// a kernel copy-to-user into the same page) must publish one new physical
/// frame. The backend owns physical allocation/mapping; the runtime owns the
/// authenticated kernel frame inventory transaction.
pub trait FrameCowQuiesce {}

impl<T> FrameCowQuiesce for T {}

pub trait FrameCowAuthority: Send + Sync {
    fn quiesce(&self)
    -> Result<Box<dyn FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>;

    fn reserve(
        &self,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_count: usize,
    ) -> Result<crate::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>;

    fn apply(
        &self,
        commit: crate::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Authenticate that the just-published physical mapping is visible in
    /// the bound mm's kernel-owned graph before the backend advertises a COW
    /// commit or disarms the permission fault.
    fn mapping_is_live(
        &self,
        mapping: crate::MappingId,
        frame: crate::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: crate::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCowIdentity {
    pub linux_pid: i32,
    pub linux_tid: i32,
    pub mm: u64,
    pub asid: u16,
}

pub trait ThreadedEngine: SyscallTrap + RegAccess + GuestMemory + Send {
    fn bind_frame_cow(
        &mut self,
        _authority: std::sync::Arc<dyn FrameCowAuthority>,
        _identity: FrameCowIdentity,
    ) {
    }

    /// Refresh fork-private backend state after the child frame inventory and
    /// exact MM/COW authority are live, but before the child enters guest code.
    fn refresh_fork_process_state(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    /// Resolve a synchronous stage-1 write-permission fault. `Ok(true)` means
    /// the exact mm now owns a writable copied frame and the instruction should
    /// be retried; `Ok(false)` leaves ordinary fault delivery unchanged.
    fn resolve_frame_cow_fault(&mut self, _syndrome: u64, _far: u64) -> Result<bool, TrapError> {
        Ok(false)
    }

    /// Arm the exact child-map transaction before any backend/topology lock is
    /// acquired. HVPatch transfers this non-cloneable reservation through its
    /// process specification; other engines retain the no-op default.
    fn begin_process_inventory(
        &mut self,
        reservation: crate::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        drop(reservation);
        Err(TrapError::Hypervisor(
            "backend does not expose process frame inventory".to_owned(),
        ))
    }

    /// Release a backend child-inventory operation slot after a fork attempt
    /// fails before materialization consumes it.
    fn cancel_process_inventory(&mut self) -> bool {
        false
    }

    /// Complete child materialization returns the staged batch through this
    /// seam. VM/vCPU replay never populates it.
    fn take_process_inventory(&mut self) -> Option<crate::FrameInventoryCommit<()>> {
        None
    }

    fn begin_retirement_inventory(
        &mut self,
        reservation: crate::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        drop(reservation);
        Err(TrapError::Hypervisor(
            "backend does not expose retirement frame inventory".to_owned(),
        ))
    }

    fn take_retirement_inventory(&mut self) -> Option<crate::FrameInventoryCommit<()>> {
        None
    }
    /// The guest CPU ISA this engine runs. Fixed per process (the guest ISA
    /// equals the host ISA), so it is an associated type — monomorphized per
    /// ISA, no syscall-hot-path vtable. Aarch64 today; x86_64 in Phase 2.
    type Arch: crate::guest_arch::GuestArch;
    type KickHandle: VcpuKick + 'static;
    type SiblingSpec: Send;
    type ProcessSpec: Send;

    /// Best-effort guest register snapshot taken before blocking-wait reclaim
    /// destroys or releases the live vCPU. Backends opt in; absence degrades
    /// diagnostics only and never changes guest behavior.
    fn diagnostic_wait_registers(&self) -> Option<GuestWaitRegisters> {
        None
    }

    /// Exact core-dump register authority.  A backend that cannot provide the
    /// complete shape returns an error/absence and no core may be published.
    fn aarch64_core_registers(&self) -> Result<Option<Aarch64CoreRegisters>, TrapError> {
        Ok(None)
    }

    /// Prepare a coherent backend memory view for live core capture. Backends
    /// whose ordinary guest-memory view is always current keep the no-op;
    /// HVPatch uses this at the all-thread safe point to load its software
    /// stage-1 observer from the live hardware table backing without editing it.
    fn prepare_core_snapshot(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    /// Read bytes from a VMA already authenticated as readable by the coherent
    /// core snapshot. The default preserves ordinary checked guest-memory
    /// semantics; AArch64 HVPatch bypasses only its syscall-path PROT_NONE
    /// reservation gate so a live `brk` prefix can be captured from backing.
    fn read_core_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        self.read_bytes(address, length)
    }

    /// Best-effort fault-time walk of the live stage-1 backing. The returned
    /// scalar is the exact TTBR root+ASID observed at the fault; descriptors are
    /// L0..L3 for `far`. Backends without host-editable guest page tables keep
    /// the default absence.
    fn diagnostic_fault_page_tables(&self, _far: u64) -> Option<(u64, [u64; 4])> {
        None
    }

    /// Select a backend lifecycle in which guest exec/fork operations retain
    /// one host VM and replace only per-process address-space state. Backends
    /// without shared-VM process support keep the default no-op; callers still
    /// gate process creation on their explicit backend policy.
    fn set_persistent_vm_lifecycle(&mut self, _enabled: bool) {}

    /// Bind this engine to one in-process guest's AArch64 ASID. The default is
    /// a no-op for backends that retain the one-host-process-per-guest-process
    /// model. Hvpatch overrides this and keeps the ASID across exec replacement.
    fn configure_process_asid(&mut self, _asid: u16) -> Result<(), TrapError> {
        Ok(())
    }

    /// True only for a backend that represents Linux fork as another vCPU plus
    /// another stage-1 address space inside the current host VM.
    fn supports_in_process_fork(&self) -> bool {
        false
    }

    /// Retire an in-process guest address space after its last vCPU reports a
    /// terminal exit. Backends with per-process stage-1/stage-2 state override
    /// this to flush translations and unmap owned ranges before lifecycle code
    /// makes the ASID/bank reusable.
    fn retire_in_process_address_space(&mut self) -> Result<(), TrapError> {
        self.process_exit_cleanup()?;
        self.destroy_vcpu_on_thread_exit();
        Ok(())
    }

    fn build_process_spec(
        &mut self,
        _entry: GuestEntryRegs,
        _child_ttbr0: u64,
        _root_slot_base: u64,
        _root_slot_size: u64,
        _child_tid: ThreadId,
        _forking_tid: ThreadId,
    ) -> Result<Self::ProcessSpec, TrapError> {
        Err(TrapError::Hypervisor(
            "backend does not support in-process fork".to_owned(),
        ))
    }

    fn materialize_process(_spec: Self::ProcessSpec) -> Result<Self, TrapError>
    where
        Self: Sized,
    {
        Err(TrapError::Hypervisor(
            "backend does not support in-process fork".to_owned(),
        ))
    }

    /// The child is materialized and every remaining fork publication failure
    /// is fail-closed. Forget the parent's saved pre-arm state.
    fn commit_process_fork(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    /// Restore parent stage-1 and COW-arm metadata after a recoverable child
    /// spawn/materialization failure.
    fn rollback_process_fork(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

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
    /// Save state for a process-shared futex wait. Backends that can release
    /// stronger host resources while parked may override this separately from
    /// the generic private-futex reclaim path.
    fn save_shared_wait_state(&mut self) -> Vec<u8> {
        self.save_guest_state()
    }
    /// Re-bind this engine to `slot`'s vCPU and restore `state` into it — called by
    /// the owning thread when it re-acquires a (possibly different) slot after a
    /// block. Only when [`reclaims`](Self::reclaims).
    fn rebind_to_slot(&mut self, slot: crate::SlotId, state: &[u8]) -> Result<(), TrapError> {
        let _ = (slot, state);
        Ok(())
    }
    /// Restore state saved by [`Self::save_shared_wait_state`].
    fn rebind_shared_wait_state(
        &mut self,
        slot: crate::SlotId,
        state: &[u8],
    ) -> Result<(), TrapError> {
        self.rebind_to_slot(slot, state)
    }
    /// MT whole-VM residency lease — VM-only release, called by the LAST
    /// parker of a multi-threaded process AFTER its own vCPU was already
    /// destroyed by [`Self::save_guest_state`] (so the runtime registry's
    /// "parked" mark truthfully means "vCPU destroyed" for every marked
    /// thread, and this call finds zero live vCPUs). Returns `Ok(true)` iff
    /// the backend released whole-VM state that a claim-true waker must
    /// rebuild via [`Self::rebind_shared_wait_state_mt`]; `Ok(false)` (the
    /// default) means the backend has no whole-VM state to release
    /// (pool-swap backends). On `Err` or `Ok(false)` the caller MUST NOT set
    /// the registry's vm-released flag — the park stays a vCPU-only park (a
    /// failed teardown must never poison an innocent sibling's wake with a
    /// rebuild against a live VM).
    fn release_vm_after_reclaim_park(&mut self) -> Result<bool, TrapError> {
        Ok(false)
    }
    /// Restore state saved by [`Self::save_shared_wait_state`] when the parked
    /// process was MULTI-THREADED (the whole-VM residency lease): the FIRST
    /// waker rebuilds the per-process VM state on behalf of every still-parked
    /// sibling, so a backend whose shared-wait park tears the whole VM down
    /// must replay the UNION of every thread's dynamic mappings — not just
    /// this (waking) thread's per-thread list (HVF overrides this via its
    /// process-global alias registry). Defaults to the single-threaded
    /// restore: pool-swap backends (KVM x86, bhyve) never tear down
    /// per-process VM state on a shared-wait park, so there is nothing extra
    /// to rebuild.
    fn rebind_shared_wait_state_mt(
        &mut self,
        slot: crate::SlotId,
        state: &[u8],
    ) -> Result<(), TrapError> {
        self.rebind_shared_wait_state(slot, state)
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
    /// Publish the guest mmap-arena high-water (the dispatcher's
    /// `mmap_arena_high_water`) just before a `vfork(2)` so a shared-VM backend can
    /// bound the per-window residency scan to the used arena prefix instead of the
    /// full (e.g. 32 GiB) arena. Default no-op; the KVM backend stores it for
    /// `prepare_vfork_share`. Harmless to call on a non-vfork fork.
    fn set_vfork_arena_high_water(&mut self, _high_water: u64) {}
    /// `vfork(2)` PARENT, on RESUME (the suspended parent's pipe wait returned —
    /// the child has execve'd/`_exit`ed). Reconcile any shared-VM writes the child
    /// made back into the parent's address space and release the share. Backends
    /// that share the parent's RAM directly (HVF) or have no shared-VM path need
    /// nothing here; the KVM backend, which shares via a shadow that the suspended
    /// parent must copy back, overrides it. Default no-op.
    fn finish_vfork_parent(&mut self) {}
    /// Backend hook before dispatching a guest syscall. Direct shared-memory
    /// backends need nothing; a backend that emulates file-backed `MAP_SHARED`
    /// with copied guest RAM can use this to publish guest stores before the
    /// syscall observes the backing file.
    fn needs_shared_file_alias_sync(&self) -> bool {
        false
    }
    fn sync_shared_file_aliases(&mut self) -> Result<(), TrapError> {
        Ok(())
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
