//! Darwin-native execution backend.
//!
//! Same-ISA Linux ELFs are loaded into a forked host child and execute only as
//! DSR-translated native code. DSR gateways dispatch Linux syscalls through the
//! existing syscall layer; guest code is never executed directly. OCI/container
//! setup is shared with the other runtime backends, while this module owns image
//! loading and the native run loop. Unsupported dispatcher outcomes fail
//! explicitly rather than falling back to HVF.

mod address;
// Transitional Darwin `NativeHostJit` impl for the extracted `carrick_dsr`
// translation cache (migrates to `carrick-native-darwin` in a later slice).
mod darwin_jit;
mod dsr;

pub(crate) fn artifact_spike_authority_snapshot_if_enabled()
-> anyhow::Result<Option<crate::native_exec_capsule::NativeReexecArtifactSpikeV1>> {
    dsr::artifact_spike::authority_snapshot_if_enabled()
}

pub(crate) fn adopt_artifact_spike_for_resume(
    snapshot: &crate::native_exec_capsule::NativeReexecArtifactSpikeV1,
) -> anyhow::Result<()> {
    dsr::artifact_spike::adopt_for_resume(snapshot)
}

pub(crate) fn aot_cache_authority_snapshot()
-> anyhow::Result<Option<crate::native_exec_capsule::NativeReexecAotCacheV1>> {
    carrick_native_darwin::aot_cache::container_cache_snapshot()
        .map(|snapshot| snapshot.map(Into::into))
        .map_err(|error| anyhow::anyhow!("snapshot native AOT cache authority: {error}"))
}

pub(crate) fn adopt_aot_cache_for_resume(
    snapshot: &crate::native_exec_capsule::NativeReexecAotCacheV1,
) -> anyhow::Result<()> {
    carrick_native_darwin::aot_cache::adopt_container_cache(&snapshot.into())
        .map_err(|error| anyhow::anyhow!("adopt native AOT cache authority: {error}"))
}
// The native guest-memory model (NativeMappedMemory + handle/config, the
// exec-mapping machinery) and the bad64 fault-path emulation moved to
// `carrick_dsr_aarch64::{mapped_memory, emulate}` as the
// extraction-completing slice (see
// docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
// re-imported here so every existing unqualified call path resolves
// unchanged (`pub(crate)` because a handful of sibling runtime modules
// reach these items through `native_darwin::…`).
pub(crate) use carrick_dsr_aarch64::emulate::*;
pub(crate) use carrick_dsr_aarch64::mapped_memory::*;

use address::{NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE, NativeAddressMode};
// Test-only imports the lib half stopped needing when the memory model and
// translator moved to the arch crate (the JIT-entangled test suites below
// still build fixtures with them).
#[cfg(test)]
use crate::dispatch::MemoryLayout;
#[cfg(test)]
use crate::native_prepared_image::native_region_copy_window;
#[cfg(test)]
use address::NativeLayout;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

use std::io::Read;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::compat::{CompatReport, CompatReporter, SyscallArgs};
use crate::dispatch::{
    DispatchOutcome, GuestMemory, MemoryError, SyscallDispatcher, SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::native_prepared_image::{NativeRelativeRelocation, ValidatedPreparedImage};
use crate::page_profile::ExecutionPlan;
// Typed fork-lifecycle ordinals for THIS lane. The raw `role`/`phase` integers
// the `fork-lifecycle` USDT probe carries are produced only inside
// `probes::native_fork_lifecycle{,_as}`; nothing on the fork path names one.
use crate::probes::{
    NativeForkPhase, NativeForkRole, NativeSyscallBranchKind, NativeSyscallServiceOutcome,
};
use crate::runtime::{RunResult, RuntimeError, maybe_dump_debug_state};
use carrick_guest_mem::RepointPrivateError;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_hal::{
    ForkOutcome, RawSyscall, Reg, RegAccess, SysReg, SyscallTrap, TrapError, VcpuRegistry,
};
use goblin::elf::Elf;
use goblin::elf::header::ET_DYN;
use goblin::elf::reloc::{R_AARCH64_NONE, R_AARCH64_RELATIVE};
use sha2::Digest;

#[cfg(test)]
const SVC_0: u32 = 0xd400_0001;
const NATIVE_CTR_EL0: u64 = 0x8444_4004;
const NATIVE_DCZID_EL0: u64 = 0x4;
const NATIVE_DARWIN_PIE_BASE: u64 = 0x4_0000_0000;
// NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE and NATIVE_DARWIN_HARD_PAGEZERO_END
// moved to `carrick_dsr::address` with the address-layout machinery. The
// trampoline base is re-imported above so unqualified references here and
// the `use super::*` glob into `mapped_memory` keep resolving; the hard
// page-zero end is only referenced by the moved address code itself.
// The heap/mmap arena constants, the relocated vvar/vdso bases, and the
// NATIVE_FORKED_GUEST_CHILD process flag moved to
// `carrick_dsr_aarch64::mapped_memory` with the memory model; the re-import
// glob above keeps every unqualified reference here resolving.
// The native test failpoints/captures moved to `carrick_dsr::test_hooks`
// (cross-crate `cfg(test)` does not compose once mapped_memory.rs moves into
// carrick-dsr). The hook STATE compiles in for this crate's own test builds
// via the [dev-dependencies] re-declaration of carrick-dsr with
// `features = ["test-hooks"]` (cargo feature unification); production builds
// never enable the feature. The check sites below stay behind
// `cfg(any(test, feature = "test-hooks"))` so the same code also compiles
// when a downstream consumer opts into carrick-runtime's forwarding
// `test-hooks` feature. NOTE: `NATIVE_TEST_REEXEC_LIFECYCLE` now captures
// the seam phase enum (`carrick_dsr::probes::DsrCacheLifecyclePhase`), not
// the USDT mirror — `native_reexec_lifecycle` converts at the probe edge.
#[cfg(any(test, feature = "test-hooks"))]
use carrick_dsr::test_hooks::NATIVE_TEST_FAIL_EXEC_AFTER_SETUP;
#[cfg(any(test, feature = "test-hooks"))]
use carrick_dsr::test_hooks::NativePreparedMappingFailpoint;
#[cfg(test)]
use carrick_dsr::test_hooks::{
    set_native_prepared_mapping_failpoint, set_native_reexec_lifecycle_capture,
    set_native_test_vvar_words, take_native_reexec_lifecycle_capture,
    take_native_test_supplemental_rollbacks,
};

/// Set by the exec teardown at its success point (BEFORE it lowers the
/// transient exec-replacement owner), never cleared for the life of the
/// image: "a spawned thread's execve replaced (or is replacing) this
/// process's image". A NORMALLY-exited leader consults it after its
/// `join_spawned_threads` returns: the teardown's own join-take can empty
/// the shared handle vec (detaching the winner's handle) while the exited
/// leader is mid-take, and without this flag the leader fell into the
/// unconditional "thread group ended without a process exit" diagnostic and
/// exited the process under the running exec'd image (the lost-exec variant
/// via a normally-exited leader). Cleared in a fork CHILD (its image was not
/// exec-replaced; a stale flag would turn the child's diagnostic into a
/// silent park).
static NATIVE_IMAGE_REPLACED_BY_EXEC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Must an EXITED leader park forever instead of surfacing the
/// no-process-exit diagnostic? True while a sibling's execve owns the
/// replacement (transient owner flag) or once one has committed (durable
/// flag) — in both cases the exec'd thread owns the process and terminates
/// it via `_exit`; the leader erroring out would kill the image.
fn native_exited_leader_must_park(tid: crate::thread::ThreadId) -> bool {
    NATIVE_IMAGE_REPLACED_BY_EXEC.load(std::sync::atomic::Ordering::Acquire)
        || crate::fork_quiesce::exec_replacing_other_thread(tid)
}

// Moved verbatim to `carrick_dsr_aarch64::snapshot` as part of the staged
// native-backend extraction (the C mirror in carrick-native-darwin's
// csrc/native_darwin.c and the gateway offset asserts pin its layout);
// re-exported so the existing use sites and the C-mirror contract stay
// unchanged.
pub(crate) use carrick_dsr_aarch64::snapshot::NativeUcontextSnapshot;

type DsrPrepareFn = fn(
    &mut dsr::ThreadTranslator,
    &SharedNativeMemory,
    &NativeUcontextSnapshot,
) -> Result<dsr::PreparedEntry, RuntimeError>;
type DsrEnterFn = fn(
    &mut dsr::ThreadTranslator,
    dsr::PreparedEntry,
    &mut NativeUcontextSnapshot,
) -> Result<dsr::PreparedExit, RuntimeError>;
/// Blocked-wait accounting for one syscall dispatch: wall time inside blocked
/// wait segments and the thread CPU consumed inside those same segments
/// (`cpu_ns <= wall_ns` by construction; see `measure_native_blocked`).
#[derive(Clone, Copy, Debug, Default)]
struct NativeBlockedSpan {
    wall_ns: u64,
    cpu_ns: u64,
}

struct TimedDispatchOutcome {
    outcome: DispatchOutcome,
    blocked: NativeBlockedSpan,
}

struct NativeForkRequest {
    pidfd_out: Option<u64>,
    clone_parent: bool,
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    exit_signal: u32,
    child_stack: u64,
    vfork: Option<u64>,
    /// Guest PC and PSTATE at the fork-like syscall, carried in purely so the
    /// `fork-pre`/`fork-post` USDT bracket reports the same shape HVF does
    /// (`scripts/dtrace/fork-phases.d` reads them). The native lane has no EL1,
    /// so the probes' `elr` argument is reported as 0 and `cpsr` carries
    /// PSTATE.
    guest_pc: u64,
    guest_pstate: u64,
}

struct NativeVforkCompletion {
    fd: RawFd,
}

impl NativeVforkCompletion {
    fn notify(&mut self) {
        if self.fd < 0 {
            return;
        }
        let byte = [1_u8];
        let _ = unsafe { libc::write(self.fd, byte.as_ptr().cast(), byte.len()) };
        close_fd(self.fd);
        self.fd = -1;
    }
}

impl Drop for NativeVforkCompletion {
    fn drop(&mut self) {
        self.notify();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeWaitResult {
    Ready,
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSignalWaitResult {
    Ready,
    Interrupted,
    TimedOut,
}

struct NativeKickState {
    raw: NonNull<libc::c_void>,
}

// The pointed-to object is a C11 lock-free atomic state block. Its lifetime is
// owned by this wrapper and every mutation goes through the C helper API.
unsafe impl Send for NativeKickState {}
unsafe impl Sync for NativeKickState {}

impl NativeKickState {
    fn new() -> Result<Self, RuntimeError> {
        let raw = unsafe { carrick_native_kick_state_create() };
        let raw = NonNull::new(raw).ok_or_else(|| last_io_error("create native kick state"))?;
        Ok(Self { raw })
    }

    fn request(&self) -> bool {
        unsafe { carrick_native_kick_state_request(self.raw.as_ptr()) == 1 }
    }

    fn acknowledge(&self) {
        unsafe { carrick_native_kick_state_acknowledge(self.raw.as_ptr()) };
    }

    fn bind_current(&self) -> Result<(), RuntimeError> {
        if unsafe { carrick_native_kick_state_bind_current(self.raw.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(last_io_error("bind native kick state"))
        }
    }

    fn unbind_current(&self) {
        unsafe { carrick_native_kick_state_unbind_current(self.raw.as_ptr()) };
    }

    // Gated exactly like the C shim's test-only accessors they call (the
    // fail-closed complement declines to stub test-only entry points).
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    fn requested_generation(&self) -> u64 {
        unsafe { carrick_native_kick_state_requested(self.raw.as_ptr()) }
    }

    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    fn acknowledged_generation(&self) -> u64 {
        unsafe { carrick_native_kick_state_acknowledged(self.raw.as_ptr()) }
    }
}

impl Drop for NativeKickState {
    fn drop(&mut self) {
        unsafe { carrick_native_kick_state_destroy(self.raw.as_ptr()) };
    }
}

#[derive(Clone)]
struct NativeKickHandle {
    pthread: usize,
    state: Arc<NativeKickState>,
}

impl NativeKickHandle {
    fn for_current_thread(state: Arc<NativeKickState>) -> Self {
        Self {
            pthread: unsafe { libc::pthread_self() } as usize,
            state,
        }
    }
}

impl carrick_hal::VcpuKick for NativeKickHandle {
    fn kick(&self) {
        if !self.state.request() {
            return;
        }
        let rc = unsafe { libc::pthread_kill(self.pthread as libc::pthread_t, libc::SIGPIPE) };
        if rc != 0 {
            self.state.acknowledge();
        }
    }
}

/// The CURRENT native run loop's vCPU kick registry. Process-global so timer
/// fallback threads — whose `NativeTimerDelivery` handle is registered once in
/// the `timer_delivery` OnceLock and inherited across fork — always kick the
/// LIVE registry: `NativeThreadRuntime::new_current` installs it at boot and
/// again in a fork child (`reset_after_fork_child`).
///
/// FORK-SAFE BY CONSTRUCTION: this is a plain `AtomicPtr`, NOT a mutex. A
/// mutex here would be COW-inherited in a LOCKED state by a fork child
/// whenever some other parent thread (timer fire, child-exit publish) was
/// mid-`kick_all` at fork time, wedging the child's `new_current` reinstall
/// forever — the same fork×kick race class as the registry's own handles
/// mutex (see `NativeThreadRuntime::drop`). Installed registries are
/// intentionally never released (one small leak per boot/fork-child
/// install), which is exactly what lets readers use the raw pointer without
/// a load/free race.
static NATIVE_PROCESS_KICKER: std::sync::atomic::AtomicPtr<carrick_hal::GenericVcpuRegistry> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Publish `kicker` as THE process kick registry (boot + fork-child reset).
/// The previous registry (if any) is deliberately leaked — a kicker thread
/// may hold a reference to it right now, and the bounded leak (one per
/// install) is what makes the reader side lock-free and fork-safe.
fn install_native_process_kicker(kicker: &Arc<carrick_hal::GenericVcpuRegistry>) {
    let raw = Arc::into_raw(Arc::clone(kicker)).cast_mut();
    let _leaked_previous = NATIVE_PROCESS_KICKER.swap(raw, std::sync::atomic::Ordering::AcqRel);
}

fn kick_all_native_guest_threads() {
    let raw = NATIVE_PROCESS_KICKER.load(std::sync::atomic::Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: pointers installed by `install_native_process_kicker` come from
    // `Arc::into_raw` and are never released (leak-on-replace), so the
    // registry outlives every reader.
    let kicker = unsafe { &*raw };
    use carrick_hal::VcpuRegistry as _;
    kicker.kick_all();
}

/// Complete a native asynchronous-interrupt publication. Pending state MUST be
/// durable before this function runs: the futex generation closes the
/// predicate-to-park registration window, then the host kick pulls threads out
/// of translated guest code. Reversing that order can lose both one-shot edges.
fn wake_all_native_guest_threads_after_interrupt_publication() {
    crate::thread::notify_current_futex_signal_pending();
    kick_all_native_guest_threads();
}

/// Publish a thread-directed signal from a native helper/dispatch path whose
/// producer may be running concurrently with the target's private-futex park.
/// This is deliberately process-wide at the wake layer: these out-of-band
/// producers do not retain the target's `NativeThreadRuntime`, while spurious
/// sibling predicate rechecks are harmless.
pub(crate) fn publish_native_pending_for(target_tid: i32, signum: i32) {
    crate::host_signal::publish_pending_for_with_wake(
        target_tid,
        signum,
        crate::host_signal::PublicationWake::CallerManaged,
    );
    wake_all_native_guest_threads_after_interrupt_publication();
}

/// Deliver a process-directed timer signal to a native guest: publish into the
/// shared pending mask, then kick every native guest thread so the run loop's
/// kick path (`resume_guest_after_kick` → `deliver_pending_signal`) injects it.
/// HVF event producers delegate their kick to the full signal pump. Native's
/// wake-only pump is reserved for external host/xsignal ingress, so a native
/// timer uses caller-managed publication and exactly one ordered direct kick.
/// A spinning guest that never traps (vDSO clock reads satisfy its spin loop in
/// userspace) would otherwise never observe the signal.
pub(crate) fn deliver_native_process_signal(signum: i32) {
    crate::host_signal::publish_process_signal_with_wake(
        signum,
        crate::host_signal::PublicationWake::CallerManaged,
    );
    wake_all_native_guest_threads_after_interrupt_publication();
}

/// Native child-exit watch glue. HVF arms `EVFILT_PROC`/`NOTE_EXIT` on its
/// signal-pump kqueue and KVM's pump reaper peeks tracked pids; the native
/// backend has neither, so a lazily started per-process watcher thread owns
/// the equivalent kqueue. Without it, child-exit signals were only discovered
/// by `native_poll_child_exit_watches` INSIDE wait-type syscalls — a parent
/// SPINNING in guest code (its clock reads satisfied by the vDSO, so no trap
/// ever happens) never observed SIGCHLD for an exited child (`sigchld`
/// probe: `sigchld_handler_ran=false`).
///
/// The kqueue fd is stamped with its owner pid: threads (and kqueue
/// registrations) do not survive `fork`, so a fork child's first
/// `native_register_child_exit_watch` observes the pid mismatch and starts a
/// fresh watcher. The neutral watch table itself was already cleared by
/// `host_signal::reinit_after_fork`.
static NATIVE_CHILD_WATCH_KQ: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static NATIVE_CHILD_WATCH_OWNER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
static NATIVE_CHILD_WATCH_SPAWN: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// The watcher's kqueue for THIS process, starting the watcher thread on first
/// use (and again after fork, keyed by owner pid). `None` if the kqueue or the
/// thread could not be created — callers fall back to the wait-path polling.
fn ensure_native_child_watcher() -> Option<RawFd> {
    use std::sync::atomic::Ordering;
    let self_pid = std::process::id();
    let fd = NATIVE_CHILD_WATCH_KQ.load(Ordering::Acquire);
    if fd >= 0 && NATIVE_CHILD_WATCH_OWNER.load(Ordering::Acquire) == self_pid {
        return Some(fd);
    }
    let _spawn_guard = NATIVE_CHILD_WATCH_SPAWN.lock();
    let fd = NATIVE_CHILD_WATCH_KQ.load(Ordering::Acquire);
    if fd >= 0 && NATIVE_CHILD_WATCH_OWNER.load(Ordering::Acquire) == self_pid {
        return Some(fd);
    }
    let kq = carrick_host_bsd::kqueue::Kqueue::new_internal()?;
    let raw = kq.raw_fd();
    let spawned = thread::Builder::new()
        .name("carrick-native-childwatch".to_string())
        .spawn(move || run_native_child_watcher(kq))
        .is_ok();
    if !spawned {
        return None;
    }
    // A stale parent fd number may linger here after fork (kqueues are not
    // inherited); the number was already dead, so overwriting loses nothing.
    NATIVE_CHILD_WATCH_KQ.store(raw, Ordering::Release);
    NATIVE_CHILD_WATCH_OWNER.store(self_pid, Ordering::Release);
    Some(raw)
}

fn run_native_child_watcher(kq: carrick_host_bsd::kqueue::Kqueue) {
    use std::sync::atomic::Ordering;
    let raw = kq.raw_fd();
    let mut events = [carrick_host_bsd::kqueue::Kevent::empty(); 8];
    loop {
        match kq.wait(&[], &mut events, None) {
            Ok(n) => {
                for event in events.iter().take(n) {
                    let Some(child) = event.proc_exit_ident() else {
                        continue;
                    };
                    native_publish_child_exit(child);
                }
            }
            Err(errno) if errno == libc::EINTR => {}
            // EBADF: the fd was torn down (process exit teardown); anything
            // else is equally unrecoverable for this watcher. The wait-path
            // polling remains as the delivery backstop.
            Err(_) => break,
        }
    }
    // Un-publish this watcher's fd BEFORE the owned kqueue drops (closing it),
    // so the next arm respawns a fresh watcher instead of hitting EBADF on a
    // lingering number. Compare-exchange: if a concurrent EBADF-arm already
    // forgot us (or a respawned watcher reused the number), leave it alone —
    // the worst outcome is one redundant respawn, never a lost publish.
    let _ = NATIVE_CHILD_WATCH_KQ.compare_exchange(raw, -1, Ordering::AcqRel, Ordering::Acquire);
}

/// Resolve a child's exit against the neutral watch table and deliver the
/// requested clone exit signal to the recorded parent tid: publish + kick-all,
/// the same shape as `deliver_native_process_signal` (the parent may be
/// spinning in guest code with no dispatch edge to piggyback on). `take` is the
/// publish-once guard against wait4's synchronous terminal-reap cancel.
fn native_publish_child_exit(child: i32) {
    let Some((parent_tid, exit_signal)) = crate::host_signal::take_child_exit_parent(child) else {
        return;
    };
    if exit_signal != 0 {
        publish_native_pending_for(parent_tid, exit_signal);
    } else {
        kick_all_native_guest_threads();
    }
}

/// Native `TimerDelivery`: the wake-only signal pump does not register timer
/// knotes, so every interval timer runs the SHARED timer-core timing loop on a
/// fallback thread — wall-clock sleeps for `ITIMER_REAL`, guest-CPU polling
/// against the native Darwin CPU provider for `ITIMER_VIRTUAL`/`ITIMER_PROF` —
/// whose fire action is publish + kick-all. POSIX per-process timers mirror the
/// KVM/bhyve/NVMM fallback shape with the same native fire action. Stateless:
/// the kicker is resolved at fire time from `NATIVE_PROCESS_KICKER`.
struct NativeTimerDelivery;

impl carrick_hal::TimerDelivery for NativeTimerDelivery {
    fn arm_itimer(
        &self,
        which: usize,
        spec: carrick_hal::TimerSpecNs,
        _needs_periodic: bool,
        signum: i32,
    ) -> bool {
        // The dispatch arm wrote the neutral slot (itimer::arm) immediately
        // before this call; its generation retires this thread on re-arm/disarm.
        let generation = crate::itimer::generation(which);
        let _ = thread::Builder::new()
            .name(format!("carrick-native-itimer-{which}"))
            .spawn(move || {
                crate::itimer::run_fallback(which, generation, spec, || {
                    crate::probes::itimer_fire(signum, 1);
                    deliver_native_process_signal(signum);
                });
            });
        true
    }

    fn disarm_itimer(&self, which: usize) {
        crate::itimer::disarm(which);
    }

    fn arm_posix(
        &self,
        id: i32,
        spec: carrick_hal::TimerSpecNs,
    ) -> Option<carrick_hal::PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let _ = thread::Builder::new()
                .name(format!("carrick-native-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback(slot, generation, spec, move || {
                        deliver_native_process_signal(signum);
                    });
                });
        }
        Some(armed.old)
    }

    fn disarm_posix(&self, id: i32) {
        let _ = carrick_timer_core::posix::arm(id, carrick_hal::TimerSpecNs::DISARM);
    }

    fn current_arm(&self, which: usize) -> Option<carrick_hal::TimerArm> {
        crate::itimer::current_arm(which)
    }
}

// The C trap/kick shim (`carrick-native-darwin/csrc/native_darwin.c`, moved
// there from this crate as M0.6 of the seams design) is genuinely
// Darwin+aarch64: x18 guest-ABI switching, `__darwin_mcontext64` snapshots,
// and the MAP_JIT cache bounds all live there, and that crate's build.rs
// only compiles it for that target. The static library it produces is
// linked into this crate transitively through the `carrick-native-darwin`
// dependency (Cargo propagates a dependency's build-script link directives
// to every consumer), so these extern declarations still resolve unchanged.
// (`carrick_native_clear_icache` is NOT declared here any more: `flush_icache`
// moved to `carrick_native_darwin::jit::DarwinHostJit`, which binds it
// directly — see that crate's `src/jit.rs`.)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe extern "C" {
    fn carrick_native_install_dsr_signal_handlers() -> libc::c_int;
    #[cfg(test)]
    fn carrick_native_unblock_transport_signals() -> libc::c_int;
    fn carrick_native_kick_state_create() -> *mut libc::c_void;
    fn carrick_native_kick_state_destroy(state: *mut libc::c_void);
    fn carrick_native_kick_state_request(state: *mut libc::c_void) -> libc::c_int;
    fn carrick_native_kick_state_acknowledge(state: *mut libc::c_void);
    fn carrick_native_kick_state_bind_current(state: *mut libc::c_void) -> libc::c_int;
    fn carrick_native_kick_state_unbind_current(state: *mut libc::c_void);
    #[cfg(test)]
    fn carrick_native_kick_state_requested(state: *mut libc::c_void) -> u64;
    #[cfg(test)]
    fn carrick_native_kick_state_acknowledged(state: *mut libc::c_void) -> u64;
    #[cfg(test)]
    fn carrick_native_dsr_enter_guest_abi(context: *mut libc::c_void) -> libc::c_int;
    #[cfg(test)]
    fn carrick_native_dsr_enter_host_abi();
    #[cfg(test)]
    fn carrick_native_dsr_benchmark_signal_mask_pair() -> libc::c_int;
    #[cfg(test)]
    fn carrick_native_dsr_benchmark_custom_x18_pair() -> libc::c_int;
}

// FAIL-CLOSED complement of the Darwin C shim (M1 item: the per-host native
// shim crates — carrick-native-darwin / carrick-native-freebsd, M0.6/M0.7 —
// replace these). Same names and signatures so every call site compiles
// unchanged; every entry answers "this host has no native trap/kick shim yet":
//   * handler install reports failure (callers surface a typed install error
//     and the native run loop refuses to start — nothing silently runs a
//     guest without trap handlers);
//   * kick-state creation returns null (surfaces as a create error before any
//     guest thread can rely on a kick that would never arrive);
//   * the remaining entries are unreachable by construction (they all require
//     a state pointer only a successful create can produce) and abort loudly
//     rather than pretend to act.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod native_shim_fail_closed {
    /// No shim: report failure so `prepare_kick_target` / the DSR run paths
    /// error out instead of running a guest without trap handlers.
    pub(super) unsafe fn carrick_native_install_dsr_signal_handlers() -> libc::c_int {
        1
    }

    /// No shim: a null state makes `NativeKickState::new` fail closed.
    pub(super) unsafe fn carrick_native_kick_state_create() -> *mut libc::c_void {
        std::ptr::null_mut()
    }

    pub(super) unsafe fn carrick_native_kick_state_destroy(_state: *mut libc::c_void) {
        unreachable!("native kick state cannot exist without a host shim");
    }

    pub(super) unsafe fn carrick_native_kick_state_request(
        _state: *mut libc::c_void,
    ) -> libc::c_int {
        unreachable!("native kick state cannot exist without a host shim");
    }

    pub(super) unsafe fn carrick_native_kick_state_acknowledge(_state: *mut libc::c_void) {
        unreachable!("native kick state cannot exist without a host shim");
    }

    pub(super) unsafe fn carrick_native_kick_state_bind_current(
        _state: *mut libc::c_void,
    ) -> libc::c_int {
        unreachable!("native kick state cannot exist without a host shim");
    }

    pub(super) unsafe fn carrick_native_kick_state_unbind_current(_state: *mut libc::c_void) {
        unreachable!("native kick state cannot exist without a host shim");
    }
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use native_shim_fail_closed::*;

// Reachable only through the macOS `runtime`/`execute` arms today; the native
// run path is wired into the non-macOS arms in M0.8 (native/ integration), at
// which point these `cfg_attr(dead_code)` allowances come off.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
pub(crate) fn run_static_elf<A, E>(
    path: &Path,
    mut dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    install_native_probe_sink();
    let Some(geometry) = plan.page_geometry.native_geometry() else {
        return Err(RuntimeError::Unsupported(
            "native Darwin run-elf selected without native page geometry".to_string(),
        ));
    };

    dispatcher.set_page_geometry(plan.page_geometry);
    dispatcher.set_execution_backend(plan.backend);
    dispatcher.set_memory_layout(native_memory_layout());
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let identity = argv
        .first()
        .cloned()
        .unwrap_or_else(|| canonical_host_executable_path(path));
    dispatcher.set_executable_identity(
        identity,
        argv.clone(),
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );

    let file = std::fs::read(path).map_err(AddressSpaceError::Io)?;
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|p| {
            dispatcher
                .read_exec_file(p)
                .or_else(|| std::fs::read(p).ok())
        },
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )?
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug())
    .without_auxv_hwcap(
        carrick_abi::LinuxAarch64Hwcap::SHA2 | carrick_abi::LinuxAarch64Hwcap::ATOMICS,
    );
    // Same vDSO image + debug-mode selection as the HVF boot/execve builders,
    // relocated to the native-mappable bases (`NATIVE_DARWIN_VVAR_BASE`).
    // `NativeMappedMemory::map` rewrites the code page's vvar loads and stamps
    // the vvar data page.
    let image = with_native_vdso(image)?.with_linux_initial_stack_page_size(
        argv,
        env,
        geometry.linux_page_size,
    )?;
    maybe_dump_debug_state(&image, debug_state_path);

    run_image_in_child(
        image,
        canonical_host_executable_path(path),
        dispatcher,
        max_traps,
        relative_relocations,
        plan,
    )
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
pub(crate) fn run_elf_from_dispatcher_debug<A, E>(
    path: &str,
    mut dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    install_native_probe_sink();
    let Some(geometry) = plan.page_geometry.native_geometry() else {
        return Err(RuntimeError::Unsupported(
            "native Darwin container launch selected without native page geometry".to_string(),
        ));
    };

    dispatcher.set_page_geometry(plan.page_geometry);
    dispatcher.set_execution_backend(plan.backend);
    dispatcher.set_memory_layout(native_memory_layout());
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let argv_for_cmdline = argv.clone();
    let argv_bytes = argv.into_iter().map(String::into_bytes).collect();
    let (resolved, argv) =
        crate::exec_helpers::resolve_entrypoint_program(path, &env, argv_bytes, &dispatcher)
            .map_err(|_| {
                RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    path.to_owned(),
                )))
            })?;
    dispatcher.set_executable_identity(
        resolved.clone(),
        argv_for_cmdline,
        env.iter().map(|value| value.as_bytes().to_vec()).collect(),
    );
    let file = dispatcher.read_exec_file(&resolved).ok_or_else(|| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            resolved.clone(),
        )))
    })?;
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|interpreter| dispatcher.read_exec_file(interpreter),
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )?
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug())
    .without_auxv_hwcap(
        carrick_abi::LinuxAarch64Hwcap::SHA2 | carrick_abi::LinuxAarch64Hwcap::ATOMICS,
    );
    let image = with_native_vdso(image)?.with_linux_initial_stack_page_size(
        argv,
        env,
        geometry.linux_page_size,
    )?;
    maybe_dump_debug_state(&image, debug_state_path);

    run_image_in_child(
        image,
        resolved,
        dispatcher,
        max_traps,
        relative_relocations,
        plan,
    )
}

type LoadedNativeExecveImage = (
    AddressSpace,
    Vec<NativeRelativeRelocation>,
    String,
    Vec<Vec<u8>>,
    [u8; 32],
);

enum NativeImageSource {
    Legacy {
        image: AddressSpace,
        relative_relocations: Vec<NativeRelativeRelocation>,
    },
    Prepared(ValidatedPreparedImage),
}

impl NativeImageSource {
    fn image(&self) -> &AddressSpace {
        match self {
            Self::Legacy { image, .. } => image,
            Self::Prepared(prepared) => &prepared.image,
        }
    }

    fn into_image(self) -> AddressSpace {
        match self {
            Self::Legacy { image, .. } => image,
            Self::Prepared(prepared) => prepared.into_image(),
        }
    }
}

struct ResumedImage {
    source: NativeImageSource,
    legacy_resolved_path: Option<String>,
}

impl ResumedImage {
    fn into_handoff(
        self,
        prepared_resolved_path: String,
    ) -> (NativeImageSource, NativeGuestImageCompatibility) {
        let resolved_path = self.legacy_resolved_path.unwrap_or(prepared_resolved_path);
        let guest_image =
            NativeGuestImageCompatibility::from_image(self.source.image(), resolved_path);
        (self.source, guest_image)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NativeGuestImageCompatibility {
    base: u64,
    entry: u64,
    resolved_path: crate::probes::PreparedGuestImagePath,
}

impl NativeGuestImageCompatibility {
    fn from_image(image: &AddressSpace, resolved_path: impl Into<String>) -> Self {
        Self {
            base: image
                .regions()
                .iter()
                .map(|region| region.start)
                .min()
                .unwrap_or(0),
            entry: image.entry(),
            resolved_path: crate::probes::prepare_guest_image_path(resolved_path.into()),
        }
    }
}

fn select_resumed_image<F>(
    prepared_image: Option<crate::native_prepared_image::NativePreparedImageV1>,
    expected_executable_digest: [u8; 32],
    legacy_loader: F,
) -> anyhow::Result<ResumedImage>
where
    F: FnOnce() -> Result<LoadedNativeExecveImage, crate::linux_abi::LinuxErrno>,
{
    if let Some(record) = prepared_image {
        native_reexec_lifecycle(
            carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateBegin,
        );
        let prepared = crate::native_prepared_image::validate_for_resume(record).map_err(
            |error| match error {
                crate::native_prepared_image::NativePreparedImageError::ChecksumMismatch {
                    ..
                } => anyhow::anyhow!("prepared-validate: checksum mismatch"),
                error => anyhow::anyhow!("prepared-validate: {error}"),
            },
        )?;
        native_reexec_lifecycle(
            carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateEnd,
        );
        return Ok(ResumedImage {
            source: NativeImageSource::Prepared(prepared),
            legacy_resolved_path: None,
        });
    }

    let (image, relative_relocations, resolved, _resolved_argv, executable_digest) =
        legacy_loader()
            .map_err(|errno| anyhow::anyhow!("reload guest executable failed: {errno:?}"))?;
    if executable_digest != expected_executable_digest {
        anyhow::bail!("guest executable changed across native host self-reexec");
    }
    Ok(ResumedImage {
        source: NativeImageSource::Legacy {
            image,
            relative_relocations,
        },
        legacy_resolved_path: Some(resolved),
    })
}

fn load_native_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    plan: &ExecutionPlan,
) -> Result<LoadedNativeExecveImage, crate::linux_abi::LinuxErrno> {
    let geometry = plan
        .page_geometry
        .native_geometry()
        .ok_or(crate::linux_abi::LINUX_ENOEXEC)?;
    let argv = if argv.is_empty() {
        vec![path.as_bytes().to_vec()]
    } else {
        argv
    };
    let absolute = dispatcher.resolve_exec_path(path);
    dispatcher.check_exec_target(&absolute)?;
    let (resolved, argv) = crate::exec_helpers::resolve_shebang(dispatcher, absolute, argv)?;
    let host_fallback = dispatcher.exec_host_fs_fallback();
    let host_read = |candidate: &str| {
        if host_fallback {
            std::fs::read(candidate).ok()
        } else {
            None
        }
    };
    let file = dispatcher
        .read_exec_file(&resolved)
        .or_else(|| host_read(&resolved))
        .ok_or(crate::linux_abi::LINUX_ENOENT)?;
    let executable_digest: [u8; 32] = sha2::Sha256::digest(&file).into();
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)
        .map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|interpreter| {
            dispatcher
                .read_exec_file(interpreter)
                .or_else(|| host_read(interpreter))
        },
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )
    .map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug())
    .without_auxv_hwcap(
        carrick_abi::LinuxAarch64Hwcap::SHA2 | carrick_abi::LinuxAarch64Hwcap::ATOMICS,
    );
    // Mirror the HVF execve builder: the replacement image carries fresh
    // vvar/vdso regions; `replace_image` → `NativeMappedMemory::map` re-stamps
    // the vvar for the new image.
    // A fork-child host self-reexec must carry the argv after shebang
    // resolution. Carrying the original script argv alongside the resolved
    // interpreter path resumes `/bin/sh` with the script as argv[0] but no
    // script operand, so the shell goes interactive on stdin.
    let resolved_argv = argv.clone();
    let image = with_native_vdso(image)
        .map_err(|_| crate::linux_abi::LINUX_ENOENT)?
        .with_linux_initial_stack_execfn_page_size(
            argv,
            env,
            resolved.as_bytes(),
            geometry.linux_page_size,
        )
        .map_err(|_| crate::linux_abi::LINUX_ENOENT)?;
    Ok((
        image,
        relative_relocations,
        resolved,
        resolved_argv,
        executable_digest,
    ))
}

pub(crate) fn resume_guest_from_capsule(
    mut guest: crate::native_exec_capsule::NativeGuestExecV1,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
) -> anyhow::Result<i32> {
    install_native_probe_sink();
    dsr::profile::seed_profile_exec_epoch_after_reexec(guest.profile_exec_epoch);
    // Startup attribution across the PID-preserving host self-reexec: the
    // pid's startup window was captured exactly once in the pre-exec image,
    // so republish that claim verbatim (one pid, one gauge). Without an
    // inherited claim, measure from this post-exec runtime entry instead.
    match guest.profile_startup {
        Some(startup) => {
            dsr::profile::seed_claimed_process_startup(
                startup.startup_wall_ns,
                startup.startup_cpu_ns,
            );
        }
        None => dsr::profile::mark_native_process_runtime_entry(),
    }
    // Thread CPU attribution across the same boundary: real execve keeps the
    // calling thread's kernel CPU accounting intact (unlike fork, which
    // starts a fresh thread at zero), so the ONE surviving thread's post-exec
    // era must subtract a baseline captured here — otherwise its flush
    // double-counts the CPU the pre-exec era already reported.
    dsr::profile::install_surviving_thread_cpu_baseline_at_reexec_entry();
    if let Some(arena) = guest.kernel_arena {
        carrick_kernel::arena::KernelArena::init_global_from_reexec(
            carrick_kernel::arena::KernelArenaReexecAuthority {
                fd: arena.host_fd,
                original_fd_flags: arena.original_host_fd_flags,
                device: arena.host_device,
                inode: arena.host_inode,
                size: arena.host_size,
            },
        )
        .map_err(|error| anyhow::anyhow!("restore native kernel arena: {error}"))?;
    }
    if let Some(waiters) = guest.shared_futex_waiters {
        crate::ulock::init_waiter_table_from_reexec(crate::ulock::WaiterTableReexecAuthority {
            fd: waiters.host_fd,
            original_fd_flags: waiters.original_host_fd_flags,
            device: waiters.host_device,
            inode: waiters.host_inode,
            size: waiters.host_size,
        })
        .map_err(|error| anyhow::anyhow!("restore native shared futex waiters: {error}"))?;
    }
    let max_traps = usize::try_from(guest.max_traps)?;
    let plan = crate::page_profile::resolve_execution_plan_for_request(
        carrick_spec::Platform::host_native(),
        carrick_spec::ExecBackendRequest::Native,
        guest.native_page_profile,
    )?;
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_page_geometry(plan.page_geometry);
    dispatcher.set_execution_backend(plan.backend);
    dispatcher.set_memory_layout(native_memory_layout());
    let backend = crate::fs_backend::HostFsBackend::attach_for_reexec(&guest.rootfs)?;
    let _ = dispatcher.set_fs_backend(Box::new(backend));
    dispatcher.restore_native_reexec_bind_mounts(&guest.bind_mounts);
    if !guest.exec_host_fs_fallback {
        dispatcher.sandbox_exec_to_container();
    }
    dispatcher.set_cwd(&guest.cwd);
    dispatcher.set_stream_stdio(guest.stream_stdio);
    dispatcher.restore_native_reexec_process_state(&guest.process_state);
    if guest.process_state.ptrace_traceme != crate::guest_cpu::self_is_virtual_ptrace_tracee() {
        anyhow::bail!("native self-reexec ptrace state disagrees with the inherited kernel arena");
    }
    dispatcher
        .restore_native_reexec_fd_table(&guest.fd_table)
        .map_err(|error| anyhow::anyhow!("restore native guest fd table: {error}"))?;
    native_reexec_lifecycle(
        carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecDispatcherReady,
    );
    let prepared_image = guest.prepared_image.take();
    let executable_digest = guest.executable_digest;
    let resumed = select_resumed_image(prepared_image, executable_digest, || {
        native_reexec_lifecycle(
            carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecImageLoadBegin,
        );
        let loaded = load_native_execve_image(
            &dispatcher,
            &guest.resolved_path,
            argv.clone(),
            env.clone(),
            &plan,
        );
        if loaded.is_ok() {
            native_reexec_lifecycle(
                carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecImageLoadEnd,
            );
        }
        loaded
    })?;
    let (source, guest_image) = resumed.into_handoff(guest.resolved_path);
    let resolved = guest_image.resolved_path.as_str().to_owned();
    native_reexec_lifecycle(carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecResetBegin);
    dispatcher.reset_memory_state_on_execve();
    dispatcher.reset_signal_handlers_on_execve();
    dispatcher.set_executable_identity(
        resolved,
        argv.iter()
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect(),
        env,
    );
    run_image_in_current_process(
        source,
        Some(executable_digest),
        dispatcher,
        max_traps,
        &plan,
        NativeCurrentProcessEntry::SelfReexecRestore,
        guest_image,
    )
    .map_err(anyhow::Error::from)
}

/// The claimed process startup gauge, exposed for the self-reexec capsule
/// producer so the post-exec image of the SAME pid republishes it verbatim.
pub(crate) fn claimed_native_process_startup() -> Option<(u64, u64)> {
    dsr::profile::claimed_process_startup()
}

pub(crate) fn next_native_profile_exec_epoch_for_reexec() -> u64 {
    dsr::profile::next_profile_exec_epoch_for_reexec()
}

// `native_reexec_lifecycle` and `native_memory_layout` moved to
// `carrick_dsr_aarch64::mapped_memory` (re-imported above); the lifecycle
// probe now reaches the USDT provider through the seam sink below.

/// Forwarder behind `carrick_dsr::probes` — the usdt-free probe seam the
/// extracted DSR code fires through — onto the real
/// `carrick-observability` USDT probes. The mirrored enums map 1:1; both
/// matches are exhaustive on BOTH sides (every observability variant appears
/// exactly once on a right-hand side), so adding a variant to either enum
/// alone breaks this build instead of silently dropping or skewing probes.
struct NativeDsrProbeForwarder;

fn native_dsr_lifecycle_phase(
    phase: carrick_dsr::probes::DsrCacheLifecyclePhase,
) -> crate::probes::DsrCacheLifecyclePhase {
    use crate::probes::DsrCacheLifecyclePhase as Usdt;
    use carrick_dsr::probes::DsrCacheLifecyclePhase as Seam;
    match phase {
        Seam::ForkChildRepairBegin => Usdt::ForkChildRepairBegin,
        Seam::ForkChildRepairEnd => Usdt::ForkChildRepairEnd,
        Seam::ExecResetBegin => Usdt::ExecResetBegin,
        Seam::ExecResetEnd => Usdt::ExecResetEnd,
        Seam::ExecImageUnmapBegin => Usdt::ExecImageUnmapBegin,
        Seam::ExecImageUnmapEnd => Usdt::ExecImageUnmapEnd,
        Seam::ExecImageMapBegin => Usdt::ExecImageMapBegin,
        Seam::ExecImageMapEnd => Usdt::ExecImageMapEnd,
        Seam::ExecCacheResetBegin => Usdt::ExecCacheResetBegin,
        Seam::ExecCacheResetEnd => Usdt::ExecCacheResetEnd,
        Seam::ExecRelocationBegin => Usdt::ExecRelocationBegin,
        Seam::ExecRelocationEnd => Usdt::ExecRelocationEnd,
        Seam::ExecTranslatorHandoffBegin => Usdt::ExecTranslatorHandoffBegin,
        Seam::ExecTranslatorHandoffEnd => Usdt::ExecTranslatorHandoffEnd,
        Seam::ExecMapMmapBegin => Usdt::ExecMapMmapBegin,
        Seam::ExecMapMmapEnd => Usdt::ExecMapMmapEnd,
        Seam::ExecMapCopyBegin => Usdt::ExecMapCopyBegin,
        Seam::ExecMapCopyEnd => Usdt::ExecMapCopyEnd,
        Seam::ExecMapIcacheBegin => Usdt::ExecMapIcacheBegin,
        Seam::ExecMapIcacheEnd => Usdt::ExecMapIcacheEnd,
        Seam::ExecMapProtectBegin => Usdt::ExecMapProtectBegin,
        Seam::ExecMapProtectEnd => Usdt::ExecMapProtectEnd,
        Seam::ExecMapVvarBegin => Usdt::ExecMapVvarBegin,
        Seam::ExecMapVvarEnd => Usdt::ExecMapVvarEnd,
        Seam::HostSelfReexecBegin => Usdt::HostSelfReexecBegin,
        Seam::HostSelfReexecEnd => Usdt::HostSelfReexecEnd,
        Seam::HostSelfReexecProbesReady => Usdt::HostSelfReexecProbesReady,
        Seam::HostSelfReexecCapsuleBegin => Usdt::HostSelfReexecCapsuleBegin,
        Seam::HostSelfReexecCapsuleEnd => Usdt::HostSelfReexecCapsuleEnd,
        Seam::HostSelfReexecRestoreBegin => Usdt::HostSelfReexecRestoreBegin,
        Seam::HostSelfReexecDispatcherReady => Usdt::HostSelfReexecDispatcherReady,
        Seam::HostSelfReexecImageLoadBegin => Usdt::HostSelfReexecImageLoadBegin,
        Seam::HostSelfReexecImageLoadEnd => Usdt::HostSelfReexecImageLoadEnd,
        Seam::HostSelfReexecResetBegin => Usdt::HostSelfReexecResetBegin,
        Seam::HostSelfReexecResetEnd => Usdt::HostSelfReexecResetEnd,
        Seam::HostSelfReexecGuestEntry => Usdt::HostSelfReexecGuestEntry,
        Seam::HostSelfReexecPreflightBegin => Usdt::HostSelfReexecPreflightBegin,
        Seam::HostSelfReexecCapsulePrepareBegin => Usdt::HostSelfReexecCapsulePrepareBegin,
        Seam::HostSelfReexecPreparedBuildBegin => Usdt::HostSelfReexecPreparedBuildBegin,
        Seam::HostSelfReexecPreparedBuildEnd => Usdt::HostSelfReexecPreparedBuildEnd,
        Seam::HostSelfReexecPreparedValidateBegin => Usdt::HostSelfReexecPreparedValidateBegin,
        Seam::HostSelfReexecPreparedValidateEnd => Usdt::HostSelfReexecPreparedValidateEnd,
        Seam::HostSelfReexecPreparedMapBegin => Usdt::HostSelfReexecPreparedMapBegin,
        Seam::HostSelfReexecPreparedMapEnd => Usdt::HostSelfReexecPreparedMapEnd,
    }
}

fn native_dsr_exec_map_detail_kind(
    kind: carrick_dsr::probes::DsrExecMapDetailKind,
) -> crate::probes::DsrExecMapDetailKind {
    use crate::probes::DsrExecMapDetailKind as Usdt;
    use carrick_dsr::probes::DsrExecMapDetailKind as Seam;
    match kind {
        Seam::Mmap => Usdt::Mmap,
        Seam::Copy => Usdt::Copy,
        Seam::Icache => Usdt::Icache,
        Seam::Protect => Usdt::Protect,
        Seam::Vvar => Usdt::Vvar,
    }
}

fn native_dsr_exit_kind(kind: carrick_dsr::probes::DsrExitKind) -> crate::probes::DsrExitKind {
    use crate::probes::DsrExitKind as Usdt;
    use carrick_dsr::probes::DsrExitKind as Seam;
    match kind {
        Seam::Syscall => Usdt::Syscall,
        Seam::DirectResolver => Usdt::DirectResolver,
        Seam::IndirectResolver => Usdt::IndirectResolver,
        Seam::Fault => Usdt::Fault,
        Seam::Kick => Usdt::Kick,
        Seam::Sensitive => Usdt::Sensitive,
        Seam::Unsupported => Usdt::Unsupported,
    }
}

fn native_dsr_prepare_outcome(
    outcome: carrick_dsr::probes::DsrPrepareOutcome,
) -> crate::probes::DsrPrepareOutcome {
    use crate::probes::DsrPrepareOutcome as Usdt;
    use carrick_dsr::probes::DsrPrepareOutcome as Seam;
    match outcome {
        Seam::ResumeEntryHit => Usdt::ResumeEntryHit,
        Seam::BlockIndexHit => Usdt::BlockIndexHit,
        Seam::Translated => Usdt::Translated,
        Seam::Failed => Usdt::Failed,
    }
}

fn native_dsr_operation_outcome(
    outcome: carrick_dsr::probes::DsrOperationOutcome,
) -> crate::probes::DsrOperationOutcome {
    use crate::probes::DsrOperationOutcome as Usdt;
    use carrick_dsr::probes::DsrOperationOutcome as Seam;
    match outcome {
        Seam::Success => Usdt::Success,
        Seam::PcOverflow => Usdt::PcOverflow,
        Seam::Decode => Usdt::Decode,
        Seam::Malformed => Usdt::Malformed,
        Seam::BlockPolicy => Usdt::BlockPolicy,
        Seam::MemoryRead => Usdt::MemoryRead,
        Seam::UnsupportedBlockAction => Usdt::UnsupportedBlockAction,
        Seam::Assembler => Usdt::Assembler,
        Seam::Gateway => Usdt::Gateway,
        Seam::CachePolicy => Usdt::CachePolicy,
        Seam::GenerationChanged => Usdt::GenerationChanged,
        Seam::Host => Usdt::Host,
        Seam::CacheCapacity => Usdt::CacheCapacity,
        Seam::InvalidTarget => Usdt::InvalidTarget,
    }
}

fn native_dsr_resolve_kind(
    kind: carrick_dsr::probes::DsrResolveKind,
) -> crate::probes::DsrResolveKind {
    use crate::probes::DsrResolveKind as Usdt;
    use carrick_dsr::probes::DsrResolveKind as Seam;
    match kind {
        Seam::Direct => Usdt::Direct,
        Seam::Indirect => Usdt::Indirect,
    }
}

fn native_dsr_cache_event_kind(
    kind: carrick_dsr::probes::DsrCacheEventKind,
) -> crate::probes::DsrCacheEventKind {
    use crate::probes::DsrCacheEventKind as Usdt;
    use carrick_dsr::probes::DsrCacheEventKind as Seam;
    match kind {
        Seam::BlockHit => Usdt::BlockHit,
        Seam::BlockMiss => Usdt::BlockMiss,
        Seam::TargetPublish => Usdt::TargetPublish,
        Seam::Invalidate => Usdt::Invalidate,
        Seam::BlockPublish => Usdt::BlockPublish,
        Seam::CapacityFailure => Usdt::CapacityFailure,
        Seam::DirectBindingEligible => Usdt::DirectBindingEligible,
        Seam::DirectBindingPublish => Usdt::DirectBindingPublish,
        Seam::DirectBindingCasLoss => Usdt::DirectBindingCasLoss,
        Seam::DirectBindingClear => Usdt::DirectBindingClear,
        Seam::DirectBindingValidationFailure => Usdt::DirectBindingValidationFailure,
        Seam::DirectBindingUnitLoaded => Usdt::DirectBindingUnitLoaded,
    }
}

fn native_dsr_cache_role(role: carrick_dsr::probes::DsrCacheRole) -> crate::probes::DsrCacheRole {
    use crate::probes::DsrCacheRole as Usdt;
    use carrick_dsr::probes::DsrCacheRole as Seam;
    match role {
        Seam::Common => Usdt::Common,
        Seam::Parent => Usdt::Parent,
        Seam::Child => Usdt::Child,
    }
}

fn native_dsr_translation_subphase(
    subphase: carrick_dsr::probes::DsrTranslationSubphase,
) -> crate::probes::DsrTranslationSubphase {
    use crate::probes::DsrTranslationSubphase as Usdt;
    use carrick_dsr::probes::DsrTranslationSubphase as Seam;
    match subphase {
        Seam::Decode => Usdt::Decode,
        Seam::Plan => Usdt::Plan,
        Seam::Emit => Usdt::Emit,
        Seam::PublicationIndex => Usdt::PublicationIndex,
        Seam::DuplicateWait => Usdt::DuplicateWait,
    }
}

fn native_dsr_synchronization_kind(
    kind: carrick_dsr::probes::DsrSynchronizationKind,
) -> crate::probes::DsrSynchronizationKind {
    use crate::probes::DsrSynchronizationKind as Usdt;
    use carrick_dsr::probes::DsrSynchronizationKind as Seam;
    match kind {
        Seam::GenerationTableWrite => Usdt::GenerationTableWrite,
        Seam::ProcessStateRead => Usdt::ProcessStateRead,
        Seam::ProcessStateWrite => Usdt::ProcessStateWrite,
    }
}

impl carrick_dsr::probes::DsrProbeSink for NativeDsrProbeForwarder {
    fn translated_range_reset(&self, event: carrick_dsr::probes::TranslatedRangeReset) {
        let Ok(epoch) = crate::probes::TranslatedRangeEpoch::new(event.epoch().get()) else {
            return;
        };
        crate::probes::host_translated_range_reset(crate::probes::TranslatedRangeReset::reset(
            epoch,
        ));
    }

    fn translated_range_add(&self, event: carrick_dsr::probes::TranslatedRangeAdd) {
        use carrick_dsr::probes::TranslatedRangeAdd as Seam;

        match event {
            Seam::Private(event) => {
                let Ok(epoch) = crate::probes::TranslatedRangeEpoch::new(event.epoch().get())
                else {
                    return;
                };
                let Ok(sequence) =
                    crate::probes::TranslatedRangeSequence::new(event.sequence().get())
                else {
                    return;
                };
                let Ok(event) = crate::probes::TranslatedPrivateRange::private(
                    epoch,
                    sequence,
                    event.range().clone(),
                ) else {
                    return;
                };
                crate::probes::host_translated_private_range(event);
            }
            Seam::Shared(event) => {
                let Ok(epoch) = crate::probes::TranslatedRangeEpoch::new(event.epoch().get())
                else {
                    return;
                };
                let Ok(sequence) =
                    crate::probes::TranslatedRangeSequence::new(event.sequence().get())
                else {
                    return;
                };
                let Ok(unit_id) = crate::probes::TranslatedUnitId::new(event.unit_id().get())
                else {
                    return;
                };
                let Ok(event) = crate::probes::TranslatedSharedRange::shared(
                    epoch,
                    sequence,
                    unit_id,
                    event.range().clone(),
                ) else {
                    return;
                };
                crate::probes::host_translated_shared_range(event);
            }
        }
    }

    fn translated_range_ready(&self, event: carrick_dsr::probes::TranslatedRangeReady) {
        let Ok(epoch) = crate::probes::TranslatedRangeEpoch::new(event.epoch().get()) else {
            return;
        };
        crate::probes::host_translated_range_ready(crate::probes::TranslatedRangeReady::ready(
            epoch,
            event.final_sequence(),
        ));
    }

    fn dsr_cache_lifecycle(
        &self,
        tid: i32,
        phase: carrick_dsr::probes::DsrCacheLifecyclePhase,
        used_bytes: u64,
        block_count: u64,
        generation_count: u64,
    ) {
        crate::probes::dsr_cache_lifecycle(
            tid,
            native_dsr_lifecycle_phase(phase),
            used_bytes,
            block_count,
            generation_count,
        );
    }

    fn dsr_exec_map_detail(
        &self,
        tid: i32,
        kind: carrick_dsr::probes::DsrExecMapDetailKind,
        duration_ns: u64,
        bytes: u64,
        operations: u64,
    ) {
        crate::probes::dsr_exec_map_detail(
            tid,
            native_dsr_exec_map_detail_kind(kind),
            duration_ns,
            bytes,
            operations,
        );
    }

    fn dsr_prepare_begin(&self, tid: i32, guest_pc: u64) {
        crate::probes::dsr_prepare_begin(tid, guest_pc);
    }

    fn dsr_prepare_end(
        &self,
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        generation: u64,
        outcome: carrick_dsr::probes::DsrPrepareOutcome,
    ) {
        crate::probes::dsr_prepare_end(
            tid,
            guest_pc,
            cache_pc,
            generation,
            native_dsr_prepare_outcome(outcome),
        );
    }

    fn dsr_run_begin(&self, tid: i32, guest_pc: u64, cache_pc: u64, generation: u64) {
        crate::probes::dsr_run_begin(tid, guest_pc, cache_pc, generation);
    }

    fn dsr_run_end(
        &self,
        tid: i32,
        kind: carrick_dsr::probes::DsrExitKind,
        guest_pc: u64,
        target_pc: u64,
        status: i32,
    ) {
        crate::probes::dsr_run_end(tid, native_dsr_exit_kind(kind), guest_pc, target_pc, status);
    }

    fn dsr_translate_begin(&self, tid: i32, guest_pc: u64, generation: u64) {
        crate::probes::dsr_translate_begin(tid, guest_pc, generation);
    }

    fn dsr_translate_end(
        &self,
        tid: i32,
        guest_pc: u64,
        cache_pc: u64,
        emitted_bytes: u64,
        outcome: carrick_dsr::probes::DsrOperationOutcome,
    ) {
        crate::probes::dsr_translate_end(
            tid,
            guest_pc,
            cache_pc,
            emitted_bytes,
            native_dsr_operation_outcome(outcome),
        );
    }

    fn dsr_translate_subphase_begin(
        &self,
        tid: i32,
        subphase: carrick_dsr::probes::DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    ) {
        crate::probes::dsr_translate_subphase_begin(
            tid,
            native_dsr_translation_subphase(subphase),
            guest_pc,
            generation,
        );
    }

    fn dsr_translate_subphase_end(
        &self,
        tid: i32,
        subphase: carrick_dsr::probes::DsrTranslationSubphase,
        guest_pc: u64,
        generation: u64,
    ) {
        crate::probes::dsr_translate_subphase_end(
            tid,
            native_dsr_translation_subphase(subphase),
            guest_pc,
            generation,
        );
    }

    fn dsr_synchronization_begin(&self, kind: carrick_dsr::probes::DsrSynchronizationKind) {
        crate::probes::dsr_synchronization_begin(native_dsr_synchronization_kind(kind));
    }

    fn dsr_synchronization_end(&self, kind: carrick_dsr::probes::DsrSynchronizationKind) {
        crate::probes::dsr_synchronization_end(native_dsr_synchronization_kind(kind));
    }

    fn dsr_resolve_begin(
        &self,
        tid: i32,
        kind: carrick_dsr::probes::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
    ) {
        crate::probes::dsr_resolve_begin(tid, native_dsr_resolve_kind(kind), source_pc, target_pc);
    }

    fn dsr_resolve_end(
        &self,
        tid: i32,
        kind: carrick_dsr::probes::DsrResolveKind,
        source_pc: u64,
        target_pc: u64,
        outcome: carrick_dsr::probes::DsrOperationOutcome,
    ) {
        crate::probes::dsr_resolve_end(
            tid,
            native_dsr_resolve_kind(kind),
            source_pc,
            target_pc,
            native_dsr_operation_outcome(outcome),
        );
    }

    fn dsr_cache_event(
        &self,
        tid: i32,
        kind: carrick_dsr::probes::DsrCacheEventKind,
        guest_pc: u64,
        generation: u64,
        used_bytes: u64,
    ) {
        crate::probes::dsr_cache_event(
            tid,
            native_dsr_cache_event_kind(kind),
            guest_pc,
            generation,
            used_bytes,
        );
    }

    fn dsr_cache_capacity(&self, role: carrick_dsr::probes::DsrCacheRole, capacity_bytes: u64) {
        crate::probes::dsr_cache_capacity(native_dsr_cache_role(role), capacity_bytes);
    }

    fn dsr_cache_bounds(&self, base: u64, end: u64) {
        crate::probes::dsr_cache_bounds(base, end);
    }
}

/// Install the USDT forwarder as `carrick_dsr::probes`' process-wide sink.
/// Idempotent (first-install-wins in the seam), so it is called at every
/// native-backend entry point — `run_static_elf` /
/// `run_elf_from_dispatcher_debug` (fresh boots) and
/// `resume_guest_from_capsule` (the PID-preserving self-reexec, a fresh
/// process image whose OnceLock starts empty) — each strictly before any
/// image mapping or DSR machinery runs, so no seam probe can fire
/// uninstalled. Guest-forked children inherit the already-installed sink
/// through fork's address-space copy.
fn install_native_probe_sink() {
    static FORWARDER: NativeDsrProbeForwarder = NativeDsrProbeForwarder;
    carrick_dsr::probes::install_probe_sink(&FORWARDER);
    // The extraction-completing slice made two more runtime-owned host
    // facts into installed seams with the same idempotent,
    // first-install-wins discipline; install them at the same entry points
    // so no moved code can observe an uninstalled seam:
    //  * the Darwin W^X JIT behind the translation cache, and
    //  * the vvar clock calibration sources for the vDSO stamper.
    carrick_dsr_aarch64::translator::install_host_jit(darwin_jit::active_host_jit());
    carrick_dsr_aarch64::mapped_memory::install_vvar_clock_sources(native_vvar_clock_sources);
}

/// Attach the shared vDSO (same ELF image + `CARRICK_DISABLE_VDSO` /
/// `CARRICK_VDSO_MODE` debug controls as the HVF builders) at the
/// native-mappable relocated bases, repointing `AT_SYSINFO_EHDR` accordingly.
fn with_native_vdso(image: AddressSpace) -> Result<AddressSpace, AddressSpaceError> {
    crate::runtime::with_optional_vdso_at::<carrick_hal::Aarch64GuestArch>(
        image,
        NATIVE_DARWIN_VVAR_BASE,
        NATIVE_DARWIN_VDSO_BASE,
    )
}

/// `(counter_freq_hz, clock_uptime_raw_ns)` — the SAME calibration sources the
/// HVF vvar stamper uses (re-exported from carrick-vmm-hvf's sysreg module), so
/// the native and HVF vvar pages describe one timeline. The off-target stub
/// returns `freq == 0`, which skips the clock words exactly like HVF's
/// zero-frequency guard; the native backend only ever RUNS on aarch64 macOS.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_vvar_clock_sources() -> (u64, u64) {
    (
        crate::trap::host_counter_frequency(),
        crate::trap::host_clock_uptime_ns(),
    )
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn native_vvar_clock_sources() -> (u64, u64) {
    (0, 0)
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn canonical_host_executable_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn native_relative_relocations(
    file: &[u8],
    load_bias: u64,
) -> Result<Vec<NativeRelativeRelocation>, RuntimeError> {
    let elf = Elf::parse(file).map_err(|err| {
        RuntimeError::Unsupported(format!(
            "native Darwin failed to parse ELF relocations: {err}"
        ))
    })?;
    if !native_image_needs_eager_relocations(&elf) {
        return Ok(Vec::new());
    }

    let mut relocations = Vec::new();
    for reloc in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
        match reloc.r_type {
            R_AARCH64_RELATIVE => {
                let addend = reloc.r_addend.ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native Darwin REL relocation without addend at 0x{:x}",
                        reloc.r_offset
                    ))
                })?;
                let address_raw = checked_add_u64(load_bias, reloc.r_offset, "relocation address")?;
                let address = crate::native_prepared_image::PreparedGuestVa::new(address_raw)
                    .ok_or_else(|| {
                        RuntimeError::Unsupported(format!(
                            "native Darwin relocation address is outside the guest VA domain: 0x{address_raw:x}"
                        ))
                    })?;
                let value_raw = add_load_bias(load_bias, addend)?;
                let value = crate::native_prepared_image::PreparedGuestVa::new(value_raw)
                    .ok_or_else(|| {
                        RuntimeError::Unsupported(format!(
                            "native Darwin relocation value is outside the guest VA domain: 0x{value_raw:x}"
                        ))
                    })?;
                relocations.push(NativeRelativeRelocation::new(address, value));
            }
            R_AARCH64_NONE => {}
            other => {
                return Err(RuntimeError::Unsupported(format!(
                    "native Darwin ET_DYN relocation type {other} at 0x{:x} is not supported",
                    reloc.r_offset
                )));
            }
        }
    }
    Ok(relocations)
}

fn native_image_needs_eager_relocations(elf: &Elf<'_>) -> bool {
    elf.header.e_type == ET_DYN && elf.interpreter.is_none()
}

// Runtime-error edge of `carrick_dsr::native_error::checked_add_u64` for the
// native_darwin.rs callers that still speak `RuntimeError` directly.
// `mapped_memory.rs` imports the carrick-dsr helpers (NativeMemoryError)
// instead; `align_up_u64` moved with them outright (its only users were
// there).
fn checked_add_u64(a: u64, b: u64, context: &str) -> Result<u64, RuntimeError> {
    carrick_dsr::native_error::checked_add_u64(a, b, context).map_err(RuntimeError::from)
}

fn add_load_bias(load_bias: u64, addend: i64) -> Result<u64, RuntimeError> {
    if addend >= 0 {
        load_bias.checked_add(addend as u64).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin relocation value overflow: 0x{load_bias:x}+0x{addend:x}"
            ))
        })
    } else {
        let magnitude = addend.unsigned_abs();
        load_bias.checked_sub(magnitude).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin relocation value underflow: 0x{load_bias:x}-0x{magnitude:x}"
            ))
        })
    }
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn run_image_in_child(
    image: AddressSpace,
    resolved_path: String,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    relative_relocations: Vec<NativeRelativeRelocation>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError> {
    let _cache_session =
        carrick_native_darwin::aot_cache::begin_container_cache().map_err(AddressSpaceError::Io)?;
    let stdout_pipe = pipe_pair()?;
    let stderr_pipe = pipe_pair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(stdout_pipe.0);
        close_fd(stdout_pipe.1);
        close_fd(stderr_pipe.0);
        close_fd(stderr_pipe.1);
        return Err(last_io_error("fork native Darwin child"));
    }

    if pid == 0 {
        close_fd(stdout_pipe.0);
        close_fd(stderr_pipe.0);
        child_dup2_or_exit(stdout_pipe.1, libc::STDOUT_FILENO);
        child_dup2_or_exit(stderr_pipe.1, libc::STDERR_FILENO);
        close_fd(stdout_pipe.1);
        close_fd(stderr_pipe.1);

        // The launch-owned CLI is the DTrace `$target`, but THIS fork child is
        // the first native translator owner. Publish its checked Darwin birth
        // tuple before any profile or DSR event so the capture can key the
        // initial catalog to the correct PID incarnation. Disabled USDT keeps
        // the query at zero cost outside a native-wall capture.
        crate::probes::host_process_birth_current();
        // Process startup attribution starts here: the guest pid is THIS
        // child, and its rusage clock restarted at fork, so the window must
        // anchor after the fork (env-gated; profile-off reads no clocks).
        dsr::profile::mark_native_process_runtime_entry();
        let guest_image = NativeGuestImageCompatibility::from_image(&image, resolved_path);
        match run_image_in_current_process(
            NativeImageSource::Legacy {
                image,
                relative_relocations,
            },
            None,
            dispatcher,
            max_traps,
            plan,
            NativeCurrentProcessEntry::Initial,
            guest_image,
        ) {
            Ok(code) => unsafe { libc::_exit(code) },
            Err(err) => {
                child_write_stderr(format!("native Darwin child error: {err}\n").as_bytes());
                unsafe { libc::_exit(125) };
            }
        }
    }

    close_fd(stdout_pipe.1);
    close_fd(stderr_pipe.1);
    let stdout_reader = thread::spawn(move || read_pipe_to_end(stdout_pipe.0));
    let stderr_reader = thread::spawn(move || read_pipe_to_end(stderr_pipe.0));
    let status = waitpid_blocking(pid)?;
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + crate::host_signal::host_to_linux_signum(libc::WTERMSIG(status))
    } else {
        125
    };

    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        traps: 0,
        report: CompatReport::default(),
        trap_limit_hit: false,
    })
}

fn run_image_in_current_process(
    source: NativeImageSource,
    executable_digest: Option<[u8; 32]>,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    plan: &ExecutionPlan,
    process_entry: NativeCurrentProcessEntry,
    guest_image: NativeGuestImageCompatibility,
) -> Result<i32, RuntimeError> {
    // Collect dyld-owned host identity before the guest mapping or self-reexec
    // restore can cross its fatal-only boundary. The Initial handoff owns this
    // allocation and only borrows it after catalog activation.
    let host_images = std::env::var_os("CARRICK_DSR_PROFILE")
        .is_some()
        .then(crate::probes::prepare_host_image_publication);
    let completion = match process_entry {
        NativeCurrentProcessEntry::Initial => NativeInitialProcessCompletion::Boot,
        NativeCurrentProcessEntry::SelfReexecRestore => NativeInitialProcessCompletion::SelfReexec,
    };
    let initial_sp = source.image().initial_stack_pointer().ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin image has no initial stack".to_string())
    })?;
    let entry = source.image().entry();
    let (memory, image) = map_current_process_image_source(source, plan, process_entry)?;
    let native_page_profile = plan.page_geometry.native_profile.ok_or_else(|| {
        RuntimeError::Unsupported(
            "native Darwin shared translation configured without a native page profile".to_string(),
        )
    })?;
    memory
        .configure_shared_translation(
            &image,
            native_page_profile,
            executable_digest,
            Arc::new(carrick_native_darwin::aot_cache::ActiveContainerUnitStore),
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let memory = Arc::new(NativeMemoryHandle::new(memory));
    let _ = crate::ulock::preinit_waiter_table();
    // PID-namespace launch placement (container path only; `run-elf` never
    // requests it): the same identity-init fallback as the HVF threaded loop —
    // this process becomes the ns-init (ns-pid 1), and every native fork
    // descendant registers through the inherited shared region
    // (`allocate_child_ns_pid_pre_fork` in `handle_native_fork`). Without this
    // the request made by `Runtime::execute` was silently dropped, so a native
    // container ran with HOST pids: the container root was not pid 1 and its
    // children's getppid() never read 1 (the pidnsroot divergence). Must run
    // before the guest's first fork so descendants inherit one mapping.
    if crate::namespace::pid::requested() && !crate::namespace::pid::enabled() {
        let _ = crate::namespace::pid::init(std::process::id());
    }
    // Guest code runs natively on host threads here, so Darwin's own process
    // accounting is the guest CPU clock (times/getrusage//proc/stat/CPU
    // itimers/RLIMIT_CPU all read through guest_cpu). Process state: forked
    // children inherit it; execve re-enters the same run loop.
    crate::guest_cpu::set_native_darwin_provider();
    // Publish the boot image's region list + auxv to the dispatcher —
    // /proc/self/maps//status VmSize/VmRSS and /proc/self/auxv render from it.
    // The native execve path already does this for replacement images; without
    // the boot-time call the snapshot held only dynamic mmaps, so VmSize
    // missed the image/stack entirely (and fell below the measured VmRSS).
    crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
    carrick_signal_core::xsig::xsig_init();
    carrick_signal_core::fasync::fasync_init();
    crate::host_signal::install_default_handlers();
    let dispatcher = Arc::new(dispatcher);
    let reporter = Arc::new(CompatReporter::default());
    let plan = Arc::new(plan.clone());
    let mut thread_runtime = NativeThreadRuntime::new_current();
    thread_runtime.prepare_kick_target()?;
    thread_runtime.start_signal_wake_pump();
    // Timer-signal delivery (setitimer/timer_settime): publish + kick-all via
    // the native kick registry. Must be registered before the guest's first
    // setitimer; the OnceLock handle is inherited by forked children and
    // resolves the CURRENT process's kicker at fire time.
    crate::timer_delivery::register_delivery(Arc::new(NativeTimerDelivery));
    match run_native_thread_loop(
        dispatcher,
        memory,
        reporter,
        max_traps,
        plan,
        &mut thread_runtime,
        NativeThreadStart::Initial {
            entry,
            initial_sp,
            guest_image,
            host_images,
            completion,
        },
    )? {
        NativeThreadLoopOutcome::ProcessExit(code) => Ok(code),
        NativeThreadLoopOutcome::ThreadDone => {
            thread_runtime.join_spawned_threads()?;
            // A sibling spawned AFTER this leader exited may have execve'd,
            // and its teardown's join-take can empty the shared handle vec
            // out from under this join. The exec'd thread owns the process
            // (it terminates via `_exit`); erroring out here exited the
            // process under the running image — the lost-exec variant via a
            // NORMALLY-exited leader. Regression:
            // exited_leader_parks_when_image_replaced_by_exec.
            if native_exited_leader_must_park(thread_runtime.tid()) {
                loop {
                    std::thread::park();
                }
            }
            Err(RuntimeError::Unsupported(
                "native Darwin thread group ended without a process exit".to_string(),
            ))
        }
        NativeThreadLoopOutcome::ExecReplacedThread => {
            // Another thread's execve replaced the image: the exec'd thread
            // owns the process and terminates it via `_exit`. This initial
            // host thread must never exit the process out from under the new
            // image — join whatever handles remain (the exec'd thread's own
            // handle blocks until process death unless the teardown's join
            // already took it), then park forever. Joining an empty vec here
            // previously fell into the unconditional error above and KILLED
            // the exec'd process (lost exec). A join error (a panicked,
            // already-retired sibling) changes nothing: the image owns the
            // process either way.
            let _ = thread_runtime.join_spawned_threads();
            loop {
                std::thread::park();
            }
        }
    }
}

fn map_native_image_source(
    source: &NativeImageSource,
    plan: &ExecutionPlan,
) -> Result<NativeMappedMemory, RuntimeError> {
    match source {
        NativeImageSource::Legacy {
            image,
            relative_relocations,
        } => Ok(NativeMappedMemory::map_for_plan(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            plan.page_geometry.linux_page_size,
            plan.page_geometry,
            relative_relocations,
        )?),
        NativeImageSource::Prepared(prepared) => Ok(NativeMappedMemory::map_prepared_for_plan(
            prepared,
            native_memory_layout(),
            plan.page_geometry,
        )?),
    }
}

fn map_and_release_native_image_source(
    source: NativeImageSource,
    plan: &ExecutionPlan,
) -> Result<(NativeMappedMemory, AddressSpace), RuntimeError> {
    let memory = map_native_image_source(&source, plan)?;
    // Every prepared extent is MAP_PRIVATE and remains valid after its
    // inherited artifact closes. Convert to the transport-neutral metadata
    // image immediately after all mappings succeed so the fd cannot survive
    // into guest execution or a later guest exec. On any mapping error the
    // owned source drops here and closes the validated artifact as well.
    let image = source.into_image();
    Ok((memory, image))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCurrentProcessEntry {
    // `Initial` is only constructed by the boot-time `run_image_in_child`
    // path (macOS-arm-only until M0.8, like `run_static_elf`); the reexec
    // restore arm constructs `SelfReexecRestore` on every platform.
    #[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
    Initial,
    SelfReexecRestore,
}

fn map_current_process_image_source(
    source: NativeImageSource,
    plan: &ExecutionPlan,
    process_entry: NativeCurrentProcessEntry,
) -> Result<(NativeMappedMemory, AddressSpace), RuntimeError> {
    let mapped = map_and_release_native_image_source(source, plan)?;
    if process_entry == NativeCurrentProcessEntry::SelfReexecRestore {
        native_reexec_lifecycle(
            carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecGuestEntry,
        );
    }
    Ok(mapped)
}

enum NativeThreadStart {
    Initial {
        entry: u64,
        initial_sp: u64,
        guest_image: NativeGuestImageCompatibility,
        host_images: Option<crate::probes::PreparedHostImagePublication>,
        completion: NativeInitialProcessCompletion,
    },
    Detached {
        context: Box<NativeUcontextSnapshot>,
        guest_tpidr_el0: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeInitialProcessCompletion {
    Boot,
    SelfReexec,
}

#[derive(Debug, Eq, PartialEq)]
enum NativeProcessHandoffError<Preparation, Activation, Completion> {
    Preparation(Preparation),
    Activation(Activation),
    Completion(Completion),
}

trait NativeImagePublisher {
    fn host_base(&mut self, metadata: &crate::probes::PreparedHostImagePublication);
    fn host_catalog(&mut self, metadata: &crate::probes::PreparedHostImagePublication);
    fn guest(&mut self, metadata: &NativeGuestImageCompatibility);
    fn host_jit(&mut self, range: std::ops::Range<u64>);
}

struct NativeProbeImagePublisher;

impl NativeImagePublisher for NativeProbeImagePublisher {
    fn host_base(&mut self, metadata: &crate::probes::PreparedHostImagePublication) {
        crate::probes::publish_host_image_base(metadata);
        #[cfg(test)]
        record_native_process_handoff_event(NativeProcessHandoffEvent::HostBase);
    }

    fn host_catalog(&mut self, metadata: &crate::probes::PreparedHostImagePublication) {
        crate::probes::publish_host_image_catalog(metadata);
        #[cfg(test)]
        record_native_process_handoff_event(NativeProcessHandoffEvent::HostCatalog);
    }

    fn guest(&mut self, metadata: &NativeGuestImageCompatibility) {
        crate::probes::guest_image_base(metadata.base, metadata.entry, &metadata.resolved_path);
        #[cfg(test)]
        record_native_process_handoff_event(NativeProcessHandoffEvent::Guest);
    }

    fn host_jit(&mut self, range: std::ops::Range<u64>) {
        crate::probes::host_jit_range(range.start, range.end);
        #[cfg(test)]
        record_native_process_handoff_event(NativeProcessHandoffEvent::HostJit);
    }
}

fn prepare_activate_publish_commit_native_process<
    T,
    Prepared,
    PreparationError,
    ActivationError,
    CompletionError,
>(
    process: Arc<dsr::ProcessTranslator>,
    prepare: impl FnOnce(Arc<dsr::ProcessTranslator>) -> Result<Prepared, PreparationError>,
    activate: impl FnOnce(&dsr::ProcessTranslator) -> Result<(), ActivationError>,
    publish: impl FnOnce(&dsr::ProcessTranslator),
    commit: impl FnOnce(Prepared) -> T,
    complete: impl FnOnce() -> Result<(), CompletionError>,
) -> Result<T, NativeProcessHandoffError<PreparationError, ActivationError, CompletionError>> {
    let prepared = prepare(Arc::clone(&process)).map_err(NativeProcessHandoffError::Preparation)?;
    activate(&process).map_err(NativeProcessHandoffError::Activation)?;
    publish(&process);
    let installed = commit(prepared);
    complete().map_err(NativeProcessHandoffError::Completion)?;
    Ok(installed)
}

fn publish_native_process_images(
    process: &dsr::ProcessTranslator,
    host_images: Option<&crate::probes::PreparedHostImagePublication>,
    guest_image: &NativeGuestImageCompatibility,
    publisher: &mut impl NativeImagePublisher,
) {
    if let Some(host_images) = host_images {
        publisher.host_base(host_images);
        publisher.host_catalog(host_images);
    }
    publisher.guest(guest_image);
    publisher.host_jit(process.cache_host_range());
}

fn install_native_thread_start_with<
    T,
    Prepared,
    PreparationError,
    ActivationError,
    CompletionError,
>(
    process: Arc<dsr::ProcessTranslator>,
    start: NativeThreadStart,
    prepare: impl FnOnce(Arc<dsr::ProcessTranslator>) -> Result<Prepared, PreparationError>,
    activate: impl FnOnce(&dsr::ProcessTranslator) -> Result<(), ActivationError>,
    publisher: &mut impl NativeImagePublisher,
    commit: impl FnOnce(Prepared) -> T,
    complete: impl FnOnce(NativeInitialProcessCompletion) -> Result<(), CompletionError>,
) -> Result<
    (T, NativeUcontextSnapshot, u64),
    NativeProcessHandoffError<PreparationError, ActivationError, CompletionError>,
> {
    match start {
        NativeThreadStart::Initial {
            entry,
            initial_sp,
            guest_image,
            host_images,
            completion,
        } => {
            let installed = prepare_activate_publish_commit_native_process(
                process,
                prepare,
                activate,
                |selected| {
                    publish_native_process_images(
                        selected,
                        host_images.as_ref(),
                        &guest_image,
                        publisher,
                    );
                },
                commit,
                || complete(completion),
            )?;
            Ok((
                installed,
                NativeUcontextSnapshot {
                    sp: initial_sp,
                    pc: entry,
                    ..NativeUcontextSnapshot::default()
                },
                0,
            ))
        }
        NativeThreadStart::Detached {
            context,
            guest_tpidr_el0,
        } => {
            let prepared = prepare(process).map_err(NativeProcessHandoffError::Preparation)?;
            Ok((commit(prepared), *context, guest_tpidr_el0))
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeProcessHandoffFailpoint {
    Activation,
    InstallationPreparation,
}

#[cfg(test)]
thread_local! {
    static NATIVE_PROCESS_HANDOFF_FAILPOINT:
        std::cell::Cell<Option<NativeProcessHandoffFailpoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_native_process_handoff_failpoint(failpoint: Option<NativeProcessHandoffFailpoint>) {
    NATIVE_PROCESS_HANDOFF_FAILPOINT.with(|slot| slot.set(failpoint));
}

#[cfg(test)]
fn take_native_process_handoff_failpoint(expected: NativeProcessHandoffFailpoint) -> bool {
    NATIVE_PROCESS_HANDOFF_FAILPOINT.with(|slot| {
        if slot.get() == Some(expected) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeProcessHandoffEvent {
    InstallationPreparationAttempt,
    ActivationAttempt,
    HostBase,
    HostCatalog,
    Guest,
    HostJit,
    InstallationCommit,
    SnapshotInstalled,
    PtraceExecStop,
    ServiceCompletion,
    Completion,
}

#[cfg(test)]
thread_local! {
    static NATIVE_PROCESS_HANDOFF_EVENTS:
        std::cell::RefCell<Vec<NativeProcessHandoffEvent>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_native_process_handoff_event(event: NativeProcessHandoffEvent) {
    NATIVE_PROCESS_HANDOFF_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
fn take_native_process_handoff_events() -> Vec<NativeProcessHandoffEvent> {
    NATIVE_PROCESS_HANDOFF_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

fn activate_selected_native_process(
    process: &dsr::ProcessTranslator,
) -> Result<(), dsr::types::DsrError> {
    #[cfg(test)]
    {
        record_native_process_handoff_event(NativeProcessHandoffEvent::ActivationAttempt);
        if take_native_process_handoff_failpoint(NativeProcessHandoffFailpoint::Activation) {
            return Err(dsr::types::DsrError::CachePolicy(
                "injected native process handoff activation failure".to_owned(),
            ));
        }
    }
    process.activate_translated_range_catalog()
}

fn prepare_initial_native_process(
    process: Arc<dsr::ProcessTranslator>,
    tid: i32,
) -> Result<dsr::PreparedThreadInstall, dsr::types::DsrError> {
    #[cfg(test)]
    {
        record_native_process_handoff_event(
            NativeProcessHandoffEvent::InstallationPreparationAttempt,
        );
        if take_native_process_handoff_failpoint(
            NativeProcessHandoffFailpoint::InstallationPreparation,
        ) {
            return Err(dsr::types::DsrError::CachePolicy(
                "injected native process handoff installation preparation failure".to_owned(),
            ));
        }
    }
    Ok(dsr::ThreadTranslator::prepare_for_process(process, tid))
}

fn commit_initial_native_process(prepared: dsr::PreparedThreadInstall) -> dsr::ThreadTranslator {
    let translator = prepared.commit();
    #[cfg(test)]
    record_native_process_handoff_event(NativeProcessHandoffEvent::InstallationCommit);
    translator
}

fn prepare_exec_native_process<'a>(
    translator: &'a mut dsr::ThreadTranslator,
    process: Arc<dsr::ProcessTranslator>,
) -> Result<dsr::PreparedThreadExecHandoff<'a>, dsr::types::DsrError> {
    #[cfg(test)]
    {
        record_native_process_handoff_event(
            NativeProcessHandoffEvent::InstallationPreparationAttempt,
        );
        if take_native_process_handoff_failpoint(
            NativeProcessHandoffFailpoint::InstallationPreparation,
        ) {
            return Err(dsr::types::DsrError::CachePolicy(
                "injected native process handoff installation preparation failure".to_owned(),
            ));
        }
    }
    translator.prepare_reset_for_exec(process)
}

fn commit_exec_native_process(prepared: dsr::PreparedThreadExecHandoff<'_>) {
    prepared.commit();
    #[cfg(test)]
    record_native_process_handoff_event(NativeProcessHandoffEvent::InstallationCommit);
}

fn install_native_thread_start(
    process: Arc<dsr::ProcessTranslator>,
    start: NativeThreadStart,
    dispatcher: &SyscallDispatcher,
    tid: i32,
) -> Result<(dsr::ThreadTranslator, NativeUcontextSnapshot, u64), RuntimeError> {
    install_native_thread_start_with(
        process,
        start,
        |selected| prepare_initial_native_process(selected, tid),
        activate_selected_native_process,
        &mut NativeProbeImagePublisher,
        commit_initial_native_process,
        |completion| {
            if completion == NativeInitialProcessCompletion::SelfReexec {
                crate::exec_helpers::stop_after_traced_exec(dispatcher);
                #[cfg(test)]
                record_native_process_handoff_event(NativeProcessHandoffEvent::PtraceExecStop);
                native_reexec_lifecycle(
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecResetEnd,
                );
            }
            #[cfg(test)]
            record_native_process_handoff_event(NativeProcessHandoffEvent::Completion);
            Ok::<(), std::convert::Infallible>(())
        },
    )
    .map_err(|error| match error {
        NativeProcessHandoffError::Preparation(error) => RuntimeError::Trap(TrapError::Hypervisor(
            format!("native initial process could not prepare translator: {error}"),
        )),
        NativeProcessHandoffError::Activation(error) => {
            RuntimeError::Unsupported(error.to_string())
        }
        NativeProcessHandoffError::Completion(never) => match never {},
    })
}

#[allow(clippy::too_many_arguments)]
fn complete_native_in_process_exec_handoff(
    process: Arc<dsr::ProcessTranslator>,
    host_images: Option<&crate::probes::PreparedHostImagePublication>,
    guest_image: &NativeGuestImageCompatibility,
    translator: &mut dsr::ThreadTranslator,
    entry: u64,
    initial_sp: u64,
    dispatcher: &SyscallDispatcher,
    service: &mut NativeSyscallServiceSpan,
    snapshot: &mut NativeUcontextSnapshot,
    guest_tpidr_el0: &mut u64,
    complete_process_state: impl FnOnce(),
) -> Result<(), RuntimeError> {
    prepare_activate_publish_commit_native_process(
        process,
        |selected| prepare_exec_native_process(translator, selected),
        activate_selected_native_process,
        |selected| {
            publish_native_process_images(
                selected,
                host_images,
                guest_image,
                &mut NativeProbeImagePublisher,
            );
        },
        commit_exec_native_process,
        || {
            complete_process_state();
            *guest_tpidr_el0 = 0;
            *snapshot = NativeUcontextSnapshot {
                sp: initial_sp,
                pc: entry,
                ..NativeUcontextSnapshot::default()
            };
            #[cfg(test)]
            record_native_process_handoff_event(NativeProcessHandoffEvent::SnapshotInstalled);
            crate::exec_helpers::stop_after_traced_exec(dispatcher);
            #[cfg(test)]
            record_native_process_handoff_event(NativeProcessHandoffEvent::PtraceExecStop);
            require_native_syscall_service_transition(
                service.end(NativeSyscallServiceOutcome::InProcessExec),
                "in-process exec end",
            )?;
            #[cfg(test)]
            record_native_process_handoff_event(NativeProcessHandoffEvent::ServiceCompletion);
            #[cfg(test)]
            record_native_process_handoff_event(NativeProcessHandoffEvent::Completion);
            Ok::<(), RuntimeError>(())
        },
    )
    .map_err(|error| match error {
        NativeProcessHandoffError::Preparation(error) => RuntimeError::Trap(TrapError::Hypervisor(
            format!("native execve could not prepare replacement translator: {error}"),
        )),
        NativeProcessHandoffError::Activation(error) => {
            RuntimeError::Unsupported(error.to_string())
        }
        NativeProcessHandoffError::Completion(error) => error,
    })
}

enum NativeThreadLoopOutcome {
    ProcessExit(i32),
    ThreadDone,
    /// This thread was retired because ANOTHER thread's execve replaced the
    /// thread group. Distinct from `ThreadDone` because the process's INITIAL
    /// host thread must react differently: the exec'd thread owns the process
    /// image now and terminates the process via `_exit`, so the initial
    /// thread must wait/park forever. Treating this as a plain `ThreadDone`
    /// let `run_image_in_current_process`'s unconditional "thread group ended
    /// without a process exit" error EXIT the process out from under the
    /// running exec'd image whenever the teardown's join-take emptied the
    /// handle vec first (a lost exec on a Linux-legal shape).
    ExecReplacedThread,
}

fn native_clone_child_context(
    mut context: NativeUcontextSnapshot,
    resume_pc: u64,
    stack: u64,
    tls: Option<u64>,
    parent_guest_tpidr_el0: u64,
) -> (NativeUcontextSnapshot, u64) {
    context.x[0] = 0;
    if stack != 0 {
        context.sp = stack;
    }
    context.pc = resume_pc;
    context.signal = 0;
    context.signal_code = 0;
    context.fault_address = 0;
    context.esr = 0;
    context.far = 0;
    (context, tls.unwrap_or(parent_guest_tpidr_el0))
}

struct NativeCloneThreadRequest {
    context: NativeUcontextSnapshot,
    resume_pc: u64,
    parent_guest_tpidr_el0: u64,
    stack: u64,
    tls: Option<u64>,
    parent_tid_addr: u64,
    child_tid_addr: u64,
    clear_child_tid_addr: u64,
    service_number: u64,
    service_name: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSyscallServiceState {
    Open,
    TerminalHandoff,
    Closed,
}

struct NativeSyscallServiceSpan {
    number: u64,
    name: &'static str,
    state: NativeSyscallServiceState,
}

impl NativeSyscallServiceSpan {
    fn open(number: u64, name: &'static str) -> Self {
        crate::probes::native_syscall_service_entry(number, name);
        #[cfg(test)]
        record_native_syscall_service_probe_event(NativeSyscallServiceProbeEvent::Entry {
            number,
            name,
        });
        Self {
            number,
            name,
            state: NativeSyscallServiceState::Open,
        }
    }

    fn inherited_open(number: u64, name: &'static str) -> Self {
        Self {
            number,
            name,
            state: NativeSyscallServiceState::Open,
        }
    }

    fn branch(&mut self, kind: NativeSyscallBranchKind) -> bool {
        if self.state != NativeSyscallServiceState::Open {
            return false;
        }
        crate::probes::native_syscall_service_branch(kind);
        #[cfg(test)]
        record_native_syscall_service_probe_event(NativeSyscallServiceProbeEvent::Branch(kind));
        true
    }

    fn end(&mut self, outcome: NativeSyscallServiceOutcome) -> bool {
        if self.state != NativeSyscallServiceState::Open {
            return false;
        }
        crate::probes::native_syscall_service_end(self.number, self.name, outcome);
        #[cfg(test)]
        record_native_syscall_service_probe_event(NativeSyscallServiceProbeEvent::End {
            number: self.number,
            name: self.name,
            outcome,
        });
        self.state = NativeSyscallServiceState::Closed;
        true
    }

    fn terminal_handoff(&mut self) -> bool {
        if self.state != NativeSyscallServiceState::Open {
            return false;
        }
        self.state = NativeSyscallServiceState::TerminalHandoff;
        true
    }

    fn reopen_after_failed_terminal_handoff(&mut self) -> bool {
        if self.state != NativeSyscallServiceState::TerminalHandoff {
            return false;
        }
        self.state = NativeSyscallServiceState::Open;
        true
    }

    #[cfg(test)]
    fn state(&self) -> NativeSyscallServiceState {
        self.state
    }
}

fn require_native_syscall_service_transition(
    completed: bool,
    transition: &'static str,
) -> Result<(), RuntimeError> {
    if completed {
        Ok(())
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native syscall service span rejected duplicate {transition} transition"
        )))
    }
}

impl Drop for NativeSyscallServiceSpan {
    fn drop(&mut self) {
        if self.state == NativeSyscallServiceState::Open {
            let _ = self.end(NativeSyscallServiceOutcome::Aborted);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeSyscallServiceProbeEvent {
    Entry {
        number: u64,
        name: &'static str,
    },
    Branch(NativeSyscallBranchKind),
    End {
        number: u64,
        name: &'static str,
        outcome: NativeSyscallServiceOutcome,
    },
}

#[cfg(test)]
thread_local! {
    static NATIVE_SYSCALL_SERVICE_PROBE_EVENTS:
        std::cell::RefCell<Vec<NativeSyscallServiceProbeEvent>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_native_syscall_service_probe_event(event: NativeSyscallServiceProbeEvent) {
    NATIVE_SYSCALL_SERVICE_PROBE_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
fn take_native_syscall_service_probe_events() -> Vec<NativeSyscallServiceProbeEvent> {
    NATIVE_SYSCALL_SERVICE_PROBE_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeForkChildResumeEvent {
    ChildTranslatorRebuild,
    ForkPost,
    SyscallCompletion,
    GuestResume,
}

#[cfg(test)]
thread_local! {
    static NATIVE_FORK_CHILD_RESUME_EVENTS:
        std::cell::RefCell<Vec<NativeForkChildResumeEvent>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_native_fork_child_resume_event(event: NativeForkChildResumeEvent) {
    NATIVE_FORK_CHILD_RESUME_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
fn take_native_fork_child_resume_events() -> Vec<NativeForkChildResumeEvent> {
    NATIVE_FORK_CHILD_RESUME_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

/// Repair the child-owned translator and publish the child-side fork boundary.
///
/// This is the last fallible child-only stage before syscall completion and
/// guest resume. Keeping the error mapping and every post-repair publication
/// in one seam makes `?` at the caller preserve the still-open syscall span:
/// its RAII drop emits one `Aborted` end while no resume-shaped event escapes.
fn repair_native_fork_child_before_resume(
    translator: &mut dsr::ThreadTranslator,
    tid: i32,
    snapshot: &mut NativeUcontextSnapshot,
    child_stack: u64,
) -> Result<(), RuntimeError> {
    let translator_rebuild_start = std::time::Instant::now();
    translator
        .after_fork_child(tid)
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let translator_rebuild_us = translator_rebuild_start
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    crate::probes::native_fork_lifecycle(
        NativeForkPhase::ChildTranslatorRebuild,
        translator_rebuild_us,
        i64::from(tid),
        0,
    );
    #[cfg(test)]
    record_native_fork_child_resume_event(NativeForkChildResumeEvent::ChildTranslatorRebuild);

    // `arg0 == 0` is the D script's child clause.
    crate::probes::fork_post(0, snapshot.pc, 0);
    #[cfg(test)]
    record_native_fork_child_resume_event(NativeForkChildResumeEvent::ForkPost);
    if child_stack != 0 {
        snapshot.sp = child_stack;
    }
    Ok(())
}

/// Outcome of [`NativeThreadRuntime::acquire_fork_token`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeForkTokenFlow {
    /// The process-wide fork token is held by this thread. `contended` records
    /// whether the CAS failed at least once, i.e. this fork QUEUED behind
    /// another fork/exec rather than taking a free token — the discriminator
    /// the `fork-lifecycle` `TokenAcquire` sample reports, so a long
    /// acquisition can be attributed to real serialization instead of guessed
    /// at from elapsed time alone.
    Acquired { contended: bool },
    /// An execve by ANOTHER thread is replacing the thread group; the caller
    /// must retire this thread instead of proceeding.
    RetireForExec,
    /// The token backstop deadline expired (an unknown holder). Fork callers
    /// degrade to Linux-shaped EAGAIN.
    TimedOut,
}

/// How a fork request left `handle_native_fork`.
enum NativeForkFlow {
    /// Resume the caller at the instruction after the fork-like syscall.
    ///
    /// DSR owns an explicit snapshot. `fork_child` records that the snapshot
    /// resumed in a host-fork child so process-cache and publication state can
    /// be repaired before translated execution continues.
    Resume {
        value: i64,
        fork_child: bool,
        child_stack: u64,
    },
    /// The fork was abandoned because an execve by another thread is
    /// replacing the thread group; the run loop must retire this thread.
    RetireForExec,
}

/// How the pre-exec sibling teardown left `native_terminate_siblings_for_exec`.
enum NativeExecTeardownFlow {
    /// Siblings (if any) are gone; proceed with the image replacement.
    Proceed,
    /// ANOTHER thread's execve won the race; the caller must retire this
    /// thread (its execve never happens — the whole group is being replaced).
    RetireForExec,
}

#[allow(clippy::too_many_arguments)]
/// Finalize a guest thread's DSR profile record before it retires from the
/// thread registry, then report whether that retirement ended the process.
///
/// `DispatchOutcome::ThreadExit` fires for `exit(2)` from a thread the
/// dispatcher believed had live siblings; `finish_thread` may still discover
/// concurrently that it was in fact the last one, turning this exit into a
/// `ProcessExit` whose caller (the spawn closure) reacts with
/// `unsafe { libc::_exit(code) }` — a hard process-wide kill with no further
/// chance for ANY thread's stack to unwind normally. So the two outcomes need
/// two DIFFERENT flushes, and the branch must be taken first:
///
/// * last thread → `finalize_profile_epoch_at_process_exit`, which also
///   drains any sibling still registered (see `SiblingSlot`) and flushes this
///   thread's own record last, so it owns the process-wide resolver delta.
/// * not the last thread → a plain `finalize_profile_epoch`: this thread
///   retires alone and the process keeps running.
///
/// Flushing only AFTER `finish_thread` (rather than before, unconditionally)
/// is safe precisely because of the sibling registry: if a CONCURRENT
/// `exit_group` on another thread kills this one mid-`finish_thread`, that
/// thread's drain finds this thread's still-`Live` slot and emits its record
/// on its behalf. The race the pre-registry code had to pre-flush against is
/// now covered by the registry itself — and covered better, since the drain
/// also reads this thread's real CPU live from its mach port.
///
/// Exactly-once regardless: every emission path claims the thread's registry
/// slot with a single map operation, so `translator`'s eventual `Drop`, a
/// concurrent foreign drain, and this call can never between them put a
/// duplicate `(pid, tid, era)` group on the wire (which the protocol rejects).
fn finalize_native_thread_exit(
    translator: &mut dsr::ThreadTranslator,
    thread_runtime: &mut NativeThreadRuntime,
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    code: i32,
) -> NativeThreadLoopOutcome {
    if thread_runtime.finish_thread(dispatcher, memory) {
        // This exit turned out to be the process's last live thread after
        // all: the same "everyone else dies at `libc::_exit()` with zero
        // chance to flush" seam as `exit_group`. Drain any straggler sibling
        // slots, then flush this thread's own record last so it owns the
        // process-wide resolver delta.
        finalize_native_process_exit(translator, memory);
        NativeThreadLoopOutcome::ProcessExit(code)
    } else {
        translator.finalize_profile_epoch();
        NativeThreadLoopOutcome::ThreadDone
    }
}

fn publish_native_shared_candidates(
    translator: &dsr::ThreadTranslator,
    memory: &SharedNativeMemory,
) {
    let result = {
        let memory = memory.read();
        translator.process.publish_shared_candidates(&memory)
    };
    if let Err(error) = result {
        tracing::warn!(%error, "native shared translation publication fell back to JIT");
    }
}

fn finalize_native_process_exit(
    translator: &mut dsr::ThreadTranslator,
    memory: &SharedNativeMemory,
) {
    publish_native_shared_candidates(translator, memory);
    maybe_dump_code_snapshot(translator);
    translator.finalize_profile_epoch_at_process_exit();
}

/// Diagnostic-only: when `CARRICK_DSR_CODE_SNAPSHOT_DIR` names a directory,
/// dump this process's published JIT bytes and guest-to-cache block index at
/// the last-thread exit seam, so an offline sampled-PC census can classify
/// emitted words after the (short-lived) process is gone. Never enabled on a
/// measurement path; failures only warn.
fn maybe_dump_code_snapshot(translator: &dsr::ThreadTranslator) {
    let Some(dir) = std::env::var_os("CARRICK_DSR_CODE_SNAPSHOT_DIR") else {
        return;
    };
    let snapshot = translator.process.code_snapshot();
    let pid = std::process::id();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let base = std::path::PathBuf::from(&dir);
    let code_path = base.join(format!("{pid}-{stamp}.bin"));
    let index_path = base.join(format!("{pid}-{stamp}.json"));
    let index = serde_json::json!({
        "pid": pid,
        "cache_base": snapshot.cache_base,
        "code_len": snapshot.code.len(),
        "blocks": snapshot.blocks,
    });
    let written = std::fs::write(&code_path, &snapshot.code)
        .and_then(|_| std::fs::write(&index_path, serde_json::to_vec(&index).unwrap_or_default()));
    if let Err(error) = written {
        tracing::warn!(%error, "code snapshot dump failed");
    }
}

fn run_native_thread_loop(
    dispatcher: Arc<SyscallDispatcher>,
    memory: SharedNativeMemory,
    reporter: Arc<CompatReporter>,
    max_traps: usize,
    plan: Arc<ExecutionPlan>,
    thread_runtime: &mut NativeThreadRuntime,
    start: NativeThreadStart,
) -> Result<NativeThreadLoopOutcome, RuntimeError> {
    run_native_dsr_thread_loop(
        dispatcher,
        memory,
        reporter,
        max_traps,
        plan,
        thread_runtime,
        start,
    )
}
#[inline(never)]
fn prepare_dsr_entry<const PROFILE: bool>(
    translator: &mut dsr::ThreadTranslator,
    memory: &SharedNativeMemory,
    snapshot: &NativeUcontextSnapshot,
) -> Result<dsr::PreparedEntry, RuntimeError> {
    let memory = memory.upgradable_read();
    // `prepare_dsr_execution` only mutates SMC/JIT (write+exec) page state
    // when the entry PC lands on a page the write-exec fault path already
    // marked writable; every other entry is a pure read. Check the
    // condition under the upgradable guard and only pay for a write guard
    // on that (rare) branch.
    let memory = if let Some(page_start) = memory.native16k_write_exec_page(snapshot.pc) {
        let host_page_size = memory.host_page_size as usize;
        let mut memory = parking_lot::RwLockUpgradableReadGuard::upgrade(memory);
        memory
            .make_native16k_write_exec_page_executable(page_start, snapshot.pc, host_page_size)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        parking_lot::RwLockWriteGuard::downgrade(memory)
    } else {
        parking_lot::RwLockUpgradableReadGuard::downgrade(memory)
    };
    translator
        .prepare_entry::<PROFILE>(&memory, snapshot)
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))
}

#[inline(never)]
fn enter_dsr_prepared<const PROFILE: bool>(
    translator: &mut dsr::ThreadTranslator,
    prepared: dsr::PreparedEntry,
    snapshot: &mut NativeUcontextSnapshot,
) -> Result<dsr::PreparedExit, RuntimeError> {
    // Translation and executable-page preparation require the shared memory
    // lock; running guest instructions must not hold it. A guest can spin
    // indefinitely between syscalls while a sibling needs this lock to publish
    // the value that ends the spin (altstacktid/mmapfileshare_mt/telemetrymap).
    translator
        .enter_prepared::<PROFILE>(prepared, snapshot)
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))
}

fn run_native_dsr_thread_loop(
    dispatcher: Arc<SyscallDispatcher>,
    memory: SharedNativeMemory,
    reporter: Arc<CompatReporter>,
    max_traps: usize,
    plan: Arc<ExecutionPlan>,
    thread_runtime: &mut NativeThreadRuntime,
    start: NativeThreadStart,
) -> Result<NativeThreadLoopOutcome, RuntimeError> {
    if std::env::var_os("CARRICK_DSR_PROFILE").is_some() {
        run_native_dsr_thread_loop_profiled::<true>(
            dispatcher,
            memory,
            reporter,
            max_traps,
            plan,
            thread_runtime,
            start,
        )
    } else {
        run_native_dsr_thread_loop_profiled::<false>(
            dispatcher,
            memory,
            reporter,
            max_traps,
            plan,
            thread_runtime,
            start,
        )
    }
}

fn run_native_dsr_thread_loop_profiled<const PROFILE: bool>(
    dispatcher: Arc<SyscallDispatcher>,
    memory: SharedNativeMemory,
    reporter: Arc<CompatReporter>,
    max_traps: usize,
    plan: Arc<ExecutionPlan>,
    thread_runtime: &mut NativeThreadRuntime,
    start: NativeThreadStart,
) -> Result<NativeThreadLoopOutcome, RuntimeError> {
    let process_translator = memory.read().dsr_process_translator()?;
    let (mut translator, mut snapshot, mut guest_tpidr_el0) = install_native_thread_start(
        process_translator,
        start,
        &dispatcher,
        thread_runtime.tid().raw(),
    )?;
    debug_assert_eq!(translator.profiling_enabled(), PROFILE);
    let prepare: DsrPrepareFn = prepare_dsr_entry::<PROFILE>;
    let enter: DsrEnterFn = enter_dsr_prepared::<PROFILE>;
    let trace_syscalls = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
    let mut vfork_completion: Option<NativeVforkCompletion> = None;
    let mut traps = 0_usize;

    loop {
        // Republish (register, the first time) this thread's profiling state
        // for a foreign `exit_group` drain -- see `SiblingSnapshot`. Every
        // loop-top is a fully reconciled boundary: the prior iteration's
        // counters (if any) are already fully advanced by this point. A
        // no-op when profiling is disabled.
        if PROFILE {
            translator.publish_sibling_snapshot();
        }
        traps = traps.saturating_add(1);
        if traps > max_traps {
            return Err(RuntimeError::TrapLimitExceeded { max_traps });
        }
        // A kick out of DSR-translated code returns to this lock-free dispatch
        // boundary. Fork may park the thread here, and a successful execve by
        // another thread must retire it before it can re-enter the old image.
        // The placement descends from the removed direct executor, but DSR is
        // the only native instruction engine now.
        if crate::fork_quiesce::exec_replacing_other_thread(thread_runtime.tid()) {
            if thread_runtime.finish_thread(&dispatcher, &memory) {
                finalize_native_process_exit(&mut translator, &memory);
                return Ok(NativeThreadLoopOutcome::ProcessExit(0));
            }
            return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
        }
        let loop_timer = if PROFILE {
            Some(dsr::profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        thread_runtime.park_for_fork_quiesce();
        if let Some(loop_timer) = loop_timer {
            translator
                .add_profile_phase(dsr::profile::Phase::LoopQuiesce, loop_timer)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }

        let prepare_timer = if PROFILE {
            Some(dsr::profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        let prepared = prepare(&mut translator, &memory, &snapshot)?;
        if let Some(prepare_timer) = prepare_timer {
            translator
                .add_profile_phase(dsr::profile::Phase::PrepareIndex, prepare_timer)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }

        let run_timer = if PROFILE {
            Some(dsr::profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        let raw_exit = enter(&mut translator, prepared, &mut snapshot)?;
        if let Some(run_timer) = run_timer {
            translator
                .add_profile_phase(dsr::profile::Phase::TranslatedRun, run_timer)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }

        if PROFILE {
            let exit_class = raw_exit.profile_class();
            translator
                .record_profile_exit(exit_class)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }
        let finish_timer = if PROFILE {
            Some(dsr::profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        let exit = translator
            .finish_exit_profiled::<PROFILE>(&memory.read(), &mut snapshot, prepared, raw_exit)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        if let Some(finish_timer) = finish_timer {
            translator
                .add_profile_phase(dsr::profile::Phase::FinishExit, finish_timer)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }
        let resume = match exit {
            dsr::ThreadExit::Syscall { resume } => resume,
            dsr::ThreadExit::Continue => continue,
            dsr::ThreadExit::Sensitive(exit) => {
                let sensitive_timer = if PROFILE {
                    Some(dsr::profile::PhaseTimer::start_if::<true>())
                } else {
                    None
                };
                let sensitive_class = if PROFILE {
                    Some(exit.kind.profile_class())
                } else {
                    None
                };
                let required_register = || {
                    exit.register.ok_or_else(|| {
                        RuntimeError::Unsupported(format!(
                            "native DSR sensitive {:?} exit has no register",
                            exit.kind
                        ))
                    })
                };
                match exit.kind {
                    dsr::types::SensitiveKind::Exclusive(word) => {
                        let guest_pc = exit.resume.raw().checked_sub(4).ok_or_else(|| {
                            RuntimeError::Unsupported(
                                "native DSR exclusive resume PC underflow".to_string(),
                            )
                        })?;
                        emulate_dsr_exclusive_access(
                            &memory.read(),
                            &mut snapshot,
                            &mut thread_runtime.exclusive_reservation,
                            word,
                            guest_pc,
                        )?;
                    }
                    dsr::types::SensitiveKind::ReadTpidr => {
                        let register = required_register()?;
                        if !native_snapshot_write_reg(&mut snapshot, register, guest_tpidr_el0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write TPIDR result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::WriteTpidr => {
                        let register = required_register()?;
                        guest_tpidr_el0 = native_snapshot_read_reg(&snapshot, register)
                            .ok_or_else(|| {
                                RuntimeError::Unsupported(format!(
                                    "native DSR could not read TPIDR source {register}"
                                ))
                            })?;
                    }
                    dsr::types::SensitiveKind::ReadCounter => {
                        #[cfg(target_os = "macos")]
                        if let Some(register) = exit.register {
                            let ticks = dsr::fallback_counter_ticks().ok_or_else(|| {
                                RuntimeError::Unsupported(
                                    "native DSR counter fallback has no exact host scale"
                                        .to_string(),
                                )
                            })?;
                            if !native_snapshot_write_reg(&mut snapshot, register, ticks) {
                                return Err(RuntimeError::Unsupported(format!(
                                    "native DSR could not write counter result to {register}"
                                )));
                            }
                        }
                        #[cfg(not(target_os = "macos"))]
                        return Err(RuntimeError::Unsupported(
                            "native DSR counter fallback requires macOS".to_string(),
                        ));
                    }
                    dsr::types::SensitiveKind::ReadCtr => {
                        let register = required_register()?;
                        if !native_snapshot_write_reg(&mut snapshot, register, NATIVE_CTR_EL0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write CTR_EL0 result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::ReadDczid => {
                        let register = required_register()?;
                        if !native_snapshot_write_reg(&mut snapshot, register, NATIVE_DCZID_EL0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write DCZID_EL0 result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::DcZva => {
                        let register = required_register()?;
                        let address =
                            native_snapshot_read_reg(&snapshot, register).ok_or_else(|| {
                                RuntimeError::Unsupported(format!(
                                    "native DSR could not read dc zva source {register}"
                                ))
                            })?;
                        native_dc_zva(&memory, address)?;
                    }
                    dsr::types::SensitiveKind::DcCvau | dsr::types::SensitiveKind::IcIvau => {}
                }
                snapshot.pc = exit.resume.raw();
                if let Some(sensitive_class) = sensitive_class {
                    translator
                        .record_profile_sensitive(sensitive_class)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                }
                if let Some(sensitive_timer) = sensitive_timer {
                    translator
                        .add_profile_phase(dsr::profile::Phase::SensitiveEmulation, sensitive_timer)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                }
                continue;
            }
            dsr::ThreadExit::Fault { kind, address } => {
                let (signal, code) = match kind {
                    dsr::ThreadFault::Host { signal, code } => (signal, code),
                    dsr::ThreadFault::Guest { signum, code } => (signum, code),
                };
                crate::event_ring::rec_dsr_fault(
                    snapshot.pc,
                    address.raw(),
                    signal,
                    snapshot.esr,
                    snapshot.sp,
                    snapshot.x[30],
                );
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace dsr fault signal={signal} code={code} guest_pc=0x{:x} address=0x{:x} esr=0x{:x} far=0x{:x}\n",
                            snapshot.pc,
                            address.raw(),
                            snapshot.esr,
                            snapshot.far,
                        )
                        .as_bytes(),
                    );
                }
                if matches!(kind, dsr::ThreadFault::Host { .. })
                    && !matches!(signal, libc::SIGSEGV | libc::SIGBUS | libc::SIGTRAP)
                {
                    return Err(RuntimeError::Unsupported(format!(
                        "native DSR trapped unexpected host signal {signal} at guest PC 0x{:x}",
                        snapshot.pc
                    )));
                }
                snapshot = lower_dsr_fault(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    thread_runtime.registry.live_count(),
                    &mut thread_runtime.exclusive_reservation,
                    kind,
                    address,
                    &mut translator,
                )?;
                continue;
            }
            dsr::ThreadExit::Kick => {
                let interrupted_pc = snapshot.pc;
                snapshot = deliver_dsr_pending_signal(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    None,
                    Some(interrupted_pc),
                    &mut translator,
                )?;
                continue;
            }
            dsr::ThreadExit::Unsupported(detail) => {
                return Err(RuntimeError::Unsupported(format!(
                    "native DSR produced unsupported exit {detail}"
                )));
            }
        };

        let request = SyscallRequest::new(
            snapshot.x[8],
            SyscallArgs([
                snapshot.x[0],
                snapshot.x[1],
                snapshot.x[2],
                snapshot.x[3],
                snapshot.x[4],
                snapshot.x[5],
            ]),
        )
        .with_current_guest_sp(Some(snapshot.sp));
        let service_number = request.number.raw();
        let service_name = carrick_abi::syscall::lookup_aarch64(service_number)
            .map_or("unknown", |syscall| syscall.name);
        let mut service = NativeSyscallServiceSpan::open(service_number, service_name);
        if trace_syscalls {
            child_write_stderr(
                format!(
                    "native trace dsr pid={} tid={} pc=0x{:x} nr={} args={:x},{:x},{:x},{:x},{:x},{:x}\n",
                    unsafe { libc::getpid() },
                    thread_runtime.tid().raw(),
                    snapshot.pc,
                    request.number.raw(),
                    request.args.0[0],
                    request.args.0[1],
                    request.args.0[2],
                    request.args.0[3],
                    request.args.0[4],
                    request.args.0[5],
                )
                .as_bytes(),
            );
        }
        let dispatch_timer = if PROFILE {
            Some(dsr::profile::PhaseTimer::start_if::<true>())
        } else {
            None
        };
        let timed_outcome = dispatch_native_syscall::<PROFILE>(
            &dispatcher,
            request,
            &memory,
            thread_runtime,
            &reporter,
            trace_syscalls,
        )?;
        if let Some(dispatch_timer) = dispatch_timer {
            let dispatch_ns = match dispatch_timer.elapsed_ns() {
                Ok(dispatch_ns) => dispatch_ns,
                Err(error) => {
                    let error = translator.invalidate_profile(error);
                    return Err(RuntimeError::Unsupported(error.to_string()));
                }
            };
            let active_dispatch_ns = match dispatch_ns.checked_sub(timed_outcome.blocked.wall_ns) {
                Some(active_dispatch_ns) => active_dispatch_ns,
                None => {
                    let error = translator
                        .invalidate_profile(dsr::profile::ProfileError::DispatchTimeUnderflow);
                    return Err(RuntimeError::Unsupported(error.to_string()));
                }
            };
            translator
                .add_profile_phase_ns(dsr::profile::Phase::Blocked, timed_outcome.blocked.wall_ns)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
            translator
                .add_profile_blocked_cpu_ns(timed_outcome.blocked.cpu_ns)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
            translator
                .add_profile_phase_ns(dsr::profile::Phase::SyscallDispatch, active_dispatch_ns)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        }
        let outcome = timed_outcome.outcome;
        if matches!(outcome, DispatchOutcome::Returned { value: 0 })
            && carrick_abi::syscall::lookup_aarch64(request.number.raw())
                .is_some_and(|syscall| syscall.name == "rt_sigaction")
            && unsafe { carrick_native_install_dsr_signal_handlers() } != 0
        {
            return Err(last_io_error(
                "restore native DSR transport after rt_sigaction",
            ));
        }
        match outcome {
            DispatchOutcome::Returned { value } => {
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    value,
                    resume,
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "resume end",
                )?;
            }
            DispatchOutcome::Errno { errno } => {
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    errno.guest_retval(),
                    resume,
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "errno resume end",
                )?;
            }
            DispatchOutcome::SigReturn => {
                snapshot = complete_dsr_sigreturn(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "signal return end",
                )?;
            }
            DispatchOutcome::Exit { code } => {
                require_native_syscall_service_transition(
                    service.terminal_handoff(),
                    "process-exit terminal handoff",
                )?;
                // Fire before anything below: the forked-child arm ends in
                // `_exit(2)`, so a probe placed after it never runs and every
                // guest process that is not the container's pid 1 would be
                // missing its exit event -- which is exactly the population a
                // process-lifecycle census is measuring.
                crate::probes::guest_exit(code);
                // `exit_group` (or `exit(2)` as the last live thread): every
                // OTHER live guest thread of this process dies unconditionally
                // and instantly at the `libc::_exit()` below, with zero chance
                // to flush its own NATIVEPERF record -- emit one for each of
                // them now, before that happens, then this thread's own last.
                finalize_native_process_exit(&mut translator, &memory);
                if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire) {
                    dispatcher.cleanup_sysv_ipc_on_process_exit();
                    crate::exec_helpers::forked_child_exit(
                        code,
                        dispatcher.stdout(),
                        dispatcher.stderr(),
                    );
                }
                return Ok(NativeThreadLoopOutcome::ProcessExit(code));
            }
            DispatchOutcome::ThreadExit { code } => {
                let outcome = finalize_native_thread_exit(
                    &mut translator,
                    thread_runtime,
                    &dispatcher,
                    &memory,
                    code,
                );
                match outcome {
                    NativeThreadLoopOutcome::ProcessExit(_) => {
                        require_native_syscall_service_transition(
                            service.terminal_handoff(),
                            "last-thread terminal handoff",
                        )?;
                    }
                    NativeThreadLoopOutcome::ThreadDone => {
                        require_native_syscall_service_transition(
                            service.end(NativeSyscallServiceOutcome::ThreadExit),
                            "thread-exit end",
                        )?;
                    }
                    NativeThreadLoopOutcome::ExecReplacedThread => {
                        return Err(RuntimeError::Unsupported(
                            "native thread exit unexpectedly reported exec replacement".to_string(),
                        ));
                    }
                }
                return Ok(outcome);
            }
            DispatchOutcome::CloneThread {
                stack,
                tls,
                flags: _,
                parent_tid_addr,
                child_tid_addr,
                clear_child_tid_addr,
            } => {
                let clone_rejection = native_clone_thread_rejection(&memory);
                if let Some(reason) = clone_rejection {
                    let syscall_name = if request.number.raw() == 435 {
                        "clone3"
                    } else {
                        "clone"
                    };
                    reporter.record(crate::compat::CompatEvent::partial_syscall(
                        request.number.raw(),
                        syscall_name,
                        request.args,
                        reason,
                    ));
                    snapshot = complete_dsr_syscall(
                        &dispatcher,
                        &memory,
                        snapshot,
                        thread_runtime.tid(),
                        request.number.raw(),
                        crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval(),
                        resume,
                        &mut translator,
                    )?;
                    require_native_syscall_service_transition(
                        service.end(NativeSyscallServiceOutcome::Resume),
                        "rejected clone resume end",
                    )?;
                    continue;
                }
                require_native_syscall_service_transition(
                    service.branch(NativeSyscallBranchKind::Thread),
                    "thread branch",
                )?;
                let tid = thread_runtime.spawn_clone_thread(
                    &dispatcher,
                    &memory,
                    &reporter,
                    &plan,
                    max_traps,
                    NativeCloneThreadRequest {
                        context: snapshot,
                        resume_pc: resume.raw(),
                        parent_guest_tpidr_el0: guest_tpidr_el0,
                        stack,
                        tls,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                        service_number,
                        service_name,
                    },
                )?;
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    i64::from(tid.raw()),
                    resume,
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "clone parent resume end",
                )?;
            }
            DispatchOutcome::Fork {
                pidfd_out,
                clone_parent,
                parent_tid_addr,
                child_tid_addr,
                exit_signal,
                child_stack,
                vfork,
            } => {
                let vfork_rejection = vfork
                    .is_some()
                    .then(|| memory.read().native16k_vfork_rejection())
                    .flatten();
                if let Some(reason) = vfork_rejection {
                    let syscall_name = if request.number.raw() == 435 {
                        "clone3"
                    } else {
                        "clone"
                    };
                    reporter.record(crate::compat::CompatEvent::partial_syscall(
                        request.number.raw(),
                        syscall_name,
                        request.args,
                        reason,
                    ));
                    snapshot = complete_dsr_syscall(
                        &dispatcher,
                        &memory,
                        snapshot,
                        thread_runtime.tid(),
                        request.number.raw(),
                        crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval(),
                        resume,
                        &mut translator,
                    )?;
                    require_native_syscall_service_transition(
                        service.end(NativeSyscallServiceOutcome::Resume),
                        "rejected fork resume end",
                    )?;
                    continue;
                }
                let syscall_nr = request.number.raw();
                let fork_request = NativeForkRequest {
                    pidfd_out,
                    clone_parent,
                    parent_tid_addr,
                    child_tid_addr,
                    exit_signal,
                    child_stack,
                    vfork,
                    guest_pc: snapshot.pc,
                    guest_pstate: snapshot.pstate,
                };
                match handle_native_fork(
                    &dispatcher,
                    &memory,
                    thread_runtime,
                    &mut vfork_completion,
                    fork_request,
                    &mut service,
                )? {
                    NativeForkFlow::Resume {
                        value,
                        fork_child,
                        child_stack,
                    } => {
                        if fork_child {
                            // The LAST post-fork repair before the child's
                            // guest is resumable, and the one the fork handler
                            // cannot time (the translator lives here). Closing
                            // the child's `fork-pre`/`fork-post` bracket after
                            // it means the bracket spans everything the guest
                            // actually waits for.
                            repair_native_fork_child_before_resume(
                                &mut translator,
                                thread_runtime.tid().raw(),
                                &mut snapshot,
                                child_stack,
                            )?;
                        }
                        snapshot = complete_dsr_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            thread_runtime.tid(),
                            syscall_nr,
                            value,
                            resume,
                            &mut translator,
                        )?;
                        require_native_syscall_service_transition(
                            service.end(NativeSyscallServiceOutcome::Resume),
                            "fork branch resume end",
                        )?;
                    }
                    NativeForkFlow::RetireForExec => {
                        if thread_runtime.finish_thread(&dispatcher, &memory) {
                            finalize_native_process_exit(&mut translator, &memory);
                            require_native_syscall_service_transition(
                                service.terminal_handoff(),
                                "fork retirement terminal handoff",
                            )?;
                            return Ok(NativeThreadLoopOutcome::ProcessExit(0));
                        }
                        require_native_syscall_service_transition(
                            service.end(NativeSyscallServiceOutcome::ThreadExit),
                            "fork retirement thread end",
                        )?;
                        return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
                    }
                }
            }
            DispatchOutcome::Execve { path, argv, env } => {
                // Same probe, same position as the shared (`runtime.rs`) and
                // FreeBSD native lanes: it names the image a guest process is
                // becoming, and is the only event that identifies a guest
                // process to a tracer. Without it a toolchain workload is an
                // anonymous wall of host pids.
                crate::probes::execve_argv(&path, &argv);
                if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire) {
                    native_reexec_lifecycle(
                        carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreflightBegin,
                    );
                }
                let capsule_env = env.clone();
                let proc_argv: Vec<String> = argv
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect();
                let host_process_name = proc_argv.join(" ");
                let proc_env = env.clone();
                match load_native_execve_image(&dispatcher, &path, argv, env, &plan) {
                    Ok((
                        image,
                        relative_relocations,
                        resolved,
                        resolved_argv,
                        executable_digest,
                    )) => {
                        if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire) {
                            if let Err(reason) = dispatcher.validate_native_reexec_fd_state() {
                                tracing::warn!(
                                    %reason,
                                    descriptors = ?dispatcher.native_reexec_fd_state_summary(),
                                    "native fork-child host self-reexec rejected unsupported fd state"
                                );
                                snapshot = complete_dsr_syscall(
                                    &dispatcher,
                                    &memory,
                                    snapshot,
                                    thread_runtime.tid(),
                                    request.number.raw(),
                                    crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval(),
                                    resume,
                                    &mut translator,
                                )?;
                                require_native_syscall_service_transition(
                                    service.end(NativeSyscallServiceOutcome::Resume),
                                    "rejected host self-exec resume end",
                                )?;
                                continue;
                            }
                            publish_native_shared_candidates(&translator, &memory);
                            translator.finalize_profile_epoch();
                            require_native_syscall_service_transition(
                                service.terminal_handoff(),
                                "host self-exec terminal handoff",
                            )?;
                            if let Err(error) = crate::native_exec_capsule::begin_guest_exec(
                                &dispatcher,
                                &image,
                                &relative_relocations,
                                resolved.clone(),
                                resolved_argv,
                                capsule_env,
                                executable_digest,
                                max_traps,
                                &plan,
                            ) {
                                require_native_syscall_service_transition(
                                    service.reopen_after_failed_terminal_handoff(),
                                    "failed host self-exec reopen",
                                )?;
                                translator.start_next_profile_era_same_image();
                                tracing::warn!(
                                    %error,
                                    path = resolved,
                                    "native fork-child host self-reexec preparation failed"
                                );
                                snapshot = complete_dsr_syscall(
                                    &dispatcher,
                                    &memory,
                                    snapshot,
                                    thread_runtime.tid(),
                                    request.number.raw(),
                                    crate::linux_abi::LINUX_EIO.guest_retval(),
                                    resume,
                                    &mut translator,
                                )?;
                                require_native_syscall_service_transition(
                                    service.end(NativeSyscallServiceOutcome::Resume),
                                    "failed host self-exec resume end",
                                )?;
                                continue;
                            }
                            require_native_syscall_service_transition(
                                service.reopen_after_failed_terminal_handoff(),
                                "unexpected host self-exec return reopen",
                            )?;
                            return Err(RuntimeError::Unsupported(
                                "native host self-reexec unexpectedly returned successfully"
                                    .to_owned(),
                            ));
                        }
                        // Retain both consumers of the resolved identity before
                        // mapped-memory retirement. The dispatcher path and the
                        // compatibility path are then moved, never cloned, in
                        // the fatal-only portion of the transition.
                        let dispatcher_resolved_path = resolved.clone();
                        let guest_image =
                            NativeGuestImageCompatibility::from_image(&image, resolved);
                        // This branch is now committed to the in-process path.
                        // Collect host dyld metadata while the retiring image is
                        // still authoritative; publication after activation only
                        // borrows this immutable payload.
                        let host_images =
                            PROFILE.then(crate::probes::prepare_host_image_publication);
                        let entry = image.entry();
                        let Some(initial_sp) = image.initial_stack_pointer() else {
                            snapshot = complete_dsr_syscall(
                                &dispatcher,
                                &memory,
                                snapshot,
                                thread_runtime.tid(),
                                request.number.raw(),
                                crate::linux_abi::LINUX_ENOEXEC.guest_retval(),
                                resume,
                                &mut translator,
                            )?;
                            require_native_syscall_service_transition(
                                service.end(NativeSyscallServiceOutcome::Resume),
                                "invalid exec image resume end",
                            )?;
                            continue;
                        };
                        // Select and reserve the replacement host layout and
                        // allocate its translator before Linux's point of no
                        // return. A collision or allocation failure leaves the
                        // old image, sibling set, dispatcher, and DSR cache live.
                        let prepared_mapping = {
                            let memory = memory.read();
                            memory.prepare_exec_mapping(&image, plan.page_geometry)
                        };
                        let prepared_mapping = match prepared_mapping {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    path = guest_image.resolved_path.as_str(),
                                    "native execve replacement validation failed before image retirement"
                                );
                                snapshot = complete_dsr_syscall(
                                    &dispatcher,
                                    &memory,
                                    snapshot,
                                    thread_runtime.tid(),
                                    request.number.raw(),
                                    crate::linux_abi::LINUX_ENOMEM.guest_retval(),
                                    resume,
                                    &mut translator,
                                )?;
                                require_native_syscall_service_transition(
                                    service.end(NativeSyscallServiceOutcome::Resume),
                                    "rejected exec mapping resume end",
                                )?;
                                continue;
                            }
                        };
                        match native_terminate_siblings_for_exec(
                            &dispatcher,
                            &memory,
                            thread_runtime,
                        )? {
                            NativeExecTeardownFlow::Proceed => {}
                            NativeExecTeardownFlow::RetireForExec => {
                                if thread_runtime.finish_thread(&dispatcher, &memory) {
                                    finalize_native_process_exit(&mut translator, &memory);
                                    require_native_syscall_service_transition(
                                        service.terminal_handoff(),
                                        "exec retirement terminal handoff",
                                    )?;
                                    return Ok(NativeThreadLoopOutcome::ProcessExit(0));
                                }
                                require_native_syscall_service_transition(
                                    service.end(NativeSyscallServiceOutcome::ThreadExit),
                                    "exec retirement thread end",
                                )?;
                                return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
                            }
                        }
                        publish_native_shared_candidates(&translator, &memory);
                        // Exec quiescence has retired every sibling and no
                        // translated guest frame remains live. Clear the sole
                        // surviving thread's cached targets before mapped
                        // memory retires sidecar cells and their authorities.
                        // No guest execution resumes until `reset_for_exec`
                        // installs the replacement process below.
                        let mut exec_reset_token = translator
                            .prepare_direct_binding_exec_reset()
                            .map_err(|error| {
                                RuntimeError::Trap(TrapError::Hypervisor(format!(
                                    "native execve could not mint retiring translator authority: {error}"
                                )))
                            })?;
                        memory
                            .replace_image(
                                &image,
                                &relative_relocations,
                                plan.page_geometry,
                                &translator,
                                &mut exec_reset_token,
                                prepared_mapping,
                            )
                            .map_err(|error| {
                                RuntimeError::Trap(TrapError::Hypervisor(format!(
                                    "native execve failed after retiring the old owned address space: {error}"
                                )))
                            })?;
                        {
                            let memory = memory.read();
                            memory
                                .configure_shared_translation(
                                    &image,
                                    plan.page_geometry.native_profile.ok_or_else(|| {
                                        RuntimeError::Unsupported(
                                            "native exec replacement has no page profile"
                                                .to_string(),
                                        )
                                    })?,
                                    Some(executable_digest),
                                    Arc::new(
                                        carrick_native_darwin::aot_cache::ActiveContainerUnitStore,
                                    ),
                                )
                                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                        }
                        // Publish process-visible exec state only after the
                        // complete replacement mapping, vvar, relocations, and
                        // translator allocation have succeeded. Before this
                        // point a validation failure returned to the old image;
                        // after retirement, failure is fatal and no partial
                        // dispatcher identity may escape.
                        dispatcher.reset_memory_state_on_execve();
                        dispatcher.reset_signal_handlers_on_execve();
                        dispatcher.set_executable_identity(
                            dispatcher_resolved_path,
                            proc_argv,
                            proc_env,
                        );
                        crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
                        dispatcher.close_cloexec_fds();
                        translator.begin_exec_reset();
                        translator.begin_exec_handoff();
                        let next_process = memory.read().dsr_process_translator()?;
                        complete_native_in_process_exec_handoff(
                            next_process,
                            host_images.as_ref(),
                            &guest_image,
                            &mut translator,
                            entry,
                            initial_sp,
                            &dispatcher,
                            &mut service,
                            &mut snapshot,
                            &mut guest_tpidr_el0,
                            || {
                                crate::namespace::pid::mark_self_execed();
                                crate::dispatch::set_host_process_name(
                                    host_process_name.as_bytes(),
                                );
                                if let Some(mut completion) = vfork_completion.take() {
                                    completion.notify();
                                }
                            },
                        )?;
                    }
                    Err(errno) => {
                        snapshot = complete_dsr_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            thread_runtime.tid(),
                            request.number.raw(),
                            errno.guest_retval(),
                            resume,
                            &mut translator,
                        )?;
                        require_native_syscall_service_transition(
                            service.end(NativeSyscallServiceOutcome::Resume),
                            "exec error resume end",
                        )?;
                    }
                }
            }
            DispatchOutcome::MapHostAlias {
                transaction,
                va,
                ipa: _,
                len,
                payload,
                file,
                prot_none,
                ..
            } => {
                let file = file.map(|(fd, offset, prot)| (fd.into_owned_fd(), offset, prot));
                let retval = match transaction.claim() {
                    None => {
                        drop(file);
                        crate::linux_abi::LINUX_ENOMEM.guest_retval()
                    }
                    Some(install) => {
                        let mut mapped_memory = memory.write();
                        if mapped_memory
                            .map_host_alias(
                                va.raw(),
                                len,
                                &payload,
                                file.map(|(fd, offset, prot)| (fd.into_raw_fd(), offset, prot)),
                                prot_none,
                            )
                            .is_err()
                        {
                            std::process::abort();
                        }
                        if let Some((bus_start, bus_len)) = install.bus_fault_range() {
                            let Ok(bus_len) = usize::try_from(bus_len) else {
                                std::process::abort();
                            };
                            if mapped_memory.protect_range(bus_start, bus_len, 0).is_err() {
                                std::process::abort();
                            }
                            mapped_memory.set_no_access(bus_start, bus_len, true);
                        }
                        if dispatcher.commit_host_alias_install(install).is_err() {
                            std::process::abort();
                        }
                        drop(mapped_memory);
                        va.raw() as i64
                    }
                };
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    retval,
                    resume,
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "mapped alias resume end",
                )?;
            }
            DispatchOutcome::SignalThread {
                tid: target,
                signum,
            } => {
                let value = thread_runtime.signal_thread(target, signum);
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    value,
                    resume,
                    &mut translator,
                )?;
                require_native_syscall_service_transition(
                    service.end(NativeSyscallServiceOutcome::Resume),
                    "signal-thread resume end",
                )?;
            }
            DispatchOutcome::SignalDeath { signum } => {
                require_native_syscall_service_transition(
                    service.terminal_handoff(),
                    "signal-death terminal handoff",
                )?;
                native_die_by_signal(&dispatcher, &mut translator, signum);
            }
            other => {
                return Err(RuntimeError::Unsupported(format!(
                    "native DSR does not support dispatcher outcome {other:?}"
                )));
            }
        }
    }
}

fn deliver_dsr_pending_signal(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    return_value: Option<i64>,
    interrupted_pc: Option<u64>,
    translator: &mut dsr::ThreadTranslator,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let memory = memory.read();
    let mut trap = NativeSignalTrap::new(&memory, snapshot, None);
    let action = crate::vcpu_loop::deliver_pending_signal(
        &mut trap,
        dispatcher,
        return_value,
        tid,
        interrupted_pc,
    )?;
    if let Some(action) = action {
        if let Some(signum) = action.stop_signal {
            crate::exec_helpers::stop_by_signal(signum);
        }
        if let Some(signum) = action.term_signal {
            native_die_by_signal(dispatcher, translator, signum);
        }
    }
    Ok(trap.into_snapshot())
}

#[allow(clippy::too_many_arguments)]
fn complete_dsr_syscall(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    syscall_nr: u64,
    return_value: i64,
    resume: carrick_guest_mem::GuestVa,
    translator: &mut dsr::ThreadTranslator,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let memory = memory.read();
    let mut trap = NativeSignalTrap::new(&memory, snapshot, Some(syscall_nr));
    trap.complete_syscall(return_value)?;
    trap.set_pc(resume.raw());
    let action = crate::vcpu_loop::deliver_pending_signal(
        &mut trap,
        dispatcher,
        Some(return_value),
        tid,
        None,
    )?;
    if let Some(action) = action {
        if let Some(signum) = action.stop_signal {
            crate::exec_helpers::stop_by_signal(signum);
        }
        if let Some(signum) = action.term_signal {
            native_die_by_signal(dispatcher, translator, signum);
        }
    }
    Ok(trap.into_snapshot())
}

fn complete_dsr_sigreturn(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    translator: &mut dsr::ThreadTranslator,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let memory = memory.read();
    let mut trap = NativeSignalTrap::new(&memory, snapshot, None);
    let action = sigreturn_restore_and_deliver(dispatcher, &mut trap, tid)?;
    if let Some(action) = action {
        if let Some(signum) = action.stop_signal {
            crate::exec_helpers::stop_by_signal(signum);
        }
        if let Some(signum) = action.term_signal {
            native_die_by_signal(dispatcher, translator, signum);
        }
    }
    Ok(trap.into_snapshot())
}

#[allow(clippy::too_many_arguments)]
fn lower_dsr_fault(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    mut snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    live_threads: usize,
    reservation: &mut Option<NativeExclusiveReservation>,
    fault: dsr::ThreadFault,
    fault_address: dsr::ThreadFaultAddress,
    translator: &mut dsr::ThreadTranslator,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let host_fault = matches!(fault_address, dsr::ThreadFaultAddress::Host(_));
    // Lock-free (Task 8): this only needs `address_mode`, so read it via
    // `NativeMemoryHandle` instead of taking the big memory `RwLock` just to
    // immediately drop the guard again.
    let biased_host_fault =
        host_fault && matches!(memory.address_mode(), NativeAddressMode::Biased { .. });
    let fault_address = lower_dsr_fault_address(&memory.read(), fault_address)
        .map_err(|error| {
            let resolver = translator.resolver_stats();
            RuntimeError::Unsupported(format!(
                "{error}; recovered_guest_pc=0x{:x} shared_unit_hits={} shared_blocks_mapped={}",
                snapshot.pc, resolver.shared_unit_hits, resolver.shared_blocks_mapped,
            ))
        })?
        .raw();
    if biased_host_fault {
        // Lock-free (Phase 0): the Biased-mode reverse translation only
        // needs `address_mode`/`owned_host_ranges`, both served by the
        // lock-free `NativeMemoryConfig` -- no need to take the big memory
        // `RwLock` just for this.
        if snapshot.far != 0 {
            let far = usize::try_from(snapshot.far)
                .ok()
                .and_then(|far| memory.biased_guest_fault_address(carrick_guest_mem::HostVa(far)));
            snapshot.far = far
                .ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native DSR FAR lies outside guest-owned host memory: 0x{:x}",
                        snapshot.far
                    ))
                })?
                .raw();
        }
        if snapshot.fault_address != 0 {
            let snapshot_fault = usize::try_from(snapshot.fault_address)
                .ok()
                .and_then(|address| {
                    memory.biased_guest_fault_address(carrick_guest_mem::HostVa(address))
                });
            snapshot.fault_address = snapshot_fault
                .ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native DSR signal fault address lies outside guest-owned host memory: 0x{:x}",
                        snapshot.fault_address
                    ))
                })?
                .raw();
        }
    }
    if matches!(fault, dsr::ThreadFault::Host { .. })
        && let Some(plan) = dispatcher.resident_fault_plan(fault_address)
    {
        let mut memory = memory.write();
        let linux_page_size = memory.linux_page_size as usize;
        if memory
            .protect_range(plan.page(), linux_page_size, plan.prot())
            .is_ok()
        {
            drop(memory);
            dispatcher.commit_resident_fault(plan);
            return Ok(snapshot);
        }
    }
    if matches!(fault, dsr::ThreadFault::Host { .. })
        && memory.write().resolve_native16k_write_exec_fault(
            fault_address,
            snapshot.pc,
            snapshot.esr,
        )?
    {
        return Ok(snapshot);
    }
    if matches!(fault, dsr::ThreadFault::Host { .. })
        && memory.read().linux4k_address_is_guarded(fault_address)
    {
        if live_threads > 1 {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded-page access at 0x{fault_address:x} from a \
                 multithreaded guest is not yet supported: the 4K-on-16K \
                 guarded-page fault emulation is not multithread-safe"
            )));
        }
        emulate_linux4k_guarded_fault(&mut memory.write(), &mut snapshot, reservation)?;
        return Ok(snapshot);
    }
    let (mut signum, mut si_code, si_addr) = match fault {
        dsr::ThreadFault::Guest { signum, code } => (signum, code, fault_address),
        dsr::ThreadFault::Host { .. } => {
            let Some(lowered) =
                crate::vcpu_loop::lower_el0_fault(snapshot.esr, snapshot.pc, fault_address)
            else {
                native_die_by_signal(dispatcher, translator, crate::linux_abi::LINUX_SIGSEGV);
            };
            lowered
        }
    };
    si_code = {
        let memory = memory.read();
        crate::vcpu_loop::upgrade_protection_si_code(&*memory, signum, si_code, si_addr)
    };
    if signum == crate::linux_abi::LINUX_SIGSEGV
        && let Some(plan) = dispatcher.mmap_growdown_fault_plan(si_addr)
    {
        let grew = memory
            .write()
            .protect_range(
                plan.start(),
                plan.len(),
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            )
            .is_ok();
        if grew {
            dispatcher.commit_mmap_growdown(plan);
            return Ok(snapshot);
        }
    }
    if signum == crate::linux_abi::LINUX_SIGSEGV && dispatcher.mmap_fault_is_sigbus(si_addr) {
        signum = crate::linux_abi::LINUX_SIGBUS;
        si_code = 2;
    }
    let interrupted_pc = snapshot.pc;
    let memory = memory.read();
    let mut trap = NativeSignalTrap::new(&memory, snapshot, None);
    let disposition = crate::vcpu_loop::inject_fault_signal(
        &mut trap,
        dispatcher,
        tid,
        signum,
        si_code,
        si_addr,
        Some(interrupted_pc),
    )?;
    match disposition {
        crate::vcpu_loop::FaultSignalDisposition::Injected => Ok(trap.into_snapshot()),
        crate::vcpu_loop::FaultSignalDisposition::Terminate(signum) => {
            native_die_by_signal(dispatcher, translator, signum)
        }
    }
}

fn lower_dsr_fault_address(
    memory: &NativeMappedMemory,
    address: dsr::ThreadFaultAddress,
) -> Result<carrick_guest_mem::GuestVa, RuntimeError> {
    match address {
        dsr::ThreadFaultAddress::Guest(address) => Ok(address),
        dsr::ThreadFaultAddress::Host(address) => match memory.address_mode() {
            NativeAddressMode::Direct => Ok(carrick_guest_mem::GuestVa(address.raw() as u64)),
            NativeAddressMode::Biased { .. } => {
                memory.guest_fault_address(address).ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native DSR fault lies outside guest-owned host memory: 0x{:x}",
                        address.raw()
                    ))
                })
            }
        },
    }
}

fn native_die_by_signal(
    dispatcher: &SyscallDispatcher,
    translator: &mut dsr::ThreadTranslator,
    signum: i32,
) -> ! {
    translator.finalize_profile_epoch();
    dispatcher.cleanup_sysv_ipc_on_process_exit();
    crate::exec_helpers::forked_child_die_by_signal(
        signum,
        dispatcher.stdout(),
        dispatcher.stderr(),
    )
}

/// Restore the interrupted context from the returning handler's sigframe,
/// then run one signal-delivery cycle at the just-restored user PC. Linux
/// delivers every deliverable pending signal before returning to the
/// interrupted context, so a second queued instance chains handler-to-handler
/// off `rt_sigreturn` instead of waiting for the next syscall or kick —
/// mirroring the HVF vCPU loop's `DispatchOutcome::SigReturn` arm, whose
/// loop tail services signals with `interrupted_pc = restored pc` (not as a
/// syscall boundary, so no retval is applied and SA_RESTART stays off).
fn sigreturn_restore_and_deliver(
    dispatcher: &SyscallDispatcher,
    trap: &mut NativeSignalTrap<'_>,
    tid: crate::thread::ThreadId,
) -> Result<Option<crate::vcpu_loop::PendingSignalAction>, RuntimeError> {
    let restored_sigmask = trap.restore_from_sigframe()?;
    dispatcher.restore_signal_mask(tid, carrick_abi::SigSet::from_raw(restored_sigmask));
    let restored_pc = trap.pc();
    crate::vcpu_loop::deliver_pending_signal(trap, dispatcher, None, tid, Some(restored_pc))
}

struct NativeSignalTrap<'a> {
    /// `&'a NativeMappedMemory` (shared, not `&mut`): every trap site
    /// constructs this from a `SharedNativeMemory::read()` guard. Its
    /// `GuestMemory::write_bytes_raw` impl below routes through
    /// `write_bytes_raw_shared`, the Phase 1 `&self` common write path --
    /// correct here because a signal frame only ever writes the guest's
    /// DATA/signal stack (`build_sigframe`/`restore_sigframe`), never an
    /// executable page, so the exec-page (`write_exec_page_bytes`) escalation
    /// this deliberately skips can never legitimately apply to a trap write.
    memory: &'a NativeMappedMemory,
    regs: NativeUcontextSnapshot,
    orig_x0: u64,
    last_syscall_nr: Option<u64>,
}

struct NativeThreadRuntime {
    tid: crate::thread::ThreadId,
    registry: Arc<crate::thread::ThreadRegistry>,
    futex: Arc<crate::thread::FutexTable>,
    platform_futex: Arc<dyn carrick_hal::PlatformFutex>,
    waiter: crate::io_wait::ThreadWaiter,
    kicker: Arc<carrick_hal::GenericVcpuRegistry>,
    signal_wake_pump: Option<crate::vcpu_kick::SignalPump>,
    kick_state: Option<Arc<NativeKickState>>,
    threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /// Per-guest-thread software reservation for DSR exclusive accesses.
    /// Host gateway/context stores clear the architectural monitor at every
    /// translated block boundary, so it cannot be the authority here.
    exclusive_reservation: Option<NativeExclusiveReservation>,
    finished: bool,
    /// True on the COW copy a fork child replaces in `reset_after_fork_child`:
    /// its `kicker` registry mutexes may have been inherited LOCKED (another
    /// parent thread mid-`kick_all` at fork time), so `Drop` must not touch
    /// them — see the fork×kick deadlock note on `Drop`.
    forked_stale: bool,
}

impl NativeThreadRuntime {
    fn new_current() -> Self {
        let tid = crate::thread::ThreadId::main_from_host_pid();
        let registry = Arc::new(crate::thread::ThreadRegistry::new(tid));
        crate::thread::set_current_registry(Arc::clone(&registry));
        let futex = Arc::new(crate::thread::FutexTable::new());
        let platform_futex = Arc::new(crate::threaded_impl::hvf_futex(Arc::clone(&futex)))
            as Arc<dyn carrick_hal::PlatformFutex>;
        let kicker = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        // Publish the fresh registry as THE process kicker (boot and fork-child
        // reset both come through here) so timer fallback threads kick the
        // live guest threads, never a stale pre-fork registry.
        install_native_process_kicker(&kicker);
        let runtime = Self {
            tid,
            registry,
            futex,
            platform_futex,
            waiter: crate::io_wait::ThreadWaiter::new(tid),
            kicker,
            signal_wake_pump: None,
            kick_state: None,
            threads: Arc::new(parking_lot::Mutex::new(Vec::new())),
            exclusive_reservation: None,
            finished: false,
            forked_stale: false,
        };
        runtime
            .registry
            .record_thread_port(runtime.tid, crate::host_proc::current_thread_port());
        runtime
    }

    fn reset_after_fork_child(&mut self) {
        // Only the calling thread survives fork; the copied JoinHandle names a
        // parent-only pump thread. Dropping it in the child would try to stop/
        // join a thread that cannot run, so abandon that COW guard and start a
        // fresh wake-only pump later, after the child registers its kick
        // target. Starting it here lets the pump consume a durable pending
        // edge against an empty registry and strand the signal forever.
        if let Some(inherited) = self.signal_wake_pump.take() {
            std::mem::forget(inherited);
        }
        self.forked_stale = true;
        *self = Self::new_current();
    }

    fn tid(&self) -> crate::thread::ThreadId {
        self.tid
    }

    fn sibling(&self, tid: crate::thread::ThreadId) -> Self {
        Self {
            tid,
            registry: Arc::clone(&self.registry),
            futex: Arc::clone(&self.futex),
            platform_futex: Arc::clone(&self.platform_futex),
            waiter: crate::io_wait::ThreadWaiter::new(tid),
            kicker: Arc::clone(&self.kicker),
            signal_wake_pump: None,
            kick_state: None,
            threads: Arc::clone(&self.threads),
            exclusive_reservation: None,
            finished: false,
            forked_stale: false,
        }
    }

    fn prepare_kick_target(&mut self) -> Result<(), RuntimeError> {
        if self.kick_state.is_some() {
            return Ok(());
        }
        if unsafe { carrick_native_install_dsr_signal_handlers() } != 0 {
            return Err(last_io_error("install native Darwin trap handler"));
        }
        let state = Arc::new(NativeKickState::new()?);
        state.bind_current()?;
        self.kicker.register(
            self.tid,
            Box::new(NativeKickHandle::for_current_thread(Arc::clone(&state))),
        );
        self.kick_state = Some(state);
        Ok(())
    }

    fn start_signal_wake_pump(&mut self) {
        if self.signal_wake_pump.is_none() {
            self.signal_wake_pump = Some(crate::vcpu_kick::spawn_signal_wake_pump(
                Arc::clone(&self.kicker) as Arc<dyn carrick_hal::VcpuRegistry>,
                Arc::clone(&self.platform_futex),
            ));
        }
    }

    fn release_kick_target(&mut self) {
        self.kicker.unregister(self.tid);
        if let Some(state) = self.kick_state.take() {
            state.unbind_current();
        }
    }

    /// Park this thread at the process fork barrier while a sibling's fork
    /// quiesce is in flight (the native analogue of HVF's
    /// `release_and_park_vcpu_for_fork`). Order is the contract the forker's
    /// drain depends on: UNREGISTER from the kicker first (the drain counts
    /// registered threads down to 1 — the forker), park second, re-register
    /// after release. The kick STATE stays bound (same host thread); only the
    /// registry entry cycles. No-op when no quiesce is in flight.
    fn park_for_fork_quiesce(&self) {
        if !crate::fork_quiesce::is_quiescing() {
            return;
        }
        self.kicker.unregister(self.tid);
        crate::fork_quiesce::barrier().park_if_quiescing();
        if let Some(state) = &self.kick_state {
            self.kicker.register(
                self.tid,
                Box::new(NativeKickHandle::for_current_thread(Arc::clone(state))),
            );
        }
    }

    /// Acquire the process-wide fork token, parking at any in-flight fork's
    /// barrier so its drain can count this thread (mirrors `handle_fork`'s
    /// token loop). Also the fork↔exec mutual exclusion: the exec teardown
    /// takes the same token, and a loser that observes an exec replacement by
    /// ANOTHER thread abandons its syscall and retires (Linux: execve kills
    /// every sibling; a concurrent fork/exec in a doomed thread never
    /// completes).
    ///
    /// SLEEPS between attempts (a `yield_now` loop burned 100% of a core for
    /// the whole time another thread held the token — worst case a vfork
    /// parent-suspend, which the guest's vfork child paces) and is BOUNDED:
    /// every legitimate holder is itself bounded (quiesce drain 10 s abort,
    /// vfork suspend 60 s, exec teardown drain 5 s), so the deadline is a
    /// backstop against an unknown holder, not a pacing bound.
    fn acquire_fork_token(&self) -> NativeForkTokenFlow {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut contended = false;
        while !crate::fork_quiesce::barrier().try_begin_fork() {
            contended = true;
            if crate::fork_quiesce::exec_replacing_other_thread(self.tid) {
                return NativeForkTokenFlow::RetireForExec;
            }
            self.park_for_fork_quiesce();
            if Instant::now() >= deadline {
                return NativeForkTokenFlow::TimedOut;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        NativeForkTokenFlow::Acquired { contended }
    }

    fn signal_thread(&self, target: crate::thread::ThreadId, signum: i32) -> i64 {
        if !self.registry.is_live(target) {
            return crate::linux_abi::LINUX_ESRCH.guest_retval();
        }
        crate::host_signal::publish_pending_for_with_wake(
            target.raw(),
            signum,
            crate::host_signal::PublicationWake::CallerManaged,
        );
        self.platform_futex.notify_signal_pending_for(target);
        self.kicker.kick(target);
        0
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_clone_thread(
        &self,
        dispatcher: &Arc<SyscallDispatcher>,
        memory: &SharedNativeMemory,
        reporter: &Arc<CompatReporter>,
        plan: &Arc<ExecutionPlan>,
        max_traps: usize,
        request: NativeCloneThreadRequest,
    ) -> Result<crate::thread::ThreadId, RuntimeError> {
        let tid = self.registry.register_child(request.clear_child_tid_addr);
        dispatcher.inherit_thread_signal_mask(self.tid, tid);
        let tid_bytes = tid.raw().to_le_bytes();
        {
            if request.parent_tid_addr != 0 {
                let _ = write_guest_ram_through_lock(memory, request.parent_tid_addr, &tid_bytes);
            }
            if request.child_tid_addr != 0 {
                let _ = write_guest_ram_through_lock(memory, request.child_tid_addr, &tid_bytes);
            }
        }

        let (context, guest_tpidr_el0) = native_clone_child_context(
            request.context,
            request.resume_pc,
            request.stack,
            request.tls,
            request.parent_guest_tpidr_el0,
        );
        let child_dispatcher = Arc::clone(dispatcher);
        let child_memory = Arc::clone(memory);
        let child_reporter = Arc::clone(reporter);
        let child_plan = Arc::clone(plan);
        let mut child_runtime = self.sibling(tid);
        let service_number = request.service_number;
        let service_name = request.service_name;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let spawn_result = std::thread::Builder::new()
            .name(format!("native-guest-tid-{tid}"))
            .spawn(move || {
                let mut inherited_service =
                    NativeSyscallServiceSpan::inherited_open(service_number, service_name);
                let mut ready = Some(ready_tx);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    child_runtime
                        .registry
                        .record_thread_port(tid, crate::host_proc::current_thread_port());
                    crate::run_state::publish_guest_tid(
                        tid.raw(),
                        crate::run_state::RunState::Running,
                    );
                    child_runtime.prepare_kick_target()?;
                    let sender = ready.take().ok_or_else(|| {
                        RuntimeError::Unsupported(
                            "native Darwin clone readiness was already published".to_string(),
                        )
                    })?;
                    sender.send(Ok(())).map_err(|_| {
                        RuntimeError::Unsupported(
                            "native Darwin clone parent dropped readiness channel".to_string(),
                        )
                    })?;
                    require_native_syscall_service_transition(
                        inherited_service.end(NativeSyscallServiceOutcome::Resume),
                        "clone child resume end",
                    )?;
                    run_native_thread_loop(
                        Arc::clone(&child_dispatcher),
                        Arc::clone(&child_memory),
                        child_reporter,
                        max_traps,
                        child_plan,
                        &mut child_runtime,
                        NativeThreadStart::Detached {
                            context: Box::new(context),
                            guest_tpidr_el0,
                        },
                    )
                }));
                match result {
                    Ok(Ok(NativeThreadLoopOutcome::ProcessExit(code))) => unsafe {
                        libc::_exit(code);
                    },
                    // A spawned sibling retired by an exec replacement ends
                    // exactly like a normal thread exit; only the INITIAL
                    // thread's caller distinguishes the two.
                    Ok(Ok(
                        NativeThreadLoopOutcome::ThreadDone
                        | NativeThreadLoopOutcome::ExecReplacedThread,
                    )) => {}
                    Ok(Err(err)) => {
                        if let Some(sender) = ready.take() {
                            let _ = sender.send(Err(err.to_string()));
                            child_runtime.finish_thread(&child_dispatcher, &child_memory);
                            return;
                        }
                        child_write_stderr(
                            format!("native Darwin guest thread {tid} error: {err}\n").as_bytes(),
                        );
                        child_runtime.finish_thread(&child_dispatcher, &child_memory);
                        unsafe { libc::_exit(125) };
                    }
                    Err(_) => {
                        if let Some(sender) = ready.take() {
                            let _ = sender
                                .send(Err("native Darwin guest thread panicked during startup"
                                    .to_string()));
                            child_runtime.finish_thread(&child_dispatcher, &child_memory);
                            return;
                        }
                        child_write_stderr(
                            format!("native Darwin guest thread {tid} panicked\n").as_bytes(),
                        );
                        child_runtime.finish_thread(&child_dispatcher, &child_memory);
                        unsafe { libc::_exit(125) };
                    }
                }
            });
        let handle = match spawn_result {
            Ok(handle) => handle,
            Err(err) => {
                let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
                self.registry.exit(tid);
                crate::host_signal::forget_thread(tid.raw());
                dispatcher.forget_thread_signal_state(tid);
                return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn native Darwin guest thread failed: {err}"
                ))));
            }
        };
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(message)) => {
                let _ = handle.join();
                return Err(RuntimeError::Unsupported(message));
            }
            Err(_) => {
                let _ = handle.join();
                return Err(RuntimeError::Unsupported(
                    "native Darwin guest thread exited before kick readiness".to_string(),
                ));
            }
        }
        self.threads.lock().push(handle);
        Ok(tid)
    }

    fn finish_thread(
        &mut self,
        dispatcher: &SyscallDispatcher,
        memory: &SharedNativeMemory,
    ) -> bool {
        if self.finished {
            return false;
        }
        let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
        self.finished = true;
        self.release_kick_target();
        if let Some(address) = self.registry.clear_child_tid(self.tid)
            && address != 0
        {
            let _ = write_guest_ram_through_lock(memory, address, &0_i32.to_le_bytes());
            self.futex.wake(address, 1);
        }
        let last = self.registry.exit(self.tid);
        crate::run_state::clear_guest_tid(self.tid.raw());
        crate::host_signal::forget_thread(self.tid.raw());
        dispatcher.forget_thread_signal_state(self.tid);
        last
    }

    fn join_spawned_threads(&self) -> Result<(), RuntimeError> {
        loop {
            let handles = std::mem::take(&mut *self.threads.lock());
            if handles.is_empty() {
                return Ok(());
            }
            for handle in handles {
                if handle.join().is_err() {
                    return Err(RuntimeError::Unsupported(
                        "native Darwin guest host thread panicked".to_string(),
                    ));
                }
            }
        }
    }
}

impl Drop for NativeThreadRuntime {
    fn drop(&mut self) {
        if self.forked_stale {
            // COW copy discarded by a fork child (`reset_after_fork_child`):
            // the inherited kicker registry's std mutexes may have been
            // captured LOCKED by another parent thread mid-`kick_all` at fork
            // time. Neither `unregister` (locks them; the observed
            // clone3signalflight/execpermitchurn wedge — a fork child parked
            // forever in `__psynch_mutexwait` under `release_kick_target`)
            // nor dropping the registry (pthread_mutex_destroy on a locked
            // copy) is safe here, and no parent thread exists in the child to
            // ever release them. Leak the registry copy and the kick-state
            // binding — bounded to one small allocation per fork — while the
            // child's replacement runtime installed a fresh registry via
            // `new_current`. Regression:
            // `fork_child_reset_skips_cow_locked_kick_registry`.
            if let Some(state) = self.kick_state.take() {
                std::mem::forget(state);
            }
            let stale_registry = std::mem::replace(
                &mut self.kicker,
                Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            );
            std::mem::forget(stale_registry);
            return;
        }
        self.release_kick_target();
    }
}

struct NativeWaitState {
    tid: crate::thread::ThreadId,
    registry: Arc<crate::thread::ThreadRegistry>,
    enrolled: std::cell::Cell<bool>,
    process_leader: bool,
}

impl NativeWaitState {
    fn new(thread_runtime: &NativeThreadRuntime) -> Self {
        let tid = thread_runtime.tid();
        Self {
            tid,
            registry: Arc::clone(&thread_runtime.registry),
            enrolled: std::cell::Cell::new(false),
            process_leader: tid == crate::thread::ThreadId::main_from_host_pid(),
        }
    }

    fn enroll(&self) {
        if self.enrolled.replace(true) {
            return;
        }
        if self.process_leader {
            crate::run_state::publish(crate::run_state::RunState::Blocked);
        }
        self.registry.set_thread_state(self.tid, 'S');
        crate::run_state::publish_guest_tid(self.tid.raw(), crate::run_state::RunState::Blocked);
    }
}

impl Drop for NativeWaitState {
    fn drop(&mut self) {
        if !self.enrolled.get() {
            return;
        }
        self.registry.set_thread_state(self.tid, 'R');
        crate::run_state::publish_guest_tid(self.tid.raw(), crate::run_state::RunState::Running);
        if self.process_leader {
            crate::run_state::publish(crate::run_state::RunState::Running);
        }
    }
}

impl<'a> NativeSignalTrap<'a> {
    fn new(
        memory: &'a NativeMappedMemory,
        regs: NativeUcontextSnapshot,
        last_syscall_nr: Option<u64>,
    ) -> Self {
        Self {
            memory,
            regs,
            orig_x0: regs.x[0],
            last_syscall_nr,
        }
    }

    fn pc(&self) -> u64 {
        self.regs.pc
    }

    fn set_pc(&mut self, pc: u64) {
        self.regs.pc = pc;
    }

    fn into_snapshot(self) -> NativeUcontextSnapshot {
        self.regs
    }
}

impl GuestMemory for NativeSignalTrap<'_> {
    fn protections(&self) -> Option<&MemoryProtections> {
        self.memory.protections()
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.memory.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // `self.memory: &NativeMappedMemory` (Task 5: narrowed from `&mut` so
        // every trap site can construct this under a `SharedNativeMemory`
        // read guard). Routes through the `&self` common write path
        // (`write_bytes_raw_shared`, Phase 1/Task 3) instead of the trait's
        // `write_bytes_raw(&mut self, ..)` dispatcher -- see the struct doc
        // comment for why a signal-frame write can never legitimately need
        // the exec-page (`write_exec_page_bytes`) escalation that skips.
        self.memory.write_bytes_raw_shared(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bytes_raw_shared(address, bytes)
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.memory.guest_range_is_writable(address, length)
    }
}

impl RegAccess for NativeSignalTrap<'_> {
    fn get_reg(&self, reg: Reg) -> Result<u64, carrick_hal::OsError> {
        Ok(match reg {
            Reg::X(index) => usize::try_from(index)
                .ok()
                .and_then(|i| self.regs.x.get(i).copied())
                .unwrap_or(0),
            Reg::Sp => self.regs.sp,
            Reg::Pc | Reg::ElrEl1 => self.regs.pc,
            Reg::Pstate | Reg::SpsrEl1 => self.regs.pstate,
            Reg::SpEl1 => 0,
            _ => 0,
        })
    }

    fn set_reg(&mut self, reg: Reg, value: u64) -> Result<(), carrick_hal::OsError> {
        match reg {
            Reg::X(index) => {
                if let Ok(i) = usize::try_from(index)
                    && let Some(slot) = self.regs.x.get_mut(i)
                {
                    *slot = value;
                }
            }
            Reg::Sp => self.regs.sp = value,
            Reg::Pc | Reg::ElrEl1 => self.regs.pc = value,
            Reg::Pstate | Reg::SpsrEl1 => self.regs.pstate = value,
            Reg::SpEl1 => {}
            _ => {}
        }
        Ok(())
    }

    fn get_sys_reg(&self, _reg: SysReg) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }

    fn set_sys_reg(&mut self, _reg: SysReg, _value: u64) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }

    fn get_vreg(&self, n: u32) -> Result<u128, carrick_hal::OsError> {
        Ok(usize::try_from(n)
            .ok()
            .and_then(|index| self.regs.v.get(index))
            .map_or(0, |value| u128::from_le_bytes(*value)))
    }

    fn set_vreg(&mut self, n: u32, value: u128) -> Result<(), carrick_hal::OsError> {
        if let Ok(index) = usize::try_from(n)
            && let Some(slot) = self.regs.v.get_mut(index)
        {
            *slot = value.to_le_bytes();
        }
        Ok(())
    }

    fn get_fpcr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(u64::from(self.regs.fpcr))
    }

    fn set_fpcr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.regs.fpcr = value as u32;
        Ok(())
    }

    fn get_fpsr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(u64::from(self.regs.fpsr))
    }

    fn set_fpsr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.regs.fpsr = value as u32;
        Ok(())
    }
}

impl SyscallTrap for NativeSignalTrap<'_> {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot enter guest".to_string(),
        ))
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(self.regs.pc)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.regs.x[0] = return_value as u64;
        Ok(())
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot fork".to_string(),
        ))
    }

    fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot execve".to_string(),
        ))
    }

    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc: interrupted_pc.or(Some(self.regs.pc)),
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source: self.regs.pstate & !0xf,
            orig_x0: self.orig_x0,
            fault_esr: 0,
            fpsimd_enabled: true,
            sigreturn_trampoline_base: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
        };
        carrick_hal::sigframe::build_sigframe(self, params)?;
        Ok(())
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        let restored = carrick_hal::sigframe::restore_sigframe(self, true)?;
        self.regs.pc = restored.saved_pc;
        Ok(restored.sigmask)
    }
}

fn dispatch_native_syscall<const PROFILE: bool>(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &SharedNativeMemory,
    thread_runtime: &NativeThreadRuntime,
    reporter: &CompatReporter,
    trace_syscalls: bool,
) -> Result<TimedDispatchOutcome, RuntimeError> {
    let mut blocked_ns = NativeBlockedSpan::default();
    let outcome = dispatch_native_syscall_inner::<PROFILE>(
        dispatcher,
        request,
        memory,
        thread_runtime,
        reporter,
        trace_syscalls,
        &mut blocked_ns,
    )?;
    Ok(TimedDispatchOutcome {
        outcome,
        blocked: blocked_ns,
    })
}

fn measure_native_blocked<const PROFILE: bool, T>(
    blocked_ns: &mut NativeBlockedSpan,
    operation: impl FnOnce() -> T,
) -> Result<T, RuntimeError> {
    if !PROFILE {
        return Ok(operation());
    }
    let timer = dsr::profile::PhaseTimer::start_if::<PROFILE>();
    let cpu_before_ns = dsr::profile::current_thread_cpu_total_ns()
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let result = operation();
    let cpu_after_ns = dsr::profile::current_thread_cpu_total_ns()
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let elapsed_ns = timer
        .elapsed_ns()
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let cpu_delta_ns = cpu_after_ns.checked_sub(cpu_before_ns).ok_or_else(|| {
        RuntimeError::Unsupported(
            dsr::profile::ProfileError::CounterUnderflow("blocked_cpu_ns").to_string(),
        )
    })?;
    // The CPU reads sit inside the wall window, so the true segment CPU can
    // never exceed the segment wall; the µs quantum of per-thread usage can
    // still round the delta past a sub-µs wall. Clamp per segment to keep
    // `phase_blocked_cpu_ns <= phase_blocked_ns` an exact invariant.
    let cpu_delta_ns = cpu_delta_ns.min(elapsed_ns);
    blocked_ns.wall_ns = blocked_ns.wall_ns.checked_add(elapsed_ns).ok_or_else(|| {
        RuntimeError::Unsupported(
            dsr::profile::ProfileError::CounterOverflow("blocked_ns").to_string(),
        )
    })?;
    blocked_ns.cpu_ns = blocked_ns.cpu_ns.checked_add(cpu_delta_ns).ok_or_else(|| {
        RuntimeError::Unsupported(
            dsr::profile::ProfileError::CounterOverflow("blocked_cpu_ns").to_string(),
        )
    })?;
    Ok(result)
}

/// Whether AArch64 canonical syscall `nr` (`crate::linux_abi::syscall::lookup_aarch64`)
/// can mutate `NativeMappedMemory`'s mapping/protection tables (`regions`,
/// `owned_host_ranges`, `protections`, `native_page_protections`,
/// `native_write_exec_writable_pages`, `linux4k_page_protections`) -- i.e.
/// whether its handler, reached through `dispatch_threaded`, calls one of the
/// eight structural `&mut self` `GuestMemory` methods (`protect_range`/
/// `unmap_range`/`unmap_alias_range`/`set_no_access`/`set_no_write`/
/// `set_unmapped`/`set_mapping_protection`/`repoint_private`) DIRECTLY --
/// as opposed to only a guest-RAM CONTENT write (`write_bytes`/
/// `write_bytes_raw`/`zero_backing`), which `NativeDispatchMemory` (below)
/// already handles correctly under a `.read()` guard via on-demand
/// escalation. Used at the `:3440` MIXED site
/// (`.superpowers/sdd/memlock-classification.md`, Section 1) to pick
/// `.write()` (`true`) vs `.read()` (`false`).
///
/// Two groups:
/// - The plan's mm/exec-family list: mmap/munmap/mprotect/madvise/mremap/
///   brk/execve/execveat. `brk`'s handler never touches `cx.memory` at all
///   and `madvise`'s only reaches the escalation-safe `zero_backing` path
///   (MADV_DONTNEED) today -- both kept `true` per the plan's explicit spec
///   rather than assuming that stays true as the handlers evolve.
/// - `shmdt`/`mlock`/`mlock2`/`mlockall`: NOT in the plan's literal list,
///   added here after grepping every `dispatch/*.rs` call site of the eight
///   mutator methods above (`grep -rn` across the whole `dispatch/` tree
///   turns up hits ONLY in `mem.rs` and `sysv.rs`):
///     - `shmdt` (`dispatch/sysv.rs`): calls `cx.memory.unmap_alias_range`
///       then `cx.memory.set_unmapped` directly.
///     - `mlock`/`mlock2` (`dispatch/mem.rs`): `populate_resident_range` ->
///       `protect_range`.
///     - `mlockall` (`dispatch/mem.rs`, `MCL_CURRENT`): `lock_current_mappings`
///       -> `populate_resident_range` -> `protect_range`.
///
///   `munlock`/`munlockall` were also audited and do NOT reach a mutator
///   (their bookkeeping lives in the separate `sysv`/`mem` `Mutex`, not
///   `NativeMappedMemory`) -- correctly `false`. `shmat`/`shmget`/`shmctl`
///   were audited too: `shmat` only touches a separate `Mutex` and returns
///   `DispatchOutcome::MapHostAlias`, whose actual mapping mutation happens
///   OUTSIDE `dispatch_threaded` in a caller that already takes its own
///   `.write()` (native_darwin.rs `MapHostAlias` arm) -- also `false`.
///
/// See `mapping_mutator_numbers_match_linux_abi_names` (native_darwin.rs
/// tests) for the per-number cross-check against `crate::linux_abi`.
fn native_syscall_mutates_mappings(nr: u64) -> bool {
    matches!(
        nr,
        197   // shmdt
            | 214 // brk
            | 215 // munmap
            | 216 // mremap
            | 221 // execve
            | 222 // mmap
            | 226 // mprotect
            | 228 // mlock
            | 230 // mlockall
            | 233 // madvise
            | 281 // execveat
            | 284 // mlock2
    )
}

/// One end of [`NativeDispatchMemory`]'s held guard: starts `Read`, and
/// [`NativeDispatchMemory::ensure_write`] escalates it to `Write` (at most
/// once per dispatch) the first time a write targets a page that may
/// execute.
enum NativeDispatchGuard<'a> {
    Read(parking_lot::RwLockReadGuard<'a, NativeMappedMemory>),
    Write(parking_lot::RwLockWriteGuard<'a, NativeMappedMemory>),
}

impl NativeDispatchGuard<'_> {
    fn inner(&self) -> &NativeMappedMemory {
        match self {
            Self::Read(guard) => guard,
            Self::Write(guard) => guard,
        }
    }
}

/// `GuestMemory` adapter for the `:3440` dispatch site's `.read()` path (a
/// syscall `native_syscall_mutates_mappings` classifies `false`). Mirrors
/// `NativeSignalTrap`'s shared-ref adapter (Task 5) but covers the FULL
/// `GuestMemory` surface `dispatch_threaded` needs generically, not just
/// `write_bytes_raw` -- Task 5's report flagged this as exactly Task 6's
/// scope.
///
/// - Pure reads (`protections`/`read_bytes_raw`/`guest_range_is_writable`/
///   `supports_concurrent_exec_protection`/`shared_futex_location`) delegate
///   straight through the held guard: `&self`, no escalation, identical
///   whether the guard is `Read` or `Write`.
/// - `write_bytes_raw` (and, through the trait's default `zero_backing`/
///   `zero_guest_range`, every other guest-RAM content write) escalates
///   `Read` -> `Write` on demand, at most once per dispatch, the first time
///   the target range may execute -- `write_guest_ram_through_lock`'s
///   pattern (Task 5), scoped to the whole dispatch instead of one write
///   call. A syscall's write target is guest-controlled and so CANNOT be
///   assumed non-executable the way a signal frame can
///   (`NativeSignalTrap`'s doc comment): a JIT can legitimately `read(2)`
///   bytecode straight into an RWX buffer, and skipping the escalation would
///   risk a host-process SIGSEGV in `copy_bytes_to_host`, not just a missed
///   optimization.
/// - The genuine mapping-table mutators (`protect_range`/`unmap_range`/
///   `unmap_alias_range`/`set_no_access`/`set_no_write`/`set_unmapped`/
///   `set_mapping_protection`/`repoint_private`) are UNREACHABLE for a `nr`
///   `native_syscall_mutates_mappings` classifies `false` -- every handler
///   that calls them is in that function's `true` set, so it gets a real
///   `NativeMappedMemory` directly and never constructs this adapter. They
///   panic here instead of silently no-op'ing (the trait's own default for
///   all eight) so a classification bug fails loudly in testing instead of
///   silently corrupting protection state.
struct NativeDispatchMemory<'a> {
    lock: &'a SharedNativeMemory,
    guard: Option<NativeDispatchGuard<'a>>,
}

impl<'a> NativeDispatchMemory<'a> {
    fn new_read(lock: &'a SharedNativeMemory) -> Self {
        Self {
            lock,
            guard: Some(NativeDispatchGuard::Read(lock.read())),
        }
    }

    fn inner(&self) -> &NativeMappedMemory {
        match &self.guard {
            Some(guard) => guard.inner(),
            None => unreachable!("NativeDispatchMemory guard is always Some between calls"),
        }
    }

    /// Escalate the held guard to `Write`, a no-op if already escalated.
    fn ensure_write(&mut self) -> &mut NativeMappedMemory {
        if !matches!(self.guard, Some(NativeDispatchGuard::Write(_))) {
            // Drop the read guard BEFORE acquiring a write guard on the same
            // lock: reversing the order self-deadlocks (`parking_lot::RwLock`
            // is not recursive -- `.write()` blocks on this thread's own
            // live `.read()`, which nothing else can ever release).
            self.guard = None;
            self.guard = Some(NativeDispatchGuard::Write(self.lock.write()));
        }
        match &mut self.guard {
            Some(NativeDispatchGuard::Write(guard)) => guard,
            _ => unreachable!("just escalated to Write"),
        }
    }
}

impl GuestMemory for NativeDispatchMemory<'_> {
    fn protections(&self) -> Option<&MemoryProtections> {
        self.inner().protections()
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner().read_bytes_raw(address, length)
    }

    /// Delegates through the held guard so a read-classified syscall (e.g.
    /// `write`/`send`/`writev` reading the guest source buffer) can still
    /// zero-copy: this only ever READS guest memory, the mapping backing is
    /// stable for as long as this adapter's guard is held (a mapping
    /// mutation needs `.write()`, which cannot run concurrently with our
    /// held `.read()`), and the trait's own contract confines the returned
    /// pointer to this dispatch.
    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        self.inner().host_ptr_for_read(address, len)
    }

    /// Delegates to `host_ptr_for_write_shared` (a `&self` method) so a
    /// read-classified syscall (e.g. `recv`/`readv` writing INTO the guest
    /// destination buffer) can still zero-copy under only the memory READ
    /// guard. This is sound even though it writes guest RAM: every gate the
    /// shared helper checks is itself `&self`-only, the exec-page escalation
    /// check that a checked `write_bytes_raw` performs before touching guest
    /// RAM lives INSIDE the shared helper (`range_may_execute` forces exec
    /// targets to `None`, i.e. the copy fallback, which then goes through
    /// the real escalation), and the mapping can't be pulled out from under
    /// the returned pointer mid-dispatch (`munmap`/`mprotect`/exec all need
    /// the WRITE guard, which excludes concurrent readers).
    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        self.inner().host_ptr_for_write_shared(address, len)
    }

    fn begin_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.inner().begin_host_write_ranges(ranges);
    }

    fn finish_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.inner().finish_host_write_ranges(ranges);
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // Mirrors `NativeMappedMemory::write_bytes`'s gate exactly (the
        // trait default's `range_no_access`-only gate is less precise: this
        // backend also EFAULTs a write into a read-only mapping).
        if !bytes.is_empty()
            && self
                .inner()
                .protections
                .range_write_denied(address, bytes.len())
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.inner().range_may_execute(address, bytes.len()) {
            return self.ensure_write().write_exec_page_bytes(address, bytes);
        }
        self.inner().write_bytes_raw_shared(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.inner().region_contains(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.inner().guest_range_is_writable(address, length)
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        self.inner().supports_concurrent_exec_protection()
    }

    fn shared_futex_location(
        &self,
        guest_addr: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        self.inner().shared_futex_location(guest_addr)
    }

    fn set_no_access(&mut self, _address: u64, _len: usize, _no_access: bool) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_no_access (a mapping-table mutator)"
        );
    }

    fn set_no_write(&mut self, _address: u64, _len: usize, _no_write: bool) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_no_write (a mapping-table mutator)"
        );
    }

    fn set_unmapped(&mut self, _address: u64, _len: usize, _unmapped: bool) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_unmapped (a mapping-table mutator)"
        );
    }

    fn set_mapping_protection(
        &mut self,
        _address: u64,
        _len: usize,
        _no_access: bool,
        _no_write: bool,
    ) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_mapping_protection (a mapping-table mutator)"
        );
    }

    fn set_mapping_sharing(
        &mut self,
        _address: u64,
        _len: usize,
        _sharing: carrick_guest_mem::MappingSharing,
    ) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_mapping_sharing (a mapping-table mutator)"
        );
    }

    fn set_mapping_protection_and_sharing(
        &mut self,
        _address: u64,
        _len: usize,
        _no_access: bool,
        _no_write: bool,
        _sharing: carrick_guest_mem::MappingSharing,
    ) {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called set_mapping_protection_and_sharing \
             (a mapping-table mutator)"
        );
    }

    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called protect_range (a mapping-table mutator)"
        );
    }

    fn unmap_range(&mut self, _address: u64, _len: usize) -> Result<(), MemoryError> {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called unmap_range (a mapping-table mutator)"
        );
    }

    fn repoint_private(
        &mut self,
        _va: u64,
        _overlay_ipa: u64,
        _len: usize,
        _content: &[u8],
    ) -> Result<(), RepointPrivateError> {
        unreachable!(
            "native_syscall_mutates_mappings classified this syscall read-only, \
             but its handler called repoint_private (a mapping-table mutator)"
        );
    }
}

fn dispatch_native_syscall_inner<const PROFILE: bool>(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &SharedNativeMemory,
    thread_runtime: &NativeThreadRuntime,
    reporter: &CompatReporter,
    trace_syscalls: bool,
    blocked_ns: &mut NativeBlockedSpan,
) -> Result<DispatchOutcome, RuntimeError> {
    let mut signal_wait_deadline = None;
    let mut fd_wait_deadline = None;
    loop {
        let outcome = {
            // MIXED site (memlock-classification.md :3440): pre-classify by
            // syscall nr (`native_syscall_mutates_mappings`, Task 6) so only
            // the small minority of mapping-mutating syscalls take `.write()`
            // -- everything else (read/write/futex/getpid/clock_gettime/
            // nanosleep/epoll/... ) takes `.read()` via `NativeDispatchMemory`,
            // whose `write_bytes_raw` still escalates to a real write guard
            // for the rare guest-controlled write-exec-page case.
            if native_syscall_mutates_mappings(request.number.raw()) {
                let mut memory = memory.write();
                dispatcher.dispatch_threaded(
                    request,
                    &mut *memory,
                    reporter,
                    thread_runtime.tid(),
                    &thread_runtime.registry,
                    &thread_runtime.futex,
                )?
            } else {
                let mut memory = NativeDispatchMemory::new_read(memory);
                dispatcher.dispatch_threaded(
                    request,
                    &mut memory,
                    reporter,
                    thread_runtime.tid(),
                    &thread_runtime.registry,
                    &thread_runtime.futex,
                )?
            }
        };
        if trace_syscalls {
            child_write_stderr(
                format!(
                    "native trace pid={} tid={} outcome={outcome:?}\n",
                    unsafe { libc::getpid() },
                    thread_runtime.tid().raw()
                )
                .as_bytes(),
            );
        }
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => {
                let Some(timeout) =
                    remaining_native_wait_timeout(timeout, &mut fd_wait_deadline, Instant::now())
                else {
                    return Ok(DispatchOutcome::Returned { value: on_timeout });
                };
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                native_wait_park_if_quiesce_nudge(
                                    dispatcher,
                                    thread_runtime,
                                    sig_mask,
                                )
                            })?
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => {
                let Some(timeout) =
                    remaining_native_wait_timeout(timeout, &mut fd_wait_deadline, Instant::now())
                else {
                    return Ok(DispatchOutcome::Returned { value: on_timeout });
                };
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_poll_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                native_wait_park_if_quiesce_nudge(
                                    dispatcher,
                                    thread_runtime,
                                    sig_mask,
                                )
                            })?
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnFdsSelect {
                fds,
                timeout,
                sig_mask,
                clear_on_timeout,
            } => {
                let Some(timeout) =
                    remaining_native_wait_timeout(timeout, &mut fd_wait_deadline, Instant::now())
                else {
                    for (addr, len) in &clear_on_timeout {
                        let _ = zero_guest_ram_through_lock(memory, *addr, *len);
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                };
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        for (addr, len) in &clear_on_timeout {
                            let _ = zero_guest_ram_through_lock(memory, *addr, *len);
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                native_wait_park_if_quiesce_nudge(
                                    dispatcher,
                                    thread_runtime,
                                    sig_mask,
                                )
                            })?
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout,
            } => match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                wait_native_signals(
                    dispatcher,
                    thread_runtime,
                    wait_set,
                    block_mask,
                    timeout,
                    &mut signal_wait_deadline,
                )
            })? {
                NativeSignalWaitResult::Ready => continue,
                NativeSignalWaitResult::Interrupted => {
                    return Ok(DispatchOutcome::Errno {
                        errno: crate::linux_abi::LINUX_EINTR,
                    });
                }
                NativeSignalWaitResult::TimedOut => {
                    return Ok(DispatchOutcome::Errno {
                        errno: crate::linux_abi::LINUX_EAGAIN,
                    });
                }
            },
            DispatchOutcome::FutexWait { wait, timeout } => {
                let value = measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_futex(dispatcher, thread_runtime, wait, timeout, 0)
                })?;
                // A pure fork-quiesce nudge: park, then RE-DISPATCH the
                // syscall (revalidating the futex word — Linux syscall
                // restart semantics) instead of surfacing a spurious EINTR.
                if value == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                        native_wait_park_if_quiesce_nudge(
                            dispatcher,
                            thread_runtime,
                            carrick_abi::WaitSigMask::NONE,
                        )
                    })?
                {
                    continue;
                }
                return Ok(DispatchOutcome::Returned { value });
            }
            DispatchOutcome::FutexWaitv {
                wait,
                timeout,
                index,
            } => {
                let value = measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_futex(dispatcher, thread_runtime, wait, timeout, index)
                })?;
                if value == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                        native_wait_park_if_quiesce_nudge(
                            dispatcher,
                            thread_runtime,
                            carrick_abi::WaitSigMask::NONE,
                        )
                    })?
                {
                    continue;
                }
                return Ok(DispatchOutcome::Returned { value });
            }
            DispatchOutcome::SharedFutexWait {
                location,
                waiter_key,
                value,
                timeout,
            } => {
                let retval = measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_shared_futex(
                        dispatcher,
                        thread_runtime,
                        location,
                        waiter_key,
                        value,
                        timeout,
                        0,
                    )
                })?;
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                        native_wait_park_if_quiesce_nudge(
                            dispatcher,
                            thread_runtime,
                            carrick_abi::WaitSigMask::NONE,
                        )
                    })?
                {
                    continue;
                }
                return Ok(DispatchOutcome::Returned { value: retval });
            }
            DispatchOutcome::SharedFutexWaitv {
                location,
                waiter_key,
                value,
                timeout,
                index,
            } => {
                let retval = measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_shared_futex(
                        dispatcher,
                        thread_runtime,
                        location,
                        waiter_key,
                        value,
                        timeout,
                        index,
                    )
                })?;
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                        native_wait_park_if_quiesce_nudge(
                            dispatcher,
                            thread_runtime,
                            carrick_abi::WaitSigMask::NONE,
                        )
                    })?
                {
                    continue;
                }
                return Ok(DispatchOutcome::Returned { value: retval });
            }
            DispatchOutcome::WaitOnSharedWord {
                location,
                waiter_key,
                value,
            } => {
                let retval = measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_shared_futex(
                        dispatcher,
                        thread_runtime,
                        location,
                        waiter_key,
                        value,
                        None,
                        0,
                    )
                })?;
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval() {
                    if measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                        native_wait_park_if_quiesce_nudge(
                            dispatcher,
                            thread_runtime,
                            carrick_abi::WaitSigMask::NONE,
                        )
                    })? {
                        continue;
                    }
                    return Ok(DispatchOutcome::Errno {
                        errno: crate::linux_abi::LINUX_EINTR,
                    });
                }
                continue;
            }
            DispatchOutcome::SharedFutexWake {
                location,
                waiter_key,
                count,
            } => {
                let woke = thread_runtime
                    .platform_futex
                    .shared_wake(location, waiter_key, count);
                return Ok(DispatchOutcome::Returned { value: woke.max(0) });
            }
            DispatchOutcome::SharedFutexRequeue {
                from,
                from_key,
                to,
                to_key,
                wake,
                requeue,
            } => {
                let (woken, requeued) = thread_runtime
                    .platform_futex
                    .shared_requeue(from, from_key, to, to_key, wake, requeue);
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(woken + requeued),
                });
            }
            DispatchOutcome::BlockingHostWrite(mut write) => loop {
                match crate::dispatch::drive_blocking_host_write(&mut write) {
                    crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                        return Ok(crate::vcpu_loop::raise_sigpipe_for_blocking_write(
                            dispatcher, &write, outcome,
                        ));
                    }
                    crate::dispatch::BlockingHostWriteStep::Wait => {
                        match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                            wait_native_fds(
                                dispatcher,
                                thread_runtime,
                                &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                None,
                                carrick_abi::WaitSigMask::NONE,
                            )
                        })? {
                            Ok(NativeWaitResult::Ready) => continue,
                            Ok(NativeWaitResult::TimedOut) => {
                                return Ok(DispatchOutcome::Returned {
                                    value: write.offset() as i64,
                                });
                            }
                            Err(errno) => {
                                // Quiesce nudge: park, then continue the INNER
                                // drive loop so the partial write's offset is
                                // preserved (never re-dispatch a partial write).
                                if errno == crate::linux_abi::LINUX_EINTR
                                    && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                        native_wait_park_if_quiesce_nudge(
                                            dispatcher,
                                            thread_runtime,
                                            carrick_abi::WaitSigMask::NONE,
                                        )
                                    })?
                                {
                                    continue;
                                }
                                if write.offset() > 0 {
                                    return Ok(DispatchOutcome::Returned {
                                        value: write.offset() as i64,
                                    });
                                }
                                return Ok(DispatchOutcome::Errno { errno });
                            }
                        }
                    }
                }
            },
            DispatchOutcome::BlockingRecordLock(lock) => {
                // The dispatcher released all subsystem locks before returning
                // this typed outcome. Native guest threads are independent host
                // pthreads, so siblings remain able to release the conflicting
                // lock while this thread blocks in the host fcntl.
                return measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    crate::dispatch::drive_blocking_record_lock(&lock)
                });
            }
            DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_proc_exit(dispatcher, thread_runtime, pid, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) | Ok(NativeWaitResult::TimedOut) => continue,
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                native_wait_park_if_quiesce_nudge(
                                    dispatcher,
                                    thread_runtime,
                                    sig_mask,
                                )
                            })?
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnProcState { sig_mask, .. } => {
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_proc_state(dispatcher, thread_runtime, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) | Ok(NativeWaitResult::TimedOut) => continue,
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                                native_wait_park_if_quiesce_nudge(
                                    dispatcher,
                                    thread_runtime,
                                    sig_mask,
                                )
                            })?
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnSleep {
                duration,
                remaining,
            } => {
                let deadline = Instant::now() + duration;
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_sleep_until(dispatcher, thread_runtime, deadline)
                })? {
                    Ok(()) => return Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(crate::linux_abi::LINUX_EINTR) => {
                        // `complete_interrupted_sleep` takes `&mut impl
                        // GuestMemory` structurally (dispatch/mod.rs), the
                        // same generic-bound constraint as the :3440 dispatch
                        // site above; conservative `.write()` for a rare
                        // (signal-interrupted-sleep) event, not the hot path.
                        let mut memory = memory.write();
                        return Ok(crate::dispatch::complete_interrupted_sleep(
                            &mut *memory,
                            remaining,
                            deadline.saturating_duration_since(Instant::now()),
                        ));
                    }
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            other => return Ok(other),
        }
    }
}

/// Opt-OUT escape hatch: restore the historical blanket refusal of guest thread
/// creation in a fork child.
///
/// The polarity is deliberately inverted from the original
/// `CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS` opt-IN. Post-fork thread creation is
/// now permitted by default (see [`native_clone_thread_rejection`]); this exists
/// so a wedge found in the field can be re-guarded without a rebuild, not
/// because the refusal is expected to be needed.
fn native_refuse_postfork_threads_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

fn native_clone_thread_rejection(memory: &SharedNativeMemory) -> Option<&'static str> {
    // HISTORY: this used to refuse ALL guest thread creation in a fork child,
    // because "forked guest exec cannot safely reinitialize Darwin libdispatch"
    // — a real observed libdispatch host trap, not a theoretical one (f56eaa95,
    // 2026-07-11). That premise no longer holds, and the refusal cost more than
    // it bought:
    //
    //   * The reason expired two days later. The fork-child host self-reexec
    //     (a8b33532, 2026-07-13) does exactly the host-state reinitialization
    //     this message says is impossible.
    //   * Carrick never calls libdispatch. The genuine CF/LaunchServices hazard
    //     was a `proctitle` Mach round-trip to launchservicesd, and it was fixed
    //     by not calling CF at all (see dispatch/proctitle.rs) — a different bug
    //     from creating a thread.
    //   * The VMM lane never had this restriction; its fork child rebuilds a
    //     fresh VM and spawns threads freely. Refusing here made the SHIPPED
    //     default backend less capable than the one it is replacing.
    //   * It broke real Linux programs. Creating a thread in a fork child is
    //     ordinary POSIX; it failed `test_threading.ThreadJoinOnShutdown`
    //     tests 2 and 3 with "can't start new thread".
    //   * It was expensive. LTP's tst_test framework forks and then wants a
    //     thread; the refusal forced a slow fallback worth ~30s per suite.
    //
    // Retired on evidence, not reasoning: 2x the full conformance smoke tier at
    // 23/23 with no hang (including 278 fork+exec-heavy cpython-subprocess
    // tests), 200 fork->thread->join cycles, and 100 fork->LIVE-thread->execve
    // cycles — that last being precisely the sequence the original message
    // named — all clean.
    if let Some(reason) = postfork_thread_refusal(
        NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire),
        std::env::var_os("CARRICK_NATIVE_REFUSE_POSTFORK_THREADS").as_deref(),
    ) {
        return Some(reason);
    }
    memory.read().native16k_clone_thread_rejection()
}

/// The post-fork thread decision, as a pure function of its two inputs, so the
/// policy can be unit tested without mutating the `NATIVE_FORKED_GUEST_CHILD`
/// process-global (which would leak across the serial test suite).
fn postfork_thread_refusal(
    is_fork_child: bool,
    refuse_env: Option<&std::ffi::OsStr>,
) -> Option<&'static str> {
    if is_fork_child && native_refuse_postfork_threads_enabled(refuse_env) {
        return Some(
            "guest thread creation in a fork child refused by CARRICK_NATIVE_REFUSE_POSTFORK_THREADS",
        );
    }
    None
}

/// Preserve one guest deadline across internal readiness re-dispatches, even
/// when an fd lifecycle change switches between poll-backed and empty-fd waits.
/// The outer `Option` is `None` only when the deadline has expired.
fn remaining_native_wait_timeout(
    timeout: Option<Duration>,
    deadline: &mut Option<Instant>,
    now: Instant,
) -> Option<Option<Duration>> {
    match timeout {
        Some(duration) => {
            let deadline = *deadline.get_or_insert(now + duration);
            (now < deadline).then_some(Some(deadline.saturating_duration_since(now)))
        }
        None => {
            *deadline = None;
            Some(None)
        }
    }
}

fn wait_native_futex(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    wait: crate::thread::FutexWait,
    timeout: Option<Duration>,
    woken_value: i64,
) -> i64 {
    let wait_state = NativeWaitState::new(thread_runtime);
    wait_state.enroll();
    let outcome =
        thread_runtime
            .futex
            .wait_prepared_for_thread(wait, timeout, thread_runtime.tid(), &|| {
                native_wait_interrupt_or_stw(
                    dispatcher,
                    thread_runtime.tid(),
                    carrick_abi::WaitSigMask::NONE,
                )
            });
    drop(wait_state);
    match outcome {
        crate::thread::FutexWaitOutcome::Woken => woken_value,
        crate::thread::FutexWaitOutcome::TimedOut => {
            crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()
        }
        crate::thread::FutexWaitOutcome::Interrupted => {
            crate::linux_abi::LINUX_EINTR.guest_retval()
        }
    }
}

fn wait_native_shared_futex(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    location: carrick_guest_mem::SharedFutexLocation,
    waiter_key: usize,
    value: u32,
    timeout: Option<Duration>,
    woken_value: i64,
) -> i64 {
    let interrupted = || {
        native_wait_interrupt_or_stw(
            dispatcher,
            thread_runtime.tid(),
            carrick_abi::WaitSigMask::NONE,
        )
    };
    let wait_state = NativeWaitState::new(thread_runtime);
    let wait_enrolled = || wait_state.enroll();
    let retval = thread_runtime.platform_futex.shared_wait(
        location,
        waiter_key,
        value,
        timeout,
        &interrupted,
        &wait_enrolled,
    );
    drop(wait_state);
    if retval == 0 { woken_value } else { retval }
}

fn wait_native_signals(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    wait_set: carrick_abi::SigSet,
    block_mask: carrick_abi::SigBlockMask,
    timeout: Option<Duration>,
    deadline: &mut Option<Instant>,
) -> NativeSignalWaitResult {
    let tid = thread_runtime.tid();
    loop {
        // Stop-the-world boundary: an exec replacement surfaces EINTR (the
        // run-loop top retires the thread); a fork quiesce parks HERE — the
        // waiter's ppoll layer returns Interrupted on the nudge, so without
        // this park the loop would spin re-arming slices for the whole
        // quiesce.
        if crate::fork_quiesce::exec_replacing_other_thread(tid) {
            return NativeSignalWaitResult::Interrupted;
        }
        thread_runtime.park_for_fork_quiesce();
        let Some(slice) = crate::vcpu_loop::signal_wait_slice(deadline, timeout) else {
            return NativeSignalWaitResult::TimedOut;
        };
        if let Some(result) = native_signal_wait_pending(dispatcher, tid, wait_set, block_mask) {
            return result;
        }
        let wait_state = NativeWaitState::new(thread_runtime);
        wait_state.enroll();
        let result =
            thread_runtime
                .waiter
                .wait_with_dispatch_pending(&[], Some(slice), block_mask, || {
                    native_signal_wait_pending(dispatcher, tid, wait_set, block_mask).is_some()
                });
        drop(wait_state);
        match result {
            crate::io_wait::WaitResult::Ready | crate::io_wait::WaitResult::Interrupted => {
                if let Some(result) =
                    native_signal_wait_pending(dispatcher, tid, wait_set, block_mask)
                {
                    return result;
                }
            }
            crate::io_wait::WaitResult::TimedOut | crate::io_wait::WaitResult::Errno(_) => {
                if crate::vcpu_loop::signal_wait_expired(*deadline) {
                    return NativeSignalWaitResult::TimedOut;
                }
            }
        }
    }
}

fn native_signal_wait_pending(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    wait_set: carrick_abi::SigSet,
    block_mask: carrick_abi::SigBlockMask,
) -> Option<NativeSignalWaitResult> {
    native_poll_child_exit_watches();
    dispatcher.drain_xsignals_process_directed();
    if crate::host_signal::has_unblocked_pending_for(
        tid.raw(),
        carrick_abi::SigBlockMask::blocking_all_of(wait_set.complement()),
    ) {
        return Some(NativeSignalWaitResult::Ready);
    }
    // ORDER MATTERS: classify the EINTR case BEFORE the generic deliverable-
    // dispatch-pending Ready check. `should_eintr` matches a deliverable
    // pending signal OUTSIDE the wait set (caught, unblocked): the syscall
    // must return EINTR so the boundary delivers its handler. The Ready check
    // below ALSO matches that signal (its Replace(block_mask) complement
    // includes every unblocked caught signal) but Ready means RE-DISPATCH —
    // `rt_sigtimedwait` would find nothing in the wait set, re-park, observe
    // the still-pending signal, and spin Ready→re-dispatch→Ready until the
    // guest timeout returned EAGAIN with the handler deferred to that
    // boundary (probes sigtimedwaitintr/shmnestedfork once pid namespaces
    // routed cross-process kills through the xsig ring into dispatcher
    // pending state). After this check, Ready below is left meaning exactly
    // "wait-set signal pending in dispatcher-owned state" (host-slot wait-set
    // pendings returned Ready above) — the HVF WaitOnSignals arm makes the
    // same distinction by consulting `signal_wait_should_eintr` on its
    // Interrupted wake before re-dispatching.
    if dispatcher.signal_wait_should_eintr(tid, wait_set, block_mask) {
        return Some(NativeSignalWaitResult::Interrupted);
    }
    if dispatcher.has_deliverable_dispatch_pending_for_wait(
        tid,
        carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(block_mask.raw())),
    ) {
        return Some(NativeSignalWaitResult::Ready);
    }
    None
}

fn wait_native_fds(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    fds: &[crate::io_wait::WaitFd],
    timeout: Option<Duration>,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = thread_runtime.tid();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    let wait_state = NativeWaitState::new(thread_runtime);
    wait_state.enroll();
    let result = thread_runtime
        .waiter
        .wait_with_dispatch_pending(fds, timeout, block_mask, || {
            native_wait_should_interrupt(dispatcher, tid, sig_mask)
        });
    drop(wait_state);
    match result {
        crate::io_wait::WaitResult::Ready => Ok(NativeWaitResult::Ready),
        crate::io_wait::WaitResult::TimedOut => Ok(NativeWaitResult::TimedOut),
        crate::io_wait::WaitResult::Interrupted => Err(crate::linux_abi::LINUX_EINTR),
        crate::io_wait::WaitResult::Errno(errno) => Err(errno),
    }
}

fn wait_native_poll_fds(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    fds: &[crate::io_wait::WaitFd],
    timeout: Option<Duration>,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = thread_runtime.tid();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    let wait_state = NativeWaitState::new(thread_runtime);
    wait_state.enroll();
    let result =
        thread_runtime
            .waiter
            .wait_poll_with_dispatch_pending(fds, timeout, block_mask, || {
                native_wait_should_interrupt(dispatcher, tid, sig_mask)
            });
    drop(wait_state);
    match result {
        crate::io_wait::WaitResult::Ready => Ok(NativeWaitResult::Ready),
        crate::io_wait::WaitResult::TimedOut => Ok(NativeWaitResult::TimedOut),
        crate::io_wait::WaitResult::Interrupted => Err(crate::linux_abi::LINUX_EINTR),
        crate::io_wait::WaitResult::Errno(errno) => Err(errno),
    }
}

fn wait_native_proc_exit(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    pid: i32,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = thread_runtime.tid();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    let wait_state = NativeWaitState::new(thread_runtime);
    wait_state.enroll();
    let result =
        thread_runtime
            .waiter
            .wait_proc_exit_with_dispatch_pending(pid, block_mask, || {
                native_wait_should_interrupt(dispatcher, tid, sig_mask)
            });
    drop(wait_state);
    match result {
        crate::io_wait::WaitResult::Ready => Ok(NativeWaitResult::Ready),
        crate::io_wait::WaitResult::TimedOut => Ok(NativeWaitResult::TimedOut),
        crate::io_wait::WaitResult::Interrupted => Err(crate::linux_abi::LINUX_EINTR),
        crate::io_wait::WaitResult::Errno(errno) => Err(errno),
    }
}

fn wait_native_proc_state(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = thread_runtime.tid();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    let wait_state = NativeWaitState::new(thread_runtime);
    wait_state.enroll();
    let result = thread_runtime
        .waiter
        .wait_proc_state_with_dispatch_pending(block_mask, || {
            native_wait_should_interrupt(dispatcher, tid, sig_mask)
        });
    drop(wait_state);
    match result {
        crate::io_wait::WaitResult::Ready => Ok(NativeWaitResult::Ready),
        crate::io_wait::WaitResult::TimedOut => Ok(NativeWaitResult::TimedOut),
        crate::io_wait::WaitResult::Interrupted => Err(crate::linux_abi::LINUX_EINTR),
        crate::io_wait::WaitResult::Errno(errno) => Err(errno),
    }
}

fn wait_native_sleep_until(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    deadline: Instant,
) -> Result<(), crate::linux_abi::LinuxErrno> {
    let tid = thread_runtime.tid();
    let sig_mask = carrick_abi::WaitSigMask::NONE;
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    loop {
        if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
            return Err(crate::linux_abi::LINUX_EINTR);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let wait_state = NativeWaitState::new(thread_runtime);
        wait_state.enroll();
        let result = thread_runtime.waiter.wait_with_dispatch_pending(
            &[],
            Some(deadline - now),
            block_mask,
            || native_wait_should_interrupt(dispatcher, tid, sig_mask),
        );
        drop(wait_state);
        match result {
            crate::io_wait::WaitResult::Ready => {}
            crate::io_wait::WaitResult::TimedOut => return Ok(()),
            crate::io_wait::WaitResult::Interrupted => {
                if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
                    return Err(crate::linux_abi::LINUX_EINTR);
                }
                // A fork-quiesce nudge: park HERE (the loop re-blocks on the
                // ORIGINAL deadline, so the sleep is not restarted) instead
                // of surfacing a spurious EINTR. An exec replacement takes
                // the EINTR path below via the loop's next wait returning
                // Interrupted with nothing pending — the run-loop top
                // retires the thread on the teardown's next kick.
                thread_runtime.park_for_fork_quiesce();
                if crate::fork_quiesce::exec_replacing_other_thread(tid) {
                    return Err(crate::linux_abi::LINUX_EINTR);
                }
            }
            crate::io_wait::WaitResult::Errno(errno) => return Err(errno),
        }
    }
}

fn native_wait_should_interrupt(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    sig_mask: carrick_abi::WaitSigMask,
) -> bool {
    native_poll_child_exit_watches();
    dispatcher.drain_xsignals_process_directed();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    crate::host_signal::has_unblocked_pending_for(tid.raw(), block_mask)
        || dispatcher.has_deliverable_dispatch_pending_for_wait(tid, sig_mask)
}

/// Blocking-wait interrupt predicate INCLUDING the stop-the-world edges: a
/// fork quiesce or an execve replacement by another thread must pull a parked
/// waiter back to its dispatch boundary (the io_wait ppoll layer surfaces
/// both on its own; the parking-lot futex paths only see the caller-supplied
/// predicate, so the OR lives here). Callers classify the resulting
/// `Interrupted` with [`native_wait_park_if_quiesce_nudge`] so a pure quiesce
/// nudge never reaches the guest as EINTR.
fn native_wait_interrupt_or_stw(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    sig_mask: carrick_abi::WaitSigMask,
) -> bool {
    native_wait_should_interrupt(dispatcher, tid, sig_mask)
        || crate::fork_quiesce::is_quiescing()
        || crate::fork_quiesce::exec_replacing_other_thread(tid)
}

/// Classify an `Interrupted` wait: returns true (after PARKING at the fork
/// barrier) iff it was a pure fork-quiesce nudge — no real deliverable
/// signal — so the caller retries/re-dispatches instead of surfacing a
/// guest-visible spurious EINTR (the HVF park-and-retry contract). A real
/// pending signal, an exec replacement (the run-loop top retires the thread;
/// the teardown keeps re-kicking until it gets there), or a nudge whose
/// quiesce already ended all return false and take the normal EINTR path.
fn native_wait_park_if_quiesce_nudge(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    sig_mask: carrick_abi::WaitSigMask,
) -> bool {
    let tid = thread_runtime.tid();
    if native_wait_should_interrupt(dispatcher, tid, sig_mask)
        || crate::fork_quiesce::exec_replacing_other_thread(tid)
        || !crate::fork_quiesce::is_quiescing()
    {
        return false;
    }
    thread_runtime.park_for_fork_quiesce();
    true
}

fn native_wait_block_mask(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    sig_mask: carrick_abi::WaitSigMask,
) -> carrick_abi::SigBlockMask {
    let effective = match sig_mask {
        carrick_abi::WaitSigMask::Replace(mask) => mask,
        carrick_abi::WaitSigMask::Additive(mask) => dispatcher.signal_mask_for(tid).union(mask),
    };
    carrick_abi::SigBlockMask::blocking_all_of(effective)
}

fn native_child_status_ready(pid: i32) -> bool {
    let (idtype, id) = if pid > 0 {
        (libc::P_PID, pid as libc::id_t)
    } else {
        (libc::P_ALL, 0 as libc::id_t)
    };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            idtype,
            id,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc == 0 {
        const CLD_EXITED: i32 = 1;
        const CLD_KILLED: i32 = 2;
        const CLD_DUMPED: i32 = 3;
        let si_pid = carrick_portable::si_pid(&info);
        return si_pid != 0 && matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED);
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

fn handle_native_fork(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    thread_runtime: &mut NativeThreadRuntime,
    vfork_completion: &mut Option<NativeVforkCompletion>,
    request: NativeForkRequest,
    service: &mut NativeSyscallServiceSpan,
) -> Result<NativeForkFlow, RuntimeError> {
    if request.clone_parent {
        return Err(RuntimeError::Unsupported(
            "native Darwin run-elf fork does not yet support CLONE_PARENT".to_string(),
        ));
    }
    // Fork-lifecycle attribution for the NATIVE (DSR) lane. Until now only the
    // HVF backend fired these probes, so a fork on the shipped default backend
    // was a single opaque ~4.6 ms span (vs ~0.53 ms for a bare macOS
    // fork+exit+reap) with nothing to attribute the difference to. The spans
    // below partition that cost; the phase legend lives on
    // `probes::NativeForkPhase`.
    //
    // COST: `Instant::now()` is read only on this path. A guest fork already
    // costs milliseconds, and nothing here is on the per-syscall or per-block
    // hot path, so a handful of timestamp reads is not measurable — but that
    // is exactly why they must not be copied into the dispatch loop.
    let elapsed_us = |start: Instant| -> u64 {
        let micros = start.elapsed().as_micros();
        micros.min(u128::from(u64::MAX)) as u64
    };
    // Mirror HVF's `fork-pre`/`fork-post` contract so `fork-phases.d` brackets
    // a native fork with NO edits. No EL1 on this lane: `elr` is reported 0 and
    // `cpsr` carries the guest PSTATE.
    crate::probes::fork_pre(request.guest_pc, 0, request.guest_pstate);
    // Serialize forks (and exclude a concurrent execve teardown): the same
    // CAS token the HVF fork barrier uses. A loser parks at the in-flight
    // fork's barrier so its drain counts this thread; a loser that observes
    // an execve replacement retires instead (its whole thread group is being
    // destroyed — the fork never happens, matching Linux).
    let token_start = Instant::now();
    match thread_runtime.acquire_fork_token() {
        NativeForkTokenFlow::Acquired { contended } => {
            crate::probes::native_fork_lifecycle(
                NativeForkPhase::TokenAcquire,
                elapsed_us(token_start),
                i64::from(contended),
                0,
            );
        }
        NativeForkTokenFlow::RetireForExec => return Ok(NativeForkFlow::RetireForExec),
        NativeForkTokenFlow::TimedOut => {
            tracing::error!(
                pid = std::process::id(),
                tid = thread_runtime.tid().raw(),
                "native fork could not acquire the fork token within its backstop \
                 deadline; degrading to EAGAIN"
            );
            return Ok(NativeForkFlow::Resume {
                value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                fork_child: false,
                child_stack: 0,
            });
        }
    }
    let barrier = crate::fork_quiesce::barrier();
    // Multithreaded fork: stop the world first. Siblings park at their
    // dispatch boundaries (run-loop top / blocking-wait retry points) holding
    // NO carrick locks; the drain completes only when the KICKER count falls
    // to 1 (parking siblings unregister first, park second — same contract as
    // HVF's `handle_fork`). Exited-mid-quiesce threads also leave the count.
    let mut quiesced = false;
    // Measured UNCONDITIONALLY, including the single-threaded case that never
    // enters the drain at all. "The stop-the-world costs nothing at threads=0"
    // is then a reading off the trace rather than an assumption — which is the
    // whole reason this probe exists: the native fork is ~8.7x a host fork at
    // threads=0, where this path is provably not entered.
    let quiesce_start = Instant::now();
    let live_at_fork = thread_runtime.registry.live_count();
    if live_at_fork > 1 {
        // linux4k boundary: the 4K-on-16K guarded-page fault emulation is not
        // multithread-safe (MT guarded faults corrupt its state and could
        // SIGSEGV the host — forkfpreclaim on linux4k; task_c2615fa2 tracks
        // making it MT-safe). MT fork on linux4k keeps the honest typed
        // rejection it had before MT fork landed; the run-loop's guarded-
        // fault arm carries the matching MT rejection, so a linux4k MT guest
        // fails typed at whichever boundary it reaches first, never with a
        // host crash.
        // Lock-free (Task 8): this only needs the two page sizes, so read
        // them via `NativeMemoryHandle` instead of taking the big memory
        // `RwLock` just to immediately drop the guard again.
        if memory.uses_linux4k_subpages() {
            barrier.end_fork();
            return Err(RuntimeError::Unsupported(
                "native Darwin multithreaded fork on the linux4k page profile is not yet \
                 supported: the 4K-on-16K guarded-page fault emulation is not \
                 multithread-safe"
                    .to_string(),
            ));
        }
        // Historical direct-execution W^X boundary (311fae9e), retained as an
        // explicit lifecycle hook. DSR never executes original bytes, carries
        // generation state across fork, and currently returns false here, so
        // native DSR does not reject this lifecycle on that removed executor's
        // patch/protection concern.
        if memory.read().write_exec_blocks_multithreaded_lifecycle() {
            barrier.end_fork();
            return Err(RuntimeError::Unsupported(
                "native Darwin multithreaded fork with write-exec pages is not supported"
                    .to_string(),
            ));
        }
        barrier.set_quiescing();
        thread_runtime.kicker.kick_all_except(thread_runtime.tid());
        thread_runtime.platform_futex.notify_signal_pending();
        // Bounded drain (10 s, generously above the sub-millisecond norm): a
        // sibling that never parks means a blocking wait arm is not surfacing
        // `is_quiescing()`; abort loudly so the core (`bt all`) names the
        // stranded thread — mirroring the HVF drain's failure discipline.
        let drain_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // An execve replacement raised mid-quiesce WINS (Linux: exec
            // kills the forking sibling; the fork never completes). Abort:
            // release the parked siblings so they reach their boundaries and
            // retire, then retire this thread too.
            if crate::fork_quiesce::exec_replacing_other_thread(thread_runtime.tid()) {
                barrier.end_quiesce();
                barrier.end_fork();
                return Ok(NativeForkFlow::RetireForExec);
            }
            if thread_runtime.kicker.count() <= 1 {
                break;
            }
            if Instant::now() >= drain_deadline {
                tracing::error!(
                    kicker = thread_runtime.kicker.count(),
                    paused = barrier.paused_count(),
                    pid = std::process::id(),
                    forker_tid = thread_runtime.tid().raw(),
                    "native fork quiesce drain: sibling guest thread(s) failed to reach \
                     the dispatch-boundary barrier in 10s — a blocking wait arm is not \
                     surfacing is_quiescing(). Aborting (core: `bt all` names the \
                     stranded thread) rather than forking a torn runtime.",
                );
                std::process::abort();
            }
            thread_runtime.kicker.kick_all_except(thread_runtime.tid());
            thread_runtime.platform_futex.notify_signal_pending();
            std::thread::sleep(Duration::from_micros(200));
        }
        quiesced = true;
    }
    crate::probes::native_fork_lifecycle(
        NativeForkPhase::SiblingQuiesce,
        elapsed_us(quiesce_start),
        live_at_fork as i64,
        i64::from(quiesced),
    );
    // Drain in-flight EXIT CLEANUPS before forking: an exiting thread has
    // already left the kicker (so the quiesce above never counted it) but may
    // still be mutating process-global signal state under process-wide
    // mutexes; `libc::fork` landing inside that window hands the child a
    // mutex held by a thread that does not exist in it (the HVF go-os_exec
    // vfork wedge). Bounded, then proceed (status-quo risk) — mirrors HVF.
    {
        let cleanup_start = Instant::now();
        let cleanup_deadline = Instant::now() + Duration::from_secs(5);
        while crate::fork_quiesce::exit_cleanups_in_flight() > 0 {
            if Instant::now() >= cleanup_deadline {
                tracing::error!(
                    in_flight = crate::fork_quiesce::exit_cleanups_in_flight(),
                    "native fork: exit-cleanup drain timed out after 5s; forking anyway \
                     (child may inherit a held cleanup lock)"
                );
                break;
            }
            std::thread::yield_now();
        }
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ExitCleanupDrain,
            elapsed_us(cleanup_start),
            crate::fork_quiesce::exit_cleanups_in_flight() as i64,
            0,
        );
    }
    let end_fork_state = |quiesced: bool| {
        if quiesced {
            barrier.end_quiesce();
        }
        barrier.end_fork();
    };
    // Publication and RLIMIT_CPU helpers are not guest registrations. Once the
    // guest drain is complete, pin their outer gates before any fork-shared
    // provider/timer mutex, using one absolute deadline and rolling back without
    // calling fork if either helper fails to leave its short iteration.
    let helper_start = Instant::now();
    let helper_deadline = Instant::now() + Duration::from_secs(10);
    let Some(network_fork_guard) = dispatcher.begin_network_fork_guard_until(helper_deadline)
    else {
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::HelperGates,
            elapsed_us(helper_start),
            1,
            0,
        );
        end_fork_state(quiesced);
        return Ok(NativeForkFlow::Resume {
            value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            fork_child: false,
            child_stack: 0,
        });
    };
    let Some(rlimit_cpu_fork_guard) = dispatcher.begin_rlimit_cpu_fork_guard_until(helper_deadline)
    else {
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::HelperGates,
            elapsed_us(helper_start),
            1,
            0,
        );
        drop(network_fork_guard);
        end_fork_state(quiesced);
        return Ok(NativeForkFlow::Resume {
            value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            fork_child: false,
            child_stack: 0,
        });
    };
    crate::probes::native_fork_lifecycle(
        NativeForkPhase::HelperGates,
        elapsed_us(helper_start),
        0,
        0,
    );
    // Everything from here to `libc::fork` is pre-fork bookkeeping done on
    // behalf of BOTH processes. The EAGAIN/error arms inside it short-circuit
    // WITHOUT a phase sample by design: a `fork-pre` with no `fork-post` is
    // already the trace signature of an abandoned fork, and emitting a partial
    // span would corrupt the phase averages the D script aggregates.
    let bookkeeping_start = Instant::now();
    let vfork_pipe = if request.vfork.is_some() {
        memory.read().set_fork_inheritance(true);
        match vfork_pipe_pair() {
            Ok(pipe) => Some(pipe),
            Err(error) => {
                memory.read().set_fork_inheritance(false);
                end_fork_state(quiesced);
                return Err(error);
            }
        }
    } else {
        None
    };
    let parent_tid = thread_runtime.tid();
    let child_parent = std::process::id();
    let child_subreaper = dispatcher.subreaper_for_fork_child();
    let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
    let prepared_child_record = match crate::guest_cpu::prepare_child_record_pre_fork(
        child_parent,
        child_subreaper,
        child_ns_pid.unwrap_or(0),
        false,
        0,
    ) {
        Ok(record) => record,
        Err(_) => {
            if let Some((read_fd, write_fd)) = vfork_pipe {
                close_fd(read_fd);
                close_fd(write_fd);
                memory.read().set_fork_inheritance(false);
            }
            end_fork_state(quiesced);
            return Ok(NativeForkFlow::Resume {
                value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                fork_child: false,
                child_stack: 0,
            });
        }
    };
    // Hold the quiesce barrier's internal mutex ACROSS the fork: a sibling
    // parking for this quiesce leaves the kicker count BEFORE it parks, so
    // the drain above can be satisfied while that sibling is still inside
    // `park_if_quiescing`'s lock-increment window HOLDING the barrier mutex
    // — a fork landing there hands the child the mutex locked forever (the
    // captured-live HVF go-os_exec wedge). Owning it here excludes that
    // window by mutual exclusion, and — because entering/leaving the
    // condvar wait also requires it — guarantees every parked sibling is
    // fully quiescent in the kernel at the fork instant, which is what makes
    // the child's `end_quiesce` (notify on the COW condvar copy) safe.
    // Dropped on both sides immediately after the fork, before any barrier
    // call.
    let paused_guard = barrier.lock_paused_across_fork();
    // ATFORK-PREPARE: pin every fork-shared signal-static mutex an auxiliary
    // thread can hold (the child-exit watcher mid-publish: child-watch tables,
    // THREAD_PENDING, THREAD_WAITERS) on THIS thread across fork(), then
    // release immediately in both processes. Without this, a fork landing
    // while the watcher held one left the child's COW lock copy locked
    // forever and the child wedged in reinit_after_fork → child_watch::clear
    // (the execpermitchurn/clone3signalflight load-coupled TIMEOUTs). The
    // kicker registry needs no hold: a stale COW runtime skips it entirely
    // (`forked_stale` in NativeThreadRuntime::drop).
    let fork_signal_locks = crate::host_signal::hold_signal_locks_for_fork();
    crate::probes::native_fork_lifecycle(
        NativeForkPhase::PreForkBookkeeping,
        elapsed_us(bookkeeping_start),
        child_ns_pid.map(i64::from).unwrap_or(-1),
        i64::from(vfork_pipe.is_some()),
    );
    let host_fork_start = Instant::now();
    require_native_syscall_service_transition(
        service.branch(NativeSyscallBranchKind::Process),
        "process branch",
    )?;
    let child = unsafe { libc::fork() };
    // Both branches: drop the prepare bundle before any signal-static use.
    // The parent releases its guards normally; the child publishes a fresh
    // waiter backing instead of unlocking a copied contended parking queue.
    drop(fork_signal_locks);
    drop(rlimit_cpu_fork_guard);
    drop(network_fork_guard);
    drop(paused_guard);
    // Both processes return from the ONE `fork(2)` and each measures its own
    // side of it (they diverge in the kernel, so the two samples are genuinely
    // different numbers), hence the explicit role: the phase alone cannot
    // derive it.
    crate::probes::native_fork_lifecycle_as(
        if child == 0 {
            NativeForkRole::Child
        } else {
            NativeForkRole::Parent
        },
        NativeForkPhase::HostFork,
        elapsed_us(host_fork_start),
        i64::from(child),
        0,
    );
    if child < 0 {
        crate::guest_cpu::abort_prepared_child_record();
        if let Some((read_fd, write_fd)) = vfork_pipe {
            close_fd(read_fd);
            close_fd(write_fd);
            memory.read().set_fork_inheritance(false);
        }
        end_fork_state(quiesced);
        return Ok(NativeForkFlow::Resume {
            value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            fork_child: false,
            child_stack: 0,
        });
    }
    if child == 0 {
        // CHILD: everything from here to the `Resume` below is the post-fork
        // repair the guest cannot resume without. Nothing measured it before —
        // it is the one span the perf_fork_scale numbers had no name for.
        let child_repair_start = Instant::now();
        let mut child_phase_start = child_repair_start;
        // Repair the inherited barrier state FIRST: the quiesce/fork flags
        // (and the parked-thread count, which belongs to PARENT threads that
        // do not exist here) would otherwise park this child's run loop at
        // its first boundary check or satisfy a future MT fork's drain with
        // phantom parkers — the HVF child arm's exact sequence. The exec-
        // replacement owner is likewise a PARENT thread that does not exist
        // here; an inherited nonzero owner would spuriously retire this
        // child's threads at their first boundary.
        barrier.end_quiesce();
        barrier.end_fork();
        barrier.reset_paused_for_child();
        crate::fork_quiesce::end_exec_replacement();
        // The durable image-replaced marker belongs to the PARENT's image
        // history; inherited true it would turn this child's
        // no-process-exit diagnostic into a silent park.
        NATIVE_IMAGE_REPLACED_BY_EXEC.store(false, std::sync::atomic::Ordering::Release);
        if let Some((read_fd, write_fd)) = vfork_pipe {
            close_fd(read_fd);
            *vfork_completion = Some(NativeVforkCompletion { fd: write_fd });
        }
        NATIVE_FORKED_GUEST_CHILD.store(true, std::sync::atomic::Ordering::Release);
        // Disabled USDT keeps this query at zero cost in ordinary runs. A
        // native-wall capture needs the child's Darwin PID incarnation before
        // any post-fork DSR event can be attributed; `proc:::create` exposes a
        // zeroed `pr_start` on current Darwin, so the child publishes the
        // checked `PROC_PIDTBSDINFO` tuple itself.
        crate::probes::host_process_birth_current();
        native_trace_fork_phase("child-guard-installed");
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ChildBarrierRepair,
            elapsed_us(child_phase_start),
            i64::from(vfork_pipe.is_some()),
            0,
        );
        child_phase_start = Instant::now();
        native_after_fork_child(dispatcher);
        native_trace_fork_phase("child-dispatcher-reset");
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ChildDispatcherReset,
            elapsed_us(child_phase_start),
            crate::native::fork_child::after_fork_child_steps().len() as i64,
            0,
        );
        child_phase_start = Instant::now();
        thread_runtime.reset_after_fork_child();
        // Retire SIBLING per-tid signal state before re-keying the forking
        // thread's own: fork clones only the calling thread, and the child's
        // fresh registry allocates tids that can collide with a dead parent
        // sibling's entry (regression:
        // fork_child_retires_sibling_thread_signal_state).
        dispatcher.retire_sibling_thread_signal_state(parent_tid);
        dispatcher.migrate_thread_signal_state(parent_tid, thread_runtime.tid());
        thread_runtime.prepare_kick_target()?;
        thread_runtime.start_signal_wake_pump();
        native_trace_fork_phase("child-thread-runtime-reset");
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ChildRuntimeReset,
            elapsed_us(child_phase_start),
            i64::from(thread_runtime.tid().raw()),
            0,
        );
        child_phase_start = Instant::now();
        crate::guest_cpu::reset();
        crate::guest_cpu::complete_child_record_post_fork_child();
        dispatcher.rlimit_cpu_after_fork_child().map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native fork child could not rearm finite RLIMIT_CPU helper: {error}"
            ))
        })?;
        // P2 getrandom fork-safety: give the child its own vvar RNG generation
        // (its PID) so the COW-inherited userspace getrandom state reseeds
        // instead of replaying the parent's keystream — the native counterpart
        // of the HVF child-side re-stamp in `fork_rebuild`.
        memory.read().restamp_vdso_rng_generation_after_fork()?;
        crate::run_state::reinit_booting_after_fork();
        let self_tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
        if let Some(addr) = request.parent_tid_addr {
            let _ = write_guest_ram_through_lock(memory, addr, &self_tid);
        }
        if let Some(addr) = request.child_tid_addr {
            let _ = write_guest_ram_through_lock(memory, addr, &self_tid);
        }
        native_trace_fork_phase("child-resume");
        let child_ns_pid_self = i64::from(crate::namespace::pid::self_ns_pid());
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ChildGuestState,
            elapsed_us(child_phase_start),
            child_ns_pid_self,
            0,
        );
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::ChildRuntimeRepairTotal,
            elapsed_us(child_repair_start),
            child_ns_pid_self,
            0,
        );
        // NOTE: `fork-post` for the CHILD is fired by the run loop, not here —
        // the DSR translator's own fork-child repair
        // (`ChildTranslatorRebuild`) still has to run before the guest is
        // resumable, and the translator lives at the call site.
        return Ok(NativeForkFlow::Resume {
            value: 0,
            fork_child: true,
            child_stack: request.child_stack,
        });
    }
    // Release the parked siblings now — the fork is done; the vfork suspend
    // below must run with siblings LIVE (HVF suspends after end_quiesce too).
    // The fork TOKEN is held across the vfork suspend because the vm-inherit
    // SHARE flags set for the vfork window are process-global: a sibling's
    // CoW fork landing inside it would wrongly SHARE guest-writable memory
    // with its child. The suspend is bounded (60 s) and exec-interruptible,
    // so the token hold is too.
    // PARENT: post-fork bookkeeping and child-record publication, i.e. every
    // remaining microsecond before the guest resumes.
    let parent_publish_start = Instant::now();
    if quiesced {
        barrier.end_quiesce();
    }
    // The vfork suspend is GUEST-PACED (it ends when the child execve's or
    // exits), so it is reported as its own phase and SUBTRACTED from
    // `ParentPublish` — folding it in would make carrick's own post-fork cost
    // look arbitrarily large on any vfork+exec workload.
    let mut vfork_suspend_us = 0u64;
    let vfork_wait = if let Some((read_fd, write_fd)) = vfork_pipe {
        let vfork_suspend_start = Instant::now();
        close_fd(write_fd);
        let wait = wait_native_vfork_completion(read_fd, thread_runtime.tid());
        close_fd(read_fd);
        memory.read().set_fork_inheritance(false);
        vfork_suspend_us = elapsed_us(vfork_suspend_start);
        crate::probes::native_fork_lifecycle(
            NativeForkPhase::VforkSuspend,
            vfork_suspend_us,
            i64::from(child),
            0,
        );
        wait
    } else {
        Ok(NativeVforkWait::Completed)
    };
    barrier.end_fork();
    match vfork_wait? {
        NativeVforkWait::Completed => {}
        NativeVforkWait::ExecRetire => {
            // Linux kills a vfork-suspended thread during a sibling's execve;
            // the vfork child lives on as a child of the (exec'd) process.
            // Publish its record so the new image can reap it, then retire.
            // No guest-memory writes (pidfd/parent_tid target the dying
            // image) and no exit-signal watch (execve resets the SIGCHLD
            // disposition to default).
            crate::guest_cpu::publish_prepared_child_record_parent_ref(
                prepared_child_record,
                child as u32,
            );
            crate::namespace::pid::notify_child_registered();
            crate::run_state::publish_child_booting(child as u32);
            return Ok(NativeForkFlow::RetireForExec);
        }
    }
    crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared_child_record, child as u32);
    crate::namespace::pid::notify_child_registered();
    crate::run_state::publish_child_booting(child as u32);
    if let Some(addr) = request.pidfd_out {
        let fd = dispatcher.install_child_pidfd(child).unwrap_or(-1);
        let _ = write_guest_ram_through_lock(memory, addr, &fd.to_le_bytes());
    }
    let guest_child_pid = child_ns_pid.unwrap_or(child as u32) as i32;
    if let Some(addr) = request.parent_tid_addr {
        let tid = guest_child_pid.to_le_bytes();
        let _ = write_guest_ram_through_lock(memory, addr, &tid);
    }
    native_register_child_exit_watch(dispatcher, child, request.exit_signal, thread_runtime.tid());
    crate::probes::native_fork_lifecycle(
        NativeForkPhase::ParentPublish,
        elapsed_us(parent_publish_start).saturating_sub(vfork_suspend_us),
        i64::from(guest_child_pid),
        0,
    );
    // Close the parent's `fork-pre`/`fork-post` bracket. `arg0` is the HOST
    // child pid (nonzero), which is what makes the D script's parent clause
    // distinguishable from its `arg0 == 0` child clause.
    crate::probes::fork_post(child, request.guest_pc, 0);
    Ok(NativeForkFlow::Resume {
        value: i64::from(guest_child_pid),
        fork_child: false,
        child_stack: 0,
    })
}

/// Linux execve(2) replaces the WHOLE thread group: every sibling thread is
/// destroyed and the new image starts single-threaded. The native mirror of
/// `terminate_siblings_for_exec`: raise the exec-replacement flag, kick every
/// sibling to its dispatch boundary where it retires COOPERATIVELY through
/// the normal thread-exit path (`finish_thread` — the HVF sibling exit shape,
/// including the CLONE_CHILD_CLEARTID clear+wake against the old image),
/// drain until this thread is the only live one, reclaim straggler records,
/// and JOIN the sibling host threads so none is still unwinding when
/// `replace_image` tears the old mappings down.
///
/// Runs AFTER the replacement image loaded successfully — a failed execve
/// must leave the thread group intact (Linux's point of no return).
fn native_terminate_siblings_for_exec(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    thread_runtime: &mut NativeThreadRuntime,
) -> Result<NativeExecTeardownFlow, RuntimeError> {
    if thread_runtime.registry.live_count() <= 1 {
        return Ok(NativeExecTeardownFlow::Proceed);
    }
    let tid = thread_runtime.tid();
    // Exec WINS: CAS-claim the replacement flag BEFORE serializing on the
    // fork token, then kick — so a token holder that cannot make progress on
    // its own observes the flag and yields it: a vfork-suspended leader
    // retires (Linux kills a vfork-waiting thread during execve; pre-fix the
    // execing thread hot-spun on the token for the whole guest-paced
    // suspend), and a forker mid-quiesce aborts its drain. A lost CAS means
    // another thread's execve already owns the group — retire.
    if !crate::fork_quiesce::try_begin_exec_replacement(tid) {
        return Ok(NativeExecTeardownFlow::RetireForExec);
    }
    thread_runtime.kicker.kick_all_except(tid);
    thread_runtime.platform_futex.notify_signal_pending();
    let barrier = crate::fork_quiesce::barrier();
    // Token acquisition is a bounded BACKSTOP only: every legitimate holder
    // now observes the exec flag and releases within its own bounded window
    // (quiesce drain abort 10 s, vfork suspend 60 s).
    let token_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if barrier.try_begin_fork() {
            break;
        }
        thread_runtime.park_for_fork_quiesce();
        if Instant::now() >= token_deadline {
            crate::fork_quiesce::end_exec_replacement();
            return Err(RuntimeError::Trap(TrapError::Hypervisor(
                "native execve could not serialize against an in-flight fork/vfork \
                 within 120s; the thread group is partially torn down"
                    .to_string(),
            )));
        }
        thread_runtime.kicker.kick_all_except(tid);
        thread_runtime.platform_futex.notify_signal_pending();
        std::thread::sleep(Duration::from_micros(200));
    }
    // Direct-execution W^X boundary (311fae9e), kept narrow and explicit — see
    // the fork-side twin. DSR retires the old translator after the sibling
    // drain and therefore does not carry patched executable bytes into exec.
    if memory.read().write_exec_blocks_multithreaded_lifecycle() {
        crate::fork_quiesce::end_exec_replacement();
        barrier.end_fork();
        return Err(RuntimeError::Unsupported(
            "native Darwin multithreaded execve with write-exec pages is not supported".to_string(),
        ));
    }
    // Drain until every sibling has RETIRED. Both counts matter: the registry
    // entry drops in `finish_thread` (a thread transiently unregistered from
    // the kicker — e.g. re-registering after a fork park — is still live and
    // must not be missed), and the kicker entry drops with it. Bounded 5 s
    // (mirrors HVF); on expiry the typed error states the honest consequence:
    // some siblings already retired, so the group is partially torn down.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if thread_runtime.registry.live_count() <= 1 && thread_runtime.kicker.count() <= 1 {
            break;
        }
        if Instant::now() >= deadline {
            crate::fork_quiesce::end_exec_replacement();
            barrier.end_fork();
            return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                "native execve thread-group teardown timed out: live={} kicker={}; \
                 the thread group is partially torn down",
                thread_runtime.registry.live_count(),
                thread_runtime.kicker.count()
            ))));
        }
        thread_runtime.kicker.kick_all_except(tid);
        thread_runtime.platform_futex.notify_signal_pending();
        std::thread::sleep(Duration::from_micros(200));
    }
    // Straggler records: a thread that had a tid but never reached a
    // boundary (spawn raced the teardown). Reclaim exactly what its own
    // retirement would have (mirrors HVF's remove_all_except sweep).
    let removed = thread_runtime
        .registry
        .remove_all_except(thread_runtime.tid());
    for tid in removed {
        thread_runtime.kicker.unregister(tid);
        crate::run_state::clear_guest_tid(tid.raw());
        crate::host_signal::forget_thread(tid.raw());
        dispatcher.forget_thread_signal_state(tid);
    }
    // Join the sibling HOST threads so none is mid-unwind while the image is
    // replaced. Skip self when the exec came from a spawned thread (joining
    // self deadlocks); dropping that handle detaches it — this thread runs
    // the new image and the process exits via its `_exit`.
    let current = std::thread::current().id();
    loop {
        let handles = std::mem::take(&mut *thread_runtime.threads.lock());
        if handles.is_empty() {
            break;
        }
        for handle in handles {
            if handle.thread().id() == current {
                continue;
            }
            let _ = handle.join();
        }
    }
    // Durable-BEFORE-transient ordering: a normally-exited leader whose
    // join-take raced this teardown's take may check
    // `native_exited_leader_must_park` at any point after our take — while
    // the transient owner flag is still up it covers the check; once we
    // lower it below, the durable flag (stored FIRST) has already taken
    // over. No gap.
    NATIVE_IMAGE_REPLACED_BY_EXEC.store(true, std::sync::atomic::Ordering::Release);
    crate::fork_quiesce::end_exec_replacement();
    barrier.end_fork();
    Ok(NativeExecTeardownFlow::Proceed)
}

fn native_trace_fork_phase(phase: &str) {
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!("native trace pid={} fork-phase={phase}\n", unsafe {
                libc::getpid()
            })
            .as_bytes(),
        );
    }
}

/// How the vfork parent-suspend ended.
enum NativeVforkWait {
    /// The child execve'd (a byte) or exited (EOF) — or the bounded suspend
    /// expired and the parent resumes DEGRADED (HVF's 60 s parity).
    Completed,
    /// A sibling thread's execve replaced the thread group mid-suspend.
    /// Linux KILLS a vfork-waiting thread during execve (its wait is
    /// killable); the caller must retire this thread. The vfork child lives
    /// on, paced by its own execve/_exit.
    ExecRetire,
}

fn wait_native_vfork_completion(
    fd: RawFd,
    tid: crate::thread::ThreadId,
) -> Result<NativeVforkWait, RuntimeError> {
    // Bounded suspend (HVF VFORK_SUSPEND_TIMEOUT parity): the child should
    // execve/_exit within ms, but a pathological guest must not wedge this
    // thread — and everything serialized behind the fork token — forever.
    // poll (not a bare read loop) so a kick's EINTR re-checks the exec flag:
    // pre-fix the raw EINTR-retrying read held the fork token for the whole
    // guest-paced suspend while a sibling's execve HOT-SPUN on the token.
    const VFORK_SUSPEND_TIMEOUT: Duration = Duration::from_secs(60);
    let deadline = Instant::now() + VFORK_SUSPEND_TIMEOUT;
    loop {
        if crate::fork_quiesce::exec_replacing_other_thread(tid) {
            return Ok(NativeVforkWait::ExecRetire);
        }
        let now = Instant::now();
        if now >= deadline {
            tracing::error!(
                "native vfork parent-suspend timed out (60s) waiting for child \
                 execve/_exit; resuming parent degraded"
            );
            return Ok(NativeVforkWait::Completed);
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if rc > 0 {
            // Readable: a byte (child execve'd) or EOF (child exited).
            let mut byte = [0_u8; 1];
            let _ = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
            return Ok(NativeVforkWait::Completed);
        }
        if rc == 0 {
            continue; // deadline re-checked at loop top
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                "native Darwin vfork completion poll failed: {err}"
            )));
        }
    }
}

fn native_register_child_exit_watch(
    dispatcher: &SyscallDispatcher,
    child: i32,
    exit_signal: u32,
    tid: crate::thread::ThreadId,
) {
    let _ = dispatcher;
    if exit_signal == 0 {
        return;
    }
    let signum = i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD);
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!(
                "native trace pid={} register-child-exit child={} parent_tid={} signum={}\n",
                unsafe { libc::getpid() },
                child,
                tid.raw(),
                signum
            )
            .as_bytes(),
        );
    }
    crate::host_signal::register_child_exit_watch(child, tid.raw(), signum);
    native_arm_child_exit_watch(child);
}

/// Arm the async watcher for `child` (the native analogue of HVF's pump-kqueue
/// EVFILT_PROC arm). ESRCH/ENOENT means the child raced its own exit AND has
/// already become unwatchable; if its status is reapable, deliver the exit
/// signal the missed one-shot can no longer publish. The same already-dead
/// check runs after a SUCCESSFUL arm too: the one-shot only fires for exits
/// after registration.
fn native_arm_child_exit_watch(child: i32) {
    use std::sync::atomic::Ordering;
    for attempt in 0..2 {
        let Some(kq) = ensure_native_child_watcher() else {
            return;
        };
        let arm = carrick_host_bsd::kqueue::apply_changes(
            kq,
            &[carrick_host_bsd::kqueue::Kevent::proc_exit(child)],
        );
        // EBADF: the advertised kqueue is dead (its watcher exited and dropped
        // it, closing the fd, while the number lingered in the static). Forget
        // the stale fd so ensure() respawns a fresh watcher, and re-arm once —
        // otherwise async delivery silently disappears for every later child.
        if arm == Err(libc::EBADF) && attempt == 0 {
            let _ =
                NATIVE_CHILD_WATCH_KQ.compare_exchange(kq, -1, Ordering::AcqRel, Ordering::Acquire);
            continue;
        }
        if matches!(arm, Ok(()) | Err(libc::ESRCH | libc::ENOENT))
            && native_child_status_ready(child)
        {
            native_publish_child_exit(child);
        }
        return;
    }
}

fn native_poll_child_exit_watches() {
    for child in carrick_signal_core::child_watch::tracked_pids() {
        if !native_child_status_ready(child) {
            continue;
        }
        if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
            child_write_stderr(
                format!(
                    "native trace pid={} child-exit-ready child={}\n",
                    unsafe { libc::getpid() },
                    child
                )
                .as_bytes(),
            );
        }
        let Some((parent_tid, exit_signal)) = crate::host_signal::take_child_exit_parent(child)
        else {
            continue;
        };
        if exit_signal != 0 {
            publish_native_pending_for(parent_tid, exit_signal);
        }
    }
}

/// Run the dispatcher + runtime fork-child resets in a fresh fork
/// descendant, so the child starts with the POSIX-correct post-`fork` state
/// instead of the parent's inherited process-global bookkeeping. Shared with
/// `native_freebsd::native_after_fork_child` — see
/// `crate::native::fork_child` for the ordered hook list and the Task 5
/// Step 1 divergence note (Darwin has no lane-specific extra step; this is a
/// bare call).
fn native_after_fork_child(dispatcher: &SyscallDispatcher) {
    crate::native::fork_child::dispatcher_after_fork_child(dispatcher);
}

fn pipe_pair() -> Result<(RawFd, RawFd), RuntimeError> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc == 0 {
        Ok((fds[0], fds[1]))
    } else {
        Err(last_io_error("pipe"))
    }
}

/// Private vfork parent-suspend channel. Both ends must be close-on-host-exec:
/// the child-side write end closing is the success notification when a forked
/// native guest crosses the host self-reexec path, while a failed guest exec
/// keeps the descriptor open and correctly leaves the parent suspended.
fn vfork_pipe_pair() -> Result<(RawFd, RawFd), RuntimeError> {
    let (read_fd, write_fd) = pipe_pair()?;
    for fd in [read_fd, write_fd] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            close_fd(read_fd);
            close_fd(write_fd);
            return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                "configure native vfork completion pipe close-on-exec: {error}"
            )));
        }
    }
    Ok((read_fd, write_fd))
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn child_dup2_or_exit(from: RawFd, to: RawFd) {
    let rc = unsafe { libc::dup2(from, to) };
    if rc < 0 {
        child_write_stderr(b"native Darwin child error: dup2 failed\n");
        unsafe { libc::_exit(125) };
    }
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn read_pipe_to_end(fd: RawFd) -> Result<Vec<u8>, std::io::Error> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn join_reader(
    handle: thread::JoinHandle<Result<Vec<u8>, std::io::Error>>,
    stream: &str,
) -> Result<Vec<u8>, RuntimeError> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(err)) => Err(RuntimeError::FsBackend(anyhow::anyhow!(
            "native Darwin failed to read {stream}: {err}"
        ))),
        Err(_) => Err(RuntimeError::Unsupported(format!(
            "native Darwin {stream} reader thread panicked"
        ))),
    }
}

// See `run_static_elf`: macOS-arm-only until M0.8.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
fn waitpid_blocking(pid: libc::pid_t) -> Result<libc::c_int, RuntimeError> {
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(status);
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                "native Darwin waitpid failed: {err}"
            )));
        }
    }
}

// Runtime-error edge of `carrick_dsr::native_error::last_io_error` (same
// captured `errno`, same "{context}: {os error}" message via the
// `From<NativeMemoryError>` conversion in run_result.rs). mapped_memory.rs
// imports the carrick-dsr helper directly.
fn last_io_error(context: &str) -> RuntimeError {
    RuntimeError::from(carrick_dsr::native_error::last_io_error(context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn handoff_guest_image() -> NativeGuestImageCompatibility {
        NativeGuestImageCompatibility {
            base: 0x40_0000,
            entry: 0x40_1000,
            resolved_path: crate::probes::prepare_guest_image_path("/bin/handoff-probe".to_owned()),
        }
    }

    fn handoff_host_images() -> crate::probes::PreparedHostImagePublication {
        crate::probes::prepare_host_image_publication()
    }

    struct RecordingNativeImagePublisher<'a> {
        events: &'a RefCell<Vec<&'static str>>,
        expected_host_images: Option<*const crate::probes::PreparedHostImagePublication>,
        expected_guest: &'a NativeGuestImageCompatibility,
        expected_host_jit: std::ops::Range<u64>,
        require_same_guest_address: bool,
    }

    impl NativeImagePublisher for RecordingNativeImagePublisher<'_> {
        fn host_base(&mut self, metadata: &crate::probes::PreparedHostImagePublication) {
            if let Some(expected) = self.expected_host_images {
                assert!(std::ptr::eq(metadata, expected));
            }
            self.events.borrow_mut().push("host-base");
        }

        fn host_catalog(&mut self, metadata: &crate::probes::PreparedHostImagePublication) {
            if let Some(expected) = self.expected_host_images {
                assert!(std::ptr::eq(metadata, expected));
            }
            self.events.borrow_mut().push("host-catalog");
        }

        fn guest(&mut self, metadata: &NativeGuestImageCompatibility) {
            assert_eq!(metadata, self.expected_guest);
            if self.require_same_guest_address {
                assert!(std::ptr::eq(metadata, self.expected_guest));
                assert_eq!(
                    metadata.resolved_path.as_str().as_ptr(),
                    self.expected_guest.resolved_path.as_str().as_ptr(),
                    "guest publisher did not retain the prepared path allocation"
                );
            }
            self.events.borrow_mut().push("guest");
        }

        fn host_jit(&mut self, range: std::ops::Range<u64>) {
            assert_eq!(range, self.expected_host_jit);
            self.events.borrow_mut().push("host-jit");
        }
    }

    #[test]
    fn successful_process_handoff_activates_publishes_and_installs_in_exact_order() {
        let process = Arc::new(dsr::test_process_translator(16 * 1024).expect("translator"));
        let process_range = process.cache_host_range();
        let host_images = handoff_host_images();
        let guest_image = handoff_guest_image();
        let events = RefCell::new(Vec::new());
        let mut publisher = RecordingNativeImagePublisher {
            events: &events,
            expected_host_images: Some(&raw const host_images),
            expected_guest: &guest_image,
            expected_host_jit: process_range,
            require_same_guest_address: true,
        };

        let installed = prepare_activate_publish_commit_native_process(
            Arc::clone(&process),
            Ok::<_, dsr::types::DsrError>,
            |selected| {
                events.borrow_mut().push("activate");
                selected.activate_translated_range_catalog()
            },
            |selected| {
                publish_native_process_images(
                    selected,
                    Some(&host_images),
                    &guest_image,
                    &mut publisher,
                );
            },
            |prepared| {
                events.borrow_mut().push("install");
                prepared
            },
            || {
                events.borrow_mut().push("completion");
                Ok::<_, dsr::types::DsrError>(())
            },
        )
        .expect("successful handoff");

        assert!(Arc::ptr_eq(&installed, &process));
        assert_eq!(
            process.translated_range_catalog_state_for_test(),
            (1, 1, Some(1), 0),
        );
        assert_eq!(
            events.into_inner(),
            [
                "activate",
                "host-base",
                "host-catalog",
                "guest",
                "host-jit",
                "install",
                "completion",
            ]
        );
    }

    #[test]
    fn activation_failure_suppresses_publication_install_and_resume() {
        let process = Arc::new(dsr::test_process_translator(16 * 1024).expect("translator"));
        let host_images = handoff_host_images();
        let guest_image = handoff_guest_image();
        let events = RefCell::new(Vec::new());
        let mut publisher = RecordingNativeImagePublisher {
            events: &events,
            expected_host_images: Some(&raw const host_images),
            expected_guest: &guest_image,
            expected_host_jit: process.cache_host_range(),
            require_same_guest_address: true,
        };

        let result = prepare_activate_publish_commit_native_process(
            process,
            Ok::<_, &'static str>,
            |_| {
                events.borrow_mut().push("activate");
                Err::<(), _>("injected activation failure")
            },
            |selected| {
                publish_native_process_images(
                    selected,
                    Some(&host_images),
                    &guest_image,
                    &mut publisher,
                );
            },
            |_| {
                events.borrow_mut().push("install");
            },
            || {
                events.borrow_mut().push("completion");
                Ok::<(), &'static str>(())
            },
        );

        assert_eq!(
            result,
            Err(NativeProcessHandoffError::Activation(
                "injected activation failure"
            ))
        );
        assert_eq!(events.into_inner(), ["activate"]);
    }

    #[test]
    fn production_post_retirement_handoff_failures_abort_without_snapshot_or_resume() {
        for failpoint in [
            NativeProcessHandoffFailpoint::Activation,
            NativeProcessHandoffFailpoint::InstallationPreparation,
        ] {
            take_native_syscall_service_probe_events();
            take_native_process_handoff_events();
            set_native_process_handoff_failpoint(Some(failpoint));

            let retiring_process =
                Arc::new(dsr::test_process_translator(16 * 1024).expect("retiring translator"));
            retiring_process
                .activate_translated_range_catalog()
                .expect("activate retiring translator");
            let mut retiring_thread =
                dsr::ThreadTranslator::for_process(Arc::clone(&retiring_process), 71);
            retiring_thread.begin_exec_reset();
            retiring_thread.begin_exec_handoff();
            let replacement =
                Arc::new(dsr::test_process_translator(16 * 1024).expect("replacement translator"));
            let replacement_range = replacement.cache_host_range();
            let guest_image = handoff_guest_image();
            let dispatcher = SyscallDispatcher::new();
            let mut service = NativeSyscallServiceSpan::open(221, "execve");
            let mut snapshot = NativeUcontextSnapshot {
                pc: 0x11_1111,
                sp: 0x22_2222,
                ..NativeUcontextSnapshot::default()
            };
            let mut guest_tpidr_el0 = 0x33_3333;
            let completion_called = Cell::new(false);

            let result = complete_native_in_process_exec_handoff(
                Arc::clone(&replacement),
                None,
                &guest_image,
                &mut retiring_thread,
                guest_image.entry,
                0x50_0000,
                &dispatcher,
                &mut service,
                &mut snapshot,
                &mut guest_tpidr_el0,
                || completion_called.set(true),
            );
            drop(service);
            set_native_process_handoff_failpoint(None);

            assert!(result.is_err(), "{failpoint:?} must propagate fatally");
            assert_eq!(snapshot.pc, 0x11_1111, "{failpoint:?} installed a PC");
            assert_eq!(snapshot.sp, 0x22_2222, "{failpoint:?} installed an SP");
            assert_eq!(guest_tpidr_el0, 0x33_3333, "{failpoint:?} reset TLS");
            assert!(
                !completion_called.get(),
                "{failpoint:?} continued completion"
            );
            assert!(
                Arc::ptr_eq(&retiring_thread.process, &retiring_process),
                "{failpoint:?} installed the replacement process pointer",
            );
            assert_eq!(
                take_native_syscall_service_probe_events(),
                vec![
                    NativeSyscallServiceProbeEvent::Entry {
                        number: 221,
                        name: "execve",
                    },
                    NativeSyscallServiceProbeEvent::End {
                        number: 221,
                        name: "execve",
                        outcome: NativeSyscallServiceOutcome::Aborted,
                    },
                ],
                "{failpoint:?} must close the real service once as Aborted",
            );

            let handoff_events = take_native_process_handoff_events();
            let expected_handoff_events = match failpoint {
                NativeProcessHandoffFailpoint::Activation => {
                    vec![
                        NativeProcessHandoffEvent::InstallationPreparationAttempt,
                        NativeProcessHandoffEvent::ActivationAttempt,
                    ]
                }
                NativeProcessHandoffFailpoint::InstallationPreparation => {
                    vec![NativeProcessHandoffEvent::InstallationPreparationAttempt]
                }
            };
            assert_eq!(
                handoff_events, expected_handoff_events,
                "{failpoint:?} published stale handoff metadata before install preflight"
            );
            assert_eq!(
                handoff_events
                    .iter()
                    .filter(|event| matches!(event, NativeProcessHandoffEvent::Completion))
                    .count(),
                0,
                "{failpoint:?} published successful completion",
            );
            assert!(!handoff_events.iter().any(|event| matches!(
                event,
                NativeProcessHandoffEvent::SnapshotInstalled
                    | NativeProcessHandoffEvent::PtraceExecStop
                    | NativeProcessHandoffEvent::ServiceCompletion
            )));
            assert_eq!(
                replacement.cache_host_range(),
                replacement_range,
                "failure changed the selected replacement identity",
            );
            assert_eq!(
                replacement.translated_range_catalog_state_for_test(),
                (1, 0, None, 0),
                "{failpoint:?} activated the replacement catalog",
            );
        }
    }

    #[test]
    fn production_self_reexec_preparation_and_activation_failures_never_close_reset() {
        for failpoint in [
            NativeProcessHandoffFailpoint::InstallationPreparation,
            NativeProcessHandoffFailpoint::Activation,
        ] {
            set_native_reexec_lifecycle_capture(true);
            take_native_process_handoff_events();
            set_native_process_handoff_failpoint(Some(failpoint));
            let process = Arc::new(dsr::test_process_translator(16 * 1024).expect("translator"));
            let guest_image = handoff_guest_image();
            let dispatcher = SyscallDispatcher::new();
            let result = install_native_thread_start(
                process,
                NativeThreadStart::Initial {
                    entry: guest_image.entry,
                    initial_sp: 0x50_0000,
                    guest_image,
                    host_images: None,
                    completion: NativeInitialProcessCompletion::SelfReexec,
                },
                &dispatcher,
                71,
            );
            set_native_process_handoff_failpoint(None);

            assert!(result.is_err(), "{failpoint:?} must be fatal");
            assert!(
                !take_native_reexec_lifecycle_capture()
                    .contains(&carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecResetEnd)
            );
            let expected = match failpoint {
                NativeProcessHandoffFailpoint::InstallationPreparation => {
                    vec![NativeProcessHandoffEvent::InstallationPreparationAttempt]
                }
                NativeProcessHandoffFailpoint::Activation => vec![
                    NativeProcessHandoffEvent::InstallationPreparationAttempt,
                    NativeProcessHandoffEvent::ActivationAttempt,
                ],
            };
            assert_eq!(
                take_native_process_handoff_events(),
                expected,
                "self-reexec failure must stop before publication, commit, and completion",
            );
        }
    }

    #[test]
    fn initial_start_hands_off_once_while_detached_start_only_installs() {
        let guest_image = handoff_guest_image();
        let initial_process =
            Arc::new(dsr::test_process_translator(16 * 1024).expect("initial translator"));
        let initial_events = RefCell::new(Vec::new());
        let mut initial_publisher = RecordingNativeImagePublisher {
            events: &initial_events,
            expected_host_images: None,
            expected_guest: &guest_image,
            expected_host_jit: initial_process.cache_host_range(),
            require_same_guest_address: false,
        };
        let initial = NativeThreadStart::Initial {
            entry: guest_image.entry,
            initial_sp: 0x50_0000,
            guest_image: handoff_guest_image(),
            host_images: None,
            completion: NativeInitialProcessCompletion::Boot,
        };
        install_native_thread_start_with(
            Arc::clone(&initial_process),
            initial,
            Ok::<_, dsr::types::DsrError>,
            |selected| {
                initial_events.borrow_mut().push("activate");
                selected.activate_translated_range_catalog()
            },
            &mut initial_publisher,
            |_| {
                initial_events.borrow_mut().push("install");
            },
            |completion| {
                assert_eq!(completion, NativeInitialProcessCompletion::Boot);
                initial_events.borrow_mut().push("completion");
                Ok::<_, dsr::types::DsrError>(())
            },
        )
        .expect("install initial thread");
        assert_eq!(
            initial_events.into_inner(),
            ["activate", "guest", "host-jit", "install", "completion"]
        );
        assert_eq!(
            initial_process.translated_range_catalog_state_for_test(),
            (1, 1, Some(1), 0),
        );

        let detached_process =
            Arc::new(dsr::test_process_translator(16 * 1024).expect("detached translator"));
        let detached_events = RefCell::new(Vec::new());
        let mut detached_publisher = RecordingNativeImagePublisher {
            events: &detached_events,
            expected_host_images: None,
            expected_guest: &guest_image,
            expected_host_jit: detached_process.cache_host_range(),
            require_same_guest_address: false,
        };
        let detached = NativeThreadStart::Detached {
            context: Box::new(NativeUcontextSnapshot::default()),
            guest_tpidr_el0: 7,
        };
        install_native_thread_start_with(
            Arc::clone(&detached_process),
            detached,
            Ok::<_, dsr::types::DsrError>,
            |_| {
                detached_events.borrow_mut().push("activate");
                Ok::<_, dsr::types::DsrError>(())
            },
            &mut detached_publisher,
            |_| {
                detached_events.borrow_mut().push("install");
            },
            |_| {
                detached_events.borrow_mut().push("completion");
                Ok::<_, dsr::types::DsrError>(())
            },
        )
        .expect("install detached thread");
        assert_eq!(detached_events.into_inner(), ["install"]);
        assert_eq!(
            detached_process.translated_range_catalog_state_for_test(),
            (1, 0, None, 0),
        );
    }

    #[test]
    fn fork_child_translator_error_aborts_service_before_all_resume_events() {
        take_native_syscall_service_probe_events();
        take_native_fork_child_resume_events();
        let process = std::sync::Arc::new(
            dsr::test_process_translator(16 * 1024).expect("create translator"),
        );
        process
            .activate_translated_range_catalog()
            .expect("activate catalog");
        process
            .set_translated_range_epoch_for_test(u64::MAX)
            .expect("seed epoch overflow");
        let mut translator = dsr::ThreadTranslator::for_process(process, 71);
        let mut snapshot = NativeUcontextSnapshot {
            pc: 0x40_0000,
            sp: 0x50_0000,
            ..NativeUcontextSnapshot::default()
        };
        let mut service = NativeSyscallServiceSpan::open(220, "clone");
        assert!(service.branch(NativeSyscallBranchKind::Process));

        let result = (|| {
            repair_native_fork_child_before_resume(&mut translator, 72, &mut snapshot, 0x60_0000)?;
            record_native_fork_child_resume_event(NativeForkChildResumeEvent::SyscallCompletion);
            require_native_syscall_service_transition(
                service.end(NativeSyscallServiceOutcome::Resume),
                "test fork resume end",
            )?;
            record_native_fork_child_resume_event(NativeForkChildResumeEvent::GuestResume);
            Ok::<(), RuntimeError>(())
        })();
        drop(service);

        assert!(matches!(
            result,
            Err(RuntimeError::Unsupported(message))
                if message.contains("translated-range epoch overflow")
        ));
        assert_eq!(
            take_native_syscall_service_probe_events(),
            vec![
                NativeSyscallServiceProbeEvent::Entry {
                    number: 220,
                    name: "clone",
                },
                NativeSyscallServiceProbeEvent::Branch(NativeSyscallBranchKind::Process),
                NativeSyscallServiceProbeEvent::End {
                    number: 220,
                    name: "clone",
                    outcome: NativeSyscallServiceOutcome::Aborted,
                },
            ],
            "the failed child branch must close its inherited service exactly once"
        );
        assert!(
            take_native_fork_child_resume_events().is_empty(),
            "repair failure must precede rebuild completion, fork-post, syscall completion, \
             and guest resume"
        );
        assert_eq!(snapshot.sp, 0x50_0000, "child stack must remain untouched");
    }

    #[test]
    fn native_syscall_service_normal_and_terminal_outcomes_close_once() {
        take_native_syscall_service_probe_events();
        for outcome in [
            crate::probes::NativeSyscallServiceOutcome::Resume,
            crate::probes::NativeSyscallServiceOutcome::ThreadExit,
            crate::probes::NativeSyscallServiceOutcome::InProcessExec,
        ] {
            let mut service = NativeSyscallServiceSpan::open(63, "read");
            assert_eq!(service.state(), NativeSyscallServiceState::Open);
            assert!(service.end(outcome));
            assert_eq!(service.state(), NativeSyscallServiceState::Closed);
            assert!(!service.end(outcome));
            assert!(!service.branch(crate::probes::NativeSyscallBranchKind::Process));
        }
        let events = take_native_syscall_service_probe_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, NativeSyscallServiceProbeEvent::Entry { .. }))
                .count(),
            3
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, NativeSyscallServiceProbeEvent::End { .. }))
                .count(),
            3
        );

        let mut process_exit = NativeSyscallServiceSpan::open(94, "exit_group");
        assert!(process_exit.terminal_handoff());
        assert_eq!(
            process_exit.state(),
            NativeSyscallServiceState::TerminalHandoff
        );
        assert!(!process_exit.terminal_handoff());
        assert!(!process_exit.branch(crate::probes::NativeSyscallBranchKind::Process));
        drop(process_exit);
        assert!(
            take_native_syscall_service_probe_events()
                .iter()
                .all(|event| !matches!(event, NativeSyscallServiceProbeEvent::End { .. }))
        );

        let mut failed_self_exec = NativeSyscallServiceSpan::open(221, "execve");
        assert!(failed_self_exec.terminal_handoff());
        assert!(failed_self_exec.reopen_after_failed_terminal_handoff());
        assert_eq!(failed_self_exec.state(), NativeSyscallServiceState::Open);
        assert!(failed_self_exec.end(NativeSyscallServiceOutcome::Resume));
        assert!(matches!(
            take_native_syscall_service_probe_events().as_slice(),
            [
                NativeSyscallServiceProbeEvent::Entry {
                    number: 221,
                    name: "execve"
                },
                NativeSyscallServiceProbeEvent::End {
                    number: 221,
                    name: "execve",
                    outcome: NativeSyscallServiceOutcome::Resume
                }
            ]
        ));
    }

    #[test]
    fn native_syscall_service_branches_only_while_open() {
        take_native_syscall_service_probe_events();
        let mut service = NativeSyscallServiceSpan::open(220, "clone");
        assert!(service.branch(crate::probes::NativeSyscallBranchKind::Process));
        assert!(service.branch(crate::probes::NativeSyscallBranchKind::Thread));
        assert!(service.end(crate::probes::NativeSyscallServiceOutcome::Resume));
        assert!(!service.branch(crate::probes::NativeSyscallBranchKind::Thread));
        assert_eq!(
            take_native_syscall_service_probe_events()
                .iter()
                .filter(|event| matches!(event, NativeSyscallServiceProbeEvent::Branch(_)))
                .count(),
            2
        );
    }

    #[test]
    fn native_syscall_service_drop_reports_aborted_only_while_open() {
        take_native_syscall_service_probe_events();
        drop(NativeSyscallServiceSpan::open(63, "read"));
        assert!(matches!(
            take_native_syscall_service_probe_events().as_slice(),
            [
                NativeSyscallServiceProbeEvent::Entry { .. },
                NativeSyscallServiceProbeEvent::End {
                    outcome: crate::probes::NativeSyscallServiceOutcome::Aborted,
                    ..
                }
            ]
        ));

        let mut inherited = NativeSyscallServiceSpan::inherited_open(220, "clone");
        assert!(inherited.end(crate::probes::NativeSyscallServiceOutcome::Resume));
        assert!(matches!(
            take_native_syscall_service_probe_events().as_slice(),
            [NativeSyscallServiceProbeEvent::End {
                outcome: crate::probes::NativeSyscallServiceOutcome::Resume,
                ..
            }]
        ));
    }

    #[test]
    fn native_syscall_service_clone_request_carries_inherited_identity() {
        let request = NativeCloneThreadRequest {
            context: NativeUcontextSnapshot::default(),
            resume_pc: 0,
            parent_guest_tpidr_el0: 0,
            stack: 0,
            tls: None,
            parent_tid_addr: 0,
            child_tid_addr: 0,
            clear_child_tid_addr: 0,
            service_number: 220,
            service_name: "clone",
        };
        assert_eq!(request.service_number, 220);
        assert_eq!(request.service_name, "clone");
    }

    fn fork_test(test: impl FnOnce()) {
        fork_test_with_timeout(std::time::Duration::from_secs(5), test);
    }

    fn prepare_exec_reset_authority(
        memory: &NativeMappedMemory,
    ) -> (dsr::ThreadTranslator, dsr::DirectBindingExecResetToken) {
        let process = memory
            .dsr_process_translator()
            .expect("retiring process translator");
        let mut thread = dsr::ThreadTranslator::for_process(process, 42);
        let token = thread
            .prepare_direct_binding_exec_reset()
            .expect("mint exec reset authority");
        (thread, token)
    }

    #[test]
    fn profile_off_blocked_measurement_is_pass_through() {
        // The PROFILE=false monomorph must stay the specialized no-timer path:
        // the operation result passes through and no wall/CPU accumulation
        // happens (no timer or usage reads are reachable before the early
        // return).
        let mut blocked = NativeBlockedSpan::default();
        let value =
            measure_native_blocked::<false, _>(&mut blocked, || 7).expect("pass-through result");
        assert_eq!(value, 7);
        assert_eq!(blocked.wall_ns, 0);
        assert_eq!(blocked.cpu_ns, 0);
    }

    #[test]
    fn profiled_blocked_cpu_never_exceeds_blocked_wall() {
        let mut blocked = NativeBlockedSpan::default();
        let value = measure_native_blocked::<true, _>(&mut blocked, || {
            let mut acc = 1_u64;
            for value in 0..200_000_u64 {
                acc = acc.wrapping_mul(31).wrapping_add(value);
            }
            std::hint::black_box(acc)
        })
        .expect("measured operation");
        assert_ne!(value, 0);
        assert!(blocked.wall_ns > 0);
        assert!(
            blocked.cpu_ns <= blocked.wall_ns,
            "blocked cpu {} exceeds blocked wall {}",
            blocked.cpu_ns,
            blocked.wall_ns
        );
    }

    fn direct_test_mapping_rollback(start: u64, length: u64) -> NativeMappingRollback {
        let start = usize::try_from(start).expect("Direct test mapping start");
        let length = usize::try_from(length).expect("Direct test mapping length");
        NativeMappingRollback::new(
            NativeMappingRollbackPlan {
                supplemental_ranges: vec![
                    carrick_guest_mem::HostVa(start)..carrick_guest_mem::HostVa(start + length),
                ],
            },
            16 * 1024,
            1,
        )
        .expect("construct Direct test rollback")
    }

    fn fork_test_with_timeout(timeout: std::time::Duration, test: impl FnOnce()) {
        install_native_probe_sink();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            assert_eq!(
                unsafe { libc::setpgid(0, 0) },
                0,
                "create test process group"
            );
            test();
            unsafe { libc::_exit(0) };
        }
        // The parent-side call closes the short race before the child sets its
        // own process group. ESRCH/EACCES are harmless because the child call
        // is authoritative and there is no exec between fork and setpgid.
        let _ = unsafe { libc::setpgid(pid, pid) };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                assert!(libc::WIFEXITED(status), "forked test status={status:#x}");
                assert_eq!(libc::WEXITSTATUS(status), 0);
                return;
            }
            assert!(
                waited == 0
                    || (waited < 0
                        && std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::Interrupted),
                "waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            if std::time::Instant::now() >= deadline {
                let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
                let _ = waitpid_blocking(pid);
                panic!("forked test timed out after {timeout:?}");
            }
            unsafe { libc::usleep(10_000) };
        }
    }

    /// Forks a bounded child without creating a nested process group.
    ///
    /// The direct child is killed and reaped exactly on its own deadline. It
    /// also remains in the outer fork-test group, so the outer supervisor's
    /// group kill contains both processes if its earlier wall deadline wins.
    fn fork_nested_test_with_timeout(timeout: std::time::Duration, test: impl FnOnce()) {
        let inherited_process_group = unsafe { libc::getpgrp() };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            assert_eq!(
                unsafe { libc::getpgrp() },
                inherited_process_group,
                "nested child must remain in the outer supervision group"
            );
            test();
            unsafe { libc::_exit(0) };
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                assert!(
                    libc::WIFEXITED(status),
                    "nested forked test status={status:#x}"
                );
                assert_eq!(libc::WEXITSTATUS(status), 0);
                return;
            }
            assert!(
                waited == 0
                    || (waited < 0
                        && std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::Interrupted),
                "nested waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            if std::time::Instant::now() >= deadline {
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                let _ = waitpid_blocking(pid);
                panic!("nested forked test timed out after {timeout:?}");
            }
            unsafe { libc::usleep(10_000) };
        }
    }

    fn biased_test_memory(
        guest_start: carrick_guest_mem::GuestVa,
        len: usize,
    ) -> NativeMappedMemory {
        biased_test_memory_with_geometry(guest_start, len, 16 * 1024)
    }

    fn biased_test_memory_with_geometry(
        guest_start: carrick_guest_mem::GuestVa,
        len: usize,
        linux_page_size: u64,
    ) -> NativeMappedMemory {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED, "map biased test memory");
        let host_start = mapped as usize;
        let bias = (host_start as u64)
            .checked_sub(guest_start.raw())
            .expect("host mapping above guest base");
        let host_bias = address::NativeHostBias::new(bias, 16 * 1024).expect("aligned bias");
        NativeMappedMemory {
            address_mode: NativeAddressMode::Biased { host_bias },
            owned_host_ranges: Arc::new(vec![
                carrick_guest_mem::HostVa(host_start)..carrick_guest_mem::HostVa(host_start + len),
            ]),
            regions: vec![NativeMappedRegion {
                start: guest_start.raw(),
                end: guest_start.raw() + len as u64,
                host_protects: true,
                shared_futex: false,
                guest_writable: true,
                default_prot: crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE,
                shared_key_base: 0,
                shared_key_offset: 0,
            }],
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
            host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
            host_page_size: 16 * 1024,
            linux_page_size,
            dsr_generations: dsr::cache::PageGenerationTable::new(16 * 1024)
                .expect("generation table"),
            dsr_translator: None,
        }
    }

    #[test]
    fn biased_memory_keeps_guest_coordinates_at_runtime_boundaries() {
        fork_test(|| {
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            memory.write_bytes(0x40_0080, b"dsr").unwrap();
            assert_eq!(memory.read_bytes(0x40_0080, 3).unwrap(), b"dsr");
            let host = memory
                .host_address(carrick_guest_mem::GuestVa(0x40_0080))
                .unwrap();
            assert_eq!(
                memory.guest_fault_address(host),
                Some(carrick_guest_mem::GuestVa(0x40_0080))
            );
            assert!(memory.read_bytes(0, 1).is_err());
        });
    }

    #[test]
    fn dsr_exclusive_reservation_survives_typed_block_boundaries() {
        fork_test(|| {
            let address = 0x40_0080;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            memory
                .atomic_store(address, 4, 1)
                .expect("seed atomic word");
            let mut snapshot = NativeUcontextSnapshot::default();
            snapshot.x[4] = address;
            snapshot.x[3] = 2;
            let mut reservation = None;

            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x885f_fc9b, // ldaxr w27, [x4]
                0x61b34,
            )
            .expect("emulate split exclusive load");
            assert_eq!(snapshot.x[27], 1);
            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x881b_fc83, // stlxr w27, w3, [x4]
                0x61b40,
            )
            .expect("emulate split exclusive store");
            assert_eq!(snapshot.x[27], 0, "unchanged reservation must store");
            assert_eq!(memory.atomic_load(address, 4).expect("read stored word"), 2);

            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x885f_fc9b,
                0x61b34,
            )
            .expect("reload reservation");
            memory
                .atomic_store(address, 4, 3)
                .expect("interfere with reservation");
            snapshot.x[3] = 4;
            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x881b_fc83,
                0x61b40,
            )
            .expect("emulate failed exclusive store");
            assert_eq!(snapshot.x[27], 1, "changed reservation must fail");
            assert_eq!(
                memory
                    .atomic_load(address, 4)
                    .expect("read interfered word"),
                3
            );

            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x885f_fc9b,
                0x61b34,
            )
            .expect("reserve before ABA interference");
            memory
                .atomic_store(address, 4, 9)
                .expect("write intermediate ABA value");
            memory
                .atomic_store(address, 4, 3)
                .expect("restore observed ABA value");
            snapshot.x[3] = 5;
            emulate_dsr_exclusive_access(
                &memory,
                &mut snapshot,
                &mut reservation,
                0x881b_fc83,
                0x61b40,
            )
            .expect("emulate stale ABA store");
            assert_eq!(snapshot.x[27], 1, "ABA must invalidate reservation");
            assert_eq!(memory.atomic_load(address, 4).unwrap(), 3);
        });
    }

    #[test]
    fn exclusive_invalidation_works_through_shared_ref() {
        fork_test(|| {
            let address = 0x40_0080;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            memory
                .atomic_store(address, 4, 1)
                .expect("seed atomic word");

            // Record an exclusive reservation into a caller-owned slot: memory
            // no longer has an `exclusive_reservation` field of its own.
            let mut reservation: Option<NativeExclusiveReservation> = None;
            let observed = memory
                .exclusive_load(address, 4, true, &mut reservation)
                .expect("exclusive load");
            assert_eq!(observed, 1);

            // Drive the overlapping-write invalidation through a SHARED reference:
            // exclusive_sequences carries its own lock, so the sequence bump that a
            // plain data write performs is reachable via &self, independent of the
            // &mut self the CAS attempt below still requires.
            let shared: &NativeMappedMemory = &memory;
            shared.bump_exclusive_sequences_in_range(address, 4);

            // The reservation captured above is now stale: a subsequent exclusive
            // store must observe the CAS failure and leave memory unchanged.
            let stored = memory
                .exclusive_store(address, 4, 2, true, &mut reservation)
                .expect("exclusive store attempt");
            assert!(
                !stored,
                "store must fail: &self overlapping write invalidated the reservation"
            );
            assert_eq!(memory.atomic_load(address, 4).unwrap(), 1);
        });
    }

    #[test]
    fn write_bytes_through_shared_ref() {
        fork_test(|| {
            let address = 0x40_0080;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            memory
                .atomic_store(address, 4, 1)
                .expect("seed atomic word");

            // Record an exclusive reservation into a caller-owned slot, exactly
            // like `exclusive_invalidation_works_through_shared_ref` above.
            let mut reservation: Option<NativeExclusiveReservation> = None;
            let observed = memory
                .exclusive_load(address, 4, true, &mut reservation)
                .expect("exclusive load");
            assert_eq!(observed, 1);

            // Write to a NORMAL (non-exec: biased_test_memory's region has no
            // PROT_EXEC bit) guest page through a SHARED &NativeMappedMemory --
            // the whole point of the split is that this common-case write no
            // longer needs &mut self. `write_bytes_raw_shared` is the inherent
            // &self common path (deliberately NOT named `write_bytes_raw`,
            // see its doc comment: that name is reserved for the GuestMemory
            // trait's &mut self dispatcher so existing owned-value call sites
            // keep resolving there).
            let shared: &NativeMappedMemory = &memory;
            shared
                .write_bytes_raw_shared(address, &9u32.to_le_bytes())
                .expect("write through &self must succeed");

            // The write landed in guest RAM...
            assert_eq!(memory.read_bytes(address, 4).unwrap(), 9u32.to_le_bytes());
            // ...and it invalidated the overlapping exclusive reservation
            // captured above, exactly as the &mut self path always did: a
            // subsequent exclusive store must observe the CAS failure.
            let stored = memory
                .exclusive_store(address, 4, 2, true, &mut reservation)
                .expect("exclusive store attempt");
            assert!(
                !stored,
                "store must fail: the &self write invalidated the reservation"
            );
            assert_eq!(memory.atomic_load(address, 4).unwrap(), 9);
        });
    }

    // Task 6: `native_syscall_mutates_mappings` pre-classifier + the
    // `NativeDispatchMemory` read-guard adapter it enables at :3440.

    #[test]
    fn mapping_mutators_take_write_guard() {
        for nr in [222u64, 215, 226, 233, 216, 214, 221, 281] {
            assert!(
                native_syscall_mutates_mappings(nr),
                "nr {nr} should be a mapping mutator"
            );
        }
        for nr in [63u64, 64, 98, 172, 113] {
            assert!(!native_syscall_mutates_mappings(nr), "nr {nr} should not");
        }
    }

    #[test]
    fn non_mutator_mm_and_ipc_syscalls_stay_read_classified() {
        // munlock/munlockall: audited, bookkeeping lives in a separate
        // Mutex, never touch NativeMappedMemory. shmget/shmctl/shmat:
        // audited, shmat only touches a separate Mutex and defers its
        // actual mapping mutation to a MapHostAlias arm outside
        // dispatch_threaded (which takes its own .write()). mincore: read-only
        // by nature.
        for nr in [194u64, 195, 196, 229, 231, 232] {
            assert!(
                !native_syscall_mutates_mappings(nr),
                "nr {nr} should not be classified as a mapping mutator"
            );
        }
    }

    #[test]
    fn mapping_mutator_numbers_match_linux_abi_names() {
        // Cross-checks every number `native_syscall_mutates_mappings` uses
        // against `crate::linux_abi::syscall::lookup_aarch64`'s name, so a future
        // syscall-table renumbering can't silently desync the classifier
        // from what it thinks it's matching.
        let expected: &[(u64, &str)] = &[
            (197, "shmdt"),
            (214, "brk"),
            (215, "munmap"),
            (216, "mremap"),
            (221, "execve"),
            (222, "mmap"),
            (226, "mprotect"),
            (228, "mlock"),
            (230, "mlockall"),
            (233, "madvise"),
            (281, "execveat"),
            (284, "mlock2"),
        ];
        for &(nr, name) in expected {
            let entry = crate::linux_abi::syscall::lookup_aarch64(nr)
                .unwrap_or_else(|| panic!("nr {nr} missing from the aarch64 syscall table"));
            assert_eq!(
                entry.name, name,
                "nr {nr} is named {:?} in linux_abi, expected {name:?}",
                entry.name
            );
            assert!(
                native_syscall_mutates_mappings(nr),
                "nr {nr} ({name}) should be classified as a mapping mutator"
            );
        }
    }

    #[test]
    fn native_dispatch_memory_read_classified_syscall_reads_and_writes_data() {
        fork_test(|| {
            let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            let address = 0x40_0080u64;
            {
                let mut dispatch_memory = NativeDispatchMemory::new_read(&shared);
                dispatch_memory
                    .write_bytes(address, &42u32.to_le_bytes())
                    .expect("write through a read-classified guard must succeed");
                assert_eq!(
                    dispatch_memory.read_bytes(address, 4).unwrap(),
                    42u32.to_le_bytes()
                );
            }
            // The write is visible outside the adapter too (it landed in the
            // real NativeMappedMemory behind the RwLock, not some adapter-local
            // buffer).
            let guard = shared.read();
            assert_eq!(guard.read_bytes(address, 4).unwrap(), 42u32.to_le_bytes());
        });
    }

    #[test]
    fn native_dispatch_memory_panics_on_a_mapping_mutator_call() {
        fork_test(|| {
            let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut dispatch_memory = NativeDispatchMemory::new_read(&shared);
                dispatch_memory.set_no_access(0x40_0080, 0x4000, true);
            }));
            assert!(
                result.is_err(),
                "a mapping-mutator call through the read-classified adapter must panic \
                 loudly, never silently no-op (the trait's own default for all eight)"
            );
        });
    }

    #[test]
    fn native_dispatch_memory_escalates_to_write_for_a_write_exec_page() {
        fork_test(|| {
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let page = memory.regions[0].start;
            // Mark the page write+exec (the native16k SMC/JIT shape a prior
            // mmap(PROT_WRITE|PROT_EXEC) would have left behind) directly in
            // the table `range_may_execute`/`native16k_write_exec_page`
            // consult.
            memory.native_page_protections.insert(
                page,
                crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE
                    | crate::linux_abi::LINUX_PROT_EXEC,
            );
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            {
                let mut dispatch_memory = NativeDispatchMemory::new_read(&shared);
                dispatch_memory
                    .write_bytes_raw(page, &[0xAAu8; 4])
                    .expect("a write-exec-page write must escalate and succeed, not fail");
            }
            let guard = shared.read();
            // `native_write_exec_writable_pages` is mutated ONLY by
            // `make_native16k_write_exec_page_writable`, a `&mut self`
            // method the `&self` common path (`write_bytes_raw_shared`)
            // never calls -- its presence here proves the adapter actually
            // escalated to a real write guard, not just that the bytes
            // happen to match.
            assert!(
                guard.native_write_exec_writable_pages.contains(&page),
                "escalated write must go through write_exec_page_bytes"
            );
            assert_eq!(guard.read_bytes(page, 4).unwrap(), [0xAAu8; 4]);
        });
    }

    #[test]
    fn host_ptr_for_read_returns_pointer_for_contiguous_readable_range() {
        fork_test(|| {
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let memory = biased_test_memory(guest, 0x4000);
            let host_base = memory.host_address(guest).expect("host base").raw();
            let ptr = memory
                .host_ptr_for_read(guest.raw(), 0x4000)
                .expect("a single mapped readable region must zero-copy");
            assert_eq!(ptr as usize, host_base);
        });
    }

    #[test]
    fn host_ptr_for_read_returns_none_for_range_spanning_two_regions() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (2 * page) as usize, 16 * 1024);
            // `biased_test_memory_with_geometry` builds ONE region covering
            // both pages; split it into two adjacent regions so no SINGLE
            // region covers the full `[guest, guest+2*page)` span (mirrors
            // `prepare_temporary_host_access_rolls_back_committed_lifts_on_later_overlap_failure`'s
            // region-splitting setup).
            let template = memory.regions.remove(0);
            memory.regions.push(NativeMappedRegion {
                start: guest.raw(),
                end: guest.raw() + page,
                host_protects: template.host_protects,
                shared_futex: template.shared_futex,
                guest_writable: template.guest_writable,
                default_prot: template.default_prot,
                shared_key_base: template.shared_key_base,
                shared_key_offset: template.shared_key_offset,
            });
            memory.regions.push(NativeMappedRegion {
                start: guest.raw() + page,
                end: guest.raw() + 2 * page,
                host_protects: template.host_protects,
                shared_futex: template.shared_futex,
                guest_writable: template.guest_writable,
                default_prot: template.default_prot,
                shared_key_base: template.shared_key_base,
                shared_key_offset: template.shared_key_offset,
            });

            assert_eq!(
                memory.host_ptr_for_read(guest.raw(), (2 * page) as usize),
                None,
                "a range spanning two mapped regions has no single contiguous host \
                 backing and must fall back to the copy path"
            );
        });
    }

    #[test]
    fn host_ptr_for_read_returns_none_for_guarded_range() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            // Bookkeep the page as guest PROT_NONE (e.g. a temporarily
            // lifted/guarded page): the checked copy path can lift it for
            // the duration of the copy, but a raw zero-copy pointer cannot.
            memory.native_page_protections.insert(guest.raw(), 0);
            assert_eq!(
                memory.host_ptr_for_read(guest.raw(), page as usize),
                None,
                "a PROT_NONE-guarded range must fall back to the copy path"
            );
        });
    }

    #[test]
    fn host_ptr_for_read_returns_none_for_unmapped_range() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            // Sanity: absent the `unmapped` bookkeeping, the range zero-copies.
            assert!(
                memory
                    .host_ptr_for_read(guest.raw(), page as usize)
                    .is_some()
            );
            // Mirrors `unmap_range`'s software bookkeeping: munmap() marks the
            // range `unmapped` in `protections` but leaves the stale
            // `native_page_protections` entry (last guest-upgraded host
            // mprotect fidelity) untouched, exactly like a real munmap() on a
            // shared-aperture VA the guest previously upgraded to R/W. A
            // zero-copy read pointer must decline a freed range even though
            // the host-mprotect-fidelity table alone would still allow it.
            memory.set_unmapped(guest.raw(), page as usize, true);
            assert_eq!(
                memory.host_ptr_for_read(guest.raw(), page as usize),
                None,
                "an unmapped range must fall back to the checked (EFAULT-capable) copy path"
            );
        });
    }

    #[test]
    fn host_ptr_for_read_returns_none_for_no_access_range() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            assert!(
                memory
                    .host_ptr_for_read(guest.raw(), page as usize)
                    .is_some()
            );
            // Software `no_access` (e.g. mprotect(PROT_NONE) tracked only in
            // `protections`, independent of the native host-mprotect-fidelity
            // table) must also decline zero-copy.
            memory.set_no_access(guest.raw(), page as usize, true);
            assert_eq!(
                memory.host_ptr_for_read(guest.raw(), page as usize),
                None,
                "a no_access range must fall back to the checked (EFAULT-capable) copy path"
            );
        });
    }

    #[test]
    fn host_ptr_for_write_returns_pointer_for_writable_non_exec_range() {
        fork_test(|| {
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory(guest, 0x4000);
            let host_base = memory.host_address(guest).expect("host base").raw();
            let ptr = memory
                .host_ptr_for_write(guest.raw(), 0x4000)
                .expect("a writable non-exec region must zero-copy");
            assert_eq!(ptr as usize, host_base);
        });
    }

    #[test]
    fn host_ptr_for_write_returns_none_for_read_only_range() {
        fork_test(|| {
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory(guest, 0x4000);
            // Guest-declared read-only (e.g. `mprotect(PROT_READ)`): the
            // host page is still physically writable, but a guest write here
            // must EFAULT through the checked copy path, never land through
            // a raw host pointer.
            memory.set_no_write(guest.raw(), 0x4000, true);
            assert_eq!(
                memory.host_ptr_for_write(guest.raw(), 0x4000),
                None,
                "a guest read-only mapping must fall back to the copy path (which EFAULTs), \
                 never be written through a raw host pointer"
            );
        });
    }

    #[test]
    fn host_ptr_for_write_returns_none_for_exec_range() {
        fork_test(|| {
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let page = memory.regions[0].start;
            // Native16k SMC/JIT write-exec shape: a raw kernel write here
            // would bypass `write_exec_page_bytes`'s W^X-metadata update.
            memory.native_page_protections.insert(
                page,
                crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE
                    | crate::linux_abi::LINUX_PROT_EXEC,
            );
            assert_eq!(
                memory.host_ptr_for_write(page, 4),
                None,
                "an exec/W^X page write needs write_exec_page_bytes's metadata update, \
                 which a raw kernel write can't perform -- must fall back to the copy path"
            );
        });
    }

    #[test]
    fn native_dispatch_memory_host_ptr_for_write_zero_copies_under_read_guard() {
        fork_test(|| {
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let memory = biased_test_memory(guest, 0x4000);
            let host_base = memory.host_address(guest).expect("host base").raw();
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            let mut dispatch_memory = NativeDispatchMemory::new_read(&shared);
            let ptr = dispatch_memory
                .host_ptr_for_write(guest.raw(), 0x4000)
                .expect("a writable non-exec range must zero-copy under only the read guard");
            assert_eq!(ptr as usize, host_base);
        });
    }

    #[test]
    fn native_dispatch_memory_host_ptr_for_write_declines_exec_range() {
        fork_test(|| {
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let page = memory.regions[0].start;
            memory.native_page_protections.insert(
                page,
                crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE
                    | crate::linux_abi::LINUX_PROT_EXEC,
            );
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            let mut dispatch_memory = NativeDispatchMemory::new_read(&shared);
            assert_eq!(
                dispatch_memory.host_ptr_for_write(page, 4),
                None,
                "an exec-page target must fall back to the checked copy path (which itself \
                 escalates to the write guard), never be handed a raw pointer"
            );
        });
    }

    #[test]
    fn immutable_config_reads_lock_free() {
        fork_test(|| {
            let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            let expected_mode = memory.address_mode();
            let expected_host_page_size = memory.host_page_size;
            let expected_linux_page_size = memory.linux_page_size;
            let expected_owned_host_ranges = memory.owned_host_ranges.clone();
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            // `parking_lot::RwLock` is not reentrant: holding a write guard
            // on the big `RwLock<NativeMappedMemory>` here means any of
            // these four accessors would self-deadlock this very thread if
            // they internally acquired that same lock. Completing without
            // hanging proves they read the separate `NativeMemoryConfig`
            // lock instead (Task 8; `owned_host_ranges` joined it in
            // Phase 0 of the mmap-writer lock-free-reads refactor).
            let _write_guard = shared.write();
            assert_eq!(shared.address_mode(), expected_mode);
            assert_eq!(shared.host_page_size(), expected_host_page_size);
            assert_eq!(shared.linux_page_size(), expected_linux_page_size);
            assert_eq!(shared.owned_host_ranges(), expected_owned_host_ranges);
        });
    }

    #[test]
    fn linux4k_exclusive_load_store_round_trip_uses_explicit_reservation() {
        fork_test(|| {
            let address = 0x40_0080;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            memory
                .atomic_store(address, 4, 1)
                .expect("seed atomic word");

            // NativeMappedMemory no longer owns an `exclusive_reservation` field:
            // the linux4k guarded exclusive path (`emulate_linux4k_guarded_exclusive_access`)
            // threads a per-thread reservation into `exclusive_load`/`exclusive_store`
            // exactly like `NativeThreadRuntime.exclusive_reservation` does for the
            // DSR-hot path. This local variable is the only place the reservation
            // lives across the two calls below.
            let mut reservation: Option<NativeExclusiveReservation> = None;

            let observed = memory
                .exclusive_load(address, 4, true, &mut reservation)
                .expect("exclusive load");
            assert_eq!(observed, 1);
            assert!(
                reservation.is_some(),
                "load must populate the caller-owned reservation slot"
            );

            let stored = memory
                .exclusive_store(address, 4, 2, true, &mut reservation)
                .expect("exclusive store attempt");
            assert!(stored, "unchanged reservation must store");
            assert!(reservation.is_none(), "store consumes the reservation");
            assert_eq!(memory.atomic_load(address, 4).unwrap(), 2);

            // ABA / interference: reload the reservation, let an unrelated write
            // invalidate it via the shared `exclusive_sequences` map, then confirm
            // the CAS fails using ONLY the caller-supplied reservation -- there is
            // no struct-embedded state left to consult.
            memory
                .exclusive_load(address, 4, true, &mut reservation)
                .expect("reload reservation");
            memory
                .atomic_store(address, 4, 9)
                .expect("interfere with reservation");
            let interfered = memory
                .exclusive_store(address, 4, 3, true, &mut reservation)
                .expect("exclusive store attempt after interference");
            assert!(!interfered, "interfered reservation must fail to store");
            assert!(
                reservation.is_none(),
                "failed store still consumes the reservation"
            );
            assert_eq!(memory.atomic_load(address, 4).unwrap(), 9);
        });
    }

    #[test]
    fn dsr_exclusive_scalar_subword_widths_use_the_software_reservation() {
        fork_test(|| {
            let address = 0x40_0080;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
            for (width, load, store, initial) in [
                (1, 0x085f_7c20, 0x0802_7c20, 0x12),   // ldxrb/stxrb w0, [x1]
                (2, 0x485f_7c20, 0x4802_7c20, 0x1234), // ldxrh/stxrh w0, [x1]
            ] {
                memory
                    .atomic_store(address, width, initial)
                    .expect("seed subword exclusive value");
                let mut snapshot = NativeUcontextSnapshot::default();
                snapshot.x[1] = address;
                snapshot.x[2] = u64::MAX;
                let mut reservation = None;

                emulate_dsr_exclusive_access(
                    &memory,
                    &mut snapshot,
                    &mut reservation,
                    load,
                    0x62000,
                )
                .expect("emulate subword exclusive load");
                assert_eq!(snapshot.x[0], initial);
                snapshot.x[0] = initial + 1;
                emulate_dsr_exclusive_access(
                    &memory,
                    &mut snapshot,
                    &mut reservation,
                    store,
                    0x62004,
                )
                .expect("emulate subword exclusive store");
                assert_eq!(snapshot.x[2], 0, "subword store must consume reservation");
                assert_eq!(
                    memory
                        .atomic_load(address, width)
                        .expect("read subword exclusive value"),
                    initial + 1
                );
            }
        });
    }

    #[test]
    fn biased_alias_remap_discards_stale_page_protection() {
        fork_test(|| {
            let address = 0x40_0000;
            let len = 16 * 1024;
            let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(address), len);
            memory
                .protect_range(address, len, 0)
                .expect("protect old alias none");
            assert!(!memory.native_range_allows(address, 1, true));

            memory
                .map_host_alias(address, len as u64, &[], None, false)
                .expect("replace old alias with writable mapping");
            assert!(
                memory.native_range_allows(address, 1, true),
                "MAP_FIXED replacement must discard the prior mapping's PROT_NONE metadata"
            );
            memory
                .write_bytes(address, &[0x5a])
                .expect("write remapped alias");
            assert_eq!(
                memory.read_bytes(address, 1).expect("read remapped alias"),
                [0x5a]
            );
        });
    }

    #[test]
    fn arbitrary_host_pointer_is_not_a_guest_fault() {
        let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
        let host = carrick_guest_mem::HostVa((&memory as *const _) as usize);
        assert_eq!(memory.guest_fault_address(host), None);
        let owned = &memory.owned_host_ranges[0];
        assert_eq!(
            unsafe { libc::munmap(owned.start.raw() as *mut libc::c_void, 0x4000) },
            0
        );
    }

    #[test]
    fn biased_memory_translates_host_fault_address_once() {
        let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
        let host = memory
            .host_address(carrick_guest_mem::GuestVa(0x40_0080))
            .expect("translate test fault to host");
        assert_eq!(
            lower_dsr_fault_address(&memory, dsr::ThreadFaultAddress::Host(host))
                .expect("lower owned host fault"),
            carrick_guest_mem::GuestVa(0x40_0080)
        );
        let owned = &memory.owned_host_ranges[0];
        assert_eq!(
            unsafe { libc::munmap(owned.start.raw() as *mut libc::c_void, 0x4000) },
            0
        );
    }

    #[test]
    fn biased_owned_guard_gap_lowers_without_accepting_arbitrary_host_memory() {
        let mut memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
        let mapped = memory.owned_host_ranges[0].clone();
        let host_bias = memory
            .address_mode()
            .to_host(carrick_guest_mem::GuestVa(0))
            .expect("translate guest null");
        memory.owned_host_ranges = Arc::new(vec![host_bias..mapped.end]);

        assert_eq!(
            lower_dsr_fault_address(&memory, dsr::ThreadFaultAddress::Host(host_bias),)
                .expect("lower owned guard fault"),
            carrick_guest_mem::GuestVa(0)
        );
        let arbitrary = carrick_guest_mem::HostVa((&memory as *const _) as usize);
        assert!(
            lower_dsr_fault_address(&memory, dsr::ThreadFaultAddress::Host(arbitrary),).is_err()
        );
        assert_eq!(
            unsafe { libc::munmap(mapped.start.raw() as *mut libc::c_void, 0x4000) },
            0
        );
    }

    #[test]
    fn biased_memory_preserves_synthetic_guest_brk_address() {
        let memory = biased_test_memory(carrick_guest_mem::GuestVa(0x40_0000), 0x4000);
        let guest_pc = carrick_guest_mem::GuestVa(0x40_0080);
        assert_eq!(
            lower_dsr_fault_address(&memory, dsr::ThreadFaultAddress::Guest(guest_pc))
                .expect("preserve synthetic guest BRK address"),
            guest_pc
        );
        let owned = &memory.owned_host_ranges[0];
        assert_eq!(
            unsafe { libc::munmap(owned.start.raw() as *mut libc::c_void, 0x4000) },
            0
        );
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_linux4k_test_instruction(
        memory: &mut NativeMappedMemory,
        pc: u64,
        host_page_size: u64,
        word: u32,
    ) -> Result<(), RuntimeError> {
        memory
            .protect_range(
                pc,
                host_page_size as usize,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            )
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        memory
            .write_bytes_unchecked(pc, &word.to_le_bytes())
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        memory
            .protect_range(
                pc,
                host_page_size as usize,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            )
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))
    }

    fn dsr_test_elf(words: &[u32]) -> Vec<u8> {
        const CODE_OFFSET: usize = 0x1000;
        let code_len = std::mem::size_of_val(words);
        let mut elf = vec![0_u8; CODE_OFFSET + code_len];
        elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_u16(&mut elf, 16, 3); // ET_DYN
        write_u16(&mut elf, 18, 183); // EM_AARCH64
        write_u32(&mut elf, 20, 1);
        write_u64(&mut elf, 24, 0); // entry, relocated to native PIE base
        write_u64(&mut elf, 32, 64); // program-header offset
        write_u16(&mut elf, 52, 64);
        write_u16(&mut elf, 54, 56);
        write_u16(&mut elf, 56, 1);
        write_u32(&mut elf, 64, 1); // PT_LOAD
        write_u32(&mut elf, 68, 5); // PF_R | PF_X
        write_u64(&mut elf, 72, CODE_OFFSET as u64);
        write_u64(&mut elf, 80, 0);
        write_u64(&mut elf, 88, 0);
        write_u64(&mut elf, 96, code_len as u64);
        write_u64(&mut elf, 104, code_len as u64);
        write_u64(&mut elf, 112, 0x1000);
        for (index, word) in words.iter().copied().enumerate() {
            write_u32(&mut elf, CODE_OFFSET + index * 4, word);
        }
        elf
    }

    fn dsr_et_exec_test_elf_at(words: &[u32], guest_base: u64) -> Vec<u8> {
        const CODE_OFFSET: usize = 0x1000;
        let code_len = std::mem::size_of_val(words);
        let mut elf = vec![0_u8; CODE_OFFSET + code_len];
        elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_u16(&mut elf, 16, goblin::elf::header::ET_EXEC);
        write_u16(&mut elf, 18, 183); // EM_AARCH64
        write_u32(&mut elf, 20, 1);
        write_u64(&mut elf, 24, guest_base);
        write_u64(&mut elf, 32, 64); // program-header offset
        write_u16(&mut elf, 52, 64);
        write_u16(&mut elf, 54, 56);
        write_u16(&mut elf, 56, 1);
        write_u32(&mut elf, 64, 1); // PT_LOAD
        write_u32(&mut elf, 68, 5); // PF_R | PF_X
        write_u64(&mut elf, 72, CODE_OFFSET as u64);
        write_u64(&mut elf, 80, guest_base);
        write_u64(&mut elf, 88, guest_base);
        write_u64(&mut elf, 96, code_len as u64);
        write_u64(&mut elf, 104, code_len as u64);
        write_u64(&mut elf, 112, 0x1000);
        for (index, word) in words.iter().copied().enumerate() {
            write_u32(&mut elf, CODE_OFFSET + index * 4, word);
        }
        elf
    }

    fn dsr_low_et_exec_test_elf(words: &[u32]) -> Vec<u8> {
        dsr_et_exec_test_elf_at(words, 0x40_0000)
    }

    #[test]
    fn low_et_exec_selects_biased_mode_and_exits_zero() {
        let words = [
            0xd280_0540, // mov x0, #42
            0xd100_43e1, // sub x1, sp, #16
            0xf900_0020, // str x0, [x1]
            0xf940_0022, // ldr x2, [x1]
            0xd100_a840, // sub x0, x2, #42 (exit 0 iff biased memory round-trips)
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create low ET_EXEC fixture");
        std::io::Write::write_all(&mut file, &dsr_low_et_exec_test_elf(&words))
            .expect("write low ET_EXEC fixture");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["low-et-exec".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("run low ET_EXEC through biased DSR");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    #[test]
    fn low_et_exec_null_dereference_delivers_zero_si_addr() {
        const GUEST_BASE: u64 = 0x40_0000;
        const ACTION_OFFSET: usize = 0x80;
        const HANDLER_OFFSET: usize = 12 * 4;
        let words = [
            0xd280_0160, // mov x0, #11 (SIGSEGV)
            0xd280_1001, // mov x1, #0x80
            0xf2a0_0801, // movk x1, #0x40, lsl #16 (0x400080)
            0xd280_0002, // mov x2, #0
            0xd280_0103, // mov x3, #8
            0xd280_10c8, // mov x8, #134 (rt_sigaction)
            SVC_0,
            0xd280_0000, // mov x0, #0
            0xf940_0001, // ldr x1, [x0] (fault at guest address zero)
            0xd280_0c60, // mov x0, #99 (unreachable)
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
            0xf940_0820, // handler: ldr x0, [x1, #16] (siginfo.si_addr)
            0xf100_001f, // cmp x0, #0
            0x9a9f_07e0, // cset x0, ne
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut elf = dsr_et_exec_test_elf_at(&words, GUEST_BASE);
        let segment_offset = 0x1000;
        elf.resize(segment_offset + ACTION_OFFSET + 32, 0);
        let action = segment_offset + ACTION_OFFSET;
        elf[action..action + 8]
            .copy_from_slice(&(GUEST_BASE + HANDLER_OFFSET as u64).to_le_bytes());
        elf[action + 8..action + 16]
            .copy_from_slice(&crate::linux_abi::LINUX_SA_SIGINFO.to_le_bytes());
        write_u64(&mut elf, 96, (ACTION_OFFSET + 32) as u64);
        write_u64(&mut elf, 104, (ACTION_OFFSET + 32) as u64);

        let mut file = tempfile::NamedTempFile::new().expect("create null-fault ET_EXEC fixture");
        std::io::Write::write_all(&mut file, &elf).expect("write null-fault ET_EXEC fixture");
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["low-et-exec-null-fault".to_string()],
            std::iter::empty::<String>(),
            32,
            None,
            &native16k_test_plan(),
        )
        .expect("null dereference must reach Linux signal delivery");
        assert_eq!(
            result.exit_code,
            0,
            "SA_SIGINFO handler observed nonzero si_addr or gateway stopped early: stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn biased_stack_ceiling_is_exclusive_without_rejecting_its_last_byte() {
        for (name, words, expected_exit) in [
            (
                "ceiling-last",
                vec![
                    0xd29f_ffe0, // movz x0, #0xffff
                    0xf2bf_ffc0, // movk x0, #0xfffe, lsl #16
                    0xf2c0_1fe0, // movk x0, #0xff, lsl #32 (stack top - 1)
                    0x3940_0000, // ldrb w0, [x0]
                    0xd280_0000, // mov x0, #0
                    0xd280_0ba8, // mov x8, #93
                    SVC_0,
                ],
                0,
            ),
            (
                "ceiling",
                vec![
                    0xd2bf_ffe0, // movz x0, #0xffff, lsl #16
                    0xf2c0_1fe0, // movk x0, #0xff, lsl #32 (stack top)
                    0x3940_0000, // ldrb w0, [x0]
                    0xd280_0ba8, // mov x8, #93
                    SVC_0,
                ],
                128 + crate::linux_abi::LINUX_SIGSEGV,
            ),
        ] {
            let mut file = tempfile::NamedTempFile::new().expect("create ceiling fixture");
            std::io::Write::write_all(&mut file, &dsr_low_et_exec_test_elf(&words))
                .expect("write ceiling fixture");
            let result = run_static_elf(
                file.path(),
                SyscallDispatcher::new(),
                [name.to_string()],
                std::iter::empty::<String>(),
                32,
                None,
                &native16k_test_plan(),
            )
            .expect("collect biased ceiling result");
            assert_eq!(
                result.exit_code,
                expected_exit,
                "{name}: stderr={}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[test]
    fn biased_address_above_ceiling_cannot_alias_an_outside_host_sentinel() {
        const OUTSIDE_GUEST: u64 = address::BIASED_GUEST_APERTURE_END + 0x20_0000;
        let outside_host = carrick_guest_mem::HostVa((0x80_0000_0000 + OUTSIDE_GUEST) as usize);
        let sentinel = address::OwnedHostMapping::map_exact(
            outside_host,
            0x4000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
        )
        .expect("map outside-host sentinel");
        unsafe { std::ptr::write_bytes(outside_host.raw() as *mut u8, 0x5a, 0x4000) };
        let words = [
            0xd280_0000, // movz x0, #0
            0xf2a0_0400, // movk x0, #0x20, lsl #16
            0xf2c0_4000, // movk x0, #0x200, lsl #32 (aperture + 2 MiB)
            0x3940_0000, // ldrb w0, [x0]
            0xd280_0ba8, // mov x8, #93
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create outside-aperture fixture");
        std::io::Write::write_all(&mut file, &dsr_low_et_exec_test_elf(&words))
            .expect("write outside-aperture fixture");
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["outside-aperture".to_string()],
            std::iter::empty::<String>(),
            32,
            None,
            &native16k_test_plan(),
        )
        .expect("collect outside-aperture result");
        assert_eq!(
            result.exit_code,
            128 + crate::linux_abi::LINUX_SIGSEGV,
            "outside guest address aliased sentinel: stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(unsafe { *(outside_host.raw() as *const u8) }, 0x5a);
        drop(sentinel);
    }

    #[derive(Clone, Copy, Debug)]
    enum LifecycleImageKind {
        DirectPie,
        LowExec,
    }

    fn native16k_test_plan() -> ExecutionPlan {
        ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        }
    }

    fn lifecycle_image(kind: LifecycleImageKind, marker: u8) -> AddressSpace {
        let start = match kind {
            LifecycleImageKind::DirectPie => NATIVE_DARWIN_PIE_BASE,
            LifecycleImageKind::LowExec => 0x40_0000,
        };
        lifecycle_image_at(start, marker)
    }

    fn lifecycle_image_at(start: u64, marker: u8) -> AddressSpace {
        AddressSpace::from_segments(
            start,
            [(
                start,
                carrick_mem::elf::SegmentPerms {
                    read: true,
                    write: true,
                    execute: false,
                },
                vec![marker; 16 * 1024],
                16 * 1024,
            )],
        )
        .expect("build lifecycle image")
    }

    fn assert_direct_target_collision_is_prevalidated(source: LifecycleImageKind) {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source_image = lifecycle_image(source, 0x4b);
            let memory = NativeMappedMemory::map(
                &source_image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map source image");
            let old_guest = source_image.regions()[0].start + 0x80;
            let target_start = 0x70_1000_0000;
            let target = lifecycle_image_at(target_start, 0x72);
            let blocker = address::OwnedHostMapping::map_exact(
                carrick_guest_mem::HostVa(target_start as usize),
                16 * 1024,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
            )
            .expect("occupy direct target-only page");
            unsafe { (target_start as *mut u8).write(0x5e) };

            let error = memory
                .prepare_exec_mapping(&target, plan.page_geometry)
                .err()
                .expect("target-only direct collision must fail before retirement");
            assert!(
                error
                    .to_string()
                    .contains("native direct VM reservation collision"),
                "unexpected error: {error}"
            );
            assert_eq!(unsafe { (target_start as *const u8).read() }, 0x5e);
            assert_eq!(
                memory
                    .read_bytes(old_guest, 1)
                    .expect("old image survives target screening"),
                [0x4b]
            );
            drop(blocker);
        });
    }

    #[test]
    fn biased_source_rejects_direct_target_only_collision_before_retirement() {
        assert_direct_target_collision_is_prevalidated(LifecycleImageKind::LowExec);
    }

    #[test]
    fn direct_source_rejects_direct_target_only_collision_before_retirement() {
        assert_direct_target_collision_is_prevalidated(LifecycleImageKind::DirectPie);
    }

    #[test]
    fn biased_guest_execve_transfers_owned_overlap_to_high_direct_target() {
        fork_test(|| {
            use std::os::unix::fs::PermissionsExt;

            let source_guest_base = 0x40_0000;
            let target_base = address::BIAS_CANDIDATES[0] + source_guest_base;
            let mut target = tempfile::NamedTempFile::new().expect("create high Direct target");
            std::io::Write::write_all(&mut target, &exec_target_pc_elf_at(target_base))
                .expect("write high Direct target");
            std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))
                .expect("make high Direct target executable");
            let mut source = tempfile::NamedTempFile::new().expect("create biased exec source");
            std::io::Write::write_all(
                &mut source,
                &execve_source_elf(LifecycleImageKind::LowExec, target.path()),
            )
            .expect("write biased exec source");

            let dispatcher = SyscallDispatcher::new();
            dispatcher.set_stream_stdio(true);
            let result = run_static_elf(
                source.path(),
                dispatcher,
                ["biased-overlap-exec".to_string()],
                std::iter::empty::<String>(),
                64,
                None,
                &native16k_test_plan(),
            )
            .expect("run biased-to-high-Direct overlap exec");
            assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
            assert_eq!(result.stdout.len(), 8, "stderr={:?}", result.stderr);
            assert_eq!(
                u64::from_le_bytes(result.stdout.try_into().expect("eight-byte guest PC")),
                target_base,
                "high Direct target must execute at the biased source's prior host-owned page"
            );
        });
    }

    #[test]
    fn arbitrary_high_et_exec_uses_direct_dsr_coordinates() {
        let guest_base = 0x70_1000_0000;
        let words = [
            0x1000_0000, // adr x0, .
            0xd100_43e1, // sub x1, sp, #16
            0xf900_0020, // str x0, [x1]
            0xf940_0022, // ldr x2, [x1]
            0xcb00_0040, // sub x0, x2, x0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create high ET_EXEC fixture");
        std::io::Write::write_all(&mut file, &dsr_et_exec_test_elf_at(&words, guest_base))
            .expect("write high ET_EXEC fixture");
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["high-et-exec".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &native16k_test_plan(),
        )
        .expect("run high ET_EXEC through direct DSR");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    fn encode_adr(register: u8, byte_offset: i64) -> u32 {
        assert!(register < 32);
        assert!((-(1 << 20)..(1 << 20)).contains(&byte_offset));
        let immediate = (byte_offset as u64) & 0x1f_ffff;
        0x1000_0000
            | (((immediate & 0x3) as u32) << 29)
            | ((((immediate >> 2) & 0x7_ffff) as u32) << 5)
            | u32::from(register)
    }

    fn execve_source_elf(kind: LifecycleImageKind, target: &Path) -> Vec<u8> {
        const CODE_OFFSET: usize = 0x1000;
        let path = target.as_os_str().as_encoded_bytes();
        let code_len = 13 * std::mem::size_of::<u32>();
        let failure_marker_offset = code_len + path.len() + 1 - 5 * std::mem::size_of::<u32>();
        let words = [
            encode_adr(0, code_len as i64), // x0 = target path
            0xd280_0001,                    // mov x1, #0 (argv)
            0xd280_0002,                    // mov x2, #0 (envp)
            0xd280_1ba8,                    // mov x8, #221 (execve)
            SVC_0,
            encode_adr(1, failure_marker_offset as i64), // old-image failure continuation
            0xd280_0020,                                 // mov x0, #1 (stdout)
            0xd280_0022,                                 // mov x2, #1
            0xd280_0808,                                 // mov x8, #64 (write)
            SVC_0,
            0xd280_0c60, // mov x0, #99
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        // Keeping the pathname immediately after code makes ADR independent of
        // direct vs biased host placement and leaves every architectural
        // pointer guest-valued.
        let mut payload = Vec::with_capacity(code_len + path.len() + 2);
        for word in words {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        payload.extend_from_slice(path);
        payload.push(0);
        payload.push(b'!');
        let (elf_type, guest_base) = match kind {
            LifecycleImageKind::DirectPie => (goblin::elf::header::ET_DYN, 0),
            LifecycleImageKind::LowExec => (goblin::elf::header::ET_EXEC, 0x40_0000),
        };
        let mut elf = vec![0_u8; CODE_OFFSET + payload.len()];
        elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_u16(&mut elf, 16, elf_type);
        write_u16(&mut elf, 18, 183);
        write_u32(&mut elf, 20, 1);
        write_u64(&mut elf, 24, guest_base);
        write_u64(&mut elf, 32, 64);
        write_u16(&mut elf, 52, 64);
        write_u16(&mut elf, 54, 56);
        write_u16(&mut elf, 56, 1);
        write_u32(&mut elf, 64, 1);
        write_u32(&mut elf, 68, 5); // PF_R | PF_X
        write_u64(&mut elf, 72, CODE_OFFSET as u64);
        write_u64(&mut elf, 80, guest_base);
        write_u64(&mut elf, 88, guest_base);
        write_u64(&mut elf, 96, payload.len() as u64);
        write_u64(&mut elf, 104, payload.len() as u64);
        write_u64(&mut elf, 112, 0x1000);
        elf[CODE_OFFSET..].copy_from_slice(&payload);
        elf
    }

    fn exec_target_pc_elf(kind: LifecycleImageKind) -> Vec<u8> {
        let words = [
            0x1000_0000, // adr x0, . (architectural guest PC)
            0xd100_43e1, // sub x1, sp, #16
            0xf900_0020, // str x0, [x1]
            0xd280_0020, // mov x0, #1 (stdout)
            0xd280_0102, // mov x2, #8
            0xd280_0808, // mov x8, #64 (write)
            SVC_0,
            0xd280_0000, // mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        match kind {
            LifecycleImageKind::DirectPie => dsr_test_elf(&words),
            LifecycleImageKind::LowExec => dsr_low_et_exec_test_elf(&words),
        }
    }

    fn exec_target_pc_elf_at(guest_base: u64) -> Vec<u8> {
        let words = [
            0x1000_0000, // adr x0, . (architectural guest PC)
            0xd100_43e1, // sub x1, sp, #16
            0xf900_0020, // str x0, [x1]
            0xd280_0020, // mov x0, #1 (stdout)
            0xd280_0102, // mov x2, #8
            0xd280_0808, // mov x8, #64 (write)
            SVC_0,
            0xd280_0000, // mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        dsr_et_exec_test_elf_at(&words, guest_base)
    }

    #[test]
    fn preflight_exec_error_returns_enomem_without_deadlocking_old_image() {
        use std::os::unix::fs::PermissionsExt;

        const TARGET_BASE: u64 = 0x70_1000_0000;
        let target_words = [
            0xd280_0000, // mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut target = tempfile::NamedTempFile::new().expect("create blocked exec target");
        std::io::Write::write_all(
            &mut target,
            &dsr_et_exec_test_elf_at(&target_words, TARGET_BASE),
        )
        .expect("write blocked exec target");
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make blocked exec target executable");
        let mut source = tempfile::NamedTempFile::new().expect("create exec source");
        std::io::Write::write_all(
            &mut source,
            &execve_source_elf(LifecycleImageKind::LowExec, target.path()),
        )
        .expect("write exec source");

        fork_test_with_timeout(std::time::Duration::from_secs(5), move || {
            let blocker = address::OwnedHostMapping::map_exact(
                carrick_guest_mem::HostVa(TARGET_BASE as usize),
                16 * 1024,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
            )
            .expect("occupy direct exec target");
            let dispatcher = SyscallDispatcher::new();
            dispatcher.set_stream_stdio(true);
            let result = run_static_elf(
                source.path(),
                dispatcher,
                ["preflight-error".to_string()],
                std::iter::empty::<String>(),
                64,
                None,
                &native16k_test_plan(),
            )
            .expect("run old image through rejected execve");
            assert_eq!(result.exit_code, 99, "stderr={:?}", result.stderr);
            assert_eq!(result.stdout, b"!");
            drop(blocker);
        });
    }

    #[test]
    fn guest_execve_runs_all_required_address_mode_transitions() {
        use std::os::unix::fs::PermissionsExt;

        for (source_kind, target_kind, expected_pc) in [
            (
                LifecycleImageKind::DirectPie,
                LifecycleImageKind::LowExec,
                0x40_0000,
            ),
            (
                LifecycleImageKind::LowExec,
                LifecycleImageKind::DirectPie,
                NATIVE_DARWIN_PIE_BASE,
            ),
            (
                LifecycleImageKind::LowExec,
                LifecycleImageKind::LowExec,
                0x40_0000,
            ),
        ] {
            let mut target = tempfile::NamedTempFile::new().expect("create exec target");
            std::io::Write::write_all(&mut target, &exec_target_pc_elf(target_kind))
                .expect("write exec target");
            std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))
                .expect("make exec target executable");

            let mut source = tempfile::NamedTempFile::new().expect("create exec source");
            std::io::Write::write_all(&mut source, &execve_source_elf(source_kind, target.path()))
                .expect("write exec source");

            let dispatcher = SyscallDispatcher::new();
            dispatcher.set_stream_stdio(true);
            let result = run_static_elf(
                source.path(),
                dispatcher,
                ["exec-transition".to_string()],
                std::iter::empty::<String>(),
                64,
                None,
                &native16k_test_plan(),
            )
            .expect("run guest execve transition");
            assert_eq!(
                result.exit_code, 0,
                "source={source_kind:?} target={target_kind:?} stderr={:?}",
                result.stderr
            );
            assert_eq!(
                result.stdout.len(),
                8,
                "source={source_kind:?} target={target_kind:?} stderr={:?}",
                result.stderr
            );
            assert_eq!(
                u64::from_le_bytes(result.stdout.try_into().expect("eight-byte guest PC")),
                expected_pc,
                "source={source_kind:?} target={target_kind:?} must report architectural guest PC after its stack store and write syscall"
            );
        }
    }

    #[test]
    fn post_retirement_exec_failure_is_fatal_without_old_image_resume() {
        use std::os::unix::fs::PermissionsExt;

        let mut target = tempfile::NamedTempFile::new().expect("create late-failure target");
        std::io::Write::write_all(
            &mut target,
            &exec_target_pc_elf(LifecycleImageKind::DirectPie),
        )
        .expect("write late-failure target");
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make late-failure target executable");
        let mut source = tempfile::NamedTempFile::new().expect("create late-failure source");
        std::io::Write::write_all(
            &mut source,
            &execve_source_elf(LifecycleImageKind::LowExec, target.path()),
        )
        .expect("write late-failure source");

        NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.set(true));
        let result = run_static_elf(
            source.path(),
            SyscallDispatcher::new(),
            ["late-exec-failure".to_string()],
            std::iter::empty::<String>(),
            64,
            None,
            &native16k_test_plan(),
        )
        .expect("collect fatal late-exec result");
        NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.set(false));

        assert_eq!(result.exit_code, 125, "stderr={:?}", result.stderr);
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("native execve failed after retiring the old owned address space"),
            "stderr={:?}",
            result.stderr
        );
        assert!(
            result.stdout.is_empty(),
            "old-image exec failure continuation emitted {:?}",
            result.stdout
        );
    }

    fn assert_exec_transition(source: LifecycleImageKind, target: LifecycleImageKind) {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source_image = lifecycle_image(source, 0x31);
            let target_image = lifecycle_image(target, 0x72);
            let mut memory = NativeMappedMemory::map(
                &source_image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map source lifecycle image");
            let source_mode = memory.address_mode();
            let source_process = memory.dsr_process_translator().expect("source translator");
            let prepared = memory
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("preselect replacement layout");
            let prepared_mode = prepared.native_layout.address_mode();
            let prepared_process = Arc::clone(&prepared.process_translator);
            let (exec_thread, mut reset_token) = prepare_exec_reset_authority(&memory);

            memory
                .replace_image(
                    &target_image,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect("replace lifecycle image");

            let expected_target_biased = matches!(target, LifecycleImageKind::LowExec);
            assert_eq!(
                matches!(memory.address_mode(), NativeAddressMode::Biased { .. }),
                expected_target_biased,
                "source={source:?} target={target:?}"
            );
            assert_eq!(memory.address_mode(), prepared_mode);
            assert!(Arc::ptr_eq(
                &memory
                    .dsr_process_translator()
                    .expect("replacement translator"),
                &prepared_process
            ));
            assert!(
                !Arc::ptr_eq(&source_process, &prepared_process),
                "root exec must hand off to a fresh process translator"
            );
            if matches!(source, LifecycleImageKind::LowExec)
                && matches!(target, LifecycleImageKind::LowExec)
            {
                assert_eq!(
                    source_mode, prepared_mode,
                    "biased->biased must transfer the collision-probed aperture"
                );
            }

            let guest_start = target_image.regions()[0].start;
            let guest_end = target_image.regions()[0].end;
            assert_eq!(guest_end - guest_start, 16 * 1024);
            assert!(memory.region_contains(guest_start, 16 * 1024));
            assert!(!memory.region_contains(guest_start - 1, 1));
            assert_eq!(
                memory
                    .read_bytes(guest_start + 0x100, 1)
                    .expect("read target marker"),
                [0x72]
            );
            memory
                .write_bytes(guest_start + 0x100, &[0xa5])
                .expect("write target by guest address");
            assert_eq!(
                memory
                    .read_bytes(guest_start + 0x100, 1)
                    .expect("read guest write"),
                [0xa5]
            );
            let host = memory
                .host_address(carrick_guest_mem::GuestVa(guest_start + 0x100))
                .expect("translate target guest address");
            assert_eq!(
                host.raw() as u64 == guest_start + 0x100,
                !expected_target_biased
            );
        });
    }

    #[test]
    fn exec_transitions_preserve_guest_addresses_across_modes() {
        for (source, target) in [
            (LifecycleImageKind::DirectPie, LifecycleImageKind::LowExec),
            (LifecycleImageKind::LowExec, LifecycleImageKind::DirectPie),
            (LifecycleImageKind::LowExec, LifecycleImageKind::LowExec),
        ] {
            assert_exec_transition(source, target);
        }
    }

    #[test]
    fn exec_transition_fresh_candidate_stays_dormant_without_retiring_catalog_reset() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source_image = lifecycle_image(LifecycleImageKind::DirectPie, 0x31);
            let target_image = lifecycle_image(LifecycleImageKind::DirectPie, 0x72);
            let mut memory = NativeMappedMemory::map(
                &source_image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map source image");
            let retiring = memory
                .dsr_process_translator()
                .expect("retiring translator");
            retiring
                .activate_translated_range_catalog()
                .expect("activate retiring catalog");
            retiring
                .add_translated_range_for_test(71, 0x2000_0000..0x2001_0000)
                .expect("seed retiring shared catalog entry");
            retiring
                .set_translated_range_epoch_for_test(u64::MAX)
                .expect("seed overflow boundary");
            let retiring_before = retiring.translated_range_catalog_state_for_test();

            let abandoned = memory
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("prepare fresh replacement");
            assert!(!abandoned.reset_inherited_translator);
            assert!(!Arc::ptr_eq(&abandoned.process_translator, &retiring));
            assert_eq!(
                abandoned
                    .process_translator
                    .translated_range_catalog_state_for_test(),
                (1, 0, None, 0),
                "fresh candidate activated before the exec point of no return",
            );
            drop(abandoned);
            assert_eq!(
                retiring.translated_range_catalog_state_for_test(),
                retiring_before,
                "abandoned preparation changed the active retiring catalog",
            );

            let prepared = memory
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("prepare replacement after abandonment");
            let candidate = Arc::clone(&prepared.process_translator);
            let (mut exec_thread, mut reset_token) = prepare_exec_reset_authority(&memory);
            memory
                .replace_image(
                    &target_image,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect("fresh replacement must not preflight retiring catalog overflow");

            assert_eq!(
                retiring.translated_range_catalog_state_for_test(),
                retiring_before,
                "fresh replacement reset the retiring catalog",
            );
            assert_eq!(
                candidate.translated_range_catalog_state_for_test(),
                (1, 0, None, 0),
                "preflight/commit slice must leave fresh replacement dormant",
            );

            let events = RefCell::new(Vec::new());
            let guest_image =
                NativeGuestImageCompatibility::from_image(&target_image, "/bin/fresh-replacement");
            let mut publisher = RecordingNativeImagePublisher {
                events: &events,
                expected_host_images: None,
                expected_guest: &guest_image,
                expected_host_jit: candidate.cache_host_range(),
                require_same_guest_address: true,
            };
            prepare_activate_publish_commit_native_process(
                Arc::clone(&candidate),
                |selected| {
                    assert!(Arc::ptr_eq(&selected, &candidate));
                    exec_thread.prepare_reset_for_exec(selected)
                },
                |selected| {
                    events.borrow_mut().push("activate");
                    selected.activate_translated_range_catalog()
                },
                |selected| {
                    publish_native_process_images(selected, None, &guest_image, &mut publisher);
                },
                |prepared| {
                    events.borrow_mut().push("install");
                    prepared.commit();
                },
                || {
                    events.borrow_mut().push("completion");
                    Ok::<_, dsr::types::DsrError>(())
                },
            )
            .expect("activate and install fresh replacement");
            assert_eq!(
                events.into_inner(),
                ["activate", "guest", "host-jit", "install", "completion"],
            );
            assert_eq!(
                candidate.translated_range_catalog_state_for_test(),
                (1, 1, Some(1), 0),
                "fresh replacement must activate exactly once at handoff",
            );
        });
    }

    #[test]
    fn exec_transition_external_private_lease_rejects_before_ponr_and_token_retries() {
        fork_test(|| {
            take_native_process_handoff_events();
            let plan = native16k_test_plan();
            let source_image = lifecycle_image(LifecycleImageKind::DirectPie, 0x31);
            let target_image = lifecycle_image(LifecycleImageKind::DirectPie, 0x72);
            let mut memory = NativeMappedMemory::map(
                &source_image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map source image");
            let retiring = memory
                .dsr_process_translator()
                .expect("retiring translator");
            retiring
                .activate_translated_range_catalog()
                .expect("activate retiring catalog");
            let retiring_before = retiring.translated_range_catalog_state_for_test();
            let external_lease = retiring.private_jit_epoch_lease_for_test();
            let prepared = memory
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("prepare rejected replacement");
            let (exec_thread, mut reset_token) = prepare_exec_reset_authority(&memory);

            let error = memory
                .replace_image(
                    &target_image,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect_err("external lease must reject replacement before PONR");

            assert!(
                error.to_string().contains("private JIT descriptor lease"),
                "unexpected error: {error}",
            );
            assert_eq!(
                memory
                    .read_bytes(source_image.regions()[0].start + 0x100, 1)
                    .expect("old image remains readable"),
                [0x31],
            );
            assert_eq!(
                retiring.translated_range_catalog_state_for_test(),
                retiring_before,
            );
            assert!(
                take_native_process_handoff_events().is_empty(),
                "pre-PONR lease rejection published successful handoff metadata",
            );

            drop(external_lease);
            let prepared = memory
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("prepare retry after lease drop");
            memory
                .replace_image(
                    &target_image,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect("same validated authority remains usable after preflight rejection");
        });
    }

    #[test]
    fn direct_exec_preserves_the_identity_fast_path_and_owned_ranges() {
        assert_exec_transition(LifecycleImageKind::DirectPie, LifecycleImageKind::DirectPie);
        let old = [carrick_guest_mem::HostVa(0x4000)..carrick_guest_mem::HostVa(0xc000)];
        let target = [carrick_guest_mem::HostVa(0x8000)..carrick_guest_mem::HostVa(0x1_0000)];
        assert_eq!(
            subtract_host_ranges(&old, &target),
            [carrick_guest_mem::HostVa(0x4000)..carrick_guest_mem::HostVa(0x8000)],
            "direct exec must retain the overlapping Carrick-owned pages continuously"
        );
    }

    #[test]
    fn replace_image_refreshes_the_lock_free_config() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source_image = lifecycle_image(LifecycleImageKind::DirectPie, 0x31);
            let target_image = lifecycle_image(LifecycleImageKind::LowExec, 0x72);
            let memory = NativeMappedMemory::map(
                &source_image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map source lifecycle image");
            let shared: SharedNativeMemory = Arc::new(NativeMemoryHandle::new(memory));
            assert_eq!(shared.address_mode(), NativeAddressMode::Direct);
            let source_owned_host_ranges = shared.owned_host_ranges();
            assert!(
                !source_owned_host_ranges.is_empty(),
                "source image must own at least one host range"
            );

            let prepared = shared
                .read()
                .prepare_exec_mapping(&target_image, plan.page_geometry)
                .expect("preselect replacement layout");
            let (exec_thread, mut reset_token) = prepare_exec_reset_authority(&shared.read());

            shared
                .replace_image(
                    &target_image,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect("replace lifecycle image");

            // The execve-updated fields must be visible through the
            // lock-free config handle -- not just through a fresh `.read()`
            // guard on the big RwLock.
            assert!(matches!(
                shared.address_mode(),
                NativeAddressMode::Biased { .. }
            ));
            let guard = shared.read();
            assert_eq!(shared.address_mode(), guard.address_mode());
            assert_eq!(shared.host_page_size(), guard.host_page_size);
            assert_eq!(shared.linux_page_size(), guard.linux_page_size);
            assert_eq!(shared.owned_host_ranges(), guard.owned_host_ranges);
            assert_ne!(
                shared.owned_host_ranges(),
                source_owned_host_ranges,
                "replace_image must refresh owned_host_ranges to the new image's ranges, \
                 not leave the pre-execve source-image ranges behind"
            );
        });
    }

    #[test]
    fn failed_biased_exec_preselection_preserves_the_old_image() {
        fork_test(|| {
            take_native_process_handoff_events();
            let plan = native16k_test_plan();
            let image = lifecycle_image(LifecycleImageKind::LowExec, 0x4d);
            let memory = NativeMappedMemory::map(
                &image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map old biased image");
            let old_mode = memory.address_mode();
            let guest_start = image.regions()[0].start;
            let invalid_target = AddressSpace::from_segments(
                guest_start,
                [
                    (
                        guest_start,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: false,
                            execute: true,
                        },
                        vec![0x71; 16 * 1024],
                        16 * 1024,
                    ),
                    (
                        address::BIASED_GUEST_APERTURE_END,
                        carrick_mem::elf::SegmentPerms {
                            read: true,
                            write: false,
                            execute: false,
                        },
                        vec![0x72; 16 * 1024],
                        16 * 1024,
                    ),
                ],
            )
            .expect("build target beyond biased ceiling");

            let error = memory
                .prepare_exec_mapping(&invalid_target, plan.page_geometry)
                .err()
                .expect("target beyond biased ceiling must fail before retirement");
            assert!(
                error
                    .to_string()
                    .contains("no collision-free native host bias")
            );
            assert_eq!(memory.address_mode(), old_mode);
            assert_eq!(
                memory
                    .read_bytes(guest_start + 0x80, 1)
                    .expect("old image remains mapped"),
                [0x4d]
            );
            assert!(
                take_native_process_handoff_events().is_empty(),
                "failed preselection published successful handoff metadata",
            );
        });
    }

    #[test]
    fn abandoned_biased_exec_preparation_preserves_the_old_image() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source = lifecycle_image(LifecycleImageKind::LowExec, 0x4d);
            let target = lifecycle_image(LifecycleImageKind::LowExec, 0x72);
            let memory = NativeMappedMemory::map(
                &source,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map old biased image");
            let guest = source.regions()[0].start + 0x80;

            let prepared = memory
                .prepare_exec_mapping(&target, plan.page_geometry)
                .expect("prepare biased replacement before sibling teardown");
            assert!(matches!(
                prepared.native_layout.address_mode(),
                NativeAddressMode::Biased { .. }
            ));
            drop(prepared);

            assert_eq!(
                memory
                    .read_bytes(guest, 1)
                    .expect("old image remains readable when prepared exec is abandoned"),
                [0x4d]
            );
        });
    }

    #[test]
    fn fork_child_inherits_the_parent_bias() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let image = lifecycle_image(LifecycleImageKind::LowExec, 0x5a);
            let memory = NativeMappedMemory::map(
                &image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map parent biased image");
            let parent_mode = memory.address_mode();
            let guest = image.regions()[0].start + 0x120;
            let parent_host = memory
                .host_address(carrick_guest_mem::GuestVa(guest))
                .expect("translate parent guest address");
            let child = unsafe { libc::fork() };
            assert!(
                child >= 0,
                "fork biased child: {}",
                std::io::Error::last_os_error()
            );
            if child == 0 {
                let inherited = memory.address_mode() == parent_mode
                    && memory
                        .host_address(carrick_guest_mem::GuestVa(guest))
                        .is_ok_and(|host| host == parent_host)
                    && memory
                        .read_bytes(guest, 1)
                        .is_ok_and(|bytes| bytes == [0x5a]);
                unsafe { libc::_exit(i32::from(!inherited)) };
            }
            let status = waitpid_blocking(child).expect("wait biased child");
            assert!(libc::WIFEXITED(status), "child status={status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(memory.address_mode(), parent_mode);
        });
    }

    #[test]
    fn fork_child_exec_reuses_translator_and_reselects_layout() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let source = lifecycle_image(LifecycleImageKind::LowExec, 0x21);
            let target = lifecycle_image(LifecycleImageKind::LowExec, 0x43);
            let mut memory = NativeMappedMemory::map(
                &source,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map parent image before fork");
            let parent_mode = memory.address_mode();
            let inherited_process = memory.dsr_process_translator().expect("parent translator");
            inherited_process
                .activate_translated_range_catalog()
                .expect("activate inherited catalog");
            inherited_process
                .add_translated_range_for_test(72, 0x2200_0000..0x2201_0000)
                .expect("seed inherited shared range");
            let inherited_before = inherited_process.translated_range_catalog_state_for_test();
            let mut exec_thread =
                dsr::ThreadTranslator::for_process(Arc::clone(&inherited_process), 42);
            let outer_process_group = unsafe { libc::getpgrp() };
            fork_nested_test_with_timeout(std::time::Duration::from_secs(5), || {
                if unsafe { libc::getpgrp() } != outer_process_group {
                    unsafe { libc::_exit(9) };
                }
                NATIVE_FORKED_GUEST_CHILD.store(true, std::sync::atomic::Ordering::Release);
                if exec_thread.after_fork_child(43).is_err() {
                    unsafe { libc::_exit(2) };
                }
                let prepared = memory
                    .prepare_exec_mapping(&target, plan.page_geometry)
                    .expect("prepare fork-child replacement without allocating a translator");
                let prepared_mode = prepared.native_layout.address_mode();
                // The inherited Carrick-owned aperture is reusable authority;
                // a biased replacement keeps its bias instead of probing a
                // different candidate after fork.
                let reused = prepared.reset_inherited_translator
                    && Arc::ptr_eq(&prepared.process_translator, &inherited_process)
                    && prepared_mode == parent_mode;
                if !reused {
                    unsafe { libc::_exit(3) };
                }
                let mut reset_token = match exec_thread.prepare_direct_binding_exec_reset() {
                    Ok(token) => token,
                    Err(_) => unsafe { libc::_exit(4) },
                };
                if memory
                    .replace_image(
                        &target,
                        &[],
                        plan.page_geometry,
                        &exec_thread,
                        &mut reset_token,
                        prepared,
                    )
                    .is_err()
                {
                    unsafe { libc::_exit(5) };
                }
                let dormant =
                    inherited_process.translated_range_catalog_state_for_test() == (3, 0, None, 0);
                if !dormant {
                    unsafe { libc::_exit(6) };
                }
                let guest_image =
                    NativeGuestImageCompatibility::from_image(&target, "/bin/inherited-exec");
                let events = RefCell::new(Vec::new());
                let mut publisher = RecordingNativeImagePublisher {
                    events: &events,
                    expected_host_images: None,
                    expected_guest: &guest_image,
                    expected_host_jit: inherited_process.cache_host_range(),
                    require_same_guest_address: true,
                };
                let installed = prepare_activate_publish_commit_native_process(
                    Arc::clone(&inherited_process),
                    |selected| {
                        if !Arc::ptr_eq(&selected, &inherited_process) {
                            return Err(dsr::types::DsrError::CachePolicy(
                                "inherited exec selected a different translator".to_owned(),
                            ));
                        }
                        exec_thread.prepare_reset_for_exec(selected)
                    },
                    dsr::ProcessTranslator::activate_translated_range_catalog,
                    |selected| {
                        publish_native_process_images(selected, None, &guest_image, &mut publisher);
                    },
                    dsr::PreparedThreadExecHandoff::commit,
                    || Ok::<_, dsr::types::DsrError>(()),
                );
                if installed.is_err() {
                    unsafe { libc::_exit(7) };
                }
                let activated = inherited_process.translated_range_catalog_state_for_test();
                if inherited_process
                    .activate_translated_range_catalog()
                    .is_err()
                    || inherited_process.translated_range_catalog_state_for_test() != activated
                    || activated != (3, 1, Some(1), 0)
                {
                    unsafe { libc::_exit(8) };
                }
                let passed = memory.address_mode() == prepared_mode
                    && Arc::ptr_eq(
                        &memory.dsr_process_translator().expect("child translator"),
                        &inherited_process,
                    )
                    && memory
                        .read_bytes(target.regions()[0].start + 0x40, 1)
                        .is_ok_and(|bytes| bytes == [0x43]);
                unsafe { libc::_exit(i32::from(!passed)) };
            });
            assert_eq!(memory.address_mode(), parent_mode);
            assert_eq!(
                inherited_process.translated_range_catalog_state_for_test(),
                inherited_before,
                "child exec reset mutated the parent's COW catalog",
            );
        });
    }

    #[test]
    fn biased_vdso_and_vvar_remain_guest_addressed() {
        fork_test(|| {
            let plan = native16k_test_plan();
            let image = with_native_vdso(lifecycle_image(LifecycleImageKind::LowExec, 0x19))
                .expect("attach native vDSO");
            let memory = NativeMappedMemory::map(
                &image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map biased vDSO image");
            assert!(matches!(
                memory.address_mode(),
                NativeAddressMode::Biased { .. }
            ));
            for (guest, len) in [
                (NATIVE_DARWIN_VVAR_BASE, crate::vdso::LINUX_VVAR_SIZE),
                (NATIVE_DARWIN_VDSO_BASE, crate::vdso::LINUX_VDSO_SIZE),
            ] {
                assert!(memory.region_contains(guest, len as usize));
                assert_eq!(
                    memory
                        .read_bytes(guest, 1)
                        .expect("read runtime guest page")
                        .len(),
                    1
                );
                let host = memory
                    .host_address(carrick_guest_mem::GuestVa(guest))
                    .expect("translate runtime guest page");
                assert_ne!(host.raw() as u64, guest);
                assert_eq!(
                    memory.guest_fault_address(host),
                    Some(carrick_guest_mem::GuestVa(guest))
                );
            }
        });
    }

    fn dsr_straight_line_syscall_elf() -> Vec<u8> {
        dsr_test_elf(&[
            0xd280_1588, // mov x8, #172 (getpid)
            SVC_0,
            0xd100_43e1, // sub x1, sp, #16
            0xf900_0020, // str x0, [x1]
            0xd280_0020, // mov x0, #1
            0xd280_0102, // mov x2, #8
            0xd280_0808, // mov x8, #64 (write)
            SVC_0,
            0xd280_0000, // mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ])
    }

    #[test]
    fn dsr_gateway_dispatches_straight_line_getpid_write_and_exit() {
        let mut file = tempfile::NamedTempFile::new().expect("create DSR ELF fixture");
        std::io::Write::write_all(&mut file, &dsr_straight_line_syscall_elf())
            .expect("write DSR ELF fixture");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let dispatcher = SyscallDispatcher::new();
        dispatcher.set_stream_stdio(true);
        let result = run_static_elf(
            file.path(),
            dispatcher,
            ["dsr-syscall".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("run straight-line DSR syscall ELF");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
        assert_eq!(result.stdout.len(), 8, "stderr={:?}", result.stderr);
        let pid = u64::from_le_bytes(result.stdout.try_into().expect("eight-byte pid output"));
        assert!(pid > 0);
    }

    #[test]
    fn dsr_direct_flow_runtime_resolves_and_links_backward_loop() {
        let words = [
            0xd280_0080, // mov x0, #4
            0xf100_0400, // subs x0, x0, #1
            0xb5ff_ffe0, // cbnz x0, -4
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create DSR loop ELF fixture");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words))
            .expect("write DSR loop ELF fixture");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-loop".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("run linked DSR loop ELF");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    #[test]
    fn dsr_generation_guard_preserves_x16_x17_and_flags_across_linked_blocks() {
        let words = [
            0xd280_0530, // mov x16, #41
            0xd280_0551, // mov x17, #42
            0xeb00_001f, // cmp x0, x0 (Z=1)
            0x1400_0001, // b target
            0x5400_00a1, // target: b.ne fail
            0xd100_a600, // sub x0, x16, #41
            0xd100_aa21, // sub x1, x17, #42
            0xaa01_0000, // orr x0, x0, x1
            0x1400_0002, // b exit
            0xd280_0c60, // fail: mov x0, #99
            0xd280_0ba8, // exit: mov x8, #93
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create DSR guard ELF fixture");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words))
            .expect("write DSR guard ELF fixture");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-guard-state".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("run linked DSR guard-state ELF");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    #[test]
    fn dsr_indirect_flow_runtime_calls_and_returns_through_guest_lr() {
        let words = [
            0x9400_0002, // bl function
            0x1400_0002, // b exit
            0xd65f_03c0, // function: ret
            0xd280_0000, // exit: mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create DSR return ELF fixture");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words))
            .expect("write DSR return ELF fixture");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-return".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("run DSR return ELF");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    #[test]
    fn dsr_indirect_flow_runtime_lowers_invalid_targets_to_guest_signals() {
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        for (target_word, expected_signal) in [
            (0xd280_0020, crate::linux_abi::LINUX_SIGBUS), // mov x0, #1
            (0xd280_0000, crate::linux_abi::LINUX_SIGSEGV), // mov x0, #0
        ] {
            let words = [target_word, 0xd61f_0000]; // br x0
            let mut file = tempfile::NamedTempFile::new().expect("create invalid-target ELF");
            std::io::Write::write_all(&mut file, &dsr_test_elf(&words))
                .expect("write invalid-target ELF");
            let result = run_static_elf(
                file.path(),
                SyscallDispatcher::new(),
                ["dsr-invalid-target".to_string()],
                std::iter::empty::<String>(),
                16,
                None,
                &plan,
            )
            .expect("collect invalid-target child result");
            assert_eq!(
                result.exit_code,
                128 + expected_signal,
                "stderr={}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[test]
    fn dsr_sensitive_flow_runtime_reuses_native_system_register_semantics() {
        let words = [
            0xd53b_d040, // mrs x0, tpidr_el0
            0xd51b_d040, // msr tpidr_el0, x0
            0xd53b_0021, // mrs x1, ctr_el0
            0xd53b_00e2, // mrs x2, dczid_el0
            0xd50b_7b20, // dc cvau, x0 (native backend no-op)
            0xd50b_7520, // ic ivau, x0 (native backend no-op)
            0xd280_0000, // mov x0, #0
            0xd280_0ba8, // mov x8, #93 (exit)
            SVC_0,
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create DSR sensitive ELF");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words))
            .expect("write DSR sensitive ELF");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-sensitive".to_string()],
            std::iter::empty::<String>(),
            32,
            None,
            &plan,
        )
        .expect("run DSR sensitive ELF");
        assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
    }

    #[test]
    fn dsr_signal_fault_runtime_lowers_cache_pc_to_guest_sigsegv() {
        let words = [
            0xd280_0020, // mov x0, #1
            0xf940_0001, // ldr x1, [x0]
        ];
        let mut file = tempfile::NamedTempFile::new().expect("create DSR fault ELF");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words)).expect("write DSR fault ELF");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-fault".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("collect DSR fault result");
        assert_eq!(
            result.exit_code,
            128 + crate::linux_abi::LINUX_SIGSEGV,
            "stderr={:?}",
            result.stderr
        );
    }

    #[test]
    fn dsr_signal_fault_runtime_lowers_guest_brk_to_sigtrap() {
        let words = [0xd420_0020]; // brk #1
        let mut file = tempfile::NamedTempFile::new().expect("create DSR brk ELF");
        std::io::Write::write_all(&mut file, &dsr_test_elf(&words)).expect("write DSR brk ELF");
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::Native,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            diagnostics: Vec::new(),
        };
        let result = run_static_elf(
            file.path(),
            SyscallDispatcher::new(),
            ["dsr-brk".to_string()],
            std::iter::empty::<String>(),
            16,
            None,
            &plan,
        )
        .expect("collect DSR brk result");
        assert_eq!(
            result.exit_code,
            128 + crate::linux_abi::LINUX_SIGTRAP,
            "stderr={:?}",
            result.stderr
        );
    }

    #[test]
    fn dsr_original_executable_page_is_a_nonexecute_backstop() {
        let address = 0x70_0000_0000_u64;
        let image = AddressSpace::from_segments(
            address,
            [(
                address,
                carrick_mem::elf::SegmentPerms {
                    read: true,
                    write: false,
                    execute: true,
                },
                0xd65f_03c0_u32.to_le_bytes().to_vec(),
                16 * 1024,
            )],
        )
        .expect("build direct-entry image");
        let mut rollback = direct_test_mapping_rollback(address, 16 * 1024);
        map_region(
            &image.regions()[0],
            None,
            None,
            &NativeLayout::direct(),
            &mut rollback,
        )
        .expect("map DSR original code page");
        rollback.commit();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork direct-entry child");
        if pid == 0 {
            unsafe {
                libc::signal(libc::SIGBUS, libc::SIG_DFL);
                libc::signal(libc::SIGSEGV, libc::SIG_DFL);
            }
            let original: unsafe extern "C" fn() = unsafe {
                std::mem::transmute(usize::try_from(address).expect("direct-entry address"))
            };
            unsafe { original() };
            unsafe { libc::_exit(0) };
        }
        let status = waitpid_blocking(pid).expect("wait direct-entry child");
        assert!(libc::WIFSIGNALED(status));
        assert!(matches!(
            libc::WTERMSIG(status),
            libc::SIGSEGV | libc::SIGBUS
        ));
        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, 16 * 1024) },
            0
        );
    }

    #[test]
    fn native_fd_wait_deadline_survives_wait_variant_changes() {
        let now = Instant::now();
        let existing = now + Duration::from_secs(10);
        let mut deadline = Some(existing);
        let remaining =
            remaining_native_wait_timeout(Some(Duration::from_secs(30)), &mut deadline, now)
                .flatten()
                .expect("existing deadline remains live");
        assert_eq!(deadline, Some(existing));
        assert_eq!(remaining, Duration::from_secs(10));

        deadline = Some(now - Duration::from_millis(1));
        assert_eq!(
            remaining_native_wait_timeout(Some(Duration::from_secs(10)), &mut deadline, now),
            None
        );

        assert_eq!(
            remaining_native_wait_timeout(None, &mut deadline, now),
            Some(None)
        );
        assert_eq!(deadline, None);
    }

    fn synthetic_dynamic_elf(interpreter: Option<&[u8]>) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;
        const PT_INTERP: u32 = 3;

        let program_header_count = u16::from(interpreter.is_some());
        let interpreter_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        let mut file = vec![0_u8; interpreter_offset + interpreter.map_or(0, <[u8]>::len)];
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        file[18..20].copy_from_slice(&183_u16.to_le_bytes());
        file[20..24].copy_from_slice(&1_u32.to_le_bytes());
        file[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        file[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        file[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        file[56..58].copy_from_slice(&program_header_count.to_le_bytes());
        if let Some(interpreter) = interpreter {
            let ph = ELF_HEADER_SIZE;
            file[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
            file[ph + 8..ph + 16].copy_from_slice(&(interpreter_offset as u64).to_le_bytes());
            file[ph + 32..ph + 40].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            file[interpreter_offset..].copy_from_slice(interpreter);
        }
        file
    }

    #[test]
    fn native_signal_frame_restores_fpsimd_state() {
        let mut stack = vec![0_u8; 16 * 1024];
        let stack_start = stack.as_mut_ptr() as u64;
        let stack_end = stack_start + stack.len() as u64;
        let memory = NativeMappedMemory {
            address_mode: NativeAddressMode::Direct,
            owned_host_ranges: Arc::new(Vec::new()),
            regions: vec![NativeMappedRegion {
                start: stack_start,
                end: stack_end,
                host_protects: false,
                shared_futex: false,
                guest_writable: true,
                default_prot: crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE,
                shared_key_base: 0,
                shared_key_offset: 0,
            }],
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
            host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            dsr_generations: dsr::cache::PageGenerationTable::new(16 * 1024)
                .expect("generation table"),
            dsr_translator: None,
        };
        let mut interrupted = NativeUcontextSnapshot {
            sp: stack_end,
            pc: 0x4000,
            pstate: 0x6000_0000,
            fpsr: 0x0800_0000,
            fpcr: 0x0040_0000,
            ..NativeUcontextSnapshot::default()
        };
        for (index, value) in interrupted.v.iter_mut().enumerate() {
            *value = (0x1000_u128 + index as u128).to_le_bytes();
        }

        let mut trap = NativeSignalTrap::new(&memory, interrupted, None);
        trap.inject_signal(
            crate::linux_abi::LINUX_SIGUSR1,
            0x5000,
            0,
            None,
            Some(interrupted.pc),
            None,
            0,
            None,
            None,
            false,
        )
        .expect("inject native signal frame");
        trap.regs.v.fill(0xff_u128.to_le_bytes());
        trap.regs.fpsr = 0;
        trap.regs.fpcr = 0;

        trap.restore_from_sigframe()
            .expect("restore native signal frame");
        assert_eq!(trap.regs.v, interrupted.v);
        assert_eq!(trap.regs.fpsr, interrupted.fpsr);
        assert_eq!(trap.regs.fpcr, interrupted.fpcr);
    }

    /// A deliverable pending signal OUTSIDE the wait set must classify a
    /// signal-park wake as `Interrupted` (the syscall returns EINTR and the
    /// delivery tail runs the handler) — NOT `Ready`. `Ready` re-dispatches
    /// `rt_sigtimedwait`, which finds nothing in the wait set and re-parks;
    /// with the pending signal never consumed, the park spins
    /// Ready→re-dispatch→Ready until the guest's own timeout and returns
    /// EAGAIN, deferring the handler to that boundary. Probes
    /// `sigtimedwaitintr` (`eintr_on_caught_nonset=false`) and `shmnestedfork`
    /// (`test_proc_eintr=false`) hit exactly this once 784c05c9 enabled pid
    /// namespaces for native container runs: a cross-process kill now drains
    /// from the xsig ring into DISPATCHER pending state, which the old
    /// Ready-first order claimed before the EINTR classifier ran (a host-slot
    /// pending — the pre-pid-ns path — only ever reached the EINTR check).
    /// Mirrors the HVF WaitOnSignals arm, whose Interrupted wake consults
    /// `signal_wait_should_eintr` before any re-dispatch.
    #[test]
    fn native_signal_wait_classifies_nonset_caught_signal_as_interrupted() {
        let dispatcher = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(0x4e53); // "NS"
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        dispatcher.mark_signal_pending(tid, usr1);
        let wait_set = carrick_abi::SigSet::EMPTY;
        let block_mask = carrick_abi::SigBlockMask::for_signal_wait(
            wait_set,
            dispatcher.signal_mask_for(tid),
            dispatcher.wait_ignored_disposition_mask(),
        );
        assert_eq!(
            native_signal_wait_pending(&dispatcher, tid, wait_set, block_mask),
            Some(NativeSignalWaitResult::Interrupted),
        );
    }

    /// Companion invariant: a pending signal INSIDE the wait set (in
    /// dispatcher-owned state — e.g. drained from the xsig ring) still
    /// classifies as `Ready`, so the re-dispatch dequeues and returns it as
    /// the signum. Guards the reorder that fixed the test above.
    #[test]
    fn native_signal_wait_classifies_wait_set_dispatch_pending_as_ready() {
        let dispatcher = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(0x4e54);
        let usr1 = crate::linux_abi::LINUX_SIGUSR1;
        dispatcher.mark_signal_pending(tid, usr1);
        let wait_set = carrick_abi::SigSet::EMPTY.with(usr1);
        let block_mask = carrick_abi::SigBlockMask::for_signal_wait(
            wait_set,
            dispatcher.signal_mask_for(tid),
            dispatcher.wait_ignored_disposition_mask(),
        );
        assert_eq!(
            native_signal_wait_pending(&dispatcher, tid, wait_set, block_mask),
            Some(NativeSignalWaitResult::Ready),
        );
    }

    /// Linux delivers EVERY deliverable pending signal before returning to the
    /// interrupted context: when a second instance of a queued (RT) signal is
    /// still pending as a handler returns, `rt_sigreturn` must chain straight
    /// into the next handler rather than resume the interrupted PC and wait
    /// for the next syscall or kick boundary. Regression: probe `dnotify`
    /// (`handler_seq_second_after_syscall` / `forked_handler_seq_ok`) after
    /// vDSO enablement removed the clock_gettime traps that used to mask this.
    #[test]
    fn native_sigreturn_delivers_next_pending_signal_before_resume() {
        const INTERRUPTED_PC: u64 = 0x4000;
        const HANDLER_PC: u64 = 0x5000;
        let sig = 34; // SIGRTMIN: queued, so a second instance can be pending
        let mut stack = vec![0_u8; 16 * 1024];
        let stack_start = stack.as_mut_ptr() as u64;
        let stack_end = stack_start + stack.len() as u64;
        let memory = NativeMappedMemory {
            address_mode: NativeAddressMode::Direct,
            owned_host_ranges: Arc::new(Vec::new()),
            regions: vec![NativeMappedRegion {
                start: stack_start,
                end: stack_end,
                host_protects: false,
                shared_futex: false,
                guest_writable: true,
                default_prot: crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE,
                shared_key_base: 0,
                shared_key_offset: 0,
            }],
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
            host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            dsr_generations: dsr::cache::PageGenerationTable::new(16 * 1024)
                .expect("generation table"),
            dsr_translator: None,
        };
        let interrupted = NativeUcontextSnapshot {
            sp: stack_end,
            pc: INTERRUPTED_PC,
            pstate: 0x6000_0000,
            ..NativeUcontextSnapshot::default()
        };
        let dispatcher = SyscallDispatcher::new();
        let tid = crate::thread::ThreadId::synthetic_for_tests(0x5347); // "SG"

        // First instance delivered: handler frame is live, guest runs at the
        // handler. (saved_sigmask = 0: the interrupted context blocked nothing.)
        let mut trap = NativeSignalTrap::new(&memory, interrupted, None);
        trap.inject_signal(
            sig,
            HANDLER_PC,
            0,
            None,
            Some(INTERRUPTED_PC),
            None,
            0,
            None,
            None,
            false,
        )
        .expect("inject first native handler frame");
        assert_eq!(trap.pc(), HANDLER_PC);

        // A second instance was queued while the first handler ran.
        let action = carrick_abi::LinuxSigaction {
            sa_handler: HANDLER_PC,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: [0; carrick_abi::LINUX_SIGSET_WORDS],
        };
        dispatcher.record_pending_signal_action(tid, sig, action);
        dispatcher.mark_signal_pending(tid, sig);

        // The handler returns: rt_sigreturn must chain into the next handler
        // at the restored PC, not resume the interrupted context.
        let outcome = sigreturn_restore_and_deliver(&dispatcher, &mut trap, tid)
            .expect("sigreturn restore and deliver");
        if let Some(outcome) = &outcome {
            assert_eq!(outcome.term_signal, None);
            assert_eq!(outcome.stop_signal, None);
        }
        assert_eq!(
            trap.pc(),
            HANDLER_PC,
            "second pending instance must be delivered at rt_sigreturn, \
             before the interrupted context resumes"
        );

        // The chained frame still returns to the original interrupted context.
        trap.restore_from_sigframe()
            .expect("restore chained native handler frame");
        assert_eq!(trap.pc(), INTERRUPTED_PC);
        assert_eq!(dispatcher.take_deliverable_pending(tid), None);
        dispatcher.forget_thread_signal_state(tid);
    }

    #[test]
    fn native_clone_child_context_sets_linux_entry_registers() {
        let mut parent = NativeUcontextSnapshot::default();
        parent.x[0] = 0xaaaa;
        parent.x[19] = 0x1919;
        parent.sp = 0x7000;
        parent.pc = 0x4000;
        parent.signal = libc::SIGTRAP;
        parent.fault_address = 0xdead;

        let (child, child_tls) =
            native_clone_child_context(parent, 0x4010, 0x8000, Some(0x9000), 0x7777);

        assert_eq!(child.x[0], 0);
        assert_eq!(child.x[19], 0x1919);
        assert_eq!(child.sp, 0x8000);
        assert_eq!(child.pc, 0x4010);
        assert_eq!(child.signal, 0);
        assert_eq!(child.fault_address, 0);
        assert_eq!(child_tls, 0x9000);

        let (inherited_stack, inherited_tls) =
            native_clone_child_context(parent, 0x4020, 0, None, 0x7777);
        assert_eq!(inherited_stack.sp, 0x7000);
        assert_eq!(inherited_tls, 0x7777);
    }

    #[test]
    fn native_refuse_postfork_threads_requires_exact_one() {
        use std::ffi::OsStr;

        // Unset means "do not refuse" — post-fork guest thread creation is
        // permitted by default. This is the inverse of the historical
        // CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS opt-in, so the unset case is
        // the one that matters most: a typo in the variable name must leave
        // threads WORKING, not silently re-enable a refusal that broke real
        // Linux programs and cost ~30s per LTP suite.
        assert!(!native_refuse_postfork_threads_enabled(None));
        for value in ["", "0", "true", "01", "yes"] {
            assert!(
                !native_refuse_postfork_threads_enabled(Some(OsStr::new(value))),
                "unexpectedly accepted {value:?}"
            );
        }
        assert!(native_refuse_postfork_threads_enabled(Some(OsStr::new(
            "1"
        ))));
    }

    /// Pins the behaviour retired in the post-fork-threads change: a fork child
    /// may create guest threads. Creating a thread after `fork(2)` is ordinary
    /// POSIX — CPython's `ThreadJoinOnShutdown` tests 2/3 do exactly it — and
    /// carrick refused it for months on the SHIPPED default backend, which also
    /// cost ~30s per LTP suite because `tst_test` forks and then wants a thread.
    /// If this ever returns `Some` for the default (unset) configuration again,
    /// those failures come back silently.
    #[test]
    fn fork_child_may_create_guest_threads_by_default() {
        use std::ffi::OsStr;

        // The case that matters: a fork child, no override set.
        assert_eq!(postfork_thread_refusal(true, None), None);
        // A non-child is never refused either way.
        assert_eq!(postfork_thread_refusal(false, None), None);
        assert_eq!(
            postfork_thread_refusal(false, Some(OsStr::new("1"))),
            None,
            "the refusal is scoped to fork children"
        );
        // The opt-OUT escape hatch still works, for re-guarding a field wedge
        // without a rebuild.
        assert!(postfork_thread_refusal(true, Some(OsStr::new("1"))).is_some());
        // A typo must fail OPEN (threads keep working), not closed.
        for typo in ["", "0", "true", "yes", "01"] {
            assert_eq!(
                postfork_thread_refusal(true, Some(OsStr::new(typo))),
                None,
                "{typo:?} must not re-enable the refusal"
            );
        }
    }

    #[test]
    fn native_thread_runtime_waiter_tracks_guest_tid() {
        let runtime = NativeThreadRuntime::new_current();
        assert_eq!(runtime.waiter.tid(), runtime.tid());

        let child_tid = runtime.registry.register_child(0);
        let child = runtime.sibling(child_tid);
        assert_eq!(child.waiter.tid(), child_tid);
        runtime.registry.exit(child_tid);
    }

    /// A fork child inherits the vCPU-kick registry as a COW copy — including
    /// its `std::sync::Mutex` state. If any OTHER parent thread was inside
    /// `kick_all` (timer fire, child-exit publish, xsig nudge) at fork time,
    /// the child's copy of the handles mutex is locked forever, and the old
    /// `reset_after_fork_child` path deadlocked the child in
    /// `Drop → release_kick_target → unregister` before it could resume the
    /// guest: the load-coupled clone3signalflight/execpermitchurn campaign
    /// TIMEOUTs (fork storms × kick storms). The stale COW runtime must be
    /// discarded WITHOUT touching the inherited registry mutexes.
    #[test]
    fn fork_child_reset_skips_cow_locked_kick_registry() {
        use carrick_hal::VcpuRegistry as _;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Clone)]
        struct BlockingKick {
            entered: Arc<AtomicBool>,
            release: Arc<AtomicBool>,
        }
        impl carrick_hal::VcpuKick for BlockingKick {
            fn kick(&self) {
                self.entered.store(true, Ordering::SeqCst);
                // Hold the registry's handles mutex (we are called from
                // kick_all) until the test releases us — spanning the fork.
                while !self.release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }

        // ManuallyDrop: while the blocking kicker holds the handles mutex, a
        // panic-unwind of a failed assert below must not drop the runtime
        // (release_kick_target would wedge the unwinding test thread). On the
        // success path the holder is released + joined first, then the
        // runtime is dropped normally so no wedge-prone handle stays behind
        // in the installed process kicker for later tests to trip on.
        let mut runtime = std::mem::ManuallyDrop::new(NativeThreadRuntime::new_current());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        runtime.kicker.register(
            crate::thread::ThreadId::synthetic_for_tests(0x424b), // "BK"
            Box::new(BlockingKick {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        );
        let kicker = Arc::clone(&runtime.kicker);
        let holder = thread::Builder::new()
            .name("test-kick-holder".into())
            .spawn(move || {
                use carrick_hal::VcpuRegistry as _;
                kicker.kick_all();
            })
            .expect("spawn kick holder");
        while !entered.load(Ordering::SeqCst) {
            thread::yield_now();
        }

        // SAFETY: plain fork; the child only runs the reset-under-test and
        // reports through its exit status.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Pre-fix this deadlocked on the COW-locked handles mutex and the
            // child never exited; the parent's bounded reap below caught it.
            runtime.reset_after_fork_child();
            unsafe { libc::_exit(0) };
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut status: libc::c_int = -1;
        loop {
            let rc = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if rc == child {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fork child wedged in reset_after_fork_child (COW-locked registry)"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "fork child died abnormally: status={status:#x}"
        );
        // Success: release the holder so the handles mutex is free again,
        // then tear the runtime down normally — leaving no forever-blocking
        // kick handle in the installed process kicker for later tests.
        release.store(true, Ordering::SeqCst);
        holder.join().expect("join kick holder");
        runtime
            .kicker
            .unregister(crate::thread::ThreadId::synthetic_for_tests(0x424b));
        // SAFETY: dropped exactly once, after the mutex holder released.
        unsafe { std::mem::ManuallyDrop::drop(&mut runtime) };
    }

    /// Serializes the tests below that raise the PROCESS-GLOBAL stop-the-world
    /// flags (fork quiesce / exec replacement) so they cannot interleave with
    /// each other.
    static STW_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static NATIVE_PUMP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Clone)]
    struct TestCountingKick(Arc<std::sync::atomic::AtomicUsize>);

    impl carrick_hal::VcpuKick for TestCountingKick {
        fn kick(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[cfg(target_os = "macos")]
    fn wait_for_test_kick(kicks: &std::sync::atomic::AtomicUsize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while kicks.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "expected backend-owned signal kick"
            );
            std::thread::yield_now();
        }
    }

    #[cfg(target_os = "macos")]
    fn counting_wake_pump(
        tid: crate::thread::ThreadId,
    ) -> (
        crate::vcpu_kick::SignalPump,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use carrick_hal::VcpuRegistry as _;

        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let kicks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        registry.register(tid, Box::new(TestCountingKick(Arc::clone(&kicks))));
        let futex = Arc::new(crate::threaded_impl::hvf_futex(Arc::new(
            crate::thread::FutexTable::new(),
        ))) as Arc<dyn carrick_hal::PlatformFutex>;
        let pump = crate::vcpu_kick::spawn_signal_wake_pump(
            registry as Arc<dyn carrick_hal::VcpuRegistry>,
            futex,
        );
        assert!(
            pump.wait_until_ready(Duration::from_secs(2)),
            "signal pump did not become ready"
        );
        // The startup reconciliation may legitimately kick for unrelated
        // process-wide state left by another runtime test. Producer tests only
        // observe work published after the pump's ready boundary.
        kicks.store(0, std::sync::atomic::Ordering::SeqCst);
        (pump, kicks)
    }

    /// The native fork-quiesce park contract at the dispatch boundary:
    /// a sibling observing `is_quiescing()` UNREGISTERS from the kicker first
    /// (the forker's drain counts registered threads down to 1), parks at the
    /// barrier, and RE-REGISTERS its kick handle after release — so a later
    /// quiesce (or thread-directed kick) still reaches it.
    #[test]
    fn fork_quiesce_parks_native_sibling_and_reregisters_kicker() {
        use carrick_hal::VcpuRegistry as _;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let _stw = STW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let runtime = NativeThreadRuntime::new_current();
        let sib_tid = runtime.registry.register_child(0);
        let mut sibling = runtime.sibling(sib_tid);
        let kicker = Arc::clone(&runtime.kicker);
        let registered = Arc::new(AtomicBool::new(false));
        let reregistered_count = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let handle = {
            let registered = Arc::clone(&registered);
            let reregistered_count = Arc::clone(&reregistered_count);
            let release = Arc::clone(&release);
            thread::Builder::new()
                .name("test-quiesce-sibling".into())
                .spawn(move || {
                    // Production registration shape minus the trap-handler
                    // install (no guest here): bound state + registered handle.
                    let state = Arc::new(NativeKickState::new().expect("kick state"));
                    sibling.kick_state = Some(Arc::clone(&state));
                    sibling.kicker.register(
                        sib_tid,
                        Box::new(NativeKickHandle::for_current_thread(state)),
                    );
                    registered.store(true, Ordering::SeqCst);
                    while !crate::fork_quiesce::is_quiescing() {
                        thread::yield_now();
                    }
                    // The dispatch-boundary behavior under test.
                    sibling.park_for_fork_quiesce();
                    reregistered_count.store(sibling.kicker.count(), Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(1));
                    }
                    // Explicit teardown: the kick state was never thread-bound
                    // by prepare_kick_target, so skip release_kick_target's
                    // unbind; `sibling` (and its kick_state) drops with the
                    // closure.
                    sibling.kicker.unregister(sib_tid);
                })
                .expect("spawn quiesce sibling")
        };
        while !registered.load(Ordering::SeqCst) {
            thread::yield_now();
        }
        // This test's "forker" (the harness thread) is not kicker-registered
        // (that is prepare_kick_target's job in the run loop), so the counts
        // here are sibling-only: 1 registered, draining to 0.
        assert_eq!(kicker.count(), 1, "sibling registered");

        let barrier = crate::fork_quiesce::barrier();
        assert!(barrier.try_begin_fork(), "no other fork in flight");
        barrier.set_quiescing();
        // The forker's drain predicate: the sibling leaves the kicker BEFORE
        // parking, so the count draining means it is at the barrier.
        let deadline = Instant::now() + Duration::from_secs(10);
        while kicker.count() > 0 {
            assert!(
                Instant::now() < deadline,
                "sibling never unregistered for the quiesce (kicker={})",
                kicker.count()
            );
            thread::yield_now();
        }
        barrier.end_quiesce();
        barrier.end_fork();

        let deadline = Instant::now() + Duration::from_secs(10);
        while reregistered_count.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "sibling never released from the fork barrier"
            );
            thread::yield_now();
        }
        assert_eq!(
            reregistered_count.load(Ordering::SeqCst),
            1,
            "sibling must re-register its kick handle after the park"
        );
        release.store(true, Ordering::SeqCst);
        handle.join().expect("join quiesce sibling");
        runtime.registry.exit(sib_tid);
    }

    /// A NORMALLY-exited leader must PARK (never surface the no-process-exit
    /// diagnostic, which exits the process) when a sibling's execve owns or
    /// has committed the image replacement — in either the transient window
    /// (owner flag up) or after the teardown committed (durable flag set,
    /// stored BEFORE the owner flag drops, so there is no gap between them).
    #[test]
    fn exited_leader_parks_when_image_replaced_by_exec() {
        use std::sync::atomic::Ordering;

        let _stw = STW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let leader = crate::thread::ThreadId::synthetic_for_tests(0x717);
        let winner = crate::thread::ThreadId::synthetic_for_tests(0x718);
        NATIVE_IMAGE_REPLACED_BY_EXEC.store(false, Ordering::Release);

        // Neither flag: the diagnostic error path stays reachable.
        assert!(!native_exited_leader_must_park(leader));

        // Transient window: a sibling owns the replacement.
        crate::fork_quiesce::begin_exec_replacement(winner);
        assert!(native_exited_leader_must_park(leader));

        // Committed: durable set first, then the owner flag drops — the
        // leader must still park after end_exec_replacement.
        NATIVE_IMAGE_REPLACED_BY_EXEC.store(true, Ordering::Release);
        crate::fork_quiesce::end_exec_replacement();
        assert!(native_exited_leader_must_park(leader));

        // Fork-child reset restores the diagnostic.
        NATIVE_IMAGE_REPLACED_BY_EXEC.store(false, Ordering::Release);
        assert!(!native_exited_leader_must_park(leader));
    }

    /// The exec-teardown nudge seam: a sibling blocked in a native private
    /// futex wait must surface `Interrupted` (EINTR at the boundary, where
    /// the run-loop top retires it) once another thread begins an execve
    /// replacement — not sleep out its timeout. Pre-fix the wait predicate
    /// ignored the exec flag and this timed out (ETIMEDOUT after 10 s).
    #[test]
    fn exec_replacement_interrupts_native_futex_wait() {
        let _stw = STW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let runtime = NativeThreadRuntime::new_current();
        let sib_tid = runtime.registry.register_child(0);
        let sibling = runtime.sibling(sib_tid);

        crate::fork_quiesce::begin_exec_replacement(runtime.tid());
        let value = {
            let dispatcher = SyscallDispatcher::new();
            let wait = sibling.futex.prepare_wait(0x9000);
            wait_native_futex(
                &dispatcher,
                &sibling,
                wait,
                Some(Duration::from_secs(10)),
                0,
            )
        };
        crate::fork_quiesce::end_exec_replacement();
        assert_eq!(
            value,
            crate::linux_abi::LINUX_EINTR.guest_retval(),
            "an exec replacement must interrupt a sibling's futex wait"
        );
        runtime.registry.exit(sib_tid);
    }

    #[test]
    fn native_wait_state_tracks_blocked_and_running_thread() {
        let runtime = NativeThreadRuntime::new_current();
        let state_for = || {
            runtime
                .registry
                .thread_state_chars()
                .into_iter()
                .find_map(|(tid, state)| (tid == runtime.tid()).then_some(state))
        };
        assert_eq!(state_for(), Some('R'));

        let wait_state = NativeWaitState::new(&runtime);
        wait_state.enroll();
        assert_eq!(state_for(), Some('S'));
        drop(wait_state);

        assert_eq!(state_for(), Some('R'));
    }

    // Reads the C shim's kick-state generations: gated exactly like the
    // shim itself (M0.6 moves both behind the host-seam crate).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_kick_state_coalesces_until_acknowledged() {
        let state = NativeKickState::new().expect("create native kick state");

        assert!(state.request());
        assert!(!state.request());
        assert_eq!(state.requested_generation(), 2);
        assert_eq!(state.acknowledged_generation(), 0);

        state.acknowledge();
        assert_eq!(state.acknowledged_generation(), 2);
        assert!(state.request());
        assert_eq!(state.requested_generation(), 3);
    }

    // Reads the C shim's kick-state generations: gated exactly like the
    // shim itself (M0.6 moves both behind the host-seam crate).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_kick_handler_ignores_ordinary_broken_pipe() {
        std::thread::spawn(|| {
            let state = NativeKickState::new().expect("create native kick state");
            assert_eq!(unsafe { carrick_native_install_dsr_signal_handlers() }, 0);
            state.bind_current().expect("bind native kick state");

            let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut kick);
                libc::sigaddset(&mut kick, libc::SIGPIPE);
            }
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &kick, std::ptr::null_mut()) },
                0
            );

            let mut sockets = [-1; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr())
                },
                0
            );
            assert_eq!(unsafe { libc::shutdown(sockets[1], libc::SHUT_RD) }, 0);
            close_fd(sockets[1]);
            let byte = [1_u8];
            assert_eq!(
                unsafe { libc::write(sockets[0], byte.as_ptr().cast(), byte.len()) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPIPE)
            );
            assert_eq!(state.requested_generation(), 0);
            assert_eq!(state.acknowledged_generation(), 0);

            state.unbind_current();
            close_fd(sockets[0]);
        })
        .join()
        .expect("join native broken-pipe test thread");
    }

    // Exercises the C shim's transport-signal unblock helper: gated exactly
    // like the shim itself (M0.6 moves both behind the host-seam crate).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_bridge_unblocks_host_transport_signals_per_thread() {
        std::thread::spawn(|| {
            let mut transport: libc::sigset_t = unsafe { std::mem::zeroed() };
            let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut transport);
                libc::sigaddset(&mut transport, libc::SIGTRAP);
                libc::sigaddset(&mut transport, libc::SIGSEGV);
                libc::sigaddset(&mut transport, libc::SIGBUS);
                libc::sigaddset(&mut transport, libc::SIGILL);
            }
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &transport, &mut original) },
                0
            );

            assert_eq!(unsafe { carrick_native_unblock_transport_signals() }, 0);

            let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
                0
            );
            for signal in [libc::SIGTRAP, libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
                assert_eq!(unsafe { libc::sigismember(&current, signal) }, 0);
            }

            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut())
                },
                0
            );
        })
        .join()
        .expect("join native transport signal test thread");
    }

    // Exercises the C shim's guest/host ABI window switches: gated exactly
    // like the shim itself (M0.6 moves both behind the host-seam crate).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn dsr_gateway_keeps_kicks_deliverable_across_host_and_guest_windows() {
        std::thread::spawn(|| {
            let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
            let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut kick);
                libc::sigaddset(&mut kick, libc::SIGPIPE);
            }
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
                0
            );

            assert_eq!(
                unsafe { carrick_native_dsr_enter_guest_abi(std::ptr::null_mut()) },
                0
            );
            let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
                0
            );
            assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 0);

            unsafe { carrick_native_dsr_enter_host_abi() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
                0
            );
            assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 0);

            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut())
                },
                0
            );
        })
        .join()
        .expect("join DSR kick-mask test thread");
    }

    // Mach VM (`vm_deallocate`/`mach_task_self_`) probe of the pagezero
    // reallocation guard: Darwin-only by construction.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(deprecated)] // libc exposes mach_task_self_ as the stable self-task port.
    fn native_pagezero_min_offset_rejects_reallocation() {
        const GUEST_ADDRESS: usize = 0x20_0000;
        const HOST_PAGE_SIZE: usize = 16 * 1024;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let deallocate = unsafe {
                libc::vm_deallocate(
                    libc::mach_task_self_,
                    GUEST_ADDRESS as libc::vm_address_t,
                    HOST_PAGE_SIZE as libc::vm_size_t,
                )
            };
            if deallocate != 0 {
                unsafe { libc::_exit(1) };
            }
            let mapped = unsafe {
                libc::mmap(
                    GUEST_ADDRESS as *mut libc::c_void,
                    HOST_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            unsafe {
                libc::_exit(i32::from(mapped as usize == GUEST_ADDRESS) * 2);
            }
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_mmap_arena_does_not_overlap_fixed_windows() {
        let layout = native_memory_layout();
        let arena = (layout.mmap_base, layout.mmap_base + layout.mmap_size);
        let fixed = [
            (
                crate::memory::LINUX_INTERPRETER_BASE,
                crate::memory::LINUX_SHARED_FILE_BASE,
            ),
            (
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_BASE + crate::memory::LINUX_SHARED_FILE_SIZE,
            ),
            (
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE
                    + crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            ),
            (
                NATIVE_DARWIN_VVAR_BASE,
                NATIVE_DARWIN_VDSO_BASE + crate::vdso::LINUX_VDSO_SIZE,
            ),
        ];
        for window in fixed {
            assert!(
                arena.1 <= window.0 || window.1 <= arena.0,
                "native mmap arena overlaps fixed window 0x{:x}..0x{:x}",
                window.0,
                window.1
            );
        }
    }

    #[test]
    fn native_mmap_arena_is_reservable_on_darwin() {
        let layout = native_memory_layout();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let mut rollback = direct_test_mapping_rollback(layout.mmap_base, layout.mmap_size);
            let code = if map_anonymous_region(
                layout.mmap_base,
                layout.mmap_size,
                false,
                &NativeLayout::direct(),
                &mut rollback,
            )
            .is_ok()
            {
                rollback.commit();
                0
            } else {
                1
            };
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn later_fixed_mapping_rejects_unowned_biased_host_range() {
        let page_size = 16 * 1024;
        let bias = address::NativeHostBias::new(0x80_0000_0000, page_size).expect("valid bias");
        let owned_start = 0x80_0000_4000_usize;
        let memory = NativeMappedMemory {
            address_mode: NativeAddressMode::Biased { host_bias: bias },
            owned_host_ranges: Arc::new(vec![
                carrick_guest_mem::HostVa(owned_start)
                    ..carrick_guest_mem::HostVa(owned_start + page_size as usize),
            ]),
            regions: Vec::new(),
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
            host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
            host_page_size: page_size,
            linux_page_size: page_size,
            dsr_generations: dsr::cache::PageGenerationTable::new(page_size)
                .expect("generation table"),
            dsr_translator: None,
        };

        assert!(
            memory
                .fixed_mapping_target(
                    0x8000,
                    page_size as usize,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                )
                .is_err()
        );
    }

    #[test]
    fn native16k_write_exec_rejects_same_page_self_modification() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let rejected = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    let data_write_esr = (0x25_u64 << 26) | (1 << 6) | 0x0f;
                    Ok(memory
                        .resolve_native16k_write_exec_fault(
                            layout.mmap_base,
                            layout.mmap_base,
                            data_write_esr,
                        )
                        .is_err())
                })
                .unwrap_or(false);
            unsafe { libc::_exit(i32::from(!rejected)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_write_exec_does_not_consume_data_translation_fault() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let accepted = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .resolve_native16k_write_exec_fault(
                            layout.mmap_base,
                            NATIVE_DARWIN_PIE_BASE,
                            (0x25_u64 << 26) | (1 << 6) | 0x04,
                        )
                        .map_err(RuntimeError::from)
                })
                .unwrap_or(true);
            unsafe { libc::_exit(i32::from(accepted)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_write_exec_does_not_consume_instruction_translation_fault() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let accepted = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if !memory
                        .resolve_native16k_write_exec_fault(
                            layout.mmap_base,
                            NATIVE_DARWIN_PIE_BASE,
                            (0x25_u64 << 26) | (1 << 6) | 0x0f,
                        )
                        .map_err(RuntimeError::from)?
                    {
                        return Err(RuntimeError::Unsupported(
                            "permission write fault was not resolved".to_string(),
                        ));
                    }
                    memory
                        .resolve_native16k_write_exec_fault(
                            layout.mmap_base,
                            layout.mmap_base,
                            (0x21_u64 << 26) | 0x04,
                        )
                        .map_err(RuntimeError::from)
                })
                .unwrap_or(true);
            unsafe { libc::_exit(i32::from(accepted)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_dsr_write_exec_allows_later_clone_thread() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let accepted = NativeMappedMemory::map_with_translator(
                &image, layout, page_size, page_size, None, None,
            )
            .map_err(RuntimeError::from)
            .and_then(|mut memory| {
                let write_exec = crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE
                    | crate::linux_abi::LINUX_PROT_EXEC;
                memory
                    .protect_range(layout.mmap_base, page_size as usize, write_exec)
                    .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                Ok(memory.native16k_clone_thread_rejection().is_none()
                    && !memory.write_exec_blocks_multithreaded_lifecycle())
            })
            .unwrap_or(false);
            unsafe { libc::_exit(i32::from(!accepted)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_write_exec_rejects_later_vfork() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let rejected = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    Ok(memory
                        .native16k_vfork_rejection()
                        .is_some_and(|reason| reason.contains("vfork")))
                })
                .unwrap_or(false);
            unsafe { libc::_exit(i32::from(!rejected)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_protection_transaction_rolls_back_late_host_failure() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let restored = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    memory
                        .write_bytes_raw(layout.mmap_base, &SVC_0.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_raw(layout.mmap_base + page_size, &SVC_0.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let calls = Cell::new(0_usize);
                    let operations = RefCell::new(Vec::new());
                    let result = memory.protect_native16k_range_with(
                        layout.mmap_base,
                        (2 * page_size) as usize,
                        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        |host_page, page_len, host_prot| {
                            let call = calls.get() + 1;
                            calls.set(call);
                            operations.borrow_mut().push((host_page, host_prot));
                            // The two coalesced pages protect in two calls:
                            // the run-wide PROT_READ phase, then the final
                            // run-wide protection. Fail the LATE call.
                            if call == 2 {
                                return Err(MemoryError::HostMap(
                                    "injected final protection failure".to_string(),
                                ));
                            }
                            let ptr = host_page.raw() as *mut libc::c_void;
                            if unsafe { libc::mprotect(ptr, page_len, host_prot) } != 0 {
                                return Err(MemoryError::HostMap(
                                    std::io::Error::last_os_error().to_string(),
                                ));
                            }
                            Ok(())
                        },
                    );

                    let writable = unsafe {
                        libc::mprotect(
                            layout.mmap_base as *mut libc::c_void,
                            (2 * page_size) as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                    } == 0;
                    let words_restored = writable
                        && memory.read_u32(layout.mmap_base).ok() == Some(SVC_0)
                        && memory.read_u32(layout.mmap_base + page_size).ok() == Some(SVC_0);
                    // Coalesced: apply is [run PROT_READ, run final(fails)],
                    // rollback restores each page individually -> 4 calls.
                    let rollback_calls = operations.borrow();
                    Ok(result.is_err()
                        && rollback_calls.len() == 4
                        && memory.native_page_protections.is_empty()
                        && memory.native_write_exec_writable_pages.is_empty()
                        && words_restored)
                })
                .unwrap_or(false);
            unsafe { libc::_exit(i32::from(!restored)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_dsr_exec_protection_preserves_linux_syscall_words() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let preserved = NativeMappedMemory::map_with_translator(
                &image, layout, page_size, page_size, None, None,
            )
            .map_err(RuntimeError::from)
            .and_then(|mut memory| {
                memory
                    .protect_range(layout.mmap_base, page_size as usize, 0)
                    .map_err(|err| RuntimeError::Unsupported(format!("test reserve: {err}")))?;
                memory
                    .write_bytes_unchecked(layout.mmap_base, &SVC_0.to_le_bytes())
                    .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                memory
                    .protect_range(
                        layout.mmap_base,
                        page_size as usize,
                        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                    )
                    .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                memory
                    .read_u32(layout.mmap_base)
                    .map_err(RuntimeError::from)
            })
            .is_ok_and(|word| word == SVC_0);
            unsafe { libc::_exit(i32::from(!preserved)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_protect_coalesces_contiguous_same_prot_pages_into_one_call() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (4 * page) as usize, 16 * 1024);
            let calls = RefCell::new(Vec::new());
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    (4 * page) as usize,
                    crate::linux_abi::LINUX_PROT_READ,
                    |host_page, len, host_prot| {
                        calls.borrow_mut().push((host_page.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect contiguous run");
            let host_base = memory.host_address(guest).expect("host base").raw();
            assert_eq!(
                calls.into_inner(),
                vec![(host_base, (4 * page) as usize, libc::PROT_READ)],
                "a contiguous same-protection run must be ONE host mprotect call"
            );
            // Per-page bookkeeping must be unchanged by syscall coalescing.
            for index in 0..4_u64 {
                assert_eq!(
                    memory
                        .native_page_protections
                        .get(&(guest.raw() + index * page))
                        .copied(),
                    Some(crate::linux_abi::LINUX_PROT_READ),
                    "page {index} must keep its own protection entry"
                );
            }
            assert_eq!(memory.native_page_protections.len(), 4);
        });
    }

    #[test]
    fn native16k_exec_protect_coalesces_both_phases_over_the_run() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (3 * page) as usize, 16 * 1024);
            let prot = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC;
            let calls = RefCell::new(Vec::new());
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    (3 * page) as usize,
                    prot,
                    |host_page, len, host_prot| {
                        calls.borrow_mut().push((host_page.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect exec run");
            let host_base = memory.host_address(guest).expect("host base").raw();
            // Exec protection keeps its two-phase shape (icache-visible
            // PROT_READ window, then the final downgraded protection), but
            // each phase covers the whole contiguous run in one call.
            assert_eq!(
                calls.into_inner(),
                vec![
                    (host_base, (3 * page) as usize, libc::PROT_READ),
                    (host_base, (3 * page) as usize, native16k_host_prot(prot)),
                ],
                "exec runs must issue exactly one call per phase over the run"
            );
            for index in 0..3_u64 {
                assert_eq!(
                    memory
                        .native_page_protections
                        .get(&(guest.raw() + index * page))
                        .copied(),
                    Some(prot),
                );
            }
        });
    }

    #[test]
    fn native16k_protect_splits_coalesced_runs_at_region_gaps() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (5 * page) as usize, 16 * 1024);
            // Two host-protected regions with a one-page hole between them:
            // pages 0-1 and pages 3-4.
            memory.regions = vec![
                NativeMappedRegion {
                    start: guest.raw(),
                    end: guest.raw() + 2 * page,
                    host_protects: true,
                    shared_futex: false,
                    guest_writable: true,
                    default_prot: crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE,
                    shared_key_base: 0,
                    shared_key_offset: 0,
                },
                NativeMappedRegion {
                    start: guest.raw() + 3 * page,
                    end: guest.raw() + 5 * page,
                    host_protects: true,
                    shared_futex: false,
                    guest_writable: true,
                    default_prot: crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE,
                    shared_key_base: 0,
                    shared_key_offset: 0,
                },
            ];
            let calls = RefCell::new(Vec::new());
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    (5 * page) as usize,
                    crate::linux_abi::LINUX_PROT_READ,
                    |host_page, len, host_prot| {
                        calls.borrow_mut().push((host_page.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect across gap");
            let host_base = memory.host_address(guest).expect("host base").raw();
            let host_page = 16 * 1024_usize;
            assert_eq!(
                calls.into_inner(),
                vec![
                    (host_base, 2 * host_page, libc::PROT_READ),
                    (host_base + 3 * host_page, 2 * host_page, libc::PROT_READ),
                ],
                "runs must split exactly at the non-contiguous page boundary"
            );
            // Bookkeeping only for pages inside host-protected regions.
            assert_eq!(memory.native_page_protections.len(), 4);
            assert!(
                !memory
                    .native_page_protections
                    .contains_key(&(guest.raw() + 2 * page)),
                "the hole page must not gain a protection entry"
            );
        });
    }

    #[test]
    fn native16k_protect_to_region_default_stores_no_entry() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (2 * page) as usize, 16 * 1024);
            // `biased_test_memory_with_geometry` sets the region's
            // `default_prot` to READ|WRITE, so protecting to that exact
            // value must NOT add an entry: a missing page already reads
            // back as the region default via `default_linux_prot_at`.
            let default_prot =
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    (2 * page) as usize,
                    default_prot,
                    |_host_va, _len, _host_prot| Ok(()),
                )
                .expect("protect to region default");
            assert!(
                memory.native_page_protections.is_empty(),
                "protecting to the region default must leave the sparse map empty, got {:?}",
                memory.native_page_protections
            );
            assert!(
                memory.native_range_allows(guest.raw(), (2 * page) as usize, false),
                "a missing (sparse) page must still read back as default-readable"
            );
            assert!(
                memory.native_range_allows(guest.raw(), (2 * page) as usize, true),
                "a missing (sparse) page must still read back as default-writable"
            );
            assert_eq!(
                memory.native_host_prot_for_page(guest.raw()),
                native16k_host_prot(default_prot),
                "a missing (sparse) page must resolve to the region default host prot"
            );
        });
    }

    #[test]
    fn native16k_protect_to_non_default_prot_stores_entry() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            let read_only = crate::linux_abi::LINUX_PROT_READ;
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    page as usize,
                    read_only,
                    |_host_va, _len, _host_prot| Ok(()),
                )
                .expect("protect to non-default prot");
            assert_eq!(
                memory.native_page_protections.get(&guest.raw()).copied(),
                Some(read_only),
                "a non-default protection must be stored explicitly"
            );
            assert!(!memory.native_range_allows(guest.raw(), page as usize, true));
            assert_eq!(
                memory.native_host_prot_for_page(guest.raw()),
                native16k_host_prot(read_only),
            );
        });
    }

    #[test]
    fn native16k_protect_back_to_default_removes_stored_entry() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            let default_prot =
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
            let read_only = crate::linux_abi::LINUX_PROT_READ;
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    page as usize,
                    read_only,
                    |_host_va, _len, _host_prot| Ok(()),
                )
                .expect("protect to non-default prot");
            assert!(
                memory.native_page_protections.contains_key(&guest.raw()),
                "sanity: non-default protection must be stored before flipping back"
            );
            memory
                .protect_native16k_range_with(
                    guest.raw(),
                    page as usize,
                    default_prot,
                    |_host_va, _len, _host_prot| Ok(()),
                )
                .expect("protect back to default prot");
            assert!(
                !memory.native_page_protections.contains_key(&guest.raw()),
                "flipping back to the region default must remove the stored entry"
            );
            assert!(memory.native_range_allows(guest.raw(), page as usize, true));
            assert_eq!(
                memory.native_host_prot_for_page(guest.raw()),
                native16k_host_prot(default_prot),
            );
        });
    }

    #[test]
    fn linux4k_protect_coalesces_uniform_host_pages_into_one_call() {
        fork_test(|| {
            let host_page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (4 * host_page) as usize, 4 * 1024);
            let prot = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
            let calls = RefCell::new(Vec::new());
            memory
                .protect_linux4k_range_with(
                    guest.raw(),
                    (4 * host_page) as usize,
                    prot,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect uniform linux4k run");
            let host_base = memory.host_address(guest).expect("host base").raw();
            assert_eq!(
                calls.into_inner(),
                vec![(
                    host_base,
                    (4 * host_page) as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )],
                "uniform linux4k host pages must merge into one mprotect call"
            );
            // Per-host-page subpage bookkeeping stays per page.
            for index in 0..4_u64 {
                assert_eq!(
                    memory
                        .linux4k_page_protections
                        .get(&(guest.raw() + index * host_page))
                        .copied(),
                    Some([prot; 4]),
                    "host page {index} must keep its own subpage protections"
                );
            }
        });
    }

    #[test]
    fn linux4k_protect_splits_runs_where_final_host_prot_differs() {
        fork_test(|| {
            let host_page = 16 * 1024_u64;
            let linux_page = 4 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (3 * host_page) as usize, linux_page);
            // Cover host pages 0-1 fully and only the first 4k subpage of
            // host page 2: pages 0-1 become uniform READ (host PROT_READ),
            // page 2 becomes mixed READ/RW (host PROT_NONE guard).
            let calls = RefCell::new(Vec::new());
            memory
                .protect_linux4k_range_with(
                    guest.raw(),
                    (2 * host_page + linux_page) as usize,
                    crate::linux_abi::LINUX_PROT_READ,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect split linux4k run");
            let host_base = memory.host_address(guest).expect("host base").raw();
            assert_eq!(
                calls.into_inner(),
                vec![
                    (host_base, 2 * 16 * 1024_usize, libc::PROT_READ),
                    (
                        host_base + 2 * 16 * 1024_usize,
                        16 * 1024_usize,
                        libc::PROT_NONE
                    ),
                ],
                "the run must split exactly where the resolved host prot changes"
            );
            let rw = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
            let read = crate::linux_abi::LINUX_PROT_READ;
            assert_eq!(
                memory
                    .linux4k_page_protections
                    .get(&(guest.raw() + 2 * host_page))
                    .copied(),
                Some([read, rw, rw, rw]),
                "the mixed page must keep exact per-subpage protections"
            );
        });
    }

    #[test]
    fn linux4k_protect_coalesces_across_exec_icache_subset_pages() {
        fork_test(|| {
            let host_page = 16 * 1024_u64;
            let linux_page = 4 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (2 * host_page) as usize, linux_page);
            let read_exec = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC;
            // Seed host page 0 with an executable first subpage so the
            // protect below leaves it exec-mixed (icache clear + PROT_READ
            // guard downgrade) while host page 1 resolves to plain uniform
            // PROT_READ. Both end at PROT_READ, so the syscall coalesces
            // even though only page 0 needs the icache clear.
            memory
                .linux4k_page_protections
                .insert(guest.raw(), [read_exec; 4]);
            let calls = RefCell::new(Vec::new());
            memory
                .protect_linux4k_range_with(
                    guest.raw() + linux_page,
                    (2 * host_page - linux_page) as usize,
                    crate::linux_abi::LINUX_PROT_READ,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("protect exec-subset linux4k run");
            let host_base = memory.host_address(guest).expect("host base").raw();
            assert_eq!(
                calls.into_inner(),
                vec![(host_base, 2 * 16 * 1024_usize, libc::PROT_READ)],
                "same final host prot must coalesce even when only some pages need icache"
            );
            let read = crate::linux_abi::LINUX_PROT_READ;
            assert_eq!(
                memory.linux4k_page_protections.get(&guest.raw()).copied(),
                Some([read_exec, read, read, read]),
            );
            assert_eq!(
                memory
                    .linux4k_page_protections
                    .get(&(guest.raw() + host_page))
                    .copied(),
                Some([read; 4]),
            );
        });
    }

    #[test]
    fn temporary_host_access_prepare_coalesces_contiguous_pages() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (3 * page) as usize, 16 * 1024);
            // Bookkeep all three pages as guest PROT_NONE so a supervisor
            // read must lift every page.
            for index in 0..3_u64 {
                memory
                    .native_page_protections
                    .insert(guest.raw() + index * page, 0);
            }
            let calls = RefCell::new(Vec::new());
            let changed = memory
                .prepare_temporary_host_access_with(
                    guest.raw(),
                    (3 * page) as usize,
                    false,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("prepare temporary access");
            let host_base = memory.host_address(guest).expect("host base").raw();
            assert_eq!(
                calls.into_inner(),
                vec![(host_base, 3 * 16 * 1024_usize, libc::PROT_READ)],
                "contiguous pages needing the same lift must be ONE mprotect call"
            );
            // The restore bookkeeping stays per page.
            assert_eq!(
                changed,
                vec![
                    (guest.raw(), libc::PROT_NONE),
                    (guest.raw() + page, libc::PROT_NONE),
                    (guest.raw() + 2 * page, libc::PROT_NONE),
                ],
            );
        });
    }

    #[test]
    fn temporary_host_access_prepare_splits_runs_at_satisfied_pages() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (3 * page) as usize, 16 * 1024);
            memory.native_page_protections.insert(guest.raw(), 0);
            // Middle page is already readable: prepare must skip it and
            // split the mprotect runs around it.
            memory
                .native_page_protections
                .insert(guest.raw() + page, crate::linux_abi::LINUX_PROT_READ);
            memory
                .native_page_protections
                .insert(guest.raw() + 2 * page, 0);
            let calls = RefCell::new(Vec::new());
            let changed = memory
                .prepare_temporary_host_access_with(
                    guest.raw(),
                    (3 * page) as usize,
                    false,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("prepare split access");
            let host_base = memory.host_address(guest).expect("host base").raw();
            let host_page = 16 * 1024_usize;
            assert_eq!(
                calls.into_inner(),
                vec![
                    (host_base, host_page, libc::PROT_READ),
                    (host_base + 2 * host_page, host_page, libc::PROT_READ),
                ],
                "an already-satisfied page must split the coalesced run"
            );
            assert_eq!(
                changed,
                vec![
                    (guest.raw(), libc::PROT_NONE),
                    (guest.raw() + 2 * page, libc::PROT_NONE),
                ],
            );
        });
    }

    #[test]
    fn temporary_host_access_restore_coalesces_adjacent_same_prot_pages() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let memory = biased_test_memory_with_geometry(guest, (3 * page) as usize, 16 * 1024);
            // Page 0 restores to PROT_READ; pages 1-2 restore to PROT_NONE.
            let changed = vec![
                (guest.raw(), libc::PROT_READ),
                (guest.raw() + page, libc::PROT_NONE),
                (guest.raw() + 2 * page, libc::PROT_NONE),
            ];
            let calls = RefCell::new(Vec::new());
            memory
                .restore_temporary_host_access_with(
                    &changed,
                    guest.raw(),
                    (3 * page) as usize,
                    |host_va, len, host_prot| {
                        calls.borrow_mut().push((host_va.raw(), len, host_prot));
                        Ok(())
                    },
                )
                .expect("restore temporary access");
            let host_base = memory.host_address(guest).expect("host base").raw();
            let host_page = 16 * 1024_usize;
            assert_eq!(
                calls.into_inner(),
                vec![
                    (host_base + host_page, 2 * host_page, libc::PROT_NONE),
                    (host_base, host_page, libc::PROT_READ),
                ],
                "adjacent pages with the same recorded prot must restore in one call; \
                 differing prots must stay exact per page"
            );
        });
    }

    #[test]
    fn temporary_host_access_refcounts_overlapping_lifts() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            // Bookkeep the single page as guest PROT_NONE so EVERY accessor must
            // lift it before it can touch the backing.
            memory.native_page_protections.insert(guest.raw(), 0);
            let host_base = memory.host_address(guest).expect("host base").raw();
            let host_page = 16 * 1024_usize;
            let rw = libc::PROT_READ | libc::PROT_WRITE;

            let calls = RefCell::new(Vec::new());
            let mut record = |host_va: carrick_guest_mem::HostVa, len: usize, prot: libc::c_int| {
                calls.borrow_mut().push((host_va.raw(), len, prot));
                Ok(())
            };

            // Two overlapping accessors lift the SAME protected page while both
            // hold the shared (read-guard) memory borrow. Before Task 6 the
            // process-wide memory mutex made this impossible; now the refcounted
            // lift table must keep the page accessible for BOTH windows and flip
            // it back exactly once, only when the LAST accessor releases.
            let changed_a = memory
                .prepare_temporary_host_access_with(guest.raw(), page as usize, true, &mut record)
                .expect("prepare A");
            let changed_b = memory
                .prepare_temporary_host_access_with(guest.raw(), page as usize, true, &mut record)
                .expect("prepare B");
            // Releasing accessor A must NOT restore -- accessor B is still
            // mid-window and would be stranded with a PROT_NONE page.
            memory
                .restore_temporary_host_access_with(
                    &changed_a,
                    guest.raw(),
                    page as usize,
                    &mut record,
                )
                .expect("restore A");
            // Releasing the last accessor restores the page exactly once.
            memory
                .restore_temporary_host_access_with(
                    &changed_b,
                    guest.raw(),
                    page as usize,
                    &mut record,
                )
                .expect("restore B");

            assert_eq!(
                *calls.borrow(),
                vec![
                    (host_base, host_page, rw),
                    (host_base, host_page, libc::PROT_NONE),
                ],
                "overlapping lifts must mprotect the shared page up exactly once and \
                 back exactly once, only at the final release",
            );
            // No refcount leaked: the final release removed the table entry.
            assert!(
                memory.host_access_lifts.lock().is_empty(),
                "the last release must remove the lift entry",
            );
        });
    }

    #[test]
    fn prepare_temporary_host_access_rolls_back_committed_lifts_on_later_overlap_failure() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory =
                biased_test_memory_with_geometry(guest, (2 * page) as usize, 16 * 1024);
            // `host_protected_overlaps` yields ONE overlap per matching region,
            // so split the single region `biased_test_memory_with_geometry`
            // built into TWO adjacent protected regions. A read/write spanning
            // both pages then drives `prepare` through TWO overlap iterations
            // -- the multi-overlap scenario the leak needs (overlap #1 fully
            // commits, overlap #2 fails).
            let template = memory.regions.remove(0);
            memory.regions.push(NativeMappedRegion {
                start: guest.raw(),
                end: guest.raw() + page,
                host_protects: true,
                shared_futex: template.shared_futex,
                guest_writable: template.guest_writable,
                default_prot: template.default_prot,
                shared_key_base: template.shared_key_base,
                shared_key_offset: template.shared_key_offset,
            });
            memory.regions.push(NativeMappedRegion {
                start: guest.raw() + page,
                end: guest.raw() + 2 * page,
                host_protects: true,
                shared_futex: template.shared_futex,
                guest_writable: template.guest_writable,
                default_prot: template.default_prot,
                shared_key_base: template.shared_key_base,
                shared_key_offset: template.shared_key_offset,
            });
            // Bookkeep BOTH pages as guest PROT_NONE so both overlaps need a
            // lift.
            memory.native_page_protections.insert(guest.raw(), 0);
            memory.native_page_protections.insert(guest.raw() + page, 0);

            let host_base = memory.host_address(guest).expect("host base").raw();
            let host_page = 16 * 1024_usize;
            let rw = libc::PROT_READ | libc::PROT_WRITE;
            let second_page_host = host_base + host_page;

            let calls = RefCell::new(Vec::new());
            let mut set_host_prot =
                |host_va: carrick_guest_mem::HostVa, len: usize, prot: libc::c_int| {
                    calls.borrow_mut().push((host_va.raw(), len, prot));
                    // Fail exactly the second overlap's lift-up mprotect --
                    // the first overlap's page must already be committed
                    // (refcounted + mprotected up) by the time this runs.
                    if host_va.raw() == second_page_host {
                        return Err(MemoryError::HostMap("synthetic lift failure".to_string()));
                    }
                    Ok(())
                };

            let error = memory
                .prepare_temporary_host_access_with(
                    guest.raw(),
                    (2 * page) as usize,
                    true,
                    &mut set_host_prot,
                )
                .expect_err("second overlap's lift must fail");
            assert_eq!(
                error,
                MemoryError::HostMap("synthetic lift failure".to_string()),
            );

            assert_eq!(
                *calls.borrow(),
                vec![
                    (host_base, host_page, rw),
                    (second_page_host, host_page, rw),
                    (host_base, host_page, libc::PROT_NONE),
                ],
                "a later overlap's failure must roll back an earlier overlap's \
                 already-committed lift back to its original protection",
            );
            // `prepare` is all-or-nothing: no refcount may survive a failed
            // call, even though the first overlap fully committed before the
            // second overlap failed.
            assert!(
                memory.host_access_lifts.lock().is_empty(),
                "a failed prepare must leave the lift table exactly as it found it",
            );
        });
    }

    #[test]
    fn exclusive_load_for_restores_host_lift_on_unsupported_width_error() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            // Bookkeep the page as guest PROT_NONE so ANY host access to it must
            // first lift it. `exclusive_load_for` now validates the access width
            // UP FRONT (rejecting anything outside {1,2,4,8} with `OutOfBounds`)
            // BEFORE it calls `prepare_temporary_host_access`, so an unsupported
            // width never commits a `HostLift` refcount in the first place -- the
            // lift table must stay empty on this error path.
            memory.native_page_protections.insert(guest.raw(), 0);
            let mut reservation = None;
            let error = memory
                .exclusive_load_for(guest.raw(), 16, true, &mut reservation)
                .expect_err("width 16 is not a supported exclusive-load width");
            assert_eq!(
                error,
                MemoryError::OutOfBounds {
                    address: guest.raw(),
                    length: 16,
                }
            );
            assert!(
                memory.host_access_lifts.lock().is_empty(),
                "an unsupported width rejected before prepare must never commit a host-lift refcount",
            );
        });
    }

    #[test]
    fn exclusive_store_for_restores_host_lift_on_unsupported_width_error() {
        fork_test(|| {
            let page = 16 * 1024_u64;
            let guest = carrick_guest_mem::GuestVa(0x40_0000);
            let mut memory = biased_test_memory_with_geometry(guest, page as usize, 16 * 1024);
            // Same setup as `exclusive_load_for_restores_host_lift_on_unsupported_width_error`:
            // `exclusive_store_for` also validates the access width UP FRONT
            // (rejecting anything outside {1,2,4,8} with `OutOfBounds`) BEFORE it
            // calls `prepare_temporary_host_access`, so the unsupported width can
            // never commit a `HostLift` refcount. The reservation is hand-built
            // (rather than obtained via `exclusive_load_for`) so its
            // `location.width` matches the unsupported width this call passes.
            memory.native_page_protections.insert(guest.raw(), 0);
            let mut reservation = Some(NativeExclusiveReservation {
                location: NativeExclusiveLocation {
                    address: guest.raw(),
                    width: 16,
                },
                observed: 0,
                sequence: NativeExclusiveSequence::INITIAL,
            });
            let error = memory
                .exclusive_store_for(guest.raw(), 16, 0, true, &mut reservation)
                .expect_err("width 16 is not a supported exclusive-store width");
            assert_eq!(
                error,
                MemoryError::OutOfBounds {
                    address: guest.raw(),
                    length: 16,
                }
            );
            assert!(
                memory.host_access_lifts.lock().is_empty(),
                "an unsupported width rejected before prepare must never commit a host-lift refcount",
            );
        });
    }

    #[test]
    fn native_region_copy_window_uses_only_initialized_stack_suffix() {
        let stack_start = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
        let image = AddressSpace::from_segments(
            0,
            [(
                stack_start,
                carrick_mem::elf::SegmentPerms {
                    read: true,
                    write: true,
                    execute: false,
                },
                Vec::new(),
                crate::memory::LINUX_STACK_SIZE,
            )],
        )
        .expect("build canonical stack region");
        let region = &image.regions()[0];
        let initialized = crate::memory::LINUX_STACK_TOP - 4096;
        let stack_len = usize::try_from(crate::memory::LINUX_STACK_SIZE).expect("stack fits host");

        assert_eq!(
            native_region_copy_window(region, Some(initialized)),
            stack_len - 4096..stack_len
        );
        assert_eq!(
            native_region_copy_window(region, None),
            0..region.bytes().len()
        );

        let non_stack = AddressSpace::from_segments(
            0,
            [(
                0x10_0000_0000,
                carrick_mem::elf::SegmentPerms {
                    read: true,
                    write: false,
                    execute: false,
                },
                vec![1, 2, 3, 4],
                16 * 1024,
            )],
        )
        .expect("build non-stack region");
        assert_eq!(
            native_region_copy_window(&non_stack.regions()[0], Some(initialized)),
            0..non_stack.regions()[0].bytes().len()
        );
    }

    #[test]
    fn native_stack_suffix_mapping_preserves_sp_and_zero_prefix() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let image = AddressSpace::from_regions(0, Vec::new())
                .and_then(|image| {
                    image.with_linux_initial_stack(
                        [b"stack-window".as_slice()],
                        std::iter::empty::<&[u8]>(),
                    )
                })
                .expect("build initial stack");
            let sp = image.initial_stack_pointer().expect("stack pointer");
            let mapped = NativeMappedMemory::map_with_translator(
                &image,
                native_memory_layout(),
                16 * 1024,
                16 * 1024,
                None,
                None,
            )
            .is_ok();
            if !mapped {
                unsafe { libc::_exit(2) };
            }
            let argc = unsafe { (sp as *const u64).read() };
            let below = unsafe { ((sp - 8) as *const u64).read() };
            unsafe { libc::_exit(i32::from(!(argc == 1 && below == 0))) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_blocks_direct_access_but_allows_backing_copy() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let guarded = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let address = layout.mmap_base + linux_page_size;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &[0x5a])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let direct = unsafe { libc::fork() };
                    if direct == 0 {
                        unsafe {
                            libc::signal(libc::SIGBUS, libc::SIG_DFL);
                            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                            let ptr = usize::try_from(address).unwrap_or(0) as *const u8;
                            std::ptr::read_volatile(ptr);
                            libc::_exit(0);
                        }
                    }
                    if direct < 0 {
                        return Err(RuntimeError::Unsupported(
                            std::io::Error::last_os_error().to_string(),
                        ));
                    }
                    let mut status = 0;
                    if unsafe { libc::waitpid(direct, &mut status, 0) } != direct
                        || !libc::WIFSIGNALED(status)
                        || !matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "direct guarded read unexpectedly completed with status 0x{status:x}"
                        )));
                    }
                    let bytes = memory
                        .read_bytes_raw(address, 1)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    (bytes == [0x5a]).then_some(()).ok_or_else(|| {
                        RuntimeError::Unsupported(
                            "guarded backing copy returned wrong byte".to_string(),
                        )
                    })
                });
            unsafe { libc::_exit(i32::from(guarded.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_emulates_scalar_load() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let emulated = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
                    let mut reservation: Option<NativeExclusiveReservation> = None;
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0xf940_0020)?;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &0x1122_3344_5566_7788_u64.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    let mut snapshot = NativeUcontextSnapshot {
                        pc,
                        signal: libc::SIGBUS,
                        fault_address: address,
                        ..NativeUcontextSnapshot::default()
                    };
                    snapshot.x[1] = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    if snapshot.x[0] != 0x1122_3344_5566_7788 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated load produced x0=0x{:x} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x4c40_7020)?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address;
                    snapshot.v[0] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    let mut expected = [0_u8; 16];
                    expected[..8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
                    if snapshot.v[0] != expected || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated vector load produced v0={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.pc
                        )));
                    }
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x3dc0_0420)?;
                    memory
                        .write_bytes_unchecked(address + 16, &[0xa5; 16])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address + 16;
                    snapshot.v[0] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    if snapshot.v[0] != [0xa5; 16] || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated q load produced v0={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.pc
                        )));
                    }
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0xad40_0420)?;
                    memory
                        .write_bytes_unchecked(address + 16, &[0xa5; 16])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address;
                    snapshot.v[0] = [0; 16];
                    snapshot.v[1] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    if snapshot.v[0] != expected
                        || snapshot.v[1] != [0xa5; 16]
                        || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated pair load produced v0={:02x?} v1={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.v[1], snapshot.pc
                        )));
                    }
                    Ok(())
                });
            unsafe { libc::_exit(i32::from(emulated.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_emulates_exclusive_compare_exchange() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let emulated = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
                    let mut reservation: Option<NativeExclusiveReservation> = None;
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x885f_fc40)?;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &7_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let mut snapshot = NativeUcontextSnapshot {
                        pc,
                        signal: libc::SIGBUS,
                        fault_address: address,
                        ..NativeUcontextSnapshot::default()
                    };
                    snapshot.x[2] = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    if snapshot.x[0] != 7 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated ldaxr produced x0={} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }

                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x8803_fc44)?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 9;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    let stored = memory
                        .read_bytes_raw(address, std::mem::size_of::<u32>())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if snapshot.x[3] != 0 || stored != 9_u32.to_le_bytes() || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated stlxr produced status={} bytes={stored:02x?} pc=0x{:x}",
                            snapshot.x[3], snapshot.pc
                        )));
                    }

                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x885f_fc40)?;
                    snapshot.pc = pc;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    memory
                        .write_bytes_unchecked(address, &11_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x8803_fc44)?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 13;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    let stored = memory
                        .read_bytes_raw(address, std::mem::size_of::<u32>())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if snapshot.x[3] != 1 || stored != 11_u32.to_le_bytes() || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "invalidated stlxr produced status={} bytes={stored:02x?} pc=0x{:x}",
                            snapshot.x[3], snapshot.pc
                        )));
                    }
                    Ok(())
                });
            if let Err(error) = &emulated {
                child_write_stderr(format!("exclusive emulation test: {error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(emulated.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_emulates_atomic_fetch_add() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let emulated = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
                    let mut reservation: Option<NativeExclusiveReservation> = None;
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0xf820_0020)?;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &7_u64.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let mut snapshot = NativeUcontextSnapshot {
                        pc,
                        signal: libc::SIGBUS,
                        fault_address: address,
                        ..NativeUcontextSnapshot::default()
                    };
                    snapshot.x[0] = 5;
                    snapshot.x[1] = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    let stored = memory
                        .read_bytes_raw(address, std::mem::size_of::<u64>())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if snapshot.x[0] != 7 || stored != 12_u64.to_le_bytes() || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated ldadd produced old={} bytes={stored:02x?} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }

                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x88df_fc20)?;
                    memory
                        .write_bytes_unchecked(address, &17_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.x[0] = 0;
                    snapshot.fault_address = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot, &mut reservation)?;
                    if snapshot.x[0] != 17 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated ldar produced value={} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }
                    Ok(())
                });
            if let Err(error) = &emulated {
                child_write_stderr(format!("atomic add emulation test: {error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(emulated.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_zero_backing_replaces_readonly_page() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let zeroed = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .map_err(RuntimeError::from)
                .and_then(|mut memory| {
                    memory
                        .write_bytes_unchecked(layout.mmap_base, &[0xff; 16])
                        .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                    memory
                        .protect_range(
                            layout.mmap_base,
                            page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ,
                        )
                        .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                    memory
                        .zero_backing(layout.mmap_base, page_size as usize)
                        .map_err(|err| RuntimeError::Unsupported(format!("test zero: {err}")))?;
                    memory
                        .read_bytes_raw(layout.mmap_base, 16)
                        .map_err(|err| RuntimeError::Unsupported(format!("test read: {err}")))
                })
                .is_ok_and(|bytes| bytes == [0; 16]);
            unsafe { libc::_exit(i32::from(!zeroed)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_vfork_completion_pipe_closes_across_host_exec() {
        let (read_fd, write_fd) = vfork_pipe_pair().expect("create vfork completion pipe");
        let read_flags = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        let write_flags = unsafe { libc::fcntl(write_fd, libc::F_GETFD) };
        close_fd(read_fd);
        close_fd(write_fd);

        assert!(read_flags >= 0, "read-end F_GETFD failed");
        assert!(write_flags >= 0, "write-end F_GETFD failed");
        assert_ne!(read_flags & libc::FD_CLOEXEC, 0, "read end must be private");
        assert_ne!(
            write_flags & libc::FD_CLOEXEC,
            0,
            "host self-reexec must close the child completion end"
        );
    }

    #[test]
    fn native_vfork_inheritance_shares_private_pages() {
        let page_size = 16 * 1024;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        let word = mapped.cast::<u32>();
        unsafe { word.write(0) };
        assert!(set_native_region_fork_inheritance(
            carrick_guest_mem::HostVa(mapped as usize),
            page_size,
            true
        ));

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                word.write(42);
                libc::_exit(0);
            }
        }

        assert!(set_native_region_fork_inheritance(
            carrick_guest_mem::HostVa(mapped as usize),
            page_size,
            false
        ));
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(unsafe { word.read() }, 42);
        unsafe { libc::munmap(mapped, page_size) };
    }

    fn native_mapping_subset_survives_shared_inheritance_fork(
        selected: impl Fn(&NativeMappedRegion) -> bool,
    ) -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let page_size = 16 * 1024_u64;
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let memory = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .expect("native mapping set should map");
            for region in memory.regions.iter().filter(|region| selected(region)) {
                let start = usize::try_from(region.start).expect("native region start fits usize");
                let len = usize::try_from(region.end - region.start)
                    .expect("native region length fits usize");
                assert!(set_native_region_fork_inheritance(
                    carrick_guest_mem::HostVa(start),
                    len,
                    true,
                ));
            }
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            for region in memory.regions.iter().filter(|region| selected(region)) {
                let start = usize::try_from(region.start).expect("native region start fits usize");
                let len = usize::try_from(region.end - region.start)
                    .expect("native region length fits usize");
                let _ = set_native_region_fork_inheritance(
                    carrick_guest_mem::HostVa(start),
                    len,
                    false,
                );
            }
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn native_nested_fork_survives_without_mappings() -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn native_fixed_mapping_survives_nested_fork(start: u64, len: u64, shared: bool) -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let mut rollback = direct_test_mapping_rollback(start, len);
            let mapped =
                map_anonymous_region(start, len, shared, &NativeLayout::direct(), &mut rollback)
                    .is_ok();
            if !mapped {
                unsafe { libc::_exit(2) };
            }
            rollback.commit();
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    #[test]
    fn native_mapping_classes_survive_shared_inheritance_fork() {
        let layout = native_memory_layout();
        assert!(
            native_nested_fork_survives_without_mappings(),
            "native nested-fork control failed without native mappings"
        );
        let fixed_cases = [
            (
                "sigreturn",
                NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
                carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
                false,
            ),
            ("heap", layout.heap_base, layout.heap_size, false),
            ("mmap", layout.mmap_base, layout.mmap_size, false),
            (
                "shared aperture",
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                true,
            ),
            (
                "private overlay",
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                false,
            ),
        ];
        let fixed_failures: Vec<_> = fixed_cases
            .into_iter()
            .filter_map(|(name, start, len, shared)| {
                (!native_fixed_mapping_survives_nested_fork(start, len, shared)).then_some(name)
            })
            .collect();
        assert!(
            fixed_failures.is_empty(),
            "native fixed mappings broke the fork child: {fixed_failures:?}"
        );
        assert!(
            native_mapping_subset_survives_shared_inheritance_fork(|_| false),
            "native nested-fork baseline failed without changing inheritance"
        );
        let cases = [
            ("sigreturn", NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE),
            ("heap", layout.heap_base),
            ("mmap", layout.mmap_base),
            ("shared aperture", crate::memory::LINUX_SHARED_FILE_BASE),
            ("private overlay", crate::memory::LINUX_PRIVATE_OVERLAY_BASE),
        ];
        let mut failures = Vec::new();
        for (name, start) in cases {
            if !native_mapping_subset_survives_shared_inheritance_fork(|region| {
                region.start == start
            }) {
                failures.push(name);
            }
        }

        if !native_mapping_subset_survives_shared_inheritance_fork(|region| {
            region.start == layout.heap_base
                || region.start == layout.mmap_base
                || region.start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
        }) {
            failures.push("HVF-equivalent writable set");
        }

        assert!(
            failures.is_empty(),
            "sharing native mapping classes broke the fork child: {failures:?}"
        );
    }

    /// The native child-exit watcher must deliver the clone exit signal
    /// ASYNCHRONOUSLY — publish to the parent tid with no wait-path polling
    /// involved (the `sigchld` probe's parent spins in guest code and never
    /// enters a wait). Forked host proof per the native skill's order: register
    /// a watch for a live child, let it exit, and observe the pending signal
    /// appear without ever calling `native_poll_child_exit_watches`.
    #[test]
    fn native_child_exit_watch_publishes_asynchronously() {
        let tid = 0x7d0_57a5; // synthetic guest tid; nothing else publishes to it
        let mut release = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                // Drop every inherited fd except the release pipe before
                // parking: this child holds copies of EVERY fd of the parallel
                // test process (bound sockets, listeners), and while it blocks
                // those copies keep ports alive under a concurrent
                // port-release test — the pre-existing parallel-suite fork
                // hazard this child should not amplify.
                for fd in 3..4096 {
                    if fd != release[0] {
                        libc::close(fd);
                    }
                }
                let mut byte = 0u8;
                let _ = libc::read(release[0], (&raw mut byte).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(release[0]) };

        // Register while the child is alive: the one-shot NOTE_EXIT is the
        // delivery edge under test (not the already-dead fallback).
        crate::host_signal::register_child_exit_watch(child, tid, crate::linux_abi::LINUX_SIGCHLD);
        native_arm_child_exit_watch(child);
        assert!(
            !crate::host_signal::has_pending_for(tid),
            "no signal may be pending while the child is alive"
        );

        // Release the child with an EXPLICIT byte, not close-EOF: a sibling
        // fork test's child inherits a copy of this pipe's write end, so EOF
        // would deadlock two concurrent fork tests against each other.
        assert_eq!(
            unsafe { libc::write(release[1], b"x".as_ptr().cast(), 1) },
            1
        );
        unsafe { libc::close(release[1]) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !crate::host_signal::has_pending_for(tid) {
            assert!(
                Instant::now() < deadline,
                "child-exit watcher did not publish the exit signal within 5s"
            );
            std::thread::yield_now();
        }

        // The publish-once guard already consumed the watch entry.
        assert_eq!(crate::host_signal::take_child_exit_parent(child), None);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        // Drain the synthetic tid so no other host-signal test sees it.
        let _ = carrick_signal_core::take_pending_for(tid);
    }

    #[test]
    fn native_timer_publication_between_futex_predicate_and_park_is_not_lost() {
        use std::sync::atomic::{AtomicBool, Ordering};

        carrick_signal_core::clear_proc_pending();
        let runtime = NativeThreadRuntime::new_current();
        let dispatcher = SyscallDispatcher::new();
        let wait = runtime.futex.prepare_wait(0x71a3_0000);
        let published = AtomicBool::new(false);

        let outcome = runtime.futex.wait_prepared_for_thread(
            wait,
            Some(Duration::from_millis(25)),
            runtime.tid(),
            &|| {
                let observed = native_wait_interrupt_or_stw(
                    &dispatcher,
                    runtime.tid(),
                    carrick_abi::WaitSigMask::NONE,
                );
                if !published.swap(true, Ordering::SeqCst) {
                    assert!(
                        !observed,
                        "timer signal must publish after the outer predicate check"
                    );
                    deliver_native_process_signal(crate::linux_abi::LINUX_SIGALRM);
                }
                observed
            },
        );

        assert_eq!(outcome, crate::thread::FutexWaitOutcome::Interrupted);
        assert!(native_wait_interrupt_or_stw(
            &dispatcher,
            runtime.tid(),
            carrick_abi::WaitSigMask::NONE,
        ));
        carrick_signal_core::clear_proc_pending();
    }

    #[test]
    fn native_fork_child_timer_publication_uses_one_direct_kick() {
        use carrick_hal::VcpuRegistry as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct CountingKick(Arc<AtomicUsize>);

        impl carrick_hal::VcpuKick for CountingKick {
            fn kick(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fork_test(|| {
            let runtime = NativeThreadRuntime::new_current();
            let kicks = Arc::new(AtomicUsize::new(0));
            runtime.kicker.register(
                crate::thread::ThreadId::synthetic_for_tests(0x714e),
                Box::new(CountingKick(Arc::clone(&kicks))),
            );
            carrick_signal_core::clear_proc_pending();
            deliver_native_process_signal(crate::linux_abi::LINUX_SIGALRM);
            assert_eq!(
                kicks.load(Ordering::SeqCst),
                1,
                "fork child must schedule exactly one direct timer kick"
            );
            assert!(carrick_signal_core::has_process_pending());
        });
    }

    // Drives the real pump pipe + C-shim kick state: Darwin-only until the
    // native lane's host shim lands (M0.6/M0.7).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn fork_child_registers_kick_target_before_replacement_pump_consumes_pending() {
        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        fork_test(|| {
            carrick_signal_core::clear_proc_pending();
            let mut runtime = NativeThreadRuntime::new_current();
            runtime.reset_after_fork_child();
            carrick_signal_core::publish_process_signal(crate::linux_abi::LINUX_SIGALRM);
            crate::host_signal::wake_signal_pump_pipe();
            std::thread::sleep(Duration::from_millis(50));

            runtime
                .prepare_kick_target()
                .expect("prepare child kick target");
            runtime.start_signal_wake_pump();
            let state = runtime.kick_state.as_ref().expect("registered kick state");
            let deadline = Instant::now() + Duration::from_secs(2);
            while state.requested_generation() == 0 {
                assert!(
                    Instant::now() < deadline,
                    "replacement pump consumed the event before target registration"
                );
                std::thread::yield_now();
            }
            carrick_signal_core::clear_proc_pending();
        });
    }

    #[test]
    fn dispatcher_wake_owner_is_selected_by_execution_backend() {
        let mut dispatcher = SyscallDispatcher::new();
        assert_eq!(
            dispatcher.async_signal_wake_owner(),
            crate::dispatch::AsyncSignalWakeOwner::SignalPump
        );
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::Native);
        assert_eq!(
            dispatcher.async_signal_wake_owner(),
            crate::dispatch::AsyncSignalWakeOwner::NativeDirect
        );
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::Vmm);
        assert_eq!(
            dispatcher.async_signal_wake_owner(),
            crate::dispatch::AsyncSignalWakeOwner::SignalPump
        );
    }

    // HVF signal-pump semantics (real pump wake): Darwin-only until the
    // native lane grows its own wake pump (M1).
    #[cfg(target_os = "macos")]
    #[test]
    fn vmm_synchronous_child_exit_uses_pump_while_vcpu_spins() {
        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carrick_signal_core::clear_proc_pending();
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();
        let tid = crate::thread::ThreadId::synthetic_for_tests(0x51c4);
        crate::host_signal::forget_thread(tid.raw());
        let (pump, kicks) = counting_wake_pump(tid);
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::Vmm);
        let child = 0x51c4_0001;
        crate::host_signal::register_child_exit_watch(
            child,
            tid.raw(),
            crate::linux_abi::LINUX_SIGCHLD,
        );

        dispatcher.publish_terminal_child_exit_signal(child);
        wait_for_test_kick(&kicks);

        assert_eq!(
            crate::host_signal::take_pending_for(tid.raw()),
            crate::linux_abi::LINUX_SIGCHLD
        );
        pump.stop();
        crate::host_signal::forget_thread(tid.raw());
    }

    // HVF signal-pump semantics (real pump wake): Darwin-only until the
    // native lane grows its own wake pump (M1).
    #[cfg(target_os = "macos")]
    #[test]
    fn vmm_rlimit_cpu_uses_pump_while_vcpu_spins() {
        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carrick_signal_core::clear_proc_pending();
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();
        let tid = crate::thread::ThreadId::synthetic_for_tests(0x58c0);
        let (pump, kicks) = counting_wake_pump(tid);
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::Vmm);

        dispatcher.publish_rlimit_cpu_signal_for_test(crate::linux_abi::LINUX_SIGXCPU);
        wait_for_test_kick(&kicks);

        assert_eq!(
            crate::host_signal::take_process_pending(),
            crate::linux_abi::LINUX_SIGXCPU
        );
        pump.stop();
    }

    #[test]
    fn native_synchronous_helpers_use_one_direct_kick() {
        use carrick_hal::VcpuRegistry as _;
        use std::sync::atomic::Ordering;

        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carrick_signal_core::clear_proc_pending();
        let runtime = NativeThreadRuntime::new_current();
        let kicks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        runtime.kicker.register(
            crate::thread::ThreadId::synthetic_for_tests(0x4e41),
            Box::new(TestCountingKick(Arc::clone(&kicks))),
        );
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::Native);
        let parent_tid = 0x4e41_0001;
        let child = 0x4e41_0002;
        crate::host_signal::forget_thread(parent_tid);
        crate::host_signal::register_child_exit_watch(
            child,
            parent_tid,
            crate::linux_abi::LINUX_SIGCHLD,
        );

        dispatcher.publish_terminal_child_exit_signal(child);
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        assert_eq!(
            crate::host_signal::take_pending_for(parent_tid),
            crate::linux_abi::LINUX_SIGCHLD
        );
        dispatcher.publish_rlimit_cpu_signal_for_test(crate::linux_abi::LINUX_SIGXCPU);
        assert_eq!(kicks.load(Ordering::SeqCst), 2);
        assert_eq!(
            crate::host_signal::take_process_pending(),
            crate::linux_abi::LINUX_SIGXCPU
        );
        crate::host_signal::forget_thread(parent_tid);
    }

    #[test]
    fn native_child_exit_publication_between_futex_predicate_and_park_is_not_lost() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let runtime = NativeThreadRuntime::new_current();
        let dispatcher = SyscallDispatcher::new();
        let child = 0x6c11_0001;
        let parent_tid = runtime.tid().raw();
        crate::host_signal::forget_thread(parent_tid);
        crate::host_signal::register_child_exit_watch(
            child,
            parent_tid,
            crate::linux_abi::LINUX_SIGCHLD,
        );
        let wait = runtime.futex.prepare_wait(0xc411_d000);
        let published = AtomicBool::new(false);

        let outcome = runtime.futex.wait_prepared_for_thread(
            wait,
            Some(Duration::from_millis(25)),
            runtime.tid(),
            &|| {
                let observed = crate::host_signal::has_unblocked_pending_for(
                    parent_tid,
                    carrick_abi::SigBlockMask::NONE,
                );
                if !published.swap(true, Ordering::SeqCst) {
                    assert!(
                        !observed,
                        "child-exit signal must publish after the outer predicate check"
                    );
                    native_publish_child_exit(child);
                }
                observed
            },
        );

        assert_eq!(outcome, crate::thread::FutexWaitOutcome::Interrupted);
        assert!(native_wait_interrupt_or_stw(
            &dispatcher,
            runtime.tid(),
            carrick_abi::WaitSigMask::NONE,
        ));
        assert_eq!(crate::host_signal::take_child_exit_parent(child), None);
        let _ = crate::host_signal::take_pending_for(parent_tid);
        crate::host_signal::forget_thread(parent_tid);
    }

    // HVF signal-pump semantics (real pump kqueue/self-pipe): Darwin-only
    // until the native lane grows its own wake pump (M1).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_host_signal_pump_closes_private_futex_park_window() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        carrick_signal_core::clear_proc_pending();
        let mut runtime = NativeThreadRuntime::new_current();
        runtime.start_signal_wake_pump();
        let pump_ready = Instant::now() + Duration::from_secs(1);
        while (crate::host_signal::pump_kqueue() < 0 || crate::host_signal::pump_pipe_read_fd() < 0)
            && Instant::now() < pump_ready
        {
            thread::yield_now();
        }
        assert!(crate::host_signal::pump_kqueue() >= 0, "pump kqueue ready");
        assert!(
            crate::host_signal::pump_pipe_read_fd() >= 0,
            "pump pipe ready"
        );

        let wait = runtime.futex.prepare_wait(0x517a_0000);
        let published = AtomicBool::new(false);
        let outcome = runtime.futex.wait_prepared_for_thread(
            wait,
            Some(Duration::from_millis(100)),
            runtime.tid(),
            &|| {
                let observed = crate::host_signal::has_unblocked_pending_for(
                    runtime.tid().raw(),
                    carrick_abi::SigBlockMask::NONE,
                );
                if !published.swap(true, Ordering::SeqCst) {
                    assert!(!observed, "host signal publishes after outer check");
                    // This is the host-handler/pump ingress shape, deliberately
                    // bypassing the native timer helper's direct futex wake.
                    crate::host_signal::publish_process_signal(crate::linux_abi::LINUX_SIGALRM);
                }
                observed
            },
        );

        assert_eq!(outcome, crate::thread::FutexWaitOutcome::Interrupted);
        carrick_signal_core::clear_proc_pending();
    }

    // HVF signal-pump semantics (real pump kqueue/self-pipe): Darwin-only
    // until the native lane grows its own wake pump (M1).
    #[cfg(target_os = "macos")]
    #[test]
    fn native_xsignal_nudge_pump_closes_private_futex_park_window() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let _pump_guard = NATIVE_PUMP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::host_signal::install_default_handlers();
        carrick_signal_core::xsig::xsig_init();
        let _ = carrick_signal_core::xsig::xsig_drain_for_self();
        let mut runtime = NativeThreadRuntime::new_current();
        runtime.start_signal_wake_pump();
        let pump_ready = Instant::now() + Duration::from_secs(1);
        while (crate::host_signal::pump_kqueue() < 0 || crate::host_signal::pump_pipe_read_fd() < 0)
            && Instant::now() < pump_ready
        {
            thread::yield_now();
        }
        assert!(crate::host_signal::pump_kqueue() >= 0, "pump kqueue ready");
        assert!(
            crate::host_signal::pump_pipe_read_fd() >= 0,
            "pump pipe ready"
        );

        let wait = runtime.futex.prepare_wait(0x517a_1000);
        let published = AtomicBool::new(false);
        let outcome = runtime.futex.wait_prepared_for_thread(
            wait,
            Some(Duration::from_millis(100)),
            runtime.tid(),
            &|| {
                let observed = carrick_signal_core::xsig::xsig_has_unblocked_for_self(
                    carrick_abi::SigBlockMask::NONE,
                );
                if !published.swap(true, Ordering::SeqCst) {
                    assert!(!observed, "xsignal publishes after outer check");
                    assert!(carrick_signal_core::xsig::xsig_enqueue(
                        std::process::id() as i32,
                        crate::linux_abi::LINUX_SIGUSR1,
                        crate::linux_abi::LINUX_SI_USER,
                        1,
                        0,
                        0,
                        0,
                    ));
                    // Exercise the real SIGINFO nudge handler. It marks the
                    // ring publication generation before its async-signal-safe
                    // pipe writes, which is the authority the pump reconciles.
                    crate::host_signal::xsig_nudge(std::process::id() as i32);
                }
                observed
            },
        );

        assert_eq!(outcome, crate::thread::FutexWaitOutcome::Interrupted);
        let drained = carrick_signal_core::xsig::xsig_drain_for_self();
        assert_eq!(drained.len(), 1);
    }

    /// If the watcher thread dies its owned kqueue drops (fd closed) while the
    /// published fd number lingers — every later arm gets EBADF, which must
    /// NOT silently disable async delivery: the arm forgets the stale fd and
    /// respawns a fresh watcher. Model the dead watcher by publishing a
    /// closed fd, then require end-to-end delivery to still work.
    #[test]
    fn native_child_exit_watch_recovers_from_dead_watcher_fd() {
        use std::sync::atomic::Ordering;
        let bad = unsafe { libc::dup(0) };
        assert!(bad >= 0, "dup(0) failed");
        unsafe { libc::close(bad) };
        NATIVE_CHILD_WATCH_KQ.store(bad, Ordering::Release);
        NATIVE_CHILD_WATCH_OWNER.store(std::process::id(), Ordering::Release);

        let tid = 0x7d0_57a6; // synthetic guest tid, distinct from the async test
        let mut release = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                // Drop every inherited fd except the release pipe before
                // parking: this child holds copies of EVERY fd of the parallel
                // test process (bound sockets, listeners), and while it blocks
                // those copies keep ports alive under a concurrent
                // port-release test — the pre-existing parallel-suite fork
                // hazard this child should not amplify.
                for fd in 3..4096 {
                    if fd != release[0] {
                        libc::close(fd);
                    }
                }
                let mut byte = 0u8;
                let _ = libc::read(release[0], (&raw mut byte).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(release[0]) };

        crate::host_signal::register_child_exit_watch(child, tid, crate::linux_abi::LINUX_SIGCHLD);
        native_arm_child_exit_watch(child);

        // Explicit-byte release; see the async test for the close-EOF hazard.
        assert_eq!(
            unsafe { libc::write(release[1], b"x".as_ptr().cast(), 1) },
            1
        );
        unsafe { libc::close(release[1]) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !crate::host_signal::has_pending_for(tid) {
            assert!(
                Instant::now() < deadline,
                "arm against a dead watcher fd silently lost async delivery"
            );
            std::thread::yield_now();
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        let _ = carrick_signal_core::take_pending_for(tid);
    }

    #[test]
    fn native_vfork_inheritance_matches_hvf_writability() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let memory = NativeMappedMemory::map(&image, layout, 16 * 1024, 16 * 1024)
                .expect("native mapping set should map");
            let writable = |start| {
                memory
                    .regions
                    .iter()
                    .find(|region| region.start == start)
                    .map(|region| region.guest_writable && !region.shared_futex)
            };
            let matches_hvf = writable(NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE) == Some(false)
                && writable(layout.heap_base) == Some(true)
                && writable(layout.mmap_base) == Some(true)
                && writable(crate::memory::LINUX_SHARED_FILE_BASE) == Some(false)
                && writable(crate::memory::LINUX_PRIVATE_OVERLAY_BASE) == Some(true);
            unsafe { libc::_exit(i32::from(!matches_hvf)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// Two direct MAP_SHARED mappings of the SAME file at DIFFERENT guest
    /// addresses must resolve one futex word to ONE waiter-count key (the
    /// native exec rebuilds the address space, so an exec'd child re-attaches
    /// an LTP checkpoint page at a fresh VA — ltpcheckpointexec). Anon shared
    /// arena words keep VA keys. Forked, per the fixed-address discipline.
    #[test]
    fn native_shared_file_futex_keys_are_mapping_independent() {
        let path = std::env::temp_dir().join(format!(
            ".carrick-native-futexkey-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        ));
        std::fs::write(&path, vec![0u8; 16 * 1024]).expect("seed checkpoint file");
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let mut memory = NativeMappedMemory::map(&image, layout, 16 * 1024, 16 * 1024)
                .expect("native mapping set should map");
            let open = || unsafe {
                let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                libc::open(c.as_ptr(), libc::O_RDWR)
            };
            let (fd1, fd2) = (open(), open());
            if fd1 < 0 || fd2 < 0 {
                unsafe { libc::_exit(2) };
            }
            let va1 = crate::memory::LINUX_SHARED_FILE_BASE;
            let va2 = crate::memory::LINUX_SHARED_FILE_BASE + 0x20_0000;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            if memory
                .map_host_alias(va1, 16 * 1024, &[], Some((fd1, 0, prot)), false)
                .is_err()
                || memory
                    .map_host_alias(va2, 16 * 1024, &[], Some((fd2, 0, prot)), false)
                    .is_err()
            {
                unsafe { libc::_exit(3) };
            }
            let key = |addr: u64| memory.shared_futex_location(addr).map(|l| l.waiter_key());
            let word = 0x4c; // the LTP checkpoint word offset
            let ok = match (key(va1 + word), key(va2 + word)) {
                // Cross-mapping rendezvous: same file+offset → same key, and it
                // is NOT the VA (either VA would differ from the other's key).
                (Some(k1), Some(k2)) => k1 == k2 && k1 != (va1 + word) as usize,
                _ => false,
            };
            // An anon shared-arena word (no file identity) still keys by VA.
            let anon = crate::memory::LINUX_SHARED_FILE_BASE + 0x100_0000;
            let anon_ok = key(anon) == Some(anon as usize);
            unsafe { libc::_exit(i32::from(!(ok && anon_ok))) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        let _ = std::fs::remove_file(&path);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// munmap must retire a file alias's futex-key material: region entries
    /// are never pruned, so after the guest unmaps file A and the shared-arena
    /// VA is reused for an ANON MAP_SHARED word (served by the boot arena
    /// region — no new region push), a stale newest-wins alias entry would
    /// keep FILE-keying the word in THIS process while every other process
    /// VA-keys the same physical word — missed cross-process wakes, the exact
    /// hang class the file-identity keys fixed, reintroduced via VA reuse.
    #[test]
    fn native_unmapped_file_alias_stops_file_keying_reused_va() {
        let path = std::env::temp_dir().join(format!(
            ".carrick-native-futexkey-unmap-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        ));
        std::fs::write(&path, vec![0u8; 16 * 1024]).expect("seed checkpoint file");
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let mut memory = NativeMappedMemory::map(&image, layout, 16 * 1024, 16 * 1024)
                .expect("native mapping set should map");
            let fd = unsafe {
                let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                libc::open(c.as_ptr(), libc::O_RDWR)
            };
            if fd < 0 {
                unsafe { libc::_exit(2) };
            }
            let va = crate::memory::LINUX_SHARED_FILE_BASE;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            if memory
                .map_host_alias(va, 16 * 1024, &[], Some((fd, 0, prot)), false)
                .is_err()
            {
                unsafe { libc::_exit(3) };
            }
            let word = va + 0x4c;
            let key = |memory: &NativeMappedMemory| {
                memory.shared_futex_location(word).map(|l| l.waiter_key())
            };
            // Sanity: while mapped, the word is file-keyed (not the VA).
            let file_keyed = matches!(key(&memory), Some(k) if k != word as usize);
            if memory.unmap_range(va, 16 * 1024).is_err() {
                unsafe { libc::_exit(4) };
            }
            memory.set_mapping_protection_and_sharing(
                va,
                16 * 1024,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
            // After shared-anon reuse is published, the VA is an arena word
            // again: it must key by VA like every other process, never by the
            // dead file.
            let va_keyed_after = key(&memory) == Some(word as usize);
            unsafe { libc::_exit(i32::from(!(file_keyed && va_keyed_after))) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        let _ = std::fs::remove_file(&path);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_private_overlay_retires_boot_shared_futex_provenance_after_fork() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let mut memory = NativeMappedMemory::map(&image, layout, 16 * 1024, 16 * 1024)
                .expect("native mapping set should map");
            let word = crate::memory::LINUX_SHARED_FILE_BASE + 0x4c;
            let shared_before = memory.shared_futex_location(word).is_some();
            let private = vec![0u8; 16 * 1024];
            let repointed = memory
                .repoint_private(
                    crate::memory::LINUX_SHARED_FILE_BASE,
                    0,
                    private.len(),
                    &private,
                )
                .is_ok();
            let private_after = memory.shared_futex_location(word).is_none();
            unsafe { libc::_exit(i32::from(!(shared_before && repointed && private_after))) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_dynamic_loader_owns_main_relocations() {
        let dynamic = synthetic_dynamic_elf(Some(b"/lib/ld-linux-aarch64.so.1\0"));
        let elf = Elf::parse(&dynamic).expect("synthetic dynamic ELF should parse");

        assert!(!native_image_needs_eager_relocations(&elf));
    }

    #[test]
    fn native_static_pie_needs_eager_relative_relocations() {
        let static_pie = synthetic_dynamic_elf(None);
        let elf = Elf::parse(&static_pie).expect("synthetic static PIE should parse");

        assert!(native_image_needs_eager_relocations(&elf));
    }

    /// Empirical hazard gate for the native vDSO (see `stamp_vdso_vvar`).
    /// The guest-visible counter is a DSR-adjusted read, not Darwin's raw
    /// `CNTVCT_EL0`: two translated reads must bracket `CLOCK_UPTIME_RAW` in
    /// the preserved `CNTFRQ_EL0` domain and remain monotonic on this already
    /// suspended host. Known host modes must stay inline so clock-heavy vDSO
    /// workloads do not acquire a sensitive gateway transition.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_virtual_counter_reads_track_clock_uptime_raw() {
        assert!(
            dsr::host_counter_plan_is_inline_for_test(),
            "this host must use an inline DSR counter plan"
        );
        let ticks_before =
            dsr::execute_virtual_counter_for_test().expect("execute first virtual counter read");
        let uptime_ns = crate::trap::host_clock_uptime_ns();
        let ticks_after =
            dsr::execute_virtual_counter_for_test().expect("execute second virtual counter read");
        let freq = crate::trap::host_counter_frequency();
        assert!(freq > 0, "CNTFRQ_EL0 read zero at EL0");
        assert!(
            ticks_after >= ticks_before,
            "DSR-adjusted counter went backwards"
        );
        let to_ns = |ticks: u64| (ticks as u128 * 1_000_000_000 / u128::from(freq)) as u64;
        // One counter tick + 1µs of conversion rounding slack.
        let slack_ns = 1_000_000_000 / freq + 1_000;
        let adjusted_before_ns = to_ns(ticks_before);
        let adjusted_after_ns = to_ns(ticks_after);
        assert!(
            adjusted_before_ns <= uptime_ns + slack_ns,
            "DSR-adjusted counter ({adjusted_before_ns} ns) is ahead of CLOCK_UPTIME_RAW ({uptime_ns} ns): timelines diverge"
        );
        assert!(
            uptime_ns <= adjusted_after_ns + slack_ns,
            "DSR-adjusted counter ({adjusted_after_ns} ns) is behind CLOCK_UPTIME_RAW ({uptime_ns} ns): timelines diverge"
        );
    }

    /// Mapping an image that carries the vDSO must (a) stamp the read-only
    /// vvar page — RNG generation = this process's PID, non-zero counter
    /// frequency, and a realtime offset that is also published to the shared
    /// syscall-path store — (b) route the injected vDSO code page through the
    /// native syscall-instruction translation pass (no `svc #0` survives; the
    /// brk replacement is present), (c) rewrite the code page's hardcoded
    /// canonical vvar-base loads to the relocated native base, and (d) support
    /// the fork-child RNG generation re-stamp against the once-again read-only
    /// page.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_map_stamps_vvar_and_patches_vdso_svc() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new()).and_then(|image| {
                image.with_vdso_bytes_at(
                    crate::vdso::vdso_image_bytes(),
                    NATIVE_DARWIN_VVAR_BASE,
                    NATIVE_DARWIN_VDSO_BASE,
                )
            });
            let Ok(image) = image else {
                unsafe { libc::_exit(10) }
            };
            let memory = match NativeMappedMemory::map(&image, layout, page_size, page_size) {
                Ok(memory) => memory,
                Err(err) => {
                    child_write_stderr(format!("map failed: {err}\n").as_bytes());
                    unsafe { libc::_exit(11) }
                }
            };
            let read_vvar_u64 = |offset: usize| unsafe {
                std::ptr::read_volatile((NATIVE_DARWIN_VVAR_BASE as usize + offset) as *const u64)
            };
            let pid = unsafe { libc::getpid() } as u64;
            if read_vvar_u64(crate::vdso::VVAR_OFF_RNG_GENERATION) != pid {
                unsafe { libc::_exit(12) }
            }
            if read_vvar_u64(crate::vdso::VVAR_OFF_FREQ) == 0 {
                unsafe { libc::_exit(13) }
            }
            let realtime_off = read_vvar_u64(crate::vdso::VVAR_OFF_REALTIME_OFF_NS);
            if realtime_off == 0 || crate::vdso::realtime_off_ns() != Some(realtime_off) {
                unsafe { libc::_exit(14) }
            }
            // DSR leaves the injected vDSO source page unmodified while its
            // hardcoded vvar-base loads are retargeted at the relocated native
            // base.
            let vdso_words: Vec<u32> = unsafe {
                std::slice::from_raw_parts(
                    NATIVE_DARWIN_VDSO_BASE as usize as *const u8,
                    crate::vdso::LINUX_VDSO_SIZE as usize,
                )
            }
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
            if !vdso_words.contains(&SVC_0) {
                unsafe { libc::_exit(15) }
            }
            let canonical_movz = movz_x_lsl32((crate::vdso::LINUX_VVAR_BASE >> 32) as u16);
            let relocated_movz = movz_x_lsl32((NATIVE_DARWIN_VVAR_BASE >> 32) as u16);
            if vdso_words.iter().any(|w| w & !0x1f == canonical_movz) {
                unsafe { libc::_exit(17) }
            }
            if !vdso_words.iter().any(|w| w & !0x1f == relocated_movz) {
                unsafe { libc::_exit(18) }
            }
            // Fork re-stamp mechanism: scribble the generation, re-stamp, and
            // verify the read-only page carries this process's PID again.
            if memory
                .write_vvar_words(&[(crate::vdso::VVAR_OFF_RNG_GENERATION, 0xdead_beef)])
                .is_err()
                || read_vvar_u64(crate::vdso::VVAR_OFF_RNG_GENERATION) != 0xdead_beef
            {
                unsafe { libc::_exit(19) }
            }
            if memory.restamp_vdso_rng_generation_after_fork().is_err()
                || read_vvar_u64(crate::vdso::VVAR_OFF_RNG_GENERATION) != pid
            {
                unsafe { libc::_exit(20) }
            }
            unsafe { libc::_exit(0) }
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "vvar/vdso child check failed");
    }

    fn native_prepared_mapping_fixture(
        relocations: bool,
    ) -> (AddressSpace, Vec<NativeRelativeRelocation>, ExecutionPlan) {
        // Every prepared-mapping test funnels through this builder before it maps
        // (`map_prepared_for_plan` / `map_for_plan`), and each mapping builds a
        // `ProcessTranslator` that resolves the Darwin host JIT through the
        // process-global seam production installs at every native-backend entry
        // (`install_native_probe_sink`). The `#[cfg(test)]` harness installs it
        // here so each test is order-independent: without it the mapping fails
        // "no host JIT installed" in isolation and only passes when a sibling
        // test happened to install it first. Idempotent / first-install-wins.
        dsr::install_test_host_jit();
        let plan = native16k_test_plan();
        let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
            &dsr_test_elf(&[0xd65f_03c0]),
            &|_| None,
            NATIVE_DARWIN_PIE_BASE,
            plan.page_geometry.host_page_size,
        )
        .expect("load prepared mapping fixture")
        .with_vdso_auxv(true);
        let image = with_native_vdso(image)
            .expect("add native vDSO")
            .with_linux_initial_stack_page_size(
                [b"prepared-mapping".as_slice()],
                [b"MODE=parity".as_slice()],
                plan.page_geometry.linux_page_size,
            )
            .expect("add prepared mapping stack");
        let relative_relocations = if relocations {
            let target = image
                .initial_stack_pointer()
                .expect("initial stack pointer");
            vec![NativeRelativeRelocation::new(
                crate::native_prepared_image::PreparedGuestVa::new(target)
                    .expect("typed relocation target"),
                crate::native_prepared_image::PreparedGuestVa::new(0x1234_5678)
                    .expect("typed relocation value"),
            )]
        } else {
            Vec::new()
        };
        (image, relative_relocations, plan)
    }

    fn native_biased_prepared_mapping_fixture() -> (AddressSpace, ExecutionPlan) {
        // See `native_prepared_mapping_fixture`: install the host-JIT seam before
        // the biased test maps. Idempotent / first-install-wins.
        dsr::install_test_host_jit();
        let plan = native16k_test_plan();
        let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
            &dsr_low_et_exec_test_elf(&[0xd65f_03c0]),
            &|_| None,
            NATIVE_DARWIN_PIE_BASE,
            plan.page_geometry.host_page_size,
        )
        .expect("load biased prepared mapping fixture")
        .with_vdso_auxv(true);
        let image = with_native_vdso(image)
            .expect("add biased native vDSO")
            .with_linux_initial_stack_page_size(
                [b"biased-prepared-mapping".as_slice()],
                std::iter::empty::<&[u8]>(),
                plan.page_geometry.linux_page_size,
            )
            .expect("add biased prepared mapping stack");
        (image, plan)
    }

    fn validated_prepared_mapping_fixture(
        image: &AddressSpace,
        relocations: &[NativeRelativeRelocation],
        host_page_size: u64,
    ) -> crate::native_prepared_image::ValidatedPreparedImage {
        let artifact =
            match crate::native_prepared_image::prepare(image, relocations, host_page_size)
                .expect("prepare mapping artifact")
            {
                crate::native_prepared_image::PreparedImageDisposition::Prepared(artifact) => {
                    artifact
                }
                crate::native_prepared_image::PreparedImageDisposition::Ineligible(reason) => {
                    panic!("mapping fixture is ineligible: {reason:?}")
                }
            };
        crate::native_prepared_image::validate_artifact_for_test(artifact)
            .expect("validate mapping artifact")
    }

    fn retire_native_test_mapping(memory: &NativeMappedMemory) {
        for range in memory.owned_host_ranges.iter() {
            let len = range
                .end
                .raw()
                .checked_sub(range.start.raw())
                .expect("owned mapping range");
            if len != 0 {
                assert_eq!(
                    unsafe { libc::munmap(range.start.raw() as *mut libc::c_void, len) },
                    0,
                    "retire native test mapping 0x{:x}..0x{:x}: {}",
                    range.start.raw(),
                    range.end.raw(),
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    fn native_mapping_region_bytes(
        memory: &NativeMappedMemory,
        image: &AddressSpace,
    ) -> Vec<Vec<u8>> {
        image
            .regions()
            .iter()
            .map(|region| {
                memory
                    .read_bytes(
                        region.start,
                        usize::try_from(region.len()).expect("region length"),
                    )
                    .expect("read mapped region")
            })
            .collect()
    }

    fn native_mapping_class_ranges(
        image: &AddressSpace,
        layout: MemoryLayout,
        mode: NativeAddressMode,
        host_page_size: u64,
    ) -> Vec<(&'static str, std::ops::Range<carrick_guest_mem::HostVa>)> {
        fn host_range(
            mode: NativeAddressMode,
            start: u64,
            length: u64,
            page_size: u64,
        ) -> std::ops::Range<carrick_guest_mem::HostVa> {
            let mask = page_size - 1;
            let aligned_start = start & !mask;
            let aligned_end = start
                .checked_add(length)
                .and_then(|end| end.checked_add(mask))
                .map(|end| end & !mask)
                .expect("aligned native test range");
            mode.to_host(carrick_guest_mem::GuestVa(aligned_start))
                .expect("translate native test range start")
                ..mode
                    .to_host(carrick_guest_mem::GuestVa(aligned_end))
                    .expect("translate native test range end")
        }

        let mut ranges = image
            .regions()
            .iter()
            .map(|region| {
                (
                    "image",
                    host_range(mode, region.start, region.len(), host_page_size),
                )
            })
            .collect::<Vec<_>>();
        ranges.extend([
            (
                "sigreturn",
                host_range(
                    mode,
                    NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
                    carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
                    host_page_size,
                ),
            ),
            (
                "heap",
                host_range(mode, layout.heap_base, layout.heap_size, host_page_size),
            ),
            (
                "mmap",
                host_range(mode, layout.mmap_base, layout.mmap_size, host_page_size),
            ),
            (
                "shared aperture",
                host_range(
                    mode,
                    crate::memory::LINUX_SHARED_FILE_BASE,
                    crate::memory::LINUX_SHARED_FILE_SIZE,
                    host_page_size,
                ),
            ),
            (
                "private overlay",
                host_range(
                    mode,
                    crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                    crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                    host_page_size,
                ),
            ),
        ]);
        ranges
    }

    fn assert_native_ranges_vacant(
        ranges: impl IntoIterator<Item = (impl AsRef<str>, std::ops::Range<carrick_guest_mem::HostVa>)>,
    ) {
        #[cfg(target_os = "macos")]
        const VACANCY_MAP_FLAGS: i32 = libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE;
        #[cfg(not(target_os = "macos"))]
        const VACANCY_MAP_FLAGS: i32 = libc::MAP_ANON | libc::MAP_PRIVATE;

        for (name, range) in ranges {
            let length = range
                .end
                .raw()
                .checked_sub(range.start.raw())
                .expect("vacancy range length");
            let vacant = address::OwnedHostMapping::map_exact(
                range.start,
                length,
                libc::PROT_NONE,
                VACANCY_MAP_FLAGS,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} range 0x{:x}..0x{:x} was not vacant: {error}",
                    name.as_ref(),
                    range.start.raw(),
                    range.end.raw()
                )
            });
            drop(vacant);
        }
    }

    fn assert_supplemental_rollback_once(
        expected: &[(&str, std::ops::Range<carrick_guest_mem::HostVa>)],
        actual: &[std::ops::Range<carrick_guest_mem::HostVa>],
    ) {
        for (name, range) in expected {
            let owners = actual
                .iter()
                .filter(|cleanup| {
                    cleanup.start.raw() <= range.start.raw() && cleanup.end.raw() >= range.end.raw()
                })
                .count();
            assert_eq!(
                owners,
                1,
                "{name} range 0x{:x}..0x{:x} supplemental owners: {actual:?}",
                range.start.raw(),
                range.end.raw()
            );
        }
        for (index, left) in actual.iter().enumerate() {
            for right in &actual[index + 1..] {
                assert!(
                    left.end.raw() <= right.start.raw() || right.end.raw() <= left.start.raw(),
                    "supplemental rollback ranges overlap: {left:?} and {right:?}"
                );
            }
        }
    }

    fn assert_native_source_execution_denied(memory: &NativeMappedMemory, guest_pc: u64) {
        let host_pc = memory
            .host_address(carrick_guest_mem::GuestVa(guest_pc))
            .expect("translate executable source page");
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork execute probe: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                libc::signal(libc::SIGBUS, libc::SIG_DFL);
                libc::signal(libc::SIGSEGV, libc::SIG_DFL);
            }
            let entry: unsafe extern "C" fn() = unsafe { std::mem::transmute(host_pc.raw()) };
            unsafe { entry() };
            unsafe { libc::_exit(99) };
        }
        let status = waitpid_blocking(child).expect("wait for execute probe");
        assert!(
            libc::WIFSIGNALED(status),
            "source page executed: status={status:#x}"
        );
        assert!(
            matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV),
            "unexpected execute-denial signal: status={status:#x}"
        );
    }

    #[test]
    fn native_prepared_mapping_matches_anonymous_bytes_and_finalization() {
        fork_test(|| {
            set_native_test_vvar_words(Some(vec![
                (crate::vdso::VVAR_OFF_RNG_GENERATION, 0x1111_2222),
                (crate::vdso::VVAR_OFF_FREQ, 0x3333_4444),
                (crate::vdso::VVAR_OFF_REALTIME_OFF_NS, 0x5555_6666),
            ]));
            let (image, no_relocations, plan) = native_prepared_mapping_fixture(false);
            let validated = validated_prepared_mapping_fixture(
                &image,
                &no_relocations,
                plan.page_geometry.host_page_size,
            );

            let legacy = NativeMappedMemory::map_for_plan(
                &image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
                plan.page_geometry,
                &no_relocations,
            )
            .expect("map anonymous fixture");
            let legacy_bytes = native_mapping_region_bytes(&legacy, &image);
            let legacy_protections = legacy.protections.snapshot_all();
            let legacy_mode = legacy.address_mode();
            let legacy_owned = legacy.owned_host_ranges.clone();
            let vvar_len = usize::try_from(crate::vdso::LINUX_VVAR_SIZE).expect("vvar length");
            let legacy_vvar = legacy
                .read_bytes(NATIVE_DARWIN_VVAR_BASE, vvar_len)
                .expect("read legacy vvar");
            assert_native_source_execution_denied(&legacy, image.entry());
            retire_native_test_mapping(&legacy);
            drop(legacy);

            let prepared = NativeMappedMemory::map_prepared_for_plan(
                &validated,
                native_memory_layout(),
                plan.page_geometry,
            )
            .expect("map prepared fixture");
            assert_eq!(validated.image.entry(), image.entry());
            assert_eq!(
                validated.image.initial_stack_pointer(),
                image.initial_stack_pointer()
            );
            assert_eq!(
                native_mapping_region_bytes(&prepared, &validated.image),
                legacy_bytes
            );
            assert_eq!(prepared.protections.snapshot_all(), legacy_protections);
            assert_eq!(prepared.address_mode(), legacy_mode);
            assert_eq!(prepared.owned_host_ranges, legacy_owned);
            assert_eq!(
                prepared
                    .read_bytes(NATIVE_DARWIN_VVAR_BASE, vvar_len)
                    .expect("read prepared vvar"),
                legacy_vvar
            );
            assert_eq!(
                validated
                    .image
                    .regions()
                    .iter()
                    .map(|region| (region.start, region.end, region.perms, region.shared))
                    .collect::<Vec<_>>(),
                image
                    .regions()
                    .iter()
                    .map(|region| (region.start, region.end, region.perms, region.shared))
                    .collect::<Vec<_>>()
            );
            assert_eq!(validated.image.linux_auxv_image(), image.linux_auxv_image());
            assert_eq!(validated.image.ro_spans(), image.ro_spans());
            assert_native_source_execution_denied(&prepared, image.entry());

            let artifact_fd = validated.file_fd();
            assert!(unsafe { libc::fcntl(artifact_fd, libc::F_GETFD) } >= 0);
            drop(validated);
            assert_eq!(unsafe { libc::fcntl(artifact_fd, libc::F_GETFD) }, -1);
            assert_eq!(
                prepared
                    .read_bytes(image.entry(), 4)
                    .expect("mapping survives artifact close"),
                0xd65f_03c0_u32.to_le_bytes()
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_mapping_matches_relocated_words() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(true);
            let target = relocations[0].address().get();
            let expected = relocations[0].value().get();
            let legacy = NativeMappedMemory::map_for_plan(
                &image,
                native_memory_layout(),
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
                plan.page_geometry,
                &relocations,
            )
            .expect("map relocated anonymous fixture");
            let legacy_word = u64::from_le_bytes(
                legacy
                    .read_bytes(target, 8)
                    .expect("read legacy relocation")
                    .try_into()
                    .expect("legacy relocation width"),
            );
            retire_native_test_mapping(&legacy);
            drop(legacy);
            let validated = validated_prepared_mapping_fixture(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            let prepared = NativeMappedMemory::map_prepared_for_plan(
                &validated,
                native_memory_layout(),
                plan.page_geometry,
            )
            .expect("map relocated prepared fixture");
            let prepared_word = u64::from_le_bytes(
                prepared
                    .read_bytes(target, 8)
                    .expect("read prepared relocation")
                    .try_into()
                    .expect("prepared relocation width"),
            );
            assert_eq!(prepared_word, expected);
            assert_eq!(prepared_word, legacy_word);
            set_native_test_vvar_words(None);
        });
    }

    fn assert_prepared_mapping_failure_cleans_up(
        failpoint: NativePreparedMappingFailpoint,
        expected: &str,
        all_classes_mapped: bool,
    ) {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(true);
            let layout = native_memory_layout();
            let selected =
                NativeLayout::for_image(&image, layout, plan.page_geometry.host_page_size)
                    .expect("select expected Direct cleanup layout");
            assert_eq!(selected.address_mode(), NativeAddressMode::Direct);
            let planned = native_mapping_class_ranges(
                &image,
                layout,
                selected.address_mode(),
                plan.page_geometry.host_page_size,
            );
            let owned = selected.owned_ranges().to_vec();
            drop(selected);
            let validated = validated_prepared_mapping_fixture(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            assert!(take_native_test_supplemental_rollbacks().is_empty());
            set_native_prepared_mapping_failpoint(Some(failpoint));
            let error = match NativeMappedMemory::map_prepared_for_plan(
                &validated,
                layout,
                plan.page_geometry,
            ) {
                Ok(_) => panic!("prepared mapping failpoint must fail"),
                // `map_prepared_for_plan` surfaces `NativeMemoryError`; the
                // runtime's public boundary wraps it into `RuntimeError` (the
                // `From` edge in run_result.rs), which is what a guest sees and
                // what the expected "unsupported in this backend: ..." string
                // describes. Assert at that production-visible layer.
                Err(error) => RuntimeError::from(error),
            };
            assert_eq!(error.to_string(), expected);
            let supplemental = take_native_test_supplemental_rollbacks();
            if all_classes_mapped {
                assert_supplemental_rollback_once(&planned, &supplemental);
                assert_native_ranges_vacant(planned.clone());
                assert_native_ranges_vacant(
                    owned
                        .into_iter()
                        .enumerate()
                        .map(|(index, range)| (format!("owned plan {index}"), range)),
                );
            } else {
                assert_native_ranges_vacant(planned.into_iter().take(1));
            }
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_mapping_second_region_failure_retires_ranges() {
        assert_prepared_mapping_failure_cleans_up(
            NativePreparedMappingFailpoint::SecondRegionMap,
            "unsupported in this backend: prepared-map: injected second-region mapping failure",
            false,
        );
    }

    #[test]
    fn native_prepared_mapping_relocation_failure_retires_ranges() {
        assert_prepared_mapping_failure_cleans_up(
            NativePreparedMappingFailpoint::Relocation,
            "unsupported in this backend: prepared-map: injected relocation failure",
            true,
        );
    }

    #[test]
    fn native_prepared_mapping_vvar_failure_retires_ranges() {
        assert_prepared_mapping_failure_cleans_up(
            NativePreparedMappingFailpoint::VvarStamp,
            "unsupported in this backend: prepared-map: injected vvar stamping failure",
            true,
        );
    }

    #[test]
    fn native_prepared_mapping_final_protection_failure_retires_ranges() {
        assert_prepared_mapping_failure_cleans_up(
            NativePreparedMappingFailpoint::FinalProtection,
            "unsupported in this backend: prepared-map: injected final protection failure",
            false,
        );
    }

    #[test]
    fn native_prepared_mapping_biased_layout_has_one_reservation_owner() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, plan) = native_biased_prepared_mapping_fixture();
            let layout = native_memory_layout();
            let selected =
                NativeLayout::for_image(&image, layout, plan.page_geometry.host_page_size)
                    .expect("select expected biased cleanup layout");
            assert!(matches!(
                selected.address_mode(),
                NativeAddressMode::Biased { .. }
            ));
            let planned = native_mapping_class_ranges(
                &image,
                layout,
                selected.address_mode(),
                plan.page_geometry.host_page_size,
            );
            let owned = selected.owned_ranges().to_vec();
            drop(selected);
            let validated =
                validated_prepared_mapping_fixture(&image, &[], plan.page_geometry.host_page_size);
            assert!(take_native_test_supplemental_rollbacks().is_empty());
            set_native_prepared_mapping_failpoint(Some(NativePreparedMappingFailpoint::VvarStamp));
            let error = match NativeMappedMemory::map_prepared_for_plan(
                &validated,
                layout,
                plan.page_geometry,
            ) {
                Ok(_) => panic!("biased late failpoint must fail"),
                // Wrap at the runtime's public boundary (see the shared helper)
                // so the assertion checks the guest-visible message.
                Err(error) => RuntimeError::from(error),
            };
            assert_eq!(
                error.to_string(),
                "unsupported in this backend: prepared-map: injected vvar stamping failure"
            );
            assert!(
                take_native_test_supplemental_rollbacks().is_empty(),
                "the biased aperture reservation must be the sole rollback owner"
            );
            assert_native_ranges_vacant(planned);
            assert_native_ranges_vacant(
                owned
                    .into_iter()
                    .enumerate()
                    .map(|(index, range)| (format!("biased owned plan {index}"), range)),
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_direct_exec_replacement_reservation_is_the_target_owner() {
        fork_test(|| {
            take_native_process_handoff_events();
            let plan = native16k_test_plan();
            let source = lifecycle_image(LifecycleImageKind::DirectPie, 0x31);
            let target = lifecycle_image_at(0x70_1000_0000, 0x72);
            let layout = native_memory_layout();
            let mut memory = NativeMappedMemory::map(
                &source,
                layout,
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map Direct replacement source");
            let prepared = memory
                .prepare_exec_mapping(&target, plan.page_geometry)
                .expect("reserve Direct replacement target");
            assert_eq!(
                prepared.native_layout.address_mode(),
                NativeAddressMode::Direct
            );
            assert!(
                !prepared.direct_target_reservations.is_empty(),
                "the disjoint Direct target must have an authoritative reservation"
            );
            let planned = native_mapping_class_ranges(
                &target,
                layout,
                prepared.native_layout.address_mode(),
                plan.page_geometry.host_page_size,
            );
            let owned = prepared.native_layout.owned_ranges().to_vec();
            let reserved_target = planned
                .iter()
                .find(|(name, _)| *name == "image")
                .expect("reserved target image range")
                .1
                .clone();
            assert!(take_native_test_supplemental_rollbacks().is_empty());
            NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.set(true));
            let (exec_thread, mut reset_token) = prepare_exec_reset_authority(&memory);
            let error = memory
                .replace_image(
                    &target,
                    &[],
                    plan.page_geometry,
                    &exec_thread,
                    &mut reset_token,
                    prepared,
                )
                .expect_err("Direct replacement late failpoint must fail");
            assert!(error.to_string().contains("injected native exec failure"));
            assert!(
                take_native_process_handoff_events().is_empty(),
                "post-retirement mapping failure published successful handoff metadata",
            );
            let supplemental = take_native_test_supplemental_rollbacks();
            assert!(
                supplemental.iter().all(|range| {
                    range.end.raw() <= reserved_target.start.raw()
                        || reserved_target.end.raw() <= range.start.raw()
                }),
                "DirectVmReservation must be the sole target owner: {supplemental:?}"
            );
            assert_native_ranges_vacant(planned);
            assert_native_ranges_vacant(
                owned
                    .into_iter()
                    .enumerate()
                    .map(|(index, range)| (format!("Direct exec owned plan {index}"), range)),
            );
        });
    }

    #[test]
    fn native_biased_exec_replacement_adopts_the_aperture_owner() {
        fork_test(|| {
            take_native_process_handoff_events();
            let plan = native16k_test_plan();
            let source = lifecycle_image(LifecycleImageKind::LowExec, 0x31);
            let target = lifecycle_image(LifecycleImageKind::LowExec, 0x72);
            let layout = native_memory_layout();
            let mut memory = NativeMappedMemory::map(
                &source,
                layout,
                plan.page_geometry.host_page_size,
                plan.page_geometry.linux_page_size,
            )
            .expect("map biased replacement source");
            let prepared = memory
                .prepare_exec_mapping(&target, plan.page_geometry)
                .expect("adopt biased replacement aperture");
            assert!(matches!(
                prepared.native_layout.address_mode(),
                NativeAddressMode::Biased { .. }
            ));
            assert!(prepared.direct_target_reservations.is_empty());
            let planned = native_mapping_class_ranges(
                &target,
                layout,
                prepared.native_layout.address_mode(),
                plan.page_geometry.host_page_size,
            );
            let owned = prepared.native_layout.owned_ranges().to_vec();
            assert!(take_native_test_supplemental_rollbacks().is_empty());
            NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.set(true));
            let (exec_thread, mut reset_token) = prepare_exec_reset_authority(&memory);
            let error = match memory.replace_image(
                &target,
                &[],
                plan.page_geometry,
                &exec_thread,
                &mut reset_token,
                prepared,
            ) {
                Ok(()) => panic!("biased replacement late failpoint must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("injected native exec failure"));
            assert!(
                take_native_process_handoff_events().is_empty(),
                "post-retirement biased mapping failure published successful handoff metadata",
            );
            assert!(
                take_native_test_supplemental_rollbacks().is_empty(),
                "the adopted biased aperture must be the sole rollback owner"
            );
            assert_native_ranges_vacant(planned);
            assert_native_ranges_vacant(
                owned
                    .into_iter()
                    .enumerate()
                    .map(|(index, range)| (format!("biased exec owned plan {index}"), range)),
            );
        });
    }

    fn native_prepared_resume_source(path: &Path, marker: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let source = path.join(format!("source-{marker:08x}"));
        std::fs::write(&source, dsr_test_elf(&[marker])).expect("write resume source ELF");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
            .expect("make resume source executable");
        source
    }

    fn native_prepared_resume_load(
        dispatcher: &SyscallDispatcher,
        path: &Path,
        plan: &ExecutionPlan,
    ) -> LoadedNativeExecveImage {
        load_native_execve_image(
            dispatcher,
            path.to_str().expect("UTF-8 resume path"),
            vec![path.as_os_str().as_encoded_bytes().to_vec()],
            Vec::new(),
            plan,
        )
        .expect("load native resume fixture")
    }

    fn native_prepared_resume_record(
        image: &AddressSpace,
        relocations: &[NativeRelativeRelocation],
        host_page_size: u64,
    ) -> crate::native_prepared_image::NativePreparedImageV1 {
        let artifact =
            match crate::native_prepared_image::prepare(image, relocations, host_page_size)
                .expect("prepare resume artifact")
            {
                crate::native_prepared_image::PreparedImageDisposition::Prepared(artifact) => {
                    artifact
                }
                crate::native_prepared_image::PreparedImageDisposition::Ineligible(reason) => {
                    panic!("resume fixture is ineligible: {reason:?}")
                }
            };
        crate::native_prepared_image::resume_record_for_test(artifact)
            .expect("create inherited resume record")
    }

    #[test]
    fn native_prepared_resume_some_skips_legacy_loader() {
        let (image, relocations, plan) = native_prepared_mapping_fixture(false);
        let record =
            native_prepared_resume_record(&image, &relocations, plan.page_geometry.host_page_size);
        let loader_calls = Cell::new(0_u32);
        let resumed = select_resumed_image(Some(record), [0; 32], || {
            loader_calls.set(loader_calls.get() + 1);
            Err(crate::linux_abi::LINUX_EIO)
        })
        .expect("select prepared image");

        assert!(matches!(resumed.source, NativeImageSource::Prepared(_)));
        assert_eq!(loader_calls.get(), 0);
    }

    #[test]
    fn native_prepared_resume_none_uses_legacy_loader_and_digest() {
        let temp = tempfile::tempdir().expect("create resume tempdir");
        let path = native_prepared_resume_source(temp.path(), 0xd65f_03c0);
        let dispatcher = SyscallDispatcher::new();
        let plan = native16k_test_plan();
        let loaded = native_prepared_resume_load(&dispatcher, &path, &plan);
        let expected_digest = loaded.4;
        let loader_calls = Cell::new(0_u32);
        let resumed = select_resumed_image(None, expected_digest, || {
            loader_calls.set(loader_calls.get() + 1);
            Ok(loaded)
        })
        .expect("select legacy image");

        assert!(matches!(resumed.source, NativeImageSource::Legacy { .. }));
        assert_eq!(loader_calls.get(), 1);
    }

    #[test]
    fn prepared_and_legacy_resume_select_identical_guest_image_compatibility() {
        let temp = tempfile::tempdir().expect("create resume tempdir");
        let path = native_prepared_resume_source(temp.path(), 0xd65f_03c0);
        let resolved_path = path.to_str().expect("UTF-8 resume path");
        let dispatcher = SyscallDispatcher::new();
        let plan = native16k_test_plan();
        let prepared_load = native_prepared_resume_load(&dispatcher, &path, &plan);
        let record = native_prepared_resume_record(
            &prepared_load.0,
            &prepared_load.1,
            plan.page_geometry.host_page_size,
        );
        let expected_digest = prepared_load.4;
        let prepared = select_resumed_image(Some(record), expected_digest, || {
            Err(crate::linux_abi::LINUX_EIO)
        })
        .expect("select prepared image");
        let (_, prepared_compatibility) = prepared.into_handoff(resolved_path.to_owned());

        let legacy_load = native_prepared_resume_load(&dispatcher, &path, &plan);
        let legacy = select_resumed_image(None, expected_digest, || Ok(legacy_load))
            .expect("select legacy image");
        let (_, legacy_compatibility) = legacy.into_handoff("ignored-fallback".to_owned());

        assert_eq!(prepared_compatibility, legacy_compatibility);
        assert_eq!(prepared_compatibility.resolved_path.as_str(), resolved_path);
        assert_eq!(prepared_compatibility.entry, prepared_load.0.entry());
        assert_eq!(
            prepared_compatibility.base,
            prepared_load
                .0
                .regions()
                .iter()
                .map(|region| region.start)
                .min()
                .unwrap_or(0),
        );
    }

    #[test]
    fn native_prepared_resume_ignores_changed_source_path() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let temp = tempfile::tempdir().expect("create substitution tempdir");
            let path = native_prepared_resume_source(temp.path(), 0xd65f_03c0);
            let dispatcher = SyscallDispatcher::new();
            let plan = native16k_test_plan();
            let loaded_a = native_prepared_resume_load(&dispatcher, &path, &plan);
            let entry = loaded_a.0.entry();
            let record = native_prepared_resume_record(
                &loaded_a.0,
                &loaded_a.1,
                plan.page_geometry.host_page_size,
            );
            let replacement = native_prepared_resume_source(temp.path(), 0xd503_201f);
            std::fs::rename(&replacement, &path).expect("atomically replace executable source");
            let loader_calls = Cell::new(0_u32);
            let resumed = select_resumed_image(Some(record), loaded_a.4, || {
                loader_calls.set(loader_calls.get() + 1);
                Ok(native_prepared_resume_load(&dispatcher, &path, &plan))
            })
            .expect("select exact prepared bytes");
            let artifact_fd = match &resumed.source {
                NativeImageSource::Prepared(prepared) => prepared.file_fd(),
                NativeImageSource::Legacy { .. } => panic!("expected prepared source"),
            };
            let (memory, _image) = map_and_release_native_image_source(resumed.source, &plan)
                .expect("map exact prepared bytes");

            assert_eq!(loader_calls.get(), 0);
            assert_eq!(unsafe { libc::fcntl(artifact_fd, libc::F_GETFD) }, -1);
            assert_eq!(
                memory.read_bytes(entry, 4).expect("read prepared marker"),
                0xd65f_03c0_u32.to_le_bytes()
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_resume_corruption_is_fatal_without_legacy_loader() {
        use std::os::unix::fs::FileExt;

        let (image, relocations, plan) = native_prepared_mapping_fixture(false);
        let artifact = match crate::native_prepared_image::prepare(
            &image,
            &relocations,
            plan.page_geometry.host_page_size,
        )
        .expect("prepare corruption artifact")
        {
            crate::native_prepared_image::PreparedImageDisposition::Prepared(artifact) => artifact,
            crate::native_prepared_image::PreparedImageDisposition::Ineligible(reason) => {
                panic!("corruption fixture is ineligible: {reason:?}")
            }
        };
        artifact
            .file
            .write_all_at(&[0], 0)
            .expect("corrupt first initialized artifact byte");
        let record = crate::native_prepared_image::resume_record_for_test(artifact)
            .expect("create corrupt inherited record");
        let loader_calls = Cell::new(0_u32);
        let error = match select_resumed_image(Some(record), [0; 32], || {
            loader_calls.set(loader_calls.get() + 1);
            Err(crate::linux_abi::LINUX_EIO)
        }) {
            Ok(_) => panic!("corrupt prepared image must be fatal"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "prepared-validate: checksum mismatch");
        assert_eq!(loader_calls.get(), 0);
    }

    #[test]
    fn native_prepared_resume_mapping_failure_is_fatal_without_legacy_loader() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(false);
            let record = native_prepared_resume_record(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            let loader_calls = Cell::new(0_u32);
            let resumed = select_resumed_image(Some(record), [0; 32], || {
                loader_calls.set(loader_calls.get() + 1);
                Err(crate::linux_abi::LINUX_EIO)
            })
            .expect("select prepared image before injected map failure");
            set_native_prepared_mapping_failpoint(Some(
                NativePreparedMappingFailpoint::SecondRegionMap,
            ));
            let artifact_fd = match &resumed.source {
                NativeImageSource::Prepared(prepared) => prepared.file_fd(),
                NativeImageSource::Legacy { .. } => panic!("expected prepared source"),
            };
            let error = match map_and_release_native_image_source(resumed.source, &plan) {
                Ok(_) => panic!("prepared mapping failure must be fatal"),
                Err(error) => error,
            };

            assert_eq!(
                error.to_string(),
                "unsupported in this backend: prepared-map: injected second-region mapping failure"
            );
            assert_eq!(loader_calls.get(), 0);
            assert_eq!(unsafe { libc::fcntl(artifact_fd, libc::F_GETFD) }, -1);
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_resume_lifecycle_nests_validate_and_map_before_restore_close() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(false);
            let record = native_prepared_resume_record(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            set_native_reexec_lifecycle_capture(true);
            let resumed =
                select_resumed_image(Some(record), [0; 32], || Err(crate::linux_abi::LINUX_EIO))
                    .expect("select prepared image");
            let _mapped = map_current_process_image_source(
                resumed.source,
                &plan,
                NativeCurrentProcessEntry::SelfReexecRestore,
            )
            .expect("map prepared image");
            assert_eq!(
                take_native_reexec_lifecycle_capture(),
                vec![
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateBegin,
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateEnd,
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecGuestEntry,
                ]
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_initial_mapping_does_not_close_self_reexec_restore() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relative_relocations, plan) = native_prepared_mapping_fixture(false);
            set_native_reexec_lifecycle_capture(true);
            let _mapped = map_current_process_image_source(
                NativeImageSource::Legacy {
                    image,
                    relative_relocations,
                },
                &plan,
                NativeCurrentProcessEntry::Initial,
            )
            .expect("map initial image");

            assert_eq!(take_native_reexec_lifecycle_capture(), Vec::new());
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_map_phase_is_incomplete_on_second_extent_failure() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(false);
            let validated = validated_prepared_mapping_fixture(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            set_native_prepared_mapping_failpoint(Some(
                NativePreparedMappingFailpoint::SecondRegionMap,
            ));
            set_native_reexec_lifecycle_capture(true);
            assert!(
                NativeMappedMemory::map_prepared_for_plan(
                    &validated,
                    native_memory_layout(),
                    plan.page_geometry,
                )
                .is_err()
            );
            assert_eq!(
                take_native_reexec_lifecycle_capture(),
                vec![carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin]
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_map_phase_completes_before_late_finalization_failure() {
        fork_test(|| {
            set_native_test_vvar_words(Some(Vec::new()));
            let (image, relocations, plan) = native_prepared_mapping_fixture(false);
            let validated = validated_prepared_mapping_fixture(
                &image,
                &relocations,
                plan.page_geometry.host_page_size,
            );
            set_native_prepared_mapping_failpoint(Some(
                NativePreparedMappingFailpoint::FinalProtection,
            ));
            set_native_reexec_lifecycle_capture(true);
            assert!(
                NativeMappedMemory::map_prepared_for_plan(
                    &validated,
                    native_memory_layout(),
                    plan.page_geometry,
                )
                .is_err()
            );
            assert_eq!(
                take_native_reexec_lifecycle_capture(),
                vec![
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                    carrick_dsr::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
                ]
            );
            set_native_test_vvar_words(None);
        });
    }

    #[test]
    fn native_prepared_resume_legacy_detects_changed_source_digest() {
        let temp = tempfile::tempdir().expect("create legacy-control tempdir");
        let path = native_prepared_resume_source(temp.path(), 0xd65f_03c0);
        let dispatcher = SyscallDispatcher::new();
        let plan = native16k_test_plan();
        let loaded_a = native_prepared_resume_load(&dispatcher, &path, &plan);
        let replacement = native_prepared_resume_source(temp.path(), 0xd503_201f);
        std::fs::rename(&replacement, &path).expect("atomically replace legacy source");
        let loader_calls = Cell::new(0_u32);
        let error = match select_resumed_image(None, loaded_a.4, || {
            loader_calls.set(loader_calls.get() + 1);
            Ok(native_prepared_resume_load(&dispatcher, &path, &plan))
        }) {
            Ok(_) => panic!("legacy substitution must fail digest validation"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "guest executable changed across native host self-reexec"
        );
        assert_eq!(loader_calls.get(), 1);
    }
}
