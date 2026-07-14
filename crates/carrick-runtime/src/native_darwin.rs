//! Darwin-native execution backend.
//!
//! Same-ISA Linux ELFs are loaded into a forked host child and execute only as
//! DSR-translated native code. DSR gateways dispatch Linux syscalls through the
//! existing syscall layer; guest code is never executed directly. OCI/container
//! setup is shared with the other runtime backends, while this module owns image
//! loading and the native run loop. Unsupported dispatcher outcomes fail
//! explicitly rather than falling back to HVF.

mod address;
mod dsr;

use address::{NativeAddressMode, NativeLayout};

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::compat::{CompatReport, CompatReporter, SyscallArgs};
use crate::dispatch::{
    DispatchOutcome, GuestMemory, HostSyscallResult, MemoryError, MemoryLayout, SyscallDispatcher,
    SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError, MemoryRegion};
use crate::native_prepared_image::{
    NativeRelativeRelocation, PreparedImageFileBacking, ValidatedPreparedImage,
    native_region_copy_window,
};
use crate::page_profile::{
    ExecutionPlan, HostPageState, MixedPageReason, PageBacking, PagePerms, SubpageState,
    classify_host_page_state,
};
use crate::runtime::{RunResult, RuntimeError, maybe_dump_debug_state};
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
const NATIVE_DC_ZVA_BLOCK_SIZE: usize = 64;
const NATIVE_DARWIN_PIE_BASE: u64 = 0x4_0000_0000;
const NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE: u64 = 0x7_0000_0000;
const NATIVE_DARWIN_HEAP_BASE: u64 = 0x8_0000_0000;
const NATIVE_DARWIN_HEAP_SIZE: u64 = 128 * 1024 * 1024;
// Darwin places randomized malloc zones in 0x70_0000_0000..0x80_0000_0000.
// MAP_FIXED would silently replace them, corrupting the host process. Keep the
// native direct-mapped arena above Carrick's shared/private aperture windows.
const NATIVE_DARWIN_MMAP_BASE: u64 = 0xa0_0000_0000;
const NATIVE_DARWIN_MMAP_SIZE: u64 = 32 * 1024 * 1024 * 1024;
// The canonical Linux vvar/vdso VAs (0x2E_0000_0000/0x2E_0001_0000) sit inside
// a Darwin-reserved host VA hole: mmap(MAP_FIXED) and mach_vm_allocate refuse
// [63 GiB, 448 GiB) with EACCES/KERN_NO_SPACE in any Darwin process (measured
// on macOS 27, entitlements make no difference), and native guest VAs ARE host
// VAs. Relocate both pages by +512 GiB into the proven-mappable high span the
// other native windows already occupy (above the 0x70..0x80 GiB*4 randomized
// malloc zones, disjoint from the 0x90/0x98 apertures, the 0xA0..0xA8 mmap
// arena, and the ~1 TiB stack). The vvar base must stay a multiple of 1<<32
// whose high half fits one `movz #imm16, lsl #32` — the injected vDSO page's
// hardcoded vvar loads are rewritten to it at map time.
const NATIVE_DARWIN_VVAR_BASE: u64 = carrick_mem::vdso::LINUX_VVAR_BASE + (0x80 << 32);
const NATIVE_DARWIN_VDSO_BASE: u64 = carrick_mem::vdso::LINUX_VDSO_BASE + (0x80 << 32);
const _: () = assert!(NATIVE_DARWIN_VVAR_BASE & ((1 << 32) - 1) == 0);
const _: () = assert!(NATIVE_DARWIN_VVAR_BASE >> 32 <= u16::MAX as u64);
const _: () = assert!(carrick_mem::vdso::LINUX_VVAR_BASE & ((1 << 32) - 1) == 0);
const NATIVE_DARWIN_HARD_PAGEZERO_END: u64 = 0x1_0000_0000;

/// True in a host process created by a GUEST `fork` (not the run-elf root
/// child, which the CLI forks for isolation). Guest-forked children must exit
/// through `exec_helpers::forked_child_exit` so their guest CPU is published
/// for the parent's wait4/waitid child-time accounting (the HVF loop's
/// `is_forked_guest_process` branch); the root child's exit is reported to the
/// CLI, which does no such accounting. Survives execve (same host process).
static NATIVE_FORKED_GUEST_CHILD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    static NATIVE_TEST_FAIL_EXEC_AFTER_SETUP: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static NATIVE_TEST_PREPARED_MAPPING_FAILPOINT:
        std::cell::Cell<Option<NativePreparedMappingFailpoint>> = const {
            std::cell::Cell::new(None)
        };
    static NATIVE_TEST_VVAR_WORDS:
        std::cell::RefCell<Option<Vec<(usize, u64)>>> = const {
            std::cell::RefCell::new(None)
        };
    static NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS:
        std::cell::RefCell<Vec<std::ops::Range<carrick_guest_mem::HostVa>>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    static NATIVE_TEST_REEXEC_LIFECYCLE:
        std::cell::RefCell<Option<Vec<crate::probes::DsrCacheLifecyclePhase>>> = const {
            std::cell::RefCell::new(None)
        };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativePreparedMappingFailpoint {
    SecondRegionMap,
    Relocation,
    VvarStamp,
    FinalProtection,
}

#[cfg(test)]
fn set_native_prepared_mapping_failpoint(failpoint: Option<NativePreparedMappingFailpoint>) {
    NATIVE_TEST_PREPARED_MAPPING_FAILPOINT.with(|slot| slot.set(failpoint));
}

#[cfg(test)]
fn take_native_prepared_mapping_failpoint(failpoint: NativePreparedMappingFailpoint) -> bool {
    NATIVE_TEST_PREPARED_MAPPING_FAILPOINT.with(|slot| {
        if slot.get() == Some(failpoint) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn set_native_test_vvar_words(words: Option<Vec<(usize, u64)>>) {
    NATIVE_TEST_VVAR_WORDS.with(|slot| *slot.borrow_mut() = words);
}

#[cfg(test)]
fn take_native_test_supplemental_rollbacks() -> Vec<std::ops::Range<carrick_guest_mem::HostVa>> {
    NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

#[cfg(test)]
fn set_native_reexec_lifecycle_capture(enabled: bool) {
    NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| {
        *slot.borrow_mut() = enabled.then(Vec::new);
    });
}

#[cfg(test)]
fn take_native_reexec_lifecycle_capture() -> Vec<crate::probes::DsrCacheLifecyclePhase> {
    NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| slot.borrow_mut().take().unwrap_or_default())
}

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

const VM_INHERIT_SHARE: libc::c_int = 0;
const VM_INHERIT_COPY: libc::c_int = 1;

type SharedNativeMemory = Arc<parking_lot::Mutex<NativeMappedMemory>>;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeUcontextSnapshot {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    v: [[u8; 16]; 32],
    fpsr: u32,
    fpcr: u32,
    event_kind: i32,
    signal: libc::c_int,
    signal_code: libc::c_int,
    fault_address: u64,
    esr: u64,
    far: u64,
}

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
struct TimedDispatchOutcome {
    outcome: DispatchOutcome,
    blocked_ns: u64,
}

struct NativeForkRequest {
    pidfd_out: Option<u64>,
    clone_parent: bool,
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    exit_signal: u32,
    child_stack: u64,
    vfork: Option<u64>,
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

    #[cfg(test)]
    fn requested_generation(&self) -> u64 {
        unsafe { carrick_native_kick_state_requested(self.raw.as_ptr()) }
    }

    #[cfg(test)]
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
    fn carrick_native_clear_icache(start: *mut libc::c_void, len: usize);
}

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

    run_image_in_child(image, dispatcher, max_traps, relative_relocations, plan)
}

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

    run_image_in_child(image, dispatcher, max_traps, relative_relocations, plan)
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
            crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateBegin,
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
            crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateEnd,
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
    native_reexec_lifecycle(crate::probes::DsrCacheLifecyclePhase::HostSelfReexecDispatcherReady);
    let prepared_image = guest.prepared_image.take();
    let resumed = select_resumed_image(prepared_image, guest.executable_digest, || {
        native_reexec_lifecycle(
            crate::probes::DsrCacheLifecyclePhase::HostSelfReexecImageLoadBegin,
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
                crate::probes::DsrCacheLifecyclePhase::HostSelfReexecImageLoadEnd,
            );
        }
        loaded
    })?;
    let resolved = resumed
        .legacy_resolved_path
        .clone()
        .unwrap_or_else(|| guest.resolved_path.clone());
    native_reexec_lifecycle(crate::probes::DsrCacheLifecyclePhase::HostSelfReexecResetBegin);
    dispatcher.reset_memory_state_on_execve();
    dispatcher.reset_signal_handlers_on_execve();
    dispatcher.set_executable_identity(
        resolved,
        argv.iter()
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect(),
        env,
    );
    // The ordinary in-process exec path reports this boundary after publishing
    // the new image. Host self-reexec must do the same before the restored image
    // executes its first instruction; otherwise PTRACE_TRACEME silently vanishes
    // across the transport even though the typed state itself was restored.
    crate::exec_helpers::stop_after_traced_exec(&dispatcher);
    native_reexec_lifecycle(crate::probes::DsrCacheLifecyclePhase::HostSelfReexecResetEnd);
    run_image_in_current_process(
        resumed.source,
        dispatcher,
        max_traps,
        &plan,
        NativeCurrentProcessEntry::SelfReexecRestore,
    )
    .map_err(anyhow::Error::from)
}

fn native_reexec_lifecycle(phase: crate::probes::DsrCacheLifecyclePhase) {
    #[cfg(test)]
    NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| {
        if let Some(phases) = slot.borrow_mut().as_mut() {
            phases.push(phase);
        }
    });
    let tid = unsafe { libc::getpid() };
    crate::probes::dsr_cache_lifecycle(tid, phase, 0, 0, 0);
}

fn native_memory_layout() -> MemoryLayout {
    MemoryLayout {
        heap_base: NATIVE_DARWIN_HEAP_BASE,
        heap_size: NATIVE_DARWIN_HEAP_SIZE,
        mmap_base: NATIVE_DARWIN_MMAP_BASE,
        mmap_size: NATIVE_DARWIN_MMAP_SIZE,
    }
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
    let (_, freq) = crate::trap::host_counter();
    (freq, crate::trap::host_clock_uptime_ns())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn native_vvar_clock_sources() -> (u64, u64) {
    (0, 0)
}

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

fn checked_add_u64(a: u64, b: u64, context: &str) -> Result<u64, RuntimeError> {
    a.checked_add(b).ok_or_else(|| {
        RuntimeError::Unsupported(format!("native Darwin {context} overflow: 0x{a:x}+0x{b:x}"))
    })
}

fn align_up_u64(value: u64, align: u64, context: &str) -> Result<u64, RuntimeError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin {context} invalid alignment: {align}"
        )));
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin {context} overflow: 0x{value:x} align 0x{align:x}"
            ))
        })
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

fn apply_native_relative_relocations(
    memory: &mut NativeMappedMemory,
    relocations: &[NativeRelativeRelocation],
) -> Result<(), RuntimeError> {
    for relocation in relocations {
        memory.write_u64(relocation.address().get(), relocation.value().get())?;
    }
    Ok(())
}

fn run_image_in_child(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    relative_relocations: Vec<NativeRelativeRelocation>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError> {
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

        match run_image_in_current_process(
            NativeImageSource::Legacy {
                image,
                relative_relocations,
            },
            dispatcher,
            max_traps,
            plan,
            NativeCurrentProcessEntry::Initial,
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
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    plan: &ExecutionPlan,
    process_entry: NativeCurrentProcessEntry,
) -> Result<i32, RuntimeError> {
    let initial_sp = source.image().initial_stack_pointer().ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin image has no initial stack".to_string())
    })?;
    let entry = source.image().entry();
    let (memory, image) = map_current_process_image_source(source, plan, process_entry)?;
    let memory = Arc::new(parking_lot::Mutex::new(memory));
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
        NativeThreadStart::Initial { entry, initial_sp },
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
        } => NativeMappedMemory::map_for_plan(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            plan.page_geometry.linux_page_size,
            plan,
            relative_relocations,
        ),
        NativeImageSource::Prepared(prepared) => {
            NativeMappedMemory::map_prepared_for_plan(prepared, native_memory_layout(), plan)
        }
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
        native_reexec_lifecycle(crate::probes::DsrCacheLifecyclePhase::HostSelfReexecGuestEntry);
    }
    Ok(mapped)
}

enum NativeThreadStart {
    Initial {
        entry: u64,
        initial_sp: u64,
    },
    Detached {
        context: Box<NativeUcontextSnapshot>,
        guest_tpidr_el0: u64,
    },
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
}

/// Outcome of [`NativeThreadRuntime::acquire_fork_token`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeForkTokenFlow {
    Acquired,
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
    let mut memory = memory.lock();
    memory
        .prepare_dsr_execution(snapshot.pc)
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
    let mut guest_tpidr_el0 = match &start {
        NativeThreadStart::Initial { .. } => 0,
        NativeThreadStart::Detached {
            guest_tpidr_el0, ..
        } => *guest_tpidr_el0,
    };
    let mut snapshot = match start {
        NativeThreadStart::Initial { entry, initial_sp } => NativeUcontextSnapshot {
            sp: initial_sp,
            pc: entry,
            ..NativeUcontextSnapshot::default()
        },
        NativeThreadStart::Detached { context, .. } => *context,
    };
    let process_translator = memory.lock().dsr_process_translator()?;
    let mut translator =
        dsr::ThreadTranslator::for_process(process_translator, thread_runtime.tid().raw());
    debug_assert_eq!(translator.profiling_enabled(), PROFILE);
    let prepare: DsrPrepareFn = prepare_dsr_entry::<PROFILE>;
    let enter: DsrEnterFn = enter_dsr_prepared::<PROFILE>;
    let trace_syscalls = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
    let mut vfork_completion: Option<NativeVforkCompletion> = None;
    let mut traps = 0_usize;

    loop {
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
            .finish_exit_profiled::<PROFILE>(&memory.lock(), &mut snapshot, prepared, raw_exit)
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
                            &mut memory.lock(),
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
                        native_dc_zva(&mut memory.lock(), address)?;
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
                    kind,
                    address,
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
            let active_dispatch_ns = match dispatch_ns.checked_sub(timed_outcome.blocked_ns) {
                Some(active_dispatch_ns) => active_dispatch_ns,
                None => {
                    let error = translator
                        .invalidate_profile(dsr::profile::ProfileError::DispatchTimeUnderflow);
                    return Err(RuntimeError::Unsupported(error.to_string()));
                }
            };
            translator
                .add_profile_phase_ns(dsr::profile::Phase::Blocked, timed_outcome.blocked_ns)
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
                )?;
            }
            DispatchOutcome::SigReturn => {
                snapshot =
                    complete_dsr_sigreturn(&dispatcher, &memory, snapshot, thread_runtime.tid())?;
            }
            DispatchOutcome::Exit { code } => {
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
                if thread_runtime.finish_thread(&dispatcher, &memory) {
                    return Ok(NativeThreadLoopOutcome::ProcessExit(code));
                }
                return Ok(NativeThreadLoopOutcome::ThreadDone);
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
                    )?;
                    continue;
                }
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
                    .then(|| memory.lock().native16k_vfork_rejection())
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
                };
                match handle_native_fork(
                    &dispatcher,
                    &memory,
                    thread_runtime,
                    &mut vfork_completion,
                    fork_request,
                )? {
                    NativeForkFlow::Resume {
                        value,
                        fork_child,
                        child_stack,
                    } => {
                        if fork_child {
                            translator.after_fork_child(thread_runtime.tid().raw());
                            if child_stack != 0 {
                                snapshot.sp = child_stack;
                            }
                        }
                        snapshot = complete_dsr_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            thread_runtime.tid(),
                            syscall_nr,
                            value,
                            resume,
                        )?;
                    }
                    NativeForkFlow::RetireForExec => {
                        if thread_runtime.finish_thread(&dispatcher, &memory) {
                            return Ok(NativeThreadLoopOutcome::ProcessExit(0));
                        }
                        return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
                    }
                }
            }
            DispatchOutcome::Execve { path, argv, env } => {
                if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire) {
                    native_reexec_lifecycle(
                        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreflightBegin,
                    );
                }
                let capsule_env = env.clone();
                let proc_argv: Vec<String> = argv
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect();
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
                                )?;
                                continue;
                            }
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
                                )?;
                                continue;
                            }
                            return Err(RuntimeError::Unsupported(
                                "native host self-reexec unexpectedly returned successfully"
                                    .to_owned(),
                            ));
                        }
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
                            )?;
                            continue;
                        };
                        // Select and reserve the replacement host layout and
                        // allocate its translator before Linux's point of no
                        // return. A collision or allocation failure leaves the
                        // old image, sibling set, dispatcher, and DSR cache live.
                        let prepared_mapping = {
                            let memory = memory.lock();
                            memory.prepare_exec_mapping(&image, &plan)
                        };
                        let prepared_mapping = match prepared_mapping {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    path = resolved,
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
                                    return Ok(NativeThreadLoopOutcome::ProcessExit(0));
                                }
                                return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
                            }
                        }
                        memory
                            .lock()
                            .replace_image(
                                &image,
                                &relative_relocations,
                                &plan,
                                Some(thread_runtime.tid()),
                                prepared_mapping,
                            )
                            .map_err(|error| {
                                RuntimeError::Trap(TrapError::Hypervisor(format!(
                                    "native execve failed after retiring the old owned address space: {error}"
                                )))
                            })?;
                        // Publish process-visible exec state only after the
                        // complete replacement mapping, vvar, relocations, and
                        // translator allocation have succeeded. Before this
                        // point a validation failure returned to the old image;
                        // after retirement, failure is fatal and no partial
                        // dispatcher identity may escape.
                        dispatcher.reset_memory_state_on_execve();
                        dispatcher.reset_signal_handlers_on_execve();
                        dispatcher.set_executable_identity(
                            resolved.clone(),
                            proc_argv.clone(),
                            proc_env,
                        );
                        crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
                        dispatcher.close_cloexec_fds();
                        translator.begin_exec_reset();
                        translator.begin_exec_handoff();
                        let next_process = memory.lock().dsr_process_translator()?;
                        translator.reset_for_exec(next_process);
                        crate::namespace::pid::mark_self_execed();
                        let cmdline = proc_argv.join(" ");
                        crate::dispatch::set_host_process_name(cmdline.as_bytes());
                        if let Some(mut completion) = vfork_completion.take() {
                            completion.notify();
                        }
                        guest_tpidr_el0 = 0;
                        snapshot = NativeUcontextSnapshot {
                            sp: initial_sp,
                            pc: entry,
                            ..NativeUcontextSnapshot::default()
                        };
                        crate::exec_helpers::stop_after_traced_exec(&dispatcher);
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
                        )?;
                    }
                }
            }
            DispatchOutcome::MapHostAlias {
                va,
                ipa: _,
                len,
                payload,
                file,
                prot_none,
            } => {
                memory
                    .lock()
                    .map_host_alias(va.raw(), len, &payload, file, prot_none)?;
                snapshot = complete_dsr_syscall(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    request.number.raw(),
                    va.raw() as i64,
                    resume,
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
                )?;
            }
            DispatchOutcome::SignalDeath { signum } => {
                native_die_by_signal(&dispatcher, signum);
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
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let mut memory = memory.lock();
    let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
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
            native_die_by_signal(dispatcher, signum);
        }
    }
    Ok(trap.into_snapshot())
}

fn complete_dsr_syscall(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    syscall_nr: u64,
    return_value: i64,
    resume: carrick_guest_mem::GuestVa,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let mut memory = memory.lock();
    let mut trap = NativeSignalTrap::new(&mut memory, snapshot, Some(syscall_nr));
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
            native_die_by_signal(dispatcher, signum);
        }
    }
    Ok(trap.into_snapshot())
}

fn complete_dsr_sigreturn(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let mut memory = memory.lock();
    let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
    let action = sigreturn_restore_and_deliver(dispatcher, &mut trap, tid)?;
    if let Some(action) = action {
        if let Some(signum) = action.stop_signal {
            crate::exec_helpers::stop_by_signal(signum);
        }
        if let Some(signum) = action.term_signal {
            native_die_by_signal(dispatcher, signum);
        }
    }
    Ok(trap.into_snapshot())
}

fn lower_dsr_fault(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    mut snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    live_threads: usize,
    fault: dsr::ThreadFault,
    fault_address: dsr::ThreadFaultAddress,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let host_fault = matches!(fault_address, dsr::ThreadFaultAddress::Host(_));
    let biased_host_fault = host_fault
        && matches!(
            memory.lock().address_mode(),
            NativeAddressMode::Biased { .. }
        );
    let fault_address = lower_dsr_fault_address(&memory.lock(), fault_address)?.raw();
    if biased_host_fault {
        let memory = memory.lock();
        if snapshot.far != 0 {
            let far = usize::try_from(snapshot.far)
                .ok()
                .and_then(|far| memory.guest_fault_address(carrick_guest_mem::HostVa(far)));
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
                .and_then(|address| memory.guest_fault_address(carrick_guest_mem::HostVa(address)));
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
        && let Some((page, prot)) = dispatcher.resident_fault_plan(fault_address)
    {
        let mut memory = memory.lock();
        let linux_page_size = memory.linux_page_size as usize;
        if memory.protect_range(page, linux_page_size, prot).is_ok() {
            drop(memory);
            dispatcher.commit_resident_fault(page);
            return Ok(snapshot);
        }
    }
    if matches!(fault, dsr::ThreadFault::Host { .. })
        && memory.lock().resolve_native16k_write_exec_fault(
            fault_address,
            snapshot.pc,
            snapshot.esr,
        )?
    {
        return Ok(snapshot);
    }
    if matches!(fault, dsr::ThreadFault::Host { .. })
        && memory.lock().linux4k_address_is_guarded(fault_address)
    {
        if live_threads > 1 {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded-page access at 0x{fault_address:x} from a \
                 multithreaded guest is not yet supported: the 4K-on-16K \
                 guarded-page fault emulation is not multithread-safe"
            )));
        }
        emulate_linux4k_guarded_fault(&mut memory.lock(), &mut snapshot)?;
        return Ok(snapshot);
    }
    let (mut signum, mut si_code, si_addr) = match fault {
        dsr::ThreadFault::Guest { signum, code } => (signum, code, fault_address),
        dsr::ThreadFault::Host { .. } => {
            let Some(lowered) =
                crate::vcpu_loop::lower_el0_fault(snapshot.esr, snapshot.pc, fault_address)
            else {
                native_die_by_signal(dispatcher, crate::linux_abi::LINUX_SIGSEGV);
            };
            lowered
        }
    };
    si_code = {
        let memory = memory.lock();
        crate::vcpu_loop::upgrade_protection_si_code(&*memory, signum, si_code, si_addr)
    };
    if signum == crate::linux_abi::LINUX_SIGSEGV
        && let Some((grow_start, grow_len)) = dispatcher.mmap_growdown_fault_plan(si_addr)
    {
        let grew = memory
            .lock()
            .protect_range(
                grow_start,
                grow_len,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            )
            .is_ok();
        if grew {
            dispatcher.commit_mmap_growdown(grow_start);
            return Ok(snapshot);
        }
    }
    if signum == crate::linux_abi::LINUX_SIGSEGV && dispatcher.mmap_fault_is_sigbus(si_addr) {
        signum = crate::linux_abi::LINUX_SIGBUS;
        si_code = 2;
    }
    let interrupted_pc = snapshot.pc;
    let mut memory = memory.lock();
    let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
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
            native_die_by_signal(dispatcher, signum)
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

fn native_die_by_signal(dispatcher: &SyscallDispatcher, signum: i32) -> ! {
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
    memory: &'a mut NativeMappedMemory,
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
        while !crate::fork_quiesce::barrier().try_begin_fork() {
            if crate::fork_quiesce::exec_replacing_other_thread(self.tid) {
                return NativeForkTokenFlow::RetireForExec;
            }
            self.park_for_fork_quiesce();
            if Instant::now() >= deadline {
                return NativeForkTokenFlow::TimedOut;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        NativeForkTokenFlow::Acquired
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
            let mut memory = memory.lock();
            if request.parent_tid_addr != 0 {
                let _ = memory.write_bytes(request.parent_tid_addr, &tid_bytes);
            }
            if request.child_tid_addr != 0 {
                let _ = memory.write_bytes(request.child_tid_addr, &tid_bytes);
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
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let spawn_result = std::thread::Builder::new()
            .name(format!("native-guest-tid-{tid}"))
            .spawn(move || {
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
            {
                let mut memory = memory.lock();
                let _ = memory.write_bytes(address, &0_i32.to_le_bytes());
            }
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
        memory: &'a mut NativeMappedMemory,
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
        self.memory.write_bytes_raw(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bytes_raw(address, bytes)
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
    let mut blocked_ns = 0;
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
        blocked_ns,
    })
}

fn measure_native_blocked<const PROFILE: bool, T>(
    blocked_ns: &mut u64,
    operation: impl FnOnce() -> T,
) -> Result<T, RuntimeError> {
    if !PROFILE {
        return Ok(operation());
    }
    let timer = dsr::profile::PhaseTimer::start_if::<PROFILE>();
    let result = operation();
    let elapsed_ns = timer
        .elapsed_ns()
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    *blocked_ns = blocked_ns.checked_add(elapsed_ns).ok_or_else(|| {
        RuntimeError::Unsupported(
            dsr::profile::ProfileError::CounterOverflow("blocked_ns").to_string(),
        )
    })?;
    Ok(result)
}

fn dispatch_native_syscall_inner<const PROFILE: bool>(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &SharedNativeMemory,
    thread_runtime: &NativeThreadRuntime,
    reporter: &CompatReporter,
    trace_syscalls: bool,
    blocked_ns: &mut u64,
) -> Result<DispatchOutcome, RuntimeError> {
    let mut signal_wait_deadline = None;
    let mut fd_wait_deadline = None;
    loop {
        let outcome = {
            let mut memory = memory.lock();
            dispatcher.dispatch_threaded(
                request,
                &mut *memory,
                reporter,
                thread_runtime.tid(),
                &thread_runtime.registry,
                &thread_runtime.futex,
            )?
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
                    let mut memory = memory.lock();
                    for (addr, len) in &clear_on_timeout {
                        let _ = memory.zero_guest_range(*addr, *len);
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                };
                match measure_native_blocked::<PROFILE, _>(blocked_ns, || {
                    wait_native_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask)
                })? {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        let mut memory = memory.lock();
                        for (addr, len) in &clear_on_timeout {
                            let _ = memory.zero_guest_range(*addr, *len);
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
                        let mut memory = memory.lock();
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

fn native_unsafe_postfork_threads_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

fn native_clone_thread_rejection(memory: &SharedNativeMemory) -> Option<&'static str> {
    let unsafe_postfork_threads = native_unsafe_postfork_threads_enabled(
        std::env::var_os("CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS").as_deref(),
    );
    if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire)
        && !unsafe_postfork_threads
    {
        return Some(
            "native Darwin cannot create guest threads in a fork child: emulated execve cannot reset the host libdispatch post-fork state",
        );
    }
    memory.lock().native16k_clone_thread_rejection()
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
) -> Result<NativeForkFlow, RuntimeError> {
    if request.clone_parent {
        return Err(RuntimeError::Unsupported(
            "native Darwin run-elf fork does not yet support CLONE_PARENT".to_string(),
        ));
    }
    // Serialize forks (and exclude a concurrent execve teardown): the same
    // CAS token the HVF fork barrier uses. A loser parks at the in-flight
    // fork's barrier so its drain counts this thread; a loser that observes
    // an execve replacement retires instead (its whole thread group is being
    // destroyed — the fork never happens, matching Linux).
    match thread_runtime.acquire_fork_token() {
        NativeForkTokenFlow::Acquired => {}
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
    if thread_runtime.registry.live_count() > 1 {
        // linux4k boundary: the 4K-on-16K guarded-page fault emulation is not
        // multithread-safe (MT guarded faults corrupt its state and could
        // SIGSEGV the host — forkfpreclaim on linux4k; task_c2615fa2 tracks
        // making it MT-safe). MT fork on linux4k keeps the honest typed
        // rejection it had before MT fork landed; the run-loop's guarded-
        // fault arm carries the matching MT rejection, so a linux4k MT guest
        // fails typed at whichever boundary it reaches first, never with a
        // host crash.
        if memory.lock().uses_linux4k_subpages() {
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
        if memory.lock().write_exec_blocks_multithreaded_lifecycle() {
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
    // Drain in-flight EXIT CLEANUPS before forking: an exiting thread has
    // already left the kicker (so the quiesce above never counted it) but may
    // still be mutating process-global signal state under process-wide
    // mutexes; `libc::fork` landing inside that window hands the child a
    // mutex held by a thread that does not exist in it (the HVF go-os_exec
    // vfork wedge). Bounded, then proceed (status-quo risk) — mirrors HVF.
    {
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
    }
    let end_fork_state = |quiesced: bool| {
        if quiesced {
            barrier.end_quiesce();
        }
        barrier.end_fork();
    };
    let vfork_pipe = if request.vfork.is_some() {
        memory.lock().set_fork_inheritance(true);
        match vfork_pipe_pair() {
            Ok(pipe) => Some(pipe),
            Err(error) => {
                memory.lock().set_fork_inheritance(false);
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
                memory.lock().set_fork_inheritance(false);
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
    let child = unsafe { libc::fork() };
    // Both branches: drop the prepare bundle before any signal-static use.
    // The parent releases its guards normally; the child publishes a fresh
    // waiter backing instead of unlocking a copied contended parking queue.
    drop(fork_signal_locks);
    drop(paused_guard);
    if child < 0 {
        crate::guest_cpu::abort_prepared_child_record();
        if let Some((read_fd, write_fd)) = vfork_pipe {
            close_fd(read_fd);
            close_fd(write_fd);
            memory.lock().set_fork_inheritance(false);
        }
        end_fork_state(quiesced);
        return Ok(NativeForkFlow::Resume {
            value: crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            fork_child: false,
            child_stack: 0,
        });
    }
    if child == 0 {
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
        native_trace_fork_phase("child-guard-installed");
        native_after_fork_child(dispatcher);
        native_trace_fork_phase("child-dispatcher-reset");
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
        crate::guest_cpu::reset();
        crate::guest_cpu::complete_child_record_post_fork_child();
        // P2 getrandom fork-safety: give the child its own vvar RNG generation
        // (its PID) so the COW-inherited userspace getrandom state reseeds
        // instead of replaying the parent's keystream — the native counterpart
        // of the HVF child-side re-stamp in `fork_rebuild`.
        memory.lock().restamp_vdso_rng_generation_after_fork()?;
        crate::run_state::reinit_booting_after_fork();
        let self_tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
        if let Some(addr) = request.parent_tid_addr {
            let _ = memory.lock().write_bytes(addr, &self_tid);
        }
        if let Some(addr) = request.child_tid_addr {
            let _ = memory.lock().write_bytes(addr, &self_tid);
        }
        native_trace_fork_phase("child-resume");
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
    if quiesced {
        barrier.end_quiesce();
    }
    let vfork_wait = if let Some((read_fd, write_fd)) = vfork_pipe {
        close_fd(write_fd);
        let wait = wait_native_vfork_completion(read_fd, thread_runtime.tid());
        close_fd(read_fd);
        memory.lock().set_fork_inheritance(false);
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
        let _ = memory.lock().write_bytes(addr, &fd.to_le_bytes());
    }
    let guest_child_pid = child_ns_pid.unwrap_or(child as u32) as i32;
    if let Some(addr) = request.parent_tid_addr {
        let tid = guest_child_pid.to_le_bytes();
        let _ = memory.lock().write_bytes(addr, &tid);
    }
    native_register_child_exit_watch(dispatcher, child, request.exit_signal, thread_runtime.tid());
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
    if memory.lock().write_exec_blocks_multithreaded_lifecycle() {
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

fn native_after_fork_child(dispatcher: &SyscallDispatcher) {
    dispatcher.clear_output_buffers();
    crate::event_ring::reinit_after_fork();
    crate::host_signal::reinit_after_fork();
    crate::dispatch::reset_fifo_beacons_after_fork_child();
    dispatcher.epoll_after_fork_child();
    dispatcher.proc_after_fork_child();
    dispatcher.mem_after_fork_child();
    dispatcher.sysv_after_fork_child();
}

fn native_dc_zva(memory: &mut NativeMappedMemory, address: u64) -> Result<(), RuntimeError> {
    let start = address & !(NATIVE_DC_ZVA_BLOCK_SIZE as u64 - 1);
    memory
        .write_bytes(start, &[0; NATIVE_DC_ZVA_BLOCK_SIZE])
        .map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native Darwin DC ZVA failed at 0x{address:x}: {error}"
            ))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeScalarAccessKind {
    Load { sign_extend: bool },
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeScalarAccess {
    kind: NativeScalarAccessKind,
    width: usize,
    destination_width: usize,
}

fn bad64_gpr_index(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let w0 = bad64::Reg::W0 as u32;
    let w30 = bad64::Reg::W30 as u32;
    if (w0..=w30).contains(&raw) {
        return Some(((raw - w0) as usize, 4));
    }
    let x0 = bad64::Reg::X0 as u32;
    let x30 = bad64::Reg::X30 as u32;
    if (x0..=x30).contains(&raw) {
        return Some(((raw - x0) as usize, 8));
    }
    None
}

fn bad64_transfer_width(reg: bad64::Reg) -> Option<usize> {
    bad64_gpr_index(reg).map(|(_, width)| width).or_else(|| {
        if reg == bad64::Reg::WZR {
            Some(4)
        } else if reg == bad64::Reg::XZR {
            Some(8)
        } else {
            None
        }
    })
}

fn native_snapshot_read_reg(snapshot: &NativeUcontextSnapshot, reg: bad64::Reg) -> Option<u64> {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let value = snapshot.x.get(index).copied()?;
        return Some(if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        });
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return Some(0);
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        return Some(snapshot.sp);
    }
    None
}

fn native_snapshot_write_reg(
    snapshot: &mut NativeUcontextSnapshot,
    reg: bad64::Reg,
    value: u64,
) -> bool {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let Some(slot) = snapshot.x.get_mut(index) else {
            return false;
        };
        *slot = if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        };
        return true;
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return true;
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        snapshot.sp = value;
        return true;
    }
    false
}

fn add_bad64_imm(base: u64, imm: bad64::Imm) -> u64 {
    match imm {
        bad64::Imm::Signed(value) => base.wrapping_add_signed(value),
        bad64::Imm::Unsigned(value) => base.wrapping_add(value),
    }
}

fn extend_bad64_index(value: u64, shift: Option<bad64::Shift>) -> Option<u64> {
    match shift {
        None => Some(value),
        Some(bad64::Shift::LSL(amount) | bad64::Shift::UXTX(amount)) => {
            Some(value.wrapping_shl(amount))
        }
        Some(bad64::Shift::SXTX(amount)) => Some((value as i64 as u64).wrapping_shl(amount)),
        Some(bad64::Shift::UXTW(amount)) => Some(u64::from(value as u32).wrapping_shl(amount)),
        Some(bad64::Shift::SXTW(amount)) => {
            Some((value as u32 as i32 as i64 as u64).wrapping_shl(amount))
        }
        _ => None,
    }
}

fn decode_native_scalar_address(
    snapshot: &NativeUcontextSnapshot,
    operand: bad64::Operand,
) -> Option<(u64, Option<(bad64::Reg, u64)>)> {
    match operand {
        bad64::Operand::MemReg(base) => Some((native_snapshot_read_reg(snapshot, base)?, None)),
        bad64::Operand::MemOffset {
            reg: base,
            offset,
            mul_vl: false,
            arrspec: None,
        } => Some((
            add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, offset),
            None,
        )),
        bad64::Operand::MemPreIdx { reg: base, imm } => {
            let address = add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, imm);
            Some((address, Some((base, address))))
        }
        bad64::Operand::MemPostIdxImm { reg: base, imm } => {
            let address = native_snapshot_read_reg(snapshot, base)?;
            Some((address, Some((base, add_bad64_imm(address, imm)))))
        }
        bad64::Operand::MemExt {
            regs: [base, index],
            shift,
            arrspec: None,
        } => {
            let base = native_snapshot_read_reg(snapshot, base)?;
            let index = native_snapshot_read_reg(snapshot, index)?;
            Some((base.wrapping_add(extend_bad64_index(index, shift)?), None))
        }
        _ => None,
    }
}

fn decode_native_scalar_access(op: bad64::Op, transfer_width: usize) -> Option<NativeScalarAccess> {
    use bad64::Op;

    let access = match op {
        Op::LDR | Op::LDUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::LDRB | Op::LDURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRH | Op::LDURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSB | Op::LDURSB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRSH | Op::LDURSH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSW | Op::LDURSW if transfer_width == 8 => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 4,
            destination_width: 8,
        },
        Op::STR | Op::STUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::STRB | Op::STURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 1,
            destination_width: transfer_width,
        },
        Op::STRH | Op::STURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 2,
            destination_width: transfer_width,
        },
        _ => return None,
    };
    Some(access)
}

fn native_load_value(bytes: &[u8], sign_extend: bool, destination_width: usize) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    if sign_extend && !bytes.is_empty() && bytes.len() < std::mem::size_of::<u64>() {
        let shift = 64 - bytes.len() * 8;
        value = ((value << shift) as i64 >> shift) as u64;
    }
    if destination_width == 4 {
        value & u64::from(u32::MAX)
    } else {
        value
    }
}

fn bad64_single_vector_index(operand: bad64::Operand) -> Option<usize> {
    let bad64::Operand::MultiReg {
        regs,
        arrspec: Some(bad64::ArrSpec::SixteenBytes(None)),
    } = operand
    else {
        return None;
    };
    let reg = regs[0]?;
    if regs[1..].iter().any(Option::is_some) {
        return None;
    }
    let raw = reg as u32;
    let first = bad64::Reg::V0 as u32;
    let last = bad64::Reg::V31 as u32;
    (first..=last)
        .contains(&raw)
        .then_some((raw - first) as usize)
}

fn bad64_vector_index_and_width(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let classes = [
        (bad64::Reg::B0 as u32, bad64::Reg::B31 as u32, 1),
        (bad64::Reg::H0 as u32, bad64::Reg::H31 as u32, 2),
        (bad64::Reg::S0 as u32, bad64::Reg::S31 as u32, 4),
        (bad64::Reg::D0 as u32, bad64::Reg::D31 as u32, 8),
        (bad64::Reg::Q0 as u32, bad64::Reg::Q31 as u32, 16),
        (bad64::Reg::V0 as u32, bad64::Reg::V31 as u32, 16),
    ];
    classes.iter().find_map(|(first, last, width)| {
        (*first..=*last)
            .contains(&raw)
            .then(|| ((raw - *first) as usize, *width))
    })
}

fn emulate_linux4k_guarded_vector_register_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    vector_reg: bad64::Reg,
    memory_operand: bad64::Operand,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let (vector_index, width) = bad64_vector_index_and_width(vector_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault does not support register {vector_reg}"
        ))
    })?;
    let write = match instruction.op() {
        bad64::Op::LDR | bad64::Op::LDUR => false,
        bad64::Op::STR | bad64::Op::STUR => true,
        _ => {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    let slot = snapshot.v.get_mut(vector_index).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector index {vector_index} is out of range"
        ))
    })?;
    if write {
        memory
            .write_bytes_raw(address, &slot[..width])
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory.read_bytes_raw(address, width).map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector load failed at 0x{address:x}: {error}"
            ))
        })?;
        slot.fill(0);
        slot[..width].copy_from_slice(&bytes);
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_pair_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [
        bad64::Operand::Reg {
            reg: first_reg,
            arrspec: None,
        },
        bad64::Operand::Reg {
            reg: second_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair fault does not support operands for {instruction}"
        )));
    };
    let write = matches!(instruction.op(), bad64::Op::STP | bad64::Op::STNP);
    if !matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair fault does not support {instruction}"
        )));
    }
    let vector_regs =
        bad64_vector_index_and_width(*first_reg).zip(bad64_vector_index_and_width(*second_reg));
    let gpr_regs = bad64_transfer_width(*first_reg).zip(bad64_transfer_width(*second_reg));
    let element_width = if let Some(((first_index, first_width), (second_index, second_width))) =
        vector_regs
    {
        if first_width != second_width || instruction.op() == bad64::Op::LDPSW {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair has incompatible vector registers for {instruction}"
            )));
        }
        let _ = (first_index, second_index);
        first_width
    } else if let Some((first_width, second_width)) = gpr_regs {
        if first_width != second_width {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair has incompatible GPR widths for {instruction}"
            )));
        }
        if instruction.op() == bad64::Op::LDPSW {
            if first_width != 8 {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded LDPSW requires X registers: {instruction}"
                )));
            }
            4
        } else {
            first_width
        }
    } else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair requires matching GPR or vector registers: {instruction}"
        )));
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair fault does not support addressing for {instruction}"
            ))
        })?;
    let total_width = element_width * 2;
    let access_end = address.checked_add(total_width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded pair access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, total_width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback {
        let base_index = bad64_gpr_index(base).map(|(index, _)| index);
        if base_index == bad64_gpr_index(*first_reg).map(|(index, _)| index)
            || base_index == bad64_gpr_index(*second_reg).map(|(index, _)| index)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair rejects overlapping writeback for {instruction}"
            )));
        }
    }

    if let Some(((first_index, _), (second_index, _))) = vector_regs {
        if write {
            let first = snapshot.v[first_index];
            let second = snapshot.v[second_index];
            memory
                .write_bytes_raw(address, &first[..element_width])
                .and_then(|()| {
                    memory.write_bytes_raw(
                        address.saturating_add(element_width as u64),
                        &second[..element_width],
                    )
                })
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded vector pair store failed at 0x{address:x}: {error}"
                    ))
                })?;
        } else {
            let bytes = memory
                .read_bytes_raw(address, total_width)
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded vector pair load failed at 0x{address:x}: {error}"
                    ))
                })?;
            snapshot.v[first_index].fill(0);
            snapshot.v[first_index][..element_width].copy_from_slice(&bytes[..element_width]);
            snapshot.v[second_index].fill(0);
            snapshot.v[second_index][..element_width].copy_from_slice(&bytes[element_width..]);
        }
    } else if write {
        let first = native_snapshot_read_reg(snapshot, *first_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not read {first_reg}"
            ))
        })?;
        let second = native_snapshot_read_reg(snapshot, *second_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not read {second_reg}"
            ))
        })?;
        memory
            .write_bytes_raw(address, &first.to_le_bytes()[..element_width])
            .and_then(|()| {
                memory.write_bytes_raw(
                    address.saturating_add(element_width as u64),
                    &second.to_le_bytes()[..element_width],
                )
            })
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded GPR pair store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory
            .read_bytes_raw(address, total_width)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded GPR pair load failed at 0x{address:x}: {error}"
                ))
            })?;
        let sign_extend = instruction.op() == bad64::Op::LDPSW;
        let first = native_load_value(&bytes[..element_width], sign_extend, 8);
        let second = native_load_value(&bytes[element_width..], sign_extend, 8);
        if !native_snapshot_write_reg(snapshot, *first_reg, first)
            || !native_snapshot_write_reg(snapshot, *second_reg, second)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not update registers for {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded pair PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_vector_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [vector_operand, memory_operand] = instruction.operands() else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault does not support operands for {instruction}"
        )));
    };
    let vector_index = bad64_single_vector_index(*vector_operand).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault supports one .16b register, got {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(16).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = instruction.op() == bad64::Op::ST1;
    if !memory.linux4k_range_allows(address, 16, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    match instruction.op() {
        bad64::Op::LD1 => {
            let bytes = memory.read_bytes_raw(address, 16).map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector load failed at 0x{address:x}: {error}"
                ))
            })?;
            let Some(slot) = snapshot.v.get_mut(vector_index) else {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                )));
            };
            slot.copy_from_slice(&bytes);
        }
        bad64::Op::ST1 => {
            let value = snapshot.v.get(vector_index).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                ))
            })?;
            memory.write_bytes_raw(address, value).map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
        }
        _ => {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

fn atomic_add_access_width(op: bad64::Op, result_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDADDB | bad64::Op::LDADDAB | bad64::Op::LDADDALB | bad64::Op::LDADDLB => {
            Some(1)
        }
        bad64::Op::LDADDH | bad64::Op::LDADDAH | bad64::Op::LDADDALH | bad64::Op::LDADDLH => {
            Some(2)
        }
        bad64::Op::LDADD | bad64::Op::LDADDA | bad64::Op::LDADDAL | bad64::Op::LDADDL => {
            bad64_transfer_width(result_reg)
        }
        _ => None,
    }
}

fn atomic_add_ordering(
    op: bad64::Op,
    result_reg: bad64::Reg,
) -> Option<std::sync::atomic::Ordering> {
    let acquire = matches!(
        op,
        bad64::Op::LDADDA
            | bad64::Op::LDADDAB
            | bad64::Op::LDADDAH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
    ) && !matches!(result_reg, bad64::Reg::WZR | bad64::Reg::XZR);
    let release = matches!(
        op,
        bad64::Op::LDADDL
            | bad64::Op::LDADDLB
            | bad64::Op::LDADDLH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
    );
    atomic_add_access_width(op, result_reg)?;
    Some(match (acquire, release) {
        (false, false) => std::sync::atomic::Ordering::Relaxed,
        (true, false) => std::sync::atomic::Ordering::Acquire,
        (false, true) => std::sync::atomic::Ordering::Release,
        (true, true) => std::sync::atomic::Ordering::AcqRel,
    })
}

fn emulate_linux4k_guarded_atomic_add(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [
        bad64::Operand::Reg {
            reg: addend_reg,
            arrspec: None,
        },
        bad64::Operand::Reg {
            reg: result_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k atomic add does not support operands for {instruction}"
        )));
    };
    let width = atomic_add_access_width(instruction.op(), *result_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k atomic add does not support width for {instruction}"
        ))
    })?;
    if bad64_transfer_width(*addend_reg).is_none() || bad64_transfer_width(*result_reg).is_none() {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k atomic add requires GPR operands for {instruction}"
        )));
    }
    let ordering = atomic_add_ordering(instruction.op(), *result_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k atomic add does not support ordering for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k atomic add does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k atomic add rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k atomic add access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, false)
        || !memory.linux4k_range_allows(address, width, true)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    let addend = native_snapshot_read_reg(snapshot, *addend_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k atomic add could not read {addend_reg}"
        ))
    })?;
    let old = memory
        .atomic_fetch_add(address, width, addend, ordering)
        .map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native linux4k atomic add failed at 0x{address:x}: {error}"
            ))
        })?;
    if !native_snapshot_write_reg(snapshot, *result_reg, old) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k atomic add could not write {result_reg}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k atomic add PC overflow".to_string())
    })?;
    Ok(())
}

fn ordered_atomic_access_width(op: bad64::Op, transfer_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDARB | bad64::Op::LDAPRB | bad64::Op::STLRB | bad64::Op::STLLRB => Some(1),
        bad64::Op::LDARH | bad64::Op::LDAPRH | bad64::Op::STLRH | bad64::Op::STLLRH => Some(2),
        bad64::Op::LDAR | bad64::Op::LDAPR | bad64::Op::STLR | bad64::Op::STLLR => {
            bad64_transfer_width(transfer_reg)
        }
        _ => None,
    }
}

fn emulate_linux4k_guarded_ordered_atomic_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [
        bad64::Operand::Reg {
            reg: transfer_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k ordered atomic access does not support operands for {instruction}"
        )));
    };
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAR
            | bad64::Op::LDARB
            | bad64::Op::LDARH
            | bad64::Op::LDAPR
            | bad64::Op::LDAPRB
            | bad64::Op::LDAPRH
    );
    let width = ordered_atomic_access_width(instruction.op(), *transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k ordered atomic access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k ordered atomic access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k ordered atomic access rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k ordered atomic access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, !load) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if load {
        let value = memory.atomic_load(address, width).map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native linux4k ordered atomic load failed at 0x{address:x}: {error}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, *transfer_reg, value) {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k ordered atomic load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, *transfer_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k ordered atomic store could not read {transfer_reg}"
            ))
        })?;
        memory
            .atomic_store(address, width, value)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k ordered atomic store failed at 0x{address:x}: {error}"
                ))
            })?;
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k ordered atomic PC overflow".to_string())
    })?;
    Ok(())
}

fn exclusive_access_width(op: bad64::Op, transfer_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDAXRB | bad64::Op::LDXRB | bad64::Op::STLXRB | bad64::Op::STXRB => Some(1),
        bad64::Op::LDAXRH | bad64::Op::LDXRH | bad64::Op::STLXRH | bad64::Op::STXRH => Some(2),
        bad64::Op::LDAXR | bad64::Op::LDXR | bad64::Op::STLXR | bad64::Op::STXR => {
            bad64_transfer_width(transfer_reg)
        }
        _ => None,
    }
}

fn emulate_dsr_exclusive_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    reservation: &mut Option<NativeExclusiveReservation>,
    word: u32,
    guest_pc: u64,
) -> Result<(), RuntimeError> {
    let instruction = bad64::decode(word, guest_pc).map_err(|error| {
        RuntimeError::Unsupported(format!(
            "native DSR could not decode exclusive word 0x{word:08x} at 0x{guest_pc:x}: {error:?}"
        ))
    })?;
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
    );
    let acquire = matches!(
        instruction.op(),
        bad64::Op::LDAXR | bad64::Op::LDAXRB | bad64::Op::LDAXRH
    );
    let release = matches!(
        instruction.op(),
        bad64::Op::STLXR | bad64::Op::STLXRB | bad64::Op::STLXRH
    );
    let (status_reg, transfer_reg, memory_operand) = if load {
        let [
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native DSR exclusive load does not support operands for {instruction}"
            )));
        };
        (None, *transfer_reg, *memory_operand)
    } else {
        let [
            bad64::Operand::Reg {
                reg: status_reg,
                arrspec: None,
            },
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native DSR exclusive store does not support operands for {instruction}"
            )));
        };
        (Some(*status_reg), *transfer_reg, *memory_operand)
    };
    let width = exclusive_access_width(instruction.op(), transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native DSR exclusive access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native DSR exclusive access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(RuntimeError::Unsupported(format!(
            "native DSR exclusive access rejects writeback for {instruction}"
        )));
    }
    if !memory.native_range_allows(address, width, !load) {
        return Err(RuntimeError::Unsupported(format!(
            "native DSR exclusive {instruction} violates guest permissions at 0x{address:x}"
        )));
    }

    if load {
        let value = memory
            .exclusive_load_for(address, width, acquire, reservation)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native DSR exclusive load failed at 0x{address:x}: {error}"
                ))
            })?;
        if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
            return Err(RuntimeError::Unsupported(format!(
                "native DSR exclusive load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native DSR exclusive store could not read {transfer_reg}"
            ))
        })?;
        let stored = memory
            .exclusive_store_for(address, width, value, release, reservation)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native DSR exclusive store failed at 0x{address:x}: {error}"
                ))
            })?;
        let status_reg = status_reg.ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native DSR exclusive store lacks status register for {instruction}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, status_reg, u64::from(!stored)) {
            return Err(RuntimeError::Unsupported(format!(
                "native DSR exclusive store could not write {status_reg}"
            )));
        }
    }
    Ok(())
}

fn emulate_linux4k_guarded_exclusive_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
    );
    let acquire = matches!(
        instruction.op(),
        bad64::Op::LDAXR | bad64::Op::LDAXRB | bad64::Op::LDAXRH
    );
    let release = matches!(
        instruction.op(),
        bad64::Op::STLXR | bad64::Op::STLXRB | bad64::Op::STLXRH
    );

    let (status_reg, transfer_reg, memory_operand) = if load {
        let [
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive load does not support operands for {instruction}"
            )));
        };
        (None, *transfer_reg, *memory_operand)
    } else {
        let [
            bad64::Operand::Reg {
                reg: status_reg,
                arrspec: None,
            },
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive store does not support operands for {instruction}"
            )));
        };
        (Some(*status_reg), *transfer_reg, *memory_operand)
    };
    let width = exclusive_access_width(instruction.op(), transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k exclusive access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k exclusive access rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k exclusive access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, !load) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }

    if load {
        let value = memory
            .exclusive_load(address, width, acquire)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k exclusive load failed at 0x{address:x}: {error}"
                ))
            })?;
        if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive store could not read {transfer_reg}"
            ))
        })?;
        let stored = memory
            .exclusive_store(address, width, value, release)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k exclusive store failed at 0x{address:x}: {error}"
                ))
            })?;
        let status_reg = status_reg.ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive store lacks status register for {instruction}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, status_reg, u64::from(!stored)) {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive store could not write {status_reg}"
            )));
        }
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k exclusive PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_fault(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
) -> Result<(), RuntimeError> {
    let fault_address = if snapshot.fault_address != 0 {
        snapshot.fault_address
    } else {
        snapshot.far
    };
    if !memory.linux4k_address_is_guarded(fault_address) {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin signal {} at 0x{fault_address:x} was not a guarded linux4k page (pc=0x{:x} sp=0x{:x} lr=0x{:x} x16=0x{:x} x17=0x{:x} x18=0x{:x} esr=0x{:x})",
            snapshot.signal,
            snapshot.pc,
            snapshot.sp,
            snapshot.x[30],
            snapshot.x[16],
            snapshot.x[17],
            snapshot.x[18],
            snapshot.esr
        )));
    }
    let word = memory.read_u32(snapshot.pc)?;
    let instruction = bad64::decode(word, snapshot.pc).map_err(|error| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded fault could not decode instruction 0x{word:08x} at 0x{:x}: {error}",
            snapshot.pc
        ))
    })?;
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!(
                "native trace pid={} guarded pc=0x{:x} addr=0x{fault_address:x} esr=0x{:x} word=0x{word:08x} instruction={instruction}\n",
                unsafe { libc::getpid() },
                snapshot.pc,
                snapshot.esr
            )
            .as_bytes(),
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDADD
            | bad64::Op::LDADDA
            | bad64::Op::LDADDAB
            | bad64::Op::LDADDAH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
            | bad64::Op::LDADDB
            | bad64::Op::LDADDH
            | bad64::Op::LDADDL
            | bad64::Op::LDADDLB
            | bad64::Op::LDADDLH
    ) {
        return emulate_linux4k_guarded_atomic_add(memory, snapshot, &instruction, fault_address);
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDAR
            | bad64::Op::LDARB
            | bad64::Op::LDARH
            | bad64::Op::LDAPR
            | bad64::Op::LDAPRB
            | bad64::Op::LDAPRH
            | bad64::Op::STLR
            | bad64::Op::STLRB
            | bad64::Op::STLRH
            | bad64::Op::STLLR
            | bad64::Op::STLLRB
            | bad64::Op::STLLRH
    ) {
        return emulate_linux4k_guarded_ordered_atomic_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
            | bad64::Op::STLXR
            | bad64::Op::STLXRB
            | bad64::Op::STLXRH
            | bad64::Op::STXR
            | bad64::Op::STXRB
            | bad64::Op::STXRH
    ) {
        return emulate_linux4k_guarded_exclusive_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(instruction.op(), bad64::Op::LD1 | bad64::Op::ST1) {
        return emulate_linux4k_guarded_vector_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return emulate_linux4k_guarded_pair_access(memory, snapshot, &instruction, fault_address);
    }
    if let [
        bad64::Operand::Reg {
            reg: vector_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
        && bad64_vector_index_and_width(*vector_reg).is_some()
    {
        return emulate_linux4k_guarded_vector_register_access(
            memory,
            snapshot,
            &instruction,
            *vector_reg,
            *memory_operand,
            fault_address,
        );
    }
    let [transfer_operand, memory_operand] = instruction.operands() else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault does not support operands for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let bad64::Operand::Reg {
        reg: transfer_reg,
        arrspec: None,
    } = *transfer_operand
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault requires a scalar GPR transfer for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let transfer_width = bad64_transfer_width(transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded fault does not support transfer register {transfer_reg} for {instruction}"
        ))
    })?;
    let access =
        decode_native_scalar_access(instruction.op(), transfer_width).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded fault does not support instruction {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let (address, writeback) = decode_native_scalar_address(snapshot, *memory_operand)
        .ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded fault does not support addressing for {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let access_end = address.checked_add(access.width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = matches!(access.kind, NativeScalarAccessKind::Store);
    if !memory.linux4k_range_allows(address, access.width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback
        && bad64_gpr_index(base).map(|(index, _)| index)
            == bad64_gpr_index(transfer_reg).map(|(index, _)| index)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault rejects overlapping writeback for {instruction}"
        )));
    }

    match access.kind {
        NativeScalarAccessKind::Load { sign_extend } => {
            let bytes = memory
                .read_bytes_raw(address, access.width)
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded load failed at 0x{address:x}: {error}"
                    ))
                })?;
            let value = native_load_value(&bytes, sign_extend, access.destination_width);
            if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded fault could not write {transfer_reg}"
                )));
            }
        }
        NativeScalarAccessKind::Store => {
            let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded fault could not read {transfer_reg}"
                ))
            })?;
            memory
                .write_bytes_raw(address, &value.to_le_bytes()[..access.width])
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded store failed at 0x{address:x}: {error}"
                    ))
                })?;
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded PC overflow".to_string())
    })?;
    Ok(())
}

struct NativeMappedMemory {
    address_mode: NativeAddressMode,
    // Host-coordinate authority for image retirement, biased fixed remaps,
    // and validated reverse faults. Biased intervals are collision-reserved;
    // direct intervals are normalized planned ownership recorded after the
    // established unreserved MAP_FIXED mapping path succeeds.
    owned_host_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    regions: Vec<NativeMappedRegion>,
    protections: MemoryProtections,
    native_page_protections: BTreeMap<u64, u64>,
    native_write_exec_writable_pages: BTreeSet<u64>,
    linux4k_page_protections: BTreeMap<u64, [u64; 4]>,
    exclusive_reservation: Option<NativeExclusiveReservation>,
    exclusive_sequences: BTreeMap<NativeExclusiveLocation, NativeExclusiveSequence>,
    host_page_size: u64,
    linux_page_size: u64,
    dsr_generations: dsr::cache::PageGenerationTable,
    dsr_translator: Option<Arc<dsr::ProcessTranslator>>,
}

struct PreparedNativeExecMapping {
    native_layout: NativeLayout,
    process_translator: Arc<dsr::ProcessTranslator>,
    reset_inherited_translator: bool,
    direct_target_reservations: Vec<crate::host_proc::DirectVmReservation>,
    rollback_plan: NativeMappingRollbackPlan,
}

#[derive(Clone, Copy)]
enum NativeImageBacking<'a> {
    AnonymousBytes,
    Prepared(&'a ValidatedPreparedImage),
}

impl NativeImageBacking<'_> {
    #[cfg(test)]
    fn is_prepared(self) -> bool {
        matches!(self, Self::Prepared(_))
    }
}

struct NativeMappingRollbackPlan {
    supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
}

impl NativeMappingRollbackPlan {
    fn for_fresh_layout(layout: &NativeLayout) -> Self {
        let supplemental_ranges = match layout.address_mode() {
            NativeAddressMode::Direct => layout.owned_ranges().to_vec(),
            NativeAddressMode::Biased { .. } => Vec::new(),
        };
        Self {
            supplemental_ranges,
        }
    }

    fn direct_exec(
        owned_ranges: &[std::ops::Range<carrick_guest_mem::HostVa>],
        mut reservation_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    ) -> Self {
        normalize_host_ranges(&mut reservation_ranges);
        Self {
            supplemental_ranges: subtract_host_ranges(owned_ranges, &reservation_ranges),
        }
    }
}

struct NativeMappingRollback {
    supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    mapped_supplemental_ranges: Vec<std::ops::Range<carrick_guest_mem::HostVa>>,
    host_page_size: usize,
    armed: bool,
}

impl NativeMappingRollback {
    fn new(
        plan: NativeMappingRollbackPlan,
        host_page_size: u64,
        capacity: usize,
    ) -> Result<Self, RuntimeError> {
        let host_page_size = usize::try_from(host_page_size).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native rollback host page size is not representable: 0x{host_page_size:x}"
            ))
        })?;
        if !host_page_size.is_power_of_two() {
            return Err(RuntimeError::Unsupported(format!(
                "native rollback host page size is invalid: 0x{host_page_size:x}"
            )));
        }
        Ok(Self {
            supplemental_ranges: plan.supplemental_ranges,
            mapped_supplemental_ranges: Vec::with_capacity(capacity),
            host_page_size,
            armed: true,
        })
    }

    fn track_mapping(&mut self, start: carrick_guest_mem::HostVa, length: usize) {
        if length == 0 || self.supplemental_ranges.is_empty() {
            return;
        }
        let page_mask = self.host_page_size.saturating_sub(1);
        let mapped_start = start.raw() & !page_mask;
        let mapped_end = start.raw().saturating_add(length).saturating_add(page_mask) & !page_mask;
        for owned in &self.supplemental_ranges {
            let overlap_start = mapped_start.max(owned.start.raw());
            let overlap_end = mapped_end.min(owned.end.raw());
            if overlap_start < overlap_end {
                self.mapped_supplemental_ranges.push(
                    carrick_guest_mem::HostVa(overlap_start)
                        ..carrick_guest_mem::HostVa(overlap_end),
                );
            }
        }
        normalize_host_ranges(&mut self.mapped_supplemental_ranges);
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for NativeMappingRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for range in &self.mapped_supplemental_ranges {
            let length = range.end.raw().saturating_sub(range.start.raw());
            if length == 0 {
                continue;
            }
            #[cfg(test)]
            NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS.with(|slot| slot.borrow_mut().push(range.clone()));
            unsafe {
                libc::munmap(range.start.raw() as *mut libc::c_void, length);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct NativeMappingPageSizes {
    host: u64,
    linux: u64,
}

struct NativeMappingOptions<'a> {
    reusable_translator: Option<Arc<dsr::ProcessTranslator>>,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    relative_relocations: &'a [NativeRelativeRelocation],
    backing: NativeImageBacking<'a>,
    rollback_plan: NativeMappingRollbackPlan,
}

struct NativeByteRegionOptions {
    final_prot: libc::c_int,
    executable: bool,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
}

#[derive(Clone, Copy)]
struct PreparedRegionMapping {
    mapped: *mut libc::c_void,
    mapped_length: usize,
    logical_length: u64,
}

#[derive(Clone, Copy)]
struct NativeExclusiveReservation {
    location: NativeExclusiveLocation,
    observed: u64,
    sequence: NativeExclusiveSequence,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NativeExclusiveLocation {
    address: u64,
    width: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeExclusiveSequence(u64);

impl NativeExclusiveSequence {
    const INITIAL: Self = Self(0);

    fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

struct NativeMappedRegion {
    start: u64,
    end: u64,
    host_protects: bool,
    shared_futex: bool,
    guest_writable: bool,
    default_prot: u64,
    /// File-identity futex-key base (`trap::shared_file_key_base`) for a
    /// direct host `MAP_SHARED` FILE mapping, else 0. Two processes mapping
    /// the same file at DIFFERENT guest addresses (native exec rebuilds the
    /// address space, so an exec'd child re-attaches an LTP checkpoint page
    /// wherever mmap lands) must resolve one futex word to ONE waiter-count
    /// key; a guest-VA key made the exec'd child's FUTEX_WAKE miss the
    /// parent's registered waiter (ltpcheckpointexec). 0 keeps VA-keying:
    /// anon MAP_SHARED is fork-inherited at the SAME VA everywhere.
    shared_key_base: u64,
    /// File offset of `start` for `shared_key_base != 0` regions.
    shared_key_offset: u64,
}

fn native_region_linux_prot(read: bool, write: bool, exec: bool) -> u64 {
    let mut prot = 0;
    if read {
        prot |= crate::linux_abi::LINUX_PROT_READ;
    }
    if write {
        prot |= crate::linux_abi::LINUX_PROT_WRITE;
    }
    if exec {
        prot |= crate::linux_abi::LINUX_PROT_EXEC;
    }
    prot
}

fn normalize_host_ranges(ranges: &mut Vec<std::ops::Range<carrick_guest_mem::HostVa>>) {
    ranges.sort_unstable_by_key(|range| range.start.raw());
    let mut write = 0;
    for read in 0..ranges.len() {
        if write != 0 && ranges[read].start.raw() <= ranges[write - 1].end.raw() {
            if ranges[read].end.raw() > ranges[write - 1].end.raw() {
                ranges[write - 1].end = ranges[read].end;
            }
        } else {
            ranges.swap(write, read);
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn subtract_host_ranges(
    owned: &[std::ops::Range<carrick_guest_mem::HostVa>],
    retained: &[std::ops::Range<carrick_guest_mem::HostVa>],
) -> Vec<std::ops::Range<carrick_guest_mem::HostVa>> {
    let mut result = Vec::new();
    for range in owned {
        let mut cursor = range.start.raw();
        for keep in retained {
            if keep.end.raw() <= cursor || keep.start.raw() >= range.end.raw() {
                continue;
            }
            if keep.start.raw() > cursor {
                result.push(
                    carrick_guest_mem::HostVa(cursor)..carrick_guest_mem::HostVa(keep.start.raw()),
                );
            }
            cursor = cursor.max(keep.end.raw()).min(range.end.raw());
            if cursor == range.end.raw() {
                break;
            }
        }
        if cursor < range.end.raw() {
            result.push(
                carrick_guest_mem::HostVa(cursor)..carrick_guest_mem::HostVa(range.end.raw()),
            );
        }
    }
    result
}

impl NativeMappedMemory {
    fn address_mode(&self) -> NativeAddressMode {
        self.address_mode
    }

    fn host_address(
        &self,
        address: carrick_guest_mem::GuestVa,
    ) -> Result<carrick_guest_mem::HostVa, MemoryError> {
        self.address_mode
            .to_host(address)
            .map_err(|error| MemoryError::HostMap(error.to_string()))
    }

    fn guest_fault_address(
        &self,
        address: carrick_guest_mem::HostVa,
    ) -> Option<carrick_guest_mem::GuestVa> {
        if matches!(self.address_mode, NativeAddressMode::Biased { .. }) {
            if !self
                .owned_host_ranges
                .iter()
                .any(|range| address >= range.start && address < range.end)
            {
                return None;
            }
            return self.address_mode.to_guest(address).ok();
        }
        let guest = self.address_mode.to_guest(address).ok()?;
        self.region_contains(guest.raw(), 1).then_some(guest)
    }

    fn dsr_process_translator(&self) -> Result<Arc<dsr::ProcessTranslator>, RuntimeError> {
        self.dsr_translator.as_ref().map(Arc::clone).ok_or_else(|| {
            RuntimeError::Unsupported(
                "native DSR process translator is unavailable outside DSR mode".to_string(),
            )
        })
    }

    fn note_dsr_code_mutation(
        &self,
        address: u64,
        len: usize,
    ) -> Result<Option<dsr::types::CodeGeneration>, MemoryError> {
        if len == 0 {
            return Ok(None);
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        self.dsr_generations
            .note_guest_code_write(
                carrick_guest_mem::GuestVa(address)..carrick_guest_mem::GuestVa(end),
            )
            .map(Some)
            .map_err(|error| MemoryError::HostMap(error.to_string()))
    }

    fn dsr_generation_observation(
        &self,
        pc: carrick_guest_mem::GuestVa,
    ) -> Result<dsr::cache::PageGenerationObservation, dsr::types::DsrError> {
        self.dsr_generations.observe(pc)
    }

    fn range_may_execute(&self, address: u64, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let end = address.saturating_add(len as u64);
        let mut page = address & !(self.host_page_size - 1);
        while page < end {
            let prot = self
                .native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(page));
            if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                return true;
            }
            page = page.saturating_add(self.host_page_size);
        }
        false
    }

    #[cfg(test)]
    fn map(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
    ) -> Result<Self, RuntimeError> {
        Self::map_with_translator(image, layout, host_page_size, linux_page_size, None, None)
    }

    fn map_for_plan(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        _plan: &ExecutionPlan,
        relative_relocations: &[NativeRelativeRelocation],
    ) -> Result<Self, RuntimeError> {
        let native_layout = NativeLayout::for_image(image, layout, host_page_size)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            image,
            layout,
            NativeMappingPageSizes {
                host: host_page_size,
                linux: linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: None,
                exec_map_dsr_tid: None,
                relative_relocations,
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn map_prepared_for_plan(
        prepared: &ValidatedPreparedImage,
        layout: MemoryLayout,
        plan: &ExecutionPlan,
    ) -> Result<Self, RuntimeError> {
        let native_layout =
            NativeLayout::for_image(&prepared.image, layout, plan.page_geometry.host_page_size)
                .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            &prepared.image,
            layout,
            NativeMappingPageSizes {
                host: plan.page_geometry.host_page_size,
                linux: plan.page_geometry.linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: None,
                exec_map_dsr_tid: None,
                relative_relocations: &prepared.relocations,
                backing: NativeImageBacking::Prepared(prepared),
                rollback_plan,
            },
        )
    }

    #[cfg(test)]
    fn map_with_translator(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        reusable_translator: Option<Arc<dsr::ProcessTranslator>>,
        exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    ) -> Result<Self, RuntimeError> {
        let native_layout = NativeLayout::for_image(image, layout, host_page_size)
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let rollback_plan = NativeMappingRollbackPlan::for_fresh_layout(&native_layout);
        Self::map_with_layout(
            image,
            layout,
            NativeMappingPageSizes {
                host: host_page_size,
                linux: linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator,
                exec_map_dsr_tid,
                relative_relocations: &[],
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )
    }

    fn map_with_layout(
        image: &AddressSpace,
        layout: MemoryLayout,
        page_sizes: NativeMappingPageSizes,
        native_layout: NativeLayout,
        options: NativeMappingOptions<'_>,
    ) -> Result<Self, RuntimeError> {
        let NativeMappingOptions {
            reusable_translator,
            exec_map_dsr_tid,
            relative_relocations,
            backing,
            rollback_plan,
        } = options;
        native_exec_map_profile_start(exec_map_dsr_tid);
        let mut regions = Vec::new();
        let mut rollback =
            NativeMappingRollback::new(rollback_plan, page_sizes.host, image.regions().len() + 5)?;
        let prepared_region_mappings = match backing {
            NativeImageBacking::AnonymousBytes => None,
            NativeImageBacking::Prepared(prepared) => {
                native_reexec_lifecycle(
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                );
                let mappings = image
                    .regions()
                    .iter()
                    .enumerate()
                    .map(|(region_index, region)| {
                        let file_backing = prepared
                            .backings
                            .get(region_index)
                            .copied()
                            .ok_or_else(|| {
                                RuntimeError::Unsupported(format!(
                                    "prepared-map: missing file backing for region {region_index}"
                                ))
                            })?;
                        map_prepared_region_extent(
                            region_index,
                            region,
                            file_backing,
                            prepared,
                            exec_map_dsr_tid,
                            &native_layout,
                            &mut rollback,
                        )
                    })
                    .collect::<Result<Vec<_>, RuntimeError>>()?;
                native_reexec_lifecycle(
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
                );
                Some(mappings)
            }
        };
        for (region_index, region) in image.regions().iter().enumerate() {
            match backing {
                NativeImageBacking::AnonymousBytes => map_region(
                    region,
                    exec_map_dsr_tid,
                    image.initial_stack_pointer(),
                    &native_layout,
                    &mut rollback,
                )?,
                NativeImageBacking::Prepared(_) => {
                    let mapped = prepared_region_mappings
                        .as_ref()
                        .and_then(|mappings| mappings.get(region_index))
                        .ok_or_else(|| {
                            RuntimeError::Unsupported(format!(
                                "prepared-map: missing mapped region {region_index}"
                            ))
                        })?;
                    finalize_image_region_mapping(
                        region,
                        mapped.mapped,
                        mapped.mapped_length,
                        mapped.logical_length,
                        exec_map_dsr_tid,
                        true,
                    )?;
                }
            };
            if region.start == NATIVE_DARWIN_VDSO_BASE && region.perms.execute {
                native_exec_map_detail(
                    exec_map_dsr_tid,
                    crate::probes::DsrCacheLifecyclePhase::ExecMapVvarBegin,
                    region.len(),
                );
                relocate_vdso_vvar_loads(region, &native_layout)?;
                native_exec_map_detail(
                    exec_map_dsr_tid,
                    crate::probes::DsrCacheLifecyclePhase::ExecMapVvarEnd,
                    0,
                );
            }
            regions.push(NativeMappedRegion {
                start: region.start,
                end: region.end,
                host_protects: true,
                shared_futex: false,
                guest_writable: region.perms.write,
                default_prot: native_region_linux_prot(
                    region.perms.read,
                    region.perms.write,
                    region.perms.execute,
                ),
                shared_key_base: 0,
                shared_key_offset: 0,
            });
        }
        map_bytes_region(
            NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            &carrick_mem::memory::sigreturn_trampoline_bytes(),
            NativeByteRegionOptions {
                final_prot: libc::PROT_READ | libc::PROT_EXEC,
                executable: true,
                exec_map_dsr_tid,
            },
            &native_layout,
            &mut rollback,
        )?;
        regions.push(NativeMappedRegion {
            start: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            end: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
                + carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            host_protects: true,
            shared_futex: false,
            guest_writable: false,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            layout.heap_size,
        );
        map_anonymous_region(
            layout.heap_base,
            layout.heap_size,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: layout.heap_base,
            end: checked_add_u64(layout.heap_base, layout.heap_size, "native heap end")?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            layout.mmap_size,
        );
        map_anonymous_region(
            layout.mmap_base,
            layout.mmap_size,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: layout.mmap_base,
            end: checked_add_u64(layout.mmap_base, layout.mmap_size, "native mmap arena end")?,
            host_protects: true,
            shared_futex: false,
            guest_writable: true,
            default_prot: if page_sizes.linux == page_sizes.host {
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE
            } else {
                0
            },
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            crate::memory::LINUX_SHARED_FILE_SIZE,
        );
        map_anonymous_region(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE,
            true,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_SHARED_FILE_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                "native shared aperture end",
            )?,
            host_protects: true,
            shared_futex: true,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
        );
        map_anonymous_region(
            crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            false,
            &native_layout,
            &mut rollback,
        )?;
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
            0,
        );
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                "native private overlay aperture end",
            )?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        let protections = MemoryProtections::default();
        for span in image.ro_spans() {
            let _span_end = checked_add_u64(span.start, span.len, "read-only ELF span end")?;
            let len = usize::try_from(span.len).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin read-only ELF span too large: 0x{:x}+0x{:x}",
                    span.start, span.len
                ))
            })?;
            protections.set_no_write(span.start, len, true);
        }
        let address_mode = native_layout.address_mode();
        let owned_host_ranges = native_layout.owned_ranges().to_vec();
        let setup: Result<Self, RuntimeError> = (|| {
            let mut memory = Self {
                address_mode,
                owned_host_ranges,
                regions,
                protections,
                native_page_protections: BTreeMap::new(),
                native_write_exec_writable_pages: BTreeSet::new(),
                linux4k_page_protections: BTreeMap::new(),
                exclusive_reservation: None,
                exclusive_sequences: BTreeMap::new(),
                host_page_size: page_sizes.host,
                linux_page_size: page_sizes.linux,
                dsr_generations: dsr::cache::PageGenerationTable::new(page_sizes.host)
                    .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
                dsr_translator: if let Some(translator) = reusable_translator {
                    Some(translator)
                } else {
                    Some(Arc::new(
                        dsr::ProcessTranslator::new(64 * 1024 * 1024)
                            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
                    ))
                },
            };
            // Publishing the vvar contents is part of establishing the address
            // space: the initial boot maps here, and an execve replacement re-maps
            // here (`replace_image`), so both get a freshly stamped vvar.
            native_exec_map_detail(
                exec_map_dsr_tid,
                crate::probes::DsrCacheLifecyclePhase::ExecMapVvarBegin,
                crate::vdso::LINUX_VVAR_SIZE,
            );
            #[cfg(test)]
            if backing.is_prepared()
                && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::VvarStamp)
            {
                return Err(RuntimeError::Unsupported(
                    "prepared-map: injected vvar stamping failure".to_string(),
                ));
            }
            memory.stamp_vdso_vvar()?;
            native_exec_map_detail(
                exec_map_dsr_tid,
                crate::probes::DsrCacheLifecyclePhase::ExecMapVvarEnd,
                0,
            );
            #[cfg(test)]
            if backing.is_prepared()
                && take_native_prepared_mapping_failpoint(
                    NativePreparedMappingFailpoint::Relocation,
                )
            {
                return Err(RuntimeError::Unsupported(
                    "prepared-map: injected relocation failure".to_string(),
                ));
            }
            apply_native_relative_relocations(&mut memory, relative_relocations)?;
            #[cfg(test)]
            if exec_map_dsr_tid.is_some()
                && NATIVE_TEST_FAIL_EXEC_AFTER_SETUP.with(|failpoint| failpoint.replace(false))
            {
                return Err(RuntimeError::Unsupported(
                    "injected native exec failure after target mapping, vvar setup, and relocations"
                        .to_string(),
                ));
            }
            Ok(memory)
        })();
        let memory = native_layout.commit_if_ok(setup)?;
        rollback.commit();
        native_exec_map_profile_finish();
        Ok(memory)
    }

    /// Publish the vvar data page (RNG generation + clock calibration) for a
    /// freshly mapped image — the native counterpart of the HVF vvar stamper
    /// (`populate_vdso_data_page` in carrick-vmm-hvf/src/trap.rs). It uses the
    /// same calibration sources and publishes the SAME realtime offset via
    /// [`crate::vdso::set_realtime_off_ns`], so the userspace vDSO fast paths
    /// and the trapping syscall clock paths cannot drift apart
    /// (clock_gettime04 coherence). No-op when the image carries no vDSO
    /// (CARRICK_DISABLE_VDSO).
    ///
    /// Natively the guest's `mrs cntvct_el0` reads the HOST counter directly
    /// (there is no CNTVOFF virtualization), so this stamping is correct only
    /// while the raw counter and CLOCK_UPTIME_RAW share one timeline on the
    /// host. That equivalence is gated empirically by the
    /// `native_el0_counter_reads_track_clock_uptime_raw` test below.
    fn stamp_vdso_vvar(&self) -> Result<(), RuntimeError> {
        if !self.vvar_region_is_mapped() {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(words) = NATIVE_TEST_VVAR_WORDS.with(|slot| slot.borrow().clone()) {
            return self.write_vvar_words(&words);
        }
        // RNG generation first and unconditionally (getrandom needs no
        // calibrated counter): this process's host PID, unique per process and
        // re-stamped in a forked child, so the userspace getrandom blob
        // reseeds instead of reusing a COW-inherited keystream.
        let pid = unsafe { libc::getpid() } as u64;
        let mut words = vec![(crate::vdso::VVAR_OFF_RNG_GENERATION, pid)];
        let (freq, mono_ns) = native_vvar_clock_sources();
        if freq != 0 {
            let unix_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let realtime_off = unix_ns.wrapping_sub(mono_ns);
            crate::vdso::set_realtime_off_ns(realtime_off);
            words.push((crate::vdso::VVAR_OFF_FREQ, freq));
            words.push((crate::vdso::VVAR_OFF_REALTIME_OFF_NS, realtime_off));
        }
        self.write_vvar_words(&words)
    }

    /// Re-stamp the vvar RNG generation with THIS process's PID — the native
    /// fork-child counterpart of the HVF child-side re-stamp in `fork_rebuild`.
    /// The child's distinct generation forces the userspace getrandom blob to
    /// reseed instead of replaying the parent's keystream (gated by the
    /// getrandomvdsofork probe). No-op when the vDSO is disabled.
    fn restamp_vdso_rng_generation_after_fork(&self) -> Result<(), RuntimeError> {
        if !self.vvar_region_is_mapped() {
            return Ok(());
        }
        let pid = unsafe { libc::getpid() } as u64;
        self.write_vvar_words(&[(crate::vdso::VVAR_OFF_RNG_GENERATION, pid)])
    }

    fn vvar_region_is_mapped(&self) -> bool {
        self.region_contains(
            NATIVE_DARWIN_VVAR_BASE,
            crate::vdso::LINUX_VVAR_SIZE as usize,
        )
    }

    /// Write little-endian u64s into the vvar data page. The vvar is mapped
    /// read-only for the guest, so the containing host page flips writable for
    /// the duration of the write. Every caller runs before guest code can
    /// observe the page (boot mapping, execve replacement, a fresh
    /// single-threaded fork child), so the transient writability is invisible.
    fn write_vvar_words(&self, words: &[(usize, u64)]) -> Result<(), RuntimeError> {
        let vvar_end = NATIVE_DARWIN_VVAR_BASE + crate::vdso::LINUX_VVAR_SIZE;
        let (page_start, page_len) = self
            .host_page_range(NATIVE_DARWIN_VVAR_BASE, vvar_end)
            .map_err(|_| {
                RuntimeError::Unsupported("native Darwin vvar page range overflow".to_string())
            })?;
        let page_ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            .raw() as *mut libc::c_void;
        if unsafe { libc::mprotect(page_ptr, page_len, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            return Err(last_io_error("mprotect native Darwin vvar page writable"));
        }
        for &(offset, value) in words {
            debug_assert!(
                offset + std::mem::size_of::<u64>() <= crate::vdso::LINUX_VVAR_SIZE as usize
            );
            let address = NATIVE_DARWIN_VVAR_BASE + offset as u64;
            let bytes = value.to_le_bytes();
            // SAFETY: the vvar region is mapped at its fixed VA (checked by the
            // callers via vvar_region_is_mapped) and was just made writable.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.host_address(carrick_guest_mem::GuestVa(address))
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
                        .raw() as *mut u8,
                    bytes.len(),
                );
            }
        }
        if unsafe { libc::mprotect(page_ptr, page_len, libc::PROT_READ) } != 0 {
            return Err(last_io_error("restore native Darwin vvar page read-only"));
        }
        Ok(())
    }

    fn set_fork_inheritance(&self, share: bool) {
        let trace = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
        for region in &self.regions {
            if region.shared_futex || !region.guest_writable {
                continue;
            }
            let Ok(start) = self.host_address(carrick_guest_mem::GuestVa(region.start)) else {
                continue;
            };
            let Ok(len) = usize::try_from(region.end.saturating_sub(region.start)) else {
                continue;
            };
            let changed =
                set_native_region_fork_inheritance(start.raw() as *mut libc::c_void, len, share);
            if trace {
                child_write_stderr(
                    format!(
                        "native trace pid={} fork-inherit share={} start=0x{:x} end=0x{:x} changed={}\n",
                        unsafe { libc::getpid() },
                        share,
                        region.start,
                        region.end,
                        changed
                    )
                    .as_bytes(),
                );
            }
        }
    }

    fn prepare_exec_mapping(
        &self,
        image: &AddressSpace,
        plan: &ExecutionPlan,
    ) -> Result<PreparedNativeExecMapping, RuntimeError> {
        let native_layout = NativeLayout::for_exec(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            &self.owned_host_ranges,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let target_only = if matches!(native_layout.address_mode(), NativeAddressMode::Direct) {
            // Every Carrick-owned overlap can transfer continuously into a
            // Direct replacement, regardless of the source address mode.
            // External mappings remain in target_only and fail the screen.
            subtract_host_ranges(native_layout.owned_ranges(), &self.owned_host_ranges)
        } else {
            Vec::new()
        };
        let mut direct_target_reservations = Vec::with_capacity(target_only.len());
        let mut direct_reservation_ranges = Vec::with_capacity(target_only.len());
        let reset_inherited_translator =
            NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire);
        let process_translator = if reset_inherited_translator {
            self.dsr_process_translator()?
        } else {
            Arc::new(
                dsr::ProcessTranslator::new(64 * 1024 * 1024)
                    .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
            )
        };
        // This is the final pre-PONR screen. The layout, target-only range
        // vector, reservation-vector capacity, and replacement MAP_JIT cache
        // are all allocated first. Each allocatable interval becomes an exact
        // PROT_NONE guard; only the measured dyld delegated shared-pmap empty
        // covering tuple may proceed without one. No allocator or mmap may run
        // after this loop before old-image retirement.
        for range in &target_only {
            let length = range
                .end
                .raw()
                .checked_sub(range.start.raw())
                .ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native direct exec target range is inverted: 0x{:x}..0x{:x}",
                        range.start.raw(),
                        range.end.raw()
                    ))
                })? as u64;
            match crate::host_proc::reserve_self_direct_vm_range(range.start.raw() as u64, length)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            {
                crate::host_proc::DirectVmReservationOutcome::Reserved(reservation) => {
                    for (start, length) in reservation.owned_spans() {
                        let end = start.checked_add(length).ok_or_else(|| {
                            RuntimeError::Unsupported(format!(
                                "native direct exec reservation range overflows: 0x{start:x}+0x{length:x}"
                            ))
                        })?;
                        direct_reservation_ranges.push(
                            carrick_guest_mem::HostVa(usize::try_from(start).map_err(|_| {
                                RuntimeError::Unsupported(format!(
                                    "native direct exec reservation start is not representable: 0x{start:x}"
                                ))
                            })?)
                                ..carrick_guest_mem::HostVa(usize::try_from(end).map_err(|_| {
                                    RuntimeError::Unsupported(format!(
                                        "native direct exec reservation end is not representable: 0x{end:x}"
                                    ))
                                })?),
                        );
                    }
                    direct_target_reservations.push(reservation);
                }
                crate::host_proc::DirectVmReservationOutcome::DelegatedDyldPmapEmpty => {}
            }
        }
        let rollback_plan = match native_layout.address_mode() {
            NativeAddressMode::Direct => NativeMappingRollbackPlan::direct_exec(
                native_layout.owned_ranges(),
                direct_reservation_ranges,
            ),
            NativeAddressMode::Biased { .. } => NativeMappingRollbackPlan {
                supplemental_ranges: Vec::new(),
            },
        };
        Ok(PreparedNativeExecMapping {
            native_layout,
            process_translator,
            reset_inherited_translator,
            direct_target_reservations,
            rollback_plan,
        })
    }

    fn replace_image(
        &mut self,
        image: &AddressSpace,
        relative_relocations: &[NativeRelativeRelocation],
        plan: &ExecutionPlan,
        dsr_tid: Option<crate::thread::ThreadId>,
        mut prepared: PreparedNativeExecMapping,
    ) -> Result<(), RuntimeError> {
        let lifecycle = |phase| {
            if let Some(tid) = dsr_tid {
                crate::probes::dsr_cache_lifecycle(tid.raw(), phase, 0, 0, 0);
            }
        };
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageUnmapBegin);
        if self.owned_host_ranges.is_empty() {
            return Err(RuntimeError::Unsupported(
                "native Darwin execve cannot retire an address space without owned host ranges"
                    .to_string(),
            ));
        }
        let retained_target_ranges = prepared.native_layout.owned_ranges();
        let retired_ranges = subtract_host_ranges(&self.owned_host_ranges, retained_target_ranges);
        // Everything above remains pre-PONR: it may validate and allocate,
        // and dropping `prepared` must leave the authoritative old image
        // untouched. From here onward replacement may retire or overwrite old
        // mappings, so arm the already-allocated reusable guards in place.
        // Any subsequent failure is fatal and the new layout becomes the sole
        // rollback owner for those transferred intervals.
        prepared.native_layout.arm_prepared_adoptions();
        for range in &retired_ranges {
            let start = range.start.raw();
            let end = range.end.raw();
            let len = end.checked_sub(start).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve owned range is inverted: 0x{start:x}..0x{end:x}"
                ))
            })?;
            if len != 0 && unsafe { libc::munmap(start as *mut libc::c_void, len) } != 0 {
                return Err(last_io_error(&format!(
                    "munmap native Darwin execve owned range 0x{start:x}..0x{end:x}"
                )));
            }
        }
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageUnmapEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageMapBegin);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecRelocationBegin);
        let PreparedNativeExecMapping {
            native_layout,
            process_translator,
            reset_inherited_translator,
            direct_target_reservations,
            rollback_plan,
        } = prepared;
        native_layout
            .reset_biased_aperture_to_guards()
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
        let inherited_translator =
            reset_inherited_translator.then(|| Arc::clone(&process_translator));
        let replacement = Self::map_with_layout(
            image,
            native_memory_layout(),
            NativeMappingPageSizes {
                host: plan.page_geometry.host_page_size,
                linux: plan.page_geometry.linux_page_size,
            },
            native_layout,
            NativeMappingOptions {
                reusable_translator: Some(process_translator),
                exec_map_dsr_tid: dsr_tid,
                relative_relocations,
                backing: NativeImageBacking::AnonymousBytes,
                rollback_plan,
            },
        )?;
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecRelocationEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecImageMapEnd);
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecCacheResetBegin);
        if let Some(translator) = inherited_translator {
            // A fork child cannot allocate a fresh JIT cache safely, so exec
            // reuses its inherited mapping. Keep the old cache intact until
            // the complete replacement image is mapped and relocated; only
            // then clear its inherited publications before the thread-level
            // handoff can execute the new image.
            translator.reset_after_fork_for_exec();
        }
        for reservation in direct_target_reservations {
            reservation.commit();
        }
        lifecycle(crate::probes::DsrCacheLifecyclePhase::ExecCacheResetEnd);
        *self = replacement;
        Ok(())
    }

    fn region_contains(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        self.regions
            .iter()
            .any(|region| address >= region.start && end <= region.end)
    }

    fn host_protected_overlaps(
        &self,
        address: u64,
        length: usize,
    ) -> impl Iterator<Item = (u64, u64)> + '_ {
        let end = address.saturating_add(length as u64);
        let linux4k = self.uses_linux4k_subpages();
        self.regions
            .iter()
            .filter(move |region| {
                (linux4k || region.host_protects) && address < region.end && region.start < end
            })
            .map(move |region| (address.max(region.start), end.min(region.end)))
    }

    fn host_page_range(&self, start: u64, end: u64) -> Result<(u64, usize), MemoryError> {
        let page_size = self.host_page_size;
        let page_start = start & !(page_size - 1);
        let page_end = end
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address: start,
                length: usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX),
            })?;
        let len = usize::try_from(page_end.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address: start,
                length: usize::MAX,
            }
        })?;
        Ok((page_start, len))
    }

    fn uses_linux4k_subpages(&self) -> bool {
        self.host_page_size == 16 * 1024 && self.linux_page_size == 4 * 1024
    }

    fn native16k_write_exec_page(&self, address: u64) -> Option<u64> {
        if self.uses_linux4k_subpages()
            || !self.regions.iter().any(|region| {
                region.host_protects && address >= region.start && address < region.end
            })
        {
            return None;
        }
        let page_start = address & !(self.host_page_size - 1);
        let prot = self
            .native_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| self.default_linux_prot_at(address));
        let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
        (prot & write_exec == write_exec).then_some(page_start)
    }

    fn has_native16k_write_exec_pages(&self) -> bool {
        if self.host_page_size != 16 * 1024 || self.linux_page_size != self.host_page_size {
            return false;
        }
        let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
        self.native_page_protections
            .values()
            .copied()
            .chain(self.regions.iter().map(|region| region.default_prot))
            .any(|prot| prot & write_exec == write_exec)
    }

    fn write_exec_blocks_multithreaded_lifecycle(&self) -> bool {
        false
    }

    fn native16k_clone_thread_rejection(&self) -> Option<&'static str> {
        None
    }

    fn native16k_vfork_rejection(&self) -> Option<&'static str> {
        self.has_native16k_write_exec_pages().then_some(
            "native16k cannot vfork while write-exec pages are present because vfork shares writable mappings",
        )
    }

    fn make_native16k_write_exec_page_writable(
        &mut self,
        page_start: u64,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        if self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(());
        }
        self.note_dsr_code_mutation(page_start, self.host_page_size as usize)?;
        self.mprotect_host_page(
            page_start,
            libc::PROT_READ | libc::PROT_WRITE,
            operation_address,
            operation_len,
        )?;
        self.native_write_exec_writable_pages.insert(page_start);
        Ok(())
    }

    fn make_native16k_write_exec_page_executable(
        &mut self,
        page_start: u64,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        if !self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(());
        }
        let page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address: operation_address,
                length: operation_len,
            })?;
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))?
            .raw() as *mut u8;
        unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
        let prot = self
            .native_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| self.default_linux_prot_at(page_start));
        self.mprotect_host_page(
            page_start,
            native16k_host_prot(prot),
            operation_address,
            operation_len,
        )?;
        self.native_write_exec_writable_pages.remove(&page_start);
        Ok(())
    }

    fn prepare_dsr_execution(&mut self, pc: u64) -> Result<(), MemoryError> {
        let Some(page_start) = self.native16k_write_exec_page(pc) else {
            return Ok(());
        };
        self.make_native16k_write_exec_page_executable(page_start, pc, self.host_page_size as usize)
    }

    fn prepare_native16k_write_exec_host_write(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        if len == 0 || self.uses_linux4k_subpages() {
            return Ok(());
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut page = address & !(self.host_page_size - 1);
        while page < end {
            if self.native16k_write_exec_page(page).is_some() {
                self.make_native16k_write_exec_page_writable(page, address, len)?;
            }
            page = page.saturating_add(self.host_page_size);
        }
        Ok(())
    }

    fn resolve_native16k_write_exec_fault(
        &mut self,
        fault_address: u64,
        pc: u64,
        esr: u64,
    ) -> Result<bool, RuntimeError> {
        let Some(page_start) = self.native16k_write_exec_page(fault_address) else {
            return Ok(false);
        };
        let ec = (esr >> 26) & 0x3f;
        let fault_status = esr & 0x3f;
        if !matches!(fault_status, 0x0c..=0x0f) {
            return Ok(false);
        }
        if matches!(ec, 0x20 | 0x21) {
            if !self.native_write_exec_writable_pages.contains(&page_start) {
                return Ok(false);
            }
            self.make_native16k_write_exec_page_executable(
                page_start,
                fault_address,
                self.host_page_size as usize,
            )
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native16k could not make guest write-exec page 0x{page_start:x} executable: {error}"
                ))
            })?;
            return Ok(true);
        }
        let write_data_abort = matches!(ec, 0x24 | 0x25) && esr & (1 << 6) != 0;
        if !write_data_abort || self.native_write_exec_writable_pages.contains(&page_start) {
            return Ok(false);
        }
        let pc_page = pc & !(self.host_page_size - 1);
        if pc_page == page_start {
            return Err(RuntimeError::Unsupported(format!(
                "native16k cannot write a guest RWX page while executing from the same 16K host page at pc=0x{pc:x} addr=0x{fault_address:x}"
            )));
        }
        self.make_native16k_write_exec_page_writable(
            page_start,
            fault_address,
            self.host_page_size as usize,
        )
        .map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native16k could not make guest write-exec page 0x{page_start:x} writable: {error}"
            ))
        })?;
        Ok(true)
    }

    fn default_linux_prot_at(&self, address: u64) -> u64 {
        self.regions
            .iter()
            .rev()
            .find(|region| address >= region.start && address < region.end)
            .map_or(0, |region| region.default_prot)
    }

    fn guest_address_is_executable(&self, address: u64) -> bool {
        let prot = if self.uses_linux4k_subpages() {
            let host_page = address & !(self.host_page_size - 1);
            let subpage = ((address - host_page) / self.linux_page_size) as usize;
            self.linux4k_host_page_protections(host_page)
                .get(subpage)
                .copied()
                .unwrap_or(0)
        } else {
            let page = address & !(self.host_page_size - 1);
            self.native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(address))
        };
        prot & crate::linux_abi::LINUX_PROT_EXEC != 0
    }

    fn native_range_allows(&self, address: u64, len: usize, write: bool) -> bool {
        if len == 0 {
            return false;
        }
        if self.uses_linux4k_subpages() {
            return self.linux4k_range_allows(address, len, write);
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        let required = if write {
            crate::linux_abi::LINUX_PROT_WRITE
        } else {
            crate::linux_abi::LINUX_PROT_READ
        };
        let mut cursor = address;
        while cursor < end {
            let page = cursor & !(self.host_page_size - 1);
            let prot = self
                .native_page_protections
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(cursor));
            if prot & required == 0 {
                return false;
            }
            cursor = page.saturating_add(self.host_page_size).min(end);
        }
        true
    }

    fn linux4k_host_page_protections(&self, page_start: u64) -> [u64; 4] {
        self.linux4k_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| {
                std::array::from_fn(|index| {
                    self.default_linux_prot_at(
                        page_start.saturating_add(index as u64 * self.linux_page_size),
                    )
                })
            })
    }

    fn classify_linux4k_host_page(&self, protections: [u64; 4]) -> HostPageState {
        let subpages = protections.map(|prot| {
            SubpageState::new(
                PageBacking::Anonymous,
                PagePerms {
                    read: prot & crate::linux_abi::LINUX_PROT_READ != 0,
                    write: prot & crate::linux_abi::LINUX_PROT_WRITE != 0,
                    exec: prot & crate::linux_abi::LINUX_PROT_EXEC != 0,
                },
            )
        });
        classify_host_page_state(
            crate::page_profile::PageGeometry {
                host_page_size: self.host_page_size,
                linux_page_size: self.linux_page_size,
                native_profile: Some(carrick_spec::NativePageProfile::Linux4kOn16k),
            },
            subpages,
        )
    }

    fn linux4k_range_allows(&self, address: u64, len: usize, write: bool) -> bool {
        if !self.uses_linux4k_subpages() || len == 0 {
            return false;
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        let required = if write {
            crate::linux_abi::LINUX_PROT_WRITE
        } else {
            crate::linux_abi::LINUX_PROT_READ
        };
        let mut cursor = address;
        while cursor < end {
            let host_page = cursor & !(self.host_page_size - 1);
            let subpage = ((cursor - host_page) / self.linux_page_size) as usize;
            let protections = self.linux4k_host_page_protections(host_page);
            if protections
                .get(subpage)
                .is_none_or(|prot| prot & required == 0)
            {
                return false;
            }
            let next = (cursor & !(self.linux_page_size - 1)).saturating_add(self.linux_page_size);
            cursor = next.min(end);
        }
        true
    }

    fn invalidate_exclusive_range(&mut self, address: u64, len: usize) {
        let end = address.checked_add(len as u64);
        if let Some(end) = end {
            // DSR exclusive locations are scalar 1/2/4/8-byte accesses. An
            // overlapping key can therefore start no earlier than address-7
            // and strictly before the write end. Range the ordered map by that
            // window rather than walking every exclusive location ever seen:
            // Go's compiler issues DC ZVA continuously, and the old O(total
            // locations) scan turned each 64-byte zero into a workload-wide
            // traversal after a few thousand mutex addresses had accumulated.
            let lower = NativeExclusiveLocation {
                address: address.saturating_sub(7),
                width: 0,
            };
            let upper = NativeExclusiveLocation {
                address: end,
                width: 0,
            };
            for (location, sequence) in self.exclusive_sequences.range_mut(lower..upper) {
                let location_end = location.address.saturating_add(location.width as u64);
                if address < location_end {
                    *sequence = sequence.next();
                }
            }
        } else {
            // An overflowing host-mediated write is rejected by its caller,
            // but conservatively invalidate every tracked reservation before
            // that error returns.
            for sequence in self.exclusive_sequences.values_mut() {
                *sequence = sequence.next();
            }
        }
        let Some(reservation) = self.exclusive_reservation else {
            return;
        };
        let Some(end) = address.checked_add(len as u64) else {
            self.exclusive_reservation = None;
            return;
        };
        let Some(reservation_end) = reservation
            .location
            .address
            .checked_add(reservation.location.width as u64)
        else {
            self.exclusive_reservation = None;
            return;
        };
        if address < reservation_end && reservation.location.address < end {
            self.exclusive_reservation = None;
        }
    }

    fn atomic_load(&self, address: u64, width: usize) -> Result<u64, MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        let observed = unsafe {
            match width {
                1 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                2 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                4 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                        .load(std::sync::atomic::Ordering::Acquire),
                ),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .load(std::sync::atomic::Ordering::Acquire),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(observed)
    }

    fn atomic_store(&mut self, address: u64, width: usize, value: u64) -> Result<(), MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        self.invalidate_exclusive_range(address, width);
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        unsafe {
            match width {
                1 => (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                    .store(value as u8, std::sync::atomic::Ordering::Release),
                2 => (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                    .store(value as u16, std::sync::atomic::Ordering::Release),
                4 => (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                    .store(value as u32, std::sync::atomic::Ordering::Release),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .store(value, std::sync::atomic::Ordering::Release),
            }
        }
        self.restore_temporary_host_access(&changed, address, width)
    }

    fn atomic_fetch_add(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
        ordering: std::sync::atomic::Ordering,
    ) -> Result<u64, MemoryError> {
        if !matches!(width, 1 | 2 | 4 | 8)
            || !address.is_multiple_of(width as u64)
            || !self.region_contains(address, width)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        self.invalidate_exclusive_range(address, width);
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        let observed = unsafe {
            match width {
                1 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU8>()).fetch_add(value as u8, ordering),
                ),
                2 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                        .fetch_add(value as u16, ordering),
                ),
                4 => u64::from(
                    (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                        .fetch_add(value as u32, ordering),
                ),
                _ => (&*ptr.cast::<std::sync::atomic::AtomicU64>()).fetch_add(value, ordering),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(observed)
    }

    fn exclusive_load(
        &mut self,
        address: u64,
        width: usize,
        acquire: bool,
    ) -> Result<u64, MemoryError> {
        let mut reservation = self.exclusive_reservation.take();
        let result = self.exclusive_load_for(address, width, acquire, &mut reservation);
        self.exclusive_reservation = reservation;
        result
    }

    fn exclusive_load_for(
        &mut self,
        address: u64,
        width: usize,
        acquire: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<u64, MemoryError> {
        if !address.is_multiple_of(width as u64) || !self.region_contains(address, width) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let ordering = if acquire {
            std::sync::atomic::Ordering::Acquire
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let observed = unsafe {
            match width {
                1 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU8>()).load(ordering)),
                2 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU16>()).load(ordering)),
                4 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU32>()).load(ordering)),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>()).load(ordering),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        let location = NativeExclusiveLocation { address, width };
        let sequence = *self
            .exclusive_sequences
            .entry(location)
            .or_insert(NativeExclusiveSequence::INITIAL);
        *reservation = Some(NativeExclusiveReservation {
            location,
            observed,
            sequence,
        });
        Ok(observed)
    }

    fn exclusive_store(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
        release: bool,
    ) -> Result<bool, MemoryError> {
        let mut reservation = self.exclusive_reservation.take();
        let result = self.exclusive_store_for(address, width, value, release, &mut reservation);
        self.exclusive_reservation = reservation;
        result
    }

    fn exclusive_store_for(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
        release: bool,
        reservation: &mut Option<NativeExclusiveReservation>,
    ) -> Result<bool, MemoryError> {
        let Some(reservation) = reservation.take() else {
            return Ok(false);
        };
        let location = NativeExclusiveLocation { address, width };
        let sequence = self
            .exclusive_sequences
            .get(&location)
            .copied()
            .unwrap_or(NativeExclusiveSequence::INITIAL);
        if reservation.location != location || reservation.sequence != sequence {
            return Ok(false);
        }
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let success = if release {
            std::sync::atomic::Ordering::Release
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let stored = unsafe {
            match width {
                1 => (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                    .compare_exchange(
                        reservation.observed as u8,
                        value as u8,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                2 => (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                    .compare_exchange(
                        reservation.observed as u16,
                        value as u16,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                4 => (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                    .compare_exchange(
                        reservation.observed as u32,
                        value as u32,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .compare_exchange(
                        reservation.observed,
                        value,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        if stored {
            self.exclusive_sequences.insert(location, sequence.next());
        }
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(stored)
    }

    fn linux4k_address_is_guarded(&self, address: u64) -> bool {
        if !self.uses_linux4k_subpages() {
            return false;
        }
        let host_page = address & !(self.host_page_size - 1);
        matches!(
            self.classify_linux4k_host_page(self.linux4k_host_page_protections(host_page)),
            HostPageState::MixedGuarded(_)
                | HostPageState::Composed16k
                | HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage)
        )
    }

    fn native_host_prot_for_page(&self, page_start: u64) -> libc::c_int {
        if !self.uses_linux4k_subpages() {
            let prot = self
                .native_page_protections
                .get(&page_start)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(page_start));
            if self.native_write_exec_writable_pages.contains(&page_start) {
                return libc::PROT_READ | libc::PROT_WRITE;
            }
            return native16k_host_prot(prot);
        }
        let protections = self.linux4k_host_page_protections(page_start);
        match self.classify_linux4k_host_page(protections) {
            HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
            HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
            HostPageState::Unsupported(_) => libc::PROT_NONE,
        }
    }

    fn mprotect_host_page(
        &self,
        page_start: u64,
        host_prot: libc::c_int,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(page_start))?
            .raw() as *mut libc::c_void;
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address: operation_address,
                length: operation_len,
            })?;
        if unsafe { libc::mprotect(ptr, host_page_len, host_prot) } != 0 {
            return Err(MemoryError::HostMap(format!(
                "mprotect native Darwin host page 0x{page_start:x}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn prepare_temporary_host_access(
        &self,
        address: u64,
        len: usize,
        write: bool,
    ) -> Result<Vec<(u64, libc::c_int)>, MemoryError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut changed = Vec::new();
        let required = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        for (start, end) in self.host_protected_overlaps(address, len) {
            let (page_start, page_len) = self.host_page_range(start, end)?;
            let page_end = page_start.saturating_add(page_len as u64);
            let mut page = page_start;
            while page < page_end {
                let restore = self.native_host_prot_for_page(page);
                if restore & required != required {
                    self.mprotect_host_page(page, required, address, len)?;
                    changed.push((page, restore));
                }
                page = page.saturating_add(self.host_page_size);
            }
        }
        Ok(changed)
    }

    fn restore_temporary_host_access(
        &self,
        changed: &[(u64, libc::c_int)],
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        for (page_start, restore) in changed.iter().rev() {
            self.mprotect_host_page(*page_start, *restore, address, len)?;
        }
        Ok(())
    }

    fn protect_linux4k_range(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), MemoryError> {
        if !address.is_multiple_of(self.linux_page_size)
            || !(len as u64).is_multiple_of(self.linux_page_size)
        {
            return Err(MemoryError::Unsupported);
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let first_host_page = address & !(self.host_page_size - 1);
        let last_host_page = end
            .checked_add(self.host_page_size - 1)
            .map(|value| value & !(self.host_page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut plan = Vec::new();
        let mut page_start = first_host_page;
        while page_start < last_host_page {
            let mut protections = self.linux4k_host_page_protections(page_start);
            for (index, subpage_prot) in protections.iter_mut().enumerate() {
                let subpage_start = page_start.saturating_add(index as u64 * self.linux_page_size);
                let subpage_end = subpage_start.saturating_add(self.linux_page_size);
                if address < subpage_end && subpage_start < end {
                    *subpage_prot = prot;
                }
            }
            let state = self.classify_linux4k_host_page(protections);
            let state = match state {
                HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage) => {
                    HostPageState::MixedGuarded(MixedPageReason::ExecutableMixedPage)
                }
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
                state => state,
            };
            plan.push((page_start, protections, state));
            page_start = page_start.saturating_add(self.host_page_size);
        }

        for (page_start, protections, state) in plan {
            let mut host_prot = match state {
                HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
                HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
            };
            if protections
                .iter()
                .any(|value| value & crate::linux_abi::LINUX_PROT_EXEC != 0)
            {
                let ptr = self
                    .host_address(carrick_guest_mem::GuestVa(page_start))?
                    .raw() as *mut u8;
                let page_len =
                    usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
                unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
                host_prot = (host_prot & !libc::PROT_EXEC) | libc::PROT_READ;
            }
            self.mprotect_host_page(page_start, host_prot, address, len)?;
            self.linux4k_page_protections
                .insert(page_start, protections);
        }
        Ok(())
    }

    fn read_u32(&self, address: u64) -> Result<u32, RuntimeError> {
        let bytes = self
            .read_bytes_raw(address, std::mem::size_of::<u32>())
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native Darwin instruction read failed at 0x{address:x}: {error}"
                ))
            })?;
        let word: [u8; 4] = bytes.try_into().map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin instruction read was short at 0x{address:x}"
            ))
        })?;
        Ok(u32::from_le_bytes(word))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), RuntimeError> {
        if !self.region_contains(address, std::mem::size_of::<u64>()) {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin relocation outside mapped guest memory at 0x{address:x}"
            )));
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))
            .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
            .raw() as *mut u64;
        unsafe { std::ptr::write_unaligned(ptr, value) };
        Ok(())
    }

    fn fixed_mapping_target(
        &self,
        guest_start: u64,
        length: usize,
        flags: i32,
    ) -> Result<(carrick_guest_mem::HostVa, i32), MemoryError> {
        let host_start = self.host_address(carrick_guest_mem::GuestVa(guest_start))?;
        let flags = self
            .address_mode
            .fixed_mapping_flags(&self.owned_host_ranges, host_start, length, flags)
            .map_err(|error| MemoryError::HostMap(error.to_string()))?;
        Ok((host_start, flags))
    }

    fn remap_private(
        &mut self,
        address: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        if content.len() != len || !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let (page_start, page_len) = self.host_page_range(address, end)?;
        let (host_start, flags) = self.fixed_mapping_target(
            page_start,
            page_len,
            libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        )?;
        let mut page = self.read_bytes_raw(page_start, page_len)?;
        let offset = usize::try_from(address.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address,
                length: len,
            }
        })?;
        page[offset..offset + len].copy_from_slice(content);

        let ptr = host_start.raw() as *mut libc::c_void;
        let mapped = unsafe {
            libc::mmap(
                ptr,
                page_len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED || mapped != ptr {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(page.as_ptr(), mapped.cast::<u8>(), page.len());
        }
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        address: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
        prot_none: bool,
    ) -> Result<(), RuntimeError> {
        let map_len = align_up_u64(len, self.host_page_size, "native alias length")?;
        let map_len_usize = usize::try_from(map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        if map_len_usize == 0 {
            return Ok(());
        }
        let page_start = address & !(self.host_page_size - 1);
        let page_delta = address.saturating_sub(page_start);
        let host_map_len = align_up_u64(
            page_delta.checked_add(len).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias host length overflow: 0x{address:x}+0x{len:x}"
                ))
            })?,
            self.host_page_size,
            "native alias host length",
        )?;
        let host_map_len_usize = usize::try_from(host_map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        let guest_map_start = if page_delta == 0 { address } else { page_start };

        let (mmap_prot, final_prot, flags, fd, offset, direct_file) = match file {
            Some((fd, offset, prot)) if page_delta == 0 => {
                (prot, prot, libc::MAP_SHARED, fd, offset, true)
            }
            Some((fd, offset, prot)) => (
                libc::PROT_READ | libc::PROT_WRITE,
                prot,
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_NORESERVE,
                fd,
                offset,
                false,
            ),
            None => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
                false,
            ),
        };
        let host_final_prot = native16k_host_prot(final_prot as u64);
        let mmap_prot = if direct_file {
            host_final_prot
        } else {
            mmap_prot
        };
        let mmap_fd = if direct_file { fd } else { -1 };
        let mmap_offset = if direct_file { offset } else { 0 };
        let (host_start, flags) =
            match self.fixed_mapping_target(guest_map_start, host_map_len_usize, flags) {
                Ok(target) => target,
                Err(error) => {
                    if file.is_some() {
                        unsafe { libc::close(fd) };
                    }
                    return Err(RuntimeError::Unsupported(error.to_string()));
                }
            };
        let addr = host_start.raw() as *mut libc::c_void;
        // File-identity futex key material (see `NativeMappedRegion`): only a
        // DIRECT host MAP_SHARED file mapping is physically coherent with an
        // independent mapping of the same file, so only it earns a file key.
        // The pread-copy fallback (unaligned offset) is anon-backed — a file
        // key there would count waiters that no physical wake can reach.
        let (shared_key_base, shared_key_offset) = if direct_file {
            (
                crate::trap::shared_file_key_base(fd),
                u64::try_from(offset).unwrap_or_default(),
            )
        } else {
            (0, 0)
        };
        let mapped = unsafe {
            libc::mmap(
                addr,
                host_map_len_usize,
                mmap_prot,
                flags,
                mmap_fd,
                mmap_offset,
            )
        };
        if mapped != libc::MAP_FAILED && file.is_some() && !direct_file {
            let copy_len = usize::try_from(len).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
                ))
            })?;
            let copy_offset = usize::try_from(page_delta).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias page delta too large: 0x{page_delta:x}"
                ))
            })?;
            let dst = unsafe { mapped.cast::<u8>().add(copy_offset) };
            let mut copied = 0usize;
            while copied < copy_len {
                let rc = unsafe {
                    libc::pread(
                        fd,
                        dst.add(copied).cast::<libc::c_void>(),
                        copy_len - copied,
                        offset.saturating_add(copied as libc::off_t),
                    )
                };
                match rc.host_syscall_errno() {
                    Ok(0) => break,
                    Ok(n) => copied = copied.saturating_add(n as usize),
                    Err(errno) if errno == crate::linux_abi::LINUX_EINTR => {}
                    Err(errno) => {
                        unsafe { libc::close(fd) };
                        return Err(RuntimeError::Unsupported(format!(
                            "native Darwin alias pread failed with errno {}",
                            errno.get()
                        )));
                    }
                }
            }
            if host_final_prot != mmap_prot {
                let rc = unsafe { libc::mprotect(mapped, host_map_len_usize, host_final_prot) };
                if rc != 0 {
                    unsafe { libc::close(fd) };
                    return Err(last_io_error(&format!(
                        "mprotect native Darwin alias 0x{page_start:x}..0x{:x}",
                        page_start.saturating_add(host_map_len)
                    )));
                }
            }
        }
        if file.is_some() {
            unsafe { libc::close(fd) };
        }
        if mapped == libc::MAP_FAILED {
            return Err(last_io_error(&format!(
                "mmap native Darwin alias 0x{address:x}..0x{:x}",
                address.saturating_add(host_map_len)
            )));
        }
        if mapped != addr {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin mmap did not honor MAP_FIXED for alias 0x{address:x}"
            )));
        }

        // MAP_FIXED replaces the physical host pages, so none of the prior
        // mapping's protection overrides remain authoritative. Leaving a
        // stale PROT_NONE entry here lets a later temporary host access restore
        // the newly writable page to no-access (Go user arenas remap freed
        // 8 MiB chunks this way). Clear whole host pages, matching mmap's
        // replacement granularity; Linux-4K subpage state is stale for the
        // same reason.
        let replaced_end = guest_map_start.saturating_add(host_map_len);
        let mut replaced_page = guest_map_start;
        while replaced_page < replaced_end {
            self.native_page_protections.remove(&replaced_page);
            self.native_write_exec_writable_pages.remove(&replaced_page);
            self.linux4k_page_protections.remove(&replaced_page);
            replaced_page = replaced_page.saturating_add(self.host_page_size);
        }

        if file.is_none() && !payload.is_empty() {
            let n = payload.len().min(map_len_usize);
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), mapped.cast::<u8>(), n);
            }
        }

        let len_usize = usize::try_from(len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        self.protections.set_mapping_protection(
            address,
            len_usize,
            prot_none,
            !prot_none && final_prot & libc::PROT_WRITE == 0,
        );
        self.regions.push(NativeMappedRegion {
            start: address,
            end: checked_add_u64(address, len, "native alias end")?,
            host_protects: true,
            shared_futex: file.is_some(),
            guest_writable: final_prot & libc::PROT_WRITE != 0,
            default_prot: if prot_none { 0 } else { final_prot as u64 },
            shared_key_base,
            shared_key_offset,
        });
        Ok(())
    }

    fn protect_native16k_range_with<F>(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
        mut set_host_prot: F,
    ) -> Result<(), MemoryError>
    where
        F: FnMut(carrick_guest_mem::HostVa, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        let host_prot = native16k_host_prot(prot);
        let mut pages = BTreeSet::new();
        for (start, end) in self.host_protected_overlaps(address, len) {
            let (page_start, page_len) = self.host_page_range(start, end)?;
            let page_end = page_start.saturating_add(page_len as u64);
            let mut page = page_start;
            while page < page_end {
                pages.insert(page);
                page = page.saturating_add(self.host_page_size);
            }
        }
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;

        let pages: Vec<(u64, carrick_guest_mem::HostVa, *mut libc::c_void)> = pages
            .into_iter()
            .map(|page_start| {
                let host_page = self.host_address(carrick_guest_mem::GuestVa(page_start))?;
                let ptr = host_page.raw() as *mut libc::c_void;
                Ok((page_start, host_page, ptr))
            })
            .collect::<Result<_, MemoryError>>()?;

        struct ProtectionSnapshot {
            host_page: carrick_guest_mem::HostVa,
            ptr: *mut libc::c_void,
            old_host_prot: libc::c_int,
            patched_words: Vec<(usize, u32)>,
        }

        let mut snapshots = Vec::with_capacity(pages.len());
        let apply_result = (|| {
            for &(page_start, host_page, ptr) in &pages {
                let old_host_prot = self.native_host_prot_for_page(page_start);
                if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                    let patched_words = Vec::new();
                    set_host_prot(host_page, host_page_len, libc::PROT_READ)?;
                    snapshots.push(ProtectionSnapshot {
                        host_page,
                        ptr,
                        old_host_prot,
                        patched_words,
                    });
                    unsafe { carrick_native_clear_icache(ptr, host_page_len) };
                } else {
                    snapshots.push(ProtectionSnapshot {
                        host_page,
                        ptr,
                        old_host_prot,
                        patched_words: Vec::new(),
                    });
                }
                set_host_prot(host_page, host_page_len, host_prot)?;
            }
            Ok(())
        })();

        if let Err(error) = apply_result {
            let mut rollback_error = None;
            for snapshot in snapshots.iter().rev() {
                if !snapshot.patched_words.is_empty() {
                    match set_host_prot(
                        snapshot.host_page,
                        host_page_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    ) {
                        Ok(()) => unsafe {
                            for &(offset, original) in &snapshot.patched_words {
                                let word = snapshot.ptr.cast::<u8>().add(offset).cast::<u32>();
                                std::ptr::write_unaligned(word, original);
                            }
                            carrick_native_clear_icache(snapshot.ptr, host_page_len);
                        },
                        Err(restore_error) => rollback_error = Some(restore_error),
                    }
                }
                if let Err(restore_error) =
                    set_host_prot(snapshot.host_page, host_page_len, snapshot.old_host_prot)
                {
                    rollback_error = Some(restore_error);
                }
            }
            if let Some(rollback_error) = rollback_error {
                return Err(MemoryError::HostMap(format!(
                    "native16k protection failed: {error}; rollback failed: {rollback_error}"
                )));
            }
            return Err(error);
        }

        for (page_start, _, _) in pages {
            self.native_page_protections.insert(page_start, prot);
            self.native_write_exec_writable_pages.remove(&page_start);
        }
        Ok(())
    }
}

impl GuestMemory for NativeMappedMemory {
    fn protections(&self) -> Option<&MemoryProtections> {
        Some(&self.protections)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !bytes.is_empty() && self.protections.range_write_denied(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.region_contains(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];
        let mut offset = 0usize;
        while offset < len {
            let chunk = (len - offset).min(ZERO_CHUNK.len());
            let chunk_address =
                address
                    .checked_add(offset as u64)
                    .ok_or(MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
            self.write_bytes_unchecked(chunk_address, &ZERO_CHUNK[..chunk])?;
            offset += chunk;
        }
        Ok(())
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *const u8;
        let mut out = vec![0u8; length];
        let changed = self.prepare_temporary_host_access(address, length, false)?;
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), length);
        }
        self.restore_temporary_host_access(&changed, address, length)?;
        Ok(out)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.invalidate_exclusive_range(address, length);
        if self.range_may_execute(address, length) {
            self.note_dsr_code_mutation(address, length)?;
        }
        self.prepare_native16k_write_exec_host_write(address, length)?;
        let ptr = self
            .host_address(carrick_guest_mem::GuestVa(address))?
            .raw() as *mut u8;
        let changed = self.prepare_temporary_host_access(address, length, true)?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, length);
        }
        self.restore_temporary_host_access(&changed, address, length)?;
        Ok(())
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        self.protections.set_no_write(address, len, no_write);
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        self.protections.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        self.protections
            .set_mapping_protection(address, len, no_access, no_write);
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !self.protections.range_write_denied(address, length)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        if !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        let old_exec = self.range_may_execute(address, len);
        let result = if self.uses_linux4k_subpages() {
            self.protect_linux4k_range(address, len, prot)
        } else {
            self.protect_native16k_range_with(
                address,
                len,
                prot,
                |host_page, page_len, host_prot| {
                    let ptr = host_page.raw() as *mut libc::c_void;
                    if unsafe { libc::mprotect(ptr, page_len, host_prot) } != 0 {
                        return Err(MemoryError::HostMap(format!(
                            "mprotect native Darwin host page 0x{:x}: {}",
                            host_page.raw(),
                            std::io::Error::last_os_error()
                        )));
                    }
                    Ok(())
                },
            )
        };
        result?;
        if old_exec || prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
            self.note_dsr_code_mutation(address, len)?;
        }
        Ok(())
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        true
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.protect_range(address, len, 0)?;
        self.set_unmapped(address, len, true);
        // Retire file-identity futex keys on unmapped file aliases: region
        // entries are never pruned, and `shared_futex_location`'s newest-wins
        // lookup would otherwise keep FILE-keying a shared-arena VA that the
        // guest munmapped and later reused for an ANON MAP_SHARED word (served
        // by the boot arena entry, no new region push) — this process would
        // key the word by the dead file while every other process VA-keys the
        // same physical word, silently missing cross-process wakes. A partial
        // munmap also neutralizes the remainder's key: that degrades the
        // still-mapped tail to VA-keying (the pre-file-key behavior), which is
        // strictly safer than mis-keying the reused portion.
        let end = address.saturating_add(len as u64);
        for region in &mut self.regions {
            if region.shared_key_base != 0 && region.start < end && address < region.end {
                region.shared_key_base = 0;
                region.shared_key_offset = 0;
            }
        }
        Ok(())
    }

    fn shared_futex_location(
        &self,
        guest_addr: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !guest_addr.is_multiple_of(std::mem::align_of::<u32>() as u64) {
            return None;
        }
        let end = guest_addr.checked_add(std::mem::size_of::<u32>() as u64)?;
        // Newest matching region wins (`.rev()`): file aliases are pushed after
        // the boot-time shared-file arena that covers the same VA range, and
        // the alias carries the file-identity key material.
        let region = self.regions.iter().rev().find(|region| {
            region.shared_futex && guest_addr >= region.start && end <= region.end
        })?;
        let word = self
            .host_address(carrick_guest_mem::GuestVa(guest_addr))
            .ok()?
            .raw();
        // The physical os_sync SHARED wait/wake uses the translated host word,
        // while waiter-count metadata remains guest-keyed. A direct MAP_SHARED
        // file mapping keys that metadata by file identity +
        // file offset (HVF's scheme): the native exec rebuilds the address
        // space, so an exec'd child re-attaches the same file at a different
        // VA and a VA key would miss the parent's registered waiter
        // (ltpcheckpointexec). Anon MAP_SHARED (fork-inherited, same VA in
        // every process) keeps the VA key.
        let waiter_key = if region.shared_key_base == 0 {
            usize::try_from(guest_addr).ok()?
        } else {
            let file_offset = region
                .shared_key_offset
                .saturating_add(guest_addr - region.start);
            crate::trap::shared_futex_waiter_key(region.shared_key_base, file_offset)
        };
        Some(carrick_guest_mem::SharedFutexLocation::Direct {
            word: carrick_guest_mem::HostVa(word),
            waiter_key,
        })
    }

    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        self.remap_private(va, len, content)
    }
}

fn linux_prot_to_native(prot: u64) -> libc::c_int {
    let mut host_prot = 0;
    if prot & crate::linux_abi::LINUX_PROT_READ != 0 {
        host_prot |= libc::PROT_READ;
    }
    if prot & crate::linux_abi::LINUX_PROT_WRITE != 0 {
        host_prot |= libc::PROT_WRITE;
    }
    if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
        host_prot |= libc::PROT_EXEC;
    }
    host_prot
}

fn native16k_host_prot(prot: u64) -> libc::c_int {
    let mut host_prot = linux_prot_to_native(prot);
    let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
    if prot & write_exec == write_exec {
        host_prot &= !libc::PROT_WRITE;
    }
    if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
        host_prot = (host_prot & !libc::PROT_EXEC) | libc::PROT_READ;
    }
    host_prot
}

#[derive(Clone, Copy, Default)]
struct NativeExecMapDetailTotal {
    duration_ns: u64,
    bytes: u64,
    operations: u64,
}

struct NativeExecMapProfile {
    tid: crate::thread::ThreadId,
    active: Option<(crate::probes::DsrExecMapDetailKind, std::time::Instant, u64)>,
    totals: [NativeExecMapDetailTotal; 5],
}

impl NativeExecMapProfile {
    fn new(tid: crate::thread::ThreadId) -> Self {
        Self {
            tid,
            active: None,
            totals: [NativeExecMapDetailTotal::default(); 5],
        }
    }

    fn begin(&mut self, kind: crate::probes::DsrExecMapDetailKind, bytes: u64) {
        self.active = Some((kind, std::time::Instant::now(), bytes));
    }

    fn end(&mut self, kind: crate::probes::DsrExecMapDetailKind) {
        let Some((active_kind, started, bytes)) = self.active.take() else {
            return;
        };
        if active_kind != kind {
            return;
        }
        let index = kind.raw() as usize - 1;
        let total = &mut self.totals[index];
        total.duration_ns = total
            .duration_ns
            .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        total.bytes = total.bytes.saturating_add(bytes);
        total.operations = total.operations.saturating_add(1);
    }

    fn emit(self) {
        for (kind, total) in crate::probes::DsrExecMapDetailKind::ALL
            .into_iter()
            .zip(self.totals)
        {
            crate::probes::dsr_exec_map_detail(
                self.tid.raw(),
                kind,
                total.duration_ns,
                total.bytes,
                total.operations,
            );
        }
    }
}

thread_local! {
    static NATIVE_EXEC_MAP_PROFILE: std::cell::RefCell<Option<NativeExecMapProfile>> =
        const { std::cell::RefCell::new(None) };
}

fn native_exec_map_profile_start(dsr_tid: Option<crate::thread::ThreadId>) {
    let profile = if std::env::var_os("CARRICK_DSR_PROFILE").is_some() {
        dsr_tid.map(NativeExecMapProfile::new)
    } else {
        None
    };
    NATIVE_EXEC_MAP_PROFILE.with(|slot| *slot.borrow_mut() = profile);
}

fn native_exec_map_profile_finish() {
    NATIVE_EXEC_MAP_PROFILE.with(|slot| {
        if let Some(profile) = slot.borrow_mut().take() {
            profile.emit();
        }
    });
}

fn native_exec_map_detail(
    dsr_tid: Option<crate::thread::ThreadId>,
    phase: crate::probes::DsrCacheLifecyclePhase,
    bytes: u64,
) {
    if dsr_tid.is_none() {
        return;
    }
    use crate::probes::{DsrCacheLifecyclePhase as Phase, DsrExecMapDetailKind as Kind};
    let boundary = match phase {
        Phase::ExecMapMmapBegin => Some((Kind::Mmap, true)),
        Phase::ExecMapMmapEnd => Some((Kind::Mmap, false)),
        Phase::ExecMapCopyBegin => Some((Kind::Copy, true)),
        Phase::ExecMapCopyEnd => Some((Kind::Copy, false)),
        Phase::ExecMapIcacheBegin => Some((Kind::Icache, true)),
        Phase::ExecMapIcacheEnd => Some((Kind::Icache, false)),
        Phase::ExecMapProtectBegin => Some((Kind::Protect, true)),
        Phase::ExecMapProtectEnd => Some((Kind::Protect, false)),
        Phase::ExecMapVvarBegin => Some((Kind::Vvar, true)),
        Phase::ExecMapVvarEnd => Some((Kind::Vvar, false)),
        _ => None,
    };
    if let Some((kind, begin)) = boundary {
        NATIVE_EXEC_MAP_PROFILE.with(|slot| {
            if let Some(profile) = slot.borrow_mut().as_mut() {
                if begin {
                    profile.begin(kind, bytes);
                } else {
                    profile.end(kind);
                }
            }
        });
    }
}

fn finalize_image_region_mapping(
    region: &MemoryRegion,
    mapped: *mut libc::c_void,
    mapped_length: usize,
    logical_length: u64,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    _prepared: bool,
) -> Result<(), RuntimeError> {
    if region.perms.execute {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheBegin,
            logical_length,
        );
        unsafe {
            carrick_native_clear_icache(
                mapped,
                usize::try_from(logical_length).unwrap_or(mapped_length),
            )
        };
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheEnd,
            0,
        );
    }

    #[cfg(test)]
    if _prepared
        && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::FinalProtection)
    {
        return Err(RuntimeError::Unsupported(
            "prepared-map: injected final protection failure".to_string(),
        ));
    }
    let mut protection = 0;
    if region.perms.read || region.perms.execute {
        protection |= libc::PROT_READ;
    }
    if region.perms.write {
        protection |= libc::PROT_WRITE;
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectBegin,
        logical_length,
    );
    if unsafe { libc::mprotect(mapped, mapped_length, protection) } != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin image region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectEnd,
        0,
    );
    Ok(())
}

fn map_region(
    region: &MemoryRegion,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    initial_stack_pointer: Option<u64>,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let length_u64 = region.end.checked_sub(region.start).ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin empty inverted region".to_string())
    })?;
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin region too large: 0x{:x}..0x{:x}",
            region.start, region.end
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    let share = if region.shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | share,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for 0x{:x}",
            region.start
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );

    let bytes = region.bytes();
    let copy_window = native_region_copy_window(region, initial_stack_pointer);
    let copy_bytes = &bytes[copy_window.clone()];
    if !copy_bytes.is_empty() {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyBegin,
            u64::try_from(copy_bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe {
            std::ptr::copy_nonoverlapping(
                copy_bytes.as_ptr(),
                mapped.cast::<u8>().add(copy_window.start),
                copy_bytes.len(),
            );
        }
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyEnd,
            0,
        );
    }
    finalize_image_region_mapping(region, mapped, length, length_u64, exec_map_dsr_tid, false)?;
    Ok(())
}

fn map_prepared_region_extent(
    region_index: usize,
    region: &MemoryRegion,
    backing: PreparedImageFileBacking,
    prepared: &ValidatedPreparedImage,
    exec_map_dsr_tid: Option<crate::thread::ThreadId>,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<PreparedRegionMapping, RuntimeError> {
    #[cfg(test)]
    if region_index == 1
        && take_native_prepared_mapping_failpoint(NativePreparedMappingFailpoint::SecondRegionMap)
    {
        return Err(RuntimeError::Unsupported(
            "prepared-map: injected second-region mapping failure".to_string(),
        ));
    }

    let length_u64 = region.end.checked_sub(region.start).ok_or_else(|| {
        RuntimeError::Unsupported("prepared-map: empty or inverted region".to_string())
    })?;
    let expected_extent = align_up_u64(
        length_u64,
        prepared.host_page_size(),
        "prepared artifact region extent",
    )?;
    if backing.artifact_extent.get() != expected_extent {
        return Err(RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} extent mismatch: artifact=0x{:x}, expected=0x{expected_extent:x}",
            backing.artifact_extent.get()
        )));
    }
    let length = usize::try_from(expected_extent).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} is too large: 0x{expected_extent:x}"
        ))
    })?;
    let artifact_offset = libc::off_t::try_from(backing.artifact_offset.get()).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "prepared-map: region {region_index} artifact offset is not representable: 0x{:x}",
            backing.artifact_offset.get()
        ))
    })?;
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
    let address = host_start.raw() as *mut libc::c_void;
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(host_start, length, libc::MAP_PRIVATE)
        .map_err(|error| RuntimeError::Unsupported(format!("prepared-map: {error}")))?;
    let mapped = unsafe {
        libc::mmap(
            address,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            prepared.file_fd(),
            artifact_offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "prepared-map: mmap region {region_index} 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    if mapped != address {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "prepared-map: mmap region {region_index} returned {:p}, expected {:p}",
            mapped, address
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );

    Ok(PreparedRegionMapping {
        mapped,
        mapped_length: length,
        logical_length: length_u64,
    })
}

fn map_bytes_region(
    start: u64,
    length_u64: u64,
    bytes: &[u8],
    options: NativeByteRegionOptions,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let NativeByteRegionOptions {
        final_prot,
        executable,
        exec_map_dsr_tid,
    } = options;
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin byte region too large: 0x{start:x}+0x{length_u64:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    if bytes.len() > length {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin byte region payload too large: {} > {length}",
            bytes.len()
        )));
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapBegin,
        length_u64,
    );
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for byte region 0x{start:x}"
        )));
    }
    rollback.track_mapping(host_start, length);
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapMmapEnd,
        0,
    );
    if !bytes.is_empty() {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyBegin,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapCopyEnd,
            0,
        );
    }
    if executable {
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheBegin,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        );
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
        native_exec_map_detail(
            exec_map_dsr_tid,
            crate::probes::DsrCacheLifecyclePhase::ExecMapIcacheEnd,
            0,
        );
    }
    let final_prot = if executable {
        (final_prot & !libc::PROT_EXEC) | libc::PROT_READ
    } else {
        final_prot
    };
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectBegin,
        length_u64,
    );
    let protect = unsafe { libc::mprotect(mapped, length, final_prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    native_exec_map_detail(
        exec_map_dsr_tid,
        crate::probes::DsrCacheLifecyclePhase::ExecMapProtectEnd,
        0,
    );
    Ok(())
}

fn map_anonymous_region(
    start: u64,
    length: u64,
    shared: bool,
    native_layout: &NativeLayout,
    rollback: &mut NativeMappingRollback,
) -> Result<(), RuntimeError> {
    let length = usize::try_from(length).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region too large: 0x{start:x}+0x{length:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let host_start = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let addr = host_start.raw() as *mut libc::c_void;
    let share = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let flags = native_layout
        .fixed_mapping_flags(
            host_start,
            length,
            libc::MAP_ANON | libc::MAP_NORESERVE | share,
        )
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin anonymous region 0x{start:x}..0x{:x}",
            start.saturating_add(length as u64)
        )));
    }
    if mapped != addr {
        unsafe { libc::munmap(mapped, length) };
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for anonymous region 0x{start:x}"
        )));
    }
    rollback.track_mapping(host_start, length);
    Ok(())
}

fn set_native_region_fork_inheritance(address: *mut libc::c_void, len: usize, share: bool) -> bool {
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }
    let inherit = if share {
        VM_INHERIT_SHARE
    } else {
        VM_INHERIT_COPY
    };
    unsafe { minherit(address, len, inherit) == 0 }
}

/// `movz Xd, #imm16, lsl #32` (sf=1, opc=10, hw=10), any destination register.
const fn movz_x_lsl32(imm16: u16) -> u32 {
    0xd2c0_0000 | ((imm16 as u32) << 5)
}

/// Rewrite the injected vDSO code page's hardcoded vvar-base loads from the
/// canonical `LINUX_VVAR_BASE` to `NATIVE_DARWIN_VVAR_BASE`. The vDSO clock
/// functions and the getrandom blob each materialise the vvar VA with a single
/// `movz Xn, #(LINUX_VVAR_BASE >> 32), lsl #32`; both bases are exact 1<<32
/// multiples (const-asserted above), so retargeting is a pure immediate swap.
/// This pass runs ONLY on carrick's own vDSO page — never on guest-owned code,
/// where an immediate rewrite would corrupt legitimate instructions.
fn relocate_vdso_vvar_loads(
    region: &MemoryRegion,
    native_layout: &NativeLayout,
) -> Result<(), RuntimeError> {
    let length = usize::try_from(region.len()).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin vDSO region is too large: 0x{:x}",
            region.len()
        ))
    })?;
    let base = native_layout
        .address_mode()
        .to_host(carrick_guest_mem::GuestVa(region.start))
        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
        .raw() as *mut u8;
    let canonical = movz_x_lsl32((carrick_mem::vdso::LINUX_VVAR_BASE >> 32) as u16);
    let relocated = movz_x_lsl32((NATIVE_DARWIN_VVAR_BASE >> 32) as u16);
    const RD_MASK: u32 = 0x1f;
    if unsafe { libc::mprotect(base.cast(), length, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return Err(last_io_error("mprotect native Darwin vdso page writable"));
    }
    for index in 0..length / std::mem::size_of::<u32>() {
        let ptr = unsafe { base.add(index * std::mem::size_of::<u32>()).cast::<u32>() };
        let word = unsafe { std::ptr::read_unaligned(ptr) };
        if word & !RD_MASK == canonical {
            unsafe { std::ptr::write_unaligned(ptr, relocated | (word & RD_MASK)) };
        }
    }
    unsafe { carrick_native_clear_icache(base.cast(), length) };
    let final_prot = libc::PROT_READ;
    if unsafe { libc::mprotect(base.cast(), length, final_prot) } != 0 {
        return Err(last_io_error("restore native Darwin vdso page protections"));
    }
    Ok(())
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

fn child_dup2_or_exit(from: RawFd, to: RawFd) {
    let rc = unsafe { libc::dup2(from, to) };
    if rc < 0 {
        child_write_stderr(b"native Darwin child error: dup2 failed\n");
        unsafe { libc::_exit(125) };
    }
}

fn child_write_stderr(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        let ptr = unsafe { bytes.as_ptr().add(written) };
        let rc = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                ptr.cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if rc <= 0 {
            break;
        }
        let Ok(n) = usize::try_from(rc) else {
            break;
        };
        written = written.saturating_add(n);
    }
}

fn read_pipe_to_end(fd: RawFd) -> Result<Vec<u8>, std::io::Error> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

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

fn last_io_error(context: &str) -> RuntimeError {
    RuntimeError::FsBackend(anyhow::anyhow!(
        "{context}: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn fork_test(test: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            test();
            unsafe { libc::_exit(0) };
        }
        let status = waitpid_blocking(pid).expect("wait for forked test");
        assert!(libc::WIFEXITED(status), "forked test status={status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
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

    fn biased_test_memory(
        guest_start: carrick_guest_mem::GuestVa,
        len: usize,
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
            owned_host_ranges: vec![
                carrick_guest_mem::HostVa(host_start)..carrick_guest_mem::HostVa(host_start + len),
            ],
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
            exclusive_reservation: None,
            exclusive_sequences: BTreeMap::new(),
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
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
                &mut memory,
                &mut snapshot,
                &mut reservation,
                0x885f_fc9b, // ldaxr w27, [x4]
                0x61b34,
            )
            .expect("emulate split exclusive load");
            assert_eq!(snapshot.x[27], 1);
            emulate_dsr_exclusive_access(
                &mut memory,
                &mut snapshot,
                &mut reservation,
                0x881b_fc83, // stlxr w27, w3, [x4]
                0x61b40,
            )
            .expect("emulate split exclusive store");
            assert_eq!(snapshot.x[27], 0, "unchanged reservation must store");
            assert_eq!(memory.atomic_load(address, 4).expect("read stored word"), 2);

            emulate_dsr_exclusive_access(
                &mut memory,
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
                &mut memory,
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
                &mut memory,
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
                &mut memory,
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
                    &mut memory,
                    &mut snapshot,
                    &mut reservation,
                    load,
                    0x62000,
                )
                .expect("emulate subword exclusive load");
                assert_eq!(snapshot.x[0], initial);
                snapshot.x[0] = initial + 1;
                emulate_dsr_exclusive_access(
                    &mut memory,
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
        memory.owned_host_ranges = vec![host_bias..mapped.end];

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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
                .prepare_exec_mapping(&target, &plan)
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
                .prepare_exec_mapping(&target_image, &plan)
                .expect("preselect replacement layout");
            let prepared_mode = prepared.native_layout.address_mode();
            let prepared_process = Arc::clone(&prepared.process_translator);

            memory
                .replace_image(&target_image, &[], &plan, None, prepared)
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
    fn failed_biased_exec_preselection_preserves_the_old_image() {
        fork_test(|| {
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
                .prepare_exec_mapping(&invalid_target, &plan)
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
                .prepare_exec_mapping(&target, &plan)
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
            let child = unsafe { libc::fork() };
            assert!(
                child >= 0,
                "fork exec child: {}",
                std::io::Error::last_os_error()
            );
            if child == 0 {
                NATIVE_FORKED_GUEST_CHILD.store(true, std::sync::atomic::Ordering::Release);
                let prepared = memory
                    .prepare_exec_mapping(&target, &plan)
                    .expect("prepare fork-child replacement without allocating a translator");
                let prepared_mode = prepared.native_layout.address_mode();
                // The inherited Carrick-owned aperture is reusable authority;
                // a biased replacement keeps its bias instead of probing a
                // different candidate after fork.
                let reused = prepared.reset_inherited_translator
                    && Arc::ptr_eq(&prepared.process_translator, &inherited_process)
                    && prepared_mode == parent_mode;
                if !reused {
                    unsafe { libc::_exit(2) };
                }
                if memory
                    .replace_image(&target, &[], &plan, None, prepared)
                    .is_err()
                {
                    unsafe { libc::_exit(3) };
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
            }
            let status = waitpid_blocking(child).expect("wait exec child");
            assert!(libc::WIFEXITED(status), "child status={status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(memory.address_mode(), parent_mode);
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
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
        let mut memory = NativeMappedMemory {
            address_mode: NativeAddressMode::Direct,
            owned_host_ranges: Vec::new(),
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
            exclusive_reservation: None,
            exclusive_sequences: BTreeMap::new(),
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

        let mut trap = NativeSignalTrap::new(&mut memory, interrupted, None);
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
        let mut memory = NativeMappedMemory {
            address_mode: NativeAddressMode::Direct,
            owned_host_ranges: Vec::new(),
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
            exclusive_reservation: None,
            exclusive_sequences: BTreeMap::new(),
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
        let mut trap = NativeSignalTrap::new(&mut memory, interrupted, None);
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
    fn native_unsafe_postfork_threads_requires_exact_one() {
        use std::ffi::OsStr;

        assert!(!native_unsafe_postfork_threads_enabled(None));
        for value in ["", "0", "true", "01", "yes"] {
            assert!(
                !native_unsafe_postfork_threads_enabled(Some(OsStr::new(value))),
                "unexpectedly accepted {value:?}"
            );
        }
        assert!(native_unsafe_postfork_threads_enabled(Some(OsStr::new(
            "1"
        ))));
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
            owned_host_ranges: vec![
                carrick_guest_mem::HostVa(owned_start)
                    ..carrick_guest_mem::HostVa(owned_start + page_size as usize),
            ],
            regions: Vec::new(),
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_reservation: None,
            exclusive_sequences: BTreeMap::new(),
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
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory.resolve_native16k_write_exec_fault(
                        layout.mmap_base,
                        NATIVE_DARWIN_PIE_BASE,
                        (0x25_u64 << 26) | (1 << 6) | 0x04,
                    )
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
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if !memory.resolve_native16k_write_exec_fault(
                        layout.mmap_base,
                        NATIVE_DARWIN_PIE_BASE,
                        (0x25_u64 << 26) | (1 << 6) | 0x0f,
                    )? {
                        return Err(RuntimeError::Unsupported(
                            "permission write fault was not resolved".to_string(),
                        ));
                    }
                    memory.resolve_native16k_write_exec_fault(
                        layout.mmap_base,
                        layout.mmap_base,
                        (0x21_u64 << 26) | 0x04,
                    )
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
                            if call == 4 {
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
                    let rollback_calls = operations.borrow();
                    Ok(result.is_err()
                        && rollback_calls.len() >= 6
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
                memory.read_u32(layout.mmap_base)
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
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    if snapshot.x[0] != 7 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated ldaxr produced x0={} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }

                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x8803_fc44)?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 9;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    memory
                        .write_bytes_unchecked(address, &11_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    write_linux4k_test_instruction(&mut memory, pc, host_page_size, 0x8803_fc44)?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 13;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
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
        assert!(set_native_region_fork_inheritance(mapped, page_size, true));

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                word.write(42);
                libc::_exit(0);
            }
        }

        assert!(set_native_region_fork_inheritance(mapped, page_size, false));
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
                    start as *mut libc::c_void,
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
                let _ = set_native_region_fork_inheritance(start as *mut libc::c_void, len, false);
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
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::NativeDarwin);
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
        dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::NativeDarwin);
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
            // After munmap the reused VA is an arena word again: it must key
            // by VA like every other process, never by the dead file.
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

    /// Empirical hazard gate for the native vDSO (see `stamp_vdso_vvar`):
    /// natively the guest's vDSO clock code reads the RAW `cntvct_el0` /
    /// `cntfrq_el0` at EL0, while the dispatcher's clock paths and the stamped
    /// vvar realtime offset are based on CLOCK_UPTIME_RAW. This proves, on the
    /// host actually running the suite, that (a) EL0 reads of both registers
    /// do not fault in a plain Darwin userspace process and (b) the raw
    /// counter and CLOCK_UPTIME_RAW share ONE timeline: two raw reads
    /// bracketing a CLOCK_UPTIME_RAW read must enclose it (modulo conversion
    /// rounding). If a host ever diverges (e.g. a raw counter that keeps
    /// ticking through suspend while CLOCK_UPTIME_RAW does not — the behavior
    /// HVF documents for older hosts in trap.rs), this fails and the native
    /// vDSO clock stamping must be re-based before trusting native clocks
    /// there.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_el0_counter_reads_track_clock_uptime_raw() {
        let (ticks_before, freq) = crate::trap::host_counter();
        assert!(freq > 0, "CNTFRQ_EL0 read zero at EL0");
        let uptime_ns = crate::trap::host_clock_uptime_ns();
        let (ticks_after, _) = crate::trap::host_counter();
        assert!(ticks_after >= ticks_before, "CNTVCT_EL0 went backwards");
        let to_ns = |ticks: u64| (ticks as u128 * 1_000_000_000 / u128::from(freq)) as u64;
        // One counter tick + 1µs of conversion rounding slack.
        let slack_ns = 1_000_000_000 / freq + 1_000;
        let raw_before_ns = to_ns(ticks_before);
        let raw_after_ns = to_ns(ticks_after);
        assert!(
            raw_before_ns <= uptime_ns + slack_ns,
            "raw CNTVCT ({raw_before_ns} ns) is ahead of CLOCK_UPTIME_RAW ({uptime_ns} ns): timelines diverge"
        );
        assert!(
            uptime_ns <= raw_after_ns + slack_ns,
            "raw CNTVCT ({raw_after_ns} ns) is behind CLOCK_UPTIME_RAW ({uptime_ns} ns): timelines diverge"
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
        for range in &memory.owned_host_ranges {
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
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
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
                &plan,
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
                &plan,
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
                &plan,
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
                &plan,
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
            let error = match NativeMappedMemory::map_prepared_for_plan(&validated, layout, &plan) {
                Ok(_) => panic!("prepared mapping failpoint must fail"),
                Err(error) => error,
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
            let error = match NativeMappedMemory::map_prepared_for_plan(&validated, layout, &plan) {
                Ok(_) => panic!("biased late failpoint must fail"),
                Err(error) => error,
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
                .prepare_exec_mapping(&target, &plan)
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
            let error = memory
                .replace_image(
                    &target,
                    &[],
                    &plan,
                    Some(crate::thread::ThreadId::main_from_host_pid()),
                    prepared,
                )
                .expect_err("Direct replacement late failpoint must fail");
            assert!(error.to_string().contains("injected native exec failure"));
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
                .prepare_exec_mapping(&target, &plan)
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
            let error = match memory.replace_image(
                &target,
                &[],
                &plan,
                Some(crate::thread::ThreadId::main_from_host_pid()),
                prepared,
            ) {
                Ok(()) => panic!("biased replacement late failpoint must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("injected native exec failure"));
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
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateBegin,
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedValidateEnd,
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecGuestEntry,
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
                    &plan,
                )
                .is_err()
            );
            assert_eq!(
                take_native_reexec_lifecycle_capture(),
                vec![crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin]
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
                    &plan,
                )
                .is_err()
            );
            assert_eq!(
                take_native_reexec_lifecycle_capture(),
                vec![
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin,
                    crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedMapEnd,
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
