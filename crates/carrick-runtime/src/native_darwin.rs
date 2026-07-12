//! Darwin-native execution backend.
//!
//! Same-ISA Linux ELFs are loaded into a forked host child, their `svc #0`
//! instructions are patched to synchronous `brk` traps, and those traps are
//! dispatched through the existing Linux syscall layer. OCI/container setup is
//! shared with the other runtime backends; this module owns only image loading
//! details and the native run loop. Unsupported dispatcher outcomes fail
//! explicitly rather than falling back to HVF.

mod dsr;

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

const SVC_0: u32 = 0xd400_0001;
const MRS_TPIDR_EL0: u32 = 0xd53b_d040;
const MSR_TPIDR_EL0: u32 = 0xd51b_d040;
const MRS_CTR_EL0: u32 = 0xd53b_0020;
const MRS_DCZID_EL0: u32 = 0xd53b_00e0;
const DC_ZVA: u32 = 0xd50b_7420;
const DC_CVAU: u32 = 0xd50b_7b20;
const IC_IVAU: u32 = 0xd50b_7520;
const SYSTEM_REGISTER_RT_MASK: u32 = 0x1f;
const BRK_NATIVE_SYSCALL_IMM: u16 = 0xf000;
const BRK_NATIVE_MRS_TPIDR_IMM_BASE: u16 = 0xe000;
const BRK_NATIVE_MSR_TPIDR_IMM_BASE: u16 = 0xe100;
const BRK_NATIVE_MRS_CTR_IMM_BASE: u16 = 0xe200;
const BRK_NATIVE_MRS_DCZID_IMM_BASE: u16 = 0xe300;
const BRK_NATIVE_DC_ZVA_IMM_BASE: u16 = 0xe400;
const BRK_NATIVE_SYSCALL: u32 = brk_instruction(BRK_NATIVE_SYSCALL_IMM);
const AARCH64_NOP: u32 = 0xd503_201f;
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
const NATIVE_EVENT_TRAP: i32 = 1;
const NATIVE_EVENT_KICK: i32 = 2;

/// True in a host process created by a GUEST `fork` (not the run-elf root
/// child, which the CLI forks for isolation). Guest-forked children must exit
/// through `exec_helpers::forked_child_exit` so their guest CPU is published
/// for the parent's wait4/waitid child-time accounting (the HVF loop's
/// `is_forked_guest_process` branch); the root child's exit is reported to the
/// CLI, which does no such accounting. Survives execve (same host process).
static NATIVE_FORKED_GUEST_CHILD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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

#[derive(Clone, Copy)]
struct NativeRelativeRelocation {
    address: u64,
    value: u64,
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
enum NativeTrap {
    Syscall { resume_pc: u64 },
    ReadTpidr { rt: u32, resume_pc: u64 },
    WriteTpidr { rt: u32, resume_pc: u64 },
    ReadConstant { rt: u32, value: u64, resume_pc: u64 },
    DcZva { rt: u32, resume_pc: u64 },
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

/// Deliver a process-directed timer signal to a native guest: publish into the
/// shared pending mask, then kick every native guest thread so the run loop's
/// kick path (`resume_guest_after_kick` → `deliver_pending_signal`) injects it.
/// The HVF fallback publishes only — its pump kqueue re-kicks busy vCPUs — but
/// native has no pump, and a spinning guest that never traps (vDSO clock reads
/// satisfy its spin loop in userspace) would otherwise never observe the
/// signal.
fn deliver_native_process_signal(signum: i32) {
    crate::host_signal::publish_process_signal(signum);
    kick_all_native_guest_threads();
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
        crate::host_signal::publish_pending_for(parent_tid, exit_signal);
    }
    kick_all_native_guest_threads();
}

/// Native `TimerDelivery`: there is no signal-pump kqueue, so every interval
/// timer runs the SHARED timer-core timing loop on a fallback thread —
/// wall-clock sleeps for `ITIMER_REAL`, guest-CPU polling against the native
/// Darwin CPU provider for `ITIMER_VIRTUAL`/`ITIMER_PROF` — whose fire action
/// is publish + kick-all. POSIX per-process timers mirror the KVM/bhyve/NVMM
/// fallback shape with the same native fire action. Stateless: the kicker is
/// resolved at fire time from `NATIVE_PROCESS_KICKER`.
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
    fn carrick_native_install_trap_handler() -> libc::c_int;
    #[cfg(test)]
    fn carrick_native_unblock_transport_signals() -> libc::c_int;
    fn carrick_native_seed_ucontext(snapshot: *const NativeUcontextSnapshot) -> libc::c_int;
    fn carrick_native_enter(entry: u64, sp: u64) -> libc::c_int;
    fn carrick_native_resume() -> libc::c_int;
    fn carrick_native_resume_detached_context() -> libc::c_int;
    fn carrick_native_snapshot_ucontext(out: *mut NativeUcontextSnapshot) -> libc::c_int;
    fn carrick_native_set_return(value: u64);
    fn carrick_native_set_pc(pc: u64);
    fn carrick_native_set_sp(sp: u64);
    fn carrick_native_set_register(index: u32, value: u64);
    fn carrick_native_set_vector(index: u32, value: *const u8);
    fn carrick_native_set_processor_state(pstate: u64, fpsr: u32, fpcr: u32);
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
    fn carrick_native_clear_icache(start: *mut libc::c_void, len: usize);
}

const fn brk_instruction(imm: u16) -> u32 {
    0xd420_0000 | ((imm as u32) << 5)
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
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug());
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
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug());
    let image = with_native_vdso(image)?.with_linux_initial_stack_page_size(
        argv,
        env,
        geometry.linux_page_size,
    )?;
    maybe_dump_debug_state(&image, debug_state_path);

    run_image_in_child(image, dispatcher, max_traps, relative_relocations, plan)
}

fn load_native_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    plan: &ExecutionPlan,
) -> Result<(AddressSpace, Vec<NativeRelativeRelocation>, String), crate::linux_abi::LinuxErrno> {
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
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug());
    // Mirror the HVF execve builder: the replacement image carries fresh
    // vvar/vdso regions; `replace_image` → `NativeMappedMemory::map` re-stamps
    // the vvar for the new image.
    let image = with_native_vdso(image)
        .map_err(|_| crate::linux_abi::LINUX_ENOENT)?
        .with_linux_initial_stack_execfn_page_size(
            argv,
            env,
            resolved.as_bytes(),
            geometry.linux_page_size,
        )
        .map_err(|_| crate::linux_abi::LINUX_ENOENT)?;
    Ok((image, relative_relocations, resolved))
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
                relocations.push(NativeRelativeRelocation {
                    address: checked_add_u64(load_bias, reloc.r_offset, "relocation address")?,
                    value: add_load_bias(load_bias, addend)?,
                });
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
        memory.write_u64(relocation.address, relocation.value)?;
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
            image,
            dispatcher,
            max_traps,
            &relative_relocations,
            plan,
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
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    relative_relocations: &[NativeRelativeRelocation],
    plan: &ExecutionPlan,
) -> Result<i32, RuntimeError> {
    let initial_sp = image.initial_stack_pointer().ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin image has no initial stack".to_string())
    })?;
    let entry = image.entry();
    let memory = Arc::new(parking_lot::Mutex::new(NativeMappedMemory::map_for_plan(
        &image,
        native_memory_layout(),
        plan.page_geometry.host_page_size,
        plan.page_geometry.linux_page_size,
        plan,
    )?));
    {
        let mut memory = memory.lock();
        apply_native_relative_relocations(&mut memory, relative_relocations)?;
    }
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
    /// `fork_child` selects the detached-context transport for the historical
    /// brk executor.  DSR owns an explicit snapshot instead and uses the same
    /// bit to repair process-cache state inherited from the parent.
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
    if plan.native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr {
        return run_native_dsr_thread_loop(
            dispatcher,
            memory,
            reporter,
            max_traps,
            plan,
            thread_runtime,
            start,
        );
    }
    let trace_syscalls = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
    let mut guest_tpidr_el0 = match &start {
        NativeThreadStart::Initial { .. } => 0,
        NativeThreadStart::Detached {
            guest_tpidr_el0, ..
        } => *guest_tpidr_el0,
    };
    let mut vfork_completion: Option<NativeVforkCompletion> = None;

    let mut traps = 0usize;
    let entered = match start {
        NativeThreadStart::Initial { entry, initial_sp } => unsafe {
            carrick_native_enter(entry, initial_sp)
        },
        NativeThreadStart::Detached { context, .. } => {
            if unsafe { carrick_native_seed_ucontext(context.as_ref()) } != 0 {
                return Err(last_io_error("seed native Darwin sibling context"));
            }
            unsafe { carrick_native_resume_detached_context() }
        }
    };
    if entered != 1 {
        return Err(RuntimeError::Unsupported(
            "native Darwin failed to enter guest".to_string(),
        ));
    }

    loop {
        traps = traps.saturating_add(1);
        if traps > max_traps {
            return Err(RuntimeError::TrapLimitExceeded { max_traps });
        }

        let mut snapshot = snapshot_ucontext()?;
        // Dispatch-boundary barrier — the native "run-loop top", where this
        // thread holds NO locks. An execve replacement by another thread
        // retires this thread (Linux: execve destroys every sibling; the
        // normal thread-exit path is the HVF sibling exit shape); a fork
        // quiesce parks it (kicker unregister → barrier → re-register) and
        // then the snapshot is processed normally, so the kick-ack path stays
        // intact.
        if crate::fork_quiesce::exec_replacing_other_thread(thread_runtime.tid()) {
            if thread_runtime.finish_thread(&dispatcher, &memory) {
                return Ok(NativeThreadLoopOutcome::ProcessExit(0));
            }
            return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
        }
        thread_runtime.park_for_fork_quiesce();
        if snapshot.event_kind == NATIVE_EVENT_KICK {
            resume_guest_after_kick(&dispatcher, &memory, snapshot, thread_runtime.tid())?;
            continue;
        }
        if snapshot.event_kind != NATIVE_EVENT_TRAP {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin reported unknown event kind {} signal={} pc=0x{:x}",
                snapshot.event_kind, snapshot.signal, snapshot.pc
            )));
        }
        if snapshot.signal == libc::SIGSEGV || snapshot.signal == libc::SIGBUS {
            let fault_address = if snapshot.fault_address != 0 {
                snapshot.fault_address
            } else {
                snapshot.far
            };
            let resident_fault_plan = dispatcher.resident_fault_plan(fault_address);
            let resident_fault_resolved = if let Some((page, prot)) = resident_fault_plan {
                let mut memory = memory.lock();
                let linux_page_size = memory.linux_page_size as usize;
                memory.protect_range(page, linux_page_size, prot).is_ok()
            } else {
                false
            };
            if let Some((page, _)) = resident_fault_plan
                && resident_fault_resolved
            {
                dispatcher.commit_resident_fault(page);
                resume_guest_snapshot(&snapshot)?;
                continue;
            }

            let write_exec_resolved = {
                let mut memory = memory.lock();
                memory.resolve_native16k_write_exec_fault(
                    fault_address,
                    snapshot.pc,
                    snapshot.esr,
                )?
            };
            if write_exec_resolved {
                resume_guest_snapshot(&snapshot)?;
                continue;
            }

            let guarded = memory.lock().linux4k_address_is_guarded(fault_address);
            if guarded {
                // linux4k boundary: the guarded-page (mixed 4K permission)
                // fault emulation is not multithread-safe — concurrent
                // guarded faults corrupt its decode/backing-copy state
                // (forkfpreclaim on linux4k: mismatched fault/instruction
                // ranges, intermittent host SIGSEGV; task_c2615fa2 tracks
                // making it MT-safe). Explicit typed error, never a crash.
                if thread_runtime.registry.live_count() > 1 {
                    return Err(RuntimeError::Unsupported(format!(
                        "native linux4k guarded-page access at 0x{fault_address:x} from a \
                         multithreaded guest is not yet supported: the 4K-on-16K \
                         guarded-page fault emulation is not multithread-safe"
                    )));
                }
                let mut memory = memory.lock();
                emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                drop(memory);
                resume_guest_snapshot(&snapshot)?;
                continue;
            }

            let Some((mut signum, mut si_code, si_addr)) =
                crate::vcpu_loop::lower_el0_fault(snapshot.esr, snapshot.pc, fault_address)
            else {
                native_die_by_signal(&dispatcher, crate::linux_abi::LINUX_SIGSEGV);
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
                    resume_guest_snapshot(&snapshot)?;
                    continue;
                }
            }
            if signum == crate::linux_abi::LINUX_SIGSEGV && dispatcher.mmap_fault_is_sigbus(si_addr)
            {
                signum = crate::linux_abi::LINUX_SIGBUS;
                si_code = 2; // BUS_ADRERR
            }
            let interrupted_pc = snapshot.pc;
            let pc = {
                let mut memory = memory.lock();
                let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
                match crate::vcpu_loop::inject_fault_signal(
                    &mut trap,
                    &dispatcher,
                    thread_runtime.tid(),
                    signum,
                    si_code,
                    si_addr,
                    Some(interrupted_pc),
                )? {
                    crate::vcpu_loop::FaultSignalDisposition::Injected => {}
                    crate::vcpu_loop::FaultSignalDisposition::Terminate(signum) => {
                        native_die_by_signal(&dispatcher, signum);
                    }
                }
                let pc = trap.pc();
                trap.commit();
                pc
            };
            resume_guest_at(pc)?;
            continue;
        }
        if snapshot.signal != libc::SIGTRAP {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin trapped unexpected signal {} code={} pc=0x{:x} addr=0x{:x} esr=0x{:x}",
                snapshot.signal,
                snapshot.signal_code,
                snapshot.pc,
                snapshot.fault_address,
                snapshot.esr
            )));
        }
        let native_trap = {
            let memory = memory.lock();
            decode_native_trap(&memory, snapshot.pc)?
        };
        match native_trap {
            NativeTrap::ReadTpidr { rt, resume_pc } => {
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} tid={} trap={traps} pc=0x{:x} read_tpidr rt={} value=0x{:x} lr=0x{:x}\n",
                            unsafe { libc::getpid() },
                            thread_runtime.tid().raw(),
                            snapshot.pc, rt, guest_tpidr_el0, snapshot.x[30]
                        )
                        .as_bytes(),
                    );
                }
                set_guest_register(rt, guest_tpidr_el0);
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::WriteTpidr { rt, resume_pc } => {
                guest_tpidr_el0 = snapshot_register(&snapshot, rt);
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} tid={} trap={traps} pc=0x{:x} write_tpidr rt={} value=0x{:x}\n",
                            unsafe { libc::getpid() },
                            thread_runtime.tid().raw(),
                            snapshot.pc, rt, guest_tpidr_el0
                        )
                        .as_bytes(),
                    );
                }
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::ReadConstant {
                rt,
                value,
                resume_pc,
            } => {
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} tid={} trap={traps} pc=0x{:x} read_const rt={} value=0x{:x}\n",
                            unsafe { libc::getpid() },
                            thread_runtime.tid().raw(),
                            snapshot.pc, rt, value
                        )
                        .as_bytes(),
                    );
                }
                set_guest_register(rt, value);
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::DcZva { rt, resume_pc } => {
                let address = snapshot_register(&snapshot, rt);
                {
                    let mut memory = memory.lock();
                    native_dc_zva(&mut memory, address)?;
                }
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::Syscall { resume_pc } => {
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
                            "native trace pid={} tid={} trap={traps} pc=0x{:x} sp=0x{:x} nr={} args={:x},{:x},{:x},{:x},{:x},{:x}\n",
                            unsafe { libc::getpid() },
                            thread_runtime.tid().raw(),
                            snapshot.pc,
                            snapshot.sp,
                            snapshot.x[8],
                            snapshot.x[0],
                            snapshot.x[1],
                            snapshot.x[2],
                            snapshot.x[3],
                            snapshot.x[4],
                            snapshot.x[5],
                        )
                        .as_bytes(),
                    );
                }

                let outcome = dispatch_native_syscall(
                    &dispatcher,
                    request,
                    &memory,
                    thread_runtime,
                    &reporter,
                    trace_syscalls,
                )?;
                match outcome {
                    DispatchOutcome::Returned { value } => {
                        resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            value,
                            request.number.raw(),
                            thread_runtime.tid(),
                        )?;
                    }
                    DispatchOutcome::Errno { errno } => {
                        resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            errno.guest_retval(),
                            request.number.raw(),
                            thread_runtime.tid(),
                        )?;
                    }
                    DispatchOutcome::SigReturn => {
                        resume_guest_from_sigreturn(
                            &dispatcher,
                            &memory,
                            snapshot,
                            thread_runtime.tid(),
                        )?;
                    }
                    DispatchOutcome::SignalDeath { signum } => {
                        native_die_by_signal(&dispatcher, signum);
                    }
                    DispatchOutcome::CloneThread {
                        stack,
                        tls,
                        flags: _,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                    } => {
                        let clone_rejection = memory.lock().native16k_clone_thread_rejection();
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
                            resume_guest_after_syscall(
                                &dispatcher,
                                &memory,
                                snapshot,
                                resume_pc,
                                crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval(),
                                request.number.raw(),
                                thread_runtime.tid(),
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
                                resume_pc,
                                parent_guest_tpidr_el0: guest_tpidr_el0,
                                stack,
                                tls,
                                parent_tid_addr,
                                child_tid_addr,
                                clear_child_tid_addr,
                            },
                        )?;
                        resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            i64::from(tid.raw()),
                            request.number.raw(),
                            thread_runtime.tid(),
                        )?;
                    }
                    DispatchOutcome::ThreadExit { code } => {
                        if thread_runtime.finish_thread(&dispatcher, &memory) {
                            return Ok(NativeThreadLoopOutcome::ProcessExit(code));
                        }
                        return Ok(NativeThreadLoopOutcome::ThreadDone);
                    }
                    DispatchOutcome::SignalThread {
                        tid: target,
                        signum,
                    } => {
                        let value = thread_runtime.signal_thread(target, signum);
                        resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            value,
                            request.number.raw(),
                            thread_runtime.tid(),
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
                            resume_guest_after_syscall(
                                &dispatcher,
                                &memory,
                                snapshot,
                                resume_pc,
                                crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval(),
                                request.number.raw(),
                                thread_runtime.tid(),
                            )?;
                            continue;
                        }
                        let request = NativeForkRequest {
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
                            request,
                        )? {
                            NativeForkFlow::Resume {
                                value,
                                fork_child,
                                child_stack,
                            } => {
                                if fork_child {
                                    if child_stack != 0 {
                                        unsafe { carrick_native_set_sp(child_stack) };
                                    }
                                    resume_guest_detached(value as u64, resume_pc)?;
                                } else {
                                    resume_guest(value as u64, resume_pc)?;
                                }
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
                        let proc_argv: Vec<String> = argv
                            .iter()
                            .map(|value| String::from_utf8_lossy(value).into_owned())
                            .collect();
                        let proc_env = env.clone();
                        match load_native_execve_image(&dispatcher, &path, argv, env, &plan) {
                            Ok((image, relative_relocations, resolved)) => {
                                // Point of no return: only AFTER the image
                                // loaded successfully may the thread group be
                                // destroyed (a failed execve leaves every
                                // sibling running, per Linux).
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
                                let entry = image.entry();
                                let initial_sp =
                                    image.initial_stack_pointer().ok_or_else(|| {
                                        RuntimeError::Unsupported(
                                            "native Darwin execve image has no initial stack"
                                                .to_string(),
                                        )
                                    })?;
                                dispatcher.reset_memory_state_on_execve();
                                dispatcher.reset_signal_handlers_on_execve();
                                dispatcher.set_executable_identity(
                                    resolved.clone(),
                                    proc_argv.clone(),
                                    proc_env,
                                );
                                crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
                                dispatcher.close_cloexec_fds();
                                memory.lock().replace_image(
                                    &image,
                                    &relative_relocations,
                                    &plan,
                                )?;
                                crate::namespace::pid::mark_self_execed();
                                let cmdline = proc_argv.join(" ");
                                crate::dispatch::set_host_process_name(cmdline.as_bytes());
                                if let Some(mut completion) = vfork_completion.take() {
                                    completion.notify();
                                }
                                guest_tpidr_el0 = 0;
                                for index in 0..31 {
                                    set_guest_register(index, 0);
                                }
                                unsafe { carrick_native_set_sp(initial_sp) };
                                crate::exec_helpers::stop_after_traced_exec(&dispatcher);
                                resume_guest_at(entry)?;
                            }
                            Err(errno) => {
                                resume_guest_after_syscall(
                                    &dispatcher,
                                    &memory,
                                    snapshot,
                                    resume_pc,
                                    errno.guest_retval(),
                                    request.number.raw(),
                                    thread_runtime.tid(),
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
                        resume_guest(va.raw(), resume_pc)?;
                    }
                    DispatchOutcome::Exit { code } => {
                        if NATIVE_FORKED_GUEST_CHILD.load(std::sync::atomic::Ordering::Acquire) {
                            // Mirror the HVF loop's forked-child exit: publish
                            // this child's guest CPU (`record_child_exit`) so
                            // the parent's wait4/waitid roll it into
                            // RUSAGE_CHILDREN / times cutime, then `_exit`.
                            // The vfork parent (if any) is released by the
                            // completion pipe's EOF on `_exit`.
                            dispatcher.cleanup_sysv_ipc_on_process_exit();
                            crate::exec_helpers::forked_child_exit(
                                code,
                                dispatcher.stdout(),
                                dispatcher.stderr(),
                            );
                        }
                        return Ok(NativeThreadLoopOutcome::ProcessExit(code));
                    }
                    other => {
                        return Err(RuntimeError::Unsupported(format!(
                            "native Darwin run-elf does not yet support dispatcher outcome {other:?}"
                        )));
                    }
                }
            }
        }
    }
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
    let mut translator = dsr::ThreadTranslator::for_process(process_translator);
    let trace_syscalls = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
    let mut vfork_completion: Option<NativeVforkCompletion> = None;
    let mut traps = 0_usize;

    loop {
        traps = traps.saturating_add(1);
        if traps > max_traps {
            return Err(RuntimeError::TrapLimitExceeded { max_traps });
        }
        // Match the brk executor's lock-free dispatch boundary. A kick out of
        // translated code returns here, where fork may park this thread and a
        // successful execve by another thread must retire it before it can
        // re-enter the old image.
        if crate::fork_quiesce::exec_replacing_other_thread(thread_runtime.tid()) {
            if thread_runtime.finish_thread(&dispatcher, &memory) {
                return Ok(NativeThreadLoopOutcome::ProcessExit(0));
            }
            return Ok(NativeThreadLoopOutcome::ExecReplacedThread);
        }
        thread_runtime.park_for_fork_quiesce();
        let exit = {
            let mut memory = memory.lock();
            memory
                .prepare_dsr_execution(snapshot.pc)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
            translator
                .enter_once(&memory, &mut snapshot)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?
        };
        let resume = match exit {
            dsr::ThreadExit::Syscall { resume } => resume,
            dsr::ThreadExit::Continue => continue,
            dsr::ThreadExit::Sensitive(exit) => {
                let register = exit.register.ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native DSR sensitive {:?} exit has no register",
                        exit.kind
                    ))
                })?;
                match exit.kind {
                    dsr::types::SensitiveKind::ReadTpidr => {
                        if !native_snapshot_write_reg(&mut snapshot, register, guest_tpidr_el0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write TPIDR result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::WriteTpidr => {
                        guest_tpidr_el0 = native_snapshot_read_reg(&snapshot, register)
                            .ok_or_else(|| {
                                RuntimeError::Unsupported(format!(
                                    "native DSR could not read TPIDR source {register}"
                                ))
                            })?;
                    }
                    dsr::types::SensitiveKind::ReadCtr => {
                        if !native_snapshot_write_reg(&mut snapshot, register, NATIVE_CTR_EL0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write CTR_EL0 result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::ReadDczid => {
                        if !native_snapshot_write_reg(&mut snapshot, register, NATIVE_DCZID_EL0) {
                            return Err(RuntimeError::Unsupported(format!(
                                "native DSR could not write DCZID_EL0 result to {register}"
                            )));
                        }
                    }
                    dsr::types::SensitiveKind::DcZva => {
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
                continue;
            }
            dsr::ThreadExit::Fault {
                signal,
                code,
                address,
            } => {
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
                if !matches!(signal, libc::SIGSEGV | libc::SIGBUS | libc::SIGTRAP) {
                    return Err(RuntimeError::Unsupported(format!(
                        "native DSR trapped unexpected host signal {signal} at guest PC 0x{:x}",
                        snapshot.pc
                    )));
                }
                if memory.lock().resolve_native16k_write_exec_fault(
                    address.raw(),
                    snapshot.pc,
                    snapshot.esr,
                )? {
                    continue;
                }
                snapshot = lower_dsr_fault(
                    &dispatcher,
                    &memory,
                    snapshot,
                    thread_runtime.tid(),
                    code,
                    address.raw(),
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
        let outcome = dispatch_native_syscall(
            &dispatcher,
            request,
            &memory,
            thread_runtime,
            &reporter,
            trace_syscalls,
        )?;
        if matches!(outcome, DispatchOutcome::Returned { value: 0 })
            && carrick_abi::syscall::lookup_aarch64(request.number.raw())
                .is_some_and(|syscall| syscall.name == "rt_sigaction")
            && unsafe { carrick_native_install_trap_handler() } != 0
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
                let clone_rejection = memory.lock().native16k_clone_thread_rejection();
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
                            translator.after_fork_child();
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
                let proc_argv: Vec<String> = argv
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect();
                let proc_env = env.clone();
                match load_native_execve_image(&dispatcher, &path, argv, env, &plan) {
                    Ok((image, relative_relocations, resolved)) => {
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
                        let entry = image.entry();
                        let initial_sp = image.initial_stack_pointer().ok_or_else(|| {
                            RuntimeError::Unsupported(
                                "native Darwin DSR execve image has no initial stack".to_string(),
                            )
                        })?;
                        dispatcher.reset_memory_state_on_execve();
                        dispatcher.reset_signal_handlers_on_execve();
                        dispatcher.set_executable_identity(
                            resolved.clone(),
                            proc_argv.clone(),
                            proc_env,
                        );
                        crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
                        dispatcher.close_cloexec_fds();
                        memory
                            .lock()
                            .replace_image(&image, &relative_relocations, &plan)?;
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
            other => {
                return Err(RuntimeError::Unsupported(format!(
                    "native DSR Task 5 does not yet support dispatcher outcome {other:?}"
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
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
    host_code: i32,
    fault_address: u64,
) -> Result<NativeUcontextSnapshot, RuntimeError> {
    let _ = host_code;
    if let Some((page, prot)) = dispatcher.resident_fault_plan(fault_address) {
        let mut memory = memory.lock();
        let linux_page_size = memory.linux_page_size as usize;
        if memory.protect_range(page, linux_page_size, prot).is_ok() {
            drop(memory);
            dispatcher.commit_resident_fault(page);
            return Ok(snapshot);
        }
    }
    if memory
        .lock()
        .resolve_native16k_write_exec_fault(fault_address, snapshot.pc, snapshot.esr)?
    {
        return Ok(snapshot);
    }
    let Some((mut signum, mut si_code, si_addr)) =
        crate::vcpu_loop::lower_el0_fault(snapshot.esr, snapshot.pc, fault_address)
    else {
        native_die_by_signal(dispatcher, crate::linux_abi::LINUX_SIGSEGV);
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

fn resume_guest_after_syscall(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    resume_pc: u64,
    return_value: i64,
    syscall_nr: u64,
    tid: crate::thread::ThreadId,
) -> Result<(), RuntimeError> {
    let pc = {
        let mut memory = memory.lock();
        let mut trap = NativeSignalTrap::new(&mut memory, snapshot, Some(syscall_nr));
        trap.complete_syscall(return_value)?;
        trap.set_pc(resume_pc);
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
        let pc = trap.pc();
        trap.commit();
        pc
    };
    resume_guest_at(pc)?;
    Ok(())
}

fn resume_guest_after_kick(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
) -> Result<(), RuntimeError> {
    let pc = {
        let mut memory = memory.lock();
        let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
        let action = crate::vcpu_loop::deliver_pending_signal(
            &mut trap,
            dispatcher,
            None,
            tid,
            Some(snapshot.pc),
        )?;
        if let Some(action) = action {
            if let Some(signum) = action.stop_signal {
                crate::exec_helpers::stop_by_signal(signum);
            }
            if let Some(signum) = action.term_signal {
                native_die_by_signal(dispatcher, signum);
            }
        }
        let pc = trap.pc();
        trap.commit();
        pc
    };
    resume_guest_at(pc)?;
    Ok(())
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

fn resume_guest_from_sigreturn(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    tid: crate::thread::ThreadId,
) -> Result<(), RuntimeError> {
    let pc = {
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
        let pc = trap.pc();
        trap.commit();
        pc
    };
    resume_guest_at(pc)
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
    kick_state: Option<Arc<NativeKickState>>,
    threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>>,
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
            kick_state: None,
            threads: Arc::new(parking_lot::Mutex::new(Vec::new())),
            finished: false,
            forked_stale: false,
        };
        runtime
            .registry
            .record_thread_port(runtime.tid, crate::host_proc::current_thread_port());
        runtime
    }

    fn reset_after_fork_child(&mut self) {
        // The runtime being replaced is the parent's COW copy. Its kicker
        // registry mutexes may have been inherited LOCKED (another parent
        // thread mid-`kick_all` at fork instant); mark it stale so the
        // assignment's implicit Drop discards it without locking them —
        // pre-fix the child deadlocked here in `release_kick_target` →
        // `unregister` (the clone3signalflight/execpermitchurn load-coupled
        // campaign TIMEOUTs).
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
            kick_state: None,
            threads: Arc::clone(&self.threads),
            finished: false,
            forked_stale: false,
        }
    }

    fn prepare_kick_target(&mut self) -> Result<(), RuntimeError> {
        if self.kick_state.is_some() {
            return Ok(());
        }
        if unsafe { carrick_native_install_trap_handler() } != 0 {
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
        crate::host_signal::publish_pending_for(target.raw(), signum);
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

    fn commit(&self) {
        for (index, value) in self.regs.x.iter().enumerate() {
            set_guest_register(index as u32, *value);
        }
        for (index, value) in self.regs.v.iter().enumerate() {
            set_guest_vector(index as u32, value);
        }
        unsafe {
            carrick_native_set_sp(self.regs.sp);
            carrick_native_set_pc(self.regs.pc);
            carrick_native_set_processor_state(self.regs.pstate, self.regs.fpsr, self.regs.fpcr);
        }
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

fn dispatch_native_syscall(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &SharedNativeMemory,
    thread_runtime: &NativeThreadRuntime,
    reporter: &CompatReporter,
    trace_syscalls: bool,
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
                match wait_native_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask) {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && native_wait_park_if_quiesce_nudge(
                                dispatcher,
                                thread_runtime,
                                sig_mask,
                            )
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
                match wait_native_poll_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask) {
                    Ok(NativeWaitResult::Ready) => continue,
                    Ok(NativeWaitResult::TimedOut) => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && native_wait_park_if_quiesce_nudge(
                                dispatcher,
                                thread_runtime,
                                sig_mask,
                            )
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
                match wait_native_fds(dispatcher, thread_runtime, &fds, timeout, sig_mask) {
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
                            && native_wait_park_if_quiesce_nudge(
                                dispatcher,
                                thread_runtime,
                                sig_mask,
                            )
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
            } => match wait_native_signals(
                dispatcher,
                thread_runtime,
                wait_set,
                block_mask,
                timeout,
                &mut signal_wait_deadline,
            ) {
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
                let value = wait_native_futex(dispatcher, thread_runtime, wait, timeout, 0);
                // A pure fork-quiesce nudge: park, then RE-DISPATCH the
                // syscall (revalidating the futex word — Linux syscall
                // restart semantics) instead of surfacing a spurious EINTR.
                if value == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && native_wait_park_if_quiesce_nudge(
                        dispatcher,
                        thread_runtime,
                        carrick_abi::WaitSigMask::NONE,
                    )
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
                let value = wait_native_futex(dispatcher, thread_runtime, wait, timeout, index);
                if value == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && native_wait_park_if_quiesce_nudge(
                        dispatcher,
                        thread_runtime,
                        carrick_abi::WaitSigMask::NONE,
                    )
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
                let retval = wait_native_shared_futex(
                    dispatcher,
                    thread_runtime,
                    location,
                    waiter_key,
                    value,
                    timeout,
                    0,
                );
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && native_wait_park_if_quiesce_nudge(
                        dispatcher,
                        thread_runtime,
                        carrick_abi::WaitSigMask::NONE,
                    )
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
                let retval = wait_native_shared_futex(
                    dispatcher,
                    thread_runtime,
                    location,
                    waiter_key,
                    value,
                    timeout,
                    index,
                );
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval()
                    && native_wait_park_if_quiesce_nudge(
                        dispatcher,
                        thread_runtime,
                        carrick_abi::WaitSigMask::NONE,
                    )
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
                let retval = wait_native_shared_futex(
                    dispatcher,
                    thread_runtime,
                    location,
                    waiter_key,
                    value,
                    None,
                    0,
                );
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval() {
                    if native_wait_park_if_quiesce_nudge(
                        dispatcher,
                        thread_runtime,
                        carrick_abi::WaitSigMask::NONE,
                    ) {
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
                        match wait_native_fds(
                            dispatcher,
                            thread_runtime,
                            &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                            None,
                            carrick_abi::WaitSigMask::NONE,
                        ) {
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
                                    && native_wait_park_if_quiesce_nudge(
                                        dispatcher,
                                        thread_runtime,
                                        carrick_abi::WaitSigMask::NONE,
                                    )
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
            DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                match wait_native_proc_exit(dispatcher, thread_runtime, pid, sig_mask) {
                    Ok(NativeWaitResult::Ready) | Ok(NativeWaitResult::TimedOut) => continue,
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && native_wait_park_if_quiesce_nudge(
                                dispatcher,
                                thread_runtime,
                                sig_mask,
                            )
                        {
                            continue;
                        }
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnProcState { sig_mask, .. } => {
                match wait_native_proc_state(dispatcher, thread_runtime, sig_mask) {
                    Ok(NativeWaitResult::Ready) | Ok(NativeWaitResult::TimedOut) => continue,
                    Err(errno) => {
                        if errno == crate::linux_abi::LINUX_EINTR
                            && native_wait_park_if_quiesce_nudge(
                                dispatcher,
                                thread_runtime,
                                sig_mask,
                            )
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
                match wait_native_sleep_until(dispatcher, thread_runtime, deadline) {
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
        // W^X boundary (311fae9e), kept narrow and explicit: W+X pages while
        // multithreaded are already unreachable (creation is rejected while
        // MT, and thread creation is rejected while W+X exists) — if the
        // invariant ever breaks, fail honestly instead of forking a torn
        // W^X state machine.
        if memory.lock().has_native16k_write_exec_pages() {
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
        match pipe_pair() {
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
    // Both branches: the forking thread (the sole survivor in the child) owns
    // the guards and must release them before any signal-static use below.
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
    // W^X boundary (311fae9e), kept narrow and explicit — see the fork-side
    // twin; unreachable while the creation-side rejections hold.
    if memory.lock().has_native16k_write_exec_pages() {
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
            crate::host_signal::publish_pending_for(parent_tid, exit_signal);
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

fn snapshot_ucontext() -> Result<NativeUcontextSnapshot, RuntimeError> {
    let mut snapshot = NativeUcontextSnapshot::default();
    let rc = unsafe { carrick_native_snapshot_ucontext(&mut snapshot) };
    if rc == 0 {
        Ok(snapshot)
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to snapshot trap context: {rc}"
        )))
    }
}

fn resume_guest(value: u64, pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_return(value);
    }
    resume_guest_at(pc)
}

fn resume_guest_snapshot(snapshot: &NativeUcontextSnapshot) -> Result<(), RuntimeError> {
    for (index, value) in snapshot.x.iter().enumerate() {
        set_guest_register(index as u32, *value);
    }
    for (index, value) in snapshot.v.iter().enumerate() {
        set_guest_vector(index as u32, value);
    }
    unsafe {
        carrick_native_set_sp(snapshot.sp);
    }
    resume_guest_at(snapshot.pc)
}

fn resume_guest_detached(value: u64, pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_return(value);
        carrick_native_set_pc(pc);
    }
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some()
        && let Ok(snapshot) = snapshot_ucontext()
    {
        child_write_stderr(
            format!(
                "native trace pid={} detached-resume pc=0x{:x} x0=0x{:x}\n",
                unsafe { libc::getpid() },
                snapshot.pc,
                snapshot.x[0]
            )
            .as_bytes(),
        );
    }
    let install = unsafe { carrick_native_install_trap_handler() };
    if install != 0 {
        return Err(last_io_error(
            "reinstall native Darwin detached trap handler",
        ));
    }
    let rc = unsafe { carrick_native_resume_detached_context() };
    if rc == 1 {
        Ok(())
    } else if rc < 0 {
        Err(last_io_error(&format!(
            "detached-resume native Darwin guest at 0x{pc:x}"
        )))
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to detached-resume guest: {rc}"
        )))
    }
}

fn set_guest_register(index: u32, value: u64) {
    if index < 31 {
        unsafe {
            carrick_native_set_register(index, value);
        }
    }
}

fn set_guest_vector(index: u32, value: &[u8; 16]) {
    if index < 32 {
        unsafe {
            carrick_native_set_vector(index, value.as_ptr());
        }
    }
}

fn snapshot_register(snapshot: &NativeUcontextSnapshot, index: u32) -> u64 {
    usize::try_from(index)
        .ok()
        .and_then(|idx| snapshot.x.get(idx).copied())
        .unwrap_or(0)
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

fn resume_guest_at(pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_pc(pc);
    }
    let install = unsafe { carrick_native_install_trap_handler() };
    if install != 0 {
        return Err(last_io_error("reinstall native Darwin trap handler"));
    }
    let rc = unsafe { carrick_native_resume() };
    if rc == 1 {
        Ok(())
    } else if rc < 0 {
        Err(last_io_error(&format!(
            "resume native Darwin guest at 0x{pc:x}"
        )))
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to resume guest: {rc}"
        )))
    }
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

fn decode_native_trap(memory: &NativeMappedMemory, pc: u64) -> Result<NativeTrap, RuntimeError> {
    if let Some(trap) = decode_trap_instruction(memory.read_u32(pc)?, pc)? {
        return Ok(trap);
    }
    if pc >= 4
        && let Some(trap) = decode_trap_instruction(memory.read_u32(pc - 4)?, pc - 4)?
    {
        return Ok(trap);
    }
    Err(RuntimeError::Unsupported(format!(
        "native Darwin SIGTRAP at non-syscall PC 0x{pc:x}"
    )))
}

fn decode_trap_instruction(word: u32, pc: u64) -> Result<Option<NativeTrap>, RuntimeError> {
    if (word & 0xffe0_001f) != 0xd420_0000 {
        return Ok(None);
    }
    let imm = ((word >> 5) & 0xffff) as u16;
    let resume_pc = pc
        .checked_add(4)
        .ok_or_else(|| RuntimeError::Unsupported("native Darwin trap PC overflow".to_string()))?;
    if imm == BRK_NATIVE_SYSCALL_IMM {
        return Ok(Some(NativeTrap::Syscall { resume_pc }));
    }
    if (BRK_NATIVE_MRS_TPIDR_IMM_BASE..BRK_NATIVE_MRS_TPIDR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadTpidr {
            rt: u32::from(imm - BRK_NATIVE_MRS_TPIDR_IMM_BASE),
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MSR_TPIDR_IMM_BASE..BRK_NATIVE_MSR_TPIDR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::WriteTpidr {
            rt: u32::from(imm - BRK_NATIVE_MSR_TPIDR_IMM_BASE),
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MRS_CTR_IMM_BASE..BRK_NATIVE_MRS_CTR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadConstant {
            rt: u32::from(imm - BRK_NATIVE_MRS_CTR_IMM_BASE),
            value: NATIVE_CTR_EL0,
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MRS_DCZID_IMM_BASE..BRK_NATIVE_MRS_DCZID_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadConstant {
            rt: u32::from(imm - BRK_NATIVE_MRS_DCZID_IMM_BASE),
            value: NATIVE_DCZID_EL0,
            resume_pc,
        }));
    }
    if (BRK_NATIVE_DC_ZVA_IMM_BASE..BRK_NATIVE_DC_ZVA_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::DcZva {
            rt: u32::from(imm - BRK_NATIVE_DC_ZVA_IMM_BASE),
            resume_pc,
        }));
    }
    Ok(None)
}

struct NativeMappedMemory {
    regions: Vec<NativeMappedRegion>,
    protections: MemoryProtections,
    native_page_protections: BTreeMap<u64, u64>,
    native_write_exec_writable_pages: BTreeSet<u64>,
    linux4k_page_protections: BTreeMap<u64, [u64; 4]>,
    exclusive_reservation: Option<NativeExclusiveReservation>,
    host_page_size: u64,
    linux_page_size: u64,
    native_code_mode: carrick_spec::NativeCodeModeRequest,
    dsr_generations: dsr::cache::PageGenerationTable,
    dsr_translator: Option<Arc<dsr::ProcessTranslator>>,
}

#[derive(Clone, Copy)]
struct NativeExclusiveReservation {
    address: u64,
    width: usize,
    observed: u64,
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

impl NativeMappedMemory {
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
        if self.native_code_mode != carrick_spec::NativeCodeModeRequest::Dsr || len == 0 {
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
        Self::map_with_code_mode(
            image,
            layout,
            host_page_size,
            linux_page_size,
            carrick_spec::NativeCodeModeRequest::Brk,
        )
    }

    fn map_for_plan(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        plan: &ExecutionPlan,
    ) -> Result<Self, RuntimeError> {
        Self::map_with_code_mode(
            image,
            layout,
            host_page_size,
            linux_page_size,
            plan.native_code_mode,
        )
    }

    fn map_with_code_mode(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
        native_code_mode: carrick_spec::NativeCodeModeRequest,
    ) -> Result<Self, RuntimeError> {
        if let Some(region) = image
            .regions()
            .iter()
            .find(|region| region.start < NATIVE_DARWIN_HARD_PAGEZERO_END)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin cannot directly map guest region 0x{:x}..0x{:x} below 0x{NATIVE_DARWIN_HARD_PAGEZERO_END:x}: arm64 Mach-O enforces a hard 4 GiB __PAGEZERO; use a PIE/ET_DYN image or an address-virtualizing backend",
                region.start, region.end
            )));
        }
        let mut regions = Vec::new();
        for region in image.regions() {
            map_region(region, native_code_mode)?;
            if region.start == NATIVE_DARWIN_VDSO_BASE && region.perms.execute {
                relocate_vdso_vvar_loads(region, native_code_mode)?;
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
            libc::PROT_READ | libc::PROT_EXEC,
            true,
            native_code_mode,
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
        map_anonymous_region(layout.heap_base, layout.heap_size, false)?;
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
        map_anonymous_region(layout.mmap_base, layout.mmap_size, false)?;
        regions.push(NativeMappedRegion {
            start: layout.mmap_base,
            end: checked_add_u64(layout.mmap_base, layout.mmap_size, "native mmap arena end")?,
            host_protects: true,
            shared_futex: false,
            guest_writable: true,
            default_prot: if linux_page_size == host_page_size {
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE
            } else {
                0
            },
            shared_key_base: 0,
            shared_key_offset: 0,
        });
        map_anonymous_region(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE,
            true,
        )?;
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
        map_anonymous_region(
            crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            false,
        )?;
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
        let memory = Self {
            regions,
            protections,
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_reservation: None,
            host_page_size,
            linux_page_size,
            native_code_mode,
            dsr_generations: dsr::cache::PageGenerationTable::new(host_page_size)
                .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
            dsr_translator: if native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr {
                Some(Arc::new(
                    dsr::ProcessTranslator::new(64 * 1024 * 1024)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?,
                ))
            } else {
                None
            },
        };
        // Publishing the vvar contents is part of establishing the address
        // space: the initial boot maps here, and an execve replacement re-maps
        // here (`replace_image`), so both get a freshly stamped vvar.
        memory.stamp_vdso_vvar()?;
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
        let page_ptr = usize::try_from(page_start).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin vvar page too large: {page_start:#x}"
            ))
        })? as *mut libc::c_void;
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
                    address as usize as *mut u8,
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
            let Ok(start) = usize::try_from(region.start) else {
                continue;
            };
            let Ok(len) = usize::try_from(region.end.saturating_sub(region.start)) else {
                continue;
            };
            let changed =
                set_native_region_fork_inheritance(start as *mut libc::c_void, len, share);
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

    fn replace_image(
        &mut self,
        image: &AddressSpace,
        relative_relocations: &[NativeRelativeRelocation],
        plan: &ExecutionPlan,
    ) -> Result<(), RuntimeError> {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .iter()
            .map(|region| (region.start, region.end))
            .collect();
        ranges.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        for (start, end) in merged {
            let len = usize::try_from(end.saturating_sub(start)).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve unmap range too large: 0x{start:x}..0x{end:x}"
                ))
            })?;
            let address = usize::try_from(start).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve unmap address too large: 0x{start:x}"
                ))
            })? as *mut libc::c_void;
            if len != 0 && unsafe { libc::munmap(address, len) } != 0 {
                return Err(last_io_error(&format!(
                    "munmap native Darwin execve range 0x{start:x}..0x{end:x}"
                )));
            }
        }
        let mut replacement = Self::map_for_plan(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            plan.page_geometry.linux_page_size,
            plan,
        )?;
        apply_native_relative_relocations(&mut replacement, relative_relocations)?;
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

    fn native16k_clone_thread_rejection(&self) -> Option<&'static str> {
        self.has_native16k_write_exec_pages()
            .then_some("native16k cannot create a guest thread while write-exec pages are present")
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
        let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
            address: operation_address,
            length: operation_len,
        })? as *mut u8;
        if self.native_code_mode == carrick_spec::NativeCodeModeRequest::Brk {
            patch_syscalls(ptr, page_len);
        }
        unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
        let prot = self
            .native_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| self.default_linux_prot_at(page_start));
        self.mprotect_host_page(
            page_start,
            native16k_host_prot(prot, self.native_code_mode),
            operation_address,
            operation_len,
        )?;
        self.native_write_exec_writable_pages.remove(&page_start);
        Ok(())
    }

    fn prepare_dsr_execution(&mut self, pc: u64) -> Result<(), MemoryError> {
        if self.native_code_mode != carrick_spec::NativeCodeModeRequest::Dsr {
            return Ok(());
        }
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
        let Some(reservation) = self.exclusive_reservation else {
            return;
        };
        let Some(end) = address.checked_add(len as u64) else {
            self.exclusive_reservation = None;
            return;
        };
        let Some(reservation_end) = reservation.address.checked_add(reservation.width as u64)
        else {
            self.exclusive_reservation = None;
            return;
        };
        if address < reservation_end && reservation.address < end {
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
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
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
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
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
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
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
        if !address.is_multiple_of(width as u64) || !self.region_contains(address, width) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
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
        self.exclusive_reservation = Some(NativeExclusiveReservation {
            address,
            width,
            observed,
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
        let Some(reservation) = self.exclusive_reservation.take() else {
            return Ok(false);
        };
        if reservation.address != address || reservation.width != width {
            return Ok(false);
        }
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
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
            return native16k_host_prot(prot, self.native_code_mode);
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
        let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
            address: operation_address,
            length: operation_len,
        })? as *mut libc::c_void;
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
            let host_prot = match state {
                HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
                HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
            };
            if protections
                .iter()
                .any(|value| value & crate::linux_abi::LINUX_PROT_EXEC != 0)
            {
                self.mprotect_host_page(
                    page_start,
                    libc::PROT_READ | libc::PROT_WRITE,
                    address,
                    len,
                )?;
                let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
                    address,
                    length: len,
                })? as *mut u8;
                let page_len =
                    usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
                patch_syscalls(ptr, page_len);
                unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
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
        let ptr = usize::try_from(address).map_err(|_| {
            RuntimeError::Unsupported(format!("guest address too large: 0x{address:x}"))
        })? as *mut u64;
        unsafe { std::ptr::write_unaligned(ptr, value) };
        Ok(())
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
        let mut page = self.read_bytes_raw(page_start, page_len)?;
        let offset = usize::try_from(address.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address,
                length: len,
            }
        })?;
        page[offset..offset + len].copy_from_slice(content);

        let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: len,
        })? as *mut libc::c_void;
        let mapped = unsafe {
            libc::mmap(
                ptr,
                page_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
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
        let addr =
            usize::try_from(if page_delta == 0 { address } else { page_start }).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias start too large: 0x{address:x}"
                ))
            })? as *mut libc::c_void;

        let (mmap_prot, final_prot, flags, fd, offset, direct_file) = match file {
            Some((fd, offset, prot)) if page_delta == 0 => (
                prot,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                offset,
                true,
            ),
            Some((fd, offset, prot)) => (
                libc::PROT_READ | libc::PROT_WRITE,
                prot,
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_NORESERVE,
                fd,
                offset,
                false,
            ),
            None => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_NORESERVE,
                -1,
                0,
                false,
            ),
        };
        let mmap_fd = if direct_file { fd } else { -1 };
        let mmap_offset = if direct_file { offset } else { 0 };
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
            if final_prot != mmap_prot {
                let rc = unsafe { libc::mprotect(mapped, host_map_len_usize, final_prot) };
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
        F: FnMut(u64, usize, libc::c_int) -> Result<(), MemoryError>,
    {
        let host_prot = native16k_host_prot(prot, self.native_code_mode);
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

        let pages: Vec<(u64, *mut libc::c_void)> = pages
            .into_iter()
            .map(|page_start| {
                let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
                    address,
                    length: len,
                })? as *mut libc::c_void;
                Ok((page_start, ptr))
            })
            .collect::<Result<_, MemoryError>>()?;

        struct ProtectionSnapshot {
            page_start: u64,
            ptr: *mut libc::c_void,
            old_host_prot: libc::c_int,
            patched_words: Vec<(usize, u32)>,
        }

        let mut snapshots = Vec::with_capacity(pages.len());
        let apply_result = (|| {
            for &(page_start, ptr) in &pages {
                let old_host_prot = self.native_host_prot_for_page(page_start);
                if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                    let mut patched_words = Vec::new();
                    if self.native_code_mode == carrick_spec::NativeCodeModeRequest::Brk {
                        set_host_prot(
                            page_start,
                            host_page_len,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )?;
                        patch_syscalls_recording(
                            ptr.cast::<u8>(),
                            host_page_len,
                            |offset, original| patched_words.push((offset, original)),
                        );
                    } else {
                        set_host_prot(page_start, host_page_len, libc::PROT_READ)?;
                    }
                    snapshots.push(ProtectionSnapshot {
                        page_start,
                        ptr,
                        old_host_prot,
                        patched_words,
                    });
                    unsafe { carrick_native_clear_icache(ptr, host_page_len) };
                } else {
                    snapshots.push(ProtectionSnapshot {
                        page_start,
                        ptr,
                        old_host_prot,
                        patched_words: Vec::new(),
                    });
                }
                set_host_prot(page_start, host_page_len, host_prot)?;
            }
            Ok(())
        })();

        if let Err(error) = apply_result {
            let mut rollback_error = None;
            for snapshot in snapshots.iter().rev() {
                if !snapshot.patched_words.is_empty() {
                    match set_host_prot(
                        snapshot.page_start,
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
                    set_host_prot(snapshot.page_start, host_page_len, snapshot.old_host_prot)
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

        for (page_start, _) in pages {
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
        let ptr = usize::try_from(address)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?
            as *const u8;
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
        let ptr = usize::try_from(address)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?
            as *mut u8;
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
                |page_start, page_len, host_prot| {
                    let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })? as *mut libc::c_void;
                    if unsafe { libc::mprotect(ptr, page_len, host_prot) } != 0 {
                        return Err(MemoryError::HostMap(format!(
                            "mprotect native Darwin host page 0x{page_start:x}: {}",
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
        let word = usize::try_from(guest_addr).ok()?;
        // Guest VA == host VA under native, so the physical os_sync SHARED
        // wait/wake already rendezvous across mappings; the waiter-COUNT key
        // must too. A direct MAP_SHARED file mapping keys by file identity +
        // file offset (HVF's scheme): the native exec rebuilds the address
        // space, so an exec'd child re-attaches the same file at a different
        // VA and a VA key would miss the parent's registered waiter
        // (ltpcheckpointexec). Anon MAP_SHARED (fork-inherited, same VA in
        // every process) keeps the VA key.
        let waiter_key = if region.shared_key_base == 0 {
            word
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

fn native16k_host_prot(
    prot: u64,
    native_code_mode: carrick_spec::NativeCodeModeRequest,
) -> libc::c_int {
    let mut host_prot = linux_prot_to_native(prot);
    let write_exec = crate::linux_abi::LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC;
    if prot & write_exec == write_exec {
        host_prot &= !libc::PROT_WRITE;
    }
    if native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr
        && prot & crate::linux_abi::LINUX_PROT_EXEC != 0
    {
        host_prot = (host_prot & !libc::PROT_EXEC) | libc::PROT_READ;
    }
    host_prot
}

fn map_region(
    region: &MemoryRegion,
    native_code_mode: carrick_spec::NativeCodeModeRequest,
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
    let addr = usize::try_from(region.start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin region start too large: 0x{:x}",
            region.start
        ))
    })? as *mut libc::c_void;
    let share = if region.shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | share,
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
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for 0x{:x}",
            region.start
        )));
    }

    let bytes = region.bytes();
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
    }
    if region.perms.execute && native_code_mode == carrick_spec::NativeCodeModeRequest::Brk {
        patch_syscalls(mapped.cast::<u8>(), bytes.len());
    }
    if region.perms.execute {
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
    }

    let mut prot = region_prot(region);
    if region.perms.execute && native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr {
        prot = (prot & !libc::PROT_EXEC) | libc::PROT_READ;
    }
    let protect = unsafe { libc::mprotect(mapped, length, prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    Ok(())
}

fn map_bytes_region(
    start: u64,
    length_u64: u64,
    bytes: &[u8],
    final_prot: libc::c_int,
    executable: bool,
    native_code_mode: carrick_spec::NativeCodeModeRequest,
) -> Result<(), RuntimeError> {
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
    let addr = usize::try_from(start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin byte region start too large: 0x{start:x}"
        ))
    })? as *mut libc::c_void;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
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
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for byte region 0x{start:x}"
        )));
    }
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
    }
    if executable && native_code_mode == carrick_spec::NativeCodeModeRequest::Brk {
        patch_syscalls(mapped.cast::<u8>(), bytes.len());
    }
    if executable {
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
    }
    let final_prot = if executable && native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr {
        (final_prot & !libc::PROT_EXEC) | libc::PROT_READ
    } else {
        final_prot
    };
    let protect = unsafe { libc::mprotect(mapped, length, final_prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    Ok(())
}

fn map_anonymous_region(start: u64, length: u64, shared: bool) -> Result<(), RuntimeError> {
    let length = usize::try_from(length).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region too large: 0x{start:x}+0x{length:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let addr = usize::try_from(start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region start too large: 0x{start:x}"
        ))
    })? as *mut libc::c_void;
    let share = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | share,
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
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for anonymous region 0x{start:x}"
        )));
    }
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

fn region_prot(region: &MemoryRegion) -> libc::c_int {
    let mut prot = 0;
    if region.perms.read {
        prot |= libc::PROT_READ;
    }
    if region.perms.write {
        prot |= libc::PROT_WRITE;
    }
    // The large mmap arena is executable in the HVF stage-1 model so later
    // guest mmap/mprotect can grant execute permission without remapping host
    // memory. Native starts narrower: executable permissions are applied to
    // initialized executable regions, not to lazy zero data arenas.
    if region.perms.execute && !region.bytes().is_empty() {
        prot |= libc::PROT_EXEC;
    }
    prot
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
    native_code_mode: carrick_spec::NativeCodeModeRequest,
) -> Result<(), RuntimeError> {
    let length = region.bytes().len();
    let base = usize::try_from(region.start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin vdso base too large: {:#x}",
            region.start
        ))
    })? as *mut u8;
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
    let final_prot = if native_code_mode == carrick_spec::NativeCodeModeRequest::Dsr {
        libc::PROT_READ
    } else {
        libc::PROT_READ | libc::PROT_EXEC
    };
    if unsafe { libc::mprotect(base.cast(), length, final_prot) } != 0 {
        return Err(last_io_error("restore native Darwin vdso page protections"));
    }
    Ok(())
}

fn patch_syscalls(base: *mut u8, length: usize) {
    patch_syscalls_recording(base, length, |_, _| {});
}

fn patch_syscalls_recording(base: *mut u8, length: usize, mut record: impl FnMut(usize, u32)) {
    let words = length / std::mem::size_of::<u32>();
    for index in 0..words {
        let offset = index * std::mem::size_of::<u32>();
        let ptr = unsafe { base.add(offset).cast::<u32>() };
        let word = unsafe { std::ptr::read_unaligned(ptr) };
        let patched = if word == SVC_0 {
            Some(BRK_NATIVE_SYSCALL)
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_TPIDR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_TPIDR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MSR_TPIDR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MSR_TPIDR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_CTR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_CTR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_DCZID_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_DCZID_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == DC_ZVA {
            Some(brk_instruction(
                BRK_NATIVE_DC_ZVA_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == DC_CVAU
            || (word & !SYSTEM_REGISTER_RT_MASK) == IC_IVAU
        {
            Some(AARCH64_NOP)
        } else {
            None
        };
        if let Some(patched_word) = patched {
            record(offset, word);
            unsafe { std::ptr::write_unaligned(ptr, patched_word) };
        }
    }
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

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
    fn dsr_indirect_flow_runtime_rejects_unaligned_and_unmapped_targets() {
        let plan = ExecutionPlan {
            backend: crate::page_profile::ExecutionBackend::NativeDarwin,
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: 16 * 1024,
                linux_page_size: 16 * 1024,
                native_profile: Some(carrick_spec::NativePageProfile::Native16k),
            },
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
            diagnostics: Vec::new(),
        };
        for (target_word, expected) in [
            (0xd280_0020, "target is not instruction aligned"), // mov x0, #1
            (0xd280_0000, "outside an executable guest mapping"), // mov x0, #0
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
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert_eq!(result.exit_code, 125, "stderr={stderr}");
            assert!(
                stderr.contains(expected),
                "unexpected error output: {stderr}"
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
            native_code_mode: carrick_spec::NativeCodeModeRequest::Dsr,
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
        map_region(
            &image.regions()[0],
            carrick_spec::NativeCodeModeRequest::Dsr,
        )
        .expect("map DSR original code page");

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
    fn native_bridge_context_is_thread_local() {
        let mut main_context = NativeUcontextSnapshot::default();
        main_context.x[0] = 0x1111;
        assert_eq!(unsafe { carrick_native_seed_ucontext(&main_context) }, 0);

        let child_context = std::thread::spawn(|| {
            let mut context = NativeUcontextSnapshot::default();
            context.x[0] = 0x2222;
            assert_eq!(unsafe { carrick_native_seed_ucontext(&context) }, 0);
            snapshot_ucontext().expect("snapshot child native context")
        })
        .join()
        .expect("join native context child");

        let main_after = snapshot_ucontext().expect("snapshot main native context");
        assert_eq!(child_context.x[0], 0x2222);
        assert_eq!(main_after.x[0], 0x1111);
    }

    #[test]
    fn native_signal_commit_restores_processor_state() {
        let initial = NativeUcontextSnapshot::default();
        assert_eq!(unsafe { carrick_native_seed_ucontext(&initial) }, 0);

        let mut restored = NativeUcontextSnapshot {
            sp: 0x7000,
            pc: 0x4000,
            pstate: 0xa000_0000,
            fpsr: 0x0800_0000,
            fpcr: 0x0040_0000,
            ..NativeUcontextSnapshot::default()
        };
        restored.x[0] = 0x1111;
        restored.v[0] = 0x2222_u128.to_le_bytes();
        let mut memory = NativeMappedMemory {
            regions: Vec::new(),
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            native_write_exec_writable_pages: BTreeSet::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_reservation: None,
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            native_code_mode: carrick_spec::NativeCodeModeRequest::Brk,
            dsr_generations: dsr::cache::PageGenerationTable::new(16 * 1024)
                .expect("generation table"),
            dsr_translator: None,
        };
        NativeSignalTrap::new(&mut memory, restored, None).commit();

        let committed = snapshot_ucontext().expect("snapshot committed native context");
        assert_eq!(committed.x[0], restored.x[0]);
        assert_eq!(committed.sp, restored.sp);
        assert_eq!(committed.pc, restored.pc);
        assert_eq!(committed.pstate, restored.pstate);
        assert_eq!(committed.v[0], restored.v[0]);
        assert_eq!(committed.fpsr, restored.fpsr);
        assert_eq!(committed.fpcr, restored.fpcr);
    }

    #[test]
    fn native_signal_frame_restores_fpsimd_state() {
        let mut stack = vec![0_u8; 16 * 1024];
        let stack_start = stack.as_mut_ptr() as u64;
        let stack_end = stack_start + stack.len() as u64;
        let mut memory = NativeMappedMemory {
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
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            native_code_mode: carrick_spec::NativeCodeModeRequest::Brk,
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
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            native_code_mode: carrick_spec::NativeCodeModeRequest::Brk,
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
            assert_eq!(unsafe { carrick_native_install_trap_handler() }, 0);
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
            let code = if map_anonymous_region(layout.mmap_base, layout.mmap_size, false).is_ok() {
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
    fn native16k_mmap_arena_can_become_executable() {
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
            let result = NativeMappedMemory::map(&image, layout, page_size, page_size).and_then(
                |mut memory| {
                    let ret = 0xd65f_03c0_u32.to_le_bytes();
                    memory
                        .write_bytes_raw(layout.mmap_base, &ret)
                        .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                    let start = usize::try_from(layout.mmap_base)
                        .map_err(|_| RuntimeError::Unsupported("test address overflow".into()))?
                        as *mut libc::c_void;
                    unsafe { carrick_native_clear_icache(start, ret.len()) };
                    memory
                        .protect_range(
                            layout.mmap_base,
                            page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                    let entry: unsafe extern "C" fn() = unsafe { std::mem::transmute(start) };
                    unsafe { entry() };
                    Ok(())
                },
            );
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_write_exec_page_transitions_between_write_and_execute() {
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
            let transitioned = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .and_then(|mut memory| {
                    let write_exec = crate::linux_abi::LINUX_PROT_READ
                        | crate::linux_abi::LINUX_PROT_WRITE
                        | crate::linux_abi::LINUX_PROT_EXEC;
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, write_exec)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    let data_write_esr = (0x25_u64 << 26) | (1 << 6) | 0x0f;
                    if !memory.resolve_native16k_write_exec_fault(
                        layout.mmap_base,
                        NATIVE_DARWIN_PIE_BASE,
                        data_write_esr,
                    )? {
                        return Err(RuntimeError::Unsupported(
                            "write-exec data fault was not resolved".to_string(),
                        ));
                    }
                    let ret = 0xd65f_03c0_u32;
                    unsafe {
                        std::ptr::write_unaligned(
                            usize::try_from(layout.mmap_base).map_err(|_| {
                                RuntimeError::Unsupported("test address overflow".to_string())
                            })? as *mut u32,
                            ret,
                        );
                    }
                    if !memory.resolve_native16k_write_exec_fault(
                        layout.mmap_base,
                        layout.mmap_base,
                        (0x21_u64 << 26) | 0x0f,
                    )? {
                        return Err(RuntimeError::Unsupported(
                            "write-exec instruction fault was not resolved".to_string(),
                        ));
                    }
                    let entry: unsafe extern "C" fn() = unsafe {
                        std::mem::transmute(usize::try_from(layout.mmap_base).map_err(|_| {
                            RuntimeError::Unsupported("test address overflow".to_string())
                        })? as *mut libc::c_void)
                    };
                    unsafe { entry() };
                    Ok(())
                });
            unsafe { libc::_exit(i32::from(transitioned.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
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
    fn native16k_write_exec_rejects_later_clone_thread() {
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
                        .native16k_clone_thread_rejection()
                        .is_some_and(|reason| reason.contains("write-exec")))
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
                        |page_start, page_len, host_prot| {
                            let call = calls.get() + 1;
                            calls.set(call);
                            operations.borrow_mut().push((page_start, host_prot));
                            if call == 4 {
                                return Err(MemoryError::HostMap(
                                    "injected final protection failure".to_string(),
                                ));
                            }
                            let ptr = usize::try_from(page_start).map_err(|_| {
                                MemoryError::OutOfBounds {
                                    address: page_start,
                                    length: page_len,
                                }
                            })? as *mut libc::c_void;
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
                        && rollback_calls.len() >= 8
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
    fn native16k_exec_protection_patches_linux_syscalls() {
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
            let patched = NativeMappedMemory::map(&image, layout, page_size, page_size)
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
                .is_ok_and(|word| word == BRK_NATIVE_SYSCALL);
            unsafe { libc::_exit(i32::from(!patched)) };
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
            let preserved = NativeMappedMemory::map_with_code_mode(
                &image,
                layout,
                page_size,
                page_size,
                carrick_spec::NativeCodeModeRequest::Dsr,
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
    fn native_linux4k_uniform_host_page_can_become_executable() {
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
            let executable = NativeMappedMemory::map(
                &image,
                layout,
                host_page_size,
                linux_page_size,
            )
            .and_then(|mut memory| {
                let ret = 0xd65f_03c0_u32.to_le_bytes();
                memory
                    .write_bytes_unchecked(layout.mmap_base, &ret)
                    .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                memory
                    .protect_range(
                        layout.mmap_base,
                        host_page_size as usize,
                        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                    )
                    .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                let entry: unsafe extern "C" fn() =
                    unsafe {
                        std::mem::transmute(usize::try_from(layout.mmap_base).map_err(|_| {
                            RuntimeError::Unsupported("test address overflow".into())
                        })? as *mut libc::c_void)
                    };
                unsafe { entry() };
                Ok(())
            });
            unsafe { libc::_exit(i32::from(executable.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_mixed_subpage_protection_is_guarded() {
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
                .is_ok_and(|mut memory| {
                    let protected = memory
                        .protect_range(
                            layout.mmap_base + linux_page_size,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ,
                        )
                        .is_ok();
                    protected
                        && matches!(
                            memory.classify_linux4k_host_page(
                                memory.linux4k_host_page_protections(layout.mmap_base)
                            ),
                            HostPageState::MixedGuarded(_)
                        )
                });
            unsafe { libc::_exit(i32::from(!guarded)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guarded_heap_allows_adjacent_subpage_backing_write() {
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
            let wrote = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .is_ok_and(|mut memory| {
                    memory
                        .protect_range(layout.heap_base, linux_page_size as usize, 0)
                        .is_ok()
                        && memory
                            .write_bytes_unchecked(layout.heap_base + linux_page_size, &[0x5a])
                            .is_ok()
                });
            unsafe { libc::_exit(i32::from(!wrote)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_executable_tail_is_guarded_until_instruction_fetch() {
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
                .is_ok_and(|mut memory| {
                    let wrote = memory
                        .write_bytes_unchecked(layout.mmap_base, &AARCH64_NOP.to_le_bytes())
                        .is_ok();
                    let protected = memory
                        .protect_range(
                            layout.mmap_base,
                            (3 * linux_page_size) as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .is_ok();
                    let mut snapshot = NativeUcontextSnapshot {
                        pc: layout.mmap_base,
                        signal: libc::SIGBUS,
                        fault_address: layout.mmap_base,
                        ..NativeUcontextSnapshot::default()
                    };
                    wrote
                        && protected
                        && memory.linux4k_address_is_guarded(layout.mmap_base)
                        && memory.read_bytes_raw(layout.mmap_base, 4).is_ok()
                        && emulate_linux4k_guarded_fault(&mut memory, &mut snapshot).is_err()
                });
            unsafe { libc::_exit(i32::from(!guarded)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_mixed_page_decoder_exposes_scalar_load_store_operands() {
        let load = bad64::decode(0xf940_0020, 0x1000).expect("decode ldr x0, [x1]");
        let store = bad64::decode(0xf900_0020, 0x1004).expect("decode str x0, [x1]");
        let vector_load = bad64::decode(0x4c40_7020, 0x1008).expect("decode ld1 {v0.16b}, [x1]");
        let pair_load = bad64::decode(0xad40_0420, 0x100c).expect("decode ldp q0, q1, [x1]");
        let q_load = bad64::decode(0x3dc0_0420, 0x100c).expect("decode ldr q0, [x1, #16]");
        let register_store =
            bad64::decode(0xf83a_5861, 0x1010).expect("decode str x1, [x3, w26, uxtw #3]");

        assert_eq!(load.op(), bad64::Op::LDR);
        assert_eq!(store.op(), bad64::Op::STR);
        assert_eq!(load.operands().len(), 2);
        assert_eq!(store.operands().len(), 2);
        assert_ne!(load.operands()[0], load.operands()[1]);
        assert_ne!(store.operands()[0], store.operands()[1]);
        assert_eq!(vector_load.op(), bad64::Op::LD1);
        assert!(matches!(
            vector_load.operands(),
            [
                bad64::Operand::MultiReg {
                    arrspec: Some(bad64::ArrSpec::SixteenBytes(None)),
                    ..
                },
                bad64::Operand::MemReg(bad64::Reg::X1)
            ]
        ));
        assert_eq!(pair_load.op(), bad64::Op::LDP);
        assert!(matches!(
            pair_load.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q0,
                    arrspec: None,
                },
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q1,
                    arrspec: None,
                },
                bad64::Operand::MemOffset {
                    reg: bad64::Reg::X1,
                    offset: bad64::Imm::Signed(0),
                    ..
                }
            ]
        ));
        assert!(matches!(
            q_load.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q0,
                    arrspec: None,
                },
                bad64::Operand::MemOffset {
                    reg: bad64::Reg::X1,
                    offset: bad64::Imm::Signed(16),
                    ..
                }
            ]
        ));
        assert!(matches!(
            register_store.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::X1,
                    arrspec: None,
                },
                bad64::Operand::MemExt {
                    regs: [bad64::Reg::X3, bad64::Reg::W26],
                    shift: Some(bad64::Shift::UXTW(3)),
                    arrspec: None,
                }
            ]
        ));
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
                    memory
                        .write_bytes_unchecked(pc, &0xf940_0020_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            pc,
                            host_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
                    memory
                        .write_bytes_unchecked(pc, &0x4c40_7020_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
                    memory
                        .write_bytes_unchecked(pc, &0x3dc0_0420_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
                    memory
                        .write_bytes_unchecked(pc, &0xad40_0420_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
                    memory
                        .write_bytes_unchecked(pc, &0x885f_fc40_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            pc,
                            host_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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

                    memory
                        .write_bytes_unchecked(pc, &0x8803_fc44_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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

                    memory
                        .write_bytes_unchecked(pc, &0x885f_fc40_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    memory
                        .write_bytes_unchecked(address, &11_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(pc, &0x8803_fc44_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
                    memory
                        .write_bytes_unchecked(pc, &0xf820_0020_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            pc,
                            host_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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

                    memory
                        .write_bytes_unchecked(pc, &0x88df_fc20_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
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
            let mapped = map_anonymous_region(start, len, shared).is_ok();
            if !mapped {
                unsafe { libc::_exit(2) };
            }
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
            // The injected vDSO ELF page went through the same syscall
            // translation pass as ordinary executable pages, and its hardcoded
            // vvar-base loads were retargeted at the relocated native base.
            let vdso_words: Vec<u32> = unsafe {
                std::slice::from_raw_parts(
                    NATIVE_DARWIN_VDSO_BASE as usize as *const u8,
                    crate::vdso::LINUX_VDSO_SIZE as usize,
                )
            }
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
            if vdso_words.contains(&SVC_0) {
                unsafe { libc::_exit(15) }
            }
            if !vdso_words.contains(&BRK_NATIVE_SYSCALL) {
                unsafe { libc::_exit(16) }
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
}
