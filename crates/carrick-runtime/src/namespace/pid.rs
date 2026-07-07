//! PID namespace translation: a host-pid ↔ ns-pid table backed by the
//! carrick-kernel arena process section so it is coherent across `fork`
//! (design §3.3, §5.2, §5.6).
//!
//! The arena is allocated **before the first guest fork** and inherited by
//! every descendant: all processes map the same physical pages, so a
//! `fetch_add`/`compare_exchange` on an atomic in one process is visible to all
//! others (Apple-Silicon hardware atomics operate on physical addresses).
//!
//! Only the *initial* root PID namespace is modeled by the global region for
//! now — the common `docker run` case (one fresh pid ns whose init is pid 1).
//! Nested guest-created namespaces (Phase 4) extend this; the slot model already
//! carries enough to distinguish them by `init_host_pid` if needed later.
//!
//! NOTE: the translation/shared-region API below is wired into the fork path,
//! `getpid`/`getppid`, `wait4`/`kill`, and `/proc` in Phase 2. Until then the
//! items are unused; the module-level `allow(dead_code)` is removed once Phase 2
//! lands.
#![allow(dead_code)]

use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use carrick_kernel::arena::{ARENA_PATH_ENV, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::process::{
    FLAG_ALIVE, FLAG_DEAD, FLAG_ORPHANED, PROCESS_RECORDS, ProcessRecord, ProcessRecordRef,
    ProcessSection, REGISTERING,
};

use super::NsId;

/// Member is alive and (so far as we know) parented within the namespace.
pub const MEMBER_ALIVE: u32 = FLAG_ALIVE;
/// Member's namespace-parent died; `getppid` should report ns-pid 1 (design
/// §3.6). Set by the NsSupervisor.
pub const MEMBER_ORPHANED: u32 = FLAG_ORPHANED;
/// Member has exited; `exit_status` holds the harvested bare exit code (the
/// multiplexer's `PollEvent::exit_status`: WEXITSTATUS, or 128+signal for a
/// signal death) so the ns-init can report it for an orphaned grandchild (§3.4).
pub const MEMBER_DEAD: u32 = FLAG_DEAD;

/// Number of process records scanned by the namespace supervisor.
pub const MEMBER_SLOTS: usize = PROCESS_RECORDS;

/// ns-pid 1 — the namespace init (`pid_namespaces(7)`).
pub const NS_INIT_PID: u32 = 1;

/// Sentinel used while a process is filling a slot. Readers must treat it as
/// unpublished; the real host pid is release-stored only after the rest of the
/// slot is initialized.
pub const HOST_PID_REGISTERING: u32 = REGISTERING;
const RUN_STATE_KIND_TID: u64 = 1 << 40;

pub type MemberSlot = ProcessRecord;

/// Active PID namespace view over the arena's process section.
#[derive(Clone, Copy)]
pub struct NsSharedRegion {
    section: &'static ProcessSection,
}

/// Global pointer to the active process section, inherited across fork (the
/// child's static still points at the same physical pages). Null until [`init`].
static REGION: AtomicPtr<ProcessSection> = AtomicPtr::new(std::ptr::null_mut());

/// Set by the container launch path (`Runtime::execute`) to request that the
/// root guest be placed in a fresh PID namespace. `run-elf` never sets it, so
/// the single-ELF path stays in the identity ns (design §3.2, §5.2). Read by
/// `run_threaded_hvf_loop` to decide whether to allocate the shared region.
static REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Request launch-time PID-namespace placement for this run (container path):
/// the in-process translation layer (getpid()==1 etc.). Always safe — no fork.
pub fn request() {
    REQUESTED.store(true, Ordering::Relaxed);
}

/// Whether launch-time PID-namespace placement was requested.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}

/// Whether to fork the NsSupervisor PROCESS (orphan reaping + teardown). This
/// is gated separately from [`request`] because the supervisor becomes the
/// fork PARENT and returns the run's result — which carries NO buffered
/// stdout/stderr. So it is only enabled for streaming output paths (raw / tty /
/// detached), where the guest writes straight to inherited fds; the buffered
/// JSON-envelope path keeps running the guest in-process (translation still
/// works via the region) and gets its output back as before.
static SUPERVISOR_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Request the forking NsSupervisor (streaming-output container runs only).
pub fn request_supervisor() {
    REQUESTED.store(true, Ordering::Relaxed);
    SUPERVISOR_REQUESTED.store(true, Ordering::Relaxed);
}

/// Whether the forking NsSupervisor was requested.
pub fn supervisor_requested() -> bool {
    SUPERVISOR_REQUESTED.load(Ordering::Relaxed)
}

/// The write end of the member-registration pipe, inherited across fork. A
/// freshly-forked guest writes one byte here after registering, waking the
/// NsSupervisor to arm an exit watch on it (design §3.5). −1 until set up.
static REG_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Publish the registration pipe's write fd (called pre-fork in the supervisor
/// setup so every descendant inherits it).
pub fn set_reg_pipe_write(fd: i32) {
    REG_PIPE_WRITE.store(fd, Ordering::Relaxed);
}

/// Notify the NsSupervisor that a new member registered: write one byte to the
/// registration pipe (non-blocking; a full pipe is fine — the supervisor also
/// rescans on a periodic timeout). No-op if the pipe is not set up.
pub fn notify_registration() {
    let fd = REG_PIPE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8];
        // SAFETY: writing one byte to a pipe fd; ignore EAGAIN/short write.
        unsafe {
            libc::write(fd, byte.as_ptr().cast(), 1);
        }
    }
}

/// Activate the arena process section for PID namespace membership, WITHOUT yet
/// knowing the init's host pid. Must be called **once, before the NsSupervisor
/// fork** (design §3.3) so both the supervisor parent and the guest-init child
/// inherit the same physical pages. The child then calls [`set_init`] with its
/// own pid. Returns `false` only if the arena cannot be initialized.
/// Idempotent — returns `true` if the region already exists.
pub fn alloc_region() -> bool {
    if !REGION.load(Ordering::Acquire).is_null() {
        return true;
    }
    persist_detached_arena_path();
    activate_global_arena()
}

/// Attach an EXISTING file-backed arena (for `carrick exec`) as a new member.
/// Does NOT seed the pid allocator — the arena already holds the container's
/// live state. Returns `false` on any failure (the caller must not run outside
/// the namespace).
pub fn attach_region(path: &std::path::Path) -> bool {
    if !REGION.load(Ordering::Acquire).is_null() {
        return true;
    }
    // SAFETY: exec join happens in the single-threaded CLI/runtime setup before
    // guest threads or forks; it tells the arena singleton to attach this file.
    unsafe {
        std::env::set_var(ARENA_PATH_ENV, path);
    }
    activate_global_arena()
}

fn activate_global_arena() -> bool {
    let section = &KernelArena::init_global().layout().processes;
    REGION.store(std::ptr::from_ref(section).cast_mut(), Ordering::Release);
    true
}

/// For a detached container (`CARRICK_CONTAINER_ID` set), record the kernel
/// arena file path into the registry so `carrick exec` can attach to it.
fn persist_detached_arena_path() {
    let Ok(id) = std::env::var("CARRICK_CONTAINER_ID") else {
        return;
    };
    if !crate::container::is_safe_id(&id) {
        return;
    }
    let Some(path) = std::env::var_os(ARENA_PATH_ENV) else {
        return;
    };
    if let Ok(mut state) = crate::container::ContainerState::load(&id) {
        state.config.region_path = Some(
            std::path::PathBuf::from(path)
                .to_string_lossy()
                .into_owned(),
        );
        let _ = state.persist();
    }
}

/// Record the init's host pid (ns-pid 1) in an already-allocated region and
/// pre-register it as the first member. Called by the guest-init child after
/// the supervisor fork, where `std::process::id()` is its own host pid (§3.7).
pub fn set_init(init_host_pid: u32) {
    let Some(region) = region() else { return };
    region
        .section
        .init_host_pid
        .store(init_host_pid, Ordering::Relaxed);
    // Capture the init's real host process-group so ns-pgid 1 ↔ this group.
    let init_host_pgid = unsafe { libc::getpgrp() };
    if init_host_pgid > 0 {
        region
            .section
            .init_host_pgid
            .store(init_host_pgid as u32, Ordering::Relaxed);
    }
    let init_host_sid = unsafe { libc::getsid(0) };
    if init_host_sid > 0 {
        region
            .section
            .init_host_sid
            .store(init_host_sid as u32, Ordering::Relaxed);
    }
    let _ = region.register(init_host_pid, NS_INIT_PID, 0);
}

/// Allocate the region AND register the init in one process (no supervisor
/// fork) — used by the degraded path / tests where translation is wanted but
/// the supervisor process is not forked. Idempotent. Returns `false` if the
/// shared-region mmap failed (caller stays in identity mode).
pub fn init(init_host_pid: u32) -> bool {
    if !alloc_region() {
        return false;
    }
    set_init(init_host_pid);
    true
}

/// Borrow the shared region, or `None` if namespaces are not enabled for this
/// run (identity behavior — `getpid` returns the host pid).
pub fn region() -> Option<NsSharedRegion> {
    let ptr = REGION.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: once published the section lives for the whole process; the
        // mapping is never unmapped while the process runs.
        Some(NsSharedRegion {
            section: unsafe { &*ptr },
        })
    }
}

/// `true` if a PID namespace is active for this run (a container launched by
/// `carrick run`). When false, every translation below is the identity (the
/// guest pid IS the host pid) so `run-elf` and non-namespaced runs are
/// unchanged.
pub fn enabled() -> bool {
    !REGION.load(Ordering::Acquire).is_null()
}

/// Translate a host pid to the pid the current ns sees. Identity when
/// namespaces are off. A host pid that is not a registered member translates
/// to `0` — matching `getppid()` of a process whose parent is outside the ns
/// (`pid_namespaces(7)`).
pub fn host_to_ns_or_self(host_pid: u32) -> u32 {
    match region() {
        Some(r) => r.host_to_ns(host_pid).unwrap_or(0),
        None => host_pid,
    }
}

/// Translate a host pid to the pid the current ns sees. Identity when
/// namespaces are off. Unlike [`host_to_ns_or_self`], this preserves the
/// "not a namespace member" distinction for wait/reap paths, where returning
/// pid 0 would be a bogus successful `waitpid(-1)` result.
pub fn host_to_ns(host_pid: u32) -> Option<u32> {
    match region() {
        Some(r) => r.host_to_ns(host_pid),
        None => Some(host_pid),
    }
}

/// Translate a host pgid/sid to the value the ns should report. If the group/
/// session leader is a namespace member, report its ns-pid; otherwise keep the
/// host value (a pgid/sid is always positive, so unlike a parent pid it must
/// NOT collapse to 0 — Phase 2 keeps non-member groups host-level, §6.6).
/// Identity when namespaces are off.
pub fn host_to_ns_pgid(host_pgid: u32) -> u32 {
    match region() {
        Some(r) => {
            // The init's host group is ns-pgid 1 (Docker-style pid-1=pgid-1),
            // even though its host pgid is the launching shell's (a non-member).
            let init_pgid = r.section.init_host_pgid.load(Ordering::Acquire);
            if init_pgid != 0 && host_pgid == init_pgid {
                return NS_INIT_PID;
            }
            let init_sid = r.section.init_host_sid.load(Ordering::Acquire);
            if init_sid != 0 && host_pgid == init_sid {
                return NS_INIT_PID;
            }
            r.host_to_ns(host_pgid).unwrap_or(host_pgid)
        }
        None => host_pgid,
    }
}

/// Translate an ns-pgid the guest supplied (e.g. `setpgid`/`kill(-pgid)`) to the
/// host pgid to operate on. ns-pgid 1 is the init's group → its real host pgid
/// (the existing group the init is in, so a child can JOIN it). Other ns-pgids
/// name a guest group leader, whose ns-pid == ns-pgid → its host pid (== its
/// host pgid, since it's a leader). Identity when namespaces are off.
pub fn ns_to_host_pgid(ns_pgid: u32) -> Option<u32> {
    match region() {
        Some(r) => {
            if ns_pgid == NS_INIT_PID {
                let init_pgid = r.section.init_host_pgid.load(Ordering::Acquire);
                if init_pgid != 0 {
                    return Some(init_pgid);
                }
            }
            r.ns_to_host(ns_pgid)
        }
        None => Some(ns_pgid),
    }
}

/// Refresh the special ns-pgid 1 ↔ host-pgid mapping after the namespace init
/// successfully changes its host process group.
pub fn refresh_init_host_pgid() {
    let Some(region) = region() else { return };
    if self_ns_pid() != NS_INIT_PID {
        return;
    }
    let pgid = unsafe { libc::getpgrp() };
    if pgid > 0 {
        region
            .section
            .init_host_pgid
            .store(pgid as u32, Ordering::Release);
    }
}

/// Translate an ns-pid the guest supplied back to the host pid to operate on.
/// Identity when namespaces are off. Returns `None` (→ `ESRCH`) for an ns-pid
/// that names no member.
pub fn ns_to_host_or_self(ns_pid: u32) -> Option<u32> {
    match region() {
        Some(r) => r.ns_to_host(ns_pid),
        None => Some(ns_pid),
    }
}

/// The current process's own ns-pid. The container init is ns-pid 1. Identity
/// (the host pid) when namespaces are off.
pub fn self_ns_pid() -> u32 {
    let host = std::process::id();
    // `host_to_ns_or_self` returns 0 for a host pid that isn't mapped in the
    // namespace region — correct for a FOREIGN pid (invisible across the pid-ns
    // boundary), but the current process ALWAYS has a real pid, so self falls
    // back to it rather than the invalid 0. (This also keeps the unit suite
    // order-independent: a sibling test may have seeded the process-global
    // region without registering this test process's host pid.)
    match region() {
        Some(r) => r.host_to_ns(host).unwrap_or(host),
        None => host,
    }
}

/// Whether the namespace-visible process `ns_pid` is the leader of its session.
/// Linux rejects `setpgid()` for a session leader with `EPERM`; Darwin cannot
/// answer that after pid-ns translation because the host process may not be a
/// session leader even when the guest-visible pid/sid pair says it is.
pub fn ns_pid_is_session_leader(ns_pid: u32) -> bool {
    let Some(host_pid) = ns_to_host_or_self(ns_pid) else {
        return false;
    };
    let sid = unsafe { libc::getsid(host_pid as i32) };
    if sid <= 0 {
        return false;
    }
    host_to_ns_pgid(sid as u32) == ns_pid
}

/// The current process's parent pid as its ns sees it — the value `getppid()`
/// returns and `/proc/self/status` shows as `PPid:`. The ns-init (ns-pid 1) has
/// no parent inside the namespace, so 0; a reparented orphan reports 1; others
/// translate their host ppid (0 if the parent is outside the ns). Identity
/// (the real host ppid) when namespaces are off (§5.3, §5.4).
pub fn self_ns_ppid() -> u32 {
    if !enabled() {
        // SAFETY: getppid is always safe.
        return unsafe { libc::getppid() } as u32;
    }
    let self_host = std::process::id();
    if self_ns_pid() == NS_INIT_PID {
        return 0;
    }
    if let Some(parent) = crate::guest_cpu::adopted_parent_for_self() {
        return region()
            .and_then(|r| r.host_to_ns(parent))
            .unwrap_or(NS_INIT_PID);
    }
    // Explicit orphan flag (set by the NsSupervisor the instant it sees the
    // parent die) — fast, race-free reparent-to-init.
    if is_orphaned(self_host) {
        return NS_INIT_PID;
    }
    if let Some(parent) = ns_ppid_for_host(self_host) {
        return parent;
    }
    let host_ppid = unsafe { libc::getppid() } as u32;
    match region().and_then(|r| r.host_to_ns(host_ppid)) {
        // Parent is a live namespace member: report its ns-pid.
        Some(ns) => ns,
        // Parent is NOT a member of this namespace. Two cases collapse here and
        // both match Linux (pid_namespaces(7)): the macOS kernel reparented us
        // to launchd because our ns-parent died — so we are an orphan and
        // reparent to the ns-init (ns-pid 1). (A process whose parent is
        // genuinely outside the ns would read 0, but carrick's container tree
        // has no such case below the init: every member descends from pid 1,
        // so a non-member host ppid always means "parent died" → 1.) This makes
        // reparenting correct even before the supervisor's orphan flag lands.
        None => NS_INIT_PID,
    }
}

/// Namespace-visible parent pid for a registered host pid, derived from the
/// fork-time parent recorded in the shared namespace table. This is more stable
/// than `libc::getppid()` for Carrick guest children because the host process
/// topology also contains runtime/supervisor processes that are not guest
/// parents.
pub fn ns_ppid_for_host(host_pid: u32) -> Option<u32> {
    region()?.ns_ppid_for_host(host_pid)
}

/// Publish that the ns-init has installed (or cleared) a handler for `signum`.
/// Called from rt_sigaction when the caller is the ns-init (ns-pid 1). Lets the
/// kill path enforce pid-1 protection without cross-process handler-table
/// visibility (§5.4). No-op when ns is off or signum out of range.
pub fn set_init_handler(signum: i32, installed: bool) {
    let Some(r) = region() else { return };
    // Standard sigset_t convention (bit `signum-1`) via SigSet. This word
    // briefly used the raw bit=signum convention — the execve ignored-mask
    // off-by-one class the typed-domains semgrep gate now rejects. SigSet
    // also lifts the old 1..=63 cap (a shift-overflow guard, not semantics)
    // to the full 1..=64 signal range; out-of-range signums are a no-op.
    let bits = carrick_abi::SigSet::EMPTY.with(signum).raw();
    if bits == 0 {
        return;
    }
    if installed {
        r.section
            .init_sig_handlers
            .fetch_or(bits, Ordering::Release);
    } else {
        r.section
            .init_sig_handlers
            .fetch_and(!bits, Ordering::Release);
    }
}

/// Whether the ns-init has a handler installed for `signum`.
pub fn init_handles(signum: i32) -> bool {
    match region() {
        Some(r) => {
            carrick_abi::SigSet::from_raw(r.section.init_sig_handlers.load(Ordering::Acquire))
                .contains(signum)
        }
        _ => false,
    }
}

/// Whether `signum` is a signal pid-1 is protected from when UNHANDLED, i.e. a
/// default-lethal signal that is NOT the always-unblockable SIGKILL/SIGSTOP
/// (those always act on pid 1). Used by the kill path to apply pid-1 semantics
/// even on the non-namespaced OCI path where `region()` is absent but the guest
/// still presents itself AS the container init (bootstrap pid 1): a default-
/// lethal, unhandled signal pid-1 sends to ITSELF is dropped, matching Linux
/// (init never gets the default action for an unhandled signal). The caller
/// supplies the "is there a handler" check (the dispatcher's own handler table).
pub fn is_init_protected_default_signal(signum: i32) -> bool {
    if signum == 9 || signum == 19 {
        return false;
    }
    is_default_lethal(signum)
}

/// The signals whose default action terminates the process and which pid-1 is
/// protected from when unhandled (`pid_namespaces(7)`: pid 1 only gets signals
/// it has a handler for, plus the always-unblockable SIGKILL/SIGSTOP which are
/// NOT in this set). Linux signal numbers.
fn is_default_lethal(signum: i32) -> bool {
    // SIGHUP(1) SIGINT(2) SIGQUIT(3) SIGILL(4) SIGABRT(6) SIGFPE(8) SIGUSR1(10)
    // SIGSEGV(11) SIGUSR2(12) SIGPIPE(13) SIGALRM(14) SIGTERM(15) SIGBUS(7)
    // SIGTRAP(5) SIGSYS(31) SIGVTALRM(26) SIGPROF(27) SIGXCPU(24) SIGXFSZ(25)
    // SIGSTKFLT(16) SIGIO(29) SIGPWR(30). SIGCHLD/SIGURG/SIGWINCH/SIGCONT have a
    // non-lethal default (ignore/continue) and are not "lethal". SIGKILL(9) and
    // SIGSTOP(19) are handled by the caller (never dropped for pid 1).
    matches!(
        signum,
        1 | 2
            | 3
            | 4
            | 5
            | 6
            | 7
            | 8
            | 10
            | 11
            | 12
            | 13
            | 14
            | 15
            | 16
            | 24
            | 25
            | 26
            | 27
            | 29
            | 30
            | 31
    )
}

/// Whether a signal `signum` sent (by an in-ns member) to host pid `target`
/// must be DROPPED because `target` is the ns-init and the init has no handler
/// for a default-lethal signal (`pid_namespaces(7)`, §5.4). SIGKILL/SIGSTOP are
/// never dropped. Returns false when ns is off, the target isn't the init, or
/// the init handles the signal. The signal is dropped silently (the kill still
/// returns success — Linux behavior).
pub fn should_drop_signal_to_init(target_host_pid: u32, signum: i32) -> bool {
    let Some(r) = region() else { return false };
    if r.init_host_pid() != target_host_pid {
        return false;
    }
    // SIGKILL(9)/SIGSTOP(19) always act on pid 1 from within the ns (Linux
    // delivers these regardless of handler — they can't be caught/ignored).
    if signum == 9 || signum == 19 {
        return false;
    }
    // Only default-lethal signals are dropped; a non-lethal-default signal
    // (SIGCHLD etc.) is harmless to deliver. Drop iff lethal-default AND the
    // init installed no handler.
    is_default_lethal(signum) && !init_handles(signum)
}

/// Whether the NsSupervisor has flagged `host_pid`'s ns-parent as dead, so its
/// `getppid()` should report ns-pid 1 (the ns-init) per `pid_namespaces(7)`
/// reparent-to-init semantics (§3.6). Always false until the NsSupervisor
/// (Phase 3) sets orphan flags.
pub fn is_orphaned(host_pid: u32) -> bool {
    region()
        .and_then(|r| r.flags_of(host_pid))
        .map(|f| f & MEMBER_ORPHANED != 0)
        .unwrap_or(false)
}

/// Called by a freshly-forked CHILD before it runs any guest code: wait until
/// the parent has registered this process in the shared table (the parent
/// allocates the ns-pid in its fork branch — §5.3). This closes the race where
/// the child's first `getpid()`/`getppid()` would otherwise see no mapping
/// (translating to 0) before the parent's `register_child` lands. The parent
/// registers within microseconds; the bounded spin (with `sched_yield`) caps
/// the wait so a never-registering parent can't hang the child. No-op when
/// namespaces are off.
pub fn await_self_registration() {
    let Some(r) = region() else { return };
    let self_host = std::process::id();
    // ~50ms worst case (5000 * ~10us yield) — orders of magnitude beyond the
    // real parent-register latency, but bounded so a crashed parent can't wedge.
    for _ in 0..5000 {
        if r.host_to_ns(self_host).is_some() {
            return;
        }
        // SAFETY: sched_yield is always safe; hands the CPU to the parent so it
        // can complete register_child.
        unsafe {
            libc::sched_yield();
        }
    }
}

/// Allocate the ns-pid before `fork(2)` so the child's process record can be
/// fully populated before either process resumes. Identity mode has no active
/// namespace table, so the caller falls back to the host pid after fork.
pub fn allocate_child_ns_pid_pre_fork() -> Option<u32> {
    region().map(|r| r.alloc_ns_pid())
}

/// Notify the namespace supervisor after a pre-registered child record has had
/// its host pid published by the fork parent.
pub fn notify_child_registered() {
    if enabled() {
        notify_registration();
    }
}

/// Register a freshly-forked child in the active ns: allocate its ns-pid and
/// record the host↔ns mapping + its ns-parent. Returns the child's ns-pid (to
/// be handed back to the guest as the `fork`/`clone` return value). When
/// namespaces are off, returns the host pid unchanged. Called by the parent in
/// the runtime fork path, which knows both pids (§5.3).
pub fn register_child(child_host_pid: u32, parent_host_pid: u32) -> u32 {
    match region() {
        Some(r) => {
            // If the parent forks the same child twice (can't happen) or the
            // child already self-registered, reuse the existing ns-pid.
            if let Some(existing) = r.host_to_ns(child_host_pid) {
                return existing;
            }
            let ns_pid = r.alloc_ns_pid();
            // A full table degrades to "no mapping": the child is still a guest
            // process (visible via the host tree), it just lacks a stable ns-pid
            // entry; report the allocated number anyway (monotonic, unique).
            let _ = r.register(child_host_pid, ns_pid, parent_host_pid);
            // Wake the NsSupervisor to arm an exit watch on the new member.
            notify_registration();
            ns_pid
        }
        None => child_host_pid,
    }
}

/// Forget a namespace member after its terminal wait consumed the zombie.
///
/// A dead-but-unreaped child must stay in the table so `wait4(ns_pid)` can still
/// translate to the host pid. Once the wait succeeds, Linux removes the zombie
/// from the process table; Carrick can likewise free the fixed-size member slot
/// for later fork storms while keeping ns-pids monotonic and never recycled.
pub fn unregister_reaped(host_pid: u32) {
    if let Some(r) = region() {
        r.unregister_reaped(host_pid);
    }
}

/// Mark the current member as having successfully crossed an `execve(2)` point
/// of no return. Linux uses this to reject a parent changing the process group
/// of its child after the child has executed a new program.
pub fn mark_self_execed() {
    let Some(r) = region() else { return };
    r.mark_execed(std::process::id());
}

/// Whether `target_ns_pid` names a direct child of the current process that has
/// successfully execed. Identity mode has no namespace table, so this predicate
/// is only authoritative for namespace-enabled container runs.
pub fn is_execed_child_of_current(target_ns_pid: u32) -> bool {
    let Some(r) = region() else { return false };
    let Some(target_host_pid) = r.ns_to_host(target_ns_pid) else {
        return false;
    };
    r.is_execed_child_of(target_host_pid, std::process::id())
}

/// `carrick exec`: attach the running container's file-backed region and join it
/// as a new member — a fresh ns-pid, parented OUTSIDE the namespace (the
/// `carrick exec` CLI, so the exec'd guest's ns-ppid is 0, matching docker exec).
/// Enables pid translation but does NOT fork a supervisor (the container already
/// has one; its 1 s rescan arms an exit watch on this member). Returns `false`
/// if the region cannot be mapped — the caller must then refuse to run, rather
/// than silently execute outside the namespace.
pub fn join_existing(path: &std::path::Path) -> bool {
    if !attach_region(path) {
        return false;
    }
    REQUESTED.store(true, Ordering::Relaxed);
    register_child(std::process::id(), 0);
    true
}

impl NsSharedRegion {
    /// Allocate the next ns-pid (lock-free, monotonic, never recycled — gaps are
    /// harmless, design §8).
    pub fn alloc_ns_pid(&self) -> u32 {
        self.section.next_ns_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        self.section.init_host_pid.load(Ordering::Acquire)
    }

    /// Claim or reuse a process record for a namespace member. Returns the
    /// record index, or `None` if the process section is full.
    pub fn register(&self, host_pid: u32, ns_pid: u32, parent_host_pid: u32) -> Option<usize> {
        if let Some(i) = self.slot_of(host_pid) {
            return Some(i);
        }
        if let Some((i, record)) = self.reusable_record_for(host_pid) {
            fill_member(record, ns_pid, parent_host_pid);
            return Some(i);
        }
        let generation = KernelArena::global().allocate_generation();
        let claimed = self
            .section
            .claim(Some(HostPid::new(host_pid)), generation, |record| {
                fill_member(record, ns_pid, parent_host_pid);
            })
            .ok()?;
        Some(claimed.index)
    }

    /// Translate a host pid to its ns-pid in this namespace, or `None` if the
    /// host pid is not a member (caller decides the fallback — e.g. 0 for a
    /// parent outside the ns).
    pub fn host_to_ns(&self, host_pid: u32) -> Option<u32> {
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        for record in self.member_records() {
            if record.host_pid.load(Ordering::Acquire) == host_pid {
                return Some(record.ns_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Translate an ns-pid to its host pid, or `None` if the ns-pid names no
    /// member (caller maps to `ESRCH`).
    pub fn ns_to_host(&self, ns_pid: u32) -> Option<u32> {
        for record in self.member_records() {
            if record.ns_pid.load(Ordering::Acquire) == ns_pid {
                return Some(record.host_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// All process records. Callers must skip non-members (`ns_pid == 0`).
    pub fn members(&self) -> &[MemberSlot] {
        &self.section.records
    }

    /// Find the slot index for a host pid, if registered.
    pub fn slot_of(&self, host_pid: u32) -> Option<usize> {
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        self.section.records.iter().position(|s| {
            s.host_pid.load(Ordering::Acquire) == host_pid && s.ns_pid.load(Ordering::Acquire) != 0
        })
    }

    /// The member's flags, or `None` if not registered.
    pub fn flags_of(&self, host_pid: u32) -> Option<u32> {
        self.slot_of(host_pid)
            .map(|i| self.section.records[i].flags.load(Ordering::Acquire))
    }

    /// The host pid recorded as this member's namespace parent at fork time.
    pub fn parent_host_pid_of(&self, host_pid: u32) -> Option<u32> {
        self.slot_of(host_pid).map(|i| {
            self.section.records[i]
                .parent_host_pid
                .load(Ordering::Acquire)
        })
    }

    /// Whether the member has successfully executed a new image since fork.
    pub fn execed_of(&self, host_pid: u32) -> Option<bool> {
        self.slot_of(host_pid).map(|i| {
            self.section.records[i]
                .exec_generation
                .load(Ordering::Acquire)
                != 0
        })
    }

    /// Mark a registered member as having crossed an exec point of no return.
    pub fn mark_execed(&self, host_pid: u32) {
        if let Some(i) = self.slot_of(host_pid) {
            let record = &self.section.records[i];
            let _ = record.exec_generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Whether `host_pid` is a direct child of `parent_host_pid` and has
    /// successfully executed a new image.
    pub fn is_execed_child_of(&self, host_pid: u32, parent_host_pid: u32) -> bool {
        let Some(i) = self.slot_of(host_pid) else {
            return false;
        };
        self.section.records[i]
            .parent_host_pid
            .load(Ordering::Acquire)
            == parent_host_pid
            && self.section.records[i]
                .exec_generation
                .load(Ordering::Acquire)
                != 0
    }

    /// Translate a member's recorded parent to the pid its namespace sees.
    pub fn ns_ppid_for_host(&self, host_pid: u32) -> Option<u32> {
        let ns_pid = self.host_to_ns(host_pid)?;
        if ns_pid == NS_INIT_PID {
            return Some(0);
        }
        if self
            .flags_of(host_pid)
            .is_some_and(|flags| flags & MEMBER_ORPHANED != 0)
        {
            return Some(NS_INIT_PID);
        }
        let parent = self.parent_host_pid_of(host_pid)?;
        if parent == 0 {
            return Some(0);
        }
        Some(self.host_to_ns(parent).unwrap_or(NS_INIT_PID))
    }

    /// Mark every live member whose ns-parent is `dead_host_pid` as orphaned
    /// (design §3.6 step 3). Called by the NsSupervisor on a parent's death.
    pub fn mark_children_orphaned(&self, dead_host_pid: u32) {
        for slot in self.member_records() {
            let host_pid = slot.host_pid.load(Ordering::Acquire);
            if host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && slot.parent_host_pid.load(Ordering::Acquire) == dead_host_pid
                && slot.flags.load(Ordering::Acquire) & MEMBER_DEAD == 0
            {
                slot.flags.fetch_or(MEMBER_ORPHANED, Ordering::AcqRel);
            }
        }
    }

    /// Record a member's death and its exit status (design §3.4).
    pub fn mark_dead(&self, host_pid: u32, exit_status: i32) {
        if let Some(i) = self.slot_of(host_pid) {
            self.section.records[i]
                .exit_status
                .store(exit_status as u32 as u64, Ordering::Relaxed);
            self.section.records[i]
                .flags
                .fetch_or(MEMBER_DEAD, Ordering::AcqRel);
        }
    }

    /// Release namespace membership for `host_pid` after the guest has reaped
    /// it. The process section is generation-checked, so a stale release cannot
    /// clear a reused record.
    pub fn unregister_reaped(&self, host_pid: u32) -> bool {
        let Some(i) = self.slot_of(host_pid) else {
            return false;
        };
        let record = &self.section.records[i];
        let generation = record.generation.load(Ordering::Acquire);
        if generation != 0 {
            self.section.release(ProcessRecordRef {
                index: i,
                generation: ProcessGeneration::new(generation),
            });
        } else {
            record.ns_pid.store(0, Ordering::Release);
            record.exec_generation.store(0, Ordering::Release);
            record.flags.fetch_and(!MEMBER_DEAD, Ordering::AcqRel);
            record.flags.fetch_and(!MEMBER_ORPHANED, Ordering::AcqRel);
            record.exit_status.store(0, Ordering::Relaxed);
        }
        true
    }

    fn member_records(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.section.records.iter().filter(|record| {
            let host_pid = record.host_pid.load(Ordering::Acquire);
            host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && record.ns_pid.load(Ordering::Acquire) != 0
        })
    }

    fn reusable_record_for(&self, host_pid: u32) -> Option<(usize, &ProcessRecord)> {
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        self.section.records.iter().enumerate().find(|(_, record)| {
            record.host_pid.load(Ordering::Acquire) == host_pid
                && record.generation.load(Ordering::Acquire) != 0
                && record.ns_pid.load(Ordering::Acquire) == 0
                && record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID == 0
        })
    }
}

fn fill_member(record: &ProcessRecord, ns_pid: u32, parent_host_pid: u32) {
    record.ns_pid.store(ns_pid, Ordering::Relaxed);
    record
        .parent_host_pid
        .store(parent_host_pid, Ordering::Relaxed);
    record.exec_generation.store(0, Ordering::Relaxed);
    record.exit_status.store(0, Ordering::Relaxed);
    // A reused record (recycled host pid) may carry the PREVIOUS process's
    // wait state; a stale adopted+exit_ready pair would make the new live
    // member spuriously reapable, and stale ptrace/subreaper links would
    // corrupt wait routing. Clear every wait-visible field.
    record.exit_ready.store(0, Ordering::Relaxed);
    record.guest_ns.store(0, Ordering::Relaxed);
    record.subreaper_pid.store(0, Ordering::Relaxed);
    record.ptrace_stop_signal.store(0, Ordering::Relaxed);
    record
        .flags
        .fetch_and(!carrick_kernel::process::FLAG_ADOPTED, Ordering::AcqRel);
    record.flags.fetch_or(MEMBER_ALIVE, Ordering::AcqRel);
    record.flags.fetch_and(!MEMBER_ORPHANED, Ordering::AcqRel);
    record.flags.fetch_and(!MEMBER_DEAD, Ordering::AcqRel);
}

/// A PID namespace descriptor — the per-process attribute (inherited at fork via
/// address-space copy) naming which ns the process lives in. The mutable
/// translation lives in the shared region; this is just identity + lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidNs {
    pub id: NsId,
    pub parent: Option<NsId>,
    /// 0 = the initial/host ns (identity map, ns_pid == host_pid).
    pub level: u32,
}

impl PidNs {
    /// The initial (host) namespace — identity translation.
    pub fn initial(id: NsId) -> Self {
        Self {
            id,
            parent: None,
            level: 0,
        }
    }

    /// A fresh child namespace at `level`.
    pub fn fresh(id: NsId, parent: NsId, level: u32) -> Self {
        Self {
            id,
            parent: Some(parent),
            level,
        }
    }

    /// `true` for the initial/host namespace (no translation).
    pub fn is_initial(&self) -> bool {
        self.level == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests run in a single process (mmap MAP_SHARED|MAP_ANON works
    // in-process); fork-coherence is validated by the conformance probes under
    // the signed build. They are gated to run serially via a fresh region per
    // test would be ideal, but the region is a process-global; so each test
    // uses the global region after init and asserts on its own pids.

    #[test]
    fn fill_member_resets_stale_wait_state_on_reuse() {
        // A recycled host pid can reuse a record that still carries the OLD
        // process's wait state; a stale adopted+exit_ready pair would make the
        // new live member spuriously reapable. fill_member must clear every
        // wait-visible field, not just lifecycle flags.
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0001u32;
        let generation = ProcessGeneration::new(41);
        let r = match section.claim(Some(HostPid::new(pid)), generation, |record| {
            record.subreaper_pid.store(999, Ordering::Relaxed);
            record.ptrace_stop_signal.store(19, Ordering::Relaxed);
            record.exit_ready.store(1, Ordering::Relaxed);
            record.guest_ns.store(123_456, Ordering::Relaxed);
            record
                .flags
                .store(carrick_kernel::process::FLAG_ADOPTED, Ordering::Relaxed);
        }) {
            Ok(r) => r,
            Err(err) => unreachable!("claim: {err:?}"),
        };
        let record = &section.records[r.index];

        fill_member(record, 42, 1);

        assert_eq!(record.exit_ready.load(Ordering::Acquire), 0);
        assert_eq!(record.guest_ns.load(Ordering::Acquire), 0);
        assert_eq!(record.subreaper_pid.load(Ordering::Acquire), 0);
        assert_eq!(record.ptrace_stop_signal.load(Ordering::Acquire), 0);
        assert_eq!(
            record.flags.load(Ordering::Acquire) & carrick_kernel::process::FLAG_ADOPTED,
            0,
            "stale ADOPTED flag must not survive member reuse"
        );
        section.release(r);
    }

    fn test_region() -> NsSharedRegion {
        let arena = Box::leak(Box::new(KernelArena::create().unwrap()));
        NsSharedRegion {
            section: &arena.layout().processes,
        }
    }

    #[test]
    fn file_backed_arena_is_shared_across_independent_mappings() {
        // exec relies on this: a fresh mmap of the container's arena file sees
        // the same process section as the container's mapping.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("arena");
        let a = KernelArena::create_at(&path).expect("create file-backed arena");
        a.layout()
            .processes
            .next_ns_pid
            .store(4242, Ordering::Relaxed);
        let b = KernelArena::attach(&path).expect("attach the arena file");
        assert_eq!(
            b.layout().processes.next_ns_pid.load(Ordering::Relaxed),
            4242
        );
    }

    #[test]
    fn pidns_descriptors() {
        let init = PidNs::initial(1);
        assert!(init.is_initial());
        let child = PidNs::fresh(2, 1, 1);
        assert!(!child.is_initial());
        assert_eq!(child.parent, Some(1));
        assert_eq!(child.level, 1);
    }

    #[test]
    fn shared_region_alloc_register_translate() {
        let region = test_region();
        region.section.init_host_pid.store(100, Ordering::Relaxed);
        // pre-register init as ns-pid 1
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));

        // a forked child host pid 200, ns-parent 100
        let ns_pid = region.alloc_ns_pid();
        assert_eq!(ns_pid, 2);
        assert!(region.register(200, ns_pid, 100).is_some());

        assert_eq!(region.host_to_ns(100), Some(1));
        assert_eq!(region.host_to_ns(200), Some(2));
        assert_eq!(region.host_to_ns(999), None);
        assert_eq!(region.ns_to_host(1), Some(100));
        assert_eq!(region.ns_to_host(2), Some(200));
        assert_eq!(region.ns_to_host(42), None);
        assert_eq!(region.parent_host_pid_of(200), Some(100));
        assert_eq!(region.ns_ppid_for_host(100), Some(0));
        assert_eq!(region.ns_ppid_for_host(200), Some(1));
        assert_eq!(region.ns_ppid_for_host(999), None);
        assert_eq!(region.execed_of(200), Some(false));
        assert!(!region.is_execed_child_of(200, 100));
        region.mark_execed(200);
        assert_eq!(region.execed_of(200), Some(true));
        assert!(region.is_execed_child_of(200, 100));
        assert!(!region.is_execed_child_of(200, 999));

        // orphan the child by killing its parent (100)
        region.mark_children_orphaned(100);
        assert_ne!(region.flags_of(200).unwrap_or(0) & MEMBER_ORPHANED, 0);
        assert_eq!(region.ns_ppid_for_host(200), Some(1));

        // mark the child dead
        region.mark_dead(200, 0);
        assert_ne!(region.flags_of(200).unwrap_or(0) & MEMBER_DEAD, 0);
    }

    #[test]
    fn in_progress_registration_slot_is_not_visible() {
        let region = test_region();
        let slot = &region.section.records[0];
        assert!(
            slot.host_pid
                .compare_exchange(0, HOST_PID_REGISTERING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        );
        slot.ns_pid.store(2, Ordering::Relaxed);
        slot.parent_host_pid.store(100, Ordering::Relaxed);
        slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);

        assert_eq!(region.host_to_ns(200), None);
        assert_eq!(region.ns_to_host(2), None);
        assert_eq!(region.slot_of(HOST_PID_REGISTERING), None);

        slot.host_pid.store(200, Ordering::Release);
        assert_eq!(region.host_to_ns(200), Some(2));
        assert_eq!(region.ns_to_host(2), Some(200));
    }

    #[test]
    fn reaped_member_slot_can_be_reused_without_recycling_ns_pid() {
        let region = test_region();

        let first_ns = region.alloc_ns_pid();
        assert_eq!(first_ns, 2);
        assert_eq!(region.register(200, first_ns, 100), Some(0));
        region.mark_execed(200);
        assert_eq!(region.execed_of(200), Some(true));
        region.mark_dead(200, 0);
        assert_eq!(region.ns_to_host(first_ns), Some(200));

        assert!(region.unregister_reaped(200));
        assert_eq!(region.ns_to_host(first_ns), None);
        assert_eq!(region.host_to_ns(200), None);

        let second_ns = region.alloc_ns_pid();
        assert_eq!(second_ns, 3);
        assert_eq!(region.register(201, second_ns, 100), Some(0));
        assert_eq!(region.ns_to_host(second_ns), Some(201));
        assert_eq!(region.execed_of(201), Some(false));
        assert_eq!(region.ns_to_host(first_ns), None);
    }
}
