//! PID namespace translation: a host-pid ↔ ns-pid table backed by a
//! `MAP_SHARED|MAP_ANON` region so it is coherent across `fork` (design §3.3,
//! §5.2, §5.6).
//!
//! The region is allocated **before the first guest fork** (mirroring
//! `carrick_host::guest_cpu::init_child_table`) and inherited by every
//! descendant: all processes map the same physical pages, so a
//! `fetch_add`/`compare_exchange` on an `AtomicU32` in one process is visible to
//! all others (Apple-Silicon hardware atomics operate on physical addresses).
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

use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};

use super::NsId;

/// Member is alive and (so far as we know) parented within the namespace.
pub const MEMBER_ALIVE: u8 = 0;
/// Member's namespace-parent died; `getppid` should report ns-pid 1 (design
/// §3.6). Set by the NsSupervisor.
pub const MEMBER_ORPHANED: u8 = 1;
/// Member has exited; `exit_status` holds the `waitpid`-format status harvested
/// from `NOTE_EXITSTATUS` (design §3.4).
pub const MEMBER_DEAD: u8 = 2;

/// Number of member slots in the shared table. Container process trees are tens
/// to low hundreds of members; 1024 is comfortable headroom (design §3.3).
pub const MEMBER_SLOTS: usize = 1024;

/// ns-pid 1 — the namespace init (`pid_namespaces(7)`).
pub const NS_INIT_PID: u32 = 1;

/// One member of a PID namespace. All fields are atomic so they can be read and
/// written cross-process through the shared mapping. `host_pid == 0` marks a
/// free slot.
#[repr(C)]
pub struct MemberSlot {
    pub host_pid: AtomicU32,
    pub ns_pid: AtomicU32,
    pub parent_host_pid: AtomicU32,
    pub flags: AtomicU8,
    pub exit_status: AtomicI32,
}

impl MemberSlot {
    const fn empty() -> Self {
        Self {
            host_pid: AtomicU32::new(0),
            ns_pid: AtomicU32::new(0),
            parent_host_pid: AtomicU32::new(0),
            flags: AtomicU8::new(MEMBER_ALIVE),
            exit_status: AtomicI32::new(0),
        }
    }
}

/// The shared region. Laid out `#[repr(C)]` so its layout is identical in every
/// process mapping the page.
#[repr(C)]
pub struct NsSharedRegion {
    /// Monotonic ns-pid allocator. Seeded at 2 (pid 1 is pre-assigned to the
    /// init before the first fork), so the first forked child gets ns-pid 2.
    pub next_pid: AtomicU32,
    /// The init's host pid (ns-pid 1). 0 until launch placement sets it.
    pub init_host_pid: AtomicU32,
    /// The init's host PROCESS-GROUP id, captured at launch. The container init
    /// is ns-pgid 1 (like Docker's pid-1=pgid-1), but on the host the carrick
    /// init usually inherited the launching shell's group — a non-member pgid.
    /// This records that real host group so the init's group maps to ns-pgid 1
    /// (`getpgrp`→1) AND `setpgid(child, 1)` resolves back to the EXISTING host
    /// group (join succeeds) instead of the init's host pid (not a group leader
    /// → EPERM → glibc posix_spawn setpgroup aborts the child with 127).
    pub init_host_pgid: AtomicU32,
    /// Bitmask of signals the ns-init has installed a handler for (bit N =
    /// signal N). Published by the init's rt_sigaction; read by the kill path
    /// to enforce pid-1 protection: a signal sent to the init by another ns
    /// member is delivered only if the init handles it (`pid_namespaces(7)`,
    /// §5.4). Signals 1..=64 fit in the low 64 bits (bit 0 unused).
    pub init_sig_handlers: AtomicU64,
    pub members: [MemberSlot; MEMBER_SLOTS],
}

/// Global pointer to the shared region, inherited across fork (the child's
/// static still points at the same physical pages). Null until [`init`].
static REGION: AtomicPtr<NsSharedRegion> = AtomicPtr::new(std::ptr::null_mut());

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

/// Allocate the shared region with `mmap(MAP_SHARED|MAP_ANON)` and publish it,
/// WITHOUT yet knowing the init's host pid. Must be called **once, before the
/// NsSupervisor fork** (design §3.3) so both the supervisor parent and the
/// guest-init child inherit the same physical pages. The child then calls
/// [`set_init`] with its own pid. Returns `false` (never panics) on mmap
/// failure; the caller falls back to identity (non-namespaced) behavior.
/// Idempotent — returns `true` if the region already exists.
pub fn alloc_region() -> bool {
    if !REGION.load(Ordering::Acquire).is_null() {
        return true;
    }
    // A DETACHED container backs its region with a FILE under its registry dir
    // so an outside process (`carrick exec`) can `mmap` the same region and join
    // the namespace. Foreground / non-detached runs use an anonymous mapping —
    // fork-coherent, but not externally attachable.
    map_region(detached_region_path().as_deref(), true)
}

/// Attach an EXISTING file-backed region (for `carrick exec`): `mmap` the
/// container's region file as a new member. Does NOT seed the pid allocator —
/// the region already holds the container's live state. Returns `false` on any
/// failure (the caller must not run outside the namespace).
pub fn attach_region(path: &std::path::Path) -> bool {
    map_region(Some(path), false)
}

/// Core region mapper: map the region (file-backed for a detached container,
/// else anonymous) and publish it to the process-global [`REGION`]. `seed`
/// seeds the pid allocator for a freshly-created region; `seed = false` attaches
/// an existing one. Idempotent.
fn map_region(path: Option<&std::path::Path>, seed: bool) -> bool {
    if !REGION.load(Ordering::Acquire).is_null() {
        return true;
    }
    match map_region_ptr(path, seed) {
        Some(region) => {
            REGION.store(region, Ordering::Release);
            true
        }
        None => false,
    }
}

/// `mmap` the region — file-backed (`MAP_SHARED` over the file, created and
/// `set_len`-sized when `seed`) when `path` is `Some`, else `MAP_ANON` — and
/// return the pointer WITHOUT publishing it to the global. The seam the unit
/// test maps two independent views through to prove file-backed coherence.
fn map_region_ptr(path: Option<&std::path::Path>, seed: bool) -> Option<*mut NsSharedRegion> {
    use std::os::fd::IntoRawFd;
    let size = std::mem::size_of::<NsSharedRegion>();
    let (flags, fd) = match path {
        Some(p) => {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true).write(true);
            if seed {
                opts.create(true);
            }
            let file = opts.open(p).ok()?;
            // Size the backing file for a fresh region (set_len zero-fills).
            if seed && file.set_len(size as u64).is_err() {
                return None;
            }
            (libc::MAP_SHARED, file.into_raw_fd())
        }
        None => (libc::MAP_SHARED | libc::MAP_ANON, -1),
    };
    // SAFETY: `mmap` of exactly the struct size. File-backed (fd ≥ 0, zero-filled
    // by set_len for a fresh region) or anonymous (kernel zero-fills). The
    // mapping keeps the file alive, so the fd is closed immediately after.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            fd,
            0,
        )
    };
    if fd >= 0 {
        // SAFETY: the mapping holds the file; the fd is no longer needed.
        unsafe {
            libc::close(fd);
        }
    }
    if ptr == libc::MAP_FAILED {
        return None;
    }
    let region = ptr.cast::<NsSharedRegion>();
    if seed {
        // SAFETY: valid writable mapping of exactly this struct.
        unsafe {
            (*region).next_pid.store(2, Ordering::Relaxed);
        }
    }
    Some(region)
}

/// For a detached container (`CARRICK_CONTAINER_ID` set), the region file path
/// `<registry>/<id>/region`, recording it into the registry so `carrick exec`
/// can `attach_region` to it. `None` for a foreground / non-detached run.
fn detached_region_path() -> Option<std::path::PathBuf> {
    let id = std::env::var("CARRICK_CONTAINER_ID").ok()?;
    if !crate::container::is_safe_id(&id) {
        return None;
    }
    let path = crate::container::container_dir(&id).join("region");
    if let Ok(mut state) = crate::container::ContainerState::load(&id) {
        state.config.region_path = Some(path.to_string_lossy().into_owned());
        let _ = state.persist();
    }
    Some(path)
}

/// Record the init's host pid (ns-pid 1) in an already-allocated region and
/// pre-register it as the first member. Called by the guest-init child after
/// the supervisor fork, where `std::process::id()` is its own host pid (§3.7).
pub fn set_init(init_host_pid: u32) {
    let Some(region) = region() else { return };
    region.init_host_pid.store(init_host_pid, Ordering::Relaxed);
    // Capture the init's real host process-group so ns-pgid 1 ↔ this group.
    let init_host_pgid = unsafe { libc::getpgrp() };
    if init_host_pgid > 0 {
        region
            .init_host_pgid
            .store(init_host_pgid as u32, Ordering::Relaxed);
    }
    let init_slot = &region.members[0];
    init_slot.ns_pid.store(NS_INIT_PID, Ordering::Relaxed);
    init_slot.parent_host_pid.store(0, Ordering::Relaxed);
    init_slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);
    // Publish host_pid last so a concurrent reader never sees a half-filled slot
    // (Release pairs with the Acquire scan in `host_to_ns`).
    init_slot.host_pid.store(init_host_pid, Ordering::Release);
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
pub fn region() -> Option<&'static NsSharedRegion> {
    let ptr = REGION.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: once published the region lives for the whole process; the
        // mapping is never unmapped while the process runs.
        Some(unsafe { &*ptr })
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
            let init_pgid = r.init_host_pgid.load(Ordering::Acquire);
            if init_pgid != 0 && host_pgid == init_pgid {
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
                let init_pgid = r.init_host_pgid.load(Ordering::Acquire);
                if init_pgid != 0 {
                    return Some(init_pgid);
                }
            }
            r.ns_to_host(ns_pgid)
        }
        None => Some(ns_pgid),
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
    host_to_ns_or_self(std::process::id())
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
    if self_ns_pid() == NS_INIT_PID {
        return 0;
    }
    // Explicit orphan flag (set by the NsSupervisor the instant it sees the
    // parent die) — fast, race-free reparent-to-init.
    if is_orphaned(std::process::id()) {
        return NS_INIT_PID;
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

/// Publish that the ns-init has installed (or cleared) a handler for `signum`.
/// Called from rt_sigaction when the caller is the ns-init (ns-pid 1). Lets the
/// kill path enforce pid-1 protection without cross-process handler-table
/// visibility (§5.4). No-op when ns is off or signum out of range.
pub fn set_init_handler(signum: i32, installed: bool) {
    let Some(r) = region() else { return };
    if !(1..=63).contains(&signum) {
        return;
    }
    let bit = 1u64 << signum;
    if installed {
        r.init_sig_handlers.fetch_or(bit, Ordering::Release);
    } else {
        r.init_sig_handlers.fetch_and(!bit, Ordering::Release);
    }
}

/// Whether the ns-init has a handler installed for `signum`.
pub fn init_handles(signum: i32) -> bool {
    match region() {
        Some(r) if (1..=63).contains(&signum) => {
            r.init_sig_handlers.load(Ordering::Acquire) & (1u64 << signum) != 0
        }
        _ => false,
    }
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
        .map(|f| f == MEMBER_ORPHANED)
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
        self.next_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        self.init_host_pid.load(Ordering::Acquire)
    }

    /// Claim a free slot for a new member. Returns the slot index, or `None` if
    /// the table is full (the caller degrades gracefully — never panics).
    pub fn register(&self, host_pid: u32, ns_pid: u32, parent_host_pid: u32) -> Option<usize> {
        for (i, slot) in self.members.iter().enumerate() {
            if slot
                .host_pid
                .compare_exchange(0, host_pid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.ns_pid.store(ns_pid, Ordering::Relaxed);
                slot.parent_host_pid
                    .store(parent_host_pid, Ordering::Relaxed);
                slot.exit_status.store(0, Ordering::Relaxed);
                // flags Release-published so a reader that sees host_pid also
                // sees ALIVE (it was set when the slot was last freed/zeroed).
                slot.flags.store(MEMBER_ALIVE, Ordering::Release);
                return Some(i);
            }
        }
        None
    }

    /// Translate a host pid to its ns-pid in this namespace, or `None` if the
    /// host pid is not a member (caller decides the fallback — e.g. 0 for a
    /// parent outside the ns).
    pub fn host_to_ns(&self, host_pid: u32) -> Option<u32> {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) == host_pid {
                return Some(slot.ns_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Translate an ns-pid to its host pid, or `None` if the ns-pid names no
    /// member (caller maps to `ESRCH`).
    pub fn ns_to_host(&self, ns_pid: u32) -> Option<u32> {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) != 0
                && slot.ns_pid.load(Ordering::Acquire) == ns_pid
            {
                return Some(slot.host_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// All member slots — the NsSupervisor scans these to arm exit watches,
    /// flag orphans, and sweep on teardown.
    pub fn members(&self) -> &[MemberSlot] {
        &self.members
    }

    /// Find the slot index for a host pid, if registered.
    pub fn slot_of(&self, host_pid: u32) -> Option<usize> {
        self.members
            .iter()
            .position(|s| s.host_pid.load(Ordering::Acquire) == host_pid)
    }

    /// The member's flags, or `None` if not registered.
    pub fn flags_of(&self, host_pid: u32) -> Option<u8> {
        self.slot_of(host_pid)
            .map(|i| self.members[i].flags.load(Ordering::Acquire))
    }

    /// Mark every live member whose ns-parent is `dead_host_pid` as orphaned
    /// (design §3.6 step 3). Called by the NsSupervisor on a parent's death.
    pub fn mark_children_orphaned(&self, dead_host_pid: u32) {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) != 0
                && slot.parent_host_pid.load(Ordering::Acquire) == dead_host_pid
                && slot.flags.load(Ordering::Acquire) == MEMBER_ALIVE
            {
                slot.flags.store(MEMBER_ORPHANED, Ordering::Release);
            }
        }
    }

    /// Record a member's death and its exit status (design §3.4).
    pub fn mark_dead(&self, host_pid: u32, exit_status: i32) {
        if let Some(i) = self.slot_of(host_pid) {
            self.members[i]
                .exit_status
                .store(exit_status, Ordering::Relaxed);
            self.members[i].flags.store(MEMBER_DEAD, Ordering::Release);
        }
    }
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
    fn file_backed_region_is_shared_across_independent_mappings() {
        // exec relies on this: a fresh `mmap` of the container's region FILE
        // (by an outside process) sees the same state as the container's
        // mapping. Two independent file-backed `MAP_SHARED` views of one file
        // are coherent; two anonymous mappings would not be. Uses the
        // pointer-returning seam so it never touches the process-global REGION.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("region");
        let size = std::mem::size_of::<NsSharedRegion>();
        let a = map_region_ptr(Some(&path), true).expect("alloc file-backed region");
        // SAFETY: `a` is a valid mapping of exactly one NsSharedRegion.
        unsafe { (*a).next_pid.store(4242, Ordering::Relaxed) };
        let b = map_region_ptr(Some(&path), false).expect("attach the region file");
        // SAFETY: `b` is an independent valid mapping of the same file.
        assert_eq!(unsafe { (*b).next_pid.load(Ordering::Relaxed) }, 4242);
        // SAFETY: unmap both mappings we created.
        unsafe {
            libc::munmap(a.cast(), size);
            libc::munmap(b.cast(), size);
        }
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
        // Use a locally-mmap'd region (not the global) so this test is
        // independent of init() ordering with other tests.
        let size = std::mem::size_of::<NsSharedRegion>();
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let region: &NsSharedRegion = unsafe { &*ptr.cast::<NsSharedRegion>() };
        region.next_pid.store(2, Ordering::Relaxed);
        region.init_host_pid.store(100, Ordering::Relaxed);
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

        // orphan the child by killing its parent (100)
        region.mark_children_orphaned(100);
        assert_eq!(region.flags_of(200), Some(MEMBER_ORPHANED));

        // mark the child dead
        region.mark_dead(200, 0);
        assert_eq!(region.flags_of(200), Some(MEMBER_DEAD));

        unsafe {
            libc::munmap(ptr, size);
        }
    }
}
