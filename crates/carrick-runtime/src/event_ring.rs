//! Lock-free, low-perturbation in-memory event ring for diagnosing timing-
//! sensitive (Heisenbug) deadlocks — specifically the nested-forkserver
//! `test_parent_process` hang where a server forked+exec'd from a forkserver
//! worker fails to function, and ANY `eprintln`/dtrace instrumentation perturbs
//! the race enough to change the manifestation (see
//! `docs/archive/forkserver-parent-process-deadlock.md`).
//!
//! Recording is hot-path-cheap and ALWAYS ON: an atomic `fetch_add` index + two
//! atomic `store`s into a fixed array — no lock, no syscall, no allocation, ~ns.
//! It is unconditional on purpose, so the ring is present in a core file or a
//! live process from ANY run with nothing pre-armed — an intermittent Heisenbug
//! you can't predict still leaves its history behind. Read it post-mortem with
//! the lldb plugin: `lldb -c <core> target/release/carrick` then
//! `carrick eventring` (works on a live `lldb -p <pid>` too).
//!
//! Only the perturbing, autonomous FILE dump is opt-in: build with the
//! `event-ring-dump` feature and set `CARRICK_EVENTRING` to a directory; a 1 Hz
//! watchdog thread (OFF the vCPU thread, so guest syscall timing is intact)
//! writes `<dir>/carrick-ring.<pid>`. Without the feature, only the in-memory
//! ring (above) exists — read it from a core or a live process via lldb.
//!
//! The ring is per HOST process. Legacy native/VMM execution normally places
//! one guest process in it; HvPatch deliberately multiplexes many Linux guest
//! processes in one host process, so its lifecycle/wait records carry explicit
//! guest PID/TID correlation. On a legacy host fork the child inherits the
//! parent's ring memory but only the forking thread survives, so
//! [`reinit_after_fork`] resets the index + re-arms the watchdog for the child.

#[cfg(feature = "event-ring-dump")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

const N: usize = 8192;

// Each event is two u64 cells (lo, hi). A reader may observe a torn write
// (lo updated, hi stale) under concurrency; that's acceptable for a diagnostic
// (rare, and a decoded `kind` outside the known event set is dropped).
struct Slot {
    lo: AtomicU64,
    hi: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY: Slot = Slot {
    lo: AtomicU64::new(0),
    hi: AtomicU64::new(0),
};

static RING: [Slot; N] = [EMPTY; N];
static IDX: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG: AtomicBool = AtomicBool::new(false);
static NEXT_HVPWAIT_ID: AtomicU32 = AtomicU32::new(1);

// Event kinds.
pub const BIND: u8 = 1;
pub const LISTEN: u8 = 2;
pub const CONNECT: u8 = 3;
pub const ACCEPT: u8 = 4;
pub const EPADD: u8 = 5;
pub const EPWAIT: u8 = 6;
pub const FORK: u8 = 7;
pub const EXEC: u8 = 8;
pub const FDOPEN: u8 = 9;
pub const FDCLOSE: u8 = 10;
pub const ACCEPTERR: u8 = 11;
pub const EPWFD: u8 = 12;
pub const EPMASK: u8 = 13;
pub const EPMASKFD: u8 = 14;
pub const EPEDGE: u8 = 15;
pub const DSRFAULT_PC: u8 = 16;
pub const DSRFAULT_ADDR: u8 = 17;
pub const DSRFAULT_SP: u8 = 18;
pub const DSRFAULT_LR: u8 = 19;
/// A socket-namespace record was refused for claiming to belong to a different
/// key or a different instance. The guest-facing paths map that to
/// `ECONNREFUSED` and say nothing, so this ring entry is the only per-occurrence
/// record of a cross-instance mis-publication.
pub const NSREJECT: u8 = 20;
/// Eventfd counter transition after a successful guest write. `a` is the host
/// readiness-pipe read fd; `b` and `c` are the low 32 bits before and after.
pub const EFDWRITE: u8 = 21;
/// Eventfd counter transition after a successful guest read/copyout.
pub const EFDREAD: u8 = 22;
/// A process-private futex wait is about to park. `a:b` is the full guest VA;
/// `c` is the guest tid.
pub const FUTEXWAIT: u8 = 23;
/// A process-private FUTEX_WAKE completed. `a:b` is the full guest VA; `c` is
/// the number of waiters actually removed from the parking-lot queue.
pub const FUTEXWAKE: u8 = 24;
/// A process-private futex wait returned. `a:b` is the full guest VA; `c` is
/// 0=woken, 1=interrupted, 2=timed out.
pub const FUTEXEND: u8 = 25;
/// HvPatch process-thread teardown checkpoint. `a` is guest PID, `b` guest
/// TID, and `c` is the cleanup phase decoded by the LLDB plugin.
pub const HVPTHREAD: u8 = 26;
/// HvPatch blocking-fd wait lifecycle. `a` is guest PID, `b` guest TID, and
/// `c` packs wait class in bits 0..7, phase in 8..15, and fd count in 16..31.
pub const HVPWAIT: u8 = 27;
/// Correlation record for an HvPatch wait. `a` is guest PID, `b` guest TID,
/// and `c` packs a 24-bit wait ID plus 4-bit class and phase fields.
pub const HVPWAITX: u8 = 28;
/// Full-width guest resume PC at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_PC: u8 = 29;
/// Full-width guest stack pointer at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_SP: u8 = 30;
/// Full-width guest link register at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_LR: u8 = 31;
/// Primary host fd/events for an HvPatch wait; `a` is wait ID, `b` fd, `c`
/// poll events. The existing HVPWAIT record retains the total fd count.
pub const HVPWAITFD: u8 = 32;
/// HvPatch process-exit publication is about to enter the shared process table.
pub const HVPPEXIT_BEGIN: u8 = 33;
/// HvPatch process-exit publication completed and waiters were notified.
pub const HVPPEXIT_END: u8 = 34;
/// Target guest process for a correlated HvPatch child wait. `a` is the wait
/// ID and `b` is the guest PID (`-1` means any child).
pub const HVPWAIT_TARGET: u8 = 35;
/// One guest-fd event actually copied into an epoll_wait result. `a` is the
/// guest epoll fd, `b` the originating guest fd, and `c` the returned mask.
/// This is deliberately distinct from [`EPEDGE`]: a multiplexer edge can be
/// observed but deferred by `maxevents`, while only EPREADY proves delivery to
/// the guest runtime.
pub const EPREADY: u8 = 36;
/// A drained multiplexer edge rejected by the guest-fd generation guard. `a`
/// is the guest fd, `b` the generation carried by the host event, and `c` the
/// live generation (`-1` when the guest fd no longer has an interest entry).
pub const EPSTALE: u8 = 37;
/// Process-qualified fd close companion. `a` is guest PID, `b` guest TID, and
/// `c` the guest fd removed from that process's private table. This record is
/// intentionally separate from [`FDCLOSE`], which preserves the historical
/// guest-fd/host-fd view used by socket and epoll investigations.
pub const FDOWNER: u8 = 38;
/// Logical open-description ownership at close. `a` is guest PID, `b` guest
/// fd, and `c` the logical reference count immediately before removal. It lets
/// a core/live LLDB session find the process clone that retained a pipe writer.
pub const FDREF: u8 = 39;

const HVPWAIT_ID_MASK: u32 = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvpatchWaitRegisters {
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
}

#[cfg(feature = "event-ring-dump")]
fn dir() -> Option<&'static str> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var("CARRICK_EVENTRING").ok())
        .as_deref()
}

/// Append one event. ALWAYS records (a few relaxed atomics, no lock/syscall/
/// alloc — ~ns) so the ring is present in a core file or live process from ANY
/// run, with no env pre-armed. That is the point: an intermittent Heisenbug you
/// can't predict still leaves its fork/socket/epoll history in the ring, readable
/// post-mortem via `lldb ... carrick eventring`. Only the perturbing FILE dump
/// (the 1 Hz watchdog) is gated, behind the `event-ring-dump` feature.
#[inline]
pub fn rec(kind: u8, a: i32, b: i32, c: i32) {
    let lo = (a as u32 as u64) | ((b as u32 as u64) << 32);
    let hi = (c as u32 as u64) | ((kind as u64) << 32);
    let i = IDX.fetch_add(1, Ordering::Relaxed) % N;
    // Write hi (with the kind tag) LAST so a reader that sees a valid kind has
    // a good chance of also seeing the matching lo.
    RING[i].lo.store(lo, Ordering::Relaxed);
    RING[i].hi.store(hi, Ordering::Relaxed);
    #[cfg(feature = "event-ring-dump")]
    maybe_start_watchdog();
}

#[inline]
fn rec_futex(kind: u8, address: u64, detail: i32) {
    rec(
        kind,
        address as u32 as i32,
        (address >> 32) as u32 as i32,
        detail,
    );
}

/// Record entry into a process-private futex wait without allocation or a
/// syscall. The guest tid lets LLDB join the address to a sleeping host thread.
#[inline]
pub fn rec_futex_wait(address: u64, tid: i32) {
    rec_futex(FUTEXWAIT, address, tid);
}

/// Record the actual number of process-private waiters removed by FUTEX_WAKE.
#[inline]
pub fn rec_futex_wake(address: u64, woken: u32) {
    rec_futex(FUTEXWAKE, address, woken.min(i32::MAX as u32) as i32);
}

/// Record how a process-private futex wait ended: 0=woken, 1=interrupted,
/// 2=timed out.
#[inline]
pub fn rec_futex_end(address: u64, outcome: i32) {
    rec_futex(FUTEXEND, address, outcome);
}

/// Record one cold-path HvPatch thread teardown checkpoint.
#[inline]
pub fn rec_hvpatch_thread_teardown(pid: i32, tid: i32, phase: i32) {
    rec(HVPTHREAD, pid, tid, phase);
}

/// Record a process-aware HvPatch fd-wait checkpoint without allocation.
#[inline]
pub fn rec_hvpatch_wait(pid: i32, tid: i32, wait_class: u8, phase: u8, fd_count: usize) {
    let packed = u32::from(wait_class)
        | (u32::from(phase) << 8)
        | ((fd_count.min(u16::MAX as usize) as u32) << 16);
    rec(HVPWAIT, pid, tid, packed as i32);
}

#[inline]
fn encode_hvpatch_wait_correlation(id: u32, wait_class: u8, phase: u8) -> u32 {
    (id & HVPWAIT_ID_MASK)
        | ((u32::from(wait_class) & 0x0f) << 24)
        | ((u32::from(phase) & 0x0f) << 28)
}

#[inline]
fn rec_hvpatch_wait_value(kind: u8, value: u64, id: u32) {
    rec(
        kind,
        value as u32 as i32,
        (value >> 32) as u32 as i32,
        (id & HVPWAIT_ID_MASK) as i32,
    );
}

/// Begin a process-aware HvPatch wait trace before vCPU reclaim destroys the
/// live register file. The returned ID must be supplied to
/// [`rec_hvpatch_wait_end`] so concurrent waits can be joined without relying
/// on event adjacency.
#[inline]
pub fn rec_hvpatch_wait_begin(
    pid: i32,
    tid: i32,
    wait_class: u8,
    fd_count: usize,
    primary_fd: Option<(i32, i16)>,
    registers: HvpatchWaitRegisters,
) -> u32 {
    let mut id = NEXT_HVPWAIT_ID.fetch_add(1, Ordering::Relaxed) & HVPWAIT_ID_MASK;
    if id == 0 {
        id = 1;
    }
    rec_hvpatch_wait(pid, tid, wait_class, 1, fd_count);
    rec(
        HVPWAITX,
        pid,
        tid,
        encode_hvpatch_wait_correlation(id, wait_class, 1) as i32,
    );
    rec_hvpatch_wait_value(HVPWAIT_PC, registers.pc, id);
    rec_hvpatch_wait_value(HVPWAIT_SP, registers.sp, id);
    rec_hvpatch_wait_value(HVPWAIT_LR, registers.lr, id);
    if let Some((fd, events)) = primary_fd {
        rec(HVPWAITFD, id as i32, fd, i32::from(events));
    }
    id
}

/// Finish a correlated HvPatch wait trace. `phase` uses the HVPWAIT lifecycle
/// values (2 ready, 3 timeout, 4 interrupted, 5 errno).
#[inline]
pub fn rec_hvpatch_wait_end(
    pid: i32,
    tid: i32,
    wait_class: u8,
    phase: u8,
    fd_count: usize,
    id: u32,
) {
    rec_hvpatch_wait(pid, tid, wait_class, phase, fd_count);
    rec(
        HVPWAITX,
        pid,
        tid,
        encode_hvpatch_wait_correlation(id, wait_class, phase) as i32,
    );
}

/// Join an in-process guest child selector to a correlated wait snapshot.
#[inline]
pub fn rec_hvpatch_wait_target(id: u32, target_pid: Option<i32>) {
    rec(
        HVPWAIT_TARGET,
        (id & HVPWAIT_ID_MASK) as i32,
        target_pid.unwrap_or(-1),
        0,
    );
}

#[inline]
pub fn rec_hvpatch_process_exit_begin(pid: i32, tid: i32, exit_code: i32) {
    rec(HVPPEXIT_BEGIN, pid, tid, exit_code);
}

#[inline]
pub fn rec_hvpatch_process_exit_end(pid: i32, tid: i32, exit_code: i32) {
    rec(HVPPEXIT_END, pid, tid, exit_code);
}

#[cfg(test)]
pub(crate) fn contains_event(kind: u8, a: i32, b: i32, c: i32) -> bool {
    RING.iter().any(|slot| {
        let lo = slot.lo.load(Ordering::Relaxed);
        let hi = slot.hi.load(Ordering::Relaxed);
        (hi >> 32) as u8 == kind
            && (lo & 0xffff_ffff) as u32 as i32 == a
            && (lo >> 32) as u32 as i32 == b
            && (hi & 0xffff_ffff) as u32 as i32 == c
    })
}

#[inline]
fn encode_dsr_fault(
    pc: u64,
    address: u64,
    signal: i32,
    esr: u64,
    sp: u64,
    lr: u64,
) -> [(u8, i32, i32, i32); 4] {
    [
        (
            DSRFAULT_PC,
            pc as u32 as i32,
            (pc >> 32) as u32 as i32,
            signal,
        ),
        (
            DSRFAULT_ADDR,
            address as u32 as i32,
            (address >> 32) as u32 as i32,
            esr as u32 as i32,
        ),
        (DSRFAULT_SP, sp as u32 as i32, (sp >> 32) as u32 as i32, 0),
        (DSRFAULT_LR, lr as u32 as i32, (lr >> 32) as u32 as i32, 0),
    ]
}

/// Record a full-width DSR guest PC and fault address without allocation or
/// syscalls. The adjacent records are paired by order in the per-process ring.
#[inline]
pub fn rec_dsr_fault(pc: u64, address: u64, signal: i32, esr: u64, sp: u64, lr: u64) {
    for (kind, a, b, c) in encode_dsr_fault(pc, address, signal, esr, sp, lr) {
        rec(kind, a, b, c);
    }
}

/// Cheap, stable 32-bit hash of an AF_UNIX path, so a `connect` can be matched
/// to the `bind` of the same socket without storing the string.
pub fn path_hash(path: &[u8]) -> i32 {
    // FNV-1a.
    let mut h: u32 = 0x811c_9dc5;
    for &byte in path {
        h ^= byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h as i32
}

/// Reset the ring + re-arm the watchdog for a freshly forked child (its
/// inherited watchdog thread did not survive the fork). The child keeps its OWN
/// event history from here, so a per-process core shows that process's events.
pub fn reinit_after_fork() {
    IDX.store(0, Ordering::SeqCst);
    WATCHDOG.store(false, Ordering::SeqCst);
}

/// Spawn the 1 Hz file-dump watchdog once per process (only compiled in under
/// the `event-ring-dump` feature). Cheap no-op on the hot path: a relaxed load,
/// and — unless `CARRICK_EVENTRING` names a dir — never spawns anything. The
/// recording itself is unconditional (see `rec`).
#[cfg(feature = "event-ring-dump")]
fn maybe_start_watchdog() {
    if WATCHDOG.load(Ordering::Relaxed) {
        return;
    }
    let Some(d) = dir() else {
        // No file dump requested; mark "started" so we don't re-check the env
        // every event. The ring is still recorded for lldb/core post-mortem.
        WATCHDOG.store(true, Ordering::Relaxed);
        return;
    };
    if WATCHDOG.swap(true, Ordering::SeqCst) {
        return; // another thread won the race
    }
    let path = format!("{d}/carrick-ring.{}", std::process::id());
    let _ = std::thread::Builder::new()
        .name("carrick-eventring".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                dump(&path);
            }
        });
}

#[cfg(feature = "event-ring-dump")]
fn decode(kind: u8, a: i32, b: i32, c: i32) -> String {
    match kind {
        BIND => format!("BIND     gfd={a} hfd={b} pathhash={c:#010x}"),
        LISTEN => format!("LISTEN   hfd={a}"),
        CONNECT => format!("CONNECT  hfd={a} rc={b} pathhash={c:#010x}"),
        ACCEPT => format!("ACCEPT   listener_hfd={a} ret={b}"),
        EPADD => format!("EPADD    kq={a} hfd={b} events={c:#x}"),
        EPWAIT => format!("EPWAIT   kq={a} ready={b} timeout={c}"),
        FORK => format!("FORK     child_pid={a}"),
        EXEC => format!("EXEC     path_present={a}"),
        FDOPEN => format!("FDOPEN   gfd={a} hfd={b} minfd={c}"),
        FDCLOSE => format!("FDCLOSE  gfd={a} hfd={b}"),
        ACCEPTERR => format!("ACCEPTER listener_hfd={a} accepted_hfd={b} errno={c}"),
        EPWFD => format!("EPWFD    fd={a} events={b:#x} timeout={c}"),
        EPMASK => format!("EPMASK   origin={a} raw={b:#x} last={c:#x}"),
        EPMASKFD => format!("EPMASKFD origin={a} gfd={b} hfd={c}"),
        EPEDGE => format!("EPEDGE   gfd={a} edge={b:#x} count={c}"),
        DSRFAULT_PC => format!(
            "DSRFAULT pc={:#018x} signal={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        DSRFAULT_ADDR => format!(
            "DSRFAULT address={:#018x} esr={:#010x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32),
            c as u32
        ),
        DSRFAULT_SP => format!(
            "DSRFAULT sp={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        DSRFAULT_LR => format!(
            "DSRFAULT lr={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        NSREJECT => format!("NSREJECT pathhash={a:#010x} reasonhash={b:#010x} pid={c}"),
        EFDWRITE => format!("EFDWRITE hfd={a} before={} after={}", b as u32, c as u32),
        EFDREAD => format!("EFDREAD  hfd={a} before={} after={}", b as u32, c as u32),
        FUTEXWAIT => format!(
            "FUTEXWAIT addr={:#018x} tid={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        FUTEXWAKE => format!(
            "FUTEXWAKE addr={:#018x} woken={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        FUTEXEND => format!(
            "FUTEXEND addr={:#018x} outcome={}",
            (a as u32 as u64) | ((b as u32 as u64) << 32),
            match c {
                0 => "woken",
                1 => "interrupted",
                2 => "timed-out",
                _ => "unknown",
            }
        ),
        HVPTHREAD => format!(
            "HVPTHREAD pid={a} tid={b} phase={}",
            match c {
                1 => "cleanup-start",
                2 => "registry-removed",
                3 => "kicker-unregistered",
                4 => "signal-forgotten",
                5 => "dispatcher-forgotten",
                6 => "vcpu-destroyed",
                7 => "loop-return",
                _ => "unknown",
            }
        ),
        HVPWAIT => {
            let packed = c as u32;
            let wait_class = match packed & 0xff {
                1 => "fds",
                2 => "select",
                3 => "poll",
                4 => "proc-exit",
                5 => "proc-state",
                6 => "child",
                7 => "futex",
                _ => "unknown",
            };
            let phase = match (packed >> 8) & 0xff {
                1 => "begin",
                2 => "ready",
                3 => "timed-out",
                4 => "interrupted",
                5 => "errno",
                _ => "unknown",
            };
            format!(
                "HVPWAIT  pid={a} tid={b} wait={wait_class} phase={phase} fds={}",
                packed >> 16
            )
        }
        HVPWAITX => {
            let packed = c as u32;
            let wait_class = match (packed >> 24) & 0x0f {
                1 => "fds",
                2 => "select",
                3 => "poll",
                4 => "proc-exit",
                5 => "proc-state",
                6 => "child",
                7 => "futex",
                _ => "unknown",
            };
            let phase = match (packed >> 28) & 0x0f {
                1 => "begin",
                2 => "ready",
                3 => "timed-out",
                4 => "interrupted",
                5 => "errno",
                _ => "unknown",
            };
            format!(
                "HVPWAITX pid={a} tid={b} id={:#08x} wait={wait_class} phase={phase}",
                packed & HVPWAIT_ID_MASK
            )
        }
        HVPWAIT_PC => format!(
            "HVPWAITPC id={:#08x} pc={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAIT_SP => format!(
            "HVPWAITSP id={:#08x} sp={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAIT_LR => format!(
            "HVPWAITLR id={:#08x} lr={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAITFD => format!(
            "HVPWAITFD id={:#08x} fd={b} events={:#x}",
            a as u32 & HVPWAIT_ID_MASK,
            c as u32
        ),
        HVPPEXIT_BEGIN => {
            format!("HVPPEXIT pid={a} tid={b} exit={c} publication=begin")
        }
        HVPPEXIT_END => {
            format!("HVPPEXIT pid={a} tid={b} exit={c} publication=complete")
        }
        HVPWAIT_TARGET => format!(
            "HVPWAITTARGET id={:#08x} target_pid={b}",
            a as u32 & HVPWAIT_ID_MASK
        ),
        EPREADY => format!("EPREADY  epfd={a} gfd={b} events={:#x}", c as u32),
        EPSTALE => format!(
            "EPSTALE  gfd={a} observed_gen={} live_gen={}",
            b as u32,
            if c < 0 {
                "none".to_owned()
            } else {
                (c as u32).to_string()
            }
        ),
        FDOWNER => format!("FDOWNER pid={a} tid={b} gfd={c}"),
        FDREF => format!("FDREF    pid={a} gfd={b} refs_before={c}"),
        _ => String::new(),
    }
}

#[cfg(feature = "event-ring-dump")]
fn dump(path: &str) {
    use std::io::Write;
    let total = IDX.load(Ordering::SeqCst);
    let count = total.min(N);
    let start = total.saturating_sub(count);
    let mut out = String::with_capacity(count * 48);
    out.push_str(&format!(
        "# carrick event ring pid={} events={}\n",
        std::process::id(),
        total
    ));
    for k in 0..count {
        let global = start + k;
        let i = global % N;
        let lo = RING[i].lo.load(Ordering::Relaxed);
        let hi = RING[i].hi.load(Ordering::Relaxed);
        let a = (lo & 0xffff_ffff) as u32 as i32;
        let b = (lo >> 32) as u32 as i32;
        let c = (hi & 0xffff_ffff) as u32 as i32;
        let kind = (hi >> 32) as u8;
        let line = decode(kind, a, b, c);
        if line.is_empty() {
            continue; // torn/empty slot
        }
        out.push_str(&format!("{global:6} {line}\n"));
    }
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = f.write_all(out.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn futex_events_preserve_full_width_address_and_lifecycle_detail() {
        let address = 0x0000_0137_89ab_cdef;

        rec_futex_wait(address, 53_664);
        rec_futex_wake(address, 3);
        rec_futex_end(address, 2);

        let low = address as u32 as i32;
        let high = (address >> 32) as u32 as i32;
        assert!(contains_event(FUTEXWAIT, low, high, 53_664));
        assert!(contains_event(FUTEXWAKE, low, high, 3));
        assert!(contains_event(FUTEXEND, low, high, 2));
    }

    #[test]
    fn hvpatch_thread_teardown_event_carries_guest_process_thread_and_phase() {
        rec_hvpatch_thread_teardown(56_172, 56_099, 3);
        assert!(contains_event(HVPTHREAD, 56_172, 56_099, 3));
    }

    #[test]
    fn hvpatch_wait_event_carries_guest_identity_class_phase_and_fd_count() {
        rec_hvpatch_wait(57_499, 57_520, 3, 1, 2);
        assert!(contains_event(
            HVPWAIT,
            57_499,
            57_520,
            3 | (1 << 8) | (2 << 16)
        ));
    }

    #[test]
    fn hvpatch_wait_snapshot_correlates_identity_registers_and_primary_fd() {
        let id = rec_hvpatch_wait_begin(
            57_499,
            57_520,
            3,
            2,
            Some((16408, libc::POLLIN)),
            HvpatchWaitRegisters {
                pc: 0x0000_0040_1234_5678,
                sp: 0x0000_007f_89ab_cdef,
                lr: 0x0000_0040_dead_beef,
            },
        );
        rec_hvpatch_wait_end(57_499, 57_520, 3, 2, 2, id);

        let begin = encode_hvpatch_wait_correlation(id, 3, 1);
        let ready = encode_hvpatch_wait_correlation(id, 3, 2);
        assert!(contains_event(HVPWAITX, 57_499, 57_520, begin as i32));
        assert!(contains_event(HVPWAITX, 57_499, 57_520, ready as i32));
        assert!(contains_event(HVPWAIT_PC, 0x1234_5678, 0x40, id as i32));
        assert!(contains_event(
            HVPWAIT_SP,
            0x89ab_cdef_u32 as i32,
            0x7f,
            id as i32
        ));
        assert!(contains_event(
            HVPWAIT_LR,
            0xdead_beef_u32 as i32,
            0x40,
            id as i32
        ));
        assert!(contains_event(
            HVPWAITFD,
            id as i32,
            16408,
            i32::from(libc::POLLIN)
        ));
    }

    #[test]
    fn hvpatch_process_exit_records_publication_boundary() {
        rec_hvpatch_process_exit_begin(62_809, 62_809, 0);
        rec_hvpatch_process_exit_end(62_809, 62_809, 0);
        assert!(contains_event(HVPPEXIT_BEGIN, 62_809, 62_809, 0));
        assert!(contains_event(HVPPEXIT_END, 62_809, 62_809, 0));
    }

    #[test]
    fn hvpatch_wait_target_joins_guest_child_pid_to_wait_id() {
        rec_hvpatch_wait_target(0x12_3456, Some(62_809));
        assert!(contains_event(HVPWAIT_TARGET, 0x12_3456, 62_809, 0));
    }

    #[test]
    fn dsr_fault_events_preserve_full_width_pc_address_signal_and_esr() {
        let pc = 0x0000_00a0_1234_5678;
        let address = 0xffff_00a0_9abc_def0;
        let signal = 11;
        let esr = 0x9600_0045;

        assert_eq!(
            encode_dsr_fault(
                pc,
                address,
                signal,
                esr,
                0x0000_00ff_1234_5678,
                0x400f_64380
            ),
            [
                (
                    DSRFAULT_PC,
                    pc as u32 as i32,
                    (pc >> 32) as u32 as i32,
                    signal,
                ),
                (
                    DSRFAULT_ADDR,
                    address as u32 as i32,
                    (address >> 32) as u32 as i32,
                    esr as i32,
                ),
                (DSRFAULT_SP, 0x1234_5678, 0x0000_00ff, 0),
                (DSRFAULT_LR, 0x00f6_4380, 0x0000_0004, 0),
            ]
        );
    }
}
