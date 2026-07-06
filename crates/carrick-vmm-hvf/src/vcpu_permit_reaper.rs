//! Root-process death-reclaim supervisor for the atomic vCPU-admission permit
//! (Option 3, Task 2).
//!
//! The flock permit path got kernel-backed reclaim for free: when a process died
//! (SIGKILL, segfault, a missed cooperative cleanup) the kernel dropped its
//! `flock`, releasing the slot. The atomic slot table has no such kernel binding,
//! so a hard death would strand its generation-stamped slots forever — the exact
//! ownerless-count leak that timed out the node suites in the 3b attempt.
//!
//! This module recreates that property WITHOUT reintroducing an ownerless count.
//! The root process (the supervisor) owns ONE `Kqueue` and watches every observed
//! owner pid with a native `EVFILT_PROC | NOTE_EXIT` knote. On a watched owner's
//! death it reclaims that owner's *generation-stamped* slots — the generation
//! guard means a late event for a dead owner can never free a NEW slot held by a
//! reused pid.
//!
//! `EVFILT_PROC` is the PRIMARY detector (not `kill(pid, 0)`, which cannot tell a
//! live process from a zombie or a reused pid). Three races are closed explicitly:
//!
//!  * **exit-before-register** — the owner may have exited between the slot-table
//!    snapshot and our `EV_ADD`, so the one-shot exit edge is already in the past.
//!    Immediately after a successful register we do a non-consuming
//!    `waitid(WNOWAIT | WNOHANG)` readiness check (the existing `io_wait` pattern)
//!    and reclaim now if the owner is already dead.
//!  * **register-on-a-gone-pid** — `EV_ADD` on a fully-vanished pid fails with
//!    `ESRCH`; that is itself proof of death, so we reclaim that owner at once.
//!  * **missed registration / kqueue setup failure** — a LOW-frequency periodic
//!    backstop sweep (every ~250 ms) is the safety net ONLY; it is never the
//!    primary path.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use crate::darwin_kqueue::{Kevent, Kqueue};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The slot-table view the supervisor consumes. Implemented by `trap::PermitRegion`
/// for the process singleton and by an in-test mock. Kept to `(pid, generation)`
/// tuples so the reaper never has to name the private slot types.
pub(crate) trait PermitReclaimSource: Send + Sync {
    /// `(owner_pid, generation)` for every currently-occupied slot.
    fn owner_slots(&self) -> Vec<(u32, u32)>;
    /// Free the slot(s) matching EXACTLY `(pid, generation)` — the generation
    /// guard. Returns the number of slots freed.
    fn reclaim(&self, pid: u32, generation: u32) -> usize;
}

/// Non-consuming death check: `waitid(WNOWAIT | WNOHANG)` peeks at the owner's
/// terminal status WITHOUT reaping it (the guest's own `wait4` still reaps).
///
/// Unlike `io_wait::child_status_ready`, `ECHILD` here is NOT treated as "dead":
/// a live grandchild (a nested guest fork, not a direct child of the root) also
/// returns `ECHILD`, and reclaiming its slots while it runs would be catastrophic.
/// Only an rc==0 terminal `CLD_*` state is a confirmed death. Non-direct-children
/// and missed edges are left to `EVFILT_PROC` / the `ESRCH`-at-register path / the
/// backstop.
fn pid_confirmed_dead(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc == 0 {
        // Darwin can report stopped/continued children even for a WEXITED probe;
        // only terminal states are a death. `si_pid != 0` distinguishes an actual
        // report from "no state available yet".
        const CLD_EXITED: i32 = 1;
        const CLD_KILLED: i32 = 2;
        const CLD_DUMPED: i32 = 3;
        info.si_pid != 0 && matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED)
    } else {
        // ECHILD (not our direct child, or already reaped) / any error: NOT a
        // confirmed death here.
        false
    }
}

/// `kill(pid, 0) == ESRCH`: the pid is fully gone (no live process AND no zombie —
/// a zombie still answers `kill` with success). Used ONLY by the periodic backstop
/// as a last-resort net, never as the primary detector. Safe against the two
/// hazards the companion review flags: a zombie returns success (so it is NOT
/// reclaimed here — its exit edge already fired through `EVFILT_PROC`), and a
/// reused-live pid also returns success (so it is NOT reclaimed); only a vanished
/// pid is `ESRCH`, and the generation guard bounds the reclaim to recorded slots.
fn pid_is_gone(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// The supervisor state: one shared `Kqueue` plus the per-pid set of generations
/// we have observed and armed a watch for. `kq` is `Option` so a kqueue setup
/// failure degrades to a backstop-only reaper rather than disabling reclaim.
struct Reaper<'a> {
    kq: Option<Kqueue>,
    source: &'a dyn PermitReclaimSource,
    /// `owner_pid -> {generation, …}`: the generations of THIS pid we have a live
    /// watch for. One `EVFILT_PROC` knote per pid (not per generation); a process
    /// with several vCPUs owns several slots (one generation each) but exits once.
    watched: HashMap<u32, HashSet<u32>>,
}

impl<'a> Reaper<'a> {
    fn new(source: &'a dyn PermitReclaimSource) -> Self {
        Self {
            kq: Kqueue::new_internal(),
            source,
            watched: HashMap::new(),
        }
    }

    /// Poll the slot table and, for any `(pid, generation)` we are not already
    /// tracking, record it; the FIRST generation seen for a pid also arms its
    /// one-shot `EVFILT_PROC` watch.
    fn register_new_owners(&mut self) {
        for (pid, generation) in self.source.owner_slots() {
            let newly_watched_pid = {
                let gens = self.watched.entry(pid).or_default();
                if gens.contains(&generation) {
                    continue;
                }
                let first = gens.is_empty();
                gens.insert(generation);
                first
            };
            if newly_watched_pid {
                self.arm_watch(pid);
            }
        }
    }

    /// Arm the one-shot proc watch for `pid` and close the exit-before-register
    /// races: a successful register is followed by a non-consuming readiness
    /// check; a register that fails with `ESRCH` (pid already gone) is itself a
    /// death signal.
    fn arm_watch(&mut self, pid: u32) {
        let reclaim_now = match &self.kq {
            Some(kq) => match kq.apply(&[Kevent::proc_exit(pid as i32)]) {
                // Registered: but the owner may have exited between the slot-table
                // snapshot and this EV_ADD (one-shot edge already in the past), so
                // confirm liveness non-destructively and reclaim now if dead.
                Ok(()) => pid_confirmed_dead(pid as i32),
                // ESRCH (or any register failure): the owner is not watchable —
                // reclaim its recorded slots immediately.
                Err(_errno) => true,
            },
            // Degraded (kqueue setup failed): the periodic backstop is the only
            // detector; leave the pid recorded so the backstop tracks it.
            None => false,
        };
        if reclaim_now {
            self.reclaim_pid(pid);
        }
    }

    /// Reclaim every recorded generation-stamped slot owned by `pid`, then drop
    /// the (possibly still-armed) one-shot watch. Idempotent: a second call (a
    /// stale `NOTE_EXIT` after we already reclaimed, or a backstop double-fire)
    /// finds nothing recorded and is a no-op, and `reclaim` itself is generation-
    /// guarded so it can never free a reused pid's newer slot.
    fn reclaim_pid(&mut self, pid: u32) {
        let Some(generations) = self.watched.remove(&pid) else {
            return;
        };
        for generation in generations {
            self.source.reclaim(pid, generation);
        }
        if let Some(kq) = &self.kq {
            let _ = kq.apply(&[Kevent::proc_exit_delete(pid as i32)]);
        }
    }

    /// Block up to `timeout` for one or more `EVFILT_PROC` events (the primary
    /// death edge) and reclaim each exited owner. With no kqueue, just sleep the
    /// interval and let the backstop do the work.
    fn wait_for_events(&mut self, timeout: &libc::timespec) {
        for pid in self.poll_kqueue(timeout) {
            self.reclaim_pid(pid);
        }
    }

    fn poll_kqueue(&self, timeout: &libc::timespec) -> Vec<u32> {
        match &self.kq {
            Some(kq) => {
                let mut out = [Kevent::empty(); 16];
                match kq.wait(&[], &mut out, Some(timeout)) {
                    // Both NOTE_EXIT and EV_ERROR events carry EVFILT_PROC, so
                    // `proc_exit_ident` maps either back to the exited pid.
                    Ok(n) => out[..n]
                        .iter()
                        .filter_map(|ev| ev.proc_exit_ident().map(|p| p as u32))
                        .collect(),
                    // EINTR / EBADF (kqueue closed under a fork-storm): the
                    // backstop covers a dropped edge.
                    Err(_errno) => Vec::new(),
                }
            }
            None => {
                unsafe { libc::nanosleep(timeout, std::ptr::null_mut()) };
                Vec::new()
            }
        }
    }

    /// Low-frequency safety net for missed registrations / lost edges / kqueue
    /// setup failure. NOT the primary detector: it reclaims only owners it can
    /// prove dead (a direct child via `waitid`, or a fully-gone pid via
    /// `kill == ESRCH`), and the generation guard bounds each reclaim.
    fn backstop(&mut self) {
        let watched_pids: Vec<u32> = self.watched.keys().copied().collect();
        for pid in watched_pids {
            if pid_confirmed_dead(pid as i32) || pid_is_gone(pid as i32) {
                self.reclaim_pid(pid);
            }
        }
    }

    /// The daemon loop: register newly-observed owners, block for the proc-exit
    /// edge, and run the backstop at most once per `BACKSTOP_INTERVAL` so it stays
    /// genuinely low-frequency even under a fork storm that keeps the kqueue busy.
    fn run(mut self) {
        const POLL_NS: i64 = 250 * 1_000_000;
        const BACKSTOP_INTERVAL: Duration = Duration::from_millis(250);
        let poll = libc::timespec {
            tv_sec: 0,
            tv_nsec: POLL_NS,
        };
        let mut last_backstop = Instant::now();
        loop {
            self.register_new_owners();
            self.wait_for_events(&poll);
            if last_backstop.elapsed() >= BACKSTOP_INTERVAL {
                self.backstop();
                last_backstop = Instant::now();
            }
        }
    }
}

/// Start the root death-reclaim supervisor. Idempotent: only the first call in a
/// process spawns the daemon thread (the `AtomicBool` is inherited as `true` by
/// fork children, so a child never starts a second supervisor — only the root
/// supervises). `source` must outlive the process (the `'static` permit region).
pub(crate) fn spawn_reaper(source: &'static dyn PermitReclaimSource) {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("carrick-vcpu-permit-reaper".into())
        .spawn(move || Reaper::new(source).run());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// In-test slot table: a plain `(pid, generation)` list standing in for the
    /// shared packed-slot table, so the supervisor logic is exercised without the
    /// private `trap::PermitRegion`.
    struct TestSlots {
        slots: Mutex<Vec<(u32, u32)>>,
    }

    impl TestSlots {
        fn new() -> Self {
            Self {
                slots: Mutex::new(Vec::new()),
            }
        }
        fn insert(&self, pid: u32, generation: u32) {
            self.slots.lock().unwrap().push((pid, generation));
        }
        fn is_empty(&self) -> bool {
            self.slots.lock().unwrap().is_empty()
        }
    }

    impl PermitReclaimSource for TestSlots {
        fn owner_slots(&self) -> Vec<(u32, u32)> {
            self.slots.lock().unwrap().clone()
        }
        fn reclaim(&self, pid: u32, generation: u32) -> usize {
            let mut slots = self.slots.lock().unwrap();
            let before = slots.len();
            slots.retain(|&(p, g)| !(p == pid && g == generation));
            before - slots.len()
        }
    }

    /// Fork a child that lives `alive_ns` then `_exit(0)` using only async-signal-
    /// safe calls. Returns the child pid.
    fn fork_short_lived_child(alive_ns: i64) -> i32 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            if alive_ns > 0 {
                let ts = libc::timespec {
                    tv_sec: alive_ns / 1_000_000_000,
                    tv_nsec: alive_ns % 1_000_000_000,
                };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            }
            unsafe { libc::_exit(0) };
        }
        pid
    }

    fn reap(pid: i32) {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    /// The proc-exit edge: a slot owned by a live child is reclaimed when the
    /// child exits and the supervisor drains the delivered `NOTE_EXIT`.
    #[test]
    fn note_exit_reclaims_owner_slot() {
        let slots = TestSlots::new();
        // Child stays alive ~150 ms so we register the watch BEFORE it exits,
        // exercising the NOTE_EXIT delivery path (not the register-after-exit one).
        let pid = fork_short_lived_child(150 * 1_000_000);
        let generation = 7u32;
        slots.insert(pid as u32, generation);

        let mut reaper = Reaper::new(&slots);
        reaper.register_new_owners(); // arms EVFILT_PROC while the child is alive
        assert!(
            reaper.kq.is_some(),
            "kqueue must open for the NOTE_EXIT path to be under test"
        );

        let timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !slots.is_empty() && Instant::now() < deadline {
            reaper.wait_for_events(&timeout);
        }
        reap(pid);
        assert!(
            slots.is_empty(),
            "the dead child's slot was not reclaimed on NOTE_EXIT"
        );
    }

    /// The register-after-exit race: a child that has ALREADY exited (a zombie)
    /// before we register must still be reclaimed — via the post-register
    /// `waitid(WNOWAIT|WNOHANG)` readiness check or the `ESRCH`-on-register path,
    /// never left stranded.
    #[test]
    fn register_after_exit_reclaims_via_readiness_check() {
        let slots = TestSlots::new();
        let pid = fork_short_lived_child(0); // exits immediately

        // Make the exit-before-register race deterministic: wait until the child
        // is confirmed dead (a zombie, since we have not reaped it) BEFORE we let
        // the supervisor register its watch.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_confirmed_dead(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            pid_confirmed_dead(pid),
            "child did not become a reapable zombie"
        );

        let generation = 11u32;
        slots.insert(pid as u32, generation);

        let mut reaper = Reaper::new(&slots);
        // register_new_owners arms the watch on an already-dead pid: the
        // post-register readiness check (or an ESRCH register error) must reclaim.
        reaper.register_new_owners();
        reap(pid);
        assert!(
            slots.is_empty(),
            "an exit-before-register child was stranded (readiness check failed)"
        );
    }
}
