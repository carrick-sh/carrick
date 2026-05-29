//! rt_sigsuspend(2) must wake on a THREAD-DIRECTED (tgkill/tkill) signal, not
//! only a process-global one. A sibling thread blocks SIGUSR1, then calls
//! sigsuspend() with a mask that UNBLOCKS SIGUSR1 (parking inside the kernel's
//! rt_sigsuspend wait with SIGUSR1 deliverable). The main thread sends
//! tgkill(getpid, sibling_tid, SIGUSR1). On Linux the suspended thread wakes
//! immediately, runs the SIGUSR1 handler, and sigsuspend returns -1/EINTR.
//!
//! carrick's rt_sigsuspend wait loop (dispatch/signal.rs ~596-612) only polls
//! the dispatcher per-tid `pendings` set and the PROCESS-GLOBAL host slot
//! (host_signal::take_pending) — never the per-tid THREAD_PENDING slot that a
//! cross-thread tgkill of an UNBLOCKED signal writes. Routing: tgkill ->
//! route_thread_signal (signal.rs:928-951); because the suspended sibling's
//! dispatcher mask is suspend_mask (SIGUSR1 unblocked), signal_blocked() is
//! false, so it takes the `SignalThread` arm (signal.rs:945-948) ->
//! complete_signal_thread (runtime.rs:1358-1372) -> publish_pending_for
//! (THREAD_PENDING) + kicker.kick. The kick is a no-op (the thread is spinning
//! in the dispatcher's 1ms sleep loop, not in vcpu.run/kqueue), and neither
//! poll source sees THREAD_PENDING. So the thread does not wake until the
//! loop's 5 s safety deadline. This probe is the LTP-style deterministic repro:
//! every reported value is a boolean, and every wait is bounded so the buggy
//! path prints `false` (never hangs the harness).

use conformance_probes::report;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

static HITS: AtomicU32 = AtomicU32::new(0);
static SIB_TID: AtomicI32 = AtomicI32::new(0);
static SIB_IN_SUSPEND: AtomicU32 = AtomicU32::new(0); // sibling about to enter sigsuspend
static SIB_RETURNED: AtomicU32 = AtomicU32::new(0); // sigsuspend returned
static SIB_RC: AtomicI32 = AtomicI32::new(0);
static SIB_ERRNO: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_sig: i32) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn install(sig: i32) -> bool {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_usr1 as *const () as usize;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, core::ptr::null_mut()) == 0
}

extern "C" fn sibling(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let sig = libc::SIGUSR1;
        let tid = libc::syscall(libc::SYS_gettid) as i32;
        SIB_TID.store(tid, Ordering::SeqCst);

        // Block SIGUSR1 in this thread's persistent mask, so it is NOT delivered
        // until sigsuspend atomically unblocks it. Capture the prior mask to
        // derive the suspend mask (== prior with SIGUSR1 cleared).
        let mut block: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, sig);
        let mut prev: libc::sigset_t = core::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, &block, &mut prev);

        // suspend_mask = prev with SIGUSR1 explicitly cleared -> SIGUSR1 is
        // deliverable for the duration of the suspend.
        let mut suspend_mask: libc::sigset_t = prev;
        libc::sigdelset(&mut suspend_mask, sig);

        SIB_IN_SUSPEND.store(1, Ordering::SeqCst);
        // glibc/musl sigsuspend(2) routes to rt_sigsuspend on aarch64.
        let rc = libc::sigsuspend(&suspend_mask);
        SIB_RC.store(rc, Ordering::SeqCst);
        SIB_ERRNO.store(conformance_probes::errno(), Ordering::SeqCst);
        SIB_RETURNED.store(1, Ordering::SeqCst);
    }
    core::ptr::null_mut()
}

fn main() {
    unsafe {
        let sig = libc::SIGUSR1;
        if !install(sig) {
            report!(install_ok = false);
            return;
        }

        let mut thr: libc::pthread_t = core::mem::zeroed();
        let prc = libc::pthread_create(&mut thr, core::ptr::null(), sibling, core::ptr::null_mut());
        if prc != 0 {
            report!(install_ok = true, sibling_spawned = false);
            return;
        }

        // Wait (bounded) for the sibling to publish its tid and signal it is
        // entering sigsuspend.
        let park = Instant::now() + Duration::from_secs(2);
        while SIB_IN_SUSPEND.load(Ordering::SeqCst) == 0 && Instant::now() < park {
            std::thread::sleep(Duration::from_millis(2));
        }
        // Give the sibling a beat to actually be parked inside the rt_sigsuspend
        // wait (and to have installed suspend_mask, so the dispatcher routes via
        // the SignalThread/THREAD_PENDING arm, not mark_signal_pending) before
        // we signal it. Bounded constant, not a correctness dependency.
        std::thread::sleep(Duration::from_millis(100));
        let target = SIB_TID.load(Ordering::SeqCst);

        // tgkill the SUSPENDED sibling. On Linux this wakes it. carrick (buggy)
        // routes via SignalThread -> publish_pending_for (per-tid THREAD_PENDING)
        // + a vCPU kick, neither of which the rt_sigsuspend sleep-loop observes.
        let tgkill_rc = libc::syscall(
            libc::SYS_tgkill,
            libc::getpid() as libc::c_long,
            target as libc::c_long,
            sig as libc::c_long,
        ) as i32;

        // Bounded wait for the wakeup + handler. On the buggy path the sibling
        // sleeps in its loop until the 5 s safety deadline, so 2 s is well inside
        // the hang window and yields `false` deterministically.
        let deadline = Instant::now() + Duration::from_secs(2);
        while (HITS.load(Ordering::SeqCst) == 0 || SIB_RETURNED.load(Ordering::SeqCst) == 0)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(2));
        }

        let woke = SIB_RETURNED.load(Ordering::SeqCst) == 1;
        let handler_ran = HITS.load(Ordering::SeqCst) >= 1;
        let returned_eintr = woke
            && SIB_RC.load(Ordering::SeqCst) == -1
            && SIB_ERRNO.load(Ordering::SeqCst) == libc::EINTR;

        // Reap the sibling so the harness does not block on join. If it never
        // woke (buggy), it is still parked in sigsuspend's own 5 s loop; detach
        // (not join) so this process can exit without hanging — process exit
        // tears the parked sibling down.
        if woke {
            libc::pthread_join(thr, core::ptr::null_mut());
        } else {
            libc::pthread_detach(thr);
        }

        report!(
            tgkill_rc_ok = tgkill_rc == 0,
            // Linux: true. carrick (buggy): false — never wakes within bound.
            suspended_thread_woke = woke,
            sigsuspend_handler_ran = handler_ran,
            sigsuspend_returned_eintr = returned_eintr,
        );
    }
}