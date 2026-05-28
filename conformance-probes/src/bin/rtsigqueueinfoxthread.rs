//! rt_sigqueueinfo with a sibling-thread target — the exact shape LTP
//! `rt_sigqueueinfo01` exercises. The sibling thread calls `gettid()` and
//! stashes its tid; the main thread calls
//! `rt_sigqueueinfo(sibling_tid, SIGUSR1, &info)`. On Linux the signal is
//! delivered to the process (handlers are process-wide), and *some* thread
//! runs the handler with the queued siginfo. The probe pins down:
//!
//!   1. The rt_sigqueueinfo call returns 0 (no ESRCH).
//!   2. The SA_SIGINFO handler runs.
//!   3. The handler's `info->si_value.sival_int` carries the payload.
//!
//! Same-process so payload-propagation works through carrick's existing
//! per-tid `pending_siginfos` machinery — no IPC needed.

use conformance_probes::{block_signal, errno, report, unblock_signal};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const PAYLOAD: i32 = 0x0BAD_F00D_u32 as i32;
static HITS: AtomicU32 = AtomicU32::new(0);
static OBSERVED_VALUE: AtomicI32 = AtomicI32::new(0);
static SIBLING_TID: AtomicI32 = AtomicI32::new(0);
static SIBLING_READY: AtomicU32 = AtomicU32::new(0);
static SIBLING_DONE: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sig(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    HITS.fetch_add(1, Ordering::SeqCst);
    if !info.is_null() {
        unsafe {
            let base = info as *const u8;
            let sival_int = core::ptr::read(base.add(0x18) as *const i32);
            OBSERVED_VALUE.store(sival_int, Ordering::SeqCst);
        }
    }
}

unsafe fn install(sig: i32) -> bool {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_sig as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, core::ptr::null_mut()) == 0
}

extern "C" fn sibling_thread(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as i32;
        SIBLING_TID.store(tid, Ordering::SeqCst);
        SIBLING_READY.store(1, Ordering::SeqCst);
        // Spin until main releases. Bounded to avoid hanging the harness.
        let deadline = Instant::now() + Duration::from_secs(5);
        while SIBLING_DONE.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
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

        // Spawn sibling so it has a tid to be queried at.
        let mut thr: libc::pthread_t = core::mem::zeroed();
        let prc = libc::pthread_create(
            &mut thr,
            core::ptr::null(),
            sibling_thread,
            core::ptr::null_mut(),
        );
        if prc != 0 {
            report!(install_ok = true, sibling_spawned = false);
            return;
        }

        // Wait for sibling to publish its tid.
        let park = Instant::now() + Duration::from_secs(2);
        while SIBLING_READY.load(Ordering::SeqCst) == 0 && Instant::now() < park {
            std::thread::sleep(Duration::from_millis(2));
        }
        let target = SIBLING_TID.load(Ordering::SeqCst);

        // Block the signal in the MAIN thread so the queued delivery has to
        // route through the sibling (which has it unblocked at thread birth).
        // This makes the delivery target deterministic.
        let _ = block_signal(sig);

        let mut info: libc::siginfo_t = core::mem::zeroed();
        let bytes = &mut info as *mut libc::siginfo_t as *mut u8;
        core::ptr::write(bytes.add(0) as *mut i32, sig);
        core::ptr::write(bytes.add(8) as *mut i32, libc::SI_QUEUE);
        core::ptr::write(bytes.add(0x18) as *mut i32, PAYLOAD);

        let rc = libc::syscall(
            libc::SYS_rt_sigqueueinfo,
            target as i64,
            sig as i64,
            &info as *const _,
        ) as i32;
        let queue_errno = if rc < 0 { errno() } else { 0 };

        // Give the sibling a moment to actually run its handler. Then release
        // the sibling so the thread terminates cleanly.
        let deadline = Instant::now() + Duration::from_secs(1);
        while HITS.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        SIBLING_DONE.store(1, Ordering::SeqCst);
        let _ = unblock_signal(sig);

        libc::pthread_join(thr, core::ptr::null_mut());

        let delivered = HITS.load(Ordering::SeqCst) >= 1;
        let payload_ok = delivered && OBSERVED_VALUE.load(Ordering::SeqCst) == PAYLOAD;

        report!(
            xthr_queue_rc = rc,
            xthr_queue_errno = queue_errno,
            xthr_handler_delivered = delivered,
            xthr_payload_propagated = payload_ok,
        );
    }
}
