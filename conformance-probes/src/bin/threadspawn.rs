//! Minimal reducer for the bhyve concurrent-vCPU cap (#10): how many guest
//! threads can be *simultaneously runnable*? Each of N threads bumps a LIVE
//! counter on entry, sleeps long enough that all N would overlap if uncapped, then
//! decrements on exit; `peak` is the max LIVE seen. carrick gives each guest thread
//! its own host vCPU, so a backend that caps live vCPUs below N (bhyve
//! `hw.vmm.maxcpu`) can never have more than `cap` threads sleeping at once — the
//! rest run only in a later wave, so `peak` plateaus at the cap instead of N.
//!
//! This measures concurrency WITHOUT a hard hang (the sleep bounds each wave),
//! unlike a true barrier which would deadlock on a capped backend. Heap-/stdio-free.
//!   prints "spawn peak=NN of NN"  — peak==N: no cap at this N; peak<N: the cap.
//!   exit 0 if peak==N, else 70.

use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

const N: usize = 14;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let now = LIVE.fetch_add(1, Ordering::SeqCst) + 1;
    PEAK.fetch_max(now, Ordering::SeqCst);
    // Stay runnable long enough that, uncapped, every thread overlaps every other.
    unsafe {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 400_000_000,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    LIVE.fetch_sub(1, Ordering::SeqCst);
    std::ptr::null_mut()
}

fn main() {
    unsafe {
        let mut tids: [libc::pthread_t; N] = std::mem::zeroed();
        for t in tids.iter_mut() {
            let _ = libc::pthread_create(t, std::ptr::null(), worker, std::ptr::null_mut());
        }
        for &t in tids.iter() {
            // pthread_t is a pointer on musl; skip slots whose create failed.
            if t as usize != 0 {
                libc::pthread_join(t, std::ptr::null_mut());
            }
        }
        let peak = PEAK.load(Ordering::SeqCst);
        let mut buf = *b"spawn peak=NN of NN\n";
        buf[11] = b'0' + (peak / 10) as u8;
        buf[12] = b'0' + (peak % 10) as u8;
        buf[17] = b'0' + (N / 10) as u8;
        buf[18] = b'0' + (N % 10) as u8;
        libc::write(1, buf.as_ptr() as *const c_void, buf.len());
        libc::_exit(if peak >= N { 0 } else { 70 });
    }
}
