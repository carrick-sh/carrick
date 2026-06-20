//! The Phase 2 (reclaim-on-block) reducer: N+ threads that ALL must be alive at
//! once to make progress, each BLOCKING on a shared barrier. Distinguishes:
//!   - Phase 1 (lifetime-bind): only ≤N threads get a vCPU; they block at the
//!     barrier still HOLDING their slots, so the remaining threads never get a slot
//!     to even reach the barrier → the barrier never completes → HANG (timeout).
//!   - Phase 2 (reclaim-on-block): a thread blocked at the barrier RELEASES its
//!     slot, so every thread reaches the barrier (≤N running at any instant) → the
//!     barrier completes → all join → exit 0.
//! pthread_barrier_wait blocks on a futex, so it is a scheduler-visible block point.
//!   prints "barrier ok n=NN" on success; HANGS (no output) on Phase 1.

use std::os::raw::c_void;

const N: usize = 14; // > a typical 8-vCPU cap

static mut BARRIER: libc::pthread_barrier_t = unsafe { std::mem::zeroed() };

extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    unsafe {
        // Block until ALL N workers + main have arrived. On Phase 1 the surplus
        // workers never get here (no vCPU), so this never returns.
        libc::pthread_barrier_wait(&raw mut BARRIER);
    }
    std::ptr::null_mut()
}

fn main() {
    unsafe {
        if libc::pthread_barrier_init(&raw mut BARRIER, std::ptr::null(), (N + 1) as u32) != 0 {
            libc::_exit(83);
        }
        let mut tids: [libc::pthread_t; N] = std::mem::zeroed();
        for t in tids.iter_mut() {
            let _ = libc::pthread_create(t, std::ptr::null(), worker, std::ptr::null_mut());
        }
        // Main also waits — the barrier completes only when all N workers reached it.
        libc::pthread_barrier_wait(&raw mut BARRIER);
        for &t in tids.iter() {
            if t as usize != 0 {
                libc::pthread_join(t, std::ptr::null_mut());
            }
        }
        let mut buf = *b"barrier ok n=NN\n";
        buf[13] = b'0' + (N / 10) as u8;
        buf[14] = b'0' + (N % 10) as u8;
        libc::write(1, buf.as_ptr() as *const c_void, buf.len());
        libc::_exit(0);
    }
}
