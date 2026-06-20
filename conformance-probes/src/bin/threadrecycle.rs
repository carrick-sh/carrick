//! >N TOTAL but ≤N CONCURRENT threads (the M:N admission-gate recycle test, #10
//! Phase 1): spawn+join serially so at most ~1 sibling is alive at once, far more
//! than N over the run. Proves the vCPU slot id is RECYCLED across exited threads
//! (no monotonic exhaustion → no `vm_activate_cpu` EINVAL after N threads).
//!   prints "recycle ok ran=NN" — ran==TOTAL means every thread actually executed.
//!   exit 0 if all ran, 70 otherwise.

use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

const TOTAL: usize = 40; // >> any 8-vCPU cap, but only ~1 alive at once (serial)
static RAN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    RAN.fetch_add(1, Ordering::SeqCst);
    std::ptr::null_mut()
}

fn main() {
    unsafe {
        for _ in 0..TOTAL {
            let mut t: libc::pthread_t = std::mem::zeroed();
            if libc::pthread_create(&mut t, std::ptr::null(), worker, std::ptr::null_mut()) == 0 {
                libc::pthread_join(t, std::ptr::null_mut()); // serial: ≤1 concurrent sibling
            }
        }
        let ran = RAN.load(Ordering::SeqCst);
        let mut buf = *b"recycle ok ran=NN\n";
        buf[15] = b'0' + (ran / 10) as u8;
        buf[16] = b'0' + (ran % 10) as u8;
        libc::write(1, buf.as_ptr() as *const c_void, buf.len());
        libc::_exit(if ran == TOTAL { 0 } else { 70 });
    }
}
