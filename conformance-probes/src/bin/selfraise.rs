//! Minimal single-threaded self-`raise()` of a caught signal. POSIX: raise()
//! returns only after the handler has run. Isolates self-signal DELIVERY from
//! the threading/tid quirks the altstack probe exposed.

use std::sync::atomic::{AtomicBool, Ordering};

static GOT: AtomicBool = AtomicBool::new(false);

extern "C" fn handler(_sig: libc::c_int) {
    GOT.store(true, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        libc::raise(libc::SIGUSR1);
    }
    println!("delivered={}", GOT.load(Ordering::SeqCst));
}
