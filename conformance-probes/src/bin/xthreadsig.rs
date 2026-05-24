//! Cross-thread signal delivery to a thread blocked in pthread_join (futex).
//! main installs an SA handler, spawns B; B signals main, then exits; main
//! (blocked in join) must run the handler before join returns (POSIX). Isolates
//! the cross-thread-to-blocked-thread delivery the altstack probe exposed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static GOT: AtomicBool = AtomicBool::new(false);
static MAIN_TH: AtomicU64 = AtomicU64::new(0);

extern "C" fn handler(_sig: libc::c_int) {
    GOT.store(true, Ordering::SeqCst);
}

extern "C" fn thread_b(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        libc::usleep(100_000); // let main reach pthread_join first
        libc::pthread_kill(MAIN_TH.load(Ordering::SeqCst) as libc::pthread_t, libc::SIGUSR1);
    }
    std::ptr::null_mut()
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        MAIN_TH.store(libc::pthread_self() as u64, Ordering::SeqCst);

        let mut tb: libc::pthread_t = std::mem::zeroed();
        libc::pthread_create(&mut tb, std::ptr::null(), thread_b, std::ptr::null_mut());
        libc::pthread_join(tb, std::ptr::null_mut());
        println!("delivered={}", GOT.load(Ordering::SeqCst));
    }
}
