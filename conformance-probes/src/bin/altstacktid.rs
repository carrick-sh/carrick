//! Per-thread `sigaltstack` storage. `sigaltstack` is per-thread in Linux — each
//! thread has its own alt stack. carrick once stored it process-globally, so a
//! thread's alt stack was clobbered when ANOTHER thread set its own; under Go's
//! per-M signal stacks that made concurrent SIGURG frames overlap → goroutine-
//! stack corruption (the c>=20 EL0 faults). This probe tests the storage
//! directly via the sigaltstack get/set round-trip (no signal delivery):
//!
//!   thread B: set alt stack BUF_B
//!   main A:   set alt stack BUF_A  (clobbers a GLOBAL slot if buggy)
//!   thread B: re-read its alt stack — must STILL be BUF_B.
//!
//! Buggy (global): B reads back BUF_A → `b_kept_own=false`. Fixed (per-thread):
//! BUF_B → `true`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const STK: usize = 64 * 1024; // > MINSIGSTKSZ
static mut BUF_A: [u8; STK] = [0; STK];
static mut BUF_B: [u8; STK] = [0; STK];

static B_SET: AtomicBool = AtomicBool::new(false); // B has set BUF_B
static A_SET: AtomicBool = AtomicBool::new(false); // A has set BUF_A (after B)
static B_READBACK: AtomicUsize = AtomicUsize::new(0); // B's ss_sp after A set its own
static B_DONE: AtomicBool = AtomicBool::new(false);

unsafe fn set_altstack(buf: *mut u8) {
    let ss = libc::stack_t {
        ss_sp: buf as *mut libc::c_void,
        ss_flags: 0,
        ss_size: STK,
    };
    libc::sigaltstack(&ss, std::ptr::null_mut());
}

unsafe fn get_ss_sp() -> usize {
    let mut cur: libc::stack_t = std::mem::zeroed();
    libc::sigaltstack(std::ptr::null(), &mut cur);
    cur.ss_sp as usize
}

extern "C" fn thread_b(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        set_altstack(std::ptr::addr_of_mut!(BUF_B) as *mut u8);
        B_SET.store(true, Ordering::SeqCst);
        // Wait until the main thread has set ITS OWN alt stack, then read back
        // ours: a per-thread store keeps BUF_B; a global store now reads BUF_A.
        while !A_SET.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        B_READBACK.store(get_ss_sp(), Ordering::SeqCst);
        B_DONE.store(true, Ordering::SeqCst);
    }
    std::ptr::null_mut()
}

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut tb: libc::pthread_t = std::mem::zeroed();
    libc::pthread_create(&mut tb, std::ptr::null(), thread_b, std::ptr::null_mut());
    while !B_SET.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    set_altstack(std::ptr::addr_of_mut!(BUF_A) as *mut u8);
    A_SET.store(true, Ordering::SeqCst);
    while !B_DONE.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    libc::pthread_join(tb, std::ptr::null_mut());

    let b_base = std::ptr::addr_of!(BUF_B) as usize;
    let a_base = std::ptr::addr_of!(BUF_A) as usize;
    let readback = B_READBACK.load(Ordering::SeqCst);
    // Deterministic: did B's alt stack survive A setting a different one?
    println!("b_kept_own={}", readback == b_base);
    // Guard against false-pass if the two buffers happen to coincide.
    println!("bufs_distinct={}", a_base != b_base);
}
