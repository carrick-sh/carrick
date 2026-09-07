//! Test whether stage-1 TLBI broadcast invalidates translation across vCPUs
//! and whether stale translation faults are observed.
//!
//! Two pthreads:
//! - Thread B spins reading a page with no syscalls of its own.
//! - Thread A mprotects / munmaps the page.
//! - Thread B reports whether it observes the change within N iterations,
//!   and whether any stale translation faults occur.
//!
//! Expected oracle lines:
//! broadcast_mprotect_observed=true
//! broadcast_munmap_observed=true
//! no_stale_fault=true

use conformance_probes::report;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[repr(align(16))]
#[allow(dead_code)]
struct JumpBuf([usize; 64]);

static mut JUMP_BUF: JumpBuf = JumpBuf([0; 64]);
static B_SPINNING: AtomicBool = AtomicBool::new(false);
static B_OBSERVED_CHANGE: AtomicBool = AtomicBool::new(false);
static B_STALE_FAULT: AtomicBool = AtomicBool::new(false);
static PHASE: AtomicI32 = AtomicI32::new(0);

static mut TEST_PAGE: *mut u8 = core::ptr::null_mut();

const MAX_ITERS: u64 = 100_000_000;

unsafe extern "C" {
    #[link_name = "__sigsetjmp"]
    fn c_sigsetjmp(env: *mut c_void, savesigs: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut c_void, val: libc::c_int) -> !;
}

extern "C" fn segv_handler(sig: i32, _info: *mut libc::siginfo_t, _uctx: *mut c_void) {
    if sig == libc::SIGSEGV {
        let phase = PHASE.load(Ordering::SeqCst);
        if phase == 1 || phase == 2 {
            B_OBSERVED_CHANGE.store(true, Ordering::SeqCst);
            unsafe {
                siglongjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1);
            }
        } else {
            B_STALE_FAULT.store(true, Ordering::SeqCst);
            unsafe {
                siglongjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 2);
            }
        }
    }
}

extern "C" fn worker_thread(_arg: *mut c_void) -> *mut c_void {
    unsafe {
        // Wait for Phase 1: mprotect test
        while PHASE.load(Ordering::SeqCst) != 1 {
            core::hint::spin_loop();
        }

        if c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0 {
            B_SPINNING.store(true, Ordering::SeqCst);
            let mut iters: u64 = 0;
            while iters < MAX_ITERS {
                let val = core::ptr::read_volatile(TEST_PAGE);
                if val != 42 {
                    break;
                }
                iters = iters.saturating_add(1);
            }
        }
        B_SPINNING.store(false, Ordering::SeqCst);

        // Wait for Phase 2: munmap test
        while PHASE.load(Ordering::SeqCst) != 2 {
            core::hint::spin_loop();
        }

        if c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0 {
            B_SPINNING.store(true, Ordering::SeqCst);
            let mut iters: u64 = 0;
            while iters < MAX_ITERS {
                let val = core::ptr::read_volatile(TEST_PAGE);
                if val != 84 {
                    break;
                }
                iters = iters.saturating_add(1);
            }
        }
        B_SPINNING.store(false, Ordering::SeqCst);

        // Wait for Phase 3: stale translation check
        while PHASE.load(Ordering::SeqCst) != 3 {
            core::hint::spin_loop();
        }

        if c_sigsetjmp(core::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) == 0 {
            B_SPINNING.store(true, Ordering::SeqCst);
            let val = core::ptr::read_volatile(TEST_PAGE);
            if val != 123 {
                B_STALE_FAULT.store(true, Ordering::SeqCst);
            }
        }
        B_SPINNING.store(false, Ordering::SeqCst);
    }
    core::ptr::null_mut()
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = segv_handler as *const () as usize;
        sa.sa_flags = libc::SA_NODEFER | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        let action_ok = libc::sigaction(libc::SIGSEGV, &sa, core::ptr::null_mut()) == 0;
        if !action_ok {
            libc::_exit(1);
        }

        // --- Phase 1: mprotect PROT_NONE ---
        let page1 = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page1 == libc::MAP_FAILED {
            libc::_exit(2);
        }
        core::ptr::write_volatile(page1.cast::<u8>(), 42);
        TEST_PAGE = page1.cast();

        let mut thread: libc::pthread_t = std::mem::zeroed();
        if libc::pthread_create(&mut thread, core::ptr::null(), worker_thread, core::ptr::null_mut()) != 0 {
            libc::_exit(3);
        }

        // Signal Phase 1
        PHASE.store(1, Ordering::SeqCst);
        while !B_SPINNING.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        // Busy spin briefly so Thread B is actively reading the page
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }

        // Thread A mprotects page to PROT_NONE
        if libc::mprotect(page1, 4096, libc::PROT_NONE) != 0 {
            libc::_exit(4);
        }

        // Wait for Thread B to exit its spin loop (via SIGSEGV jump)
        let mut spin_wait = 0;
        while B_SPINNING.load(Ordering::SeqCst) && spin_wait < 100_000_000 {
            core::hint::spin_loop();
            spin_wait += 1;
        }
        let mprotect_observed = B_OBSERVED_CHANGE.load(Ordering::SeqCst);
        libc::munmap(page1, 4096);

        // --- Phase 2: munmap ---
        B_OBSERVED_CHANGE.store(false, Ordering::SeqCst);
        let page2 = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page2 == libc::MAP_FAILED {
            libc::_exit(5);
        }
        core::ptr::write_volatile(page2.cast::<u8>(), 84);
        TEST_PAGE = page2.cast();

        PHASE.store(2, Ordering::SeqCst);
        while !B_SPINNING.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }

        // Thread A munmaps page2
        if libc::munmap(page2, 4096) != 0 {
            libc::_exit(6);
        }

        let mut spin_wait2 = 0;
        while B_SPINNING.load(Ordering::SeqCst) && spin_wait2 < 100_000_000 {
            core::hint::spin_loop();
            spin_wait2 += 1;
        }
        let munmap_observed = B_OBSERVED_CHANGE.load(Ordering::SeqCst);

        // --- Phase 3: stale translation check ---
        let page3 = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page3 == libc::MAP_FAILED {
            libc::_exit(7);
        }
        if libc::mprotect(page3, 4096, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            libc::_exit(8);
        }
        core::ptr::write_volatile(page3.cast::<u8>(), 123);
        TEST_PAGE = page3.cast();

        PHASE.store(3, Ordering::SeqCst);
        while !B_SPINNING.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        libc::pthread_join(thread, core::ptr::null_mut());
        let stale_fault = B_STALE_FAULT.load(Ordering::SeqCst);
        libc::munmap(page3, 4096);

        report!(
            broadcast_mprotect_observed = mprotect_observed,
            broadcast_munmap_observed = munmap_observed,
            no_stale_fault = !stale_fault,
        );
    }
}
