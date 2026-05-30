//! Main-thread C-stack / recursion-guard sizing probe.
//!
//! CPython (and any runtime that calibrates its C-recursion guard from the
//! main-thread stack size) needs the guest main stack to match Linux's 8 MiB
//! default RLIMIT_STACK so the guard fires (RecursionError) before the real C
//! stack overflows. carrick previously gave the guest a 2 MiB stack AND reported
//! a 2 MiB RLIMIT_STACK, so deep C recursion overflowed and took a translation
//! fault (SIGSEGV) where Linux raises a catchable error.
//!
//! This probe is run as the SAME static binary under carrick and real Linux and
//! the boolean lines are diffed. On real Linux:
//!   * RLIMIT_STACK soft == 8 MiB, max == unlimited (RLIM_INFINITY);
//!   * pthread_getattr_np reports the main-thread stack size as 8 MiB (within
//!     one page — glibc reserves a guard page), i.e. >= ~8 MiB and < 16 MiB;
//!   * a bounded C recursion that writes ~1 KiB of stack per frame for 4096
//!     frames (~4 MiB, comfortably inside an 8 MiB stack but a guaranteed fault
//!     on the old 2 MiB stack) completes without crashing.
//!
//! Deterministic: booleans only (no addresses, no timings).

use std::os::raw::c_int;

const MIB: u64 = 1024 * 1024;

#[inline(never)]
fn burn(depth: u32, acc: u64) -> u64 {
    // ~1 KiB of live stack per frame; `black_box` + the volatile read defeat
    // tail-call/elision so the frames really nest.
    let mut buf = [0u8; 1024];
    buf[0] = (depth & 0xff) as u8;
    buf[1023] = (acc & 0xff) as u8;
    let v = std::hint::black_box(&buf)[1023] as u64;
    if depth == 0 {
        acc.wrapping_add(v)
    } else {
        burn(depth - 1, acc.wrapping_add(v))
    }
}

fn main() {
    // 1) getrlimit(RLIMIT_STACK) — the value runtimes calibrate their guard to.
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_STACK, &mut rl) };
    let soft_8mib = rc == 0 && u64::from(rl.rlim_cur) == 8 * MIB;
    let max_unlimited = rc == 0 && rl.rlim_max == libc::RLIM_INFINITY;
    println!("rlimit_stack_soft_8mib={soft_8mib}");
    println!("rlimit_stack_max_unlimited={max_unlimited}");

    // 2) Main-thread stack size as glibc reports it (what CPython samples).
    let mut size_8mib_ish = false;
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) == 0 {
            let mut base: *mut libc::c_void = std::ptr::null_mut();
            let mut size: libc::size_t = 0;
            if libc::pthread_attr_getstack(&attr, &mut base, &mut size) == 0 {
                // >= 8 MiB minus one guard page, and < 16 MiB.
                let sz = size as u64;
                size_8mib_ish = sz >= (8 * MIB - 64 * 1024) && sz < 16 * MIB;
            }
            libc::pthread_attr_destroy(&mut attr);
        }
    }
    println!("main_stack_size_8mib={size_8mib_ish}");

    // 3) A ~4 MiB-deep C recursion completes (fits 8 MiB, would fault on 2 MiB).
    //    Run it in a child so a stack overflow shows up as a non-zero wait
    //    status rather than killing the probe before it can print.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = burn(4096, 0);
        // Keep the result observable so the whole recursion isn't optimized out.
        unsafe { libc::_exit((r & 0x7f) as c_int) };
    }
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    // Exited normally (not killed by SIGSEGV/SIGBUS) => the deep recursion fit.
    let recursion_fits_8mib = libc::WIFEXITED(status);
    println!("deep_c_recursion_fits={recursion_fits_8mib}");
}
