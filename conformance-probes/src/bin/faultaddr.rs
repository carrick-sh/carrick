//! SIGSEGV fault-address conformance: on a synchronous memory fault the kernel
//! delivers BOTH `siginfo.si_addr` AND `ucontext.uc_mcontext.fault_address`
//! (aarch64 `struct sigcontext`, first field) = the faulting VA. Go's runtime
//! reads `fault_address`; glibc/CPython read `si_addr`. carrick used to leave
//! both stale/zero on the direct EL0-abort path, so every guest SIGSEGV looked
//! like a nil deref at the wrong PC. This probe faults on a FIXED unmapped
//! address and checks both fields match it — deterministic across carrick/docker.

use std::sync::atomic::{AtomicU64, Ordering};

const BAD_ADDR: usize = 0x4000; // page-aligned, unmapped, deterministic

static SI_ADDR: AtomicU64 = AtomicU64::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);

// aarch64 struct sigcontext: { u64 fault_address; u64 regs[31]; u64 sp; u64 pc; ... }
#[repr(C)]
struct Aarch64SigContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    // __reserved[...] follows; we only need the head.
}

extern "C" fn handler(_sig: i32, info: *mut libc::siginfo_t, ucontext: *mut libc::c_void) {
    // si_addr lives at a fixed offset in siginfo_t; libc exposes it via si_addr().
    unsafe {
        let addr = (*info).si_addr() as u64;
        SI_ADDR.store(addr, Ordering::SeqCst);
        // ucontext_t -> uc_mcontext (struct sigcontext) -> fault_address.
        let uc = ucontext as *const libc::ucontext_t;
        let mc = &(*uc).uc_mcontext as *const _ as *const Aarch64SigContext;
        FAULT_ADDR.store((*mc).fault_address, Ordering::SeqCst);
    }
    // Can't return (would re-fault); exit deterministically from the handler.
    let si = SI_ADDR.load(Ordering::SeqCst);
    let fa = FAULT_ADDR.load(Ordering::SeqCst);
    println!("si_addr_match={}", si == BAD_ADDR as u64);
    println!("fault_addr_match={}", fa == BAD_ADDR as u64);
    println!("DONE");
    unsafe { libc::_exit(0) };
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            println!("sigaction FAIL");
            return;
        }
    }
    // Force a read fault at the fixed address (volatile so it isn't elided).
    let p = BAD_ADDR as *const u64;
    let v = unsafe { std::ptr::read_volatile(p) };
    // Unreachable on a faulting platform; keep the read live.
    println!("NOFAULT v={v}");
}
