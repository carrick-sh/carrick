// Probe E — synchronous fault -> guest signal. Installs a SIGSEGV SA_SIGINFO
// handler, dereferences a nil pointer, and in the handler records si_addr and
// advances the interrupted PC past the faulting instruction so execution
// resumes. This is the Go nil-deref->panic->recover idiom in miniature.
//
// Real Linux delivers SIGSEGV with si_addr=0 to the handler; the handler skips
// the faulting store and main prints SEGV_OK. carrick (before SP2a) instead
// kills the guest ("EL0 fault not handled by trap path"). Expected:
//   SEGV_OK si_addr=0x0   (Docker oracle, and carrick after the fix)
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static GOT_SIGNAL: AtomicUsize = AtomicUsize::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0xdead);

#[cfg(target_arch = "aarch64")]
extern "C" fn on_segv(_sig: i32, info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    unsafe {
        // si_addr (the faulting address) lives in _sifields._sigfault at
        // offset 16 in linux/aarch64 siginfo_t (si_signo/errno/code = 12, the
        // union is 8-aligned at 16).
        let addr = *((info as *const u8).add(16) as *const u64);
        FAULT_ADDR.store(addr, Ordering::SeqCst);
        GOT_SIGNAL.fetch_add(1, Ordering::SeqCst);
        // Advance the interrupted PC past the faulting instruction (4 bytes on
        // aarch64) so we don't re-fault on return. uc_mcontext.pc on
        // linux/aarch64.
        let ctx = &mut *(uc as *mut libc::ucontext_t);
        ctx.uc_mcontext.pc = ctx.uc_mcontext.pc.wrapping_add(4);
    }
}

fn install() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_segv as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()),
            0,
            "sigaction(SIGSEGV) failed"
        );
    }
}

fn main() {
    install();
    // Nil dereference: a volatile store to address 0. The handler skips it.
    let p = std::ptr::null_mut::<u64>();
    unsafe {
        std::ptr::write_volatile(p, 0x1234);
    }
    // If we reach here, the handler ran and skipped the faulting store.
    if GOT_SIGNAL.load(Ordering::SeqCst) >= 1 {
        println!("SEGV_OK si_addr=0x{:x}", FAULT_ADDR.load(Ordering::SeqCst));
    } else {
        println!("SEGV_MISSED");
        std::process::exit(1);
    }
}
