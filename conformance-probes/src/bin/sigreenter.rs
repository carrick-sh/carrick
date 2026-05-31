//! SA_NODEFER on an alternate signal stack: a handler installed with
//! SA_NODEFER|SA_ONSTACK that re-raises its own signal must re-enter
//! SYNCHRONOUSLY (the signal is NOT auto-blocked), and the NESTED sigframe must
//! land at a DIFFERENT, lower address on the alt stack (continuing down from the
//! live frame, not reset to the top — which would clobber the parent frame and
//! trip glibc's stack canary). This is exactly how CPython faulthandler's
//! `chain=True` re-raises the previously-installed handler.
//!
//! Two carrick bugs this guards:
//!   1. enter_signal_handler always blocked the delivered signal, ignoring
//!      SA_NODEFER → the re-raise was deferred and re-entered the SAME handler
//!      after it returned (infinite loop).
//!   2. signal_frame_stack_pointer always pushed from the alt-stack TOP, so the
//!      nested frame overlapped the parent → "stack smashing detected".
//! Deterministic booleans, line-exact vs Linux.

use conformance_probes::report;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

static DEPTH: AtomicUsize = AtomicUsize::new(0);
static MAX_DEPTH: AtomicUsize = AtomicUsize::new(0);
static REENTERED: AtomicI32 = AtomicI32::new(0);
// Approximate SP at each nesting level, captured inside the handler so we can
// prove the nested frame is at a distinct (lower) address.
static SP_OUTER: AtomicUsize = AtomicUsize::new(0);
static SP_INNER: AtomicUsize = AtomicUsize::new(0);

extern "C" fn handler(_sig: i32) {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    MAX_DEPTH.fetch_max(depth, Ordering::SeqCst);
    let local = 0u8;
    let sp = &local as *const u8 as usize;
    if depth == 1 {
        SP_OUTER.store(sp, Ordering::SeqCst);
        // Re-raise: with SA_NODEFER this re-enters the handler synchronously,
        // here and now (depth 2), before this store completes.
        REENTERED.store(1, Ordering::SeqCst);
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
    } else {
        SP_INNER.store(sp, Ordering::SeqCst);
    }
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        // Alternate signal stack (faulthandler installs SA_ONSTACK handlers).
        let mut stack = vec![0u8; libc::SIGSTKSZ];
        let ss = libc::stack_t {
            ss_sp: stack.as_mut_ptr() as *mut libc::c_void,
            ss_flags: 0,
            ss_size: stack.len(),
        };
        let altstack_ok = libc::sigaltstack(&ss, core::ptr::null_mut()) == 0;

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_NODEFER | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        let install_ok = libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut()) == 0;

        libc::raise(libc::SIGUSR1);

        let sp_outer = SP_OUTER.load(Ordering::SeqCst);
        let sp_inner = SP_INNER.load(Ordering::SeqCst);

        report!(
            altstack_ok = altstack_ok,
            install_ok = install_ok,
            // SA_NODEFER let the re-raise re-enter synchronously to depth 2.
            reentered = REENTERED.load(Ordering::SeqCst) == 1,
            max_depth_is_2 = MAX_DEPTH.load(Ordering::SeqCst) == 2,
            // Nested frame is at a strictly LOWER address than the outer one
            // (pushed down the same alt stack, not reset to the top).
            nested_frame_below_outer = sp_outer != 0 && sp_inner != 0 && sp_inner < sp_outer,
            // Both handler invocations unwound cleanly back to depth 0.
            unwound_clean = DEPTH.load(Ordering::SeqCst) == 0,
        );
    }
}
