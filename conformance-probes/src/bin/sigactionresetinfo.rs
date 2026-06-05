//! Linux keeps SA_SIGINFO visible when an SA_RESETHAND handler has reset the
//! disposition to SIG_DFL on entry. LTP sigaction01 case 1 checks this by
//! calling sigaction(SIGUSR1, NULL, &old) from inside the handler.
//!
//! Carrick previously removed the handler entry entirely on SA_RESETHAND entry,
//! so an in-handler sigaction query reported empty flags and lost SA_SIGINFO.

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, Ordering};

const SA_RESETHAND: i32 = 0x8000_0000_u32 as i32;

static HANDLER_RAN: AtomicBool = AtomicBool::new(false);
static QUERY_OK: AtomicBool = AtomicBool::new(false);
static QUERY_RETAINED_SIGINFO: AtomicBool = AtomicBool::new(false);
static INFO_NONNULL: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
    INFO_NONNULL.store(!info.is_null(), Ordering::SeqCst);

    unsafe {
        let mut cur: libc::sigaction = std::mem::zeroed();
        let rc = libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut cur);
        QUERY_OK.store(rc == 0, Ordering::SeqCst);
        QUERY_RETAINED_SIGINFO.store(cur.sa_flags & libc::SA_SIGINFO != 0, Ordering::SeqCst);
    }
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as *const () as usize;
        sa.sa_flags = SA_RESETHAND | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        let install_ok = libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) == 0;

        let kill_ok = libc::kill(libc::getpid(), libc::SIGUSR1) == 0;

        let mut after: libc::sigaction = std::mem::zeroed();
        let after_query_ok = libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut after) == 0;

        report!(
            install_ok = install_ok,
            self_signal_ok = kill_ok,
            handler_ran = HANDLER_RAN.load(Ordering::SeqCst),
            handler_siginfo_nonnull = INFO_NONNULL.load(Ordering::SeqCst),
            handler_query_ok = QUERY_OK.load(Ordering::SeqCst),
            handler_query_retained_siginfo = QUERY_RETAINED_SIGINFO.load(Ordering::SeqCst),
            disposition_reset_to_dfl =
                after_query_ok && after.sa_sigaction == libc::SIG_DFL,
        );
    }
}
