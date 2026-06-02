//! `SA_RESETHAND` one-shot handler semantics (audit H6): the disposition resets
//! to SIG_DFL before the handler runs, so the handler fires exactly once and a
//! second occurrence takes the default action. carrick previously stored the
//! flag but never honored it (the handler re-entered forever).
//!
//! Uses SIGURG (default action: IGNORE) so the second delivery is safe to
//! observe without terminating the probe.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - After installing an SA_RESETHAND handler and raising once, the handler
//!     ran (count == 1).
//!   - The disposition is now SIG_DFL (sigaction reports the default).
//!   - Raising a second time does NOT re-run the handler (count stays 1).

use conformance_probes::{current_disposition, install_handler, report};
use std::sync::atomic::{AtomicUsize, Ordering};

const SA_RESETHAND: i32 = 0x8000_0000_u32 as i32;
static COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_sigurg(_sig: i32) {
    COUNT.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        report!(install_ok = install_handler(libc::SIGURG, on_sigurg, SA_RESETHAND));

        // First raise: the one-shot handler runs.
        libc::raise(libc::SIGURG);
        report!(handler_ran_once = COUNT.load(Ordering::SeqCst) == 1);

        // Disposition was reset to SIG_DFL on entry.
        report!(disposition_reset_to_dfl = current_disposition(libc::SIGURG) == libc::SIG_DFL);

        // Second raise: default action (ignore) — the handler does NOT re-run.
        libc::raise(libc::SIGURG);
        report!(handler_not_rerun = COUNT.load(Ordering::SeqCst) == 1);
    }
}
