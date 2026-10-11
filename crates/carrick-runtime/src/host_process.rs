//! Process-wide host initialization required before running any Carrick guest.

use std::sync::Once;

static PREPARE_ONCE: Once = Once::new();

/// Perform idempotent, process-wide host environment setup.
///
/// This configures:
/// 1. `SIGPIPE` ignored: guest pipe writes to closed ends return `EPIPE` rather than
///    killing the host process.
/// 2. `proctitle_init`: relocates `environ` onto the heap so the argv/env stack bytes
///    form a contiguous buffer for process renaming.
/// 3. `OS_ACTIVITY_MODE=disable`: disables Apple os_log activity tracing before any
///    HVF call, avoiding fork-safety crashes in `hv_vcpu_create`.
pub fn prepare() {
    PREPARE_ONCE.call_once(|| {
        arm_fatal_debugger_hold_from_env();
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        carrick_kernel::dispatch::proctitle_init();

        unsafe {
            let key = c"OS_ACTIVITY_MODE";
            let val = c"disable";
            libc::setenv(key.as_ptr(), val.as_ptr(), 1);
        }
    });
}

/// `CARRICK_FATAL_HOLD_SECS=<n>`: keep the carrier alive `n` seconds on a
/// `carrick_fatal!` so `sudo lldb -p <pid>` can save a core of the failing
/// graph (`carrick debug lldb-run` only attaches at its deadline). Diagnostic
/// only; unset or `0` leaves the fatal path unchanged.
pub fn arm_fatal_debugger_hold_from_env() {
    if let Ok(value) = std::env::var("CARRICK_FATAL_HOLD_SECS")
        && let Ok(secs) = value.trim().parse::<u32>()
        && secs > 0
    {
        carrick_fatal::arm_debugger_hold(secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_is_idempotent() {
        prepare();
        prepare();
    }
}
