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
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        crate::dispatch::proctitle_init();

        unsafe {
            let key = c"OS_ACTIVITY_MODE";
            let val = c"disable";
            libc::setenv(key.as_ptr(), val.as_ptr(), 1);
        }
    });
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
