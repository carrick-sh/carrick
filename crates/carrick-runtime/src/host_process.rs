//! Process-wide host initialization required before running any Carrick guest.

use std::sync::Once;

static PREPARE_ONCE: Once = Once::new();

/// Perform idempotent, process-wide host environment setup.
///
/// This configures:
/// 1. Internal host fd range (`RLIMIT_NOFILE` raise + `fdtable` pre-expansion to
///    `HOST_INTERNAL_FD_MIN`) while the process is still single-threaded
///    (`files->count == 1`), before `block_on_oci` (`tokio::fs` worker pool) or
///    `HostFsBackend` (`carrick-fs-cleanup`) spawns any thread.
/// 2. `SIGPIPE` ignored: guest pipe writes to closed ends return `EPIPE` rather than
///    killing the host process.
/// 3. `proctitle_init`: relocates `environ` onto the heap so the argv/env stack bytes
///    form a contiguous buffer for process renaming.
/// 4. `OS_ACTIVITY_MODE=disable`: disables Apple os_log activity tracing before any
///    HVF call, avoiding fork-safety crashes in `hv_vcpu_create`.
pub fn prepare() {
    PREPARE_ONCE.call_once(|| {
        carrick_host::internal_fd::ensure_internal_fd_range();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_is_idempotent() {
        prepare();
        prepare();
        assert!(
            carrick_host::internal_fd::is_internal_fd_range_ensured(),
            "host_process::prepare must pre-expand the internal fd range before any tokio or carrier threads spawn"
        );
    }
}
