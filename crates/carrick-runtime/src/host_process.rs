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

    #[test]
    fn runtime_host_process_creation_inventory_is_exact_and_shrinking() {
        use std::collections::BTreeMap;
        use std::path::{Path, PathBuf};

        fn visit_rs_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(current).expect("read runtime source directory") {
                let path = entry.expect("runtime source entry").path();
                if path.is_dir() {
                    visit_rs_files(root, &path, files);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    files.push(
                        path.strip_prefix(root)
                            .expect("relative source path")
                            .to_owned(),
                    );
                }
            }
        }

        let expected: BTreeMap<&str, [usize; 3]> = BTreeMap::from([
            // NOT rows any more: `fs_backend/tests.rs` left this crate with the
            // filesystem model (carrick-vfs), and eight more rows
            // (`dispatch/ioring.rs`, `dispatch/mem/tests.rs`,
            // `dispatch/sysv.rs`, `dispatch/tests.rs`, `exec_stamps.rs`,
            // `kernel/continuation/tests.rs`, `network/socket_namespace.rs`,
            // `run_state.rs`) left it with the kernel (carrick-kernel). This
            // inventory scans `CARGO_MANIFEST_DIR/src`, so they are out of
            // SCOPE here, not retired: every one of them is still gated, by
            // `scripts/migrate/check-carrier-only-process-invariant.py` in
            // `just lint-domains`, whose scan roots follow the code.
            // The cfg(test) nonce-exhaustion witness self-spawns its exact
            // ignored child to isolate a process-global SIGABRT. It bounds
            // and reaps that child; committed retirement creates no host
            // process in production.
            ("hvpatch/stage1_mm.rs", [0, 0, 1]),
            // `carrier::tests::isolated_fixture_process` self-spawns the exact
            // carrier unit test in its own process, because the VM lifecycle
            // window and preemption driver are process-global host state
            // (#504). It bounds and reaps that child; it is test isolation,
            // not production host-process-per-guest architecture.
            ("carrier.rs", [0, 0, 1]),
            // The census policy test self-spawns only its exact unit test to
            // isolate its environment and OnceLock. Each child is bounded and
            // reaped; production census publication creates no host process.
            ("el1_census.rs", [0, 0, 1]),
            // This unit test self-spawns to isolate a process-global abort
            // boundary while proving pending exec error preservation. It is
            // not production host-process-per-guest architecture.
            ("vcpu_loop/exec.rs", [0, 0, 1]),
            // Task 7's budget-one proof self-spawns this exact unit test in an
            // isolated process so it can install the process-global vCPU
            // scheduler before any sibling test initializes the OnceLock. The
            // test moved with the carrier foreign-COW projection tests from
            // `kernel/mm_access.rs` (Task 2.2 of the crate extraction).
            ("vcpu_loop/memory.rs", [0, 0, 1]),
            // Both are unit tests that fork a child to BE the tracee, because
            // a ptrace stop needs a real host parent/child pair:
            // 1. `ptrace_signal_stop_queued_host_sigkill_remains_terminal`
            // 2. `synchronous_fault_stops_for_ptrace_before_default_termination`
            // (added by `ac13739db` without moving this row). Neither is a
            // production host-process creation, which is what this inventory
            // is shrinking toward zero.
            ("vcpu_loop/signal.rs", [2, 0, 0]),
            // `wedge_capture.rs` carries the one reviewed OPERATOR BOUNDARY
            // (`sudo -n lldb`) but is NOT a row here: it lives beside the
            // deadlock watchdog it serves, in `carrick-kernel`, so this
            // carrier-crate scan never sees it. Its limit is stated in
            // `scripts/migrate/check-carrier-only-process-invariant.py`, which
            // scans the whole workspace.
        ]);
        let patterns = [
            ["unsafe { libc::", "fork()"].concat(),
            ["libc::posix_", "spawn("].concat(),
            ["Command", "::new("].concat(),
        ];
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        visit_rs_files(&source_root, &source_root, &mut files);
        let mut observed = BTreeMap::new();
        for relative in files {
            let source = std::fs::read_to_string(source_root.join(&relative))
                .expect("read runtime source file");
            let counts = patterns
                .each_ref()
                .map(|pattern| source.matches(pattern).count());
            if counts != [0, 0, 0] {
                observed.insert(relative.to_string_lossy().into_owned(), counts);
            }
        }
        let expected: BTreeMap<String, [usize; 3]> = expected
            .into_iter()
            .map(|(path, counts)| (path.to_owned(), counts))
            .collect();
        assert_eq!(
            observed, expected,
            "runtime host-process creation changed; classify the exact call as a test, explicit operator boundary, or retirement regression before updating this shrinking inventory"
        );
    }
}
