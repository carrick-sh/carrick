//! Fork churn that exercises the atomic vCPU-permit release paths.
//!
//! Each round forks N children; the parent reaps all N before the next round;
//! repeat M rounds. Every child is a fresh guest vCPU that acquires a vCPU-
//! admission permit at VM/vCPU create and must release it when it's done.
//! Under `CARRICK_HVF_ATOMIC_PERMIT=1` the child's cooperative
//! `process_exit_cleanup` frees its permit slot on its own thread BEFORE
//! `_exit`, so the shared slot table returns to baseline promptly instead of
//! lingering at budget until the root reaper backstop sweeps it (the churn
//! window that timed out the node suites in 3b). The occupancy assertion
//! itself lives in the host-side unit tests (`cooperative_release_*` /
//! `execve_rebuild_*` in `carrick-vmm-hvf::trap`), which can read the
//! in-process slot table directly; this probe is the reproducible WORKLOAD
//! for the gate (Task 5) and produces a deterministic line-diff against Linux.
//!
//! Two child modes, selected by `EXECPERMITCHURN_MODE` (default "exit"):
//!   - "exit": the child `_exit(0)`s immediately (Task 3 — cooperative
//!     release on fork-child exit).
//!   - "execve": the child re-`execve`s itself (self-path, with a marker arg,
//!     so the probe never depends on a `/bin/true` existing in whatever
//!     minimal rootfs it runs against) before exiting. This drives
//!     `execve_rebuild`'s teardown of the inherited pre-exec vCPU (Task 4):
//!     the destroyed vCPU's permit must release through the ordinary
//!     `vcpu_destroyed` path, and the exec'd replacement (which takes the
//!     marker branch below and exits at once) must NOT acquire a NEW permit,
//!     since `ExecveRebuild` is ungated.

use conformance_probes::report;
use std::ffi::CString;

const ROUNDS: i32 = 8;
const CHILDREN_PER_ROUND: i32 = 6;
const EXECVE_MARKER: &str = "child-execve-exit";

/// Re-exec this same binary (via the `argv[0]` we were invoked with — always
/// present, unlike an assumed `/bin/true` in a minimal rootfs) with a marker
/// arg, then exit 0 without forking again. Only reached in "execve" mode.
fn execve_self_then_exit(argv0: &str) -> ! {
    unsafe {
        let path = CString::new(argv0).expect("argv[0]");
        let marker = CString::new(EXECVE_MARKER).expect("marker");
        let argv: [*const libc::c_char; 3] = [path.as_ptr(), marker.as_ptr(), core::ptr::null()];
        let envp: [*const libc::c_char; 1] = [core::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        // Only reached if execve itself failed; still exit so the round's
        // waitpid doesn't hang.
        libc::_exit(9);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(EXECVE_MARKER) {
        // We ARE the exec'd replacement image: exit immediately.
        unsafe { libc::_exit(0) };
    }
    let argv0 = args
        .first()
        .cloned()
        .unwrap_or_else(|| "/proc/self/exe".to_string());

    let execve_mode = std::env::var("EXECPERMITCHURN_MODE").ok().as_deref() == Some("execve");

    unsafe {
        let mut forked_all = true;
        let mut reaped_all = true;
        let mut all_exit_zero = true;

        for _round in 0..ROUNDS {
            let mut kids = [0i32; CHILDREN_PER_ROUND as usize];
            for kid in kids.iter_mut() {
                match libc::fork() {
                    -1 => {
                        forked_all = false;
                        *kid = -1;
                    }
                    0 => {
                        if execve_mode {
                            execve_self_then_exit(&argv0);
                        }
                        // Fresh guest child: acquired a permit at VM/vCPU
                        // create; exit at once so the cooperative release
                        // path runs.
                        libc::_exit(0);
                    }
                    pid => {
                        *kid = pid;
                    }
                }
            }

            for &pid in kids.iter() {
                if pid <= 0 {
                    continue;
                }
                let mut status: libc::c_int = 0;
                if libc::waitpid(pid, &mut status, 0) != pid {
                    reaped_all = false;
                    continue;
                }
                if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                    all_exit_zero = false;
                }
            }
        }

        report!(
            mode = if execve_mode { "execve" } else { "exit" },
            forked_all = forked_all,
            reaped_all = reaped_all,
            all_exit_zero = all_exit_zero,
        );
    }
}
