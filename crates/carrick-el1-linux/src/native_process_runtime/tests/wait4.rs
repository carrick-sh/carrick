//! Native wait4 bindings for kernel.wait.child-rusage.
use super::{LinuxWaitOptions, UserVa, compact_root_fork_wait_with_outputs};

#[test]
fn native_wait4_untraced_continued_reaps_child() {
    compact_root_fork_wait_with_outputs(
        (false, false, false, false, None, false),
        (
            LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED,
            UserVa::new(0),
        ),
    );
}
#[test]
fn native_wait4_nonnull_rusage_reaps_child() {
    compact_root_fork_wait_with_outputs(
        (false, false, false, false, None, false),
        (LinuxWaitOptions::empty(), UserVa::new(0x9000)),
    );
}
#[test]
fn native_wait4_rusage_fault_consumes_child_after_status() {
    compact_root_fork_wait_with_outputs(
        (false, false, false, false, None, false),
        (LinuxWaitOptions::empty(), UserVa::new(1)),
    );
}
