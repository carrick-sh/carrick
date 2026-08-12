//! umask follows Linux fs_struct sharing, not descriptor or credential identity.
//!
//! A pthread shares CLONE_FS and must publish its umask change to the main
//! thread. A subsequent ordinary fork copies fs_struct, so the child's change
//! must not flow back to its parent.

use conformance_probes::report;

fn main() {
    unsafe {
        let original = libc::umask(0o022);
        let thread = std::thread::spawn(|| libc::umask(0o077));
        let thread_set_from_022 = thread.join().is_ok_and(|previous| previous == 0o022);
        let shared_previous = libc::umask(0o022);

        let child = libc::fork();
        if child == 0 {
            let inherited = libc::umask(0o033);
            libc::_exit(if inherited == 0o022 { 0 } else { 125 });
        }
        let mut status = 0;
        while libc::waitpid(child, &mut status, 0) < 0 {
            if *libc::__errno_location() != libc::EINTR {
                break;
            }
        }
        let private_previous = libc::umask(original);

        report!(
            clone_fs_thread_change_visible = thread_set_from_022 && shared_previous == 0o077,
            fork_child_inherited_umask = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            fork_child_change_isolated = private_previous == 0o022,
        );
    }
}
