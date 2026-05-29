//! fchmod(2) on a directory fd persists the mode so a subsequent fstat on the
//! SAME fd reflects it (LTP fchmod04/05). carrick reported the cached open-time
//! mode for Directory fds (only HostFile fstat re-read the live xattr), so an
//! fchmod(dirfd)+fstat(dirfd) saw the stale mode. Runs privileged (root in
//! docker / guest-root under run-elf) so the setgid bit is preserved.
//! Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let dir = b"/tmp/fchmod_d\0".as_ptr() as *const libc::c_char;
        libc::mkdir(dir, 0o755);
        let fd = libc::open(dir, libc::O_RDONLY | libc::O_DIRECTORY);

        let check = |label: &str, perms: libc::mode_t| {
            let rc = libc::fchmod(fd, perms);
            let mut st: libc::stat = std::mem::zeroed();
            let s = libc::fstat(fd, &mut st);
            println!(
                "{}={}",
                label,
                rc == 0 && s == 0 && (st.st_mode & 0o7777) == perms as u32
            );
        };

        check("fchmod_sticky_1777", 0o1777);
        check("fchmod_plain_0750", 0o750);
        check("fchmod_setgid_2755", 0o2755);

        libc::close(fd);
        let _ = errno;
    }
}
