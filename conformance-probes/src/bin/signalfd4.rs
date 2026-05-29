//! signalfd4 (syscall 74) flag handling: SFD_CLOEXEC (== O_CLOEXEC) sets
//! FD_CLOEXEC on the returned fd; SFD_NONBLOCK (== O_NONBLOCK) sets O_NONBLOCK;
//! an unknown flag bit → EINVAL. macOS has no signalfd, so carrick emulates the
//! fd; these are pure fd-flag checks (no signals are read), matching LTP
//! signalfd4_01 / signalfd4_02 exactly. Deterministic booleans, diffed
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;

const SYS_SIGNALFD4: libc::c_long = 74;

fn main() {
    unsafe {
        let mask: u64 = 0; // zeroed sigset; the tests only check fd flags
        let sz: libc::c_long = 8; // kernel sigset_t ABI size

        // SFD_CLOEXEC → FD_CLOEXEC on the returned fd.
        let fd_ce = libc::syscall(
            SYS_SIGNALFD4,
            -1i64,
            &mask as *const u64,
            sz,
            libc::O_CLOEXEC as libc::c_long,
        ) as i32;
        let cloexec_set = fd_ce >= 0 && {
            let f = libc::fcntl(fd_ce, libc::F_GETFD);
            f >= 0 && (f & libc::FD_CLOEXEC) != 0
        };
        println!("signalfd4_created={}", fd_ce >= 0);
        println!("signalfd4_cloexec={}", cloexec_set);
        if fd_ce >= 0 {
            libc::close(fd_ce);
        }

        // SFD_NONBLOCK → O_NONBLOCK on the returned fd.
        let fd_nb = libc::syscall(
            SYS_SIGNALFD4,
            -1i64,
            &mask as *const u64,
            sz,
            libc::O_NONBLOCK as libc::c_long,
        ) as i32;
        let nonblock_set = fd_nb >= 0 && {
            let f = libc::fcntl(fd_nb, libc::F_GETFL);
            f >= 0 && (f & libc::O_NONBLOCK) != 0
        };
        println!("signalfd4_nonblock={}", nonblock_set);
        if fd_nb >= 0 {
            libc::close(fd_nb);
        }

        // An unknown flag bit → EINVAL.
        let bad = libc::syscall(SYS_SIGNALFD4, -1i64, &mask as *const u64, sz, 0x4000i64) as i32;
        println!(
            "signalfd4_bad_flag_einval={}",
            bad == -1 && errno() == libc::EINVAL
        );
    }
}
