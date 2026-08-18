//! userfaultfd(2) container-policy probe. In the differential oracle (Docker's
//! default seccomp profile, no CAP_SYS_PTRACE) userfaultfd is denied with
//! EPERM before the kernel ever sees it — regardless of flags, including
//! UFFD_USER_MODE_ONLY and even invalid flag bits (seccomp matches on the
//! syscall number alone). Carrick models the same container policy: its guest
//! runs with the Docker default capability set, which lacks CAP_SYS_PTRACE,
//! so LTP's userfaultfd01/02/06 TCONF identically on both sides.
//!
//! Deterministic: prints errno numbers only.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    const UFFD_USER_MODE_ONLY: libc::c_ulong = 1;
    unsafe {
        let r = libc::syscall(libc::SYS_userfaultfd, 0 as libc::c_ulong);
        println!("uffd_plain_errno={}", if r == -1 { errno() } else { 0 });

        let r = libc::syscall(libc::SYS_userfaultfd, UFFD_USER_MODE_ONLY);
        println!("uffd_usermode_errno={}", if r == -1 { errno() } else { 0 });

        // An invalid flag word is still EPERM under the container policy (the
        // seccomp deny fires before flag validation could return EINVAL).
        let r = libc::syscall(libc::SYS_userfaultfd, 0xdead_0000u64 as libc::c_ulong);
        println!("uffd_badflags_errno={}", if r == -1 { errno() } else { 0 });
    }
}
