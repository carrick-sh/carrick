//! Bounded admission and descriptor-lifetime checks for Linux /dev/tty0.
//!
//! The native oracle must expose the Linux VM's /dev/tty0 device explicitly.
//! This probe only reads terminal state; it never writes console data or changes
//! settings. All error values are numeric observations, not guessed semantics.

use conformance_probes::{errno, report};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelTermios {
    input: u32,
    output: u32,
    control: u32,
    local: u32,
    line: u8,
    cc: [u8; 19],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelTermio {
    input: u16,
    output: u16,
    control: u16,
    local: u16,
    line: u8,
    cc: [u8; 8],
}

fn observed_errno(rc: i64) -> i32 {
    if rc < 0 {
        errno()
    } else {
        0
    }
}

fn main() {
    unsafe {
        let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let first = libc::open(b"/dev/tty0\0".as_ptr().cast(), flags);
        let first_errno = observed_errno(first as i64);
        let second = libc::open(b"/dev/tty0\0".as_ptr().cast(), flags);
        let second_errno = observed_errno(second as i64);
        let duplicate = libc::dup(first);
        let duplicate_errno = observed_errno(duplicate as i64);

        let mut stat: libc::stat = std::mem::zeroed();
        let stat_rc = libc::fstat(first, &mut stat);
        let stat_errno = observed_errno(stat_rc as i64);
        let is_character = stat_rc == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFCHR;
        let rdev_major = if stat_rc == 0 {
            libc::major(stat.st_rdev) as i64
        } else {
            -1
        };
        let rdev_minor = if stat_rc == 0 {
            libc::minor(stat.st_rdev) as i64
        } else {
            -1
        };

        let mut modern = KernelTermios::default();
        let get_rc = libc::ioctl(first, 0x5401u32 as _, &mut modern);
        let get_errno = observed_errno(get_rc as i64);
        let mut legacy = KernelTermio::default();
        let legacy_rc = libc::ioctl(second, 0x5405u32 as _, &mut legacy);
        let legacy_errno = observed_errno(legacy_rc as i64);
        let legacy_agrees = get_rc == 0
            && legacy_rc == 0
            && legacy.input == modern.input as u16
            && legacy.output == modern.output as u16
            && legacy.control == modern.control as u16
            && legacy.local == modern.local as u16
            && legacy.line == modern.line
            && legacy.cc == modern.cc[..8];

        let invalid_rc = libc::ioctl(first, 0x5401u32 as _, std::ptr::null_mut::<u8>());
        let invalid_errno = observed_errno(invalid_rc as i64);
        let unknown_rc = libc::ioctl(first, 0xdead_beefu32 as _, 0);
        let unknown_errno = observed_errno(unknown_rc as i64);
        let close_first = if first >= 0 { libc::close(first) } else { -1 };
        let mut after_close = KernelTermios::default();
        let duplicate_get = libc::ioctl(duplicate, 0x5401u32 as _, &mut after_close);
        let duplicate_get_errno = observed_errno(duplicate_get as i64);
        let duplicate_state_retained = get_rc == 0
            && duplicate_get == 0
            && after_close.input == modern.input
            && after_close.output == modern.output
            && after_close.control == modern.control
            && after_close.local == modern.local
            && after_close.line == modern.line
            && after_close.cc == modern.cc;
        let close_duplicate = if duplicate >= 0 {
            libc::close(duplicate)
        } else {
            -1
        };
        let close_second = if second >= 0 { libc::close(second) } else { -1 };

        report!(
            tty0_opened = first >= 0,
            tty0_open_errno = first_errno,
            tty0_second_opened = second >= 0,
            tty0_second_open_errno = second_errno,
            tty0_dup_succeeded = duplicate >= 0,
            tty0_dup_errno = duplicate_errno,
            tty0_fstat_rc = stat_rc,
            tty0_fstat_errno = stat_errno,
            tty0_is_character = is_character,
            tty0_rdev_major = rdev_major,
            tty0_rdev_minor = rdev_minor,
            tty0_tcgets_rc = get_rc,
            tty0_tcgets_errno = get_errno,
            tty0_tcgeta_rc = legacy_rc,
            tty0_tcgeta_errno = legacy_errno,
            tty0_termio_matches_termios = legacy_agrees,
            tty0_bad_pointer_rc = invalid_rc,
            tty0_bad_pointer_errno = invalid_errno,
            tty0_unknown_request_rc = unknown_rc,
            tty0_unknown_request_errno = unknown_errno,
            tty0_close_first_rc = close_first,
            tty0_dup_tcgets_after_close_rc = duplicate_get,
            tty0_dup_tcgets_after_close_errno = duplicate_get_errno,
            tty0_dup_state_retained = duplicate_state_retained,
            tty0_close_duplicate_rc = close_duplicate,
            tty0_close_second_rc = close_second,
        );
    }
}
