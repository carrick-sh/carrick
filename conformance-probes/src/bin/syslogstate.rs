//! Nonblocking syslog argument and credential semantics, qualified against Linux.
//! The harness grants SYSLOG; observations report numeric errno values.
use conformance_probes::errno;

fn syslog_errno(action: i32, buffer: *mut u8, length: i32) -> i32 {
    let result = unsafe { libc::syscall(libc::SYS_syslog, action, buffer, length) };
    if result < 0 { errno() } else { 0 }
}

fn main() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let effective = status.lines().find_map(|line| {
        line.strip_prefix("CapEff:")
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    }).unwrap_or(0);
    println!("syslog_cap_effective={}", effective & (1u64 << 34) != 0);
    let mut byte = 0u8;
    println!("invalid_action_errno={}", syslog_errno(100, &mut byte, 0));
    println!("null_read_errno={}", syslog_errno(2, std::ptr::null_mut(), 0));
    println!("negative_length_errno={}", syslog_errno(3, &mut byte, -1));
    println!("negative_level_errno={}", syslog_errno(8, &mut byte, -1));
    println!("excessive_level_errno={}", syslog_errno(8, &mut byte, 9));
    println!("zero_read_errno={}", syslog_errno(2, &mut byte, 0));
    let size = unsafe { libc::syscall(libc::SYS_syslog, 10, std::ptr::null_mut::<u8>(), 0) };
    println!("buffer_size_errno={}", if size < 0 { errno() } else { 0 });
    println!("buffer_size_positive={}", size > 0);
    let drop_result = unsafe { libc::seteuid(65534) };
    println!("drop_euid_errno={}", if drop_result < 0 { errno() } else { 0 });
    println!("nonroot_read_errno={}", syslog_errno(2, &mut byte, 0));
    let restore = unsafe { libc::seteuid(0) };
    println!("restore_euid_errno={}", if restore < 0 { errno() } else { 0 });
}
