//! Bounded pipe handshakes shared by guest scenarios.
/// Send one observed count to the peer as 8 little-endian bytes.
pub(crate) fn write_count(fd: libc::c_int, count: u64) -> bool {
    let bytes = count.to_le_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    n == bytes.len() as isize
}

/// Receive a count written by `write_count`, bounded by `timeout_ms`.
pub(crate) fn poll_read_count(fd: libc::c_int, timeout_ms: libc::c_int) -> Option<u64> {
    let mut bytes = [0u8; 8];
    let mut have = 0;
    while have < bytes.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            return None;
        }
        let n = unsafe { libc::read(fd, bytes[have..].as_mut_ptr().cast(), bytes.len() - have) };
        if n <= 0 {
            return None;
        }
        have += n as usize;
    }
    Some(u64::from_le_bytes(bytes))
}
