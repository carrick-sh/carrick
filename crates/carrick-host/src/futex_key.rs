//! Mapping-independent futex-word keys for `MAP_SHARED` file mappings.
//!
//! A guest FUTEX on a real `MAP_SHARED` file page is an inter-process
//! rendezvous: two processes mapping the same file at different addresses (an
//! exec'd child re-attaching an LTP checkpoint page) must land in one
//! waiter-count slot, so the key must derive from the FILE identity + offset,
//! never from a mapping address. Shared by the HVF trap layer and the native
//! (DSR) backend so both derive identical keys — portable POSIX (`fstat`), no
//! OS cfg.

/// splitmix64-style avalanche so near-identical `(st_dev, st_ino)` pairs and
/// small file offsets spread across the waiter table.
fn mix_futex_key(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// File-identity base for a `MAP_SHARED` file futex-word key: a hash of the
/// backing file's `(st_dev, st_ino)`, `0` when the fd cannot be stat'd (the
/// caller falls back to address-keying).
pub fn shared_file_key_base(fd: libc::c_int) -> u64 {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return 0;
    }
    let key = mix_futex_key((st.st_dev as u64) ^ (st.st_ino as u64).rotate_left(32));
    if key == 0 { 1 } else { key }
}

/// Mapping-independent waiter key for a shared file futex word: the file's
/// [`shared_file_key_base`] mixed with the word's file offset.
pub fn shared_futex_waiter_key(base: u64, file_offset: u64) -> usize {
    let key = mix_futex_key(base ^ file_offset.rotate_left(17));
    let key = if key == 0 { 1 } else { key };
    key as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_file_same_offset_same_key_regardless_of_fd() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = std::ffi::CString::new(f.path().as_os_str().as_encoded_bytes()).unwrap();
        let fd_a = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        let fd_b = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        assert!(fd_a >= 0 && fd_b >= 0);
        let base_a = shared_file_key_base(fd_a);
        let base_b = shared_file_key_base(fd_b);
        unsafe {
            libc::close(fd_a);
            libc::close(fd_b);
        }
        assert_ne!(base_a, 0, "stat'able file must not use the fallback base");
        assert_eq!(base_a, base_b, "key base is file identity, not fd identity");
        assert_eq!(
            shared_futex_waiter_key(base_a, 0x40),
            shared_futex_waiter_key(base_b, 0x40)
        );
        assert_ne!(
            shared_futex_waiter_key(base_a, 0x40),
            shared_futex_waiter_key(base_a, 0x44),
            "distinct word offsets must not collide on one slot"
        );
    }

    #[test]
    fn unstatable_fd_reports_fallback_base() {
        assert_eq!(shared_file_key_base(-1), 0);
    }

    #[test]
    fn keys_are_never_zero() {
        // 0 is the "no base" sentinel; a real key must never alias it.
        assert_ne!(shared_futex_waiter_key(0, 0), 0);
    }
}
