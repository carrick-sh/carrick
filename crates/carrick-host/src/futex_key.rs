//! Mapping-independent futex-word keys for `MAP_SHARED` file mappings.
//!
//! A guest FUTEX on a real `MAP_SHARED` file page is an inter-process
//! rendezvous: two processes mapping the same file at different addresses (an
//! exec'd child re-attaching an LTP checkpoint page) must land in one
//! waiter-count slot, so the key must derive from the FILE identity + offset,
//! never from a mapping address. The carrier compares that full identity;
//! the legacy waiter-table hint below remains for the retired native lane.

use carrick_guest_mem::SharedFutexFileIdentity;

/// splitmix64-style avalanche so near-identical `(st_dev, st_ino)` pairs and
/// small file offsets spread across the waiter table.
fn mix_futex_key(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Exact `(st_dev, st_ino)` identity for a `MAP_SHARED` file futex word.
/// An unstatable fd has no file identity; callers fall back to address-keying.
pub fn shared_file_key_base(fd: libc::c_int) -> Option<SharedFutexFileIdentity> {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(SharedFutexFileIdentity {
        device: st.st_dev as u64,
        inode: st.st_ino as u64,
    })
}

/// Legacy cross-process waiter-table hint. This hash must never decide carrier
/// queue equality: distinct file identities and offsets can produce the same
/// value, while [`SharedFutexFileIdentity`] preserves the full key.
pub fn shared_futex_waiter_key(base: SharedFutexFileIdentity, file_offset: u64) -> usize {
    let base = mix_futex_key(base.device ^ base.inode.rotate_left(32));
    let base = if base == 0 { 1 } else { base };
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
        assert!(base_a.is_some(), "stat'able file must have an identity");
        assert_eq!(base_a, base_b, "key base is file identity, not fd identity");
        assert_eq!(
            shared_futex_waiter_key(base_a.unwrap(), 0x40),
            shared_futex_waiter_key(base_b.unwrap(), 0x40)
        );
        assert_ne!(
            shared_futex_waiter_key(base_a.unwrap(), 0x40),
            shared_futex_waiter_key(base_a.unwrap(), 0x44),
            "distinct word offsets must not collide on one slot"
        );
    }

    #[test]
    fn unstatable_fd_reports_fallback_base() {
        assert_eq!(shared_file_key_base(-1), None);
    }

    #[test]
    fn keys_are_never_zero() {
        let identity = SharedFutexFileIdentity {
            device: 0,
            inode: 0,
        };
        assert_ne!(shared_futex_waiter_key(identity, 0), 0);
    }

    #[test]
    fn distinct_file_words_with_a_forced_hash_collision_keep_distinct_keys() {
        let first_base = SharedFutexFileIdentity {
            device: 0x1234,
            inode: 0,
        };
        let second_base = SharedFutexFileIdentity {
            device: 0x1234 ^ 1_u64.rotate_left(32),
            inode: 1,
        };
        let first_offset = 0x40_u64;
        let second_offset = first_offset;
        assert_ne!((first_base, first_offset), (second_base, second_offset));
        assert_eq!(
            shared_futex_waiter_key(first_base, first_offset),
            shared_futex_waiter_key(second_base, second_offset),
            "the legacy 64-bit hint is deliberately forced to collide"
        );
        assert_ne!(
            carrick_guest_mem::SharedFutexKey::File {
                identity: first_base,
                offset: first_offset,
            },
            carrick_guest_mem::SharedFutexKey::File {
                identity: second_base,
                offset: second_offset,
            },
            "exact carrier keys must preserve the distinct file identities"
        );
    }
}
