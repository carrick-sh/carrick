//! FreeBSD-only shared-futex waiter-key derivation.
//!
//! Moved verbatim from `carrick-runtime/src/native_freebsd.rs`
//! (`freebsd_shared_waiter_key`) as part of the identity-memory
//! neutralization (Phase 2 of the native-lane seam plan): confirmed
//! FreeBSD-only ABI (`libc::KERN_PROC_VMMAP`/`libc::kinfo_vmentry` are absent
//! from Darwin's `libc`), reached through
//! `carrick_dsr::lane::NativeHost::shared_futex_waiter_key` rather than a
//! direct call, so `carrick-dsr::identity_memory` never names this crate.

/// Resolve a mapped vnode page to a process-independent futex waiter key using
/// FreeBSD's documented `kern.proc.vmmap` ABI. Linux keys a shared futex by its
/// backing object and byte offset, not by the caller's VA; after exec the same
/// checkpoint file is commonly remapped at a different address. `_umtx_op`
/// already uses that backing identity for the physical wait/wake. Carrick needs
/// the same identity for its fork-shared waiter-count side table so WAKE returns
/// Linux's count rather than a false zero.
pub fn shared_waiter_key(address: usize) -> Option<usize> {
    let pid = unsafe { libc::getpid() };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_VMMAP, pid];
    let mut needed = 0usize;
    // SAFETY: first sysctl call requests the required buffer size only.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || needed < std::mem::size_of::<libc::kinfo_vmentry>()
    {
        return None;
    }
    let mut bytes = vec![0u8; needed];
    // SAFETY: `bytes` owns `needed` writable bytes and this is a read-only MIB.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    let mut cursor = 0usize;
    while cursor
        .checked_add(std::mem::size_of::<libc::kinfo_vmentry>())
        .is_some_and(|end| end <= needed)
    {
        // SAFETY: the bounds check above covers one complete ABI entry. Sysctl
        // entries need not be naturally aligned inside the byte buffer.
        let entry = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(cursor).cast::<libc::kinfo_vmentry>())
        };
        let entry_size = usize::try_from(entry.kve_structsize).ok()?;
        if entry_size == 0
            || cursor
                .checked_add(entry_size)
                .is_none_or(|end| end > needed)
        {
            break;
        }
        let address = address as u64;
        if entry.kve_start <= address && address < entry.kve_end && entry.kve_vn_fileid != 0 {
            let backing_offset = entry
                .kve_offset
                .checked_add(address.saturating_sub(entry.kve_start))?;
            // Stable 64-bit avalanche over vnode fsid/fileid + byte offset.
            let mut key = entry.kve_vn_fsid
                ^ entry.kve_vn_fileid.rotate_left(21)
                ^ backing_offset.rotate_left(42)
                ^ 0x9e37_79b9_7f4a_7c15;
            key ^= key >> 30;
            key = key.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            key ^= key >> 27;
            key = key.wrapping_mul(0x94d0_49bb_1331_11eb);
            key ^= key >> 31;
            return Some((key as usize) | 1);
        }
        cursor += entry_size;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn shared_waiter_key_follows_vnode_offset_not_mapping_address() {
        const LEN: usize = 8192;
        let file = tempfile::tempfile().expect("temporary backing file");
        file.set_len(LEN as u64).expect("size backing file");
        let map = || unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        let first = map();
        let second = map();
        assert_ne!(first, libc::MAP_FAILED);
        assert_ne!(second, libc::MAP_FAILED);
        assert_ne!(first, second);

        let first_key = shared_waiter_key(first as usize).expect("first vnode key");
        let alias_key = shared_waiter_key(second as usize).expect("alias vnode key");
        let next_page_key =
            shared_waiter_key(first as usize + 4096).expect("second-page vnode key");
        assert_eq!(first_key, alias_key);
        assert_ne!(first_key, next_page_key);

        unsafe {
            libc::munmap(first, LEN);
            libc::munmap(second, LEN);
        }
    }
}
