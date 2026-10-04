//! Owned, bounded bytes crossing from an excluded delegated inode to host I/O.
use super::*;

struct DirtyPage {
    offset: u64,
    bytes: Box<[u8]>,
}

/// Captured under actual inode exclusion; contains no guest pointer or guard.
/// At most the fixed delegated cache capacity can be retained.
pub(super) struct InodeWriteback {
    size: u64,
    dirty: u64,
    pages: Vec<DirtyPage>,
}

impl InodeWriteback {
    pub(super) fn capture(guard: &DelegatedFileGuard<'_>, handle: u32) -> Self {
        let file = guard.file();
        let size = file.size.load(Ordering::Acquire);
        let dirty = file.dirty_mask.load(Ordering::Acquire);
        let cache = delegated_cache(get_el1_region_host_ptr(), handle);
        let mut pages = Vec::with_capacity(dirty.count_ones() as usize);
        for page in 0..DELEGATED_MAX_PAGES {
            let offset = page as u64 * DELEGATED_PAGE_SIZE;
            if dirty & (1 << page) == 0 || offset >= size {
                continue;
            }
            let len = DELEGATED_PAGE_SIZE.min(size - offset) as usize;
            // SAFETY: the authenticated inode guard excludes cache mutation;
            // each selected page is inside its fixed delegated cache slot.
            let bytes = unsafe { std::slice::from_raw_parts(cache.add(offset as usize), len) };
            pages.push(DirtyPage {
                offset,
                bytes: bytes.into(),
            });
        }
        file.dirty_mask.store(0, Ordering::Release);
        Self { size, dirty, pages }
    }

    pub(super) fn apply(
        &self,
        handle: u32,
        identity: InodeIdentity,
        target: &WriteBackTarget,
        rootfs: Option<&carrick_vfs::RootFsVfs>,
    ) -> Result<(), carrick_abi::LinuxErrno> {
        #[cfg(test)]
        tests::observe_writeback_admission();
        let Some(fd) = target.writeback.as_ref() else {
            if self.dirty != 0 {
                carrick_fatal!(
                    "el1_delegation",
                    "in-zone inode (handle={handle}) has dirty pages but no writable member"
                );
            }
            return Ok(());
        };
        let last_error = || {
            crate::host_to_linux_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            )
        };
        let mut first_error = None;
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        let size_changed =
            unsafe { libc::fstat(fd.raw(), &mut st) } != 0 || st.st_size.max(0) as u64 != self.size;
        if size_changed {
            target
                .sparse
                .truncate_host_sparse_extents(fd.raw(), self.size);
            if unsafe { libc::ftruncate(fd.raw(), self.size as libc::off_t) } != 0 {
                first_error.get_or_insert(last_error());
            }
        }
        for page in &self.pages {
            let written = unsafe {
                libc::pwrite(
                    fd.raw(),
                    page.bytes.as_ptr().cast(),
                    page.bytes.len(),
                    page.offset as libc::off_t,
                )
            };
            if written < 0 {
                first_error.get_or_insert(last_error());
            } else {
                target
                    .sparse
                    .record_host_sparse_write(fd, page.offset, written as usize);
            }
        }
        if (self.dirty != 0 || size_changed)
            && let Some(vfs) = rootfs
        {
            vfs.notify_inode_changed("", Some(identity));
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}
