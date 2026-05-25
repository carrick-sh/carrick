//! RAII ownership for host mmap regions that back HVF guest mappings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostMappingKind {
    PrivateAnon,
    SharedAnon,
    SharedFile,
    ChildPrivateSnapshot,
}

/// RAII owner for host virtual memory that backs a guest HVF mapping.
///
/// The trap engine still performs `hv_vm_map`/`hv_vm_unmap` explicitly; this
/// type owns only the host `mmap` lifetime and makes failure rollback local.
#[derive(Debug)]
pub(crate) struct OwnedHostMapping {
    ptr: *mut u8,
    len: usize,
    kind: HostMappingKind,
}

impl OwnedHostMapping {
    pub(crate) fn map_shared_anon(
        len: usize,
        kind: HostMappingKind,
    ) -> Result<Self, std::io::Error> {
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                // MAP_NORESERVE: the guest arena (2 GiB) + heap (128 MiB) are
                // demand-zero; the guest can't exceed the arena, so the
                // overcommit-SIGSEGV caveat doesn't apply. Without this, macOS
                // reserves swap backing for the full extent — re-paid per forked
                // guest. RSS is already lazy regardless. (On Darwin MAP_NORESERVE may
                // be accepted-but-ignored; harmless either way.)
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        Self::from_mmap_result(host, len, kind)
    }

    pub(crate) fn map_shared_file(
        len: usize,
        host_fd: i32,
        offset: u64,
    ) -> Result<Self, std::io::Error> {
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                host_fd,
                offset as libc::off_t,
            )
        };
        unsafe { libc::close(host_fd) };
        Self::from_mmap_result(host, len, HostMappingKind::SharedFile)
    }

    fn from_mmap_result(
        host: *mut libc::c_void,
        len: usize,
        kind: HostMappingKind,
    ) -> Result<Self, std::io::Error> {
        if host == libc::MAP_FAILED {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self {
                ptr: host.cast::<u8>(),
                len,
                kind,
            })
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn guest_shared(&self) -> bool {
        matches!(
            self.kind,
            HostMappingKind::SharedAnon | HostMappingKind::SharedFile
        )
    }
}

impl Drop for OwnedHostMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast::<libc::c_void>(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_host_mapping_unmaps_on_drop() {
        let mapping = OwnedHostMapping::map_shared_anon(16 * 1024, HostMappingKind::PrivateAnon)
            .expect("anonymous mapping");
        let ptr = mapping.as_ptr();
        let len = mapping.len();
        assert_eq!(unsafe { libc::msync(ptr.cast(), len, libc::MS_ASYNC) }, 0);
        drop(mapping);
        assert_eq!(unsafe { libc::msync(ptr.cast(), len, libc::MS_ASYNC) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
    }
}
