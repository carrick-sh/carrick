//! RAII ownership for host mmap regions that back HVF guest mappings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMappingKind {
    PrivateAnon,
    SharedAnon,
    ChildPrivateSnapshot,
    /// A live `MAP_SHARED` mapping of a host file — coherent with the file's
    /// page cache and shared across `fork(2)`. Backs a guest MAP_SHARED file
    /// mapping `hv_vm_map`'d at a fresh IPA.
    SharedFile,
}

/// RAII owner for host virtual memory that backs a guest HVF mapping.
///
/// The trap engine still performs `hv_vm_map`/`hv_vm_unmap` explicitly; this
/// type owns only the host `mmap` lifetime and makes failure rollback local.
#[derive(Debug)]
pub struct OwnedHostMapping {
    ptr: *mut u8,
    len: usize,
    kind: HostMappingKind,
}

impl OwnedHostMapping {
    pub fn map_shared_anon(len: usize, kind: HostMappingKind) -> Result<Self, std::io::Error> {
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

    /// `MAP_SHARED` a host file region. The resulting mapping is coherent with
    /// the file's page cache: writes the guest makes are visible to any other
    /// process that mmaps or reads the file, and survive `fork(2)` because the
    /// kernel object is the file, not anonymous swap. `fd` need only outlive
    /// this call — `mmap` retains its own reference — so the caller may close
    /// (or close a dup of) it immediately after.
    ///
    /// `prot` is the guest's requested protection (`PROT_*`) and MUST be a
    /// subset of the fd's access mode: a `PROT_WRITE` MAP_SHARED mapping of a
    /// read-only fd is rejected with `EACCES` by the host (matching Linux), so
    /// the caller must pass the guest's actual prot, not a blanket RW.
    pub fn map_shared_file(
        fd: libc::c_int,
        offset: libc::off_t,
        len: usize,
        prot: libc::c_int,
    ) -> Result<Self, std::io::Error> {
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd,
                offset,
            )
        };
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

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn guest_shared(&self) -> bool {
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
