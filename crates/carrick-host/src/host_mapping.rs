//! RAII ownership for host mmap regions that back HVF guest mappings.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_FLAGS_ANYWHERE: libc::c_int = 0x0001;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_INHERIT_NONE: libc::vm_inherit_t = 2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const KERN_SUCCESS: libc::kern_return_t = 0;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe extern "C" {
    fn mach_vm_remap(
        target_task: libc::vm_map_t,
        target_address: *mut libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        mask: libc::mach_vm_offset_t,
        flags: libc::c_int,
        src_task: libc::vm_map_t,
        src_address: libc::mach_vm_address_t,
        copy: libc::boolean_t,
        cur_protection: *mut libc::vm_prot_t,
        max_protection: *mut libc::vm_prot_t,
        inheritance: libc::vm_inherit_t,
    ) -> libc::kern_return_t;
}

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

    /// Create a copy-on-write clone of an existing host mapping using Mach VM.
    ///
    /// Carrick private guest RAM is host `MAP_SHARED` for HVF coherence, so a
    /// normal host `fork(2)` keeps parent and child sharing the same object. A
    /// `mach_vm_remap(copy=TRUE)` clone gives the child a private COW object
    /// without eagerly walking/copying each resident page. If the call fails,
    /// callers should fall back to an explicit sparse copy.
    ///
    /// # Safety
    ///
    /// `src` must name a live mapping in this process covering `len` bytes.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[allow(deprecated)] // libc exposes mach_task_self_ as the stable task port here.
    pub unsafe fn remap_copy(
        src: *mut u8,
        len: usize,
        kind: HostMappingKind,
    ) -> Result<Self, std::io::Error> {
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot remap zero-length host mapping",
            ));
        }

        let task = unsafe { libc::mach_task_self_ };
        let mut target: libc::mach_vm_address_t = 0;
        let mut cur: libc::vm_prot_t = 0;
        let mut max: libc::vm_prot_t = 0;
        let kr = unsafe {
            mach_vm_remap(
                task,
                &mut target,
                len as libc::mach_vm_size_t,
                0,
                VM_FLAGS_ANYWHERE,
                task,
                src as libc::mach_vm_address_t,
                1,
                &mut cur,
                &mut max,
                VM_INHERIT_NONE,
            )
        };
        if kr != KERN_SUCCESS {
            return Err(std::io::Error::other(format!(
                "mach_vm_remap(copy=TRUE) failed: {kr}"
            )));
        }
        Ok(Self {
            ptr: target as *mut u8,
            len,
            kind,
        })
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

    pub fn is_empty(&self) -> bool {
        self.len == 0
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn cow_snapshot_isolates_source_and_clone_writes() {
        let len = 4 * 16 * 1024;
        let source = OwnedHostMapping::map_shared_anon(len, HostMappingKind::PrivateAnon)
            .expect("source mapping");
        unsafe {
            source.as_ptr().write_volatile(0x41);
            source.as_ptr().add(16 * 1024).write_volatile(0x42);
        }

        let snapshot = unsafe {
            OwnedHostMapping::remap_copy(
                source.as_ptr(),
                len,
                HostMappingKind::ChildPrivateSnapshot,
            )
        }
        .expect("cow snapshot");

        assert_eq!(snapshot.len(), len);
        assert!(
            !snapshot.guest_shared(),
            "child private snapshots must not be treated as guest-shared"
        );
        assert_eq!(unsafe { snapshot.as_ptr().read_volatile() }, 0x41);
        assert_eq!(
            unsafe { snapshot.as_ptr().add(16 * 1024).read_volatile() },
            0x42
        );

        unsafe {
            source.as_ptr().write_volatile(0x51);
            snapshot.as_ptr().add(16 * 1024).write_volatile(0x62);
        }

        assert_eq!(
            unsafe { snapshot.as_ptr().read_volatile() },
            0x41,
            "source writes after the snapshot must not leak into the child copy"
        );
        assert_eq!(
            unsafe { source.as_ptr().add(16 * 1024).read_volatile() },
            0x42,
            "snapshot writes must not leak back into the source"
        );
    }
}
