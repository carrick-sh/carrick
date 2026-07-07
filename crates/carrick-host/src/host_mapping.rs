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
        // EXPERIMENT: map private guest RAM as MAP_PRIVATE so host fork(2)
        // COW-isolates it for free (cheap fork) — testing whether MAP_PRIVATE
        // stays coherent under hv_vm_map (the disputed "desync"). Shared regions
        // (aperture, signal rings, shared files) MUST stay MAP_SHARED.
        let share = match kind {
            HostMappingKind::PrivateAnon => libc::MAP_PRIVATE,
            _ => libc::MAP_SHARED,
        };
        #[allow(deprecated)] // MAP_NORESERVE: removed in FreeBSD 11, harmless no-op elsewhere
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
                libc::MAP_ANON | share | libc::MAP_NORESERVE,
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

    /// All three tests in this binary mmap into the SHARED process address space.
    /// `owned_host_mapping_unmaps_on_drop` asserts that a just-FREED address is
    /// unmapped — which races any concurrent mmap (cargo runs the binary's tests
    /// in parallel): a sibling test can reuse the freed address in the window
    /// before the check, so `msync` succeeds instead of ENOMEM (flaky under load).
    /// Serialize the mmap tests so none maps during another's freed-address check.
    /// Poison-recovering so a panic in one test doesn't cascade-fail the others.
    static MMAP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn owned_host_mapping_unmaps_on_drop() {
        let _serialize = MMAP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// Count the process's currently-open file descriptors by probing the fd
    /// table directly with `fcntl(F_GETFD)`. Portable across macOS and Linux (no
    /// `/proc` dependency) and — unlike a lowest-free-fd sample — detects a leak
    /// at ANY descriptor number, not just contiguous low slots. The scan ceiling
    /// is bounded by `RLIMIT_NOFILE` (clamped) so it terminates even if the soft
    /// limit is large.
    #[cfg(unix)]
    fn open_fd_count() -> usize {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ceiling = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
            // Clamp: the soft limit can be huge (or RLIM_INFINITY); 4096 is far
            // above anything this single-threaded test opens, and bounds the scan.
            (rl.rlim_cur as usize).min(4096)
        } else {
            4096
        };
        (0..ceiling)
            .filter(|&fd| unsafe { libc::fcntl(fd as libc::c_int, libc::F_GETFD) } != -1)
            .count()
    }

    /// Regression guard for the `mmap(MAP_SHARED, fd)` alias-window host-fd leak
    /// (cpython multiprocessing.Pool semaphore churn): `map_shared_file` retains
    /// its OWN kernel reference to the file, so a caller (the per-engine
    /// `map_host_alias`) MUST close the dup'd fd it was handed once the mapping
    /// exists — and doing so must NOT leak. This asserts both halves: the dup is
    /// safe to close immediately after the map (the mapping stays valid), and
    /// repeated map→close→drop cycles do not grow the process's open-fd count.
    ///
    /// The bug this catches: an engine that forgets the `close(fd)` (or a future
    /// refactor that drops it) leaks one host fd per guest mmap of a /dev/shm
    /// semaphore, climbing unbounded in a long-lived guest until per-cycle time
    /// degrades and the forkserver test module blows its 300 s budget.
    #[cfg(unix)]
    #[test]
    fn map_shared_file_does_not_leak_host_fds_across_cycles() {
        let _serialize = MMAP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Other host tests can lazily initialize the shared kernel arena, which
        // opens one fd. Do it before the fd-count baseline so this leak test
        // measures only map_shared_file cycles.
        crate::guest_cpu::init_child_table();
        // A real backing file (mmap of an anonymous/closed fd is not portable);
        // 16 KiB so it is a single HVF granule.
        let len = 16 * 1024usize;
        let path = std::env::temp_dir().join(format!(
            "carrick-host-mapping-leak-{}-{}.bin",
            std::process::id(),
            // a per-run salt so concurrent test binaries never collide
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        {
            let data = vec![0xABu8; len];
            std::fs::write(&path, &data).expect("write backing file");
        }
        let c_path = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes())
            .expect("path has no interior NUL");

        // Warm one cycle first so any one-time lazy allocations (page-cache
        // structures, etc.) are already paid before we sample the baseline.
        let warm_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        assert!(warm_fd >= 0, "open backing file");
        {
            let dup = unsafe { libc::dup(warm_fd) };
            assert!(dup >= 0, "dup");
            let m =
                OwnedHostMapping::map_shared_file(dup, 0, len, libc::PROT_READ | libc::PROT_WRITE)
                    .expect("map_shared_file");
            // Contract: the dup may be closed immediately — the mapping retains
            // its own reference and stays valid.
            assert_eq!(unsafe { libc::close(dup) }, 0, "close dup after map");
            assert_eq!(
                unsafe { libc::msync(m.as_ptr().cast(), len, libc::MS_ASYNC) },
                0,
                "mapping must outlive the closed dup"
            );
            drop(m);
        }
        unsafe { libc::close(warm_fd) };

        // Baseline open-fd count after warm-up.
        let base = open_fd_count();

        // N map→close-dup→drop cycles. Each mirrors what the per-engine
        // `map_host_alias` does with the dispatcher's dup'd fd.
        const N: usize = 64;
        for _ in 0..N {
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
            assert!(fd >= 0, "open backing file in loop");
            let dup = unsafe { libc::dup(fd) };
            assert!(dup >= 0, "dup in loop");
            let m =
                OwnedHostMapping::map_shared_file(dup, 0, len, libc::PROT_READ | libc::PROT_WRITE)
                    .expect("map_shared_file in loop");
            assert_eq!(unsafe { libc::close(dup) }, 0, "close dup in loop");
            // The guest fd (`fd`) is also closed by the guest on Linux; mirror it.
            assert_eq!(unsafe { libc::close(fd) }, 0, "close guest fd in loop");
            drop(m);
        }

        let after = open_fd_count();
        let _ = std::fs::remove_file(&path);

        assert!(
            after <= base,
            "open-fd count grew across {N} map_shared_file cycles \
             ({base} -> {after}): the alias-window MAP_SHARED file path is \
             leaking host fds (an engine's map_host_alias likely forgot to \
             close the dispatcher's dup'd fd)"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn cow_snapshot_isolates_source_and_clone_writes() {
        let _serialize = MMAP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
