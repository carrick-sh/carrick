//! RAII ownership for host mmap regions that back HVF guest mappings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMappingKind {
    PrivateAnon,
    SharedAnon,
    /// One HVPatch writer-owned compound frame. Host `MAP_SHARED` is required
    /// for HVF coherence; guest privacy comes from per-mm stage-1 ownership.
    FrameCow,
    /// Carrick-owned EL1 control state (identity page / syscall mailbox) for a
    /// single HVPatch mm.  This is not guest-private memory and is materialized
    /// before entry so Carrick's exception vector never depends on a recoverable
    /// current-EL permission fault.
    PerMmKernelState,
    /// A live `MAP_SHARED` mapping of a host file — coherent with the file's
    /// page cache and shared across `fork(2)`. Backs a guest MAP_SHARED file
    /// mapping `hv_vm_map`'d at a fresh IPA.
    SharedFile,
    /// A COW mapping of an immutable Carrick-owned file artifact. Used for
    /// patched executable regions: every exec gets a distinct host mapping,
    /// while untouched pages stay demand-backed by the cached artifact.
    PrivateFile,
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

    /// `MAP_PRIVATE` a Carrick-owned file artifact read-write. Host writes
    /// (HvPatch overlays or an HVF-coherent guest store) COW-fault private
    /// pages and can never mutate the cached artifact. `fd` need only outlive
    /// this call; the VM mapping retains its own vnode reference.
    pub fn map_private_file(
        fd: libc::c_int,
        offset: libc::off_t,
        len: usize,
    ) -> Result<Self, std::io::Error> {
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd,
                offset,
            )
        };
        Self::from_mmap_result(host, len, HostMappingKind::PrivateFile)
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

    /// Whether a real host `fork(2)` keeps both processes on the same backing.
    ///
    /// This says nothing about guest-physical identity: HVPatch may keep a
    /// shared anonymous mapping process-scoped while a shared file mapping uses
    /// a VM-global IPA. Callers must make that policy decision separately.
    pub fn shares_across_host_fork(&self) -> bool {
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
        // The failed-msync return value itself (-1, i.e. "this range is not a
        // live mapping") is reliable and platform-independent -- confirmed by
        // a single-threaded (zero-concurrency) repro of exactly this
        // mmap->msync->munmap->msync sequence on real NetBSD 10.1/aarch64:
        // rc=-1 every time, no ambiguity, no address-reuse window.
        assert_eq!(unsafe { libc::msync(ptr.cast(), len, libc::MS_ASYNC) }, -1);
        // The ERRNO that failure carries is where platforms diverge. NetBSD's
        // own msync(2) man page documents ENOMEM for "one or more pages which
        // are unmapped", but that same single-threaded repro shows NetBSD
        // 10.1's actual kernel returns EFAULT (14) instead -- a real
        // man-page-vs-kernel discrepancy, not a race (the MMAP_TEST_LOCK
        // above already rules concurrency out, and the repro reproduced it
        // with no other thread in the process at all). macOS and FreeBSD both
        // give ENOMEM here, matching the BSD/POSIX msync man page text.
        #[cfg(target_os = "netbsd")]
        let expected_errno = libc::EFAULT;
        #[cfg(not(target_os = "netbsd"))]
        let expected_errno = libc::ENOMEM;
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(expected_errno)
        );
    }

    /// The `(st_dev, st_ino)` identity of an open descriptor, or `None` if the
    /// slot is closed (or cannot be stat'd).
    #[cfg(unix)]
    fn fd_identity(fd: libc::c_int) -> Option<(libc::dev_t, libc::ino_t)> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return None;
        }
        let st = unsafe { st.assume_init() };
        Some((st.st_dev, st.st_ino))
    }

    /// Count the descriptors in this process that reference exactly the file
    /// `target` identifies, by scanning the whole fd table and comparing
    /// `(st_dev, st_ino)`.
    ///
    /// Scoping the count to ONE file's identity — rather than sampling the
    /// process-wide open-fd total — is what makes this measurement valid inside
    /// a parallel test harness. `MMAP_TEST_LOCK` serialises the mapping tests
    /// against each other, but it does not stop the ~70 other `carrick-host`
    /// unit tests from opening descriptors on other threads of the same test
    /// binary (`internal_fd`'s dup/relocate cases and `ulock`'s re-exec
    /// transport cases both leave descriptors open by design). A process-wide
    /// before/after delta therefore measured THEIR descriptors as well as this
    /// test's, and reported an unrelated concurrent open as a `map_shared_file`
    /// leak. Descriptors on this test's own private, uniquely-named backing
    /// file can only come from this test.
    ///
    /// Portable across macOS/Linux/FreeBSD/NetBSD (no `/proc` dependency), and
    /// — unlike a lowest-free-fd sample — it detects a leak at ANY descriptor
    /// number, not just contiguous low slots. The scan ceiling is bounded by
    /// `RLIMIT_NOFILE` (clamped) so it terminates even if the soft limit is
    /// large.
    #[cfg(unix)]
    fn fds_referencing(target: (libc::dev_t, libc::ino_t)) -> usize {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ceiling = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
            // Clamp: the soft limit can be huge (or RLIM_INFINITY); 4096 is far
            // above anything this test opens, and bounds the scan.
            (rl.rlim_cur as usize).min(4096)
        } else {
            4096
        };
        (0..ceiling)
            .filter(|&fd| fd_identity(fd as libc::c_int) == Some(target))
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
    ///
    /// The leak is counted by `(st_dev, st_ino)` identity against this test's
    /// own backing file, not by a process-wide open-fd delta — see
    /// [`fds_referencing`] for why the process-wide form was not a valid
    /// measurement inside a parallel test binary.
    #[cfg(unix)]
    #[test]
    fn map_shared_file_does_not_leak_host_fds_across_cycles() {
        let _serialize = MMAP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        // structures, etc.) are already paid before the measured cycles.
        let warm_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        assert!(warm_fd >= 0, "open backing file");
        let backing = fd_identity(warm_fd).expect("fstat backing file");
        assert_eq!(
            fds_referencing(backing),
            1,
            "only this test's own open descriptor may reference its private backing file"
        );
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

        // Baseline: with every descriptor this test opened now closed, nothing
        // in the process may still reference the backing file.
        let base = fds_referencing(backing);
        assert_eq!(
            base, 0,
            "the warm-up cycle left a descriptor open on the backing file"
        );

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

        let after = fds_referencing(backing);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            after, 0,
            "{after} descriptor(s) still reference the backing file after {N} \
             map_shared_file cycles that closed every fd they opened: the \
             alias-window MAP_SHARED file path is leaking host fds (an \
             engine's map_host_alias likely forgot to close the dispatcher's \
             dup'd fd, or map_shared_file retained a descriptor of its own)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn map_private_file_is_cow_and_outlives_the_source_fd() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;

        let _serialize = MMAP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = 16 * 1024usize;
        let mut file = tempfile::tempfile().expect("create private-file fixture");
        file.write_all(&vec![0xA5; len]).expect("write fixture");
        file.seek(SeekFrom::Start(0)).expect("rewind fixture");
        let mapping =
            OwnedHostMapping::map_private_file(file.as_raw_fd(), 0, len).expect("map private file");
        let bytes = unsafe { std::slice::from_raw_parts_mut(mapping.as_ptr(), len) };
        assert_eq!(bytes[0], 0xA5);
        bytes[0] = 0x5A;
        assert_eq!(bytes[0], 0x5A, "private mapping must be writable");

        file.seek(SeekFrom::Start(0)).expect("rewind source");
        let mut source_byte = [0_u8; 1];
        file.read_exact(&mut source_byte).expect("read source");
        assert_eq!(
            source_byte[0], 0xA5,
            "a COW write must not mutate the file artifact"
        );
        drop(file);

        // The fd is closed above; the mapping's vnode reference must remain
        // live and the COW write must not fault.
        assert_eq!(
            unsafe { libc::msync(mapping.as_ptr().cast(), len, libc::MS_ASYNC) },
            0
        );
    }
}
