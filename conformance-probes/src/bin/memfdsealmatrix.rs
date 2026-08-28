//! memfd sealing lifecycle and fcntl sealing semantics probe.
//!
//! Covers:
//! 1. memfd created without MFD_ALLOW_SEALING starts with F_SEAL_SEAL preset and
//!    rejects F_ADD_SEALS with EPERM.
//! 2. memfd created with MFD_ALLOW_SEALING starts with an empty seal set (0).
//! 3. F_SEAL_GROW prevents enlarging the file (ftruncate/write beyond EOF) while
//!    preserving shrink and same-size ftruncate.
//! 4. F_SEAL_SHRINK prevents reducing file size while preserving grow and same-size
//!    ftruncate.
//! 5. F_SEAL_GROW | F_SEAL_SHRINK fixes the file size in both directions.
//! 6. F_SEAL_WRITE prevents write/pwrite modifications while allowing reads.
//! 7. F_SEAL_WRITE cannot be added while a live shared writable mapping exists (EBUSY);
//!    after unmapping, adding F_SEAL_WRITE succeeds and subsequent MAP_SHARED + PROT_WRITE
//!    attempts fail with EPERM, while MAP_PRIVATE writable mappings and read-only mappings
//!    remain permitted.
//! 8. F_SEAL_SEAL prevents any subsequent seals from being added (EPERM).
//! 9. Exact F_GET_SEALS transitions and shared seal state across duplicated file descriptors.
//! 10. F_SEAL_FUTURE_WRITE can be added even with active shared writable mappings, permits
//!     writes through pre-existing shared mappings, but blocks new write/pwrite calls and
//!     new MAP_SHARED + PROT_WRITE mappings.
//!
//! Deterministic: prints booleans only via `report!`. No fork, sleeps, unbounded waits,
//! or hard-coded fd values. Independent memfds per subcase with RAII cleanup.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, report};
use std::ffi::CString;

const MFD_CLOEXEC: u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;

const F_ADD_SEALS: libc::c_int = 1033;
const F_GET_SEALS: libc::c_int = 1034;

const F_SEAL_SEAL: i32 = 0x0001;
const F_SEAL_SHRINK: i32 = 0x0002;
const F_SEAL_GROW: i32 = 0x0004;
const F_SEAL_WRITE: i32 = 0x0008;
const F_SEAL_FUTURE_WRITE: i32 = 0x0010;

struct FdGuard(i32);

impl FdGuard {
    fn new(fd: i32) -> Self {
        Self(fd)
    }
    fn get(&self) -> i32 {
        self.0
    }
    fn is_valid(&self) -> bool {
        self.0 >= 0
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
            self.0 = -1;
        }
    }
}

struct MmapGuard {
    addr: *mut libc::c_void,
    len: usize,
}

impl MmapGuard {
    fn new(addr: *mut libc::c_void, len: usize) -> Self {
        Self { addr, len }
    }
    fn is_valid(&self) -> bool {
        self.addr != libc::MAP_FAILED && !self.addr.is_null()
    }
    fn as_mut_ptr(&self) -> *mut u8 {
        self.addr as *mut u8
    }
}

impl Drop for MmapGuard {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                libc::munmap(self.addr, self.len);
            }
            self.addr = libc::MAP_FAILED;
        }
    }
}

unsafe fn sys_memfd_create(name: &str, flags: u32) -> i32 {
    let Ok(c) = CString::new(name) else {
        return -1;
    };
    libc::syscall(libc::SYS_memfd_create, c.as_ptr(), flags as libc::c_ulong) as i32
}

unsafe fn get_seals(fd: i32) -> (i32, i32) {
    let rc = libc::fcntl(fd, F_GET_SEALS);
    if rc < 0 {
        (-1, errno())
    } else {
        (rc, 0)
    }
}

unsafe fn add_seals(fd: i32, seals: i32) -> (i32, i32) {
    let rc = libc::fcntl(fd, F_ADD_SEALS, seals);
    if rc < 0 {
        (-1, errno())
    } else {
        (rc, 0)
    }
}

fn main() {
    unsafe {
        // Probe-local 1-second upper-bound alarm for fast nonblocking execution.
        arm_alarm_ms(1000);

        // 1. no-MFD_ALLOW_SEALING starts with F_SEAL_SEAL and rejects F_ADD_SEALS.
        let fd_noseal = FdGuard::new(sys_memfd_create("noseal", MFD_CLOEXEC));
        let (s_noseal_init, err_noseal_init) = if fd_noseal.is_valid() {
            get_seals(fd_noseal.get())
        } else {
            (-1, -1)
        };
        let (add_shrink_rc, add_shrink_err) = if fd_noseal.is_valid() {
            add_seals(fd_noseal.get(), F_SEAL_SHRINK)
        } else {
            (-1, -1)
        };
        let (add_grow_rc, add_grow_err) = if fd_noseal.is_valid() {
            add_seals(fd_noseal.get(), F_SEAL_GROW)
        } else {
            (-1, -1)
        };
        let (add_write_rc, add_write_err) = if fd_noseal.is_valid() {
            add_seals(fd_noseal.get(), F_SEAL_WRITE)
        } else {
            (-1, -1)
        };
        let (s_noseal_final, err_noseal_final) = if fd_noseal.is_valid() {
            get_seals(fd_noseal.get())
        } else {
            (-1, -1)
        };

        let noseal_initial_seal = s_noseal_init == F_SEAL_SEAL && err_noseal_init == 0;
        let noseal_add_shrink_eperm = add_shrink_rc == -1 && add_shrink_err == libc::EPERM;
        let noseal_add_grow_eperm = add_grow_rc == -1 && add_grow_err == libc::EPERM;
        let noseal_add_write_eperm = add_write_rc == -1 && add_write_err == libc::EPERM;
        let noseal_seals_unchanged = s_noseal_final == F_SEAL_SEAL && err_noseal_final == 0;

        // 2. allow-sealing starts empty.
        let fd_allow = FdGuard::new(sys_memfd_create(
            "allowseal",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let (s_allow_init, err_allow_init) = if fd_allow.is_valid() {
            get_seals(fd_allow.get())
        } else {
            (-1, -1)
        };
        let allow_sealing_initial_empty = s_allow_init == 0 && err_allow_init == 0;

        // 3. F_SEAL_GROW enforces ftruncate/write grow boundaries while shrink/same-size work.
        let fd_grow = FdGuard::new(sys_memfd_create(
            "sealgrow",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut grow_subcase_ok = fd_grow.is_valid();
        if grow_subcase_ok {
            grow_subcase_ok = libc::ftruncate(fd_grow.get(), 4096) == 0;
        }
        let (add_grow_seal_rc, add_grow_seal_err) = if grow_subcase_ok {
            add_seals(fd_grow.get(), F_SEAL_GROW)
        } else {
            (-1, -1)
        };
        let (s_grow, err_s_grow) = if grow_subcase_ok {
            get_seals(fd_grow.get())
        } else {
            (-1, -1)
        };
        let trunc_grow_rc = if grow_subcase_ok {
            libc::ftruncate(fd_grow.get(), 8192)
        } else {
            0
        };
        let trunc_grow_err = errno();
        let trunc_same_rc = if grow_subcase_ok {
            libc::ftruncate(fd_grow.get(), 4096)
        } else {
            -1
        };
        let trunc_shrink_rc = if grow_subcase_ok {
            libc::ftruncate(fd_grow.get(), 2048)
        } else {
            -1
        };
        let trunc_grow_back_rc = if grow_subcase_ok {
            libc::ftruncate(fd_grow.get(), 4096)
        } else {
            0
        };
        let trunc_grow_back_err = errno();
        let buf_write = [0x5au8; 4];
        let pwrite_past_eof_rc = if grow_subcase_ok {
            libc::pwrite(
                fd_grow.get(),
                buf_write.as_ptr() as *const libc::c_void,
                buf_write.len(),
                2048,
            )
        } else {
            0
        };
        let pwrite_past_eof_err = errno();
        let pwrite_within_rc = if grow_subcase_ok {
            libc::pwrite(
                fd_grow.get(),
                buf_write.as_ptr() as *const libc::c_void,
                buf_write.len(),
                0,
            )
        } else {
            -1
        };

        let seal_grow_added = add_grow_seal_rc == 0
            && add_grow_seal_err == 0
            && s_grow == F_SEAL_GROW
            && err_s_grow == 0;
        let seal_grow_prevents_grow = trunc_grow_rc == -1 && trunc_grow_err == libc::EPERM;
        let seal_grow_allows_same_size = trunc_same_rc == 0;
        let seal_grow_allows_shrink = trunc_shrink_rc == 0;
        let seal_grow_prevents_grow_back =
            trunc_grow_back_rc == -1 && trunc_grow_back_err == libc::EPERM;
        let seal_grow_pwrite_past_eof_eperm =
            pwrite_past_eof_rc == -1 && pwrite_past_eof_err == libc::EPERM;
        let seal_grow_pwrite_within_size_ok = pwrite_within_rc == 4;

        // 4. F_SEAL_SHRINK enforces ftruncate shrink boundaries while grow/same-size work.
        let fd_shrink = FdGuard::new(sys_memfd_create(
            "sealshrink",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut shrink_subcase_ok = fd_shrink.is_valid();
        if shrink_subcase_ok {
            shrink_subcase_ok = libc::ftruncate(fd_shrink.get(), 4096) == 0;
        }
        let (add_shrink_seal_rc, add_shrink_seal_err) = if shrink_subcase_ok {
            add_seals(fd_shrink.get(), F_SEAL_SHRINK)
        } else {
            (-1, -1)
        };
        let (s_shrink, err_s_shrink) = if shrink_subcase_ok {
            get_seals(fd_shrink.get())
        } else {
            (-1, -1)
        };
        let trunc_shrink_rc2 = if shrink_subcase_ok {
            libc::ftruncate(fd_shrink.get(), 2048)
        } else {
            0
        };
        let trunc_shrink_err2 = errno();
        let trunc_same_rc2 = if shrink_subcase_ok {
            libc::ftruncate(fd_shrink.get(), 4096)
        } else {
            -1
        };
        let trunc_grow_rc2 = if shrink_subcase_ok {
            libc::ftruncate(fd_shrink.get(), 8192)
        } else {
            -1
        };
        let trunc_shrink_back_rc = if shrink_subcase_ok {
            libc::ftruncate(fd_shrink.get(), 4096)
        } else {
            0
        };
        let trunc_shrink_back_err = errno();

        let seal_shrink_added = add_shrink_seal_rc == 0
            && add_shrink_seal_err == 0
            && s_shrink == F_SEAL_SHRINK
            && err_s_shrink == 0;
        let seal_shrink_prevents_shrink =
            trunc_shrink_rc2 == -1 && trunc_shrink_err2 == libc::EPERM;
        let seal_shrink_allows_same_size = trunc_same_rc2 == 0;
        let seal_shrink_allows_grow = trunc_grow_rc2 == 0;
        let seal_shrink_prevents_shrink_back =
            trunc_shrink_back_rc == -1 && trunc_shrink_back_err == libc::EPERM;

        // 5. F_SEAL_GROW | F_SEAL_SHRINK fixes size in both directions.
        let fd_fixed = FdGuard::new(sys_memfd_create(
            "sealfixed",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut fixed_subcase_ok = fd_fixed.is_valid();
        if fixed_subcase_ok {
            fixed_subcase_ok = libc::ftruncate(fd_fixed.get(), 4096) == 0;
        }
        let (add_fixed_rc, add_fixed_err) = if fixed_subcase_ok {
            add_seals(fd_fixed.get(), F_SEAL_GROW | F_SEAL_SHRINK)
        } else {
            (-1, -1)
        };
        let (s_fixed, err_s_fixed) = if fixed_subcase_ok {
            get_seals(fd_fixed.get())
        } else {
            (-1, -1)
        };
        let trunc_fixed_grow_rc = if fixed_subcase_ok {
            libc::ftruncate(fd_fixed.get(), 8192)
        } else {
            0
        };
        let trunc_fixed_grow_err = errno();
        let trunc_fixed_shrink_rc = if fixed_subcase_ok {
            libc::ftruncate(fd_fixed.get(), 2048)
        } else {
            0
        };
        let trunc_fixed_shrink_err = errno();
        let trunc_fixed_same_rc = if fixed_subcase_ok {
            libc::ftruncate(fd_fixed.get(), 4096)
        } else {
            -1
        };

        let seal_fixed_added = add_fixed_rc == 0
            && add_fixed_err == 0
            && s_fixed == (F_SEAL_GROW | F_SEAL_SHRINK)
            && err_s_fixed == 0;
        let seal_fixed_prevents_grow =
            trunc_fixed_grow_rc == -1 && trunc_fixed_grow_err == libc::EPERM;
        let seal_fixed_prevents_shrink =
            trunc_fixed_shrink_rc == -1 && trunc_fixed_shrink_err == libc::EPERM;
        let seal_fixed_allows_same_size = trunc_fixed_same_rc == 0;

        // 6. F_SEAL_WRITE rejects write/pwrite and allows read/pread.
        let fd_write = FdGuard::new(sys_memfd_create(
            "sealwrite",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut write_subcase_ok = fd_write.is_valid();
        if write_subcase_ok {
            write_subcase_ok = libc::ftruncate(fd_write.get(), 4096) == 0;
        }
        let init_data = b"init";
        let pre_pwrite_rc = if write_subcase_ok {
            libc::pwrite(
                fd_write.get(),
                init_data.as_ptr() as *const libc::c_void,
                init_data.len(),
                0,
            )
        } else {
            -1
        };
        let (add_write_seal_rc, add_write_seal_err) = if write_subcase_ok && pre_pwrite_rc == 4 {
            add_seals(fd_write.get(), F_SEAL_WRITE)
        } else {
            (-1, -1)
        };
        let (s_write, err_s_write) = if write_subcase_ok {
            get_seals(fd_write.get())
        } else {
            (-1, -1)
        };
        let new_data = b"test";
        let post_pwrite_rc = if write_subcase_ok {
            libc::pwrite(
                fd_write.get(),
                new_data.as_ptr() as *const libc::c_void,
                new_data.len(),
                0,
            )
        } else {
            0
        };
        let post_pwrite_err = errno();
        let post_write_rc = if write_subcase_ok {
            libc::write(
                fd_write.get(),
                new_data.as_ptr() as *const libc::c_void,
                new_data.len(),
            )
        } else {
            0
        };
        let post_write_err = errno();
        let mut read_buf = [0u8; 4];
        let pread_rc = if write_subcase_ok {
            libc::pread(
                fd_write.get(),
                read_buf.as_mut_ptr() as *mut libc::c_void,
                read_buf.len(),
                0,
            )
        } else {
            -1
        };

        let seal_write_added = add_write_seal_rc == 0
            && add_write_seal_err == 0
            && s_write == F_SEAL_WRITE
            && err_s_write == 0;
        let seal_write_pwrite_eperm = post_pwrite_rc == -1 && post_pwrite_err == libc::EPERM;
        let seal_write_write_eperm = post_write_rc == -1 && post_write_err == libc::EPERM;
        let seal_write_pread_ok = pread_rc == 4 && &read_buf == init_data;

        // 7. Live shared writable mapping makes F_ADD_SEALS(F_SEAL_WRITE) return EBUSY;
        //    succeeds after unmap and blocks new shared writable mappings.
        let fd_mmap = FdGuard::new(sys_memfd_create(
            "sealwritemmap",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut mmap_subcase_ok = fd_mmap.is_valid();
        if mmap_subcase_ok {
            mmap_subcase_ok = libc::ftruncate(fd_mmap.get(), 4096) == 0;
        }

        let map_active = if mmap_subcase_ok {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd_mmap.get(),
                0,
            )
        } else {
            libc::MAP_FAILED
        };
        let map_guard = MmapGuard::new(map_active, 4096);
        let map_created = map_guard.is_valid();

        let (add_write_ebusy_rc, add_write_ebusy_err) = if map_created {
            add_seals(fd_mmap.get(), F_SEAL_WRITE)
        } else {
            (0, 0)
        };
        let (s_ebusy, err_s_ebusy) = if map_created {
            get_seals(fd_mmap.get())
        } else {
            (-1, -1)
        };

        // Write through the active mapping to prove it is functional
        if map_created {
            core::ptr::write_volatile(map_guard.as_mut_ptr(), 0xa5);
        }
        let map_write_ok = if map_created {
            core::ptr::read_volatile(map_guard.as_mut_ptr()) == 0xa5
        } else {
            false
        };

        // Explicitly drop/unmap the active shared mapping
        drop(map_guard);

        let (add_write_post_unmap_rc, add_write_post_unmap_err) = if mmap_subcase_ok {
            add_seals(fd_mmap.get(), F_SEAL_WRITE)
        } else {
            (-1, -1)
        };
        let (s_post_unmap, err_s_post_unmap) = if mmap_subcase_ok {
            get_seals(fd_mmap.get())
        } else {
            (-1, -1)
        };

        // Attempt new MAP_SHARED + PROT_WRITE (must fail with EPERM)
        let map_shared_rw_after = if mmap_subcase_ok {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd_mmap.get(),
                0,
            )
        } else {
            core::ptr::null_mut()
        };
        let map_shared_rw_err = errno();
        let _guard_shared_rw = MmapGuard::new(map_shared_rw_after, 4096);

        // Attempt new MAP_SHARED + PROT_READ (must succeed)
        let map_shared_ro_after = if mmap_subcase_ok {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd_mmap.get(),
                0,
            )
        } else {
            libc::MAP_FAILED
        };
        let guard_shared_ro = MmapGuard::new(map_shared_ro_after, 4096);

        // Attempt new MAP_PRIVATE + PROT_WRITE (must succeed)
        let map_priv_rw_after = if mmap_subcase_ok {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd_mmap.get(),
                0,
            )
        } else {
            libc::MAP_FAILED
        };
        let guard_priv_rw = MmapGuard::new(map_priv_rw_after, 4096);

        let seal_write_active_shared_mmap_ebusy =
            add_write_ebusy_rc == -1 && add_write_ebusy_err == libc::EBUSY;
        let seal_write_ebusy_seals_unchanged = s_ebusy == 0 && err_s_ebusy == 0;
        let seal_write_active_mmap_writable = map_write_ok;
        let seal_write_after_unmap_ok =
            add_write_post_unmap_rc == 0 && add_write_post_unmap_err == 0;
        let seal_write_after_unmap_seals_has_write =
            s_post_unmap == F_SEAL_WRITE && err_s_post_unmap == 0;
        let seal_write_new_shared_rw_map_eperm =
            map_shared_rw_after == libc::MAP_FAILED && map_shared_rw_err == libc::EPERM;
        let seal_write_new_shared_ro_map_ok = guard_shared_ro.is_valid();
        let seal_write_new_private_rw_map_ok = guard_priv_rw.is_valid();

        // 8. F_SEAL_SEAL prevents any subsequent seals from being added.
        let fd_seal = FdGuard::new(sys_memfd_create(
            "sealseal",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let seal_subcase_ok = fd_seal.is_valid();
        let (add_shrink_rc3, add_shrink_err3) = if seal_subcase_ok {
            add_seals(fd_seal.get(), F_SEAL_SHRINK)
        } else {
            (-1, -1)
        };
        let (s_pre_seal, err_pre_seal) = if seal_subcase_ok {
            get_seals(fd_seal.get())
        } else {
            (-1, -1)
        };
        let (add_seal_rc, add_seal_err) = if seal_subcase_ok {
            add_seals(fd_seal.get(), F_SEAL_SEAL)
        } else {
            (-1, -1)
        };
        let (s_post_seal, err_post_seal) = if seal_subcase_ok {
            get_seals(fd_seal.get())
        } else {
            (-1, -1)
        };
        let (add_grow_blocked_rc, add_grow_blocked_err) = if seal_subcase_ok {
            add_seals(fd_seal.get(), F_SEAL_GROW)
        } else {
            (0, 0)
        };
        let (add_write_blocked_rc, add_write_blocked_err) = if seal_subcase_ok {
            add_seals(fd_seal.get(), F_SEAL_WRITE)
        } else {
            (0, 0)
        };
        let (add_seal_blocked_rc, add_seal_blocked_err) = if seal_subcase_ok {
            add_seals(fd_seal.get(), F_SEAL_SEAL)
        } else {
            (0, 0)
        };
        let (s_final_seal, err_final_seal) = if seal_subcase_ok {
            get_seals(fd_seal.get())
        } else {
            (-1, -1)
        };

        let seal_seal_pre_shrink_ok = add_shrink_rc3 == 0
            && add_shrink_err3 == 0
            && s_pre_seal == F_SEAL_SHRINK
            && err_pre_seal == 0;
        let seal_seal_added_ok = add_seal_rc == 0
            && add_seal_err == 0
            && s_post_seal == (F_SEAL_SHRINK | F_SEAL_SEAL)
            && err_post_seal == 0;
        let seal_seal_blocks_add_grow_eperm =
            add_grow_blocked_rc == -1 && add_grow_blocked_err == libc::EPERM;
        let seal_seal_blocks_add_write_eperm =
            add_write_blocked_rc == -1 && add_write_blocked_err == libc::EPERM;
        let seal_seal_blocks_readd_seal_eperm =
            add_seal_blocked_rc == -1 && add_seal_blocked_err == libc::EPERM;
        let seal_seal_final_seals_unchanged =
            s_final_seal == (F_SEAL_SHRINK | F_SEAL_SEAL) && err_final_seal == 0;

        // 9. Exact F_GET_SEALS transitions and duplicated-fd shared state.
        let fd_orig = FdGuard::new(sys_memfd_create("sealdup", MFD_ALLOW_SEALING | MFD_CLOEXEC));
        let mut dup_subcase_ok = fd_orig.is_valid();
        if dup_subcase_ok {
            dup_subcase_ok = libc::ftruncate(fd_orig.get(), 4096) == 0;
        }
        let fd_dup = if dup_subcase_ok {
            FdGuard::new(libc::dup(fd_orig.get()))
        } else {
            FdGuard::new(-1)
        };
        let dup_created = fd_dup.is_valid();

        let (s_orig_0, err_orig_0) = if dup_created {
            get_seals(fd_orig.get())
        } else {
            (-1, -1)
        };
        let (s_dup_0, err_dup_0) = if dup_created {
            get_seals(fd_dup.get())
        } else {
            (-1, -1)
        };

        // Add F_SEAL_GROW via original fd
        let (add_grow_via_orig_rc, add_grow_via_orig_err) = if dup_created {
            add_seals(fd_orig.get(), F_SEAL_GROW)
        } else {
            (-1, -1)
        };
        let (s_orig_1, err_orig_1) = if dup_created {
            get_seals(fd_orig.get())
        } else {
            (-1, -1)
        };
        let (s_dup_1, err_dup_1) = if dup_created {
            get_seals(fd_dup.get())
        } else {
            (-1, -1)
        };

        // Add F_SEAL_SHRINK via duplicated fd
        let (add_shrink_via_dup_rc, add_shrink_via_dup_err) = if dup_created {
            add_seals(fd_dup.get(), F_SEAL_SHRINK)
        } else {
            (-1, -1)
        };
        let (s_orig_2, err_orig_2) = if dup_created {
            get_seals(fd_orig.get())
        } else {
            (-1, -1)
        };
        let (s_dup_2, err_dup_2) = if dup_created {
            get_seals(fd_dup.get())
        } else {
            (-1, -1)
        };

        // Test ftruncate enforcement across both fds
        let trunc_grow_via_dup_rc = if dup_created {
            libc::ftruncate(fd_dup.get(), 8192)
        } else {
            0
        };
        let trunc_grow_via_dup_err = errno();
        let trunc_shrink_via_orig_rc = if dup_created {
            libc::ftruncate(fd_orig.get(), 2048)
        } else {
            0
        };
        let trunc_shrink_via_orig_err = errno();

        let dup_initial_both_empty =
            s_orig_0 == 0 && err_orig_0 == 0 && s_dup_0 == 0 && err_dup_0 == 0;
        let dup_grow_visible_on_both = add_grow_via_orig_rc == 0
            && add_grow_via_orig_err == 0
            && s_orig_1 == F_SEAL_GROW
            && err_orig_1 == 0
            && s_dup_1 == F_SEAL_GROW
            && err_dup_1 == 0;
        let dup_shrink_visible_on_both = add_shrink_via_dup_rc == 0
            && add_shrink_via_dup_err == 0
            && s_orig_2 == (F_SEAL_GROW | F_SEAL_SHRINK)
            && err_orig_2 == 0
            && s_dup_2 == (F_SEAL_GROW | F_SEAL_SHRINK)
            && err_dup_2 == 0;
        let dup_grow_enforced_on_dup =
            trunc_grow_via_dup_rc == -1 && trunc_grow_via_dup_err == libc::EPERM;
        let dup_shrink_enforced_on_orig =
            trunc_shrink_via_orig_rc == -1 && trunc_shrink_via_orig_err == libc::EPERM;

        // 10. F_SEAL_FUTURE_WRITE allows addition with active shared writable mapping,
        //     permits writes through pre-existing mapping, but blocks new write/pwrite calls
        //     and new MAP_SHARED + PROT_WRITE mappings.
        let fd_future = FdGuard::new(sys_memfd_create(
            "sealfuturewrite",
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        ));
        let mut future_subcase_ok = fd_future.is_valid();
        if future_subcase_ok {
            future_subcase_ok = libc::ftruncate(fd_future.get(), 4096) == 0;
        }

        let existing_map_ptr = if future_subcase_ok {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd_future.get(),
                0,
            )
        } else {
            libc::MAP_FAILED
        };
        let existing_map_guard = MmapGuard::new(existing_map_ptr, 4096);
        let existing_map_created = existing_map_guard.is_valid();

        // Adding F_SEAL_FUTURE_WRITE succeeds even with active shared writable mapping
        let (add_future_rc, add_future_err) = if existing_map_created {
            add_seals(fd_future.get(), F_SEAL_FUTURE_WRITE)
        } else {
            (-1, -1)
        };
        let (s_future, err_s_future) = if existing_map_created {
            get_seals(fd_future.get())
        } else {
            (-1, -1)
        };

        // Write through the pre-existing shared mapping must succeed
        if existing_map_created {
            core::ptr::write_volatile(existing_map_guard.as_mut_ptr(), 0x77);
        }
        let existing_mmap_write_ok = if existing_map_created {
            core::ptr::read_volatile(existing_map_guard.as_mut_ptr()) == 0x77
        } else {
            false
        };

        // New write/pwrite must return EPERM
        let future_buf = [0x33u8; 4];
        let future_pwrite_rc = if existing_map_created {
            libc::pwrite(
                fd_future.get(),
                future_buf.as_ptr() as *const libc::c_void,
                future_buf.len(),
                0,
            )
        } else {
            0
        };
        let future_pwrite_err = errno();
        let future_write_rc = if existing_map_created {
            libc::write(
                fd_future.get(),
                future_buf.as_ptr() as *const libc::c_void,
                future_buf.len(),
            )
        } else {
            0
        };
        let future_write_err = errno();

        // New MAP_SHARED + PROT_WRITE must fail with EPERM
        let new_map_shared_rw_future = if existing_map_created {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd_future.get(),
                0,
            )
        } else {
            core::ptr::null_mut()
        };
        let new_map_shared_rw_future_err = errno();
        let _guard_new_shared_rw_future = MmapGuard::new(new_map_shared_rw_future, 4096);

        // pread must still work
        let mut future_read_buf = [0u8; 1];
        let future_pread_rc = if existing_map_created {
            libc::pread(
                fd_future.get(),
                future_read_buf.as_mut_ptr() as *mut libc::c_void,
                1,
                0,
            )
        } else {
            -1
        };

        drop(existing_map_guard);

        let seal_future_write_add_with_active_map_ok = add_future_rc == 0 && add_future_err == 0;
        let seal_future_write_seals_has_future_write =
            s_future == F_SEAL_FUTURE_WRITE && err_s_future == 0;
        let seal_future_write_existing_mmap_write_ok = existing_mmap_write_ok;
        let seal_future_write_pwrite_eperm =
            future_pwrite_rc == -1 && future_pwrite_err == libc::EPERM;
        let seal_future_write_write_eperm =
            future_write_rc == -1 && future_write_err == libc::EPERM;
        let seal_future_write_new_shared_rw_map_eperm = new_map_shared_rw_future
            == libc::MAP_FAILED
            && new_map_shared_rw_future_err == libc::EPERM;
        let seal_future_write_pread_ok = future_pread_rc == 1 && future_read_buf[0] == 0x77;

        report!(
            noseal_initial_seal = noseal_initial_seal,
            noseal_add_shrink_eperm = noseal_add_shrink_eperm,
            noseal_add_grow_eperm = noseal_add_grow_eperm,
            noseal_add_write_eperm = noseal_add_write_eperm,
            noseal_seals_unchanged = noseal_seals_unchanged,
            allow_sealing_initial_empty = allow_sealing_initial_empty,
            seal_grow_added = seal_grow_added,
            seal_grow_prevents_grow = seal_grow_prevents_grow,
            seal_grow_allows_same_size = seal_grow_allows_same_size,
            seal_grow_allows_shrink = seal_grow_allows_shrink,
            seal_grow_prevents_grow_back = seal_grow_prevents_grow_back,
            seal_grow_pwrite_past_eof_eperm = seal_grow_pwrite_past_eof_eperm,
            seal_grow_pwrite_within_size_ok = seal_grow_pwrite_within_size_ok,
            seal_shrink_added = seal_shrink_added,
            seal_shrink_prevents_shrink = seal_shrink_prevents_shrink,
            seal_shrink_allows_same_size = seal_shrink_allows_same_size,
            seal_shrink_allows_grow = seal_shrink_allows_grow,
            seal_shrink_prevents_shrink_back = seal_shrink_prevents_shrink_back,
            seal_fixed_added = seal_fixed_added,
            seal_fixed_prevents_grow = seal_fixed_prevents_grow,
            seal_fixed_prevents_shrink = seal_fixed_prevents_shrink,
            seal_fixed_allows_same_size = seal_fixed_allows_same_size,
            seal_write_added = seal_write_added,
            seal_write_pwrite_eperm = seal_write_pwrite_eperm,
            seal_write_write_eperm = seal_write_write_eperm,
            seal_write_pread_ok = seal_write_pread_ok,
            seal_write_active_shared_mmap_ebusy = seal_write_active_shared_mmap_ebusy,
            seal_write_ebusy_seals_unchanged = seal_write_ebusy_seals_unchanged,
            seal_write_active_mmap_writable = seal_write_active_mmap_writable,
            seal_write_after_unmap_ok = seal_write_after_unmap_ok,
            seal_write_after_unmap_seals_has_write = seal_write_after_unmap_seals_has_write,
            seal_write_new_shared_rw_map_eperm = seal_write_new_shared_rw_map_eperm,
            seal_write_new_shared_ro_map_ok = seal_write_new_shared_ro_map_ok,
            seal_write_new_private_rw_map_ok = seal_write_new_private_rw_map_ok,
            seal_seal_pre_shrink_ok = seal_seal_pre_shrink_ok,
            seal_seal_added_ok = seal_seal_added_ok,
            seal_seal_blocks_add_grow_eperm = seal_seal_blocks_add_grow_eperm,
            seal_seal_blocks_add_write_eperm = seal_seal_blocks_add_write_eperm,
            seal_seal_blocks_readd_seal_eperm = seal_seal_blocks_readd_seal_eperm,
            seal_seal_final_seals_unchanged = seal_seal_final_seals_unchanged,
            dup_initial_both_empty = dup_initial_both_empty,
            dup_grow_visible_on_both = dup_grow_visible_on_both,
            dup_shrink_visible_on_both = dup_shrink_visible_on_both,
            dup_grow_enforced_on_dup = dup_grow_enforced_on_dup,
            dup_shrink_enforced_on_orig = dup_shrink_enforced_on_orig,
            seal_future_write_add_with_active_map_ok = seal_future_write_add_with_active_map_ok,
            seal_future_write_seals_has_future_write = seal_future_write_seals_has_future_write,
            seal_future_write_existing_mmap_write_ok = seal_future_write_existing_mmap_write_ok,
            seal_future_write_pwrite_eperm = seal_future_write_pwrite_eperm,
            seal_future_write_write_eperm = seal_future_write_write_eperm,
            seal_future_write_new_shared_rw_map_eperm = seal_future_write_new_shared_rw_map_eperm,
            seal_future_write_pread_ok = seal_future_write_pread_ok,
        );

        disarm_alarm();
    }
}
