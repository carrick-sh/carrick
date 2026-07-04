use conformance_probes::report;

const IPC_RMID: i32 = 0;
const SHM_STAT_ANY: i32 = 15;
const SHM_INFO: i32 = 14;
const SHM_RDONLY: i32 = 0o10000;
const SHM_RND: i32 = 0o20000;
const SYS_REMAP_FILE_PAGES: libc::c_long = 234;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn reset_errno() {
    #[cfg(any(target_env = "gnu", target_env = "musl"))]
    {
        *libc::__errno_location() = 0;
    }
}

unsafe fn cleanup_shm(shmid: i32) {
    if shmid >= 0 {
        libc::shmctl(shmid, IPC_RMID, core::ptr::null_mut());
    }
}

fn child_write_signal(addr: *mut libc::c_void) -> i32 {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            *(addr as *mut u8) = 1;
            libc::_exit(0);
        }
        let mut status = 0;
        libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
        if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        }
    }
}

fn child_attach_status(shmid: i32, addr: *mut libc::c_void) -> i32 {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            reset_errno();
            let attached = libc::shmat(shmid, addr.cast_const(), 0);
            if attached == addr {
                libc::shmdt(attached);
                libc::_exit(0);
            }
            let err = errno().clamp(0, 127);
            libc::_exit(err);
        }
        let mut status = 0;
        libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        }
    }
}

fn main() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let scratch = libc::shmget(libc::IPC_PRIVATE, page, libc::IPC_CREAT | 0o600);
        let scratch_addr = if scratch >= 0 {
            libc::shmat(scratch, core::ptr::null(), 0)
        } else {
            libc::MAP_FAILED
        };
        let reusable_addr = if scratch_addr == libc::MAP_FAILED {
            core::ptr::null_mut()
        } else {
            libc::shmdt(scratch_addr);
            scratch_addr
        };
        cleanup_shm(scratch);

        let shmid = libc::shmget(libc::IPC_PRIVATE, page, libc::IPC_CREAT | 0o600);

        let null_addr = if shmid >= 0 {
            libc::shmat(shmid, core::ptr::null(), 0)
        } else {
            libc::MAP_FAILED
        };
        let null_attach_ok = null_addr != libc::MAP_FAILED;
        if null_attach_ok {
            libc::shmdt(null_addr);
        }

        reset_errno();
        let aligned_addr = if shmid >= 0 && !reusable_addr.is_null() {
            libc::shmat(shmid, reusable_addr.cast_const(), 0)
        } else {
            libc::MAP_FAILED
        };
        let aligned_errno = errno();
        let aligned_attach_ok = aligned_addr == reusable_addr;
        if aligned_addr != libc::MAP_FAILED {
            libc::shmdt(aligned_addr);
        }

        let child_aligned_status = if shmid >= 0 && !reusable_addr.is_null() {
            child_attach_status(shmid, reusable_addr)
        } else {
            -1
        };

        reset_errno();
        let rounded_addr = if shmid >= 0 && !reusable_addr.is_null() {
            libc::shmat(shmid, reusable_addr.wrapping_add(page - 1).cast_const(), SHM_RND)
        } else {
            libc::MAP_FAILED
        };
        let rounded_errno = errno();
        let rounded_attach_ok = rounded_addr == reusable_addr;
        if rounded_addr != libc::MAP_FAILED {
            libc::shmdt(rounded_addr);
        }

        reset_errno();
        let readonly_addr = if shmid >= 0 && !reusable_addr.is_null() {
            libc::shmat(shmid, reusable_addr.cast_const(), SHM_RDONLY)
        } else {
            libc::MAP_FAILED
        };
        let readonly_errno = errno();
        let readonly_signal = if readonly_addr == libc::MAP_FAILED {
            -1
        } else {
            let sig = child_write_signal(readonly_addr);
            libc::shmdt(readonly_addr);
            sig
        };

        let mut shm_info = [0u8; 128];
        reset_errno();
        let max_index = libc::shmctl(shmid, SHM_INFO, shm_info.as_mut_ptr().cast());
        let shm_info_errno = errno();

        let mut shmid_ds = core::mem::MaybeUninit::<libc::shmid_ds>::zeroed();
        reset_errno();
        let stat_any = if max_index >= 0 {
            libc::shmctl(max_index, SHM_STAT_ANY, shmid_ds.as_mut_ptr())
        } else {
            -1
        };
        let stat_any_errno = errno();

        reset_errno();
        let remap_invalid = libc::syscall(SYS_REMAP_FILE_PAGES, 0, 0, 0, 0, 0);
        let remap_invalid_errno = errno();

        cleanup_shm(shmid);

        report!(
            null_attach_ok = null_attach_ok,
            aligned_attach_ok = aligned_attach_ok,
            aligned_errno = aligned_errno,
            child_aligned_status = child_aligned_status,
            rounded_attach_ok = rounded_attach_ok,
            rounded_errno = rounded_errno,
            readonly_errno = readonly_errno,
            readonly_signal = readonly_signal,
            shm_info_ok = max_index >= 0,
            shm_info_errno = shm_info_errno,
            stat_any_ok = stat_any >= 0,
            stat_any_errno = stat_any_errno,
            remap_invalid = remap_invalid,
            remap_invalid_errno = remap_invalid_errno,
        );
    }
}
