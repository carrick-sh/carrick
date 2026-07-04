use conformance_probes::report;

const IPC_RMID: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_INFO: i32 = 19;
const SEM_STAT_ANY: i32 = 20;
const SYS_SEMGET: libc::c_long = libc::SYS_semget as libc::c_long;
const SYS_SEMCTL: libc::c_long = libc::SYS_semctl as libc::c_long;
const SYS_SEMOP: libc::c_long = libc::SYS_semop as libc::c_long;
const SYS_SEMTIMEDOP: libc::c_long = libc::SYS_semtimedop as libc::c_long;

#[repr(C)]
struct Sembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn reset_errno() {
    #[cfg(any(target_env = "gnu", target_env = "musl"))]
    {
        *libc::__errno_location() = 0;
    }
}

unsafe fn semctl(semid: i32, semnum: i32, cmd: i32, arg: *mut libc::c_void) -> i64 {
    libc::syscall(
        SYS_SEMCTL,
        semid as libc::c_long,
        semnum as libc::c_long,
        cmd as libc::c_long,
        arg,
    ) as i64
}

unsafe fn wait_child_success(pid: libc::pid_t) -> bool {
    let mut status = 0;
    for _ in 0..40 {
        let waited = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if waited == pid {
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        libc::nanosleep(&req, core::ptr::null_mut());
    }
    libc::kill(pid, libc::SIGKILL);
    libc::waitpid(pid, &mut status, 0);
    false
}

unsafe fn semop_rmid_wakes_child(sem_num: u16, initial_value: i32, sem_op: i16) -> bool {
    let nsems = i32::from(sem_num) + 1;
    let semid = libc::syscall(
        SYS_SEMGET,
        libc::IPC_PRIVATE,
        nsems,
        IPC_CREAT | 0o600,
    ) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, i32::from(sem_num), SETVAL, initial_value as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }
    let pid = libc::fork();
    if pid == 0 {
        reset_errno();
        let mut decrement = Sembuf {
            sem_num,
            sem_op,
            sem_flg: 0,
        };
        let ret = libc::syscall(SYS_SEMOP, semid, &mut decrement, 1) as i64;
        let ok = ret == -1 && errno() == libc::EIDRM;
        libc::_exit(if ok { 0 } else { 1 });
    }
    if pid < 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    libc::nanosleep(&req, core::ptr::null_mut());
    let removed = semctl(semid, 0, IPC_RMID, core::ptr::null_mut()) == 0;
    removed && wait_child_success(pid)
}

fn proc_state(pid: libc::pid_t) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?;
    after_comm.1.chars().next()
}

unsafe fn semop_zero_wait_child_reports_sleeping() -> bool {
    let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 3, IPC_CREAT | 0o600) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, 2, SETVAL, 1usize as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    let pid = libc::fork();
    if pid == 0 {
        let mut wait_zero = Sembuf {
            sem_num: 2,
            sem_op: 0,
            sem_flg: 0,
        };
        let _ = libc::syscall(SYS_SEMOP, semid, &mut wait_zero, 1);
        libc::_exit(0);
    }
    if pid < 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    let mut saw_sleeping = false;
    for _ in 0..40 {
        if proc_state(pid) == Some('S') {
            saw_sleeping = true;
            break;
        }
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        libc::nanosleep(&req, core::ptr::null_mut());
    }

    semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
    let _ = wait_child_success(pid);
    saw_sleeping
}

unsafe extern "C" fn handle_hup(_sig: i32) {}

unsafe fn install_hup_handler() {
    let mut action: libc::sigaction = core::mem::zeroed();
    action.sa_sigaction = handle_hup as usize;
    libc::sigemptyset(&mut action.sa_mask);
    action.sa_flags = 0;
    libc::sigaction(libc::SIGHUP, &action, core::ptr::null_mut());
}

unsafe fn semtimedop_interrupted_by_rmid() -> bool {
    let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 3, IPC_CREAT | 0o600) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, 2, SETVAL, 1usize as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    let pid = libc::fork();
    if pid == 0 {
        reset_errno();
        let mut wait_zero = Sembuf {
            sem_num: 2,
            sem_op: 0,
            sem_flg: 0,
        };
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(SYS_SEMTIMEDOP, semid, &mut wait_zero, 1, &timeout) as i64;
        let ok = ret == -1 && errno() == libc::EIDRM;
        libc::_exit(if ok { 0 } else { 1 });
    }
    if pid < 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    for _ in 0..40 {
        if proc_state(pid) == Some('S') {
            break;
        }
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        libc::nanosleep(&req, core::ptr::null_mut());
    }
    semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
    wait_child_success(pid)
}

unsafe fn semtimedop_interrupted_by_signal() -> bool {
    let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 3, IPC_CREAT | 0o600) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, 2, SETVAL, 1usize as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    let pid = libc::fork();
    if pid == 0 {
        install_hup_handler();
        reset_errno();
        let mut wait_zero = Sembuf {
            sem_num: 2,
            sem_op: 0,
            sem_flg: 0,
        };
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(SYS_SEMTIMEDOP, semid, &mut wait_zero, 1, &timeout) as i64;
        let ok = ret == -1 && errno() == libc::EINTR;
        libc::_exit(if ok { 0 } else { 1 });
    }
    if pid < 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    for _ in 0..40 {
        if proc_state(pid) == Some('S') {
            break;
        }
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        libc::nanosleep(&req, core::ptr::null_mut());
    }
    libc::kill(pid, libc::SIGHUP);
    let ok = wait_child_success(pid);
    semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
    ok
}

unsafe fn semop_positive_overflow_erange() -> bool {
    let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, 0, SETVAL, 1usize as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    reset_errno();
    let mut increment = Sembuf {
        sem_num: 0,
        sem_op: i16::MAX,
        sem_flg: 0,
    };
    let ret = libc::syscall(SYS_SEMOP, semid, &mut increment, 1) as i64;
    let value = semctl(semid, 0, GETVAL, core::ptr::null_mut());
    semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
    ret == -1 && errno() == libc::ERANGE && value == 1
}

unsafe fn semtimedop_positive_overflow_erange() -> bool {
    let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
    if semid < 0 {
        return false;
    }
    if semctl(semid, 0, SETVAL, 1usize as *mut libc::c_void) != 0 {
        semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        return false;
    }

    reset_errno();
    let mut increment = Sembuf {
        sem_num: 0,
        sem_op: i16::MAX,
        sem_flg: 0,
    };
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let ret = libc::syscall(SYS_SEMTIMEDOP, semid, &mut increment, 1, &timeout) as i64;
    let value = semctl(semid, 0, GETVAL, core::ptr::null_mut());
    semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
    ret == -1 && errno() == libc::ERANGE && value == 1
}

unsafe fn semctl_rmid_owner_ignores_mode() -> bool {
    let pid = libc::fork();
    if pid == 0 {
        if libc::setuid(65_534) != 0 {
            libc::_exit(2);
        }
        let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 1, IPC_CREAT) as i32;
        if semid < 0 {
            libc::_exit(3);
        }
        let ok = semctl(semid, 0, IPC_RMID, core::ptr::null_mut()) == 0;
        libc::_exit(if ok { 0 } else { 1 });
    }
    if pid < 0 {
        return false;
    }
    wait_child_success(pid)
}

fn main() {
    unsafe {
        reset_errno();
        let first = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
        let semid = libc::syscall(SYS_SEMGET, libc::IPC_PRIVATE, 2, IPC_CREAT | 0o600) as i32;
        let semget_ok = semid >= 0;
        let semget_errno = errno();
        if first >= 0 {
            semctl(first, 0, IPC_RMID, core::ptr::null_mut());
        }

        let mut info = [0u8; 64];
        reset_errno();
        let info_ret = semctl(0, 0, SEM_INFO, info.as_mut_ptr().cast());
        let info_errno = errno();

        let mut ds = [0u8; 128];
        reset_errno();
        let hole_ret = semctl(0, 0, SEM_STAT_ANY, ds.as_mut_ptr().cast());
        let hole_errno = errno();

        reset_errno();
        let stat_ret = semctl(info_ret as i32, 0, SEM_STAT_ANY, ds.as_mut_ptr().cast());
        let stat_errno = errno();
        let sem_nsems = u64::from_le_bytes([
            ds[64], ds[65], ds[66], ds[67], ds[68], ds[69], ds[70], ds[71],
        ]);

        reset_errno();
        let setval_ret = semctl(semid, 0, SETVAL, 5usize as *mut libc::c_void);
        let getval_ret = semctl(semid, 0, GETVAL, core::ptr::null_mut());

        let setall_values = [3u16, 7u16];
        let mut getall_values = [0u16; 2];
        let setall_ret = semctl(semid, 0, SETALL, setall_values.as_ptr().cast_mut().cast());
        let getall_ret = semctl(semid, 0, GETALL, getall_values.as_mut_ptr().cast());

        let mut decrement = Sembuf {
            sem_num: 0,
            sem_op: -2,
            sem_flg: 0,
        };
        let semop_ret = libc::syscall(SYS_SEMOP, semid, &mut decrement, 1) as i64;
        let semop_value = semctl(semid, 0, GETVAL, core::ptr::null_mut());

        reset_errno();
        let e2big_ret = libc::syscall(SYS_SEMOP, semid, core::ptr::null::<u8>(), 501) as i64;
        let e2big_errno = errno();

        let proc_sem = std::fs::read_to_string("/proc/sysvipc/sem").unwrap_or_default();

        if semget_ok {
            semctl(semid, 0, IPC_RMID, core::ptr::null_mut());
        }
        let decrement_rmid_wakes = semop_rmid_wakes_child(0, 0, -1);
        let zero_wait_rmid_wakes = semop_rmid_wakes_child(2, 1, 0);
        let zero_wait_sleeping = semop_zero_wait_child_reports_sleeping();
        let timed_rmid = semtimedop_interrupted_by_rmid();
        let timed_signal = semtimedop_interrupted_by_signal();
        let semop_overflow = semop_positive_overflow_erange();
        let timed_overflow = semtimedop_positive_overflow_erange();
        let rmid_ignores_mode = semctl_rmid_owner_ignores_mode();

        report!(semget_ok = semget_ok);
        report!(semget_errno = semget_errno);
        report!(sem_info_ok = info_ret >= 0);
        report!(sem_info_scan_bound_ok = info_ret >= 1);
        report!(sem_info_errno = info_errno);
        report!(sem_stat_hole_ok = hole_ret == -1 && hole_errno == libc::EINVAL);
        report!(sem_stat_any_ok = stat_ret == semid as i64);
        report!(sem_stat_any_errno = stat_errno);
        report!(sem_stat_nsems_ok = sem_nsems == 2);
        report!(setval_getval = setval_ret == 0 && getval_ret == 5);
        report!(
            setall_getall = setall_ret == 0 && getall_ret == 0 && getall_values == [3, 7]
        );
        report!(semop_decrement = semop_ret == 0 && semop_value == 1);
        report!(semop_e2big_ret = e2big_ret);
        report!(semop_e2big_errno = e2big_errno);
        report!(semop_decrement_rmid_wakes = decrement_rmid_wakes);
        report!(semop_zero_wait_rmid_wakes = zero_wait_rmid_wakes);
        report!(semop_zero_wait_child_sleeping = zero_wait_sleeping);
        report!(semtimedop_rmid_eidrm = timed_rmid);
        report!(semtimedop_signal_eintr = timed_signal);
        report!(semop_positive_overflow_erange = semop_overflow);
        report!(semtimedop_positive_overflow_erange = timed_overflow);
        report!(semctl_rmid_owner_ignores_mode = rmid_ignores_mode);
        report!(proc_sysvipc_sem_present = proc_sem.contains("semid"));
    }
}
