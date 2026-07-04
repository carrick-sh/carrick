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
        report!(proc_sysvipc_sem_present = proc_sem.contains("semid"));
    }
}
