//! Host-process introspection for synthesising `/proc/<pid>/` of carrick guest
//! processes. carrick forks each guest process as a real macOS process and the
//! guest pid IS the host pid (the trees mirror), so the host kernel — queried
//! via libproc `proc_pidinfo` — is the source of truth for another guest
//! process's state and identity. We never expose a process that is not one of
//! our own descendants (validated by walking the ppid chain up to this
//! process), so a guest can't probe arbitrary host processes.

/// Host pid of the ROOT guest process, recorded once at startup before any
/// guest fork. A pid is a "guest process" (and thus exposable via `/proc`) iff
/// its host ppid chain reaches this. 0 = unset (single-process `run-elf`, where
/// the per-process self check suffices).
static ROOT_GUEST_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Record the root guest's host pid (called once at carrick startup).
pub fn set_root_guest_pid(pid: u32) {
    ROOT_GUEST_PID.store(pid, std::sync::atomic::Ordering::Relaxed);
}

/// Identity + state of a guest process, read from the host kernel.
#[derive(Debug, Clone)]
pub struct GuestProcInfo {
    /// Linux `/proc/<pid>/stat` state char (`R`/`S`/`T`/`Z`).
    pub state: char,
    pub ppid: u32,
    pub pgid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Short command name (max 15 chars, like Linux `comm`).
    pub comm: String,
}

/// Process resource usage, read from the host kernel — the source of truth for
/// `getrusage`/`times`/`/proc/<pid>/stat` CPU accounting and `/proc/statm` /
/// `/proc/<pid>/status` memory accounting. Times are microseconds; sizes bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceUsage {
    /// CPU time this process spent in user mode (all threads, live + reaped).
    pub user_us: u64,
    /// CPU time this process spent in the kernel on its behalf.
    pub system_us: u64,
    /// User-mode CPU time of reaped children (for RUSAGE_CHILDREN / tms_cutime).
    pub child_user_us: u64,
    pub child_system_us: u64,
    /// Current resident set size (physical footprint).
    pub resident_bytes: u64,
    /// Peak resident set size (Linux `ru_maxrss`, reported in KiB).
    pub maxrss_bytes: u64,
    /// Current virtual address space size.
    pub virtual_bytes: u64,
    /// Major faults (page-ins from backing store).
    pub majflt: u64,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{GuestProcInfo, ResourceUsage};

    /// Map a macOS process status (`pbi_status`) to the Linux stat state char.
    /// The tests only distinguish "sleeping in a syscall" (`S`) from "running"
    /// (`R`); a guest blocked in pause()/futex parks carrick's run loop in a
    /// host syscall, so the host reports `SSLEEP`.
    fn state_char(pbi_status: u32) -> char {
        // libc's S* status constants vary in signedness across versions; widen
        // both sides so the comparison is type-agnostic.
        let s = pbi_status as i64;
        if s == libc::SSLEEP as i64 {
            'S'
        } else if s == libc::SSTOP as i64 {
            'T'
        } else if s == libc::SZOMB as i64 {
            'Z'
        } else {
            // SRUN and SIDL (and anything unexpected) → running.
            'R'
        }
    }

    fn comm_from(buf: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Extract the guest task name carrick stamped into a process's proctitle
    /// (`argv[0]`): `carrick:<run-id>: <name>` or `carrick: <name>` (see
    /// `carrick_runtime::dispatch::proctitle::proc_label`). Returns `<name>` —
    /// the part after the last `": "` — truncated to Linux's 15-byte comm, or
    /// `None` when the title carries no guest name. carrick does not host-exec,
    /// so the macOS `pbi_comm` is always "carrick"; the proctitle is the only
    /// cross-process channel that carries a sibling guest's real command, so a
    /// `/proc/<pid>/comm` read can show "sleep"/"bash" instead of "carrick".
    pub(super) fn parse_proctitle_name(argv0: &str) -> Option<String> {
        if !argv0.contains(": ") {
            return None;
        }
        let name = argv0.rsplit(": ").next()?.trim();
        if name.is_empty() || name == "carrick" {
            return None;
        }
        Some(name.chars().take(15).collect())
    }

    /// Read `pid`'s `argv[0]` (the proctitle) via `KERN_PROCARGS2` and pull the
    /// guest task name from it. Same-user processes (all carrick guests) are
    /// readable. `None` on any failure or unexpected layout.
    fn proctitle_comm(pid: u32) -> Option<String> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let mut size: libc::size_t = 0;
        // SAFETY: size query with a null oldp is the documented sysctl idiom.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
            || size < 4
        {
            return None;
        }
        let mut buf = vec![0u8; size];
        // SAFETY: buf holds `size` bytes; sysctl writes at most that many.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(size);
        // Layout: [argc:i32][exec_path\0][\0…padding][argv0\0][argv1\0]…[envp…].
        let mut i = 4usize;
        while i < buf.len() && buf[i] != 0 {
            i += 1; // skip exec_path
        }
        while i < buf.len() && buf[i] == 0 {
            i += 1; // skip padding NULs before argv[0]
        }
        let start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1; // argv[0] (the proctitle)
        }
        let argv0 = std::str::from_utf8(buf.get(start..i)?).ok()?;
        parse_proctitle_name(argv0)
    }

    /// Fetch a pid's BSD info via `proc_pidinfo(PROC_PIDTBSDINFO)`. `None` if the
    /// pid doesn't exist or isn't inspectable.
    fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; we pass
        // the matching size and a zeroed, correctly-typed buffer.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info)
    }

    /// Aggregate Linux state char from the process's THREAD run states. macOS
    /// `pbi_status` is process-level and stays `SRUN` for any live process
    /// (sleeping is a per-thread concept), so it can't tell whether the guest
    /// is blocked. Instead enumerate threads (PROC_PIDLISTTHREADS) and read
    /// each thread's `pth_run_state` (PROC_PIDTHREADINFO): if any thread is
    /// RUNNING the process is `'R'`; if all are WAITING/HALTED it's `'S'`
    /// (a guest blocked in a syscall parks every carrick thread — the vCPU in
    /// kevent and the signal pump in its own kevent). Falls back to the
    /// process status if thread enumeration fails.
    fn aggregate_thread_state(pid: u32, fallback_status: u32) -> char {
        // PROC_PIDLISTTHREADS isn't exported by the libc crate (sys/proc_info.h
        // value 6); the array it fills is u64 thread handles.
        const PROC_PIDLISTTHREADS: libc::c_int = 6;
        let mut handles = [0u64; 64];
        let cap = std::mem::size_of_val(&handles) as libc::c_int;
        // SAFETY: PROC_PIDLISTTHREADS writes an array of u64 thread handles.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDLISTTHREADS,
                0,
                handles.as_mut_ptr() as *mut libc::c_void,
                cap,
            )
        };
        if n <= 0 {
            return state_char(fallback_status);
        }
        let count = (n as usize / 8).min(handles.len());
        let mut any_running = false;
        let mut saw_thread = false;
        for &h in handles.iter().take(count) {
            let mut ti: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::proc_threadinfo>() as libc::c_int;
            // SAFETY: PROC_PIDTHREADINFO fills proc_threadinfo for thread `h`.
            let r = unsafe {
                libc::proc_pidinfo(
                    pid as libc::c_int,
                    libc::PROC_PIDTHREADINFO,
                    h,
                    &mut ti as *mut _ as *mut libc::c_void,
                    size,
                )
            };
            if r as usize != std::mem::size_of::<libc::proc_threadinfo>() {
                continue;
            }
            saw_thread = true;
            if ti.pth_run_state == libc::TH_STATE_RUNNING
                || ti.pth_run_state == libc::TH_STATE_UNINTERRUPTIBLE
            {
                any_running = true;
                break;
            }
        }
        if !saw_thread {
            state_char(fallback_status)
        } else if any_running {
            'R'
        } else {
            'S'
        }
    }

    /// Linux state char for a single host thread, read from the kernel via
    /// `thread_info(THREAD_BASIC_INFO)` — `run_state` tells us whether the
    /// thread is RUNNING or WAITING. Used for `/proc/<tid>/stat` of THIS
    /// process's threads, so we don't track a per-thread "sleeping" flag by
    /// hand (the kernel is the source of truth and covers every blocking path).
    /// `port` is the thread's mach port (from `pthread_mach_thread_np`).
    pub fn thread_run_state_char(port: libc::mach_port_t) -> char {
        let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: thread_info writes a thread_basic_info; we pass the matching
        // flavor + count and a correctly-typed zeroed buffer.
        let kr = unsafe {
            libc::thread_info(
                port,
                libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                &mut info as *mut _ as libc::thread_info_t,
                &mut count,
            )
        };
        if kr != libc::KERN_SUCCESS {
            return 'R';
        }
        match info.run_state {
            libc::TH_STATE_WAITING | libc::TH_STATE_HALTED => 'S',
            libc::TH_STATE_STOPPED => 'T',
            libc::TH_STATE_UNINTERRUPTIBLE => 'D',
            // TH_STATE_RUNNING and anything unexpected → running.
            _ => 'R',
        }
    }

    /// This thread's mach port (no ownership transfer — safe to store for the
    /// thread's lifetime without deallocating).
    pub fn current_thread_port() -> libc::mach_port_t {
        // SAFETY: pthread_mach_thread_np on the current pthread is always valid.
        unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) }
    }

    pub fn pid_info(pid: u32) -> Option<GuestProcInfo> {
        let info = bsdinfo(pid)?;
        Some(GuestProcInfo {
            state: aggregate_thread_state(pid, info.pbi_status),
            ppid: info.pbi_ppid,
            pgid: info.pbi_pgid,
            uid: info.pbi_uid,
            gid: info.pbi_gid,
            // Prefer the guest task name carrick stamped into the proctitle
            // ("sleep"/"bash"); the macOS pbi_comm is always the host binary
            // ("carrick") since carrick never host-execs the guest program.
            comm: proctitle_comm(pid).unwrap_or_else(|| comm_from(&info.pbi_comm)),
        })
    }

    /// True iff `pid` is a carrick GUEST process: walk its host ppid chain and
    /// see if it reaches the root guest pid (or this process — covers the
    /// single-process `run-elf` case where the root isn't recorded). Any guest
    /// process may read any other guest's `/proc` (LTP futex_wait02 has a child
    /// read its parent's stat), but a non-guest host process is never exposed.
    /// Bounded so a cycle / unexpected tree can't loop forever.
    pub fn is_guest_process(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let me = std::process::id();
        let root = super::ROOT_GUEST_PID.load(std::sync::atomic::Ordering::Relaxed);
        if pid == root {
            return true;
        }
        let mut cur = pid;
        for _ in 0..256 {
            let Some(info) = bsdinfo(cur) else {
                return false;
            };
            let pp = info.pbi_ppid;
            if pp == me || (root != 0 && pp == root) {
                return true;
            }
            if pp == 0 || pp == cur {
                return false;
            }
            cur = pp;
        }
        false
    }

    /// This process's resource usage, queried from the host kernel:
    /// `proc_pid_rusage(RUSAGE_INFO_V2)` for CPU time (live + reaped threads),
    /// child CPU time, resident size, pageins; `task_info(MACH_TASK_BASIC_INFO)`
    /// for the virtual size and peak RSS. carrick forks each guest as a real
    /// host process, so the calling guest IS this host process — `getpid()` and
    /// `mach_task_self()` name exactly the task whose usage Linux would report.
    // `mach_task_self_` is flagged deprecated by libc only to steer new code to
    // the `mach2` crate; the static is the canonical self-task port and still
    // works. carrick already uses libc's mach bindings (thread_info,
    // pthread_mach_thread_np) directly, so we stay consistent rather than add a
    // dependency for one constant.
    #[allow(deprecated)]
    pub fn self_resource_usage() -> Option<ResourceUsage> {
        let mut usage = ResourceUsage::default();

        let mut ri: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: proc_pid_rusage fills the rusage_info_v2 the `rusage_info_t*`
        // points at when given the V2 flavor. `rusage_info_t` is itself `void*`,
        // so the parameter is `void**`; the struct address cast to that type is
        // the buffer the kernel writes into. (Passing `&pointer_to_ri` instead
        // would make it write the struct over an 8-byte stack slot — a crash.)
        let rc = unsafe {
            libc::proc_pid_rusage(
                std::process::id() as libc::c_int,
                libc::RUSAGE_INFO_V2,
                &mut ri as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
            )
        };
        if rc == 0 {
            usage.user_us = ri.ri_user_time / 1000;
            usage.system_us = ri.ri_system_time / 1000;
            usage.child_user_us = ri.ri_child_user_time / 1000;
            usage.child_system_us = ri.ri_child_system_time / 1000;
            usage.resident_bytes = ri.ri_phys_footprint;
            usage.majflt = ri.ri_pageins;
        }

        let mut ti: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
        let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
        // SAFETY: task_info writes a mach_task_basic_info for the matching
        // flavor + count; `mach_task_self_` is the constant self task port
        // (read directly to avoid the deprecated `mach_task_self()` wrapper).
        let kr = unsafe {
            libc::task_info(
                libc::mach_task_self_,
                libc::MACH_TASK_BASIC_INFO,
                &mut ti as *mut _ as libc::task_info_t,
                &mut count,
            )
        };
        if kr == libc::KERN_SUCCESS {
            usage.virtual_bytes = ti.virtual_size;
            usage.maxrss_bytes = ti.resident_size_max;
            // If proc_pid_rusage was unavailable, fall back to the basic info's
            // resident size (current) for RSS.
            if usage.resident_bytes == 0 {
                usage.resident_bytes = ti.resident_size;
            }
        }

        if rc != 0 && kr != libc::KERN_SUCCESS {
            return None;
        }

        // HVF guest execution does not accrue to the host thread's rusage
        // (proc_pid_rusage above under-counts it ~40×), so the guest's user-mode
        // CPU time is sourced from the hypervisor's per-vCPU clock instead. We
        // ADD it to the user time and treat the host-side proc_pid_rusage time
        // (carrick's syscall handling) as the system component — the natural
        // Linux split of "guest userspace compute" vs "kernel work on its
        // behalf". A guest that has run no vCPU (pure host bootstrap) just keeps
        // the proc_pid_rusage user time.
        let guest_us = crate::guest_cpu::total_us();
        if guest_us > 0 {
            usage.user_us = usage.user_us.saturating_add(guest_us);
        }
        Some(usage)
    }

    /// (user_us, system_us) CPU time for the current thread, from
    /// `thread_info(THREAD_BASIC_INFO)`. Used by `getrusage(RUSAGE_THREAD)`.
    pub fn self_thread_cpu_us() -> Option<(u64, u64)> {
        let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: matching flavor/count and a zeroed buffer of the right type.
        let kr = unsafe {
            libc::thread_info(
                libc::pthread_mach_thread_np(libc::pthread_self()),
                libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                &mut info as *mut _ as libc::thread_info_t,
                &mut count,
            )
        };
        if kr != libc::KERN_SUCCESS {
            return None;
        }
        let to_us = |t: libc::time_value_t| t.seconds as u64 * 1_000_000 + t.microseconds as u64;
        Some((to_us(info.user_time), to_us(info.system_time)))
    }

    #[cfg(test)]
    mod proctitle_tests {
        use super::parse_proctitle_name;

        #[test]
        fn extracts_guest_name_after_last_colon_space() {
            // The two proctitle shapes carrick stamps (with / without a run id).
            assert_eq!(
                parse_proctitle_name("carrick:ctrlz-85929: sleep").as_deref(),
                Some("sleep")
            );
            assert_eq!(
                parse_proctitle_name("carrick: bash").as_deref(),
                Some("bash")
            );
        }

        #[test]
        fn declines_titles_with_no_guest_name() {
            // No ": " delimiter, or the name is just the host binary → fall back
            // to pbi_comm (None here) instead of reporting a bogus "carrick".
            assert_eq!(parse_proctitle_name("carrick"), None);
            assert_eq!(parse_proctitle_name("carrick:run-1: carrick"), None);
            assert_eq!(parse_proctitle_name("carrick:run-1: "), None);
        }

        #[test]
        fn truncates_to_linux_comm_length() {
            let got = parse_proctitle_name("carrick:x: averylongprocessname1234567").unwrap();
            assert!(
                got.chars().count() <= 15,
                "comm must fit Linux TASK_COMM_LEN"
            );
            assert!("averylongprocessname1234567".starts_with(&got));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{GuestProcInfo, ResourceUsage};
    pub fn pid_info(_pid: u32) -> Option<GuestProcInfo> {
        None
    }
    pub fn is_guest_process(_pid: u32) -> bool {
        false
    }
    pub fn thread_run_state_char(_port: u32) -> char {
        'R'
    }
    pub fn current_thread_port() -> u32 {
        0
    }
    pub fn self_resource_usage() -> Option<ResourceUsage> {
        None
    }
    pub fn self_thread_cpu_us() -> Option<(u64, u64)> {
        None
    }
}

pub use imp::{
    current_thread_port, is_guest_process, pid_info, self_resource_usage, self_thread_cpu_us,
    thread_run_state_char,
};

/// Mach port type alias for the registry (real on macOS, u32 elsewhere).
#[cfg(target_os = "macos")]
pub type ThreadPort = libc::mach_port_t;
#[cfg(not(target_os = "macos"))]
pub type ThreadPort = u32;

#[cfg(test)]
mod accounting_smoke {
    #[test]
    fn self_resource_usage_does_not_crash() {
        let u = super::self_resource_usage();
        // On macOS this must succeed and report non-zero virtual size.
        #[cfg(target_os = "macos")]
        {
            let u = u.expect("resource usage available");
            assert!(u.virtual_bytes > 0, "vsize should be > 0");
        }
        let _ = u;
    }
    #[test]
    fn self_thread_cpu_does_not_crash() {
        let _ = super::self_thread_cpu_us();
    }
}
