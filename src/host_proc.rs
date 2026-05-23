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

#[cfg(target_os = "macos")]
mod imp {
    use super::GuestProcInfo;

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
            comm: comm_from(&info.pbi_comm),
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
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::GuestProcInfo;
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
}

pub use imp::{current_thread_port, is_guest_process, pid_info, thread_run_state_char};

/// Mach port type alias for the registry (real on macOS, u32 elsewhere).
#[cfg(target_os = "macos")]
pub type ThreadPort = libc::mach_port_t;
#[cfg(not(target_os = "macos"))]
pub type ThreadPort = u32;
