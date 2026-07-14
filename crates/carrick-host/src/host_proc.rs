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

#[derive(Debug)]
pub enum DirectVmReservationOutcome {
    Reserved(DirectVmReservation),
    DelegatedDyldPmapEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectVmReservationError {
    InvalidRange {
        start: u64,
        length: u64,
    },
    Redirected {
        requested_start: u64,
        requested_end: u64,
        actual: u64,
    },
    Occupied {
        requested_start: u64,
        requested_end: u64,
        mapped_start: u64,
        mapped_end: u64,
        protection: i32,
        max_protection: i32,
        shared: bool,
        reserved: bool,
        user_tag: u32,
        share_mode: u8,
    },
    Kernel {
        operation: &'static str,
        code: i32,
    },
    Host {
        operation: &'static str,
        errno: i32,
    },
    Unsupported,
}

impl std::fmt::Display for DirectVmReservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRange { start, length } => write!(
                formatter,
                "invalid native direct VM reservation range 0x{start:x}+0x{length:x}"
            ),
            Self::Redirected {
                requested_start,
                requested_end,
                actual,
            } => write!(
                formatter,
                "native direct VM reservation at 0x{requested_start:x}..0x{requested_end:x}: fixed Mach allocation unexpectedly returned 0x{actual:x}"
            ),
            Self::Occupied {
                requested_start,
                requested_end,
                mapped_start,
                mapped_end,
                protection,
                max_protection,
                shared,
                reserved,
                user_tag,
                share_mode,
            } => write!(
                formatter,
                "native direct VM reservation collision at 0x{requested_start:x}..0x{requested_end:x}: mapping 0x{mapped_start:x}..0x{mapped_end:x} protection=0x{protection:x} max=0x{max_protection:x} shared={shared} reserved={reserved} user_tag={user_tag} share_mode={share_mode}"
            ),
            Self::Kernel { operation, code } => {
                write!(formatter, "{operation} failed with Mach return {code}")
            }
            Self::Host { operation, errno } => {
                write!(formatter, "{operation} failed with host errno {errno}")
            }
            Self::Unsupported => write!(
                formatter,
                "native direct VM reservations require a macOS host"
            ),
        }
    }
}

impl std::error::Error for DirectVmReservationError {}

/// Exact, non-overwriting `PROT_NONE` ownership of a future Direct mapping.
/// The guard stays armed after `MAP_FIXED` replaces the reservation so any
/// later setup failure unmaps the partial target. `commit` transfers ownership
/// to the completed native address-space object.
#[derive(Debug)]
pub struct DirectVmReservation {
    #[cfg(target_os = "macos")]
    spans: Vec<DirectVmReservationSpan>,
    #[cfg(target_os = "macos")]
    armed: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct DirectVmReservationSpan {
    address: u64,
    length: u64,
}

impl DirectVmReservation {
    /// Host VM spans this reservation owns and will retire while armed.
    ///
    /// A requested Direct range can contain dyld delegated shared-pmap holes,
    /// so callers must use these measured spans rather than treating the
    /// complete requested range as reservation-owned.
    pub fn owned_spans(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        #[cfg(target_os = "macos")]
        let spans = self.spans.iter().map(|span| (span.address, span.length));
        #[cfg(not(target_os = "macos"))]
        let spans = std::iter::empty();
        spans
    }

    pub fn commit(mut self) {
        #[cfg(target_os = "macos")]
        {
            self.armed = false;
        }
    }
}

impl Drop for DirectVmReservation {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.armed {
            let task = unsafe { mach2::traps::mach_task_self() };
            for span in &self.spans {
                let _ = unsafe { mach2::vm::mach_vm_deallocate(task, span.address, span.length) };
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{
        DirectVmReservation, DirectVmReservationError, DirectVmReservationOutcome,
        DirectVmReservationSpan, GuestProcInfo, ResourceUsage,
    };

    const VM_REGION_BASIC_INFO_64: i32 = 9;
    const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
    const VM_REGION_EXTENDED_INFO: i32 = 13;
    const VM_MEMORY_SHARED_PMAP: u32 = 32;
    // mach/vm_statistics.h: a nested shared pmap receives this tag after it
    // becomes unnested, including in a fork child that inherited a Direct
    // guest mapping inside the canonical dyld range.
    const VM_MEMORY_UNSHARED_PMAP: u32 = 35;
    const SM_EMPTY: u8 = 3;

    #[repr(C)]
    #[derive(Default)]
    struct VmRegionExtendedInfo {
        protection: i32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u16,
        external_pager: u8,
        share_mode: u8,
        pages_reusable: u32,
    }

    const VM_REGION_EXTENDED_INFO_COUNT: u32 =
        (std::mem::size_of::<VmRegionExtendedInfo>() / std::mem::size_of::<i32>()) as u32;

    unsafe extern "C" {
        fn mach_vm_region(
            target_task: libc::vm_map_t,
            address: *mut libc::mach_vm_address_t,
            size: *mut libc::mach_vm_size_t,
            flavor: i32,
            info: *mut i32,
            info_count: *mut u32,
            object_name: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;
    }

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
        let label = argv0.rsplit(": ").next()?.trim();
        if label.is_empty() || label == "carrick" {
            return None;
        }
        // Linux `comm` is a SINGLE token with no spaces — the basename of
        // argv[0], truncated to TASK_COMM_LEN-1 (15). The proctitle LABEL may be
        // the full command line ("/bin/sh -c cat …", set for `ps` readability),
        // so reduce it to the comm: first whitespace-delimited token, then its
        // path basename. A comm containing spaces breaks a `/proc/<pid>/stat`
        // reader that scans the `(comm)` field with `%s` (LTP getpgid01 parsing
        // /proc/1/stat, whose init label is the full shell command line).
        let argv0_token = label.split_whitespace().next().unwrap_or(label);
        let base = argv0_token.rsplit('/').next().unwrap_or(argv0_token);
        if base.is_empty() {
            return None;
        }
        Some(base.chars().take(15).collect())
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

    /// Convert a `rusage_info` time value to nanoseconds. The `ri_*_time`
    /// fields are in MACH TIME UNITS, not nanoseconds: on Apple Silicon the
    /// timebase is 125/3 (~41.67 ns/unit), so treating them as nanoseconds
    /// under-reports CPU ~41.7× (measured: a 1.185 s burn read back as 28 ms,
    /// which kept `times(2)` under its 10 ms tick — probe `accounting`
    /// `times_cpu_pos=false` under the native backend, where the host value is
    /// the only CPU source). On Intel the timebase is 1/1 and this is identity.
    // libc flags mach_timebase_info deprecated only to steer new code to the
    // `mach2` crate; it is the canonical timebase API and this file already
    // uses libc's mach bindings directly (see `mach_task_self_` above), so we
    // stay consistent rather than add a dependency for one call.
    #[allow(deprecated)]
    fn mach_ticks_to_ns(ticks: u64) -> u64 {
        static TIMEBASE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
        let (numer, denom) = *TIMEBASE.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: fills the fixed-size out-struct; failure leaves zeros,
            // mapped to the 1/1 identity below rather than a divide-by-zero.
            if unsafe { libc::mach_timebase_info(&mut info) } != libc::KERN_SUCCESS
                || info.denom == 0
            {
                (1, 1)
            } else {
                (info.numer, info.denom)
            }
        });
        (u128::from(ticks) * u128::from(numer) / u128::from(denom)) as u64
    }

    /// Convert a `rusage_info` mach-time-unit value to microseconds.
    pub(super) fn mach_ticks_to_us(ticks: u64) -> u64 {
        mach_ticks_to_ns(ticks) / 1000
    }

    /// This process's total CPU time (user + system) in nanoseconds, from
    /// `proc_pid_rusage`. The Darwin-native provider for guest CPU accounting
    /// under the native exec backend, where guest cycles are ordinary host
    /// execution and the host kernel's bookkeeping is the source of truth.
    pub fn self_cpu_total_ns() -> Option<u64> {
        let mut ri: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: see `self_resource_usage` — V2 flavor writes one
        // rusage_info_v2 through the struct address cast to `rusage_info_t*`.
        let rc = unsafe {
            libc::proc_pid_rusage(
                std::process::id() as libc::c_int,
                libc::RUSAGE_INFO_V2,
                &mut ri as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
            )
        };
        if rc != 0 {
            return None;
        }
        Some(mach_ticks_to_ns(
            ri.ri_user_time.saturating_add(ri.ri_system_time),
        ))
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
            // ri_*_time are mach time units, NOT nanoseconds (see
            // `mach_ticks_to_ns`); the former `/1000` under-reported ~41.7×.
            usage.user_us = mach_ticks_to_us(ri.ri_user_time);
            usage.system_us = mach_ticks_to_us(ri.ri_system_time);
            usage.child_user_us = mach_ticks_to_us(ri.ri_child_user_time);
            usage.child_system_us = mach_ticks_to_us(ri.ri_child_system_time);
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
        //
        // Native provider: guest cycles ARE this process's host CPU, and
        // `guest_cpu::total_us()` reads the SAME proc_pid_rusage counters as
        // above — adding it would double-count. The converted user/system split
        // is already the honest native model (guest utime = host user time,
        // guest stime = host system time).
        if !crate::guest_cpu::native_darwin_provider() {
            let guest_us = crate::guest_cpu::total_us();
            if guest_us > 0 {
                usage.user_us = usage.user_us.saturating_add(guest_us);
            }
        }
        Some(usage)
    }

    /// Count this process's Mach VM regions by walking the task map. This is a
    /// diagnostics-only fork-footprint signal: it tells us whether host `fork(2)`
    /// cost is scaling with address-space shape, not just resident bytes.
    #[allow(deprecated)] // libc::mach_task_self_ is the stable self-task port here.
    pub fn self_vm_region_count() -> Option<u64> {
        let task = unsafe { libc::mach_task_self_ };
        let mut address: libc::mach_vm_address_t = 0;
        let mut regions = 0u64;

        loop {
            let mut size: libc::mach_vm_size_t = 0;
            let mut info = [0i32; 16];
            let mut count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: libc::mach_port_t = 0;
            // SAFETY: queries this process's VM map and writes fixed-size result
            // buffers matching VM_REGION_BASIC_INFO_64.
            let kr = unsafe {
                mach_vm_region(
                    task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &mut count,
                    &mut object_name,
                )
            };
            if object_name != 0 {
                let _ = unsafe { mach_port_deallocate(task, object_name) };
            }
            if kr != libc::KERN_SUCCESS {
                return (regions > 0).then_some(regions);
            }
            if size == 0 {
                return None;
            }
            regions = regions.checked_add(1)?;
            let next = address.checked_add(size)?;
            if next <= address {
                return None;
            }
            address = next;
        }
    }

    enum ExactReservationResult {
        Reserved,
        NoSpace,
    }

    fn reserve_exact_vm_span(
        task: libc::mach_port_t,
        start: u64,
        length: u64,
    ) -> Result<ExactReservationResult, DirectVmReservationError> {
        let end = start
            .checked_add(length)
            .ok_or(DirectVmReservationError::InvalidRange { start, length })?;
        let mut address = start;
        // SAFETY: the caller supplies a checked, non-empty range.
        // `VM_FLAGS_FIXED` requests this exact interval; overwrite is a
        // separate Mach flag which Carrick deliberately never passes, so an
        // occupied page makes the call fail instead of replacing host memory.
        let allocation_kr = unsafe {
            mach2::vm::mach_vm_allocate(
                task,
                &mut address,
                length,
                mach2::vm_statistics::VM_FLAGS_FIXED,
            )
        };
        if allocation_kr == mach2::kern_return::KERN_NO_SPACE {
            return Ok(ExactReservationResult::NoSpace);
        }
        if allocation_kr != libc::KERN_SUCCESS {
            return Err(DirectVmReservationError::Kernel {
                operation: "mach_vm_allocate fixed native direct reservation",
                code: allocation_kr,
            });
        }
        if address != start {
            let _ = unsafe { mach2::vm::mach_vm_deallocate(task, address, length) };
            return Err(DirectVmReservationError::Redirected {
                requested_start: start,
                requested_end: end,
                actual: address,
            });
        }
        let protect_kr = unsafe {
            mach2::vm::mach_vm_protect(task, address, length, 0, mach2::vm_prot::VM_PROT_NONE)
        };
        if protect_kr != libc::KERN_SUCCESS {
            let _ = unsafe { mach2::vm::mach_vm_deallocate(task, address, length) };
            return Err(DirectVmReservationError::Kernel {
                operation: "mach_vm_protect native direct reservation",
                code: protect_kr,
            });
        }
        Ok(ExactReservationResult::Reserved)
    }

    /// Acquire one future Direct interval without overwriting any host mapping.
    /// Exact fixed allocations own ordinary vacant spans. A mapped segment is
    /// skipped only when both Mach region flavors identify the measured dyld
    /// delegated shared-pmap empty tuple. XNU retags that entry from
    /// `VM_MEMORY_SHARED_PMAP` to `VM_MEMORY_UNSHARED_PMAP` when it becomes
    /// unnested after `fork`; every other occupied segment is a collision.
    /// Mixed ranges retain exact guards for every true gap, so a split dyld
    /// entry cannot leave its vacant tail unowned before image retirement.
    pub fn reserve_self_direct_vm_range(
        start: u64,
        length: u64,
    ) -> Result<DirectVmReservationOutcome, DirectVmReservationError> {
        let end = start
            .checked_add(length)
            .filter(|end| length != 0 && *end > start)
            .ok_or(DirectVmReservationError::InvalidRange { start, length })?;
        let _ = usize::try_from(start)
            .map_err(|_| DirectVmReservationError::InvalidRange { start, length })?;
        let _ = usize::try_from(length)
            .map_err(|_| DirectVmReservationError::InvalidRange { start, length })?;
        let task = unsafe { mach2::traps::mach_task_self() };
        let mut reservation = DirectVmReservation {
            spans: Vec::new(),
            armed: true,
        };
        let mut cursor = start;
        while cursor < end {
            reservation
                .spans
                .try_reserve(1)
                .map_err(|_| DirectVmReservationError::Host {
                    operation: "reserve native direct span metadata",
                    errno: libc::ENOMEM,
                })?;
            match reserve_exact_vm_span(task, cursor, end - cursor)? {
                ExactReservationResult::Reserved => {
                    reservation.spans.push(DirectVmReservationSpan {
                        address: cursor,
                        length: end - cursor,
                    });
                    cursor = end;
                    continue;
                }
                ExactReservationResult::NoSpace => {}
            }

            let mut basic_address = cursor as libc::mach_vm_address_t;
            let mut basic_size: libc::mach_vm_size_t = 0;
            let mut basic = [0i32; 16];
            let mut basic_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut basic_object: libc::mach_port_t = 0;
            let basic_kr = unsafe {
                mach_vm_region(
                    task,
                    &mut basic_address,
                    &mut basic_size,
                    VM_REGION_BASIC_INFO_64,
                    basic.as_mut_ptr(),
                    &mut basic_count,
                    &mut basic_object,
                )
            };
            if basic_object != 0 {
                let _ = unsafe { mach_port_deallocate(task, basic_object) };
            }
            if basic_kr != libc::KERN_SUCCESS {
                return Err(DirectVmReservationError::Kernel {
                    operation: "mach_vm_region basic64 after fixed allocation no-space",
                    code: basic_kr,
                });
            }
            let basic_end =
                basic_address
                    .checked_add(basic_size)
                    .ok_or(DirectVmReservationError::Kernel {
                        operation: "mach_vm_region basic64 range overflow",
                        code: basic_kr,
                    })?;

            if basic_address > cursor {
                let gap_end = basic_address.min(end);
                match reserve_exact_vm_span(task, cursor, gap_end - cursor)? {
                    ExactReservationResult::Reserved => {
                        reservation.spans.push(DirectVmReservationSpan {
                            address: cursor,
                            length: gap_end - cursor,
                        });
                        cursor = gap_end;
                    }
                    // A mapping raced into the measured gap. Re-query it rather
                    // than overwriting or trusting stale vacancy information.
                    ExactReservationResult::NoSpace => {}
                }
                continue;
            }

            let mut extended_address = cursor as libc::mach_vm_address_t;
            let mut extended_size: libc::mach_vm_size_t = 0;
            let mut extended = VmRegionExtendedInfo::default();
            let mut extended_count = VM_REGION_EXTENDED_INFO_COUNT;
            let mut extended_object: libc::mach_port_t = 0;
            let extended_kr = unsafe {
                mach_vm_region(
                    task,
                    &mut extended_address,
                    &mut extended_size,
                    VM_REGION_EXTENDED_INFO,
                    &mut extended as *mut VmRegionExtendedInfo as *mut i32,
                    &mut extended_count,
                    &mut extended_object,
                )
            };
            if extended_object != 0 {
                let _ = unsafe { mach_port_deallocate(task, extended_object) };
            }
            if extended_kr != libc::KERN_SUCCESS {
                return Err(DirectVmReservationError::Kernel {
                    operation: "mach_vm_region extended after fixed allocation no-space",
                    code: extended_kr,
                });
            }
            let extended_end = extended_address.checked_add(extended_size).ok_or(
                DirectVmReservationError::Kernel {
                    operation: "mach_vm_region extended range overflow",
                    code: extended_kr,
                },
            )?;
            let protection = basic[0];
            let max_protection = basic[1];
            let shared = basic[3] != 0;
            let reserved = basic[4] != 0;
            let delegated_end = basic_end.min(extended_end).min(end);
            if basic_address <= cursor
                && extended_address <= cursor
                && delegated_end > cursor
                && protection == libc::VM_PROT_READ
                && max_protection == libc::VM_PROT_READ
                && !shared
                && reserved
                && matches!(
                    extended.user_tag,
                    VM_MEMORY_SHARED_PMAP | VM_MEMORY_UNSHARED_PMAP
                )
                && extended.share_mode == SM_EMPTY
            {
                cursor = delegated_end;
                continue;
            }

            return Err(DirectVmReservationError::Occupied {
                requested_start: start,
                requested_end: end,
                mapped_start: basic_address,
                mapped_end: basic_end,
                protection,
                max_protection,
                shared,
                reserved,
                user_tag: extended.user_tag,
                share_mode: extended.share_mode,
            });
        }

        if reservation.spans.is_empty() {
            Ok(DirectVmReservationOutcome::DelegatedDyldPmapEmpty)
        } else {
            Ok(DirectVmReservationOutcome::Reserved(reservation))
        }
    }

    #[cfg(test)]
    mod direct_vm_reservation_tests {
        use super::{DirectVmReservationOutcome, reserve_self_direct_vm_range};

        const PAGE: usize = 16 * 1024;

        fn fork_test(test: impl FnOnce() + std::panic::UnwindSafe) {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
            if pid == 0 {
                let passed = std::panic::catch_unwind(test).is_ok();
                unsafe { libc::_exit(i32::from(!passed)) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }

        #[test]
        fn exact_allocatable_reservation_rolls_back_replacement() {
            fork_test(|| {
                let scratch = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        PAGE,
                        libc::PROT_NONE,
                        libc::MAP_ANON | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                };
                assert_ne!(scratch, libc::MAP_FAILED);
                assert_eq!(unsafe { libc::munmap(scratch, PAGE) }, 0);
                let guard = match reserve_self_direct_vm_range(scratch as u64, PAGE as u64)
                    .expect("reserve exact allocatable interval")
                {
                    DirectVmReservationOutcome::Reserved(guard) => guard,
                    DirectVmReservationOutcome::DelegatedDyldPmapEmpty => {
                        panic!("ordinary scratch interval was classified as delegated")
                    }
                };
                let replacement = unsafe {
                    libc::mmap(
                        scratch,
                        PAGE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                assert_eq!(replacement, scratch);
                unsafe { replacement.cast::<u8>().write(0xa5) };
                drop(guard);
                assert!(matches!(
                    reserve_self_direct_vm_range(scratch as u64, PAGE as u64)
                        .expect("rollback leaves interval reservable"),
                    DirectVmReservationOutcome::Reserved(_)
                ));
            });
        }

        #[test]
        fn canonical_dyld_delegated_empty_tuple_is_accepted() {
            fork_test(|| {
                assert!(matches!(
                    reserve_self_direct_vm_range(0x4_0000_0000, PAGE as u64)
                        .expect("classify canonical dyld gap"),
                    DirectVmReservationOutcome::DelegatedDyldPmapEmpty
                ));
            });
        }

        #[test]
        fn fork_child_canonical_unnested_dyld_gap_is_accepted() {
            fork_test(|| {
                let source = 0x4_0000_0000usize;
                let mapped = unsafe {
                    libc::mmap(
                        source as *mut libc::c_void,
                        PAGE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                assert_eq!(mapped as usize, source);

                let child = unsafe { libc::fork() };
                assert!(
                    child >= 0,
                    "fork direct-mapped child: {}",
                    std::io::Error::last_os_error()
                );
                if child == 0 {
                    let accepted = matches!(
                        reserve_self_direct_vm_range(0x4_0002_0000, PAGE as u64),
                        Ok(DirectVmReservationOutcome::DelegatedDyldPmapEmpty)
                    );
                    unsafe { libc::_exit(i32::from(!accepted)) };
                }
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
                assert_eq!(libc::WEXITSTATUS(status), 0);
            });
        }

        #[test]
        fn fork_child_split_canonical_range_is_accepted_segmentwise() {
            fork_test(|| {
                let source = 0x4_0000_0000usize;
                let mapped = unsafe {
                    libc::mmap(
                        source as *mut libc::c_void,
                        PAGE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                assert_eq!(mapped as usize, source);
                unsafe { mapped.cast::<u8>().write(0x5e) };

                let child = unsafe { libc::fork() };
                assert!(
                    child >= 0,
                    "fork direct-mapped child: {}",
                    std::io::Error::last_os_error()
                );
                if child == 0 {
                    let outcome = reserve_self_direct_vm_range(0x4_0002_4000, 0x0628_0000);
                    match outcome {
                        Ok(DirectVmReservationOutcome::Reserved(guard)) => drop(guard),
                        Ok(DirectVmReservationOutcome::DelegatedDyldPmapEmpty) => {}
                        Err(error) => panic!(
                            "Node-sized split Direct range was not accepted segmentwise: {error:?}"
                        ),
                    }
                    assert_eq!(unsafe { mapped.cast::<u8>().read() }, 0x5e);
                    unsafe { libc::_exit(0) };
                }

                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
                assert_eq!(libc::WEXITSTATUS(status), 0);
                assert_eq!(unsafe { mapped.cast::<u8>().read() }, 0x5e);
            });
        }

        #[test]
        fn canonical_direct_gap_sentinel_is_rejected_and_preserved() {
            fork_test(|| {
                let address = 0x4_0000_0000usize;
                let sentinel = unsafe {
                    libc::mmap(
                        address as *mut libc::c_void,
                        PAGE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                assert_eq!(sentinel as usize, address);
                unsafe { sentinel.cast::<u8>().write(0x5e) };
                assert!(reserve_self_direct_vm_range(address as u64, PAGE as u64).is_err());
                assert_eq!(unsafe { sentinel.cast::<u8>().read() }, 0x5e);
            });
        }

        #[test]
        fn guard_region_is_rejected() {
            fork_test(|| {
                assert!(reserve_self_direct_vm_range(0xf_c000_0000, PAGE as u64).is_err());
            });
        }

        #[test]
        fn generic_shared_readonly_mapping_is_rejected() {
            fork_test(|| {
                let mapping = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        PAGE,
                        libc::PROT_READ,
                        libc::MAP_ANON | libc::MAP_SHARED,
                        -1,
                        0,
                    )
                };
                assert_ne!(mapping, libc::MAP_FAILED);
                assert!(
                    reserve_self_direct_vm_range(mapping as u64, PAGE as u64).is_err(),
                    "generic shared/read-only mapping must not match delegated dyld tuple"
                );
            });
        }
    }

    /// Measured resident bytes within the given virtual-address ranges of THIS
    /// process, from a `mach_vm_region(VM_REGION_EXTENDED_INFO)` walk
    /// (`pages_resident` per mach region, clipped to the queried overlap).
    ///
    /// This exists for the native exec backend, where guest VAs ARE host VAs:
    /// the whole-process `phys_footprint` includes the carrick runtime's own
    /// memory and can exceed the guest's modeled VmSize, so `/proc/self/status`
    /// VmRSS is instead MEASURED over exactly the guest's VMA spans. Ranges are
    /// merged before walking so overlapping inputs never double-count. `None`
    /// only if the first region query of every range fails.
    #[allow(deprecated)] // libc::mach_task_self_ — see self_resource_usage.
    pub fn resident_bytes_in_ranges(ranges: &[(u64, u64)]) -> Option<u64> {
        const VM_REGION_EXTENDED_INFO: i32 = 13;
        /// mach/vm_region.h `vm_region_extended_info` (flavor 13).
        #[repr(C)]
        #[derive(Default)]
        struct VmRegionExtendedInfo {
            protection: i32,
            user_tag: u32,
            pages_resident: u32,
            pages_shared_now_private: u32,
            pages_swapped_out: u32,
            pages_dirtied: u32,
            ref_count: u32,
            shadow_depth: u16,
            external_pager: u8,
            share_mode: u8,
            pages_reusable: u32,
        }
        const VM_REGION_EXTENDED_INFO_COUNT: u32 =
            (std::mem::size_of::<VmRegionExtendedInfo>() / std::mem::size_of::<i32>()) as u32;

        let mut merged: Vec<(u64, u64)> = ranges.iter().copied().filter(|(s, e)| e > s).collect();
        merged.sort_unstable();
        merged.dedup_by(|next, prev| {
            if next.0 <= prev.1 {
                prev.1 = prev.1.max(next.1);
                true
            } else {
                false
            }
        });

        let task = unsafe { libc::mach_task_self_ };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
        let mut resident = 0u64;
        let mut any_query_succeeded = false;
        for (start, end) in merged {
            let mut addr: libc::mach_vm_address_t = start;
            loop {
                let mut size: libc::mach_vm_size_t = 0;
                let mut info = VmRegionExtendedInfo::default();
                let mut count = VM_REGION_EXTENDED_INFO_COUNT;
                let mut object_name: libc::mach_port_t = 0;
                // SAFETY: queries this process's VM map with a matching
                // flavor/count and a correctly sized out-struct (cast to the
                // int-array parameter type, as the basic64 walk above does).
                let kr = unsafe {
                    mach_vm_region(
                        task,
                        &mut addr,
                        &mut size,
                        VM_REGION_EXTENDED_INFO,
                        &mut info as *mut VmRegionExtendedInfo as *mut i32,
                        &mut count,
                        &mut object_name,
                    )
                };
                if object_name != 0 {
                    let _ = unsafe { mach_port_deallocate(task, object_name) };
                }
                if kr != libc::KERN_SUCCESS || addr >= end {
                    // Past the last mapping (or past this range): next range.
                    if kr == libc::KERN_SUCCESS {
                        any_query_succeeded = true;
                    }
                    break;
                }
                any_query_succeeded = true;
                let Some(region_end) = addr.checked_add(size) else {
                    break;
                };
                let overlap = region_end.min(end).saturating_sub(addr.max(start));
                // pages_resident covers the whole mach region; native guest
                // mappings are their own mach regions so boundaries align —
                // clip to the overlap anyway so a wider host region can never
                // over-count the queried span.
                resident = resident.saturating_add(
                    (u64::from(info.pages_resident).saturating_mul(page)).min(overlap),
                );
                if region_end <= addr {
                    break;
                }
                addr = region_end;
            }
        }
        any_query_succeeded.then_some(resident)
    }

    /// (user_us, system_us) CPU time for the current thread, from
    /// `thread_info(THREAD_BASIC_INFO)`. Used by `getrusage(RUSAGE_THREAD)`.
    pub fn self_thread_cpu_us() -> Option<(u64, u64)> {
        // SAFETY: pthread_mach_thread_np on the current pthread is always valid.
        thread_cpu_us_for_port(unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) })
    }

    /// (user_us, system_us) CPU time for an ARBITRARY host thread identified
    /// by its mach port, from `thread_info(THREAD_BASIC_INFO)`.
    /// `thread_info` accepts any `thread_act_t` this task holds a send right
    /// to, not only the calling thread's own port -- exactly like
    /// `thread_run_state_char` above, which already reads a different
    /// `thread_info` flavor for a foreign thread. `port` is expected to come
    /// from `current_thread_port()`, captured on the target thread itself and
    /// stored for later cross-thread reads (no ownership transfer, so no
    /// `mach_port_deallocate` is needed here either).
    pub fn thread_cpu_us_for_port(port: libc::mach_port_t) -> Option<(u64, u64)> {
        let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: matching flavor/count and a zeroed buffer of the right type.
        let kr = unsafe {
            libc::thread_info(
                port,
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
        fn reduces_a_full_command_line_label_to_a_single_token_comm() {
            // The init/root proctitle carries the whole command line for `ps`
            // readability; `comm` must be the basename of argv[0] alone (no
            // spaces, no path) — else a `/proc/<pid>/stat` `(comm)` scan breaks.
            assert_eq!(
                parse_proctitle_name("carrick:run-1: /bin/sh -c cat /proc/1/stat").as_deref(),
                Some("sh")
            );
            assert_eq!(
                parse_proctitle_name("carrick:run-1: /opt/ltp/testcases/bin/getpgid01").as_deref(),
                Some("getpgid01")
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

/// Non-macOS hosts (KVM / bhyve / NVMM lanes): the host kernel is the source of
/// truth, same as macOS. carrick forks each guest process as a real host
/// process (the trees mirror), so a sibling guest's identity/state and a
/// process's own resource usage come straight from the host kernel — the
/// synthetic guest `/proc` then re-renders them in the guest's namespace.
///
/// Two host-kernel surfaces are used, picked per OS at the call sites below:
///   * **Linux** — the real `/proc/<pid>/stat` + `/proc/self/statm` +
///     `getrusage`. (FreeBSD/NetBSD have NO Linux-format `/proc`; on FreeBSD
///     procfs is not even mounted by default — `/proc/<pid>/stat` reads fail,
///     so the Linux path is inert there and returned zeros.)
///   * **FreeBSD** — `sysctl(KERN_PROC_PID)` → `struct kinfo_proc`, the BSD
///     analogue of `/proc/<pid>/stat`.
///   * **NetBSD** — `sysctl(KERN_PROC2, KERN_PROC_PID, ...)` →
///     `struct kinfo_proc2`, the NetBSD analogue of `/proc/<pid>/stat`.
///
/// Both BSD records carry ppid/pgid/state/comm/creds and resident/virtual size
/// for ANY pid the caller may inspect. This is the durable, fork-coherent,
/// cross-process kernel bookkeeping the project prefers over in-process shadow
/// state.
///
/// Reads degrade to `None`/`false` on any failure (also keeping any future host
/// with neither surface inert).
#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{GuestProcInfo, ResourceUsage};

    /// FreeBSD `kinfo_proc` via `sysctl(KERN_PROC_PID)` — the BSD source of truth
    /// for a process's identity, state, and resource usage. Used by `pid_info`
    /// (sibling `/proc/<pid>/stat`), `is_guest_process` (the ppid-chain guard),
    /// and `self_resource_usage` (statm/status/getrusage memory + CPU). procfs
    /// is not mounted on FreeBSD by default, so the Linux `/proc` reader is inert
    /// there; this is the working path.
    #[cfg(target_os = "freebsd")]
    mod freebsd {
        /// Read the kernel's `kinfo_proc` for `pid` via `sysctl(KERN_PROC_PID)`.
        /// `None` if the pid does not exist or the call fails. The mib is the
        /// documented `{ CTL_KERN, KERN_PROC, KERN_PROC_PID, pid }` (sysctl(3));
        /// the kernel writes exactly one fixed-size `kinfo_proc` (`ki_structsize`
        /// matches `size_of::<kinfo_proc>()` on a matching libc, so a short read
        /// is treated as failure rather than parsed).
        pub(super) fn read_kinfo(pid: u32) -> Option<libc::kinfo_proc> {
            let mut mib: [libc::c_int; 4] = [
                libc::CTL_KERN,
                libc::KERN_PROC,
                libc::KERN_PROC_PID,
                pid as libc::c_int,
            ];
            let mut kp: libc::kinfo_proc = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::kinfo_proc>();
            // SAFETY: a documented 4-element KERN_PROC_PID mib and a correctly
            // sized, zeroed out-buffer of exactly one kinfo_proc. The kernel
            // writes at most `len` bytes and updates `len` to what it wrote.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    &mut kp as *mut libc::kinfo_proc as *mut libc::c_void,
                    &mut len,
                    std::ptr::null(),
                    0,
                )
            };
            // rc==0 AND a full struct written (a live pid yields exactly one
            // record; an empty result leaves len < struct size).
            if rc == 0 && len >= std::mem::size_of::<libc::kinfo_proc>() {
                Some(kp)
            } else {
                None
            }
        }

        /// The Linux `/proc/<pid>/stat` state char for a FreeBSD `ki_stat`.
        /// SRUN → 'R'; SSLEEP/SWAIT/SLOCK (interruptible / kernel waits) → 'S';
        /// SSTOP → 'T'; SZOMB → 'Z'; SIDL (being created) → 'R' (runnable on
        /// Linux during setup). Mirrors the macOS mapping's R/S/T/Z surface.
        pub(super) fn state_char(ki_stat: libc::c_char) -> char {
            match ki_stat {
                libc::SRUN | libc::SIDL => 'R',
                libc::SSTOP => 'T',
                libc::SZOMB => 'Z',
                // SSLEEP / SWAIT / SLOCK — blocked in the kernel.
                _ => 'S',
            }
        }

        /// `ki_comm` (NUL-padded `c_char` array) as a Rust String, truncated at
        /// the first NUL (Linux `comm` semantics).
        pub(super) fn comm(kp: &libc::kinfo_proc) -> String {
            let bytes: Vec<u8> = kp
                .ki_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    /// NetBSD `kinfo_proc2` via `sysctl(KERN_PROC2, KERN_PROC_PID)` — the BSD
    /// source of truth for a process's identity, state, and resource usage.
    #[cfg(target_os = "netbsd")]
    mod netbsd {
        /// Read exactly one `kinfo_proc2` for `pid`. NetBSD's KERN_PROC2 mib is
        /// `{ CTL_KERN, KERN_PROC2, KERN_PROC_PID, pid, sizeof(kinfo_proc2), 1 }`.
        pub(super) fn read_kinfo(pid: u32) -> Option<libc::kinfo_proc2> {
            let mut mib: [libc::c_int; 6] = [
                libc::CTL_KERN,
                libc::KERN_PROC2,
                libc::KERN_PROC_PID,
                pid as libc::c_int,
                std::mem::size_of::<libc::kinfo_proc2>() as libc::c_int,
                1,
            ];
            let mut kp: libc::kinfo_proc2 = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::kinfo_proc2>();
            // SAFETY: a documented KERN_PROC2 mib and one correctly sized
            // zeroed out-buffer. The kernel writes at most `len` bytes and
            // updates `len` to what it wrote.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    &mut kp as *mut libc::kinfo_proc2 as *mut libc::c_void,
                    &mut len,
                    std::ptr::null(),
                    0,
                )
            };
            if rc == 0 && len >= std::mem::size_of::<libc::kinfo_proc2>() {
                Some(kp)
            } else {
                None
            }
        }

        /// The Linux `/proc/<pid>/stat` state char for a NetBSD `p_stat`.
        pub(super) fn state_char(p_stat: i8) -> char {
            match p_stat as libc::c_int {
                libc::LSRUN | libc::LSIDL => 'R',
                libc::LSSTOP => 'T',
                libc::LSZOMB => 'Z',
                _ => 'S',
            }
        }

        /// `p_comm` (NUL-padded `c_char` array) as a Rust String.
        pub(super) fn comm(kp: &libc::kinfo_proc2) -> String {
            let bytes: Vec<u8> = kp
                .p_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    /// Parse a Linux `/proc/<pid>/stat` line into `(comm, state, ppid, pgrp)`.
    /// The comm is delimited by the FIRST `(` and LAST `)` — it may itself
    /// contain spaces or parens (proc_pid_stat(5)). Linux-only; FreeBSD reads
    /// the same facts from `kinfo_proc` (no procfs).
    #[cfg(target_os = "linux")]
    fn parse_stat(line: &str) -> Option<(String, char, u32, u32)> {
        let open = line.find('(')?;
        let close = line.rfind(')')?;
        let comm = line.get(open + 1..close)?.to_owned();
        let mut rest = line.get(close + 1..)?.split_ascii_whitespace();
        let state = rest.next()?.chars().next()?;
        let ppid = rest.next()?.parse().ok()?;
        let pgrp = rest.next()?.parse().ok()?;
        Some((comm, state, ppid, pgrp))
    }

    #[cfg(target_os = "linux")]
    fn read_stat(path: &str) -> Option<(String, char, u32, u32)> {
        parse_stat(&std::fs::read_to_string(path).ok()?)
    }

    /// Aggregate Linux state char across the process's threads, mirroring the
    /// macOS thread aggregation: the leader's state in `/proc/<pid>/stat` only
    /// reflects the MAIN thread, but a carrick guest executes on a vCPU worker
    /// thread — a guest spinning in userspace would otherwise read 'S' from
    /// the parked leader. Any running task ⇒ 'R'; otherwise the leader state
    /// stands (a blocked guest parks every carrick thread, so it reads 'S').
    /// Linux-only (FreeBSD's `ki_stat` is already a whole-process state).
    #[cfg(target_os = "linux")]
    fn aggregate_state(pid: u32, leader: char) -> char {
        if leader == 'Z' || leader == 'T' {
            return leader;
        }
        let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return leader;
        };
        for ent in dir.flatten() {
            let Some(tid) = ent.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some((_, st, _, _)) = read_stat(&format!("/proc/{pid}/task/{tid}/stat"))
                && st == 'R'
            {
                return 'R';
            }
        }
        leader
    }

    #[cfg(target_os = "linux")]
    pub fn pid_info(pid: u32) -> Option<GuestProcInfo> {
        let (comm, leader_state, ppid, pgid) = read_stat(&format!("/proc/{pid}/stat"))?;
        // Real uid/gid of the host process (`/proc/<pid>` is owned by it). The
        // guest-facing renderers substitute container creds where it matters.
        let (uid, gid) = std::fs::metadata(format!("/proc/{pid}"))
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                (m.uid(), m.gid())
            })
            .unwrap_or((0, 0));
        Some(GuestProcInfo {
            state: aggregate_state(pid, leader_state),
            ppid,
            pgid,
            uid,
            gid,
            comm,
        })
    }

    /// FreeBSD `pid_info`: read the `kinfo_proc` directly (no procfs). The
    /// process state is `ki_stat`, which already reflects the whole process (a
    /// guest spinning on a vCPU thread shows SRUN), so no per-thread aggregation
    /// pass is needed — the macOS/Linux `task`-walk exists only because their
    /// leader-only stat under-reports a busy worker thread.
    #[cfg(target_os = "freebsd")]
    pub fn pid_info(pid: u32) -> Option<GuestProcInfo> {
        let kp = freebsd::read_kinfo(pid)?;
        Some(GuestProcInfo {
            state: freebsd::state_char(kp.ki_stat),
            ppid: kp.ki_ppid.max(0) as u32,
            pgid: kp.ki_pgid.max(0) as u32,
            uid: kp.ki_ruid,
            gid: kp.ki_rgid,
            comm: freebsd::comm(&kp),
        })
    }

    /// NetBSD `pid_info`: read the `kinfo_proc2` directly (no procfs).
    #[cfg(target_os = "netbsd")]
    pub fn pid_info(pid: u32) -> Option<GuestProcInfo> {
        let kp = netbsd::read_kinfo(pid)?;
        Some(GuestProcInfo {
            state: netbsd::state_char(kp.p_stat),
            ppid: kp.p_ppid.max(0) as u32,
            pgid: kp.p__pgid.max(0) as u32,
            uid: kp.p_ruid,
            gid: kp.p_rgid,
            comm: netbsd::comm(&kp),
        })
    }

    /// Any other non-macOS host without a wired process source: inert.
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd")))]
    pub fn pid_info(_pid: u32) -> Option<GuestProcInfo> {
        None
    }

    /// The host parent pid of `cur`, or `None` if it has no live host record.
    /// The one per-OS primitive the `is_guest_process` chain-walk needs: Linux
    /// reads `/proc/<pid>/stat`, FreeBSD reads `kinfo_proc.ki_ppid` (no procfs).
    #[cfg(target_os = "linux")]
    fn parent_pid(cur: u32) -> Option<u32> {
        read_stat(&format!("/proc/{cur}/stat")).map(|(_, _, pp, _)| pp)
    }
    #[cfg(target_os = "freebsd")]
    fn parent_pid(cur: u32) -> Option<u32> {
        freebsd::read_kinfo(cur).map(|kp| kp.ki_ppid.max(0) as u32)
    }
    #[cfg(target_os = "netbsd")]
    fn parent_pid(cur: u32) -> Option<u32> {
        netbsd::read_kinfo(cur).map(|kp| kp.p_ppid.max(0) as u32)
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd")))]
    fn parent_pid(_cur: u32) -> Option<u32> {
        None
    }

    /// True iff `pid` is a carrick GUEST process — the ppid-chain walk (chain
    /// must reach the root guest pid or this process), via the per-OS host kernel
    /// `parent_pid`. Bounded so a cycle can't loop forever. The guard that keeps
    /// a guest from probing arbitrary host processes: only carrick's own
    /// descendants are exposable via `/proc`.
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
            let Some(pp) = parent_pid(cur) else {
                return false;
            };
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

    pub fn thread_run_state_char(_port: u32) -> char {
        'R'
    }
    pub fn current_thread_port() -> u32 {
        0
    }
    /// No cross-thread CPU accounting primitive exists on this host the way
    /// mach `thread_info` does on macOS (there is no non-self `RUSAGE_THREAD`
    /// analog on Linux/FreeBSD): inert here, matching every other
    /// mach-specific accessor in this stub `imp`.
    pub fn thread_cpu_us_for_port(_port: u32) -> Option<(u64, u64)> {
        None
    }
    pub fn self_resource_usage() -> Option<ResourceUsage> {
        #[cfg(target_os = "linux")]
        {
            let mut usage = ResourceUsage::default();

            // CPU + peak RSS from getrusage(RUSAGE_SELF). ru_maxrss is KiB on Linux.
            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: getrusage(RUSAGE_SELF) fills `ru` for this process; a zeroed
            // rusage is a valid out-buffer.
            let ru_ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0;
            if ru_ok {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.user_us = to_us(ru.ru_utime);
                usage.system_us = to_us(ru.ru_stime);
                usage.maxrss_bytes = (ru.ru_maxrss.max(0) as u64).saturating_mul(1024);
                usage.majflt = ru.ru_majflt.max(0) as u64;
            }

            // RUSAGE_CHILDREN for reaped children (tms_cutime / RUSAGE_CHILDREN).
            let mut ruc: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: same contract as above for RUSAGE_CHILDREN.
            if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ruc) } == 0 {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.child_user_us = to_us(ruc.ru_utime);
                usage.child_system_us = to_us(ruc.ru_stime);
            }

            // Current VSZ / RSS from /proc/self/statm (pages: size, resident, ...).
            let mut statm_ok = false;
            if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
                let mut fields = statm.split_whitespace();
                // SAFETY: sysconf(_SC_PAGESIZE) has no side effects; >0 on Linux.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
                if let (Some(size), Some(resident)) = (fields.next(), fields.next())
                    && let (Ok(size), Ok(resident)) = (size.parse::<u64>(), resident.parse::<u64>())
                {
                    usage.virtual_bytes = size.saturating_mul(page);
                    usage.resident_bytes = resident.saturating_mul(page);
                    statm_ok = true;
                }
            }

            if !ru_ok && !statm_ok {
                return None;
            }
            Some(usage)
        }
        #[cfg(target_os = "freebsd")]
        {
            let mut usage = ResourceUsage::default();

            // CPU + peak RSS from getrusage(RUSAGE_SELF) — always accurate for
            // self, regardless of procfs. ru_maxrss is KiB on FreeBSD (as Linux).
            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: getrusage(RUSAGE_SELF) fills `ru`; a zeroed rusage is a
            // valid out-buffer.
            let ru_ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0;
            if ru_ok {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.user_us = to_us(ru.ru_utime);
                usage.system_us = to_us(ru.ru_stime);
                usage.maxrss_bytes = (ru.ru_maxrss.max(0) as u64).saturating_mul(1024);
                usage.majflt = ru.ru_majflt.max(0) as u64;
            }

            // RUSAGE_CHILDREN for reaped children (tms_cutime / RUSAGE_CHILDREN).
            let mut ruc: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: same contract for RUSAGE_CHILDREN.
            if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ruc) } == 0 {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.child_user_us = to_us(ruc.ru_utime);
                usage.child_system_us = to_us(ruc.ru_stime);
            }

            // Current VSZ / RSS from the live kinfo_proc — the BSD analogue of
            // /proc/self/statm (FreeBSD has no procfs by default). ki_size is the
            // virtual size in BYTES; ki_rssize is the resident set in PAGES.
            let mut kinfo_ok = false;
            if let Some(kp) = freebsd::read_kinfo(std::process::id()) {
                // SAFETY: sysconf(_SC_PAGESIZE) has no side effects; >0 on FreeBSD.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
                usage.virtual_bytes = kp.ki_size as u64;
                usage.resident_bytes = (kp.ki_rssize.max(0) as u64).saturating_mul(page);
                kinfo_ok = true;
            }

            // FreeBSD's getrusage(RUSAGE_SELF).ru_maxrss is the PEAK RSS, but the
            // kernel only updates it as the process accumulates resident pages —
            // a freshly-started process reads 0 (verified: a hello-world reports
            // ru_maxrss=0). Peak RSS is by definition ≥ the current RSS, so floor
            // it to the live resident size: this keeps VmHWM/ru_maxrss positive
            // and consistent (peak ≥ current) without ever over-reporting.
            if usage.maxrss_bytes < usage.resident_bytes {
                usage.maxrss_bytes = usage.resident_bytes;
            }

            if !ru_ok && !kinfo_ok {
                return None;
            }
            Some(usage)
        }
        #[cfg(target_os = "netbsd")]
        {
            let mut usage = ResourceUsage::default();

            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: getrusage(RUSAGE_SELF) fills `ru`; a zeroed rusage is a
            // valid out-buffer.
            let ru_ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0;
            if ru_ok {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.user_us = to_us(ru.ru_utime);
                usage.system_us = to_us(ru.ru_stime);
                usage.maxrss_bytes = (ru.ru_maxrss.max(0) as u64).saturating_mul(1024);
                usage.majflt = ru.ru_majflt.max(0) as u64;
            }

            let mut ruc: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: same contract for RUSAGE_CHILDREN.
            if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ruc) } == 0 {
                let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
                usage.child_user_us = to_us(ruc.ru_utime);
                usage.child_system_us = to_us(ruc.ru_stime);
            }

            let mut kinfo_ok = false;
            if let Some(kp) = netbsd::read_kinfo(std::process::id()) {
                // SAFETY: sysconf(_SC_PAGESIZE) has no side effects; >0 on NetBSD.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
                usage.virtual_bytes = kp.p_vm_vsize.max(0) as u64;
                usage.resident_bytes = (kp.p_vm_rssize.max(0) as u64).saturating_mul(page);
                kinfo_ok = true;
            }

            if usage.maxrss_bytes < usage.resident_bytes {
                usage.maxrss_bytes = usage.resident_bytes;
            }

            if !ru_ok && !kinfo_ok {
                return None;
            }
            Some(usage)
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd")))]
        {
            None
        }
    }

    pub fn self_vm_region_count() -> Option<u64> {
        None
    }

    pub fn reserve_self_direct_vm_range(
        _start: u64,
        _length: u64,
    ) -> Result<super::DirectVmReservationOutcome, super::DirectVmReservationError> {
        Err(super::DirectVmReservationError::Unsupported)
    }

    /// Native-backend VmRSS measurement is a Darwin mach-walk; no equivalent
    /// is needed here (the native exec backend is macOS-only).
    pub fn resident_bytes_in_ranges(_ranges: &[(u64, u64)]) -> Option<u64> {
        None
    }

    /// (user_us, system_us) CPU time for the CURRENT thread, from the host
    /// kernel's own per-thread accounting: `getrusage(RUSAGE_THREAD)`. KVM
    /// guest execution is charged to the vCPU thread as guest time, which
    /// Linux folds into utime — so a busy guest's user time ADVANCES here
    /// (LTP getrusage04 spins on getrusage(RUSAGE_THREAD) until it does).
    /// The dispatcher runs on the same host thread as the vCPU that issued
    /// the syscall, so "current thread" is the right scope — mirroring the
    /// macOS impl, which reads the calling host thread's
    /// `thread_info(THREAD_BASIC_INFO)`. FreeBSD exposes the same scope as
    /// `RUSAGE_THREAD`; NetBSD's libc target does not expose an equivalent
    /// per-thread rusage selector, so that host stays inert here.
    pub fn self_thread_cpu_us() -> Option<(u64, u64)> {
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: getrusage(RUSAGE_THREAD) fills `ru` for the calling
            // thread; a zeroed rusage is a valid out-buffer.
            if unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) } != 0 {
                return None;
            }
            let to_us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
            Some((to_us(ru.ru_utime), to_us(ru.ru_stime)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
        {
            None
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod stat_parse_tests {
        use super::parse_stat;

        #[test]
        fn parses_fields_after_last_close_paren() {
            // comm containing spaces AND a paren — the canonical proc(5) trap.
            let line = "1234 (a (weird) name) S 1 1234 1234 0 -1 4194560 0 0\n";
            let (comm, state, ppid, pgrp) = parse_stat(line).unwrap();
            assert_eq!(comm, "a (weird) name");
            assert_eq!(state, 'S');
            assert_eq!(ppid, 1);
            assert_eq!(pgrp, 1234);
        }

        #[test]
        fn rejects_malformed_lines() {
            assert!(parse_stat("not a stat line").is_none());
            assert!(parse_stat("1 (x)").is_none());
        }
    }
}

#[cfg(target_os = "macos")]
pub use imp::self_cpu_total_ns;
pub use imp::{
    current_thread_port, is_guest_process, pid_info, reserve_self_direct_vm_range,
    resident_bytes_in_ranges, self_resource_usage, self_thread_cpu_us, self_vm_region_count,
    thread_cpu_us_for_port, thread_run_state_char,
};

/// Mach port type alias for the registry (real on macOS, u32 elsewhere).
#[cfg(target_os = "macos")]
pub type ThreadPort = libc::mach_port_t;
#[cfg(not(target_os = "macos"))]
pub type ThreadPort = u32;

#[cfg(test)]
mod accounting_smoke {
    /// `self_resource_usage` CPU times must agree with the kernel's own
    /// `getrusage(RUSAGE_SELF)` (both are µs of this process's CPU). The old
    /// code read `proc_pid_rusage`'s mach-time-unit fields as nanoseconds and
    /// under-reported ~41.7× on Apple Silicon — this test fails against that
    /// interpretation. Tolerances are wide (2×) because other test threads
    /// keep burning CPU between the two reads, only monotonically inflating
    /// the later one.
    #[cfg(target_os = "macos")]
    #[test]
    fn self_cpu_matches_getrusage_units() {
        // Burn enough CPU that unit errors dominate scheduling noise.
        let mut acc: u64 = 1;
        for _ in 0..40_000_000u64 {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
            acc ^= acc >> 17;
        }
        std::hint::black_box(acc);
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) }, 0);
        let getrusage_cpu_us = (ru.ru_utime.tv_sec as u64 * 1_000_000 + ru.ru_utime.tv_usec as u64)
            + (ru.ru_stime.tv_sec as u64 * 1_000_000 + ru.ru_stime.tv_usec as u64);
        let usage = super::self_resource_usage().expect("resource usage available");
        // The HVF guest_cpu addition is 0 in unit tests, so user+system here is
        // purely the converted proc_pid_rusage reading.
        let converted_us = usage.user_us + usage.system_us;
        assert!(
            converted_us >= getrusage_cpu_us / 2,
            "converted CPU {converted_us}µs under-reports getrusage {getrusage_cpu_us}µs — \
             mach-time-unit conversion regressed"
        );
        assert!(
            converted_us <= getrusage_cpu_us.saturating_mul(2).saturating_add(100_000),
            "converted CPU {converted_us}µs over-reports getrusage {getrusage_cpu_us}µs"
        );
        let total_ns = super::self_cpu_total_ns().expect("self cpu total");
        assert!(
            total_ns / 1000 >= getrusage_cpu_us / 2,
            "self_cpu_total_ns {total_ns}ns under-reports getrusage {getrusage_cpu_us}µs"
        );
    }

    /// The mach-walk residency measurement: touched pages of a private mapping
    /// count as resident, the result never exceeds the queried span, and
    /// passing the same range twice must not double-count (merge invariant).
    #[cfg(target_os = "macos")]
    #[test]
    fn resident_bytes_in_ranges_measures_touched_pages() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = page * 4;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        // Touch two of the four pages.
        unsafe {
            std::ptr::write_volatile(base.cast::<u8>(), 1);
            std::ptr::write_volatile(base.cast::<u8>().add(page), 1);
        }
        let range = (base as u64, base as u64 + len as u64);
        let resident =
            super::resident_bytes_in_ranges(&[range]).expect("mach region walk succeeds");
        assert!(
            resident >= 2 * page as u64,
            "two touched pages must be resident (got {resident} bytes)"
        );
        assert!(
            resident <= len as u64,
            "residency is clipped to the queried span (got {resident} > {len})"
        );
        let doubled =
            super::resident_bytes_in_ranges(&[range, range]).expect("duplicate ranges still walk");
        assert_eq!(
            doubled, resident,
            "overlapping input ranges must merge, not double-count"
        );
        unsafe { libc::munmap(base, len) };
    }

    #[test]
    fn self_resource_usage_does_not_crash() {
        let u = super::self_resource_usage();
        // On macOS this must succeed and report non-zero virtual size.
        #[cfg(target_os = "macos")]
        {
            let u = u.expect("resource usage available");
            assert!(u.virtual_bytes > 0, "vsize should be > 0");
        }
        // FreeBSD reads kinfo_proc via sysctl: the live process always has a
        // positive virtual + resident size and a non-negative peak RSS. This is
        // exactly what /proc/self/statm + /proc/self/status + getrusage(maxrss)
        // surface to the guest (the accounting probe). Linux uses the same
        // surfaces but `self_resource_usage` is a no-op stub there (guest_cpu
        // supplies CPU), so this stronger assert is FreeBSD-only.
        #[cfg(target_os = "freebsd")]
        {
            let u = u.expect("resource usage available on freebsd");
            assert!(u.virtual_bytes > 0, "vsize should be > 0");
            assert!(u.resident_bytes > 0, "rss should be > 0");
            assert!(u.maxrss_bytes > 0, "maxrss should be > 0");
        }
        let _ = u;
    }
    #[test]
    fn self_thread_cpu_does_not_crash() {
        let _ = super::self_thread_cpu_us();
    }
}
