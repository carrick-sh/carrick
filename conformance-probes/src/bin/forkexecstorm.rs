//! Concurrency test for parallel vfork + execve(/bin/true) + waitpid
//! from a multithreaded process with bounded supervision and exact lifecycle instrumentation.
//!
//! When multiple threads concurrently invoke vfork + execve, each child must
//! receive its own independent stage-1 authority without clobbering the
//! parent's live page tables or stealing its arena source.
//!
//! Substantive workload:
//! - 4 simultaneously active guest threads
//! - 50 vfork -> execve(/bin/true) -> wait cycles per thread (200 cycles total)
//! - All 200 children independently executed and reaped with exit status 0
//! - Fully bounded via an outer supervisor to guarantee hang-free termination
//!   and scoped cleanup of owned descendants even under kernel or vfork failure.
//! - Cleanup signaling authority is the authenticated dedicated workload PROCESS GROUP,
//!   whose identity is pinned by retaining its leader unreaped until cleanup signaling completes.
//! - Subreaper (on Linux) guarantees adopted descendant reap to ECHILD under all failure modes.

#![allow(clippy::missing_safety_doc)]

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

pub const THREAD_COUNT: usize = 4;
pub const ITERATIONS_PER_THREAD: usize = 50;
pub const EXPECTED_TOTAL_CHILDREN: u32 = (THREAD_COUNT * ITERATIONS_PER_THREAD) as u32;
pub const DEFAULT_SUPERVISOR_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_PER_CHILD_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_CONCURRENT_CHILDREN: usize = 32;

static TRUE_PATH: &[u8] = b"/bin/true\0";
static FAILING_PATH: &[u8] = b"/nonexistent_forkexecstorm_binary_path_404\0";
static SLEEP_PATH: &[u8] = b"/bin/sleep\0";
static SLEEP_ARG: &[u8] = b"60\0";

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Telemetry {
    pub threads_started: u32,
    pub threads_completed: u32,
    pub threads_joined: u32,
    pub total_attempted: u32,
    pub total_spawned: u32,
    pub total_reaped: u32,
    pub total_exited_ok: u32,
    pub vfork_failures: u32,
    pub first_vfork_errno: i32,
    pub wait_failures: u32,
    pub first_wait_errno: i32,
    pub unexpected_status_count: u32,
    pub first_unexpected_status: i32,
    pub timed_out: bool,
    pub fork_exec_storm_success: bool,
}

pub fn report_telemetry(t: &Telemetry) {
    report!(
        threads_started = t.threads_started,
        threads_completed = t.threads_completed,
        threads_joined = t.threads_joined,
        total_attempted = t.total_attempted,
        total_spawned = t.total_spawned,
        total_reaped = t.total_reaped,
        total_exited_ok = t.total_exited_ok,
        vfork_failures = t.vfork_failures,
        first_vfork_errno = t.first_vfork_errno,
        wait_failures = t.wait_failures,
        first_wait_errno = t.first_wait_errno,
        unexpected_status_count = t.unexpected_status_count,
        first_unexpected_status = t.first_unexpected_status,
        timed_out = t.timed_out,
        fork_exec_storm_success = t.fork_exec_storm_success,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupReport {
    pub group_killed: bool,
    pub workload_killed: bool,
    pub workload_reaped: bool,
    pub descendants_reaped: u32,
    pub all_descendants_reaped: bool,
    pub unretired_children: u32,
    pub cleanup_succeeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisedResult {
    pub telemetry: Telemetry,
    pub cleanup: CleanupReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMode {
    None,
    FailSubreaper,
    FailVfork,
    FailExec,
    WithholdChildExitBeforeExec,
    WithholdChildExitAfterExec,
    PanicThread,
    FailGroupSetup,
    PartialStreamWrite,
}

/// Audited non-returning child boundary for AArch64 Linux.
///
/// Encapsulates clone(CLONE_VM | CLONE_VFORK | SIGCHLD) + child execution + execve/exit.
/// The child NEVER returns to caller Rust frames, NEVER touches or clobbers the suspended
/// parent's shared stack, and executes precomputed arguments entirely via direct syscalls.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[inline(never)]
unsafe fn vfork_exec_child(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    withhold_before_exec: bool,
) -> libc::pid_t {
    let mut pid: libc::pid_t;
    let withhold_flag: u64 = if withhold_before_exec { 1 } else { 0 };
    core::arch::asm!(
        "mov x0, 0x4111",      // flags = CLONE_VM | CLONE_VFORK | SIGCHLD
        "mov x1, 0",           // child_stack = 0 (same stack, child never writes)
        "mov x2, 0",           // parent_tid = 0
        "mov x3, 0",           // tls = 0
        "mov x4, 0",           // child_tid = 0
        "mov x8, 220",         // SYS_clone
        "svc #0",

        "cbz x0, 2f",
        "b 7f",

        // Child path: NEVER RETURNS TO CALLER, NEVER TOUCHES STACK
        "2:",
        "cbz x23, 3f",

        // Withhold pre-exec loop:
        "5:",
        "adr x0, 6f",          // pointer to static timespec
        "mov x1, 0",           // rem = NULL
        "mov x8, 101",         // SYS_nanosleep
        "svc #0",
        "b 5b",

        // Execve path:
        "3:",
        "mov x0, x20",
        "mov x1, x21",
        "mov x2, x22",
        "mov x8, 221",         // SYS_execve
        "svc #0",

        // If execve returns, it failed: exit with status 127
        "mov x0, 127",
        "mov x8, 93",          // SYS_exit
        "svc #0",

        "4:",
        "b 4b",

        ".p2align 3",
        "6:",
        ".quad 1",
        ".quad 0",

        "7:",
        in("x20") path,
        in("x21") argv,
        in("x22") envp,
        in("x23") withhold_flag,
        out("x0") pid,
        out("x1") _,
        out("x2") _,
        out("x3") _,
        out("x4") _,
        out("x8") _,
        clobber_abi("C"),
    );

    if pid < 0 {
        *libc::__errno_location() = -pid;
        -1
    } else {
        pid
    }
}

/// Audited non-returning child boundary for x86_64 Linux.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(never)]
unsafe fn vfork_exec_child(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    withhold_before_exec: bool,
) -> libc::pid_t {
    let mut pid: i64;
    let withhold_flag: u64 = if withhold_before_exec { 1 } else { 0 };
    core::arch::asm!(
        "mov rax, 56",        // SYS_clone
        "mov rdi, 0x4111",    // flags = CLONE_VM | CLONE_VFORK | SIGCHLD
        "mov rsi, 0",         // child_stack = 0
        "mov rdx, 0",         // parent_tid = 0
        "mov r10, 0",         // child_tid = 0
        "mov r8, 0",          // tls = 0
        "syscall",

        "test rax, rax",
        "jz 2f",
        "jmp 7f",

        // Child path:
        "2:",
        "test r15, r15",
        "jz 3f",

        // Withhold loop:
        "5:",
        "lea rdi, [rip + 6f]",
        "mov rsi, 0",
        "mov rax, 35",         // SYS_nanosleep
        "syscall",
        "jmp 5b",

        // Execve path:
        "3:",
        "mov rdi, r12",
        "mov rsi, r13",
        "mov rdx, r14",
        "mov rax, 59",         // SYS_execve
        "syscall",

        // Exit with 127 if execve fails
        "mov rdi, 127",
        "mov rax, 60",         // SYS_exit
        "syscall",

        "4:",
        "jmp 4b",

        ".p2align 3",
        "6:",
        ".quad 1",
        ".quad 0",

        "7:",
        in("r12") path,
        in("r13") argv,
        in("r14") envp,
        in("r15") withhold_flag,
        out("rax") pid,
        out("rdi") _,
        out("rsi") _,
        out("rdx") _,
        out("r10") _,
        out("r8") _,
        out("rcx") _,
        out("r11") _,
        clobber_abi("C"),
    );

    let pid = pid as libc::pid_t;
    if pid < 0 {
        *libc::__errno_location() = -pid;
        -1
    } else {
        pid
    }
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64")
)))]
compile_error!(
    "forkexecstorm probe only supports aarch64-linux (canonical native Docker qualification) and x86_64-linux (compile-only/unqualified)"
);

#[repr(C)]
pub struct ChildSlot {
    pub pid: AtomicI32,
    pub active: AtomicU32,
}

impl Default for ChildSlot {
    fn default() -> Self {
        Self {
            pid: AtomicI32::new(0),
            active: AtomicU32::new(0),
        }
    }
}

#[repr(C)]
struct SharedState {
    child_slots: [ChildSlot; MAX_CONCURRENT_CHILDREN],
    threads_started: AtomicU32,
    threads_completed: AtomicU32,
    total_attempted: AtomicU32,
    total_spawned: AtomicU32,
    total_reaped: AtomicU32,
    total_exited_ok: AtomicU32,
    vfork_failures: AtomicU32,
    first_vfork_errno: AtomicI32,
    wait_failures: AtomicU32,
    first_wait_errno: AtomicI32,
    unexpected_status_count: AtomicU32,
    first_unexpected_status: AtomicI32,
}

/// Allocate a pipe pair with error return, closing partial descriptors if creation fails.
#[inline]
pub fn create_fallible_pipe() -> Result<(i32, i32), i32> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(errno());
    }
    Ok((fds[0], fds[1]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadExactResult {
    Ok,
    Timeout,
    EofOrError,
}

/// Read exact buffer from a file descriptor before deadline expires.
pub fn read_exact_bounded(
    fd: i32,
    buf: &mut [u8],
    deadline: std::time::Instant,
) -> ReadExactResult {
    let mut offset = 0;
    while offset < buf.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return ReadExactResult::Timeout;
        }
        let remaining = deadline.saturating_duration_since(now);
        let remaining_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut poll_fd, 1, remaining_ms) };
        if prc == 0 {
            return ReadExactResult::Timeout;
        }
        if prc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return ReadExactResult::EofOrError;
        }
        if (poll_fd.revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
            return ReadExactResult::EofOrError;
        }
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().add(offset).cast(), buf.len() - offset) };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 || errno() != libc::EINTR {
            return ReadExactResult::EofOrError;
        }
    }
    ReadExactResult::Ok
}

/// Write exact buffer to a file descriptor before deadline expires.
pub fn write_all_bounded(fd: i32, buf: &[u8], deadline: std::time::Instant) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now);
        let remaining_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT | libc::POLLERR,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut poll_fd, 1, remaining_ms) };
        if prc <= 0 {
            if prc < 0 && errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        if (poll_fd.revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
            return false;
        }
        let n = unsafe { libc::write(fd, buf.as_ptr().add(offset).cast(), buf.len() - offset) };
        if n > 0 {
            offset += n as usize;
        } else if errno() != libc::EINTR {
            return false;
        }
    }
    offset == buf.len()
}

/// Bounded reap of a specific PID using WNOHANG polling with strict cumulative deadline.
#[allow(clippy::disallowed_methods)]
pub unsafe fn bounded_reap_pid(pid: libc::pid_t, timeout: Duration) -> (libc::pid_t, i32, bool) {
    if pid <= 0 {
        return (pid, 0, false);
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut status = 0i32;
    loop {
        if std::time::Instant::now() >= deadline {
            return (0, 0, true);
        }
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return (rc, status, false);
        }
        if rc == -1 {
            let err = errno();
            if err == libc::EINTR {
                continue;
            }
            return (rc, status, false);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return (0, 0, true);
        }
        let sleep_ns = remaining.as_nanos().min(1_000_000) as i64;
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: sleep_ns,
        };
        libc::nanosleep(&ts, core::ptr::null_mut());
    }
}

/// Bounded reap of all pending child processes using waitpid(-1, WNOHANG) with strict cumulative deadline.
/// Returns `(reaped_count, all_descendants_gone)`.
/// `all_descendants_gone` is true ONLY if waitpid(-1) returned ECHILD, proving no live descendants remain.
#[allow(clippy::disallowed_methods)]
pub unsafe fn reap_all_descendants_bounded(timeout: Duration) -> (u32, bool) {
    let deadline = std::time::Instant::now() + timeout;
    let mut count = 0u32;
    let mut all_descendants_gone = false;
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let mut status = 0i32;
        let rc = libc::waitpid(-1, &mut status, libc::WNOHANG);
        if rc > 0 {
            count += 1;
            continue;
        }
        if rc == -1 {
            let err = errno();
            if err == libc::EINTR {
                continue;
            }
            if err == libc::ECHILD {
                all_descendants_gone = true;
                break;
            }
            break;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let sleep_ns = remaining.as_nanos().min(1_000_000) as i64;
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: sleep_ns,
        };
        libc::nanosleep(&ts, core::ptr::null_mut());
    }
    (count, all_descendants_gone)
}

#[cfg(target_os = "linux")]
#[inline]
unsafe fn siginfo_get_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid()
}

#[cfg(not(target_os = "linux"))]
#[inline]
unsafe fn siginfo_get_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

/// Bounded non-consuming check for leader exit using waitid(P_PID, WEXITED | WNOWAIT | WNOHANG).
/// Returns Ok(true) if leader has exited, Ok(false) if still running, Err(errno) on error.
#[allow(clippy::disallowed_methods)]
pub unsafe fn observe_leader_exited(pid: libc::pid_t) -> Result<bool, i32> {
    if pid <= 1 {
        return Ok(true);
    }
    let mut info: libc::siginfo_t = core::mem::zeroed();
    let rc = libc::waitid(
        libc::P_PID,
        pid as libc::id_t,
        &mut info,
        libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
    );
    if rc != 0 {
        return Err(errno());
    }
    let si_pid = siginfo_get_pid(&info);
    let exited = si_pid == pid || si_pid != 0;
    Ok(exited)
}

/// Bounded non-consuming wait for leader exit using waitid(P_PID, WEXITED | WNOWAIT | WNOHANG).
/// Does not consume/reap the leader PID, preserving process group identity.
#[allow(clippy::disallowed_methods)]
pub unsafe fn bounded_observe_leader_exited(pid: libc::pid_t, timeout: Duration) -> (bool, bool) {
    if pid <= 1 {
        return (true, false);
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match observe_leader_exited(pid) {
            Ok(true) => return (true, false),
            Ok(false) => {}
            Err(err) => {
                if err == libc::ECHILD {
                    return (true, false);
                }
                if err != libc::EINTR {
                    return (false, false);
                }
            }
        }

        if std::time::Instant::now() >= deadline {
            return (false, true);
        }

        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return (false, true);
        }
        let sleep_ns = remaining.as_nanos().min(1_000_000) as i64;
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: sleep_ns,
        };
        libc::nanosleep(&ts, core::ptr::null_mut());
    }
}

/// Explicitly cleans up owned workload and descendants via authenticated process group signaling.
///
/// Leader identity is retained unreaped until process group signaling completes, pinning the PGID.
#[allow(clippy::disallowed_methods)]
pub unsafe fn cleanup_owned_descendants(
    workload_pid: libc::pid_t,
    workload_reaped: &mut bool,
    group_authenticated: &mut bool,
    state_ptr: usize,
    leader_status: &mut i32,
) -> CleanupReport {
    let mut report = CleanupReport::default();
    let st = if state_ptr != 0 {
        &*(state_ptr as *const SharedState)
    } else {
        core::ptr::null()
    };

    // 1. Group kill ONLY if group was authenticated AND leader not yet reaped
    if *group_authenticated && !*workload_reaped && workload_pid > 1 {
        let rc = libc::kill(-workload_pid, libc::SIGKILL);
        if rc == 0 {
            report.group_killed = true;
        } else {
            let err = errno();
            if err == libc::ESRCH {
                report.group_killed = true;
            }
        }
    }
    *group_authenticated = false;

    // 2. Direct kill & reap of workload leader if not yet reaped
    if !*workload_reaped && workload_pid > 1 {
        if !report.group_killed {
            let rc = libc::kill(workload_pid, libc::SIGKILL);
            if rc == 0 {
                report.workload_killed = true;
            } else {
                let err = errno();
                if err == libc::ESRCH {
                    report.workload_killed = true;
                }
            }
        }
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        libc::nanosleep(&ts, core::ptr::null_mut());
        if report.group_killed {
            let _ = libc::kill(-workload_pid, libc::SIGKILL);
        }
        let (waited, status, _) = bounded_reap_pid(workload_pid, Duration::from_millis(500));
        if waited == workload_pid {
            *workload_reaped = true;
            report.workload_reaped = true;
            *leader_status = status;
        }
    } else if *workload_reaped || workload_pid <= 1 {
        *workload_reaped = true;
        report.workload_reaped = true;
    }

    // 3. Bounded reap of all remaining reparented descendants
    let (reaped_count, all_descendants_gone) =
        reap_all_descendants_bounded(Duration::from_millis(500));
    report.descendants_reaped = reaped_count;
    report.all_descendants_reaped = all_descendants_gone;

    // 4. Upon verified group kill, leader reap, and descendant reap, retire observation slots
    if report.group_killed && *workload_reaped && all_descendants_gone && !st.is_null() {
        for i in 0..MAX_CONCURRENT_CHILDREN {
            let slot_ref = &(*st).child_slots[i];
            slot_ref.active.store(0, Ordering::Release);
            slot_ref.pid.store(0, Ordering::Release);
        }
    }

    // 5. Final census of child observation table
    if !st.is_null() {
        for i in 0..MAX_CONCURRENT_CHILDREN {
            let slot_ref = &(*st).child_slots[i];
            let active = slot_ref.active.load(Ordering::Acquire);
            let pid = slot_ref.pid.load(Ordering::Acquire);
            if active != 0 || pid > 1 {
                report.unretired_children += 1;
            }
        }
    }

    report.cleanup_succeeded =
        *workload_reaped && report.unretired_children == 0 && all_descendants_gone;
    report
}

#[allow(clippy::disallowed_methods)]
fn thread_worker(
    state_ptr: usize,
    injection: InjectionMode,
    thread_idx: usize,
    per_child_timeout: Duration,
) {
    let state = unsafe { &*(state_ptr as *const SharedState) };
    let slot = thread_idx % MAX_CONCURRENT_CHILDREN;

    state.threads_started.fetch_add(1, Ordering::Relaxed);

    if injection == InjectionMode::PanicThread && thread_idx == 0 {
        panic!("injected worker thread panic for testing join loss");
    }

    let (exec_path, argv_ptrs) = match injection {
        InjectionMode::FailExec => (
            FAILING_PATH.as_ptr().cast::<libc::c_char>(),
            [
                FAILING_PATH.as_ptr().cast::<libc::c_char>(),
                core::ptr::null(),
                core::ptr::null(),
            ],
        ),
        InjectionMode::WithholdChildExitAfterExec => (
            SLEEP_PATH.as_ptr().cast::<libc::c_char>(),
            [
                SLEEP_PATH.as_ptr().cast::<libc::c_char>(),
                SLEEP_ARG.as_ptr().cast::<libc::c_char>(),
                core::ptr::null(),
            ],
        ),
        _ => (
            TRUE_PATH.as_ptr().cast::<libc::c_char>(),
            [
                TRUE_PATH.as_ptr().cast::<libc::c_char>(),
                core::ptr::null(),
                core::ptr::null(),
            ],
        ),
    };
    let envp = [core::ptr::null()];
    let withhold_before_exec = injection == InjectionMode::WithholdChildExitBeforeExec;

    for _ in 0..ITERATIONS_PER_THREAD {
        state.total_attempted.fetch_add(1, Ordering::Relaxed);

        if injection == InjectionMode::FailVfork {
            state.vfork_failures.fetch_add(1, Ordering::Relaxed);
            let _ = state.first_vfork_errno.compare_exchange(
                0,
                libc::EAGAIN,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }

        // Audited non-returning child boundary: child never returns to Rust frame or touches stack.
        let child = unsafe {
            vfork_exec_child(
                exec_path,
                argv_ptrs.as_ptr(),
                envp.as_ptr(),
                withhold_before_exec,
            )
        };

        if child < 0 {
            let err = errno();
            state.vfork_failures.fetch_add(1, Ordering::Relaxed);
            let _ = state.first_vfork_errno.compare_exchange(
                0,
                err,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }

        // child > 0: record child PID in observation slot
        state.total_spawned.fetch_add(1, Ordering::Relaxed);
        let slot_ref = &state.child_slots[slot];
        slot_ref.pid.store(child, Ordering::Release);
        slot_ref.active.store(1, Ordering::Release);

        let (waited, status, timed_out) = unsafe { bounded_reap_pid(child, per_child_timeout) };

        if timed_out || waited != child {
            let err = if waited < 0 { errno() } else { libc::ETIMEDOUT };
            state.wait_failures.fetch_add(1, Ordering::Relaxed);
            let _ = state.first_wait_errno.compare_exchange(
                0,
                err,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }

        // Successfully reaped: clear observation slot
        slot_ref.active.store(0, Ordering::Release);
        slot_ref.pid.store(0, Ordering::Release);
        state.total_reaped.fetch_add(1, Ordering::Relaxed);

        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            state.total_exited_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            state
                .unexpected_status_count
                .fetch_add(1, Ordering::Relaxed);
            let _ = state.first_unexpected_status.compare_exchange(
                0,
                status,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            return;
        }
    }

    state.threads_completed.fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::disallowed_methods)]
fn run_workload(
    state_ptr: usize,
    injection: InjectionMode,
    per_child_timeout: Duration,
) -> (Telemetry, u32) {
    let state = unsafe { &*(state_ptr as *const SharedState) };
    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for idx in 0..THREAD_COUNT {
        handles.push(thread::spawn(move || {
            thread_worker(state_ptr, injection, idx, per_child_timeout)
        }));
    }

    let mut threads_joined = 0u32;
    for h in handles {
        if h.join().is_ok() {
            threads_joined += 1;
        }
    }

    let threads_started = state.threads_started.load(Ordering::Relaxed);
    let threads_completed = state.threads_completed.load(Ordering::Relaxed);
    let total_attempted = state.total_attempted.load(Ordering::Relaxed);
    let total_spawned = state.total_spawned.load(Ordering::Relaxed);
    let total_reaped = state.total_reaped.load(Ordering::Relaxed);
    let total_exited_ok = state.total_exited_ok.load(Ordering::Relaxed);
    let vfork_failures = state.vfork_failures.load(Ordering::Relaxed);
    let first_vfork_errno = state.first_vfork_errno.load(Ordering::Relaxed);
    let wait_failures = state.wait_failures.load(Ordering::Relaxed);
    let first_wait_errno = state.first_wait_errno.load(Ordering::Relaxed);
    let unexpected_status_count = state.unexpected_status_count.load(Ordering::Relaxed);
    let first_unexpected_status = state.first_unexpected_status.load(Ordering::Relaxed);

    let fork_exec_storm_success = threads_started == THREAD_COUNT as u32
        && threads_completed == THREAD_COUNT as u32
        && threads_joined == THREAD_COUNT as u32
        && total_attempted == EXPECTED_TOTAL_CHILDREN
        && total_spawned == EXPECTED_TOTAL_CHILDREN
        && total_reaped == EXPECTED_TOTAL_CHILDREN
        && total_exited_ok == EXPECTED_TOTAL_CHILDREN
        && vfork_failures == 0
        && wait_failures == 0
        && unexpected_status_count == 0;

    let telemetry = Telemetry {
        threads_started,
        threads_completed,
        threads_joined,
        total_attempted,
        total_spawned,
        total_reaped,
        total_exited_ok,
        vfork_failures,
        first_vfork_errno,
        wait_failures,
        first_wait_errno,
        unexpected_status_count,
        first_unexpected_status,
        timed_out: false,
        fork_exec_storm_success,
    };

    (telemetry, threads_joined)
}

#[allow(clippy::disallowed_methods)]
pub fn run_supervised(
    injection: InjectionMode,
    timeout: Duration,
    per_child_timeout: Duration,
) -> SupervisedResult {
    // 1. Allocate shared memory region for live state & positive PID registry
    let state_size = core::mem::size_of::<SharedState>();
    let state_map = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            state_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if state_map == libc::MAP_FAILED {
        return SupervisedResult {
            telemetry: Telemetry {
                vfork_failures: 1,
                first_vfork_errno: errno(),
                ..Default::default()
            },
            cleanup: CleanupReport {
                cleanup_succeeded: true,
                ..Default::default()
            },
        };
    }
    unsafe {
        core::ptr::write_bytes(state_map, 0, state_size);
    }
    let state_ptr = state_map as usize;

    // 2. Establish child subreaper on Linux to catch reparented descendants
    #[cfg(target_os = "linux")]
    let subreaper_ok = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0 };
    #[cfg(not(target_os = "linux"))]
    let subreaper_ok = true;

    if !subreaper_ok || injection == InjectionMode::FailSubreaper {
        let err = if injection == InjectionMode::FailSubreaper {
            libc::EPERM
        } else {
            errno()
        };
        unsafe {
            libc::munmap(state_map, state_size);
        }
        return SupervisedResult {
            telemetry: Telemetry {
                vfork_failures: 1,
                first_vfork_errno: err,
                ..Default::default()
            },
            cleanup: CleanupReport {
                cleanup_succeeded: true,
                ..Default::default()
            },
        };
    }

    // 3. Allocate fallible pipes with cleanup on partial allocation failure
    let (read_fd, write_fd) = match create_fallible_pipe() {
        Ok(pair) => pair,
        Err(err) => {
            unsafe {
                libc::munmap(state_map, state_size);
            }
            return SupervisedResult {
                telemetry: Telemetry {
                    vfork_failures: 1,
                    first_vfork_errno: err,
                    ..Default::default()
                },
                cleanup: CleanupReport {
                    cleanup_succeeded: true,
                    ..Default::default()
                },
            };
        }
    };

    let (handshake_r, handshake_w) = match create_fallible_pipe() {
        Ok(pair) => pair,
        Err(err) => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
                libc::munmap(state_map, state_size);
            }
            return SupervisedResult {
                telemetry: Telemetry {
                    vfork_failures: 1,
                    first_vfork_errno: err,
                    ..Default::default()
                },
                cleanup: CleanupReport {
                    cleanup_succeeded: true,
                    ..Default::default()
                },
            };
        }
    };

    let (ack_r, ack_w) = match create_fallible_pipe() {
        Ok(pair) => pair,
        Err(err) => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
                libc::close(handshake_r);
                libc::close(handshake_w);
                libc::munmap(state_map, state_size);
            }
            return SupervisedResult {
                telemetry: Telemetry {
                    vfork_failures: 1,
                    first_vfork_errno: err,
                    ..Default::default()
                },
                cleanup: CleanupReport {
                    cleanup_succeeded: true,
                    ..Default::default()
                },
            };
        }
    };

    let workload_pid = unsafe { libc::fork() };
    if workload_pid < 0 {
        let err = errno();
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
            libc::close(handshake_r);
            libc::close(handshake_w);
            libc::close(ack_r);
            libc::close(ack_w);
            libc::munmap(state_map, state_size);
        }
        return SupervisedResult {
            telemetry: Telemetry {
                vfork_failures: 1,
                first_vfork_errno: err,
                ..Default::default()
            },
            cleanup: CleanupReport {
                cleanup_succeeded: true,
                ..Default::default()
            },
        };
    }

    if workload_pid == 0 {
        // Child workload process
        unsafe {
            libc::close(read_fd);
            libc::close(handshake_r);
            libc::close(ack_w);
        }

        let mut pgid_ok = false;
        if injection != InjectionMode::FailGroupSetup {
            let set_rc = unsafe { libc::setpgid(0, 0) };
            if set_rc == 0 {
                let get_pgrp = unsafe { libc::getpgrp() };
                let my_pid = unsafe { libc::getpid() };
                if get_pgrp == my_pid && my_pid > 1 {
                    pgid_ok = true;
                }
            }
        }

        let handshake_byte = [if pgid_ok { 1u8 } else { 0u8 }];
        let write_ok = write_all_bounded(
            handshake_w,
            &handshake_byte,
            std::time::Instant::now() + Duration::from_secs(1),
        );
        unsafe {
            libc::close(handshake_w);
        }

        if !pgid_ok || !write_ok {
            unsafe {
                libc::close(ack_r);
                libc::close(write_fd);
                libc::_exit(2);
            }
        }

        // Bounded two-way enrollment: wait for parent's durable group acceptance ACK
        let mut ack_byte = [0u8; 1];
        let ack_res = read_exact_bounded(
            ack_r,
            &mut ack_byte,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        unsafe {
            libc::close(ack_r);
        }

        if ack_res != ReadExactResult::Ok || ack_byte[0] != 1 {
            unsafe {
                libc::close(write_fd);
                libc::_exit(3);
            }
        }

        let (telemetry, _joined) = run_workload(state_ptr, injection, per_child_timeout);
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &telemetry as *const Telemetry as *const u8,
                core::mem::size_of::<Telemetry>(),
            )
        };

        let write_bytes = if injection == InjectionMode::PartialStreamWrite {
            &bytes[..bytes.len() / 2]
        } else {
            bytes
        };

        let _ = write_all_bounded(
            write_fd,
            write_bytes,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        unsafe {
            libc::close(write_fd);
            libc::_exit(if telemetry.fork_exec_storm_success {
                0
            } else {
                1
            });
        }
    }

    // Outer supervisor process
    unsafe {
        libc::close(write_fd);
        libc::close(handshake_w);
        libc::close(ack_r);
        if workload_pid > 1 {
            let _ = libc::setpgid(workload_pid, workload_pid);
        }
    }

    let mut handshake_byte = [0u8; 1];
    let handshake_deadline = std::time::Instant::now() + Duration::from_secs(2);
    let handshake_ok = read_exact_bounded(handshake_r, &mut handshake_byte, handshake_deadline)
        == ReadExactResult::Ok;
    unsafe {
        libc::close(handshake_r);
    }
    let mut group_authenticated = handshake_ok && handshake_byte[0] == 1 && workload_pid > 1;

    // Send ACK byte to child if group was authenticated
    if group_authenticated {
        let ack_byte = [1u8];
        let _ = write_all_bounded(
            ack_w,
            &ack_byte,
            std::time::Instant::now() + Duration::from_secs(1),
        );
    }
    unsafe {
        libc::close(ack_w);
    }

    let mut workload_reaped = false;

    let deadline = std::time::Instant::now() + timeout;

    let mut telemetry = Telemetry::default();
    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            &mut telemetry as *mut Telemetry as *mut u8,
            core::mem::size_of::<Telemetry>(),
        )
    };

    let read_res = read_exact_bounded(read_fd, buf, deadline);
    unsafe {
        libc::close(read_fd);
    }

    let mut leader_status = 0i32;

    if read_res == ReadExactResult::Timeout {
        let cleanup_report = unsafe {
            cleanup_owned_descendants(
                workload_pid,
                &mut workload_reaped,
                &mut group_authenticated,
                state_ptr,
                &mut leader_status,
            )
        };
        let st = unsafe { &*(state_map as *const SharedState) };
        let threads_started = st.threads_started.load(Ordering::Relaxed);
        let threads_completed = st.threads_completed.load(Ordering::Relaxed);
        let total_attempted = st.total_attempted.load(Ordering::Relaxed);
        let total_spawned = st.total_spawned.load(Ordering::Relaxed);
        let total_reaped = st.total_reaped.load(Ordering::Relaxed);
        let total_exited_ok = st.total_exited_ok.load(Ordering::Relaxed);
        let vfork_failures = st.vfork_failures.load(Ordering::Relaxed);
        let first_vfork_errno = st.first_vfork_errno.load(Ordering::Relaxed);
        let wait_failures = st.wait_failures.load(Ordering::Relaxed);
        let first_wait_errno = st.first_wait_errno.load(Ordering::Relaxed);
        let unexpected_status_count = st.unexpected_status_count.load(Ordering::Relaxed);
        let first_unexpected_status = st.first_unexpected_status.load(Ordering::Relaxed);

        unsafe {
            libc::munmap(state_map, state_size);
        }

        return SupervisedResult {
            telemetry: Telemetry {
                threads_started,
                threads_completed,
                threads_joined: 0,
                total_attempted,
                total_spawned,
                total_reaped,
                total_exited_ok,
                vfork_failures,
                first_vfork_errno,
                wait_failures,
                first_wait_errno,
                unexpected_status_count,
                first_unexpected_status,
                timed_out: true,
                fork_exec_storm_success: false,
            },
            cleanup: cleanup_report,
        };
    }

    if read_res != ReadExactResult::Ok {
        let cleanup_report = unsafe {
            cleanup_owned_descendants(
                workload_pid,
                &mut workload_reaped,
                &mut group_authenticated,
                state_ptr,
                &mut leader_status,
            )
        };
        let st = unsafe { &*(state_map as *const SharedState) };
        let threads_started = st.threads_started.load(Ordering::Relaxed);
        let threads_completed = st.threads_completed.load(Ordering::Relaxed);
        let total_attempted = st.total_attempted.load(Ordering::Relaxed);
        let total_spawned = st.total_spawned.load(Ordering::Relaxed);
        let total_reaped = st.total_reaped.load(Ordering::Relaxed);
        let total_exited_ok = st.total_exited_ok.load(Ordering::Relaxed);
        let vfork_failures = st.vfork_failures.load(Ordering::Relaxed);
        let first_vfork_errno = st.first_vfork_errno.load(Ordering::Relaxed);
        let wait_failures = st.wait_failures.load(Ordering::Relaxed);
        let first_wait_errno = st.first_wait_errno.load(Ordering::Relaxed);
        let unexpected_status_count = st.unexpected_status_count.load(Ordering::Relaxed);
        let first_unexpected_status = st.first_unexpected_status.load(Ordering::Relaxed);

        unsafe {
            libc::munmap(state_map, state_size);
        }

        return SupervisedResult {
            telemetry: Telemetry {
                threads_started,
                threads_completed,
                threads_joined: 0,
                total_attempted,
                total_spawned,
                total_reaped,
                total_exited_ok,
                vfork_failures,
                first_vfork_errno,
                wait_failures,
                first_wait_errno,
                unexpected_status_count,
                first_unexpected_status,
                timed_out: false,
                fork_exec_storm_success: false,
            },
            cleanup: cleanup_report,
        };
    }

    // Observe leader exit without consuming it first, pinning PGID identity
    let (leader_exited, leader_timed_out) =
        unsafe { bounded_observe_leader_exited(workload_pid, Duration::from_secs(5)) };

    let cleanup_report = unsafe {
        cleanup_owned_descendants(
            workload_pid,
            &mut workload_reaped,
            &mut group_authenticated,
            state_ptr,
            &mut leader_status,
        )
    };

    let is_clean_success = !leader_timed_out
        && leader_exited
        && cleanup_report.workload_reaped
        && libc::WIFEXITED(leader_status)
        && libc::WEXITSTATUS(leader_status) == 0
        && telemetry.fork_exec_storm_success
        && cleanup_report.cleanup_succeeded;

    if !is_clean_success {
        telemetry.fork_exec_storm_success = false;
    }

    unsafe {
        libc::munmap(state_map, state_size);
    }

    SupervisedResult {
        telemetry,
        cleanup: cleanup_report,
    }
}

fn main() {
    let result = run_supervised(
        InjectionMode::None,
        DEFAULT_SUPERVISOR_TIMEOUT,
        DEFAULT_PER_CHILD_TIMEOUT,
    );
    report_telemetry(&result.telemetry);
    if !result.telemetry.fork_exec_storm_success || !result.cleanup.cleanup_succeeded {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII guard for spawned test child processes that guarantees SIGKILL + reap on drop.
    /// Prevents orphan leaks during test panics or negative control assertions.
    #[allow(clippy::disallowed_methods)]
    struct TestProcessGuard {
        pid: libc::pid_t,
    }

    impl TestProcessGuard {
        fn new(pid: libc::pid_t) -> Self {
            Self { pid }
        }

        fn disarm(&mut self) {
            self.pid = 0;
        }
    }

    impl Drop for TestProcessGuard {
        #[allow(clippy::disallowed_methods)]
        fn drop(&mut self) {
            if self.pid > 1 {
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                    bounded_reap_pid(self.pid, Duration::from_millis(500));
                }
            }
        }
    }

    #[test]
    fn test_telemetry_default() {
        let t = Telemetry::default();
        assert_eq!(t.threads_started, 0);
        assert!(!t.fork_exec_storm_success);
    }

    #[test]
    fn test_normal_success_200_children() {
        let res = run_supervised(
            InjectionMode::None,
            DEFAULT_SUPERVISOR_TIMEOUT,
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(
            res.telemetry.fork_exec_storm_success,
            "normal workload must succeed: {res:?}"
        );
        assert_eq!(res.telemetry.threads_started, THREAD_COUNT as u32);
        assert_eq!(res.telemetry.threads_completed, THREAD_COUNT as u32);
        assert_eq!(res.telemetry.threads_joined, THREAD_COUNT as u32);
        assert_eq!(res.telemetry.total_attempted, EXPECTED_TOTAL_CHILDREN);
        assert_eq!(res.telemetry.total_spawned, EXPECTED_TOTAL_CHILDREN);
        assert_eq!(res.telemetry.total_reaped, EXPECTED_TOTAL_CHILDREN);
        assert_eq!(res.telemetry.total_exited_ok, EXPECTED_TOTAL_CHILDREN);
        assert_eq!(res.telemetry.vfork_failures, 0);
        assert_eq!(res.telemetry.wait_failures, 0);
        assert_eq!(res.telemetry.unexpected_status_count, 0);
        assert!(!res.telemetry.timed_out);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_vfork_child_boundary_executes_and_reaps() {
        let path = TRUE_PATH.as_ptr().cast::<libc::c_char>();
        let argv = [path, core::ptr::null()];
        let envp = [core::ptr::null()];
        let child = unsafe { vfork_exec_child(path, argv.as_ptr(), envp.as_ptr(), false) };
        assert!(
            child > 1,
            "vfork_exec_child must return valid child PID to parent"
        );
        let (reaped, status, timed_out) =
            unsafe { bounded_reap_pid(child, Duration::from_secs(2)) };
        assert_eq!(reaped, child);
        assert!(!timed_out);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_vfork_child_boundary_failing_exec_exits_127() {
        let path = FAILING_PATH.as_ptr().cast::<libc::c_char>();
        let argv = [path, core::ptr::null()];
        let envp = [core::ptr::null()];
        let child = unsafe { vfork_exec_child(path, argv.as_ptr(), envp.as_ptr(), false) };
        assert!(
            child > 1,
            "vfork_exec_child must return valid child PID to parent"
        );
        let (reaped, status, timed_out) =
            unsafe { bounded_reap_pid(child, Duration::from_secs(2)) };
        assert_eq!(reaped, child);
        assert!(!timed_out);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 127);
    }

    #[test]
    fn test_injected_subreaper_failure() {
        let res = run_supervised(
            InjectionMode::FailSubreaper,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert_eq!(res.telemetry.first_vfork_errno, libc::EPERM);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_injected_vfork_failure() {
        let res = run_supervised(
            InjectionMode::FailVfork,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.telemetry.vfork_failures > 0);
        assert_eq!(res.telemetry.first_vfork_errno, libc::EAGAIN);
        assert!(!res.telemetry.timed_out);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_injected_exec_failure() {
        let res = run_supervised(
            InjectionMode::FailExec,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.telemetry.unexpected_status_count > 0, "{res:?}");
        assert!(!res.telemetry.timed_out);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_injected_panic_is_detected() {
        let res = run_supervised(
            InjectionMode::PanicThread,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.telemetry.threads_joined < THREAD_COUNT as u32);
        assert!(!res.telemetry.timed_out);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_leader_exit_observed_unreaped() {
        let child_pid = unsafe { libc::fork() };
        if child_pid == 0 {
            unsafe {
                libc::_exit(42);
            }
        }
        assert!(child_pid > 1);
        let mut guard = TestProcessGuard::new(child_pid);

        // Observe leader exit without consuming it
        let (exited, timed_out) =
            unsafe { bounded_observe_leader_exited(child_pid, Duration::from_secs(2)) };
        assert!(exited, "leader exit must be observed");
        assert!(!timed_out, "observe must not time out");

        // Prove that the child is STILL UNREAPED (waitpid immediately reaps it and returns child_pid)
        let mut status = 0i32;
        let reaped = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        assert_eq!(
            reaped, child_pid,
            "leader must remain unreaped after observe_leader_exited"
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 42);

        guard.disarm();
    }

    #[test]
    fn test_withheld_child_exit_before_exec_times_out_and_leaves_no_orphans() {
        let res = run_supervised(
            InjectionMode::WithholdChildExitBeforeExec,
            Duration::from_millis(150),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.telemetry.timed_out);
        assert!(res.cleanup.cleanup_succeeded);
        assert!(res.cleanup.workload_reaped);
        assert!(res.cleanup.group_killed);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_withheld_child_exit_after_exec_times_out_and_leaves_no_orphans() {
        let res = run_supervised(
            InjectionMode::WithholdChildExitAfterExec,
            Duration::from_secs(5),
            Duration::from_millis(150),
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.telemetry.wait_failures > 0, "{res:?}");
        assert!(res.cleanup.cleanup_succeeded);
        assert!(res.cleanup.workload_reaped);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_failed_group_setup_fails_closed_without_group_kill() {
        let res = run_supervised(
            InjectionMode::FailGroupSetup,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(!res.cleanup.group_killed);
        assert!(res.cleanup.workload_reaped);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    fn test_partial_stream_write_fails_safely() {
        let res = run_supervised(
            InjectionMode::PartialStreamWrite,
            Duration::from_secs(5),
            DEFAULT_PER_CHILD_TIMEOUT,
        );
        assert!(!res.telemetry.fork_exec_storm_success);
        assert!(res.cleanup.workload_reaped);
        assert!(res.cleanup.cleanup_succeeded);
        assert_eq!(res.cleanup.unretired_children, 0);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_negative_control_premature_leader_reap_invalidates_group_cleanup() {
        let (r, w) = create_fallible_pipe().expect("pipe creation failed");
        let (child_r, child_w) = create_fallible_pipe().expect("pipe creation failed");

        // Spawn a leader that creates a process group and spawns a background child
        let leader_pid = unsafe { libc::fork() };
        if leader_pid == 0 {
            unsafe {
                libc::close(r);
                libc::close(child_r);
                libc::setpgid(0, 0);
                let child_pid = libc::fork();
                if child_pid == 0 {
                    libc::close(w);
                    loop {
                        libc::pause();
                    }
                }
                let bytes = [1u8];
                let _ = libc::write(w, bytes.as_ptr().cast(), 1);
                libc::close(w);
                let c_bytes = [
                    (child_pid & 0xff) as u8,
                    ((child_pid >> 8) & 0xff) as u8,
                    ((child_pid >> 16) & 0xff) as u8,
                    ((child_pid >> 24) & 0xff) as u8,
                ];
                let _ = libc::write(child_w, c_bytes.as_ptr().cast(), 4);
                libc::close(child_w);
                libc::_exit(0);
            }
        }
        assert!(leader_pid > 1);
        let mut leader_guard = TestProcessGuard::new(leader_pid);
        unsafe {
            libc::close(w);
            libc::close(child_w);
        }

        let mut byte = [0u8; 1];
        let read_res = read_exact_bounded(
            r,
            &mut byte,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        unsafe {
            libc::close(r);
        }
        assert_eq!(read_res, ReadExactResult::Ok);

        let mut child_bytes = [0u8; 4];
        let child_read = read_exact_bounded(
            child_r,
            &mut child_bytes,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        unsafe {
            libc::close(child_r);
        }
        assert_eq!(child_read, ReadExactResult::Ok);
        let child_pid = i32::from_le_bytes(child_bytes);
        assert!(child_pid > 1);
        let mut _child_guard = TestProcessGuard::new(child_pid);

        // Intentionally PREMATURELY REAP the leader before group cleanup
        let (reaped, _, _) = unsafe { bounded_reap_pid(leader_pid, Duration::from_secs(2)) };
        assert_eq!(reaped, leader_pid);
        leader_guard.disarm();
        let mut workload_reaped = true; // Leader already reaped

        // Now attempt group cleanup with group_authenticated = true
        // Because leader is already reaped, the PGID was released / unpinned
        let mut group_authenticated = true;
        let mut leader_status = 0i32;
        let cleanup = unsafe {
            cleanup_owned_descendants(
                leader_pid,
                &mut workload_reaped,
                &mut group_authenticated,
                0,
                &mut leader_status,
            )
        };

        // Assert that group kill was NOT sent on the recycled/reaped leader PID
        assert!(
            !cleanup.group_killed,
            "group kill must not be sent when leader was already reaped"
        );
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_negative_control_unretired_child_fails_cleanup_census() {
        let state_size = core::mem::size_of::<SharedState>();
        let state_map = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                state_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(state_map, libc::MAP_FAILED);
        unsafe {
            core::ptr::write_bytes(state_map, 0, state_size);
        }
        let st = unsafe { &*(state_map as *const SharedState) };

        // Mark slot 0 as active (unretired observation)
        let slot = &st.child_slots[0];
        slot.pid.store(12345, Ordering::Release);
        slot.active.store(1, Ordering::Release);

        let mut workload_reaped = true;
        let mut group_authenticated = false;
        let mut leader_status = 0i32;

        let cleanup = unsafe {
            cleanup_owned_descendants(
                1,
                &mut workload_reaped,
                &mut group_authenticated,
                state_map as usize,
                &mut leader_status,
            )
        };

        // Assert that unretired child is detected and causes cleanup failure
        assert_eq!(cleanup.unretired_children, 1);
        assert!(!cleanup.cleanup_succeeded);

        // Retire child
        slot.active.store(0, Ordering::Release);
        slot.pid.store(0, Ordering::Release);

        let cleanup_fixed = unsafe {
            cleanup_owned_descendants(
                1,
                &mut workload_reaped,
                &mut group_authenticated,
                state_map as usize,
                &mut leader_status,
            )
        };
        assert_eq!(cleanup_fixed.unretired_children, 0);
        assert!(cleanup_fixed.cleanup_succeeded);

        unsafe {
            libc::munmap(state_map, state_size);
        }
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_early_leader_exit_reaps_all_descendants() {
        let state_size = core::mem::size_of::<SharedState>();
        let state_map = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                state_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(state_map, libc::MAP_FAILED);
        unsafe {
            core::ptr::write_bytes(state_map, 0, state_size);
        }
        let st = unsafe { &*(state_map as *const SharedState) };

        let (r, w) = create_fallible_pipe().expect("pipe creation failed");
        let leader_pid = unsafe { libc::fork() };
        if leader_pid == 0 {
            unsafe {
                libc::close(r);
                let child_pid = libc::fork();
                if child_pid == 0 {
                    loop {
                        libc::pause();
                    }
                }
                let slot = &st.child_slots[0];
                slot.pid.store(child_pid, Ordering::Release);
                slot.active.store(1, Ordering::Release);
                let byte = [1u8];
                let _ = libc::write(w, byte.as_ptr().cast(), 1);
                libc::close(w);
                libc::_exit(0);
            }
        }
        assert!(leader_pid > 1);
        let mut leader_guard = TestProcessGuard::new(leader_pid);
        unsafe {
            libc::close(w);
        }
        let mut byte = [0u8; 1];
        let read_res = read_exact_bounded(
            r,
            &mut byte,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        unsafe {
            libc::close(r);
        }
        assert_eq!(read_res, ReadExactResult::Ok);

        let child_pid = st.child_slots[0].pid.load(Ordering::Acquire);
        let mut child_guard = if child_pid > 1 {
            Some(TestProcessGuard::new(child_pid))
        } else {
            None
        };

        let mut workload_reaped = false;
        let mut group_authenticated = false;
        let mut leader_status = 0i32;

        let cleanup = unsafe {
            cleanup_owned_descendants(
                leader_pid,
                &mut workload_reaped,
                &mut group_authenticated,
                state_map as usize,
                &mut leader_status,
            )
        };

        assert!(cleanup.workload_reaped);
        leader_guard.disarm();
        if let Some(ref mut g) = child_guard {
            #[cfg(target_os = "linux")]
            if cleanup.all_descendants_reaped {
                g.disarm();
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = g; // Drop will cleanly kill & reap child on macOS
            }
        }

        unsafe {
            libc::munmap(state_map, state_size);
        }
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn controller_cleanup_census_rejects_unpublished_live_child() {
        let state: Box<SharedState> = Box::new(unsafe { core::mem::zeroed() });
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        assert!(child > 1);
        let mut guard = TestProcessGuard::new(child);
        let mut leader_reaped = true;
        let mut group_authenticated = false;
        let mut leader_status = 0i32;

        // A pre-exec vfork child can exist before the parent publishes its PID.
        // The empty publication table is not proof that all children retired.
        let cleanup = unsafe {
            cleanup_owned_descendants(
                1,
                &mut leader_reaped,
                &mut group_authenticated,
                (&*state as *const SharedState) as usize,
                &mut leader_status,
            )
        };
        let still_live = unsafe { libc::kill(child, 0) } == 0;
        // Retain ownership and clean up before asserting the negative result.
        unsafe {
            libc::kill(child, libc::SIGKILL);
        }
        let (reaped, _, timed_out) = unsafe { bounded_reap_pid(child, Duration::from_secs(2)) };
        if reaped == child {
            guard.disarm();
        }
        assert_eq!(reaped, child, "controller-owned child must be reaped");
        assert!(!timed_out);
        assert!(
            still_live,
            "fixture must have an actual live child at census"
        );
        assert!(
            !cleanup.cleanup_succeeded,
            "cleanup reported success while an unpublished child was still alive: {cleanup:?}"
        );
    }
}
