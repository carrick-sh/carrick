//! Carrier-wide descriptor-ceiling semantics for the AArch64 `fstat` fast path.
//!
//! The ceiling is a conservative optimization hint, so every descriptor that
//! has ever been published must remain semantically ordinary. This probe makes
//! a high descriptor with `F_DUPFD_CLOEXEC`, exercises it across fork and
//! `CLONE_FILES`, then closes it without expecting the ceiling to fall. The
//! final child installs seccomp and proves policy still takes precedence over
//! an invalid descriptor above the ceiling.
//!
//! All child communication and reaping is bounded. The probe does not alter
//! `RLIMIT_NOFILE`; it chooses descriptor 4096 when the live soft limit permits.

use conformance_probes::errno;
use std::ffi::CString;
use std::mem::{size_of, MaybeUninit};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

const PREFERRED_HIGH_FD: i32 = 4096;
const IO_TIMEOUT_MS: i32 = 2_000;
const REAP_TIMEOUT: Duration = Duration::from_secs(3);
const KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);
const CPU_LIMIT_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

static CPU_REPORT_FD: AtomicI32 = AtomicI32::new(-1);
static ALARM_SEEN: AtomicBool = AtomicBool::new(false);

extern "C" fn report_sigxcpu(_signal: i32) {
    let fd = CPU_REPORT_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8];
        unsafe { libc::write(fd, byte.as_ptr().cast(), byte.len()) };
    }
}

extern "C" fn mark_alarm(_signal: i32) {
    ALARM_SEEN.store(true, Ordering::Relaxed);
}

fn wait_fd(fd: i32, events: i16) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let deadline = Instant::now() + Duration::from_millis(IO_TIMEOUT_MS as u64);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let timeout_ms = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return true;
        }
        if rc != -1 || errno() != libc::EINTR {
            return false;
        }
    }
}

fn write_i32(fd: i32, value: i32) -> bool {
    if !wait_fd(fd, libc::POLLOUT) {
        return false;
    }
    unsafe { libc::write(fd, value.to_ne_bytes().as_ptr().cast(), 4) == 4 }
}

fn read_i32(fd: i32) -> Option<i32> {
    if !wait_fd(fd, libc::POLLIN) {
        return None;
    }
    let mut bytes = [0u8; 4];
    let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), 4) };
    (n == 4).then(|| i32::from_ne_bytes(bytes))
}

fn reap_bounded(pid: i32) -> Option<i32> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return Some(status);
        }
        if rc == -1 && errno() != libc::EINTR {
            return None;
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let kill_deadline = Instant::now() + KILL_REAP_TIMEOUT;
            loop {
                let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if rc == pid || (rc == -1 && errno() != libc::EINTR) {
                    break;
                }
                if Instant::now() >= kill_deadline {
                    break;
                }
                unsafe { libc::usleep(5_000) };
            }
            return None;
        }
        unsafe { libc::usleep(5_000) };
    }
}

fn fstat_errno(fd: i32, stat: *mut libc::stat) -> i32 {
    unsafe { *libc::__errno_location() = 0 };
    let rc = unsafe { libc::syscall(libc::SYS_fstat, fd, stat) };
    if rc == 0 {
        0
    } else {
        errno()
    }
}

fn exec_successor(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("--exec-high-fd") {
        return false;
    }
    let high = args.get(1).and_then(|value| value.parse::<i32>().ok());
    let report_fd = args.get(2).and_then(|value| value.parse::<i32>().ok());
    let observed = match high {
        Some(fd) => {
            let mut stat: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
            fstat_errno(fd, &mut stat)
        }
        None => -2,
    };
    let reported = report_fd.is_some_and(|fd| write_i32(fd, observed));
    std::process::exit(if reported { 0 } else { 61 });
}

fn sf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

unsafe fn install_fstat_errno_filter(configured_errno: i32) -> bool {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return false;
    }
    let mut filter = [
        sf(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        sf(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, libc::SYS_fstat as u32),
        sf(
            BPF_RET | BPF_K,
            0,
            0,
            SECCOMP_RET_ERRNO | configured_errno as u32,
        ),
        sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    libc::prctl(
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_FILTER as libc::c_ulong,
        &program as *const libc::sock_fprog as libc::c_ulong,
        0,
        0,
    ) == 0
}

fn cpu_limit_fstat_case(invalid_fd: i32) -> (bool, i32, bool) {
    let mut report_pipe = [0i32; 2];
    if unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        panic!("CPU-limit pipe2 failed: errno={}", errno());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(report_pipe[0]) };
        CPU_REPORT_FD.store(report_pipe[1], Ordering::Relaxed);
        let mut action: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        action.sa_sigaction = report_sigxcpu as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGXCPU, &action, std::ptr::null_mut()) != 0 {
                libc::_exit(51);
            }
        }
        let limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 2,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &limit) } != 0 {
            unsafe { libc::_exit(52) };
        }
        let mut stat: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
        loop {
            std::hint::black_box(fstat_errno(invalid_fd, &mut stat));
        }
    }
    unsafe { libc::close(report_pipe[1]) };
    if pid < 0 {
        unsafe { libc::close(report_pipe[0]) };
        return (false, -1, false);
    }

    let deadline = Instant::now() + CPU_LIMIT_TIMEOUT;
    let mut saw_sigxcpu = false;
    let mut status = 0;
    let mut completed = false;
    let mut reaped = false;
    let mut usage: libc::rusage = unsafe { MaybeUninit::zeroed().assume_init() };
    while Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: report_pipe[0],
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe { libc::poll(&mut pfd, 1, 20) };
        if pfd.revents & libc::POLLIN != 0 {
            let mut byte = 0u8;
            if unsafe { libc::read(report_pipe[0], (&mut byte as *mut u8).cast(), 1) } == 1 {
                saw_sigxcpu |= byte == 1;
            }
        }
        let wait = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
        if wait == pid {
            completed = true;
            reaped = true;
            break;
        }
        if wait == -1 && errno() != libc::EINTR {
            break;
        }
    }
    let timed_out = !completed;
    if timed_out {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let kill_deadline = Instant::now() + KILL_REAP_TIMEOUT;
        while Instant::now() < kill_deadline {
            let wait = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
            if wait == pid {
                reaped = true;
                break;
            }
            if wait == -1 && errno() != libc::EINTR {
                break;
            }
            unsafe { libc::usleep(5_000) };
        }
    }
    unsafe { libc::close(report_pipe[0]) };
    if std::env::var_os("CARRICK_FDCEILING_RUSAGE").is_some() {
        let user_us = usage.ru_utime.tv_sec as i128 * 1_000_000 + usage.ru_utime.tv_usec as i128;
        let system_us = usage.ru_stime.tv_sec as i128 * 1_000_000 + usage.ru_stime.tv_usec as i128;
        eprintln!("fdceiling_cpu_rusage reaped={reaped} user_us={user_us} system_us={system_us}");
    }
    let terminal_signal = if completed && libc::WIFSIGNALED(status) {
        libc::WTERMSIG(status)
    } else {
        -1
    };
    (saw_sigxcpu, terminal_signal, timed_out)
}

fn signal_fstat_case(invalid_fd: i32) -> (bool, bool) {
    let mut report_pipe = [0i32; 2];
    if unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!("signal pipe2 failed: errno={}", errno());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(report_pipe[0]) };
        ALARM_SEEN.store(false, Ordering::Relaxed);
        let mut action: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
        action.sa_sigaction = mark_alarm as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) != 0 {
                libc::_exit(62);
            }
        }
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: 50_000,
            },
        };
        let mut stat: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
        std::hint::black_box(fstat_errno(invalid_fd, &mut stat));
        let mut calls = 1u64;
        unsafe { libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()) };
        while !ALARM_SEEN.load(Ordering::Relaxed) {
            std::hint::black_box(fstat_errno(invalid_fd, &mut stat));
            calls = calls.saturating_add(1);
        }
        let disarmed: libc::itimerval = unsafe { MaybeUninit::zeroed().assume_init() };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &disarmed, std::ptr::null_mut()) };
        let reported = write_i32(report_pipe[1], i32::from(calls > 0));
        unsafe { libc::_exit(if reported { 0 } else { 63 }) };
    }
    unsafe { libc::close(report_pipe[1]) };
    if pid < 0 {
        unsafe { libc::close(report_pipe[0]) };
        return (false, false);
    }
    let progress = read_i32(report_pipe[0]);
    let timed_out = progress.is_none();
    if timed_out {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let status = reap_bounded(pid);
    unsafe { libc::close(report_pipe[0]) };
    let exited_zero =
        status.is_some_and(|value| libc::WIFEXITED(value) && libc::WEXITSTATUS(value) == 0);
    (progress == Some(1) && exited_zero, timed_out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if exec_successor(&args) {
        return;
    }

    let mut limit = MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        panic!("getrlimit failed: errno={}", errno());
    }
    let limit = unsafe { limit.assume_init() };
    let high_floor =
        PREFERRED_HIGH_FD.min((limit.rlim_cur.saturating_sub(1)).min(i32::MAX as _) as i32);
    if high_floor < 64 {
        panic!(
            "RLIMIT_NOFILE too low for fd-ceiling probe: {}",
            limit.rlim_cur
        );
    }

    let seed = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if seed < 0 {
        panic!("open /dev/null failed: errno={}", errno());
    }
    let high = unsafe { libc::fcntl(seed, libc::F_DUPFD_CLOEXEC, high_floor) };
    if high < 0 {
        panic!("F_DUPFD_CLOEXEC({high_floor}) failed: errno={}", errno());
    }

    let mut stat: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        std::ptr::write_bytes(
            (&mut stat as *mut libc::stat).cast::<u8>(),
            0xa5,
            size_of::<libc::stat>(),
        )
    };
    let valid_errno = fstat_errno(high, &mut stat);
    let canary_changed = unsafe {
        std::slice::from_raw_parts(
            (&stat as *const libc::stat).cast::<u8>(),
            size_of::<libc::stat>(),
        )
        .iter()
        .any(|byte| *byte != 0xa5)
    };
    println!("valid_high_fstat_errno={valid_errno}");
    println!("valid_high_fstat_buffer_changed={canary_changed}");
    println!(
        "valid_high_fstat_bad_pointer_errno={}",
        fstat_errno(high, 1usize as *mut libc::stat)
    );

    let invalid = high.saturating_add(1024);
    unsafe { libc::close(invalid) };
    println!(
        "invalid_above_high_fstat_errno={}",
        fstat_errno(invalid, &mut stat)
    );
    println!("negative_fd_fstat_errno={}", fstat_errno(-1, &mut stat));

    let fork_result = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(if fstat_errno(high, &mut stat) == 0 {
                0
            } else {
                31
            });
        }
        if pid < 0 {
            None
        } else {
            reap_bounded(pid)
        }
    };
    println!(
        "fork_inherits_high_fd={}",
        fork_result.is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
    );

    let mut exec_pipe = [0i32; 2];
    if unsafe { libc::pipe(exec_pipe.as_mut_ptr()) } != 0 {
        panic!("exec pipe failed: errno={}", errno());
    }
    let exec_pid = unsafe { libc::fork() };
    if exec_pid == 0 {
        unsafe { libc::close(exec_pipe[0]) };
        if unsafe { libc::fcntl(high, libc::F_SETFD, 0) } != 0 {
            unsafe { libc::_exit(64) };
        }
        let exe = CString::new(std::env::args().next().unwrap_or_default()).unwrap();
        let mode = c"--exec-high-fd";
        let high_arg = CString::new(high.to_string()).unwrap();
        let report_arg = CString::new(exec_pipe[1].to_string()).unwrap();
        let argv = [
            exe.as_ptr(),
            mode.as_ptr(),
            high_arg.as_ptr(),
            report_arg.as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null()];
        unsafe {
            libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(65);
        }
    }
    unsafe { libc::close(exec_pipe[1]) };
    let exec_errno = if exec_pid > 0 {
        read_i32(exec_pipe[0]).unwrap_or(-1)
    } else {
        -1
    };
    let exec_status = (exec_pid > 0).then(|| reap_bounded(exec_pid)).flatten();
    unsafe { libc::close(exec_pipe[0]) };
    println!("exec_inherits_high_fstat_errno={exec_errno}");
    println!(
        "exec_high_fstat_child_exited={}",
        exec_status.is_some_and(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
    );

    let mut report_pipe = [0i32; 2];
    if unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!("pipe2 failed: errno={}", errno());
    }
    let clone_pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_FILES | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        ) as i32
    };
    if clone_pid == 0 {
        let shared_errno = fstat_errno(high, &mut stat);
        let unshare_errno = if unsafe {
            libc::syscall(
                libc::SYS_close_range,
                high as u32,
                high as u32,
                CLOSE_RANGE_UNSHARE,
            )
        } == 0
        {
            fstat_errno(high, &mut stat)
        } else {
            -errno()
        };
        let _ = write_i32(report_pipe[1], shared_errno);
        let _ = write_i32(report_pipe[1], unshare_errno);
        unsafe { libc::_exit(0) };
    }
    let clone_shared_errno = read_i32(report_pipe[0]).unwrap_or(-1);
    let clone_unshared_errno = read_i32(report_pipe[0]).unwrap_or(-1);
    let clone_status = (clone_pid > 0).then(|| reap_bounded(clone_pid)).flatten();
    println!("clone_files_shared_high_fstat_errno={clone_shared_errno}");
    println!("clone_files_unshared_closed_high_fstat_errno={clone_unshared_errno}");
    println!(
        "clone_files_parent_high_fstat_errno={}",
        fstat_errno(high, &mut stat)
    );
    println!(
        "clone_files_child_exited={}",
        clone_status.is_some_and(|status| libc::WIFEXITED(status))
    );

    unsafe { libc::close(high) };
    println!("closed_high_fstat_errno={}", fstat_errno(high, &mut stat));
    println!(
        "lower_seed_after_high_close_errno={}",
        fstat_errno(seed, &mut stat)
    );

    let (signal_seen, signal_timed_out) = signal_fstat_case(invalid);
    println!("signal_fstat_seen={signal_seen}");
    println!("signal_fstat_timeout={signal_timed_out}");

    // Run before seccomp: seccomp installation is one-way and intentionally
    // disables eligible EL1 syscall fast paths for the installing task.
    let (cpu_sigxcpu, cpu_terminal_signal, cpu_timed_out) = cpu_limit_fstat_case(invalid);
    println!("cpu_limit_fstat_sigxcpu_seen={cpu_sigxcpu}");
    println!("cpu_limit_fstat_terminal_signal={cpu_terminal_signal}");
    println!("cpu_limit_fstat_timeout={cpu_timed_out}");

    let seccomp_result = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if !install_fstat_errno_filter(libc::EPERM) {
                libc::_exit(41);
            }
            let observed = fstat_errno(invalid, &mut stat);
            let reported = write_i32(report_pipe[1], observed);
            libc::_exit(if reported { 0 } else { 42 });
        }
        if pid < 0 {
            (None, None)
        } else {
            (read_i32(report_pipe[0]), reap_bounded(pid))
        }
    };
    let seccomp_exit = seccomp_result
        .1
        .filter(|status| libc::WIFEXITED(*status))
        .map(|status| libc::WEXITSTATUS(status))
        .unwrap_or(-1);
    println!(
        "seccomp_invalid_high_fstat_errno={}",
        seccomp_result.0.unwrap_or(-1)
    );
    println!("seccomp_invalid_high_fstat_child_exit={seccomp_exit}");

    unsafe {
        libc::close(seed);
        libc::close(report_pipe[0]);
        libc::close(report_pipe[1]);
    }
}
