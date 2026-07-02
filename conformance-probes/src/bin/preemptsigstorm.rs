//! Async-signal storm against threads in a tight small-syscall loop — the Go
//! async-preemption (SIGURG) shape that exposed the x86 trampoline-RIP signal
//! corruption: an async signal landing while a guest thread is inside carrick's
//! x86 syscall trampoline captured a supervisor-window PC
//! (X86_KERNEL_WINDOW_BASE + 2 = 0x10000002) into the sigframe; rt_sigreturn
//! then resumed ring-3 execution on the non-executable kernel-window page →
//! SIGSEGV (SEGV_ACCERR, si_addr = 0x10000002), killing the process (go build /
//! go vet under go-debug_gosym / go-net_http on the KVM lane). Real Linux never
//! faults here.
//!
//! Shape: N worker threads issue small fast syscalls (getpid / sched_yield /
//! openat+close) as fast as possible while (a) a storm thread tgkills SIGURG
//! round-robin at the worker tids (exactly Go's preemptM) and (b) ITIMER_REAL
//! delivers SIGALRM at ~1ms process-wide, for a bounded ~2.5s. A
//! SIGSEGV/SIGBUS/SIGILL handler records the fault address so the 0x10000002
//! signature is visible in the DIFF.
//!
//! Deterministic only: booleans/relationships, never raw counts or times.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const WORKERS: usize = 4;
const STORM_MS: u64 = 2500;
/// Each worker must complete at least this many loop iterations (progress
/// invariant — a wedged/livelocked thread turns this false).
const ITER_FLOOR: u64 = 1000;
/// Watchdog bound: the run must finish well within this (never fires on a
/// correct host; a hang under carrick becomes a bounded DIFF, not a stuck gate).
const WATCHDOG_MS: u64 = STORM_MS + 12_000;

static STOP: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);
static URG_COUNT: AtomicU64 = AtomicU64::new(0);
static ALRM_COUNT: AtomicU64 = AtomicU64::new(0);
static BAD_RETVAL: AtomicBool = AtomicBool::new(false);
static DONE_WORKERS: AtomicUsize = AtomicUsize::new(0);
static ITERS: [AtomicU64; WORKERS] = [const { AtomicU64::new(0) }; WORKERS];
/// Kernel tids the storm thread targets (published by each worker at start).
static WORKER_TIDS: [AtomicU64; WORKERS] = [const { AtomicU64::new(0) }; WORKERS];

extern "C" fn on_urg(_sig: libc::c_int) {
    URG_COUNT.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn on_alrm(_sig: libc::c_int) {
    ALRM_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Async-signal-safe fixed-width hex formatter (no allocation, no locks).
fn hex64(v: u64, out: &mut [u8; 18]) {
    out[0] = b'0';
    out[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        out[2 + i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + nib - 10
        };
    }
}

/// Fatal-fault handler: report the faulting signal + address deterministically
/// (the corruption signature is a fixed kernel-window address), then _exit(1).
/// Everything here is async-signal-safe (write + _exit only).
extern "C" fn on_fatal(sig: libc::c_int, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let addr = if info.is_null() {
        0u64
    } else {
        // SAFETY: kernel-provided siginfo for a SIGSEGV/SIGBUS/SIGILL carries
        // si_addr; reading it in the handler is the documented use.
        (unsafe { (*info).si_addr() }) as u64
    };
    let mut hex = [0u8; 18];
    hex64(addr, &mut hex);
    let mut buf = [0u8; 64];
    let head = b"no_sigsegv=false sig=";
    let mut n = 0;
    buf[..head.len()].copy_from_slice(head);
    n += head.len();
    // sig is 1..=31 here; two decimal digits max.
    if sig >= 10 {
        buf[n] = b'0' + (sig / 10) as u8;
        n += 1;
    }
    buf[n] = b'0' + (sig % 10) as u8;
    n += 1;
    let mid = b" addr=";
    buf[n..n + mid.len()].copy_from_slice(mid);
    n += mid.len();
    buf[n..n + 18].copy_from_slice(&hex);
    n += 18;
    buf[n] = b'\n';
    n += 1;
    // SAFETY: write(2)+_exit(2) are async-signal-safe.
    unsafe {
        libc::write(1, buf.as_ptr().cast(), n);
        libc::_exit(1);
    }
}

fn install_counter_handler(sig: libc::c_int, f: extern "C" fn(libc::c_int)) {
    // SAFETY: standard sigaction install with an async-signal-safe counter
    // handler; SA_RESTART mirrors Go's preemption-signal registration.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = f as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn install_fatal_handlers() {
    // SAFETY: SA_SIGINFO handler + write/_exit only; installed once at startup.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_fatal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_SIGINFO;
        for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Sleep until `ms` milliseconds from now on CLOCK_MONOTONIC, recomputing the
/// remainder from the clock each iteration. Deliberately does NOT depend on
/// nanosleep writing `rem` on EINTR (std::thread::sleep does, and a separate
/// carrick gap — dispatch/time.rs nanosleep never writes rem — would turn this
/// probe into a hang under the 1ms storm; that gap is out of scope here).
fn sleep_wall(ms: u64) {
    fn now_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime with a valid out-param.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
    }
    let deadline = now_ns() + ms * 1_000_000;
    loop {
        let now = now_ns();
        if now >= deadline {
            return;
        }
        let left = (deadline - now).min(50_000_000);
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: left as i64,
        };
        // SAFETY: nanosleep with a valid timespec; EINTR just re-loops.
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }
}

fn gettid() -> u64 {
    // SAFETY: gettid(2) takes no arguments and cannot fail.
    (unsafe { libc::syscall(libc::SYS_gettid) }) as u64
}

/// Pick a path that exists in any rootfs (image or bare run-elf) for the
/// openat/close leg. Falls back to "." (always present).
fn open_path() -> &'static [u8] {
    for p in [&b"/dev/null\0"[..], &b"/proc/self/status\0"[..]] {
        // SAFETY: openat with a NUL-terminated literal.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, p.as_ptr().cast(), libc::O_RDONLY) };
        if fd >= 0 {
            // SAFETY: fd was just returned by openat.
            unsafe { libc::close(fd) };
            return p;
        }
    }
    &b".\0"[..]
}

fn worker(idx: usize, path: &'static [u8], my_pid: libc::pid_t) {
    WORKER_TIDS[idx].store(gettid(), Ordering::SeqCst);
    let iters = &ITERS[idx];
    while !STOP.load(Ordering::Relaxed) {
        // getpid: constant-retval sanity.
        // SAFETY: plain getpid.
        let pid = unsafe { libc::getpid() };
        if pid != my_pid {
            BAD_RETVAL.store(true, Ordering::Relaxed);
        }
        // sched_yield: must return 0 (the go-build hot syscall; the c136 crash
        // captured rax=0x18 = its x86 number mid-flight).
        // SAFETY: plain sched_yield.
        let y = unsafe { libc::sched_yield() };
        if y != 0 {
            BAD_RETVAL.store(true, Ordering::Relaxed);
        }
        // openat/close: the c62 crash captured rax=0x101 (openat's number)
        // mid-flight. A lost/duplicated completion shows up as a bogus fd or a
        // failing close. EINTR is tolerated (not a corruption signature).
        // SAFETY: openat with a NUL-terminated path, close of the returned fd.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, path.as_ptr().cast(), libc::O_RDONLY) };
        if fd >= 0 {
            // SAFETY: fd is live and owned here.
            if unsafe { libc::close(fd) } != 0 {
                BAD_RETVAL.store(true, Ordering::Relaxed);
            }
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::EINTR {
                BAD_RETVAL.store(true, Ordering::Relaxed);
            }
        }
        iters.fetch_add(1, Ordering::Relaxed);
    }
    DONE_WORKERS.fetch_add(1, Ordering::Relaxed);
}

fn main() {
    install_fatal_handlers();
    install_counter_handler(libc::SIGURG, on_urg);
    install_counter_handler(libc::SIGALRM, on_alrm);
    let path = open_path();
    // SAFETY: plain getpid.
    let my_pid = unsafe { libc::getpid() };

    // Watchdog: never fires on a correct host; bounds a wedged run.
    std::thread::spawn(|| {
        sleep_wall(WATCHDOG_MS);
        if !FINISHED.load(Ordering::SeqCst) {
            println!("watchdog_timeout=true");
            // SAFETY: _exit after the diagnostic line.
            unsafe { libc::_exit(2) };
        }
    });

    let workers: Vec<std::thread::JoinHandle<()>> = (0..WORKERS)
        .map(|i| std::thread::spawn(move || worker(i, path, my_pid)))
        .collect();

    // Storm thread: round-robin tgkill(pid, tid, SIGURG) at the worker tids —
    // exactly Go's preemptM shape (tid-directed async signal at a thread that
    // is overwhelmingly likely to be mid-syscall).
    let storm = std::thread::spawn(move || {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 200_000, // 200µs between kicks ≈ 5k signals/s
        };
        let mut i = 0usize;
        while !STOP.load(Ordering::Relaxed) {
            let tid = WORKER_TIDS[i % WORKERS].load(Ordering::SeqCst);
            if tid != 0 {
                // SAFETY: tgkill at a live worker tid with a handled signal.
                unsafe {
                    libc::syscall(libc::SYS_tgkill, my_pid as u64, tid, libc::SIGURG as u64);
                }
            }
            i = i.wrapping_add(1);
            // SAFETY: nanosleep with a valid timespec.
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
        }
    });

    // ITIMER_REAL at ~1ms: the async process-wide storm leg.
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 1_000,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 1_000,
        },
    };
    // SAFETY: setitimer with a valid itimerval.
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };

    sleep_wall(STORM_MS);
    STOP.store(true, Ordering::SeqCst);
    let zero = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    // SAFETY: disarm with a zeroed itimerval.
    unsafe { libc::setitimer(libc::ITIMER_REAL, &zero, std::ptr::null_mut()) };

    for h in workers {
        let _ = h.join();
    }
    let _ = storm.join();
    FINISHED.store(true, Ordering::SeqCst);

    let iters_floor = ITERS
        .iter()
        .all(|c| c.load(Ordering::Relaxed) >= ITER_FLOOR);
    println!("no_sigsegv=true");
    println!(
        "workers_done={}",
        DONE_WORKERS.load(Ordering::SeqCst) == WORKERS
    );
    println!("iters_floor={iters_floor}");
    println!("urg_delivered={}", URG_COUNT.load(Ordering::Relaxed) > 0);
    println!("alrm_delivered={}", ALRM_COUNT.load(Ordering::Relaxed) > 0);
    println!("retvals_ok={}", !BAD_RETVAL.load(Ordering::Relaxed));
}
