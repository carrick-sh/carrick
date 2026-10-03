//! Thread-lifecycle witnesses (EL1 thread lifecycle, stage L0).
//!
//! Every mode asserts LINUX semantics only, so each one must print
//! `... ok=true` on native arm64 Docker. Whether EL1 serves the lifecycle
//! (exit slope, forwarded counts) is measured by the embed test from the zone
//! counters, never by the fixture. Modes are two-live-process wherever the
//! design asks: a forked peer runs beside the parent and each line names its
//! role; the parent prints `<name> summary parent_ok=.. child_ok=.. ok=..`.
//!
//! - `thread-spawn-slope <n> <rounds>`: both processes spawn and join `n`
//!   threads per round, `rounds` times.
//! - `tgkill-after-clone <rounds>`: a raw `clone(CLONE_THREAD)` child is
//!   `tgkill`ed the instant clone returns; the peer `kill`s its tid.
//! - `mask-storm <sends>`: a thread flips the mask of a real-time signal in a
//!   loop while the peer `sigqueue`s `sends` distinct values; each must be
//!   delivered exactly once.
//! - `signal-retarget <rounds>`: a process-directed signal while one thread
//!   blocks it lands on the other thread.
//! - `tid-reuse <rounds>`: joined threads leave `/proc/self/task` and their
//!   tid is not handed out again while still listed.
//! - `nproc-limit`: `RLIMIT_NPROC` counts threads uid-wide; at the limit a
//!   clone fails `EAGAIN` while a peer of the same uid forks.
//! - `fork-storm <forks>`: fork during an 8-thread clone storm; the child has
//!   exactly one thread.
//! - `exit-group-storm <rounds>` / `exec-storm <rounds>`: `exit_group` /
//!   `execve` from one thread during a clone storm; no survivor, no hang.
//! - `ptrace-clone`: `PTRACE_O_TRACECLONE` reports the clone and attaches
//!   the new thread.
//! - `seccomp-clone`: a filter returning `EPERM` for thread clones.
//! - `futex-flood <threads>`: more parked threads than the executor pool has
//!   workers; all complete.
//!
//! Every wait is bounded; a lost wake is a failed line, never a hang.

use super::{
    futex_wait_timeout, futex_wake, gettid, poll_read_byte, poll_read_count, raw6, write_count,
    write_signal_byte,
};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const SYS_KILL: u64 = 129;
const SYS_TGKILL_NR: u64 = 131;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP_NR: u64 = 94;
const SYS_CLONE: u64 = 220;
const FUTEX_WAIT_SHARED: u64 = 0;
const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const EAGAIN: i64 = 11;

const THREAD_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM) as u64;

const WAIT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Helpers

/// Wait until `word >= target`, bounded by `total`.
fn wait_word_ge(word: &AtomicU32, target: u32, total: Duration) -> bool {
    let start = Instant::now();
    loop {
        let value = word.load(Ordering::Acquire);
        if value >= target {
            return true;
        }
        if start.elapsed() > total {
            return false;
        }
        let _ = futex_wait_timeout(word, value, Duration::from_millis(50));
    }
}

fn bump(word: &AtomicU32) {
    word.fetch_add(1, Ordering::AcqRel);
    futex_wake(word, i32::MAX as u32);
}

fn wait_true(total: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if check() {
            return true;
        }
        if start.elapsed() > total {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Numeric entries of `/proc/self/task`.
fn task_ids() -> Option<Vec<i32>> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task").ok()? {
        let name = entry.ok()?.file_name();
        ids.push(name.to_str()?.parse().ok()?);
    }
    ids.sort_unstable();
    Some(ids)
}

fn kill_pid(pid: i32, signal: i32) -> i64 {
    unsafe { raw6(SYS_KILL, pid as u64, signal as u64, 0, 0, 0, 0) }
}

fn tgkill_in(tgid: i32, tid: i32, signal: i32) -> i64 {
    unsafe {
        raw6(
            SYS_TGKILL_NR,
            tgid as u64,
            tid as u64,
            signal as u64,
            0,
            0,
            0,
        )
    }
}

fn current_pid() -> i32 {
    std::process::id() as i32
}

fn install_handler(signal: i32, handler: usize, siginfo: bool) -> bool {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = if siginfo { libc::SA_SIGINFO } else { 0 };
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, std::ptr::null_mut()) == 0
    }
}

fn set_blocked(signal: i32, block: bool) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        let how = if block {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        libc::pthread_sigmask(how, &set, std::ptr::null_mut());
    }
}

fn spawn_small<F: FnOnce() + Send + 'static>(
    body: F,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(body)
}

/// One process's end of a parent/child pair of pipes.
struct Role {
    name: &'static str,
    peer: i32,
    rd: libc::c_int,
    wr: libc::c_int,
}

fn make_pipe() -> [libc::c_int; 2] {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    fds
}

/// Run `body` in this process ("parent") and in a forked peer ("child") at
/// the same time. The parent waits for the peer (bounded) and prints the
/// summary. Must be called before the process has any thread.
fn two_process(name: &str, body: &dyn Fn(&Role) -> bool) -> i32 {
    let p2c = make_pipe();
    let c2p = make_pipe();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("{name} fork failed");
        return 1;
    }
    if pid == 0 {
        unsafe {
            libc::close(p2c[1]);
            libc::close(c2p[0]);
        }
        let identity_ok = gettid() == current_pid();
        let ok = body(&Role {
            name: "child",
            peer: unsafe { libc::getppid() },
            rd: p2c[0],
            wr: c2p[1],
        });
        unsafe { libc::_exit(if ok && identity_ok { 0 } else { 1 }) };
    }
    unsafe {
        libc::close(p2c[0]);
        libc::close(c2p[1]);
    }
    let identity_ok = gettid() == current_pid();
    let parent_ok = body(&Role {
        name: "parent",
        peer: pid,
        rd: c2p[0],
        wr: p2c[1],
    });
    let child_ok = reap(pid, Duration::from_secs(120)) == Some(0);
    let ok = parent_ok && child_ok && identity_ok;
    println!("{name} summary parent_ok={parent_ok} child_ok={child_ok} ok={ok}");
    if ok { 0 } else { 1 }
}

/// Reap `pid` within `total`; the exit code, or `None` on timeout/signal.
fn reap(pid: i32, total: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
        }
        if rc < 0 || start.elapsed() > total {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

// ---------------------------------------------------------------------------
// (a) spawn/join slope

pub fn spawn_slope(n: usize, rounds: usize) -> i32 {
    two_process("thread-spawn-slope", &|role| {
        static RAN: AtomicU64 = AtomicU64::new(0);
        let mut failures = 0u64;
        for _ in 0..rounds {
            let mut handles = Vec::with_capacity(n);
            for _ in 0..n {
                match spawn_small(|| {
                    RAN.fetch_add(1, Ordering::Relaxed);
                }) {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        failures += 1;
                        println!("thread-spawn-slope role={} spawn_errno={} error={error}", role.name, error.raw_os_error().unwrap_or(0));
                    }
                }
            }
            for handle in handles {
                if handle.join().is_err() {
                    failures += 1;
                }
            }
        }
        let ran = RAN.load(Ordering::Relaxed);
        let ok = failures == 0 && ran == (n * rounds) as u64;
        println!(
            "thread-spawn-slope role={} n={n} rounds={rounds} threads={ran} failures={failures} ok={ok}",
            role.name
        );
        ok
    })
}

// ---------------------------------------------------------------------------
// (b) tgkill immediately after clone

static HANDLED1: AtomicU32 = AtomicU32::new(0);
static HANDLER1_TID: AtomicI32 = AtomicI32::new(0);
static HANDLED2: AtomicU32 = AtomicU32::new(0);
static HANDLER2_TID: AtomicI32 = AtomicI32::new(0);
static CHILD_TID: AtomicI32 = AtomicI32::new(0);
static CHILD_STARTED: AtomicU32 = AtomicU32::new(0);
static CHILD_RELEASE: AtomicU32 = AtomicU32::new(0);
static PTID: AtomicI32 = AtomicI32::new(0);
static CTID: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    HANDLER1_TID.store(gettid(), Ordering::SeqCst);
    HANDLED1.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_usr2(_: i32) {
    HANDLER2_TID.store(gettid(), Ordering::SeqCst);
    HANDLED2.fetch_add(1, Ordering::SeqCst);
}

/// Body of a raw `CLONE_THREAD` child. It shares the parent's TLS pointer,
/// so it touches only atomics and raw system calls (never errno).
extern "C" fn raw_thread_body(_: *mut libc::c_void) -> libc::c_int {
    CHILD_TID.store(gettid(), Ordering::SeqCst);
    CHILD_STARTED.store(1, Ordering::SeqCst);
    futex_wake(&CHILD_STARTED, 1);
    for _ in 0..200 {
        if CHILD_RELEASE.load(Ordering::SeqCst) != 0 {
            break;
        }
        let _ = futex_wait_timeout(&CHILD_RELEASE, 0, Duration::from_millis(50));
    }
    0
}

/// aarch64 `clone` with a child that calls `func(0)` on `stack_top` and then
/// `exit`s. Returns the child tid (or `-errno`) in the parent.
///
/// # Safety
/// `stack_top` must be the 16-byte-aligned top of a live stack; `ptid`/`ctid`
/// must stay valid for the child's lifetime.
unsafe fn raw_clone_thread(
    flags: u64,
    stack_top: u64,
    ptid: *mut i32,
    ctid: *mut u32,
    func: extern "C" fn(*mut libc::c_void) -> libc::c_int,
) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            "cbnz x0, 2f",
            "blr x9",
            "mov x8, #93",
            "svc #0",
            "2:",
            inlateout("x0") flags as i64 => ret,
            in("x1") stack_top,
            in("x2") ptid as u64,
            in("x3") 0u64,
            in("x4") ctid as u64,
            in("x8") SYS_CLONE,
            in("x9") func as usize,
            clobber_abi("C"),
        );
    }
    ret
}

/// Wait for a non-private futex word (what `CLONE_CHILD_CLEARTID` wakes) to
/// become zero, bounded.
fn wait_cleartid(word: &AtomicU32, total: Duration) -> bool {
    let start = Instant::now();
    loop {
        let value = word.load(Ordering::Acquire);
        if value == 0 {
            return true;
        }
        if start.elapsed() > total {
            return false;
        }
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        unsafe {
            raw6(
                98,
                word.as_ptr() as u64,
                FUTEX_WAIT_SHARED,
                u64::from(value),
                &ts as *const libc::timespec as u64,
                0,
                0,
            );
        }
    }
}

pub fn tgkill_after_clone(rounds: usize) -> i32 {
    two_process("tgkill-after-clone", &|role| {
        if role.name == "child" {
            return tgkill_injector(role, rounds);
        }
        let mut failures = Vec::new();
        if !install_handler(libc::SIGUSR1, on_usr1 as *const () as usize, false)
            || !install_handler(libc::SIGUSR2, on_usr2 as *const () as usize, false)
        {
            println!("tgkill-after-clone sigaction failed");
            return false;
        }
        let stack_len = 256 * 1024;
        for round in 0..rounds {
            HANDLED1.store(0, Ordering::SeqCst);
            HANDLER1_TID.store(0, Ordering::SeqCst);
            HANDLED2.store(0, Ordering::SeqCst);
            HANDLER2_TID.store(0, Ordering::SeqCst);
            CHILD_TID.store(0, Ordering::SeqCst);
            CHILD_STARTED.store(0, Ordering::SeqCst);
            CHILD_RELEASE.store(0, Ordering::SeqCst);
            PTID.store(0, Ordering::SeqCst);
            CTID.store(0xffff, Ordering::SeqCst);
            let stack = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    stack_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if stack == libc::MAP_FAILED {
                failures.push(format!("round {round}: stack mmap"));
                continue;
            }
            let top = (stack as u64 + stack_len as u64) & !15;
            let flags =
                THREAD_FLAGS | libc::CLONE_PARENT_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64;
            let rc = unsafe {
                raw_clone_thread(flags, top, PTID.as_ptr(), CTID.as_ptr(), raw_thread_body)
            };
            if rc <= 0 {
                failures.push(format!("round {round}: clone rc={rc}"));
                unsafe { libc::munmap(stack, stack_len) };
                continue;
            }
            let tid = rc as i32;
            // The thread must be signalable the instant clone returns.
            let kill_rc = tgkill_in(current_pid(), tid, libc::SIGUSR1);
            if kill_rc != 0 {
                failures.push(format!("round {round}: tgkill rc={kill_rc}"));
            }
            if PTID.load(Ordering::SeqCst) != tid {
                failures.push(format!(
                    "round {round}: PARENT_SETTID {} != clone rc {tid}",
                    PTID.load(Ordering::SeqCst)
                ));
            }
            if !wait_word_ge(&CHILD_STARTED, 1, WAIT) || !wait_word_ge(&HANDLED1, 1, WAIT) {
                failures.push(format!("round {round}: child did not start/handle"));
            }
            if CHILD_TID.load(Ordering::SeqCst) != tid {
                failures.push(format!(
                    "round {round}: child gettid {} != {tid}",
                    CHILD_TID.load(Ordering::SeqCst)
                ));
            }
            if HANDLER1_TID.load(Ordering::SeqCst) != tid {
                failures.push(format!(
                    "round {round}: handler ran on {} not {tid}",
                    HANDLER1_TID.load(Ordering::SeqCst)
                ));
            }
            if !task_ids().is_some_and(|ids| ids.contains(&tid)) {
                failures.push(format!("round {round}: tid {tid} not in /proc/self/task"));
            }
            // The peer process signals the thread by its tid.
            if !write_count(role.wr, tid as u64) {
                failures.push(format!("round {round}: peer write"));
            } else {
                match read_report(role.rd, 10_000) {
                    Ok(1) => {}
                    other => failures.push(format!("round {round}: peer kill result {other:?}")),
                }
            }
            if !wait_word_ge(&HANDLED2, 1, WAIT) {
                failures.push(format!("round {round}: peer kill(tid) not delivered"));
            }
            if HANDLER2_TID.load(Ordering::SeqCst) != tid {
                failures.push(format!(
                    "round {round}: peer kill handler ran on {} not {tid}",
                    HANDLER2_TID.load(Ordering::SeqCst)
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
            if HANDLED1.load(Ordering::SeqCst) != 1 || HANDLED2.load(Ordering::SeqCst) != 1 {
                failures.push(format!(
                    "round {round}: handled counts usr1={} usr2={} (want 1,1)",
                    HANDLED1.load(Ordering::SeqCst),
                    HANDLED2.load(Ordering::SeqCst)
                ));
            }
            bump(&CHILD_RELEASE);
            if !wait_cleartid(&CTID, WAIT) {
                failures.push(format!("round {round}: CLEARTID never cleared"));
            } else {
                unsafe { libc::munmap(stack, stack_len) };
            }
        }
        let _ = write_count(role.wr, 0);
        let ok = failures.is_empty();
        println!(
            "tgkill-after-clone role=parent rounds={rounds} failures={} ok={ok}",
            failures.len()
        );
        for failure in failures.iter().take(8) {
            println!("tgkill-after-clone failure {failure}");
        }
        ok
    })
}

/// The peer process: `kill(tid, 0)` then `kill(tid, SIGUSR2)` for each tid the
/// parent sends. Linux resolves a non-leader tid and signals its group.
fn tgkill_injector(role: &Role, rounds: usize) -> bool {
    let mut bad = 0;
    for _ in 0..rounds {
        let Some(tid) = poll_read_count(role.rd, 30_000) else {
            bad += 1;
            break;
        };
        let exists = kill_pid(tid as i32, 0);
        let sent = kill_pid(tid as i32, libc::SIGUSR2);
        if exists != 0 || sent != 0 {
            println!("tgkill-after-clone injector kill(tid={tid}) exists={exists} sent={sent}");
            bad += 1;
        }
        let _ = write_count(role.wr, u64::from(exists == 0 && sent == 0));
    }
    println!(
        "tgkill-after-clone role=child rounds={rounds} bad={bad} ok={}",
        bad == 0
    );
    bad == 0
}

// ---------------------------------------------------------------------------
// (c) mask Dekker storm and shared-pending retarget

const STORM_MAX: usize = 8192;
static STORM_SEEN: [AtomicU32; STORM_MAX] = [const { AtomicU32::new(0) }; STORM_MAX];
static STORM_TOTAL: AtomicU32 = AtomicU32::new(0);
static STORM_STOP: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_rt_value(_: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let value = unsafe { (*info).si_value().sival_ptr as usize };
    if value < STORM_MAX {
        STORM_SEEN[value].fetch_add(1, Ordering::SeqCst);
    }
    STORM_TOTAL.fetch_add(1, Ordering::SeqCst);
}

pub fn mask_storm(sends: usize) -> i32 {
    let sends = sends.min(STORM_MAX);
    two_process("mask-storm", &|role| {
        let signal = libc::SIGRTMIN() + 1;
        if role.name == "child" {
            // Sender. Wait until the receiver is set up.
            if !poll_read_byte(role.rd, 10_000) {
                println!("mask-storm role=child receiver never ready");
                return false;
            }
            let mut failures = 0;
            for value in 0..sends {
                let mut attempts = 0;
                loop {
                    let payload = libc::sigval {
                        sival_ptr: value as *mut libc::c_void,
                    };
                    if unsafe { libc::sigqueue(role.peer, signal, payload) } == 0 {
                        break;
                    }
                    // A full real-time queue (EAGAIN) is legitimate backpressure.
                    attempts += 1;
                    if attempts > 5_000 {
                        failures += 1;
                        break;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
            let _ = write_signal_byte(role.wr, b'D');
            println!(
                "mask-storm role=child sends={sends} send_failures={failures} ok={}",
                failures == 0
            );
            return failures == 0;
        }
        if !install_handler(signal, on_rt_value as *const () as usize, true) {
            println!("mask-storm sigaction failed");
            return false;
        }
        STORM_STOP.store(0, Ordering::SeqCst);
        let flipper = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut flips = 0u64;
                while STORM_STOP.load(Ordering::Acquire) == 0 {
                    set_blocked(signal, true);
                    set_blocked(signal, false);
                    flips += 1;
                }
                set_blocked(signal, false);
                flips
            });
        let Ok(flipper) = flipper else {
            println!("mask-storm flipper spawn failed");
            return false;
        };
        if !write_signal_byte(role.wr, b'G') {
            return false;
        }
        let complete = wait_true(Duration::from_secs(60), || {
            STORM_TOTAL.load(Ordering::SeqCst) as usize >= sends
        });
        let sender_done = poll_read_byte(role.rd, 10_000);
        // Let any duplicate arrive before the exactly-once check.
        std::thread::sleep(Duration::from_millis(200));
        STORM_STOP.store(1, Ordering::Release);
        let flips = flipper.join().unwrap_or(0);
        let total = STORM_TOTAL.load(Ordering::SeqCst) as usize;
        let mut missing = 0;
        let mut duplicated = 0;
        for value in 0..sends {
            match STORM_SEEN[value].load(Ordering::SeqCst) {
                0 => missing += 1,
                1 => {}
                _ => duplicated += 1,
            }
        }
        let ok = complete
            && sender_done
            && total == sends
            && missing == 0
            && duplicated == 0
            && flips > 0;
        println!(
            "mask-storm role=parent sends={sends} delivered={total} missing={missing} duplicated={duplicated} flips={flips} complete={complete} sender_done={sender_done} ok={ok}"
        );
        ok
    })
}

static RT_TID: AtomicI32 = AtomicI32::new(0);
static RT_ACK: AtomicU32 = AtomicU32::new(0);
static MAIN_READY: AtomicU32 = AtomicU32::new(0);
static OTHER_READY: AtomicU32 = AtomicU32::new(0);
static MAIN_DONE: AtomicU32 = AtomicU32::new(0);
static OTHER_DONE: AtomicU32 = AtomicU32::new(0);
static OTHER_TID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_retarget(_: i32) {
    RT_TID.store(gettid(), Ordering::SeqCst);
    bump(&RT_ACK);
}

pub fn signal_retarget(rounds: usize) -> i32 {
    two_process("signal-retarget", &|role| {
        for word in [&RT_ACK, &MAIN_READY, &OTHER_READY, &MAIN_DONE, &OTHER_DONE] {
            word.store(0, Ordering::SeqCst);
        }
        RT_TID.store(0, Ordering::SeqCst);
        if !install_handler(libc::SIGUSR1, on_retarget as *const () as usize, false) {
            return false;
        }
        let main_tid = gettid();
        let other = spawn_small(move || {
            OTHER_TID.store(gettid(), Ordering::SeqCst);
            retarget_thread(false, rounds);
        });
        let Ok(other) = other else {
            println!("signal-retarget spawn failed");
            return false;
        };
        let wrong = retarget_thread(true, rounds);
        let joined = other.join().is_ok();
        let ok = wrong == 0 && joined;
        println!(
            "signal-retarget role={} rounds={rounds} main_tid={main_tid} wrong_target={wrong} ok={ok}",
            role.name
        );
        ok
    })
}

/// Both threads run this. Round `r`: the blocker (other thread on even
/// rounds, main on odd) blocks the signal and sends it to the process; the
/// receiver, which leaves it unblocked, must run the handler. Returns the
/// number of rounds whose handler ran on the wrong thread (main only).
fn retarget_thread(is_main: bool, rounds: usize) -> usize {
    let (ready_mine, ready_other, done_mine, done_other) = if is_main {
        (&MAIN_READY, &OTHER_READY, &MAIN_DONE, &OTHER_DONE)
    } else {
        (&OTHER_READY, &MAIN_READY, &OTHER_DONE, &MAIN_DONE)
    };
    let mut wrong = 0;
    for round in 0..rounds {
        let target = (round + 1) as u32;
        let blocker_is_main = round % 2 == 1;
        let i_block = blocker_is_main == is_main;
        set_blocked(libc::SIGUSR1, i_block);
        bump(ready_mine);
        let peer_ready = wait_word_ge(ready_other, target, WAIT);
        if i_block && peer_ready {
            let _ = kill_pid(current_pid(), libc::SIGUSR1);
        }
        let acked = wait_word_ge(&RT_ACK, target, WAIT);
        bump(done_mine);
        let peer_done = wait_word_ge(done_other, target, WAIT);
        if is_main {
            let receiver = if blocker_is_main {
                OTHER_TID.load(Ordering::SeqCst)
            } else {
                gettid()
            };
            if !(peer_ready && acked && peer_done) || RT_TID.load(Ordering::SeqCst) != receiver {
                wrong += 1;
            }
        }
        set_blocked(libc::SIGUSR1, false);
    }
    wrong
}

// ---------------------------------------------------------------------------
// (d) CLEARTID join and tid reuse

pub fn tid_reuse(rounds: usize) -> i32 {
    two_process("tid-reuse", &|role| {
        let mut reused = 0;
        let mut stuck = 0;
        let mut listed_after_join = 0;
        let mut failures = 0;
        for _ in 0..rounds {
            let (first_tid, first) = match parked_thread() {
                Some(pair) => pair,
                None => {
                    failures += 1;
                    continue;
                }
            };
            first.release_and_join();
            let listed = task_ids().is_some_and(|ids| ids.contains(&first_tid));
            listed_after_join += usize::from(listed);
            // The next thread is born while the old tid may still be listed.
            let (second_tid, second) = match parked_thread() {
                Some(pair) => pair,
                None => {
                    failures += 1;
                    continue;
                }
            };
            if second_tid == first_tid {
                reused += 1;
            }
            // The joined tid must leave the task list.
            if !wait_true(Duration::from_secs(5), || {
                task_ids().is_some_and(|ids| !ids.contains(&first_tid) || first_tid == second_tid)
            }) {
                stuck += 1;
            }
            second.release_and_join();
        }
        let ok = failures == 0 && reused == 0 && stuck == 0;
        println!(
            "tid-reuse role={} rounds={rounds} listed_after_join={listed_after_join} reused={reused} stuck={stuck} failures={failures} ok={ok}",
            role.name
        );
        ok
    })
}

struct Parked {
    go: std::sync::Arc<AtomicU32>,
    handle: std::thread::JoinHandle<()>,
}

impl Parked {
    fn release_and_join(self) {
        bump(&self.go);
        let _ = self.handle.join();
    }
}

/// A thread parked until released; returns its kernel tid.
fn parked_thread() -> Option<(i32, Parked)> {
    let go = std::sync::Arc::new(AtomicU32::new(0));
    let tid = std::sync::Arc::new(AtomicI32::new(0));
    let (go2, tid2) = (go.clone(), tid.clone());
    let handle = spawn_small(move || {
        tid2.store(gettid(), Ordering::SeqCst);
        wait_word_ge(&go2, 1, Duration::from_secs(30));
    })
    .ok()?;
    if !wait_true(WAIT, || tid.load(Ordering::SeqCst) != 0) {
        return None;
    }
    Some((tid.load(Ordering::SeqCst), Parked { go, handle }))
}

// ---------------------------------------------------------------------------
// (e) RLIMIT_NPROC

const NPROC_UID: u32 = 34_567;

fn drop_privileges() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return true;
    }
    unsafe { libc::setgid(NPROC_UID) == 0 && libc::setuid(NPROC_UID) == 0 }
}

fn set_nproc_soft(soft: u64, hard: u64) -> bool {
    let limit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) == 0 }
}

/// Spawn one held thread; `Err(errno)` when the kernel refuses.
fn try_spawn_held(release: std::sync::Arc<AtomicU32>) -> Result<std::thread::JoinHandle<()>, i32> {
    spawn_small(move || {
        wait_word_ge(&release, 1, Duration::from_secs(30));
    })
    .map_err(|error| error.raw_os_error().unwrap_or(-1))
}

/// Probe at soft limit `limit`: does one thread spawn succeed? Waits for the
/// probe thread to be reaped so it stops counting.
fn probe_spawn(limit: u64, hard: u64) -> bool {
    if !set_nproc_soft(limit, hard) {
        return false;
    }
    let release = std::sync::Arc::new(AtomicU32::new(1));
    match try_spawn_held(release) {
        Ok(handle) => {
            let _ = handle.join();
            wait_true(Duration::from_secs(5), || {
                task_ids().is_some_and(|ids| ids.len() == 1)
            });
            std::thread::sleep(Duration::from_millis(50));
            true
        }
        Err(_) => false,
    }
}

pub fn nproc_limit() -> i32 {
    two_process("nproc-limit", &|role| {
        if !drop_privileges() {
            println!(
                "nproc-limit role={} could not drop privileges ok=false",
                role.name
            );
            return false;
        }
        if role.name == "child" {
            // The peer keeps its own (unlimited) RLIMIT_NPROC, same uid.
            let _ = write_signal_byte(role.wr, b'R');
            let mut peer_forks = 0;
            loop {
                let mut byte = 0u8;
                let mut pfd = libc::pollfd {
                    fd: role.rd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut pfd, 1, 60_000) } <= 0
                    || unsafe { libc::read(role.rd, (&mut byte as *mut u8).cast(), 1) } != 1
                {
                    return false;
                }
                match byte {
                    b'F' => {
                        let pid = unsafe { libc::fork() };
                        if pid == 0 {
                            unsafe { libc::_exit(0) };
                        }
                        let ok = pid > 0 && reap(pid, Duration::from_secs(10)) == Some(0);
                        peer_forks += usize::from(ok);
                        let _ = write_signal_byte(role.wr, if ok { b'K' } else { b'X' });
                    }
                    _ => break,
                }
            }
            println!("nproc-limit role=child peer_forks={peer_forks} ok=true");
            return true;
        }
        if !poll_read_byte(role.rd, 10_000) {
            println!("nproc-limit role=parent peer not ready ok=false");
            return false;
        }
        let mut hard_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut hard_limit) };
        let hard = hard_limit.rlim_max as u64;
        let ceiling: u64 = if hard == libc::RLIM_INFINITY as u64 {
            8192
        } else {
            hard.min(8192)
        };
        let mut report = Vec::new();

        // Phase 1: far over the limit, clone and fork fail EAGAIN, while the
        // peer (same uid, its own limit) forks.
        let mut phase1 = set_nproc_soft(1, hard);
        let held = std::sync::Arc::new(AtomicU32::new(1));
        let refused = try_spawn_held(held);
        let clone_errno = refused.as_ref().err().copied();
        phase1 &= clone_errno == Some(EAGAIN as i32);
        let fork_pid = unsafe { libc::fork() };
        let fork_errno = if fork_pid < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            if fork_pid == 0 {
                unsafe { libc::_exit(0) };
            }
            reap(fork_pid, Duration::from_secs(10));
            None
        };
        phase1 &= fork_errno == Some(EAGAIN as i32);
        if let Ok(handle) = refused {
            let _ = handle.join();
        }
        let peer_forked = write_signal_byte(role.wr, b'F') && {
            let mut byte = [0u8; 1];
            let mut pfd = libc::pollfd {
                fd: role.rd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut pfd, 1, 20_000) };
            polled > 0
                && unsafe { libc::read(role.rd, byte.as_mut_ptr().cast(), 1) } == 1
                && byte[0] == b'K'
        };
        report.push(format!(
            "clone_errno={clone_errno:?} fork_errno={fork_errno:?} peer_forked={peer_forked}"
        ));

        // Phase 2: find the smallest limit that admits one more task. It
        // counts every task of the uid (both processes' threads), so it is at
        // least three: this process, the peer and the new thread.
        let (mut low, mut high) = (1u64, 2u64);
        while high < ceiling && !probe_spawn(high, hard) {
            low = high;
            high *= 2;
        }
        high = high.min(ceiling);
        while high - low > 1 {
            let mid = (low + high) / 2;
            if probe_spawn(mid, hard) {
                high = mid;
            } else {
                low = mid;
            }
        }
        let lmin = high;
        let stable = probe_spawn(lmin, hard) && !probe_spawn(lmin - 1, hard);
        report.push(format!("lmin={lmin} stable={stable}"));

        // Phase 3: the rule measured in phase 2 is "a new task is refused
        // when the uid already has >= limit tasks" (count after the new task
        // > limit). With C = lmin - 1 existing tasks and limit L = lmin + 2,
        // exactly L - C = 3 held threads are admitted and the 4th gets
        // EAGAIN. Each admission is printed.
        let existing = lmin - 1;
        let limit3 = lmin + 2;
        let mut phase3 = set_nproc_soft(limit3, hard);
        let release = std::sync::Arc::new(AtomicU32::new(0));
        let mut held = Vec::new();
        let mut refused_at = None;
        let mut refused_errno = None;
        for attempt in 1..=8u64 {
            match try_spawn_held(release.clone()) {
                Ok(handle) => held.push(handle),
                Err(errno) => {
                    refused_at = Some(attempt);
                    refused_errno = Some(errno);
                    break;
                }
            }
        }
        let admitted = held.len() as u64;
        phase3 &= admitted == limit3 - existing
            && refused_at == Some(admitted + 1)
            && refused_errno == Some(EAGAIN as i32);
        // An exited thread stops counting: releasing them frees the slots
        // (bounded wait: the count drops when the task is released).
        bump(&release);
        for handle in held {
            let _ = handle.join();
        }
        let freed = wait_true(Duration::from_secs(5), || {
            let probe = std::sync::Arc::new(AtomicU32::new(1));
            match try_spawn_held(probe) {
                Ok(handle) => {
                    let _ = handle.join();
                    true
                }
                Err(_) => false,
            }
        });
        phase3 &= freed;
        report.push(format!(
            "existing={existing} limit3={limit3} admitted={admitted} refused_at={refused_at:?} refused_errno={refused_errno:?} freed={freed}"
        ));

        let _ = write_signal_byte(role.wr, b'D');
        let ok = phase1 && peer_forked && lmin >= 3 && stable && phase3;
        println!(
            "nproc-limit role=parent uid={} phase1={phase1} phase3={phase3} {} ok={ok}",
            unsafe { libc::getuid() },
            report.join(" ")
        );
        ok
    })
}

// ---------------------------------------------------------------------------
// (f)(g) clone storms

static STORM_SPAWNED: AtomicU64 = AtomicU64::new(0);

/// `count` threads that each spawn and join short-lived threads until
/// `stop` is set. Returns their handles.
fn start_storm(count: usize, stop: std::sync::Arc<AtomicU32>) -> Vec<std::thread::JoinHandle<()>> {
    (0..count)
        .filter_map(|_| {
            let stop = stop.clone();
            spawn_small(move || {
                // Bounded and paced: at most 5000 cycles per storm thread.
                let mut cycles = 0;
                while stop.load(Ordering::Acquire) == 0 && cycles < 5000 {
                    if let Ok(handle) = spawn_small(|| {
                        STORM_SPAWNED.fetch_add(1, Ordering::Relaxed);
                    }) {
                        let _ = handle.join();
                    }
                    cycles += 1;
                    std::thread::sleep(Duration::from_micros(300));
                }
            })
            .ok()
        })
        .collect()
}

/// Why one fork of `fork-storm` failed, so a red line names the stage.
enum ForkStormFailure {
    /// `fork` returned -1 with this errno.
    Fork { errno: i32 },
    /// The child's report did not arrive: `poll` timed out, was interrupted
    /// (errno), hung up without data, or the read came up short.
    Report(ReportFailure),
    /// The child reported, but it was not exactly one thread (`threads`
    /// counts `/proc/self/task`) or its own thread clone/join failed.
    Membership { threads: u64 },
    /// The child ended other than `exit(0)`.
    Reap(ReapOutcome),
}

#[derive(Debug)]
enum ReportFailure {
    PollTimeout,
    PollError { errno: i32 },
    HangupWithoutData { revents: i16 },
    ShortRead { have: usize, errno: i32 },
}

#[derive(Debug)]
enum ReapOutcome {
    Exited(i32),
    Signaled(i32),
    TimedOut,
    WaitError { errno: i32 },
}

impl std::fmt::Display for ForkStormFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fork { errno } => write!(f, "fork errno={errno}"),
            Self::Report(ReportFailure::PollTimeout) => write!(f, "report poll timed out"),
            Self::Report(ReportFailure::PollError { errno }) => {
                write!(f, "report poll errno={errno}")
            }
            Self::Report(ReportFailure::HangupWithoutData { revents }) => {
                write!(f, "report hangup without data revents={revents:#x}")
            }
            Self::Report(ReportFailure::ShortRead { have, errno }) => {
                write!(f, "report short read have={have} errno={errno}")
            }
            Self::Membership { threads } => {
                write!(f, "child threads={threads} or its clone/join failed")
            }
            Self::Reap(ReapOutcome::Exited(code)) => write!(f, "child exit code={code}"),
            Self::Reap(ReapOutcome::Signaled(signal)) => {
                write!(f, "child killed by signal={signal}")
            }
            Self::Reap(ReapOutcome::TimedOut) => write!(f, "child not reaped in 20s"),
            Self::Reap(ReapOutcome::WaitError { errno }) => write!(f, "waitpid errno={errno}"),
        }
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `poll_read_count`, with the reason it failed.
fn read_report(fd: libc::c_int, timeout_ms: libc::c_int) -> Result<u64, ReportFailure> {
    let mut bytes = [0u8; 8];
    let mut have = 0;
    while have < bytes.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc == 0 {
            return Err(ReportFailure::PollTimeout);
        }
        if rc < 0 {
            return Err(ReportFailure::PollError {
                errno: last_errno(),
            });
        }
        if (pfd.revents & libc::POLLIN) == 0 {
            return Err(ReportFailure::HangupWithoutData {
                revents: pfd.revents,
            });
        }
        let n = unsafe { libc::read(fd, bytes[have..].as_mut_ptr().cast(), bytes.len() - have) };
        if n <= 0 {
            return Err(ReportFailure::ShortRead {
                have,
                errno: if n < 0 { last_errno() } else { 0 },
            });
        }
        have += n as usize;
    }
    Ok(u64::from_le_bytes(bytes))
}

/// `reap`, with how the child ended.
fn reap_outcome(pid: i32, total: Duration) -> ReapOutcome {
    let start = Instant::now();
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            if libc::WIFEXITED(status) {
                return ReapOutcome::Exited(libc::WEXITSTATUS(status));
            }
            return ReapOutcome::Signaled(libc::WTERMSIG(status));
        }
        if rc < 0 {
            return ReapOutcome::WaitError {
                errno: last_errno(),
            };
        }
        if start.elapsed() > total {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return ReapOutcome::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub fn fork_storm(forks: usize) -> i32 {
    let stop = std::sync::Arc::new(AtomicU32::new(0));
    let storm = start_storm(8, stop.clone());
    // Fork only once the storm is demonstrably running (bounded wait).
    let storm_started = wait_true(Duration::from_secs(20), || {
        STORM_SPAWNED.load(Ordering::Relaxed) >= 64
    });
    let mut failures: Vec<(usize, ForkStormFailure)> = Vec::new();
    let mut child_threads_seen = Vec::new();
    for round in 0..forks {
        let pipe = make_pipe();
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            failures.push((
                round,
                ForkStormFailure::Fork {
                    errno: last_errno(),
                },
            ));
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            continue;
        }
        if pid == 0 {
            unsafe { libc::close(pipe[0]) };
            let ids = task_ids().unwrap_or_default();
            let single = ids.len() == 1 && ids[0] == current_pid();
            let spawned = spawn_small(|| {})
                .map(|handle| handle.join().is_ok())
                .unwrap_or(false);
            let packed = ids.len() as u64 | (u64::from(single && spawned) << 32);
            write_count(pipe[1], packed);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(pipe[1]) };
        match read_report(pipe[0], 20_000) {
            Ok(packed) => {
                child_threads_seen.push(packed & 0xffff_ffff);
                if packed >> 32 != 1 {
                    failures.push((
                        round,
                        ForkStormFailure::Membership {
                            threads: packed & 0xffff_ffff,
                        },
                    ));
                }
            }
            Err(report) => failures.push((round, ForkStormFailure::Report(report))),
        }
        unsafe { libc::close(pipe[0]) };
        match reap_outcome(pid, Duration::from_secs(20)) {
            ReapOutcome::Exited(0) => {}
            other => failures.push((round, ForkStormFailure::Reap(other))),
        }
    }
    stop.store(1, Ordering::Release);
    for handle in storm {
        let _ = handle.join();
    }
    let spawned = STORM_SPAWNED.load(Ordering::Relaxed);
    let bad = failures.len();
    let ok = bad == 0 && storm_started;
    for (round, failure) in failures.iter().take(8) {
        println!("fork-storm failure round {round}: {failure}");
    }
    println!(
        "fork-storm forks={forks} storm_spawned={spawned} bad={bad} child_thread_counts={child_threads_seen:?} ok={ok}"
    );
    if ok { 0 } else { 1 }
}

/// Layout of the page shared with the victim: 8 storm-thread slots, then 4
/// parked-thread slots (guaranteed alive when the victim dies).
const SLOT_STORM: usize = 8;
const SLOT_PARKED: usize = 4;
const SLOTS: usize = SLOT_STORM + SLOT_PARKED;

#[derive(Clone, Copy)]
enum Teardown {
    ExitGroup,
    Exec,
}

pub fn exit_group_storm(rounds: usize) -> i32 {
    teardown_storm("exit-group-storm", Teardown::ExitGroup, rounds, "")
}

pub fn exec_storm(rounds: usize, argv0: &str) -> i32 {
    teardown_storm("exec-storm", Teardown::Exec, rounds, argv0)
}

/// The image `exec-storm` execs: a single-threaded process in the victim's
/// pid.
pub fn exec_storm_child() -> i32 {
    let ids = task_ids().unwrap_or_default();
    let ok = ids.len() == 1 && ids[0] == current_pid() && gettid() == current_pid();
    println!("exec-storm-child tasks={ids:?} ok={ok}");
    if ok { 0 } else { 3 }
}

fn teardown_storm(name: &str, how: Teardown, rounds: usize, argv0: &str) -> i32 {
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED, "shared page");
    let slots = unsafe { std::slice::from_raw_parts(page as *const AtomicI32, SLOTS + 1) };
    let mut failures = Vec::new();
    for round in 0..rounds {
        for slot in slots {
            slot.store(0, Ordering::SeqCst);
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            failures.push(format!("round {round}: fork"));
            continue;
        }
        if pid == 0 {
            victim(how, slots, argv0);
        }
        let expected = match how {
            Teardown::ExitGroup => 7,
            Teardown::Exec => 0,
        };
        match reap_outcome(pid, Duration::from_secs(30)) {
            ReapOutcome::Exited(code) if code == expected => {}
            other => failures.push(format!(
                "round {round}: victim status {other:?} want {expected}"
            )),
        }
        if kill_pid(pid, 0) != -ESRCH {
            failures.push(format!("round {round}: victim pid {pid} still exists"));
        }
        for (index, slot) in slots.iter().enumerate().take(SLOTS) {
            let tid = slot.load(Ordering::SeqCst);
            if tid == 0 || tid == pid {
                continue;
            }
            if !wait_true(Duration::from_secs(5), || kill_pid(tid, 0) == -ESRCH) {
                failures.push(format!("round {round}: survivor tid {tid} (slot {index})"));
            }
        }
        if slots[SLOT_STORM..SLOTS]
            .iter()
            .any(|slot| slot.load(Ordering::SeqCst) == 0)
        {
            failures.push(format!("round {round}: victim never parked its threads"));
        }
    }
    let ok = failures.is_empty();
    println!("{name} rounds={rounds} failures={} ok={ok}", failures.len());
    for failure in failures.iter().take(8) {
        println!("{name} failure {failure}");
    }
    if ok { 0 } else { 1 }
}

/// The forked victim: a clone storm and parked threads, then one thread tears
/// the process down. Never returns.
fn victim(how: Teardown, slots: &'static [AtomicI32], argv0: &str) -> ! {
    let stop = std::sync::Arc::new(AtomicU32::new(0));
    let park = std::sync::Arc::new(AtomicU32::new(0));
    for index in 0..SLOT_PARKED {
        let park = park.clone();
        let slot: &'static AtomicI32 = &slots[SLOT_STORM + index];
        let _ = spawn_small(move || {
            slot.store(gettid(), Ordering::SeqCst);
            wait_word_ge(&park, 1, Duration::from_secs(60));
        });
    }
    for index in 0..SLOT_STORM {
        let stop = stop.clone();
        let slot: &'static AtomicI32 = &slots[index];
        let _ = spawn_small(move || {
            while stop.load(Ordering::Acquire) == 0 {
                if let Ok(handle) = spawn_small(move || {
                    slot.store(gettid(), Ordering::SeqCst);
                    STORM_SPAWNED.fetch_add(1, Ordering::Relaxed);
                }) {
                    let _ = handle.join();
                }
            }
        });
    }
    let started = wait_true(Duration::from_secs(20), || {
        STORM_SPAWNED.load(Ordering::Relaxed) >= 64
            && slots[SLOT_STORM..SLOTS]
                .iter()
                .all(|slot| slot.load(Ordering::SeqCst) != 0)
    });
    if !started {
        unsafe { libc::_exit(9) };
    }
    let path = std::ffi::CString::new(argv0).unwrap_or_default();
    // A non-leader thread performs the teardown.
    let killer = spawn_small(move || match how {
        Teardown::ExitGroup => {
            unsafe { raw6(SYS_EXIT_GROUP_NR, 7, 0, 0, 0, 0, 0) };
        }
        Teardown::Exec => {
            let arg0 = std::ffi::CString::new("el1-sched").unwrap_or_default();
            let arg1 = std::ffi::CString::new("exec-storm-child").unwrap_or_default();
            let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            unsafe { libc::_exit(8) };
        }
    });
    if killer.is_err() {
        unsafe { libc::_exit(10) };
    }
    // Bounded: the teardown must take this thread down.
    std::thread::sleep(Duration::from_secs(60));
    unsafe { libc::_exit(11) }
}

// ---------------------------------------------------------------------------
// (h) ptrace and seccomp

pub fn ptrace_clone() -> i32 {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("ptrace-clone fork failed");
        return 1;
    }
    if pid == 0 {
        let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
        if rc != 0 {
            println!(
                "ptrace-clone tracee PTRACE_TRACEME errno={:?}",
                std::io::Error::last_os_error().raw_os_error()
            );
            unsafe { libc::_exit(20) };
        }
        unsafe { libc::raise(libc::SIGSTOP) };
        let joined = spawn_small(|| {})
            .map(|handle| handle.join().is_ok())
            .unwrap_or(false);
        unsafe { libc::_exit(if joined { 0 } else { 21 }) };
    }
    let mut notes = Vec::new();
    let waited = |flags: i32| -> Option<(i32, i32)> {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | flags) };
        (rc > 0).then_some((rc, status))
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut initial_stop = false;
    let mut clone_event = false;
    let mut new_tid = 0;
    let mut new_thread_stopped = Vec::new();
    let mut exit_code = None;
    let mut options_ok = false;
    let mut options_errno = None;
    while Instant::now() < deadline && exit_code.is_none() {
        let Some((who, status)) = waited(libc::WNOHANG) else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        if libc::WIFEXITED(status) {
            if who == pid {
                exit_code = Some(libc::WEXITSTATUS(status));
            }
            continue;
        }
        if libc::WIFSIGNALED(status) {
            if who == pid {
                exit_code = Some(128 + libc::WTERMSIG(status));
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if who == pid && !initial_stop && signal == libc::SIGSTOP && event == 0 {
            initial_stop = true;
            options_ok =
                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACECLONE) }
                    == 0;
            if !options_ok {
                options_errno = std::io::Error::last_os_error().raw_os_error();
            }
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) };
        } else if event == libc::PTRACE_EVENT_CLONE {
            clone_event = true;
            let mut message: libc::c_ulong = 0;
            unsafe {
                libc::ptrace(
                    libc::PTRACE_GETEVENTMSG,
                    who,
                    0,
                    &mut message as *mut libc::c_ulong,
                )
            };
            new_tid = message as i32;
            unsafe { libc::ptrace(libc::PTRACE_CONT, who, 0, 0) };
        } else if who != pid {
            new_thread_stopped.push((who, signal));
            unsafe { libc::ptrace(libc::PTRACE_CONT, who, 0, 0) };
        } else {
            let pass = if signal == libc::SIGSTOP { 0 } else { signal };
            unsafe { libc::ptrace(libc::PTRACE_CONT, who, 0, pass as libc::c_long) };
        }
    }
    if exit_code.is_none() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        notes.push("timeout".to_owned());
    }
    let attached = new_tid > 0
        && new_thread_stopped
            .iter()
            .any(|&(tid, signal)| tid == new_tid && signal == libc::SIGSTOP);
    let ok = initial_stop
        && options_ok
        && clone_event
        && new_tid != pid
        && attached
        && exit_code == Some(0);
    println!(
        "ptrace-clone initial_stop={initial_stop} options_ok={options_ok} options_errno={options_errno:?} clone_event={clone_event} new_tid={new_tid} new_thread_stopped={new_thread_stopped:?} exit={exit_code:?} {} ok={ok}",
        notes.join(",")
    );
    if ok { 0 } else { 1 }
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

pub fn seccomp_clone() -> i32 {
    two_process("seccomp-clone", &|role| {
        if role.name == "child" {
            // An unfiltered peer keeps spawning threads meanwhile.
            let mut bad = 0;
            for _ in 0..32 {
                if !spawn_small(|| {})
                    .map(|handle| handle.join().is_ok())
                    .unwrap_or(false)
                {
                    bad += 1;
                }
            }
            let _ = write_signal_byte(role.wr, b'D');
            println!(
                "seccomp-clone role=child unfiltered_spawn_failures={bad} ok={}",
                bad == 0
            );
            return bad == 0;
        }
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JEQ_K: u16 = 0x15;
        const BPF_JSET_K: u16 = 0x45;
        const BPF_RET_K: u16 = 0x06;
        const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
        let filter = [
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JEQ_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_AARCH64,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 3,
                k: SYS_CLONE as u32,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 16,
            },
            SockFilter {
                code: BPF_JSET_K,
                jt: 0,
                jf: 1,
                k: libc::CLONE_THREAD as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: 0x0005_0000 | EPERM as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            },
        ];
        let program = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        let installed = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_SECCOMP, 2, &program as *const SockFprog) == 0
        };
        if !installed {
            println!(
                "seccomp-clone role=parent install failed errno={:?} ok=false",
                std::io::Error::last_os_error().raw_os_error()
            );
            return false;
        }
        // A thread clone is refused with EPERM (raw result -EPERM) and creates
        // no task.
        let raw = unsafe { raw6(SYS_CLONE, THREAD_FLAGS, 0, 0, 0, 0, 0) };
        let before = task_ids().map(|ids| ids.len());
        let spawned = spawn_small(|| {});
        let spawn_errno = spawned
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error);
        let refused = spawned.is_err();
        if let Ok(handle) = spawned {
            let _ = handle.join();
        }
        let after = task_ids().map(|ids| ids.len());
        // A process clone (fork) passes the filter.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let forked = pid > 0 && reap(pid, Duration::from_secs(10)) == Some(0);
        let peer_done = poll_read_byte(role.rd, 20_000);
        let ok = raw == -EPERM && refused && before == after && forked && peer_done;
        println!(
            "seccomp-clone role=parent raw_clone={raw} spawn_errno={spawn_errno:?} tasks_before={before:?} tasks_after={after:?} fork_ok={forked} peer_done={peer_done} ok={ok}"
        );
        ok
    })
}

// ---------------------------------------------------------------------------
// (j) executor-pool exhaustion

static FLOOD_DONE: AtomicU32 = AtomicU32::new(0);
static FLOOD_GO: AtomicU32 = AtomicU32::new(0);

pub fn futex_flood(threads: usize) -> i32 {
    two_process("futex-flood", &|role| {
        FLOOD_DONE.store(0, Ordering::SeqCst);
        FLOOD_GO.store(0, Ordering::SeqCst);
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
            return false;
        }
        let [pipe_rd, pipe_wr] = fds;
        let futex_waiters = threads / 2;
        let pipe_waiters = threads - futex_waiters;
        let mut handles = Vec::new();
        let mut spawn_failures = 0;
        for index in 0..threads {
            let use_futex = index < futex_waiters;
            match spawn_small(move || {
                let woke = if use_futex {
                    wait_word_ge(&FLOOD_GO, 1, Duration::from_secs(60))
                } else {
                    flood_pipe_wait(pipe_rd)
                };
                if woke {
                    bump(&FLOOD_DONE);
                }
            }) {
                Ok(handle) => handles.push(handle),
                Err(_) => spawn_failures += 1,
            }
        }
        // Let the waiters park before anything wakes them.
        std::thread::sleep(Duration::from_millis(300));
        bump(&FLOOD_GO);
        let bytes = vec![1u8; pipe_waiters];
        let wrote = unsafe { libc::write(pipe_wr, bytes.as_ptr().cast(), bytes.len()) };
        let complete = wait_word_ge(&FLOOD_DONE, threads as u32, Duration::from_secs(60));
        for handle in handles {
            let _ = handle.join();
        }
        let done = FLOOD_DONE.load(Ordering::SeqCst);
        let ok = spawn_failures == 0
            && wrote == pipe_waiters as isize
            && complete
            && done == threads as u32;
        println!(
            "futex-flood role={} threads={threads} futex_waiters={futex_waiters} pipe_waiters={pipe_waiters} done={done} spawn_failures={spawn_failures} ok={ok}",
            role.name
        );
        ok
    })
}

/// Wait for one byte on a non-blocking pipe: poll (bounded), then read.
fn flood_pipe_wait(fd: libc::c_int) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 1000) } > 0 {
            let mut byte = 0u8;
            if unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) } == 1 {
                return true;
            }
        }
    }
    false
}

// The raw `exit` number is used by `raw_clone_thread`'s child stub.
const _: u64 = SYS_EXIT;
