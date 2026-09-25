//! Guest fixture for carrick-embed's signed EL1 scheduler tests (EL1 plan 1b,
//! in-guest futex handoff). A static aarch64 musl program; every futex call
//! is a raw `svc` so the exact operation under test is the one issued, and a
//! raw return value (not libc's errno) is what the checks read.
//!
//! Modes:
//! - `pingpong <iters>`: two threads hand off through
//!   `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`; prints the round-trip latency.
//! - `signal`: signals a thread parked in a futex wait, once with a handler
//!   without `SA_RESTART` (the handler runs and the wait returns `EINTR`) and
//!   once with `SA_RESTART` (the handler runs; the wait then returns `EINTR`
//!   or, restarted, 0 when woken: the restart is reported, not asserted).
//! - `exit-group`: `exit_group(42)` while threads are parked in futex waits
//!   and a pair is handing off.
//! - `exec`: `execve` from a non-leader thread while siblings are parked.
//! - `exec-child`: the image `exec` runs.
//!
//! Every wait in the checks is bounded, so a lost wake or a lost signal is a
//! failed line, never a hung test.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SYS_FUTEX: u64 = 98;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_GETTID: u64 = 178;
const SYS_TGKILL: u64 = 131;
const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
const EINTR: i64 = 4;

unsafe fn raw6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            inlateout("x0") a0 as i64 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            in("x8") nr,
            options(nostack)
        );
    }
    ret
}

/// `FUTEX_WAIT_PRIVATE` with no timeout: the in-guest (EL1) handoff case.
fn futex_wait(word: &AtomicU32, expected: u32) -> i64 {
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAIT_PRIVATE,
            u64::from(expected),
            0,
            0,
            0,
        )
    }
}

/// `FUTEX_WAIT_PRIVATE` bounded by a relative timeout.
fn futex_wait_timeout(word: &AtomicU32, expected: u32, timeout: Duration) -> i64 {
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos() as i32),
    };
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAIT_PRIVATE,
            u64::from(expected),
            &ts as *const libc::timespec as u64,
            0,
            0,
        )
    }
}

fn futex_wake(word: &AtomicU32, count: u32) -> i64 {
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAKE_PRIVATE,
            u64::from(count),
            0,
            0,
            0,
        )
    }
}

fn gettid() -> i32 {
    unsafe { raw6(SYS_GETTID, 0, 0, 0, 0, 0, 0) as i32 }
}

fn tgkill(tid: i32, signal: i32) -> i64 {
    let pid = std::process::id() as u64;
    unsafe { raw6(SYS_TGKILL, pid, tid as u64, signal as u64, 0, 0, 0) }
}

fn cntvct() -> u64 {
    let value: u64;
    unsafe { std::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) value) };
    value
}

fn cntfrq() -> u64 {
    let value: u64;
    unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) value) };
    value
}

/// Wait until `word != value`, bounded by `limit`; true when it changed.
fn wait_until_changed(word: &AtomicU32, value: u32, limit: Duration) -> bool {
    let start = Instant::now();
    while word.load(Ordering::Acquire) == value {
        let spent = start.elapsed();
        if spent >= limit {
            return false;
        }
        let _ = futex_wait_timeout(word, value, limit - spent);
    }
    true
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

// ---------------------------------------------------------------------------
// pingpong

static TURN: AtomicU32 = AtomicU32::new(0); // 0: A acts, 1: B acts, 2: stop

fn pingpong(iters: usize) -> i32 {
    const WARMUP: usize = 2000;
    let b = std::thread::spawn(|| {
        loop {
            while TURN.load(Ordering::Acquire) == 0 {
                let _ = futex_wait(&TURN, 0);
            }
            if TURN.load(Ordering::Acquire) == 2 {
                return;
            }
            TURN.store(0, Ordering::Release);
            let _ = futex_wake(&TURN, 1);
        }
    });
    let mut samples = Vec::with_capacity(iters);
    for i in 0..WARMUP + iters {
        let t0 = cntvct();
        TURN.store(1, Ordering::Release);
        let _ = futex_wake(&TURN, 1);
        while TURN.load(Ordering::Acquire) == 1 {
            let _ = futex_wait(&TURN, 1);
        }
        if i >= WARMUP {
            samples.push(cntvct() - t0);
        }
    }
    TURN.store(2, Ordering::Release);
    let _ = futex_wake(&TURN, 1);
    b.join().expect("pingpong partner exits");
    let ns = 1e9 / cntfrq() as f64;
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2] as f64 * ns;
    let mean = samples.iter().sum::<u64>() as f64 * ns / samples.len() as f64;
    println!(
        "pingpong iters={iters} p50_ns={p50:.0} mean_ns={mean:.0} max_ns={:.0}",
        *samples.last().unwrap_or(&0) as f64 * ns
    );
    0
}

// ---------------------------------------------------------------------------
// signal

static GO: AtomicU32 = AtomicU32::new(0);
static PARK: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static DONE: AtomicU32 = AtomicU32::new(0);
static HANDLED: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static RESULT: [AtomicI64; 2] = [AtomicI64::new(i64::MIN), AtomicI64::new(i64::MIN)];
static WORKER_TID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_: libc::c_int) {
    HANDLED[0].fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_usr2(_: libc::c_int) {
    HANDLED[1].fetch_add(1, Ordering::SeqCst);
}

fn install(signal: libc::c_int, handler: extern "C" fn(libc::c_int), flags: libc::c_int) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = flags;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(signal, &action, std::ptr::null_mut()),
            0,
            "sigaction"
        );
    }
}

fn signal_mode() -> i32 {
    install(libc::SIGUSR1, on_usr1, 0);
    install(libc::SIGUSR2, on_usr2, libc::SA_RESTART);
    let worker = std::thread::spawn(|| {
        WORKER_TID.store(gettid(), Ordering::SeqCst);
        for round in 0..2 {
            // Wake the main thread, then park: the wake puts main on this
            // vCPU's EL1 run queue, so the wait below is served in-guest.
            GO.store(round + 1, Ordering::Release);
            let _ = futex_wake(&GO, 1);
            let result = futex_wait(&PARK[round as usize], 0);
            RESULT[round as usize].store(result, Ordering::SeqCst);
            DONE.store(round + 1, Ordering::Release);
            let _ = futex_wake(&DONE, 1);
        }
    });
    let limit = Duration::from_secs(10);
    for round in 0..2u32 {
        if !wait_until_changed(&GO, round, limit) {
            println!("signal round={round} worker never woke main");
            return 1;
        }
        // Give the worker time to reach its wait if it is on another vCPU.
        sleep_ms(20);
        let signal = if round == 0 {
            libc::SIGUSR1
        } else {
            libc::SIGUSR2
        };
        let rc = tgkill(WORKER_TID.load(Ordering::SeqCst), signal);
        if rc != 0 {
            println!("signal round={round} tgkill={rc}");
            return 1;
        }
        if round == 1 {
            // SA_RESTART: once the handler has run, wake the wait (a restarted
            // wait returns 0; one that returned EINTR is already done).
            let start = Instant::now();
            while HANDLED[1].load(Ordering::SeqCst) == 0 && start.elapsed() < limit {
                sleep_ms(1);
            }
            PARK[1].store(1, Ordering::Release);
            let _ = futex_wake(&PARK[1], 1);
        }
        if !wait_until_changed(&DONE, round, limit) {
            println!("signal round={round} worker never finished its wait");
            return 1;
        }
    }
    worker.join().expect("signal worker exits");
    let eintr = RESULT[0].load(Ordering::SeqCst);
    let restart = RESULT[1].load(Ordering::SeqCst);
    let handled = [
        HANDLED[0].load(Ordering::SeqCst),
        HANDLED[1].load(Ordering::SeqCst),
    ];
    println!(
        "signal eintr_result={eintr} usr1_handled={} restart_result={restart} usr2_handled={}",
        handled[0], handled[1]
    );
    let ok = eintr == -EINTR && (restart == 0 || restart == -EINTR) && handled == [1, 1];
    i32::from(!ok)
}

// ---------------------------------------------------------------------------
// exit-group / exec: siblings parked while another thread ends the image

static PAIR: AtomicU32 = AtomicU32::new(0);
static FOREVER: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static HANDOFF: AtomicU32 = AtomicU32::new(0);

/// A pair handing off forever, a thread parked in-guest after a handoff, and
/// a thread parked with nothing to switch to.
fn spawn_parked_siblings() {
    for side in 0..2u32 {
        std::thread::spawn(move || {
            loop {
                while PAIR.load(Ordering::Acquire) != side {
                    let _ = futex_wait(&PAIR, side ^ 1);
                }
                PAIR.store(side ^ 1, Ordering::Release);
                let _ = futex_wake(&PAIR, 1);
            }
        });
    }
    std::thread::spawn(|| {
        while HANDOFF.load(Ordering::Acquire) == 0 {
            let _ = futex_wait(&HANDOFF, 0);
        }
        loop {
            let _ = futex_wait(&FOREVER[1], 0);
        }
    });
    sleep_ms(20);
    std::thread::spawn(|| {
        HANDOFF.store(1, Ordering::Release);
        let _ = futex_wake(&HANDOFF, 1);
        loop {
            let _ = futex_wait(&FOREVER[0], 0);
        }
    });
    sleep_ms(100);
}

fn exit_group_mode() -> i32 {
    spawn_parked_siblings();
    unsafe {
        raw6(SYS_EXIT_GROUP, 42, 0, 0, 0, 0, 0);
    }
    unreachable!("exit_group returned")
}

fn exec_mode(argv0: &str) -> i32 {
    spawn_parked_siblings();
    let path = std::ffi::CString::new(argv0).expect("argv0");
    let exec = std::thread::spawn(move || {
        let arg0 = std::ffi::CString::new("el1-sched").expect("arg0");
        let arg1 = std::ffi::CString::new("exec-child").expect("arg1");
        let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        let rc = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        println!("exec failed rc={rc}");
        std::process::exit(3);
    });
    let _ = exec.join();
    loop {
        let _ = futex_wait(&FOREVER[0], 0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("pingpong");
    let code = match mode {
        "pingpong" => pingpong(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(20_000)),
        "signal" => signal_mode(),
        "exit-group" => exit_group_mode(),
        "exec" => exec_mode(&args[0]),
        "exec-child" => {
            println!("exec-child ok");
            0
        }
        other => {
            println!("unknown mode {other}");
            2
        }
    };
    std::process::exit(code);
}
