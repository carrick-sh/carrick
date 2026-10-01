//! Guest fixture for carrick-embed's signed EL1 scheduler tests (EL1 plan 1b,
//! in-guest futex handoff). A static aarch64 musl program; every futex call
//! is a raw `svc` so the exact operation under test is the one issued, and a
//! raw return value (not libc's errno) is what the checks read.
//!
//! Modes:
//! - `pingpong <iters>`: two threads pinned to guest CPU 0 hand off through
//!   `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`, so every handoff parks one
//!   thread and switches to the other on that vCPU; prints the round-trip
//!   latency. (`pinned-pingpong` is the cross-vCPU handoff.)
//! - `signal`: signals a thread parked in a futex wait, once with a handler
//!   without `SA_RESTART` (the handler runs and the wait returns `EINTR`) and
//!   once with `SA_RESTART` (the handler runs; the wait then returns `EINTR`
//!   or, restarted, 0 when woken: the restart is reported, not asserted).
//! - `exit-group`: `exit_group(42)` while threads are parked in futex waits
//!   and a pair is handing off.
//! - `exec`: `execve` from a non-leader thread while siblings are parked.
//! - `exec-child`: the image `exec` runs.
//! - `epoll-pingpong <iters>`: two threads hand a turn back and forth through
//!   eventfds, each blocking in `epoll_wait` on its own epoll (libuv's
//!   MessagePort shape); prints the round-trip latency.
//! - `pinned-pingpong <iters> <work_us>`: `pingpong` with the two threads
//!   pinned to different guest CPUs, each computing `work_us` with the turn,
//!   so every handoff wakes a thread parked on the other vCPU (EL1 plan 1c).
//! - `timed-wait <iters>`: `FUTEX_WAIT_PRIVATE` with a 1 ms relative timeout
//!   and no waker, `iters` times: every result must be `ETIMEDOUT`; prints the
//!   lateness past the deadline.
//! - `compute-pair <ms>`: both threads pinned to guest CPU 0; the main
//!   thread wakes a sibling parked in a host served wait onto its own vCPU,
//!   then both compute without a syscall for `<ms>`; prints how far each got.
//! - `idle-carrier <ms>`: four threads parked in untimed futex waits while the
//!   main thread waits `<ms>` with a timeout: the carrier has nothing to run.
//! - `wfi-signal <rounds>`: a thread parked in an untimed futex wait on an
//!   idle vCPU is signalled `rounds` times; each wait must return `EINTR`.
//! - `pstate`: the PSTATE a signal handler sees, for a signal delivered at a
//!   syscall boundary and for one that interrupts a computing thread.
//! - `pipe-pingpong <iters>` (EL1 plan 1d): two threads hand a byte back and
//!   forth over two pipes, so every turn blocks one thread in a host-served
//!   `read` and completes it from the other; prints the round-trip latency.
//! - `sock-pingpong <iters> [pinned]`: the `pipe-pingpong` hand-off over two
//!   `AF_UNIX` socketpairs. Sockets are host objects (`IpcBacking::Host`): EL1
//!   forwards their `read`/`write`, so every turn blocks one thread in a
//!   genuinely host-served `read` that the host completes. With `pinned`
//!   both threads share guest CPU 0, so a completed read queues behind the
//!   thread that is about to block in the next host wait.
//! - `pipe-compute <ms>` (EL1 plan 1d): two threads pinned to one guest CPU;
//!   one completes the other's host-served pipe `read`, then computes: the
//!   woken thread must still run within the window.
//! - `two-process <iters>` (EL1 plan 1d): `fork`, then each process runs a
//!   `pingpong` pair pinned to guest CPUs 0 and 1, so threads of the two
//!   address spaces share those vCPUs; prints each process's round trips.
//!
//! - `mm-occupancy <forks>` (EL1 increment 2): `fork`, then each of the two
//!   processes runs twice as many writer threads as guest CPUs (pairs handing
//!   a turn off through private futexes, each writing and reading back its own
//!   page), an editor thread churning `mmap`/`mprotect`/`munmap`/`madvise` on
//!   a scratch region (stage-1 pauses of the MM; verified non-zero completed
//!   edits and zero edit failures), and a forker thread that forks `<forks>`
//!   times while the writers run (each allocation-free child checks that all
//!   allocated writer pages stay stable after fork) and `vfork`s as often
//!   (each child `_exit`s at once, with waitpid status and reap verification).
//!   Prints each process's counters; any torn page, changed snapshot, edit
//!   failure, unmap failure, worker join panic, or child failure is a failure.
//!
//! - `first-touch <pages>` (EL1 increment 2): `mmap`s `<pages>` private anonymous
//!   pages before `fork`, then parent and child concurrently touch all pages at the
//!   same inherited virtual range: verify zero fill, write distinct role values,
//!   rendezvous via bounded pipes, and verify role values are preserved.
//!
//! - `mapping-retirement <pages> <rounds>` (EL1 increment 2): repeatedly maps
//!   one private anonymous range at the same VA, verifies every byte is zero,
//!   writes every Linux page, verifies the writes, and unmaps the whole range.
//!
//! - `permission-transitions <pages> <rounds>` (EL1 increment 2): initializes
//!   private anonymous pages, repeatedly applies read-only and `PROT_NONE` to
//!   the complete range, proves write/read denial through `SEGV_ACCERR`, restores
//!   RW from the signal handler, and verifies every byte remains intact.
//!
//! - `anonymous-reservations <count>` (EL1 increment 2): exercises anonymous
//!   `mmap`, `MAP_FIXED` replacement, and `brk` growth and shrink, proving
//!   authoritative in-guest reservation tracking and zero-fill semantics.
//!
//! - `anonymous-discard-and-exit <pages> <rounds>` (EL1 increment 2): exercises
//!   `madvise(MADV_DONTNEED)` and process termination without `munmap` under a
//!   live fork peer, proving elastic frame return and zero-fill on reuse.
//!
//! - `delegated-root-vma <rounds>`, `delegated-root-fixed-cow <pages> <rounds>`,
//!   `kick-first-read <rounds>` (EL1 stage S3): two-process delegated-root
//!   witnesses, described in `delegated_root.rs`.
//!
//! - `fault-entry`: triggers a stage-1 permission fault on a PROT_READ mapping,
//!   catches SIGSEGV with SA_SIGINFO, verifies si_addr, mprotects PROT_READ|PROT_WRITE,
//!   retries store, and verifies store success and register preservation.
//!
//! Every wait in the checks is bounded, so a lost wake or a lost signal is a
//! failed line, never a hung test.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::time::{Duration, Instant};

mod delegated_root;
mod ipc;
mod sample_buffer;
mod threads;
use sample_buffer::measured_samples;

const SYS_FUTEX: u64 = 98;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_GETTID: u64 = 178;
const SYS_TGKILL: u64 = 131;
const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
const EINTR: i64 = 4;
const ETIMEDOUT: i64 = 110;
const SYS_SCHED_SETAFFINITY: u64 = 122;
const FUTEX_WAIT_BITSET_PRIVATE: u64 = 128 | 9;
const FUTEX_BITSET_MATCH_ANY: u64 = 0xffff_ffff;

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
static TURN_PIN: AtomicI64 = AtomicI64::new(i64::MIN);

/// Both threads share guest CPU 0: unpinned, EL1 places a woken thread on
/// an idle vCPU, and two threads on two vCPUs can finish a round trip
/// without either parking, which makes the number of handoffs (the thing
/// measured) depend on timing.
fn pingpong(iters: usize) -> i32 {
    const WARMUP: usize = 2000;
    let pin_a = pin(0);
    let b = std::thread::spawn(|| {
        TURN_PIN.store(pin(0), Ordering::Release);
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
    let mut samples = measured_samples(iters, 55_000);
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
    let pin_b = TURN_PIN.load(Ordering::Acquire);
    if pin_a != 0 || pin_b != 0 {
        println!("pingpong sched_setaffinity failed: main={pin_a} partner={pin_b}");
        return 1;
    }
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

// ---------------------------------------------------------------------------
// EL1 plan 1c modes

/// Pin the calling thread to guest CPU `cpu` (raw `sched_setaffinity`).
fn pin(cpu: u32) -> i64 {
    let mask: u64 = 1 << cpu;
    unsafe {
        raw6(
            SYS_SCHED_SETAFFINITY,
            0,
            8,
            &mask as *const u64 as u64,
            0,
            0,
            0,
        )
    }
}

fn ns_per_tick() -> f64 {
    1e9 / cntfrq() as f64
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

static PTURN: AtomicU32 = AtomicU32::new(0); // 0: A acts, 1: B acts, 2: stop
static PREADY: AtomicU32 = AtomicU32::new(0);

/// Spin for `ticks` of the virtual counter (no syscall).
fn busy(ticks: u64) {
    let start = cntvct();
    while cntvct() - start < ticks {
        std::hint::spin_loop();
    }
}

/// `pingpong` between threads pinned to guest CPUs 0 and 1, each computing
/// for `work_us` once it has the turn and before it hands it back: the
/// partner is parked by then, so every handoff wakes a thread parked on the
/// other vCPU. Below the idle vCPU's spin budget the partner's vCPU is still
/// polling; above it, it is parked in WFI. Prints the round trip and the
/// handoff latency (half the round trip less one side's work).
fn pinned_pingpong(iters: usize, work_us: u64) -> i32 {
    const WARMUP: usize = 200;
    let work = cntfrq() * work_us / 1_000_000;
    let pin_a = pin(0);
    let b = std::thread::spawn(move || {
        let rc = pin(1);
        PREADY.store(if rc == 0 { 1 } else { 2 }, Ordering::Release);
        let _ = futex_wake(&PREADY, 1);
        loop {
            while PTURN.load(Ordering::Acquire) == 0 {
                let _ = futex_wait(&PTURN, 0);
            }
            if PTURN.load(Ordering::Acquire) == 2 {
                return;
            }
            busy(work);
            PTURN.store(0, Ordering::Release);
            let _ = futex_wake(&PTURN, 1);
        }
    });
    if !wait_until_changed(&PREADY, 0, Duration::from_secs(10)) {
        println!("pinned-pingpong partner never started");
        return 1;
    }
    if pin_a != 0 || PREADY.load(Ordering::Acquire) != 1 {
        println!(
            "pinned-pingpong sched_setaffinity failed: main={pin_a} partner={}",
            PREADY.load(Ordering::Acquire)
        );
        return 1;
    }
    // Written before the loop: its first-touch page faults are host memory
    // work (each one quiesces the process's other vCPUs), which is not what
    // this mode measures.
    let mut samples = vec![0u64; iters];
    for sample in samples.iter_mut() {
        // SAFETY: an element of the live vector.
        unsafe { std::ptr::write_volatile(sample, 1) };
    }
    for i in 0..WARMUP + iters {
        busy(work);
        let t0 = cntvct();
        PTURN.store(1, Ordering::Release);
        let _ = futex_wake(&PTURN, 1);
        while PTURN.load(Ordering::Acquire) == 1 {
            let _ = futex_wait(&PTURN, 1);
        }
        if i >= WARMUP {
            samples[i - WARMUP] = cntvct() - t0;
        }
    }
    PTURN.store(2, Ordering::Release);
    let _ = futex_wake(&PTURN, 1);
    b.join().expect("pinned-pingpong partner exits");
    samples.sort_unstable();
    let ns = ns_per_tick();
    let handoff = |rt: u64| (rt.saturating_sub(work)) as f64 * ns / 2.0;
    println!(
        "pinned-pingpong iters={iters} work_us={work_us} rt_p50_ns={:.0} handoff_p50_ns={:.0} \
         handoff_p99_ns={:.0} rt_max_ns={:.0}",
        percentile(&samples, 0.5) as f64 * ns,
        handoff(percentile(&samples, 0.5)),
        handoff(percentile(&samples, 0.99)),
        *samples.last().unwrap_or(&0) as f64 * ns
    );
    0
}

static NEVER: AtomicU32 = AtomicU32::new(0);

/// `iters` 1 ms waits on a word nobody wakes: each must return
/// `ETIMEDOUT`, no earlier than its deadline.
fn timed_wait(iters: usize) -> i32 {
    let timeout = Duration::from_millis(1);
    let freq = cntfrq();
    let timeout_ticks = (freq as u128 * timeout.as_nanos() / 1_000_000_000) as u64;
    let mut lateness = measured_samples(iters, 1_200);
    let mut wrong = 0usize;
    let mut early = 0usize;
    for _ in 0..iters {
        let t0 = cntvct();
        let rc = futex_wait_timeout(&NEVER, 0, timeout);
        let t1 = cntvct();
        if rc != -ETIMEDOUT {
            wrong += 1;
            if wrong < 4 {
                println!("timed-wait result={rc}");
            }
            continue;
        }
        let elapsed = t1 - t0;
        if elapsed < timeout_ticks {
            early += 1;
        }
        lateness.push(elapsed.saturating_sub(timeout_ticks));
    }
    lateness.sort_unstable();
    let ns = ns_per_tick();
    println!(
        "timed-wait iters={iters} wrong={wrong} early={early} late_p50_ns={:.0} \
         late_p99_ns={:.0} late_max_ns={:.0}",
        percentile(&lateness, 0.5) as f64 * ns,
        percentile(&lateness, 0.99) as f64 * ns,
        *lateness.last().unwrap_or(&0) as f64 * ns
    );
    i32::from(wrong != 0 || early != 0)
}

static CP_PARK: AtomicU32 = AtomicU32::new(0);
static CP_READY: AtomicU32 = AtomicU32::new(0);
static CP_STOP: AtomicU32 = AtomicU32::new(0);
static CP_A: AtomicU64Counter = AtomicU64Counter::new();
static CP_B: AtomicU64Counter = AtomicU64Counter::new();

/// A counter bumped by a compute loop (no syscall anywhere in the loop).
struct AtomicU64Counter(std::sync::atomic::AtomicU64);

impl AtomicU64Counter {
    const fn new() -> Self {
        Self(std::sync::atomic::AtomicU64::new(0))
    }
    fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// `FUTEX_WAIT_BITSET_PRIVATE` with an absolute `CLOCK_MONOTONIC` deadline:
/// a wait EL1 forwards, so the host parks the thread.
fn futex_wait_bitset_until(word: &AtomicU32, expected: u32, after: Duration) -> i64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    let total_ns = now.tv_nsec as u128 + after.subsec_nanos() as u128;
    let ts = libc::timespec {
        tv_sec: now.tv_sec + after.as_secs() as i64 + (total_ns / 1_000_000_000) as i64,
        tv_nsec: (total_ns % 1_000_000_000) as libc::c_long,
    };
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAIT_BITSET_PRIVATE,
            u64::from(expected),
            &ts as *const libc::timespec as u64,
            0,
            FUTEX_BITSET_MATCH_ANY,
        )
    }
}

/// Two compute loops sharing the main thread's vCPU: the sibling parks in a
/// host-served wait, the main thread wakes it in-guest (so it is queued on
/// the main thread's vCPU) and both then count for `ms` without a syscall.
fn compute_pair(ms: u64) -> i32 {
    // Both on guest CPU 0: since EL1 increment 2 an idle vCPU installs a
    // published address space itself and would take the woken sibling, so
    // the pair shares a vCPU only when pinned.
    let b = std::thread::spawn(|| {
        pin(0);
        CP_READY.store(1, Ordering::Release);
        let _ = futex_wake(&CP_READY, 1);
        while CP_PARK.load(Ordering::Acquire) == 0 {
            let _ = futex_wait_bitset_until(&CP_PARK, 0, Duration::from_secs(20));
        }
        while CP_STOP.load(Ordering::Relaxed) == 0 {
            CP_B.bump();
        }
    });
    pin(0);
    if !wait_until_changed(&CP_READY, 0, Duration::from_secs(10)) {
        println!("compute-pair sibling never started");
        return 1;
    }
    // Let the sibling reach its host-served wait.
    sleep_ms(30);
    CP_PARK.store(1, Ordering::Release);
    let _ = futex_wake(&CP_PARK, 1);
    let freq = cntfrq();
    let start = cntvct();
    let window = freq * ms / 1000;
    let mut b_started_ticks = None;
    loop {
        CP_A.bump();
        let now = cntvct();
        if b_started_ticks.is_none() && CP_B.get() != 0 {
            b_started_ticks = Some(now - start);
        }
        if now - start >= window {
            break;
        }
    }
    CP_STOP.store(1, Ordering::Relaxed);
    let (a, bcount) = (CP_A.get(), CP_B.get());
    b.join().expect("compute-pair sibling exits");
    let ns = ns_per_tick();
    println!(
        "compute-pair ms={ms} a_count={a} b_count={bcount} b_first_ms={:.3}",
        b_started_ticks.map_or(-1.0, |t| t as f64 * ns / 1e6)
    );
    i32::from(a == 0 || bcount == 0)
}

static IDLE_WORDS: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static IDLE_MAIN: AtomicU32 = AtomicU32::new(0);

/// Every thread blocked: four in untimed waits, the main thread in one timed
/// wait of `ms`. The carrier has nothing to run for `ms`.
fn idle_carrier(ms: u64) -> i32 {
    let mut threads = Vec::new();
    for word in &IDLE_WORDS {
        threads.push(std::thread::spawn(move || {
            while word.load(Ordering::Acquire) == 0 {
                let _ = futex_wait(word, 0);
            }
        }));
    }
    // Let every sibling park.
    sleep_ms(20);
    let t0 = cntvct();
    let rc = futex_wait_timeout(&IDLE_MAIN, 0, Duration::from_millis(ms));
    let elapsed_ms = (cntvct() - t0) as f64 * ns_per_tick() / 1e6;
    for word in &IDLE_WORDS {
        word.store(1, Ordering::Release);
        let _ = futex_wake(word, 1);
    }
    for thread in threads {
        thread.join().expect("idle sibling exits");
    }
    println!("idle-carrier ms={ms} result={rc} elapsed_ms={elapsed_ms:.3}");
    i32::from(rc != -ETIMEDOUT)
}

static WS_READY: AtomicU32 = AtomicU32::new(0);
static WS_DONE: AtomicU32 = AtomicU32::new(0);
static WS_PARK: AtomicU32 = AtomicU32::new(0);
static WS_HANDLED: AtomicU32 = AtomicU32::new(0);
static WS_EINTR: AtomicU32 = AtomicU32::new(0);
static WS_WOKE_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

extern "C" fn on_ws_signal(_: libc::c_int) {
    WS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// A thread parked with nothing else to run (its vCPU idles in EL1) is
/// signalled `rounds` times; every wait returns `EINTR` and the handler runs.
fn wfi_signal(rounds: u32) -> i32 {
    install(libc::SIGUSR1, on_ws_signal, 0);
    let worker = std::thread::spawn(move || {
        WORKER_TID.store(gettid(), Ordering::SeqCst);
        for round in 0..rounds {
            WS_READY.store(round + 1, Ordering::Release);
            let _ = futex_wake(&WS_READY, 1);
            let rc = futex_wait(&WS_PARK, 0);
            WS_WOKE_AT.store(cntvct(), Ordering::SeqCst);
            if rc == -EINTR {
                WS_EINTR.fetch_add(1, Ordering::SeqCst);
            }
            WS_DONE.store(round + 1, Ordering::Release);
            let _ = futex_wake(&WS_DONE, 1);
        }
    });
    let limit = Duration::from_secs(5);
    let mut latency = Vec::with_capacity(rounds as usize);
    for round in 0..rounds {
        if !wait_until_changed(&WS_READY, round, limit) {
            println!("wfi-signal round={round} worker never parked");
            return 1;
        }
        // Past the idle vCPU's spin: it is in WFI.
        sleep_ms(2);
        let t0 = cntvct();
        let rc = tgkill(WORKER_TID.load(Ordering::SeqCst), libc::SIGUSR1);
        if rc != 0 {
            println!("wfi-signal round={round} tgkill={rc}");
            return 1;
        }
        if !wait_until_changed(&WS_DONE, round, limit) {
            println!("wfi-signal round={round} the signal never reached the parked thread");
            return 1;
        }
        latency.push(WS_WOKE_AT.load(Ordering::SeqCst).saturating_sub(t0));
    }
    worker.join().expect("wfi-signal worker exits");
    latency.sort_unstable();
    let ns = ns_per_tick();
    let eintr = WS_EINTR.load(Ordering::SeqCst);
    let handled = WS_HANDLED.load(Ordering::SeqCst);
    println!(
        "wfi-signal rounds={rounds} eintr={eintr} handled={handled} wake_p50_us={:.1} \
         wake_max_us={:.1}",
        percentile(&latency, 0.5) as f64 * ns / 1e3,
        *latency.last().unwrap_or(&0) as f64 * ns / 1e3
    );
    i32::from(eintr != rounds || handled != rounds)
}

static PS_SYNC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static PS_ASYNC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static PS_SPIN_TID: AtomicI32 = AtomicI32::new(0);
static PS_SPINNING: AtomicU32 = AtomicU32::new(0);
static PS_SCRATCH: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_ps_sync(_: libc::c_int, _: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let context = context as *const libc::ucontext_t;
    PS_SYNC.store(unsafe { (*context).uc_mcontext.pstate }, Ordering::SeqCst);
}

extern "C" fn on_ps_async(_: libc::c_int, _: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let context = context as *const libc::ucontext_t;
    PS_ASYNC.store(unsafe { (*context).uc_mcontext.pstate }, Ordering::SeqCst);
}

fn install_siginfo(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(signal, &action, std::ptr::null_mut()),
            0,
            "sigaction"
        );
    }
}

/// The PSTATE a handler finds in its `ucontext` for a signal taken at a
/// syscall boundary and for one that interrupts guest computation after
/// in-guest futex service (the EL1 return path) ran on that thread.
fn pstate_mode() -> i32 {
    install_siginfo(libc::SIGUSR1, on_ps_sync);
    install_siginfo(libc::SIGUSR2, on_ps_async);
    let rc = tgkill(gettid(), libc::SIGUSR1);
    let spinner = std::thread::spawn(|| {
        PS_SPIN_TID.store(gettid(), Ordering::SeqCst);
        // In-guest futex service: wakes with no waiter return 0 at EL1.
        for _ in 0..16 {
            let _ = futex_wake(&PS_SCRATCH, 1);
        }
        PS_SPINNING.store(1, Ordering::Release);
        let start = cntvct();
        let limit = cntfrq() * 10;
        while PS_ASYNC.load(Ordering::SeqCst) == u64::MAX && cntvct() - start < limit {
            std::hint::spin_loop();
        }
    });
    while PS_SPINNING.load(Ordering::Acquire) == 0 {
        std::hint::spin_loop();
    }
    sleep_ms(5);
    let rc2 = tgkill(PS_SPIN_TID.load(Ordering::SeqCst), libc::SIGUSR2);
    spinner.join().expect("pstate spinner exits");
    let sync = PS_SYNC.load(Ordering::SeqCst);
    let async_ = PS_ASYNC.load(Ordering::SeqCst);
    println!(
        "pstate tgkill={rc}/{rc2} sync_daif={:#x} async_daif={:#x} sync_el={} async_el={}",
        sync & 0x3c0,
        async_ & 0x3c0,
        sync & 0xf,
        async_ & 0xf
    );
    i32::from(sync == u64::MAX || async_ == u64::MAX)
}

// ---------------------------------------------------------------------------
// EL1 plan 1d modes

fn pipe_pair() -> (i32, i32) {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    (fds[0], fds[1])
}

fn read_byte(fd: i32) -> i64 {
    let mut byte = 0u8;
    unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) as i64 }
}

fn write_byte(fd: i32) -> i64 {
    let byte = 1u8;
    unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) as i64 }
}

fn pipe_pingpong(iters: usize) -> i32 {
    const WARMUP: usize = 200;
    let (to_b_read, to_b_write) = pipe_pair();
    let (to_a_read, to_a_write) = pipe_pair();
    let total = WARMUP + iters;
    let b = std::thread::spawn(move || {
        for _ in 0..total {
            if read_byte(to_b_read) != 1 || write_byte(to_a_write) != 1 {
                return false;
            }
        }
        true
    });
    let mut samples = Vec::with_capacity(iters);
    for i in 0..total {
        let t0 = cntvct();
        if write_byte(to_b_write) != 1 || read_byte(to_a_read) != 1 {
            println!("pipe-pingpong failed at {i}");
            return 1;
        }
        if i >= WARMUP {
            samples.push(cntvct() - t0);
        }
    }
    if !b.join().expect("pipe partner exits") {
        println!("pipe-pingpong partner failed");
        return 1;
    }
    let ns = ns_per_tick();
    samples.sort_unstable();
    println!(
        "pipe-pingpong iters={iters} rt_p50_ns={:.0} rt_p99_ns={:.0}",
        percentile(&samples, 0.5) as f64 * ns,
        percentile(&samples, 0.99) as f64 * ns
    );
    0
}

fn socket_pair() -> (i32, i32) {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair");
    (fds[0], fds[1])
}

/// `pipe_pingpong` over `AF_UNIX` socketpairs (host-served descriptors).
fn sock_pingpong(iters: usize, pinned: bool) -> i32 {
    const WARMUP: usize = 200;
    // Each pair: `.0` is the end A uses, `.1` the end B uses.
    let to_b = socket_pair();
    let to_a = socket_pair();
    let total = WARMUP + iters;
    let b = std::thread::spawn(move || {
        if pinned {
            pin(0);
        }
        for _ in 0..total {
            if read_byte(to_b.1) != 1 || write_byte(to_a.1) != 1 {
                return false;
            }
        }
        true
    });
    if pinned {
        pin(0);
    }
    let mut samples = Vec::with_capacity(iters);
    for i in 0..total {
        let t0 = cntvct();
        if write_byte(to_b.0) != 1 || read_byte(to_a.0) != 1 {
            println!("sock-pingpong failed at {i}");
            return 1;
        }
        if i >= WARMUP {
            samples.push(cntvct() - t0);
        }
    }
    if !b.join().expect("sock partner exits") {
        println!("sock-pingpong partner failed");
        return 1;
    }
    let ns = ns_per_tick();
    samples.sort_unstable();
    println!(
        "sock-pingpong iters={iters} pinned={pinned} rt_p50_ns={:.0} rt_p99_ns={:.0}",
        percentile(&samples, 0.5) as f64 * ns,
        percentile(&samples, 0.99) as f64 * ns
    );
    0
}

/// One direction of `epoll_pingpong`: an eventfd and the epoll that watches
/// it (`EPOLLIN`, level-triggered, data = the eventfd).
#[derive(Clone, Copy)]
struct EpollEventfd {
    efd: i32,
    ep: i32,
}

fn epoll_eventfd() -> EpollEventfd {
    let efd = unsafe { libc::eventfd(0, 0) };
    assert!(efd >= 0, "eventfd");
    let ep = unsafe { libc::epoll_create1(0) };
    assert!(ep >= 0, "epoll_create1");
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: efd as u64,
    };
    assert_eq!(
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev) },
        0,
        "epoll_ctl"
    );
    EpollEventfd { efd, ep }
}

fn epoll_post(c: EpollEventfd) -> bool {
    let one = 1u64;
    unsafe { libc::write(c.efd, (&one as *const u64).cast(), 8) == 8 }
}

/// Block in `epoll_wait` (bounded at 5 s) for the one event, then consume it.
fn epoll_take(c: EpollEventfd) -> bool {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];
    let n = unsafe { libc::epoll_wait(c.ep, out.as_mut_ptr(), 2, 5_000) };
    if n != 1 || out[0].u64 != c.efd as u64 {
        return false;
    }
    let mut value = 0u64;
    unsafe { libc::read(c.efd, (&mut value as *mut u64).cast(), 8) == 8 }
}

/// `epoll-pingpong <iters>`: libuv's MessagePort shape. Two threads, each
/// with its own epoll over its own eventfd; A posts B's eventfd and blocks in
/// `epoll_wait` until B posts A's. Every turn is an eventfd write, an
/// `epoll_wait` that blocks, and an eventfd read, all on in-zone objects.
fn epoll_pingpong(iters: usize) -> i32 {
    const WARMUP: usize = 200;
    let to_b = epoll_eventfd();
    let to_a = epoll_eventfd();
    let total = WARMUP + iters;
    let b = std::thread::spawn(move || {
        for _ in 0..total {
            if !epoll_take(to_b) || !epoll_post(to_a) {
                return false;
            }
        }
        true
    });
    let mut samples = Vec::with_capacity(iters);
    for i in 0..total {
        let t0 = cntvct();
        if !epoll_post(to_b) || !epoll_take(to_a) {
            println!("epoll-pingpong failed at {i}");
            return 1;
        }
        if i >= WARMUP {
            samples.push(cntvct() - t0);
        }
    }
    if !b.join().expect("epoll partner exits") {
        println!("epoll-pingpong partner failed");
        return 1;
    }
    let ns = ns_per_tick();
    samples.sort_unstable();
    println!(
        "epoll-pingpong iters={iters} rt_p50_ns={:.0} rt_p99_ns={:.0}",
        percentile(&samples, 0.5) as f64 * ns,
        percentile(&samples, 0.99) as f64 * ns
    );
    0
}

static PC_STOP: AtomicU32 = AtomicU32::new(0);
static PC_B: AtomicI64 = AtomicI64::new(0);

/// `pipe-compute <ms>`: both threads pinned to guest CPU 0. B blocks in a
/// host-served pipe `read`; A writes the byte that completes it, then
/// computes without a syscall for `<ms>`. B must still run: its completed
/// read is a thread that needs its executor, queued on the vCPU A holds, and
/// only the in-guest scheduler's slice can give it that vCPU.
fn pipe_compute(ms: u64) -> i32 {
    let (read_fd, write_fd) = pipe_pair();
    let b = std::thread::spawn(move || {
        pin(0);
        if read_byte(read_fd) != 1 {
            return;
        }
        while PC_STOP.load(Ordering::Relaxed) == 0 {
            PC_B.fetch_add(1, Ordering::Relaxed);
        }
    });
    pin(0);
    sleep_ms(30);
    if write_byte(write_fd) != 1 {
        println!("pipe-compute write failed");
        return 1;
    }
    let freq = cntfrq();
    let start = cntvct();
    let window = freq * ms / 1000;
    let mut a = 0u64;
    let mut b_first = None;
    loop {
        a += 1;
        let now = cntvct();
        if b_first.is_none() && PC_B.load(Ordering::Relaxed) != 0 {
            b_first = Some(now - start);
        }
        if now - start >= window {
            break;
        }
    }
    PC_STOP.store(1, Ordering::Relaxed);
    b.join().expect("pipe-compute sibling exits");
    let bcount = PC_B.load(Ordering::Relaxed);
    println!(
        "pipe-compute ms={ms} a_count={a} b_count={bcount} b_first_ms={:.3}",
        b_first.map_or(-1.0, |t| t as f64 * ns_per_tick() / 1e6)
    );
    i32::from(bcount == 0)
}

/// One process's pinned futex ping-pong for `two-process`: returns the round
/// trips it completed.
fn pinned_pair(iters: usize) -> usize {
    static TURN2: AtomicU32 = AtomicU32::new(0);
    let b = std::thread::spawn(move || {
        pin(1);
        loop {
            while TURN2.load(Ordering::Acquire) == 0 {
                let _ = futex_wait(&TURN2, 0);
            }
            if TURN2.load(Ordering::Acquire) == 2 {
                return;
            }
            TURN2.store(0, Ordering::Release);
            let _ = futex_wake(&TURN2, 1);
        }
    });
    pin(0);
    let mut done = 0;
    for _ in 0..iters {
        TURN2.store(1, Ordering::Release);
        let _ = futex_wake(&TURN2, 1);
        while TURN2.load(Ordering::Acquire) == 1 {
            let _ = futex_wait(&TURN2, 1);
        }
        done += 1;
    }
    TURN2.store(2, Ordering::Release);
    let _ = futex_wake(&TURN2, 1);
    b.join().expect("pair partner exits");
    done
}

fn two_process(iters: usize) -> i32 {
    // Both processes start their ping-pong together (a two-pipe rendezvous
    // after the fork), so their threads share the two pinned vCPUs rather
    // than running one after the other.
    let mut ready = [0 as libc::c_int; 2];
    let mut go = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0 || unsafe { libc::pipe(go.as_mut_ptr()) } != 0
    {
        println!("pipe failed");
        return 1;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("fork failed");
        return 1;
    }
    let mut byte = 0u8;
    let byte_ptr = std::ptr::addr_of_mut!(byte).cast::<libc::c_void>();
    let rendezvous = if pid == 0 {
        unsafe { libc::write(ready[1], byte_ptr, 1) == 1 && libc::read(go[0], byte_ptr, 1) == 1 }
    } else {
        unsafe { libc::read(ready[0], byte_ptr, 1) == 1 && libc::write(go[1], byte_ptr, 1) == 1 }
    };
    if !rendezvous {
        println!("two-process rendezvous failed");
        return 1;
    }
    let started = Instant::now();
    let done = pinned_pair(iters);
    let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
    if pid == 0 {
        println!("two-process child round_trips={done} ms={elapsed_ms:.1}");
        unsafe { libc::_exit(if done == iters { 0 } else { 1 }) };
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let child_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("two-process parent round_trips={done} ms={elapsed_ms:.1} child_ok={child_ok}");
    if done == iters && child_ok { 0 } else { 1 }
}

const PAGE: usize = 16384;
const WORDS: usize = 64;

/// Two processes, each with more threads than guest CPUs, under stage-1
/// pauses (the editor), fork COW arming (the forker) and vfork (shared MM).
fn mm_occupancy(forks: usize) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("fork failed");
        return 1;
    }
    let role = if pid == 0 { "child" } else { "parent" };
    let ok = mm_occupancy_process(role, forks);
    if pid == 0 {
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let child_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("mm-occupancy child_ok={child_ok}");
    if ok && child_ok { 0 } else { 1 }
}

fn mm_occupancy_process(role: &str, forks: usize) -> bool {
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as usize;
    let writers = (2 * cpus).max(4) & !1;
    let region_len = match writers.checked_mul(PAGE) {
        Some(len) if len > 0 => len,
        _ => {
            println!("mm-occupancy {role} invalid writers {writers}");
            return false;
        }
    };
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            region_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        println!("mm-occupancy {role} mmap failed");
        return false;
    }
    let base = region as usize;
    let stop = std::sync::Arc::new(AtomicU32::new(0));
    let mismatches = std::sync::Arc::new(AtomicU32::new(0));
    let turns: std::sync::Arc<Vec<AtomicU32>> =
        std::sync::Arc::new((0..writers / 2).map(|_| AtomicU32::new(0)).collect());
    let mut threads = Vec::new();
    for id in 0..writers {
        let (stop, mismatches, turns) = (stop.clone(), mismatches.clone(), turns.clone());
        threads.push(std::thread::spawn(move || {
            let page = (base + id * PAGE) as *mut u64;
            let turn = &turns[id / 2];
            let mine = (id % 2) as u32;
            let mut round = 0u64;
            while stop.load(Ordering::Acquire) == 0 {
                round += 1;
                let value = ((id as u64) << 40) | round;
                for word in 0..WORDS {
                    unsafe { page.add(word).write_volatile(value) };
                }
                for word in 0..WORDS {
                    if unsafe { page.add(word).read_volatile() } != value {
                        mismatches.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Hand the pair's turn over and wait for it back (bounded).
                if turn.load(Ordering::Acquire) % 2 == mine {
                    turn.fetch_add(1, Ordering::AcqRel);
                    futex_wake(turn, 1);
                } else {
                    let seen = turn.load(Ordering::Acquire);
                    if seen % 2 != mine {
                        futex_wait_timeout(turn, seen, Duration::from_millis(2));
                    }
                }
            }
            // Release a partner parked on the turn.
            turn.fetch_add(1, Ordering::AcqRel);
            futex_wake(turn, 1);
        }));
    }
    let editor_stop = stop.clone();
    let editor = std::thread::spawn(move || {
        let mut edits = 0u64;
        let mut edit_failures = 0u64;
        let mut edit_errors = Vec::new();
        while editor_stop.load(Ordering::Acquire) == 0 {
            let len = 8 * PAGE;
            let scratch = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if scratch == libc::MAP_FAILED {
                edit_failures += 1;
                if edit_errors.len() < 8 {
                    edit_errors.push(format!(
                        "mmap:{}",
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                    ));
                }
                continue;
            }
            for page in 0..8 {
                unsafe {
                    (scratch as *mut u8)
                        .add(page * PAGE)
                        .write_volatile(page as u8)
                };
            }
            let rc_ro = unsafe { libc::mprotect(scratch, len, libc::PROT_READ) };
            if rc_ro != 0 && edit_errors.len() < 8 {
                edit_errors.push(format!(
                    "mprotect_ro:{}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            let rc_rw = unsafe { libc::mprotect(scratch, len, libc::PROT_READ | libc::PROT_WRITE) };
            if rc_rw != 0 && edit_errors.len() < 8 {
                edit_errors.push(format!(
                    "mprotect_rw:{}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            let rc_madv = unsafe { libc::madvise(scratch, len, libc::MADV_DONTNEED) };
            if rc_madv != 0 && edit_errors.len() < 8 {
                edit_errors.push(format!(
                    "madvise:{}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            let rc_unmap = unsafe { libc::munmap(scratch, len) };
            if rc_unmap != 0 && edit_errors.len() < 8 {
                edit_errors.push(format!(
                    "munmap:{}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            if rc_ro != 0 || rc_rw != 0 || rc_madv != 0 || rc_unmap != 0 {
                edit_failures += 1;
            } else {
                edits += 1;
            }
        }
        (edits, edit_failures, edit_errors)
    });
    let mut forked = 0;
    let mut snapshot_changes = 0;
    let mut child_failures = 0;
    let mut snapshot_buf = vec![0u64; writers];
    for _ in 0..forks {
        let child = unsafe { libc::fork() };
        if child == 0 {
            // A fork child's memory is a copy as of the fork: the parent's
            // writers keep writing, and none of it may show up here.
            let before = snapshot_buf.as_mut_slice();
            for (id, slot) in before.iter_mut().enumerate() {
                *slot = unsafe { ((base + id * PAGE) as *const u64).read_volatile() };
            }
            let spin = Instant::now();
            while spin.elapsed() < Duration::from_micros(500) {
                std::hint::spin_loop();
            }
            let mut changed = false;
            for (id, slot) in before.iter().enumerate() {
                let after = unsafe { ((base + id * PAGE) as *const u64).read_volatile() };
                if after != *slot {
                    changed = true;
                    break;
                }
            }
            unsafe { libc::_exit(if changed { 3 } else { 0 }) };
        }
        if child < 0 {
            child_failures += 1;
            continue;
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited != child {
            child_failures += 1;
        } else if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 3 {
            snapshot_changes += 1;
        } else if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
            child_failures += 1;
        }
        // The vfork child only `_exit`s: it shares this stack and MM until
        // then, which is the shape (posix_spawn, Go os/exec) under test.
        #[allow(deprecated)]
        let vchild = unsafe { libc::vfork() };
        if vchild == 0 {
            unsafe { libc::_exit(0) };
        }
        if vchild > 0 {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(vchild, &mut status, 0) };
            if waited != vchild || !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                child_failures += 1;
            }
        } else {
            child_failures += 1;
        }
        forked += 1;
    }
    stop.store(1, Ordering::Release);
    let mut join_failures = 0usize;
    for thread in threads {
        if thread.join().is_err() {
            join_failures += 1;
        }
    }
    let (edits, edit_failures, edit_errors) = match editor.join() {
        Ok((e, ef, errors)) => (e, ef, errors),
        Err(_) => {
            join_failures += 1;
            (0, 1, vec!["editor_join:0".to_string()])
        }
    };
    let edit_errors = if edit_errors.is_empty() {
        "none".to_string()
    } else {
        edit_errors.join(",")
    };
    let torn = mismatches.load(Ordering::Relaxed);
    let unmap_rc = unsafe { libc::munmap(region, region_len) };
    let unmap_ok = unmap_rc == 0;
    if !unmap_ok {
        println!("mm-occupancy {role} munmap failed rc={unmap_rc}");
    }
    let ok = forked == forks
        && edits > 0
        && edit_failures == 0
        && torn == 0
        && snapshot_changes == 0
        && child_failures == 0
        && join_failures == 0
        && unmap_ok;
    println!(
        "mm-occupancy {role} writers={writers} forks={forked} edits={edits} edit_failures={edit_failures} edit_errors={edit_errors} torn={torn} \
         snapshot_changes={snapshot_changes} child_failures={child_failures} join_failures={join_failures} ok={ok}"
    );
    ok
}

// ---------------------------------------------------------------------------
// EL1 increment 2: anonymous memory first-touch

fn poll_read_byte(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
        return false;
    }
    let mut byte = 0u8;
    let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
    n == 1
}

fn write_signal_byte(fd: libc::c_int, byte: u8) -> bool {
    let n = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    n == 1
}

fn first_touch_process(
    role: &str,
    base: usize,
    pages: usize,
    page_size: usize,
    write_fd: libc::c_int,
    read_fd: libc::c_int,
) -> bool {
    let words_per_page = page_size / std::mem::size_of::<u64>();
    let mut zero_mismatches = 0u64;
    for page_idx in 0..pages {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        for w in 0..words_per_page {
            let val = unsafe { page_ptr.add(w).read_volatile() };
            if val != 0 {
                zero_mismatches += 1;
            }
        }
    }

    let role_magic: u64 = if role == "child" {
        0x4348_494c_4400_0000 // 'CHILD'
    } else {
        0x5041_5245_4e54_0000 // 'PARENT'
    };
    for page_idx in 0..pages {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let page_val = role_magic | (page_idx as u64);
        for w in 0..words_per_page {
            let val = page_val ^ ((w as u64) << 32);
            unsafe { page_ptr.add(w).write_volatile(val) };
        }
    }

    let mut immediate_mismatches = 0u64;
    for page_idx in 0..pages {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let page_val = role_magic | (page_idx as u64);
        for w in 0..words_per_page {
            let expected = page_val ^ ((w as u64) << 32);
            let seen = unsafe { page_ptr.add(w).read_volatile() };
            if seen != expected {
                immediate_mismatches += 1;
            }
        }
    }

    // Rendezvous 1: signal write completion to peer and wait for peer's signal.
    const TIMEOUT_MS: libc::c_int = 10_000;
    if !write_signal_byte(write_fd, b'W') || !poll_read_byte(read_fd, TIMEOUT_MS) {
        return false;
    }

    // Post-write check: preserve each process's values until both completed writes, then check again.
    let mut post_mismatches = 0u64;
    for page_idx in 0..pages {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let page_val = role_magic | (page_idx as u64);
        for w in 0..words_per_page {
            let expected = page_val ^ ((w as u64) << 32);
            let seen = unsafe { page_ptr.add(w).read_volatile() };
            if seen != expected {
                post_mismatches += 1;
            }
        }
    }

    // Rendezvous 2: signal post-check completion to peer and wait for peer's signal.
    if !write_signal_byte(write_fd, b'D') || !poll_read_byte(read_fd, TIMEOUT_MS) {
        return false;
    }

    zero_mismatches == 0 && immediate_mismatches == 0 && post_mismatches == 0
}

fn first_touch(pages: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("first-touch invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if pages == 0 || pages > 65_536 || !page_size.is_multiple_of(8) {
        println!("first-touch invalid pages={pages} page_size={page_size}");
        return 1;
    }
    let len = match pages.checked_mul(page_size) {
        Some(len) if len > 0 => len,
        _ => {
            println!("first-touch overflowing pages={pages} page_size={page_size}");
            return 1;
        }
    };

    // Bound the entire fixture, including waitpid and a stuck peer. The child
    // arms its own deadline because fork does not inherit an alarm timer.
    unsafe { libc::alarm(60) };
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        println!("first-touch mmap failed");
        return 1;
    }
    let base = region as usize;

    let mut p2c = [0 as libc::c_int; 2];
    let mut c2p = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0 {
        println!("first pipe failed");
        unsafe { libc::munmap(region, len) };
        return 1;
    }
    if unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0 {
        println!("second pipe failed");
        unsafe {
            libc::close(p2c[0]);
            libc::close(p2c[1]);
            libc::munmap(region, len);
        }
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("fork failed");
        unsafe {
            libc::close(p2c[0]);
            libc::close(p2c[1]);
            libc::close(c2p[0]);
            libc::close(c2p[1]);
            libc::munmap(region, len);
        };
        return 1;
    }

    if pid == 0 {
        unsafe {
            libc::close(p2c[1]);
            libc::close(c2p[0]);
        }
        unsafe { libc::alarm(60) };
        let (write_fd, read_fd) = (c2p[1], p2c[0]);
        let ok = first_touch_process("child", base, pages, page_size, write_fd, read_fd);
        unsafe {
            libc::close(write_fd);
            libc::close(read_fd);
            libc::munmap(region, len);
        }
        println!("first-touch child pages={pages} ok={ok}");
        use std::io::Write;
        let flushed = std::io::stdout().flush().is_ok();
        unsafe { libc::_exit(if ok && flushed { 0 } else { 1 }) };
    }

    unsafe {
        libc::close(p2c[0]);
        libc::close(c2p[1]);
    }
    let (write_fd, read_fd) = (p2c[1], c2p[0]);
    let parent_ok = first_touch_process("parent", base, pages, page_size, write_fd, read_fd);
    unsafe {
        libc::close(write_fd);
        libc::close(read_fd);
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let child_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    unsafe { libc::munmap(region, len) };
    println!("first-touch parent pages={pages} child_ok={child_ok} ok={parent_ok}");
    if parent_ok && child_ok { 0 } else { 1 }
}

fn fork_cow_worker(
    base: usize,
    pages: usize,
    page_size: usize,
    role_magic: u64,
    worker_id: usize,
    workers: usize,
    round: usize,
) -> Option<u64> {
    pin((worker_id % 4) as u32);
    let start_page = (worker_id * pages) / workers;
    let end_page = ((worker_id + 1) * pages) / workers;
    let words_per_page = page_size / std::mem::size_of::<u64>();

    for page_idx in start_page..end_page {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let page_val =
            role_magic | ((round as u64) << 32) | ((worker_id as u64) << 16) | (page_idx as u64);
        for w in 0..words_per_page {
            let val = page_val ^ ((w as u64) << 48);
            unsafe { page_ptr.add(w).write_volatile(val) };
        }
    }

    for page_idx in start_page..end_page {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let page_val =
            role_magic | ((round as u64) << 32) | ((worker_id as u64) << 16) | (page_idx as u64);
        for w in 0..words_per_page {
            let expected = page_val ^ ((w as u64) << 48);
            let seen = unsafe { page_ptr.add(w).read_volatile() };
            if seen != expected {
                return None;
            }
        }
    }
    // Pages this worker wrote after the fork and read back intact.
    Some((end_page - start_page) as u64)
}

/// Returns the pages this process wrote after the fork and verified intact
/// (each is a COW break against the peer), or `None` on any failure.
fn fork_cow_process(
    role: &str,
    base: usize,
    pages: usize,
    page_size: usize,
    round: usize,
    write_fd: libc::c_int,
    read_fd: libc::c_int,
) -> Option<u64> {
    let role_magic: u64 = if role == "child" {
        0x4348_494C_0000_0000 // 'CHIL'
    } else {
        0x5041_5245_0000_0000 // 'PARE'
    };
    const WORKERS: usize = 4;
    let mut handles = Vec::with_capacity(WORKERS);
    for w in 0..WORKERS {
        handles.push(std::thread::spawn(move || {
            fork_cow_worker(base, pages, page_size, role_magic, w, WORKERS, round)
        }));
    }
    let mut verified_pages = 0u64;
    for h in handles {
        verified_pages += h.join().ok().flatten()?;
    }

    const TIMEOUT_MS: libc::c_int = 10_000;
    if !write_signal_byte(write_fd, b'W') || !poll_read_byte(read_fd, TIMEOUT_MS) {
        return None;
    }

    // Verify after peer wrote that our memory is still intact
    let words_per_page = page_size / std::mem::size_of::<u64>();
    for page_idx in 0..pages {
        let page_ptr = (base + page_idx * page_size) as *mut u64;
        let worker_id = (page_idx * WORKERS) / pages;
        let page_val =
            role_magic | ((round as u64) << 32) | ((worker_id as u64) << 16) | (page_idx as u64);
        for w in 0..words_per_page {
            let expected = page_val ^ ((w as u64) << 48);
            let seen = unsafe { page_ptr.add(w).read_volatile() };
            if seen != expected {
                return None;
            }
        }
    }

    if !write_signal_byte(write_fd, b'D') || !poll_read_byte(read_fd, TIMEOUT_MS) {
        return None;
    }
    Some(verified_pages)
}

/// Send one observed count to the peer as 8 little-endian bytes.
fn write_count(fd: libc::c_int, count: u64) -> bool {
    let bytes = count.to_le_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    n == bytes.len() as isize
}

/// Receive a count written by `write_count`, bounded by `timeout_ms`.
fn poll_read_count(fd: libc::c_int, timeout_ms: libc::c_int) -> Option<u64> {
    let mut bytes = [0u8; 8];
    let mut have = 0;
    while have < bytes.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            return None;
        }
        let n = unsafe { libc::read(fd, bytes[have..].as_mut_ptr().cast(), bytes.len() - have) };
        if n <= 0 {
            return None;
        }
        have += n as usize;
    }
    Some(u64::from_le_bytes(bytes))
}

fn fork_cow(forks: usize, pages: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("fork-cow invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if pages == 0 || pages > 65_536 || forks == 0 {
        println!("fork-cow invalid parameters: forks={forks} pages={pages}");
        return 1;
    }
    let len = match pages.checked_mul(page_size) {
        Some(len) if len > 0 => len,
        _ => {
            println!("fork-cow overflowing len: pages={pages}");
            return 1;
        }
    };

    unsafe { libc::alarm(120) };
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        println!("fork-cow mmap failed");
        return 1;
    }
    let base = region as usize;

    let words_per_page = page_size / std::mem::size_of::<u64>();
    let mut parent_verified = 0u64;
    let mut child_verified = 0u64;
    for round in 0..forks {
        // Pre-populate memory so all pages are resident before fork
        for page_idx in 0..pages {
            let page_ptr = (base + page_idx * page_size) as *mut u64;
            let val = 0xAA00_0000_0000_0000u64 | ((round as u64) << 32) | (page_idx as u64);
            for w in 0..words_per_page {
                unsafe { page_ptr.add(w).write_volatile(val ^ ((w as u64) << 48)) };
            }
        }

        let mut p2c = [0 as libc::c_int; 2];
        let mut c2p = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0
        {
            println!("pipe failed round={round}");
            unsafe { libc::munmap(region, len) };
            return 1;
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("fork failed round={round}");
            unsafe {
                libc::close(p2c[0]);
                libc::close(p2c[1]);
                libc::close(c2p[0]);
                libc::close(c2p[1]);
                libc::munmap(region, len);
            }
            return 1;
        }

        if pid == 0 {
            unsafe {
                libc::close(p2c[1]);
                libc::close(c2p[0]);
                libc::alarm(60);
            }
            let verified = fork_cow_process("child", base, pages, page_size, round, c2p[1], p2c[0]);
            // Report the child's own observation to the parent; a failed child
            // reports nothing and exits non-zero.
            let ok = verified.is_some_and(|count| write_count(c2p[1], count));
            unsafe {
                libc::close(c2p[1]);
                libc::close(p2c[0]);
                libc::munmap(region, len);
            }
            use std::io::Write;
            let _ = std::io::stdout().flush();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }

        unsafe {
            libc::close(p2c[0]);
            libc::close(c2p[1]);
        }
        let parent_pages =
            fork_cow_process("parent", base, pages, page_size, round, p2c[1], c2p[0]);
        let child_pages = if parent_pages.is_some() {
            poll_read_count(c2p[0], 10_000)
        } else {
            None
        };
        unsafe {
            libc::close(p2c[1]);
            libc::close(c2p[0]);
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        let child_exit_ok =
            waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        let parent_ok = parent_pages.is_some();
        let child_ok = child_exit_ok && child_pages.is_some();
        if !parent_ok || !child_ok {
            println!("fork-cow failed round={round} parent_ok={parent_ok} child_ok={child_ok}");
            unsafe { libc::munmap(region, len) };
            return 1;
        }
        parent_verified += parent_pages.unwrap_or(0);
        child_verified += child_pages.unwrap_or(0);
    }

    unsafe { libc::munmap(region, len) };
    // Every count below was observed by the process it names: pages written
    // after the fork and read back intact, summed over all rounds. A failure
    // above returns before any of these lines exist.
    println!(
        "fork-cow parent writers=4 forks={forks} pages={pages} verified_pages={parent_verified} ok=true"
    );
    println!(
        "fork-cow child writers=4 forks={forks} pages={pages} verified_pages={child_verified} ok=true"
    );
    println!(
        "fork-cow forks={forks} pages={pages} cow_pages={} isolation_ok=true ok=true",
        parent_verified + child_verified
    );
    0
}

fn mapping_retirement(pages: usize, rounds: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("mapping-retirement invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if pages == 0 || pages > 65_536 || rounds < 2 || rounds > 32 {
        println!("mapping-retirement invalid pages={pages} rounds={rounds} page_size={page_size}");
        return 1;
    }
    let Some(len) = pages.checked_mul(page_size).filter(|len| *len > 0) else {
        println!("mapping-retirement overflowing pages={pages} page_size={page_size}");
        return 1;
    };
    unsafe { libc::alarm(90) };

    let mut fixed_base = 0usize;
    for round in 0..rounds {
        let requested = if round == 0 {
            std::ptr::null_mut()
        } else {
            fixed_base as *mut libc::c_void
        };
        let flags =
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | if round == 0 { 0 } else { libc::MAP_FIXED };
        let region = unsafe {
            libc::mmap(
                requested,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            println!("mapping-retirement mmap failed round={round}");
            return 1;
        }
        if round == 0 {
            fixed_base = region as usize;
        } else if region as usize != fixed_base {
            println!(
                "mapping-retirement wrong VA round={round} actual={:#x} expected={fixed_base:#x}",
                region as usize
            );
            unsafe { libc::munmap(region, len) };
            return 1;
        }

        let words = len / core::mem::size_of::<u64>();
        for word in 0..words {
            let value = unsafe { std::ptr::read_volatile((region as *const u64).add(word)) };
            if value != 0 {
                println!(
                    "mapping-retirement stale byte round={round} word={word} value={value:#x}"
                );
                unsafe { libc::munmap(region, len) };
                return 1;
            }
        }
        for page in 0..pages {
            let value = 0xC411_0000_0000_0000u64 ^ ((round as u64) << 32) ^ page as u64;
            unsafe {
                std::ptr::write_volatile(
                    (region as *mut u8).add(page * page_size).cast::<u64>(),
                    value,
                );
            }
        }
        for page in 0..pages {
            let expected = 0xC411_0000_0000_0000u64 ^ ((round as u64) << 32) ^ page as u64;
            let actual = unsafe {
                std::ptr::read_volatile((region as *const u8).add(page * page_size).cast::<u64>())
            };
            if actual != expected {
                println!(
                    "mapping-retirement write mismatch round={round} page={page} actual={actual:#x} expected={expected:#x}"
                );
                unsafe { libc::munmap(region, len) };
                return 1;
            }
        }
        if unsafe { libc::munmap(region, len) } != 0 {
            println!("mapping-retirement munmap failed round={round}");
            return 1;
        }
    }
    println!(
        "mapping-retirement pages={pages} rounds={rounds} base={fixed_base:#x} zero=true writes=true unmaps=true"
    );
    0
}

static PERMISSION_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PERMISSION_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PERMISSION_EXPECTED_ADDR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static PERMISSION_PHASE: AtomicU32 = AtomicU32::new(0);
static PERMISSION_WRITE_FAULTS: AtomicU32 = AtomicU32::new(0);
static PERMISSION_READ_FAULTS: AtomicU32 = AtomicU32::new(0);
static PERMISSION_ERRORS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_permission_segv(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    if sig != libc::SIGSEGV || info.is_null() {
        unsafe { libc::_exit(51) };
    }
    let phase = PERMISSION_PHASE.swap(0, Ordering::SeqCst);
    let fault_addr = unsafe { (*info).si_addr() as usize };
    let expected_addr = PERMISSION_EXPECTED_ADDR.load(Ordering::SeqCst);
    let si_code = unsafe { (*info).si_code };
    if phase == 0 || fault_addr != expected_addr || si_code != 2 {
        PERMISSION_ERRORS.fetch_add(1, Ordering::SeqCst);
    }
    match phase {
        1 => {
            PERMISSION_WRITE_FAULTS.fetch_add(1, Ordering::SeqCst);
        }
        2 => {
            PERMISSION_READ_FAULTS.fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }

    let base = PERMISSION_BASE.load(Ordering::SeqCst);
    let len = PERMISSION_LEN.load(Ordering::SeqCst);
    if base == 0
        || len == 0
        || unsafe {
            libc::mprotect(
                base as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
    {
        unsafe { libc::_exit(52) };
    }
}

fn permission_transitions(pages: usize, rounds: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("permission-transitions invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if pages == 0 || pages > 65_536 || rounds == 0 || rounds > 64 {
        println!(
            "permission-transitions invalid pages={pages} rounds={rounds} page_size={page_size}"
        );
        return 1;
    }
    let Some(len) = pages.checked_mul(page_size).filter(|len| *len > 0) else {
        println!("permission-transitions overflowing pages={pages} page_size={page_size}");
        return 1;
    };
    unsafe { libc::alarm(90) };

    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        println!("permission-transitions mmap failed");
        return 1;
    }
    let base = region as usize;
    PERMISSION_BASE.store(base, Ordering::SeqCst);
    PERMISSION_LEN.store(len, Ordering::SeqCst);
    PERMISSION_PHASE.store(0, Ordering::SeqCst);
    PERMISSION_WRITE_FAULTS.store(0, Ordering::SeqCst);
    PERMISSION_READ_FAULTS.store(0, Ordering::SeqCst);
    PERMISSION_ERRORS.store(0, Ordering::SeqCst);

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_permission_segv as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) } != 0 {
        println!("permission-transitions sigaction failed");
        unsafe { libc::munmap(region, len) };
        return 1;
    }

    let mut expected = Vec::with_capacity(pages);
    for page in 0..pages {
        let value = 0xC411_5045_524D_0000u64 ^ page as u64;
        expected.push(value);
        unsafe {
            std::ptr::write_volatile(
                (region as *mut u8).add(page * page_size).cast::<u64>(),
                value,
            );
        }
    }

    let mut transition_failures = 0u64;
    let mut byte_failures = 0u64;
    for round in 0..rounds {
        if unsafe { libc::mprotect(region, len, libc::PROT_READ) } != 0 {
            transition_failures += 1;
            break;
        }
        for page in 0..pages {
            let actual = unsafe {
                std::ptr::read_volatile((region as *const u8).add(page * page_size).cast::<u64>())
            };
            if actual != expected[page] {
                byte_failures += 1;
            }
        }

        let write_page = round % pages;
        let write_ptr = unsafe {
            (region as *mut u8)
                .add(write_page * page_size)
                .cast::<u64>()
        };
        let write_value = 0xC411_5752_4954_0000u64 ^ round as u64;
        expected[write_page] = write_value;
        PERMISSION_EXPECTED_ADDR.store(write_ptr as usize, Ordering::SeqCst);
        PERMISSION_PHASE.store(1, Ordering::SeqCst);
        unsafe { std::ptr::write_volatile(write_ptr, write_value) };
        if PERMISSION_PHASE.load(Ordering::SeqCst) != 0 {
            transition_failures += 1;
        }

        if unsafe { libc::mprotect(region, len, libc::PROT_NONE) } != 0 {
            transition_failures += 1;
            break;
        }
        let read_page = (round.wrapping_mul(17).wrapping_add(1)) % pages;
        let read_ptr = unsafe {
            (region as *const u8)
                .add(read_page * page_size)
                .cast::<u64>()
        };
        PERMISSION_EXPECTED_ADDR.store(read_ptr as usize, Ordering::SeqCst);
        PERMISSION_PHASE.store(2, Ordering::SeqCst);
        let actual = unsafe { std::ptr::read_volatile(read_ptr) };
        if PERMISSION_PHASE.load(Ordering::SeqCst) != 0 {
            transition_failures += 1;
        }
        if actual != expected[read_page] {
            byte_failures += 1;
        }

        for page in 0..pages {
            let actual = unsafe {
                std::ptr::read_volatile((region as *const u8).add(page * page_size).cast::<u64>())
            };
            if actual != expected[page] {
                byte_failures += 1;
            }
        }
    }

    let write_faults = PERMISSION_WRITE_FAULTS.load(Ordering::SeqCst);
    let read_faults = PERMISSION_READ_FAULTS.load(Ordering::SeqCst);
    let signal_errors = PERMISSION_ERRORS.load(Ordering::SeqCst);
    PERMISSION_PHASE.store(0, Ordering::SeqCst);
    PERMISSION_BASE.store(0, Ordering::SeqCst);
    PERMISSION_LEN.store(0, Ordering::SeqCst);
    let unmap_ok = unsafe { libc::munmap(region, len) } == 0;
    let ok = transition_failures == 0
        && byte_failures == 0
        && signal_errors == 0
        && write_faults == rounds as u32
        && read_faults == rounds as u32
        && unmap_ok;
    println!(
        "permission-transitions pages={pages} rounds={rounds} write_faults={write_faults} read_faults={read_faults} signal_errors={signal_errors} transition_failures={transition_failures} byte_failures={byte_failures} preserved={} segv_accerr={} unmap={unmap_ok}",
        byte_failures == 0,
        signal_errors == 0,
    );
    i32::from(!ok)
}

fn anonymous_reservations(count: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("anonymous-reservations invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if count == 0 {
        println!("anonymous-reservations invalid count {count}");
        return 1;
    }

    let mut mmaps = 0usize;
    let mut reserved_pages = 0usize;
    let mut brks = 0usize;
    let mut regions = Vec::with_capacity(count);

    for i in 0..count {
        let pages = (i % 4) + 1;
        let len = pages * page_size;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            println!("anonymous-reservations mmap failed at {i}");
            return 1;
        }
        mmaps += 1;
        reserved_pages += pages;
        let p = ptr as *mut u64;
        unsafe {
            p.write_volatile(0x1122_3344_5566_7788 ^ (i as u64));
            if p.read_volatile() != (0x1122_3344_5566_7788 ^ (i as u64)) {
                println!("anonymous-reservations readback failed at {i}");
                return 1;
            }
        }
        regions.push((ptr, len));
    }

    if let Some(&(first_ptr, first_len)) = regions.first() {
        let fixed_ptr = unsafe {
            libc::mmap(
                first_ptr,
                first_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if fixed_ptr == libc::MAP_FAILED {
            println!("anonymous-reservations MAP_FIXED failed");
            return 1;
        }
        mmaps += 1;
    }

    // brk is required to work: growth by one page must move the break exactly,
    // the new page must be writable, and shrinking must restore the break.
    let initial_brk = unsafe { raw6(214, 0, 0, 0, 0, 0, 0) } as usize;
    if initial_brk == 0 {
        println!("anonymous-reservations brk query failed");
        return 1;
    }
    let expanded = initial_brk + page_size;
    let grown = unsafe { raw6(214, expanded as u64, 0, 0, 0, 0, 0) } as usize;
    if grown != expanded {
        println!("anonymous-reservations brk growth failed: want {expanded:#x} got {grown:#x}");
        return 1;
    }
    brks += 1;
    let heap_ptr = initial_brk as *mut u64;
    unsafe {
        heap_ptr.write_volatile(0xDEAD_BEEF_CAFE_BABE);
        if heap_ptr.read_volatile() != 0xDEAD_BEEF_CAFE_BABE {
            println!("anonymous-reservations heap readback failed");
            return 1;
        }
    }
    let shrunk = unsafe { raw6(214, initial_brk as u64, 0, 0, 0, 0, 0) } as usize;
    if shrunk != initial_brk {
        println!("anonymous-reservations brk shrink failed: want {initial_brk:#x} got {shrunk:#x}");
        return 1;
    }
    brks += 1;

    for (ptr, len) in regions {
        unsafe { libc::munmap(ptr, len) };
    }

    println!(
        "anonymous-reservations count={count} pages={reserved_pages} mmaps={mmaps} brks={brks} ok=true"
    );
    0
}

fn anonymous_discard_and_exit(pages: usize, rounds: usize) -> i32 {
    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        println!("anonymous-discard-and-exit invalid page size {page_size_raw}");
        return 1;
    }
    let page_size = page_size_raw as usize;
    if pages == 0 || rounds == 0 {
        println!("anonymous-discard-and-exit invalid pages={pages} rounds={rounds}");
        return 1;
    }
    let len = match pages.checked_mul(page_size) {
        Some(l) if l > 0 => l,
        _ => {
            println!("anonymous-discard-and-exit overflow len");
            return 1;
        }
    };

    let words_per_page = page_size / std::mem::size_of::<u64>();

    for round in 0..rounds {
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            println!("anonymous-discard-and-exit mmap failed round={round}");
            return 1;
        }
        let base = region as usize;

        for p in 0..pages {
            let page_ptr = (base + p * page_size) as *mut u64;
            let val = 0xD15C_0000_0000_0000u64 | ((round as u64) << 32) | (p as u64);
            for w in 0..words_per_page {
                unsafe { page_ptr.add(w).write_volatile(val ^ ((w as u64) << 48)) };
            }
        }

        let mut p2c = [0 as libc::c_int; 2];
        let mut c2p = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0
        {
            println!("pipe failed round={round}");
            unsafe { libc::munmap(region, len) };
            return 1;
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("fork failed round={round}");
            unsafe {
                libc::close(p2c[0]);
                libc::close(p2c[1]);
                libc::close(c2p[0]);
                libc::close(c2p[1]);
                libc::munmap(region, len);
            }
            return 1;
        }

        if pid == 0 {
            unsafe {
                libc::close(p2c[1]);
                libc::close(c2p[0]);
            }
            let mut child_ok = true;
            for p in 0..pages {
                let page_ptr = (base + p * page_size) as *mut u64;
                let expected = 0xD15C_0000_0000_0000u64 | ((round as u64) << 32) | (p as u64);
                if unsafe { page_ptr.read_volatile() } != expected {
                    child_ok = false;
                }
            }

            let rc = unsafe { libc::madvise(region, len, libc::MADV_DONTNEED) };
            if rc != 0 {
                child_ok = false;
            }

            for p in 0..pages {
                let page_ptr = (base + p * page_size) as *mut u64;
                for w in 0..words_per_page {
                    if unsafe { page_ptr.add(w).read_volatile() } != 0 {
                        child_ok = false;
                        break;
                    }
                }
            }

            write_signal_byte(c2p[1], if child_ok { b'K' } else { b'F' });
            poll_read_byte(p2c[0], 5000);

            unsafe {
                libc::close(c2p[1]);
                libc::close(p2c[0]);
                libc::_exit(if child_ok { 0 } else { 1 });
            }
        }

        unsafe {
            libc::close(p2c[0]);
            libc::close(c2p[1]);
        }

        let ok_child_signal = poll_read_byte(c2p[0], 10000);
        write_signal_byte(p2c[1], b'A');

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        let child_ok = ok_child_signal
            && waited == pid
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0;
        unsafe {
            libc::close(p2c[1]);
            libc::close(c2p[0]);
        }

        if !child_ok {
            println!("child discard failed round={round}");
            unsafe { libc::munmap(region, len) };
            return 1;
        }

        for p in 0..pages {
            let page_ptr = (base + p * page_size) as *mut u64;
            let expected = 0xD15C_0000_0000_0000u64 | ((round as u64) << 32) | (p as u64);
            if unsafe { page_ptr.read_volatile() } != expected {
                println!("parent memory corruption after child discard round={round} page={p}");
                unsafe { libc::munmap(region, len) };
                return 1;
            }
        }

        let rc = unsafe { libc::madvise(region, len, libc::MADV_DONTNEED) };
        if rc != 0 {
            println!("parent madvise failed round={round}");
            unsafe { libc::munmap(region, len) };
            return 1;
        }

        for p in 0..pages {
            let page_ptr = (base + p * page_size) as *mut u64;
            for w in 0..words_per_page {
                if unsafe { page_ptr.add(w).read_volatile() } != 0 {
                    println!("parent non-zero page after discard round={round} page={p}");
                    unsafe { libc::munmap(region, len) };
                    return 1;
                }
            }
        }

        unsafe { libc::munmap(region, len) };
    }

    println!(
        "anonymous-discard-and-exit pages={pages} rounds={rounds} dontneed_ok=true exit_ok=true zero_ok=true ok=true"
    );
    0
}

static FAULT_COUNT: AtomicU32 = AtomicU32::new(0);
static FAULT_ADDR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FAULT_MMAP_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn on_fault_segv(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    if sig != libc::SIGSEGV {
        unsafe { libc::_exit(41) };
    }
    let count = FAULT_COUNT.fetch_add(1, Ordering::SeqCst);
    if count >= 1 {
        // Repeated fault: mprotect failed or store looped, terminate immediately to avoid hang
        unsafe { libc::_exit(42) };
    }
    if info.is_null() {
        unsafe { libc::_exit(43) };
    }
    let si_addr = unsafe { (*info).si_addr() as usize };
    FAULT_ADDR.store(si_addr, Ordering::SeqCst);

    let base = FAULT_MMAP_BASE.load(Ordering::SeqCst);
    if base == 0 {
        unsafe { libc::_exit(44) };
    }
    // Upgrade permissions to PROT_READ | PROT_WRITE so the retried store succeeds
    let rc = unsafe {
        libc::mprotect(
            base as *mut libc::c_void,
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    if rc != 0 {
        unsafe { libc::_exit(45) };
    }
}

#[repr(C, align(16))]
struct FaultTestContext {
    target_addr: u64,
    store_val: u64,
    captured_val: u64,
    captured_sp_pre: u64,
    captured_sp_post: u64,
    captured_regs: [u64; 31],
}

#[inline(never)]
unsafe fn execute_fault_sequence(ctx: &mut FaultTestContext) {
    unsafe {
        std::arch::asm!(
            // Save callee-saved registers x19-x30 and frame context
            "sub sp, sp, #128",
            "stp x19, x20, [sp, #0]",
            "stp x21, x22, [sp, #16]",
            "stp x23, x24, [sp, #32]",
            "stp x25, x26, [sp, #48]",
            "stp x27, x28, [sp, #64]",
            "stp x29, x30, [sp, #80]",
            // Save ctx pointer to stack slot [sp, #96]
            "str x0, [sp, #96]",

            // Record pre-fault SP (offset 24 in ctx)
            "mov x19, sp",
            "str x19, [x0, #24]",

            // Load target address (x1) and store value (x2)
            "ldr x1, [x0, #0]",
            "ldr x2, [x0, #8]",

            // Set canary values in registers x3..x30
            "movz x3, 0x0303, lsl #0",
            "movk x3, 0x0303, lsl #16",
            "movk x3, 0x0303, lsl #32",
            "movk x3, 0x0303, lsl #48",

            "movz x4, 0x0404, lsl #0",
            "movk x4, 0x0404, lsl #16",
            "movk x4, 0x0404, lsl #32",
            "movk x4, 0x0404, lsl #48",

            "movz x5, 0x0505, lsl #0",
            "movk x5, 0x0505, lsl #16",
            "movk x5, 0x0505, lsl #32",
            "movk x5, 0x0505, lsl #48",

            "movz x6, 0x0606, lsl #0",
            "movk x6, 0x0606, lsl #16",
            "movk x6, 0x0606, lsl #32",
            "movk x6, 0x0606, lsl #48",

            "movz x7, 0x0707, lsl #0",
            "movk x7, 0x0707, lsl #16",
            "movk x7, 0x0707, lsl #32",
            "movk x7, 0x0707, lsl #48",

            // x8 canary: 172 (libc::SYS_getpid on Linux AArch64) - valid served syscall
            "mov x8, 172",

            "movz x9, 0x0909, lsl #0",
            "movk x9, 0x0909, lsl #16",
            "movk x9, 0x0909, lsl #32",
            "movk x9, 0x0909, lsl #48",

            "movz x10, 0x0A0A, lsl #0",
            "movk x10, 0x0A0A, lsl #16",
            "movk x10, 0x0A0A, lsl #32",
            "movk x10, 0x0A0A, lsl #48",

            "movz x11, 0x0B0B, lsl #0",
            "movk x11, 0x0B0B, lsl #16",
            "movk x11, 0x0B0B, lsl #32",
            "movk x11, 0x0B0B, lsl #48",

            "movz x12, 0x0C0C, lsl #0",
            "movk x12, 0x0C0C, lsl #16",
            "movk x12, 0x0C0C, lsl #32",
            "movk x12, 0x0C0C, lsl #48",

            "movz x13, 0x0D0D, lsl #0",
            "movk x13, 0x0D0D, lsl #16",
            "movk x13, 0x0D0D, lsl #32",
            "movk x13, 0x0D0D, lsl #48",

            "movz x14, 0x0E0E, lsl #0",
            "movk x14, 0x0E0E, lsl #16",
            "movk x14, 0x0E0E, lsl #32",
            "movk x14, 0x0E0E, lsl #48",

            "movz x15, 0x0F0F, lsl #0",
            "movk x15, 0x0F0F, lsl #16",
            "movk x15, 0x0F0F, lsl #32",
            "movk x15, 0x0F0F, lsl #48",

            "movz x16, 0x1616, lsl #0",
            "movk x16, 0x1616, lsl #16",
            "movk x16, 0x1616, lsl #32",
            "movk x16, 0x1616, lsl #48",

            "movz x17, 0x1717, lsl #0",
            "movk x17, 0x1717, lsl #16",
            "movk x17, 0x1717, lsl #32",
            "movk x17, 0x1717, lsl #48",

            "movz x18, 0x1818, lsl #0",
            "movk x18, 0x1818, lsl #16",
            "movk x18, 0x1818, lsl #32",
            "movk x18, 0x1818, lsl #48",

            "movz x19, 0x1919, lsl #0",
            "movk x19, 0x1919, lsl #16",
            "movk x19, 0x1919, lsl #32",
            "movk x19, 0x1919, lsl #48",

            "movz x20, 0x2020, lsl #0",
            "movk x20, 0x2020, lsl #16",
            "movk x20, 0x2020, lsl #32",
            "movk x20, 0x2020, lsl #48",

            "movz x21, 0x2121, lsl #0",
            "movk x21, 0x2121, lsl #16",
            "movk x21, 0x2121, lsl #32",
            "movk x21, 0x2121, lsl #48",

            "movz x22, 0x2222, lsl #0",
            "movk x22, 0x2222, lsl #16",
            "movk x22, 0x2222, lsl #32",
            "movk x22, 0x2222, lsl #48",

            "movz x23, 0x2323, lsl #0",
            "movk x23, 0x2323, lsl #16",
            "movk x23, 0x2323, lsl #32",
            "movk x23, 0x2323, lsl #48",

            "movz x24, 0x2424, lsl #0",
            "movk x24, 0x2424, lsl #16",
            "movk x24, 0x2424, lsl #32",
            "movk x24, 0x2424, lsl #48",

            "movz x25, 0x2525, lsl #0",
            "movk x25, 0x2525, lsl #16",
            "movk x25, 0x2525, lsl #32",
            "movk x25, 0x2525, lsl #48",

            "movz x26, 0x2626, lsl #0",
            "movk x26, 0x2626, lsl #16",
            "movk x26, 0x2626, lsl #32",
            "movk x26, 0x2626, lsl #48",

            "movz x27, 0x2727, lsl #0",
            "movk x27, 0x2727, lsl #16",
            "movk x27, 0x2727, lsl #32",
            "movk x27, 0x2727, lsl #48",

            "movz x28, 0x2828, lsl #0",
            "movk x28, 0x2828, lsl #16",
            "movk x28, 0x2828, lsl #32",
            "movk x28, 0x2828, lsl #48",

            "movz x29, 0x2929, lsl #0",
            "movk x29, 0x2929, lsl #16",
            "movk x29, 0x2929, lsl #32",
            "movk x29, 0x2929, lsl #48",

            "movz x30, 0x3030, lsl #0",
            "movk x30, 0x3030, lsl #16",
            "movk x30, 0x3030, lsl #32",
            "movk x30, 0x3030, lsl #48",

            // Set x0 canary right before faulting store
            "movz x0, 0x0000, lsl #0",
            "movk x0, 0x1234, lsl #16",
            "movk x0, 0x5678, lsl #32",
            "movk x0, 0x9ABC, lsl #48",

            // The faulting store: stage-1 permission fault taken at EL0 to EL1
            "str x2, [x1]",

            // Capture post-retry state:
            // Save post-fault x0 and x1 to stack scratch slots [sp, #104] and [sp, #112]
            "stp x0, x1, [sp, #104]",
            // Reload ctx pointer from [sp, #96] into x0
            "ldr x0, [sp, #96]",
            // Record post-fault SP using x1 as scratch
            "mov x1, sp",
            "str x1, [x0, #32]",

            // Store captured registers x2..x30 into ctx.captured_regs (offset 40 + r*8)
            "str x2, [x0, #56]",
            "str x3, [x0, #64]",
            "str x4, [x0, #72]",
            "str x5, [x0, #80]",
            "str x6, [x0, #88]",
            "str x7, [x0, #96]",
            "str x8, [x0, #104]",
            "str x9, [x0, #112]",
            "str x10, [x0, #120]",
            "str x11, [x0, #128]",
            "str x12, [x0, #136]",
            "str x13, [x0, #144]",
            "str x14, [x0, #152]",
            "str x15, [x0, #160]",
            "str x16, [x0, #168]",
            "str x17, [x0, #176]",
            "str x18, [x0, #184]",
            "str x19, [x0, #192]",
            "str x20, [x0, #200]",
            "str x21, [x0, #208]",
            "str x22, [x0, #216]",
            "str x23, [x0, #224]",
            "str x24, [x0, #232]",
            "str x25, [x0, #240]",
            "str x26, [x0, #248]",
            "str x27, [x0, #256]",
            "str x28, [x0, #264]",
            "str x29, [x0, #272]",
            "str x30, [x0, #280]",

            // Retrieve post-fault x0 and x1 from stack scratch slots into x1 and x2
            "ldp x1, x2, [sp, #104]",
            // Store post-fault x0 and x1 into ctx.captured_regs[0] and ctx.captured_regs[1]
            "str x1, [x0, #40]",
            "str x2, [x0, #48]",

            // Read back written value from target_addr
            "ldr x1, [x0, #0]",
            "ldr x2, [x1]",
            "str x2, [x0, #16]",

            // Restore callee-saved registers x19-x30
            "ldp x19, x20, [sp, #0]",
            "ldp x21, x22, [sp, #16]",
            "ldp x23, x24, [sp, #32]",
            "ldp x25, x26, [sp, #48]",
            "ldp x27, x28, [sp, #64]",
            "ldp x29, x30, [sp, #80]",
            "add sp, sp, #128",
            inout("x0") ctx as *mut FaultTestContext => _,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            out("x4") _,
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            out("x18") _,
        );
    }
}

fn fault_entry_mode() -> i32 {
    let page_size = 4096;
    // Step 1: Establish backing first by mapping read/write and initializing memory
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        println!("fault-entry mmap failed");
        return 1;
    }
    let base = ptr as usize;
    FAULT_MMAP_BASE.store(base, Ordering::SeqCst);

    let target_addr = (base + 0x40) as u64;
    let initial_val: u64 = 0x5555_AAAA_3333_CCCC;
    unsafe {
        std::ptr::write_volatile(target_addr as *mut u64, initial_val);
    }

    // Step 2: Demote page to read-only to create a genuine stage-1 permission fault condition
    let prot_rc = unsafe { libc::mprotect(ptr, page_size, libc::PROT_READ) };
    if prot_rc != 0 {
        println!("fault-entry initial mprotect failed");
        unsafe { libc::munmap(ptr, page_size) };
        return 1;
    }

    // Step 3: Install SA_SIGINFO handler for SIGSEGV
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_fault_segv as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    let rc = unsafe { libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) };
    if rc != 0 {
        println!("fault-entry sigaction failed");
        unsafe { libc::munmap(ptr, page_size) };
        return 1;
    }

    let store_val: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut ctx = FaultTestContext {
        target_addr,
        store_val,
        captured_val: 0,
        captured_sp_pre: 0,
        captured_sp_post: 0,
        captured_regs: [0; 31],
    };

    // Step 4: Execute faulting sequence with all register canaries and SP capture
    unsafe {
        execute_fault_sequence(&mut ctx);
    }

    let fault_count = FAULT_COUNT.load(Ordering::SeqCst);
    let fault_addr = FAULT_ADDR.load(Ordering::SeqCst);

    unsafe { libc::munmap(ptr, page_size) };

    if fault_count != 1 {
        println!("fault-entry unexpected fault_count={fault_count}");
        return 1;
    }
    if fault_addr as u64 != target_addr {
        println!("fault-entry unexpected fault_addr={fault_addr:#x} expected={target_addr:#x}");
        return 1;
    }
    if ctx.captured_val != store_val {
        println!(
            "fault-entry store failed captured_val={:#x} expected={:#x}",
            ctx.captured_val, store_val
        );
        return 1;
    }
    if ctx.captured_sp_pre == 0 || ctx.captured_sp_post == 0 {
        println!("fault-entry SP not captured");
        return 1;
    }
    if (ctx.captured_sp_pre & 0xF) != 0 {
        println!("fault-entry SP unaligned pre={:#x}", ctx.captured_sp_pre);
        return 1;
    }
    if ctx.captured_sp_pre != ctx.captured_sp_post {
        println!(
            "fault-entry SP mismatch pre={:#x} post={:#x}",
            ctx.captured_sp_pre, ctx.captured_sp_post
        );
        return 1;
    }

    // Expected canary values for all 31 registers:
    let make_canary = |b: u16| -> u64 {
        let b = b as u64;
        b | (b << 16) | (b << 32) | (b << 48)
    };
    let expected_x0 = 0x9ABC_5678_1234_0000_u64;
    let expected_x8 = 172_u64; // libc::SYS_getpid
    if ctx.captured_regs[0] != expected_x0 {
        println!(
            "fault-entry canary mismatch x0={:#x} expected={:#x}",
            ctx.captured_regs[0], expected_x0
        );
        return 1;
    }
    if ctx.captured_regs[1] != target_addr {
        println!(
            "fault-entry canary mismatch x1={:#x} expected={:#x}",
            ctx.captured_regs[1], target_addr
        );
        return 1;
    }
    if ctx.captured_regs[2] != store_val {
        println!(
            "fault-entry canary mismatch x2={:#x} expected={:#x}",
            ctx.captured_regs[2], store_val
        );
        return 1;
    }
    if ctx.captured_regs[8] != expected_x8 {
        println!(
            "fault-entry canary mismatch x8={:#x} expected={:#x}",
            ctx.captured_regs[8], expected_x8
        );
        return 1;
    }
    for r in 3..=30 {
        if r == 8 {
            continue;
        }
        let byte_val = match r {
            3 => 0x0303,
            4 => 0x0404,
            5 => 0x0505,
            6 => 0x0606,
            7 => 0x0707,
            9 => 0x0909,
            10 => 0x0A0A,
            11 => 0x0B0B,
            12 => 0x0C0C,
            13 => 0x0D0D,
            14 => 0x0E0E,
            15 => 0x0F0F,
            16 => 0x1616,
            17 => 0x1717,
            18 => 0x1818,
            19 => 0x1919,
            20 => 0x2020,
            21 => 0x2121,
            22 => 0x2222,
            23 => 0x2323,
            24 => 0x2424,
            25 => 0x2525,
            26 => 0x2626,
            27 => 0x2727,
            28 => 0x2828,
            29 => 0x2929,
            30 => 0x3030,
            _ => 0,
        };
        let expected = make_canary(byte_val);
        if ctx.captured_regs[r] != expected {
            println!(
                "fault-entry canary mismatch x{r}={:#x} expected={:#x}",
                ctx.captured_regs[r], expected
            );
            return 1;
        }
    }

    println!("fault-entry ok");
    0
}

/// Four guest threads grow/free the shared EL1 heap while a fifth thread
/// completes host-served uname calls. The embed watchdog bounds every join.
fn metadata_allocator_control(subtest: u64) -> i64 {
    unsafe {
        raw6(
            carrick_el1_abi::SYS_CARRICK_EL1_CONTROL,
            1,
            subtest,
            0,
            0,
            0,
            0,
        )
    }
}

fn metadata_allocator_drain() -> i64 {
    // One global mailbox can require one boundary per grant/return. The
    // allocator admits at most 128 extents, so this bound covers a complete
    // request and return for every descriptor without timing-based retries.
    const MAX_BOUNDARIES: usize = 2 * 128 + 2;
    for _ in 0..MAX_BOUNDARIES {
        let drain = metadata_allocator_control(5);
        if drain != carrick_el1_abi::METADATA_GRANT_PENDING as i64 {
            return drain;
        }
    }
    0xCA88_0502
}

fn metadata_allocator_phase(subtest: u64, drain_on_success: bool) -> i64 {
    const MAX_BOUNDARIES: usize = 2 * 128 + 2;
    for _ in 0..MAX_BOUNDARIES {
        let rc = metadata_allocator_control(subtest);
        if rc != carrick_el1_abi::METADATA_GRANT_PENDING as i64 {
            if rc != 0 {
                return rc;
            }
            if drain_on_success {
                return metadata_allocator_drain();
            }
            return 0;
        }
    }
    0xCA88_0501
}

fn metadata_allocator_concurrent() -> i32 {
    const ROUNDS: usize = 16;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut failure_codes = Vec::new();
            for _ in 0..ROUNDS {
                barrier.wait();
                let rc = metadata_allocator_phase(2, false);
                if rc != 0 {
                    failure_codes.push(rc);
                }
                barrier.wait();
            }
            failure_codes
        }));
    }
    let mut host_calls = 0;
    let mut host_failures = 0;
    let mut coordinator_failure_codes = Vec::new();
    for _ in 0..ROUNDS {
        barrier.wait();
        for _ in 0..64 {
            let mut name = [0u8; 390];
            let rc = unsafe { raw6(160, name.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
            host_calls += 1;
            host_failures += usize::from(rc != 0 || &name[..5] != b"Linux");
        }
        barrier.wait();
        // All four transactions have freed their allocations. Reclaim every
        // pending extent before the next round so historical returns cannot
        // consume the bounded 128-slot host aperture.
        let drain = metadata_allocator_drain();
        if drain != 0 {
            coordinator_failure_codes.push(drain);
        }
    }
    let mut failure_codes: Vec<i64> = workers
        .into_iter()
        .flat_map(|worker| worker.join().expect("allocator worker"))
        .collect();
    failure_codes.extend(coordinator_failure_codes);
    let drain = metadata_allocator_drain();
    if drain != 0 {
        failure_codes.push(drain);
    }
    failure_codes.sort_unstable();
    let failures = failure_codes.len();
    println!(
        "metadata-allocator concurrent workers=4 rounds={ROUNDS} failures={failures} host_calls={host_calls} host_failures={host_failures} failure_codes={failure_codes:?}"
    );
    i32::from(failures != 0 || host_failures != 0)
}

fn metadata_allocator_mode(phase: &str) -> i32 {
    if phase == "concurrent" {
        return metadata_allocator_concurrent();
    }
    // Each invocation executes one phase so the host can arm grant refusal
    // only after ordinary growth/return has completed in this carrier.
    let subtest = match phase {
        "basic" => 1,
        "growth" => 2,
        "denial" => 3,
        "irq" => 4,
        _ => {
            eprintln!("metadata-allocator requires basic, growth, denial, or irq");
            return 2;
        }
    };
    let result = metadata_allocator_phase(subtest, true);
    if result != 0 {
        println!("metadata-allocator {phase} failed: rc={result}");
        return 1;
    }
    println!("metadata-allocator {phase} ok");
    0
}

/// Parent pauses at an intercepted marker until its child's notification
/// snapshot is captured. It then reaps the child and exits; the root reaps
/// that parent before the auditor permits the saved notification to continue.
fn delayed_parent_notification() -> i32 {
    unsafe {
        libc::alarm(10);
    }
    let parent = unsafe { libc::fork() };
    if parent < 0 {
        return 70;
    }
    if parent == 0 {
        let child = unsafe { libc::fork() };
        if child < 0 {
            unsafe {
                libc::_exit(71);
            }
        }
        if child == 0 {
            unsafe {
                libc::_exit(0);
            }
        }
        // sched_yield ignores arguments; the marker is a test rendezvous,
        // and ordinary Linux still executes the same valid syscall.
        unsafe {
            libc::syscall(libc::SYS_sched_yield, 0x454c314e_u64);
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        let code = if waited == child && status == 0 {
            0
        } else {
            72
        };
        unsafe {
            libc::_exit(code);
        }
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(parent, &mut status, 0) };
    if waited != parent || status != 0 {
        return 73;
    }
    println!("delayed-parent-notification reaped=1");
    0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("pingpong");
    let code = match mode {
        "pingpong" => pingpong(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(20_000)),
        "signal" => signal_mode(),
        "delayed-parent-notification" => delayed_parent_notification(),
        "exit-group" => exit_group_mode(),
        "exec" => exec_mode(&args[0]),
        "pinned-pingpong" => pinned_pingpong(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(20_000),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(5),
        ),
        "timed-wait" => timed_wait(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(200)),
        "compute-pair" => compute_pair(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(300)),
        "idle-carrier" => idle_carrier(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(500)),
        "wfi-signal" => wfi_signal(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(100)),
        "pstate" => pstate_mode(),
        "ipc-mixed" => ipc::mixed(args.get(2).map(String::as_str).unwrap_or("pipe")),
        "ipc-lifetime" => ipc::lifetime(),
        "ipc-processes" => ipc::processes(
            args.get(2).map(String::as_str).unwrap_or("pipe"),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(1),
            args.get(4).and_then(|n| n.parse().ok()).unwrap_or(128),
        ),
        "ipc-pairs" => ipc::pairs(
            args.get(2).map(String::as_str).unwrap_or("pipe"),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(1),
            args.get(4).and_then(|n| n.parse().ok()).unwrap_or(128),
        ),
        "pipe-pingpong" => pipe_pingpong(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(2_000)),
        "epoll-pingpong" => {
            epoll_pingpong(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(2_000))
        }
        "sock-pingpong" => sock_pingpong(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(2_000),
            args.get(3).is_some_and(|mode| mode == "pinned"),
        ),
        "pipe-compute" => pipe_compute(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(300)),
        "two-process" => two_process(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(20_000)),
        "mm-occupancy" => mm_occupancy(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(200)),
        "first-touch" => match args.get(2) {
            None => first_touch(256),
            Some(value) => match value.parse() {
                Ok(pages) => first_touch(pages),
                Err(_) => {
                    println!("first-touch invalid page count {value}");
                    2
                }
            },
        },
        "fork-cow" => fork_cow(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(100),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(16),
        ),
        "mapping-retirement" => mapping_retirement(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(256),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(4),
        ),
        "permission-transitions" => permission_transitions(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(256),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(4),
        ),
        "anonymous-reservations" => {
            anonymous_reservations(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(64))
        }
        "anonymous-discard-and-exit" => anonymous_discard_and_exit(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(256),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(4),
        ),
        "delegated-root-vma" => {
            delegated_root::concurrent_vma(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(16))
        }
        "delegated-root-fixed-cow" => delegated_root::fixed_over_cow(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(64),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(8),
        ),
        "kick-first-read" => {
            delegated_root::kick_first_read(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(1))
        }
        "thread-spawn-slope" => threads::spawn_slope(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(4),
            args.get(3).and_then(|n| n.parse().ok()).unwrap_or(16),
        ),
        "tgkill-after-clone" => {
            threads::tgkill_after_clone(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(16))
        }
        "mask-storm" => {
            threads::mask_storm(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(2000))
        }
        "signal-retarget" => {
            threads::signal_retarget(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(32))
        }
        "tid-reuse" => threads::tid_reuse(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(100)),
        "nproc-limit" => threads::nproc_limit(),
        "fork-storm" => threads::fork_storm(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(16)),
        "exit-group-storm" => {
            threads::exit_group_storm(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(4))
        }
        "exec-storm" => threads::exec_storm(
            args.get(2).and_then(|n| n.parse().ok()).unwrap_or(4),
            &args[0],
        ),
        "exec-storm-child" => threads::exec_storm_child(),
        "ptrace-clone" => threads::ptrace_clone(),
        "seccomp-clone" => threads::seccomp_clone(),
        "futex-flood" => {
            threads::futex_flood(args.get(2).and_then(|n| n.parse().ok()).unwrap_or(192))
        }
        "fault-entry" => fault_entry_mode(),
        "metadata-allocator" => {
            metadata_allocator_mode(args.get(2).map(String::as_str).unwrap_or(""))
        }
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
