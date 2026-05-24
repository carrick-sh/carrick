// Probe B — futex ring (same as Probe A) PLUS a Go-style SIGURG storm: a
// "sysmon" thread tgkill-storms every worker with SIGURG while they contend on
// the Condvar. A SA_RESTART|SA_SIGINFO handler does trivial work and returns.
//
// If Probe A passes at high P but Probe B hangs/deadlocks, signal delivery is
// corrupting the futex/condvar wait path (the prime suspect, since Go's
// asyncpreemptoff=1 makes the 10-CPU oracle clean). Prints "PROBE_B_OK <rounds>".
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static PREEMPTS: AtomicU64 = AtomicU64::new(0);
static PROGRESS: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_sigurg(_sig: i32, _info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    // Trivial non-reentrant-safe-enough work: just bump a counter, like Go's
    // doSigPreempt acknowledging the preemption. The point is to exercise
    // carrick's inject_signal + rt_sigreturn under high concurrency.
    PREEMPTS.fetch_add(1, Ordering::Relaxed);
}

fn install_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigurg as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        let rc = libc::sigaction(libc::SIGURG, &sa, std::ptr::null_mut());
        assert_eq!(rc, 0, "sigaction(SIGURG) failed");
    }
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn tgkill(tgid: i32, tid: i32, sig: i32) {
    unsafe {
        libc::syscall(libc::SYS_tgkill, tgid, tid, sig);
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let workers: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let rounds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);

    install_handler();
    spawn_watchdog(Duration::from_secs(15), "PROBE_B_TIMEOUT");
    // Live progress heartbeat (always on): prints the ring counter so a deadlock
    // shows up as "progress froze at N" with a timestamp.
    {
        let start = Instant::now();
        thread::spawn(move || {
            let mut last = u64::MAX;
            loop {
                thread::sleep(Duration::from_millis(500));
                let p = PROGRESS.load(Ordering::Relaxed);
                let pre = PREEMPTS.load(Ordering::Relaxed);
                eprintln!(
                    "HEARTBEAT t={:?} progress={p} preempts={pre} {}",
                    start.elapsed(),
                    if p == last { "FROZEN" } else { "" }
                );
                last = p;
            }
        });
    }

    let pid = unsafe { libc::getpid() };
    let tids: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));

    let turn = Arc::new((Mutex::new(0u64), Condvar::new()));
    let total = rounds * workers as u64;
    let mut handles = Vec::new();
    for id in 0..workers {
        let turn = Arc::clone(&turn);
        let tids = Arc::clone(&tids);
        let id = id as u64;
        let n = workers as u64;
        handles.push(thread::spawn(move || {
            tids.lock().unwrap().push(gettid());
            let (m, c) = &*turn;
            let mut g = m.lock().unwrap();
            loop {
                if *g >= total {
                    c.notify_all();
                    return;
                }
                if *g % n == id {
                    *g += 1;
                    PROGRESS.store(*g, Ordering::Relaxed);
                    c.notify_all();
                } else {
                    g = c.wait(g).unwrap();
                }
            }
        }));
    }

    // Sysmon: storm SIGURG at all workers until the ring finishes.
    let sysmon = {
        let tids = Arc::clone(&tids);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let snapshot = tids.lock().unwrap().clone();
                for tid in snapshot {
                    tgkill(pid, tid, libc::SIGURG);
                }
                // Tight storm; a few microseconds between sweeps.
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    for h in handles {
        h.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    sysmon.join().unwrap();

    let final_turn = *turn.0.lock().unwrap();
    assert_eq!(final_turn, total, "ring did not complete all rounds");
    println!(
        "PROBE_B_OK {rounds} preempts={}",
        PREEMPTS.load(Ordering::Relaxed)
    );
}

fn spawn_watchdog(budget: Duration, msg: &'static str) {
    let start = Instant::now();
    thread::spawn(move || {
        // Sample progress mid-window and again at timeout: if the two match, the
        // ring is FROZEN (true deadlock); if it advanced, it was merely slow.
        let mut mid = 0u64;
        loop {
            thread::sleep(Duration::from_millis(200));
            let e = start.elapsed();
            if e >= budget / 2 && mid == 0 {
                mid = PROGRESS.load(Ordering::Relaxed).max(1);
            }
            if e >= budget {
                let p = PROGRESS.load(Ordering::Relaxed);
                let state = if p == mid { "FROZEN" } else { "advancing" };
                eprintln!(
                    "{msg} progress={p} (mid={mid} -> {state}) preempts={}",
                    PREEMPTS.load(Ordering::Relaxed)
                );
                std::process::exit(2);
            }
        }
    });
}
