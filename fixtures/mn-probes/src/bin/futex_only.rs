// Probe A — futex-only control. N threads pass a token around a strict ring
// using Mutex+Condvar (musl Condvar => futex). A single lost wakeup deadlocks
// the ring, so this is a high-sensitivity futex correctness test with heavy
// contention, and NO signals. Prints "PROBE_A_OK <rounds>" on success.
//
// Tunables via argv: [workers] [rounds]. Defaults sized to run a few seconds.
use std::env;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let mut args = env::args().skip(1);
    let workers: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let rounds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);

    // Self-watchdog: if the ring stalls, exit(2) so the verdict is deterministic
    // even without an external timeout (unless the whole VM is wedged).
    spawn_watchdog(Duration::from_secs(30), "PROBE_A_TIMEOUT");

    let turn = Arc::new((Mutex::new(0u64), Condvar::new()));
    let total = rounds * workers as u64;
    let mut handles = Vec::new();
    for id in 0..workers {
        let turn = Arc::clone(&turn);
        let id = id as u64;
        let n = workers as u64;
        handles.push(thread::spawn(move || {
            let (m, c) = &*turn;
            let mut g = m.lock().unwrap();
            loop {
                if *g >= total {
                    c.notify_all();
                    return;
                }
                if *g % n == id {
                    *g += 1;
                    c.notify_all();
                } else {
                    g = c.wait(g).unwrap();
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_turn = *turn.0.lock().unwrap();
    assert_eq!(final_turn, total, "ring did not complete all rounds");
    println!("PROBE_A_OK {rounds}");
}

fn spawn_watchdog(budget: Duration, msg: &'static str) {
    let start = Instant::now();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(200));
        if start.elapsed() >= budget {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    });
}
