use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

const DEFAULT_WORKERS: usize = 6;
const DEFAULT_ROUNDS: usize = 4;

fn main() {
    let mut args = std::env::args().skip(1);
    let workers = args
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_WORKERS);
    let rounds = args
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ROUNDS);

    let barrier = Arc::new(Barrier::new(workers));
    let fork_failures = Arc::new(AtomicUsize::new(0));
    let wait_failures = Arc::new(AtomicUsize::new(0));
    let status_failures = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let barrier = Arc::clone(&barrier);
        let fork_failures = Arc::clone(&fork_failures);
        let wait_failures = Arc::clone(&wait_failures);
        let status_failures = Arc::clone(&status_failures);
        handles.push(thread::spawn(move || {
            for _ in 0..rounds {
                barrier.wait();
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe { libc::_exit(0) };
                }
                if pid < 0 {
                    fork_failures.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut status = 0;
                let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
                if waited != pid {
                    wait_failures.fetch_add(1, Ordering::Relaxed);
                } else if status != 0 {
                    status_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        if handle.join().is_err() {
            status_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    let fork_failures = fork_failures.load(Ordering::Relaxed);
    let wait_failures = wait_failures.load(Ordering::Relaxed);
    let status_failures = status_failures.load(Ordering::Relaxed);
    let failures = fork_failures + wait_failures + status_failures;
    if failures == 0 {
        println!("CONCURRENT_FORK_OK workers={workers} rounds={rounds}");
    } else {
        eprintln!(
            "CONCURRENT_FORK_FAIL fork_failures={fork_failures} wait_failures={wait_failures} status_failures={status_failures}"
        );
        process::exit(1);
    }
}
