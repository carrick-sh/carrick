//! Serial `fork(2)`/`_exit`/`waitpid` storm: the fork primitive under repeated
//! child creation from one parent.
//!
//! The parent forks `n` children one at a time; each child `_exit(0)`s at
//! once and the parent reaps it before forking the next. Linux (`man 2 fork`,
//! `man 2 wait4`) gives every child exit status 0 and returns each child's own
//! pid from `waitpid`. Under Carrick this is the `kernel.fork.stage1-image`
//! fixture: every child owns a private stage-1 page-table image, and a storm
//! must recycle retired images instead of allocating one per fork
//! (`ltp-fork14` spawns 16k children this way).
//!
//! `forkserial [n] [dirty] [timing]` — `n` defaults to 8 so the oracle-diffed
//! generic run is deterministic; the contract bindings pass the scale point
//! explicitly. `dirty` makes the parent write one private heap page between
//! forks, the `ltp-fork14` shape (a COW split per iteration). `timing` adds
//! the per-fork latency distribution (`fork_serial_p50_us=`,
//! `fork_serial_wall_us=`) for the uninstrumented timing binding; the oracle
//! records stdout and stderr, so those numeric lines are printed only on
//! request and never in the diffed default run. Every wait is bounded (4 s) so
//! a lost child is a false line, not a hang.

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

const DEFAULT_FORKS: usize = 8;
const REAP_TIMEOUT: Duration = Duration::from_secs(4);

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
            return None;
        }
        unsafe { libc::sched_yield() };
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let forks = args
        .iter()
        .find_map(|arg| arg.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_FORKS);
    let timing = args.iter().any(|arg| arg == "timing");

    let dirty = args.iter().any(|arg| arg == "dirty");
    let mut scratch = vec![0u8; 4096];

    let mut fork_ok = true;
    let mut children_exited_zero = true;
    let mut reaped_own_pid = true;
    let mut distinct_pids = true;
    let mut last_pid = -1;
    let mut latencies_us = Vec::with_capacity(forks);
    let wall_started = Instant::now();

    for i in 0..forks {
        if dirty {
            // One private write per iteration: the parent's COW-armed page
            // splits after every fork, as fork14's parent does.
            unsafe { core::ptr::write_volatile(scratch.as_mut_ptr(), i as u8) };
        }
        let started = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        if pid < 0 {
            fork_ok = false;
            break;
        }
        if pid == last_pid {
            distinct_pids = false;
        }
        last_pid = pid;
        match reap_bounded(pid) {
            Some(status) => {
                if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                    children_exited_zero = false;
                }
            }
            None => {
                reaped_own_pid = false;
                children_exited_zero = false;
            }
        }
        latencies_us.push(started.elapsed().as_micros() as u64);
    }
    let wall_us = wall_started.elapsed().as_micros() as u64;

    latencies_us.sort_unstable();
    let p50_us = latencies_us
        .get(latencies_us.len() / 2)
        .copied()
        .unwrap_or(0);

    report!(
        serial_forks = forks,
        dirty_parent = dirty,
        fork_succeeded = fork_ok,
        children_exited_zero = children_exited_zero,
        reaped_each_child = reaped_own_pid,
        child_pids_distinct = distinct_pids,
    );
    if timing {
        println!("fork_serial_p50_us={p50_us}");
        println!("fork_serial_wall_us={wall_us}");
    }
}
