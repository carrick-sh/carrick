//! Many-process residency invariant: a parent can hold N simultaneously-alive,
//! *blocked* children (each parked in `pause(2)`) and then reap them all.
//!
//! On Linux this is trivially true for any reasonable N. Under carrick/HVF the
//! host materializes one VM+vCPU per guest process, and the measured
//! system-wide residency ceiling is ~126 (soft budget 120, trap.rs
//! GLOBAL_VCPU_CEILING) — so at N past the budget, fork stalls indefinitely in
//! the unbounded permit wait while every child sleeps holding a permit. This
//! probe is the red-first gate for the WakeFromBlockingSyscall residency-lease
//! track: blocked processes should not hold materialized VMM residency.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_reaped_all — every forked child was SIGKILLed and reaped
//!
//! N defaults to 8 (safely under the ceiling) so the probe gate stays green;
//! the over-ceiling evidence/acceptance run sets PROC_LADDER_N=160.
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::report;
use std::env;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 1024)
}

fn main() {
    let n = ladder_n();
    let mut pids: Vec<i32> = Vec::with_capacity(n);
    unsafe {
        for _ in 0..n {
            let pid = libc::fork();
            if pid == 0 {
                loop {
                    libc::pause();
                }
            }
            if pid < 0 {
                break;
            }
            pids.push(pid);
        }
        let forked = pids.len();
        for &pid in &pids {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut reaped = 0usize;
        for &pid in &pids {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid {
                reaped += 1;
            }
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_reaped_all = reaped == forked,
        );
    }
}
