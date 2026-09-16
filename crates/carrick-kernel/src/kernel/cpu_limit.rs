//! `RLIMIT_CPU` enforcement (`setrlimit(2)`): `SIGXCPU` when a process's
//! user CPU reaches its soft limit — repeated once per further second of CPU
//! it consumes — and `SIGKILL` when it reaches the hard limit.
//!
//! The limit is guest state, so it is judged from the kernel graph: each
//! task's own threads' guest CPU ([`Task::self_cpu_ns_including_active`]),
//! never the carrier's process-wide counters, which under HVPatch sum every
//! guest process together. It is enforced by a watchdog thread, not on the
//! syscall path: Linux charges CPU on the scheduler tick, so a process that
//! never traps — LTP `setrlimit06`'s `while (1);` child — still dies on time,
//! whereas a check that runs only when the guest makes a syscall never runs
//! for exactly the process the limit exists to stop.
//!
//! One watchdog per kernel scans the registry for tasks with a finite limit.
//! It is started by the first finite limit to appear (a `setrlimit`/`prlimit`
//! write or a fork that inherits one) and exits when a scan finds none left,
//! so a kernel whose guests never bound their CPU pays nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use carrick_abi::{LINUX_RLIM_INFINITY, LinuxResource, LinuxRlimit};
use parking_lot::{Condvar, Mutex};

use super::{Kernel, LinuxSignal, Task, TaskKey};

const NS_PER_S: u64 = 1_000_000_000;

/// The watchdog never sleeps longer than this even when every limit is far
/// away: a task can gain threads (multiplying its CPU rate against the wall
/// clock) between scans, and a second is the granularity Linux itself
/// enforces `RLIMIT_CPU` at.
const MAX_RECHECK: Duration = Duration::from_secs(1);
/// Nor shorter than this: sub-millisecond precision buys nothing against a
/// whole-second limit and would turn the watchdog into a busy loop.
const MIN_RECHECK: Duration = Duration::from_millis(1);

/// What one task's CPU means against its limit right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CpuLimitVerdict {
    /// Under both limits; nothing to send.
    Within,
    /// At or past the soft limit and due another `SIGXCPU`.
    Soft,
    /// At or past the hard limit: `SIGKILL`.
    Hard,
}

/// One task's evaluation: the verdict, the CPU point (ns) at which its NEXT
/// `SIGXCPU` falls due (`None` when the soft limit is infinite), and how much
/// more CPU it may consume before the watchdog must look again (`None` when
/// nothing further can ever fall due).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuLimitEvaluation {
    pub(crate) verdict: CpuLimitVerdict,
    pub(crate) next_soft_due_ns: Option<u64>,
    pub(crate) cpu_until_next_ns: Option<u64>,
}

fn limit_ns(seconds: u64) -> Option<u64> {
    (seconds != LINUX_RLIM_INFINITY).then(|| seconds.saturating_mul(NS_PER_S))
}

/// Judge `cpu_ns` of consumed user CPU against `limit`. `soft_due_ns` is the
/// point the previous evaluation scheduled the next `SIGXCPU` for, so the
/// once-per-second cadence survives across scans; the first evaluation
/// passes `None`.
pub(crate) fn evaluate(
    limit: LinuxRlimit,
    cpu_ns: u64,
    soft_due_ns: Option<u64>,
) -> CpuLimitEvaluation {
    let hard_ns = limit_ns(limit.rlim_max);
    if let Some(hard) = hard_ns
        && cpu_ns >= hard
    {
        return CpuLimitEvaluation {
            verdict: CpuLimitVerdict::Hard,
            next_soft_due_ns: None,
            cpu_until_next_ns: None,
        };
    }
    let soft_ns = limit_ns(limit.rlim_cur);
    let (verdict, next_soft_due_ns) = match soft_ns {
        None => (CpuLimitVerdict::Within, None),
        Some(soft) => {
            // A raised soft limit moves the next delivery out to it; a lowered
            // one keeps the cadence the previous delivery already set.
            let due = soft_due_ns.map_or(soft, |due| due.max(soft));
            if cpu_ns >= due {
                (CpuLimitVerdict::Soft, Some(cpu_ns.saturating_add(NS_PER_S)))
            } else {
                (CpuLimitVerdict::Within, Some(due))
            }
        }
    };
    let next = match (next_soft_due_ns, hard_ns) {
        (Some(soft), Some(hard)) => Some(soft.min(hard)),
        (Some(point), None) | (None, Some(point)) => Some(point),
        (None, None) => None,
    };
    CpuLimitEvaluation {
        verdict,
        next_soft_due_ns,
        cpu_until_next_ns: next.map(|point| point.saturating_sub(cpu_ns)),
    }
}

/// Wall time to wait before `remaining_cpu_ns` more CPU could have been
/// consumed by `running_guest_threads` threads running flat out. A task with
/// no thread in guest code right now can still enter one, so the divisor is
/// never below 1.
fn recheck_delay(remaining_cpu_ns: u64, running_guest_threads: u64) -> Duration {
    Duration::from_nanos(remaining_cpu_ns.div_ceil(running_guest_threads.max(1)))
        .clamp(MIN_RECHECK, MAX_RECHECK)
}

#[derive(Debug, Default)]
struct WatchState {
    /// Whether a watchdog thread is alive for this kernel.
    running: bool,
    /// Bumped by every [`CpuLimitWatch::ensure_watching`]. A scan that found
    /// no finite limit lets the thread exit only if no nudge arrived while it
    /// scanned — a fork's child can be published after the scan snapshotted
    /// the task set but before its parent gave up its own limit.
    nudges: u64,
    /// Per-task CPU point of the next `SIGXCPU`; pruned to live finite-limit
    /// tasks on every scan.
    soft_due_ns: BTreeMap<TaskKey, u64>,
}

#[derive(Debug, Default)]
struct WatchInner {
    state: Mutex<WatchState>,
    wake: Condvar,
}

/// The kernel's `RLIMIT_CPU` watchdog: see the module documentation.
///
/// The watchdog thread shares only [`WatchInner`], never the kernel itself,
/// so a sleeping watchdog never keeps a torn-down kernel alive.
#[derive(Debug, Default)]
pub(crate) struct CpuLimitWatch {
    inner: Arc<WatchInner>,
}

impl CpuLimitWatch {
    /// A finite `RLIMIT_CPU` may now exist on `task`: make sure the watchdog
    /// is running and has it in view. Cheap and idempotent; a task whose
    /// limit is infinite both ways needs no watching and is ignored.
    pub(crate) fn ensure_watching(&self, kernel: &Arc<Kernel>, task: &Task) {
        let limit = task.rlimit(LinuxResource::Cpu);
        if limit.rlim_cur == LINUX_RLIM_INFINITY && limit.rlim_max == LINUX_RLIM_INFINITY {
            return;
        }
        let mut state = self.inner.state.lock();
        state.nudges = state.nudges.wrapping_add(1);
        if !state.running {
            let weak = Arc::downgrade(kernel);
            let inner = Arc::clone(&self.inner);
            match std::thread::Builder::new()
                .name("carrick-cpu-limit".to_owned())
                .spawn(move || Self::drive(weak, inner))
            {
                Ok(_) => state.running = true,
                Err(error) => {
                    tracing::error!(%error, "RLIMIT_CPU watchdog thread could not start");
                }
            }
        }
        self.inner.wake.notify_one();
    }

    fn drive(kernel: Weak<Kernel>, inner: Arc<WatchInner>) {
        loop {
            let delay = {
                let Some(kernel) = kernel.upgrade() else {
                    return;
                };
                let nudges_seen = inner.state.lock().nudges;
                (kernel.cpu_limit_watch().scan_once(&kernel), nudges_seen)
            };
            let mut state = inner.state.lock();
            match delay {
                (Some(delay), _) => {
                    inner.wake.wait_for(&mut state, delay);
                }
                (None, nudges_seen) if state.nudges == nudges_seen => {
                    state.running = false;
                    return;
                }
                (None, _) => {}
            }
        }
    }

    /// Judge every finite-limit task once, deliver what is due, and return how
    /// long to wait before the next scan — `None` when no task has a finite
    /// limit any more.
    pub(crate) fn scan_once(&self, kernel: &Kernel) -> Option<Duration> {
        let tasks: Vec<Arc<Task>> = kernel
            .registry()
            .state
            .read()
            .tasks
            .values()
            .map(|record| Arc::clone(&record.task))
            .collect();
        let mut next_soft_due = BTreeMap::new();
        let mut delay: Option<Duration> = None;
        let previous = std::mem::take(&mut self.inner.state.lock().soft_due_ns);
        for task in tasks {
            let limit = task.rlimit(LinuxResource::Cpu);
            if limit.rlim_cur == LINUX_RLIM_INFINITY && limit.rlim_max == LINUX_RLIM_INFINITY {
                continue;
            }
            let key = task.key();
            let sample = task.sample_cpu_including_active();
            let evaluation = evaluate(limit, sample.cpu_ns, previous.get(&key).copied());
            match evaluation.verdict {
                CpuLimitVerdict::Hard => {
                    Self::deliver(kernel, key, carrick_abi::LINUX_SIGKILL);
                    continue;
                }
                CpuLimitVerdict::Soft => {
                    Self::deliver(kernel, key, carrick_abi::LINUX_SIGXCPU);
                }
                CpuLimitVerdict::Within => {}
            }
            if let Some(due) = evaluation.next_soft_due_ns {
                next_soft_due.insert(key, due);
            }
            if let Some(remaining) = evaluation.cpu_until_next_ns {
                let candidate = recheck_delay(remaining, sample.running_guest_threads);
                delay = Some(delay.map_or(candidate, |current| current.min(candidate)));
            }
        }
        self.inner.state.lock().soft_due_ns = next_soft_due;
        delay
    }

    fn deliver(kernel: &Kernel, task: TaskKey, signum: i32) {
        if let Ok(signal) = LinuxSignal::for_signal_number(signum) {
            // A false return means the exact task generation is gone; the
            // next scan no longer sees it.
            let _ = kernel.post_signal_to_task_key(task, signal, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(cur: u64, max: u64) -> LinuxRlimit {
        LinuxRlimit::new(cur, max)
    }

    #[test]
    fn within_both_limits_schedules_the_soft_point() {
        let e = evaluate(limit(1, 2), 400_000_000, None);
        assert_eq!(e.verdict, CpuLimitVerdict::Within);
        assert_eq!(e.next_soft_due_ns, Some(NS_PER_S));
        assert_eq!(e.cpu_until_next_ns, Some(600_000_000));
    }

    #[test]
    fn soft_limit_fires_then_repeats_once_per_second() {
        let first = evaluate(limit(1, 5), NS_PER_S, None);
        assert_eq!(first.verdict, CpuLimitVerdict::Soft);
        assert_eq!(first.next_soft_due_ns, Some(2 * NS_PER_S));
        // 300 ms later it is not yet due again.
        let quiet = evaluate(limit(1, 5), NS_PER_S + 300_000_000, first.next_soft_due_ns);
        assert_eq!(quiet.verdict, CpuLimitVerdict::Within);
        assert_eq!(quiet.cpu_until_next_ns, Some(700_000_000));
        // A second of CPU later it fires again.
        let again = evaluate(limit(1, 5), 2 * NS_PER_S + 1, first.next_soft_due_ns);
        assert_eq!(again.verdict, CpuLimitVerdict::Soft);
    }

    #[test]
    fn hard_limit_wins_and_ends_scheduling() {
        let e = evaluate(limit(1, 2), 2 * NS_PER_S, Some(3 * NS_PER_S));
        assert_eq!(e.verdict, CpuLimitVerdict::Hard);
        assert_eq!(e.cpu_until_next_ns, None);
    }

    #[test]
    fn infinite_soft_with_finite_hard_only_waits_for_the_hard_point() {
        let e = evaluate(limit(LINUX_RLIM_INFINITY, 3), NS_PER_S, None);
        assert_eq!(e.verdict, CpuLimitVerdict::Within);
        assert_eq!(e.next_soft_due_ns, None);
        assert_eq!(e.cpu_until_next_ns, Some(2 * NS_PER_S));
    }

    #[test]
    fn raising_the_soft_limit_moves_the_next_delivery_out() {
        let e = evaluate(limit(10, 20), 5 * NS_PER_S, Some(2 * NS_PER_S));
        assert_eq!(e.verdict, CpuLimitVerdict::Within);
        assert_eq!(e.next_soft_due_ns, Some(10 * NS_PER_S));
    }

    fn pending(task: &Task) -> Vec<i32> {
        task.shared()
            .pending_signals()
            .snapshot_entries()
            .into_iter()
            .map(|entry| entry.signal.raw())
            .collect()
    }

    #[test]
    fn scan_delivers_sigxcpu_then_sigkill_from_the_task_own_cpu() {
        let bootstrap = super::super::RootBootstrap::for_reference_model(
            100,
            crate::thread::ThreadId::synthetic_for_tests(100),
            "cpu-limit".to_string(),
        )
        .expect("root bootstrap");
        let (kernel, context) = Kernel::bootstrap_root(bootstrap).expect("root kernel");
        let watch = kernel.cpu_limit_watch();

        // No finite limit anywhere: nothing to watch.
        assert_eq!(watch.scan_once(&kernel), None);

        context
            .task()
            .replace_rlimit(LinuxResource::Cpu, |_| Ok::<_, ()>(limit(10, 20)))
            .expect("set cpu limit");
        // 5 s consumed: under the soft limit; the next look is due within a
        // second (the wall-clock cap) and nothing is pending.
        context.thread().charge_user_ns(5 * NS_PER_S);
        assert_eq!(watch.scan_once(&kernel), Some(MAX_RECHECK));
        assert!(pending(context.task()).is_empty());

        // 15 s: past the soft limit → exactly one SIGXCPU, and the task is
        // still to be watched.
        context.thread().charge_user_ns(10 * NS_PER_S);
        assert!(watch.scan_once(&kernel).is_some());
        assert_eq!(pending(context.task()), vec![carrick_abi::LINUX_SIGXCPU]);
        // Another 300 ms of CPU is not another second: no repeat yet.
        context.thread().charge_user_ns(300_000_000);
        assert!(watch.scan_once(&kernel).is_some());
        assert_eq!(pending(context.task()), vec![carrick_abi::LINUX_SIGXCPU]);

        // 25 s: past the hard limit → SIGKILL.
        context.thread().charge_user_ns(10 * NS_PER_S);
        watch.scan_once(&kernel);
        assert!(pending(context.task()).contains(&carrick_abi::LINUX_SIGKILL));
    }

    #[test]
    fn recheck_delay_is_bounded_and_scaled_by_threads() {
        assert_eq!(recheck_delay(0, 1), MIN_RECHECK);
        assert_eq!(recheck_delay(100 * NS_PER_S, 1), MAX_RECHECK);
        assert_eq!(recheck_delay(400_000_000, 4), Duration::from_millis(100));
    }
}
