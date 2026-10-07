//! How an armed timer SLOT becomes a delivered signal — the per-backend
//! mechanism behind the neutral `carrick-timer-core` slot/registry bookkeeping.
//! HVF arms an `EVFILT_TIMER` on its kqueue signal pump (so a busy vCPU is
//! kicked on expiry); KVM has no pump, so `arm_itimer` returns `false` and the
//! caller spawns the shared wall-clock fallback thread
//! (`carrick_timer_core::itimer::run_fallback`). The trait PERMITS divergence:
//! the slot/spec/remaining math is shared verbatim (timer-core), only the
//! delivery glue differs.
//!
//! `signum`/`si_value` for a POSIX timer are captured at `timer_create` (carried
//! on the slot), NOT at arm time — so `arm_posix` takes only `id` + the
//! value/interval spec, matching `carrick_timer_core::posix::arm`.
use std::sync::Arc;

use crate::threaded::VcpuRegistry;

pub use crate::posix_timer::PosixTimerSpec;
pub use carrick_timer_core::TimerSpecNs;
pub use carrick_timer_core::itimer::TimerArm;

/// Arm a POSIX per-process timer using the shared fallback firing thread.
///
/// KVM, bhyve, and NVMM all lack the HVF kqueue timer pump path, so their
/// delivery sequence is identical: mutate the neutral timer-core slot, spawn a
/// per-arm fallback thread, publish the process-directed Linux signal, and kick
/// every vCPU so any unblocked guest thread can observe it.
pub fn arm_fallback_posix_timer(
    id: i32,
    spec: TimerSpecNs,
    kicker: &Arc<dyn VcpuRegistry>,
) -> Option<PosixTimerSpec> {
    let armed = crate::posix_timer::arm(id, spec)?;
    if spec.value > 0 {
        let signum = armed.signum;
        let generation = armed.generation;
        let slot = armed.slot.clone();
        let kicker = Arc::clone(kicker);
        let on_fire = move || {
            carrick_signal_linux::publish_process_signal(signum);
            kicker.kick_all();
        };
        let _ = std::thread::Builder::new()
            .name(format!("carrick-ptimer-{id}"))
            .spawn(move || {
                crate::posix_timer::run_fallback(slot, generation, spec, on_fire);
            });
    }
    Some(armed.old)
}

/// Disarm a POSIX timer driven by [`arm_fallback_posix_timer`].
///
/// `TimerSpecNs::DISARM` bumps the timer-core generation, causing any in-flight
/// fallback thread to retire before it can publish another signal.
pub fn disarm_fallback_posix_timer(id: i32) {
    let _ = crate::posix_timer::arm(id, TimerSpecNs::DISARM);
}

/// Shared fallback-timer timing loop body for interval timers.
pub fn run_fallback(which: usize, generation: u64, spec: TimerSpecNs, on_fire: impl Fn()) {
    run_fallback_with_sampler(which, generation, spec, None, on_fire);
}

/// Shared fallback-timer timing loop body with an optional CPU sampler.
///
/// Every delivery goes through `carrick_timer_core::itimer::fire_*_if_current`,
/// which checks this worker's `generation`, decides expiry and runs `on_fire`
/// under the slot gate: once a `setitimer` arm/disarm of `which` returns, this
/// worker (if superseded) can neither deliver nor touch the slot again.
/// `on_fire` runs under that gate, so it must not call back into
/// `carrick_timer_core::itimer` for the same `which`.
pub fn run_fallback_with_sampler(
    which: usize,
    generation: u64,
    spec: TimerSpecNs,
    cpu_sampler: Option<&dyn carrick_timer_core::CpuSampler>,
    on_fire: impl Fn(),
) {
    if carrick_timer_core::itimer::is_cpu_timer(which) {
        run_fallback_cpu(which, generation, cpu_sampler, &on_fire);
        return;
    }
    std::thread::sleep(std::time::Duration::from_nanos(spec.value));
    while carrick_timer_core::itimer::fire_wall_if_current(which, generation, &on_fire)
        == carrick_timer_core::itimer::FireOutcome::Fired
    {
        std::thread::sleep(std::time::Duration::from_nanos(spec.interval));
    }
}

/// CPU-itimer fallback poll loop. Drives delivery off the aggregate guest CPU total.
pub fn run_fallback_cpu(
    which: usize,
    generation: u64,
    cpu_sampler: Option<&dyn carrick_timer_core::CpuSampler>,
    on_fire: &impl Fn(),
) {
    use carrick_timer_core::itimer::FireOutcome;
    loop {
        // Sample OUTSIDE the slot gate (the sampler reads host CPU counters);
        // the expiry decision against the live arm happens under it.
        let now_ns = cpu_sampler.map_or(0, |s| s.total_cpu_ns());
        let active_vcpus = cpu_sampler.map_or(0, |s| s.active_vcpus());
        match carrick_timer_core::itimer::fire_cpu_if_current(
            which,
            generation,
            now_ns,
            active_vcpus,
            on_fire,
        ) {
            FireOutcome::Fired => {}
            FireOutcome::Wait { delay_ns } => {
                std::thread::sleep(std::time::Duration::from_nanos(delay_ns.raw()));
            }
            FireOutcome::Retired => break,
        }
    }
}

pub trait TimerDelivery: Send + Sync {
    /// Whether this delivery object owns interval-timer slot state itself.
    ///
    /// The mature VMM/native implementations use the process-global
    /// `carrick-timer-core` slots because one host process represents one Linux
    /// process. HVPatch multiplexes multiple Linux processes as host threads,
    /// so its per-dispatcher delivery must keep independent slots and the
    /// dispatcher must not mutate the global slots before calling it.
    fn owns_itimer_state(&self) -> bool {
        false
    }

    /// Arm interval timer `which`. The neutral slot state is written by the
    /// caller into timer-core FIRST (via `carrick_timer_core::itimer::arm`);
    /// this method initiates DELIVERY. Returns `true` if the backend OWNS
    /// delivery (HVF armed an `EVFILT_TIMER` on the pump kq); `false` → the
    /// caller spawns the shared wall-clock fallback thread (KVM, or an HVF
    /// process that has no pump kqueue yet).
    fn arm_itimer(
        &self,
        which: usize,
        spec: TimerSpecNs,
        needs_periodic: bool,
        signum: i32,
    ) -> bool;

    /// Disarm interval timer `which` (clear the slot + tear down any backend
    /// delivery, e.g. delete the `EVFILT_TIMER`).
    fn disarm_itimer(&self, which: usize);

    /// (Re-)arm POSIX per-process timer `id`. `signum`/`si_value` were captured
    /// at `timer_create` and live on the slot, so only the value/interval spec
    /// is passed here. Returns the PREVIOUS spec (`timer_settime`'s
    /// `old_value`), or `None` for an unknown id. A `spec.value == 0` disarms.
    /// Delegates slot mutation to `carrick_timer_core::posix::arm`; the backend
    /// spawns its firing mechanism (KVM/HVF: a wall-clock thread).
    fn arm_posix(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec>;

    /// Disarm POSIX timer `id` (a `spec.value == 0` arm); bumps generation so
    /// any in-flight firing thread retires.
    fn disarm_posix(&self, id: i32);

    /// Reconstruct the current arm for fork replay (HVF re-applies the
    /// `EVFILT_TIMER` on the fresh pump kq; KVM re-spawns the fallback thread).
    /// `None` if `which` is disarmed.
    fn current_arm(&self, which: usize) -> Option<TimerArm>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{
        GenericVcpuRegistry, ThreadId, VcpuKickDyn, VcpuRegistrationEnrollment, VcpuRegistry,
    };

    struct CountingKick(Arc<AtomicU64>);

    impl VcpuKickDyn for CountingKick {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn fallback_posix_timer_publishes_process_signal_and_kicks_all() {
        // Serialise against the other tests over the same process-global
        // registry and pending store (`guest_timer_bridge::tests`).
        let _serial = crate::guest_timer_bridge::TIMER_REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::posix_timer::clear();
        carrick_signal_linux::clear_proc_pending();

        let kicks = Arc::new(AtomicU64::new(0));
        let registry = Arc::new(GenericVcpuRegistry::new());
        let in_guest = crate::InGuestFlag::for_guest_thread();
        assert!(matches!(
            registry.subscribe_register(
                ThreadId::synthetic_for_tests(1),
                Box::new(CountingKick(Arc::clone(&kicks))),
                &in_guest,
                Arc::new(|| {}),
            ),
            VcpuRegistrationEnrollment::Registered
        ));
        let kicker: Arc<dyn VcpuRegistry> = registry;
        let id = crate::posix_timer::create(0, 14);

        let old = arm_fallback_posix_timer(
            id,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
            &kicker,
        )
        .expect("known timer id should arm");

        assert_eq!(old.signum, 14);
        let deadline = Instant::now() + Duration::from_secs(1);
        while kicks.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        assert_eq!(carrick_signal_linux::take_process_pending(), 14);

        disarm_fallback_posix_timer(id);
        let _ = crate::posix_timer::delete(id);
        carrick_signal_linux::clear_proc_pending();
    }

    use crate::guest_timer_bridge::TIMER_REGISTRY_TEST_LOCK as TEST_LOCK;

    #[derive(Clone, Copy, Debug, Default)]
    struct MockCpuSampler(u64, u64);

    impl carrick_timer_core::CpuSampler for MockCpuSampler {
        fn total_cpu_ns(&self) -> u64 {
            self.0
        }

        fn active_vcpus(&self) -> u64 {
            self.1
        }
    }

    #[test]
    fn run_fallback_cpu_one_shot_fires_once_when_cpu_advances() {
        use std::sync::atomic::AtomicUsize;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_timer_core::itimer::clear();
        let which = 1; // VIRTUAL, one-shot
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 0,
        };
        let generation = carrick_timer_core::itimer::arm_with_cpu_now(which, spec, false, 0);
        let sampler = MockCpuSampler(10_000, 1);
        let fires = Arc::new(AtomicUsize::new(0));
        let fires2 = Arc::clone(&fires);
        run_fallback_with_sampler(which, generation, spec, Some(&sampler), move || {
            fires2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            fires.load(Ordering::SeqCst),
            1,
            "one-shot CPU timer fires once"
        );
        carrick_timer_core::itimer::disarm(which);
    }

    /// A CPU sampler that parks the fallback worker on its FIRST sample —
    /// i.e. after the worker has observed the arm it was spawned for, before
    /// its expiry decision — until the test has mutated the slot, then reports
    /// `now_ns` guest CPU. This forces the disarm/re-arm-vs-fire interleaving
    /// deterministically instead of racing a spawned thread against the test.
    struct ParkingCpuSampler {
        now_ns: u64,
        park: std::sync::Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    }

    impl carrick_timer_core::CpuSampler for ParkingCpuSampler {
        fn total_cpu_ns(&self) -> u64 {
            let park = self
                .park
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some((parked, resume)) = park {
                parked.send(()).expect("test observes the parked worker");
                resume
                    .recv_timeout(PARK_BOUND)
                    .expect("test resumes the parked worker");
            }
            self.now_ns
        }

        fn active_vcpus(&self) -> u64 {
            1
        }
    }

    use std::sync::mpsc;

    const PARK_BOUND: Duration = Duration::from_secs(5);

    /// Spawn a CPU-itimer fallback worker for `which`/`generation` whose first
    /// sample parks; returns once the worker is parked, with the fire counter,
    /// the resume sender and the worker handle.
    fn spawn_parked_cpu_worker(
        which: usize,
        generation: u64,
        spec: TimerSpecNs,
        now_ns: u64,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let (parked_tx, parked_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let sampler = ParkingCpuSampler {
            now_ns,
            park: std::sync::Mutex::new(Some((parked_tx, resume_rx))),
        };
        let fires = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fires2 = Arc::clone(&fires);
        let runner = std::thread::spawn(move || {
            run_fallback_with_sampler(which, generation, spec, Some(&sampler), move || {
                fires2.fetch_add(1, Ordering::SeqCst);
            });
        });
        parked_rx
            .recv_timeout(PARK_BOUND)
            .expect("fallback worker reaches its first CPU sample");
        (fires, resume_tx, runner)
    }

    #[test]
    fn run_fallback_cpu_retires_on_generation_bump() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_timer_core::itimer::clear();
        let which = 1;
        let spec = TimerSpecNs {
            value: 1_000_000,
            interval: 1_000_000,
        };
        let generation = carrick_timer_core::itimer::arm_with_cpu_now(which, spec, false, 0);
        // The worker has seen its live arm and is about to decide expiry; the
        // CPU total it will report has reached the due point exactly.
        let (fires, resume, runner) = spawn_parked_cpu_worker(which, generation, spec, 1_000_000);
        // `disarm` returns before the worker's decision: the retired arm must
        // never deliver, even though its expiry is reached afterwards.
        carrick_timer_core::itimer::disarm(which);
        resume.send(()).expect("worker still parked");
        runner.join().expect("runner thread terminates");
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "a fallback worker fired for an arm disarmed before its expiry decision"
        );
    }

    #[test]
    fn run_fallback_cpu_stale_worker_leaves_replacement_arm_alone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_timer_core::itimer::clear();
        let which = 1;
        let old_spec = TimerSpecNs {
            value: 1_000_000,
            interval: 1_000_000,
        };
        let old_generation =
            carrick_timer_core::itimer::arm_with_cpu_now(which, old_spec, false, 0);
        let (fires, resume, runner) =
            spawn_parked_cpu_worker(which, old_generation, old_spec, 1_000_000);
        // Replace the arm with a one-shot that is already due. Its own worker
        // (not spawned here) owns that expiry; the stale worker must neither
        // deliver it nor retire the replacement slot.
        let new_spec = TimerSpecNs {
            value: 500,
            interval: 0,
        };
        let new_generation =
            carrick_timer_core::itimer::arm_with_cpu_now(which, new_spec, false, 0);
        resume.send(()).expect("worker still parked");
        runner.join().expect("runner thread terminates");
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "a stale fallback worker delivered the replacement arm's expiry"
        );
        assert!(
            carrick_timer_core::itimer::is_armed(which),
            "a stale fallback worker retired the replacement arm"
        );
        assert_eq!(
            carrick_timer_core::itimer::generation(which),
            new_generation
        );
        carrick_timer_core::itimer::disarm(which);
    }

    #[test]
    fn run_fallback_real_retires_on_generation_bump() {
        use std::sync::atomic::AtomicUsize;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_timer_core::itimer::clear();
        let which = 0;
        let spec = TimerSpecNs {
            value: 1,
            interval: 1,
        };
        let generation = carrick_timer_core::itimer::arm(which, spec, false);
        // The disarm is ordered before the worker runs at all: a worker for a
        // retired generation must not deliver.
        carrick_timer_core::itimer::disarm(which);
        let fires = AtomicUsize::new(0);
        run_fallback(which, generation, spec, || {
            fires.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(fires.load(Ordering::SeqCst), 0);
    }
}
