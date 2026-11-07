//! Bounded host `ClockDomain` resource adapter for ring-owned processes.
//!
//! Serves the fixed-size `carrick_core_abi::clock` wire protocol without
//! blocking any vCPU executor thread or routing Linux syscalls through the
//! legacy root dispatcher.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use carrick_abi::{
    LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME, LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_TAI,
    LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EINVAL, LINUX_EOPNOTSUPP, LINUX_EPERM, LinuxTimeval,
    LinuxTimex,
};
use carrick_core_abi::clock::{
    CLOCK_RECORD_BYTES, CLOCK_TIMEX_BYTES, ClockRecordError, ClockRequest, ClockSleepArmOutcome,
    ClockSleepChannel, ClockSleepFlags, parse_request, write_errno_reply, write_sample_reply,
    write_sleep_arm_reply, write_sleep_cancel_reply, write_timex_apply_reply,
    write_timex_preflight_ok,
};
use carrick_sched_core::object_wait::ObjectWaitKey;
use carrick_sched_core::{HostPlacement, LockWait, RecordRef, ZoneTables};
use carrick_time_core::{TimexAccess, TimexRequest, TimexValidationError};
use zerocopy::{FromBytes, IntoBytes};

use crate::dispatch::format_time::{dynamic_cpu_clock, linux_coarse_duration};
use crate::kernel::container::{
    ClockChangeEnrollment, ClockChangeSubscription, ClockDomain, DeterministicWaiterSubscription,
};

/// Non-blocking wakeup hook invoked when an armed native sleep expires or its
/// underlying clock changes.
pub trait ClockSleepWaker: Send + Sync {
    fn wake_sleep(&self, channel: ClockSleepChannel);
}

/// Waker that wakes a native process member in the process-wide `el1_zone`.
#[derive(Debug, Default, Clone, Copy)]
pub struct El1ZoneClockSleepWaker;

impl ClockSleepWaker for El1ZoneClockSleepWaker {
    fn wake_sleep(&self, channel: ClockSleepChannel) {
        crate::el1_zone::wake_native_sleep_channel(channel);
    }
}

/// Generic zone sleep wakeup sequence reusable by x86 CPL0 and VM-free test
/// harnesses: increments the member's `native_service` queue epoch first (no
/// nested locks) and then wakes its futex/signal wait channel.
pub fn wake_sleep_channel_in_zone<C>(
    zone: &ZoneTables<C>,
    wait: &impl LockWait<C>,
    schedules_in_guest: bool,
    channel: ClockSleepChannel,
    handed: &mut impl FnMut(RecordRef),
    placed: &mut impl FnMut(HostPlacement),
) where
    C: Copy + Send + Sync + zerocopy::FromZeros,
{
    if let Some(id) = carrick_el1_abi::RecordId::from_raw(channel.record_id) {
        let record = RecordRef {
            id,
            incarnation: channel.record_generation,
        };
        if let Some(key) = ObjectWaitKey::native_service(record)
            && let Ok(queue) = zone.object_wait(key, wait)
        {
            let _ = queue.notify_object_host(handed, placed);
        }
    }
    let mut transfers = Vec::new();
    if let Some(guard) = zone.lock(
        ZoneTables::<C>::bucket_of_with_context(channel.mm, channel.address.get()),
        wait,
    ) {
        zone.wake_host(
            &guard,
            channel.mm,
            channel.address.get(),
            u32::MAX,
            u32::MAX,
            schedules_in_guest,
            &mut |transfer| transfers.push(transfer),
            placed,
        );
    }
    for transfer in transfers {
        if let Some(record) = transfer.finish(wait) {
            handed(record);
        }
    }
}

struct ArmedSleep {
    channel: ClockSleepChannel,
    host_due: Option<Instant>,
    fired: bool,
    _clock_change: Option<ClockChangeSubscription>,
    _deterministic: Option<DeterministicWaiterSubscription>,
}

struct TimerState {
    shutdown: bool,
    sleeps: BTreeMap<NonZeroU64, ArmedSleep>,
}

struct TimerHub {
    state: Mutex<TimerState>,
    cvar: Condvar,
    waker: Arc<dyn ClockSleepWaker>,
}

/// Run-scoped host adapter serving `carrick_core_abi::clock` records against
/// one container's [`ClockDomain`].
pub struct ClockResourceService {
    clock: Arc<ClockDomain>,
    hub: Arc<TimerHub>,
    next_sleep_id: AtomicU64,
    worker_started: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for ClockResourceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockResourceService")
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl ClockResourceService {
    pub fn new(clock: Arc<ClockDomain>, waker: Arc<dyn ClockSleepWaker>) -> Self {
        Self {
            clock,
            hub: Arc::new(TimerHub {
                state: Mutex::new(TimerState {
                    shutdown: false,
                    sleeps: BTreeMap::new(),
                }),
                cvar: Condvar::new(),
                waker,
            }),
            next_sleep_id: AtomicU64::new(1),
            worker_started: AtomicBool::new(false),
            worker: Mutex::new(None),
        }
    }

    pub fn clock(&self) -> &Arc<ClockDomain> {
        &self.clock
    }

    /// Validate and answer one 256-byte staged clock-resource record in place.
    pub fn serve_record(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
    ) -> Result<(), ClockRecordError> {
        let request = parse_request(bytes)?;
        match request {
            ClockRequest::Sample { clock_id } => {
                match sample_container_clock(&self.clock, clock_id) {
                    Ok(now) => write_sample_reply(bytes, now.as_secs(), now.subsec_nanos()),
                    Err(errno) => write_errno_reply(bytes, errno),
                }
            }
            ClockRequest::TimexPreflight { can_adjust, timex } => {
                let timex = *timex;
                self.serve_timex_preflight(bytes, can_adjust, &timex)
            }
            ClockRequest::TimexApply { can_adjust, timex } => {
                let timex = *timex;
                self.serve_timex_apply(bytes, can_adjust, &timex)
            }
            ClockRequest::SleepArm {
                clock_id,
                flags,
                sleep_id,
                secs,
                nanos,
                channel,
            } => self.serve_sleep_arm(bytes, clock_id, flags, sleep_id, secs, nanos, channel),
            ClockRequest::SleepCancel {
                sleep_id,
                clock_id: _,
                compute_remaining,
                deadline_secs,
                deadline_nanos,
            } => {
                self.cancel_sleep_entry(sleep_id);
                let remaining = if compute_remaining {
                    Duration::new(deadline_secs, deadline_nanos)
                        .saturating_sub(self.clock.monotonic_now())
                } else {
                    Duration::ZERO
                };
                write_sleep_cancel_reply(bytes, remaining.as_secs(), remaining.subsec_nanos())
            }
        }
    }

    fn serve_timex_preflight(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
        can_adjust: bool,
        raw_timex: &[u8; CLOCK_TIMEX_BYTES],
    ) -> Result<(), ClockRecordError> {
        let Ok(parsed) = LinuxTimex::read_from_bytes(raw_timex) else {
            return Err(ClockRecordError::Invalid);
        };
        let access = if can_adjust {
            TimexAccess::Adjust
        } else {
            TimexAccess::ReadOnly
        };
        let request = match TimexRequest::validate(&parsed, access) {
            Ok(req) => req,
            Err(TimexValidationError::Errno(errno)) => {
                return write_errno_reply(bytes, errno.get());
            }
            Err(TimexValidationError::InvalidModeOutput) => {
                return write_errno_reply(bytes, LINUX_EINVAL.get());
            }
        };
        let step = match request.realtime_step(|| {
            carrick_abi::LinuxTimexStatus::from_bits_retain(self.clock.adjtimex_state().status)
        }) {
            Ok(step) => step,
            Err(errno) => return write_errno_reply(bytes, errno.get()),
        };
        if step.is_some() && self.clock.is_controlled() {
            return write_errno_reply(bytes, LINUX_EPERM.get());
        }
        write_timex_preflight_ok(bytes)
    }

    fn serve_timex_apply(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
        can_adjust: bool,
        raw_timex: &[u8; CLOCK_TIMEX_BYTES],
    ) -> Result<(), ClockRecordError> {
        let Ok(parsed) = LinuxTimex::read_from_bytes(raw_timex) else {
            return Err(ClockRecordError::Invalid);
        };
        let access = if can_adjust {
            TimexAccess::Adjust
        } else {
            TimexAccess::ReadOnly
        };
        let request = match TimexRequest::validate(&parsed, access) {
            Ok(req) => req,
            Err(TimexValidationError::Errno(errno)) => {
                return write_errno_reply(bytes, errno.get());
            }
            Err(TimexValidationError::InvalidModeOutput) => {
                return write_errno_reply(bytes, LINUX_EINVAL.get());
            }
        };
        let mut output = LinuxTimex::new_read_state(LinuxTimeval::new(0, 0));
        match self.clock.apply_timex(&request, &mut output) {
            Ok(value) => {
                let out_bytes: &[u8; CLOCK_TIMEX_BYTES] = output
                    .as_bytes()
                    .try_into()
                    .map_err(|_| ClockRecordError::Invalid)?;
                write_timex_apply_reply(bytes, value, out_bytes)
            }
            Err(errno) => write_errno_reply(bytes, errno.get()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_sleep_arm(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
        clock_id: u64,
        flags: ClockSleepFlags,
        existing_id: Option<NonZeroU64>,
        secs: u64,
        nanos: u32,
        channel: ClockSleepChannel,
    ) -> Result<(), ClockRecordError> {
        let input = Duration::new(secs, nanos);
        let realtime_family = is_realtime_sleep_clock(clock_id);
        let mut pinned_relative_deadline: Option<Duration> =
            (!flags.is_absolute() && flags.has_pinned_deadline()).then_some(input);

        loop {
            let (snapshot_gen, snapshot_res) = self.clock.with_clock_change_snapshot(|| {
                let now = sample_sleep_clock(&self.clock, clock_id)?;
                if flags.is_absolute() {
                    if input <= now {
                        return Ok(None);
                    }
                    let wait_guest = input.saturating_sub(now);
                    Ok(Some((input, wait_guest)))
                } else {
                    if !flags.has_pinned_deadline() && input.is_zero() {
                        return Ok(None);
                    }
                    let mono_now = self.clock.monotonic_now();
                    let deadline = *pinned_relative_deadline
                        .get_or_insert_with(|| mono_now.saturating_add(input));
                    if deadline <= mono_now {
                        return Ok(None);
                    }
                    let wait_guest = deadline.saturating_sub(mono_now);
                    Ok(Some((deadline, wait_guest)))
                }
            });

            let (deadline, wait_guest) = match snapshot_res {
                Err(errno) => {
                    if let Some(id) = existing_id {
                        self.cancel_sleep_entry(id);
                    }
                    return write_errno_reply(bytes, errno);
                }
                Ok(None) => {
                    if let Some(id) = existing_id {
                        self.cancel_sleep_entry(id);
                    }
                    return write_sleep_arm_reply(bytes, ClockSleepArmOutcome::Elapsed);
                }
                Ok(Some(pair)) => pair,
            };

            let clock_change = if flags.is_absolute() && realtime_family {
                let waker = Arc::clone(&self.hub.waker);
                match self.clock.subscribe_clock_change(
                    snapshot_gen,
                    Arc::new(move || waker.wake_sleep(channel)),
                ) {
                    ClockChangeEnrollment::Ready(_) => continue,
                    ClockChangeEnrollment::Subscribed(sub) => Some(sub),
                }
            } else {
                None
            };

            let id = match existing_id {
                Some(id) => id,
                None => self.allocate_sleep_id(),
            };

            // Remove any prior subscriptions outside the timer lock before installing replacements.
            let old = self
                .hub
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .sleeps
                .remove(&id);
            drop(old);

            let (host_due, deterministic) = if self.clock.is_deterministic() {
                let due_monotonic = if flags.is_absolute() && realtime_family {
                    Some(deadline.saturating_sub(self.clock.realtime_epoch_duration()))
                } else {
                    Some(deadline)
                };
                let waker = Arc::clone(&self.hub.waker);
                let sub = self
                    .clock
                    .enroll_deterministic_waiter(due_monotonic, move || waker.wake_sleep(channel));
                (None, sub)
            } else if flags.is_absolute() && realtime_family && self.clock.is_frozen() {
                (None, None)
            } else {
                let host_wait = self.clock.scale_timeout(wait_guest);
                if host_wait.is_zero() {
                    drop(clock_change);
                    return write_sleep_arm_reply(bytes, ClockSleepArmOutcome::Elapsed);
                }
                (Instant::now().checked_add(host_wait), None)
            };

            if host_due.is_some() {
                self.ensure_worker();
            }

            {
                let mut state = self.hub.state.lock().unwrap_or_else(|p| p.into_inner());
                if !state.shutdown {
                    state.sleeps.insert(
                        id,
                        ArmedSleep {
                            channel,
                            host_due,
                            fired: false,
                            _clock_change: clock_change,
                            _deterministic: deterministic,
                        },
                    );
                    if host_due.is_some() {
                        self.hub.cvar.notify_all();
                    }
                }
            }

            return write_sleep_arm_reply(
                bytes,
                ClockSleepArmOutcome::Armed {
                    sleep_id: id,
                    deadline_secs: deadline.as_secs(),
                    deadline_nanos: deadline.subsec_nanos(),
                },
            );
        }
    }

    fn cancel_sleep_entry(&self, id: NonZeroU64) {
        let removed = self
            .hub
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sleeps
            .remove(&id);
        drop(removed);
    }

    fn allocate_sleep_id(&self) -> NonZeroU64 {
        loop {
            let raw = self.next_sleep_id.fetch_add(1, Ordering::Relaxed);
            if let Some(id) = NonZeroU64::new(raw) {
                return id;
            }
        }
    }

    fn ensure_worker(&self) {
        if self.worker_started.load(Ordering::Acquire) {
            return;
        }
        let mut guard = self.worker.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            self.worker_started.store(true, Ordering::Release);
            return;
        }
        let hub = Arc::clone(&self.hub);
        if let Ok(handle) = std::thread::Builder::new()
            .name("carrick-native-clock".to_owned())
            .spawn(move || run_timer_worker(hub))
        {
            *guard = Some(handle);
            self.worker_started.store(true, Ordering::Release);
        }
    }
}

impl Drop for ClockResourceService {
    fn drop(&mut self) {
        let drained = {
            let mut state = self.hub.state.lock().unwrap_or_else(|p| p.into_inner());
            state.shutdown = true;
            self.hub.cvar.notify_all();
            std::mem::take(&mut state.sleeps)
        };
        drop(drained);
        let handle = self.worker.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

fn run_timer_worker(hub: Arc<TimerHub>) {
    let mut due_channels = Vec::new();
    loop {
        due_channels.clear();
        let next_due = {
            let mut state = hub.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.shutdown {
                return;
            }
            let now = Instant::now();
            let mut earliest: Option<Instant> = None;
            for sleep in state.sleeps.values_mut() {
                if sleep.fired {
                    continue;
                }
                if let Some(due) = sleep.host_due {
                    if due <= now {
                        sleep.fired = true;
                        due_channels.push(sleep.channel);
                    } else {
                        earliest = Some(match earliest {
                            Some(cur) => cur.min(due),
                            None => due,
                        });
                    }
                }
            }
            if due_channels.is_empty() {
                match earliest {
                    Some(due) => {
                        let wait = due.saturating_duration_since(now);
                        let (guard, _) = hub
                            .cvar
                            .wait_timeout(state, wait)
                            .unwrap_or_else(|p| p.into_inner());
                        if guard.shutdown {
                            return;
                        }
                        continue;
                    }
                    None => {
                        let guard = hub.cvar.wait(state).unwrap_or_else(|p| p.into_inner());
                        if guard.shutdown {
                            return;
                        }
                        continue;
                    }
                }
            }
            earliest
        };
        let _ = next_due;
        for channel in &due_channels {
            hub.waker.wake_sleep(*channel);
        }
    }
}

fn is_realtime_sleep_clock(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_TAI
    )
}

fn sample_container_clock(clock: &ClockDomain, clock_id: u64) -> Result<Duration, i32> {
    match clock_id {
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM | LINUX_CLOCK_TAI => {
            Ok(clock.realtime_now())
        }
        LINUX_CLOCK_REALTIME_COARSE => Ok(linux_coarse_duration(clock.realtime_now())),
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW => Ok(clock.monotonic_now()),
        LINUX_CLOCK_MONOTONIC_COARSE => Ok(linux_coarse_duration(clock.monotonic_now())),
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => Ok(clock.boottime_now()),
        _ => Err(LINUX_EINVAL.get()),
    }
}

fn sample_sleep_clock(clock: &ClockDomain, clock_id: u64) -> Result<Duration, i32> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP.get());
    }
    sample_container_clock(clock, clock_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::clock::{
        ClockReply, encode_sample_request, encode_sleep_arm_request, encode_sleep_cancel_request,
        encode_timex_request, parse_reply,
    };
    use std::sync::atomic::AtomicUsize;
    use std::time::UNIX_EPOCH;

    struct CountWaker(AtomicUsize);
    impl ClockSleepWaker for CountWaker {
        fn wake_sleep(&self, _channel: ClockSleepChannel) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn sample_and_deterministic_sleep_wake_through_service() {
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = Arc::new(ClockDomain::deterministic(base));
        // This scenario advances time explicitly while another participant
        // remains untimed. Without it, enrollment correctly auto-advances
        // straight to the sleep deadline before serve_record returns.
        let participant = clock.enroll_deterministic_waiter(None, || {}).unwrap();
        let wakes = Arc::new(CountWaker(AtomicUsize::new(0)));
        let waker: Arc<dyn ClockSleepWaker> = Arc::clone(&wakes) as _;
        let service = ClockResourceService::new(Arc::clone(&clock), waker);

        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        encode_sample_request(&mut buf, LINUX_CLOCK_REALTIME);
        service.serve_record(&mut buf).unwrap();
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::Sample(Ok((1_700_000_000, 0))))
        );

        let channel = ClockSleepChannel {
            record_id: 1,
            record_generation: 1,
            mm: 1,
            address: NonZeroU64::new(0x1000).unwrap(),
        };
        encode_sleep_arm_request(
            &mut buf,
            LINUX_CLOCK_MONOTONIC,
            ClockSleepFlags::new(false, false),
            None,
            0,
            50_000_000,
            channel,
        );
        service.serve_record(&mut buf).unwrap();
        let sleep_id = match parse_reply(&buf).unwrap() {
            ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed {
                sleep_id,
                deadline_secs: 0,
                deadline_nanos: 50_000_000,
            })) => sleep_id,
            other => panic!("expected armed sleep, got {other:?}"),
        };

        clock.advance(Duration::from_millis(20)).unwrap();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        encode_sleep_cancel_request(
            &mut buf,
            sleep_id,
            LINUX_CLOCK_MONOTONIC,
            true,
            0,
            50_000_000,
        );
        service.serve_record(&mut buf).unwrap();
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::SleepCancel {
                remaining_secs: 0,
                remaining_nanos: 30_000_000,
            })
        );
        drop(participant);
        assert_eq!(clock.monotonic_now(), Duration::from_millis(20));

        // A new lone timed participant auto-advances and wakes immediately.
        // The cancelled 50 ms deadline must not influence that advancement.
        encode_sleep_arm_request(
            &mut buf,
            LINUX_CLOCK_MONOTONIC,
            ClockSleepFlags::new(false, false),
            None,
            0,
            80_000_000,
            channel,
        );
        service.serve_record(&mut buf).unwrap();
        assert!(matches!(
            parse_reply(&buf),
            Ok(ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed {
                deadline_secs: 0,
                deadline_nanos: 100_000_000,
                ..
            })))
        ));
        assert_eq!(clock.monotonic_now(), Duration::from_millis(100));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn absolute_realtime_sleep_wakes_on_timex_step() {
        let clock = Arc::new(ClockDomain::system());
        let wakes = Arc::new(CountWaker(AtomicUsize::new(0)));
        let waker: Arc<dyn ClockSleepWaker> = Arc::clone(&wakes) as _;
        let service = ClockResourceService::new(Arc::clone(&clock), waker);

        let now = clock.realtime_now();
        let target = now + Duration::from_secs(30);
        let channel = ClockSleepChannel {
            record_id: 2,
            record_generation: 1,
            mm: 1,
            address: NonZeroU64::new(0x2000).unwrap(),
        };
        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        encode_sleep_arm_request(
            &mut buf,
            LINUX_CLOCK_REALTIME,
            ClockSleepFlags::new(true, false),
            None,
            target.as_secs(),
            target.subsec_nanos(),
            channel,
        );
        service.serve_record(&mut buf).unwrap();
        let sleep_id = match parse_reply(&buf).unwrap() {
            ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed { sleep_id, .. })) => sleep_id,
            other => panic!("expected armed sleep, got {other:?}"),
        };

        let mut tx = LinuxTimex::new_read_state(LinuxTimeval::new(0, 0));
        tx.modes = carrick_abi::LinuxTimexModes::SETOFFSET.bits()
            | carrick_abi::LinuxTimexModes::NANO.bits();
        tx.time = LinuxTimeval::new(60, 0);
        let raw: [u8; CLOCK_TIMEX_BYTES] = tx.as_bytes().try_into().unwrap();
        encode_timex_request(&mut buf, false, true, &raw);
        service.serve_record(&mut buf).unwrap();
        assert!(matches!(
            parse_reply(&buf),
            Ok(ClockReply::TimexApply(Ok(_)))
        ));
        assert!(wakes.0.load(Ordering::SeqCst) >= 1);

        encode_sleep_arm_request(
            &mut buf,
            LINUX_CLOCK_REALTIME,
            ClockSleepFlags::new(true, true),
            Some(sleep_id),
            target.as_secs(),
            target.subsec_nanos(),
            channel,
        );
        service.serve_record(&mut buf).unwrap();
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Elapsed)))
        );
    }
}
