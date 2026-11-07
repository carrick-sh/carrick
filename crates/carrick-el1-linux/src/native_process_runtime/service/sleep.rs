//! Ring custody of a sleep across bounded clock-resource requests.
//!
//! The entry adapter must enroll the exact member's wake channel before
//! submitting an arm request. `Waiting` releases execution custody; only a
//! notification or signal may drive its next request. No method waits on a
//! host thread or rereads the guest's request timespec.

extern crate alloc;

use alloc::boxed::Box;
use carrick_core_abi::clock::{
    CLOCK_RECORD_BYTES, ClockRecordError, ClockReply, ClockSleepArmOutcome, ClockSleepChannel,
    ClockSleepFlags, encode_sleep_arm_request, encode_sleep_cancel_request, parse_reply,
};
use carrick_guest_arch::UserVa;
use carrick_syscall_abi::{LINUX_EINTR, LINUX_EINVAL, LinuxErrno};
use core::{num::NonZeroU64, time::Duration};

/// Copied input and the host-admitted deadline belong to this continuation.
/// It is deliberately neither `Clone` nor `Copy`: there is one cancellation
/// authority for the subscription, even while output memory is unavailable.
#[must_use]
pub struct NativeSleep {
    clock_id: u64,
    absolute: bool,
    deadline: Duration,
    subscription: Option<NonZeroU64>,
    remaining: Option<UserVa>,
    channel: ClockSleepChannel,
}

/// A transport request owns the continuation until its exact ACK.
#[must_use]
pub struct SleepRequest {
    sleep: NativeSleep,
    record: Box<[u8; CLOCK_RECORD_BYTES]>,
    cancelling: bool,
}

/// The scheduler retains `Waiting` without retaining an execution lease.
#[must_use]
pub enum SleepProgress {
    Waiting(NativeSleep),
    Complete(SleepCompletion),
}

/// Final result and optional bytes for the existing retained-copyout owner.
pub struct SleepCompletion {
    pub result: Result<(), LinuxErrno>,
    pub remaining: Option<(UserVa, [u8; 16])>,
}

impl NativeSleep {
    /// `input` is a single exact-MM copy of the Linux 64-bit timespec.
    /// Clock support is checked by the shared resource authority.
    pub fn new(
        clock_id: u64,
        absolute: bool,
        input: [u8; 16],
        remaining: Option<UserVa>,
        channel: ClockSleepChannel,
    ) -> Result<Self, LinuxErrno> {
        let seconds = i64::from_le_bytes(input[..8].try_into().map_err(|_| LINUX_EINVAL)?);
        let nanos = i64::from_le_bytes(input[8..].try_into().map_err(|_| LINUX_EINVAL)?);
        if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
            return Err(LINUX_EINVAL);
        }
        Ok(Self {
            clock_id,
            absolute,
            deadline: Duration::new(seconds as u64, nanos as u32),
            subscription: None,
            remaining: remaining.filter(|address| !absolute && address.raw() != 0),
            channel,
        })
    }

    /// The first arm converts a relative interval exactly once in the clock
    /// authority. Subsequent wake-driven arms carry its pinned deadline.
    pub fn arm(self) -> SleepRequest {
        let mut record = Box::new([0; CLOCK_RECORD_BYTES]);
        encode_sleep_arm_request(
            &mut record,
            self.clock_id,
            ClockSleepFlags::new(self.absolute, self.subscription.is_some()),
            self.subscription,
            self.deadline.as_secs(),
            self.deadline.subsec_nanos(),
            self.channel,
        );
        SleepRequest {
            sleep: self,
            record,
            cancelling: false,
        }
    }

    /// A signal cannot drop a live subscription. The bounded cancellation
    /// request acknowledges its removal before EINTR or remaining copyout.
    pub fn interrupt(self) -> Result<SleepRequest, Self> {
        let Some(subscription) = self.subscription else {
            return Err(self);
        };
        let mut record = Box::new([0; CLOCK_RECORD_BYTES]);
        encode_sleep_cancel_request(
            &mut record,
            subscription,
            self.clock_id,
            self.remaining.is_some(),
            self.deadline.as_secs(),
            self.deadline.subsec_nanos(),
        );
        Ok(SleepRequest {
            sleep: self,
            record,
            cancelling: true,
        })
    }
}

impl SleepRequest {
    /// Stable ring-owned supervisor storage, retained through transport ACK.
    pub fn record(&self) -> &[u8; CLOCK_RECORD_BYTES] {
        &self.record
    }

    /// Mutable access belongs only to the authenticated clock transport.
    pub fn record_mut(&mut self) -> &mut [u8; CLOCK_RECORD_BYTES] {
        &mut self.record
    }

    pub fn complete(mut self) -> Result<SleepProgress, ClockRecordError> {
        match (self.cancelling, parse_reply(&*self.record)?) {
            (
                false,
                ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed {
                    sleep_id,
                    deadline_secs,
                    deadline_nanos,
                })),
            ) => {
                // A rearm may refresh subscriptions, never change the owner
                // or extend the previously admitted deadline.
                let deadline = Duration::new(deadline_secs, deadline_nanos);
                if self.sleep.subscription.is_some_and(|id| id != sleep_id)
                    || (self.sleep.subscription.is_some() && deadline != self.sleep.deadline)
                {
                    return Err(ClockRecordError::Invalid);
                }
                self.sleep.subscription = Some(sleep_id);
                self.sleep.deadline = deadline;
                Ok(SleepProgress::Waiting(self.sleep))
            }
            (false, ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Elapsed))) => {
                Ok(SleepProgress::Complete(SleepCompletion {
                    result: Ok(()),
                    remaining: None,
                }))
            }
            (false, ClockReply::SleepArm(Err(errno))) => {
                Ok(SleepProgress::Complete(SleepCompletion {
                    result: Err(errno),
                    remaining: None,
                }))
            }
            (
                true,
                ClockReply::SleepCancel {
                    remaining_secs,
                    remaining_nanos,
                },
            ) => {
                let remaining = self.sleep.remaining.map(|address| {
                    let mut bytes = [0; 16];
                    bytes[..8].copy_from_slice(&remaining_secs.to_le_bytes());
                    bytes[8..].copy_from_slice(&u64::from(remaining_nanos).to_le_bytes());
                    (address, bytes)
                });
                Ok(SleepProgress::Complete(SleepCompletion {
                    result: Err(LINUX_EINTR),
                    remaining,
                }))
            }
            _ => Err(ClockRecordError::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use carrick_core_abi::EntryMmKey;
    use carrick_kernel::{
        clock_service::{ClockResourceService, ClockSleepWaker},
        kernel::container::ClockDomain,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::time::UNIX_EPOCH;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl ClockSleepWaker for Wakes {
        fn wake_sleep(&self, _: ClockSleepChannel) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn input(nanos: u64) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[8..].copy_from_slice(&nanos.to_le_bytes());
        bytes
    }

    fn sleep(absolute: bool) -> NativeSleep {
        NativeSleep::new(
            carrick_abi::LINUX_CLOCK_MONOTONIC,
            absolute,
            input(10_000_000),
            Some(UserVa::new(0x2000)),
            ClockSleepChannel {
                record_id: 1,
                record_generation: 1,
                mm: EntryMmKey::from_raw(1),
                address: NonZeroU64::new(0x1000).unwrap(),
            },
        )
        .unwrap()
    }

    fn waiting(request: SleepRequest) -> NativeSleep {
        match request.complete().unwrap() {
            SleepProgress::Waiting(sleep) => sleep,
            SleepProgress::Complete(_) => panic!("sleep must remain armed"),
        }
    }

    #[test]
    fn native_sleep_owner_pins_relative_deadline_across_clock_notifications() {
        let clock = Arc::new(ClockDomain::deterministic(UNIX_EPOCH));
        let participant = clock.enroll_waiter(None);
        let wakes = Arc::new(Wakes::default());
        let resource = ClockResourceService::new(clock.clone(), wakes.clone());
        clock.advance(Duration::from_millis(20)).unwrap();
        let mut request = sleep(false).arm();
        resource.serve_record(request.record_mut()).unwrap();
        let owner = waiting(request);
        assert_eq!(owner.deadline, Duration::from_millis(30));
        clock.advance(Duration::from_millis(5)).unwrap();
        // Model a clock-change notification before expiry. The refreshed
        // request must carry 30 ms, rather than adding another 10 ms.
        let mut request = owner.arm();
        resource.serve_record(request.record_mut()).unwrap();
        let owner = waiting(request);
        assert_eq!(owner.deadline, Duration::from_millis(30));
        clock.advance(Duration::from_millis(5)).unwrap();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        let mut request = owner.arm();
        resource.serve_record(request.record_mut()).unwrap();
        let SleepProgress::Complete(completion) = request.complete().unwrap() else {
            panic!("deadline must complete");
        };
        assert_eq!(completion.result, Ok(()));
        assert!(completion.remaining.is_none());
        clock.remove_waiter(participant);
    }

    #[test]
    fn native_sleep_owner_interrupt_ack_retains_remaining_output() {
        let clock = Arc::new(ClockDomain::deterministic(UNIX_EPOCH));
        let participant = clock.enroll_waiter(None);
        let resource = ClockResourceService::new(clock.clone(), Arc::new(Wakes::default()));
        for absolute in [false, true] {
            let mut request = sleep(absolute).arm();
            resource.serve_record(request.record_mut()).unwrap();
            let owner = waiting(request);
            if !absolute {
                clock.advance(Duration::from_millis(3)).unwrap();
            }
            let mut request = owner
                .interrupt()
                .unwrap_or_else(|_| panic!("admitted subscription"));
            resource.serve_record(request.record_mut()).unwrap();
            let SleepProgress::Complete(completion) = request.complete().unwrap() else {
                panic!("cancel ACK must complete");
            };
            assert_eq!(completion.result, Err(LINUX_EINTR));
            if absolute {
                assert!(completion.remaining.is_none());
            } else {
                assert_eq!(
                    completion.remaining,
                    Some((UserVa::new(0x2000), input(7_000_000)))
                );
            }
        }
        // Removing the last untimed participant cannot advance to a cancelled
        // deadline: cancellation ACK has relinquished both subscriptions.
        clock.remove_waiter(participant);
        assert_eq!(clock.monotonic_now(), Duration::from_millis(3));
    }

    #[test]
    fn native_sleep_owner_validates_copied_timespec() {
        let owner = sleep(false);
        assert!(matches!(
            NativeSleep::new(
                owner.clock_id,
                false,
                input(1_000_000_000),
                None,
                owner.channel
            ),
            Err(LINUX_EINVAL)
        ));
        let mut negative = input(0);
        negative[..8].copy_from_slice(&(-1_i64).to_le_bytes());
        assert!(matches!(
            NativeSleep::new(owner.clock_id, false, negative, None, owner.channel),
            Err(LINUX_EINVAL)
        ));
    }
}
