//! Relative deadlines and numeric results cross the real Linux futex client.
use carrick_core_abi::ReservationMm;
use carrick_guest_arch::{CounterTick, UserVa};
use carrick_personality_linux::sched::{
    FUTEX_WAIT_PRIVATE, FutexCall, FutexFrequency, FutexVenue, FutexWait, serve_futex,
};

struct ClockVenue {
    home_record: bool,
    nanos: u64,
    waits: u64,
}
impl FutexVenue for ClockVenue {
    type Served = FutexWait;
    fn mm(&self) -> Option<ReservationMm> {
        ReservationMm::new(17)
    }
    fn timed_wait_allowed(&self) -> bool {
        self.home_record
    }
    fn read_u64(&self, address: UserVa) -> Option<u64> {
        match address.raw() {
            0x2000 => Some(1),
            0x2008 => Some(self.nanos),
            _ => None,
        }
    }
    fn frequency(&self) -> FutexFrequency {
        FutexFrequency::from_hz(100)
    }
    fn now(&self) -> CounterTick {
        CounterTick::new(1000)
    }
    fn invalid(&mut self, _: carrick_personality_linux::entry::SyscallResult) -> Option<FutexWait> {
        None
    }
    fn wake(&mut self, _: ReservationMm, _: UserVa, _: u32, _: u32) -> Option<FutexWait> {
        None
    }
    fn wait(&mut self, wait: FutexWait) -> Option<FutexWait> {
        self.waits += 1;
        Some(wait)
    }
}

#[test]
fn relative_timeout_preserves_home_record_admission_and_numeric_results() {
    let call = FutexCall {
        args: [0x1000, FUTEX_WAIT_PRIVATE, 7, 0x2000, 0, 0],
    };
    for scale in [1, 2, 8] {
        let mut venue = ClockVenue {
            home_record: false,
            nanos: 500_000_000,
            waits: 0,
        };
        for _ in 0..scale {
            assert!(serve_futex(call, &mut venue).is_none());
        }
        assert_eq!(venue.waits, 0, "a switched-in timed wait has no effects");
        venue.home_record = true;
        venue.nanos = 1_000_000_000;
        assert!(serve_futex(call, &mut venue).is_none());
        assert_eq!(venue.waits, 0, "invalid Linux timespec forwards unchanged");
        venue.nanos = 500_000_000;
        for _ in 0..scale {
            let wait = serve_futex(call, &mut venue).unwrap();
            assert_eq!(wait.mm.raw(), 17);
            assert_eq!(wait.address.raw(), 0x1000);
            assert_eq!(wait.expected, 7);
            assert_eq!(wait.bitset, u32::MAX);
            assert_eq!(wait.deadline.map(CounterTick::raw), Some(1150));
            assert_eq!(wait.mismatch_result.raw(), -11);
            assert_eq!(wait.timeout_result.raw(), -110);
        }
        assert_eq!(venue.waits, scale);
    }
}

#[test]
fn untimed_realtime_bitset_wait_uses_the_same_private_wait_owner() {
    use carrick_personality_linux::sched::FUTEX_WAIT_BITSET_PRIVATE_REALTIME;
    let mut venue = ClockVenue {
        home_record: false,
        nanos: 0,
        waits: 0,
    };
    let mut call = FutexCall {
        args: [
            0x1000,
            FUTEX_WAIT_BITSET_PRIVATE_REALTIME,
            7,
            0,
            0,
            0x8000_0000,
        ],
    };
    let wait = serve_futex(call, &mut venue).unwrap();
    assert_eq!(wait.mm.raw(), 17);
    assert_eq!(wait.bitset, 0x8000_0000);
    assert_eq!(wait.expected, 7);
    assert!(wait.deadline.is_none(), "the clock flag creates no timeout");
    assert_eq!(venue.waits, 1);
    for (op, timeout, mask) in [
        (FUTEX_WAIT_BITSET_PRIVATE_REALTIME, 0x2000, 1),
        (FUTEX_WAIT_BITSET_PRIVATE_REALTIME, 0, 0),
        (FUTEX_WAIT_PRIVATE | 256, 0, 1),
        (FUTEX_WAIT_BITSET_PRIVATE_REALTIME | 512, 0, 1),
    ] {
        call.args[1] = op;
        call.args[3] = timeout;
        call.args[5] = mask;
        assert!(serve_futex(call, &mut venue).is_none());
        assert_eq!(venue.waits, 1, "an unserved variant must not enroll");
    }
}

/// Every shared spelling of an admitted PRIVATE op is a candidate for the
/// private-anonymous key, including glibc's `pthread_join` wait (#2124:
/// shared `FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME`, op 265). PRIVATE
/// spellings and unadmitted shared variants are never candidates.
#[test]
fn shared_candidates_cover_every_admitted_private_spelling() {
    let call = |op, timeout, mask| FutexCall {
        args: [0x1000, op, 42, timeout, 0, mask],
    };
    for (shared, private) in [(0, 128), (1, 129), (9, 137), (10, 138), (265, 393)] {
        let candidate = call(shared, 0, 0xffff_ffff)
            .shared_private_candidate()
            .unwrap_or_else(|| panic!("shared op {shared} must be a candidate"));
        assert_eq!(candidate.args[1], private);
        assert!(candidate.admitted());
        assert!(
            call(private, 0, 0xffff_ffff)
                .shared_private_candidate()
                .is_none()
        );
    }
    for (op, timeout, mask) in [
        (265, 0x2000, 0xffff_ffff), // absolute realtime deadline
        (9, 0x2000, 0xffff_ffff),   // absolute monotonic deadline
        (9, 0, 0),                  // empty bitset
        (256, 0, 0xffff_ffff),      // clock flag on plain WAIT
        (6, 0, 0),                  // FUTEX_LOCK_PI
    ] {
        assert!(
            call(op, timeout, mask).shared_private_candidate().is_none(),
            "op {op} timeout {timeout:#x} mask {mask:#x}"
        );
    }
}
