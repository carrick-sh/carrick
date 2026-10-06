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
