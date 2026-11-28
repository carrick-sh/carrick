//! Relative and absolute deadlines and numeric results cross the real Linux
//! futex client.
use carrick_core_abi::ReservationMm;
use carrick_guest_arch::{CounterTick, UserVa};
use carrick_personality_linux::sched::{
    FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_BITSET_PRIVATE_REALTIME, FUTEX_WAIT_PRIVATE, FutexCall,
    FutexFrequency, FutexVenue, FutexWait, UserReadRefusal, serve_futex,
};

/// What the policy handed the venue: an enrolment, or an immediate answer.
enum Answer {
    Wait(FutexWait),
    Invalid(i64),
}
impl Answer {
    fn wait(self) -> Option<FutexWait> {
        match self {
            Self::Wait(wait) => Some(wait),
            Self::Invalid(_) => None,
        }
    }
    fn invalid(self) -> Option<i64> {
        match self {
            Self::Invalid(value) => Some(value),
            Self::Wait(_) => None,
        }
    }
}

struct ClockVenue {
    home_record: bool,
    secs: u64,
    nanos: u64,
    realtime_offset: Option<u64>,
    waits: u64,
    reads: u64,
}
impl ClockVenue {
    fn new(home_record: bool, nanos: u64) -> Self {
        Self {
            home_record,
            secs: 1,
            nanos,
            realtime_offset: None,
            waits: 0,
            reads: 0,
        }
    }
}
impl FutexVenue for ClockVenue {
    type Served = Answer;
    fn mm(&self) -> Option<ReservationMm> {
        ReservationMm::new(17)
    }
    fn timed_wait_allowed(&self) -> bool {
        self.home_record
    }
    /// The timespec lives at 0x2000; 0x3000 is not backed yet; anything
    /// else is unreadable.
    fn read_u64(&mut self, address: UserVa) -> Result<u64, UserReadRefusal> {
        self.reads += 1;
        match address.raw() {
            0x2000 => Ok(self.secs),
            0x2008 => Ok(self.nanos),
            0x3000 | 0x3008 => Err(UserReadRefusal::Pending),
            _ => Err(UserReadRefusal::Fault),
        }
    }
    fn frequency(&self) -> FutexFrequency {
        FutexFrequency::from_hz(100)
    }
    fn now(&self) -> CounterTick {
        CounterTick::new(1000)
    }
    fn realtime_offset(&self) -> Option<u64> {
        self.realtime_offset
    }
    fn invalid(
        &mut self,
        result: carrick_personality_linux::entry::SyscallResult,
    ) -> Option<Answer> {
        Some(Answer::Invalid(result.raw()))
    }
    /// A wake always finishes in the venue (#1941); this deadline fixture
    /// echoes it as a zero-deadline record, which its tests never request.
    fn wake(&mut self, mm: ReservationMm, address: UserVa, bitset: u32, limit: u32) -> Answer {
        Answer::Wait(FutexWait {
            mm,
            address,
            bitset,
            expected: limit,
            deadline: None,
            mismatch_result: carrick_personality_linux::entry::SyscallResult::new(0),
            timeout_result: carrick_personality_linux::entry::SyscallResult::new(0),
        })
    }
    fn wait(&mut self, wait: FutexWait) -> Option<Answer> {
        self.waits += 1;
        Some(Answer::Wait(wait))
    }
}

#[test]
fn relative_timeout_preserves_home_record_admission_and_numeric_results() {
    let call = FutexCall {
        args: [0x1000, FUTEX_WAIT_PRIVATE, 7, 0x2000, 0, 0],
    };
    for scale in [1, 2, 8] {
        let mut venue = ClockVenue::new(false, 500_000_000);
        for _ in 0..scale {
            assert!(serve_futex(call, &mut venue).is_none());
        }
        assert_eq!(venue.waits, 0, "a switched-in timed wait has no effects");
        venue.home_record = true;
        venue.nanos = 1_000_000_000;
        assert_eq!(
            serve_futex(call, &mut venue).unwrap().invalid().unwrap(),
            -22,
            "Linux answers an invalid timespec EINVAL"
        );
        assert_eq!(venue.waits, 0, "an invalid timespec never enrols");
        venue.nanos = 500_000_000;
        for _ in 0..scale {
            let wait = serve_futex(call, &mut venue).unwrap().wait().unwrap();
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
    let mut venue = ClockVenue::new(false, 0);
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
    let wait = serve_futex(call, &mut venue).unwrap().wait().unwrap();
    assert_eq!(wait.mm.raw(), 17);
    assert_eq!(wait.bitset, 0x8000_0000);
    assert_eq!(wait.expected, 7);
    assert!(wait.deadline.is_none(), "the clock flag creates no timeout");
    assert_eq!(venue.waits, 1);
    for (op, timeout, mask) in [
        (FUTEX_WAIT_PRIVATE | 256, 0, 1),
        (FUTEX_WAIT_BITSET_PRIVATE_REALTIME | 512, 0, 1),
    ] {
        call.args[1] = op;
        call.args[3] = timeout;
        call.args[5] = mask;
        assert!(serve_futex(call, &mut venue).is_none());
        assert_eq!(venue.waits, 1, "an unserved variant must not enroll");
    }
    call.args[1] = FUTEX_WAIT_BITSET_PRIVATE_REALTIME;
    call.args[5] = 0;
    assert_eq!(
        serve_futex(call, &mut venue).unwrap().invalid().unwrap(),
        -22
    );
    assert_eq!(venue.waits, 1, "an empty bitset never enrols");
}

/// #3174: a timed `FUTEX_WAIT_BITSET` carries an ABSOLUTE deadline on the
/// clock its op names, through the same wait owner as the untimed one. At
/// 100 Hz a 1.5 s monotonic deadline is tick 150, whatever "now" reads; a
/// realtime deadline subtracts the zone's realtime offset first.
#[test]
fn timed_bitset_waits_carry_an_absolute_deadline_on_their_clock() {
    let call = |op| FutexCall {
        args: [0x1000, op, 7, 0x2000, 0, 0xffff_ffff],
    };
    let mut venue = ClockVenue::new(true, 500_000_000);
    let wait = serve_futex(call(FUTEX_WAIT_BITSET_PRIVATE), &mut venue)
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(wait.deadline.map(CounterTick::raw), Some(150));
    assert_eq!(wait.mismatch_result.raw(), -11, "EAGAIN on a changed word");
    assert_eq!(wait.timeout_result.raw(), -110, "ETIMEDOUT at the deadline");

    // No realtime calibration: the realtime wait stays unserved, never
    // converted on a guessed epoch.
    assert!(serve_futex(call(FUTEX_WAIT_BITSET_PRIVATE_REALTIME), &mut venue).is_none());
    assert_eq!(venue.waits, 1);
    // Realtime 1_000_000_001.5 s with an offset of 1e9 s is monotonic 1.5 s.
    venue.secs = 1_000_000_001;
    venue.realtime_offset = Some(1_000_000_000 * 1_000_000_000);
    let wait = serve_futex(call(FUTEX_WAIT_BITSET_PRIVATE_REALTIME), &mut venue)
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(wait.deadline.map(CounterTick::raw), Some(150));

    // A deadline already past expires at once, after the value check.
    venue.secs = 0;
    venue.nanos = 0;
    for op in [
        FUTEX_WAIT_BITSET_PRIVATE,
        FUTEX_WAIT_BITSET_PRIVATE_REALTIME,
    ] {
        let wait = serve_futex(call(op), &mut venue).unwrap().wait().unwrap();
        assert_eq!(wait.deadline.map(CounterTick::raw), Some(1), "op {op}");
    }

    // Linux validates the timespec: EINVAL, never an enrolment.
    venue.nanos = 1_000_000_000;
    for op in [
        FUTEX_WAIT_BITSET_PRIVATE,
        FUTEX_WAIT_BITSET_PRIVATE_REALTIME,
    ] {
        assert_eq!(
            serve_futex(call(op), &mut venue)
                .unwrap()
                .invalid()
                .unwrap(),
            -22
        );
    }
    venue.nanos = 0;
    venue.secs = (-1_i64) as u64;
    assert_eq!(
        serve_futex(call(FUTEX_WAIT_BITSET_PRIVATE), &mut venue)
            .unwrap()
            .invalid()
            .unwrap(),
        -22
    );
    assert_eq!(venue.waits, 4);
}

/// Every shared spelling of an admitted PRIVATE op is a candidate for the
/// private-anonymous key, including glibc's `pthread_join` wait (#2124:
/// shared `FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME`, op 265) and the timed
/// bitset waits (#3174). PRIVATE spellings and unadmitted shared variants
/// are never candidates.
#[test]
fn shared_candidates_cover_every_admitted_private_spelling() {
    let call = |op, timeout, mask| FutexCall {
        args: [0x1000, op, 42, timeout, 0, mask],
    };
    for timeout in [0, 0x2000] {
        for (shared, private) in [(0, 128), (1, 129), (9, 137), (10, 138), (265, 393)] {
            let candidate = call(shared, timeout, 0xffff_ffff)
                .shared_private_candidate()
                .unwrap_or_else(|| panic!("shared op {shared} must be a candidate"));
            assert_eq!(candidate.args[1], private);
            assert!(candidate.admitted());
            assert!(
                call(private, timeout, 0xffff_ffff)
                    .shared_private_candidate()
                    .is_none()
            );
        }
    }
    // A shared wait with an empty bitset is a candidate too: policy answers
    // it EINVAL before any mapping authority runs.
    assert_eq!(
        call(9, 0, 0).shared_private_candidate().map(|c| c.args[1]),
        Some(FUTEX_WAIT_BITSET_PRIVATE)
    );
    for (op, timeout, mask) in [
        (256, 0, 0xffff_ffff), // clock flag on plain WAIT
        (6, 0, 0),             // FUTEX_LOCK_PI
    ] {
        assert!(
            call(op, timeout, mask).shared_private_candidate().is_none(),
            "op {op} timeout {timeout:#x} mask {mask:#x}"
        );
    }
}

/// #3174 (pre-review P0-1, P0-2): Linux copies and validates a supplied
/// timeout before it checks the word's operands. An unreadable timespec is
/// EFAULT and a malformed one EINVAL whatever the word and mask; with a valid
/// timespec, a misaligned word or an empty bitset is EINVAL. Every wait
/// spelling is admitted with any operands, so none of these declines (a
/// fork child's decline is a counted ENOSYS). A timespec that is not backed
/// yet leaves the call to the venue's copy continuation, never an errno.
#[test]
fn a_supplied_timeout_is_read_and_validated_before_the_word_operands() {
    let mut venue = ClockVenue::new(true, 500_000_000);
    venue.realtime_offset = Some(0);
    for op in [
        FUTEX_WAIT_PRIVATE,
        FUTEX_WAIT_BITSET_PRIVATE,
        FUTEX_WAIT_BITSET_PRIVATE_REALTIME,
    ] {
        // (word, mask): misaligned, empty bitset (the plain wait has none).
        let mut bad_operands = vec![(0x1001, 0xffff_ffff)];
        if op != FUTEX_WAIT_PRIVATE {
            bad_operands.push((0x1000, 0));
        }
        for (word, mask) in bad_operands {
            let call = |timeout| FutexCall {
                args: [word, op, 7, timeout, 0, mask],
            };
            assert!(
                call(0x10).admitted(),
                "op {op} word {word:#x} mask {mask:#x}"
            );
            let answer = |venue: &mut ClockVenue, timeout| {
                serve_futex(call(timeout), venue)
                    .unwrap_or_else(|| panic!("op {op} timeout {timeout:#x} declined"))
                    .invalid()
                    .unwrap()
            };
            assert_eq!(answer(&mut venue, 0x10), -14, "EFAULT first, op {op}");
            venue.nanos = 1_000_000_000;
            assert_eq!(answer(&mut venue, 0x2000), -22, "malformed, op {op}");
            venue.nanos = 500_000_000;
            assert_eq!(answer(&mut venue, 0x2000), -22, "operands, op {op}");
            assert_eq!(answer(&mut venue, 0), -22, "untimed operands, op {op}");
            let reads = venue.reads;
            assert!(serve_futex(call(0x3000), &mut venue).is_none());
            assert_eq!(venue.reads, reads + 1, "a pending read stops at once");
        }
        // Aligned, with a mask: the fault is still EFAULT, never a decline.
        let call = FutexCall {
            args: [0x1000, op, 7, 0x10, 0, 0xffff_ffff],
        };
        assert_eq!(
            serve_futex(call, &mut venue).unwrap().invalid().unwrap(),
            -14,
            "op {op}"
        );
    }
    assert_eq!(venue.waits, 0, "no invalid call enrols");
}

/// #3174 (pre-review P0-4): a deadline at or before the counter has expired,
/// the zone timer's own rule; venues answer ETIMEDOUT without parking.
#[test]
fn a_wait_expires_at_or_after_its_deadline_tick() {
    let mut venue = ClockVenue::new(true, 0);
    venue.secs = 0;
    let wait = serve_futex(
        FutexCall {
            args: [0x1000, FUTEX_WAIT_BITSET_PRIVATE, 7, 0x2000, 0, 1],
        },
        &mut venue,
    )
    .unwrap()
    .wait()
    .unwrap();
    assert_eq!(wait.deadline, Some(CounterTick::new(1)));
    assert!(!wait.expired_at(CounterTick::new(0)));
    assert!(wait.expired_at(CounterTick::new(1)));
    assert!(wait.expired_at(CounterTick::new(2)));
    let untimed = FutexWait {
        deadline: None,
        ..wait
    };
    assert!(!untimed.expired_at(CounterTick::new(u64::MAX)));
}
