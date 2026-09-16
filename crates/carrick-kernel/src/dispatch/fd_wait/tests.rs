use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::*;
use crate::dispatch::LinearMemory;

const BASE: u64 = 0x4000;

fn negative_poll_wait(deadline: Option<Instant>) -> BlockingFdWait {
    match BlockingFdWait::new(
        BlockingFdWaitKind::Poll {
            entries: vec![RetainedPollFd {
                guest_fd: -1,
                events: libc::POLLIN,
                address: BASE,
                source: RetainedFdSource::Negative,
            }],
        },
        deadline,
        WaitFds::empty(),
    ) {
        Ok(wait) => wait,
        Err(errno) => panic!("empty wait registration must admit: errno {errno:?}"),
    }
}

#[test]
fn pending_poll_does_not_write_guest_pollfd_before_terminal_completion() {
    let dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(BASE, vec![0xA5; 16]);
    let before = memory.bytes.clone();

    assert!(matches!(
        negative_poll_wait(None).complete(&mut memory, &dispatcher),
        BlockingFdWaitStep::Wait(_)
    ));
    assert_eq!(memory.bytes, before, "a re-park must not copy out revents");
}

#[test]
fn terminal_poll_updates_only_revents_not_saved_input_fields() {
    let dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(BASE, vec![0xA5; 16]);
    memory.bytes[..6].copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    memory.bytes[6..8].copy_from_slice(&[0xFE, 0xCA]);
    let expected_input = memory.bytes[..6].to_vec();
    let expected_tail = memory.bytes[8..].to_vec();

    assert!(matches!(
        negative_poll_wait(Some(Instant::now() - Duration::from_secs(1)))
            .complete(&mut memory, &dispatcher),
        BlockingFdWaitStep::Done(DispatchOutcome::Returned { value: 0 })
    ));
    assert_eq!(memory.bytes[..6], expected_input);
    assert_eq!(memory.bytes[6..8], 0i16.to_ne_bytes());
    assert_eq!(memory.bytes[8..], expected_tail);
}

#[test]
fn independently_admitted_fd_waits_have_distinct_identity() {
    let first = negative_poll_wait(None);
    let second = negative_poll_wait(None);
    assert_ne!(first, second);
    assert_eq!(first, first.clone());
}

#[test]
fn admission_duplicates_host_registration_before_the_original_closes() {
    let mut raw = [-1; 2];
    assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
    let read = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    let _write = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    let wait = match BlockingFdWait::new(
        BlockingFdWaitKind::Poll {
            entries: Vec::new(),
        },
        None,
        WaitFds::raw_one(read.as_raw_fd(), libc::POLLIN),
    ) {
        Ok(wait) => wait,
        Err(errno) => panic!("pipe wait registration must admit: errno {errno:?}"),
    };
    assert_eq!(wait.registrations().len(), 1);

    drop(read);
    assert!(
        unsafe { libc::fcntl(wait.registrations()[0].fd.as_raw_fd(), libc::F_GETFD) } >= 0,
        "retained registration must outlive the original raw wait target"
    );
}

#[test]
fn repark_preserves_the_original_absolute_caller_deadline() {
    let dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(BASE, vec![0xA5; 16]);
    let deadline = Instant::now() + Duration::from_secs(60);

    let first_repark = match negative_poll_wait(Some(deadline)).complete(&mut memory, &dispatcher) {
        BlockingFdWaitStep::Wait(wait) => wait,
        other => panic!("expected pending negative poll, got {other:?}"),
    };
    assert_eq!(first_repark.caller_deadline(), Some(deadline));

    let second_repark = match first_repark.complete(&mut memory, &dispatcher) {
        BlockingFdWaitStep::Wait(wait) => wait,
        other => panic!("expected second pending negative poll, got {other:?}"),
    };
    assert_eq!(second_repark.caller_deadline(), Some(deadline));
}
