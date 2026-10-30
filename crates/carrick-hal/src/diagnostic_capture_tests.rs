//! Diagnostic preservation evidence for the trap hook only. These tests
//! prove zero unsolicited register reads and isolated capture requests;
//! they do not prove guest semantics, HVF cancellation or signed acceptance.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use std::time::Duration;

#[derive(Clone, Copy, Default)]
struct GuestRegisters {
    pc: Option<u64>,
    esr: Option<u64>,
}

#[test]
fn unrequested_exit_does_not_read_registers() {
    CaptureSlot::<GuestRegisters>::new().observe(|| panic!("unsolicited register read"));
}

#[test]
fn capture_never_returns_a_previous_requests_registers() {
    let slot = CaptureSlot::new();
    let first = slot.request().unwrap();
    slot.observe(|| GuestRegisters {
        pc: Some(0x1234),
        ..Default::default()
    });
    assert_eq!(first.wait(Instant::now()).unwrap().pc, Some(0x1234));
    let second = slot.request().unwrap();
    assert!(second.wait(Instant::now()).is_none());
    slot.observe(|| GuestRegisters {
        pc: Some(0x5678),
        ..Default::default()
    });
    assert_eq!(second.wait(Instant::now()).unwrap().pc, Some(0x5678));
}

#[test]
fn late_observation_cannot_complete_a_newer_request() {
    let slot = CaptureSlot::new();
    let first = slot.request().unwrap();
    assert!(first.wait(Instant::now()).is_none());
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let slot_ref = &slot;
        let owner = scope.spawn(move || {
            slot_ref.observe(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                GuestRegisters {
                    pc: Some(0x1111),
                    ..Default::default()
                }
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second = slot.request().unwrap();
        release_tx.send(()).unwrap();
        owner.join().unwrap();
        assert!(second.wait(Instant::now()).is_none());
        slot.observe(|| GuestRegisters {
            pc: Some(0x2222),
            ..Default::default()
        });
        assert_eq!(second.wait(Instant::now()).unwrap().pc, Some(0x2222));
    });
}

#[test]
fn two_owner_threads_publish_independent_registers() {
    let slots = [CaptureSlot::new(), CaptureSlot::new()];
    let requests = slots.each_ref().map(CaptureSlot::request);
    std::thread::scope(|scope| {
        for (index, slot) in slots.iter().enumerate() {
            scope.spawn(move || {
                slot.observe(|| GuestRegisters {
                    pc: Some(0x4000 + index as u64 * 4096),
                    esr: Some(0x92000006),
                })
            });
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        for (index, request) in requests.iter().enumerate() {
            let sample = request.unwrap().wait(deadline).unwrap();
            assert_eq!(sample.pc, Some(0x4000 + index as u64 * 4096));
            assert_eq!(sample.esr, Some(0x92000006));
        }
    });
}
