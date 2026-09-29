#![allow(clippy::unwrap_used)]
use super::*;

#[test]
fn atomic_write_cannot_publish_a_prefix() {
    let mut bytes = [0; 4096];
    let mut slots = [Page::default(); 1];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, 4096, 4096).unwrap();
    assert_eq!(p.try_write(&[7; 4095]).result, Ok(4095));
    assert_eq!(
        p.try_write(&[8; 2]).result,
        Err(Error::WouldBlock(WaitFor::Writable))
    );
    assert_eq!(p.unread_bytes(), 4095);
}

#[test]
fn event_counter_never_wraps() {
    let mut e = EventFd::new(0, EventMode::Counter);
    assert_eq!(e.try_write(EVENTFD_MAX).result, Ok(()));
    assert_eq!(
        e.try_write(1).result,
        Err(Error::WouldBlock(WaitFor::Writable))
    );
    assert_eq!(e.try_read().result, Ok(EVENTFD_MAX));
}

#[test]
fn all_atomic_sizes_and_space_boundaries() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    for n in 1..=PIPE_BUF {
        for spare in [0, n - 1, n, PIPE_BUF] {
            let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
            let filler = [1; PIPE_BUF];
            let input = [2; PIPE_BUF];
            p.try_write(&filler[..PIPE_BUF - spare]);
            let before = p.unread_bytes();
            let result = p.try_write(&input[..n]);
            if spare < n {
                assert_eq!(result.result, Err(Error::WouldBlock(WaitFor::Writable)));
                assert_eq!(result.wake, WakeSet::default());
                assert_eq!(p.unread_bytes(), before);
            } else {
                assert_eq!(result.result, Ok(n));
                let mut output = [0; PIPE_BUF];
                assert_eq!(p.try_read(&mut output).result, Ok(before + n));
                assert!(output[..before].iter().all(|b| *b == 1));
                assert!(output[before..before + n].iter().all(|b| *b == 2));
            }
        }
    }
}

#[test]
fn large_writes_split_and_resume_without_restarting() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
    let source: std::vec::Vec<_> = (0..PIPE_BUF * 3 + 7).map(|n| (n % 251) as u8).collect();
    let mut cursor = WriteCursor::new(&source);
    let mut result = std::vec::Vec::new();
    let mut out = [0; PIPE_BUF];
    while !cursor.is_complete() {
        let before = cursor.written();
        let n = cursor.advance(&mut p).result.unwrap();
        assert!(n > 0 && n <= PIPE_BUF);
        assert_eq!(cursor.written(), before + n);
        assert_eq!(p.try_read(&mut out).result, Ok(n));
        result.extend_from_slice(&out[..n]);
    }
    assert_eq!(result, source);
    assert_eq!(cursor.advance(&mut p).result, Ok(0));
}

#[test]
fn page_fragmentation_controls_fullness_and_resize() {
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 2).unwrap();
    p.try_write(&[1; PIPE_BUF - 1]);
    p.try_write(&[2; 2]); // Cannot merge: two occupied slots, only 4097 bytes.
    p.try_read(&mut [0; PIPE_BUF - 2]);
    assert_eq!(p.unread_bytes(), 3);
    assert_eq!(
        p.set_capacity(PIPE_BUF, usize::MAX).result,
        Err(Error::Busy)
    );
    assert!(!p.readiness(End::Writer).writable);
    assert_eq!(p.try_write(&[3]).result, Ok(1)); // Tail merge despite !POLLOUT.
    let mut out = [0; 4];
    assert_eq!(p.try_read(&mut out).result, Ok(4));
    assert_eq!(out, [1, 2, 2, 3]);
    assert_eq!(p.set_capacity(0, 0).result, Ok(PIPE_BUF));
}

#[test]
fn large_write_remainder_merge_and_full_ring() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
    p.try_write(&[1; PIPE_BUF - 1]);
    assert_eq!(p.try_write(&[2; PIPE_BUF + 1]).result, Ok(1));
    assert_eq!(
        p.try_write(&[3; PIPE_BUF + 1]).result,
        Err(Error::WouldBlock(WaitFor::Writable))
    );
    assert_eq!(p.unread_bytes(), PIPE_BUF);
}

#[test]
fn resizing_wrapped_data_preserves_bytes_and_fragmentation() {
    let mut bytes = [0; PIPE_BUF * 8];
    let mut slots = [Page::default(); 8];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    p.try_write(&[1; PIPE_BUF * 3]);
    p.try_read(&mut [0; PIPE_BUF * 2 + 3]);
    p.try_write(&[2; PIPE_BUF * 2]);
    assert_eq!(
        p.set_capacity(PIPE_BUF * 4 + 1, usize::MAX).result,
        Ok(PIPE_BUF * 8)
    );
    assert_eq!(p.set_capacity(PIPE_BUF * 4, 0).result, Ok(PIPE_BUF * 4));
    let mut out = [0; PIPE_BUF * 3];
    assert_eq!(p.try_read(&mut out).result, Ok(PIPE_BUF * 3 - 3));
    assert!(out[..PIPE_BUF - 3].iter().all(|b| *b == 1));
    assert!(out[PIPE_BUF - 3..PIPE_BUF * 3 - 3].iter().all(|b| *b == 2));
    assert_eq!(p.set_capacity(PIPE_BUF, 0).result, Ok(PIPE_BUF));
    assert_eq!(p.try_write(b"next").result, Ok(4));
    assert_eq!(p.try_read(&mut out[..4]).result, Ok(4));
    assert_eq!(&out[..4], b"next");
}

#[test]
fn resize_errors_are_transactional_and_shrink_ignores_growth_limits() {
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 2).unwrap();
    p.try_write(b"kept");
    for (request, limit, error) in [
        (PIPE_BUF * 4, PIPE_BUF * 2, Error::Permission),
        (PIPE_BUF * 8, usize::MAX, Error::Storage),
        (usize::MAX, usize::MAX, Error::Invalid),
    ] {
        let step = p.set_capacity(request, limit);
        assert_eq!(step.result, Err(error));
        assert_eq!(step.wake, WakeSet::default());
        assert_eq!(p.capacity(), PIPE_BUF * 2);
        assert_eq!(p.unread_bytes(), 4);
    }
    assert_eq!(p.set_capacity(1, 0).result, Ok(PIPE_BUF));
    let mut out = [0; 4];
    assert_eq!(p.try_read(&mut out).result, Ok(4));
    assert_eq!(&out, b"kept");
}

#[test]
fn default_capacity_and_guest_page_sizes() {
    for page_size in [4096, 16384, 65536] {
        let mut bytes = std::vec![0; page_size*16];
        let mut slots = [Page::default(); 16];
        let mut p = Pipe::new(&mut bytes, &mut slots, page_size).unwrap();
        assert_eq!(p.capacity(), page_size * 16);
        assert_eq!(
            p.set_capacity(page_size + 1, usize::MAX).result,
            Ok(page_size * 2)
        );
        assert_eq!(p.try_write(&[1; PIPE_BUF]).result, Ok(PIPE_BUF));
    }
    for bad in [0, 1, 2048, 4097, usize::MAX] {
        assert_eq!(Pipe::rounded_capacity(bad, 1), Err(Error::Invalid));
    }
    assert_eq!(Pipe::rounded_capacity(4096, 0), Ok(4096));
    assert_eq!(
        Pipe::rounded_capacity(4096, i32::MAX as usize),
        Err(Error::Invalid)
    );
}

#[test]
fn eof_epipe_refcounts_zero_length_and_wakes() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
    assert_eq!(
        p.try_read(&mut [0]).result,
        Err(Error::WouldBlock(WaitFor::Readable))
    );
    p.retain(End::Writer).unwrap();
    assert_eq!(p.references(End::Writer), 2);
    assert_eq!(p.release(End::Writer).wake, WakeSet::default());
    assert!(!p.readiness(End::Reader).hup);
    assert!(p.try_write(b"a").wake.readers);
    assert!(p.release(End::Writer).wake.readers);
    assert!(p.readiness(End::Reader).hup);
    assert!(p.readiness(End::Reader).readable);
    assert_eq!(p.try_read(&mut [0]).result, Ok(1));
    assert_eq!(p.try_read(&mut [0]).result, Ok(0));
    assert!(!p.readiness(End::Reader).readable);
    assert_eq!(p.retain(End::Writer), Err(Error::Refcount));
    assert_eq!(p.release(End::Writer).result, Err(Error::Refcount));
    p.retain(End::Reader).unwrap();
    assert_eq!(p.release(End::Reader).wake, WakeSet::default());
    assert!(p.release(End::Reader).wake.writers);
    assert!(p.readiness(End::Writer).err);
    assert!(p.readiness(End::Writer).writable);
    assert_eq!(p.try_write(b"x").result, Err(Error::BrokenPipe));
    assert_eq!(p.try_write(&[]).result, Ok(0));
    assert_eq!(p.try_read(&mut []).result, Ok(0));
}

#[test]
fn broken_pipe_precedes_fullness_and_preserves_partial_cursor() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
    let input = [5; PIPE_BUF + 1];
    let mut cursor = WriteCursor::new(&input);
    assert_eq!(cursor.advance(&mut p).result, Ok(PIPE_BUF));
    assert_eq!(
        cursor.advance(&mut p).result,
        Err(Error::WouldBlock(WaitFor::Writable))
    );
    p.release(End::Reader);
    assert_eq!(cursor.advance(&mut p).result, Err(Error::BrokenPipe));
    assert_eq!(cursor.written(), PIPE_BUF);
    assert_eq!(p.unread_bytes(), PIPE_BUF);
}

#[test]
fn eventfd_modes_boundaries_readiness_and_notifications() {
    for mode in [EventMode::Counter, EventMode::Semaphore] {
        let mut e = EventFd::new(0, mode);
        assert_eq!(
            e.try_read().result,
            Err(Error::WouldBlock(WaitFor::Readable))
        );
        assert!(e.readiness().writable);
        assert!(!e.readiness().readable);
        assert_eq!(e.try_write(0).wake, WakeSet::default());
        assert!(e.try_write(3).wake.readers);
        assert!(e.readiness().readable);
        assert!(e.try_read().wake.writers);
        assert_eq!(e.value(), if mode == EventMode::Counter { 0 } else { 2 });
        while e.value() != 0 {
            assert_eq!(e.try_read().result, Ok(1));
        }
        assert_eq!(e.try_write(u64::MAX).result, Err(Error::Invalid));
        assert_eq!(e.value(), 0);
        e.try_write(EVENTFD_MAX);
        assert!(!e.readiness().writable);
        assert!(!e.readiness().err);
        assert_eq!(e.try_write(0).result, Ok(()));
        assert_eq!(
            e.try_write(1).result,
            Err(Error::WouldBlock(WaitFor::Writable))
        );
        e.try_read();
        assert!(e.readiness().writable);
        assert_eq!(e.try_write(1).result, Ok(()));
    }
    let mut e = EventFd::new(u32::MAX, EventMode::Counter);
    assert_eq!(e.try_read().result, Ok(u64::from(u32::MAX)));
}

#[test]
fn ring_matches_fifo_model_across_many_wraps() {
    use std::collections::VecDeque;
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    let mut model = VecDeque::new();
    let mut seed = 21u64;
    for _ in 0..10000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = (seed as usize >> 8) % (PIPE_BUF * 2) + 1;
        if seed & 1 == 0 {
            let input = std::vec![(seed >> 32) as u8; n];
            match p.try_write(&input).result {
                Ok(written) => {
                    assert!(n > PIPE_BUF || written == n);
                    model.extend(&input[..written]);
                }
                Err(e) => assert_eq!(e, Error::WouldBlock(WaitFor::Writable)),
            }
        } else {
            let mut out = std::vec![0; n];
            if model.is_empty() {
                assert_eq!(
                    p.try_read(&mut out).result,
                    Err(Error::WouldBlock(WaitFor::Readable))
                );
            } else {
                let expected = model.len().min(n);
                assert_eq!(p.try_read(&mut out).result, Ok(expected));
                for byte in &out[..expected] {
                    assert_eq!(Some(*byte), model.pop_front());
                }
            }
        }
        assert_eq!(p.unread_bytes(), model.len());
    }
}

#[test]
fn structural_copy_work_is_linear_and_storage_is_never_replaced() {
    // Production is no_std with no extern crate alloc and no dependencies:
    // allocation is unavailable. These counters bound all page visits/copies,
    // independent of the pipe's reserve size and historical traffic.
    for n in [1, 4096, 16384] {
        let mut bytes = [0; PIPE_BUF * 16];
        let address = bytes.as_ptr();
        let mut slots = [Page::default(); 16];
        let mut p = Pipe::new(&mut bytes, &mut slots, PIPE_BUF).unwrap();
        let input = [6; PIPE_BUF * 4];
        let mut output = [0; PIPE_BUF * 4];
        for _ in 0..100 {
            p.work = Work::default();
            assert_eq!(p.try_write(&input[..n]).result, Ok(n));
            assert_eq!(p.try_read(&mut output[..n]).result, Ok(n));
            assert_eq!(p.work.copied, n * 2);
            assert!(p.work.visits <= 2 * n.div_ceil(PIPE_BUF));
            assert_eq!(p.bytes.as_ptr(), address);
            assert_eq!(&output[..n], &input[..n]);
        }
    }
}

// ---- contract kernel.el1.ipc-object-state (VM-free bindings) ----

fn shared_view<'a>(
    record: &'a mut PipeRecord,
    bytes: &'a mut [u8],
    slots: &'a mut [Page],
) -> Pipe<'a, &'a mut PipeRecord> {
    Pipe::attach(record, bytes, slots).unwrap()
}

#[test]
fn el1_ipc_shared_record_view_runs_the_same_algorithm() {
    // The owned pipe and a view over a record kept outside the view (as in
    // shared memory, reattached for every operation) agree byte for byte.
    let mut owned_bytes = [0; PIPE_BUF * 4];
    let mut owned_slots = [Page::default(); 4];
    let mut owned =
        Pipe::with_capacity(&mut owned_bytes, &mut owned_slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut record = PipeRecord::default();
    Pipe::init(&mut record, &mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    let mut seed = 7u64;
    for _ in 0..4000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = (seed as usize >> 8) % (PIPE_BUF * 2) + 1;
        let mut view = shared_view(&mut record, &mut bytes, &mut slots);
        if seed & 1 == 0 {
            let input = std::vec![(seed >> 32) as u8; n];
            assert_eq!(view.try_write(&input), owned.try_write(&input));
        } else {
            let (mut a, mut b) = (std::vec![0; n], std::vec![0; n]);
            assert_eq!(view.try_read(&mut a), owned.try_read(&mut b));
            assert_eq!(a, b);
        }
        assert_eq!(view.unread_bytes(), owned.unread_bytes());
        assert_eq!(view.readiness(End::Writer), owned.readiness(End::Writer));
    }
}

#[test]
fn el1_ipc_attach_rejects_records_that_do_not_describe_the_storage() {
    let mut bytes = [0; PIPE_BUF * 2];
    let mut slots = [Page::default(); 2];
    let mut zero = PipeRecord::default();
    assert!(matches!(
        Pipe::attach(&mut zero, &mut bytes, &mut slots),
        Err(Error::Corrupt)
    ));
    let good = PipeRecord::new(PIPE_BUF * 2, 2, PIPE_BUF, PIPE_BUF * 2).unwrap();
    for bad in [
        PipeRecord {
            capacity_pages: 4,
            ..good
        },
        PipeRecord { head: 2, ..good },
        PipeRecord { used: 3, ..good },
        PipeRecord {
            unread: 1,
            used: 0,
            ..good
        },
        PipeRecord {
            page_size: 4097,
            ..good
        },
    ] {
        let mut r = bad;
        assert!(matches!(
            Pipe::attach(&mut r, &mut bytes, &mut slots),
            Err(Error::Corrupt)
        ));
    }
    let mut r = good;
    assert!(Pipe::attach(&mut r, &mut bytes, &mut slots).is_ok());
}

#[test]
fn el1_ipc_atomic_writes_through_shared_record() {
    let mut bytes = [0; PIPE_BUF];
    let mut slots = [Page::default(); 1];
    let mut record = PipeRecord::default();
    for n in 1..=PIPE_BUF {
        for spare in [0, n - 1, n, PIPE_BUF] {
            Pipe::init(&mut record, &mut bytes, &mut slots, PIPE_BUF, PIPE_BUF).unwrap();
            let mut p = shared_view(&mut record, &mut bytes, &mut slots);
            p.try_write(&[1; PIPE_BUF][..PIPE_BUF - spare]);
            let before = p.unread_bytes();
            let mut fills = 0;
            let step = p.write_with(n, |_, dst| {
                fills += 1;
                dst.fill(2);
                dst.len()
            });
            if spare < n {
                assert_eq!(step.result, Err(Error::WouldBlock(WaitFor::Writable)));
                assert_eq!(fills, 0, "no byte of a refused atomic write is staged");
                assert_eq!(p.unread_bytes(), before);
            } else {
                assert_eq!(step.result, Ok(n));
                assert_eq!(fills, 1, "an atomic write lands in one chunk");
            }
        }
    }
}

#[test]
fn el1_ipc_staged_read_fault_preserves_undelivered_bytes() {
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    let input: std::vec::Vec<u8> = (0..PIPE_BUF * 2 + 10).map(|n| (n % 253) as u8).collect();
    assert_eq!(p.try_write(&input).result, Ok(input.len()));
    // Fault before the first byte: nothing consumed, no wake.
    let step = p.read_with(100, |_| 0);
    assert_eq!(step.result, Err(Error::Fault));
    assert_eq!(step.wake, WakeSet::default());
    assert_eq!(p.unread_bytes(), input.len());
    // Fault after a delivered prefix spanning a page boundary.
    let mut out = std::vec::Vec::new();
    let step = p.read_with(PIPE_BUF * 2, |chunk| {
        let take = if out.is_empty() { chunk.len() } else { 5 };
        out.extend_from_slice(&chunk[..take]);
        take
    });
    assert_eq!(step.result, Ok(PIPE_BUF + 5));
    assert!(step.wake.writers);
    assert_eq!(p.unread_bytes(), input.len() - PIPE_BUF - 5);
    let mut rest = std::vec![0; input.len()];
    let n = p.try_read(&mut rest).result.unwrap();
    out.extend_from_slice(&rest[..n]);
    assert_eq!(out, input, "no byte lost or duplicated across the fault");
}

#[test]
fn el1_ipc_staged_write_fault_publishes_only_the_filled_prefix() {
    let mut bytes = [0; PIPE_BUF * 4];
    let mut slots = [Page::default(); 4];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 4).unwrap();
    assert_eq!(p.write_with(10, |_, _| 0).result, Err(Error::Fault));
    assert_eq!(p.unread_bytes(), 0);
    assert_eq!(p.readiness(End::Reader), Readiness::default());
    // Large write faults 7 bytes into its second page.
    let source: std::vec::Vec<u8> = (0..PIPE_BUF * 3).map(|n| (n % 241) as u8).collect();
    let mut progress = WriteProgress::new(source.len() as u64);
    let step = p.write_progress(&mut progress, |at, dst| {
        let n = if at == 0 { dst.len() } else { 7 };
        dst[..n].copy_from_slice(&source[at..at + n]);
        n
    });
    assert_eq!(step.result, Ok(PIPE_BUF + 7));
    assert_eq!(progress.written, (PIPE_BUF + 7) as u64);
    // Resume from the recorded offset, never from zero.
    let step = p.write_progress(&mut progress, |at, dst| {
        dst.copy_from_slice(&source[at..at + dst.len()]);
        dst.len()
    });
    assert!(step.result.is_ok());
    assert!(progress.is_complete());
    let mut out = std::vec![0; source.len()];
    assert_eq!(p.try_read(&mut out).result, Ok(source.len()));
    assert_eq!(out, source);
}

#[test]
fn el1_ipc_eventfd_drain_semaphore_overflow_and_fault() {
    // In place, as the shared record: all-zero is a zero counter.
    let mut e = EventFd::new(0, EventMode::Counter);
    assert_eq!(e.try_write(5).result, Ok(()));
    assert_eq!(e.read_with(|_| false).result, Err(Error::Fault));
    assert_eq!(e.value(), 5, "a failed copyout drains nothing");
    assert_eq!(e.read_with(|v| v == 5).result, Ok(5));
    let mut s = EventFd::new(3, EventMode::Semaphore);
    assert_eq!(s.try_read().result, Ok(1));
    assert_eq!(s.value(), 2);
    assert_eq!(s.try_write(EVENTFD_MAX - 2).result, Ok(()));
    assert_eq!(
        s.try_write(1).result,
        Err(Error::WouldBlock(WaitFor::Writable))
    );
    assert_eq!(s.try_write(u64::MAX).result, Err(Error::Invalid));
    assert_eq!(s.value(), EVENTFD_MAX);
    assert_eq!(core::mem::size_of::<EventFd>(), 16);
}

#[test]
fn el1_ipc_copy_work_is_linear_in_delivered_bytes() {
    for n in [1, 4096, 16384] {
        let mut record = PipeRecord::default();
        let mut bytes = [0; PIPE_BUF * 16];
        let mut slots = [Page::default(); 16];
        Pipe::init(&mut record, &mut bytes, &mut slots, PIPE_BUF, PIPE_BUF * 16).unwrap();
        let input = [9; PIPE_BUF * 4];
        let mut output = [0; PIPE_BUF * 4];
        for round in 0..64 {
            let mut p = shared_view(&mut record, &mut bytes, &mut slots);
            assert_eq!(p.try_write(&input[..n]).result, Ok(n));
            assert_eq!(p.try_read(&mut output[..n]).result, Ok(n));
            assert_eq!(p.work.copied, n * 2, "round {round}");
            assert!(p.work.visits <= 2 * n.div_ceil(PIPE_BUF) + 2);
        }
    }
}

#[test]
fn el1_ipc_reback_preserves_wrapped_partial_pages_and_endpoints() {
    let mut bytes = [0; 8192];
    let mut slots = [Page::default(); 2];
    let mut record = PipeRecord::default();
    let mut p = Pipe::init(&mut record, &mut bytes, &mut slots, 4096, 8192).unwrap();
    assert_eq!(p.try_write(&[1; 8192]).result, Ok(8192));
    assert_eq!(p.try_read(&mut [0; 4096]).result, Ok(4096));
    assert_eq!(p.try_write(&[2; 4096]).result, Ok(4096));
    assert_eq!(p.try_read(&mut [0; 17]).result, Ok(17));
    p.retain(End::Reader).unwrap();
    let mut larger = [0; 16384];
    let mut larger_slots = [Page::default(); 4];
    let mut p = p.replace_storage(&mut larger, &mut larger_slots).unwrap();
    assert_eq!(p.capacity(), 8192);
    assert_eq!(p.references(End::Reader), 2);
    assert_eq!(p.references(End::Writer), 1);
    assert_eq!(p.set_capacity(16384, 16384).result, Ok(16384));
    assert_eq!(p.try_write(&[3; 4096]).result, Ok(4096));
    let mut out = [0; 16384];
    assert_eq!(p.try_read(&mut out).result, Ok(12288 - 17));
    assert!(out[..4079].iter().all(|b| *b == 1));
    assert!(out[4079..8175].iter().all(|b| *b == 2));
    assert!(out[8175..12271].iter().all(|b| *b == 3));
}

#[test]
fn el1_ipc_reback_refusal_preserves_live_record_and_bytes() {
    let mut bytes = [0; 8192];
    let mut slots = [Page::default(); 2];
    let mut record = PipeRecord::default();
    let mut p = Pipe::init(&mut record, &mut bytes, &mut slots, 4096, 8192).unwrap();
    assert_eq!(p.try_write(b"unchanged").result, Ok(9));
    let before = *p.state;
    let mut small = [0; 4096];
    let mut small_slots = [Page::default(); 1];
    assert!(matches!(
        p.replace_storage(&mut small, &mut small_slots),
        Err(Error::Storage)
    ));
    assert_eq!(record, before);
    let mut p = Pipe::attach(&mut record, &mut bytes, &mut slots).unwrap();
    let mut out = [0; 9];
    assert_eq!(p.try_read(&mut out).result, Ok(9));
    assert_eq!(&out, b"unchanged");
}

#[test]
fn el1_ipc_peek_then_commit_preserves_undelivered_suffix() {
    let mut bytes = [0; 8192];
    let mut slots = [Page::default(); 2];
    let mut p = Pipe::with_capacity(&mut bytes, &mut slots, 4096, 8192).unwrap();
    assert_eq!(p.try_write(&[7; 5000]).result, Ok(5000));
    let before = *p.st();
    let mut copied = 0;
    assert_eq!(
        p.peek_with(5000, |chunk| {
            let n = chunk.len().min(4000 - copied);
            copied += n;
            n
        }),
        Ok(4000)
    );
    assert_eq!(*p.st(), before);
    assert_eq!(p.peek_with(5000, |_| 0), Err(Error::Fault));
    assert_eq!(*p.st(), before);
    assert_eq!(p.consume(5001).result, Err(Error::Invalid));
    assert_eq!(*p.st(), before);
    assert_eq!(p.consume(4000).result, Ok(4000));
    let mut out = [0; 2000];
    assert_eq!(p.try_read(&mut out).result, Ok(1000));
    assert!(out[..1000].iter().all(|b| *b == 7));
}
