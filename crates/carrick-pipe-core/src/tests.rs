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
