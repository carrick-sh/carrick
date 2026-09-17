//! Pipe EOF, SIGPIPE, atomicity, non-blocking, and ioctl semantics.

use super::common::*;

/// A pipe read returns 0 (EOF) only after all file descriptors referring to the write end are closed.
///
/// Authority: `man 7 pipe`, `man 2 read` (read returns 0 EOF only after all write-end descriptors close).
#[test]
fn read_returns_zero_only_after_every_writer_closes() {
    let mut readfds = [0u8; 8];
    readfds[0] = 1 << 3; // bit 3 set (fd 3, slot 0)
    let mut timeout = [0u8; 16];
    timeout[8..16].copy_from_slice(&10_000_000u64.to_le_bytes()); // 10ms

    let run = run(vec![
        pipe(),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(1)).ret(0)), // child closes its write end
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)), // child is reaped, its write end closed
        // Parent still holds slot(1) open: read end is not ready for EOF (pselect6 times out -> 0 ready)
        Step::Sys(sys::pselect6(4, in_out(&readfds), 0, 0, &timeout[..], 0).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)), // parent closes last write end
        Step::Sys(sys::read(slot(0), 10).ret(0)), // read sees EOF (returns 0)
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// Writing to a pipe with no open readers raises `SIGPIPE` and terminates the writer.
///
/// Authority: `man 7 pipe`, `man 2 write` (write to broken pipe generates SIGPIPE, terminating process).
#[test]
fn write_to_a_pipe_with_no_readers_dies_by_sigpipe() {
    let run = run(vec![
        pipe_to_slots(0, 1), // pipe_test: slot 0 (read), slot 1 (write)
        pipe_to_slots(2, 3), // pipe_sync: parent (write 3) -> child (read 2)
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)), // child closes read end of pipe_test
            Step::Sys(sys::close(slot(3)).ret(0)), // child closes unused write end of pipe_sync
            Step::Sys(sys::read(slot(2), 1).ret(1)), // wait for parent to close its read end of pipe_test
            Step::Sys(sys::close(slot(2)).ret(0)),   // close sync read end
            Step::Sys(sys::write(slot(1), b"dead").death(LINUX_SIGPIPE)),
        ]),
        Step::Sys(sys::close(slot(0)).ret(0)), // parent closes read end of pipe_test
        Step::Sys(sys::close(slot(2)).ret(0)), // parent closes unused read end of pipe_sync
        Step::Sys(sys::write(slot(3), b"g").ret(1)), // signal child to write
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)), // reap child terminated by SIGPIPE
        Step::Sys(sys::close(slot(1)).ret(0)),  // close parent's write end
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(wtermsig(wait_status(&run, "wait4")), LINUX_SIGPIPE);
    assert_eq!(run.exit_code(), 0);
}

/// When `SIGPIPE` disposition is `SIG_IGN`, writing to a pipe with no readers returns `EPIPE`.
///
/// Authority: `man 7 pipe`, `man 2 write` (write to broken pipe with SIGPIPE ignored yields EPIPE).
#[test]
fn write_with_sigpipe_ignored_is_epipe() {
    let run = run(vec![
        Step::Sys(sys::rt_sigaction_ign(LINUX_SIGPIPE).ret(0)),
        pipe(),
        Step::Sys(sys::close(slot(0)).ret(0)), // close read end
        Step::Sys(sys::write(slot(1), b"fail").errno(LINUX_EPIPE)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// Writes of up to `PIPE_BUF` (4096 bytes) are atomic across multiple writers; records must not interleave.
///
/// Authority: `man 7 pipe` (writes up to PIPE_BUF 4096 bytes are atomic and not interleaved).
#[test]
fn writes_up_to_pipe_buf_are_atomic_across_two_writers() {
    let payload_a = vec![b'A'; 4096];
    let payload_b = vec![b'B'; 4096];

    let mut script = vec![
        pipe(),
        Step::Sys(sys::fork()), // Child A (writes 8 blocks of 'A')
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_a).ret(4096)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::fork()), // Child B (writes 8 blocks of 'B')
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::write(slot(1), &payload_b).ret(4096)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)), // Parent closes write end
    ];

    // Parent reads all 65536 bytes in 4096-byte requests
    for _ in 0..16 {
        script.push(Step::Sys(sys::read(slot(0), 4096)));
    }
    script.push(Step::Sys(sys::read(slot(0), 4096).ret(0))); // EOF
    script.push(Step::Sys(sys::wait4(-1, 0)));
    script.push(Step::Sys(sys::wait4(-1, 0)));
    script.push(Step::Sys(sys::close(slot(0)).ret(0)));
    script.push(Step::Sys(sys::exit_group(0)));

    let run = run(script);
    assert_eq!(run.exit_code(), 0);

    let mut received = Vec::new();
    for (completion, output) in run
        .completions()
        .iter()
        .filter(|c| c.label == "read" && c.pid == 1)
        .zip(
            run.outputs()
                .iter()
                .filter(|o| o.label == "read" && o.pid == 1),
        )
    {
        let bytes_read = completion.result.expect("read succeeded") as usize;
        received.extend_from_slice(&output.bytes[..bytes_read]);
    }

    assert_eq!(
        received.len(),
        65536,
        "must receive exactly 65536 bytes in total"
    );

    let mut count_a = 0;
    let mut count_b = 0;
    for chunk in received.chunks_exact(4096) {
        let tag = chunk[0];
        assert!(tag == b'A' || tag == b'B', "invalid tag: {}", tag);
        assert!(
            chunk.iter().all(|&b| b == tag),
            "4096-byte chunk must be uniform and not interleaved with other writer"
        );
        if tag == b'A' {
            count_a += 1;
        } else {
            count_b += 1;
        }
    }
    assert_eq!(count_a, 8, "exactly 8 blocks of 'A'");
    assert_eq!(count_b, 8, "exactly 8 blocks of 'B'");
}

/// Non-blocking read on an empty pipe returns `EAGAIN`, and non-blocking write to a full pipe returns `EAGAIN`.
///
/// Authority: `man 7 pipe`, `man 2 fcntl` (O_NONBLOCK read on empty pipe or write to full pipe yields EAGAIN).
#[test]
fn o_nonblock_read_on_an_empty_pipe_is_eagain_and_write_to_a_full_pipe_is_eagain() {
    let full_payload = vec![0x55u8; 65536];

    let run = run(vec![
        pipe(),
        Step::Sys(fcntl_getpipe_sz(slot(0)).ret(65536).save(2)),
        Step::Sys(fcntl_setfl(slot(0), LINUX_O_NONBLOCK).ret(0)),
        Step::Sys(sys::read(slot(0), 10).errno(LINUX_EAGAIN)),
        Step::Sys(fcntl_setfl(slot(1), LINUX_O_NONBLOCK).ret(0)),
        Step::Sys(sys::write(slot(1), &full_payload).ret(65536)),
        Step::Sys(sys::write(slot(1), b"overflow").errno(LINUX_EAGAIN)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// `ioctl(FIONREAD)` reports queued buffered bytes on both the read end and the write end of a pipe.
///
/// Authority: `man 7 pipe`, `man 2 ioctl_tty` (FIONREAD reports queued buffered bytes on read and write ends).
#[test]
fn fionread_reports_queued_bytes_on_the_read_end_and_on_the_write_end() {
    let run = run(vec![
        pipe(),
        Step::Sys(sys::write(slot(1), b"hello").ret(5)),
        Step::Sys(ioctl_fionread_labeled("fionread_read_end", slot(0)).ret(0)),
        Step::Sys(ioctl_fionread_labeled("fionread_write_end", slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);

    let read_end_fionread = run.output("fionread_read_end");
    let read_bytes = i32::from_le_bytes(read_end_fionread[0..4].try_into().unwrap());
    assert_eq!(
        read_bytes, 5,
        "FIONREAD on read end must report 5 queued bytes"
    );

    let write_end_fionread = run.output("fionread_write_end");
    let write_bytes = i32::from_le_bytes(write_end_fionread[0..4].try_into().unwrap());
    assert_eq!(
        write_bytes, 5,
        "FIONREAD on write end must report 5 queued bytes"
    );
}

/// Duplicating a pipe's write end (`dup3`) keeps the write end open until all duplicated descriptors are closed.
///
/// Authority: `man 2 dup3`, `man 7 pipe` (duplicated write ends keep pipe open until all are closed).
#[test]
fn a_dup2d_write_end_keeps_the_pipe_open_until_both_descriptors_close() {
    let run = run(vec![
        pipe(),
        Step::Sys(dup3(slot(1), 10, 0).ret(10)), // Duplicate write end to fd 10
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(10).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::read(slot(0), 5).ret(5)), // reads "first"
            Step::Sys(sys::read(slot(0), 5).ret(5)), // reads "secon"
            Step::Sys(sys::read(slot(0), 5).ret(0)), // sees EOF after parent closes fd 10
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)), // Parent closes original write fd (slot 1)
        Step::Sys(sys::write(10, b"first").ret(5)),
        Step::Sys(sys::write(10, b"secon").ret(5)),
        Step::Sys(sys::close(10).ret(0)), // Parent closes duplicated write fd (10)
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}
