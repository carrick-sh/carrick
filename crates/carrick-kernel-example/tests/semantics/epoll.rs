//! epoll semantics conformance tests: fork sharing, edge triggering, close/aliasing, errors, EPOLLHUP.
//!
//! Authorities: man 7 epoll, man 2 epoll_create1, man 2 epoll_ctl, man 2 epoll_pwait.

use carrick_abi::{
    LINUX_EBADF, LINUX_EEXIST, LINUX_ENOENT, LINUX_EPOLLET, LINUX_EPOLLHUP, LINUX_EPOLLIN,
};
use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};

#[test]
fn an_epoll_instance_is_shared_across_fork_and_a_write_in_the_child_wakes_the_parent() {
    // man 7 epoll: An epoll instance created before fork(2) is inherited by the child;
    // events registered in the interest list remain active across fork.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        Step::Sys(
            sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 0x1234_5678_u64).ret(0),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Await parent parking on epoll_pwait
            await_parked(1, "epoll_pwait"),
            // Child writes to the pipe write end (slot 1) to make slot 0 readable
            Step::Sys(sys::write(slot(1), b"ping").ret(4)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent waits on epoll_pwait: parks on wait service, resumed on child's write
        Step::Sys(sys::epoll_pwait(slot(2), 1, 5000, 0).ret(1)),
        Step::Sys(sys::read(slot(0), 4).ret(4)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Parent's epoll_pwait parked once and completed on kernel wake: dispatched exactly twice
    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        2,
        "a parked epoll_pwait is dispatched exactly twice"
    );

    // Validate event record: struct epoll_event { u32 events; u32 _pad; u64 data; }
    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & (LINUX_EPOLLIN as u32),
        0,
        "man 7 epoll: EPOLLIN reported on pipe readability"
    );
    assert_eq!(
        event_data, 0x1234_5678_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}

#[test]
fn edge_triggered_reports_once_until_new_data_arrives() {
    // man 7 epoll: Level-triggered vs Edge-triggered (EPOLLET).
    // An EPOLLET registration reports readiness only upon state transitions; consecutive waits without draining return 0.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        Step::Sys(
            sys::epoll_ctl_add(
                slot(2),
                slot(0),
                (LINUX_EPOLLIN as u32) | LINUX_EPOLLET,
                42u64,
            )
            .ret(0),
        ),
        // Write first batch of bytes
        Step::Sys(sys::write(slot(1), b"edge1").ret(5)),
        // First epoll_pwait observes the edge transition: returns 1
        Step::Sys(sys::epoll_pwait(slot(2), 1, 10, 0).ret(1)),
        // Second epoll_pwait without draining data: edge already delivered, returns 0 (timeout)
        Step::Sys(sys::epoll_pwait(slot(2), 1, 10, 0).ret(0)),
        // Drain ready bytes
        Step::Sys(sys::read(slot(0), 5).ret(5)),
        // Write second batch of bytes: generates a fresh edge
        Step::Sys(sys::write(slot(1), b"edge2").ret(5)),
        // epoll_pwait now observes the new edge: returns 1
        Step::Sys(sys::epoll_pwait(slot(2), 1, 10, 0).ret(1)),
        // Drain second batch
        Step::Sys(sys::read(slot(0), 5).ret(5)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn closing_an_inherited_descriptor_keeps_the_epoll_registration_until_the_child_closes_it() {
    // man 7 epoll Q&A 6: An open file description remains in the epoll set as long as any file descriptor
    // referring to that description is open.
    let script = vec![
        // Data pipe: slot 0 (read), slot 1 (write)
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        // Ack pipe: slot 2 (child reads), slot 3 (parent writes)
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 2)
                .save_out_i32(0, 1, 3),
        ),
        // Epoll instance: slot 4
        Step::Sys(sys::epoll_create1(0).save(4)),
        Step::Sys(sys::epoll_ctl_add(slot(4), slot(0), LINUX_EPOLLIN as u32, 99u64).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(3)).ret(0)),
            // Await parent parking on epoll_pwait
            await_parked(1, "epoll_pwait"),
            // Child writes to data pipe to trigger readiness
            Step::Sys(sys::write(slot(1), b"dup").ret(3)),
            // Child waits for parent's ack so child holds its inherited read alias (slot 0) until parent observes readiness
            Step::Sys(sys::read(slot(2), 1).ret(1)),
            // Child now closes the last remaining read descriptor for the pipe
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(2)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(2)).ret(0)),
        // Parent closes its own descriptor (slot 0); child's inherited copy keeps OFD alive
        Step::Sys(sys::close(slot(0)).ret(0)),
        // Child's write wakes parent's epoll because OFD is still referenced by child's slot 0
        Step::Sys(sys::epoll_pwait(slot(4), 1, 5000, 0).ret(1)),
        // Parent sends ack to child so child can close its descriptor and exit
        Step::Sys(sys::write(slot(3), b"K").ret(1)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Now that child has exited, all references to the pipe read OFD are closed.
        // In Linux, closing the last descriptor automatically removed the OFD from the epoll set.
        // epoll_pwait must return 0 (timeout) because the registration was auto-removed:
        Step::Sys(sys::epoll_pwait(slot(4), 1, 10, 0).ret(0)),
        // DEL on closed slot 0 is EBADF:
        Step::Sys(sys::epoll_ctl_del(slot(4), slot(0)).errno(LINUX_EBADF)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn closing_a_duplicated_descriptor_in_the_same_process_keeps_the_epoll_registration_until_both_close()
 {
    // man 7 epoll Q&A 6: An open file description remains in the epoll set as long as any duplicate fd is open.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        // Register slot 0 (read end) in epoll slot 2
        Step::Sys(sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 123u64).ret(0)),
        // Duplicate slot 0 -> slot 3
        Step::Sys(sys::dup(slot(0)).save(3)),
        // Close original slot 0
        Step::Sys(sys::close(slot(0)).ret(0)),
        // Write to pipe write end (slot 1)
        Step::Sys(sys::write(slot(1), b"dup_test").ret(8)),
        // epoll_pwait on slot 2 must report readiness because slot 3 still holds the open file description
        Step::Sys(sys::epoll_pwait(slot(2), 1, 5000, 0).ret(1)),
        // Drain data from slot 3
        Step::Sys(sys::read(slot(3), 8).ret(8)),
        // Close slot 3: now ALL descriptors referring to the pipe read description are closed
        Step::Sys(sys::close(slot(3)).ret(0)),
        // epoll_pwait must return 0 because the registration was automatically removed when slot 3 closed
        Step::Sys(sys::epoll_pwait(slot(2), 1, 10, 0).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn reused_numeric_descriptor_does_not_trigger_or_mask_epoll_for_original_description() {
    // man 7 epoll: An epoll registration is bound to the open file description, not the numeric fd.
    // Reusing the numeric fd for a different file must not trigger or mask the original registration.
    //
    // File descriptor and harness slot map:
    // - Linux fds 0, 1, 2 = standard I/O (stdin, stdout, stderr).
    // - Pipe A: Linux fd 3 (read end, saved in harness slot 0), Linux fd 4 (write end, saved in harness slot 1).
    // - Epoll instance: Linux fd 5 (saved in harness slot 2).
    // - Pipe A read alias: Linux fd 6 (duplicated from Linux fd 3, saved in harness slot 3).
    // - Linux fd 3 is closed, freeing numeric fd 3 for allocation.
    // - Pipe B: Linux fd 3 (read end, reusing numeric fd 3, saved in harness slot 0), Linux fd 7 (write end, saved in harness slot 4).
    let script = vec![
        // Pipe A: Linux fd 3 (slot 0, read), Linux fd 4 (slot 1, write)
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        // Epoll instance: Linux fd 5 (slot 2)
        Step::Sys(sys::epoll_create1(0).save(2)),
        // Register Pipe A OFD (slot 0 / Linux fd 3) in epoll with data 0x1111
        Step::Sys(sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 0x1111u64).ret(0)),
        // Duplicate slot 0 (Linux fd 3) -> slot 3 (Linux fd 6), keeping Pipe A OFD alive
        Step::Sys(sys::dup(slot(0)).save(3)),
        // Close slot 0 (Linux fd 3): numeric fd 3 is now free for allocation
        Step::Sys(sys::close(slot(0)).ret(0)),
        // Create Pipe B: allocates lowest available numeric fd (Linux fd 3) for read end (slot 0), Linux fd 7 for write end (slot 4)
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 4),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Await parent parking on epoll_pwait
            await_parked(1, "epoll_pwait"),
            // Child writes to Pipe B (slot 4 / Linux fd 7): numeric fd 3 is readable for Pipe B,
            // but epoll watches Pipe A's open file description so parent must remain parked.
            Step::Sys(sys::write(slot(4), b"pipe_B").ret(6)),
            // Child writes to Pipe A (slot 1 / Linux fd 4): Pipe A becomes readable, waking parent's epoll_pwait.
            Step::Sys(sys::write(slot(1), b"pipe_A").ret(6)),
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(2)).ret(0)),
            Step::Sys(sys::close(slot(3)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent parks on epoll_pwait: must NOT wake on Pipe B write, wakes on Pipe A write
        Step::Sys(sys::epoll_pwait(slot(2), 1, 5000, 0).ret(1)),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Drain data from Pipe A via slot 3 (Linux fd 6)
        Step::Sys(sys::read(slot(3), 6).ret(6)),
        // Drain data from Pipe B via slot 0 (Linux fd 3)
        Step::Sys(sys::read(slot(0), 6).ret(6)),
        // Close Pipe A alias (slot 3) and write end (slot 1): now Pipe A is completely closed -> auto-detached from epoll
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // epoll_pwait on slot 2 must return 0 because Pipe A registration was auto-detached upon closing last descriptor
        Step::Sys(sys::epoll_pwait(slot(2), 1, 10, 0).ret(0)),
        // Clean up Pipe B (slot 0 / Linux fd 3, slot 4 / Linux fd 7) and epoll (slot 2 / Linux fd 5)
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Verify numeric fd reuse: both Pipe A and Pipe B received numeric Linux fd 3
    let pipe_outputs = run.outputs_for("pipe2");
    assert_eq!(pipe_outputs.len(), 2, "two pipe2 calls were issued");
    let pipe_a_read = i32::from_le_bytes(pipe_outputs[0].bytes[0..4].try_into().unwrap());
    let pipe_b_read = i32::from_le_bytes(pipe_outputs[1].bytes[0..4].try_into().unwrap());
    assert_eq!(pipe_a_read, 3, "Pipe A read descriptor is Linux fd 3");
    assert_eq!(pipe_b_read, 3, "Pipe B read descriptor reused Linux fd 3");
    assert_eq!(
        pipe_a_read, pipe_b_read,
        "numeric file descriptor integers must match"
    );

    // Parent issued two epoll_pwait syscalls: the first parked and completed on kernel wake (2 dispatches),
    // and the second timed out after auto-detachment (1 dispatch), for 3 total dispatches.
    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        3,
        "parked epoll_pwait (2 dispatches) plus immediate timeout epoll_pwait (1 dispatch)"
    );

    // Verify returned event data is 0x1111 (matching Pipe A registration)
    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & (LINUX_EPOLLIN as u32),
        0,
        "EPOLLIN reported on Pipe A readability"
    );
    assert_eq!(
        event_data, 0x1111,
        "event.data must match Pipe A registration 0x1111"
    );
}

#[test]
fn epoll_ctl_add_of_a_registered_fd_is_eexist_and_del_of_an_unregistered_fd_is_enoent() {
    // man 2 epoll_ctl: EPOLL_CTL_ADD on already registered fd -> EEXIST.
    // EPOLL_CTL_DEL on unregistered fd -> ENOENT.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        // Add slot 0
        Step::Sys(sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 1u64).ret(0)),
        // Add slot 0 again -> EEXIST
        Step::Sys(
            sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 2u64).errno(LINUX_EEXIST),
        ),
        // DEL slot 1 (valid fd, but not registered in epoll) -> ENOENT
        Step::Sys(sys::epoll_ctl_del(slot(2), slot(1)).errno(LINUX_ENOENT)),
        // DEL slot 0 -> success
        Step::Sys(sys::epoll_ctl_del(slot(2), slot(0)).ret(0)),
        // DEL slot 0 again -> ENOENT
        Step::Sys(sys::epoll_ctl_del(slot(2), slot(0)).errno(LINUX_ENOENT)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn epollhup_is_reported_when_every_writer_closes() {
    // man 7 epoll: EPOLLHUP is set on the read end of a pipe when all writers have closed.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        Step::Sys(sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLIN as u32, 100u64).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            // Child closes its write end (slot 1)
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(2)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent closes its write end (slot 1) -- all writers to the pipe are now closed
        Step::Sys(sys::close(slot(1)).ret(0)),
        // epoll_pwait reports EPOLLHUP (and/or EPOLLIN for EOF)
        Step::Sys(sys::epoll_pwait(slot(2), 1, 5000, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    assert_ne!(
        event_mask & (LINUX_EPOLLHUP as u32),
        0,
        "man 7 epoll: EPOLLHUP reported when all writers have closed"
    );
}
