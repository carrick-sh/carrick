# poll/ppoll publish only `revents` (#1897)

`kernel.el1.poll-revents` owns the output shape of the legacy shared poll
body on both ISAs.

## Linux authority

`man 2 poll` and `man 2 ppoll`: `fd` and `events` are inputs; the kernel
writes only each entry's `revents`. Nothing forbids a caller from rewriting
its own `pollfd` array while the call blocks, and Linux does not undo that.
A negative `fd` is ignored with `revents = 0`; an fd absent from the caller's
table reports `POLLNVAL`; the return value counts nonzero `revents`.

## Carrick invariant

`crates/carrick-el1-linux/src/dispatch.rs` publishes one two-byte field per
entry at `offset_of!(LinuxPollFd, revents)`, matching the kernel's
`FdWaitWrites::Poll`. It never republishes the frozen whole-record array. The
native venue retains the same shape through
`ProcessNative::complete_poll_revents` and the retained output's
`CopyoutShape::PollRevents`; the legacy venue copies it directly in
`copy_poll_revents`. Both the host-wait path and the immediate /
zero-timeout path share the one publication helper.

The structural budget is unchanged and smaller in bytes than before: exactly
`2n` guest-memory bytes for `n` entries, one published unit per entry, and no
input reads on the publication path.

## Witnesses

- `carrick-el1-linux::ipc::tests::host_wait_publishes_only_revents_and_keeps_the_callers_rewrites`
  drives the production `TrapFrame` (aarch64) and the x86 CPL0 frame through
  the shared body, rewriting the second entry's `fd`/`events` inside the
  readiness crossing. It requires the rewrite to survive and only `revents`
  to change. Red on the pre-fix whole-array copy-out: the rewritten `fd`
  reverts to its frozen value.
- `carrick-el1-linux::ipc::tests::immediate_poll_publishes_only_revents_for_both_isa_frames`
  covers the immediate and zero-timeout path on both ISAs with a ready
  in-zone eventfd and no host crossing.
- `carrick-el1-linux::native_process_runtime::host_test_support::production_trap_frame_ppoll_retains_completed_output_across_owner_wait`
  binds the retained native-venue owner wait to one two-byte unit per entry
  and an unchanged result. It is red when the retained shape is a byte run.

## Open gates

A signed HVF or KVM guest run of the mutation witness and Docker
differential are not available on this worker VM; signed promotion remains
director-owned.
