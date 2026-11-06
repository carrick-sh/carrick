# IPC entry-binding fatal: reproduction limits

Issue [#887](https://github.com/carrick-sh/carrick/issues/887) requires a
red-first native-process reproduction before changing the owner. This note
records why the existing fork/exec pipe witness does not yet provide that
reproduction. It does not diagnose the signed fatal or claim a fix.

## What the existing witness proves

`serial_host_native_fork_exec_pipe_writer_reaches_its_parent` in
`crates/carrick-el1-linux/src/aarch64_process_tests/native_exec_pipe_tests.rs`
creates a real native child, inherits an IPC table, adopts an exec successor,
writes through the inherited pipe and reads the bytes from the parent. Both
processes remain live during the I/O.

It stops after the parent read and unregisters the runtime. It does not drive
the child's exit, descriptor teardown, a signal-check frame, or the carrier's
return transport. Its `Physical` service accepts a fixture-sealed successor
manifest; this is not the host `Kernel::commit_exec_transition` path. The
dispatch closure calls `enter_registered` directly, rather than crossing
`with_process_entry` on every call. A pass therefore cannot establish that
the reported entry-binding fatal is gone.

## Missing crossing authentication

The physical-stock fixture has a separate, confirmed limitation tracked by
[#1758](https://github.com/carrick-sh/carrick/issues/1758):

- `PhysicalStock::loan` in `aarch64_process_tests/native_retirement_tests.rs`
  constructs `GrantExecution` from the loan request and saves it in
  `self.execution`.
- `PhysicalStock::reserve` and `PhysicalStock::commit` pass that saved value
  to `ForkStock::reserve_custody` and `ForkStock::commit_admitted`.
- The fixture therefore cannot observe a changed live execution binding,
  root or generation at those later crossings. Its custody validation
  callbacks also return `true` unconditionally.

Production's `stopped_execution` in
`crates/carrick-vmm-hvf/src/metadata_grant.rs` instead reads the stopped lane
and authenticates its live execution and address context. The fixture needs
that same per-crossing authority, not an override of a cached request, to
reproduce that class of interleaving. This limitation alone does not prove
that #887 belongs to that class.

## Exec settlement decision still applies

The director's
[InFlight ruling](https://github.com/carrick-sh/carrick/issues/887#issuecomment-6529637696)
requires an owned post-publication settlement continuation on the member's
release notification. It explicitly rejects a fatal contention path. The
preceding investigation explains why a check in kernel prepare does not
solve it: runtime prepare is already in the destructive suffix, a dropped
membership claim permits another claimant, and that suffix cannot suspend.

Do not restore the old stack's new fatal settlement arms or convert Busy to
an ordinary errno or SIGSEGV. A future reduction must retain the operation,
enrol on the exact owner's release notification, probe once and complete
after release without repeating publication.

## Evidence needed next

1. Restore the historical EL1 image corresponding to the fatal log and
   symbolize the PC and caller against that image. A current image cannot
   attribute the historical address; neither the image nor its source object
   is present in this checkout. The issue history distinguishes several
   `entry_binding` callers, so the reason string alone is insufficient.
2. Extend the native crossing fixture's live authentication as specified in
   #1758. Drive the production admission and resume boundaries with two live
   processes, inherited descriptor custody across exec, and exit/teardown.
   Include the signal-check return boundary if it is required by the
   symbolized caller. Capture a deterministic red assertion before fixing.
3. Fix the identified refusal in its neutral owner, with a Busy-once/release/
   success witness if the refusal is contention. Do not guess which fatal
   call needs changing from the saved signal-check marker alone.
4. Run the native suite and worker gates, then have the director run the
   paired signed population on the Mac. Native passes and build checks do
   not satisfy the signed zero-carrier-fatal acceptance criterion.
