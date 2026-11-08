# Prepared-fork argument-copy diagnostic (#1877, rounds 10 and 12)

Contract: `kernel.memory.owner-wait`. This diagnostic changes no owner
preparation, syscall result, wait policy or work budget. It adds no signed
correctness claim. The default `prepared-fork` sequence remains the control;
`prepared-fork-touch` performs volatile stores to every pollfd and timespec
field immediately before the parent's ppoll and reports
`pollfd_touched=true timespec_touched=true` on `prepared-fork-steps`.

The fixture's ring-served ppoll enters `ipc_poll_transfer` and
`serve_single_zone_ppoll`. Its timespec and pollfd reads use `OwnerCopy`'s
boolean interface, not lifecycle `copy_argument`. `DiagnosedCopy` now wraps
the production `ValidatedCopy` there and in IPC admission. It records the
original refusal before `OwnerCopy` retains an input request and before
`wait_guest_copy` can prepare memory or redispatch. Lifecycle argument
copies use the same primitive and record store.

On ARM the validator retains PAR.FST from the **original** refusing AT S1E0R
(or S1E0W), without sampling another translation. A successful validator is
followed by LDTRB/STTRB under exception fixup; its refusal is `guarded-fault`.
Forbidden ranges, other validator rejections and translation faults have
distinct codes. Permission faults alone do not prove COW. The native input
preparation observer records Fault, Busy or OwnerWait before service
admission can change the outcome. Busy keeps its existing continuation;
it never becomes an errno. Later asynchronous supply failures are not
comprehensively sampled by this diagnostic.

The same bounded store records owner absence and binding mismatch separately
from the original physical-copy reason. Every row carries canonical ordinal,
VA, length, argument index (6 means derived), direction, reason, actual owner
presence, presented venue binding and expected current-task binding. Each
binding contains MM, execution generation, task and thread generation; zero
binding words mean absent identity. A present mismatched owner is therefore
not confused with an absent owner. These snapshots confer no authority.

The first 16 rows are immutable and individually release/acquire published,
without locks or allocation. Full storage retains its prefix; these are
samples, not a complete census. No record array is returned on the EL1 stack.
The counters layout and ABI hash change: rebuild host and image together.
The LLDB `carrick el1-counters` reader and its known-answer test use this
layout. `Counters::write_copy_refusals` streams the same committed rows for
in-process failure messages; its formatting test runs without a VM.

The production-dispatch prepared-fork parent ppoll assertion was red:
"ring ppoll must retain the original guarded-copy refusal before owner
preparation". The VM-free fixture injects a guarded-copy rejection using
TEST_USER_ACCESS. It proves diagnostic routing and ordering, not AT/LDTRB
execution. The prepared pollfd/timespec and invalid-input cases also compare
the recorded presented and expected identities after real fork preparation.

Source inspection finds no parent binding replacement in `fork_reserve`,
`fork_owned` or `fork_publish`: the parent MM is cloned as a handle, the child
gets a new MM and initial execution generation, and only the child's record
is published. ARM `prepare_mm` snapshots the parent's address context rather
than assigning a successor to the parent. A lifecycle owner mismatch at
`process_venue` on input wait raises EntryBinding, rather than returning
EFAULT. Thus parent identity drift is not established as the signed EFAULT's
cause; no identity fix is justified by these VM-free projections.

The director must run signed HVF selectors
`el1_inherited_prepared_fork_preserves_bytes_and_isolates_live_processes` and
`el1_prepared_fork_poll_arguments_touched_after_fork` via `just test-embed`.
Their failed output assertions and unwound harness failures include the
carrier counter rows directly, with original reason and both bindings,
without LLDB. Signed AT/LDTRB
attribution remains required before claiming a cause fix.
