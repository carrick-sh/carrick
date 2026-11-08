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

## Round 13: frame provenance

The refused argument index is **zero-based**, found by matching the copy VA
against the six decoded argument words. Thus argument 3 means x3, not x2;
duplicate values select the first match, and 6 means a derived address.
Rows now retain all six actual decoded words and the frame PC. The sibling
`syscall-frame` store records the first 32 ppoll frames with typed sources,
PC, slot, execution binding and syndrome. Both stores appear in the existing
embed failure formatter, including harness unwinds. Source labels name the
actual code boundary, not an inference from register values:

- `fresh-trap`: the frame delivered to the ARM syscall dispatcher;
- `decoded-dispatch`: the shared dispatch entry before serving any family;
- `owner-input-redispatch`: the frame after synchronous input preparation
  rewound its SVC;
- `scheduler-object-replay`, `scheduler-owner-replay`,
  `scheduler-saved-replay`, `scheduler-saved-return`: the actual frame loaded
  by the production scheduler, before an optional result is installed.

A fresh trap may itself be a replayed SVC. Correlate the preceding replay
sample's PC (at SVC) with the fresh trap's PC (after SVC), exact binding and
argument words. A `scheduler-saved-return` can be an arbitrary interrupted
EL0 instruction with stale x8=73: its six words are saved GPRs, not necessarily
syscall arguments. Only trap/decoded samples describe actual SVC arguments;
never attribute a syscall corruption from a saved-return row alone.
These bounded prefixes are observations, never a complete
population or an authority to resume. Saturated or missing samples do not
exclude an unsampled path. Only ppoll consumes sibling slots, so unrelated
startup syscalls cannot displace the target. Publication is bounded and
allocation-free; syscall and scheduling policies and budgets are unchanged.

The production native-dispatch prepared-pollfd and prepared-timeout witnesses
check the recorded raw words and dispatch source. The ABI test drives the
public recorder/formatter and checks source labels, word order, incomplete
publication, snapshot and prefix saturation. The ARM save/load witness drives
the same `save_frame` and `load_frame` used by HardwareCpu over all 31 GPRs.
None of these witnesses executes HVF instructions.

### What inspection establishes

The HVF `GPR_TABLE` maps each index 0 through 30 to X0 through X30, both in
main and in this branch. Snapshot, restore and thread-start restore iterate
that same table. The fork-quiesce module re-exports the neutral barrier; it
does not reconstruct syscall arguments. The ARM scheduler saves and loads
`frame.x` as a whole array. Native fork derives a separate child context with
x0 zero and its own MM; a running parent gets the child's PID as x0, without
assigning x3. Owner input redispatch rewinds PC; scheduler owner replay loads
the saved context and rewinds PC when required. Signal restart also preserves
x1 through x5, and ppoll is excluded from SA_RESTART.

A locally rebuilt static aarch64-musl `el1-sched` was disassembled, including
both prepared-fork variants and libc, rather than assuming libc's ABI. Both
call sites explicitly zero x3 before calling `ppoll`. Musl copies the timespec
into its own stack, passes the mask through x4 at the seven-argument
`__syscall_cp` C boundary, and passes size 8 in x5 there. `__syscall_cp_c`
moves x4 to architectural x3, x5 to x4, x6 (zero) to x5 and issues SVC 73.
The architectural x2 therefore points at libc's timespec copy, not necessarily
the fixture's original timeout. This local rebuild is not proof of the
director's signed fixture identity; restore/verify the matching bundle there.

No inspected assignment identifies the origin of 4999. It resembles a
remaining millisecond timeout, but neither a millisecond-to-mask conversion
nor a child/stale frame substitution is established. The table-index typo
and the claim that normal musl intentionally supplies 4999 as sigmask are
excluded by inspection. Live snapshot/restore corruption, a stale saved
context, and a replay at the wrong instruction remain open. No frame-source
fix is justified yet.

### Signed interpretation

Rebuild the host and image together, restore/verify the matching signed fixture
bundle, and run on the exact head:

```
CARRICK_TEST_TARGET=el1_sched scripts/test-signed.sh carrick-embed prepared_fork
```

This selects exactly `el1_inherited_prepared_fork_preserves_bytes_and_isolates_live_processes`
and `el1_prepared_fork_poll_arguments_touched_after_fork` in one signed test
artifact. The equivalent broad recipe is `just test-embed prepared_fork`.
Also run `just smoke-signed` before reporting
signed evidence. Retain artifact identity and scoped cleanup. If the failure
persists, the copy row identifies the raw words used for the refusal. If x3
is already 4999 at `fresh-trap`, the source precedes shared dispatch; compare
scheduler replay rows before attributing it to HVF or libc. If fresh x3 is
zero but decoded x3 is 4999 on that binding/PC, the entry boundary is implicated.
If a saved/replay row first shows 4999, inspect that saved-context producer.
If both tests pass, that establishes only this artifact's signed outcomes;
this diagnostic-only round does not establish a cause fix. If only touch
passes, operand residency/timing still matters and requires attribution.
