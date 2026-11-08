# Prepared-fork argument-copy diagnostic and ppoll replay (#1877)

Contract: `kernel.memory.owner-wait`. Rounds 10–13 added diagnostics without
changing owner preparation, syscall results, wait policy or work budgets.
Round 14 fixes host ppoll continuation as described below; signed cause
verification remains pending. The default `prepared-fork` sequence remains
the control;
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
exclude an unsampled path. Guest-side sources sample only ppoll; the host
replay source also samples epoll to expose its timeout-register convention.
Either can saturate the shared prefix. Publication is bounded and
allocation-free; diagnostic recording does not change scheduling budgets.

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

Round 14 identifies the concrete conversion: host IPC completion grouped
`PollWait` with `EpollWait`, retired its operation and called `epoll_rerun`.
`restart_with_remaining` then wrote remaining milliseconds into x3, ppoll's
signal-mask pointer. A five-second wait sampled one millisecond later
therefore produced 4999 (`0x1387`) without an HVF register-table error.
The three production `complete_handback` witnesses were red on round 13:
readiness and control wakes returned `Some(4999)`; expiry returned
`Some(0)` instead of completing the admitted poll.

### Round 14: retained poll completion

The host now continues PollWait in the existing IPC operation arena. It
reuses the description pin, original pollfd bytes and absolute counter
deadline; closing/reusing the numeric fd or editing user inputs cannot
change that admission. The existing shared `member_level` primitive supplies
readiness. An empty wake retains the token and deadline on the same object
queue, including the host timer; expiry copies zero revents and returns 0
without restarting a relative wait. A completed answer and its byte cursor
remain in that operation through owner-copyout refusal, without another
readiness query. The normal in-ring resumption already consumes the same
retained token before fd lookup.

Replay uses `IpcRestart::Original` or `IpcRestart::EpollPwait`, which alone
can authorize a millisecond write. The runtime checks that convention's
ordinal before writing both the vCPU argument and any host request.
PollWait produces no syscall replay or timeout-argument writes. Real
handler interruptions still return EINTR, independent of SA_RESTART;
control interruptions retain the original operation. A directly claimed
ring park's `handback=None` is normalized to `Continue` before host
completion can suspend on copyout. Its production interruption/copyout
witness was red at the subsequent `complete_handback` (Corrupt); the fixed
resume retains the decided answer despite readiness and counter changes.

The frame store also samples `host-ipc-replay` at
`restart_with_remaining`, after any authorized argument writes. It records
canonical ordinal, PC, binding, all six argument registers and an
`argument-write-mask` (bit N means argument N was written at this boundary).
For this source the last existing row word holds that mask instead of ESR;
there is no row-layout change. A ppoll sample must show mask 0 and x3 NULL;
an epoll timeout rewrite shows mask 8. The Rust formatter and LLDB decoder
both distinguish these meanings. The bounded prefix is still not a census.

The x86 CPL0 dispatcher currently does not produce PollWait: its poll family
is the shared non-parking snapshot/output path. ARM's blocking single-zone
admission is in `serve_single_zone_ppoll`. Host continuation and typed replay
are shared, so any future x86 PollWait producer receives the same retained
completion without a separate register convention. This round does not add
x86 blocking poll routing or edit the crossing allowlist.

VM-free proof covers production host completion, retained pin/snapshot and
counter deadlines, copyout refusal, and the runtime argument-write boundary.
The two signed prepared-fork cases remain the exact-binary HVF proof.

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
If a host-ipc-replay row writes x3 for nr=73, replay is still defective;
compare that row with the next fresh trap before blaming the saved context.
If both tests pass, that establishes only this artifact's signed outcomes;
the paired red/green run is required to establish that this replay fix
removes the recorded signed failure. If only touch
passes, operand residency/timing still matters and requires attribution.
