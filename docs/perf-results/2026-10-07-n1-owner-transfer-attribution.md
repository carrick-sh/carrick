# N1 owner-transfer exit attribution

Status: focused pipe-creation repair has red/green proof; whole N1 remains
not review-ready. The original measurement source is
`0d154a9a4e5819251f08d8de198d197a97591935`, compared with `f0e9a3265`.
No Docker or load generator was started.

## Measurements

The exact-HEAD fixture bundle restored and verified 1,133 executables.
`target/n1cm-sol-taskload-red.log` records the foreground signed binding
`el1_task_load_costs_no_host_round_trip`: 685 additional loads cost 7,795
maintenance exits against the unchanged zero budget. The entitlement
negative control passed; both scoped cleanup counts were zero.

The retained signed scheduler executable was then launched through
`carrick trace --script scripts/dtrace/hvpatch-maintenance-service-attribution.d
--require-script-exit -- --external ...`. Its raw receipt is
`target/n1cm-sol-taskload-trace.raw`: 23,112 maintenance events, errors zero,
12,504 during read, 5,469 during write, 5,021 outside forwarded service,
and 12 host faults. Capture success does not imply test success: the
instrumented witness also failed. Counts are mechanism evidence, not timing.

Against the merge base, `carrick-aarch64/src/user_transfer.rs` and its
`staging.rs`/`prepared.rs` children are new. Ordinary input uses owner SELECT
then a service copy handshake; prepared output additionally uses PREPARE and
COMMIT/CANCEL. Every service enters EL1 through
`TransferServiceLoan::run_user` and `run_el1_service_effect_on`, returning
through MaintenanceDone. The trace attributes the scaling to host I/O, not
task installation. This is not evidence to remove required descriptor TLBI.

## Proposed correction before implementation

Keep the sole `carrick_core::mm::transaction::MmPortal` owner and its exact
carrier/MM/incarnation, reservation generation, retained physical generation,
range/protection checks and prepared permits. Replace repeated host-driven
service invocation for an already resident ordinary transfer with a native
venue adapter to that same owner. The adapter supplies authenticated live
table reads, existing owner/editor exclusion and existing completion wake
delivery; it introduces no independent VMA policy or host descriptor editor.
Unrepresented pages still request exact owned supply and relinquish CPU/editor
custody before waiting. Actual descriptor changes retain required guest
invalidation and fail-closed receipts. Per-page work remains bounded to 4 KiB.

First prove two live MMs at the same VA select different physical owners,
generation/range/protection failures refuse before copying, and prepared
short-prefix commit/drop conserve permits. Then prove resident input/output
has no maintenance-service invocation in a VM-free venue witness, followed
by the unchanged signed task-load and frame-publication budgets. No delayed
result batching, retries, budget changes or host-copy bypass is proposed.
This design still needs concrete table/resolver/wake integration; no native
adapter implementation or signed acceptance is claimed here.

## Separate IPC evidence

`target/n1cm-sol-ipc-red.log` reproduces `el1_ipc_pairs_blocking`: one pair
completes 128 rounds; the eight-pair case fails creating a pipe. The qualified
`host-copyout-refusal.d` capture has two owner-bind controls, zero errors and
zero drops, with no refusal events. That capture did not establish the pipe errno. The later qualified
`target/n1cm-sol-ipc-prepare.raw` shows pipe2 errno 14 immediately after
output preparation phase 4/detail 2 (an owner Editor wait). Its positive
return and owner-bind controls fired, errors and diagnostic bound were zero.
The initially added blind observer duplicated default reporter returns; the
final hook only registers the existing CompatReporter probe hook.

The new `pipe2_copyout_owner_wait_preserves_admission_before_effects`
VM-free witness failed with `LinuxErrno(14)` before the handler correction.
It now preserves the exact wait without output, then creates descriptors
3/4 on resumption. A genuine bad destination still returns errno 14 and
releases its descriptor pair: the next successful call uses 5/6. The owner
handler prepares output before creation, retaining prepared custody through
publication and infallible commit. Genuine preparation faults defer their
EFAULT until after resource admission, preserving resource-error precedence.
The focused signed confirmation `target/n1cm-sol-ipc-green.log` passes
pipe/eventfd populations 1/8/64 at 128 rounds, with an entitled artifact,
passing unentitled negative control and zero scoped survivors. The retained
receipt is `target/n1cm-sol-evidence/ipc-green-artifacts.jsonl`. No full
branch acceptance or runtime-ratio closure follows from this focused pass.
A subsequent `syscalls.d` capture fired no syscall probes and did not end
with its witness; it is rejected. Scoped privileged cleanup reaped its exact
run ID with zero survivors. Do not infer an EFAULT from the fixture's `-1`.

The pipe repair is committed as `d559ef7b4`. The final diagnostic hook and
script were qualified together on the corrected retained scheduler artifact:
`target/n1cm-sol-pipe-qualified.raw` reports return/bind controls, errors=0,
bounded=0, and the instrumented IPC witness passes. The CLI capture exited
zero, so its consumer accepted the drop/exit receipt. This supplements the
uninstrumented signed proof; it does not replace it.

The reported pipe-creation failure now has deterministic red-to-green and
focused signed proof. The rest of the reported failures and the full-suite
comparison remain open. No history reword or review-ready claim is made.
