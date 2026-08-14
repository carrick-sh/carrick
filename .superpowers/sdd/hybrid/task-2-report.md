# Task 2 report — HVPatch fatal exec shape and six-stage evidence

Date: 2026-08-13 (America/Los_Angeles)

Task base: `212df9e2`

Implementation: `0650cbe9b` (`fix(hvpatch): preserve fatal exec failure shape`)

## Result

Accepted. The three reachable HVPatch inventory failures after sibling
teardown now terminate the Linux process with signal-shaped SIGSEGV state all
the way through `RunResult`, the HVPatch wait publication, and the guest
parent's `waitpid(2)` observation. They cannot be confused with a real guest
`exit(127)`.

The append-only runtime-stage ABI remains exactly ordinals 0 through 5, and
`CloseCloexec` is emitted around the committed CLOEXEC close. The durable
`carrick trace --profile hvpatch-exec-runtime-stages` producer and strict
consumer accepted a current signed run containing one completed exec and
exactly six stage events, every ordinal once.

## Systematic root-cause trace

### Hypothesis 1 — the three post-teardown inventory errors escape as ordinary runtime errors

I first traced the observable bad state backward without changing the error
policy. The guest parent saw `WIFEXITED=true`, `WEXITSTATUS=127`. In
`vcpu_loop/mod.rs`, the terminal HVPatch loop converted any escaped `Err(_)`
from the vCPU loop to `assemble_run_result(..., 127, None, ...)`. The absence of
a signal was preserved by `RunResult::wait_status_encoding` and then by
`HvpatchProcess::publish_exit_status`, so the guest parent received a normal
exit record.

The escaped sources were all after the documented point of no return in
`handle_execve`: old-inventory capacity calculation, replacement-inventory
reservation, and `begin_exec_inventory`. Sibling teardown had already run, so
returning an errno or resuming the old image was not valid.

The three deterministic RED runs confirmed the hypothesis:

```text
old-capacity run cr-65726-21517
replacement-reservation run cr-65918-23161
begin-inventory run cr-65984-26737

child_exited=true
child_exit_status=127
child_signaled=false
child_signal=0
```

No fix was attempted until all three paths reproduced serially with the signed
binary.

### Hypothesis 2 — routing every post-point-of-no-return failure through the fatal helper preserves signal shape

I routed the three injected failures through `exec_failed_past_no_return`, then
audited the rest of the destructive transaction. Inventory sizing and both
reservations, inventory arming/take/apply, authoritative Kernel preparation and
commit, stage-1 root read, image replacement/verification, VMA acknowledgement,
and guest-thread identity publication now use the same terminal route.
Fork-child cleanup failure is logged but cannot replace the required SIGSEGV
terminal shape with an escaped `RuntimeError`.

The final signed GREEN runs confirmed this hypothesis independently for all
three injected points:

```text
old-capacity run cr-68889-13208 cleanup=0
replacement-reservation run cr-68935-18176 cleanup=0
begin-inventory run cr-68979-22236 cleanup=0

child_exited=false
child_exit_status=-1
child_signaled=true
child_signal=11
```

This is distinguishable from an actual guest exit 127 because the wait status
has `WIFSIGNALED=true` and `WTERMSIG=SIGSEGV` rather than `WIFEXITED=true`.

## Strict TDD evidence

### Fatal paths: RED before implementation

The test probe and diagnostic failure seam were added first. Each signed serial
command below failed the assertion on the unfixed routing:

```sh
CARRICK_EXEC_BACKEND=hvpatch CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE='old-capacity@/bin/true' scripts/run-probe.sh execfatalstatus
CARRICK_EXEC_BACKEND=hvpatch CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE='replacement-reservation@/bin/true' scripts/run-probe.sh execfatalstatus
CARRICK_EXEC_BACKEND=hvpatch CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE='begin-inventory@/bin/true' scripts/run-probe.sh execfatalstatus
```

All three published normal exit 127 as shown in Hypothesis 1. The optional
`@PATH` target is necessary so the outer probe process can start normally and
only its `/bin/true` exec crosses the injected point.

### Fatal paths: GREEN after the root fix

The same commands against the final signed binary produced the signal-shaped
results shown in Hypothesis 2. No current run left a scoped Carrick process.

The ordinary differential controls stayed green:

```text
execfatalstatus run cr-69023-26296: MATCH Docker, normal child exit 0
execfailsurvive run cr-68879-10482: MATCH Docker, all seven errno cases kept the old image and survived
```

### Strict consumer: RED before implementation

I added parser tests against an intentionally incomplete implementation and
observed three failures before implementing the reader:

```text
accepts_exactly_six_unique_stages_for_each_completed_exec: expected 1 completed exec, got 0
rejects_empty_missing_duplicate_and_unbalanced_streams: empty stream was accepted
rejects_timeout_provider_error_drops_and_interruption: timeout stream was accepted
test result: FAILED. 0 passed; 3 failed
```

The final suite contains positive exact-six coverage, DTrace buffer-reordering
coverage, and negative zero/missing/duplicate/unbalanced/timeout/provider-error/
producer-drop/consumer-drop/interruption coverage.

## Live DTrace debugging and acceptance

Only `carrick trace` was used for live execution; it auto-sudoed successfully.
There was no host-policy block.

### Hypothesis 3 — the first D compilation failure is an undeclared thread-local predicate read

The first live command failed before launch:

```text
dtrace_program_strcompile failed: in action list: self->active has not yet been declared or assigned
```

The first lifecycle predicate read `self->active` before any D action declared
it. Duplicate/unbalanced begin is already caught by the independent begin and
complete totals, so I removed that unnecessary pre-read. The program then
compiled.

### Hypothesis 4 — completion accounting observes state cleared by an earlier clause for the same probe

The next live receipt contained all six unique stage rows but ended
`status=error` with `completion_errors=1`. The matched completion clause cleared
`self->active`; a later unmatched-completion clause for the same firing then
saw the cleared value. Moving the unmatched check before the matched/clearing
clause produced a clean producer summary. The rejected raw receipt is retained
as `2026-08-13-hvpatch-exec-runtime-stages-consumer-red.raw`.

### Hypothesis 5 — raw DTrace records can be delivered out of event order

The next producer summary was clean (`events=6`, all phases one), but the Rust
consumer rejected after reading a complete row before three stage rows. The raw
receipt directly showed the reordered rows, confirming that stream order was
not a valid join key.

The protocol now emits a monotonically increasing `exec_sequence` on begin,
stage, and complete rows. The consumer accumulates the unordered records by
host PID/TID plus that sequence and only validates after the complete stream is
read. This prevents adjacent or concurrent execs from merging while remaining
independent of DTrace buffer drain order. The rejected raw receipt is retained
as `2026-08-13-hvpatch-exec-runtime-stages-order-red.raw`.

### Final accepted current-binary receipt

```sh
CARRICK_RUN_ID=task2-final-trace-20260813 \
  target/release/carrick trace \
  --profile hvpatch-exec-runtime-stages \
  --trace-out docs/perf-results/2026-08-13-hvpatch-exec-runtime-stages.raw \
  -- run --exec-backend hvpatch ubuntu:24.04 /bin/sh -c 'exec /bin/true'
```

```text
HVPatch exec runtime stages: completed_execs=1, events=6, events_per_exec=6
remaining carrick procs (run-id task2-final-trace-20260813) = 0
```

The final summary is `status=ok`, begins/completes are 1/1, phase0 through
phase5 are each 1, all join/error/drop/bounded counts are zero, and the traced
target exited normally with status 0.

Hashes:

```text
durable D program  bad668a8fb2b872ebd14d29314559334d410f99553b6c42d9da2cb6d9ac60289
accepted raw       6b7f50362fb51dfd0c474f53dfd78c8a1993f8b6bc21fe57c460aa66d0f6b159
signed carrick     3da910e7886b4e413c425559f85918c516b44800d517e060cec24612416c9870
execfatalstatus    4782c72b1c23584ed5f14599f2b5ca404fa734fa369b39b20afe0740dd4583b3
```

## ABI and consumer guarantees

The existing ordinal pin remains unchanged:

```text
0 ProcState
1 CloseCloexec
2 SiblingDrain
3 TopologyLock
4 EngineReplace
5 Publication
```

`EngineReplace` is emitted when the destructive engine/Kernel transaction is
committed. `CloseCloexec` brackets only the committed file-table close. The
publication event follows final image verification and guest-thread identity
publication.

The producer fails its summary on zero events, count imbalance, missing or
duplicate ordinals, lifecycle join errors, timeout, provider errors, DTrace
drops, or nonzero/missing target exit. The Rust consumer separately rejects all
of those shapes plus malformed/unknown fields, identity drift, duplicate
records, arithmetic inconsistency, libdtrace drop categories, and interruption.

## Files

- `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- `conformance-probes/src/bin/execfatalstatus.rs`
- `scripts/dtrace/hvpatch-phase4-exec-runtime-stages.d`
- `crates/carrick-runtime/src/dtrace_consumer.rs`
- `crates/carrick-cli/src/hvpatch_exec_runtime_profile.rs`
- `crates/carrick-cli/src/trace_profile.rs`
- `crates/carrick-cli/src/commands.rs`
- `crates/carrick-cli/src/args.rs`
- `crates/carrick-cli/src/main.rs`
- raw evidence under `docs/perf-results/2026-08-13-hvpatch-exec-*`

`crates/carrick-observability/src/probes.rs` required no edit: it already
declared all six append-only ordinals and its existing ABI test pinned their
numeric values. That test was rerun explicitly.

## Verification

```text
cargo test -p carrick-observability exec_runtime_stage_event_keeps_outer_runtime_cost_typed -- --nocapture
  PASS: 1 passed

RUST_MIN_STACK=8388608 cargo test -p carrick-cli hvpatch_exec_runtime -- --nocapture
  PASS: 5 passed

cargo test -p carrick-runtime --lib exec_image_verification_tests -- --nocapture
  PASS: 3 passed

just build
  PASS: release binary rebuilt and signed with scripts/entitlements.plist

RUST_TEST_THREADS=1 CARRICK_RUN_ID=task2-ci2-20260813 just ci
  PASS
  carrick-cli unit: 358 passed
  carrick-runtime unit: 1564 passed, 5 ignored
  carrick-runtime integration: 296 passed
  trace-profile integration: 41 passed
```

The first CI attempt stopped at `fmt-check` after the final audit edit. I ran
`cargo fmt --all` and reran the complete CI recipe from the beginning; the
second run above passed.

## Self-review

- The failpoint is diagnostic, HVPatch-only, opt-in, and target-scoped. Unknown
  values do nothing. It exercises the real capacity/reservation rejection paths
  rather than substituting a synthetic top-level return.
- All injected runs were serialized, Carrick and Docker were never run in
  parallel, and each harness cleanup reported zero remaining scoped processes.
- No ordinal was added, removed, reused, or renumbered.
- Signal state is carried in `RunResult.signal`, encoded by Linux wait status,
  and verified from inside the guest parent. A real exit 127 remains a distinct
  `WIFEXITED` shape.
- The live consumer proved fail-closed behavior twice before acceptance; zero
  events or incomplete data never became evidence.
- No ad-hoc logging or scratch D script was added. Runtime failure reporting
  uses the existing tracing infrastructure, and the live instrument is the
  durable repository D program selected through `carrick trace`.
- `hybrid.md` and the SDD ledger were not edited.

## Concerns

No acceptance blocker. The injected fault runs intentionally differ from
Docker because Docker has no Carrick internal failpoint; the non-injected probe
and the established errno/rollback probe both match Docker. The final live
receipt covers one completed exec; the sequence-keyed parser has deterministic
unit coverage for reordered records and is designed to keep multiple/concurrent
exec identities separate.
