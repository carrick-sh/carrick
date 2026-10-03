# M2–M5 contract preparation (no cutover)

Baseline: `1047fefdc7cf6ee99faca70c90bf94b2e5e854d4`.
Production behavior is unchanged. No Docker, runtime ratio or migration
acceptance is claimed. Scoped signed EL0 semantic receipts from the follow-up
are recorded below; they do not establish EL1 delivery ownership. Known-red gates execute
normally and use exact `expect_err` reasons; unexpected green fails. At
cutover invert the assertion in the same commit that deletes the old owner.

## M2 — flips at M2 cutover

`dispatch::fs::pipe::tests::red_until_step3_m2_shared_close_still_needs_host_endpoint_release`
requires final shared writer close to retire the endpoint. Exact current red:
`final shared writer close retains host endpoint pin`. At 1/8/64 pairs, two
live shared tables retain respectively 1/8/64 host writer pins after shared
close. Explicit host release then produces EOF and balanced object retirement.
This is an ownership defect, not a Linux EOF bug: today's production close
also invokes the host release. Tables are live owners as in M1, not scheduled
EL0 processes.

Semantic bindings: existing broken-pipe/EOF, zero write, capacity/nonblocking,
partial-write lifetime and ABI continuation/no-replay/overlapping-VA tests.
The new `kernel.el1.ipc-lifecycle` descriptor keeps the signed 32-writer default
pool exhaustion and lifecycle differential explicitly unresolved. M2 cutover
must also cover eventfd semaphore/overflow, vectored faults, restart/cancel,
splice/tee, elastic growth and backed steady-state allocation. A host-pin
count is not a forwarded-dispatch measurement.

## M3 — flips at M3 cutover

`dispatch::net::epoll_zone::tests::red_until_step3_m3_zone_pipe_waits_create_host_proxies`
requires zero host readiness proxies for zone pipe wait enrollment. Exact red:
`all-zone pipe wait enrollment creates host readiness proxies`. At 1/8/64
members the fixture observes exactly 1/8/64 scoped proxy handles. Reader and
writer descriptions reside in two live tables; no process-global fd count is
sampled. This calls the current enrollment seam directly, not ppoll through
EL0. Existing ABI epoll LT/ET/ONESHOT, harvest/maxevents and last-file detach
and kernel cycle/fd-reuse/POLLNVAL fixtures remain positive semantics.

`kernel.el1.poll-select-owner` complements `kernel.el1.epoll-zone`; it does not
replace the landed guest harvest. Mixed external-socket plus pipe completion,
stale host token incarnation, zero/finite/infinite waits, copyout faults and
atomic mask install/enroll/recheck/restore on ready/timeout/EINTR/cancel still
need executable two-process bindings. Proxy count is not a queue-visit or
forwarded-dispatch counter; no scan-work claim is made by this fixture.

## M4 — flips at M4 cutover

- `dispatch::net::scm_rights::tests::red_until_step3_m4_rights_create_placeholder_per_message`:
  exact red `guest rights transport creates host placeholder pipes`.
  Two live tables park an eventfd description, close/reuse sender fd 3,
  claim the original description, install receiver fd 3 with CLOEXEC and
  return every logical reference. Exactly 1/8/64 scoped placeholders remain
  necessary for 1/8/64 messages. The fixture does not call host sendmsg.
- `dispatch::net::unix_pure::tests::red_until_step3_m4_stream_payloads_live_in_host_socket_state`:
  exact red `guest stream payload remains in host PureSocketState queue`.
  Two live tables own the connected endpoints. At 1/8/64 streams,
  7/56/448 payload bytes reside in host socket state before recv. Payload
  roundtrip and guest peer credentials pass independently of ownership red.

`kernel.el1.unix-owner` and `kernel.el1.unix-rights` are registered separately.
`m4_equal_address_bytes_are_isolated_by_registry_owner` keeps identical abstract
and pathname bytes in separate registries, removes/rebinds one and verifies
that the other survives. This is registry isolation, not proof that two
containers select different registries in production. Existing stream/dgram,
shutdown/HUP, claim/abort/orphan-GC reducers are positive semantics.

Still missing executable cutover bindings: pipe writer/epoll/host-file rights,
shared flags and cursor, ancillary truncation/fault rollback, queued-message
socket close, cyclic graph collection and bounded historical scan work,
backlog/nonblock/partial stream writes, datagram peek/truncation and SEQPACKET,
actual container namespace/pathname permission wiring and host-peer imports.
No Linux-semantics defect was observed in these new fixtures.

## M5 — flips at M5 cutover

`kernel::objects::signal::tests::red_until_step3_m5_shared_pending_clear_does_not_consume_host_queue`:
exact red `shared pending clear leaves host realtime queue authoritative`.
Two live task/thread fixtures in separate containers enqueue independent RT
payloads at 1/8/32/128 queue lengths. Clearing the target shared summary
leaves every host payload live; the peer remains unchanged. Host consumption
then returns each payload FIFO and both queues empty.

This intentionally exposes the projection seam. Summary clear is **not** a
Linux signal-delivery operation. At cutover replace this seam operation with
consumption through the new shared payload owner, then invert the red gate;
do not make summary clear silently discard payloads to satisfy the test.
The scale axis is queued payload count, not a target-population routing
measurement. Existing standard coalescing, RT FIFO, fork/exec mask/pending/
action reducers and thread-first provenance remain positive semantics.

`kernel.el1.signal-delivery-owner` complements the existing lease-gap,
thread-lifecycle and job-control contracts. Still missing executable cutover
bindings: multi-thread born/exit/reuse routing, permission/sender info,
CLONE_SIGHAND, exact routing at 1/8/32/128 targets, SIGPENDING accounting,
SA_RESTART/NODEFER/RESETHAND, interrupted partial pipe/socket I/O,
ppoll/pselect/sigsuspend/sigtimedwait/signalfd transactions, stop/continue/kill,
SIGCHLD, nested altstack/siglongjmp/fault/malformed sigreturn/PSTATE,
ptrace/seccomp and delivery on IRQ/fault EL0 returns.

## Preparation status and evidence limits

These five executable ownership seams and five registered descriptors are
initial preparation, **not full M2–M5 contract coverage**. The missing bindings
above must be authored before claiming any milestone is immediately ready
for cutover. No new executable guest probe was added; all new fixtures are
VM-free Rust unit tests. Any subsequent executable probe belongs in
carrick-conformance-next. Two descriptor-owner tables follow M1's reducer
convention; they do not substitute for scheduled two-process integration.
No ownership assertion is ignored or should-panic. No budget is relaxed.

Initial fixture checks caught insufficient descriptor backing and a private
module import; both were corrected. Neither is Linux red evidence. No new
Linux-semantics bug was reproduced, so no production fix is included.

## Verification receipt

With `CARGO_BUILD_JOBS=3`, foreground, on committed fixture sources:

- `just test-kernel`: exit 0; ABI 109, fd-core 32, kernel 2354 passed;
  one pre-existing ignored kernel test, 155 serial-host filtered tests.
  All kernel-semantics suites completed. All five new known-red gates and
  the registry-isolation positive test executed.
- `just clippy`: exit 0, workspace/all targets with `-D warnings`.
- `just lint-domains`: exit 0. Host-authority census is the existing macOS
  subset; Linux/FreeBSD/NetBSD compiler profiles remain pending. The exact
  97 production raw-lock-site gate passed; no production owner retired.
- `just check-inventory`: exit 0; 338 syscall rows, support classifications
  unchanged. Associations include the five new contract descriptors.
- `just fmt` and `git diff --check`: exit 0.

The first `just reconcile-inventories` refused three new SCM fixture table
guards. They are explicitly classified `test_or_definition` / `inspect_misc`
under `red_until_step3_m4_rights_create_placeholder_per_message`; taxonomy
rebinding and the full domain gate then pass. Production category counts and
compiler capture row hash are unchanged. Capture source-head is refreshed.
The read-only final review found no blocking defect in this partial groundwork
and confirmed the missing coverage prevents full cutover readiness.

Milestone commits: M2 `98ed6ae2c`, M3 `49cb164c4`, M4 `525cb6ebc`,
M5 `b1b5b007d`. Inventory reconciliation: `9a34d6937`.

Fixture source SHA-256 (after all Rust edits):

```
8228b79c5235a50831aa13474e24c9d654c6cb382640263ec777e34b1102a600  crates/carrick-kernel/src/dispatch/fs/pipe.rs
dea04f5175d27233bcc4b0cec9b625681495ccb02a0b524173f5f5f01d96e649  crates/carrick-kernel/src/dispatch/net/epoll_zone.rs
6fb32aecd9bbd588387d383f9cf085ee4e556fe19ec0f9c7b630935ef6316462  crates/carrick-kernel/src/dispatch/net/scm_rights.rs
d24c1ee0735def7a60c2352751854a1678151f5414903cad0ab26edf95254d24  crates/carrick-kernel/src/dispatch/net/unix_pure.rs
a401dc5beb024894ad54fe0a3c51e65381356c62d03bcfefeaca49f0d988f287  crates/carrick-kernel/src/kernel/objects/signal.rs
```

## Follow-up binding preparation, 2026-10-02

Rebased onto main before continuation (already up to date at `948f43f4b`).
The original receipt above remains historical; the following entries extend it.

### M3 mixed mask — flips at M3 cutover

`kernel::continuation::tests::controller_mixed_ppoll_netlink_real_service_wake`
uses actual dispatcher ppoll on eventfd plus synthetic netlink, actual carrier
service enrollment and netlink reply production. Two fork-related live tasks
have different persistent masks. The waiter installs a replacement mask;
ready completion restores its original mask and clears armed restoration,
without touching the peer. This is a positive semantic binding, not an
external-socket/pipe or all-EL1 owner proof.

`red_until_step3_m3_cancel_leaves_temporary_wait_mask_installed` observes exact
failure `cancelled wait retains temporary mask and armed restore` after
`CancellationCause::ServiceShutdown`. The cleanup probe settles once but the
surviving task stays unblocked and retains its armed persistent restore mask;
the fork peer's mask is unchanged. No production correction is included.
Exact reproduction: construct `WaitOnFds` Poll with `Replace(EMPTY)`, persistent
SIGUSR1 blocked, call `install_temporary_signal_mask`, then `cancel` while
keeping the context live. This is a cancellation API defect, not proof that
an ordinary Linux syscall currently returns with the wrong mask.

Remaining M3 cutover bindings: real external socket plus pipe simultaneous
readiness, stale host completion incarnation and fd reuse, copyout fault,
zero/finite/infinite deadlines, atomic enrollment signal-arrival race, and
ready/timeout/EINTR/cancel restoration through ppoll/pselect/epoll_pwait.
Inherited continuation signal/timeout reducers remain registered elsewhere;
this new ready path does not claim their entire mixed-set composition.

### M4 cyclic rights — flips at M4 cutover

`dispatch::net::scm_rights::tests::red_until_step3_m4_cyclic_rights_survive_last_external_close`
uses actual host socketpair/sendmsg placeholder transport with two live tables.
Each receiving socket has a queued placeholder retaining its own description.
After both sender-side placeholder handles and both table aliases close,
`gc` retains exactly 2/16/128 descriptions at 1/8/64 cycles. Exact failure:
`SCM vault cannot collect queued socket-description cycles`. The test claims
both scoped keys before releasing either description for bounded cleanup;
no cross-test global count or scan budget is inferred.

This reproduces a main reclamation defect: socket descriptions retained by
unreachable in-flight rights keep their own host receive queues alive, so the
placeholder writer never reports HUP and the vault's orphan collector cannot
break the cycle. No production fix is included. Reproduction command:
`CARGO_BUILD_JOBS=3 cargo test -p carrick-kernel --lib m4_cyclic -- --nocapture`.

Remaining M4: deterministic collector work budgets/historical VAULT visits,
ancillary truncation/fault rollback, all backing-kind flags/cursor/EOF lifetime,
SEQPACKET/message options and actual namespace/host-peer boundary bindings.
The cycle witness is cutover input, not proof that a collector exists.

### M5 multi-thread routing — flips at M5 cutover

`dispatch::signal::tests::m5_two_process_exact_thread_routing_isolated_at_four_populations`
keeps a fork peer and 1/8/32/128 live target threads. Exact kernel authorization
and post send three RT instances to the last target, checking SI_TKILL,
independent blocked masks and no queue changes in the leader, peer or other
threads. Retirement removes the exact key; a replacement has another key
and starts with no pending signal. This is a positive kernel routing binding,
not an instrumented no-population-scan proof or a concurrent born-thread race.

The former peer-tgkill known-red entry is retired: target resolution now uses
the caller's PID namespace rather than comparing the dispatcher root PID.
`m5_peer_tgkill_targets_root_group` and
`m5_peer_rt_tgsigqueueinfo_targets_root_group` assert delivery to the root's
exact secondary thread, leaving the peer and root leader queues untouched.
`m5_peer_kill_targets_root_group` and
`m5_peer_rt_sigqueueinfo_targets_root_group` assert root process pending and
an empty peer queue. Both queued-signal calls separately reject forged
nonnegative si_code from the peer. Each affected case fails before the fix;
`m5_peer_tkill_targets_root_group` confirms the existing namespace TID route.
Reproduction: `cargo test -p carrick-kernel --lib m5_peer_ -- --test-threads=1`.
The process-route and queued-code helper fixtures live under `serial_host`
because they pin the carrier-global HVPatch lane; `just test` executes them.
These VM-free syscall-boundary bindings do not close EL0 integration,
population-scan budgets, or EL1 signal ownership.

### M5 EL0 frame bindings

`carrick-conformance-next::probes_shard_0::m5_el0_nested_altstack_and_fault_frame_bindings`
reuses existing `sigreenter`, `siglongjmpaltstack`, `sigbadstack` and
`preemptsigstorm` executables through the signed embed TestContainer and the
existing probeinit fork/exec topology. Each runs for musl and glibc against
its committed source-hash-validated Linux oracle. Nested altstack frames,
siglongjmp reconciliation, faulted frame copyout and repeated async sigreturn
need actual EL0 execution; a host-only reducer cannot prove them. Fresh local
cross-builds and binary hashes precede these runs. No new executable probe
or CLI subprocess runner is added, and no Docker is invoked.
The existing signed PSTATE fixture is bound separately. These semantic
bindings do not prove that frame construction/restoration moved to EL1.

Remaining M5: malformed sigreturn frame validation, permission/accounting
exhaustion, concurrent born/exit/TID-reuse races and deterministic exact-route
work budgets; CLONE_SIGHAND/exec composition; ppoll/pselect handler restore;
stop/continue/SIGCHLD; traced/seccomp/fault/compute IRQ delivery owner proofs.
Existing lifecycle and frame semantics alone do not close those requirements.

## Follow-up signed verification receipts

Source: `c808b83002d099990f6e4defd1f8c97699820b0f`, clean for both runs.
Evidence: `docs/perf-results/2026-10-02-step3-m2-m5-followup/` contains full
logs, signed artifact receipts and SHA-256 for the ten freshly cross-built
probe/init binaries. Builds used `CARGO_BUILD_JOBS=3 cargo build --release`
with each aarch64 Linux libc target and the five named binaries; GNU used
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/opt/homebrew/bin/aarch64-unknown-linux-gnu-gcc`.

- `CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=s3m25-frames-20261002-a CARRICK_CONTRACT_ID=kernel.el1.signal-delivery-owner scripts/test-signed.sh carrick-conformance-next m5_el0_nested_altstack_and_fault_frame_bindings --nocapture`: pass, all eight probe/libc comparisons.
- `CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=s3m25-pstate-20261002-a CARRICK_CONTRACT_ID=kernel.el1.signal-delivery-owner scripts/test-signed.sh carrick-embed el1_sched_pstate_seen_by_the_guest_is_unchanged --nocapture`: pass.

Each script passed the unentitled negative control and reported zero scoped
remaining processes for the run ID and its CLI suffix. Receipts carry SHA-256,
CDHash, LC_UUID, entitlement digest and DOF presence for invoked executables.
The frame tests validate the committed source-hash-checked oracle; no fresh
Docker oracle was run. The Ubuntu image tag is not an immutable image-digest
acceptance receipt. These focused runs do not confer full backend acceptance.

No milestone is yet claimed fully cutover-ready: the precise M2–M5 remaining
lists above still apply. This follow-up supplies the requested four binding
areas and records the newly observed cancellation, cycle and tgkill reds.

### Final follow-up host gates

On source `c808b8300` (kernel/clippy) and receipt tree `b230195c1`
(lint/inventory; source unchanged), all four foreground commands exited zero:
`CARGO_BUILD_JOBS=3 just test-kernel`, `CARGO_BUILD_JOBS=3 just clippy`,
`CARGO_BUILD_JOBS=3 just lint-domains`, and
`CARGO_BUILD_JOBS=3 just check-inventory`. Kernel: 2358 passed, one existing
ignored, 155 serial-host cases filtered; ABI 109 and fdcore 32 passed, plus
the kernel-semantics suites. The production compiler census retains the
same 599 rows. Its macOS subset passes; Linux/FreeBSD/NetBSD profiles remain
pending as before. One new table guard is classified test_or_definition;
other operation inventory changes only rebind test line positions.

Follow-up commits: M3 `87c949c86`, M4 `fd09845b8`, M5 `c808b8300`;
signed evidence and inventory reconciliation `b230195c1`. The director's
signed-lane hold was read at the final mailbox breakpoint after both signed
runs had completed and scoped cleanup reported zero. No further signed runs
were started after reading the hold.
