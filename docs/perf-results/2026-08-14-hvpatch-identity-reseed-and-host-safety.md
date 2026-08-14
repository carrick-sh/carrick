# HVPatch kernel identity reseed and Darwin host-safety evidence

Date: 2026-08-14

Status: **GO — fourth review findings closed; ready for final independent re-review**

Implementation source: `437f28af6f90276bbb626197aca22dc735d68594`

Required base: `a609e43cc4630cb917588e873792af6ef4dab989`

## Decision

HVPatch now seeds its in-process kernel root at Linux PID/TGID/leader-TID/
PGID/SID 1. Descendants allocate their low Linux-shaped IDs from that same
kernel authority. Native and VMM retain their established host-derived
bootstrap identities.

HVPatch signal selectors are resolved against kernel tasks, threads, process
groups, credentials, sessions, signal dispositions, and pending queues. Any
selector that is not handled by that kernel path fails closed before the
mature-lane xsig or Darwin `kill(2)` transport. The reference lanes retain that
transport.

## RED observations and attribution

The cohesive static `kernelidentity` probe was introduced before the production
fixes and run through the signed HVPatch lane. Each Carrick run was scoped by a
generated `CARRICK_RUN_ID`, reaped before the Docker phase, and the two arms
were never concurrent.

| Signed run | RED observation | Attributed cause |
|---|---|---|
| `cr-85768-16143` | Root low-ID, `/proc`, descendant identity, signal, session, and exec relationships differed from Linux. | Root task and main `ThreadRegistry` were seeded from the Darwin PID; `/proc` used host synthesis; cross-task signals could leave the kernel graph. |
| `cr-86407-7096` | Root/kernel signal routing was fixed; `/proc`, child TID/PPID, cross-task signals, session, and exec `/proc` remained red. | HVPatch `/proc` had no exact `KernelContext` identity, and `tgkill` still met the mature current-host-thread-group guard. |
| `cr-87708-23278` | Remaining failures narrowed to child TID/PPID, cross-call aggregation, and group wait. | `gettid` still used the legacy host/single-thread `ThreadRegistry` fallback; `wait4` had no authoritative guest-PGID selector. |
| `cr-88429-23318` | Only the child TID relationship remained red. | The threaded-independent `gettid` fast path still bypassed the exact HVPatch kernel thread ID. |
| `cr-730-7073` | The strengthened reviewer probe terminated before producing Carrick relationships when a descendant sent default-lethal `SIGTERM` to PID 1; Docker produced all 38 then-current relationships. | The new kernel signal route returned before the mature PID-1 default-action immunity check. The same review also found that kernel-routed targets had bypassed credential authorization and that group/broadcast enumeration retained exiting tasks. |
| `cr-10120-22509` | The second reviewer-strengthened signed probe produced no relationship stream and hit its 15-second hard timeout; scoped cleanup was zero. | Default `SIGTSTP`/`SIGSTOP` still called the mature `stop_by_signal` path, which raises a Darwin signal and stopped the one host process carrying every HVPatch task. Default `SIGCONT` was also classified as terminate, and process-directed authorization returned `Missing` once a non-final leader thread exited. |
| `cr-18213-27118` | The third reviewer-strengthened signed probe hit its 20-second hard timeout during `SIGSTOP → WUNTRACED → SIGSTOP → SIGCONT`; scoped cleanup was zero. | Signal generation did not apply Linux's task-wide opposing-pending cancellation rule. The duplicate pending stop therefore survived continue generation and re-stopped the child. |
| `task3-self-stop-old-red` | A correctly signed HVPatch binary at the preceding source produced every established relationship as true but all seven new self `SIGSTOP → WUNTRACED → SIGCONT → WCONTINUED` relationships as false; scoped cleanup was zero. | HVPatch self and same-task sends still bypassed the kernel queues, so job-control generation fell into the legacy host-carrier/global-pending routes. |

Before production changes, focused tests failed to compile because the kernel
had no task-scoped stop/continue state, wait outcome, or retained process
credential authority. After adding only the test interfaces, the default
SIGCONT action test exposed its terminate classification. The signed RED is
retained in `2026-08-14-hvpatch-job-control-red-receipt.txt`; the binary was the
previous signed source `277ff71f` with SHA256 `ced6d5a3…`.

The third focused RED wave compiled and failed in both directions: SIGCONT left
pending stop signals in the process and thread queues, and a generated stop
left pending SIGCONT in both. A separate RED dequeued STOP before its default
action, generated SIGCONT, and proved the stale action could still re-stop the
task. The strengthened signed RED is retained in
`2026-08-14-hvpatch-job-control-generation-red-receipt.txt`; it used the
previous signed source `10e8a15b` and the exact strengthened probe later used
for GREEN.

The fourth focused RED wave proved two remaining concurrency defects. Two stop
signals dequeued before SIGCONT could consume the scalar cancellation state
twice: the first stale action was suppressed but the second could re-stop the
task. A compile RED for an authorization ticket tied to an exact task
generation proved that authorization and publication were still separate
bare-ID operations. The signed self-job-control RED and both focused REDs are
bound in `2026-08-14-hvpatch-exact-signal-red-receipt.txt`.

The former `debug_assert` encoded host-PID coincidence rather than a kernel
invariant. It now asserts the real invariant: the attached HVPatch root is task
1 and is initially the only live process. A unit test passes an unrelated host
PID of 67000 and proves the root task and leader TID are still 1. A separate
lane test proves native and VMM still return 67000.

## Architecture and routing changes

- HVPatch root construction uses `LINUX_BOOTSTRAP_PID` for `TaskId`, leader
  `LinuxTid`, root `ProcessGroupId`, and root `SessionId`.
- HVPatch getpid/gettid/set-tid-address and TPIDR_EL1 stamping use the exact
  `KernelContext` task/thread record. Mature lane namespace translation is
  unchanged.
- Synthetic `/proc/self/stat` and `/proc/self/status` accept an optional exact
  kernel identity. `None` preserves native/VMM rendering.
- Every HVPatch process send, including self, and every `tkill`/`tgkill` send,
  including same-task threads, uses the kernel pending queues. Signal zero uses
  kernel liveness. No HVPatch self or sibling route reaches the mature
  `raise(3)`, `SignalThread`, or global process-pending transports.
- Every selected HVPatch target is authorized from the caller and target's
  exact kernel credential objects. The authorization result is a private weak
  ticket to the exact `Task` or `Thread` generation, never a bare TaskId/TID.
  Publication upgrades that exact object and rechecks lifecycle and exact
  membership under the signal-generation lock; reap/reuse therefore fails
  closed instead of redirecting an already-authorized send. Group and
  broadcast selection enumerate exact `TaskKey` generations.
- Root privilege, real/effective versus real/saved-ID matching, and the
  same-session `SIGCONT` exception are decided in the kernel graph before
  liveness success or queue publication.
- Each task retains the last published leader credential generation separately
  from its live thread set. A non-final leader exit therefore leaves positive
  and group process signals authorized against a still-live task; exact
  thread-directed signals continue to require the named live thread.
- PID 1 drops default-action signals while retaining caught-signal delivery;
  `SIGKILL` and `SIGSTOP` keep their Linux exceptions. The decision reads the
  target's authoritative kernel `Sighand` rather than caller-local state.
  Default `SIGTSTP`, `SIGTTIN`, and `SIGTTOU` now receive the same PID-1
  immunity, while caught terminal-stop signals remain deliverable.
- Process-group and broadcast enumerators admit only `TaskLifecycle::Live`
  targets, so signal-zero cannot race-success solely against exiting members.
- Kernel wait selection now supports an exact authoritative process group for
  both live children and group-stamped zombies.
- HVPatch default-stop actions publish a task-local stopped state and park only
  that task's vCPU threads on a condition variable. `SIGCONT` and `SIGKILL`
  enqueue before releasing the state; default `SIGCONT` is nonterminal.
  WUNTRACED and WCONTINUED consume task-local state events encoded as Linux
  wait statuses. Native/VMM retain their established host-process job-control
  lowering.
- Job-control generation is serialized per task. Generating SIGCONT discards
  SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU from the shared process queue and every
  thread queue before enqueueing and resuming; generating any of those stop
  signals discards pending SIGCONT from all of the same queues. Queue hints,
  siginfo, and pending-action snapshots are updated in the same transaction.
  The latest generation state remains published after a default action, so a
  later SIGCONT cancels every stop dequeued before it, not only the first one.
  A newly generated stop supersedes that cancellation and can stop normally.
- The mature xsig/host transport snapshots the typed selector before lowering,
  and rejects every HVPatch selector before xsig lookup or `libc::kill`.

## Signed differential GREEN

Exact command:

```sh
CARRICK_EXEC_BACKEND=hvpatch \
  CARRICK_PROBE_EXEC_AS_INIT=1 \
  CARRICK_PROBE_RECEIPT=docs/perf-results/2026-08-14-hvpatch-kernelidentity-cleanup.txt \
  scripts/run-probe.sh kernelidentity \
  | tee docs/perf-results/2026-08-14-hvpatch-kernelidentity-differential.txt
```

Final run `cr-29791-6307` was `MATCH kernelidentity`; scoped cleanup reported
`remaining carrick procs (run-id cr-29791-6307) = 0`. All 64 relationships
matched native arm64 Docker:

- exact root getpid/gettid 1, PGID/SID, `/proc`, PID 1 and selector-zero
  liveness;
- broadcast `-1` and negative PGID 1 liveness;
- nonzero self `kill` and `tgkill` delivery;
- PID-1 immunity to a default-lethal signal and delivery to an installed
  handler;
- PID-1 immunity to positive and group default `SIGTSTP`;
- task-local SIGSTOP/SIGCONT with correct WUNTRACED/WCONTINUED status, a
  continuously runnable sender, resumed child, and clean terminal reap;
- a second SIGSTOP generated while stopped, then discarded by SIGCONT so the
  child still resumes and exits cleanly;
- child self `kill(getpid(), SIGSTOP)`, parent-side WUNTRACED/SIGCONT/
  WCONTINUED, a continuously runnable carrier, and resumed child exit;
- positive-process, thread-directed, and negative-group signal-zero `EPERM`
  across distinct non-root credentials;
- an exact `set_tid_address` clear barrier proving non-final leader exit,
  followed by successful positive/group signal-zero, nonzero delivery to the
  surviving sibling, and clean task exit;
- child PID/TID/PPID, process group/session, and `/proc` identity;
- cross-task kill, tgkill, group signal, and former early-xsig SIGCHLD shape;
- `waitpid(-child_pgid)`;
- `setsid` identity; and
- exec PID/TID/PGID/SID and `/proc` persistence plus caught/ignored disposition
  reset/preservation.

The complete values are retained in
`2026-08-14-hvpatch-kernelidentity-differential.txt`.

## Fail-closed Darwin host-safety trace

`hvpatch-identity-host-safety` is a bundled `carrick trace` profile, not a
scratch D script. It observes the target and all progeny, requires positive
populations for Linux kill selectors `1`, `0`, `-1`, `< -1`, tgkill, and the
former SIGCHLD xsig shape. It requires at least three exact SIGSTOP populations
and one SIGCONT population. This capture recorded three and two respectively;
paired with the signed relationships, it covers both parent-directed and
self-directed job control and proves the shared carrier was never host-stopped.
It independently watches Darwin
`syscall::kill:entry`. A Darwin target in the guest low-ID range `[-63, 63]`
emits a fatal `host-kill` record. The strict reader also rejects a missing
population, timeout, provider error, DTrace drop, interruption, absent/nonzero
target exit, duplicate/truncated records, or a lossy consumer capture.

Exact command shape (the static probe bytes were piped on stdin):

```sh
CARRICK_RUN_ID=task3-identity-host-safety-exacttickets \
  target/release/carrick trace \
  --profile hvpatch-identity-host-safety \
  --trace-out docs/perf-results/2026-08-14-hvpatch-identity-host-safety.raw \
  run ubuntu:24.04 --exec-backend hvpatch --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && exec /tmp/p'
sudo -n scripts/sudo/kill.sh task3-identity-host-safety-exacttickets
```

Authenticated terminal record:

```text
HVPATCHIDENTITY1|summary|status=ok|guest_kills=25|positive_one=5|zero=3|broadcast=2|negative_group=4|tgkills=4|xsig_shapes=1|stop_signals=3|continue_signals=2|host_low_kills=0|bounded=0|errors=0|drops=0|target_exited=1|target_exit_seen=1|target_exit_code=0|target_exit_reason=1
```

The consumer accepted it as `guest_kills=25, guest_sigstops=3,
guest_sigconts=2, low_guest_id_host_kills=0`. Scoped cleanup reported
`remaining carrick procs (run-id task3-identity-host-safety-exacttickets) = 0`.

The durable diagnostic `hvpatch-job-control-flow.d` independently observed all
29 guest signal-generation events and terminated with
`status=ok|errors=0|drops=0|bounded=0|target_exited=1`. Its header records that
per-vCPU DTrace buffers may flush counter records out of order, so this capture
is cited only for exact population and liveness, never timing.

## Focused and full gates

Focused runtime tests were run serially and passed 35/35 for dispatch signal
policy, 66/66 for kernel operations, and 19/19 for the HVPatch adapter:

```sh
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dispatch::signal::tests
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::operations
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib hvpatch::tests
```

The exact tests covered root seed, native/VMM preservation, exact HVPatch
gettid, explicit `/proc` fields, pre-xsig/host-kill selector blocking,
authoritative process-group wait, exact thread-directed signal membership,
credential and session authorization, PID-1 disposition policy, and exiting
target exclusion. The new focused cases also cover retained non-root credential
authority after leader exit, task-local stop/continue transitions, Linux wait
status encoding, default SIGCONT, and PID-1 terminal-stop policy.
The third review tests cover process- and thread-directed cancellation across
both queue classes plus the dequeue/default-action race. The fourth review
tests cover multiple independently dequeued stale stops, a new stop generation
after continue, exact self/same-task queue ownership, and forced PID reuse
between authorization and publication.

The CLI/profile tests passed 3/3 under the repository-required CLI stack:

```sh
RUST_MIN_STACK=8388608 RUST_TEST_THREADS=1 \
  cargo test -p carrick-cli --bin carrick hvpatch_identity
```

They cover CLI selection, acceptance of a complete lossless stream, and
rejection of host escape, a missing selector, and capture loss.

The exact post-commit gate was then run at implementation HEAD
`437f28af6f90276bbb626197aca22dc735d68594`:

```sh
RUST_TEST_THREADS=1 just ci
```

Result: exit 0. This includes fmt-check, clippy with warnings denied,
typed-domain lint, deny, matrix drift, check, rustdoc, host tests, and integration
tests. The runtime library ran 1,591 cases with 0 failures (5 ignored); the
runtime integration suite was 296 passed / 0 failed.

## Signed artifact provenance

The release binary was rebuilt and re-signed with `just build` after the
implementation commit and before both final captures.

| Property | Value |
|---|---|
| Source commit | `437f28af6f90276bbb626197aca22dc735d68594` |
| Carrick SHA256 | `9bf917133448408a58fb3e838dbeb9f405b735f86bbd43c50dbd98150fd55354` |
| Probe SHA256 | `48364d5473c643d67a105951748fe64ff7fadd306961c2ec297605e483f7f75d` |
| LC_UUID | `794A6FA2-FA57-3448-B11F-AF3EA0468229` |
| Signature | ad hoc; CDHash `50b7604e68affa7f98418228ac36888f80740a36` |
| Entitlement | `com.apple.security.hypervisor = true` |
| DOF | `__TEXT,__dof_carrick` present (address `0x00000001012b7db2`, size `0xb8e8`) |

Raw receipt hashes:

| Receipt | SHA256 |
|---|---|
| `2026-08-14-hvpatch-job-control-red-receipt.txt` | `2e34f499469af0ef2bf4842d832ce0cf34835e901553df22a6a123402dfaa3cb` |
| `2026-08-14-hvpatch-job-control-generation-red-receipt.txt` | `0765976b427678b6fdbb956f7239b27b552d5e8bfb6946e4ef5f14b67a68ffd3` |
| `2026-08-14-hvpatch-exact-signal-red-receipt.txt` | `10845a5cfc19b1cedaff63695c7cd2a29e6e34f22b22c0ace3e8fbcb9f8dafc8` |
| `2026-08-14-hvpatch-kernelidentity-differential.txt` | `3832c8f9be77667e8a9d528345e86b8b1da8188867c8cb61f8e220c683a9f852` |
| `2026-08-14-hvpatch-kernelidentity-cleanup.txt` | `404301941fe6d5cdb5d65497b32d70e517c53c533d28f8bb5a178fe4723fdcd9` |
| `2026-08-14-hvpatch-identity-host-safety.raw` | `495b9d48d66b0e002847c2f9f2c31b683cf1bf4daed1d0327b62b056ad5836cc` |
| `2026-08-14-hvpatch-identity-host-safety-command.txt` | `58a475644a5f3f0d809ccd76c7c2eff464fdd914f880be15af9868b9a061dc4f` |
| `2026-08-14-hvpatch-identity-host-safety-cleanup.txt` | `9671b73649df1f76016e1c13c3112f7bbece65d8da45f6eeccec1ccab512ca1d` |
| `2026-08-14-hvpatch-job-control-flow.raw` | `f0b63b44ddabf3f726265413e4621e14ce9b891ff993be231665e17b7e1bdd74` |
| `2026-08-14-hvpatch-job-control-flow-command.txt` | `6df2b4f332a63274c5819bc295cc04ab875ffc95a8d1c47d253aaf5340942c65` |
| `2026-08-14-hvpatch-job-control-flow-cleanup.txt` | `6563e29cd7288df2277956d66ce13bbb025d4468a5bfe4950576bb08a3871dc7` |

## Remaining concerns

No known Task 3 acceptance gap remains. HVPatch `waitid(P_PGID, ...)` is still an
explicit `ECHILD` outside this task's required group-`waitpid` minimum; it was
not baselined or mistaken for a passing semantic. The new kernel group selector
is the authority that a future `waitid(P_PGID)` implementation should reuse.
