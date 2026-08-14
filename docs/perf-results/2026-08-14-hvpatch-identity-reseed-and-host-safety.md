# HVPatch kernel identity reseed and Darwin host-safety evidence

Date: 2026-08-14

Status: **GO — second review findings closed; ready for independent re-review**

Implementation source: `10e8a15bf65497cdf884bcd6ab3b072f3b02d9d1`

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

Before production changes, focused tests failed to compile because the kernel
had no task-scoped stop/continue state, wait outcome, or retained process
credential authority. After adding only the test interfaces, the default
SIGCONT action test exposed its terminate classification. The signed RED is
retained in `2026-08-14-hvpatch-job-control-red-receipt.txt`; the binary was the
previous signed source `277ff71f` with SHA256 `ced6d5a3…`.

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
- Positive process targets, `tkill`/`tgkill` thread targets, and process-group
  targets use kernel task/group lookup and kernel pending queues. Signal zero
  uses kernel liveness.
- Every selected HVPatch target is authorized from the caller and target's
  exact kernel credential objects. Root privilege, real/effective versus
  real/saved-ID matching, and the same-session `SIGCONT` exception are decided
  in the kernel graph before liveness success or queue publication.
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
- The mature xsig/host transport snapshots the typed selector before lowering,
  and rejects every HVPatch selector before xsig lookup or `libc::kill`.

## Signed differential GREEN

Exact command:

```sh
CARRICK_EXEC_BACKEND=hvpatch \
  CARRICK_PROBE_EXEC_AS_INIT=1 \
  CARRICK_PROBE_RECEIPT=docs/perf-results/2026-08-14-hvpatch-kernelidentity-cleanup.txt \
  scripts/run-probe.sh kernelidentity 2>&1 \
  | tee docs/perf-results/2026-08-14-hvpatch-kernelidentity-differential.txt
```

Final run `cr-11504-5266` was `MATCH kernelidentity`; scoped cleanup reported
`remaining carrick procs (run-id cr-11504-5266) = 0`. All 56 relationships
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
former SIGCHLD xsig shape. It now also requires exact SIGSTOP and SIGCONT
populations, so a cleanly completed target proves the shared carrier was never
host-stopped. It independently watches Darwin
`syscall::kill:entry`. A Darwin target in the guest low-ID range `[-63, 63]`
emits a fatal `host-kill` record. The strict reader also rejects a missing
population, timeout, provider error, DTrace drop, interruption, absent/nonzero
target exit, duplicate/truncated records, or a lossy consumer capture.

Exact command shape (the static probe bytes were piped on stdin):

```sh
CARRICK_RUN_ID=task3-identity-host-safety-reviewfix \
  target/release/carrick trace \
  --profile hvpatch-identity-host-safety \
  --trace-out docs/perf-results/2026-08-14-hvpatch-identity-host-safety.raw \
  run ubuntu:24.04 --exec-backend hvpatch --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && exec /tmp/p'
sudo -n scripts/sudo/kill.sh task3-identity-host-safety-reviewfix
```

Authenticated terminal record:

```text
HVPATCHIDENTITY1|summary|status=ok|guest_kills=22|positive_one=5|zero=3|broadcast=2|negative_group=4|tgkills=4|xsig_shapes=1|stop_signals=1|continue_signals=1|host_low_kills=0|bounded=0|errors=0|drops=0|target_exited=1|target_exit_seen=1|target_exit_code=0|target_exit_reason=1
```

The consumer accepted it as `guest_kills=22, guest_sigstops=1,
guest_sigconts=1, low_guest_id_host_kills=0`. Scoped cleanup reported
`remaining carrick procs (run-id task3-identity-host-safety-reviewfix) = 0`.

## Focused and full gates

Focused runtime tests were run serially and passed 35/35 for dispatch signal
policy, 68/68 for kernel operations, and 19/19 for the HVPatch adapter:

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

The CLI/profile tests passed 3/3 under the repository-required CLI stack:

```sh
RUST_MIN_STACK=8388608 RUST_TEST_THREADS=1 \
  cargo test -p carrick-cli --bin carrick hvpatch_identity
```

They cover CLI selection, acceptance of a complete lossless stream, and
rejection of host escape, a missing selector, and capture loss.

The exact post-commit gate was then run at implementation HEAD
`10e8a15bf65497cdf884bcd6ab3b072f3b02d9d1`:

```sh
RUST_TEST_THREADS=1 just ci
```

Result: exit 0. This includes fmt-check, clippy with warnings denied,
typed-domain lint, deny, matrix drift, check, rustdoc, host tests, and integration
tests. The runtime library result was 1,579 passed / 0 failed / 5 ignored; the
runtime integration suite was 296 passed / 0 failed.

## Signed artifact provenance

The release binary was rebuilt and re-signed with `just build` after the
implementation commit and before both final captures.

| Property | Value |
|---|---|
| Source commit | `10e8a15bf65497cdf884bcd6ab3b072f3b02d9d1` |
| Carrick SHA256 | `f7d56db370fe2873ddecd9030864279339c6760d506da98108bdb9f86dfaf061` |
| Probe SHA256 | `6d15641539760a5469a67420d4581020c374019210a446d430c06d552baf999d` |
| LC_UUID | `52C22344-709D-3CCD-A002-7C6E4C13B9C7` |
| Signature | ad hoc; CDHash `1b09866235526973b6728418af010d99f0fed479` |
| Entitlement | `com.apple.security.hypervisor = true` |
| DOF | `__TEXT,__dof_carrick` present (address `0x00000001012b3dfa`) |

Raw receipt hashes:

| Receipt | SHA256 |
|---|---|
| `2026-08-14-hvpatch-job-control-red-receipt.txt` | `2e34f499469af0ef2bf4842d832ce0cf34835e901553df22a6a123402dfaa3cb` |
| `2026-08-14-hvpatch-kernelidentity-differential.txt` | `380dac235d353cb0011173ad7909f9e0e489e8bd25734fab61760bd8bc05d574` |
| `2026-08-14-hvpatch-kernelidentity-cleanup.txt` | `d8a8b421fac516c4e6c8e594e7fef9a2e07a4d9fff5474dbefead720a8a29215` |
| `2026-08-14-hvpatch-identity-host-safety.raw` | `367817cf88f340a2511bc4bb94c01894ee9a7a0f7f5307c40d9ecefe736dfd43` |
| `2026-08-14-hvpatch-identity-host-safety-command.txt` | `e94f6aeb3745f63c05f7c41b32d2d139d65d263a03e13069142750fb38c85dc3` |
| `2026-08-14-hvpatch-identity-host-safety-cleanup.txt` | `29906bba0c1295cc3fca18b2f976325b9aaccb02c44a0335c15a6d93cc4f597d` |

## Remaining concerns

No known Task 3 acceptance gap remains. HVPatch `waitid(P_PGID, ...)` is still an
explicit `ECHILD` outside this task's required group-`waitpid` minimum; it was
not baselined or mistaken for a passing semantic. The new kernel group selector
is the authority that a future `waitid(P_PGID)` implementation should reuse.
