# HVPatch kernel identity reseed and Darwin host-safety evidence

Date: 2026-08-14

Status: **GO — ready for spec and quality review**

Implementation source: `f2075a2aaa1d384360273850e88c8f7b035ee0a0`

Required base: `a609e43cc4630cb917588e873792af6ef4dab989`

## Decision

HVPatch now seeds its in-process kernel root at Linux PID/TGID/leader-TID/
PGID/SID 1. Descendants allocate their low Linux-shaped IDs from that same
kernel authority. Native and VMM retain their established host-derived
bootstrap identities.

HVPatch signal selectors are resolved against kernel tasks, threads, process
groups, and pending queues. Any selector that is not handled by that kernel
path fails closed before the mature-lane xsig or Darwin `kill(2)` transport.
The reference lanes retain that transport.

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
- Kernel wait selection now supports an exact authoritative process group for
  both live children and group-stamped zombies.
- The mature xsig/host transport snapshots the typed selector before lowering,
  and rejects every HVPatch selector before xsig lookup or `libc::kill`.

## Signed differential GREEN

Exact command:

```sh
CARRICK_EXEC_BACKEND=hvpatch \
  CARRICK_PROBE_RECEIPT=docs/perf-results/2026-08-14-hvpatch-kernelidentity-cleanup.txt \
  scripts/run-probe.sh kernelidentity 2>&1 \
  | tee docs/perf-results/2026-08-14-hvpatch-kernelidentity-differential.txt
```

Final run `cr-92732-27150` was `MATCH kernelidentity`; scoped cleanup reported
`remaining carrick procs (run-id cr-92732-27150) = 0`. All 31 relationships
matched native arm64 Docker:

- root getpid/gettid, PGID/SID, `/proc`, PID 1 and selector-zero liveness;
- broadcast `-1` and negative PGID 1 liveness;
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
former SIGCHLD xsig shape, and independently watches Darwin
`syscall::kill:entry`. A Darwin target in the guest low-ID range `[-63, 63]`
emits a fatal `host-kill` record. The strict reader also rejects a missing
population, timeout, provider error, DTrace drop, interruption, absent/nonzero
target exit, duplicate/truncated records, or a lossy consumer capture.

Exact command shape (the static probe bytes were piped on stdin):

```sh
CARRICK_RUN_ID=task3-identity-host-safety-final \
  target/release/carrick trace \
  --profile hvpatch-identity-host-safety \
  --trace-out docs/perf-results/2026-08-14-hvpatch-identity-host-safety.raw \
  run ubuntu:24.04 --exec-backend hvpatch --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
sudo -n scripts/sudo/kill.sh task3-identity-host-safety-final
```

Authenticated terminal record:

```text
HVPATCHIDENTITY1|summary|status=ok|guest_kills=8|positive_one=1|zero=1|broadcast=2|negative_group=1|tgkills=2|xsig_shapes=1|host_low_kills=0|bounded=0|errors=0|drops=0|target_exited=1|target_exit_seen=1|target_exit_code=0|target_exit_reason=1
```

The consumer accepted it as `guest_kills=8,
low_guest_id_host_kills=0`. Scoped cleanup reported
`remaining carrick procs (run-id task3-identity-host-safety-final) = 0`.

## Focused and full gates

Focused runtime tests were run serially with this command shape and passed
1/1 each:

```sh
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib <exact-test-name>
```

The exact tests covered root seed, native/VMM preservation, exact HVPatch
gettid, explicit `/proc` fields, pre-xsig/host-kill selector blocking,
authoritative process-group wait, and exact thread-directed signal membership.

The CLI/profile tests passed 3/3 under the repository-required CLI stack:

```sh
RUST_MIN_STACK=8388608 RUST_TEST_THREADS=1 \
  cargo test -p carrick-cli --bin carrick hvpatch_identity
```

They cover CLI selection, acceptance of a complete lossless stream, and
rejection of host escape, a missing selector, and capture loss.

The exact post-commit gate was then run at implementation HEAD
`f2075a2aaa1d384360273850e88c8f7b035ee0a0`:

```sh
RUST_TEST_THREADS=1 just ci
```

Result: exit 0. This includes fmt-check, clippy with warnings denied,
typed-domain lint, deny, matrix drift, check, rustdoc, host tests, and integration
tests. The runtime library result was 1,573 passed / 0 failed / 5 ignored; the
runtime integration suite was 296 passed / 0 failed.

## Signed artifact provenance

The release binary was rebuilt and re-signed with `just build` after the
implementation commit and before both final captures.

| Property | Value |
|---|---|
| Source commit | `f2075a2aaa1d384360273850e88c8f7b035ee0a0` |
| Carrick SHA256 | `63da900981baa68a64c214a8dd0bbd26e372f0e4b246d4681229e059e450952d` |
| Probe SHA256 | `fa20f136d6c1ffe90e6095a374af6a6ff825ded88a85ce960aabfb9961a46fd6` |
| LC_UUID | `B5A15CBA-6A5C-364C-9DAB-30582F84DA0E` |
| Signature | ad hoc; CDHash `c832a6a0151d683593b5b456ff91cbf6afbde0b6` |
| Entitlement | `com.apple.security.hypervisor = true` |
| DOF | `__TEXT,__dof_carrick` present (address `0x00000001012b3e7f`) |

Raw receipt hashes:

| Receipt | SHA256 |
|---|---|
| `2026-08-14-hvpatch-kernelidentity-differential.txt` | `a29d8eeb15a3111b1eab49b4a01ff1d5a7bdafa0f8538d093e307286205dd510` |
| `2026-08-14-hvpatch-kernelidentity-cleanup.txt` | `e75dd3ce93da7eb5944e8e15b88012057d54755c2d101d12e16a561fa2c772a5` |
| `2026-08-14-hvpatch-identity-host-safety.raw` | `6c4a7a17c35cab637140fa4edb5affd55b8df02611b7817b8cafbe88d3d96095` |
| `2026-08-14-hvpatch-identity-host-safety-command.txt` | `7c595b9205c95d69c28e8d2e622f2287844ff3735ce682139e27a6cf755f2e4` |
| `2026-08-14-hvpatch-identity-host-safety-cleanup.txt` | `f13dbb0aeb8331f07ba4522e23e0d4cd058e448fe5d7a6198cf20d5998651d59` |

## Remaining concerns

No Task 3 acceptance gap remains. HVPatch `waitid(P_PGID, ...)` is still an
explicit `ECHILD` outside this task's required group-`waitpid` minimum; it was
not baselined or mistaken for a passing semantic. The new kernel group selector
is the authority that a future `waitid(P_PGID)` implementation should reuse.
