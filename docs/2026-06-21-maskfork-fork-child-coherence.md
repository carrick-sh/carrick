# maskfork conformance failure — fork-child guest-memory read-staleness (HVF)

**Status:** root-caused, NOT fixed. **Pre-existing** on `codex/matrix-liveness-closure`
(the base of `audit/structural-leverage`); none of the structural-audit commits
touch any signal/fork/mask code (`git diff acd249f4..HEAD -- '*signal*' '*fork*'`
is empty). Surfaced while runtime-verifying the audit work on the HVF rig.

## Symptom

`just conformance-probes` fails one gating probe, `arm64:musl:maskfork`:

```
- carrick: child_inherits_blocked_mask=false   + linux: true
- carrick: child_pending_cleared_on_fork=false  + linux: true
  carrick: parent_pending_survives_fork=true    (correct)
```

The probe (conformance-probes/src/bin/maskfork.rs): parent blocks SIGUSR1, raises
it (pending), forks; the child must (a) inherit the blocked mask and (b) have its
pending set cleared. Reproduces deterministically via both `run --raw --fs host`
(the harness path) and `run-elf`.

## Root cause (evidence)

carrick's bookkeeping is **correct** — a gated trace at the child's `rt_sigprocmask`
/ `rt_sigpending` shows, under the child's own tid (post-fork pid):

```
[MF] sigprocmask-query pid=7038 tid=7038 mask_for=0x200  masks_keys=[7038]   # mask INHERITED
[MF] sigpending        pid=7038 tid=7038 pending=0x0      # pending CLEARED
```

i.e. `migrate_thread_signal_state(parent_tid, child_tid)` (vcpu_loop/quiesce.rs)
ran, moved the blocked mask to the child's tid, and cleared the child's pending —
exactly right. Yet the guest reports the opposite.

The only model consistent with **all** the data: the fork child's vCPU **reads
stale pre-fork stack memory**. Neither the guest's own `memset(&cur/&p, 0)` nor
carrick's syscall-buffer writes invalidate the child's stale stage-2 read view:

- `cur` (mask query buffer) reads its pre-fork stale value `0` → `sigismember(SIGUSR1)`
  false → `child_inherits_blocked_mask=false`.
- `p` (pending buffer) reads `0x200` — left over from the parent's
  `set = {SIGUSR1}` (= `0x200`) at that same stack slot → `sigismember(SIGUSR1)`
  true → `child_pending_cleared_on_fork=false`.

This rules out a tid mismatch (carrick uses the right tid with the right state)
and points squarely at the **arm64-HVF stage-2 coherence** wall (no host-driven
stage-2 TLB flush): the fork child rebuilds its VM, but writes to the child's
stack pages are not made visible to the vCPU's read view. Same class as the
documented SHARED_FILE / go-build MAP_SHARED-file coherence gaps.

## Why it's narrow (only maskfork fails)

The failure needs "fork WITHOUT execve, then read back a stack buffer written
post-fork, and compare to a value that differs from the pre-fork stale content."
Most fork-heavy workloads execve (fresh address space) or make intervening
syscalls before reading critical stack data, so they don't trip it. maskfork
reads `cur`/`p` immediately after fork.

## Fix direction (not done)

Per the project's HVF stage-2 notes, the recommended (unimplemented) remedy is to
recreate the faulting vCPU / force a stage-2 invalidation on the child's pages
after the fork VM rebuild, so the child's stack reads reflect post-fork writes.
This is the known-hard HVF coherence area; it needs a focused HVF-backend change
plus the maskfork probe as the regression gate. A first cheap check: bisect the
branch's M:N vCPU reclaim/recreate work — if maskfork passed before it, the
fork-child vCPU rebuild changed in a way that regressed stack coherence.

## Reproduce

```
base64 < conformance-probes/target/aarch64-unknown-linux-musl/release/maskfork \
  | ./target/release/carrick run --platform linux/arm64 --raw --fs host \
      ubuntu:24.04 /bin/sh -c "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p"
# or, single binary:
./target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/maskfork
```
