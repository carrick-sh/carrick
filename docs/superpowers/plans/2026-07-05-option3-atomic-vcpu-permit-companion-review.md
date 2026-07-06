# Companion review - Option 3 atomic vCPU admission permit

Companion to `docs/superpowers/plans/2026-07-05-option3-atomic-vcpu-permit.md`.

Scope: static review only. This writeup reads the current tree, the saved
`.superpowers/sdd/task-3b-mech-atomic.patch`, the 3b report, and the existing
HVF lifecycle code. It does not depend on a build, test, or guest run.

## Executive finding

The Option 3 direction is plausible, but the current plan is not yet executable
as a safe implementation plan. It correctly identifies the missing property of
the 3b atomic attempt: the old per-slot `flock` did not just serialize admission,
it also gave kernel-backed reclaim when a process died or skipped Rust drops.

The plan still treats reclaim as a layer bolted onto a shared counter. That is
the wrong center of gravity. The replacement has to make ownership itself the
source of truth: every admitted count must be represented by a generation-stamped
slot that a local release, cooperative `_exit` cleanup, or supervisor death event
can reclaim idempotently. A count that exists without a reclaimable owner record
is the exact failure mode that timed out the node suites.

The original plan should be amended before any agent applies the saved 3b patch.

## Current invariants worth preserving

The flock implementation has three load-bearing invariants:

1. `create_vm_with_admission` acquires a cross-process permit only for admission
   classes with a budget. `ExecveRebuild` and vfork rebuilds are deliberately
   ungated (`VmCreateAdmission::global_permit_budget_from_mn`, `trap.rs:726-734`).
2. A permit is not released on every `vcpu_destroyed`. It is released only if the
   destroyed `vcpu_id` is present in `GlobalVcpuPermitState.live`
   (`trap.rs:854-883`). This prevents unpermitted sibling vCPUs from releasing
   the process-VM permit.
3. The fork child must discard inherited parent-side permit tracking without
   releasing the parent's permit. In the flock path it closes inherited file
   descriptors because the child inherited them; in an atomic path it must clear
   the inherited local map without decrementing the shared table
   (`trap.rs:887-897`).

The saved 3b patch preserved the local `vcpu_id` guard with a `HashSet<u64>`,
but it replaced the kernel-reclaimed fd with a bare `AtomicUsize`. The 3b report
then found the shared count pinned at budget with no local owners:

- `cur=4 budget=4 live_len=0`
- node suites timed out at roughly 447x
- the baseline flock path matched in about 7-8 seconds

That evidence means the replacement design must prove that every shared count
is owned by a reclaimable slot before it tries to optimize the acquire path.

## Problems in the current Option 3 plan

### 1. Increment-before-owner can still leak

Task 1 says to CAS-increment `live` while below budget, then claim a free
owner-PID slot. If the process dies between those two operations, the shared
count has no owner slot. The supervisor cannot infer who to reclaim. That is a
permanent leak in the same shape as the 3b failure.

Fix: never create an unowned count. The slot table should be the source of
truth, or the count update must be after a reclaimable owner slot exists.

A safe shape is:

- claim a free slot with a packed atomic slot word (`state`, `pid`,
  `generation`);
- count occupied slots against the caller's budget;
- if this claim exceeds budget, release the slot and back off;
- otherwise return a `GlobalVcpuPermit { slot, generation, owner_pid }`;
- register that token against the created `vcpu_id`.

Scanning 64 slots is still a userspace operation and should be much cheaper than
`open` + `flock` + backoff. More importantly, a crash after slot claim is
reclaimable because the owner record already exists.

### 2. `release(pid)` is too weak; release must be token-guarded

The plan's interface centers `release_atomic(pid)`. That loses the current
`vcpu_id -> permit` guard. Current `vcpu_destroyed(vcpu_id)` runs for many
non-global-permit vCPUs: sibling fork quiesce, per-thread exit, shared-wait
park, and reclaim surfaces all call `vcpu_destroyed` after raw
`hv_vcpu_destroy` (`trap.rs:2845-2849`, `2900-2903`, `2993-2997`,
`3048-3053`, `3169-3172`, `3544-3548`).

If the atomic path releases by PID without first proving this `vcpu_id` owns a
global permit token, an unrelated sibling vCPU destroy can release the process
VM's global slot. That would undercount admission and reintroduce
`HV_NO_RESOURCES` risk.

Fix: keep an in-process `HashMap<u64, PermitToken>` where `PermitToken` includes
`slot`, `generation`, and `owner_pid`. `vcpu_destroyed(vcpu_id)` removes a token
by id and releases only that exact token. Reaper and process-exit cleanup may
reclaim by PID/generation, but normal vCPU teardown should stay id-scoped.

### 3. Periodic `kill(pid, 0)` is not a crash-reclaim equivalent

The plan makes `EVFILT_PROC/NOTE_EXIT` conditional on whether the 20 ms
polling reaper passes the gate. That is too weak for this workload.

`kill(pid, 0)` answers "does a process with this pid exist and may I signal it",
not "has the original owner exited and become reclaimable". An exited child can
remain as a zombie until reaped, and pid reuse can make a stale pid look live.
The existing code already treats `NOTE_EXIT` as the native readiness edge and
uses `waitid(WNOWAIT)` as the non-consuming readiness check
(`host_signal.rs:197-205`, `353-361`; `io_wait.rs:659-667`).

Fix: make `EVFILT_PROC` prompt reclaim part of the first reclaim task, not a
conditional Task 4. Keep periodic scanning only as a safety net for missed
registrations, kqueue setup failure, or diagnostic self-healing.

### 4. Cooperative fork-child `_exit` should release explicitly

The runtime already has a backend hook precisely for cleanup before a forked
guest child calls `_exit`: `engine.process_exit_cleanup()` is called on normal
fork-child exit and signal death (`vcpu_loop/mod.rs:1461-1475`,
`1495-1505`). HVF currently overrides that hook as a no-op because the flock path
was fd-lifetime-bound (`hvf_aarch64_engine.rs:295-298`).

In the atomic path, this hook becomes useful. The child is alive, on the owning
thread, and can release its own slot before `_exit` skips drops. That shrinks
the churn window and leaves the reaper for hard death (`SIGKILL`, host crash,
segfault, missed cooperative cleanup).

Fix: add an HVF atomic-only `process_exit_cleanup` release that frees all slots
owned by the current PID, or at least the current engine's registered token.
It must not run on the parent after a fork reset, and it must be idempotent with
the supervisor.

### 5. The proposed runtime integration point is wrong

Task 2 wires the reaper from `crates/carrick-runtime/src/threaded_loop.rs` using
`crate::hvf::...`. That module path does not exist in `carrick-runtime`. The
runtime re-exports the HVF leaf crate as `crate::trap`, `crate::host_signal`,
`crate::io_wait`, etc. (`runtime lib.rs:163-166`).

The generic loop also runs for non-HVF backends and should not grow direct HVF
knowledge. The existing backend-specific setup hook is
`HvfHostBackend::pre_loop_setup` (`runtime.rs:1610-1613`). Starting the root
reaper there, through a `crate::trap::start_vcpu_permit_reaper()` re-export, is
cleaner than editing the generic loop body.

One caveat: the initial HVF VM is created before the threaded loop begins, so
the permit region must already exist by then. Starting the reaper in
`pre_loop_setup` is fine for supervision, but region initialization still belongs
in the initial admission path or an earlier HVF engine init hook.

### 6. The exec leak premise is stale

The plan says `ExecveRebuild` must explicitly release the pre-exec permit. The
current code already destroys the inherited vCPU and calls `vcpu_destroyed` before
creating the ungated exec replacement (`trap.rs:3544-3556`). Because
`ExecveRebuild` has no global budget, it does not acquire a new permit.

That does not mean exec needs no test. It means Task 3 should first prove the
current path is covered after the atomic token rewrite. Add an explicit release
only if the tokenized atomic path bypasses `vcpu_destroyed`; otherwise an extra
`release_atomic(getpid())` risks double-release.

### 7. The plan's cap-raise experiment conflicts with its own constraints

The global constraint says keep cap math unchanged. Task 5 then proposes raising
`CONSERVATIVE_GLOBAL_VM_CAP` from 4 toward physical cores. That is a valid
experiment, but it should be a separate temporary patch or env-gated experiment,
not a commit named `test(hvf): validate...`.

Keep the atomic-permit correctness spike and the cap-raise payoff measurement
separate. Otherwise a failed fork-storm gate is ambiguous: it may be the new
permit, the raised cap, or their interaction.

## Recommended replacement design

### Shared region

Use one `MAP_ANON | MAP_SHARED` region created before any guest fork. The region
should include a version/magic header and a fixed slot table. Prefer the slot
table as the authoritative occupancy structure.

Suggested logical fields:

```text
PermitRegion {
  magic/version
  next_generation: AtomicU32
  slots[MAX_SLOTS]: AtomicU64 packed as:
    state: free | acquiring | registered
    owner_pid: u32
    generation: u30-or-similar
}
```

The exact bit packing can vary, but a single packed atomic word avoids
multi-field torn state. If separate atomics are used, the writeup should define
which field is the publication point and how the reaper distinguishes partial
claims from free slots.

### Acquire

Acquire should not increment an ownerless counter. It should:

1. compute the effective budget from the existing admission class;
2. CAS a free slot to `acquiring(pid, generation)`;
3. count occupied slots (`acquiring` or `registered`) and compare to budget;
4. if over budget, CAS the exact `(slot, generation)` back to free and back off;
5. return `GlobalVcpuPermit { slot, generation, owner_pid }`.

This allows a process that dies between acquire and `vcpu_create` to be reaped:
the slot is visible and owner-stamped before the VM/vCPU work begins.

### Register

On successful `vcpu_create`, transition the slot from `acquiring` to
`registered` for the same `(pid, generation)`, then insert
`vcpu_id -> PermitToken` in the process-local state.

If registration fails or sees a stale token, release the exact token and return
an HVF error. Do not collapse this to PID-only release.

### Normal release

`vcpu_destroyed(vcpu_id)` should:

1. remove `vcpu_id` from the local `HashMap<u64, PermitToken>`;
2. if present, CAS the exact slot generation back to free;
3. notify the vCPU gate.

If no token is present, it should only update `VCPU_LIVE` and notify. This keeps
unpermitted sibling vCPU teardown from freeing a global process permit.

### Fork child reset

After fork, the child inherited the parent's local permit map. It must clear that
local map without releasing the parent's slots, then acquire its own permit for
the `ForkRebuild` admission path. This is the atomic equivalent of the current
`reset_global_vcpu_permits_after_fork_child`, but without closing inherited
flock fds.

### Cooperative process exit

On HVF `process_exit_cleanup`, if atomic permits are enabled, release current
PID-owned permit tokens before `_exit`. This should be idempotent with normal
`vcpu_destroyed` and supervisor reclaim by using slot generation checks.

This is not a substitute for death reclaim. It is the fast path for normal
fork-child exit and signal-death paths that currently skip Rust drops.

### Supervisor reclaim

The root supervisor should own one `Kqueue` and watch all observed owner PIDs
from the slot table:

- use the existing `Kevent::proc_exit(pid)` helper, which is already one-shot
  `EVFILT_PROC | NOTE_EXIT | NOTE_EXITSTATUS` (`kqueue.rs:195-214`);
- when a new `(pid, generation)` appears, register a watch promptly;
- after successful registration, immediately perform a non-consuming readiness
  check like the existing `waitid(WNOWAIT | WNOHANG)` pattern so a process that
  exited before registration is not stranded;
- on `EV_ERROR`/`ESRCH`, reclaim matching generation-stamped slots immediately;
- on `NOTE_EXIT`, reclaim slots matching the watched `(pid, generation)` set;
- keep a periodic scan as a backstop, but do not rely on `kill(pid, 0)` as the
  primary death detector.

The generation guard matters for stale events and PID reuse. A late event for an
old owner must not free a new slot held by a reused PID.

## Tests the amended plan should require

Add unit tests for the state machine before any gate run:

- acquire cannot leave an unowned count: force a slot in `acquiring(pid, gen)`
  and prove the reaper can free it;
- `vcpu_destroyed` for an unregistered vCPU does not release a registered
  process permit;
- token release is generation-checked: stale token or stale event cannot free a
  newer owner of the same slot;
- fork child reset clears local tracking but does not change shared slot
  occupancy;
- `process_exit_cleanup` frees current PID-owned atomic slots and is idempotent;
- exec rebuild does not leak and does not double-release, using the current
  `vcpu_destroyed` path as the expected route;
- kqueue register-after-exit path reclaims without consuming child status,
  following the existing `waitid(WNOWAIT)` pattern.

Then run the same integration gates from the original plan, but keep phases
separate:

1. atomic permit with tokenized owner slots, cooperative cleanup, and mandatory
   proc-event supervisor;
2. `scripts/conformance/vcpu-admission-gate.sh` with `CARRICK_HVF_ATOMIC_PERMIT=1`;
3. `ltp-msgstress01` and `ltp-futex_cmp_requeue01` at `--workers 8`, repeated;
4. only after that, a separate cap-raise experiment.

## Suggested plan edits

Replace Task 1 with "tokenized slot table as source of truth." Do not apply the
3b patch mechanically; port only the useful parts (MAP_SHARED setup, injectable
tests, cap math preservation) into the tokenized design.

Merge Tasks 2 and 4. The first reclaim implementation should include
`EVFILT_PROC` plus the periodic backstop. Calling prompt reclaim conditional
creates a false intermediate milestone.

Insert a new Task 3 before exec: "cooperative `_exit` cleanup via
`process_exit_cleanup`." That addresses the known normal fork-child path and
reduces dependence on polling latency.

Downgrade the current exec task to a proof task: "verify exec uses
`vcpu_destroyed` and does not leak after tokenization." Add code only if that
proof fails.

Move the cap-raise experiment to a separate follow-up plan or a final
measurement section explicitly marked "temporary local experiment; do not commit
the cap change with the atomic permit."

## Bottom line

The plan's high-level thesis is good: a shared-memory permit can be faster than
the flock gate only if it recreates flock's death-reclaim property. The current
plan does not yet do that because it still allows an ownerless count, relies on
PID polling as a primary detector, and loses the `vcpu_id` guard that protects
normal vCPU teardown.

Make the slot token the durable fact, make `EVFILT_PROC` mandatory, release
cooperatively before fork-child `_exit`, and keep cap changes separate. With
those amendments, Option 3 becomes a reasonable spike instead of a likely replay
of the 3b timeout.
