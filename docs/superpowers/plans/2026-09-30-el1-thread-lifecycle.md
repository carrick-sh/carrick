# EL1 born-in-zone thread lifecycle (design, 2026-09-30)

Status: design accepted as the direction by the director (L0-L2 dispatched);
not implemented. Companion to the controller
[`2026-09-26-el1-completion.md`](2026-09-26-el1-completion.md).

## Why

`el1_fork_cow_resolves_in_guest` makes about 6k host exits for 20 rounds
against a 144 ceiling. The fixture is static musl with 4 worker threads per
process. By count, each thread spawn and exit forwards about 9 calls: `clone`,
4x `rt_sigprocmask`, 3x `sigaltstack` and `exit`. S3 does not move those.

## Invariant

The kernel graph stays the only authority for thread identity
(`TaskKey`/generation, visible tid), signals, rlimits, ptrace and wait. EL1
consumes identities the kernel has already issued. Every observer of thread
membership settles the pending births and exits first, so no observer can
tell whether a thread was born in the zone or on the host.

## Design

### 1. Identity

Identities come from a kernel `ThreadIdentityPool`: a reclaimable lease per
task.

- **Entries.** Each entry is a reserved tid and visible tid, a `ThreadKey`, an
  initial generation, and a pre-prepared runtime backend. Entries are built
  from the `reserve_thread_clone` pieces
  (`kernel/operations/thread.rs:676`). Creds, mask, affinity and the
  `ClonePlan` are bound at publication, not at reservation.
- **Lifecycle page.** A per-process `ThreadLifecyclePage` is EL1-RW and
  unreachable from EL0. It holds the entry states
  (`Reserved→Claimed→Born→Published→ExitedInZone→Reaped`, or `Revoked`), a
  gate word (Open, ForkClosing or Closed), the live-thread count and the
  pending-signal summary.
- **Clone in EL1.**
  1. Claim an entry with a CAS, using a Dekker pair against the gate.
  2. Write the tid words, using the `CloneTidOutputTransaction` rules.
  3. `alloc_record` the child.
  4. Write the Born record and enqueue the child.
- **Visibility.** A born entry is observable from clone return. Every
  membership reader calls `ThreadLedger::settle(task)`. That reuses the same
  `publish_reserved` body as the host lane, so there is one publication path.
  `Registry.state` becomes private behind a `SettledRegistryView`. A lookup
  by an unknown tid goes through a `reserved_tid → TaskKey` map.
- **Settle cost.** Settle runs on every host entry, moved before context
  resolution (`vcpu_loop/mod.rs` ~1460). With nothing pending it is one
  atomic compare.
- **`RLIMIT_NPROC`.** Enforcement becomes exact for threads, which it is not
  today (`operations.rs:1179-1184`). Uid credits are carried per entry and
  revoked by CAS under pressure.
- **Clone flags.** EL1 serves only the libc/Go thread flag sets. Anything else
  is forwarded and consumes a pool entry through the same ledger.
- **Gate.** The gate closes EL1 lifecycle serving for:
  - a tracer;
  - seccomp;
  - `pending_host_work`;
  - `CARRICK_EL1_THREADS=0`.

### 2. Execution capacity

- A born thread is a zone record with no home. It runs on parent park, on an
  idle-slot steal, or when an SGI wakes a slot in WFI.
- The host adopts it on its first forwarded syscall, using the existing
  service/exit adoption, after settle.
- `Exhausted` returns the entry to the pool and forwards the clone.

### 3. Exit

EL1 serves `exit` for a non-leader thread when:
- it is untraced;
- no host work is pending;
- the live count goes from n>1 to n-1. That counter is the storage for
  `ThreadRegistry::live_count`; there is no second copy.

In-guest exit steps:
1. Walk the robust list. The walker is shared with the host lane and lives in
   sched-core; none exists today.
2. Clear the `CLEARTID` word and wake its futex (`Sched::wake_word`).
3. `free_record` and mark the entry `ExitedInZone`.

Freeing the tid, folding CPU time and decrementing the /proc and
`RLIMIT_NPROC` counts are deferred to the next settle.

The last thread, the leader, a traced thread, a thread with pending signals,
and `exit_group` stay synchronous on the host.

### 4. Per-thread setup

A per-thread `ThreadControlSlot` in carrick-el1-abi is the only storage.

| Call | EL1 serves it? | Detail |
|---|---|---|
| `rt_sigprocmask` | Yes | `blocked` becomes an atomic. Uses a Dekker pair with senders. If the change unblocks something pending, it serves and leaves served-with-work. |
| `sigaltstack` | Yes | Seqlocked slot field. |
| `set_robust_list` | Yes | Head stored in the slot. |
| `gettid` | Yes | A projection of the immutable visible tid. |
| `sched_getaffinity` | No | Stays on the host. |

`sigaction`, delivery, `rt_sigreturn` and temporary masks stay on the host,
on the same atomic.

### 5. Fork and exec

- **Fork.** Set the gate to ForkClosing. Wait for claimed entries to settle,
  which is bounded because the window cannot block. Then settle, read the
  forking thread's slot, seed the child's pool inside the fork commit, and
  reopen the gate. EL1 clones that meet a closed gate park on the gate word,
  as `CloneEnrollment::Deferred` does.
- **Exec.** Close the gate, settle, revoke the pool and cancel sibling
  records.

## Budget

With this design and S3, thread lifecycle costs about 0 exits per round.
About 20 host-served non-thread calls per round remain, roughly 440-500
exits in total. Reaching 144 (about 4 per round) also needs:

- pipe2/close in the EL1 fd table;
- poll/ppoll on EL1 IPC objects;
- S3 batched retirement;
- no idle or kick exits on wait4 and fork-child placement.

The `hvf_syscall_exits <= 64` cap in `el1-fork-cow.toml` cannot be met under
these authority rules. The director must re-register it.

## Open questions

These need a director ruling or the Docker oracle:

- `gettid` is already served at EL1 by the legacy `CONTEXTIDR_EL1` shim
  (`carrick-mem/src/memory.rs:466`). Does it collide with the "no EL1
  `gettid`" second-path rule? Needs a census count and a ruling.
- The host lane returns EFAULT and rolls back when the `CLONE_PARENT_SETTID`
  copyout faults (`binding.rs:1999-2008`); Linux likely does not. Check with
  the Docker oracle before changing either lane.
- Host entry resolves `KernelContext` before `settle_el1_boundary`. Settle
  must move before context resolution.

## Stages

Each stage has an exact `=0` hatch where it adds behaviour.

| Stage | Scope | Waits for | Hatch |
|---|---|---|---|
| L0 | Red witnesses and contracts: spawn slope; tgkill right after clone; mask Dekker storm; CLEARTID tid reuse; `RLIMIT_NPROC` vs oracle; fork during a clone storm; exec/exit_group during a clone storm; `PTRACE_O_TRACECLONE`/seccomp gate; `Exhausted`; executor-pool exhaustion. All two-live-process. | — | — |
| L1 | Kernel ledger and pool; the host-lane clone rebased on pool consumption; `RLIMIT_NPROC` enforced for threads. | — | `CARRICK_THREAD_POOL=0` |
| L2 | ABI: lifecycle page, control slot, hash bump. | — | — |
| L5 | Signal storage moved to the slot. | L1, L2 | — |
| L3 | EL1 personality `lifecycle.rs`. | S3-T1, L2 | `CARRICK_EL1_THREADS=0`, `CARRICK_EL1_SIGMASK=0` |
| L4 | Runtime: settle-before-context, adoption, gates. | L1, L3 | — |
| L6 | Director's signed ladder. | L4 | — |

## Director rulings after L1 (2026-09-30)

1. **Pre-issued identities shift guest-visible numbering.** A task primed
   after its first thread clone holds up to 4 tids and namespace ids
   ahead of use, so a later fork elsewhere is numbered after them.
   Accepted: Linux assigns pids to concurrent processes in no guaranteed
   order. Landing is conditional on `just conformance-probes` and
   `conformance smoke` showing no pid-dependent diffs on the landing
   artifact.
2. **Bind at claim, not publication.** Creds, blocked mask and affinity
   bind at the clone instant (claim). This supersedes "bound at
   publication" in section 1: Linux copies them when clone runs.
3. **No `reserved_tid → TaskKey` map.** Settle is global and costs one
   atomic load when nothing is pending.
4. **The ForkClosing gate is load-bearing.** Settle publishes a birth even
   while a fork transaction holds the task. L4 must close the gate before
   any fork or exec transaction takes the task.
5. **Unsettled births hold `Arc<Kernel>`.** exit_group, exec and carrier
   teardown must settle or revoke every pending birth. L4 adds a test
   that the kernel drops.
6. **Pool entries carry no runtime backend.** They hold tid, namespace id
   and uid credit only. The runtime backend is prepared at adoption.
