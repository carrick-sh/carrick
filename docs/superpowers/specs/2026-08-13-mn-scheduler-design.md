# Carrick's M:N scheduler — executors, not welded threads

**Status:** design, decided 2026-08-13. Supersedes the implicit
"one host thread per guest thread" model for HVPatch.

## The decision

Carrick is a kernel. A kernel multiplexes its own threads onto CPUs. The
current HVPatch model welds one host thread to one Linux thread for that
thread's whole life and then rations execution with a separate ten-slot vCPU
pool — which is not scheduling, it is delegating scheduling to Darwin and then
arbitrating the result. `hybrid.md` already forbids baking this in: *"the
interface must not bake in one permanent host thread per Linux thread."*

We are on the M:N path. This document says what that requires.

## The constraint that dictates the shape

**An HVF vCPU is bound to the host thread that created it.** carrick's own
code says so (`carrick-vmm-hvf/src/trap.rs:5201`, "only the per-thread vCPU is
recycled"; the fork path rebuilds a vCPU on the same thread,
`trap.rs:2593`). There is also a system-wide ceiling near 127
(`trap.rs:1221`).

So a guest thread cannot carry a vCPU with it between host threads. The vCPU
must stay put. Therefore:

> **Executors are persistent `(host thread, HVF vCPU)` pairs. Guest threads are
> data that migrate between executors.**

That is the only M:N shape HVF permits, and it is exactly what a kernel does:
a run queue of runnable threads, a small set of CPUs, and context switching by
register state.

## The model

```text
Kernel
 ├── RunQueue           runnable ThreadRef, ordered
 ├── Executor[0..N]     persistent host thread + its own HVF vCPU
 └── Thread             register file, run state, blocked-on reason
```

- **N ≈ usable cores**, not guest-thread count. Today's 69 host threads
  collapse to N executors.
- An executor loop is: take a runnable `Thread`, load its register file into
  the executor's own vCPU, set `TTBR0`/ASID for the thread's `Mm`, run until
  exit, save the register file back, decide the thread's next state, repeat.
- **Blocking releases the executor immediately and holds nothing.** A blocked
  guest thread is a `Thread` object on a wait queue with no executor, no vCPU,
  and no host thread. This is what removes the slot-starvation deadlock class
  by construction rather than by rationing.
- **No vCPU is ever destroyed to free capacity.** The executor keeps its vCPU
  for the process lifetime. The measured +9% churn cost of extra reclaims
  (`2026-08-13-hvpatch-reclaim-churn.md`) disappears along with the whole
  destroy/recreate path.

K1 already built the object model this needs: `Thread` carries "LinuxTid,
register/signal mask/TLS state, run state, and a lease on a vCPU worker while
runnable", and `Mm` carries the ASID and stage-1 root. The scheduler is the
piece K1 deliberately deferred.

## What this is NOT allowed to change

Every one of these is a hard invariant, and the reason this is a scheduler
change and not a "fast path":

- **Blocking and wake semantics stay exact.** A futex wake, a signal, an fd
  becoming ready, and a child exiting must make the thread runnable with
  Linux's ordering and no lost wakeups. Moving a thread off an executor must
  not coalesce, drop, or reorder a wake.
- **Signal interruption stays exact.** `EINTR`, restartable syscalls, and
  `SA_RESTART` behaviour are unchanged by where a thread runs.
- **Memory ordering stays exact.** A guest thread that migrates between
  executors must observe the same memory model. Register state moves; guest
  memory does not, and the stage-2 mapping is shared, so this is a matter of
  correct barriers at save/restore.
- **Per-thread identity stays exact.** `gettid`, `/proc/self/task`, thread
  signal masks and altstacks are properties of the `Thread`, not of whichever
  executor happens to run it.
- **TLS/`TPIDR_EL0` and FP/SIMD state migrate with the thread.** The 2026
  SIMD/FP restore bug (`set_simd_fp_reg` zeroing V-registers) is the standing
  reminder that a partial register file is a silent corruptor.

## Order of work

1. **Reclaim counter first.** Before removing the destroy/recreate path,
   count today's reclaims so the win is measured, not assumed
   (the caveat recorded in the churn document).
2. **Make the register file the authority.** Guest state must live in the
   `Thread` object, complete — GPRs, PC, PSTATE, `TPIDR_EL0`, FP/SIMD, and the
   sysregs the guest can observe. Today it is implicit in the engine bound to a
   host thread. This is the enabling refactor and it is where the SIMD/FP
   lesson applies.
3. **Introduce the executor pool alongside the current model**, with a
   red-first test that a thread which blocks holds no executor.
4. **Move the run loop** from per-guest-thread `run_vcpu_until_exit` to
   executor-owned scheduling.
5. **Delete** the ten-slot `vcpu_sched` pool, the reclaim/destroy path,
   `should_reclaim_vcpu_for_timed_wait`, and the per-guest-thread spawn. No
   second path survives.

## What this does and does not buy

**Does:** removes an entire deadlock class by construction; removes
destroy/recreate churn (bounded at ~9% by measurement); collapses 69 host
threads to N executors, with their stacks and kqueues; gives carrick a real
run queue, which is the precondition for honest guest CPU accounting and for
`sched_yield`/priority semantics later.

**Does not:** reach the 2.3 CPU-s bar. Measurement is explicit that the bar is
~1.01x the workload's intrinsic cost and that ~1.97 CPU-s must go; reclaim
churn is a small share of that. This change is justified on correctness,
liveness and architecture — it is what a kernel must own — and the CPU bar
must still be met in the syscall path, exec, and fault handling.

Claiming this as the performance fix would repeat the error this session has
already made twice and caught by measuring.
