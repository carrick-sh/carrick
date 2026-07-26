# Syscall amplification on the native lane: 17× host calls, 71% of them ours

**Status:** investigation complete for this round. **The obvious fix was tried and
REVERTED** — it was correct, took effect, and bought nothing. Priority list below
is corrected against the critical-path measurement.
**Lane:** Darwin/aarch64 native (DSR) — the shipped default backend.

---

## 1. What is measured and true

All on this box (macOS 27.0, build 26A5388g, `xnu-13432.0.94.501.4`, M4 10-core),
workload `go-build` under the conformance harness, box quiet.

### 1.1 Amplification, split by what each host syscall is FOR

`scripts/dtrace/syscall-amplification.d` attributes every host macOS syscall to
the work in flight on that thread — `linux:<name>` while servicing a guest
syscall, `trap:<kind>` while servicing a non-syscall exit, `carrick-only` when
there is no guest work at all:

| | |
|---|---|
| guest Linux syscalls | 22,903 |
| host macOS syscalls | 394,115 |
| **amplification** | **17.2×** |
| **`carrick-only`** (no guest work in flight) | **278,329 — 71%** |

A single host/guest ratio would have hidden the actionable part: **most of our
host syscalls are not emulating anything.**

Top host syscalls: `psynch_cvwait` 63,956 · `psynch_cvsignal` 63,266 ·
`mprotect` 51,152 · `unlinkat` 43,511 · `close` 34,777.

### 1.2 The critical path — what actually gates the guest

Marking threads that service guest syscalls, then attributing THEIR off-CPU time
to the blocking stack (40 s window):

| | |
|---|---|
| guest-thread blocked | 41.5 thread-seconds |
| guest-thread on-CPU | ~3.9 s (3,906 samples @ 997 Hz) |

Top blocking stacks for guest-working threads:

```
kevent          <- ThreadWaiter::wait_proc_exit <- wait_native_proc_exit
__psynch_cvwait <- FutexTable::wait_prepared_with_token <- wait_native_futex
```

**The guest is blocked waiting for child processes to exit, and on guest
futexes.** That is `go build` spawning `compile`/`link` and Go's scheduler doing
what they legitimately do — so the cost that matters is **child process
lifecycle**, not translation and not the translator's locks.

This is consistent with the earlier fork decomposition: the parent's wakeup is
posted only after `task_terminate_internal` → `vm_map_terminate` completes, so a
child's full address-space teardown sits on the parent's critical path (measured
328 µs of a 1,374 µs fork/exec/reap cycle).

---

## 2. What was tried, and why it was reverted

### 2.1 The hypothesis

Contended `parking_lot` stacks appeared under the condvar storm:

```
psynch_cvwait   <- RawRwLock::lock_shared_slow <- translate_read_mostly <- prepare_entry
psynch_cvsignal <- RawRwLock::unlock_exclusive_slow <- PageGenerationTable::observe
```

`PageGenerationTable::observe` (`carrick-dsr/src/cache.rs`) takes the map's
**write** lock on every call — via `.entry().or_insert_with()`, which needs `&mut`
even when the page is already present — and it runs on **every gateway entry**.
That looked like a textbook reader/writer storm.

### 2.2 The fix, and the result

Changed `observe()` to look up under a read lock, falling back to the write lock
only on a genuine first-touch miss (double-checked).

| | before | after |
|---|---|---|
| `go-build` wall | 31,767 ms | 31,760 / 31,236 / 31,407 ms |
| amplification | 17.2× | 17.3× |
| `carrick-only` bucket | 278,329 (71%) | 286,983 (71%) |
| `psynch_cvwait` | 63,956 | 67,927 |

**Nothing moved.** Not wall clock, not the condvar count, not the bucket share.
So `observe()` was not the dominant writer, and the change was reverted rather
than kept as an unvalidated "improvement".

(It also, on the first attempt, deadlocked: `match self.pages.read().get(&page)`
keeps the read guard alive for the whole match expression, so the miss arm took
the write lock while still holding the read guard. `RwLock` is not reentrant —
the original code carried a comment warning about exactly this. A 32 s suite
became a hang.)

### 2.3 The reasoning error, recorded so it is not repeated

A spike measured **41.4 thread-seconds blocked** in `psynch_cvwait` against
**6.9 thread-seconds on-CPU** and was read as "confirms the priority".

It does not. That figure is **aggregated across all threads**: it proves the lock
is contended, not that it gates completion. Threads blocked off the critical path
cost zero wall clock. This is the same class of error as "syscall count is not
time", one level down: **blocked time is not critical-path time.**

The spike was also designed so it could only confirm — there was no outcome that
would have refuted the priority. The critical-path measurement in §1.2 is the one
that could, and did: the same ~41 s of blocking is overwhelmingly the guest
waiting on child exits and futexes, not on our lock.

---

## 3. Corrected priority

1. **Child process lifecycle.** The guest is *provably* blocked on it, and
   `vm_map_terminate` teardown is on the parent's critical path by construction.
   The aperture fix (`58a84062`) already moved `go-build` 44,768 → 31,767 ms
   through this path; there is more here.
2. **`mprotect` — 51,152 calls, 2.2 per guest syscall.** Completely unexplained.
   Suspect W^X or guarded-page toggling on a hot path. Cheapest unexamined lead.
3. **The translator lock.** Real contention (~157k condvar calls), demonstrably
   NOT gating completion. Mature DBTs take **no lock on the hot path** — QEMU's
   multi-threaded TCG uses a per-vCPU `tb_jmp_cache` updated with plain atomics
   over a lockless QHT, with a lockless radix tree for the page table and locks
   only for code generation and jump patching; FEX-Emu adds indirect-branch
   translation caching specifically to avoid lock accesses. That is the right
   long-term architecture, but it must be justified by a measurement showing it
   gates something. (QEMU is GPL: its *design documentation* is fair reference,
   its source is not — see AGENTS.md.)

---

## 4. Tooling this produced

- `scripts/dtrace/syscall-amplification.d` — rewritten from a bare host/guest
  ratio into the three-bucket attribution above, with per-instance amplification
  distributions and pid/tid attribution. This is the candidate CI ratchet metric:
  `carrick-only` share and host-per-guest ratio are exactly the numbers a
  regression would move.
- `scripts/dtrace/offcpu-attribution.d`, `scripts/dtrace/fork-cost-attribution.d`
  — off-CPU and fork-window attribution used for §1.2.

Traps worth knowing, all hit during this work: DTrace `profile-N` with a
thread-local predicate (`/self->x/`) silently yields ZERO samples — use a
pid-keyed array; `fbt` on the core kernel is blocked by SIP (kexts only);
`pr_psargs` never sees carrick's proctitle rewrite, so `execname` is the correct
filter; and a dtrace without a bounded `tick` never flushes its aggregations AND
leaks a root process that cannot be reaped without a password.
