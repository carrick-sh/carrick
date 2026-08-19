# `FUTEX_CMP_REQUEUE` across processes: root cause, and why the obvious fix is blocked

Target: `arm64:musl:futexforkrequeue`, the one DETERMINISTIC probe failure in the
gate (the other two seen on 2026-08-19, `futexforkwakegroups` and `ptyfionread`,
did not reproduce on a second sample and are load-coupled). Same cluster as
`ltp-futex_cmp_requeue01` (122 rows).

**Status: root-caused, NOT fixed. The attempted fix was measured WORSE and has
been reverted.** This report exists so the next attempt starts from the
measurements rather than repeating them.

## The divergence

`futexrequeue` (threads, PRIVATE futex) passes. `futexforkrequeue` (1000 forked
children, `MAP_SHARED` futex) fails on three assertions, all of them COUNTS —
every child is woken correctly and none time out, so nothing functional is
visibly broken:

| metric | carrick | Linux |
|---|---|---|
| `FUTEX_CMP_REQUEUE` return | 300 | 800 (300 woken + 500 requeued) |
| `FUTEX_WAKE(word1)` (destination) | 0 | 500 |
| `FUTEX_WAKE(word0)` (remainder) | 8 | 200 |

Carrick woke 300 and requeued NOTHING.

## Root cause

`FutexTable::requeue` relinks waiters with `parking_lot_core::unpark_requeue`.
A gated instrument in the requeue path measured, at the moment of the call:

    enrolled_before=1000 after_wake=771 nr_wake=300 nr_requeue=500
    woken=300 requeued=20 break=requeued_threads==0 enrolled_now=771
    spurious_reparks=154 spurious_signal_token=154 notify_broadcasts=179

Read it in order:

1. All 1000 waiters ARE enrolled, so this is not an enrollment race.
2. The requeue moves ~20 and then finds the source queue "empty" while ~771
   waiters are still enrolled on it.
3. `spurious_signal_token == spurious_reparks`, exactly. **Every** spurious
   re-park is a signal-pending broadcast that found nothing to deliver.

The mechanism: `notify_signal_pending()` unparks EVERY waiter in EVERY bucket
carrier-wide (179 times during this probe). Each woken waiter re-checks
`interrupted()`, finds nothing, and re-parks — computing its key from **its own
address**. A waiter that `unpark_requeue` had silently relinked to the
destination therefore walks straight back to the source queue. The requeue is
undone within microseconds, so the destination is empty when the parent wakes it.

`have_more_threads` is also unreliable here: it reported "no more threads" with
~900 waiters still enrolled, which is why the loop stopped at 20 rather than 500.

Two defects, one mechanism:

- **Correctness** — a requeue is not durable.
- **Performance** — 179 broadcasts x ~1000 waiters ~= 179k unparks in one probe.
  A signal is delivered to a TASK; waking every waiter in the carrier to ask
  "was it you?" is the process-global surrogate `docs/identity-and-scope-domains.md`
  warns about, and it is a thundering herd on every signal.

## What was tried, and what it measured

A two-pass requeue that INFORMS waiters instead of relinking behind their backs:
`unpark_filter` walks the queue in FIFO order, wakes the first `nr_wake`, and
publishes a destination ("redirect") for the next `nr_requeue` while leaving them
parked; `unpark_requeue` then relinks the marked ones without waking them; a
waiter consults its redirect on any unpark and re-parks on the destination.

That fixed the return value **reliably** (800, every run). It did not stabilize
the rest:

| variant | cmp_requeue | wake_dest | wake_orig | timed out |
|---|---|---|---|---|
| baseline (HEAD) | 300 | 0 | 8 | 0 |
| two-pass, hand-off by unpark | 800 | 54 | 107 | 446 |
| two-pass + relink | 800 | 500 | 84 | 0 |
| ... + enqueue latch | 800 | 500 | 22 | 178 |
| ... + requeued flag only | 800 | 13 / 7 / 189 | 17 / 0 / 200 | 487 / 493 / 311 |

Reverted. A change that trades a wrong COUNT for hundreds of 60-second timeouts
is worse than the bug it fixes.

## Why it is blocked, precisely

Two independent defects sit underneath, and the requeue cannot be made correct
until they are:

1. **A spurious unpark opens a lost-wake window.** Between being unparked and
   re-parking, a waiter is queued NOWHERE. A `FUTEX_WAKE` in that window misses
   it and is simply lost — the waiter then sleeps to its timeout. Linux has no
   such window; its waiter never leaves the queue until released.

2. **Carrick re-runs the futex-word comparison on every re-park.** Linux compares
   `*uaddr` to `val` ONCE, at enqueue, and a later store does not release a
   queued waiter. Carrick's waiter re-checks and can release ITSELF. That is a
   real divergence — and latching it (the faithful behaviour) is what turned 178
   waiters into timeouts, because the self-release was the only thing rescuing
   the wakes lost to defect 1.

So the self-release is **masking** the lost-wake defect. Fixing either one alone
makes the probe worse; they have to be fixed together, foundation first.

## The foundation the next attempt needs

Make a wake durable across the in-flight window, then the requeue and the enqueue
latch both become straightforward:

- Count LOGICAL enrollment per futex (from the first successful enqueue to the
  wait's return), not just current parking_lot residency — `bucket.waiters` is
  decremented as soon as a waiter is unparked, so an in-flight waiter is
  invisible to `wake` today.
- `wake(addr, n)` unparks what it finds and, when it finds fewer than `n` while
  logical enrollment says more exist, deposits that many wake CREDITS on the
  futex. A waiter consumes a credit instead of re-parking and returns `Woken`.
- With wakes durable, apply the enqueue latch (defect 2) and the requeue redirect
  together.

Worth doing first regardless, because it independently removes the herd:
**make signal notification targeted.** `notify_signal_pending_for(tid)` already
exists; the broadcast form has ~30 callers. The one that fires here is
`HvpatchTaskWaker::wake_task`, which is invoked ON a specific task. Converting
callers that know their target both removes ~179k pointless unparks and shrinks
the window that defect 1 exploits. It is not a correctness fix on its own — a
missed wake is a hang, so each caller has to be shown to know its target.

## Reducers

`futexforkrequeue counts` (the probe itself, run with the `counts` argument)
prints every raw number above and is the reducer; no new one was needed. The
instrument that settled it was a temporary `CARRICK_FUTEX_REQUEUE_DEBUG` block in
`FutexTable::requeue` reporting enrolled/woken/requeued/break-reason plus the
spurious-re-park and broadcast counters — reconstruct it from the numbers above
rather than guessing at a different one.
