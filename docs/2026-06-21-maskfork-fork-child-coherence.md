# maskfork fork-child signal wait coherence

**Status:** resolved on 2026-06-21.

`arm64:musl:maskfork` originally looked like a fork-child memory coherence bug:
the child appeared not to inherit the blocked SIGUSR1 mask and appeared to retain
the parent's pending SIGUSR1. That diagnosis was stale. The child computes the
correct result; the parent was not receiving it because Carrick interrupted the
blocking pipe read on a signal that was pending but still blocked.

## Symptom

`conformance-probes/src/bin/maskfork.rs`:

1. Parent blocks SIGUSR1.
2. Parent raises SIGUSR1, leaving it pending.
3. Parent creates a pipe and forks.
4. Child checks:
   - blocked SIGUSR1 mask is inherited;
   - pending SIGUSR1 is cleared on fork.
5. Child writes one byte to the pipe.
6. Parent reads that byte and prints the booleans.

Broken Carrick output:

```text
child_inherits_blocked_mask=false
child_pending_cleared_on_fork=false
parent_pending_survives_fork=true
```

Expected Linux output:

```text
child_inherits_blocked_mask=true
child_pending_cleared_on_fork=true
parent_pending_survives_fork=true
```

## Root Cause

The threaded HVF wait loop services blocking fd reads by returning
`DispatchOutcome::WaitOnFds`, then checking whether a pending signal should
interrupt the wait before parking in `io_wait`.

The dispatcher-side predicate,
`SyscallDispatcher::has_deliverable_dispatch_pending_for_wait`, checked pending
signals against only the temporary wait mask passed by `ppoll`/`pselect`. It did
not also apply the thread's persistent blocked mask.

For `maskfork`, the parent still has SIGUSR1 pending and persistently blocked.
Linux does not let that signal interrupt `read(2)`. Carrick treated it as
deliverable, broke the blocking pipe read before waiting for the child byte, and
the probe ignored the failed read return, leaving `b[0] == 0`.

The fix is to use:

```text
effective_block_mask = persistent_thread_mask | temporary_wait_mask
```

before deciding whether dispatcher-owned pending signals should interrupt a
blocking wait.

## Evidence

The signal bookkeeping was already correct:

- child `mask_for(tid) == 0x200`, so SIGUSR1 was inherited as blocked;
- child pending set was empty after fork;
- the child wrote byte `0x03` to the pipe, meaning both child booleans were true.

A focused fd trace showed the parent side of the failure:

```text
parent read(fd=3, len=1)
host read(pipe_read_fd, len=1) -> -1 EAGAIN
no io-wait-begin
child write(pipe_write_fd, len=1) -> 1
```

So the failure was not that the child computed or wrote the wrong byte. Carrick
misclassified the parent's blocked pending SIGUSR1 as a deliverable signal and
interrupted the fd wait before it parked for pipe readability.

## Apple Shootdown API Check

macOS 27 adds `hv_vcpu_invalidate_tlb(hv_vcpu_t, hv_tlbi_op_t, uint64_t)`.
Local SDK inspection confirmed the public `hv_tlbi_op_t` values currently expose
EL1/EL0 invalidations such as `VMALLE1IS`, not a stage-2/IPAS2 invalidation.

Testing `hv_vcpu_invalidate_tlb(..., VMALLE1IS, 0)` in the fork child did not
change `maskfork`. That is consistent with the final root cause: this was not a
stale stage-2 TLB problem.

## Regression Coverage

Added unit coverage to
`crates/carrick-runtime/src/dispatch/signal.rs`:

- process-pending SIGUSR1 interrupts a wait when unblocked;
- the same signal does not interrupt when blocked by the temporary wait mask;
- the same signal also does not interrupt when blocked by the thread's persistent
  signal mask.

Runtime verification:

```text
CARRICK_TRACE_MASKFORK=1 timeout 20 ./target/release/carrick run-elf \
  conformance-probes/target/aarch64-unknown-linux-musl/release/maskfork
```

Fixed output:

```text
child_inherits_blocked_mask=true
child_pending_cleared_on_fork=true
parent_pending_survives_fork=true
```

## Follow-up: the persistent-mask union over-blocked ppoll/pselect/epoll_pwait

The first fix unioned the thread's persistent mask into the wait's interrupt
predicate unconditionally:

```text
effective_block_mask = signal.mask_for(tid) | block_mask
```

That is correct for `read`/`recv` (additive; `block_mask == 0`, so the persistent
mask gates the wait) and for `wait4`/`waitid` (whose `block_mask` is already a
persistent-mask superset). It is **wrong** for `ppoll`/`pselect6`/`epoll_pwait`:
POSIX has their sigmask *REPLACE* the thread mask for the wait, so a signal the
temp mask UNBLOCKS must be able to interrupt even if persistently blocked. The
union leaves it blocked and suppresses a legitimate `EINTR`. carrick keeps
`mask_for(tid)` persistent during these waits (it never installs the temp sigmask
into `masks`), passing the temp mask separately as `block_signals`, so the union
genuinely computed `persistent | temp`.

Differential proof (probe `ppollunblock`: block SIGUSR1 persistently, raise it
pending, then `ppoll` a never-ready fd with an EMPTY temp mask):

```text
              carrick (union)   Docker (native arm64)
ppoll_eintr   false ✗           true ✓
ppoll_timeout true  ✗           false ✓
```

### Fix

The effective wait mask is now chosen per call site instead of always unioning.
`DispatchOutcome::WaitOnFds`/`WaitOnFdsSelect`/`WaitOnPollFds` carry a
`mask_replaces: bool`, set `true` exactly when a sigmask was supplied to
`ppoll`/`pselect6`/`epoll_pwait` (so an EMPTY-but-present sigmask still replaces —
the `ppollunblock` case). The predicate:

```text
effective_block_mask = if mask_replaces { block_mask }       // POSIX replace
                       else { mask_for(tid) | block_mask }    // additive read/recv
```

Plain `poll`/`epoll_wait` (no sigmask) → `mask_replaces == false`, unchanged.
Both `maskfork` (additive) and `ppollunblock` (replace) now match Linux, and the
unit test `wait_predicate_sees_shared_process_pending` asserts all four quadrants
(additive/replace × blocked/unblocked).
