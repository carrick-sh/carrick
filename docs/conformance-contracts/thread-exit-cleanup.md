# Thread exit cleanup (#1724): terminal copy faults

Contract: `kernel.el1.thread-lifecycle`.

Linux's `set_tid_address(2)` contract describes clearing the registered word
and waking one futex waiter at thread exit. The clear is best effort: a
terminal write fault cannot return an errno from raw `exit` or cancel thread
retirement. The wake remains owed even when the write faults.

Authority: https://man7.org/linux/man-pages/man2/set_tid_address.2.html

This first slice distinguishes terminal `CopyOutcome::Fault` from
`CopyOutcome::NotYet` in the existing shared nonfinal exit path. A terminal
fault completes the store obligation, then the existing wake and exact-address
progress publication run before scheduler retirement. The ARM/common dispatch
adapter rejects a range outside `carrick_guest_arch::lower_half_range` as
terminal Fault, since no backing producer can make that range a user address.
The shared personality exit policy also serves CPL0. No ABI layout changes.

The production ARM witness runs with both adopted and native-owned records (the latter has no host adopter and
sets the production exit adapter's `unadopted` flag). The
shared-policy witness starts a real futex joiner, refuses the clear-store,
requires unchanged user bytes, one additional scheduler wake, one remaining
live thread, and selection of the joiner with return value zero. Both witnesses
were red on admitted main. The structural bound is one four-byte store attempt
and one wake, with no copy retry on a terminal fault. The existing NotYet
handback witness remains in the suite as a preservation control.

## Still required for #1724

This slice does **not** implement parking. NotYet still takes main's handback,
and a readable registered robust list still declines before any in-ring mutation.
Consequently this slice does not satisfy the issue's full acceptance criteria.

The next slice consumes a terminal fault reading the robust-list head and
continues to clear-TID and retirement. Both adopted and native-owned production
ARM records must retire on a noncanonical head. A shared ARM/x86 policy witness
also refuses scheduler release after the clear-TID wake, then re-enters exit:
the terminal head fault must not prevent retirement or replay that wake. The
head read is bounded to the 24-byte Linux ABI header; no robust futex update is
attempted when that header faults. ARM/common copy-in now classifies non-user
ranges as terminal faults, matching copy-out. Canonical unavailable memory
continues to need the retained owner described below.

A parked exit needs an exact-thread owned terminal continuation, not generic
`wait_guest_copy`/syscall redispatch. That owner must retain the original exit
status and cleanup phase through changes to signal state, the lifecycle gate,
and the last-thread decision. A refused fault supply must become a consumed
fault of the exact cleanup attempt and advance its cursor; it must neither
install `-14` in user registers nor endlessly reissue the same fault.

Robust owner-death handling additionally needs an atomic guest-word operation
under the existing exact-MM transfer fence. Main has no robust walker and no
user-word compare-exchange operation. `prepare_user_write` followed by a raw
CAS is insufficient: preparation has already dropped that fence. The existing
`MmPortal::write_user_target`/`UserWriteVenue::copy` fence is the appropriate
venue for that operation, with shared policy and true ISA access mechanics.
A cursor must retain the next list link before an entry's owner-death update,
handle pending entries once, bound malformed cycles, skip terminal faults and
never replay a completed wake when a later copy parks.

VM-free evidence for the terminal-fault slice does not establish actual
backing supply, signed execution, robust-list semantics or runtime ratios.
HVF/Docker acceptance and owned-parking/robust witnesses remain outstanding.

## Finishing-round production witnesses

The unavailable-head and empty-head raw-exit bindings use the same real
`arm_call` dispatch as the terminal-fault controls, with both adopted and
native-owned records and a second live thread. The empty head is registered
user storage whose first link points back to itself; the unavailable head is
registered storage with a guarded-copy refusal injected at the production
copy boundary. The empty-head rows require in-zone retirement and a consumed live membership.
Unavailable-copy rows require terminal custody at admission and no host-exit
request; they do not require retirement before a backing reply is consumed.
These are acceptance assertions, not preservation assertions for the existing
handback.

The unavailable-clear-TID raw-exit bindings similarly require terminal custody
at admission. They do not yet drive backing supply or its refusal. The exit-group worker binding starts the
leader's actual `exit_group(7)` while the worker lives, then drive that worker
through production service admission and terminal retirement. Before the close
owner completes, the worker must have settled its resident
clear-TID obligation, including the actual user word rather than only the
slot's bookkeeping. Existing no-clear and retained-IPC rows remain controls.

These witnesses alone do not implement the exact-thread terminal owner,
exercise a robust entry's atomic owner-death update, prove exactly-once wakeups
for parked copies, or confer signed acceptance. They must become green through
the retained owner rather than by accepting HostCustody, returning errno 14,
or treating NotYet as Fault.

The production clear-TID terminal-fault control must register an address the
slot actually retains. `u64::MAX` is normalized to `ClearChildTidState::None`
and therefore never reaches copyout. The control now uses `1 << 47`, below the
slot codec's `1 << 48` bound but outside the guest lower-half copy domain, and
asserts that the slot retained the exact address before dispatch. The shared
policy's injected-Fault/joiner witness remains the separate exactly-once wake
check.
