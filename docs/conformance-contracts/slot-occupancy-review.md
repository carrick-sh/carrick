# Slot occupancy review follow-up (#1426)

`kernel.el1.address-space-switch` requires a published open grant and an
observed matching live root before a switch can keep translations. An
unreadable live root now selects installation through the gate, with a
maintenance-root transition first. The existing occupancy test is red on
S1 (`Keep` instead of `Install { leave_live_root: true }`) for that case.
The successful matching-root fast path and its constant work are unchanged.

The idle-exit token and its constructor now share a private module. The
constructor's field is inaccessible to sibling scheduler modules. Its
compile-fail doctest also checks that callers cannot fabricate the token.
The token attests EL1 relinquishment, not an unconditional live-root read:
already vacant slots are not re-read and the no-maintenance-root case retains
host-owned occupancy. This documents the existing ownership boundary rather
than changing host initialization or the unpublished-entry policy (#1413).

CPL0's execution-root reader is not a terminal-custody decision. Its executor
still has no zone slot; extending idle vacancy to it remains dependent on
#925. Signed EL1 execution and paired performance evidence remain necessary
for full runtime acceptance; VM-free results cannot establish either.
