# x86 anonymous editor boundary mapping (2026-10-06)

`carrick-core::mm::anonymous` now owns the ISA-neutral anonymous edit,
retirement-custody, and reservation-commit sequence. Linux syscall decoding,
errno selection, AArch64 descriptor encoding, and AArch64 TLBI/DSB/ISB remain
in their existing adapters.

The extraction deliberately does not introduce a second interpretation path.
The AArch64 adapter maps the new neutral refusals to the same `AnonymousLeave`
and therefore the same pre-existing host/Linux result:

| Before extraction | Neutral boundary | After extraction |
|---|---|---|
| host-owned leaf | `Foreign(HostOwnedLeaf)` | `BackingHostOwnedLeaf`; unchanged syscall forwarded |
| block terminal | `Foreign(Block)` | `BackingBlock`; unchanged syscall forwarded |
| malformed/out-of-arena table | `Foreign(Malformed)` | `BackingMalformed`; unchanged syscall forwarded |
| more than one backed run | `MultiRun` / `Foreign(TooManyRuns)` | `BackingMultiRun`; unchanged syscall forwarded |
| retained retired terminal | `BackingRetired` | `BackingRetired`; unchanged syscall forwarded |
| ISA edit refusal | `EditRefused` | `EditRefused`; unchanged syscall forwarded |
| return journal full | `JournalFull` | `JournalFull`; unchanged syscall forwarded |
| operation not owned by this vertical | `RootDeclined` | `RootDeclined`; unchanged syscall forwarded |
| reservation-root refusal before edit | `Root(Refusal)` | `RootUnavailable`; unchanged syscall forwarded |
| descriptor rollback failure | `RollbackFailed` | same fatal invariant failure |
| root commit refusal after a live edit | `CommitAfterEdit(Refusal)` | same fatal invariant failure |

`mprotect`, `munmap`, `mmap`, and `brk` errno values are still produced only by
the existing Linux decoder/personality. The neutral owner returns no errno.
Retired frames remain unavailable until the existing core retirement receipt;
the extraction does not create an alternate frame-reuse authority.

## Behaviour-preservation checks

- The existing AArch64 VM-free delegated-anonymous suite exercises lazy,
  resident, prepared, retired, malformed, split-run, journal-full, and rollback
  paths through the moved core body.
- The AArch64 classifier and hardware editor still call the same
  `carrick-mmu-core::aarch64` descriptor transactions and the same ASID
  invalidation adapter.
- No AArch64 descriptor constants, table walking, TLBI, DSB, ISB, HVC, or
  Linux policy moved into `carrick-core`.
- The signed AArch64 comparison against baseline `56bf8c0ca` remains the
  director-owned post-push gate.
