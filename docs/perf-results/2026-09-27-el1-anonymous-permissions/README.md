# EL1 anonymous permission acceptance

This directory binds the `kernel.el1.anonymous-permissions` contract to source
commit `f1bff2ec47d91ec358f6b55801f21498062edec7`. The checkpoint moves exact,
fully resident private-anonymous `mprotect` transitions into guest EL1, keeps
the output frames and permission ceilings authoritative in live stage-1
descriptors, and routes denied reads and writes to Linux `SIGSEGV` with
`SEGV_ACCERR` without attempting another first-touch frame grant.

## Impact

The committed signed witness serves all four target-range protection changes
per round in EL1 at every scale. One fixed one-page `mprotect` for the process
signal-stack guard still forwards; it is independent of page and round count
and remains work for the signal increment.

| Pages | Rounds | Host exits | EL1 target `mprotect` | Forwarded guard | Fault entries | Grants / returns | Bytes granted / returned |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 256 | 4 | 57 | 16 | 1 | 14 | 3 / 3 | 1,114,112 / 1,114,112 |
| 1,024 | 4 | 59 | 16 | 1 | 18 | 5 / 5 | 4,276,224 / 4,276,224 |
| 4,096 | 4 | 65 | 16 | 1 | 30 | 11 / 11 | 16,875,520 / 16,875,520 |
| 256 | 2 | 49 | 8 | 1 | 10 | 3 / 3 | 1,114,112 / 1,114,112 |
| 256 | 18 | 113 | 72 | 1 | 42 | 3 / 3 | 1,114,112 / 1,114,112 |

The page-scale exit slopes are 0.0007 and 0.0005 exits per added page per
round, well below the strict 0.125 limit. Increasing the transition count from
2 to 18 rounds allocates no additional frames or bytes. Its four-exit round
slope is exactly the two denied-access signal cycles that remain host-served.

The final L2-block red witness is also an impact control. Before the
allocation-free guest editor handled complete 2 MiB terminals, the 4,096-page
run forwarded all 16 target transitions and used 97 exits. The committed run
serves all 16 in EL1 and uses 65 exits, removing 32 exits and the target-range
host authority crossing.

## Red-first diagnosis

The permission fixture first exposed two direct live-authority failures.

1. A host `munmap` built from its older shadow image erased an adjacent live
   subtree grown by the guest editor. The target range completed, then a Rust
   allocation immediately above it faulted because its valid leaf had been
   lost. `live_host_unmap_preserves_adjacent_guest_private_leaf` failed before
   the host editor adopted the complete reachable live table pages for its
   exact range and passes afterward.
2. Small ranges used L3 leaves and stayed in EL1, while 1,024- and 4,096-page
   ranges retained complete L2 block terminals and forwarded. The red-first
   `allocation_free_guest_permission_edit_updates_complete_l2_block` witness
   returned `MissingTable`. The final editor walks L1/L2 blocks and L3 leaves,
   validates the whole range before its first store, and still rejects a
   partial coarse block for explicit host splitting.

The COW winner check now accepts host-shadow divergence only when the live leaf
carries the EL1 private-authority tag and independently proves exact IPA,
validity, `nG`, and writable permission. Untagged mappings retain the previous
fail-closed parity rule. Host syscall-buffer reads and writes consult the same
live permission descriptor, so host service cannot bypass a guest-served
`PROT_NONE` or read-only transition.

## Bound acceptance

- `signed-artifacts.jsonl` binds the passed signed execution to source commit
  `f1bff2ec4`, test executable SHA-256
  `b3dc860a9dc8184c3979958860c0e300fa4082736eb30e401bfa3017c127143b`,
  CDHash `d923040a1b4ba64c374b80df6447296b8ac3cdc7`, LC_UUID
  `6B10F669-1F84-3159-B2C1-5678AA7BE945`, the hypervisor entitlement and the
  `__dof_carrick` section. The unentitled negative control passes and scoped
  cleanup is zero.
- `artifact.txt` records the signed CLI and same-source fixture identities.
- `docker-{256,1024,4096}.out` are same-source executions on the pinned native
  arm64 Docker oracle. Every row reports exact fault counts, byte preservation,
  `SEGV_ACCERR`, and successful unmap; all stderr files are empty.
- `gate-status.md` records focused source gates and the unchanged inherited
  aggregate domain-lint failure.

This accepts the permission vertical inside checkpoint 2. Checkpoint 2 remains
open: broader `mmap`/`munmap`/`brk` ownership, fork-COW authority, the fixed
signal-stack guard, and final removal of the host page-table writer/pause are
still required.
