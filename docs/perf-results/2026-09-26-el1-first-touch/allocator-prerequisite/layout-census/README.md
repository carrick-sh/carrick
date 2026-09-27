# Compiled EL1 ABI region census

The retained Rust witness imports the current ABI constants, asserts the named
reservations do not overlap or exceed the 64 MiB region, and reports their
complement. It completed successfully at the source and ABI hash in receipt.json.
This is a host-only layout observation, not guest allocation acceptance.

| Unassigned offset interval | Bytes | Within nominal heap? |
|---|---:|---|
| 0x00700000..0x01000000 | 9,437,184 | No |
| 0x01030000..0x01100000 | 851,968 | Yes |
| 0x03410000..0x03500000 | 983,040 | Yes |

Only 1,835,008 bytes (1.75 MiB) of the advertised 48 MiB heap are outside the
named reservations. The whole 64 MiB region has 11,272,192 unassigned bytes
(10.75 MiB). The final 11 MiB are the scheduler zone; placing a general heap
at the end of the region would overlap it. The existing BumpAllocator begins
on the object table, as the earlier red witness already established.

These intervals are candidates for an explicitly assigned bootstrap arena,
not permission to allocate from them or a replacement for elastic grants.
The next allocator design must reserve and hash its own ABI interval, prove
that every allocation excludes these occupied regions, reclaim individual
allocations and fully free extents, and route exhaustion through typed refusal.
Its dynamic extents need explicit guest-pointer/IPA/owner-generation identity,
transactional mapping, and exact-once host return. Fixed bootstrap capacity
cannot be the final metadata or anonymous-memory pool.

Source inspection also finds only a spinning EL1 lock, with no IRQ-mask guard
in alloc.rs or lock.rs. Any allocator installation must establish interrupt
exclusion and lock ordering, and must not request a host grant while holding
an allocator lock that the completion path needs. The current EL1 binary has
no global allocator; no guest allocation has been enabled by this census.

The captured manifest belongs to the existing standalone target-directory
witness package; layout.rs is the exact added example. The run command in the
receipt identifies the original execution location.
