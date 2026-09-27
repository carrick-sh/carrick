# Signed allocator test-control gate verification

Source 5b2da6bef1636509e6d30d1a36231e658e7990bf. The signed run completed
with both sequential and concurrent allocator tests passing, the unentitled
negative control passing, and zero processes in both cleanup scopes.
The sequential case granted and returned 5,767,168 bytes, including one
intentional grant denial and subsequent recovery. The exact test executable,
CLI and Linux fixture are frozen at the paths in identity.json. The test SHA
matches the runner receipt.

This verifies the test-feature wiring. IRQ/host-wait handling, bounded-work
acceptance, allocator integration, first-touch slope and workload timings remain
open. No memory-checkpoint acceptance is claimed.
