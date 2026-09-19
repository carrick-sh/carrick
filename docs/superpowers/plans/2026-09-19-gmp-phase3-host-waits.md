# Phase 3 host-wait inventory

Working inventory, not acceptance. Paths below are repository-relative.
The controller is `2026-09-19-gmp-phase3.md`; unclassified or unproved sites
block the default executor-count change.

| Surface / source | Current classification | Ownership and remaining proof |
|---|---|---|
| `dispatch/fs.rs`: sync, syncfs, fsync, fdatasync, sync_file_range | External host operation; first handoff binding implemented | Pin `HostFdRef` before releasing description guard; consume captured file-table use, leave MM, lend P, run injected `HostIo`, reclaim P, check exact-thread liveness, restore MM only if live. No later file lookup in that scope. VM-free retirement/MM progress proven; signed proof pending. |
| `dispatch/fs/rw.rs`: host regular-file read/readv/preadv | External wait, handoff integrated | Integrated with `SyscallHostWaitReleaser` and `read_host_pipe_at`/`read_host_pipe_owned_at`. Releases P and MM participation across host blocking calls while holding owned buffer pointers. |
| `dispatch/fs/rw.rs`: write/pwrite/writev host-file paths | External wait plus shared-description transaction, handoff integrated | Integrated with `SyscallHostWaitReleaser` and `write_host_pipe_at`/`write_host_pipe_owned_at`. Releases P and MM participation across host calls with atomic offset updates. Contention and progress proven. |
| `dispatch/fs.rs`: scalar write_owned_stdio_sink | Scalar owned handoff implemented; proven | Captured output remains memory-only. Bare inherited output pins its host endpoint; caller-provided Write mutex/backpressure runs after P/MM release. Inherited backpressure and writer mutex contention verified by `stdio_inherited_backpressure` and `stdio_host_wait_contention`. |
| `dispatch/fs.rs`: write_stdio_sink calls from writev/transfer | External waits, handoff integrated | Integrated across vectored and transfer paths (splice, tee, copy_file_range) with `with_host_wait_parts`. Staged transfers avoid per-chunk amplification while preserving partial completions. |
| `dispatch/fs/rw.rs`: HostPipe and in-memory-pipe writes | Existing owned `BlockingWrite` continuation | Keep retained endpoint, committed prefix/offset, signal and readiness semantics. Never replace with blocking host-thread wait. Existing tests are not yet Phase 3 composition proof. |
| `dispatch/fs/open.rs`: FIFO reader/writer rendezvous | Existing `BlockingOpen` continuation | Preserve retained open/publication and cancellation. Host path resolution/backend opens outside this rendezvous still need inventory. |
| `dispatch/fs/locks.rs`: contended record locks/flock | Existing `BlockingRecordLock` continuation | Keep exact description/lock ownership; do not hold P in a host flock/fcntl wait. |
| `dispatch/fs.rs` and mounted VFS methods: content, path, metadata operations | Backend-dependent external work, **pending audit** | Existing injected VFS implementations must remain the real operation seam. Content read_at/write_at may execute host I/O under description state; classify actual backend, not just the method name. |
| Runtime fault/materialization and mapping publication | Critical ownership transaction, **pending audit** | Guest VA, IPA, host-owner generation, MM census and inventory publication cannot be relinquished indiscriminately. Identify owned staging phase before selecting any external wait boundary. |
| Runtime fork/exec and physical retirement | Mixed continuation/admission/critical phases, **pending audit** | Existing clone admission and exec/exit cancellation must retain exact owner/generation. The fixed file-table retirement cycle demonstrates why lending P while retaining resource admission is unsafe. |
| Reactor / retained continuation service | Off-executor readiness service | Do not manufacture a P for reactor, embed host API, or off-executor dispatch. Verify no extra guest-memory access or blocking retained-service operation leaks through this boundary. |

For every pending external path require deterministic injected blocking at the
actual production operation, progress by a replacement with one P/one spare,
error/partial completion and retirement/cancellation tests, and signed embed
composition. The inventory does not assert every host syscall has been audited.
