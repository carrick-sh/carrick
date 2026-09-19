# Phase 3 host-wait inventory

Working inventory, not acceptance. Paths below are repository-relative.
The controller is `2026-09-19-gmp-phase3.md`; unclassified or unproved sites
block the default executor-count change.

| Surface / source | Current classification | Ownership and remaining proof |
|---|---|---|
| `dispatch/fs.rs`: sync, syncfs, fsync, fdatasync, sync_file_range | External host operation; first handoff binding implemented | Pin `HostFdRef` before releasing description guard; consume captured file-table use, leave MM, lend P, run injected `HostIo`, reclaim P, check exact-thread liveness, restore MM only if live. No later file lookup in that scope. VM-free retirement/MM progress proven; signed proof pending. |
| `dispatch/fs/rw.rs`: host regular-file read/readv/preadv | External wait, **not yet handoff-safe** | Some fast paths hold guest-backed iovecs; fallbacks hold description/offset authority and copy out afterwards. O_NONBLOCK does not guarantee regular-file storage latency is nonblocking. Need owned arguments plus exact return/copyout authority, without per-iovec amplification. |
| `dispatch/fs/rw.rs`: write/pwrite/writev host-file paths | External wait plus shared-description transaction, **pending** | Offset/append save-seek-write-restore and cache invalidation surround calls. A P transfer cannot retain a mutex needed by its replacement. Preserve partial-write count and shared offset atomically; do not wrap libc blindly. |
| `dispatch/fs.rs`: scalar write_owned_stdio_sink | Scalar owned handoff implemented; **higher proof pending** | Captured output remains memory-only. Bare inherited output pins its host endpoint; caller-provided Write mutex/backpressure runs after P/MM release. Redirected piped output stages the handler's exact description; completion rearms current matching epoll interests without file-table use. VM-free progress, retirement, short-write error and unwind tests pass. Inherited backpressure and signed composition remain unproved. |
| `dispatch/fs.rs`: write_stdio_sink calls from writev/transfer | External waits, **pending** | These callers emit multiple chunks and revisit guest/resource state. Stage owned arguments while preserving partial-fault/committed-prefix semantics and bounded work; the consuming boundary cannot be inserted per chunk. Preserve the existing caller-provided Write interface. |
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
