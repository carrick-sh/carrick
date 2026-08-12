# Per-run FileAuthority atomic migration

**Status:** approved architecture; implementation required before K1 file
cutover can be committed.

**Reason for existence:** Carrick's host-process fallback lanes cannot preserve
Linux `CLONE_FILES`, post-fork open-file-description state, or staged pipe
bytes with process-local Rust objects. This plan defines the only accepted
migration to one per-run authority without an intermediate dual-authority
state.

**Controlling context:** [`hybrid.md`](../../../hybrid.md),
[`2026-08-09-hvpatch-k1-kernel-object-model.md`](../specs/2026-08-09-hvpatch-k1-kernel-object-model.md).

## Decision

Create one `FileAuthorityCore` per Carrick run.

- Kernel-first/HVPatch callers invoke the core directly.
- Native and VMM host-process callers use versioned typed IPC to the same core.
- The core exclusively owns every `FileTable`, reachable `FileDescription`,
  mutable open-description state, epoll subordinate state, splice stream state,
  stable ID allocator, logical slot references, and revisions.
- Clients own exact `KernelContext` and mixed-domain orchestration. They retain
  typed IDs, request handles, and bounded capability leases only. They never
  retain a slot map, mutable description snapshot, or fallback authority.
- Authority death terminates the run. A client never reconnects, promotes a
  cache, or retries an operation whose terminal commit state is unknown.

Do not commit or enable an intermediate model. Develop the waves below in one
isolated worktree, but merge them as one authority cutover after all acceptance
gates pass.

## Rejected shortcuts

### Shared slot metadata

A `MAP_SHARED` file-table map cannot convey a socket, pipe, kqueue, or synthetic
description opened after host fork. It would also leave mutable
`OpenDescription` state process-local and create two authorities.

### Whole-syscall RPC

Do not execute complete file-related syscall handlers in the helper. A
`KernelContext` is an exact retained object bundle, not reconstructible from
IDs. mmap, io_uring, waits, signal cancellation, and guest-memory publication
cross file, MM, thread, and signal domains. Nested guest-memory callbacks move
rather than reduce the typed protocol and introduce partial-commit ambiguity.

### Permanent client capabilities

An fd received through `SCM_RIGHTS` is not semantic authority. Permanent
client-owned host fds allow local operations to mutate offsets, status, and
readiness outside authority transactions. Only operation-bounded borrows and
acknowledged mapping leases are allowed.

## Ownership model

```text
KernelContext
  └─ ThreadResources
       └─ FileAuthorityBinding { authority, table_id, generation }

FileAuthorityCore
  ├─ tables: FileTableId -> FileTableState
  ├─ descriptions: FileDescriptionId -> FileDescriptionState
  ├─ streams: PipeId -> PipeStreamState
  ├─ mmap_leases: MappingLeaseId -> MappingLease
  ├─ clients: (HostPid, ProcessGeneration) -> ClientState
  ├─ dedup: (ClientId, RequestId) -> TerminalResponse
  └─ epoch + monotonic ID/revision allocators
```

`ThreadResources` no longer contains `Arc<FileTable>`. Descriptions never
expose `Arc<RwLock<OpenDescription>>`, a lock guard, `&mut` variant state, or a
raw host fd across the authority API.

Logical file references count reachable fd slots. Request objects, Rust `Arc`
clones, capability borrows, waits, and mmap leases use separate typed counts.

## Closed operation surface

The direct and IPC transports implement the same closed interface. Operation
payloads contain values and typed IDs only.

| Family | Required operations and results |
|---|---|
| Inspect | Resolve fd to typed description metadata; enumerate slots; obtain fd flags, path, status, tty/type, revisions, and snapshots. |
| Install | Create/adopt a typed backing; reserve lowest free fd(s); atomically install path/fd flags and logical references. |
| Slot mutation | Close, dup, dup2/dup3, replace, set CLOEXEC, and close ranges. Return typed close effects after one commit. |
| Description mutation | Status flags, owner/signal, lease, seals, pipe size, socket options/timeouts/errors, offsets, and synthetic state. |
| I/O attempt | Byte/value input produces `Complete`, `WouldBlock(WaitToken)`, or `Retry`; guest pointers never cross the boundary. |
| epoll | Create, ctl, collect readiness, acknowledge delivery, and close cleanup as multi-description transactions. |
| Stream transfer | Read/readv/splice/tee/sendfile consume one `PipeStreamState` keyed by stable `PipeId`, with exact partial-commit results. |
| mmap | Resolve and pin a mapping source; return one `SCM_RIGHTS` capability plus lease ID; commit or abort against the caller's exact MM transaction. |
| io_uring | Own backing/layout/SQ-CQ state; parse guest data in the client; execute typed fd operations; publish CQ outside authority locks. |
| Lifecycle | Fork-copy table, share table, exec-unshare/CLOEXEC, drain generation, client exit, snapshot, restore, and native reexec adoption. |
| Limits | Read/set `RLIMIT_NOFILE` and reject allocation atomically against the same table revision. |

Every request contains authority epoch, client `(HostPid,
ProcessGeneration)`, monotonic request ID, target typed ID, and expected object
generation. Every mutation publishes one monotonic revision after all fields
commit.

## Locking and blocking

Canonical order:

1. authority lifecycle/exec freeze;
2. tables by ascending `FileTableId`;
3. descriptions by ascending `FileDescriptionId`;
4. streams by ascending `PipeId`;
5. lease and dedup ledgers.

Never hold authority locks across guest-memory access, host waits, signal
wake/cancellation, backend mapping work, registry operations, or IPC send.
Resolve a slot and acquire an in-flight description lease under the table lock,
then release the table before I/O. Close removes the slot immediately; backing
reclamation waits for operation and mapping leases.

Blocking operations use prepare/attempt/park/revalidate:

1. marshal guest input in the client;
2. authority attempts nonblocking I/O and returns a typed wait token;
3. caller parks under its exact signal/cancellation context;
4. caller retries with the same logical operation and a new request ID;
5. authority validates object generation before another attempt.

The authority completes already-committed stream transfers if the requester
dies. Cancellation reports the exact committed partial count.

## Transport

Use `AF_UNIX/SOCK_DGRAM` socket pairs with one bounded frame per `sendmsg`.
Datagram payload and `SCM_RIGHTS` capabilities are one record.

- Encode a fixed endian-independent header manually: magic, version, frame
  kind, operation, payload length, fd count, epoch, client identity, request
  ID, and expected generation.
- Set `FD_CLOEXEC` explicitly on every control and received fd, except for the
  prepared native self-reexec successor endpoint described below.
- Reject `MSG_TRUNC`, `MSG_CTRUNC`, unknown versions/operations, wrong lengths,
  unexpected ancillary records/counts, stale epochs, stale generations, and
  duplicate nonterminal requests.
- Close every received fd on every rejection path.
- Keep frames conservatively bounded and chunk byte I/O.
- The helper starts before guest host forks. Do not continue Rust execution in
  a child forked from a multithreaded process; start before threads or
  fork-and-exec using only async-signal-safe child work.
- Socket loss, helper exit, malformed frames, dedup exhaustion, and invariant
  failure are run-fatal.

### Native self-reexec endpoint inheritance

A control fd marked `FD_CLOEXEC` cannot preserve the same FileAuthority across
host `execve`, while reconnecting or serializing mutable descriptions would
create a second or ambiguous authority. The approved exception is one prepared
successor endpoint:

1. the authority creates a dedicated successor endpoint and binds it to the
   successor generation, authority epoch, and a single-use nonce;
2. `HostFdFlagTransaction` clears `FD_CLOEXEC` only after exec preparation has
   otherwise succeeded and immediately before the host exec;
3. the successor authenticates the inherited endpoint with the epoch and nonce,
   adopts the existing authority, and restores `FD_CLOEXEC` before guest work;
4. an aborted or failed exec restores the endpoint's original fd flags; and
5. no pathname reconnect, inherited parent endpoint, file-description snapshot,
   or mutable client mirror is permitted.

This is the only exception to the control-fd CLOEXEC rule. It preserves the
no-reconnect and one-authority requirements.

## Atomic implementation waves

### Wave 1 — characterize and enumerate

Add red Docker differentials for:

- `CLONE_FILES`: opposite-process open, close, dup, and fcntl visibility;
- ordinary fork: isolated table membership with shared offset/status;
- exec by one `CLONE_FILES` sharer, including CLOEXEC isolation;
- pre-fork staged pipe bytes consumed in exact order across processes;
- requester death during partial splice;
- authority death and duplicate request delivery.

Generate a checked operation inventory from all production
`read_open_files`, `write_open_files`, description guard, epoll, splice, mmap,
io_uring, restore, and lifecycle sites. Test-only fixture mutations are listed
separately.

### Wave 2 — direct core

Implement the complete closed API over one core. Migrate production callers
family-by-family without enabling a second store. `ThreadResources` changes to
`FileAuthorityBinding` only after every direct call site compiles against the
closed API. Delete guard-returning APIs in the same wave.

### Wave 3 — helper and IPC equivalence

Start the helper before guest host forks. Implement protocol validation,
request deduplication, client death records, capability borrows, mapping
leases, and fail-closed helper death. Run every operation model test against
both direct and IPC transports from the same test vector.

### Wave 4 — lifecycle and backends

Route Kernel fork-copy, in-process `CLONE_FILES`, host-process `CLONE_FILES`,
exec-unshare/CLOEXEC, draining generations, native reexec, VMM, native Darwin,
native x86, DirectRunner, and HVPatch through authority lifecycle operations.
Child task publication waits for authority binding acknowledgement.

Move splice pushback to `PipeStreamState`. Route ordinary read/readv and every
splice/tee/sendfile consumer through it.

### Wave 5 — deletion and enablement

Delete:

- `host_fork_file_authority_rejection`;
- `ThreadResources.files: Arc<FileTable>`;
- guard-returning table and description APIs;
- descendant-local shared-object ID allocation;
- per-table splice pushback;
- backend host-fork table copies and local epoll/synthetic mutable mirrors.

The new authority is always on. There is no opt-in flag or compatibility path.

## Verification

Structural gate:

```bash
rg -n 'host_fork_file_authority_rejection|read_open_files|write_open_files|read_splice_pushback|write_splice_pushback' crates/carrick-runtime/src
rg -n 'Arc<FileTable>|RwLock(Read|Write)Guard.*OpenDescription' crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel
```

Both commands must return no production authority escapes. Explicit test
fixture builders may remain under `#[cfg(test)]`.

Correctness gates:

```bash
cargo test -p carrick-runtime kernel:: -- --test-threads=1
cargo test -p carrick-runtime --lib -- --test-threads=1
cargo test -p carrick-runtime --test integration -- --test-threads=1
cargo test -p carrick-runtime --test process -- --test-threads=1
just ci
git diff --check
```

Live gates use signed binaries and scoped `CARRICK_RUN_ID`s. Run Carrick and
the Docker oracle in separate phases. Require direct/IPC equivalence,
HVPatch/native/VMM fork/exec probes, file-backed mmap and io_uring mapping
lifetime, epoll close across copied tables, staged splice ordering, requester
death, and authority-death fail-closed behavior.

## Completion criteria

The FileAuthority cutover is complete only when:

- one run has one mutable file authority in every backend;
- all sharing, fork, exec, offset, flag, CLOEXEC, epoll, splice, mmap, and
  io_uring differentials match Linux;
- snapshots join table, description, stream, and lease revisions coherently;
- authority/client death tests prove bounded failure without loss or replay;
- direct and IPC model tests are identical;
- signed HVPatch, native, and VMM demonstrations pass;
- `just ci` passes; and
- the rejected APIs and fallback paths are deleted, not deprecated.
