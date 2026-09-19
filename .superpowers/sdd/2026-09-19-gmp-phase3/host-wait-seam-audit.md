# Phase 3 remaining host-wait seam audit

Static inspection on 2026-09-19 in `codex/gmp-phase3`; no builds, tests,
guests, Docker, or acceptance measurements were run. Source line numbers are
the inspected working-tree positions and may shift during concurrent work.
This report supplements the controller and inventory; it does not complete
either. Applied the Carrick conformance-contract workflow to identify proof
requirements, not to claim new bindings. Contract: `kernel.scheduler.host-wait-handoff`.

## Boundary rule and immediate priorities

`dispatch/mod.rs:1437` consumes the remaining captured file-table use, leaves
the exact MM, lends P, executes owned work, reclaims P, and restores MM only
for a live exact thread. `dispatch/resources.rs:237` rejects a second use of
this consuming boundary. A callable closure is not evidence that its captured
state is safe: no guest pointers, description guards, namespace transactions,
or other authority required by the replacement may cross it. Exact-thread
retirement suppresses guest completion; it does not undo host side effects or
interrupt a blocked host call. Flush proves only the existing owned flush slice.

1. Finish scalar owned stdio with deterministic backpressure and retirement
   tests. Keep vector and transfer callers explicitly open until their whole
   operation has owned staging and preserved partial-fault behavior.
2. Stage positional regular-file reads before tackling shared-offset or append
   writes. Preserve injected VFS content methods as actual operation seams.
3. Inventory path and MM publication transactions separately; do not wrap a
   broad dispatch closure or host backend trait indiscriminately.
4. Keep default sizing unchanged while any of these production classes can
   occupy every bound executor without a replacement being able to progress.

## Concrete sites and smallest candidate boundaries

| Site | Held state / hazard | Smallest next boundary |
| --- | --- | --- |
| `dispatch/fs.rs:1464`, `:1491`, `:1518` | Captured output is memory-only. Embed writer mutex acquisition and `Write::write_all` can block. Inherited write loops call indefinite `poll` at `:1558`. Route-lock release alone does not remove MM or file-table admission. | Clone route and own complete scalar bytes before handoff. Acquire caller writer mutex only after handoff, so a second writer never blocks while owning P. Keep the same `Write` interface and ordered serialization. Pin inherited endpoint with owned host descriptor before handoff, rather than capture numeric process fd 1/2. |
| `dispatch/fs/rw.rs:2398`, `:2494`, `:2956` | Scalar write stages bytes, but redirected HostPipe branch still has `io_lease` and `open_file` after dropping `open`. | Select final route before consuming captured files. Explicitly end unused guards/references before call. `io_lease` is a description fd reference, not a table functional lease; retain it only where endpoint semantics require it. |
| `dispatch/fs/rw.rs:3267`, `:3636` and transfer callers | Multiple sink calls revisit guest iovecs/resource state; partial bytes may already be committed. | Do not insert consuming handoff inside each chunk. Stage a complete owned request with committed-prefix accounting and preserve Linux short-write/EFAULT ordering; avoid allocating an unbounded aggregate. |
| `dispatch/fs/rw.rs:1461-1501` | Scalar host `pread` already has owned output buffer but holds description read guard and copies to guest immediately afterward. VFS `contents.read_at` may block too. | Clone host endpoint or content owner and scalar offset; drop guard; perform one owned read; reclaim P/MM and verify exact authority before copyout. Copyout must require no fresh captured-file lookup. |
| `dispatch/fs/rw.rs:1149-1177`, `:1613-1673` | `readv`/`preadv` fast paths use guest-backed iovecs under MM admission. Fallback loops use several host calls. | Owned iovec staging with bounded work and exact partial-read rules; no guest-memory slice can survive MM departure. Do not turn one vector operation into an unbounded number of handoff episodes. |
| `dispatch/fs/rw.rs:1787-1871`, `:2171-2249`, `:2710`, `:3406` | Writes retain description authority. Append pwrite does save offset, seek, write, restore; sparse/cache publication follows. Vector fast path borrows guest data. | Positional non-append owned writes are the simpler next slice, but stage cache identity and completion state too. Shared-offset/append operations need a typed description transaction whose contention parks without P; dropping the lock between save/restore is incorrect. O_NONBLOCK does not eliminate regular-file storage latency. |
| `dispatch/fs.rs:1720-1813`, `:1933-1981` | File resizing/allocation may read contents and write zero chunks while holding description state. | Owned content operation with bounded chunk accounting and explicit size/cache commit. Do not release description ownership while silently permitting conflicting size/offset updates. |
| `carrick-vfs/src/fs_backend.rs:554`, `:615`, `:964`, `:1075`; `rootfs.rs:1225`, `:1275` | Metadata, open, readlink and host-backed resolution may call storage. Dispatch open later publishes guest fd state. Namespace/cache transactions can span lookup and mutation. | Split owned path/dir authority plus backend operation from validated publication. Preserve exact directory/namespace identity and rollback, not just a copied pathname. Existing `FsBackend` injection is the seam for these operations; flush `HostIo` does not cover them. |
| `dispatch/mem/backing.rs:643-680`, `:899`; `mem/mmap.rs:1652`, `:1723`, `:2033` | Snapshot/materialization does host pread or VFS content read; some mapping paths write directly into selected backing. MM mapping/publication authority may already be active. | Candidate is owned backing-fill before publication, with pinned endpoint and checked file offset. Authenticate MM generation, stage-1 identity, host owner and reservations before publishing afterward. Do not lend P while retaining a mutation/pause lock the replacement needs. A direct guest/backing pointer is not automatically owned staging. |
| `vcpu_loop/lifecycle.rs:305`, `:336`, `:473`; `vcpu_loop/exec.rs:544-562` | Fork materialization and exec replacement load are lifecycle transactions, not simple host I/O. | Stage external image/content work before the critical publish phase where possible; preserve fork admission, cancellation, load guard and physical backing ownership. Reuse existing continuation/admission paths rather than blanket host-wait wrapping. |
| `vcpu_loop/binding.rs:4852-4880`; `vcpu_loop/wait_wake.rs:248`, `:362`, `:522` | Root launch wait and physical retirement coordinator can run off executor. Condvar presence does not imply a P is held. | First establish caller role. Off-executor coordinator waits need no fabricated P. Executor retirement must not wait on an authority held by its suspended original. |

## Description lifetime versus table lifetime

`kernel/objects.rs:1307` retains a `FileDescriptionFdLease`; its drop at `:1517`
releases description fd_refs and can trigger final-close effects. In contrast,
`FileTableFunctionalGate::retire` at `:1824` waits on table active uses/mutations,
and `FileTableFunctionalLease` at `:1838` controls that use count. The scalar
stdio reroute's leftover description lease does not itself recreate the known
table-use retirement cycle. Nevertheless it can delay endpoint finalization;
do not retain it accidentally when the selected destination is an independent
embed writer. Test guest close/reuse and final-close timing explicitly.

Inherited fd duplication pins the endpoint but shares host status flags and
offset. Do not clear O_NONBLOCK or assume the duplicate isolates flags. Pinning
also needs an acquisition error path before MM/P departure. Logical guest
signals do not automatically interrupt arbitrary `Write::write_all`, fsync,
or host poll. Handoff provides sibling progress; cancellation of the host
operation is a separate API/lifetime obligation. Arbitrary embed writer code
may never return, so container shutdown/join behavior requires explicit proof.

## In-zone continuations and existing interfaces

HostPipe/in-memory pipe `BlockingWrite`, FIFO `BlockingOpen`, record-lock
`BlockingRecordLock`, futex and reactor readiness remain retained kernel
continuations. Do not replace them with blocking host-thread calls. Their
committed prefixes, exact fd authority, readiness enrollment and signal restart
rules must survive composition with a host-waiting peer.

`dispatch/host_io.rs:10` presently provides only sync/flush. Its injection
replaces actual work; adding observer-only hooks would not establish progress.
`carrick-embed/src/builder.rs:382` exposes scheduling policy and `:390` exposes
HostIo; policy and owned-operation fixtures should use these real interfaces.
`PersistentExecutor` and its runtime fake backend establish production-loop
settlement ordering; a kernel script using host threads does not prove executor
handoff. Platform-neutral ownership must remain outside HVF-specific types,
and an HVF vCPU stays on its original host thread.

## Required focused tests

- At one P/one spare, block at the actual production operation, prove a sibling
  progresses, then release and prove exactly one completion and balanced MM/P.
- For stdio, test the mutex-acquisition wait as well as writer backpressure,
  short writes followed by error, unwind, inherited endpoint reuse, captured
  output bypass, redirected fd 1/2, and an ordinary non-stdio fd.
- Retire the exact original thread/private table while blocked; return must
  not copy bytes to guest or publish guest registers. Keep another process alive
  and verify no process-wide exit. A distinct test covers container close while
  arbitrary host writer is still blocked.
- For reads, mutate/unmap destination while the operation is suspended; reject
  stale copyout correctly after readmission. For writes, verify committed prefix,
  append offset and close/reuse behavior against Linux authority.
- Exercise replacement MM mutation, nested handoff, no spare, pre-park wake,
  concurrent return, affinity and record/replay. Assert bounded executor count
  and zero guest execution without P at deterministic scales 1, 8, 32.
- Add signed embed composition and pinned same-image Docker semantics/timing;
  VM-free success does not close signal delivery or guest-memory projection.

## Registry integration still required

At inspection the descriptor directory contained only `futex-contention.toml`
and `futex-requeue.toml`; `surfaces.toml` had no scheduler host-wait ownership.
The plan's ID is not a registered binding. Add a descriptor for
`kernel.scheduler.host-wait-handoff` with actual fixture identity, surfaces,
Linux authority, scale points and justified structural budgets. Register exact
changed source/test surfaces. Adapt scenario results to typed complete
observations, including source identity and fixture identity; debug enter/resume
counters alone are not contract evaluation.

Name VM-free, signed embed and Docker bindings only when corresponding runners
exist. Until then preserve UnsupportedLayer/IncompleteMeasurement, not a
placeholder function name that suggests implementation. Structural metrics
must cover conservation/uniqueness, completed episode enter/resume balance,
bounded spares and absent unowned guest entry, with contention/overflow reported
as unavailable rather than zero. Timing uses uninstrumented release evidence,
separate from structural runs. Same-artifact probes, smoke, full, provenance and
scoped cleanup remain parent-owned acceptance work.

## Follow-up: post-I/O epoll rearm after consumed file authority

The reported scalar test failure has a concrete dependency chain:
`dispatch/execution.rs:440` calls `epoll_rearm_after_io` after dispatch;
`dispatch/net/epoll_ops.rs:665` enumerates `captured_file_table`, resolves epoll
descriptions and resolves target fds again. The consumed scope therefore cannot
execute this epilogue. Merely moving the top-level enumeration is insufficient:

- Target matching resolves `host_fd_for_poll` and `open_file` for each target;
  the EAGAIN arm repeats these for each candidate.
- Host rearm resolves matching fd numbers again, then
  `rebind_epoll_host_registration` (`:356`) resolves every union member.
- That rebind calls `epoll_effective_interest` (`:283`), which resolves
  one-way-pipe classification, in-memory endpoint direction and OOB support.
- Lazy prune at `:828` writes the captured epoll-fd set.
- `interest_host_fd` (`:425`) is table-free only when `slot.target` is Some;
  its bare-stdio fallback still resolves the current fd table.

### Smallest safe staged implementation

Introduce a specific owned scalar-write rearm receipt; keep ordinary syscall
rearm unchanged initially. Prepare it in the scalar stdio handler, after the
actual output route is selected and before `with_host_wait`. The receipt holds
the exact I/O description (if present), exact epoll owner Arcs, and matching
registration keys `(registration_fd, reg_gen, target identity)`. For a described
target, `FileDescription::epoll_owners` (`kernel/objects.rs:1237`) provides exact
owners without retaining a file-table use. Bare stdio requires preparation
under captured files by enumerating the table's epoll owners. Hold no epoll or
description mutex during the host wait and do not retain table functional use.

After return, apply the outcome to each still-live exact epoll description.
Under its description guard, verify the current registration still matches the
receipt's generation and target identity before touching `io_gen`,
`last_ready`, `last_read_avail` or `write_backpressured`. Never resolve the
numeric target or epoll fd again. Close/reuse must leave the replacement's
registration untouched. DEL/ADD and MOD mint or change registration state;
respect that state instead of restoring the old event mask or udata. Newly
added registrations already start with their own fresh latch.

Preserve the existing positive/zero/EAGAIN decision function. Scalar write's
normal successful result clears writable latch state; EAGAIN requests writable
backpressure tracking. This is outcome-dependent work, so preparing a receipt
must not clear anything before I/O. Errors and unwinds must not fabricate a
positive consumption event. Fatal retired return currently bypasses the
epilogue; preserve that terminal behavior unless a separately justified
endpoint-side completion contract requires otherwise.

For BSD host rebind, add a table-free variant over the CURRENT interest map.
Resolve sources and endpoint classification from each slot's retained exact
description, not the caller's table. Factor the effective-interest arithmetic
into a helper accepting explicit endpoint facts (one-way read end, in-memory
direction, OOB capability). The existing fd-based helper can delegate to this
arithmetic after its usual lookups. This is necessary to preserve the union of
live duplicate-fd registrations and changes made by concurrent epoll_ctl.
Do not replay a pre-wait union mask: that could overwrite concurrent MOD/DEL.
Do not indiscriminately replace the current helper with one that still falls
back to fd lookup when `slot.target` is absent.

Bare inherited stdio is the remaining explicit identity corner: its interests
currently have `target: None` (`dispatch/fd_table.rs:67`) and only numeric host
source identity. At minimum stage its exact epoll registration generation and
owned endpoint/source before release; never match None against a newly
table-backed target at the same fd. A dup pins the host endpoint but changes
the numeric descriptor, while kqueue registration identity still uses the
original fd. Therefore a blanket claim that dup alone protects rebind against
arbitrary embedder close/dup2 of process stdio would be false. Either retain an
owned registration source in that bare interest through ADD/DEL, or explicitly
prove the inherited process descriptors remain stable for the run. This corner
cannot be solved by converting missing identity into numeric equality.

Make the epilogue consume the staged receipt exactly once when present;
otherwise use ordinary rearm. An explicit receipt state can distinguish
`not staged` from `staged, no matching interests`, so empty-watch writes still
avoid the consumed table. Do not use a global skip flag: it obscures whether
rearm was performed. Do not reacquire functional table use with P held. Lazy
pruning is unnecessary for receipt application because it has exact owner Arcs;
leave table-set maintenance to normal close or the ordinary epilogue.

### Decisive regressions

1. Positive scalar stdio write with no epoll watchers returns without rereading
   consumed file authority; live watcher clears exactly once.
2. While blocked, close/reuse guest target fd and epoll fd; old completion must
   never mutate replacement interests. Keep a dup to old description and prove
   its surviving registration receives the correct consumption change.
3. Concurrent DEL/ADD and MOD preserve new registration generation/events/data;
   concurrent unrelated duplicate registration remains in the host union.
4. EAGAIN sets backpressure without manufacturing a positive OUT consumption;
   error-before-progress leaves positive-consumption latch unchanged.
5. Private-table retirement/MM replacement still completes, proving receipt
   preparation did not reintroduce table functional use or held mutexes.
6. BSD host-rebind path and Linux software-latch path both execute; a Linux-only
   receipt test cannot catch the nested BSD table lookups described above.

This is an ownership correction to the scalar seam, not permission to stage
all read/write syscalls indiscriminately or to skip epoll rearm.
