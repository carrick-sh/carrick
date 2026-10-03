# EL1 migration step 4: names, metadata and host-file pages

Design pass, 2026-10-02. Source inspected: `4c4d06b4c345550da68b4b8cd44dfd8f6e53457b`.
This is an implementation brief, not an implementation or acceptance receipt.
The owner has approved the migration direction. The design of record is
[the EL1 kernel spec](../specs/2026-09-24-el1-kernel.md), including its complete
as-built history. This plan follows its single-owner deletion requirement.

## Outcome and boundaries

EL1 owns the Linux pathname walk, dentry/stat observations, and cached regular
host-file bytes. The host remains authoritative for the physical namespace,
containment, host resource rights and actual file I/O. Namespace mutations are
one contained request each; cache hits do not become permission to skip host
validation of an operation. Reads/writes wholly within valid resident pages
have no host exit. Misses, revalidation and write-back use asynchronous host
requests, releasing guest execution capacity. They never recall ownership.

Stage 2a is milestone 0 and must land before any step-4 ownership cutover.
The [census](../../perf-results/2026-09-24-el1-census.md) reports host CPU costs,
not latency promises: rename 260 µs, unlink 128.3 µs, openat 49.5 µs. Moving
name resolution cannot repair an expensive host namespace primitive.

| Object | Sole owner after this step | Host responsibility |
| --- | --- | --- |
| Mount routing, cwd/root/dirfd walk, symlink budget, Linux access decisions | EL1 personality, shared logic for other venues | Validate containment independently; never trust a guest path string |
| Positive/negative dentries, directory topology, inode metadata, resolution dependencies | EL1 cache authority scoped by backing cohort and namespace view | Return authenticated identity/metadata observations and mutation outcomes |
| Cohort identity and source admission | Carrier admission registry; EL1 consumes exact issued identities | Pin source inode; maintain carrier-local admission, not process-global numeric matching |
| Regular-file cache pages, validity, dirty ranges, EOF, write-back ordering | EL1 inode authority, shared across descriptions/processes observing that backing | Positional bytes and sync by owned handle; no Linux offset or second dirty map |
| Description offset/status, fd generation and lifetime | Step-3 description authority used by EL1 | Handle custody only; do not update a shadow host offset |
| Shared mappings exposed to external host writers | Existing host-backed stage-2 alias | Own mapping/bytes; EL1 owns stage-1 projection, not a copied shared page |
| Private file mappings | EL1 page-cache fill and private COW after first write | Supply bytes; frames granted/reclaimed in bulk |

Linux syscall flags, errno conversion, credentials and permission policy live
in the personality. Cache indexes, frame accounting and request transport are
substrate; they must not depend on `carrick-abi` or embed Linux numbers. Reuse
existing logic through a platform-neutral core; other backends execute that
same core in-process until their privileged venue exists. No duplicate cache
implementation may survive as an off-lane compatibility path.

## Grounded inventory and removal boundaries

These are existing symbols, not proposed APIs. New protocols below are design
obligations; their spelling/layout must be reviewed before implementation.

- `crates/carrick-vfs/src/fs_resolve_cache.rs`: `FsCacheCoherence` carries
  separate path, directory, marker and metadata generations.
  `BindCacheCohorts::admit` pins sources by host `(dev, ino)`.
  `ResolveCache::{get,put}` retains rewritten paths and `CoherenceStamp`
  dependencies; stamps are sampled before component reads. The map is local
  to an observer, validated by cohort generations (not a carrier-global path
  cache). Its 8192-entry overflow currently clears the entire map.
- `crates/carrick-vfs/src/vfs/dentry.rs`: `DentryCache::lookup_path`,
  `lookup_path_slow`, `fill_component`, `stat`, `get_or_refresh_inode`,
  `refresh_inode`, `readlink`, `fast_open`, `open_metadata_fd`,
  `get_or_open_dir_fd`; positive/negative entries, inode records, pinned
  directories and bounded eviction. Mutation publication uses
  `entry_created`, `entry_removed`, `entry_moved`, `entry_exchanged`,
  `inode_changed` and `invalidate_inode`. This combines cache logic with
  host descriptors and locks; moving the struct wholesale is not the design.
- `crates/carrick-vfs/src/fs_backend/host.rs`: `HostFsBackend::stat_cache`,
  `stat_cache_get_or_fill`, `stat_cache_active`, `evict_stat_cache_subtree`,
  `fast_real_stat`, `fast_lstat_contained` retain host metadata answers.
  Contained host directory handles are backend capability custody and may
  remain; cached Linux metadata answers may not.
- `crates/carrick-vfs/src/vfs/rootfs.rs`: `resolved_parent`,
  `rename_with_flags_and_publish`, `rename_with_flags_admitted_info`, VFS
  `unlink`/`rename` implement physical/layered mutations.
  `vfs/namespace_mutation.rs::NamespaceMutationCoordinator::with_parents`
  and `with_archive` span anchored operation and publication. Retain host
  containment, physical whiteouts/copy-up and archive transactions; replace
  their guest-cache publication with completion records. Do not delete the
  physical operation merely because its Linux decision moves.
- `vfs/bind.rs::BindVfs::{lookup,lookup_nofollow,real_stat}` reads host
  metadata per call, rather than sharing the rootfs dentry cache. Bind routing
  bypasses that cache. `BindVfs::to_host` and mutation methods remain contained
  backend operations, not an alternative Linux walk.
- `crates/carrick-kernel/src/dispatch/fs/pathres.rs`:
  `resolve_at_path`, `resolve_dotdot_symlink_aware`,
  `resolve_intermediate_symlinks`, `canonicalize_following`,
  `canonicalize_following_allow_missing`, `check_search_access`,
  `check_directory_search_access`, layered metadata/readlink helpers and
  bind-dependency observation. `fs/state.rs::FsState::resolve_cache` and
  `fork_clone` create the current observer cache.
- `dispatch/fs/lookup.rs::FsView::lookup_path` chooses trusted-dirfd,
  dentry, stat-cache and immutable-lower fast paths, handles synthetic names,
  trailing slash and empty-path semantics. `fs/open.rs` contains
  `open_at_path_string`, `try_dentry_fast_open`, `try_trusted_dirfd_openat`,
  `try_immutable_lower_absolute_open` and the `openat2_*` walk helpers.
  `fs/stat.rs` has `path_stat_record`, `try_trusted_dirfd_stat`, `newfstatat`
  and `statx`; `fs/directory.rs::do_renameat` and `unlinkat` resolve and
  publish host mutations. `dispatch/fs.rs::rename_open_paths` updates recorded
  names. These become clients/projections of one walk, not parallel walkers.
- File zone: `crates/carrick-kernel/src/el1_delegation.rs` owns `OWNERS`,
  `OwnerState`, `delegate_transaction`, `join_transaction`, `recall_inode`,
  `recall_binding`, `recall_path`, `recall_all_delegated`, `sync_owner`,
  `write_back_inode` and `write_back_target`. Admission is once at open;
  mapped, watched and unsupported-flag files can be refused. Cache slots are
  whole-file bounded. `dispatch/fs/open.rs::enter_zone_at_open` starts it;
  `fs/rw.rs` read/pread/write/pwrite branches fall through recalling accessors.
  `carrick-el1/src/file.rs::ZoneFile`, `read_with`, `pread64_with`,
  `store_at` and write helpers use `DelegatedFile`/`DelegatedOpenFile`;
  `personality/file.rs` supplies Linux results. Preserve guarded user-copy
  mechanics while replacing whole-file storage and recall semantics.
- `dispatch/fs/state.rs::HostSparseExtentsRegistry` and
  `record_host_sparse_write` track sparse writes. Move guest extent decisions
  with cache writes; retain physical backend hole queries where needed.
  `dispatch/mem/mmap.rs` already has live host page-cache aliases; do not
  silently replace them with copied pages.

## Coherence protocol and external writers

Keep `kernel.fs.cache-cohort` semantics: independent rootfs cohorts do not
invalidate each other; admitted bind aliases observe the same source; nested
walks stamp only consulted authorities. Carrier-local source admission is not
cross-carrier coherence. Host self-reexec starts fresh admission. Do not infer
identity from fd, pathname, tid or inode number alone: include cohort/source
incarnation, live host handle and exact namespace view. Pin an unlinked open
inode until its final description/mapping/request retires.

An asynchronous namespace completion carries the request incarnation, pinned
parent/leaf identities, resulting metadata and an explicit outcome (including
same-inode rename no-op). EL1 publishes a coherent invalidation/update before
waking the caller. Failed requests publish nothing; canceled request storage
cannot be reused until completion is settled. Renamed cwd/dirfds follow pinned
directory identity; a path string is not that authority.

External host writers do not publish `FsCacheCoherence`. Revalidate on open,
explicit sync boundaries, and an EL1 timer-driven bounded cadence for active
cached objects. Proposed freshness bound: 10 ms, measured in guest clock time;
this is a new policy requiring signed visibility tests and director review,
not an existing API or Linux instantaneous-coherence guarantee. An expired
entry is unusable until validation completes; a descheduled vCPU cannot serve
an overdue entry. Schedule validation only for active objects, coalesce
waiters, and use normal request completion wakes rather than host polling.

Compare handle identity, size, high-resolution mtime/ctime and available host
change generation. Directory/name dependencies need validation too: replacing
an intermediate symlink, creating a negative name and replacing a path's inode
must invalidate the walk. Watch notifications accelerate invalidation but are
not proof of freshness; overflow or lost coverage expires affected leases.
Equal-size rewrites and restored mtime must be covered. If the backend cannot
supply a trustworthy change token, stat alone is insufficient: validate bytes
for the requested clean range on lease renewal, or use live host alias backing.
Never invent a universally reliable host generation counter.

Dirty bytes require range ownership and write sequence numbers, not a dirty
page bit that overwrites externally changed neighboring bytes. Write-back
sends only modified byte ranges. Completion clears only the acknowledged
sequence; partial writes retain the remaining range and errors. Cache size is
not permission to `ftruncate` a host file after an unrelated external extend.
Explicit guest truncate is a serialized operation; stale fills cannot resurrect
its old EOF. Same-range simultaneous uncoordinated host/guest writes have no
atomic conflict-resolution promise; establish allowed ordering with the oracle.
Non-overlapping external writes and external extension must survive write-back.
An external truncate invalidates clean beyond-EOF pages and orders dirty writes
according to actual operations, never an old whole-file snapshot.

Bounded freshness is weaker than Linux's common immediate same-file visibility.
The spec explicitly permits bounded revalidation, but its precise external
visibility contract must be registered and disclosed. A witness requiring
immediate external visibility uses host-backed live aliases rather than a
stale copied cache. Sol must resolve this capability split before milestone 3;
do not close it with mtime-only checks or rename it a known gap.

## Milestones and one-owner cutovers

Every milestone uses acceptance bundle A below, including all three paired
rows and all three per-op workloads. Each lands independently with an as-built
receipt and deletion inventory. Proposed contract IDs are marked **new**;
register them red-first rather than claiming they already exist.

An exact `=0` hatch is for transient bisection only. During development it
selects the venue before admission and must disable mapping/publication as
well as service. It cannot let host and EL1 mutate an admitted object together.
At proof, remove the hatch and old implementation in the same milestone's
final landing. Old-artifact comparison remains available afterward; no runtime
fallback to a retired owner. Errors, resource pressure and unsupported I/O
shapes still use the same authority and a backend request.

### 0. Stage 2a: bounded host namespace primitives (Sol) — LANDED `f1681c228` (2026-10-02)

Landed with the full `just el1-gate` green; census and before/after tables in
`docs/perf-results/2026-10-02-stage2a-scoped-census-red.md`. The text below is
the original milestone brief.

Entry: current namespace work contract and a fresh contained-parent census.
Extend `kernel.vfs.host-namespace-mutation-work` with signed binding and
openat work; its current descriptor covers rename/unlink, VM-free only, with
`host_backend_calls <= 8*n` at 1/8/32/128 and zero warm parent host opens.
Red first: two live processes repeatedly mutate the same and unrelated parents,
rename hardlinks (no-op), NOREPLACE, exchange, lower-layer copy-up/whiteout,
archive rollback, unlink-open and directory rename. Count exact host calls and
path visits; varying unrelated namespace population must not change the slope.
Open requires a real backend operation, not a cached fd masquerading as open.

Delete repeated parent reopen/whole-path walks from admitted operations in
`fs_backend/host.rs` and `vfs/rootfs.rs`, redundant resolution around
`NamespaceMutationCoordinator::with_parents`, and any superseded trusted lane
introduced to bypass them. Keep one contained primitive per operation and
its transaction through physical publication; no cache ownership moves yet.
The exact deletion sites must be identified by the red census, not guessed
from the September µs numbers. This is a bounded prerequisite goal for Sol,
not a precise Flash patch list. No new step-4 hatch; any stage-2a bisection
hatch follows the policy above and is removed at proof.
Acceptance: A plus namespace structural binding and before/after per-call
CPU census, pinned native Linux oracle and direct native macOS I/O control.
Do not equate the existing VM-free contract with stage-2a acceptance.

### 1. Single cache core and request boundary, host venue first (Sol)

Extract the existing cache/walk state into shared platform-neutral logic;
initially execute it in the host venue. Replace callers atomically by object
family. Establish authenticated namespace/file-bytes request/completion layouts
in the existing EL1 ABI, with layout-hash update, quotas and exact generations.
Host handles stay opaque; ABI storage contains no host pointers or locks.
This is independently landable without enabling a second EL1 owner.

Red first: extend `kernel.fs.cache-cohort`; **new**
`kernel.el1.names-authority` covers equal numeric identities in two live kernels,
shared bind sources, independent roots, stale completion after mount/handle
reuse, failed publication, two processes changing cwd/dirfd, nested bind
symlink dependency and fork observer inheritance. At 1/8/128 active names,
require work proportional to queried components/dependencies, zero unrelated
cohort host opens, bounded eviction work, and no clear-all rewarming cliff.
VM-free core proves transitions; signed bindings prove storage/transport.

Delete the old `ResolveCache` map/get/put implementation and its `FsState`
construction/fork copy, replacing it with the one core observer. Replace
`DentryCache` cache containers, walk/inode-refresh/eviction and mutation logic
with the core; remove `HostFsBackend::stat_cache` and its fill/eviction/enable
policy after all callers use that core. Host descriptor adapters remain.
Do not retain both old/new maps during the final landing. Source registry
admission and generation words survive as issued backing authority, not a
second metadata owner. No behavior hatch needed for byte-equivalent extraction;
any ABI venue hatch follows the common policy. Acceptance: A and cohort suite.

### 2. EL1 owns names and metadata (Sol; bounded tests can use Flash)

Move that same core instance into retained EL1-visible storage and make EL1
its only writer on HVF. Linux path clients use it for all paths, including
synthetic mounts, permission checks, openat2, x86 host venue and exec readers.
Warm valid stat/readlink and component walks exit zero times. Open still makes
one contained namespace request; mutations make one request each. Cache
misses scale with missing components, not unrelated cached population.

Red first: `kernel.el1.names-authority` signed two-live-process tests and
**new** `kernel.el1.names-revalidation`: absolute/relative symlinks, `..`,
trailing slash, empty path/AT_EMPTY_PATH, ELOOP, openat2 containment flags,
mount boundaries, credentials/search access, renamed pinned cwd, unlink-open,
failed rename, same-inode no-op, exchange and NOREPLACE. Host writer changes
an intermediate symlink and creates/removes a negative name while both guests
stay alive; synchronize against the declared lease deadline, not sleeps/retries.
Measure 1/8/128 components and warm repeats; no host namespace population scan.

Delete host Linux walkers in `fs/pathres.rs` named in the inventory; delete
`FsView::lookup_path` fast-path selection, `try_dentry_fast_open`,
`try_trusted_dirfd_openat`, `try_immutable_lower_absolute_open`,
`try_trusted_dirfd_stat` and host `openat2_*` walk decisions. Replace syscall
wrappers with clients of the same personality/core; remove host guest-cache
updates in `do_renameat`, `unlinkat`, `rename_open_paths` and rootfs/bind
publication callbacks. Retain contained namespace and physical layer operations.
Temporary proposed `CARRICK_EL1_NAMES=0` selects the host venue of the SAME
core before objects exist; remove it and host venue adapters on HVF at proof.
Acceptance: A plus namespace/path probes on both libc variants.

### 3. General page-cache owner; retire the whole-file zone (Sol)

Cut over regular host-file byte authority as one family. Use page/range entries,
not fixed whole-file admission; bring read/write/pread/pwrite and vectored I/O,
seek/size, truncation, append, sync/direct I/O and transfer clients through the
one inode authority. Direct/synchronous requests may cross for every operation
but cannot bypass cache ordering. Watchers, locks, seccomp/observers, rlimits
and EFAULT remain Linux personality decisions; they cannot trigger recall.

Red first: extend `kernel.el1.files.shared-inode` and existing `el1-files`,
`el1-files-path-mutation`, `el1-files-cross-process-readers` descriptors;
**new** `kernel.el1.host-pages` covers two live processes with separate opens,
dup/fork-shared offsets, shared bind aliases and independent equal-key roots.
Test partial user copies, sparse holes, >whole-file-slot size, EOF/truncate,
append against an external writer, missed notification, short/failed write-back,
fsync error persistence, write during in-flight flush and canceled waiter.
Resident valid-page read/write has exactly zero file-bytes requests and zero
host service exits. At 1/8/128 pages, fill work scales with missing pages and
flush work with dirty ranges; untouched file length/population adds no work.
Two external writers alter disjoint bytes in one page, restore mtime, extend
and truncate; no dirty-range loss or unrequested truncate is acceptable.

Delete `OWNERS`/`OwnerState` delegate/join/recall ownership machinery,
`delegate_transaction`, `join_transaction`, all `recall_*` entry points,
`sync_owner`, `write_back_inode`/`write_back_target` and whole-file slot
allocation in `el1_delegation.rs` AFTER clients use the new authority. Do not
delete unrelated scheduler/inotify boundary functions in that module.
Delete `open.rs::enter_zone_at_open`, delegation refusal/once-only admission,
regular-host-file direct/recalling paths in `rw.rs::write_host_file`, read,
pread64, pwrite64, write and vectored variants. Replace `ZoneFile` whole-file
backing and `DelegatedFile`/`DelegatedOpenFile` usages in EL1 file service;
retain guarded user copy. Move sparse extent ownership out of host `FsState`.
Close/fsync/stat/notify/transfer clients must stop invoking recall before
removing the functions; grep all callers, not just `rw.rs`.
Temporary proposed `CARRICK_EL1_HOST_PAGES=0` selects the pre-cutover artifact
behavior only in development; no mixed old/new inode admission. Remove old
zone and hatch together at proof. Acceptance: A, byte/coherence differential,
file/inotify gates and exact zero hit-exit witness.

### 4. Mapping, loader and retirement closure (Sol; mechanical audit to Flash)

Private file mapping fill and exec file-byte readers use the page-cache owner;
shared mappings keep their host-backed stage-2 aliases and route ordinary I/O
through those live bytes. One inode backing mode is selected under admission;
mode transition drains requests, flushes dirty ranges and revokes old pages
before mapping publication. There is never a private dirty cache beside a live
shared alias. Private COW pages stop following external writers once copied.

Red first: **new** `kernel.el1.host-pages-mapping` with two live processes:
read/write vs shared mmap and external host mapping, truncate/SIGBUS, private
COW isolation across fork, exec during miss/write-back, unlink-open mapping,
final-close with outstanding request, frame pressure, and failed stage-2
publication rollback. Page-cache retention is charged once per inode; return
free frame extents promptly under pressure. At 1/8/128 pages bound backing
allocation by simultaneously live pages, never historical reads or fork count.
Quotas refuse before backend work; no deadlock when default execution capacity
is exhausted by misses. Completion wakes precisely the waiting generation.

Delete eager private host-file snapshot/fill decisions in
`dispatch/mem/mmap.rs` replaced by EL1 fills; retain live shared alias platform
operations. Delete host Linux path walks in `dispatch/fs.rs::exec_symlink_resolved`
and byte-cache ownership in `read_exec_file_head`/`read_exec_file_head_at`;
retain bootstrap image reading before an EL1 instance exists as platform input,
not a guest-side second resolver. Delete remaining host byte/offset authority
in close/sync/transfer paths, leaving opaque handle lifetime adapters. The
milestone's audit must enumerate residual callers and classify each as physical
backend or same-core venue; unexplained host ownership blocks landing.
No new mapping hatch: use old-artifact bisection, or remove a temporary exact-zero
venue hatch at proof as above. Acceptance: A plus signed mapping/loader tests,
clean-tree authority inventory and personality-boundary gates.

## Acceptance bundle A (mandatory for milestones 0–4)

These are future implementation commands, not checks run for this doc pass.
Use repository root, fresh Linux fixtures and both libc probe executables.
Record source HEAD, SHA-256, CDHash, LC_UUID, entitlement and DOF for each
executable, immutable image digests, run IDs, raw streams, verdict populations
and scoped cleanup. A signed test executable is a different artifact from CLI.
Do not rebuild/re-sign a CLI during its promotion or timing campaign.

```sh
CARGO_BUILD_JOBS=3 just test-kernel
CARGO_BUILD_JOBS=3 just ci
CARGO_BUILD_JOBS=3 ./scripts/build-linux-fixtures.sh
CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=step4-M-el1 ./scripts/test-signed.sh carrick-embed el1_ --nocapture
CARGO_BUILD_JOBS=3 just el1-gate
# Keep the CLI artifact produced by el1-gate for promotion.
just --no-deps conformance smoke
just --no-deps conformance full
```

Replace `M` with milestone number and make run IDs unique per invocation.
`el1-gate` includes the signed suite, probes, file/inotify LTP rows and current
EL1 on/off inotify09 screen. Its recipe currently still uses `CARRICK_EL1=0`;
when this global hatch is retired, update that screen to a recorded prior
artifact comparison, not a resurrected host implementation. Source-hash checks
alone do not prove probe executable freshness. Missing bindings or fixtures
fail acceptance. Register new probes in `carrick-conformance-next`.

For paired **previous-main versus candidate** workloads, preserve separately
signed artifacts in separate worktrees. Run the existing conformance harness
command below for each pair, changing only artifact and run ID. Execute ABBA
(base/candidate/candidate/base), three fixed quads per row after one excluded
warm-up per artifact; retain wall and carrier user+sys CPU, image/argv identity,
host-load context and all failures. Repeat for all three suite names. This is
a fixed measurement schedule, not retry-until-green.

```sh
CARRICK_RUN_ID=step4-M-base-go-A1 cargo run -q -p carrick-conformance -- --tier full --suite go-build --carrick-bin /absolute/base/carrick --jsonl target/step4-M/base-go-A1.jsonl
CARRICK_RUN_ID=step4-M-new-go-B1 cargo run -q -p carrick-conformance -- --tier full --suite go-build --carrick-bin /absolute/candidate/carrick --jsonl target/step4-M/new-go-B1.jsonl
CARRICK_RUN_ID=step4-M-new-go-B2 cargo run -q -p carrick-conformance -- --tier full --suite go-build --carrick-bin /absolute/candidate/carrick --jsonl target/step4-M/new-go-B2.jsonl
CARRICK_RUN_ID=step4-M-base-go-A2 cargo run -q -p carrick-conformance -- --tier full --suite go-build --carrick-bin /absolute/base/carrick --jsonl target/step4-M/base-go-A2.jsonl
# Same four-command schedule for --suite cpython-threading and
# --suite cpython-subprocess, with distinct output paths/run IDs.
```

Precompile the harness before timing. Use existing exact suite declarations,
not improvised guest commands. Cached oracle output can serve semantics only
with valid identity; refresh Docker deliberately in a separate phase. The
existing `scripts/perf/el1_workload_ab.py carrick` compares two environment
arms on ONE binary; it is useful during bisection, but is not a previous-main
binary comparison and must not be represented as one.

The xtask per-op campaign is also required at each milestone. Build the
fork-exec fixture first, as documented in [impact receipts](../../impact-receipts.md):

```sh
(cd conformance-probes && CARGO_BUILD_JOBS=3 cargo build --locked --release --target aarch64-unknown-linux-musl --bin perf_fork_exec)
CARGO_BUILD_JOBS=3 just xtask impact carrick --artifact /absolute/base/carrick --workload spawn-loop --workload thread-spawn --workload fork-exec --out target/step4-M/impact-base.json
CARGO_BUILD_JOBS=3 just xtask impact carrick --artifact /absolute/candidate/carrick --workload spawn-loop --workload thread-spawn --workload fork-exec --out target/step4-M/impact-candidate.json
# Director phase, after all Carrick guests have stopped:
CARGO_BUILD_JOBS=3 just xtask impact docker --workload spawn-loop --workload thread-spawn --workload fork-exec --out target/step4-M/impact-docker.json
just xtask impact report --base target/step4-M/impact-base.json --candidate target/step4-M/impact-candidate.json --docker target/step4-M/impact-docker.json --out target/step4-M/impact-report.md
```

Use default operation counts and ten samples with excluded warm-up, immutable
identical declarations and fixtures; do not use the five-operation plumbing
receipt as acceptance. Impact reports are observational and exit zero even
for INCOMPLETE/WARNING: director must inspect completeness, per-op medians,
raw ranges and ratios. Docker client CPU is not container CPU. Objective is
≤2x native-arm64 Docker per-op; candidate >1.15x base is an explicit warning,
not an automatic acceptance. At ≥10x return to correctness triage immediately.
Report temporary migration regressions as the spec allows; no suppressed
failures, looser budgets, deadline inflation or lower concurrency.

Run VM-free semantic/work reds first, then signed structural bindings, then
uninstrumented timings. Capture a scoped census before/after for each milestone
and distinguish namespace/file-bytes requests from scheduler and memory exits.
No request-count improvement proves CPU savings. A green bundle and reviewed
host deletion inventory are required for acceptance; a diagnostic receipt is
never promoted by changing its label.

## Dependencies and sequencing

1. Stage 2a must have its own signed/per-call evidence before milestone 1.
   Milestone 0 is a prerequisite goal, not permission to change it during this
   design-only task.
2. Step 2 frame-grant/reclaim, stage-1 publication, exact owner generations,
   COW and mapping rollback are prerequisites for EL1 cache storage/private
   fills. No new fixed VM RAM reservation or per-mm whole-file pool.
3. Step 3 fd tables/open descriptions, IPC waits, signals, rlimits, observers
   and request lifetime must expose one authority to cache clients. Names
   cannot use a second fd map while descriptors are migrating.
4. Read the latest lifecycle integration before implementation. The
   [thread plan](2026-09-30-el1-thread-lifecycle.md) is design history;
   [the investigation](../../perf-results/2026-10-01-el1-forkexit-investigation.md)
   ends with Phase A setup serving, exit still forwarded, Phase B settlement,
   admission closure and exact teardown unfinished. Its final EL1 batch is
   74 passes and six failures, not green acceptance. Step 4 must not bypass
   that gate. Shared ABI backing must be retained/pinned with exact release;
   the 128-slot metadata aperture and 512 KiB slab lessons apply to caches.
5. Lifecycle settlement must precede context resolution/membership reads.
   Fork/exec admission closes before conflicting authority; cache request
   retention participates in those drains. Step 5 moves fork/exec execution,
   while this step supplies names/pages without trying to own lifecycle too.
6. fscohort stays authoritative until its single core cutover. Carrier bind
   admission is reused; external coherence cannot be inferred from its
   carrier-local registry. Coordinate namespace-generation layout with the
   owner of fscohort rather than adding an EL1 shadow counter.
7. Inventory reconciliation belongs to clean implementation checkpoints and
   clean post-merge source. Off-host compiler profiles remain explicit pending
   work where tooling reports them; macOS success is not universal coverage.

## Risks and implementer allocation

- External coherence is the largest semantic decision: coarse timestamps and
  lossy host watches cannot validate unchanged bytes. Shared mappings and
  cache dirty ranges must not form two byte owners. Sol owns capability and
  freshness policy review, with native Linux differential witnesses.
- Namespace containment is a host validation obligation even after EL1 resolves
  names. Parent rename, symlink substitution, mount teardown and reused handles
  require exact identity and rollback, not trusting cached host paths.
- Error semantics cross asynchronous boundaries: short I/O, interrupted wait,
  partial user-copy and fsync error sequencing need owned progress. Replaying
  from byte zero or clearing dirty state before acknowledgement corrupts data.
- Cache memory pressure must release frames elastically without holding a
  lock across host completion or parking vCPU workers. Persistent miss/write-back
  waiters cannot exhaust execution capacity needed for completions.
- Private mappings, shared aliases, page sizes and EOF/SIGBUS require memory
  owner review; a page-cache port must not casually alter stage-2 topology.
- No expected performance win is asserted from the old census. Namespace work
  remains host-native; host noise and startup dominate short ecosystem rows.

Milestones 0–4 are **Sol-led**: each changes ownership or a protocol, and none
is precise enough to hand wholesale to Gemini Flash. Flash can implement
bounded pieces after Sol freezes the contracts/layout/deletion manifest:
fixture matrices and deterministic budgets in 1–3, ABI layout checks for 1,
mechanical same-core callsite rewiring for 2, and residual symbol/caller audit
and documented deletions in 4. It must not decide revalidation policy, invent
handle authority, modify memory/lifecycle ownership, or relax acceptance.
These are allocation recommendations, not delegation performed by this pass.

## Completion of this design task

Only this plan is written and committed. No implementation tests or guests
are run for a documentation-only design. Verify formatting/diff and path/symbol
references; preserve unrelated worktree changes. Implementation acceptance,
policy confirmation and runtime evidence above remain future work.
