# K1 total-goal session handoff

**Status:** K1 remains RED and the active goal is paused at a safe committed
boundary. **Re-baselined 2026-08-12** — see "Phase re-baseline".
**Updated 2026-08-13** — see "2026-08-13 session" below; the three
observability deliverables are now GREEN and the K1 blocker has changed.

## 2026-08-13 session

Committed HEAD is now `cf5fc732b`. Evidence document:
[`docs/perf-results/2026-08-13-hvpatch-k1-observability-evidence.md`](../../perf-results/2026-08-13-hvpatch-k1-observability-evidence.md),
which records **NO-GO** for K1 with full provenance.

**Now GREEN, all live-verified on the signed binary (not tests alone):**

- **#26 live debug protocol** — `carrick debug hvpatch-kernel --run-id <id>
  [--table ...]` reads one coherent snapshot from a running guest over a
  per-run uid-authenticated `AF_UNIX` socket. Returned 12,667 bytes of
  validated canonical JSON against a live `ubuntu:24.04 /bin/sleep`.
- **#25 coherent file snapshots** — proven by that same live capture. The
  Kernel `FileTable` is already the production authority (`IoState` is
  gone). `RuntimeIo` is deliberately excluded: it is process-local output
  transport with no guest-visible Linux semantics.
- **#27 typed lifecycle identity** — records carry `task_serial`,
  `parent_serial` and `mm`; new `hvpatch-guest-lifecycle-identity` USDT
  companion probe; `hvpatch-k1-lifecycle.d` at protocol version 2; the
  strict reader rejects a zero/duplicate serial and an exec naming an
  unborn serial.

**The K1 blocker has MOVED.** It is no longer the four deliverables — it is
that the `68 fork / 67 exec / 69 process` receipt **cannot be produced on
any commit tested**. A cold `go build` under `--exec-backend hvpatch` fails
identically on a signed binary built from `25f67f1fa`, so this predates the
observability work. Attributed, not assumed.

- Layer 1, **FIXED** (`ce369be39`): `handle_in_process_fork` installed the
  child pidfd through the ambient `captured_file_table()`, which has nothing
  installed on the vCPU-loop thread and therefore called
  `std::process::abort()`. Any `CLONE_PIDFD` fork killed the runtime.
- Layer 2, **RED, next task**: with the abort gone the run reports
  `kernel context revision is stale` (fork reservation returns `EAGAIN`)
  and then `kernel context is foreign or internally inconsistent` (child
  exec). This is the fork/exec transaction contract — K3/K4 territory.

Simple fork/exec guests are fine; the defect needs Go's concurrent
`CLONE_PIDFD` fork/exec pattern.

**Two incidental correctness fixes**, both found by the new protocol on its
first live use against a guest:

- `b72d11142` — `close(2)` never retired the descriptor's `fd_open_paths`
  entry on most close paths, so a freed fd number kept claiming a filename
  for the lifetime of the table. Fixed at the `note_fd_closed` funnel with a
  red-first test.
- `3db419d5e` — `validate_snapshot` ran *before* every revision check, so a
  concurrent mutation was reported as `InvariantViolation`, i.e. a healthy
  run was called corrupt. Revisions and the registry epoch are now verified
  first.

**Recorded design correction.** The spec's
`$TMPDIR/carrick-kernel/<uid>/<sha256>/snapshot.sock` is not bindable on
macOS: 146 bytes against a 104-byte `sun_path`. Shipped a fixed
`/tmp/carrick-kernel` base and a 32-hex token (70 bytes), with an over-long
path refused by name. Isolation is unchanged.

**Housekeeping.** ~280 orphaned processes were cleaned: 192 from this tree's
`target/debug/carrick`, 26 from the stale
`/private/tmp/carrick-k1-file-authority-cutover` tree, plus test children
and 5-hour-old guest leftovers. Several were 5–7 hours old and may have
perturbed earlier measurements. Kill by **exact absolute binary path**,
never a bare `pkill -f carrick`.

**Dropped uncommitted work.** The tree carried an uncommitted K3 #41 test,
`host_fork_descendants_receive_collision_free_client_identities`, which did
not compile — it calls `FileAuthorityRun::reserve_host_fork_child`, which
does not exist. It was removed so the tree could be gated. Its intent is
already recorded below as red test 2 ("Parent and host-fork descendants
receive collision-free identities"); rewrite it with the API when the K3
file slice is built.

**Next single task — now diagnosed, needs the fix.** Concurrent sibling
forks cannot both succeed. `PublishedFork::commit` bumps the **parent's**
task revision because committing a child calls `add_child`
(`operations.rs:623`, `:634`), and `reserve_fork` refuses any caller whose
captured `parent.revision` no longer matches the registry record
(`operations.rs:1097`). Thread A's fork therefore invalidates thread B's
in-flight fork, and the guest gets `EAGAIN`. Go forks concurrently from
several threads, which is exactly the observed
`fork/exec .../compile: resource temporarily unavailable`. Linux requires
both to succeed, so this is a semantic defect, not load.

Relaxing only the reserve-time check moves the failure to commit: for
`ForkParentMode::Caller` the reservation records
`child_parent_revision = caller_revision` and commit re-checks it
(`ForkParentChanged`).

**UPDATE — layer 2 is FIXED in `f4cdea7a6`.** `KernelContext` now captures
`parent_at_capture` and `reserve_fork` compares the parent association
instead of the task revision, so concurrent sibling forks commit while
reparenting stays detected. The cold `go build` no longer reports
stale/foreign contexts or `EAGAIN` and now runs dozens of compile
processes.

**Layer 3, the current blocker:** Go's `.a` archives are missing their
leading `!<arch>\n` — the reader finds an `ar` member header where the
8-byte magic belongs ("not the start of an archive file"). Two hypotheses
are already **refuted** on the signed binary, so do not retest them: plain
write/read/`cp`/`cat` round-trips are byte-exact, and `lseek(SEEK_SET)` plus
`pwrite` are exact (magic, seek back to 8, rewrite, `pwrite` at 12 yields
`!<arch>\nBBBBCCCC` with the offset at 16), and it is not the file-backed
mmap lowering (`CARRICK_MMAP_FILE_BACKED=0` reproduces identically).
`GOCACHE` is run-scoped and cold, so a stale cache entry is excluded.

**Attack it as a CONCURRENCY problem, not a filesystem one.** The failure is
nondeterministic: an identical rerun did not corrupt any archive and instead
aborted with `sibling materialization start gate timed out`
(`vcpu_loop::threads`, `process_exiting=false clone_cancelled=false`, exit
134) before reaching the compile stage. Single-threaded write/seek/pwrite/
mmap paths are all proven exact, so the remaining suspects are racing
writers and mis-sequenced thread/fork start gates under this workload's
load. Sample repeatedly — with nondeterminism, one green or red run proves
nothing.

**Sampled failure distribution** (4 identical runs, current signed binary):
`archive-magic` 3, `start-gate-abort` 1, `BUILD_OK` 0. Archive corruption is
the dominant mode; attack it first.

**The archive defect is localised — this is the strongest lead.** Dumping the
build cache on disk after a failing run shows **9 archives written correctly
with `!<arch>\n`, and exactly ONE missing it**: a 95,486-byte entry whose
content begins at the `ar` member header `cpu.o`. So writing archives works;
one file in ten loses precisely its leading 8 bytes.

**CORRECTION — the "lost 8-byte write" reading is WRONG.** A commit earlier
in this session (`7a19fed1e`) inferred that a standalone
`write(fd, "!<arch>\n", 8)` was reported successful but never landed. The
runtime's own `trace-io` instrument disproves it: build with
`just build --features trace-io` and the guest **never issues an 8-byte
magic write at all**. Every write beginning with `21 3c 61 72 63 68 3e 0a`
is a larger buffered write — `n=68` (a stub archive: magic plus 60 zero
bytes), `n=7667`, `n=32768` — 67 of them in one build. Go buffers the magic
together with the following data.

So the corruption is a large write that begins with the magic losing
precisely its first 8 bytes, not a small write going missing. Do not spend
time on lost-small-write theories.

**Prime suspect: the build-cache COPY, not the compile.** Go stores an
archive in `GOCACHE` by copying the compiler's output, and 9 of 10 archives
land correctly — a per-file race, not a systematic offset error. That copy
reaches `copy_file_range` (canonical 285), which on macOS has a whole-file
fast path, `try_darwin_copyfile_range_fast_path` →
`darwin_fs::copyfile_clone_or_data` (`dispatch/fs/sendfile.rs`).

Its guards require `in_offset == 0`, both NULL guest offset pointers, an
empty destination, and `count >= input.size`, and it reads the two HOST fd
offsets with `lseek(SEEK_CUR)` before cloning. Those host offsets are shared
across forked guest processes, so the check looked like a TOCTOU against a
concurrent sibling.

**REFUTED — do not retest.** The fast path now has an exact ablation hatch,
`CARRICK_DARWIN_COPYFILE_FAST_PATH=0` (added because a fast path with no way
to turn it off cannot be attributed). Four ablated runs of the fixture still
produce a corrupt archive (`archive-magic` on run 1, then `start-gate-abort`
×2 and one other mode), so the Darwin `copyfile`/`fclonefileat` fast path is
**not** the cause. The hatch is retained: it is default-ON with an `=0`
escape, and it is the instrument for attributing any future
`copy_file_range` corruption.

Remaining suspects for the corrupt cache archive, none yet tested: the
generic `copy_file_range` read-then-write body (`sendfile_bytes` plus
`write_output_fd`) under concurrent siblings sharing a host file offset;
Go's cache writing via `os.Link`/rename rather than a copy at all; and a
short write reported as complete somewhere in that path.

**The start-gate abort is the other 1-in-4 mode; classify it before changing
it.** The start gate is a
**10-second wall-clock deadline that calls `std::process::abort()`**
(`vcpu_loop/threads.rs`, `ready_deadline = Instant::now() +
Duration::from_secs(10)`, polling `recv_timeout(1ms)`). It fired with
`process_exiting=false` and `clone_cancelled=false`, i.e. nothing was
shutting down, on a host that was simultaneously running builds and had
been carrying ~280 orphaned processes.

That makes it a candidate **time assumption** rather than a deadlock
detector — precisely the distinction this project's load-sensitivity rule
exists to force. Do not simply raise the bound: first determine whether the
child materializer is genuinely wedged (take a core and `bt all`, per the
debugging rules — `sample`/`SIGQUIT` have mislabelled fork-quiesce
deadlocks before) or merely slow under load. If it is a time assumption,
an arbitrary wall-clock abort in the thread-creation path is the wrong
mechanism and should be replaced by a progress-aware condition, the way the
trap watchdog already was.

The history below is retained because the rejected approach is instructive.

**The first fix attempt was WRONG — do not repeat it.** Dropping the
`caller_record.revision != parent.revision` check in `reserve_fork` (and the
matching `ForkParentChanged` check in commit, advancing from the current
revision as `PreparedThreadClone::commit` does) makes concurrent sibling
forks pass, but the suite catches two regressions:

- `stale_context_cannot_commit_a_fork` — a reused context must still be
  refused;
- `exiting_parent_reparents_live_and_zombie_children_to_root` — **a context
  captured before the task was REPARENTED must not fork**, or the child
  attaches to the wrong parent.

The revision is therefore load-bearing: it detects reparenting and
association changes, not merely "gained a child". One counter cannot
distinguish the benign advance (a sibling published a child) from the
dangerous one (this task's parent association changed), so the two cases
need separate signals.

Fix shape, restated: give the fork path a signal that distinguishes
"children set changed" from "parent association changed". The most direct
option is for `KernelContext` to carry the captured parent `TaskKey` so
`reserve_fork` can compare parent association exactly and stop leaning on
revision equality; a separate association revision would also work.
`PreparedThreadClone::commit` is the reference for the identity-checks-then-
advance-from-current pattern. **Write red tests for concurrent sibling forks
AND keep the two tests above green** — they encode real invariants. Then
re-run the go fixture for the 68/67/69 receipt and re-measure the cold
build, which has had no product-visible number since the ~4.27 CPU-s
reading of 2026-08-09.

The unit-level red test that proves the sibling bug is a two-fork sequence
from one captured context, which fails with `StaleContext`; note that it
does not perfectly model production, where each syscall captures a fresh
context and the race is capture → sibling commits → reserve.

**Reason for existence:** the next session must resume the complete K1 objective,
not mistake the immediate FileAuthority blocker for the goal itself. This is the
single continuity artifact for completed architecture, remaining gates, current
risks, execution order, and the next bounded milestone.

## Phase re-baseline (2026-08-12)

An earlier reading of this handoff's gate ledger put the complete FileAuthority
production cutover inside K1. Checked against `hybrid.md`, it is not K1 work:

- `hybrid.md` K1 introduces typed interfaces "while adapting the working one-VM
  prototype **behind** them," and its gate is model/property tests, exact
  cold-build output with 68/67/69, and `just ci`.
- `hybrid.md` K3 owns "fork/clone/vfork-compatible task creation on the new
  objects, **including file-description sharing**."
- `hybrid.md` K4's gate owns "multithreaded exec, **CLOEXEC**, signals,
  credentials … match Docker."

Task #41's own required contract spans both: prepared FileAuthority transitions
on fork/exit (K3) and "successful exec publishes CLOEXEC and successor table"
(K4). Three of the seven RED rows below are therefore K3 deliverables, and a
fourth (#25) was chained behind them without needing to be.

**Decision.** K1 GO does not require sole file/VFS authority, the 361 call-site
migration, or legacy file-state deletion. Those move to K3, tracked by
[`2026-08-12-per-run-file-authority-atomic-migration.md`](2026-08-12-per-run-file-authority-atomic-migration.md).
Coherent snapshots (#25) are unchained: a K1 snapshot joins whichever authority
currently owns file state, and the source moves when K3 moves the authority.
Task #41 remains the next milestone but is reclassified as the **first K3 file
slice** and no longer gates the K1 GO document. Recorded in the spec under
"Phase ownership of the file authority".

**Accepted risk.** The production FileAuthority root activates at real run
boundaries but owns no table — a live mechanism doing nothing, the shape this
project treats as abandoned. Accepted only as K3 staging. If the K3 file slice
does not proceed, delete the root rather than leave it dark.

## Total goal

Continue the kernel-first single-VM architecture in root-level `hybrid.md`.

**K1 GO now needs three deliverables**, all unblocked at HEAD:

- typed lifecycle/CTF events (#27) — inputs (frame inventory, lifecycle
  authority) are GREEN;
- live `carrick debug` protocol (#26) over coherent snapshots;
- final coherent snapshots (#25, unchained) and the durable K1 GO evidence
  document (#29), with exact cold-build output, 68 forks/67 execs/69 processes,
  `just ci`, and signed native/VMM/HVPatch receipts.

Already GREEN and retained: mandatory exact `KernelContext` dispatch; unified
HVPatch lifecycle authority and frame inventory; snapshot foundation;
credential, fs-context, and signal authorities; preserved Linux semantics and
native/VMM/HVPatch/KVM/bhyve/NVMM fallbacks.

**K3 (parallel correctness track, not the K1 critical path):** FileAuthority
lifecycle binding, the 361 semantic call sites, and legacy state deletion.

**K2 is the next phase after K1 GO** and is where `hybrid.md`'s goal lives — the
Phase-4 prototype's last measured cold build is ~4.27 CPU-s against a 2.3 CPU-s
gate, and K2's own gate ("fork work scales with writable table paths/touched
frames, not virtual span") is the mechanism that closes it. No performance claim
is required for K1.

## Resume coordinates

- Repository: `/Volumes/CaseSensitive/carrick`
- Branch: `main`
- Committed HEAD: `7b35fc591 fix(runtime): verify file authority activation`
- Goal ID: `3029e5b8-ff93-4e05-8f3b-daf5c38a0c19` (paused)
- Immediate task: `#41 Cut over file lifecycle` — reclassified 2026-08-12 as the
  first K3 file slice; it is the next milestone but no longer a K1 gate
- Controlling K1 spec:
  [`docs/superpowers/specs/2026-08-09-hvpatch-k1-kernel-object-model.md`](../specs/2026-08-09-hvpatch-k1-kernel-object-model.md)
- FileAuthority plan:
  [`2026-08-12-per-run-file-authority-atomic-migration.md`](2026-08-12-per-run-file-authority-atomic-migration.md)
- Signal plan:
  [`2026-08-12-kernel-signal-authority-atomic-migration.md`](2026-08-12-kernel-signal-authority-atomic-migration.md)
- User decision: mandatory `KernelContext` uses the **full Kernel transaction
  cutover**. Lifecycle publication cannot be a dispatcher/backend post-hook.
- User decision 2026-08-12: re-baseline the K1/K3 boundary against `hybrid.md`
  rather than re-litigating it per session; then build #41. See "Phase
  re-baseline".
- `proposed-plan.md` is untracked user work. Never edit, delete, move, or add it.

Before this handoff was written, accidental formatting-only Rust edits were
restored. They reappeared and were restored again on 2026-08-12 in
`file_authority/root.rs` and `threaded_loop.rs` — both were pre-`style_edition
2024` reversions (import ordering, closure wrapping) that `cargo fmt --check` on
the pinned 1.96.0 toolchain rejects. This is toolchain skew from some other
environment, not authored work; `git checkout` it. Verify again at session
start; tracked dirt must be attributed before any implementation.

## K1 gate ledger

Do not quote a completion percentage. The red gates contain most of the
remaining semantic risk.

| K1 area | State | Verified meaning |
| --- | --- | --- |
| K0 memory/HAL qualification | GREEN | Signed decisive probes and durable K0 evidence exist. |
| Typed Kernel object graph | GREEN | Stable task/thread/mm/resource identities, transactions, rollback, generations, and start gates are committed. |
| Mandatory exact `KernelContext` | GREEN | Dispatch and lifecycle boundaries retain exact captured context; recapture is forbidden. |
| HVPatch lifecycle | GREEN | Fork/clone/exec/exit publication, unified finalization, authenticated lifecycle ledger, and strict profile are committed. |
| Frame inventory | GREEN | Sparse reservation/commit, fork/exec publication, retirement, and multi-vCPU qualification are committed. |
| Snapshot foundation | GREEN | Coherent owned snapshots include task/thread/mm, VMAs, frames, files, credentials, fs context, and signals with strict joins and draining generations. |
| Credential authority | GREEN | Kernel-owned credential identity and transforms are committed. |
| FsContext authority | GREEN | Kernel-owned cwd/chroot/umask sharing and transforms are committed. |
| Signal authority | GREEN | Kernel-owned sighand, task/thread pending queues, exact dequeue, exec transforms, and snapshot rows are committed. |
| FileAuthority model and IPC | GREEN as infrastructure | Direct/IPC equivalence covers bounded table/description/VFS/epoll/stream/mapping/io_uring/timer/signalfd state. |
| Production FileAuthority root | GREEN but dormant | One helper-backed root activates at real run boundaries and completes an authenticated empty-table request. |
| File lifecycle binding | RED — **K3** | No committed Kernel transaction binds FileAuthority fork/share/exec/exit/reexec. Task #41; the exec/CLOEXEC half is K4 contract. |
| Sole file/VFS authority | RED — **K3** | Zero of the 361 classified legacy production call sites have been migrated. |
| Legacy state deletion | RED — **K3** | `ThreadResources.files`, `OpenDescription`, writable VFS, epoll, splice, mapping/io_uring mirrors, reexec state, and host-fork rejection remain. |
| Final coherent file snapshots | RED — K1 | Snapshot foundation still reads legacy file state. Task #25 is **unchained** from the sole-authority cutover: it joins the current authority coherently and follows it when K3 moves it. |
| Live `carrick debug` protocol | RED — K1 | Task #26 depends on #25 only. |
| Typed K1 lifecycle/CTF events | RED — K1 | Task #27 is unblocked at HEAD; the authenticated ledger/profile foundation is GREEN. |
| Durable K1 GO evidence | RED — K1 | Task #29 needs debug, typed events, lifecycle counts, CI, and signed backend receipts. |

Measured surface of the K3 rows at HEAD, from the checked-in inventories: 361
classified call sites (161 `inspect_misc`, 62 `lifecycle`, 44 `create_install`,
34 `epoll_wait`, 19 `write_attempt`, 13 `read_attempt`, 12 `stream_transfer`, 9
`slot_description_mutation`, 7 `mapping_ring`); structural escapes
`write_open_files` 36, `read_open_files` 31, `Arc<FileTable>` 13,
`host_fork_file_authority_rejection` 7, `lock_splice_pushback` 6.

The K1 dependency chain after the re-baseline:

```text
frame inventory + lifecycle authority (GREEN)
  -> typed lifecycle/CTF events (#27)

snapshot foundation (GREEN)
  -> final coherent snapshots (#25, unchained)
  -> live debug protocol (#26)

#25 + #26 + #27 + strict profile (#28 complete)
  -> durable K1 GO evidence (#29)  -> K1 GO -> K2
```

The K3 chain runs in parallel and gates nothing above:

```text
#41 lifecycle spine (first K3 file slice)
  -> vertical FileAuthority semantic families + legacy deletion (#37/#33)
```

## Durable progress already retained

The recent commit sequence is the durable audit trail. Important checkpoints:

- `a547fb4bb` typed Kernel identities;
- `7a300db90` transactional registry;
- `113239918` fork reservation and `0a9bfa9b9` replacement-MM preparation;
- `32b2b2550`/`b99d55a40` child/thread publication gates;
- `d9823b391` authenticated process-wide lifecycle;
- `9fa8e2414` HVPatch lifecycle cutover;
- `995e08fa1` through `20028cc64` frame inventory integration;
- `6e8f6076a`/`3f977dc54` coherent snapshot foundation;
- `4ae5558d2` authoritative VMA snapshots and `6f2fd0154` draining objects;
- `90d2c8e50` credentials, `181d76880` fs context, and `78bfa986c`
  file/signal Kernel foundations;
- `6c59eb6ea` through `b9eb85064` FileAuthority model/IPC capabilities;
- `559649cbd` production root activation;
- `7b35fc591` authenticated activation health check.

K0 evidence is in `docs/perf-results/2026-08-09-hvpatch-k0-kernel-memory.md`.
K1 does not yet have an equivalent GO document; task #29 must create it.

## Verified current baseline

Immediately before this handoff:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime file_authority --lib -- --nocapture
# 39 passed; 0 failed

cargo clippy -p carrick-runtime --lib --tests -- -D warnings
# passed
```

Earlier accepted receipts included the complete sequential runtime library suite,
strict runtime Clippy, inventory/taxonomy checks, a signed build, and signed
native Ubuntu `/bin/true` with no persistent helper. They are historical, not a
substitute for re-running gates after lifecycle changes.

## Progress reflection

### What worked

1. Typed identities and transactions made lifecycle mistakes observable before
   they became backend-specific behavior.
2. Exact-context discipline prevented stale-generation and mixed-resource bugs.
3. Fail-closed authority/ledger rules avoided fallback promotion and ambiguous
   reconstruction.
4. Characterization probes and checked inventories exposed the real migration
   surface instead of relying on intuition.
5. Independent reviews found substantive bugs: request overtaking, invalid
   client allocation, incomplete publication wiring, and stale cleanup claims.
6. Reverting the blocked lifecycle prototype preserved a safe product boundary.
7. Small accepted commits left usable foundations even when the full gate stayed
   RED.

### What did not work

1. We broadened the detached FileAuthority model before cutting over one
   production family. Model completeness was confused with product ownership.
2. “Complete FileAuthority” was too large a unit: lifecycle identity, protocol
   ordering, native reexec, 361 sites, snapshots, debug, and backend validation
   were entangled.
3. We edited lifecycle wrappers before agreeing on a Kernel-owned transaction
   seam. The wrappers compiled in tests but no production publisher called them.
4. Process-local atomics were incorrectly considered for identity and request
   ordering across COW host forks.
5. Long sessions and temporary full-cutover trees caused stale offsets, exact
   edit failures, xattr noise, and repeated state reconstruction.
6. Broad subagent mapping had low yield; several agents failed with HTTP 401.
   Transaction synthesis cannot be delegated.
7. Repeated prose status updates did not advance a gate. Receipts and deletion
   counts must be the progress record.

## Improved operating strategy

- Treat each red K1 gate as a deliverable with explicit entry/exit evidence.
- Measure FileAuthority progress by fewer production escapes and deleted legacy
  state, not operations implemented or tests added.
- Complete one bounded milestone, request a fresh review, validate, and commit
  before expanding scope.
- Use the Kernel transaction as the sole lifecycle publication point. Backend
  loops only materialize or supply host facts.
- Write red concurrency/rollback/publication tests before lifecycle APIs.
- Work on `main`; avoid another temporary full tree unless isolation is required
  for a destructive experiment.
- Use subagents only for bounded read-only questions with explicit files. Keep
  architecture decisions in the primary session.
- End each session by updating this file with HEAD, dirt, exact receipts,
  rejected experiments, gate changes, and the next single milestone.

## Immediate next milestone: lifecycle spine (first K3 file slice)

Complete only FileAuthority lifecycle binding. Do not begin the 361 semantic
callers in the same milestone.

Reclassified by the 2026-08-12 re-baseline: this is K3 work (with a K4 exec
contract), run as a parallel correctness track. It does **not** gate K1 GO, so
it must not absorb #25/#26/#27/#29. The seam must go live in production — a
test-only lifecycle API reproduces the exact failure recorded in "What did not
work" §3 and trips the stop condition below.

### Required contract

- `PreparedFork`, `PreparedExec`, and `PreparedTaskExit` own or retain prepared
  FileAuthority transitions.
- Validate all fallible Kernel state, obtain authenticated FileAuthority terminal
  acknowledgement, then execute an otherwise-infallible Kernel publication.
- Open child/start gates only after both authorities commit.
- Ambiguous transport completion terminates the run; never reconnect,
  reconstruct, mirror, or publish only one side.
- Authority-assigned or authority-reserved client identities must remain unique
  across COW host forks.
- Per-client request allocation and the complete transport round trip are one
  serialized critical section; N+1 cannot overtake N.
- `CLONE_FILES`, `CLONE_THREAD`, and logical task/client identity remain
  independent dimensions.
- Dropped fork preparation reclaims its client/table reservation.
- Failed exec retains the exact old binding. Successful exec publishes CLOEXEC
  and successor table before replacement Kernel resources.
- Thread exit does not release a task client; final task exit releases it once.
- Native self-reexec preserves epoch, client, table, generation, sequence, lock,
  lifetime descriptor, and successor endpoint without re-registration.

The reverted prototype violated several of these rules. Do not reconstruct
`FileAuthorityRun::{fork_process,exec_process,exit_process}` from conversation.

### Red tests first

1. Same-client concurrent requests cannot overtake transport completion.
2. Parent and host-fork descendants receive collision-free identities.
3. Dropped prepared fork reclaims every FileAuthority reservation.
4. Child/task discovery and start remain closed until authority acknowledgement.
5. Authority failure during exec leaves old Kernel resources/binding live.
6. Final task exit releases exactly once; thread exit does not.
7. Thread clone selects table share/copy independently of task topology.
8. Native reexec resumes the exact sequence without duplicate registration.

### Production seams to read before editing

- `kernel/operations.rs`: fork prepare/commit and task-exit prepare/commit;
- `kernel/exec.rs`: exec prepare/commit;
- `kernel/objects.rs`: `ThreadResources` clone/exec transforms;
- `file_authority/root.rs`: root and request sequencing;
- native exec capsule/adoption and host-fork child reset;
- HVPatch child publication/start gate.

Do not distribute lifecycle calls among native, VMM, and HVPatch loops. Add one
Kernel-owned lifecycle participant seam.

## Roadmap to K1 GO

These four are the K1 critical path. None depends on the FileAuthority cutover.

1. **Typed events (#27):** finish lifecycle/CTF schemas and validators with no
   missing or ambiguous identity. Unblocked at HEAD.
2. **Coherent snapshots (#25):** join the current file authority's
   table/description/stream state with task/mm/frame/signal state; fail closed
   on busy/torn data. Follows the authority if K3 moves it.
3. **Live debug protocol (#26):** bounded/versioned `carrick debug` readers for
   task, thread, mm, VMA, frame, fd, and signal summaries plus event-ring
   identity.
4. **K1 proof and evidence (#29):** `just ci`, Docker differentials, signed
   native/VMM/HVPatch demonstrations, exact cold-build output, and 68/67/69;
   then a document recording commit, signed UUID/hash, host/HVF provenance,
   image/argv/env, raw hashes, scoped run IDs, correctness/concurrency/rollback,
   event populations, and the GO decision — naming the K3 file rows as remaining
   RED rather than claiming them.

## Parallel K3 track (gates nothing above)

1. **Lifecycle spine:** fork/copy/share, clone, exec/CLOEXEC, exit, host fork,
   and native reexec with rollback and ordering tests.
2. **Vertical semantic cutovers:** basic fd lifecycle first, then VFS/files,
   streams/sockets, epoll/waits, splice, mappings, and io_uring. Each slice
   deletes the corresponding legacy state; no dual writes or mirrors.
3. **Structural closure:** remove all 361 classified escapes,
   `host_fork_file_authority_rejection`, `ThreadResources.files`, guard-returning
   APIs, local writable VFS, reexec mirrors, and duplicate capability state.

## After K1 GO

K2 — global IPA frames and persistent stage-1 address spaces, replacing
per-process banks and flat page-table publication. This is where `hybrid.md`'s
goal lives: the Phase-4 prototype's last measured cold build is ~4.27 CPU-s
against a 2.3 CPU-s gate, and K2's gate ("fork work scales with writable table
paths/touched frames, not virtual span") is the mechanism that closes it. K1 has
produced no product-visible number by design; do not let that continue past K1
GO without re-measuring the prototype on current HEAD.

Never run Carrick and Docker concurrently. VMM/HVF runs require `just build` or
`just run`; use scoped `CARRICK_RUN_ID`s and exact cleanup.

## Next-session startup

```bash
cd /Volumes/CaseSensitive/carrick
git status --short
git rev-parse HEAD
git diff --check
RUST_TEST_THREADS=1 cargo test -p carrick-runtime file_authority --lib -- --nocapture
cargo clippy -p carrick-runtime --lib --tests -- -D warnings
python3 scripts/migrate/check-k1-file-authority-inventory.py
python3 scripts/migrate/check-k1-file-authority-taxonomy.py
```

Expected committed HEAD is `7b35fc591`. Preserve `proposed-plan.md`. Attribute
any tracked dirt before proceeding. Then mark task #41 in progress and implement
only the red-test lifecycle milestone above.

Before committing that milestone, run focused tests, the full sequential runtime
library suite, strict Clippy, formatting, inventory/taxonomy checks, and
`git diff --check`; obtain a fresh read-only review. Signed backend lifecycle
probes are required before calling the lifecycle slice complete.

## Stop conditions

Stop and redesign if a change:

- recaptures `KernelContext` or publishes after losing exact identity;
- opens a child gate before FileAuthority acknowledgement;
- updates FileAuthority after Kernel publication;
- allocates descendant-local client identity or allows request overtaking;
- leaves new lifecycle APIs test-only or unused in production;
- introduces a mutable mirror, reconnect reconstruction, compatibility path, or
  second guest-visible authority;
- weakens Linux fork/clone/exec, `CLONE_FILES`, `CLONE_FS`, CLOEXEC, offset,
  readiness, mapping, signal, credential, rlimit, or seccomp semantics;
- calls K1 GO without live debug, typed events, 68/67/69, `just ci`, signed
  backend receipts, and a durable evidence document.

## Historical continuity breadcrumbs

These are not reproduced blockers on current HEAD. Preserve them for attribution
only if a current command reproduces them:

- stale read/edit coordinates: `Offset 560 is beyond end of file` and exact-edit
  mismatch in temporary `dispatch/mem.rs` copies;
- earlier VMA compile error: `MemAuthority: VmaSnapshotSource is not satisfied`;
- earlier signed retirement regression: `HVPatch process retirement has mappings
  without frame inventory authority`;
- earlier context migration mismatch: `expected KernelContext, found
  &KernelContext`;
- earlier observability schema mismatch: missing
  `VmLifecycleArtifactError::MissingSourceSha256`;
- unused frame-inventory import and truncated Cargo logs from temporary trees;
- macOS `com.apple.provenance` restoration failures from archive/worktree xattrs;
- `ssh 10.14.14.189` timeout and missing FreeBSD sysroot/`assert.h`;
- subagent intercom notice and HTTP 401 failures;
- an unactionable dependency-tree tail through `reqwest`, `tokio-rustls`, and
  `rustls-webpki`.

## Definition of K1 done

K1 is complete only when every RED row **marked K1** in the gate ledger is GREEN
with current receipts: snapshots and live debug are coherent and bounded;
lifecycle events are typed and authenticated; exact cold-build output and
68/67/69 remain green on the signed shipped paths; `just ci` passes; and a
durable K1 GO document contains reproducible provenance and raw artifact hashes.

The three rows marked K3 — sole file/VFS authority, the 361 call sites, legacy
state deletion — are **not** K1 completion criteria after the 2026-08-12
re-baseline. K1 evidence must name them as remaining RED. Claiming them as K1 GO
is the scope error this re-baseline corrects.

## Verify this handoff

```bash
test -f docs/superpowers/plans/2026-08-12-k1-total-goal-session-handoff.md
rg -n 'Phase re-baseline|Total goal|K1 gate ledger|Roadmap to K1 GO|Parallel K3 track|Definition of K1 done' \
  docs/superpowers/plans/2026-08-12-k1-total-goal-session-handoff.md
git diff --check
```
