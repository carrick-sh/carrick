# File-Description Seam Progress

Controller: `docs/superpowers/plans/2026-08-27-fd-description-seam.md`

Task 9 controller: `docs/superpowers/plans/2026-08-28-fd-description-task9-canonical-authority.md`

Implementation base: `10dcaf444`

## Status

Tasks 1 through 9 are implemented. Task 9 uses the approved canonical-object
vertical slice rather than the superseded nine-site/model-table recipe retained
in the original controller for audit history.

## Integrated implementation

| Task | Evidence | Result |
|---|---|---|
| 1, K1 burndown gate | `77556ebc3` | Inventory, taxonomy, and monotone-ceiling checkers added. |
| 2, `DescriptionCommon` | `8c8952016` | Generic description identity/lifecycle state moved under the kernel description. |
| 3, shared status flags | `8dd3b9265` | One status-flags value per description. |
| 4, remaining generic fields | `ed4068dd8` | Generic description state consolidated. |
| 5, close the generic backing escape | `f87e9c5db` | `base()`, `base_mut()`, and the io_uring shadow removed. |
| 6, readiness authority | `f13337ec5`, `d01feb4a3`, `c802a86d1` | One typed readiness authority, including review fixes for wake/scaling behavior. |
| 7, readiness translators | `4950fb4d7`, `d4cc71b02`, `3373d2073` | Poll and epoll reduced to translators; FIFO reconnect/close review defects fixed. |
| 8, open authority backing | `99dd39d7e` | Trait-object backing kinds replace the closed backing enum. |
| 9.1, canonical target | `9a2af8df2` | Production launch creates no model table or model description. |
| 9.2, canonical capacity mutation | `004d5547e` | Exact table/slot-token resolution and one narrow pipe-capacity mutation seam. |
| 9.3, production activation | `531b34cbf` | `F_SETPIPE_SZ` routes through the canonical authority with no direct fallback. |
| 9.4, K1 evidence | `dda62fb2a` | Measured ledgers and monotone ceilings reconciled. |
| 9 acceptance prerequisite | `ac9e27c2b` | Graph-backed numeric `/proc/<pid>` leaves are resolved before context-free access following. |

## Review findings closed

Independent review rejected or repaired the following before integration:

- a strong root `Arc` that pinned an obsolete launch table;
- an independent request-id allocator that could collide with ordinary calls;
- authority routing that changed `EBADF` precedence;
- stale claims about host-fork/helper behavior;
- missing proof that exec and `CLOSE_RANGE_UNSHARE` successor tables remain valid;
- K1 ledgers whose counts fell without lowering the corresponding monotone
  ceilings; and
- an LTP setup failure where the graph-aware `/proc/<peer>/oom_score_adj`
  implementation was unreachable behind context-free symlink following.

The Task 9 Antigravity workers completed with `WORK=done`, `TESTS=pass` after
the findings were sent back to their original conversations and repaired.

## K1 receipts

Task 9 changed the measured ledger as follows:

- total inventory: 1768 -> 1763, with no additions;
- `table_guard`: 132 -> 131;
- `description_guard`: 215 -> 211;
- taxonomy: 364 -> 359;
- `create_install`: 75 -> 72;
- `inspect_misc`: 146 -> 144;
- `slot_description_mutation`: unchanged at 14; and
- ceilings tightened to `create_install = 72`, `inspect_misc = 144`, and—after
  independent completion review—`slot_description_mutation = 14`.

The later access-path prerequisite moved two `access.rs` inventory positions by
12 lines without changing any count or classification. The checked-in inventory
and taxonomy record only those deterministic location changes.

All three K1 checkers pass.

## Independent completion review

Two read-only reviewers re-audited the current tree against the original
Tasks 1-8 and the replacement Task 9 controller. Task 9 was READY/CLEAN with
15/15 focused canonical-authority tests and 5/5 dispatcher tests. The Tasks 1-8
review found two actionable residuals:

- the measured `slot_description_mutation` family was 14 while its ceiling
  still allowed 16; and
- Task 3 had left Task 2's temporary `#[allow(dead_code)]` on the now-live
  `DescriptionCommon` implementation.

Commit `be4aca0a7` lowers the ceiling to 14 and removes the suppression.
`python3 scripts/migrate/check-k1-burndown.py`, its `--self-test`, and
`RUSTC_WRAPPER= cargo check -p carrick-runtime` pass after the fixes. The K1
finding was also sent back to the original `task9-ledgers` Antigravity
conversation; its third turn independently made the same one-line correction
and passed the burndown, inventory, taxonomy, and diff checks.

## Host-gate receipts

At the Task 9 implementation checkpoint:

- `RUSTC_WRAPPER= just test`: pass, including `carrick-runtime` 2027/2027;
- `RUSTC_WRAPPER= just test-integration`: pass, including runtime 302/302,
  syscall-process 9/9, trace-profile 41/41, engine 31/31, and image 33/33;
- `RUSTC_WRAPPER= just clippy`: pass;
- `RUSTC_WRAPPER= just doc`: pass;
- `just fmt-check` and `git diff --check`: pass; and
- `RUSTC_WRAPPER= just lint-domains`: semantic and conformance checks pass,
  then the known host-authority positional inventory stop reports `changed=[]`.

After `ac9e27c2b`, `RUSTC_WRAPPER= just test`, `RUSTC_WRAPPER= just clippy`,
`just fmt-check`, the three K1 checkers, and `git diff --check` pass again.

## Signed acceptance receipts

The focused cross-process `oomscoreadj` probe was red before `ac9e27c2b`
(`foreign_pid_file_exists=false`) and green after it
(`foreign_pid_file_exists=true`). Cross-process value reads, writes, fd-reuse
absence, and dead-pid absence remained green.

On the rebuilt signed binary after `ac9e27c2b`, the Carrick-first cached-oracle
gate reports:

- `ltp-fcntl30`: MATCH, Carrick 4/4, oracle 4/4;
- `ltp-fcntl37`: MATCH, Carrick 3/3, oracle 3/3.

The live native-arm64 Docker phase then passed sequentially:

- `fcntl30`: 4 passed, 0 failed/broken/skipped;
- `fcntl37`: 3 passed, 0 failed/broken/skipped.

The final focused signed-probe run used implementation HEAD `ac9e27c2b` and:

- SHA-256: `8448c4d5dc0b7b3e7de201596b9c055474e14d46c792c264e784b881e2355204`;
- CDHash: `08b5e080087042d287fb34fa5a310681d581fd7c`;
- LC_UUID: `605A3DE2-5998-3E99-94B8-06405EC8024E`;
- entitlement: `com.apple.security.hypervisor = true`; and
- `__TEXT,__dof_carrick`: present.

`CARRICK_PROBE_FILTER=fcntlpipesz,pipeszcrossend,spawnflagmatrix,epollcluster`
passed for arm64 musl and glibc, the retained CLI/container contracts passed,
and the unsigned negative control returned the expected entitlement error. The
first public-wrapper attempt stopped fail-closed when unrelated retained probe
`arm64:musl:execfromthread` flipped once from its checked-in XFAIL to an
unexpected pass; after scoped cleanup, the quiet-host rerun reproduced the
known gap and the complete public gate passed. No baseline or known-gap entry
was changed. Final scoped cleanup reported zero processes for run id
`fd-task9-final`.

## Scope boundary

Task 9 does not claim host-fork transport, IPC equivalence, full file-table
lifecycle binding, or close-family migration. Those remain Wave 3/4 work under
the approved atomic migration and the runtime-abstraction controller.

## PTRACE acceptance closure

Ruling: prove the structural-vvar fork fix through the production host-only
foreign-MM COW transaction on the exact prepared child ledger, rather than
fabricating an `HvfVmState` or starting an HVF VM from a host unit test. This
must demonstrate the original semantics at vvar + 24: child-private mutation
succeeds and parent bytes remain unchanged. If wrong, the unit test could miss
integration that exists only in `refresh_fork_process_state`; the signed public
probe and full ecosystem gates therefore remain mandatory on the exact landed
artifact.

PTRACE closure: fix round 1/5 (one finding addressed, two open). Exact
structural permission authentication is resolved. A different stage-1 IPA must
also have an authenticated overlay owner rather than bypassing the error, and
the vvar test must use privileged-internal COW while preserving guest-read-only
authority; the ordinary foreign-COW substitute was rejected by review.

PTRACE closure: fix round 2/5 (two prior findings addressed, one new finding
open). Exact overlay ownership, exact-custody task COW, canonical lookup reuse,
privileged vvar refresh, read-only AP, parent preservation, child-private
ownership, disarm, and one flush are all covered. Review found that overlay
authorization sampled only the candidate base; a partial overlay could hide an
unowned later leaf. Round 3 requires full-range authorization and a red-first
partial-overlay regression.

Ruling: stop the PTRACE perfection loop and use the signed public conformance
probes plus exhaustive ecosystem suite as the landing authority, per the
user's explicit direction. The incomplete round-3 experiment was removed while
the probe-blocking round-2 structural-vvar fix was retained. If wrong, a stale
coarse mapping with only a partially authenticated replacement overlay remains
a fail-open fork edge; it is recorded here rather than silently represented as
closed.

## Final conformance landing

The signed `procladder_mt` reducer exposed a three-lock retirement cycle:
global-owner custody -> replay inventory -> alias inventory -> global-owner
custody. The landing fix publishes an exact `RetirementPending` claim before
backend unmap, drops directory custody across replay/backend work, makes pending
owners unavailable to live readers and successor publication, and retries only
from named executor-idle boundaries after task, binding, and topology authority
has been released. Foreign-MM `Drop` paths now only release pins/registration
and enqueue work; they never invoke HVF or replay callbacks.

Pending retirement maintenance is carrier-scoped, exact, and bounded. It uses
deduplicated removable FIFO indexes keyed by `((IPA, length), generation)` and
detached record id, attempts at most 16 items per class per turn, tail-requeues
deferred/transient work, removes synchronous completions without tombstones,
and prevents concurrent maintenance turns from duplicating backend work. The
executor guarantees an immediate turn after exec cleanup and after terminal
topology release; invariant failures still settle the active scheduler claim.

The final host receipts are:

- carrier custody: 48/48;
- foreign-MM: 42/42, with the signed-HVF-only case intentionally ignored in the
  unsigned host executable;
- two-crate all-target Clippy with `-D warnings`: pass;
- formatting and `git diff --check`: pass; and
- two independent final queue reviews plus the terminal-custody review: CLEAN.

The focused signed reducer passed `procladder_mt` for arm64 musl and glibc in
2.59 seconds and the entitlement negative control passed. The retained CLI
contract then found a separate deterministic carrier-exit defect: after exact
custody had committed raw VM destruction, the final persistent-carrier mapping
owner attempted a redundant `hv_vm_unmap`, received `HV_NO_DEVICE`, and
aborted. Persistent carrier mappings now accept only an exact post-commit
terminal receipt; live-VM unmap failures remain fatal and no generic
`HV_NO_DEVICE` exception was introduced. The direct signed `true` reducer now
exits 0, all five CLI exit/stream cases pass, and both scoped cleanups report
zero residual Carrick processes.

The complete public probe gate and exhaustive ecosystem gate remain the final
acceptance authority for the exact committed and signed artifact.

## Session handoff — 2026-08-30 final-gate pause

The user explicitly paused all work so the landing can resume in a new session.
All delegated agents were interrupted, no guest or DTrace consumer remains
active, and local `main` is the only integration branch. Nothing was pushed.

### Landed on local main

- `a1f568917` — `hvpatch: bound deferred owner retirement`;
- `6ac2c6b8d` — `test(conformance): refresh final probe expectations`; and
- `968c01c78` — `trace: attribute executor signal-mask amplification`.

`6ac2c6b8d` removed six musl gaps only after the public shard reported them as
unexpected fixes, then reached the GNU lane and removed the five independently
proven GNU gaps. The combined musl/GNU filter
`cluster10errno,mqnotifycrossproc,ppid,procpeermem,shmnestedfork,sysinfo` passed
three consecutive signed repetitions. It also rebuilt `memflagmatrix` for both
arm64 libc targets and re-blessed the Docker oracle bodies; the old musl cache
had ended in `Segmentation fault`, so changing only its hash header was
explicitly rejected. All three shard host/cache tests pass. The stale shard-0
gap-count assertion was corrected to match its already-explicit exact sets.

`968c01c78` extends the durable fork caller-attribution D script with the live
Darwin `syscall::__pthread_sigmask:entry` provider. The script ran successfully
through `carrick trace` with a nonzero, error-free receipt.

### Probe blocker attribution

The first unfiltered public probe run had no new shard-1 regression. It stopped
on the newly fixed gaps above, the stale `memflagmatrix` source hash, and one
real `futexforkrequeue` mismatch. In the mismatch every futex, wake, and shared
counter assertion is true; only `children_exited_all` and
`children_exit_count_ok` are false. A private diagnostic reported 623 normal
exits, zero abnormal statuses, zero wait errors, and 377 children still live at
the probe's 40-second reap bound.

This is not introduced by `a1f568917`: an isolated signed `06279ae9b` artifact
reproduced the same exit-only failure in 75.41 seconds. `7a982b540` cannot reach
the comparison because it fails immediately at the older root-slot collision.
The current optimized release CLI passes the exact probe; the failure belongs
to the unoptimized signed conformance test profile.

A clean, single-variable ablation restored baseline executor code and ran the
focused signed shard with `CARGO_PROFILE_TEST_OPT_LEVEL=2`. Both arm64 musl and
GNU `futexforkrequeue` passed in 29.63 seconds and the unentitled negative
control passed. Scoped cleanup reported zero. No Cargo profile change is
committed yet. The next session should test the narrowest package-scoped
`[profile.test.package.*]` optimization covering the product runtime/HVF
dependencies; it must not weaken ASID invalidation, topology locking, retirement
ordering, or extend the probe timeout.

### Carrick trace and LLDB evidence

The release amplification capture at
`/private/tmp/fd-final-futex-trace.log` completed 1,001 forks with
`bounded=0`, `errors=0`, 7,046 stage-2 maps, 7,041 unmaps, and 827,281 host
syscalls. It counted 510,946 host `__pthread_sigmask` calls. The durable caller
capture at `/private/tmp/fd-final-futex-callers.log` reported 443,872 stacks,
`bounded=0`, `errors=0`, and 303,089 `__pthread_sigmask` calls. `atos` bound the
two dominant 146,199-call stacks to the pre-claim and post-save
`WorkerBoundaryAudit::audit_runtime` sites. These calls only query the Darwin
pthread mask; guest Linux signal masks remain Carrick kernel state.

A temporary, uncommitted split that omitted only the pre-claim mask query
reduced a signed debug-profile trace to 102,154 mask calls, 91,738 at post-save,
but the probe still failed in 78.54 seconds. That experiment was restored and
is not in `main`.

The same temporary debug artifact was captured at the 35-second deadline with
`carrick debug lldb-run`. Durable artifacts are:

- `target/conformance/logs/lldb-runs/fd-final-futex-lldb.manifest.txt`;
- `target/conformance/logs/lldb-runs/fd-final-futex-lldb.lldb.txt`;
- `target/conformance/logs/lldb-runs/fd-final-futex-lldb.37157.core`
  (modified-memory, approximately 2.2 GiB); and
- the corresponding `.ps.txt` and empty pre-flush `.guest.log`.

The event ring was valid (`total=69685`, showing 8,192, `errors=0`). At the
deadline all ten executor pthreads were in one terminal-retirement convoy: five
were waiting in `acquire_process_retire_topology_lock_servicing`, three were
waiting for cross-executor invalidation acknowledgements, one was retiring the
detached address space, and one was releasing the topology guard and waking the
scheduler. This explains the debug-profile sensitivity without showing a
product semantic failure. The ring already records exit-publication
begin/complete but not the intervening invalidation/topology/cleanup phases.

The LLDB kernel census also failed closed with:

`kernel snapshot invariant violated: file-table functional state disagrees with live classification`

An interrupted red-first experiment was intentionally not committed. Its test
name was `published_file_table_predecessor_is_explicitly_retirement_pending`;
it modeled the publication-to-`retire_file_table_generation` window and expected
the retained predecessor row to be `Draining`, `functional_refs_active`,
`retirement_pending`, with its retained owner also classified `Draining`.
Resume by reproducing that red test, then either classify the legal transient
or report the exact inconsistent object/owner; never make the snapshot accept
actual corruption.

### Exact resume sequence and non-completion conditions

1. Confirm `git status --short --branch` is clean on local `main` at
   `968c01c78` (or its exact fast-forward descendant). Do not read, search, or
   consult Linux kernel source.
2. Add and test the narrowest explicit optimized test profile that makes the
   signed in-process conformance runtime representative of the shipped product.
   Re-run `futexforkrequeue` signed at least three times for both libc lanes.
3. Complete the kernel snapshot red-first invariant above and add cheap fixed
   event-ring phases for terminal invalidation, topology wait/acquire/release,
   detached cleanup, settlement, and waitability; update
   `scripts/carrick_lldb.py` in lockstep. No allocation, formatting, or syscall
   is allowed in the ring recorder.
4. Run host tests, Clippy, formatting, and diff checks for those changes, review
   them, and commit each coherent milestone directly on local `main`.
5. Rebuild and sign one exact release CLI. Record HEAD, SHA-256, CDHash,
   LC_UUID, hypervisor entitlement, and `__dof_carrick` from that final file.
6. Run the complete unfiltered `just conformance-probes` with a scoped
   `CARRICK_RUN_ID`; require exit zero and scoped cleanup zero. Focused reducers
   and the earlier partial run do not satisfy this gate.
7. Without relinking or re-signing the CLI, run the exhaustive 2,127-row full
   ecosystem suite against that same file. Require its gating verdicts to pass,
   preserve any legitimate canonical oracle refresh, and prove scoped cleanup.

The goal is not complete at this pause: the post-refresh public probe gate has
not reached exit zero, the exhaustive ecosystem suite has not started, and the
current release binary has been re-signed during diagnostics so its earlier
identity receipt is no longer the final artifact receipt. The executable bits
on `scripts/test-signed.sh` and `scripts/build-signed.sh` remain `0755`.

## 2026-08-30 resume — `futexforkrequeue` root-caused as an O(N²) exit path

Resumed in worktree `.worktrees/conformance-next-landing`
(`fix/conformance-next-lifecycle`, branched from `edaa79455`). The previous
session's proposed landing was to make the signed conformance test profile
optimized so the probe stops failing. Measurement says that would have hidden a
real product defect: the failure is not a constant-factor slowdown, it is
quadratic work on the guest process-exit path.

### Deterministic reproduction

`CARRICK_PROBE_FILTER=futexforkrequeue scripts/test-signed.sh
carrick-conformance-next generic_probe_shard_2` fails on arm64 musl in ~96 s
with exactly `children_exited_all=false` and `children_exit_count_ok=false`;
every futex, requeue, wake and return assertion matches the Docker oracle. All
1,000 children reach `_exit(0)`; the parent cannot reap them all inside the
probe's 40 s bound.

### Attribution

The conformance-next lane is NOT USDT-dark. The `__dof_carrick` section is
registered by dyld, so the VM CARRIER — a grandchild carrying the
`carrick:<run-id>:` proctitle, not the `test-signed.sh` process — exposes 150
probes including `hvpatch-topology-lock`. `register_dtrace_probes()` is a CLI
call and is not required for USDT visibility.

`scripts/dtrace/hvpatch-phase4-topology-lock.d` attached to that carrier
(`-p <carrier-pid>`), one failing run:

- carrier-global topology mutex held **70.3 s of an ~85 s run (~83%)**;
- `ProcessRetire`: 2,004 acquisitions, **44.47 s held**, mean 22.2 ms, max 88 ms;
- `ProcessRetire`: **271,629 try-misses** against 2,004 successes (135:1) — the
  50 µs→5 ms backoff spin in
  `acquire_process_retire_topology_lock_servicing`;
- `InProcessFork` 18.27 s / 901 holds; `FrameCow` waits total 19.4 s, max
  212 ms — fork and COW are starved behind the retire convoy.

New durable instrument
`scripts/dtrace/hvpatch-process-retire-critical-section.d` brackets the
ProcessRetire hold window and splits it on-CPU / off-CPU / host-syscall:

- 2,004 holds, 45.41 s held, **89,434 on-CPU samples at 1997 Hz = 44.8 s
  on-CPU (98.6%)**, only 0.32 s off-CPU. The section is compute-bound, which is
  exactly why an unoptimized build fails it and a release build does not.
- Instrument trap, now recorded in the script header: keying the hold window on
  `self->` reported **zero** on-CPU samples. `self->` resolves against the
  wrong thread in the macOS `profile` provider; keying on `tid` explicitly
  gives the true 89,434. The first reading was a broken instrument, not a
  blocked holder — control counters (`profile_ticks`, `target_ticks`) are now
  printed unconditionally so that cannot recur silently.

### The defect is quadratic, not slow

Per-hold duration against wall time across the run's 2,004 holds:

| decile | mean hold | max hold |
|---|---|---|
| 0 (≈1000 children live) | 38.70 ms | 87.95 ms |
| 5 | 19.97 ms | 45.39 ms |
| 9 (few children live) | 5.34 ms | 14.45 ms |

Monotonic and ~7×: retirement cost is **linear in the number of live guest
processes**, so total exit cost is O(N²), fully serialized on one carrier-wide
mutex.

Ranked by innermost Carrick frame inside the critical section (top-15 stack
population, 8,854 samples):

- **89.8 % `carrick_vmm_hvf::trap::mutate_external_alias_state`** — clones the
  entire replay set and alias registry per mutation, then rebuilds
  `before_by_key`/`after_by_key`/`alias_keys` over the whole registry and
  regroups both replay sides by IPA, to discover keys the caller already knows;
- **10.2 % `AliasPublicationReceipt::retire_exact`** — per retired version id,
  linear `position`/`find` over `versions.aliases`, `versions.replays`,
  `alias_epochs`, `replay_epochs` and the whole `alias_registry` Vec.

`scoped_alias_epoch_update` already exists and its comment names this exact
workload, but it was only wired into the two per-COW-fault mutators. The
process-retirement mutation at `trap.rs:27850` still goes through the generic
clone-and-diff path.

This is the scope-domain defect class from
`docs/identity-and-scope-domains.md`: carrier-global `Vec`s holding per-process
rows, so a per-process operation pays for every other process.

### Landing plan

1. Cost-accounting interface so complexity is testable without timing: an
   always-on scanned-row counter over the global alias/replay/version state,
   with a red-first unit test asserting that retiring one owner among many
   foreign owners scans a bounded number of rows.
2. Index `AliasVersionRegistry` by key (`aliases`, `replays`, `alias_epochs`,
   `replay_epochs` → maps; add version-id → key indexes for `retire_exact`).
3. Replace the process-retirement clone-and-diff with a delta-reporting
   mutation, as the COW path already does.
4. Rebuild replay chain bases with a `BTreeSet` range query on the leading IPA
   instead of filtering the whole set.

Only after that is the test-profile question worth re-asking.

### Horizontal hot-path sweep (2026-08-30, after the retirement fix)

`scripts/dtrace/hvpatch-carrier-user-cpu-ranking.d` (new durable artifact),
attached to the carrier under the same `futexforkrequeue` fork/exit storm.
213,029 samples, `errors=0`, unbounded. Ranked by innermost Carrick frame over
the top-120 stack population (42,535 samples):

| share | frame | shape |
|---|---|---|
| 22.5% + 14.6% | `retain_external_aliases` and its closure | O(all alias rows) per process exit |
| 13.3% | `fork_source_translation_has_overlay_owner` | O(M) inside a loop over M mappings = **O(M^2) per fork** |
| 13.2% | `HvpatchRuntimeDirectory::continuation...` | not yet dissected |
| 9.8% | `kernel::objects::Task::thread` | map `get`, but a mutex acquire + `Arc::clone` per lookup |
| 8.6% | `thread_mapping_semantic_ipa_at` | O(1) itself; its share IS the fork quadratic above |
| 6.8% | `AliasOwnershipScope as Ord` | comparison cost of the new keyed maps; shrinks with the registry fix |
| 1.3% | `run_state::find_record` | linear scan over ALL process records |

Found statically, not rankable from this profile because they sit inside the
serialized sections:

- `CowArmedRanges` is a flat `Vec`: `span_for` linearly filters every armed
  range PER COW FAULT, `disarm` rebuilds the whole `Vec` per fault, and
  `ranges.clone()` heap-copies it per fault largely to feed a debug `len()`.
  A fork arms every private writable range, so resolving them is O(A^2).
- `perform_frame_cow` takes a stop-the-world sibling quiesce AND the
  carrier-global topology lock on EVERY COW page fault (10,896 acquisitions,
  42.7 s aggregate wait in one run) — whole-VM serialization per page fault.
- `acquire_process_retire_topology_lock_servicing` still spins: 201,813
  try-misses against 2,333 successes, on a 50 us -> 5 ms sleep backoff rather
  than a queued wait.

Ranked plan: (1) key the alias registry by ownership scope so exit is O(own
rows); (2) index fork source mappings by translated IPA once per fork instead
of rescanning per mapping; (3) give `CowArmedRanges` an interval index and stop
cloning it per fault; (4) revisit the per-COW-fault carrier-global
serialization; (5) `run_state::find_record`; (6) replace the retire backoff
spin with a queued wait.

### Landed 2026-08-30 — three horizontal hot-path fixes

| commit | what | contract test |
|---|---|---|
| `3172754f1` | process retirement stops re-deriving touched keys by diffing whole global snapshots; `AliasVersionRegistry` keyed on every lookup axis | `retiring_one_owner_does_not_scan_foreign_alias_rows` |
| `db6bac478` | fork overlay-owner question indexed once per fork instead of O(M^2 * I) rescan | `fork_overlay_owner_lookup_does_not_rescan_every_source_mapping` |
| `9e43ecd02` | alias registry partitioned by ownership scope; exit, `munmap` and five scoped lookups become O(that process) | contract above tightened to 16 visited rows |

`futexforkrequeue` went from a hard failure at its 40 s reap bound to
3/3 signed passes at 98.8 s / 81.6 s / 79.3 s for the shard.

Two regressions were introduced and caught by the gate on the way, both now
documented at the code they broke:

1. Iterating the partitioned registry in BUCKET order silently broke
   `lookup_shared_alias`: a thousand processes aliasing one shared futex page
   at the same IPA got different `host_addr`s for the same word, so wakes were
   lost (`timeout_count_zero=false`, 2/2). Order-sensitive callers now use
   explicit `oldest_matching` / `newest_matching`.
2. Fixing that by materializing global order per lookup made
   `AliasRegistry::ordered` 89.6% of carrier CPU and the probe still failed —
   children could no longer enrol on the futex inside the probe's window. The
   ordering primitives are single passes with no allocation.

The second one is the lesson worth keeping: on this workload a correctness fix
that costs a sort per lookup fails the SAME assertion as the correctness bug
did, so "the probe is still red" was not evidence the ordering theory was
wrong. Profiling, not re-reasoning, separated them.

### Remaining ranked list (profile after the three fixes, 169,860 samples)

Everything that led the original sweep is gone: `retain_external_aliases`
(37.1%), `fork_source_translation_has_overlay_owner` (13.3%),
`HvpatchRuntimeDirectory::continuation` (13.2%) and `Task::thread` (9.8%) no
longer appear in the top ranks. What replaced them:

| share | frame | shape |
|---|---|---|
| 34.4% | `AliasPublicationReceipt::commit` | per-publication work, not yet dissected |
| 14.4% | `fork_translation_has_overlay_owner` | the `ProcessMappingDesc` SIBLING of the function fixed in `db6bac478`, same O(M^2) shape, untouched |
| 8.3% | `kernel::frame_inventory::FrameInventory...` | not yet dissected |
| 6.8% | `alias_matches_process_scope` | the predicate of the remaining whole-registry scans |
| 5.1% + 4.0% | `AliasRegistry::iter` / `iter_mut` closures | callers that still walk the carrier |
| 3.7% + 2.7% | `missing_process_aliases` | scope-filtered scan over the whole registry |
| 3.0% | `process_alias_index` | builds a map over all aliases, then filters by scope |

Plus the COW fault path, still untouched and still per-operation quadratic:
`CowArmedRanges` is a flat `Vec` whose `span_for` linearly filters every armed
range per COW fault and whose `disarm` rebuilds the whole `Vec` per fault, and
`perform_frame_cow` takes a stop-the-world quiesce AND the carrier-global
topology lock on EVERY page fault.

Not yet run on this branch: the full unfiltered probe gate and `just ci`.

## 2026-08-31 — full probe gate GREEN, and the fixes it took

`just conformance-probes` (full, unfiltered, `CARRICK_RUN_ID=cn-fullgate-10`)
exits **0**: 818 probe runs, zero `test result: FAILED`, zero aborts, the 46
`carrick-cli` conformance tests pass, and scoped cleanup reports zero residual
processes. The only DIFFs are the three declared baseline gaps
(`lifecycleflagmatrix`, `memflagmatrix`, `vfs_mount_rw`).

Ten gate runs were needed. The gate had never reached exit zero, and each phase
that failed was masking the next.

### Product bugs the gate surfaced (all pre-existing on `main`)

1. **`mremap` with a misaligned `old_address` aborted the carrier.**
   `man 2 mremap` documents EINVAL for it; the handler validated a long list of
   other EINVAL conditions, including the MREMAP_FIXED `new_address`
   alignment, but never the source. The request therefore ran the whole move,
   published the destination, could not reclaim the misaligned source, and hit
   the deliberate fail-stop `abort()`. That killed the entire shard-2
   executable at `memflagmatrix`, so ~146 other shard-2 probes were never
   compared at all.
2. **`hv_vm_create: HV_BUSY` in the concurrent container gate.**
   `carrier_root_boot_gate` exists to stop two roots both creating the one
   per-process VM, and is held across `hv_vm_create` — but `CARRIER_VM_LIVE`,
   the predicate that gate guards, was published far later by
   `PendingCarrierVmCreation::commit`. The second root took the gate, still
   read `false`, and created. The flag's own doc already said it is "set on the
   single create funnel's success"; the code had drifted. Publishing it in
   `create_vm_with_admission` fixes it.
3. **`probe-inventory.json` was missing `ptracepoketext`**, which
   `ptrace_poketext_signed` already owns, and `PROBE_SOURCE_COUNT` was 490
   against 491 sources on disk.

### Diagnostics defects fixed where they happened

- The `mremap` fail-stop printed NOTHING before aborting. Locating it needed a
  7.5 GiB core dump. It now names the destination, the source, and both errors.
- `create_with_no_resources_backpressure` takes a `what` label for its trace
  output and threw it away on the error path, and `create_vcpu` wrapped bare.
  HV_BUSY surfaced as "owning resource is busy (error 0xfae94002)" with nothing
  saying which call. Naming them is what identified defect 2 above.

### Baselines

23 probes the gate proves passing were removed from the gap lists, most of them
signals and process lifecycle — the axes the O(N^2) work in this branch was
starving: `childsubreaper`, `clonefsumask`, `coredumpfile`,
`futexforkwakegroups`, `killchld`, `mmapfileshare_mt`, `mprotectexec`,
`pidfdprocdir`, `pidnsroot`, `proclife`, `procpeerdir`, `ptraceattach`,
`rlimitnproc`, `setidthreadchurn`, `siginfo`, `sigpairrace`,
`sigtimedwaitintr`, `sigwaitblock`, `telemetrymap` and the rest. Every removal
was made only after the gate reported it as an unexpected pass, and no gate run
ever reported an unexpected FAILURE. `memflagmatrix` was ADDED as a declared
gap: it used to crash before it could be compared, and now that it can be, it
genuinely diverges on `madvise` WIPEONFORK/DONTFORK lifecycle, `mincore`
lifecycle, `mmap` invalid-prot and `mremap` DONTUNMAP.

### Known residual, NOT introduced here

Carrick's own host process intermittently fails to `mmap` a sigaltstack when
spawning a thread — `failed to allocate an alternative stack: Cannot allocate
memory (os error 12)` — which truncates whatever guest is running. It hit
`telemetrymap` twice but can hit any probe. Measured at roughly one run in
five, reproducible in ISOLATION (not positional or cumulative), and it
reproduces on unmodified `main`. Ruled out: host thread leak (flat at 8-25),
VM region growth (fluctuates 327-7259, no trend), carrier VSZ growth (flat at
~467 GB from the first probes), and guest `setrlimit` leaking into the host
(carrick never sets host `RLIMIT_AS`). Not yet explained; it is the next thing
to chase for a gate that is green every time rather than most times.

A separate one-off: an `inventory owner absent` fatal during process
retirement in `forkstackstorm`, seen once in ten gate runs and not reproducible
in 3 filtered plus 2 full-shard runs.

## 2026-08-31 (cont.) — closing conformance gaps

Gate green again (`cn-fullgate-11`, exit 0, 818 probe runs, 0 aborts, 0
failures). Declared gaps: **9 -> 7**, and two of the survivors shrank
substantially. Only 4 of the 7 are actually executable — `execfromthread`,
`execthreads` and `vforkexecthread` are `OUT_OF_PROCESS_PROBES`, excluded from
the cached lane, so they never run.

### Closed

**`eventwaitmatrix`** (13 divergences). All ordering/coverage of argument and
permission validation:
- `clock_settime` checked CAP_SYS_TIME LAST. Without the capability — Docker's
  default profile denies the syscall — Linux answers EPERM for an unknown clock
  id, a NULL `timespec`, a negative `tv_nsec`, an out-of-range `tv_nsec` and a
  non-settable clock alike; carrick reported EINVAL/EFAULT for all five.
- `clock_adjtime` orders its checks DIFFERENTLY and the oracle shows all three
  steps: unknown id EINVAL, NULL `timex` EFAULT, known-but-non-adjustable clock
  EOPNOTSUPP. carrick said EINVAL for every one.
- `timerfd_create` admitted any clock it could READ, so
  `CLOCK_PROCESS_CPUTIME_ID` returned a working fd.
- `ppoll` folded its timeout `timespec` into milliseconds without validating it.
- `futex` gained four validations it never had (misaligned `uaddr`, unknown op
  ENOSYS, zero BITSET mask, timeout validation). The ENOSYS check must PRECEDE
  the flag-mask check, and the same gate had to go in `dispatch_threaded_futex`
  — a guest thread reaches that path, so validating only the `proc.rs` handler
  left every check unreachable, which is why the first attempt moved nothing.

**`vfs_mount_rw`**. A VFS mount answers `readdir` from its own view and cannot
know about mounts layered inside it: `DevVfs` owns `/dev` and has no idea
`/dev/shm` is a separate bind mount, so `shm` resolved and opened but was never
listed. The rootfs path already injected mount children; synthetic mounts now
do too, which covers any `-v` bind under a synthetic parent.

### Reduced

**`lifecycleflagmatrix` 9 -> 4.** A session/process-group id IS its leader's
pid, so it belongs to the domain `getpid` reports; `setsid`, `getpgid` and
`getsid` returned the raw `TaskId`. This is the
`docs/identity-and-scope-domains.md` class behaving exactly as that document
predicts: the numbering domains coincide while only one process is live, so it
is invisible to a single-process lane and appears the moment a probe forks and
compares a child's ids against its own pid. Also `setpgid(-1, 0)`: `pgid == 0`
means "use `pid`", and that substitution precedes the range check, so the call
asks for group -1 and is EINVAL.

**`memflagmatrix` 9 -> 7.** `mmap` rejected unknown protection bits; `mmap` and
`mprotect` differ here and the probe asserts both. `mremap` with `old_size == 0`
rounded the zero up instead of requiring MREMAP_MAYMOVE.

### What is left, and why each is not a quick fix

| probe | remaining | shape |
|---|---|---|
| `memflagmatrix` | 7 | MADV_WIPEONFORK/MADV_DONTFORK lifecycle, the madvise hint matrix, `mincore` accuracy (lifecycle + sparse multipage), MREMAP_FIXED relocation, MREMAP_DONTUNMAP — all unimplemented FEATURES, not validation |
| `lifecycleflagmatrix` | 4 | `process_vm_writev` into a child (2), `ptrace_attach_init_eperm`, `waitid_no_children_echild` |
| `memfdsealmatrix` | 1 | a write through an existing `MAP_SHARED` memfd mapping is not visible to `pread` on that fd — shared-mapping/file coherence |
| `budget_two_proc` | 1 | `parent_pid=9` (Docker) vs `2` (carrick). An ABSOLUTE pid value that depends on how many processes the runtime happened to start first; matching it would mean burning pids to imitate Docker's count, not fixing a semantic |
