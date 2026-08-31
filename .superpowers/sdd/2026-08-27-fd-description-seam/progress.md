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
