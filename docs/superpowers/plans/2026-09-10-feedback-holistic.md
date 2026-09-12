# Holistic response to `feedback.md` — 2026-09-10

**Goal:** address every finding in `feedback.md` (the 2026-09 code-smell and
architecture review) as one campaign, with structural fixes rather than
site-by-site patches, keeping the runtime correct and fast.

**Method:** the director (Claude, this plan's author) decomposes into
file-disjoint, independently verifiable tasks; Antigravity workers (Gemini
3.8 Flash High) execute each in its own worktree; the director reviews diffs,
re-runs verification, and lands. Work Antigravity cannot converge on in three
rounds comes back to the director.

**Owner decisions recorded here (from the goal statement):**

- DSR and `carrick-native-darwin` were preserved for a targeted-patching
  optimisation that has not materialised; the exec backend enum now has one
  variant (`hvpatch`). If keeping them is a drag, remove them. It is (78K LOC,
  four crates, four CLI modules, a test lane and 13 D scripts for a lane that
  no longer runs). **Decision: remove.** Git remembers.
- `std::process::abort()` is deliberate: the project prefers post-mortem
  analysis (core + `carrick-lldb`) over unwinding. The defect is not the
  abort, it is that a raw abort carries no reason into the core and that each
  site is a bare call with nothing to grep. **Decision: keep abort-on-invariant
  (the `BUG()` analogue), route every site through one `carrick_fatal!` sink
  that records domain + message before aborting, and gate raw `abort()` out.**
  Sites whose rationale is a recoverable resource condition are reclassified
  to a guest-visible errno in the shard that migrates them.
- Clean-room only: no GPL sources. Structure from BSD/Go/gVisor analogues.

## Mapping from feedback item → task

| # | Finding | Task | Wave |
|---|---|---|---|
| 13, 7(x86 emit) | preserved DSR / native-darwin | T1 `dsr-removal` | 1 |
| 5a, 9b | path resolution inlined 4×, x86 stat raw masks | T2 `fs-path-resolution` | 1 |
| 7 (AutoCloseFd, portable errno), 11a | fd RAII dupes, errno shim, blanket allow | T3 `fd-raii-errno` | 1 |
| 4 | `as i64` at the return boundary | T4 `return-boundary` (non-fs dispatch) then T4b (fs.rs) + semgrep gate | 1, 2 |
| 6 | 570 raw aborts | T5 `fatal-sink` (infra + scanner + pilot) then T5a/b/c shards | 1, 2 |
| 5c, 5d, 10c | CLI RunElf/args triplication, named-user→root | T6 `cli-args-engine` | 2 |
| 3, 5b | `DispatchOutcome` wait triplication | T7 `wait-outcome` | 2 |
| 12 | `Result<_, String>` in kernel exec prepare | T8 `typed-exec-errors` | 2 |
| 5f | `VCPU_LIVE` duplicated per VMM | T9 `vcpu-live-hal` | 2 |
| 1, 8 | god files, 140 too_many_arguments | T10 `split-trap`, T11 `split-vcpu-loop`, T12 `split-fs`, T13 `split-dispatch` — pure moves, context structs where a split exposes them | 3 |
| 11b, 11c | `Arc<Mutex<Vec<VcpuThreadHandle>>>`, bitmasked atomic state | T14 `vcpu-registry`, T15 `process-state-enum` | 3 |
| 2 | `SyscallDispatcher` god object | T16 `dispatcher-subsystems` — after splits expose the seams | 3 |
| 9c, 9d, 10a, 10b | builder consistency, `RunSpec` grab-bag, tokio/env hacks | T17 `spec-and-embed-hygiene` | 3 |
| 5e | errno translation split | verified correct by feature closure; no change | — |

## Wave 1 (dispatched 2026-09-10, base `0ec4e75e9`)

File fences are disjoint except `crates/carrick-runtime/src/dispatch/mod.rs`
(T3 edits `AutoCloseFd`; T4 adds one `mod` line) and
`crates/carrick-portable/src/lib.rs` (T3 edits `errno`; nothing else).

Verification every worker runs before reporting: `just fmt-check`,
`just clippy`, `just lint-domains`, and the crate's `--lib` tests. The
director runs `just ci` and the signed conformance probe gate on the merged
tree before landing.

## Waves 2–3

Sequenced after wave 1 lands because they share files with it. Splits (T10–T13)
are pure moves committed the same day they start, reconciled with
`just reconcile-inventories`, because `trap.rs` alone sees ~9 commits a day
from sibling branches.

## Progress log

- 2026-09-10 wave 1 LANDED on main: clippy fix (643b4f0a5); `OwnedFd` wrappers
  + std errno (f06d4acc9); `carrick-fatal` + ledger gate (094233272); typed
  return constructors `dispatch/retval.rs` (dd5d4435a); unified fs path lookup
  `dispatch/fs/lookup.rs` (c6a2187c2); DSR + native-darwin removal
  (cc7d9eaa2, four crates, bench-native, 121K lines).
- 2026-09-10 wave 2a LANDED: abort shards for leaf crates (d0a6dc970), vcpu_loop
  (3eff19088), carrick-vmm-hvf (f7fa24e44), fs.rs typed returns + semgrep rule
  `carrick-no-raw-returned-as-i64` (20add4f9f). The runtime shard (T5c) lands
  once its gate is green. After it: every ledger row is `sink: fatal`; the
  ledger gate refuses any new raw `std::process::abort()` anywhere under
  `crates/` except the sink itself.
- Carried into wave 2b: `typed_error_debt` rows still `sink: fatal` (22 in
  runtime.json, 3 in vcpu-loop.json — their conversion needs cross-file
  signature changes; T8 owns them); the semgrep rule still excludes
  `dispatch/mod.rs` (two `Returned { value: … as i64 }` sites; T4c).
- Two integration tests in `tests/integration/syscall_fs_open.rs` were red
  on main before this campaign (bisected to 8236ed8bf and b2d22a814); fix
  branch `agy/fsopen-red-bisect-sep10` routes overlay mutations through the VFS
  and drops the host-isatty authority for guest stdio.
- 2026-09-10 wave 2a/2b LANDED: runtime abort shard (73dc8c517; every ledger
  row is now `sink: fatal`); fs open fixes for the two pre-existing reds
  (965268b70); CLI argument flattening + run-elf through the engine + named
  `--user` resolved against the image passwd/group (d81900348); typed
  `ExecPrepareError` on the exec-prepare path with `RuntimeError::Exec`
  (e64f8df07); typed `RecordStateCell` for process records (212226756);
  shared `carrick_hal::VcpuCensus` with an RAII live guard (a10e8b59e);
  `--rehome` mode for the line-pinned inventories (02756b0ab); one
  `WaitOnFds { completion: FdWaitCompletion }` and `SharedFutexTarget`
  (6d6baf99c).
- Wave 3 dispatched: T10–T13 god-file splits (trap.rs, vcpu_loop/mod.rs,
  fs.rs, dispatch/mod.rs + net.rs), T17 spec/embed hygiene; T19 (two more
  pre-existing red integration tests: syslog manifest owner, timer_create
  thread-clock SIGEV_THREAD_ID) in review round 2.
- Landing discipline learned today: never `git add -A` while a rebase is
  paused (a conflict-markered capture JSON reached main once and was fixed
  forward in eec00f45f); validate every inventory JSON parses before commit;
  `git rerere` is enabled in this clone — its cache was cleared so a recorded
  "take main" resolution can never be replayed onto a newer inventory.
- 2026-09-10 live verification: `just conformance-probes` on main at
  ce62ddb26 (signed, carrick-only against the cached oracle) — every probe
  MATCH except four DIFFs already recorded as open reds by earlier sessions
  the same day (`seekholemap` 9bf699d88, `statfslifetime` 9bf699d88,
  `tty0state` 4392584d0, `packetv3state` 1655fd6dd). No campaign regression
  on the probe gate. Log: `target/perf/probes-wave2b-sep10.log`.
- 2026-09-10 `just ci` GREEN on main at 73bb6d842 (log
  `target/perf/ci-wave2b4-sep10.log`). Before the campaign main failed
  `just clippy` (15 lints), four runtime integration tests (O_TMPFILE
  materialisation, TIOCSCTTY on stdio, the syslog manifest owner,
  timer_create thread-clock SIGEV_THREAD_ID) and the conformance-next
  retained-probe manifest check; all fixed forward and attributed to
  pre-campaign commits in their commit bodies.
- 2026-09-10 wave 3 round 1 LANDED (pure moves, inventories re-homed):
  trap.rs 61,201 → 32,014 lines (vcpu_admission, carrier_custody,
  foreign_mm, task_mapping_index, frame_inventory, memory_protection
  submodules); vcpu_loop/mod.rs 22,797 → 20,051 (wait_wake, terminal,
  VcpuThreadRegistry); dispatch/fs.rs 16,754 → 12,256 (notify, locks,
  proc_synthetic, mount, directory); dispatch/mod.rs 13,583 → 10,122
  (outcome, request, wait_authority, host_alias, core_publication; the
  semgrep exclusion for mod.rs is gone). Each worker hit its 90-minute
  budget twice; round 2 continues from the landed state with a
  commit-per-move, stop-green-at-70-minutes rule. T17 spec/embed hygiene
  landed (70f8413a3). T16 dispatcher subsystem views is briefed and waits
  for the dispatch split to finish.
- 2026-09-10 wave 3 round 2 LANDED: trap.rs → 21,662 (guest_memory,
  global_frame, test modules moved with their subjects); vcpu_loop/mod.rs
  → 16,525 (memory, crash, outcome); dispatch/fs.rs → 9,603 (attr, stat,
  ioctl); dispatch/mod.rs → 7,724 (mm_authority, dispatcher,
  kernel_context). `just ci` green after round 1 (ci-wave3a); round 2 CI
  running (ci-wave3b). Round 3 dispatched; net.rs starts this round.
  Note for the splits: `runtime-global-state.json` keys rows by file and is
  not covered by `--rehome`; the director merges the worker's rows for the
  touched files over main's ledger at landing (`merge-global-state.py`,
  session scratchpad) until the tool grows that mode.
- 2026-09-10 wave 3 round 3 LANDED: trap.rs → 14,123 (execve_rebuild,
  stage2_backend and more); vcpu_loop/mod.rs → 10,890; dispatch/fs.rs →
  6,135; dispatch/mod.rs → 4,773. net.rs (11,837) untouched so far — round 4
  starts it. Landing recipe now: `prep-split.sh` (save any half-move as a
  patch, reset to the green prefix, rebase, merge the global-state rows,
  reconcile --rehome, gate) then the gated `land()`; a doc link to a
  now-private helper was the only fix needed after the moves.
- 2026-09-10 wave 3 round 4 LANDED: trap.rs → 7,548 (target ≤8K met),
  vcpu_loop/mod.rs → 3,468 (≤5K met), dispatch/fs.rs → 1,470 (≤3K met),
  dispatch/mod.rs 4,773, dispatch/net.rs → 8,905 (first net moves). Round 5
  dispatched for net.rs; T16 dispatcher subsystem views dispatched starting
  with the fs subsystem. CI green after round 3 (ci-wave3d); round 4 CI
  running (ci-wave3e).
- 2026-09-11 probe gate on main after split round 4
  (`target/perf/probes-wave3-sep10.log`): the four pre-recorded reds plus a
  fifth, `coredumpfile` (three_threads_captured=false and the three
  per-thread fields). Re-run alone on the SAME binary it MATCHes
  (`coredump-main-sep11.log`); the gate run overlapped six workspace builds.
  Classified load-sensitive per AGENTS.md ("anything flaky is an
  architectural flaw"): the crash-capture thread census under host load is
  an open defect class (it was root-caused once already on 2026-09-08,
  cea7eecad), not a campaign regression. Not excused; recorded for the
  next fix cycle.
- 2026-09-11 wave 3 round 5 LANDED: dispatch/net.rs 8,905 → 2,975 and
  dispatch/mod.rs → 3,081 (9a04404c9). Every god file from feedback item 1
  is now at or below its brief target except dispatch/mod.rs (3.1K vs
  2K, the remaining lines are `mod` declarations and re-exports). `just ci`
  green on main (ci-wave3f). Remaining: T16 dispatcher subsystem views
  (FsView landed in review), then the final probe run.
- 2026-09-11 T16 LANDED (2624ae8bc): typed subsystem views (`FsView`,
  `NetView`, `ProcView`, `SignalView`, `IpcView`, `MemView`) on
  `SyscallDispatcher`; all 88 fs handlers take `FsView`, whose
  `cross: &dyn FsCrossSubsystem` is non-optional (the test fixture
  implements the trait — no production fallback, no `expect`);
  `open_at_path_string` takes `OpenAtArgs`. `too_many_arguments` allows
  140 → 101. Every task in the mapping table is landed; final `just ci` +
  probe gate running (`ci-final-sep11`, `probes-final-sep11`).
- Carried forward (not done, recorded honestly): routing net/proc/signal/
  ipc/mem handlers through their views (T16 did fs only); dispatch/mod.rs
  at 3.1K vs the 2K target; 101 `too_many_arguments` allows; 24 + 3
  `typed_error_debt` ledger rows still `sink: fatal`; the load-sensitive
  `coredumpfile` thread census; four pre-recorded probe reds.
- 2026-09-11 final gates: `just ci` green (ci-final-sep11); the probe gate
  caught one real regression from the dispatcher-views landing — FsView
  had header-only copies of the `/proc/sysvipc/*` renderers shadowing the
  live ones (`sysvmsg` DIFF, deterministic) — fixed forward in de31e8ef5
  by routing them through `FsCrossSubsystem`; `coredumpfile` MATCHed this
  time (load-sensitive as recorded). Final CI + probes re-running with the
  fix (`*final2-sep11`).
- Carry-forward added: FsView carries its own copies of five signal-state
  helpers (`signal_blocked`, `signal_is_ignored`, `signal_mask_for`,
  `mark_signal_pending`, `proc_status_signal_masks`) that also exist on
  SyscallDispatcher in dispatch/signal.rs; they take no dispatcher state
  and should become shared free functions (duplication class 5).

## Closing state — 2026-09-11

`just ci` green on main at 2fa79aba3 (`target/perf/ci-final3-sep11.log`);
signed probe gate shows only the four reds recorded before the campaign
(`probes-final2-sep11.log`). Every task in the mapping table landed. The
carry-forward items above are the honest remainder; none is a regression
introduced by this campaign (the one regression the gate caught, sysvmsg,
was fixed forward the same day).

## Phase 2 — 2026-09-11 (AGY_RUN_ID=feedback-sep11)

Order: (1) the five open probe reds, (2) route every subsystem through its
view + dedupe the FsView signal helpers, (3) retire the typed_error_debt
rows, (4) resume the perf2x campaign.

- (1) LANDED: `seekholemap` (748724945: F_PUNCHHOLE via libc on beyond-EOF
  writes, block size from fstat, SparseBuffer seek), `statfslifetime`
  (161ead9a2: typed `FsIdentity` per description, unlinked /proc/self/fd
  reopen), `packetv3state` (1c3751ff2: in-zone AF_PACKET with a TPACKET
  ring; `linux_to_host_af` now refuses unknown families instead of passing
  them through), `tty0state` (c8650ee77: kernel-owned `VirtualConsole`,
  per-tty termios shared across opens, no host fd). `just ci` green
  (ci-phase2a-sep11). `coredumpfile` in review round 2: root cause found
  (premature begin_process_exit + a 10 s quorum deadline); round-1 branch
  waited forever for a departed participant — the census must shrink on
  participation drop, not only on register publication.
- (2) dispatched (`views-routing`).
- rerere is now disabled for this clone (`git config rerere.enabled false`)
  after it replayed a wrong inventory resolution onto a later rebase.
- (1) `coredumpfile` LANDED (22f6ddbf1): `try_claim_persistent_process_exit`
  no longer flips `process_exiting` before capture; `CrashQuorum` snapshots
  the census at open, collects parked registers from blocked/withdrawing
  siblings, treats a dropped participation as departure, and has no
  wall-clock deadline. `vcpu_loop` + `core_publication` test filters return
  (the round-1 branch hung one of them for 44 minutes); probe 3/3 alone and
  10/10 under `cargo clippy` load per the worker. Item 1 is complete; a
  full probe gate + CI on main is running to confirm (phase2b logs).
- Gate after item 1: `fdsemantics` regressed (the statfslifetime reopen
  copied the inode instead of sharing it, so an O_TRUNC through
  /proc/self/fd/N was invisible to the original fd); fixed forward in
  8caf30c2c (shared `FileContents` authority, size read from the bytes).
  Next full gate: every prior red MATCH; one new load-only red,
  `setidthreadchurn` (gnu lane, guest SIGSEGV, 0 observations; passes
  alone 2/2) — root-cause worker dispatched with a load reproduction and
  a bisect across the day's thread-lifecycle landings.
- (2) round 1 LANDED (9b3055d11): FsView signal helpers are shared free
  functions; net and signal route through NetView/SignalView. Round 2
  (proc, ipc, mem) in flight.
- `setidthreadchurn` LANDED (66fe4d7af): an exiting thread is retired from
  the task graph (peer tgkill → ESRCH) BEFORE its child-tid futex wake and
  runtime withdrawal; glibc's setxid signal could previously land on a
  stack the guest had already reclaimed (SignalDeliveryFault → SIGSEGV).
  3/3 alone, 10/10 under load per the worker; deterministic integration
  test pins the order.
- (2) COMPLETE (ad248a618): proc, ipc and mem route through ProcView /
  IpcView / MemView. Landing note: the abort ledger and the dispatch-lock
  and K1 inventories key rows by qualified function name, so a handler
  moving from `SyscallDispatcher::x` to `MemView<'a>::x` needs its rows
  re-keyed (done by fingerprint + ordinal at landing). `too_many_arguments`
  allows are still 101 — the workers routed handlers but did not use the
  views to delete the allows; that is a bounded follow-up.
- (3) dispatched (`typed-error-debt`).
- (3) LANDED (57de08799): 22 of the 27 `typed_error_debt` rows converted
  to their named typed errors (KernelOperationError, RuntimeError,
  LinuxErrno, ArenaError, ThreadExecutionError; the wait reactor
  constructor is fallible and the scheduler propagates it); 5 rows remain
  in runtime.json with the worker's reasons in its report — a bounded
  follow-up. Every generic probe shard MATCHed in the phase-2d gate (first
  zero-DIFF generic run). The legacy CLI step of the gate was red on two
  pre-existing bookkeeping items: the probe-source denominator (531 sources
  vs a 527 constant, four sources added 2026-09-10 by sibling sessions) and
  the three quarantined probes with no blessed oracle since 2026-09-08.
  Blessing them (arm64 only; a Rosetta amd64 container hung and was killed)
  found: `tlbibroadcast`/`windowcoherence` print non-deterministic
  telemetry (probe defect, being fixed) and `ppollwaitset` exposes a real
  runtime bug — poll on an unconnected stream socket must be POLLHUP
  immediately (worker dispatched).
- Legacy lane LANDED (eddeef6b7): denominator 531 with the four new sources
  classified; `tlbibroadcast`/`windowcoherence` no longer print
  non-deterministic telemetry and MATCH on both arm64 lanes with freshly
  blessed oracles; `ppollwaitset` is bounded (5 s caps, 4 s writer) and
  blessed, and stays red until the POLLHUP runtime fix lands (worker
  running). No known-gap excuse was added anywhere.
- ppollwaitset LANDED (f2e69c86c + 85d8f3240, reconciled f9a240698): the
  runtime now reports POLLHUP immediately on an unconnected stream socket
  (`connected` on the open description; readiness and the wait authority
  consult it). Probe-design finding: the probe put that unconnected socket
  in EVERY wait set, so on Linux cases (b)..(g) returned at once and never
  tested a blocking wait; the blessed oracle recorded them all false. The
  probe now keeps the unconnected socket only in case (a) (pinning the
  answer that exposed the bug) and uses a connected AF_UNIX socketpair end
  for the blocking cases; raw timings are gone and the two threshold lines
  the Docker oracle itself missed under load (30 ms timeout inside 28..33,
  SIGALRM wake under 10 ms) became "never early" and "under 500 ms".
  Re-blessed arm64 musl+gnu (every semantic line true on Linux); carrick
  PASS/MATCH on both lanes. The legacy lane has no open red.
- Cleanup: 7 orphan worktree directories (one holding an 11 GiB stale
  build), 64 merged worktrees and 46 merged branches removed; 94 GiB of
  stale `target/debug` cleared before the confirming `just ci`. Left in
  place: unmerged opus/codex/agy branches with commits ahead of main (other
  sessions' work), `codex-hybrid-kernel` (root-owned lldb cores) and the
  root-owned 12 GiB `asid-wedge` core cited by the 2026-08-22 audit.
- Item 4 started: paired interleaved scorecard armed
  (`target/conformance/eco-load/paired-sep11.sh`, summary
  `paired-summary.py`): base = pinned 62c63d979 binary afccec0cc339993c,
  cand = pinned current main, w4 x3 reps with alternating order, then w1,
  quiet-gated before every phase. Workers are dispatched only after it
  finishes (their builds would contaminate it).
- Gate receipt on main 541a575ff (binary sha256 3c8dbee5b686c49d, CDHash sha256=cced55bc2,
  hypervisor entitlement present, `__dof_carrick` present): `just ci`
  EXIT 0 (target/perf/ci-ppoll-sep11.log, after clearing target/debug so
  every crate rebuilt from scratch) and `just conformance-probes` EXIT 0
  (target/perf/probes-ppoll-sep11.log; every generic shard and the legacy
  CLI step green, no gating DIFF). Pushed to origin/main
  (01f812101..541a575ff). Residual: the report-only amd64:musl lane still
  shows a stale ppollwaitset oracle carrying the old probe's panic text
  (non-gating, no native amd64 bless host here; root@carrick-x86 and
  willow VM 210 are candidates for a native amd64 oracle later).

## Phase 3 — the reviewer's 2026-09-11 progress vet (feedback.md v2)

The updated feedback.md scores phase 1: god files 60K→12K, DSR removed,
`carrick_fatal!` landed, wait variants unified, CLI/exec duplication gone,
LOC −88K. Its "next tier" list, mapped to workers (one worktree each,
`.worktrees/agy-<name>-sep11`, model 3.8 flash high), all file-disjoint so
they run in parallel with the perf2x clusters:

| feedback item | worker | fence |
|---|---|---|
| continuation.rs 12.1K | `split-continuation` | vcpu_loop/continuation{.rs,/} |
| kernel/operations.rs 11.8K | `split-operations` | kernel/operations{.rs,/} |
| kernel/objects.rs 10.2K | `split-objects` | kernel/objects{.rs,/} |
| fs_backend.rs 10.8K | `split-fs-backend` | fs_backend{.rs,/} |
| vcpu_loop/executor.rs 10.8K | `split-executor` | vcpu_loop/executor{.rs,/} |
| dispatch/mem.rs 10.3K (+10.3K tests) | `split-mem` | dispatch/mem{.rs,/} |
| 98–101 `too_many_arguments` | `tma` | every allow outside the split files |
| syscall tables keyed by bare numbers | `syscall-names` | carrick-abi + `syscall_table!` arms (mem.rs deferred) |
| 32 residual `process::abort()` (27 outside carrick-fatal; most are test-only `unwrap_or_else`) | `fatal-residue` | site files outside the split files |

Deferred to a second round (needs the splits landed first): the ~6K raw
`as` casts (typed conversions per file, starting with mem/net/continuation/
executor), `RunSpec` grab-bag and embed builder consistency, the second
`SyscallDispatcher` decomposition step (19 fields → per-view state), and the
remaining `SharedFutex*` outcome grouping. Item 10 (macOS anti-patterns) as
listed in v1 was `tokio`/env hacks in the CLI (T17 landed) and named-user→
root (T6 landed); the v2 "unchanged" verdict predates re-reading those
commits and is re-checked at the next vet.
- Item 4 re-baseline DONE (ecosystem doc "2026-09-11 16:20"): 88/88 MATCH,
  candidate ≤ base on 10/11 rows paired (multiprocessing 0.63, importlib
  0.69), net_http 1.06; 3/11 rows ≤2x unchanged. Profiles of compile,
  multiprocessing, tarfile, importlib on the candidate binary follow, then
  the perf workers are dispatched alongside Phase 3.
- Profiles on the candidate binary (carrier user-CPU ranking, quiet host,
  `target/perf/perf2x-sep11/*.rank`, aggregator `rank-agg.py`):
  - compile (17.4 s): 86% under `munmap` → `commit_process_alias_retirement`
    → `TaskMappingIndex::retain` full walk + `Vec::from_iter` per unmap
    (O(rows) per munmap → O(n²)). Worker `alias-retain-index`.
  - tarfile (22.4 s, sys 7.2 s): host `openat` is the leaf of 48.5% of
    samples; unlinkat/rmdir 37.5%, mkdirat 23.6%; `HashMap::retain`
    prefix-scan cache eviction 12.5%; `std::path::Components` 17%. Worker
    `hostfs-amplification` (dentry parent dirfd = one `*at` per op; ordered
    cache; no re-normalize). `split-fs-backend` deferred behind it.
  - importlib (5.9 s): `dispatch_threaded_futex` → guest read →
    `AliasRegistry::newest_containing` 18.5% (window bounded by the widest
    row, not by the answer); poll/psynch waits 22%. Worker
    `alias-newest-index` (width-class containment index).
  - multiprocessing (8.1 s, user 10.3 s): 73% of carrier user CPU is guest
    execution (`hv_trap` leaf), syscall service 15% (openat 5.8, fault 4.7,
    getdents 3.7). Not a carrier-CPU cluster; a Docker-side CPU comparison
    of the same row is running to separate "guest does more work" (spinning)
    from "carrier adds work" before a worker is briefed.
- Dispatched 2026-09-11 16:30 (AGY_RUN_ID=feedback-sep11, 90 min budgets):
  split-continuation, split-operations, split-objects, split-executor,
  split-mem, tma, syscall-names, fatal-residue, alias-retain-index,
  alias-newest-index, hostfs-amplification. Director verification for the
  perf three = paired interleaved A/B of the row on a quiet host after the
  Phase 3 landings.
- multiprocessing finding: the row is a PARALLELISM defect, not per-op CPU.
  Docker runs the test in 2.9 s wall with ~14 s of user CPU (rusage of the
  container's children; CPU measured under load, wall from the cached
  oracle), i.e. ~5 cores busy; carrick takes 7.6 s wall for 10.3 s user
  (1.3 cores). The guest does no more work under carrick; its child
  processes do not run concurrently. Next instrument (quiet host, after the
  workers finish): per-task syscall flow / executor claim sequence during
  the row to name what serializes fork+exec children (carrier topology lock,
  PtQuiesce election, fork admission, vCPU leases are the candidates).
- Rearchitecture plan for the parallelism defect written and pushed:
  `docs/superpowers/plans/2026-09-11-per-mm-topology-authority.md`
  (measure first; two-process red-first tests; typed per-mm and leaf
  registry authorities replace the carrier topology mutex site by site;
  per-mm alias containers; per-parent-mm fork flag and coordinator;
  exposed-CPU policy decision; paired-scorecard acceptance). Research
  facts behind it: the page-table pause is already per mm (mm-scope,
  09-07); no production `hv_vm_destroy` exists, so the mutex's founding
  reason is dead; fork holds it ~4 ms mean, exec ~1.6 ms, exit across a
  ~265-line transaction; the fork barrier's `quiescing` flag is one
  carrier-global bool every executor reads; one process-fork coordinator
  per carrier. Tasks 1 and 2 dispatched (`mm-two-process-tests`,
  `mm-topology-guards`); Tasks 3–6 wait for the split/perf landings that
  own the same files; Task 0 (traces) runs on the next quiet host.
- Worker round 1 (90 min budgets) outcomes: alias-retain-index and
  alias-newest-index done and reviewed. Review finding on alias-retain: the
  keyed removal discovered candidates by the SEMANTIC IPA index while the
  retirement predicate matches the PHYSICAL stage-2 extent; the worker's
  red-first differential test against an unconstrained full-walk reference
  failed (`ref=5 keyed=6`, a missed row), and an explicit
  projection-inside-physical-extent assertion failed an existing custody
  test, so a `by_physical` index now feeds discovery too (de7e8fde0). On
  alias-newest: the legacy `by_va_start`/`by_ipa_start` maps were kept
  beside the class index (double maintenance); deleted in 6d625c8bc.
  The five splits each committed one submodule before the budget and were
  re-tasked to continue at green boundaries; tma deleted 9/101 allows (CLI
  only) and continues into the runtime; hostfs-amplification landed the
  right shape but with a `serves_dentry_cache()` if/else (a second path),
  three copies of the parent-resolution logic, `.ok()`-swallowed dirfd
  errors and no red-first numbers — re-tasked; syscall-names and
  fatal-residue are in director verification for landing.
- Landed and pushed 2026-09-11 (evening): alias-newest-index (width-class
  alias containment index, legacy maps deleted), alias-retain-index (keyed
  extent removal with the physical index the review demanded), fatal-residue
  (27 raw aborts → carrick_fatal! or a test helper; the 10 left sit in the
  split files), syscall-names (`carrick_abi::syscall::nr` typed constants;
  mem.rs arms still literal until its split lands), hostfs-amplification
  (one `*at` host call per mutation on the dentry-held parent, ordered
  caches, per-directory generations; red-first 1,250→250 host opens and
  34,500→500 eviction visits per 1,000 ops). The perf effect of the three
  clusters is unmeasured until the host is quiet: next paired run is
  compile/tarfile/importlib against the pinned 3c8dbee5b686c49d binary.
  Splits in flight (third turns): operations 11.8K→6.1K, mem 10.3K→8.3K,
  objects 10.2K→8.8K, executor 10.8K→6.8K, continuation 0 commits (ordered
  to commit). tma 101→66 allows. Per-mm plan: Task 1 tests and Task 2
  guards verified and queued to land.
- Landed and pushed (night): split-executor (10,804 → 1,131 lines; two
  continuation.rs source-shape tests repointed at the new submodules by the
  director), split-operations (11,762 → 2,974; six submodules), per-mm
  Task 1 tests (`perf_forkstorm` + `two_process_parallelism`, red numbers
  pending a quiet host) and Task 2 guards (`MmMutationGuard::
  begin_transaction`, `FrameRegistryGuard`, VM-rebuild rationale deleted).
  Task 3 (frame publication under the registry leaf) is green on its
  branch and on a follow-up to also take the leaf inside the fork/exec/exit
  reservation steps before it lands (otherwise COW publication and fork
  reservation stop excluding each other on the shared-frame registry).
  Continuation split: the worker produced no commit in three turns; the
  director committed its compiled `quantum` submodule (12.1K → 10.5K) and
  started a fresh conversation on the same worktree.
- Per-mm Task 3 LANDED (393340069): mmap alias install and the COW/
  materialize paths publish frames under `FrameRegistryGuard` (a leaf)
  instead of the carrier topology mutex; fork, exec and exit also take the
  leaf around their frame-inventory reservation/retirement steps so the
  two sides keep excluding each other on the shared-frame registry until
  Task 4 removes the mutex from those transactions. Landing note: the
  abort ledger refused fingerprint drift on the fatal statements the guard
  now wraps (binding.rs exit retirement #5–#7, exec.rs drive_execve #3,
  mod.rs redispatch alias install) — re-blessed with sink/domain asserted
  equal per row (that refusal is the review gate working as designed).
  The executor-lane retirement site is Task 4's.
- Landed and pushed (late night): split-objects (10,187 → 2,851; six
  submodules), split-fs-backend (10,821 → 1,035; host/memory/path/tests),
  split-mem (12,097 → 2,318; brk/madvise/vma/fault/backing/mmap with
  per-submodule tests). Landing note for split-mem: the reconciler
  refuses rows whose OWNER changed, not just their position — membarrier
  became `MemView::membarrier` in mem/madvise.rs, mmap's call sites moved
  to mem/mmap.rs with identical texts (ambiguous 1:N), and a test helper
  was renamed to its `_with_source` delegate; re-keyed by hand with the
  reason in the commit. Every file the 2026-09-11 vet listed above 10K
  lines is now under 3K except continuation.rs (restart in progress).
  tma at 101 → 32 allows (17 commits) is landing; `syscall-names-mem`
  dispatched to finish the memory tables and delete the literal-arm macro
  variant now that the split has landed.
- tma landing note: a 17-commit branch rebased over the mem split, Task 3
  and alias landings needed three hand resolutions — main's moved test
  block (kept main's layout and re-applied the four `ThreadCtx::new`
  call-site edits where the tests now live), and in cow_engine.rs and
  foreign_mm.rs the Task 3 `drop(registry)` beside tma's new
  `CowInventoryLifecycleScope` binding. Long-lived worker branches over a
  fast-moving main pay this at landing; land smaller batches sooner.
- tma LANDED (4308621ca): 101 → 32 `too_many_arguments` allows over 17
  commits (CLI/embed/conformance, file_authority, dispatch/execution,
  observability probes, runtime.rs, vcpu_loop signal/mod/binding, trap,
  vfs/inotify). Remaining 32 are a bounded follow-up on fresh main.
  Per-mm Task 4 (`mm-transactions`: fork/exec/exit/unmap hold their mm's
  transaction guard plus the registry leaf; the carrier mutex loses its
  production callers) dispatched now that Task 3, the executor split and
  tma are all on main.
- Landed and pushed (early 2026-09-12): split-continuation quantum
  submodule (12,097 → 10,549; the global-state ledger keys statics by
  file, so `NEXT_RUNNER_JOB_ID` was re-homed by hand) and
  syscall-names-mem (decc8aca0: every routing arm now names its
  `nr::` constant; the literal-arm macro variant and its
  `#[allow(unreachable_code)]` are gone; a routing characterization
  fixture pins the handler set). Running: `mm-transactions` (per-mm Task
  4) and `split-continuation-r3` (three named moves: tests, wait service,
  readiness). Still queued behind them: Task 6, the 32 remaining
  `too_many_arguments` allows, and the quiet-host measurements (Task 0
  traces, the two-process red numbers, paired A/B of the three landed perf
  clusters against 3c8dbee5b686c49d).
- 2026-09-12 morning: per-mm Task 4 LANDED (5149bba88): fork, exec, exit
  and unmap hold their mm's `MmTransactionGuard` (minted from the stage-1
  authority) plus the registry leaf; the executor-lane retirement backoff
  helper is deleted; `acquire_topology_lock` has no production caller.
  Landing needed the abort-ledger re-bless (fatal statements re-tokened by
  the guard) and dropping the retired host-authority rows of the deleted
  helper by hand. split-continuation-r3 LANDED (28d625f3f): continuation.rs
  12,097 → 2,176 with quantum/tests/wait_service/readiness submodules —
  every file the vet listed above 10K lines is now under 3K.
- Probe-gate stall (7h47m): on a cache miss the legacy harness ran the
  amd64:musl lane's probe live under a Rosetta container (the stale
  ppollwaitset amd64 oracle had been deleted on 09-11), which never
  returned. Fixed forward (13aad0ba8): a live Docker oracle is attempted
  only for the host's own ISA; a foreign-platform miss is Unblessed
  (report-only NOTE) and must be blessed on a native amd64 host
  (root@carrick-x86 / willow VM 210). The `--platform linux/amd64` path in
  `bless_probe_oracle` is the same class and is next.
- OPEN observation: `tlbibroadcast` (arm64 musl) TIMED OUT at 45 s with
  empty stdout once in the Task 4 gate, under a concurrent worker build and
  eight gate workers; 3/3 PASS in isolation on the same binary, gnu lane
  passed in the gate. Load-coupled, not dismissed: if the full gate rerun
  reproduces it, take a core of the carrier and the per-task syscall-flow
  trace before any fix; the probe spins a sibling vCPU with no syscalls
  while the main thread mprotects/munmaps, i.e. exactly the per-mm pause
  path Task 4 touched.
- REGRESSION found by the sep12 measurement block: on every binary from
  the Task 4 landing (5149bba88) onward, `python3 -m test
  test_multiprocessing_main_handling` on the `--fs host` cpython image
  wedges at interpreter startup — the per-task syscall-flow trace shows
  pid 1 parked in `openat` (nr 56, AT_FDCWD, O_CLOEXEC) after 2,557 completed
  syscalls; the event ring holds only pid 1's fd churn (no fork yet); all 18
  executors idle in `RunQueue::take`; the kernel debug server times out.
  Core: `target/perf/perf2x-sep12/mp-wedge-14703.core` (+ `mp-wedge-bt.txt`,
  `mp-wedge-ring.txt`, `mp-wedge-flow.out`). Trivial guests (`python3 -c`,
  `/bin/sh -c echo`) and every probe lane pass on the same binary; the
  pre-cluster control binary (3c8dbee5b686c49d, 541a575ff) runs the row in
  7 s. Bisect in progress between 541a575ff and 5149bba88 with signed
  builds, filesystem landings (hostfs-amplification fe9ceb4d6, fs_backend
  split 32d32d44a) first. The sep12 measurement block is void until this is
  fixed; the stall watch's guest threshold is being lowered to 10 minutes.
- Post-mortem of the openat wedge (owner: post-mortem first, bisect second):
  the core's `bt all` had ONE non-idle thread — `carrick-executor-4` in
  `RawMutex::lock_slow` under `commit_process_alias_retirement`, reached
  from `mmap` → `materialize_private_file_backing` →
  `materialize_sparse_mmap_extent_inner` (holding `FrameRegistryGuard`
  since Task 3) → `publish_replacing`. Task 4's unmap step (6ede8db7d)
  made the commit take `frame_registry_lock()` again: a self-deadlock on
  the non-reentrant leaf, on every private file-backed `mmap` that
  replaces live rows (Python loading `_bz2`). My first stack summary had
  filtered `parking_lot` frames and reported "all executors idle", which
  cost an hour of bisect builds that then converged on the same commit.
  Fix forward: the commit takes the caller's `&FrameRegistryGuard` as
  proof and never locks the leaf (the rule is now the signature); shape
  test red on 5149bba88, green after; live receipt = the row completing on
  the rebuilt binary, then the full probe gate.
- Wedge FIXED and landed (c1a967fc0): `commit_process_alias_retirement`
  takes the caller's `&FrameRegistryGuard`; live receipt — the
  multiprocessing row that wedged on every binary since 6ede8db7d
  completes in 6.3 s on the rebuilt binary e40b856312ac253b; `just
  conformance-probes` EXIT 0 on main (target/perf/probes-fix-sep12.log);
  denominator test fixed (8dfc069b7, 532 sources). The sep12 measurement
  block is rerunning on that binary; Task 6 and the allows round dispatch
  after it. Leaf rule for Tasks 5–6, now in the plan memory: a callee
  never locks the frame-registry leaf; it receives the guard.
- Second Task 4 defect, found by the sep12 scorecard rerun and fixed
  forward (3e69641b5): `go-net_http` hung [blocked] at four workers (twice)
  and, standalone, died with `acquire exact-MM terminal authority failed:
  UnkickableExecutor` → `CarrierFailed` at test 754/1,388 — the exit path
  had been made to elect a stage-1 pause over sibling executors that
  `exit_group` had already put beyond kicking. The terminal retirement
  edits no live stage-1 table, so it now mints its transaction from
  `mm_mutation::terminal_process_transaction()` (depth + registry leaf, no
  pause); the exit shape test forbids `acquire_mm_stage1_authority` there.
  Attribution: pre-Task-4 pinned binaries pass 1,388/1,388, the Task 4
  binary dies at 754. Receipts on the rebuilt binary 4843f86387c98083:
  go-net_http PASS ×3 (1,388 each), multiprocessing SUCCESS 6.4 s,
  `just conformance-probes` EXIT 0 (target/perf/probes-exitfix-sep12.log).
  Embed tests restructured around one carrier (cf5c08042). Measurement
  block re-armed on this binary; Task 6 and the allows round follow it.
- PERF REGRESSION found by the rerun scorecard: cpython-compile 17.5 s →
  175.9 s at four workers and 14.3 s → 175.6 s standalone (173 s user
  CPU) on the fixed binary. Carrier CPU ranking on the row: 95.5% under
  `TaskMappingIndex::remove_rows_matching_in_ranges`, 90.8% as its own
  leaf — the alias-retain-index landing (e91947203) bounded candidate
  discovery by the WIDEST live row (`max_ipa_span`/`max_physical_span`),
  so one large row makes every munmap walk the whole index with a
  BTreeSet insert per key: worse than the linear `retain` it replaced,
  hidden by tests that generate uniformly small rows. Same class the
  alias-newest fix closed with width-class partitions; worker
  `alias-retain-r2` dispatched with a red-first huge-row visit-count test.
  The other four rows improved in the same rep (tarfile 0.74x, importlib
  0.89x, multiprocessing 0.94x, net_http 0.94x paired).
- Attribution confirmed by pinned binaries (standalone compile row):
  541a575ff 14.3 s; 5f4b957fd (alias-newest + alias-retain landed) 182.8 s;
  fe9ceb4d6 174.0 s; 5149bba88 wedges (the openat deadlock). The 12x is
  the alias-retain-index landing's widest-row window.
- Compile regression FIXED and landed (874056e25): `TaskMappingIndex`
  discovery is partitioned by width class (`TaskMappingClassIndex`,
  mirroring `AliasClassIndex`); red-first huge-row test (32 GiB row +
  4,096 small rows: thousands of visits before, 1 after), 2,000-case
  differential green. Live receipt on d286e85eabab67f4: the compile row
  standalone 7.86 s wall / 7.05 s user — vs 14.3 s on the pre-cluster
  control and 175.6 s on the regressed binary — the keyed retirement now
  pays off (≈1.8x faster than base on this row). Probe gate rerunning;
  paired scorecard to be rerun on this binary.
- Item 4 scorecard on the compile-fixed main (ecosystem doc "2026-09-12
  11:33"): 40/40 MATCH; every targeted row faster paired — compile 0.58,
  tarfile 0.68, importlib 0.82, multiprocessing 0.90, net_http 0.90;
  importlib ≤2x at one worker. Task 6 and the allows round dispatching.
- 2026-09-12 12:35: per-mm Task 6 landed and pushed (4242d0229) — fork
  quiesce is per parent mm, fork kicks only sibling threads; receipts in
  the per-mm plan's Measurement section (mp 6.94 s, net_http 8/8 PASS,
  fault-latency embed test 154 s→37 s). Probe gate running on the pinned
  main e32d0b3e1851faef; Task 5 (per-mm alias containers, delete the
  carrier topology mutex) dispatched; `tma-r2-sep12` still running.
- 2026-09-12 13:40, probe gate on e32d0b3e1851faef (post-Task-6 main) RED:
  2 of 46 tests. (a) `conformance_container_gate`: alpha
  `child_comm_visible=false` — PROBE race (parent scanned /proc before the
  forked child ran `prctl(PR_SET_NAME)`); 8/8 green standalone on both the
  new and pre-Task-6 binaries; fixed with a pipe rendezvous + bounded poll
  (528cc75c0), gnu probe rebuilt, both gate modes report
  `child_renamed=true`. (b) `arm64:musl:execfromthread` kernel abort
  `lost exact transition: thread#2:<old serial> Runnable N -> N+1 rejected
  while the kernel graph still calls it reachable; registry view: thread
  absent; same-tid threads=[2:136]`. PRE-EXISTING and LOAD-DEPENDENT: 8/8
  green standalone on both binaries; under eight concurrent runs 1/24 on
  the NEW and 1/24 on the OLD binary (post-mortems
  `target/perf/perf2x-sep12/eftpm/efts-{new,old}-2-6/`), plus a second
  shape on both binaries (8/48): `carrick fatal [hvpatch::mm_authority]:
  drop HVPatch MM authority (phase=active … holder=registration-cleanup)`
  preceded by `executor failed a claimed task … reason=AddressSpaceRetired`
  on the retired leader (tid 2). Reading: exec-from-a-non-leader-thread
  relies on each sibling's host loop to retire its own kernel thread
  (`publish_persistent_sibling_stop` → `remove_all_except` + kick;
  `finish_persistent_process_handles` settles member completions
  externally), so a leader whose executor claim is still in flight stays
  `Runnable{requeue_pending}` in the task graph after the exec replaced its
  registry entry; its late requeue is a lost exact transition (exit 125)
  and its late load fails `AddressSpaceRetired` and drops the shared MM
  authority still `Active` (exit 134). Linux `de_thread` waits for the
  siblings; carrick's drain does not wait for the kernel-graph settlement.
  Evidence tooling added so the next reproduction yields a core:
  `carrick debug lldb-run --fatal-hold-seconds` + `CARRICK_FATAL_HOLD_SECS`
  (d6db89efc). 96 further lldb-run stress runs reproduced only the 125
  shape (4×, post-mortem JSON, `target/perf/perf2x-sep12/eftcore{3,4}`).
  Fix dispatched as a red-first worker task (brief `exec-sibling-settle`).
