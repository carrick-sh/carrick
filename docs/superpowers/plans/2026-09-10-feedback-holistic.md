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
