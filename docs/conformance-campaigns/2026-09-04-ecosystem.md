# Ecosystem conformance and wall-time campaign

## Contract

Reach 100% executed assertion-level ecosystem conformance, then bring successful
non-timeout ecosystem workloads below 2x native-arm64 Docker wall time. Retain
the frozen 2,127-suite scope (438 CPython, 194 Go, 1,492 LTP, 3 Node) while
checking current suite declarations and image identities for drift. A match
that skips assertions, an expected gap, an oracle failure, or a timeout does
not close coverage. Timeouts are correctness failures, not performance ratios.

Use `carrick-conformance-next` and `carrick-embed` for reductions, debugging and
regression. Exact cached-oracle probes and focused property tests expand
confidence where they expose otherwise untested semantics. Docker is a separate,
serial oracle/cache-refresh phase; ordinary reducers use existing local images
and committed oracle data. Runtime fixes and acceptance belong to Codex.

Antigravity receives only independently verifiable mechanical probe/test work
in isolated worktrees. Codex reviews actual diffs, reruns gates, and integrates
accepted changes. No push is authorized.

## Starting evidence (2026-09-04)

Clean main at `05316a669`. The root handoff predates the newer FD-seam progress
ledger and recent carrier-kernel changes; do not resume its obsolete runtime
blockers without reproduction.

- Historical `target/conformance/results.hvf.full.jsonl` contains 2,127 unique
  suites, dated August 30. Its counts are discovery evidence, not current HEAD
  acceptance: CPython 397 match / 16 timeout / 14 crash / 11 regression;
  Go 178 crash / 15 timeout / 1 regression; LTP 1,334 match / 112 regression /
  12 diff / 24 timeout / 10 new; Node 3 regression.
- September 4 smoke receipt has 21 match and 2 timeout (`go-build`,
  `cpython-subprocess`). Neither current correctness nor performance is closed.
- Latest filtered receipt reports `cpython-concurrent_futures` regression,
  including forkserver `BrokenProcessPool` failures and a child segmentation
  fault during extension import. Its 489,833 ms / cached 75,826 ms ratio is
  attached to a failing workload and is not accepted performance evidence.

## Current work

1. Reproduce one forkserver result-pickling failure through a signed embed test
   (`ecosystem_cpython_forkserver_result_pickle`), using only the local CPython
   image. Narrow further based on actual failure; no speculative runtime fix.
2. Antigravity `streamdestmatrix`, conversation
   `8247df96-344c-4b22-b9c2-473d306bc80d`, run `ecosystem-sep04`, isolated at
   `.worktrees/agy-ecosystem-net-sep04` on starting HEAD. Scope is one probe
   source for connected TCP/UNIX sendto and getpeername semantics. No Docker or
   guest runs by worker; Codex owns wiring, oracle qualification and acceptance.
3. After focused closure, refresh the full assertion ledger on one identified
   signed artifact. Verify source HEAD, executable SHA-256/CDHash/LC_UUID,
   entitlement, DOF and run-scoped cleanup. Verify declared images and oracle
   source hashes; deliberately refresh only invalid or new oracle entries.
4. After correctness closure, measure successful non-timeout workloads on a
   quiet host, Carrick and native-arm64 Docker serially, retaining individual
   and ecosystem aggregates plus cold go-build. Cached historic times alone
   cannot establish the final below-2x gate.

## Open acceptance gates

Focused reducer red/green and adjacent regressions; reviewed delegated probe;
unfiltered signed probe gate; full 2,127-suite assertion coverage; current image
and oracle identity; controlled below-2x performance; required host checks;
final signed artifact provenance and scoped cleanup. None is claimed closed by
this campaign initialization.

## Updated operating instructions

The owner broadened delegation to code implementation, with Codex retaining
runtime diagnosis, architecture, diff review, gate reruns and acceptance. Use
isolated Antigravity worktrees. Prefer `carrick trace`, `carrick debug` and saved
core/post-mortem analysis over attaching to running processes. Improve durable
development tools when a demonstrated deficiency blocks this loop. Make logical
commits as changes pass their relevant acceptance gates.

## First reductions and review (in progress)

- The isolated CPython unittest reproduces in 1.83 seconds through signed embed;
  its native-arm64 Docker counterpart passes (1 test, 0.062 seconds, image ID
  `sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30`).
  This pair is diagnosis, not a performance measurement (host test profile and
  different harness overhead). No routine Docker dependency was introduced.
- Existing mmap diagnostics identify a sparse materialization lookup returning
  view VA `0x40002f8000..0x40002fc000` for request VA `0x60010f0000`, selected
  through live IPA `0x9d251bc000`. Host regression
  `semantic_lookup_rejects_foreign_va_alias_at_same_live_ipa` is red before the
  candidate correction and green after. Signed embed then loses the mmap
  refusal but still has a child extension-import SIGSEGV. **Not closed.**
- `CARRICK_FAULT_DEBUG` records thousands of recoverable write faults before
  the useful fault. The first unrecovered-looking read fault is ESR
  `0x92000007`, loader PC `0x8c0000cbc4`, FAR `0x8`, x0=0. Static LLDB
  disassembly of the exact image loader shows `ldr x9, [x0, #8]`; further
  evidence is required before attributing the missing dynamic-loader state.
- The mounted artifact directory stayed empty; no core is available yet.
  Default warning logging reports no core-publication failure. This is an
  open observability question, not evidence that no crash occurred.
- Antigravity's first network probe was reviewed, returned once for partial
  reads/exact errno/destination isolation, cross-built by Codex, and qualified
  twice per libc in a serial Docker-only phase. Cached embed finds a real
  short-sockaddr connected-TCP sendto gap (Linux writes 17 bytes, Carrick EINVAL).
  Worker now owns a narrow runtime fix and expanded argument matrix; its first
  runtime revision was returned for zero-length semantics, host-vs-Linux bounds,
  provider remapping, and a reintroduced hardcoded UDP destination. Not accepted.
- Antigravity `mm-lookup` independently reviews the copied MM candidate in
  `.worktrees/agy-ecosystem-mm-sep04` and expands production-path identity tests;
  it may edit only `crates/carrick-vmm-hvf/src/trap.rs`.

Receipts are currently `/tmp/carrick-ecosystem-sep04-{pickle-host,pickle-mmap,
pickle-bounds,pickle-fixed,pickle-fault,core-warn,va-red,va-green,network,
pickle-oracle}.log`. Signed wrappers run the unsigned negative control and
verify run-scoped cleanup. The initial sandbox-only run failed before any guest
execution; its cleanup could not enumerate processes and is not a valid receipt.

## Reviewed candidate checkpoint

- The expanded `streamdestmatrix` oracle contains 92 deterministic lines per
  libc, source hash `e87404e6ac445679`; two native-arm64 Docker runs per libc
  agreed. The pre-fix runtime fails zero/short TCP address lengths, oversized
  addresses, and zero-length UNIX destinations. The reviewed fix passes both
  cached libc rows. SCTP retains its prior parse/provider/connected-send path.
- MM review additionally rejects a live stage-1 mismatch instead of falling
  through to a stale VA-only row. Six production-path host regressions pass;
  the adjacent foreign-MM module reports 63 passed and one existing ignored
  test. The combined signed socket/fork/mmap selection executes 22 cached rows
  successfully, with the entitlement negative control and scoped cleanup.
- The CPython reducer passes twice after this stronger lookup correction.
  Restoring only the stale VA-only fallback reproduces the extension-import
  SIGSEGV (3.64-second failing run); restoring the correction passes again.
  This closes the focused reproduction, not the full
  `cpython-concurrent_futures` suite.
- Formatting, strategy enforcement and runtime/HVF library Clippy pass.
  Sandbox Clippy initially failed because DTrace could not generate USDT
  providers; the same check passed with host authority.
- `carrick trace` core-lifecycle diagnostics record two successful core
  publications, despite an empty host bind mount. Static inspection finds
  publication and rollback directly targeting the root overlay rather than
  mount routing. The trace profile expects exactly one core, so it rejects
  this two-core capture; its summary is diagnostic, not profile acceptance.
  Isolated Antigravity `core-publication`, conversation
  `929e4131-e022-4de3-9619-5a44b9ed8ccd`, now owns that bounded repair and host
  failure-path regressions. It is not yet integrated.

Additional logs use `/tmp/carrick-ecosystem-sep04-` with suffixes
`network-expanded-red.log`, `network-expanded-green.log`,
`mm-reviewed.log`, `mm-adjacent.log`, `mm-net-adjacent.log`,
`runtime-clippy-host.log`, `pickle-reviewed.log`, and `core-trace.log`.
Candidate signed artifact inventories are copied under
`target/conformance/ecosystem-sep04-receipts/`. These are dirty-source focused
receipts; the final clean-artifact, unfiltered, full-suite and performance gates
remain open.

The socket correction and cached matrix are committed as `d63a89de8`. Additional
MM attribution logs are `pickle-repeat.log`, `pickle-fallback-red.log`, and
`pickle-restored.log` under the same `/tmp/carrick-ecosystem-sep04-` prefix.
The current arm64 full-module cache contains 239 assertion IDs, but 205 are
classified `other` (20 `ok`, 14 `skipped`), including its `closure-v1` row.
That cache cannot establish final assertion closure. Antigravity
`ecosystem-reducers` (`45ec01b2-8a36-4c46-be40-398fa317cedd`) is adding a bounded
full-module embed test with transcript retention; actual assertion parsing and
oracle requalification remain Codex acceptance work.

## Broader probe gate and oracle accounting

At `f82349e98`, the unfiltered cached generic embed gate executed 836 distinct
rows (418 musl and 418 GNU), with zero diffs. The unsigned negative control and
run-scoped cleanup passed. Receipt:
`target/conformance/ecosystem-sep04-receipts/cached-all-artifacts.jsonl`; log:
`/tmp/carrick-ecosystem-sep04-cached-all.log`. This excludes retained live-oracle
and process-boundary lanes and does not close ecosystem conformance.

The full local host gate passed formatting, workspace Clippy, strategy/shard
checks and preceding domain audits, then stopped at host-authority inventory
drift. Recorded compiler call-site locations need reviewed reconciliation;
cross-platform profiles must remain explicitly pending. Log:
`/tmp/carrick-ecosystem-sep04-ci.log`.

CPython emits elapsed times before outcomes and occasionally before the next
test name, plus two-line docstring descriptions. The old parser both classified
valid outcomes as `other` and omitted whole identities. The reviewed parser
now accounts for all 255 tests in the earlier failing transcript: 232 pass,
18 skip, four errors and one failure. Both regression and closure modes retain
the complete identities; incomplete descriptions remain `other`.

A fresh, separate native-arm64 Docker phase on the recorded CPython image
completed the exact declared `test_concurrent_futures` command with exit 0:
237 pass, 18 skip, all 255 identities classified. Only that suite's two arm64
oracle entries (regression and closure) were refreshed. The 80,405 ms elapsed
time is diagnostic because host builds were active; it is not controlled
performance evidence. Raw transcripts, image/argv/hash receipt and parsed maps
are `target/conformance/ecosystem-sep04-cpython-oracle.{stdout,stderr,json}` and
`target/conformance/ecosystem-sep04-oracle-{regression,closure}.json`.

Independent host checks passed all 192 conformance-package tests and 16 embed
transcript tests. The full-module embed wrapper requires completed unittest
blocks and a terminal regrtest success, retains transcripts before assertions,
and rejects empty, skipped-only, expected-failures-only and malformed results.
It is aggregate completion evidence; exact assertion parity is checked
separately. The first full-module guest run aborted after 648 seconds; it is not accepted.
The macOS crash report identifies two executor workers dropping active MM
inventories from failure settlement. Offline LLDB lookup against the matching
executable UUID `D3F1BF92-C27E-3FAB-9DD8-E4417C8A0CB0` places both callers at
`executor.rs:3735`, the initial runtime boundary-audit failure path. The
triggering audit error is still unknown. Buffered guest output was lost with
the host abort; durable streaming is the next diagnostic correction.
Logs: `/tmp/carrick-ecosystem-sep04-cpython-full.log` and
`/tmp/carrick-ecosystem-sep04-cpython-crash-location.txt`.


## Mounted core publication

Core publication now resolves the guest cwd and mount before creating, writing,
fsyncing and atomically renaming the temporary core. Overlay publication remains
supported. Bind opens enforce NOFOLLOW/CLOEXEC and reject exclusive-create
symlink targets. Cleanup uses the same mount and does not truncate symlink
targets. Independent host tests passed 17 core-publication cases and eight bind
VFS cases, including rollback and injected write failures.

The new signed `core_publication_visible_on_bind_mount` embed test uses the
existing source-hash-validated `coredumpfile` oracle. It failed against the
pre-fix runtime and passed with the mount-aware candidate for both musl and GNU.
Each run uses a fresh directory, requires exact host path `core`, rejects
leftover temporary cores, and compares all guest output to the cached oracle.
`carrick debug core` independently validated both ELF files and all three thread
records. No Docker phase was needed. The negative entitlement control and scoped
cleanup passed. Final test-only error-reporting adjustment passed Clippy.

Evidence: `/tmp/carrick-ecosystem-sep04-core-mount-{red,green}.log`,
`target/conformance/ecosystem-sep04-mounted-core-green/`, and
`target/conformance/ecosystem-sep04-receipts/core-mount-green-artifacts.jsonl`.
This closes mounted core visibility for the reducer; it does not fix the
separate host executor-boundary abort or qualify the full ecosystem gate.


## Durable ecosystem transcripts

The full-module and focused CPython reducers now stream configured stdout and
stderr artifact files through the public embed writer API before guest execution.
Unbuffered Python output survives a host abort. Permanent capture errors fail
the host check even if the guest ignores its stdio errno; interrupted writes
retain standard retry semantics. The existing captured mode remains available
when no artifact directory is requested.

Independent checks passed 16 aggregate transcript cases, five writer failure
cases and Clippy. The signed focused forkserver reducer passed with streamed
artifacts in 2.56 seconds, including negative entitlement control and scoped
cleanup. This is diagnostic validation under concurrent host work, not a
performance result. Evidence:
`/tmp/carrick-ecosystem-sep04-streaming-host.log`,
`/tmp/carrick-ecosystem-sep04-streaming-smoke.log`, and
`target/conformance/ecosystem-sep04-streaming-smoke/`.


## Reviewed macOS authority inventory

A fresh compiler capture of clean source `27fe93d69` found 638 macOS call sites:
588 unchanged, 48 moved, two new. Codex verified all moved operation spans
against the prior captured source; 46 also retained identical surrounding
context. The changed bind-open flag and PTY status contexts preserve their
recorded authority roles. The two new rows name bind-path no-follow metadata
and fixed carrier FIFO retry sleep, with specific backing/carrier resources.
The FIFO classification does not establish correct blocking-open timeout or
executor-lease behavior; those semantics remain a focused-probe opportunity.

Only the reviewed macOS slice and its existing-format compiler capture were
updated. All six non-macOS profiles remain pending. The full modern candidate
with clean-source provenance is retained at
`target/conformance/ecosystem-sep04-receipts/authority-candidate.json`; it remains
explicitly partial and non-authoritative for the full matrix. The checked legacy
macOS receipt is an exact projection of its matching fields, not a new full-matrix
claim. Independent static validation and diff whitespace checks passed; the
fresh compiler comparison passed after commit. Full local CI then stopped at
dispatch-lock authority: 109 raw sites exceed the 107 ceiling, including five
unclassified acquisitions and 39 positional mismatches. K1 operation inventory
also contains real additions. These require semantic review and remediation;
raising ceilings or treating additions as positional drift is not acceptance.

## Core-qualified heap protection failure and single-case tooling

The streamed full CPython module reached
`ProcessPoolForkserverExecutorDeadlockTest.test_crash_big_data` and aborted in
`brk` while growing `0x400088c000..0x4000c8c000` (4 MiB). The host core is
`target/conformance/ecosystem-sep04-cpython-stream-debug/host.core`; its exact
debug executable is `/tmp/carrick-ecosystem-sep04-stream-debug-executable`.
Offline LLDB selected thread 12, frame 5 at `dispatch/mem.rs:3662`.

The core retains a deferred-COW authentication error at VA `0x4000948000`:
leaf `0x20009c09d80fc3`, translated and expected IPA `0x9c09d80000`, expected
AP `0xc0`. The leaf is executable despite the requested RW protection.
Offline inspection of the active engine's arm vector confirms covering arms
with `executable=true`. The generic AArch64 protection path first applies the
requested permissions, then re-downgrades COW spans using their historical
execute flag. A narrow correction and production-path page-table regressions
are under isolated Antigravity review; no runtime fix is accepted yet.
This core does not explain the separate earlier executor-boundary abort.

The new ignored `ecosystem_cpython_unittest_case` embed diagnostic requires
`CARRICK_CPYTHON_UNITTEST_CASE`, uses the local image without pulling, preserves
streamed evidence, and requires exactly one completed test with plain `OK`.
Independent host validation passed 30 transcript/writer cases. The signed
isolated `test_crash_big_data` passed in 7.70 seconds, with the negative
entitlement control and scoped cleanup passing. Thus the full-module failure
may depend on accumulated state; this single pass is not full-module acceptance
or controlled performance evidence. Logs use
`/tmp/carrick-ecosystem-sep04-{single-host,crash-big-data}.log`; the signed receipt
is `target/conformance/ecosystem-sep04-receipts/single-case-artifacts.jsonl`.

The independently compiled FIFO open matrix produced identical 16-line stdout
on two serial native-arm64 Docker runs per libc, all exit zero and empty stderr.
Raw outputs are in `target/conformance/ecosystem-sep04-fifo-oracle/`. Cached
fixture/wiring review and the signed Carrick red run remain pending.

## Fork COW execute permission closed (be541e9a6)

The core-qualified heap-protection abort had a wider cause than the mprotect
re-downgrade alone: `fork_cow_ranges` derived each range's execute flag from
the HOST mapping's perms (RWX for the anonymous arena), and `ForkReadOnly`
wrote that flag into UXN, so every inherited private page became executable in
both parent and child. New probe `forkprotectexec` (Docker oracle blessed
twice per libc) was red on the previous binary on three of eight lines,
including `parent_rw_control_faults=false`, and MATCHes after the fix on both
libcs. `ForkReadOnly` now preserves the leaf's own UXN and `protect_range`
applies the requested `PROT_EXEC` to armed COW spans. Sixteen adjacent
fork/mprotect/ptrace probes MATCH under the signed embed gate with the
unentitled negative control passing. Receipts:
`target/conformance/ecosystem-sep04-receipts/{fifo-forkexec-red,cow-exec-green,cow-exec-unit}.log`.

## FIFO open matrix (red, branch `agy/fifo-open-sep04`)

`fifoopenmatrix` is wired and blessed on that branch and red on six lines: a
blocking `O_RDONLY` open never blocks, a blocking `O_WRONLY` open gives up with
ENXIO after the dispatcher's 500x2 ms sleep loop, and no blocking open is
signal-interruptible (EINTR / SA_RESTART). Antigravity `fifo-open`
(`ecc3e9af-3421-486d-b2f9-47e0c9c86bcd`, run `ecosystem-sep04b`) owns the
runtime fix under a brief that requires kernel-pollable per-FIFO presence
pipes and `WaitOnFds` parking; Codex runs the signed gate and accepts.

## Authority inventories (branch `agy/authority-sep04b`)

The five raw lock additions and the K1 category drift from `05316a669` are
delegated to Antigravity `authority` (`602cb1f4-09f0-4ee4-8b79-db6c8cbac057`)
for encapsulation or trusted-boundary classification; ceilings stay where they
are. The three `libc::getpid` host-authority rows moved by the COW fix were
rebound as a positional reconcile (`7c7193512`).

## Targeted re-measurement on the fork COW fix (signed 4871fc81…, source 9168071e0)

With declared budgets (`--carrick-timeout-cap-s 0`, single worker, host
shared with two worker cargo builds so no ratio below is a measurement):
`go-build` MATCH with zero diffs (it was a CRASH in the August ledger);
`cpython-subprocess` reported 21 "regressions" that are a cache artifact,
see below; `cpython-concurrent_futures` hit its 600 s budget at test 193.
The single-case and `test_init` module reducers pass in isolation, and the
streamed full-module embed reducer then passed end to end: 255 assertions,
0 failures, 9 skips, 2615 s wall under load (`test_wait` 8 min 52 s,
`test_shutdown` 9 min). The suite is CORRECT on this runtime and roughly
30x its 80 s oracle; the "timeout" rows are the harness enforcing the 2x
cached-oracle budget, and a pathological ratio on a fork/process-pool
suite is the next correctness-shaped performance target, not a hang.
Evidence: `target/conformance/ecosystem-sep04-cf-module/` (streamed
transcript) and `ecosystem-sep04-receipts/{targeted-cap0-9168071e0,cf-module-reducer3}.log`.

## Oracle cache keyed by parser fingerprint (025e4298b)

The 21 `cpython-subprocess` diffs were ids the old regrtest parser never
recognised (two-line docstring assertions), so the committed oracle rows
carried them as `absent`. `OracleKey` now includes
`regrtest::PARSER_FINGERPRINT`; every regrtest row misses until a
deliberate serial `--oracle-fill --oracle-fill-profile regression
--ecosystem cpython` refresh (about 0.26 h of Docker for the 440 arm64
regression rows; the amd64 rows can only be re-blessed on the fleet).

## FIFO open handshake (branch `agy/fifo-open-sep04`, two review rounds)

Round 1 was returned for hooking a global mutex into every `HostFdOwner`
drop (fork-safety and close-path cost) and for learning FIFO identity by
opening a transient reader. Round 2 owns the parked opener through a
`WaitFdGuard::ParkedOpener` token and stats the path via
`FsBackend::fifo_identity`. Codex added `InternalWaitKind::FifoOpen` (the
run loop refuses a `Missing` wait authority). The signed gate then went
from 6 red lines to 1: `reader_unblocked_after_writer`, whose probe-side
non-blocking writer open raced the child's park on a loaded host; the
probe now retries that open for up to 2 s and is being re-blessed.

## Full ledger on the FIFO-landed artifact (ee40fc454, SHA e0f1b31c…)

Exhaustive run (`--force`, cached oracles required, declared budgets, four
workers on the 4P+6E host, two Antigravity cargo builds sharing the host, so
every ratio is a hypothesis). Artifact identity:
`target/conformance/ecosystem-sep04-receipts/ledger-ee40fc454-artifact.txt`;
rows `ledger-ee40fc454.jsonl`.

| ecosystem | match | regression | crash | timeout | other |
|---|---|---|---|---|---|
| CPython | 428/438 | 4 | 4 | 2 | |
| Go | 190/194 | 2 | 0 | 2 | |
| LTP | 1443/1492 | 28 | 0 | 4 | 10 known diff, 7 unbaselined |
| Node | 2/3 | 1 | | | |

2,063 of 2,127 match (97.0%); 47 gating rows. Go was 178 crashes in the
August ledger. The four CPython crashes are host carrier aborts with
distinct signatures: `cpython-asyncio` "vfork parent resumed without
release completion" then FATAL MM-authority drop during
`test_kill_issue43884`; `cpython-builtin` "persistent executor boundary
audit failed: host-signal-mask added=[…]" in `PtyTests.test_input_no_stdout_fileno`;
`cpython-readline` "mutation reached a draining FileTable generation" in
`test_auto_history_enabled`; `cpython-compile` is a guest fatal in
`test_compiler_recursion_limit`. The two CPython timeouts
(`concurrent_futures`, `multiprocessing_fork`) are the process-pool
performance gap. Matched-row ratios (hypothesis): LTP median 0.46x, Go
1.38x, CPython 2.32x; 125/428 CPython and 158/190 Go rows inside 2x.

Delegated after the ledger (run `ltp-sep04`): `ltp-fd` (pidfd
PIDFD_NONBLOCK accepted; memfd re-open through `/proc/self/fd` must yield a
new read-only description, returned for round 2), `ltp-net` (SO_PEERCRED
guest identity, MSG_MORE coalescing), `ltp-pipe` (full-pipe blocking
write, pwritev2 ESPIPE on pipes, blocking inotify/fanotify reads).

## Crash attribution from batch-lldb backtraces (no live attach)

- `cpython-builtin` (`PtyTests.test_input_no_stdout_fileno`) reproduces in
  isolation: exit-time `retire_hvpatch_process_fds` → `close_open_file_and_free_pty`
  → `rescue_pty_master_before_slave_close` → `stage_splice_bytes_for_description`
  → `FileTable::lock_splice_pushback` → the mutation gate of the exiting task's
  already-drained table aborts the carrier (`builtin-lldb2.log`). The splice
  pushback queue is per-table state for what is per-description state; the
  pty master lives in the parent's table. Delegated as `pty-rescue`
  (queue moves into `DescriptionCommon`, red-first host test, probe
  `ptyexitrescue`).
- `cpython-compile` (`test_compiler_recursion_limit`): fifteen 1 MiB anonymous
  maps refused with `OutOfTables (in_use=438 free=0 capacity=440
  multi_vcpu=true exclusive=true reclaim_pending=false)` after `7f9c29866`
  attached the census to the sparse-mmap planner, i.e. genuine exhaustion of
  the fixed 1.75 MiB per-process stage-1 pool, not refused reclaim. The pool
  is bounded by the 2 MiB kernel region. Linux has no such limit; the design
  answer is a multi-pool `PageTableManager` that grows by mapping further
  kernel-only IPA pools on demand (tables are reached by the MMU through
  stage-2, so an overflow pool needs no stage-1 mapping at all), with fork
  cloning only the used watermark of each pool. Not yet delegated.
- `cpython-asyncio` (`test_kill_issue43884`) and `cpython-readline`
  (`test_auto_history_enabled`) pass in isolation; their aborts depend on
  accumulated module state and will be re-run under the full-module reducer
  after the pty-rescue fix lands, since the readline signature is the same
  draining-table abort.

## Performance targets (from the ee40fc454 ledger; ratios are hypotheses)

Aggregate over the 2,063 matched suites: Carrick 3,575 s vs oracle 2,012 s
(1.78x), but the distribution is what matters: 299 suites sit in 2-5x
(794 s), 28 in 5-10x (532 s) and 20 above 10x carry 1,206 s of wall on
their own. Per AGENTS.md a pathological ratio is a correctness signal, so
the first targets are the smallest reproducers of each family:

| suite | ratio | carrick | oracle | family |
|---|---|---|---|---|
| ltp-munmap04 | 75.8x | 30.5 s | 0.4 s | mmap/munmap algorithm (single process) |
| cpython-call | 20.2x | 8.3 s | 0.4 s | compute-bound CPython, no fork |
| go-crypto | 33.1x | 13.4 s | 0.4 s | Go runtime scheduler / threads |
| cpython-tarfile | 59.4x | 283 s | 4.8 s | fs-heavy (open/utimes/chmod amplification) |
| go-go_types, go-go_internal_srcimporter | 31-43x | 115-192 s | 3-6 s | Go compute + fs |
| cpython-concurrent_futures, multiprocessing_fork | budget timeouts | >600 s | 52-74 s | fork / process pools |

Method: exact suite invocation under `carrick trace` (in-process libdtrace)
for the syscall shape first, then a controlled single-variable quiet-host
comparison per fix. Traces land under
`target/conformance/ecosystem-sep04-receipts/perf/`.

## Anonymous-memory cost, attributed (2026-09-04 late)

`perf_arena_churn` (CPython arena shape) serially under Docker and Carrick,
two runs each: untouched map+unmap 1 µs vs 60 µs; map, touch 64 pages,
unmap 52 µs vs 325 µs; the same with 64 arenas live 54 µs vs 550 µs.
`guest-mmap-shape.d` places 417 ms wall / 412 ms CPU of the run inside the
6,064 `mmap(256 KiB, anon)` dispatches (69 µs CPU each).

A symbolized carrier CPU ranking (`perf/arena-cpu-ranking4.txt`; taken
with the dtrace CLI grabbing the carrier directly because `carrick trace`
still prints `ustack()` frames unsymbolized for progeny, a tool gap now
noted in the ranking script) attributes the run: 28% first-touch faults
(`resident_fault_plan` → `protect_range` of one 4 KiB leaf → the EL1
stage-1 TLBI trampoline on a vCPU, per page), 29% guest execution, 8.5%
`memset` in `zero_guest_backing` on every anonymous mmap, 6% an
`AliasRegistry::process_visible_ordered` scan inside that scrub (grows
with live mappings), 3% `hv_vm_unmap`+`munmap` per unmap. Delegated as
Antigravity `mmap-cost` with three ordered levers: no TLBI for an
invalid→valid leaf edit (the architecture never caches an invalid
translation), no scrub of fresh backing (kernel zero-fill), and no
registry scan on the mmap path. Correctness gate: the mmap/COW probe
set; performance gate: `perf_arena_churn` per lever.

`socketcredmore`'s Docker oracle corrected two assumptions in the MSG_MORE
work: Linux does not cork AF_UNIX datagrams and discards a corked UDP
datagram on close. `pipeblockedge` needed `CAP_SYS_ADMIN` in both lanes
(fanotify_init) to stop its fanotify lines being vacuous; under that
privilege the pipe branch's runtime loses the whole probe output (a
fanotify blocking-read park that never wakes), still open.

## Pipe readiness branch landed (b31077560)

The open fanotify item above was the runtime, not the probe: `install_fd`
dropped the description's status flags, so a `fanotify_init(FAN_NONBLOCK)`
group blocked in `read` and the harness's SIGALRM ended the probe before it
flushed a line (`carrick trace` showed the `FAN_NONBLOCK` init followed by an
EINTR'd read). `install_fd_with_status_flags` keeps them; the same fix had
already closed pidfd `PIDFD_NONBLOCK`. The branch also parks full-pipe writes
and inotify/fanotify reads on readiness instead of spinning. `pipeblockedge`
is all-true against its `CAP_SYS_ADMIN` oracle in both libc lanes. Landed as
`8dc06bae2..b31077560`; main's K1 burndown red (`read_attempt`,
`slot_description_mutation`, `stream_transfer`) predates the branch and is the
`socket-state` worker's item.

The growable per-mm page-table backing (cpython `test_compile` exhaustion,
`in_use=438 capacity=440`) is briefed as chained 2 MiB root slots behind a
typed arena source on the manager; it waits on the `mmap-cost` worker, which
holds `page_table.rs`.

## Partial-send count loss (ae130a80a) and the touched-suite re-run

Re-running the twelve suites the fd/net/pty/pipe landings touched on
`b31077560` left four gating rows. `cpython-asyncio` moved from a crash to
twelve `test_sendfile_*` failures whose server side received 278529 of
1114113 bytes; a plain non-blocking `send` loop with `SO_SNDBUF` shrunk to
4 KiB reproduces the loss outside asyncio. Both socket send sites mapped any
non-negative host result to the full payload length, so a partial host
accept was reported as complete and the remainder was silently dropped.
`settle_cork_send` now returns the host's count minus the corked prefix that
rode along, EAGAINs a non-blocking call that made no progress, and puts the
unsent corked bytes back at the head of the cork buffer. The new
`socketpartialsend` probe (send / sendmsg / MSG_MORE on a 4 KiB send buffer;
counts must equal bytes received) is red on `b31077560` and MATCH on
`e4f233615` in both lanes. Its first draft also asserted that a short send
was observed; the Docker oracle showed Linux accepts every 16 KiB send whole
on loopback even with the shrunk buffer, so that line was not a Linux
invariant and was dropped before the bless.

Two LTP rows in the same batch were fixed the same way: `memfd_create01`
(a `/proc/self/fd` re-open of a write-sealed memfd returned EPERM; Linux
opens it and lets the resize seals decide the O_TRUNC; `fdsemantics` lines
15-16) and `pipe12` (FIONREAD on an in-memory pipe write end fell to the
catch-all 0; `pipeextra` write-end line). `pipe06`'s stale Docker row was
refilled Docker-only. `fanotify04` remains: `read` on a `FAN_NONBLOCK`
group returns EAGAIN where Linux has an event queued, so a marked open is
not generating its event (Docker 9/9, carrick 7/8 + TBROK).

The `socket-state` worker's refactor (peer credentials and cork state on
`DescriptionCommon`) landed as `7f63a0a39`; main's K1 burndown is green
again with no ceiling raised.

## Batch closed (99fc45746)

Two more deterministic defects fell out of gating the batch, both in
"fast path skips the bookkeeping" shape:

- `sigunblockpending` regressed on the probe shard gate after the pipe
  readiness landing: `write_pipe` consulted the pending-signal check before
  copying, so a handler's one-byte write with a second signal pending
  returned EINTR with nothing written. The guest syscall-flow trace showed
  the `write ret=-4` directly. Restructured to the BSD `pipe_write` shape
  (copy when there is room; interruptible only at the sleep) in `7f11d985b`.
- `fanotify04`: the three trusted `--fs host` fast lanes declined on inotify
  watches but not fanotify marks, so a marked directory's open never reached
  the FAN_OPEN emission. `99fc45746`; new probe `fanotifyondir` (all eight
  lines MATCH both lanes), `ltp-fanotify04` 9/9.

All twelve suites touched by the fd/net/pty/pipe landings now MATCH.
`fanotify01`/`fanotify06` match as broken-on-both-sides; they are candidates
for the under-privileged-oracle inversion and need a Docker privilege check
before anything else.

## Two findings from gating the mmap-cost branch

- **Guest-reachable crash on the default rootfs lane, pre-existing on main.**
  `mapfixedfork` and `mmapcluster` run cleanly under `--fs host` (the shard
  gate's lane) but kill the guest on the in-memory rootfs:
  `borrowed structural mapping at IPA 0x9800000000 lost its owner`
  (`LINUX_PRIVATE_OVERLAY_BASE`) in the fork projection plan. A
  `MAP_FIXED|MAP_PRIVATE` over a shared-aperture VA records its overlay
  mapping without a structural owner on that lane. Delegated as
  `overlay-owner` (worktree `.worktrees/agy-overlay-owner-sep05`); the gate
  must run both lanes for the memory probes from now on.
- **`preemptsigstorm` is a throughput assertion in disguise.** Its
  `iters_floor` demanded 1000 iterations per worker inside a 2.5 s wall
  window, so a contended host (the branch gate running beside the main shard
  gate) failed it with every other line true, and five quiet reruns matched.
  The probe now keeps the storm running until every worker has crossed the
  floor (watchdog-bounded), which makes the line the progress invariant it
  was documented as. Rebuild and re-bless pending the Docker phase.

## mmap-cost levers landed (perf, first pathological-ratio work)

Three commits from the `mmap-cost` worker after one rejected round (a
freshness flag duplicated across six alias indices with linear scans, and a
chore commit raising three burndown ceilings, both dropped):

1. Skip the stage-1 TLBI when an edit only validates invalid leaves (an
   invalid translation is never cached); `PageTableApplyOutcome` carries
   `changed` and `flush_required` as a typed outcome, no bool impersonation.
2. Replace the whole-range memset of reused private anonymous backing with
   a fresh `mmap(MAP_FIXED|MAP_ANON|MAP_PRIVATE)` of the coalesced run, so
   the kernel zero-fills lazily; COW sources, shared/file-backed and
   unaligned tails keep the memset.
3. Answer the mmap reuse-path alias queries from the existing `by_va_start`
   and owned-scope indices instead of the full process-visible scan.

Gate: full probe shard gate green on the branch binary (both lanes, all
shards). Interleaved A/B, three reps each, same host load:

| probe / case | main (µs/op) | branch (µs/op) | Docker |
|---|---|---|---|
| arena churn, touched | 328 | 212 | 52 |
| arena pool, 64 live | 555 | 385 | 54 |
| arena untouched | 59 | 50 | 1 |
| mmap churn total (ms) | 9.95 | 9.69 | n/a |

Still 4x/7x/50x the oracle; the untouched case is pure dispatch cost and is
the next attribution target. Receipts: `perf-ab-mmap-cost.txt`,
`conformance-probes-mmap-cost.log`. Landed as `ea55f4028..c89dec3c2`.

The first harness pass on the lever binary read `cpython-call` at 34x and
`cpython-mmap` at 7.4x against ledger values of 20x and 4.2x, taken while two
Antigravity workers were compiling (load 9 on a 10-core host). An interleaved
A/B of `test_call` wall time between a pre-lever build (`ecb026784`) and the
lever build under that same load reads 4.92 s vs 4.61 s (three reps each,
lever faster every pair), so the levers did not regress the call-heavy
suite; the harness numbers were load. Quiet-host ledger refresh still owed.
`cpython-compile` still crashes on page-table exhaustion (pt-pool worker in
flight); `concurrent_futures` completed 232/237 with five timing-sensitive
failures under that load.

## Carrier allocation churn on the fault path (0492887cd)

A dtrace `pid$target::__bzero:entry` census on perf_arena_churn (lever
binary) found 3.5 million small zeroed allocations per run: two per data
abort for the instruction fetch feeding the `vcpu__fault__regs` USDT probe
(computed eagerly with no consumer attached), one `Rc` per fault in
`acquire_mm_stage1_authority`, one per fault in `remove_fault_range`, a Vec
growth per munmap in `unregister_alias`, and 624k `BTreeMap` node
allocations from `unregister_process_alias` cloning the whole
process-visible alias registry (snapshot, ordered, clone) on every munmap.
It also showed `MAP_FIXED` fired once in the whole run against 6,000
256 KiB memsets: lever 2's remap is inert because every HVPatch anonymous
mapping is a reusable global-frame extent, which its eligibility excludes.

Landed now: the fault probes take their arguments lazily (`1b3f2a5f2`),
and the env-gated `SIGDBG`/`FAULTDBG`/`RUNSTATE` eprintln blocks on the
per-quantum, per-fault and per-signal paths are deleted with the watchdog
window cached (`0492887cd`); `__findenv_locked` had been 4.9% of carrier
user CPU. Interleaved A/B against the pre-lever build under a loaded host
(two worker compiles running) suggests about 2x on the touched arena cases
and parity on the untouched case; absolute figures from that run are not
citable. Briefed for the next worker round
(`scratchpad/brief-mmap-cost-2.md`): O(affected rows) munmap planning with
an undo journal, an HVF stage-2 test deciding lever 2's fate, and the
per-fault `Rc`.

## Private-overlay owner fix landed (7d5ab8e23); page-table growth in review

`overlay-owner` found the root cause: on exec rebuild
`publish_exec_region_host_owner_in` provisioned structural owners only for
the mm root slot, so the 2 GiB private overlay region had none; a later
`MAP_FIXED|MAP_PRIVATE` repoint read a zero owner generation, and the
first fork failed closed on the borrowed row. Non-reusable global-frame
extents are now structural at exec publication, the carrier root install
gets the same authority, and the repoint propagates the owner generation.
`mapfixedfork` MATCHes on the in-memory rootfs in both lanes. `mmapcluster`
now reaches the next defect on that lane, an underflow in the guest-read
chunk loop (`chunk_address - mapping_start` with a non-containing
mapping), handed back to the same worker as a which-mapping domain error.

`pt-pool` delivered a multi-arena `PageTableManager` (`TableArenaSource`,
per-arena `HostArenaResolver`, extension slots returned on retirement) but
attached the source only in a unit test: no production manager grows, so
the mechanism was default-off. Sent back to wire every HVPatch manager
(root, exec, fork child with its own slots) before it can be gated with
`cpython-compile`.

## Oracle-privilege pass over the broken-on-both-sides LTP rows

Docker-only check of the five rows that matched as broken on both sides,
default caps vs `--privileged`: `fanotify01` (312/312), `fanotify06`
(18/18), `vhangup02` and `clock_settime03` pass privileged; `semctl06`
fails identically (semop EACCES) either way and is a genuine LTP-vs-kernel
failure, not a carrick gap. Exact grants replaced `--privileged`:
`vhangup02` needs `CAP_SYS_TTY_CONFIG` (now in the manifest and the
override table; MATCH 1/1 both sides, `eb1849dfb`), `clock_settime03`'s
row was stale and refills to MATCH under the `CAP_SYS_TIME` it already
declared. `fanotify01`/`fanotify06` need a loop block device
(`tst_device: Failed to acquire device`), which neither Docker's default
container nor carrick provides; they stay matched-broken until carrick has
a block-device story, and are not mis-filed as runtime gaps.

## LTP tail read on 98f705902

- `mremap06`: `mremap(MREMAP_MAYMOVE|MREMAP_FIXED)` of one page inside a
  `MAP_SHARED` file mapping to a fixed address in the same mapping fails
  (TBROK at the first mremap). Needs a probe (`mremapfixedshared`) and a
  runtime fix for fixed-destination moves of shared file-backed pages.
- `process_vm_readv03`: the remote read returns 18368 of 131072 bytes (the
  child TBROKs, 17 passed). A cross-process read that stops short at what
  looks like an iov or page boundary; reduce with a probe before fixing.
- `splice02` passes 1/1 when run directly; its ledger row is stale.
- `setsockopt02` needs `AF_PACKET` (`SOL_PACKET`/`PACKET_VERSION`), an
  unimplemented family: a real gap, not a privilege inversion.
- `clock_adjtime01` reports `tst_test.c:825: TBROK: Invalid option` under
  carrick; the harness invocation passes no option, so something in the
  argv/env the guest sees differs. Unattributed.

Worker hygiene: two long-lived Antigravity conversations (`pt-pool`,
`overlay-owner`) started timing out on every turn with nothing committed
once their context grew; both were replaced by fresh conversations on the
same worktrees with narrower briefs (`pt-pool-wire`, `overlay-read`).

`process_vm_readv03`, traced with `hvpatch-guest-syscall-flow.d`: every
small case (1024 bytes) returns fully; the 8-iov 131072-byte case returns
18368 with errno 0 (receipt `pvr03-flow.txt`). A short cross-process read
that stops mid-buffer without an error is the remote-side chunk loop ending
at the first page it cannot resolve, most plausibly a not-yet-resident
anonymous page of the child (Linux reads it as zeros). Next step is a probe
(`processvmsparse`: remote buffer partially touched, read the whole range,
assert full length and zeros in the untouched pages) and a fix in the
foreign-mm read path once the two trap.rs workers have landed.

## adjtimex model landed (cf4357f9b); two new red probes

`clock-adjtime` (fresh worker, one round plus two oracle corrections by
the director) gives the container clock domain a real `struct timex`
state: every ADJ_* mode stores and reads back, `ADJ_SETOFFSET` moves the
virtual realtime offset, capability still gates any modification; `freq`
and `tick` are recorded but do not skew the rate, `maxerror` is static and
the singleshot offset is a step (all documented approximations). Two
places the first cut was stricter than Linux were corrected against the
oracle: an oversized `freq` is clamped and undefined `status` bits are
dropped, and `ADJ_MICRO|ADJ_NANO` / `ADJ_TAI|ADJ_TIMECONST` together are
accepted. Probe `adjtimexmodel` (18 lines, `CAP_SYS_TIME`) MATCHes both
lanes; `ltp-clock_adjtime01` 9/9 MATCH through the harness (was 3/9 with
six EPERM). `adjtimex01`/`adjtimex02` match as fail-on-both-sides and are
the next oracle-privilege check.

Two probes were added red on purpose and gate from here:
`processvmsparse` (process_vm_readv03: the remote read stops at the first
non-resident page) and `mremapfixedshared` (mremap06: fixed move inside a
shared file mapping). The mremap fix's first cut moved the VMA but minted a
fresh host `MAP_SHARED` mmap at a 4 KiB file offset, which Darwin rejects on
a 16 KiB page host; the correct lowering is a stage-1 repoint to the extent
already mapped, sent back to the worker.

`adjtimex01`/`adjtimex02` were the same inversion as `vhangup02`: Docker
without `CAP_SYS_TIME` fails every modifying mode with EPERM. With the
exact grant in both lanes (`3a2dc90b4`) the oracle passes 2/2 and 7/7 and
Carrick's new adjtimex model MATCHes both plus `clock_adjtime01` 9/9.

Gate incidents worth remembering: main's `conformance-probes/target` was
found replaced by a self-referencing symlink (created while worktrees were
being added and removed with symlinked probe directories), which made two
"gates" report empty output for every probe; both were re-run after the
directory was restored and the closure set rebuilt. The page-table growth
branch (`e39cb980c`) hangs every guest at its first mmap: a live lldb
backtrace shows its `HostArenaResolver` closure resolving an arena base
through `mapping_for_range` -> `translate_va_for_cow`, which re-takes the
page-table mutex the caller already holds under `sync_to_host`. Sent back
with the frames.

Page-table growth branch, round three: with the resolver deadlock fixed
(resolvers now go through stage-2/physical lookups), every multi-task mm
and every fork child failed with "stage-1 table arena source is already
installed". The install-exactly-once guard I had asked for was scoped to a
task's first poll, but the manager is a per-mm object: thread siblings
share it and a fork child's job also polls, so the second task of any mm
tripped it. Corrected semantics sent back: the source is an mm property
installed where the manager is created or adopted (root, exec, fork child
before its rebase); re-installing the same lease's source is a no-op, a
different lease is the error. This is the identity-and-scope class
(`docs/identity-and-scope-domains.md`): a rule that is true while one task
exists and wrong the instant a second appears.

Parked: branch `agy/overlay-owner-sep05` (worktree kept) carries
`3214d3da4`, which keys guest reads/writes on the semantic VA and makes
`mmapcluster`/`mapfixedfork` MATCH on the in-memory rootfs, but regresses
`coredumpfile`'s sibling-thread capture (four lines). Three worker turns
across two conversations produced no fix (each died on transport with the
tree untouched or only a compile fix). The likely cause is the core writer
handing already-translated (IPA) addresses to the read path that now
insists on semantic VAs; the fix belongs with whoever next touches the
core writer. Main keeps the pre-existing in-memory-lane `mmapcluster`
underflow until then; `--fs host` (the shard gate's lane) is unaffected.

## Shared-file fixed mremap landed (2357a08c6)

Seven commits from two worker conversations. The final cause, found by a
fresh conversation in one turn after the long one had died eight times:
the dispatcher hands the repoint the mm's SEMANTIC alias IPA token
(`LINUX_ALIAS_IPA_BASE`, 0x1800000000), while under the persistent VM
lifecycle the shared file's live backing is a global-frame GPA at a
different address, so the owner lookup could never match. The source leaf
is now authenticated through the live stage-1 translation (the rule from
`identity-and-scope-domains.md`: never feed one address domain into a
lookup for another). `mremapfixedshared` MATCHes both lanes, LTP mremap06
goes 3/3 (was TBROK), and the neighbouring memory probes and the full
shard gate stay green. `processvmsparse` is registered as the tracked gap
it is until its fix lands (worker `processvm` dispatched); the page-table
growth branch has the deferred-install fix (director-written) under its
hardware gate.

Root cause of the probe-directory symlink incident, found while wiring a
new probe: `git add -A crates conformance-probes` in a worktree swept that
worktree's `conformance-probes/target` symlink into `4a9cb845e`; when the
branch fast-forwarded and the main tree checked it out, git replaced the
real probe directory with a symlink pointing at itself. The path is now
untracked and ignored (`842ad99dc`). Lesson: never `git add -A` a directory
that carries a per-worktree convenience symlink; add files by name.

Page-table growth, round five: with the director-written deferred install
(the source is applied the moment a manager exists, at the lazy first
edit or the exec rebuild, and rides the task-state round trip), every
guest boots, `concurrent_futures` runs 186 tests before its 2x-budget
timeout, and `cpython-compile` no longer exhausts its tables: it now runs
to `test_compiler_recursion_limit`, which dies with a real guest
`Segmentation fault` while the C compiler recurses on the main thread. A
200k-frame pure-Python recursion is fine under carrick, so the remaining
gap is C-stack growth toward `RLIMIT_STACK` (Linux grows the main stack on
demand to 8 MiB); probe `stackgrowmain` isolates it and is red-first
pending the next Docker phase. The branch's last gate diffs
(`processvmsparse`, `mremapfixedshared`) were its stale base; the clean
rebase and full gate run now.

## Page-table growth landed (ee7293816)

Six commits: the worker's multi-arena `PageTableManager` (`TableArenaSource`,
per-arena `HostArenaResolver`, extension root slots returned on
retirement), the source plumbing through the fork request and the vCPU
loop, the MM-scoped install, and the director's two commits deferring the
install until a manager exists (lazy first edit or exec rebuild) and
propagating a refused rebuild install as an error. Gate on the rebased
branch: shards 0 and 1 green, shard 2 green except the not-yet-built
`stackgrowmain` binary, lint-domains green, every guest boots. The
`in_use=438 capacity=440` exhaustion is gone from `cpython-compile`; its
remaining failure is the main-stack growth segfault tracked by
`stackgrowmain`. Cost of the growth path on the hot mmap loop is not yet
measured on a quiet host; it is the next A/B once the host is idle.

## 2026-09-05: page-table growth has no stage-2 backing (cpython-compile crash root cause)

`cpython-compile`'s `test_compiler_recursion_limit` was NOT stack growth
(`stackgrowmain` MATCHes; isolated compiles raise RecursionError at every
depth). Under regrtest it hits

    mmap refused: ... sparse HVPatch mmap publication failed at VA 0x602e600000: leaf=0x0 expected_ipa=0x9b86200000

and in the full suite it segfaults. Attribution, read from the code:

- `Stage1MmTableArenaSource::take_arena` hands the `PageTableManager` a free
  2 MiB root-slot IPA and nothing else. The primary arena is an
  `HvfMappedRegion` with a structural owner published by the exec path; an
  extension arena has no host allocation, no `hv_vm_map`, no mapping row.
- Every `page_table_resolver` in `trap.rs` resolves the extension base through
  `host_ptr`, which finds no mapping. `PageTableManager::sync_to_host`
  silently skips dirty words whose arena does not resolve, so the descriptors
  never reach the guest: either the walker takes a stage-2 abort (guest
  SIGSEGV) or the shadow-vs-live check refuses the mmap (ENOMEM).
- No probe forced growth past 448 tables, so the shard gate was green.

Red-first probe `pagetablegrow` (3000 scattered 4 KiB `MAP_FIXED` pages at
2 MiB strides): exits 139 with no output on main `41296092b`. Cross-compiled
locally (`cargo build --target aarch64-unknown-linux-musl` works without Docker
for libc-only probes). Worker `pt-backing` (worktree `agy-pt-backing-sep05`,
brief `scratchpad/brief-pt-backing.md`) is publishing extension arenas with the
root slot's backing shape, failing `sync_to_host` closed on an unresolved arena,
and covering fork rebase and exec release.

Also landed: foreign-mm zero-fill for non-resident readable pages (`213ddbcf6`,
`processvmsparse` MATCH both lanes). LTP `process_vm_readv03` still TBROKs
(131072 requested, 18368 returned) — a further short-read class to attribute on
the rebuilt main.

## 2026-09-05: process_vm_readv03 — two structural defects, both landed

LTP `process_vm_readv03` had failed at two different points; neither was the
zero-fill gap the worker fixed.

1. **Per-local-iovec transactions** (`a2b0c5610`). The foreign read loop cut
   every transaction at the LOCAL iovec boundary, so the 1024×1-byte local
   shape opened 1024 snapshot+transport round trips for a 1 KiB read, each
   under a 50 ms wall-clock deadline; under load the 959th timed out and the
   syscall returned a prefix (Linux never shortens a read for time). Now one
   transaction per remote page, scattered across local iovecs. Unit test
   counts transactions through the test transport (1024 → 1). Timing for the
   scatter shapes went from ~30 ms to ~0 ms.
2. **Stale lease misreported as a missing binding** (`7c58644eb`). Remaining
   failure was deterministic: `bufsize=131072, remote_iovecs=1024` returned
   18368. A glibc reproducer (parent scatter buffer in brk heap shared COW with
   the forked child) reproduced it; field-level diagnostics on the carrier
   lease showed only the TARGET's frame-inventory revision drifting between
   retain and chunk 5 — the parent's host-side writes republish the shared
   frames and bump the child's revision. The carrier returned `MissingBinding`
   for a lease that merely predated the snapshot. New typed `LeaseStale`;
   `read_foreign` re-retains against the snapshot it just validated and caches
   the fresh lease in the token. Red-first unit test; LTP MATCH 32/32 ×3.

Tooling kept: `tracing::debug!` on `carrick::process_vm` (silent break points)
and `carrick::foreign_mm` (which snapshot fields drifted), enabled with
`RUST_LOG=carrick::process_vm=debug,carrick::foreign_mm=debug`. Probes for
libc-only cases cross-compile locally without Docker
(`cargo build --target aarch64-unknown-linux-{musl,gnu}` in `conformance-probes`).

Open (recorded, not fixed): `MmAccessState::OVERALL_DEADLINE` (50 ms) still
converts scheduling delay into a short foreign read; with page-granular
transactions the exposure is ~32 round trips per 128 KiB instead of 1024, but
the shape (wall clock → guest-visible short read) is the flaky class the owner
ruled architectural. The write side (`prepare_write`) now returns `LeaseStale`
typed but the runtime does not yet re-retain there.

## 2026-09-05 (later): page-table backing landed; splice02 was a false EOF

- **Extension table arenas backed** (`6516fb902`, worker pt-backing after a
  transport death at 59 min; director committed its clean, fully-tested diff).
  `pagetablegrow` 5/5 on both lanes; gap entry retired. `cpython-compile` now
  runs 65 tests and dies at `test_compiler_recursion_limit` with a genuine
  guest SIGSEGV (was ENOMEM/refusal) — next attribution via
  `scripts/dtrace/hvpatch-phase4-guest-fault.d`.
- **splice02** (`640d8a849`): not slow, not a wakeup loss. `take_pipe_bytes`
  returned an empty Vec for an empty pipe with live writers, so
  `splice(pipe->file)`/`vmsplice` returned 0 (EOF) whenever the reader outran
  the writer; four concurrent LTP runs stopped at 76–212 KB, alone it passed.
  Typed `PipeDrain`, shared `wait_for_pipe_readable` park with `read(2)`.
  Probe `splicepipeempty` red-first 4/5 → 5/5 both lanes; splice02 4/4 concurrent.
- LTP tail rerun on `92540fc5a`: 18/49 previously-gating rows now match.
  Still gating and attributed: futex_wake02 (`/proc/<pid>/task` for a foreign
  pid answered from host-process legacy → worker proctask), lseek11
  (SEEK_DATA/HOLE on the overlay lane → worker seekhole), ioctl02/test_ioctl
  (`/dev/tty0`), setsockopt02 (AF_PACKET), fork14 (16 TB PROT_NONE reservation
  refused: arena-bounded hidden reservations), sendfile09 (statfs free space
  < 5G), syslog12 (`syslog(2)` ENOSYS), semctl06 (oracle broken, privilege),
  inotify09/msgstress01/setsid01/shmctl05 (timeouts, unattributed).
- Pre-existing unit failure `pipe_end_direction_matrix_and_fd_lifecycle_closure`
  (pwrite64 on a pipe read end EBADF vs expected ESPIPE) predates today's fs
  commits through `7f11d985b`; bisect continuing over the later merges.

## 2026-09-05 (evening): the arena source kept disappearing — four leaks, one instrument

After extension arenas got backing, growth still failed in specific shapes.
Each leak was a place a manager was built or replaced without the source:

1. **exec** (`311c6e858`): `replace_page_tables` only applied a PENDING source
   and the old source belongs to the retired mm's lease → mint a fresh source
   for the replacement lease at exec commit. Then, because the slot is shared
   and the first sparse mmap could build the manager before that install
   took, **eager build at install** (`31b30f96f`).
2. **sibling threads** (`0fa4c7eff`): the deferral was engine-local, so a
   `CLONE_THREAD` sibling's lazy build came up sourceless → shared
   `DeferredArenaSource` in the sibling spec.
3. **foreign-COW rollback** and **parent fork-COW rollback** restored clones →
   `adopt_live_extension_state`.
4. **rolled-back fork** (`7d0ca6c5f`): a fork transaction that loses vCPU
   admission (guest EAGAIN) restores the pre-fork clone. This was the CPython
   `-v` case: `-v` runs `uname` via subprocess, the fork lost once, the root
   lost its source, 755 refused mmaps. `RUST_LOG=debug` on the bind path hid
   it by changing admission timing, which is why the USDT probes
   `stage1-arena-bind`/`stage1-arena-install` and
   `scripts/dtrace/hvpatch-stage1-arena.d` exist now (`f1a0995d2`).

Lesson written into memory: the identity/scope class again — every one of
these was correct with one process and one thread. Any path that writes a
`PageTableManager` into the live slot must go through adoption or install,
never a bare clone.

Also landed: seekhole worker (`22b7a8d16` + ENXIO corrections), proctask
worker (`28ba900e2`), probes `seekholemap`/`proctaskchild`/`pipeextra`
blessed; pwrite-on-pipe smuggled change reverted (`f99ae555b`).

## 2026-09-05 (night): pathological-ratio attribution, first pass (owner priority)

Ranking from the last ledger (timeouts sit on their budget, so ratios are
floors): go-os_signal 80x (2.3 s on Docker), go-net 67x (2.7 s), ltp-setsid01
25x (1.6 s), cpython-multiprocessing_fork 11.6x, cpython-concurrent_futures 8.1x,
then inotify09/msgstress01/shmctl05 under 4x. Attributions so far:

- **go-os_signal** hangs in `TestTerminalSignal`: a guest pty with job control
  (`TIOCSCTTY`/`tcsetpgrp`, Ctrl-C must reach the guest foreground process
  group). carrick's pty line discipline is the HOST's, so ISIG lands on the
  carrier, never on the guest pgrp. A wedged carrier shows every executor idle
  in a condvar with no runnable guest thread — a guest-visible lost signal.
  Architectural: guest-side ISIG → guest pgrp delivery (the same family as the
  earlier interactive job-control work). Also seen: the CLI ignores `timeout`'s
  SIGTERM once wedged (1009 s until SIGKILL) — its own defect.
- **go-net** crawls (58 tests in 240 s) and stops in
  `TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode`: "received unexpected DNS
  query" — the hosts-file lookup misses and the resolver falls to the fake DNS
  server; in two of three runs the single test then hangs 120 s with no output.
  Needs the hosts-file read path (`--fs host`, stat mtime/size caching in Go's
  hosts cache) compared against Docker before touching code.
- **ltp-setsid01** passes standalone in 1 s: its 25x row is a harness-context
  effect (`[blocked]`), to be re-measured in-harness on a quiet host.
- **cpython-concurrent_futures** cannot be measured yet: on today's binary it
  aborts at `test_max_tasks_per_child_defaults_to_spawn_context` with "HVPatch
  COW page-table manager is absent" (2/2), while every bound authority in the
  arena trace has a manager. A `stage1-arena-absent` probe now names the empty
  authority at the refusal.
- Tooling: `scratchpad/gsf_reduce.py` turns a `hvpatch-guest-syscall-flow.d`
  capture into "which task is parked in which syscall" plus per-syscall wall;
  worth promoting into `carrick trace` as a profile. Caveat learned: nanosleep
  and exit_group emit no service-end record, so their "parks" are artifacts.

## 2026-09-05 (late night): fifth arena-source leak — the vfork child's exec

Worker `arena-race` (brief: enumerate every manager construction/swap) found
the residual: a `posix_spawn`/vfork (`CLONE_VM`) child still SHARES its
parent's page-table authority when it execs, and `replace_page_tables`
`take()`d the manager out of that shared authority and retired its extension
arenas. The parent was left with an empty slot ("HVPatch COW page-table
manager is absent" — concurrent_futures' spawn-context test) or rebuilt a
manager without a source on its next edit (the `-v` regrtest case: `-v` runs
`uname` through subprocess, which is posix_spawn). dash's `sh -c` vforks too,
which is why the exec-path probe and CPython under the harness both hit it.
Fix `ffe723778`: a shared authority (`Arc::strong_count > 1`) is left alone
and the child gets a fresh authority and deferred source.

Live on `3f3d715b9`: `-v` recursion case SUCCESS 3/3 with zero refusals,
`pagetablegrow` through `/bin/sh -c` 3000/3000, concurrent_futures past the
former abort with no absent-manager refusal. Instrument that found it:
`stage1-arena-absent` naming the empty authority + the bind/install history
of that pointer in `hvpatch-stage1-arena.d`.

Rule (now in memory): a `PageTableManager` slot is per-mm and may be shared by
a vfork child until exec; NO path may take, clone-replace, or retire through a
shared authority. The five leaks were: exec pending-only install, engine-local
deferral vs sibling lazy build, foreign-COW/fork-COW rollback clones,
rolled-back fork clone, and the vfork child's exec stealing the parent's slot.

## 2026-09-06: process creation is the lever behind both CPython pool suites

Measured on this host (Docker twin run in the Docker phase; carrick figures are
from a mostly quiet host unless noted):

| operation                          | carrick      | Docker   | ratio |
|------------------------------------|--------------|----------|-------|
| `fork` + `_exit` + `waitpid`       | 6.1 ms       | 0.66 ms  | 9x    |
| `posix_spawn /bin/true`            | 37 ms (loaded) | 0.36 ms | ~100x (loaded) |
| `python3 -c pass`                  | 72 ms (loaded) | 6.7 ms  | ~11x (loaded) |

Where the fork goes (`hvpatch-fork-wait-roundtrip.d`, `-fork-child-dispatch.d`,
`-frame-cow.d`, a 30-fork loop whose child only `_exit`s):

- parent critical section 1–2 ms, of which the process-spec build
  (`ProcessSpec`, mostly the 1.75 MiB page-table clone + COW arming) is ~1.1 ms;
- the child's lifetime 4–16 ms: **~47 copy-on-write faults per child** (CPython's
  refcount writes on the fork-return path) at a **median 80 µs per fault**
  (p99 107 µs), and 71 µs of that is between the fault trigger and the byte
  copy — fault exit, decode, frame lease, host allocation, stage-2 map — before
  16 KiB is copied. Linux takes the same faults at ~1–2 µs;
- reap 0.5–8 ms (parent wake after child exit).

So the structural target is the per-fault service pipeline (COW and sparse
anonymous faults alike), not fork itself; a pre-mapped frame pool and a
lighter fault exit path are the levers, and they compound into exec (dynamic
loader faults) and `posix_spawn`. `concurrent_futures` standalone: 658 s vs
74 s (8.9x), 20 ok, forkserver cluster failing with a widened race (late
worker connects after the Manager's temp dir is gone).

Also found by the gate on this binary and fixed in `f6b48151e`: a quadratic
page-table resolver once extension arenas exist (every edit scanned every
mapping row), and a rebind heuristic that stole a shared authority's manager
(coredumpfile lost two threads).

## 2026-09-06 (cont.): munmap was O(aliases); tty session rules; burndown honoured

- **munmap cloned and reindexed the process's alias registry twice per call**
  (`process_visible_snapshot` + a second clone to plan retirement): three
  `lldb` samples of the carrier at 99% CPU during `pagetablegrow` sat in
  `AliasRegistry::reindex`. Worker `alias-unmap` (`f7c87e272`) plans from the
  live scope-keyed indices (`by_va_start` range, `by_scope_physical_start`)
  and removes in place with `index_remove`; a legacy-snapshot oracle test
  proves identical planned leases and disarm spans, and a 5,000-row registry
  unmapping one row no longer allocates proportionally. First live number
  after the landing is recorded in the next entry.
- **Extension-arena resolution was O(mapping rows) per edit** (`f6b48151e`):
  the resolver now asks the structural-owner map keyed by (base, 2 MiB).
- **Guest-pty session rules** (`13e2cc680`): TIOCNOTTY off the controlling
  tty is ENOTTY, a leader releasing its tty hangs up the foreground group
  (SIGHUP, SIGCONT), TIOCSCTTY refuses a leader whose session already owns a
  tty. Found by the gate (`ptyflagmatrix`) and an isolated two-case check
  against Docker; the ISIG landing had relaxed them.
- **Dispatch-lock burndown**: the ISIG landing had grown `pty_table` lock
  sites from 10 to 15 against a ceiling of 10; one `pty_is_controlling`
  accessor brought it back to 10 (`f8f997110`) rather than raising the cap.
- Workers in flight: `stage1-authority` (page-table ownership as a type),
  `frame-pool` (pre-mapped frames; no syscalls per COW/sparse fault).

## 2026-09-05: alias-unmap landing measured, and its one regression

- **`pagetablegrow` standalone: 53.8 s → 9.7 s** after the in-place alias
  unmap (`f7c87e272`) and the O(1) extension-arena resolver.
- **Regression caught by the probe gate, not by the worker's tests**:
  `mincoreedge` aborted 3/3 with "alias registry changed under topology
  lock". The planner deduped co-holders of a physical extent by sequence
  number, but the two fragments of a split row keep the row's sequence, so
  planning the head's unmap dropped the tail and released an extent the
  registry still held. Fixed in `19a3fd139` (row identity = sequence plus
  semantic start) with a sequence test that replays the probe: middle page,
  head, tail. The worker's oracle test only ever unmapped once from a fresh
  registry; any plan/apply pair needs a SEQUENCE test.
- **Launch-shape trap**: `alpine /bin/sh -c 'a && b && /tmp/p'` tail-execs
  the probe (busybox), so it runs as PID 1 and a session leader under both
  carrick and Docker. A manual `ptyflagmatrix` run through that shape
  "diverged" on TIOCSCTTY while the gate's shard matched; the isolated
  two-case check and the gate agree with the oracle.
- Frame-pool worker round 1 returned with four findings: a check-then-act
  topology-lock bypass on the fault path (`is_fork_in_flight`), a
  frame-pool/state lock-order inversion against VM destroy, swallowed pool
  creation failures, and an out-of-fence test edit.

## 2026-09-05 afternoon: frame pool landed; fork's fixed cost attributed

Frame pool (`61daae8b4`, worker frame-pool, two review rounds: the first
round's `is_fork_in_flight` topology-lock bypass was a check-then-act race
and was removed; a frame-pool/state lock inversion against VM destroy was
fixed with a two-thread test). A/B on one binary, `CARRICK_FRAME_POOL=0`
as the off arm, 30-iteration `fork`+`_exit`+`waitpid` fixture
(`scratchpad/forkloop`, musl static; child touches N 4 KiB pages), host
under worker compile load so absolute numbers are "suggests":

| fixture | carrick pool on | carrick pool off | Docker |
|---|---|---|---|
| fork+wait, child touches 1 page | 0.62 ms | 0.64 ms | 0.08 ms |
| child touches 64 pages | 0.76 ms | 0.90 ms | 0.16 ms |
| child touches 512 pages (128 COW faults) | 2.04 ms | 2.77 ms | 0.67 ms |
| CPython `os.fork`+`_exit`+`waitpid` | 2.4 ms | 2.6 ms | 0.17 ms |

Per COW fault: ~11 µs with the pool, ~17 µs without, ~1.2 µs on Linux.
The pool met the per-fault target; the remaining pathology is the FIXED
cost per fork, 0.54 ms against Linux's 0.08 ms. `carrick trace -s
scripts/dtrace/hvpatch-phase4-fork-process-spec-stages.d` on the 1-page
fixture attributes it: the process-spec stage is ~0.4 of the ~0.49 ms
fork, and inside it phase 2 "parent table clone" is 0.19–0.24 ms for
3.5 MiB copied (the 1.75 MiB stage-1 image cloned once for the child and
once as the parent's rollback pre-image) and phase 7 "table publish" is
~0.1 ms for 2 MiB (a fresh `map_shared_anon` root-slot backing per fork
plus a full-image `restore_quiesced_snapshot_to_host`). Linux copies only
populated page tables, tens of KiB for a small process. Next lever, briefed
in `scratchpad/brief-fork-table-copy.md`: copy and publish only the
populated prefix of each table arena and take root-slot backing from a
pre-mapped slot pool, the same shape as the frame pool.

Also today: the probe gate's `docker_compose_shared_network_namespace_smoke`
failed once with an empty `docker compose down` error and passed alone in
5.5 s; it runs in the same test binary as carrick-lane smokes, so Docker and
carrick overlap there. Open harness item.

## 2026-09-05 evening: the VFS path-walk is the widest pathological term

Per-syscall microbench in `python:3.12-slim` (20k-iteration loops), default
lane, one binary; Docker on the same image:

| guest op | carrick | Docker | ratio |
|---|---|---|---|
| `os.stat("/usr/local/bin/python3")` (symlink chain) | 23.2 µs | 0.8 µs | 29x |
| `os.open`+`os.close` of the same | 33.1 µs | 1.2 µs | 28x |
| `os.stat("/usr/lib/nonexistent")` | 46.9 µs | 0.6 µs | 78x |
| `os.getpid()` | 0.06 µs | 0.17 µs | 0.35x |
| `subprocess.run(["/bin/true"])` | 3.9 ms | 0.2 ms | 19x |
| `subprocess.run(["python3","-c","pass"])` | 16.6 ms | 4.5 ms | 3.7x |

A spawn is ~60 fs syscalls at 20–70 µs each (`hvpatch-guest-syscall-flow.d`
reduced by `scratchpad/gsf_reduce.py`: newfstatat 42 µs avg, openat 44,
getdents64 294). The carrier user-CPU ranking
(`scripts/dtrace/hvpatch-carrier-user-cpu-ranking.d`, attached live) puts 89%
of the ENOENT stat inside host `__openat`: `real_stat` → `dir_fd_for`,
`stat_cache_get_or_fill`, `namei_leaf`, `fast_metadata_contained`,
`lookup_kind_and_metadata`, `fast_nofollow_metadata`, `fast_lstat_contained`
each re-open the same missing leaf, and nothing remembers a negative answer.
The successful stat re-reads the symlink chain and re-stats every component
per call (`canonicalize_following`, `layered_lstat`, `readlink_layered`);
the stat cache refuses symlinks. `dir_fd_for` also pays a real `getpid()`
syscall per call for host-fork detection the carrier never needs.

The rootfs scratch is private to the run and every guest write goes through
carrick, which is exactly the dcache invariant: carrick can cache positive
and negative dentries and symlink targets and invalidate at its own mutating
syscalls, with host revalidation only under shared (`-v`) mounts. Brief:
`scratchpad/brief-dentry-cache.md`, worker `dentry-cache` dispatched from
main (file-disjoint from the page-table workers). Targets: stat ≤ 4 µs,
ENOENT ≤ 3 µs, open+close ≤ 8 µs.

Two more instances of the same class, same method (attached carrier CPU ranking):

- **readdir**: `os.listdir` of a 201-entry directory is 1.54 ms vs 40 µs on
  Docker (39x), 12 entries 177 µs vs 6 µs, `/proc/self/fd` 265 µs vs 3.6 µs.
  `getdents64` → `layered_directory_entries` → `shadows` plus a per-entry
  `real_stat`/`lookup_kind` (fstatat is 74% of samples): every entry is
  stat'ed on the host to derive d_type/ino and layer shadowing, ~7.5 µs per
  entry. `getdirentries64` already reports d_type and d_ino; only nodes
  carrying a carrick mode xattr need more. Follow-up for the dentry-cache
  worker (a listing fills the cache; d_type from the host entry).
- **any open under a synthetic mount** (`/proc`, `/sys`, `/dev`) builds the
  ENTIRE `OpenContext` eagerly in `try_vfs_open`: memory snapshot, creds,
  groups, signal masks, the SysV shm/sem/msg tables (`msg_table` reads files
  and was 57% of the `/proc/self/fd` open), the process list, zombies,
  threads. CPython's `_posixsubprocess` lists `/proc/self/fd` on every spawn.
  Fix shape: lazy fields, so the opened node's renderer pulls only what it
  reads. Brief: `scratchpad/brief-lazy-proc-context.md`.

## 2026-09-05 late: mmap materialization is eager (file-backed 670x, anonymous 24x)

Microbench, `python:3.12-slim`, one binary, Docker on the same image:

| guest op | carrick | Docker | ratio |
|---|---|---|---|
| `mmap(MAP_PRIVATE, fd)` of a 6 MiB file + `munmap` | 1347 µs | 2.0 µs | 670x |
| same, fresh VA each time (kept mapped) | 1478 µs | 2.1 µs | 700x |
| `munmap` of one of those | 114 µs | 4.4 µs | 26x |
| anonymous `mmap` 1 MiB + `munmap` | 58 µs | 2.4 µs | 24x |
| `pread` 64 KiB | 9.4 µs | 1.8 µs | 5x |

Attached carrier CPU ranking on the file loop: 37% `write_guest_bytes`, 23%
host `pread`, 19% `__bzero`, 21% a 6 MiB `vec![0; len]`: the dispatcher's
eager snapshot path reads the whole file and copies it into guest memory
page by page (1,617 `write_guest_bytes` and 3,235 `ensure_sparse_mmap_backing`
calls per 6 MiB mmap). The lazy page-cache view (`materialize_private_file_backing`,
Move-3 E1) IS attempted every time (pid-provider counts: 200 candidates, 200
backend entries, 0 `overlay_shared_file_view`) and refuses inside the backend
after the whole-range hole walk (323,400 `mapping_for_range` calls for 200
mmaps = one full pass each), i.e. at the `alias_overlaps` scan, which also
walks EVERY alias in the registry per mmap. `ensure_sparse_mmap_backing`
runs before the view is attempted. Anonymous mmap spends its time in
`zero_anonymous_reuse` → `ensure_frame_cow_write` → `zero_guest_backing`
(bzero): a reused arena range is scrubbed eagerly at mmap time instead of
being re-materialized zero on first touch. Every exec of a dynamic binary
maps its libraries this way; this is most of the 3.7 ms spawn fixed cost.
Brief: `scratchpad/brief-mmap-lazy.md` (dispatch after the stage-1 authority
lands; same files).

## 2026-09-05 evening: Stage1Authority landed; lazy /proc context measured; cap-std to go

- **Stage1Authority landed** (`9a315bc22`, worker stage1-authority, three
  review rounds). The page-table manager, its arena source and the
  vfork share state live in one type; every stage-1 mutator takes the
  source explicitly (`Option<&mut dyn TableArenaSource>` is the contract);
  `Stage1Editor` has no `DerefMut` and the authority hands out no raw
  `&mut PageTableManager`. Round 1 caught two regressions the first draft
  would have shipped: the three COW rollback sites called a source-less
  `rollback_undo` (arena leak on every rollback) and the fork child rebased
  before its source was installed (fork of a grown process failed). Live
  receipt: 300,000-deep recursion then fork, both sides complete;
  `pagetablegrow`, `mincoreedge`, `forkstackstorm` MATCH.
- **Lazy `OpenContext`** (worker lazy-proc, landing): `/proc/self/fd` listing
  300 → 64 µs, `/proc/self/status` 382 → 82 µs, `/proc/self/maps` 414 → 52 µs
  (Docker: 3.6 µs for the listing). Round 2 will profile the residual.
- **Owner direction**: retire cap-std. With one kernel owning every guest
  fs syscall, carrick's namei (dentry cache → contained parent fd + leaf,
  one `*at` host call with `O_NOFOLLOW`) is the resolver; cap-std's
  per-component re-walk is redundant containment. Brief:
  `scratchpad/brief-retire-capstd.md`, queued as the dentry-cache worker's
  round 2. Workers `mmap-lazy` and `fork-table-copy` dispatched from the
  post-Stage1Authority main.
- **Open (flaky = flaw)**: the runtime's vfs/dispatch::fs unit tests fail a
  different test each PARALLEL run (`closedir` EBADF, stale `fd_open_paths`
  counts) on main and on branches; `just test` hides it by serializing the
  crate. Cached dir fds and the process-global resolve generation are shared
  or recycled across backends. Folded into the cap-std retirement brief: fd
  ownership becomes explicit in the dentry cache, parallel batch 10/10.
- **Open (tooling)**: four `carrick trace -s scripts/dtrace/hvpatch-stage1-arena.d`
  fronts from this morning were still alive as root 5–6 hours later with no
  guest, and a worker's `carrick trace --script /dev/stdin` wedged for 13
  minutes with the script on a pipe. `carrick trace` should bound itself
  (the flow script's 45 s bound is the model) and refuse a non-file script
  path; reaped with `scripts/sudo/kill.sh --all`.

## 2026-09-05 night: Stage1Authority broke exec-in-a-forked-child; caught by the gate

The probe gate on the post-landing main failed every shard at its first
probe: the carrier's executor pool refused shutdown ("quantum returned
without execution lease authority"). Reduced to `sh -c '/bin/true; echo
rc=$?'` → `rc=139`: every exec in a forked child died past its point of no
return with "install replacement HVPatch table arena source: conflicting
arena source". Two-point bisect (`1cb713732` good, `c3d001378` bad) named
the refactor; `replace_for_exec` kept the retired image's arena source and
the runtime's install of the replacement lease's source then refused. Fix:
the source retires with the image (red-first unit test
`exec_replacement_drops_the_retired_source_so_the_replacement_lease_installs`).

Why the worker's receipts missed it: its live checks were `run-elf` of
single probes and a CPython fork+`_exit`, none of which exec in a child.
Review rule from here: a page-table or exec landing's live receipt must
include the harness launch shape (`sh -c 'base64 -d > /tmp/p && … && /tmp/p'`)
and a fork+exec (`sh -c '/bin/true'`). Workers `mmap-lazy` and
`fork-table-copy` branched from the broken base; their fork/exec
measurements are void until they rebase.
- **Gate on the fixed main** (`696d0db59`): shards 0 and 2 green, shard 1
  red on `futexforkrequeue` only (requeue/wake counts and a timeout under
  the gate's load; 3/3 MATCH standalone). The oracle expects zero timeouts,
  so this is a load-sensitive verdict, not a match-by-luck: measured under
  identical synthetic load on the fixed main and on the pre-Stage1Authority
  binary to decide whether it is a regression or a pre-existing
  wall-clock-vs-scheduling flaw in the wake path (results below).
- **futexforkrequeue under load**: 10/10 MATCH on both the fixed main and the
  pre-Stage1Authority binary under six busy loops, so CPU load alone does not
  reproduce the gate's miss; the gate's own concurrency (three shards plus
  worker builds) does. Not a Stage1Authority regression. Open: reproduce with
  concurrent guests and read the wake path for a wall-clock assumption.
- **Dentry cache round 1** (worker dentry-cache, branch `agy/dentry-cache-sep06`):
  stat 21.7 → 2.9 µs, ENOENT 43.9 → 2.9 µs, open+close 30.9 → 17.1 µs.
  Rejected for landing on coherence: the positive dentry carries stat fields
  and only path syscalls invalidate them, so `write`/`ftruncate`/`link`/
  `O_APPEND` through a descriptor left size and nlink stale against Docker
  (11 vs 5, 1 vs 3, 2 vs 1). Round 2: dentries map names to inode identity;
  stat fields live in an inode record keyed by (dev, ino) that every
  fd-based mutation invalidates; red-first rows added to the `dentrycache`
  probe. The `open+close` residual (17 µs vs 1.2 on Linux) is the host
  `openat` itself and is the cap-std retirement's target (round 3).

## 2026-09-05 late night: fork copies only populated tables (worker fork-table-copy)

Two review rounds. Round 1 found the populated prefix recorded only at
publish, so growth after publish left stale descriptors in a recycled root
slot for its next occupant (silent corruption); round 2 records the prefix
on every host sync through the resolver (`record_populated_prefix`, a
`fetch_max` on the pooled slot handle) with a red-then-green sequence test.
Director receipt on the branch binary, `hvpatch-phase4-fork-process-spec-stages.d`
over the 1-page fork loop: phase 2 "parent table clone" 3.5 MiB / 0.19–0.24 ms
→ 128–256 KiB / 4–9 µs; phase 7 "table publish" 2 MiB / ~100 µs → ~110 KiB /
7–8 µs; process-spec total ~0.45 → 0.15–0.21 ms. Wall-clock ms/op is not
citable tonight (two workers compiling; main measured 2.1–3.6 ms against its
own 0.62 ms of the afternoon), so the byte counts are the evidence and the
quiet-host number follows. Fork/COW probes MATCH; `sh -c '/bin/true'` rc=0.
Open from the worker: `AliasRegistry::private_owned_containing_physical`
can panic on a reversed `BTreeMap` range when the scope's widest recorded
physical size is smaller than the query length; guard to land on main.
- **Gate on the fork-table-copy landing** (`8abf4648b` + reconcile): green,
  all three shards, the dedicated runners and the CLI suite. The alias
  reversed-range panic the worker reported is fixed (`ed304a27b`, red-first
  test `containing_physical_query_wider_than_any_recorded_row_does_not_panic`).

## 2026-09-06 early: dentry cache landed (worker dentry-cache, three rounds)

`d7c4e1f31` + `a249f8acb`: a hierarchical dentry cache over the host-backed
rootfs, names → inode identity, stat fields in an inode record keyed by
(dev, ino) that every descriptor-based mutation invalidates. Director
receipts on the branch binary, `python:3.12-slim`: stat 23.2 → 2.9 µs,
stat ENOENT 46.9 → 2.9 µs, open+close 33.1 → 15.7 µs (the residual is the
host `openat`; cap-std retirement's target), `listdir` of 201 entries
1544 → 840 µs (per-entry stats still there; next round). The 16-row
coherence script (fd writes, ftruncate, link, O_APPEND, rename, symlink,
child-process mutations) matches Docker line for line; the `dentrycache`
probe (49 rows) is Docker-blessed on both lanes after the stale gnu probe
binary was rebuilt (the first bless captured a 33-row build). Landing
mechanics lesson repeated: `git merge --ff-only` typed inside a worktree
merges into the worktree's own branch and reports "Already up to date";
fast-forward from the main tree only.
- **Gate on the dentry landing** turned three path-resolution rows red
  (`patherrno` ENAMETOOLONG, `unicodenorm` NFD aliasing, `legacyfs` hard-link
  nlink after unlink of the other name), each a rule the old resolver
  enforced somewhere the fast path bypassed. Fixed in one commit with the
  byte-exact name check lifted onto the `FsBackend` trait; all four probes
  match on both lanes; gate rerun recorded below. Lesson for the review rule:
  a resolver change must run the whole `fs`/`path` probe family, not the
  probe the worker wrote.
- **Second gate on the dentry fixes** turned `fifonode`, `bindunixnode` and
  `symlinkfollow` red: the unlink pre-resolve left a negative dentry that the
  FIFO `mknod` branch and the AF_UNIX `bind` node creation never announced.
  Patched (`badb9dac8`), all seven affected probes match on both lanes.
  Owner's reading is the right one: "lacks a `notify_create` call" is a
  rule in prose. The dentry cache moves behind the rootfs VFS object so
  every mutator maintains it inside the method and dispatch cannot reach
  the cache at all; briefed as the cap-std worker's round-3 add-on
  (`scratchpad/review-capstd-vfs-owned-dcache.md`).
- **Gate after the node-creation fix**: all three probe shards green
  (shard 2 in 249 s under worker load); the only red row was the CLI
  suite's closure-inventory denominator, still at 467/490/980 after the
  `dentrycache` probe was added (fixed `af1a1f752`).

## 2026-09-06: lazy mmap round 1 (worker mmap-lazy2)

Branch `agy/mmap-lazy-sep06` (five commits plus a continuation the director
committed after the worker's second transport death): lazy file views, an
O(log n) hole walk, MAP_FIXED-over-private retirement, and a skipped eager
arena scrub. Rejected: `python:3.12-slim python3 -c 'print(1)'` dies with
rc 139 on the branch binary while `ubuntu /bin/ls` runs. Fault record:
`esr=0x92000047 far=0x6000000028`, a write, level-3 translation fault at
the first page of the sparse mmap arena. The last commit stopped scrubbing
reused anonymous ranges eagerly and relies on first-touch materialization
that does not exist, so the first store faults through to SIGSEGV. Round
1 review requires the fault path to own lazy zero-fill (materialize a
zeroed compound and install the leaf) with a red-first test, then the
microbench and the mmap/COW probe family. A bisect build without the last
commit is running to confirm the attribution.

## 2026-09-06 morning: in-memory lane blind spot fixed; cap-std round 2 fails on glibc images

- **Main**: `mkdirat_creates_overlay_dir_and_fstatat_sees_it` had been red
  since the dentry landing and none of the earlier filtered test runs
  covered its group. The dentry cache fills from host fds and `real_stat`,
  so on `FsBackendKind::Memory` guest-created entries were invisible to it.
  `FsBackend::serves_dentry_cache` (host backend only) gates the three
  `RootFsVfs` entry points; `notify_create` also clears negative entries
  along the whole created path. Full serial runtime suite green (2440),
  `1bb1edbf4`.
- **cap-std retirement round 2** (`e61e95028`, worker's tree committed by
  the director after a third transport death): cap-std and cap-primitives
  are out of the graph and banned; the parallel fs test batch is 10/10 (3/3
  in the director's runs). Rejected: every glibc image exits 127 before the
  guest runs. Proof: `ubuntu:24.04 /usr/bin/true` → 127; the same program
  launched through its real interpreter path
  `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 /usr/bin/true` → 0. The
  new namei refuses a symlinked intermediate directory (`/lib -> usr/lib`,
  where the interpreter lives) and follows links only at the leaf; the
  removed cap-std walk used to re-root intermediate targets under the guest
  root. The extraction rewrite also wrote `/bin` as an empty real directory.
  Round 3b: full component-wise namei with carrick-side symlink resolution,
  extraction fidelity, `namei_escape` rows for symlinked intermediates, and
  glibc launches as mandatory receipts.
- **Gate on `1bb1edbf4` + positions chore**: signed build, `ubuntu:24.04`
  fork+exec sanity, and the full `just conformance-probes` gate all green
  (rc 0). Main is landed end to end after the dentry cache and its five
  follow-ups.
- **Lazy mmap round 2** (`65c9b48d6`): the CPython crash is fixed by a
  fault-path zero-fill (frame pool first, per-fault allocation on a miss)
  and every mmap/COW probe matches both lanes. Performance regressed: file
  mmap 1444 → 3222 µs, anon 58 → 98 µs, spawn 4.5 → 6.4 ms. The page-cache
  view is installed 100/100 times and the dispatcher still copies all 1,616
  pages through `write_guest_bytes` afterwards, so installing the view only
  added work. Round 2 requires a zero-copy receipt for a whole-file private
  view before any number is re-measured.

## 2026-09-06: cap-std retirement rounds 3–4 — glibc fixed by the worker, extraction containment lost

Round 3 (`b97a9d32e..20165cef4`, rebased onto main by the director) removed
the fork from the descriptor-exhaustion test, moved the dentry cache behind
`RootFsVfs` with four mutator verbs and zero dispatch references (the
owner's structural ask), and resolved intermediate directory symlinks in
`dir_fd_for`, which the worker found itself via `accessx`/`fexecveprobe`.
Director receipts on that binary: `ubuntu:24.04 /bin/true` rc 0, `sh -c`
child exit reported, CPython prints. All three probe shards green in the
worker's run.

Blocking finding at the lint gate: 88 new host-authority rows, and the
real ones are `extract_to_dir` rewritten from cap-std's `Dir` methods to
`std::fs::*` on `dest.join(<layer entry path>)`. Image content is
untrusted; with `Path::join` a `../` entry escapes the scratch root and an
absolute or directory symlink entry is followed by the host for later
entries. No test ever guarded this because cap-std made it unrepresentable.
Round 5: extraction becomes fd-relative namei from the scratch root fd
(`mkdirat`/`openat(O_EXCL|O_NOFOLLOW)`/`symlinkat`/`linkat`/`unlinkat`),
red-first escape tests, then the inventory rows classified one by one.
- Correction: `/bin` and `/sbin` appearing as empty real directories on
  `ubuntu:24.04` is identical on main (directory mtimes from the run
  itself), so it is pre-existing and not the extraction rewrite; the
  containment regression stands on the `dest.join` shape alone. Open item
  on main: where the run-time `/bin` and `/sbin` directories come from on a
  merged-usr image (see the merged-/usr clonefile note in memory).

## 2026-09-06: `carrick trace` fails closed on an unbounded custom script

Five wedged root-owned tracers in one day, all the same shape: a worker's
`-s` script with no `exit()` outliving a one-second guest, because the
consumer let a custom script outlive the traced child on the strength of a
skill rule. `14cb2439c`: a bounded post-child drain (60 s, hatch
`CARRICK_TRACE_POST_CHILD_LINGER_S`, `0` = legacy) then a named
`ScriptOutlivedChild` error that says what to add. Red: still running at
a 40 s cap; green: named error in 6 s with a 5 s bound; the self-exiting
flow script still completes. Also learned: `scripts/sudo/kill.sh --all`
matches its own caller if the caller's command line contains the literal
`release/carrick trace`, so never grep for that text in the same command.

## Handoff at 2026-09-06 landing

**Main** (`38a5d78be`): clean, full probe gate green (gate44, rc 0), serial
runtime suite green, lint green through the ledger step (a final
`just lint-domains` was still running at landing; the only change after the
last green lint was the ledgered env-var row).

**Landed this campaign leg**: frame pool; lazy `/proc` context; fork
populated-table copy + root-slot pool; Stage1Authority (plus its exec fix);
dentry cache with inode records, five follow-up fixes and the in-memory-lane
capability gate; alias planner and alias range-panic fixes; the exec-in-child
regression fix; `carrick trace` bounded custom-script drain.

**In flight, parked** (worktrees under `.worktrees/`, briefs in this
session's scratchpad are summarized here):
- `agy/retire-capstd-sep06` (worker `retire-capstd`, round 5 running):
  cap-std is out and banned, namei is the resolver, dentry cache is behind
  `RootFsVfs` (zero dispatch references), glibc images run. BLOCKED on a
  security regression: `extract_to_dir` uses `dest.join(<layer entry>)` +
  `std::fs`, so a `../` or symlink entry escapes the scratch root. Required:
  fd-relative extraction (`mkdirat`/`openat(O_EXCL|O_NOFOLLOW)`/`symlinkat`/
  `linkat`/`unlinkat` from the root fd) with red-first escape tests, then
  classify the 88 host-authority rows, then land. Correction already sent:
  `/bin` as an empty dir is pre-existing on main, not the branch.
- `agy/mmap-lazy-sep06` (worker stopped after five wedged tracers; the
  tracer now fails closed so a fresh conversation can take it): correctness
  restored (CPython runs, all mmap/COW probes match) but file mmap is 3222 µs
  vs main 1444 vs Docker 2, anon 98 vs 58 vs 2.4. The page-cache view is
  installed 100/100 and the dispatcher still copies 1,616 pages per mmap
  through `write_guest_bytes`; find why `lowered_file_backed` does not skip
  the snapshot, prove zero-copy, then re-measure.
- Not started: readdir per-entry stats (840 µs / 201 entries), the
  VFS-owned invalidation is done but `serves_dentry_cache` means the
  in-memory lane has no cache at all.

**Open items**: `futexforkrequeue` gate-concurrency sensitivity; the `/bin`
and `/sbin` run-time directories on merged-usr images; `docker_compose`
smoke sharing a test binary with carrick lanes; stale `.worktrees/` (over a
hundred, including `bisect-*`); the quiet-host fork number and a fresh full
ecosystem ledger, both deferred until the two parked branches land.

## 2026-09-06 resumed: cap-std accepted on macOS

The reviewed `agy/retire-capstd-sep06` work landed through the acceptance branch
at `5c959e191`, fast-forwarded from the main checkout. Full serial runtime
2467 passed / 2 ignored; full cached generic probe gate 874/874 across musl
and GNU; lint, Ubuntu glibc launches, Python print and coherence loops passed.
The full probe run additionally exposed and fixed the dentry fast-open
O_NOFOLLOW bypass with a red-first dispatcher regression. Exact artifact and
run receipts: [cap-std acceptance](2026-09-06-capstd-acceptance.md).

Scope is macOS and pathological performance affecting correctness. Further
cross-platform xattr work is deferred. Next: rebase the parked mmap branch
onto this landing, use a fresh worker conversation, prove zero write_guest_bytes
for the whole-file private view and meet file <=10 us / anon <=6 us. The
quiet-host fork number and full cached ecosystem ledger remain pending; the
Sep 4 floor is not replaced yet.

## 2026-09-06 mmap accepted and Sep 4 floor replaced

The reviewed `agy/mmap-lazy-sep06` branch landed at `3889fde8e`,
fast-forwarded from the main checkout. Exact-artifact acceptance satisfied the
whole-file private-map zero-copy contract: 100/100 mappings, zero errors, zero
`write_guest_bytes`, and zero copy chunks. A forced eager positive control
copied 661,504,000 bytes in 161,500 chunks. Untraced five-by-1,000 CNTVCT
trials measured 6.346125 us median for a whole-libpython private file mmap and
4.302208 us for a 1 MiB anonymous mmap, below the 10/6 us gates.

The complete serial runtime suite passed 2,473 tests with 2 ignored. The whole
signed probe family passed 470 generic probes on each libc lane, 24 dedicated
cases, the CLI boundary contract, 46 retained probes with 1 ignored, and the
container gate. Ubuntu shell true, Python print, and five Python allocator
imports passed with fresh run IDs and zero scoped survivors. Artifact identity,
launch, copy, latency and gate details are in
[the mmap host contract](2026-09-06-mmap-host-contract.md).

On the rebuilt main artifact (source `3889fde8e`, SHA-256
`82c8bb495f791466b6c0fdc2926f97a2d3949e4e67d18d5f2c173b6decc9cb2f`), the
quiet-host fork reducer settled below load 4 with no `yes` or Carrick process
present, then measured 300 fork-to-wait samples after 30 warmups: p50
250.875 us, p95 315.042 us, minimum 212.875 us. Against the retained 80 us
Linux reference, the current fork floor is 3.14x and remains above target.
Receipt: `target/conformance/eco-final-ledger/quiet-fork-3889fde8e.json`.

The four declared oracle image IDs and live registry digests exactly matched
the frozen closure scope. Docker was then stopped and verified unavailable.
The four-worker Carrick-only run used all 2,127 cached oracle rows and wrote
2,127 unique results with 2,127 fresh child run IDs; no guest or harness
survived. The harness returned 1 solely because the discovery contains gating
rows. Receipt:
`target/conformance/eco-final-ledger/ledger-3889fde8e.jsonl` and its log and
machine summary in the same directory.

This result replaces the Sep 4 floor:

| Ecosystem | Match | Regression | Crash | Timeout | Known diff | Unbaselined |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CPython | 420 / 438 | 11 | 1 | 6 | 0 | 0 |
| Go | 177 / 194 | 5 | 12 | 0 | 0 | 0 |
| LTP | 1,452 / 1,492 | 20 | 0 | 3 | 10 | 7 |
| Node | 2 / 3 | 1 | 0 | 0 | 0 | 0 |
| **Total** | **2,051 / 2,127 (96.43%)** | **37** | **13** | **9** | **10** | **7** |

There are 59 gating verdicts, versus 47 on Sep 4. Twenty-two former blockers
became matches, including the targeted fanotify, clock, pipe, splice, memfd,
mremap and process-vm rows. Thirty-four former matches became nonmatches, so
the net coverage count fell by 12. The replacement floor is intentionally not
smoothed or re-blessed around those regressions.

The remaining work ranks as follows:

1. **Repair page-table/root publication before further optimization.** All 13
   crash rows have one HVPatch authority failure family: 11 direct
   projection-manager/CPU-TTBR root mismatches, one conflicting arena-source
   install, and CPython regrtest dropping an active published inventory before
   exact retirement while also reporting the root mismatch. Twelve are Go
   packages and one is CPython. This is the first correctness blocker and is
   suitable for unperturbed core plus event-ring attribution.
2. **Repair the fd-relative namei/file-description regressions as one cluster.**
   Twenty-one of the 22 match-to-regression transitions are path/filesystem
   rows: CPython ctypes, mailbox, pathlib, shutil, tarfile, venv and zipfile;
   Go build, io/fs and path/filepath; and LTP chroot02, fcntl01/11, lstat02,
   open07, readlink03 and stat03 including their 64-bit variants. Representative
   failures include temporary files becoming immediately unstatable and LTP
   directory cleanup returning EISDIR. Go's FIPS CAST regression is the one
   transition outside this cluster.
3. **Treat nine budget-aligned rows as hangs, not ratios.** CPython compile,
   importlib and asyncio stop at about 300 s; concurrent_futures,
   multiprocessing_fork and multiprocessing_forkserver stop at about 600 s.
   LTP inotify09, msgstress01 and shmctl05 stop at about 40 s. Reduce these after
   the page-table crash and filesystem clusters so a shared cause is not counted
   repeatedly.
4. **Remove excess time above 2x in total-cost order.** Among semantically
   matching rows, the largest excesses are CPython multiprocessing_spawn
   (394.800 s, 6.46x, 272.626 s above 2x), multiprocessing_main_handling
   (253.480 s, 87.65x, 247.696 s excess), threading (165.435 s, 11.97x,
   137.803 s excess), os (77.679 s, 94.27x, 76.031 s excess), and logging
   (102.828 s, 7.42x, 75.116 s excess). The next structural rows are CPython
   itertools, tempfile, compileall, uuid, tracemalloc and random, plus
   `ltp-munmap04` at 73.32x and `ltp-epoll-ltp` at 21.96x. End-to-end
   `cpython-mmap` is correct but remains 4.21x despite the primitive mmap gate.
5. **Lower the process floor.** Quiet-host fork remains 3.14x the retained
   Linux number, so fork/exec amplification remains a separate cross-workload
   term after the correctness clusters are fixed.

Of the 2,051 matching rows, 397 are still at or above 2x, 56 are at or above
5x and 25 are at or above 10x. The >=2x matches consume 70.11% of all matched
Carrick time; the >=10x matches consume 30.03%. Aggregate matched time is
1.623x the cached oracle and the median ratio is 0.49x, but only 1,654 of 2,127
rows (77.76%) currently satisfy both semantic match and <2x. The live backlog
to the combined goal is therefore 473 rows: 76 semantic/nonexecution rows plus
397 matching but slow rows.

## 2026-09-06 evening: the 2x campaign — baseline attributed, five workers dispatched

Owner directive: drive the pathological ratios to 2x, fork and memory first,
clean baseline then cluster and fix; Antigravity workers on Gemini 3.8 high
do the code, the director reviews and lands.

**Baseline.** `ledger-3889fde8e.jsonl` (section above) is the clean run:
main `48629d304` differs from `3889fde8e` only in documentation, and the
shipped binary still carries SHA-256 `82c8bb49…`, so re-running would have
measured the same artifact. Its ratios are load-inflated (four workers): the
same `cpython-re` row is 19.2 s in the ledger, 8.1 s standalone, 0.4 s in
Docker. Standalone quiet-host numbers are the campaign's working figures;
the full ledger is re-run only after landings.

**Instrument that found the clusters.** Attach the user-stack ranker to the
live carrier ~2.5 s after launch:

    sudo dtrace -qs scripts/dtrace/hvpatch-carrier-user-cpu-ranking.d -p "$(pgrep -f 'carrick:<run-id>:' | head -1)"

(direct `sudo`, never under `timeout`: sudo then has no tty and the attach
fails silently with rc=1). `carrick trace -s hvpatch-phase4-whole-cpu.d`
first showed that syscall services were NOT the cost (3,713 services, 0.2 s,
of ~10 CPU-s), which is what pointed at the fault path.

**Clusters, each reproduced standalone on the baseline binary:**

1. *AliasRegistry batch removal is O(rows-in-mm) per fault.* ~90% of carrier
   user CPU in `test_re` is `remove_exact_values_in_batch` →
   `rebuild_scope_rows`, which clones the whole scope bucket, filters it,
   un-indexes and re-indexes every row across five secondary indexes and
   rebuilds the exact-first index, once per retired stage-2 projection —
   i.e. per COW fault and per first-touch fault. The compile-suite "hang"
   (`test_compiler_recursion_limit`) is the same cost: 45k sequential 4 KiB
   first-touch write faults at ~270 µs each (`hvpatch-phase4-guest-fault.d`).
   Worker `alias-batch`.
2. *Semantic VMA maintenance is O(n) per mmap.* `ltp-munmap04` (65k maps)
   spends 90% in `trim_semantic_vmas` + `coalesce_semantic_vmas` (a whole-Vec
   sort per mmap). The same list's coalesce compares every attribute except
   `dump_policy`, so a `MADV_DONTDUMP` sub-range is re-merged and loses its
   policy. Worker `vma-map` (a `VmaMap` type owning split/adjust/merge).
3. *Guest-created symlink-to-directory as an intermediate component.*
   `open07` (creat via `symdir1/`), `lstat02`/`readlink03` (ELOOP cases
   succeed), `chroot02` (absolute path after chroot), `fcntl01` and siblings
   (tmpdir cleanup EISDIR), CPython shutil/zipfile/tarfile. All entered with
   the cap-std retirement. Worker `namei-symdir`.
4. *Parallel fork+exec from a multithreaded process kills the carrier.*
   Go `testing.TestFlag` (three parallel subtests re-exec the binary) →
   "task projection manager root … does not match CPU TTBR root" on every
   executor, then "published HVPatch inventory dropped before exact
   retirement". Twelve Go rows and `cpython-regrtest`. Worker `exec-ttbr`.
5. *Storage interface cannot report host errors.* `FileContents::read_at`
   turns a `pread` error into a short/empty result (EOF), `resize` ignores
   `ftruncate` failure. Worker `storage-fallible` (from the owner's static
   review; verified in source).

Queued from the same review, verified in source, not yet dispatched: the
mixed/synthetic `ppoll` path (`net.rs` ~7340) sleeps in 10 ms slices,
estimates elapsed time by counting sleeps and returns 0 after ~60 s to an
indefinite waiter — needs a kernel wait set with owned registrations; the
host-operation fd capability type; file-operation policy behind
`FileDescriptionBacking` (`write_shared_supported` keeps a second list of
writable variants); in-kernel AF_UNIX for guest-local sockets.

**Found while verifying worker binaries (queued, not yet dispatched):**
- `*getxattr` on any lower-layer (image) path returns ENOENT instead of
  ENODATA (`HostFsBackend::get_xattr` → `metadata_fd` only finds upper-layer
  entries). Debian's GNU `ls -l` reports the unexpected errno per entry, which
  is how `ls -la` "fails" in every image directory on the Go image and why
  `fs.WalkDir`/`go list` rows fail (`go-build`, `go-io_fs`, `go-path_filepath`,
  `crypto/internal/fips140test`). Handed to the namei worker.
- Trailing `/.` and `/` path forms (`stat("dir/.")`, `stat("dir/")`,
  `stat("file/")` must be ENOTDIR) fail; Go `os` `TestRootConsistency{Stat,Lstat}`,
  `TestCopyFSWithSymlinks`. Handed to the namei worker.
- With the exec crash fixed, `go-syscall` runs into `TestSetpgid` and hangs
  to the 300 s cap (twice), and `go-types` runs `TestSelf` past 300 s
  (previously both crashed in under a second, so these were masked).
- A one-off `scheduler generation observer lost exact transition … run queue
  publication authority does not match the submitted generation` abort in
  `TestUnshareMountNameSpaceChroot` under concurrent load; not reproduced in
  two quiet re-runs on either binary.

**Landing receipts so far (director-verified on each worker's binary):**
- alias-batch (two rounds; round 2 finished by the director after a
  transport timeout): registry tests 9/9, clippy/fmt clean, `test_re`
  user CPU 7.7 → 2.5 s standalone (3.5 s under four concurrent worker
  builds), `test_os` 39 → 17.7 s under load. Landed as `5ed36c064` +
  `79499d032`; the abort shard re-blessed by hand (`upsert_by_key` gained a
  fourth carrier-fault site, `rebuild_scope_rows` is test-only).
- exec-ttbr (two rounds): the vfork share state is a counter on
  `Stage1AuthorityInner`; the runtime's predecessor-sharing hint is a
  warn-only witness, never a decision input. `testing.test` 5/5 and 2/2,
  `forkexecstorm` probe green, `os_exec`/`os_signal`/`net_netip` PASS.
  Landed as `135bc3b42`.
- vma-map (two rounds): `dump_policy` merge fix + `VmaMap`/`VmaAttributes`
  with O(log n + affected) mutations (partition_point + splice + neighbour
  merge; global coalesce only in bulk constructors, debug-asserted
  otherwise). `ltp-munmap04` 30 s timeout → 2.6 s and now reproduces the
  oracle's own `tst_test.c:1948` SIGSEGV TBROK exactly (Docker: 1.2 s).
  `vma_map` tests 5/5 re-run by the director.
- namei (two rounds, both turns ended on transport timeouts with the code
  complete; the director gated and committed): intermediate symlink-to-dir
  via `validate_parents_fast`, ELOOP on loops, chroot-aware stat/access
  fast paths, dentry-cache inode/nlink invalidation on child create/unlink/
  rename (the EISDIR cleanup failures), xattrs served through the dentry
  cache across layers (ENODATA, not ENOENT, on image paths), trailing `/.`
  and `/` normalization with the directory requirement preserved. Receipts:
  open07/lstat02/readlink03/chroot02/stat03 all pass, `ls -la /usr/lib` on
  the Go image 32 → 0 errors, Go `os` `TestRootConsistency|TestCopyFS`
  PASS, CPython shutil/zipfile/pathlib/tarfile subsets SUCCESS. Landed as
  `2582ea944` + `52357bf57`.
- Attribution after the exec fix: `go-syscall` `TestSetpgid` passes in 70 ms
  without `-t` and wedges under `-t` — all executors idle, the `pty-relay`
  thread spinning in `poll` at ~85% CPU (it only handles POLLIN/POLLHUP);
  `go-types` `TestSelf` passes standalone in 34 s with 30% of carrier CPU in
  that same relay `poll` and most of the rest in dentry slow-path `openat`s.
  Worker `pty-jobctl` dispatched for both relay defects; the dentry
  slow path is the next fs perf item.
- storage-fallible (two rounds; round 2 ended on a transport timeout with
  the code complete): `FileContents` is `read_at(&mut [u8]) -> Result<usize,
  LinuxErrno>` / `write_at` / `len() -> Result` / `resize() -> Result`, host
  errors are typed errnos, partial progress follows Linux (bytes moved, else
  the errno), and the mmap populate path refuses with the errno instead of
  zero-filling. Serial runtime suite 2,491 passed after landing; LTP
  read/pread/pwrite/ftruncate/readv/memfd rows 6/6 on the branch binary.
  Landed as `01424766a`.

Main after these five landings is `HEAD` of this section's commit. The
landed rows are re-verified standalone on that binary in the next section;
the full cached ecosystem ledger is re-run once the first-touch, ppoll and
pty-jobctl workers land, so a single artifact carries all of it.

## 2026-09-07: sixth landing, two rejections, and where the fault path's cost went

- **pty-jobctl landed** (`d137ef232`, `cf15c8c59`, probe `f5b4d784a`, main
  `4ec85a708`): the relay loop is fail-closed on `POLLERR`/`POLLNVAL` and a
  0-byte non-tty stdin (it spun at 85% CPU under `-t` with stdin from
  /dev/null), and job control follows POSIX for background process groups
  on the controlling tty (TOSTOP off: background writes succeed; background
  reads get SIGTTIN, or EIO when the group is orphaned or SIGTTIN is
  ignored/blocked). Receipts on the branch binary: `go-syscall`
  `TestSetpgid` under `-t` PASS twice (was a 300 s wedge), `os_signal`,
  `os_exec` PASS, LTP setpgid01–03 pass, 2,492 runtime tests. The
  `ptyjobcontrol` probe is committed but not yet registered: registration
  needs a Docker-oracle bless, which is a Docker-only phase.
- **What the setpgid wedge unmasked**: the full `go-syscall` suite now aborts
  the carrier under host load in `TestUnshareMountNameSpaceChroot`
  (`scheduler generation observer lost exact transition … run queue
  publication authority does not match the submitted generation`, then
  every executor `failed boundary audit before ASID invalidation`), 2 of 4
  loaded runs, 0 of 4 quiet, on two different binaries. Worker
  `exec-generation` is reproducing it deterministically under a load
  generator before fixing the transition authority.
- **ppoll wait set, round 1 accepted, round 2 checkpointed** (`054605932`,
  `67297a4cb`, `a40d54516`): the 10 ms slicing loop is gone; pipe wake
  1.09 → 0.29 ms and eventfd 2.11 → 0.09 ms once the wake pipe became
  per-executor; 30 ms timeouts land at 30.6 ms; an 85 s infinite wait no
  longer returns 0 at 60 s. Still red: a `SIGALRM` to a task parked in a
  mixed `ppoll` does not produce EINTR (the itimer publication path does
  not reach the task-wake subscription) — worker `ppoll2`.
- **vfs-hot2 round 1 rejected.** Measured back-to-back against main's
  binary under the same host load (~15): the branch made stat 4.6 → 28 µs,
  open+close 21.6 → 99 µs, ENOENT 3.6 → 19 µs and listdir(202) 0.95 →
  4.8 ms, doubled go-types `TestSelf` to 71 s, and its fstat cache returned
  the HOST uid/gid (501/20) for lower-layer files where the layered record
  says 7/9. Lesson written into the brief: a perf branch is measured
  against main's binary in the same run, never against yesterday's quiet
  numbers. Worker `vfs-hot2b` has the table and the red test.
- **first-touch, three checkpoints** (`86df75872`, `ca6533f0e`, `0be17ee7b`
  plus the worker's own `ee46d7e5c`…`ea6c351b7`): interval index on the
  task mapping table, bounded alias queries, in-place retain, batched
  retirement, and an IPA index for `host_ptr` (lldb on the spinning carrier
  showed `mapping_for_ipa_range` — a reverse linear scan by IPA — under
  every stage-1 PTE edit). The million-depth compile reducer now completes
  (8.8 / 54 / 31 s per shape under load) instead of hitting the 300 s cap;
  the remaining cost is 84% address-space retirement
  (`stage_retirement` + `retire_task_state_process_mappings_inner` per
  mapping) and one red rollback test — worker `first-touch3`.
- Landed-main receipts after the fifth landing (SHA `c52a38a2…`): test_re
  8.1 → 2.9 s, test_os 41.9 → 20.7 s (under load), munmap04 30 s → 1.2 s,
  multiprocessing_main_handling 253 → 33.6 s standalone (still 11× Docker;
  profile: first-touch 35%, retirement 10%, an `fgetxattr` per `fstat` 5%),
  `ls -la` on the Go image 32 → 0 errors, go testing/os_exec/io_fs/
  path_filepath PASS. One load-coupled flake recorded: a child SIGSEGV in
  `runtime.memmove` during `crypto/internal/fips140test` `TestCASTFailures`
  under three concurrent builds, 0/6 quiet reruns.

## 2026-09-07: seventh landing — the kernel wait set

Landed `cc136d016`, `4d16538c1`, `ef46cef07` (main `1ff55a204`): mixed and
synthetic `ppoll`/`pselect6` sets enroll on carrick-owned readiness queues
(pipes, eventfd, timerfd, pure AF_UNIX sockets, epoll instances) with RAII
registrations, park on one wake pipe per executor multiplexed with the host
fds, and use monotonic deadlines. The 10 ms `nanosleep` slicing loop and its
~60 s "give up and return 0" ceiling are gone. Signal publication wakes a
parked wait set through the task-wake subscription, and process-directed
signals prefer the thread-group leader so a watchdog thread cannot steal
them from the parked leader. Receipts on the landed binary under host load
~15: pipe wake 2.3 ms (0.29 ms on a quieter host; was 5–7 ms), `SIGALRM`
armed at 100 ms interrupts the wait at 107.9 ms with EINTR, a sibling's
`SIGUSR1` interrupts in 0.13 ms, a blocked `SIGALRM` correctly does not
interrupt, 30 ms timeouts land at 30.6 ms, an 85 s infinite wait no longer
returns at 60 s; LTP poll01/ppoll01/select01/pselect01/alarm02/setitimer01
pass; CPython test_signal/test_selectors/test_poll/test_select SUCCESS;
2,491 runtime tests. Open follow-up recorded by the worker: a long mixed
wait still holds its executor host thread (parity with the old loop), to be
routed through the lease-release helper other long host waits use.

## 2026-09-07: a pre-existing directory-listing defect behind the pathlib rows

While gating the vfs round-3 branch, `test_pathlib` failed on main too:
68 tests on the Sep 6 baseline build, 134 on today's main, 189 on the
branch — every one the same shape: `os_helper.rmtree` calls `os.unlink`
on `dirA` (EISDIR) because `scandir`'s `is_dir(follow_symlinks=False)`,
i.e. carrick's `getdents64` `d_type`, said the directory was not one, and
every later test's `setUp` then fails with `FileExists`. The earlier ledger
summaries only quoted the first six failing test names, which hid the size
of this row. It is not one test's doing: no alphabetical group before the
first failure triggers it, and the exact `setUp` tree replays cleanly once.
A loop of `setUp` + `rmtree` (`plcycle.py`, now in the vfs worktree's
`target/`) fails deterministically at cycle 225 on main: immediately after
`setUp` every entry's `d_type` matches `lstat`, so the mis-pairing happens
mid-stream, after deletions, at an accumulation boundary in the directory
listing/dentry cache. Worker `vfs-hot2d` has the reducer. The vfs branch it
runs on is otherwise at parity or better than main back-to-back (fstat
3.8 vs 25 µs, open+close 16.6 vs 19 µs, stat/ENOENT/listdir equal, 2,494
runtime tests) after the worker reverted its own getdents change and
fixed `utimensat` `AT_SYMLINK_NOFOLLOW` on dangling symlinks.

Also this section: the exec-generation race is parked after three
conversations (a probe that does not reproduce; a draft that re-checks and
falls back, which the brief forbade); it stays an explicitly open item for
a director-driven instrumented reduction. first-touch is at round 5: the
million-depth compile reducer went from a 300 s cap to 72 s and
`test_compile` from a 420 s timeout to 62 s, but the batched stage-2
retirement broke four rollback/custody invariants that the round must
restore before it lands.

## 2026-09-07: the first-touch branch is parked, and the second ledger is running

Measured on a quiet host (load ~2.6) after the eighth landing:

| binary | multiprocessing_main_handling | test_compile |
| --- | ---: | ---: |
| main `ed3a42c85` | 32 s | 420 s (cap) |
| branch at the mapping index + owner-generation fix | 117 s | 183 s |
| branch at + O(n) retirement (4 custody tests red) | 142 s | 66 s |
| branch at + custody fix | guest SIGBUS | guest SIGBUS |

The indexed `MappingTable` fixes the first-touch hang but makes every
fork/exec/retire clone or rebuild the whole table, so fork-heavy rows get
3–4× slower; the later custody fix and the alias-retirement optimization
retire frames a sibling still shares. A mechanism measured worse is not
shipped: the branch is parked at `agy/first-touch-sep06`, the one neutral
commit (diagnostic walk off the handled path) was measured alone and
discarded, and the next design is briefed with the constraint that fork
and retire cost must scale with the mappings that change, caching the
page-table arena's host pointer on the stage-1 authority rather than
indexing the table.

With no worker running, the full cached ecosystem ledger is being re-run on
main `ed3a42c85` (binary SHA-256 `a4c5c672…`), same invocation as the Sep 6
baseline (`--workers 4 --carrick-timeout-cap-s 0 --require-cached-oracle`),
into `target/conformance/eco-final-ledger/ledger-ed3a42c85.jsonl`; the host
is kept free of other guests and builds for its duration.

## 2026-09-07: second ledger — the campaign's measured effect

Same harness invocation and cached oracle as the Sep 6 floor, on main
`ed3a42c85` (binary SHA-256 `a4c5c672…`), host otherwise idle. Receipt:
`target/conformance/eco-final-ledger/ledger-ed3a42c85.jsonl` (+ `.log`,
`-summary.txt`).

| Ecosystem | Sep 6 match | Now match | Regression | Crash | Timeout | Known diff | Unbaselined |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CPython | 420 / 438 | **431** / 438 | 3 | 0 | 3 | 1 | 0 |
| Go | 177 / 194 | **189** / 194 | 2 | 1 | 1 | 1 | 0 |
| LTP | 1,452 / 1,492 | **1,459** / 1,492 | 11 | 0 | 4 | 11 | 7 |
| Node | 2 / 3 | 2 / 3 | 1 | 0 | 0 | 0 | 0 |
| **Total** | **2,051 (96.4%)** | **2,081 (97.8%)** | 17 | 1 | 8 | 13 | 7 |

Gating verdicts 59 → 26. Thirty-four rows flipped to match (all twelve Go
crash suites, the LTP fs regressions, cpython asyncio/importlib/
multiprocessing_forkserver/regrtest/pathlib/shutil/tarfile/zipfile/venv/
ctypes/mailbox); four LTP rows flipped the other way (`fcntl29`: execve
past the point of no return kills the guest; `open04` timeout; `openat03`
and `renameat202`: ENOENT on a just-created file — the dentry-cache
eviction path, see below) and are the first items of the next leg.

Time: the rows that were hangs or pathologies moved by tens to hundreds
of seconds each (importlib 300 → 31 s, asyncio 300 → 176 s,
multiprocessing_main_handling 253 → 98 s, threading 165 → 42 s, logging
103 → 28 s, os 78 → 19 s, munmap04 29 → 1.8 s, tempfile 31 → 4 s, uuid
27 → 2 s, tracemalloc 25 → 4 s). Against the 2x bar the aggregate is
worse, not better: matched carrick time 3,107 → 3,809 s over 30 more
matching rows, rows meeting both match and <2x 1,654 → 1,636 (77.8% →
76.9%), rows ≥2x 397 → 445. Two causes are visible in the rows: newly
matching suites are now counted at their full (slow) cost where a crash
used to cost nothing (go_types 0.7 → 31 s, net_http 2.5 → 25.6 s,
regrtest 10 → 42 s, tarfile 24 → 142 s), and create-heavy LTP rows gained
~1.1 s each (mknod01, mkdirat02, mkdir05, link05) from the dentry cache's
4096-directory bulk reset, which also explains the two ENOENT rows above.
Neither is the fault path: that branch is parked with its measurements in
the previous section.

Open at hand-off, in priority order: (1) replace the dentry cache's bulk
reset with per-entry eviction and re-verify `openat03`/`renameat202`/
`fcntl29`/`open04`; (2) the first-touch redesign under the fork-cost
constraint (brief in the session scratchpad, `brief-first-touch-v2.md`);
(3) the exec-generation race (go-syscall, go-net under load); (4) the
Docker-only bless of the three new probes; (5) the per-suite fixed cost
on small CPython rows (abc 0.70 → 0.90 s), to be attributed standalone.

## 2026-09-07: load coupling measured — the goal's third leg

Owner goal (2026-09-07 morning): the fork/memory rows match at ≤2x on the
standard cached ledger with `--workers 4`; fork-to-wait under four sibling
guests ≤2x Linux; nothing that matched in `ledger-ed3a42c85` regresses; any
row whose ratio moves more than 1.5x between an idle host and the 4-worker
run is a load-coupling defect to be fixed, not excused.

**Idle vs ledger.** Same binary (`a4c5c672…`, main `b82dd2b7c` is docs-only
on top of the ledger's source), same harness invocation, one suite at a
time on a quiet host (`target/conformance/eco-idle/`):

| row | idle s | 4-worker ledger s | loaded/idle | Docker s | idle/Docker |
| --- | ---: | ---: | ---: | ---: | ---: |
| cpython-itertools | 28.1 | 80.4 | **2.86** | 1.0 | 27.2 |
| cpython-importlib | 10.9 | 30.8 | **2.83** | 2.7 | 4.05 |
| cpython-multiprocessing_main_handling | 32.9 | 98.0 | **2.98** | 2.9 | 11.4 |
| cpython-tarfile | 80.4 | 142.5 | **1.77** | 4.8 | 16.9 |
| cpython-threading | 27.0 | 42.4 | **1.57** | 13.8 | 1.95 |
| cpython-subprocess | 71.1 | 111.0 | **1.56** | 20.7 | 3.44 (2 diffs) |
| cpython-asyncio | 108.8 | 176.0 | **1.62** | 72.1 | 1.51 |
| go-go_types | 22.6 | 31.0 | 1.37 | 6.2 | 3.65 |
| go-net_http | 22.0 | 25.6 | 1.16 | 4.1 | 5.36 |
| go-runtime_pprof | 41.8 | 49.4 | 1.18 | 17.2 | 2.44 (TestTimeVDSO) |
| cpython-compile | 300 cap | 300 cap | — | 2.7 | hang |

Seven of the eleven rows exceed the 1.5x coupling bar; every CPython row
does, no Go row does.

**What the coupling is.** `target/conformance/eco-load/coupling.sh` runs a
row's exact ledger argv under `/usr/bin/time -l` in controlled conditions:
L0 idle; L1 three host `yes` hogs (pure CPU, no HVF, default QoS); L1B the
same hogs at background QoS; L1P six hogs; L2 three sibling carrick guests
running a fault+fork loop. Wall / (user+sys) CPU-seconds:

| row | L0 | L1 | L1B | L1P | L2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| itertools | 28.0 / 27.9 | 35.7 / 35.6 | 27.5 / 27.5 | 44.3 / 44.1 | 48.7 / 48.3 |
| multiprocessing_main_handling | 33.4 / 40.5 | 59.2 / 70.7 | | | 65.5 / 78.0 |
| importlib | 12.8 / 18.2 | 22.2 / 33.1 | | | 22.3 / 35.1 |

The carrier's own CPU-seconds inflate under pure-CPU host load with
`sys` flat, and background-QoS hogs cost nothing, so the coupling is host
scheduling of carrick's threads against equal-priority competitors, not
host-kernel serialization. Raising the executor threads to
`QOS_CLASS_USER_INITIATED` measured no gain (L1 34.5 s, L1P 55.2 s — worse)
and was discarded. The attached off-CPU capture on `importlib`
(`target/perf/ivcs/importlib-offcpu-attached.txt`, 8 s window, symbolized
by attaching to the live carrier) shows the mechanism candidates:
`run_executor_loop` ends EVERY executor boundary with an unconditional
`std::thread::yield_now()` (`executor.rs:4437`, from the persistent
executor landing) — 5.6 s of `swtch_pri` in the window — and the scheduler's
run-queue mutex is contended by all ten executors (`lock_slow` under
`GuestExecutorCensus::enter_inner`, `WakeAdmission::drop`,
`settle_blocked_continuation`) because every wake/park/release calls
`notify_all`. `importlib` shows ~44k involuntary context switches per
second idle. A no-yield experiment binary is being measured.

**Where the base ratios come from** (three read-only code maps this
session; every line verified at the cited spots): the first-touch fault
materializes ONE 4 KiB page per transaction and the pre-mapped frame pool
serves only 16 KiB-aligned pages (`can_pool` needs `physical_offset == 0`),
so three of four sequential first touches pay `mmap` + `hv_vm_map`; the
hole computation walks every alias of every process twice
(`alias_registry().lock().iter()`); `PtQuiesce`'s coordinator election is
carrier-global for every `mmap`/`munmap`/`mprotect`/`brk`; the topology
lock is one carrier mutex shared by fork, COW, alias map/unmap, retire and
exec; the continuation reactor rebuilds its whole `pollfd` vector per
cycle; exit takes the carrier inventory mutex once per extent. Seven
workers (`AGY_RUN_ID=perf2x-sep07`) hold the briefs: fault-window,
mm-scope, exit-scaling, reactor, pprof-vdso (SIGPROF never lands in the
vDSO), subprocess-fdleak, dentry-evict.

## 2026-09-07: three landings, one rejection, and two reds under load

Landed on main, each fast-forwarded from the worker branch, inventories
reconciled, `just lint-domains` and the signed build green, `ubuntu:24.04
/bin/true` and `python:3.12-slim print(1)` launch receipts:

- **subprocess-fdleak** (`dc23e0128`..`5967a7b71`): `/proc/<self-pid>/fd`
  resolves under HVPatch (the guest pid is not the carrier pid) and the
  `/proc/self/fd` listing is built from the live fd table on every
  `getdents64`. `cpython-subprocess` 297/297 on main (was 295/297).
  Probe `procselffdfail` awaits its Docker bless.
- **dentry-evict** (`cba377ccb`..`a4fe401e5`, hatch cleanup `1c8a320a4`):
  the 4096-directory bulk reset is replaced by memory-bounded per-entry
  eviction (32 MiB default, `CARRICK_DENTRY_CACHE_CAPACITY_BYTES`;
  `CARRICK_DENTRY_EVICT=0` hatch), directories pinned by an explicit pin
  count through the `RootFsVfs` mutators (a `strong_count` heuristic was
  rejected in review), lookups re-walk on a concurrent eviction. Quiet
  gate, both binaries: `openat03` DIFF → MATCH, `renameat202` REGRESSION
  → MATCH, the six create-heavy LTP rows and `cpython-pathlib`/`tempfile`
  unchanged to the millisecond.
- **fault-window** (`4daf4bb29`..`03908a220`): a single-page first touch
  materializes its whole 16 KiB compound (always the pooled, zero-syscall
  path), anonymous private windows widen to 64 KiB
  (`CARRICK_FAULT_WINDOW_BYTES`, `=4096` hatch) clamped to the pristine
  hole, VMA, next mapping/alias and 2 MiB boundary, with untouched pages
  left invalid and armed; every alias-registry walk on the path is a
  bounded `by_va_start` query; the task mapping vector is kept sorted for
  `partition_point`. 454 vmm-hvf tests serial. Quiet-gate numbers in the
  same window, branch vs main: `cpython-itertools` 3.6 s vs 48.0 s,
  `multiprocessing_main_handling` 13.8 vs 53.0 s, `importlib` 17.8 vs
  24.9 s, `cpython-compile` 62 s vs the 300 s cap; `perf_fork` p50 253 vs
  273 µs (unchanged). On the landed binary: `mincore01/02`,
  `madvise01/06`, `mmap18`, `mmap01`, `munmap01`, `brk01`, `cpython-mmap`
  all MATCH; `cpython-compile` MATCH 150/150 (first time).

**Rejected.** `sched-herd` (no boundary yield, exact wakes): under three
default-QoS hogs `cpython-importlib` wedged at
`test_multiprocessing_pool_circular_import` with every executor parked in
`RunQueue::take_row` — a lost wakeup (`target/perf/sched-herd-wedge/`).
Its idle number was good (importlib 11.6 vs 24.9 s, involuntary context
switches 325k vs 810k), so the worker is fixing the park/wake state
machine with a red-first interleaving test. `exit-scaling`: the `wait`
read-lock fast path drops ptrace tracee stops (4 kernel tests red on the
branch, green on main). `pprof-vdso`: `cpython-signal` crashed the
carrier and `TestCPUProfileMultithreadMagnitude` regressed on its own
receipts. `reactor`: `withdraw` rebinds the wrong token after
`swap_remove` (it reads the removed element, not the moved one).

**Two reds under load, attributed.** With four workers building (load
30), `go-go_types` aborts the carrier on EVERY binary including the
ledger's `a4c5c672` (`scheduler generation observer lost exact
transition … run queue publication authority does not match the
submitted generation`, then every executor `failed boundary audit before
ASID invalidation: host-signal-mask added=[1..31]`). This is the parked
exec-generation race; it is pre-existing, load-coupled, and now
reproduces 4 of 6 runs — the goal's "under the harness's own
concurrency" clause cannot be met until it is fixed. Separately, two of
three `go_types` runs on the landed binary ended in a Go runtime
`fatal error: s.allocCount != s.nelems` inside a compile child (heap
corruption), seen on neither the 4 KiB-window hatch nor the ledger
binary in the same window; a larger sample is running before the window
default is decided.

## 2026-09-07: the exec-generation abort, captured

With the observer's failure sources named (`e0899dde9`) and the registry's
view logged at the abort (`19235a09a`), `go-go_types` under eight
default-QoS CPU hogs reproduced it on the first run:

    scheduler generation observer lost exact transition
      thread=ThreadKey { tid: LinuxTid(1864), serial: ThreadSerial(225511) }
      predecessor=ExecutionGeneration(84) successor=ExecutionGeneration(85)
      kind=Runnable
      error=run queue publication authority does not match the submitted generation
      kernel_view=thread absent from registry; same-tid threads=[]

The transition is a WAKE (`Runnable`, 84 → 85) for a thread the Kernel
registry no longer holds: the wake was published after the thread's
terminal transition and its registry record had been reaped, while a
`Thread` handle still drove the transition. `rollover_exact` then fails
its liveness check (`with_live_active_scheduler_thread` finds no thread)
and the carrier aborts. Linux semantics: waking an already-exited task is
a no-op; carrick must either make the terminal transition revoke every
pending wake for that generation, or make a wake for a thread whose
registry record is gone a rejected, non-fatal publication. The load
coupling is only the window: a preempted executor between "thread exits
and is reaped" and "its last wake is published". Reproducer options, in
order of exactness: the adversarial scheduling policy (design phase 2,
in flight), then `SyscallJitter` (`crates/carrick-embed/tests/scheduler_race.rs`),
then `target/conformance/eco-load/gotypes-capture3.sh` (eight hogs).
Three sibling fault+fork guests did NOT reproduce it (6 of 6 pass), so
the coupling is host CPU starvation, not guest traffic. Note also that
`with_live_active_scheduler_thread` scans every task in the carrier on
every generation transition — an O(live tasks) cost on the wake/park
path that the per-CPU scheduler must not inherit.

## 2026-09-07: the fault-window corruption — a binary search on an unsorted vector

The wide-window Go heap fatal (`allocCount != nelems`, 5 of 6 runs at
64 KiB, 2 of 3 at 16 KiB, 0 of 4 at 4 KiB) and the rarer
`memmove`/`stkbucket` SIGSEGV share one cause. The fault-window landing
(`d8f8df493`) made the window arm's "next local mapping" and "mapping
below the compound" questions and the materializer's next-mapping bound
`partition_point` searches over `HvfTaskState.mappings`, assuming the
vector is sorted by start — but five publication paths `push` and one
`extend`s out of order. A binary search over an unsorted vector misses
live mappings, so a sparse extent could be materialized on top of a
mapping the guest had already written; wider windows simply asked the
broken question more often. `a1fd9ad94` restores full scans for the
three questions (the two sorted inserts stay, harmless). The perf that
landed came from the compound-aligned pooled first touch and the bounded
alias-registry queries, not from those searches. Validation on the fixed
binary with `CARRICK_FAULT_WINDOW_BYTES=65536` forced is
`target/conformance/eco-load/unsorted-fix-validate.log`; if it is clean
the 64 KiB default returns. Lesson for the inventories: a `Vec` that one
site binary-searches needs a single sorted-insert path and a debug
assertion, or the search is a bug waiting for the next `push`.

## 2026-09-07 evening: where the perf lives, and who holds what

On the fixed binary (`a1fd9ad94`, load 12–17), `cpython-itertools` runs in
**6.3 s** with `CARRICK_FAULT_WINDOW_BYTES=65536` and **47.8 s** with the
4 KiB default — the compound-aligned pooled first touch alone buys
nothing measurable on this row; the whole win is the wide window, which
still corrupts guest memory (Go `allocCount != nelems`, 2 of 3 runs at
64 KiB on the fixed binary, 0 of 6 at 4 KiB). The `partition_point`
searches on the unsorted mapping vector (`a1fd9ad94`) were a real latent
bug but not this one; the per-chunk receipt clamping was verified
correct. A one-minute reducer exists:
`target/conformance/eco-load/gobuild-loop.sh <label> <window> [iters] [bin]`
(a `go build fmt net/http` loop in the Go image; the fatal appears in the
first builds at 64 KiB).

Owner directions during the day: the scheduler (design phase 2, with the
embed-pluggable policy whose first consumer is an adversarial race
reproducer) is the top priority and is finished by an Opus subagent in
`.worktrees/agy-guest-cpu-sep07` (the Antigravity worker's policy types
and draft run queue are its base); the window corruption is hunted by a
Fable subagent in `.worktrees/agy-window-corruption-sep07` (brief in the
session scratchpad, `fable-window.md`). The captured reaped-thread wake
abort (previous section) is part of the scheduler work. Remaining
Antigravity workers: reactor (poll deadline regression); sched-herd is
prior art only.

**Reactor branch parked** (`agy/reactor-sep07`, six turns). The
incremental interest set, the exact-token wakes and the `swap_remove`
rebinding fix are sound, but its deadline handling never matched Linux:
first `poll() slept for too long` (5/7 on `ltp-poll02`), then, after the
worker's re-arm fix, `poll() woken up early` (1/7 to 2/7) because it
published deadlines due "within 1 ms". Main's reactor stays. The GuestCpu
scheduler's phase 3 (blocking as a scheduler operation) is where the
reactor's O(live blocked tasks) cost gets designed out, so the branch is
kept as prior art rather than iterated further.

**mm-scope landed** (`f0e783943`..`60af77a56`, repair `691ef3fd7`, main
binary `20b7aebd…`): the stage-1 pause's coordinator election is per mm
(`PtQuiesce` owned by the `Mm`, bound thread-locally while a vCPU
executes for it) instead of one carrier-wide static, and the
`tlbibroadcast` probe (awaiting its Docker bless) records that a guest
`tlbi vmalle1is` on one vCPU is observed by a sibling vCPU without a
stop-the-world pause on Hypervisor.framework — the fact phase 4 of the
scheduler design needs. Quiet-host gate on both binaries: all nine rows
MATCH with identical times (`go_types` 571/571, `net_http` 1316/1316,
`threading`, `multiprocessing_main_handling`, `mprotect01/04`,
`munmap01`, `brk01`, `mmap01`); post-landing smoke and rows green. The
worker's own receipts had used `--flake-retries`, so the landing gate
re-ran them without retries. Two inventory JSONs reached main with
conflict markers through the rebase and were repaired in `691ef3fd7`.

## 2026-09-07: the wide-window corruption, found — a stale row trusted by frame liveness

A Fable subagent proved the mechanism (branch `agy/window-corruption-sep07`,
landed as `e22aca098`..`5094077b8` plus registration). A task's
`HvfMappedRegion` rows are per-task caches of the process-wide alias
registry. A sibling thread's partial `munmap` (or `MAP_FIXED` over a
sub-range) splits the registry entry and mirrors the split only onto the
unmapping task's own rows; every other task keeps a row still spanning
the retired page. `mapping_for_range_in` authenticated such rows by FRAME
liveness, which cannot see a page-level retirement while the compound is
still owned by a neighbouring page, so on the page's next incarnation
the "already backed" fast path of `ensure_sparse_mmap_backing` skipped
materialization and revalidated the retired leaf: the page's previous
bytes (Go's `s.allocCount != s.nelems`), a frame recycled to another
mapping (silent aliasing), or a stage-2-unmapped frame that
`resolve_stale_stage1_fault` retried forever (a 100% CPU livelock). The
4 KiB arm was clean only because a one-page row cannot be partially
unmapped. The fix authenticates a dynamic row against the registry at the
page (same physical incarnation and owner generation), gated to the
persistent lifecycle; the stale-fault retry is now bounded and named.
Evidence: `windowcoherence` `fragment_stress` livelocks deterministically
at op 663 at 64 KiB on the unfixed binary and is 20/20 green fixed; the
go-build reducer went from 6 of 8 bitmap fatals to 0 in 13 wide-window
runs; go_types 150/150 twice. Still open and window-independent: a Go
startup `SIGSEGV` in `persistentalloc` (~1 in 8 compiles, both windows),
exit wedges with every executor idle (the wake-vs-reap family), and the
observer abort. The 64 KiB default returns with this landing; the
receipts are in `target/conformance/eco-load/land-window.log`.

**Landed with the 64 KiB default** (`9ac383a69`, main binary `1536e789…`,
load ~5): `cpython-itertools` 3.6 s (3.5x; was 20–28 s), `importlib`
7.1 s (2.6x; was 10.9), `multiprocessing_main_handling` 14.8 s (5.1x; was
33), `cpython-compile` MATCH 150/150 in 62 s (was the 300 s cap),
`go-go_types` 18.3 s (3.0x; was 22.6) but 569/571, the mm rows MATCH, the
go-build reducer 16 builds with zero bitmap fatals and one `SIGSEGV`.
That `SIGSEGV` (SEGV_MAPERR in `runtime.persistentalloc1`, first touch of
a chunk Go just `mmap`ed on another M) is the one remaining
memory-integrity class: window-independent, load-coupled, ~1 in 8
compiles. A Fable subagent is on it (brief `fable-segv.md`).

## 2026-09-07: the GuestCpu scheduler, round 1 (not landed)

An Opus subagent implemented design phase 2 on `agy/guest-cpu-sep07`
(HEAD `85a0bbcfc`): one `GuestCpu` per exposed CPU with its own run
queue, the carrier mutex off the enqueue/claim path, a `findrunnable`
steal, Go's `wakep` idle flag with a wake-ticket pre-park re-check, a
`GuestCpuPolicy` placement hook, executors bound to CPUs, guest-visible
CPU truth (`sched_getcpu`, `/proc/<pid>/stat` field 39 — which had been
the constant 17), a conditional boundary yield, and the captured abort
closed: a wake whose target was reaped is rejected, never fatal
(red-first: removing the liveness branch reproduces the SIGABRT). Every
unit gate is green (2,517 runtime tests, clippy, fmt, lint, signed
build). Two findings keep it off main: a guest `SIGSEGV` in a forked
`go build` (`mcentral.uncacheSpan` → `spanSet.push`, 3 of 7 runs vs 0 of
5 on main in the same session) — the same first-touch class the SEGV
worker is hunting, presumably made more frequent by `last_cpu`
stickiness; and `cpython-importlib` at 13.7 s vs 6.8 s on main
(load ~10), with involuntary context switches down only 28%. It also
found that sizing one executor per guest CPU wedges teardown with every
queue provably empty: the exiting process's job result is never
published from terminal settlement (the same unpublished-result wedge
the director captured on main), so the executor count stays decoupled
from the CPU count until phase 3 closes that. Steps 5 and 6 (the
embed-pluggable policy and the adversarial reproducer) are not done.
Next round after the SEGV fix lands: rebase, re-run the go rows, ablate
`sticky_depth` and idle-CPU wake against importlib, then the policy hook.

### 2026-09-07 evening — exit-wedge mechanism, owner ruling on the runner, scheduler round 1 report

**Exit wedge, decisive snapshot.** Run `gbl-fixsegv2-141` (main-derived binary,
workload finished `BUILDS=8 FAILS=0`) wedged after its last line. `carrick debug
hvpatch-kernel` returned `tasks: []`, `threads: []` and ONE zombie:
`{ id: 1, serial: 6, parent: null, process_group: 1, session: 1 }` — the
container's init exited and became a zombie nobody can reap; all ten executors
in `RunQueue::take_row`, main in `HvpatchLoopResult::wait`. Evidence under
`target/perf/wedges/gbl-fixsegv2-141/`. The Opus exit-wedge branch
(`opus/exitwedge-sep07`, 1616728e6) fixes a lost-exit-claim publish path
(`DeferredToProcessOwner` → `AlreadyPublished`, lost claim publishes its own
member outcome); whether the pid-1 zombie is that path or a second one is
open.

**Owner ruling.** "Shouldn't our embed runner be able to handle this and abort
in this scenario?" — yes, and it is now a requirement, not an option: the
runner checks a liveness invariant when the process graph goes empty (event
driven, never a timer): zero live tasks, no pending reactor work, and an
unpublished process job ⇒ abort with a named error returned from
`ContainerJobGroup::join`. Parking is unrepresentable. Brief:
scratchpad `brief-runner-liveness.md` (dispatched after the exit-wedge branch
reports, same files).

**Host-wide carrier watchdog** (`target/conformance/eco-load/carrier-watchdog.sh`,
log `target/perf/wedges/watchdog.log`): any guest alive > 5 min whose CPU time
is frozen 3 min gets its kernel snapshot + `bt all` saved and is reaped by run
id, whichever agent started it. Agents kept missing their own wedges.

**Scheduler round 1 report (Opus, branch `agy/guest-cpu-sep07`).** Steps 1–4
and 7 built and unit-tested (per-CPU queues, `last_cpu` affinity, own-CPU
before steal, pinned rows unstealable, spares park); step 2 shipped with M =
host parallelism (M = P wedged in teardown — the unpublished-result defect
above, bisected to d1cae10e3); steps 5/6 (embed policy hook, adversarial
policy) not done. Blockers: guest SIGSEGV in a forked `go build`
(`mcentral.uncacheSpan → spanSet.push`) 3/7 vs main 0/5, not removed by
restoring the boundary yield; importlib L0 2x slower than main (13.65 s vs
6.79 s) while its load-coupling ratio improved (1.66 → 1.31) and IVCs fell
28 % (not the tenth the design predicted). Round 2 brief: ablate
`sticky_depth`/`wake_idle_cpu` on importlib first; bisect the placement policy
(round-robin, no stealing) before touching memory code; then the policy hook
with `cpu_count()` as the single `nproc` authority.
## 2026-09-07: the Go startup SEGV_MAPERR, found — a per-task authority pointer trusted across a quiesce

A Fable subagent proved the mechanism (branch `fable/segv-sep07`, brief
`fable-segv.md`). The remaining window-independent, load-coupled Go
startup `SIGSEGV` (SEGV_MAPERR in `runtime.persistentalloc1`, ~1 in 8
`go build`) was the first touch of a chunk Go had just `mmap`ed. The
runtime's sparse first-touch publication (`PublicationContext::for_local`
in `crates/carrick-vmm-hvf/src/trap/sparse_materialization.rs`) reads the
MM-scoped frame-COW runtime binding, quiesces the mm through it, then
re-reads the binding and refused the publication unless the authority
`Arc` was **pointer-identical** across the quiesce ("sparse publication
MM changed during quiesce"). But that binding carries a **per-task**
authority — its `linux_tid`/`tid` name the task that last ran — so every
sibling thread's first run and every exec legitimately rebinds it with a
fresh, equivalent authority object. A sibling being created while another
task sat in its first-touch quiesce replaced the pointer, the `ptr_eq`
read "the MM changed", and the refusal was lowered to SEGV_MAPERR. The
"correct with one process, wrong the instant a second appears" class; the
foreign-mm path (`for_foreign`) already authenticated by semantic fields
and no pointer. The fix authenticates the semantic MM identity across the
quiesce (mm, asid, stage-1 root slot, container, persistent lifecycle),
not the authority pointer; the quiesce is valid regardless of which
equivalent authority minted it, because `KernelFrameCowAuthority::quiesce`
routes through the `PtQuiesce` barrier and executor census owned by the
shared `DispatchMmAuthority` for the mm.

Instruments added (`diagnostics(runtime)`): `hvpatch-first-touch-deliver`
(FAR, reason ordinal, TID — names WHICH of the five arms of
`resolve_mutating_fault` gave up), `hvpatch-cow-runtime-bind` (authority
pointer lineage per task), and `scripts/dtrace/hvpatch-first-touch-segv.d`
which joins the fault, the deliver reason, the last process-wide `munmap`,
and the bind lineage into one line per delivered SIGSEGV. On main's binary
(`1536e789…`) it attributed every SIGSEGV to a `BackendRefused` reading
"sparse publication MM changed during quiesce", FAR in Go's arena,
`esr=92000047` (write translation fault).

Evidence (fix binary `6bdfe4b1…`, load 5–15): new unit
`local_publication_tolerates_equivalent_rebind_during_quiesce` injects the
sibling rebind inside the quiesce window — RED with the `ptr_eq` clause
restored, GREEN with the fix, control (rebind to a different mm) still
rejected. New `windowcoherence` scenario `sibling_handoff_first_touch`:
9/12 SEGV on main's binary under load, 20/20 green on the fixed binary.
go-build reducer at 64 KiB: three 8-build sets with zero SIGSEGV and zero
fatal lines (one run excluded for the known `scheduler generation observer
lost exact transition` race, reran clean). Suite gate ×2 on the fixed
binary via the harness (`--require-cached-oracle`): `go-go_types` 571/571,
`go-net_http` 1316/1316, `cpython-multiprocessing_main_handling` 39/39,
`ltp-mmap01` 1/1, `ltp-mmap18` 4/4 — all MATCH, no regressions.

### 2026-09-07 20:54 — post-SEGV-landing receipt on main 0529523ac (binary 5f3ed049…)

`--workers 1`, `--require-cached-oracle`, host load 5.3 → 1.9 over the run,
no other guests. go-build reducer 8/8, zero fatal lines. All eleven goal
rows MATCH; `go-go_types` 571/571 and `go-runtime_pprof` 93/93 are whole
for the first time (the SEGV class took `TestMapping`/`tracebackGoOnly`).

| row | carrick ms | oracle ms | ratio |
|---|---|---|---|
| cpython-asyncio | 76882 | 72130 | 1.07 |
| cpython-threading | 16889 | 13816 | 1.22 |
| go-runtime_pprof | 23034 | 17180 | 1.34 |
| cpython-importlib | 7293 | 2685 | 2.72 |
| go-go_types | 19135 | 6182 | 3.10 |
| cpython-subprocess | 64479 | 20698 | 3.12 |
| cpython-itertools | 3838 | 1032 | 3.72 |
| go-net_http | 15967 | 4098 | 3.90 |
| cpython-multiprocessing_main_handling | 14808 | 2892 | 5.12 |
| cpython-tarfile | 75581 | 4765 | 15.86 |
| cpython-compile | 62282 | 2677 | 23.27 |

Three of eleven at ≤2x. `compile` and `tarfile` are the two order-of-
magnitude rows and are unattributed; attribution workers dispatched
(briefs `brief-attr-compile.md`, `brief-attr-tarfile.md`).

### 2026-09-07 22:25 — exit wedge confirmed end-to-end by the watchdog; fix gated

The host-wide carrier watchdog reaped four wedges in 17 minutes, all with
the same shape (ten executors in `take_row`, main in
`HvpatchLoopResult::wait`). Two were the exit-wedge agent's own A/B **base**
binary runs (`gbl-ABbase1`, `gbl-ABbase3`): kernel graph `tasks: []`,
`threads: []`, one zombie pid 1 with no parent. The agent had recorded them
as unexplained `rc=137` after `BUILDS=8`; that was the watchdog. So the
pre-fix binary wedges 2/5 and the fix binary 0/5 on the same reducer under
the same load. Two more were conformance rows on a main-class binary
(`conf-36312-c00`, `conf-41112-c00`) whose kernel snapshot **refused itself**
("mapping MappingId(22) names mm MmId(1), which is not in the snapshot") —
a leaked alias-registry row is part of the wedge signature and the
post-mortem capture must record it rather than refuse (lane B).

Fix under gate: `opus/exitwedge-sep07` rebased (df0a28a4d publish-on-lost-
claim, e42253f68 bounded signed exec/exit-storm test); unit reproducer 20/20
red → green; signed embed test running before the fast-forward.

**Landed 2026-09-07 22:35:** exit-wedge publish fix on main (f8487d23b,
8a27b53f1, reconcile 1152ced70; signed binary 93632a2e…). Gates run by the
director: unit reproducer green, `just lint-domains` 0, probe shards 3/3,
signed build 0. The signed embed test `go_types_exit_publishes_every_process_job`
compiles but did **not** execute: `just test-embed` shells out to Docker on
the image path although the go image is in the local store and both local
registries were down; fixing that lane is part of lane B. Post-landing rows
in `post-exitwedge.log`. Lane B (KernelAbort sink, post-mortem, debug abort,
deadline, exit budgets) dispatched on the same worktree.

**Post-exit-wedge receipt (main 1152ced70, binary 93632a2e…, `--workers 1`,
load 4.6 → 2.9, other agents' guests intermittently alive):** smoke ok,
go-build reducer 8/8 clean, all eleven rows MATCH, no regression. Ratios:
asyncio 1.07, threading 1.22, pprof 1.47, importlib 2.71, subprocess 3.09,
itertools 3.69, go_types 3.92, net_http 5.3, mp_main 5.1, tarfile 16.26,
compile 23.49. The two Go rows moved up from the previous receipt (3.10 →
3.92, 3.90 → 5.3) under a higher starting load; treated as noise until a
quiet-host pair says otherwise.

**Worker fleet note:** all three antigravity workers dispatched this evening
(attr-compile, attr-tarfile, kernel-auditor) died on an agy model-response
transport timeout at 44–61 min with their work uncommitted. Parked as WIP
commits (a0f0323f4, b4a8fa2e1, aa3913412 — the auditor WIP compiles with
tests) and re-dispatched as short-turn workers (kernel-auditor2, attr-tarfile2
continuing; attr-compile2 fresh from main, attribution-first, because the
first turn scattered unverified edits across three subsystems).

### 2026-09-08 00:30 — a fifth wedge class: orphaned pool workers parked in HostWait (main)

Two watchdog reaps of `cpython-importlib` coupling runs on main's binary
(`cpl-cpython-importlib-L0-5062`, `-L1-8919`; the 326 s and 311 s "wedge"
rows in the scheduler round-2 table) are not the exit wedge: the kernel
graph has pid 1 plus 18 (resp. 11) `hvpatch-child-of-1592` tasks reparented
to pid 1 after 1592 became a zombie, and **every** thread is
`Blocked { reason: HostWait, continuation: Some(..) }` with the run queue
empty and the reactor idle. This is `test_multiprocessing_pool_circular_import`:
on Linux the pool parent's exit SIGTERMs its workers and the script's
stdout pipe reaches EOF; here the orphans never leave their host wait and
pid 1 waits on a pipe they still hold. Hypotheses (signal into HostWait not
cancelling the continuation; exit-path signal send lost; EOF not propagated
when the last in-zone writer exits) are in `brief-hostwait-orphans.md`;
dispatched to a dedicated agent with both snapshots.

### 2026-09-08 01:30 — scheduler round 2 gated (not landable), two attributions landed on branches, round 3 dispatched

**Scheduler round 2** (branch `agy/guest-cpu-sep07`, rebased onto main by the
director as 24dd04d76, binary 2d2487fc…) delivered placement by executor
availability (`CpuLoad{queued, idle, bound}`, counted idle announcements),
the Go-style wake chain (`propagate_wake`), the embed policy hook
(`ContainerBuilder::scheduler`, `cpu_count()` as the one nproc source) and a
no-op reaped wake. Director's interleaved go_types gate under load 5→30:
**branch 3/5 MATCH + 2/5 CARRICK_CRASH; main 5/5**. Both crashes: `executor
worker died … exact thread generation is not live` → ASID retirement fails →
`FATAL: drop HVPatch MM authority`. A queued row goes stale between enqueue
and claim on the per-CPU/steal path and reaches `backend.load`. Round 3
brief: authenticate the generation at claim (stale row discarded through
lane A's `wake_rejected`), narrow the observer-error swallow, then M = P
(unblocked by the exit-wedge landing), ablation, adversarial/record-replay
policies.

**cpython-compile attribution** (`docs/perf-results/2026-09-07-cpython-compile-attribution.md`
on `agy/attr-compile2-sep07`, 78155cb5e): `test_compiler_recursion_limit`
is 95 % of the row; reducer `compile('a' + '()' * 1_000_000)` is 36–55x
and quadratic in depth because every first-touch fault runs eight linear
scans over `HvfTaskState.mappings`, which grows one row per materialized
extent to ~100k rows. Director decision: replace the vector with a
sorted-by-construction, coalescing map keyed by `GuestVa` (row count stays
O(#VMAs), lookups O(log N)); the page-level registry authentication stays.
Round 3 worker dispatched.

**cpython-tarfile attribution** (`docs/perf-results/2026-09-07-cpython-tarfile-attribution.md`
on `agy/attr-tarfile-sep07`, cb916f5d1): 28 `NoneInfoExtractTests_*` are
82 % of the row; per guest `unlinkat` ~211 host `openat` + ~160 `fstatat`,
per `mkdirat` ~125 + ~125 — `dir_fd_for(full_path)` re-walks from the
deepest cached ancestor, lower-layer lookups probe the upper backend per
component, pure-upper dirs re-probe the lower `/tmp` fd. Owner ruling
applies (carrick namei is the resolver): the dentry owns the parent fd, one
host call per operation relative to it, negative lower dentries, per-entry
invalidation. Round 3 worker dispatched with a "≤2 host opens per warm
operation" invariant.

**Lane A (`KernelAuditor`)** reported done by its worker; director gate:
emit sites outside registry locks, 42 runtime + 69 embed unit tests green,
rebased onto main (e08784dbb), lint 0, workspace check 0; `just test`
running before the fast-forward. The signed embed test could not run: the
`just test-embed` lane still needs Docker (lane B).

**Landed 2026-09-08 01:50: lane A `KernelAuditor`** (agy/kernel-auditor-sep07 →
main, last d462d6809; signed binary e1a87448…). Gates by the director:
42 runtime + 69 embed unit tests, `just test` 0, `just lint-domains` 0,
probe shards 3/3, signed build 0; smoke and the eleven rows running
(`post-lanea.log`). Until lane B lands, an `Abort` verdict surfaces as
`EmbedError::CarrierFailed` when the run ends, and the per-executor
`GuestCpuId` is a placeholder until the scheduler branch lands (it carries
the real `carrick-hal::scheduler::GuestCpuId`; expect a small merge there).

**Scheduler gate, main side (suggests, not confirmed):** under host load
18–28 main's go_types row took 80–174 s (13–28x the oracle) against ~19 s
at idle — the load-coupling the goal names, measured on main itself. The
scheduler binary's one loaded MATCH at load 23 was 64 s (10.4x). Pairs only;
a quiet-vs-4-worker measurement on one binary is still owed.

**Post-lane-A rows (binary e1a87448…, host load 26–33 from six live agents):**
9/11 MATCH, two `CARRICK_CRASH`, both pre-existing load-exposed classes, not
the auditor: `go-go_types` (`conf-36877-c00`) died on `scheduler generation
observer lost exact transition` (exec-generation abort; the scheduler
branch's rejection-instead-of-abort turned out to kill the waking executor,
so it lands with round 3, not alone); `cpython-asyncio` (`conf-36877-c03`,
inside `test_subprocess…test_kill_issue43884`) died on `HVPatch terminal
owner publishes failure error=configuration refused: vfork parent resume`
→ `FATAL: drop HVPatch MM authority (holder=registration-cleanup)`. That
vfork-parent-resume refusal is a new named signature; filed here for the
next process-lifecycle round. Every ratio in that run is inflated by the
load and is not cited. Rule for the rest of the campaign: no ecosystem
ratio is measured while the host load exceeds ~5; gates under load count
only crashes and wedges.

### 2026-09-08 02:40 — scheduler round 3: the crash is fixed at its real site

Round 2's crash was NOT a stale row reaching `backend.load` (the queue
already discards those). `observe_generation_transition`'s reaped-target
rejection propagated with `?` out of every settlement arm before
`executors.unbind()` / `running.finish_claim()`, so a reap mid-settlement
abandoned the transaction with the lease taken: worker death → ASID
retirement failure → `FATAL: published HVPatch inventory dropped before
exact retirement`. Fix 5d7efe418: the observer returns
`GenerationTransitionOutcome::{Recorded, TargetReaped}`; settlements always
complete and only the successor publication is withheld; the fatal meaning
is unrepresentable to callers. Red-first unit tests, `kernel::scheduler`
45/45, go_types **5/5 interleaved vs main 5/5** under load 12–27 with
0-byte `.err` files, means 58.4 s vs 58.2 s. Also landed on the branch:
adversarial + record/replay embed policies (e123f2a34), the M=P ablation
hatch `CARRICK_BOUND_EXECUTORS` (0aca74c42). M=4 no longer wedges (the
round-2 wedge was the exit-wedge class), but the timing ablation was
order-confounded and is redone in round 4. Round 4 (dispatched): rebase over
lane A, close the reaped-path `SubmissionAuthority` leak, signed adversarial
receipt, probe shards, un-confounded M=P.

### 2026-09-08 03:30 — the importlib live-task hang was carrick killing the pool parent (fixed on branch)

Not a lost signal into `HostWait`: the pool parent (pid 1592) is a zombie
with `wait_status 127<<8`, carrick's own `PersistentTerminal::Error`. Under
load a real producer woke a just-forked task before its dormant submission
was activated; the exact `(thread, generation)` row was already queued and
`SubmissionPublication::publish_unique` rejected ITS OWN row, which callers
lowered to a fatal `TrapError` → exit 127 for the whole Linux process, so
`Pool._terminate_pool` never ran and the orphans held the pipe writers pid 1
was reading. `SubmissionRejected` had also been carrying seven unrelated
conditions under one "closing" message. Fix (`opus/hostwait-sep08`
79ce8103a): publication is idempotent — coalescing onto the exact queued row
is success, `AlreadyQueued` deleted; bd1563e78 names the rejections. Red-
first unit test; interleaved 16-pair A/B on the importlib argv, load 3–11:
pre-fix 15/16 + 1 hang (stderr `the exact runnable generation is already
queued`), fixed 16/16; rows importlib and mp_main MATCH; gates 0. Open, the
other half of the same window: a wake-queued row claimed before `activate`
→ `SnapshotRestoreFailed` → carrier abort (seen once, rc=134); brief
`brief-activation-window.md`, dispatched after this lands.

**Landed 2026-09-08 ~02:40 (two landings, one binary):**
- **Lane B** (`opus/exitwedge-sep07` → main through 0268b74d2): `KernelAbort`
  sink with in-process `PostMortem` (kernel graph, executors, event ring,
  findings incl. dangling mappings), `EmbedError::KernelAborted` from
  `join`/`execute`, `ContainerBuilder::post_mortem_dir` + `CARRICK_POSTMORTEM_DIR`
  + CLI flag, `carrick debug abort --run-id` (verified live), every job wait
  supervised, `TestContainer::deadline`, the embed interceptor probe rebuilt
  as a cross-compiled Rust crate so `just test-embed` no longer touches
  Docker, and a lock-order fix (result→registry inversion). Director gates
  on the rebase over lane A (one additive conflict in the embed test
  container): workspace check 0, lint 0, `just test` 0 (38 suites), signed
  `a_container_that_will_not_finish_aborts_with_a_post_mortem` green in
  90 s with the negative control. Follow-ups filed: `ExitBudget` wiring onto
  lane A's events; the liveness judgement is poll-backed rather than driven
  by `process_graph_empty`; the abort request and post-mortem dir are
  process-global statics; `std::process::abort()` sites are outside the
  sink; carrier teardown after an abort prints a lost-lease error.
- **Activation-publish fix** (`opus/hostwait-sep08` → main through
  c6f2eeb70): idempotent `SubmissionPublication::publish` and named run-queue
  rejections. Director gates: the three unit tests green on the rebased tree,
  lint 0 after the host-authority rows were rebound. Binary of main
  c6f2eeb70: 32f5… (see build log). Smoke + reducer + rows in `post-laneb.log`
  (host loaded; crashes/wedges are the verdict).

### 2026-09-08 03:05 — a silent carrier abort in the mmap alias-install path (main, under load)

The post-landing go-build reducer on c6f2eeb70 (binary 79e957f1…) died
rc=134 with empty stdout/stderr at host load 49. The crash report names
the site: `carrick-executor-8`, `std::process::abort` inside
`redispatch_threaded_syscall_for_executor`'s mmap alias-install arm, where
four aborts (`take_alias_inventory` None, `apply_alias_frame_inventory`
error, `len` conversion, PROT_NONE `protect_range` error) have no log line
at all. Filed with tonight's two other load-exposed MM-authority FATALs
(`vfork parent resume` refused; duplicate exec MM authority key) as one
family; Fable agent dispatched (`brief-mmap-abort.md`): name the sites
through the lane B sink, reproduce under hogs with a post-mortem, fix the
root cause. Five `carrick_runtime` test-binary crash reports at 02:48 abort
in `dispatch::sysv::shmdt` — an agent's unit-test run; noted, unowned.

**Post-landing rows on c6f2eeb70 (binary 79e957f1…, load 49 → 3 over the
run):** 11/11 MATCH, no crash in the row run (the one silent abort was the
go-build reducer before it, filed above). Ratios not cited (load). A quiet
window opened at the end (load 3.2): `quiet-short.sh` is taking the
fork-to-wait measurement and the short rows on this binary.

**Quiet-window points on c6f2eeb70 (binary 79e957f1…, `--workers 1`, load
2.8–3.3, the only three rows that finished before the fleet resumed):**
itertools 3.67 (3787 ms), importlib 3.10 (8328 ms), threading 2.22
(30738 ms). Unchanged from the pre-fleet receipt within noise, as expected:
tonight's landings are correctness (wedges, crashes, hangs); the ratio
levers are still on branches (scheduler placement/M=P for importlib,
itertools and multiprocessing; the mapping index for compile; the dentry
resolution for tarfile). The quiet fork-to-wait driver refused its
preflight (two sibling guests alive); the goal's fork measurement is the
four-sibling ledger condition and runs with the final ledger.

### 2026-09-08 03:45 — tarfile dirfd-invalidation fix landed (main 7d4a5d222)

The parked WIP self-deadlocked (a `Weak<DentryCache>` bridge re-entered a
`parking_lot::RwLock` held across the root fill) and was removed. The real
mechanism was narrower than the attribution's shape: `remove_entry_checked`
answered every directory removal with `bump_dir_generation()` +
`drop_dir_cache()`, and both `DirCacheEntry` and `StatCacheEntry` carry
that one stamp, so **one `rmdir` invalidated every cached dirfd and leaf
stat in every process, including the remover's own re-walk**; `rmtree`
re-walked from the sandbox root on nearly every operation. Fix
(3da0053c6): the removal evicts exactly its subtree and re-stamps
survivors with the generation it just established, keeping the
cross-process invalidation contract. Receipt (same reducer, both binaries,
identical guest call counts): host `openat`/`fstatat` per guest `unlinkat`
212.8/162.6 → 6.41/6.89, per `mkdirat` 123.5/124.4 → 7.91/7.71; total host
syscalls 3,190,240 → 503,294 (6.34x). 19/19 rows MATCH (tarfile,
subprocess, unlink/mkdir/rmdir/rename ltp cases); gates 0; director re-ran
the 97 dentry/backend unit tests, lint and workspace check on the rebase.
Not met: ≤2 opens per warm op (6–8 remain, unattributed, outside the path
walk; `getdents64` at 3.3 opens/call is the largest remaining multiplier);
the ratio is not citable (load 13–24). Next design item, from the worker:
a per-path dirfd epoch instead of one global generation word, which also
makes the cross-process re-stamp argument a type instead of a comment.

**Post-tarfile gates (main 7d4a5d222, binary from build-7d4a5d222.log):**
lint 0, probe shards 3/3, smoke incl. an `rmtree` sequence ok. The go-build
reducer aborted once at load 32 on `scheduler generation observer lost
exact transition` (crash report `carrick-2026-09-08-034418.ips`,
`observe_generation_transition ← settle_blocked_continuation`), the
exec-generation class whose fix (5d7efe418, settlement outcome instead of
`?`) is on the scheduler branch and lands with round 4 — second instance
on a main reducer tonight, both at load ≥ 30. Rows in `post-tarfile.log`.

### 2026-09-08 04:30 — compile mapping index landed (main)

`HvfTaskState.mappings` is now `TaskMappingIndex` (agy/attr-compile2-sep07,
9576bb27f…06d1bf317): a `BTreeMap<GuestVa, HvfMappedRegion>` of live rows
that coalesces contiguous same-owner rows, keeps displaced rows reachable
until their handles drop, plus an **IPA-ordered view** with a span
multiset that bounds the raw-IPA walk. The worker measured its own
regression first — ordered VA lookups alone were **1.39x slower** because
`mapping_for_ipa_range` (every fault, via `diagnostic_fault_page_tables →
host_ptr`) still walked the whole table and a reverse `BTreeMap` walk costs
several times the vector — then the IPA view flipped it: reducer at 400k
depth 3.98 s → 1.37 s (2.39x), at 1M 45.8 s → 7.76 s (5.91x);
`cpython-compile` 62.3 s / 23.3x → **26.8 s / 10.0x** (load 8–14), `cpython-mmap`,
`ltp-mmap18`, `ltp-munmap01`, `go-go_types` MATCH; go-build reducer zero
SIGSEGV / zero fatal lines across 7 runs (the window-corruption criterion).
Director gates on the rebase: 463 hvf lib tests serially, lint 0, workspace
check 0. Not proven / follow-on: scaling is flatter but still super-linear
(8x depth costs 23x, was 161x); coalescing cannot fire on this workload
because each sparse extent has its own global-frame owner generation (the
representation cost is now the per-extent owner, not the lookup); the
per-fault row count is uninstrumented (probe requested — granted, lane:
carrick-observability); `shadowed` rows are retained until handles drop
and their growth under repeated MAP_FIXED is unbounded (review note);
`carrick-vmm-hvf` tests are flaky in parallel at base (shared statics).
The `lost exact transition` abort the worker hit under load ≥19 on both
binaries is the scheduler lane's (round 4).

**Post-mapping-index gates (main f84bfe3e7):** lint 0, probe shards 3/3,
smoke ok, rows 6/6 MATCH (`cpython-compile` 150/150 at 48.1 s under load
24–35 — the pre-fix binary took 62 s at load 5; not a citable ratio, but
the direction holds under worse load; `cpython-mmap`, `ltp-mmap18`,
`ltp-munmap01`, `go-go_types`, `cpython-itertools` MATCH). The reducer
aborted once on the exec-generation observer class (third instance on
main tonight, all at load ≥30; scheduler round 4 owns it).

### 2026-09-08 05:10 — the pre-activation wake window closed (main a5f8592fc)

The other half of the importlib hang: a wake-queued row could be CLAIMED
before its submission's binding record was active, so `resolve` failed
with `SnapshotRestoreFailed` and the clone rollback aborted the carrier
(reproduced live: `lost exact transition … kernel_view=Failed {
SnapshotRestoreFailed }` → `FATAL: authoritative HVPatch clone rollback`).
Fix 119f07e97 (`opus/activation-window-sep08`): the run queue is the single
authority for claimability and activation IS publication — every `admit_*`
marks the key `unpublished` under the same lock that counts the authority;
a wake for such a key owns the edge but its row is `deferred`, never in
`rows`; only `publish` (from `activate`) clears the mark and releases the
held row in the same critical section; `enqueue` returns a typed
`EnqueueOutcome { Claimable, Deferred, Coalesced }` because a bool cannot
say "queued but not claimable". Red-first unit test (wake → claim →
activate) fails pre-fix with `missing exact HVPatch task binding`, green
after; two existing tests that encoded the wrong order were corrected.
Gates 0; go-build reducer 8/8; interleaved 16-pair A/B on the importlib
argv: base 14/16 (two rc=134), fix 16/16, zero hangs, zero watchdog reaps.
Director gates on the rebase: 36 scheduler/executor tests, lint 0,
workspace check 0. Note for the scheduler branch: the per-CPU queue must
carry the same gate when it rebases. Stale ledger argv: `--raw` (deleted
in 457fd7bb0) still appears in `scripts/conformance/baseline.jsonl`.

### 2026-09-08 05:30 — scheduler round 4 verdict and round 5

Round 4 (056a8cc23) landed on the branch: the rebase over lane A, one
`GuestCpuId` (lane A had compiled a second copy of the hal file via
`#[path]`, so its placeholder CPU ids were a different type), the real
guest CPU on every auditor emit, `wake_rejected(StaleGeneration)` from the
queue's discard paths, and the reaped-path `SubmissionAuthority` leak
closed (`retire_reaped`, red-first). Gates 0 (5161 tests, probe shards,
lint). **Blocker attributed:** the branch's go_types wedge (eight watchdog
reaps + one 20-min test bound; guest prints PASS, 18 executors parked,
main in `wait_process_jobs`) is the same defect main aborts on
(`lost exact transition`): round 3's `TargetReaped` settlement withholds
the successor AND skips the terminal publication the old executor-death
path made, and `classify_transition_rejection` reads only registry
absence, which is also true mid-retirement. M = P: four interleaved pairs
on importlib, two favour M = 10, one tie, one confounded — not flipped.
Round 5 (dispatched): reaped settlement publishes the terminal result;
classification from the kernel graph's execution state with the
lost-transition arm becoming a `KernelAbort`; rebase onto a5f8592fc and
port the claimability gate into the per-CPU queues; go_types 5/5 with
zero reaps as the bar.
