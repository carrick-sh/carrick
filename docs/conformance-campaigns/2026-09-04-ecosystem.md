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
