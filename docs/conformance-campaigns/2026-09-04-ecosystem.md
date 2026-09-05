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
