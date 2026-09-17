# Non-ASCII pathname amplification — 2026-09-17

The fresh [ptrace-batch ledger](2026-09-17-ptrace-wait-batch.md) ranked CPython
bufio at 5.47x Docker among completed workloads. Isolated measurement on the
same signed artifact (`36cf56ae...`, source `8b54551fa`, documentation HEAD
`4925ecdad`) passed at 1,275 ms versus fresh native ARM64 Docker 405 ms (3.15x).
These discovery timings are not controlled performance claims.

## Reproduction and diagnosis

The exact image's test_bufio repeatedly creates, writes, reopens, reads, and
unlinks `test.support.os_helper.TESTFN`, which contains non-ASCII bytes.
A complete Carrick host-syscall trace records 6,786 guest openat calls and
6,410 unlinkat calls. These cause 6,411 and 6,413 host directory enumerations,
respectively. Within unlinkat there are 41,666 host fstatat calls; within
openat there are 20,032. `name_matches_on_disk_impl` enumerates every sibling
for each non-ASCII leaf, and its generic directory reader stats each regular
sibling even though this caller discards sizes.

A bounded reduction performs 64 create/read/unlink cycles with content checks,
varying only leaf spelling and sibling population. The inner measured work
excludes sibling setup and cleanup. All six cases pass on both implementations.

| Siblings | Carrick ASCII | Carrick non-ASCII | Docker non-ASCII |
| --- | --- | --- | --- |
| 0 | 10.20 ms | 14.51 ms | 1.17 ms |
| 512 | 11.10 ms | 118.81 ms | 1.58 ms |
| 4,096 | 11.19 ms | 863.38 ms | 1.49 ms |

This establishes directory-size-dependent work for the non-ASCII operation.
The baseline source confirms the algorithmic cause; no cache or timeout change
is proposed. These are single-sample diagnostic measurements, not final
paired performance qualification.

The first trace using `tarfile-host-syscall-breakdown.d` exited during startup
on a logical guest-exit; it is incomplete and preserved as such. The new durable
`buffered-io-host-amplification.d` exits only when the root process finishes and
reports completion/errors. `amplification2.raw` records complete=1, errors=0,
and the workload's four tests pass. Tracing perturbs timing; only operation
counts are used. The sampling trace is diagnostic, with unsymbolized addresses;
no stack attribution claim is made from them.

## Bounded design and validation status

Use macOS `getattrlistat` with ATTR_CMN_NAME and FSOPT_NOFOLLOW through the
existing contained parent descriptor. Compare the returned stored bytes with
the requested leaf using checked attribute-buffer bounds. Keep the existing
non-macOS/unsupported-query fallback, no persistent name cache, and no new
pathname authority. Local APFS qualification distinguishes composed/decomposed
aliases, preserves each hardlink's own name, and does not follow symlink leaves.
F_GETPATH is not a substitute for the named directory entry. This change does
not make normalization-equivalent names coexist on APFS; that pre-existing
representation limitation remains.

Antigravity read-only review independently identified the same whole-directory
scan and per-sibling stat amplification. The implementation is committed locally as `089830e95` (tests) and
`592273159` (fix), with inventory positions and portable test imports in
`5b4a20661`. An independent read-only review found no defects. The director
replayed both red tests: the kernel case visited 101 entries and the VFS owner
case visited 201. Five semantic cases passed before the fix; all six kernel
cases pass afterward. The new backend can now install a public FsBackend
before process binding, without enabling product test-only features.

The normal kernel recipe passes 2,162 tests with one ignored test. Full local
CI passes 5,516 tests with zero failures and five ignored tests, including the
VFS owner and checked attribute-buffer decoder tests. These counts include the
recipe's subprocess test summaries. Earlier worker console WouldBlock retries
and a run with an incorrect test-thread override are preserved but excluded
from acceptance. The director used the unmodified recipes with regular-file
output. A sandboxed pre-fix build was blocked by DTrace code generation; the
unsandboxed replay produced the expected structural failures.

Signed probe and smoke validation passed; full closure remains red. The frozen
candidate source is `5b4a206617d7de31fb74725e68db5b29c0997d3b`, SHA-256
`1f03f7fd5eb215ae99382bacc2014cd8e18b819a837c53ca0dcc00dae76f9656`, CDHash
`d9efcc76f474aa13f58b91f48fc842aac4c6d559`, LC_UUID
`6B46AFD4-4806-3308-9B75-34CC72AE3A39`. The hypervisor entitlement, strict
signature verification, and `__dof_carrick` are recorded. The full gate and controlled measurements below define the limits of acceptance.

Local evidence: `target/conformance/eco-bufio-20260917/` (gitignored), including
baseline/scaling ledgers, both raw streams, image identities, trace outputs,
exact image test source, local API qualification, and architecture review.

## Smoke timing provenance

The first candidate smoke run used a new isolated oracle cache that lacked
slow-suite timing metadata. Four rows hit the default five-second discovery
budget: go-time, cpython-json, cpython-subprocess, and cpython-threading. Docker
itself took roughly 6–21 seconds for those rows. The original signed binary,
run once with the same cold-cache condition, hit the same four cutoffs. Both
incomplete ledgers are retained (`smoke-cold-cache-results.jsonl` and
`baseline-cold-smoke.jsonl`); a successful harness exit is not a complete pass.

The gate was then run with a copy of the prior qualified timing cache, matching
the previous batch's setup. All 23 rows matched fresh Docker results. There
were no flag changes, concurrency reductions, serial confirmations, or flake
retries. `--refresh-oracle` preserves timing inputs before invalidating verdicts;
the qualified cache therefore supplies the existing oracle-derived budget but
never substitutes an old verdict for the fresh Docker phase. The binary SHA
remained unchanged after both probe and smoke gates.

## Controlled result and remaining overhead

Two same-host ABBA blocks ran original/fixed/fixed/original, four samples per
arm, against the digest-pinned native ARM64 CPython image
`sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30`.
The first block ran a fresh Docker phase after Carrick; subsequent samples used
that contemporaneous oracle. All 32 case executions matched. No builds, workers,
or other Carrick processes overlapped. Docker values below are single samples,
not a distribution; medians describe the four Carrick samples per arm.

| Case | Original median | Fixed median | Docker | Original/fixed |
| --- | ---: | ---: | ---: | ---: |
| Non-ASCII, no siblings, 64 operations | 14.566 ms | 11.799 ms | 1.146 ms | 1.23x |
| ASCII, 4,096 siblings, 64 operations | 11.623 ms | 11.487 ms | 1.443 ms | 1.01x |
| Non-ASCII, 4,096 siblings, 64 operations | 872.593 ms | 12.002 ms | 1.436 ms | 72.70x |
| Exact CPython test_bufio, total harness wall | 1,490.5 ms | 1,300.5 ms | 411 ms | 1.15x |

The bounded reduction excludes sibling setup/cleanup and asserts all written
and read bytes. Its fixed non-ASCII cost is nearly independent of sibling count.
However it remains 8.36x Docker at 4,096 siblings, and the full bufio workload
remains 3.16x Docker in this isolated sample. Those are still correctness-priority
overhead gaps; this fix removes one demonstrated algorithmic amplification,
not the whole filesystem cost. The broad full-run bufio row separately passed
four tests on both sides at 1,912/806 ms (2.37x); it is discovery evidence, not a
substitute for the controlled comparison.

The final durable trace was run on both preserved binaries using the same
script. Both report complete=1, errors=0, nonzero events, root exit 0, and all
four workload tests passing. Each observes 6,786 guest openat and 6,410 unlinkat
calls. Host getdirentries64 within those calls falls from 6,411/6,413 to 1/1;
the fixed path instead performs 6,410/6,412 getattrlistat queries. Associated
fstatat64 counts fall from 20,032/41,666 to 13,624/35,259. Other metadata work
remains visible. Traced timing is not used. The preserved binary copy initially
could not use the canonical sudo rule; the successful captures used the
configured canonical path, restoring the candidate byte-for-byte afterward.

A nonzero-exit control exposed a tracer reporting limitation: guest exit 7 is
visible in the trace, but the CLI still exits zero despite DTrace exit(2). The
final script emits complete=0 for this control, and its header requires consumers
to validate completion, errors, nonzero events, root exit, guest code, and workload
output. The final script was rerun on both successful workloads. CLI exit-status
propagation remains a separate instrumentation gap; exit zero alone is not proof.

## Full conformance, limits, and next priorities

The exact 2,127 declared rows ran with fresh Docker results and unique run IDs
on both sides; no metadata or raw stdout/stderr files are missing. The result is
**1,265 MATCH / 862 INCOMPLETE**, exit 1: **full closure is not accepted**.
The ecosystem split is CPython 229/209, Go 128/66, LTP 906/586, Node 2/1
(match/incomplete). There are 28 failure results and 11 cutoffs against successful
Docker results. No previously successful row became a failure or cutoff, and
no new failed assertion pair appeared. The two extra MATCH rows over the prior
batch are poll02 and go-net_smtp; their known variability is not credited to
this pathname change. Several prior cutoffs completed, also without a causal
claim from one broad run.

Raw-output inspection adds a blocker that verdict totals alone conceal:
`ltp-file_attr05` (`conf-54276-c341`) failed before test output with host ENFILE
while creating a private executable artifact after exec's point of no return.
It then reported SnapshotRestoreFailed, an execution-lease settlement error,
and terminal ASID retirement failure. Docker itself TBROKs for lack of a device;
that does not excuse the Carrick crash. Two focused original and two focused
fixed executions each returned the normal device-unavailable TBROK, so the
full-load crash is **unattributed and unresolved**, not cleared by those runs.
`ltp-open04` returned ENFILE (23) rather than EMFILE (24); the prior raw transcript
contains that same failure even though its earlier result was truncated.

Next evidence-driven priorities:

1. Descriptor exhaustion and failed-exec retirement: reproduce the load-coupled
   ENFILE/lease/ASID chain, enforce per-process guest descriptor limits, and make
   failed exec settle ownership correctly. Do not serialize the suite or raise
   limits as closure.
2. Remaining completed filesystem amplification: CPython pathlib 4.71x, os
   4.68x, threadedtempfile 3.23x, tarfile 3.17x in this discovery run, plus bufio's
   controlled residual. These need their own paired reduction and attribution.
3. Existing socket/SSL gaps: socket retains 21 SCTP failures and SSL two failures;
   futex_cmp_requeue01 remains a cutoff and the earlier scale reduction is open.

The signed artifact's identity stayed unchanged through the ladder and after
the diagnostic canonical-path swap. All 1,076 previously rebuilt ARM64 probe
executables retain their recorded hashes. Probe logs retain report-only AMD64
differences and unavailable legacy lanes; they are not native x86 acceptance.
Image identities remained unchanged before/after. Scoped cleanup checks found
no remaining guests or containers. Work is local only; nothing was pushed.
