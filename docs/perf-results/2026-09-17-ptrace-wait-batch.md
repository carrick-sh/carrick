# Ptrace wait conformance batch — 2026-09-17

The preceding [socket batch](2026-09-17-socket-conformance-batch.md) exposed an
intermittent `ltp-ptrace11` carrier failure: `HVPatch child selector is stale or
invalid`. This batch reduces that workload failure through the new VM-free
kernel backend and corrects a second, independently witnessed stop-status bug.

## Changes and red-first evidence

Added 16 public-kernel ptrace tests, bringing the backend from 123 to 139 tests.
They cover sibling and ancestor/root tracees across wait4 and waitid, with stop
publication before the wait, between scanning and enrollment, and after
enrollment. Controls preserve unrelated ECHILD, ECHILD after detach, ordinary
job-control stop reporting, and ordinary child exit. Waits are bounded; scripted
interleavings do not use sleeps or schedule retries.

The wait syscall already admitted a tracer waiting for a non-child tracee, but
continuation construction required the real parent. Continuation validation now
accepts the exact parent or exact ptrace tracer from the same live task registry
snapshot. It preserves exact task generations and the scan-time wake precheck.
The zombie path remains parent-only; wider ptrace exit/detach/reap behavior is
not claimed closed by this change.

Stop provenance now travels as `StopKind` from the task owner through the wait
receipt. `waitid` renders ptrace stops as CLD_TRAPPED (4) and ordinary job-control
stops as CLD_STOPPED (5). The encoded wait4 stop status is unchanged.

On original source `1fa517693`, four deterministic continuation tests fail and
two controls pass (`selector-red.log`). After the continuation fix, four
intermediate waitid assertions fail with code 5 rather than 4
(`stop-kind-red.log`). Native ARM64 Docker independently reports 4 for a ptrace
stop and 5 for an ordinary stop. The signed baseline diagnostic `conf-66293`
reports 5 and fails; Docker reports 4 and passes. Its harness exit is zero
because a NEW row is non-gating, so acceptance reads the actual fail/ok pair.
The director independently verified all 16 final tests passing.

An existing Unix credentials test assumed the two forked children send in PID
order. Its assertion now pairs each received payload with the credentials from
the same receive call, checks both senders, and retains SO_PEERCRED checks.
There is no scheduling serialization.

## Verification status

Implementation commits: `6fcf9e831` (red tests), `c349748fa` (fixes and complete
coverage). Documentation/inventory follow-ups: `0544ccb0b`, `8b54551fa`.
Independent read-only Antigravity review found no introduced defects. The
director reviewed the inventory changes separately: only position/fingerprint
receipts changed, with all 585 authority classifications retained.

The normal partitioned kernel recipe passed on unchanged main and the candidate
with complete regular-file output. Worker console/resource failures and the
faulty sender-order assertion are retained in `worker-final.jsonl`; subsequent
passing retries were not accepted as their resolution. The worker was corrected
to use the prescribed recipe. Final worker kernel output is preserved in
`worker-final-kernel.log`, and the director's focused result is
`ptrace-final-green.log`.

An initial full CI attempt failed because the sandbox denied compiler temporary
files during authority capture. Host-access capture succeeded. Full host CI passed: 5,507 passing test executions, zero failures, and five
existing ignores. The macOS authority census is authoritative for its host
profiles; Linux/FreeBSD/NetBSD profiles remain pending on their own hosts.

Signed source: `8b54551fa`.

- SHA-256: `36cf56ae51c5f14cf1415eecc3a6fd8bc26595d8bfe1a99d5e94dc08b526b5e9`.
- CDHash: `655f60add77b569ed9c159346581f93fe77cd6cb`.
- LC_UUID: `CCAFC24C-B28A-37DA-9FC5-D8FAF85E47F8`.
- Hypervisor entitlement, signature verification, and `__dof_carrick` recorded.
- Public signed probe gate passed, including all three generic shards,
  dedicated signed scenarios and entitlement negative controls. Non-native
  AMD64 report-only differences/skips are not cross-platform acceptance.
- Fresh-oracle smoke passed: 23/23 MATCH.
- Full strict closure: 1,263 MATCH / 864 INCOMPLETE, exit 1. All 2,127
  declared names and unique nonempty run IDs are present on both sides; zero
  cached oracles. Raw prefix: `conf-96791`. No full/release acceptance.

The product was signed once and preserved as `final-carrick`; gate recipes use
`--no-deps` to prevent re-signing it. Its hash was unchanged after probes and
smoke. Its hash also remained unchanged after the full gate. All four registry and
Docker image identities match before and after the measurement.

Local evidence: `target/conformance/eco-ptrace-20260917/` (gitignored). Original
raw streams and the preceding full ledger are retained. No push is authorized.

## Signed witnesses and remaining priorities

`ltp-ptrace11` matches the fresh oracle: both pass 1/1 with zero broken results
(`conf-96791-c953/d953`). A predetermined 20-run ABBA diagnostic retained all
results: original artifact 9/10 successful, corrected artifact 10/10 successful.
Original `conf-5483-c00` reproduces the exact stale-selector termination and
TBROK after its passing assertion. This sample supports, but does not replace,
the deterministic red-to-green tests. Its cached oracle was freshly measured in
the preceding full run; it is not a performance experiment.

The signed waitid reduction is also red-to-green: original `conf-66293` reports
stop code 5 and fails; corrected `conf-5257` and fresh Docker both report code 4
and signal 19, with `pairs.suite = [ok, ok]`. Both raw streams were inspected.

The full ledger still has 29 Carrick failures and 18 cutoffs where Docker
succeeds. Of its 864 incomplete rows, 784 have equal parsed pairs, including
empty pairs; that is not equivalent to complete execution. `full-audit.json`
and `audit-full.py` retain the exact row populations and comparison to the
previous full run. The prior two missing Carrick metadata records are present
this time; this observation does not fix the pre-existing harness provenance
loss path.

1. **Completed-workload amplification:** CPython bufio measures 5.47x Docker
   (3,366 ms / 615 ms), httplib 4.13x, and os 4.05x. These are same-image
   discovery measurements under the normal harness workload, not controlled
   ABBA performance claims. Buffered I/O is the strongest completed-workload
   reduction target; pathological amplification remains a correctness issue.
2. **Blocking and scaling:** futex_cmp_requeue01 is still cut off after five
   passing assertions versus Docker's seven; retain the 100-versus-1,000-waiter
   reduction. Go syscall and CPython compile remain truncated. Five additional
   rows cut off relative to the preceding run: inotify11, multiprocessing_fork,
   multiprocessing_main_handling, pathlib, and queue. Their budgets and raw
   streams are retained; none is accepted as merely slow or dismissed as noise.
   Go os completes this time, which does not explain its previous cutoff.
3. **Socket semantics and variable outcomes:** CPython socket still has 21 SCTP
   record/EOR failures, SSL still has two close-ordering failures. The four LTP
   socket fixes from the previous batch remain successful. Go net_smtp adds
   `TestTLSClient` failing to send TLS closeNotify because of EPIPE; poll02 adds
   a poll oversleep assertion (100 ms samples, truncated mean 102,593 us versus
   2,537 us allowed oversleep). A fixed ABBA comparison, two original and two
   candidate runs per suite, passed on both artifacts. These focused passes do
   not close or attribute either full-run failure. Both remain open, including
   the possibility of load-coupled behavior, with exact raw records preserved.

No retry, timeout increase, lower-concurrency result, or baseline waiver was
used to turn the full closure result green. The one-worker ABBA diagnostics
are explicitly attribution samples, not replacement gate results.

## Cleanup and handoff

Final cleanup checks 4,338 recorded run IDs and finds no task processes or
containers, and no other Carrick executables. The signed artifact still verifies
and retains its recorded SHA-256. Both Antigravity workers are finished; their
logs are copied into the evidence directory. The clean integrated worktree was
removed normally, with its branch preserved. Unrelated user plans remain
untouched. Changes are committed locally; nothing was pushed.
