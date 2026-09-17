# Ecosystem discovery — 2026-09-17

The next kernel-harness coverage batch should start with socket receive and
close semantics. This recommendation comes from a fresh full ecosystem run,
followed by a separate one-worker reproduction of nine concrete failures.
No runtime or test implementation was changed during this discovery.

## Measurement and evidence

- Source: `00fb0920b` (full revision in the evidence directory).
- Fresh signed product build and explicit release conformance-harness build.
- Carrick SHA-256: `2b257700adc2db54eaae2e78c4b0e03d58a79cf7a9b47a1e27a6e82627b15a18`.
- Harness SHA-256: `e264c0c9725652369c9b94f707b02a6aa31030d4a9915f9beeef68a78ded50f9`.
- CDHash: `673ac22d18d38650081e118c56660cf5e0856ac8`.
- LC_UUID: `5949AF5C-1357-340C-97DC-05665580D20C`.
- Hypervisor entitlement and `__dof_carrick` recorded. Binary/harness/manifest
  hashes unchanged after both runs. Registry and Docker image identities
  matched before the run and remained unchanged after the full run; Carrick's
  image-digest sidecar matched all four registry digests.
- Full run: eight workers, four CPython heavy workers, all Carrick executions
  followed by all Docker executions. Native Linux arm64 oracle, fresh for every
  row. No flake retries. Automatic serial confirmation disabled so the loaded
  observation is retained; this does not turn a diagnostic cutoff into a hang.
- Exactly 2,127 unique suite names, Carrick run IDs, and Docker run IDs; zero
  cached Docker rows. Name set equals the declared manifest.
- Full and focused commands both exited 1. No baseline blessing or push.
- Final scoped census: no remaining processes or containers for `conf-76653`
  or `conf-85246`.

Local evidence directory: [`target/conformance/eco-20260917`](../../target/conformance/eco-20260917).
It contains `results.jsonl`, `focused-results.jsonl`, `summary.json`, both logs,
the separate refreshed oracle cache, image identities, signing receipts,
hashes, invocation, exit codes, and `cleanup.json`. Raw stdout and stderr are
under `target/conformance/raw/<run-id>.{out,err}`. These target artifacts are
local and gitignored; this document retains the conclusions and provenance.

Full invocation:

```sh
target/release/carrick-conformance --closure --tier full --force \
  --refresh-oracle --flake-retries 0 --carrick-serial-confirm-budget-s 0 \
  --oracle-cache target/conformance/eco-20260917/oracle-cache.jsonl \
  --jsonl target/conformance/eco-20260917/results.jsonl
```

## Full accounting

| Ecosystem | Rows | Strict MATCH | INCOMPLETE |
| --- | ---: | ---: | ---: |
| LTP | 1,492 | 905 | 587 |
| Go | 194 | 128 | 66 |
| Node | 3 | 2 | 1 |
| CPython | 438 | 230 | 208 |
| Total | 2,127 | 1,265 | 862 |

INCOMPLETE is not a count of Carrick defects. Of those 862 rows, 779 have equal
parsed side summaries and equal assertion pairs, but still do not satisfy
strict nonempty all-pass closure (for example, common skips or setup failures).
The remaining 83 require individual interpretation too. There are 32 rows
with a Carrick failure-shaped result and a successful Docker result, and 12
truncated Carrick rows whose Docker counterpart succeeds. Failure-shaped
results include skips and broken setup, not just failed assertions.

For example, libuv has 499 passing assertions and eight skips on both sides,
with identical assertion pairs; strict closure correctly remains incomplete.
`bind02` and both `fcntl12` variants fail on Docker as well as Carrick. Do not
prioritize them as Carrick-only failures. Conversely, inversions such as
`copy_file_range03`, `epoll_pwait03`, `select02`, and Go `os/signal` need oracle
and assertion review, not automatic credit for Carrick.

## Ranked coverage and investigation targets

### 1. Socket receive and close contracts

This cluster has both small LTP witnesses and real language-suite failures.
Use the VM-free backend for deterministic syscall/continuation tests with
explicit enrollment handshakes, then revalidate the originating signed suites.

- `ltp-epoll_wait05`: Linux reports `EPOLLRDHUP`; Carrick reports zero events.
  Full run: 2,281 ms versus 201 ms (11.35x). Independent one-worker run:
  2,325 ms versus 205 ms (11.34x). The missing event and wait account for the
  observed pathological behavior; these are not successful-workload speed
  measurements. Raw full IDs: `conf-76653-{c,d}164`; focused IDs:
  `conf-85246-{c,d}01`.
  Subsequent signed syscall tracing narrowed this to **local `SHUT_RD`**, not
  peer close: the client connects, registers epoll, shuts down its own read
  side, then waits two seconds and receives zero events. The fresh native
  Docker reduction returns `EPOLLRDHUP` for local read shutdown on both TCP
  and Unix streams. See `epoll-close-flow.txt` and
  `socket-contract-oracle.txt` in the evidence directory.
- `ltp-recv01`, `ltp-recvfrom01`, `ltp-recvmsg01`: empty `MSG_ERRQUEUE`
  behavior diverges; recvfrom also fails an invalid address-length case.
  All three reproduce with one worker. The in-memory recvmsg path precedes
  later error-queue handling in `dispatch/net/send_recv.rs`; that is a source
  hypothesis for a reducer, not a proven root cause.
  The reduced fresh Docker oracle also establishes a family boundary: TCP
  returns `EAGAIN` without consuming ordinary queued bytes; Unix socketpair
  receive ignores `MSG_ERRQUEUE` and consumes those bytes normally. An
  unconditional early error-queue return would introduce a Unix regression.
- CPython socket: 23 failures versus zero on Docker. Twenty-one are in the
  two SCTP recvmsg classes, two in TCP long ancillary-buffer cases. One SCTP
  witness expects `MSG_EOR` and gets zero. Do not silently emulate SCTP as TCP
  or hide these failures by declaring new expected gaps. Full raw IDs:
  `conf-76653-{c,d}2001`.
- CPython SSL: two pre-handshake-close failures versus zero on Docker. The
  client receives `ConnectionResetError` instead of `ssl.SSLError`; the server
  sees an HTTP-request SSL error instead of the expected pre-handshake-data
  error. These justify close/reset/data-order reducers, but are not yet proven
  to share the epoll root cause. Full raw IDs: `conf-76653-{c,d}2007`.
- Adjacent one-worker-confirmed witnesses: `accept02` (multicast state copied
  into accepted socket), `send02` (`MSG_MORE` data arrives too early),
  `sendto01` (unconnected TCP returns errno 111 instead of 32), and
  `setsockopt02` (invalid packet-ring private size accepted). Preserve their
  distinct contracts rather than assume one networking patch fixes all.

### 2. Blocking and scalability failures

All twelve truncated rows have a successful fresh Docker counterpart:

| Suite | Carrick cutoff | Docker time | Cutoff kind |
| --- | ---: | ---: | --- |
| ltp-epoll-ltp | 10 s | 3.220 s | Diagnostic |
| ltp-fork14 | 14 s | 6.049 s | Diagnostic |
| ltp-futex_cmp_requeue01 | 5 s | 0.805 s | Diagnostic |
| ltp-inotify09 | 23 s | 6.846 s | Diagnostic |
| ltp-msgstress01 | 40 s | 20.452 s | Declared |
| ltp-pipe06 | 7 s | 1.807 s | Diagnostic |
| ltp-shmctl05 | 40 s | 37.000 s | Declared |
| ltp-timerfd_settime02 | 15 s | 6.287 s | Diagnostic |
| go-go_types | 14 s | 6.177 s | Diagnostic; output progressing |
| go-net | 8 s | 2.485 s | Diagnostic |
| go-net_http | 11 s | 4.091 s | Diagnostic; output progressing |
| cpython-tarfile | 13 s | 5.484 s | Diagnostic; output progressing |

Do not cite the ledger's ratio field for these rows: a killed run is not a
completed timing sample. The harness's `blocked` sample classification also
does not prove a lost wake. For the two declared cutoffs, particularly shmctl05
whose Docker run itself needs 37 seconds, distinguish timeout from a proven
hang before choosing a fix.

The best scaling reducer is `futex_cmp_requeue01`: Carrick's transcript ends
after the 100-waiter cases; Docker completes the 1,000-waiter cases and all
seven assertions. Establish whether the missing progress is in kernel
requeue/wake ownership or runtime task/executor admission. The new harness
uses host threads and has no actual vCPU pool, so it cannot by itself prove
the runtime-capacity part. Keep the signed workload witness.

### 3. Concrete missing operations and I/O semantics

`io_submit04` (completion missing, also reproduced with one worker),
`fcntl40`/`fcntl40_64` (`F_CREATED_QUERY`, six failed assertions total), and
`ioctl10` (`PROCMAP_QUERY`, eleven failures) are explicit current behavior gaps.
`msync03`, `execve03`, and filesystem-handle cases also differ. Pick public
kernel-API reducers where the backend can model the contract; real exec and
page-table behavior remain outside its proof boundary.

### 4. Completed workload overhead

Successful-side screening ratios include `inotify11` 4.10x, CPython `pathlib`
4.09x, `os` 3.60x, and `venv` 3.23x. These exceed the project's 2x target and
deserve operation-count/ownership investigation. They are parallel-run leads,
not controlled ABBA performance claims, and successful side summaries do not
imply strict all-assertion closure. Establish a same-image quiet measurement
and attributable work amplification before proposing an optimization.

## Focused reproduction and next acceptance boundary

The focused run used the same binary with `--workers 1 --refresh-oracle`, the
same cache/output isolation, zero flake retries and zero automatic serial
confirmations. Selected rows: accept02, epoll_wait05, io_submit04, recv01,
recvfrom01, recvmsg01, send02, sendto01, setsockopt02. All nine retain a Carrick
failure with successful Docker assertions. Ordinary baseline classification
labels three DIFF/non-gating and six REGRESSION/gating; all nine are defects
for this investigation regardless of that historical classification.

Start with red kernel-harness tests for receive flags and close readiness,
then fix the evidenced ownership/state transitions. Preserve the SSL/SCTP
workload witnesses as separate boundaries until a reducer demonstrates a
shared cause. Keep exact dispatch/completion accounting so a result obtained
through polling or excessive repeated work cannot pass as a correct fix.

This discovery did not run the probes-to-smoke promotion ladder, fix the
reported defects, qualify performance, or establish release acceptance.
