# Current conformance closure clusters — 2026-09-18

Status: historical reconciliation has reduced the earlier 862 incomplete rows
to 14 explicit non-matches. This is discovery and focused repair evidence, not
release acceptance: the current worktree has not yet passed the full signed
promotion ladder.

## Evidence boundary

The authoritative broad ledger remains
`target/conformance/results.hvf.full.jsonl`. It exercised all 2,127 declared
rows and retained 2,127 unique names and nonempty Carrick run IDs. Focused
signed screens after that run are additive evidence for rows that were
incomplete in `target/conformance/eco-20260917/results.jsonl`; they do not turn
the older full run into a current-artifact full gate.

The current focused artifact is built from committed source
`5522e139f3be13a56ccaf90502ea961e237a8a90` plus the reviewed worktree changes:

- SHA-256: `968d44296fe0043f3c92b3b894c067838da0fe45a01c058726fc3b463b44cada`
- CDHash: `1b6b9996abb6cd8a7ede28283597fc9c74107f17`
- LC_UUID: `828F46F4-D072-3F1E-9832-365B5B415683`
- signature identifier: `carrick.tmp.29109`
- Hypervisor entitlement and `__TEXT,__dof_carrick` are present.

`target/conformance/historical-incomplete-22-current-20260918.jsonl` exercised
the last 22 rows together against cached Docker oracles. The repaired
`io_submit04`, `msync03`, and `setsockopt02` rows were then rerun together on
an earlier focused artifact in
`target/conformance/closure-three-final-20260918.jsonl`; all three MATCH.
`accept02` and `sendto01` both MATCH in
`target/conformance/socket-final-20260918.jsonl`. The current artifact above
then closed `ioctl10` at 17/17 in
`target/conformance/ioctl10-final2-20260918.jsonl`.
The current artifact above closed `pidfd_getfd01` and `pidfd_getfd02` in
`target/conformance/pidfd-getfd-gated-20260918.jsonl`; both MATCH with their
former `summary` waiver removed.
The same artifact also reran Go `os/signal` after qualifying the Docker
container with unconfined seccomp and `CAP_SYS_ADMIN`: both sides passed all 30
executed assertions at 1.12x in
`target/conformance/go-os-signal-qualified-20260918.jsonl`. That is strong
differential evidence for `TestTerminalSignal`, but the suite remains strict-
closure incomplete because `TestAllThreadsSyscallSignals` is skipped when cgo
is disabled. The closure cache correctly refuses that skipped assertion.

## Impact on the 862-row incomplete population

The earlier fresh-oracle ledger contained 1,265 MATCH and 862 INCOMPLETE rows.
The current backend, intervening runtime work, and focused signed proofs now
give explicit Docker parity for 848 of those 862 rows:

| Ecosystem | Earlier INCOMPLETE | Proved MATCH | Still non-MATCH |
| --- | ---: | ---: | ---: |
| LTP | 587 | 575 | 12 |
| Go | 66 | 65 | 1 |
| Node | 1 | 1 | 0 |
| CPython | 208 | 207 | 1 |
| **Total** | **862** | **848** | **14** |

That is 98.4% of the historical incomplete population classified as MATCH.
The original bucket was therefore dominated by missing execution evidence,
not 862 independent runtime defects. The remaining 14 are concrete behavior,
setup, or performance differences.

## Current 14-row clusters

| Cluster | Rows | Exact rows | Boundary |
| --- | ---: | --- | --- |
| Oracle/setup inversions | 7 | `acct01`, `acct02`, `fanotify25`, `fsetxattr02`, `setsockopt08`, Go `os/signal`, CPython `ssl` | Carrick skip/pass versus Docker setup failure or the reverse; qualify privileges and declarations before changing runtime behavior |
| Blocking/pathological | 3 | `inotify09`, `msgstress01`, `shmctl05` | All hit the 40-second budget; `inotify09` was serially confirmed at 3.88x Docker |
| Readiness | 1 | `epoll_pwait06` | The suite reaches a pipe-end case and is terminated by `SIGALRM` |
| Filesystem seek semantics | 1 | `lseek11` | `SEEK_HOLE` corrupts the following read position |
| Unsupported syscall/API | 2 | `delete_module02`, `name_to_handle_at03` | Confirmed unsupported or `ENOSYS` paths |

The three-row repair batch closed independent kernel contracts:

- `io_submit04`: a `RWF_NOWAIT` pread on an empty pipe now publishes an AIO
  completion with `res=-EAGAIN`; focused result 1/1 at 1.71x Docker.
- `msync03`: `MS_INVALIDATE` alone is accepted, and an intersecting locked
  range returns `EBUSY`; focused result 6/6 at 0.57x Docker.
- `setsockopt02`: TPACKET_V3 private-area sizing is checked without 32-bit
  wrap and ring offsets preserve that private area; focused result 2/2 at
  0.86x Docker.
- `accept02`: accepted in-memory sockets start without the listener's IPv6
  multicast memberships; focused result 1/1 at 1.16x Docker.
- `sendto01`: an unconnected INET stream reports `EPIPE` and raises `SIGPIPE`
  before provider routing can turn the error into `ECONNREFUSED`; focused
  result 10/10 at 0.38x Docker.
- `ioctl10`: `PROCMAP_QUERY` now reads the same live map projection as
  `/proc/<pid>/maps`, including exact/next selection, permission filters, and
  executable names; focused result 17/17 at 1.73x Docker.
- `pidfd_getfd01` and `pidfd_getfd02`: HVPatch resolves the pidfd's stable task
  key, applies ptrace real-credential permission, duplicates the target's exact
  open-file description with `FD_CLOEXEC`, and exposes the shared identity to
  `KCMP_FILE`; focused results 1/1 and 5/5.

## Performance correctness remains open

`fork14` improved from about 9.84 seconds to 6.46 seconds while its pinned
Docker oracle is 1.652 seconds. The 3.91x ratio is a correctness blocker even
though the row's assertions match. The reduction removed repeated fork
projection, coalesced mapping work, promoted last-owner COW frames in place,
gave each child independent vvar storage, and avoided unrelated mailbox
relocation. CPU evidence still places the largest remaining costs in process
spec construction, COW-fault resolution, page-table cloning, and carrier
scheduling; reaching 2x requires another fork-graph change rather than a larger
timeout.

Other assertion-matching rows above 2x remain in scope, including Go
`go/types`, `net`, `net/http`, `go/build`, and CPython `tarfile`. They must not
be counted as performance closure merely because their parsed verdict is
MATCH.

## Next reduction order

1. Reduce the three 40-second rows under serial load, treating amplification as
   the defect rather than increasing their budgets.
2. Close the single-row filesystem and readiness contracts (`lseek11`, then
   `epoll_pwait06`).
3. Audit the seven setup/inversion rows against fresh qualified Docker runs.
4. Implement the two remaining unsupported syscall rows only after their
   capability and host-filesystem boundaries are explicit.

Every accepted batch still requires `just conformance-probes`, then
`just --no-deps conformance smoke`, then `just --no-deps conformance full` on
one unchanged signed artifact. Any red rung blocks promotion.
