Branch `work/s3-t3b`, clean HEAD `1cf7568e1`. Not review-ready.

WIP two-process inverse tests committed at `a2f1ccdca`. Single live-mapping
intervention `690383cc8` was reverted by `1cf7568e1`: its signed focused run
failed before probe output, rejecting the internal EL1-only identity-bootstrap
read at `0x2d001e4004`. This does not prove or disprove the stale-mirror cause.
GNU and inverse test were not reached; do not call this a red-to-green fix.
No new seam protocol or further probe fix was attempted.

Restored signed build passed. Full generic batch ran once: 13 musl DIFFs,
one deadline failure. The dedicated case batch ran once: 33/33 passed and
entitlement negative control passed. Both batches had zero scoped leftovers.
No Docker ran. No GNU probe executed: shard 0/2 stop at musl mismatch
assertions; shard 1 stops at epollstopcont before the private-file probe.
The recorded branch/main mmapprivatefiletrack red witness remains unresolved,
but was not reached in this full batch. These are observed rows, not an
exhaustive remaining regression list across both libcs.

| Suspected shared cause | Observed musl DIFFs | Evidence | N1 seam relation |
| --- | --- | --- | --- |
| Anonymous placement, capacity and VMA policy | coredumpbit, mmapcluster | sparse/large anonymous maps return ENOMEM (12) | N1 replaces admitted host mmap policy/root-capacity seam; causal link unproved |
| Protection/fault classification across admission and fork | forkfault, roprotect | anonymous access violations report MAPERR where ACCERR is expected; file control passes | N1 replaces memory/fault/protection seam |
| Host syscall buffer authorization after reuse | mmapv8align | stdout copy fails EFAULT (14), guest exits 134 | N1 deletes mirror/raw-pointer gates; stale-mirror cause unproved |
| Memory-policy synchronization with host-forwarded operations | msyncalign, rlimitasdata | aligned msync fails; within-limit mremap and child limit inheritance fail | N1 replaces admitted mmap-family policy; rlimit/lifecycle component may extend beyond N1 |
| Fork/child survival and inherited state | futexforkwakegroups, nxwritableimage, exitgroupthreads, forkexecstorm | child exit/wake verdicts fail, fork child lost, fork-exec success false | Memory fork seam is replaced in N1; task/futex/exit ownership is N2; not attributed |
| Signal delivery / stopped-task wait continuation | killrt | empty realtime-signal output | Primarily N2 signal/task/wait; possible memory-transfer dependency unproved |
| Suspended I/O continuation or buffer authorization | splicepipeempty | blocking wait-for-writer and output bytes both false | N2 IPC/wait; N1 only if authenticated memory transfer is the cause |
| Deadline failure, not a DIFF | epollstopcont | 60075 ms; 60000 ms container budget exceeded | N2 stop/continue/wait; N1 contribution not established |

Receipts:
- `/tmp/s3t3-intervention-focused.log`, `.cleanup.log`: rejected experiment.
- `/tmp/s3t3-intervention-build.log`, `-identity.log`: intervention artifact.
- `/tmp/s3t3-restored-build.log`, `-identity.log`, `-post-batches-sha.log`.
- `/tmp/s3t3-narrow-generic.log`, `.cleanup.log`, `-artifacts.jsonl`.
- `/tmp/s3t3-narrow-cases.log`, `.cleanup.log`, `-artifacts.jsonl`.

The CLI SHA after both batches equals its restored-build receipt. Signed
executable identities are preserved separately for each test batch. Full
acceptance and a valid live-buffer authentication fix remain outstanding.
