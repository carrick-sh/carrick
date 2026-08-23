# HVPatch Clauseless Probe Deaths Classification — 2026-08-22

**Provenance:** Extracted from `target/perf/closure-run-7.log` (union of runs 6–7 clauseless probe failures displaying `<missing>` lines without `phase=active`, `FATAL`, `ERROR`, `panicked`, or pinned fd diagnostics). Evaluated on 2026-08-22 on branch `agy/noclause` under codesigned release binary (`target/release/carrick`) via 3x serial execution (`timeout -k 5 40`) and 4-way concurrent load verification for serial passes.

---

## Summary Counts

- **Total Probes Analyzed:** 35
- **(a) NAMED-CLAUSE-recovered:** 3 (8.6%)
- **(b) WEDGE (rc=124):** 17 (48.6%)
- **(c) GENUINE-SILENT:** 0 (0.0%)
- **(d) PASSES-NOW:** 15 (42.8%)
- **Sum:** 35 / 35 (100.0%)

---

## Classification Table

| # | Probe | Verdict | Exact Quoted Clause or Exit Status | Detail |
|---|---|---|---|---|
| 1 | `accessx` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by VFS / mode permission resolution merges (`6d469d80`, `ed73e4ba`). |
| 2 | `aliassize` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by stage-1 page-table block coalescing and alias sizing fix (`4f07672e`). |
| 3 | `altstacktid` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by signal altstack per-thread isolation merge (`fdb6a997`). |
| 4 | `bsd_signal_xlate` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 2 & 3; carrier sampled) | Intermittent lost wake / wait wedge during signal handler delivery quiescence. |
| 5 | `clone3exithandled` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by clone3 exit handler propagation fixes (`ae247b77`). |
| 6 | `cloneexithandled` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by clone exit handler lifecycle fixes (`ae247b77`, `f01d5720`). |
| 7 | `execfromthread` | `(a) NAMED-CLAUSE-recovered` | `"carrick: configuration refused: persistent executor pool shutdown failed: hypervisor operation failed: HVPatch ASID load rejected: ASID generation is closed to new executor loads"` | Rejection during persistent executor teardown while multi-threaded child execs; also manifested as timeout (`rc=124`). |
| 8 | `execpermitchurn` | `(b) WEDGE` | `rc=124` (TIMEOUT in run 2; carrier sampled) | Intermittent vCPU lease starvation / executor quiesce hang under rapid exec churn. |
| 9 | `fdio` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Stalls on pipe2 / nonblocking event I/O loop in guest child. |
| 10 | `forkfault` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by stage-2 COW fault delivery and page allocation fixes (`965ea500`). |
| 11 | `forkfpreclaim` | `(a) NAMED-CLAUSE-recovered` | `"ERROR carrick_runtime::vcpu_loop: HVPatch process job failed error=trap engine failed: hypervisor operation failed: hvpatch child stage-1 VA 0x6000004000 resolves to IPA 0x9c0a600000, expected 0x9c09e04000"` / `"carrick: unsupported in this backend: HVPatch process child panicked"` | Mismatched child stage-1 IPA resolution and COW missing physical backing during fork frame reclamation. |
| 12 | `forkshared` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by MAP_SHARED memory inheritance across multi-generation forks (`df009570`). |
| 13 | `forksigwalk` | `(b) WEDGE` | `rc=124` (TIMEOUT in run 2; carrier sampled) | Intermittent wait hang waiting for signal delivery across child process tree. |
| 14 | `futexforkrequeue` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Deadlock in futex requeue wait list synchronization across fork barrier. |
| 15 | `getsocknameval` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by socket address/length validation merge (`e924d8a3`). |
| 16 | `killuidperm` | `(a) NAMED-CLAUSE-recovered` | `"carrick: FATAL: HVPatch alias registry changed under topology lock: planned={(670180589568, 16384), (670182686720, 16384), (670186864640, 32768)} actual={(670180589568, 16384), (670186864640, 32768)}"` | Alias registry mutation race under topology lock triggered `SIGABRT` (`rc=134`) on run 3. |
| 17 | `legacyaio` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by legacy AIO syscall emulation stubs and error mapping (`fdb6a997`). |
| 18 | `loopbacksubnet` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by loopback subnet 127.0.0.0/8 alias bind support (`e924d8a3`). |
| 19 | `mlock2` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by mlock2 and mincore onfault emulation fixes (`4f07672e`). |
| 20 | `mtforkcorrupt` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Deadlock during multi-threaded memory quiescence / fork barrier handoff. |
| 21 | `nsfsioctl` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Stalls during recursive user/peer namespace ioctl traversal. |
| 22 | `openeloop` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by symlink loop recursion limit returning ELOOP (`6d469d80`). |
| 23 | `pendingunblock` | `(b) WEDGE` | `rc=124` (TIMEOUT in run 3; carrier sampled) | Intermittent stall while draining queued realtime signals upon unmasking. |
| 24 | `pipeextra` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Stalls on nonblocking pipe capacity / packet read boundary. |
| 25 | `procladder_mixed` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Hangs on nested process ladder fork and waitpid reaping under HVPatch. |
| 26 | `proclife` | `(b) WEDGE` | `rc=124` (passes 3x serial; TIMEOUT in 4-way concurrent load) | Passes serially but wedges under concurrent gate load during pgroup/session waitpid reaping. |
| 27 | `ptracekillcont` | `(b) WEDGE` | `rc=124` (passes 3x serial; TIMEOUT in 4-way concurrent load) | Passes serially but wedges under concurrent gate load on ptrace child wait state. |
| 28 | `reparenttoinit` | `(b) WEDGE` | `rc=124` (passes 3x serial; TIMEOUT in 4-way concurrent load) | Passes serially but wedges under concurrent gate load on grandchild init reparenting notification. |
| 29 | `rosharedbus` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by read-only shared mapping bus error emulation (`df009570`). |
| 30 | `setidthreadchurn` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Deadlock during thread credential broadcast across concurrent thread churn. |
| 31 | `shmrdonly` | `(b) WEDGE` | `rc=124` (TIMEOUT in run 1; runs 2 & 3 pass; carrier sampled) | Intermittent stall on read-only shmat page fault attachment. |
| 32 | `usernsmap` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by user namespace identity uid_map/gid_map handling (`f01d5720`). |
| 33 | `vforkexecthread` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Deadlock when multithreaded child execs while parent is blocked in vfork. |
| 34 | `waitidcputime` | `(d) PASSES-NOW` | `rc=0` (all 3 serial runs pass, all 4 concurrent pass) | Fixed by rusage CPU time accumulation on waitid/wait4 (`fdb6a997`). |
| 35 | `waitrestart` | `(b) WEDGE` | `rc=124` (TIMEOUT in runs 1, 2, 3; carrier sampled) | Stalls on SA_RESTART interrupted wait syscall restart loop. |

---

## Saved Carrier Sample Files

When a carrier process timed out (`rc=124`), a diagnostic sample was captured via `sample <pid> 1 -file /tmp/<probe>.sample.txt` before process tree termination via `scripts/sudo/kill.sh <run_id>`:

1. `/tmp/bsd_signal_xlate.sample.txt`
2. `/tmp/execfromthread.sample.txt`
3. `/tmp/execpermitchurn.sample.txt`
4. `/tmp/fdio.sample.txt`
5. `/tmp/forksigwalk.sample.txt`
6. `/tmp/futexforkrequeue.sample.txt`
7. `/tmp/mtforkcorrupt.sample.txt`
8. `/tmp/nsfsioctl.sample.txt`
9. `/tmp/pendingunblock.sample.txt`
10. `/tmp/pipeextra.sample.txt`
11. `/tmp/procladder_mixed.sample.txt`
12. `/tmp/proclife.sample.txt`
13. `/tmp/ptracekillcont.sample.txt`
14. `/tmp/reparenttoinit.sample.txt`
15. `/tmp/setidthreadchurn.sample.txt`
16. `/tmp/shmrdonly.sample.txt`
17. `/tmp/vforkexecthread.sample.txt`
18. `/tmp/waitrestart.sample.txt`
