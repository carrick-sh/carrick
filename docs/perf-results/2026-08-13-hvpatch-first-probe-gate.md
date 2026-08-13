# The kernel lane's first conformance gate

**Recorded 2026-08-13.** KP requires `baseline.hvpatch.jsonl` and a
conformance position for the kernel lane. This is the first step: the
line-exact ABI probe gate has **never been run against `--exec-backend
hvpatch`** until now, so the lane this tree is measured against had no
conformance number at all.

## Why it had never been measured

`crates/carrick-cli/tests/conformance.rs` reads `CARRICK_EXEC_BACKEND` and,
unset, uses the shipped default — which is `native`
(`ExecBackendRequest::Native`). So every probe-gate run in this tree's history,
including every one taken during this session's KN/KF/KL work, gated the
**native DSR** lane. That is worth stating plainly because it means the 123
`arm64:musl` failures those runs reported — the ones correctly attributed as
pre-existing and not caused by any change here — are **native-lane failures,
and say nothing about the kernel lane.**

Running it is one environment variable:

```sh
CARRICK_EXEC_BACKEND=hvpatch cargo test -p carrick-cli --test conformance conformance_probes
```

## The result

| lane | PASS | FAIL |
| --- | ---: | ---: |
| `arm64:musl` on **hvpatch** | **304** | **90** |
| `arm64:gnu` on **hvpatch** | 303 | — |
| `arm64:musl` on `native` (same commit) | — | 124 |

**The kernel lane fails 90 probes where the native lane fails 124.** It is
already the better-behaved backend on this suite, which is consistent with the
performance picture and with `vmm`-derived correctness, but it has 90 real
gaps and no blessed baseline.

## The actionable split

Comparing the two failure sets at the same commit:

| set | count | meaning |
| --- | ---: | --- |
| fail on BOTH lanes | 64 | shared gaps — a dispatcher/VFS/signal issue, not backend-specific |
| fail ONLY on `hvpatch` | **26** | **kernel-lane specific — the KP work list** |
| fail ONLY on `native` | 60 | native DSR gaps; out of scope per the backend decision |

The 26 kernel-lane-specific failures:

```text
blockingpipewrite  childsubreaper   dsrconstantpool  execthreads
forksigwalk        futexpilock      killchld         killtarget
mlock2             pauseeintr       pidfdprocdir     pidnsinitsig
posixtimers        procselfpid      procsignalmask   procsignalmulti
roprotect          selecttimeout    sigactionresetinfo  siginfo
signals            sigwaitthread    threadcommname   threadstatuscount
vforkexecthread    waitpgid
```

They cluster, and the clusters name the work:

- **signals and their delivery identity** — `siginfo`, `signals`,
  `sigactionresetinfo`, `procsignalmask`, `procsignalmulti`, `sigwaitthread`,
  `forksigwalk`, `killchld`, `killtarget`, `pauseeintr`. The largest cluster by
  far, and expected: under one host process, signal *targeting* is carrick's
  own problem rather than something the host kernel does for it.
- **per-process identity in `/proc`** — `procselfpid`, `pidfdprocdir`,
  `threadcommname`, `threadstatuscount`, `pidnsinitsig`. Same root: a Linux
  process is a thread, so anything that answers "about the calling process"
  must come from the kernel objects, not from the host process. This is the
  same class as the `times`/`getrusage` bug fixed at `ad5845c56` and the
  system-time bug fixed at `f850336c5`.
- **thread/exec lifecycle** — `execthreads`, `vforkexecthread`,
  `childsubreaper`, `waitpgid`.
- **blocking and timers** — `blockingpipewrite`, `selecttimeout`,
  `posixtimers`, `futexpilock`.
- **memory protection** — `roprotect`, `mlock2`.
- `dsrconstantpool` is a native-lane probe that has no meaning here and should
  be excluded from this lane rather than counted.

## What this is NOT

- **Not a blessed baseline.** `baseline.hvpatch.jsonl` still does not exist;
  this is a raw gate run, and the 90 failures include probes that may be
  legitimate lane exclusions (`dsrconstantpool` certainly is).
- **Not a regression signal for this session's work.** These are first
  measurements, with no prior kernel-lane run to compare against.
- **Not the full suite.** This is the line-exact probe gate only — not LTP, not
  the language ecosystems, and not the `amd64` lanes (which hvpatch cannot
  run).

## Next

1. Exclude the probes that are meaningless on this lane, then bless
   `baseline.hvpatch.jsonl` from the remainder — that is KP's stated gate and
   the thing every later claim needs.
2. Take the signal cluster first. It is the largest, its members share one root
   cause class, and that root cause is the same one-host-process identity
   problem the per-task accounting fixes already solved twice — so there is a
   worked pattern to follow.
3. Re-run this gate on the kernel lane, not the native one, whenever a change
   touches the kernel lane. Every probe-gate receipt in this tree before today
   is a native-lane receipt.
