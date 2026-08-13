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

---

## Root cause of the signal cluster, found: forked guest processes have no pid

**Recorded the same day.** Reducing the signal cluster gave one shared symptom
across `siginfo`, `signals`, `killtarget`, `procsignalmask` and others:
**`kill(getpid(), sig)` returns ESRCH.**

The reduction:

```text
carrick hvpatch:   shell_pid=1   ppid=0   child_pid=52111
Docker:            shell_pid=1   ppid=0   child_pid=6
```

**The container init gets pid 1 correctly. A FORKED CHILD reports a HOST pid.**
`kill(getpid(), 0)` from that child then fails, because no host process has
that id — the guest is signalling a pid that does not exist.

`identity_pid()` (`dispatch/creds.rs`), which is what `getpid(2)` answers from,
reads `proc.virtual_pid` and falls back to `namespace::pid::self_ns_pid()`.
`virtual_pid` is set by `bind_hvpatch_process`
(`dispatch/mod.rs:2739`) — but it is **dispatcher state, and under this lane
ONE dispatcher serves every Linux process**. The init binds and gets its pid; a
forked child never does, falls through to `self_ns_pid()`, and reads the host
process that all 69 guest processes share.

This is the same failure mode as the two accounting bugs already fixed — an
identity the host process boundary used to supply for free, which the one-VM
design must now supply itself — and it is the third instance, which makes it a
pattern rather than a coincidence:

| symptom | authority that was wrong | fixed |
| --- | --- | --- |
| `times`/`getrusage` self vs children | `proc_pid_rusage` (host process) | `ad5845c56` |
| `stime` reported as zero | vCPU exec clock only sees guest execution | `f850336c5` |
| **forked child's `getpid`** | **`proc.virtual_pid` / host pid** | **open** |

**Why this gates the whole cluster.** The conformance harness runs each probe
as a CHILD of a `probeinit` shim, precisely so the process topology matches the
oracle's. So every probe in the gate runs in the topology where the pid is
wrong — which is why the same probe passes when run as the container command
and fails under the gate.

### What was fixed, and what it does not fix

`kill`'s self-target test compared the target against `std::process::id()` —
the HOST process — which under this lane can never match a guest's own Linux
pid. It now also accepts a target equal to `identity_pid()`, the same authority
`getpid(2)` answers from. Verified: `siginfo` goes from 0/5 to **5/5**, and
`killtarget`, `signals` and `procsignalmask` all improve, **when the probe is
the container's init**.

It does **not** move the gate, and the reason is exactly the bug above: in the
child topology `identity_pid()` itself returns a host pid, so there is nothing
correct for the self-test to match. **The fix is necessary and not sufficient**;
the pid authority has to be corrected first.

An attempt to route `identity_pid()` through the active kernel context's task
id was written and **reverted**: it did not change the observed child pid, and
this tree does not keep an unproven path that changes nothing measurable. The
next step is to find why the child's dispatch does not reach a bound kernel
context — not to add another fallback.

### The root, one level deeper: the kernel's id space is seeded from the HOST pid

Following the child's pid to its source settles it. Three observations from one
forked child on the kernel lane:

```text
$$ (getpid)              55234
/proc/self               1          <- wrong: says every process is init
/proc/self/stat field 1  55233
kill -0 1                ok         <- init IS reachable at pid 1
```

Host-magnitude, consecutive, and one apart. The allocator explains both:

```text
dispatch/mod.rs:2475   let observed_pid = i32::try_from(std::process::id())   <- HOST pid
kernel/core.rs:222     task_id: TaskId::for_root_bootstrap(observed_pid)
kernel/core.rs:546     IdRegistry::with_root(bootstrap.task_id)
kernel/registry.rs:31  let next = root.raw().checked_add(1)                   <- allocate from root+1
```

**The kernel's task-id registry is seeded from `std::process::id()`.** The root
task takes the host pid, and every guest process is allocated from `host_pid +
1` upward. Linux starts at 1 and hands out small sequential pids; carrick hands
out 55233, 55234, 55235.

The container init escapes it only because `virtual_pid` is separately forced
to 1 for the bootstrap process, which masks the problem for exactly one
process — the one most tests look at first.

**This is the fourth instance of one pattern, and it is the root of the other
three.** `times`/`getrusage`, `stime`, and the forked child's `getpid` were all
symptoms of the host process standing in for guest identity; this is that
substitution at the point where identity is CREATED. It is also why
`/proc/self` answers 1 for every process, which is a fifth symptom of the same
thing.

**The fix is to seed the kernel's id space at 1** — Linux's init is pid 1 — so
children get 2, 3, 4. It is a small change with a wide blast radius: task ids
feed pidfds, process groups, sessions, `/proc`, `wait4` and every signal
target, so it needs its own careful pass and its own gate run, not a
drive-by. It is the highest-value single fix available on this lane: it is
upstream of the largest failing cluster and of two clusters beyond it.
