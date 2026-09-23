# Syscall context borrowing: rejected

The context-borrow candidate reduces measured exact context retention, but does
not improve original `inotify09` or its watch-only controls. The candidate,
instrumentation, test feature change, and new contract registration were removed.
The exact signed baseline is restored. No new product speedup is claimed.

## Decision and original workload

One baseline and one candidate warmup preceded the measured ABBA / BAAB sequence.
Each invocation ran the unmodified LTP20260529 `inotify09` command through
`/bin/sh -c`, on the same pinned native ARM64 image and host filesystem mode.
The 40-second completion bound was unchanged. No builds or Docker workloads ran
alongside the Carrick measurements. The three Linux runs followed all Carrick
runs. Every full-workload invocation reported TPASS and reached the execution
loop limit; the adaptive spin work is not a fixed instruction population.

| Arm | Measured elapsed seconds | Median |
|---|---|---|
| Baseline | 21.88, 21.89, 21.91, 21.72 | 21.885 s |
| Candidate | 22.10, 22.29, 21.69, 21.93 | 22.015 s |
| Native ARM64 Linux | 6.05, 5.98, 5.98 | 5.980 s |

Candidate median elapsed time is **0.594% higher**, with overlapping samples.
The first balanced block is 1.416% slower; the second is effectively tied
(0.023% lower). This fails the predeclared requirement of at least 1% lower
median elapsed time and improvement in both balanced blocks. The data do not
establish a repeatable regression either; they reject a useful gain.

Raw Linux ratios are baseline **3.660x**, candidate **3.681x**. The different
ratio from the previous 3.80x receipt reflects a different fresh Linux time,
not a newly improved Carrick baseline. Native macOS I/O and Docker bind-path
controls remain separate in [the preceding experiment](../seek-header/README.md);
none of those medians were subtracted from this workload.

## What was changed and proved

The runtime captured a fresh `KernelContext`, retained it into the service
owner, retained it for the completion token, and retained it again for dispatch.
The candidate moved the captured context into the service owner and borrowed it
during dispatch. The completion token still owned its exact captured generation.
There was no cross-syscall cache, registry recapture on redispatch, or change to
signal, MM authority, observer, or syscall-result policy.

The archived `kernel.syscall.context-retention` contract exercised the real
runtime service and completion path through the VM-free carrier fixture, with
invalid `inotify_rm_watch` returning EBADF. Both the ordinary and redispatch
cases retained exact pid/tid/task/container completion identity and exactly one
entry observation and completion per logical syscall.

| Work per scale N | Before | Candidate |
|---|---:|---:|
| Exact context retains, ordinary call | 3N | N |
| Exact context retains, one explicit redispatch | 4N | N |
| Logical kernel dispatches | N | N |

Scales were 1, 8, 32, 128. The final red run failed the structural budget;
the green run passed all scales with no dropped or unknown metrics.
The first test invocation exposed a contract registration omission, corrected
before the true red receipt; it is retained as `registration-check.log` and
is not the structural red proof.

The focused runtime completion/interception/redispatch/exec suite passed
33 tests. Four existing opt-in cost diagnostics were ignored; these were not
semantic skips. Contract registry validation passed. The signed performance
build's normal dependency closure has no `conformance-metrics` or
`test-support` features. Work counters were compiled out for timing.

The earlier completed census established 3M add-watch and 3M remove-watch host
services. The production service probe is entered in this runtime dispatch
path, so this candidate addressed that common path. Frequency alone did not
predict the effect of removing the copies. No new instrumented timing claim is
made, and shell-wrapper JSON trap counts are not used as the full population.

## Watch-only controls

These ran separately in ABBA order, two independent processes per arm.
Each process's reported value summarizes 21 internal samples; the table is
the median of the two process summaries, not 42 independent trials.

| Phase | Baseline ns/pair | Candidate ns/pair |
|---|---:|---:|
| Invalid pair, scale 65536 | 3202.5 | 3201.0 |
| Unchanged pair, scale 65536 | 3689.5 | 3677.5 |
| Empty batch, scale 128 | 3543.0 | 3522.0 |
| Growing queue, scale 8192 | 3542.5 | 3548.0 |
| Overflow, scale 65536 | 3544.0 | 3543.5 |

There is no repeatable material improvement here either. The additional serial
`contract-scale 128` phase completed in every microcontrol invocation; it is
not the original concurrent LTP workload. Probe executable SHA-256:
`4c37f0a5cf6acecd055263d40adf1a7def332f9a889259d22cd06c572931fb3d`.

## Scope and receipts

Source HEAD: `9bb2392396b8531e93f5262657bf3aa9c5767488`, with the existing campaign
changes preserved. Source snapshots and frozen executables are under
`target/lease-cost/context-borrow/` in this worktree.

- Baseline SHA-256: `1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918`.
- Candidate SHA-256: `d0ccb5d7b7f5a2b86afa91121ee6f66631a0c3351e1590bde72ea145fa748b62`.
- [Candidate identity](candidate-artifact.json) records CDHash, LC_UUID, signature,
  entitlement, DOF presence, product features, and build-log hash.
- [Runs](runs.jsonl) retain commands, run IDs, raw output paths by run ID,
  completion evidence, timings, and cleanup status.
- [Summary](summary.json), [plan](plan.json), [red](red-test.log),
  [green](green-test.log), and [rejected patch](rejected-candidate.patch).
- [Restoration](restoration.json) verifies all 9,747 preexisting file hashes
  before these evidence-document updates and the restored binary signature.

All run-scoped cleanup receipts contain zero Carrick survivors, or an empty
Docker container census. No commit, push, broad signed probe gate, smoke/full
promotion, or full CI claim is made. The candidate failed its workload gate,
so no higher-layer acceptance was attempted. The near-native goal remains open.

## Consequence for the next experiment

Do not pursue more context-copy tuning on recurrence alone. This removes two
of three measured copies and still leaves invalid watch-pair time essentially
unchanged. The next material target remains the syscall execution/transition
cost. Require a controlled reduction in that cost and improvement in original
completion time before expanding a native/DSR design. This experiment does not
demonstrate that any particular transition proposal will work.

