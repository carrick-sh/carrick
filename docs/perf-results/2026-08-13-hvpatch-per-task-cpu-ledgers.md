# Per-task CPU accounting: taking `times`/`getrusage` off the host process

**Recorded 2026-08-13.** Closes the Linux divergence found by
[`2026-08-13-hvpatch-guest-vs-host-cost.md`](2026-08-13-hvpatch-guest-vs-host-cost.md),
whose Finding 2 was that carrick over-reported guest CPU by ~40% and attributed
a whole `go build` to the shell rather than to the compiler processes it forked.

## The divergence

Linux keeps two CPU ledgers per process: the process's own time
(`times`' `tms_utime`/`tms_stime`, `getrusage(RUSAGE_SELF)`) and the summed
time of its **reaped** children (`tms_cutime`/`tms_cstime`,
`getrusage(RUSAGE_CHILDREN)`). carrick sourced the first from
`crate::host_proc::self_resource_usage()` — `proc_pid_rusage`, the whole HOST
process — and the second from two process-global statics in
`carrick-host/src/guest_cpu.rs`.

Both were correct only while each Linux process was its own host process. The
HVPatch backend's entire premise is that they are not: all Linux processes are
threads of ONE host process. So `proc_pid_rusage` returns the summed CPU of
every guest process at once, and every guest reads that total as its own
`RUSAGE_SELF`.

This is precisely the failure mode `hybrid.md` names — Mach supplying *process*
semantics instead of serving as an execution HAL — and it is guest-visible, not
cosmetic: `make`, the shell's `time` builtin, and every benchmark harness
attribute work by reading the children ledger.

## Red first

`conformance-probes/src/bin/timeschildren.rs` forks a child that burns 300 ms
of CPU, reaps it, and reports only orderings and signs so it is line-exact
across machines of different speeds.

| assertion | Docker oracle | carrick hvpatch (before) | after |
| --- | --- | --- | --- |
| `times_children_nonzero` | true | **false** | true |
| `times_self_below_children` | true | **false** | true |
| `rusage_children_nonzero` | true | **false** | true |
| `rusage_self_delta_below_children` | true | **false** | true |

The child's entire burn was absent from the children ledger and charged to the
parent's SELF account.

## The fix — the kernel owns the ledgers

K1 had already built `TaskRusage` and given `Task` its `threads` and `children`
maps, but every construction site passed `TaskRusage::default()`: the slot
existed and was never filled. The accounting now lives on the kernel objects.

- `Thread` records the `guest_cpu` slot it runs on (`bind_own_cpu_slot`, bound
  at the syscall dispatch boundary — the one place that reliably runs ON the
  guest thread with its kernel object in hand). `guest_cpu` gained
  `this_thread_slot()` and `slot_us(slot)` so a slot can be read by a thread
  other than its owner.
- `Task::self_cpu_us()` totals its live threads plus `retain_exited_thread_cpu`,
  which folds a departing thread's CPU into the task in `retire_thread` before
  its slot is recycled.
- `Task::charge_reaped_child` is called from the **consuming** branch of the
  wait path only, so a `WNOHANG` poll or `WNOWAIT` peek cannot double-count.
- `Zombie` now carries `rusage` (the child's own CPU, for `wait4`'s `rusage`
  argument) and `children_rusage` separately, so a reaper can be charged the
  whole subtree via `total_charge_to_reaper()` — Linux folds a reaped child's
  `cutime` into its parent's — while `wait4` still reports the child alone.
- The vestigial `rusage: TaskRusage` parameter was deleted from
  `prepare_task_exit`, `prepare_task_exit_key`, `exit_task_key_eventually` and
  `Zombie::from_task` rather than left as a second, dead way to supply it.

## Verified end-to-end on the workload that exposed it

Cold `go build`, signed binary, `times` run in the guest shell after the build:

| | shell line | children line |
| --- | --- | --- |
| carrick before | `0m4.34s 0m1.43s` | zero |
| **carrick after** | `0m0.000000s 0m0.000000s` | **`0m2.090000s 0m0.000000s`** |
| Docker oracle | zero | `0m2.28s 0m0.24s` |

The shape now matches the oracle, and the impossible over-report is gone: the
guest previously claimed 5.98 CPU-s inside a host process that had spent 4.29,
and now reports 2.09 inside 4.21. Build result unchanged (`BUILD_OK`, exit 0).

Four sibling probes that exercise the same syscalls — `accounting`,
`timeextra`, `timeclock`, `waitidcputime` — report no new mismatches;
`timeclock`'s single `false` is `clock_gettime_process_cputime sec_positive`,
which the Docker oracle also reports false, so it MATCHES.

## Known remaining gap, stated rather than papered over

**Per-task SYSTEM time is reported as zero.** carrick does not yet split system
time per task, and the honest options were zero or a host number that belongs
to every guest process at once. Docker reports `0m0.24s` of children system
time on this build where carrick reports `0m0.000000s`. The probe does not
catch it because it sums user and system; closing it needs per-task system-time
accounting at the syscall boundary, which is separate work.

`ru_maxrss` and `ru_majflt` likewise remain host-sourced — they describe the
address space, which is not yet accounted per task.
