# Decoupling carrick from host facilities it should own: audit + ordered plan

Produced by a five-way fan-out over the guest-authority subsystems (resource
limits, process identity, signal delivery, reaping/lifecycle, netns/UTS) plus a
synthesis pass. Analysis only — no builds, no guests, no Docker, because a
conformance gate held the machine.

Raw output: `audits-and-plan.json` (5 audits, 9 batches, 10 shared prerequisites).

## The surface, counted

**119 call sites classified**: 81 `wrong-domain`, 24 `legitimate-host-io`,
14 `needs-investigation`.

The 24 legitimate ones matter as much as the 81. `raise_host_nofile_backing`
(`time.rs:998/1021`), the carrick-cli startup raise (`main.rs:326`) and
`inherited_fd_scan_limit` (`file_authority/ipc.rs:368`) size CARRICK's own
descriptor budget — carrick really does hold a real Darwin fd per guest fd, so
the host IS the authority there. An agent that "cleaned those up" would make
things worse; they are named exemptions in the proposed lint.

## What the audit found that the earlier hand audit did not

- **`prlimit64(other, …)` corrupts the CALLER too.** It writes
  `this.proc.lock()`, so the parent's own soft NOFILE drops 43 -> 42 while the
  target is untouched. Linux leaves the parent alone. The parent's next `open`
  can then EMFILE at fd 42.
- **`/proc/self/limits` is a compile-time literal** (`vfs/proc.rs:4052`) that
  contradicts `getrlimit(2)` on four resources BEFORE any `setrlimit`: core 0 vs
  RLIM_INFINITY (carrick does dump), locked memory 65536 vs infinity (so a guest
  believes it may `mlock` only 64 KiB), pending signals, and processes.
- **Three files give three different answers for "max processes"** — the frozen
  literal, `getrlimit(RLIMIT_NPROC)` from the Mac user's shell
  (`vfs/proc.rs:509`, order 2000-4000 where Docker reports ~63087, and it varies
  by login shell so it is not even reproducible), and `NOFILE_DEFAULT`.
- **`Zombie` already carries `process_group` and `session` and is never
  consulted**, so `getpgid`/`getsid` on an exited-but-unreaped child returns
  ESRCH where Linux answers.
- **`self_ns_pid()` is the linchpin** — one function, starting from
  `std::process::id()`, feeding the identity of everything downstream.
- **`SIOC*` has no network-mode gate at all.**

## The warning worth repeating

> Every existing rlimit probe (`rlimitnofile`, `rlimitroundtrip`,
> `rlimitresource`, `nofiledefault`) is single-process and all four PASS today
> with the bug in place. Do NOT accept them, or `just ci`, as evidence.

That is the same lesson this campaign keeps re-learning: with ONE live guest
process the carrier pid, the root task id and `getuid()` coincide, so the whole
class is invisible. Every batch's verification is specified as two (or three)
live guest processes.

## Ordering

**Batch 1 lands ALONE and first**: four of the five subsystems need a new field
on `Task`, `Zombie` or `Session`, and all of those land in the same struct-field
hunk of a 4,775-line file. It is also host-only — no guest, no HVF — so it is the
one batch that can land while a gate occupies the machine.

Then, by evidence rank (recorded failing row > verified live wrong value > silent
hang > reasoned-from-code > deletion debt):

| order | batch | parallel with |
|---|---|---|
| 1 | kernel-graph foundations | — (alone) |
| 2 | rlimits as task state | netns object+view |
| 3 | process identity + UTS | — (owns every contended file) |
| 4 | signal delivery unification | — |
| 5 | controlling terminal / job control | — |
| 6 | reaping fidelity | netns consumers + resolver policy |
| 7 | retire host transports, close the lint | — (deletion only) |

The final batch is a DELETION batch whose success criterion is that nothing
moves: the same verdicts as the preceding run, with the replaced paths gone.

## The enforcement that stops recurrence

`Authority { Guest, Host, Hybrid }` on `Syscall`, plus `just lint-domains` rules
with a FULL monotonic baseline: a `Guest`-authority dispatch path may not name
`std::process::id`, `libc::get{pid,ppid,pgrp,sid,uid,gid}`, `libc::kill`,
`libc::wait*`, `libc::getrlimit/setrlimit`, `libc::tc{get,set}pgrp`,
`libc::getifaddrs`, `libc::gethostname`, or `crate::namespace::pid`. Legitimately
carrier-scoped uses call a NAMED `carrier_pid()` the lint allows, so an exemption
is a declaration rather than an omission — and the baseline fails both on a new
finding AND on an entry that stops matching, so the file can only shrink.
