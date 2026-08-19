# `prlimit` on ANOTHER process silently sets the caller's own limit

The last `go-syscall` row, `TestPrlimitFileLimit`. Attributed, not fixed — the
fix is structural and is written down here rather than faked.

## What the test does

The parent starts a helper, waits for it to signal, then calls

    syscall.Prlimit(cmd.Process.Pid, syscall.RLIMIT_NOFILE, &lim, nil)

setting the CHILD's `RLIMIT_NOFILE` to a magic value, and the child then reports
what it sees. carrick's child reports the limit unchanged:

    helper2 rlimit is {1048575 1048576}
    helper2 cached rlimit is &{43 1048576}
    cached rlimit is 43, want 42

## Cause

`prlimit64` (`dispatch/time.rs`) validates that the target pid EXISTS and then
applies the new limit to

    this.proc.lock().rlimit_overrides

which is the CALLER's own per-process dispatcher state, whatever pid was named.
So `prlimit(child, …)` changes the parent and leaves the child untouched; the
existence check is the only part of the pid argument that does anything.

There is a second, quieter defect in the same block. The "is this me?" test is

    let self_pid = std::process::id() as i64;

with a comment saying "carrick's getpid returns the host pid". That was true
under the retired one-process-per-guest model. Under HVPatch every logical Linux
process is a thread of ONE carrier, so `std::process::id()` is the same value for
every guest process — `identity_pid()` is the guest-domain answer, and its own doc
warns about exactly this substitution. The code then mixes domains further by
consulting `guest_pid_is_live` (guest domain) and falling back to
`kill(pid, 0)` (host domain). This is the class
`docs/identity-and-scope-domains.md` catalogues, and it is invisible while only
one guest process exists.

## Why it is not fixed here

An rlimit is a property of a Linux PROCESS, but carrick stores it in
`self.proc`, reachable only by the thread running that process. Nothing else can
reach it, so cross-process `prlimit` cannot work by construction — no amount of
patching the pid check helps.

The fix is to give rlimits a home the kernel graph can address, keyed by
`TaskId`, the way credentials already are (`live_task_process_euid`). Each
process then consults that table instead of its private copy, and `prlimit`
writes the TARGET's entry. `ProcessRecord` is a fixed-size atomic record in the
shared process section, so the table needs sizing deliberately (16 resources x 2
u64 per record).

The narrow alternative — special-casing `RLIMIT_NOFILE` because that is what this
test uses — would turn the row green while leaving every other resource wrong,
and would leave the domain bug in place. Not done.

## Ranking

One row. It should be scheduled with the other identity/scope-domain work rather
than alone, since it shares a root cause with that audit and the same fix
(kernel-graph-owned, `TaskId`-keyed process state) closes several at once.
