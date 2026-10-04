# Host lease supervision and containment follow-up

The lease supervisor owns flock; arbitrary commands, tests and guests own zero
flock descriptors. Caller exit and supervisor SIGTERM/SIGINT/SIGHUP request
cancellation. The supervisor cancels and observes supervised work exiting,
reaps its children, observes lifetime EOF, and only then releases exclusion.
The existing direct `try_exclusive` still performs a zero-wait flock attempt.

Linux uses a dedicated child subreaper. Detached descendants remain owned even
after `setsid` and closing every inherited descriptor. Darwin selects members
by the workload session or the exact kernel scope-pipe identity. Cancellation
issues SIGKILL without first stopping processes. An EPERM helper keeps running
while exit observation and cleanup remain active and exclusion stays held.
Permission to signal is independent of permission to reap an adopted child.

## Explicit limits

- **Sole supervisor SIGKILL:** the kernel closes its descriptors and releases
  flock. Work can survive it. `supervisor_sigkill_cannot_preserve_exclusion` is
  an ignored regression that deliberately fails when explicitly invoked on
  either platform. A normal runner's SIGKILL is covered; it is a different
  process from the flock owner.
- **Darwin detached close-all-fds descendants:** leaving the session and closing
  every inherited scope descriptor removes both membership proofs.
  `detached_closed_scope_descendant_is_cancelled` deliberately fails on Darwin
  when explicitly invoked with `--ignored`; it runs normally and passes on
  Linux. The fixture closes every duplicate, not just the advertised writer.
- **Darwin PID reuse:** every signal rechecks the kernel unique process ID and,
  when readable, `(pid, start seconds, start microseconds)` from
  `PROC_PIDTBSDINFO`. Root-owned helpers deny that full query; UID-independent
  unique-ID and short-BSD status queries preserve observation across UID changes.
  The native layout and permission rules are qualified against
  [Apple's process-info API](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h)
  and [implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c).
  Exit watches register on the selected
  process and are authenticated again after registration. Reaping compares the
  same incarnation; it never waits on a replacement using `kill(pid, 0)`.
  Deterministic model tests cover exit, reap and reuse before each signal check.
  There is still a window **after the final successful proc_pidinfo comparison
  and before PID-only kill acquires the kernel process reference**. A process
  exiting and its PID being reused in that window can cause a wrong signal.
  Start-time comparison is not atomic signaling or full crash containment.

These limits are part of the CLI/recipe help and the native contract. This PR
does not claim to contain arbitrary host process trees or survive flock-owner
SIGKILL. Ignored failures document missing guarantees; they confer no acceptance.

## Follow-up design

Before broadening the contract, establish kernel-backed membership independent
of file descriptors, sessions, argv and working directory. A periodic process
census cannot recover a descendant whose short-lived parent was already reaped.

For Linux, evaluate a delegated per-run cgroup v2 with atomic membership
assignment before exec, recursive `cgroup.kill`, and `cgroup.events` population
closure. Preserve subreaping for wait statuses and require empty membership
before release. Reject admission when delegation is unavailable.

For Darwin, qualify a kernel lineage/containment facility or an entitled
EndpointSecurity fork/exec/exit authority before implementation. Track process
incarnations from birth, fail closed on event gaps, and use an incarnation-aware
native signaling API. The SDK declares `proc_signal_with_audittoken`; integrating
it needs a maintained libc binding, qualified token acquisition, platform
availability checks, and native red-first tests. A start-time check followed by
kill cannot replace that atomic operation.

Move flock ownership into independent guardians, with an explicit fault model:
at least one dedicated holder survives any single supervised process failure.
Guardians must receive durable membership and exit evidence before admission,
retain exclusion while recovering a dead worker/supervisor, and never pass
flock into the workload. Test SIGKILL of each actual holder independently, loss
of cleanup privilege, descriptor closure, reparenting and PID reuse. If all
holders die, kernel flock cannot remain held: stronger recovery needs durable
admission state checked by every participant, including Docker, before work.
Privileged containment/service installation is a separate reviewed change.
