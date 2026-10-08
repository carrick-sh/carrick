# Host lease supervision and containment follow-up

On macOS the supervisor and an independent guardian share flock custody;
arbitrary commands, tests and guests own zero
flock descriptors. Caller exit and supervisor SIGTERM/SIGINT/SIGHUP request
cancellation. The supervisor cancels and observes supervised work exiting,
reaps its children, observes lifetime EOF, and only then releases exclusion on success. Cleanup failure releases with a
reported failed-run error under the bounded policy below. If the supervisor
fails cleanup, its guardian retains custody while recovering the workload.
The existing direct `try_exclusive` still performs a zero-wait flock attempt.

Linux uses a dedicated child subreaper. With child-list support, detached descendants remain owned even
after `setsid` and closing every inherited descriptor. Darwin selects members
by the workload session or the exact kernel scope-pipe identity. Cancellation
issues SIGKILL without first stopping processes. An EPERM helper keeps running
while exit observation and cleanup remain active within the single deadline.
Permission to signal is independent of permission to reap an adopted child.

## Explicit limits

- **macOS single-custodian SIGKILL:** supervisor and guardian share the locked
  description with last-close release authority. Guardian readiness and the
  supervisor's guardian-exit watch precede workload admission. A child-specific
  pre-exec handshake registers the workload session before user code can fork
  or close its scope writer. The guardian
  watches supervisor exit and the finish channel; the supervisor watches
  guardian exit. Either survivor cancels scope members and confirms their
  exit/reaping before dropping custody. Both single-holder SIGKILL cases are
  active deterministic regressions. Commands inherit no raw flock fd.
- **Loss of all custodians:** killing both macOS holders releases flock. Linux
  retains the sole-supervisor limitation. An ordinary runner is a proxy, not
  a custodian. No user-space watcher can survive its own SIGKILL.
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
  Queries request zombie entries explicitly: NOTE_EXIT certifies exit, and
  `exited_child_is_not_reaped_until_waitpid` requires a child's identity to stay
  present until its parent's actual wait/reap.
  Deterministic model tests cover exit, reap and reuse before each signal check.
  There is still a window **after the final successful proc_pidinfo comparison
  and before PID-only kill acquires the kernel process reference**. A process
  exiting and its PID being reused in that window can cause a wrong signal.
  Start-time comparison is not atomic signaling or full crash containment.

These limits are part of the CLI/recipe help and the native contract. Single
macOS custodian failure is covered; arbitrary process trees and simultaneous
loss of all custodians are not. Ignored failures confer no acceptance.

## Bounded cleanup failure

Cleanup has one five-second deadline across cancellation, worker and descendant
reaping, and scope EOF. Interrupted native observations resume the same syscall under the unchanged
deadline, preserving exit authority across SIGCHLD. Permanent I/O errors return immediately; pending exit
and reaping observations must finish within that deadline. A typed
`HostLeaseError::Cleanup` reports the operation and cause, explicitly marks the
run failed. On macOS, supervisor failure leaves custody with the guardian
through its recovery cleanup; final custodian failure releases the lease. Failure is not acceptance or a promise that
unkillable work has stopped. The supervisor must not wedge the host indefinitely.
Linux subreaper `waitpid(-1)` through `ECHILD` is release authority; procfs child
lists only help cancel live adopted roots and are optional. Without those lists,
an undiscoverable live detached child may cause the bounded failed-run state.
The containment follow-up below remains necessary for stronger guarantees.

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

The macOS implementation now uses cooperating supervisor/guardian custody.
For stronger containment and other hosts, extend this explicit fault model:
at least one dedicated holder survives any single supervised process failure.
Guardians must receive durable membership and exit evidence before admission,
retain exclusion while recovering a dead worker/supervisor, and never pass
flock into the workload. Test SIGKILL of each actual holder independently, loss
of cleanup privilege, descriptor closure, reparenting and PID reuse. If all
holders die, kernel flock cannot remain held: stronger recovery needs durable
admission state checked by every participant, including Docker, before work.
Privileged containment/service installation is a separate reviewed change.
