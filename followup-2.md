# follow-up: pidfd_open (434) is a counted ENOSYS on ARM ring

**Labels:** follow-up, conformance

On the production ARM entry (`ProductionProcessHarness`), `pidfd_open(getpid(), 0)` returns -38. Linux 5.3+ serves it,
and the host dispatcher has a handler (`proc::pidfd_open`), but `docs/design/arm-ring-first-flip.tsv` lists 434, 424
(`pidfd_send_signal`) and `waitid(P_PIDFD)` as Host-only/Counted-ENOSYS. Go 1.23's `os.checkPidfd` probes
`pidfd_open`, `waitid(P_PIDFD)`, `pidfd_send_signal` and `clone(CLONE_PIDFD)` and falls back to plain pids, so this is
not a stop for the Go rows. It is still a guest-visible gap: Go processes, systemd-style supervisors and Python 3.9+
`os.pidfd_open` take their fallbacks or fail.

Acceptance: pidfd_open / pidfd_send_signal / waitid(P_PIDFD) and clone(CLONE_PIDFD) served in ring for native tasks,
with a red-first contract against the Docker oracle (Go's `checkPidfd` sequence is a good witness).
