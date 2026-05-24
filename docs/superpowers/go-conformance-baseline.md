# Go conformance baseline (T2) — carrick vs Docker linux/arm64

Date: 2026-05-24. Tool: `scripts/go-conformance.sh`. carrick build: EL1-kick +
FP + ExecLevel commits. Args: `-test.run 'Test' -test.short -test.v`.

## Per-package tally (carrick-only failures = PASS on Docker, not on carrick)

| package | docker PASS | carrick PASS | carrick-only result |
|---|---|---|---|
| `sync` | 47 | 46 | 1: `TestMutexMisuse` → pidfd/os-exec |
| `sync/atomic` | 95 | 86 | CRASH at `TestNilDeref` (EL0 fault `esr=0x9200000e far=0x0` not delivered as SIGSEGV); +9 absent (cascade, not real) |
| `context` | 38 | 38 | **clean match** ✓ |
| `time` | 0 | 0 | no `Test*` in `-test.short` (non-signal) |
| `os/signal` | 18 | 15 | 3: `TestAtomicStop`, `TestDetectNohup` (pidfd re-exec), `TestNotifyContextNotifications` (possible real notify gap), `TestTerminalSignal` (pidfd "function not implemented") |
| `os/exec` | 36 | 35 | 1: `TestString` → raw-rootfs PATH has no real `echo` executable |

## Two dominant root causes

1. **pidfd / subprocess spawn** (`pidfd_open(434)` / `CLONE_PIDFD` → ENOSYS):
   accounts for `os/exec` (26), `sync` `TestMutexMisuse`, and most of
   `os/signal`. Fix = SP2b (pidfd backed by host kqueue `EVFILT_PROC`).
2. **Synchronous EL0 fault → guest signal** not implemented: carrick kills the
   guest on a guest bad memory access instead of injecting SIGSEGV/SIGBUS with
   `si_addr=FAR`. `TestNilDeref` (nil deref, `far=0x0`) is the clear case.
   Go's nil-deref→panic→recover is a core idiom, so this likely blocks large
   parts of the unmeasured `runtime`/`net` suites. Fix = SP2a (EL0 fault →
   guest signal).

## Prioritization

SP2a (fault→SIGSEGV) and SP2b (pidfd) are the capability phase. SP2a is a
*crash* and a core Go idiom (and self-contained); SP2b clears the most test
count. Both precede SP3 (loader) and SP4 (drive-to-zero + runtime/net + T3).

`runtime` and `net` not yet tallied (slow; expected to be dominated by the same
two gaps — will re-run after SP2a/SP2b).

## Progress update

- **SP2a (EL0 fault → SIGSEGV/SIGBUS): DONE** (commit `feat(signal): deliver
  synchronous EL0 faults…`). `sync/atomic` 86→**95/95** (TestNilDeref crash +
  9-test cascade cleared); `segv-recover` probe → `SEGV_OK`.
- **SP2b (pidfd): precise finding.** Go 1.24 `os/exec` `forkExec` aborts in the
  PARENT at `pidfd_open(434)` → ENOSYS, **before any `clone`/fork** (trace: no
  `fork-post`, no `execve`; only `[parent] ENOSYS nr=434` + `nr=293 rseq`). So
  `pidfd_open` must succeed (return a real pollable fd) for Go to proceed to
  `clone(CLONE_PIDFD)`. Also `rseq(293)` ENOSYS (Go 1.24 enables rseq; likely
  tolerated, verify). Fix = kqueue-`EVFILT_PROC`-backed pidfd (see SP2b plan).
- **os/exec waitid stop-state bug: DONE** (2026-05-24). `TestWaitid` exposed a
  Darwin adaptation mismatch: host `waitid(P_PID, child, WEXITED|WNOWAIT)`
  reports a SIGSTOPped child even though Linux would not. Carrick now filters
  host `siginfo_t` states against the guest's requested `W*` bits before
  returning waitable status. Focused Go `TestWaitid` passes; full
  `scripts/go-conformance.sh os/exec` is **35/36** with only `TestString`
  remaining, because the raw seeded rootfs has no real `/usr/bin/echo`.
