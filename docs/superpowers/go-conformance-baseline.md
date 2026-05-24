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
| `os/exec` | 36 | 10 | 26: all subprocess-spawn tests → pidfd |

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
