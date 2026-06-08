# signal-sender-pid — KVM si_pid regression lock

A static glibc aarch64 Linux binary that locks the dispatcher's siginfo-queue
`si_pid` path on the carrick KVM backend (Phase 2 / signal refactor, Task 2).

## What it does

1. Installs a `SIGUSR1` handler with `SA_SIGINFO`.
2. `kill(getpid(), SIGUSR1)` — a self-directed `kill(2)`.
3. In the handler, reads `siginfo->si_pid` and asserts it equals `getpid()` and
   is non-zero.
4. Prints `si_pid=<pid> getpid=<pid>` (for the trace) then `sender-pid-ok` and
   `exit(0)`.

## Why this proves something

glibc lowers `kill(getpid(), SIGUSR1)` onto the `kill(2)` dispatcher arm, which
queues an `SI_USER` siginfo carrying the SENDER's pid (== this guest process).
The generic vCPU loop injects that exact siginfo into the handler's frame, so
the handler sees a correct, non-zero `si_pid`.

This is deliberately NOT the async `last_sender_for` path: KVM has no
host-signal pump yet (that is Task 7), so `last_sender_for` is correctly `0` on
KVM. The dispatcher siginfo queue is the path that carries identity for
guest-issued sends, and this fixture is its regression lock.

## Build / run

This needs glibc (`sigaction`/`printf`) and therefore the REAL dispatcher
(`carrick-kvm`), not the freestanding thin shim. It is built + run inside the
nested-KVM Lima guest by `scripts/kvm-smoke-lima.sh` (case 26), where an aarch64
Linux gcc + glibc exist:

```sh
gcc -static -O2 -o sender-pid sender-pid.c
carrick-kvm run-elf ./sender-pid   # stdout contains "sender-pid-ok", exit 0
```

`build.sh` performs that gcc build with whatever `gcc` (or `$CC`) is on PATH. On
macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest rather
than committed (the same reason the C-based signal cases in the smoke script are
gcc-compiled in-guest).
