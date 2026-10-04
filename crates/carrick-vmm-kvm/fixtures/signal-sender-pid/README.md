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

This glibc fixture belonged to the retired 1:1 aarch64 dispatcher driver.
It has no current acceptance binding. On native aarch64 Linux, its oracle
prints `sender-pid-ok` and exits 0:

```sh
gcc -static -O2 -o sender-pid sender-pid.c
./sender-pid
```

`build.sh` performs the gcc build using `gcc` (or `$CC`).
