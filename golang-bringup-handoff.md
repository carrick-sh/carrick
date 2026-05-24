# Handoff — Go runtime bring-up on carrick (2026-05-24)

## Current state

Do **not** treat Go bring-up as complete yet. A real multithreaded Go HTTP
fixture (`fixtures/go-aarch64-hello`: server goroutine + client + graceful
shutdown; clone/futex/epoll-netpoller/loopback TCP/SIGURG preemption) runs under
carrick, but the default high-concurrency path is still unreliable.

Validated current results:

- Native macOS Go baseline is clean: `go version go1.26.2 darwin/arm64`;
  rebuilding `fixtures/go-aarch64-hello/src/main.go` natively and running
  `-benchmark -c 50 -n 300` passed 10/10.
- Carrick signed build after the latest fixes: `./scripts/build-signed.sh`
  passed and produced `target/release/carrick`.
- Carrick default Go `-benchmark -c 50 -n 300` after the fixed sigreturn
  trampoline: 6/10 clean, 2 context-deadline panics, 2 timeout/kills.
- The prior handoff claim "zero corruption/EL0 faults" was false before this
  continuation. We reproduced EL0 faults at `elr=0x604...bfd0`, traced them to
  Carrick's stack-resident `rt_sigreturn` stub, and fixed that by moving
  sigreturn to a fixed user trampoline. The latest 10-run c50 sweep had no EL0
  faults, but the progress stall remains.
- `GODEBUG=schedtrace=500,scheddetail=1` still reproduces the remaining c50
  stall. One failing run showed `gomaxprocs=10`, `idleprocs=9`, `threads=15`,
  `runqueue=0` for several seconds before client deadlines fired; after panic
  and GC, the dump shows goroutines in GC assist/mark termination and many
  parked in `select`/`IO wait`.

## What changed in this continuation

- `64e742b fix(epoll): poll backing kqueue waits`
  - `epoll_pwait` no-ready handoff is now `WaitOnPollFds` on the epoll
    instance kqueue fd. The runtime services it with `poll(2)`, not the
    per-thread kqueue.
  - Reason: polling a kqueue fd observes readability without draining events;
    calling `kevent()` in the runtime would consume events before the
    re-dispatched `epoll_pwait` can copy them to the guest.
- `db27f5c fix(signal): use fixed sigreturn trampoline`
  - Adds a read/execute user trampoline at `0x200000` containing
    `mov x8, #139; svc #0`.
  - `inject_signal` now uses that trampoline when the guest did not provide a
    real `sa_restorer`, instead of writing executable code into the signal
    frame on the guest stack.
- `cd7b1b0 fix(hvf): avoid remapping shared VM regions for threads`
  - Thread siblings now copy local mapping metadata only. The sibling vCPU is
    created in the same Hypervisor.framework VM, so stage-2 mappings are
    already VM-global and should not be reissued per vCPU.
- `70b1a76 chore(trace): add focused Go bring-up scripts`
  - Adds `scripts/trace-go-futex.d` and `scripts/trace-go-signal.d`.

## Verification run this continuation

- `cargo test --release memory::loader_tests::linux_runtime_regions_include_fixed_user_sigreturn_trampoline --lib -- --exact --nocapture`
  passed.
- `cargo test --release trap::thread_sibling_tests --lib -- --nocapture`
  passed: 5 tests.
- `cargo test --release trap::memory_protection_tests --lib -- --nocapture`
  passed: 3 tests.
- `cargo test --release --test syscall_net -- --test-threads=1 --nocapture`
  passed: 24 tests.
- `cargo test --release --test io_wait -- --nocapture`
  passed: 2 tests.
- `./scripts/build-signed.sh` passed.
- `target/release/carrick run-elf --raw --fs host "$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello" -- -benchmark -c 50 -n 300`
  loop: 6/10 clean, 2 deadline panics, 2 timeout/kills.

## Darwin/macOS and FreeBSD leverage

FreeBSD's Linuxulator is the right comparison point for the epoll/kqueue shape:

- `epoll_create_common` creates a real kqueue via `kern_kqueue`.
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L103-L138>
- `linux_epoll_ctl` translates Linux epoll interests into kqueue filters
  (`EVFILT_READ`/`EVFILT_WRITE`, plus flags such as `EV_CLEAR`).
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L282-L355>
- `linux_epoll_wait_ts` waits by calling into kevent on that kqueue.
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L369-L428>
- FreeBSD also makes kqueue fds poll/read-ready when queued events exist
  (`kqueue_poll`/`kqueue_kqfilter` observe `kq_count`).
  <https://github.com/freebsd/freebsd-src/blob/main/sys/kern/kern_event.c#L406-L435>

Carrick cannot simply call `kevent()` in the runtime wait helper, because that
would drain the epoll instance before `epoll_pwait` gets a chance to translate
events back to Linux `struct epoll_event`. The useful Darwin leverage is:

- maintain the epoll instance as a persistent host kqueue;
- register fd readiness with native EVFILT filters at `epoll_ctl`;
- in the runtime, use `poll(2)` on the epoll kqueue fd only as a readiness
  sleep primitive;
- re-dispatch `epoll_pwait` to drain and translate the events.

This keeps the kernel as the readiness source of truth while preserving the
Linux epoll syscall boundary.

## Open blocker

The remaining blocker is the high-concurrency progress stall, not the
stack-resident sigreturn crash. Native macOS Go does not reproduce it, so this is
still Carrick-specific.

Next best path:

- Use `GODEBUG=schedtrace=500,scheddetail=1` and `scripts/trace-go-futex.d` on a
  failing c50 run to correlate Go's "one P not idle, runqueue empty" state with
  futex returns, epoll returns, and io wait wakeups.
- Reduce the workload toward a loopback netpoll + timer/deadline + GC-assist
  fixture. The full HTTP fixture is still useful as the oracle, but it is too
  broad for the final stall.
- Re-check whether guest-visible CPU count should remain host-logical-count
  (`sched_getaffinity` currently reports host logical CPUs, so Go defaults to
  `GOMAXPROCS=10` here) or whether Carrick should expose a smaller vCPU capacity
  until the runtime can support host-level concurrency reliably. This is a
  correctness/product decision, not a substitute for fixing the stall.

## Commands

Build:

```sh
./scripts/build-signed.sh
```

Carrick c50 oracle:

```sh
artifact="$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"
target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```

Native macOS baseline:

```sh
go build -o /tmp/carrick-go-native ./fixtures/go-aarch64-hello/src/main.go
/tmp/carrick-go-native -benchmark -c 50 -n 300
```

Schedtrace failure oracle:

```sh
GODEBUG=schedtrace=500,scheddetail=1 \
  target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```
