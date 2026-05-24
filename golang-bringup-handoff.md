# Handoff — Go runtime bring-up on carrick (2026-05-24)

## Current state

Default Go bring-up is now reliable for the validated oracle on this macOS host:
the signed Carrick binary runs the multithreaded Go HTTP fixture
(`fixtures/go-aarch64-hello`: server goroutine + client + graceful shutdown;
clone/futex/epoll-netpoller/loopback TCP/SIGURG preemption) at
`-benchmark -c 50 -n 300` for 20/20 clean runs.

Do **not** generalize that to every possible guest CPU exposure. Forcing
`CARRICK_EXPOSED_CPUS=10` still reproduces the high-P progress stall, so full
host-logical CPU stress remains an open issue. The durable default on this Apple
Silicon machine is to expose the Darwin performance cluster count:

- `hw.logicalcpu: 10`
- `hw.ncpu: 10`
- `hw.physicalcpu: 10`
- `hw.perflevel0.name: Performance`
- `hw.perflevel0.logicalcpu: 4`
- `hw.perflevel1.name: Efficiency`
- `hw.perflevel1.logicalcpu: 6`

Validated current results:

- Native macOS Go baseline is clean: `go version go1.26.2 darwin/arm64`;
  rebuilding `fixtures/go-aarch64-hello/src/main.go` natively and running
  `-benchmark -c 50 -n 300` passed 10/10.
- Carrick default Go c50 on the current tree is clean: 10/10.
- `CARRICK_EXPOSED_CPUS=10` on the current tree is still not clean:
  6/10 clean, 2 client deadline panics, 2 timeout/kills.
- `CARRICK_EXPOSED_CPUS=10 GODEBUG=asyncpreemptoff=1` on the current tree is
  clean: 10/10.
- `CARRICK_EXPOSED_CPUS=10 GOGC=off` still failed earlier: 11/20 clean, 9
  deadline panics, 0 timeouts. GC is visible in schedtrace failures, but
  disabling GC is not a fix.
- A minimal `carrick trace` script (`scripts/trace-go-missed-event.d`) catches
  the failing path without broad syscall tracing overhead. In a failing run it
  showed one epoll kqueue wait timing out while a different tid absorbed 412
  `SIGURG` publish/deliver cycles; the hottest interrupted PCs were inside Go's
  runtime syscall wrappers (`runtime.futex.abi0`, `runtime.osyield.abi0`,
  `runtime.nanotime1.abi0`).

## What changed in this continuation

- `64e742b fix(epoll): poll backing kqueue waits`
  - `epoll_pwait` no-ready handoff is now `WaitOnPollFds` on the epoll
    instance kqueue fd. The runtime services it with `poll(2)`, not the
    per-thread kqueue.
  - Reason: polling a kqueue fd observes readability without draining events;
    calling `kevent()` in the runtime would consume events before the
    re-dispatched `epoll_pwait` can copy them to the guest.
- `db27f5c fix(signal): use fixed sigreturn trampoline`
  - Added a read/execute user trampoline for `rt_sigreturn` containing
    `mov x8, #139; svc #0`.
  - `inject_signal` now uses that trampoline when the guest did not provide a
    real `sa_restorer`, instead of writing executable code into the signal frame
    on the guest stack.
- Follow-up sigreturn relocation
  - The first fixed trampoline address, `0x200000`, overlapped small static
    ET_EXEC fixtures. The trampoline is now at `0x30_0000_0000`, above the PIE
    default base and below Carrick's heap/mmap arenas.
  - `/proc/self/maps` labels it `[carrick-sigreturn]`.
- `cd7b1b0 fix(hvf): avoid remapping shared VM regions for threads`
  - Thread siblings now copy local mapping metadata only. The sibling vCPU is
    created in the same Hypervisor.framework VM, so stage-2 mappings are
    already VM-global and should not be reissued per vCPU.
- Thread-directed signal wake hardening
  - Thread-directed guest signals now wake a per-thread pipe watched only by the
    target waiter. The process-wide async-safe self-pipe remains for
    process-directed signals.
  - This closes the first-principles lost-wake hole where a non-target waiter
    could drain the shared pipe before the target waiter observed it. It did not
    eliminate the forced-10-CPU Go stall.
- Signal-mask fidelity
  - Thread-directed sibling signals that target a thread with that signal
    currently blocked now queue directly in Carrick's per-thread pending set
    instead of immediately kicking the target.
  - Carrick now saves the target thread's previous guest signal mask in the
    sigframe `ucontext`, installs the handler-time blocked mask before
    injection, and restores that saved mask on `rt_sigreturn`.
- Darwin CPU surface hardening
  - `host_facts::logical_cpu_count()` now selects `hw.perflevel0.logicalcpu` on
    macOS when present, capped by total logical CPUs. `CARRICK_EXPOSED_CPUS`
    overrides the default for differential runs.
  - `/proc/cpuinfo`, `/sys/devices/system/cpu/*`, and `sched_getaffinity` tests
    now derive expectations from the same Linux-visible CPU count.
- Trace scripts
  - `70b1a76` added `scripts/trace-go-futex.d` and `scripts/trace-go-signal.d`.
  - `d09005e` added `scripts/trace-go-net.d`.
  - `4c783cc` made the futex trace bounded and raised DTrace buffers.
  - `scripts/trace-go-missed-event.d` is the current lightweight trace for the
    residual race: only Carrick USDT epoll/signal/io-wait probes, no broad
    syscall-entry/return coverage.

## Verification run this continuation

- `sudo -n -l` verified NOPASSWD coverage for Carrick/project helper paths and
  selected tracing tools. `sudo -n /usr/sbin/dtrace -V` and
  `sudo -n target/release/carrick --version` both worked.
- `cargo test --release memory::loader_tests::linux_runtime_regions_include_fixed_user_sigreturn_trampoline --lib -- --exact --nocapture`
  passed.
- `cargo test --release host_facts --lib -- --nocapture` passed: 4 tests.
- `cargo test --release host_signal --lib -- --nocapture` passed: 6 tests.
- `cargo test --release io_wait --lib -- --nocapture` passed: 1 test.
- `cargo test --release --test syscall_creds scheduler_bootstrap_yields_and_writes_current_affinity -- --exact --nocapture`
  passed.
- `cargo test --release --test syscall_fs synthetic_sys_surface_serves_common_cpu_and_mm_files -- --exact --nocapture`
  passed.
- `cargo test --release --test io_wait -- --nocapture` passed: 2 tests.
- `cargo test --release --test syscall_net -- --test-threads=1 --nocapture`
  passed: 25 tests.
- `cargo test --release --test syscall_thread -- --nocapture` passed: 15 tests.
- `cargo test --release --test syscall_signal -- --nocapture` passed: 4 tests.
- `./scripts/build-signed.sh` passed after the latest cargo test rebuilds.
- Static scheduler fixture:
  `target/release/carrick run-elf --raw --fs host fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-scheduler`
  printed `scheduler`.
- CLI scheduler fixture:
  `cargo test --release --test cli run_elf_command_drives_scheduler_static_fixture -- --exact --nocapture`
  passed before the final test rebuild; re-sign before using `target/release/carrick`
  for HVF runs.
- Native macOS Go c50: 10/10 clean.
- Carrick default Go c50 on the current tree: 10/10 clean.
- Carrick `CARRICK_EXPOSED_CPUS=10` Go c50 on the current tree: 6/10 clean,
  2 deadline panics, 2 timeout/kills.
- Carrick `CARRICK_EXPOSED_CPUS=10 GODEBUG=asyncpreemptoff=1` Go c50 on the
  current tree: 10/10 clean.
- Carrick `CARRICK_EXPOSED_CPUS=10 GOGC=off` Go c50 earlier: 11/20 clean,
  9 deadline panics, 0 timeouts.
- Carrick `CARRICK_EXPOSED_CPUS=10 GOMAXPROCS=4` Go c50 earlier: 19/20 clean,
  1 deadline panic, 0 timeouts.

## Darwin/macOS and FreeBSD leverage

FreeBSD's Linuxulator is the right comparison point for the epoll/kqueue shape:

- `epoll_create_common` creates a real kqueue via `kern_kqueue`.
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L103-L138>
- `linux_epoll_ctl` translates Linux epoll interests into kqueue filters
  (`EVFILT_READ`/`EVFILT_WRITE`, plus flags such as `EV_CLEAR`).
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L282-L355>
- `linux_epoll_wait_ts` waits by calling into kevent on that kqueue.
  <https://github.com/freebsd/freebsd-src/blob/main/sys/compat/linux/linux_event.c#L369-L428>
- FreeBSD also makes kqueue fds poll/read-ready when queued events exist.
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

For CPU exposure, the Darwin leverage is `sysctl` topology, not a hardcoded
Linux fiction. On this host, exposing `hw.perflevel0.logicalcpu` gives Go a
stable default. Go 1.26.2's Linux runtime computes its default CPU count from
the `sched_getaffinity` population count (`runtime/os_linux.go:getCPUCount`),
so Carrick's Linux-visible affinity mask is the surface that directly drives
default `GOMAXPROCS`.

## Open blocker

The remaining blocker is forced high-P progress with `CARRICK_EXPOSED_CPUS=10`.
The old stack-resident sigreturn crash is fixed, the shared waiter-pipe
lost-wake hole is fixed, pending host-backed epoll events are now preserved
across `maxevents`, and the handler-time guest signal mask is now saved and
restored. High-P still produces deadline failures and timeouts.

The strongest current diagnosis is: async preemption is still implicated, but
not in the original "signal delivery is completely broken" way. On the current
tree:

- `asyncpreemptoff=1` makes the 10-CPU oracle clean.
- lightweight `carrick trace` still catches a failing run.
- in that failing trace, one thread receives a large `SIGURG` storm while a
  different thread times out waiting on the epoll kqueue fd.

That points to a remaining race or semantic mismatch in the async-preemption
path or in how that path interacts with Go's scheduler/runtime state, not a
plain missed epoll event.

Next best path:

- Keep using `scripts/trace-go-missed-event.d` for low-perturbation failing
  samples; the broader syscall aggregators are too heavy for this race.
- Correlate the hot `SIGURG` target tid with its interrupted PCs and Go runtime
  state. The current failure signature is a thread stuck in repeated preemption
  around `runtime.futex.abi0` / `runtime.osyield.abi0` / `runtime.nanotime1.abi0`.
- Reduce the workload toward a loopback netpoll + timer/deadline fixture that
  keeps `GOMAXPROCS=10` but removes HTTP and JSON.
- Keep the default CPU surface at the validated Darwin performance-cluster count
  unless the high-P async-preemption interaction is fixed.

## Commands

Build and sign:

```sh
./scripts/build-signed.sh
```

Carrick default c50 oracle:

```sh
artifact="$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"
target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```

Forced high-P stress oracle:

```sh
CARRICK_EXPOSED_CPUS=10 \
  target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```

Native macOS baseline:

```sh
go build -o /tmp/carrick-go-native ./fixtures/go-aarch64-hello/src/main.go
/tmp/carrick-go-native -benchmark -c 50 -n 300
```

Schedtrace failure oracle:

```sh
CARRICK_EXPOSED_CPUS=10 GODEBUG=schedtrace=500,scheddetail=1 \
  target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```
