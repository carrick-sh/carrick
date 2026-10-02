# Deterministic sigsuspend dispatch fixture

The failure is test-fixture interference, not evidence of a production lost
wake. `SyscallDispatcher::new()` uses `NullHostSignalBridge`, which suppresses
host plumbing but still reads `carrick-signal-linux`'s process-global pending
slots and xsignal ring. Parallel `ring_drain_*` tests enqueue SIGUSR1 for the
same host PID before draining it. During that interval, the suspend test's
otherwise empty guest graph sees host ingress and correctly returns EINTR.
The ring producer's mutex does not exclude this unrelated reader.

The fix supplies an explicit `NoHostSignalIngress` bridge only to this test.
Its sole expected operation reports no inbound host signals; every other host
signal operation panics. Kernel pending queues, temporary mask installation,
owned `WaitOnSignals` return, sibling publication and EINTR redispatch remain
real and retain their original assertions. No production code changes, sleeps,
retries, concurrency reductions or shared lock were added.

## Reproduction

On the pre-fix source, temporarily replace the first
`let outcome = bounded(&mut memory);` in this test with:

```rust
carrick_signal_linux::xsig::xsig_init();
assert!(carrick_signal_linux::xsig::xsig_enqueue(
    std::process::id() as i32,
    crate::linux_abi::LINUX_SIGUSR1,
    crate::linux_abi::LINUX_SI_USER,
    4242, 1000, 0, 0,
));
let outcome = bounded(&mut memory);
let _ = carrick_signal_linux::xsig::xsig_drain_for_self();
assert!(matches!(outcome, DispatchOutcome::WaitOnSignals { .. }),
    "held ring outcome: {outcome:?}");
```

This freezes the producer's enqueue-before-drain interleaving without a timing
assumption. Run from the repo root:

```sh
CARGO_BUILD_JOBS=3 cargo test -p carrick-kernel --lib --features test-support \
  rt_sigsuspend_releases_dispatch_before_waiting -- --test-threads=1
```

The reduction fails with `Errno { errno: LinuxErrno(4) }`. The built test
executable also fails with `--test-threads=2` and `--test-threads=16`.
Remove this diagnostic injection after reproducing; it deliberately writes
shared state and is not suitable for the committed parallel suite.

## Reduction and validation receipts

The unmodified signal test subset passed ten runs at each of 1, 2 and 16 test
threads, plus ten at 16 threads with `--skip ring_drain` (all also used
`--skip serial_host`). Thus the unsynchronized rare failure was not reproduced
in those 40 runs; the held-ring reduction, rather than a statistical failure
rate, identifies the interference. Other worktrees were running Cargo builds
while the reduction ran. All task-owned Cargo commands used
`CARGO_BUILD_JOBS=3`.

The held-ring reduction passed after the fixture change at 1, 2 and 16 threads.
The diagnostic injection was then removed. Final-source verification:

- The focused test passed 20/20 runs with `--test-threads=16`.
- The signal subset passed with `RUST_TEST_THREADS=1`, `2` and `16`
  (42 tests each).
- `just test-kernel` passed three times (2,593 passing tests across 21
  partitions per run; the library's pre-existing ignored test remains ignored).

The first `just lint-domains` attempt reached the host-authority compiler
capture and refused dirty tracked snapshot inputs. The clean-snapshot gate is
run after committing, rather than bypassing that requirement. No Docker or
signed guest gate is claimed: only the test fixture changes.

`CARGO_BUILD_JOBS=3 just clippy` also passed on the final source.
