# Guest-Side Syscall Shim

Status:

- The base EL1 identity shim services `getpid` and `gettid` without an HVF
  exit. Credential reads trap through Kernel dispatch because Linux credentials
  can diverge per thread and cannot live on one process-shared page.
- `carrick-cli` enables the base shim by default through the `syscall-shim`
  Cargo feature. `carrick-runtime` has no default feature so the binary remains
  the control point; `--no-default-features` builds the legacy trap-only path.
- The async futex ring has been dropped from this branch. There is no
  `syscall-shim-futex` feature, command ring, EL1 futex producer, or service
  thread in the rebased stack.
- Futexes, `read`/`write`, polling syscalls, sleeps, and other host-state or
  blocking syscalls remain on the correct trap path. Performance work for them
  belongs in that path.
- `LD_PRELOAD` remains deferred. The measured `writev_burst` gap was reduced by
  host-path batching, not by an interposer.

## Why This Shim Is Narrow

The trap path is `svc -> EL1 vector -> hvc #2 -> HVF exit -> host dispatch`.
Skipping that path is correct only when the answer is already local to Carrick
or the guest CPU and can be returned exactly.

The safe set is the identities that do not diverge across sibling threads:

- `getpid` returns Carrick's namespace-aware process id.
- `gettid` returns the current guest-visible thread id.

`getuid`, `geteuid`, `getgid`, and `getegid` are deliberately excluded. Their
immutable Kernel credential objects can diverge per thread after a COW
publication. The normal trap path reads the exact dispatch-captured
`KernelContext`; a process-shared page would be a false mirror.

## Data Model

The per-process identity page lives in the kernel hole at
`LINUX_IDENTITY_PAGE_BASE`, mapped EL1-readable and EL0-inaccessible. It stores:

```text
+0x00  pid
+0x04  shim-enabled
```

The runtime stamps this page before the first vCPU run, after fork in the
child, and after exec into a new address space. Credential mutations do not
write it.

`gettid` is per-thread, so it is not stored in the shared identity page. Each
vCPU gets its guest-visible tid stamped into `TPIDR_EL1`; the EL1 handler reads
that sysreg and falls back to the host trap if it is unexpectedly zero.

## EL1 Vector Path

The EL1 vector's syscall slot compares `x8` against the supported syscall
numbers. Matching identity calls load the stamped value into `x0` and `eret`.
Non-matching syscalls preserve syscall arguments and fall through to `hvc #2`.

The handler deliberately clobbers only `x0` after a match. There is no EL1 stack
or guest-user-memory access in the base shim, so it avoids the scratch-register
and PAN problems that make broader in-guest syscall production risky.

## Removed Futex Ring

The async futex ring was removed during the rebase onto `origin/main`.

The reason is semantic, not just implementation complexity: `FUTEX_WAKE` returns
the actual number of waiters woken. A fire-and-forget EL1 producer can only
return an optimistic count. A correct producer must wait for the host-owned
futex table result; on Apple HVF that wait is either a CPU-burning spin or a
`WFI` VM exit. That is not a sound zero-exit performance path.

Correct futex work remains on the host trap path. The current branch keeps the
measured trap-path cleanups:

- private futex operations skip shared-address lookup;
- `CARRICK_FUTEX_HALT_POLL_NS` provides an opt-in halt-poll tuning knob, default
  `0`.

## I/O And Preload

Fire-and-forget `read`/`write` is not a valid fast path because Linux-visible
byte counts, short I/O, `EAGAIN`, `EPIPE`, signal interruption, and blocking
behavior are load-bearing.

The accepted I/O work is host-path optimization:

- normalize host fds to nonblocking at creation/adoption instead of every I/O;
- classify host write kinds once and avoid hot `fstat`;
- gather bounded host-backed `writev` buffers and issue one host write.

`LD_PRELOAD` should only be revisited after a dynamically linked, pipe-backed
benchmark shows remaining libc-level batching headroom that the host path cannot
remove. Static Go and static musl do not benefit from preload.

## Verification Surface

The minimum checks for this branch shape are:

```sh
cargo metadata --no-deps --format-version=1
cargo test -p carrick-cli --test perf_runner cases -- --nocapture
cargo test -p carrick-runtime --test integration futex_wake_returns_count_and_advances_table -- --nocapture
cargo test -p carrick-vmm-hvf futex -- --nocapture
cargo test -p carrick-runtime --test integration writev -- --nocapture
scripts/build-signed.sh --features syscall-shim
scripts/build-probes.sh
CARRICK_PERF_FILTER=futex_pingpong just bench
CARRICK_PERF_FILTER=stdio_burst just bench
CARRICK_PERF_FILTER=writev_burst just bench
```
