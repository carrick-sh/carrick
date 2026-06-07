# fork-wait4 — freestanding KVM fork(2) test fixture

A hand-written, libc-free aarch64 Linux ELF that exercises the raw `fork(2)`
primitive (Phase 2, Task 2) as serviced by the carrick-linux KVM thin shim.

## What it does

1. Issues `clone(SIGCHLD, 0, 0, 0, 0)` — a plain `fork()` with no child stack.
2. The child immediately calls `exit_group(42)`.
3. The parent calls `wait4(pid, &status, 0, NULL)` to reap the child.
4. Asserts the wait status equals `42 << 8` (i.e., `WIFEXITED` with exit code 42).
5. Writes `"fork-ok\n"` to stdout and calls `exit_group(0)`.

Only four syscalls are used: `clone` (220), `wait4` (260), `write` (64), and
`exit_group` (94) — exactly the fork primitive under test, nothing else.

## Build (Mac-native, no extra toolchain)

```sh
./build.sh        # clang integrated assembler + bundled rust-lld
file ./fork-wait4
# ELF 64-bit LSB executable, ARM aarch64, statically linked
```

The same toolchain as the `hello-aarch64` fixture is used: clang's integrated
assembler assembles `fork.S` to an aarch64 ELF object, then `rust-lld` links it
into a static executable.

## Running

The fixture is run by `scripts/kvm-smoke-lima.sh` against the carrick-linux thin
shim inside the nested-KVM Lima VM (`just kvm-smoke-lima`). Expected stdout is
`fork-ok\n` (see `oracle.expected`); expected exit code is 0.

A static aarch64 Linux ELF cannot exec directly on macOS, so the smoke test is
gated behind the Lima L2 lane.
