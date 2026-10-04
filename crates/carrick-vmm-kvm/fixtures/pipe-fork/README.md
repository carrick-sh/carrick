# pipe-fork — freestanding KVM pipe + fork test fixture

A hand-written, libc-free aarch64 Linux ELF that exercises `pipe2(2)`,
`fork(2)` (via `clone(SIGCHLD)`), and pipe I/O across the fork boundary as
serviced by the carrick-vmm-kvm thin shim (Phase 2, Task 3).

## What it does

1. Issues `pipe2(fds, O_CLOEXEC)` to create a pipe pair.
2. Issues `clone(SIGCHLD, 0, 0, 0, 0)` — a plain `fork()`.
3. **Child:** closes the write end, calls `read(rfd, buf, 2)`, asserts it got
   exactly 2 bytes equal to `"hi"`, then calls `exit_group(42)`.
4. **Parent:** closes the read end, calls `write(wfd, "hi", 2)`, closes the
   write end, then calls `wait4(pid, &status, 0, NULL)` to reap the child.
5. Asserts the wait status equals `42 << 8` (i.e., `WIFEXITED` with exit code 42).
6. Writes `"pipe-ok\n"` to stdout and calls `exit_group(0)`.

Syscalls used: `pipe2` (59), `close` (57), `read` (63), `write` (64),
`clone` (220), `wait4` (260), `exit_group` (94).

## Build (Mac-native, no extra toolchain)

```sh
./build.sh        # clang integrated assembler + bundled rust-lld
file ./pipe-fork
# ELF 64-bit LSB executable, ARM aarch64, statically linked
```

The same toolchain as the `fork-wait4` fixture is used: clang's integrated
assembler assembles `pipe-fork.S` to an aarch64 ELF object, then `rust-lld`
links it into a static executable.

## Running

This is a historical fixture for the retired 1:1 aarch64 smoke lane.
Expected stdout is `pipe-ok\n` (see `oracle.expected`); expected exit code
is 0. It has no current acceptance binding.
