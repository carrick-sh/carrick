# x86_64 DSR test fixtures

`tinyguest-x86_64-linux` — a `#![no_std]` static-pie Linux x86_64 ELF used by
`tests/native_static_elf.rs` to prove the DSR lane runs REAL compiler output
(not hand-assembly). Source: `tinyguest.rs`.

It is checked in (rather than built during `cargo test`) so the test needs no
Linux cross-linker; the source and the exact build recipe live here for
review and regeneration. On the FreeBSD rig (rustc 1.96.0 with the
`x86_64-unknown-linux-musl` rust-std installed):

```sh
rustc --edition 2021 --target x86_64-unknown-linux-musl \
      -O -C panic=abort -C relocation-model=pic \
      --emit obj -o tinyguest.o tinyguest.rs
# Link a bare static-pie ELF with no CRT (rust-lld ships with the toolchain):
rust-lld -flavor gnu -static -pie -e _start -o tinyguest-x86_64-linux tinyguest.o
```

The guest computes a loop sum, `write(1, msg, len)` (msg reached
RIP-relatively — the emitter's absolute-VA rewrite), and `exit_group(sum)`
(sum == 0+1+…+6 == 21). It has no relocations (pure RIP-relative codegen) and
no TLS, so the loader needs no relocation pass and no `arch_prctl` servicing.

`computeloop-x86_64-linux` — a `#![no_std]` guest (`computeloop.rs`, built the
same way) running a 50-million-iteration PURE compute loop (no syscall inside
the loop) then `exit_group(sum & 0xff)`. It is the direct-branch-chaining
regression: the runtime test asserts `traps == 1` (the loop's conditional
back-edge ran natively in the JIT every iteration — unchained it would
round-trip to Rust 50M times) and `exit_code == 192` (the correct
`sum(3i+1, i in 0..50M) mod 256`, proving chaining preserved control flow and
register state).

`dynamic-main-x86_64-linux` carries a `PT_INTERP` whose main entry is an
intentional `ud2` sentinel. `dynamic-interpreter-x86_64-linux` is a
relocation-free static PIE that walks the kernel entry stack, requires nonzero
`AT_PHDR`, `AT_PHNUM`, `AT_BASE`, and `AT_ENTRY`, writes `dynamic-elf ok`, and
exits 23. Regenerate both with FreeBSD clang/lld:

```sh
clang --target=x86_64-linux-musl -nostdlib -fuse-ld=lld -pie \
  -Wl,--no-dynamic-linker -Wl,-e,_start \
  -o dynamic-interpreter-x86_64-linux dynamic-interpreter.S
clang --target=x86_64-linux-musl -nostdlib -fuse-ld=lld -pie \
  -Wl,--dynamic-linker,/lib/carrick-dynamic-interpreter -Wl,-e,_start \
  -o dynamic-main-x86_64-linux dynamic-main.S
```

The `exitgroup-sibling-*-x86_64-linux` binaries come from one bare-static
assembly fixture. Private/shared modes park the initial thread indefinitely in
the corresponding `FUTEX_WAIT` while a sibling calls `exit_group(37)`; immediate
mode makes that call directly after clone to race handle publication; busy mode
has a sibling spin forever in chained JIT code while the initial thread calls
`exit_group(0)`. Together they prove blocking-wait release, clone teardown, and
asynchronous translated-code kicks before native arena teardown. Regenerate
them with FreeBSD clang/lld:

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o exitgroup-sibling-futex-x86_64-linux exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DSHARED_FUTEX -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-shared-futex-x86_64-linux \
  exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DIMMEDIATE_CHILD -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-immediate-x86_64-linux \
  exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DBUSY_SIBLING -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-busy-x86_64-linux \
  exitgroup-sibling-futex.S
```

`fork-child-sibling-exitgroup-output-x86_64-linux` covers the fork-child
lifecycle path: a sibling publishes `exit_group` while the child's initial
thread is parked, and 128 KiB of buffered output must survive terminal cleanup.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o fork-child-sibling-exitgroup-output-x86_64-linux \
  fork-child-sibling-exitgroup-output.S
```

`identity-loop-x86_64-linux` executes 1,000 `getpid` and 1,000 `gettid`
syscalls before `exit_group`. The native integration gate requires one Rust
trap total, proving both identity calls remain inside the chained JIT path.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o identity-loop-x86_64-linux identity-loop.S
```

`identity-seccomp-x86_64-linux` installs an allow-all seccomp filter before 20
identity calls. Its integration test requires all 23 syscalls to trap, proving
the live atomic gate disables already-translated identity paths immediately.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o identity-seccomp-x86_64-linux identity-seccomp.S
```
