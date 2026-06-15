# M2 fixture: static x86_64 musl hello

The Phase 2 M2 guest: a real `std` Rust hello cross-compiled to
`x86_64-unknown-linux-musl` as a **static, non-PIE `ET_EXEC`** binary. Unlike the
aarch64 `fixtures/linux-aarch64-hello` (which is `#![no_std]` with hand-written
aarch64 asm), this is a genuine libc binary, so it exercises real **musl startup**
— the point of M2.

## Build
```
./build.sh        # or: just build-x86-fixture
```
Needs only rustup (`x86_64-unknown-linux-musl` target) — NO C toolchain, NO Docker.
rust-lld links the ELF directly (Apple's `cc`/`ld` cannot link GNU/ELF musl
output); `relocation-model=static --no-pie` yields a fixed-base `ET_EXEC` with no
dynamic relocations (simplest for carrick's loader). The binary
(`hello-x86_64`) is gitignored; rsync still ships it to the FreeBSD box.

## Oracle policy (no Rosetta)
`oracle.expected` (the pass/fail stdout, `hello, x86_64 world`) is transcribed
from `src/main.rs` — no execution needed. The **startup-syscall set** is
discovered TRAP-DRIVEN: `run_elf_bhyve` (T10) fails loudly on each unhandled raw
x86_64 number, in real order, on the real path — that IS the red-first list. If a
ground-truth Linux x86_64 trace is ever needed (argument semantics, not set
membership), ask for a NATIVE x86_64 Linux box (container 104, `carrick-x86`) —
NEVER capture an oracle through Rosetta-translated Docker.

## Observed startup-syscall set (filled by T11's first live run)
_(pending — T11)_
