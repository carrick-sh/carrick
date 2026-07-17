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
