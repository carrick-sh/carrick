# Carrick

Carrick is a Rust bootstrap for the Linux-on-macOS compatibility layer described in
`plan.md`. The current tree is intentionally a foundation, not a finished runtime:
it wires the CLI, OCI image plumbing, ELF inspection, syscall/probe data models, and
the Hypervisor.framework trap boundary that later runtime work will fill in.

## Implemented now

- `carrick inspect-elf <path>` parses ELF metadata with `goblin`.
- `carrick plan-elf-load <path>` turns `PT_LOAD` headers into a structured
  mapping plan for the Mach VM/HVF runtime.
- `carrick load-elf <path>` materializes that plan into typed guest memory
  regions with permissions and zero-filled memory past the file-backed bytes.
- `carrick run-elf <path> [--rootfs-layer layer.tar.gz ...]` loads a static
  Linux/aarch64 ELF, maps it into the HVF backend, runs `svc #0` exits through
  the host syscall dispatcher, and emits stdout, stderr, exit status, trap count,
  and compatibility report JSON. This is the tight bring-up path for the static
  Rust fixtures, including a rootfs-backed `/etc/motd` reader.
- `carrick pull <image>` uses `oci-distribution` to fetch image layers into a
  content-addressed store under `$CARRICK_HOME` or `~/.carrick`.
- `carrick rootfs --layer <layer.tar.gz> ...` composes OCI tar layers in memory,
  including whiteouts, opaque directory markers, and symlinks, without extracting
  the root filesystem.
- `carrick compat-report -- <cmd>` emits the machine-parseable compatibility report
  shape that runtime hooks will populate.
- `carrick dispatch-syscall <nr> --args ...` exercises the host-side syscall
  dispatcher that the HVF trap loop will call; `openat(2)`, `getdents64(2)`,
  `lseek(2)`, `read(2)`, `write(2)`, `close(2)`, `newfstatat(2)`, `fstat(2)`,
  `exit(2)`, `ENOENT`, `EFAULT`, `EBADF`, and `ENOSYS` paths are covered by
  tests.
- Linux ABI outputs for `stat` and `getdents64` are represented by packed Rust
  structs in `linux_abi`, with `zerocopy` used to expose initialized bytes for
  guest-memory writes.
- The dispatcher now has a rootfs-backed file descriptor table for read-only
  file opens from composed OCI layers, and the runtime loop can drive a scripted
  `cat`-style `openat -> read -> write -> close -> exit` flow and a directory
  listing flow using `getdents64`.
- USDT support wires compatibility events to DTrace probes through the Apache-2.0
  `usdt` crate.
- `carrick syscalls` exposes the initial Linux/aarch64 syscall table and support
  status for the bring-up tranche.
- `carrick trap-capabilities` reports the Hypervisor.framework backend.
- On macOS/aarch64, the HVF backend uses the permissively licensed `applevisor`
  crate to create the VM/vCPU, map ELF-backed guest address-space regions, seed
  the program counter, decode AArch64 SVC exits, and write syscall return values
  back into guest registers. The same mapped HVF memory implements Carrick's
  guest-memory read/write trait, so syscall handlers can copy data into guest
  buffers.
- `scripts/build-linux-fixtures.sh` builds static Linux/aarch64 Rust fixtures
  whose guest syscalls cover `write(2)`, `openat(2)`, `read(2)`, `close(2)`, and
  `exit(2)`, giving the loader, HVF loop, rootfs, and dispatcher a tight
  feedback loop.

`run`, `shell`, and `exec` are present as CLI surfaces, but they still stop before
OCI-backed process execution. The current executable path is `run-elf`, which is
deliberately scoped to static Linux/aarch64 ELF bring-up.

## License policy

The crate is dual licensed as `Apache-2.0 OR MIT`. Dependencies are selected from
permissive Rust ecosystem crates. `deny.toml` records the allowed dependency licenses
for `cargo-deny`; the current resolved dependency graph uses permissive licenses such
as MIT, Apache-2.0, BSD, ISC, Unicode-3.0, Zlib, Unlicense, 0BSD, BSL-1.0,
and CDLA-Permissive-2.0.

## Development

```sh
cargo fmt --all
cargo test
cargo build
```
