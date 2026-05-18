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
- `carrick pull <image>` uses `oci-distribution` to fetch image layers into a
  content-addressed store under `$CARRICK_HOME` or `~/.carrick`.
- `carrick rootfs --layer <layer.tar.gz> ...` composes OCI tar layers in memory,
  including whiteouts, opaque directory markers, and symlinks, without extracting
  the root filesystem.
- `carrick compat-report -- <cmd>` emits the machine-parseable compatibility report
  shape that runtime hooks will populate.
- `carrick dispatch-syscall <nr> --args ...` exercises the host-side syscall
  dispatcher that the HVF trap loop will call; `write(2)`, `exit(2)`, `EFAULT`,
  `EBADF`, and `ENOSYS` paths are covered by tests.
- USDT support wires compatibility events to DTrace probes through the Apache-2.0
  `usdt` crate.
- `carrick syscalls` exposes the initial Linux/aarch64 syscall table and support
  status for the bring-up tranche.
- `carrick trap-capabilities` reports the Hypervisor.framework backend.
- On macOS/aarch64, the HVF backend uses the permissively licensed `applevisor`
  crate to create the VM/vCPU, map ELF-backed guest address-space regions, and
  seed the program counter. The actual `svc #0` trap/run loop is still the next
  runtime milestone.
- `scripts/build-linux-fixtures.sh` builds a static Linux/aarch64 Rust fixture
  whose first guest syscalls are `write(2)` and `exit(2)`, giving the loader and
  dispatcher a tight feedback loop.

`run`, `shell`, and `exec` are present as CLI surfaces, but they stop before process
execution because the HVF `svc #0` trap/run loop has not been wired to the loader and
syscall dispatcher yet.

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
