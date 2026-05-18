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
- `carrick run-elf <path> [--rootfs-layer layer.tar.gz ...] [-- args ...]`
  loads a static Linux/aarch64 ELF, maps it into the HVF backend, builds a
  Linux-style initial stack with `argc`, `argv`, `envp`, and a terminating auxv,
  runs `svc #0` exits through the host syscall dispatcher, and emits stdout,
  stderr, exit status, trap count, and compatibility report JSON. This is the
  tight bring-up path for the static Rust fixtures, including a rootfs-backed
  `/etc/motd` reader, an argv reader, and a timerfd/epoll readiness probe.
- `carrick pull <image>` uses `oci-distribution` to fetch image layers into a
  content-addressed store under `$CARRICK_HOME` or `~/.carrick`.
- `carrick run <image> /path/to/elf [args ...]` loads a previously pulled image
  summary, composes its layer blobs as a read-only rootfs, loads the executable
  from that rootfs, maps any `PT_INTERP` interpreter from the same rootfs at a
  deterministic base with `AT_BASE`, and runs it through the same HVF/syscall
  loop with the command vector installed on the guest stack.
- `carrick rootfs --layer <layer.tar.gz> ...` composes OCI tar layers in memory,
  including whiteouts, opaque directory markers, and symlinks, without extracting
  the root filesystem.
- `carrick compat-report -- <cmd>` emits the machine-parseable compatibility report
  shape that runtime hooks will populate.
- `carrick dispatch-syscall <nr> --args ...` exercises the host-side syscall
  dispatcher that the HVF trap loop will call; `getcwd(2)`, `faccessat(2)`,
  `chdir(2)`, `fchdir(2)`, `eventfd2(2)`, `epoll_create1(2)`, `epoll_ctl(2)`,
  `epoll_pwait(2)`, `openat(2)`, `dup(2)`, `dup3(2)`, `fcntl(2)`, `ioctl(2)`,
  `statfs(2)`, `fstatfs(2)`, `getdents64(2)`, `lseek(2)`, `readlinkat(2)`,
  `pipe2(2)`, `read(2)`, `readv(2)`, `pread64(2)`, `write(2)`, `writev(2)`,
  `ppoll(2)`, `timerfd_create(2)`, `timerfd_settime(2)`, `timerfd_gettime(2)`, `close(2)`,
  `newfstatat(2)`, `fstat(2)`, `exit(2)`, `ENOENT`, `EACCES`, `EFAULT`,
  `EBADF`, and `ENOSYS` paths are covered by tests.
- Loaded ELFs include bootstrap heap and mmap arenas. The dispatcher can
  service `brk(2)`, file-backed and anonymous `mmap(2)`, bootstrap no-op
  `mprotect(2)`/`munmap(2)`, and `exit_group(2)`, which gives `ld-linux` a
  first place to map shared objects while fuller VM semantics land.
- Dynamic-linker bring-up syscalls now include bootstrap `uname(2)`, `getpid(2)`
  and uid/gid identity calls, `set_tid_address(2)`, `set_robust_list(2)`,
  `clock_gettime(2)`, `clock_getres(2)`, `gettimeofday(2)`, `prlimit64(2)`,
  `getrandom(2)`, and minimal `rt_sigaction(2)`/`rt_sigprocmask(2)` stubs.
- Linux ABI outputs for `stat`, `statfs`, `getdents64`, `iovec`,
  `eventfd` counters, `timerfd` timers and expiration counts, `epoll_event`, `pollfd`,
  `pipe2` fd pairs, `winsize`, `timespec`, `timeval`, `timezone`, auxv entries,
  `utsname`, `rlimit`, and signal-action stubs are represented by packed Rust
  structs in `linux_abi`, with `zerocopy` used to expose initialized bytes for
  guest-memory writes.
- The dispatcher now has a rootfs-backed file descriptor table for read-only
  file opens from composed OCI layers. Duplicated descriptors share open-file
  offsets while keeping descriptor flags such as `FD_CLOEXEC` per descriptor,
  and the runtime loop can drive a scripted `cat`-style
  `openat -> read -> write -> close -> exit` flow and a directory listing flow
  using `getdents64`.
- Rootfs symlink target text is preserved for Linux `readlinkat(2)`, and
  `/proc/self/exe` is synthesized from the launched executable path.
- Synthetic procfs support now serves `/proc/self/maps` and `/proc/cpuinfo`
  through normal `openat(2)`/`read(2)` descriptors, writes their `stat(2)`
  records with the packed Linux ABI struct path, and records compatibility-report
  entries for proc/sys files that are not synthesized yet.
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
  whose guest behavior covers direct `write(2)`, initial-stack argv reads,
  `openat(2)`, `eventfd2(2)`, `ppoll(2)`, `timerfd_create(2)`,
  `timerfd_settime(2)`, `epoll_pwait(2)`, `read(2)`, `close(2)`, and
  `exit(2)`, giving the loader, HVF loop, rootfs, and dispatcher a tight
  feedback loop.

`shell` and `exec` are present as CLI surfaces, but they still stop before
interactive process execution. `run` can map a dynamic ELF's rootfs-backed
interpreter and seed `AT_BASE`, but real dynamically linked program execution is
still gated on broader dynamic-linker syscall/runtime coverage.

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
