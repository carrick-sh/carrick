# x86 KVM lane health — 2026-10-04

Carrick builds for Linux x86 after minimal API/cfg repairs. The existing raw
static x86 guest runs on KVM and prints `hello`. The static musl fixture aborts,
and an OCI shell cannot start: the current HVPatch production runtime has not
been ported to KVM. This lane is experimental, with partial coverage; this is a
health receipt, not conformance acceptance or a performance measurement.

Host: willow VM 210, Debian 12 x86_64, 12 vCPU, accessible `/dev/kvm`.
Base: `ad3e127a9`; repaired source: `d04b5eb9e97d5533b0db936b9bbe0c655e1f7562`.
No Docker containers/oracle were run, registry containers were untouched, and
`~/carrick` was consulted only for historical scripts/notes. No GPL sources
were consulted. No baselines, timeouts, concurrency or semantic assertions
were weakened.

## Minimal repairs

- `015d6b79a`: KVM gains its missing `zerocopy` dependency and implements the
  shared engine's typed `X86VcpuSnapshot` save/rebind signatures. Snapshot
  errors propagate instead of becoming empty byte buffers; the existing
  park/recycle mechanism remains. The obsolete private serializer is removed.
- The same commit makes neutral `execute` rootfs helpers and
  `ExecCompletionOrigin` available outside macOS. Existing HVF-only
  `prepare_execve`, in-process fork preparation, logical-job re-exports and
  matching dispatch/probe arms receive the same macOS/AArch64 cfg as their
  dependencies/variants. Non-macOS carrier launch remains explicitly
  unsupported. These cfg changes leave the ARM64/macOS method bodies intact.
- CLI DTrace report handling receives the existing macOS/FreeBSD cfg;
  offline profile hashes include the identical bundled D-script bytes without
  importing the DTrace-only runtime module. Core validation uses
  `anyhow::Result`, matching the command dispatcher and allowing error
  conversion on Linux. No tracing behavior or script changed.
- `846964027`: the KVM futex test uses `&|| false` instead of a removed
  `never_interrupted()` helper (test compilation repair).
- `d04b5eb9e`: three memfd tests passed native x86 syscall numbers into a
  canonical-number dispatcher. They now use `carrick_abi::syscall::nr`.
  Red-first: all three initially returned ENOSYS (38); the focused memfd
  selection then passed 4/4. Guest syscall normalization is unchanged.

## Builds and smoke

Commands ran in the worktree. Local logs and generated fixtures are under
`target/x86-kvm-health/` and are not committed.

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux
cargo build -p carrick-vmm-kvm
just fmt-check
```

All three exit zero. Builds still emit numerous warnings; a warnings-as-errors
gate is not claimed. The final CLI build log is `build-final.log`.

The retired smoke recipe targeted the AArch64 fixture, so this x86 audit used
`crates/carrick-vmm-kvm/tests/live_vcpu_x86.rs` and standalone KVM `run-elf`.
The raw M0/M1 ELF was materialized from the existing `m01_blob()` in
`guest_setup_x86.rs`, using the same ELF wrapper as the live test. It has no
libc and performs write/exit; no new conformance probe was added.

```sh
CARRICK_RUN_ID=x86-kvm-health-20261004-m01-final target/debug/carrick-vmm-kvm run-elf target/x86-kvm-health/m01.elf
```

Exit **0**, stdout `hello\n`, stderr empty (`m01.out` / `m01.err`). The live
M0/M1 test also passes with real `/dev/kvm`; it did not skip.

The existing shared x86 musl fixture was built locally (its documented
`build.sh` is absent in this checkout):

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS='-C linker=rust-lld -C linker-flavor=ld.lld -C relocation-model=static -C link-arg=--no-pie' cargo build --release --manifest-path crates/carrick-vmm-bhyve/fixtures/hello-x86_64/Cargo.toml --target x86_64-unknown-linux-musl
CARRICK_RUN_ID=x86-kvm-health-20261004-hello target/debug/carrick-vmm-kvm run-elf crates/carrick-vmm-bhyve/fixtures/hello-x86_64/target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64
```

Fixture build exits **0**; ELF64 x86_64, static ET_EXEC. Run exits **134**,
stdout empty. Stderr reports unhandled canonical `18446744073709551575`, then
`guest called tkill(SIGABRT)`. That value is the correctly normalized private
x86 **poll** ordinal, not a corrupt register. Native poll (7) is normalized in
`carrick-hal/src/x8664_arch.rs`; the limited standalone service loop in
`carrick-x86/src/bringup_fns.rs` does not implement it. M2 hits the same failure.

Read-only HTTP registry catalogs showed `ltp`/`cpython-test` on 5050 and
`carrick-go-conformance` on 5005; no BusyBox/Alpine repository was advertised.
The historically named `localhost:5050/ltp:arm64` resolves to an **amd64**
image (manifest `sha256:a83d94ae7c101a232f220ac1d72cb729242d9a86989159e71ff6bd3952aa1838`).
It was used for the available shell-start attempt:

```sh
CARRICK_RUN_ID=x86-kvm-health-20261004-oci-final CARRICK_INSECURE_REGISTRIES=localhost:5050,localhost:5005 target/debug/carrick run --rm --platform linux/amd64 localhost:5050/ltp:arm64 /bin/sh -c 'echo x86-kvm-shell-ok'
```

Exit **125**, stdout empty (`oci.out` / `oci.err`):

```text
carrick: unsupported in this backend: hvpatch requires macOS/AArch64 host and AArch64 guest; got host=Linux/Amd64 guest=Amd64
```

The CLI also prints an inappropriate Apple Rosetta notice on native Linux
x86, a separate diagnostic defect left unchanged. No OCI shell success,
including BusyBox/Alpine, is claimed.

SHA-256 identities (final rebuild preserved the tested bytes):

| Artifact | SHA-256 |
|---|---|
| `target/debug/carrick` | `5025f8479926e88eb0fe5c2d609672cf8f262a21e605f12ed36c75e1aa5363c3` |
| `target/debug/carrick-vmm-kvm` | `4c499f056e06938c45fd80d7209f72db5c9ecd60de77eec0acc00d6c1760f782` |
| musl hello fixture | `71c4d80dcb7086cf642be22e8050d27964ba73f8d9983adc8cc6ce2797886e82` |
| raw M0/M1 ELF | `5e64b9d9052f77c07ce6bfba23f85539aaa59c5ee28d746a6bbac1b814159986` |

All guest invocations were stamped, including KVM tests with
`CARRICK_RUN_ID=x86-kvm-health-20261004-kvm-tests`. Scoped
`scripts/sudo/kill.sh <run-id>` cleanup reported zero remaining processes for
hello, OCI, raw and test runs, including the final smoke IDs. No broad kill
was used. Standalone KVM does not publish the CLI's run-id process title;
its foreground children exited, so cleanup output alone is not its proof.

## Test inventory

| Command | Result |
|---|---|
| `just test-kernel` (initial) | 109 EL1 ABI + 32 fd-core pass; kernel 2297 pass / 11 fail / 1 ignored, 138 filtered; exit 101 |
| `cargo test -p carrick-kernel --lib --features test-support memfd` | 4 pass, 2443 filtered; exit 0 |
| `just test-kernel` (after repair) | 109 EL1 ABI + 32 fd-core pass; kernel **2300 pass / 8 fail / 1 ignored**, 138 filtered; exit 101 |
| `cargo test -p carrick-x86` | **39 pass**, no failures; exit 0 |
| `CARRICK_RUN_ID=x86-kvm-health-20261004-kvm-tests cargo test -p carrick-vmm-kvm -- --nocapture` | 19 library pass; live M0/M1 pass, musl M2 fail; exit 101 |
| `cargo test -p carrick-vmm-kvm --test sentinel_decode` | 2 pass; exit 0 (not reached by preceding failing invocation) |
| `cargo test -p carrick-vmm-kvm --doc` | 0 doctests; exit 0 |
| `just test-kernel-semantics` | Fails at socket-close target; exit 101 |
| `cargo test -p carrick-kernel-example --tests --no-fail-fast` | Complete inventory: **265 pass / 1 fail**, no ignores; exit 101 |
| `just accept --phase signed --receipt target/x86-kvm-health/accept.json` | Explicitly unsupported on `linux-x86_64`; exit 1, no acceptance receipt emitted |

The kernel recipe stops before semantics on failure, so semantics were run
separately; `--no-fail-fast` inventories otherwise unreached targets, not a
retry-to-green. Total completed KVM test cases: **22 pass / 1 fail**.
The reported historical “12 macOS-assumption tests” is not the observed count:
this checkout had eleven initial kernel failures, three repaired and eight
remaining. The ignored/filtered recipe cases are not claimed as passes.

All observed failed test names, including repaired failures:

| Test | Class and evidence |
|---|---|
| `dispatch::fs::tests::memfd_proc_self_fd_reopen_access_mode_and_seals` | **x86 bit-rot fixed**: native 319 instead of canonical 279; ENOSYS before, passes after |
| `dispatch::fs::tests::memfd_proc_self_fd_reopen_trunc_shares_inode` | **x86 bit-rot fixed**: native numbers at canonical boundary; passes after |
| `dispatch::fs::tests::pwrite64_to_memfd_returns_without_deadlock` | **x86 bit-rot fixed**: memfd_create ENOSYS before pwrite; passes after |
| `dispatch::fs::tests::lseek_data_and_hole_across_backends` | **Real Linux defect**: host sparse-file SEEK_DATA(0) gives 4096, expected 0. `dispatch/fs/rw.rs:525` and another host seek path use Darwin DATA=4 / HOLE=3 on Linux, where those values are reversed |
| `dispatch::mem::backing::tests::readonly_host_fd_cannot_carry_a_writable_shared_file_mapping` | **macOS-host-assumption test**: requires HVF writable alias rejection of O_RDONLY; `backing.rs` explicitly applies that admission only on macOS, while this assertion is unconditional |
| `dispatch::net::lifecycle::icmp_ping_tests::loopback_echo_reply_is_queued_with_valid_checksum` | **Host-capability assumption**: Linux ping socket returns EACCES (13); willow `net.ipv4.ping_group_range` is `1 0` (disabled). No host privilege/sysctl changes made |
| `dispatch::net::support::tests::host_to_linux_sockaddr_unix_does_not_leak_private_hash_path_without_metadata` | **macOS-host-assumption fixture**: injects BSD `[len, AF_UNIX]` header; Linux reads native u16 family 256, so conversion is not exercised; actual length 56, expected 2 |
| `dispatch::net::support::tests::host_to_linux_sockaddr_unix_falls_back_to_xattr_across_processes` | **macOS-host-assumption fixture**: same invalid Linux sockaddr header; expected reverse translation not exercised |
| `dispatch::overlay_dispatch_tests::epoll_et_delivers_listener_edge_without_read_byte_growth` | **Real defect candidate**: second listener EPOLLET edge missing (0 vs 1) at `dispatch/tests.rs:2103`; no timeout/concurrency changes or retry acceptance |
| `dispatch::overlay_dispatch_tests::large_nonblocking_host_pipe_write_uses_small_ready_window` | **macOS-host-assumption test**: draining one byte from a full Linux pipe need not free a buffer slot; EAGAIN (11) contradicts fixture's assumed positive partial write |
| `dispatch::overlay_dispatch_tests::large_nonblocking_host_socket_write_uses_small_ready_window` | **macOS-host-assumption test**: same one-byte drain assumption for a full host socket; EAGAIN (11), expected positive progress |
| `test_m2_musl_static_hello` (`live_vcpu_x86`) | **Real standalone capability gap**: private x86 poll unhandled; abort 134, expected hello/exit 0 |
| `unix_socketpair_local_shut_rd_wakes_epoll_with_epollrdhup` (`carrick-kernel-example`, `socket_close`) | **Real defect candidate**: local guest AF_UNIX SHUT_RD fails to publish EPOLLRDHUP; epoll_pwait 0 vs 1 at `tests/socket_close.rs:512` |

Host-assumption classifications come from fixture/source inspection; they
are not Docker differential verdicts. In particular, listener and shutdown
defects need focused follow-up, not labeling as known gaps. Existing tests
provide semantic witnesses; no new implementation or work-budget change was
made for those failures.

## Production runtime blocker and hand-off

OCI startup first refuses in `crates/carrick-kernel/src/page_profile.rs:70`.
Even bypassing that check would hit explicit pending entries:
`PreparedRun::execute`'s non-macOS arm at
`crates/carrick-runtime/src/prepare.rs:912`, and `runtime::run_oci` at
`crates/carrick-runtime/src/lib.rs:478` (message at 480):
`Pending port to hvpatch VM carrier model`. Standalone KVM `run-elf` and
shared x86 engine/unit tests remain usable; the full OCI kernel dispatcher
is not wired to a KVM HVPatch carrier.

The director confirmed that carrier port is outside this minimal repair.
It needs a KVM carrier projecting Carrick's task graph, bounded executor/vCPU
leases, owned blocking continuations and fork/exec/signal lifecycle; an explicit
decision on an x86 CPL0 runtime equivalent to the ARM EL1 fast paths versus
host dispatch with the same contracts; and per-mm page-table/backing ownership
with typed VA/GPA/frame/generation domains and rollback-capable mapping
publication/retirement. Existing host-fork KVM machinery is not that carrier.
Disabling the page-profile check or reviving a retired process-per-task backend
would not implement it. Acceptance needs two-live-process and exhausted-pool
contracts plus real OCI execution. No carrier/recycle stress, ARM64/HVF runtime
gate, Docker oracle, full `just ci`, or overhead ratio is claimed here.

Current x86 entry smoke uses `cargo test -p carrick-vmm-kvm --test cpl0_entry`
on a Linux x86_64 host with real `/dev/kvm` and a built CPL0 image.
