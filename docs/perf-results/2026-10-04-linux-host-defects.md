# Linux host defect repairs — 2026-10-04

Six defect groups from the [x86 lane health receipt](2026-10-04-x86-kvm-lane-health.md)
are repaired on willow VM 210, native Debian x86_64. Base: `00cd94614`;
verified source: `2cc42f5b944f4b12f18af2873c0b4972011d189c`.
This is host-library verification, not KVM carrier acceptance or a performance
measurement. No Docker, signed/HVF tests, host configuration changes, retries,
timeout increases or concurrency reductions were used. macOS acceptance remains
with the director.

## Commits and red-first evidence

| Commit | Change | Linux failure before repair |
|---|---|---|
| `d68e18b52` | Both host seek paths use `libc::SEEK_DATA` / `SEEK_HOLE`; guest ABI constants remain separate | `lseek_data_and_hole_across_backends`: DATA(0) returned 4096 instead of 0 |
| `295a7e9fe` | Linux host-socket sampler requests and translates native `POLLRDHUP` | `unix_socketpair_local_shut_rd_wakes_epoll_with_epollrdhup`: epoll returned 0 instead of 1 |
| `13846027a` | A drained native Linux listener edge carries arrival authority independently of byte growth | `epoll_et_delivers_listener_edge_without_read_byte_growth`: second edge returned 0 instead of 1 |
| `434bd2550` | Rosetta notice constant, implementation, import and invocation are macOS-only | Native Linux amd64 CLI attempt printed the Apple Rosetta notice |
| `93cbd7956` | Five fixtures express native header, mapping and buffer-window contracts | All five named fixtures failed before correction |
| `2cc42f5b9` | Restrict unused helpers/imports to their callers' hosts; remove uncalled private code | Requested Clippy rejected six VFS and eleven kernel production diagnostics; all-targets also exposed VFS test fixture compilation errors |

The shutdown defect was in `HostSocket` readiness sampling: RDHUP-only interest
did not request native `POLLRDHUP`. The existing socketpair transport took this
path; Carrick's guest interest masking remains authoritative. BSD half-close
reconstruction is unchanged. No AF_UNIX host delegation was newly introduced.

Linux listener epoll events have no accept-queue count, and listener `FIONREAD`
remains zero. The old count-growth predicate discarded a second native arrival.
For Linux ET listeners with no pending in-zone connection, host level sampling
now waits for the native edge to drain, preventing duplicate delivery before that
edge is consumed. In-zone arrivals retain their own generation; both mixed
arrival orders are exercised on Linux. BSD count/level behavior is unchanged.

These changes retain the existing readiness sample and event drain, adding no
polling loop, scan or extra host call. Existing `kernel.fs.write-seek`,
`kernel.el1.epoll-zone` and `kernel.el1.unix-owner` contracts guided the fixes;
existing tests supply the semantic witnesses. No runtime ratio is claimed.

Fixture changes preserve macOS assertions: O_RDONLY HVF alias admission remains
rejected there, and one-byte drains still require positive partial progress on
macOS. Linux admits the non-HVF alias but still rejects physical writable shared
`mprotect` on an O_RDONLY file; its full pipe/socket one-byte-drain cases assert
EAGAIN. AF_UNIX tests use the existing native sockaddr header helper and retain
the private-path and cross-process xattr assertions.

The Clippy repair also makes existing portable VFS test helpers/imports available
on Linux. No test or semantic assertion was removed. Test-only allocation and
directory parsing helpers are restricted to the hosts of their existing callers.
No blanket lint allowance was added.

## Verification

Each requested command ran directly in the foreground and was awaited.

| Command | Result |
|---|---|
| `just test-kernel` | Exit 101: 109 EL1 ABI + 32 fd-core pass; kernel **2309 pass / 1 fail / 1 ignored**, 138 filtered. Only failure is the permitted ping-socket capability case below. Recipe stops before semantics. |
| `cargo test -p carrick-kernel-example --tests` | Exit 0; every unit and integration target passes, including socket-close and structural contract suites. |
| `cargo clippy -p carrick-kernel -p carrick-vfs -p carrick-kernel-example --all-targets --no-deps -- -D warnings` | Exit 0. Clippy emits a nonfatal configuration warning about unreachable `libc::proc_listallpids` in the existing `clippy.toml` catalog. |
| `just fmt-check` | Exit 0. |

Focused verification, after each corresponding red witness:

```sh
cargo test -p carrick-kernel --lib --features test-support lseek_data_and_hole_across_backends
cargo test -p carrick-kernel-example --test socket_close
cargo test -p carrick-kernel --lib --features test-support epoll_et_ -- --skip serial_host
RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support serial_host::epoll_et_repolls_host_level_when_mux_misses_wake
cargo test -p carrick-kernel --lib --features test-support readonly_host_fd_cannot_carry_a_writable_shared_file_mapping
cargo test -p carrick-kernel --lib --features test-support host_to_linux_sockaddr_unix_
cargo test -p carrick-kernel --lib --features test-support large_nonblocking_host_
cargo test -p carrick-vfs --lib host_checked_remove_distinguishes_unlink_failure_from_absence
cargo test -p carrick-vfs --lib host_mkdir_then_stat
cargo test -p carrick-vfs --lib admission_retains_backing_cohort_and_replacement_detaches_old_backing
cargo test -p carrick-vfs --lib test_rootfs_vfs_create_node_kinds_after_negative_lookup
```

All exit zero: respectively 1, 8, 10, 1, 1, 2, 2, 1, 1, 1 and 1 tests pass.
An earlier focused `epoll_et_` invocation included the serial-host case alongside
other tests; verification above reran the proper serial/parallel partitions.

The remaining failure is
`dispatch::net::lifecycle::icmp_ping_tests::loopback_echo_reply_is_queued_with_valid_checksum`:
native ping socket creation returns EACCES (13). Read-only inspection confirms
`/proc/sys/net/ipv4/ping_group_range` is `1 0` (disabled), with uid/gid 1000.
No reusable host-capability precondition pattern was found in the kernel test
support, so the existing test is unchanged, as requested. No sysctl was modified.

The director confirmed that these native Linux commands are this worker's gate;
`just accept` stays with the director on macOS because its host phase includes
HVF-only/default-macOS commands.

## Final CLI diagnostic artifact

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux
CARRICK_RUN_ID=linux-host-defects-rosetta-final CARRICK_INSECURE_REGISTRIES=localhost:5050,localhost:5005 target/debug/carrick run --rm --platform linux/amd64 localhost:5050/ltp:arm64 /bin/sh -c 'echo linux-host-notice-check'
sha256sum target/debug/carrick
scripts/sudo/kill.sh linux-host-defects-rosetta-final
```

Build exits zero. Its runtime/CLI Linux warnings outside the requested three
crates remain; no workspace warnings-as-errors pass is claimed. CLI SHA-256:
`62926ea6989504ec8846dd80dd6047a253b3c1a183bd02f351ba0a65b310ba56`.

The rebuilt native Linux CLI prints no Rosetta notice. It exits **125** with
only the existing carrier refusal:

```text
carrick: unsupported in this backend: hvpatch requires macOS/AArch64 host and AArch64 guest; got host=Linux/Amd64 guest=Amd64
```

The scoped cleanup exits zero with zero remaining processes. Earlier red and
green diagnostic attempts were also stamped and cleaned up by their exact run
IDs. No OCI guest execution success is claimed; the unchanged KVM carrier and
standalone musl/poll gaps belong to the prior receipt's separate hand-off.
