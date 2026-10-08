# x86 user VA ceiling

Native x86_64 Linux is the authorized oracle for the four-level Carrick guest
layout. No Docker is used. LA57 native kernels need a separate oracle because
they can accept fixed mappings above the four-level ceiling.

Build from the repository root and run the native oracle:

```
cargo build --locked --release --manifest-path crates/carrick-conformance-next/tests/fixtures/x86-va-ceiling/Cargo.toml --target x86_64-unknown-linux-musl --target-dir target/x86-va-ceiling
target/x86-va-ceiling/x86_64-unknown-linux-musl/release/x86-va-ceiling
```

The committed oracle records the source hash and native executable hash.
Refresh `oracle.json` deliberately after a source change, recording
native `uname`, executable hash and exact stdout. This probe checks ordinary
placement and fixed-address refusals; the VM-free dispatcher test forces the
crowded lower-half search without allocating huge host memory.

The VM-free red was captured against `904fd644b` before changing placement:
`x86_mmap_crowded_lower_half_refuses_noncanonical_gap` returned
`0x800000200000` (140737490452480, above `2^47`) instead of `-12`.
It reserves the occupied range as metadata and performs no huge host allocation.
The green contract checks errno `12` and zero backend protection calls at
64, 512 and 2048 GiB; a separate test leaves one gap ending exactly at `2^47-4096`.

The production route is `carrick run --platform linux/amd64` through the
shared CPL0 kernel. Its host dispatcher and mmap family binding remain
[PR #81 dependencies](https://github.com/carrick-sh/carrick/pull/81); this
fixture has no current live shared-dispatcher mmap receipt.

`kvm-observation.json` and `production-observation.json` preserve historical
observations from before standalone KVM run-elf retirement. The former loop
returned `-38` for fixed mappings; the former production plan refused execution
before the guest started. These archived artifacts are not evidence for the
current CPL0 lane. The standalone binary, its host PTE authoring and its smoke
tests have been removed. HVF signed tests remain director-owned on macOS.

The second VM-free red tested the native final-page boundary with the initial
`2^47` typed limit: `x86_mmap_task_size_guard_matches_native_linux` returned
`0x7ffffffff000` (140737488351232) instead of errno `12`. The x86 arch value
now excludes one 4 KiB guest page (`2^47-4096`), matching the native oracle;
ARM remains exactly `2^48`. The x86 ceiling is therefore the Linux user limit,
not merely the hardware canonical-address boundary.
