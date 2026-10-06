# x86 user VA ceiling

Native x86_64 Linux is the authorized oracle for the four-level Carrick guest
layout. No Docker is used. LA57 native kernels need a separate oracle because
they can accept fixed mappings above the four-level ceiling.

Build from the repository root (the same static ELF runs natively and in KVM):

```
cargo build --locked --release --manifest-path crates/carrick-conformance-next/tests/fixtures/x86-va-ceiling/Cargo.toml --target x86_64-unknown-linux-musl --target-dir target/x86-va-ceiling
target/x86-va-ceiling/x86_64-unknown-linux-musl/release/x86-va-ceiling
CARRICK_RUN_ID=x86-va-ceiling-live target/debug/carrick-vmm-kvm run-elf target/x86-va-ceiling/x86_64-unknown-linux-musl/release/x86-va-ceiling
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

The conformance-next in-process runner requires a macOS/AArch64 host and
AArch64 guest for HVPatch. This fixture therefore has native and standalone
KVM observations, with the shared-dispatcher live binding explicitly open.
The existing KVM CPL0
entry (6 tests) and standalone live-vCPU smoke (2 tests, including musl hello)
pass on this host but do not exercise the shared dispatcher mmap placement.
HVF signed tests cannot run on x86-w1; no acceptance runner was invoked.

The live standalone KVM fixture exits zero and matches the three `mmap(NULL)`
bounds checks. Its fixed checks differ: `bringup_fns::run_elf_service_loop`
explicitly returns `-38` for `MAP_FIXED` before any placement (`is_fixed` in
its mmap arm). This loop does not call the shared dispatcher. Native Linux
returns `0` at `2^47-8192` and `12` at `2^47-4096` and all higher test addresses.
`kvm-observation.json` preserves both executable hashes and the exact KVM
output; `oracle.json` preserves the exact native output. No KVM parity is
claimed for the fixed-address checks or the shared dispatcher fix.

The production conformance path is `Lane::KvmLocal` in
`crates/carrick-conformance/src/lane.rs`: it invokes `carrick run` with
`--platform linux/amd64`. The mounted fixture was also attempted through
that exact production path. It exits `125` before guest execution, with
empty stdout and this stderr (preserved with binary hashes in
`production-observation.json`):

```
carrick: unsupported in this backend: hvpatch requires macOS/AArch64 host and AArch64 guest; got host=Linux/Amd64 guest=Amd64
```

`prepare::resolve_plan` calls `page_profile::resolve_execution_plan`, whose
only backend rejects non-macOS/AArch64 hosts and guests. The off-macOS
`PreparedRun::execute` is also an explicit pending-carrier-port refusal.
The production path never reaches the standalone M2 `bringup_fns` loop.

The second VM-free red tested the native final-page boundary with the initial
`2^47` typed limit: `x86_mmap_task_size_guard_matches_native_linux` returned
`0x7ffffffff000` (140737488351232) instead of errno `12`. The x86 arch value
now excludes one 4 KiB guest page (`2^47-4096`), matching the native oracle;
ARM remains exactly `2^48`. The x86 ceiling is therefore the Linux user limit,
not merely the hardware canonical-address boundary.
