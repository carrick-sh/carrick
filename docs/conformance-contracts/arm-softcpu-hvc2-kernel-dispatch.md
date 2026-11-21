# Soft AArch64 single-process HVC #2 production kernel dispatch

`arm.softcpu.hvc2-kernel-dispatch` covers single-process `HVC #2` syscall
routing from the soft AArch64 CPU (`carrick-softcpu-aarch64` +
`carrick-softcpu-aarch64-host`) through the shared AArch64 engine
(`Aarch64EngineCore<SoftAarch64Vmm>`) into production `carrick-kernel`
(`SyscallDispatcher`) and `carrick-personality-linux` (`#1236` M2 R1).

## Architectural invariants

- **One AArch64 trap and stage-1 lane**: `SoftAarch64Engine` is
  `Aarch64EngineCore<SoftAarch64Vmm>`, sharing stage-1 `PageTableManager`
  mutation, `LINUX_EL1_MAINT_BASE` `HVC #1` TLBI maintenance, `MapHostAlias`
  stage-2 alias installation, `GuestMemory` user copy, and
  `Aarch64SyscallMailbox` `HVC #2` request/response framing with HVF and KVM.
- **4 KiB stage-2 extent authority**: `SoftStage2` separates 4 KiB logical
  guest stage-2 pages (`carrick-softmmu::ExtentTable`) from host OS backing
  granularity (`MappingGeometry`), enforces independent R/W/X permissions on
  guest data and instruction fetch (`GuestMemory::fetch`), and bumps
  `ExtentTable` code generations on both guest stores and host writes.
- **Zero fixture syscall replies**: dynamic glibc hello (`CARRICK_A64_DYN_ROOT`)
  and static musl hello (`musl_hello.rs`) run to `exit_group(0)` with
  `fixture_answered == 0`, while any ring-refused startup syscall (`ENOSYS` in
  `EL1_COUNTERS_BASE`) is sampled and asserted explicitly.

## Witnesses

- Cross-ISA (`x86_64` and `aarch64`):
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_facade_serves_single_process_hvc2_syscalls_via_production_kernel`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_stage2_enforces_execute_permission_and_extent_code_generations`
  - `carrick-aarch64::mailbox::tests::mailbox_slot_round_trips_request_and_response`
  - `carrick-aarch64::mailbox::tests::hvc_immediates_classify_canonically`
- Native Linux `aarch64` (`soft-aarch64-native`):
  - `carrick-softcpu-aarch64-host::boot_probe::soft_cpu_runs_dynamic_glibc_hello_through_production_dispatch`
  - `carrick-softcpu-aarch64-host::boot_probe::soft_cpu_runs_static_musl_hello_through_production_dispatch`
