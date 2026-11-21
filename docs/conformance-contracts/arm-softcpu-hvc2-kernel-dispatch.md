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
- **Zero fixture syscall replies (`Hvc2ReplyCensus`)**: dynamic glibc hello
  (`CARRICK_A64_DYN_ROOT`) and static musl hello (`musl_hello.rs`) run to
  `exit_group(0)` with `reply_census.fixture_answers == 0` and
  `reply_census.production_answers == syscalls_dispatched` counted at the
  `HVC #2` completion boundary. Calls not yet wired for single-process soft
  bring-up (`set_tid_address` 96 and `prlimit64` 261 pending `#2645`, `rseq`
  293 per `#1906`, and timer/signal syscalls refused fail-closed with `-ENOSYS`)
  are sampled in `counted_enosys` rather than faked.
- **Shared host-carrier stage-1 alias inventory, first-touch, and owner wait**:
  `carrick_kernel::dispatch::carrier_loop` owns alias `FrameInventoryCommit`
  publication, post-publish stage-1 protection/sharing/`SIGBUS` tail commit,
  first-touch + `MAP_GROWSDOWN` + stale-leaf retry, and `ReservationBusy`
  owner-release enrollment (`PortalWaitEnrollment::park_host`, probe-once, then
  sleep without `yield_now()` polling), shared with `carrick-runtime`.
- **Stage-1 and stage-2 permission and unmap enforcement**: stores after
  `mprotect(..., PROT_READ)` terminate with `SIGSEGV` (`SEGV_ACCERR`) leaving
  read-only contents intact, and accesses after `munmap` terminate with
  `SIGSEGV` (`SEGV_MAPERR`).

## Witnesses

- Cross-ISA (`x86_64` and `aarch64`):
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_facade_serves_single_process_hvc2_syscalls_via_production_kernel`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_single_process_refuses_timer_and_signal_syscalls_with_counted_enosys`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_carrier_enforces_single_live_aperture_and_compare_clears`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_single_process_store_after_mprotect_prot_read_faults_with_segv_accerr`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_single_process_access_after_munmap_faults_with_segv_maperr`
  - `carrick-softcpu-aarch64-host::soft_dispatch_witness::soft_stage2_enforces_execute_permission_and_extent_code_generations`
  - `carrick-aarch64::esr::tests::lowers_el0_aborts_and_debug_faults_to_linux_signal_triples`
  - `carrick-aarch64::mailbox::tests::mailbox_slot_round_trips_request_and_response`
  - `carrick-aarch64::mailbox::tests::hvc_immediates_classify_canonically`
  - `carrick-kernel::dispatch::carrier_loop::tests::apply_first_touch_enforces_linux_stage1_access_matrix`
  - `carrick-kernel::dispatch::carrier_loop::tests::owner_memory_wait_parks_once_on_reservation_busy_and_resumes_after_release`
- Native Linux `aarch64` (`soft-aarch64-native`):
  - `carrick-softcpu-aarch64-host::boot_probe::soft_cpu_runs_dynamic_glibc_hello_through_production_dispatch`
  - `carrick-softcpu-aarch64-host::boot_probe::soft_cpu_runs_static_musl_hello_through_production_dispatch`
