# Standalone x86 KVM run-elf retirement

The production x86 Linux CLI lane uses the shared `carrick-el1` kernel at
CPL0, with receipt backend `kvm-x86-cpl0`. The former per-process `KvmVmm`
and its host `Pml4Manager` editor are removed. KVM register ioctl marshalling
moves unchanged into `vcpu_x86`; this adapter owns no RAM or page tables.
The bhyve/NVMM engines and their shared `carrick-x86` implementation remain
unchanged.

The applicable production contract is `x86.carrier.cli-run`. Native Linux
execution of each exact ELF supplies output and exit-status authority. The
retirement invariant is zero standalone KVM x86 service-loop callers and
zero host PTE editors in the deleted engine. The standalone polling contract
`x86.run-elf.poll` continues to cover bhyve/NVMM and its existing VM-free
budgets; KVM's migrated live binding belongs to the production contract.

## Removed executable surfaces

| Surface | Disposition |
| --- | --- |
| `carrick-vmm-kvm run-elf <x86-elf>` | Removed execution entry. The executable remains for byte-identical ARM run-elf; its x86 main exits 1 and names `carrick run --platform linux/amd64` and the shared CPL0 kernel. |
| `examples/syscall_round_trip.rs` | Deleted. It benchmarks the retired two-instruction LSTAR/host-service boundary; that ratio does not describe shared-kernel execution. No replacement performance claim. |
| `src/run_elf_x86.rs` | Deleted; no KVM caller of the shared standalone service loop remains. |
| `src/kvm_x86_engine.rs` | Deleted per-process VM, RAM, host PTE authoring, host-fork rebuild and bring-up. Register-only functions retained in `src/vcpu_x86.rs` for carrier custody and boot. |
| `src/guest_setup_x86.rs` | Deleted identity-layout RAM builder, layout-only constants and hand-coded blob. Stopped-CPU layout lives with its register adapter; CPL0 boot owns production layout. |

## Every removed or migrated test

| Previous test | Replacement or reason |
| --- | --- |
| `live_vcpu_x86::test_m01_syscall_round_trip` | CLI `x86_kvm_run::mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel`: exact hello output and exit status, native ELF authority, production CPL0 receipt and shared-kernel entries/forwards. It also proves nonzero guest exit propagation. |
| `live_vcpu_x86::test_m2_musl_static_hello` | CLI `x86_kvm_run::musl_static_hello_runs_through_shared_kernel`: same Rust/std musl source and committed expected bytes, rebuilt in a private temporary directory, native execution plus production CPL0 receipt. Missing fixture build is a failure rather than a silent skip. |
| `guest_setup_x86::tests::gdt_selector_encoding` | Moved to `vcpu_x86::tests`; preserves STAR-derived selector checks. |
| `guest_setup_x86::tests::segment_type_accessed_bits` | Moved to `vcpu_x86::tests`; asserts the actual shared segment-state values used by the adapter, including accessed bits. |
| `guest_setup_x86::tests::cr0_cr4_efer_bit_patterns` | Moved to `vcpu_x86::tests`; preserves bootstrap control-register checks. |
| `guest_setup_x86::tests::sfmask_masks_interrupts` | Moved to `vcpu_x86::tests`; preserves syscall-entry IF masking check. |
| `guest_setup_x86::tests::high_region_window_covers_full_mmap_arena` | Dropped with the private identity-layout RAM builder it tested. Production carrier memory uses typed custody/backing registration, already covered by `carrier_memory` and `cpl0_initial_mm`. |
| `guest_setup_x86::tests::high_region_window_preserves_shared_aperture_kind` | Dropped with the same deleted RAM builder; its standalone host `WindowKind` projection is not a CPL0 interface. Carrier-memory ownership/alias tests remain. |
| `guest_setup_x86::tests::m01_blob_msg_offset` | Dropped with the hand-coded blob; the CLI fixture is executed natively and through CPL0 with exact output checks, which proves its message addressing. |

No tests were defined in `kvm_x86_engine.rs`, `run_elf_x86.rs` or the deleted
example. Existing carrier CPU readback, two-context VM-free custody and CPL0
entry/lifecycle/progress/MM tests remain. A new
`retired_x86_entry::standalone_x86_entry_names_shared_kernel_replacement`
checks the old executable's precise refusal and replacement message.

## Evidence

On pre-retirement `afd08480f`, the refusal regression exits 127 after trying
to load `missing.elf`, versus required retirement exit 1. The structural red
audit finds the legacy `edit_page_tables` implementation, its six mutation
call sites, `impl X86Vmm for KvmVmm`, bring-up callers and run-elf entry.
Logs are under `target/x86-legacy-retire/` on the worker host.

Final focused gate results and source revision are recorded in the draft PR.
Linux worker scope excludes Docker and signed HVF acceptance; the director
owns those higher-layer gates and full stacked-batch acceptance. This
retirement does not claim full x86 conformance or production readiness.

## TLS prerequisite found by the migration

The migrated musl test first refused native syscall 158 (`arch_prctl`) on
PR #81 head `6fade63a8`; native execution succeeded. Its replacement is in
the shared kernel's x86 context leaf, classified through the same no_std
syscall-table source used by `carrick-abi` and the guest personality.
FS/GS SET edits the typed parked-context TLS projection and writes FS_BASE
or the user KERNEL_GS_BASE before the same task resumes. GET uses the existing
exact-task guarded copyout. CPL0's GS binding stays active during handling.

The [arch_prctl manual](https://man7.org/linux/man-pages/man2/arch_prctl.2.html)
and native Linux are the semantic authority. On this host, invalid GET
pointers return errno 14, supervisor SET addresses return errno 1, and unknown
operations return errno 22. Native CPUID GET returns 1 and SET returns errno
19; the CPL0 lane keeps native CPUID enabled and lacks CPUID faulting.
The live TLS fixture checks FS/GS loads and GETs, failed SET preservation,
GET errno 14 and unknown errno 22, with exactly two host forwards (write and
exit). The VM-free context edit was red before the leaf existed.

The production initial lane still lacks `ZoneRecord` custody. Its private
TLS projection never becomes a runnable scheduler context; full production
scheduler custody remains an x86-run open item. This change does not invent
another task-context registry.

## Preserved red dependency

With TLS implemented, the same musl fixture exposed native `set_tid_address`
(218). The shared personality now registers the typed user pointer in the
calling thread's existing lifecycle control slot and returns its Linux-visible
TID. It authenticates a born-in-zone pool entry and incarnation separately
from that visible TID. A VM-free red-first test registers after clone without
`CLONE_CHILD_CLEARTID`, then exercises existing shared `serve_exit`: clear
before one wake and retirement, with another MM untouched. The ARM entry
routing remains unchanged.

The migrated musl CLI test remains red at native `poll` (7). Production
shared host-dispatch binding and real scheduler/futex exit custody are tracked
dependencies on [PR #81's x86-run follow-up](https://github.com/carrick-sh/carrick/pull/81).
The initial host exit refuses a registered clear-tid pointer until that
custody exists; it never reports successful exit while omitting the clear.
This retained test has no ignore, retry, timeout increase or reduced concurrency.
