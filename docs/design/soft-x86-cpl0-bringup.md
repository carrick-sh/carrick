# Soft x86 CPL0 bring-up: existing mechanisms and extraction

Part of #671 / #578 step 2b; R3. References below name functions and types in the
shared host coordinator and KVM adapter.
Clean room: Carrick code and Intel SDM only; no external implementation source.
No instruction-semantics web search was used.

## Existing mechanisms

The accepted [soft backend design](../superpowers/specs/2026-10-17-soft-backend-design.md)
step 2b and #1486 G4/L4 require the real ring bytes, not a host-code ring or
user-mode fake syscall harness. #671 remains open until static hello boots
through `carrick run --vcpu soft` without KVM and the fixture suite agrees.

The neutral host crate already exports the coordinator (`src/lib.rs`),
`CarrierCpuBackend` (`carrier_cpu.rs`) and the sealed `CarrierCpuIo`
(`carrier_cpu.rs`). `claim_carrier_cpu_io` owns backend admission; do not
implement a second executor. It covers snapshot read/write, VcpuExit, pending
I/O, kick arm/disarm, slot identity, MSRs and FS base. `CarrierMemoryIo`
(`carrier_memory.rs`) covers slot limit, registration and MSI; the generic
`CarrierMemory` owns extents, identities, roots and publication/retirement.
`ProductionCpuLease`, `ProductionCpuFactory`, and `BootstrapCustody` already
live in neutral `cpl0_boot.rs`; KVM aliases them at `cpl0_boot.rs`.
Keep their authority and teardown ordering unchanged.

The remaining `Cpl0Carrier` is concrete (`vmm-kvm/src/cpl0_boot.rs`):
`boot`/`boot_with_interrupts` load fixture paths;
`boot_production` includes the built image; `boot_production_image` validates
extent size. All converge on `boot_bytes_inner`.

### Backend disposition

Paths in this table are under `crates/`. A “soft counterpart” is follow-up,
not code introduced in R1. Neutral protocol/policy moves; ioctl mechanics stay.

| Mechanism and current sites | Disposition |
| --- | --- |
| VM creation / memslots: `KvmVm::create_empty`, `CarrierMemory::install_bootstrap` | KVM registration stays. RAM window selection and shared `CarrierMemory<M>` installation move. Soft implements slot registration over retained extents, preserving backing identities and lifetime. |
| In-kernel irqchip: `KvmVm::create_empty`; LAPIC/APIC route discovery in `Cpl0Carrier::boot_bytes_inner` | KVM irqchip ioctls stay; soft counterpart is ApicCluster. Route publication and guest binding are neutral. |
| Secondary SIPI admission: `Cpl0Carrier::boot_bytes_inner` | KVM MP-state transition stays; soft creates stopped CPU state directly. No emulated SIPI required for M1. |
| MSI: `CarrierMemoryIo::signal_msi` | KVM_SIGNAL_MSI stays behind CarrierMemoryIo. Soft queues the corresponding ApicCluster event. |
| Guest-debug stepping: `Cpl0Carrier` | KVM fixture debugger stays; no shared ioctl-shaped API. |
| vCPU allocation/run/exits: `CarrierMachine::from_memory`, `CarrierCpuBackend` | KVM handles and exit conversion stay. Soft drives SoftMachine through the existing owned CarrierCpuIo protocol. |
| MSR/sysreg/segment setup: `Cpl0Carrier::boot_bytes_inner`, `program_longmode_entry`, `program_fault_segments` | Register encoding/ioctls stay. Desired long-mode state, private IDT/TSS aliases, syscall entry and KERNEL_GS_BASE are neutral boot policy. |
| CPUID: `GuestCpuidView`, `Cpl0Carrier::boot_bytes_inner`, `fixture_cpuid_with_tsc_hz` | KVM CPUID installation stays. Move required-feature validation with boot policy; reuse the existing guest view. |
| TSC: `Cpl0Carrier::boot_bytes_inner`, `fixture_publish_tsc_hz` | KVM_GET_TSC_KHZ stays. Frequency publication into CpuBinding is neutral; soft supplies its clock/view frequency. |
| Kick/signal/watchdog: `FixtureWatchdog`, `CarrierCpuBackend` | KVM thread signal/immediate_exit stays. Soft sets durable cancellation checked at block boundaries. |
| GDT/fault stubs/IDT/TSS/IST/IRQ gates: `initialize_bootstrap_descriptors` | Shared byte construction uses existing carrick-x86 layout/descriptor helpers. Neither backend reimplements the bytes. |
| PML4/image/trampoline/maps and metadata: `Cpl0Carrier::boot_bytes_inner` | Move RAM/image/map preparation and binding initialization next. Move `supervisor_maps`, `lapic_map` and `data_map` from carrier_interrupts; never copy them. |
| Reservations/IPC/file-region/initial extent: `Cpl0Carrier::boot_bytes_inner`, `BootstrapCustody::new` | Move installation around CarrierMemory<M>; reuse anonymous_owner, BootstrapFileRegion and custody. No backend-specific reservation or allocator authority. |

## Minimal seam and staged extraction

1. **This landable:** `initialize_bootstrap_descriptors(&mut GuestRam,
   &X8664BootSysregs, hardware_interrupts)` in the existing neutral cpl0_boot
   module. It moves GDT/fault/IST/IRQ construction verbatim, modulo indentation,
   before CPU creation/entry. The caller retains bootstrap_sysregs for subsequent
   CPU programming. It needs no new trait: these are writes to already-neutral
   GuestRam, before CarrierMemoryIo registration or CarrierCpuIo admission.
   The two-slot layout stays exactly as KVM currently builds it.
2. **Remaining neutral preparation:** extract RAM windows, ELF load/validation,
   PML4/trampoline/fixture maps and metadata/bindings into an owned prepared-boot
   value; retain the ELF plan, table capacity, IPC backings/generation and pod
   storage without copies. Move fixture map helpers, not their implementations
   into a second module. Install the value through CarrierMemory<M>, initialize
   file-region/reservations, and construct BootstrapCustody<M>.
3. **Remaining CPU bring-up:** a small boot provider creates stopped CPUs from
   that memory owner, installs desired descriptor/control state, reports TSC
   frequency and APIC identity, and admits execution. Separate this boot-only
   surface from CarrierCpuBackend's running snapshot protocol; existing HvVcpu /
   X86Vcpu helpers supply long-mode setup. Concrete KVM ioctl conversion remains
   in KVM. Do not relocate fixture stepping, watchdog or unrelated custody work.
4. **Follow-up soft slice:** create carrick-vmm-soft implementing
   CarrierCpuBackend (claimed as CarrierCpuIo) over SoftMachine, plus
   CarrierMemoryIo over soft memslots and ApicCluster MSI. Reuse the prepared
   image, neutral custody, factories, executor protocol and exact ring artifact.
   M1 is **single-vCPU**: #2397 blocks parallel shared-inventory admission until
   code-activation revocation waits for running peers. Do not infer SMP safety
   from serialized ExtentTable tests or start a peer to satisfy a two-CPU API.
   Parameterizing CPU count is a separate behavioral change after the pure move.
5. **Follow-up selection slice:** add ExecutionBackend::SoftX86Cpl0 alongside
   KvmX86Cpl0 (`carrick-kernel/src/page_profile.rs`), runtime factory selection,
   `--vcpu hardware|soft|auto` and CARRICK_VCPU. Auto chooses soft only for absent
   hypervisor capability, never after a hardware error. Keep exec-backend hvpatch
   orthogonal. Follow with static hello and hosted soft-x86 receipt integration.

## Overlap, evidence and authority

At start, all five boot functions were compared against each PR's merge base:
#2263, #2380, #2343, #2369 and #2414 leave them byte-identical. Their unrelated
custody/service changes are outside this slice. #2414 has landing priority;
this PR stays draft, never enters the queue ahead of it, and must rebase after
it merges. Repeat the comparison before push.

R1c classifies this extraction as a helper/signature boundary change, not
an automatic whole-function move exemption. The isolated extraction commit
names all eight affected families and the existing witnesses run:
`kernel.el1.ipc-two-process`, `kernel.el1.thread-lifecycle`,
`kernel.x86.file-region`, `x86.cpuid.v3`, `x86.mm.initial-image`,
`x86.vmx.segment-entry`, `kernel.native.entropy`, and
`kernel.native.host-file-venue`. Their descriptor rationale records the
selected bound witnesses without weakening semantics, bindings or budgets.
Intel SDM vol. 3 remains the descriptor layout authority. The byte witness
below checks unchanged descriptor writes with explicit mutation controls.

R3 status: descriptor construction is shared through
`initialize_bootstrap_descriptors`; remaining neutral preparation and CPU
bring-up are still in `Cpl0Carrier::boot_bytes_inner`. The KVM-free
`bootstrap_descriptor_tests::initialize_bootstrap_descriptors_has_exact_bytes`
witness checks GDT, rebased fault gates, private TSS/IST and optional IRQ gates.
Mutation results and transient run populations belong to the PR evidence.
Fixture map geometry and its layout assertions now live in the shared
`cpl0_boot::fixture_maps` module. KVM re-exports the same helpers so boot
and fixture call sites continue to use one implementation. The cross-crate
visibility change is isolated from the remaining preparation extraction.
The native Linux oracle failure is tracked as flaky on main in #2320.
CPUID and VMX segment bindings provide gate coverage; no descriptor-path
coverage (follow-up #2476). The byte witness addresses #2477.
Signed HVF and merge-queue acceptance remain director-owned. #2414 has landing
priority; #2468 stays draft and must rebase after it lands.
