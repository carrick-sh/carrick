# Soft x86 CPL0 bring-up: existing mechanisms and extraction

Part of #671 / #578 step 2b; R1, 2026-11-17. Source inventory taken at
GitHub main 51c981ab4bbc550c24f18982713ccec671c538fc. References below name
source locations at that revision, not a maintained line-pinned inventory.
Clean room: Carrick code and Intel SDM only; no external implementation source.
No instruction-semantics web search was used.

## Existing mechanisms

The accepted [soft backend design](../superpowers/specs/2026-10-17-soft-backend-design.md)
step 2b and #1486 G4/L4 require the real ring bytes, not a host-code ring or
user-mode fake syscall harness. #671 remains open until static hello boots
through `carrick run --vcpu soft` without KVM and the fixture suite agrees.

The neutral host crate already exports the coordinator (`src/lib.rs:7`),
`CarrierCpuBackend` (`carrier_cpu.rs:97`) and the sealed `CarrierCpuIo`
(`carrier_cpu.rs:123`). `claim_carrier_cpu_io` owns backend admission; do not
implement a second executor. It covers snapshot read/write, VcpuExit, pending
I/O, kick arm/disarm, slot identity, MSRs and FS base. `CarrierMemoryIo`
(`carrier_memory.rs:31`) covers slot limit, registration and MSI; the generic
`CarrierMemory` owns extents, identities, roots and publication/retirement.
`ProductionCpuLease`, `ProductionCpuFactory`, and `BootstrapCustody` already
live in neutral `cpl0_boot.rs`; KVM aliases them at `cpl0_boot.rs:65-71`.
Keep their authority and teardown ordering unchanged.

The remaining `Cpl0Carrier` is concrete (`vmm-kvm/src/cpl0_boot.rs:287`):
`boot`/`boot_with_interrupts` (729/737) load fixture paths;
`boot_production` (747) includes the built image; `boot_production_image`
(758) validates extent size. All converge on `boot_bytes_inner` (1777-2605).

### Backend disposition

Paths in this table are under `crates/`. A “soft counterpart” is follow-up,
not code introduced in R1. Neutral protocol/policy moves; ioctl mechanics stay.

| Mechanism and current sites | Disposition |
| --- | --- |
| VM creation / memslots: `carrick-vmm-kvm/src/cpl0_boot.rs:2312-2316`, `carrier_memory.rs:24-40`; shared custody in `carrick-x86-cpl0-host/src/carrier_memory.rs:31` | KVM registration stays. RAM window selection and shared `CarrierMemory<M>` installation move. Soft implements slot registration over its retained extent table, preserving backing identities and lifetime. |
| In-kernel irqchip: `carrick-vmm-kvm/src/kvm.rs:1169`; LAPIC state / APIC base and route discovery at `cpl0_boot.rs:2472,2546-2590` | KVM irqchip ioctls stay; soft counterpart is ApicCluster. Route publication and guest binding are neutral. |
| Secondary SIPI admission: `carrick-vmm-kvm/src/cpl0_boot.rs:2485-2494,3899` | KVM MP-state transition stays; soft creates stopped CPU state directly. No emulated SIPI required for M1's single CPU. |
| MSI: `carrick-vmm-kvm/src/carrier_memory.rs:43-60`, `cpl0_boot.rs:220,2705,2888` | KVM_SIGNAL_MSI stays behind CarrierMemoryIo. Soft signal_msi queues the corresponding ApicCluster event. Shared wake/shootdown protocol must use that seam. |
| Guest-debug stepping: `carrick-vmm-kvm/src/cpl0_boot.rs:3050-3082` | KVM fixture debugger stays; no shared ioctl-shaped API. Soft diagnostics use bounded block execution and typed exits if a later fixture needs stepping. |
| vCPU allocation/run/exits: `carrick-vmm-kvm/src/carrier_memory.rs:79-95`, `cpl0_boot.rs:267,2420`, `carrier_cpu.rs:20-95` | KVM handles and exit conversion stay. Shared coordinator uses owned CarrierCpuIo, soft counterpart drives SoftMachine and converts run results into VcpuExit. |
| MSR/sysreg/segment setup: `carrick-vmm-kvm/src/cpl0_boot.rs:2434-2523`; fixture retarget at 1136-1175 and 1604-1633 | Register encoding/ioctls stay. Desired long-mode state, private IDT/TSS aliases, syscall entry and KERNEL_GS_BASE are neutral boot policy; soft installs the same values. Existing CarrierCpuBackend handles running snapshots/MSRs; boot also needs descriptor/control-state installation. |
| CPUID: `carrick-vmm-kvm/src/kvm.rs:1137,1527`; production SMEP/SMAP check at `cpl0_boot.rs:2442-2458`, fixture overrides at 2636-2672 | KVM CPUID installation stays; reuse existing GuestCpuidView on soft. Move required-feature validation with boot policy, not a new host-derived view. |
| TSC: `carrick-vmm-kvm/src/cpl0_boot.rs:2527-2544,2616`; `kvm.rs:1102-1118` | KVM_GET_TSC_KHZ stays. Frequency publication into CpuBinding is neutral; soft supplies its clock/view frequency. Do not alter KVM's clock. |
| Kick/signal/watchdog: `carrick-vmm-kvm/src/cpl0_boot.rs:96-118,2931,3195,3715`; `carrier_cpu.rs:89-95`, `kvm.rs:673` | KVM thread signal/immediate_exit stays. Existing CarrierCpuBackend kick protocol is shared; soft kick sets durable cancellation checked at block boundaries. Never use host signals as soft guest faults. |
| GDT/fault stubs/IDT/TSS/IST/IRQ gates: `carrick-vmm-kvm/src/cpl0_boot.rs:2087-2180` | Move byte construction into neutral host crate, using existing carrick-x86 layout/descriptor helpers. Neither backend reimplements these bytes. |
| PML4/image/trampoline/maps: `carrick-vmm-kvm/src/cpl0_boot.rs:1787-2085`; initial binding/metadata at 2181-2310 | Move RAM/image/map preparation and binding initialization next. Fixture interrupt map helpers in carrier_interrupts must move first or be passed as data, never copied. |
| Reservations/IPC/file-region/initial extent: `carrick-vmm-kvm/src/cpl0_boot.rs:1965-2000,2317-2418`; neutral `BootstrapCustody::new` | Move installation around CarrierMemory<M>; reuse anonymous_owner, BootstrapFileRegion and custody. No backend-specific reservation or allocator authority. |

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
   KvmX86Cpl0 (`carrick-kernel/src/page_profile.rs:20`), runtime factory selection,
   `--vcpu hardware|soft|auto` and CARRICK_VCPU. Auto chooses soft only for absent
   hypervisor capability, never after a hardware error. Keep exec-backend hvpatch
   orthogonal. Follow with static hello and hosted soft-x86 receipt integration.

## Overlap, evidence and authority

At start, all five boot functions were compared against each PR's merge base:
#2263, #2380, #2343, #2369 and #2414 leave them byte-identical. Their unrelated
custody/service changes are outside this slice. #2414 has landing priority;
this PR stays draft, never enters the queue ahead of it, and must rebase after
it merges. Repeat the comparison before push.

The move exemption in docs/conformance-contracts.md applies to the two exact
cpl0_boot.rs paths in this slice: same constants, loops, ordering, writes and
errors; only a borrowed RAM/boot-register helper boundary is introduced.
Affected existing families include kernel.el1.thread-lifecycle,
kernel.x86.file-region and x86.carrier.cli-run. Intel SDM vol. 3 is the descriptor
layout authority; existing KVM boot witnesses remain the behavior authority.
There is no deliberately failing semantic witness for a behavior-neutral move.
No test is renamed or removed. Check moved-block equality, one implementation,
contract-change classification, and source/range authority-debt ratchets; record
an authority-moves entry only if a nonzero cohort actually moves. Never raise a
ceiling. Runtime evidence and any failed checks are reported separately on the PR.
