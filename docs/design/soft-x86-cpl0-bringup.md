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
| PML4/image/trampoline/maps and metadata: `prepare_boot`, `PreparedBoot` | Shared RAM/image/map preparation and binding initialization retain the original owned allocations. `supervisor_maps`, `lapic_map` and `data_map` live once in `fixture_maps`; KVM re-exports them. |
| Reservations/IPC/file-region/initial extent: `Cpl0Carrier::boot_bytes_inner`, `BootstrapCustody::new` | Move installation around CarrierMemory<M>; reuse anonymous_owner, BootstrapFileRegion and custody. No backend-specific reservation or allocator authority. |

## Minimal seam and staged extraction

1. **Shared descriptor preparation:** `initialize_bootstrap_descriptors(&mut GuestRam,
   &X8664BootSysregs, hardware_interrupts)` in the existing neutral cpl0_boot
   module. It moves GDT/fault/IST/IRQ construction verbatim, modulo indentation,
   before CPU creation/entry. The caller retains bootstrap_sysregs for subsequent
   CPU programming. It needs no new trait: these are writes to already-neutral
   GuestRam, before CarrierMemoryIo registration or CarrierCpuIo admission.
   The two-slot layout stays exactly as KVM currently builds it.
2. **Shared neutral preparation:** `prepare_boot` extracts RAM windows, ELF load/validation,
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
`initialize_bootstrap_descriptors`. `prepare_boot` now owns RAM windows,
ELF loading/validation, page-table and fixture-map preparation, and initial
metadata/bindings. Its `PreparedBoot` retains the original RAM, ELF plan,
table capacity, IPC backings/generation and kernel pod storage by move. KVM
consumes that value before memory registration; registration, installation
and CPU bring-up remain in `Cpl0Carrier::boot_bytes_inner`. The KVM-free
`bootstrap_descriptor_tests::initialize_bootstrap_descriptors_has_exact_bytes`
witness checks GDT, rebased fault gates, private TSS/IST and optional IRQ gates.
Mutation results and transient run populations belong to the PR evidence.
Fixture map geometry and its layout assertions now live in the shared
`cpl0_boot::fixture_maps` module. KVM re-exports the same helpers so boot
and fixture call sites continue to use one implementation. The cross-crate
visibility change is isolated from the inline preparation extraction.
That extraction changes the helper/value boundary and module paths only;
its descriptor evidence is a separate additive-rationale commit.
The native Linux oracle failure is tracked as flaky on main in #2320.
CPUID and VMX segment bindings provide gate coverage; no descriptor-path
coverage (follow-up #2476). The byte witness addresses #2477.
Signed HVF and merge-queue acceptance remain director-owned. #2414 has landing
priority; #2468 stays draft and must rebase after it lands.


### R4 CPU bring-up classification (before extraction)

After `prepare_boot`, VM creation (`KvmVm::create_empty`), CPU allocation
(`CarrierMachine::from_memory`), raw sreg reads/writes and `KvmSegment`
conversion, CPUID ioctl reads, MP-state RUNNABLE admission, MSR ioctl arrays,
TSC-kHz reads and LAPIC register reads/writes are KVM mechanics. They remain
in the adapter, including its readback checks and error messages.

Memory registration, IPC slot binding, fixture copy-window provisioning,
file-region/initial-extent installation, fault-record initialization and
file-binding publication precede CPU creation. These use shared owners but
are outside this CPU-state extraction. Custody construction follows it.

Neutral CPU policy comprises the entry-layout trampoline override, per-slot
RIP/RSP, existing `program_longmode_entry` and `program_fault_segments`
helpers, fixture IF enablement, production SMEP/SMAP requirement and CR4 bits,
direct-map GDTR/IDTR/TR aliases, optional LAPIC base/BSP bits, syscall
LSTAR/STAR/SFMASK and per-slot KERNEL_GS_BASE. The helpers already own the
CR0/CR3/CR4/EFER and segment descriptor definitions: reuse them, do not copy.
CPUID view construction/qualification is already shared in `GuestCpuidView`;
this function only checks installed leaf 7 for production SMEP/SMAP.
TSC conversion and nonzero validation, binding publication, APIC destination
encoding, software-enable vector and route publication are neutral policy
interleaved with KVM observations. No APIC identity may be guessed from slot.

A boot-only provider is justified only with a KVM production caller here;
no unused provider or change to the running snapshot/memory protocols belongs
in R4. Fixture stepping, watchdog, execution and soft-machine selection stay
outside this slice. Any change to setter order or admission semantics requires
a separate behavior change and stops this mechanical lane.


R4 status: `cpl0_boot::boot_cpu::BootCpuState` now computes the desired
per-slot entry values, direct-map descriptor aliases, production CPUID/CR4
masks, LAPIC base/BSP bits and syscall MSRs. Its `program_entry` reuses the
existing shared long-mode/fault-segment helpers, in their original order.
The value retains `CpuId`; programming cannot accept a different slot.
KVM consumes it through the original setters and keeps the same observation,
conversion, readback and MP-state admission. The helper/value boundary is an
isolated extraction commit; the contract rationale follows separately.
The module lives inline in the already-mapped boot surface, avoiding a registry
or gate change for a new file. KVM-free value/recorded-setter witnesses cover
both slots and all fixture/production and interrupt-mode combinations, with
three independent mutation controls. The existing KVM tests are unchanged.
No new provider trait lands: this value has a production caller, but CPU
creation/admission and the observed TSC/LAPIC publication loop remain concrete
KVM operations. A generic boot provider remains a later extraction, requiring
its own production caller and evidence; it does not reuse the running snapshot
protocol. No behavior change, soft-machine work or execution selection is part
of this slice. Signed HVF and final queue acceptance remain director-owned.


### M1-1 status: shared memory installation and initial-MM admission

The neutral boot after `prepare_boot` is now one implementation used by
both backends. `install_boot_memory`, generic over `CarrierMemoryIo`,
holds the memory-registration block that `boot_bytes_inner` used to run
inline: bootstrap windows, IPC backings and slot binding, fixture copy
windows, kernel file region, fault records, initial extent and CPU file
bindings. Only VM creation stays in KVM.

The initial-MM admission (`load_guest_mm`,
`publish_production_reservations`) is generic over `Cpl0BootCarrier`.
This is the boot-only provider the R4 status anticipated, and it has two
production callers. It carries only what the admission needs from a
backend: custody, CPU count, a stopped register read, one `KernelEntry`
and run-to-exit. KVM implements it with its original sregs/MSR/regs
ioctl sequence and production run context. The running snapshot protocol
(`CarrierCpuBackend`) is untouched.

`bind_initial_task_identity`, `bind_execution` and `initial_mm_key` now
live on `BootstrapCustody`, and `initial_extent_bytes_for` and
`unexpected_boot_wake` are shared functions. KVM's methods delegate to
them.

The soft carrier (`carrick-vmm-soft`) implements `CarrierMemoryIo` as
`SoftVm`, a slot table. Its `SoftMmuMemory` places each registered slot
as one linear segment (`LinearPlacement::with_segments`). The soft CPU
therefore translates through the allocations `CarrierMemory` owns; no
bytes are copied. `SoftCarrier` implements `Cpl0BootCarrier` over one
`SoftMachine` and authenticates the admitted initial root for soft walks
before each run.

The probe follows the KVM witnesses' `boot_program_carrier` sequence:
kernel-issued root, birth source, IPC table map, then
`bind_initial_task_identity` and `load_guest_mm`. It boots the production
ring past initial-MM admission. The root runs its `exit_group(7)` syscall
to the first serviced carrier exit, `WORK_PORT` in `carrick_x86_enter`.

Still concrete per backend: stopped-CPU creation and programming
(`BootCpuState` is shared; the setters are not), TSC and APIC identity
publication, MP-state admission, and the peer CPU's start. The soft
carrier is single-vCPU (#2397), refuses MSI, and does not refresh its
placement when slots change at run time. Those, the executor
(`CarrierCpuBackend` over `SoftMachine`) and runtime selection are the
next slices.


### M1-2 status: the soft carrier CPU behind `CarrierCpuBackend`

The production ring now runs a static hello to its exit on soft CPUs.
`SoftCpuBackend` implements `CarrierCpuBackend` over one `SoftMachine`,
and the shared custody claims it as `CarrierCpuIo`. Images go through the
shared `X86Vcpu` snapshot, with a full x87/SSE/AVX XSAVE area. Its runs
enter through `run_production_member`. That function moved from KVM's
`run_member` into the shared host, over a small `ProductionMemberCpu`
trait. It owns the file-execution lease, the shootdown table's
running/ack protocol and the reentry KICK. A soft kick is a flag checked
between blocks. A soft `OUT` has already advanced RIP, so pending I/O
completion has nothing to do. `SoftCpuContext` is `Send`, so executor
worker threads can own it. Its two raw pointers are per-block borrows that
`execute`'s guard clears.

`SoftCarrier::into_worker_parts` builds the shared `ProductionWorkerParts`.
The issued root's state comes from `BootstrapCustody::worker_root_state`,
which also moved out of KVM. The second physical CPU is a stopped soft CPU
in slot 1's boot state. M1 is single-vCPU (#2397), so it is never started.

`tests/soft_hello.rs` drives the root lease of the shared
`ProductionCpuFactory`, as the KVM stopped-worker witnesses in
`cpl0_initial_mm.rs` do. The run takes four steps:

- initial-MM admission, then the root load;
- the forwarded `write`, dispatched by the kernel dispatcher;
- `WORK_PORT`;
- the exit doorbell.

The guest exits 0 with stdout `hello\n`.

Rust std's startup on the bhyve musl hello fixture polls fds 0-2 through
`HostReadinessCrossing`. M1-2 found that only the runtime executor's
host-readiness service answered it (`carrick-runtime`,
`vcpu_loop/executor/cpl0.rs`), so the soft driver refused it and std
aborted.

### M1-3 status: review fixes and the shared readiness service

The independent review's findings on #2518 are fixed, each red first:

- **Memory custody.** The soft memory view (`SoftCarrierMemory`) now owns
  an `Arc` of every backing it places (`SoftBackings`: the bootstrap
  windows' `GuestRam` and each registered `BackingExtent`). Its
  constructor is crate-private and `unsafe`, and it refuses a
  registration the backings do not retain. A soft CPU no longer depends
  on a carrier's custody for liveness. The witness swaps two carriers'
  custodies and drops one; before the fix it died with `SIGSEGV`.
- **JIT high-byte forms.** The high-byte stand-in is chosen after the
  memory operand is rebased on R14. A virtualized RSP beside a high-byte
  register is hosted in a legacy register.
- **Probe rows** each assert their own expected exit.
- **Setter state.** `SoftBootVcpu` refreshes the TLB mode tag on RFLAGS,
  recomputes `EFER.LMA` on CR0, and installs the FS/GS descriptor base.

The neutral part of the readiness service moved, as new code, into
`carrick-x86-cpl0-host::host_readiness`:

- the crossing decode;
- the host-owned stdio descriptor table;
- the one-shot host `poll` sample over the task's supervisor batch;
- the remaining-wait decision.

Parking a waiting task stays with the executor. The soft hello driver
answers the crossing through it. The runtime executor's delegation to the
module is a `carrick-runtime` hunk for the director.

The musl hello now boots to: the readiness crossing answered with 0, then
two `OWNER_GRANT_PORT` (`0xd1`) doorbells. It fails at a fault loop in the
ring (`dispatch_classified_fault` -> `FaultSupply::editor` ->
`descriptor_txn::Planner::edit`, once per ~512 soft blocks). The owner
grants install carrier slots after boot. The soft memory view
authenticates and places only the slots it saw at boot, so every touch of
a granted frame faults again. Admitting run-time slots needs the view to
retain their backings. That means a read of the `CarrierMemory` slot
backings, which `carrier_memory.rs` does not expose today.

Still open:

- the soft peer CPU's start and the APIC cluster;
- MSI;
- placement and extent refresh, with retained backings, when slots
  change at run time (the musl hello's frontier);
- soft-walk admission of roots other than the CPU's current CR3;
- runtime selection (`--vcpu soft`).
