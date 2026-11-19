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

### M1-4 status: one build recipe, and the run-time slot refresh design

**Build recipe.** The nested `cargo build -p carrick-x86-cpl0` recipe
moved out of `carrick-vmm-kvm/build.rs` into `carrick-vmm-kvm/cpl0_build.rs`,
beside `cpl0_inputs.rs`. Both build scripts `#[path]`-include it and call
`build_images`. The only parameter is whether `CARRICK_X86_CPL0_TEST_IMAGE`
is published (KVM yes, soft no). Each build script still reads its own
cargo environment and passes `std::fs::copy` in. The authority-debt census
refuses an authority site in a file two build programs compile ("ambiguous
compilation-target owner"), so the shared file holds none. The same rule
already refuses `cpl0_inputs.rs`'s `std::fs` sites under `--base` (see the
PR evidence).

**Run-time slots (the musl hello frontier).** Owner grants
(`service_anonymous_grant`, via `CarrierMemory::prepare` -> `install`) add
carrier slots while the CPU is stopped at `OWNER_GRANT_PORT`. `SoftVm`
records each registration, but `SoftCarrierMemory` placed and
authenticated only the slots it saw at construction. The refresh reuses
existing mechanisms and adds none:

1. **Retained backings.** The view may place only memory it retains
   (`SoftBackings::retains`, the M1-3 custody fix). A granted slot's
   `Arc<BackingExtent>` lives only in `CarrierMemory`'s private `Slot`
   table. The additive read-only accessor
   `CarrierMemory::retained_backings() -> impl Iterator<Item = &Arc<BackingExtent>>`
   must yield `slot.backing.extent` for every installed slot, bootstrap
   windows included (their extents retain the `GuestRam`). It must not
   expose `Slot`, handles or identities. This needs the director's ruling on
   `carrier_memory.rs`.
2. **Who feeds it.** The view's `SoftBackings` becomes a shared handle
   (`Arc<Mutex<..>>`) held by every soft view of the carrier (slot 0 and
   the peer). After any crossing the custody serves under `with_stopped_io`
   (owner grant, fork stock, child retire), the soft driver (the
   `soft_hello` driver now, the runtime's soft executor later) copies the
   accessor's `Arc`s into that handle. Missing that step fails closed: the
   refresh refuses an unretained registration rather than placing it.
3. **Refresh point.** `SoftCpuBackend::run_guest` already calls
   `admit_current_root` before each run. It first calls a new
   `SoftCarrierMemory::refresh(&SoftVm)`, which compares the view's placed
   `CarrierMemoryRegion`s with `SoftVm`'s, keyed by slot. For each new
   region it checks `retains`, rebuilds the `LinearPlacement` from the full
   segment list (`LinearPlacement::with_segments`; `SoftVm`'s slot limit is
   `MAX_PLACEMENT_SEGMENTS`, so it never overflows), and authenticates the
   extent with `ExtentTable::install(ExtentRecord::new(.., BOOT_GENERATION))`.
   That is the walker's existing extent authentication, as at boot. A
   removed or changed slot fails closed for now. Its retirement path is
   `ExtentTable::remove` with a `SoftRequester` and the seat's
   `PendingRetirement`/`reclaim`, and that is a later slice (fork-child
   retirement needs it).
4. **Flush.** After a refresh that changed anything, the backend calls
   `SoftCpu::flush_tlb` (the `mov cr3`-style local flush). Old segments keep
   their host addresses, so cached translations stay valid. The flush is
   there because the placement object itself was replaced. Additions need no
   code-page work: `ExtentTable` marks code pages per frame, and no frame of
   a new extent can have a translated block. Removals clear their span's
   code pages inside `ExtentTable::remove`.

`soft_hello.rs::production_ring_runs_musl_hello_to_exit_on_soft_cpu`
(now `#[ignore]`d) becomes the red-first
witness on the production run path: today it fails at the fault loop, and
it must pass once the accessor lands. No soft-side code lands before the
ruling, because a refresh with no production caller would be an unused
second path.

### M1-5 status: owner-granted slots reach the software MMU

The stopped host service publishes the current slot snapshot under the
existing custody lock. Each published registration matches the retained
allocation's GPA, length and host base. Each soft CPU view holds its own
reference to the snapshot, so subsequent unregisters or custody changes
cannot free memory the view still addresses. A registration invalidates
the publication until custody supplies its backing.

Before entering the guest, the soft backend keeps the same walker
inventory and adds an extent only for each newly installed slot. A new
snapshot rebuilds placement only when slots were added. The subsequent
local TLB flush includes instruction fetch. Cached blocks re-authenticate
their code frames and generations on their next entry. At M1-5 a removed
or replaced slot stopped the soft carrier before re-entry.

The fixture-independent anonymous-page test exhausted the unchanged
4,000,000-block budget after two owner grants before the refresh. It now
prints `hello\n` and exits 0. The separately built musl hello completes
its startup poll, takes four owner grants, prints
`hello, x86_64 world\n` and exits 0 through the production soft ring.

### M1-6 status: fork and raw thread exit

The musl hello stays opt-in. Its source and lockfile are in-tree and the
standalone fixture builds offline with an installed musl Rust target. The
shared CPL0 build recipe invokes Cargo for the freestanding image and its
test-support sibling. Embedding the musl user ELF would add a separate build
invocation and artifact copy to that recipe or the soft build script. That
build authority is outside this round's scope.

Two existing static assembly fixtures exercise the production soft ring.
The fork fixture makes the parent wait for its child, which writes `E` and
exits before the parent reaps it and exits 7. The `TWO_LIVE` fixture holds a
sibling live while another worker performs raw `exit`, joins both via their
clear-child-tid words, and exits 0. Direct Linux execution produced both
expected results. These are diagnostic fixtures for the existing
`kernel.el1.fork-cow` and `kernel.el1.thread-lifecycle` surfaces.

From the repository root, build and run the raw-exit diagnostic:

```sh
mkdir -p target/soft-lifecycle
cc -nostdlib -static -no-pie -Wl,--build-id=none -DTWO_LIVE \
  crates/carrick-vmm-kvm/tests/fixtures/native_robust_raw_exit.S \
  -o target/soft-lifecycle/raw-exit
cargo test --locked -p carrick-vmm-soft --test soft_hello -- \
  production_ring_non_last_threads_raw_exit --ignored --exact
```

- Before the fix, fork reached initial MM admission, root load, the
  root-fork seed doorbell (`0xd9`) and three fork-stock doorbells (`0xd2`).
  It triple-faulted on the first walk after `install_maintenance_root`
  selected `0x480b000`, before child stdout. GDB observed
  `ExtentTable::expected_generation` return `None` for that root. The soft
  worker hand-off now admits the shared carrier's exact maintenance root
  into both existing extent inventories before either worker starts. The
  maintenance root is retained for the carrier lifetime. The same fixture
  now walks the maintenance root and reaches `install_address_context` for
  the fork child's CR3 (`0x480c000`). That root has no walker generation, so
  the next walk still triple-faults before child stdout. Child-root
  publication and retirement need the shared carrier's authority for the
  exact adopted root. The stopped slot snapshot currently provides backing
  placement alone.
- Raw thread exit boots through initial MM admission, root load and two owner
  grants (`0xd1`). GDB observed the first `clone` and then 23 consecutive
  timer interrupts (`0xe0`) at the same user return RIP (`0x4010f9`). The
  guest interval exceeds the debug watchdog deadline. An optimized host
  build reaches the unchanged 4,000,000-block limit. Neither run proves
  worker exit or clear-child-tid completion.

### M1-7 status: fork CR3 and the raw-exit timer

The fork now walks the child's `0x480c000` root. The soft runner admits
the page selected by the ring's committed MOV CR3 before its next fetch or
interrupt delivery. A new root must name a full page in an authenticated
retained extent. The instruction already invalidates the TLB and every
descriptor in the subsequent walk still goes through extent authentication.
The fixture serves the child's native stdout request with the shared
dispatcher and requester record. The regular soft suite assembles the
in-tree fixture locally. The child writes `E`, the parent reaps it and
exits 7.

The raw-exit fixture reaches the first clone. GDB observed the kick vector
`0xe2`, followed by timer vector `0xe0` alternating between the parent
(positive RAX) and the child (zero RAX) at `0x4010f9`. This is the user
`test %rax,%rax` immediately after the clone syscall. The APIC latched
expired deadlines with IF clear inside the CPL0 `arm_tsc_deadline` and
`prepare_parked_resume` paths. The next return to CPL3 takes the pending
timer before executing that user instruction. At M1-7 the fixture was opt-in.

### #2537: the single-vCPU execution clock

The original soft carrier used a host `Instant` for RDTSC and the APIC
deadline. A timer slice could elapse while the soft CPU translated or
executed CPL0 resume blocks, or while the host was outside the CPU. On
re-entry, an already pending vector could take the first interruptible
boundary after the CPL0 return. The APIC correctly disarmed each expired
deadline and latched one vector. Scheduling another runnable task then
armed a new deadline, which could expire before that task resumed.

GDB on the original carrier recorded the following from
`LocalApic::poll_timer`, `deliver_external_interrupt` and the runner's
block counter:

| Block | Event | RIP | RFLAGS | TSC / deadline or RAX |
| ---: | --- | --- | --- | --- |
| 141305 | Deadline latches `0xe0` in CPL0 | `0xffffffff8000c6a1` | `0x46` | `0xb395e6b6` / `0xb395e37e` |
| 141415 | Delivers `0xe0` to child | `0x4010f9` | `0x246` | `RAX = 0` |
| 143383 | Deadline latches `0xe0` in CPL0 | `0xffffffff80157280` | `0x46` | `0xc1b94a18` / `0xc1b91e04` |
| 143492 | Delivers `0xe0` to parent | `0x4010f9` | `0x246` | `RAX = 0x26de` |

The block-only clock eliminated the observed timer-return stall, but its
HLT deadline jump also let a 200 ms ring nanosleep return in 79 ms of
host time between guest markers on the release carrier.

The soft runner uses the maximum of host monotonic time at its published
2 GHz rate and 200 ticks per executed block. A block ending in a guest
fault or carrier exit counts toward the floor. RDTSC and absolute LAPIC
deadlines share that timebase, including the guest's TSC offset. An
interruptible HLT with an eligible timer enrolls on the APIC node until
the corresponding host deadline or an earlier notification. The host
wait translates the deadline using the monotonic anchor because the
block floor stays fixed while parked. The same host anchor applies while
executing, halted, or stopped in the carrier. The timebase is local to
the single-vCPU soft carrier.

An APIC deadline can pass while a slow soft CPL0 return executes with IF
clear. The APIC latches the timer in IRR at expiry and records an eight-user-block
recognition window for that vector. Intel specifies external interrupt
recognition at instruction boundaries. The soft CPU checks at translated block
boundaries and applies the window only while executing CPL3. Each CPL3 block
counts, including a block that enters the kernel through a syscall, software
interrupt or fault. Later returns and expirations that coalesce into the same
pending bit leave the original window in place. The timer becomes eligible at
the first boundary after eight CPL3 blocks from the latch.

Timers follow the usual IF, interrupt-shadow, and APIC priority rules
outside that window, including at CPL0 and on HLT wakeup. Fixed interrupts
remain eligible throughout. The IRR register still exposes the combined
timer and fixed pending bits, and acceptance of a shared vector clears
both sources. This policy applies to the soft CPU alone.
[Intel SDM, Vol. 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

The same in-tree `TWO_LIVE` fixture exits 0 on KVM, where hardware executes
the resume path directly. Intel VMX describes a
guest-visible offset and optional scaling of the physical TSC. On the
worker VM, two `KVM_GET_MSRS` reads of `IA32_TSC` after a one-instruction
guest's HLT exit, with no intervening `KVM_RUN`, observed `0x2b5658e`
and `0x7bb8bf6` about 20 ms apart.
[Intel SDM, Vol. 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

The active soft fixture assembles the KVM witness's source and verifies both
non-last raw exits and their clear-child-tid joins under the existing
4,000,000-block ceiling. The VM-free APIC witness checks the TSC floor at a
PIO exit, a host kick before the deadline, and delivery after the host
deadline. The production nanosleep witness measures from a child write
before its ring syscall to another write after it returns. It uses a
200 ms lower bound and a 10 s upper bound to allow host scheduling and
translation overhead. A controlled-clock witness runs a two-thread multi-slice
raw-exit guest at 50 µs per block under a 200,000-worker-block ceiling, and a
contended-head witness holds slot 0's queued head claim away from slot 0 across
one user-origin `0xe0` interrupt (`runnable_head` returns `None` while
`queued() != 0`) before restoring it on `iretq`. It injects host latency in
the CPL0 return and checks that the re-armed interrupt arrives after eight
user blocks. One IDT witness checks that a lower-priority fixed interrupt,
or one sharing the timer vector, can still arrive immediately. A second IDT
witness runs an `int 0x80` loop across repeated IRETQ returns and checks the
exact eight-block boundary. The production-ring poller calls `gettid` every
two user blocks and can finish only after its queued leader runs on the same
slot and releases it. These witnesses are bound to `x86.softcpu.apic-timer`.

Before the CPL0 slice-accounting fix, the host-clock trial reached both
initial-MM allocation exits for `TWO_LIVE`, then stalled on CPL3 RIP
`0x4010f9`, the first instruction after `clone`. Three x86 CPL0 mechanics
allowed `TIMER_VECTOR` (`0xe0`) to latch in the edge-triggered xAPIC `IRR`
with `IF` clear and interrupt the resumed thread before it retired an
instruction: starting the 2 ms slice before `prepare_parked_resume` and
CR3/TLS installation, re-arming a 1 ms slice retry in `expire_timers` before
`signal_irq_return` rotated a slot with a runnable head, and leaving an
outgoing thread's expired `0xe0` pending in `IRR` when higher-priority
`RESCHED_VECTOR` (`0xe2`) entered `schedule`. `context_resume::resume_parked`
now runs a single pre-`iretq` callback on the one return path after context
validation and CR3/TLS installation so `arm_slice` stamps and arms the 2 ms
slice immediately before `carrick_x86_resume_iret`; `expire_timers` arms only
timed-park deadlines; `signal_irq_return`'s non-rotating branch re-arms the
ongoing slice via `with_slice` whenever `queued() != 0` (covering a concurrent
`steal_from` that claimed the head `Queued{thief}` before unlinking it,
matching ARM EL1's `Sched::program_timer(true)`); and `schedule` drains any
pending xAPIC `IRR` vectors after disarming outgoing timers. ARM EL1 already
restores its parked frame before stamping the level-triggered virtual timer and
checks actual slice expiry before rotating. With this fix, the controlled-clock
and contended-head witnesses, eight-round `TWO_LIVE`, the 200 ms nanosleep
witness, the musl static hello, and the KVM `TWO_LIVE` and slice-end witnesses
all exit 0 under unchanged slice and block budgets.

### #671: retired slots in the production fixture sweep

The sweep uses the production CPL0 image from #2541. The existing
`soft_hello` driver boots each standalone fixture, binds the issued root
and enters the shared production worker. Run an individual locally built
fixture from the repository root:

```sh
CARRICK_SOFT_FIXTURE=/absolute/path/to/local/static-elf \
  cargo test --locked -p carrick-vmm-soft --test soft_hello -- \
  production_ring_static_fixture_probe --exact --ignored --nocapture
```

The earliest recurring carrier stop was after a normal custody update.
`native_child_entropy.S` forked from the root, used the child entropy
service at `0xd8`, and reached the child-retire doorbell `0xd6`. The next
guest entry after work doorbell `0xcb` refused to refresh soft slot 7.
GDB on the corrected worker observed `OUT` at `0xffffffff8012372b` on
port `0xd6` with width 4 and value `0x90e0dc00`, then work port
`0xcb` at `0xffffffff80003a67` with width 1 and value `0x60`. The
retired extent began at GPA `0x228000000`. The parent reaped the child
and exited 8 with empty stdout, matching the KVM witness's required
result.

The soft memory view compares the published slot registrations and retains
the old backing until its extent retirement completes. It reuses
`ExtentTable::remove` and `reclaim` in the existing invalidation domain.
M1's sole runnable software vCPU is parked between blocks, so completion
requires no wait. Its next entry serves the invalidation debt. Code
reactivation at a reused GPA gets a new code generation, and root admission
requires a full page in a live extent. Each changed snapshot does one
retirement per revoked or replaced slot. The unchanged snapshot takes the
existing pointer comparison, and block entry has the same work budget.
The contract is `softmmu.x86.physical-retirement` (Intel SDM Vol. 3A,
§4.10.4).

The fixture census records guest termination and stdout from the harness
and the exact diagnostic or last carrier event on a stop. The default
driver has empty argv and env, no mounted root filesystem or injected
preopened descriptors, and refuses native exec image loading. It samples
host readiness without parking. Its output therefore describes the soft
driver's execution of each ELF. Configuration-specific KVM witnesses add
their own peers, inputs, and handshakes.

The assembly inputs come from `carrick-vmm-kvm/tests/fixtures` and
`x86_kvm_run.rs`'s fixtures in `carrick-cli/tests/fixtures`. They were
linked with `cc -nostdlib -static -no-pie -Wl,--build-id=none`, with
local scratch paths and the named preprocessor modes where applicable.
The standalone Rust examples are under `carrick-vmm-kvm/fixtures/x86-*`;
the musl and glibc hello ELFs both use the bhyve/KVM hello source. The
conformance table includes the checked-in amd64-musl oracle population
and the other locally buildable static x86-64 probes selected by the
generic conformance runner. That runner's normal GNU probes are dynamic.
ELFs were built offline. In scratch copies, the unavailable probe lock
entry for `simd-adler32` went from 0.3.10 to cached 0.3.9, and the
standalone Rust example lock entry for `libc` went from 0.2.189 to cached
0.2.186. The repository lockfiles are authoritative for normal builds.
The offline x86 build produced no standalone binaries for `ctrel0`,
`forkfpregs`, `inzonetcp`, `mmapv8align`, `nativeetexecfork`,
`ptracepoketext`, `tlsswitch`, and `windowcoherence`.

The SIGABRT exits include different guest failures. For example,
`connrefused` reported an fd-set bounds panic with index
`288230376151711743`, `futexdeadline` panicked with errno 22 on its time
query, and `futexextra` printed five passing futex checks before a thread
library assertion received errno 38. The hard host deadline rows have
no captured terminal worker event. Fixtures that deliberately deliver
signals retain those terminal statuses in the census.

The static glibc build of the same hello prints `hello, x86_64 world\n`
and reaches the root-exit doorbell `0xd3` with SIGSEGV. On the rebased
`#2541` CPL0 image, the soft block trace immediately before the fatal
fetch demangles the initial exit-handler entry in `__run_exit_handlers`
(`0x276bd8..0x276c0f`: `ror $0x11, %rax; xor %fs:0x30, %rax` with
`fs_base = 0x31e400`) to `RAX = 0xd7` and executes `call *%rax` at
`0x276c0f`, raising CPL3 `#PF(error=0x14, RIP=CR2=0xd7)` after block
`629412`. The same ELF exits 0 with the greeting on native Linux, and
exits 139 (`SIGSEGV`) on KVM. GDB traced `0xd7` to
`carrick_x86_carrier::initial_boot::carrier_initial_boot`
(`0xffffffff800037ee..0xffffffff800037f9`) and `carrick_x86_boot_iret`
(`0xffffffff8013837c..0xffffffff8013838a`): CPL0 rings
`X86_INITIAL_RUNNER_READY_PORT` (`0xd7`) via `out %al, (%dx)` and
executes `push $0x1b; push %rsi; push $0x202; push $0x23; push %rdi;
swapgs; iretq` without clearing `RDX` or the other general-purpose
registers (leaving `RDX = 0xd7` plus supervisor addresses in `RAX`,
`RCX`, `RBP`, and `R8` live at `_start` `0x23b580` on block `428316`).
Under the System V AMD64 psABI, `%rdx` at `_start` is `rtld_fini` (`0`
when entered directly from the kernel); `_start` forwards `RDX = 0xd7`
in `%r9` to `__libc_start_main` (`0x2754f0`), which registers `0xd7` as
an exit handler. Zeroing the 15 non-`RSP` GPRs in GDB immediately before
`carrick_x86_boot_iret`'s `iretq` at `0xffffffff8013838a` makes the
static glibc ELF exit 0 with `hello, x86_64 world\n` (`0xcb -> 0xd3`).
Clearing initial user GPRs belongs to `carrick-x86-carrier` (shared by
KVM and soft x86, outside the soft-backend fence).

| Production soft witness | On #2541 | With slot retirement |
| --- | --- | --- |
| Static assembly hello | Exit 0, `hello\n` | Exit 0, `hello\n` |
| Static musl hello | Exit 0, `hello, x86_64 world\n` | Exit 0, `hello, x86_64 world\n` |
| Static glibc hello | `0xd3`, SIGSEGV after `hello, x86_64 world\n` | Same CPL3 fetch fault at `0xd7` (`carrick_x86_boot_iret` leaves `RDX = 0xd7`) |
| Forked child stdout | Exit 7, `E` | Exit 7, `E` |
| Robust raw exit, `TWO_LIVE` | Exit 0, empty stdout | Exit 0, empty stdout |
| Child entropy and wait | Slot 7 rejected after `0xd6 → 0xcb`, empty stdout | Exit 8, empty stdout |
| Autoreap, three forks | Slot 11 rejected after `0xd6 → 0xcb`, bytes `01 02` | Exit 7, bytes `01 02 03 04` |

### Static fixture census

The baseline captured 149 assembly and standalone Rust cases and 502
musl conformance probes. Of those 651 rows, 430 reached an exit code
and 83 stopped at the retired-slot check. On the original `#2541`
pre-host-clock base with slot retirement wired in, 68 of those 83
reached an exit code and 15 reached another stop. Re-running the full
651-fixture sweep on the rebased `#2541` base (host-clock APIC deadline
waits and pre-`iretq` CPL0 slice accounting) with slot retirement brings
the 83-row cohort to 70 exit codes (`proclife` and `sigtimedwaitintr`
now exit 0, and `killfault` reaches the 4,000,000-block ceiling instead
of the 65 s host deadline) and 13 other stops, and brings the full
651-fixture population to 506 exit codes (`native_sibling_raw_exit`,
`native_sibling_raw_exit.EDITOR_BUSY_ONCE`, `pagetablegrow`,
`ptraceinvaliderrno`, `ptracetraceme`, and `traceexecstop` also exit 0,
with zero 65 s host-deadline stops across all 651 rows). An exit code
records where execution ended, including fixture-defined refusal or
mismatch codes.


<details>
<summary>KVM assembly fixtures and standalone Rust examples (149 rows)</summary>

| ELF | Baseline stop | Stdout | First worker event | Last worker event |
| --- | --- | --- | --- | --- |
| `carrick-x86-fsprobe` | `exit 0` | `"uname.sysname=Linux uname.nodename=carrick\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `native_autoreap_exit` | `soft slot 11 changed or retired without a retirement protocol` | `"\u{1}\u{2}"` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_brk_regrow` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_brk_settle_at_exclusion` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_child_entropy` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_child_futex_wake` | `soft slot 9 changed or retired without a retirement protocol` | `"\u{1}\u{2}"` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_child_inet` | `exit 103` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_child_readlink_exe` | `exit 218` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_child_sleep` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_child_sleep_witness` | `exit 8` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_child_unstaged_crossing` | `exit 7` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_clone_parent_tid_busy` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_cow_retire_race` | `exit 85` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_crossing_operand` | `exit 90` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_cwd` | `exit 102` | `""` | `forward 0x50=-2` | `doorbell 0xd3` |
| `native_direct_outputs` | `exit 0` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_epoll_copyout` | `exit 7` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_exec_live_successor` | `exit 92` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_exec_marker` | `exit 0` | `"X\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `native_exec_stock_successor` | `exit 0` | `"X\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `native_exit_order` | `soft slot 11 changed or retired without a retirement protocol` | `"\u{1}\u{2}"` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_file_attr` | `exit 91` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_file_fork` | `soft slot 9 changed or retired without a retirement protocol` | `"\0\u{1}"` | `forward 0x1=1` | `doorbell 0xcb` |
| `native_file_metadata` | `exit 0` | `hex 2609890989090902022609890902` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_fork_birth_contention` | `exit 85` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_fork_exec` | `exit 38` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_fork_exec_live` | `exit 38` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_fork_exec_stock` | `exit 38` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_group_exit` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_group_exit.TWO_LIVE` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_kill_wait` | `stopped CPU image after FaultDoorbellWord(6): hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4802000, actual CR3 0x480c000, RSP 0xffffffff90ac0fd0, saved GPR7 0xffffffff90ac0fd0, expected MM 1, context 1` | `"\u{1}\u{2}"` | `doorbell 0xd9` | `doorbell 0xd8` |
| `native_loader_reopen` | `exit 38` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_not_now_contention` | `exit 90` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_owed_return_gib` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_owed_return_retired_holders` | `block budget exhausted, rip=0xffffffff80154ef2 cpl=0 cr3=0x4805000 blocks=4000000` | `""` | `doorbell 0xd9` | `doorbell 0xd2` |
| `native_owed_return_table_full` | `block budget exhausted, rip=0xffffffff80154ef2 cpl=0 cr3=0x4805000 blocks=4000000` | `""` | `doorbell 0xd9` | `doorbell 0xd2` |
| `native_peer_birth` | `soft slot 11 changed or retired without a retirement protocol` | `"\u{1}\u{2}"` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_pipe2` | `exit 7` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_pipe_child_write` | `exit 0` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_pipe_exit_wake` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4803000, actual CR3 0x480c000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `native_pipe_poll_wake` | `exit 7` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_poll_revents_only` | `unserved host readiness wait Some(80ms): parking needs an execution lease` | `""` | — | — |
| `native_private_file` | `exit 31` | `hex daffffffffffffff` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_record_lock` | `soft slot 8 changed or retired without a retirement protocol` | `hex 26092609000989002609000909000009` | `doorbell 0xd8` | `doorbell 0xcb` |
| `native_redirect_write` | `exit 12` | `"hello world\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_resolv_read` | `exit 10` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_ring_descriptors` | `exit 144` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_robust_raw_exit` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_robust_raw_exit.TWO_LIVE` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_root_exec` | `exit 38` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_root_exec_successor` | `exit 0` | `"root-exec-ok\n"` | `forward 0x1=13` | `doorbell 0xd3` |
| `native_root_fcntl` | `exit 7` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `native_root_loader_io` | `exit 10` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `native_sibling_raw_exit` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `native_sibling_raw_exit.EDITOR_BUSY_ONCE` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `native_stack_growth` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_wait4_output_contention` | `exit 90` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `native_wait_birth_contention` | `exit 85` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `native_yield_sibling_progress` | `exit 0` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `x86-fork` | `soft slot 8 changed or retired without a retirement protocol` | `"child\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `x86-signal` | `exit 0` | `"signal-ok\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `x86-threads` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(46876), expected: EntryTaskKey(46875) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `x86_adjacent_memory` | `exit 7` | `"A\n"` | `doorbell 0xd1` | `doorbell 0xd3` |
| `x86_authority_refusal` | `exit 7` | `"R\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_b1_files` | `exit 13` | `""` | `forward 0x102=0` | `doorbell 0xd3` |
| `x86_b1_metadata` | `exit 11` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `x86_b1_xattr` | `exit 11` | `""` | `doorbell 0xd8` | `doorbell 0xd3` |
| `x86_bad_write` | `exit 7` | `"E\n"` | `forward 0x1=-14` | `doorbell 0xd3` |
| `x86_blocking_stdin` | `exit 99` | `"R\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_clear_tid_dependency` | `exit 7` | `"T\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_clear_tid_exit` | `exit 91` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_clear_tid_raise` | `exit 7` | `"S\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_descriptor_stdio` | `exit 94` | `""` | `forward 0x4341525252454c53=-38` | `doorbell 0xd3` |
| `x86_descriptor_writev` | `exit 99` | `""` | `forward 0x4341525252454c53=-38` | `doorbell 0xd3` |
| `x86_dispatch_getpid` | `exit 7` | `"D\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_dispatch_segments` | `exit 7` | `"T\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_dispatch_startup` | `exit 95` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `x86_entrypoint_argv` | `guest fault FaultDoorbellRecord { vector: 14, error_code: 4, rip: 4198424, cs: 35, rsp: 2147417744, rflags: 66118, saved_rax: 18446744065119617024, cr2: 0 }` | `""` | — | — |
| `x86_exec_dependency` | `exit 7` | `"F\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_fork_prepared_cow_write` | `soft slot 9 changed or retired without a retirement protocol` | `"C\n"` | `doorbell 0xd1` | `doorbell 0xcb` |
| `x86_fork_reuse` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_fork_reuse.AUTOREAP` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_fork_reuse.IGNORE_SIGCHLD` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_fork_stock_reuse` | `exit 7` | `"R\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_forked_child_forward_authority` | `exit 7` | `""` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_forked_child_stdout` | `exit 7` | `"E"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_hello` | `exit 7` | `"hello\n"` | `forward 0x1=6` | `doorbell 0xd3` |
| `x86_identity_eperm` | `exit 7` | `"P\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_identity_fork` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_ipc_msg` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_ipc_perm` | `exit 7` | `"P\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_ipc_sem` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_ipc_sem_rmid` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_ipc_sem_undo` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_ipc_shm_unrouted` | `exit 7` | `"U\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_last_writer` | `exit 7` | `"E\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_memory_fork_wait` | `exit 7` | `"F\n"` | `doorbell 0xd1` | `doorbell 0xd3` |
| `x86_memory_only` | `exit 7` | `"M\n"` | `doorbell 0xd1` | `doorbell 0xd3` |
| `x86_mprotect_fault` | `exit 99` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_munmap_fault` | `terminated by signal 11` | `""` | `doorbell 0xd3` | `doorbell 0xd3` |
| `x86_poll_blocking_stdin` | `exit 7` | `"R\nP\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_poll_closed_stdio` | `exit 97` | `"C\n"` | `forward 0xfffffffffffffeff=1` | `doorbell 0xd3` |
| `x86_poll_empty_sets` | `exit 99` | `"B\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_poll_empty_stdin` | `exit 92` | `""` | `forward 0xfffffffffffffeff=2` | `doorbell 0xd3` |
| `x86_poll_stdio` | `exit 7` | `"P\n"` | `forward 0xfffffffffffffeff=2` | `doorbell 0xd3` |
| `x86_poll_timeout` | `exit 99` | `""` | `forward 0xfffffffffffffeff=1` | `doorbell 0xd3` |
| `x86_ppoll_timeout` | `exit 99` | `"B\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_sched_inring` | `exit 7` | `"S\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_sched_refusal` | `exit 7` | `"R\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_signal_abort` | `exit 7` | `"A\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_altstack` | `exit 7` | `"S\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_signal_bad_fault_handler` | `terminated by signal 11` | `""` | `doorbell 0xd3` | `doorbell 0xd3` |
| `x86_signal_bad_handler` | `terminated by signal 11` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_signal_badstack` | `terminated by signal 11` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_signal_block_pending` | `exit 7` | `"BHU\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_blocked` | `exit 7` | `"F\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_chld_exit` | `exit 7` | `"C\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_chld_killed` | `exit 7` | `"D\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_direction_flag` | `exit 7` | `"HK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_fault_badstack` | `exit 7` | `"F\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_group_exit_dependency` | `terminated by signal 15` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_signal_handler` | `exit 7` | `"HK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_ignored` | `exit 7` | `"F\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_kill_child` | `exit 7` | `"W\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_kill_loop` | `exit 7` | `"K\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_kill_read` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4802000, actual CR3 0x480b000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_signal_nested` | `exit 7` | `"HHK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_resethand` | `exit 7` | `"HK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_return_badframe` | `terminated by signal 11` | `""` | `doorbell 0xcb` | `doorbell 0xd3` |
| `x86_signal_return_flags` | `exit 7` | `"HK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_segv_child` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_signal_segv_fault` | `exit 7` | `"SC\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_segv_resume` | `exit 7` | `"S\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_signal_sigsuspend` | `exit 7` | `"S\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_sigsuspend_pingpong` | `exit 7` | `"S\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_sse` | `exit 7` | `"HK\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_stop_continue` | `block budget exhausted, rip=0x401160 cpl=3 cr3=0x480c000 blocks=4000000` | `""` | `doorbell 0xd9` | `doorbell 0xd2` |
| `x86_signal_thread_child` | `soft slot 7 changed or retired without a retirement protocol` | `""` | `doorbell 0xd9` | `doorbell 0xcb` |
| `x86_signal_thread_identity` | `exit 7` | `"T\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_signal_timedwait` | `exit 7` | `"PT\n"` | `forward 0x1=1` | `doorbell 0xd3` |
| `x86_signal_wait4_interrupt` | `exit 7` | `"I\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_wait4_restart` | `exit 7` | `"R\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_wait_child` | `exit 7` | `"W\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_wait_concurrent` | `exit 7` | `"T\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_signal_wait_copyfault` | `exit 7` | `"F\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_signal_wait_pingpong` | `exit 7` | `"W\n"` | `doorbell 0xd9` | `doorbell 0xd3` |
| `x86_startup_sequence` | `exit 7` | `"S\n"` | `forward 0x1=2` | `doorbell 0xd3` |
| `x86_two_mm_private` | `block budget exhausted, rip=0x40109d cpl=3 cr3=0x4802000 blocks=4000000` | `""` | `doorbell 0xd9` | `doorbell 0xd2` |
| `x86_wait_forever` | `unserved host readiness wait None: parking needs an execution lease` | `""` | — | — |

</details>

<details>
<summary>Static musl conformance probes (502 rows)</summary>

| ELF | Baseline stop | Stdout | First worker event | Last worker event |
| --- | --- | --- | --- | --- |
| `abortdeath` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `acceptsock` | `exit 0` | `"accept_opath_ebadf=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `accessx` | `exit 0` | `"access_root_r=ERR:38\naccess_root_w=ERR:38\naccess_root_x=ERR:38\naccess_varcacheapt_w=ERR:38\naccess_etc_w=ERR:38\naccess_usr_w=ERR:38\naccess_hostname_w=ERR:38\naccess_passwd_r=ERR:38\nfaccessat_varcacheapt_w=ERR:38\nfaccessat_varcacheapt_w_eaccess=ERR:38\nfaccessat2_varcacheapt_w_eaccess=ERR:38\naccess_sh_x=ERR:38\naccess_hostname_x=ERR:38\naccess_missing_f=ERR:38\naccess_missing_r=ERR:38\naccess_hostname_f=ERR:38\nfaccessat_missing_f=ERR:38\naccess_invalid_mode=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `accounting` | `block budget exhausted, rip=0x880000af00 cpl=3 cr3=0x4873000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `forward 0xfffffffffffffeff=0` |
| `adjtimexmodel` | `exit 0` | `"clock_adjtime_read_ok=false\nadjtimex_read_ok=false\nadj_offset_ok=false\nadj_frequency_ok=false\nadj_maxerror_ok=false\nadj_esterror_ok=false\nadj_status_ok=false\nadj_timeconst_ok=false\nadj_tai_ok=false\nadj_tick_ok=false\nadj_setoffset_ok=false\noversized_freq_accepted=false\nbad_tick_einval=false\nunknown_status_bits_accepted=false\nbad_setoffset_usec_einval=false\nmicro_nano_together_accepted=false\ntai_timeconst_together_accepted=false\nsingleshot_flag_without_offset_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `adjtimexstate` | `exit 0` | `"clock_adjtime_read_nonnegative=false\nadjtimex_read_nonnegative=false\nclock_adjtime_adjust_eperm=false\nadjtimex_adjust_eperm=false\nclock_adjtime_status_flag_eperm=false\nclock_adjtime_singleshot_flag_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `alarmretval` | `exit 0` | `"fresh_alarm_returns_zero=true\ncancel_returns_remaining=false\nbig_alarm_returns_zero=true\nbig_cancel_exact=false\nsetitimer_arm_ok=false\nsetitimer_disarm_ok=false\nold_value_sec_intmax=false\nold_value_usec_range=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `aliassize` | `exit 0` | `"hi512g_fixed_ok=false\nhi4g_fixed_ok=false\nro16k_open=ERR:38\nrw16k_open=ERR:38\nro32k_open=ERR:38\nrw32k_open=ERR:38\nro27k_open=ERR:38\nro27k_rdonlyfd_open=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `altstacktid` | `exit 0` | `"b_kept_own=true\nbufs_distinct=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `archiveflagmatrix` | `exit 0` | `"statfs_tmp_rc=-1\nstatfs_tmp_errno=2\nstatfs_tmp_ftype_nonzero=false\nstatfs_tmp_bsize_positive=false\nstatfs_tmp_blocks_positive=false\nstatfs_tmp_namelen_ge_255=false\nstatfs_tmp_frsize_positive=false\nfstatfs_regfile_open_ok=false\nfstatfs_regfile_rc=-1\nfstatfs_regfile_errno=38\nfstatfs_regfile_match_type=true\nfstatfs_regfile_match_bsize=true\nfstatfs_regfile_match_namelen=true\nfstatfs_regfile_match_frsize=true\nstatfs_empty_path_rc=-1\nstatfs_empty_path_errno=2\nstatfs_nonexistent_rc=-1\nstatfs_nonexistent_errno=2\nfstatfs_bad_fd_rc=-1\nfstatfs_bad_fd_errno=9\ngetdents64_open_dir_ok=false\nxattr_target_open_ok=false\nlinkat_symlink_follow_rc=-1\nlinkat_symlink_follow_errno=2\nlinkat_symlink_follow_target_is_reg=false\nlinkat_symlink_nofollow_rc=-1\nlinkat_symlink_nofollow_errno=2\nlinkat_symlink_nofollow_target_is_lnk=false\nlinkat_directory_rc=-1\nlinkat_directory_errno=2\nfchmodat_symlink_nofollow_rc=-1\nfchmodat_symlink_nofollow_errno=2\nutimensat_atime_now_mtime_omit_rc=-1\nutimensat_atime_now_mtime_omit_errno=2\nutimensat_atime_omit_mtime_now_rc=-1\nutimensat_atime_omit_mtime_now_errno=2\nutimensat_symlink_nofollow_rc=-1\nutimensat_symlink_nofollow_errno=2\nutimensat_invalid_nsec_rc=-1\nutimensat_invalid_nsec_errno=22\nmkfifo_rc=-1\nmkfifo_errno=38\nmkfifo_is_fifo=false\nmkfifo_mode_0640=false\nmkfifo_size_zero=true\nopen_fifo_rdonly_nonblock_ok=false\nopen_fifo_rdonly_nonblock_errno=38\nmkfifo_for_writer_rc=-1\nmkfifo_for_writer_errno=38\nopen_fifo_wronly_nonblock_no_reader_rc=-1\nopen_fifo_wronly_nonblock_no_reader_errno=38\nmknodat_fifo_rc=-1\nmknodat_fifo_errno=2\nmknodat_fifo_is_fifo=false\nmknodat_fifo_mode_0644=false\nmknodat_reg_rc=-1\nmknodat_reg_errno=2\nmknodat_reg_is_reg=false\nmknodat_reg_mode_0644=false\nmknodat_existing_rc=-1\nmknodat_existing_errno=2\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `bigallocfree` | `block budget exhausted, rip=0x880000961f cpl=3 cr3=0x4871000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `bigread` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `bindunixnode` | `exit 0` | `"socket_ok=false\nbind_ok=false\nstat_ok=false\nis_sock=false\naccess_ok=false\nchmod_ok=false\nchmod_bits_600=false\nstill_sock=false\nunlink_ok=false\ngone_after_unlink=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `blockingpipewrite` | `exit 0` | `"write_returned_partial=false\nwrite_blocked_until_signal=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `bridge_dns_epoll_wake` | `exit 0` | `"dns_epoll_nameserver_ok=false\ndns_epoll_socket_ok=false\ndns_epoll_add_ok=false\ndns_epoll_send_ok=false\ndns_epoll_ready_after_send=false\ndns_epoll_reply_id_matches=false\ndns_epoll_wake_while_parked=false\ndns_epoll_parked_reply_id_matches=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `bridge_tcp_peer` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `brkbeyondbreak` | `exit 0` | `"brkbeyondbreak requires aarch64\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `brkheapgrow` | `block budget exhausted, rip=0xffffffff80022907 cpl=0 cr3=0x4871000 blocks=4000000` | `"brk_initial_nonzero=true\nbrk_grow_32mib=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `bsd_signal_xlate` | `exit 0` | `"setup_pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `budget_two_proc` | `soft slot 10 changed or retired without a retirement protocol` | `"parent_pid_positive=true\nchild_ppid_matches=true\nchild_ok\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `cachestatpages` | `exit 0` | `"cachestat_ok=false\ncachestat_bad_flags_einval=false\ncachestat_badfd_ebadf=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `capbsetisolation` | `terminated by signal 6` | `"parent_before_capbset_chown=-38\nparent_before_capbset_kill=-38\nparent_before_capbset_setpcap=-38\nparent_before_capbset_net_raw=-38\nparent_before_capbset_sys_chroot=-38\nparent_before_capbset_sys_admin=-38\nparent_before_status_capbnd=unreadable\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `carrierwindowaccess` | `exit 0` | `"carrierwindowaccess requires aarch64\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `childrusage` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `childsubreaper` | `exit 0` | `"set_subreaper_ok=true\nchild_subreaper_not_inherited=true\ngrandchild_pid_reported=false\norphan_ppid_is_subreaper=false\nwait_reaped_orphan=false\norphan_exit_status=false\nsigchld_from_orphan=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `chmodfollowsymlink` | `exit 0` | `"chmod_followed_symlink=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `chmodsetgid` | `exit 0` | `"setgid_chmod_ok=false\nsetgid_cleared_for_nonmember=false\nfchmodat2_bad_flag_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clockcoarsevdso` | `exit 1` | `"vdso_clock_gettime_resolved=false\nvdso_clock_getres_resolved=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clockcoherence` | `exit 1` | `"vdso_clock_gettime_resolved=false\nmonotonic_vdso_syscall_coherent=false\nrealtime_vdso_syscall_coherent=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clockgetres` | `exit 0` | `"realtime_rc_zero=false\nrealtime_sec_zero=true\nmonotonic_rc_zero=false\nmonotonic_sec_zero=true\nmonoraw_rc_zero=false\nmonoraw_sec_zero=true\nboottime_rc_zero=false\nboottime_sec_zero=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clocknanosleepcpu` | `exit 0` | `"thread_cputime_raw_eopnotsupp=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clocksettimevdso` | `soft slot 10 changed or retired without a retirement protocol` | `"clock_settime_monotonic rc=-1 errno=38\ninitial_reads rc_raw=-1 rc_vdso=0 rc_gtod=0\nclock_settime_realtime rc=-1 errno=38\nparent_shifted raw_shifted=false vdso_shifted=false gtod_shifted=false\nchild_shifted raw_shifted=false vdso_shifted=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `clone3args` | `exit 0` | `"clone3_happy_rejected_or_succeeded=true\nclone3_extra_size_efault_or_blocked=true\nclone3_truncated_rc_minus_one=true\nclone3_truncated_rejected=true\nclone3_sighand_no_vm_rejected=true\nclone3_thread_no_sighand_rejected=true\nclone3_fs_newns_rejected=true\nclone3_invalid_pidfd_efault_or_blocked=true\nclone3_invalid_signal_rejected=true\nclone3_newpid_fork_or_blocked=true\nclone3_badflag_rc_minus_one=true\nclone3_badflag_rejected=true\nclone3_badstack_rc_minus_one=true\nclone3_badstack_rejected=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clone3exithandled` | `exit 0` | `"install_ok=true\nclone3_blocked_or_cloned_all=true\nreaped_all=true\nall_exit_handlers_observed_or_blocked=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clone3pidfdsig` | `exit 0` | `"clone3_pidfd_created_or_blocked=true\npidfd_send_signal_ok=true\npidfd_siginfo_delivered=true\npidfd_siginfo_code_is_queue=true\npidfd_siginfo_payload=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clone3signalflight` | `exit 0` | `"setup_vfork_ok_or_blocked=true\ninstall_ok=true\nclone3_blocked_or_sequence_ok=true\nchild_payload_ok=true\nparent_exit_signals_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clonebasic` | `soft slot 12 changed or retired without a retirement protocol` | `"clone_basic_rc_positive=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `cloneexithandled` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `cloneexitsig` | `exit 0` | `"block_ok=true\nclone_rc_positive=false\nexit_signal_is_usr1=false\nexit_signal_is_not_chld=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clonefilesexec` | `exit 0` | `"clone_files_exec_clone_ok=false\nsuccessor_exec_succeeded=false\nsuccessor_closed_cloexec=false\nsuccessor_inherited_noncloexec=false\nsuccessor_closed_own_noncloexec=false\nparent_retained_cloexec_slot=false\nparent_retained_successor_closed_slot=false\nsuccessor_exited_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clonefileshare` | `exit 0` | `"clone_files_clone_ok=false\nchild_open_visible_in_parent=false\nparent_close_visible_in_child=false\nparent_dup_visible_in_child=false\nchild_setfd_visible_in_parent=false\nchild_setfl_visible_in_parent=false\nchild_exited_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `clonefsumask` | `soft slot 11 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `clonestack` | `exit 0` | `"clone_ok=false\nwait_ok=true\nchild_exit_42=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `closedstdio` | `exit 0` | `"close0_ok=false\nfstat0_ebadf=true\ngetfl0_ebadf=true\ngetfd0_ebadf=true\nisatty0_false=true\ndup0_ebadf=true\nlseek0_ebadf=true\nread0_ebadf=true\ndevnull_reuses_fd0=false\ndevnull_is_chardev=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `cluster10errno` | `exit 0` | `"pidfd_open_ok=false\npidfd_cloexec=false\nfadvise_bad_advice_einval=false\nfadvise_pipe_espipe=false\nftruncate_ro_einval=false\nftruncate_ro_not_ebadf=false\nfdatasync_devnull_einval=false\nfdatasync_badfd_ebadf=false\nfdatasync_regular_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `connrefused` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `container_gate` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `copyrangeflags` | `exit 0` | `"nonzero_flags_einval=false\nnull_offsets_advance=false\nexplicit_offsets_update=false\nzero_length_noop=false\nsame_file_overlap_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `coredumpbit` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `coredumpfile` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `cpucount` | `exit 0` | `"affinity_ge_1=false\nonline_gt_1=false\ntopology_surfaces_agree=false\naffinity_subset_of_online=false\nsysconf_conf_ge_onln_ge_1=true\nsysconf_onln_in_affinity_online_range=false\ngetcpu_ok=false\ngetcpu_in_range=false\nsetaffinity_full_ok=false\nsetaffinity_full_roundtrip=false\nsetaffinity_empty_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `credtransition` | `exit 0` | `"privileged_setresuid_ok=true\nprivileged_setresuid_readback=true\nsetreuid_to_real_ok=true\nsetreuid_saved_unchanged=true\nunpriv_setresuid_foreign_eperm=true\nunpriv_setuid_to_saved_ok=true\nunpriv_setuid_only_euid_changed=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dentrycache` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `devnullseek` | `exit 0` | `"devnull_lseek_cur0=false\ndevnull_lseek_set=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dirdac` | `exit 0` | `"dropped_to_nonroot=true\nmkdir_in_unwritable_eacces=false\nmkdir_in_writable_ok=false\nrmdir_in_writable_ok=false\nsymlink_in_unwritable_eacces=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dirfdnotdir` | `exit 0` | `"fstatat_nondir_dirfd_enotdir=false\nfstatat_badfd_ebadf=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dirops` | `exit 0` | `"mkdir_d1 exists=false\nrmdir_d1 gone=true\nmkdirp_d2 exists=false\nmkdirp_d2 dir=false\nmkdirp_d2_a dir=false\nmkdirp_d2_a_b dir=false\nreaddir_dd names=\nreaddir_dd count=0\nreaddir_dd_zzz listed=false\nhardlink_h2_content_ok=false\nhardlink_h1_nlink=ERR:38\nsymlink_dlnk_target=ERR:38\nsymlink_dlnk_stat_dir=ERR:38\nsymlink_dlnk_lstat_symlink=ERR:38\nrename_dir source_gone=true\nrename_dir rd2_file_exists=false\nunlink_u1 gone=true\nrmdir_notempty_errno=38\nrmdir_emptied_rc=-1\nrmdir_emptied_gone=true\ngetdents_dot count=0\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dirrenamecache` | `exit 0` | `"made_dir=false\nseeded_leaf=false\nwarm_before_rename=false\nrenamed=false\nold_path_gone=false\nnew_path_present=false\ncontent_followed=false\nold_open_enoent=false\nrecreated=false\nrecreated_dir_is_empty=false\nrecreated_dir_itself_exists=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dnotify` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dsrconstantpool` | `exit 0` | `"constant_word_match=true\nexecutable_hash_unchanged=true\nsection_executed=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `dupclosestdin` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollclosenodel` | `exit 0` | `"epoll_create_ok=true\neventfd_ok=true\nadd_ok=true\nclose_ok=true\nreused_fd_number=true\nreadd_ok=true\nreadd_not_eexist=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollcluster` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(63478), expected: EntryTaskKey(63477) }` | `"epollpri_pipe_add_errno=9\nnested_epoll_add_errno=38\nnested_epoll_cycle_errno=38\npwait2_zero_rc=0\npwait2_zero_errno=0\nrodata_events_errno=0\nmmap_ro_events_errno=0\npipe_set_capacity=-1\npipe_first_write=-1\npipe_second_write_errno=9\nsocket_peer_close_rc=1\nsocket_peer_close_events=8209\net_first_rc=0\net_first_events=0\net_after_half_rc=0\net_after_refill_rc=0\net_after_refill_events=0\nepollfd_nested_add_errno=38\nepollfd_empty_poll=0\nepollfd_empty_poll_mask=0\nepollfd_empty_outer=0\nepollfd_empty_outer_mask=0\nepollfd_child_add_errno=0\nepollfd_registered_poll=0\nepollfd_registered_poll_mask=0\nepollfd_registered_outer=0\nepollfd_registered_outer_mask=0\nepollfd_write=8\nepollfd_signalled_poll=1\nepollfd_signalled_poll_mask=1\nepollfd_signalled_outer=0\nepollfd_signalled_outer_mask=0\nepollfd_signalled_child=1\nepollfd_signalled_child_mask=1\nepollfd_read=8\nepollfd_read_value=1\nepollfd_drained_poll=0\nepollfd_drained_poll_mask=0\nepollfd_drained_outer=0\nepollfd_drained_outer_mask=0\nepollfd_drained_child=0\nepollfd_drained_child_mask=0\n"` | `doorbell 0xd1` | `doorbell 0xc5 (forward capture)` |
| `epolletblockedhup` | `exit 0` | `"pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epolletchildhup` | `exit 0` | `"pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epolletmanyhup` | `exit 0` | `"pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epolletpipeeof` | `exit 0` | `"pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollexclusive` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollforkeventfd` | `soft slot 10 changed or retired without a retirement protocol` | `"setup_ok=true\nepoll_add_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `epollinmemwake` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(24274), expected: EntryTaskKey(24273) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `epolloutrearm` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epolloutxthread` | `exit 0` | `"woke_via_epollout=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollpri` | `exit 0` | `"epollpri_setup_ok=false\nepollpri_add_ok=false\nepollpri_send_oob_ok=false\nepollpri_wait_ready=false\nepollpri_revents_pri=false\nepollpri_recv_oob_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollpwait` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `epollstaledel` | `exit 0` | `"setup_ok=false\nfirst_returned_one=false\nfirst_data_is_token=false\nno_stale_event_after_del=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollstopcont` | `terminated by signal 6` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `epollzoneclose` | `terminated by signal 6` | `"dup_add_rc=0\nsurvives_close_n=1\nsurvives_close_tag=111\ndel_closed_rc=-1\ndel_closed_errno=9\ngone_after_last_close_n=0\nreadd_rc=0\nreadd_errno=0\nreadd_n=1\nreadd_tag=222\ntwo_items_add_rc1=0\ntwo_items_add_rc2=0\ntwo_items_n=2\ntwo_items_tag_sum=3000\nafter_dup_close_n=2\nafter_dup_close_tag_sum=3000\nadd_twice_rc=-1\nadd_twice_errno=17\nmod_unregistered_rc=-1\nmod_unregistered_errno=2\ndel_unregistered_rc=-1\ndel_unregistered_errno=2\nadd_self_rc=-1\nadd_self_errno=22\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollzoneeintr` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `epollzonemixed` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollzonepingpong` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `epollzonesigmask` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4873000, actual CR3 0x487d000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `epollzonetimeout` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `epollzonetrigger` | `exit 0` | `"lt_eventfd_n1=1\nlt_eventfd_mask=1\nlt_eventfd_n2=1\nlt_eventfd_n3=0\net_eventfd_n1=1\net_eventfd_mask=1\net_eventfd_n2=0\net_eventfd_n3_new_write=1\net_eventfd_n4_after_read=0\net_pipe_n1=1\net_pipe_partial_read=1\net_pipe_n2_after_partial=0\net_pipe_n3_new_write=1\nhup_pipe_with_data_n=1\nhup_pipe_with_data_mask=17\nhup_pipe_drained_bytes=2\nhup_pipe_empty_n=1\nhup_pipe_empty_mask=16\net_hup_n0=0\net_hup_n1=1\net_hup_mask=16\net_hup_n2=0\nwriter_n0=1\nwriter_mask0=4\nwriter_reader_closed_n=1\nwriter_reader_closed_mask=12\noneshot_n1=1\noneshot_n2_disarmed=0\noneshot_n3_new_write=0\noneshot_mod_rc=0\noneshot_n4_rearmed=1\noneshot_n5_disarmed=0\nout_only_n=1\nout_only_mask=4\nin_out_mod_rc=0\nin_out_n=1\nin_out_mask=5\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `etchostnamefile` | `exit 0` | `"etc_hostname_present=false\netc_hostname_matches_gethostname=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `eventfdsignalmatrix` | `exit 0` | `"eventfd_flags_cloexec=true\neventfd_flags_nonblock=true\neventfd_sem_decrement_to_eagain=true\neventfd_ord_aggregate_and_reset=true\neventfd_short_read_einval=true\neventfd_short_write_einval=true\neventfd_write_u64_max_einval=true\neventfd_write_overflow_eagain=true\nsignalfd_sigprocmask_ok=true\nsignalfd_flags_cloexec=false\nsignalfd_flags_nonblock=false\nsignalfd_update_same_fd=false\nsignalfd_batch_drain_records=false\nsignalfd_empty_eagain=false\nsignalfd_short_read_einval=false\nsignalfd_signals_drained=true\nsignalfd_mask_restored=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `eventwaitmatrix` | `exit 0` | `"clock_adjtime_monotonic_einval=false\nclock_adjtime_boottime_einval=false\nclock_adjtime_process_cputime_einval=false\nclock_adjtime_invalid_clockid_einval=false\nclock_adjtime_null_timex_efault=false\nclock_settime_monotonic_einval=false\nclock_settime_invalid_clockid_einval=false\nclock_settime_negative_nsec_einval=false\nclock_settime_overflow_nsec_einval=false\nclock_settime_null_timespec_efault=false\ntimerfd_create_nonblock_cloexec_ok=false\ntimerfd_create_is_nonblock=false\ntimerfd_create_is_cloexec=false\ntimerfd_create_realtime_ok=false\ntimerfd_create_boottime_ok=false\ntimerfd_create_cputime_einval=false\ntimerfd_create_invalid_clockid_einval=false\ntimerfd_create_invalid_flags_einval=false\ntimerfd_settime_invalid_flags_einval=false\ntimerfd_settime_cancel_without_abstime_einval=false\ntimerfd_settime_cancel_on_monotonic_einval=false\ntimerfd_settime_bad_value_nsec_einval=false\ntimerfd_settime_bad_interval_nsec_einval=false\ntimerfd_settime_pipe_fd_einval=false\ntimerfd_settime_bad_fd_ebadf=false\ntimerfd_gettime_pipe_fd_einval=false\ntimerfd_gettime_bad_fd_ebadf=false\ntimerfd_disarm_returned_old_value=false\ntimerfd_disarm_gettime_zero=false\ntimerfd_unfired_nonblock_read_eagain=false\ntimer_settime_invalid_id_einval=false\ntimer_gettime_invalid_id_einval=false\ntimer_delete_invalid_id_einval=false\ntimer_getoverrun_invalid_id_einval=false\nfutex_wait_negative_nsec_einval=false\nfutex_wait_overflow_nsec_einval=false\nfutex_wait_unaligned_address_einval=false\nfutex_wait_zero_timeout_etimedout=true\nfutex_wait_bitset_zero_mask_einval=false\nfutex_wait_bitset_bad_timespec_einval=false\nfutex_wait_bitset_past_realtime_etimedout=false\nfutex_invalid_op_enosys=true\nmq_open_ok=false\nmq_timedsend_bad_fd_ebadf=false\nmq_timedreceive_bad_fd_ebadf=false\nmq_timedsend_pipe_fd_ebadf=false\nmq_timedreceive_pipe_fd_ebadf=false\nmq_timedsend_rdonly_ebadf=false\nmq_timedreceive_wronly_ebadf=false\nmq_timedsend_msg_too_large_emsgsize=false\nmq_timedreceive_buffer_too_small_emsgsize=false\nmq_timedsend_invalid_prio_einval=false\nmq_timedsend_negative_nsec_einval=false\nmq_timedsend_overflow_nsec_einval=false\nmq_timedreceive_negative_nsec_einval=false\nmq_timedreceive_overflow_nsec_einval=false\nmq_timedreceive_empty_past_etimedout=false\nmq_timedsend_fill_ok=false\nmq_timedsend_full_past_etimedout=false\nmq_timedreceive_drain_ok=false\nppoll_negative_nsec_einval=true\nppoll_overflow_nsec_einval=true\nppoll_negative_fd_ignored=true\npoll_negative_fd_ignored=true\npselect6_negative_nsec_einval=false\npselect6_overflow_nsec_einval=false\nselect_negative_nfds_einval=false\npselect6_negative_nfds_einval=false\nselect_zero_timeout_ready_zero=false\npselect6_zero_timeout_ready_zero=false\npoll_zero_timeout_revents_zero=true\nppoll_zero_timeout_revents_zero=true\nepoll_wait_zero_timeout_events_zero=true\nepoll_pwait_zero_timeout_events_zero=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execfailsurvive` | `exit 2` | `"setup_keepfile=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execfatalstatus` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `execfromthread` | `terminated by signal 6` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `execpermitchurn` | `block budget exhausted, rip=0xffffffff8009cbb0 cpl=0 cr3=0x4874000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd2` |
| `execpipe` | `terminated by signal 6` | `"pipe_setup_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execsig` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execsocket` | `terminated by signal 6` | `"socketpair_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execthreads` | `exit 0` | `"stage1_pthread_create_errno=11\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `execvenonutf8` | `soft slot 14 changed or retired without a retirement protocol` | `"forked=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `execvereset` | `exit 3` | `"stage1_execve_failed_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `exitgroupmainthreads` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `exitgroupthreads` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `exitstatus127` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `expectcontinue` | `exit 0` | `"expectcontinue_body_wake=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fallocatebig` | `exit 0` | `"open=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fanotifyondir` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `faultaddr` | `exit 0` | `"si_addr_match=true\nfault_addr_match=false\nDONE\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fchmoddir` | `exit 0` | `"fchmod_sticky_1777=false\nfchmod_plain_0750=false\nfchmod_setgid_2755=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntlgetlk` | `exit 0` | `"open_ok=false\ngetlk_ok=false\ngetlk_type_unlck=false\ngetlk_lpid_preserved=true\ngetlk_whence_preserved=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntllease` | `exit 0` | `"setlease_rdlck_ok=false\ngetlease_is_rdlck=false\nsetlease_unlck_ok=false\ngetlease_is_unlck=false\nsetlease_bad_type_einval=false\nsetlease_rdlck_on_rdwr_eagain=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntllock` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntlofdlock` | `exit 0` | `"ofd_open=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntlowner` | `exit 0` | `"setown_ok=false\ngetown_roundtrip=false\nsetsig_ok=false\ngetsig_roundtrip=false\nsetown_ex_ok=false\ngetown_ex_roundtrip=false\ngetsig_default_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntlpipesz` | `exit 0` | `"getpipe_default_ge_4096=false\nsetpipe_ok=false\ngetpipe_eq_set=false\nfnotify_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fcntlstdio` | `exit 0` | `"getfl_fd0_ok=true\nsetfl_nonblock_fd0_ok=true\ngetfd_fd0_ok=true\nsetfd_fd0_ok=true\ngetfl_fd1_ok=true\nsetfl_nonblock_fd1_ok=true\ngetfd_fd1_ok=true\nsetfd_fd1_ok=true\ngetfl_fd2_ok=true\nsetfl_nonblock_fd2_ok=true\ngetfd_fd2_ok=true\nsetfd_fd2_ok=true\nsetfl_badfd_ebadf=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fdceiling` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fdio` | `exit 0` | `"pipe2=ERR:38\ndup=ERR:38\nlseek=ERR:38\npwrite=ERR:38\nfcntl=ERR:38\no_append=ERR:38\nftruncate=ERR:38\nwritev=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fdsemantics` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fdstat` | `exit 0` | `"open=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fdstatus` | `exit 0` | `"pipe_ok=true\npipe_read_rdonly=true\npipe_write_wronly=true\npipe_cloexec_not_nonblock=true\nsocket_ok=true\nsocket0_rdwr=true\nsocket1_rdwr=true\nsock_cloexec_not_nonblock=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fexecveprobe` | `exit 0` | `"fexecve_runs=false\nfexecve_rootfs_binary_after_chdir=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fgetflcreate` | `exit 0` | `"open_ok=false\nno_o_creat=false\nno_o_trunc=false\naccmode_is_rdwr=false\nkeeps_o_nonblock=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fifoepolleof` | `exit 0` | `"mkfifo_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fifoforkeof` | `exit 0` | `"mkfifo_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fifonode` | `terminated by signal 6` | `"mknod_fifo_ok=false\nstat_ok=false\nstat_is_fifo=false\nstat_mode_0644=false\nopen_rdwr_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fifoopenmatrix` | `exit 0` | `"nonblock_reader_without_writer_ok=false\nnonblock_writer_without_reader_enxio=false\nrdwr_immediate_success=false\ncreat_excl_existing_fifo_eexist=false\nflags_o_nonblock_retained=false\nflags_o_cloexec_retained=false\nrdwr_cloexec_retained=false\nreader_blocked_without_writer=false\nreader_unblocked_after_writer=false\nwriter_blocked_without_reader=false\nwriter_unblocked_after_reader=false\ndelayed_peer_writer_succeeded=false\ndelayed_peer_writer_enxio=false\ninterrupted_open_eintr=false\nsa_restart_stayed_blocked=false\nsa_restart_open_resumed_and_succeeded=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fileaccessmode` | `soft slot 11 changed or retired without a retirement protocol` | `"create_ok=false\nseed_written=false\nrdonly_accmode=2097155\nrdonly_nonblock=true\nrdonly_append=true\nwronly_accmode=2097155\nwronly_nonblock=true\nrdwr_append_accmode=2097155\nrdwr_append_append=true\nrdwr_append_nonblock=true\nexplicit_nonblock_reported=true\nsetfl_clear_rc=-1\nafter_clear_nonblock=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `flocklock` | `exit 0` | `"flock_ex_ok=false\nflock_conflict_eagain=false\nflock_un_ok=false\nflock_reacquire_ok=false\nflock_badfd_ebadf=true\nflock_worker_setup_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkaltstack` | `soft slot 11 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkcow` | `soft slot 11 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkexecpthread` | `soft slot 10 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkexecstorm` | `exit 1` | `"threads_started=0\nthreads_completed=0\nthreads_joined=0\ntotal_attempted=0\ntotal_spawned=0\ntotal_reaped=0\ntotal_exited_ok=0\nvfork_failures=1\nfirst_vfork_errno=38\nwait_failures=0\nfirst_wait_errno=0\nunexpected_status_count=0\nfirst_unexpected_status=0\ntimed_out=false\nfork_exec_storm_success=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkfault` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkfiletable` | `exit 0` | `"fork_succeeded=false\nchild_open_isolated_from_parent=false\nparent_slot_installed=false\nparent_open_isolated_from_child=false\nshared_offset_child_read_prefix=false\nshared_offset_parent_read_next=false\nshared_status_visible_in_parent=false\ndescriptor_flags_isolated_from_parent=false\nchild_exited_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkfpreclaim` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(65569), expected: EntryTaskKey(65563) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `forkheapalloc` | `soft slot 11 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkhighva` | `soft slot 10 changed or retired without a retirement protocol` | `"parent_highva_map_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkprotectexec` | `soft slot 11 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forkreadexitcow` | `exit 0` | `"setup=false errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkserial` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkshared` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forksigwalk` | `soft slot 15 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `forksnapshot` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forksplicestage` | `exit 0` | `"splice_staged_all=false\nfork_after_splice_succeeded=false\nparent_consumed_prefix=false\nchild_consumed_middle=false\nparent_consumed_suffix=false\nglobal_pipe_order_exact=false\nchild_exited_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `forkstackstorm` | `block budget exhausted, rip=0x880000af38 cpl=3 cr3=0x4878000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `fsescapeguard` | `exit 0` | `"intermediate_symlink_no_host_read=true\nleaf_symlink_no_host_read=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fsetfl` | `exit 0` | `"setup_open_ok=false\nopen_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fsmeta` | `exit 0` | `"getcwd=/\nstat_passwd=ERR:38\nlstat_symlink=ERR:38\nstat_symlink=ERR:38\nreadlink=ERR:38\naccess_passwd_r=-1\naccess_passwd_w=-1\naccess_sh_x=-1\naccess_missing=-1\nreadlink=ERR:38\nrename src_gone=true dst_exists=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fstatatflags` | `exit 0` | `"seed=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `fsx` | `exit 0` | `"statfs_root bsize_pos=true blocks_pos=true\nfstatfs_root=ERR:38\nutimensat=ERR:2\nfadvise=ERR:38\nfallocate=ERR:38\nsync rc=0\nsyncfs=ERR:38\nfsync=ERR:38\nsetxattr=ERR:2\ngetxattr=ERR:2\nlistxattr=ERR:2\nremovexattr=ERR:2\ngetxattr_after_remove=ERR:2\nremovexattr_absent=ERR:2\nremovexattr_nopath=ERR:2\nfaccessat2_passwd_r=ERR:38\nreadlinkat_exe_nonempty=true\nchdir_tmp=ERR:2\nmknod_reg=ERR:38\nmknod_reg_exists=false\nmknodat_reg=ERR:2\nmknodat_reg_exists=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexcheckpointexit` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexdeadline` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexextra` | `terminated by signal 6` | `"wait_mismatch_rc_is_minus_one=true\nwait_mismatch_errno_is_eagain=true\nwaitbitset_mismatch_rc_is_minus_one=true\nwaitbitset_mismatch_errno_is_eagain=true\nwake_no_waiters_rc_is_zero=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexforkrequeue` | `exit 0` | `"shared_map_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexforkwakegroups` | `soft slot 15 changed or retired without a retirement protocol` | `"grandchild_fork_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `futexghost` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexpilock` | `exit 0` | `"lock_pi_uncontended_rc_zero=false\nlock_pi_records_owner_tid=false\ntrylock_pi_self_rc_neg_one=true\ntrylock_pi_self_errno_edeadlk=false\nunlock_pi_owner_rc_zero=false\nunlock_pi_clears_word=true\nunlock_pi_unowned_rc_neg_one=true\nunlock_pi_unowned_errno_eperm=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexpingpong` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexprivatewakeexact` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexrealtime` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexrequeue` | `terminated by signal 6` | `"cmp_requeue_mismatch_rc_neg_one=true\ncmp_requeue_mismatch_errno_eagain=false\ncmp_requeue_neg_count_rc_neg_one=true\ncmp_requeue_neg_count_errno_einval=false\nrequeue_empty_returns_zero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexshare` | `exit 0` | `"futex_shared_setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexsharedalias` | `exit 0` | `"futex_shared_alias_setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexsharedto` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexwaiterstates` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexwakecount` | `exit 0` | `"futex_wake_N1_woke_at_least_N=false\nfutex_wake_N1_all_children_reaped=false\nfutex_wake_N2_woke_at_least_N=false\nfutex_wake_N2_all_children_reaped=false\nfutex_wake_N5_woke_at_least_N=false\nfutex_wake_N5_all_children_reaped=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `futexwakeexact` | `exit 0` | `"max_wake_return=ERR\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `getrandomflags` | `exit 0` | `"valid_no_flags_ok=true\nvalid_nonblock_ok=true\nvalid_random_ok=true\ninvalid_flag_einval=true\nall_bits_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `getrandomvdso` | `exit 0` | `"kernel_getrandom_absent=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `getrandomvdsofork` | `exit 0` | `"kernel_getrandom_absent=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `getrandomvdsoloop` | `exit 0` | `"kernel_getrandom_absent=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `getsocknameval` | `exit 0` | `"getsockname_null_addr_efault=false\ngetsockname_null_len_efault=false\ngetsockname_neg_len_einval=false\ngetsockname_ok=false\ngetpeername_neg_len_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `hostreadunmap` | `exit 0` | `"setup=mmap_shared_failed\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `hugepage` | `exit 0` | `"madv_hugepage_ok=false\nmadv_nohugepage_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `icmp` | `exit 0` | `"icmp_ping_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `inotifymatrix` | `unserved host readiness wait Some(250ms): parking needs an execution lease` | `"init1_default_flags_ok=false\ninit1_cloexec_ok=false\ninit1_nonblock_ok=false\ninit1_both_flags_ok=false\ninit1_invalid_flags_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `forward 0x1=33` |
| `inotifyqueue` | `unserved host readiness wait Some(250ms): parking needs an execution lease` | `""` | `forward 0xfffffffffffffeff=0` | `forward 0xfffffffffffffeff=0` |
| `inotifywakethread` | `unserved host readiness wait Some(3s): parking needs an execution lease` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `inotifywrite` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `inzonetcpclose` | `unserved host readiness wait Some(500ms): parking needs an execution lease` | `""` | `forward 0xfffffffffffffeff=0` | `forward 0xfffffffffffffeff=0` |
| `inzonetcpoob` | `exit 0` | `"oob_case=default\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\nconnect_attempted=false\nconnect_rc=0\nconnect_errno=0\nconnect_poll_attempted=false\nconnect_poll_rc=0\nconnect_poll_errno=0\nconnect_so_error_attempted=false\nconnect_so_error_rc=0\nconnect_so_error_errno=0\nconnect_so_error_value=-1\naccept_poll_attempted=false\naccept_poll_rc=0\naccept_poll_errno=0\naccept_attempted=false\naccept_rc=0\naccept_errno=0\nset_inline_attempted=false\nset_inline_rc=0\nset_inline_errno=0\nsend_oob_attempted=false\nsend_oob_rc=0\nsend_oob_errno=0\nsend_normal_attempted=false\nsend_normal_rc=0\nsend_normal_errno=0\nready_poll_attempted=false\nready_poll_rc=0\nready_poll_errno=0\nready_poll_revents=0\nmark_before_attempted=false\nmark_before_rc=0\nmark_before_errno=0\nmark_before_value=-1\nnormal_first_attempted=false\nnormal_first_rc=0\nnormal_first_errno=0\nnormal_first_hex=\nmark_after_first_attempted=false\nmark_after_first_rc=0\nmark_after_first_errno=0\nmark_after_first_value=-1\nrecv_oob_attempted=false\nrecv_oob_rc=0\nrecv_oob_errno=0\nrecv_oob_hex=\nmark_after_oob_attempted=false\nmark_after_oob_rc=0\nmark_after_oob_errno=0\nmark_after_oob_value=-1\nsecond_ready_poll_attempted=false\nsecond_ready_poll_rc=0\nsecond_ready_poll_errno=0\nsecond_ready_poll_revents=0\nnormal_second_attempted=false\nnormal_second_rc=0\nnormal_second_errno=0\nnormal_second_hex=\noob_case=inline\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\nconnect_attempted=false\nconnect_rc=0\nconnect_errno=0\nconnect_poll_attempted=false\nconnect_poll_rc=0\nconnect_poll_errno=0\nconnect_so_error_attempted=false\nconnect_so_error_rc=0\nconnect_so_error_errno=0\nconnect_so_error_value=-1\naccept_poll_attempted=false\naccept_poll_rc=0\naccept_poll_errno=0\naccept_attempted=false\naccept_rc=0\naccept_errno=0\nset_inline_attempted=false\nset_inline_rc=0\nset_inline_errno=0\nsend_oob_attempted=false\nsend_oob_rc=0\nsend_oob_errno=0\nsend_normal_attempted=false\nsend_normal_rc=0\nsend_normal_errno=0\nready_poll_attempted=false\nready_poll_rc=0\nready_poll_errno=0\nready_poll_revents=0\nmark_before_attempted=false\nmark_before_rc=0\nmark_before_errno=0\nmark_before_value=-1\nnormal_first_attempted=false\nnormal_first_rc=0\nnormal_first_errno=0\nnormal_first_hex=\nmark_after_first_attempted=false\nmark_after_first_rc=0\nmark_after_first_errno=0\nmark_after_first_value=-1\nrecv_oob_attempted=false\nrecv_oob_rc=0\nrecv_oob_errno=0\nrecv_oob_hex=\nmark_after_oob_attempted=false\nmark_after_oob_rc=0\nmark_after_oob_errno=0\nmark_after_oob_value=-1\nsecond_ready_poll_attempted=false\nsecond_ready_poll_rc=0\nsecond_ready_poll_errno=0\nsecond_ready_poll_revents=0\nnormal_second_attempted=false\nnormal_second_rc=0\nnormal_second_errno=0\nnormal_second_hex=\noob_case=cross_mark\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\noob_case=peek\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\noob_case=repeated\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\noob_case=toggle_after_arrival\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\noob_case=zero_length\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\noob_case=inline_mark_peek\nsetup_attempted=true\nsetup_rc=-1\nsetup_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ioctlcluster` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `iopriovhangup` | `exit 0` | `"set_be4_ok=false\nget_returns_be4=false\nnone_level0_ok=false\nnone_nonzero_einval=false\nbad_which_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `iouring` | `exit 0` | `"iouring_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `iouringenterflag` | `exit 0` | `"bad_flag_rejected=true\nnormal_nop_completes=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `iouringsqpoll` | `exit 0` | `"sqpoll_rejected_or_unavailable=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `iovecedge` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ipv6recvhoplimit` | `exit 0` | `"hoplimit_cmsg_received=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ipv6sendhoplimit` | `exit 0` | `"sent_hoplimit_roundtrips=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `itimer` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `itimerprofidle` | `exit 0` | `"prof_idle_arm_rc_zero=false\nprof_idle_no_ticks=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `kernelidentity` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `keydeny` | `exit 0` | `"add_key_ret=-1\nadd_key_errno=38\nrequest_key_ret=-1\nrequest_key_errno=38\nkeyctl_join_ret=-1\nkeyctl_join_errno=38\nkeyctl_get_keyring_id_ret=-1\nkeyctl_get_keyring_id_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `killchld` | `exit 0` | `"caught=0\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `killfault` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `killgroup` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `killreap` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `killrt` | `soft slot 9 changed or retired without a retirement protocol` | `"rt_code=-1 rt_value=0xcafe correct=1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `killtarget` | `exit 0` | `"kill_self_sig0_rc_zero=true\nkill_self_usr1_rc_zero=true\nkill_self_usr1_handler_ran_once=true\nkill_neg_pgid_rc_zero=true\nkill_neg_pgid_delivered=true\nkill_zero_rc_zero=true\nkill_zero_delivered=true\nkill_bogus_rc_minus_one=true\nkill_bogus_errno_is_esrch=true\ntkill_zero_tid_rc_minus_one=true\ntkill_zero_tid_errno_is_einval=true\ntkill_bogus_tid_rc_minus_one=true\ntkill_bogus_tid_errno_is_esrch=true\ntgkill_zero_tgid_rc_minus_one=true\ntgkill_zero_tgid_errno_is_einval=true\ntgkill_zero_tid_rc_minus_one=true\ntgkill_zero_tid_errno_is_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `killuidperm` | `soft slot 13 changed or retired without a retirement protocol` | `"root_to_other_uid_allowed=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `lchownsymlink` | `exit 0` | `"link_owner_set=false\ntarget_untouched=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `legacyaio` | `exit 0` | `"null_ctx_errno=38\nnonzero_ctx_errno=38\nzero_events_errno=38\nhuge_errno=38\nu32_neg_events_errno=38\nover_aio_max_errno=38\nsetup_errno=38\nctx_nonzero=false\ndestroy_invalid_errno=38\ngetevents_invalid_errno=38\ncancel_null_errno=38\ncancel_invalid_null_errno=38\naio_max_nr_readable=false\nfds_ok=false\nsubmit_one=-1\nsubmit_zero=-1\ninvalid_nr_errno=38\ninvalid_iocbpp_errno=38\nnull_iocb_errno=38\nbadfd_errno=38\nread_wronly_errno=38\nwrite_rdonly_errno=38\ndestroy_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `legacyfs` | `exit 0` | `"mkdir=false\ncreat=false\nchmod=false\nchmod_verified=false\nchown=false\nlink=false\nlink_verified=false\nunlink=false\nunlink_verified=false\nsymlink=false\nreadlink=false\nrename=false\nrename_verified=false\nmknod=false\nmknod_verified=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `lifecycleflagmatrix` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `linkatflag` | `exit 0` | `"setup_target_ok=false\nsetup_sym_ok=false\nfollow_rc_zero=false\nbogus_einval=true\ndefault_link_rc_zero=false\nnofollow_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `linkstat` | `exit 0` | `"symlink_setup=ERR:2\nreadlinkat_sym_rc_pos=false\nreadlinkat_sym_target_match=false\nreadlinkat_regfile_errno=2\nreadlinkat_dir_errno=2\nreadlinkat_missing_errno=2\nreadlinkat_short_count=ERR:2\nreadlinkat_procexe_nonempty=true\nfstat_regfile=ERR:38\nfstat_dir=ERR:38\nlstat_symlink=ERR:38\nfstat_pipe_rd=ERR:38\nfstat_pipe_wr=ERR:38\nfstat_eventfd=other\nfstat_socket=sock\nc_symlink_setup=ERR:2\nc_fstatat_follow=ERR:38\nc_fstatat_nofollow=ERR:38\nc_statx_follow=ERR:38\nc_statx_nofollow=ERR:38\nfstat_stdin=chr\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `linuxsysinfo` | `exit 0` | `"sysinfo_rc_zero=true\nmem_unit_is_one=true\nmem_unit_not_65536=true\ntotalhigh_zero=true\nfreehigh_zero=true\ntotalram_nonzero=true\nprocs_at_least_one=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `loopbacksubnet` | `exit 0` | `"bind_127_0_1_1=false\nbind_127_0_0_9=false\nloopback_subnet_roundtrip=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ltpcheckpoint` | `exit 0` | `"devshm_access_ok=false\nshm_open_ok=false\nshm_open_errno=38\nshm_chmod_ok=false\nshm_ftruncate_ok=false\nshm_mmap_ok=false\nshm_close_ok=false\nshm_post_close_writable=false\nshm_fork_child_sees_parent_write=false\nshm_futex_xprocess_wake_wakes_wait=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ltpcheckpointexec` | `exit 0` | `"shm_create_ok=false\nshm_mmap_ok=false\nexec_child_woke_parent_wait=false\nexec_child_exit_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `lutimesym` | `exit 0` | `"setup=false open_target\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `lxattr` | `exit 0` | `"reg_lsetxattr_ok=false\nreg_lgetxattr_roundtrip=false\nreg_llistxattr_has=false\nreg_lremovexattr_ok=false\nreg_lgetxattr_after_remove_enodata=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mailboxregs` | `exit 0` | `"mailboxregs skipped_non_aarch64=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mapfixed` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mapfixedfork` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `maskfork` | `exit 0` | `"setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mcastjoingroup` | `exit 0` | `"tcp_socket=ERR:38\nudp_socket=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mem` | `exit 0` | `"mmap_anon_ok=true\nmmap_anon_readback=0,1,2,3\nmprotect_r_rc=0\nmadvise_dontneed=ERR:38\nmunmap_rc=0\nmremap=ERR:38\nsbrk0_nonzero=true\nmlock=ERR:38\nmunlock=ERR:38\nmsync=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `memfdcreate` | `exit 0` | `"memfd_cloexec_ok=false\nmemfd_sealing_ok=false\nmemfd_bad_flag_einval=false\nmemfd_null_name_efault=false\nmemfd_long_name_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `memfdsealmatrix` | `exit 0` | `"noseal_initial_seal=false\nnoseal_add_shrink_eperm=false\nnoseal_add_grow_eperm=false\nnoseal_add_write_eperm=false\nnoseal_seals_unchanged=false\nallow_sealing_initial_empty=false\nseal_grow_added=false\nseal_grow_prevents_grow=false\nseal_grow_allows_same_size=false\nseal_grow_allows_shrink=false\nseal_grow_prevents_grow_back=false\nseal_grow_pwrite_past_eof_eperm=false\nseal_grow_pwrite_within_size_ok=false\nseal_shrink_added=false\nseal_shrink_prevents_shrink=false\nseal_shrink_allows_same_size=false\nseal_shrink_allows_grow=false\nseal_shrink_prevents_shrink_back=false\nseal_fixed_added=false\nseal_fixed_prevents_grow=false\nseal_fixed_prevents_shrink=false\nseal_fixed_allows_same_size=false\nseal_write_added=false\nseal_write_pwrite_eperm=false\nseal_write_write_eperm=false\nseal_write_pread_ok=false\nseal_write_active_shared_mmap_ebusy=false\nseal_write_ebusy_seals_unchanged=false\nseal_write_active_mmap_writable=false\nseal_write_after_unmap_ok=false\nseal_write_after_unmap_seals_has_write=false\nseal_write_new_shared_rw_map_eperm=false\nseal_write_new_shared_ro_map_ok=false\nseal_write_new_private_rw_map_ok=false\nseal_seal_pre_shrink_ok=false\nseal_seal_added_ok=false\nseal_seal_blocks_add_grow_eperm=false\nseal_seal_blocks_add_write_eperm=false\nseal_seal_blocks_readd_seal_eperm=false\nseal_seal_final_seals_unchanged=false\ndup_initial_both_empty=false\ndup_grow_visible_on_both=false\ndup_shrink_visible_on_both=false\ndup_grow_enforced_on_dup=false\ndup_shrink_enforced_on_orig=false\nseal_future_write_add_with_active_map_ok=false\nseal_future_write_seals_has_future_write=false\nseal_future_write_existing_mmap_write_ok=false\nseal_future_write_pwrite_eperm=false\nseal_future_write_write_eperm=false\nseal_future_write_new_shared_rw_map_eperm=false\nseal_future_write_pread_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `memfdsecret` | `exit 0` | `"create_badflags_einval=false\ncreate_ok=false\ncloexec_default_clear=false\nfd_link_secretmem=false\nread_errno=-1\nwrite_errno=-1\nftruncate_ok=false\nfstat_size=-1\nmmap_private_errno=-1\nmmap_shared_ok=false\nmap_rw=false\nprocmem_hidden=false\ncreate_cloexec_set=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `memfdsharedcoherence` | `soft slot 11 changed or retired without a retirement protocol` | `"memfd_created=false\nshared_map_ok=false\ninitial_zero=false\nstore_visible_to_pread=false\nstore_visible_to_dup_pread=false\nstore_visible_in_second_map=false\npwrite_ok=false\npwrite_visible_in_map=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `memflagmatrix` | `terminated by signal 6` | `"mmap_no_type_einval=false\nmmap_both_types_einval=false\nmmap_len_zero_einval=true\nmmap_unaligned_offset_einval=true\nmmap_invalid_prot_result=errno:38\nmmap_fixed_unaligned_einval=true\nmmap_fixed_noreplace_eexist=true\nmmap_fixed_noreplace_unmapped_ok=true\nmmap_populate_resident=false\nmmap_unpopulated_not_resident=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `memmap` | `exit 0` | `"pagesize_sane=true\na_mremap_grow_2to8=ERR:38\na2_grow_nomaymove_enomem=false\na2_grow_maymove=ERR:38\nb_open=ERR:38\nc_mmap_len0=ERR:22\nc_mprotect_rw_rc_success=true\nc_protnone_then_rw_readback_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mincoreedge` | `exit 0` | `"invalid_vec_errno=38\nhole_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mkdirsetgid` | `exit 0` | `"mkdir_child_ok=false\nstat_ok=false\nchild_gid_inherited_100=false\nchild_has_setgid=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mknoddevnode` | `exit 0` | `"cdev_mknod=ERR:38\nbdev_mknod=ERR:38\nsock_mknod=ERR:38\ncdev_eexist=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mlock2` | `exit 0` | `"mlock2_onfault_ok=false\nmlock2_vmlck_grew=false\nmlock2_repeat_not_double=false\nmlock2_invalid_flag_einval=false\nmlock2_unmapped_enomem=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapanonreuse` | `exit 0` | `"mmapanonreuse=CLEAN\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapcage` | `exit 0` | `"reserved_oversized_prot_none=true\ntrimmed_head=true\ntrimmed_tail=true\naligned_region_survives=true\ncommitted_inside_reservation=true\ncommitted_reads_zero=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapcluster` | `exit 0` | `"private_perms=MAP_FAILED\nshared_perms=MAP_FAILED\nwrite_only_errno=9\nnoreplace_errno=17\npagemap_open_ok=false\nbus_child_signal=-1\nhigh_errno=38\nvma64g_map_errno=12\nvma64g_protected_pages=0\nvma64g_initial_zero_pages=0\nvma64g_distinct_pages=0\nvma64g_unmap=-1\nvma16t_map_errno=12\nvma16t_protected_pages=0\nvma16t_initial_zero_pages=0\nvma16t_distinct_pages=0\nvma16t_unmap=-1\nvma64g_rw_map_errno=12\nvma64g_rw_pipe_errno=0\nvma64g_rw_initial_zero_pages=0\nvma64g_rw_distinct_groups=0\nvma64g_rw_kernel_first_copyin=0\nvma64g_rw_kernel_first_copyout=0\nvma64g_rw_unmap=-1\nvma16t_rw_map_errno=12\nvma16t_rw_pipe_errno=0\nvma16t_rw_initial_zero_pages=0\nvma16t_rw_distinct_groups=0\nvma16t_rw_kernel_first_copyin=0\nvma16t_rw_kernel_first_copyout=0\nvma16t_rw_unmap=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapdevzero` | `exit 0` | `"open=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapexecshared` | `exit 0` | `"open_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapfile` | `exit 0` | `"open FAIL\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapfileforkwriteback` | `exit 0` | `"setup_open=false\nsetup_truncate=false\nsetup_mmap=false\nchild_saw_parent_pre=false\nparent_saw_child_map=false\nfile_saw_child_write=false\nfile_saw_parent_post=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapfileshare_mt` | `exit 0` | `"open FAIL\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapmunmap` | `exit 0` | `"mmap_badfd_len0_fails=true\nmmap_badfd_len0_ebadf=false\nmmap_validfd_len0_einval=false\nmmap_shared_ok=false\nmunmap_shared_ok=false\nmmap_private_ok=false\nmunmap_private_ok=false\nmunmap_unaligned_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapprivatefiletrack` | `exit 0` | `"memfd_created=false\nmemfd_private_map_ok=false\nmemfd_initial_contents=false\nmemfd_store_not_in_file=false\nmemfd_clean_page_sees_file_write=false\nmemfd_dirty_page_keeps_cow_copy=false\nfile_created=false\nfile_private_map_ok=false\nfile_initial_contents=false\nfile_store_not_in_file=false\nfile_clean_page_sees_file_write=false\nfile_dirty_page_keeps_cow_copy=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapprivfile` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmaprecl` | `block budget exhausted, rip=0xffffffff8001843d cpl=0 cr3=0x4872000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `mmapreuse` | `exit 0` | `"mmapreuse=CLEAN\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmaptrimprotect` | `exit 0` | `"hinted_high_result=-1\nhinted_high2_result=-1\nhinted_high_shared_fork_visibility=-1\nv8_readonly_page_errno=0\ntail_trim_only_errno=0\nlarge_reserve_errno=0\nuntrimmed_control_errno=0\nhinted_high_live_mprotect_errno=-1\nhinted_high_rw_roundtrip=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mmapzerofill` | `block budget exhausted, rip=0x880000961d cpl=3 cr3=0x4872000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `mmsgmatrix` | `exit 0` | `"setup_socketpair_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mock_network_socket` | `exit 0` | `"sock_created=false\nnonblock_set=false\nsocketpair_ok=true\nread_eagain=true\nfull_write_ok=true\nselect_readable=false\npoll_readable=true\nepoll_add_ok=true\nepoll_edge1=true\npartial_read_ok=true\nepollet_no_spurious_edge=false\nfull_drain_ok=true\ndup_ok=true\ndup_write_ok=true\ndup_read_ok=true\nshutdown_ok=true\nshut_write_epipe=true\neof_received=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mprotectexec` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `mqnotifycrossproc` | `terminated by signal 6` | `"signal_queue_opened=false\nsignal_notification_registered=false\nsignal_child_sent=false\nsignal_received=false\nsignal_code_is_mesgq=false\nsignal_sender_pid_matches_child=false\nsignal_sender_uid_matches_child_ruid=false\nsignal_value_matches=false\nsignal_child_reaped=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mqueue` | `exit 0` | `"mq_open_leading_slash_eacces=false\nmq_open_embedded_slash_eacces=false\nmq_open_empty_enoent=false\nmq_open_create_ok=false\nmq_open_create_errno=E38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mqueueworkerprogress` | `exit 1` | `"receive_progress=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mremapfixedshared` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mremapgrow` | `exit 0` | `"win_ok=true\nr1_ok=true\nr2_ok=true\nmremap_ok=false\nin_place=false\npreserved=false\ntail_usable=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mremapmove` | `exit 0` | `"move_integrity=false\nshrink_unmaps_tail=false\nfresh_is_zeroed=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mremapsharedshrink` | `exit 0` | `"file_shrink_ok=false\nfile_prefix_readable=false\nanon_shared_shrink_ok=false\nanon_prefix_readable=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mremapshrink` | `soft slot 12 changed or retired without a retirement protocol` | `"mmap_ok=true\nshrink_ok=false\nkept_readable=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `msgctlstat` | `exit 0` | `"msgget_ok=true\nmsgctl_stat_ok=true\nmsg_perm_key_matches=true\nmsg_perm_mode_0660=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `msgoverflow` | `exit 0` | `"huge_msgsnd_failed=true\nhuge_msgsnd_einval=true\nsmall_msgsnd_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `msyncalign` | `exit 0` | `"aligned_msync_ok=false\nunaligned_msync_fails=true\nunaligned_errno_is_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mtidlesleep` | `exit 0` | `"slept_both=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `mtsigrelease` | `soft slot 18 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `namei_escape` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nanosleeprem` | `exit 0` | `"nanosleeprem_handler_installed=true\nnanosleeprem_interrupted=false\nnanosleeprem_handler_ran=false\nnanosleeprem_positive=false\nnanosleeprem_less_than_request=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nativebrk` | `exit 0` | `"nativebrk requires aarch64\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nativeprefixwrite` | `exit 1` | `"open_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nativex18` | `exit 0` | `"aarch64_x18_not_applicable=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `net` | `exit 0` | `"socketpair_bytes=hi\nsocketpair_ok=true\nsocket_inet=ERR:38\nsocket_inet6=ERR:38\nsocket_netlink=ERR:38\nunix_bind=ERR:38\nunix_loopback=ERR:38\nso_reuseaddr=ERR:38\nso_type=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `netflagmatrix` | `exit 0` | `"sock_create_nonblock_cloexec=false\nsock_create_invalid_flags_einval=false\nsock_create_invalid_family_eafnosupport=false\nsockpair_dgram_nonblock_cloexec=false\nsockpair_inet_eopnotsupp=false\naccept4_setup_ok=false\naccept4_invalid_flags_einval=false\naccept4_not_socket_enotsock=false\naccept4_nonblock_cloexec=false\nsend_nosignal_closed_peer_epipe=true\nsendto_connected_stream_dest_eisconn=true\nsend_oob_dgram_eopnotsupp=false\nsendto_dgram_unconnected_edestaddrreq=false\nsend_not_socket_enotsock=false\nrecv_msg_peek_preserves_data=true\nrecv_oob_af_unix_einval=false\nrecv_dgram_msg_trunc_returns_full_length=false\nrecv_not_socket_enotsock=false\nsockopt_so_acceptconn_lifecycle=false\nsockopt_so_error_read_and_clear=false\nsockopt_readonly_setsockopt_enoprotoopt=false\nsockopt_invalid_optname_enoprotoopt=false\nsockopt_short_optlen_einval=false\nsockopt_not_socket_enotsock=false\nshutdown_invalid_how_einval=true\nshutdown_unconnected_enotconn=false\nshutdown_not_socket_enotsock=false\nshutdown_shut_wr_semantics=true\nshutdown_shut_rd_eof=true\npoll_rdhup_on_peer_shut_wr=true\nepoll_create1_flags_matrix=true\nepoll_ctl_error_matrix=false\nepoll_rdhup_and_oneshot_lifecycle=true\ncross_msg_peek_poll_epoll_coherence=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `netifmcast` | `exit 0` | `"active_ipv6_iface_present=false\nigmp6_membership_present=false\nipv6_iface_has_igmp6_membership=false\niface_name_index_roundtrip=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `netlink_route` | `exit 0` | `"route_dump_ok=false\nroute_dump_done=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `netpoll` | `exit 0` | `"netpoll_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `newmountapi` | `exit 0` | `"fsopen_eperm=false\nfsopen_null_badflags_eperm=false\nfsconfig_badfd_eperm=false\nfsconfig_badcmd_eperm=false\nfsmount_badfd_eperm=false\nfsmount_badflags_eperm=false\nfspick_root_eperm=false\nfspick_badflags_eperm=false\nopen_tree_root_eperm=false\nopen_tree_clone_eperm=false\nopen_tree_badflags_eperm=false\nmove_mount_empty_eperm=false\nmove_mount_badflags_eperm=false\nmount_setattr_badsize_eperm=false\nmount_setattr_nullattr_eperm=false\nstatmount_enosys=true\nlistmount_enosys=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nicepriority` | `soft slot 10 changed or retired without a retirement protocol` | `"set_nice_2_ok=false\nget_nice_is_2=false\nisolation_parent_nice=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `nofiledefault` | `exit 0` | `"getrlimit_ok=true\nnofile_soft=1048576\nnofile_hard=1048576\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nsfsioctl` | `exit 0` | `"mnt_open_ok=false\nuts_open_ok=false\nipc_open_ok=false\nnet_open_ok=false\npid_open_ok=false\nuser_open_ok=false\ncgroup_open_ok=false\ntime_open_ok=false\nmnt_nstype=ERR:38\nuts_nstype=ERR:38\nipc_nstype=ERR:38\nnet_nstype=ERR:38\npid_nstype=ERR:38\nuser_nstype=ERR:38\ncgroup_nstype=ERR:38\ntime_nstype=ERR:38\nuser_owner_uid=ERR:38\nuser_parent=ERR:38\nuts_parent_errno=ERR:38\nuser_ino_equal=ERR:38\nuserns_from_uts_ok=ERR:38\nuserns_from_user_errno=ERR:38\npeer_ns_setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `nxwritableimage` | `exit 0` | `"nxwritableimage requires aarch64\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `oappendroundtrip` | `exit 0` | `"setup_open_ok=false\nopen_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `odirectory` | `exit 0` | `"odirectory_on_file_enotdir=false\nodirectory_on_dir_ok=false\nrdwr_on_dir_eisdir=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `oomscoreadj` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `opathfd` | `exit 0` | `"seed=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openat2resolve` | `exit 0` | `"plain_symlink_open_ok=false\nno_symlinks_rejects_symlink_eloop=false\ndirfd_open_ok=false\nplain_dotdot_escape_ok=false\nbeneath_rejects_dotdot_escape_exdev=false\nno_xdev_rejects_proc_exdev=false\nno_magiclinks_rejects_proc_fd_eloop=false\nin_root_absolute_scoped_open_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openat2valid` | `exit 0` | `"openat2_create_ok=false\nopenat2_mode_no_create_einval=false\nopenat2_bad_mode_einval=false\nopenat2_bad_resolve_einval=false\nopenat2_size_zero_einval=false\nopenat2_nonzero_pad_e2big=false\nopenat2_bad_dfd_ebadf=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openbrokensymlinkcreate` | `exit 0` | `"symlink_created=false\nopen_create_through_broken_symlink=false\nwrote_through_link=false\ntarget_materialised=false\nlink_unchanged=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openeloop` | `exit 0` | `"setup=false symlink_rc=-1,-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openempty` | `exit 0` | `"open_empty_fails=true\nopen_empty_enoent=false\nopenat_empty_enoent=true\nnonempty_open_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `openexcldir` | `exit 0` | `"excl_existing_dir_eexist=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `otmpfileforkexec` | `exit 0` | `"open_ok=false\nrdonly_einval=false\nchild_status0=false\nparent_readback=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `overlaysymlink` | `soft slot 10 changed or retired without a retirement protocol` | `"link_to_image_file_stats=false\nlink_to_image_file_same_size=false\nlink_to_image_file_opens=false\nlink_to_image_file_access_x=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `packetv3state` | `unserved host readiness wait Some(2s): parking needs an execution lease` | `""` | `forward 0xfffffffffffffeff=0` | `forward 0xfffffffffffffeff=0` |
| `pagetablegrow` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `patherrno` | `exit 0` | `"toolong_rc_neg_one=true\ntoolong_errno_enametoolong=false\nnotdir_rc_neg_one=true\nnotdir_errno_enotdir=false\nmkdir_toolong_rc_neg_one=true\nmkdir_toolong_errno=true\nvalid_stat_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pathflagmatrix` | `exit 0` | `"openat2_opath_rdwr_einval=false\nopenat2_opath_wronly_einval=false\nopenat2_opath_creat_einval=false\nopenat2_opath_trunc_einval=false\nopenat2_opath_tmpfile_einval=false\nopenat2_unknown_flag_bits_einval=false\nopenat2_tmpfile_rdonly_einval=false\nopenat2_resolve_beneath_absolute_exdev=false\nopenat2_resolve_beneath_rel_ok=false\nopenat2_resolve_in_root_escape_stay_in_root=false\nopenat2_resolve_no_symlinks_regfile_ok=false\nopenat2_resolve_unknown_bits_einval=false\nfstatat_symlink_follow_einval=false\nfstatat_removedir_einval=false\nfstatat_bogus_flag_einval=false\nfstatat_empty_path_valid_fd_ok=false\nfstatat_empty_path_without_flag_enoent=true\nfstatat_empty_path_at_fdcwd_enoent=false\nfstatat_no_automount_ok=false\nfstatat_symlink_dir_nofollow_is_lnk=false\nfstatat_symlink_dir_follow_is_dir=false\nstatx_unknown_flag_bits_einval=false\nstatx_symlink_follow_einval=false\nstatx_sync_conflict_einval=false\nstatx_empty_path_valid_fd_ok=false\nstatx_empty_path_without_flag_enoent=true\nstatx_reserved_mask_einval=false\nstatx_unsupported_mask_ignored_ok=false\nrenameat2_unknown_flag_einval=true\nrenameat2_exchange_whiteout_einval=true\nrenameat2_noreplace_existing_dest_eexist=false\nrenameat2_noreplace_new_dest_ok=false\nrenameat2_dir_to_file_enotdir=false\nrenameat2_file_to_dir_eisdir=false\nrenameat2_dir_to_nonempty_dir_enotempty=false\nrenameat2_cross_dir_exchange_ok=false\nunlinkat_invalid_flag_nofollow_einval=true\nunlinkat_invalid_flag_emptypath_einval=true\nunlinkat_invalid_flag_bogus_einval=true\nunlinkat_file_with_removedir_enotdir=false\nunlinkat_dir_without_removedir_eisdir=false\nunlinkat_symlink_to_dir_with_removedir_enotdir=false\nunlinkat_symlink_to_dir_without_removedir_ok=false\nunlinkat_nonempty_dir_enotempty=false\nunlinkat_empty_path_enoent=true\nfaccessat2_invalid_flag_follow_einval=false\nfaccessat2_invalid_flag_automount_einval=false\nfaccessat2_invalid_flag_bogus_einval=false\nfaccessat2_invalid_mode_einval=false\nfaccessat2_invalid_mode_high_bit_einval=false\nfaccessat2_dangling_symlink_follow_enoent=false\nfaccessat2_dangling_symlink_nofollow_ok=false\nfaccessat2_empty_path_valid_fd_ok=false\nfaccessat2_empty_path_without_flag_enoent=true\nfchownat_invalid_flag_removedir_einval=true\nfchownat_invalid_flag_follow_einval=true\nfchownat_invalid_flag_bogus_einval=true\nfchownat_empty_path_valid_fd_ok=false\nfchownat_empty_path_without_flag_enoent=true\nutimensat_invalid_flag_removedir_einval=true\nutimensat_invalid_flag_follow_einval=true\nutimensat_invalid_flag_bogus_einval=true\nutimensat_dangling_symlink_nofollow_ok=false\nutimensat_dangling_symlink_follow_enoent=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pathnonutf8` | `exit 0` | `"open_create=ERR:38\nwrite_ok=false\nfstat_ok=false\nreopen_ok=false\nread_roundtrip=false\nlistdir_has_name=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pauseeintr` | `exit 0` | `"pause_returned_minus_one=true\npause_errno_is_eintr=false\npause_handler_ran=false\nsigsuspend_pending_before=true\nsigsuspend_returned_minus_one=true\nsigsuspend_errno_is_eintr=true\nsigsuspend_handler_ran=true\nsigsuspend_mask_restored=true\nsigsuspend_pending_cleared=true\nblock_rc_ok=true\nblock_made_blocked=true\nunblock_rc_ok=true\nunblock_made_unblocked=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pauseinterrupt2` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pendingunblock` | `exit 0` | `"standard_coalesced_to_one=true\nrealtime_queued_all_three=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pidfdprocdir` | `exit 0` | `"pidfd0_ebadf=false\nprocpid_dir_open_ok=false\npidfd_self_sigint_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pidnsinitreap` | `forward capture: hypervisor operation failed: physical service requires its loaded task generation` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `pidnsinitsig` | `exit 0` | `"kill_init_term_ok=false\nkill_init_term_errno=3\nsurvived_after_signalling_init=true\nself_handler_fired=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pidnsorphanreap` | `soft slot 10 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `pidnsroot` | `forward capture: hypervisor operation failed: physical service requires its loaded task generation` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `pidnswait` | `soft slot 10 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `pidtaskdomain` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pipeblockedge` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pipeextra` | `exit 0` | `"pipe2_nonblock_rc_zero=true\npipe2_nonblock_read_end_nonblock=true\npipe2_nonblock_write_end_nonblock=true\npipe2_cloexec_rc_zero=true\npipe2_cloexec_read_end_cloexec=true\npipe2_cloexec_write_end_cloexec=true\npipe2_direct_rejected_or_ok=true\npipe2_direct_packet_read_short=false\npipe2_direct_empty_returns_eagain=false\npipe_setup_rc_zero=true\npipe_fionread_matches_written=true\npipe_fionread_write_end_matches_written=true\npipe_nonblock_fills=true\npipe_nonblock_write_eagains_when_full=true\npipe_eof_setup_rc_zero=false\npipe_read_after_close_returns_zero=false\npipe_epipe_setup_rc_zero=false\npipe_write_after_rclose_rc_minus_one=true\npipe_write_after_rclose_errno_epipe=false\npositional_setup_rc_zero=false\npwrite_pipe_read_end_espipe=false\npwrite_pipe_write_end_espipe=false\npread_pipe_write_end_espipe=false\npread_pipe_read_end_espipe=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pipelargewrite` | `exit 0` | `"pipe_large_write_intact=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pipemass` | `exit 0` | `"soft_nofile=200000\npipes=0 fds_opened=0 highest_fd=-1 fail=errno38\nopen_last_slot=errno38\nclosed=1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pipeszcrossend` | `exit 0` | `"crossend_eq=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pollevent` | `exit 0` | `"eventfd_read_value=5\neventfd_reset=true\nepoll_pipe=ERR:38\npoll_epoll_pipe=ERR:38\npoll_pipe=ERR:38\nselect_pipe=ERR:38\ntimerfd_create=ERR:38\npoll_invalid_nval=true\npipe2_nb_flag=true\npipe2_nb_empty_eagain=true\npipe2_nb_read_match=true\npipe2_nb_eof=true\npoll_multi_pipe1=ERR:38\ntimerfd_worker_setup_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `posixtimers` | `exit 0` | `"timer_create_rc_zero=false\ntimer_settime_rc_zero=false\ntimer_gettime_remaining_is_positive=false\ntimer_signal_delivered=false\ntimer_getoverrun_nonneg=false\ntimer_delete_rc_zero=false\ntimer_gettime_after_delete_fails=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ppid` | `exit 0` | `"ppid pipe=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ppollsig` | `exit 0` | `"ppoll_blocks=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ppollunblock` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ppollwaitset` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `prctldumpable` | `exit 0` | `"prctl_initial_dumpable_is_one=true\nprctl_set_zero_ok=true\nprctl_get_after_zero_is_zero=true\nprctl_set_one_ok=true\nprctl_get_after_one_is_one=true\nprctl_set_two_rc=-1\nprctl_set_two_errno=22\nprctl_get_after_two=1\nprctl_set_invalid_rc_is_neg_one=true\nprctl_set_invalid_errno_is_einval=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `prctlerrors` | `exit 0` | `"thp_valid_forms_supported=false\nambient_valid_form_supported=false\nspeculation_valid_form_supported=false\nthp_set_bad_arg_einval=false\nthp_get_bad_arg_einval=false\nambient_bad_subcmd_einval=false\nspeculation_extra_arg_einval=false\nseccomp_filter_bad_pointer_efault=false\nseccomp_filter_without_nnp_eacces=false\nsecurebits_without_setpcap_eperm=false\ncapbset_drop_without_setpcap_eperm=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `prctlnnp` | `exit 0` | `"nnp_initial_zero=true\nnnp_set_ok=true\nnnp_now_one=true\nnnp_bad_arg_einval=true\nkeepcaps_initial_zero=false\nkeepcaps_set_ok=false\nkeepcaps_now_one=false\nkeepcaps_two_einval=false\nsubreaper_set_ok=true\nsubreaper_get_ok=true\nsubreaper_value_one=true\ntimerslack_default_50000=false\ntimerslack_set_ok=false\ntimerslack_now_120000=false\ntimerslack_reset_ok=false\ntimerslack_back_to_default=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `preadspecial` | `exit 0` | `"pread_dir_eisdir=false\nreadv_dir_eisdir=false\npread_regular_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `preadv2flags` | `exit 0` | `"preadv2_ret_10=false\npreadv2_content_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `preadvwronly` | `exit 0` | `"preadv_wronly_ebadf=false\npreadv_rdonly_reads4=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `preemptsigstorm` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `probeinit` | `exit 0` | `"transport_helper_not_invoked=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procconfigloop` | `exit 0` | `"proc_config_decoded=false\nproc_config_loop_enabled=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `processvmsparse` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procexeidentity` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procid` | `exit 0` | `"pid_positive=true\nppid_differs=true\ngetuid=0\ngeteuid=0\ngetgid=0\ngetegid=0\ngetgroups count=0 has_root=false\numask_prev=22\nuname_sysname=Linux\nuname_machine=x86_64\nsysinfo totalram_pos=true procs_ge1=true\ngetpriority=ERR:38\nprctl_dumpable=1\nrlimit_nofile cur_pos=true cur_le_max=true\nsched_yield=0\nsched_affinity=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procladder` | `block budget exhausted, rip=0xffffffff80148ab2 cpl=0 cr3=0x4873000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd9` |
| `procladder_epollmgr` | `soft slot 19 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `procladder_mixed` | `exit 0` | `"ladder_forked_all=false\nladder_children_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procladder_mt` | `block budget exhausted, rip=0xffffffff8009d11a cpl=0 cr3=0x4878000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd9` |
| `proclife` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `procpeerdir` | `soft slot 12 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `procpeermem` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procprctlview` | `exit 0` | `"proc_self_comm_set_name=false\nproc_self_comm_truncated=false\nproc_self_timerslack_min=false\nproc_self_timerslack_middle=false\nforked_timerslack_default=false\nproc_self_timerslack_reset=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procselfdir` | `exit 0` | `"self_opendir=false\nself_accessible=false\nself_subpath=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procselffdfail` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procselfpid` | `exit 0` | `"gettid_eq_getpid=true\nproc_pid_eq_getpid=false\nproc_tgid_eq_getpid=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procselfstatleader` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(91327), expected: EntryTaskKey(91326) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `procsignalmask` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procsignalmulti` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procstat` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procstatstate` | `exit 0` | `"child_pid_known=false\nchild_state_is_sleeping=false\nchild_reaped=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `procstatussig` | `exit 0` | `"sigign_has_usr1=false\nsigcgt_has_usr2=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `proctaskchild` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `protnonesyscall` | `exit 83` | `"protnone=ERR open\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `pselecteintr` | `exit 0` | `"select_returned=true\nselect_rc_negative=true\nselect_eintr=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptraceattach` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `ptraceinvaliderrno` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `ptracekillcont` | `soft slot 10 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `ptracesequence` | `exit 0` | `"ptrace05_signal_sweep_ok=false\nfirst_bad_signal=0\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptracesigdeath` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `ptracesignalstop` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `ptracestop` | `soft slot 10 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `ptracetraceme` | `native fixture guest interval deadline` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `ptyexitrescue` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyfionbio` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyfionread` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyflagmatrix` | `exit 0` | `"openpt_rdwr_cloexec_nonblock_opened=false\nopenpt_rdwr_cloexec_nonblock_has_cloexec=false\nopenpt_rdwr_cloexec_nonblock_has_nonblock=false\nopenpt_rdonly_rc=-1\nopenpt_rdonly_errno=38\nopenpt_wronly_rc=-1\nopenpt_wronly_errno=38\npty_master_open_ok=false\nwinsize_setup_ok=false\ntermios_setup_ok=false\npgrp_ctty_setup_ok=false\nfionread_setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyforkreopen` | `exit 0` | `"setup_master=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyisig` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptyjobcontrol` | `exit 0` | `"pty_setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ptypair` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `readpasteof` | `exit 0` | `"setup_ok=false\nsetup_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `readwronly` | `exit 0` | `"read_wronly_ebadf=true\nread_rdonly_reads4=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `recursionguard` | `soft slot 10 changed or retired without a retirement protocol` | `"rlimit_stack_soft_8mib=true\nrlimit_stack_max_unlimited=true\nmain_stack_size_8mib=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `recverrqueue` | `exit 0` | `"recv_errqueue_empty_eagain=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `recvmsgtrunc` | `exit 0` | `"setup_socketpair_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `renameexchange` | `exit 0` | `"seed=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `reparenttoinit` | `exit 0` | `"reparent_pipe_ok=false\nreparent_read_ok=false\nreparent_grandchild_ppid_is_1=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rlimitasdata` | `soft slot 10 changed or retired without a retirement protocol` | `"data_limit_set=true\nbrk_16mib_ok=true\nbrk_past_data_unchanged=false\nmmap_rw_private_past_data_enomem=false\nmmap_prot_none_not_data=true\nmmap_shared_rw_not_data=false\nbrk_shrink_ok=true\nmmap_rw_private_within_data_ok=true\nas_limit_set=true\nmmap_within_as_ok=true\nmmap_past_as_enomem=false\nmremap_past_as_enomem=false\nmremap_within_as_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `rlimitnofile` | `exit 0` | `"rlimit_nofile_raised=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rlimitnproc` | `terminated by signal 6` | `"setrlimit_nproc_2=true\nsetresuid_unprivileged=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rlimitresource` | `exit 0` | `"prlimit_bad_resource_einval=true\nprlimit_resource16_einval=true\nprlimit_nofile_ok=true\nprlimit_self_ok=true\nprlimit_pid_neg1_esrch=true\nprlimit_pid_999999_esrch=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rlimitroundtrip` | `exit 0` | `"core_set_ok=true\ncore_cur_roundtrips=true\ncore_max_roundtrips=true\nstack_set_ok=true\nstack_soft_roundtrips=true\ncore_unchanged_by_stack=true\ncore_cur_gt_max_einval=true\ncore_raise_hard_eperm=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `robustlist` | `exit 0` | `"set_robust_list_badlen_einval=true\nset_robust_list_ok=true\nget_robust_list_null_len_efault=true\nget_robust_list_null_head_efault=true\nget_robust_list_unused_esrch=true\nget_robust_list_self_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `roprotect` | `exit 2` | `"mmapro_write_faults=true\nmmapro_write_si_code=1\nmmapro_write_addr_match=true\nmmapro_write_after=true\nmprotect_rw_precheck=true\nmprotectro_write_faults=true\nmprotectro_write_si_code=2\nmprotectro_write_addr_match=true\nmprotect_rw_restore_ok=true\nprotnone_read_faults=true\nprotnone_read_si_code=1\nprotnone_read_addr_match=true\nprotnone_write_faults=true\nprotnone_write_si_code=1\nprotnone_write_addr_match=true\nmmap FAIL\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `roreadwrite` | `exit 83` | `"ro=ERR open\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rosharedbus` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `rtsigqueueinfo` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rtsigqueueinfoxthread` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `rtsigtimedwaitsiginfo` | `exit 0` | `"sigqueue_ok=true\nsigtimedwait_returns_sigusr1=true\nsi_signo_is_sigusr1=true\nsi_code_is_si_queue=true\nsi_pid_is_self=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `saresethand` | `exit 0` | `"install_ok=true\nhandler_ran_once=true\ndisposition_reset_to_dfl=true\nhandler_not_rerun=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `schedaffinitysibling` | `terminated by signal 6` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `schedaffinitythreads` | `terminated by signal 6` | `""` | `doorbell 0xd1` | `doorbell 0xd3` |
| `schedgetattr` | `exit 0` | `"getattr_self_ok=false\ngetattr_size_48=false\ngetattr_policy_sched_other=true\ngetattr_null_einval=false\ngetattr_small_size_einval=false\ngetattr_bad_flags_einval=false\ngetattr_bad_pid_esrch=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `schedparam` | `exit 0` | `"sched_get_priority_max_other_nonneg=true\nsched_get_priority_min_other_nonneg=true\nsched_get_priority_other_max_eq_min=true\nsched_get_priority_fifo_max_gt_min=true\nsched_get_priority_rr_max_gt_min=true\nsched_get_priority_min_fifo_positive=true\nsched_getscheduler_nonneg=false\nsched_getscheduler_is_other=false\nsched_getparam_rc_zero=false\nsched_getparam_priority_is_zero=true\nsched_rr_get_interval_rc_zero=true\nsched_rr_get_interval_tv_sec_nonneg=true\nsched_rr_get_interval_tv_nsec_nonneg=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `schedprio` | `exit 0` | `"getscheduler_negpid_einval=false\ngetparam_negpid_einval=false\nsetparam_negpid_einval=false\nsetscheduler_negpid_einval=false\nsetscheduler_badptr_efault=false\ngetpriority_badwhich_einval=false\ngetpriority_process_negwho_esrch=false\ngetpriority_pgrp_negwho_esrch=false\ngetpriority_user_negwho_esrch=false\nsetpriority_pgrp_negwho_esrch=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `schedthread` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `scmrightsfds` | `exit 0` | `"socketpair_ok=true\nopen_payload_ok=false\nwrite_marker_ok=false\nsendmsg_ok=false\nrecvmsg_ok=false\none_scm_cmsg=false\nreceived_fd_valid=false\nreceived_fd_fresh=false\nreadback_matches=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `seccompenforce` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `seccompexec` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `seekholedata` | `exit 0` | `"seek_data_ok=false\nseek_hole_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `seekholemap` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `selectnfds` | `exit 0` | `"pselect6_neg_nfds_einval=false\npselect6_neg_nfds_with_set_einval=false\npselect6_zero_nfds_returns_0=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `selecttimeout` | `terminated by signal 6` | `"select_bare_timeout_rc_zero=false\nselect_bare_timeout_bounded=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `selfhostnameresolve` | `exit 0` | `"gethostname_ok=true\nself_hostname_resolves=false\nresolves_to_ipv4=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `selfraise` | `exit 0` | `"delivered=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `semctlrange` | `exit 0` | `"setval_neg_erange=true\nsetval_toobig_erange=true\nsetval_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `semgetnsems` | `exit 0` | `"semget_nsems_too_large_einval=true\nsemget_small_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `semtimedop` | `exit 0` | `"timed_wait_eagain=true\nnowait_eagain=true\ntimed_acquire_ok=true\nval_zero_after_acquire=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sendfilebadf` | `exit 0` | `"sendfile_in_wronly_ebadf=false\nsendfile_out_rdonly_ebadf=false\nsendfile_valid_returns_8=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `setfsid` | `exit 0` | `"setfsuid_prev_is_euid0=true\nsetfsuid_query_is_1000=true\nsetfsuid_prev_is_1000=true\nsetfsgid_prev_is_egid0=true\nsetfsgid_query_is_1000=true\nsetfsgid_prev_is_1000=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `setgroupsroundtrip` | `exit 0` | `"groups_roundtrip=true\nempty_clears=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `setidthreadchurn` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `setpgidparentgroup` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `shared_buffer_mmap` | `exit 0` | `"shbuf_open=ERR\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sharedanonfutexfork` | `exit 0` | `"shared_map_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `shmlinkat` | `exit 0` | `"open_ok=false\nlink_ok=false\nlink_no_erofs=true\nfinal_exists=false\ncleanup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `shmnestedfork` | `exit 0` | `"mmap_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `shmrdonly` | `exit 0` | `"setup_ok=false\nrdonly_attach_ok=false\nrdonly_read_coherent=false\nrdonly_store_faults=false\nrw_attach_store_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigactionresetinfo` | `exit 0` | `"install_ok=true\nself_signal_ok=true\nhandler_ran=true\nhandler_siginfo_nonnull=true\nhandler_query_ok=true\nhandler_query_retained_siginfo=true\ndisposition_reset_to_dfl=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigbadstack` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `sigchld` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `siginfo` | `exit 0` | `"siginfo_kill_rc_zero=true\nsiginfo_handler_ran_once=true\nsiginfo_si_code_is_si_user=true\nsiginfo_si_pid_is_sender=true\nsiginfo_si_uid_is_sender=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `siglongjmpaltstack` | `exit 0` | `"maperr_siglongjmp=true\nmaperr_signal=11\nmaperr_si_code=1\nmaperr_si_addr_matches=true\nbus_setup_errno=38\nbus_siglongjmp=false\nbus_signal=0\nbus_si_code=0\nbus_si_addr_matches=false\ndefault_fault_signal=-38\nblocked_fault_signal=-38\naltstack_ok=true\ninstall_ok=true\nfirst_handler_seen=true\nfirst_handler_on_alt=true\nsiglongjmp_returned=true\nafter_longjmp_not_onstack=true\nreplace_altstack_ok=true\nreplace_altstack_errno=0\nsecond_handler_seen=true\nsecond_handler_on_replaced_alt=true\nafter_second_not_onstack=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `signalexit` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `signalfd4` | `exit 0` | `"signalfd4_created=false\nsignalfd4_cloexec=false\nsignalfd4_nonblock=false\nsignalfd4_bad_flag_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `signalfdread` | `exit 0` | `"signalfd_ok=false\nread_returns_full_record=false\nssi_signo_is_sigusr1=false\nshort_buffer_einval=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `signals` | `exit 0` | `"sigprocmask_usr1_blocked=true\nsigprocmask_usr1_absent=true\nsigaction_handler_ran=true\nsigaction_restore_rc=0\nsigign_usr2_survived=true\nsigaltstack_size_match=true\nsigaltstack_rc=0\nsigpending_usr1=true\nkill_self_sig0_rc=0\nsigtimedwait_signo=10\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigpairrace` | `exit 0` | `"usr1=0 usr2=0 both=0\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigpipewrite` | `exit 0` | `"write_broken_pipe_epipe=false\nsigpipe_delivered_once=false\nignored_still_epipe=false\nignored_no_handler=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigprofvdso` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `sigqueueusr1` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigreenter` | `exit 0` | `"altstack_ok=true\ninstall_ok=true\nreentered=true\nmax_depth_is_2=true\nnested_frame_below_outer=true\nunwound_clean=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigstopjobcontrol` | `exit 0` | `"mmap_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigsuspendxthread` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4874000, actual CR3 0x487e000, RSP 0xffffffff90e0d400, saved GPR7 0xffffffff90e0d400, expected MM 1, context 1` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `sigtimedwaitintr` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `sigunblockpending` | `exit 72` | `"sigunblockpending=ERR pipe\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigwaitalarm` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigwaitblock` | `exit 0` | `"sigwait_pipe_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigwaitmatrix` | `exit 0` | `"sigtimedwait_timespec_validation=true\nsigtimedwait_sigsetsize_validation=true\nsigtimedwait_zero_timeout_eagain=true\nsigtimedwait_null_set_efault=true\nsigtimedwait_single_dequeue_semantics=false\nsigtimedwait_numerical_priority_order=true\nsigtimedwait_suppresses_handler_execution=true\nsigqueue_invalid_signum_einval=false\nsigqueue_nonexistent_target_esrch=true\nsigqueue_user_code_security_eperm=false\nsigqueue_signo_mismatch_einval=false\nsigqueue_si_queue_payload_roundtrip=true\nsigmask_unblockable_signals=true\nsigprocmask_invalid_how_einval=true\nsigpending_null_pointer_efault=true\nsigsuspend_null_pointer_efault=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sigwaitthread` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(63472), expected: EntryTaskKey(63471) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `sockbufreuseport` | `exit 0` | `"socket_ok=false\nrcvbuf_set_ok=false\nrcvbuf_doubled=false\nsndbuf_set_ok=false\nsndbuf_doubled=false\nreuseaddr_set_ok=false\nreuseport_still_zero=false\nreuseport_set_ok=false\nreuseport_now_one=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `socketcredmore` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `socketpartialsend` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sockoptdomainproto` | `exit 0` | `"unix_getsockopt_ok=false\nunix_domain_af_unix=false\nunix_protocol_zero=false\ninet_getsockopt_ok=false\ninet_domain_af_inet=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sotimeo` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4872000, actual CR3 0x487c000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `"setup_socketpair_ok=true\ndontwait_rc_minus_one=true\ndontwait_errno_eagain=true\n"` | `forward 0xfffffffffffffeff=0` | `forward 0x1=27` |
| `spawnflagmatrix` | `terminated by signal 6` | `"close_range_setup_ok=false\npipe2_cloexec_nonblock_ok=true\npipe_set_get_capacity_ok=true\npipe2_invalid_flags_einval=true\nprctl_pdeathsig_set_get=true\nprctl_pdeathsig_clear=true\nprctl_pdeathsig_invalid_einval=true\nprctl_no_new_privs_set_get=true\nprctl_no_new_privs_invalid_arg_einval=true\nprctl_dumpable_roundtrip=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `splicematrix` | `exit 0` | `"pipe2_invalid_flags_einval=true\npipe2_nonblock_cloexec_flags=true\npipe_wrong_direction_ebadf=true\npipe_lseek_espipe=true\npipe_empty_nonblock_read_eagain=true\nsplice_invalid_fd_ebadf=false\nsplice_non_pipe_targets_einval=false\nsplice_access_mode_mismatch_ebadf=false\nsplice_pipe_offset_espipe=false\nsplice_negative_file_offset_einval=false\nsplice_append_target_einval=false\nsplice_invalid_flags_einval=false\nsplice_zero_length_success=false\nvmsplice_error_matrix=false\ntee_error_matrix=false\nsplice_pipe_to_pipe_nonblock_and_eagain=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `splicenetpoll` | `exit 0` | `"splicenetpoll_progress=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `splicepipe` | `exit 0` | `"splice_f_pipe=ERR:38\nsplice_pp_pipe=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `splicepipeempty` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `spliceunixpoll` | `exit 0` | `"spliceunixpoll_progress=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `stackgrowmain` | `block budget exhausted, rip=0xffffffff80148a8c cpl=0 cr3=0x4877000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `statfdino` | `exit 0` | `"dir_setup=ERR:38\ndir_samestat=ERR\nfile_setup=ERR:38\nfile_samestat=ERR\nsymlink_setup=ERR:38\nsymlink_lstat_islnk=ERR\nsymlink_stat_isreg=ERR\nsymlink_distinct_from_target=ERR\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `statfslifetime` | `exit 0` | `"create_ok=false\nstatfs_path_ok=false\nfstatfs_fd_ok=false\npath_fd_type_match=true\npath_fd_bsize_match=true\npath_fd_blocks_match=true\nunlink_ok=false\nunlinked_statfs_errno=2\nunlinked_fstatfs_ok=false\nunlinked_fstatfs_type_match=true\nunlinked_fstatfs_blocks_match=true\ndup_ok=false\nproc_open_ok=false\nproc_fd_reused=true\nproc_fstatfs_errno=9\ndup_fstatfs_errno=9\norig_f_type=0x0\ndup_f_type=0x0\nproc_f_type=0x0\ndup_retains_orig_type=true\nreused_fd_distinct_type=false\npipe_create_errno=38\nsock_create_errno=38\nfifo_mk_errno=38\nfifo_open_errno=38\nempty_path_errno=2\nmissing_path_errno=2\nbad_fd_errno=9\nbad_fd_high_errno=9\nmemfd_create_errno=38\nmemfd_fstatfs_errno=-1\nmemfd_magic=0x0\nmemfd_blocks=0\nsecret_create_errno=38\nsecret_fstatfs_errno=-1\nsecret_magic=0x0\nsecret_blocks=0\ntmpfile_create_errno=38\ntmpfile_fstatfs_errno=-1\ntmpfile_magic=0x0\ntmpfile_magic_match=false\ntmpfile_blocks_match=false\nproc_self_fd_orig_open_errno=38\nproc_self_fd_reopen_errno=-1\nproc_self_fd_fstatfs_errno=-1\nproc_self_fd_magic_match=false\nproc_self_fd_blocks_match=false\nscm_socketpair_errno=0\nscm_send_errno=-1\nscm_recv_errno=-1\nscm_fstatfs_errno=-1\nscm_magic_match=false\nscm_blocks_match=false\nreopen_access_create_errno=38\nreopen_access_linked_errno=-1\nreopen_access_linked_written=-1\nreopen_access_linked_write_errno=-1\nreopen_access_unlink_errno=38\nreopen_access_unlinked_errno=-1\nreopen_access_unlinked_written=-1\nreopen_access_unlinked_write_errno=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `streamdestmatrix` | `terminated by signal 6` | `"unconnected_inet_stream_getpeername_rc=-1\nunconnected_inet_stream_getpeername_errno=EUNKNOWN:38\nunconnected_inet_dgram_getpeername_rc=-1\nunconnected_inet_dgram_getpeername_errno=EUNKNOWN:38\nunconnected_unix_stream_getpeername_rc=-1\nunconnected_unix_stream_getpeername_errno=EUNKNOWN:38\ntcp_setup_ok=false\ntcp_setup_errno=EUNKNOWN:38\nudp_setup_ok=false\nudp_setup_errno=EUNKNOWN:38\nunix_setup_ok=true\nunix_setup_errno=0\nunix_socketpair_peer0_getpeername_rc=0\nunix_socketpair_peer0_getpeername_errno=0\nunix_socketpair_peer1_getpeername_rc=0\nunix_socketpair_peer1_getpeername_errno=0\nunix_socketpair_peer0_family_unix=true\nunix_socketpair_peer1_family_unix=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `symlinkfollow` | `exit 0` | `"dangling_setup=false\ndangling_lstat_islnk=false\ndangling_stat_enoent=false\nsymlink_follow_target_mode=false\ncreate_trailing_slash_eisdir=false\ncreate_no_slash_ok=false\nfifo_setup=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `symlinkmknod` | `exit 0` | `"setup_real_dir=false\nsetup_abs_symlink=false\nmknod_via_symlink_ok=false\nmknod_via_symlink_did_not_return_enoent=true\nfifo_at_target_in_rootfs=false\nfifo_via_symlink_path=false\ncontained_consistent=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `syncfilerange` | `exit 0` | `"sfr_badfd_ebadf=false\nsfr_pipe_espipe=false\nsfr_neg_offset_einval=false\nsfr_neg_nbytes_einval=false\nsfr_bad_flags_einval=false\nsfr_valid_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `syscallregpreserve` | `exit 0` | `"aarch64_syscall_reg_probe_skipped=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sysinfo` | `exit 0` | `"uname_sysname_linux=true\nuname_machine_aarch64=false\nsysinfo_ok=true\nsysinfo_mem_unit_pos=true\nsysinfo_totalram_pos=true\ngetrlimit_nofile_ok=true\ngetrlimit_nofile_cur_le_max=true\ngetrlimit_stack_ok=true\ngetrlimit_stack_cur_le_max=true\nprlimit64_nofile_ok=true\nprlimit64_nofile_cur_le_max=true\nprlimit64_stack_ok=true\nprlimit64_stack_cur_le_max=true\nprctl_name_roundtrip=true\ngetrandom_both_16=true\ngetrandom_differ=true\nsched_getaffinity=ERR:38\nsched_yield_ok=true\ngetpriority=ERR:38\ngettid_eq_getpid=true\numask_set_return=22\ngetcpu=ERR:38\ncapget_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `syslogstate` | `exit 0` | `"syslog_cap_effective=false\ninvalid_action_errno=38\nnull_read_errno=38\nnegative_length_errno=38\nnegative_level_errno=38\nexcessive_level_errno=38\nzero_read_errno=38\nbuffer_size_errno=38\nbuffer_size_positive=false\ndrop_euid_errno=0\nnonroot_read_errno=38\nrestore_euid_errno=0\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sysvmsg` | `soft slot 10 changed or retired without a retirement protocol` | `"msgget_ok=true\nsend_recv_roundtrip=true\nqnum_after_send_is_1=true\nqnum_after_recv_is_0=true\nproc_sysvipc_msg_present=false\nproc_sysvipc_msg_live_queue=false\ntype_selective_recv=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `sysvmsgselect` | `exit 0` | `"msgget_ok=true\nnowait_empty_rc=-1\nnowait_empty_errno=42\nzero_head_fifo=true\nexact_type_select=true\nexact_type_miss_enomsg=true\nmsg_except_select=true\nmsg_except_miss_enomsg=true\nnegative_miss_enomsg=true\nnegative_lowest_type_select=true\nundersized_noerror_e2big=true\ne2big_retained_received_by_noerror=true\nmsg_noerror_truncates_and_dequeues=true\nipc_rmid_ok=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sysvmsgwake` | `soft slot 10 changed or retired without a retirement protocol` | `"nowait_empty_enomsg=true\nnowait_full_eagain=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `sysvsem` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `sysvsemstat` | `exit 0` | `"semget_ok=true\nsemctl_stat_ok=true\nsem_mode_lo9=418\nsem_nsems=1700000000\nsem_uid_is_euid=true\nsem_gid_is_egid=true\nsem_cuid_is_euid=true\nsem_ctime_nonzero=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `sysvshm` | `exit 0` | `"null_attach_ok=false\naligned_attach_ok=false\naligned_errno=0\nchild_aligned_status=-1\nrounded_attach_ok=false\nrounded_errno=0\nreadonly_errno=0\nreadonly_signal=-1\nshm_info_ok=false\nshm_info_errno=38\nstat_any_ok=false\nstat_any_errno=0\nremap_invalid=-1\nremap_invalid_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `telemetrymap` | `exit 0` | `"open FAIL\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `termiosbits` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `termiosflow` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `tgsigqueue` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `threadbarrier` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4872000, actual CR3 0x487c000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `threadcommname` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `threadrecycle` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `threadspawn` | `exit 70` | `"spawn peak=01 of 14\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `threadstatstate` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `threadstatuscount` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `timeclock` | `exit 0` | `"clock_gettime_realtime rc=0 sec_positive=true\nclock_gettime_monotonic=ERR:22\nclock_gettime_boottime=ERR:22\nclock_gettime_process_cputime=ERR:22\nclock_monotonic_nondecreasing=ERR:22\nclock_boottime_ge_monotonic=ERR:22\nclock_getres_realtime=ERR:38\nclock_getres_monotonic=ERR:38\nnanosleep rc=-1 errno=38 no_eintr=true\nclock_nanosleep rc=38\ngettimeofday rc=0 sec_positive=true\ntimes rc_nonneg=false\ngetrusage rc=0 maxrss_nonneg=true\ntime_after_2023=true\ngetcpuclockid_process=ERR:38\npthread_getcpuclockid_thread rc=0 dynamic=true gettime_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `timeextra` | `exit 0` | `"clock_gettime_monotonic_rc_zero=false\nmonotonic_sec_positive=false\nclock_gettime_realtime_rc_zero=true\nrealtime_sec_positive=false\nmonotonic_nondecreasing=true\nclock_getres_monotonic_rc_zero=false\nclock_getres_monotonic_nsec_positive=false\ngettimeofday_rc_zero=true\ngettimeofday_sec_positive=true\ntimes_rc_nonneg=true\nclock_settime_rc_minus_one=true\nclock_settime_errno_eperm=false\nclock_adjtime_rc_minus_one=true\nclock_adjtime_errno_eperm=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `timersettimeabs` | `exit 0` | `"create_ok=false\nnsec_too_big_einval=false\nnsec_negative_einval=false\nsec_negative_einval=false\nvalid_arm_ok=false\nabstime_past_delivered=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `timeschildren` | `block budget exhausted, rip=0x880000a948 cpl=3 cr3=0x487e000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `tlbibroadcast` | `exit 4` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `tmpfileatime` | `exit 0` | `"memfd_open_ok=false\nmemfd_thread_roundtrip=false\natime_set_in_past=false\natime_survives_readdir=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `tmpfilewrite` | `exit 0` | `"o_tmpfile_open_ok=false\no_tmpfile_write_full=false\no_tmpfile_readback_matches=false\n"` | `doorbell 0xd1` | `doorbell 0xd3` |
| `traceexecstop` | `host deadline (65 s, status 124)` | `uncaptured` | — | — |
| `tty0state` | `exit 0` | `"tty0_opened=false\ntty0_open_errno=38\ntty0_second_opened=false\ntty0_second_open_errno=38\ntty0_dup_succeeded=false\ntty0_dup_errno=9\ntty0_fstat_rc=-1\ntty0_fstat_errno=9\ntty0_is_character=false\ntty0_rdev_major=-1\ntty0_rdev_minor=-1\ntty0_tcgets_rc=-1\ntty0_tcgets_errno=9\ntty0_tcgeta_rc=-1\ntty0_tcgeta_errno=9\ntty0_termio_matches_termios=false\ntty0_bad_pointer_rc=-1\ntty0_bad_pointer_errno=9\ntty0_unknown_request_rc=-1\ntty0_unknown_request_errno=9\ntty0_close_first_rc=-1\ntty0_dup_tcgets_after_close_rc=-1\ntty0_dup_tcgets_after_close_errno=9\ntty0_dup_state_retained=false\ntty0_close_duplicate_rc=-1\ntty0_close_second_rc=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `ttyencoding` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `udpconnectunspec` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `udplitesock` | `exit 0` | `"udplite_socket_ok=false\nudplite_roundtrip=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `udpreuseaddr` | `exit 0` | `"setup_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `uffdpolicy` | `exit 0` | `"uffd_plain_errno=38\nuffd_usermode_errno=38\nuffd_badflags_errno=38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `unicodenorm` | `exit 0` | `"setup_dir=false\nsetup_nfc_file=false\nnfc_stat_ok=false\nnfd_stat_enoent=false\nnfd_open_enoent=false\nnfd_lstat_enoent=false\nreaddir_has_nfc=false\nreaddir_excludes_nfd=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `unlinkatbindmount` | `exit 0` | `"shm_dir_exists=false\nunlinkat_open_ok=false\nunlinkat_pre_exists=false\nunlinkat_returned_zero=false\nunlinkat_post_missing=false\nunlinkat_post_errno_enoent=false\nunlink_open_ok=false\nunlink_returned_zero=false\nunlink_post_errno_enoent=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `usernsisolation` | `soft slot 16 changed or retired without a retirement protocol` | `"parent_before_uid_map=err=38\nparent_before_gid_map=err=38\nparent_before_setgroups=err=38\nchild_unshare_newuser_rc=-38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `usernsmap` | `exit 0` | `"uid_map_identity=false\ngid_map_identity=false\nsetgroups_allow=false\ncapeff=\ncapeff_nonzero=false\ncapbnd_eq_capeff=true\ncapprm_eq_capeff=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `usernswrite` | `exit 0` | `"uid_map_write_rejected=true\ngid_map_write_rejected=true\nuid_map_unchanged=false\ngid_map_unchanged=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `vdsogtod` | `exit 0` | `"gettimeofday_resolved=false\ntime_resolved=false\ngtod_close=false\ngtod_usec_valid=false\ntime_close=false\ngtod_time_agree=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `vdsosymbols` | `exit 0` | `"vdso_present=false\nhas_clock_gettime=false\nhas_gettimeofday=false\nhas_clock_getres=false\nhas_time=false\nall_expected_present=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `vforkexecthread` | `forward capture: hypervisor operation failed: forward capture MM binding mismatch: TaskIdMismatch { stopped: EntryTaskKey(103151), expected: EntryTaskKey(103150) }` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `vforkpid` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `vforkvmshare` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `vfs_mount_rw` | `exit 0` | `"write_mount_file=ERR\nreread_mount_file=ERR\nparent_readdir_has_mount=false\ncross_mount_rename_errno=38\ncross_mount_link_errno=38\nsame_mount_rename_rc=-1\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `vmsplicepipe` | `exit 0` | `"vms_u2p_pipe=ERR:38\nvms_p2u_pipe=ERR:38\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `waitexitstorm` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `waitidcputime` | `block budget exhausted, rip=0x880000a832 cpl=3 cr3=0x487e000 blocks=4000000` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd1` |
| `waitidsiuid` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `waitidspec` | `soft slot 8 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `waitpgid` | `exit 0` | `"waitpid_intmin_esrch=false\nwaitpid_badflags_einval=true\nwaitpid_nochild_echild=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `waitrestart` | `forward capture: hypervisor operation failed: physical service requires its loaded task generation` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `waitsiblingsigchld` | `soft slot 9 changed or retired without a retirement protocol` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xcb` |
| `writeseek` | `exit 0` | `"iterations=8\ncompleted_writes=0\ncompleted_rewinds=0\nfile_limit_unlimited=true\nbytes_match=false\noffset_matches=false\nlength_matches=false\nclosed=false\nremoved=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `writevpartial` | `exit 0` | `"writev_big_returns_partial=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `xprocsigign` | `terminated by signal 6` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `xsignal` | `forward capture: hypervisor operation failed: physical service requires its loaded task generation` | `""` | `forward 0xfffffffffffffeff=0` | `doorbell 0xc5 (forward capture)` |
| `xthreadsig` | `exit 0` | `"delivered=true\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |
| `zerolenio` | `exit 0` | `"open_ok=false\npwrite_null_zero_returns_0=false\nwrite_null_zero_returns_0=false\npwritev_with_null_seg_returns_4=false\nreadback_ok=false\n"` | `forward 0xfffffffffffffeff=0` | `doorbell 0xd3` |

</details>

<details>
<summary>Slot-retirement cohort after the fix (83 rows)</summary>

| ELF | Stop after fix | Stdout | Last worker event |
| --- | --- | --- | --- |
| `abortdeath` | `exit 0` | `"sigterm_kills_child=true\nsigterm_wtermsig_matches=true\nsigkill_kills_child=true\nsigkill_wtermsig_matches=true\nabort_sigabrts_child=true\nabort_wtermsig_matches=true\nclean_exit_no_signal=true\nclean_exit_wifexited=true\nclean_exit_status_zero=true\n"` | `doorbell 0xd3` |
| `bigread` | `exit 0` | `"runtime_survived_huge_read=true\nchild_not_killed=true\nchild_handled_cleanly=false\n"` | `doorbell 0xd3` |
| `budget_two_proc` | `exit 0` | `"parent_pid_positive=true\nchild_ppid_matches=true\nchild_ok\nchild_forked=true\nchild_pid_distinct=true\nchild_exited_zero=true\nparent_pid_stable=true\nchild_reaped_once=true\nparent_ok\nparent_write_ok=true\n"` | `doorbell 0xd3` |
| `childrusage` | `terminated by signal 6` | `""` | `doorbell 0xd3` |
| `clocksettimevdso` | `exit 0` | `"clock_settime_monotonic rc=-1 errno=38\ninitial_reads rc_raw=-1 rc_vdso=0 rc_gtod=0\nclock_settime_realtime rc=-1 errno=38\nparent_shifted raw_shifted=false vdso_shifted=false gtod_shifted=false\nchild_shifted raw_shifted=false vdso_shifted=true\nchild_wait wait_rc_ok=true exit_ok=true\nclock_settime_restore rc=-1 errno=38\n"` | `doorbell 0xd3` |
| `clonebasic` | `exit 0` | `"clone_basic_rc_positive=true\nclone_basic_child_reaped=true\nclone_thread_alone_rc_neg_one=true\nclone_thread_alone_errno_einval=false\n"` | `doorbell 0xd3` |
| `clonefsumask` | `exit 0` | `"clone_fs_thread_change_visible=true\nfork_child_inherited_umask=true\nfork_child_change_isolated=true\n"` | `doorbell 0xd3` |
| `coredumpbit` | `exit 0` | `"sigabrt_wifsignaled=true\nsigabrt_wcoredump_set=false\nsigsegv_wifsignaled=true\nsigsegv_wcoredump_set=false\nsigquit_wifsignaled=true\nsigquit_wcoredump_set=false\nsigterm_wifsignaled=true\nsigterm_wcoredump_clear=true\nsigkill_wifsignaled=true\nsigkill_wcoredump_clear=true\nsparse_core_transport_ok=false\nsparse_core_map_errno=18446744073709551615\nsparse_core_limit_errno=18446744073709551615\nsparse_core_reaped=false\nsparse_core_wait_status=0\nsparse_core_sigsegv=false\nsparse_core_wcoredump=false\nsparse_core_elf=false\nsparse_core_nonempty=false\nsparse_core_storage_within_limit=false\nsparse_core_full_load_extent=false\n"` | `doorbell 0xd3` |
| `coredumpfile` | `exit 0` | `"made_dir=false\nchdir_ok=false\nraised_rlimit_core=true\nreaped=true\nchild_was_signaled=false\nchild_exited_normally=true\nchild_exit_status_zero=false\nchild_died_of_sigsegv=false\nwcoredump_set=false\ncore_pattern_is_plain_file=false\ncore_file_exists_when_bit_set=true\ncore_is_elf64_aarch64=false\nfork_exec_identity_exact=false\nlow_process_group_session_identity=false\ncrash_signal_code_addr_exact=false\ncrash_pc_fault_instruction_exact=false\nthree_threads_captured=false\nthread_ids_distinct=true\nthread_register_markers_exact=false\nthread_stack_pointers_distinct=false\nrunning_and_blocked_pcs_exact=false\nboot_mapping_path_exact=false\nnonzero_offset_file_mapping_exact=false\nanonymous_exec_not_file_labeled=true\nnt_file_symbolizer_truth=false\npt_load_vmas_nonoverlapping=true\nauxv_present=false\nprivate_cow_sample_present=false\nshared_sample_present=false\nstack_sample_present=false\nheap_sample_present=false\nfile_mapping_sample_present=false\n"` | `doorbell 0xd3` |
| `epollforkeventfd` | `exit 0` | `"setup_ok=true\nepoll_add_ok=true\nchild_write_ok=true\nparent_epoll_woke=true\nparent_epollin=true\neventfd_value_one=true\n"` | `doorbell 0xd3` |
| `epollpwait` | `exit 0` | `"ready_immediate=true\nwoke_crossproc=true\nsigmask_blocks=true\n"` | `doorbell 0xd3` |
| `epollzoneeintr` | `stopped CPU image after Halt: hypervisor operation failed: x86 CPU image does not match its issued MM/context/root binding; expected root 0x4879000, actual CR3 0x4883000, RSP 0xffffffff90e0d980, saved GPR7 0xffffffff90e0d980, expected MM 1, context 1` | `""` | `doorbell 0xcb` |
| `execfatalstatus` | `exit 0` | `"reaped=true\nchild_exited=true\nchild_exit_status=126\nchild_signaled=false\nchild_signal=0\n"` | `doorbell 0xd3` |
| `execvenonutf8` | `exit 0` | `"forked=true\nchild_reaped=true\nexecve_nonutf8_ok=false\n"` | `doorbell 0xd3` |
| `exitgroupthreads` | `exit 0` | `"waitpid_reaped_child=true\nchild_exited_normally=true\nchild_exit_status_37=true\n"` | `doorbell 0xd3` |
| `exitstatus127` | `exit 0` | `"reaped=true\nchild_exited=true\nchild_exit_status=127\nchild_signaled=false\nchild_signal=0\n"` | `doorbell 0xd3` |
| `fileaccessmode` | `fault record: hypervisor operation failed: kernel fault policy refused: reason 1, FaultDoorbellRecord { vector: 14, error_code: 4, rip: 584115595856, cs: 35, rsp: 2147417216, rflags: 66054, saved_rax: 0, cr2: 18446744073709551615 }` | `"create_ok=false\nseed_written=false\nrdonly_accmode=2097155\nrdonly_nonblock=true\nrdonly_append=true\nwronly_accmode=2097155\nwronly_nonblock=true\nrdwr_append_accmode=2097155\nrdwr_append_append=true\nrdwr_append_nonblock=true\nexplicit_nonblock_reported=true\nsetfl_clear_rc=-1\nafter_clear_nonblock=true\nchild_setfl_visible=true\nread_before_map=false\nshared_read_map_ok=false\n"` | `doorbell 0xc7 (fault record)` |
| `forkaltstack` | `exit 0` | `"parent_set_altstack_ok=true\nchild_inherits_altstack=false\n"` | `doorbell 0xd3` |
| `forkcow` | `exit 0` | `"data_isolated=true\nbss_isolated=true\nheap_isolated=true\nmmap_isolated=true\n"` | `doorbell 0xd3` |
| `forkexecpthread` | `exit 0` | `"parent_observed_child_success=false\n"` | `doorbell 0xd3` |
| `forkfault` | `exit 0` | `"child_exited=true\nchild_signaled=false\nchild_code=1\nchild_fault_delivered_accerr=false\nfilenone_exited=true\nfilenone_signaled=false\nfilenone_code=6\nfilenone_fault_delivered_accerr=false\nDONE\n"` | `doorbell 0xd3` |
| `forkheapalloc` | `exit 0` | `"seed_ok=true\nchild_reaped=true\npost_fork_heap_alloc=true\n"` | `doorbell 0xd3` |
| `forkhighva` | `exit 0` | `"parent_highva_map_ok=false\nchild_highva_map_ok=false\nchild_survived=true\n"` | `doorbell 0xd3` |
| `forkprotectexec` | `fault record: hypervisor operation failed: kernel fault policy refused: reason 0, FaultDoorbellRecord { vector: 6, error_code: 0, rip: 18446744071563412349, cs: 8, rsp: 18446744071841779544, rflags: 65538, saved_rax: 1, cr2: 584116007516 }` | `""` | `doorbell 0xc7 (fault record)` |
| `forksigwalk` | `block budget exhausted, rip=0xffffffff8014871e cpl=0 cr3=0x4872000 blocks=4000000` | `""` | `doorbell 0xd2` |
| `futexforkwakegroups` | `exit 0` | `"grandchild_fork_ok=true\nfork_ok=true\nchild_exit_ok=false\n"` | `doorbell 0xd3` |
| `killfault` | `block budget exhausted, rip=0xffffffff801832e0 cpl=0 cr3=0x4878000 blocks=4000000` | `""` | `doorbell 0xd8` |
| `killgroup` | `exit 0` | `"child_caught_group_kill0=\0\n"` | `doorbell 0xd3` |
| `killreap` | `block budget exhausted, rip=0xffffffff8001a366 cpl=0 cr3=0x4872000 blocks=4000000` | `""` | `doorbell 0xd1` |
| `killrt` | `exit 0` | `"rt_code=-1 rt_value=0xcafe correct=1\n"` | `doorbell 0xd3` |
| `killuidperm` | `exit 0` | `"root_to_other_uid_allowed=true\ncross_uid_nonroot_kill_rc_neg_one=false\ncross_uid_nonroot_kill_errno_eperm=false\nsame_uid_nonroot_kill_allowed=true\n"` | `doorbell 0xd3` |
| `memfdsharedcoherence` | `exit 0` | `"memfd_created=false\nshared_map_ok=false\ninitial_zero=false\nstore_visible_to_pread=false\nstore_visible_to_dup_pread=false\nstore_visible_in_second_map=false\npwrite_ok=false\npwrite_visible_in_map=false\nfork_child_exited_ok=false\nfork_child_store_visible_to_parent=false\nfork_child_pwrite_visible_to_parent=false\nprivate_map_ok=false\nprivate_map_initial_contents=false\nprivate_store_not_in_file=false\nprivate_store_visible_privately=false\nprivate_dirty_page_keeps_cow_copy=false\nmsync_ok=false\nmunmap_keeps_other_map=false\nmap_outlives_last_fd=false\n"` | `doorbell 0xd3` |
| `mprotectexec` | `fault record: hypervisor operation failed: kernel fault policy refused: reason 0, FaultDoorbellRecord { vector: 6, error_code: 0, rip: 18446744071563412349, cs: 8, rsp: 18446744071841779544, rflags: 65538, saved_rax: 1, cr2: 2147416744 }` | `""` | `doorbell 0xc7 (fault record)` |
| `mremapshrink` | `exit 0` | `"mmap_ok=true\nshrink_ok=false\nkept_readable=true\ntail_unmapped=false\n"` | `doorbell 0xd3` |
| `mtsigrelease` | `exit 0` | `"ladder_forked_all=true\nladder_children_ok=false\n"` | `doorbell 0xd3` |
| `native_autoreap_exit` | `exit 7` | `"\u{1}\u{2}\u{3}\u{4}"` | `doorbell 0xd3` |
| `native_child_entropy` | `exit 8` | `""` | `doorbell 0xd3` |
| `native_child_futex_wake` | `exit 94` | `"\u{1}\u{2}"` | `doorbell 0xd3` |
| `native_child_sleep` | `exit 8` | `""` | `doorbell 0xd3` |
| `native_exit_order` | `exit 7` | `"\u{1}\u{2}\u{3}"` | `doorbell 0xd3` |
| `native_file_fork` | `fault record: hypervisor operation failed: kernel fault policy refused: reason 0, FaultDoorbellRecord { vector: 6, error_code: 0, rip: 4198486, cs: 35, rsp: 2147417744, rflags: 66118, saved_rax: 1, cr2: 2147417736 }` | `"\0\u{1}\u{2}"` | `doorbell 0xc7 (fault record)` |
| `native_group_exit` | `exit 0` | `""` | `doorbell 0xd3` |
| `native_group_exit.TWO_LIVE` | `exit 0` | `""` | `doorbell 0xd3` |
| `native_peer_birth` | `exit 7` | `"\u{1}\u{2}\u{2}"` | `doorbell 0xd3` |
| `native_record_lock` | `exit 0` | `hex 26092609000989002609000909000009` | `doorbell 0xd3` |
| `nicepriority` | `exit 0` | `"set_nice_2_ok=false\nget_nice_is_2=false\nisolation_parent_nice=-1\nisolation_child_a_exited_0=true\nisolation_child_b_nice=-1\nset_nice_50_ok=false\nget_nice_clamped_19=false\ngetpriority_bad_which_einval=false\n"` | `doorbell 0xd3` |
| `overlaysymlink` | `exit 0` | `"link_to_image_file_stats=false\nlink_to_image_file_same_size=false\nlink_to_image_file_opens=false\nlink_to_image_file_access_x=false\nlink_to_image_binary_execs=false\ndangling_link_stat_enoent=false\ndangling_link_lstat_ok=false\n"` | `doorbell 0xd3` |
| `pidnsorphanreap` | `exit 0` | `"reaped_two=true\nreaped_direct_child=true\nreaped_orphan_grandchild=true\n"` | `doorbell 0xd3` |
| `pidnswait` | `exit 0` | `"both_children_alive=true\nforeign_pid_esrch=true\nwait_a_eq_fork_a=true\nwait_b_eq_fork_b=true\nchildren_distinct=true\n"` | `doorbell 0xd3` |
| `procladder_epollmgr` | `exit 0` | `"mgr_forked_all=true\nmgr_children_ok=false\n"` | `doorbell 0xd3` |
| `proclife` | `exit 0` | `"exit_normal reaped_match=true ifexited=true exitstatus=42 not_signaled=true\nexit_signalled reaped_match=true ifsignaled=true termsig=15 not_exited=true\nexecve_true ifexited=true exitstatus_match=false\nexecve_false ifexited=true exitstatus_match=false\nwnohang first_zero=true final_match=true exitstatus=7\npgroup setpgid=ERR:1\nsession sid_pos=true setsid_failed_eperm=true\n"` | `doorbell 0xd3` |
| `procpeerdir` | `exit 0` | `"peer_access=false\npeer_is_dir=false\npeer_opendir=false\npeer_task_dir=false\npeer_task_lists_leader=false\npeer_stat_file=false\npeer_in_proc=false\nself_numeric_dir=false\ndead_pid_enoent=true\n"` | `doorbell 0xd3` |
| `ptraceattach` | `exit 0` | `"attach_nondumpable_eperm=false\n"` | `doorbell 0xd3` |
| `ptracekillcont` | `exit 0` | `"kill_plain_ok=false\nkill_plain_ptrace_errno=0\nkill_plain_final_errno=38\nkill_plain_cleanup_no_child=false\nkill_plain_cleanup_rc=-1\nkill_plain_cleanup_errno=38\nkill_handler_ok=false\nkill_handler_ptrace_errno=0\nkill_handler_final_errno=38\nkill_handler_cleanup_no_child=false\nkill_handler_cleanup_rc=-1\nkill_handler_cleanup_errno=38\ncont_plain_ok=false\ncont_plain_ptrace_errno=0\ncont_plain_final_errno=38\ncont_plain_cleanup_no_child=false\ncont_plain_cleanup_rc=-1\ncont_plain_cleanup_errno=38\ncont_handler_ok=false\ncont_handler_ptrace_errno=0\ncont_handler_final_errno=38\ncont_handler_cleanup_no_child=false\ncont_handler_cleanup_rc=-1\ncont_handler_cleanup_errno=38\n"` | `doorbell 0xd3` |
| `ptracestop` | `exit 0` | `"fork_ok=true\nblocking_wait_reaped_stop=true\nblocking_wait_completed_before_alarm=true\nblocking_wait_errno=0\nblocking_wait_errno_zero=true\nblocking_wait_stopped=false\nblocking_wait_stopsig=0\nblocking_wait_stopsig_is_sigstop=false\ncont_ok=false\ncont_errno=0\ncont_errno_zero=true\nexit_reaped=false\nexit_errno=10\nexit_errno_zero=false\nexit_exited=true\nexit_status_zero=true\n"` | `doorbell 0xd3` |
| `recursionguard` | `exit 0` | `"rlimit_stack_soft_8mib=true\nrlimit_stack_max_unlimited=true\nmain_stack_size_8mib=false\ndeep_c_recursion_fits=true\n"` | `doorbell 0xd3` |
| `rlimitasdata` | `exit 0` | `"data_limit_set=true\nbrk_16mib_ok=true\nbrk_past_data_unchanged=false\nmmap_rw_private_past_data_enomem=false\nmmap_prot_none_not_data=true\nmmap_shared_rw_not_data=false\nbrk_shrink_ok=true\nmmap_rw_private_within_data_ok=true\nas_limit_set=true\nmmap_within_as_ok=true\nmmap_past_as_enomem=false\nmremap_past_as_enomem=false\nmremap_within_as_ok=false\nchild_inherits_as_limit=false\n"` | `doorbell 0xd3` |
| `rosharedbus` | `exit 0` | `"child_exited_clean=true\nchild_read_efault=false\nchild_not_killed_by_signal=true\n"` | `doorbell 0xd3` |
| `seccompenforce` | `exit 0` | `"kill_process_filter_kills_with_sigsys=false\narch_gate_allows_native_isa=false\nnative_number_deny_eperm=false\n"` | `doorbell 0xd3` |
| `setpgidparentgroup` | `exit 0` | `"child_joins_parent_group=true\n"` | `doorbell 0xd3` |
| `sigbadstack` | `exit 0` | `"child_killed_by_signal=true\nchild_wtermsig_sigsegv=true\n"` | `doorbell 0xd3` |
| `signalexit` | `exit 0` | `"sigterm_wifsignaled=true\nsigterm_wtermsig_matches=true\nsigkill_wifsignaled=true\nsigkill_wtermsig_matches=true\nclean_exit_not_signalled=true\nclean_exit_status_zero=true\n"` | `doorbell 0xd3` |
| `sigtimedwaitintr` | `exit 0` | `"eintr_on_caught_nonset=true\nhandler_ran=true\nwaitset_signum_ok=true\nwaitset_si_code_is_user=true\nwaitset_si_pid_is_child=true\neagain_on_timeout=true\nsigchld_ignored_no_eintr=true\nrt_signum_ok=true\nrt_si_signo_ok=true\nrt_si_code_is_user=true\nrt_si_pid_is_child=true\nbad_info_efault=true\nhandler_total_ok=true\n"` | `doorbell 0xd3` |
| `sysvmsg` | `exit 0` | `"msgget_ok=true\nsend_recv_roundtrip=true\nqnum_after_send_is_1=true\nqnum_after_recv_is_0=true\nproc_sysvipc_msg_present=false\nproc_sysvipc_msg_live_queue=false\ntype_selective_recv=true\nxprocess_send_recv=true\nipc_rmid_ok=true\n"` | `doorbell 0xd3` |
| `sysvmsgwake` | `exit 0` | `"nowait_empty_enomsg=true\nnowait_full_eagain=true\nfork_reader_wakes_sender=true\nrmid_wakes_receiver=false\n"` | `doorbell 0xd3` |
| `usernsisolation` | `exit 0` | `"parent_before_uid_map=err=38\nparent_before_gid_map=err=38\nparent_before_setgroups=err=38\nchild_unshare_newuser_rc=-38\nchild_exit=0\nparent_after_uid_map=err=38\nparent_after_gid_map=err=38\nparent_after_setgroups=err=38\n"` | `doorbell 0xd3` |
| `vforkpid` | `exit 0` | `"vfork_child_created=true\nvfork_child_reaped=true\ngetpid_stable_after_vfork=true\nkill_getpid_after_vfork_rc_zero=true\nkill_getpid_after_vfork_not_esrch=true\nkill_getpid_after_vfork_handler_ran=true\n"` | `doorbell 0xd3` |
| `vforkvmshare` | `exit 0` | `"vfork_clone_returned_child=true\nclone_vm_shared_write_visible=false\n"` | `doorbell 0xd3` |
| `waitexitstorm` | `block budget exhausted, rip=0xffffffff80154ef2 cpl=0 cr3=0x487d000 blocks=4000000` | `""` | `doorbell 0xd1` |
| `waitidspec` | `exit 0` | `"waitid_exit7_rc_zero=true\nwaitid_exit7_si_signo_is_sigchld=true\nwaitid_exit7_si_code_is_cld_exited=true\nwaitid_exit7_si_status_is_7=true\nwaitid_kill_rc_zero=true\nwaitid_kill_si_code_is_cld_killed=true\nwaitid_kill_si_status_is_sigkill=true\nwaitid_wnowait_peek_ok=true\nwaitid_wnowait_peek_status_is_11=true\nwaitid_wnowait_reap_ok=true\nwaitid_wnowait_reap_status_is_11=true\nwaitid_no_children_rc_is_neg_one=true\nwaitid_no_children_errno_is_echild=true\n"` | `doorbell 0xd3` |
| `waitsiblingsigchld` | `exit 0` | `"default_ignore_wait_not_eintr=true\ndefault_ignore_wait_no_errno=true\ndefault_ignore_child_a_exited_zero=true\nhandler_interrupted_implies_eintr=true\nhandler_observed_sigchld=true\n"` | `doorbell 0xd3` |
| `x86-fork` | `exit 0` | `"child\nparent-ok\n"` | `doorbell 0xd3` |
| `x86_fork_prepared_cow_write` | `exit 7` | `"C\nP\n"` | `doorbell 0xd3` |
| `x86_fork_reuse` | `block budget exhausted, rip=0xffffffff80148a80 cpl=0 cr3=0x4802000 blocks=4000000` | `""` | `doorbell 0xd1` |
| `x86_fork_reuse.AUTOREAP` | `block budget exhausted, rip=0xffffffff80018e89 cpl=0 cr3=0x480c000 blocks=4000000` | `""` | `doorbell 0xd2` |
| `x86_fork_reuse.IGNORE_SIGCHLD` | `block budget exhausted, rip=0xffffffff80154ef2 cpl=0 cr3=0x480c000 blocks=4000000` | `""` | `doorbell 0xd2` |
| `x86_identity_fork` | `exit 7` | `"K\n"` | `doorbell 0xd3` |
| `x86_ipc_msg` | `exit 7` | `"M\n"` | `doorbell 0xd3` |
| `x86_ipc_sem` | `exit 7` | `"S\n"` | `doorbell 0xd3` |
| `x86_ipc_sem_rmid` | `exit 7` | `"R\n"` | `doorbell 0xd3` |
| `x86_ipc_sem_undo` | `exit 7` | `"U\n"` | `doorbell 0xd3` |
| `x86_signal_segv_child` | `exit 7` | `"S\nP"` | `doorbell 0xd3` |
| `x86_signal_thread_child` | `exit 7` | `"T\n"` | `doorbell 0xd3` |

</details>
