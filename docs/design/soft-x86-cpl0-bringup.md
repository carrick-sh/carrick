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
their code frames and generations on their next entry. A removed or
replaced slot still stops the soft carrier pending integration with
`ExtentTable::remove` and its retirement protocol.

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
