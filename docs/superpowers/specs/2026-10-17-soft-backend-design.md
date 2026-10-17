# Soft backend: HVPatch without hardware virtualization

Date: 2026-10-17
Status: design accepted by the owner 2026-10-17; epic carrick-sh/carrick#578; no code yet
Owner inputs (2026-10-17): x86_64 guests on x86_64 Linux hosts first, same ISA
only; then AArch64 on macOS hosted runners. Capacity, not product performance,
is the driver. Plan only, no implementation in this pass.

## 1. Summary

Carrick cannot run a guest without `/dev/kvm`, `Hypervisor.framework`, bhyve or
NVMM, and nested-virtualization capacity is the throughput ceiling for the
signed and KVM gates. This document designs a **software x86-64 machine**: a
set of software vCPUs that execute guest code by same-ISA dynamic binary
translation inside the carrier process, translate every guest virtual address
through a software TLB over the page tables Carrick already builds, and run the
**same CPL0 ring image bytes** the KVM lane runs today. The software machine
plugs in exactly where KVM does: it implements the `CarrierCpuIo` surface the
x86 CPL0 production carrier already drives (read image, write image, run,
complete pending I/O), plus a memory counterpart for what KVM memslots do. The
kernel, the executor pool, continuations, the CPL0 carrier lifecycle, the ring
body and every test the KVM lane has are shared, not reimplemented.

Feasibility verdict: **yes.** The CPL0 carrier is already driven through a
sealed trait with six in-crate test implementers besides KVM, so a software
CPU is the seventh. The stage-1 software walker, the COW resolver and the fault
policy are host-runnable today. The privileged instruction set the ring image
uses is small and enumerated (§4.3.3). What is new is the translator, the soft
TLB, a minimal local APIC, and extracting the CPL0 host carrier from the KVM
crate into a neutral one.

What this lane is for: hosted CI capacity for semantic gates and deterministic
work budgets, and a test loop for the x86 ring that needs no nested KVM. What
it is not: a replacement for the hardware lanes' runtime-ratio gates. A
translated guest is several times slower than native, and the ring body runs
translated too; this document says so and budgets for it.

## 2. Why now, goals, non-goals, anti-goals

### Why now

- `kernel-runtime.yml` runs the signed gate on one self-hosted cloudmac and the
  KVM lane on the Contabo host or ephemeral GCP nested-KVM VMs
  (`docs/ci/contabo-kvm.md`, `docs/ci/gcp-kvm.md`). Both are scarce and shared
  with build-heavy work (CPU admission is #376).
- Hosted `ubuntu-latest` (x86_64), `ubuntu-24.04-arm` and `macos-15` runners
  are plentiful but offer no usable hypervisor. HVF without the entitlement is
  `HV_DENIED`, which Rule 0 makes a failure, never a skip.
- `just test-kernel-semantics` already runs VM-free on hosted Linux but
  executes no guest instructions. Everything that boots an ELF needs trusted
  hardware.

### Goals

1. Run unmodified static and dynamic Linux x86_64 ELF binaries on an x86_64
   Linux host with no hypervisor, inside one carrier process, with guest
   `fork`/`clone`/`execve` creating no host processes.
2. Reuse the kernel, the executor pool, the continuation protocol, the CPL0
   carrier lifecycle, the stage-1 tables and descriptor transactions, the COW
   resolver, the signal frame codec and the ring image unchanged.
3. Make `carrick-vmm-kvm`'s fixture and lifecycle tests, `carrick-embed` guest
   tests and `carrick-conformance-next` probes runnable on hosted Linux
   runners as a failure-set diff lane against main.
4. Deterministic structural work budgets: the software machine counts
   translated blocks, TLB misses, faults, interrupts and syscalls exactly.

### Non-goals (first stack)

- Cross-ISA execution. Same ISA only; nothing here depends on an interpreter.
- Native-parity performance; the lane produces no runtime-ratio verdicts.
- A persistent on-disk translation cache.
- Rosetta `linux/amd64` on macOS (HVF-only, unaffected).
- A hardened trust boundary. Trusted test guests only, like every lane.

### Anti-goals

- A second kernel path or a second ring. The software machine executes the
  ring image the KVM lane executes; it does not call the ring body as host
  code, patch it, or reroute syscalls around it.
- Host `mmap` of guest virtual addresses (`MAP_FIXED` at guest VA, bias
  windows): retired in `f9933c9da` for measured reasons
  (`docs/native-dsr-static-campaign.md`). This design never maps a guest VA.
- Host signals for guest faults or kicks.
- Default-off work. Selectable from day one with one exact `=0` hatch;
  measured-worse pieces are deleted.

## 3. Ground truth

Three read-only audits of the current tree (HEAD `237356f00`), one builder
review of the first draft, and inspection of the retired crates at
`f9933c9da~1` back this section. References are to the current tree.

### 3.1 How the x86 CPL0 lane is built today

```text
carrick-cli --exec-backend hvpatch      (only variant; "auto" is an alias)
  -> carrick-kernel::page_profile::ExecutionBackend::KvmX86Cpl0
  -> carrick-runtime prepare.rs: ExecutorPool<KvmPersistentExecutorFactory>
       executor/kvm.rs (1,620 lines): PersistentExecutor over
         carrick_vmm_kvm::cpl0_boot::{Cpl0Carrier, ProductionCpuFactory,
           ProductionCpuLease, ProductionForwardFrame, KernelStackSnapshot, ForwardVenue}
         carrick_vmm_kvm::carrier_cpu::{KvmCarrierCpu<I: CarrierCpuIo>, CarrierRunExit}
       carrick_vmm_kvm::carrier_memory::{CarrierMachine, CarrierMemory}   (KVM memslots)
  -> ring image: crates/carrick-x86-cpl0 (bin, x86_64-unknown-none, built by
       carrick-vmm-kvm/build.rs) over carrick-x86-carrier over carrick-el1
```

- `CarrierCpuIo` (`crates/carrick-vmm-kvm/src/carrier_cpu.rs`) is sealed and
  has four methods: `read_image() -> X86VcpuSnapshot`, `write_image(&snapshot)`,
  `run() -> VcpuExit`, `complete_pending_io()`. `KvmCpuIo` implements it over a
  `VcpuFd`; five deterministic in-crate test drivers (`TestIo`, `ChildRetireIo`,
  `PendingIo`, `ReadFaultIo`, `FaultIo`) implement it without hardware. The
  carrier was built to be driven by something other than KVM.
- `CarrierRunExit` is the carrier's protocol over `carrick_hal::VcpuExit`:
  `SyscallTrap` (an `out` to `FORWARD_PORT`), `Halt`, `Kick`,
  `FaultDoorbellWord(u32)` (an `out` to `FAULT_DOORBELL_PORT`),
  `FaultException{syndrome, far}`, `PhysicalDoorbell{port, data}`.
- `X86VcpuSnapshot` (`crates/carrick-x86/src/bringup_fns.rs`) is the state a
  CPU provider must hold: 16 GPRs, `rip`, `rsp`, `rflags`, `cr0/cr3/cr4`,
  `efer`, `fs_base`, `gs_base`, and the XSAVE area.
- `CarrierMemory` owns the KVM memslot table (`KvmVm`, `slots`, `by_gpa`,
  aliases, roots, admitted/drained sets, generations) and implements the
  `InventoryTransaction`/`InventoryRetirement` traits that publish frame
  custody (`BackingIdentity{frame_id, mapping_id, owner_generation,
  inventory_revision}`). There is no trait between the carrier and the
  memslot mechanism today.
- The ring's shared region and metadata live at fixed guest-physical addresses
  the carrier chooses (`META_GPA = 0xc0_0000`, `KERNEL_REGION_GPA =
  0x1_0000_0000`, image at `X86_CPL0_SUPERVISOR_IMAGE_GPA`, a 16 MiB RAM
  window, allocator and initial-extent windows). The ring addresses them
  through supervisor VAs in the upper half (`X86_CPL0_REGION_BASE =
  0xffff_ffff_c000_0000` and friends) mapped by its own PML4.
- The KVM lane snapshots and restores the ring's **kernel stack** across
  blocking continuations (`save_kernel_stack`/`restore_kernel_stack`,
  `KernelStackSnapshot`). The ring can block mid-kernel; the carrier owns that.
- The ring programs a local APIC: xAPIC MMIO page at `0xfee0_0000`
  (`LAPIC_BASE`), TSC-deadline timer via MSR `0x6e0`, IPIs for wake, resched
  and TLB shootdown (`interrupts::hardware::{send_wake, send_resched,
  send_shootdown}`), a shootdown table in metadata (`SHOOTDOWN_OFFSET`). The
  host side injects wakes with `kvm_msi`.
- CPUID is the host table, installed on every vCPU (`kvm.rs`, `cpuid:
  Arc<CpuId>`), so the guest's CPU view already varies per KVM host.

### 3.2 What a software machine must emulate: the ring's privileged surface

Census of mnemonics in `asm!`/`global_asm!` across `carrick-x86-carrier`,
`carrick-el1/src/isa/x86`, `carrick-x86-cpl0`, `carrick-x86` and
`carrick-mem` (sites, not dynamic frequency):

| Mnemonic | Sites | Soft handling |
|---|---|---|
| `iretq` | 24 | exception return: pop frame, CPL change, flags |
| `out dx, al/eax` | 23 | doorbells → `VcpuExit::IoOut` |
| `swapgs` | 10 | swap `gs_base` and `KERNEL_GS_BASE` |
| `rdtsc` | 9 | copy through (same host) |
| `cli` / `sti` | 9 / 6 | IF bit; delivery check at block boundary |
| `wrmsr` / `rdmsr` | 8 / 2 | FS/GS/KERNEL_GS base, LSTAR/STAR/SFMASK, EFER, APIC base, TSC deadline, x2APIC if enabled |
| `mov cr3`, `mov cr2` | 8 | root switch (TLB flush), fault address |
| `xsetbv` | 6 | XCR0 of the guest view |
| `hlt` | 6 | `VcpuExit::Halt` when nothing pending |
| `clac` / `stac` | 6 / 3 | AC flag; SMAP enforced by the soft walker |
| `ud2` | 5 | `#UD` delivery |
| `cpuid` | 4 | pinned guest view (§4.3.5) |
| `sysretq` / `sysret` | 4 | return to CPL3 |
| `invlpg` | 1 | evict one VA on this CPU |
| `in` | 1 | port read → doorbell protocol |
| `lfence` | 1 | copy through |
| `syscall` (user) | n/a | enter CPL0 at LSTAR per `STAR`/`SFMASK` |

Plus: `#PF`, `#GP`, `#UD`, `#DE` delivery through the IDT the ring installs;
`lidt`/`lgdt`/`ltr` at boot; the xAPIC MMIO page; the TSC-deadline timer; IPIs.
That is a bounded, well-specified set. Everything else in the ring and in the
guest is ordinary x86-64 code and copies through.

### 3.3 What already runs without a VM

| Need | Existing, VM-free |
|---|---|
| Stage-1 walk with permission check and fault class | `carrick_mmu_core::x86::descriptor_txn::translate_leaf` via `X86Mmu: OwnerMmu` |
| Descriptor publication over host atomics | `LiveDescriptorWords` implementers over host pointers (`carrick-el1/src/isa/x86/mmu.rs`, `carrick-x86-carrier/src/entry.rs`) |
| COW | `carrick_core::mm::cow::resolve_guest_cow` (host tests in `cow.rs`); but in this design the **ring** runs it, as on KVM, so the host never calls it |
| Blocking | `prepare_blocked_continuation`, `ExecutorExit::BlockedContinuation`, `resume_continuation`; the KVM executor already uses them |
| Kicks and shootdown handshake | `VcpuKick`, `VcpuRegistry`, `InGuestFlag`, `GuestLeaveWake` |
| Signals | `carrick_hal::sigframe` over `RegAccess + CurrentMmMemory` (KVM path) |
| Timers | `KickerGuestTimers` over `TimerCoreBridge` (every kick+futex lane) |
| CPL0 carrier tests | `carrick-vmm-kvm` unit tests driving `KvmCarrierCpu` through scripted `CarrierCpuIo` doubles |

### 3.4 Retired DSR crates: what carries over

The old lane was same-ISA copy-through DBT with host-mapped guest memory and
one host process per Linux process. No interpreter, no cross-ISA code, no
encoding census ever existed. Salvage table in Appendix A. Reusable for x86:
the iced-x86 classifier and sensitive catalogue (`decode.rs`), the
variable-length block planner (`block.rs`), control-flow resolution over a
memory trait (`cflow.rs`), the pure FXSAVE/x87/XSAVE emulators, the
`X86UcontextSnapshot` layout, the translation cache and page-generation table
(`carrick-dsr/src/cache.rs`), the W^X seam, and about 40 tiny static x86_64 ELF
fixtures with sources and a loader harness.

`iced-x86`, `bad64` and `dynasmrt` are declared in the root `Cargo.toml` but
absent from `Cargo.lock`: no crate uses them, so they are fresh dependencies on
the build graph (all license-allowed by `deny.toml`).

Measured lessons that carry over:

1. Inserted glue must not clobber flags, or must own them explicitly.
2. Register-allocate by guest liveness; per-op scratch borrowing was about
   16% of CPU.
3. Never hold an address-space lock while guest code runs.
4. Per-page code generations bumped on writes to executable pages, plus entry
   guards; direct links are routinely cross-generation and must be severed.
5. Deliver asynchronous events only at block boundaries or poll points.
6. Return traps to Rust as typed exits with the resume PC; never execute the
   guest's trap instruction natively.
7. Invalid control-flow targets become Linux `SIGSEGV`/`SIGBUS` with the right
   `si_code` (here: a `#PF`/`#GP` delivered to the ring, which already does
   this), never backend errors.
8. TLS bases, PKRU, x87 selectors and the XSAVE layout are guest-virtual state
   presented from the guest's CPUID view.

Measured envelope of the old same-ISA translator: compute microbenchmarks 3.4x
to 3.8x native; glue was 52% of executed emitted instructions; cold `go build`
10.2x, dominated by per-process costs a single carrier does not pay.

### 3.5 x86 lane maturity

`scripts/conformance/baseline.kvm.jsonl` has 9 rows (8 `diff`, 1
`oracle_fail`) against 2,064 on the AArch64 lane. The merge-queue `kvm-tests`
job records its per-SHA receipt with `just accept --profile kvm --receipt` and
`kvm-gate` diffs failure sets with `carrick-xtask ci-receipt gate --lane kvm`.
The soft lane inherits the x86 lane's ceiling and uses the same receipt and
gate machinery with a new lane name. It is also the cheapest way to raise that
ceiling: every x86 ring change becomes testable on a laptop and a hosted runner.

### 3.6 Corrections to the first draft (from the builder review)

- The KVM persistent executor is built on `cpl0_boot`/`carrier_cpu`, not on
  `X86Vmm`/`X86EngineCore<V>`; the engine-generic VMM pair is used only by the
  legacy `run-elf` bring-up engines. This design therefore plugs in at
  `CarrierCpuIo`, not at `X86Vmm`.
- The x86 ring reads its CPU binding from `GS:[16]` after `swapgs`, not from
  the stack pointer (that is AArch64). Irrelevant now: the ring is executed,
  not bound.
- `AsidGeneration` and `Stage1MmLease` exist only on the HVF lane; the x86
  lane's `invalidate_asid` is a no-op. The soft TLB is keyed by CR3 root and
  flushed on `mov cr3`, as hardware without PCID is (§4.2.2).
- `commit_existing_el1_prepared_page` and `PrimaryTableWords` are AArch64-side
  types; the x86 lane has its own `LiveDescriptorWords` implementers. Neither
  is called by the host in this design.
- `GuestCpuidView` does not exist; it is new work (§4.3.5).

## 4. Architecture

```text
carrick-cli  (--vcpu soft | hardware | auto; see §4.6)
  -> ExecutionBackend::SoftX86Cpl0
  -> carrick-runtime: ExecutorPool<Cpl0PersistentExecutorFactory<SoftMachine>>
       executor/cpl0.rs  (today's executor/kvm.rs, generic over the machine)
         load -> run_until_boundary -> save -> settle          (unchanged)
           carrick-x86-cpl0-host::Cpl0Carrier                  (moved from carrick-vmm-kvm)
             KvmCarrierCpu<I: CarrierCpuIo>  --->  I = SoftCpu  (carrick-vmm-soft)
               SoftCpu::run():
                 translated blocks (carrick-softcpu-x86) over
                 soft TLB + walker (carrick-softmmu) over
                 LinearPlacement of guest-physical memory
                 privileged emulation, exceptions, local APIC, timer
                 returns VcpuExit::{IoOut, Exception, Kicked, Halt}
             CarrierMemory<M: CarrierMemoryIo> ---> M = SoftMemory (placement)
  -> ring image carrick-x86-cpl0 (same bytes as KVM) -> carrick-kernel on Forward
```

### 4.1 Where it plugs in

**Decision: the software machine is a CPU and memory provider for the existing
x86 CPL0 production carrier.** Not a new `PersistentExecutor` (that copies the
CPL0 lifecycle), not an `X86Vmm` (the production lane does not use that
engine; building on it would be a second path), and not a host-code binding of
the ring body (the x86 ring is a `target_os = "none"` image with assembly
entry and return paths, a `GS:[16]` CPU binding and a kernel stack the carrier
snapshots; binding it would reimplement the carrier's entry layer).

Concretely:

1. **Move, never copy.** `cpl0_boot.rs`, `carrier_cpu.rs` and
   `carrier_memory.rs` (about 10.4k lines) move from `carrick-vmm-kvm` into a
   new neutral crate `carrick-x86-cpl0-host`, with two provider traits:
   - `CarrierCpuIo` (exists; unsealed to a public trait with the same four
     methods plus `kick()`),
   - `CarrierMemoryIo` (new; the memslot operations `CarrierMemory` performs
     on `KvmVm` today: install extent at GPA, replace, remove, read/write
     bytes, host pointer for a committed extent).
   `carrick-vmm-kvm` keeps `KvmCpuIo` (over `VcpuFd`) and gains `KvmMemoryIo`
   (over `VmFd`). The KVM lane's failure set and the carrier's unit tests are
   the witness that this is a pure move.
2. `executor/kvm.rs` becomes `executor/cpl0.rs`, generic over the machine
   provider (`Cpl0PersistentExecutorFactory<M>`); KVM and soft instantiate it.
3. `carrick-vmm-soft` provides `SoftMachine: CarrierMemoryIo` and
   `SoftCpu: CarrierCpuIo` plus a `VcpuKick` handle. It depends on
   `carrick-x86-cpl0-host`, `carrick-softcpu-x86`, `carrick-softmmu`,
   `carrick-x86`, `carrick-hal`; never on `kvm-ioctls`, `carrick-vmm-kvm` or
   `carrick-kernel` (layering gate).
4. `CarrierRunExit::from_raw` is unchanged: the soft CPU produces the same
   `VcpuExit`s KVM does, including `IoOut` for the doorbell ports and
   `Exception{syndrome, far}` for faults the ring does not handle itself.

### 4.2 Memory

#### 4.2.1 Linear placement of guest-physical memory

`SoftMemory` reserves one host virtual range at machine creation
(`mmap(PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE)` for the whole
guest-physical span the carrier can address) and places every extent at
`host = gpa + K` for one carrier-constant `K` (`mmap(MAP_FIXED)` inside the
reservation on install; `madvise(MADV_DONTNEED)` or `munmap` back to
`PROT_NONE` on remove). `K` is typed (`LinearPlacement`) and is the only place a
`Gpa` becomes a `HostVa`. The x86 CPL0 guest-physical span is small today
(windows below 4 GiB plus the frame extents the carrier installs), so the
reservation is far under the 47-bit user limit on Linux x86_64. The
reservation size is a `LinearPlacement` parameter, and the AArch64 phase
measures what macOS allows before relying on one span.

Typed-domain rule (AGENTS.md): guest VA, stage-1 output GPA, frame GPA and
owner generation remain distinct types; placement is a `Gpa -> HostVa`
mechanism and never lets a guest VA or host VA stand in for a GPA. A
`lint-domains` rule pins the conversion to `LinearPlacement::host`.

The xAPIC page at `0xfee0_0000` and the doorbell ports are **not** placed:
they are MMIO/PIO holes the soft TLB never fills, so accesses there always take
the slow path into the device models (§4.3.4).

#### 4.2.2 Soft TLB

Per soft CPU, L1-resident, direct-mapped, 1024 entries per kind (data read,
data write, instruction fetch), 16 bytes each:

```text
tag    : u64  = va_page | cpl_bit | ac_bit        ; u64::MAX = invalid
addend : u64  = host_page - va_page               ; host = va + addend
```

- The tag carries the current privilege level and, for CPL0, the AC flag, so
  SMAP semantics (`clac`/`stac`) are enforced without a walk: a CPL0 access to
  a USER page hits only if the entry was filled while AC=1.
- `mov cr3` flushes all entries (hardware semantics without PCID). The ring's
  own cross-CPU shootdown protocol (shootdown table plus IPI plus `invlpg`)
  works unchanged because the soft CPU implements `invlpg` (evict one VA on
  this CPU) and IPIs faithfully. No `AsidGeneration` is needed on x86.
- `write` entries stay invalid for pages whose leaf is read-only, COW-armed
  (`COW` bit) or that hold cached translations (§4.3.2); writes take the slow
  path.
- `exec` entries exist only for pages with `NX` clear, and fetch also checks
  the page's code generation.
- Page-crossing accesses never hit (§4.3.6).

Slow path (Rust, entered from the translated block with the CPU context):

1. Walk with `translate_leaf` over the live CR3 through `LiveDescriptorWords`
   backed by the placement, with the exact hardware checks: `PRESENT`, `USER`
   vs CPL, `WRITE`, `NX`, SMAP via AC, reserved bits.
2. On success fill the entry and retry.
3. On failure deliver `#PF` **to the ring** exactly as hardware would: set
   `cr2`, build the exception frame on the CPL0 stack per the IDT entry, enter
   the ring's fault handler at CPL0. The ring then does what it does on KVM:
   COW resolution in-ring via `resolve_guest_cow`, frame grants via the
   mailbox, or the fault doorbell `out` that becomes
   `CarrierRunExit::FaultDoorbellWord` for the host. The host side of fault
   handling is **unchanged**.

Shootdown correctness depends on the same thing it depends on under KVM: the
ring's IPI protocol. The soft CPU delivers IPIs at block boundaries and
back-edges (bounded countdown, §4.3.7), so a shootdown is acknowledged within a
bounded number of guest instructions; a CPU that misses the bound is a named
fatal, never a retry.

#### 4.2.3 Frames, inventory, custody

Frame custody is the carrier's (`InventoryTransaction`, `InventoryRetirement`,
`BackingIdentity`, generations) and moves with it into
`carrick-x86-cpl0-host`. `SoftMemory` implements only the mechanism
(`CarrierMemoryIo`): install an extent at a GPA (commit `MAP_FIXED` into the
placement), replace, remove (back to `PROT_NONE`), and expose a host pointer
for a committed extent. Stage-1, placement and inventory publication stay one
rollback-capable transaction because the same carrier code sequences them.

Guest `MAP_SHARED` across tasks is one host range; `LOCK` RMWs copy through
onto it and are coherent across worker threads. Cross-carrick-process shared
futexes keep riding the `PlatformFutex` seam.

### 4.3 Execution: same-ISA copy-through translation

**Decision: no interpreter. One translator for CPL3 and CPL0 code, two levels
of ambition.** Every instruction that touches only registers copies through
verbatim, so ISA coverage is the host CPU's. Four classes need work: memory
operands (soft TLB), control flow (block ends and links), the privileged and
sensitive set of §3.2, and anything the classifier refuses (fail closed as
`#UD` delivered to the ring, counted and logged with the encoding, so gaps are
visible).

- **Level 0 (Phase 2 exit criterion):** one block per translation, every block
  ends in an exit to the dispatch loop, memory operands lowered with flags
  saved and restored around the probe unconditionally, two reserved scratch
  registers. Correct, slow, small.
- **Level 1 (Phase 3):** block chaining with generation guards, rflags
  liveness from iced-x86 `instr_info` so the probe is flag-free when flags are
  dead, scratch allocation by guest liveness, BMI2 probe variant, indirect
  target cache. Each feature is its own PR, kept only if measured better.

#### 4.3.1 Decoder, emitter, context

`iced-x86` decodes and re-encodes; glue (probe, exit stubs, exception entry)
comes from a small hand-rolled assembler as the retired `emit.rs` did. One
`SoftCpuContext` per CPU, pointed to by reserved `r15`: the `X86VcpuSnapshot`
state plus CPL, IDT/GDT/TR bases, the MSR file, XCR0, AC/IF bookkeeping, the
three soft TLBs, the pending-interrupt set, the exit word, spill slots and
exit-stub addresses. `r14` is the address scratch. Both are virtualized: guest
values live in the context and guest instructions naming them are rewritten
through spill slots (as DSR did for `r15`). FS- and GS-relative operands are
lowered as `base_from_context + displacement` then probed; the host's own
segment bases are never touched.

#### 4.3.2 Translation cache keying and invalidation

Blocks are keyed by **physical identity**: `(frame GPA page, page offset, page
code generation)`, with a per-root VA front table mapping `va_page` to the
frame entry after a walk. A `fork` child shares every translation of a shared
frame with its parent; a COW break re-keys only the copied frame; the ring
image's translations are shared by every CPU. Pages holding translations keep
their `write` TLB entry invalid; a write to one takes the slow path, bumps the
page's generation, severs direct links into its blocks (lesson 4), then
performs the write. Self-modifying code and runtime JITs are correct and slow
in the way QEMU is. `invlpg`, `mov cr3` and descriptor edits affect the TLB,
not the translation cache; the cache is keyed physically so a remap of the same
frame keeps its translations and a frame reuse gets a new generation through
the inventory's owner generation.

#### 4.3.3 Privileged emulation and privilege transitions

Each mnemonic in §3.2 is classified `Sensitive` and lowered to an exit stub
that returns to Rust with the instruction's identity; Rust performs the state
transition on the context and the loop re-enters the translated code at the
new RIP. `syscall` (CPL3) becomes a transition to CPL0 at `LSTAR` with `rcx`,
`r11`, `rflags & ~SFMASK` and `cs/ss` from `STAR`; `sysretq` and `iretq`
reverse it; `swapgs` swaps the two GS bases; `mov cr3` installs the root and
flushes the TLB; `out`/`in` on the doorbell ports produce `VcpuExit::IoOut`
for the carrier; `hlt` with nothing pending produces `VcpuExit::Halt`;
`cli`/`sti`/`clac`/`stac` set bits; `wrmsr`/`rdmsr` access the MSR file;
`xsetbv` sets the guest XCR0; `cpuid` returns the pinned view (§4.3.5);
`rdtsc` copies through. CPL0 is enforced: a `Sensitive` instruction executed
at CPL3 delivers `#GP`, as hardware does.

Exceptions (`#PF`, `#GP`, `#UD`, `#DE`) are delivered through the ring's IDT:
switch to the CPL0 stack from the TSS when coming from CPL3, push the hardware
frame (and error code where defined), load the handler from the IDT entry,
enter at CPL0. Faults the ring does not handle in-ring become
`VcpuExit::Exception{syndrome, far}` through the ring's existing doorbells, as
on KVM.

#### 4.3.4 Local APIC, timer, IPIs, kicks

A minimal xAPIC device model: the MMIO page at `LAPIC_BASE` is a soft-TLB hole
so every access reaches Rust; implemented registers are ID, version, TPR, EOI,
SVR, ICR (fixed-vector IPIs to a physical destination), ISR/IRR enough for
`highest_in_service_vector`, LVT timer and the TSC-deadline MSR. An IPI sets
the vector pending on the target CPU and kicks it. The host wake that KVM
injects with `kvm_msi` becomes the same pending-vector set plus a kick. Pending
vectors are delivered at block boundaries when IF=1, by the exception-delivery
path with no error code. The TSC-deadline timer is a deadline the CPU checks at
block boundaries and that the pool's parked wait honours when the CPU halts.

`VcpuKick::kick` sets the CPU's exit word and `mark_pending_host_work(slot)`
exactly as the KVM kick handle does before `KVM_RUN` is interrupted; translated
code polls the word at every block end (Level 0) or at back-edges and
indirect branches with a bounded countdown (Level 1), so a tight loop still
exits within a bounded number of iterations. This is the mechanism that bounds
IPI and shootdown latency in §4.2.2.

#### 4.3.5 Guest CPU view

`cpuid` is intercepted and answers from a pinned `GuestCpuidView` (new, in
`carrick-x86`): a documented baseline, proposed **x86-64-v3** (SSE4.2, AVX2,
BMI1/2, FMA, F16C, MOVBE, POPCNT; no AVX-512, no AMX, hypervisor bit clear),
with the leaf 0xD XSAVE layout that view implies and XCR0 limited to
x87|SSE|AVX. The host must support the baseline or the machine refuses to
start. Copy-through means a guest that executes an instruction above the view
anyway runs it on the host; that is also true under KVM today. The soft lane
pins the view so its failure set does not move with runner allocation (a
moving verdict is a `flaky` defect under AGENTS.md). Whether the KVM lane
should pin the same view is an owner question (§11).

`xsave`/`xrstor`/`fxsave`/`fxrstor` and the legacy x87 env forms go through
the reused pure emulators over the soft TLB, so their footprint matches the
guest view and page-crossing is handled; `xgetbv`, `rdpkru`/`wrpkru` and
`rdpid` answer from the virtual XCR0/PKRU/TSC-aux.

#### 4.3.6 Page-crossing and unaligned accesses

The translated instruction takes its memory operand from the scratch register,
so the slow path never has to emulate the instruction: for an access that
crosses a page it translates both pages, copies the straddling bytes into a
per-CPU bounce buffer, points the scratch at the buffer, lets the copied
instruction execute, and writes back when iced marks the operand written.
Atomicity of a page-straddling `LOCK` RMW is lost; hardware implements it as a
split lock and QEMU accepts the same loss. Counted, documented, not hidden.

#### 4.3.7 Flags, scratch and glue cost

x86 has no flag-free `and`/`cmp`, so Level 0 brackets every probe with
`lahf`/`seto` and the reverse. Level 1 drops the bracket when flags are dead
after the instruction (the common case for loads and stores) and uses BMI2
`shrx`/`rorx`/`pext` for the index when the host has them. Estimated emitted
instructions per memory operand:

| Variant | Instructions |
|---|---|
| Level 0, flags live | 11 to 13 |
| Level 1, flags dead, BMI2 | 6 to 7 |

### 4.4 The ring, unchanged

The ring image is `carrick-x86-cpl0` built for `x86_64-unknown-none` by the
same `build.rs` and loaded at the same GPA by the same carrier code. It
executes under the translator at CPL0. Every in-ring syscall, COW resolution,
fault, scheduler decision and kernel-stack snapshot behaves as on KVM because
it is the same code reading the same guest memory. Ring-first and the crossing
allowlist (`crates/carrick-personality-linux/src/crossing.rs`) are untouched.
The cost is that the ring runs at translation overhead rather than native; the
benefit is that every x86 ring defect found on the soft lane is a defect of
the KVM lane too, and vice versa, which is what makes the soft lane a valid
test loop for the ring.

### 4.5 Syscalls, signals, execve, fork

All four are the KVM lane's paths. A guest `syscall` enters the ring at CPL0
(translated); the ring either serves it or writes its forward frame and does
`out FORWARD_PORT`, which `CarrierRunExit::from_raw` turns into `SyscallTrap`
for the executor; blocking outcomes become `ExecutorExit::BlockedContinuation`
and release the lease; signals are built with `carrick_hal::sigframe` over the
carrier's `RegAccess`; `execve` and `fork` publish through the shared kernel
operations and the carrier's inventory, with the soft TLB learning the new
mappings on first touch. Nothing in this section is new code.

### 4.6 Selection, features, builds

- **Request.** `ExecBackendRequest::HvPatch` stays the only execution model.
  The vCPU provider is an orthogonal choice: `--vcpu hardware|soft|auto`
  (`CARRICK_VCPU` for the environment), default `auto`. `auto` resolves to
  hardware when the host has a usable hypervisor device and to `soft` when it
  has **none** (no `/dev/kvm`); it never falls back on a hypervisor **error**
  (`HV_DENIED`, `EPERM` on `/dev/kvm`). Signed and KVM recipes pass
  `--vcpu hardware` explicitly. `CARRICK_VCPU=hardware` is the exact `=0`
  hatch for the new default behaviour.
- `ExecutionBackend` gains `SoftX86Cpl0`; `resolve_execution_plan_for_request`
  consults the provider; `PreparedRun::execute` instantiates the generic cpl0
  executor with `SoftMachine`.
- Cargo: `carrick-runtime` gains `vcpu-soft = ["dep:carrick-vmm-soft"]`, on by
  default under `platform-linux` (and later under `platform-macos` for the
  AArch64 machine). `check-layering` adds: no `carrick-kernel`, `kvm-ioctls`
  or `carrick-vmm-kvm` in `carrick-vmm-soft`'s closure; no `carrick-vmm-*` in
  `carrick-x86-cpl0-host`'s closure.

## 5. Crate structure

| Crate | Kind | Depends on | Role |
|---|---|---|---|
| `carrick-x86-cpl0-host` | std | `carrick-x86`, `carrick-hal`, `carrick-el1`, `carrick-el1-abi`, `carrick-mmu-core`, `carrick-core-abi`, `carrick-sched-core` | **Moved** CPL0 production carrier: `Cpl0Carrier`, `KvmCarrierCpu<I>` (renamed `CarrierCpu<I>`), `CarrierMemory<M>`, inventory, kernel-stack snapshots, forward venue. Defines `CarrierCpuIo` and `CarrierMemoryIo`. |
| `carrick-vmm-kvm` | existing | + `carrick-x86-cpl0-host` | `KvmCpuIo`, `KvmMemoryIo`, kick handle, the rest of the KVM backend. |
| `carrick-softmmu` | `no_std` + `alloc` | `carrick-mmu-core`, `carrick-guest-arch`, `carrick-core-abi` | `LinearPlacement`, `SoftTlb`, walker binding with the hardware permission model (CPL, SMAP, NX), MMIO holes. |
| `carrick-softcpu-x86` | std | `iced-x86`, `carrick-softmmu`, `carrick-x86` | Classifier, planner, Level 0/1 translator and emitter, translation cache, bounce path, privileged emulation, exception delivery, local APIC and timer models, reused xstate/x87 emulators, `GuestCpuidView` consumer. Sees memory only through a `SoftMemory` trait. |
| `carrick-vmm-soft` | std | `carrick-x86-cpl0-host`, `carrick-softcpu-x86`, `carrick-softmmu`, `carrick-x86`, `carrick-hal` | `SoftMachine: CarrierMemoryIo`, `SoftCpu: CarrierCpuIo`, `VcpuKick` handle, host-wake injection. |
| `carrick-runtime` | existing | `vcpu-soft` | generic `executor/cpl0.rs`, selection, pool start. |
| `carrick-spec`, `carrick-cli`, `carrick-embed` | existing | | `--vcpu`, `auto` resolution, test lanes. |

## 6. Verification

Cheapest capable layer first, as `carrick-conformance-contract` requires.

1. **VM-free structure.** `carrick-softmmu` and `carrick-softcpu-x86` unit
   tests on every host; deterministic counts (TLB misses per access pattern,
   translations per block, interrupts delivered, shootdown acknowledgements)
   are exact structural budgets.
2. **Differential against the real CPU for user-mode translation.** On an
   x86_64 host, a property test runs an instruction sequence natively (a
   forked child under `ptrace` single-step, or a fixture ELF with a syscall
   shim) and under the translator, and compares registers and memory after
   every block. Operand shapes are generated from the iced instruction tables:
   every addressing mode and width, page-crossing, flags live and dead,
   `LOCK`, segment overrides. The hardware says what an instruction means.
   Red-first: a translator bug must produce a diff before the fix. CPL0 code
   cannot be single-stepped natively; its oracle is item 3.
3. **The KVM lane as the whole-machine oracle.** `carrick-x86-cpl0-host`'s
   carrier tests and `carrick-vmm-kvm`'s fixture-image tests (boot the
   `carrick-x86-cpl0-fixture` image, observe its ports and metadata) are
   re-run with `SoftMachine` in place of KVM, on a host with no `/dev/kvm`.
   Same image, same expected observations. This is the exit criterion for
   privileged emulation: the fixture suite passes identically on both.
4. **Guest conformance.** `carrick-embed` guest tests and
   `carrick-conformance-next` probes under `--vcpu soft` on hosted
   `ubuntu-latest`, as a new test lane `soft-x86` in
   `[package.metadata.carrick.test-lanes]`, recorded with `just accept
   --profile soft --receipt` and gated by `carrick-xtask ci-receipt gate --lane
   soft` as a failure-set diff against main, itemized per binary with the
   started-vs-finished population check. The soft lane never runs Docker
   concurrently with a guest.

What the soft lane does **not** gate: runtime ratios. Its contract class is
"semantic plus deterministic work budget". A guest at 5x is the expected cost
of translation; a guest at 500x is a translator bug caught by work-budget
counters, not by wall time. Hardware lanes keep the ratio gates.

Instrumentation: fail-closed `#UD` for unsupported encodings, bounce-buffer
executions, flag-bracketed probes, interrupts, TLB misses and translations are
counted in the machine and exposed as a `soft-x86` profile of `carrick trace`
(Rust-first rule). A census subcommand (`carrick debug soft-census ELF`)
histograms iced opcodes over an image's executable sections so coverage is
planned from data.

## 7. Phased plan as stacked PRs

Each layer is one PR under 4k lines with its own issue (`Part of #<epic>`),
witness and receipt. Layers that touch Linux paths take the full signed gate at
the top of the stack; the pure move (1c) takes the KVM merge-queue receipt as
its witness; the rest are additive and take the lighter gate.

**Phase 0: this document and the epic issue.** Decision requests to #231:
contract class (§6), `--vcpu auto` resolution (§4.6), CPUID pinning (§4.3.5).

**Phase 1: substrate (VM-free, every host).**

- 1a `carrick-softmmu`: `LinearPlacement`, `SoftTlb` with the CPL/AC tag,
  walker binding with the hardware permission model, MMIO holes. Witness:
  unit tests over `Vec<AtomicU64>` tables including SMAP, NX, USER and
  reserved-bit cases; a two-thread test that an `invlpg`-style eviction and a
  root switch flush exactly what hardware would.
- 1b `carrick-softcpu-x86` Level 0 for user mode: classifier, planner, probe,
  exit protocol, bounce path, `#PF`/`#UD`/`#GP`/`#DE` surfaced as typed
  exits; the retired fixture ELFs under the reused loader harness; the
  differential harness with its first property suites.
- 1c **Pure move:** `cpl0_boot.rs`, `carrier_cpu.rs`, `carrier_memory.rs`
  → `carrick-x86-cpl0-host`, `CarrierCpuIo` unsealed, `CarrierMemoryIo`
  extracted, `executor/kvm.rs` → `executor/cpl0.rs<M>`, KVM instantiating
  both. Witness: KVM-lane receipt `NEW=[]`, carrier unit tests unchanged,
  `just check-contract-change`. This layer touches the owner-flagged hot
  file and is sequenced per §11.

**Phase 2: whole machine and end-to-end ELF (x86_64 Linux host, no KVM).**

- 2a Privileged emulation, exception delivery, local APIC and timer, MSR
  file, `GuestCpuidView`. Witness (§6.3): the CPL0 fixture-image tests pass
  on `SoftMachine` identically to KVM.
- 2b `carrick-vmm-soft`: `SoftMachine`, `SoftCpu`, kick handle, host wake
  injection; `--vcpu`, `ExecutionBackend::SoftX86Cpl0`, pool start. Live
  demo: a static `hello` ELF through `carrick run --vcpu soft` on a host
  without `/dev/kvm`; artifact SHA recorded on the PR.
- 2c Lanes: `soft-x86` test lane, `accept --profile soft`, `ci-receipt gate
  --lane soft`, the hosted `soft-tests` job running `carrick-embed` guest
  tests. Witness: green with a non-empty, itemized population.
- 2d `carrick-conformance-next` probe families under `--vcpu soft`;
  failure-set diff against the KVM receipt. Exit criterion: `NEW=[]` against
  the KVM failure set, and the embed suite wall time recorded (this number
  schedules Phase 3).

**Phase 3: Level 1 translator.** Chaining with generation guards, rflags
liveness, BMI2 probe, scratch by liveness, indirect target cache; each a PR
with a paired, interleaved A/B on one host, deleted if measured worse.

**Phase 4: AArch64 on macOS hosted runners.** A separate design pass, because
the AArch64 production lane is `Aarch64EngineCore<V: Aarch64Vmm>` over the EL1
image, not the CPL0 carrier. The same principle applies and is the
recommendation to carry into that pass: a software AArch64 machine that
executes the EL1 image bytes (EL1 system registers, exception entry and
return, `hvc` exits mapped to `Aarch64Exit`, stage-1 walk with PAN, exclusive
monitor, GIC SGIs), implementing `Aarch64Vmm`/`Aarch64Vcpu` so the engine,
signals and COW glue are shared; `MAP_JIT` plus per-thread write protect from
the retired `jit.rs`; the `macos-15` hosted job. Pre-condition from 1a: the
achievable host reservation on macOS.

Acceptance criterion for the epic: the CPL0 fixture suite, `carrick-embed`
guest tests and `carrick-conformance-next` run green as a failure-set diff on
hosted `ubuntu-latest` with no hypervisor, from one unsigned `cargo build`, and
the KVM and HVF failure sets are unchanged.

## 8. Risks

| Risk | Why it is real | Mitigation |
|---|---|---|
| x86 lane maturity caps the soft lane | 9 baseline rows vs 2,064 | 2d measures against the KVM failure set; the soft lane is the x86 ring's new inner loop. |
| The pure move (1c) collides with live x86 ring work | 10.4k lines in the hot file | Sequenced by the owner (§11); the move changes no behaviour and is witnessed by the KVM receipt; a stack layer, not a parallel copy. |
| Privileged-emulation fidelity (exception frames, `iretq` corner cases, APIC) | the ring depends on exact semantics | The CPL0 fixture suite is the oracle; the ring's privileged surface is enumerated (§3.2) and small. |
| User-mode translator long tail (XSAVE footprints, x87, split lock, segment overrides) | DSR spent months here | reused pure emulators; differential oracle; fail-closed `#UD` with counts; census tool. |
| Ring runs translated, so in-ring syscalls are slower than on KVM | glue cost on every ring memory operand | accepted for a CI lane; no ratio gate; Level 1 helps the ring as much as the guest. |
| Interrupt latency bound (a CPU stuck in a long translated block) | lost-wake class | bounded back-edge countdown; a CPU that misses the bound is a named fatal. |
| Host VA reservation on macOS (Phase 4) | unknown maximum span | 1a reports the achievable span per host; `K` is variable. |
| "Second implementation" of the ISA | unavoidable in a translator | copy-through makes the ISA the host's; only glue is ours, and glue is differentially tested. |

## 9. Performance envelope (estimates, replaced by Phase 2d numbers)

| Workload class | Expected soft/native | Basis |
|---|---|---|
| Syscall-bound probes and LTP cases | 2x to 4x | guest compute small; the ring runs translated too |
| Compute-bound, Level 0 | 5x to 10x | flag bracketing on every memory operand |
| Compute-bound, Level 1 | 3x to 5x | retired same-ISA translator measured 3.4x to 3.8x |
| Fork/exec-heavy | 2x to 4x | per-process exec/translate costs of the old lane do not exist in one carrier; translations shared by physical keying |

Not claims. Perf claims need a controlled, paired, interleaved run on a quiet
host; 2d records the first such numbers.

## 10. Decisions made here (the owner can overrule)

1. Plug in as a CPU and memory provider for the existing CPL0 production
   carrier (`CarrierCpuIo` + new `CarrierMemoryIo`), after moving that carrier
   into a neutral crate. Not a new executor, not an `X86Vmm`, not a host-code
   binding of the ring.
2. Execute the ring image as translated CPL0 code; emulate its enumerated
   privileged surface, exceptions, a minimal xAPIC and the TSC-deadline timer.
3. No interpreter; same-ISA copy-through translation, Level 0 then Level 1,
   for CPL3 and CPL0 alike.
4. Linear placement `host = gpa + K`, typed, the only `Gpa -> HostVa`
   conversion; xAPIC and ports are holes.
5. Soft TLB tagged by VA, CPL and AC; flushed on `mov cr3`; `invlpg` evicts;
   no ASID machinery on x86.
6. Translation cache keyed by physical frame identity; code pages keep their
   write entry invalid.
7. Page-crossing accesses through a bounce buffer; split-lock atomicity loss
   accepted and counted.
8. CPUID pinned to x86-64-v3 for the soft lane; host must meet it.
9. `--vcpu hardware|soft|auto` orthogonal to `--exec-backend hvpatch`; `auto`
   picks `soft` only when no hypervisor device exists, never on an error.
10. Contract class of the lane: semantic plus deterministic work budget; no
    runtime-ratio verdicts.
11. First hosted target `ubuntu-latest`; the embed suite's pool size is tuned
    to its 4 vCPUs rather than requiring larger runners.

## 11. Owner decisions (2026-10-17)

1. **Sequencing of the pure move (1c), amended the same day:** the in-flight
   fork stack (#513 → #493) and #542 land **first**, because they edit the
   exact files 1c relocates (`cpl0_boot.rs`, `carrier_cpu.rs`,
   `carrier_memory.rs`, `executor/kvm.rs`) and are close to landing; 1c then
   rebases onto them. 1a (`carrick-softmmu`) and 1b (`carrick-softcpu-x86`
   Level 0 plus the differential harness) start immediately in parallel, since
   they touch none of those files. 1c stays behaviour-neutral and is witnessed
   by the KVM receipt.
2. **CPUID pinning: both lanes.** One `GuestCpuidView` (x86-64-v3) installed by
   the KVM lane and answered by the soft lane, in the soft lane's stack. A view
   that moves with the host is a `flaky`-class defect on either lane.
3. **Scope: product capability.** `carrick run` on a host without
   virtualization is a shipped feature, not only a CI lane. Consequences:
   `--vcpu auto` selects `soft` on such hosts without a notice; the §9
   envelope becomes a product budget class of its own after 2d records real
   numbers (the soft vCPU is a different host-capability class, so the ≤2x
   native Docker target of the hardware lanes does not apply to it, and its
   budget is stated as a translation ratio against the KVM lane on the same
   host); the lane's semantic gate is the same as every lane's. Decision log:
   #231.
4. **Epic filed:** carrick-sh/carrick#578 with this plan and the acceptance
   criterion; board column Todo.

## Appendix A: salvage table (at `f9933c9da~1`)

| Module | Verdict | Reason |
|---|---|---|
| `carrick-dsr-x86/src/decode.rs` | adapt | iced classifier and sensitive catalogue are the front end; add the CPL0 privileged set |
| `carrick-dsr-x86/src/block.rs` | adapt | pure variable-length block planner |
| `carrick-dsr-x86/src/cflow.rs` | reuse | Rust branch semantics over a memory trait |
| `carrick-dsr-x86/src/{fxstate,legacy_x87}.rs` | reuse as-is | pure checked emulators over reader/writer traits |
| `carrick-dsr-x86/src/xstate_{save,restore,address}.rs` | adapt | pure; layout parameter from `GuestCpuidView` |
| `carrick-dsr-x86/src/gateway.rs` | adapt snapshot, discard context | `X86UcontextSnapshot` is needed by the emulators |
| `carrick-dsr-x86/src/{gateway_x86_64.S,emit.rs,translator.rs}` | discard | identity/bias host-VA lowering |
| `carrick-dsr-x86/tests/*` | reuse | ~40 static ELF fixtures with sources, loader harness |
| `carrick-dsr/src/cache.rs` | adapt | translation cache, page generations, publication dedupe; re-key by frame |
| `carrick-dsr/src/host.rs` | adapt | W^X seam; drop fork remap |
| `carrick-dsr/src/{vocabulary,ids,lane}.rs` | reuse | small vocabulary |
| `carrick-dsr/src/{address,identity_memory,prepared_image,fault,native_error,probes,profile}.rs` | discard | host-mapping, self-reexec, host-signal model |
| `carrick-dsr-aarch64/src/{decode,types,block,emulate}.rs` | adapt (Phase 4) | tables, IR vocabulary, exclusive fusion, memory-op semantics |
| `carrick-dsr-aarch64/src/mapped_memory.rs` | discard except the exclusive-monitor algorithm | value CAS plus per-page seqlock |
| `carrick-dsr-aarch64/src/{translator,emit,gateway,gateway_aarch64.S,shared_cache}.rs` | discard, mine design | fork/exec lifecycle, bias lowering, host-register context |
| `carrick-dsr-aarch64/src/prot_ranges.rs` | reuse as-is | pure coalesced interval map |
| `carrick-native-darwin/src/jit.rs` | reuse as-is (Phase 4) | `MAP_JIT` plus per-thread write protect |
| `carrick-native-darwin/src/{direct.rs,aot_cache.rs}`, `csrc/` | discard | in-place execution, persistent store, host signals |

## Appendix B: what the current tree has that this touches or deliberately leaves

- `experiments/native-syscall-slice`: macOS same-ISA AArch64 research runner
  with a whitelist classifier, a JIT gateway and a 256-back-edge checkpoint
  over the kernel's `NativeExecution` scope. Its checkpoint shape informs
  §4.3.4; its private memory model does not carry over.
- `crates/carrick-kernel/src/dispatch/native_execution.rs`: the no-vCPU
  admission. The soft CPU is a vCPU as far as the executor is concerned, so it
  uses the persistent-executor path; the admission stays for host-side native
  data paths.
- `crates/carrick-runtime/src/hvpatch/{patcher,island}.rs`: static `svc`
  rewriting for the AArch64 HVPatch lane; not used here, listed so nobody adds
  a second patcher.
- `crates/carrick-x86/src/{vmm,engine}.rs` (`X86Vmm`, `X86EngineCore`): the
  legacy bring-up engines' seam, not the production lane's; untouched.
