# Carrick structural leverage audit — 2026-06-20

Static read-and-reason pass over the source (no build/run). Method: a 41-agent
fan-out — 3 structural-map builders, a 17-concern read→adversarial-verify
pipeline (each "unify this" attacked by a skeptic told to catch the cardinal
error of collapsing a load-bearing split), 3 census sweeps, 1 completeness
critic. All 17 verdicts survived scrutiny; one was corrected (errno:
load-bearing → partial-unify).

---

## 0. The one-paragraph verdict

The architecture is **honest about its hardware boundaries and further along the
unification curve than the file names suggest.** The dependency graph is
strictly acyclic, the load-bearing splits (privilege model, ISA, VMM ABI,
fork/COW mechanism) are real and mostly already isolated behind tidy seams
(`X86Vmm`/`X86Vcpu`, `GuestArch`, `EventMultiplexer`, `FutexTableFutex<S>`,
`HostSignalGlue`). The residual debt is **not random duplication — it is one
recurring structural pattern**: the x86 lane proved a factoring (`X86EngineCore`,
shared pumps, shared fork coordinator) and the **aarch64/HVF lane did not
follow**, while the **forwarder scaffolding generated during each migration was
never swept.** Three shapes recur: (1) HVF is the consistent holdout that
re-implements by hand what a shared seam already provides, almost always because
one genuinely load-bearing difference (its kqueue pump) was never given a hook,
so the *whole* unit forked; (2) the missing `Aarch64EngineCore` symmetric to the
proven `X86EngineCore`; (3) a layer of dead/vestigial forwarder files. Hiding
inside that copied code are a handful of real correctness divergences (notably a
**dropped ring-0 fault guard on bhyve** and **`/proc/cpuinfo` reporting ARM for
x86 guests**). Fixing the pattern is high-leverage and mostly *subtraction*.

---

## 1. Structural map

### 1.1 Crate dependency graph

25-crate workspace, edges flow strictly downhill (stated authoritatively in
`carrick-spec/src/lib.rs:481-483`), verified: **no backend or leaf crate depends
up on `carrick-runtime`** — clean layering, no cycles.

```
                         carrick-cli            (single control point; binary `carrick`)
                              │  selects exactly one platform-* feature
                ┌─────────────┴───────────────┐
          carrick-engine                 (RunSpec merge; only re-forwards platform-*)
                │
        carrick-runtime  ── dispatch/ (~30k LOC, arch+host-neutral) · vfs/ · fs_backend · re-export hub
                │  optional dep: per platform-*
   ┌────────────┼───────────────┬───────────────┐
 vmm-hvf      vmm-kvm        vmm-bhyve        vmm-nvmm          (per-VMM backends)
 (macOS/arm)  (Linux/x86+arm) (FreeBSD/x86)   (NetBSD/x86)
   │            └──────┬───────┴───────────────┘
   │              carrick-x86   (SHARED x86 engine: trap loop, long-mode, snapshot, run-elf — ONCE)
   │
 ── shared engines ──  carrick-thread (registry + private futex + fork_quiesce) · carrick-mem · carrick-observability
 ── host-OS glue   ──  carrick-host-bsd (kqueue mux, SIGNUM_XLATE, BsdFutex) · carrick-host-linux (epoll mux)
 ── leaf/trait/data ── carrick-hal (≈18 traits) · carrick-abi · carrick-guest-mem · carrick-portable
                       carrick-signal-core · carrick-timer-core · carrick-host · carrick-spec
```

Key facts:
- **`carrick-cli` is the sole control point.** `platform-{macos,linux,freebsd,netbsd}`
  each (a) activate exactly one VMM + host crate via the `dep:` pattern and
  (b) forward the same feature to `carrick-runtime` and `carrick-engine`
  (`cli/Cargo.toml:22-26`). The `dep:` syntax is load-bearing — it stops the four
  optional VMM crates from auto-becoming implicit features, so the only path to
  `carrick-vmm-hvf` is `platform-macos`.
- **"Exactly one platform" is enforced-by-construction and *assumed*, not
  statically checked** — there is no `compile_error!` guard anywhere. A bad
  multi-platform combo fails with duplicate-symbol errors, not a diagnostic.
- **The empty-crate `#![cfg]` pattern is inconsistent.** kvm/bhyve/nvmm and
  host-linux gate the whole crate; `carrick-host-bsd` uses a custom
  `carrick_bsd_family` cfg from its `build.rs` (a new BSD = one line — the better
  pattern). **`carrick-vmm-hvf` is the odd one out**: no crate-level cfg, gates
  per-module internally.
- Recently hoisted shared engines (the good direction): `CompatReporter`+USDT
  probes into `carrick-observability`, `shared_aperture` into `carrick-mem`, the
  AArch64 syscall table into `carrick-abi` — all were HVF-private with Linux/KVM
  no-op stubs; now every backend gets the real impl.

### 1.2 Type-level architecture

The cross-boundary types are mostly well-placed. The good patterns to preserve:

- **`TrapError` layered correctly**: aarch64-internal `EL0Fault`/`GuestAtEl1`
  (raw `ESR_EL1`) are *lowered at the loop boundary* to the ISA-neutral
  `GuestFault{signum,si_code,fault_addr}` that x86 emits directly
  (`carrick-hal/src/trap.rs:197,248`). This is the right way to share an error
  type across ISAs.
- **`GuestArch` (per-ISA seam via associated types** `Frame`/`Mmu`/`Table`/`BootSysregs`,
  `guest_arch.rs:78`) selected statically through `ThreadedEngine::Arch` so the
  syscall hot path monomorphizes — no vtable. A `FakeArch` compile-test proves a
  third ISA would plug in. **Best-factored axis in the tree.**
- **`X86Vmm`/`X86Vcpu` (`carrick-x86/src/vmm.rs:222,475`)** quarantines the two
  real bhyve outliers as *enum returns* (`MsrInstall::NeedsRing0Blob`,
  `get_fp()==None`) rather than per-backend branches — removing any backend would
  not simplify the trait, which is the correct test for a load-bearing seam.
- **Per-ISA ABI struct splits are all load-bearing and self-documenting**:
  `LinuxStat`/`LinuxX8664Stat` (different offsets), `LinuxEpollEvent` (16B aarch64)
  /`LinuxX8664EpollEvent` (12B x86), `Aarch64SyscallFrame`/`X8664SyscallFrame`.
  **Do not abstract these away.**

The type-level smells (detailed in §2.2):
- `carrick_hal::Reg` is an **over-broad merged aarch64+x86 register enum** that
  forces `unreachable!()` arms (`kvm.rs:454`) and a hand-written `reg_to_x86()`
  bridge (`engine.rs:492`) — the x86 GPR set is enumerated twice.
- The x86 control registers (`Cr0..4`/`Efer`) live *only* on `X86Reg`, so the HAL
  trait surface can never name them — a three-way `Reg`/`SysReg`/`X86Reg` split
  where no enum is a superset.

### 1.3 Trait surface — what is abstracted, and the gaps

Already well-expressed (do **not** re-abstract): `HostSignalGlue` +
`GenericSignalPump`, `SharedFutexSyscall` + `FutexTableFutex`,
`GenericVcpuRegistry`, `GenericForkCoordinator<Glue>`, `GenericSignalArrival`,
`EventMultiplexer`, `GuestArch`.

**The unexpressed-polymorphism gaps:**
1. **No `Aarch64EngineCore`** (highest durability leverage). KVM-aarch64
   `trap_engine.rs:562` (1.8k LOC) and HVF `trap.rs` (5.8k LOC) hand-roll the
   aarch64 trap-loop shell twice. The x86 side already proved the
   `X86EngineCore<V>`-over-`(X86Vmm,X86Vcpu)` pattern erases exactly this.
2. **Double VM/vCPU abstraction**: `HvVm`/`HvVcpu` (`hypervisor.rs`) and
   `X86Vmm`/`X86Vcpu` both abstract "a vCPU/VM"; `X86Vcpu::run` delegates to
   `HvVcpu::run`. Resolve by making `HvVm`/`HvVcpu` the aarch64 pair (feeding
   gap #1).
3. **Vestigial forwarders**: `*_signal_pump.rs` / `*_xsig.rs` are pure forwarders
   to shared generics, self-documented as "these forwarders then go away".

---

## 2. Findings by theme

Notation: **[verdict]** read→verified, **leverage**. Every "unify" states why the
divergence is incidental; every "leave it" states the essential reason.

### 2.1 Duplication across VMMs/arches/hosts

#### F1 — bhyve fault decode bypasses the shared classifier *and drops a safety guard* — **[partial-unify, high]** · CORRECTNESS
KVM and NVMM route fault classification through `carrick_x86::fault_exit_from_record`
(`fault.rs:420-449`), which includes a **ring-0-fault guard** (`fault.rs:425-430`):
a fault whose saved CS is ring-0 (inside the LSTAR stub / kernel window) is a hard
engine error, not a deliverable guest signal. **bhyve re-implements the entire
decode inline** (`bhyve_x86_engine.rs:706-761`) — its own vector→`X86FaultKind`
match, its own fault-addr-per-kind selection, its own user-context restore — and
**omits the ring-0 guard.** A ring-0 stub fault on bhyve is mis-delivered as a
guest SIGSEGV with bogus user RIP/RSP instead of surfacing the bug. This is a
*behavioral fork hiding in copied code*, not a latent one.
- **Incidental** because everything after "I have vector+error+rip+rsp+cr2" is
  identical to the shared path; only `read_va` (the ring-0 fault-frame page-walk,
  `276-322`) is genuinely bhyve mechanism.
- **Target**: bhyve builds the neutral fault record from its `FaultScratchRecord`,
  then calls `fault_exit_from_record(self, record, "bhyve-x86")` like KVM/NVMM.
  Deletes ~55 lines, restores the guard, single-sources the vector→kind tables.

#### F2 — POSIX timer firing thread copied 4×; bhyve POSIX timers are a silent no-op — **[partial-unify, high]** · CORRECTNESS
The firing thread (`sleep value_ns → generation guard → publish → interval loop`)
is copied ~90-98% identical four times: `kvm/timer_delivery.rs:59-79`,
`nvmm_threaded_glue.rs:48-69`, `hvf/posix_timer.rs:23-44`, `runtime/lib.rs:2543-2562`.
The itimer fallback was correctly hoisted into `timer-core::run_fallback` (which is
CPU-timer-aware) — but the POSIX thread was not, so **none of the 4 copies handle
`CLOCK_PROCESS_CPUTIME_ID`** (they fire off wall-clock). Worse, **bhyve `arm_posix`
returns `None`** (`bhyve_threaded_glue.rs:40-47`) → POSIX timers silently do nothing
on FreeBSD, and **`disarm_itimer` is a no-op** that leaks `armed=true` state.
- **Essential**: HVF's `arm_itimer` can register `EVFILT_TIMER` (returns `true`,
  owns delivery via the kqueue pump); KVM/bhyve/NVMM have no pump and must return
  `false` + spawn a host thread. The kick is folded into `publish` on HVF but
  explicit `kick_all()` on the others.
- **Target**: move the POSIX firing thread into `carrick-timer-core::posix` (mirror
  `itimer::run_fallback`, branch on `clock_id`); collapse the per-fire action behind
  one `fire(signum)` hook. HVF goes from three timer files to one.

#### F3 — `run_threaded_hvf_loop` is a 130-line clone of the generic loop — **[needs-split, high]**
KVM/bhyve/NVMM all funnel through the generic `run_threaded_loop<E,H:HostBackend>`
(`lib.rs:507`); **HVF alone bypasses it** with a hand-written twin
(`runtime.rs:1452`). The *only* load-bearing reason is HVF's signal **arrival** is a
kqueue pump, not the kick+futex `GenericSignalArrival` the others share — and
`HostBackend` lacks a `make_signal_arrival()` hook. Everything else in the 130 lines
is a verbatim clone of the generic scaffold.
- **Target**: add `fn make_signal_arrival(&self, kicker, futex) -> Arc<dyn SignalArrival>`
  to `HostBackend` (default `GenericSignalArrival`); implement `HostBackend` for an
  `HvfHostBackend` whose `make_signal_arrival` returns the kqueue-pump arrival.
  Delete the clone; **all four backends enter through one loop**, and the next
  VMM/host is strictly cheaper. HVF already impls `ThreadedEngine` — only the host
  seam is missing.

#### F4 — HVF re-implements the host-signal disposition control flow — **[partial-unify, high]** · drift already happening
`carrick-signal-core::host_glue` generalizes `ensure_host_handler`/`set_host_ignore`/
`set_host_default`/`reset_routed_handlers_after_execve`; **HVF hand-rolls all of them
again** (`host_signal.rs:945-1083`, ~80% structurally identical). The policy has
*already drifted*: the neutral `is_host_routable` (`host_disposition.rs:109-116`) and
HVF's inline skip sets disagree (HVF excludes SIGINT(2) from ignore/default; the
generic policy does not). The `reset_routed_handlers_after_execve` off-by-one ABI
subtlety (`ignored_mask` indexed by `signum` vs install mask by `signum-1`) is
implemented twice — exactly the off-by-one that gets fixed in one copy only. This is
the subsystem that exists to fix LTP `kill02/kill12` / CPython interprocess-signal
bugs; a fix landing in `host_glue` will not reach macOS.
- **Essential & must stay separate**: HVF's pump/wake (kqueue + self-pipe), its
  `SIGNUM_XLATE` table, and its **synchronous-fault `si_code` guard**
  (`handle_routed:899-919`) — under HVF a guest fault is a vmexit, so a host
  SIGSEGV with `si_code>0` is always a carrick bug and must crash visibly.
- **Target**: make HVF implement `HostSignalGlue`; add the si_code guard to the
  trait as a provided method `fn is_synchronous_self_fault(...) -> bool { false }`
  that HVF overrides. `ensure_host_handler` etc. then exist once.

#### F5 — `HvfFutex` re-implements the whole `PlatformFutex` surface — **[partial-unify, high]** · drift-prone, hardest-to-test backend
The futex layer is otherwise the **gold-standard pattern**: `FutexTableFutex<S>` +
a ~15-line per-host `SharedFutexSyscall` shim. But `HvfFutex`
(`threaded_impl.rs:33-142`) re-implements the entire surface — `private_wait` is
byte-for-byte the same as `platform_futex.rs:73-90`, `shared_wait` is the same
`shared_wait_sliced` + classification as `kvm_futex.rs:100-121`. ~90-95% identical;
the only HVF-unique bits are the trace probes and the per-waiter `sched_yield` wake.
- **Essential**: the raw kernel call (`os_sync_wait_on_address` / `_umtx_op` /
  `SYS_futex` / `__futex`) and HVF's one-at-a-time `sched_yield` wake (macOS
  `os_sync_wake_by_address_any` reports spurious back-to-back successes on a SHARED
  address) — but this is *already captured* by the `SharedFutexSyscall::wake`
  contract.
- **Target**: define `HvfSharedFutex: SharedFutexSyscall` (wraps `ulock::wait` with
  probe bracketing + the sched_yield wake loop), make `HvfFutex =
  FutexTableFutex<HvfSharedFutex>`, delete the 110-line hand-roll. Then **every
  backend is `FutexTableFutex<S>`.** Because HVF is the macOS-only, hardest-to-test
  backend, a shared-slice-loop fix (lost-wake, signal-interruptibility) silently
  missing HVF is the least likely to be caught by Linux/FreeBSD CI.

#### F6 — bhyve carries ~2000 lines of x86 bring-up that NVMM proves is shareable — **[partial-unify, high]**
`carrick-x86::bringup_fns` owns `build_pml4`/`program_longmode_entry`/`snapshot`/
`restore`/the fault tables. **NVMM (a non-KVM third-party hypervisor, so no
privilege excuse) routes bring-up entirely through carrick-x86 and has no
`guest_setup` file at all.** bhyve's `guest_setup_x86.rs` is **3132 lines vs KVM's
472**, hand-rolling its own `fault_idt`/`fault_stub_for_vector`/`write_fault_tables`
and a `fp_stub_bytes` that is **byte-for-byte identical** to
`carrick_x86::bringup::fp_stub_bytes` (held in sync only by a unit test;
`msr_init_blob` has already diverged by two args).
- **Essential & must stay** behind the existing `MsrInstall` seam: bhyve's
  libvmmapi has **no MSR ioctl** (`vm_set_register(LSTAR)` → EINVAL), so it must
  enter at CPL 0 on a ring-0 WRMSR blob and `iretq` to ring 3 — forcing ring-0
  segment ARs and a no-op `set_segment` (re-programming segments mid-stream
  triple-faults; the M1 iretq blocker). FS/GS base must go through `vm_set_desc`.
  These are real VT-x/libvmmapi facts.
- **Target**: delete bhyve's local `msr_init_blob`/`fp_stub_bytes`, re-point at the
  canonical ones; add a shared `enter_via_ring0_blob` companion to
  `program_longmode_entry`; replace `ACCESS_RING0_*` hex with `seg_ar(DPL=0)`.
  Risk if not done: the SYSCALL-enable blob and the FP/XSAVE stub **must stay
  bit-compatible for fork/clone to work**, with no compiler enforcement.

#### F7 — two aarch64 trap-loop shells (HVF + KVM) hand-written; x86 has one — **[partial-unify, medium]**
The post-classification handoff (`SyscallTrap::next_syscall` → neutral `RawSyscall`)
and the x86 classifier (`X86EngineCore::next_syscall` over `X86Exit`) are correctly
single-sourced. But the **aarch64 `next_syscall` loop shell is written twice**
(HVF `trap.rs:2354-2475` vs KVM `trap_engine.rs:562-690`): the EL1-vector-kick guard
(KVM's comment literally says "Mirror HVF"), the EL0-fault register capture, and the
`guest_cpu` run-timing wrapper (triplicated verbatim — `engine.rs:728-730` notes the
x86 side factored it and the aarch64 sides did not).
- **Essential & must NOT collapse the arm trap path into x86**: HVF is trap-based
  (routes `svc`→EL1 vector→`hvc #2` because public arm64 HVF has **no stage-2
  TLBI**); KVM-aarch64 uses an MMIO sentinel; x86 uses PIO fault doorbells (hardware
  doesn't trap guest faults to the host). Different vehicles dictated by what each
  hypervisor surfaces.
- **Target**: mirror the x86 split — an `Aarch64Exit` enum + `Aarch64EngineCore<V>`
  owning the shared shell, with a thin per-VMM `Aarch64Vcpu::run()` doing only the
  vehicle decode. Minimum-viable first step: hoist the `guest_cpu` timing wrapper
  (3→1) and add a shared `TrapError::el0_fault(...)` constructor — zero mechanism risk.

#### F8 — `HostForkCoordinator` state machine written twice (HVF + generic) — **[partial-unify, medium]** · drift already happening
The vCPU **quiesce barriers** are correctly single-sourced
(`carrick-thread/fork_quiesce.rs`; HVF is a 7-line re-export) and `ForkRamStrategy`
correctly separates policy from mechanism. But the *signal-pump* coordinator's
5-method state machine is ~85% identical between `GenericForkCoordinator`
(`fork_coord.rs:80-147`) and HVF's `ForkCoordinator` (`hvf/fork_coord.rs:59-113`).
It has **already diverged**: the generic restarts the pump on the error path ("KVM
previously only re-asserted … restarting is strictly more robust") and calls
`block/restore_pump_signals_for_fork` — **both absent from HVF's copy.**
- **Essential**: the wake primitive (kqueue/EVFILT_USER vs self-pipe/sigaction) and
  the COW mechanism (Mach VM COW / OS COW / bhyve freeze+rebuild).
- **Target**: lift the state machine into one `PumpForkCoordinator<P: HostSignalPump>`
  in carrick-hal; supply `SelfPipePump` (current generic) and HVF's `KqueuePump`.
  The `had_signal_pump` gating and error-path-restart then live once.

#### F9 — run-elf image-prep preamble copied 4× + a parallel aarch64 loop — **[partial-unify, high]**
The x86 service loop *is* shared (`run_elf_service_loop`). The duplication is the
5-line image-prep idiom (`load_elf_for + with_vdso_bytes + with_linux_initial_stack`)
verbatim in 4 places — **NVMM does it twice in one file** (`nvmm/run_elf.rs:29-37` and
`51-59`). Separately, the **aarch64 KVM `run_elf.rs:42-340` is a ~300-line parallel
reimplementation** of the concept with its own `sys_writev`/`sys_read`/`host_write`
(~80% identical to `bringup_fns.rs:646-713`), differing only in frame field access and
**errno accessor** (`*__errno_location()` Linux-only vs portable
`Error::last_os_error()`). The two loops drifted to non-overlapping feature sets
(x86 has `mmap`/`brk`; aarch64 has `clone`/`fork`/`wait4`).
- **Essential**: the aarch64-vs-x86 loop split at the ISA boundary (different syscall
  numbers, register frame, no fork on aarch64).
- **Target**: hoist `load_x86_elf_image(path)` into carrick-x86 (cheap, high value);
  factor the byte-moving helpers; eventually reconcile both loops into one generic
  loop over `SyscallTrap + GuestMemory`.

#### F10 — three VMM service `main.rs` + `run_threaded_X_loop` + `run_elf_*_dispatch` wrappers — **[incidental, low-medium]**
`carrick-vmm-{kvm,nvmm,bhyve}/src/main.rs` are near-verbatim ("Mirrors
carrick-vmm-kvm's main.rs pattern verbatim"). `run_threaded_{kvm,bhyve,nvmm}_loop`
(`lib.rs:752,770,783`) are one-line forwarders that the type-erased
`Box<dyn VcpuKickDyn>` registration already makes unnecessary. `run_elf_real_dispatch`
is cfg-fanned 3× (vs `run_oci` which is already a clean 6-line closure into
`run_oci_with_engine`).
- **Target**: `run_elf_with_engine<E,Build,Run>` mirroring `run_oci_with_engine`
  (arch-parametric via `E::Arch`); delete the loop wrappers (call generic directly);
  a `run_elf_cli_entry` macro for the three mains.

### 2.2 Type-level divergence

#### T1 — `carrick_hal::Reg` is over-broad (merged aarch64+x86) — **[over-broad-shared-type]** · runtime panic guards a type gap
`Reg` (`error.rs:93`) crams the aarch64 view (`X(n)`/`Sp`/`Pc`/`Pstate`/…) and the
x86 GPRs (`Rax..R15`/`Rip`/`Rflags`) into one enum. The doc claims this makes ISA
mixups compile errors — but it doesn't: every aarch64 `RegAccess` impl carries
`_ => unreachable!("x86_64 Reg variant on the aarch64 KVM lane")` (`kvm.rs:454`,
`SysReg` same at `470`). The x86 GPR set is enumerated **twice** (here and in
`carrick_x86::X86Reg`, which is a superset adding `Cr0..4`/`Efer`), forcing the
hand-written `reg_to_x86()` bridge (`engine.rs:492-514`, 18 arms) whose sole purpose
is to map two models of one concept.
- **Target**: make the arch seam generic over an associated `Reg` type
  (`Aarch64Reg`/`X86Reg`) so each `ThreadedEngine::Arch` carries only its own
  register enum; `reg_to_x86()` and the `unreachable!()` arms disappear. `X86Reg` is
  the natural canonical x86 enum. The per-VMM native marshalling (`RegLoc`,
  `VM_REG_GUEST_*`, kvm offsets) is **load-bearing** and is the model `Reg` should
  emulate (one shared enum, per-target marshalling).

#### T2 — name collision: bhyve `X86Exit` shadows `carrick_x86::X86Exit` — **[load-bearing, rename]**
`vmm_x86.rs:197` is the raw FreeBSD `vm_exitcode` decode (imported as `NativeExit`),
converted into the shared `carrick_x86::X86Exit` in `run()`. Genuinely per-VMM
marshalling — keep it, but **rename to `BhyveVmExit`** to kill the false "two
X86Exit enums" reading.

#### T3 — `X86FaultKind` / `EL0Fault` / `GuestFault` three-layer — **[load-bearing, keep]**
x86 native fault kinds and aarch64 raw-ESR `EL0Fault` both converge on the neutral
`GuestFault{signum,si_code,fault_addr}` at the loop boundary. Correct three-layer
design — not duplication. (Optionally document that x86 has no `EL0Fault`-equivalent
so the asymmetry reads as intentional.)

### 2.3 cfg gates that should be traits

The census confirmed **`carrick-portable`'s 47 OS gates are load-bearing by design**
— it is the single libc-symbol seam (errno accessor, kqueue/extattr/sendfile/xattr
normalization), guarded by a semgrep rule. Likewise `F_FULLFSYNC`, `EVFILT_EXCEPT`,
`sin_len`, sysctl CPU count, and the `platform-*` selectors are correctly gated. The
real cfg-as-trait targets:

#### C1 — `proctitle.rs` — **[unexpressed-polymorphism]**
`discover_and_relocate()` is duplicated nearly verbatim between the macOS arm
(`319-419`) and Linux arm (`493-581`) — same contiguity walk + environ relocation,
differing only in the argv/environ accessor. → `trait HostProcTitle { fn argv_environ();
fn write_title(); }` with one shared relocation algorithm; BSD delegates to
`setproctitle(3)`. Collapses ~260 lines.

#### C2 — `load_execve_image` + the misnamed `macos_helper_stubs` — **[unexpressed-polymorphism]**
Two divergent image-builder bodies, one in a module **literally named
`macos_helper_stubs` that holds the production Linux/KVM path** (`vcpu_loop/mod.rs:92-282`).
Per-ISA vDSO/ELF-machine selection is cfg-picked at the call site even though
`GuestArch` already abstracts `elf_machine()`/`vdso_bytes()`. → make image-building a
method on `ThreadedEngine`/`GuestArch`; rename the module.

#### C3 — host-COW seeding scattered as ~30 inline cfgs — **[mechanism load-bearing, structure incidental]**
`fs_backend.rs` (clonefile vs FICLONE+copy_file_range vs FreeBSD copy_file_range,
~30 inline `#[cfg(target_os)]` pairs at `542,1204-1264,1484-1640,1805-1918,2097-2390`)
and `layer_cache.rs` (clonefile vs replicate_tree vs Unsupported). The COW *operations*
are load-bearing (and the unprivileged-LXC KVM box can't reflink at all); their
*shape* is not. → a `trait ScratchSeeder`/`HostCowSeed { fn seed_entry(src,dst) ->
io::Result<bool> }` (or a `host_proc`-style `mod imp` per OS — the canonical good
pattern in this tree), giving one call site and a clean home for the privileged-recreate
path the KVM box needs.

#### C4 — dead `#[cfg(target_os="macos")]` guards on `probes::host_pipe_io` — **[incidental, delete]**
`dispatch/mod.rs:961,4552,4751` gate a call that is already defined unconditionally
and no-ops where the USDT provider is a stub — leftover from pre-unification. The
guards also mean the probe never fires on FreeBSD (which *does* fire real USDT). Pure
subtraction.

#### C5 — dual selection axes: `platform-*` feature vs raw `cfg(target_os)` — **[over-broad, under-specified]**
The host backend is selected on **two parallel axes** kept consistent only by
convention; nothing enforces `platform-linux ⇔ target_os=linux`. `vcpu_loop` already
mixes `feature=platform-linux` with `target_arch` to disambiguate engines, and
`lib.rs` uses both spellings for the same intent. → assert the invariant in
`build.rs`; pick one canonical axis per question (feature = "which VMM/EventMultiplexer
is linked"; `target_os`/`carrick_bsd` = "which libc ABI shape").

### 2.4 Extensibility seams (add a VMM / arch / host)

- **Add an arch (e.g. riscv64): essentially no shotgun.** Implement `GuestArch` +
  `PageTableCodec` + `SyscallTable` + an abi syscall table. The dispatch layer does
  not leak (`vcpu_loop` is generic over `E::Arch`, zero arch match-arms). This is the
  best-factored axis. (Nit: `x8664_arch.rs` is 2135 lines inside a traits-only crate;
  a 3rd ISA of that size argues for per-ISA leaf crates — cosmetic, not a leak.)
- **Add a VMM: ~70% one impl behind `X86Vmm`, ~30% mechanical copy-paste that should
  be deleted** — a 4th copy each of the loop wrapper, run-elf dispatch, and the
  xsig/pump/backend/kicker forwarder files. The manifest cost is the *legitimate* part
  (2-3 well-localized `platform-*` lines).
- **Add a host (e.g. OpenBSD/vmm): mostly "implement `HostBackend`"** — the fork
  coordinator, signal pump, xsig ring, and posix-timer thread are already
  host-agnostic; only errno/signum tables and itimer arming are genuinely per-host.

**The one structural divergence gating "cheap new backend" is F3** (`run_threaded_hvf_loop`):
adding `make_signal_arrival()` to `HostBackend` unifies all four backends on one loop
and makes every future VMM/host strictly cheaper.

### 2.5 The completeness critic's extra catch — CORRECTNESS

**`/proc/cpuinfo` hardcodes ARM64 for every guest** (`vfs/proc.rs:1604`,
`synthetic_proc_cpuinfo`) — emits `CPU architecture: 8`, ARM features, `CPU implementer
0x61` regardless of guest ISA. Yet `uname(2)` (same conceptual data) **correctly
branches** on guest arch (`dispatch/proc.rs:1551`). So an x86_64 guest (KVM, bhyve,
NVMM, or Rosetta-on-macOS) sees `uname=x86_64` but `/proc/cpuinfo=ARM` — an internally
contradictory machine that diverges from Docker for anything parsing cpuinfo (lscpu,
language runtimes). Incidental: cpuinfo was never wired to the guest-arch signal uname
already uses. → a single guest-arch accessor (mirroring `guest_hostname()`) feeding
uname + cpuinfo + future arch-dependent synthetic files. (Also minor: `vfs/sys.rs`
`net_interfaces` is macOS-only → `/sys/class/net` empty off-macOS.)

---

## 3. Load-bearing splits — explicitly NOT to unify

Collapsing any of these would be a worse error than the duplication:

| Split | Why essential |
|---|---|
| Futex raw syscall (`os_sync`/`_umtx_op`/`SYS_futex`/`__futex`) + HVF sched_yield wake | macOS has no `futex(2)`; physical-vs-mm keying differs; macOS reports spurious wakes on SHARED addresses |
| `ForkRamStrategy::{Cow,EagerCopy}` | bhyve fundamentally can't COW kernel-owned guest sysmem (OBJT_SWAP no-shadow); NVMM HVA writes race host COW; KVM/HVF get COW from the OS/Mach |
| `MsrInstall::NeedsRing0Blob` (bhyve) | FreeBSD 15.1 libvmmapi has no MSR ioctl — must WRMSR via a ring-0 blob + iretq |
| `get_fp()==None` (bhyve) | no FP getter → must drive a ring-3 FXSAVE stub |
| HVF trap-based mechanism / EL1 vector | public arm64 HVF has no stage-2 TLBI; the EL1 trampoline is the only place for stage-1 maintenance |
| aarch64 stage-2 incoherence machinery in `page_table.rs` (break-before-make, spare-table reclaim, multi-vcpu coalesce) | no host-driven stage-2 TLB flush on arm64 HVF; x86 gets hardware-coherent shootdown |
| kqueue vs epoll behind `EventMultiplexer` | kqueue is a unified multi-filter object; epoll needs satellite fds (eventfd/timerfd/inotify/pidfd) + software EPOLLET. **The reference seam — the model the other concerns should follow.** |
| Per-ISA struct layouts (`stat`, `epoll_event`), syscall numbering, register frames, sigframes | fixed by the two ISAs/kernel ABIs |
| BSD `SIGNUM_XLATE` table vs Linux identity | host kernel signal numbering genuinely differs (BSD `EUSR1=30` would land as Linux SIGBUS) |
| Descriptor bit layouts (ARM AP/UXN/PXN vs x86 P/RW/US/NX, US-at-every-level) | ARM ARM vs Intel SDM — clean-room rule the project enforces |
| Per-VMM `X86Vmm`/`X86Vcpu` register marshalling (`RegLoc`/`VM_REG_GUEST_*`/kvm offsets) | irreducible per-hypervisor ABI tables |
| `platform-*` feature wiring (2-3 manifests) | mutually-exclusive host targets; Cargo has no better mechanism — the correct minimal cost |
| `carrick-portable`'s 47 OS gates | the single libc-symbol seam, by design (function/const seam, not a trait) |

---

## 4. Prioritized refactors (highest leverage first)

Ordered by the rubric: **correctness → robustness → durability → leverage.**

### P0 — Correctness (active or near-active bugs)
1. **Route bhyve fault decode through `carrick_x86::fault_exit_from_record`** (F1).
   Restores the dropped ring-0 guard; single-sources the vector→kind tables;
   deletes ~55 lines. *Active behavioral divergence.*
2. **Single guest-arch accessor feeding `uname` + `/proc/cpuinfo`; emit an x86
   cpuinfo block for x86 guests** (§2.5). *Active conformance bug on every x86 backend.*
3. **Make `SyscallRequest::from_raw` take the `LinuxGuestAbi`** (carry it on
   `RawSyscall`) so no call site can forget `.with_guest_abi()` — the x86
   no-threads loop (`lib.rs:411`) currently hardcodes aarch64, mis-marshalling
   epoll/struct layouts on the `CARRICK_NO_THREADS` x86 path (`dispatch-neutrality`).
   *Latent ABI corruption masked by the threaded path.*
4. **Move the POSIX firing thread into `carrick-timer-core`; wire bhyve
   `arm_posix`/`disarm_itimer`** (F2). Fixes CLOCK_PROCESS_CPUTIME_ID firing on
   wall-clock everywhere and the bhyve silent-no-op + state leak.

### P1 — Durability seams (structural, highest long-term leverage)
5. **Introduce `Aarch64EngineCore<V>` + `Aarch64Exit`** mirroring the proven
   `X86EngineCore` (F7). Unifies the two aarch64 trap-loop shells; the next aarch64
   backend gets the loop for free. Start with the zero-risk slice: hoist the
   `guest_cpu` timing wrapper (3→1) + shared `TrapError::el0_fault`.
6. **Add `make_signal_arrival()` to `HostBackend`; delete `run_threaded_hvf_loop`**
   (F3). All four backends enter through one loop — the single change that makes new
   VMMs/hosts cheap.
7. **Fold HVF onto the shared seams it bypasses**: `HvfFutex` → `FutexTableFutex<HvfSharedFutex>`
   (F5); HVF disposition → `host_glue` with an `is_synchronous_self_fault` provided
   method (F4); HVF posix timer → timer-core (F2). Each is "give the one load-bearing
   bit a hook, fold the rest."
8. **Lift the `HostForkCoordinator` state machine into `PumpForkCoordinator<P>`** (F8).
   Closes an already-diverged fork/pump handshake.

### P2 — Subtraction (zero/low-risk dead code & scaffolding)
9. **Delete the vestigial forwarders**: 9 `*_signal_pump.rs`/`*_xsig.rs` files, the
   dead `CrossProcessFutex`/`BsdFutex` twin, the dead `VcpuKick::target_in_guest`/
   `raw_vcpu_id` surface + always-`None` `Option<Arc<AtomicBool>>` fields, the
   `host_pipe_io` macOS cfg guards (C4); fix the stale comments
   (`lib.rs:1735/1753/1761`, `signum.rs:18-19`).
10. **Migrate bhyve `guest_setup_x86` onto `carrick-x86` bringup/fault helpers** (F6).
    NVMM proves it works on a non-KVM VMM; removes a parallel ~2000-line x86 bring-up
    and the byte-identical `fp_stub_bytes` kept in sync by a single test.
11. **`run_elf_with_engine` generic + drop `run_threaded_X_loop` wrappers + retire
    per-VMM mains** (F9, F10).

### P3 — Type-level & cfg-as-trait hygiene
12. **Split `carrick_hal::Reg` into a per-ISA associated `Reg` type** (T1) — kills
    `reg_to_x86()` + the `unreachable!()` arms. Rename bhyve `X86Exit` → `BhyveVmExit`
    (T2).
13. **Extend `PageTableCodec` with the edit contract** (`set_prot_none`/`set_rw`/
    `map_aliased`/`translate`) so `mprotect`/`mmap`/`munmap` bring up once across
    ISAs; factor the shared 4-level-walk skeleton (the "2 MiB-bulk + 4 KiB-tail"
    table-exhaustion fix currently lives twice). Keep descriptor bits and the arm
    stage-2-incoherence extras per-ISA (memory-model).
14. **cfg-as-trait conversions**: `proctitle.rs` → `HostProcTitle` (C1);
    `load_execve_image` → engine method + rename `macos_helper_stubs` (C2);
    `fs_backend`/`layer_cache` COW → `ScratchSeeder` (C3).
15. **Collapse the two syscall NUMBER tables into one name-keyed registry** that
    generates both arch tables (arch-abi). Makes "no x86 number reaches the dispatcher
    unremapped" a *structural* invariant instead of per-entry vigilance (the
    `uname(63)→read(63)` collision class), and adds a syscall in one row for all arches.

### P4 — Robustness guards
16. `compile_error!` for exactly-one-platform; assert `platform-* ⇔ target_os` in
    build.rs (C5).
17. Shared helpers for the last-10% duplications: bare-exit-code normalization in hal
    (event-mux), `install_kick_noop_handler(signum)`, a `bsd_is_claimed` default
    method, the `host_backend!` declarative macro.

---

## 5. Senior-engineer read

Is the architecture honest about its boundaries? **Yes** — the splits that matter
(privilege model, ISA, VMM ABI, COW mechanism) are real and the project clearly knows
which is which; the `X86Vmm` enum-return quarantine and the `EventMultiplexer` neutral
types are exactly how Oxide/Joyent-grade systems isolate irreducible difference. Are
the abstractions load-bearing or decorative? **Overwhelmingly load-bearing** — the rare
decorative one is `carrick_hal::Reg` (a "compile-error safety" claim the type system
doesn't actually deliver). Do the type boundaries fall where the real differences are?
**Mostly yes**, with the aarch64 side one factoring behind the x86 side.

Where will this calcify? **The aarch64/HVF lane and the migration scaffolding.** Every
time the x86 lane gets a shared mechanism, HVF either gets a hand-written twin (because
one load-bearing difference wasn't given a hook) or is left behind, and the forwarder
files from the cfg-flip migrations accumulate. The incidental-complexity tax is concrete
and measurable: a fix to the cross-process-signal policy, the fork/pump handshake, the
trap-loop kick guard, or a page-table edit must today be applied in two-to-four places,
and the codebase has *already* paid that tax (the diverged error-path restart, the SIGINT
skip-set disagreement, the bhyve dropped ring-0 guard). The good news is the cure is
cheap and mostly subtractive: the seams to plug HVF and the missing `Aarch64EngineCore`
into already exist on the x86 side as a working template. Do P0 now (real bugs), then
P1 (the `Aarch64EngineCore` + `make_signal_arrival` seams) before the 5th backend or
the x86-on-each-host matrix lands — after that, P2's deletions fall out almost for free.

---

## 6. Implementation status (2026-06-20)

Work landed on branch `audit/structural-leverage`. Verification is from a single
macOS host via `scripts/xcheck.sh` (macОS native build + `cargo check` of each
backend crate for its target triple: aarch64/x86 Linux, FreeBSD, NetBSD). The
full `carrick-cli` cannot be cross-compiled (it pulls `ring` via the OCI puller,
whose build script needs a C cross-toolchain), so cross-targets check the backend
crates — which is also why this pass is scoped to compile-checking; HVF/KVM/bhyve
*runtime* behavior is not exercised here.

### Done (committed, compile-verified on the noted targets)

- **F1 / P0.1 — bhyve ring-0 fault guard restored.** bhyve now builds a neutral
  `FaultDoorbellRecord` and calls `carrick_x86::fault_exit_from_record` like
  KVM/NVMM, restoring the dropped ring-0 guard and single-sourcing the vector→kind
  tables. *(freebsd)*
- **§2.5 / P0.2 — guest-arch accessor.** `ProcState::reported_arch()` feeds both
  `uname(2)` and `/proc/cpuinfo`; x86 guests get a real x86_64 cpuinfo block.
  `/sys/class/net` gets a synthetic loopback off-macOS. *(macos + all)*
- **P0.3 — `RawSyscall` carries `LinuxGuestAbi`.** Stamped by each backend's
  `GuestArch` at decode time; `SyscallRequest::from_raw` reads it, so the
  type-erased no-threads / combined-Linux loops can no longer mis-marshal the x86
  path. *(macos + linux-x86 + freebsd + netbsd)*
- **F2 / P0.4 — POSIX timer firing thread → `timer-core::posix::run_fallback`.**
  De-duplicated 4× → 1; now branches on the clock so `CLOCK_PROCESS_CPUTIME_ID`
  fires off aggregate guest CPU (not wall-clock). bhyve's silent-no-op
  `arm_posix` and state-leaking `disarm_itimer`/`current_arm` are wired to match
  KVM. *(macos + linux-x86 + freebsd + netbsd; the runtime/lib.rs Linux copy is
  changed to match but is ring-blocked from cross-check)*
- **T2 — bhyve `X86Exit` → `BhyveVmExit`.** Kills the false "two X86Exit enums"
  shadow of `carrick_x86::X86Exit`. *(freebsd)*
- **C4 — deleted the dead `#[cfg(target_os="macos")]` guards on
  `probes::host_pipe_io`** (defined unconditionally; the guard wrongly suppressed
  the real FreeBSD USDT probe). *(macos)*
- **C5 / P4.16 — exactly-one-platform enforced.** `compile_error!` in the CLI for
  zero/multiple `platform-*`; a `build.rs` asserts `platform-* ⇔ target_os`.
- **Pre-existing fix (fix-forward):** arch-split `kvm::append_vcpu_state` — it
  called x86-only `VcpuFd::get_regs/get_sregs` unconditionally, so the aarch64
  KVM lane did not compile.
- **Compile-time:** dropped `clap` from `carrick-observability` (one `ValueEnum`
  derive → hand-written `FromStr`/`Display`), removing the heavy clap proc-macro
  from every backend's compile closure (they pulled it only via observability).

### Deferred, with rationale (NOT silently skipped)

These are the large structural seams. Each is either **unverifiable in this
environment** (HVF runtime behavior, or `carrick-runtime` Linux-cfg code that is
ring-blocked from cross-compile) or carries **mechanism risk** the audit itself
flags — so landing them blind, compile-check-only, would be the wrong trade. They
are sequenced for a follow-up with the right test rig (HVF host + KVM/bhyve VMs):

- **F3 — `make_signal_arrival()` on `HostBackend` + delete `run_threaded_hvf_loop`.**
  The seam is additive and safe, but migrating HVF onto the shared loop changes
  the macOS signal-arrival path (kqueue pump), which only manifests at runtime and
  cannot be exercised here. The shared-loop body is also `cfg(platform-linux/
  freebsd/netbsd)`-only in `carrick-runtime` (ring-blocked from cross-check).
- **F4 / F5 / F8 — fold HVF onto `host_glue` / `FutexTableFutex<HvfSharedFutex>` /
  `PumpForkCoordinator<P>`.** All three change the hardest-to-test macOS backend's
  signal-disposition / futex / fork-pump handshake — the exact class of change
  (lost-wake, interruptibility) that a compile check cannot catch and that
  Linux/FreeBSD CI would miss.
- **F7 — `Aarch64EngineCore<V>` + `Aarch64Exit`.** Touches both aarch64 trap-loop
  shells (HVF + KVM). The zero-risk slices (hoist the `guest_cpu` run-timing
  wrapper 3→1, add a shared `TrapError::el0_fault` constructor) are safe and
  verifiable and are the recommended first step.
- **F6 — migrate bhyve `guest_setup_x86` onto carrick-x86 bringup/fault helpers.**
  Verifiable (freebsd) and high value (the byte-identical `fp_stub_bytes` kept in
  sync only by a unit test); the SYSCALL-enable blob and FP/XSAVE stub MUST stay
  bit-compatible for fork/clone, with no compiler enforcement — wants the bhyve
  fork/clone runtime gate to confirm, not just a typecheck.
- **F9 / F10 — `run_elf_with_engine` generic + drop `run_threaded_X_loop`
  wrappers + retire per-VMM mains.** The cheap slice (hoist `load_x86_elf_image`
  into carrick-x86) is verifiable and worth doing next.
- **T1 — split `carrick_hal::Reg` into a per-ISA associated `Reg` type.** Removes
  `reg_to_x86()` + the `unreachable!()` arms; large and touches hal/x86/kvm —
  verifiable but wants its own focused change.
- **C1 / C2 / C3 — cfg-as-trait conversions** (`proctitle` → `HostProcTitle`;
  `load_execve_image` → engine method + rename the misnamed `macos_helper_stubs`;
  `fs_backend`/`layer_cache` COW → `ScratchSeeder`). Mechanical but broad; C2's
  module rename is a cheap standalone win.
- **P3.13 / P3.15 — `PageTableCodec` edit contract; one name-keyed syscall-number
  registry.** Both large; P3.13 carries memory-model risk (the arm stage-2
  incoherence extras must stay per-ISA).
- **Dead-forwarder deletion (part of P2.9).** The `*_signal_pump.rs` / `*_xsig.rs`
  files are thin per-backend instantiations of the shared generics, not pure dead
  code — deleting them needs call-site migration, so it is a refactor, not the
  "pure subtraction" the heading implies.
