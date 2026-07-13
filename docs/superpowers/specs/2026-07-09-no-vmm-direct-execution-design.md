# No-VMM direct execution design

Date: 2026-07-09

## Summary

Carrick should explore a trusted-code, same-ISA Darwin-native execution backend
that preserves the central invariant: one Linux process is one macOS process.
This backend runs Linux AArch64 user instructions directly on Apple Silicon,
without Hypervisor.framework, and keeps Carrick's Rust dispatcher as the Linux
syscall authority.

The intended shape is a new Darwin execution backend that plugs into the same
runtime/HAL contract as HVF, KVM, bhyve, and NVMM at the `SyscallTrap`,
`ThreadedEngine`, and `GuestMemory` boundary. It should not be modeled as a raw
`HvVm`/`HvVcpu` backend because it has no VM object, no guest EL1, and no vCPU
run ioctl. It is "backend-shaped" for runtime selection and code sharing, not a
VMM.

The recommended first implementation is:

```text
carrick-cli / carrick-runtime
  -> RuntimePlatform: macos-native
  -> carrick-exec-darwin
  -> NativeDarwinEngine: SyscallTrap + ThreadedEngine + GuestMemory
  -> Darwin host primitives and carrick-kernel arena
```

HVF remains the release-quality reference lane. Native Darwin starts as an
experimental, opt-in performance lane for trusted Linux/AArch64 programs.

## Why this exists

The current macOS/HVF path uses one host process per Linux process, but each
process also owns materialized HVF state. Recent architecture work already made
VMM residency a lease rather than identity, but the remaining fork and
fork-heavy workload cost is still tied to creating, destroying, and replaying
HVF process state.

A native Darwin backend asks a more radical question: if the host CPU already
has the same ISA as the guest user binary, can Carrick remove the VMM from the
execution path while keeping the part of Carrick that matters most - host-native
process identity and the Linux syscall translation layer?

The answer is plausibly yes for a constrained first lane:

- host macOS on Apple Silicon;
- guest `linux/arm64`;
- trusted guest code only;
- no promise of a hardened guest/host isolation boundary;
- strict feasibility probes before any default path is touched.

## Goals

- Preserve one Linux process equals one macOS process.
- Preserve host-native `fork(2)`, `wait4(2)`, host scheduling, host-visible PIDs,
  and normal macOS process tooling.
- Remove HVF VM/vCPU materialization from the hot execution and fork paths.
- Reuse the existing Carrick runtime dispatcher, VFS, signal, process, namespace,
  futex, and `carrick-kernel` arena work.
- Keep the integration point backend-shaped: the runtime drives an engine through
  `SyscallTrap`, `ThreadedEngine`, and `GuestMemory`.
- Make host ABI collisions and page-size limits explicit decision gates.
- Keep HVF as the correctness oracle lane for Carrick-internal regressions.

## Non-goals

- Do not run untrusted code in this mode. Without a VMM, the guest shares the
  host address space with Carrick's runtime and is not isolated from it.
- Do not support cross-ISA execution in the first design. `linux/amd64` remains
  Rosetta/HVF or future DBT territory.
- Do not forward Linux syscalls to the Darwin kernel. Linux syscalls still enter
  Carrick's dispatcher.
- Do not build a userspace kernel daemon or hot-path RPC monitor.
- Do not make this the default macOS backend until the feasibility gates pass.
- Do not force the implementation through `HvVm`, `HvVcpu`, or hypervisor exit
  enums. Those traits describe raw VMM objects that do not exist here.

## Answer to "is this another VMM backend?"

Implementation should follow a backend pattern, but one level above the raw VMM
adapter layer.

The useful precedent is not `HvfVm` or `KvmVcpu`; it is the runtime contract that
all engines satisfy:

- `SyscallTrap` runs guest execution until a Linux syscall or guest fault is
  available to the runtime.
- `GuestMemory` lets the dispatcher read and write guest pointers.
- `ThreadedEngine` lets the generic threaded loop spawn guest threads, inject
  signals, fork, exec, and coordinate blocking waits.
- `HostBackend` supplies host futex, fork coordination, signal arrival, timer,
  and pre-loop setup primitives.

Native Darwin should therefore add a peer execution backend, tentatively
`carrick-exec-darwin`, rather than a crate named `carrick-vmm-native`. Runtime
selection can still look like other backends:

```text
platform-macos + exec-hvf       -> carrick-vmm-hvf
platform-macos + exec-native    -> carrick-exec-darwin
platform-linux                  -> carrick-vmm-kvm
platform-freebsd                -> carrick-vmm-bhyve
platform-netbsd                 -> carrick-vmm-nvmm
```

The CLI flag should be explicit, for example:

```text
CARRICK_EXEC_BACKEND=native
carrick run --exec-backend native ...
```

The build feature should remain opt-in until the lane is proved:

```text
platform-macos-native
```

or, if feature explosion becomes awkward:

```text
platform-macos + native-exec
```

The important rule is that `platform-macos` must not silently switch away from
HVF.

## Core design

### Execution model

The native engine maps a Linux ELF image into the host process at the guest
virtual addresses the Linux program expects, then transfers control to the
guest entry point on the same host thread.

When guest code reaches a Linux syscall instruction, it must not fall through to
Darwin. The engine rewrites guest syscall sites to a Carrick gateway. The gateway
captures the Linux register frame, returns control to the Rust run loop, and
lets the existing dispatcher produce the Linux return value.

The run-loop shape remains:

```text
next_syscall() -> RawSyscall
dispatch RawSyscall through SyscallDispatcher
complete_syscall(retval)
next_syscall() resumes native guest code
```

The difference is only the vehicle:

```text
HVF:    guest svc -> EL1 vector -> hvc -> hv_vcpu_run returns
Native: guest patched svc site -> Carrick gateway -> host loop resumes
```

### Syscall interception

The first backend should support two syscall vehicles.

#### Vehicle A: `brk`/signal prototype

For bring-up, patch each `svc #0` to a distinguished `brk` instruction. A
`SA_SIGINFO` signal handler recognizes the breakpoint while the thread is in
guest mode, copies the ucontext register state into the native engine's saved
frame, and returns to the host loop.

This is not the final hot path. It is the smallest end-to-end proof that:

- Linux ELF code can execute directly in the host process;
- `svc` sites can be found and patched;
- ucontext exposes the register state Carrick needs;
- the existing dispatcher can complete a syscall and resume guest code;
- host faults outside guest mode still crash normally instead of being swallowed.

#### Vehicle B: branch-to-gateway fast path

The production vehicle patches each `svc #0` to an AArch64 branch to a nearby
gateway island. The island saves all guest-visible register state, restores the
host ABI context needed to call Rust, and returns to the run loop.

A direct branch is preferable to a signal on every syscall, but it has range and
code-layout constraints:

- AArch64 unconditional branch reaches only a bounded PC-relative range, so the
  engine must place gateway islands close enough to every executable segment.
- If a branch island cannot be placed near a site, the site falls back to the
  `brk` vehicle and the run is marked as using a slow path.
- The gateway must preserve Linux argument registers `x0..x5`, syscall register
  `x8`, return PC, guest SP, guest TLS state, FP/SIMD state as required, and any
  Darwin-reserved register state before calling host Rust.

The spec intentionally does not assume one gateway per process is sufficient.
The engine should plan for per-region or per-128-MiB gateway islands.

### Syscall-site discovery and patching

Phase 1 may patch loaded executable bytes by scanning executable ELF segments
for the AArch64 Linux `svc #0` encoding. That is acceptable only as a bring-up
strategy.

The durable patcher must be tied to executable mappings:

- patch the main ELF and `PT_INTERP` before first entry;
- patch executable file mappings produced by `mmap`;
- patch pages that become executable through `mprotect(PROT_EXEC)`;
- patch the Carrick-provided vDSO and any syscall fallback path it contains;
- keep a per-page patch manifest recording original instruction, patch vehicle,
  patched PC, resume PC, and code generation.

Self-modifying code and JIT-produced code are not phase-1 goals. The honest
phase-1 policy is:

- executable pages are patched before execution;
- writes to executable pages are denied or force the page back through the patch
  pipeline before it can execute again;
- if the engine cannot enforce that policy on macOS with acceptable overhead, it
  must fail the run rather than allow a Linux `svc #0` to reach Darwin.

### Guest memory

Native Darwin needs a new `GuestMemory` implementation over real host mappings.
Unlike HVF, there is no guest physical memory hidden behind a VM. In Direct
mode, a guest virtual address is the host virtual address. In Biased mode, host
mappings are reached through `NativeHostBias`, while every guest-visible
coordinate remains the Linux guest virtual address.

#### Darwin low-address boundary

On arm64, XNU requires every 64-bit Mach-O process to carry a 4 GiB
`__PAGEZERO`; the loader rejects a smaller segment with `LOAD_BADMACHO`. This is
also a hard minimum mapping offset: deallocating part of `__PAGEZERO` does not
make a later low fixed mapping available. For PIE outputs, current `ld64` also
ignores `-image_base`, so linker placement cannot move Carrick itself out of the
way while retaining a valid arm64 process image.

The native backend must therefore distinguish two address modes:

- PIE/`ET_DYN` Linux images whose layouts are available use direct mode, where
  host and guest addresses are identical;
- fixed Linux `ET_EXEC` images with a required segment below 4 GiB cannot be
  directly mapped and use biased DSR, where the complete image has one
  collision-selected high host bias;
- an image that cannot fit in either mode fails with a typed diagnostic.

Changing the native page profile does not solve the address-space collision.
DSR solves it without rebasing the Linux architecture: PC, SP, LR, branch
targets, register-held pointers, fault addresses, signal-frame pointers, auxv,
`/proc` mappings, and diagnostics remain in guest coordinates. Only
instruction fetches and host memory accesses add the bias. The audited biased
lowerings cover scalar, pair, SIMD, atomic, exclusive, and literal memory
families; every unsupported or ambiguous memory form fails closed through a
typed error. Direct mode retains its byte-identical memory-emission fast path.

Measured closeout (2026-07-13): the signed native16k binary runs the low static
`devnullseek` `ET_EXEC` fixture to exit zero with both expected markers. A
signed static fork witness proves a parent function PC and static pointer below
4 GiB, identical child guest values, retained static data, and a zero child
exit. These are correctness results only. The isolated `altstacktid` workload
still times out, and the earlier 331/378 comparison campaign crossed a
post-fork lifecycle defect, so neither is valid performance authority and no
projected probe count is recorded here.

References:

- XNU arm64 Mach-O page-zero validation:
  https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_loader.c#L3700-L3760
- Xcode 13 linker note for PIE image bases:
  https://developer.apple.com/documentation/xcode-release-notes/xcode-13-release-notes

The engine should reuse:

- Carrick's ELF loader and initial stack construction;
- `MemoryProtections` for syscall-buffer `EFAULT` checks;
- `GuestMemoryRegion` and `safe_guest_access` style region checks where the
  native region model is flat enough;
- existing dispatcher memory outcomes such as `MapHostAlias`, `protect_range`,
  and `unmap_range`, adapted to host `mmap`, `mprotect`, and `munmap`.

However, native execution has a hard page-size question. HVF gives Carrick a
4-KiB guest page-table world even when macOS uses larger host pages. Native
Darwin can only enforce host page protections at the host kernel's page
granularity.

The design gate is:

- either native mode presents the host page size as the guest Linux page size
  and accepts that this lane is a host-page-shaped Linux personality;
- or it proves that Carrick can preserve 4-KiB Linux-visible `mmap`,
  `mprotect`, `munmap`, guard-page, and fault semantics on macOS without a VMM;
- otherwise the native backend is useful only for page-size-neutral smoke and
  performance probes, not for conformance.

The first path is the realistic one for an MVP. It requires making page size an
execution-backend property instead of relying on a single global Linux page-size
constant in every path.

### Host ABI context switch

Direct execution shares a thread with host Rust code. That makes the host/guest
register boundary load-bearing.

The native gateway must treat the transition like a userspace CPU context
switch, not a normal function call:

- save all guest general-purpose registers;
- save guest PC and SP;
- save/restore Darwin-reserved register state such as the platform register;
- save/restore host TLS registers before calling Rust;
- preserve or lazily save FP/SIMD state according to measured ABI needs;
- maintain host stack alignment before entering Rust;
- prevent guest values from leaking into host unwinding or panic paths.

This is a feasibility gate, not an implementation detail. If a Linux program's
TLS use collides with Darwin's thread-local ABI and Carrick cannot reliably
swap the relevant state on every guest/host crossing, the direct backend cannot
run real libc workloads.

### Faults and Linux signals

Without a VMM, guest memory faults arrive as host synchronous signals. The
native backend installs `SA_SIGINFO` handlers for the fault classes Carrick
already maps to Linux signals:

- `SIGSEGV`;
- `SIGBUS`;
- `SIGILL`;
- `SIGTRAP`;
- `SIGFPE`;
- `SIGSYS`, if Darwin uses it for a leaked syscall or bad system call shape.

Handlers must discriminate by thread state:

```text
InHost  -> chain to previous handler or terminate as a host bug
InGuest -> capture ucontext and report a guest fault to the runtime
InGate  -> treat as a Carrick backend bug unless explicitly expected
```

Guest faults are lowered to the same Linux signal model the current vCPU loop
uses: Linux signal number, `si_code`, fault address, default action, handler
injection, alt-stack handling, and `rt_sigreturn`.

Signal injection can reuse Carrick's existing logical model, but the mechanics
change. Instead of writing a frame into guest memory and programming vCPU
registers, `NativeDarwinEngine::inject_signal` writes the Linux sigframe and
updates the saved native guest register frame before the next resume.

### Fork

Native fork is the primary payoff.

The parent reaches the existing Carrick fork safe point, prepares arena process
records as today, and calls real `libc::fork`. Because there is no live HVF VM,
there is no parent VM teardown, no child VM rebuild, no stage-2 replay, no vCPU
permit, and no `HV_BUSY` shape.

After fork:

- the child inherits guest mappings through host COW;
- patched executable pages remain patched;
- the child resets host-only runtime state that is not fork-safe;
- the child publishes its process record liveness;
- the child resumes guest execution with `fork() == 0`;
- the parent completes the syscall with the child's Linux PID.

This should move fork cost toward host `fork()+waitpid()` cost. The first
performance gate should be stricter than the HVF lazy-replay target:

```text
native perf_fork p50 <= 2x host-Darwin fork p50
native perf_fork p95 <= 3x host-Darwin fork p95
```

If native fork cannot stay close to host fork, the backend does not justify its
complexity.

### Clone threads

`clone(CLONE_VM)` creates a host pthread and starts it at a saved native guest
context. There is no vCPU slot and no HVF concurrent-vCPU ceiling.

The hard parts are:

- Linux TLS setup versus Darwin TLS state;
- guest stack ownership and guard behavior;
- host signal delivery while a thread is in guest code;
- clean transition back to host Rust on syscall, fault, exit, and cancellation;
- preserving Carrick's `ThreadRegistry`, futex, signal, and `/proc/task`
  semantics.

The existing `ThreadedEngine` shape should be retained, but many methods become
no-ops or pure saved-context operations:

- `vcpu_budget() == usize::MAX`;
- `reclaims() == false`;
- no vCPU slot wait;
- no VM release/rebind;
- `build_sibling_spec` stores a native register/TLS/stack start state;
- `materialize_sibling` starts a native guest thread.

### Exec

`execve` keeps the host PID, as today. The native engine:

1. unmaps the old guest mappings and gateway islands;
2. resets patch manifests, memory protections, vDSO/vvar state, and guest TLS;
3. loads the new ELF and interpreter through the existing rootfs/VFS path;
4. maps executable/data/stack regions into the host address space;
5. patches executable syscall sites;
6. installs a fresh saved entry context;
7. resumes at the new Linux entry point without returning to the old image.

Late lease releases and arena process generation checks remain relevant even
though there is no VM lease. Exec generation still protects cross-process state
from stale pre-exec operations.

### Blocking syscalls and futexes

There is no vCPU to reclaim. A native guest thread that blocks in Carrick's host
wait path simply blocks as a host thread.

The existing dispatcher outcomes still apply:

- `WaitOnFds`;
- `WaitOnPollFds`;
- `WaitOnSleep`;
- `WaitOnSignals`;
- `FutexWait`;
- `SharedFutexWait`;
- `BlockingHostWrite`;
- `BlockingRecordLock`.

This should simplify the backend: no `shared_wait_park`, no whole-VM residency
lease, no `WakeFromBlockingSyscall` VM rebuild. Carrick still needs run-state
publication so `/proc` and wait-state diagnostics report Linux-visible `S` and
`R` accurately.

## Integration plan

### Crate and feature shape

Add a new crate:

```text
crates/carrick-exec-darwin
```

It owns:

- `NativeDarwinEngine`;
- fixed-address host mapping and unmapping;
- syscall patching and gateway islands;
- guest/host context switch assembly;
- signal/ucontext bridge;
- native sibling-thread materialization;
- native fork/exec glue.

It does not own:

- Linux syscall semantics;
- VFS/rootfs;
- Linux ABI constants;
- `carrick-kernel` arena sections;
- Docker/OCI lowering;
- raw hypervisor traits.

The initial runtime feature shape should make HVF the default:

```text
default = ["platform-macos"]
platform-macos = ["carrick-vmm-hvf", ...]
platform-macos-native = ["platform-macos", "carrick-exec-darwin"]
```

If Cargo feature unification makes that awkward, split execution backend choice
from platform selection:

```text
platform-macos
exec-hvf
exec-native
```

but keep `exec-hvf` as the default.

### Runtime selection

Introduce a small backend-selection layer instead of scattering cfg branches:

```rust
enum DarwinExecBackend {
    Hvf,
    Native,
}
```

`carrick run --exec-backend native` selects `NativeDarwinEngine` only when the
binary is built with the native feature. Without the feature, the CLI returns a
clear unsupported-backend error.

Longer term, this should converge with the previously identified
`RuntimePlatform` descriptor idea: backend selection should choose an engine
builder and a host backend, not duplicate OCI/run-loop code.

### Shared host backend

Darwin-native should consume a Darwin `HostBackend` implementation for:

- platform futex / `__ulock` or `os_sync_wait_on_address`;
- signal arrival;
- timer delivery;
- fork coordinator;
- pre-loop setup.

HVF has special signal-pump behavior today. Native Darwin should start with the
generic `HostBackend` shape where possible and only fork a native-specific host
mechanism after measurement proves the generic mechanism cannot express the
needed behavior.

### Relationship to `carrick-kernel`

Native Darwin keeps the arena strategy:

- process records;
- PID namespace membership;
- run-state publication;
- wait metadata;
- SysV and futex shared-object sections as they land;
- provider/resource cleanup state.

The arena becomes more important, not less, because no VMM object can be used
as an implicit process/thread lifecycle marker. Host PID plus arena generation
remains the cross-process identity contract.

## Phased delivery

### Phase 0: feasibility probes

Write small standalone probes before backend implementation:

1. Map Linux-shaped executable/data/stack regions at their expected addresses on
   macOS without colliding with dyld, stack, shared cache, or Carrick runtime
   mappings.
2. Allocate executable gateway islands under current code-signing constraints.
   Check `MAP_JIT`, `pthread_jit_write_protect_np`, and the required
   entitlements on the signed `carrick` binary.
3. Patch a tiny AArch64 function containing `svc #0` to `brk`, catch it with
   `SA_SIGINFO`, read registers, and resume after the instruction.
4. Patch the same function to a branch gateway and return to a host loop.
5. Save guest TLS/register state, restore host TLS/register state, call Rust,
   then resume guest code without corrupting either ABI.
6. Demonstrate a guest `SIGSEGV` fault can be distinguished from a host crash.
7. Measure host page size and prove the chosen page-size policy with mmap and
   mprotect probes.

If any of these fail, stop and record the blocker before adding backend code.

### Phase 1: static no-libc smoke

Run a hand-built static Linux/AArch64 ELF that performs:

- `write(1, "ok\n", 3)`;
- `getpid`;
- `exit(0)`;
- a handled null fault;
- a simple `fork()+waitpid()`;
- one private futex wait/wake if the minimal runtime path can supply it.

The first implementation may use the `brk` vehicle only.

### Phase 2: branch gateway and loader path

Add gateway islands and a real patch manifest. Run:

- static musl hello;
- dynamic loader plus `/bin/true`;
- basic shell command under an extracted rootfs;
- vDSO clock/gettimeofday smoke;
- basic `mmap`, `mprotect`, `munmap`, and guard-page checks under the selected
  native page-size policy.

### Phase 3: fork and exec workload proof

Make fork the first real value gate:

- `perf_fork`;
- `perf_fork_exec`;
- `cpython-multiprocessing_fork` if dynamic Python reaches phase-2 readiness;
- fork-heavy LTP rows that are currently dominated by HVF rebuild cost.

Acceptance is relative to host Darwin fork, not to HVF.

### Phase 4: threads and signal fidelity

Add `clone(CLONE_VM)` pthread materialization and real signal delivery:

- `pthread_create` smoke under guest libc;
- private futex pingpong;
- signal handler with alt-stack;
- `rt_sigreturn`;
- thread-directed signal;
- `go` or CPython thread smoke if phase 2 supports the dynamic runtime.

### Phase 5: conformance lane

Only after the above gates pass, add a separate conformance lane:

```text
--lane macos-native
```

The native lane gets its own baseline overlay. Its expected gaps must not be
merged into the HVF baseline.

## Validation gates

### Hard feasibility gates

- Fixed-address Linux ELF mapping succeeds on the supported macOS versions.
- Code-signing and executable-memory policy allow the required gateway strategy.
- Darwin and Linux thread-local ABI state can be swapped safely.
- Host page-size policy is explicit and tested.
- Host crash signals are not swallowed as guest faults.
- Unpatched Linux `svc #0` cannot reach Darwin in a supported run.

### Correctness gates

- Existing dispatcher unit tests remain backend-agnostic.
- Native `GuestMemory` follows the same `EFAULT` rules for syscall buffers under
  the selected page-size policy.
- Guest fault-to-Linux-signal tests match HVF for the supported fault classes.
- `fork`, `wait4`, `execve`, `clone`, `rt_sigaction`, and `rt_sigreturn` have
  focused probes before ecosystem runs.
- The native lane never changes the HVF baseline or support claims.

### Performance gates

- Native syscall gateway p50 is lower than HVF syscall p50 on a hot syscall
  microbench. The `brk` prototype does not need to pass this; the branch gateway
  does.
- Native `perf_fork` p50 is within 2x host Darwin fork p50.
- Native `perf_fork_exec` materially beats HVF after warm-up.
- Direct guest atomics/futex fast paths do not regress relative to HVF for
  thread-local synchronization.

### Safety gates

- Native mode prints or records a trusted-code warning in diagnostics.
- `carrick run --exec-backend native` refuses unsupported guest ISAs.
- Native mode has a kill switch and never auto-selects itself.
- Host-signal handlers chain or terminate correctly outside guest mode.

## Risks and blockers

### No isolation

This is the largest semantic difference from HVF. A guest store to an arbitrary
mapped host address can corrupt Carrick. Address-space layout makes that hard by
accident, not by guarantee. Native mode is therefore not a hardened trust
boundary and must remain trusted-code only.

### Host/guest TLS collision

Linux/AArch64 user code expects Linux TLS behavior. Darwin has its own thread
ABI and reserved state. The gateway and resume path must prove they can switch
between those worlds reliably. If not, real libc workloads are blocked.

### Host page size

macOS page granularity may not match the Linux page size Carrick currently
presents. This can affect `mmap`, `mprotect`, guard pages, `SIGSEGV`/`SIGBUS`
classification, and tests that assume 4-KiB pages. This must be resolved as an
explicit native-mode ABI choice.

### Signal ownership

HVF turns guest faults into engine results. Native Darwin shares host signal
delivery with Carrick itself. A bug in the discriminator can hide host crashes
or misreport guest faults. The handler must be minimal and mechanically tested.

### Syscall patch completeness

Every executable Linux syscall path must be patched before execution. Dynamic
code, self-modifying code, late executable mappings, and vDSO fallbacks all make
this harder than a one-time ELF scan.

### Debuggability

Native guest frames and host runtime frames share a process and thread. LLDB,
crash logs, unwinding, and sampling will need annotations or frame filters to
avoid confusing guest Linux frames with Carrick host frames.

## Decision

Proceed with a spec-backed exploration of a Darwin-native, no-VMM backend, but
sequence it as feasibility probes first. The backend should plug into Carrick
like a peer execution backend at the runtime contract boundary, not like a raw
hypervisor implementation.

The first high-information deliverable is not a full engine. It is a probe
bundle that proves or refutes the native gateway, ABI context switch, page-size
policy, and signal discriminator. If those pass, build `carrick-exec-darwin`
behind an opt-in backend flag and drive the existing dispatcher through
`SyscallTrap`.
