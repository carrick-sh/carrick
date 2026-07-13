# Native-default execution and VMM syscall mailbox design

**Date:** 2026-07-13

**Status:** implemented; mailbox rejected as production default by the frozen gate

**Scope:** container execution policy plus the macOS/HVF/AArch64 syscall boundary

## Purpose

Make Darwin-native DSR Carrick's ordinary execution model without retaining a
VMM-style process or vCPU ceiling. Keep virtual-machine execution as an
explicit, container-scoped compatibility option, named `vmm` rather than after
a particular host implementation. Reduce the cost of the remaining HVF syscall
path with a per-vCPU shared mailbox, and accept that fast path only after a
same-binary performance comparison derived from the historical DSR-versus-`brk`
gateway proof.

This design does not make DSR a speculative tier in front of HVF. A DSR gap is
a native-backend correctness or coverage problem, not an automatic request for
a scarce VM. A container chooses one execution model and keeps it for its
entire lifetime.

## Measured outcome

The execution-policy portion shipped as designed: native is the default and
`--exec-backend vmm` is explicit, portable, and container-immutable. The HVF
mailbox implementation passed its correctness gates and removed ordinary
register API traffic, but the clean full ABBA campaign measured a trap-floor
ratio of exactly `1.000 [1.000, 1.000]`, below the required 10% win. The
production VMM path therefore remains on the legacy register transport;
mailbox is retained only behind the private explicit diagnostic selector. See
[`docs/2026-07-13-hvf-syscall-mailbox-performance.md`](../../2026-07-13-hvf-syscall-mailbox-performance.md).

## Fixed decisions

- The public execution choices are `native` and `vmm`.
- Omitted `--exec-backend` means `native`.
- `auto` is removed.
- Platform-specific public values such as `hvf` are removed.
- `--exec-backend vmm` is always explicit. Carrick never selects it because of
  an image property, page profile, instruction, architecture, or runtime error.
- The selected backend is immutable for a container and is inherited by every
  process, `fork`, clone, and `execve` in that container.
- There is no live or `execve`-time transfer between native DSR and a VMM.
- Native DSR must not impose a VMM-style VM/vCPU admission ceiling. Ordinary
  host memory, process, thread, and descriptor resource limits still apply.
- A native DSR rejection is typed and actionable. It may suggest an explicit
  VMM invocation, but it does not retry under a VMM.
- The first mailbox implementation and performance decision target
  macOS/HVF/AArch64. Other VMM and ISA paths keep their current behavior until
  they have separate correctness and performance evidence.
- Linux/Docker remains the semantic oracle. No Linux kernel or other GPL
  implementation source is consulted.

## Execution policy

### Public vocabulary

`ExecBackendRequest` becomes a two-variant policy:

```rust
pub enum ExecBackendRequest {
    Native,
    Vmm,
}
```

`Native` is the default. The CLI, `CARRICK_EXEC_BACKEND`, engine requests,
`RunSpec`, lifecycle state, and persisted container configuration accept only
`native` and `vmm`.

The old `auto` and `hvf` CLI/environment values fail with migration guidance.
Old persisted container state containing those values is rejected as an
incompatible execution policy and tells the operator to recreate the
container. It is not silently reinterpreted, because doing so could acquire a
VM without an explicit current request.

### Platform routing

`vmm` names an execution model, not a concrete implementation. Platform
resolution selects the available implementation:

| Host | `--exec-backend vmm` implementation |
| --- | --- |
| macOS/AArch64 | HVF |
| Linux | KVM |
| FreeBSD | bhyve |
| NetBSD | NVMM |

An unavailable platform implementation returns a typed unsupported error. A
host without a native backend also returns a typed error when `native` is
selected or implied, directing the user to make the explicit
`--exec-backend vmm` choice.

Concrete VMM names remain valid internal diagnostics and capability labels.
They do not leak back into portable request or persisted-state vocabulary.

### Container lifetime

Backend policy is resolved before the container's first process starts and is
stored with the container configuration. Every descendant and every successful
`execve` continues on the selected backend. Native and VMM processes therefore
never share one container's process model, guest address space, or backend
lifecycle state.

This boundary keeps the consequences of HVF's measured VM/vCPU limits inside
containers whose operators explicitly requested them. It also avoids the
register, memory, signal, and fork-coherence problem of transferring a live
process between execution engines.

## Existing HVF syscall cost

The ordinary AArch64 HVF route is:

```text
guest EL0 svc
  -> carrick EL1 vector
  -> hvc #2
  -> hv_vcpu_run exit
  -> host register/sysreg reads
  -> dispatch
  -> host x0 write
  -> hvc return + eret
```

The current host decoder reads `ESR_EL1`, `ELR_EL1`, `x0..x5`, `x8`, FP, LR,
and `SP_EL0` on the ordinary syscall path, then writes `x0` on completion. Some
of those values feed always-available observability rather than dispatch, but
they still cross the Hypervisor.framework register API. The mailbox removes
those calls from the normal path without weakening the information carried to
the dispatcher or tracer.

The existing EL1 identity shim remains a distinct zero-exit optimization for
the small set of syscalls whose exact Linux-visible answer is already stored in
guest-local Carrick state. The mailbox handles syscalls that still require host
dispatch; it does not broaden the identity shim with approximate answers.

## Mailbox architecture

### Ownership and mapping

Each live AArch64 vCPU owns one mailbox slot in a Carrick-controlled region of
the guest kernel hole. The host retains a direct mapping of the same backing.
The slot is inaccessible to original guest EL0 code and is used only by
Carrick's EL1 vector and host VMM implementation.

`SP_EL1` points at the current vCPU's mailbox slot. Carrick's vector does not
use a guest kernel stack, so the slot can serve as the stable EL1 base without
borrowing a guest-visible GPR. The vector stores live registers before using
scratch registers and restores any scratch state before the HVC.

The mailbox handle belongs to the vCPU wrapper, not to the dispatcher. vCPU
creation, destruction, scheduler reclaim/rebind, fork reconstruction, and exec
reconstruction install a fresh generation before the vCPU can run. Mailbox
payload is never restored from an old vCPU snapshot.

The shared AArch64 mailbox layout and vector offsets live with the guest-memory
layout in `carrick-mem`, which is already below `carrick-aarch64` and the VMM
crates. Host-side accessors use typed domain values such as `NativeNr`,
`GuestVa`, and a dedicated mailbox generation/sequence type; raw integers do
not cross the protocol boundary without an explicit wire conversion.

### Wire protocol

The aligned fixed-size slot contains:

- protocol magic and version;
- vCPU ownership generation;
- monotonically advancing request sequence;
- request/response state;
- trap kind;
- response action;
- native syscall number;
- original `x0` and arguments `x0..x5`;
- guest resume PC from `ELR_EL1`;
- guest `SPSR_EL1`, FP, LR, and `SP_EL0` for restart and observability;
- underlying `ESR_EL1` and fault metadata when relevant;
- syscall return value;
- reserved zeroed space for versioned extension.

The initial states are `Idle`, `RequestReady`, and `ResponseReady`. The initial
response actions are:

- `NormalReturn`: EL1 loads the mailbox return value into `x0` and executes
  `eret`.
- `RegistersPrepared`: the host has used the existing slow path to prepare
  signal, restart, ptrace, or other exceptional register state; EL1 restores
  its own temporary scratch only and executes `eret` without overwriting the
  prepared guest registers.

The state word and generation are naturally aligned and accessed atomically.
EL1 writes the full payload, performs the required AArch64 ordering barrier,
and release-publishes `RequestReady` last. The host acquire-loads the state
after `hv_vcpu_run` exits and validates every authority field before consuming
the payload. Completion writes the response payload before release-publishing
`ResponseReady`; EL1 acquire-loads and validates it after the HVC returns.

The host does not poll the mailbox while a vCPU runs. The VMM exit remains the
notification mechanism, so the design adds no service thread, spin loop, or
fire-and-forget syscall semantics.

### Normal syscall flow

For a lower-EL synchronous exception, the vector first confirms
`ESR_EL1.EC == SVC64`. Existing guest-local identity calls may return at EL1 as
they do today. For every other syscall:

1. Save the complete dispatch/trace frame into the current slot.
2. Publish `RequestReady` with the current generation and next sequence.
3. Execute the existing `hvc #2` exit vehicle.
4. Let the HVF decoder validate the HVC and consume the mailbox frame directly
   from host memory.
5. Dispatch through the existing `SyscallDispatcher` and outcome machinery.
6. For an ordinary return, publish `NormalReturn` and the Linux return value.
7. Re-enter the vCPU. The vector validates the response, loads `x0`, resets the
   slot to `Idle`, and `eret`s to the instruction after `svc`.

No ordinary syscall-frame `hv_vcpu_get_reg`, `hv_vcpu_get_sys_reg`, or
`hv_vcpu_set_reg(x0)` operation is required. The vCPU remains the authority for
the full architectural register file; the mailbox is a validated transport
snapshot, not a second CPU state store.

### Slow and exceptional paths

Direct EL0 aborts, non-SVC lower-EL exceptions, maintenance HVCs, malformed
mailbox state, signal-frame construction, `rt_sigreturn`, ptrace/debug state,
and any outcome that needs arbitrary register mutation retain the existing
register/sysreg path initially.

When the host prepares exceptional register state while the vCPU is stopped in
the syscall vector, it publishes `RegistersPrepared`. The vector must not load
the ordinary return value over signal-handler arguments or restored state.

A kick during mailbox construction cannot expose a request because the state
is published last. A kick after publication follows the existing load-bearing
rule: Carrick finishes its EL1 vector/HVC boundary before reporting an EL0 guest
interruption. Fork, exec, and vCPU rebuild invalidate the previous generation,
so an inherited or stale response cannot resume a different execution
instance.

Any impossible transition, wrong generation, duplicate sequence, bad trap
kind, or unsupported response action is fail-closed:

- no syscall is dispatched from the suspect payload;
- a typed diagnostic records the expected and observed authority fields;
- the implementation uses the existing register path when safe to do so;
- an EL1-side impossible response uses the existing fail-loud HVC rather than
  resuming guest state speculatively.

## Portability boundary

The request-level `vmm` policy is immediately portable. The mailbox fast path
is capability-driven and narrower:

- `carrick-aarch64` owns the shared engine decision between mailbox and legacy
  frame acquisition.
- The VMM vCPU contract reports whether a validated mailbox frame is available
  and supplies its concrete exit classification.
- HVF installs the first mailbox implementation using its `hvc #2` vehicle.
- KVM/AArch64 may adopt the same shared wire protocol only after a separate
  comparison against its current MMIO-sentinel path.
- x86_64 continues using its LSTAR/trampoline and VMM-specific exit vehicle; it
  does not pretend to implement the AArch64 mailbox contract.
- bhyve and NVMM keep their current paths until their real target hosts prove a
  mailbox or analogous portal is both correct and faster.

An unsupported backend returns `None` from the mailbox capability and uses the
existing frame path. There is no shell-level approximation or backend-name
special case in the dispatcher.

## Performance proof

### Historical method to reuse

Commit `63942161` introduced
`dsr_gateway_perf_feasibility_30_samples`, the feasibility comparison that
selected the exception-free DSR gateway over the native `brk`/signal transport.
It used one optimized binary containing both implementations, twenty warmups,
thirty samples, two hundred equal transitions per sample, per-transition
timing, p50 comparison, and a candidate/baseline ratio. The gate stopped unless
DSR beat `brk`.

The mailbox decision reuses that same-binary, equal-work, boundary-isolation
strategy and combines it with Carrick's later fixed-order ABBA and seeded
bootstrap facilities.

### Boundary comparator

A signed HVF performance helper contains both the legacy register path and the
mailbox path in the same executable and VM. A test-only control word selects
the portal mode; production execution has no user-facing legacy-mode switch.
The guest executes a synthetic syscall loop whose host side returns a constant
without entering the real dispatcher or issuing a host syscall.

The signed `carrick` candidate used for end-to-end comparison contains an
internal diagnostic override that forces all ordinary syscalls through the
legacy register path. The performance harness sets that override directly; it
is not an `ExecBackendRequest`, CLI value, persisted container option, or
automatic fallback policy. Invalid override values fail before guest startup.
The override remains as a documented diagnostic opt-out through the first
promoted evidence cycle and may be removed only by a later measured change.

The comparator:

- warms each path at least twenty times;
- records thirty balanced `legacy -> mailbox -> mailbox -> legacy` blocks;
- uses equal transitions per leg, starting at two hundred and increasing before
  the campaign if timer quantization is visible;
- runs serially with a scoped `CARRICK_RUN_ID`;
- records the exact binary SHA-256, commit, codesign identity, host, OS, CPU,
  power state, mode order, transition count, and cleanup result;
- publishes raw samples, minimum, p50, p95, IQR, sample count, ratio estimate,
  and seeded 95% bootstrap interval to versioned JSONL.

The transport candidate is promoted only when correctness is green, the p50
improves by at least 10%, and the 95% ratio upper bound is below 1.0. Thresholds
are frozen before sampling and are not weakened after seeing the result. A
smaller or inconclusive result closes the mailbox experiment without shipping
hot-path complexity.

### End-to-end guard

A boundary win is not an application claim. The same signed binary also runs
the existing syscall-floor, syscall-burst, blocking wakeup, fork/exec, and
direct workload cases with mailbox on/off under balanced ordering. Artifact
hashes, guest artifacts, arguments, environment, filesystem mode, and CPU
exposure must match.

Promotion requires:

- syscall-floor and syscall-burst p50 improvement with a 95% ratio upper bound
  below 1.0;
- blocking-wakeup and direct-compute non-inferiority with a 95% ratio upper
  bound at or below 1.02;
- fork and fork/exec non-inferiority with a 95% ratio upper bound at or below
  1.05;
- no increase in wrong-result, timeout, crash, or leftover-process outcomes;
- a profile showing that removed register/sysreg calls explain the boundary
  improvement;
- a checked-in report that separates transport, end-to-end, skipped, and
  invalid rows.

Carrick and Docker oracle phases remain separate. Performance modes never alter
Linux-visible syscall answers.

### Conditional second experiment

After mailbox promotion or rejection, re-profile the remaining boundary. Only
if the HVC/VM-exit transport is still a material pole may a later design reuse
DSR decoding/emission to investigate guest-resident rewritten syscall portals
or direct EL0 exit vehicles.

That later experiment must first measure candidate HVF exit instructions or
sentinel accesses in a signed minimal VM. It must not build a VMM translation
cache on the assumption that a different exit is cheaper. Live native/VMM
state migration remains out of scope even if that experiment proceeds.

## Correctness and testing

### Red-first protocol tests

Before the vector uses the mailbox, add tests that fail against the current
tree and prove:

- `ExecBackendRequest` exposes only `Native` and `Vmm`;
- omitted CLI selection resolves to native;
- `auto` and `hvf` are rejected with migration guidance;
- a container persists one backend and carries it through `fork`, clone, and
  `execve`;
- an SVC vector publishes the declared mailbox layout;
- the host refuses stale generation, duplicate sequence, partial publication,
  wrong trap kind, and unknown response action;
- normal completion preserves every guest-visible register except the declared
  syscall return in `x0`;
- `RegistersPrepared` does not overwrite signal-handler or restart state.

The wire layout has compile-time size, alignment, offset, state-value, and
uniqueness assertions. Generated vector words are decoded back in tests.

### Interruption matrix

Targeted tests place a kick or exceptional outcome at each protocol phase:

1. before request construction;
2. during payload construction but before publication;
3. after `RequestReady` and before HVC exit;
4. while host dispatch owns the request;
5. after response payload but before `ResponseReady`;
6. after `ResponseReady` and before `eret`;
7. immediately after the guest returns to EL0.

The matrix covers ordinary return, EINTR, SA_RESTART, signal-handler entry,
`rt_sigreturn`, ptrace stop, fork, clone, exec, vCPU reclaim/rebind, and
generation rollover. No case may dispatch twice, lose a syscall, apply a stale
return, or expose a Carrick EL1 PC as a guest resume PC.

### Live verification

After focused unit and integration gates:

- build and sign through the repository's signed build path;
- verify the exact helper binary's hypervisor entitlement;
- run the boundary comparator and end-to-end guard serially;
- run `just fmt-check`, `just clippy`, `just lint-domains`, and `just ci`;
- run the authoritative conformance-probe lane against Docker in separate
  Carrick and oracle phases;
- run representative Rust, Go, CPython, Node/V8, fork-heavy, signal-heavy, and
  multithreaded workloads under explicit `--exec-backend vmm`;
- audit scoped process cleanup and preserve all raw JSONL evidence.

Helper binaries that call HVF must be signed themselves; signing only
`target/release/carrick` is insufficient.

## Completion criteria

The design is implemented only when all of the following are true:

- public and persisted backend policy contains only `native` and `vmm`;
- omitted selection means native and VMM use is explicit;
- a container cannot change backend after creation;
- native DSR has no VMM-style admission ceiling or automatic VMM fallback;
- macOS `vmm` resolves to HVF without exposing `hvf` as public policy;
- the mailbox protocol is generation-safe, interruption-safe, and fail-closed;
- ordinary HVF syscalls avoid the previous register/sysreg frame reads and x0
  write;
- legacy slow paths remain correct for exceptional outcomes;
- the frozen same-binary performance gate promotes or rejects the mailbox
  without moving thresholds;
- focused tests, full CI, signed workloads, and Docker differential evidence
  are green;
- the evidence report states measured effects and limitations without claiming
  a universal workload speedup;
- any direct-exit/rewritten-portal follow-up remains evidence-gated and separate
  from this implementation.
