# Native DSR Biased `ET_EXEC` Design

**Date:** 2026-07-12

**Status:** approved design

## Purpose

Carrick's Darwin-native backend must execute ordinary low-address AArch64 Linux
`ET_EXEC` binaries without restoring the removed BRK executor and without
falling back to HVF. Dynamic syscall rewriting (DSR) remains the sole native
instruction engine. The existing direct-address DSR path for PIE/`ET_DYN` must
remain the primary performance path and must not pay a per-memory-access branch
for `ET_EXEC` support.

This design introduces a second, explicitly typed DSR address mode. Low-address
`ET_EXEC` keeps Linux guest virtual addresses architecturally visible while its
host mappings live at one fixed high bias. DSR rewrites memory operations across
that boundary. Direct-address PIE remains unchanged.

## Current constraint and measured evidence

Carrick currently rejects any native guest region below 4 GiB because the arm64
Mach-O process reserves that range as `__PAGEZERO`. Shrinking the primary
binary's segment is not a viable solution on the current host.

A live linker/loader experiment on 2026-07-12 produced arm64 Mach-O executables
with `__PAGEZERO` sizes of 64 KiB, 256 MiB, 1 GiB, 2 GiB, and 4 GiB. The first
four were killed by the loader with status 137. Only the 4 GiB binary ran. The
same restriction applies to an internal helper because every arm64 Mach-O
process crosses the same loader validation.

Therefore this design does not alter Carrick's Mach-O layout. It solves the
collision inside DSR's guest-to-host address model.

## Scope

This spec covers:

- initial execution of low-address AArch64 Linux `ET_EXEC` under native16k DSR;
- a typed direct-versus-biased native address domain;
- transactional biased mappings that cannot overwrite live Carrick mappings;
- biased DSR instruction fetch, memory access, fault, and syscall-pointer
  translation;
- direct-to-biased, biased-to-direct, and biased-to-biased image replacement
  mechanics for single-threaded `execve`;
- fork inheritance of an already selected bias;
- correctness and fast-path regression evidence.

This spec does not claim to fix the independently reproduced post-fork,
multithreaded DSR `execve` lifecycle defect. That defect is the next design and
implementation unit. Task 6 performance publication remains blocked until that
second unit restores authoritative native probe results.

## Rejected approaches

### Smaller primary-binary `__PAGEZERO`

Rejected by the live arm64 loader experiment. XNU kills the process when the
segment is smaller than 4 GiB.

### Separate small-page-zero helper

Rejected for the same loader reason. It would also require an unnecessary
dispatcher, namespace, mount, signal, and descriptor reconstruction protocol.

### ELF rebasing

Rebasing segments and allowing registers to contain host-biased addresses is
not correct for general `ET_EXEC`. Fixed executables need not carry relocation
metadata for embedded pointers. Carrick must not silently support only the
fortunate subset that happens to be position-independent.

### Software interpretation of all memory operations

Correct in principle, but incompatible with DSR's performance objective. The
biased path should remain generated native code with a predictable address-add
cost, not route every access through a helper call.

## Address-domain model

Add a typed native address policy:

```rust
enum NativeAddressMode {
    Direct,
    Biased { host_bias: NativeHostBias },
}
```

`NativeHostBias` is a nonzero, host-page-aligned domain type. It is not a bare
`u64`, and construction validates alignment and overflow bounds.

The selection rules are:

- PIE/`ET_DYN` and an `ET_EXEC` image whose complete native layout can map at
  its Linux addresses use `Direct`;
- an image with any required mapping below the 4 GiB Mach-O boundary uses
  `Biased`;
- an image that cannot fit into any candidate biased window fails with a typed
  diagnostic.

In both modes, Linux-visible state remains in guest coordinates:

- general-purpose registers and SP;
- PC, LR, branch targets, and return targets;
- auxv and initial-stack pointers;
- signal-frame pointers and reported `si_addr` values;
- syscall arguments and return values;
- `/proc` mappings and diagnostics;
- DSR cache keys, dependency pages, and code generations.

Only host mappings and actual host memory accesses use translated coordinates.
The translation is:

```text
Direct: host = guest
Biased: host = guest + host_bias
```

Reverse fault translation subtracts the bias only after proving the host address
belongs to the Carrick-owned biased aperture, including its guard gaps. Host
faults outside that aperture remain host faults and must never be mislabeled as
guest addresses.

## Bias selection and transactional mapping

One bias applies to the complete guest address space for a biased image. A
single constant keeps generated access sequences small and avoids a mapping
table lookup on every instruction.

Bias candidates are deterministic, host-page-aligned high windows. Selection
validates the complete prospective layout, including:

- main ELF and interpreter segments;
- initial stack;
- heap and mmap arenas;
- vDSO and vvar;
- signal trampoline;
- overflow against the usable Darwin user address range.

The semantic biased guest aperture is the contiguous interval from guest zero
through the exclusive fixed ceiling `LINUX_STACK_TOP`. Carrick also reserves a
bounded 1 MiB overflow guard so a near-ceiling literal or multi-byte access
cannot escape into unrelated host memory. Candidate selection acquires this
entire translated aperture as one collision-probed `PROT_NONE` ownership
interval; it does not reserve only the image's currently modeled mappings.

Each candidate is attempted transactionally. Carrick requests exact host
ranges without `MAP_FIXED`. Darwin may treat the supplied address as a hint; if
the returned address differs, Carrick immediately unmaps it, cleans up every
range already acquired for that candidate, and tries the next candidate. This
probing path therefore cannot replace Carrick, dyld, allocator, shared-cache,
or other live mappings.

After Carrick owns the aperture, its normal protection and remapping operations
may replace only subranges inside that owned interval. A typed owned-range check
guards any later fixed mapping operation. The rest of the aperture stays
`PROT_NONE`, including guest zero and every unmodeled gap, so those faults occur
inside Carrick-owned address space and can be lowered deterministically.

Guest address zero remains invalid. In biased mode it corresponds arithmetically
to `host_bias`, but that host page remains a `PROT_NONE` Carrick-owned guard. A
null or otherwise unmapped access therefore lowers back to the correct Linux
guest fault without depending on whatever mapping happens to exist at a later
bias candidate.

Mapping attempts are all-or-nothing. Before the Linux `execve` point of no
return, candidate validation errors return the appropriate guest errno. After
the old image has been retired, an unexpected host mapping failure terminates
the guest process with a typed runtime diagnostic; Carrick does not resume a
partially replaced image.

## `NativeMappedMemory` authority

`NativeMappedMemory` owns `NativeAddressMode` and becomes the only authority for
guest/host translation. Its internal helpers accept and return typed addresses:

- `GuestVa -> HostVa` for mapped access;
- `HostVa -> Option<GuestVa>` for validated reverse translation;
- guest range -> checked host range for mapping and protection operations.

All memory responsibilities translate internally:

- instruction-source reads for DSR translation;
- syscall buffer reads and writes;
- signal-frame construction and restoration;
- mmap, munmap, mprotect, and resident-page operations;
- code-generation and executable-page tracking;
- vDSO/vvar relocation and access;
- initial-stack and auxv population.

Dispatcher APIs continue to carry Linux guest pointers. Biased `HostVa` values
must not escape into VFS, signal, futex, process, or compatibility-report
interfaces.

Futex identity, file-backed shared mapping identity, and fork-coherent state
remain based on guest coordinates and backing-object identity. The host bias is
an implementation detail and must not split Linux objects that alias the same
guest backing.

## DSR execution modes

DSR emission is specialized by address mode. Direct mode must compile to the
existing code shape; biased support must not introduce a runtime condition into
each direct-mode load or store.

### Instruction fetch and control flow

DSR cache keys, guest PCs, direct targets, indirect targets, return targets,
and dependency generations remain `GuestVa`. Instruction-source reads ask
`NativeMappedMemory` for the corresponding host bytes.

ADR, ADRP, branches, calls, returns, and address-producing literal rewrites
continue to produce guest-visible values. A branch never exposes a biased host
source address to a guest register.

### Direct memory operations

`Direct` preserves the current emitter. Ordinary memory instructions remain
eligible for exact copying. Existing x18/x28 virtualization and sensitive
instruction handling are unchanged.

Exact-byte oracle tests pin this property. A direct-mode performance regression
cannot be accepted merely because biased mode works.

### Biased memory operations

In `Biased`, every guest memory operation computes its guest effective address,
adds the immutable host bias into a dynamically selected scratch register, and
performs the equivalent host instruction through that scratch address.

The supported surface includes:

- scalar loads and stores;
- pair loads and stores;
- SIMD/FP loads and stores;
- SP-relative accesses;
- pre-index, post-index, and register-offset addressing;
- atomic read-modify-write operations;
- exclusive load/store sequences;
- literal memory reads;
- the audited x18/x28 virtual-register combinations already supported by DSR.

Writeback updates remain in guest coordinates. Exclusive semantics operate on
the translated host address while guest-visible reservation/fault reporting
uses the guest address.

The fixed guest ceiling is exclusive. Biased lowering computes the exact guest
effective address for every memory form. A flags-neutral `LSR`/`CBZ` check keeps
guest NZCV unchanged and gives all addresses below 1 TiB the normal translated
host operand without publishing per-access recovery state. The `PROT_NONE`
overflow guard covers the narrow interval from `LINUX_STACK_TOP` to 1 TiB, so
those addresses still fault inside Carrick-owned memory. A larger address
publishes that exact guest value, tags the host operand with a bit outside
Darwin's user address range, and deliberately faults without allowing the guest
address to alias unrelated host memory. Signal recovery then reports the
published guest address. Direct emission is unchanged by this check.

The bias is immutable gateway context, not a guest-visible reserved register.
Scratch selection must compose with DSR's existing x17 entry transport and
x18/x28 virtualization. If an instruction cannot be lowered without corrupting
architectural state, translation fails with the instruction word, guest PC,
addressing class, and typed unsupported reason.

No biased guest instruction may execute an untranslated low memory operand.

## Faults and signals

The native signal bridge first classifies whether a host fault address belongs
to a mapped biased guest interval. When it does, Carrick subtracts the bias and
uses the guest address for:

- mmap growth and SIGBUS classification;
- protection-versus-mapping `si_code` upgrades;
- Linux signal-frame `si_addr`;
- diagnostics and event-ring records;
- executable-generation and guarded-page decisions.

The interrupted host cache PC is already resolved through DSR metadata to a
guest PC. Address-mode translation must not change that control-flow contract.

A fault in the DSR cache, Carrick host memory, dyld, or another unowned mapping
must not be reverse-translated. It remains a native-runtime failure.

## Fork and exec lifecycle

`fork` inherits the immutable address mode, bias, and Darwin mappings through
normal process copy-on-write. Fork repair continues to reset DSR publication
and thread-local state while leaving guest coordinates unchanged.

For `execve`, after the existing successful-load and sibling-teardown point:

1. classify the replacement image as direct or biased;
2. validate a complete candidate layout before changing the current image,
   subtracting current Carrick-owned ranges from collision probes so an
   overlapping replacement may reuse them;
3. retire old DSR metadata and unmap only old ranges the replacement will not
   retain;
4. transfer retained ownership, restore a retained biased aperture to
   `PROT_NONE` guards, and map the replacement only inside that authority;
5. rebuild stack, auxv, vDSO/vvar, signal trampoline, and memory accounting;
6. reset registers and DSR translator state in guest coordinates;
7. publish the replacement only when every mapping and relocation succeeds.

This supports single-threaded direct-to-biased, biased-to-direct, and
biased-to-biased transitions. It deliberately does not claim that Darwin host
runtime state after guest fork+exec is ready for later guest thread creation.
That is the next architecture unit.

## Diagnostics and errors

New failures are typed and include enough context to reproduce:

- guest-to-host or host-to-guest arithmetic overflow;
- invalid or unaligned host bias;
- no collision-free bias candidate for the complete layout;
- exact-address mapping returned at a different host address;
- a fixed operation outside a Carrick-owned host range;
- a host fault outside mapped guest intervals;
- a biased memory instruction with no audited lowering;
- an image transition that cannot be completed transactionally.

There is no automatic HVF fallback, no ELF rebasing, no silent address widening,
and no partial success. Carrick remains explicit that native execution is
experimental and trusted-code-only.

## Verification

Implementation follows red-first proof.

### Typed address and mapping tests

- direct and biased forward translation;
- validated reverse translation;
- alignment and arithmetic overflow;
- null and unmapped gaps;
- complete-layout candidate validation;
- collision attempts do not replace an existing host mapping;
- partial candidate cleanup leaves no mappings behind.

### DSR emission oracles

- scalar, pair, SIMD, SP-relative, pre/post-index, register-offset, atomic,
  exclusive, and literal operations use biased host addresses while preserving
  guest writeback;
- x18/x28 virtualized combinations remain correct;
- unsupported encodings fail closed;
- direct-mode emitted bytes remain identical to the pre-feature baseline.

### Live signed evidence

- a real low-address AArch64 static `ET_EXEC` fixture is red against the current
  native backend and green under native16k biased DSR;
- the same fixture runs under HVF as the behavior reference;
- initial `ET_EXEC` plus single-threaded direct/biased `execve` transitions;
- fork inheritance of a selected bias;
- guest-authored `brk` still delivers Linux SIGTRAP semantics;
- JIT rewrite and concurrent DSR publication regressions remain green;
- existing native PIE workload and backend-pair performance smokes remain green;
- full local CI passes before beginning the post-fork lifecycle spec.

The first unit is complete only when a signed low-address `ET_EXEC` executes
end-to-end and direct PIE behavior remains unchanged. It does not unblock Task 6
publication by itself; authoritative native probes must also pass after the
separate post-fork lifecycle repair.

## Performance contract

PIE/`ET_DYN` direct mode is Carrick's primary DSR performance lane and is
expected to become orders of magnitude cheaper than HVF on syscall-heavy
workloads. This feature must not tax that path.

Low `ET_EXEC` biased mode pays generated address-add instructions as the cost of
supporting a layout XNU cannot map directly. Its results are reported separately
from direct PIE. Neither lane gates on a ratio or declares a global winner.
