# Durable guest memory architecture for Carrick

## Context

Carrick's current Go blocker is not a normal Linux `mmap` bug. The failed
workarounds point at an architectural mismatch:

- arm64 Hypervisor.framework exposes `hv_vm_map`, `hv_vm_unmap`,
  `hv_vm_protect`, and `hv_vcpus_exit`, but no public arm64 equivalent of the
  x86-only `hv_vcpu_invalidate_tlb`.
- Recreating only a vCPU after a late `hv_vm_map` did not clear the stale
  shared-stage2 symptom.
- Quiescing sibling vCPUs around a late shared mapping did not clear it.
- Whole-VM rebuild appeared to remove the stale fault, but it is too expensive
  to be the steady-state memory model.

The durable rule is therefore:

> After guest vCPU threads exist, Carrick must not use `hv_vm_map`,
> `hv_vm_unmap`, or `hv_vm_protect` for ordinary guest `mmap`, `munmap`,
> `mprotect`, or shared-memory lifetime changes.

Git preserves the old behavior. We do not need backward-compatible internal
interfaces. The new design should optimize for correctness, low memory
overhead, fork scalability, and predictable performance.

## Research findings

### Apple HVF surface

The macOS 26.2 SDK arm64 headers provide:

- `hv_vm_map(void *addr, hv_ipa_t ipa, size_t size, hv_memory_flags_t flags)`
- `hv_vm_unmap(hv_ipa_t ipa, size_t size)`
- `hv_vm_protect(hv_ipa_t ipa, size_t size, hv_memory_flags_t flags)`
- `hv_vcpus_exit(hv_vcpu_t *vcpus, uint32_t vcpu_count)`

The same local SDK has `hv_vcpu_invalidate_tlb` only in `Hypervisor.framework`
`hv.h`, which is guarded by `#ifdef __x86_64__`. arm64 public HVF does not give
Carrick a stage-2 TLB shootdown primitive.

Relevant public references:

- Apple `hv_vm_map`: https://developer.apple.com/documentation/hypervisor/hv_vm_map
- Apple `hv_vm_unmap`: https://developer.apple.com/documentation/hypervisor/hv_vm_unmap
- Apple `hv_vm_protect`: https://developer.apple.com/documentation/hypervisor/hv_vm_protect
- Apple `hv_vcpus_exit`: https://developer.apple.com/documentation/hypervisor/hv_vcpus_exit

### QEMU/HVF comparison

QEMU's HVF backend registers a memory listener and maps/unmaps/protects memory
regions through HVF memory slots. That model is appropriate for a full VM with
well-defined RAM/MMIO regions, but it does not solve Carrick's late
Linux-ABI-level `MAP_SHARED` churn problem. QEMU still relies on the same public
HVF calls (`hv_vm_map`, `hv_vm_unmap`, `hv_vm_protect`), not an arm64 public
TLBI API.

Reference:

- QEMU `accel/hvf/hvf-all.c`: https://raw.githubusercontent.com/qemu/qemu/master/accel/hvf/hvf-all.c

### Darwin VM leverage

Darwin VM gives Carrick useful primitives for laziness and low resident memory:

- large virtual reservations can stay nonresident until touched;
- `MAP_NORESERVE` reduces commit pressure for huge demand-zero apertures;
- `mincore` can keep fork snapshots sparse by copying only resident pages;
- `mach_vm_remap` / Mach VM objects are worth probing for copy-on-write
  snapshots.

Darwin COW is not a drop-in replacement for Carrick's private guest fork
semantics today, because HVF coherence forced host `MAP_SHARED` backing for
guest RAM. A normal host `fork(2)` does not COW-isolate those shared mappings.
Private guest memory therefore still needs either explicit sparse snapshots or
a validated Mach-VM-backed COW clone.

Reference:

- Apple VM overview: https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/AboutMemory.html
- Apple allocation guidance: https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/MemoryAlloc.html

## Goals

1. Eliminate post-thread stage-2 mapping mutations for routine guest memory
   operations.
2. Preserve low resident memory for large guest address windows.
3. Make fork fast by avoiding per-guest-`mmap` HVF topology churn and copying
   only private resident pages.
4. Make Linux memory semantics real at guest execution time, not just in
   host-side `read_guest_bytes` checks.
5. Keep the implementation decomposed: stable host apertures, guest-visible
   stage-1 mappings, backing objects, and fork snapshots are separate concepts.

## Non-goals

- A public arm64 stage-2 TLBI interface. Carrick cannot implement that from
  userspace with the public HVF API.
- Keeping the current dynamic `LINUX_SHARED_FILE` mapping path.
- Preserving old internal APIs if they make the durable architecture harder.
- Eagerly backing huge memory regions. Virtual reservation is acceptable;
  resident memory growth is not.

## Core architecture

### 1. Stable stage-2 aperture topology

Carrick should allocate and `hv_vm_map` a small fixed set of host-backed
apertures before guest vCPU threads can run:

- executable/image aperture(s);
- heap aperture;
- anonymous mmap aperture;
- shared mapping aperture;
- stack aperture;
- Carrick EL1 trampoline/vector/page-table regions.

The general-purpose apertures should be backed by host
`mmap(MAP_ANON | MAP_SHARED | MAP_NORESERVE)` where possible. HVF stage-2
permissions should be a stable superset for the aperture, usually
read/write/execute for user memory, because guest-visible permissions move to
stage-1. Carrick should stop using stage-2 permission changes to implement
guest `mprotect`.

This converts stage-2 from "dynamic Linux mapping table" into "stable physical
RAM topology".

### 2. Guest-visible memory semantics in stage-1

Carrick already owns the EL1 page tables used to run Linux EL0 code with Normal
cacheable memory. The new design makes those page tables the source of truth
for guest-visible memory:

- `mmap` allocates a virtual range, attaches a backing object, and installs
  valid stage-1 descriptors for the range.
- `munmap` invalidates stage-1 descriptors and returns the virtual range to the
  allocator.
- `mprotect` updates AP/UXN/PXN attributes in stage-1 descriptors.
- `PROT_NONE` and unmapped ranges must fault in guest execution, not only fail
  host-side memory helper checks.

The page-table manager should use coarse descriptors wherever valid and split
only when a guest operation needs finer granularity. Do not build dense 4 KiB
PTEs for the entire 32 GiB mmap aperture. Start from the existing block-mapped
identity table and add controlled splitting/coalescing.

### 3. Carrick-owned stage-1 TLBI interface

Carrick cannot flush HVF stage-2 TLB state through a public arm64 API, but it
can control guest EL1 code and guest stage-1 page tables.

When Carrick mutates page tables after vCPUs exist:

1. Stop sibling vCPUs at a lock-safe boundary using the existing kick/quiesce
   machinery.
2. Write page-table updates.
3. Run a tiny Carrick EL1 maintenance trampoline that performs the required
   barrier and stage-1 TLBI sequence.
4. Resume guest vCPUs.

The first implementation can conservatively use a whole-address-space stage-1
flush (`tlbi vmalle1is` plus barriers). Later optimization can add range TLBI
when the generated maintenance code and CPU feature detection justify it.

This is not "our own HVF TLBI". It is a Carrick EL1 stage-1 maintenance path,
which is the layer Carrick owns.

### 4. Backing objects

Guest virtual memory should be described by backing objects independent from
stage-1 descriptors:

- `PrivateAnon`: demand-zero, private to the guest process, sparse-snapshotted
  on true fork.
- `SharedAnon`: shared across guest processes or threads, never copied on fork.
- `SharedFile`: backed by a host `MAP_SHARED` file mapping or a durable file
  object; shared across guest fork.
- `PrivateFile`: file bytes with private dirty pages; candidate for future
  Mach VM COW leverage.
- `CarrickKernel`: EL1 trampoline/vector/page-table storage.

The important split is guest visibility versus host backing. A backing object
may cover a large aperture while stage-1 marks only a subrange valid.

### 5. Fork model

Fork performance comes from avoiding HVF topology churn and avoiding full-memory
copies.

For true Linux `fork`:

- quiesce vCPUs so the memory manager has a stable point-in-time view;
- copy metadata cheaply;
- clone private resident pages only, using the current `mincore`-style sparse
  snapshot as the correctness baseline;
- share `SharedAnon` and `SharedFile` backings;
- rebuild the child HVF VM from the fixed aperture descriptors, not from a long
  list of dynamic per-`mmap` mappings.

For the common `CLONE_VM | CLONE_VFORK | CLONE_PIDFD` + `execve` path used by
Go `os/exec`, Carrick should prefer a spawn/vfork-exec path that does not
snapshot the guest address space and does not rebuild the parent VM. The child
is expected to exec promptly; the robust design should handle that as a distinct
fast path instead of forcing it through the expensive true-fork machinery.

Longer term, Carrick should probe whether Mach VM objects or `mach_vm_remap`
with copy semantics can replace explicit copies for private resident pages. The
design must keep sparse explicit snapshotting as the fallback until a probe
proves both correctness and lower cost under HVF.

## Memory overhead policy

The architecture is allowed to reserve large virtual apertures. It is not
allowed to make those apertures resident or commit-heavy merely because they
exist.

Rules:

- Use lazy host mappings and `MAP_NORESERVE` for large demand-zero apertures.
- Do not eagerly zero fresh aperture ranges; untouched pages should stay
  demand-zero.
- Zero only recycled guest ranges before returning them to satisfy anonymous
  `mmap` semantics.
- Keep stage-1 tables sparse/coarse. Split only the affected region and
  coalesce when possible.
- Measure with `vmmap`/`footprint` or equivalent after each milestone. Resident
  memory, compressed memory, and swap/commit pressure are part of correctness
  for this design.

## Performance policy

Steady-state guest `mmap`, `munmap`, and `mprotect` should not enter HVF VM
topology mutation APIs. Their hot cost should be:

- Carrick metadata update;
- stage-1 descriptor update;
- bounded quiesce/TLBI when permissions or validity change under active vCPUs.

Fork hot cost should be:

- quiesce;
- metadata clone;
- sparse private resident-page snapshot, or validated Mach COW clone;
- child HVF setup over fixed apertures.

The design explicitly rejects whole-VM rebuild as the normal response to shared
mapping changes. Whole-VM rebuild remains useful only as a diagnostic proof or
emergency fallback while the new architecture is being implemented.

## Failure handling

- If host aperture reservation fails, fail process startup with a clear error.
- If a stage-1 page-table split/allocation fails, return the correct Linux
  errno for the syscall (`ENOMEM` for allocation failure, `EINVAL` for invalid
  inputs).
- If a maintenance TLBI trampoline fails to complete, stop the process rather
  than resuming guest vCPUs with ambiguous memory visibility.
- If a Mach COW snapshot probe fails validation, keep explicit sparse snapshot
  as the production path.

## Implementation decomposition

This architecture is too large for one implementation plan. Split execution into
separate plans:

1. Stable shared aperture and memory-manager skeleton:
   remove the dynamic shared-stage2 path, model shared ranges as backing
   objects inside a pre-mapped aperture, preserve current private mmap behavior.
2. Stage-1 page-table manager:
   descriptor split/coalesce, guest-visible `PROT_NONE`/unmapped faults, and
   tests for `mmap`/`munmap`/`mprotect`.
3. Stage-1 TLBI trampoline:
   quiesce integration, whole-ASID flush first, range flush later only if
   measured useful.
4. Fork refactor:
   fixed-aperture child rebuild, sparse private snapshots, and separate
   vfork-exec fast path.
5. Darwin COW probe:
   benchmark and correctness tests for Mach VM remap/object cloning versus
   explicit sparse copy.
6. Go conformance closure:
   run full Go package matrix, update `golang-bringup-handoff.md`, and remove
   stale experiment notes.

## Validation strategy

Unit tests:

- page-table descriptor split/coalesce;
- backing-object range insertion/removal;
- no dense PTE construction for untouched apertures;
- fork snapshot policy: private copied, shared not copied.

Guest probes:

- `MAP_SHARED | MAP_ANON` read/write across fork;
- file-backed `MAP_SHARED` visibility across fork;
- `MAP_PRIVATE` file dirty-page isolation;
- `mprotect(PROT_NONE)` causes guest fault;
- `munmap` causes guest fault and range reuse returns zeroed pages;
- concurrent `mmap`/`munmap` while many vCPUs run.

Performance/memory gates:

- resident memory after startup with large apertures;
- resident memory after churned `mmap`/`munmap`;
- true fork latency under sparse and dirty heaps;
- vfork-exec/Go `os/exec` latency;
- no calls to `hv_vm_map`, `hv_vm_unmap`, or `hv_vm_protect` for ordinary guest
  memory syscalls after vCPU threads exist.

Go gates:

- focused runtime package first;
- then `sync`, `sync/atomic`, `context`, `time`, `os/signal`, `os/exec`, `net`;
- then full `scripts/go-conformance-image.sh`.

## Open probes before implementation lock-in

1. Does pre-mapping the complete shared aperture through HVF materially
   increase kernel memory or stage-2 page-table memory compared with dynamic
   shared ranges?
2. Can `mach_vm_remap(copy=true)` or a Mach memory-entry workflow produce a
   correct sparse private fork snapshot while preserving HVF coherence?
3. Is whole-ASID stage-1 TLBI under quiesce fast enough for Go and common Linux
   workloads, or do we need range TLBI in the first production version?
4. Can the vfork-exec path avoid parent VM teardown entirely while preserving
   Linux `CLONE_VFORK | CLONE_VM` blocking semantics?

## Self-review

- Placeholder scan: no `TBD`/`TODO` placeholders remain.
- Consistency: stage-2 is stable topology; guest memory validity/protection is
  stage-1 plus metadata throughout.
- Scope: implementation is explicitly decomposed into multiple plans because
  the architecture spans memory management, TLBI, and fork.
- Ambiguity: stage-2 TLBI is out of scope; Carrick's TLBI interface is only for
  guest stage-1 translations.
