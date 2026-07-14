# Native Prepared-Image Self-Reexec Design

**Date:** 2026-07-13

**Status:** approved for implementation on 2026-07-13

## Purpose

PID-preserving host self-reexec is the correctness boundary that lets ordinary
Node, Go, and CPython fork-to-exec children create threads without inheriting
Darwin `libdispatch` state. It must remain. The current implementation,
however, constructs the replacement Linux image twice:

1. the fork child resolves the target, validates ELF/interpreter/stack state,
   computes relocations, and builds an `AddressSpace` before the host exec; and
2. the fresh Carrick process reopens the path, repeats that work, checks a
   content digest, then copies the rebuilt regions into native mappings.

The complete `dsr-fork` profile measures one preflight and one fresh image load
for every one of 220 execs. Untraced timing assigns about 1.22 ms to preflight
and 1.03 ms to the repeated fresh image load for the canonical static-PIE
probe. The repeated work is a material part of the remaining 12.1 ms native
fork-exec median.

This design transfers the already-validated prepared image across host exec in
a separate inherited sparse regular file. The fresh process maps the exact
validated bytes and typed metadata instead of resolving and constructing the
guest image a second time.

## Goals

- Preserve the real host `execve(2)` boundary and its PID/libdispatch semantics.
- Preserve the current rule that every guest-visible validation failure returns
  a Linux errno before the host exec point of no return.
- Execute exactly the target bytes validated by the old process, even if the
  guest path changes during host exec.
- Remove fresh-process path resolution, ELF/interpreter parsing, digesting,
  stack reconstruction, and anonymous-region byte copy when the prepared image
  artifact is eligible.
- Keep capsule metadata small and bounded for large real-world executables.
- Retain the existing reconstruction path as a correctness-preserving fallback
  when a prepared artifact cannot be represented.
- Improve canonical native fork-exec p50 by at least 10% with a 95% bootstrap
  ratio upper bound below 1.0, without regressing representative Node, Go, or
  CPython workloads.

## Non-goals

- Removing host self-reexec or weakening its post-fork thread safety.
- Persisting DSR translations across unrelated processes or runs.
- Creating a public checkpoint/restore or executable-cache format.
- Changing HVF/VMM execution or performance.
- Treating a microbenchmark-only win as sufficient for promotion.
- Raising the existing capsule payload limit to fit arbitrary executable bytes.

## Selected architecture

### Separate prepared-image artifact

The old process creates a second anonymous regular file after
`load_native_execve_image` has completed successfully. This file is distinct
from the small versioned state capsule.

The capsule gains a typed `NativePreparedImageV1` record containing:

- inherited artifact fd, original descriptor flags, device, inode, and size;
- artifact format version and host-page geometry;
- guest entry and initial stack pointer;
- exact serialized auxv image;
- ordered region descriptors: guest start/end, Linux permissions, shared bit,
  artifact offset, and artifact extent length;
- ordered initialized-span descriptors: owning region, guest-relative offset,
  artifact offset, and byte length;
- ordered read-only ELF spans;
- relative relocation records; and
- a SHA-256 identity over the artifact header, region table, and initialized
  payload bytes.

The record contains no Rust object dump and no raw pointer. Every address is a
typed guest address or artifact offset validated against the declared geometry.
The artifact is internal and version-locked to the producing Carrick binary.

### Sparse file layout

Each guest region receives a host-page-aligned extent in the artifact. The file
is truncated to the complete bounded layout, so unwritten holes read as zero.
Carrick scans the current mapper's byte windows and writes only non-zero page
runs:

- ordinary ELF/vDSO regions write their non-zero initialized page runs;
- the 8 MiB initial stack writes only the suffix beginning at the authoritative
  initial stack pointer; and
- BSS and other zero ranges remain sparse holes.

Zero bytes inside an initialized range need no physical block because sparse
file holes read identically. The initialized-span table makes that omission
explicit and checksum-visible. The layout therefore avoids placing the full
zero stack prefix, BSS, or other zero pages in either the capsule or physical
file blocks.

Version 1 permits at most 256 regions, 16,384 initialized spans, a 1 GiB sparse
artifact extent, 512 MiB of written payload, and 64 KiB of auxv bytes. It
rejects shared image regions as artifact-ineligible because mapping them
`MAP_PRIVATE` would change their semantics. Exceeding any prepared-artifact
limit or encountering a shared region selects the existing fresh reload path;
it never rejects an exec that currently succeeds.

### Fresh-process adoption

After capsule validation, the resume path validates the prepared-image fd with
`fstat`, including regular-file type, device/inode identity, exact size, and
descriptor flags. It validates the format version, all region and payload
ranges, page alignment, region ordering, stack pointer containment, auxv bound,
read-only spans, relocation targets, and SHA-256 identity before mapping.

`NativeMappedMemory` gains a prepared-image mapping constructor. For each image
region it maps the corresponding artifact extent `MAP_PRIVATE` at the native
layout's fixed host address with read/write setup permissions. Sparse holes
supply the same zero fill as the current anonymous mappings. Relocations, vvar
stamping, DSR generation tables, protection bookkeeping, and final source-page
protection use the existing code paths. DSR still removes host execute
permission from guest source-code regions and executes only translated cache
code, so the artifact is not treated as trusted host executable code.

A metadata-only `AddressSpace` view is reconstructed from the validated table
for `/proc/self/maps`, `/proc/self/auxv`, address-mode selection, and existing
runtime interfaces. It does not rebuild ELF or initial-stack bytes.

The prepared fd is closed immediately after every mapping has succeeded. It is
never installed in the guest fd table and cannot survive another guest exec
unless a new artifact is prepared from the current image.

## Validation and rollback boundary

All existing old-process work remains authoritative before host exec:

- guest path and shebang resolution;
- execute permission and ELF/interpreter validation;
- relative relocation validation;
- initial stack, argv/env, auxv, and page-profile construction;
- supported post-exec fd/process-state validation; and
- complete native address-layout representability.

Artifact construction happens only after those checks. The writer computes the
digest while writing, validates its complete in-memory table with the same
checked validator used by the fresh process, and confirms the final file
identity and size with `fstat`. It does not add a stable-storage flush or a
second pre-exec payload read: the private inherited file has a coherence
contract, not a crash-recovery contract. It then clears `FD_CLOEXEC` on the
capsule, prepared-image fd, xsignal fd, and approved guest survivors. The fresh
process performs the independent payload digest before mapping.

If artifact construction or its pre-exec self-validation fails, Carrick uses
the existing digest-bound fresh reload path. If host `execve` returns, Carrick
restores every modified descriptor flag and closes the artifact before
returning the mapped Linux errno to the old guest.

Successful host exec remains the point of no return. A prepared-artifact
identity or mapping failure after that point is a stage-specific fatal internal
error; it never falls through to path reload, because doing so would execute
different bytes from those validated before the point of no return.

## Correctness invariants

1. The artifact represents the exact `AddressSpace`, initial stack, auxv,
   read-only spans, and relocations accepted by preflight.
2. Import cannot manufacture, overlap, truncate, reorder, or escalate a region.
3. Every artifact offset and guest range uses checked typed-domain arithmetic.
4. Source mappings remain non-executable under DSR, matching the current native
   W^X contract.
5. `MAP_PRIVATE` retains host-fork COW behavior and guest writes never mutate the
   inherited artifact.
6. Linux-visible `/proc` maps and auxv are byte-for-byte equal to the ordinary
   loader result.
7. Artifact fallback cannot turn a formerly successful exec into a rejection.
8. A changed guest path after preflight cannot substitute different executable
   content in the resumed process.

## Failure handling

- Bounds, version, checksum, identity, alignment, and overlap errors are typed
  artifact errors with an exact stage name.
- Pre-host-exec errors close the artifact and preserve the old guest image.
- Host-exec failure restores all temporary descriptor flags.
- Post-host-exec validation/mapping errors terminate loudly; they cannot safely
  return to the old image.
- Allocation or artifact-size limits select legacy fresh reload before the
  point of no return.
- Test-only failpoints cover artifact creation, pre-exec validation, fd flag
  preparation, fresh validation, region mapping, relocation, and final
  protection.

## Observability

The stable `dsr-fork` lifecycle gains paired phases for:

- `host-self-reexec-prepared-build`;
- `host-self-reexec-prepared-validate`; and
- `host-self-reexec-prepared-map`.

The legacy `host-self-reexec-image-load` phase remains present only on fallback.
A successful canonical prepared run must report 220 prepared build/map samples,
zero fresh image-load samples, zero incomplete pairs, and zero drops.

The untraced canonical probe remains the wall-time authority. DTrace phase
magnitudes are attribution, not the acceptance metric.

## Red-first verification

### Mechanism tests

1. Capture the current red profile: 220 old-process preflights and 220
   fresh-process image loads.
2. Add a prepared-image round-trip test that compares entry, stack pointer,
   region geometry/permissions/bytes, auxv image, read-only spans, and
   relocations against the ordinary loader result. It must fail before the new
   artifact API exists.
3. Add corruption tests for magic/version, fd type and identity, truncation,
   payload checksum, unaligned/overlapping regions, sparse initialized windows,
   out-of-region stack pointers, relocation targets, and permission escalation.
4. Prove that the 8 MiB stack's zero prefix consumes no artifact payload blocks
   and reconstructs as zero.
5. Prove that forced artifact ineligibility uses legacy reload and preserves the
   existing successful result.
6. Prove host-exec failure restores artifact and survivor `FD_CLOEXEC` flags.

### Signed runtime gates

- static-PIE and dynamic-PIE exec probes;
- `forkexecpthread` and `vforkexecthread`;
- shebang argv reducers;
- non-leader exec and exec-surviving fd/process-state probes;
- native conformance probe gate;
- focused Node app/V8, Go build/runtime/sync, and CPython subprocess lanes; and
- workers=4 smoke after the focused lanes are stable.

### Performance gate

Run the exact-source canonical `perf_fork` and `perf_fork_exec` probes serially,
with one discarded warm-up and at least five recorded repetitions per binary.
Compare the signed parent commit and candidate in fixed ABBA order. Promotion
requires all of the following:

- fork-exec p50 candidate/baseline ratio at most 0.90;
- seeded-bootstrap 95% ratio upper bound below 1.0;
- no material fork-only regression (95% upper bound at most 1.02);
- zero failed spawn iterations;
- prepared-image phases reconcile with the outer lifecycle; and
- no representative ecosystem wall-time regression above 2% unless the
  workload variance interval includes parity and a repeat clears it.

If the prepared artifact removes the duplicate load but misses the 10% wall
gate, the mapping/copy attribution determines whether to revise the backing
representation. The candidate is not promoted merely because its mechanism
works.

## Follow-up boundary

This slice does not add a persistent DSR AOT cache. After prepared-image
promotion, remeasure the remaining guest-entry-to-first-exit interval. A later
cache design is justified only if cold translation remains at least 10% of
untraced fork-exec wall time. That design must address process-specific gateway
addresses, cache-base references, code-generation invalidation, W^X, and
relocation rather than persisting raw emitted bytes naively.
