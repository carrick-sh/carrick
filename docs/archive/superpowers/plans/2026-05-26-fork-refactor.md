# Fork Refactor (Plan 4) — Status & vfork-exec Design

> Spec: `docs/superpowers/specs/2026-05-26-durable-memory-architecture-design.md` §5 "Fork model" + decomposition item 4: *"fixed-aperture child rebuild, sparse private snapshots, and separate vfork-exec fast path."*

This plan has three parts. Two are **already satisfied** by Plans 1–3 and verified; the third (vfork-exec fast path) is a performance optimization gated on the spec's own open probe #4.

## Part 1 — Fixed-aperture child rebuild ✅ DONE (via Plan 1)

Before Plan 1, guest `MAP_SHARED` mmaps each added a *dynamic* `HvfMappedRegion` (a per-mmap `hv_vm_map`), so the fork rebuild iterated a long, growing list. Plan 1 made the shared window a **single stable aperture** (sub-allocations live inside it, not as separate regions). The fork rebuild (`HvfInner::fork`, trap.rs) now iterates a **short, fixed** mapping set — the image/heap/stack/mmap-arena/shared-aperture/kernel regions — i.e. the fixed-aperture descriptors, exactly as the spec asks. No code change needed in Plan 4; the property fell out of Plan 1.

## Part 2 — Sparse private snapshots ✅ DONE (pre-existing, re-verified)

`clone_region_for_child` (trap.rs) already copies only `mincore`-resident pages (sparse), falling back to a full copy if `mincore` fails. Shared (`guest_shared`) regions are **borrowed** (same host buffer, not copied) so `MAP_SHARED`/`SharedAnon` stay shared across fork. Plans 1–3 reworked the memory/page-table subsystem the child inherits, so this was **re-verified** with two guest fixtures:

- `fork_private_isolation` (new): `MAP_PRIVATE|ANON`, fork, child overwrites, parent re-reads → parent sees ITS value (isolated). **5/5 clean.**
- `shared_mmap_fork` (Plan 1): `MAP_SHARED|ANON` visible across fork. **3/3 clean.**

Together these prove the spec's fork-validation probes ("MAP_PRIVATE dirty-page isolation" + "MAP_SHARED visibility across fork"). The child also inherits the parent's runtime stage-1 page-table edits (the page-table region is a private region, snapshotted); the child's `HvfInner.page_tables` resets to `None` and lazily rebuilds from the inherited host backing on first edit — consistent.

## Part 3 — vfork-exec fast path ⏳ DESIGNED (open probe #4)

**Today:** `clone(CLONE_VM|CLONE_VFORK|CLONE_PIDFD)`+`execve` (Go `os/exec`, glibc `posix_spawn`) routes through the full true-fork path (quiesce → mincore snapshot of all private regions → `libc::fork` → symmetric VM destroy+rebuild). `CLONE_VFORK` is not even decoded. This **works** (verified: `sh -c 'ls|wc -l'`, 8× fork+exec in one shell, `fork_bench`, debian `/bin/ls` all exit 0; Go `os/exec` `TestEcho` green per project notes) but is wasteful: the snapshot is discarded by the child's `execve`.

**Designed optimization (the fast path):**
1. Decode `CLONE_VFORK` (add to `LinuxCloneFlags`).
2. When `CLONE_VFORK` is set, **skip the private-region snapshot** — the child borrows the parent's regions (guest RAM is already host-`MAP_SHARED`, so a `libc::fork` shares it: `CLONE_VM` semantics for free). This is the spec's "does not snapshot the guest address space."
3. Implement `CLONE_VFORK` **blocking**: the parent suspends until the child `execve`s or `_exit`s. REQUIRED for safety — without it, parent and child run concurrently over shared private memory and corrupt each other. Mechanism: a close-on-exec pipe (child closes it on successful `execve`/exit; parent blocks on read).
4. On the child's `execve`, the child rebuilds **its own** VM with the new image (existing `execve_into`); the parent resumes its untouched VM.

**Open probe #4 (the risk, spec-acknowledged):** *"Can the vfork-exec path avoid parent VM teardown entirely while preserving CLONE_VFORK|CLONE_VM blocking semantics?"* The current fork destroys the parent's HVF VM pre-`libc::fork` to avoid the child inheriting a busy VM handle (`HV_BUSY` at `hv_vm_destroy` — see `project_go_osexec_mtfork`). Avoiding the parent teardown requires proving the child can stand up a fresh VM while the parent's VM stays live across `libc::fork` without `HV_BUSY`. This is unproven and is the gating experiment before implementing step 4's "resume parent's untouched VM."

**Decision:** Deferred as a measured call — it is a *performance* optimization (the correctness path works), it touches carrick's most fault-prone subsystem (HVF fork / `HV_BUSY`), and the spec itself frames the key question as an unresolved probe. Implementing it under time pressure risks regressing the working fork path. The prerequisite is to **prove open-probe #4 first** (a focused `HV_BUSY` experiment: keep the parent VM live across `libc::fork`, have the child create a fresh VM, measure), then implement steps 1–4 with the `mmap_churn_threads`-style proof-first discipline.

## Out of scope (noted, not Plan 4)

A backgrounded shell job + `wait` (`sh -c 'echo hi & wait'`) returns exit 1 with correct output (Docker returns 0) — a child-exit-status reaping divergence in the **process/signal** subsystem, not the memory architecture. Pre-existing (Plans 1–3 didn't touch wait4/exit-status). Tracked for a separate process-subsystem fix.

## Validation

- `fork_private_isolation` 5/5, `shared_mmap_fork` 3/3 (fork memory model).
- Regression: `fork_bench`, `sh -c` multi-fork+exec, debian `/bin/ls`, `thread_stress`, `mmap_churn_threads` all green after the Plan 1–3 memory rework.
