# NativeLane Seam — Phase 3 design (loop merge → NetBSD bring-up)

**Date:** 2026-07-23

**Status:** approved (maintainer preemptive approval)

**Scope:** Complete the NativeLane seam by merging the two per-lane thread run
loops behind the trait, adopting the remaining shared POSIX modules on the
FreeBSD lane, factoring the cross-process futex host operations behind a seam,
and bringing up the **NetBSD/x86_64 native lane as the campaign's acceptance
test** — proving the shared floor makes a new lane host-glue, not a monolith.

## Why now

Phases 1–2 built the floor: `carrick_dsr::lane` traits, host crates
(`carrick-native-{darwin,freebsd}`), the `native/` facade wiring point, and
the shared `identity_memory` + `TranslationCache` bump-allocator. The final
whole-branch review confirmed "a NetBSD lane genuinely needs only host glue
(~15 lines) plus its own waiter-key body and a JIT dual-map analog." Phase 3
cashes that in. Maintainer roadmap: "after we get into a stable state, we're
going to bring up netbsd on native backend" — we are at that state.

## The four pieces (spec §Phase-2 pointer, now planned)

1. **Loop merge.** The two thread run loops —
   `native_darwin.rs::run_native_dsr_thread_loop_profiled` (~855 lines) and
   `native_freebsd.rs::run_x86_thread` (~1,750 lines) — are the last large
   per-lane duplication. Merge behind a generic `run_native_thread_loop<L:
   NativeLane>` consuming a **grown `GuestIsa`** surface (the part Phase 1
   deliberately deferred: decode/classify + instruction length, gateway
   entry/exit symbol surface, `Context` repr(C) block, sensitive catalog +
   counter plan). This is the campaign's highest-risk refactor: the loops
   differ in fault lowering, xstate handling (x86 XSAVE vs aarch64 FP), and
   signal delivery — the merge must isolate genuinely-shared control flow from
   lane-specific gateway/xstate behind trait methods, NOT unify semantics.
   Precision-scouting task first (Phase-2 discipline), with a **STOP gate** if
   the loops prove too divergent to share without semantic risk — partial
   merge with a documented boundary beats a forced one.

2. **Exec-capsule + prepared_image adoption (FreeBSD).** FreeBSD's inline
   `parse_loadable_elf`/`load_static_pie` duplicate the shared
   `native_prepared_image::prepare` + `native_exec_capsule` that Darwin uses
   (the capsule was un-gated from macOS in Phase 1). Adopt them, delete the
   duplication. Behavior-preserving, LTP-equivalence-gated.

3. **Cross-process futex host trait.** FreeBSD's `_umtx_op` + userspace
   waiter-table and Darwin's `__ulock` are the same conceptual operation
   (cross-process wait/wake/requeue) behind different host primitives. Factor
   a `NativeHost` futex surface so the shared code names the operation, not
   the syscall. NetBSD's `SYS___futex` slots in here.

4. **NetBSD/x86_64 native lane bring-up (the acceptance test).** With 1–3
   done, a NetBSD lane is: a `NativeHost` impl (JIT dual-map — NetBSD lacks
   `SHM_ANON`, so the fork-repair analog needs a NetBSD mechanism; fault shim
   over NetBSD `mcontext_t`; `SYS___futex`; lwp threads), its waiter-key body
   (NetBSD `MAP_TRYFIXED` semantics, not `MAP_EXCL` — per the Phase-2 doc
   correction), and reuse of `carrick-dsr-x86` + `identity_memory` verbatim.
   Prerequisite: the NetBSD toolchain follow-up (pkgsrc rust ≥ workspace
   floor + libclang for bindgen — see [[project_netbsd_nvmm_backend]]); the
   bsdvm netbsd-arm64 VM is aarch64, so x86 NetBSD bring-up needs the willow
   VM 201 (x86_64 NetBSD, already rustup 1.96) or a fresh x86 NetBSD box.
   Acceptance: a static x86_64 ELF runs under `--exec-backend native` on
   NetBSD, and the native gate ladder reaches parity-minus-known-gaps.

## Fixed decisions

- Same-ISA lane invariant holds: NetBSD/x86_64 reuses `carrick-dsr-x86`
  entirely; the seam is host-OS only.
- The loop merge grows `GuestIsa` but stays sized-to-consumption (only what
  the generic loop actually calls); no speculative trait surface.
- Every behavior-adjacent task carries LTP-gate pass-set equivalence
  (FreeBSD box, before/after programmatic diff) — the Phase-1/2 gate.
- No scattered `#[cfg(target_os)]` in shared code; the wiring point stays the
  single cfg pair; NetBSD joins `HostNativeLane` as a third arm.
- NetBSD bring-up is staged behind the seam work: pieces 1–3 must land and
  gate-clean on FreeBSD (the proving lane) BEFORE the NetBSD lane starts, so
  NetBSD validates a finished seam rather than co-evolving with it.

## Risks

- **Loop merge is the crux** — if the aarch64/x86 loops can't share without
  semantic entanglement (fault lowering + xstate are the danger zones), the
  fallback is a thinner shared skeleton with more lane-specific trait
  callbacks. The scouting task decides; a forced merge that regresses either
  lane's LTP set is unacceptable.
- **NetBSD JIT fork-repair** — no `SHM_ANON`; the `remap_for_fork_child`
  `Fresh` analog needs a NetBSD-viable mechanism (named shm + unlink, or
  MAP_PRIVATE CoW like Darwin). Scout during the NetBSD task before committing
  to the host-crate shape.
- **NetBSD x86 test host** — the current bsdvm NetBSD VM is aarch64; x86_64
  NetBSD lane bring-up needs willow VM 201 or equivalent. If no x86 NetBSD
  host is available, the NetBSD task is BLOCKED on infra (maintainer decision)
  and Phase 3 lands pieces 1–3 as a complete sub-deliverable.

## Correction (2026-07-24): Task-3 category error

The Task-3 scout found — and the controller verified — that §"2. Exec-capsule +
prepared_image adoption (FreeBSD)" above is WRONG: `native_prepared_image::prepare`
+ `native_exec_capsule` are the Darwin execve *self-reexec transport* (hard-gated
`cfg(macos,aarch64)`), not a shared ELF loader, and `native_freebsd.rs` never
duplicated them. There was no such duplication to remove. The REAL FreeBSD-loader
dedup (maintainer-approved re-scope) is adopting `carrick_mem::AddressSpace`
(`load_elf_bytes...` + `with_native_vdso` + `with_linux_initial_stack`) — which
Darwin already uses and FreeBSD hand-rolls via `map_one_elf`. See the plan's
re-scoped Task 3.
