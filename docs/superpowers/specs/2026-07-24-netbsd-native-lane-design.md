# NetBSD/x86_64 native lane — design (the seam campaign's acceptance test)

**Date:** 2026-07-24

**Status:** approved (maintainer)

**Scope:** Bring up a NetBSD/x86_64 host lane for carrick's native (no-VMM)
backend, proving the Phase-1/2/3 seam floor makes a new host lane **host-glue,
not a monolith** — the campaign's stated acceptance test.

## The thesis this validates

Phases 1–3 built: `carrick_dsr::lane` traits, `native/` facade + `HostNativeLane`
wiring, shared `identity_memory` + `TranslationCache`, and the x86 translate
engine in `carrick-dsr-x86::translator`. The Phase-2 whole-branch review predicted
"a NetBSD lane genuinely needs only host glue (~15 lines) plus its own waiter-key
body and a JIT dual-map analog." NetBSD/x86_64 is same-ISA, so it **reuses
`carrick-dsr-x86` + `identity_memory` verbatim**; only the host-OS seam is new. If
that thesis holds, this is a small crate + wiring. Where it *doesn't* hold, each
gap is a seam defect to fix in the shared layer — NOT to patch NetBSD-locally.

## Host & toolchain (verified 2026-07-24)

willow VM 201: `root@10.14.14.136`, NetBSD 10.1 amd64, 6c/8G, rust **1.96.0**
(matches pin), **libclang present** (`/usr/pkg/lib/libclang.so`), git 2.53. Host
crates + `carrick-host-bsd` build CLEAN, zero NetBSD cfg gaps. Wake it: STOPPED by
default → `ssh root@willow 'qm start 201'`, ~40s. **bindgen needs
`LIBCLANG_PATH=/usr/pkg/lib` explicit** (this was the netbsd-arm64 stage1 blocker).
No rsync → sync via `git archive | ssh … tar -x` (committed snapshot). See
[[reference to project_netbsd_nvmm_backend memory]].

## The host-OS seam pieces (what's genuinely new)

A new `crates/carrick-native-netbsd` (`#![cfg(target_os = "netbsd")]`), mirroring
`carrick-native-freebsd`:

1. **JIT (`NativeHostJit` + `remap_for_fork_child`).** NetBSD has **no
   `SHM_ANON`** (FreeBSD's dual-map mechanism). The W^X code cache + the
   `Fresh`-on-fork analog need a NetBSD-viable mechanism — candidates: a named
   `shm_open` + immediate `shm_unlink` (POSIX shm, then dual-map), or Darwin-style
   `MAP_JIT`-less `mprotect` toggle (rejected on FreeBSD as process-wide-unsafe —
   verify NetBSD's threading model), or `MAP_PRIVATE` CoW like Darwin's fork-repair
   `Inherited` arm. **The scout decides this before the crate is built.**
2. **Fault shim (`fault.rs`).** Redirect SIGSEGV/SIGBUS/SIGFPE to the guest via
   NetBSD's `mcontext_t` (different layout from FreeBSD's amd64 mcontext). A raw
   signal handler reading NetBSD `__mcontext`/`__gregs` (host TLS is poison there).
3. **Futex (`futex.rs`).** NetBSD has `SYS___futex` (since 9.0). Task-4 of Phase 3
   left **no shared cross-lane futex trait** (FreeBSD-only extraction), so NetBSD
   **mirrors `carrick-native-freebsd::futex`** adapted to `SYS___futex`, and the
   run loop's four direct `carrick_native_freebsd::futex::` call sites (the
   `SharedFutexWait/Wake/Requeue` handlers) need **lane dispatch**. Prior in-repo
   NetBSD futex art: `crates/carrick-vmm-nvmm/src/nvmm_futex.rs` (SYS___futex via
   `carrick_host` — study it). Verify `SYS___futex` supports cross-process +
   requeue + woken-count (FreeBSD's `_umtx_op` lacked count/atomic-requeue, forcing
   the waiter-table workaround — NetBSD may or may not need the same).
4. **Waiter-key (`waiter_key.rs`).** The shared-vs-private discrimination: NetBSD
   has **`MAP_TRYFIXED`, not `MAP_EXCL`** (per the Phase-2 doc correction). The
   `exclusive_fixed_map_flag` seam returns 0 → `NativeMappingTransaction`'s own
   overlap bookkeeping is the sole protection, same as Darwin.
5. **Threads:** NetBSD lwp (`_lwp_create`/`clone`-equivalent) for guest `clone`.

## Wiring (the "one cfg pair" grows a third arm)

- `native/mod.rs`: `NetbsdX8664Lane` struct + a third `HostNativeLane` cfg arm.
- `page_profile.rs`: `(HostOs::NetBsd, Platform::Amd64)` capability-table entry.
- `carrick-portable`: NetBSD arms (partly done, `ea72e207` — complete any gaps the
  build surfaces).
- Known deferred gap: `carrick-hal` kqueue `EVFILT_*` NetBSD wiring (u32-vs-i16
  filter contract) — needed for the event-mux path; may be M2/M3 not M1.

## Fixed decisions

- Same-ISA: reuse `carrick-dsr-x86` + `identity_memory` VERBATIM. If either needs a
  NetBSD change, that's a shared-seam defect → escalate, don't patch locally.
- Scout-first: characterize NetBSD's primitives (SHM/JIT, mcontext, SYS___futex,
  lwp) on VM 201 BEFORE building the crate; each subsystem gets a go/mechanism
  decision or a BLOCKED-with-gap.
- Clean-room: NetBSD ABIs from man-pages/headers/oracle only. The mremap-oracle
  pattern is the template for any NetBSD ABI question; NetBSD `getauxval`/auxv and
  syscall numbers verified against the box's headers, not assumed from FreeBSD.
- Acceptance = a static x86_64 hello ELF runs under `--exec-backend native` on
  NetBSD, then a native gate ladder; a red list is EXPECTED and IS the NetBSD
  worklist (like the aarch64-BSD stage1 red list).

## Risks

- **JIT fork-repair without SHM_ANON** — the highest-uncertainty piece; the scout
  must land a concrete, verified mechanism before Task 1 commits to a crate shape.
- **`SYS___futex` capability** — if it lacks cross-process or requeue semantics the
  lane needs, the waiter-table workaround (or worse) may be required; scout it.
- **Verbatim-reuse thesis** — if `carrick-dsr-x86`/`identity_memory` hit NetBSD
  gaps, the "host-glue only" claim weakens and the fix belongs in the shared layer.
- **Infra** — VM 201 is nested on willow; if it becomes unavailable the lane is
  infra-blocked (maintainer decision), but the seam work already merged as a
  complete deliverable independent of NetBSD.
