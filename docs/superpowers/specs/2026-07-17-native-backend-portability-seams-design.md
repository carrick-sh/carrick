# Native backend portability seams (FreeBSD/x86_64 bring-up) design

**Date:** 2026-07-17

**Status:** approved

**Scope:** Crate-level decomposition of the Darwin/AArch64-only native (DSR)
backend into host-OS and guest-ISA seams, plus the FreeBSD/amd64 native lane
bring-up that the decomposition exists to serve.

## Purpose

The native backend (DSR: selective same-ISA binary translation, no VMM) is
being promoted to supplant the VMM backends, but it exists only for
macOS/AArch64 and is structurally welded to that platform: `bad64`/`dynasmrt`
AArch64 codegen, `gateway_aarch64.S`, Darwin `MAP_JIT` +
`pthread_jit_write_protect_np`, the Darwin commpage/mach timebase, the Darwin
custom-x18 ABI, and a Darwin-mcontext C trap shim. `native_darwin` compiles
unconditionally in `carrick-runtime`, so the `platform-freebsd` build of
`carrick-cli` is red on main today (432 errors: unresolved `bad64`,
`dynasmrt`, `mach2`, `MAP_JIT`, `pthread_jit_write_protect_np`,
macOS-only runtime helpers).

This design cuts the native backend along two seams — **host OS** and
**guest ISA** — as dedicated crates mirroring the existing
`carrick-vmm-*` / `carrick-x86` / `carrick-aarch64` factoring, then brings the
lane up on FreeBSD/amd64 (Linux/x86_64 guests). The native lane is always
same-ISA (guest ISA == host ISA), so "x86_64" and "FreeBSD" are one new lane:
`(FreeBSD, x86_64)` joining `(Darwin, aarch64)`.

## Fixed decisions

- **Crate extraction, not in-module cfg's.** New crates (see graph below);
  exactly one `#[cfg]` pair at the runtime wiring point selects the lane.
  Scattered `#[cfg(target_os/target_arch)]` inside shared native code is a
  review-rejectable smell; per-target dependency gating lives in Cargo.toml
  `[target.'cfg(...)'.dependencies]` and per-crate `build.rs`, following the
  `carrick_bsd_family` precedent.
- **The macOS/AArch64 lane keeps identical behavior.** Extraction is
  move-plus-rename; anything that must change semantically is called out and
  test-covered. Pure moves are verified deleted-lines == added-lines.
- **`ExecutionBackend::NativeDarwin` is renamed `ExecutionBackend::Native`**,
  and the `page_profile` gate becomes a host-capability table keyed on
  (host OS, host arch, host/guest page geometry) instead of
  `HostOs::Macos`-hardcoded checks. Darwin/aarch64 keeps `native16k` +
  composed `linux4k`; FreeBSD/amd64 is uniform 4k-on-4k (no composed-page
  machinery, no `HostPageState::Composed16k` on that lane).
- **x86_64 decode uses `iced-x86`** (MIT), the `bad64` analog; emission uses
  `dynasmrt`'s x64 assembler (already a workspace dep for aarch64). x86 block
  planning is variable-length: the fixed 4-byte stride in the block
  planner/reader generalizes to a decoder-reported instruction length.
- **x86 has no exclusive-monitor problem.** `lock`-prefixed RMW and plain
  loads/stores copy through natively; the entire exclusive-region /
  biased-fusion apparatus is AArch64-only and stays in the aarch64 arch crate.
  The x86 sensitive catalog is: `syscall`, `int 0x80`, `rdtsc`/`rdtscp`,
  `cpuid`, `wrfsbase`/`wrgsbase` (+ `arch_prctl` interplay), and the
  fs/gs-segment-prefix access policy. TLS: guest `%fs` base swaps at the
  gateway (FSGSBASE), the x86 analog of TPIDR/x18 virtualization; exact design
  lands in the M2 design doc, not here.
- **Clean-room rule unchanged:** ABIs from manpages/specs and the Docker
  oracle; no GPL sources. (`iced-x86` is MIT and is a decoder, not kernel
  code.)
- **Milestones gate merges:**
  - **M0** — seams extracted, `platform-freebsd` builds green with the x86
    arch crate present but returning typed `Unsupported` at plan resolution;
    macOS lane still green.
  - **M1** — FreeBSD host crate live: mprotect W^X JIT cache, sigaction trap
    transport reading FreeBSD amd64 `mcontext_t`, kick transport, monotonic
    clock. Provable by host-side unit tests on this lane's hardware.
  - **M2** — x86_64 DSR minimal: decode/emit/gateway for copy-through +
    syscall exits; static hello-world ELF runs under
    `--exec-backend native` on FreeBSD/amd64.
  - **M3** — lifecycle parity: threads/TLS, signals, fork/exec capsule
    (un-gate from macOS; it is POSIX), conformance `Lane` for the FreeBSD
    native backend, LTP/ecosystem ladders.
- **Verification constraint on this rig:** the FreeBSD/amd64 box cannot run
  macOS builds, and a full-workspace `--target aarch64-apple-darwin` check is
  blocked by `ring`'s C build (no Apple SDK). A second blocker: `usdt` 0.6.0
  (latest) selects probe-asm registers by the proc-macro HOST arch, so any
  crate with `carrick-observability`/`usdt` in its graph cross-checks to
  darwin with x86 registers in aarch64 asm — unfixable without forking usdt.
  Consequence: `cargo check --target aarch64-apple-darwin` validates only the
  `ring`-free AND `usdt`-free subset (e.g. `carrick-host`, `carrick-hal`,
  `carrick-dsr-aarch64` if its probe calls stay in the runtime-facing layer);
  the Darwin C shim moves byte-identical. Compensating controls: pure moves
  (deleted == added), and the freebsd platform build compiles the shared code
  with the REAL usdt provider (FreeBSD has DTrace). A macOS `just ci` +
  signed conformance run is still REQUIRED before declaring the refactor
  done for the reference lane.

## Crate graph

```
carrick-dsr             neutral DSR engine + seam traits (no OS, no ISA deps)
  ├─ depends on: carrick-abi, carrick-guest-mem, carrick-mem, carrick-hal,
  │              carrick-thread (ThreadId), carrick-host (cpu/thread facts)
  ├─ contents: dsr types (IR scrubbed of bad64), block planner (stride via
  │            decoder), translation cache + publication index (W^X via
  │            HostJit), profile, orchestration (ProcessTranslator<L>,
  │            ThreadTranslator<L>), artifact store, NativeMappedMemory,
  │            native address layout, page-profile capability table
  └─ traits (the seams):
       NativeLane   — bundle: type Isa: GuestIsa, type Host: NativeHost
       GuestIsa     — type Snapshot (register file, accessor surface),
                      type Context (gateway repr(C) block),
                      decode/classify (+ instruction length),
                      emit_block, patch_direct_branch encoding,
                      gateway entry/exit symbol surface,
                      sensitive catalog + counter plan
       NativeHost   — jit: alloc / begin_write / publish / fork repair /
                            icache_flush
                      trap: install handlers, kick transport, altstack
                      clock: monotonic ticks + frequency for guest counter
                             synthesis
carrick-dsr-aarch64     GuestIsa impl: bad64 + dynasmrt aarch64 decode/emit,
                        gateway_aarch64.S (own build.rs cc), DsrContext,
                        exclusive/biased-fusion analysis + emulation helpers,
                        CNTVCT/CNTFRQ counter plan
carrick-dsr-x86         GuestIsa impl: iced-x86 decode, dynasmrt x64 emit,
                        gateway_x86_64.S, x86 DsrContext, rdtsc counter plan
                        (M0: typed Unsupported stubs; M2: real)
carrick-native-darwin   NativeHost impl: csrc trap shim (byte-identical move
                        of csrc/native_darwin.c), MAP_JIT +
                        pthread_jit_write_protect_np, custom-x18 ABI,
                        commpage/mach timebase          [target: macos]
carrick-native-freebsd  NativeHost impl: mprotect RW↔RX JIT, sigaction shim
                        reading amd64 mcontext_t, SIGPIPE-analog kick,
                        CLOCK_MONOTONIC/TSC clock; reuses carrick-host umtx
                        futex + carrick-host-bsd kqueue  [target: freebsd]
carrick-runtime         native/ integration module (thread runtime, dispatch
                        adapter NativeDispatchMemory, signal lowering, exec
                        capsule, prepared image) — generic over NativeLane,
                        monomorphized at ONE wiring point:
                          #[cfg(all(target_os="macos", target_arch="aarch64"))]
                          type HostNativeLane = DarwinAarch64Lane;
                          #[cfg(all(target_os="freebsd", target_arch="x86_64"))]
                          type HostNativeLane = FreebsdX8664Lane;
                        Other targets: no lane; plan resolution returns typed
                        Unsupported (today's error path, now by capability
                        table rather than hardcoded host check).
```

Naming note: `carrick-dsr*` for the translation engine (the ISA axis),
`carrick-native-<os>` for host glue (the OS axis), matching
`carrick-vmm-<vmm>` / `carrick-host-<os>` conventions.

## What moves where (from carrick-runtime)

| Today | Destination |
|---|---|
| `native_darwin/dsr/{types,block,cache,profile,mod}.rs`, `artifact_spike.rs` | `carrick-dsr` (bad64/dynasmrt refs scrubbed into the seam) |
| `native_darwin/dsr/{decode,emit}.rs`, `gateway_aarch64.S`, aarch64 half of `gateway.rs`, `counter.rs` arch side | `carrick-dsr-aarch64` |
| `native_darwin/mapped_memory.rs`, `address.rs` | `carrick-dsr` (already cfg-free POSIX; DSR-lifecycle USDT probes move with it) |
| aarch64 emulation blobs in `native_darwin.rs` (exclusive/atomic/DC-ZVA emulation, snapshot reg accessors, TPIDR plumbing) | `carrick-dsr-aarch64` behind `GuestIsa::Snapshot` |
| `csrc/native_darwin.c`, MAP_JIT/W^X calls, commpage/mach clock, custom-x18 | `carrick-native-darwin` |
| `native_darwin.rs` thread loop, dispatch adapter, signal lowering, fork/exec orchestration | `carrick-runtime/src/native/` generic over `NativeLane` |
| `native_exec_capsule.rs` (drop the `cfg(macos)` module gate; it is POSIX) | `carrick-runtime/src/native/exec_capsule.rs` |
| `page_profile.rs` backend gate | capability table in `carrick-dsr`, consumed by runtime plan resolution |
| `crate::trap::{host_clock_uptime_ns, host_counter_frequency, shared_futex_waiter_key, shared_file_key_base}` (macOS-only today — part of the freebsd breakage) | neutral homes: clock → `NativeHost::clock` / `carrick-host`; futex keys → `carrick-guest-mem`/`carrick-thread` as appropriate |

## Non-goals

- No behavior or performance change on the Darwin/AArch64 lane; the frozen W1
  perf workload and conformance baselines must be unaffected.
- No production x86 artifact-cache / fusion work (see
  `STOP_PER_BLOCK_ARTIFACT_CACHE` authority; fusion is aarch64-only anyway).
- No attempt to run x86_64 guests on macOS or aarch64 guests on FreeBSD via
  DSR (native is same-ISA by definition; cross-ISA stays VMM/Rosetta).

## Risks

- **Generic infection:** `ProcessTranslator<L: NativeLane>` monomorphizes
  through the thread loop and dispatch adapter. This is the accepted repo
  pattern (`Aarch64EngineCore<V>`, `X86EngineCore<V>`); the wiring stays at
  one alias.
- **Darwin verification gap on this rig** (see fixed decisions): mitigated by
  pure moves, per-crate darwin cross-checks, and a required macOS `just ci`
  before the refactor is declared done.
- **`usdt` probe relocation:** DSR probes move crates; probe names must stay
  stable so `carrick trace` scripts keep working — assert via the existing
  trace smoke path on macOS.

## Implementation drift (2026-07-23)

Recorded after Phase 1 (`docs/superpowers/plans/2026-07-23-native-lane-seam-phase1.md`,
Tasks 1-6) landed on `feat/native-lane-seam-phase1`. This section notes where
the landed shape differs from the fixed decisions and crate graph above; it
does not revise them.

- **FreeBSD JIT cache: an SHM_ANON dual map, not the `mprotect` RW↔RX flip the
  M1 milestone assumed.** `crates/carrick-native-freebsd/src/jit.rs` gives the
  reason:

  > FreeBSD has no Darwin `MAP_JIT`/per-thread write-protect toggle, and
  > `mprotect` RW↔RX flips would be PROCESS-wide — a writer would yank X from
  > under concurrently-executing guest threads.

  The cache is instead one `shm_open(SHM_ANON)` object mapped twice —
  `PROT_READ|PROT_EXEC` at `JitRegion.exec_base`, `PROT_READ|PROT_WRITE` at
  `JitRegion.write_base` — so `begin_thread_write`/`end_thread_write` are
  no-ops and no protection ever flips.

- **`carrick-native-darwin` now exists** (`crates/carrick-native-darwin`,
  commit `ee1d63ba`), as the crate graph above already named it: the Darwin
  host layer's `csrc/native_darwin.c` trap/kick shim moved byte-identical
  (git-mv'd; that file shows 0 added/removed lines in the extraction commit)
  out of `carrick-runtime`, alongside the real `DarwinHostJit` (MAP_JIT /
  `pthread_jit_write_protect_np`) and a `DarwinHost` impl of
  `carrick_dsr::lane::NativeHost`.

- **Fork repair landed as `NativeHostJit::remap_for_fork_child`**
  (`crates/carrick-dsr/src/host.rs`), fulfilling the "fork repair" line in the
  `NativeHost` trait sketch above with this exact named shape: every native
  host answers it, and a fork child never keeps executing against the
  parent's JIT region. `FreebsdHostJit::remap_for_fork_child` always returns a
  brand-new SHM_ANON object (`ForkChildJit::Fresh`) — its `MAP_SHARED` dual
  map would otherwise still be shared with the child. Darwin's `MAP_JIT`
  region is `MAP_PRIVATE` and survives fork as a COW copy already, so
  `DarwinHostJit::remap_for_fork_child` answers `ForkChildJit::Inherited` and
  leaves the real repair to `after_fork_child` (resetting the per-thread
  write-protect bit).

- **M0.8 wiring is a facade module, not a bare `#[cfg]` pair inline at call
  sites.** `crates/carrick-runtime/src/native/mod.rs` is the single place
  `execute.rs`/`runtime.rs`/`lib.rs` reach into a native backend (enforced by
  a drift-guard test reading the three files' committed source); it defines
  `type HostNativeLane` under exactly one
  `#[cfg(all(target_os = ..., target_arch = ...))]` pair per lane
  (`DarwinAarch64Lane` / `FreebsdX8664Lane`), matching this design's "ONE
  wiring point" decision. Per the module's own doc comment this is
  **strangler-interim**: the facade's function bodies still branch on target
  `#[cfg]` and call straight into `native_darwin`/`native_freebsd`; Phase 2 is
  what collapses them into one generic call through `HostNativeLane`.

- **`prepared_image` now lives in `carrick-dsr`**
  (`crates/carrick-dsr/src/prepared_image.rs`), closing the "What moves
  where" table's mapped-memory/address row for that piece; `carrick-dsr-aarch64`
  re-exports it under its old path (`pub use carrick_dsr::prepared_image;`) so
  existing `carrick_dsr_aarch64::prepared_image::…` call sites are unaffected.

- **x86_64 emission is hand-rolled, not `dynasmrt`** — a drift in the "Fixed
  decisions" section above, predating Phase 1 (the seams design's own M2
  milestone, landed 2026-07-17 through 2026-07-20 per `git log --
  crates/carrick-dsr-x86`, tracked by the separate
  `docs/superpowers/specs/2026-07-17-x86-dsr-execution-design.md`). `carrick-dsr-x86/src/emit.rs`
  hand-encodes x86_64 bytes directly (`iced-x86` is used for decode only);
  there is no `dynasmrt` dependency in that crate's `Cargo.toml`. The crate
  now also has a real `gateway.rs`/`gateway_x86_64.S`, block planner
  (`block.rs`), control-flow lowering (`cflow.rs`), and full x87/SSE/AVX
  state transfer (`fxstate.rs`/`legacy_x87.rs`/`xstate_{save,restore}.rs`) —
  well past the crate graph's "M0: typed Unsupported stubs" note above (that
  crate's own `lib.rs` doc comment is itself stale on this point and is a
  separate follow-up, not fixed here).

Not this file's business: the `bsdvm` acceptance-harness campaign's own
`ladder` subcommand addition is tracked in its own plan, not here.
