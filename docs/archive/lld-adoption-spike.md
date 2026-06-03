# Spike: adopting `lld` without losing USDT probes

**Status:** spike / not scheduled. This documents the work required before the
linker can be switched; it is not a committed plan.

## Why we want this

`carrick-runtime` is a single ~44k-line crate and the workspace links ~27
integration-test binaries plus the CLI, each statically linking its rlib. With
Apple's default `ld64`, an incremental rebuild after a one-line runtime edit
spends ~37s of its ~57s wall time in the linker (see
[`build-decomposition-design.md`](build-decomposition-design.md)). LLVM `lld`
links the same rlib far faster (~2.16× incremental wins were measured before the
revert), so it is the single biggest build-time lever we have.

## Why we can't just flip it

`-fuse-ld=lld` currently **breaks `carrick trace`**. Root cause, as recorded in
[`.cargo/config.toml`](../.cargo/config.toml):

- `usdt` 0.6 hardcodes the macOS **`Linker`** backend
  (`usdt-impl` `build.rs`: `Some("macos") => Backend::Linker`).
- That backend relies on Apple **ld64**'s proprietary DTrace probe-processing
  pass to synthesize the `__DATA,__dof_carrick` Mach-O section at link time.
- `ld64.lld` does not implement that pass, so `__dof_carrick` is never emitted
  and `usdt::register_probes()` finds **zero** probes (verified: 551 probes
  under ld64 → 0 under lld on the same trace).

This is the regression that caused the earlier lld adoption to be reverted. USDT
observability is load-bearing for this project (it is the primary debugger — see
the `carrick-trace` workflow), so losing it is not acceptable.

## The unlock: usdt's `no-linker` backend

`usdt` ships a linker-agnostic backend that builds the DOF (DTrace Object
Format) blob **at runtime** and registers it via the `dof_helper` ioctl on
`/dev/dtrace/helper`, instead of relying on the linker to emit the section. With
that backend the linker no longer participates in probe registration, so `lld`
becomes safe.

The blocker is that `usdt` 0.6 selects the backend at *its own* build time based
on target OS and does **not** expose a stable feature/knob to force `no-linker`
on macOS. So adopting it requires either:

1. **A patched/forked `usdt`** that selects `Backend::NoLinker` on macOS (or
   honors an env/feature toggle), pinned via a `[patch.crates-io]` entry; or
2. **Upstreaming** a feature flag to `usdt`/`usdt-impl` that lets a consumer opt
   into the runtime-DOF path on macOS, then depending on the released version.

## Proposed steps

1. **Reproduce the baseline.** Build the signed release binary with `ld64`,
   confirm `otool -l target/release/carrick | grep dof` shows `__dof_carrick`
   and `carrick trace` emits syscall events. Record probe count
   (`register_dtrace_probes()` / `dtrace -l` count) as the regression oracle.
2. **Switch the backend.** Patch `usdt`/`usdt-impl` to use `Backend::NoLinker`
   on macOS; wire `register_probes()` so DOF is built and `dof_helper`-loaded at
   startup. Confirm a debug build *still registers all probes under ld64* — this
   isolates the backend change from the linker change.
3. **Flip the linker.** Add `-fuse-ld=lld` (via `RUSTFLAGS`/`.cargo/config.toml`
   `[target.aarch64-apple-darwin]`), rebuild, and re-run the step-1 oracle:
   `carrick trace` must emit the same probe set with `lld`.
4. **Gate it in CI.** Add a check that `carrick trace` still fires probes (probe
   count > 0 on a trivial guest), so a future linker/usdt bump can't silently
   re-break observability.
5. **Measure.** Record the incremental-rebuild delta to confirm the win still
   holds with the runtime-DOF path.

## Risks / open questions

- **`dof_helper` availability & SIP.** Runtime DOF registration opens
  `/dev/dtrace/helper`; confirm it works under the codesigned binary and current
  SIP posture without extra entitlements. This is the highest-risk unknown.
- **Maintenance cost of a fork.** A `[patch.crates-io]` fork of `usdt` is a
  standing maintenance burden; prefer upstreaming the toggle if feasible.
- **Probe-fire cost.** Verify the runtime-built DOF path keeps the
  `is_enabled!()` fast path zero-cost when no consumer is attached.

## Verification

The spike is "done" when, with `lld` as the linker:
`otool -l target/release/carrick | grep dof` shows the section **and**
`carrick trace -n 'carrick*:::syscall-entry'` (or the standard trace recipe)
reports the same non-zero probe count as the `ld64` baseline, with the
incremental-rebuild time improved. Addresses roadmap WS-A4 (report §11 lld note).
