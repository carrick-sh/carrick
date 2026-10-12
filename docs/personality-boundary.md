# Substrate and Personality Boundary

## Overview and Architecture Rule

Carrick's guest execution runs unmodified Linux binaries on host virtualization
platforms (HVF, KVM, bhyve, NVMM). Under the accepted EL1 kernel design
([`docs/superpowers/specs/2026-09-24-el1-kernel.md`](superpowers/specs/2026-09-24-el1-kernel.md)),
low-level substrate objects (MMU and ASID management, frame allocation, GIC,
context switches, run queues, WFI parking, timers, hypercall rings, and
occupancy tables) execute at guest EL1 and as shared `no_std` cores.

**Rule:** A substrate crate or module must not depend on `carrick-abi` (or
designated Linux personality crates) and must not hard-code Linux-specific
values (such as errno literals or syscall opcodes). The personality layer
(EL1 Linux compat layer, runtime dispatch) passes guest-specific values into
substrate APIs.

## Landed Boundary Split: Scheduler Core

The initial substrate boundary split is enforced on `carrick-sched-core`:

1. **Removed hard-coded Linux errno literal:** Removed `ETIMEDOUT_RESULT = -110`
   from `carrick-sched-core`.
2. **Parameterized `expire_timer`:** `ZoneTables::expire_timer(&self, slot: SlotId, now: u64, result: u64)`
   now receives the caller-supplied result value and marks woken records with
   that value upon timer expiration.
3. **Preserved guest semantics:** The Linux EL1 scheduler caller in
   `carrick-el1/src/sched.rs` passes `ETIMEDOUT_RESULT = (-110_i64) as u64`
   at both `expire_timer` callsites (`Sched::enter_idle` and `Sched::serve_irq`).
   All timer race, stale timer, one-winner, and run-queue properties are preserved.
4. **Arbitrary caller values:** Substrate unit tests demonstrate that arbitrary
   non-Linux values (e.g. `0xCAFE_BABE_DEAD_BEEF`) propagate through `expire_timer`
   without assuming Linux errno constants.

## Mechanical Boundary Gate

A mechanical boundary checker is implemented in `carrick-conformance-contract`
under `crates/carrick-conformance-contract/src/bin/check-personality-boundary.rs`
and `personality_boundary.rs`. It is integrated into `just lint-domains`:

```sh
cargo metadata --locked --offline --all-features --format-version 1 > target/cargo-metadata.json
cargo run -p carrick-conformance-contract --bin check-personality-boundary -- --root . --metadata-file target/cargo-metadata.json
```

### Coverage and Verification Mechanics

- **Explicit Substrate Allowlist:** Configured with an allowlist initially
  containing `carrick-sched-core` and `carrick-mmu-core`. The checker fails closed if an allowlisted
  crate is missing from disk or metadata, ensuring missing components are never
  reported as passing.
- **Authoritative Resolved Cargo Dependency Graph:**
  - Operates on the resolved Cargo metadata graph produced with `--all-features`
    under locked/offline conditions for deterministic, reproducible verification.
  - Traverses all normal (`[dependencies]`), target-conditioned (`[target.<target>.dependencies]`),
    build (`[build-dependencies]`), and optional dependency edges across the full resolved graph,
    including transitive path, registry, and git packages.
  - Resolves package aliases and renames (e.g. `my_pkg = { package = "carrick-abi", ... }`),
    tracking the complete dependency path.
  - Explicitly isolates `[dev-dependencies]` at the substrate root, recording them in
    the dev-dependency scope without traversing them into the shipped dependency closure.
  - Verifies that no package in the shipped dependency closure resolves to `carrick-abi`
    or designated personality crates (`carrick-abi`, `carrick-el1-abi`,
    `carrick-signal-core`, `carrick-timer-core`, `carrick-kernel`).
  - Unresolved graph nodes, missing registry entries, or unavailable graph data fail
    closed as hard errors without attempting unlocked or network fallback.
- **Target Source Roots & Module Tree Traversal (`syn` & `proc-macro2`):**
  - Resolves actual target entry points from Cargo metadata (including custom
    `[lib].path`, `[[bin]].path`, and build scripts such as `build.rs`).
  - Any configured substrate crate with zero scanned production source files
    fails closed as a hard error.
  - Parses Rust source files into abstract syntax trees to distinguish actual
    code tokens from prose.
  - Ignores line/block comments and `#[doc = "..."]` attributes, allowing design
    and rationale prose to reference Linux errnos without false positives.
  - **CFG AST Evaluation:** Parses `cfg(...)` attributes into a structured AST.
    Code is only exempt if proven absent during production compilation (`test = false`).
    Conditions such as `#[cfg(not(test))]`, `#[cfg(any(test, feature = "prod"))]`,
    and features containing "test" fail closed and are audited as production code.
  - **Module Tree Traversal:** Recursively traverses the module tree starting from
    crate root entrypoints tracking inherited `#[cfg(test)]` depth. Follows
    `mod name;` and `#[path = "..."] mod name;`. Unreferenced `.rs` files are
    audited fail-closed as production code rather than assuming filename heuristics.
  - **Macro TokenStream Scanning:** Traverses `macro_rules!` definitions and macro
    invocations, scanning their token streams for forbidden literals and symbols.
  - Rejects forbidden production literals (specifically `-110` / `110_i64` in
    negative contexts) and forbidden Linux symbols (`LINUX_*`, `SYS_*`, Linux
    errno names like `ETIMEDOUT`, `EAGAIN`, `EINTR`, and references to `carrick_abi`).
- **Scope Limitations:**
  The gate mechanically verifies the resolved dependency graph closure, AST syntax, and
  declarative macro definition/invocation token streams. It provides mechanical enforcement
  against direct and transitive personality leakage. Procedural macro expansion output is
  not dynamically expanded or evaluated by the checker, and the tool does not claim a complete
  formal proof of absence of all possible encoded semantics.

## Remaining Staged Split Roadmap

As the EL1 migration proceeds, the substrate allowlist and boundary gate will
expand across subsystems:

1. **MMU Core:** The extracted `carrick-mmu-core` is now included in the gate.
   Live-table ownership and guest fault service remain separate memory work.
2. **Increment 3 (Signals & Timers):** Split `carrick-signal-core` and
   `carrick-timer-core` into platform-neutral bitset/timer substrate cores and
   distinct Linux personality mappings.
3. **Increment 4 (VFS & Descriptors):** Separate EL1 file descriptor tables and
   dentry caches into substrate storage and Linux syscall bindings.

### Verification constraints

The checker binds metadata to the selected workspace and the actual substrate
manifest. Every declared production target must exist; a missing target cannot
fall back to a different source file. The unit fixtures are temporary,
self-contained workspaces with resolved graph inputs, so missing scratch files
cannot silently skip regression coverage. The public recipe regenerates locked,
offline, all-feature metadata immediately before checking. Standalone use must
likewise provide freshly generated metadata.

## Terminal execution transport

`carrick-core-abi` owns `NativeRunFailureReason`, `NativeRunFailure` and
`NativeRunFailureConsumer`, including the terminal port/sentinel constants.
The Linux personality supplies lifecycle decisions; the transport authenticates
an exact execution binding and consumes a terminal crossing once. Reason values,
record bytes and refusal behavior are preserved across the ownership move.
The boundary checker rejects fd-core, pipe-core and inotify-core transitively
for core-abi and personality-api, in addition to its existing forbidden personality dependencies.
The mixed Linux EL1 image and shared-record ABI are not certified neutral by
this extraction; their remaining dependency closure is tracked in #237.

`carrick-personality-api` re-exports the neutral failure reason for personality
lifecycle interfaces; transport consumers use its defining core-abi owner.

## Neutral file seam (F0, #224)

`carrick-personality-api::file` re-exports `carrick-core::file`. A carrier
binds one `FileService` to a `CallContext` with `with_files`; unbound calls
return `IoError::Unsupported`. `cx.files()` copies positional I/O through
`cx.user()` using a bounded 64 KiB scratch buffer. Larger single transfers
are refused with `TooLarge`; personalities may submit bounded operations.

`FileRoot`, `FileIdentity` and `FilePinKey` are separate backend-issued
key domains. Backends authenticate their scope. Pins are non-cloning and
have no destructor; explicit release consumes the pin and retires the backend
record. A caller cannot reuse the consumed pin. Backends must refuse stale or
foreign keys with `Stale`. Pending release will own the pin's retirement custody.

`FileOperation::Pending(FilePending)` reserves the owned-continuation API.
F0 cannot construct a pending value. F4 will put owned buffers, the original
operation's progress, and completion authority in the private representation,
without borrowing a call context or retaining a vCPU lease. Read continuations
must also own the guest destination and arrange copy-out when resumed. Adding
host crossing or suspension is outside F0.

`NamePath` permits an empty sequence to name the capability root, but rejects
empty individual components. The boundary gate scans core and the facade and
rejects personality open flags and errno symbols. Pure type tests cover name
validation, request construction and exhaustive neutral errors. Behavioral
red-first witnesses belong to F1/F4 against the real zone/crossing backend;
F0 deliberately supplies no second file implementation.
