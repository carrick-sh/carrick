# Same-ISA Dynamic Syscall Rewriter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Darwin-native backend's blind in-place instruction
patching and per-syscall `SIGTRAP` path with an opt-in AArch64 same-ISA dynamic
binary translator that leaves original guest code unmodified, reports Linux
guest PCs precisely, supports coherent executable-page generations, and proves
correctness against the Linux oracle and publishes measured performance without
requiring the legacy trap executor as a control lane.

**Architecture:** Keep the existing Darwin-native loader, direct guest-memory
mapping, dispatcher, process model, signal machinery, and fork/exec/thread
coordination. Add an in-runtime DSR that decodes from actual guest entry points,
emits translated basic blocks into a Darwin `MAP_JIT` cache, and exits through a
small host/guest context gateway for syscalls, indirect resolution, kicks,
faults, and invalidation. Work on the legacy trap executor is out of scope: this
plan neither preserves it as a control nor gates DSR progress on it.

**Tech Stack:** Rust 1.96.0; `bad64` for AArch64 decoding; `dynasmrt` for
AArch64 emission and relocations; `proptest` for generated relocation and cache
state tests; existing `goblin`, `libc`, and `parking_lot`; Carrick's signed build,
probe, conformance, and Docker-oracle infrastructure.

## Global Constraints

- The initial supported profile is macOS/AArch64 plus `native16k`; `linux4k` is
  an explicit typed rejection in DSR mode until a later plan adds it.
- Original guest executable pages are readable but not executable in DSR mode.
  No supported path may execute an untranslated Linux `svc #0` on Darwin.
- Do not scan or modify original guest executable bytes in DSR mode.
- Reuse `bad64`; do not implement a general AArch64 decoder.
- Use `dynasmrt` for generated AArch64 instructions and relocation fixups; raw
  encoders are allowed only for a reviewed instruction not expressible by the
  selected `dynasmrt` version, with decode-back tests for every emitted word.
- Use the existing `libc` crate for Darwin APIs. Do not add ad-hoc C ABI
  declarations when `libc` exposes the symbol.
- Keep the stable context gateway small and auditable. Translated code reserves
  physical `x28` as the per-thread `DsrContext` pointer; guest `x18` and guest
  `x28` are virtualized in that context. Physical `x17` is the internal edge
  register and is restored from guest state at every block entry. Ordinary
  entry and indirect targets must not transit physical `x18`, because Darwin's
  custom-x18 state is not reliable across asynchronous signal/TLS traffic. The
  gateway must preserve every guest-visible GPR, SP, NZCV, FP/SIMD registers,
  FPSR, FPCR, guest TLS state, and the original guest PC before entering Rust.
  A copy-only block must reject instructions mentioning virtualized `x18` or
  `x28`; those require explicit lowering before entering the fast path.
- The syscall gateway must be exception-free and must not read or write below
  guest SP. A signal/ucontext exit is not an acceptable DSR transport because
  it retains the trap cost this work is intended to remove.
- Unsupported instructions and transitions fail with a typed diagnostic that
  includes the guest PC, raw instruction word, decoded operation, cache
  generation, and block start. Never fall through to original guest code.
- No performance percentage is a requirement. Measure p50, p95, minimum, IQR,
  and sample count before making a performance claim.
- The authoritative current comparison point is the 2026-07-11 `native16k`
  result: 376/376 static-musl probes byte-identical with Docker. The checked-in
  829/1492 strict-LTP result predates roughly 45 native commits and must be
  refreshed before it is used as a final DSR parity claim.
- Carrick and Docker oracle phases never overlap. Stamp `CARRICK_RUN_ID` and
  reap only with `scripts/sudo/kill.sh <run-id>`.
- Build runnable binaries with `just build`; never run an unsigned `cargo build`
  artifact and never use `lld`.
- Clean-room rules remain in force: do not read Linux kernel or other GPL
  implementation source.
- DSR remains experimental, opt-in, same-ISA, and trusted-code-only throughout
  this plan. It does not become the default automatically.

---

## Audit of the RFC

The original RFC described a greenfield runtime, but the repository already has
a substantial Darwin-native backend in
`crates/carrick-runtime/src/native_darwin.rs` and
`crates/carrick-runtime/csrc/native_darwin.c`. It already provides:

- direct guest mappings for `native16k` and a guarded `linux4k` profile;
- a legacy trap-based executor for `svc #0`, TPIDR operations, selected
  ID-register reads, `dc zva`, and cache-maintenance instructions (out of scope
  as a DSR control lane);
- executable-page transitions that patch newly executable mappings;
- full native ucontext capture including GPR, FP/SIMD, FPSR, and FPCR state;
- guest/host TLS and x18 switching;
- clone threads, kicks, Linux signal delivery, `rt_sigreturn`, fork, vfork,
  execve, wait, futex, and page-fault integration;
- 376/376 measured native16k static-musl probe parity as of 2026-07-11.

The DSR is therefore a new instruction-execution vehicle inside the current
native backend, not a replacement runtime or a new HAL backend.

The following RFC claims are intentionally removed:

- “99.9% byte-for-byte pass-through” and “100% native speed.” AArch64
  PC-relative data instructions, branches, calls, literal loads, indirect
  control flow, and sensitive system instructions require relocation or exits.
- “95% to 98%” syscall-latency reduction. The signal tax is plausible but must
  be measured separately from dispatcher and host-syscall cost.
- “100% fidelity in days.” Differential and property tests reduce uncertainty;
  they do not prove the full ISA.
- AI-generated encoding tables. Carrick will use maintained decoder and
  assembler crates instead.
- A pinned guest-state register such as x28. Guest code may legally use every
  GPR; the initial design reserves no guest-visible register.
- “Executable-only” cache pages. The actual contract is Darwin-approved
  write/execute phase separation using `MAP_JIT`,
  `pthread_jit_write_protect_np`, `mprotect`, and explicit I-cache publication,
  proven on supported hosts.
- Identity `GuestMemory` as unchecked pointer access. The existing native memory
  object owns bounds, permissions, page profiles, aliases, write/execute
  transitions, and fork/exec behavior and remains authoritative.

## Target execution model

```text
NativeMappedMemory (guest bytes, readable and non-executable in DSR mode)
          |
          | read instruction at GuestVa
          v
bad64 decoder -> typed BlockPlan -> dynasmrt emitter
                                      |
                                      v
                         MAP_JIT TranslationCache
                                      |
                     +----------------+----------------+
                     |                |                |
                 direct edge      indirect edge      exit
                     |                |                |
                cached block     resolver lookup   NativeDsrExit
                                                       |
                                            audited context gateway
                                                       |
                                      existing native dispatch loop
```

The cache key is `(GuestVa, CodeGeneration)`. Every published block carries:

- its guest start and exclusive guest end;
- its code generation;
- its cache start and exclusive cache end;
- an instruction-granular guest-PC to cache-PC map;
- an inverse cache-PC to guest-PC map;
- outgoing direct-link patch sites;
- the guest executable pages from which it was decoded.

The first implementation uses
`parking_lot::RwLock<BTreeMap<(GuestVa, CodeGeneration), PublishedBlock>>` for
the process-wide block index and a per-thread 1,024-entry direct-mapped target
cache for indirect branches. Lock-free lookup, direct block chaining, epoch
reclamation, and larger or set-associative target caches require profile
evidence and are not prerequisites for correctness.

## File structure

New code stays within `carrick-runtime` until the interface is stable:

| File | Responsibility |
| --- | --- |
| `crates/carrick-runtime/src/native_darwin/dsr/mod.rs` | Public DSR orchestration and integration contract |
| `crates/carrick-runtime/src/native_darwin/dsr/types.rs` | Typed PCs, generations, block IDs, exits, and errors |
| `crates/carrick-runtime/src/native_darwin/dsr/decode.rs` | `bad64` classification into the small DSR relocation IR |
| `crates/carrick-runtime/src/native_darwin/dsr/block.rs` | Basic-block construction and termination rules |
| `crates/carrick-runtime/src/native_darwin/dsr/emit.rs` | `dynasmrt` emission and decode-back verification helpers |
| `crates/carrick-runtime/src/native_darwin/dsr/cache.rs` | `MAP_JIT` allocation, publication, indexes, and PC maps |
| `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs` | Safe wrapper around the host/guest context transition |
| `crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S` | Minimal stable context save/restore gateway |
| `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs` | Direct-vs-translated CPU-state test harness |
| `crates/carrick-runtime/src/native_darwin.rs` | Select DSR, feed memory generations, reuse dispatcher loop |

The assembly file is compiled only for macOS/AArch64 from
`crates/carrick-runtime/build.rs`. No new workspace crate is created in this
plan.

---

### Task 1: Add the typed DSR selection surface and baseline evidence

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/carrick-runtime/Cargo.toml`
- Modify: `crates/carrick-spec/src/lib.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/lifecycle.rs`
- Modify: `crates/carrick-engine/src/lib.rs`
- Modify: `crates/carrick-runtime/src/container.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-runtime/src/page_profile.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `conformance-probes/src/bin/perf_trap_floor.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `crates/carrick-cli/tests/perf_support/cases.rs`
- Create: `docs/perf-results/native-dsr-syscall-floor.jsonl`

**Interfaces:**

- Produces: `NativeCodeModeRequest::{Brk,Dsr}` in `carrick-spec`, serialized as
  `brk` and `dsr`.
- Produces: CLI/environment selection
  `--native-code-mode <brk|dsr>` / `CARRICK_NATIVE_CODE_MODE`.
- Constraint: default is `Brk`; `Dsr` rejects non-AArch64, non-macOS, and
  non-`native16k` execution before image mapping.

- [x] **Step 1: Add a failing serialization and default test**

  Add tests beside the existing execution-backend tests in
  `crates/carrick-spec/src/lib.rs` asserting that default `RunSpec` state selects
  `Brk`, and that `Dsr` serializes to the exact JSON string `"dsr"`.

- [x] **Step 2: Run the focused test and verify red**

  Run:

  ```bash
  cargo test -p carrick-spec native_code_mode --lib
  ```

  Expected: compilation fails because `NativeCodeModeRequest` does not exist.

- [x] **Step 3: Thread the typed request through every run surface**

  Add the enum, a `native_code_mode` field next to `native_page_profile`, and
  the matching CLI arguments on `run`, `run-elf`, and container-create paths.
  Extend `RunStaticElfBackendOptions`. At the native execution boundary, call a
  single validator with this contract:

  ```rust
  fn validate_native_code_mode(
      mode: carrick_spec::NativeCodeModeRequest,
      plan: &crate::page_profile::ExecutionPlan,
  ) -> Result<(), RuntimeError>;
  ```

  `Brk` returns `Ok(())`. `Dsr` returns a typed `RuntimeError::Unsupported` unless
  the plan is Darwin-native, AArch64, and `NativePageProfile::Native16k`.

- [x] **Step 4: Establish the pre-DSR performance floor**

  Extend the existing `perf_trap_floor` raw-`getpid` probe with a raw `gettid`
  case and an equal empty-loop control. Record the historical trap-transport
  floor once, then use DSR-only measurements for continuing work. Store
  provenance, p50, p95, min, IQR, and `n` in the new JSONL evidence file. This
  is observation, not a legacy-mode compatibility requirement.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-spec native_code_mode --lib
  cargo test -p carrick-cli --test conformance native --no-fail-fast
  just fmt-check
  ```

  Expected: all pass and explicit DSR selection reaches the typed native
  boundary. Legacy-mode behavior is not a gate for subsequent tasks.

  Commit: `feat(native): add typed DSR execution selection`

---

### Task 2: Introduce typed DSR addresses, exits, and decoder IR

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/carrick-runtime/Cargo.toml`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/types.rs`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- Consumes: `carrick_guest_mem::GuestVa` and `HostVa`.
- Produces:

  ```rust
  pub(super) struct CodeGeneration(u64);
  pub(super) struct BlockId(u64);
  pub(super) struct CacheOffset(u32);
  pub(super) struct CacheVa(HostVa);

  pub(super) enum InstAction {
      Copy(u32),
      PcRelative(PcRelativeInst),
      Direct(DirectExit),
      Indirect(IndirectExit),
      Syscall { resume: GuestVa },
      Sensitive(SensitiveExit),
      Unsupported { word: u32, op: bad64::Op },
  }

  pub(super) enum NativeDsrExit {
      Syscall { resume: GuestVa },
      ResolveIndirect { source: GuestVa, target: GuestVa, link: Option<GuestVa> },
      Fault { guest_pc: GuestVa, signal: i32, code: i32, address: GuestVa },
      Kick { resume: GuestVa },
      StaleGeneration { guest_pc: GuestVa, observed: CodeGeneration },
      Unsupported { guest_pc: GuestVa, word: u32, op: bad64::Op },
  }
  ```

- [x] **Step 1: Write table tests for the initial instruction classes**

  Cover ordinary arithmetic, `svc #0`, `b`, `bl`, `b.cond`, `cbz`, `cbnz`,
  `tbz`, `tbnz`, `br`, `blr`, `ret`, `adr`, `adrp`, literal loads, TPIDR_EL0
  reads/writes, CTR_EL0, DCZID_EL0, `dc zva`, `dc cvau`, and `ic ivau`. Each test
  asserts the typed action and exact guest target/resume address.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime native_darwin::dsr::decode --lib
  ```

  Expected: compilation fails because the DSR module and types do not exist.

- [x] **Step 3: Implement classification with `bad64`**

  Decode with `bad64::decode(word, guest_pc.0)`. Match `bad64::Op` and typed
  operands; do not infer instruction classes from mnemonic strings. Preserve the
  raw word in every action so diagnostics and decode-back tests can report it.
  Any decoded operation not explicitly supported becomes `Unsupported`; decode
  errors become a DSR error carrying the raw word and PC.

- [x] **Step 4: Add property tests for target arithmetic**

  Add `proptest = "1.11.0"` to `[workspace.dependencies]` and
  `proptest.workspace = true` to `carrick-runtime`'s `[dev-dependencies]`.
  Generate aligned guest PCs and legal immediate ranges for the direct and
  PC-relative classes. Assert that classification produces the same
  architectural target as the instruction's encoded immediate, including
  negative displacements and page-rounded `adrp`.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime native_darwin::dsr::decode --lib
  just clippy
  ```

  Expected: all decoder and property tests pass with no string-based decode
  logic and no bare address-domain integers crossing the module interface.

  Commit: `feat(native): classify AArch64 blocks for DSR`

---

### Task 3: Build and prove the Darwin JIT code cache

**Files:**

- Create: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- Produces:

  ```rust
  pub(super) struct TranslationCache;

  impl TranslationCache {
      pub(super) fn new(capacity: usize) -> Result<Self, DsrError>;
      pub(super) fn begin_write(&mut self, len: usize) -> Result<CacheWriter<'_>, DsrError>;
      pub(super) fn publish(&mut self, writer: CacheWriter<'_>)
          -> Result<PublishedCode, DsrError>;
      pub(super) fn contains_host_pc(&self, pc: HostVa) -> bool;
  }
  ```

- Constraint: writable and executable phases never overlap for a cache page.
- Constraint: cache capacity exhaustion returns a typed error in this task; no
  eviction or reclamation is added yet.

- [x] **Step 1: Write fork-isolated executable-memory tests**

  Tests must prove: cache allocation succeeds; a generated `mov x0, #42; ret`
  returns 42; publication flushes I-cache; a second write changes the result;
  execution during the write phase faults in the child; writing during the
  execute phase faults in the child; and a non-cache host PC is rejected.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_cache --lib
  ```

  Expected: compilation fails because `TranslationCache` does not exist.

- [x] **Step 3: Implement the narrow Darwin policy wrapper**

  Allocate with `MAP_PRIVATE | MAP_ANON | MAP_JIT`. Centralize
  `pthread_jit_write_protect_np` and I-cache publication in the existing native
  C companion only where the `libc` crate lacks a stable declaration. The Rust
  wrapper owns bounds, page alignment, state transitions, and lifetime. It must
  never expose a raw mutable cache slice outside `CacheWriter`.

- [x] **Step 4: Test fork inheritance explicitly**

  Publish a block, fork, execute it in the child, and report the result through
  the exit status. Then prove the child can discard inherited unpublished
  writer state and begin a clean write transaction. This is only a memory-policy
  proof; metadata repair lands in Task 11.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_cache --lib
  just fmt-check
  just clippy
  ```

  Expected: every fork-isolated protection test passes on macOS/AArch64 and is
  cfg-skipped elsewhere.

  Commit: `feat(native): add a Darwin DSR translation cache`

---

### Task 4: Form straight-line blocks and emit instruction maps

**Files:**

- Create: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `Cargo.toml`
- Modify: `crates/carrick-runtime/Cargo.toml`

**Interfaces:**

- Produces:

  ```rust
  pub(super) struct BlockPlan {
      pub(super) start: GuestVa,
      pub(super) end: GuestVa,
      pub(super) generation: CodeGeneration,
      pub(super) instructions: Vec<PlannedInst>,
      pub(super) exit: PlannedExit,
  }

  pub(super) struct PcMapEntry {
      pub(super) guest: GuestVa,
      pub(super) cache: CacheOffset,
  }

  pub(super) fn plan_block(
      memory: &NativeMappedMemory,
      start: GuestVa,
      generation: CodeGeneration,
      max_instructions: usize,
  ) -> Result<BlockPlan, DsrError>;
  ```

- Constraint: block formation stops at the first syscall, sensitive instruction,
  direct branch, indirect branch, return, unsupported operation, page boundary,
  or configured maximum. It never decodes through an exit.

- [x] **Step 1: Write boundary and constant-pool tests**

  Construct byte regions containing ordinary instructions, an early `svc`, a
  branch, a page boundary, and a data word equal to `0xd4000001` after an
  unconditional branch. Assert that only reachable instructions before the
  terminator enter the plan and that the data word remains unchanged.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_block --lib
  ```

  Expected: compilation fails because `BlockPlan` and `plan_block` do not exist.

- [x] **Step 3: Add `dynasmrt` and emit the copy-only subset**

  Add `dynasmrt = "5.0.0"` to `[workspace.dependencies]` and
  `dynasmrt.workspace = true` to the macOS/AArch64 target dependencies in
  `carrick-runtime`. Emit with
  `dynasmrt::VecAssembler<dynasmrt::aarch64::Aarch64Relocation>` so Carrick's
  `MAP_JIT` cache, not dynasmrt's generic executable allocator, owns final code
  memory. Emit ordinary position-independent instructions as their original
  32-bit words, append a typed exit stub for the block terminator, and publish
  the instruction-granular PC map atomically with the code. Reject every
  `PcRelative`, `Direct`, and `Indirect` action until its later task lands.

- [x] **Step 4: Decode back every emitted block in tests**

  Read the published cache bytes and run `bad64::decode` at their cache
  addresses. Assert that copied instructions retain their operation and
  operands and that every PC-map entry points to an instruction boundary.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_block --lib
  cargo test -p carrick-runtime dsr_emit --lib
  just clippy
  ```

  Expected: straight-line plans publish with exact forward and inverse maps;
  unsupported exits are typed and deterministic.

  Commit: `feat(native): emit mapped DSR basic blocks`

---

### Task 5: Land the context gateway and first real syscall round trip

**Files:**

- Create: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S`
- Create: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Modify: `crates/carrick-runtime/build.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- Consumes: existing `NativeUcontextSnapshot`, TLS/x18 switching, dispatcher
  request construction, and resume machinery.
- Produces:

  ```rust
  pub(super) fn enter_translated(
      entry: CacheVa,
      snapshot: &mut NativeUcontextSnapshot,
      exit: &mut NativeDsrExit,
  ) -> Result<(), DsrError>;
  ```

- Constraint: Rust code always runs on the saved host stack with host TLS/x18
  state; translated guest code always runs on the guest stack with guest state.
- Constraint: translated code keeps physical `x28` equal to the current
  `DsrContext`. Guest `x18` and `x28` live in the context and are never silently
  exposed as their physical registers. Physical `x17` carries internal edges
  only until the target block restores guest `x17`.
- Stop condition: do not proceed to Tasks 6-11 unless a straight-line syscall
  round trip completes without SIGTRAP/SIGSEGV/SIGBUS and the optimized
  30-sample gateway floor demonstrates that the exception-free boundary is
  materially below the historical trap-transport floor. This is a bounded
  feasibility proof, not an ongoing legacy-mode compatibility gate or a
  promised final workload speedup.

- [x] **Step 1: Write red full-state and reserved-register oracle tests**

  Seed x0..x30, SP, NZCV, v0..v31, FPSR, and FPCR with distinct values. Execute
  a translated straight-line block that changes only an enumerated subset and
  exits. Compare the resulting state with the same instruction sequence run
  directly in a fork-isolated native function. Include x16, x17, x18, and LR
  explicitly. Add decode-table and generated tests proving no instruction whose
  operands mention `x18` can remain `InstAction::Copy`.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_gateway --lib
  ```

  Expected: compilation fails because the gateway does not exist.

- [x] **Step 3: Implement the audited exception-free gateway**

  `DsrContext` owns the complete guest snapshot plus the saved host stack and
  callee-saved state. Assembly entry installs `DsrContext *` in physical x28,
  branches to translated code through physical x17, and lets the emitted block
  restore guest x17 before its first guest instruction. Guest x18 and x28 are
  explicitly virtualized. Exit stubs save guest x17 through physical x28,
  branch via x17, save the remaining state, restore the host stack and host x18
  ABI, write a `NativeDsrExit`, and only then return to Rust. Resume performs the
  inverse transition. Add compile-time offset assertions shared with the
  existing C ucontext layout. Do not call Rust directly on the guest stack and
  do not use guest stack memory as gateway scratch.

- [x] **Step 4: Route translated `svc #0` through the existing dispatcher**

  Change the DSR `svc` terminator to exit with `NativeDsrExit::Syscall` and a
  guest resume PC of `svc_pc + 4`. Reuse the existing syscall frame extraction,
  `SyscallDispatcher`, outcome handling, signal-delivery cycle, and resume
  snapshot. Add a DSR-only integration test executing raw `getpid`, writing the
  result, and exiting.

- [x] **Step 5: Run the preliminary performance feasibility gate**

  Compare the exception-free gateway with the already-recorded historical
  trap/signal floor in one optimized test binary. Use 30 batches with equal
  transition counts and report both p50 values and their ratio. This isolates
  the boundary mechanism; it is not an end-to-end syscall or workload claim.
  The bounded 2026-07-11 proof measured 30 batches of 200 transitions: DSR p50
  31.2 ns versus the historical trap floor of 2207.9 ns (ratio 0.014). Later
  tasks measure DSR directly and do not rerun or preserve the legacy executor.

- [x] **Step 6: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_gateway --lib
  cargo test --release -p carrick-runtime \
    dsr_gateway_perf_feasibility_30_samples --lib -- --ignored --nocapture
  ```

  Expected: full-state and straight-line dispatcher oracles match, no transport
  signal is involved in DSR entry/exit, and the 30-sample gateway floor clears
  the Task 5 p50 feasibility gate. If it does not, stop and retain Tasks 1-4 as
  the bounded experiment rather than continuing on hoped-for gains.

  Commit: `feat(native): dispatch syscalls through the DSR gateway`

---

### Task 6: Relocate PC-relative data instructions

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**

- Extends: `PcRelativeInst` for `adr`, `adrp`, integer and SIMD literal loads,
  and literal-address prefetch. Any other `bad64`-identified PC-relative
  operation remains a typed unsupported exit until Task 12 adds a red oracle
  case and a reviewed lowering.
- Produces: semantically equivalent emitted sequences that leave every
  non-destination register unchanged.

- [x] **Step 1: Write generated relocation tests across distance classes**

  For each instruction, generate guest and cache addresses that are near, far,
  positive, negative, page-aligned, and page-crossing. For `adr`/`adrp`, derive
  the architectural target independently from the encoded immediate and compare
  it with the translated destination; direct execution at the cache address is
  not a valid oracle because it has a different PC. For literal operations,
  compare the translated loaded value and preserved state with ordinary host
  memory values. Include xzr/wzr and 32-bit destination behavior where
  architecturally legal.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_pc_relative --lib
  ```

  Expected: tests fail with the typed unsupported action from Task 4.

- [x] **Step 3: Emit relocations with audited AArch64 encodings**

  Materialize `adr`/`adrp` targets directly in the architectural destination.
  Materialize integer literal addresses in their destination before loading.
  SIMD loads, prefetches, zero-register destinations, and virtual guest x18 use
  physical x17 only after saving its current guest value in `DsrContext`, and
  restore it before the next guest instruction. Literal loads read the original
  guest data address, not a copied constant, so guest writes remain visible.
  Decode every fixed encoding in tests and route any unreviewed PC-relative form
  through a typed unsupported exit.

- [x] **Step 4: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_pc_relative --lib
  cargo test -p carrick-runtime native_darwin::dsr::oracle --lib
  ```

  Expected: generated immediate targets match independently derived AArch64
  semantics; literal values and preserved state match host memory; and every
  emitted instruction decodes at its published cache address.

  Commit: `feat(native): relocate DSR PC-relative instructions`

---

### Task 7: Add direct control flow and lazy block linking

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Modify: `conformance-probes/src/bin/syscallregpreserve.rs`
- Modify: `crates/carrick-cli/tests/probe-oracle/arm64-musl/syscallregpreserve`

**Interfaces:**

- Supports: `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `tbz`, and `tbnz`.
- Produces: a correct resolver exit for an unpublished direct target and an
  optional link patch once source and destination blocks are both published.
- Constraint: `bl` writes the original guest return PC to x30, never a cache PC.

- [x] **Step 1: Write graph-shaped execution tests**

  Cover taken/not-taken conditional edges, forward/backward loops, nested calls,
  guest LR observation, a direct target on another guest page, and a source
  block linked before and after its destination is published.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_direct_flow --lib
  ```

  Expected: tests fail with typed unsupported direct exits.

- [x] **Step 3: Implement correct lazy resolution first**

  Every unresolved edge exits with its architectural guest target. The Rust
  coordinator looks up or translates `(target, generation)`, then resumes at
  the cache address. Direct patching is added only after the slow path passes all
  graph tests. Patches use a JIT write-protection transaction and one aligned
  atomic instruction store followed by instruction-cache invalidation; an
  executor must see either the resolver branch or the complete linked branch.

- [x] **Step 4: Verify and commit**

  Before the commit, extend `syscallregpreserve` with x18, NZCV, and FP/SIMD
  preservation cases and record byte-identical native-Linux output. Do not claim
  that the shipped Rust static PIE runs under DSR yet: its startup path requires
  indirect returns from Task 8 and sensitive TLS/system-register handling from
  Task 9. Task 9 runs this probe under DSR and owns the 30-sample signed-CLI
  `perf_trap_floor` stop gate at the earliest honest end-to-end point.

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_direct_flow --lib
  cargo test -p carrick-runtime native_darwin::dsr::oracle --lib
  ./scripts/build-probes.sh --native-pie
  docker run --rm --platform linux/arm64 \
    -v "$PWD/conformance-probes:/p:ro" alpine:latest \
    /p/target/native-pie/aarch64-unknown-linux-musl/release/syscallregpreserve
  ```

  Expected: all direct-flow tests match architectural state before and after
  linking, and Linux reports every extended syscall-preservation field `true`.

  Commit: `feat(native): link direct DSR control flow`

---

### Task 8: Add indirect branches and returns with a correct resolver

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`

**Interfaces:**

- Supports: `br`, `blr`, and `ret`.
- Produces:

  ```rust
  fn resolve_indirect(
      &self,
      source: GuestVa,
      target: GuestVa,
      generation: CodeGeneration,
  ) -> Result<CacheVa, DsrError>;
  ```

- Constraint: the initial implementation always uses the typed Rust lookup.
  The only fast cache is a per-thread
  `(GuestVa, CodeGeneration, CacheVa)` entry.

- [x] **Step 1: Write indirect-control tests**

  Cover function pointers, alternating two targets at one callsite, recursive
  returns, tail calls, `blr` guest-LR semantics, stale generation rejection, and
  an indirect target outside an executable guest mapping.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_indirect_flow --lib
  ```

  Expected: tests fail with typed unsupported indirect exits.

- [x] **Step 3: Implement the resolver and thread-local target cache**

  Validate target alignment and guest execute permission before lookup. On a
  miss, translate synchronously and publish before resuming. `blr` sets x30 to
  the guest instruction's resume PC. `ret` treats its register value only as a
  guest target; a cache address in a guest register is rejected.

- [x] **Step 4: Profile before considering assembly lookup**

  Add counters for resolver exits, resume-entry hits, translations, and
  duplicate publication races. Verify their state transitions with handcrafted
  call/return ELFs here. Record shipped static-PIE counts after Task 9 supplies
  the sensitive startup instructions those binaries require. Do not implement
  a larger assembly hash table unless indirect misses are a material share of
  runtime after Task 12 workloads.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_indirect_flow --lib
  cargo test -p carrick-runtime native_darwin::dsr::oracle --lib
  ```

  Expected: indirect-flow state matches independently asserted architectural
  state and invalid targets produce deterministic diagnostics.

  Commit: `feat(native): resolve indirect DSR control flow`

---

### Task 9: Translate faults, Linux signals, and sensitive instructions

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs`

**Interfaces:**

- Consumes: existing native TPIDR, CTR_EL0, DCZID_EL0, `dc zva`, signal frame,
  fault lowering, `rt_sigreturn`, and kick behavior.
- Produces: exact inverse lookup from any published cache instruction PC to its
  Linux guest PC.

- [x] **Step 1: Write PC reconstruction and sensitive-instruction tests**

  Fault on the first and last instruction of a block and in an expanded
  relocation sequence; assert Linux `ucontext` PC and `si_addr` refer to guest
  addresses. Add TPIDR read/write, constant register reads, `dc zva`, cache
  maintenance, guest `brk`, and kick-at-block-boundary cases.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_signal_fault --lib
  ```

  Expected: tests fail because cache PCs are not yet lowered through inverse
  maps and sensitive instructions are unsupported.

- [x] **Step 3: Route cache faults through existing Linux lowering**

  In the Darwin signal handler, distinguish a PC inside the translation cache.
  Capture the host fault, exit to the native loop, map the cache PC to the exact
  guest instruction, then reuse `lower_el0_fault`, protection upgrades,
  grow-down handling, SIGBUS past EOF, signal-frame construction, and
  `rt_sigreturn`. Expanded instruction sequences map every emitted word back to
  the single originating guest PC.

- [x] **Step 4: Lower sensitive instructions through typed exits**

  Reuse the current native semantics rather than reimplementing them inside the
  emitter. A sensitive instruction exits with its destination/source register
  and resume PC; the native loop updates the snapshot and resumes translated
  execution. Cache-maintenance operations may become no-ops only where the
  current native backend already does so and a focused test proves the expected
  guest-visible behavior.

- [x] **Step 5: Verify and commit**

  Extend this task's verification with the first honest shipped-static-PIE and
  end-to-end performance gates. Run `syscallregpreserve` under signed DSR and
  require byte-identical output to its checked-in Docker oracle. Then run 30
  separate signed-CLI `perf_trap_floor` samples for DSR, record p50, p95, min,
  IQR, and provenance in `docs/perf-results/native-dsr-syscall-floor.jsonl`, and
  stop before Task 10 if the DSR floor is unstable or loses the bounded gateway
  feasibility demonstrated in Task 5.

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_signal_fault --lib
  just build
  target/release/carrick run-elf --exec-backend native \
    --native-page-profile native16k --native-code-mode dsr \
    conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/syscallregpreserve
  cargo test -p carrick-cli --test conformance native --no-fail-fast
  ```

  Expected: focused signal/fault probes match their Linux oracles under DSR.

  Commit: `feat(native): reconstruct DSR faults at guest PCs`

---

### Task 10: Add executable-page generations and real JIT invalidation

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `conformance-probes/src/bin/mprotectexec.rs`
- Create: `conformance-probes/src/bin/dsrconstantpool.rs`
- Create: `crates/carrick-cli/tests/probe-oracle/arm64-musl/dsrconstantpool`

**Interfaces:**

- Produces: one monotonically increasing `CodeGeneration` per guest executable
  page and reverse page-to-block dependency lists.
- Produces:

  ```rust
  fn note_guest_code_write(&self, range: Range<GuestVa>) -> CodeGeneration;
  fn invalidate_page(&self, page: GuestVa, generation: CodeGeneration);
  fn generation_for_pc(&self, pc: GuestVa) -> Result<CodeGeneration, DsrError>;
  ```

- Constraint: translation reads bytes only while holding a stable generation
  observation; publication fails if any source page changed during decode.

- [x] **Step 1: Write a failing generation state-machine test**

  Use `proptest` to generate sequences of write, protect, translate, execute,
  invalidate, fork-view, and unmap operations. The model invariant is: execution
  returns only a value produced by the current published guest bytes, never an
  older generation. Persist every minimized failure seed.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_generation --lib
  ```

  Expected: the model finds stale execution because generations do not exist.

- [x] **Step 3: Wire every executable-byte mutation**

  Advance generations for loader population, `mmap`, `mprotect`,
  `pkey_mprotect`, `munmap`, `mremap`, dispatcher writes, ptrace writes,
  `process_vm_writev`-equivalent guest writes, and native write/execute fault
  transitions. If a syscall is currently unsupported by the native dispatcher,
  retain that typed syscall result; do not add a fake mutation hook. Remove
  `patch_syscalls` calls from DSR mode. Changes to the legacy executor are out
  of scope. Keep every guest page that has published translations host-read-only
  while executing; a write fault must quiesce translated threads, invalidate the
  prior generation, transition the guest page to its writable phase, and only
  then retry the store. Every block entry checks its source-page generations
  before executing, including linked direct edges and backward loops.

- [x] **Step 4: Add a real JIT probe**

  Extend `mprotectexec` or add a focused probe that writes function A, changes
  the page to executable and calls it, changes it back to writable, writes
  function B at the same address, re-enables execute, and calls it from two
  guest threads. Require A then B with no stale result, host crash, or typed
  rejection on native16k DSR.

- [x] **Step 5: Prove original code is never patched or executed**

  Add a constant-pool probe containing `0xd4000001` as read-only data inside an
  executable segment. Hash original executable bytes before and after the run.
  Require the hash to remain unchanged, the constant read to match, and a
  deliberate direct entry into an original code page to be rejected/faulted by
  the DSR safety backstop.

- [x] **Step 6: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_generation --lib
  just build
  cargo test -p carrick-cli --test conformance native16k_mprotect_exec_permissions_match_linux -- --nocapture
  ```

  Expected: the state-machine test and both executable-page probes pass with no
  stale block execution.

  Commit: `feat(native): invalidate DSR blocks by code generation`

---

### Task 11: Make cache publication correct across threads, fork, exec, and kicks

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`
- Modify: `crates/carrick-cli/tests/conformance.rs`

**Interfaces:**

- Produces: at-most-one published block per `(GuestVa, CodeGeneration)` despite
  duplicate concurrent translation.
- Produces: `after_fork_child()` and `reset_for_exec()` cache lifecycle hooks.
- Constraint: a kick reaches a thread executing a long-running translated loop
  and returns through `NativeDsrExit::Kick` without corrupting guest state.

- [x] **Step 1: Write race-focused tests**

  Start multiple guest pthreads at the same untranslated target; inject a pause
  between allocation and publication; assert one winner, equivalent discarded
  candidates, and no partial branch visibility. Add fork while other threads are
  translating, exec from a non-leader, vfork/exec, and kick during a translated
  loop.

- [x] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_concurrency --lib -- --nocapture
  ```

  Expected: at least the duplicate-publication and fork-state tests fail before
  lifecycle repair exists.

- [x] **Step 3: Integrate with current quiesce boundaries**

  Translation and publication participate in the same fork/exec quiesce rules
  as native memory metadata. The child discards inherited in-progress writers,
  clears thread-local resolver entries, repairs locks using the established
  atfork bundle, and may retain only fully published immutable blocks whose
  generation metadata is valid. Exec discards the old image's block index,
  dependency lists, and resolver caches before mapping the replacement image.

- [x] **Step 4: Make kicks observable at bounded translated intervals**

  Preserve current thread-directed signal delivery. Long straight-line blocks
  are already bounded by the block instruction limit; backward edges add a
  lightweight pending-kick check or resolver boundary proven by the test. Record
  worst observed instruction count from kick request to exit; do not claim a
  time bound independent of scheduling.

- [x] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_concurrency --lib -- --nocapture
  just build
  cargo test -p carrick-cli --test conformance native --no-fail-fast
  ```

  Expected: all race-focused tests pass repeatedly without retry-until-green,
  and focused clone/fork/exec/signal probes match Docker.

  Commit: `feat(native): coordinate DSR across process lifecycle`

---

### Task 12: Drive the static native corpus to parity

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `scripts/conformance/suites.toml`
- Create: `scripts/conformance/baseline.native-dsr.jsonl`
- Create: `docs/native-dsr-static-campaign.md`

**Interfaces:**

- Produces: a separate `macos-native-dsr` conformance lane and overlay.
- Constraint: each newly supported instruction class begins with a minimized
  failing reproducer and direct-vs-translated state oracle case.

- [x] **Step 1: Run the complete static-musl DSR lane**

  Run all Carrick cases first, then Docker cache misses. Capture every typed DSR
  unsupported diagnostic and classify by instruction/control-flow mechanism,
  not by probe name alone.

- [x] **Step 2: Close gaps one mechanism at a time**

  For each instruction class: reduce one failing block; add a red decoder or
  execution-oracle test; implement the class using `bad64` and `dynasmrt`; prove
  the focused probe; rerun every probe sharing the same failure signature; make
  one narrow commit with the proof in its body.

- [x] **Step 3: Reach the static stop condition**

  Stop this task only when one of these is true:

  1. all 376 authoritative native16k musl probes are byte-identical with Docker
     under DSR; or
  2. the remaining rows have explicit typed DSR limitations, minimized repros,
     and maintainer-approved deferral recorded in the campaign document.

  A crash, signal death, silent original-code fallback, or untyped unsupported
  error is never an acceptable baseline entry.

- [x] **Step 4: Verify and commit**

  Run:

  ```bash
  just check-matrix
  just ci
  ```

  Expected: full local CI passes and the DSR overlay remains a separate,
  Linux-oracle-backed evidence surface.

  Commit: `test(conformance): establish the native DSR lane`

---

### Task 13: Refresh LTP, run real workloads, and measure performance

**Files:**

- Create: `docs/native-dsr-ltp-campaign.md`
- Create: `docs/perf-results/native-dsr.jsonl`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `README.md` only if the evidence justifies a user-facing experimental
  mode statement

**Interfaces:**

- Consumes: static parity from Task 12.
- Produces: current DSR-vs-Linux correctness evidence and DSR performance
  distributions with exact git SHA and host provenance.

- [x] **Step 1: Run a fresh strict LTP campaign**

  Run the full selected native16k LTP corpus under DSR and refresh the Docker
  oracle only in a separate Docker-only phase. Report selected, executed, raw
  parity, strict clean parity, timeouts, crashes, typed unsupported exits, and
  no-assertion cases. Do not compare only against the stale 829/1492 snapshot;
  the fresh Linux differential is authoritative.

- [x] **Step 2: Run real ecosystem workloads**

  Run dynamic glibc `/bin/true`; `node-app-smoke`; `node-v8-smoke` (the required
  generated-code workload); `go-build`; `cpython-thread`;
  `cpython-multiprocessing_fork`; and the existing fork/exec benchmark. Use
  explicit suite filters so each Carrick phase finishes before any uncached
  Docker phase:

  ```bash
  target/release/carrick-conformance \
    --suite node-app-smoke --suite node-v8-smoke --suite go-build \
    --suite cpython-thread --suite cpython-multiprocessing_fork \
    --jsonl target/conformance/native-dsr-workloads.jsonl
  ```

  A workload is successful only if output and exit status match its Linux
  oracle. Otherwise record a typed, minimized limitation; do not substitute a
  legacy-mode control for Linux semantics.

- [x] **Step 3: Measure without predetermined wins**

  Re-run the syscall floor from Task 1 plus syscall-heavy, branch-heavy,
  fork/exec, network round-trip, and file-metadata workloads. Use the existing
  performance result schema and record p50, p95, min, IQR, `n`, noise flag,
  host, git SHA, mode, and run ID. Report regressions as well as wins.

- [x] **Step 4: Profile before optimizing the resolver or cache**

  Record time or counts attributable to translation, cache lookup, indirect
  misses, gateway transitions, dispatcher work, invalidation, and code-cache
  pressure. Only create follow-up plans for direct chaining, larger inline
  caches, lock-free publication, eviction, or epoch reclamation when the profile
  identifies a material bottleneck or capacity limit.

- [x] **Step 5: Apply the final go/no-go gate**

  DSR may be documented as an experimental alternative when:

  - static native16k parity meets Task 12's stop condition;
  - the refreshed LTP campaign has no unexplained DSR-only crash or silent
    fallback;
  - CPython, Node/V8 JIT, and Go smoke complete or have typed, documented,
    minimized limitations;
  - original guest code remains byte-identical and non-executable;
  - generation tests show no stale JIT execution;
  - `just ci` passes; and
  - performance results are published without an unsupported headline claim.

  Defaulting native execution to DSR is explicitly outside this plan and
  requires a separate decision based on this evidence.

- [x] **Step 6: Verify and commit**

  Run:

  ```bash
  just ci
  git diff --check
  git status --short
  ```

  Expected: CI and diff checks pass; evidence artifacts are tracked; unrelated
  worktree changes remain untouched.

  Commit: `docs(native): record DSR correctness and performance evidence`

---

## Completion criteria

This plan is complete when Tasks 1–13 have landed and the Task 13 evidence gate
has an explicit result. “The translator compiles,” “the syscall microbenchmark
improves,” and “most probes pass” are intermediate milestones, not completion.

The final report must state, with artifact paths:

- exact supported host, guest ISA, and page profile;
- static probe parity for DSR against Linux;
- fresh strict-LTP counts and classification;
- CPython, Node/V8 JIT, and Go outcomes;
- original-code integrity and stale-generation proof results;
- syscall-floor and workload performance distributions;
- remaining typed limitations; and
- whether DSR remains an opt-in experiment or merits a separate default-mode
  decision.

Final status (2026-07-11): Tasks 1–13 are implemented. Task 13 has fresh
strict-LTP and workload artifacts, including direct Node/V8, Go PIE, Rust
static/dynamic PIE, and fork/exec proof. Performance distributions exist for
the syscall floor, fork/exec, TCP round-trip, metadata, and generated-code
paths. The current-runtime LTP result is 1,331 MATCH and 91 gating rows with no
DSR cache-policy exit. The default-mode decision is NO-GO; DSR remains opt-in.
Full `just ci` passes. Fork lifecycle attribution and the three typed DSR
control-flow regressions are explicit follow-up work, not unfinished steps in
this implementation/evidence plan. See `docs/native-dsr-ltp-campaign.md`,
`docs/perf-results/native-dsr.jsonl`, and
`docs/perf-results/native-dsr-profile.jsonl`.

Profiling follow-up (2026-07-12): the durable `carrick trace --profile` surface
now attributes the remaining DSR costs with versioned, fail-closed JSONL. The
measured optimization queue is indirect target-cache collisions, repeated
prepare lookup, exec subdivision, a low-perturbation gateway benchmark, then
translation/publication. This is an ordered experiment program, not a claim
that every proposed structure will win: each candidate must improve an
untraced workload or leave an evidence-backed stop record. See the
[measured profile report](native-dsr-dtrace-profile.md), the
[approved design](superpowers/specs/2026-07-12-dsr-profile-driven-performance-design.md),
and the
[execution plan](superpowers/plans/2026-07-12-dsr-profile-driven-performance.md).

First accepted optimization (2026-07-12): the 8,192-entry mixed indirect cache
reduced the direct V8 p50 from 7982.07 ms to 7883.38 ms (ratio estimate 0.9869,
95% interval 0.9674–0.9993) and successful resolver exits from 416,997 to
132,213. A separate monomorphic call/return gate bounded the hit path at ratio
0.9804 with an upper interval of 1.0031 against the 1.02 limit. The candidate
is promoted; the next target is repeated prepare lookup. Full provenance and
samples are in `docs/perf-results/native-dsr-indirect-cache-v1.jsonl` and
`docs/perf-results/native-dsr-indirect-cache-hit-v1.jsonl`.

Second accepted optimization (2026-07-12): persistent generation-validated
prepared entries reduced syscall-floor p50 from 0.705 us to 0.678 us (ratio
0.9603, 95% interval 0.9342–0.9891) without regressing direct V8. The broad
profile moved 43,986 outcomes to the typed thread-local fast path: resume hits
rose from 264 to 44,250 and process block-index hits fell from 45,140 to 1,151.
The candidate is promoted without the four-entry fallback. The next target is
subdividing the 1.581 ms outer exec interval before selecting a structural
change. Evidence is in
`docs/perf-results/native-dsr-prepare-cache-v1.jsonl`.
