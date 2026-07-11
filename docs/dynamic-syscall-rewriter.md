# Same-ISA Dynamic Syscall Rewriter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Darwin-native backend's blind in-place instruction
patching and per-syscall `SIGTRAP` path with an opt-in AArch64 same-ISA dynamic
binary translator that leaves original guest code unmodified, reports Linux
guest PCs precisely, supports coherent executable-page generations, and proves
correctness and performance against Carrick's existing native backend.

**Architecture:** Keep the existing Darwin-native loader, direct guest-memory
mapping, dispatcher, process model, signal machinery, and fork/exec/thread
coordination. Add an in-runtime DSR that decodes from actual guest entry points,
emits translated basic blocks into a Darwin `MAP_JIT` cache, and exits through a
small host/guest context gateway for syscalls, indirect resolution, kicks,
faults, and invalidation. The current distinguished-`brk` backend remains a
separately selectable comparison oracle until DSR passes the complete native
gate.

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
- Keep the stable context gateway small and auditable. It must preserve all
  guest-visible GPRs, SP, NZCV, FP/SIMD registers, FPSR, FPCR, guest TLS state,
  and the original guest PC before entering Rust.
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
- distinguished-`brk` translation for `svc #0`, TPIDR operations, selected
  ID-register reads, `dc zva`, and cache-maintenance instructions;
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
the process-wide block index and a per-thread one-entry last-target cache for
indirect branches. Lock-free lookup, direct block chaining, epoch reclamation,
and larger inline caches require profile evidence and are not prerequisites for
correctness.

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
| `crates/carrick-runtime/src/native_darwin.rs` | Select DSR vs `brk`, feed memory generations, reuse dispatcher loop |

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

- [ ] **Step 1: Add a failing serialization and default test**

  Add tests beside the existing execution-backend tests in
  `crates/carrick-spec/src/lib.rs` asserting that default `RunSpec` state selects
  `Brk`, and that `Dsr` serializes to the exact JSON string `"dsr"`.

- [ ] **Step 2: Run the focused test and verify red**

  Run:

  ```bash
  cargo test -p carrick-spec native_code_mode --lib
  ```

  Expected: compilation fails because `NativeCodeModeRequest` does not exist.

- [ ] **Step 3: Thread the typed request through every run surface**

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

- [ ] **Step 4: Establish the pre-DSR performance floor**

  Extend the existing `perf_trap_floor` raw-`getpid` probe with a raw `gettid`
  case and an equal empty-loop control. Extend the existing perf runner so its
  Carrick lane accepts native16k `brk`, native16k DSR, and HVF as distinct
  engines. Run 30 samples under current native16k `brk` and HVF in separate
  phases before DSR execution exists. Store provenance, p50, p95, min, IQR, and
  `n` in the new JSONL evidence file. This is observation, not an acceptance
  threshold.

- [ ] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-spec native_code_mode --lib
  cargo test -p carrick-cli --test conformance native --no-fail-fast
  just fmt-check
  ```

  Expected: all pass; existing native commands still select `brk` when the new
  option is omitted.

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

- [ ] **Step 1: Write table tests for the initial instruction classes**

  Cover ordinary arithmetic, `svc #0`, `b`, `bl`, `b.cond`, `cbz`, `cbnz`,
  `tbz`, `tbnz`, `br`, `blr`, `ret`, `adr`, `adrp`, literal loads, TPIDR_EL0
  reads/writes, CTR_EL0, DCZID_EL0, `dc zva`, `dc cvau`, and `ic ivau`. Each test
  asserts the typed action and exact guest target/resume address.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime native_darwin::dsr::decode --lib
  ```

  Expected: compilation fails because the DSR module and types do not exist.

- [ ] **Step 3: Implement classification with `bad64`**

  Decode with `bad64::decode(word, guest_pc.0)`. Match `bad64::Op` and typed
  operands; do not infer instruction classes from mnemonic strings. Preserve the
  raw word in every action so diagnostics and decode-back tests can report it.
  Any decoded operation not explicitly supported becomes `Unsupported`; decode
  errors become a DSR error carrying the raw word and PC.

- [ ] **Step 4: Add property tests for target arithmetic**

  Add `proptest = "1.11.0"` to `[workspace.dependencies]` and
  `proptest.workspace = true` to `carrick-runtime`'s `[dev-dependencies]`.
  Generate aligned guest PCs and legal immediate ranges for the direct and
  PC-relative classes. Assert that classification produces the same
  architectural target as the instruction's encoded immediate, including
  negative displacements and page-rounded `adrp`.

- [ ] **Step 5: Verify and commit**

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

- [ ] **Step 1: Write fork-isolated executable-memory tests**

  Tests must prove: cache allocation succeeds; a generated `mov x0, #42; ret`
  returns 42; publication flushes I-cache; a second write changes the result;
  execution during the write phase faults in the child; writing during the
  execute phase faults in the child; and a non-cache host PC is rejected.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_cache --lib
  ```

  Expected: compilation fails because `TranslationCache` does not exist.

- [ ] **Step 3: Implement the narrow Darwin policy wrapper**

  Allocate with `MAP_PRIVATE | MAP_ANON | MAP_JIT`. Centralize
  `pthread_jit_write_protect_np` and I-cache publication in the existing native
  C companion only where the `libc` crate lacks a stable declaration. The Rust
  wrapper owns bounds, page alignment, state transitions, and lifetime. It must
  never expose a raw mutable cache slice outside `CacheWriter`.

- [ ] **Step 4: Test fork inheritance explicitly**

  Publish a block, fork, execute it in the child, and report the result through
  the exit status. Then prove the child can discard inherited unpublished
  writer state and begin a clean write transaction. This is only a memory-policy
  proof; metadata repair lands in Task 11.

- [ ] **Step 5: Verify and commit**

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

- [ ] **Step 1: Write boundary and constant-pool tests**

  Construct byte regions containing ordinary instructions, an early `svc`, a
  branch, a page boundary, and a data word equal to `0xd4000001` after an
  unconditional branch. Assert that only reachable instructions before the
  terminator enter the plan and that the data word remains unchanged.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_block --lib
  ```

  Expected: compilation fails because `BlockPlan` and `plan_block` do not exist.

- [ ] **Step 3: Add `dynasmrt` and emit the copy-only subset**

  Add `dynasmrt = "5.0.0"` to `[workspace.dependencies]` and
  `dynasmrt.workspace = true` to the macOS/AArch64 target dependencies in
  `carrick-runtime`. Emit with
  `dynasmrt::VecAssembler<dynasmrt::aarch64::Aarch64Relocation>` so Carrick's
  `MAP_JIT` cache, not dynasmrt's generic executable allocator, owns final code
  memory. Emit ordinary position-independent instructions as their original
  32-bit words, append a typed exit stub for the block terminator, and publish
  the instruction-granular PC map atomically with the code. Reject every
  `PcRelative`, `Direct`, and `Indirect` action until its later task lands.

- [ ] **Step 4: Decode back every emitted block in tests**

  Read the published cache bytes and run `bad64::decode` at their cache
  addresses. Assert that copied instructions retain their operation and
  operands and that every PC-map entry points to an instruction boundary.

- [ ] **Step 5: Verify and commit**

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
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `conformance-probes/src/bin/syscallregpreserve.rs`
- Modify: `crates/carrick-cli/tests/probe-oracle/arm64-musl/syscallregpreserve`

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

- [ ] **Step 1: Write a red full-state oracle test**

  Seed x0..x30, SP, NZCV, v0..v31, FPSR, and FPCR with distinct values. Execute
  a translated straight-line block that changes only an enumerated subset and
  exits. Compare the resulting state with the same instruction sequence run
  directly in a fork-isolated native function. Include x16, x17, x18, and LR
  explicitly.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_gateway --lib
  ```

  Expected: compilation fails because the gateway does not exist.

- [ ] **Step 3: Implement the audited gateway**

  The assembly entry saves complete guest state before using a scratch register,
  switches to the recorded host SP and host TLS/x18 ABI, writes a
  `NativeDsrExit`, and returns to Rust. Resume performs the inverse transition.
  Add compile-time offset assertions shared with the existing C ucontext layout.
  Do not call Rust directly on the guest stack.

- [ ] **Step 4: Route translated `svc #0` through the existing dispatcher**

  Change the DSR `svc` terminator to exit with `NativeDsrExit::Syscall` and a
  guest resume PC of `svc_pc + 4`. Reuse the existing syscall frame extraction,
  `SyscallDispatcher`, outcome handling, signal-delivery cycle, and resume
  snapshot. Add a DSR-only integration test executing raw `getpid`, writing the
  result, and exiting.

- [ ] **Step 5: Red-first the shipped register-preservation probe**

  Before enabling the complete save set, run `syscallregpreserve` under DSR and
  record the expected mismatch. Restore the complete gateway and require exact
  Docker-oracle output. Add NZCV and FP/SIMD preservation cases to the probe.

- [ ] **Step 6: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_gateway --lib
  just build
  target/release/carrick run-elf --exec-backend native \
    --native-page-profile native16k --native-code-mode dsr \
    conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/syscallregpreserve
  ```

  Expected: unit oracle state matches and the probe output is byte-identical to
  `crates/carrick-cli/tests/probe-oracle/arm64-musl/syscallregpreserve`.

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

- [ ] **Step 1: Write generated relocation tests across distance classes**

  For each instruction, generate guest and cache addresses that are near, far,
  positive, negative, page-aligned, and page-crossing. Assert the translated
  destination register or loaded value equals direct execution. Include xzr/wzr
  and 32-bit destination behavior where architecturally legal.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_pc_relative --lib
  ```

  Expected: tests fail with the typed unsupported action from Task 4.

- [ ] **Step 3: Emit relocations with `dynasmrt`**

  Prefer a single equivalent instruction when the translated displacement fits.
  Otherwise materialize the guest architectural address in a scratch-free
  sequence that targets only the original destination register. Literal loads
  load from the original guest data address, not a copied constant, so guest
  writes remain visible. If an instruction cannot be expanded without a scratch
  register or semantic loss, end the block and route through a correct slow exit
  before adding an optimized form.

- [ ] **Step 4: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_pc_relative --lib
  cargo test -p carrick-runtime dsr_oracle --lib
  ```

  Expected: all generated cases match direct execution and decode-back checks
  confirm targets.

  Commit: `feat(native): relocate DSR PC-relative instructions`

---

### Task 7: Add direct control flow and lazy block linking

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`

**Interfaces:**

- Supports: `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `tbz`, and `tbnz`.
- Produces: a correct resolver exit for an unpublished direct target and an
  optional link patch once source and destination blocks are both published.
- Constraint: `bl` writes the original guest return PC to x30, never a cache PC.

- [ ] **Step 1: Write graph-shaped execution tests**

  Cover taken/not-taken conditional edges, forward/backward loops, nested calls,
  guest LR observation, a direct target on another guest page, and a source
  block linked before and after its destination is published.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_direct_flow --lib
  ```

  Expected: tests fail with typed unsupported direct exits.

- [ ] **Step 3: Implement correct lazy resolution first**

  Every unresolved edge exits with its architectural guest target. The Rust
  coordinator looks up or translates `(target, generation)`, then resumes at
  the cache address. Direct patching is added only after the slow path passes all
  graph tests. Patches use a cache write transaction and are published
  atomically; a concurrent executor must see either the resolver stub or the
  complete linked branch.

- [ ] **Step 4: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_direct_flow --lib
  cargo test -p carrick-runtime dsr_oracle --lib
  ```

  Expected: all direct-flow tests match direct execution before and after
  linking.

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

- [ ] **Step 1: Write indirect-control tests**

  Cover function pointers, alternating two targets at one callsite, recursive
  returns, tail calls, `blr` guest-LR semantics, stale generation rejection, and
  an indirect target outside an executable guest mapping.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_indirect_flow --lib
  ```

  Expected: tests fail with typed unsupported indirect exits.

- [ ] **Step 3: Implement the resolver and one-entry thread-local cache**

  Validate target alignment and guest execute permission before lookup. On a
  miss, translate synchronously and publish before resuming. `blr` sets x30 to
  the guest instruction's resume PC. `ret` treats its register value only as a
  guest target; a cache address in a guest register is rejected.

- [ ] **Step 4: Profile before considering assembly lookup**

  Add counters for resolver exits, one-entry hits, translations, and duplicate
  publication races. Run static PIE probes and record counts. Do not implement
  a larger assembly hash table unless indirect misses are a material share of
  runtime after Task 12 workloads.

- [ ] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_indirect_flow --lib
  cargo test -p carrick-runtime dsr_oracle --lib
  ```

  Expected: indirect-flow state matches direct execution and invalid targets
  produce deterministic diagnostics.

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

- [ ] **Step 1: Write PC reconstruction and sensitive-instruction tests**

  Fault on the first and last instruction of a block and in an expanded
  relocation sequence; assert Linux `ucontext` PC and `si_addr` refer to guest
  addresses. Add TPIDR read/write, constant register reads, `dc zva`, cache
  maintenance, guest `brk`, and kick-at-block-boundary cases.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_signal_fault --lib
  ```

  Expected: tests fail because cache PCs are not yet lowered through inverse
  maps and sensitive instructions are unsupported.

- [ ] **Step 3: Route cache faults through existing Linux lowering**

  In the Darwin signal handler, distinguish a PC inside the translation cache.
  Capture the host fault, exit to the native loop, map the cache PC to the exact
  guest instruction, then reuse `lower_el0_fault`, protection upgrades,
  grow-down handling, SIGBUS past EOF, signal-frame construction, and
  `rt_sigreturn`. Expanded instruction sequences map every emitted word back to
  the single originating guest PC.

- [ ] **Step 4: Lower sensitive instructions through typed exits**

  Reuse the current native semantics rather than reimplementing them inside the
  emitter. A sensitive instruction exits with its destination/source register
  and resume PC; the native loop updates the snapshot and resumes translated
  execution. Cache-maintenance operations may become no-ops only where the
  current native backend already does so and a focused test proves the expected
  guest-visible behavior.

- [ ] **Step 5: Verify and commit**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_signal_fault --lib
  just build
  cargo test -p carrick-cli --test conformance native --no-fail-fast
  ```

  Expected: focused signal/fault probes match their Docker oracles under DSR and
  the existing `brk` mode remains unchanged.

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

- [ ] **Step 1: Write a failing generation state-machine test**

  Use `proptest` to generate sequences of write, protect, translate, execute,
  invalidate, fork-view, and unmap operations. The model invariant is: execution
  returns only a value produced by the current published guest bytes, never an
  older generation. Persist every minimized failure seed.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_generation --lib
  ```

  Expected: the model finds stale execution because generations do not exist.

- [ ] **Step 3: Wire every executable-byte mutation**

  Advance generations for loader population, `mmap`, `mprotect`,
  `pkey_mprotect`, `munmap`, `mremap`, dispatcher writes, ptrace writes,
  `process_vm_writev`-equivalent guest writes, and native write/execute fault
  transitions. If a syscall is currently unsupported by the native dispatcher,
  retain that typed syscall result; do not add a fake mutation hook. Remove
  `patch_syscalls` calls from DSR mode only and preserve them exactly in `brk`
  mode. Keep every guest page that has published translations host-read-only
  while executing; a write fault must quiesce translated threads, invalidate the
  prior generation, transition the guest page to its writable phase, and only
  then retry the store. Every block entry checks its source-page generations
  before executing, including linked direct edges and backward loops.

- [ ] **Step 4: Add a real JIT probe**

  Extend `mprotectexec` or add a focused probe that writes function A, changes
  the page to executable and calls it, changes it back to writable, writes
  function B at the same address, re-enables execute, and calls it from two
  guest threads. Require A then B with no stale result, host crash, or typed
  rejection on native16k DSR.

- [ ] **Step 5: Prove original code is never patched or executed**

  Add a constant-pool probe containing `0xd4000001` as read-only data inside an
  executable segment. Hash original executable bytes before and after the run.
  Require the hash to remain unchanged, the constant read to match, and a
  deliberate direct entry into an original code page to be rejected/faulted by
  the DSR safety backstop.

- [ ] **Step 6: Verify and commit**

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

- [ ] **Step 1: Write race-focused tests**

  Start multiple guest pthreads at the same untranslated target; inject a pause
  between allocation and publication; assert one winner, equivalent discarded
  candidates, and no partial branch visibility. Add fork while other threads are
  translating, exec from a non-leader, vfork/exec, and kick during a translated
  loop.

- [ ] **Step 2: Verify red**

  Run:

  ```bash
  cargo test -p carrick-runtime dsr_concurrency --lib -- --nocapture
  ```

  Expected: at least the duplicate-publication and fork-state tests fail before
  lifecycle repair exists.

- [ ] **Step 3: Integrate with current quiesce boundaries**

  Translation and publication participate in the same fork/exec quiesce rules
  as native memory metadata. The child discards inherited in-progress writers,
  clears thread-local resolver entries, repairs locks using the established
  atfork bundle, and may retain only fully published immutable blocks whose
  generation metadata is valid. Exec discards the old image's block index,
  dependency lists, and resolver caches before mapping the replacement image.

- [ ] **Step 4: Make kicks observable at bounded translated intervals**

  Preserve current thread-directed signal delivery. Long straight-line blocks
  are already bounded by the block instruction limit; backward edges add a
  lightweight pending-kick check or resolver boundary proven by the test. Record
  worst observed instruction count from kick request to exit; do not claim a
  time bound independent of scheduling.

- [ ] **Step 5: Verify and commit**

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

- [ ] **Step 1: Run the complete static-musl DSR lane**

  Run all Carrick cases first, then Docker cache misses. Capture every typed DSR
  unsupported diagnostic and classify by instruction/control-flow mechanism,
  not by probe name alone.

- [ ] **Step 2: Close gaps one mechanism at a time**

  For each instruction class: reduce one failing block; add a red decoder or
  execution-oracle test; implement the class using `bad64` and `dynasmrt`; prove
  the focused probe; rerun every probe sharing the same failure signature; make
  one narrow commit with the proof in its body.

- [ ] **Step 3: Reach the static stop condition**

  Stop this task only when one of these is true:

  1. all 376 authoritative native16k musl probes are byte-identical with Docker
     under DSR; or
  2. the remaining rows have explicit typed DSR limitations, minimized repros,
     and maintainer-approved deferral recorded in the campaign document.

  A crash, signal death, silent original-code fallback, or untyped unsupported
  error is never an acceptable baseline entry.

- [ ] **Step 4: Verify and commit**

  Run:

  ```bash
  just check-matrix
  just ci
  ```

  Expected: full local CI passes and the DSR overlay does not modify the HVF or
  current native-`brk` baseline.

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
- Produces: current DSR-vs-`brk`-vs-HVF-vs-Docker correctness and performance
  evidence with exact git SHA and host provenance.

- [ ] **Step 1: Run a fresh strict LTP campaign**

  Run the full selected native16k LTP corpus under DSR and refresh the Docker
  oracle only in a separate Docker-only phase. Report selected, executed, raw
  parity, strict clean parity, timeouts, crashes, typed unsupported exits, and
  no-assertion cases. Do not compare only against the stale 829/1492 snapshot;
  run current `brk` mode on the same revision as the control.

- [ ] **Step 2: Run real ecosystem workloads**

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

  A workload is successful only if output and exit status match its Linux oracle
  or documented same-revision native-`brk` control.

- [ ] **Step 3: Measure without predetermined wins**

  Re-run the syscall floor from Task 1 plus syscall-heavy, branch-heavy,
  fork/exec, network round-trip, and file-metadata workloads. Use the existing
  performance result schema and record p50, p95, min, IQR, `n`, noise flag,
  host, git SHA, mode, and run ID. Report regressions as well as wins.

- [ ] **Step 4: Profile before optimizing the resolver or cache**

  Record time or counts attributable to translation, cache lookup, indirect
  misses, gateway transitions, dispatcher work, invalidation, and code-cache
  pressure. Only create follow-up plans for direct chaining, larger inline
  caches, lock-free publication, eviction, or epoch reclamation when the profile
  identifies a material bottleneck or capacity limit.

- [ ] **Step 5: Apply the final go/no-go gate**

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

- [ ] **Step 6: Verify and commit**

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
- static probe parity for DSR and the same-revision `brk` control;
- fresh strict-LTP counts and classification;
- CPython, Node/V8 JIT, and Go outcomes;
- original-code integrity and stale-generation proof results;
- syscall-floor and workload performance distributions;
- remaining typed limitations; and
- whether DSR remains an opt-in experiment or merits a separate default-mode
  decision.
