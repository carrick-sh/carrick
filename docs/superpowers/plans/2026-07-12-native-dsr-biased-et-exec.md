
# Native DSR Biased `ET_EXEC` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute ordinary low-address AArch64 Linux `ET_EXEC` binaries through DSR by preserving guest virtual addresses and mapping the guest at one collision-checked high host bias, without changing the direct PIE fast path.

**Architecture:** Add a typed `NativeAddressMode` owned by `NativeMappedMemory`. Direct mode preserves the current mapping and emitted instruction shape. Biased mode maps the complete guest layout at `guest + host_bias`, translates all runtime memory boundaries, and emits audited native memory operations through a gateway-provided bias while keeping registers, control flow, signals, and diagnostics in guest coordinates.

**Tech Stack:** Rust 1.96.0, edition 2024, `bad64`, `dynasmrt`, Darwin VM primitives, Carrick DSR, signed native16k probes.

## Global Constraints

- DSR remains the sole Darwin-native instruction engine. Do not restore legacy BRK execution or internal BRK sentinels.
- Do not add an automatic HVF fallback or rebase `ET_EXEC`.
- Keep registers, PC/SP/LR, auxv, signal frames, syscall pointers, `/proc`, and diagnostics in `GuestVa`.
- Use typed `GuestVa`, `HostVa`, and `NativeHostBias` at every address boundary.
- Biased probing never uses `MAP_FIXED` against an unowned range.
- Direct PIE emission gains no biased-mode branch or address addition.
- Unsupported biased memory encodings fail closed with word, guest PC, and addressing class.
- This plan does not claim to fix the separate post-fork multithreaded DSR `execve` defect.
- Build and run guests only through a path that re-signs `target/release/carrick`.

## File Structure

- Create `crates/carrick-runtime/src/native_darwin/address.rs`: address mode, bias validation, conversion, candidate layouts, and exact mapping ownership.
- Modify `crates/carrick-runtime/src/native_darwin.rs`: mapping selection, `GuestMemory`, fault, signal, fork, and exec integration.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/{types,decode,block,emit,gateway,mod}.rs`: typed memory actions and mode-specialized emission.
- Modify `crates/carrick-runtime/csrc/native_darwin.c`: mirrored gateway layout and fault recovery.
- Modify `crates/carrick-cli/tests/conformance.rs`: signed low-`ET_EXEC` acceptance.
- Modify `docs/dynamic-syscall-rewriter.md` and the superseded direct-execution design: durable behavior and evidence.

---

### Task 1: Typed Native Address Domain

**Files:**
- Create: `crates/carrick-runtime/src/native_darwin/address.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces `NativeHostBias::new(u64, u64) -> Result<Self, NativeAddressError>`.
- Produces `NativeAddressMode::{Direct, Biased { host_bias }}`.
- Produces `to_host(GuestVa) -> Result<HostVa, NativeAddressError>`, `to_guest(HostVa) -> Result<GuestVa, NativeAddressError>`, and checked range translation.
- Consumed by Tasks 2-7.

- [ ] **Step 1: Write failing typed-domain tests**

```rust
#[test]
fn direct_mode_is_identity() {
    let mode = NativeAddressMode::Direct;
    assert_eq!(mode.to_host(GuestVa(0x4000)).unwrap(), HostVa(0x4000));
    assert_eq!(mode.to_guest(HostVa(0x4000)).unwrap(), GuestVa(0x4000));
}

#[test]
fn biased_mode_round_trips_guest_addresses() {
    let bias = NativeHostBias::new(0x20_0000_0000, 0x4000).unwrap();
    let mode = NativeAddressMode::Biased { host_bias: bias };
    let host = mode.to_host(GuestVa(0x40_0000)).unwrap();
    assert_eq!(host, HostVa(0x20_0040_0000));
    assert_eq!(mode.to_guest(host).unwrap(), GuestVa(0x40_0000));
}

#[test]
fn bias_rejects_zero_misalignment_and_overflow() {
    assert!(NativeHostBias::new(0, 0x4000).is_err());
    assert!(NativeHostBias::new(0x20_0000_0001, 0x4000).is_err());
    let mode = NativeAddressMode::Biased {
        host_bias: NativeHostBias::new(u64::MAX & !0x3fff, 0x4000).unwrap(),
    };
    assert!(mode.to_host(GuestVa(0x4000)).is_err());
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib native_darwin::address::tests -- --nocapture
```

Expected: compilation fails because the types and methods do not exist.

- [ ] **Step 3: Implement the types**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeHostBias(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeAddressMode {
    Direct,
    Biased { host_bias: NativeHostBias },
}

#[derive(Debug, thiserror::Error)]
pub(super) enum NativeAddressError {
    #[error("native host bias 0x{bias:x} is invalid for page size 0x{page_size:x}")]
    InvalidBias { bias: u64, page_size: u64 },
    #[error("native address translation overflow: address=0x{address:x} bias=0x{bias:x}")]
    Overflow { address: u64, bias: u64 },
    #[error("host address 0x{address:x} is below native bias 0x{bias:x}")]
    BelowBias { address: u64, bias: u64 },
}
```

Require nonzero power-of-two page size, nonzero aligned bias, checked addition/subtraction, and checked range ends. Add `mod address;`, replace the stale BRK module description with DSR-only wording, add `address_mode` to `NativeMappedMemory`, and initialize every existing constructor to `Direct`.

- [ ] **Step 4: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib native_darwin::address::tests -- --nocapture
cargo test -p carrick-runtime --lib native_darwin::tests -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: all commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/native_darwin/address.rs
git commit -m "feat(native): type direct and biased guest addresses" \
  -m "Introduce checked guest-to-host address modes for DSR while leaving existing mappings direct. Pin alignment, overflow, and round-trip behavior.

Verified with focused native tests and clippy.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 2: Collision-Safe Biased Layout Selection

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/address.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces `NativeLayout::for_image(&AddressSpace, MemoryLayout, u64) -> Result<Self, NativeAddressError>`.
- Produces `NativeLayout::address_mode() -> NativeAddressMode`.
- Produces RAII `OwnedHostMapping::map_exact(HostVa, usize, i32, i32)`.
- Consumed by Tasks 3, 6, and 7.

- [ ] **Step 1: Write failing collision tests**

```rust
#[test]
fn exact_mapping_never_replaces_an_existing_page() {
    fork_test(|| {
        let sentinel = map_any_page();
        unsafe { std::ptr::write_bytes(sentinel.as_ptr(), 0x5a, 0x4000) };
        let result = OwnedHostMapping::map_exact(
            HostVa(sentinel.as_ptr() as usize),
            0x4000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
        );
        assert!(matches!(result, Err(NativeAddressError::HostCollision { .. })));
        assert_eq!(unsafe { *sentinel.as_ptr() }, 0x5a);
    });
}

#[test]
fn failed_candidate_unmaps_every_acquired_range() {
    fork_test(|| {
        let candidate = CandidateLayout::test_fixture();
        let collision = occupy(candidate.ranges()[1].clone());
        assert!(candidate.try_map().is_err());
        assert!(range_is_vacant(candidate.ranges()[0].clone()));
        drop(collision);
    });
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib native_darwin::address::tests -- --nocapture
```

Expected: missing exact-mapping and candidate-layout APIs.

- [ ] **Step 3: Implement exact mapping and candidate selection**

`OwnedHostMapping::map_exact` calls `mmap(requested, ..., flags & !MAP_FIXED, ...)`. If Darwin returns another address, unmap it and return `HostCollision`. `Drop` unmaps until `commit` transfers ownership.

Use aligned deterministic candidates:

```rust
const BIAS_CANDIDATES: [u64; 4] = [
    0x80_0000_0000,
    0xc0_0000_0000,
    0x100_0000_0000,
    0x140_0000_0000,
];
```

These are 512, 768, 1024, and 1280 GiB. They deliberately start above
Darwin's measured 63–448 GiB reserved VA hole; lower candidates cannot be
acquired even when otherwise vacant.

Validate ELF/interpreter segments, stack, heap, mmap arena, vDSO/vvar, trampoline, and address overflow under each candidate. Change initial `map_region`, `map_bytes_region`, and `map_anonymous_region` ownership to accept `NativeAddressMode`. Permit later `MAP_FIXED` only inside a recorded owned interval.

- [ ] **Step 4: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib native_darwin::address::tests -- --nocapture
cargo test -p carrick-runtime --lib native_fixed_mapping -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: collision sentinel and cleanup pass; existing fixed mapping tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/native_darwin/address.rs
git commit -m "feat(native): reserve biased guest layouts safely" \
  -m "Acquire deterministic high guest windows without MAP_FIXED, roll back partial candidates, and guard later fixed mappings with owned-range checks.

Verified with fork-isolated collision and cleanup tests.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 3: Translate Runtime Memory and Fault Boundaries

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces `NativeMappedMemory::host_address(GuestVa) -> Result<HostVa, MemoryError>`.
- Produces `NativeMappedMemory::guest_fault_address(HostVa) -> Option<GuestVa>`.
- Produces `NativeMappedMemory::address_mode() -> NativeAddressMode`.
- Consumed by Tasks 4-7.

- [ ] **Step 1: Write failing boundary tests**

```rust
#[test]
fn biased_memory_keeps_guest_coordinates_at_runtime_boundaries() {
    fork_test(|| {
        let mut memory = biased_test_memory(GuestVa(0x40_0000), 0x4000);
        memory.write_bytes(0x40_0080, b"dsr").unwrap();
        assert_eq!(memory.read_bytes(0x40_0080, 3).unwrap(), b"dsr");
        let host = memory.host_address(GuestVa(0x40_0080)).unwrap();
        assert_eq!(memory.guest_fault_address(host), Some(GuestVa(0x40_0080)));
        assert!(memory.read_bytes(0, 1).is_err());
    });
}

#[test]
fn arbitrary_host_pointer_is_not_a_guest_fault() {
    let memory = biased_test_memory(GuestVa(0x40_0000), 0x4000);
    let host = HostVa((&memory as *const _) as usize);
    assert_eq!(memory.guest_fault_address(host), None);
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib biased_memory_keeps_guest_coordinates -- --nocapture
```

Expected: raw guest addresses are still used as host pointers.

- [ ] **Step 3: Implement boundary translation**

Add the three interfaces. Route instruction reads, raw reads/writes, protections, mmap/munmap, aliases, stack/vector creation, vDSO/vvar, signal frames, and resident faults through `host_address`. Keep region/protection/futex metadata guest-keyed. Store host owned intervals separately.

In `lower_dsr_fault`, reverse-translate FAR and `fault_address` only after host interval membership. A fault in DSR cache, Carrick, dyld, or another unowned range remains a runtime failure.

- [ ] **Step 4: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib biased_memory_keeps_guest_coordinates -- --nocapture
cargo test -p carrick-runtime --lib native_signal -- --nocapture
cargo test -p carrick-runtime --lib native_linux4k -- --nocapture
cargo test -p carrick-runtime --lib dsr_ -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: biased boundaries and all direct regressions pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin.rs
git commit -m "feat(native): translate biased runtime memory" \
  -m "Make NativeMappedMemory the sole translation authority for buffers, mappings, protections, signal frames, and faults while retaining guest-coordinate metadata.

Verified with biased boundary, signal, linux4k, and DSR tests.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 4: Classify Audited DSR Memory Instructions

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`

**Interfaces:**
- Produces `MemoryAccess { word, op, base, writeback, class }`.
- Produces `MemoryBase`, `MemoryWriteback`, `MemoryClass`.
- Produces `InstAction::Memory(MemoryAccess)`.
- Consumed by Task 5.

- [ ] **Step 1: Write a failing decode matrix**

```rust
#[test]
fn classifies_memory_operands_for_biased_lowering() {
    let cases = [
        (0xf940_0020, MemoryClass::Scalar, MemoryWriteback::None),
        (0xf81f_0ffe, MemoryClass::Scalar, MemoryWriteback::PreIndex),
        (0xa8c1_7bfd, MemoryClass::Pair, MemoryWriteback::PostIndex),
        (0x3dc0_0020, MemoryClass::Simd, MemoryWriteback::None),
        (0xc85f_7c20, MemoryClass::Exclusive, MemoryWriteback::None),
        (0xf8e1_0022, MemoryClass::Atomic, MemoryWriteback::None),
        (0x5800_0040, MemoryClass::Literal, MemoryWriteback::None),
    ];
    for (word, class, writeback) in cases {
        let InstAction::Memory(memory) = classify(word, GuestVa(0x4000)).unwrap() else {
            panic!("0x{word:08x} was not classified as memory");
        };
        assert_eq!(memory.class, class);
        assert_eq!(memory.writeback, writeback);
    }
}
```

Add x18/x28-base and malformed-memory cases.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib classifies_memory_operands_for_biased_lowering -- --nocapture
```

Expected: typed memory actions do not exist.

- [ ] **Step 3: Implement typed classification**

Decode `MemReg`, `MemOffset`, `MemPreIdx`, `MemPostIdxImm`, `MemPostIdxReg`, and literal labels. Validate the encoded base field. Classify scalar, pair, SIMD, atomic, exclusive, and literal opcode families explicitly.

Run x18/x28 virtualization policy before ordinary memory classification and retain virtual-base metadata. Update block planning so `InstAction::Memory` remains in the instruction stream.

- [ ] **Step 4: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::decode::tests -- --nocapture
cargo test -p carrick-runtime --lib native_darwin::dsr::block::tests -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: matrix, virtual-register cases, and block tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/types.rs \
  crates/carrick-runtime/src/native_darwin/dsr/decode.rs \
  crates/carrick-runtime/src/native_darwin/dsr/block.rs
git commit -m "feat(native): classify DSR memory operands" \
  -m "Represent audited memory and writeback operations as typed DSR actions while preserving x18/x28 virtualization precedence.

Verified with decoder and block-planning matrices.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 5: Emit and Recover Biased Memory Operations

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/{types,emit,gateway,mod}.rs`
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`

**Interfaces:**
- Produces `EmitAddressMode::{Direct, Biased { host_bias }}`.
- Produces mode-aware `emit_block`.
- Produces `DsrContext::host_bias` with Rust/C layout assertions.
- Produces typed scratch/writeback recovery.

- [ ] **Step 1: Write failing direct and biased oracles**

```rust
#[test]
fn direct_memory_emission_is_word_identical() {
    let plan = plan_words(&[0xf940_0020, 0xd400_0001]);
    let emitted = emit_words(&plan, EmitAddressMode::Direct);
    assert!(emitted.windows(4).any(|b| b == 0xf940_0020_u32.to_le_bytes()));
}

#[test]
fn biased_memory_families_access_guest_data() {
    for fixture in biased_memory_fixtures() {
        let result = execute_biased_fixture(fixture);
        assert_eq!(result.registers, fixture.expected_registers);
        assert_eq!(result.memory, fixture.expected_memory);
    }
}
```

Add pre/post-index guest-writeback and signal recovery tests.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib direct_memory_emission_is_word_identical -- --nocapture
cargo test -p carrick-runtime --lib biased_memory_families_access_guest_data -- --nocapture
```

Expected: the mode-aware emitter is absent.

- [ ] **Step 3: Extend gateway context**

Append `host_bias: u64` to Rust `DsrContext` and C `carrick_native_dsr_signal_context`. Update every `offset_of!`, `_Static_assert`, and total-size assertion. Direct passes zero; biased passes `NativeHostBias::get()`.

- [ ] **Step 4: Implement specialized emission**

Direct emits the original memory word exactly. Biased uses physical x16/x17 under existing save/recovery discipline:

```text
save guest x16/x17 in DsrContext
load host_bias from [x28, #CTX_HOST_BIAS]
form translated base = guest_base + host_bias
execute the original operation with its base field replaced
for writeback: guest_base = translated_writeback - host_bias
restore guest scratch values unless architecturally written
```

Literal reads use `literal_guest_target + bias`; ADR/ADRP remain guest-valued. Atomics/exclusives retain their opcode ordering semantics. Add recovery entries that restore scratch and guest-coordinate base state before fault lowering. Fail closed when scratch selection cannot preserve architectural state.

- [ ] **Step 5: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib native_darwin::dsr::emit::tests -- --nocapture
cargo test -p carrick-runtime --lib native_darwin::dsr::gateway::tests -- --nocapture
cargo test -p carrick-runtime --lib native_darwin::dsr::oracle -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: direct byte identity, every biased family, writeback, recovery, and layout checks pass.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr crates/carrick-runtime/csrc/native_darwin.c
git commit -m "feat(native): emit biased DSR memory accesses" \
  -m "Carry immutable host bias in gateway context and lower audited memory families while preserving direct words, guest writeback, atomics, exclusives, and recovery.

Verified with emitter, gateway, oracle, and clippy gates.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 6: Integrate Initial Image, Exec, and Fork Lifecycles

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`

**Interfaces:**
- Produces initial low-`ET_EXEC` selection.
- Produces single-thread direct→biased, biased→direct, biased→biased exec.
- Produces fork inheritance of address mode.

- [ ] **Step 1: Write failing lifecycle tests**

```rust
#[test]
fn low_et_exec_selects_biased_mode_and_exits_zero() {
    let result = run_test_elf(low_et_exec_exit_elf(), NativePageProfile::Native16k);
    assert_eq!(result.exit_code, 0, "stderr={:?}", result.stderr);
}

#[test]
fn exec_transitions_preserve_guest_addresses_across_modes() {
    for (source, target) in [
        (ImageKind::DirectPie, ImageKind::LowExec),
        (ImageKind::LowExec, ImageKind::DirectPie),
        (ImageKind::LowExec, ImageKind::LowExec),
    ] {
        assert_exec_transition(source, target);
    }
}

#[test]
fn fork_child_inherits_the_parent_bias() {
    assert_forked_bias_matches_parent(low_et_exec_fork_elf());
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p carrick-runtime --lib low_et_exec_selects_biased_mode -- --nocapture
```

Expected: current hard 4 GiB rejection.

- [ ] **Step 3: Integrate image boundaries**

Remove the blanket low-region rejection. Build `NativeLayout` before mapping, store its mode, and pass the mode into the DSR translator.

For exec, validate before the Linux point of no return. After sibling teardown, unmap only old owned ranges, map the replacement transactionally, reset dispatcher state, and hand the new mode to the translator. An unexpected post-retirement host failure terminates with a typed diagnostic.

Fork inherits mode and mappings; repair clears publication/thread-local state without recalculating bias.

- [ ] **Step 4: Verify GREEN**

```bash
cargo test -p carrick-runtime --lib low_et_exec_selects_biased_mode -- --nocapture
cargo test -p carrick-runtime --lib exec_transitions_preserve_guest_addresses -- --nocapture
cargo test -p carrick-runtime --lib fork_child_inherits_the_parent_bias -- --nocapture
cargo test -p carrick-runtime --lib native16k_mprotect -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: all lifecycle and JIT tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/native_darwin/dsr/mod.rs
git commit -m "feat(native): run low ET_EXEC through biased DSR" \
  -m "Carry a collision-checked biased layout through initial execution, single-thread image replacement, and fork inheritance without exposing host addresses.

Verified with mode transitions, fork inheritance, JIT rewrite, and clippy.

Co-Authored-By: Codex <codex@openai.com>"
```

### Task 7: Signed Acceptance, Fast-Path Guard, and Documentation

**Files:**
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md`
- Modify: `docs/superpowers/plans/2026-07-12-native-dsr-only-backend-comparison.md`

**Interfaces:**
- Produces signed low-`ET_EXEC` authority.
- Produces direct-mode no-regression evidence.
- Produces handoff to the post-fork lifecycle project.

- [ ] **Step 1: Replace rejection with a live acceptance test**

```rust
#[test]
fn native_low_et_exec_runs_through_biased_dsr() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = carrick_bin().expect("signed carrick binary");
    ensure_signed(&bin);
    let probe = ensure_native_et_exec_probe("devnullseek");
    let out = run_native_run_elf(&bin, &probe, "native16k");
    assert!(out.contains("status=exit status: 0"), "{out}");
    assert!(out.contains("devnull_lseek_cur0=true"), "{out}");
    assert!(out.contains("devnull_lseek_set=true"), "{out}");
}
```

Add a forked `ET_EXEC` witness that reports PCs/pointers below 4 GiB and proves the child retains guest values. Do not use `altstacktid`; it belongs to the next project.

- [ ] **Step 2: Verify RED against the pre-feature binary**

```bash
cargo test -p carrick-cli --test conformance native_low_et_exec_runs_through_biased_dsr -- --nocapture
```

Expected on the pre-feature signed binary: typed hard-4-GiB rejection. Restore current implementation before continuing.

- [ ] **Step 3: Run signed GREEN acceptance**

```bash
just build
codesign --verify --verbose=2 target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
cargo test -p carrick-cli --test conformance native_low_et_exec_runs_through_biased_dsr -- --nocapture
cargo test -p carrick-cli --test conformance native16k_mprotect_exec_permissions_match_linux -- --nocapture
CARRICK_EXEC_BACKEND=native CARRICK_NATIVE_PAGE_PROFILE=native16k scripts/run-probe.sh nativebrk
cargo test -p carrick-cli --test perf_runner direct_ -- --nocapture
```

Expected: signed low `ET_EXEC`, JIT rewrite, guest BRK semantics, and direct PIE guards pass.

- [ ] **Step 4: Run full local gates**

```bash
just fmt-check
just clippy
just lint-domains
git diff --check
RUST_TEST_THREADS=1 just ci
```

Expected: all commands pass. Do not run `just bench-backends full`; Task 6 remains blocked on post-fork lifecycle.

- [ ] **Step 5: Update durable documentation**

Record the measured 4 GiB XNU minimum, direct versus biased DSR modes, guest-coordinate contract, audited memory families, direct-mode fast-path guard, signed results, and the still-authoritative isolated `altstacktid` timeout plus invalid 331/378 campaign. Do not publish projected probe counts.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-cli/tests/conformance.rs docs/dynamic-syscall-rewriter.md \
  docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md \
  docs/superpowers/plans/2026-07-12-native-dsr-only-backend-comparison.md
git commit -m "test(native): prove biased ET_EXEC execution" \
  -m "Replace page-zero rejection with signed low-address ET_EXEC execution, forked guest-address evidence, and direct-mode guards. Keep post-fork lifecycle separate from performance authority.

Verified with signed native acceptance and full local CI.

Co-Authored-By: Codex <codex@openai.com>"
```

## Completion Boundary

This plan is complete when a signed low-address AArch64 `ET_EXEC` runs through native16k DSR; guest pointers, faults, and diagnostics remain Linux-valued; host collisions are non-destructive; direct PIE emission is byte-pinned; guest BRK semantics pass; and `just ci` passes.

Next, write and approve a separate post-fork multithreaded DSR `execve` design/plan, rerun the authoritative native probe lane, and only then resume `just bench-backends full`.
