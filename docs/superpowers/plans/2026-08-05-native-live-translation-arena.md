# Native Live Translation Arena Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make compiler translations emitted by one Darwin/AArch64 native process directly executable by later fork/exec siblings, with zero waiting and a retained cold-`go build` child-CPU and wall-time improvement of at least 10%.

**Architecture:** Add a Darwin Mach-backed append-only code/control arena whose process-local view is consumed by the AArch64 translator. READY records contain immutable, guardless INITIAL-generation blocks and offset-only metadata. Publishers claim with CAS and emit once into a shared RW/RX reservation; consumers map the arena anywhere and execute through a local catalog. Every miss, race, stale page, corrupt record, or unsupported block falls through immediately to the existing private translator.

**Tech Stack:** Rust 2024, AArch64 dynasm emission, Darwin Mach VM and registered-port APIs, Carrick NATIVEPERF/USDT, LLDB core export, `just ci`, signed native conformance, controlled ABBA performance harness.

## Global Constraints

- Work only in `/Volumes/CaseSensitive/carrick/.worktrees/native-store-default` on `codex/native-store-default`.
- Preserve every retained performance win already on the branch and unrelated worktree dirt.
- Do not merge, push, or move `main` without separate user approval.
- Keep Tier D default-off.
- Never wait for a shared publication. `READY` consumes; `EMPTY` may win a single CAS; every other state immediately translates privately.
- Never patch a READY shared source block. Shared code is immutable after the release-store publication.
- Never weaken generation, fault, mmap, signal, fork, or exec semantics.
- Keep full eager translation deferred as documented in the design.
- Use red-first focused tests for every behavior change, then the repository recipes. Do not use a bare parallel `cargo test` for `carrick-runtime`.
- Make narrow logical commits after each task. Run `git diff --check` and inspect `git status --short` before every commit.
- The performance kill gate is 10% in both child CPU and wall time. A mechanism win without the real workload win is removed.

---

### Task 1: Freeze the approved contract and evidence boundary

**Files:**

- Add: `docs/superpowers/specs/2026-08-05-native-live-translation-arena-design.md`
- Add: `docs/superpowers/plans/2026-08-05-native-live-translation-arena.md`
- Modify after implementation: `handoff.md`

- [x] Write the design with the measured compiler opportunity, the completed-before overlap, the Mach coherence/revocation/self-exec proofs, and the prior monotonic-augmentation negative result.
- [x] Record the zero-wait state machine, immutable READY rule, exact identity, source-page revocation, stale-instruction-abort classifier, export-only debugging, and the 10% kill gate.
- [x] Review both documents for contradictions with the controller and old rejected shared-arena design.
- [x] Run:

  ```bash
  rg -n "TBD|TO.?DO|placeholder|fixed-address MAP_JIT|wait for" \
    docs/superpowers/specs/2026-08-05-native-live-translation-arena-design.md \
    docs/superpowers/plans/2026-08-05-native-live-translation-arena.md
  git diff --check
  ```

- [ ] Commit:

  ```bash
  git add docs/superpowers/specs/2026-08-05-native-live-translation-arena-design.md \
    docs/superpowers/plans/2026-08-05-native-live-translation-arena.md
  git commit -m "docs: design live native translation arena"
  ```

---

### Task 2: Add the offset-only live-arena protocol and zero-wait state machine

**Files:**

- Add: `crates/carrick-dsr-aarch64/src/live_arena.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`

- [ ] Add red unit tests in `live_arena.rs` named:

  - `ready_acquire_exposes_complete_record`
  - `building_record_falls_back_without_waiting`
  - `failed_record_falls_back_without_waiting`
  - `owner_death_never_steals_building_record`
  - `record_rejects_misaligned_or_overflowing_extents`
  - `record_rejects_wrong_unit_key_or_translator_abi`
  - `reservation_cursors_never_overlap_under_concurrency`
  - `ready_record_is_immutable`

- [ ] Run the focused test and prove the new module is missing or the tests fail:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_arena -- --nocapture
  ```

- [ ] Implement the wire types with fixed-width fields and compile-time layout assertions:

  ```rust
  pub const LIVE_ARENA_SCHEMA_V1: u32 = 1;
  pub const LIVE_BLOCK_EMPTY: u32 = 0;
  pub const LIVE_BLOCK_BUILDING: u32 = 1;
  pub const LIVE_BLOCK_READY: u32 = 2;
  pub const LIVE_BLOCK_FAILED: u32 = 3;

  #[repr(C, align(64))]
  pub struct LiveBlockRecordV1 {
      state: AtomicU32,
      owner_pid: AtomicI32,
      unit_key_digest: [u8; 32],
      guest_start: u64,
      source_page: u64,
      code_offset: u64,
      code_len: u32,
      entry_offset: u32,
      hot_offset: u64,
      hot_len: u32,
      cold_offset: u64,
      cold_len: u32,
      code_sha256: [u8; 32],
  }

  pub enum LiveLookup<'a> {
      Ready(ValidatedLiveBlock<'a>),
      Publish(LivePublishClaim<'a>),
      Private(LivePrivateReason),
  }
  ```

- [ ] Make `TranslationUnitKey::live_digest()` domain-separate the existing exact key with `b"carrick-live-arena-v1"`, schema, and `TRANSLATOR_ABI_CURRENT`; do not create a basename or partial-key path.
- [ ] Implement lookup exactly as one acquire load plus, only for `EMPTY`, one `compare_exchange(EMPTY, BUILDING, AcqRel, Acquire)`. A CAS loss returns `Private` without retrying.
- [ ] Store records in a fixed 131,072-slot open-addressed table. Hash
  `(unit_key_digest, guest_start)` to the low 17 bits and probe at most 16
  consecutive slots. Continue only past a READY different key or a
  release-published FAILED different key. BUILDING, same-key FAILED, CAS loss,
  or 16 exhausted probes immediately returns `Private`; bounded collision
  probing is never a publication wait/retry.
- [ ] Implement append-only code/hot/cold reservations with atomic fetch-update and checked page/instruction alignment. Capacity failure stores `FAILED` and returns the private disposition.
- [ ] Implement publication as field writes, bounds/hash validation, then one `state.store(READY, Release)`. Expose no method capable of modifying a READY record.
- [ ] Run:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_arena -- --nocapture
  cargo test -p carrick-dsr-aarch64 shared_cache -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-dsr-aarch64/src/lib.rs \
    crates/carrick-dsr-aarch64/src/live_arena.rs \
    crates/carrick-dsr-aarch64/src/shared_cache.rs
  git commit -m "feat(dsr): add zero-wait live arena protocol"
  ```

---

### Task 3: Implement Darwin Mach code/control mappings

**Files:**

- Add: `crates/carrick-native-darwin/src/live_arena.rs`
- Modify: `crates/carrick-native-darwin/src/lib.rs`
- Modify: `crates/carrick-native-darwin/src/jit.rs`
- Modify: `crates/carrick-native-darwin/Cargo.toml`

- [ ] Add red Darwin live tests named:

  - `writer_and_rx_alias_execute_coherent_code`
  - `memory_entry_maps_at_unrelated_addresses`
  - `task_local_rx_revoke_does_not_revoke_parent`
  - `drop_deallocates_aliases_and_send_rights`
  - `subregion_exposes_matching_rw_and_rx_offsets`

  The coherence test writes `mov w0,#42; ret`, executes 42 through RX, replaces the immediate through RW, calls the existing instruction-cache shim, and executes 43.

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-native-darwin live_arena -- --nocapture
  ```

- [ ] Add the target production dependency:

  ```toml
  [target.'cfg(target_os = "macos")'.dependencies]
  mach2.workspace = true
  ```

- [ ] Implement RAII wrappers with no raw Mach port escaping their owner:

  ```rust
  pub struct DarwinLiveArena {
      code_entry: MachSendRight,
      control_entry: MachSendRight,
      code_rw: VmMapping,
      code_rx: VmMapping,
      control_rw: VmMapping,
      code_len: usize,
      control_len: usize,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub struct LiveArenaTransitV1 {
      pub schema: u32,
      pub code_len: u64,
      pub control_len: u64,
      pub nonce: [u8; 16],
  }
  ```

- [ ] Create the code/control objects with `mach_vm_allocate` plus `mach_make_memory_entry_64`. Map separate code RW and RX aliases with `mach_vm_map`, never W+X on one alias. Validate page alignment, requested size, max protection, and returned object size.
- [ ] Provide `DarwinLiveArena::jit_region(range)` returning a borrowed `JitRegion { exec_base: rx+offset, write_base: rw+offset, capacity }` and a stateless `LiveArenaHostJit` whose write toggles are no-ops and whose flush calls `carrick_native_clear_icache` on the RX address.
- [ ] Provide `revoke_rx(range)` using `mach_vm_protect(..., PROT_NONE)` and a checked `restore_rx_for_test` only under `cfg(test)`.
- [ ] Expose fresh code/control send-right duplication for the exec transaction; do not expose receive rights or a global mutable raw port.
- [ ] Run:

  ```bash
  cargo test -p carrick-native-darwin live_arena -- --nocapture
  cargo test -p carrick-native-darwin jit -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-native-darwin/Cargo.toml \
    crates/carrick-native-darwin/src/lib.rs \
    crates/carrick-native-darwin/src/jit.rs \
    crates/carrick-native-darwin/src/live_arena.rs
  git commit -m "feat(darwin): map live translation arena aliases"
  ```

---

### Task 4: Preserve the live arena through every host self-exec

**Files:**

- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-native-darwin/src/live_arena.rs`

- [ ] Add red tests named:

  - `registered_port_transaction_preserves_all_three_slots`
  - `failed_exec_restores_original_registered_port_vector`
  - `resume_rejects_missing_swapped_or_extra_arena_rights`
  - `fork_exec_successor_maps_arena_at_fresh_addresses`
  - `fork_exec_successor_observes_parent_code_publication`

- [ ] Run and prove red:

  ```bash
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_live_arena -- --nocapture
  ```

- [ ] Extend `NativeGuestExecV1` with a required option in the current capsule
  schema. Do not add a legacy/default decode arm; Carrick self-execs the same
  binary and carries no backward-compatible capsule reader:

  ```rust
  pub(crate) live_arena: Option<NativeReexecLiveArenaV1>,

  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  pub(crate) struct NativeReexecLiveArenaV1 {
      schema: u32,
      code_len: u64,
      control_len: u64,
      nonce: [u8; 16],
  }
  ```

- [ ] Add `RegisteredPortTransaction` in the Darwin host crate. Its constructor calls `mach_ports_lookup`, normalizes to exactly `TASK_PORT_REGISTER_MAX == 3`, retains the complete old vector, duplicates fresh arena rights into the two typed slots, and calls `mach_ports_register` once. Its `Drop` restores the old vector unless `commit_after_exec_adoption()` consumed the transaction.
- [ ] In `exec_capsule_with`, prepare registered ports only after every fd transaction and capsule validation succeeds, immediately before `invoke_exec`. If `execve` returns, RAII restores both fd flags and the registered-port vector.
- [ ] In `resume`, call arena adoption after capsule validation and before rebuilding mapped memory or the translator. Validate schema, nonce, object sizes, protections, and both typed slots; then clear the typed registered slots while preserving the third slot and deallocate transit rights.
- [ ] Make the real lifecycle test fork, register, invoke the existing `__native-exec-resume` path, map at unrelated VAs, execute 42, accept a parent synchronization byte, and execute 43.
- [ ] Run:

  ```bash
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_live_arena -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_capsule -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-native-darwin/src/live_arena.rs \
    crates/carrick-runtime/src/native_exec_capsule.rs \
    crates/carrick-runtime/src/native_darwin.rs
  git commit -m "feat(native): carry live arena through self exec"
  ```

---

### Task 5: Emit one immutable INITIAL-generation block directly into the arena

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs`
- Modify: `crates/carrick-dsr-aarch64/src/live_arena.rs`

- [ ] Add red structural tests named:

  - `shared_initial_entry_is_private_trusted_suffix_without_guard`
  - `shared_initial_emission_has_no_process_relocations`
  - `shared_initial_emission_preserves_generation_publish_and_guest_x17`
  - `shared_ready_source_is_never_patchable`
  - `building_source_can_bind_only_an_already_ready_shared_target`

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 shared_initial -- --nocapture
  ```

- [ ] Replace the emitter's optional guard with an explicit entry policy:

  ```rust
  enum GenerationEntry {
      Unguarded,
      PrivateAbsolute(GenerationGuard),
      SharedInitial,
  }
  ```

  Existing public emit functions keep their current byte output by selecting
  `PrivateAbsolute` or `Unguarded`. Add:

  ```rust
  pub fn emit_block_recording_shared_initial(
      cache: &mut TranslationCache,
      plan: &BlockPlan,
      mode: EmitAddressMode,
      source_words: Vec<u32>,
  ) -> Result<(EmittedBlock, ArtifactRecord), DsrError>;
  ```

- [ ] `SharedInitial` begins with the existing trusted suffix: materialize `CodeGeneration::INITIAL` into x17, store it to `CTX_GENERATION`, and reload guest x17. It emits no generation address, no `ldar`, no comparison, and no stale branch. Its entry offset is zero.
- [ ] Assert the finished artifact record contains zero process relocations. A nonzero relocation count returns `DsrError::CachePolicy` before READY publication.
- [ ] Assemble once through dynasm and publish the byte stream into the exact reserved arena `JitRegion`; do not publish to the private cache, serialize a second unit, or replay.
- [ ] Before READY, patch only links whose targets are already READY in the same local arena view and are branch-reachable. Leave every other source word at the existing fall-into-gateway-stub encoding. Remove any shared-source site from the mutable `direct_link_incoming` collection.
- [ ] Run byte-parity tests proving the private modes are unchanged, then:

  ```bash
  cargo test -p carrick-dsr-aarch64 emit -- --nocapture
  cargo test -p carrick-dsr-aarch64 artifact_spike -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-dsr-aarch64/src/emit.rs \
    crates/carrick-dsr-aarch64/src/artifact_spike.rs \
    crates/carrick-dsr-aarch64/src/live_arena.rs
  git commit -m "feat(dsr): emit immutable shared initial blocks"
  ```

---

### Task 6: Integrate READY lookup and direct publication into `ProcessState`

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

- [ ] Add red translator tests named:

  - `ready_live_block_bypasses_private_translation_and_replay`
  - `building_live_block_translates_privately_without_waiting`
  - `live_publish_winner_emits_once_into_shared_region`
  - `sensitive_or_regenerated_block_is_always_private`
  - `private_source_may_link_to_shared_target`
  - `shared_source_never_enters_mutable_link_index`
  - `live_block_fault_metadata_decodes_lazily`
  - `live_range_has_process_local_target_authority`

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_block -- --nocapture
  ```

- [ ] Add `live_arena: Option<Arc<LiveArenaProcessView>>`, a shared published index, and a source-page slab catalog to `ProcessState`. Configure them from `NativeMappedMemory::configure_shared_translation` only when `CARRICK_DSR_LIVE_ARENA=compiler` and the exact unit-key policy matches.
- [ ] Add a publication kind rather than inferring ownership from addresses:

  ```rust
  pub enum PublishedCodeKind {
      Private,
      LiveArena { slab: LiveSlabId },
  }

  pub enum PublishedBlockMetadata {
      Owned { map: Vec<PcMapEntry>, recovery: Vec<RecoveryEntry> },
      Unit { manifest: Arc<TranslationUnitManifest>, block: u32, bindings: ArtifactBindings },
      LiveArena { record: ValidatedLiveBlockHandle },
  }
  ```

- [ ] Extend `private_published_index` with a separate address-sorted live index. `published_block_containing` searches both, and `guest_pc_for_cache` decodes the shared cold stream only on fault/kick.
- [ ] At the top of the INITIAL-generation miss path, query the exact live record. A READY record validates hash/bounds/key, derives the local RX entry, installs target authority and metadata, and returns `TranslationOutcome::LiveArena` without touching `self.cache`. BUILDING/FAILED/CAS loss continues immediately to the unchanged private path.
- [ ] A CAS winner plans once, refuses sensitive metadata, reserves extents, emits once into the shared subregion, validates the source generation again, publishes metadata and READY, then installs its own local READY record through the same consumer path. If generation moved or any step fails, mark FAILED and privately translate.
- [ ] Teach target authority and indirect-cache publication that a live block is flavor 0 with the arena range's process-local `TargetCacheAuthority`. Private trusted entries remain flavor 1. Private direct links may patch to a shared target; shared source links are immutable stubs.
- [ ] Ensure `cache_used_bytes` remains the private-cache gauge and add distinct live code/metadata gauges so a READY hit cannot masquerade as private cache growth.
- [ ] Run:

  ```bash
  cargo test -p carrick-dsr-aarch64 translator -- --nocapture
  cargo test -p carrick-dsr-aarch64 gateway -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime dsr -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-dsr-aarch64/src/translator.rs \
    crates/carrick-dsr-aarch64/src/gateway.rs \
    crates/carrick-dsr-aarch64/src/mapped_memory.rs \
    crates/carrick-runtime/src/native_darwin.rs
  git commit -m "feat(native): execute ready live arena blocks"
  ```

---

### Task 7: Revoke mutated source pages and recover only exact stale instruction aborts

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/live_arena.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify if the snapshot lacks the needed syndrome field: `crates/carrick-native-darwin/csrc/native_darwin.c`

- [ ] Add red tests named:

  - `guest_write_revokes_only_matching_source_page_slabs`
  - `mprotect_munmap_and_remap_share_the_revocation_seam`
  - `instruction_abort_in_revoked_slab_recovers_guest_pc_privately`
  - `data_abort_in_revoked_slab_is_not_consumed`
  - `instruction_abort_in_foreign_prot_none_range_is_not_consumed`
  - `mismatched_pc_and_far_is_not_consumed`
  - `fork_child_rebuilds_revoked_slab_catalog_before_guest_entry`
  - `in_process_exec_drops_retired_live_ranges`

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_revoke -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime live_revoke -- --nocapture
  ```

- [ ] Add one callback from every `PageGenerationTable::note_guest_code_write` owner into `LiveArenaProcessView::revoke_source_range`. Index guest 16 KiB source pages to all local RX extents containing their shared blocks, deduplicate extents, and call Darwin `mach_vm_protect(PROT_NONE)` once per active extent.
- [ ] Keep revocation task-local. Do not write a shared FAILED/REVOKED state and do not change another process's generation or protection.
- [ ] Implement the exact classifier:

  ```rust
  fn stale_live_instruction_abort(
      &self,
      esr: u64,
      pc: u64,
      far: u64,
  ) -> Option<LiveStaleRecovery> {
      let ec = (esr >> 26) & 0x3f;
      if !matches!(ec, 0x20 | 0x21) || pc != far {
          return None;
      }
      self.revoked_slab_containing(pc)?.recover(pc)
  }
  ```

- [ ] On a classified stale abort, use the lazy live metadata to restore the guest snapshot, set the guest PC, remove the stale live block from process/thread lookup indexes, and run the normal private translation path against the newly observed generation. Do not remap or reactivate the revoked slab.
- [ ] Add live tests that execute from the revoked alias and assert the C signal snapshot retains exact ESR, FAR, and PC. Preserve the current C shim unless the test proves one field is missing.
- [ ] Run:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_revoke -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime live_revoke -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native16k -- --nocapture
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-dsr-aarch64/src/live_arena.rs \
    crates/carrick-dsr-aarch64/src/mapped_memory.rs \
    crates/carrick-dsr-aarch64/src/translator.rs \
    crates/carrick-runtime/src/native_darwin.rs \
    crates/carrick-native-darwin/csrc/native_darwin.c
  git commit -m "fix(native): recover revoked live translations safely"
  ```

---

### Task 8: Add authenticated performance counters and export-only core diagnostics

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr/src/profile.rs`
- Modify: `crates/carrick-dsr/src/probes.rs`
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`
- Add: `scripts/dtrace/dsr-live-arena.d`
- Modify: `scripts/carrick_lldb.py`

- [ ] Add red serialization tests proving every counter appears once in the `resolver-process` NATIVEPERF frame and round-trips through the parser.
- [ ] Extend `ResolverStats`, `ResolverStat::ALL`, `ProfileSnapshot`, and serialization with the twelve counters named in the design. Use saturating accounting and process deltas exactly like existing shared-unit counters.
- [ ] Add typed USDT outcomes for claim win, CAS loss, READY hit, private fallback, validation refusal, and revocation. Add `TraceProfileKind::DsrLiveArena`, its authenticated `scripts/dtrace/dsr-live-arena.d` program, typed parser, and zero-event rejection; do not add a standalone harness.
- [ ] Add LLDB export structures with stable `repr(C)` headers and magic/version fields. Extend `scripts/carrick_lldb.py` with `xlat-live-arena` to print mappings, READY records, revoked slabs, and cache-PC to guest-PC recovery from a live process or core. It must not import or modify an arena.
- [ ] Run:

  ```bash
  cargo test -p carrick-dsr profile -- --nocapture
  cargo test -p carrick-observability --lib -- --nocapture
  cargo test -p carrick-cli --test trace_profile dsr_live_arena -- --nocapture
  python3 -m py_compile scripts/carrick_lldb.py
  cargo fmt --all -- --check
  ```

- [ ] Commit:

  ```bash
  git add crates/carrick-dsr-aarch64/src/translator.rs \
    crates/carrick-dsr/src/profile.rs \
    crates/carrick-dsr/src/probes.rs \
    crates/carrick-observability/src/probes.rs \
    crates/carrick-cli/src/trace_profile.rs \
    crates/carrick-cli/tests/trace_profile.rs \
    scripts/dtrace/dsr-live-arena.d scripts/carrick_lldb.py
  git commit -m "feat(debug): export live translation arena state"
  ```

---

### Task 9: Close correctness gates on the compiler-only slice

**Files:**

- Modify: exact focused tests adjacent to the source files above
- Add durable evidence under: `docs/perf-results/`

- [ ] Build the signed current candidate with the evidence switch default-off:

  ```bash
  scripts/build-signed.sh
  otool -l target/release/carrick | rg '__dof_carrick'
  codesign -d --entitlements :- target/release/carrick
  shasum -a 256 target/release/carrick
  ```

- [ ] Run the complete focused matrix: READY consume, BUILDING fallback, owner death, corrupt bounds/hash, sensitive fallback, mutation, mmap/munmap/mprotect, fork, in-process exec, host self-exec, signals, indirect edges, and lazy fault recovery.
- [ ] Run the full local gate serialized:

  ```bash
  RUST_TEST_THREADS=1 just ci
  ```

- [ ] Run native smoke and the applicable probe/conformance gate through the repository recipes. Stamp a unique `CARRICK_RUN_ID`; reap only that id with `scripts/sudo/kill.sh`. Never run Carrick and Docker concurrently.
- [ ] Capture an LLDB live export and a core export from a disposable compiler child, and verify both resolve the same READY record and cache PC.
- [ ] Capture the authenticated DTrace arena profile to prove READY hits replace private translations. Let the trace finish normally; do not abort fasttrap against a continuing workload.
- [ ] If any correctness gate fails, attribute with current and pre-change binaries before fixing. Do not proceed to ABBA until every required gate is green.
- [ ] Commit durable correctness and mechanism evidence:

  ```bash
  git add docs/perf-results
  git commit -m "test(native): qualify live arena compiler slice"
  ```

---

### Task 10: Run the 10% retention gate and either broaden or remove

**Files:**

- Add: `docs/perf-results/2026-08-05-native-live-arena-compiler-abba.json`
- Modify: `docs/superpowers/specs/2026-08-02-performance-roadmap.md`
- Modify: `handoff.md`
- Modify on retention: remove the temporary compiler-only switch and superseded per-process replay path from the implementation files

- [ ] Requalify the exact signed tip and bind binary SHA-256, source commit, semantic knob set, run receipts, power state, and core-class policy in the evidence artifact.
- [ ] Run quiet-box ABBA with at least eight samples per arm:

  - A: persistent store on, live arena off;
  - B: persistent store on, live arena compiler slice on.

  Record child CPU, workload wall, self CPU, system/user split, READY hits,
  publish wins/losses, BUILDING fallbacks, private translations, code bytes,
  metadata bytes, and revoked slabs.

- [ ] Compute geometric-mean ratios and confidence intervals. Retain only if child CPU and wall ratios are each at most 0.90 and each confidence interval is below 1.00.
- [ ] Run the compute, filesystem, startup, 20-exec, and workload-spread sentinels. Reject any sentinel regression above 3% unless repeated attribution proves unrelated noise.
- [ ] If the slice fails the 10% gate, delete Tasks 2-9 runtime changes while preserving the design and negative evidence in a narrow revert commit. Reprofile the shipped-default lane before choosing another redesign.
- [ ] If the slice passes, remove `CARRICK_DSR_LIVE_ARENA=compiler`, enable exact-key live sharing by default, and delete the superseded per-process unit replay implementation rather than retaining two production paths. Rerun `RUST_TEST_THREADS=1 just ci`, signed smoke, conformance, and the official Carrick-then-Docker cold-build comparison.
- [ ] Update the roadmap and handoff with measured results separated from projections, the new official ratio, remaining CPU buckets, and confidence levels for 8x, 5x, 3x, and 2x.
- [ ] Stage only the implementation files changed by the retained or rejected
  candidate (never the whole `crates/` or `scripts/` tree), then commit:

  ```bash
  git add docs/perf-results/2026-08-05-native-live-arena-compiler-abba.json \
    docs/superpowers/specs/2026-08-02-performance-roadmap.md handoff.md
  git add -A -- \
    crates/carrick-dsr-aarch64/src/lib.rs \
    crates/carrick-dsr-aarch64/src/live_arena.rs \
    crates/carrick-dsr-aarch64/src/shared_cache.rs \
    crates/carrick-dsr-aarch64/src/emit.rs \
    crates/carrick-dsr-aarch64/src/artifact_spike.rs \
    crates/carrick-dsr-aarch64/src/translator.rs \
    crates/carrick-dsr-aarch64/src/gateway.rs \
    crates/carrick-dsr-aarch64/src/mapped_memory.rs \
    crates/carrick-native-darwin/Cargo.toml \
    crates/carrick-native-darwin/src/lib.rs \
    crates/carrick-native-darwin/src/jit.rs \
    crates/carrick-native-darwin/src/live_arena.rs \
    crates/carrick-native-darwin/csrc/native_darwin.c \
    crates/carrick-runtime/src/native_exec_capsule.rs \
    crates/carrick-runtime/src/native_darwin.rs \
    crates/carrick-dsr/src/profile.rs crates/carrick-dsr/src/probes.rs \
    crates/carrick-observability/src/probes.rs \
    crates/carrick-cli/src/trace_profile.rs \
    crates/carrick-cli/tests/trace_profile.rs \
    scripts/dtrace/dsr-live-arena.d scripts/carrick_lldb.py
  git commit -m "perf(native): retain live compiler translation arena"
  ```

  If the gate rejects the candidate, use:

  ```bash
  git add docs/perf-results/2026-08-05-native-live-arena-compiler-abba.json \
    docs/superpowers/specs/2026-08-02-performance-roadmap.md handoff.md
  git add -A -- \
    crates/carrick-dsr-aarch64/src/lib.rs \
    crates/carrick-dsr-aarch64/src/live_arena.rs \
    crates/carrick-dsr-aarch64/src/shared_cache.rs \
    crates/carrick-dsr-aarch64/src/emit.rs \
    crates/carrick-dsr-aarch64/src/artifact_spike.rs \
    crates/carrick-dsr-aarch64/src/translator.rs \
    crates/carrick-dsr-aarch64/src/gateway.rs \
    crates/carrick-dsr-aarch64/src/mapped_memory.rs \
    crates/carrick-native-darwin/Cargo.toml \
    crates/carrick-native-darwin/src/lib.rs \
    crates/carrick-native-darwin/src/jit.rs \
    crates/carrick-native-darwin/src/live_arena.rs \
    crates/carrick-native-darwin/csrc/native_darwin.c \
    crates/carrick-runtime/src/native_exec_capsule.rs \
    crates/carrick-runtime/src/native_darwin.rs \
    crates/carrick-dsr/src/profile.rs crates/carrick-dsr/src/probes.rs \
    crates/carrick-observability/src/probes.rs \
    crates/carrick-cli/src/trace_profile.rs \
    crates/carrick-cli/tests/trace_profile.rs \
    scripts/dtrace/dsr-live-arena.d scripts/carrick_lldb.py
  git commit -m "perf(native): record rejected live arena slice"
  ```

---

## Completion Checklist

- [ ] Every READY record is immutable and acquire/release ordered.
- [ ] No shared lookup waits, retries, or steals a dead owner's record.
- [ ] The real fork/self-exec path preserves the complete registered-port vector.
- [ ] A consumer maps at an arbitrary address and executes coherent code.
- [ ] Source mutation revokes only the calling task's matching RX slabs.
- [ ] Only exact revoked-slab instruction aborts are recovered.
- [ ] Sensitive and regenerated blocks remain private.
- [ ] LLDB works live and from a core; the interface is export-only.
- [ ] `RUST_TEST_THREADS=1 just ci`, signed smoke, and conformance pass.
- [ ] Controlled ABBA proves or rejects a ≥10% child-CPU and wall-time win.
- [ ] The shipped-default official ratio and remaining path to 3x are recorded.
