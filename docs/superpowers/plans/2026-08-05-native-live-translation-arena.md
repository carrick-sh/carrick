# Native Live Translation Arena Implementation Plan

> **CLOSED 2026-08-06 — Task 10 failure arm executed.** Tasks 2-9 landed and
> were review-clean, but the Task-10 gate was a foregone conclusion: policy-ON
> lost the cold go build by ~36x wall and the 20-exec micro by ~16%, the
> structural cause (immutable shared code cannot be link-patched; forward-
> dominated residue unreachable by publication-window binding) was empirically
> pinned at `c1600799`/`9922cb26`, and the original exec-startup prize was
> already delivered by the persistent unit store. The runtime was deleted in
> `1cb06de6` (`revert(native): remove the live translation arena runtime`);
> the deadlock fix (`8d5b3a19`+`bcd2062e`), the 6E catalog publication, the
> trace-instrument improvements (`08531c73`+`d774a3ff`), and the host test
> fixes survive. Evidence:
> [`2026-08-06-live-arena-36x-attribution.md`](../../perf-results/2026-08-06-live-arena-36x-attribution.md),
> [`2026-08-06-native-live-arena-compiler-qualification.md`](../../perf-results/2026-08-06-native-live-arena-compiler-qualification.md),
> and the campaign ledger
> `.superpowers/sdd/2026-08-05-native-live-translation-arena-task6/progress.md`.

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

> Historical completed-slice record for Tasks 2–4: every V1 protocol,
> `LiveArenaTransitV1`, `NativeGuestExecV1`, `NativeReexecLiveArenaV1`,
> 131,072 x 192-byte table, and per-block cursor instruction in those tasks
> describes the first substrate only. Do not execute or retain those V1
> instructions: the measured Task 6C1 census rejected that allocator, and
> authoritative Task 6B3 replaces every affected portable, Darwin, runtime,
> and outer-capsule layer with V2 and deletes the V1 path.

**Files:**

- Add: `crates/carrick-dsr-aarch64/src/live_arena.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`

- [x] Add red unit tests in `live_arena.rs` named:

  - `ready_acquire_exposes_complete_record`
  - `building_record_falls_back_without_waiting`
  - `failed_record_falls_back_without_waiting`
  - `owner_death_never_steals_building_record`
  - `record_rejects_misaligned_or_overflowing_extents`
  - `record_rejects_wrong_unit_key_or_translator_abi`
  - `reservation_cursors_never_overlap_under_concurrency`
  - `ready_record_is_immutable`

- [x] Run the focused test and prove the new module is missing or the tests fail:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_arena -- --nocapture
  ```

- [x] Implement the wire types with fixed-width fields and compile-time layout assertions:

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

- [x] Make `TranslationUnitKey::live_digest()` domain-separate the existing exact key with `b"carrick-live-arena-v1"`, schema, and `TRANSLATOR_ABI_CURRENT`; do not create a basename or partial-key path.
- [x] Implement lookup exactly as one acquire load plus, only for `EMPTY`, one `compare_exchange(EMPTY, BUILDING, AcqRel, Acquire)`. A CAS loss returns `Private` without retrying.
- [x] Store records in a fixed 131,072-slot open-addressed table. Hash
  `(unit_key_digest, guest_start)` to the low 17 bits and probe at most 16
  consecutive slots. Continue only past a READY different key or a
  release-published FAILED different key. BUILDING, same-key FAILED, CAS loss,
  or 16 exhausted probes immediately returns `Private`; bounded collision
  probing is never a publication wait/retry.
- [x] Implement append-only code/hot/cold reservations with atomic fetch-update and checked page/instruction alignment. Capacity failure stores `FAILED` and returns the private disposition.
- [x] Implement publication as field writes, bounds/hash validation, then one `state.store(READY, Release)`. Expose no method capable of modifying a READY record.
- [x] Run:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_arena -- --nocapture
  cargo test -p carrick-dsr-aarch64 shared_cache -- --nocapture
  cargo fmt --all -- --check
  ```

- [x] Commit:

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

- [x] Add red Darwin live tests named:

  - `writer_and_rx_alias_execute_coherent_code`
  - `memory_entry_maps_at_unrelated_addresses`
  - `task_local_rx_revoke_does_not_revoke_parent`
  - `drop_deallocates_aliases_and_send_rights`
  - `subregion_exposes_matching_rw_and_rx_offsets`

  The coherence test writes `mov w0,#42; ret`, executes 42 through RX, replaces the immediate through RW, calls the existing instruction-cache shim, and executes 43.

- [x] Run and prove red:

  ```bash
  cargo test -p carrick-native-darwin live_arena -- --nocapture
  ```

- [x] Add the target production dependency:

  ```toml
  [target.'cfg(target_os = "macos")'.dependencies]
  mach2.workspace = true
  ```

- [x] Implement RAII wrappers with no raw Mach port escaping their owner:

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

- [x] Create the control object with `mach_vm_allocate` plus `mach_make_memory_entry_64`. Create the code entry from a private constructor-only nominal-RWX `MAP_JIT` bootstrap, containing no published code and unmapped before the arena escapes: the controlled PROT_NONE/RW/RX/plain-allocation matrix all failed on this host, and only this Darwin-required shape produced an entry that could map both permissions. Map the live code RW and RX aliases separately with `mach_vm_map`; retain no W+X mapping. Validate page alignment, requested size, max protection, and returned object size.
- [x] Provide `DarwinLiveArena::jit_region(range)` returning a `BorrowedLiveJitRegion` with checked matching RW/RX offsets, lifetime-bound pointer tokens, and no safe conversion to an owned `JitRegion`; a compile-fail test prevents the reviewed lifetime-erasure bug. Provide a stateless `LiveArenaHostJit` whose write toggles are no-ops and whose flush calls `carrick_native_clear_icache` on the RX address.
- [x] Provide `revoke_rx(range)` using `mach_vm_protect(..., PROT_NONE)` and a checked `restore_rx_for_test` only under `cfg(test)`.
- [x] Expose fresh code/control send-right duplication for the exec transaction; do not expose receive rights or a global mutable raw port.
- [x] Run:

  ```bash
  cargo test -p carrick-native-darwin live_arena -- --nocapture
  cargo test -p carrick-native-darwin jit -- --nocapture
  cargo fmt --all -- --check
  ```

- [x] Commit:

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

- [x] Add red tests named:

  - `registered_port_transaction_preserves_all_three_slots`
  - `failed_exec_restores_original_registered_port_vector`
  - `resume_rejects_missing_swapped_or_extra_arena_rights`
  - `fork_exec_successor_maps_arena_at_fresh_addresses`
  - `fork_exec_successor_observes_parent_code_publication`

- [x] Run and prove red:

  ```bash
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_live_arena -- --nocapture
  ```

- [x] Extend `NativeGuestExecV1` with a required option in the current capsule
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

- [x] Qualify and use Darwin's PID-preserving
  `posix_spawn(POSIX_SPAWN_SETEXEC)` registered-port action. Plain `execve`
  is a measured red control: it leaves one arena memory-entry right dead.
  `RegisteredPortExecPlan` snapshots and retains the existing slot-0 right,
  requires historical slots 1/2 to be empty, and owns duplicate code/control
  rights without mutating the old task. XNU atomically installs
  `[preserved slot 0, code, control]` only in the replacement task; a returned
  call therefore leaves the old registered vector unchanged.
- [x] In `exec_capsule_with`, prepare the immutable exec plan only after every
  fd transaction and capsule validation succeeds, immediately before the
  replacement call. The ordinary no-arena path remains `execve`.
- [x] In `resume`, adopt after capsule validation and before rebuilding mapped
  memory or the translator. Validate schema, nonce, object kinds and sizes,
  headers, protections, non-overlap, and slots 1/2; clear only slots 1/2 after
  success while preserving runtime-owned slot 0. Missing current-schema
  `live_arena` is rejected while explicit `null` remains valid.
- [x] Make the real lifecycle test create an independent publisher with true
  `posix_spawn` registered-port actions, independently adopt/map the arena,
  replace the owner at the same PID through the existing
  `__native-exec-resume` path, prove fresh VAs, execute 42, publish 43 through
  the helper's RW alias, execute 43 through the resumed owner's RX alias, and
  reap all processes cleanly.
- [x] Run after the lifecycle proof traverses production `resume()` rather than
  directly adopting from the libtest entry:

  ```bash
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_live_arena -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime native_exec_capsule -- --nocapture
  cargo fmt --all -- --check
  ```

- [x] Commit:

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

- [x] Add red structural tests named:

  - `shared_initial_entry_is_private_trusted_suffix_without_guard`
  - `shared_initial_emission_has_no_process_relocations`
  - `shared_initial_emission_preserves_generation_publish_and_guest_x17`
  - `shared_ready_source_is_never_patchable`
  - `prepared_shared_initial_reports_exact_lengths_before_publication`
  - `prepared_shared_initial_publishes_once_after_exact_reservation`
  - `rejected_shared_initial_never_grows_cache`

- [x] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 shared_initial -- --nocapture
  ```

- [x] Replace the emitter's optional guard with an explicit entry policy:

  ```rust
  enum GenerationEntry {
      Unguarded,
      PrivateAbsolute(GenerationGuard),
      SharedInitial,
  }
  ```

  Existing public emit functions keep their current byte output by selecting
  `PrivateAbsolute` or `Unguarded`. Add one type-state path, not a combined
  convenience API beside it:

  ```rust
  pub fn prepare_shared_initial(
      plan: &BlockPlan,
      mode: EmitAddressMode,
      source_words: Vec<u32>,
  ) -> Result<PreparedSharedInitial, DsrError>;

  impl PreparedSharedInitial {
      pub fn lengths(&self) -> SharedInitialLengths;
      pub fn code_bytes(&self) -> &[u8];
      pub fn hot_bytes(&self) -> &[u8];
      pub fn cold_bytes(&self) -> &[u8];
      pub fn link_candidates(&self) -> &[DirectLink];
      pub fn publish(
          self,
          cache: &mut TranslationCache,
      ) -> Result<EmittedBlock, DsrError>;
  }
  ```

- [x] `SharedInitial` begins with the existing trusted suffix: materialize `CodeGeneration::INITIAL` into x17, store it to `CTX_GENERATION`, and reload guest x17. It emits no generation address, no `ldar`, no comparison, and no stale branch. Its entry offset is zero.
- [x] Assert the finished shared metadata contains zero process relocations and
  zero process bindings. A violation returns `DsrError::CachePolicy` during
  preparation, before any cache cursor growth or executable visibility.
- [x] Assemble once through dynasm, encode pointer-free HOT/COLD metadata once,
  and expose exact checked code/HOT/COLD lengths before reservation. Consume
  the prepared object to publish the byte stream exactly once to the
  caller-provided `TranslationCache`; do not publish to the private cache,
  serialize a second code unit, or replay. Task 6 supplies that cache through
  a lifetime-bound Darwin bridge over the exact reserved arena range; Task 5
  must not reconstruct an owned `JitRegion` from borrowed pointer tokens.
- [x] Keep direct-link candidates private to `PreparedSharedInitial`. Remove
  any public/caller-asserted BUILDING enum and any post-publication source-site
  drain. Consuming publication returns a block with no mutable shared-source
  sites; Task 6 owns claim-bound, same-view prebinding before that transition.
- [x] Run byte-parity tests proving the private modes are unchanged, then:

  ```bash
  cargo test -p carrick-dsr-aarch64 emit -- --nocapture
  cargo test -p carrick-dsr-aarch64 artifact_spike -- --nocapture
  cargo fmt --all -- --check
  ```

- [x] Commit (implementation `f93e6977`, prepared-publication correction
  `e6661fe5`):

  ```bash
  git add crates/carrick-dsr-aarch64/src/emit.rs \
    crates/carrick-dsr-aarch64/src/artifact_spike.rs \
    crates/carrick-dsr-aarch64/src/live_arena.rs
  git commit -m "feat(dsr): emit immutable shared initial blocks"
  ```

---

### Task 6: Integrate READY lookup and direct publication into `ProcessState`

> **Execution split:** the Task 6 preflight proved the portable record/cursor
> state is process-private and the original monolithic checklist cannot be
> integrated soundly. Execute authoritative Tasks 6A–6B3, 6C1–6C2, and 6D–6F in
> [`2026-08-05-native-live-translation-arena-task6.md`](2026-08-05-native-live-translation-arena-task6.md).
> The checklist below remains the Task 6 completion rollup.

**Files:**

- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-native-darwin/src/live_arena.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

- [ ] Add red translator tests named:

  - `ready_live_block_bypasses_private_translation_and_replay`
  - `building_live_block_translates_privately_without_waiting`
  - `live_publish_winner_emits_once_into_shared_region`
  - `building_source_can_bind_only_an_already_ready_shared_target`
  - `sensitive_or_regenerated_block_is_always_private`
  - `private_source_may_link_to_shared_target`
  - `shared_source_never_enters_mutable_link_index`
  - `live_block_fault_metadata_decodes_lazily`
  - `live_range_has_process_local_target_authority`
  - `live_arena_translation_cache_cannot_outlive_arena_or_claim`

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_block -- --nocapture
  ```

- [ ] Add `live_arena: Option<Arc<LiveArenaProcessView>>`, a shared published index, and a source-page/group hint with descriptor-authoritative chunk enumeration to `ProcessState`. Configure them from `NativeMappedMemory::configure_shared_translation` only when `CARRICK_DSR_LIVE_ARENA=compiler` and the exact unit-key policy matches.
- [ ] Add a lifetime-bound `LiveArenaTranslationCache<'arena>` in the Darwin
  host crate. Construct it only by joining a checked
  `BorrowedLiveJitRegion<'arena>` with the unique Task-2 reservation
  capability; privately wrap the exact RW/RX aliases in a non-owning
  `TranslationCache`, expose only a temporary `&mut TranslationCache`, and
  prove the bridge cannot outlive either arena ownership or the claim. Never
  expose an owned `JitRegion` or reconstruct one at the Task-6 call site.
- [ ] Add a publication kind rather than inferring ownership from addresses:

  ```rust
  pub enum PublishedCodeKind {
      Private,
      LiveArena { group: LiveSourceGroupId, chunk: LiveChunkId },
  }

  pub enum PublishedBlockMetadata {
      Owned { map: Vec<PcMapEntry>, recovery: Vec<RecoveryEntry> },
      Unit { manifest: Arc<TranslationUnitManifest>, block: u32, bindings: ArtifactBindings },
      LiveArena { record: ValidatedLiveBlockHandle },
  }
  ```

- [ ] Extend `private_published_index` with a separate address-sorted live index. `published_block_containing` searches both, and `guest_pc_for_cache` decodes the shared cold stream only on fault/kick.
- [ ] At the top of the INITIAL-generation miss path, perform only the read-only exact READY lookup. A READY record validates hash/bounds/key, derives the local RX entry, installs target authority and metadata, and returns `TranslationOutcome::LiveArena` without touching `self.cache`.
- [ ] On a read-only miss, plan once and reject regenerated, cross-page, sensitive, exclusive, or unsupported shapes before shared mutation. Then call B3 `claim_eligible`: recheck the same-domain generation, resolve/create the exact source group, recheck generation again, and only then CAS the block. BUILDING/FAILED/CAS loss continues immediately to the unchanged private path. The unique block winner prepares once, reserves exact extents, emits once into the shared subregion, performs every Task 6B generation/metadata/flush proof, publishes READY, then installs its own local record through the same consumer path. Any failure marks only an acquired claim FAILED and privately translates.
- [ ] The winner first creates `PreparedSharedInitial`, then reserves its exact
  code/HOT/COLD lengths. While it still owns both the unique BUILDING claim and
  the prepared source, it may prebind only a branch-reachable target capability
  constructed by the same `LiveArenaProcessView` from an acquired validated
  READY record. Missing, cross-view, or unreachable targets retain the gateway
  stub. Consuming publication makes the source immutable and exposes no site
  that can enter `direct_link_incoming`.
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

  - `guest_write_revokes_only_matching_source_page_chunks`
  - `mprotect_munmap_and_remap_share_the_revocation_seam`
  - `instruction_abort_in_revoked_chunk_recovers_guest_pc_privately`
  - `data_abort_in_revoked_chunk_is_not_consumed`
  - `instruction_abort_in_foreign_prot_none_range_is_not_consumed`
  - `mismatched_pc_and_far_is_not_consumed`
  - `fork_child_rebuilds_revoked_chunk_catalog_before_guest_entry`
  - `in_process_exec_drops_retired_live_ranges`

- [ ] Run and prove red:

  ```bash
  cargo test -p carrick-dsr-aarch64 live_revoke -- --nocapture
  RUST_TEST_THREADS=1 cargo test -p carrick-runtime live_revoke -- --nocapture
  ```

- [ ] Add one callback from every `PageGenerationTable::note_guest_code_write` owner into `LiveArenaProcessView::revoke_source_range`. For the mutated guest 16 KiB source page, enumerate every ACTIVE descriptor owned by every locally executable exact group, including multiple chunks and multiple unit digests. The descriptor table is authority; any process-local catalog is only a validated hint and cannot omit later expansion. Deduplicate exact 64 KiB local RX chunks and call Darwin `mach_vm_protect(PROT_NONE)` once per active chunk.
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
      self.revoked_chunk_containing(pc)?.recover(pc)
  }
  ```

- [ ] On a classified stale abort, use the lazy live metadata to restore the guest snapshot, set the guest PC, remove the stale live block from process/thread lookup indexes, and run the normal private translation path against the newly observed generation. Do not remap or reactivate the revoked chunk.
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
- [ ] Add LLDB export structures with stable `repr(C)` headers and magic/version fields. Extend `scripts/carrick_lldb.py` with `xlat-live-arena` to print mappings, READY records, revoked chunks, and cache-PC to guest-PC recovery from a live process or core. It must not import or modify an arena.
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
  metadata bytes, and revoked chunks.

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
- [x] The real same-PID self-exec path preserves runtime slot 0, transports
  authenticated arena rights in slots 1/2, and clears only those typed slots
  after adoption.
- [x] A consumer maps at an arbitrary address and executes coherent code.
- [ ] Source mutation revokes only the calling task's matching RX chunks.
- [ ] Only exact revoked-chunk instruction aborts are recovered.
- [ ] Sensitive and regenerated blocks remain private.
- [ ] LLDB works live and from a core; the interface is export-only.
- [ ] `RUST_TEST_THREADS=1 just ci`, signed smoke, and conformance pass.
- [ ] Controlled ABBA proves or rejects a ≥10% child-CPU and wall-time win.
- [ ] The shipped-default official ratio and remaining path to 3x are recorded.
