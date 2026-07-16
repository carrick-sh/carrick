# Native Translation Artifact Feasibility Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove or falsify that container-scoped relocatable DSR artifacts materially improve the exact inner-container one-file cgo reducer before production cache work begins.

**Architecture:** Under the private `CARRICK_DSR_ARTIFACT_SPIKE=1` switch, one unlinked bounded file belongs to the native container process tree and survives Carrick self-reexec. Fresh DSR emission records normalized words, metadata, and typed process relocations; later siblings validate and replay them into private `MAP_JIT` caches. This plan ends at the measured verdict.

**Tech Stack:** Rust 1.96, Darwin file mappings, process-shared atomics, `zerocopy`, SHA-256, the existing DSR emitter/oracle and native exec capsule, Python 3.

## Global Constraints

- Work in `/Volumes/CaseSensitive/carrick/.worktrees/codex-biased-exclusive-fusion`.
- Preserve and checkpoint the current five-file DSR delta before artifact edits overlap it.
- Use `just build` for runnable guests and verify codesigning.
- Never overlap Carrick and Docker phases.
- Use unique `CARRICK_RUN_ID` values and scoped cleanup.
- Measure cgo inside an already-started container.
- Keep the spike disabled by default and absent from the public CLI.
- Keep executable code in private anonymous per-process `MAP_JIT` mappings.
- Treat unknown, stale, malformed, partial, or unrelocated records as misses.
- Stop cache work if any feasibility gate fails.
- Do not run full c94 or plan production hardening before a passing verdict.

## File Structure

- Create `crates/carrick-runtime/src/native_darwin/dsr/artifact_spike.rs`: authority, wire format, typed relocations, bounded lookup, counters.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`: record and replay normalized templates.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`: publish validated replay words.
- Modify `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`: lookup, replay, append, common publication, diagnostics.
- Modify `crates/carrick-runtime/src/native_darwin/mapped_memory.rs`: attach inherited authority to `ProcessTranslator`.
- Modify `crates/carrick-runtime/src/native_exec_capsule.rs`: carry and adopt authority across self-reexec.
- Create `scripts/perf/native_translation_artifact_spike.py` and its unit tests.
- Create `scripts/perf/evidence/native-translation-artifact-spike-v1.json` only from the final signed run.

---

### Task 0: Checkpoint current instruction contracts

**Files:** Verify and commit `crates/carrick-runtime/src/native_darwin/dsr/{block,decode,emit,mod,types}.rs`.

**Interfaces:** Produces one reviewed correctness commit so artifact work cannot mix with the existing SIMD, DC ZVA, biased-exclusive, or dual-x18/x28 changes.

- [ ] **Step 1: Verify the existing delta**

```bash
git status --short
git diff --check -- crates/carrick-runtime/src/native_darwin/dsr
cargo test -p carrick-runtime native_darwin::dsr::emit::tests --lib
cargo test -p carrick-runtime native_darwin::dsr::tests --lib
```

Expected: only the five known DSR files are modified and focused tests pass.

- [ ] **Step 2: Run the proactive executable audit**

```bash
CARRICK_DSR_SCAN_CORPUS=target/conformance/dsr-audit-go-corpus-v1 \
CARRICK_DSR_OBJDUMP=aarch64-linux-gnu-objdump \
cargo test -p carrick-runtime \
  native_darwin::dsr::tests::dsr_static_elf_instruction_contract_audit \
  --lib -- --ignored --exact
```

Expected: PASS with nonzero decoded words and no writeback or reserved-register gaps.

- [ ] **Step 3: Commit exactly those files**

```bash
git add crates/carrick-runtime/src/native_darwin/dsr/{block,decode,emit,mod,types}.rs
git commit -m "fix(runtime): complete native compiler instruction contracts" \
  -m "Preserve exact compiler instruction semantics and the proactive executable audit.

Verified with focused DSR tests and the AArch64 executable corpus.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 1: Prove typed normalization and private replay

**Files:** Create `artifact_spike.rs`; modify `dsr/{mod,emit,cache}.rs`; test inline in `artifact_spike.rs` and `emit.rs`.

**Interfaces:** Produces `ArtifactTemplate`, `ArtifactBindings`, `ArtifactRelocation`, `ProcessValue`, `emit_block_recording_artifact`, and `replay_artifact`.

- [ ] **Step 1: Write red equivalence tests**

```rust
#[test]
fn normalization_removes_every_process_value() {
    let a = emit_artifact_fixture(0x1000_0000, 0x2000_0000, 1);
    let b = emit_artifact_fixture(0x3000_0000, 0x4000_0000, 9);
    assert_eq!(a.template, b.template);
    assert_ne!(a.bindings, b.bindings);
}

#[test]
fn replay_matches_fresh_metadata_and_guest_result() {
    let f = replay_fixture();
    let fresh = f.emit_fresh().expect("fresh");
    let replay = f.replay(&fresh.template).expect("replay");
    assert_eq!(fresh.map, replay.map);
    assert_eq!(fresh.recovery, replay.recovery);
    assert_eq!(fresh.direct_links, replay.direct_links);
    assert_eq!(f.execute(fresh.block), f.execute(replay.block));
}
```

Expected: both fail because artifact recording is absent.

- [ ] **Step 2: Define exhaustive process values**

```rust
pub(super) enum GatewayKind { Syscall, Direct, Indirect, Sensitive, Unsupported, Signal }
pub(super) enum ProcessValue {
    Gateway(GatewayKind), GenerationAddress, GenerationExpected, HostBias,
}
pub(super) struct ArtifactRelocation {
    pub(super) first_word: u32,
    pub(super) register: u8,
    pub(super) value: ProcessValue,
    pub(super) expected_opcode_mask: [u32; 4],
}
```

`ArtifactTemplate` contains normalized words, PC map, a portable exhaustive mirror of every `RecoveryAction`, unresolved direct links, typed relocations, and all source words. Conversion and rebind matches have no wildcard arm. Normalize the host bias inside recovery metadata as well as emitted code.

- [ ] **Step 3: Record materializations at their source**

Change `emit_mov_u64` inputs to `MaterializedValue::Guest(u64)` or `MaterializedValue::Process(ProcessValue, u64)`. Gateway addresses, generation address/value, and host bias are process values. Guest PCs, targets, resumes, and literal guest addresses are guest values. Each process value owns exactly one four-word MOV-wide relocation; unexplained, duplicate, overlapping, or incomplete relocations reject eligibility.

- [ ] **Step 4: Replay into private cache space**

```rust
pub(super) fn publish_words(&mut self, words: &[u32]) -> Result<PublishedCode, DsrError> {
    let len = words.len().checked_mul(4).ok_or_else(||
        DsrError::CachePolicy("artifact replay length overflow".to_string()))?;
    let mut writer = self.begin_write(len)?;
    writer.write_words(words)?;
    writer.publish()
}
```

`replay_artifact` verifies opcode masks, applies and consumes every relocation, rebinds recovery metadata, leaves links unresolved, and constructs `EmittedBlock` through `InstructionMap::new`.

- [ ] **Step 5: Verify and commit**

```bash
cargo test -p carrick-runtime normalization_removes_every_process_value --lib -- --exact
cargo test -p carrick-runtime replay_matches_fresh_metadata_and_guest_result --lib -- --exact
cargo test -p carrick-runtime native_darwin::dsr::emit::tests --lib
git add crates/carrick-runtime/src/native_darwin/dsr/{artifact_spike,mod,emit,cache}.rs
git commit -m "feat(runtime): replay typed native translation artifacts" \
  -m "Normalize process-derived DSR state and replay validated templates into private MAP_JIT space.

Verified with cross-binding normalization and fresh-versus-replay execution.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Preserve one authority across the process tree

**Files:** Modify `artifact_spike.rs`, `native_exec_capsule.rs`, and `native_darwin/mapped_memory.rs`.

**Interfaces:** Produces `NativeReexecArtifactSpikeV1`, `ArtifactAuthority::{create,snapshot,map_store}`, `adopt_for_resume`, and `authority_if_enabled`.

- [ ] **Step 1: Write red lifecycle tests**

```rust
#[test]
fn authority_survives_capsule_exec() {
    let a = ArtifactAuthority::create_for_test().expect("authority");
    let before = a.snapshot().expect("snapshot");
    let after = exec_capsule_capture_artifact(before).expect("capture");
    assert_eq!((after.device, after.inode), (before.device, before.inode));
    assert_eq!(fd_flags(after.host_fd) & libc::FD_CLOEXEC, 0);
}

#[test]
fn authority_rejects_substituted_fd() {
    let a = ArtifactAuthority::create_for_test().expect("authority");
    let mut snapshot = a.snapshot().expect("snapshot");
    snapshot.inode ^= 1;
    assert!(adopt_for_resume(&snapshot).is_err());
}
```

- [ ] **Step 2: Add typed capsule authority**

```rust
pub(crate) struct NativeReexecArtifactSpikeV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
    pub(crate) authority_nonce: [u8; 16],
}
```

Add an optional record to `NativeGuestExecV1`. Snapshot it in `begin_guest_exec`, clear `FD_CLOEXEC` through `HostFdFlagTransaction`, validate fd identity/size/nonce after capsule consumption, and adopt it before guest mapping.

Implement `exec_capsule_capture_artifact` in the test module by calling the existing `exec_capsule_with` closure, reading the artifact fd from the captured payload, and returning its `fstat` identity plus current fd flags. It must not call real `execve`.

- [ ] **Step 3: Scope authority creation to the spike**

Use `OnceLock<ArtifactAuthority>`. Initial native mapping creates a 256 MiB unlinked `tempfile` only under the switch; fork inherits it and self-reexec adopts it. Change the constructor to `ProcessTranslator::new(capacity: usize, artifact_store: Option<Arc<ArtifactStore>>) -> Result<Self, DsrError>` and pass the adopted store from `NativeMappedMemory`.

- [ ] **Step 4: Verify and commit**

```bash
cargo test -p carrick-runtime authority_ --lib
cargo test -p carrick-runtime native_exec_capsule --lib
cargo test -p carrick-runtime native_prepared_image --lib
git add crates/carrick-runtime/src/native_darwin/dsr/artifact_spike.rs \
  crates/carrick-runtime/src/native_exec_capsule.rs \
  crates/carrick-runtime/src/native_darwin/mapped_memory.rs
git commit -m "feat(runtime): inherit the artifact spike per container" \
  -m "Carry one opted-in unlinked artifact authority through fork and host self-reexec.

Verified with capsule identity, substitution, rollback, and prepared-image tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Publish and consume cross-process records

**Files:** Modify `dsr/{artifact_spike,mod,emit}.rs`; test inline in `artifact_spike.rs` and `mod.rs`.

**Interfaces:** Produces `ArtifactStore::{lookup,insert}`, `ArtifactMiss`, and replay before live decode/plan/emit.

- [ ] **Step 1: Write red store tests**

```rust
#[test]
fn second_mapping_reads_committed_artifact() {
    let a = ArtifactAuthority::create_for_test().expect("authority");
    let writer = a.map_store().expect("writer");
    let reader = a.map_store().expect("reader");
    let t = synthetic_template();
    writer.insert(&t).expect("insert");
    assert_eq!(reader.lookup(&t.key).expect("lookup"), Some(t));
}

#[test]
fn partial_or_source_mismatched_record_never_replays() {
    let f = shared_lookup_fixture();
    f.write_uncommitted();
    assert_eq!(f.lookup(), ArtifactMiss::Uncommitted);
    f.commit_then_mutate_source();
    assert_eq!(f.lookup(), ArtifactMiss::SourceMismatch);
}
```

- [ ] **Step 2: Add a bounded O(1) spike index**

Use a 256 MiB file, 65,536 fixed index slots, 16 probes, and 64 KiB maximum records. The shared header owns an aligned atomic append cursor. Slots transition `empty -> writing -> committed` and store a 128-bit key tag, offset, length, and checksum. Readers acquire-load committed; writers publish it with a release store after writing the complete payload. A dead writer exposes no record.

Encode explicit little-endian lengths and fixed `zerocopy` entries. Check every addition/multiplication and require exact payload consumption.

- [ ] **Step 3: Integrate lookup before decode**

Build the lookup prefix from translator ABI, address mode, guest PC, and 32 instruction bytes under the current generation observation. Before replay compare every stored source word against guest memory. Extract existing publication into `publish_emitted`; fresh and replayed blocks use the same final generation check, recovery map, dependencies, sensitive metadata, unresolved links, and concurrent publication. Append only after successful local publication.

- [ ] **Step 4: Verify and commit**

```bash
cargo test -p carrick-runtime artifact_spike::tests --lib
cargo test -p carrick-runtime native_darwin::dsr::tests --lib
cargo test -p carrick-runtime native_darwin::dsr::emit::tests --lib
git add crates/carrick-runtime/src/native_darwin/dsr/{artifact_spike,mod,emit}.rs
git commit -m "feat(runtime): reuse native translations across siblings" \
  -m "Validate source, checksum, relocations, and generation before sibling replay.

Verified with cross-mapping, partial-write, source-mutation, generation-race, and DSR tests.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Add exact accounting and verdict harness

**Files:** Modify `dsr/{artifact_spike,mod}.rs`; create `scripts/perf/native_translation_artifact_spike.py` and `scripts/perf/tests/test_native_translation_artifact_spike.py`.

**Interfaces:** Produces `ARTIFACTSPIKE1` epoch records and JSON `pass|stop` verdicts.

- [ ] **Step 1: Write red gate tests**

```python
def test_all_gates_are_mandatory():
    passing = verdict(
        baseline_ns=[2_500_000_000, 2_550_000_000, 2_600_000_000],
        spike_ns=[1_300_000_000, 1_400_000_000, 1_500_000_000],
        translation_reduction=.82, replay_ratio=.15,
        cross_process_hits=10_000, failures=[])
    assert passing["status"] == "pass"
```

Add independent stop cases for no cross-process hits, reduction below 0.80, speedup below 1.70, replay ratio at least 0.20, SIGILL/nonzero status, timeout, and dirty cleanup.

Use one table so each failed gate is named exactly:

```python
def test_each_failed_gate_stops_the_spike():
    mutations = {
        "cross_process_hits": {"cross_process_hits": 0},
        "translation_reduction": {"translation_reduction": .79},
        "wall_speedup": {"spike_ns": [1_600_000_000] * 3},
        "replay_cost": {"replay_ratio": .20},
        "correctness": {"failures": ["sigill"]},
        "cleanup": {"cleanup": "dirty"},
    }
    for gate, mutation in mutations.items():
        candidate = passing_fixture() | mutation
        result = verdict(**candidate)
        assert result["status"] == "stop"
        assert gate in result["failed_gates"]
```

- [ ] **Step 2: Emit one checked record per exec epoch**

```text
ARTIFACTSPIKE1|pid=N|exec_epoch=N|lookups=N|hits=N|cross_process_hits=N|fresh=N|committed=N|validation_misses=N|generation_misses=N|capacity_misses=N|replay_cpu_ns=N|fresh_translation_cpu_ns=N|fresh_publication_cpu_ns=N
```

Counter overflow disables spike reuse for that process instead of wrapping.

- [ ] **Step 3: Implement exact separated phases**

Use image `localhost:5005/carrick-go-conformance:1.24`, workdir `/usr/local/go/src/cmd/cgo/internal/test`, native16k, private PID namespace, and:

```sh
rm -rf /tmp/cgoout && mkdir -p /tmp/cgoout
s=$(date +%s%N)
/usr/local/go/bin/go tool cgo -objdir /tmp/cgoout -- -I /tmp/cgoout callback.go
rc=$?
e=$(date +%s%N)
echo inner_ns=$((e-s)) rc=$rc
exit $rc
```

Provide `docker`, `carrick-baseline`, `carrick-spike`, `carrick-profiled`, and `summarize`. Carrick phases use one warm-up and three samples, unique run ids, and scoped cleanup. Profiled CPU is directional; unprofiled p50 is authoritative.

- [ ] **Step 4: Verify and commit**

```bash
python3 -m unittest scripts.perf.tests.test_native_translation_artifact_spike -v
python3 scripts/perf/native_translation_artifact_spike.py --help
git add crates/carrick-runtime/src/native_darwin/dsr/{artifact_spike,mod}.rs \
  scripts/perf/native_translation_artifact_spike.py \
  scripts/perf/tests/test_native_translation_artifact_spike.py
git commit -m "diagnostics(runtime): gate the artifact feasibility spike" \
  -m "Measure cross-process hits, eliminated CPU, replay cost, exact cgo wall, correctness, and cleanup.

Return stop unless every approved proof gate passes.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Run the signed hard verdict

**Files:** Create `scripts/perf/evidence/native-translation-artifact-spike-v1.json` from the real run; do not edit runtime code during comparison.

**Interfaces:** Produces the terminal `pass` or `stop` decision.

- [ ] **Step 1: Run focused gates and sign**

```bash
just fmt-check
cargo test -p carrick-runtime artifact_spike --lib
cargo test -p carrick-runtime native_exec_capsule --lib
cargo test -p carrick-runtime native_darwin::dsr::emit::tests --lib
CARRICK_DSR_SCAN_CORPUS=target/conformance/dsr-audit-go-corpus-v1 \
CARRICK_DSR_OBJDUMP=aarch64-linux-gnu-objdump \
cargo test -p carrick-runtime \
  native_darwin::dsr::tests::dsr_static_elf_instruction_contract_audit \
  --lib -- --ignored --exact
just build
codesign --verify --verbose=2 target/release/carrick
shasum -a 256 target/release/carrick
```

Expected: all pass and signed SHA is recorded.

- [ ] **Step 2: Run strictly separated phases**

```bash
python3 scripts/perf/native_translation_artifact_spike.py docker --output target/conformance/native-artifact-spike-docker.json
python3 scripts/perf/native_translation_artifact_spike.py carrick-baseline --output target/conformance/native-artifact-spike-baseline.json
python3 scripts/perf/native_translation_artifact_spike.py carrick-spike --output target/conformance/native-artifact-spike-enabled.json
python3 scripts/perf/native_translation_artifact_spike.py carrick-profiled --output target/conformance/native-artifact-spike-profiled.json
```

Expected: zero status, no SIGILL/timeout, and clean scoped cleanup.

- [ ] **Step 3: Produce the verdict**

```bash
python3 scripts/perf/native_translation_artifact_spike.py summarize \
  --docker target/conformance/native-artifact-spike-docker.json \
  --baseline target/conformance/native-artifact-spike-baseline.json \
  --spike target/conformance/native-artifact-spike-enabled.json \
  --profiled target/conformance/native-artifact-spike-profiled.json \
  --output scripts/perf/evidence/native-translation-artifact-spike-v1.json
```

Mandatory pass conditions:

```text
cross_process_hits > 0
translation_publication_reduction >= 0.80
wall_speedup >= 1.70
replay_cpu_ratio < 0.20
failures == []
cleanup == clean
status == pass
```

- [ ] **Step 4: Obey the result**

If `stop`, commit the evidence with `diagnostics(runtime): falsify the native artifact speedup`, name failed gates, and end cache work. Do not expand eligibility, capacity, timeouts, or hardening to rescue it.

If `pass`, commit the evidence with `diagnostics(runtime): prove the native artifact speedup` and request review. Only then create a separate production plan.
