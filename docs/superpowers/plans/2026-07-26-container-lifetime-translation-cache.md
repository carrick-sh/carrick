# Container-lifetime AArch64 Translation Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reuse immutable Darwin/AArch64 DSR translations across the guest
processes of one `carrick run`, reducing the measured 21,786 ms `go-build`
median without changing guest behavior.

**Architecture:** Keep first execution demand-JITed, record portable block
templates, batch them by executable identity into signed Mach-O dylibs, and
load those immutable units in later siblings. A private directory authority
survives fork and native host self-reexec; full image identity, source
fingerprints, address mode, host bias, and translator ABI prevent wrong-code
aliasing. Existing JIT execution remains the typed fallback.

**Tech Stack:** Rust, AArch64 `dynasmrt`, the existing DSR artifact recorder,
hand-emitted Mach-O, ad-hoc `codesign`, `dlopen`, serde JSON manifests, SHA-256,
Darwin directory file descriptors, Python `unittest`, Carrick native
conformance.

## Global Constraints

- Darwin/AArch64 native DSR only; no VMM/HVF or x86 behavior changes.
- The cache lifetime is exactly one top-level `carrick run`; no persistent
  `CARRICK_HOME` store or cross-run reuse.
- Published instructions are immutable and receive no per-process rewrite.
- Guest VA alone is never an image identity.
- Cache failure falls back to the existing JIT; validation never fails open.
- Carrick and Docker oracle phases never run concurrently.
- Performance claims use five idle, untraced, back-to-back samples and report
  the median; the starting median is 21,786 ms.
- Every behavior change follows red, green, refactor. Record the red command
  and failure in the commit body or `scripts/perf/evidence/`.
- Each behavior-changing commit has a Conventional Commit subject, explanatory
  body, verification receipt, and `Co-Authored-By: Codex <codex@openai.com>`.

---

### Task 1: Promote the reference workload into a repeatable gate

**Files:**
- Create: `scripts/perf/native_go_build.py`
- Create: `scripts/perf/test_native_go_build.py`
- Create: `scripts/perf/fixtures/native-go-build-baseline-v1.json`
- Modify: `scripts/perf/README.md`

**Interfaces:**
- Produces:
  `build_carrick_command(repo: Path, run_id: str) -> list[str]`,
  `median_ms(samples: Sequence[int]) -> int`, and a CLI that writes one JSON
  result containing provenance and all samples.
- Consumers: Task 8 uses the CLI for the post-cache comparison.

- [ ] **Step 1: Write parsing and command-construction tests**

```python
class NativeGoBuildTest(unittest.TestCase):
    def test_command_is_native_and_cold_cache(self):
        cmd = native_go_build.build_carrick_command(
            pathlib.Path("/repo"), "perf-test-1"
        )
        rendered = "\0".join(cmd)
        self.assertIn("--exec-backend\0native", rendered)
        self.assertIn("GOCACHE=/tmp/gc-$CARRICK_RUN_ID", rendered)
        self.assertNotIn("docker", rendered)

    def test_five_sample_median_is_middle_value(self):
        self.assertEqual(native_go_build.median_ms([21, 18, 30, 19, 20]), 20)
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```sh
python3 -m unittest -v scripts/perf/test_native_go_build.py
```

Expected: import failure because `scripts/perf/native_go_build.py` does not
exist.

- [ ] **Step 3: Implement the harness**

The CLI must:

```python
def build_carrick_command(repo: pathlib.Path, run_id: str) -> list[str]:
    script = (
        'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; '
        'printf "package main\\nfunc main(){println(\\"ok\\")}\\n" > h.go; '
        'GOCACHE="/tmp/gc-$CARRICK_RUN_ID" '
        '/usr/local/go/bin/go build -o h ./h.go; ./h; echo BUILD_OK'
    )
    return [
        str(repo / "target/release/carrick"),
        "run", "--exec-backend", "native", "-w", "/tmp",
        "localhost:5005/carrick-go-conformance:1.24",
        "/bin/sh", "-c", script,
    ]

def median_ms(samples: Sequence[int]) -> int:
    return int(statistics.median(samples))
```

Before sampling, reject active `while :` spin loops, a one-minute load average
above the host logical CPU count, or another `cargo`/`rustc` process. Run each
sample with a unique `CARRICK_RUN_ID`, a monotonic clock, a 180-second deadline,
and scoped cleanup through `scripts/sudo/kill.sh`. Record Carrick binary SHA-256,
git commit, dirty status, host facts, timestamps, raw durations, and median.

- [ ] **Step 4: Verify GREEN and run the non-executing CLI help**

Run:

```sh
python3 -m unittest -v scripts/perf/test_native_go_build.py
python3 scripts/perf/native_go_build.py --help
```

Expected: tests pass; help names `--samples`, `--output`, and `--allow-busy`.

- [ ] **Step 5: Record the existing baseline**

Store the handoff values, not a fabricated rerun, in
`native-go-build-baseline-v1.json`:

```json
{
  "schema": "carrick.native-go-build-baseline.v1",
  "git_commit": "26de3c07",
  "samples": 5,
  "median_ms": 21786,
  "docker_wall_ms": 942,
  "source": "handoff.md 2026-07-26"
}
```

- [ ] **Step 6: Commit**

```sh
git add scripts/perf/native_go_build.py \
  scripts/perf/test_native_go_build.py \
  scripts/perf/fixtures/native-go-build-baseline-v1.json \
  scripts/perf/README.md
git commit
```

Subject: `diagnostics(native): make go-build performance repeatable`

---

### Task 2: Define collision-safe portable unit identity

**Files:**
- Create: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs`

**Interfaces:**
- Produces:
  `ExecutableIdentity`, `AddressModeIdentity`, `TranslationUnitKey`,
  `SourceFingerprint`, `TRANSLATOR_ABI_V1`, and
  `TranslationUnitKey::for_segment(...)`.
- Consumers: Tasks 5-7 serialize, publish, validate, and index by these types.

- [ ] **Step 1: Write the red identity tests**

```rust
#[test]
fn same_guest_va_with_different_images_never_aliases() {
    let first = TranslationUnitKey::for_segment(
        ExecutableIdentity::Digest([0x11; 32]),
        0x1000, 0x4000, GuestVa(0x400000), 0x4000,
        SourceFingerprint([0xaa; 32]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::Biased { host_bias: 0x8000_0000 },
    );
    let second = TranslationUnitKey::for_segment(
        ExecutableIdentity::Digest([0x22; 32]),
        0x1000, 0x4000, GuestVa(0x400000), 0x4000,
        SourceFingerprint([0xbb; 32]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::Biased { host_bias: 0x8000_0000 },
    );
    assert_ne!(first, second);
    assert_ne!(first.file_stem(), second.file_stem());
}

#[test]
fn same_image_with_different_host_biases_never_aliases() {
    // Construct otherwise-identical keys and assert inequality.
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-dsr-aarch64 shared_cache::tests -- --nocapture
```

Expected: compile failure because `shared_cache` and its typed keys do not
exist.

- [ ] **Step 3: Implement typed identity**

Use these exact public shapes:

```rust
pub const TRANSLATOR_ABI_V1: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SourceFingerprint(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum NativePageProfileIdentity {
    Native16k,
    Linux4kOn16k,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ExecutableIdentity {
    HostFile {
        device: u64,
        inode: u64,
        size: u64,
        mtime_seconds: i64,
        mtime_nanoseconds: i64,
    },
    Digest([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum AddressModeIdentity {
    Direct,
    Biased { host_bias: u64 },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TranslationUnitKey {
    pub executable: ExecutableIdentity,
    pub segment_file_offset: u64,
    pub segment_file_len: u64,
    pub guest_va_start: GuestVa,
    pub guest_va_len: u64,
    pub source_fingerprint: SourceFingerprint,
    pub page_profile: NativePageProfileIdentity,
    pub address_mode: AddressModeIdentity,
    pub translator_abi: u32,
}
```

`file_stem()` is lowercase SHA-256 of canonical JSON bytes, so file names never
embed untrusted guest paths. Add
`SourceFingerprint::from_words(words: &[u32])`, using the same little-endian
word encoding as `ArtifactKey::new`; do not make the rejected artifact store
the authority. Implement `Serialize` and `Deserialize` for
`TranslationUnitKey` through a private wire type whose guest VA is `u64`,
reconstructing `GuestVa` at that boundary. Do not add a general raw
deserializer to the foundational `GuestVa` type.

- [ ] **Step 4: Verify GREEN and serialization stability**

Run:

```sh
cargo test -p carrick-dsr-aarch64 shared_cache::tests -- --nocapture
cargo test -p carrick-dsr-aarch64 artifact_spike::tests -- --nocapture
```

Expected: identity tests and existing artifact tests pass.

- [ ] **Step 5: Prove the test is adversarial**

Temporarily remove `executable` from `TranslationUnitKey` equality/hash input,
rerun `same_guest_va_with_different_images_never_aliases`, and capture the
failure. Restore the field and rerun green before committing.

- [ ] **Step 6: Commit**

Subject: `feat(native): key shared translations by image identity`

---

### Task 3: Carry a private cache authority through host self-reexec

**Files:**
- Create: `crates/carrick-native-darwin/src/aot_cache.rs`
- Modify: `crates/carrick-native-darwin/src/lib.rs`
- Modify: `crates/carrick-native-darwin/Cargo.toml`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Produces:
  `ContainerCacheAuthority::create()`,
  `ContainerCacheAuthority::snapshot_for_reexec()`,
  `ContainerCacheAuthority::adopt(AotCacheReexecConfig)`,
  `active_container_cache()`, and capsule
  `NativeReexecAotCacheV1`.
- Consumers: Task 5 uses the authority directory; Task 7 installs it before
  mapping a resumed image.

- [ ] **Step 1: Write authority lifecycle tests**

```rust
#[test]
fn cache_authority_round_trips_through_reexec_config() {
    let owner = ContainerCacheAuthority::create().expect("create authority");
    let snapshot = owner.snapshot_for_reexec().expect("snapshot");
    let adopted = ContainerCacheAuthority::adopt(snapshot).expect("adopt");
    assert_eq!(owner.identity(), adopted.identity());
    assert_eq!(owner.path(), adopted.path());
}

#[test]
fn cache_authority_rejects_changed_directory_identity() {
    let owner = ContainerCacheAuthority::create().expect("create authority");
    let mut snapshot = owner.snapshot_for_reexec().expect("snapshot");
    snapshot.host_inode ^= 1;
    assert!(ContainerCacheAuthority::adopt(snapshot).is_err());
}
```

Add a capsule test asserting the cache directory descriptor has `FD_CLOEXEC`
cleared only inside the existing `HostFdFlagTransaction` and restored if
`invoke_exec` fails.

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo test -p carrick-runtime native_exec_capsule::tests -- --nocapture
```

Expected: missing module/type failures.

- [ ] **Step 3: Implement the authority**

Use:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AotCacheReexecConfig {
    pub host_fd: RawFd,
    pub original_host_fd_flags: i32,
    pub host_device: u64,
    pub host_inode: u64,
    pub owner_pid: u32,
    pub path: PathBuf,
    pub authority_nonce: [u8; 16],
    pub translator_abi: u32,
}
```

Create a mode-`0700` directory under `std::env::temp_dir()`, open it with
`O_RDONLY | O_DIRECTORY | O_CLOEXEC`, and validate both `fstat(fd)` and
`stat(path)` during adoption. Cleanup runs only when
`getpid() == owner_pid`; forked children never remove the directory.

Add `#[serde(default)] aot_cache: Option<NativeReexecAotCacheV1>` to
`NativeGuestExecV1`, include it in `validate`, descriptor preparation, fixtures,
and resume adoption. This is an optional V1 field, so older capsules retain
their decode meaning.

- [ ] **Step 4: Verify GREEN and the real PID-preserving transport**

Run:

```sh
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo test -p carrick-runtime native_exec_capsule::tests -- --nocapture
just build
target/release/carrick debug native-self-reexec-pid
```

Expected: unit tests pass and the real probe reports
`native_self_reexec_pid_preserved=true`.

- [ ] **Step 5: Commit**

Subject: `feat(native): preserve translation-cache authority across exec`

---

### Task 4: Make generation guards portable without weakening invalidation

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway_aarch64.S`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Produces:
  `GenerationBinding`, appended `DsrContext::generation_bindings`,
  `GenerationGuard::Absolute` for JIT blocks, and
  `GenerationGuard::BindingIndex(u32)` for immutable unit blocks.
- Consumers: Task 5 creates one binding table per loaded unit; Task 6 enters
  immutable blocks with that table installed.

- [ ] **Step 1: Write the immutable-code and stale-generation tests**

```rust
#[test]
fn binding_generation_guard_contains_no_process_pointer() {
    let process_pointer = 0x1234_5678_9abc_def0_u64;
    let words = emit_guard_fixture(
        GenerationGuard::BindingIndex(3),
        process_pointer,
    );
    let bytes = words.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<_>>();
    assert!(!bytes.windows(8).any(|window| window == process_pointer.to_le_bytes()));
}

#[test]
fn binding_generation_guard_exits_stale_after_atomic_changes() {
    // Execute a binding-index block once at INITIAL, increment the source
    // atomic, execute again, and require NativeDsrExit::StaleGeneration.
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-runtime \
  binding_generation_guard -- --nocapture
```

Expected: missing `BindingIndex` and context-field failures.

- [ ] **Step 3: Append the context ABI**

Add:

```rust
#[repr(C)]
pub struct GenerationBinding {
    pub current: *const AtomicU64,
    pub expected: u64,
}

#[repr(C)]
pub struct DsrContext {
    // existing fields unchanged
    pub generation_bindings: *const GenerationBinding,
}
```

Pin the new Rust offset and total size with const assertions and mirror the
offset in `gateway_aarch64.S` even if the assembly gateway does not dereference
it. Existing offsets must not move.

- [ ] **Step 4: Emit the indexed prelude**

Refactor the guard emitter so `Absolute` preserves today's bytes and
`BindingIndex(index)` emits:

```text
ldr x16, [x28, #CTX_GENERATION_BINDINGS]
materialize index in x17
add x16, x16, x17, lsl #4
ldp x16, x17, [x16]
ldar x16, [x16]
cmp x16, x17
b.ne stale_generation_gateway
```

The normal recovery entries must restore guest `x16`, guest `x17`, and NZCV at
every interruptible word exactly as the absolute guard does.

- [ ] **Step 5: Verify GREEN, disassembly, and red control**

Run:

```sh
cargo test -p carrick-runtime binding_generation_guard -- --nocapture
cargo test -p carrick-runtime generation_guard -- --nocapture
cargo test -p carrick-dsr-aarch64 emit::tests -- --nocapture
```

Use `bad64::decode` in the test to assert the indexed sequence. Revert the
indexed load to use a captured process pointer, show
`binding_generation_guard_contains_no_process_pointer` red, then restore green.

- [ ] **Step 6: Commit**

Subject: `feat(native): indirect shared-block generation guards`

---

### Task 5: Batch, sign, atomically publish, and load immutable units

**Files:**
- Modify: `crates/carrick-native-darwin/Cargo.toml`
- Modify: `crates/carrick-native-darwin/src/aot.rs`
- Modify: `crates/carrick-native-darwin/src/aot_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/artifact_spike.rs`

**Interfaces:**
- Produces:
  `PortableBlockRecord`, `TranslationUnitManifest`,
  `ContainerCacheAuthority::publish_unit`, and
  `ContainerCacheAuthority::load_unit`.
- Consumers: Task 6 records candidates and indexes `LoadedTranslationUnit`.

- [ ] **Step 1: Write validation and concurrency tests**

```rust
#[test]
fn source_fingerprint_mismatch_is_a_typed_miss() {
    let published = fixture_unit(&[0x00, 0x00, 0x80, 0xd2]);
    let err = validate_unit(&published.manifest, &[0x20, 0x00, 0x80, 0xd2])
        .expect_err("different source must miss");
    assert_eq!(err.reason(), UnitMissReason::SourceFingerprint);
}

#[test]
fn concurrent_publishers_converge_on_one_unit() {
    // Start two threads with the same authority and key. Both publish the
    // same fixture. Require one Winner, one Existing, identical final bytes,
    // and no temporary files.
}

#[test]
fn partial_publish_pair_is_never_loadable() {
    // Leave only the final manifest, then only the final dylib. Both are typed
    // misses and neither calls dlopen.
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo test -p carrick-dsr-aarch64 shared_cache::tests -- --nocapture
```

Expected: missing manifest/publisher types.

- [ ] **Step 3: Define the manifest**

```rust
pub const TRANSLATION_UNIT_SCHEMA_V1: u32 = 1;
pub const MAX_TRANSLATION_UNIT_CODE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranslationUnitManifest {
    pub schema: u32,
    pub key: TranslationUnitKey,
    pub dylib_sha256: [u8; 32],
    pub base_export: String,
    pub code_len: u64,
    pub blocks: Vec<PortableBlockRecord>,
}

#[derive(Clone, Debug)]
pub struct PortableBlockRecord {
    pub guest_start: GuestVa,
    pub generation_binding: u32,
    pub entry_offset: u32,
    pub code_len: u32,
    pub template: ArtifactTemplate,
}

#[derive(Clone, Debug)]
pub struct PendingTranslationUnit {
    pub manifest: TranslationUnitManifest,
    pub code: Vec<u8>,
}

pub enum PublishOutcome {
    Winner,
    Existing,
}

pub enum UnitMissReason {
    MissingPair,
    Schema,
    TranslatorAbi,
    ImageIdentity,
    SourceFingerprint,
    AddressMode,
    PageProfile,
    DylibDigest,
    ManifestRange,
    Dlopen,
}

pub struct LoadedTranslationUnit {
    pub manifest: TranslationUnitManifest,
    pub base: NonNull<u8>,
    pub generation_bindings: Box<[GenerationBinding]>,
    handle: NonNull<c_void>,
}

pub struct UnitStoreError {
    pub operation: &'static str,
    pub reason: UnitMissReason,
    pub source: Option<Box<dyn Error + Send + Sync>>,
}
```

Make `ArtifactTemplate` serializable through its existing
`WireArtifactTemplate` conversion and give it typed accessors for unit packing;
implement `Serialize`/`Deserialize` for `PortableBlockRecord` through a private
wire record whose guest address is `u64`; do not duplicate recovery variants in
`shared_cache.rs`. Reuse artifact normalization only to capture code and
lossless metadata.
Replace `GenerationAddress` and `GenerationExpected` relocations with one stable
binding index during unit packing. Bind host bias once while packing because it
is part of the key. Reject every other `ProcessValue`; do not replay it in the
loader.

- [ ] **Step 4: Implement atomic publication**

Emit one dylib with export `carrick_aot_unit_base`, write canonical manifest
JSON, invoke `/usr/bin/codesign -s -`, validate with `codesign --verify`, and
publish uniquely named temporary files with same-directory `rename`. Hold an
exclusive lock file named from `TranslationUnitKey::file_stem()` only across
winner selection and final rename, not across translation.

`load_unit` validates both files and the source bytes before `dlopen(RTLD_NOW |
RTLD_LOCAL)`, calls `dlsym` once for the base, and keeps the handle alive in
`LoadedTranslationUnit`. Its `Drop` calls `dlclose` exactly once. Unit packing
rejects code above `MAX_TRANSLATION_UNIT_CODE_BYTES`; the 64 MiB cap keeps every
intra-unit AArch64 `B` displacement within its signed range.

- [ ] **Step 5: Verify GREEN and file-backed executable mapping**

Run:

```sh
cargo test -p carrick-native-darwin aot_cache::tests -- --nocapture
cargo test -p carrick-dsr-aarch64 shared_cache::tests -- --nocapture
cargo run -p carrick-native-darwin --example aot_bench --release
```

Extend the focused integration test to pause after `dlopen`; inspect it with
`vmmap -w PID` and save the matching `r-x`/file-backed line under
`scripts/perf/evidence/native-aot-unit-vmmap-v1.txt`.

- [ ] **Step 6: Commit**

Subject: `feat(native): publish immutable translation units`

---

### Task 6: Resolve shared blocks before translating and publish on retirement

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`
- Modify: `crates/carrick-dsr-aarch64/src/mapped_memory.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes: authority, keys, portable guards, publisher, loader.
- Produces:
  `ProcessTranslator::configure_shared_image`,
  `ProcessTranslator::publish_shared_candidates`,
  shared-unit lookup before JIT translation, and immutable-range recovery.

- [ ] **Step 1: Write lookup-order and retirement tests**

```rust
#[test]
fn published_shared_block_prevents_second_process_translation() {
    let store = FixtureUnitStore::new();
    let first = process_for_image(&store, [0x11; 32]);
    run_fixture(&first);
    first.publish_shared_candidates().expect("publish");

    let second = process_for_image(&store, [0x11; 32]);
    run_fixture(&second);
    assert_eq!(second.stats().shared_unit_hits, 1);
    assert_eq!(second.stats().translations, 0);
}

#[test]
fn changed_generation_evicts_shared_entry_and_jits() {
    // Load a shared block, mutate its source generation, require one stale
    // exit and then one ordinary JIT translation.
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-dsr-aarch64 shared_unit -- --nocapture
cargo test -p carrick-runtime shared_unit -- --nocapture
```

Expected: missing configuration and stats APIs.

- [ ] **Step 3: Add explicit translator configuration**

Preserve `ProcessTranslator::new(capacity)` for tests and non-Darwin consumers.
Add:

```rust
pub fn configure_shared_image(
    &self,
    image: SharedImageConfig,
    store: Arc<dyn TranslationUnitStore>,
) -> Result<(), DsrError>;

pub trait TranslationUnitStore: Send + Sync {
    fn load(&self, key: &TranslationUnitKey, source: &[u8])
        -> Result<Option<LoadedTranslationUnit>, UnitStoreError>;
    fn publish(&self, unit: PendingTranslationUnit)
        -> Result<PublishOutcome, UnitStoreError>;
}

pub struct SharedImageConfig {
    pub executable: ExecutableIdentity,
    pub page_profile: NativePageProfileIdentity,
    pub address_mode: AddressModeIdentity,
    pub segments: Vec<SharedExecutableSegment>,
}

pub struct SharedExecutableSegment {
    pub file_offset: u64,
    pub file_len: u64,
    pub guest_start: GuestVa,
    pub guest_len: u64,
    pub source_fingerprint: SourceFingerprint,
}
```

`NativeMappedMemory` exposes `configure_shared_translation` so the runtime can
install executable digest, page profile, address mode, segment provenance, and
the Darwin store immediately after mapping and before the first thread starts.

- [ ] **Step 4: Integrate lookup, entry, recovery, and retirement**

At `ProcessState::translate`, try the current JIT cache, then a loaded shared
unit, then disk load, before planning a new block. A shared `PreparedEntry`
retains an `Arc<LoadedTranslationUnit>` and its generation-binding table through
gateway entry. Recovery searches the unit's immutable range and manifest
metadata without copying it.

Record only blocks whose source pages remain initially generated and executable
but not writable. Call `publish_shared_candidates` from the existing process
retirement/final-profile seams before `_exit`; make it idempotent because
multiple threads may race to retire.

- [ ] **Step 5: Add performance protocol counters**

Extend the existing resolver/profile schema with unit lookups, hits, loads,
blocks mapped, translations avoided, publish outcomes, load/sign/emit time, and
typed fallback counts. Update `scripts/perf/native_compiler_budget.py` and
`scripts/perf/test_native_compiler_budget.py` so unknown/missing fields still
fail closed.

- [ ] **Step 6: Verify GREEN and red controls**

Run:

```sh
cargo test -p carrick-dsr-aarch64 shared_unit -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime shared_unit -- --nocapture
python3 -m unittest -v scripts/perf/test_native_compiler_budget.py
```

Temporarily reverse lookup order so JIT translation precedes shared lookup;
verify `published_shared_block_prevents_second_process_translation` goes red,
then restore.

- [ ] **Step 7: Commit**

Subject: `feat(native): reuse translations across guest processes`

---

### Task 7: Prove image isolation with concurrent same-VA siblings

**Files:**
- Create: `conformance-probes/src/bin/nativecacheidentity.rs`
- Modify: `conformance-probes/Cargo.toml`
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `scripts/conformance/probes.toml`

**Interfaces:**
- Consumes the production container cache end to end.
- Produces the permanent `nativecacheidentity` regression.

- [ ] **Step 1: Add the adversarial probe and test declaration**

The probe must create two executable images with the same ELF load addresses
but different source instructions and expected exit values, fork two siblings,
exec each image repeatedly, wait for both, and print:

```text
same_va=true
first_value=17
second_value=42
identity_isolated=true
```

The conformance row compares that output with Docker.

- [ ] **Step 2: Prove RED against a VA-only key**

Build the probe, temporarily map both images to a test-only VA-only
`TranslationUnitKey`, build and sign Carrick, and run:

```sh
scripts/build-probes.sh
just build
CARRICK_RUN_ID=nativecacheidentity-red \
  scripts/run-probe.sh nativecacheidentity
```

Expected: wrong value, identity collision diagnostic, or DIFF. Save the output
under `scripts/perf/evidence/native-cache-identity-red-v1.txt`. Restore the
production key without using `git checkout` on a file containing unrelated
edits.

- [ ] **Step 3: Verify GREEN**

Run the same signed probe with a new run id.

Expected: MATCH and `identity_isolated=true`. Save
`native-cache-identity-green-v1.txt`.

- [ ] **Step 4: Run focused native workload guards**

Run Carrick phase first, Docker phase second:

```sh
just conformance-native smoke --workers 1 \
  --suite go-sync \
  --suite cpython-threading \
  --suite node-app-smoke
```

Do not run Docker concurrently with Carrick.

- [ ] **Step 5: Commit**

Subject: `test(native): isolate shared translations by executable`

---

### Task 8: Measure, gate, and update the controller

**Files:**
- Create: `scripts/perf/evidence/native-go-build-post-cache-v1.json`
- Create: `scripts/perf/evidence/native-go-build-post-cache-profile-v1.json`
- Modify: `handoff.md`

**Interfaces:**
- Consumes all prior tasks.
- Produces the authoritative wall-time result, CPU attribution, verification
  receipts, and next ranked direction.

- [ ] **Step 1: Build and verify signing**

Run:

```sh
just build
codesign --verify --verbose=2 target/release/carrick
```

Expected: signed binary verifies.

- [ ] **Step 2: Establish an idle host**

Run:

```sh
ps -eo pid,args | rg 'while :|cargo|rustc|target/release/carrick'
uptime
```

Stop only scoped leftovers owned by this work. Do not kill unrelated agents or
use `pkill -f carrick`.

- [ ] **Step 3: Run five untraced samples**

Run:

```sh
python3 scripts/perf/native_go_build.py \
  --samples 5 \
  --output scripts/perf/evidence/native-go-build-post-cache-v1.json
```

Expected: five successful `BUILD_OK` samples and a median below 21,786 ms.
Report the actual number; do not turn that expectation into a claim if it is
not met.

- [ ] **Step 4: Attribute the result**

Run one separate profiled sample using the existing native CPU attribution
workflow and write
`native-go-build-post-cache-profile-v1.json`. Require cache hits and avoided
translations to reconcile with the reduction in `phase_translate_ns`. If wall
time regresses or the counters do not explain the change, resize publication
units or change publication timing and repeat before proceeding.

- [ ] **Step 5: Run runtime and conformance gates**

Run:

```sh
just conformance-native smoke --workers 4
just ci
```

Start Docker and `vt-ferry-registry` first; keep oracle and Carrick phases
separate.

- [ ] **Step 6: Rewrite `handoff.md` from measured state**

Record:

- commits and exact dirty/branch state;
- all five wall samples and median;
- Docker reference without rerunning concurrently;
- translation CPU/count before and after;
- unit hits, misses, publication/load cost, and fallback reasons;
- runtime/conformance/CI commands and outcomes;
- unexplained outliers;
- the new measured ranking between indirect chaining and setup amortization.

- [ ] **Step 7: Commit**

Subject: `docs(native): record container-cache performance`

The commit body must state the measured improvement or regression candidly and
name every gate actually run.
