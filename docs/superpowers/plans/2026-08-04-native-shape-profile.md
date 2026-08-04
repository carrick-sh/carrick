# Authenticated NativeShape Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the approved Darwin/AArch64 `native-shape` attribution path so two independent cold-Go-build captures can name, or fail to name, one source-distinct removable emitted-code mechanism that is at least 10% of all sampled CPU in both captures.

**Architecture:** Add a first-class `TraceProfileKind::NativeShape` that renders one authenticated `NSHAPE2` DTrace program, exports retirement snapshots into a fresh owned directory, and publishes a dedicated capture receipt. Extract snapshot loading and PC resolution into one strict Rust authority shared by capture and census. Replace the old `SHAPE1`/external-ratio/Python workflow with deterministic Rust v2 census and pair-comparison commands. Keep capture integrity separate from workload success and keep all traced timing non-authoritative.

**Tech Stack:** Rust 2024, Clap derive and `ArgMatches::value_source`, serde/serde_json, SHA-256 via `sha2`, `tempfile` atomic publication, Carrick's libdtrace consumer and native launch qualification, DTrace 997 Hz sampling, existing `carrick.code-snapshot.v4` exports, `just` gates.

## Global Constraints

- The approved design at `docs/superpowers/specs/2026-08-04-native-shape-profile-design.md` is normative. Do not weaken an acceptance gate to make a live capture pass.
- This plan implements attribution tooling and takes evidence. It does not change emitted code, runtime defaults, Tier D policy, the 10.1776x scoreboard, or the deferred eager-translation decision.
- Replace `SHAPE1`, `carrick.jit-shape-census.v1`, and `--jit-share-of-total`; do not retain compatibility parsing or aliases.
- Never `copyin` live JIT instruction bytes. Snapshot export remains opt-in and export-only. A crashed workload yields a rejected receipt; no core-file recovery is added.
- Every evidence count comes from one profile-997 population. Traced wall time is never retention authority.
- Parse the target through Clap and parse its image through `ImageReference`; do not discover either by scanning arbitrary guest command strings.
- All accepted arithmetic uses checked integer operations. JSON field order comes from fixed Rust struct declaration order; no maps, options, or floats enter the authority digest.
- All new evidence files are atomically published. A failed validation must not overwrite an accepted artifact.
- Use `apply_patch` for source changes. Preserve unrelated dirt. Each task ends in one narrow commit after its stated gates pass.
- Do not push, merge, or move `main` without new explicit approval.

## File and Ownership Map

| Responsibility | Files |
|---|---|
| Snapshot pair validation, deterministic manifest, exact own/ancestor PC resolution | create `crates/carrick-cli/src/jit_shape_snapshot.rs`; shrink `crates/carrick-cli/src/debug_jit_shape.rs`; register in `crates/carrick-cli/src/main.rs` |
| Bundled D source and runtime exposure | replace `scripts/dtrace/native-shape-census.d`; modify `crates/carrick-runtime/src/dtrace_consumer.rs` |
| NativeShape authority, raw parser, receipt | create `crates/carrick-cli/src/native_shape_profile.rs`; minimally share identity/drop types from `crates/carrick-cli/src/trace_profile.rs` |
| Native launch rendering and qualification binding | modify `crates/carrick-cli/src/native_profile_qualification.rs` and `crates/carrick-cli/src/trace_profile.rs` |
| CLI vocabulary, conditional validation, sudo reconstruction, capture dispatch | modify `crates/carrick-cli/src/args.rs`, `crates/carrick-cli/src/trace_cli.rs`, `crates/carrick-cli/src/commands.rs`, `crates/carrick-cli/src/debug.rs` |
| Rust census/classifier and paired comparator | replace most of `crates/carrick-cli/src/debug_jit_shape.rs`; delete `scripts/perf/shape_classify.py` |
| Campaign evidence and controller state | create `scripts/perf/evidence/native-go-build-shape-comparison-v1.json`; update `docs/perf-results/native-wall-time-campaign.md`, `handoff.md`, `.superpowers/sdd/2026-08-04-native-optimistic-decode/progress.md` |

## Fixed Cross-Task Interfaces

These names and ownership boundaries are fixed so independent task commits compose without parallel implementations.

```rust
// crates/carrick-cli/src/jit_shape_snapshot.rs
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotManifest {
    pub(crate) sha256: String,
    pub(crate) pairs: u64,
    pub(crate) pids: u64,
    pub(crate) blocks: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionOrigin {
    Own,
    Ancestor { pid: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedInstruction {
    pub(crate) word: u32,
    pub(crate) origin: ResolutionOrigin,
}

pub(crate) struct SnapshotSet {
    manifest: SnapshotManifest,
    by_pid: std::collections::BTreeMap<u32, Vec<Snapshot>>,
}

impl SnapshotSet {
    pub(crate) fn load(directory: &std::path::Path) -> anyhow::Result<Self>;
    pub(crate) fn manifest(&self) -> &SnapshotManifest;
    pub(crate) fn resolve(
        &self,
        pid: u32,
        pc: u64,
        parents: &std::collections::BTreeMap<u32, u32>,
    ) -> anyhow::Result<ResolvedInstruction>;
}
```

```rust
// crates/carrick-cli/src/native_shape_profile.rs
pub(crate) const RAW_SCHEMA: &str = "carrick.native-shape.raw.v2";
pub(crate) const CAPTURE_SCHEMA: &str = "carrick.native-shape-capture.v1";
pub(crate) const SAMPLING_HZ: u64 = 997;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeAuthority {
    pub(crate) schema: String,
    pub(crate) profile: String,
    pub(crate) raw_schema: String,
    pub(crate) git_head: String,
    pub(crate) git_dirty: bool,
    pub(crate) executable_sha256: String,
    pub(crate) host: String,
    pub(crate) host_arch: String,
    pub(crate) os_build: String,
    pub(crate) image: String,
    pub(crate) target_argv: Vec<String>,
    pub(crate) target_argv_sha256: String,
    pub(crate) run_id: String,
    pub(crate) program_template_sha256: String,
    pub(crate) birth_qualification_sha256: String,
    pub(crate) terminal_qualification_sha256: String,
    pub(crate) sampling_hz: u64,
}

impl NativeShapeAuthority {
    pub(crate) fn sha256(&self) -> anyhow::Result<String>;
    pub(crate) fn header_record(&self) -> anyhow::Result<String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CaptureOutcome {
    Accepted,
    Rejected,
}

pub(crate) struct NativeShapeRaw {
    pub(crate) user_cpu: u64,
    pub(crate) kernel_cpu: u64,
    pub(crate) invalid_cpu: u64,
    pub(crate) jit_user: u64,
    pub(crate) non_jit_user: u64,
    pub(crate) pc_samples: Vec<PcSample>,
    pub(crate) parents: std::collections::BTreeMap<u32, u32>,
    pub(crate) lifecycle: NativeShapeLifecycle,
}

impl NativeShapeRaw {
    pub(crate) fn parse(
        bytes: &[u8],
        authority: &NativeShapeAuthority,
    ) -> anyhow::Result<Self>;
}
```

The authority's `schema` is `carrick.native-shape-authority.v1`; `profile`, `raw_schema`, `git_dirty`, and `sampling_hz` must serialize as `native-shape`, `carrick.native-shape.raw.v2`, `false`, and `997`. The argv digest is SHA-256 over a big-endian `u64` argument count followed by, for every UTF-8 argument, a big-endian `u64` byte length and the exact bytes. The authority digest is SHA-256 over `serde_json::to_vec(&authority)`.

---

### Task 1: Extract and Harden Snapshot Authority

**Files:**

- Create: `crates/carrick-cli/src/jit_shape_snapshot.rs`
- Modify: `crates/carrick-cli/src/debug_jit_shape.rs`
- Modify: `crates/carrick-cli/src/main.rs`

**Step 1: Add red strict-directory and manifest tests**

Move the existing v4 snapshot fixtures into the new module and add tests named:

```rust
#[test]
fn snapshot_directory_rejects_unknown_entries_and_symlinks() {
    let fixture = SnapshotFixture::one_pair(41, 0x1000, &[0x20, 0x00, 0x1f, 0xd6]);
    fixture.write_unknown("notes.txt", b"not evidence");
    assert!(SnapshotSet::load(fixture.path()).unwrap_err().to_string().contains("unknown"));
    fixture.remove("notes.txt");
    fixture.symlink_pair("linked.json");
    assert!(SnapshotSet::load(fixture.path()).unwrap_err().to_string().contains("symlink"));
}

#[test]
fn manifest_is_sorted_and_domain_separated() {
    let a = SnapshotFixture::two_pairs_in_order(["41-2", "41-1"]);
    let b = SnapshotFixture::two_pairs_in_order(["41-1", "41-2"]);
    assert_eq!(SnapshotSet::load(a.path()).unwrap().manifest(), SnapshotSet::load(b.path()).unwrap().manifest());
    assert_eq!(SnapshotSet::load(a.path()).unwrap().manifest().pairs, 2);
}
```

Also cover: directory and nested-directory rejection; incomplete pair; wrong schema; JSON and payload digest mismatch; `code_len` mismatch; empty code; non-four-byte code length; unaligned cache base/block endpoints; overflowing and out-of-payload block ranges; overlapping resolving ranges for one PID; duplicate PID snapshots whose ranges do not overlap; and pair/PID/block/byte counters. Within one real directory, the same recognized extension plus the same stem implies the same filename, so a duplicate-stem case is not representable; same-stem `.json`/`.bin` entries are the required pair.

Run:

```bash
cargo test -p carrick-cli jit_shape_snapshot -- --nocapture
```

Expected: compile failure because the module and `SnapshotSet` do not exist.

**Step 2: Move the existing loader without changing accepted v4 behavior**

Move `SnapshotMetadata`, `Snapshot`, `SnapshotSet`, metadata/payload hashing, and the existing manifest logic out of `debug_jit_shape.rs`. Register `mod jit_shape_snapshot;` in `main.rs`. Keep the runtime's v4 writer unchanged in this task.

The manifest byte stream must be exactly, for each lexically sorted stem:

```text
stem NUL json_sha256 NUL payload_sha256 NEWLINE
```

Hash that complete byte stream with SHA-256. Count unique PIDs, pairs, total block rows, and payload bytes with checked addition.

**Step 3: Add red exact-resolution tests**

```rust
#[test]
fn resolve_requires_own_snapshot_before_ancestor_fallback() {
    let set = SnapshotFixture::parent_and_child().load();
    let parents = std::collections::BTreeMap::from([(42, 41)]);
    let resolved = set.resolve(42, 0x1000, &parents).unwrap();
    assert_eq!(resolved.origin, ResolutionOrigin::Ancestor { pid: 41 });

    let only_parent = SnapshotFixture::parent_only().load();
    let error = only_parent.resolve(42, 0x1000, &parents).unwrap_err();
    assert!(error.to_string().contains("own authenticated snapshot"));
}
```

Add cases for exact own resolution, unique ancestor resolution, missing PID, missing range, ambiguous own range, ambiguous ancestor range, ancestry cycle, and a PC whose four-byte read crosses the payload end.

Run the same focused command and confirm the new resolution cases fail before implementation.

**Step 4: Implement fail-closed resolution and remove duplicate code**

Resolution order is exact:

1. Require at least one authenticated snapshot for sampled `pid`.
2. Search all of that PID's ranges and require zero or one matching four-byte word.
3. If one matches, return `Own`.
4. If none matches, walk the recorded parent chain with cycle detection and collect ancestor matches.
5. Require exactly one ancestor match and return its PID; zero or multiple matches are errors.

Update the existing v1 census internals to call this module temporarily so the move is behavior-preserving until Task 5 replaces v1.

**Step 5: Verify and commit**

```bash
cargo test -p carrick-cli jit_shape_snapshot -- --nocapture
cargo test -p carrick-cli debug_jit_shape -- --nocapture
cargo fmt --all -- --check
git diff --check
git add crates/carrick-cli/src/jit_shape_snapshot.rs crates/carrick-cli/src/debug_jit_shape.rs crates/carrick-cli/src/main.rs
git commit -m "refactor(trace): centralize JIT snapshot authority"
```

---

### Task 2: Replace SHAPE1 with Authenticated NSHAPE2

**Files:**

- Create: `crates/carrick-cli/src/native_shape_profile.rs`
- Modify: `scripts/dtrace/native-shape-census.d`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-cli/src/main.rs`

**Step 1: Add red D-template contract tests**

Expose `BUNDLED_NATIVE_SHAPE_D` beside the other bundled profiles and add tests that require:

```rust
#[test]
fn native_shape_template_is_snapshot_only_and_tracks_one_population() {
    let source = BUNDLED_NATIVE_SHAPE_D;
    assert!(source.contains("/* CARRICK_NSHAPE2_HEADER */"));
    assert!(source.contains("profile-997"));
    assert!(source.contains("arg1 != 0 && arg0 == 0"));
    assert!(source.contains("arg0 != 0 && arg1 == 0"));
    assert!(source.contains("(arg0 == 0) == (arg1 == 0)"));
    assert!(source.contains("tick-180s"));
    assert!(!source.contains("copyin("));
    assert!(!source.contains("SHAPE1"));
}
```

Add string-contract checks for process admission, inherited cache bounds, admitted/exited/live counters, the exact section names, one `NSHAPE2|complete` format, and delayed exit until all tracked descendants retire.

Run:

```bash
cargo test -p carrick-runtime native_shape -- --nocapture
```

Expected: compile failure because the constant is absent and the old source still emits `SHAPE1`.

**Step 2: Write the NSHAPE2 D program**

Replace the durable D file in place. Preserve and update its provider-ABI and perturbation header. Use a single `profile-997` clause with mutually exclusive user, kernel, and invalid counters. Only user/JIT samples enter `@pc[pid, arg1]`.

Initialize `admitted=1`, `live=1`, and `exited=0` for `$target`. A tracked `proc:::create` admits each child once, publishes the fork row, and inherits current JIT bounds. A tracked `proc:::exit` increments `exited`, decrements `live`, clears state, records target completion/reason when applicable, and calls `exit(0)` only when the target has completed and `live==0`. `tick-180s` sets `bounded=1` and exits. `dtrace:::ERROR` increments `probe_errors`.

Print the immutable rendered header first from `dtrace:::BEGIN`; print sections in `mode`, `region`, `pc`, `complete` order from `dtrace:::END`. Ensure zero-valued named mode/region rows are still printed exactly once by using scalar counters rather than relying on absent aggregations.

**Step 3: Add red strict parser and authority tests**

Register `mod native_shape_profile;` and implement only fixtures first. Tests must cover the valid exact stream plus each single mutation:

```rust
#[test]
fn nshap2_reconciles_one_cpu_population() {
    let authority = fixture_authority();
    let raw = NativeShapeRaw::parse(valid_raw(&authority).as_bytes(), &authority).unwrap();
    assert_eq!(raw.user_cpu, 70);
    assert_eq!(raw.kernel_cpu, 30);
    assert_eq!(raw.jit_user, 40);
    assert_eq!(raw.non_jit_user, 30);
    assert_eq!(raw.pc_samples.iter().map(|row| row.count).sum::<u64>(), 40);
}

#[test]
fn nshap2_rejects_shape1_and_authority_substitution() {
    let authority = fixture_authority();
    assert!(NativeShapeRaw::parse(b"SHAPE1|samples=1\n", &authority).is_err());
    let mut other = authority.clone();
    other.run_id = "different-run".to_owned();
    assert!(NativeShapeRaw::parse(valid_raw(&authority).as_bytes(), &other).is_err());
}
```

Test header-first ordering, exact fields and field order, duplicate/unknown/missing records, section order, duplicate fork parent, self-parent, ancestry cycle, zero PC rows, zero JIT samples, invalid mode nonzero, every checked-add overflow, all three reconciliation equations, bounded completion, abnormal target reason, incomplete target, admitted/exited mismatch, live nonzero, probe errors, and trailing records after completion.

Run:

```bash
cargo test -p carrick-cli native_shape_profile -- --nocapture
```

Expected: fixture tests fail until the parser and authority are complete.

**Step 4: Implement authority hashing and the strict state-machine parser**

Implement `NativeShapeAuthority::sha256`, `header_record`, argv hashing, percent-token validation for header values, exact SHA validation, and a parser whose enum state is:

```rust
enum ParseState {
    Header,
    ForksOrModeSection,
    ModeRows { seen: u8 },
    RegionSection,
    RegionRows { seen: u8 },
    PcSection,
    PcRows,
    Complete,
    Finished,
}
```

Do not route these rows through `ProfileSummary`. Ignore no nonempty line: any non-`NSHAPE2` content in the raw evidence file is an error.

**Step 5: Verify and commit**

```bash
cargo test -p carrick-runtime native_shape -- --nocapture
cargo test -p carrick-cli native_shape_profile -- --nocapture
cargo fmt --all -- --check
cargo clippy -p carrick-runtime -p carrick-cli --all-targets -- -D warnings
git diff --check
git add scripts/dtrace/native-shape-census.d crates/carrick-runtime/src/dtrace_consumer.rs crates/carrick-cli/src/native_shape_profile.rs crates/carrick-cli/src/main.rs
git commit -m "feat(trace): define authenticated native shape protocol"
```

---

### Task 3: Add NativeShape CLI, Preflight, and Sudo Preservation

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`
- Modify: `crates/carrick-cli/src/native_profile_qualification.rs`
- Modify: `crates/carrick-cli/src/native_shape_profile.rs`
- Modify: `crates/carrick-cli/src/trace_cli.rs`
- Modify: `crates/carrick-cli/src/commands.rs`

**Step 1: Add red CLI and structural-target tests**

Add `NativeShape` to `TraceProfileKind` and add this trace option:

```rust
/// Fresh directory for native-shape retirement snapshots.
#[arg(long = "native-shape-snapshots", value_name = "DIR", requires = "profile")]
native_shape_snapshots: Option<std::path::PathBuf>,
```

Add tests for:

- parsing `--profile native-shape`;
- rejecting NativeShape unless `--trace-out`, `--summary-jsonl`, and `--native-shape-snapshots` are all supplied;
- rejecting the snapshot option for every other profile and generic script;
- rejecting equal raw/receipt paths and any output path that aliases the snapshot directory after lexical absolute normalization;
- rejecting non-Darwin/AArch64 hosts before launch;
- rejecting target subcommands other than `run`;
- rejecting defaulted native, explicit VMM, a tag-only image, malformed digest, and an empty command;
- accepting only explicit command-line native plus an `ImageReference` whose `digest()` is exactly `sha256:` and 64 lowercase hex characters; and
- preserving the snapshot path and `CARRICK_RUN_ID` through sudo argv reconstruction.

The central target test is:

```rust
#[test]
fn native_shape_requires_command_line_native_and_digest_image() {
    let accepted = NativeShapeTarget::parse(&[
        "run".to_owned(),
        "--exec-backend".to_owned(),
        "native".to_owned(),
        "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "/bin/true".to_owned(),
    ]).unwrap();
    assert_eq!(accepted.image_digest, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let defaulted = [
        "run".to_owned(),
        "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "/bin/true".to_owned(),
    ];
    assert!(NativeShapeTarget::parse(&defaulted).unwrap_err().to_string().contains("explicit"));
}
```

Run:

```bash
cargo test -p carrick-cli native_shape -- --nocapture
```

Expected: compile/test failures because the vocabulary and preflight do not exist.

**Step 2: Implement structural target parsing**

Use `Cli::command().try_get_matches_from()` and the nested `run` `ArgMatches`. Require `value_source("exec_backend") == Some(ValueSource::CommandLine)`, then use `Cli::from_arg_matches()` and match `Commands::Run { image, exec_backend, .. }`. Require `exec_backend == ExecBackendRequest::Native`. Parse `image` with `ImageReference::parse`, validate `digest()`, and store its canonical reference plus the exact original target argv.

Expose:

```rust
pub(crate) struct NativeShapeTarget {
    pub(crate) image: String,
    pub(crate) image_digest: String,
    pub(crate) argv: Vec<String>,
    pub(crate) argv_sha256: String,
}

impl NativeShapeTarget {
    pub(crate) fn parse(command: &[String]) -> anyhow::Result<Self>;
}
```

**Step 3: Implement strict source/binary identity and run-ID preflight**

Add one reusable `CaptureIdentity` in `native_shape_profile.rs` that reads `git rev-parse HEAD`, `git status --porcelain`, the current executable bytes, `hostname`, `std::env::consts::ARCH`, and `kern.osversion`. Unlike generic provenance, unknown values are errors and dirty must be false. Capture it before qualification and recompute it after tracing; exact Git HEAD, clean state, binary digest, host, arch, and OS build must match.

If `CARRICK_RUN_ID` is absent, generate `native-shape-<UTC>-<pid>` before the root check and set it while still single-threaded. Reject an explicitly present empty value. Include it in the forwarded environment so the re-exec and traced child see the identical value.

**Step 4: Render NativeShape through existing launch qualification**

Add `NativeShape` to `uses_native_launch_qualification`. Add exact placeholders:

```rust
const NSHAPE2_HEADER_PLACEHOLDER: &str = "/* CARRICK_NSHAPE2_HEADER */";
const NSHAPE2_TERMINALS_PLACEHOLDER: &str = "/* CARRICK_NSHAPE2_TERMINALS */";
```

Add `render_native_shape_profile_program`, taking the already-built `NativeShapeAuthority`, verifying its OS/qualification/template hashes match the qualification object, and substituting exactly one header and terminal block. Do not widen `V2ProfileAuthority`; NativeShape owns its richer authority type.

**Step 5: Create and preserve the snapshot directory**

Only the root-side invocation creates the directory, using `create_dir` so an existing path fails. Verify the created object with `symlink_metadata`, require a directory and not a symlink, then `chown` it to the trace uid/gid before child launch. Set and forward `CARRICK_DSR_CODE_SNAPSHOT_DIR` to that exact path. The unprivileged pre-sudo invocation validates only that the path is absent and reconstructs it through `TraceSudoInvocation`.

Extend `TraceSudoInvocation` with:

```rust
pub(crate) native_shape_snapshots: Option<&'a std::path::Path>,
```

and place `--native-shape-snapshots PATH` before internal identity arguments in the reconstructed argv. Update every existing constructor/test explicitly.

**Step 6: Verify and commit**

```bash
cargo test -p carrick-cli native_shape -- --nocapture
cargo test -p carrick-cli sudo_argv -- --nocapture
cargo test -p carrick-cli native_profile_qualification -- --nocapture
cargo fmt --all -- --check
cargo clippy -p carrick-cli --all-targets -- -D warnings
git diff --check
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/trace_profile.rs crates/carrick-cli/src/native_profile_qualification.rs crates/carrick-cli/src/native_shape_profile.rs crates/carrick-cli/src/trace_cli.rs crates/carrick-cli/src/commands.rs
git commit -m "feat(trace): preflight native shape captures"
```

---

### Task 4: Publish Dedicated Accepted or Rejected Capture Receipts

**Files:**

- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs`
- Modify: `crates/carrick-cli/src/native_shape_profile.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/trace_profile.rs`

**Step 1: Add red observed-run tests to the DTrace consumer**

The current consumer loses drop/interruption state when an error occurs after `dtrace_proc_continue`. Add an internal result used by NativeShape while leaving existing callers' `Result<DTraceRunReport, DTraceError>` surface intact:

```rust
pub struct DTraceObservedFailure {
    pub error: DTraceError,
    pub report: DTraceRunReport,
    pub child_launched: bool,
}

pub fn run_child_under_dtrace_observed(
    child_path: &std::path::Path,
    child_argv: &[String],
    opts: &TraceOptions,
) -> Result<DTraceRunReport, DTraceObservedFailure>;
```

Factor the state transition into testable helpers and prove compile/exec/go failures have `child_launched=false`, while work/interrupt/post-continue failures carry `child_launched=true` and the exact report accumulated so far. Existing wrappers map the failure back to its `error` so NativeWall and generic trace behavior does not change.

Run:

```bash
cargo test -p carrick-runtime observed -- --nocapture
```

Expected: compile failure because the observed result does not exist.

**Step 2: Define the exact receipt schema and red serialization tests**

Use fixed nested structs, not `serde_json::Value` or maps:

```rust
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeCaptureReceipt {
    pub(crate) schema: String,
    pub(crate) outcome: CaptureOutcome,
    pub(crate) evidence_errors: Vec<String>,
    pub(crate) authority: Option<NativeShapeAuthority>,
    pub(crate) authority_sha256: Option<String>,
    pub(crate) raw_trace_sha256: Option<String>,
    pub(crate) snapshot_manifest: Option<SnapshotManifest>,
    pub(crate) counts: Option<NativeShapeCounts>,
    pub(crate) lifecycle: Option<NativeShapeLifecycle>,
    pub(crate) drops: NativeShapeDrops,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeDrops {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) dynamic_rinse_drops: u64,
    pub(crate) dynamic_dirty_drops: u64,
    pub(crate) other_drops: u64,
    pub(crate) interrupted: bool,
}
```

`NativeShapeCounts` contains `user_cpu`, `kernel_cpu`, `all_cpu`, `invalid_cpu`, `jit_user`, `non_jit_user`, `pc_rows`, and `pc_samples`, all `u64`. `NativeShapeLifecycle` contains `bounded`, `target_completed`, `target_exit_reason`, `admitted`, `exited`, `live_at_end`, and `probe_errors` with integer/bool types matching the raw protocol.

Tests must prove exactly one newline-terminated JSON object, deterministic bytes, accepted receipts with no null fields and empty errors, rejected receipts with ordered errors and explicit nulls, denial of unknown fields, and each of the six nonzero drop counters plus interruption independently forcing rejection.

**Step 3: Implement one finalizer shared by live capture and offline tests**

```rust
pub(crate) struct NativeShapeFinalizeRequest<'a> {
    pub(crate) authority: &'a NativeShapeAuthority,
    pub(crate) raw_path: &'a std::path::Path,
    pub(crate) snapshot_directory: &'a std::path::Path,
    pub(crate) drops: NativeShapeDrops,
    pub(crate) post_identity: anyhow::Result<CaptureIdentity>,
    pub(crate) trace_error: Option<String>,
}

pub(crate) fn finalize_capture(
    request: NativeShapeFinalizeRequest<'_>,
) -> anyhow::Result<NativeShapeCaptureReceipt>;

pub(crate) fn write_capture_atomic(
    path: &std::path::Path,
    receipt: &NativeShapeCaptureReceipt,
    owner: Option<(u32, u32)>,
) -> anyhow::Result<()>;
```

The finalizer accumulates evidence errors in this fixed order: trace execution, DTrace losses/interruption, post-identity drift, raw read/hash/parse, snapshot load/manifest, and PC resolution. It resolves every PC through `SnapshotSet`; any failed or ambiguous sample rejects. It accepts only with 100% resolution and all required fields populated.

Preflight, output creation, D compilation, D program execution, and `dtrace_go` errors have `child_launched=false`: exit nonzero without a receipt. Any observed failure after `dtrace_proc_continue` has `child_launched=true`: finalize whatever evidence exists, atomically publish a rejected receipt, then exit nonzero. A completed trace always publishes accepted or rejected; rejected returns nonzero after publication.

**Step 4: Dispatch NativeShape outside generic ProfileSummary**

In `Commands::Trace`, branch NativeShape before NativeFault/NativeWall summary parsing. Require the dedicated receipt path and snapshot directory, invoke `run_child_under_dtrace_observed`, recompute identity, finalize, print a concise human status, and write the one-line receipt. Do not call `ProfileSummary::from_path` or `write_summary_atomic` for NativeShape.

Receipt acceptance means trace integrity only. Do not inspect guest stdout or search for `BUILD_OK` here. The live command's normal process result remains visible to the operator/controller.

**Step 5: Verify and commit**

```bash
cargo test -p carrick-runtime observed -- --nocapture
cargo test -p carrick-cli native_shape_profile -- --nocapture
cargo test -p carrick-cli native_shape_capture -- --nocapture
cargo fmt --all -- --check
cargo clippy -p carrick-runtime -p carrick-cli --all-targets -- -D warnings
git diff --check
git add crates/carrick-runtime/src/dtrace_consumer.rs crates/carrick-cli/src/native_shape_profile.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/trace_profile.rs
git commit -m "feat(trace): publish native shape capture receipts"
```

---

### Task 5: Replace the v1 Census and Python Classifier with Rust v2

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/debug.rs`
- Replace: `crates/carrick-cli/src/debug_jit_shape.rs`
- Delete: `scripts/perf/shape_classify.py`

**Step 1: Change the CLI and add red compatibility-rejection tests**

Replace the debug command shape with:

```rust
JitShapeCensus {
    trace: PathBuf,
    #[arg(long)]
    capture: PathBuf,
    #[arg(long)]
    snapshots: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
},
```

Tests must prove `--capture` and `--snapshots` are mandatory, `--output` is optional, `--jit-share-of-total` is unknown, SHAPE1 is rejected, a v1 capture/census is rejected, and omitted output writes deterministic JSON to stdout without a second human format.

Run:

```bash
cargo test -p carrick-cli jit_shape -- --nocapture
```

Expected: old CLI tests fail because they still require the imported ratio.

**Step 2: Add exhaustive classifier parity fixtures red-first**

Port every active exact mask and precedence rule from both current classifiers into table-driven Rust tests. Include at least one positive and one one-bit-neighbor negative for each exact inserted family, plus coarse guest families and register extraction.

The result type is:

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceClass {
    InsertedExact,
    GuestDescriptive,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Classification {
    evidence_class: EvidenceClass,
    family: &'static str,
}
```

Preserve this exact precedence: context 64/32/pair; generation guard; window UBFM/CBZ; bias ORR; NZCV MSR/MRS; x17/x18 materialization; exact x17 trusted branch; x18-based load/store; generic branch register/return; coarse guest branch, load/store, arithmetic, logic, multiply-add, SIMD, other.

Add frozen word/expected-family fixtures copied from the Python implementation before deleting it. Run the Rust test and the existing Python script against one existing local fixture if present; compare the complete family/word populations, not top-N text. If no local fixture remains, construct a synthetic trace/snapshot fixture containing every frozen word once and compare both implementations on that fixture.

**Step 3: Define and implement the v2 report**

Use fixed ordered row vectors:

```rust
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JitShapeCensusV2 {
    pub(crate) schema: String,
    pub(crate) capture_receipt_sha256: String,
    pub(crate) raw_trace_sha256: String,
    pub(crate) snapshot_manifest_sha256: String,
    pub(crate) capture_authority: NativeShapeAuthority,
    pub(crate) census_identity: CaptureIdentity,
    pub(crate) classifier_schema: String,
    pub(crate) populations: CensusPopulations,
    pub(crate) coverage: CensusCoverage,
    pub(crate) inserted_exact_floor: CensusShare,
    pub(crate) families: Vec<FamilyRow>,
    pub(crate) words: Vec<WordRow>,
    pub(crate) contexts: Vec<ContextRow>,
}
```

`classifier_schema` is `carrick.jit-shape-classifier.aarch64.v2`. Sort family rows by `(evidence_class, family)`, word rows by `(family, word)`, and context rows by `(direction, slot, physical_register)`. Emit every exact word row. Store samples plus integer numerator/denominator pairs for both JIT and all-CPU shares; serialize display decimals only as derived strings if a human-readable value is needed. Do not hash floating-point values.

Context decoding reports direction (`load`/`store`), exact context slot, physical register, and sample count. Require context totals to equal the union of context family samples and require every family to be mutually exclusive. `inserted_exact_floor` is the checked sum of only `EvidenceClass::InsertedExact` rows.

**Step 4: Authenticate every input and the census executor**

`run_jit_shape_census(trace, capture, snapshots, output)` must:

1. require a clean known current Git identity and hash the running census binary;
2. read exactly one accepted `carrick.native-shape-capture.v1` object;
3. hash and strictly parse raw against the receipt authority;
4. recompute the snapshot manifest and require the receipt hash/counters;
5. repeat 100% own/ancestor PC resolution;
6. recompute all raw and receipt counts;
7. classify every resolved word exactly once; and
8. atomically publish deterministic v2 JSON or print the same serialized bytes plus one newline.

Substitution tests independently change the receipt, raw trace, snapshot payload, snapshot metadata, manifest, capture authority, and current binary/source identities and require failure before classification.

**Step 5: Delete Python only after parity is green**

Remove `scripts/perf/shape_classify.py` and use `rg` to ensure no active command/docs tell operators to run it. Historical evidence prose may name it as historical authority but must not present it as current tooling.

**Step 6: Verify and commit**

```bash
cargo test -p carrick-cli jit_shape -- --nocapture
cargo test -p carrick-cli native_shape -- --nocapture
rg -n "jit-share-of-total|SHAPE1|shape_classify.py" crates scripts docs handoff.md .superpowers
cargo fmt --all -- --check
cargo clippy -p carrick-cli --all-targets -- -D warnings
git diff --check
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs crates/carrick-cli/src/debug_jit_shape.rs scripts/perf/shape_classify.py
git commit -m "feat(debug): authenticate native shape census v2"
```

The `rg` result may contain only immutable historical evidence and explicit statements that the old path was replaced.

---

### Task 6: Add Determinant-Locked Pair Comparison

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/debug.rs`
- Modify: `crates/carrick-cli/src/debug_jit_shape.rs`

**Step 1: Add the command and red determinant tests**

Add:

```rust
JitShapeCompare {
    a: PathBuf,
    b: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
},
```

Build two valid synthetic censuses and mutate one determinant per test. Require equality of capture Git HEAD, capture executable SHA, D template SHA, image canonical digest reference, exact target argv and argv SHA, sampling frequency, classifier schema, census Git HEAD, and census executable SHA. Require inequality of run IDs, capture-receipt hashes, raw hashes, and snapshot manifests.

Reject identical files, v1 schema, a rejected capture embedded in either census, missing rows, duplicate rows, row population mismatches, and a determinant mismatch even when all numerical shares agree.

Run:

```bash
cargo test -p carrick-cli jit_shape_compare -- --nocapture
```

Expected: compile failure because the command and comparison type do not exist.

**Step 2: Implement a full outer join with exact rational arithmetic**

Define:

```rust
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JitShapeComparisonV1 {
    pub(crate) schema: String,
    pub(crate) a_sha256: String,
    pub(crate) b_sha256: String,
    pub(crate) determinants: ComparisonDeterminants,
    pub(crate) family_rows: Vec<ComparisonRow>,
    pub(crate) word_rows: Vec<ComparisonRow>,
    pub(crate) context_rows: Vec<ComparisonRow>,
    pub(crate) mechanical_crossings: Vec<MechanicalCrossing>,
}
```

For every union key, missing means zero samples only after each source census has independently passed its own internal completeness checks. Compare shares by cross multiplication against 10/100 and drift by exact integer arithmetic against 5/100; do not make the gate depend on rounded floats. A mechanical crossing requires both shares at least 10% of all CPU and absolute drift at most five percentage points.

Sort all rows by their census keys. Sort crossings by descending minimum all-CPU share, then key. Publish one deterministic JSON object atomically or to stdout.

**Step 3: Prove boundary and determinism behavior**

Add exact tests at 9.999%, 10.000%, 10.001%, 4.999 percentage-point drift, 5.000, and 5.001. Regenerate the same comparison twice and require byte equality. Swap A/B and require the same crossing set while preserving labelled A/B values.

**Step 4: Verify and commit**

```bash
cargo test -p carrick-cli jit_shape_compare -- --nocapture
cargo test -p carrick-cli jit_shape -- --nocapture
cargo fmt --all -- --check
cargo clippy -p carrick-cli --all-targets -- -D warnings
git diff --check
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/debug.rs crates/carrick-cli/src/debug_jit_shape.rs
git commit -m "feat(debug): compare native shape captures"
```

---

### Task 7: Full Verification and One Signed Qualification Capture

**Files:**

- Modify only if a gate exposes a defect: files from Tasks 1–6
- Write untracked qualification artifacts under: `target/perf/native-shape-qualification-dbe1c32f/`

**Step 1: Run focused source and schema audits**

```bash
rg -n "copyin\(|SHAPE1|jit-share-of-total|carrick\.jit-shape-census\.v1" scripts/dtrace/native-shape-census.d crates/carrick-cli/src crates/carrick-runtime/src
rg -n "BUNDLED_NATIVE_SHAPE_D|NativeShape|NSHAPE2|carrick\.native-shape-capture\.v1|carrick\.jit-shape-census\.v2|carrick\.jit-shape-comparison\.v1" crates scripts/dtrace/native-shape-census.d
git diff --check
```

The first command must return no active-code match. The second must show one coherent producer/parser/CLI chain.

**Step 2: Run focused tests and full local authority**

```bash
cargo test -p carrick-runtime native_shape -- --nocapture
cargo test -p carrick-runtime observed -- --nocapture
cargo test -p carrick-cli native_shape -- --nocapture
cargo test -p carrick-cli jit_shape -- --nocapture
RUST_TEST_THREADS=1 just ci
```

If any command fails, diagnose and fix only the attributable defect, rerun the failed command, then rerun the entire sequence. Commit any repair separately with a message naming the contract repaired.

**Step 3: Independent plan/spec implementation review**

Review the diff against every bullet in the approved design's Testing and acceptance section. Confirm no generic ProfileSummary path handles NativeShape, no output is accepted with missing evidence, and no runtime/emitter/default behavior changed. Record findings before live tracing. A clean review is required; resolve all correctness findings before continuing.

**Step 4: Build the fresh signed binary and run native smoke**

```bash
just build
codesign -dv --verbose=4 target/release/carrick
RUST_TEST_THREADS=1 just conformance-native smoke --workers 4 --flake-retries 1
```

Record the exact Git HEAD and `shasum -a 256 target/release/carrick`. Require the applicable native smoke to match its current blessed result; investigate any delta before tracing.

**Step 5: Run one small signed qualification capture**

Use the digest-pinned native-arm64 image already frozen in the controller and a short fork/exec workload that prints exactly one `TRACE_OK`. Keep the target argv explicit and immutable:

```bash
target/release/carrick trace \
  --profile native-shape \
  --trace-out target/perf/native-shape-qualification-dbe1c32f/raw.trace \
  --summary-jsonl target/perf/native-shape-qualification-dbe1c32f/capture.jsonl \
  --native-shape-snapshots target/perf/native-shape-qualification-dbe1c32f/snapshots \
  -- run --exec-backend native \
  localhost:5005/carrick-go-conformance@sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6 \
  /bin/sh -c 'true & wait; echo TRACE_OK'
```

The image is the campaign's current frozen native-arm64 Go conformance image. Reconfirm that exact digest against the controller before executing; if it has intentionally changed, update the controller and this command together before taking evidence.

Require: exit zero, one `TRACE_OK`, one accepted receipt, exact authenticated header, `bounded=false`, target complete, admitted=exited, live zero, all seven loss fields zero/false, snapshot manifest valid, nonzero user/kernel/JIT/PC populations, and 100% PC resolution.

**Step 6: Regenerate the qualification census twice**

```bash
target/release/carrick debug jit-shape-census \
  target/perf/native-shape-qualification-dbe1c32f/raw.trace \
  --capture target/perf/native-shape-qualification-dbe1c32f/capture.jsonl \
  --snapshots target/perf/native-shape-qualification-dbe1c32f/snapshots \
  --output target/perf/native-shape-qualification-dbe1c32f/census-a.json
target/release/carrick debug jit-shape-census \
  target/perf/native-shape-qualification-dbe1c32f/raw.trace \
  --capture target/perf/native-shape-qualification-dbe1c32f/capture.jsonl \
  --snapshots target/perf/native-shape-qualification-dbe1c32f/snapshots \
  --output target/perf/native-shape-qualification-dbe1c32f/census-b.json
cmp target/perf/native-shape-qualification-dbe1c32f/census-a.json target/perf/native-shape-qualification-dbe1c32f/census-b.json
```

Qualification validates the tool. It is not performance evidence and must not be fed to the pair comparator.

**Step 7: Commit any qualification-only documentation repair**

If implementation code did not change, do not create an empty commit. If a live-only defect was repaired, rerun Steps 1–6 and commit that repair narrowly.

---

### Task 8: Take Two Quiet Cold-Build Captures and Make the Carry Decision

**Files:**

- Create: `scripts/perf/evidence/native-go-build-shape-comparison-v1.json`
- Modify: `docs/perf-results/native-wall-time-campaign.md`
- Modify: `handoff.md`
- Modify: `.superpowers/sdd/2026-08-04-native-optimistic-decode/progress.md`

**Step 1: Freeze determinants before capture A**

Require a clean tree. Record exact Git HEAD, signed binary SHA-256, Darwin build, hostname, digest-pinned image, exact target argv, D-template SHA-256, launch-qualification hashes, sampling frequency, and classifier schema. Create fresh, separately named `target/perf/native-shape-go-build-v1/a` and `b` artifact roots; neither snapshot directory may preexist.

Use the controller's existing cold-build command with a fixed guest path that is synchronously removed before each run. Keep A and B target argv byte-identical. `CARRICK_RUN_ID` and host artifact paths remain outside target argv.

**Step 2: Run capture A serially**

Run the exact NativeShape command using A's raw, receipt, and snapshot paths. Admit A only if:

- the trace command exits zero;
- guest stdout contains exactly one full-line `BUILD_OK`;
- cleanup succeeds and no scoped descendants remain;
- the receipt outcome is accepted with every integrity gate green; and
- a fresh census is generated twice with identical bytes.

If A rejects, preserve its artifacts, diagnose the named evidence error, and do not run B until the tool or environment is corrected and a newly named A attempt is authorized by the controller.

**Step 3: Run capture B serially**

Repeat Step 2 with B paths and a different nonempty run ID. Do not rebuild, edit source, change command argv, change image, or run Docker between A and B. Reject any determinant drift.

**Step 4: Compare and independently regenerate**

```bash
target/release/carrick debug jit-shape-compare \
  target/perf/native-shape-go-build-v1/a/census.json \
  target/perf/native-shape-go-build-v1/b/census.json \
  --output target/perf/native-shape-go-build-v1/comparison-a.json
target/release/carrick debug jit-shape-compare \
  target/perf/native-shape-go-build-v1/a/census.json \
  target/perf/native-shape-go-build-v1/b/census.json \
  --output target/perf/native-shape-go-build-v1/comparison-b.json
cmp target/perf/native-shape-go-build-v1/comparison-a.json target/perf/native-shape-go-build-v1/comparison-b.json
shasum -a 256 target/perf/native-shape-go-build-v1/a/raw.trace target/perf/native-shape-go-build-v1/a/capture.jsonl target/perf/native-shape-go-build-v1/a/census.json target/perf/native-shape-go-build-v1/b/raw.trace target/perf/native-shape-go-build-v1/b/capture.jsonl target/perf/native-shape-go-build-v1/b/census.json target/perf/native-shape-go-build-v1/comparison-a.json
```

Copy the byte-identical comparison JSON to `scripts/perf/evidence/native-go-build-shape-comparison-v1.json` with `apply_patch` only after every hash and receipt is verified.

**Step 5: Audit each mechanical crossing in source**

For each reported crossing, locate the exact emitter source and disassembly shape. Prove all four carry conditions from the design: one source-distinct removable mechanism; no overlap with closed context/trusted-entry lines or another selected row; inserted rather than guest-required semantics; and removable without weakening register, recovery, publication, generation, signal, or memory semantics.

Do not group rows merely to exceed 10%. A group is admissible only when one explicit source mechanism necessarily emits every included row and the rows are non-overlapping.

**Step 6: Make exactly one of two durable decisions**

If one mechanism survives, record its A/B all-CPU shares, percentage-point drift, sample counts, exact words/context rows, source locations, non-overlap proof, and confidence. Authorize a separate brainstorming/design turn only; do not patch the emitter in this plan.

If none survives, record that emitted-shape attribution is closed with no selectable >=10% mechanism and return to the next non-regrettable host/kernel opportunity from the broad Task 12 split.

In both cases retain the official 10.1776x score and state that traced timing changed no baseline.

**Step 7: Update controllers, verify, and commit**

Update the campaign evidence table, handoff current state/next step/confidences, and SDD progress ledger with exact artifact hashes and the carry/no-carry decision.

```bash
git diff --check
rg -n "10\.1776x|native-shape|mechanical crossing|carry|no-carry" docs/perf-results/native-wall-time-campaign.md handoff.md .superpowers/sdd/2026-08-04-native-optimistic-decode/progress.md scripts/perf/evidence/native-go-build-shape-comparison-v1.json
git status --short
git add scripts/perf/evidence/native-go-build-shape-comparison-v1.json docs/perf-results/native-wall-time-campaign.md handoff.md .superpowers/sdd/2026-08-04-native-optimistic-decode/progress.md
git commit -m "docs(perf): record authenticated native shape attribution"
```

Do not merge or push after this commit. Report the exact branch tip, clean/dirty state, artifact hashes, decision, next non-regrettable step, and updated confidence.

## Plan Self-Review Checklist

- Every approved design section maps to a task: first-class profile (2–4), snapshot authority (1), receipt (4), Rust census (5), comparator (6), qualification (7), and two-capture decision (8).
- The same snapshot loader/resolver is used at capture and census; no second manifest or ancestry implementation is authorized.
- NativeShape never enters generic ProfileSummary and never imports a JIT ratio.
- Explicit native uses Clap value source, and image digest comes from parsed `ImageReference`.
- Authority, raw, receipt, census, and comparison schemas are versioned and strict; old versions are rejected.
- Capture acceptance and workload success remain separate.
- All pair gates use exact integer arithmetic and determinant locks.
- The plan contains no emitter optimization, no eager translation, no Docker overlap, and no baseline claim from traced timing.
- Every implementation task has a red test, focused green test, formatting/lint gate, and narrow commit.
- Full CI, signed build, smoke, live qualification, deterministic regeneration, and independent quiet captures occur before a carry decision.
