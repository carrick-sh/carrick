# Native DSR-only Backend and HVF Comparison Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every Carrick-owned native `brk` transport and make DSR the sole Darwin-native execution path, then produce a provenance-complete report-only native16k/HVF performance comparison.

**Architecture:** Collapse public policy, runtime planning, image mapping, and thread execution onto one DSR-only path while preserving Linux `brk(2)` and guest-authored AArch64 `brk` semantics. Extend the existing performance support with a serial native-HVF-HVF-native runner that executes identical artifacts, records seeded bootstrap intervals, and never gates on a ratio.

**Tech Stack:** Rust 1.96.0, edition 2024, clap/serde, DSR AArch64 emission, C ucontext gateway support, conformance probes, existing `perf_stats` and JSONL provenance, shell/just, codesign, Docker oracle.

## Global Constraints

- Build runnable guests through `just build` or `scripts/build-signed.sh`; never run a bare `cargo build` artifact.
- Keep Apple `ld64`; never substitute `lld`, because DTrace requires `__DATA,__dof_carrick`.
- Do not read Linux kernel or other GPL implementation source.
- Never run Carrick and Docker concurrently. Use scoped `CARRICK_RUN_ID` values and `scripts/sudo/kill.sh` cleanup.
- Preserve Linux `brk(2)` heap behavior and guest-authored AArch64 `brk` to SIGTRAP behavior.
- Remove Carrick-owned `brk` transports, sentinels, comparative oracles, CLI/environment policy, and persisted policy completely.
- Native execution is DSR-only and remains restricted to the validated Darwin/AArch64 native16k plan.
- Native16k/HVF ratios are report-only. Invalid samples fail the deliberate measurement; ratios never fail it.
- Keep measured results separate from projections and historical evidence.
- Preserve unrelated worktree state, including the untracked `.codex/` directory.

---

## File structure

- `crates/carrick-spec/src/lib.rs`: public run vocabulary with no native code-mode type or field.
- `crates/carrick-engine/src/lib.rs`: request lowering with backend/page profile only.
- `crates/carrick-cli/src/{args,commands,lifecycle}.rs`: CLI and persisted-container plumbing.
- `crates/carrick-runtime/src/{container,execute,page_profile,runtime}.rs`: mode-free runtime plan and stored configuration.
- `crates/carrick-runtime/src/native_darwin.rs`: DSR-only execution/mapping; no legacy trap loop or patcher.
- `crates/carrick-runtime/csrc/native_darwin.c`: DSR signal/ucontext support; no SIGTRAP bootstrap transport.
- `crates/carrick-runtime/src/native_darwin/dsr/{emit,oracle,mod}.rs`: branch gateways and typed exits without `BRK_DSR_*`.
- `conformance-probes/src/bin/nativebrk.rs`: guest-authored `brk` semantic witness.
- `crates/carrick-cli/tests/perf_support/backend_pair.rs`: backend identity, ABBA schedule, artifact identity, comparison and skip schema.
- `crates/carrick-cli/tests/perf_support/{cases,invoke,provenance,stats,mod}.rs`: reusable case metadata, invocation, JSONL, and statistics.
- `crates/carrick-cli/tests/perf_runner.rs`: deliberate Carrick/Docker and native16k/HVF entrypoints.
- `scripts/measure-perf.sh` and `justfile`: user-facing benchmark commands.
- `docs/perf-results/2026-07-12-native16k-hvf.jsonl` and `docs/2026-07-12-native16k-hvf-performance.md`: measured evidence.

---

### Task 1: Remove native code-mode policy and the legacy `brk` executor

**Files:**
- Modify: `crates/carrick-spec/src/lib.rs`
- Modify: `crates/carrick-engine/src/lib.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/lifecycle.rs`
- Modify: `crates/carrick-cli/tests/cli.rs`
- Modify: `crates/carrick-runtime/src/container.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-runtime/src/page_profile.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/csrc/native_darwin.c`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Create: `conformance-probes/src/bin/nativebrk.rs`

**Interfaces:**
- Consumes: `RunSpec::{exec_backend,native_page_profile}`, `ExecutionBackend::NativeDarwin`, `NativePageProfile::Native16k`, and DSR `ProcessTranslator`/branch gateways.
- Produces: `ExecutionPlan { backend, page_geometry, diagnostics }`, unconditional DSR entry, mode-free mapping helpers, and `carrick_native_install_dsr_signal_handlers()`.

- [ ] **Step 1: Write red public-policy tests**

Add to `crates/carrick-cli/tests/cli.rs`:

```rust
#[test]
fn native_code_mode_flag_is_not_public_policy() {
    let output = command().args([
        "run-elf", "--exec-backend", "native", "--native-page-profile",
        "native16k", "--native-code-mode", "dsr", "/does/not/matter",
    ]).output().expect("run carrick CLI parser");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unexpected argument '--native-code-mode'"));
}
```

Replace the mode-validation unit test in `page_profile.rs` with:

```rust
#[test]
fn native16k_plan_has_no_instruction_vehicle_policy() {
    let plan = native_plan(NativePageProfileRequest::Native16k, DARWIN_NATIVE_PAGE_SIZE)
        .expect("native16k plan");
    assert_eq!(plan.backend, ExecutionBackend::NativeDarwin);
    assert_eq!(plan.page_geometry.native_profile, Some(NativePageProfile::Native16k));
}
```

In `carrick-spec`, serialize a default `RunSpec`, insert
`"native_code_mode":"brk"`, deserialize it, and assert reserialization has no
`native_code_mode` key.

Add a red `emit.rs` test that constructs the existing syscall fallback plan,
calls `exit_word`, and rejects the current sentinel:

```rust
#[test]
fn carrick_owned_exit_is_not_brk_transport() {
    let word = exit_word(&syscall_plan()).expect("legacy fallback word");
    assert_ne!(word & 0xffe0_001f, 0xd420_0000);
}
```

Create `conformance-probes/src/bin/nativebrk.rs` in the repository's existing
fork/signal probe style. Install `SA_SIGINFO`, execute one guest instruction,
advance the AArch64 PC by four in the handler, and emit
`delivered_sigtrap=true`, `si_code_trap_brkpt=true`, and
`resumed_after_brk=true`:

```rust
#[cfg(target_arch = "aarch64")]
unsafe fn execute_guest_brk() {
    core::arch::asm!("brk #0x1234", options(nostack));
}
```

- [ ] **Step 2: Verify the red state**

Run:

```bash
cargo test -p carrick-spec native_code_mode --lib
cargo test -p carrick-runtime native16k_plan_has_no_instruction_vehicle_policy --lib
cargo test -p carrick-runtime carrick_owned_exit_is_not_brk_transport --lib
cargo test -p carrick-cli --test cli native_code_mode_flag_is_not_public_policy -- --nocapture
scripts/build-probes.sh
scripts/build-signed.sh
scripts/run-probe.sh nativebrk
```

Expected: the model still has the field, the CLI accepts the option, and the
exit test observes a Carrick BRK sentinel. Record `nativebrk` as the pre-change
semantic baseline; it may already MATCH, because its purpose is to prevent the
transport deletion from regressing guest-authored breakpoint behavior.

- [ ] **Step 3: Remove public and persisted mode policy**

Delete `NativeCodeModeRequest`, `RunSpec::native_code_mode`, request fields,
lowering assignments, clap arguments, command destructuring, lifecycle copies,
container fields, defaults, and fixtures. Do not add a private replacement enum
or boolean. The final plan is:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

pub(crate) fn resolve_execution_plan_for_request(
    platform: Platform,
    exec_backend: ExecBackendRequest,
    native_page_profile: NativePageProfileRequest,
) -> Result<ExecutionPlan, RuntimeError>
```

Serde's normal unknown-field behavior reads old container state but ignores the
removed value; new state never writes it.

- [ ] **Step 4: Make native mapping and execution unconditionally DSR**

`run_native_thread_loop` delegates directly:

```rust
fn run_native_thread_loop(
    dispatcher: Arc<SyscallDispatcher>, memory: SharedNativeMemory,
    reporter: Arc<CompatReporter>, max_traps: usize, plan: Arc<ExecutionPlan>,
    thread_runtime: &mut NativeThreadRuntime, start: NativeThreadStart,
) -> Result<NativeThreadLoopOutcome, RuntimeError> {
    run_native_dsr_thread_loop(
        dispatcher, memory, reporter, max_traps, plan, thread_runtime, start,
    )
}
```

Remove mode parameters from `NativeMappedMemory::map*`, `map_region`,
`map_bytes_region`, `relocate_vdso_vvar_loads`, and `native16k_host_prot`.
Keep the former DSR branches: translator reuse, non-executable source mappings,
generation invalidation, DSR W^X, vDSO relocation, and branch-gateway entry.

- [ ] **Step 5: Delete the Rust legacy executor and DSR sentinels**

Delete `BRK_NATIVE_*`, `NATIVE_EVENT_TRAP`, `NativeTrap`, the non-DSR run loop,
`decode_native_trap`, `decode_trap_instruction`, `patch_syscalls`,
`patch_syscalls_recording`, `brk_instruction`, `BRK_DSR_*`,
`legacy_brk_round_trip`, and their legacy-only tests. Retain snapshot/register
helpers only where DSR, fork/exec, linux4k fault emulation, or signal delivery
still calls them.

Add an emission test covering `PlannedExit::{Syscall,Direct,Indirect,Sensitive,
Continue,Unsupported}`:

```rust
#[test]
fn carrick_owned_emitted_blocks_contain_no_brk_transport() {
    for words in emitted_words_for_all_gateway_exits() {
        assert!(words.iter().all(|word| word & 0xffe0_001f != 0xd420_0000));
    }
}
```

Keep `emitted_words_for_all_gateway_exits` test-local and build it from existing
plan constructors/emission inspection.

- [ ] **Step 6: Delete the C SIGTRAP bootstrap**

In `native_darwin.c`, delete `CARRICK_NATIVE_EVENT_TRAP`, `raise(SIGTRAP)`
bootstrap, legacy `carrick_native_enter`, and SIGTRAP-as-transport branches.
Rename the retained installer in C and Rust:

```c
int carrick_native_install_dsr_signal_handlers(void) {
    /* Existing DSR synchronous-fault and kick handler installation. */
}
```

```rust
unsafe extern "C" {
    fn carrick_native_install_dsr_signal_handlers() -> libc::c_int;
}
```

Update DSR oracle callers. Guest SIGTRAP remains in the Linux signal model; it
is not a private host transport.

- [ ] **Step 7: Run focused gates and source audit**

```bash
cargo test -p carrick-spec --lib
cargo test -p carrick-engine --lib
cargo test -p carrick-runtime --lib
cargo test -p carrick-cli --test cli native_code_mode_flag_is_not_public_policy -- --nocapture
cargo clippy -p carrick-spec -p carrick-engine -p carrick-runtime -p carrick-cli --all-targets -- -D warnings
scripts/build-probes.sh
scripts/build-signed.sh
scripts/run-probe.sh nativebrk
rg -n "NativeCodeModeRequest|native_code_mode|native-code-mode|CARRICK_NATIVE_CODE_MODE|BRK_NATIVE_|BRK_DSR_|legacy_brk_round_trip|patch_syscalls|decode_native_trap" crates bench-native conformance-probes scripts README.md
```

Expected: tests/clippy pass, `MATCH nativebrk`, and the final audit has no matches.

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-spec crates/carrick-engine crates/carrick-cli/src \
  crates/carrick-cli/tests/cli.rs crates/carrick-runtime/src \
  crates/carrick-runtime/csrc/native_darwin.c conformance-probes/src/bin/nativebrk.rs
git commit -m "refactor(native): make DSR the sole execution path" -m "Remove native code-mode policy, the legacy SIGTRAP executor, generated BRK sentinels, and the BRK comparison oracle while preserving guest ABI semantics.

Verified: focused tests, clippy with warnings denied, and native BRK transport audit.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Prove guest `brk` semantics and migrate the native lane/current docs

**Files:**
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `crates/carrick-conformance/src/lane.rs`
- Modify: `crates/carrick-conformance/src/main.rs`
- Modify: `README.md`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `docs/native-dsr-static-campaign.md`
- Modify: `docs/native-dsr-ltp-campaign.md`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/diagnostics-and-debugging.md`

**Interfaces:**
- Consumes: Task 1 DSR-only CLI, `nativebrk`, and the existing probe harness.
- Produces: a native16k lane without a code-mode flag and current DSR-only docs.

- [ ] **Step 1: Remove mode arguments from conformance helpers**

Replace `run_native_code_mode_run_elf_with_args` with:

```rust
fn run_native_run_elf_with_args(
    bin: &Path, probe: &Path, native_page_profile: &'static str,
    guest_args: &[&str],
) -> ProbeOutput
```

The command supplies `--exec-backend native --native-page-profile native16k`.
Keep the `macos-native-dsr` lane/overlay names for historical result continuity,
but its injected arguments contain only backend and page profile. Rename the
lane test and assert `--native-code-mode` is absent.

- [ ] **Step 2: Update current docs without rewriting dated history**

Remove obsolete mode arguments from current commands and describe DSR as the
only native path. In `dynamic-syscall-rewriter.md`, replace dual-mode bring-up
instructions with a superseded-history note and link to the approved design.
Do not rewrite dated plans, old JSONL, or evidence that truthfully records the
former comparison.

- [ ] **Step 3: Verify and commit**

```bash
cargo test -p carrick-conformance lane::tests --lib
cargo test -p carrick-cli --test conformance nativebrk -- --nocapture
rg -n "native-code-mode|CARRICK_NATIVE_CODE_MODE" README.md \
  docs/dynamic-syscall-rewriter.md docs/native-dsr-static-campaign.md \
  docs/native-dsr-ltp-campaign.md docs/native-dsr-dtrace-profile.md \
  docs/diagnostics-and-debugging.md crates scripts bench-native conformance-probes
git add conformance-probes/src/bin/nativebrk.rs crates/carrick-cli/tests/conformance.rs \
  crates/carrick-conformance/src README.md docs/dynamic-syscall-rewriter.md \
  docs/native-dsr-static-campaign.md docs/native-dsr-ltp-campaign.md \
  docs/native-dsr-dtrace-profile.md docs/diagnostics-and-debugging.md
git commit -m "test(native): prove DSR breakpoint semantics" -m "Add a guest-authored BRK witness, remove obsolete code-mode arguments from the native lane, and update current documentation to DSR-only execution.

Verified: nativebrk Carrick/Docker MATCH, lane tests, and current-doc mode audit.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Add reusable report-only backend-pair evidence types

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/backend_pair.rs`
- Modify: `crates/carrick-cli/tests/perf_support/mod.rs`
- Modify: `crates/carrick-cli/src/perf_stats.rs`
- Modify: `crates/carrick-cli/tests/perf_support/provenance.rs`
- Modify: `crates/carrick-cli/tests/perf_support/stats.rs`

**Interfaces:**
- Consumes: `Summary`, `bootstrap_median_ratio`, `HostFacts`, and existing SHA-256 dependency.
- Produces: `CarrickBackend`, `BACKEND_PAIR_ORDER`, `ArtifactIdentity`, tagged `BackendEvidenceRow`, and atomic writer.

- [ ] **Step 1: Write red model tests**

```rust
#[test]
fn backend_pair_schedule_is_drift_balanced() {
    assert_eq!(BACKEND_PAIR_ORDER, [
        CarrickBackend::Native16k, CarrickBackend::Hvf,
        CarrickBackend::Hvf, CarrickBackend::Native16k,
    ]);
}

#[test]
fn comparison_is_native_over_hvf_and_has_no_pass_field() {
    let row = comparison_row("trap_floor", false, &[2.0, 2.2], &[4.0, 4.2], 7, 2_000)
        .expect("comparison");
    assert!(row.ratio.estimate < 1.0);
    assert!(!serde_json::to_string(&row).expect("serialize").contains("pass"));
    assert_eq!(row.ratio_numerator, "native16k");
    assert_eq!(row.ratio_denominator, "hvf");
}

#[test]
fn comparison_rejects_artifact_mismatch() {
    assert!(validate_same_artifact(
        &ArtifactIdentity::file("probe", "aaa"),
        &ArtifactIdentity::file("probe", "bbb"),
    ).expect_err("mismatch").contains("artifact sha256 mismatch"));
}
```

- [ ] **Step 2: Verify red**

```bash
cargo test -p carrick-cli --test perf_runner backend_pair -- --nocapture
```

Expected: compile failure because the backend-pair model does not exist.

- [ ] **Step 3: Promote and implement reusable statistics/evidence**

Remove `#[cfg(test)]` from `RatioInterval`, `bootstrap_median_ratio`, and
`sample_median`. Preserve the pinned seeded test. Define:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrickBackend { Native16k, Hvf }

pub const BACKEND_PAIR_ORDER: [CarrickBackend; 4] = [
    CarrickBackend::Native16k, CarrickBackend::Hvf,
    CarrickBackend::Hvf, CarrickBackend::Native16k,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactIdentity { pub kind: String, pub label: String, pub sha256: String }

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendEvidenceRow {
    Run(BackendRun), Measurement(BackendMeasurement),
    Comparison(BackendComparison), Skip(BackendSkip),
}
```

`BackendComparison` has workload, metric, unit, direction, fixed numerator and
denominator labels, summaries, and `RatioInterval`; it has no pass, limit,
winner, or global ranking. File identity hashes exact bytes; OCI identity uses
the immutable image digest.

- [ ] **Step 4: Add atomic JSONL output**

```rust
pub fn write_backend_rows_atomic(path: &Path, rows: &[BackendEvidenceRow])
    -> std::io::Result<()> {
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    for row in rows {
        serde_json::to_writer(&mut file, row).map_err(std::io::Error::other)?;
        writeln!(file)?;
    }
    file.sync_all()?;
    std::fs::rename(tmp, path)
}
```

Test one object per line and replacement of the destination only after success.

- [ ] **Step 5: Verify and commit**

```bash
cargo test -p carrick-cli --test perf_runner backend_pair -- --nocapture
cargo test -p carrick-cli --test dsr_trace_overhead bootstrap_ratio -- --nocapture
cargo clippy -p carrick-cli --test perf_runner --test dsr_trace_overhead -- -D warnings
git add crates/carrick-cli/src/perf_stats.rs crates/carrick-cli/tests/perf_support
git commit -m "test(perf): add backend-pair evidence model" -m "Add typed backend identities, fixed ABBA order, artifact checks, seeded bootstrap comparisons, and atomic JSONL with no performance pass field.

Verified: backend-pair tests, bootstrap pin, and clippy with warnings denied.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Execute identical registered cases under native16k and HVF

**Files:**
- Modify: `crates/carrick-cli/tests/perf_support/cases.rs`
- Modify: `crates/carrick-cli/tests/perf_support/invoke.rs`
- Modify: `crates/carrick-cli/tests/perf_support/backend_pair.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `scripts/measure-perf.sh`
- Modify: `justfile`

**Interfaces:**
- Consumes: Task 3 evidence model and existing `PerfCase`/metric parser.
- Produces: `BackendPairSupport`, `run_carrick_backend`, `collect_backend_pair`, ignored `backend_pair_report`, and `just bench-backends`.

- [ ] **Step 1: Write red invocation/order tests**

```rust
#[test]
fn native_and_hvf_use_the_same_direct_elf_artifact() {
    let probe = Path::new("/repo/probes/perf_trap_floor");
    let native = backend_args(CarrickBackend::Native16k, probe, &[]);
    let hvf = backend_args(CarrickBackend::Hvf, probe, &[]);
    assert_eq!(native.last(), hvf.last());
    assert!(native.windows(2).any(|w| w == ["--exec-backend", "native"]));
    assert!(hvf.windows(2).any(|w| w == ["--exec-backend", "hvf"]));
    assert!(!native.iter().any(|arg| arg == "--native-code-mode"));
}

#[test]
fn collector_runs_native_hvf_hvf_native() {
    let seen = RefCell::new(Vec::new());
    collect_backend_pair_once(|backend| { seen.borrow_mut().push(backend); Ok(1.0) })
        .expect("collect");
    assert_eq!(*seen.borrow(), BACKEND_PAIR_ORDER);
}
```

- [ ] **Step 2: Verify red**

```bash
cargo test -p carrick-cli --test perf_runner native_and_hvf_use_the_same_direct_elf_artifact -- --nocapture
cargo test -p carrick-cli --test perf_runner collector_runs_native_hvf_hvf_native -- --nocapture
```

Expected: missing invocation and collector functions.

- [ ] **Step 3: Declare support and exact arguments**

Add to `PerfCase`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPairSupport { DirectElf, Unsupported(&'static str) }
```

Also add `guest_args: &'static [&'static str]`. Mark no-mount,
non-cross-boundary AArch64 cases `DirectElf`; every unsupported case has an
exact non-empty reason.

`backend_args` returns native
`run-elf --raw --exec-backend native --native-page-profile native16k` or HVF
`run-elf --raw --exec-backend hvf`, then appends the same canonical probe path
and guest arguments.

- [ ] **Step 4: Implement serial collection and report entrypoint**

`run_carrick_backend` sets scoped run ID, exposed CPUs, process group, deadline,
output capture, and cleanup for both backends. `collect_backend_pair` loops over
`BACKEND_PAIR_ORDER`, cools down after each completed process, parses the same
metric, and errors on timeout, nonzero status, missing metric, wrong `nproc`, or
too few samples.

Add:

```rust
#[test]
#[ignore = "requires signed carrick and deliberate serial native16k/HVF sampling"]
fn backend_pair_report() { run_backend_pair_report(); }
```

It writes run/measurement/comparison rows for supported cases and explicit skip
rows for unsupported cases to required `CARRICK_BACKEND_REPORT`. It never
asserts a ratio.

- [ ] **Step 5: Expose deliberate command**

Extend `scripts/measure-perf.sh` with `backends quick|full`, preserving existing
`quick|full` behavior. Add:

```make
bench-backends PROFILE="quick":
    ./scripts/measure-perf.sh backends {{PROFILE}}
```

The script builds signed Carrick/probes and runs only the ignored backend report test.

- [ ] **Step 6: Verify and commit**

```bash
cargo test -p carrick-cli --test perf_runner backend_pair -- --nocapture
just build
CARRICK_PERF_FILTER=trap_floor just bench-backends quick
git add crates/carrick-cli/tests/perf_support crates/carrick-cli/tests/perf_runner.rs \
  scripts/measure-perf.sh justfile
git commit -m "perf: compare native16k and HVF serially" -m "Extend the existing runner with identical-artifact ABBA sampling, invalid-sample errors, explicit skips, and a report-only backend comparison command.

Verified: backend-pair tests and signed trap-floor smoke.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Cover fork scaling and direct V8

**Files:**
- Modify: `crates/carrick-cli/tests/perf_support/cases.rs`
- Modify: `crates/carrick-cli/tests/perf_support/backend_pair.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`
- Modify: `conformance-probes/src/bin/perf_fork_scale.rs`

**Interfaces:**
- Consumes: Task 4 collector, `perf_fork`, `perf_fork_exec`, `perf_fork_scale [threads [mem_mb]]`, and existing V8 image/script values.
- Produces: zero/256 MiB fork rows and digest-identified V8 row.

- [ ] **Step 1: Write red coverage tests**

```rust
#[test]
fn backend_pair_contains_required_process_cases() {
    for workload in ["fork", "fork_exec", "fork_scale_0m", "fork_scale_256m"] {
        let case = CASES.iter().find(|case| case.workload == workload)
            .unwrap_or_else(|| panic!("missing {workload}"));
        assert_eq!(case.backend_pair, BackendPairSupport::DirectElf);
    }
}

#[test]
fn v8_pair_uses_one_immutable_image_digest() {
    let identity = v8_artifact_identity("sha256:abc").expect("digest");
    validate_same_artifact(&identity, &identity).expect("same image");
}
```

- [ ] **Step 2: Verify red**

```bash
cargo test -p carrick-cli --test perf_runner backend_pair_contains_required_process_cases -- --nocapture
cargo test -p carrick-cli --test perf_runner v8_pair_uses_one_immutable_image_digest -- --nocapture
```

- [ ] **Step 3: Register process shapes**

Add `perf_fork`, `perf_fork_exec`, and:

```rust
PerfCase {
    probe: "perf_fork_scale", artifact: PerfArtifact::StaticMusl,
    dimension: "process", workload: "fork_scale_0m",
    metric_key: "fork_p50_us", unit: "us", higher_is_better: false,
    mount_scratch: false, carrick_fs_mode: "host", cross_boundary: false,
    backend_pair: BackendPairSupport::DirectElf, guest_args: &["0", "0"],
}
```

Add `fork_scale_256m` with `guest_args: &["0", "256"]`. Make the probe echo
parsed thread/memory values so the runner rejects wrong-shape output.

- [ ] **Step 4: Add direct V8**

Resolve the immutable local image digest once. Build native and HVF commands
with identical image, entrypoint, script, filesystem, CPUs, and max-traps; only
backend/page-profile arguments differ. Record wall milliseconds only after
`v8-smoke ok`, use the digest as `ArtifactIdentity`, and collect through the
same scheduler without a threshold.

- [ ] **Step 5: Verify and commit**

```bash
just build
CARRICK_PERF_FILTER=fork just bench-backends quick
CARRICK_PERF_FILTER=direct_v8 just bench-backends quick
git add crates/carrick-cli/tests/perf_support/cases.rs \
  crates/carrick-cli/tests/perf_support/backend_pair.rs \
  crates/carrick-cli/tests/perf_runner.rs conformance-probes/src/bin/perf_fork_scale.rs
git commit -m "perf: cover fork scaling and V8 by backend" -m "Add identical-artifact native16k/HVF coverage for fork, fork/exec, zero- and 256-MiB scaling, and direct V8 with validated knobs and immutable image identity.

Verified: focused signed fork and V8 backend-pair smoke.

Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 6: Run full correctness/performance campaigns and publish evidence

**Files:**
- Create: `docs/perf-results/2026-07-12-native16k-hvf.jsonl`
- Create: `docs/2026-07-12-native16k-hvf-performance.md`
- Modify: `handoff.md`

**Interfaces:**
- Consumes: all prior tasks, signed binary, probes, Docker oracle, and `just bench-backends full`.
- Produces: authoritative correctness results, raw comparison evidence, human report, and updated handoff.

- [ ] **Step 1: Run local gates**

```bash
just fmt-check
just clippy
just lint-domains
git diff --check
RUST_TEST_THREADS=1 just ci
```

Expected: all exit 0. Classify generated/cache changes before staging; preserve unrelated state.

- [ ] **Step 2: Verify signed runnable binary**

```bash
just build
codesign --verify --verbose=2 target/release/carrick
otool -l target/release/carrick | rg dof
```

Expected: valid signature and DOF section.

- [ ] **Step 3: Run semantic/lifecycle workloads**

```bash
scripts/build-probes.sh
scripts/run-probe.sh nativebrk
scripts/run-probe.sh perf_fork
scripts/run-probe.sh perf_fork_exec
cargo test -p carrick-cli --test conformance native16k_mprotect_exec_permissions_match_linux -- --nocapture
```

Then run the documented signed Rust static/dynamic PIE, Go static/dynamic PIE,
V8, JIT mutation/concurrent publication, fork, vfork, exec, and non-leader exec
commands from `docs/native-dsr-dtrace-profile.md`. Require exit 0 and markers.

- [ ] **Step 4: Rerun authoritative native16k probes**

Run the current `macos-native-dsr` full probe command from
`docs/native-dsr-static-campaign.md` with a fresh run ID/log. Record exact
numerator, denominator, duration, git SHA, binary SHA-256, and log path. Do not
reuse the old 376/376 count.

- [ ] **Step 5: Run full report-only campaign**

```bash
CARRICK_BACKEND_REPORT=docs/perf-results/2026-07-12-native16k-hvf.jsonl \
  just bench-backends full
```

Expected: each comparable workload has two measurements and one comparison;
unsupported cases have skips; no ratio drives exit status.

- [ ] **Step 6: Validate JSONL**

```bash
jq -e -s '
  any(.[]; .kind == "comparison") and
  all(.[] | select(.kind == "comparison");
      .ratio_numerator == "native16k" and
      .ratio_denominator == "hvf" and
      (has("pass") | not))
' docs/perf-results/2026-07-12-native16k-hvf.jsonl
```

Expected: `true`. Verify each comparison's measurements share artifact identity.

- [ ] **Step 7: Write measured report and handoff**

Create `docs/2026-07-12-native16k-hvf-performance.md` with provenance,
correctness receipts, a table of workload/metric/native p50+p95/HVF p50+p95/
ratio/95% interval, all skip/invalid reasons, and workload-specific limits. Use
actual rows only; no blank result cells, global winner, or projected values.

Update `handoff.md` with the DSR-only commit range, freshly measured probe
aggregate, evidence link, and remaining unsupported/invalid comparison shapes.
Remove stale claims that DSR is opt-in or `brk` is selectable.

- [ ] **Step 8: Final audit and evidence commit**

```bash
rg -n "NativeCodeModeRequest|native_code_mode|native-code-mode|CARRICK_NATIVE_CODE_MODE|BRK_NATIVE_|BRK_DSR_|legacy_brk_round_trip|patch_syscalls|decode_native_trap" crates bench-native conformance-probes scripts README.md
git diff --check
git status --short
git add docs/perf-results/2026-07-12-native16k-hvf.jsonl \
  docs/2026-07-12-native16k-hvf-performance.md handoff.md
git commit -m "docs(perf): compare native16k with HVF" -m "Record the DSR-only correctness rerun and provenance-complete report-only native16k/HVF measurements with workload-specific ratios and explicit unsupported shapes.

Verified: RUST_TEST_THREADS=1 just ci; signed workload suite; authoritative native16k probes; full backend campaign; JSONL audit.

Co-Authored-By: Codex <codex@openai.com>"
```

---

## Final review checklist

- [ ] No public, persisted, or internal code-mode selector remains.
- [ ] No Carrick-private SIGTRAP transport or generated `brk` sentinel remains.
- [ ] Linux `brk(2)` and guest-authored `brk` behavior are verified.
- [ ] Current commands/docs are DSR-only; dated history remains truthful.
- [ ] Native16k/HVF sampling is identical-artifact, serial ABBA, and provenance-complete.
- [ ] Ratio rows contain confidence intervals and no pass/fail field.
- [ ] Correctness/live workloads are green before performance publication.
- [ ] Evidence and handoff contain measured values only.
