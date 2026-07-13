# Native-default and portable VMM policy implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> implement this plan task-by-task. Track progress with the checkboxes below.

**Goal:** Make `native` Carrick's omitted/default execution backend, retain VMM
execution only behind the explicit portable spelling `--exec-backend vmm`, and
carry that immutable choice through container persistence and every lifecycle
operation.

**Architecture:** Keep one typed `ExecBackendRequest::{Native,Vmm}` from clap
and environment parsing through `CliRunRequest`, `RunSpec`, `RunConfig`, and
runtime planning. Platform routing resolves `Vmm` to the compiled host VMM;
the public and persisted vocabulary never names HVF/KVM/bhyve/NVMM. Legacy
`auto` and `hvf` input fails closed with migration guidance rather than
silently acquiring an HVF VM.

**Tech Stack:** Rust 1.96.0, edition 2024, clap `ValueEnum`, serde, Carrick's
engine/spec/runtime split, container registry JSON, conformance lanes, signed
macOS runtime verification.

## Global constraints

- macOS/Apple Silicon is the delivery gate. Cross-host work in this plan keeps
  the request vocabulary portable and compile-checks the existing platform
  closures; it does not claim live KVM/bhyve/NVMM evidence.
- Omitted CLI/environment/container policy means `Native`, including legacy
  state that predates the `config` object or `exec_backend` field.
- Explicit persisted `"auto"` or `"hvf"` is incompatible state and must fail
  to load. Do not migrate it silently.
- A native rejection may mention `--exec-backend vmm`, but no runtime layer may
  retry or mutate the request.
- Conformance lanes that intend to exercise a VMM must inject
  `--exec-backend vmm`; they may not rely on the new CLI default.
- Preserve unrelated worktree state, including `.codex/` and
  `last_1000_commits.txt`.

## File map

- `crates/carrick-spec/src/lib.rs`: the two-value public/persisted enum,
  fail-closed parsing, default, and serialization tests.
- `crates/carrick-cli/src/args.rs`: all three public command surfaces default to
  `Native` and expose only `native|vmm`.
- `crates/carrick-cli/src/commands.rs`: programmatic requests default to
  `Native`.
- `crates/carrick-engine/src/lib.rs`: request fixtures and lowering retain the
  exact backend.
- `crates/carrick-runtime/src/page_profile.rs`: `Vmm` platform plan versus
  `NativeDarwin`, with no `Auto` branch.
- `crates/carrick-runtime/src/container.rs`: native defaults and incompatible
  persisted-value tests.
- `crates/carrick-cli/src/lifecycle.rs`: create/start/restart/exec carry stored
  policy unchanged.
- `crates/carrick-conformance/src/lane.rs`: every HVF/KVM/bhyve/NVMM lane
  explicitly requests `vmm`.
- `crates/carrick-cli/tests/perf_support/{backend_pair,invoke}.rs` and
  `crates/carrick-cli/tests/perf_runner.rs`: internal evidence labels may remain
  `Hvf`, but invocation uses public `vmm`.
- `README.md` and `docs/conformance-testing.md`: current user-facing defaults
  and explicit lane commands. Dated evidence/spec documents remain historical.

---

### Task 1: Replace the public enum and prove legacy values fail closed

**Files:**

- Modify: `crates/carrick-spec/src/lib.rs`

**Interfaces:**

- Produces: `ExecBackendRequest::{Native,Vmm}` with `Native: Default`.
- Produces: serde names `"native"` and `"vmm"` only.
- Produces: clap possible values `native` and `vmm` only.
- Rejects: `auto` with `execution backend 'auto' was removed; omit
  --exec-backend for native execution or pass --exec-backend vmm`.
- Rejects: `hvf` with `execution backend 'hvf' was renamed; pass
  --exec-backend vmm`.

- [ ] **Step 1: Add red enum tests**

Add tests alongside the existing `RunSpec` compatibility tests:

```rust
#[test]
fn exec_backend_default_is_native() {
    assert_eq!(ExecBackendRequest::default(), ExecBackendRequest::Native);
}

#[test]
fn exec_backend_serde_accepts_only_portable_policy() {
    assert_eq!(
        serde_json::from_str::<ExecBackendRequest>(r#""vmm""#).unwrap(),
        ExecBackendRequest::Vmm,
    );
    for (legacy, guidance) in [("auto", "omit --exec-backend"), ("hvf", "--exec-backend vmm")] {
        let error = serde_json::from_str::<ExecBackendRequest>(&format!(r#""{legacy}""#))
            .expect_err("legacy value must fail")
            .to_string();
        assert!(error.contains(guidance), "{error}");
    }
}
```

Under `#[cfg(feature = "clap")]`, assert `ValueEnum::value_variants()` is
exactly `[Native, Vmm]` and `from_str("auto", false)` / `from_str("hvf",
false)` include the same guidance.

Run and confirm RED:

```sh
cargo test -p carrick-spec exec_backend -- --nocapture
```

Expected: tests fail because `Auto`/`Hvf` still exist and `Native` is not the
default.

- [ ] **Step 2: Implement one parser used by serde and clap**

Replace the derived deserializer and derived `ValueEnum` for this enum with a
small private parser returning the exact migration strings above. Keep derived
`Serialize`; implement `Deserialize` by deserializing a string and passing it
through the parser. Under the `clap` feature implement `clap::ValueEnum`
manually so help still lists only `native` and `vmm` and parser errors retain
guidance.

Do not add aliases for legacy values: an alias would accept the value and
violate explicit VMM selection.

- [ ] **Step 3: Run the focused gate**

```sh
cargo test -p carrick-spec exec_backend -- --nocapture
cargo test -p carrick-spec --lib
```

- [ ] **Step 4: Commit the typed policy**

```sh
git add crates/carrick-spec/src/lib.rs
git commit -m "feat(spec): make native the explicit backend default" -m "Replace the auto/HVF request vocabulary with portable native/VMM policy. Legacy explicit values now fail with migration guidance so old state cannot silently acquire a VM.\n\nVerified with carrick-spec backend parsing and library tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Propagate native defaults and portable VMM routing

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-engine/src/lib.rs`
- Modify: `crates/carrick-runtime/src/page_profile.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-cli/tests/cli.rs`

**Interfaces:**

- `ExecutionBackend::{Vmm,NativeDarwin}` is the resolved internal execution
  model. Concrete VMM crate names stay in cfg-selected implementation code and
  diagnostics.
- `resolve_execution_plan_for_request_for_host(..., Native, AutoPage, ...)`
  selects native only on supported macOS/same-ISA hosts.
- `resolve_execution_plan_for_request_for_host(..., Vmm, ...)` retains the VMM
  Linux page geometry and never consults native page-profile heuristics.

- [ ] **Step 1: Add red CLI and planner tests**

In `crates/carrick-cli/tests/cli.rs`, parse `run-elf` only far enough to exercise
clap and assert:

- `--help` says `possible values: native, vmm`;
- `--exec-backend auto` exits 2 and contains `omit --exec-backend`;
- `CARRICK_EXEC_BACKEND=hvf` exits 2 and contains `--exec-backend vmm`.

In `page_profile.rs`, replace the HVF-named tests with:

- `Vmm + AutoPage -> ExecutionBackend::Vmm`;
- `Vmm + native16k -> actionable native-page-profile error`;
- omitted/default request is `Native` and resolves native on a modeled
  macOS/AArch64 16K host;
- default native on modeled Linux and cross-ISA hosts is a typed unsupported
  result mentioning explicit `--exec-backend vmm`.

Run and confirm RED:

```sh
cargo test -p carrick-cli --test cli exec_backend -- --nocapture
cargo test -p carrick-runtime page_profile --lib -- --nocapture
```

- [ ] **Step 2: Replace every request default**

Change all clap `default_value_t`, `CliRunRequest` fixtures, command-created
requests, `RunSpec` fixtures, and execution tests from `Auto` to `Native`.
Rename public-request matches from `Hvf` to `Vmm`; rename the resolved internal
`ExecutionBackend::Hvf` to `ExecutionBackend::Vmm` so runtime policy is not tied
to macOS.

Use this audit after editing:

```sh
rg -n 'ExecBackendRequest::(Auto|Hvf)|ExecutionBackend::Hvf|"hvf"\.to_owned\(\)' crates --glob '*.rs'
```

The only allowed `Hvf` results are concrete implementation types, evidence
labels, and backend crate diagnostics; there must be no request variant or
public CLI argument left.

- [ ] **Step 3: Preserve typed no-fallback errors**

Update the native capability errors in `page_profile.rs` so unsupported host,
ISA, or page geometry says native execution is unavailable and suggests an
explicit `--exec-backend vmm`. Do not catch these errors in `runtime.rs` or
`execute.rs`; the caller receives the native error unchanged.

- [ ] **Step 4: Run focused compile and tests**

```sh
cargo test -p carrick-cli --test cli exec_backend -- --nocapture
cargo test -p carrick-engine --lib
cargo test -p carrick-runtime page_profile --lib -- --nocapture
cargo check -p carrick-cli
```

- [ ] **Step 5: Commit request propagation**

```sh
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/commands.rs \
  crates/carrick-cli/tests/cli.rs crates/carrick-engine/src/lib.rs \
  crates/carrick-runtime/src/page_profile.rs crates/carrick-runtime/src/runtime.rs \
  crates/carrick-runtime/src/execute.rs
git commit -m "feat(runtime): route portable vmm policy explicitly" -m "Default every execution request to Darwin-native DSR and resolve the portable VMM request through the compiled platform backend. Unsupported native plans fail without retrying under a VMM.\n\nVerified with CLI parser, engine, page-profile, and runtime compile gates.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Make persisted container policy immutable and incompatible values visible

**Files:**

- Modify: `crates/carrick-runtime/src/container.rs`
- Modify: `crates/carrick-cli/src/lifecycle.rs`

**Interfaces:**

- `RunConfig::default().exec_backend == Native`.
- `build_created_state` persists the exact create-time request.
- `rebuild_request_from_state`, `container start/restart`, and `container exec`
  copy the stored value without accepting an override.
- `ContainerState::load` wraps an explicit legacy backend parse failure with
  the state path/id and `recreate the container with --exec-backend vmm`.

- [ ] **Step 1: Add red registry tests**

Extend `run_config_round_trips_and_defaults_when_missing`:

- a state with no `config` defaults to `Native`;
- a config with no `exec_backend` defaults to `Native`;
- explicit `"exec_backend":"native"` and `"vmm"` round-trip;
- explicit `"auto"` and `"hvf"` fail and retain migration guidance.

Add lifecycle tests proving `build_created_state` and
`rebuild_request_from_state` preserve `Vmm` exactly. The existing exec request
test should assert it receives the same stored value; there is no exec-specific
backend parameter to override it.

Run and confirm RED:

```sh
cargo test -p carrick-runtime container::tests::run_config --lib -- --nocapture
cargo test -p carrick-cli lifecycle --lib -- --nocapture
```

- [ ] **Step 2: Implement native defaults and contextual load errors**

Change `RunConfig::default`. Keep `#[serde(default)]` on the field so absent
legacy fields become native. Do not add a serde fallback for known legacy
strings.

In `ContainerState::load`, retain `InvalidData` but prepend the state path/id
and an operator action. This distinguishes incompatible state from a missing
container and avoids a raw serde-only message at the CLI.

- [ ] **Step 3: Audit lifecycle immutability**

```sh
rg -n 'exec_backend:' crates/carrick-cli/src/lifecycle.rs crates/carrick-runtime/src/container.rs
```

Every relaunch/exec assignment must be either the original request at create
or `state.config.exec_backend`. No branch may resolve, upgrade, or replace it.

- [ ] **Step 4: Run focused tests and commit**

```sh
cargo test -p carrick-runtime container --lib -- --nocapture
cargo test -p carrick-cli lifecycle --lib -- --nocapture
```

```sh
git add crates/carrick-runtime/src/container.rs crates/carrick-cli/src/lifecycle.rs
git commit -m "feat(runtime): persist immutable container backend policy" -m "Make absent container policy native while rejecting explicitly persisted auto/HVF values as incompatible state. Start, restart, and exec continue to copy the create-time backend unchanged.\n\nVerified with registry compatibility and lifecycle reconstruction tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Make VMM conformance and performance lanes explicit

**Files:**

- Modify: `crates/carrick-conformance/src/lane.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `crates/carrick-cli/tests/perf_support/backend_pair.rs`
- Modify: `crates/carrick-cli/tests/perf_support/invoke.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`

**Interfaces:**

- `Lane::Hvf`, Lima KVM, KVM-local, bhyve-local, and NVMM-local all insert
  `--exec-backend vmm` before the image argument.
- Internal evidence row labels may continue to say `Hvf` when they identify the
  measured macOS implementation. Only invocation vocabulary changes.
- Backend pair schedule remains Native/HVF/HVF/Native; HVF legs pass `vmm`.

- [ ] **Step 1: Add red argv tests**

For each VMM lane assert the full argv has exactly one adjacent
`["--exec-backend", "vmm"]` pair before the image. Assert the native DSR lane
has `native` and not `vmm`. Change perf invocation tests to expect `vmm` while
leaving `CarrickBackend::Hvf` evidence identity intact.

Run and confirm RED:

```sh
cargo test -p carrick-conformance lane -- --nocapture
cargo test -p carrick-cli --test perf_runner backend -- --nocapture
```

- [ ] **Step 2: Implement one VMM argv inserter**

Add `carrick_argv_with_exec_backend(argv, image, "vmm")` (or an equivalent
typed helper) and call it before platform rewriting/wrapping. Do not special
case concrete backend names. Update legacy conformance harness invocations that
intentionally exercise HVF to pass `vmm`.

- [ ] **Step 3: Run focused gates and commit**

```sh
cargo test -p carrick-conformance --lib
cargo test -p carrick-cli --test perf_runner backend -- --nocapture
cargo test -p carrick-cli --test conformance lane_allowed_for_backend -- --nocapture
```

```sh
git add crates/carrick-conformance/src/lane.rs \
  crates/carrick-cli/tests/conformance.rs \
  crates/carrick-cli/tests/perf_support/backend_pair.rs \
  crates/carrick-cli/tests/perf_support/invoke.rs \
  crates/carrick-cli/tests/perf_runner.rs
git commit -m "test(conformance): request vmm lanes explicitly" -m "Keep HVF, KVM, bhyve, and NVMM evidence lanes on their intended execution model after native becomes the CLI default. Internal implementation labels remain concrete while argv uses portable VMM policy.\n\nVerified with conformance-lane and backend-pair argv tests.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

---

### Task 5: Update current documentation and prove both macOS paths live

**Files:**

- Modify: `README.md`
- Modify: `docs/conformance-testing.md`
- Modify if needed after audit: `docs/architecture-overview.md`

- [ ] **Step 1: Update current policy text**

In `README.md`, make native DSR the ordinary macOS same-ISA path, state its
experimental/trusted-code limitations honestly, and show HVF compatibility as:

```sh
target/release/carrick run --exec-backend vmm ubuntu:24.04 /bin/echo hi
```

Do not rewrite dated campaign/evidence documents that accurately record HVF as
the default at their measurement date. Update `docs/conformance-testing.md` to
say the default *lane* is macOS/HVF and that the harness passes explicit `vmm`;
this is distinct from the user CLI default.

- [ ] **Step 2: Run static policy audits**

```sh
rg -n -- '--exec-backend (auto|hvf)|CARRICK_EXEC_BACKEND=(auto|hvf)' \
  README.md docs crates scripts justfile \
  --glob '!docs/archive/**' --glob '!docs/superpowers/specs/**' \
  --glob '!docs/superpowers/plans/**'
rg -n 'ExecBackendRequest::(Auto|Hvf)' crates --glob '*.rs'
```

Classify dated evidence hits rather than mechanically changing them. Active
source and current user docs must have none.

- [ ] **Step 3: Build, sign, and live-verify macOS delivery**

```sh
just build
codesign -d --entitlements :- target/release/carrick 2>&1 | \
  grep com.apple.security.hypervisor
target/release/carrick run --rm ubuntu:24.04 /bin/echo native-default-ok
target/release/carrick run --rm --exec-backend vmm ubuntu:24.04 /bin/echo vmm-explicit-ok
```

Expected: both print their marker and exit zero; the first invocation contains
no VMM selection and must not consume an HVF VM.

Also prove a native gap does not fall back by running one known unsupported
native fixture (or a purpose-built planner test) and checking the typed error
plus absence of an HVF VM-create probe/event.

- [ ] **Step 4: Run final gates**

```sh
just fmt-check
just clippy
just lint-domains
just ci
```

- [ ] **Step 5: Commit docs and any final test-only adjustments**

```sh
git add README.md docs/conformance-testing.md docs/architecture-overview.md
git commit -m "docs: make native-default execution explicit" -m "Document native DSR as the omitted macOS execution policy and VMM execution as an explicit portable compatibility choice. Keep the macOS/HVF conformance lane clearly distinguished from the user-facing default.\n\nVerified with signed native-default and explicit-VMM echo workloads plus the full local CI gate.\n\nCo-Authored-By: Codex <codex@openai.com>"
```

## Completion evidence

Record the exact commands and outcomes in the implementation handoff. Do not
claim completion unless:

- `carrick run` without a backend reaches native DSR on macOS;
- `carrick run --exec-backend vmm` reaches HVF;
- `auto` and `hvf` fail at CLI, environment, and persisted-state boundaries;
- lifecycle tests prove create/start/restart/exec retain one backend;
- every VMM conformance lane is explicit;
- native failure shows no VM fallback;
- focused tests, `just ci`, and both signed live markers pass.
