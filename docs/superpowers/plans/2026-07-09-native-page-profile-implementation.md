# Native Page Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the request, selection, geometry, and first mixed-page enforcement slice for Darwin native `native16k` and `linux4k-on-16k` page profiles.

**Architecture:** CLI and engine carry policy requests in `RunSpec`; runtime selects a page geometry only when the native backend is requested; memory and auxv construction consume one selected geometry. The first enforcement slice does not build the complete native engine. It proves the policy, geometry threading, uniform fast path, mixed-page classification, and unsupported-case diagnostics needed before native execution can consume it.

**Tech Stack:** Rust 1.96.0, edition 2024, `serde`, `clap::ValueEnum`, Carrick workspace crates `carrick-spec`, `carrick-engine`, `carrick-cli`, `carrick-runtime`, `carrick-mem`, and the existing `bench-native` feasibility probe crate.

## Global Constraints

- The native lane is trusted-code-only and experimental.
- `native16k`: Linux-visible page size equals the host-native Darwin page size.
- `linux4k-on-16k`: Linux-visible page size is exactly 4096 while Darwin host mappings remain 16 KiB.
- Preserve exact Linux 4K behavior for containers that need it without routing that decision to HVF.
- Do not silently expose 16K semantics to a 4K-shaped container.
- Keep HVF available as an explicitly selected backend, but keep native page-profile selection inside the native backend.
- Metadata-only subpage tracking is not enough for exact 4K behavior on a 16K host.
- Uniform 16K-compatible pages must stay on the direct host mapping fast path.
- Mixed pages must use a measured slow path or fail with a typed diagnostic.
- Existing macOS default behavior must stay HVF until the native backend has its own gates.
- Do not run untrusted code in native mode.
- Do not support cross-ISA execution in this slice.

---

## File Structure

- Modify `crates/carrick-spec/src/lib.rs`: add serializable request and selected page-profile vocabulary.
- Modify `crates/carrick-engine/src/lib.rs`: add `CliRunRequest` fields and copy them into `RunSpec`.
- Modify `crates/carrick-cli/src/args.rs`: expose `--exec-backend` and `--native-page-profile` on `run` and `create`.
- Modify `crates/carrick-cli/src/commands.rs`: pass the new CLI fields into `CliRunRequest`.
- Modify `crates/carrick-runtime/src/container.rs`: persist backend and page-profile requests in `RunConfig`.
- Modify `crates/carrick-cli/src/lifecycle.rs`: preserve backend and page-profile requests across `start`, `restart`, and `exec`.
- Create `crates/carrick-runtime/src/page_profile.rs`: native execution plan selection, host page-size probing, page geometry, mixed-page state classification, and user-facing diagnostics.
- Modify `crates/carrick-runtime/src/lib.rs`: publish the new runtime module for runtime integration tests while keeping the crate internal to Carrick.
- Modify `crates/carrick-runtime/src/execute.rs`: resolve native execution/page-profile requests before backend launch and reject unsupported native runs with typed errors.
- Modify `crates/carrick-mem/src/memory.rs`: make auxv `AT_PAGESZ` and stack construction consume selected Linux page size.
- Modify `crates/carrick-runtime/src/exec_helpers.rs`, `crates/carrick-runtime/src/runtime.rs`, and `crates/carrick-runtime/src/vcpu_loop/mod.rs`: pass selected page geometry into all initial and `execve` image builders.
- Modify `crates/carrick-runtime/src/dispatch/mod.rs`: store `PageGeometry` on `SyscallDispatcher`.
- Modify `crates/carrick-runtime/src/dispatch/mem.rs`: use dispatcher page geometry for Linux page rounding/alignment and feed mapping transitions into mixed-page classification.
- Modify `crates/carrick-runtime/tests/integration/address_space.rs`: pin auxv page-size behavior for 4K and 16K profiles.
- Modify `crates/carrick-runtime/tests/integration/syscall_mem.rs`: pin mmap and mixed-page behavior under both page geometries.
- Modify `bench-native/src/native_exec_probe/mapping.rs`, `bench-native/src/native_exec_probe/mod.rs`, and `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`: add the Darwin subpage-protection probe and record the observed host behavior.

---

### Task 1: Policy Vocabulary, CLI, Engine, And Lifecycle Threading

**Files:**
- Modify: `crates/carrick-spec/src/lib.rs`
- Modify: `crates/carrick-engine/src/lib.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-runtime/src/container.rs`
- Modify: `crates/carrick-cli/src/lifecycle.rs`

**Interfaces:**
- Produces:
  - `carrick_spec::ExecBackendRequest`
  - `carrick_spec::NativePageProfileRequest`
  - `carrick_spec::NativePageProfile`
  - `carrick_spec::NativePageGeometry`
  - `RunSpec::exec_backend: ExecBackendRequest`
  - `RunSpec::native_page_profile: NativePageProfileRequest`
  - `CliRunRequest::exec_backend: ExecBackendRequest`
  - `CliRunRequest::native_page_profile: NativePageProfileRequest`
- Consumes: no earlier plan task.

- [ ] **Step 1: Add failing `carrick-spec` serialization tests**

Add these tests inside `crates/carrick-spec/src/lib.rs` under `#[cfg(test)] mod tests`:

```rust
#[test]
fn run_spec_defaults_execution_backend_and_native_page_profile() {
    let json = r#"{
        "executable": "/bin/sh",
        "argv": ["/bin/sh"],
        "envp": [],
        "cwd": "/",
        "rootfs_layers": [],
        "fs_backend": "Host",
        "mounts": [],
        "tty": false,
        "raw": true,
        "interactive": false,
        "max_traps": 100,
        "debug_state_path": null
    }"#;

    let spec: RunSpec = serde_json::from_str(json).expect("legacy spec should deserialize");
    assert_eq!(spec.exec_backend, ExecBackendRequest::Auto);
    assert_eq!(spec.native_page_profile, NativePageProfileRequest::Auto);
}

#[test]
fn page_profile_vocabulary_round_trips() {
    let geometry = NativePageGeometry {
        host_page_size: 16_384,
        linux_page_size: 4096,
        profile: NativePageProfile::Linux4kOn16k,
    };

    let encoded = serde_json::to_string(&geometry).expect("serialize geometry");
    assert_eq!(
        encoded,
        r#"{"host_page_size":16384,"linux_page_size":4096,"profile":"linux4k_on16k"}"#
    );
    let decoded: NativePageGeometry = serde_json::from_str(&encoded).expect("deserialize geometry");
    assert_eq!(decoded, geometry);
}
```

- [ ] **Step 2: Run the failing spec tests**

Run:

```sh
cargo test -p carrick-spec run_spec_defaults_execution_backend_and_native_page_profile --lib
cargo test -p carrick-spec page_profile_vocabulary_round_trips --lib
```

Expected before implementation: compile failure naming missing `ExecBackendRequest`, `NativePageProfileRequest`, `NativePageProfile`, `NativePageGeometry`, and missing `RunSpec` fields.

- [ ] **Step 3: Add the spec vocabulary and `RunSpec` fields**

Insert these definitions near the other request enums in `crates/carrick-spec/src/lib.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ExecBackendRequest {
    #[default]
    Auto,
    Hvf,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum NativePageProfileRequest {
    #[default]
    Auto,
    #[cfg_attr(feature = "clap", value(name = "native16k"))]
    Native16k,
    #[cfg_attr(feature = "clap", value(name = "linux4k"))]
    Linux4k,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePageProfile {
    Native16k,
    Linux4kOn16k,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePageGeometry {
    pub host_page_size: u64,
    pub linux_page_size: u64,
    pub profile: NativePageProfile,
}
```

Add these fields to `RunSpec` after `platform`:

```rust
    /// Execution backend requested by CLI/API policy. `Auto` preserves the
    /// platform default; explicit `Native` is experimental and trusted-code-only.
    #[serde(default)]
    pub exec_backend: ExecBackendRequest,
    /// Native-only page profile request. Ignored by explicitly non-native
    /// backends; explicit native profiles are validated by the runtime plan.
    #[serde(default)]
    pub native_page_profile: NativePageProfileRequest,
```

Update every struct literal that constructs `RunSpec` to include:

```rust
        exec_backend: carrick_spec::ExecBackendRequest::Auto,
        native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
```

Inside `crates/carrick-spec/src/lib.rs`, use unqualified names in local tests and struct literals.

- [ ] **Step 4: Add failing engine and lifecycle propagation tests**

In `crates/carrick-engine/src/lib.rs`, update `base_req` to include the new fields with `Auto`, then add:

```rust
#[test]
fn execution_backend_and_page_profile_flow_into_run_spec() {
    let mut req = base_req(None);
    req.exec_backend = carrick_spec::ExecBackendRequest::Native;
    req.native_page_profile = carrick_spec::NativePageProfileRequest::Linux4k;

    let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
    let spec = resolve_run_spec(req, image).expect("resolve run spec");

    assert_eq!(spec.exec_backend, carrick_spec::ExecBackendRequest::Native);
    assert_eq!(
        spec.native_page_profile,
        carrick_spec::NativePageProfileRequest::Linux4k
    );
}
```

In `crates/carrick-cli/src/lifecycle.rs`, extend `sample_state()` so its `RunConfig` contains:

```rust
                exec_backend: carrick_spec::ExecBackendRequest::Native,
                native_page_profile: carrick_spec::NativePageProfileRequest::Linux4k,
```

Then extend `rebuild_request_reproduces_run_inputs_split_not_merged` with:

```rust
        assert_eq!(req.exec_backend, carrick_spec::ExecBackendRequest::Native);
        assert_eq!(
            req.native_page_profile,
            carrick_spec::NativePageProfileRequest::Linux4k
        );
```

- [ ] **Step 5: Run the failing propagation tests**

Run:

```sh
cargo test -p carrick-engine execution_backend_and_page_profile_flow_into_run_spec --lib
cargo test -p carrick-cli rebuild_request_reproduces_run_inputs_split_not_merged
```

Expected before implementation: compile failures naming missing fields in `CliRunRequest`, `RunConfig`, and request builders.

- [ ] **Step 6: Thread policy through engine, CLI, and lifecycle**

Modify `CliRunRequest` in `crates/carrick-engine/src/lib.rs`:

```rust
    pub exec_backend: carrick_spec::ExecBackendRequest,
    pub native_page_profile: carrick_spec::NativePageProfileRequest,
```

Copy the fields into the `RunSpec` literal:

```rust
        exec_backend: req.exec_backend,
        native_page_profile: req.native_page_profile,
```

Import the new clap-backed spec types in `crates/carrick-cli/src/args.rs`:

```rust
use carrick_spec::{ExecBackendRequest, FsBackendKind, NativePageProfileRequest, PidMode};
```

Add these arguments to `Commands::Run` and `Commands::Create`:

```rust
        /// Execution backend policy. `native` is experimental and trusted-code-only.
        #[arg(long = "exec-backend", value_enum, default_value_t = ExecBackendRequest::Auto, env = "CARRICK_EXEC_BACKEND")]
        exec_backend: ExecBackendRequest,
        /// Page profile for the native execution backend.
        #[arg(long = "native-page-profile", value_enum, default_value_t = NativePageProfileRequest::Auto, env = "CARRICK_NATIVE_PAGE_PROFILE")]
        native_page_profile: NativePageProfileRequest,
```

In `crates/carrick-cli/src/commands.rs`, bind those fields in the `Run` and `Create` match arms and pass them into `CliRunRequest`:

```rust
                exec_backend,
                native_page_profile,
```

Add these fields to `RunConfig` in `crates/carrick-runtime/src/container.rs`:

```rust
    /// Execution backend request preserved across start/restart/exec.
    #[serde(default)]
    pub exec_backend: carrick_spec::ExecBackendRequest,
    /// Native page profile request preserved across start/restart/exec.
    #[serde(default)]
    pub native_page_profile: carrick_spec::NativePageProfileRequest,
```

Add the defaults:

```rust
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
```

In `crates/carrick-cli/src/lifecycle.rs`, persist both fields in `state_from_request`, restore both in `rebuild_request_from_state`, and pass both in the `exec` request:

```rust
            exec_backend: req.exec_backend,
            native_page_profile: req.native_page_profile,
```

```rust
        exec_backend: c.exec_backend,
        native_page_profile: c.native_page_profile,
```

```rust
        exec_backend: state.config.exec_backend,
        native_page_profile: state.config.native_page_profile,
```

- [ ] **Step 7: Verify and commit Task 1**

Run:

```sh
cargo test -p carrick-spec run_spec_defaults_execution_backend_and_native_page_profile --lib
cargo test -p carrick-spec page_profile_vocabulary_round_trips --lib
cargo test -p carrick-engine execution_backend_and_page_profile_flow_into_run_spec --lib
cargo test -p carrick-cli rebuild_request_reproduces_run_inputs_split_not_merged
```

Expected: all pass.

Commit:

```sh
git add crates/carrick-spec/src/lib.rs crates/carrick-engine/src/lib.rs crates/carrick-cli/src/args.rs crates/carrick-cli/src/commands.rs crates/carrick-runtime/src/container.rs crates/carrick-cli/src/lifecycle.rs
git commit -m "feat(native): thread page profile policy" -m "Carry explicit execution backend and native page-profile requests from the CLI through RunSpec and persisted container state. This adds policy vocabulary without changing the default HVF runtime path." -m "Verified with carrick-spec serialization tests, carrick-engine merge tests, and carrick-cli lifecycle reconstruction tests." -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 2: Runtime Execution Plan And Auxv Page Geometry

**Files:**
- Create: `crates/carrick-runtime/src/page_profile.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`
- Modify: `crates/carrick-mem/src/memory.rs`
- Modify: `crates/carrick-runtime/src/exec_helpers.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Test: `crates/carrick-runtime/tests/integration/address_space.rs`

**Interfaces:**
- Consumes:
  - `carrick_spec::ExecBackendRequest`
  - `carrick_spec::NativePageProfileRequest`
  - `carrick_spec::NativePageGeometry`
- Produces:
  - `crate::page_profile::ExecutionBackend`
  - `crate::page_profile::ExecutionPlan`
  - `crate::page_profile::PageGeometry`
  - `crate::page_profile::resolve_execution_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError>`
  - `AddressSpace::with_linux_initial_stack_page_size`
  - `AddressSpace::with_linux_initial_stack_execfn_page_size`

- [ ] **Step 1: Add failing page-profile plan tests**

Create `crates/carrick-runtime/src/page_profile.rs` with test scaffolding first:

```rust
use crate::runtime::RuntimeError;
use carrick_spec::{
    ExecBackendRequest, NativePageGeometry, NativePageProfile, NativePageProfileRequest, RunSpec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionBackend {
    Hvf,
    NativeDarwin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageGeometry {
    pub host_page_size: u64,
    pub linux_page_size: u64,
    pub native_profile: Option<NativePageProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

pub(crate) fn resolve_execution_plan(_spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError> {
    Err(RuntimeError::Unsupported("page-profile plan red-first stub".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    fn spec(exec_backend: ExecBackendRequest, page: NativePageProfileRequest) -> RunSpec {
        RunSpec {
            executable: "/bin/sh".to_string(),
            argv: vec!["/bin/sh".to_string()],
            envp: Vec::new(),
            cwd: Some(Utf8PathBuf::from("/")),
            rootfs_layers: Vec::new(),
            fs_backend: carrick_spec::FsBackendKind::Host,
            mounts: Vec::new(),
            tty: false,
            raw: true,
            interactive: false,
            max_traps: 100,
            debug_state_path: None,
            platform: carrick_spec::Platform::Aarch64,
            exec_backend,
            native_page_profile: page,
            pid: carrick_spec::PidMode::Private,
            hostname: None,
            network: carrick_spec::NetworkNamespaceSpec::default(),
            extra_hosts: Vec::new(),
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn hvf_request_ignores_native_page_geometry() {
        let plan = resolve_execution_plan(&spec(
            ExecBackendRequest::Hvf,
            NativePageProfileRequest::Auto,
        ))
        .expect("hvf plan");
        assert_eq!(plan.backend, ExecutionBackend::Hvf);
        assert_eq!(plan.page_geometry.linux_page_size, carrick_abi::LINUX_PAGE_SIZE);
        assert_eq!(plan.page_geometry.native_profile, None);
    }

    #[test]
    fn explicit_hvf_rejects_explicit_native_page_profile() {
        let err = resolve_execution_plan(&spec(
            ExecBackendRequest::Hvf,
            NativePageProfileRequest::Linux4k,
        ))
        .expect_err("explicit native page profile requires native backend");
        assert!(err.to_string().contains("native page profile requires --exec-backend=native"));
    }
}
```

Add the module in `crates/carrick-runtime/src/lib.rs`:

```rust
pub mod page_profile;
```

- [ ] **Step 2: Run the failing plan tests**

Run:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
```

Expected before implementation: `hvf_request_ignores_native_page_geometry` fails with `page-profile plan red-first stub`.

- [ ] **Step 3: Implement runtime plan selection**

Replace the stub in `crates/carrick-runtime/src/page_profile.rs` with:

```rust
pub(crate) const DEFAULT_LINUX_PAGE_SIZE: u64 = carrick_abi::LINUX_PAGE_SIZE;

pub(crate) fn resolve_execution_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError> {
    if spec.exec_backend != ExecBackendRequest::Native
        && spec.native_page_profile != NativePageProfileRequest::Auto
    {
        return Err(RuntimeError::Unsupported(
            "native page profile requires --exec-backend=native".to_string(),
        ));
    }

    match spec.exec_backend {
        ExecBackendRequest::Auto | ExecBackendRequest::Hvf => Ok(ExecutionPlan {
            backend: ExecutionBackend::Hvf,
            page_geometry: PageGeometry {
                host_page_size: DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
            diagnostics: Vec::new(),
        }),
        ExecBackendRequest::Native => native_plan(spec.native_page_profile),
    }
}

fn native_plan(request: NativePageProfileRequest) -> Result<ExecutionPlan, RuntimeError> {
    let host_page_size = host_page_size();
    let profile = match request {
        NativePageProfileRequest::Auto => {
            if host_page_size == 16_384 {
                NativePageProfile::Native16k
            } else if host_page_size == DEFAULT_LINUX_PAGE_SIZE {
                NativePageProfile::Linux4kOn16k
            } else {
                return Err(RuntimeError::Unsupported(format!(
                    "native execution unsupported on host page size {host_page_size}"
                )));
            }
        }
        NativePageProfileRequest::Native16k => {
            if host_page_size != 16_384 {
                return Err(RuntimeError::Unsupported(format!(
                    "native16k requires host page size 16384, got {host_page_size}"
                )));
            }
            NativePageProfile::Native16k
        }
        NativePageProfileRequest::Linux4k => NativePageProfile::Linux4kOn16k,
    };

    let linux_page_size = match profile {
        NativePageProfile::Native16k => host_page_size,
        NativePageProfile::Linux4kOn16k => DEFAULT_LINUX_PAGE_SIZE,
    };
    Ok(ExecutionPlan {
        backend: ExecutionBackend::NativeDarwin,
        page_geometry: PageGeometry {
            host_page_size,
            linux_page_size,
            native_profile: Some(profile),
        },
        diagnostics: vec![format!(
            "native page profile selected: profile={profile:?} host_page_size={host_page_size} linux_page_size={linux_page_size}"
        )],
    })
}

fn host_page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        DEFAULT_LINUX_PAGE_SIZE
    }
}

impl From<PageGeometry> for NativePageGeometry {
    fn from(value: PageGeometry) -> Self {
        let profile = value
            .native_profile
            .unwrap_or(NativePageProfile::Linux4kOn16k);
        Self {
            host_page_size: value.host_page_size,
            linux_page_size: value.linux_page_size,
            profile,
        }
    }
}
```

In `Runtime::execute` in `crates/carrick-runtime/src/execute.rs`, call the resolver before filesystem setup:

```rust
        let execution_plan = crate::page_profile::resolve_execution_plan(spec)?;
        if execution_plan.backend == crate::page_profile::ExecutionBackend::NativeDarwin {
            return Err(RuntimeError::Unsupported(
                "native Darwin execution backend is gated off; page-profile selection is wired for the native backend only".to_string(),
            ));
        }
```

- [ ] **Step 4: Add failing auxv page-size tests**

In `crates/carrick-runtime/tests/integration/address_space.rs`, add:

```rust
#[test]
fn loaded_elf_initial_stack_can_report_16k_pages() {
    build_fixture();
    let artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello";
    let image = AddressSpace::load_elf(artifact)
        .unwrap()
        .with_linux_initial_stack_page_size(
            [artifact.to_owned()],
            std::iter::empty::<String>(),
            16_384,
        )
        .unwrap();
    let sp = image.initial_stack_pointer().unwrap();
    let auxv = read_auxv(&image, sp + 32);

    assert!(auxv.contains(&(LINUX_AT_PAGESZ, 16_384)));
}
```

- [ ] **Step 5: Run the failing auxv test**

Run:

```sh
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_can_report_16k_pages
```

Expected before implementation: compile failure naming missing `with_linux_initial_stack_page_size`.

- [ ] **Step 6: Add page-size-aware auxv construction**

In `crates/carrick-mem/src/memory.rs`, add page-size-aware variants next to the existing stack builders:

```rust
    pub fn with_linux_initial_stack_page_size<A, E>(
        mut self,
        argv: A,
        env: E,
        linux_page_size: u64,
    ) -> Result<Self, AddressSpaceError>
    where
        A: IntoIterator,
        A::Item: AsRef<[u8]>,
        E: IntoIterator,
        E::Item: AsRef<[u8]>,
    {
        self.set_linux_auxv_page_size(linux_page_size);
        self.with_linux_initial_stack(argv, env)
    }

    pub fn with_linux_initial_stack_execfn_page_size<A, E>(
        mut self,
        argv: A,
        env: E,
        execfn: &[u8],
        linux_page_size: u64,
    ) -> Result<Self, AddressSpaceError>
    where
        A: IntoIterator,
        A::Item: AsRef<[u8]>,
        E: IntoIterator,
        E::Item: AsRef<[u8]>,
    {
        self.set_linux_auxv_page_size(linux_page_size);
        self.with_linux_initial_stack_execfn(argv, env, execfn)
    }

    fn set_linux_auxv_page_size(&mut self, linux_page_size: u64) {
        for entry in &mut self.linux_auxv {
            if entry.a_type == LINUX_AT_PAGESZ {
                *entry = LinuxAuxvEntry::new(LINUX_AT_PAGESZ, linux_page_size);
                self.linux_auxv_image.clear();
                return;
            }
        }
        self.linux_auxv
            .push(LinuxAuxvEntry::new(LINUX_AT_PAGESZ, linux_page_size));
        self.linux_auxv_image.clear();
    }
```

Keep existing `with_linux_initial_stack` behavior unchanged at 4096 by leaving `linux_auxv_from_load_plan` as the default source.

- [ ] **Step 7: Thread page geometry into initial image builders**

Change `build_run_image_for` and `build_run_image_for_execfn` in `crates/carrick-runtime/src/exec_helpers.rs` to take `linux_page_size: u64` and call the new page-size-aware stack builders.

Use this call shape:

```rust
    image.with_linux_initial_stack_page_size(argv, env.iter().map(|s| s.as_bytes()), linux_page_size)
```

and:

```rust
    image.with_linux_initial_stack_execfn_page_size(
        argv,
        env.iter().map(|s| s.as_bytes()),
        execfn,
        linux_page_size,
    )
```

At current callers, pass `crate::page_profile::DEFAULT_LINUX_PAGE_SIZE`. In the native backend caller created in a later task, pass `execution_plan.page_geometry.linux_page_size`.

Update the macOS `execve` builder in `crates/carrick-runtime/src/runtime/exec.rs` and the platform loop in `crates/carrick-runtime/src/vcpu_loop/mod.rs` to use `DEFAULT_LINUX_PAGE_SIZE` until the dispatcher exposes selected geometry to execve in Task 3.

- [ ] **Step 8: Verify and commit Task 2**

Run:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_includes_linux_auxv
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_can_report_16k_pages
```

Expected: all pass.

Commit:

```sh
git add crates/carrick-runtime/src/page_profile.rs crates/carrick-runtime/src/lib.rs crates/carrick-runtime/src/execute.rs crates/carrick-mem/src/memory.rs crates/carrick-runtime/src/exec_helpers.rs crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/vcpu_loop/mod.rs crates/carrick-runtime/tests/integration/address_space.rs
git commit -m "feat(native): select page geometry for native runs" -m "Add runtime execution-plan selection for explicit native page profiles and make ELF auxv construction accept the selected Linux page size. The default HVF path still reports the existing 4K Linux page size." -m "Verified with runtime page-profile selection tests and auxv page-size integration tests." -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 3: Geometry-Aware Memory Dispatch And First Mixed-Page Model

**Files:**
- Modify: `crates/carrick-runtime/src/page_profile.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs`
- Modify: `crates/carrick-runtime/src/runtime/exec.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Test: `crates/carrick-runtime/tests/integration/syscall_mem.rs`

**Interfaces:**
- Consumes:
  - `crate::page_profile::PageGeometry`
  - `crate::page_profile::DEFAULT_LINUX_PAGE_SIZE`
- Produces:
  - `SyscallDispatcher::with_page_geometry(page_geometry: PageGeometry) -> Self`
  - `SyscallDispatcher::page_geometry(&self) -> PageGeometry`
  - `SyscallDispatcher::linux_page_size(&self) -> u64`
  - `crate::page_profile::HostPageState`
  - `crate::page_profile::MixedPageReason`
  - `crate::page_profile::classify_host_page_state`

- [ ] **Step 1: Add failing mixed-page classifier tests**

Append this to `crates/carrick-runtime/src/page_profile.rs` tests:

```rust
#[test]
fn classifies_uniform_16k_page_as_fast_path() {
    let state = classify_host_page_state(
        PageGeometry {
            host_page_size: 16_384,
            linux_page_size: 4096,
            native_profile: Some(NativePageProfile::Linux4kOn16k),
        },
        [
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
        ],
    );
    assert_eq!(state, HostPageState::Uniform16k);
}

#[test]
fn classifies_non_executable_mixed_permissions_as_guarded() {
    let state = classify_host_page_state(
        PageGeometry {
            host_page_size: 16_384,
            linux_page_size: 4096,
            native_profile: Some(NativePageProfile::Linux4kOn16k),
        },
        [
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
        ],
    );
    assert_eq!(state, HostPageState::MixedGuarded(MixedPageReason::Permissions));
}

#[test]
fn rejects_executable_mixed_page_without_instruction_instrumentation() {
    let state = classify_host_page_state(
        PageGeometry {
            host_page_size: 16_384,
            linux_page_size: 4096,
            native_profile: Some(NativePageProfile::Linux4kOn16k),
        },
        [
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
            SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
        ],
    );
    assert_eq!(
        state,
        HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage)
    );
}
```

- [ ] **Step 2: Run the failing classifier tests**

Run:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
```

Expected before implementation: compile failure naming missing classifier types and functions.

- [ ] **Step 3: Implement the first mixed-page classifier**

Add this to `crates/carrick-runtime/src/page_profile.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostPageState {
    Uniform16k,
    Composed16k,
    MixedGuarded(MixedPageReason),
    Unsupported(MixedPageReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MixedPageReason {
    Permissions,
    Backing,
    ExecutableMixedPage,
    UnsupportedGeometry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageBacking {
    Anonymous,
    PrivateFile,
    SharedFile,
    Unmapped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PagePerms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl PagePerms {
    pub(crate) const fn none() -> Self {
        Self {
            read: false,
            write: false,
            exec: false,
        }
    }

    pub(crate) const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
        }
    }

    pub(crate) const fn read_exec() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubpageState {
    pub backing: PageBacking,
    pub perms: PagePerms,
}

impl SubpageState {
    pub(crate) const fn new(backing: PageBacking, perms: PagePerms) -> Self {
        Self { backing, perms }
    }
}

pub(crate) fn classify_host_page_state<const N: usize>(
    geometry: PageGeometry,
    subpages: [SubpageState; N],
) -> HostPageState {
    if geometry.host_page_size == geometry.linux_page_size {
        return HostPageState::Uniform16k;
    }
    if geometry.host_page_size != 16_384 || geometry.linux_page_size != 4096 || N != 4 {
        return HostPageState::Unsupported(MixedPageReason::UnsupportedGeometry);
    }

    let first = subpages[0];
    if subpages.iter().all(|state| *state == first) {
        return HostPageState::Uniform16k;
    }
    if subpages.iter().any(|state| state.perms.exec) {
        return HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage);
    }
    if subpages.iter().any(|state| state.backing != first.backing) {
        return HostPageState::Composed16k;
    }
    HostPageState::MixedGuarded(MixedPageReason::Permissions)
}
```

- [ ] **Step 4: Add failing dispatcher geometry tests**

In `crates/carrick-runtime/tests/integration/syscall_mem.rs`, add:

```rust
#[test]
fn dispatcher_mmap_uses_configured_16k_linux_page_size() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), Vec::new(), LINUX_MMAP_SIZE)],
    )
    .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_page_geometry(
        carrick_runtime::page_profile::PageGeometry {
            host_page_size: 16_384,
            linux_page_size: 16_384,
            native_profile: Some(carrick_spec::NativePageProfile::Native16k),
        },
    );
    let map_private_anonymous = 0x02 | 0x20;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([0, 1, 0, map_private_anonymous, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([0, 1, 0, map_private_anonymous, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: (LINUX_MMAP_BASE + 16_384) as i64
        }
    );
}
```

- [ ] **Step 5: Run the failing dispatcher geometry test**

Run:

```sh
cargo test -p carrick-runtime --test integration dispatcher_mmap_uses_configured_16k_linux_page_size
```

Expected before implementation: compile failure naming missing `SyscallDispatcher::with_page_geometry`.

- [ ] **Step 6: Store page geometry in the dispatcher**

In `crates/carrick-runtime/src/dispatch/mod.rs`, add a field to `SyscallDispatcher`:

```rust
    page_geometry: crate::page_profile::PageGeometry,
```

Initialize it in every constructor:

```rust
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
```

Add methods:

```rust
    pub fn with_page_geometry(page_geometry: crate::page_profile::PageGeometry) -> Self {
        let mut dispatcher = Self::new();
        dispatcher.page_geometry = page_geometry;
        dispatcher
    }

    pub(crate) fn set_page_geometry(&mut self, page_geometry: crate::page_profile::PageGeometry) {
        self.page_geometry = page_geometry;
    }

    pub(crate) fn page_geometry(&self) -> crate::page_profile::PageGeometry {
        self.page_geometry
    }

    pub(crate) fn linux_page_size(&self) -> u64 {
        self.page_geometry.linux_page_size
    }
```

When runtime builds a dispatcher for a selected execution plan, call `dispatcher.set_page_geometry(execution_plan.page_geometry)`.

- [ ] **Step 7: Replace memory-dispatch page-size assumptions with geometry**

In `crates/carrick-runtime/src/dispatch/mem.rs`, add local helpers:

```rust
fn page_floor(value: u64, page_size: u64) -> u64 {
    value & !(page_size - 1)
}

fn page_ceil(value: u64, page_size: u64) -> Option<u64> {
    value
        .checked_add(page_size - 1)
        .map(|end| end & !(page_size - 1))
}
```

For helpers that currently use `LINUX_PAGE_SIZE` outside a `SyscallDispatcher` method, add a `page_size: u64` parameter. For methods on `SyscallDispatcher`, replace the constant with:

```rust
let page_size = this.linux_page_size();
```

The first pass must cover these behaviors:

- `mmap` length rounding and fixed-address validation
- `mprotect` address validation and length rounding
- `munmap` address validation and length rounding
- `mremap` old/new size rounding
- `mincore` page iteration and vector length
- `mlock`/`munlock` tracked ranges
- growdown fault page rounding
- `/proc/self/maps` dynamic mapping bounds already recorded by the memory dispatcher

Keep non-memory subsystems that intentionally model Linux ABI constants unchanged in this task.

- [ ] **Step 8: Wire execve image rebuild to dispatcher geometry**

In `crates/carrick-runtime/src/runtime/exec.rs`, use:

```rust
let linux_page_size = dispatcher.linux_page_size();
```

Then call:

```rust
.and_then(|a| a.with_linux_initial_stack_execfn_page_size(argv, env, path.as_bytes(), linux_page_size))
```

In `crates/carrick-runtime/src/vcpu_loop/mod.rs`, use the same dispatcher method in each `execve` image rebuild arm and call `with_linux_initial_stack_page_size`.

- [ ] **Step 9: Verify and commit Task 3**

Run:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
cargo test -p carrick-runtime --test integration dispatcher_mmap_uses_configured_16k_linux_page_size
cargo test -p carrick-runtime --test integration mmap_without_hint_uses_next_page_granular_address
```

Expected: all pass, including the existing 4K mmap test.

Commit:

```sh
git add crates/carrick-runtime/src/page_profile.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/dispatch/mem.rs crates/carrick-runtime/src/runtime/exec.rs crates/carrick-runtime/src/vcpu_loop/mod.rs crates/carrick-runtime/tests/integration/syscall_mem.rs
git commit -m "feat(runtime): honor selected page geometry" -m "Thread selected page geometry into the dispatcher and memory syscalls, and add the first mixed-page classifier for linux4k-on-16k. Uniform pages remain the fast path while executable mixed pages produce a typed unsupported state." -m "Verified with mixed-page classifier tests, a 16K mmap geometry test, and the existing 4K mmap geometry test." -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

### Task 4: Native Probe Gate For Darwin Subpage Protection

**Files:**
- Modify: `bench-native/src/native_exec_probe/mapping.rs`
- Modify: `bench-native/src/native_exec_probe/mod.rs`
- Modify: `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`

**Interfaces:**
- Consumes:
  - Existing `ProbeReport`
  - Existing `Status`
  - Existing `errno()`
- Produces:
  - `native_exec_probe subpage-protect`
  - `native_exec_probe all` includes `subpage-protect`

- [ ] **Step 1: Add failing probe command routing**

In `bench-native/src/native_exec_probe/mod.rs`, add the new command before implementing it:

```rust
use mapping::{fixed_map_child, page_size, subpage_protect};
```

Add to the `match`:

```rust
        "subpage-protect" => print_one(subpage_protect()?),
```

Add to `run_all()`:

```rust
        subpage_protect()?,
```

Update `usage()`:

```rust
"usage: native_exec_probe page-size|fixed-map|subpage-protect|execmem|brk-trap|branch-gateway|fault-discriminator|all".to_string()
```

- [ ] **Step 2: Run the failing probe build**

Run:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- subpage-protect
```

Expected before implementation: compile failure naming missing `subpage_protect`.

- [ ] **Step 3: Implement `subpage_protect`**

Add this implementation to `bench-native/src/native_exec_probe/mapping.rs`:

```rust
pub fn subpage_protect() -> Result<ProbeReport, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail)
            .field("sysconf", page_size)
            .field("errno", errno()));
    }
    let page_size = page_size as usize;
    let len = page_size;
    if len < 16_384 {
        return Ok(ProbeReport::new("subpage-protect", Status::Pass)
            .field("host_page_size", page_size)
            .field("host_supports_4k_pages", page_size == 4096)
            .field("result", "host_page_smaller_than_16k"));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail).field("fork_errno", errno()));
    }
    if pid == 0 {
        child_subpage_protect(len);
    }

    let mut status_word = 0;
    let wait = unsafe { libc::waitpid(pid, &mut status_word, 0) };
    if wait != pid {
        return Ok(ProbeReport::new("subpage-protect", Status::Fail)
            .field("waitpid", wait)
            .field("errno", errno()));
    }

    let code = if libc::WIFEXITED(status_word) {
        libc::WEXITSTATUS(status_word)
    } else {
        128
    };
    let status = match code {
        0 | 94 | 95 => Status::Pass,
        _ => Status::Fail,
    };
    Ok(ProbeReport::new("subpage-protect", status)
        .field("host_page_size", page_size)
        .field("child_exit", code)
        .field("meaning", subpage_exit_meaning(code)))
}

fn child_subpage_protect(len: usize) -> ! {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            libc::_exit(92);
        }
        std::ptr::write_volatile(ptr.cast::<u8>(), 1);
        std::ptr::write_volatile(ptr.cast::<u8>().add(4096), 2);
        if libc::mprotect(ptr.cast::<u8>().add(4096).cast(), 4096, libc::PROT_NONE) != 0 {
            libc::munmap(ptr, len);
            libc::_exit(93);
        }

        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = subpage_fault_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(96);
        }
        if libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut()) != 0 {
            libc::_exit(97);
        }

        let _neighbor = std::ptr::read_volatile(ptr.cast::<u8>());
        let _target = std::ptr::read_volatile(ptr.cast::<u8>().add(4096));
        libc::munmap(ptr, len);
        libc::_exit(95);
    }
}

extern "C" fn subpage_fault_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _uap: *mut libc::c_void,
) {
    unsafe {
        libc::_exit(94);
    }
}

fn subpage_exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "exact_4k_subpage_protection",
        92 => "mmap_failed",
        93 => "mprotect_rejected_subpage_range",
        94 => "neighbor_or_target_faulted_after_subpage_mprotect",
        95 => "target_subpage_access_succeeded",
        96 => "sigsegv_handler_install_failed",
        97 => "sigbus_handler_install_failed",
        _ => "unexpected_child_status",
    }
}
```

The code treats `95` as a pass for the probe process because it is an observation, not a runtime success criterion. The interpretation is load-bearing: `target_subpage_access_succeeded` means metadata-only 4K tracking would be unsound; `neighbor_or_target_faulted_after_subpage_mprotect` means Darwin applied protection at host granularity and exact Linux4K needs guarded mixed-page handling.

- [ ] **Step 4: Run the probe and update evidence**

Run:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- subpage-protect
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

Expected on current Apple Silicon 16K hosts: `subpage-protect` prints one line with `host_page_size=16384` and a `meaning` field. `all` still exits nonzero because `page-size` remains a failed feasibility gate for plain 4K Linux semantics.

Append the new probe line and interpretation to `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`. Use the actual observed line from the run.

- [ ] **Step 5: Verify and commit Task 4**

Run:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- subpage-protect
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

Expected: `subpage-protect` runs and `all` reports every probe line including `subpage-protect`.

Commit:

```sh
git add bench-native/src/native_exec_probe/mapping.rs bench-native/src/native_exec_probe/mod.rs docs/2026-07-09-no-vmm-native-feasibility-evidence.md
git commit -m "diagnostics(native): probe darwin subpage protection" -m "Add a native feasibility probe for 4K subpage protection on 16K Darwin pages. The probe records whether a 4K mprotect range silently widens, over-protects the host page, or gets exact 4K behavior." -m "Verified with native_exec_probe subpage-protect and native_exec_probe all." -m "Co-Authored-By: Codex <codex@openai.com>"
```

---

## Final Verification

Run after all tasks:

```sh
just fmt-check
cargo test -p carrick-spec --lib
cargo test -p carrick-engine execution_backend_and_page_profile_flow_into_run_spec --lib
cargo test -p carrick-cli rebuild_request_reproduces_run_inputs_split_not_merged
cargo test -p carrick-runtime page_profile::tests --lib
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_includes_linux_auxv
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_can_report_16k_pages
cargo test -p carrick-runtime --test integration dispatcher_mmap_uses_configured_16k_linux_page_size
cargo test -p carrick-runtime --test integration mmap_without_hint_uses_next_page_granular_address
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

Expected:

- Formatting passes.
- All unit and integration tests pass.
- `native_exec_probe all` prints the full probe set including `subpage-protect`.
- `native_exec_probe all` may exit nonzero on a 16K host while `page-size` remains the deliberate feasibility failure for plain 4K native execution.

Run the full local gate before pushing:

```sh
just ci
```

Expected: pass. If `just ci` fails outside the touched files, triage with the existing Carrick regression attribution rules before changing unrelated code.

---

## Self-Review

- Spec coverage: Tasks 1 and 2 implement explicit backend/page-profile requests and selected page geometry. Task 3 implements the uniform fast path model, geometry-aware memory dispatch, and the first mixed-page classifier. Task 4 adds the required Darwin subpage probe and updates evidence.
- Correctness boundary: No task routes native `linux4k` to HVF. Explicit native profiles either select native geometry or fail with typed diagnostics.
- Robustness boundary: Existing HVF default behavior remains unchanged unless the user explicitly selects native policy.
- Performance boundary: The fast path remains uniform host-page mapping. The only mixed-page work in this slice is classification and targeted metadata, not a global memory-access tax.
