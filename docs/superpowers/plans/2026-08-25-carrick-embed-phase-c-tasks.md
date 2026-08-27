# carrick-embed Plan — Phase C — RunRequest, prepare.rs, carrick-embed v1

> Part of [`2026-08-25-carrick-embed-phase-a-c-plan.md`](2026-08-25-carrick-embed-phase-a-c-plan.md); read that index and the spec first. Line numbers verified at `39426141`; quoted existing text is the authority.


<!-- cluster C1-engine-runrequest -->
## Cluster C1-engine-runrequest

### Task 24: `RunSpec.raw`/`RunSpec.interactive` → typed `StdioMode`

> Line numbers below are for HEAD `ea0dac4c` (the files this task touches are byte-identical at `3dc6cc72`; only `crates/carrick-runtime/src/dispatch/mod.rs` differs, and both numberings are given where it is cited).

**Files:**
- Modify: `crates/carrick-spec/src/lib.rs` (insert `StdioMode` after `NetworkMode` at :318-326; RunSpec doc :809; RunSpec fields :828-829; legacy-JSON tests :961-981 and :1091-1110)
- Modify: `crates/carrick-engine/src/lib.rs:84-88` (re-export), `:449-450` (RunSpec literal)
- Modify: `crates/carrick-runtime/src/execute.rs:15` (import), `:369-376` and `:461-468` (call sites incl. their comment line), `:721-735` (`setup_interactive_stdio`), `:745-747` and `:768-769` (test import + literal)
- Modify: `crates/carrick-runtime/src/page_profile.rs:120-121`
- Modify: `crates/carrick-runtime/src/bin/carrick-nvmm.rs:74-75`, `crates/carrick-runtime/src/bin/carrick-kvm.rs:71-72` (cross-platform bins; `required-features` gate them off macOS — see the note in Step 5)
- Test: `crates/carrick-spec/src/lib.rs` (`mod tests`), `crates/carrick-runtime/src/execute.rs` (new `mod stdio_mode_tests`)

**Interfaces:**
- Consumes: `SyscallDispatcher::set_stream_stdio(&self, bool)` / `stream_stdio_enabled(&self) -> bool` (`crates/carrick-runtime/src/dispatch/mod.rs:5395,5409` at `ea0dac4c`; `:5346,5360` at `3dc6cc72`); `SyscallDispatcher::new()` (`dispatch/mod.rs:4446` / `:4397`). The dispatcher's `stream_stdio` flag is born `false` (`dispatch/fs/state.rs:228`), i.e. buffering.
- Produces:
  ```rust
  // crates/carrick-spec/src/lib.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum StdioMode { #[default] Inherit, Captured, Piped }
  // RunSpec { ..., pub tty: bool, #[serde(default)] pub stdio: StdioMode, pub max_traps: usize, ... }  — `raw` and `interactive` deleted
  // crates/carrick-engine/src/lib.rs: pub use carrick_spec::StdioMode;
  ```

- [ ] **Step 1: Red — write the spec test for the type that does not exist yet**

  In `crates/carrick-spec/src/lib.rs` `mod tests` (starts :884), add after `run_spec_network_defaults_to_host` (:960-981):

  ```rust
      #[test]
      fn stdio_mode_defaults_to_inherit_and_serializes_snake_case() {
          // `Inherit` is the docker-shaped CLI default; the wire spelling is
          // snake_case like `PidMode`/`NetworkMode`.
          assert_eq!(StdioMode::default(), StdioMode::Inherit);
          assert_eq!(
              serde_json::to_string(&StdioMode::Captured).expect("serialize"),
              r#""captured""#
          );
          assert_eq!(
              serde_json::from_str::<StdioMode>(r#""piped""#).expect("deserialize"),
              StdioMode::Piped
          );
      }
  ```

  In `run_spec_network_defaults_to_host` (:961-981) delete the two JSON lines (:971-972)
  ```
              "raw": true,
              "interactive": false,
  ```
  and append after `assert!(spec.network.published_ports.is_empty());` (:980):
  ```rust
          // No `stdio` key: the serde default is the streaming CLI mode.
          assert_eq!(spec.stdio, StdioMode::Inherit);
  ```
  In `native_code_mode_is_ignored_legacy_state` (:1091-1110) delete the same two JSON lines (:1101-1102: `"raw": true,` / `"interactive": false,`).

  Run: `cargo test -p carrick-spec --lib stdio_mode`
  Expected: compile error `error[E0412]: cannot find type `StdioMode` in this scope` (red).

- [ ] **Step 2: Add `StdioMode` and swap the two `RunSpec` bools for it**

  In `crates/carrick-spec/src/lib.rs`, directly after the `NetworkMode` enum (:318-326, ends `    None,\n}`), insert:

  ```rust
  /// Where the guest's stdout/stderr bytes go for one run — the output mode the
  /// runtime installs on the dispatcher before boot. Replaces the retired
  /// `raw: bool` (stream vs. buffer, which the engine hardcoded on) and the
  /// never-read `interactive: bool`.
  ///
  /// * `Inherit` — stream byte-exact to the carrier's own fds 1/2 as the guest
  ///   writes, like `docker run`; `RunResult.stdout`/`stderr` stay empty. The
  ///   CLI default.
  /// * `Captured` — buffer into `RunResult.stdout`/`stderr` and hand them back
  ///   with the exit status (library callers, tests).
  /// * `Piped` — deliver to a caller-supplied `Write` sink installed through
  ///   `Runtime::prepare`. `Runtime::execute` alone carries no sink and refuses
  ///   this mode at configuration time instead of guessing.
  ///
  /// A `tty: true` run allocates a pty and ignores this field; tty output modes
  /// are outside the embed v1 surface.
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum StdioMode {
      #[default]
      Inherit,
      Captured,
      Piped,
  }
  ```

  Replace the RunSpec doc line :809
  ```
  /// - *How it behaves*: `tty` / `raw` / `interactive` (terminal handling),
  ```
  with
  ```
  /// - *How it behaves*: `tty` (pty allocation) and `stdio` (where guest fd 1/2
  ///   bytes go — see [`StdioMode`]),
  ```

  Replace the fields :828-829
  ```rust
      pub raw: bool,
      pub interactive: bool,
  ```
  with
  ```rust
      /// Output mode for guest fd 1/2 — see [`StdioMode`]. Serde-defaults to
      /// `Inherit`, the docker-shaped streaming mode.
      #[serde(default)]
      pub stdio: StdioMode,
  ```

  Run: `cargo test -p carrick-spec --lib`
  Expected: all carrick-spec tests pass, including `stdio_mode_defaults_to_inherit_and_serializes_snake_case`, `run_spec_network_defaults_to_host`, `native_code_mode_is_ignored_legacy_state`.

- [ ] **Step 3: Red — runtime tests for the three modes**

  In `crates/carrick-runtime/src/execute.rs`, add a new module right before the two lines `#[cfg(test)]` / `mod exit_code_tests {` (:737-738):

  ```rust
  #[cfg(test)]
  mod stdio_mode_tests {
      use super::setup_interactive_stdio;
      use crate::dispatch::SyscallDispatcher;
      use carrick_spec::StdioMode;

      #[test]
      fn captured_keeps_the_dispatcher_buffering_and_inherit_streams() {
          let mut dispatcher = SyscallDispatcher::new();
          let session = setup_interactive_stdio(&mut dispatcher, false, StdioMode::Captured)
              .expect("captured is always installable");
          assert!(session.is_none());
          assert!(!dispatcher.stream_stdio_enabled(), "Captured must buffer into RunResult");

          let session = setup_interactive_stdio(&mut dispatcher, false, StdioMode::Inherit)
              .expect("inherit is always installable");
          assert!(session.is_none());
          assert!(dispatcher.stream_stdio_enabled(), "Inherit must stream to the carrier fds");
      }

      #[test]
      fn piped_is_refused_without_a_prepare_installed_sink() {
          let mut dispatcher = SyscallDispatcher::new();
          let err = setup_interactive_stdio(&mut dispatcher, false, StdioMode::Piped)
              .expect_err("Runtime::execute has no sink for Piped");
          assert!(err.to_string().contains("Runtime::prepare"), "{err}");
          assert!(!dispatcher.stream_stdio_enabled());
      }
  }
  ```

  Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib stdio_mode_tests`
  Expected: compile errors — `error[E0560]: struct `RunSpec` has no field named `raw`` at `execute.rs:768` and `page_profile.rs:120` (both test-only literals compiled by `--lib`), `error[E0609]: no field `raw` on type `&RunSpec`` at :371/:463, plus the mismatched `bool` argument in the new tests (red).

- [ ] **Step 4: Lower `StdioMode` in `Runtime::execute`**

  `crates/carrick-runtime/src/execute.rs:15` — replace
  ```rust
  use carrick_spec::{FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec};
  ```
  with
  ```rust
  use carrick_spec::{FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec, StdioMode};
  ```

  Both call sites (:369-371 and :461-463 are textually identical):
  ```rust
                  // Interactive pty or raw stream
                  let _interactive_session =
                      setup_interactive_stdio(&mut dispatcher, spec.tty, spec.raw).map_err(|e| {
  ```
  Rewrite with a count-asserted substitution:
  ```sh
  test "$(rg -c 'setup_interactive_stdio\(&mut dispatcher, spec\.tty, spec\.raw\)' crates/carrick-runtime/src/execute.rs)" = 2
  perl -pi -e 's/setup_interactive_stdio\(&mut dispatcher, spec\.tty, spec\.raw\)/setup_interactive_stdio(\&mut dispatcher, spec.tty, spec.stdio)/; s{// Interactive pty or raw stream}{// Interactive pty, or the requested output mode for fd 1/2}' crates/carrick-runtime/src/execute.rs
  test "$(rg -c 'spec\.stdio\)' crates/carrick-runtime/src/execute.rs)" = 2
  ```

  Replace `setup_interactive_stdio` (:721-735):
  ```rust
  fn setup_interactive_stdio(
      dispatcher: &mut SyscallDispatcher,
      tty: bool,
      raw: bool,
  ) -> anyhow::Result<Option<crate::interactive_supervisor::InteractiveSession>> {
      if !tty {
          if raw {
              dispatcher.set_stream_stdio(true);
          }
          return Ok(None);
      }
      crate::interactive_supervisor::InteractiveSession::start(dispatcher)
          .context("failed to create carrier-local interactive PTY")
          .map(Some)
  }
  ```
  with
  ```rust
  fn setup_interactive_stdio(
      dispatcher: &mut SyscallDispatcher,
      tty: bool,
      stdio: StdioMode,
  ) -> anyhow::Result<Option<crate::interactive_supervisor::InteractiveSession>> {
      if !tty {
          match stdio {
              // Docker-shaped: guest fd 1/2 bytes go straight to the carrier's
              // own fds as they are written.
              StdioMode::Inherit => dispatcher.set_stream_stdio(true),
              // The dispatcher's default: accumulate into RunResult.stdout/stderr.
              StdioMode::Captured => {}
              // A Piped sink is installed by `Runtime::prepare`; `Runtime::execute`
              // carries none, so refuse rather than silently buffer or stream.
              StdioMode::Piped => anyhow::bail!(
                  "StdioMode::Piped needs a sink installed through Runtime::prepare; \
                   Runtime::execute carries none"
              ),
          }
          return Ok(None);
      }
      crate::interactive_supervisor::InteractiveSession::start(dispatcher)
          .context("failed to create carrier-local interactive PTY")
          .map(Some)
  }
  ```

  In `mod exit_code_tests` replace the import (:745-747)
  ```rust
      use carrick_spec::{
          ExecBackendRequest, FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec,
      };
  ```
  with
  ```rust
      use carrick_spec::{
          ExecBackendRequest, FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec,
          StdioMode,
      };
  ```
  and in `hvpatch_run_spec()` (:768-769) replace
  ```rust
              raw: true,
              interactive: false,
  ```
  with
  ```rust
              stdio: StdioMode::Inherit,
  ```

  Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib stdio_mode_tests`
  Expected: still a compile error, now only in `page_profile.rs:120` (`no field named raw`) — proceed to Step 5.

- [ ] **Step 5: Update the remaining `RunSpec` literals (page_profile test, cross-platform bins)**

  `crates/carrick-runtime/src/page_profile.rs:120-121` — replace
  ```rust
              raw: true,
              interactive: false,
  ```
  with
  ```rust
              stdio: carrick_spec::StdioMode::Inherit,
  ```

  `crates/carrick-runtime/src/bin/carrick-nvmm.rs:74-75` and `crates/carrick-runtime/src/bin/carrick-kvm.rs:71-72` — both read
  ```rust
                  raw: false,
                  interactive: false,
  ```
  `raw: false` with `tty: false` was the buffering path, so replace each with
  ```rust
                  stdio: carrick_spec::StdioMode::Captured,
  ```
  Note: these two bins are gated by `required-features = ["platform-linux"]` / `["platform-netbsd"]` (`crates/carrick-runtime/Cargo.toml:17,24`) and are not compiled on macOS. They are ALSO already stale against today's `RunSpec` — both write `uid: 0, gid: 0` (kvm :80-81, nvmm :83-84) where the fields are the `carrick_abi::NsUid`/`NsGid` newtypes — so no lane can compile-check this edit until that bit-rot is fixed separately. Make the textual edit, do not chase the bins' other errors in this task.

  Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib stdio_mode_tests`
  Expected: `test result: ok. 2 passed` (`captured_keeps_the_dispatcher_buffering_and_inherit_streams`, `piped_is_refused_without_a_prepare_installed_sink`).

- [ ] **Step 6: Engine emits `StdioMode::Inherit` where it hardcoded `raw: true`**

  `crates/carrick-engine/src/lib.rs:84-88` — replace
  ```rust
  pub use carrick_spec::{
      BridgeId, FsBackendKind, ImageConfig, Mount, NetworkAttachmentSpec, NetworkMode,
      NetworkNamespaceId, NetworkNamespaceSpec, PidMode, Platform, PortMapping, RunSpec,
      SeccompPolicy,
  };
  ```
  with
  ```rust
  pub use carrick_spec::{
      BridgeId, FsBackendKind, ImageConfig, Mount, NetworkAttachmentSpec, NetworkMode,
      NetworkNamespaceId, NetworkNamespaceSpec, PidMode, Platform, PortMapping, RunSpec,
      SeccompPolicy, StdioMode,
  };
  ```
  In the `Ok(RunSpec { ... })` literal (:449-450) replace
  ```rust
          raw: true,
          interactive: req.interactive,
  ```
  with
  ```rust
          // Docker-shaped streaming until `RunRequest.stdio` lands (next commit).
          stdio: StdioMode::Inherit,
  ```
  (`CliRunRequest.interactive` is now carried and unread; Task 19 deletes it.)

  Grep gate — must print nothing:
  ```sh
  rg -n 'spec\.raw\b|\braw: (true|false),|RunSpec\b.*interactive|\binteractive: req\.interactive' crates/carrick-spec crates/carrick-engine crates/carrick-runtime
  ```

  Run: `cargo test -p carrick-engine --lib`
  Expected: all existing engine tests pass (`bridge_network_resolves_into_run_spec`, `test_merge_argv_*`, …).

- [ ] **Step 7: Format, lint, full host gate**

  ```sh
  just fmt
  just clippy
  just doc
  just test
  ```
  Expected: each exits 0; `just test` reports `test result: ok` for carrick-spec, carrick-engine, the `carrick-cli --bin carrick` lane and the serial carrick-runtime lib run.

- [ ] **Step 8: Commit**

  ```sh
  git add crates/carrick-spec/src/lib.rs crates/carrick-engine/src/lib.rs crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/page_profile.rs crates/carrick-runtime/src/bin/carrick-nvmm.rs crates/carrick-runtime/src/bin/carrick-kvm.rs
  git commit -F - <<'EOF'
  feat(spec): replace RunSpec.raw/interactive with a typed StdioMode

  Why: `raw: bool` could only choose between streaming guest fd 1/2 to
  the carrier's own fds and buffering them, and `resolve_run_spec`
  hardcoded it to `true`, so captured output was unreachable from every
  product path and `RunResult.stdout/stderr` were always empty. The
  `interactive` flag on `RunSpec` had no reader in the runtime at all.
  Two bools that both mean "where do the bytes go" is the untyped domain
  value AGENTS.md forbids across a seam.

  What: `carrick_spec::StdioMode { Inherit, Captured, Piped }` (serde
  snake_case, `Default = Inherit`, the docker-shaped CLI behaviour)
  replaces both fields. `Runtime::execute` lowers `Inherit` to
  `set_stream_stdio(true)`, `Captured` to the dispatcher's buffering
  default, and refuses `Piped` — its sink is installed by
  `Runtime::prepare`, which does not exist yet — rather than silently
  picking a mode. The engine still emits `Inherit` unconditionally; the
  request-side field arrives with `RunRequest` in the next commit. The
  two legacy-JSON spec fixtures drop the dead keys (no compat shim; the
  new field serde-defaults like every trailing `RunSpec` field). The
  Linux/NetBSD dev bins get the same textual edit but were already stale
  against `RunSpec` (`uid: 0` into the `NsUid` newtype) and remain
  uncompiled here.

  Verified: `carrick-spec` `stdio_mode_defaults_to_inherit_and_serializes_snake_case`
  and both legacy-JSON tests (red before the enum existed);
  `carrick-runtime` `stdio_mode_tests` prove Inherit streams, Captured
  buffers and Piped is refused; `just fmt`, `just clippy`, `just doc`,
  `just test` green.

  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  EOF
  ```

---

### Task 25: `CliRunRequest` → `RunRequest` with `Default`, explicit inputs, typed warnings

**Files:**
- Modify: `crates/carrick-image/src/lib.rs:410-415` (`PullPolicy` gains `Default = Missing`)
- Modify: `crates/carrick-engine/src/lib.rs` — module doc :1-77; `CliRunRequest` :97-155; `request_platform` :199; `resolve_run_spec` :242-463 (env import :296-310, user :341-356, namespace id :403-409, literal :439-462); `Engine::resolve` :516-548; tests :551-1232 (`mod tests {` is :552, `base_req` :576-615)
- Test: `crates/carrick-engine/src/lib.rs` `mod tests`

**Interfaces:**
- Consumes: `carrick_spec::StdioMode` (Task 18); `carrick_runtime::runtime::DEFAULT_MAX_TRAPS: usize = usize::MAX` (`crates/carrick-runtime/src/runtime.rs:185`); `carrick_spec::NetworkNamespaceId::new` (`carrick-spec/src/lib.rs:371`).
- Produces:
  ```rust
  // crates/carrick-image/src/lib.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum PullPolicy { Always, #[default] Missing, Never }

  // crates/carrick-engine/src/lib.rs
  #[derive(Debug, Clone)] pub struct RunRequest { /* 34 pub fields, listed in Step 5 */ }
  impl Default for RunRequest { fn default() -> Self }   // manual impl: max_traps = DEFAULT_MAX_TRAPS (see deviations)
  #[derive(Debug, Clone, PartialEq, Eq)] pub struct ResolveWarning(pub String);
  impl std::fmt::Display for ResolveWarning
  #[derive(Debug, Clone, PartialEq, Eq)] pub struct Resolved { pub spec: RunSpec, pub warnings: Vec<ResolveWarning> }
  pub fn request_platform(req: &RunRequest) -> Platform;
  pub fn resolve_run_spec(req: RunRequest, image: ResolvedImage) -> Result<Resolved, String>;
  impl Engine { pub async fn resolve(&self, req: RunRequest) -> Result<Resolved, anyhow::Error>; }
  ```
  Note for downstream clusters: the workspace binary `carrick-cli` does not compile between this commit and Task 20's; every Task 19 gate is crate-scoped (`-p carrick-engine`). The pre-push hook runs workspace clippy, so push the Task 19 and Task 20 commits together (never `--no-verify`).

- [ ] **Step 1: Baseline — pin the full merge output of one fixed request (green on the old code)**

  In `crates/carrick-engine/src/lib.rs` `mod tests`, after `base_req` (:576-615), add the pin. It is written against today's `CliRunRequest` and must PASS now; the expected `RunSpec` is never edited again in this task, which is what makes the rename provably output-neutral. (`make_test_image` sets the image `USER` to the name `"root"`; the pin's explicit numeric `--user` overrides it, so the pin produces no named-user warning either — Step 3's `numeric_user_produces_no_warning` relies on that.)

  ```rust
      /// The request the parity pin merges. Every field that reaches the spec is
      /// set to a non-default value except the network mode (bridge lowering
      /// derives addresses from a name hash and is pinned by its own tests).
      fn parity_request() -> CliRunRequest {
          CliRunRequest {
              cap_add: vec!["SYS_PTRACE".to_string()],
              image_ref: "alpine".to_string(),
              platform: None,
              args: vec!["/bin/ls".to_string(), "-l".to_string()],
              env_overrides: vec!["CUSTOM=2".to_string()],
              mounts: vec![Mount {
                  source: Utf8PathBuf::from("/h"),
                  target: Utf8PathBuf::from("/g"),
                  readonly: true,
              }],
              workdir: Some("/app".to_string()),
              user: Some("1000:2000".to_string()),
              hostname: Some("api-host".to_string()),
              entrypoint_override: None,
              tty: false,
              interactive: false,
              rm: false,
              name: None,
              max_traps: 100,
              debug_state_path: Some("/tmp/state".to_string()),
              fs: Some(FsBackendKind::Host),
              pull: carrick_image::PullPolicy::Missing,
              exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
              pid: PidMode::default(),
              network: NetworkMode::Host,
              network_bridge: None,
              network_container: None,
              network_namespace_id: None,
              network_attachments: Vec::new(),
              network_ipv4: None,
              network_aliases: Vec::new(),
              extra_hosts: vec!["db.local:10.12.0.7".to_string()],
              dns_servers: vec!["1.1.1.1".to_string()],
              dns_search: vec!["example.test".to_string()],
              dns_options: vec!["ndots:2".to_string()],
              volumes_from: Vec::new(),
              published_ports: Vec::new(),
              stop_signal: None,
              stop_timeout: None,
              security_opts: vec!["seccomp=unconfined".to_string()],
          }
      }

      /// Hand-derived from `resolve_run_spec` at the pre-rename revision: args
      /// override the image cmd, baseline env plus the override sorted, absolute
      /// workdir verbatim, numeric uid:gid, dns fields set on the host-mode
      /// namespace spec, `seccomp=unconfined` opting out.
      fn parity_expected() -> RunSpec {
          RunSpec {
              executable: "/bin/ls".to_string(),
              argv: vec!["/bin/ls".to_string(), "-l".to_string()],
              envp: vec![
                  "CUSTOM=2".to_string(),
                  "DEBIAN_FRONTEND=noninteractive".to_string(),
                  "HOME=/root".to_string(),
                  "LANG=C.UTF-8".to_string(),
                  "LC_ALL=C.UTF-8".to_string(),
                  "PAGER=cat".to_string(),
                  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                  "TERM=xterm-256color".to_string(),
              ],
              cwd: Some(Utf8PathBuf::from("/app")),
              rootfs_layers: vec![Utf8PathBuf::from("/layer1")],
              fs_backend: FsBackendKind::Host,
              mounts: vec![Mount {
                  source: Utf8PathBuf::from("/h"),
                  target: Utf8PathBuf::from("/g"),
                  readonly: true,
              }],
              tty: false,
              stdio: StdioMode::Inherit,
              max_traps: 100,
              debug_state_path: Some(Utf8PathBuf::from("/tmp/state")),
              platform: Platform::host_native(),
              exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
              pid: PidMode::Private,
              hostname: Some("api-host".to_string()),
              network: NetworkNamespaceSpec {
                  dns_servers: vec!["1.1.1.1".parse::<std::net::IpAddr>().expect("ip")],
                  dns_search: vec!["example.test".to_string()],
                  dns_options: vec!["ndots:2".to_string()],
                  ..NetworkNamespaceSpec::default()
              },
              extra_hosts: vec!["db.local:10.12.0.7".to_string()],
              uid: carrick_abi::NsUid::new(1000),
              gid: carrick_abi::NsGid::new(2000),
              seccomp_policy: SeccompPolicy::Unconfined,
              cap_add: vec!["SYS_PTRACE".to_string()],
          }
      }

      #[test]
      fn resolve_run_spec_parity_pin() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let spec = resolve_run_spec(parity_request(), image).expect("resolve");
          assert_eq!(spec, parity_expected());
      }
  ```

  Run: `cargo test -p carrick-engine --lib resolve_run_spec_parity_pin`
  Expected: `test result: ok. 1 passed` — this is the baseline receipt for the rename.

- [ ] **Step 2: Route the existing precedence tests through a `spec_of` helper**

  The warning-carrying return type lands in Step 6; the 22 existing tests only care about the spec. Add, right after `base_req`. The body calls through `super::` ON PURPOSE: the mechanical rewrite below keys on that prefix to leave the helper's own call alone (its body line is otherwise textually identical to three test lines).
  ```rust
      /// The merged spec alone, for tests that pin precedence rules and do not
      /// care about warnings.
      fn spec_of(req: CliRunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
          super::resolve_run_spec(req, image)
      }
  ```
  then rewrite every un-prefixed `resolve_run_spec(` call inside `mod tests` (the module starts at the line `mod tests {`, :552 before the insertions), leaving the helper body and the parity pin untouched:
  ```sh
  test "$(perl -ne 'if (/^mod tests \{/) { $t = 1 } print if $t && /resolve_run_spec\(/' crates/carrick-engine/src/lib.rs | wc -l | tr -d ' ')" = 24
  perl -pi -e 'if (/^mod tests \{/) { $t = 1 } if ($t && !/fn spec_of|fn resolve_run_spec_parity_pin|let spec = resolve_run_spec\(parity_request/) { s/(?<!::)\bresolve_run_spec\(/spec_of(/g }' crates/carrick-engine/src/lib.rs
  test "$(rg -c '\bspec_of\(' crates/carrick-engine/src/lib.rs)" = 23
  test "$(perl -ne 'if (/^mod tests \{/) { $t = 1 } print if $t && /resolve_run_spec\(/' crates/carrick-engine/src/lib.rs | wc -l | tr -d ' ')" = 2
  ```
  (24 = 22 existing test call sites at HEAD (lines 623…1151) + the helper's `super::resolve_run_spec(` + the pin. After the rewrite `spec_of(` appears 23 times — 22 call sites + the helper definition — and exactly 2 `resolve_run_spec(` lines remain in the module: the pin and the helper body.)

  Run: `cargo test -p carrick-engine --lib`
  Expected: unchanged pass count (every test green).

- [ ] **Step 3: Red — tests for the new request shape and behaviour**

  Append to `mod tests` (these reference types and fields that do not exist yet):

  ```rust
      #[test]
      fn run_request_default_is_a_runnable_docker_shaped_baseline() {
          let d = RunRequest::default();
          assert_eq!(d.max_traps, carrick_runtime::runtime::DEFAULT_MAX_TRAPS);
          assert_eq!(d.pull, carrick_image::PullPolicy::Missing);
          assert_eq!(d.exec_backend, carrick_spec::ExecBackendRequest::HvPatch);
          assert_eq!(d.pid, PidMode::Private);
          assert_eq!(d.network, NetworkMode::Host);
          assert_eq!(d.stdio, StdioMode::Inherit);
          assert!(d.fs.is_none(), "fs is probed when unset");
          assert!(d.host_env.is_none(), "a library host imports nothing by default");
          assert!(d.bridge_namespace_id.is_none());
          assert!(d.image_ref.is_empty() && d.args.is_empty());
      }

      #[test]
      fn stdio_mode_flows_from_request_into_run_spec() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let mut req = base_req(None);
          req.stdio = StdioMode::Captured;
          assert_eq!(spec_of(req, image).expect("resolve").stdio, StdioMode::Captured);
      }

      #[test]
      fn bare_env_key_imports_from_the_host_env_snapshot() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let mut req = base_req(None);
          req.env_overrides = vec!["CARRICK_TEST_IMPORT_XYZ".to_string()];
          req.host_env = Some(vec![(
              "CARRICK_TEST_IMPORT_XYZ".to_string(),
              "from-host".to_string(),
          )]);
          let spec = spec_of(req, image).expect("resolve");
          assert!(
              spec.envp.iter().any(|e| e == "CARRICK_TEST_IMPORT_XYZ=from-host"),
              "bare `-e KEY` imports from the snapshot; envp={:?}",
              spec.envp
          );
      }

      #[test]
      fn bare_env_key_without_a_host_env_imports_nothing() {
          // The process env is set ON PURPOSE: the engine must not read it when
          // no snapshot is supplied.
          // SAFETY: test setup; unique key so no other test races it.
          unsafe { std::env::set_var("CARRICK_TEST_NO_IMPORT_XYZ", "leaked") };
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let mut req = base_req(None);
          req.env_overrides = vec!["CARRICK_TEST_NO_IMPORT_XYZ".to_string()];
          req.host_env = None;
          let spec = spec_of(req, image).expect("resolve");
          // SAFETY: test teardown of the key set above.
          unsafe { std::env::remove_var("CARRICK_TEST_NO_IMPORT_XYZ") };
          assert!(
              !spec.envp.iter().any(|e| e.starts_with("CARRICK_TEST_NO_IMPORT_XYZ=")),
              "engine read std::env; envp={:?}",
              spec.envp
          );
      }

      #[test]
      fn unnamed_bridge_container_needs_an_explicit_bridge_namespace_id() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let mut req = base_req(None);
          req.network = NetworkMode::Bridge;
          req.bridge_namespace_id = None;
          let err = resolve_run_spec(req, image).expect_err("no namespace-id source");
          assert!(err.contains("bridge_namespace_id"), "{err}");

          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let mut req = base_req(None);
          req.network = NetworkMode::Bridge;
          req.bridge_namespace_id = Some("anon-4242".to_string());
          let spec = spec_of(req, image).expect("explicit id");
          assert_eq!(
              spec.network.namespace_id.as_ref().map(NetworkNamespaceId::as_str),
              Some("anon-4242")
          );
      }

      #[test]
      fn named_user_becomes_a_typed_warning_not_stderr() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let resolved = resolve_run_spec(base_req(Some("nobody")), image).expect("resolve");
          assert_eq!(
              (resolved.spec.uid, resolved.spec.gid),
              (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
          );
          assert_eq!(
              resolved.warnings,
              vec![ResolveWarning(
                  "--user \"nobody\": name resolution is not yet supported; running as root (use a numeric uid[:gid])"
                      .to_string()
              )]
          );
          assert_eq!(resolved.warnings[0].to_string(), resolved.warnings[0].0);
      }

      #[test]
      fn numeric_user_produces_no_warning() {
          let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
          let resolved = resolve_run_spec(parity_request(), image).expect("resolve");
          assert!(resolved.warnings.is_empty(), "{:?}", resolved.warnings);
      }
  ```
  Also delete the old `bare_env_key_imports_host_value` test (`#[test]` at :781 through its closing `}` at :797, pre-insertion numbering) — it asserted the ambient `std::env` read that is being removed.

  Run: `cargo test -p carrick-engine --lib`
  Expected: compile errors `cannot find type `RunRequest``, `no field `host_env``, `cannot find type `ResolveWarning`` (red).

- [ ] **Step 4: `PullPolicy` gets a `Default`**

  `crates/carrick-image/src/lib.rs:410-415` — replace
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum PullPolicy {
      Always,
      Missing,
      Never,
  }
  ```
  with
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
  pub enum PullPolicy {
      Always,
      /// Docker's default: pull only when the image is absent locally.
      #[default]
      Missing,
      Never,
  }
  ```

  Run: `cargo test -p carrick-image --lib`
  Expected: passes (no behaviour change).

- [ ] **Step 5: Replace `CliRunRequest` with `RunRequest` + manual `Default`; add `Resolved`/`ResolveWarning`**

  Replace the whole `CliRunRequest` definition (`crates/carrick-engine/src/lib.rs:97-155`, from `#[derive(Debug, Clone)]\npub struct CliRunRequest {` through its closing `}`) with:

  ```rust
  /// One run's inputs, docker-shaped, as every frontend lowers them: the
  /// `carrick` CLI (clap flags), the Docker API server (`carrick serve`) and a
  /// library embedder (`carrick-embed`). [`resolve_run_spec`] merges it over the
  /// resolved image into a [`RunSpec`]; nothing else reads it. `Default` is a
  /// runnable baseline — host network, private pid namespace, HvPatch, `Missing`
  /// pull, no trap limit, docker-shaped streamed stdio — so a caller names only
  /// what it overrides.
  ///
  /// Container-lifecycle inputs (`--rm`, `--stop-signal`, `--stop-timeout`,
  /// `--volumes-from`, `-i`) are NOT here: the engine never consumed them, and
  /// the CLI keeps them beside this struct (`LaunchRequest` in `carrick-cli`).
  #[derive(Debug, Clone)]
  pub struct RunRequest {
      pub image_ref: String,
      /// Raw OCI platform string (`--platform linux/amd64`), or `None` for the
      /// host-native architecture (see [`Platform::host_native`]).
      pub platform: Option<String>,
      /// Command override — docker's positional args after the image.
      pub args: Vec<String>,
      /// `-e KEY=VALUE` / `-e KEY` entries, last-wins. A bare `KEY` imports from
      /// [`RunRequest::host_env`].
      pub env_overrides: Vec<String>,
      /// The environment a bare `-e KEY` imports from. The CLI passes a snapshot
      /// of its own process environment (docker's `-e KEY` semantics); `None`
      /// imports nothing, so a library host never leaks its environment into a
      /// guest by accident. The engine never reads `std::env` itself.
      pub host_env: Option<Vec<(String, String)>>,
      pub mounts: Vec<Mount>,
      pub workdir: Option<String>,
      pub user: Option<String>,
      /// Docker-compatible container hostname / UTS identity.
      pub hostname: Option<String>,
      pub entrypoint_override: Option<Vec<String>>,
      /// Allocate a pty (`-t`). A pty run streams through the pty and ignores
      /// `stdio`.
      pub tty: bool,
      /// Where guest fd 1/2 bytes go — see [`StdioMode`]. `Inherit` is the CLI's
      /// docker-shaped default; library callers typically choose `Captured`.
      pub stdio: StdioMode,
      /// Container name. Consumed only in bridge mode, where it becomes the
      /// container's DNS name and the fallback network-namespace id.
      pub name: Option<String>,
      /// Guest trap budget; `DEFAULT_MAX_TRAPS` (`usize::MAX`) means unbounded.
      pub max_traps: usize,
      pub debug_state_path: Option<String>,
      /// Writable-layer backend; `None` probes the shared default.
      pub fs: Option<FsBackendKind>,
      /// Docker `--pull` policy for image resolution. Defaults to `Missing`.
      pub pull: carrick_image::PullPolicy,
      pub exec_backend: carrick_spec::ExecBackendRequest,
      /// PID namespace mode (`docker run --pid`). Defaults to `Private`.
      pub pid: PidMode,
      pub network: NetworkMode,
      pub network_bridge: Option<String>,
      pub network_container: Option<String>,
      pub network_namespace_id: Option<String>,
      /// The namespace id a bridge-mode container falls back to when it has no
      /// `network_namespace_id`, `network_container` or `name`. The CLI mints
      /// `anon-<pid>` here — once per carrier process, so fork children share
      /// it. The engine never asks for the host pid itself: an embedder running
      /// several unnamed bridge containers in one process must give each its
      /// own id, and a bridge request with no id source at all is an error.
      pub bridge_namespace_id: Option<String>,
      pub network_attachments: Vec<CliNetworkAttachment>,
      pub network_ipv4: Option<String>,
      pub network_aliases: Vec<String>,
      pub extra_hosts: Vec<String>,
      pub dns_servers: Vec<String>,
      pub dns_search: Vec<String>,
      pub dns_options: Vec<String>,
      pub published_ports: Vec<PortMapping>,
      /// Raw `--security-opt` values (docker syntax). Resolved by
      /// [`resolve_seccomp_policy`] over the `carrick run` default
      /// ([`SeccompPolicy::ContainerDefault`], docker's own default).
      pub security_opts: Vec<String>,
      /// Docker-compatible `--cap-add` names (no `CAP_` prefix), the same
      /// lifetime rule as `security_opts`.
      pub cap_add: Vec<String>,
  }

  /// Hand-written rather than derived: a derived `Default` would set
  /// `max_traps` to `0`, which trips the trap limit on the first syscall.
  impl Default for RunRequest {
      fn default() -> Self {
          Self {
              image_ref: String::new(),
              platform: None,
              args: Vec::new(),
              env_overrides: Vec::new(),
              host_env: None,
              mounts: Vec::new(),
              workdir: None,
              user: None,
              hostname: None,
              entrypoint_override: None,
              tty: false,
              stdio: StdioMode::default(),
              name: None,
              max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
              debug_state_path: None,
              fs: None,
              pull: carrick_image::PullPolicy::default(),
              exec_backend: carrick_spec::ExecBackendRequest::default(),
              pid: PidMode::default(),
              network: NetworkMode::default(),
              network_bridge: None,
              network_container: None,
              network_namespace_id: None,
              bridge_namespace_id: None,
              network_attachments: Vec::new(),
              network_ipv4: None,
              network_aliases: Vec::new(),
              extra_hosts: Vec::new(),
              dns_servers: Vec::new(),
              dns_search: Vec::new(),
              dns_options: Vec::new(),
              published_ports: Vec::new(),
              security_opts: Vec::new(),
              cap_add: Vec::new(),
          }
      }
  }

  /// A merge decision the caller should surface but that does not fail the
  /// run — today only "named `--user` fell back to root". The engine never
  /// prints; the CLI writes these to stderr, a library caller inspects them.
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct ResolveWarning(pub String);

  impl std::fmt::Display for ResolveWarning {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
          f.write_str(&self.0)
      }
  }

  /// [`resolve_run_spec`]'s result: the fully merged spec plus the warnings the
  /// merge produced.
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct Resolved {
      pub spec: RunSpec,
      pub warnings: Vec<ResolveWarning>,
  }
  ```

  `request_platform` (:199): replace `pub fn request_platform(req: &CliRunRequest) -> Platform {` with `pub fn request_platform(req: &RunRequest) -> Platform {`.

- [ ] **Step 6: `resolve_run_spec` — explicit host env, explicit bridge id, typed warning, `Resolved`**

  Signature (:242): replace
  ```rust
  pub fn resolve_run_spec(req: CliRunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
  ```
  with
  ```rust
  pub fn resolve_run_spec(req: RunRequest, image: ResolvedImage) -> Result<Resolved, String> {
  ```

  Env import (:296-310): replace
  ```rust
      // Add env overrides (last-wins). A bare `KEY` (no `=`) imports the value
      // from the HOST environment, matching docker's `-e KEY` / env-file semantics;
      // an unset host var contributes nothing (docker drops it too).
      for entry in &req.env_overrides {
          match entry.split_once('=') {
              Some((k, v)) => {
                  env_map.insert(k.to_string(), v.to_string());
              }
              None => {
                  if let Ok(v) = std::env::var(entry) {
                      env_map.insert(entry.to_string(), v);
                  }
              }
          }
      }
  ```
  with
  ```rust
      // Add env overrides (last-wins). A bare `KEY` (no `=`) imports the value
      // from the caller-supplied host-environment snapshot, matching docker's
      // `-e KEY` / env-file semantics; a key absent there — or no snapshot at
      // all — contributes nothing (docker drops it too). The engine never reads
      // `std::env`: the frontend decides what, if anything, leaks in.
      for entry in &req.env_overrides {
          match entry.split_once('=') {
              Some((k, v)) => {
                  env_map.insert(k.to_string(), v.to_string());
              }
              None => {
                  let imported = req
                      .host_env
                      .iter()
                      .flatten()
                      .find(|(key, _)| key == entry)
                      .map(|(_, value)| value.clone());
                  if let Some(v) = imported {
                      env_map.insert(entry.to_string(), v);
                  }
              }
          }
      }
  ```

  User (:341-356): replace
  ```rust
      // 4. Resolve user (`--user` overrides image USER). Numeric `uid[:gid]` only;
      // a user/group NAME needs in-image /etc/passwd resolution (not yet
      // supported), so warn and run as root rather than silently mis-mapping.
      let (uid, gid) = match req.user.clone().or_else(|| image.config.user.clone()) {
          None => (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
          Some(s) if s.is_empty() => (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
          Some(s) => match parse_numeric_user(&s) {
              Some((u, g)) => (u, g),
              None => {
                  eprintln!(
                      "carrick: --user {s:?}: name resolution is not yet supported; running as root (use a numeric uid[:gid])"
                  );
                  (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
              }
          },
      };
  ```
  with
  ```rust
      // 4. Resolve user (`--user` overrides image USER). Numeric `uid[:gid]` only;
      // a user/group NAME needs in-image /etc/passwd resolution (not yet
      // supported), so record a warning and run as root rather than silently
      // mis-mapping. The warning is returned, never printed: the CLI relays it
      // to stderr, a library caller reads `Resolved::warnings`.
      let mut warnings = Vec::new();
      let (uid, gid) = match req.user.clone().or_else(|| image.config.user.clone()) {
          None => (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
          Some(s) if s.is_empty() => (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
          Some(s) => match parse_numeric_user(&s) {
              Some((u, g)) => (u, g),
              None => {
                  warnings.push(ResolveWarning(format!(
                      "--user {s:?}: name resolution is not yet supported; running as root (use a numeric uid[:gid])"
                  )));
                  (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
              }
          },
      };
  ```

  Namespace id (:403-409): replace
  ```rust
              let namespace_id = req
                  .network_namespace_id
                  .clone()
                  .or_else(|| req.network_container.clone())
                  .or_else(|| req.name.clone())
                  .unwrap_or_else(|| format!("anon-{}", std::process::id()));
              spec.namespace_id = Some(NetworkNamespaceId::new(namespace_id));
  ```
  with
  ```rust
              // The engine never samples the host pid: an unnamed container's
              // fallback id is an explicit input (`anon-<pid>` from the CLI, a
              // per-container id from an embedder). No source at all is an error
              // rather than a silently shared namespace.
              let namespace_id = req
                  .network_namespace_id
                  .clone()
                  .or_else(|| req.network_container.clone())
                  .or_else(|| req.name.clone())
                  .or_else(|| req.bridge_namespace_id.clone())
                  .ok_or_else(|| {
                      "bridge networking needs a namespace id: name the container, set \
                       `network_namespace_id`/`network_container`, or supply \
                       `bridge_namespace_id`"
                          .to_string()
                  })?;
              spec.namespace_id = Some(NetworkNamespaceId::new(namespace_id));
  ```

  Return literal (:439-462): replace
  ```rust
      Ok(RunSpec {
          cap_add: req.cap_add.clone(),
  ```
  with
  ```rust
      let spec = RunSpec {
          cap_add: req.cap_add.clone(),
  ```
  and the two lines introduced by Task 18
  ```rust
          // Docker-shaped streaming until `RunRequest.stdio` lands (next commit).
          stdio: StdioMode::Inherit,
  ```
  with
  ```rust
          stdio: req.stdio,
  ```
  and the literal's closing
  ```rust
          seccomp_policy,
      })
  }
  ```
  with
  ```rust
          seccomp_policy,
      };
      Ok(Resolved { spec, warnings })
  }
  ```

  Grep gate — production code only (everything before the first `#[cfg(test)]`, :551), comment lines excluded; must print nothing. (The test module legitimately contains `std::env::set_var`, and its fixtures still say `CliRunRequest` until Step 8, whose gate covers that.)
  ```sh
  perl -ne 'last if /^#\[cfg\(test\)\]/; print "$.: $_" if /std::env|std::process::id|eprintln!/ && !m{//}' crates/carrick-engine/src/lib.rs
  ```

- [ ] **Step 7: `Engine::resolve` returns `Resolved`; refresh its doc**

  Replace :516-523
  ```rust
      /// Resolve a run request to a `RunSpec`: parse the image ref, pull/resolve
      /// the image for the target platform, and merge into a fully-specified spec.
      /// This is the ONLY async part of a run — it does NOT execute, so no fork
      /// happens here and it is safe to drive inside a tokio runtime. The caller
      /// drops the runtime (joining its blocking pool in the parent) BEFORE
      /// calling `carrick_runtime::Runtime::execute`, so tokio is never alive
      /// across a fork.
      pub async fn resolve(&self, req: CliRunRequest) -> Result<RunSpec, anyhow::Error> {
  ```
  with
  ```rust
      /// Resolve a run request: parse the image ref, pull/resolve the image for
      /// the target platform, and merge into a fully-specified [`Resolved`]
      /// (spec + warnings). This is the ONLY async part of a run — the image
      /// store awaits `tokio::fs` and the registry client — and it does NOT
      /// execute. The CLI drives it on a throwaway current-thread runtime that it
      /// drops before `carrick_runtime::Runtime::execute` (`block_on_oci`).
      pub async fn resolve(&self, req: RunRequest) -> Result<Resolved, anyhow::Error> {
  ```
  (The body's final `resolve_run_spec(req, resolved).map_err(anyhow::Error::msg)` already has the new type.)

- [ ] **Step 8: Rewrite the test fixtures onto `RunRequest`**

  `base_req` (:576-615) becomes:
  ```rust
      fn base_req(user: Option<&str>) -> RunRequest {
          RunRequest {
              image_ref: "alpine".to_string(),
              args: vec!["/bin/ls".to_string()],
              user: user.map(|s| s.to_string()),
              max_traps: 100,
              fs: Some(FsBackendKind::Host),
              // What the CLI always supplies; the bridge tests rely on it.
              bridge_namespace_id: Some("anon-test".to_string()),
              ..RunRequest::default()
          }
      }
  ```
  `spec_of` helper: change its signature/body to
  ```rust
      fn spec_of(req: RunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
          super::resolve_run_spec(req, image).map(|resolved| resolved.spec)
      }
  ```
  `parity_request` (Step 1) becomes the compact form — the expected spec is untouched:
  ```rust
      fn parity_request() -> RunRequest {
          RunRequest {
              image_ref: "alpine".to_string(),
              args: vec!["/bin/ls".to_string(), "-l".to_string()],
              env_overrides: vec!["CUSTOM=2".to_string()],
              mounts: vec![Mount {
                  source: Utf8PathBuf::from("/h"),
                  target: Utf8PathBuf::from("/g"),
                  readonly: true,
              }],
              workdir: Some("/app".to_string()),
              user: Some("1000:2000".to_string()),
              hostname: Some("api-host".to_string()),
              max_traps: 100,
              debug_state_path: Some("/tmp/state".to_string()),
              fs: Some(FsBackendKind::Host),
              extra_hosts: vec!["db.local:10.12.0.7".to_string()],
              dns_servers: vec!["1.1.1.1".to_string()],
              dns_search: vec!["example.test".to_string()],
              dns_options: vec!["ndots:2".to_string()],
              security_opts: vec!["seccomp=unconfined".to_string()],
              cap_add: vec!["SYS_PTRACE".to_string()],
              ..RunRequest::default()
          }
      }
  ```
  and the pin's body becomes
  ```rust
          let resolved = resolve_run_spec(parity_request(), image).expect("resolve");
          assert_eq!(resolved.spec, parity_expected());
  ```

  The six inline `CliRunRequest { ... }` literals collapse onto `base_req` (verified: each differs from `base_req(None)` only in the fields named below). Each replacement is the entire `let req = CliRunRequest { … };` block of the named test (pre-insertion line numbers):

  `test_merge_argv_no_override` (:824-861):
  ```rust
          let mut req = base_req(None);
          req.args = vec![];
  ```
  `test_merge_argv_cmd_override` (:875-912):
  ```rust
          let req = base_req(None);
  ```
  `test_merge_argv_entrypoint_override` (:925-962):
  ```rust
          let mut req = base_req(None);
          req.args = vec![];
          req.entrypoint_override = Some(vec!["/bin/bash".to_string()]);
  ```
  `test_merge_env_variables` (:975-1012):
  ```rust
          let mut req = base_req(None);
          req.env_overrides = vec!["CUSTOM=2".to_string(), "USER_VAR=yes".to_string()];
  ```
  `test_merge_workdir` (:1034-1071):
  ```rust
          let mut req = base_req(None);
          req.workdir = Some("/user/app".to_string());
  ```
  `relative_workdir_resolves_against_image_workingdir` closure (:1082-1119):
  ```rust
              let mut req = base_req(None);
              req.workdir = wd.map(|s| s.to_string());
  ```

  Gate — no literal of the old shape survives anywhere in the crate (`rg -q` exits 1 on zero matches, so the negation is the pass condition):
  ```sh
  ! rg -q 'CliRunRequest|interactive:|volumes_from:|stop_signal:|stop_timeout:|\brm:' crates/carrick-engine/src/lib.rs
  ```

  Run: `cargo test -p carrick-engine --lib`
  Expected: every test passes, including `resolve_run_spec_parity_pin` (same expected spec as Step 1), `run_request_default_is_a_runnable_docker_shaped_baseline`, `stdio_mode_flows_from_request_into_run_spec`, `bare_env_key_imports_from_the_host_env_snapshot`, `bare_env_key_without_a_host_env_imports_nothing`, `unnamed_bridge_container_needs_an_explicit_bridge_namespace_id`, `named_user_becomes_a_typed_warning_not_stderr`, `numeric_user_produces_no_warning`.

- [ ] **Step 9: Module doc — the contract this seam now keeps**

  Replace :10-16
  ```
  //! nothing about images, registries, or docker flags). This crate is the seam
  //! between them: it takes a [`CliRunRequest`] — the loosely-typed, docker-CLI-
  //! shaped bundle of flags and overrides the user typed — resolves the image,
  //! and *merges* the two into a single, fully-specified `RunSpec`. The runtime
  //! never sees a `CliRunRequest`; the CLI never builds a `RunSpec`. All
  //! docker-compatibility merge semantics — the rules for which of image-config
  //! vs. command-line wins — live in exactly one place: [`resolve_run_spec`].
  ```
  with
  ```
  //! nothing about images, registries, or docker flags). This crate is the seam
  //! between them: it takes a [`RunRequest`] — the typed, docker-shaped bundle
  //! of overrides that every frontend (the `carrick` CLI, the Docker API server,
  //! `carrick-embed`) lowers into — resolves the image, and *merges* the two into
  //! a single, fully-specified `RunSpec`. The runtime never sees a `RunRequest`;
  //! no frontend builds a `RunSpec`. All docker-compatibility merge semantics —
  //! the rules for which of image-config vs. request wins — live in exactly one
  //! place: [`resolve_run_spec`].
  ```
  Replace :20-22
  ```
  //! [`resolve_run_spec`] is a deterministic, side-effect-light function (its only
  //! reads of ambient state are `std::env` for bare-`-e KEY` import and the APFS
  //! case-sensitivity probe). It reproduces docker's precedence rules:
  ```
  with
  ```
  //! [`resolve_run_spec`] is a deterministic function of its two arguments. It
  //! reads no process environment (a bare `-e KEY` imports from
  //! [`RunRequest::host_env`], which the CLI fills from its own environment and a
  //! library caller may leave `None`), never samples the host pid (an unnamed
  //! bridge container's namespace id comes from
  //! [`RunRequest::bridge_namespace_id`], or the merge fails), and never prints
  //! (a named `--user` it cannot resolve becomes a [`ResolveWarning`] in the
  //! returned [`Resolved`]). Its one remaining touch of the host is the APFS
  //! case-sensitivity probe. It reproduces docker's precedence rules:
  ```
  Replace :34-36
  ```
  //!   overrides last-wins. A bare `-e KEY` (no `=`) imports `KEY` from the *host*
  //!   environment and contributes nothing if the host has it unset — matching
  //!   docker's `-e KEY` / env-file passthrough. The result is sorted for a
  ```
  with
  ```
  //!   overrides last-wins. A bare `-e KEY` (no `=`) imports `KEY` from the
  //!   request's `host_env` snapshot and contributes nothing if it is absent
  //!   there (or the snapshot is `None`) — matching docker's `-e KEY` / env-file
  //!   passthrough. The result is sorted for a
  ```
  Replace :63-66
  ```
  //! [`RunSpec`] to the caller. Resolving the spec is deliberately kept separate
  //! from executing it: the CLI calls [`carrick_runtime::Runtime::execute`] only
  //! after `resolve` has returned and the async (tokio) image-pull machinery has
  //! been torn down, so no tokio runtime is ever live across the `execute` fork.
  ```
  with
  ```
  //! [`Resolved`] to the caller. Resolving the spec is deliberately kept separate
  //! from executing it: `resolve` is the only async step (the image store awaits
  //! `tokio::fs` and the registry client) and
  //! [`carrick_runtime::Runtime::execute`] is synchronous, so a frontend chooses
  //! the runtime shape — the CLI drives `resolve` on a throwaway current-thread
  //! runtime it drops before executing.
  ```
  Replace :68-77
  ```
  //! ## What this layer does *not* own
  //!
  //! Several `CliRunRequest` fields are carried but not consumed here. `rm`,
  //! `name`, `stop_signal`, and `stop_timeout` are container-lifecycle concerns
  //! resolved and persisted by the CLI/registry at create time, not run-merge
  //! inputs — they are part of the request shape for a single source of truth, but
  //! [`resolve_run_spec`] ignores them. `interactive`/`tty`/`pid`/`mounts` flow
  //! straight through into the `RunSpec` unchanged. Keeping the merge function
  //! pure of lifecycle bookkeeping is what makes it exhaustively unit-testable
  //! (see the `tests` module: argv/env/workdir/user precedence are pinned there).
  ```
  with
  ```
  //! ## What this layer does *not* own
  //!
  //! Container-lifecycle inputs — `--rm`, `--stop-signal`, `--stop-timeout`,
  //! `--volumes-from`, `-i` — are not run-merge inputs and are not on
  //! [`RunRequest`]: the CLI owns them (`LaunchRequest` in `carrick-cli`) and
  //! persists them beside the request at create time. `name` IS consumed, but
  //! only in bridge mode (it becomes the container's DNS name and the fallback
  //! namespace id). `tty`/`stdio`/`pid`/`mounts` flow straight through into the
  //! `RunSpec` unchanged. Keeping the merge function pure of lifecycle
  //! bookkeeping is what makes it exhaustively unit-testable (see the `tests`
  //! module: argv/env/workdir/user precedence and a full-field parity pin live
  //! there).
  ```

- [ ] **Step 10: Crate-scoped gates (the CLI is lowered in Task 20)**

  ```sh
  just fmt
  cargo test -p carrick-engine --lib
  cargo test -p carrick-image --lib
  cargo clippy -p carrick-engine -p carrick-image --all-targets -- -D warnings
  RUSTDOCFLAGS="-D warnings" cargo doc -p carrick-engine --no-deps --document-private-items
  ```
  Expected: all five commands exit 0. (`just test`/`just clippy` will fail on `carrick-cli` until Task 20's commit — that is expected and stated in the commit body; the pre-push hook runs workspace clippy, so push this commit together with Task 20's.)

- [ ] **Step 11: Commit**

  ```sh
  git add crates/carrick-engine/src/lib.rs crates/carrick-image/src/lib.rs
  git commit -F - <<'EOF'
  feat(engine): CliRunRequest -> RunRequest with Default and explicit inputs

  Why: the engine's request was CLI-shaped and ambient. `resolve_run_spec`
  read `std::env` for a bare `-e KEY`, sampled `std::process::id()` to mint
  an unnamed bridge container's namespace id (so two unnamed bridge
  containers in one embedding process would silently share a namespace),
  and `eprintln!`ed when a named `--user` fell back to root. Four fields
  (`rm`, `stop_signal`, `stop_timeout`, `volumes_from`) were carried but
  never read here, `interactive` lost its only consumer when
  `RunSpec.interactive` went, and with 36 fields and no `Default` every
  caller (three CLI sites, serve, lifecycle, six test literals) spelled
  the whole struct out. `carrick-embed` needs one typed request both
  frontends lower into.

  What: `RunRequest` with a manual `Default` (a derived one would set
  `max_traps` to 0 and trip the trap limit immediately), `stdio: StdioMode`
  replacing the hardcoded `raw: true`, `host_env: Option<Vec<(String,
  String)>>` as the only source for bare-`KEY` import (`None` imports
  nothing), and `bridge_namespace_id: Option<String>` as the explicit
  fallback id — a bridge request with no id source at all is now an
  error. The lifecycle-only fields move to the CLI. `resolve_run_spec`
  and `Engine::resolve` return `Resolved { spec, warnings }`; the
  named-user notice is a `ResolveWarning` the CLI prints. `PullPolicy`
  gains `Default = Missing`. The engine no longer touches `std::env`,
  `std::process` or stderr.

  The `carrick-cli` binary does not build against this commit; its
  lowering onto `RunRequest` is the next commit so the engine change
  reviews on its own.

  Verified: `resolve_run_spec_parity_pin` — a full-field `RunSpec` pin
  captured against the pre-rename `CliRunRequest` and kept byte-identical
  across the rename; red-first `bare_env_key_without_a_host_env_imports_nothing`
  (process env set on purpose, proven unread),
  `unnamed_bridge_container_needs_an_explicit_bridge_namespace_id`,
  `named_user_becomes_a_typed_warning_not_stderr`,
  `run_request_default_is_a_runnable_docker_shaped_baseline`; every
  existing precedence test unchanged through the `spec_of` helper;
  `cargo clippy -p carrick-engine -p carrick-image --all-targets -D
  warnings` and `cargo doc -p carrick-engine` green.

  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  EOF
  ```

---

### Task 26: CLI lowers clap flags into `RunRequest`; lifecycle keeps its own fields

**Files:**
- Modify: `crates/carrick-cli/src/runtime_util.rs` (add three helpers after `emit_raw` :36-42)
- Modify: `crates/carrick-cli/src/lifecycle.rs` — doc :45-46; new `LaunchRequest` above `run_detached`'s doc comment (:94); `run_detached` :105-124; `build_created_state` :446-515; `resolve_request_image` :541-560; `run_detached_carrier` :568-605; `create` :613-621, `create_one_direct` :623-629, `create_one_direct_with_metadata` :652-676; `rebuild_request_from_state` :678-740; `start` :912-918; tests :2506-3268
- Modify: `crates/carrick-cli/src/commands.rs` — doc :20; Run arm :915-953, :970, :987, :1010-1016, :1069-1070; Create arm :1166-1204; `run_build` :2806-2848 at HEAD `ea0dac4c` (:2798-2840 at `3dc6cc72`; the file differs only after :1426)
- Modify: `crates/carrick-cli/src/serve/spawn.rs:79-119`
- Modify: `crates/carrick-cli/src/main.rs:26`
- Test: `crates/carrick-cli/src/lifecycle.rs` `mod tests`

**Interfaces:**
- Consumes: `carrick_engine::{RunRequest, Resolved, ResolveWarning, request_platform, resolve_run_spec, Engine::resolve}` (Task 19); `carrick_spec::StdioMode` (Task 18); `carrick_spec::NetworkNamespaceId::anonymous(pid: u32)` / `as_str()` (`crates/carrick-spec/src/lib.rs:379,393`).
- Produces (crate-private, CLI only):
  ```rust
  // crates/carrick-cli/src/lifecycle.rs
  #[derive(Debug, Clone)]
  pub(crate) struct LaunchRequest {
      pub run: carrick_engine::RunRequest,
      pub interactive: bool,
      pub rm: bool,
      pub stop_signal: Option<String>,
      pub stop_timeout: Option<u64>,
      pub volumes_from: Vec<String>,
  }
  // crates/carrick-cli/src/runtime_util.rs
  pub(crate) fn host_env_snapshot() -> Vec<(String, String)>;
  pub(crate) fn anon_bridge_namespace_id() -> String;
  pub(crate) fn emit_resolve_warnings(warnings: &[carrick_engine::ResolveWarning]);
  ```

- [ ] **Step 1: Red — the lifecycle test for the split**

  In `crates/carrick-cli/src/lifecycle.rs` `mod tests` (starts :2506), after `rebuild_request_reproduces_run_inputs_split_not_merged` (:2782-2809), add. The local is deliberately named `launch`, not `req`: Step 7 mechanically rewrites every `req.<field>` in this module to `req.run.<field>`, and this test is the one place that addresses the wrapper's own fields.

  ```rust
      #[test]
      fn launch_request_keeps_lifecycle_fields_beside_the_engine_request() {
          let launch = rebuild_request_from_state(&sample_state());
          // Lifecycle inputs live on the CLI wrapper, not on the engine request.
          assert!(!launch.rm);
          assert!(!launch.interactive);
          assert_eq!(launch.stop_signal, None);
          assert_eq!(launch.stop_timeout, None);
          assert!(launch.volumes_from.is_empty());
          // The CLI always lowers docker-shaped output and its own environment.
          assert_eq!(launch.run.stdio, carrick_spec::StdioMode::Inherit);
          assert!(launch.run.host_env.is_some());
          // A relaunch always carries the persisted namespace id; no anon fallback.
          assert!(launch.run.network_namespace_id.is_some());
          assert_eq!(launch.run.bridge_namespace_id, None);

          let state =
              build_created_state(&launch, "container-id", None, 17, Some(libc::SIGQUIT));
          assert_eq!(state.auto_remove, launch.rm);
          assert_eq!(state.config.interactive, launch.interactive);
          assert_eq!(state.config.stop_timeout, launch.stop_timeout);
          assert_eq!(state.config.volumes_from, launch.volumes_from);
          assert_eq!(state.config.stop_signal, Some(libc::SIGQUIT));
      }
  ```

  Run: `env RUST_MIN_STACK=8388608 cargo test -p carrick-cli --bin carrick launch_request_keeps`
  Expected: compile errors — `cannot find type `CliRunRequest` in crate `carrick_engine`` (from Task 19) and the new test's `launch.run` (red).

- [ ] **Step 2: The three CLI-side helpers**

  `crates/carrick-cli/src/runtime_util.rs`, after `emit_raw` (:36-42), add:

  ```rust
  /// The environment a bare `-e KEY` imports from: this CLI process's own,
  /// snapshotted once per request (docker `-e KEY` semantics). The engine never
  /// reads `std::env` itself.
  pub(crate) fn host_env_snapshot() -> Vec<(String, String)> {
      std::env::vars().collect()
  }

  /// The network-namespace id an unnamed bridge container falls back to:
  /// `anon-<pid>` of this carrier process, minted once here so every guest fork
  /// child inherits the same id. Passed to the engine explicitly; it never
  /// samples the pid itself.
  pub(crate) fn anon_bridge_namespace_id() -> String {
      carrick_spec::NetworkNamespaceId::anonymous(std::process::id())
          .as_str()
          .to_owned()
  }

  /// Relay the engine's merge warnings (e.g. a named `--user` falling back to
  /// root) to stderr with the CLI's `carrick:` prefix.
  pub(crate) fn emit_resolve_warnings(warnings: &[carrick_engine::ResolveWarning]) {
      for warning in warnings {
          eprintln!("carrick: {warning}");
      }
  }
  ```

- [ ] **Step 3: `lifecycle.rs` — `LaunchRequest` and every function that carried `CliRunRequest`**

  Replace the module-doc lines :45-46
  ```
  //! `create`/`start`/`restart` reconstruct a [`carrick_engine::CliRunRequest`]
  //! from the stored [`RunConfig`] via `rebuild_request_from_state`. The subtlety
  ```
  with
  ```
  //! `create`/`start`/`restart` reconstruct a [`LaunchRequest`] (the engine's
  //! [`carrick_engine::RunRequest`] plus the CLI's lifecycle fields) from the
  //! stored [`RunConfig`] via `rebuild_request_from_state`. The subtlety
  ```

  Insert directly above the doc comment of `pub(crate) fn run_detached` — the comment beginning `/// Detach into the background and run the container as one VM carrier,` (:94; it runs to :104, the signature is :105):
  ```rust
  /// A `run`/`create` request as the CLI owns it: the engine's
  /// [`carrick_engine::RunRequest`] (everything `resolve_run_spec` merges) plus
  /// the container-lifecycle inputs the engine never reads. Those are persisted
  /// into [`RunConfig`] at create time and consumed by `stop`/`rm`/`inspect` and
  /// the Docker API — never by the merge.
  #[derive(Debug, Clone)]
  pub(crate) struct LaunchRequest {
      pub run: carrick_engine::RunRequest,
      /// `-i`: keep stdin open (persisted for `start --attach` / API attach).
      pub interactive: bool,
      /// `--rm`: remove the container when it exits.
      pub rm: bool,
      /// Raw `--stop-signal` value, resolved against the image `STOPSIGNAL` at
      /// create time; `None` defers to the image.
      pub stop_signal: Option<String>,
      /// `--stop-timeout` seconds; `None` for the default grace window.
      pub stop_timeout: Option<u64>,
      /// Raw `--volumes-from` specs. Already expanded into `run.mounts`; kept so
      /// `inspect` can report `VolumesFrom`.
      pub volumes_from: Vec<String>,
  }
  ```

  `run_detached` (:105-124): replace
  ```rust
  pub(crate) fn run_detached(
      req: carrick_engine::CliRunRequest,
  ```
  with
  ```rust
  pub(crate) fn run_detached(
      req: LaunchRequest,
  ```
  and `    let resolved = resolve_request_image(&req, &store)?;` (:116) with `    let resolved = resolve_request_image(&req.run, &store)?;` (`req.stop_signal.as_deref()` at :118 and `build_created_state(&req, …)` at :123 are unchanged).

  `build_created_state` (:446-515) — replace the whole function with:
  ```rust
  fn build_created_state(
      req: &LaunchRequest,
      id: &str,
      name: Option<String>,
      created_secs: u64,
      stop_signal: Option<i32>,
  ) -> ContainerState {
      let run = &req.run;
      ContainerState {
          id: id.to_string(),
          name,
          image: run.image_ref.clone(),
          command: run.args.clone(),
          status: ContainerStatus::Created,
          supervisor_pid: 0,
          init_pid: 0,
          created_secs,
          exit_code: None,
          auto_remove: req.rm,
          api_auto_remove: false,
          labels: std::collections::HashMap::new(),
          control: None,
          terminal_control: None,
          launch_ticket: None,
          config: RunConfig {
              platform: run.platform.clone(),
              exec_backend: run.exec_backend,
              env: run.env_overrides.clone(),
              workdir: run.workdir.clone(),
              user: run.user.clone(),
              hostname: run.hostname.clone(),
              pid: run.pid,
              network: run.network,
              api_network_mode: run.network_bridge.clone().or_else(|| match run.network {
                  carrick_spec::NetworkMode::Bridge => Some("bridge".to_string()),
                  carrick_spec::NetworkMode::Host => Some("host".to_string()),
                  carrick_spec::NetworkMode::None => Some("none".to_string()),
              }),
              network_aliases: run.network_aliases.clone(),
              network_attachments: default_network_attachments(
                  run.network,
                  run.network_bridge.as_deref(),
                  &run.network_aliases,
                  run.network_ipv4.as_deref(),
              ),
              network_container: run.network_container.clone(),
              extra_hosts: run.extra_hosts.clone(),
              dns_servers: run.dns_servers.clone(),
              dns_search: run.dns_search.clone(),
              dns_options: run.dns_options.clone(),
              volumes_from: req.volumes_from.clone(),
              published_ports: run.published_ports.clone(),
              scratch_path: None,
              region_path: None,
              entrypoint: run.entrypoint_override.clone(),
              mounts: run.mounts.clone(),
              fs: run.fs,
              tty: run.tty,
              interactive: req.interactive,
              max_traps: run.max_traps,
              stop_signal,
              stop_signal_abi: StopSignalAbi::Linux,
              stop_timeout: req.stop_timeout,
              security_opts: run.security_opts.clone(),
              cap_add: run.cap_add.clone(),
          },
      }
  }
  ```

  `resolve_request_image` (:541-544): replace
  ```rust
  fn resolve_request_image(
      req: &carrick_engine::CliRunRequest,
      store: &carrick_image::ImageStore,
  ) -> anyhow::Result<carrick_image::ResolvedImage> {
  ```
  with
  ```rust
  fn resolve_request_image(
      req: &carrick_engine::RunRequest,
      store: &carrick_image::ImageStore,
  ) -> anyhow::Result<carrick_image::ResolvedImage> {
  ```
  (the body's `req.image_ref` / `req.platform` / `request_platform(req)` at :550-556 are already `RunRequest` fields).

  `run_detached_carrier` (:568-605; its only caller is the `__carrier-entry` path at :403, which passes `rebuild_request_from_state(&state)`): replace the signature line `    req: carrick_engine::CliRunRequest,` (:569) with `    req: LaunchRequest,`, and the resolve/execute tail (:594-601)
  ```rust
      let spec = match crate::runtime_util::block_on_oci(engine.resolve(req)) {
          Ok(s) => s,
          Err(_) => {
              container::mark_exited(id, 1);
              std::process::exit(1);
          }
      };
      match carrick_runtime::Runtime::execute(&spec) {
  ```
  with
  ```rust
      let resolved = match crate::runtime_util::block_on_oci(engine.resolve(req.run)) {
          Ok(resolved) => resolved,
          Err(_) => {
              container::mark_exited(id, 1);
              std::process::exit(1);
          }
      };
      // stderr is the container log here; the notice lands with the run.
      crate::runtime_util::emit_resolve_warnings(&resolved.warnings);
      match carrick_runtime::Runtime::execute(&resolved.spec) {
  ```

  `create` (:614), `create_one_direct` (:624), `create_one_direct_with_metadata` (:653): each `    req: carrick_engine::CliRunRequest,` parameter becomes `    req: LaunchRequest,`; in `create_one_direct_with_metadata` replace `    let resolved = resolve_request_image(&req, &store)?;` (:662) with `    let resolved = resolve_request_image(&req.run, &store)?;`.

  `rebuild_request_from_state` (:678-740) — replace the doc line `/// Reconstruct a `CliRunRequest` from a persisted container so `start` can` (:678) with `/// Reconstruct a [`LaunchRequest`] from a persisted container so `start` can`, the signature (:682) with `fn rebuild_request_from_state(state: &ContainerState) -> LaunchRequest {`, and the literal (from `    carrick_engine::CliRunRequest {` at :693 to its closing `    }` at :739) with:
  ```rust
      LaunchRequest {
          run: carrick_engine::RunRequest {
              image_ref: state.image.clone(),
              // Restart/exec reuses the already-resolved image; no re-pull.
              pull: carrick_image::PullPolicy::Missing,
              platform: c.platform.clone(),
              args: state.command.clone(),
              env_overrides: c.env.clone(),
              // A bare `-e KEY` persisted in `env` re-imports from THIS process's
              // environment at relaunch, exactly as before.
              host_env: Some(crate::runtime_util::host_env_snapshot()),
              mounts: c.mounts.clone(),
              workdir: c.workdir.clone(),
              user: c.user.clone(),
              hostname: c.hostname.clone(),
              entrypoint_override: c.entrypoint.clone(),
              tty: c.tty,
              stdio: carrick_spec::StdioMode::Inherit,
              name: state.name.clone(),
              max_traps: c.max_traps,
              debug_state_path: None,
              fs: c.fs,
              exec_backend: c.exec_backend,
              pid: c.pid,
              network: effective_network.network,
              network_bridge: bridge_network_name(effective_network),
              network_container: c.network_container.clone(),
              network_namespace_id: Some(
                  c.network_container
                      .clone()
                      .unwrap_or_else(|| state.id.clone()),
              ),
              // `network_namespace_id` above is always set on a relaunch, so the
              // anonymous fallback can never be consulted.
              bridge_namespace_id: None,
              network_attachments: bridge_network_attachments(effective_network, effective_name),
              network_ipv4: bridge_network_ipv4(effective_network, effective_name),
              network_aliases: bridge_network_aliases(effective_network),
              extra_hosts: c.extra_hosts.clone(),
              dns_servers: c.dns_servers.clone(),
              dns_search: c.dns_search.clone(),
              dns_options: c.dns_options.clone(),
              published_ports: c.published_ports.clone(),
              security_opts: c.security_opts.clone(),
              cap_add: c.cap_add.clone(),
          },
          interactive: c.interactive,
          rm: state.auto_remove,
          // The effective Linux stop signum is already persisted in RunConfig and
          // preserved across relaunch, so leave these unset.
          stop_signal: None,
          stop_timeout: None,
          volumes_from: c.volumes_from.clone(),
      }
  ```

  `start` (:912-918): replace (:917)
  ```rust
      carrick_engine::check_platform_runnable(carrick_engine::request_platform(&req))
  ```
  with
  ```rust
      carrick_engine::check_platform_runnable(carrick_engine::request_platform(&req.run))
  ```

- [ ] **Step 4: `commands.rs` — the `Run` arm**

  Replace the doc line :20
  ```
  //!    - `Run`/`Create`/`Exec` build a [`carrick_engine::CliRunRequest`] and go
  ```
  with
  ```
  //!    - `Run`/`Create` lower their flags into a `lifecycle::LaunchRequest` (the
  //!      engine's [`carrick_engine::RunRequest`] plus lifecycle fields) and go
  ```

  Replace the request literal :915-953
  ```rust
              let req = carrick_engine::CliRunRequest {
                  image_ref: image,
                  pull: pull.into(),
                  platform,
                  args: command,
                  env_overrides,
                  mounts,
                  workdir,
                  user,
                  hostname: None,
                  entrypoint_override,
                  tty,
                  interactive,
                  rm,
                  name,
                  max_traps,
                  debug_state_path: debug_state_path.map(|p| p.to_string_lossy().into_owned()),
                  fs,
                  exec_backend,
                  pid,
                  network: parsed_network.mode,
                  network_bridge: parsed_network.bridge,
                  network_container: parsed_network.container,
                  network_namespace_id: None,
                  network_attachments: Vec::new(),
                  network_ipv4: ip,
                  network_aliases: network_alias,
                  extra_hosts: add_host,
                  dns_servers: dns,
                  dns_search,
                  dns_options: dns_option,
                  volumes_from,
                  published_ports,
                  stop_signal,
                  stop_timeout,
                  security_opts: security_opt,
                  cap_add,
              };
  ```
  with
  ```rust
              let req = crate::lifecycle::LaunchRequest {
                  run: carrick_engine::RunRequest {
                      image_ref: image,
                      pull: pull.into(),
                      platform,
                      args: command,
                      env_overrides,
                      // docker `-e KEY`: import from the user's shell environment.
                      host_env: Some(crate::runtime_util::host_env_snapshot()),
                      mounts,
                      workdir,
                      user,
                      hostname: None,
                      entrypoint_override,
                      tty,
                      // docker-shaped: guest stdout/stderr stream to this terminal.
                      stdio: carrick_spec::StdioMode::Inherit,
                      name,
                      max_traps,
                      debug_state_path: debug_state_path.map(|p| p.to_string_lossy().into_owned()),
                      fs,
                      exec_backend,
                      pid,
                      network: parsed_network.mode,
                      network_bridge: parsed_network.bridge,
                      network_container: parsed_network.container,
                      network_namespace_id: None,
                      bridge_namespace_id: Some(crate::runtime_util::anon_bridge_namespace_id()),
                      network_attachments: Vec::new(),
                      network_ipv4: ip,
                      network_aliases: network_alias,
                      extra_hosts: add_host,
                      dns_servers: dns,
                      dns_search,
                      dns_options: dns_option,
                      published_ports,
                      security_opts: security_opt,
                      cap_add,
                  },
                  interactive,
                  rm,
                  stop_signal,
                  stop_timeout,
                  volumes_from,
              };
  ```
  Then the four uses of the request below it:
  - :970 `                let name_for_state = req.name.clone();` → `                let name_for_state = req.run.name.clone();`
  - :987 `                let scope = req.name.clone().unwrap_or_else(|| {` → `                let scope = req.run.name.clone().unwrap_or_else(|| {`
  - :1010-1016
    ```rust
              let spec = match block_on_oci(engine.resolve(req.clone())) {
                  Ok(s) => s,
                  // resolve runs in the PARENT (no fork yet) → normal exit is safe.
                  Err(e) => {
                      eprintln!("carrick: {e:#}");
                      std::process::exit(125);
                  }
              };
    ```
    →
    ```rust
              let resolved = match block_on_oci(engine.resolve(req.run.clone())) {
                  Ok(resolved) => resolved,
                  // resolve runs in the PARENT (no fork yet) → normal exit is safe.
                  Err(e) => {
                      eprintln!("carrick: {e:#}");
                      std::process::exit(125);
                  }
              };
              crate::runtime_util::emit_resolve_warnings(&resolved.warnings);
              let spec = resolved.spec;
    ```
  - :1069-1070 `"image": req.image_ref,` / `"command": req.args,` → `"image": req.run.image_ref,` / `"command": req.run.args,`

- [ ] **Step 5: `commands.rs` — the `Create` arm and the kaniko build carrier**

  Replace :1166-1204
  ```rust
              let req = carrick_engine::CliRunRequest {
                  image_ref: image,
                  pull: pull.into(),
                  platform,
                  args: command,
                  env_overrides,
                  mounts,
                  workdir,
                  user,
                  hostname: None,
                  entrypoint_override,
                  tty,
                  interactive,
                  rm,
                  name: None,
                  max_traps: DEFAULT_MAX_TRAPS,
                  debug_state_path: None,
                  fs,
                  exec_backend,
                  pid,
                  network: parsed_network.mode,
                  network_bridge: parsed_network.bridge,
                  network_container: parsed_network.container,
                  network_namespace_id: None,
                  network_attachments: Vec::new(),
                  network_ipv4: ip,
                  network_aliases: network_alias,
                  extra_hosts: add_host,
                  dns_servers: dns,
                  dns_search,
                  dns_options: dns_option,
                  volumes_from,
                  published_ports: parse_publish_specs(parsed_network.mode, &publish)?,
                  stop_signal,
                  stop_timeout,
                  security_opts: security_opt,
                  cap_add,
              };
  ```
  with
  ```rust
              let req = crate::lifecycle::LaunchRequest {
                  run: carrick_engine::RunRequest {
                      image_ref: image,
                      pull: pull.into(),
                      platform,
                      args: command,
                      env_overrides,
                      host_env: Some(crate::runtime_util::host_env_snapshot()),
                      mounts,
                      workdir,
                      user,
                      hostname: None,
                      entrypoint_override,
                      tty,
                      stdio: carrick_spec::StdioMode::Inherit,
                      name: None,
                      max_traps: DEFAULT_MAX_TRAPS,
                      debug_state_path: None,
                      fs,
                      exec_backend,
                      pid,
                      network: parsed_network.mode,
                      network_bridge: parsed_network.bridge,
                      network_container: parsed_network.container,
                      network_namespace_id: None,
                      bridge_namespace_id: Some(crate::runtime_util::anon_bridge_namespace_id()),
                      network_attachments: Vec::new(),
                      network_ipv4: ip,
                      network_aliases: network_alias,
                      extra_hosts: add_host,
                      dns_servers: dns,
                      dns_search,
                      dns_options: dns_option,
                      published_ports: parse_publish_specs(parsed_network.mode, &publish)?,
                      security_opts: security_opt,
                      cap_add,
                  },
                  interactive,
                  rm,
                  stop_signal,
                  stop_timeout,
                  volumes_from,
              };
  ```
  (`crate::lifecycle::create(req, store.clone(), name)?;` on the next line is unchanged.)

  In `run_build`, replace :2806-2845 (HEAD `ea0dac4c`; :2798-2837 at `3dc6cc72`)
  ```rust
      let request = carrick_engine::CliRunRequest {
          image_ref: KANIKO_IMAGE.to_owned(),
          platform: None,
          args: argv[image_index + 1..].to_vec(),
          env_overrides: Vec::new(),
          mounts,
          workdir: None,
          user: None,
          hostname: None,
          entrypoint_override: None,
          tty: false,
          interactive: false,
          rm: false,
          name: None,
          max_traps: usize::MAX,
          debug_state_path: None,
          fs: Some(carrick_spec::FsBackendKind::Host),
          pull: carrick_image::PullPolicy::Missing,
          exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
          pid: carrick_spec::PidMode::Private,
          network: carrick_spec::NetworkMode::Host,
          network_bridge: None,
          network_container: None,
          network_namespace_id: None,
          network_attachments: Vec::new(),
          network_ipv4: None,
          network_aliases: Vec::new(),
          extra_hosts: Vec::new(),
          dns_servers: Vec::new(),
          dns_search: Vec::new(),
          dns_options: Vec::new(),
          volumes_from: Vec::new(),
          published_ports: Vec::new(),
          stop_signal: None,
          stop_timeout: None,
          security_opts: Vec::new(),
          cap_add: Vec::new(),
      };
  ```
  with
  ```rust
      // Everything not named here is the `RunRequest` baseline: `Missing` pull,
      // HvPatch, private pid ns, host network, unbounded traps. No env overrides
      // means there is no bare KEY to import, and host networking never needs a
      // bridge namespace id, so both stay `None`.
      let request = carrick_engine::RunRequest {
          image_ref: KANIKO_IMAGE.to_owned(),
          args: argv[image_index + 1..].to_vec(),
          mounts,
          fs: Some(carrick_spec::FsBackendKind::Host),
          // kaniko's build log streams to this terminal, docker-shaped.
          stdio: carrick_spec::StdioMode::Inherit,
          ..carrick_engine::RunRequest::default()
      };
  ```
  and :2847-2848 (:2839-2840 at `3dc6cc72`)
  ```rust
      let spec = block_on_oci(engine.resolve(request)).context("resolve kaniko build carrier")?;
      let result = carrick_runtime::Runtime::execute(&spec).context("run kaniko build carrier")?;
  ```
  with
  ```rust
      let resolved =
          block_on_oci(engine.resolve(request)).context("resolve kaniko build carrier")?;
      crate::runtime_util::emit_resolve_warnings(&resolved.warnings);
      let result = carrick_runtime::Runtime::execute(&resolved.spec)
          .context("run kaniko build carrier")?;
  ```

- [ ] **Step 6: `serve/spawn.rs` and the `main.rs` doc**

  Replace `crates/carrick-cli/src/serve/spawn.rs:79-119`
  ```rust
      let request = carrick_engine::CliRunRequest {
          image_ref: image.to_owned(),
          platform: None,
          args: cmd.to_vec(),
          env_overrides: opts.env.to_vec(),
          mounts,
          workdir: opts.workdir.map(str::to_owned),
          user: opts.user.map(str::to_owned),
          hostname: opts.hostname.map(str::to_owned),
          entrypoint_override: opts.entrypoint.map(<[String]>::to_vec),
          tty: opts.tty,
          interactive: opts.interactive,
          rm: opts.auto_remove,
          name: opts.name.map(str::to_owned),
          max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
          debug_state_path: None,
          fs: Some(carrick_spec::FsBackendKind::Host),
          pull: carrick_image::PullPolicy::Missing,
          exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
          pid: carrick_spec::PidMode::Private,
          network,
          network_bridge,
          network_container,
          network_namespace_id: None,
          network_attachments: Vec::new(),
          network_ipv4: None,
          network_aliases: opts.network_aliases.to_vec(),
          extra_hosts: opts.extra_hosts.to_vec(),
          dns_servers: opts.dns_servers.to_vec(),
          dns_search: opts.dns_search.to_vec(),
          dns_options: opts.dns_options.to_vec(),
          volumes_from: opts.volumes_from.to_vec(),
          published_ports: crate::runtime_util::parse_publish_specs(network, opts.publish_specs)?,
          stop_signal: None,
          stop_timeout: None,
          security_opts: opts.security_opts.to_vec(),
          cap_add: Vec::new(),
      };
  ```
  with
  ```rust
      let request = crate::lifecycle::LaunchRequest {
          run: carrick_engine::RunRequest {
              image_ref: image.to_owned(),
              args: cmd.to_vec(),
              env_overrides: opts.env.to_vec(),
              // Same import source as before: the serving process's environment.
              host_env: Some(crate::runtime_util::host_env_snapshot()),
              mounts,
              workdir: opts.workdir.map(str::to_owned),
              user: opts.user.map(str::to_owned),
              hostname: opts.hostname.map(str::to_owned),
              entrypoint_override: opts.entrypoint.map(<[String]>::to_vec),
              tty: opts.tty,
              stdio: carrick_spec::StdioMode::Inherit,
              name: opts.name.map(str::to_owned),
              fs: Some(carrick_spec::FsBackendKind::Host),
              network,
              network_bridge,
              network_container,
              bridge_namespace_id: Some(crate::runtime_util::anon_bridge_namespace_id()),
              network_aliases: opts.network_aliases.to_vec(),
              extra_hosts: opts.extra_hosts.to_vec(),
              dns_servers: opts.dns_servers.to_vec(),
              dns_search: opts.dns_search.to_vec(),
              dns_options: opts.dns_options.to_vec(),
              published_ports: crate::runtime_util::parse_publish_specs(
                  network,
                  opts.publish_specs,
              )?,
              security_opts: opts.security_opts.to_vec(),
              ..carrick_engine::RunRequest::default()
          },
          interactive: opts.interactive,
          rm: opts.auto_remove,
          stop_signal: None,
          stop_timeout: None,
          volumes_from: opts.volumes_from.to_vec(),
      };
  ```
  (The `..default()` covers exactly what the old literal spelled out as defaults: `platform: None`, `debug_state_path: None`, `pull: Missing`, `exec_backend: HvPatch`, `pid: Private`, `max_traps: DEFAULT_MAX_TRAPS`, `network_namespace_id: None`, `network_attachments: []`, `network_ipv4: None`, `cap_add: []`. `create_one_direct_with_metadata(request, …)` at :126 takes the `LaunchRequest` unchanged.)

  `crates/carrick-cli/src/main.rs:26` — replace
  ```
  //! For a docker `run`, the CLI builds a [`carrick_engine::CliRunRequest`] and
  ```
  with
  ```
  //! For a docker `run`, the CLI builds a [`carrick_engine::RunRequest`] (inside
  //! its own `lifecycle::LaunchRequest`, which adds the lifecycle-only flags) and
  ```

- [ ] **Step 7: Lifecycle tests follow the wrapper**

  Every `req.<field>` read in `lifecycle.rs`'s `mod tests` is a `LaunchRequest` from `rebuild_request_from_state` (32 lines at :2785-2992 plus one `req.rm` at :2805; `rebuilt.exec_backend` at :2824); all but `req.rm` address the engine request. The Step 1 test uses `launch`, so nothing below touches it. Rewrite with a count-asserted substitution scoped to the test module (perl, not awk — macOS awk has no `\<` word boundary):
  ```sh
  test "$(perl -ne 'if (/^mod tests \{/) { $t = 1 } print if $t && /\breq\./ && !/\breq\.rm\b/' crates/carrick-cli/src/lifecycle.rs | wc -l | tr -d ' ')" = 32
  test "$(perl -ne 'if (/^mod tests \{/) { $t = 1 } print if $t && /\brebuilt\./' crates/carrick-cli/src/lifecycle.rs | wc -l | tr -d ' ')" = 1
  perl -pi -e 'if (/^mod tests \{/) { $t = 1 } if ($t) { s/\breq\.(?!run\.|rm\b)/req.run./g; s/\brebuilt\./rebuilt.run./g }' crates/carrick-cli/src/lifecycle.rs
  test "$(rg -c '\breq\.run\.' crates/carrick-cli/src/lifecycle.rs)" = 32
  test "$(rg -c '\brebuilt\.run\.' crates/carrick-cli/src/lifecycle.rs)" = 1
  ```
  Then, in `rebuild_request_preserves_custom_bridge_network_identity`, replace (:2859 pre-insertion)
  ```rust
          let spec = carrick_engine::resolve_run_spec(req, image).expect("resolve run spec");
  ```
  with
  ```rust
          let spec = carrick_engine::resolve_run_spec(req.run, image)
              .expect("resolve run spec")
              .spec;
          // The CLI's wrapper lowers docker-shaped streaming into the spec.
          assert_eq!(spec.stdio, carrick_spec::StdioMode::Inherit);
  ```

  Gate — the old name is gone from the workspace (`rg -c` over a directory prints one `file:count` line per matching file, so an empty listing is the pass; `docs/` plans may still say `CliRunRequest`, which is fine):
  ```sh
  test "$(rg -c 'CliRunRequest' crates/ | wc -l | tr -d ' ')" = 0
  ```

  Run: `env RUST_MIN_STACK=8388608 cargo test -p carrick-cli --bin carrick lifecycle::`
  Expected: `test result: ok` with `launch_request_keeps_lifecycle_fields_beside_the_engine_request`, `rebuild_request_reproduces_run_inputs_split_not_merged`, `rebuild_request_preserves_custom_bridge_network_identity`, `create_and_relaunch_preserve_explicit_hvpatch_backend` and the rest passing.

- [ ] **Step 8: Full host gate**

  ```sh
  just fmt
  just clippy
  just lint-domains
  just doc
  just test
  ```
  Expected: each exits 0 (`just test` runs the workspace lib tests, the `carrick-cli --bin carrick` tests (justfile:181), and the serial runtime/host/native-darwin lanes green).

- [ ] **Step 9: Live-verify the CLI is behaviour-identical (needs a signed binary + HVF; macOS only)**

  ```sh
  export CARRICK_RUN_ID=embed-c1-smoke
  just build
  # 1. docker-shaped streaming + exit code (StdioMode::Inherit through RunRequest)
  target/release/carrick run alpine:3.20 sh -c 'echo hello-from-guest; exit 7'; echo "exit=$?"
  # 2. bare -e KEY imports from the CLI's environment (host_env snapshot)
  CARRICK_T_IMPORT=42 target/release/carrick run -e CARRICK_T_IMPORT alpine:3.20 sh -c 'echo "import=$CARRICK_T_IMPORT"'
  # 3. unnamed bridge container still gets its anon-<pid> id (bridge_namespace_id); `--network` is an alias of `--net`
  target/release/carrick run --network bridge alpine:3.20 sh -c 'cat /etc/hostname; true'; echo "exit=$?"
  # 4. the named-user notice still reaches stderr, now via ResolveWarning
  target/release/carrick run --user nobody alpine:3.20 id -u 2>&1
  scripts/sudo/kill.sh embed-c1-smoke
  ```
  Expected: (1) prints `hello-from-guest` then `exit=7`; (2) prints `import=42`; (3) exits 0 (`exit=0`) and does not print the `bridge networking needs a namespace id` error; (4) prints the line `carrick: --user "nobody": name resolution is not yet supported; running as root (use a numeric uid[:gid])` followed by `0`. Do not run the Docker oracle concurrently.

- [ ] **Step 10: Commit**

  ```sh
  git add crates/carrick-cli/src/runtime_util.rs crates/carrick-cli/src/lifecycle.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/serve/spawn.rs crates/carrick-cli/src/main.rs
  git commit -F - <<'EOF'
  refactor(cli): lower run/create/serve/build onto carrick_engine::RunRequest

  Why: the engine's request became `RunRequest` (previous commit) and the
  lifecycle-only inputs it never read — `--rm`, `--stop-signal`,
  `--stop-timeout`, `--volumes-from`, `-i` — left it; the CLI is their
  owner. The engine also stopped reading the process environment and pid
  on its own, so the CLI must now say explicitly what it always meant:
  bare `-e KEY` imports from the user's shell environment, an unnamed
  bridge container is `anon-<pid>` of this carrier, and guest stdio
  streams to the terminal.

  What: `lifecycle::LaunchRequest { run: RunRequest, interactive, rm,
  stop_signal, stop_timeout, volumes_from }` is the CLI's request; the
  `Run`/`Create` arms, `serve`'s Docker-API create, and the kaniko build
  carrier build it (kaniko uses `..RunRequest::default()` for the
  baseline it never varied). Every constructor sets `stdio: Inherit`,
  `host_env: Some(host_env_snapshot())` and, where bridge mode is
  reachable, `bridge_namespace_id: Some(anon_bridge_namespace_id())` —
  minted through `NetworkNamespaceId::anonymous`, one definition of the
  prefix. A relaunch (`rebuild_request_from_state`) always carries the
  persisted namespace id, so it leaves the fallback `None`. Engine merge
  warnings are relayed to stderr with the `carrick:` prefix at the three
  resolve sites (`emit_resolve_warnings`). No user-visible behaviour
  changes.

  Verified: red-first `launch_request_keeps_lifecycle_fields_beside_the_engine_request`
  (lifecycle fields persist from the wrapper; relaunch lowers Inherit +
  host_env + no anon fallback); the existing rebuild/create round-trip
  tests unchanged through `req.run.*`; `just fmt`, `just clippy`,
  `just lint-domains`, `just doc`, `just test` green; live on the signed
  binary: streamed exit code 7, `-e KEY` import, unnamed `--network
  bridge` run, and the `--user nobody` notice all identical to before.

  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  EOF
  ```

<details><summary>Verifier problems fixed in place (13) and claims still unverified (7)</summary>

- fixed: Revision mismatch: repo HEAD is ea0dac4c, not 3dc6cc72 (an ancestor). All cited files are identical between the two EXCEPT crates/carrick-cli/src/commands.rs (+8 lines after :1426, so run_build is :2806-2848 at HEAD / :2798-2840 at 3dc6cc72) and crates/carrick-runtime/src/dispatch/mod.rs (new()=4446/4397, set_stream_stdio=5395/5346, stream_stdio_enabled=5409/5360). Draft cited the HEAD numbers without saying so; both are now recorded.
- fixed: Task 19 Step 2: the count is wrong — `mod tests` has 22 `resolve_run_spec(` call sites at HEAD (lines 623..1151), not 21, so after Step 1's pin and the helper the pre-rewrite count is 24 and the post-rewrite `spec_of(` count is 23 (22 call sites + the helper definition).
- fixed: Task 19 Step 2: the perl guard only excludes the `fn spec_of` SIGNATURE line; the helper BODY line `        resolve_run_spec(req, image)` is textually identical to test lines 690/703/1120 and would be rewritten to `spec_of(req, image)` → the helper recurses forever and every test hangs. Fixed by having the helper call `super::resolve_run_spec(...)` and rewriting with a `(?<!::)` lookbehind; added a post-check that exactly 2 `resolve_run_spec(` lines remain in the test module (pin + helper body).
- fixed: Task 19 Step 6 grep gate can never print nothing at Step 6: `CliRunRequest` still appears in the test fixtures until Step 8, and the Step 3 test `bare_env_key_without_a_host_env_imports_nothing` contains `unsafe { std::env::set_var(...) }` on a code line (no `//`, so `grep -v` does not filter it). Gate rewritten to scan only production code (before the first `#[cfg(test)]`, line 551) and `CliRunRequest` dropped from it (Step 8's gate covers that).
- fixed: Task 19 Step 8 gate `test "$(rg -c PATTERN file)" = 0` fails on SUCCESS: rg prints nothing (exit 1) for a file with zero matches, so the shell compares "" to 0. Replaced with `! rg -q PATTERN file`.
- fixed: Task 20 Step 7 pre-count uses awk `/\<req\./` — macOS BWK awk has no `\<` word boundary, so the count is 0 and the `= 32` gate fails. Replaced with perl (verified: 32 lines match `\breq\.` excluding `req.rm`, 1 line matches `\brebuilt\.`).
- fixed: Task 20 Step 7's perl rewrite `s/\breq\.(?!run\.|rm\b)/req.run./g` would also rewrite the Step 1 test's `req.interactive`, `req.stop_signal`, `req.stop_timeout`, `req.volumes_from` lines into `req.run.*` (breaking it), and those 11 extra `req.` lines would make the pre-count 43, not 32. The draft's claim that the `(?!run\.)` guard leaves that test alone is false. Fixed by naming the Step 1 test's variable `launch`, so no rewrite touches it and the counts stay 32/32/1.
- fixed: Task 20 Step 3: the `LaunchRequest` insertion anchor quotes a doc comment `/// \`carrick run -d\`` that does not exist; `run_detached`'s doc begins `/// Detach into the background and run the container as one VM carrier,` at lifecycle.rs:94 (fn signature at :105, not :106). Anchor corrected.
- fixed: Task 18 line ranges off: `setup_interactive_stdio` spans :721-735 (draft :721-733); `#[cfg(test)]`/`mod exit_code_tests {` are :737-738 (draft :736-737); the two call-site blocks including the comment line the perl rewrites are :369-376 / :461-468.
- fixed: Task 18 Step 3 expected-failure list omits `page_profile.rs:120` (`no field named raw`), which fails in the same `cargo test -p carrick-runtime --lib` compile; added.
- fixed: Task 18 Step 5 / unverified: carrick-kvm.rs and carrick-nvmm.rs ALREADY do not compile against today's RunSpec — both write `uid: 0, gid: 0` where the fields are the `carrick_abi::NsUid`/`NsGid` newtypes. The `stdio:` edit there is right but no lane can prove it until someone fixes that bit-rot; recorded in the step so the engineer does not chase it.
- fixed: Task 19 Step 2 awk `/^mod tests \{/` relies on `\{` being a literal brace in BWK awk; replaced with perl for the same robustness reason as the Task 20 fix.
- fixed: Task 19: the repo's pre-push hook runs workspace clippy, which fails on `carrick-cli` between the Task 19 and Task 20 commits; noted that both commits must be pushed together (no `--no-verify`).
- UNVERIFIED: crates/carrick-runtime/src/bin/carrick-kvm.rs and carrick-nvmm.rs are gated by `required-features = ["platform-linux"]` / `["platform-netbsd"]` (carrick-runtime/Cargo.toml:17,24) and are not compiled on macOS; the `stdio: StdioMode::Captured` edits there are compile-checked only on the Linux/NetBSD lanes (`cargo build -p carrick-cli --no-default-features --features platform-<linux|netbsd>`). kvm's literal also contains `uid: 0,` (line 80) which I did not investigate.
- UNVERIFIED: `SyscallDispatcher::new()` constructibility inside a plain unit test (Task 18 `stdio_mode_tests`): verified only that it takes no arguments (dispatch/mod.rs:4446) and that 134 in-crate test lines already call it; not verified that it has no process-global side effect that would matter under the serial `RUST_TEST_THREADS=1` runtime lane.
- UNVERIFIED: The Task 19 Step 2 awk/perl counts (23 pre-rewrite `resolve_run_spec(` lines inside `mod tests`, 22 `spec_of(` after) and Task 20 Step 7 counts (32 `req.` lines excluding `req.rm`, 1 `rebuilt.`) were derived by grep against HEAD (39426141); if Phase A/B commits land in these files first the counts must be re-derived, not forced.
- UNVERIFIED: `NetworkNamespaceSpec` struct-update syntax in `parity_expected` assumes no private fields (all 13 fields at carrick-spec/src/lib.rs:468-484 are `pub`; verified) — a later private field would break the literal.
- UNVERIFIED: Live smoke (Task 20 Step 9) expects `alpine:3.20` to pull from the default registry and the `--network bridge` unnamed run to exit 0 on this host; not executed here (read-only brief).
- UNVERIFIED: Overlap with Phase A item 6 (fork-era prose in commands.rs/main.rs/lifecycle.rs and the `Runtime::execute` tokio `debug_assert`): this cluster only rewrites the lines that name `CliRunRequest` and the engine's own module doc; if Phase A lands first, re-read those doc lines before applying the quoted replacements.
- UNVERIFIED: clippy on the spawn.rs `..RunRequest::default()` literal: `clippy::needless_update` fires only when EVERY field is listed; the literal omits ten, so it should not fire — not compile-checked.

</details>


<!-- cluster C2-prepare-rs -->
## Cluster C2-prepare-rs

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 21..22 -> 27..28), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] CARRICK_JOIN_REGION / `namespace::pid::{join_existing, attach_region}` is deleted THREE times: B1 Task 11 ('deletes the dead branch plus attach_region, join_existing'), B2 Task 14/15 ('the CARRICK_JOIN_REGION read', `join_existing`, `attach_region`, `KernelArena::attach`), and C2 Task 21 ('Deleted namespace::pid::join_existing and the CARRICK_JOIN_REGION env branch (execute.rs:224-231)'). Later clusters' grep expectations (B2 Task 14 Step 1 hit list incl. execute.rs:224/227/233; C2's 'verified attach_region/register_child are pub so deleting join_existing leaves no dead-code warning') are false after B1. FIX: B1 Task 11 owns the deletion (earliest) and the HA-000536 inventory row; B2 drops those items from Tasks 14/15 (keeps `KernelArena::attach` + by-path constructor deletion) and recomputes the Step 1 hit list; C2 Task 21 removes the deletion, its deviation bullet and the pid.rs verification note.
> - [ ] `LaunchContext` shape drift between producer B1 and consumers C2/C3: B1 adds a 5th pub FIELD `registry_id: Option<RegistryContainerId>`; C2 consumes a METHOD `LaunchContext::registry_id(&self) -> Option<&str>` ('Task 11 must provide it'); C3's `embedded_launch_context()` builds the contract's 4-field literal and would not compile. FIX: B1 adds `pub fn registry_id(&self) -> Option<&str>` (delegating to `RegistryContainerId::as_str`) -- C2 keeps its text; C3 prepared.rs uses `LaunchContext::unmanaged(RunId::new(run_id))` (B1-produced; allocates the ContainerId, exec_overlay/launch_authorization/registry_id = None) instead of a struct literal.
> - [ ] `LaunchContext::from_process_env()` fallback is required but not produced: C2 requires it to SUCCEED when CARRICK_RUN_ID/CARRICK_CONTAINER_ID are unset (foreground/in-lib tests; 'mirroring runtime.rs:718-722 pid-<pid>'), B4 relies on `Runtime::execute` calling it, and B1's hvpatch fallback calls it for run-elf -- yet B1 only states 'empty CARRICK_RUN_ID counts as absent' and 'unsafe CARRICK_CONTAINER_ID refuses', never what absent yields, and the existing `pid-<pid>` fallback lives in `kernel_arena_run_scope`, which B2 deletes. FIX: B1 produces text: absent/empty CARRICK_RUN_ID -> `RunId::new(format!("pid-{}", std::process::id()))` (this is the one surviving new HA-CATALOG-PROCESS-ID row B1 already reconciles), registry_id None, exec_overlay/launch_authorization from env only when set; Err only on an unsafe registry id.
> - [ ] C2's `PidPlacement` is written against pre-B2 code: it adds `pub fn namespace::pid::withdraw_request()` ('withdraws only the REQUESTED flag') and re-anchors on the `pid::requested()` gate at runtime.rs:621, but B2 (Tasks 13-15, before C2's Task 21) DELETES `request`, `requested`, statics REGION/REQUESTED and `RunConfig.region_path`. C2's own deviation admits 'if Task 11 has replaced request(), withdraw_request is unnecessary'. FIX: C2 removes `withdraw_request` from produces; `resolve_plan`/`Runtime::prepare` allocate placement via `NsSharedRegion::allocate(KernelArena::global())` + `container.install_pid_ns(region)` (B2) for `PidMode::Private`, and rollback is dropping the Arc (B2 Drop releases the slot).
> - [ ] C2's `Runtime::prepare` is anchored on the 3dc6cc72 `execute.rs`, but Phase B rewrites that function first: B1 (build `Arc<Container>` from LaunchContext, `dispatcher.set_container`), B2 (`container.install_pid_ns`), B3 (`apply_launch_privileges(policy, &Container)` -- C2 still consumes the old `apply_launch_privileges (:5807)` `&[String]` shape), B4 (`carrier::admit_container`/`retire_container`, `record_container_terminal`). C2's trimmed import lists, Step 5/8 counts and the moved body would drop those seams. FIX: C2 consumes lists add B1 `Container::new`/`set_container`, B2 `install_pid_ns`, B3 `apply_launch_privileges(&mut self, SeccompPolicy, &Container)`, B4 `admit_container/retire_container/record_container_terminal`; Task 21 states it moves the POST-Phase-B body and re-derives every execute.rs anchor after B4.
> - [ ] Carrier one-time init is unowned for embed: C3 consumes 'prepare (not the CLI) performs the idempotent carrier init `memory::init_alias_ipa_allocator()` + `fs_resolve_cache::init()` that commands.rs:960-963 does today', but C2's produces never mention it (verified: the pair is called only from carrick-cli commands.rs:565/958/2844). An embedded guest would run with neither initialized. FIX: C2 Task 21 adds to `Runtime::prepare`: idempotent `carrick_runtime::memory::init_alias_ipa_allocator(); carrick_runtime::fs_resolve_cache::init();` (guarded by a Once) and removes the three CLI call sites (one path); C2 produces records it; C1's Task 20 CLI edits must not re-add them.
> - [ ] The tokio `debug_assert!(Handle::try_current().is_err())` is deleted twice: A5 Task 7 deletes it and demotes tokio to a dev-dependency; C2 Task 21's commit body claims to delete it ('silently deletes ... added to the commit message') and says 'tokio stays a dependency because tests/integration/oci_layout.rs uses it'; C3 consumes its deletion as 'Phase A item 6'. FIX: C2 drops the deletion claim (it is gone after A5) and says 'tokio remains a dev-dependency (A5)'; C3 consumes text: 'deleted by A5 Task 7'.
> - [ ] C2 places `prepare.rs` (and therefore `Runtime::prepare`/`PreparedRun`/`RuntimeExtensions`) under `#[cfg(feature = "platform-macos")]`, while C3 forwards `platform-linux/freebsd/netbsd` features to carrick-runtime and consumes `carrick_runtime::Runtime::prepare` unconditionally, so `carrick-embed --no-default-features --features platform-linux` cannot compile. FIX: C2 makes prepare.rs platform-neutral (only the HVF-specific run path stays cfg-gated inside `PreparedRun::execute`), or C3 gates the crate's non-macOS features as 'compile-checked only' and cfg-gates `PreparedContainer::execute`; choose the former (opt-out rule).
>
### Task 27: `prepare.rs` — split `Runtime::execute` into `resolve_plan` / `Runtime::prepare` / `PreparedRun::execute`

**Files:**
- Create: `crates/carrick-runtime/src/prepare.rs`
- Modify: `crates/carrick-runtime/src/execute.rs:1-17` (imports), `:76-92` (`detached_stable_scratch`), `:188-509` (delete `pub struct Runtime` + `impl Runtime`, including the tokio `debug_assert!` at `:193-201` — see Step 5), `:721-735` (delete `setup_interactive_stdio`), helper visibilities at `:23,32,49,64,95,102,125,157,176,524,572,580`, test `:892-901`
- Modify: `crates/carrick-runtime/src/lib.rs:323-334`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs:71-74` (doc), `:77-86` (add `withdraw_request`), `:604-617` (delete dead `join_existing`)
- Modify: `crates/carrick-runtime/src/dispatch/fs/state.rs:210-221` (add `StdioSink` above `RuntimeIo`), `crates/carrick-runtime/src/dispatch/fs.rs:188-192`, `crates/carrick-runtime/src/dispatch/mod.rs:702`
- Modify: `justfile:225-247` (`test-integration` gains the `prepare` doctest)
- Test: `crates/carrick-runtime/src/prepare.rs` (`mod tests`), `crates/carrick-runtime/src/execute.rs` (moved test)

**Interfaces:**
- Consumes: `crate::kernel::container::LaunchContext { pub exec_overlay: Option<camino::Utf8PathBuf>, .. }` and `LaunchContext::from_process_env() -> Result<Self, RuntimeError>` (Task 11); `LaunchContext::registry_id(&self) -> Option<&str>` (the `CARRICK_CONTAINER_ID` registry key, `None` for a foreground run — see `deviations`); `carrick_spec::StdioMode { Inherit, Captured, Piped }` and `RunSpec { stdio: StdioMode, tty: bool, .. }` with `raw`/`interactive` deleted (Task 18); existing `pub(crate) fn run_elf_from_dispatcher_debug(path: &str, dispatcher: SyscallDispatcher, argv: A, env: E, max_traps: usize, debug_state_path: Option<&PathBuf>) -> Result<RunResult, RuntimeError>` (`runtime.rs:450`) and `pub fn run_rootfs_elf_with_hvf_args_and_dispatcher_debug` (`runtime.rs:379`); existing `SyscallDispatcher::{with_network_and_host_resolver (dispatch/mod.rs:4568), with_rootfs_and_executable (:4952), set_host_resolver_snapshot (:4598), set_rootfs_layer (:4987), set_page_geometry, set_guest_hostname (:4672), sandbox_exec_to_container (:4966), set_executable_path (:5009), set_cwd (:5687), set_credentials (:5036), apply_launch_privileges (:5807), register_mount (dispatch/fs.rs:1498), set_fs_backend (:4980), set_stream_stdio (:5395), rootfs (:5202)}`; `crate::page_profile::{resolve_execution_plan, ExecutionPlan, DEFAULT_LINUX_PAGE_SIZE}` (all `pub(crate)`, `page_geometry: PageGeometry` is `Copy`).
- Produces:
  ```rust
  // crates/carrick-runtime/src/prepare.rs  (re-exported from the crate root)
  pub struct Runtime;
  pub struct ExecutionPlan { /* private: launch, page, host_resolver, network, placement, env */ }
  impl ExecutionPlan { pub fn launch(&self) -> &LaunchContext; }
  pub fn resolve_plan(spec: &RunSpec, launch: LaunchContext) -> Result<ExecutionPlan, RuntimeError>;
  #[derive(Default)] pub struct RuntimeExtensions { /* private */ }
  impl RuntimeExtensions {
      pub fn vfs_mount(self, target: camino::Utf8PathBuf, vfs: Box<dyn crate::vfs::Vfs>) -> Self;
      pub fn stdio(self, sink: StdioSink) -> Self;
  }
  pub struct PreparedRun { /* private, single-use */ }
  impl Runtime {
      pub fn prepare(spec: &RunSpec, launch: LaunchContext, ext: RuntimeExtensions) -> Result<PreparedRun, RuntimeError>;
      pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError>;
  }
  impl PreparedRun { pub fn execute(self) -> Result<RunResult, RuntimeError>; }
  // crates/carrick-runtime/src/dispatch/fs/state.rs (re-exported as crate::dispatch::StdioSink and crate::prepare::StdioSink)
  pub enum StdioSink { Captured, Inherit }   // Task 22 adds `Piped { stdout, stderr }`
  // crates/carrick-runtime/src/namespace/pid.rs
  pub fn withdraw_request();
  ```

Rollback contract that this task implements (each item is a `Drop`, ordered by `PreparedRun` field order, and the same drops fire on every `?` inside `prepare`):

| Publication made by `prepare` | Undo |
| --- | --- |
| `namespace::pid::request()` (`PidMode::Private`) | `PidPlacement` guard → `withdraw_request()` on drop (failure AND after `execute`) |
| `RuntimeNetwork::create` namespace lease | `Arc<RuntimeNetwork>` drop → `destroy_namespace` (`network/mod.rs:438-442`); the only holders are `ExecutionPlan` and the dispatcher |
| fresh `HostFsBackend::new()` scratch `TempDir` + lockfile, extracted layers, seeded `/etc/*` | `HostFsBackend::drop` → `defer_remove_tree` (`fs_backend.rs:1954-1997`); the backend is owned by a local until `set_fs_backend`, then by the dispatcher |
| attached overlay (`exec_overlay` or the registry `<id>/scratch`) | deliberately NOT removed — the registry owns it (`carrick rm`); `HostFsBackend::attach` has no `TempDir` (`fs_backend.rs:2485-2494`) |
| registry `scratch_path` publication (`ContainerState::persist`, `container.rs:651`) | moved to AFTER `attach_or_create` + `prepare_host_root` succeed, so a failed preparation publishes nothing; once published it stays: the record is the durable cleanup handle for the directory that now exists |
| bind/rosetta/extension `register_mount`, `set_fs_backend`, resolv.conf mount | dispatcher-local (`VfsMounts`), dropped with the dispatcher |
| `InteractiveSession` `dup2` over fds 0–2 (`spec.tty`) | `SessionSetupGuard::drop` (partial, `interactive_supervisor.rs:80-96`) / `InteractiveSession::drop` → `restore` (complete, `:57-70`, `:98-102`) |
| `publish_root_net_view` (inside `with_network_and_host_resolver`, `dispatch/mod.rs:4584-4586`), `grant_launch_capabilities` (`dispatch/mod.rs:5816-5818` → `LAUNCH_GRANTED_CAPS`, `namespace/process.rs:198`), `set_host_process_name` (`dispatch/proctitle.rs`) | carrier-scoped statics: overwritten by the next `prepare`, moved onto `Container` by Phase B — documented in the module doc, not reversed here |

- [ ] **Step 1: Write the failing tests (new module, not yet compiling)**

Create `crates/carrick-runtime/src/prepare.rs` with ONLY the test module below and register it in `lib.rs` (Step 2). Every referenced item is absent, so `cargo test` fails to compile — that is the red state.

```rust
//! Phased run lifecycle: [`resolve_plan`] → [`Runtime::prepare`] →
//! [`PreparedRun::execute`]. (Body lands in Steps 3–6.)

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use carrick_spec::{
        ExecBackendRequest, FsBackendKind, NetworkNamespaceSpec, PidMode, Platform, RunSpec,
        StdioMode,
    };

    fn hvpatch_run_spec() -> RunSpec {
        RunSpec {
            cap_add: Vec::new(),
            executable: "/bin/sh".to_string(),
            argv: vec!["/bin/sh".to_string()],
            envp: Vec::new(),
            cwd: Some(Utf8PathBuf::from("/")),
            rootfs_layers: Vec::new(),
            fs_backend: FsBackendKind::Host,
            mounts: Vec::new(),
            tty: false,
            stdio: StdioMode::Inherit,
            max_traps: 100,
            debug_state_path: None,
            platform: Platform::Aarch64,
            exec_backend: ExecBackendRequest::HvPatch,
            pid: PidMode::Host,
            hostname: None,
            network: NetworkNamespaceSpec::default(),
            extra_hosts: Vec::new(),
            uid: carrick_abi::NsUid::ROOT,
            gid: carrick_abi::NsGid::ROOT,
            seccomp_policy: carrick_spec::SeccompPolicy::ContainerDefault,
        }
    }

    fn test_launch() -> LaunchContext {
        LaunchContext::from_process_env().expect("a foreground launch context needs no env")
    }

    /// Type-level phase order: extensions are MOVED into `prepare` (nothing can
    /// be added afterwards) and `execute` CONSUMES the run (no second execute).
    #[test]
    fn prepared_run_is_single_use_and_extensions_seal_at_prepare() {
        fn extensions_are_moved(ext: RuntimeExtensions) -> RuntimeExtensions {
            ext.stdio(StdioSink::Captured)
        }
        fn execute_consumes(run: PreparedRun) -> Result<RunResult, RuntimeError> {
            run.execute()
        }
        fn assert_send<T: Send>() {}
        assert_send::<PreparedRun>();
        assert_send::<RuntimeExtensions>();
        let _ = extensions_are_moved as fn(RuntimeExtensions) -> RuntimeExtensions;
        let _ = execute_consumes as fn(PreparedRun) -> Result<RunResult, RuntimeError>;
    }

    #[test]
    fn stdio_mode_and_extension_must_agree() {
        let mut spec = hvpatch_run_spec();
        spec.stdio = StdioMode::Captured;
        assert!(matches!(
            resolve_stdio(&spec, None),
            Ok(StdioSink::Captured)
        ));
        spec.stdio = StdioMode::Inherit;
        assert!(matches!(resolve_stdio(&spec, None), Ok(StdioSink::Inherit)));
        // An extension sink on a non-Piped spec is a contradiction, not a silent override.
        assert!(matches!(
            resolve_stdio(&spec, Some(StdioSink::Captured)),
            Err(RuntimeError::Configuration(_))
        ));
        spec.tty = true;
        spec.stdio = StdioMode::Captured;
        assert!(matches!(
            resolve_stdio(&spec, None),
            Err(RuntimeError::Configuration(_))
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn prepare_failure_withdraws_pid_placement() {
        let mut spec = hvpatch_run_spec();
        spec.pid = PidMode::Private;
        spec.rootfs_layers = vec![Utf8PathBuf::from(
            "/nonexistent/carrick-prepare-test/sha256-missing-layer",
        )];
        let err = Runtime::prepare(&spec, test_launch(), RuntimeExtensions::default())
            .err()
            .expect("a missing layer must fail preparation");
        assert!(matches!(err, RuntimeError::FsBackend(_)), "{err}");
        assert!(
            !crate::namespace::pid::requested(),
            "a failed prepare must withdraw its PID-namespace placement request"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn execute_releases_pid_placement_after_the_run() {
        let mut spec = hvpatch_run_spec();
        spec.pid = PidMode::Private;
        let result = Runtime::prepare(&spec, test_launch(), RuntimeExtensions::default())
            .expect("empty rootfs prepares")
            .execute()
            .expect("a missing entrypoint classifies as 127");
        assert_eq!(result.exit_code, 127);
        assert!(!crate::namespace::pid::requested());
    }

    /// Moved from `execute.rs`: the wrapper keeps the 127 classification.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvpatch_uses_container_entrypoint_resolution() {
        let result = Runtime::execute(&hvpatch_run_spec())
            .expect("hvpatch container setup should classify a missing entrypoint");
        assert_eq!(result.exit_code, 127);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
}
```

- [ ] **Step 2: Register the module and run the tests to see them fail (red)**

In `crates/carrick-runtime/src/lib.rs`, replace

```rust
#[cfg(feature = "platform-macos")]
pub mod execute;
pub(crate) mod hvpatch;
pub mod pty_relay;
pub mod rootfs;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub(crate) mod seccomp;
pub(crate) mod vdso_policy;
pub mod vfs;
#[cfg(feature = "platform-macos")]
pub use execute::Runtime;
```

with

```rust
#[cfg(feature = "platform-macos")]
pub mod execute;
pub(crate) mod hvpatch;
#[cfg(feature = "platform-macos")]
pub mod prepare;
pub mod pty_relay;
pub mod rootfs;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub(crate) mod seccomp;
pub(crate) mod vdso_policy;
pub mod vfs;
#[cfg(feature = "platform-macos")]
pub use prepare::{
    ExecutionPlan, PreparedRun, Runtime, RuntimeExtensions, StdioSink, resolve_plan,
};
```

Run: `cargo test -p carrick-runtime --lib prepare:: --no-run`
Expected: compile errors `cannot find type \`RuntimeExtensions\` in this scope`, `cannot find function \`resolve_stdio\``, `unresolved import \`prepare::Runtime\`` — red for the right reason (the API does not exist).

- [ ] **Step 3: Add `StdioSink` (two variants) and `withdraw_request`**

In `crates/carrick-runtime/src/dispatch/fs/state.rs`, immediately above

```rust
/// Process-local output transport. Linux fd-table authority lives exclusively
/// in the captured Kernel [`crate::kernel::FileTable`].
pub(in crate::dispatch) struct RuntimeIo {
```

insert

```rust
/// Where a guest's bare fd 1/2 bytes go for the whole run. Chosen at
/// `Runtime::prepare`, sealed at boot, inherited by every logical child.
pub enum StdioSink {
    /// Buffer into `RunResult::{stdout,stderr}`; nothing reaches the host fds.
    Captured,
    /// Write through to the carrier's own host fds 1/2 — `docker run` shape,
    /// the CLI default (`StdioMode::Inherit`).
    Inherit,
}
```

In `crates/carrick-runtime/src/dispatch/fs.rs`, replace

```rust
mod state;
mod xattr;
pub(crate) use pipe::*;
use state::*;
pub(super) use state::{FsState, RuntimeIo, host_fd_offset};
```

with

```rust
mod state;
mod xattr;
pub(crate) use pipe::*;
use state::*;
pub use state::StdioSink;
pub(super) use state::{FsState, RuntimeIo, host_fd_offset};
```

In `crates/carrick-runtime/src/dispatch/mod.rs`, directly below the line `mod fs;` (line 702, preceded by `#[macro_use]` at 701) add

```rust
pub use fs::StdioSink;
```

In `crates/carrick-runtime/src/namespace/pid.rs`, replace the `REQUESTED` doc comment (lines 71-74)

```rust
/// Set by the container launch path (`Runtime::execute`) to request that the
/// root guest be placed in a fresh PID namespace. `run-elf` never sets it, so
/// the single-ELF path stays in the identity ns (design §3.2, §5.2). Read by
/// `run_threaded_hvf_loop` to decide whether to allocate the shared region.
```

with

```rust
/// Set by the container launch path (`Runtime::prepare`, via its
/// `PidPlacement` guard) to request that the root guest be placed in a fresh
/// PID namespace, and withdrawn again by [`withdraw_request`] when that
/// preparation fails or its run finishes. `run-elf` never sets it, so the
/// single-ELF path stays in the identity ns (design §3.2, §5.2). Read by
/// `run_threaded_hvf_loop` to decide whether to allocate the shared region.
```

then replace

```rust
/// Whether launch-time PID-namespace placement was requested.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}
```

with

```rust
/// Whether launch-time PID-namespace placement was requested.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}

/// Withdraw a launch-time placement request: a preparation that failed, or a
/// run that finished, must not leave the flag armed for the next `prepare` in
/// the same carrier (a later `PidMode::Host` run would otherwise inherit it).
/// Only the request flag is withdrawn — an already-activated region stays
/// active for the carrier's lifetime (Phase B makes it per-container).
pub fn withdraw_request() {
    REQUESTED.store(false, Ordering::Relaxed);
}
```

and delete the dead `carrick exec` joiner (its only caller was the `CARRICK_JOIN_REGION` branch in `execute.rs:224-231`; nothing in `crates/` sets that variable — `carrick exec` runs over the carrier control endpoint, `kernel/control/exec.rs`; the remaining mentions are prose in `docs/` and the `scripts/migrate/host-authority-transition-inventory.json` audit record):

```rust
/// `carrick exec`: attach the running container's file-backed region and join it
/// as a new member — a fresh ns-pid, parented OUTSIDE the namespace (the
/// `carrick exec` CLI, so the exec'd guest's ns-ppid is 0, matching docker exec).
/// Enables pid translation while the original VM carrier remains namespace
/// init. Returns `false` if the region cannot be mapped — the caller must then
/// refuse to run, rather than silently execute outside the namespace.
pub fn join_existing(path: &std::path::Path) -> bool {
    if !attach_region(path) {
        return false;
    }
    REQUESTED.store(true, Ordering::Relaxed);
    register_child(std::process::id(), 0);
    true
}
```

- [ ] **Step 4: Make the `execute.rs` helpers crate-visible and split the registry publication**

In `crates/carrick-runtime/src/execute.rs` change visibility (`fn` → `pub(crate) fn`, `enum` → `pub(crate) enum`) on: `is_entrypoint_not_found` (:23), `entrypoint_not_found_result` (:32), `is_entrypoint_not_executable` (:49), `entrypoint_not_executable_result` (:64), `HostRootLayout` (:95), `prepare_host_root` (:102), `cached_lower_enabled` (:125), `rosetta_license_notice` (:157), `install_rosetta_mounts` (:176), `effective_guest_hostname` (:572), `seed_guest_baseline` (:580), and (under `#[cfg(feature = "fs-memory")]`) `install_fs_backend` (:524).

Replace the env-reading, publish-before-attach helper

```rust
/// For a detached container (`CARRICK_CONTAINER_ID` set), the stable on-disk
/// overlay path `<registry>/<id>/scratch`, recording it into the registry so
/// `carrick exec` can attach the same filesystem. `None` for a foreground run
/// (which uses an ephemeral per-run scratch). Best-effort registry write — a
/// failure just means `exec` can't find the overlay later, not a run failure.
fn detached_stable_scratch() -> Option<PathBuf> {
    let id = std::env::var("CARRICK_CONTAINER_ID").ok()?;
    if !crate::container::is_safe_id(&id) {
        return None;
    }
    let scratch = crate::container::container_dir(&id).join("scratch");
    if let Ok(mut state) = crate::container::ContainerState::load(&id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
    Some(scratch)
}
```

with two pure halves (the path, then the publication that `prepare` performs only after the overlay exists):

```rust
/// For a managed (detached) container, the stable on-disk overlay path
/// `<registry>/<id>/scratch`. `None` for an id that is not a safe registry
/// key. A foreground run never calls this (it uses an ephemeral per-run
/// scratch).
pub(crate) fn detached_stable_scratch_path(id: &str) -> Option<PathBuf> {
    if !crate::container::is_safe_id(id) {
        return None;
    }
    Some(crate::container::container_dir(id).join("scratch"))
}

/// Record a managed container's overlay path into its registry record so
/// `carrick exec`/`rm` find the same filesystem. Called only once the overlay
/// has been attached and its root prepared: a preparation that fails earlier
/// publishes nothing. Best-effort — a failed write means `exec` cannot find
/// the overlay later, not a run failure.
pub(crate) fn record_detached_scratch(id: &str, scratch: &std::path::Path) {
    if let Ok(mut state) = crate::container::ContainerState::load(id) {
        state.config.scratch_path = Some(scratch.to_string_lossy().into_owned());
        let _ = state.persist();
    }
}
```

- [ ] **Step 5: Delete the monolith from `execute.rs`**

Delete everything from

```rust
pub struct Runtime;

impl Runtime {
    pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError> {
```

through the closing

```rust
        };

        Ok(result)
    }
}
```

(HEAD lines 188–509; the tokio `debug_assert!` and `raw`/`interactive` lines inside that block may already have been edited by Phase A / Task 18 — the whole block goes regardless.)

**Deliberate deletion, not an accident:** that block carries the tokio "runtime must not be live" `debug_assert!` (`execute.rs:193-201`). It guarded a host-fork inside the interactive path that no longer exists — `InteractiveSession` is carrier-local `dup2` over fds 0–2 with no host process (`interactive_supervisor.rs:1-5`, `:21-55`) — and the embed contract's `ContainerBuilder::run` executes a `PreparedRun` inside `tokio::task::spawn_blocking`, where `Handle::try_current()` succeeds by design. It is NOT re-added in `prepare.rs`; the commit body records this.

Also delete

```rust
fn setup_interactive_stdio(
    dispatcher: &mut SyscallDispatcher,
    tty: bool,
    raw: bool,
) -> anyhow::Result<Option<crate::interactive_supervisor::InteractiveSession>> {
    if !tty {
        if raw {
            dispatcher.set_stream_stdio(true);
        }
        return Ok(None);
    }
    crate::interactive_supervisor::InteractiveSession::start(dispatcher)
        .context("failed to create carrier-local interactive PTY")
        .map(Some)
}
```

and the now-unused test `hvpatch_uses_container_entrypoint_resolution` (lines 892–901; it lives in `prepare.rs` from Step 1). Fix the imports at the top of `execute.rs` to exactly what remains in use (`FsBackendKind` is still matched by the `fs-memory`-gated `install_fs_backend`, so it stays under that cfg; `anyhow::{Context, Result}`, `Platform`, `PidMode` and both `run_*` drivers had no remaining users):

```rust
use crate::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use crate::fs_backend::MemoryBackend;
use crate::fs_backend::{FsBackend, HostFsBackend};
use crate::network::NetworkHostsEntry;
use crate::rootfs::RootFs;
use crate::runtime::{RunResult, RuntimeError};
use crate::vfs::BindVfs;
#[cfg(feature = "fs-memory")]
use carrick_spec::FsBackendKind;
use carrick_spec::{NetworkNamespaceSpec, RunSpec};
use std::borrow::Cow;
use std::path::PathBuf;
```

and in `exit_code_tests` change `use super::{Runtime, is_entrypoint_not_executable, is_entrypoint_not_found};` to `use super::{is_entrypoint_not_executable, is_entrypoint_not_found};`, drop the now-unused `hvpatch_run_spec` helper, drop the `use camino::Utf8PathBuf;` line, and shrink the `carrick_spec` import to `use carrick_spec::NetworkNamespaceSpec;` (`ExecBackendRequest`, `FsBackendKind`, `PidMode`, `Platform`, `RunSpec` and `Utf8PathBuf` were used only by that helper; `NetworkNamespaceSpec` is still used by the `seed_guest_baseline_*` tests and `FsBackend`/`HostFsBackend`/`MemoryBackend` by the host-root and seeding tests).

- [ ] **Step 6: Write `prepare.rs` (the body above the test module)**

```rust
//! Phased run lifecycle: [`resolve_plan`] → [`Runtime::prepare`] →
//! [`PreparedRun::execute`].
//!
//! `prepare` builds the whole container — rootfs, mounts, network, policy,
//! stdio — and hands back a [`PreparedRun`] that boots it exactly once.
//! [`RuntimeExtensions`] are applied between dispatcher construction and
//! boot; after `prepare` returns nothing can be added (the extensions were
//! moved in), and `execute(self)` consumes the run.
//!
//! # Rollback
//!
//! Every `?` inside `prepare` drops the locals built so far, and each of them
//! undoes its own publication: the private `PidPlacement` guard withdraws the
//! PID-namespace request; the `Arc<RuntimeNetwork>` destroys its namespace
//! lease; a fresh [`HostFsBackend`] reclaims its scratch `TempDir` (layers,
//! seeded `/etc/*` and all); [`InteractiveSession`] restores fds 0–2; bind,
//! rosetta and extension mounts live in the dispatcher's own mount table.
//! An ATTACHED overlay (`LaunchContext::exec_overlay` or a managed
//! container's `<registry>/<id>/scratch`) is never removed here — the
//! registry owns it and `carrick rm` reaps it — and its `scratch_path`
//! record is written only after the overlay exists, so a failed preparation
//! publishes nothing. Carrier-scoped statics (`publish_root_net_view`,
//! `grant_launch_capabilities`, the host process title) are overwritten by
//! the next `prepare`; Phase B moves them onto `Container`.

use std::path::PathBuf;
use std::sync::Arc;

use camino::Utf8PathBuf;
use carrick_spec::{FsBackendKind, PidMode, Platform, RunSpec, StdioMode};

pub use crate::dispatch::StdioSink;
use crate::dispatch::SyscallDispatcher;
use crate::execute::{
    HostRootLayout, cached_lower_enabled, detached_stable_scratch_path,
    effective_guest_hostname, entrypoint_not_executable_result, entrypoint_not_found_result,
    install_rosetta_mounts, is_entrypoint_not_executable, is_entrypoint_not_found,
    prepare_host_root, record_detached_scratch, rosetta_license_notice, seed_guest_baseline,
};
use crate::fs_backend::HostFsBackend;
use crate::interactive_supervisor::InteractiveSession;
use crate::kernel::container::LaunchContext;
use crate::network::RuntimeNetwork;
use crate::runtime::{RunResult, RuntimeError, run_elf_from_dispatcher_debug};
use crate::vfs::{BindVfs, HostResolverSnapshot, Vfs};

pub struct Runtime;

/// Launch-time PID-namespace placement, withdrawn when this guard drops —
/// on a failed `prepare` and again when `execute` returns — so the request
/// never leaks into the next run in the same carrier.
struct PidPlacement {
    requested: bool,
}

impl PidPlacement {
    fn for_mode(mode: PidMode) -> Self {
        match mode {
            // `--pid=host`: share the host pid ns — no placement.
            PidMode::Host => Self { requested: false },
            // Container launch: the root guest sees getpid()==1, ns-local
            // child pids and an ns-filtered /proc (docs/namespaces-design.md
            // §1.0, §5.2). Placement is initialized inside the single VM
            // carrier at boot; no host process is ever created for it.
            PidMode::Private => {
                crate::namespace::pid::request();
                Self { requested: true }
            }
        }
    }
}

impl Drop for PidPlacement {
    fn drop(&mut self) {
        if self.requested {
            crate::namespace::pid::withdraw_request();
        }
    }
}

/// Everything `prepare` resolves before it touches the filesystem: page
/// geometry, the host resolver snapshot, PID placement, the network lease and
/// the verbatim environment. Owns the [`LaunchContext`].
pub struct ExecutionPlan {
    launch: LaunchContext,
    page: crate::page_profile::ExecutionPlan,
    host_resolver: Option<HostResolverSnapshot>,
    network: Arc<RuntimeNetwork>,
    placement: PidPlacement,
    env: Vec<String>,
}

impl ExecutionPlan {
    pub fn launch(&self) -> &LaunchContext {
        &self.launch
    }
}

pub fn resolve_plan(spec: &RunSpec, launch: LaunchContext) -> Result<ExecutionPlan, RuntimeError> {
    let page = crate::page_profile::resolve_execution_plan(spec)?;
    debug_assert_eq!(
        page.page_geometry.linux_page_size,
        crate::page_profile::DEFAULT_LINUX_PAGE_SIZE
    );
    let host_resolver = HostResolverSnapshot::capture_for_network(&spec.network)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let placement = PidPlacement::for_mode(spec.pid);
    // Name the host process `carrick: <argv>` up front so it's identifiable in
    // ps/Activity Monitor even before the guest sets its own comm via prctl.
    {
        let cmdline = spec.argv.join(" ");
        crate::dispatch::set_host_process_name(cmdline.as_bytes());
    }
    let network = Arc::new(
        RuntimeNetwork::create(&spec.network)
            .map_err(|e| RuntimeError::Unsupported(format!("network setup failed: {e}")))?,
    );
    // The environment is already fully resolved by the engine layer (image
    // ENV + baseline defaults + overrides, docker precedence). Pass it through
    // verbatim: a second baseline here would place duplicate keys BEFORE
    // spec.envp and glibc's getenv returns the first match.
    Ok(ExecutionPlan {
        launch,
        page,
        host_resolver,
        network,
        placement,
        env: spec.envp.clone(),
    })
}

/// Embedder-supplied additions, applied between dispatcher construction and
/// boot. Builder-style; moved into [`Runtime::prepare`], so nothing can be
/// added after preparation.
#[derive(Default)]
pub struct RuntimeExtensions {
    vfs_mounts: Vec<(Utf8PathBuf, Box<dyn Vfs>)>,
    stdio: Option<StdioSink>,
}

impl RuntimeExtensions {
    /// Mount `vfs` at the absolute guest path `target` (longest prefix wins,
    /// shadowing the image and any `RunSpec` bind mount at the same point).
    pub fn vfs_mount(mut self, target: Utf8PathBuf, vfs: Box<dyn Vfs>) -> Self {
        self.vfs_mounts.push((target, vfs));
        self
    }

    /// The caller-owned sink for a `StdioMode::Piped` run (Task 22). For
    /// `Inherit`/`Captured` the `RunSpec::stdio` mode alone is authoritative
    /// and supplying a sink here is a `RuntimeError::Configuration` (see
    /// `resolve_stdio`) — never a silent override of the spec.
    pub fn stdio(mut self, sink: StdioSink) -> Self {
        self.stdio = Some(sink);
        self
    }
}

/// Reconcile the spec's output mode with the extension sink. The spec is the
/// engine's contract, the sink is the embedder's; they must say the same
/// thing, and a tty run streams by definition.
fn resolve_stdio(spec: &RunSpec, ext: Option<StdioSink>) -> Result<StdioSink, RuntimeError> {
    if spec.tty && spec.stdio != StdioMode::Inherit {
        return Err(RuntimeError::Configuration(format!(
            "tty runs stream to the carrier's terminal; StdioMode::{:?} is not a tty mode",
            spec.stdio
        )));
    }
    match (spec.stdio, ext) {
        (StdioMode::Inherit, None) => Ok(StdioSink::Inherit),
        (StdioMode::Captured, None) => Ok(StdioSink::Captured),
        (StdioMode::Piped, _) => Err(RuntimeError::Configuration(
            "StdioMode::Piped: the dispatcher has no caller-owned sink; use Inherit or Captured"
                .to_owned(),
        )),
        (mode, Some(_)) => Err(RuntimeError::Configuration(format!(
            "RuntimeExtensions::stdio conflicts with RunSpec stdio mode {mode:?}"
        ))),
    }
}

enum RootBacking {
    Host,
    #[cfg(feature = "fs-memory")]
    Memory { rootfs: crate::rootfs::RootFs },
}

/// A fully built container waiting to boot. Single-use: `execute` takes
/// `self`. Field order is drop order — the dispatcher (which owns the fs
/// backend and the network lease) first, then the terminal restore, then the
/// placement guard.
pub struct PreparedRun {
    executable: String,
    argv: Vec<String>,
    env: Vec<String>,
    max_traps: usize,
    debug_state_path: Option<PathBuf>,
    root: RootBacking,
    dispatcher: SyscallDispatcher,
    interactive_session: Option<InteractiveSession>,
    placement: PidPlacement,
}

/// The first two setters both fs backends apply, in the order `execute.rs`
/// applied them: page geometry, then the UTS nodename.
fn configure_page_and_hostname(
    dispatcher: &mut SyscallDispatcher,
    plan: &ExecutionPlan,
    guest_hostname: &str,
) {
    dispatcher.set_page_geometry(plan.page.page_geometry);
    dispatcher.set_guest_hostname(guest_hostname);
}

/// Initial cwd, credentials and the launch-time syscall policy, in the order
/// `execute.rs` applied them. The host backend calls
/// `sandbox_exec_to_container` + `set_executable_path` between this and
/// [`configure_page_and_hostname`], exactly where `execute.rs` did.
fn configure_identity_and_policy(dispatcher: &mut SyscallDispatcher, spec: &RunSpec) {
    if let Some(cwd) = &spec.cwd {
        dispatcher.set_cwd(cwd.as_str());
    }
    dispatcher.set_credentials(spec.uid, spec.gid);
    // Launch-time container syscall policy (the Docker default-seccomp model,
    // or unconfined) — before boot, inherited by the whole guest process tree.
    dispatcher.apply_launch_privileges(spec.seccomp_policy, &spec.cap_add);
}

fn install_spec_mounts(dispatcher: &mut SyscallDispatcher, spec: &RunSpec) {
    for mount in &spec.mounts {
        let host_path = PathBuf::from(mount.source.as_std_path());
        let target_path = PathBuf::from(mount.target.as_std_path());
        let bind_vfs = BindVfs::new(mount.target.as_str(), host_path, mount.readonly);
        dispatcher.register_mount(target_path, Box::new(bind_vfs));
    }
    if spec.platform == Platform::Amd64 {
        install_rosetta_mounts(dispatcher);
    }
}

fn layer_paths(spec: &RunSpec) -> Vec<PathBuf> {
    spec.rootfs_layers
        .iter()
        .map(|p| PathBuf::from(p.as_std_path()))
        .collect()
}

/// `--fs host`: stream every OCI layer onto the cap-std scratch Dir. An
/// `exec_overlay` ATTACHES a running container's existing overlay and skips
/// extraction; a managed container gets a STABLE overlay under its registry
/// dir; a foreground run gets an ephemeral per-run TempDir.
fn prepare_host_backend(
    spec: &RunSpec,
    plan: &ExecutionPlan,
) -> Result<SyscallDispatcher, RuntimeError> {
    let exec_overlay = plan.launch.exec_overlay.as_ref();
    let managed_scratch = match exec_overlay {
        Some(_) => None,
        None => plan
            .launch
            .registry_id()
            .and_then(|id| detached_stable_scratch_path(id).map(|path| (id.to_owned(), path))),
    };
    let mut host = if let Some(scratch) = exec_overlay {
        HostFsBackend::attach(scratch.as_std_path()).map_err(|e| {
            RuntimeError::FsBackend(anyhow::anyhow!(
                "failed to attach container overlay {scratch}: {e}"
            ))
        })?
    } else if let Some((_, scratch)) = &managed_scratch {
        HostFsBackend::attach_or_create(scratch).map_err(|e| {
            RuntimeError::FsBackend(anyhow::anyhow!("failed to create container overlay: {e}"))
        })?
    } else {
        HostFsBackend::new().map_err(|e| {
            RuntimeError::FsBackend(anyhow::anyhow!("failed to create scratch directory: {e}"))
        })?
    };

    // Darwin native runs bind the once-extracted digest-keyed cache directly
    // as an immutable lower and leave this run's host root sparse; the exact
    // `CARRICK_FS_CACHED_LOWER=0` hatch keeps the full-root extraction path.
    let cache_root = crate::fs_backend::default_scratch_root().map_err(|error| {
        RuntimeError::FsBackend(anyhow::anyhow!(
            "failed to locate rootfs cache directory: {error}"
        ))
    })?;
    let root_layout = prepare_host_root(
        &mut host,
        &layer_paths(spec),
        exec_overlay.is_some(),
        cached_lower_enabled(&plan.page),
        &cache_root,
    )
    .map_err(|error| {
        RuntimeError::FsBackend(anyhow::anyhow!("failed to prepare OCI rootfs: {error}"))
    })?;
    // The overlay exists and holds a prepared root: NOW it is safe to tell the
    // registry where it is.
    if let Some((id, scratch)) = &managed_scratch {
        record_detached_scratch(id, scratch);
    }

    let mut dispatcher = SyscallDispatcher::with_network_and_host_resolver(
        Arc::clone(&plan.network),
        plan.host_resolver.as_ref(),
    );
    if let HostRootLayout::CachedLower(rootfs) = root_layout {
        dispatcher.set_rootfs_layer(rootfs);
    }
    let guest_hostname = effective_guest_hostname(spec);
    configure_page_and_hostname(&mut dispatcher, plan, guest_hostname.as_ref());
    // Sandboxed container fs: forbid the execve host-fs fallback so a target
    // absent from the container ENOENTs instead of escaping to the host.
    dispatcher.sandbox_exec_to_container();
    dispatcher.set_executable_path(spec.executable.clone());
    configure_identity_and_policy(&mut dispatcher, spec);

    let hosts_entries = plan.network.guest_hosts_entries().map_err(|e| {
        RuntimeError::Unsupported(format!("network hosts setup failed: {e}"))
    })?;
    seed_guest_baseline(
        &mut host,
        dispatcher.rootfs(),
        &spec.network,
        &hosts_entries,
        &spec.extra_hosts,
        guest_hostname.as_ref(),
    );
    install_spec_mounts(&mut dispatcher, spec);
    let _ = dispatcher.set_fs_backend(Box::new(host));
    Ok(dispatcher)
}

#[cfg(feature = "fs-memory")]
fn prepare_memory_backend(
    spec: &RunSpec,
    plan: &ExecutionPlan,
) -> Result<(SyscallDispatcher, crate::rootfs::RootFs), RuntimeError> {
    let rootfs = crate::rootfs::RootFs::from_layer_paths(&layer_paths(spec)).map_err(|e| {
        RuntimeError::FsBackend(anyhow::anyhow!("failed to compose rootfs: {e}"))
    })?;
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(
        rootfs.clone(),
        spec.executable.clone(),
    );
    if let Some(snapshot) = plan.host_resolver.as_ref() {
        dispatcher.set_host_resolver_snapshot(snapshot);
    }
    let guest_hostname = effective_guest_hostname(spec);
    configure_page_and_hostname(&mut dispatcher, plan, guest_hostname.as_ref());
    configure_identity_and_policy(&mut dispatcher, spec);
    crate::execute::install_fs_backend(
        &mut dispatcher,
        FsBackendKind::Memory,
        guest_hostname.as_ref(),
    )
    .map_err(|e| RuntimeError::FsBackend(anyhow::anyhow!("failed to install fs backend: {e}")))?;
    install_spec_mounts(&mut dispatcher, spec);
    Ok((dispatcher, rootfs))
}

impl Runtime {
    /// Build the container and stop just short of booting it. On any error
    /// every host mapping, mount, lease and registry publication made so far
    /// is undone (module doc: Rollback).
    pub fn prepare(
        spec: &RunSpec,
        launch: LaunchContext,
        ext: RuntimeExtensions,
    ) -> Result<PreparedRun, RuntimeError> {
        let RuntimeExtensions { vfs_mounts, stdio } = ext;
        let sink = resolve_stdio(spec, stdio)?;
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
        }
        let plan = resolve_plan(spec, launch)?;

        let (mut dispatcher, root) = match spec.fs_backend {
            FsBackendKind::Host => (prepare_host_backend(spec, &plan)?, RootBacking::Host),
            #[cfg(feature = "fs-memory")]
            FsBackendKind::Memory => {
                let (dispatcher, rootfs) = prepare_memory_backend(spec, &plan)?;
                (dispatcher, RootBacking::Memory { rootfs })
            }
        };

        // Extensions go in after the image, bind and rosetta mounts so an
        // embedder's mount at the same point shadows them (re-mount replaces).
        for (target, vfs) in vfs_mounts {
            dispatcher.register_mount(PathBuf::from(target.as_std_path()), vfs);
        }
        dispatcher.set_stream_stdio(matches!(sink, StdioSink::Inherit));
        let interactive_session = if spec.tty {
            Some(InteractiveSession::start(&mut dispatcher).map_err(|e| {
                RuntimeError::FsBackend(anyhow::anyhow!(
                    "failed to create carrier-local interactive PTY: {e}"
                ))
            })?)
        } else {
            None
        };

        let ExecutionPlan {
            placement, env, ..
        } = plan;
        Ok(PreparedRun {
            executable: spec.executable.clone(),
            argv: spec.argv.clone(),
            env,
            max_traps: spec.max_traps,
            debug_state_path: spec
                .debug_state_path
                .as_ref()
                .map(|p| PathBuf::from(p.as_std_path())),
            root,
            dispatcher,
            interactive_session,
            placement,
        })
    }

    /// The CLI seam: prepare with the process-environment launch context and
    /// no extensions, then execute.
    pub fn execute(spec: &RunSpec) -> Result<RunResult, RuntimeError> {
        Self::prepare(
            spec,
            LaunchContext::from_process_env()?,
            RuntimeExtensions::default(),
        )?
        .execute()
    }
}

/// runc/shell exit conventions for a failed entrypoint load: 127 for "not
/// found", 126 for "found but not executable"; a configuration-time refusal
/// passes through unwrapped so it surfaces labeled as what it is.
fn classify_run_outcome(
    run: Result<RunResult, RuntimeError>,
    label: &str,
) -> Result<RunResult, RuntimeError> {
    match run {
        Ok(result) => Ok(result),
        Err(e) if is_entrypoint_not_found(&e) => Ok(entrypoint_not_found_result()),
        Err(e) if is_entrypoint_not_executable(&e) => Ok(entrypoint_not_executable_result()),
        Err(e @ RuntimeError::Configuration(_)) => Err(e),
        Err(e) => Err(RuntimeError::FsBackend(anyhow::anyhow!("{label}: {e}"))),
    }
}

impl PreparedRun {
    /// Boot the container and run it to completion. Consumes the run: a second
    /// execute is a compile error.
    ///
    /// ```compile_fail
    /// # use carrick_runtime::PreparedRun;
    /// fn twice(run: PreparedRun) {
    ///     let _ = run.execute();
    ///     let _ = run.execute(); // error[E0382]: use of moved value: `run`
    /// }
    /// ```
    pub fn execute(self) -> Result<RunResult, RuntimeError> {
        let PreparedRun {
            executable,
            argv,
            env,
            max_traps,
            debug_state_path,
            root,
            dispatcher,
            interactive_session,
            placement,
        } = self;
        let run = match root {
            RootBacking::Host => classify_run_outcome(
                run_elf_from_dispatcher_debug(
                    &executable,
                    dispatcher,
                    argv,
                    env,
                    max_traps,
                    debug_state_path.as_ref(),
                ),
                "failed to run ELF from dispatcher",
            ),
            #[cfg(feature = "fs-memory")]
            RootBacking::Memory { rootfs } => classify_run_outcome(
                crate::runtime::run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
                    &executable,
                    &rootfs,
                    dispatcher,
                    argv,
                    env,
                    max_traps,
                    debug_state_path.as_ref(),
                ),
                "failed to run rootfs ELF",
            ),
        };
        // The guest is gone: give the carrier its terminal back, then release
        // the placement request for the next run in this carrier.
        drop(interactive_session);
        drop(placement);
        run
    }
}
```

- [ ] **Step 7: Build and run the new tests (green)**

Run: `cargo test -p carrick-runtime --lib prepare:: -- --test-threads=1`
Expected: `test result: ok. 5 passed` (`prepared_run_is_single_use_and_extensions_seal_at_prepare`, `stdio_mode_and_extension_must_agree`, `prepare_failure_withdraws_pid_placement`, `execute_releases_pid_placement_after_the_run`, `hvpatch_uses_container_entrypoint_resolution`). The two placement tests need no HVF: the missing layer fails in `layer_cache::acquire_immutable_entry` → `stack_key`'s `std::fs::metadata(path)?` (`layer_cache.rs:52`, `:205`; or in `extract_layers` under the `CARRICK_FS_CACHED_LOWER=0` hatch) before any VM, and the missing `/bin/sh` fails in `resolve_entrypoint_program` (`runtime.rs:476`) before `hv_vm_create`.

Run: `cargo test -p carrick-runtime --doc prepare`
Expected: `test crates/carrick-runtime/src/prepare.rs - prepare::PreparedRun::execute (line N) - compile fail ... ok`.

- [ ] **Step 8: Wire the doctest into a gate and assert the dead env branch is gone**

`just test` runs `--lib --bins` only (`justfile:203`), so add the doctest to `test-integration`. In `justfile`, replace

```
        cargo test -p carrick-runtime --test integration
        cargo test -p carrick-runtime --test syscall_process
```

with

```
        cargo test -p carrick-runtime --test integration
        cargo test -p carrick-runtime --test syscall_process
        # `PreparedRun::execute(self)` single-use contract is a compile_fail
        # doctest; `just test`'s `--lib --bins` never runs doctests.
        cargo test -p carrick-runtime --doc prepare
```

Run: `rg -n "CARRICK_JOIN_REGION|join_existing|setup_interactive_stdio|detached_stable_scratch\(\)" crates/`
Expected: no output (before this task: `execute.rs:224,227`, `pid.rs:610`, `execute.rs:383,452,721`, `execute.rs:81,272`).

Run: `rg -n "Runtime::execute" crates/carrick-cli/src/commands.rs crates/carrick-cli/src/lifecycle.rs`
Expected: the three existing call sites (`commands.rs:1018`, `commands.rs:2848`, `lifecycle.rs:601`) unchanged — the wrapper keeps the CLI seam byte-identical.

- [ ] **Step 9: Full gate**

Run: `just fmt && just clippy && just doc && just test`
Expected: clippy clean under `-D warnings` (no unused imports left in `execute.rs`); `just doc` clean (the module doc links only public items — `PidPlacement` is mentioned in plain backticks because a `[link]` to a private item trips `rustdoc::private_intra_doc_links` under `-D warnings`); `just test` green, including `crates/carrick-runtime/src/execute.rs` `exit_code_tests` and `namespace::pid` tests.

- [ ] **Step 10: Commit**

```bash
git add crates/carrick-runtime/src/prepare.rs crates/carrick-runtime/src/execute.rs \
  crates/carrick-runtime/src/lib.rs crates/carrick-runtime/src/namespace/pid.rs \
  crates/carrick-runtime/src/dispatch/fs/state.rs crates/carrick-runtime/src/dispatch/fs.rs \
  crates/carrick-runtime/src/dispatch/mod.rs justfile
git commit -m "refactor(runtime): split Runtime::execute into prepare and execute phases

Why: Runtime::execute was one 320-line function that resolved the plan,
built the dispatcher (rootfs, mounts, network, policy, stdio) and booted
the guest in a single breath, so nothing could be injected between
dispatcher construction and boot and nothing could inspect a prepared
container. carrick-embed needs exactly that seam (RuntimeExtensions), and
the CLI needs the same runtime path to stay byte-identical.

What: crates/carrick-runtime/src/prepare.rs owns the lifecycle:
resolve_plan (page geometry, resolver snapshot, PID placement, network
lease) -> Runtime::prepare (fs backend, dispatcher, seeding, spec + rosetta
+ extension mounts, stdio mode, tty session) -> PreparedRun::execute(self)
(the trap loop plus the 127/126/Configuration classification).
Runtime::execute is the wrapper: prepare(spec,
LaunchContext::from_process_env()?, RuntimeExtensions::default())?.execute().
Every dispatcher setter runs in the order execute.rs ran it.
- Preparation rolls back on failure through Drop: a new PidPlacement
  guard withdraws namespace::pid::request() (new withdraw_request), the
  Arc<RuntimeNetwork> destroys its lease, a fresh HostFsBackend reclaims
  its scratch, InteractiveSession restores fds 0-2. The registry
  scratch_path record is written only AFTER attach_or_create and
  prepare_host_root succeed (it was written before either).
- StdioSink { Captured, Inherit } names the output mode; RunSpec::stdio
  and RuntimeExtensions::stdio must agree (Configuration error otherwise).
  StdioMode::Piped is refused until the sink seam lands.
- Deleted the dead CARRICK_JOIN_REGION branch and namespace::pid::
  join_existing: nothing sets the variable since carrick exec moved to
  the carrier control endpoint.
- Deleted the tokio-runtime debug_assert guardrail: it guarded a host
  fork inside the interactive path that no longer exists (InteractiveSession
  is carrier-local dup2), and the embed API executes a PreparedRun inside
  spawn_blocking, where a tokio handle is live by design.
- Both fs-backend arms are kept (Memory stays behind fs-memory).

Verified: new prepare:: unit tests (placement withdrawn on a failed
prepare and after execute; stdio agreement; Send + single-use API), the
compile_fail doctest on PreparedRun::execute now run by
just test-integration, the moved hvpatch_uses_container_entrypoint_
resolution test, just clippy, just doc, just test.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

### Task 28: dispatcher-held `StdioSink` — replace the direct `libc::write(1/2)` stream flag with `Captured` / `Inherit` / `Piped`

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fs/state.rs:212-260` (`StdioSink` gains `Piped`; `RuntimeIo` holds a route), `:440-457` (tests)
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs:5187-5196` (doc), `:5773-5794` (`write_output_fd_inner`), `:7675-7678` (`F_SETFL`), `:9341-9342` (comment), `:12784-12800` (`write`), `:13193-13214` (`writev`)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:5390-5411` (`set_stream_stdio` → `set_stdio_sink`; delete `stream_stdio_enabled`)
- Modify: `crates/carrick-runtime/src/interactive_supervisor.rs:49`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:1014` (external-exec child)
- Modify: `crates/carrick-cli/src/commands.rs:609-611` (run-elf `--raw`), `:1061-1064` (`--json` note)
- Modify: `crates/carrick-runtime/src/prepare.rs` (`resolve_stdio`, the `set_stream_stdio` call, tests)
- Modify: `crates/carrick-runtime/src/run_result.rs:72-76` (doc)
- Test: `crates/carrick-runtime/src/dispatch/fs/state.rs` (`stdio_sink_tests`), `crates/carrick-runtime/src/prepare.rs` (`mod tests`)

**Interfaces:**
- Consumes: `StdioSink { Captured, Inherit }`, `RuntimeExtensions::stdio`, `resolve_stdio` (Task 21); `carrick_spec::StdioMode::Piped` (Task 18); `crate::host_to_linux_errno(i32) -> LinuxErrno` (`lib.rs:481`); `DispatchOutcome::errno(LinuxErrno)` (`dispatch/mod.rs:1947`); `crate::linux_abi` = `carrick_abi` (`lib.rs:151`), `LINUX_EPIPE` at `carrick-abi/src/lib.rs:3099`.
- Produces:
  ```rust
  // crates/carrick-runtime/src/dispatch/fs/state.rs (re-exported as crate::dispatch::StdioSink / crate::prepare::StdioSink)
  pub enum StdioSink {
      Captured,
      Inherit,
      Piped { stdout: Box<dyn std::io::Write + Send>, stderr: Box<dyn std::io::Write + Send> },
  }
  // crates/carrick-runtime/src/dispatch/mod.rs
  impl SyscallDispatcher { pub fn set_stdio_sink(&self, sink: StdioSink); }
  ```
  `SyscallDispatcher::stdout()/stderr()` keep their signatures (`dispatch/mod.rs:5386`) and return the `Captured` buffers (empty under `Inherit`/`Piped`), so `RunResult::{stdout,stderr}` (`run_result.rs:101-102`, filled at `threaded_loop.rs:501-502`, `vcpu_loop/mod.rs:8347-8348` and `runtime.rs:881,952,968,1359,1372`) is populated exactly for `Captured` runs.

- [ ] **Step 1: Write the failing sink test (red)**

Append to `crates/carrick-runtime/src/dispatch/fs/state.rs` (after `mod fork_clone_tests`):

```rust
#[cfg(test)]
mod stdio_sink_tests {
    use super::*;
    use crate::compat::{CompatReporter, SyscallArgs};
    use std::sync::Arc;

    /// A `Write` that records into a shared buffer so the test can read back
    /// what the guest's write(2) delivered.
    struct Recorder(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Recorder {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn write_fd(dispatcher: &mut SyscallDispatcher, fd: u64, bytes: &[u8]) -> DispatchOutcome {
        const BUF: u64 = 0x4000;
        let mut memory = LinearMemory::new(BUF, vec![0u8; 0x1000]);
        memory.write_bytes(BUF, bytes).unwrap();
        let reporter = CompatReporter::default();
        // Same two-phase-borrow idiom as tests/integration/address_space.rs:236.
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(64, SyscallArgs::from([fd, BUF, bytes.len() as u64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap()
    }

    #[test]
    fn write_to_fd1_and_fd2_lands_in_the_piped_sink_not_the_capture_buffer() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let err = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(Recorder(Arc::clone(&err))),
        });

        assert_eq!(
            write_fd(&mut dispatcher, 1, b"hello"),
            DispatchOutcome::Returned { value: 5 }
        );
        assert_eq!(
            write_fd(&mut dispatcher, 2, b"oops\n"),
            DispatchOutcome::Returned { value: 5 }
        );

        assert_eq!(&*out.lock(), b"hello");
        assert_eq!(&*err.lock(), b"oops\n");
        assert!(dispatcher.stdout().is_empty(), "piped bytes must not also be captured");
        assert!(dispatcher.stderr().is_empty());
    }

    #[test]
    fn captured_sink_fills_the_run_result_buffers() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Captured);
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"kept"),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(dispatcher.stdout(), b"kept");
    }

    #[test]
    fn piped_writer_errors_surface_as_the_guest_write_errno() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(libc::EPIPE))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_stdio_sink(StdioSink::Piped {
            stdout: Box::new(Broken),
            stderr: Box::new(std::io::sink()),
        });
        assert_eq!(
            write_fd(&mut dispatcher, 1, b"x"),
            DispatchOutcome::errno(crate::linux_abi::LINUX_EPIPE)
        );
    }

    #[test]
    fn forked_runtime_io_shares_the_piped_writer() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let parent = RuntimeIo::new();
        parent.set_sink(StdioSink::Piped {
            stdout: Box::new(Recorder(Arc::clone(&out))),
            stderr: Box::new(std::io::sink()),
        });
        let child = parent.fork_clone();
        let StdioRoute::Piped { stdout, .. } = child.route() else {
            panic!("a forked child must inherit the parent's piped route");
        };
        // UFCS: `std::io::Write` is not in scope in this module (nor via the
        // `dispatch` glob), and a trait import just for one call is noise.
        std::io::Write::write_all(&mut *stdout.lock(), b"child").unwrap();
        assert_eq!(&*out.lock(), b"child");
    }
}
```

Also update the existing `fork_clone_tests` case (it names the field this task deletes). Replace

```rust
    #[test]
    fn forked_runtime_io_starts_with_clean_output_and_preserves_stream_mode() {
        let parent = RuntimeIo::new();
        parent.stdout.lock().extend_from_slice(b"parent");
        *parent.stream_stdio.lock() = true;

        let child = parent.fork_clone();

        assert!(child.stdout.lock().is_empty());
        assert!(child.stderr.lock().is_empty());
        assert!(*child.stream_stdio.lock());
        assert_eq!(&*parent.stdout.lock(), b"parent");
    }
```

with

```rust
    #[test]
    fn forked_runtime_io_starts_with_clean_output_and_preserves_sink() {
        let parent = RuntimeIo::new();
        parent.stdout.lock().extend_from_slice(b"parent");
        parent.set_sink(StdioSink::Inherit);

        let child = parent.fork_clone();

        assert!(child.stdout.lock().is_empty());
        assert!(child.stderr.lock().is_empty());
        assert!(matches!(child.route(), StdioRoute::Inherit));
        assert_eq!(&*parent.stdout.lock(), b"parent");
    }
```

Run: `cargo test -p carrick-runtime --lib stdio_sink_tests --no-run`
Expected: compile errors `no variant named \`Piped\` found for enum \`StdioSink\``, `no method named \`set_stdio_sink\``, `cannot find type \`StdioRoute\`` — red.

- [ ] **Step 2: `RuntimeIo` holds a route instead of a bool**

In `crates/carrick-runtime/src/dispatch/fs/state.rs` replace the Task 21 enum and the `RuntimeIo` block

```rust
pub enum StdioSink {
    /// Buffer into `RunResult::{stdout,stderr}`; nothing reaches the host fds.
    Captured,
    /// Write through to the carrier's own host fds 1/2 — `docker run` shape,
    /// the CLI default (`StdioMode::Inherit`).
    Inherit,
}

/// Process-local output transport. Linux fd-table authority lives exclusively
/// in the captured Kernel [`crate::kernel::FileTable`].
pub(in crate::dispatch) struct RuntimeIo {
    pub stdout: Arc<Mutex<Vec<u8>>>,
    pub stderr: Arc<Mutex<Vec<u8>>>,
    /// When true, writes to fd 1/2 stream directly to host fds 1/2 instead of
    /// buffering into `stdout`/`stderr`.
    pub stream_stdio: Mutex<bool>,
    external_exec_capture: AtomicBool,
}

impl RuntimeIo {
    pub(in crate::dispatch) fn new() -> Self {
        Self {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            stream_stdio: Mutex::new(false),
            external_exec_capture: AtomicBool::new(false),
        }
    }

    pub(in crate::dispatch) fn fork_clone(&self) -> Self {
        let external_exec_capture = self.external_exec_capture.load(Ordering::Acquire);
        Self {
            // The host-fork child clears inherited buffered output before it
            // resumes. An in-process child starts with the same clean boundary.
            stdout: if external_exec_capture {
                Arc::clone(&self.stdout)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            stderr: if external_exec_capture {
                Arc::clone(&self.stderr)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            stream_stdio: Mutex::new(*self.stream_stdio.lock()),
            external_exec_capture: AtomicBool::new(external_exec_capture),
        }
    }
```

with

```rust
pub enum StdioSink {
    /// Buffer into `RunResult::{stdout,stderr}`; nothing reaches the host fds.
    Captured,
    /// Write through to the carrier's own host fds 1/2 — `docker run` shape,
    /// the CLI default (`StdioMode::Inherit`).
    Inherit,
    /// The caller's writers. Each guest write(2)/writev(2) to fd 1/2 runs the
    /// matching writer on the guest's own vCPU thread under a mutex: a writer
    /// that blocks blocks THAT guest write (and any sibling writing the same
    /// stream), exactly as a full pipe would. Writer errors come back to the
    /// guest as the host errno translated to Linux (EPIPE stays EPIPE).
    Piped {
        stdout: Box<dyn std::io::Write + Send>,
        stderr: Box<dyn std::io::Write + Send>,
    },
}

/// Shared writer for one piped stream: the same `Arc` is cloned into every
/// logical child so the whole process tree drains into one caller writer.
pub(in crate::dispatch) type SharedWriter = Arc<Mutex<Box<dyn std::io::Write + Send>>>;

/// The dispatcher-side form of [`StdioSink`]: cheap to clone (only `Arc`s), so
/// a write reads the route once and drops the lock BEFORE the possibly
/// blocking host/caller write.
#[derive(Clone)]
pub(in crate::dispatch) enum StdioRoute {
    Captured,
    Inherit,
    Piped {
        stdout: SharedWriter,
        stderr: SharedWriter,
    },
}

impl From<StdioSink> for StdioRoute {
    fn from(sink: StdioSink) -> Self {
        match sink {
            StdioSink::Captured => StdioRoute::Captured,
            StdioSink::Inherit => StdioRoute::Inherit,
            StdioSink::Piped { stdout, stderr } => StdioRoute::Piped {
                stdout: Arc::new(Mutex::new(stdout)),
                stderr: Arc::new(Mutex::new(stderr)),
            },
        }
    }
}

/// Process-local output transport. Linux fd-table authority lives exclusively
/// in the captured Kernel [`crate::kernel::FileTable`].
pub(in crate::dispatch) struct RuntimeIo {
    pub stdout: Arc<Mutex<Vec<u8>>>,
    pub stderr: Arc<Mutex<Vec<u8>>>,
    /// Where bare fd 1/2 writes go. `Captured` (the default) appends to
    /// `stdout`/`stderr` above.
    route: Mutex<StdioRoute>,
    external_exec_capture: AtomicBool,
}

impl RuntimeIo {
    pub(in crate::dispatch) fn new() -> Self {
        Self {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            route: Mutex::new(StdioRoute::Captured),
            external_exec_capture: AtomicBool::new(false),
        }
    }

    pub(in crate::dispatch) fn set_sink(&self, sink: StdioSink) {
        *self.route.lock() = StdioRoute::from(sink);
    }

    /// A snapshot of the route; the lock is released before the caller writes.
    pub(in crate::dispatch) fn route(&self) -> StdioRoute {
        self.route.lock().clone()
    }

    /// Whether fd 1/2 are the carrier's real host fds (the only mode in which
    /// a guest `F_SETFL` on stdio must reach the host descriptor).
    pub(in crate::dispatch) fn inherits_host_stdio(&self) -> bool {
        matches!(*self.route.lock(), StdioRoute::Inherit)
    }

    pub(in crate::dispatch) fn fork_clone(&self) -> Self {
        let external_exec_capture = self.external_exec_capture.load(Ordering::Acquire);
        Self {
            // The host-fork child clears inherited buffered output before it
            // resumes. An in-process child starts with the same clean boundary.
            stdout: if external_exec_capture {
                Arc::clone(&self.stdout)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            stderr: if external_exec_capture {
                Arc::clone(&self.stderr)
            } else {
                Arc::new(Mutex::new(Vec::new()))
            },
            // Same route object: a piped tree shares ONE caller writer.
            route: Mutex::new(self.route()),
            external_exec_capture: AtomicBool::new(external_exec_capture),
        }
    }
```

- [ ] **Step 3: One write helper in `fs.rs`; three call sites collapse onto it**

In `crates/carrick-runtime/src/dispatch/fs.rs`, above `fn write_all_stdio` (line 5187) insert

```rust
    /// Deliver a bare-stdio write (fd 1/2 with no `OpenDescription`) to the
    /// run's [`StdioSink`]. Reads the route once so no dispatcher lock is held
    /// across the blocking host or caller write.
    fn write_stdio_sink(&self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        #[cfg(feature = "trace-io")]
        if !bytes.is_empty() {
            eprintln!(
                "[IODBG] SINKWRITE fd={fd} n={} bytes={:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(64)]
            );
        }
        match self.io.route() {
            StdioRoute::Captured => {
                match fd {
                    1 => self.io.stdout.lock().extend_from_slice(bytes),
                    2 => self.io.stderr.lock().extend_from_slice(bytes),
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
                DispatchOutcome::Returned {
                    value: bytes.len() as i64,
                }
            }
            // BLOCKING-IO-OK: the inherited stdout/stderr (the user's
            // tty/pipe); blocking here is the correct backpressure.
            StdioRoute::Inherit => match fd {
                1 | 2 => Self::write_all_stdio(fd, bytes),
                _ => DispatchOutcome::errno(LINUX_EBADF),
            },
            // BLOCKING-IO-OK: the embedder's writer runs on this vCPU thread;
            // a blocking writer blocks this guest write, like a full pipe.
            StdioRoute::Piped { stdout, stderr } => {
                let writer = match fd {
                    1 => stdout,
                    2 => stderr,
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                };
                let mut writer = writer.lock();
                // UFCS: `std::io::Write` is not imported anywhere in this file
                // (no `use std::io` at all) and one call does not earn one.
                match std::io::Write::write_all(&mut *writer, bytes) {
                    Ok(()) => DispatchOutcome::Returned {
                        value: bytes.len() as i64,
                    },
                    Err(error) => DispatchOutcome::errno(crate::host_to_linux_errno(
                        error.raw_os_error().unwrap_or(libc::EIO),
                    )),
                }
            }
        }
    }
```

(`StdioRoute` is `pub(in crate::dispatch)` and arrives through the existing `use state::*;` glob at `fs.rs:191`; `fd` is already an `i32` at every call site — `Fd(pub i32)` is unwrapped by `let fd = fd.0;` at the top of both handlers.)

Site A — `write_output_fd_inner` (lines 5773–5794; the shared tail of `write_output_fd` / `write_output_fd_partial`, the sendfile and splice output path). Replace

```rust
        if *self.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
            // BLOCKING-IO-OK: streamed write to the inherited stdout/stderr
            // (the user's tty/pipe). Blocking here is the correct backpressure
            // and isn't a guest socket on the server path.
            #[cfg(feature = "trace-io")]
            if !bytes.is_empty() {
                eprintln!(
                    "[IODBG] STREAMWRITE fd={fd} n={} bytes={:02x?}",
                    bytes.len(),
                    &bytes[..bytes.len().min(64)]
                );
            }
            return Self::write_all_stdio(fd, bytes);
        }
        match fd {
            1 => self.io.stdout.lock().extend_from_slice(bytes),
            2 => self.io.stderr.lock().extend_from_slice(bytes),
            _ => return DispatchOutcome::errno(LINUX_EBADF),
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }
```

with

```rust
        self.write_stdio_sink(fd, bytes)
    }
```

Site B — `write` handler (lines 12784–12800; on this path `bytes.len() == length` — the two `bytes.truncate` calls at `:12612`/`:12659` are inside `open_file` arms that return before reaching here). Replace

```rust
            if *this.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
                // Stream bare stdio to the inherited stdout/stderr (the user's
                // tty/pipe) exactly like writev does — do NOT buffer it. Buffering
                // delays interactive output until process exit: busybox ash writes
                // its post-Enter newline to fd 2 via write(2), so buffering left the
                // newline stuck and the next command's output ran onto the prompt.
                return Ok(Self::write_all_stdio(fd, &bytes));
            }
            match fd {
                1 => this.io.stdout.lock().extend_from_slice(&bytes),
                2 => this.io.stderr.lock().extend_from_slice(&bytes),
                _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
            }

            Ok(DispatchOutcome::Returned {
                value: length as i64,
            })
```

with

```rust
            // Bare stdio goes to the run's sink exactly like writev does —
            // never buffered when the sink is live: busybox ash writes its
            // post-Enter newline to fd 2 via write(2), and buffering it left
            // the newline stuck until exit.
            Ok(this.write_stdio_sink(fd, &bytes))
```

Site C — `writev` handler (lines 13193–13214). Replace

```rust
                if *this.io.stream_stdio.lock() && (fd == 1 || fd == 2) {
                    // BLOCKING-IO-OK: streamed writev to the inherited stdout/
                    // stderr (the user's tty/pipe); blocking is correct backpressure.
                    // Full write loop — never drop the tail on an O_NONBLOCK slave.
                    match Self::write_all_stdio(fd, &bytes) {
                        DispatchOutcome::Returned { value } => {
                            total = total
                                .checked_add(value as usize)
                                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                            continue;
                        }
                        other => return Ok(other),
                    }
                }
                match fd {
                    1 => this.io.stdout.lock().extend_from_slice(&bytes),
                    2 => this.io.stderr.lock().extend_from_slice(&bytes),
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
                total = total
                    .checked_add(bytes.len())
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
```

with

```rust
                // Full write loop per iovec — never drop the tail on an
                // O_NONBLOCK slave; a hard error ends the writev.
                match this.write_stdio_sink(fd, &bytes) {
                    DispatchOutcome::Returned { value } => {
                        total = total
                            .checked_add(value as usize)
                            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    }
                    other => return Ok(other),
                }
```

Site D — `F_SETFL` (line 7678). Replace `if *this.io.stream_stdio.lock() {` with `if this.io.inherits_host_stdio() {`, and in the comment above it (line 7675) replace `stdio is wired to our host fds (stream_stdio / --raw),` with `stdio is wired to our host fds (StdioSink::Inherit),`. Line 9342: replace `(host fd stays open under stream_stdio so` with `(host fd stays open under StdioSink::Inherit so`. Line 5201 (`write_all_stdio` body comment): replace `release the stream_stdio lock before getting here` with `release the route lock before getting here`. Update the `write_all_stdio` doc (line 5187) first sentence to `Write ALL of \`bytes\` to an inherited stdio host fd (\`StdioSink::Inherit\`: the user's tty/pipe), looping until the whole buffer is queued.`

- [ ] **Step 4: Dispatcher API: `set_stdio_sink`, drop the bool setters, migrate every caller**

In `crates/carrick-runtime/src/dispatch/mod.rs` replace

```rust
    /// Enable live passthrough for fd 1/2. After this, `write`/`writev`
    /// to the stdio fds go straight to host fd 1/2 via `libc::write`
    /// instead of accumulating in the in-memory buffers — required for
    /// interactive prompts (`/ # `, cursor-position queries, etc.) to
    /// reach the user's terminal before the guest exits.
    pub fn set_stream_stdio(&self, on: bool) {
        *self.io.stream_stdio.lock() = on;
    }
```

with

```rust
    /// Choose where bare fd 1/2 writes go for this run (and every logical
    /// child forked from it). `Inherit` is required for interactive prompts
    /// (`/ # `, cursor-position queries) to reach the terminal before exit;
    /// `Captured` (the construction default) fills `RunResult`; `Piped` hands
    /// bytes to the embedder's writers. Set before boot.
    pub fn set_stdio_sink(&self, sink: StdioSink) {
        self.io.set_sink(sink);
    }
```

and delete

```rust
    /// Whether guest stdout/stderr are live inherited host descriptors. Native
    /// host self-reexec restores this execution-mode bit in the fresh dispatcher.
    pub fn stream_stdio_enabled(&self) -> bool {
        *self.io.stream_stdio.lock()
    }
```

(no caller: `rg -n "stream_stdio_enabled" crates/` returns only the definition).

`set_stream_stdio` has FOUR callers at HEAD; all four migrate, or the build breaks:

- `crates/carrick-runtime/src/interactive_supervisor.rs:49`: replace `        dispatcher.set_stream_stdio(true);` with `        dispatcher.set_stdio_sink(crate::dispatch::StdioSink::Inherit);`.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:1014` (the external-exec child, which must buffer into the parent-shared capture buffers that `enable_external_exec_capture` selects on the next line): replace `            child_dispatcher.set_stream_stdio(false);` with `            child_dispatcher.set_stdio_sink(crate::dispatch::StdioSink::Captured);`.
- `crates/carrick-cli/src/commands.rs:609-611` (run-elf `--raw`, an in-process dispatcher the CLI builds by hand): replace

  ```rust
            if raw {
                dispatcher.set_stream_stdio(true);
            }
  ```

  with

  ```rust
            if raw {
                dispatcher.set_stdio_sink(carrick_runtime::dispatch::StdioSink::Inherit);
            }
  ```

  (`carrick_runtime::dispatch` is `pub mod` at `lib.rs:121`, so the path resolves on every platform, unlike the `platform-macos`-gated crate-root re-export.)
- `crates/carrick-runtime/src/prepare.rs` — Step 5 below.

- [ ] **Step 5: `prepare.rs` maps the mode onto the sink and accepts `Piped`**

In `crates/carrick-runtime/src/prepare.rs` replace the `resolve_stdio` match

```rust
    match (spec.stdio, ext) {
        (StdioMode::Inherit, None) => Ok(StdioSink::Inherit),
        (StdioMode::Captured, None) => Ok(StdioSink::Captured),
        (StdioMode::Piped, _) => Err(RuntimeError::Configuration(
            "StdioMode::Piped: the dispatcher has no caller-owned sink; use Inherit or Captured"
                .to_owned(),
        )),
        (mode, Some(_)) => Err(RuntimeError::Configuration(format!(
            "RuntimeExtensions::stdio conflicts with RunSpec stdio mode {mode:?}"
        ))),
    }
```

with

```rust
    match (spec.stdio, ext) {
        (StdioMode::Inherit, None) => Ok(StdioSink::Inherit),
        (StdioMode::Captured, None) => Ok(StdioSink::Captured),
        (StdioMode::Piped, Some(sink @ StdioSink::Piped { .. })) => Ok(sink),
        (StdioMode::Piped, _) => Err(RuntimeError::Configuration(
            "StdioMode::Piped requires RuntimeExtensions::stdio(StdioSink::Piped { .. })"
                .to_owned(),
        )),
        (mode, Some(_)) => Err(RuntimeError::Configuration(format!(
            "RuntimeExtensions::stdio conflicts with RunSpec stdio mode {mode:?}"
        ))),
    }
```

and in `Runtime::prepare` replace `        dispatcher.set_stream_stdio(matches!(sink, StdioSink::Inherit));` with `        dispatcher.set_stdio_sink(sink);`. Also update the `RuntimeExtensions::stdio` doc: replace `The caller-owned sink for a \`StdioMode::Piped\` run (Task 22).` with `The caller-owned sink for a \`StdioMode::Piped\` run.`

Extend `stdio_mode_and_extension_must_agree` in `prepare.rs` tests — replace the `spec.tty = true;` block with

```rust
        spec.stdio = StdioMode::Piped;
        assert!(matches!(
            resolve_stdio(&spec, None),
            Err(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            resolve_stdio(&spec, Some(StdioSink::Captured)),
            Err(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            resolve_stdio(
                &spec,
                Some(StdioSink::Piped {
                    stdout: Box::new(std::io::sink()),
                    stderr: Box::new(std::io::sink()),
                })
            ),
            Ok(StdioSink::Piped { .. })
        ));
        spec.tty = true;
        spec.stdio = StdioMode::Captured;
        assert!(matches!(
            resolve_stdio(&spec, None),
            Err(RuntimeError::Configuration(_))
        ));
```

- [ ] **Step 6: Docs that lied about capture**

In `crates/carrick-runtime/src/run_result.rs` replace

```rust
/// What a finished guest run produced. The dispatcher buffers the guest's
/// stdout/stderr (fd 1/2); the driver flushes them to the host after the loop
/// returns. `report` / `trap_limit_hit` are the macOS compat-reporting fields;
/// the KVM loop fills `report` from its (stub) reporter and leaves
/// `trap_limit_hit` false (it surfaces the limit as `RuntimeError` instead).
```

with

```rust
/// What a finished guest run produced. `stdout`/`stderr` hold the guest's fd
/// 1/2 bytes ONLY for a `StdioSink::Captured` run; under `Inherit` they went
/// to the carrier's own fds and under `Piped` to the caller's writers, so both
/// are empty here. `report` / `trap_limit_hit` are the macOS compat-reporting
/// fields; the KVM loop fills `report` from its (stub) reporter and leaves
/// `trap_limit_hit` false (it surfaces the limit as `RuntimeError` instead).
```

In `crates/carrick-cli/src/commands.rs` replace

```rust
            // `--json`: opt into the legacy compat-report envelope on stdout.
            // Output already streamed live during the run (the engine runs every
            // container with raw/streaming stdio), so the envelope's stdout/
            // stderr fields are informational only.
```

with

```rust
            // `--json`: the compat-report envelope on stdout. The CLI runs the
            // container with `StdioMode::Inherit`, so the guest's bytes already
            // went straight to this process's fds 1/2 during the run and the
            // envelope's `stdout`/`stderr` fields are EMPTY; only a
            // `StdioMode::Captured` run (carrick-embed) populates them.
```

- [ ] **Step 7: Run the sink tests (green) and the grep assertion**

Run: `cargo test -p carrick-runtime --lib stdio_sink_tests -- --test-threads=1`
Expected: `test result: ok. 4 passed` (`write_to_fd1_and_fd2_lands_in_the_piped_sink_not_the_capture_buffer`, `captured_sink_fills_the_run_result_buffers`, `piped_writer_errors_surface_as_the_guest_write_errno`, `forked_runtime_io_shares_the_piped_writer`).

Run: `cargo test -p carrick-runtime --lib fork_clone_tests prepare:: -- --test-threads=1`
Expected: all green, including `stdio_mode_and_extension_must_agree` with its new `Piped` arms.

Run: `rg -n "stream_stdio|set_stream_stdio" crates/`
Expected: no output (HEAD has 20 occurrences across `dispatch/fs.rs` (6), `dispatch/fs/state.rs` (5), `dispatch/mod.rs` (4), `interactive_supervisor.rs` (1), `vcpu_loop/quiesce.rs` (1), `carrick-cli/src/commands.rs` (1), `execute.rs` (1, gone with Task 21), plus `prepare.rs` after Task 21).

- [ ] **Step 8: Prove `Inherit` is unchanged end to end (HVF, signed)**

This step needs a codesigned binary (Rule 0) and a live guest. Run:

```bash
just build
CARRICK_RUN_ID=t22-inherit target/release/carrick run --fs host ubuntu:24.04 sh -c 'echo out; echo err 1>&2; exit 7' > /tmp/t22.out 2> /tmp/t22.err; echo "status=$?"
cat /tmp/t22.out; cat /tmp/t22.err
scripts/sudo/kill.sh t22-inherit
```

Expected: `status=7`, `/tmp/t22.out` is exactly `out`, `/tmp/t22.err` is exactly `err` (plus carrick's own banner lines, if any, which were there before this task). Then the interactive pty path (the only other `Inherit` producer): `target/release/carrick run -t --fs host ubuntu:24.04 sh -c 'printf "prompt> "; read x; echo got:$x'`, type `hi` + Enter — expected `prompt> ` appears BEFORE input is typed (live streaming, not buffered to exit) and `got:hi` follows. Finally the run-elf `--raw` caller migrated in Step 4: `target/release/carrick run-elf --raw <any static aarch64 ELF that prints>` must still print live to the terminal.

- [ ] **Step 9: Full gate**

Run: `just fmt && just clippy && just test && just test-integration`
Expected: green. (`tests/integration/address_space.rs:235-244` keeps passing: `SyscallDispatcher::new()` defaults to `Captured`, so `dispatcher.stdout() == b"hello"`.)

- [ ] **Step 10: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/fs/state.rs crates/carrick-runtime/src/dispatch/fs.rs \
  crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/interactive_supervisor.rs \
  crates/carrick-runtime/src/vcpu_loop/quiesce.rs \
  crates/carrick-runtime/src/prepare.rs crates/carrick-runtime/src/run_result.rs \
  crates/carrick-cli/src/commands.rs
git commit -m "feat(runtime): route guest stdio through a dispatcher-held StdioSink

Why: guest fd 1/2 output had exactly two destinations, chosen by a bool
(stream_stdio): libc::write to the CARRIER's own host fds 1/2, or the
in-memory buffers behind RunResult.stdout/stderr. An embedding host
application cannot accept the first (it clobbers the host process's own
stdout) and cannot read the second until the run ends. There was no way
to hand the guest's bytes to a caller-owned writer at all.

What: StdioSink { Captured, Inherit, Piped { stdout, stderr } } replaces
the flag. The dispatcher holds a cheaply cloneable StdioRoute (Piped
writers behind Arc<Mutex<Box<dyn Write + Send>>>, shared by every logical
child through RuntimeIo::fork_clone) and one write_stdio_sink helper
serves write(2), writev(2) and the sendfile/splice output path
(write_output_fd_inner) that all previously open-coded the bool test.
Captured appends to the RunResult buffers; Inherit keeps the exact
write_all_stdio loop (EAGAIN-poll on an O_NONBLOCK pty slave, never drop
the tail); Piped runs the caller's writer on the guest's vCPU thread -- a
blocking writer blocks that guest write, like a full pipe, and writer
errors return as the translated errno. The route is read once per write
so no dispatcher lock is held across the blocking host/caller write.
F_SETFL on bare stdio reaches the host fd only under Inherit, as before.
All four set_stream_stdio callers migrate: Runtime::prepare maps
RunSpec::stdio onto the sink (StdioMode::Piped now requires and accepts
RuntimeExtensions::stdio(StdioSink::Piped)), the interactive PTY session
and run-elf --raw select Inherit, and the external-exec child in
vcpu_loop::quiesce selects Captured. stream_stdio_enabled had no callers
and is deleted. The RunResult and CLI --json docs no longer claim
stdout/stderr are informational: they are empty under the CLI's Inherit
mode and populated only for Captured runs.

Verified: red-first stdio_sink_tests (write(1)/write(2) via the
in-process dispatcher land in the Piped writers and not the capture
buffer; Captured fills RunResult; an EPIPE writer surfaces as EPIPE; a
forked RuntimeIo shares the piped writer), prepare:: stdio agreement
tests, rg shows zero stream_stdio occurrences, just clippy, just test,
just test-integration, and a signed carrick run of
sh -c 'echo out; echo err 1>&2; exit 7' (status 7, out/err on the right
host fds) plus an interactive -t prompt streaming before input and a
run-elf --raw guest still printing live.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

<details><summary>Verifier problems fixed in place (12) and claims still unverified (8)</summary>

- fixed: Tree revision: the brief names HEAD 3dc6cc72 but the checkout is ea0dac4c (the draft says it re-read at 39426141, two commits back). Every cited line range was re-verified at ea0dac4c and matches; none of the intervening commits (0265e5e4, ea0dac4c) touch the files this cluster edits. No change needed beyond noting it.
- fixed: Task 21 Step 5 (compile error under `--features fs-memory`): the replacement import list for execute.rs drops `carrick_spec::FsBackendKind`, but the retained `install_fs_backend` (execute.rs:524-556, kept under `#[cfg(feature = "fs-memory")]`) matches on `FsBackendKind::Memory` / `FsBackendKind::Host`. Fixed: keep `#[cfg(feature = "fs-memory")] use carrick_spec::FsBackendKind;`.
- fixed: Task 21 Step 5 (`-D warnings` failure): in `exit_code_tests` the only use of `FsBackendKind` is inside `hvpatch_run_spec` (execute.rs:757-781), so deleting that helper also orphans the `FsBackendKind` import; the draft's list of imports to drop omitted it. Fixed: the test import becomes `use carrick_spec::NetworkNamespaceSpec;`.
- fixed: Task 22 (build break): `rg -n stream_stdio crates/` at HEAD has 20 hits, not 17, and two of them are CALLERS of `set_stream_stdio` the draft never edits: `crates/carrick-cli/src/commands.rs:610` (run-elf `--raw`: `dispatcher.set_stream_stdio(true)`) and `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:1014` (external-exec child: `child_dispatcher.set_stream_stdio(false)`). Deleting the setter in Step 4 breaks both. Fixed: both added to Files, Step 4 (→ `set_stdio_sink(StdioSink::Inherit)` / `set_stdio_sink(StdioSink::Captured)`), the Step 7 rg expectation (20 occurrences across 6 files), and the commit's `git add`/body.
- fixed: Task 22 Interfaces: cites `vcpu_loop/mod.rs:8304-8305` as a `RunResult::{stdout,stderr}` fill site; that range is `TrapWatchdog` code. The real fill is `vcpu_loop/mod.rs:8347-8348` (plus `runtime.rs:881,952,968,1359,1372` on the non-HVPatch drivers). Fixed.
- fixed: Task 21 Step 6 (`just doc` failure): the prepare.rs module doc uses an intra-doc link `[`PidPlacement`]` to a PRIVATE item from a public module's docs; rustdoc's `private_intra_doc_links` warns even under `--document-private-items` ("this link resolves only because you passed --document-private-items"), and `just doc` runs with `RUSTDOCFLAGS="-D warnings"`. Fixed: plain backticks for `PidPlacement`; `HostFsBackend`/`InteractiveSession` links kept (both pub in pub modules and imported in prepare.rs).
- fixed: Task 21 Step 6 (false claim): `configure_shared` is documented as applying setters "in the order execute.rs applied them", but the draft moves `sandbox_exec_to_container` + `set_executable_path` AFTER `set_cwd`/`set_credentials`/`apply_launch_privileges` (execute.rs:325-338 has them between `set_guest_hostname` and `set_cwd`). Verified the setters are independent (dispatch/mod.rs:4966 sets a bool; :5009 writes `proc.executable_path`/`argv`; :5807 reads only policy/cap_add), so it is not a behaviour bug, but the claim is wrong and the CLI seam is supposed to be byte-identical. Fixed: split into `configure_page_and_hostname` + `configure_identity_and_policy` so both backends keep the exact original order.
- fixed: Task 21 Step 5 (silent behaviour change): deleting the `Runtime::execute` block also deletes the tokio-runtime `debug_assert!` guardrail (execute.rs:193-201) without saying so. Verified the reason it existed is gone (`InteractiveSession` is carrier-local dup2, no host fork — interactive_supervisor.rs:1-5, 21-55) and the shared contract's `ContainerBuilder::run` executes inside `tokio::task::spawn_blocking` where `Handle::try_current()` succeeds, so the assertion MUST go — but it has to be an explicit, recorded deletion. Fixed: stated in Step 5 and in the commit body.
- fixed: Task 22 Step 1/Step 3 (compile error): `std::io::Write` is not in scope in `dispatch/fs.rs` (no `use std::io` line at all) nor in `dispatch/fs/state.rs`, and `dispatch/mod.rs` (the glob source for both) does not import it either; the draft hedged with "add it if not already" for fs.rs and did nothing for the state.rs test that calls `.write_all`. Fixed: both call sites use UFCS `std::io::Write::write_all(&mut *writer, bytes)`, no import question.
- fixed: Task 21 Step 3 (stale doc): `namespace/pid.rs:71-74` documents `REQUESTED` as "Set by the container launch path (`Runtime::execute`)"; after this task the setter is `Runtime::prepare` via `PidPlacement`, and the flag is now also withdrawn. Fixed: doc updated in Step 3.
- fixed: Task 21 Rollback table / Step 8 (cosmetic refs): `InteractiveSession` restore cited as `interactive_supervisor.rs:58-107` — actual `restore` :57-70, `SessionSetupGuard::drop` :80-96, `InteractiveSession::drop` :98-102 (fixed to :57-102). The Step 8 "before this task" list for `setup_interactive_stdio` gives only the definition (:721); the rg also matches the two call sites :383 and :452 (fixed).
- fixed: Task 21 Step 6 (misleading doc): `RuntimeExtensions::stdio` says the sink "must agree with `RunSpec::stdio`", yet `resolve_stdio` rejects `(Captured, Some(Captured))` — by design the extension sink exists only to carry `Piped` writers (Task 22). Fixed the doc to say exactly that; the arms and tests are unchanged.
- UNVERIFIED: Line numbers cited for dispatch/fs.rs and dispatch/mod.rs differ from the survey (survey: write path 5745-5764 / set_stream_stdio 5346; HEAD 39426141: 5773-5794 / 5395). All cited ranges were re-read at HEAD 39426141; the intervening Phase A/B/C1 tasks will shift them again -- the plan quotes the exact text, which is the anchor.
- UNVERIFIED: That `HostFsBackend::new()` + `prepare_host_root` fail cleanly (returning Err, no panic) for a nonexistent layer path in the red-first placement test: `layer_cache::stack_key` calls `std::fs::metadata(path)?` (layer_cache.rs:205) so the cached-lower path errors; the `CARRICK_FS_CACHED_LOWER=0` path goes through `HostFsBackend::extract_layers`, whose failure mode on a missing file was not read. The test asserts `RuntimeError::FsBackend(_)`, which both paths produce.
- UNVERIFIED: That `Runtime::prepare` with `rootfs_layers: []` and executable `/bin/sh` reaches `run_elf_from_dispatcher_debug` and classifies 127 WITHOUT touching the KernelArena/HVF (needed for `execute_releases_pid_placement_after_the_run` under `just test`). The existing in-lib test `hvpatch_uses_container_entrypoint_resolution` (execute.rs:892-901) already does exactly this with PidMode::Host and passes in `just test`; PidMode::Private only sets a flag until `run_address_space_with_hvf_and_dispatcher` (runtime.rs:621) which is after ELF resolution.
- UNVERIFIED: `PreparedRun: Send` -- SyscallDispatcher is moved into `Arc<KernelState>` shared across vCPU threads (threaded_loop.rs:324-331), so it must be Send+Sync, and InteractiveSession holds RawFds plus a PtyRelay thread handle; not proven by a compile in this read-only session. The `assert_send::<PreparedRun>()` test makes this a compile-time check.
- UNVERIFIED: `SyscallArgs::from([u64; 6])` and `SyscallRequest::new(u64, SyscallArgs)` are used exactly as in tests/integration/address_space.rs:238 and dispatch/tests.rs:1778; `DispatchOutcome: PartialEq` is relied on by existing tests (syscall_process.rs:26).
- UNVERIFIED: Whether `std::io::Write` is already imported in dispatch/fs.rs (needed for `write_all` on the piped writer) -- the step says to add it if absent.
- UNVERIFIED: The exact wording/presence of carrick's stderr banner on a signed `carrick run` (Task 22 Step 8 expected output) -- AGENTS.md mentions a one-line `--user "root"` banner; the assertion is on the guest lines `out`/`err` and exit status 7, not on the banner.
- UNVERIFIED: The Task 21 commit-message subject uses type `refactor(runtime)`; the change adds public API (prepare/PreparedRun) but is behaviour-preserving for the CLI seam.

</details>


<!-- cluster C3-embed-crate -->
## Cluster C3-embed-crate

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 23..24 -> 29..30), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] `LaunchContext` shape drift between producer B1 and consumers C2/C3: B1 adds a 5th pub FIELD `registry_id: Option<RegistryContainerId>`; C2 consumes a METHOD `LaunchContext::registry_id(&self) -> Option<&str>` ('Task 11 must provide it'); C3's `embedded_launch_context()` builds the contract's 4-field literal and would not compile. FIX: B1 adds `pub fn registry_id(&self) -> Option<&str>` (delegating to `RegistryContainerId::as_str`) -- C2 keeps its text; C3 prepared.rs uses `LaunchContext::unmanaged(RunId::new(run_id))` (B1-produced; allocates the ContainerId, exec_overlay/launch_authorization/registry_id = None) instead of a struct literal.
> - [ ] Carrier one-time init is unowned for embed: C3 consumes 'prepare (not the CLI) performs the idempotent carrier init `memory::init_alias_ipa_allocator()` + `fs_resolve_cache::init()` that commands.rs:960-963 does today', but C2's produces never mention it (verified: the pair is called only from carrick-cli commands.rs:565/958/2844). An embedded guest would run with neither initialized. FIX: C2 Task 21 adds to `Runtime::prepare`: idempotent `carrick_runtime::memory::init_alias_ipa_allocator(); carrick_runtime::fs_resolve_cache::init();` (guarded by a Once) and removes the three CLI call sites (one path); C2 produces records it; C1's Task 20 CLI edits must not re-add them.
> - [ ] The tokio `debug_assert!(Handle::try_current().is_err())` is deleted twice: A5 Task 7 deletes it and demotes tokio to a dev-dependency; C2 Task 21's commit body claims to delete it ('silently deletes ... added to the commit message') and says 'tokio stays a dependency because tests/integration/oci_layout.rs uses it'; C3 consumes its deletion as 'Phase A item 6'. FIX: C2 drops the deletion claim (it is gone after A5) and says 'tokio remains a dev-dependency (A5)'; C3 consumes text: 'deleted by A5 Task 7'.
> - [ ] Engine resolve signature: C1 produces `resolve_run_spec(req, image) -> Result<Resolved, String>` and `Engine::resolve(&self, req) -> Result<Resolved, anyhow::Error>` with `Resolved { spec: RunSpec, warnings: Vec<ResolveWarning> }` (and explicitly expects the embed cluster to read `.spec/.warnings`), but C3 consumes `Engine::resolve -> Result<RunSpec, anyhow::Error>` ('signature unchanged -- the OR keep signature branch') and `resolve_run_spec -> Result<RunSpec, String>`; `PreparedContainer`/parity tests would not compile. FIX: C3 adopts C1's shape: `let Resolved { spec, warnings } = engine.resolve(req).await.map_err(EmbedError::Image)?;` and exposes `PreparedContainer::warnings(&self) -> &[ResolveWarning]` (re-export `carrick_embed::ResolveWarning`); the lowering tests compare `resolve_run_spec(..)?.spec`.
> - [ ] C4 consumes a stale Phase-B VM lifecycle: 'sequential PreparedRun::execute calls in ONE carrier process work (the VM is destroyed at run terminal via destroy_persistent_vm_at_run_terminal and re-created)'. B4 renames that fn to `destroy_persistent_vm_at_carrier_exit()` (no alias) and changes the model: the VM persists across containers and is destroyed once at `carrier::shutdown()`/`exit_carrier`. C4's Task 26 red-first step and prose would look for a symbol that no longer exists. FIX: C4 consumes text -> 'B4: VM retained across sequential containers; `destroy_persistent_vm_at_carrier_exit` + `carrier::shutdown()`'; C3 must state that embed never calls `carrier::shutdown()/exit_carrier` (the host process owns exit; VM teardown at process exit is B4's idempotent atexit path) -- add to C3 deviations.
> - [ ] Embed error lowering is split across C3 and C4 without a handoff: C4 requires `EmbedError`'s RuntimeError lowering to delegate to `carrick_embed::entitlement::classify` (Task 25; 'Task 23 must not keep a second lowering') and `is_hv_denied` at the prepare-time `Prepare(_)` lowering, but C3 Task 23 lands first and never mentions entitlement.rs or how `Entitlement` is produced. FIX: C3 Task 23 introduces `entitlement.rs` with the two fns as the SINGLE lowering site (C4 Task 25 then only adds HV_DENIED_MARKER detection, tests and the negative control), or C3 states that Task 23's temporary `EmbedError::Runtime(err)` mapping lives in one private fn `lower_runtime_error` that Task 25 renames to `entitlement::classify`. Either way `PreparedContainer::execute` uses `classify` and `ContainerBuilder::prepare` uses `is_hv_denied`.
> - [ ] Two signed smoke suites for one crate: C3 produces `crates/carrick-embed/tests/guest_smoke.rs` (6 HVF cases, hand-run codesign in Step 12) and C4 produces `tests/signed_smoke.rs` ('runs four guests in one libtest process') + `tests/common/mod.rs` (`guest_lock`, `run_or_fail`, `run_id`, SMOKE_IMAGE) + `tests/entitlement_negative.rs`. Both are run by `scripts/test-signed.sh`, duplicating captured/inherit/piped/parity cases and the run-id handling (C3 generates a short id when CARRICK_RUN_ID is unset; C4's `run_id()` is fail-closed). FIX: C4 Task 26 extends C3's `guest_smoke.rs` (adding the CLI-parity and Piped cases and moving shared helpers into `tests/common/mod.rs`) instead of creating `signed_smoke.rs`; C3's Step 12 hand-run commands are replaced by 'until Task 25's `just test-embed` lands' wording; run-id policy: builder honours an explicit CARRICK_RUN_ID else mints one (C3), the test helper `run_id()` stays fail-closed (C4) -- both consistent.
> - [ ] C2 places `prepare.rs` (and therefore `Runtime::prepare`/`PreparedRun`/`RuntimeExtensions`) under `#[cfg(feature = "platform-macos")]`, while C3 forwards `platform-linux/freebsd/netbsd` features to carrick-runtime and consumes `carrick_runtime::Runtime::prepare` unconditionally, so `carrick-embed --no-default-features --features platform-linux` cannot compile. FIX: C2 makes prepare.rs platform-neutral (only the HVF-specific run path stays cfg-gated inside `PreparedRun::execute`), or C3 gates the crate's non-macOS features as 'compile-checked only' and cfg-gates `PreparedContainer::execute`; choose the former (opt-out rule).
> - [ ] C5's Gate C parity input and C3's `to_run_request` disagree on the comparison surface: C5 consumes 'Gate C parity test in crates/carrick-embed/tests/ comparing ContainerResult to the CLI RunResult for the same image/command (embed cluster)', C3 produces `to_run_request(&self)` for 'Gate C's CLI/embed RunSpec parity tests' (RunSpec equality, no guest), and C4's `just test-embed` depends on `build` because 'the CLI-parity test needs a signed target/release/carrick' (guest-running result parity). FIX: C3 records that the guest-running parity case (`carrick run --json` envelope exit_code/trap_limit_hit/stdout vs ContainerResult) lives in the signed smoke file owned by C4 Task 26, and C5 links that test by name; the RunSpec parity test stays in C3's no-HVF lib tests.
>
### Task 29: Create the `carrick-embed` crate (builder, result, error, prepared, testing)

> Tree references below were verified at HEAD `ea0dac4c` (the brief's `3dc6cc72` is two commits older; `carrick-vmm-hvf/src/trap.rs` and `carrick-cli/src/commands.rs` changed in between and their line numbers here are the current ones).

**Files:**
- Create: `crates/carrick-embed/Cargo.toml`
- Create: `crates/carrick-embed/src/lib.rs`
- Create: `crates/carrick-embed/src/error.rs`
- Create: `crates/carrick-embed/src/result.rs`
- Create: `crates/carrick-embed/src/builder.rs`
- Create: `crates/carrick-embed/src/prepared.rs`
- Create: `crates/carrick-embed/src/testing.rs`
- Create: `crates/carrick-embed/tests/guest_smoke.rs` (HVF guest; signed recipe only)
- Modify: `Cargo.lock` (cargo adds the new member automatically; `members = ["crates/*"]` at `Cargo.toml:3`)
- Test: in-file `#[cfg(test)]` modules of every `src/*.rs` (run by `just test`: its macOS branch is `cargo test --workspace --exclude … --lib --bins`, `justfile:148-203`), plus `tests/guest_smoke.rs` (run ONLY by the signed `just test-embed` recipe; `HV_DENIED` is a failure, never a skip)

**Interfaces:**
- Consumes (Task 19, engine): `carrick_engine::RunRequest` (`#[derive(Debug, Clone, Default)]`, fields `image_ref: String`, `platform: Option<String>`, `args: Vec<String>`, `entrypoint_override: Option<Vec<String>>`, `env_overrides: Vec<String>`, `host_env: Option<Vec<(String, String)>>`, `mounts: Vec<Mount>`, `workdir: Option<String>`, `user: Option<String>`, `hostname: Option<String>`, `max_traps: usize`, `pull: carrick_image::PullPolicy`, `stdio: carrick_spec::StdioMode`, `bridge_namespace_id: Option<String>`, remaining former `CliRunRequest` fields); `carrick_engine::Engine::new(ImageStore)`, `Engine::resolve(&self, RunRequest) -> Result<RunSpec, anyhow::Error>`, `carrick_engine::resolve_run_spec(RunRequest, ResolvedImage) -> Result<RunSpec, String>`, `carrick_engine::request_platform(&RunRequest) -> Platform`. **Prerequisite the Task 19 owner must satisfy:** today `CliRunRequest` derives only `Debug, Clone` (`crates/carrick-engine/src/lib.rs:97-98`) and `carrick_image::PullPolicy` (`crates/carrick-image/src/lib.rs:410-415`) has NO `Default` impl, so the contract's `#[derive(Default)]` on `RunRequest` needs `impl Default for PullPolicy { Missing }` (or a manual `Default`); this crate's `..RunRequest::default()` depends on it.
- Consumes (Task 19, spec): `carrick_spec::StdioMode { Inherit, Captured, Piped }` (`Copy`, `Default = Inherit`), `RunSpec.stdio: StdioMode` (replacing the `raw: true` hardcoded at `crates/carrick-engine/src/lib.rs:449` today).
- Consumes (Task 21/22, runtime): `carrick_runtime::prepare::{RuntimeExtensions, StdioSink, PreparedRun}`; `RuntimeExtensions::default()`, `RuntimeExtensions::stdio(self, StdioSink) -> Self`; `StdioSink::{Captured, Inherit, Piped { stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send> }}`; `carrick_runtime::Runtime::prepare(&RunSpec, LaunchContext, RuntimeExtensions) -> Result<PreparedRun, RuntimeError>`; `PreparedRun::execute(self) -> Result<RunResult, RuntimeError>`; `RuntimeExtensions: Send`. **Hard prerequisite:** `Runtime::execute` at `crates/carrick-runtime/src/execute.rs:197-201` carries `debug_assert!(tokio::runtime::Handle::try_current().is_err(), …)`. A `tokio::task::spawn_blocking` thread DOES have a runtime handle, so the contract's `ContainerBuilder::run` (and the Step 12 `async_run_executes_on_the_blocking_pool` case, a debug test binary) panics unless Task 21/22 confines that guard to the interactive host-fork path it protects. Confirm it is gone from the `prepare`/`execute` seam before running Step 12.
- Consumes (Phase B): `carrick_runtime::kernel::container::{LaunchContext, ContainerId, RunId}` with pub fields `container_id`, `run_id`, `exec_overlay`, `launch_authorization`; constructors `ContainerId::allocate() -> ContainerId` and `RunId::new(impl Into<String>) -> RunId` (assumed names; adapt in `embedded_launch_context()` only).
- Consumes (existing, verified in tree at `ea0dac4c`): `carrick_runtime::runtime::{RunResult, RuntimeError, DEFAULT_MAX_TRAPS}` (`run_result.rs:19-49, 76-107`; the `runtime` module is `runtime.rs` on macOS — re-exports at `runtime.rs:196`, `DEFAULT_MAX_TRAPS` at `runtime.rs:185` — and the inline `lib.rs:447-453` module on the other arms); `carrick_runtime::trap::TrapError::Hypervisor(String)` (`carrick-hal/src/trap.rs:299-303`; `crate::trap` is `carrick_vmm_hvf::trap` on macOS via `lib.rs:201-204` and the inline module at `lib.rs:265` elsewhere — `run_result.rs` itself uses `crate::trap::TrapError`, so the path resolves on both arms; `hvf_error` at `carrick-vmm-hvf/src/trap.rs:19821-19823` stringifies applevisor's `Display`, `"{} (error {:#08x})"` with `Denied => "operation not allowed by the system"` — applevisor-1.0.0 `error.rs:52,71,111-115` — so `HV_DENIED` prints `operation not allowed by the system (error 0xfae94007)`); `carrick_runtime::dispatch::Signal(pub i32)` (`Debug, Clone, Copy, PartialEq, Eq`; `dispatch/abi_args.rs:154-156`, re-exported at `dispatch/mod.rs:732`); `carrick_runtime::compat::CompatReport` (`Debug, Clone, Default, PartialEq, Eq`; `lib.rs:216` → `carrick-observability/src/compat.rs:414-415`); `carrick_runtime::container::{make_id(u64, u64) -> String, short_id(&str) -> &str}` (`container.rs:791-801`); `carrick_image::{ImageStore, PullPolicy, ResolvedImage}` (`ImageStore: Debug, Clone, PartialEq, Eq`; `ImageStore::new(impl AsRef<Path>)`, `default_for_user()`, `root() -> &Path`, `load_docker_archive(&Path)` at `lib.rs:112-131, 943-972`; `PullPolicy { Always, Missing, Never }` `Copy, PartialEq`; `ResolvedImage { layers: Vec<Utf8PathBuf>, config: ImageConfig }` at `lib.rs:583-587`); `carrick_spec::{Mount, Platform, RunSpec, ImageConfig}` (`Mount { source, target: Utf8PathBuf, readonly: bool }` at `lib.rs:187-192`; `ImageConfig` `Default` with `entrypoint/cmd/env/working_dir/user/…` at `lib.rs:172-185`; `Platform { Aarch64, Amd64 }` at `lib.rs:600-608` with `from_oci_str`/`oci_arch` at `lib.rs:759-780`; `RunSpec` is `PartialEq, Eq` at `lib.rs:818` with `argv`, `envp`, `cwd: Option<Utf8PathBuf>`, `rootfs_layers`, `mounts`, `max_traps`, `hostname: Option<String>`, `uid: carrick_abi::NsUid`, `gid: carrick_abi::NsGid` — both expose `.raw() -> u32`, NOT `.get()`).
- Produces:
  - `pub struct carrick_embed::ContainerBuilder` with `from_image`, `command`, `entrypoint`, `env`, `workdir`, `user`, `hostname`, `mount`, `mount_readonly`, `platform`, `pull_policy`, `image_store`, `stdout`, `stderr`, `max_traps`, `to_run_request(&self) -> Result<RunRequest, EmbedError>`, `async fn prepare(self) -> Result<PreparedContainer, EmbedError>`, `async fn run(self) -> Result<ContainerResult, EmbedError>`, `fn run_blocking(self) -> Result<ContainerResult, EmbedError>`.
  - `pub enum carrick_embed::StdioConfig { Captured, Inherit, Piped(Box<dyn std::io::Write + Send>) }`
  - `pub struct carrick_embed::ContainerResult { pub exit_code: i32, pub signal: Option<Signal>, pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub trap_limit_hit: bool, pub traps: usize, pub compat: CompatReport }` with `stdout_utf8`, `stderr_utf8`, `success`, `ensure_success(self) -> Result<Self, EmbedError>`.
  - `#[non_exhaustive] pub enum carrick_embed::EmbedError { Image(anyhow::Error), Config(String), Prepare(RuntimeError), Entitlement, Guest { exit_code: i32, signal: Option<Signal> }, TrapLimit, Runtime(RuntimeError), ExecutePanicked(String) }`
  - `pub struct carrick_embed::PreparedContainer` (no `Debug`: it owns a `RuntimeExtensions`) with `run_spec(&self) -> &RunSpec`, `execute(self) -> Result<ContainerResult, EmbedError>`.
  - `pub mod carrick_embed::testing { pub struct TestContainer; pub fn run_in_container(image: &str, cmd: &[&str]) -> Result<ContainerResult, EmbedError>; pub trait ResultAssert { fn assert_success(&self) -> &Self; fn assert_exit_code(&self, code: i32) -> &Self; fn assert_stdout_contains(&self, needle: &str) -> &Self; fn assert_stderr_contains(&self, needle: &str) -> &Self; } }`
  - Re-exports at the crate root: `RunRequest`, `ImageStore`, `PullPolicy`, `CompatReport`, `Signal`, `RunResult`, `RuntimeError`, `Mount`, `Platform`, `RunSpec`, `StdioMode`.

- [ ] **Step 1: Red — assert the workspace has no `carrick-embed` member yet**

```sh
cd /Volumes/CaseSensitive/carrick
cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; names=[p["name"] for p in json.load(sys.stdin)["packages"]]; print(names); sys.exit(0 if "carrick-embed" in names else 1)'
```
Expected: the printed list has no `carrick-embed`, exit status 1 (red).

- [ ] **Step 2: Create `crates/carrick-embed/Cargo.toml` mirroring the CLI's feature forwarding**

`crates/carrick-cli/Cargo.toml` forwards `syscall-shim = ["carrick-runtime/syscall-shim"]` and `platform-* = [..., "carrick-runtime/platform-*", "carrick-engine/platform-*"]` with `default = ["syscall-shim", "platform-macos"]`; `carrick-runtime/Cargo.toml` documents that `syscall-shim` has NO default on purpose ("dependents that use carrick-runtime as a library do not re-enable it through feature unification"), so the embed crate must forward it itself. `carrick-engine` has no `syscall-shim` feature (only `platform-*` and `fs-memory`), so that edge goes to the runtime alone. Unlike the CLI, embed never names `carrick-vmm-hvf`/`carrick-host-bsd` directly (it has no probes), so only the forwarding edges are needed. All eight `.workspace = true` dependencies below exist in `[workspace.dependencies]` (`tokio` there already carries `rt`, `rt-multi-thread`, `macros`).

```toml
[package]
name = "carrick-embed"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "carrick_embed"
path = "src/lib.rs"

[lints]
workspace = true

[features]
# Mirrors carrick-cli: an embedded guest must run with the SAME guest-side
# syscall shim and host backend as the shipped binary. carrick-runtime keeps
# `syscall-shim` default-OFF so library dependents choose explicitly — we choose
# ON, with `--no-default-features` as the escape hatch.
default = ["platform-macos", "syscall-shim"]
syscall-shim = ["carrick-runtime/syscall-shim"]
# Exactly one platform-* is active at a time (crates/README.md, Feature Closure
# Rules). Forwarded to the same two crates carrick-cli forwards to.
platform-macos = ["carrick-runtime/platform-macos", "carrick-engine/platform-macos"]
platform-linux = ["carrick-runtime/platform-linux", "carrick-engine/platform-linux"]
platform-freebsd = ["carrick-runtime/platform-freebsd", "carrick-engine/platform-freebsd"]
platform-netbsd = ["carrick-runtime/platform-netbsd", "carrick-engine/platform-netbsd"]
# In-memory fs backend selection (default OFF; same control-point rule as the CLI).
fs-memory = ["carrick-spec/fs-memory", "carrick-engine/fs-memory", "carrick-runtime/fs-memory"]

[dependencies]
carrick-engine = { path = "../carrick-engine", default-features = false }
carrick-runtime = { path = "../carrick-runtime", default-features = false }
# The engine re-exports neither PullPolicy nor the spec's StdioMode; take the
# two leaf crates directly rather than widening the engine's re-export list.
carrick-image = { path = "../carrick-image" }
carrick-spec = { path = "../carrick-spec" }
anyhow.workspace = true
camino.workspace = true
thiserror.workspace = true
tokio.workspace = true

[dev-dependencies]
tempfile.workspace = true
serde_json.workspace = true
tar.workspace = true
flate2.workspace = true
```

- [ ] **Step 3: Create the crate skeleton (`lib.rs` + empty modules) and prove feature closure**

`crates/carrick-embed/src/lib.rs`:

```rust
//! `carrick-embed`: run a containerized Linux workload from a Rust host
//! application, on Carrick's own kernel.
//!
//! ```text
//! ContainerBuilder
//!   -> carrick_engine::RunRequest -> Engine::resolve (async; tokio)   -> RunSpec
//!   -> Runtime::prepare(&RunSpec, LaunchContext, RuntimeExtensions)   -> PreparedRun
//!   -> PreparedRun::execute()                                         -> RunResult
//!   -> ContainerResult
//! ```
//!
//! The image-resolution half is async (the OCI store uses `tokio::fs` and
//! `oci-client`); the execution half is synchronous and blocking.
//! [`ContainerBuilder::run`] resolves on the ambient tokio runtime and executes
//! on its blocking pool; [`ContainerBuilder::run_blocking`] builds a throwaway
//! current-thread runtime for resolution, drops it, then executes directly.
//!
//! # Entitlement
//!
//! On macOS the executable that calls into this crate must carry the
//! `com.apple.security.hypervisor` entitlement (`scripts/entitlements.plist`);
//! an unsigned test or application binary fails with
//! [`EmbedError::Entitlement`] (`HV_DENIED`, `0xfae94007`). See AGENTS.md
//! Rule 0 and the signed `just test-embed` recipe.
//!
//! # Defaults
//!
//! Both stdio streams default to [`StdioConfig::Captured`] (a library caller
//! wants the bytes); the CLI's default is `Inherit`. No network mocking, VFS
//! injection, observers, time control or tty support is exposed in this
//! version — those arrive with later phases of the embed program
//! (`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`).
#![forbid(unsafe_code)]

mod builder;
mod error;
mod prepared;
mod result;
pub mod testing;

pub use builder::{ContainerBuilder, StdioConfig};
pub use error::EmbedError;
pub use prepared::PreparedContainer;
pub use result::ContainerResult;

pub use carrick_engine::RunRequest;
pub use carrick_image::{ImageStore, PullPolicy};
pub use carrick_runtime::compat::CompatReport;
pub use carrick_runtime::dispatch::Signal;
pub use carrick_runtime::runtime::{RunResult, RuntimeError};
pub use carrick_spec::{Mount, Platform, RunSpec, StdioMode};
```

For this step only, create each of `src/builder.rs`, `src/error.rs`, `src/prepared.rs`, `src/result.rs`, `src/testing.rs` containing just a `//!` line naming the module, and TEMPORARILY comment out the four `pub use builder::…`/`error`/`prepared`/`result` lines so the skeleton compiles. Then:

```sh
cd /Volumes/CaseSensitive/carrick
cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; names=[p["name"] for p in json.load(sys.stdin)["packages"]]; sys.exit(0 if "carrick-embed" in names else 1)' && echo member-ok
cargo check -p carrick-embed
# Feature closure: the linux arm must be HVF-free (scripts/closure-assert-no-hvf.sh only walks carrick-cli).
cargo tree -p carrick-embed --no-default-features --features platform-linux \
  --target aarch64-unknown-linux-gnu --edges normal | grep -Ei 'carrick-vmm-hvf|applevisor' ; echo "grep-exit=$?"
# The shim is forwarded by default:
cargo tree -p carrick-embed --edges features -i carrick-runtime | grep -c 'feature "syscall-shim"'
```
Expected: `member-ok`; `cargo check` finishes with no warnings; `grep-exit=1` (no HVF crate in the linux closure); the last count is `>= 1`.

- [ ] **Step 4: Red — `error.rs` tests**

Write `crates/carrick-embed/src/error.rs` with ONLY the test module first:

```rust
//! Typed failure surface of an embedded run.

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_runtime::runtime::RuntimeError;
    use carrick_runtime::trap::TrapError;

    #[test]
    fn trap_limit_maps_to_trap_limit_in_both_phases() {
        for phase in [Phase::Prepare, Phase::Execute] {
            let error = RuntimeError::TrapLimitExceeded { max_traps: 5 };
            assert!(matches!(
                EmbedError::from_runtime(error, phase),
                EmbedError::TrapLimit
            ));
        }
    }

    /// `carrick-vmm-hvf`'s `hvf_error` stringifies applevisor's Display, which
    /// prints `HV_DENIED` as `operation not allowed by the system (error 0xfae94007)`.
    #[test]
    fn hv_denied_maps_to_entitlement_regardless_of_phase() {
        for phase in [Phase::Prepare, Phase::Execute] {
            let error = RuntimeError::Trap(TrapError::Hypervisor(
                "operation not allowed by the system (error 0xfae94007)".to_string(),
            ));
            assert!(matches!(
                EmbedError::from_runtime(error, phase),
                EmbedError::Entitlement
            ));
        }
    }

    #[test]
    fn other_hypervisor_errors_keep_their_phase() {
        let make = || {
            RuntimeError::Trap(TrapError::Hypervisor(
                "hypervisor fault (error 0xfae94003)".to_string(),
            ))
        };
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Prepare),
            EmbedError::Prepare(RuntimeError::Trap(_))
        ));
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Execute),
            EmbedError::Runtime(RuntimeError::Trap(_))
        ));
    }

    #[test]
    fn configuration_refusals_keep_their_phase() {
        let make = || RuntimeError::Configuration("knob removed".to_string());
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Prepare),
            EmbedError::Prepare(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Execute),
            EmbedError::Runtime(RuntimeError::Configuration(_))
        ));
    }

    #[test]
    fn entitlement_display_names_the_fix() {
        let text = EmbedError::Entitlement.to_string();
        assert!(text.contains("0xfae94007"), "{text}");
        assert!(text.contains("entitlements.plist"), "{text}");
    }
}
```

```sh
cargo test -p carrick-embed --lib error::
```
Expected: compile error `cannot find type EmbedError`/`Phase` in this scope (red).

- [ ] **Step 5: Green — implement `EmbedError` and the phase-aware runtime mapping**

Insert above the test module in `crates/carrick-embed/src/error.rs`:

```rust
use carrick_runtime::runtime::RuntimeError;
use carrick_runtime::trap::TrapError;

use crate::Signal;

/// The `hv_return_t` of `HV_DENIED` as applevisor's `Display` prints it
/// (`operation not allowed by the system (error 0xfae94007)`), which
/// `carrick-vmm-hvf::trap::hvf_error` copies verbatim into
/// [`TrapError::Hypervisor`]. There is no typed variant to match on today.
const HV_DENIED_HEX: &str = "0xfae94007";

/// Why an embedded run did not produce a [`crate::ContainerResult`].
///
/// Linux outcomes delivered to the guest (errno denials, faults) are never an
/// `EmbedError`; a guest that exits non-zero is an `Ok(ContainerResult)` and
/// becomes [`EmbedError::Guest`] only through
/// [`crate::ContainerResult::ensure_success`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmbedError {
    /// Image reference parsing, pull/store resolution, or the engine's
    /// request→spec merge failed (`Engine::resolve` reports all three as one
    /// `anyhow::Error`).
    #[error("image resolution failed: {0:#}")]
    Image(anyhow::Error),
    /// The builder was given something the runtime could never honour.
    #[error("invalid container configuration: {0}")]
    Config(String),
    /// `Runtime::prepare` failed; everything it published was rolled back.
    #[error("container preparation failed: {0}")]
    Prepare(#[source] RuntimeError),
    /// The hypervisor refused the calling executable (`HV_DENIED`).
    #[error(
        "hypervisor entitlement denied (HV_DENIED 0xfae94007): the executable that embeds \
         carrick must be codesigned with scripts/entitlements.plist (AGENTS.md Rule 0)"
    )]
    Entitlement,
    /// A completed run whose guest did not succeed (see `ensure_success`).
    #[error("guest terminated unsuccessfully: exit_code={exit_code}, signal={signal:?}")]
    Guest { exit_code: i32, signal: Option<Signal> },
    /// The guest hit `max_traps` without exiting.
    #[error("guest hit the trap limit without exiting")]
    TrapLimit,
    /// Runtime infrastructure failed after preparation succeeded.
    #[error("runtime failure: {0}")]
    Runtime(#[source] RuntimeError),
    /// The blocking execute task panicked (`tokio::task::JoinError`).
    #[error("the execute task panicked: {0}")]
    ExecutePanicked(String),
}

/// Which runtime call produced a [`RuntimeError`]; decides `Prepare` vs
/// `Runtime` for errors that are not otherwise special-cased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Prepare,
    Execute,
}

impl EmbedError {
    pub(crate) fn from_runtime(error: RuntimeError, phase: Phase) -> Self {
        match error {
            RuntimeError::TrapLimitExceeded { .. } => Self::TrapLimit,
            RuntimeError::Trap(TrapError::Hypervisor(message))
                if message.contains(HV_DENIED_HEX) =>
            {
                Self::Entitlement
            }
            other => match phase {
                Phase::Prepare => Self::Prepare(other),
                Phase::Execute => Self::Runtime(other),
            },
        }
    }
}
```

Re-enable `pub use error::EmbedError;` in `lib.rs` (leave the other three re-exports commented until their modules exist).

```sh
cargo test -p carrick-embed --lib error::
```
Expected: `test result: ok. 5 passed`.

- [ ] **Step 6: Red — `result.rs` tests**

`crates/carrick-embed/src/result.rs`, test module first. `RunResult` has exactly the seven fields used below (`run_result.rs:76-107`):

```rust
//! What a finished embedded run produced.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn run_result(exit_code: i32, terminating_signal: Option<i32>) -> RunResult {
        RunResult {
            exit_code,
            terminating_signal,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            traps: 3,
            report: CompatReport::default(),
            trap_limit_hit: false,
        }
    }

    #[test]
    fn a_clean_exit_is_success_and_keeps_runtime_buffers() {
        let result = ContainerResult::from_run_result(run_result(0, None), CapturedStreams::default());
        assert!(result.success());
        assert_eq!(result.stdout_utf8(), "out");
        assert_eq!(result.stderr_utf8(), "err");
        assert_eq!(result.traps, 3);
        assert!(result.ensure_success().is_ok());
    }

    #[test]
    fn signal_death_is_typed_and_unsuccessful() {
        let result = ContainerResult::from_run_result(run_result(139, Some(11)), CapturedStreams::default());
        assert_eq!(result.signal, Some(Signal(11)));
        assert!(!result.success());
        assert!(matches!(
            result.ensure_success(),
            Err(EmbedError::Guest { exit_code: 139, signal: Some(Signal(11)) })
        ));
    }

    #[test]
    fn a_nonzero_exit_is_a_guest_error_only_through_ensure_success() {
        let result = ContainerResult::from_run_result(run_result(7, None), CapturedStreams::default());
        assert!(!result.success());
        assert!(matches!(
            result.ensure_success(),
            Err(EmbedError::Guest { exit_code: 7, signal: None })
        ));
    }

    #[test]
    fn trap_limit_is_never_success() {
        let mut raw = run_result(0, None);
        raw.trap_limit_hit = true;
        let result = ContainerResult::from_run_result(raw, CapturedStreams::default());
        assert!(!result.success());
        assert!(matches!(result.ensure_success(), Err(EmbedError::TrapLimit)));
    }

    #[test]
    fn embed_side_capture_buffers_override_runtime_buffers_per_stream() {
        let stdout = CaptureBuffer::default();
        stdout.clone().write_all(b"captured-by-embed").unwrap();
        let captured = CapturedStreams { stdout: Some(stdout), stderr: None };
        let result = ContainerResult::from_run_result(run_result(0, None), captured);
        assert_eq!(result.stdout, b"captured-by-embed");
        assert_eq!(result.stderr, b"err", "an uncaptured stream keeps the runtime's bytes");
    }

    #[test]
    fn utf8_accessors_are_lossy_not_fallible() {
        let mut raw = run_result(0, None);
        raw.stdout = vec![0xff, b'o', b'k'];
        let result = ContainerResult::from_run_result(raw, CapturedStreams::default());
        assert!(result.stdout_utf8().ends_with("ok"));
    }
}
```

```sh
cargo test -p carrick-embed --lib result::
```
Expected: compile error (`ContainerResult`, `CapturedStreams`, `CaptureBuffer` unresolved) — red.

- [ ] **Step 7: Green — implement `ContainerResult`, `CaptureBuffer`, `CapturedStreams`**

Insert above the test module in `crates/carrick-embed/src/result.rs`:

```rust
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use carrick_runtime::compat::CompatReport;
use carrick_runtime::runtime::RunResult;

use crate::{EmbedError, Signal};

/// A `Box<dyn Write + Send>` the runtime's `Piped` sink writes into, whose
/// bytes the embed side reads back after the run. Cloning shares the buffer.
#[derive(Clone, Debug, Default)]
pub(crate) struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl CaptureBuffer {
    pub(crate) fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Write for CaptureBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Which streams the embed side captured itself (mixed per-stream stdio
/// configurations lower to `StdioSink::Piped` with these as the writers).
/// `None` means the runtime's own `RunResult` buffer is authoritative.
#[derive(Debug, Default)]
pub(crate) struct CapturedStreams {
    pub(crate) stdout: Option<CaptureBuffer>,
    pub(crate) stderr: Option<CaptureBuffer>,
}

/// The outcome of one embedded run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerResult {
    /// The guest init process's exit code (`128 + signum` when it died of a
    /// signal, the shell convention; `signal` is the typed source of truth).
    pub exit_code: i32,
    /// The signal that killed the guest init, if one did.
    pub signal: Option<Signal>,
    /// Captured guest stdout (empty under `StdioConfig::Inherit`).
    pub stdout: Vec<u8>,
    /// Captured guest stderr (empty under `StdioConfig::Inherit`).
    pub stderr: Vec<u8>,
    /// The run stopped at `max_traps` without the guest exiting.
    pub trap_limit_hit: bool,
    /// Syscall traps serviced during the run.
    pub traps: usize,
    /// The runtime's compat summary (unhandled/deferred/partial syscalls).
    pub compat: CompatReport,
}

impl ContainerResult {
    pub(crate) fn from_run_result(result: RunResult, captured: CapturedStreams) -> Self {
        let RunResult {
            exit_code,
            terminating_signal,
            stdout,
            stderr,
            traps,
            report,
            trap_limit_hit,
        } = result;
        Self {
            exit_code,
            signal: terminating_signal.map(Signal),
            stdout: captured.stdout.map_or(stdout, |buffer| buffer.take()),
            stderr: captured.stderr.map_or(stderr, |buffer| buffer.take()),
            trap_limit_hit,
            traps,
            compat: report,
        }
    }

    /// Lossy UTF-8 view of `stdout`.
    pub fn stdout_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Lossy UTF-8 view of `stderr`.
    pub fn stderr_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Exit code 0, no terminating signal, and the trap limit was not hit.
    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.signal.is_none() && !self.trap_limit_hit
    }

    /// Turn an unsuccessful run into the typed error a `?`-style caller wants.
    pub fn ensure_success(self) -> Result<Self, EmbedError> {
        if self.trap_limit_hit {
            return Err(EmbedError::TrapLimit);
        }
        if self.success() {
            Ok(self)
        } else {
            Err(EmbedError::Guest {
                exit_code: self.exit_code,
                signal: self.signal,
            })
        }
    }
}
```

Re-enable `pub use result::ContainerResult;` in `lib.rs`.

```sh
cargo test -p carrick-embed --lib result::
```
Expected: `test result: ok. 6 passed`.

- [ ] **Step 8: Red — `builder.rs` lowering tests, compared against the engine's own `resolve_run_spec`**

`crates/carrick-embed/src/builder.rs`, test module first. The fixture image mirrors `carrick-engine`'s `make_test_image` (`crates/carrick-engine/src/lib.rs:555-574`); the docker-archive seeding mirrors `carrick-image`'s `gzip_layer`/`docker_archive` test helpers (`crates/carrick-image/src/lib.rs:1604-1660`) so `prepare()` resolves from a local store with `PullPolicy::Never` and never touches the network. Note that the image crate's own `load_docker_archive_ingests_blobs_and_summary` (`lib.rs:1662-1725`) stops at `list_images().len() == 1` and never calls `resolve` — `prepare_resolves_a_local_image_without_pulling` below is the first resolve-after-load proof; it works because `load_docker_archive` writes under `image_dir_for(tag, PlatformTarget::default_target())` and `Engine::resolve` with no platform reads `image_dir_for(tag, {linux, host_native().oci_arch()})`, the same directory (`lib.rs:160-168, 251-257`).

```rust
//! `ContainerBuilder`: the Docker-shaped happy path, lowered into
//! `carrick_engine::RunRequest` so the engine's single merge path
//! (`resolve_run_spec`) decides every image-vs-request precedence rule.

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use carrick_engine::{request_platform, resolve_run_spec};
    use carrick_image::ResolvedImage;
    use carrick_spec::ImageConfig;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn image(entrypoint: Option<&[&str]>, cmd: Option<&[&str]>, env: &[&str]) -> ResolvedImage {
        ResolvedImage {
            layers: vec![Utf8PathBuf::from("/layer1")],
            config: ImageConfig {
                entrypoint: entrypoint.map(strings),
                cmd: cmd.map(strings),
                env: strings(env),
                ..ImageConfig::default()
            },
        }
    }

    #[test]
    fn env_precedence_matches_a_hand_built_request() {
        let builder = ContainerBuilder::from_image("alpine")
            .command(["/bin/ls"])
            .env("A", "builder")
            .env("A", "later");
        let from_builder = resolve_run_spec(
            builder.to_run_request().unwrap(),
            image(None, None, &["A=image", "B=image"]),
        )
        .unwrap();

        let hand = RunRequest {
            image_ref: "alpine".to_string(),
            args: strings(&["/bin/ls"]),
            env_overrides: strings(&["A=builder", "A=later"]),
            stdio: StdioMode::Captured,
            max_traps: DEFAULT_MAX_TRAPS,
            ..RunRequest::default()
        };
        let from_hand = resolve_run_spec(hand, image(None, None, &["A=image", "B=image"])).unwrap();

        assert_eq!(from_builder, from_hand);
        assert!(from_builder.envp.contains(&"A=later".to_string()));
        assert!(from_builder.envp.contains(&"B=image".to_string()));
        assert!(!from_builder.envp.contains(&"A=image".to_string()));
    }

    #[test]
    fn command_overrides_image_cmd_but_not_image_entrypoint() {
        let spec = resolve_run_spec(
            ContainerBuilder::from_image("alpine").command(["/bin/ls"]).to_run_request().unwrap(),
            image(Some(&["/bin/sh"]), Some(&["-c", "true"]), &[]),
        )
        .unwrap();
        assert_eq!(spec.argv, strings(&["/bin/sh", "/bin/ls"]), "docker: cmd override keeps ENTRYPOINT");
    }

    #[test]
    fn entrypoint_overrides_and_an_empty_entrypoint_clears() {
        let img = || image(Some(&["/bin/sh"]), Some(&["-c", "true"]), &[]);
        let overridden = resolve_run_spec(
            ContainerBuilder::from_image("alpine").entrypoint(["/bin/ls"]).to_run_request().unwrap(),
            img(),
        )
        .unwrap();
        assert_eq!(overridden.argv, strings(&["/bin/ls", "-c", "true"]));

        let cleared = resolve_run_spec(
            ContainerBuilder::from_image("alpine")
                .entrypoint(Vec::<String>::new())
                .command(["/bin/true"])
                .to_run_request()
                .unwrap(),
            img(),
        )
        .unwrap();
        assert_eq!(cleared.argv, strings(&["/bin/true"]));
    }

    #[test]
    fn mounts_lower_in_order_with_readonly_preserved() {
        let request = ContainerBuilder::from_image("alpine")
            .command(["/bin/true"])
            .mount("/host/data", "/data")
            .mount_readonly("/host/ro", "/ro")
            .to_run_request()
            .unwrap();
        assert_eq!(
            request.mounts,
            vec![
                Mount { source: "/host/data".into(), target: "/data".into(), readonly: false },
                Mount { source: "/host/ro".into(), target: "/ro".into(), readonly: true },
            ]
        );
        let spec = resolve_run_spec(request.clone(), image(None, Some(&["/bin/sh"]), &[])).unwrap();
        assert_eq!(spec.mounts, request.mounts);
    }

    #[test]
    fn relative_mount_paths_are_a_config_error() {
        let error = ContainerBuilder::from_image("alpine")
            .mount("data", "/data")
            .to_run_request()
            .unwrap_err();
        assert!(matches!(error, EmbedError::Config(_)), "{error}");
        let error = ContainerBuilder::from_image("alpine")
            .mount("/host", "data")
            .to_run_request()
            .unwrap_err();
        assert!(matches!(error, EmbedError::Config(_)), "{error}");
    }

    #[test]
    fn platform_round_trips_through_the_oci_string() {
        let request = ContainerBuilder::from_image("alpine")
            .platform(Platform::Aarch64)
            .to_run_request()
            .unwrap();
        assert_eq!(request.platform.as_deref(), Some("linux/arm64"));
        assert_eq!(request_platform(&request), Platform::Aarch64);
        let amd = ContainerBuilder::from_image("alpine").platform(Platform::Amd64).to_run_request().unwrap();
        assert_eq!(request_platform(&amd), Platform::Amd64);
    }

    #[test]
    fn workdir_user_hostname_and_max_traps_lower_verbatim() {
        let request = ContainerBuilder::from_image("alpine")
            .workdir("/srv")
            .user("1000:1000")
            .hostname("embedded")
            .max_traps(42)
            .pull_policy(PullPolicy::Never)
            .to_run_request()
            .unwrap();
        assert_eq!(request.workdir.as_deref(), Some("/srv"));
        assert_eq!(request.user.as_deref(), Some("1000:1000"));
        assert_eq!(request.hostname.as_deref(), Some("embedded"));
        assert_eq!(request.max_traps, 42);
        assert_eq!(request.pull, PullPolicy::Never);
        let spec = resolve_run_spec(request, image(None, Some(&["/bin/sh"]), &[])).unwrap();
        // `NsUid`/`NsGid` expose `.raw()` (carrick-abi/src/lib.rs:2867-2880, 2987-3000).
        assert_eq!(spec.uid.raw(), 1000);
        assert_eq!(spec.gid.raw(), 1000);
        assert_eq!(spec.hostname.as_deref(), Some("embedded"));
        assert_eq!(spec.max_traps, 42);
    }

    #[test]
    fn a_named_user_is_a_config_error_not_a_silent_root() {
        let error = ContainerBuilder::from_image("alpine").user("nobody").to_run_request().unwrap_err();
        match error {
            EmbedError::Config(message) => assert!(message.contains("numeric"), "{message}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn env_keys_must_be_non_empty_and_free_of_equals() {
        for (key, value) in [("", "x"), ("A=B", "x")] {
            let error = ContainerBuilder::from_image("alpine").env(key, value).to_run_request().unwrap_err();
            assert!(matches!(error, EmbedError::Config(_)), "{error}");
        }
    }

    #[test]
    fn bare_host_env_import_and_bridge_ids_are_never_requested() {
        let request = ContainerBuilder::from_image("alpine").to_run_request().unwrap();
        assert_eq!(request.host_env, None);
        assert_eq!(request.bridge_namespace_id, None);
    }

    #[test]
    fn stdio_defaults_to_captured_and_mixed_configs_lower_to_piped() {
        let default = ContainerBuilder::from_image("alpine").to_run_request().unwrap();
        assert_eq!(default.stdio, StdioMode::Captured);

        let inherit = ContainerBuilder::from_image("alpine")
            .stdout(StdioConfig::Inherit)
            .stderr(StdioConfig::Inherit)
            .to_run_request()
            .unwrap();
        assert_eq!(inherit.stdio, StdioMode::Inherit);

        let mixed = ContainerBuilder::from_image("alpine")
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Inherit)
            .to_run_request()
            .unwrap();
        assert_eq!(mixed.stdio, StdioMode::Piped);

        let plan = StdioPlan::lower(StdioConfig::Captured, StdioConfig::Inherit);
        assert!(matches!(plan.sink, StdioSink::Piped { .. }));
        assert!(plan.captured.stdout.is_some(), "captured stream gets an embed-side buffer");
        assert!(plan.captured.stderr.is_none(), "inherited stream has no buffer");

        let both = StdioPlan::lower(StdioConfig::Captured, StdioConfig::Captured);
        assert!(matches!(both.sink, StdioSink::Captured));
        assert!(both.captured.stdout.is_none() && both.captured.stderr.is_none());
    }

    #[test]
    fn piped_writer_receives_bytes_written_through_the_plan() {
        let sink_buffer = CaptureBuffer::default();
        let plan = StdioPlan::lower(StdioConfig::Piped(Box::new(sink_buffer.clone())), StdioConfig::Captured);
        let StdioSink::Piped { mut stdout, .. } = plan.sink else {
            panic!("mixed config must lower to Piped");
        };
        stdout.write_all(b"hello").unwrap();
        assert_eq!(sink_buffer.take(), b"hello");
    }

    #[tokio::test]
    async fn run_blocking_inside_a_tokio_runtime_is_a_config_error() {
        let error = ContainerBuilder::from_image("alpine").command(["/bin/true"]).run_blocking().unwrap_err();
        match error {
            EmbedError::Config(message) => assert!(message.contains("run().await"), "{message}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    /// gzip a single-file tar: the layer-blob shape a docker-archive carries.
    fn gzip_layer(path: &str, contents: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Ingest a one-layer docker-archive into `store` under `tag` so resolution
    /// with `PullPolicy::Never` needs no registry.
    fn seed_local_image(store: &ImageStore, tag: &str, config_json: &str) {
        let layer = gzip_layer("etc/embed-fixture", b"fixture");
        let manifest = serde_json::json!([{
            "Config": "config.json",
            "RepoTags": [tag],
            "Layers": ["layer.tar.gz"],
        }]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, data) in [
                ("manifest.json", manifest_bytes.as_slice()),
                ("config.json", config_json.as_bytes()),
                ("layer.tar.gz", layer.as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, data).unwrap();
            }
            builder.finish().unwrap();
        }
        let archive = store.root().join("embed-fixture.tar");
        std::fs::write(&archive, &tar_bytes).unwrap();
        store.load_docker_archive(&archive).unwrap();
    }

    #[tokio::test]
    async fn prepare_resolves_a_local_image_without_pulling() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::new(tmp.path());
        seed_local_image(
            &store,
            "embedtest:latest",
            r#"{"architecture":"arm64","os":"linux","config":{"Cmd":["/bin/sh"],"Env":["FOO=image"],"WorkingDir":"/srv"}}"#,
        );

        let prepared = ContainerBuilder::from_image("embedtest:latest")
            .image_store(store)
            .pull_policy(PullPolicy::Never)
            .command(["/bin/true"])
            .env("BAR", "builder")
            .prepare()
            .await
            .expect("resolves from the seeded store");
        let spec = prepared.run_spec();
        assert_eq!(spec.argv, strings(&["/bin/true"]));
        assert!(spec.envp.contains(&"FOO=image".to_string()));
        assert!(spec.envp.contains(&"BAR=builder".to_string()));
        assert_eq!(spec.cwd.as_deref().map(|p| p.as_str()), Some("/srv"));
        assert_eq!(spec.rootfs_layers.len(), 1);
        assert_eq!(spec.stdio, StdioMode::Captured);
    }

    #[tokio::test]
    async fn an_absent_image_with_pull_never_is_an_image_error() {
        let tmp = tempfile::tempdir().unwrap();
        // `PreparedContainer` has no `Debug` (it owns a `RuntimeExtensions`), so
        // `unwrap_err()` cannot be used on this Result; destructure instead.
        let Err(error) = ContainerBuilder::from_image("never-pulled:latest")
            .image_store(ImageStore::new(tmp.path()))
            .pull_policy(PullPolicy::Never)
            .command(["/bin/true"])
            .prepare()
            .await
        else {
            panic!("an absent image under PullPolicy::Never must not resolve");
        };
        assert!(matches!(error, EmbedError::Image(_)), "{error}");
    }
}
```

```sh
cargo test -p carrick-embed --lib builder::
```
Expected: compile error (`ContainerBuilder`, `StdioConfig`, `StdioPlan` unresolved) — red.

- [ ] **Step 9: Green — implement `StdioConfig`, the stdio lowering, and `ContainerBuilder`**

Insert above the test module in `crates/carrick-embed/src/builder.rs`:

```rust
use std::io::Write;

use camino::Utf8PathBuf;
use carrick_engine::{Engine, RunRequest};
use carrick_image::{ImageStore, PullPolicy};
use carrick_runtime::prepare::{RuntimeExtensions, StdioSink};
use carrick_runtime::runtime::DEFAULT_MAX_TRAPS;
use carrick_spec::{Mount, Platform, StdioMode};

use crate::result::{CaptureBuffer, CapturedStreams};
use crate::{ContainerResult, EmbedError, PreparedContainer};

/// Where one guest stdio stream goes.
pub enum StdioConfig {
    /// Buffer the bytes into [`ContainerResult`].
    Captured,
    /// Write through to the host process's own fd 1/2.
    Inherit,
    /// Hand every write to this writer as the guest produces it.
    Piped(Box<dyn Write + Send>),
}

impl StdioConfig {
    fn is_captured(&self) -> bool {
        matches!(self, Self::Captured)
    }

    fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

/// The request-level stdio mode for a pair of per-stream configs. Only a
/// homogeneous pair maps onto the runtime's `Captured`/`Inherit` sinks; any
/// mixed pair is `Piped` with embed-owned writers (see [`StdioPlan::lower`]).
pub(crate) fn stdio_mode(stdout: &StdioConfig, stderr: &StdioConfig) -> StdioMode {
    if stdout.is_captured() && stderr.is_captured() {
        StdioMode::Captured
    } else if stdout.is_inherit() && stderr.is_inherit() {
        StdioMode::Inherit
    } else {
        StdioMode::Piped
    }
}

/// The runtime sink for a run plus the embed-side buffers that back any
/// `Captured` stream inside a `Piped` sink.
pub(crate) struct StdioPlan {
    pub(crate) sink: StdioSink,
    pub(crate) captured: CapturedStreams,
}

impl StdioPlan {
    pub(crate) fn lower(stdout: StdioConfig, stderr: StdioConfig) -> Self {
        match stdio_mode(&stdout, &stderr) {
            StdioMode::Captured => Self {
                sink: StdioSink::Captured,
                captured: CapturedStreams::default(),
            },
            StdioMode::Inherit => Self {
                sink: StdioSink::Inherit,
                captured: CapturedStreams::default(),
            },
            StdioMode::Piped => {
                let mut captured = CapturedStreams::default();
                let stdout = piped_writer(stdout, || Box::new(std::io::stdout()), &mut captured.stdout);
                let stderr = piped_writer(stderr, || Box::new(std::io::stderr()), &mut captured.stderr);
                Self {
                    sink: StdioSink::Piped { stdout, stderr },
                    captured,
                }
            }
        }
    }
}

fn piped_writer(
    config: StdioConfig,
    inherit: impl FnOnce() -> Box<dyn Write + Send>,
    capture_slot: &mut Option<CaptureBuffer>,
) -> Box<dyn Write + Send> {
    match config {
        StdioConfig::Captured => {
            let buffer = CaptureBuffer::default();
            *capture_slot = Some(buffer.clone());
            Box::new(buffer)
        }
        StdioConfig::Inherit => inherit(),
        StdioConfig::Piped(writer) => writer,
    }
}

/// Docker-shaped description of one containerized run.
///
/// Every setter is a by-value builder step; [`Self::to_run_request`] lowers the
/// whole thing into [`RunRequest`] so `carrick_engine::resolve_run_spec` — the
/// CLI's merge path — applies image-vs-request precedence. The builder itself
/// only rejects what the engine could never honour (a named user, a relative
/// mount path, a malformed env key).
pub struct ContainerBuilder {
    image: String,
    platform: Option<Platform>,
    pull: PullPolicy,
    store: Option<ImageStore>,
    command: Vec<String>,
    entrypoint: Option<Vec<String>>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    mounts: Vec<Mount>,
    stdout: StdioConfig,
    stderr: StdioConfig,
    max_traps: usize,
}

impl ContainerBuilder {
    /// Start from an image reference (`ubuntu:24.04`, `ghcr.io/org/app@sha256:…`).
    pub fn from_image(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            platform: None,
            pull: PullPolicy::Missing,
            store: None,
            command: Vec::new(),
            entrypoint: None,
            env: Vec::new(),
            workdir: None,
            user: None,
            hostname: None,
            mounts: Vec::new(),
            stdout: StdioConfig::Captured,
            stderr: StdioConfig::Captured,
            max_traps: DEFAULT_MAX_TRAPS,
        }
    }

    /// Replace the image `Cmd` (the image `Entrypoint`, if any, still prefixes it).
    pub fn command<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = argv.into_iter().map(Into::into).collect();
        self
    }

    /// Replace the image `Entrypoint`; an empty iterator clears it (`--entrypoint ""`).
    pub fn entrypoint<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = Some(argv.into_iter().map(Into::into).collect());
        self
    }

    /// Set one environment variable (last call for a key wins, over the image `Env`).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Working directory; a relative path resolves against the image `WorkingDir`.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Numeric `uid[:gid]` (names are rejected: no in-image `/etc/passwd` lookup exists).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Container hostname / UTS identity.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Bind-mount an absolute host path at an absolute guest path, read-write.
    pub fn mount(self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.push_mount(host, guest, false)
    }

    /// Bind-mount an absolute host path at an absolute guest path, read-only.
    pub fn mount_readonly(self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.push_mount(host, guest, true)
    }

    fn push_mount(mut self, host: impl Into<String>, guest: impl Into<String>, readonly: bool) -> Self {
        self.mounts.push(Mount {
            source: Utf8PathBuf::from(host.into()),
            target: Utf8PathBuf::from(guest.into()),
            readonly,
        });
        self
    }

    /// Target ISA (default: the host-native platform).
    pub fn platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Docker `--pull` policy (default: `Missing`).
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.pull = policy;
        self
    }

    /// Image store root (default: `ImageStore::default_for_user`, i.e. `$CARRICK_HOME`).
    pub fn image_store(mut self, store: ImageStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Guest stdout destination (default: `Captured`).
    pub fn stdout(mut self, config: StdioConfig) -> Self {
        self.stdout = config;
        self
    }

    /// Guest stderr destination (default: `Captured`).
    pub fn stderr(mut self, config: StdioConfig) -> Self {
        self.stderr = config;
        self
    }

    /// Stop the run after this many syscall traps (default: unlimited).
    pub fn max_traps(mut self, max_traps: usize) -> Self {
        self.max_traps = max_traps;
        self
    }

    /// Lower into the engine's request. Pure: no I/O, no ambient reads.
    pub fn to_run_request(&self) -> Result<RunRequest, EmbedError> {
        if self.image.trim().is_empty() {
            return Err(EmbedError::Config("image reference is empty".to_string()));
        }
        let mut env_overrides = Vec::with_capacity(self.env.len());
        for (key, value) in &self.env {
            if key.is_empty() || key.contains('=') {
                return Err(EmbedError::Config(format!(
                    "environment key {key:?} must be non-empty and contain no '='"
                )));
            }
            env_overrides.push(format!("{key}={value}"));
        }
        if let Some(user) = &self.user
            && !is_numeric_user(user)
        {
            return Err(EmbedError::Config(format!(
                "user {user:?} must be numeric `uid[:gid]`: carrick-embed does not resolve \
                 names against the image's /etc/passwd"
            )));
        }
        for mount in &self.mounts {
            if !mount.source.is_absolute() || !mount.target.is_absolute() {
                return Err(EmbedError::Config(format!(
                    "mount {} -> {} must use absolute host and guest paths",
                    mount.source, mount.target
                )));
            }
        }
        Ok(RunRequest {
            image_ref: self.image.clone(),
            platform: self.platform.map(|platform| format!("linux/{}", platform.oci_arch())),
            args: self.command.clone(),
            entrypoint_override: self.entrypoint.clone(),
            env_overrides,
            // Bare `KEY` host-env import is a CLI convenience; a library caller
            // passes explicit values, so the engine is told there is nothing to import.
            host_env: None,
            mounts: self.mounts.clone(),
            workdir: self.workdir.clone(),
            user: self.user.clone(),
            hostname: self.hostname.clone(),
            max_traps: self.max_traps,
            pull: self.pull,
            stdio: stdio_mode(&self.stdout, &self.stderr),
            // Networking is the engine default (`NetworkMode::Host`); no bridge
            // namespace is requested, so no id is needed. Never derived from a pid.
            bridge_namespace_id: None,
            ..RunRequest::default()
        })
    }

    /// Resolve the image (async) and freeze the run. No guest work happens here.
    pub async fn prepare(self) -> Result<PreparedContainer, EmbedError> {
        let request = self.to_run_request()?;
        let store = self.store.clone().unwrap_or_else(ImageStore::default_for_user);
        let spec = Engine::new(store)
            .resolve(request)
            .await
            .map_err(EmbedError::Image)?;
        let plan = StdioPlan::lower(self.stdout, self.stderr);
        let extensions = RuntimeExtensions::default().stdio(plan.sink);
        Ok(PreparedContainer::new(spec, extensions, plan.captured))
    }

    /// Resolve on the ambient tokio runtime, then execute on its blocking pool.
    ///
    /// Requires the runtime seam (Task 21/22) to have retired the
    /// `Handle::try_current().is_err()` debug assertion that guarded the old
    /// `Runtime::execute` (`execute.rs:197-201`): a `spawn_blocking` thread
    /// carries a runtime handle by construction.
    pub async fn run(self) -> Result<ContainerResult, EmbedError> {
        let prepared = self.prepare().await?;
        tokio::task::spawn_blocking(move || prepared.execute())
            .await
            .map_err(|join| EmbedError::ExecutePanicked(join.to_string()))?
    }

    /// Resolve on a private current-thread runtime (dropped before execution),
    /// then execute on the calling thread. Refuses to run inside a tokio
    /// runtime (`block_on` would panic there); use [`Self::run`] instead.
    pub fn run_blocking(self) -> Result<ContainerResult, EmbedError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(EmbedError::Config(
                "run_blocking() was called from inside a tokio runtime; use `.run().await` there"
                    .to_string(),
            ));
        }
        let prepared = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    EmbedError::Config(format!(
                        "failed to build the image-resolution tokio runtime: {error}"
                    ))
                })?;
            runtime.block_on(self.prepare())?
        };
        prepared.execute()
    }
}

/// `uid[:gid]`, both decimal — the only form `resolve_run_spec` honours
/// (its private `parse_numeric_user`, `crates/carrick-engine/src/lib.rs:494-505`).
fn is_numeric_user(spec: &str) -> bool {
    let (uid, gid) = match spec.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (spec, None),
    };
    let gid_ok = match gid {
        Some(gid) => gid.parse::<u32>().is_ok(),
        None => true,
    };
    uid.parse::<u32>().is_ok() && gid_ok
}
```

Re-enable `pub use builder::{ContainerBuilder, StdioConfig};` in `lib.rs`. `builder.rs` references `PreparedContainer::new`, so Step 10 must land before this compiles — write both, then run.

- [ ] **Step 10: Implement `prepared.rs` (run identity + `PreparedContainer`) with its own pure tests**

`crates/carrick-embed/src/prepared.rs`:

```rust
//! A resolved run, one step from execution: the merged `RunSpec` plus the
//! runtime extensions (stdio sink today; VFS mounts, observers, clock modes in
//! later phases) that `Runtime::prepare` installs and `PreparedRun::execute`
//! seals.

use std::time::{SystemTime, UNIX_EPOCH};

use carrick_runtime::Runtime;
use carrick_runtime::container::{make_id, short_id};
use carrick_runtime::kernel::container::{ContainerId, LaunchContext, RunId};
use carrick_runtime::prepare::RuntimeExtensions;
use carrick_spec::RunSpec;

use crate::error::Phase;
use crate::result::CapturedStreams;
use crate::{ContainerResult, EmbedError};

/// Inspect the plan, then [`Self::execute`] it exactly once.
pub struct PreparedContainer {
    spec: RunSpec,
    extensions: RuntimeExtensions,
    captured: CapturedStreams,
}

impl PreparedContainer {
    pub(crate) fn new(spec: RunSpec, extensions: RuntimeExtensions, captured: CapturedStreams) -> Self {
        Self {
            spec,
            extensions,
            captured,
        }
    }

    /// The fully merged spec the runtime will execute.
    pub fn run_spec(&self) -> &RunSpec {
        &self.spec
    }

    /// Prepare the container on the kernel graph and run it to completion on
    /// the calling thread. Blocking; see [`crate::ContainerBuilder::run`].
    pub fn execute(self) -> Result<ContainerResult, EmbedError> {
        let launch = embedded_launch_context();
        let prepared = Runtime::prepare(&self.spec, launch, self.extensions)
            .map_err(|error| EmbedError::from_runtime(error, Phase::Prepare))?;
        let result = prepared
            .execute()
            .map_err(|error| EmbedError::from_runtime(error, Phase::Execute))?;
        Ok(ContainerResult::from_run_result(result, self.captured))
    }
}

/// The run id an embedded container is scoped under: an explicit
/// `CARRICK_RUN_ID` (a caller's grouping override), else a fresh 12-hex short
/// id from the `carrick ps` id scheme. Same precedence as `carrick run`
/// (`crates/carrick-cli/src/commands.rs:979-998`, minus the `--name` rung the
/// builder does not have). The id is what `scripts/sudo/kill.sh <run-id>`
/// keys on through the carrier's proctitle; today
/// `dispatch/proctitle.rs:71` stamps that title from the ENV var itself, so an
/// explicit `CARRICK_RUN_ID` is reapable now and a generated one becomes
/// reapable once Phase B routes the stamp through `LaunchContext::run_id`.
pub(crate) fn run_id_from(explicit: Option<String>) -> String {
    match explicit.filter(|id| !id.is_empty()) {
        Some(id) => id,
        None => {
            let entropy = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            // `make_id` takes two bare entropy words by design (container.rs:791-801);
            // the host pid is a SEED here, never an identity.
            short_id(&make_id(u64::from(std::process::id()), entropy)).to_string()
        }
    }
}

fn embedded_launch_context() -> LaunchContext {
    LaunchContext {
        container_id: ContainerId::allocate(),
        run_id: RunId::new(run_id_from(std::env::var("CARRICK_RUN_ID").ok())),
        exec_overlay: None,
        launch_authorization: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_run_id_is_used_verbatim() {
        assert_eq!(run_id_from(Some("embed-gate-7".to_string())), "embed-gate-7");
    }

    #[test]
    fn an_absent_or_empty_run_id_becomes_a_twelve_hex_short_id() {
        for explicit in [None, Some(String::new())] {
            let id = run_id_from(explicit);
            assert_eq!(id.len(), 12, "{id}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        }
    }

    #[test]
    fn generated_run_ids_are_not_constant() {
        // Two generations in the same process differ by their nanosecond
        // entropy; `make_id` avalanches both seeds into the short-id word.
        let first = run_id_from(None);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = run_id_from(None);
        assert_ne!(first, second);
    }
}
```

Re-enable `pub use prepared::PreparedContainer;` in `lib.rs` (all four re-exports are now live).

```sh
# cargo takes ONE test-name positional; extra filters go to libtest after `--`.
cargo test -p carrick-embed --lib -- builder:: prepared::
```
Expected: `test result: ok.` with the 15 `builder::` cases and 3 `prepared::` cases passing; `prepare_resolves_a_local_image_without_pulling` prints no `pulling…` line (it resolves the seeded store).

- [ ] **Step 11: Red then green — `testing.rs` (`TestContainer`, `run_in_container`, `ResultAssert`)**

`crates/carrick-embed/src/testing.rs`, tests first (they construct `ContainerResult` directly, so no guest is needed):

```rust
//! Test-facing conveniences: a reusable [`TestContainer`], the one-liner
//! [`run_in_container`], and [`ResultAssert`] for fluent assertions on a
//! [`ContainerResult`]. Guest-running uses of these belong in tests executed
//! by the signed `just test-embed` recipe.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompatReport;

    fn result(exit_code: i32, stdout: &str, stderr: &str) -> ContainerResult {
        ContainerResult {
            exit_code,
            signal: None,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            trap_limit_hit: false,
            traps: 1,
            compat: CompatReport::default(),
        }
    }

    #[test]
    fn assertions_chain_on_a_passing_result() {
        result(0, "hello world\n", "warn\n")
            .assert_success()
            .assert_exit_code(0)
            .assert_stdout_contains("hello")
            .assert_stderr_contains("warn");
    }

    #[test]
    #[should_panic(expected = "expected a successful run")]
    fn assert_success_panics_on_a_nonzero_exit() {
        result(3, "", "").assert_success();
    }

    #[test]
    #[should_panic(expected = "stdout does not contain")]
    fn assert_stdout_contains_panics_and_names_the_needle() {
        result(0, "abc", "").assert_stdout_contains("zzz");
    }

    #[test]
    fn test_container_builds_a_captured_request_per_run() {
        let container = TestContainer::new("ubuntu:24.04")
            .env("K", "v")
            .max_traps(9);
        let request = container.builder(["/bin/true"]).to_run_request().unwrap();
        assert_eq!(request.image_ref, "ubuntu:24.04");
        assert_eq!(request.args, vec!["/bin/true".to_string()]);
        assert_eq!(request.env_overrides, vec!["K=v".to_string()]);
        assert_eq!(request.max_traps, 9);
        assert_eq!(request.stdio, crate::StdioMode::Captured);
    }
}
```

```sh
cargo test -p carrick-embed --lib testing::
```
Expected: compile error (`TestContainer`, `ResultAssert` unresolved) — red. Then insert above the tests:

```rust
use crate::{ContainerBuilder, ContainerResult, EmbedError, ImageStore};

/// One image, many commands: each [`Self::run`] builds a fresh
/// [`ContainerBuilder`] with captured stdio, so tests read the guest's bytes
/// from the returned [`ContainerResult`].
#[derive(Clone, Debug)]
pub struct TestContainer {
    image: String,
    env: Vec<(String, String)>,
    max_traps: Option<usize>,
    store: Option<ImageStore>,
}

impl TestContainer {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            env: Vec::new(),
            max_traps: None,
            store: None,
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn max_traps(mut self, max_traps: usize) -> Self {
        self.max_traps = Some(max_traps);
        self
    }

    pub fn image_store(mut self, store: ImageStore) -> Self {
        self.store = Some(store);
        self
    }

    /// The builder one `run` would execute (exposed so request-level tests
    /// can check the lowering without a guest).
    pub fn builder<I, S>(&self, argv: I) -> ContainerBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut builder = ContainerBuilder::from_image(self.image.clone()).command(argv);
        for (key, value) in &self.env {
            builder = builder.env(key.clone(), value.clone());
        }
        if let Some(max_traps) = self.max_traps {
            builder = builder.max_traps(max_traps);
        }
        if let Some(store) = &self.store {
            builder = builder.image_store(store.clone());
        }
        builder
    }

    /// Run `argv` to completion (blocking; needs a signed executable).
    pub fn run<I, S>(&self, argv: I) -> Result<ContainerResult, EmbedError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.builder(argv).run_blocking()
    }
}

/// `ContainerBuilder::from_image(image).command(cmd).run_blocking()`.
pub fn run_in_container(image: &str, cmd: &[&str]) -> Result<ContainerResult, EmbedError> {
    ContainerBuilder::from_image(image)
        .command(cmd.iter().copied())
        .run_blocking()
}

/// Fluent assertions; each returns `&Self` so they chain.
pub trait ResultAssert {
    fn assert_success(&self) -> &Self;
    fn assert_exit_code(&self, code: i32) -> &Self;
    fn assert_stdout_contains(&self, needle: &str) -> &Self;
    fn assert_stderr_contains(&self, needle: &str) -> &Self;
}

impl ResultAssert for ContainerResult {
    fn assert_success(&self) -> &Self {
        assert!(
            self.success(),
            "expected a successful run; exit_code={} signal={:?} trap_limit_hit={} stderr={:?}",
            self.exit_code,
            self.signal,
            self.trap_limit_hit,
            self.stderr_utf8()
        );
        self
    }

    fn assert_exit_code(&self, code: i32) -> &Self {
        assert_eq!(
            self.exit_code,
            code,
            "unexpected exit code; stderr={:?}",
            self.stderr_utf8()
        );
        self
    }

    fn assert_stdout_contains(&self, needle: &str) -> &Self {
        let stdout = self.stdout_utf8();
        assert!(
            stdout.contains(needle),
            "stdout does not contain {needle:?}; stdout={stdout:?}"
        );
        self
    }

    fn assert_stderr_contains(&self, needle: &str) -> &Self {
        let stderr = self.stderr_utf8();
        assert!(
            stderr.contains(needle),
            "stderr does not contain {needle:?}; stderr={stderr:?}"
        );
        self
    }
}
```

```sh
cargo test -p carrick-embed --lib testing::
```
Expected: `test result: ok. 4 passed` (two of them via `should_panic`).

- [ ] **Step 12: Add the signed end-to-end smoke test (HVF guest; NOT run by `just test`)**

`just test` runs `--lib --bins` only and `just test-integration` names its packages explicitly (`justfile:148-203, 225-247`), so a `tests/` target in this crate is reached only by the signed recipe. Before running this step, confirm the Task 21/22 seam no longer carries the `Handle::try_current().is_err()` debug assertion from `execute.rs:197-201` — with it, `async_run_executes_on_the_blocking_pool` panics in every debug build. `crates/carrick-embed/tests/guest_smoke.rs`:

```rust
//! Signed end-to-end smoke for `carrick-embed`. REQUIRES an HVF-entitled test
//! executable: run only via `just test-embed` (which codesigns the test binary
//! with scripts/entitlements.plist and serializes with RUST_TEST_THREADS=1).
//! `EmbedError::Entitlement` here is a FAILURE, never a skip.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use carrick_embed::testing::ResultAssert;
use carrick_embed::{ContainerBuilder, StdioConfig};

const IMAGE: &str = "ubuntu:24.04";

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn captured_stdio_round_trips_guest_output_and_exit_code() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo hello-from-embed; echo to-stderr 1>&2; exit 7"])
        .run_blocking()
        .expect("guest ran (HV_DENIED means the test binary is unsigned)");
    result.assert_exit_code(7).assert_stdout_contains("hello-from-embed");
    assert_eq!(result.stdout_utf8(), "hello-from-embed\n");
    assert_eq!(result.stderr_utf8(), "to-stderr\n");
    assert!(!result.success());
    assert_eq!(result.signal, None);
}

#[test]
fn env_workdir_and_hostname_reach_the_guest() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo $GREETING; pwd; hostname"])
        .env("GREETING", "hi")
        .workdir("/tmp")
        .hostname("embedded-host")
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hi\n/tmp\nembedded-host\n");
}

#[test]
fn piped_stdout_reaches_the_callers_writer_and_captured_stderr_stays_in_result() {
    let writer = SharedWriter::default();
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo piped-line; echo err-line 1>&2"])
        .stdout(StdioConfig::Piped(Box::new(writer.clone())))
        .stderr(StdioConfig::Captured)
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    let piped = writer.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(String::from_utf8_lossy(&piped), "piped-line\n");
    assert!(result.stdout.is_empty(), "piped stdout is not also captured");
    assert_eq!(result.stderr_utf8(), "err-line\n");
}

#[test]
fn inherit_mode_leaves_the_result_buffers_empty() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo inherited-to-host-stdout"])
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit)
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_run_executes_on_the_blocking_pool() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo async-ok"])
        .run()
        .await
        .expect("guest ran");
    result.assert_success().assert_stdout_contains("async-ok");
}

#[test]
fn a_trap_limit_is_reported_not_erred() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "while :; do :; done"])
        .max_traps(2_000)
        .run_blocking()
        .expect("a trap-limited run still returns a result");
    assert!(result.trap_limit_hit);
    assert!(!result.success());
}
```

Until the `just test-embed` recipe lands (it is specified in `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md:291-296` and belongs to another task), the same mechanics by hand (macOS, from the repo root). `CARRICK_RUN_ID=embed-smoke` is what makes the guests reapable with `scripts/sudo/kill.sh embed-smoke` today: `kill.sh` matches the carrier proctitle, which `dispatch/proctitle.rs:71` stamps from that env var. `CARRICK_DSR_STORE_DIR` is the carrick-native-darwin AOT cache root (`aot_cache.rs:100`); pointing it at a scratch dir is optional isolation, not a requirement of the HVPatch lane.

```sh
cd /Volumes/CaseSensitive/carrick
exe=$(cargo test -p carrick-embed --test guest_smoke --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json,sys
for line in sys.stdin:
    m=json.loads(line)
    if m.get("reason")=="compiler-artifact" and m.get("executable") and m["target"]["name"]=="guest_smoke": print(m["executable"])')
codesign --force --sign - --entitlements scripts/entitlements.plist "$exe"
codesign -d --entitlements - "$exe" 2>&1 | grep -c com.apple.security.hypervisor
CARRICK_DSR_STORE_DIR="$(mktemp -d -t carrick-embed-store)" CARRICK_RUN_ID=embed-smoke RUST_TEST_THREADS=1 "$exe"
```
Expected: entitlement count `>= 1`; `test result: ok. 6 passed`. Running `"$exe"` WITHOUT the `codesign` step must print `EmbedError::Entitlement` panics (`hypervisor entitlement denied (HV_DENIED 0xfae94007)`) and `FAILED` — that is the fail-closed behaviour the spec demands, proven red-first.

- [ ] **Step 13: Whole-crate gates (fmt, clippy, doc, `just test`)**

```sh
cd /Volumes/CaseSensitive/carrick
just fmt
cargo clippy -p carrick-embed --all-targets -- -D warnings
env RUSTDOCFLAGS="-D warnings" cargo doc -p carrick-embed --no-deps --document-private-items
# Gate logs are never truncated (AGENTS.md): keep the full log and the exit status.
just test > target/embed-just-test.log 2>&1; echo "just-test status=$?"
grep -E 'Running .*carrick_embed|test result' target/embed-just-test.log
git status --short crates/carrick-embed Cargo.lock
```
Expected: clippy clean (the workspace denies `unwrap_used`/`expect_used`/`panic` in non-test code — `clippy.toml` allows all three in tests — and the crate uses `unwrap_or_else(PoisonError::into_inner)` and `?` everywhere else). One lint to watch: `RuntimeError` already sits at or under clippy's 128-byte `result_large_err` threshold (it is returned bare across the workspace), and `EmbedError` adds a discriminant on top of it; if `result_large_err` fires on `Result<_, EmbedError>`, box the payload (`Prepare(Box<RuntimeError>)`, `Runtime(Box<RuntimeError>)`) and record that as a contract deviation rather than `allow`ing the lint. rustdoc clean; `just-test status=0` and the `carrick_embed` line of the log reads `test result: ok. 33 passed` (5 error + 6 result + 15 builder + 3 prepared + 4 testing); `git status` shows the new crate directory and a modified `Cargo.lock`.

- [ ] **Step 14: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-embed Cargo.lock
git commit -F - <<'EOF'
feat(embed): add the carrick-embed library crate

Why: the embed program's Phase C needs a Rust library surface that runs a
containerized Linux workload from a host application through the SAME
merge path (`carrick_engine::resolve_run_spec`) and the SAME runtime seam
(`Runtime::prepare` -> `PreparedRun::execute`) as `carrick run`, so the CLI
and an embedder can never disagree about what a request means. Captured
stdout was previously unreachable from any product path (`raw: true` was
hardcoded in the engine); the library's default is `Captured`, the CLI's
stays `Inherit`.

What:
- `crates/carrick-embed` (`lib.rs`, `builder.rs`, `result.rs`, `error.rs`,
  `prepared.rs`, `testing.rs`), depending on `carrick-engine` AND
  `carrick-runtime` with `default-features = false` and forwarding
  `platform-*`/`syscall-shim` exactly like `carrick-cli` (default
  `platform-macos` + `syscall-shim`), so embedded guests run with the shipped
  EL1 shim.
- `ContainerBuilder` lowers into `RunRequest` (`to_run_request` is pub for
  parity tests); named users, relative mount paths and malformed env keys
  are `EmbedError::Config`; bare host-env import and bridge ids are never
  requested.
- Stdio: homogeneous `Captured`/`Inherit` pairs use the runtime sinks; any
  mixed pair lowers to `StdioSink::Piped` with embed-owned writers and the
  captured stream is read back from an embed-side buffer.
- `run()` resolves on the ambient tokio runtime and executes via
  `spawn_blocking`; `run_blocking()` owns a current-thread runtime for
  resolution, drops it, then executes, and refuses to run inside tokio.
- `EmbedError` maps `RuntimeError::TrapLimitExceeded` to `TrapLimit` and an
  `HV_DENIED` `TrapError::Hypervisor` to `Entitlement` (string match on the
  applevisor `0xfae94007` text: no typed variant exists yet).
- `testing::{TestContainer, run_in_container, ResultAssert}`.

Verified: `just test` (33 new no-HVF cases: builder lowering compared
against `resolve_run_spec` on identical inputs, error/result mapping,
local-store `prepare()` with `PullPolicy::Never` via a docker-archive
fixture, `run_blocking`-inside-tokio refusal); `cargo clippy -p
carrick-embed --all-targets -- -D warnings`; rustdoc `-D warnings`; linux
closure `cargo tree ... --features platform-linux` is HVF-free;
`tests/guest_smoke.rs` (6 cases: captured/piped/inherit stdio, env/cwd/
hostname, async `run`, trap limit) green on a codesigned test executable
and red (`EmbedError::Entitlement`) on the unsigned one.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

---

### Task 30: Document `carrick-embed` in the crate map and add its quick start

**Files:**
- Modify: `crates/README.md:3-7` (crate count + product path), `:17-19` (product table, insert after the `carrick-engine` row), `:68-71` (test/harness table, insert after `carrick-conformance`), `:73-85` (Feature Closure Rules, add one bullet). Line numbers are PRE-EDIT (verified at HEAD: line 3 reads `30-crate`, line 18 is the `carrick-engine` row, line 70 the `carrick-conformance` row, line 82 ends `pull HVF/applevisor.`); Step 2 grows the file by 5 lines, so locate each later insertion by the quoted line text, not the number.
- Create: `crates/carrick-embed/README.md`
- Test: grep-based assertions (below); `cargo doc` for the crate README's Rust snippet is NOT doctested (README is not `include_str!`ed), so the snippet mirrors `tests/guest_smoke.rs` verbatim in shape

**Interfaces:**
- Consumes: the Task 23 public surface (`ContainerBuilder`, `StdioConfig`, `ContainerResult`, `EmbedError`, `testing::ResultAssert`).
- Produces: documentation only.

- [ ] **Step 1: Red — assert the crate map does not mention the embed crate**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'carrick-embed' crates/README.md; test -f crates/carrick-embed/README.md && echo present || echo absent
```
Expected: `0` and `absent` (red).

- [ ] **Step 2: Update the crate count and product path**

Replace `crates/README.md:3-7`, currently:

```markdown
Carrick is a 30-crate Cargo workspace. The product path is:

```text
carrick-cli -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
```
```

with:

```markdown
Carrick is a 31-crate Cargo workspace. The product path is:

```text
carrick-cli   -> carrick-engine -> { carrick-image, carrick-runtime } -> carrick-spec
carrick-embed -> { carrick-engine, carrick-runtime }                   -> carrick-spec
```

`carrick-embed` is the library front door and takes the runtime directly (for
`RuntimeExtensions`, the `Vfs` trait and, in later phases, observers); the CLI
reaches the runtime only through the engine.
```

- [ ] **Step 3: Add the product-table row**

After the line (pre-edit `crates/README.md:18`), currently:

```markdown
| `carrick-engine` | Docker-style request merge layer: image config + CLI flags -> `RunSpec`. |
```

insert:

```markdown
| `carrick-embed` | Library embedding surface: `ContainerBuilder` -> `RunRequest` -> `Engine::resolve` -> `Runtime::prepare`/`PreparedRun::execute`, with captured, inherited or piped stdio and the `testing` helpers (`TestContainer`, `run_in_container`, `ResultAssert`). The dog-food consumer for Carrick's own guest tests; guest-running tests need the signed `just test-embed` recipe. |
```

- [ ] **Step 4: Add the planned `carrick-conformance-next` row**

After the line (pre-edit `crates/README.md:70`), currently:

```markdown
| `carrick-conformance` | Differential conformance harness; shells out to built carrick binaries and Docker oracles, classifies baselines, renders support matrix. |
```

insert:

```markdown
| `carrick-conformance-next` | **Planned, not yet in the tree** (Phase J of `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`): self-hosted conformance over `carrick-embed` — `TestContainer` ports of LTP/probe cases, in-process dispatcher fuzzing, Docker `bpftrace` alignment. `carrick-conformance` stays the verdict authority until it reproduces every historical false-green rejection. |
```

- [ ] **Step 5: Add the feature-closure bullet**

After the `platform-netbsd` bullet (pre-edit `crates/README.md:81-82`, ending `not pull HVF/applevisor.`), insert:

```markdown
- `carrick-embed` forwards `platform-*` and `syscall-shim` to `carrick-runtime`
  and `carrick-engine` exactly as `carrick-cli` does (default
  `["platform-macos", "syscall-shim"]`), so an embedded guest runs with the same
  EL1 shim as the shipped binary. `scripts/closure-assert-no-hvf.sh` walks
  `carrick-cli` only; check the embed closure with
  `cargo tree -p carrick-embed --no-default-features --features platform-linux
  --target aarch64-unknown-linux-gnu --edges normal | grep -Ei
  'carrick-vmm-hvf|applevisor'` (expect no output).
```

- [ ] **Step 6: Create `crates/carrick-embed/README.md`**

```markdown
# carrick-embed

Run an unmodified Linux container image from a Rust program, on Carrick's own
kernel (no guest Linux kernel, no Docker daemon). Experimental, like the rest of
Carrick: syscall coverage is partial and a guest is not a hardened trust
boundary — do not run untrusted code under it.

## Quick start

```rust
use carrick_embed::testing::ResultAssert;
use carrick_embed::{ContainerBuilder, EmbedError};

fn main() -> Result<(), EmbedError> {
    let result = ContainerBuilder::from_image("ubuntu:24.04")
        .command(["/bin/sh", "-c", "echo hello from $GREETING"])
        .env("GREETING", "carrick-embed")
        .run_blocking()?;                      // resolve image, run guest, return
    result.assert_success().assert_stdout_contains("hello from carrick-embed");
    print!("{}", result.stdout_utf8());
    Ok(())
}
```

Inside tokio, use `.run().await` (it resolves the image on your runtime and
executes on the blocking pool); `run_blocking()` refuses to run inside a runtime.

## What you get

- Docker-shaped inputs: `command`, `entrypoint`, `env`, `workdir`, `user`
  (numeric `uid[:gid]` only), `hostname`, `mount`/`mount_readonly` (absolute
  paths), `platform`, `pull_policy`, `image_store`, `max_traps`.
- Stdio per stream: `StdioConfig::Captured` (default; bytes land in
  `ContainerResult::{stdout, stderr}`), `Inherit` (your process's fd 1/2), or
  `Piped(Box<dyn Write + Send>)`.
- `ContainerResult { exit_code, signal, stdout, stderr, trap_limit_hit, traps,
  compat }`, `success()`, `ensure_success()` (turns a failed guest into
  `EmbedError::Guest`).
- `EmbedError`: `Image`, `Config`, `Prepare`, `Entitlement`, `Guest`,
  `TrapLimit`, `Runtime`, `ExecutePanicked`. Linux errnos delivered to the guest
  are never errors here.
- `carrick_embed::testing`: `TestContainer` (one image, many commands),
  `run_in_container(image, cmd)`, and the `ResultAssert` chain.
- Every request lowers into `carrick_engine::RunRequest`, so image-vs-request
  precedence (entrypoint/cmd, env layering, cwd, user) is decided by the same
  code as `carrick run`.

## Entitlement (macOS)

The executable that calls this crate — your application, or the cargo test
binary — must carry the hypervisor entitlement (`scripts/entitlements.plist`).
An unsigned binary gets `EmbedError::Entitlement` (`HV_DENIED`, `0xfae94007`)
from every run. For Carrick's own tests the signed `just test-embed` recipe
codesigns each test executable and runs it serialized; `Entitlement` there is a
failure, never a skip. See AGENTS.md Rule 0.

## Not in this version

tty/interactive sessions, VFS injection, syscall observers, time control,
fault injection, shared memory, network mocking and resource budgets are
later phases of the embed program
(`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`); running
two containers in one host process depends on Phase B (container objects on the
kernel graph).

## Features

Default `["platform-macos", "syscall-shim"]`, forwarded to `carrick-runtime`
and `carrick-engine` exactly like `carrick-cli`. Off macOS build with
`--no-default-features --features platform-<linux|freebsd|netbsd>` (optionally
plus `syscall-shim`).
```

- [ ] **Step 7: Green — re-run the assertions and the doc gate**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'carrick-embed' crates/README.md
grep -c 'carrick-conformance-next' crates/README.md
grep -n '31-crate' crates/README.md
test -f crates/carrick-embed/README.md && echo present
ls -d crates/*/ | wc -l
just fmt-check
env RUSTDOCFLAGS="-D warnings" cargo doc -p carrick-embed --no-deps --document-private-items
```
Expected: first count `>= 5`, second `1`, the `31-crate` line prints, `present`, and `ls -d crates/*/ | wc -l` prints `31` (matching the README; it is `30` at HEAD); `fmt-check` and rustdoc clean.

- [ ] **Step 8: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add crates/README.md crates/carrick-embed/README.md
git commit -F - <<'EOF'
docs(embed): index carrick-embed in the crate map and add a quick start

Why: `crates/README.md` is the crate map AGENTS.md points readers at
instead of a summary, and it must not go stale: Task 23 added a 31st
workspace member with its own feature-forwarding rule and a second entry
point into the runtime that the product-path diagram did not show.

What: bump the crate count, draw the `carrick-embed -> { carrick-engine,
carrick-runtime }` path beside the CLI path, add the product-table row,
add the planned `carrick-conformance-next` row (explicitly marked as not
yet in the tree, with `carrick-conformance` remaining the verdict
authority), and a Feature Closure bullet with the HVF-free closure check
for the linux arm (`scripts/closure-assert-no-hvf.sh` walks carrick-cli
only). `crates/carrick-embed/README.md` carries the quick start, the
stdio/result/error surface, the macOS entitlement requirement, and the
v1 non-goals.

Verified: `grep -c carrick-embed crates/README.md` went 0 -> >=5;
`ls -d crates/*/ | wc -l` = 31 matches the README; `just fmt-check`;
`cargo doc -p carrick-embed` under `RUSTDOCFLAGS="-D warnings"`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

<details><summary>Verifier problems fixed in place (13) and claims still unverified (8)</summary>

- fixed: HEAD mismatch: the brief names 3dc6cc72 but the checkout is at ea0dac4c (two commits later; `crates/carrick-vmm-hvf/src/trap.rs` and `crates/carrick-cli/src/commands.rs` are among the changed files). Every line reference was re-verified at ea0dac4c: `hvf_error` 19821-19823 and `hv_vm_create` 4425 still hold; the commands.rs refs had drifted (see below). Added an explicit 'verified at ea0dac4c' note.
- fixed: Compile error in Step 8 test `workdir_user_hostname_and_max_traps_lower_verbatim`: `spec.uid.get()` / `spec.gid.get()` do not exist. `carrick_abi::NsUid`/`NsGid` (carrick-abi/src/lib.rs:2867, 2987) expose `raw()` (plus `new`, `ROOT`, `is_root`). Changed to `.raw()`.
- fixed: Compile error in Step 8 test `an_absent_image_with_pull_never_is_an_image_error`: `Result::<PreparedContainer, EmbedError>::unwrap_err()` requires `PreparedContainer: Debug`, and the draft's `PreparedContainer` has no `Debug` derive (it holds `RuntimeExtensions`, whose Debug-ness the contract does not promise). Rewrote with `let Err(error) = … else { panic!(…) }`.
- fixed: Step 10 run command `cargo test -p carrick-embed --lib builder:: prepared::` is not runnable: cargo accepts one TESTNAME positional; a second one is an 'unexpected argument' error. Changed to `cargo test -p carrick-embed --lib -- builder:: prepared::` (libtest takes multiple filters after `--`).
- fixed: Step 13 piped `just test 2>&1 | grep … | tail -40`, which AGENTS.md forbids for gates (tail/grep destroys evidence and masks the FAIL exit status). Replaced with a redirect to `target/embed-just-test.log`, an explicit `status=$?` echo, and a grep of the saved log.
- fixed: Hard prerequisite was buried in 'unverified': `Runtime::execute` at `crates/carrick-runtime/src/execute.rs:197-201` has `debug_assert!(tokio::runtime::Handle::try_current().is_err())`. A `tokio::task::spawn_blocking` thread DOES carry a runtime handle, so the contract-mandated `run()` (and the Step 12 `async_run_executes_on_the_blocking_pool` case, which runs in a debug test binary) panics unless Task 21/22 confines that assert to the interactive host-fork path. Promoted to an explicit Interfaces prerequisite with the exact location.
- fixed: Second buried prerequisite: `..RunRequest::default()` (used by the builder and the Step 8 hand-built request) needs `RunRequest: Default`. Today `CliRunRequest` derives only `Debug, Clone` (engine lib.rs:97-98) and `carrick_image::PullPolicy` (lib.rs:410-415) has NO `Default` impl, so Task 19's `#[derive(Default)]` cannot compile without also adding `impl Default for PullPolicy` (= `Missing`) or a manual impl. Recorded in Interfaces so the Task 19 owner sees it.
- fixed: Run-id claim overstated: `crates/carrick-runtime/src/dispatch/proctitle.rs:71` reads `CARRICK_RUN_ID` from the process env itself (the very env read Phase B is replacing), and `scripts/sudo/kill.sh` keys on that proctitle. An embed-GENERATED id therefore reaches kill.sh only once Phase B stamps the title from `LaunchContext::run_id`; an explicit `CARRICK_RUN_ID` (as Step 12 sets) works today. Softened the prepared.rs doc comment and the Step 12 note accordingly.
- fixed: Line-reference drift fixed: `make_test_image` is at `crates/carrick-engine/src/lib.rs:555-574` (not 560-574); the CLI run-id scheme is at `commands.rs:979-998` (not 989-1001) and the carrier init calls at `commands.rs:958,961` (not 960-963); `DEFAULT_MAX_TRAPS` is `runtime.rs:185` on the macOS arm and `lib.rs:453` on the non-macOS arm (451 is the `pub use` line).
- fixed: Step 8 prose implied an existing proof that a docker-archive-seeded store resolves: `load_docker_archive_ingests_blobs_and_summary` (carrick-image lib.rs:1662-1725) only asserts `list_images().len() == 1`; it never calls `resolve`. Reworded so the engineer knows this test is the first resolve-after-load proof (the dir-key equality `default_target()` == `Engine::resolve`'s host-native target, image lib.rs:160-168/251-257, is what makes it work).
- fixed: Step 12 expected `codesign -d --entitlements - … | grep -c com.apple.security.hypervisor` to print exactly `1`; the plist dump can match more than one line. Changed to `>= 1`. Also noted that `CARRICK_DSR_STORE_DIR` is the carrick-native-darwin AOT cache root (`aot_cache.rs:100`), optional isolation on the HVPatch lane.
- fixed: Clippy risk not called out: `EmbedError` wraps `RuntimeError` in two variants; `RuntimeError` already sits at or under clippy's 128-byte `result_large_err` threshold (it is returned bare across the workspace under `-D warnings`), so adding a discriminant can tip `Result<_, EmbedError>` over it. Added a Step 13 note naming the lint and the remedy (box the payload, record the deviation) so a red clippy is not mis-diagnosed.
- fixed: Task 24 line anchors (`:18`, `:70`, `:82`) are pre-edit numbers; Step 2 grows the file by 5 lines so later anchors shift. Added a note to locate each insertion by the quoted line text, which was verified exact at HEAD (README line 3 says `30-crate`; `ls -d crates/*/ | wc -l` = 30 today).
- UNVERIFIED: Task 19's exact RunRequest field names for the three new inputs (`stdio`, `host_env: Option<Vec<(String,String)>>`, `bridge_namespace_id`) and whether `interactive`/`tty` survive on RunRequest — the builder uses `..RunRequest::default()` for everything it does not set, so only the named fields must match.
- UNVERIFIED: Task 21/22 module path `carrick_runtime::prepare` and that `RuntimeExtensions` is `Send` (required to move a PreparedContainer into `tokio::task::spawn_blocking`); that `Runtime::prepare` performs the alias-IPA/fs-resolve carrier init the CLI does at commands.rs:960-963 (both helpers are OnceLock-backed and idempotent, verified at carrick-mem/src/memory.rs:630-660 and fs_resolve_cache.rs:40-84); that the execute.rs:191-200 tokio debug_assert is gone (otherwise `run()` trips it in debug builds).
- UNVERIFIED: Phase B constructor names `ContainerId::allocate()` and `RunId::new(..)` are assumed (the shared contract gives only the pub field shapes and the CLI-only `from_process_env`); adaptation is confined to `embedded_launch_context()` in prepared.rs.
- UNVERIFIED: `RuntimeError: Send` (needed for `spawn_blocking`'s return); every variant's payload (AddressSpaceError, RootFsError, TrapError, DispatchError, FrameInventoryReserveError, anyhow::Error, String) looks Send by inspection but was not compiled.
- UNVERIFIED: The exact HV_DENIED text reaching `RuntimeError::Trap(TrapError::Hypervisor(_))`: applevisor 1.0.0's Display is `"{} (error {:#08x})"` with `as_str() = "operation not allowed by the system"` and code HV_DENIED (`error.rs:52,71,111-115`), copied verbatim by `hvf_error` (carrick-vmm-hvf/src/trap.rs:19821-19823) — so it contains `0xfae94007` — but whether `hv_vm_create`'s failure path at trap.rs:4425 is the one an unsigned embedder hits first (vs an earlier probe) was not run.
- UNVERIFIED: `ImageStore::load_docker_archive` accepting arbitrary entry names (`config.json`, `layer.tar.gz`) — the loader matches manifest names by string equality and re-derives digests from bytes (carrick-image/src/lib.rs:1020-1063), and the default-platform image dir equals the un-suffixed dir Engine::resolve reads (lib.rs:160-168, 251-257); the fixture test was not executed.
- UNVERIFIED: `just test` off macOS derives its crate list from `cargo tree -p carrick-cli` (justfile:30-31,200-203), so carrick-embed's lib tests run only on the macOS lane until a follow-up adds it to `_platform_crates`; not in this cluster's brief.
- UNVERIFIED: Test counts quoted in Step 13 (33 lib cases) and the README crate count (31 after this task; `ls crates` shows 30 crate dirs + README.md today) are computed from the plan text, not from a run.

</details>


<!-- cluster C4-signed-recipe-e2e -->
## Cluster C4-signed-recipe-e2e

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 25..26 -> 31..32), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] C4 consumes a stale Phase-B VM lifecycle: 'sequential PreparedRun::execute calls in ONE carrier process work (the VM is destroyed at run terminal via destroy_persistent_vm_at_run_terminal and re-created)'. B4 renames that fn to `destroy_persistent_vm_at_carrier_exit()` (no alias) and changes the model: the VM persists across containers and is destroyed once at `carrier::shutdown()`/`exit_carrier`. C4's Task 26 red-first step and prose would look for a symbol that no longer exists. FIX: C4 consumes text -> 'B4: VM retained across sequential containers; `destroy_persistent_vm_at_carrier_exit` + `carrier::shutdown()`'; C3 must state that embed never calls `carrier::shutdown()/exit_carrier` (the host process owns exit; VM teardown at process exit is B4's idempotent atexit path) -- add to C3 deviations.
> - [ ] Embed error lowering is split across C3 and C4 without a handoff: C4 requires `EmbedError`'s RuntimeError lowering to delegate to `carrick_embed::entitlement::classify` (Task 25; 'Task 23 must not keep a second lowering') and `is_hv_denied` at the prepare-time `Prepare(_)` lowering, but C3 Task 23 lands first and never mentions entitlement.rs or how `Entitlement` is produced. FIX: C3 Task 23 introduces `entitlement.rs` with the two fns as the SINGLE lowering site (C4 Task 25 then only adds HV_DENIED_MARKER detection, tests and the negative control), or C3 states that Task 23's temporary `EmbedError::Runtime(err)` mapping lives in one private fn `lower_runtime_error` that Task 25 renames to `entitlement::classify`. Either way `PreparedContainer::execute` uses `classify` and `ContainerBuilder::prepare` uses `is_hv_denied`.
> - [ ] Two signed smoke suites for one crate: C3 produces `crates/carrick-embed/tests/guest_smoke.rs` (6 HVF cases, hand-run codesign in Step 12) and C4 produces `tests/signed_smoke.rs` ('runs four guests in one libtest process') + `tests/common/mod.rs` (`guest_lock`, `run_or_fail`, `run_id`, SMOKE_IMAGE) + `tests/entitlement_negative.rs`. Both are run by `scripts/test-signed.sh`, duplicating captured/inherit/piped/parity cases and the run-id handling (C3 generates a short id when CARRICK_RUN_ID is unset; C4's `run_id()` is fail-closed). FIX: C4 Task 26 extends C3's `guest_smoke.rs` (adding the CLI-parity and Piped cases and moving shared helpers into `tests/common/mod.rs`) instead of creating `signed_smoke.rs`; C3's Step 12 hand-run commands are replaced by 'until Task 25's `just test-embed` lands' wording; run-id policy: builder honours an explicit CARRICK_RUN_ID else mints one (C3), the test helper `run_id()` stays fail-closed (C4) -- both consistent.
> - [ ] C5's Gate C parity input and C3's `to_run_request` disagree on the comparison surface: C5 consumes 'Gate C parity test in crates/carrick-embed/tests/ comparing ContainerResult to the CLI RunResult for the same image/command (embed cluster)', C3 produces `to_run_request(&self)` for 'Gate C's CLI/embed RunSpec parity tests' (RunSpec equality, no guest), and C4's `just test-embed` depends on `build` because 'the CLI-parity test needs a signed target/release/carrick' (guest-running result parity). FIX: C3 records that the guest-running parity case (`carrick run --json` envelope exit_code/trap_limit_hit/stdout vs ContainerResult) lives in the signed smoke file owned by C4 Task 26, and C5 links that test by name; the RunSpec parity test stays in C3's no-HVF lib tests.
>
### Task 31: `just test-embed` — sign cargo test executables on the shipped post-link path, fail closed on `HV_DENIED`

> Line numbers below were verified against the checkout HEAD `ea0dac4c` (the
> brief's `3dc6cc72` is 35 commits older; every file cited here except
> `crates/carrick-vmm-hvf/src/trap.rs` and `crates/carrick-cli/src/commands.rs`
> is byte-identical between the two).

**Files:**
- Create: `scripts/lib/post-link-sign.sh` (the vtool + codesign post-link path, lifted verbatim out of `scripts/build-signed.sh:83-90`)
- Modify: `scripts/build-signed.sh:16-17` (source the helper) and `scripts/build-signed.sh:74-90` (call it)
- Create: `scripts/test-signed.sh`
- Create: `crates/carrick-embed/src/entitlement.rs`
- Modify: `crates/carrick-embed/src/lib.rs` (Task 23 output — add `mod entitlement;` and route the `RuntimeError` lowering through `entitlement::classify`)
- Modify: `crates/carrick-embed/Cargo.toml` (Task 23 output — `[dev-dependencies]`)
- Create: `crates/carrick-embed/tests/common/mod.rs`
- Create: `crates/carrick-embed/tests/entitlement_negative.rs`
- Modify: `justfile:366-368` (insert the `test-embed` recipe before `sign`)
- Test: `crates/carrick-embed/src/entitlement.rs` (unit, runs in `just test`), `crates/carrick-embed/tests/entitlement_negative.rs` (negative control, run only by the recipe on an unentitled copy), `just test-embed` (HVF, signed recipe)

**Interfaces:**
- Consumes: `carrick_embed::ContainerBuilder::{from_image, command, pull_policy, run_blocking}` and `carrick_embed::EmbedError::{Entitlement, Runtime(RuntimeError)}` (Task 23; `EmbedError` must implement `Display` — Task 23's `thiserror` derive — because the test helpers format it with `{err}`); `carrick_runtime::run_result::RuntimeError` (`crates/carrick-runtime/src/run_result.rs:19-50`, `pub mod run_result` at `lib.rs:313`); `carrick_runtime::trap::TrapError::Hypervisor(String)` (defined at `crates/carrick-hal/src/trap.rs:303-304`, re-exported by `carrick-runtime/src/lib.rs:265-266` and on macOS at `crates/carrick-vmm-hvf/src/trap.rs:202`); `carrick_image::PullPolicy` (`crates/carrick-image/src/lib.rs:410-415`); `scripts/sudo/kill.sh <run-id>`; `scripts/entitlements.plist`.
- Produces: `sh` function `carrick_post_link_sign <built> <dest> <entitlements.plist>` (`scripts/lib/post-link-sign.sh`); `scripts/test-signed.sh <package> [libtest args...]`; `just test-embed [ARGS]`; `pub(crate) const carrick_embed::entitlement::HV_DENIED_MARKER: &str`; `pub(crate) fn carrick_embed::entitlement::is_hv_denied(err: &RuntimeError) -> bool`; `pub(crate) fn carrick_embed::entitlement::classify(err: RuntimeError) -> EmbedError`; test helpers `carrick_embed` `tests/common/mod.rs`: `pub const SMOKE_IMAGE: &str`, `pub fn guest_lock() -> MutexGuard<'static, ()>`, `pub fn repo_root() -> PathBuf`, `pub fn run_or_fail(Result<ContainerResult, EmbedError>) -> ContainerResult`; the `#[ignore]`d `#[test] fn unsigned_executable_maps_hv_denied_to_entitlement()` whose exact name `scripts/test-signed.sh` looks up.

- [ ] **Step 1: Red — prove the recipe and the script do not exist**

```sh
cd /Volumes/CaseSensitive/carrick
just --summary | tr ' ' '\n' | grep -x test-embed; echo "recipe grep exit=$?"
test -x scripts/test-signed.sh; echo "script exit=$?"
test -f scripts/lib/post-link-sign.sh; echo "helper exit=$?"
```

Expected: `recipe grep exit=1`, `script exit=1`, `helper exit=1` (today `just --summary` lists 49 recipes and none is `test-embed`; `scripts/lib/` does not exist).

- [ ] **Step 2: Red — the `HV_DENIED` classifier, tests first with a stub body**

Create `crates/carrick-embed/src/entitlement.rs`:

```rust
//! `HV_DENIED` classification: the one runtime failure that means "this
//! EXECUTABLE is not entitled", not "the guest failed".
//!
//! Hypervisor.framework refuses `hv_vm_create` with `HV_DENIED`
//! (`0xfae94007`) when the calling executable lacks
//! `com.apple.security.hypervisor`. A bare `cargo build` / `cargo test`
//! output is exactly that executable (AGENTS.md Rule 0). Consumers must see
//! it as its own error — [`EmbedError::Entitlement`](crate::EmbedError) — so
//! a host application can say "sign me" instead of "the container crashed",
//! and so `scripts/test-signed.sh` can FAIL on it instead of skipping.
//!
//! Why a string key: `applevisor::error::HypervisorError::Denied` Displays as
//! `operation not allowed by the system (error 0xfae94007)`; `carrick-vmm-hvf`
//! wraps that verbatim in `TrapError::Hypervisor(String)` (`trap.rs`
//! `hvf_error`), and `carrick-runtime/src/execute.rs` re-wraps the
//! dispatcher's error as `RuntimeError::FsBackend(anyhow!("failed to run ELF
//! from dispatcher: {}", e))`, which erases the variant. The only key that
//! survives both wrappers is applevisor's `(error 0xfae94007)` suffix. A
//! typed hypervisor code on `TrapError` is the durable fix; until then this
//! module is the single place that knows the string, and the recipe's
//! unentitled negative control proves it live on every run.
use carrick_runtime::run_result::RuntimeError;

use crate::EmbedError;

/// `HV_DENIED` exactly as applevisor prints it (`error {:#08x}`).
pub(crate) const HV_DENIED_MARKER: &str = "(error 0xfae94007)";

/// True when `err` is Hypervisor.framework refusing the VM because the
/// calling executable has no hypervisor entitlement.
pub(crate) fn is_hv_denied(err: &RuntimeError) -> bool {
    let _ = err;
    false
}

/// The single `RuntimeError` -> `EmbedError` lowering: the entitlement case
/// gets its own variant; everything else stays a runtime failure.
pub(crate) fn classify(err: RuntimeError) -> EmbedError {
    if is_hv_denied(&err) {
        EmbedError::Entitlement
    } else {
        EmbedError::Runtime(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_runtime::trap::TrapError;

    /// `HypervisorError::Denied` as `applevisor-1.0.0/src/error.rs` Displays it
    /// (`"{} (error {:#08x})"`).
    const APPLEVISOR_DENIED: &str = "operation not allowed by the system (error 0xfae94007)";

    #[test]
    fn typed_trap_hv_denied_is_entitlement() {
        let err = RuntimeError::Trap(TrapError::Hypervisor(APPLEVISOR_DENIED.to_owned()));
        assert!(is_hv_denied(&err), "{err}");
        assert!(matches!(classify(err), EmbedError::Entitlement));
    }

    #[test]
    fn dispatcher_rewrapped_hv_denied_is_entitlement() {
        // execute.rs:404-409: `RuntimeError::FsBackend(anyhow!("failed to run ELF from dispatcher: {}", e))`
        let inner = RuntimeError::Trap(TrapError::Hypervisor(APPLEVISOR_DENIED.to_owned()));
        let err = RuntimeError::FsBackend(anyhow::anyhow!(
            "failed to run ELF from dispatcher: {}",
            inner
        ));
        assert!(is_hv_denied(&err), "{err}");
        assert!(matches!(classify(err), EmbedError::Entitlement));
    }

    #[test]
    fn other_failures_stay_runtime_errors() {
        let busy = RuntimeError::Trap(TrapError::Hypervisor(
            "owning resource is busy (error 0xfae94002)".to_owned(),
        ));
        assert!(!is_hv_denied(&busy));
        assert!(matches!(classify(busy), EmbedError::Runtime(_)));
        let limit = RuntimeError::TrapLimitExceeded { max_traps: 7 };
        assert!(!is_hv_denied(&limit));
        assert!(matches!(classify(limit), EmbedError::Runtime(_)));
    }
}
```

Register the module in `crates/carrick-embed/src/lib.rs` (Task 23's file) next to its other private module declarations:

```rust
mod entitlement;
```

`anyhow` must already be in `[dependencies]` of `crates/carrick-embed/Cargo.toml` (the contract's `EmbedError::Image(anyhow::Error)` needs it); if it is not, add `anyhow = { workspace = true }` there — not under `[dev-dependencies]` — because the product path uses it too.

Run:

```sh
cargo test -p carrick-embed --lib entitlement
```

Expected: `test result: FAILED. 1 passed; 2 failed` — `typed_trap_hv_denied_is_entitlement` and `dispatcher_rewrapped_hv_denied_is_entitlement` fail on `assert!(is_hv_denied(&err))`; `other_failures_stay_runtime_errors` passes.

- [ ] **Step 3: Green — implement the classifier**

In `crates/carrick-embed/src/entitlement.rs` replace

```rust
pub(crate) fn is_hv_denied(err: &RuntimeError) -> bool {
    let _ = err;
    false
}
```

with

```rust
pub(crate) fn is_hv_denied(err: &RuntimeError) -> bool {
    // Display walks every wrapper (`trap engine failed: hypervisor operation
    // failed: …`, `filesystem backend error: failed to run ELF from
    // dispatcher: …`), so the applevisor suffix is reachable from both shapes.
    err.to_string().contains(HV_DENIED_MARKER)
}
```

Run:

```sh
cargo test -p carrick-embed --lib entitlement
```

Expected: `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 4: Route Task 23's error lowering through `classify`**

In `crates/carrick-embed/src/lib.rs` (or wherever Task 23 converts `RuntimeError` into `EmbedError` — its `impl From<RuntimeError> for EmbedError`, and/or the `Err` arm of `PreparedContainer::execute` / `ContainerBuilder::run_blocking`), make that conversion delegate so there is exactly one lowering point:

```rust
impl From<carrick_runtime::run_result::RuntimeError> for EmbedError {
    fn from(err: carrick_runtime::run_result::RuntimeError) -> Self {
        crate::entitlement::classify(err)
    }
}
```

and, if Task 23 matches on the execute error inline instead of `?`/`From`:

```rust
let result = prepared.execute().map_err(crate::entitlement::classify)?;
```

Run `cargo test -p carrick-embed --lib` and `cargo clippy -p carrick-embed --all-targets -- -D warnings`. Expected: all embed unit tests pass; clippy clean (no `dead_code` on `classify`/`is_hv_denied` — both are now reachable from the product path).

- [ ] **Step 5: Lift the shipped binary's post-link path into a shared helper**

Create `scripts/lib/post-link-sign.sh`:

```sh
#!/bin/sh
# Carrick's post-link contract for ANY executable that calls hv_vm_create:
# the shipped CLI (scripts/build-signed.sh) AND cargo test executables that
# boot guests in-process (scripts/test-signed.sh). SOURCED, not executed:
#
#     . scripts/lib/post-link-sign.sh
#     carrick_post_link_sign <built> <dest> <entitlements.plist>
#
# Steps, in order, exactly as build-signed.sh has always done them:
#   1. copy <built> to <dest>.raw.$$ (vtool needs distinct input/output paths);
#   2. stamp the build version. XNU's arm64 exception-return policy preserves
#      physical x18 for binaries linked against the pre-macOS-13 ABI. Tier D
#      proves that behavior again at runtime before using x18; if Apple
#      changes it, Carrick refuses dynamic code rather than trusting this
#      metadata. The private custom-x18 entitlement is intentionally NOT
#      used: ad-hoc signed binaries carrying it are killed by AMFI;
#   3. ad-hoc codesign with the hypervisor entitlement — a bare `cargo build`
#      strips it and every guest then dies HV_DENIED (0xfae94007);
#   4. rename(2) <dest>.tmp.$$ over <dest> ATOMICALLY, so a concurrent exec
#      sees the complete old or new binary, never a torn one.
# Temporaries are <dest>.raw.$$ and <dest>.tmp.$$; callers that want cleanup
# on failure trap on exactly those names. <built> may equal <dest>.
# POSIX sh only: it is sourced by a /bin/sh script and by bash 3.2.
carrick_post_link_sign() {
    _cpls_built="$1"
    _cpls_dest="$2"
    _cpls_entitlements="$3"
    _cpls_raw="$_cpls_dest.raw.$$"
    _cpls_tmp="$_cpls_dest.tmp.$$"
    cp -f "$_cpls_built" "$_cpls_raw"
    /usr/bin/vtool -set-build-version macos 11.0 12.0 -replace -output "$_cpls_tmp" "$_cpls_raw"
    codesign --force --sign - --entitlements "$_cpls_entitlements" "$_cpls_tmp"
    mv -f "$_cpls_tmp" "$_cpls_dest"
    rm -f "$_cpls_raw"
}
```

Modify `scripts/build-signed.sh`. Replace lines 16-17:

```sh
set -e
cd "$(dirname "$0")/.."
```

with

```sh
set -e
cd "$(dirname "$0")/.."
# The vtool + codesign post-link path is shared with scripts/test-signed.sh
# (cargo test executables that boot guests need the identical treatment).
. scripts/lib/post-link-sign.sh
```

and replace lines 74-90:

```sh
# XNU's arm64 exception-return policy preserves physical x18 for binaries
# linked against the pre-macOS-13 ABI. Tier D proves that behavior again at
# runtime before using x18; if Apple changes it, Carrick refuses dynamic code
# rather than trusting this metadata. The private custom-x18 entitlement is
# intentionally NOT used: ad-hoc signed binaries carrying it are killed by
# AMFI on current macOS.
#
# Always materialise ATOMICALLY — vtool requires distinct input/output paths,
# and rename(2) means a concurrent exec sees the complete old or new binary.
mkdir -p target/release
raw="$signed.raw.$$"
tmp="$signed.tmp.$$"
trap 'rm -f "$raw" "$tmp"' EXIT
cp -f "$built" "$raw"
/usr/bin/vtool -set-build-version macos 11.0 12.0 -replace -output "$tmp" "$raw"
codesign --force --sign - --entitlements "$entitlements" "$tmp"
mv -f "$tmp" "$signed"
```

with

```sh
# vtool build-version stamp (x18 ABI) + ad-hoc codesign + atomic rename, in
# scripts/lib/post-link-sign.sh — the rationale lives there. The temporaries
# are <signed>.raw.$$ / <signed>.tmp.$$; clean them up if a step fails.
mkdir -p target/release
raw="$signed.raw.$$"
tmp="$signed.tmp.$$"
trap 'rm -f "$raw" "$tmp"' EXIT
carrick_post_link_sign "$built" "$signed" "$entitlements"
```

Verify the helper alone on a scratch copy of the current binary, then the real path:

```sh
cd /Volumes/CaseSensitive/carrick
scratch=/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad
cp target/release/carrick "$scratch/carrick.unsigned"
codesign --force --sign - "$scratch/carrick.unsigned"
codesign -d --entitlements - "$scratch/carrick.unsigned" 2>&1 | grep -c com.apple.security.hypervisor
sh -c '. scripts/lib/post-link-sign.sh && carrick_post_link_sign "$1" "$2" scripts/entitlements.plist' _ "$scratch/carrick.unsigned" "$scratch/carrick.signed"
codesign -d --entitlements - "$scratch/carrick.signed" 2>&1 | grep -c com.apple.security.hypervisor
/usr/bin/vtool -show-build "$scratch/carrick.signed" | grep -E 'minos|sdk'
ls "$scratch"/carrick.signed.raw.* 2>/dev/null | wc -l
just build
codesign -d --entitlements - target/release/carrick 2>&1 | grep -c com.apple.security.hypervisor
```

Expected: first count `0` (ad-hoc copy has no entitlement), second count `1` (`codesign -d --entitlements -` prints `[Key] com.apple.security.hypervisor` on one line), `minos 11.0` / `sdk 12.0`, `0` leftover raw files, `just build` ends with `built + signed: target/release/carrick (from target/release/carrick, entitlements=scripts/entitlements.plist)` (the `from` path is `$CARGO_TARGET_DIR/release/carrick` when that variable is set — `build-signed.sh:68`), final count `1`.

- [ ] **Step 6: Create `scripts/test-signed.sh`**

```bash
#!/usr/bin/env bash
# Sign and run a crate's cargo test executables so they can boot HVF guests.
#
# A guest under macOS/HVF only runs from an executable carrying the
# com.apple.security.hypervisor entitlement — and the executable that calls
# hv_vm_create is the TEST BINARY (target/debug/deps/<crate>-<hash>), which
# nothing else signs. A bare `cargo test` therefore dies HV_DENIED
# (0xfae94007) on its first guest. This is the test-executable counterpart of
# scripts/build-signed.sh: build the package's test executables without
# running them, push each through the SAME post-link path the shipped CLI
# uses (scripts/lib/post-link-sign.sh: vtool build-version stamp + ad-hoc
# codesign with scripts/entitlements.plist), prove the entitlement landed,
# then run each serially (HVF allows ONE VM per process; the guest tests also
# redirect the process's own fd 1 for the Inherit case).
#
# FAIL-CLOSED by design: an unsigned executable is a FAILURE here, never a
# skip (AGENTS.md: a test no gate executes is not a test). The embed crate
# maps HV_DENIED to `EmbedError::Entitlement`, its guest tests assert that
# variant never appears, and this script additionally runs the NEGATIVE
# control: an ad-hoc-signed copy WITHOUT the entitlement (exactly a bare
# `cargo test` executable) must produce `EmbedError::Entitlement`. A signing
# regression cannot pass silently in either direction.
#
# Usage: scripts/test-signed.sh <package> [libtest args...]
#   scripts/test-signed.sh carrick-embed
#   scripts/test-signed.sh carrick-embed captured_ --nocapture
# The extra args go STRAIGHT to each libtest executable (no cargo in between),
# so do NOT write a `--` separator: libtest would treat everything after it as
# positional filters and silently ignore `--nocapture`.
#
# Written for the macOS system bash (3.2): no mapfile, no `${arr[@]}` on an
# empty array under `set -u`, `+=` array appends only.
#
# Cleanup is run-id scoped: every guest these executables launch carries
# CARRICK_RUN_ID (default embed-signed-<pid>), stamped into the carrier's
# proctitle as `carrick:<run-id>:`; scripts/sudo/kill.sh <run-id> reaps only
# those on exit (plus the `<run-id>-cli` child the CLI-parity test spawns —
# kill.sh anchors on the literal `carrick:<id>:` token, so the `-cli` id needs
# its own call). Never `pkill -f carrick`. Logs are never truncated (tail/grep
# on a gate destroys evidence): every executable's full output goes to the
# terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/post-link-sign.sh

pkg="${1:?usage: scripts/test-signed.sh <package> [libtest args...]}"
shift

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-signed: macOS/HVF only — the entitlement requirement does not exist on this host" >&2
    exit 1
fi
for tool in cargo jq codesign /usr/bin/vtool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "test-signed: missing required tool: $tool" >&2
        exit 1
    fi
done

entitlements="scripts/entitlements.plist"
negative_test="unsigned_executable_maps_hv_denied_to_entitlement"

run_id="${CARRICK_RUN_ID:-embed-signed-$$}"
export CARRICK_RUN_ID="$run_id"
# Hermetic translation store, as `just test` does: fixture guests must never
# warm (or be warmed by) the user's persistent store.
CARRICK_DSR_STORE_DIR="$(mktemp -d -t carrick-test-store)"
export CARRICK_DSR_STORE_DIR

scratch=()
cleanup() {
    status=$?
    # Scoped reap of anything this run (or its CLI-parity child) left wedged.
    # Guests are same-user processes, so a direct call reaps them; `sudo -n`
    # first (NOPASSWD on the rig: scripts/sudo/ is under carrick/*/*/*) also
    # catches root-owned `carrick trace` front-ends carrying the same id.
    for id in "$run_id" "$run_id-cli"; do
        sudo -n scripts/sudo/kill.sh "$id" >/dev/null 2>&1 \
            || scripts/sudo/kill.sh "$id" >/dev/null 2>&1 \
            || true
    done
    rm -rf "$CARRICK_DSR_STORE_DIR"
    if [ "${#scratch[@]}" -gt 0 ]; then
        rm -f "${scratch[@]}"
    fi
    exit "$status"
}
trap cleanup EXIT

# 1. Build (never run) the package's test executables and collect their
#    paths. Only the package's OWN test-profile artifacts carry
#    `profile.test == true` plus an `executable`; dependencies compile with
#    `test: false`. The JSON goes to a file first so a build failure stops the
#    script (a process substitution's exit status would not).
json_log="$(mktemp -t carrick-test-signed-build)"
scratch+=("$json_log")
cargo test -p "$pkg" --no-run --message-format=json >"$json_log"
exes=()
while IFS= read -r exe; do
    [ -n "$exe" ] && exes+=("$exe")
done < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' "$json_log")
if [ "${#exes[@]}" -eq 0 ]; then
    echo "test-signed: cargo produced no test executables for $pkg" >&2
    exit 1
fi

# 2. Sign each executable in place through the shared post-link path, and
#    PROVE the entitlement is on the file before trusting it.
for exe in "${exes[@]}"; do
    scratch+=("$exe.raw.$$" "$exe.tmp.$$")
    carrick_post_link_sign "$exe" "$exe" "$entitlements"
    if ! codesign -d --entitlements - "$exe" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
        echo "test-signed: $exe does not carry com.apple.security.hypervisor after signing" >&2
        exit 1
    fi
    echo "test-signed: signed $exe"
done

# 3. Run each signed executable serially (one VM per process).
failed=0
for exe in "${exes[@]}"; do
    echo "test-signed: running $exe $*"
    if ! env RUST_TEST_THREADS=1 "$exe" "$@"; then
        echo "test-signed: FAIL $exe" >&2
        failed=1
    fi
done

# 4. Negative control. The executable carrying the negative test is copied
#    and re-signed ad-hoc WITHOUT the entitlement — byte-for-byte the state
#    of a bare `cargo test` binary — and must classify HV_DENIED as
#    EmbedError::Entitlement. The test is #[ignore] so step 3 skips it.
carrier=""
for exe in "${exes[@]}"; do
    if "$exe" --list 2>/dev/null | grep -qx "$negative_test: test"; then
        carrier="$exe"
        break
    fi
done
if [ -z "$carrier" ]; then
    echo "test-signed: no test executable of $pkg carries $negative_test; the negative control cannot run" >&2
    exit 1
fi
noent="$carrier.noent.$$"
scratch+=("$noent")
cp -f "$carrier" "$noent"
codesign --force --sign - "$noent"
if codesign -d --entitlements - "$noent" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
    echo "test-signed: $noent still carries the hypervisor entitlement; the negative control would prove nothing" >&2
    exit 1
fi
neg_log="$(mktemp -t carrick-test-signed-negative)"
scratch+=("$neg_log")
echo "test-signed: negative control on $noent"
neg_rc=0
env RUST_TEST_THREADS=1 "$noent" --ignored --exact "$negative_test" >"$neg_log" 2>&1 || neg_rc=$?
cat "$neg_log"
if [ "$neg_rc" -ne 0 ] || ! grep -aq '^test result: ok. 1 passed' "$neg_log"; then
    echo "test-signed: FAIL negative control ($negative_test did not pass on the unentitled copy, rc=$neg_rc)" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    echo "test-signed: FAILED ($pkg)" >&2
    exit 1
fi
echo "test-signed: OK ($pkg: ${#exes[@]} signed executable(s) passed, negative control passed)"
```

Then:

```sh
chmod +x scripts/test-signed.sh
bash -n scripts/test-signed.sh && echo syntax-ok
scripts/test-signed.sh; echo "bare exit=$?"
```

Expected: `syntax-ok`; the bare invocation prints bash's `${1:?}` message containing `usage: scripts/test-signed.sh <package> [libtest args...]` on stderr and `bare exit=1`.

- [ ] **Step 7: Shared test helpers and the negative-control test**

Create `crates/carrick-embed/tests/common/mod.rs`:

```rust
//! Shared helpers for carrick-embed's guest-running (signed) tests.
//!
//! These suites are run ONLY through `just test-embed` (scripts/test-signed.sh),
//! which signs the test executable with the hypervisor entitlement, exports
//! `CARRICK_RUN_ID`, and runs it under `RUST_TEST_THREADS=1`.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use carrick_embed::{ContainerResult, EmbedError};

/// The canonical smoke image: the arm64 probe lane's image
/// (`crates/carrick-cli/tests/conformance.rs:209`, `ARM64.image`) and
/// AGENTS.md's default guest (frame pointers, so `carrick trace` can walk it).
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process: HVF allows one VM per
/// process, and the Inherit case redirects the process's own fd 1. The recipe
/// sets `RUST_TEST_THREADS=1`; this is the in-file belt for a filtered run.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The repository root (`crates/carrick-embed` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-embed lives under crates/carrick-embed")
        .to_path_buf()
}

/// Unwrap a container run, turning `EmbedError::Entitlement` into a loud,
/// actionable FAILURE. Never a skip: an unsigned test executable is a broken
/// gate, not an absent one.
pub fn run_or_fail(outcome: Result<ContainerResult, EmbedError>) -> ContainerResult {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-embed` \
             (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
             can never boot a guest."
        ),
        Err(err) => panic!("container run failed: {err}"),
    }
}
```

Create `crates/carrick-embed/tests/entitlement_negative.rs`:

```rust
//! Negative control for the signed test recipe: on an executable WITHOUT the
//! hypervisor entitlement (a bare `cargo test` binary, or the ad-hoc-resigned
//! copy scripts/test-signed.sh makes), the first guest launch must surface as
//! `EmbedError::Entitlement` — never as a generic runtime failure, and never
//! as a skip.
//!
//! `#[ignore]`d so the SIGNED pass skips it (there it would fail: the guest
//! simply runs). scripts/test-signed.sh looks this test up by name and runs it
//! with `--ignored --exact` on the unentitled copy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_embed::{ContainerBuilder, EmbedError};
use carrick_image::PullPolicy;

#[test]
#[ignore = "negative control: scripts/test-signed.sh runs it on an UNENTITLED copy of this executable"]
fn unsigned_executable_maps_hv_denied_to_entitlement() {
    let _guard = common::guest_lock();
    let outcome = ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/true"])
        .run_blocking();
    match outcome {
        Err(EmbedError::Entitlement) => {}
        Err(other) => panic!(
            "expected EmbedError::Entitlement from an unentitled executable, got: {other}"
        ),
        Ok(result) => panic!(
            "an unentitled executable ran a guest (exit {}): this process IS entitled, \
             so the negative control proves nothing",
            result.exit_code
        ),
    }
}
```

- [ ] **Step 8: Dev-dependencies for the test targets**

In `crates/carrick-embed/Cargo.toml` (Task 23's file) add, or extend, the `[dev-dependencies]` table, using the tree's `{ workspace = true }` spelling (see `crates/carrick-image/Cargo.toml`):

```toml
[dev-dependencies]
libc = { workspace = true }
serde_json = { workspace = true }
tempfile = { workspace = true }
```

(`libc`, `serde_json`, `tempfile` are consumed by Task 26's `signed_smoke.rs`; declaring them here keeps that task a pure test addition. `carrick-image` is NOT added here: the contract's `pull_policy(PullPolicy)` / `image_store(ImageStore)` / `platform(Platform)` make it a regular `[dependencies]` entry of carrick-embed, and integration tests under `tests/` can use a package's regular dependencies directly. Only if Task 23 somehow did not list it, add `carrick-image = { path = "../carrick-image" }` here.)

Run:

```sh
cargo test -p carrick-embed --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable'
```

Expected: two paths — `target/debug/deps/carrick_embed-<hash>` (lib unit tests) and `target/debug/deps/entitlement_negative-<hash>`.

- [ ] **Step 9: The `just test-embed` recipe**

In `justfile`, insert before lines 366-368:

```
# Re-sign an already-built release binary (rarely needed on its own).
sign:
    codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick
```

the recipe:

```
# Guest-running tests of the embedding crate, from SIGNED cargo test
# executables. A cargo test binary is the process that calls hv_vm_create, so
# it needs the hypervisor entitlement ITSELF — `just build` signs only
# target/release/carrick, and a bare `cargo test -p carrick-embed` dies
# HV_DENIED (0xfae94007). scripts/test-signed.sh builds the crate's test
# executables with --no-run, signs each through the shipped binary's post-link
# path (scripts/lib/post-link-sign.sh), proves the entitlement, runs them under
# RUST_TEST_THREADS=1 (one VM per process), then runs an UNENTITLED negative
# control that must classify HV_DENIED as EmbedError::Entitlement. HV_DENIED
# is a failure here, never a skip. ARGS go straight to the libtest executables
# (`just test-embed captured_ --nocapture`; no `--` separator). Depends on
# `build`: the CLI-parity test compares the library against
# target/release/carrick. Needs HVF + the docker.io/library/ubuntu:24.04
# image, so it is an opt-in guest lane like conformance-quick — deliberately
# NOT part of `just ci`.
test-embed *ARGS: build
    ./scripts/test-signed.sh carrick-embed {{ARGS}}
```

- [ ] **Step 10: Green — run the signed recipe (HVF; needs `docker.io/library/ubuntu:24.04` pulled or network to pull it once)**

```sh
cd /Volumes/CaseSensitive/carrick
just --summary | tr ' ' '\n' | grep -x test-embed; echo "recipe grep exit=$?"
test -x scripts/test-signed.sh; echo "script exit=$?"
{ just test-embed; echo "recipe exit=$?"; } 2>&1 | tee target/test-embed-task25.log
grep -a -c 'test-signed: signed ' target/test-embed-task25.log
grep -a 'test result:' target/test-embed-task25.log
grep -a 'test-signed: OK\|recipe exit=' target/test-embed-task25.log
```

(The `{ …; echo "recipe exit=$?"; } | tee` form records the exit status inside the untruncated log and works in both bash and the rig's zsh, where `${PIPESTATUS[0]}` does not exist.)

Expected: `recipe grep exit=0`, `script exit=0`; `built + signed: target/release/carrick …`; two `test-signed: signed …` lines; the lib executable reports `test result: ok. N passed` (N ≥ 3, the entitlement tests plus Task 23's unit tests); the negative executable's signed pass reports `test result: ok. 0 passed; 0 failed; 1 ignored`; the negative control log (printed in full by `cat`) reports `test result: ok. 1 passed`; `test-signed: OK (carrick-embed: 2 signed executable(s) passed, negative control passed)`; `recipe exit=0`. If the negative control instead prints `expected EmbedError::Entitlement … got: …`, the classifier or Task 23's lowering is wrong — do not weaken the assertion.

Also prove the entitlement is really on the test executables:

```sh
for exe in $(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' <(cargo test -p carrick-embed --no-run --message-format=json)); do codesign -d --entitlements - "$exe" 2>&1 | grep -c com.apple.security.hypervisor; done
```

Expected: `1` per executable.

- [ ] **Step 11: House gates and the cleanup receipt**

```sh
just fmt
just clippy
just test
ps -axww -o command= | grep -c 'carrick:embed-signed-'
```

Expected: fmt applies nothing new; clippy clean (`-D warnings` across `--all-targets`, so the new test files compile under the no-panic gate via their file-level allows); `just test` runs carrick-embed's lib tests (`entitlement` ×3) among the parallel crates (`cargo test --workspace --exclude …` — carrick-embed must be a workspace member, Task 23); `0` leftover `carrick:embed-signed-…` processes (the script's own EXIT trap already ran the scoped `kill.sh` for its pid-derived run id — an interactive `kill.sh embed-signed-$$` would use the SHELL's pid and prove nothing).

- [ ] **Step 12: Commit**

```sh
git add scripts/lib/post-link-sign.sh scripts/build-signed.sh scripts/test-signed.sh justfile \
        crates/carrick-embed/Cargo.toml crates/carrick-embed/src/lib.rs crates/carrick-embed/src/entitlement.rs \
        crates/carrick-embed/tests/common/mod.rs crates/carrick-embed/tests/entitlement_negative.rs
git commit -F - <<'EOF'
test(embed): sign cargo test executables for HVF guests

Why: a guest under macOS/HVF only runs from an executable carrying
`com.apple.security.hypervisor`, and for an in-process guest test that
executable is `target/debug/deps/<crate>-<hash>`, which `just build`
never touches. The only in-process VM test in the tree
(`crates/carrick-runtime/tests/trap_hvf.rs`) self-skips on `HV_DENIED`
and runs in no gate, so `carrick-embed`'s guest tests would have been
tests no gate executes. The owner's decision (2026-08-25 spec): a new
signing step for test executables, and `HV_DENIED` is a failure, never
a skip.

What:
- `scripts/lib/post-link-sign.sh` lifts the vtool build-version stamp +
  ad-hoc codesign + atomic rename out of `scripts/build-signed.sh` into
  one sourced function, so the shipped CLI and the test executables
  share one post-link path instead of two drifting copies.
- `scripts/test-signed.sh <package>` builds the package's test targets
  with `--no-run --message-format=json`, signs each through that path,
  proves the entitlement with `codesign -d --entitlements -`, runs each
  under `RUST_TEST_THREADS=1` (one VM per process), and then runs a
  NEGATIVE control: an ad-hoc-signed copy without the entitlement must
  turn `HV_DENIED` into `EmbedError::Entitlement`. Cleanup is scoped by
  `CARRICK_RUN_ID` through `scripts/sudo/kill.sh`.
- `carrick_embed::entitlement` is the single `RuntimeError -> EmbedError`
  lowering; it keys on applevisor's `(error 0xfae94007)` Display suffix
  because `execute.rs` re-wraps the dispatcher error in
  `FsBackend(anyhow!(..))` and erases the `TrapError` variant. A typed
  hypervisor code on `TrapError` is the durable follow-up.
- `just test-embed [ARGS]` (depends on `build`) is an opt-in HVF lane,
  deliberately outside `just ci`.

Verified: `cargo test -p carrick-embed --lib entitlement` red (2 of 3
fail on the stub) then green; the helper on an ad-hoc copy of
`target/release/carrick` goes 0 -> 1 hypervisor entitlement with
`minos 11.0`; `just build` still signs the CLI; `just test-embed`
signs two executables, the lib suite passes, the `#[ignore]`d negative
control is skipped signed and passes (`1 passed`) on the unentitled
copy; `just clippy`, `just test` green.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 32: First signed end-to-end smoke — library vs CLI, and the three stdio sinks

**Files:**
- Create: `crates/carrick-embed/tests/signed_smoke.rs`
- Modify: `crates/carrick-embed/tests/common/mod.rs` (Task 25 output — add `run_id()`)
- Modify: `AGENTS.md:63-66` (Rule 0 bullet "After changing `carrick-runtime`…") and `AGENTS.md:97` (Commands table row `just conformance-probes`)
- Test: `crates/carrick-embed/tests/signed_smoke.rs` — HVF, signed recipe only (`just test-embed`); needs `target/release/carrick` (the recipe's `build` dependency) and `docker.io/library/ubuntu:24.04`

**Interfaces:**
- Consumes: `carrick_embed::{ContainerBuilder, ContainerResult, StdioConfig::{Captured, Inherit, Piped(Box<dyn Write + Send>)}, EmbedError}` with `ContainerBuilder::{from_image, image_store(ImageStore), pull_policy(PullPolicy), command, stdout(StdioConfig), stderr(StdioConfig), run_blocking}`, `ContainerResult { exit_code: i32, signal: Option<Signal>, stdout: Vec<u8>, stderr: Vec<u8>, trap_limit_hit: bool }`, `ContainerResult::{stdout_utf8, stderr_utf8, success}` (Task 23); `carrick_image::{ImageStore::default_for_user, ImageStore::root, PullPolicy::Missing}` (`crates/carrick-image/src/lib.rs:113-134`; `ImageStore` derives `Clone`, `default_for_user` honours `CARRICK_HOME`); the CLI `--json` envelope (`crates/carrick-cli/src/commands.rs:1061-1081`: streamed guest bytes first, then `serde_json::to_string_pretty` of `{image, command, store, exit_code, stdout, stderr, traps, trap_limit_hit, report}`) and `run --pull missing` (`crates/carrick-cli/src/args.rs:427`, `PullArg`); `crates/carrick-runtime/src/dispatch/proctitle.rs:71` honouring `CARRICK_RUN_ID` for the spawned CLI (today a process-global `OnceLock` env read; the Phase B contract moves that read into `LaunchContext::from_process_env()`, so the EMBEDDED process only stamps `carrick:<run-id>:` if Task 23 builds its `LaunchContext` from the process env — confirm when Task 23 lands, otherwise the recipe's scoped reap cannot see library-launched guests); Phase B's guarantee that sequential `PreparedRun::execute` calls in one carrier work (Gate B), since four `#[test]`s run guests in one process.
- Produces: `crates/carrick-embed/tests/common/mod.rs`: `pub fn run_id() -> String`; the four signed tests `captured_stdout_is_hello_world`, `library_result_matches_cli_run`, `inherit_streams_to_the_carrier_stdout`, `piped_delivers_stdout_and_stderr_to_caller_writers`; AGENTS.md documentation of `just test-embed`.

- [ ] **Step 1: Red — the smoke suite does not exist and the recipe runs no guest**

```sh
cd /Volumes/CaseSensitive/carrick
test -f crates/carrick-embed/tests/signed_smoke.rs; echo "file exit=$?"
{ just test-embed; echo "recipe exit=$?"; } >target/test-embed-task26-red.log 2>&1
grep -a 'recipe exit=' target/test-embed-task26-red.log
grep -a -c 'hello world' target/test-embed-task26-red.log
```

Expected: `file exit=1`; the recipe passes (`recipe exit=0`) but `0` — no signed executable has produced guest output yet, i.e. nothing proves the SIGNED path can boot a guest. That is the gap this task closes.

- [ ] **Step 2: `run_id()` helper (fail-closed on a missing stamp)**

In `crates/carrick-embed/tests/common/mod.rs` append after the `run_or_fail` function (whose last lines are):

```rust
        Err(err) => panic!("container run failed: {err}"),
    }
}
```

the helper:

```rust
/// The run id `scripts/test-signed.sh` exported. Every guest this process
/// launches is titled `carrick:<run-id>:`, and the CLI-parity test derives
/// `<run-id>-cli` for the child it spawns, so `scripts/sudo/kill.sh` can reap
/// exactly this run. Fail closed: without the stamp nothing can clean up.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}
```

- [ ] **Step 3: Write the failing smoke suite**

Create `crates/carrick-embed/tests/signed_smoke.rs`:

```rust
//! First signed end-to-end tests for `carrick-embed`: a real HVF guest booted
//! from a cargo test executable, compared against the shipped CLI on the
//! same image and command, with each stdio sink proven.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs this
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and
//! runs it under `RUST_TEST_THREADS=1`. A bare `cargo test` fails here with
//! `EmbedError::Entitlement` — by design, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_embed::{ContainerBuilder, ContainerResult, StdioConfig};
use carrick_image::{ImageStore, PullPolicy};

const HELLO: &[u8] = b"hello world\n";

/// The conformance gate's per-case budget (`CASE_DEADLINE`,
/// `crates/carrick-cli/tests/conformance.rs:169`).
const CLI_DEADLINE: Duration = Duration::from_secs(45);

fn hello_builder(store: &ImageStore) -> ContainerBuilder {
    ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .command(["echo", "hello world"])
}

fn assert_clean_exit(result: &ContainerResult) {
    assert!(
        result.success(),
        "exit_code={} signal={:?} trap_limit_hit={}",
        result.exit_code,
        result.signal.is_some(),
        result.trap_limit_hit
    );
    assert_eq!(result.exit_code, 0);
    assert!(result.signal.is_none(), "guest was killed by a signal");
    assert!(!result.trap_limit_hit, "trap limit hit");
}

#[test]
fn captured_stdout_is_hello_world() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let result = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(result.stdout, HELLO, "stdout={:?}", result.stdout_utf8());
    assert_eq!(result.stdout_utf8(), "hello world\n");
    assert_eq!(result.stderr, b"", "stderr={:?}", result.stderr_utf8());
}

/// What `carrick run --json` prints: the guest's streamed bytes, then the
/// pretty-printed envelope (`crates/carrick-cli/src/commands.rs:1061-1081`,
/// the `if json` arm: output streams live; the envelope's own stdout/stderr
/// fields are informational).
struct CliRun {
    streamed_stdout: Vec<u8>,
    envelope: serde_json::Value,
    status: i32,
}

/// The envelope is `serde_json::to_string_pretty`, so it starts with `{` at
/// column 0 on its own line; everything before that line is the guest's own
/// streamed stdout.
fn split_json_envelope(stdout: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let start = if stdout.starts_with(b"{\n") {
        0
    } else {
        stdout
            .windows(3)
            .position(|w| w == b"\n{\n")
            .map(|i| i + 1)
            .unwrap_or_else(|| {
                panic!(
                    "no JSON envelope in `carrick run --json` stdout: {:?}",
                    String::from_utf8_lossy(stdout)
                )
            })
    };
    let envelope = serde_json::from_slice(&stdout[start..]).expect("parse --json envelope");
    (stdout[..start].to_vec(), envelope)
}

fn run_cli_json(store: &ImageStore) -> CliRun {
    let bin = common::repo_root().join("target/release/carrick");
    assert!(
        bin.exists(),
        "{} missing: `just test-embed` depends on `build`",
        bin.display()
    );
    let run_id = format!("{}-cli", common::run_id());
    let mut child = Command::new(&bin)
        .args([
            "run",
            "--json",
            "--pull",
            "missing",
            common::SMOKE_IMAGE,
            "echo",
            "hello world",
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .env("CARRICK_HOME", store.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn target/release/carrick");
    // Host pid domain: the child is a HOST process (its own process group,
    // set above), so `kill(-pgid)` is the right primitive; no NsPid here.
    let pgid: libc::pid_t = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CLI_DEADLINE {
                    // SAFETY: kill(2) on the child's own process group; the
                    // pgid was created by `process_group(0)` above.
                    let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let output = child.wait_with_output().expect("wait for carrick run");
    done.store(true, Ordering::Relaxed);
    watchdog.join().expect("watchdog thread");
    let status = output.status.code().unwrap_or_else(|| {
        panic!(
            "carrick run died by signal (deadline {CLI_DEADLINE:?}?): {:?}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let (streamed_stdout, envelope) = split_json_envelope(&output.stdout);
    CliRun {
        streamed_stdout,
        envelope,
        status,
    }
}

#[test]
fn library_result_matches_cli_run() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();

    let cli = run_cli_json(&store);
    assert_eq!(cli.status, 0, "carrick run exit status");
    assert_eq!(
        cli.streamed_stdout,
        HELLO,
        "cli stdout={:?}",
        String::from_utf8_lossy(&cli.streamed_stdout)
    );
    assert_eq!(cli.envelope["exit_code"], serde_json::json!(0));
    assert_eq!(cli.envelope["trap_limit_hit"], serde_json::json!(false));

    let lib = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&lib);
    assert_eq!(lib.stdout, cli.streamed_stdout, "library stdout != CLI stdout");
    assert_eq!(
        i64::from(lib.exit_code),
        cli.envelope["exit_code"].as_i64().expect("exit_code"),
        "library exit code != CLI exit code"
    );
    assert_eq!(
        lib.trap_limit_hit,
        cli.envelope["trap_limit_hit"].as_bool().expect("trap_limit_hit")
    );
}

/// Points this process's fd 1 at `file` until dropped. The guest's Inherit
/// sink is the CARRIER's fd 1 (the runtime `libc::write`s guest fd 1 to its
/// own fd 1 under `stream_stdio`); libtest captures only `print!`, never the
/// fd, so a file is the only way to observe it. Restores on drop so a
/// panicking test cannot leave the next one writing into the file.
struct StdoutRedirect {
    saved: libc::c_int,
}

impl StdoutRedirect {
    fn install(file: &std::fs::File) -> Self {
        // libtest's pretty formatter has already flushed its `test <name> ... `
        // prefix (it flushes after every write), but make that a guarantee
        // rather than an implementation detail: nothing of ours may be left
        // buffered on the real fd 1 when it is swapped out.
        std::io::stdout().flush().expect("flush real stdout");
        // SAFETY: dup/dup2 on descriptors this process owns; the suite is
        // serialized by guest_lock() and RUST_TEST_THREADS=1, so no other
        // thread writes fd 1 meanwhile.
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0, "dup(1) failed");
        let rc = unsafe { libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO) };
        assert_eq!(rc, libc::STDOUT_FILENO, "dup2(file, 1) failed");
        Self { saved }
    }
}

impl Drop for StdoutRedirect {
    fn drop(&mut self) {
        // SAFETY: restoring the descriptor we saved above, then closing it.
        unsafe {
            libc::dup2(self.saved, libc::STDOUT_FILENO);
            libc::close(self.saved);
        }
    }
}

#[test]
fn inherit_streams_to_the_carrier_stdout() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let mut sink = tempfile::tempfile().expect("tempfile");
    let result = {
        let _redirect = StdoutRedirect::install(&sink);
        common::run_or_fail(
            hello_builder(&store)
                .stdout(StdioConfig::Inherit)
                .stderr(StdioConfig::Captured)
                .run_blocking(),
        )
    };
    assert_clean_exit(&result);
    assert!(
        result.stdout.is_empty(),
        "Inherit must not also capture: {:?}",
        result.stdout_utf8()
    );
    let mut seen = Vec::new();
    sink.seek(SeekFrom::Start(0)).expect("rewind");
    sink.read_to_end(&mut seen).expect("read fd-1 sink");
    assert_eq!(
        seen,
        HELLO,
        "carrier fd 1 received {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// A `Write` the test keeps a handle to after moving a clone into the builder.
#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn piped_delivers_stdout_and_stderr_to_caller_writers() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let out = SharedSink::default();
    let err = SharedSink::default();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .image_store(store.clone())
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo hello world; echo to-stderr 1>&2"])
            .stdout(StdioConfig::Piped(Box::new(out.clone())))
            .stderr(StdioConfig::Piped(Box::new(err.clone())))
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(out.bytes(), HELLO, "piped stdout={:?}", String::from_utf8_lossy(&out.bytes()));
    assert_eq!(
        err.bytes(),
        b"to-stderr\n",
        "piped stderr={:?}",
        String::from_utf8_lossy(&err.bytes())
    );
    assert!(
        result.stdout.is_empty() && result.stderr.is_empty(),
        "Piped must not also capture"
    );
}
```

Compile the suite without a guest, then prove it is red for the RIGHT reason on an unentitled executable (a bare `cargo test` binary):

```sh
cd /Volumes/CaseSensitive/carrick
cargo test -p carrick-embed --test signed_smoke --no-run
red_id="embed-red-$$"
{ CARRICK_RUN_ID="$red_id" RUST_TEST_THREADS=1 cargo test -p carrick-embed --test signed_smoke -- --exact captured_stdout_is_hello_world; echo "exit=$?"; } 2>&1 | tee target/signed-smoke-red.log
grep -a -c 'HV_DENIED (0xfae94007): this test executable lacks com.apple.security.hypervisor' target/signed-smoke-red.log
scripts/sudo/kill.sh "$red_id"
```

(Here the `--` IS correct: it is consumed by cargo, which forwards `--exact captured_stdout_is_hello_world` to libtest.)

Expected: compiles; the bare run FAILS (`exit=101`, `1 failed`) with the `run_or_fail` panic text — count `1` — i.e. an unsigned executable is a failure, not a skip; `kill.sh` prints `remaining carrick procs (run-id embed-red-…) = 0`.

- [ ] **Step 4: Green — the signed recipe boots the guest (HVF; needs `target/release/carrick` via the recipe's `build` dependency and `docker.io/library/ubuntu:24.04`)**

```sh
cd /Volumes/CaseSensitive/carrick
{ just test-embed; echo "recipe exit=$?"; } 2>&1 | tee target/test-embed-task26.log
grep -a -c 'test-signed: signed ' target/test-embed-task26.log
grep -a 'test result:' target/test-embed-task26.log
grep -a -E '^test (captured_stdout_is_hello_world|library_result_matches_cli_run|inherit_streams_to_the_carrier_stdout|piped_delivers_stdout_and_stderr_to_caller_writers) \.\.\. ok$' target/test-embed-task26.log | wc -l
grep -a 'test-signed: OK\|recipe exit=' target/test-embed-task26.log
```

Expected: `recipe exit=0`; `3` signed executables (lib, `entitlement_negative`, `signed_smoke`); the `signed_smoke` executable reports `test result: ok. 4 passed; 0 failed` and the four named lines count `4`; the negative control still reports `test result: ok. 1 passed`; `test-signed: OK (carrick-embed: 3 signed executable(s) passed, negative control passed)`.

Then the filtered form (ARGS pass-through — no `--`, the args reach libtest directly) and the scoped cleanup receipt:

```sh
just test-embed captured_ 2>&1 | grep -a -E 'test result:|test-signed: OK'
ps -axww -o command= | grep -c 'carrick:embed-signed-'
```

Expected: the smoke executable reports `1 passed` (the other two executables `0 passed` on the filter), `test-signed: OK …`; `0` leftover `carrick:embed-signed-…` processes.

- [ ] **Step 5: Document the lane in AGENTS.md**

In `AGENTS.md`, after the Rule 0 bullet at lines 63-66:

```
- **After changing `carrick-runtime`, rebuild `-p carrick-cli` and re-sign.**
  Building the runtime lib alone does **not** relink `target/release/carrick`, so
  you'll test a stale binary. Confirm the new code is in the binary:
  `strings target/release/carrick | grep <your-marker>`.
```

insert (before the `- **Never swap in a faster linker (`lld`).**` bullet at line 67):

```
- **A cargo test executable is unsigned too.** The entitlement has to be on
  the process that calls `hv_vm_create`; for an in-process guest test that is
  `target/debug/deps/<crate>-<hash>`, which `just build` never touches. Guest
  tests in `carrick-embed` therefore run only through `just test-embed` →
  [`scripts/test-signed.sh`](scripts/test-signed.sh), which signs each test
  executable on the shipped binary's post-link path
  ([`scripts/lib/post-link-sign.sh`](scripts/lib/post-link-sign.sh)), runs
  them serially, and runs an unentitled negative control. `HV_DENIED` there is
  a FAILURE (`EmbedError::Entitlement`), never a self-skip — the
  `trap_hvf.rs` skip pattern is not to be copied.
```

and after the Commands-table row at line 97:

```
| `just conformance-probes` 🔏 | Line-exact ABI probe gate vs Docker. |
```

insert:

```
| `just test-embed [ARGS]` 🔏 | Signed guest tests for `carrick-embed`: `cargo test --no-run`, sign each test executable with the hypervisor entitlement through the shipped post-link path (`scripts/test-signed.sh`), run under `RUST_TEST_THREADS=1`, then an unentitled negative control that must yield `EmbedError::Entitlement`. `HV_DENIED` is a failure, never a skip. Opt-in (HVF + `ubuntu:24.04`); deliberately **not** in `just ci`. |
```

Verify:

```sh
grep -n 'just test-embed' AGENTS.md
```

Expected: exactly two hits — the Rule 0 bullet and the Commands-table row.

- [ ] **Step 6: House gates**

```sh
just fmt
just clippy
just test
```

Expected: fmt applies nothing new; clippy clean under `--all-targets -D warnings` (the smoke suite compiles on every macOS lint run even though only the signed recipe executes it); `just test` green.

- [ ] **Step 7: Commit**

```sh
git add crates/carrick-embed/tests/signed_smoke.rs crates/carrick-embed/tests/common/mod.rs AGENTS.md
git commit -F - <<'EOF'
test(embed): first signed end-to-end smoke against the CLI

Why: Gate C of the embed program needs one signed end-to-end run that
compares the library result to the CLI result for the same image and
command on the same artifact, with `Captured`, `Inherit` and `Piped`
each proven. Until now nothing in the tree booted a guest from a cargo
test executable and PASSED; the only in-process VM test self-skipped on
the unsigned binary.

What: `crates/carrick-embed/tests/signed_smoke.rs`, run only by
`just test-embed` (scripts/test-signed.sh signs the executable and
exports `CARRICK_RUN_ID`):
- `captured_stdout_is_hello_world`: `docker.io/library/ubuntu:24.04`
  (the arm64 probe lane's image) running `echo "hello world"` under
  `Captured` yields exactly `hello world\n`, empty stderr, exit 0, no
  signal, no trap limit.
- `library_result_matches_cli_run`: spawns `target/release/carrick run
  --json` on the same store/image/command under `<run-id>-cli`, splits
  the streamed guest bytes from the pretty-printed envelope, and asserts
  the library's stdout, exit code and `trap_limit_hit` equal the CLI's.
  A 45 s watchdog (the conformance `CASE_DEADLINE`) kills the child's
  process group; cleanup is run-id scoped through `scripts/sudo/kill.sh`.
- `inherit_streams_to_the_carrier_stdout`: fd 1 is dup2'd onto a
  tempfile around the run (restored on drop), proving `Inherit` writes
  the carrier's fd 1 and captures nothing.
- `piped_delivers_stdout_and_stderr_to_caller_writers`: two caller
  `Write` sinks receive `hello world\n` and `to-stderr\n` respectively,
  and `ContainerResult` captures nothing.
`EmbedError::Entitlement` fails every case loudly via `run_or_fail`; it
is never a skip. AGENTS.md documents `just test-embed` in the Commands
table and adds the "a cargo test executable is unsigned too" rule under
Rule 0; the recipe stays out of `just ci` (needs HVF).

Verified: unsigned `cargo test --test signed_smoke` red with the
`HV_DENIED (0xfae94007)` panic (exit 101, not a skip); `just test-embed`
green: 3 signed executables, `signed_smoke` 4 passed, negative control
1 passed on the unentitled copy, zero `carrick:embed-signed-` processes
left; `just clippy`, `just test` green.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

<details><summary>Verifier problems fixed in place (14) and claims still unverified (9)</summary>

- fixed: Revision mismatch: the brief names HEAD 3dc6cc72 but the checkout HEAD is ea0dac4c (35 commits later) and the draft's own citations (`hvf_error` at carrick-vmm-hvf/src/trap.rs:19821, `destroy_persistent_vm_at_run_terminal` at :4137) are ea0dac4c line numbers (19723/4043 at 3dc6cc72). Every other cited file is byte-identical between the two. Recorded the revision explicitly in the draft.
- fixed: `TrapError::Hypervisor(String)` is at crates/carrick-hal/src/trap.rs:303-304, not 302-303 (302 is `UnsupportedPlatform`). Fixed.
- fixed: `proctitle.rs` is at crates/carrick-runtime/src/dispatch/proctitle.rs:71, not crates/carrick-cli/src/dispatch/proctitle.rs (carrick-cli has no dispatch/ directory). Fixed in Task 26 Interfaces. Also noted that line 71 is a process-global `OnceLock` env read which the Phase B contract's `LaunchContext.run_id` replaces, so the embedded library process only stamps `carrick:<run-id>:` if Task 23 derives its `LaunchContext` via `LaunchContext::from_process_env()` (or otherwise honours `CARRICK_RUN_ID`); added as an explicit dependency.
- fixed: AGENTS.md Rule 0 bullet ('After changing carrick-runtime, rebuild…') spans lines 63-66, not 66-69 (66-69 straddles the lld bullet). Fixed the insertion anchor in Task 26 Step 5 and Files list; the Commands-table anchor at line 97 was correct.
- fixed: scripts/test-signed.sh usage example `carrick-embed captured_ -- --nocapture` is wrong: the args are passed straight to the libtest executable, where `--` ends option parsing and `--nocapture` becomes a second positional filter (silently no-op). Fixed to `captured_ --nocapture` in the script header and the recipe comment.
- fixed: The rig's `/usr/bin/env bash` is 3.2.57 (verified), so the script must stay bash-3.2-clean (it is: `+=` arrays, guarded `${#arr[@]}`, no mapfile); documented that constraint in the header. Separately, the interactive verification steps use `${PIPESTATUS[0]}`, which does not exist in the user's zsh (it is `$pipestatus[1]`); rewrote those steps to capture the exit status inside the tee'd group so they work in either shell without truncating logs.
- fixed: Task 25 Step 11 ran `scripts/sudo/kill.sh "embed-signed-$$"` where `$$` is the interactive shell's pid, not the recipe's script pid — it can never match and proves nothing. Replaced with the `ps -axww … grep -c 'carrick:embed-signed-'` leftover-process receipt used in Task 26.
- fixed: Cleanup in test-signed.sh used only `sudo -n scripts/sudo/kill.sh … || true`: when NOPASSWD sudo is absent the reap silently does nothing. Guests are same-user processes, so added a direct (non-sudo) fallback invocation before `|| true`. (conformance.rs:2676 `scoped_kill_guests` and carrick-conformance/src/engine.rs:610 confirm the `sudo -n` pattern; sudoers `carrick/*/*/*` covers scripts/sudo/kill.sh.)
- fixed: Task 26 Step 3 contained a stray `cd /Volutes 2>/dev/null;`. Removed.
- fixed: Task 25 Step 8 dev-dependencies used `libc.workspace = true` spelling and added `carrick-image` as a dev-dep; the tree's convention is `{ workspace = true }` (crates/carrick-image/Cargo.toml) and `carrick-image` must already be a regular dependency of carrick-embed (the contract's `pull_policy(PullPolicy)`/`image_store(ImageStore)`/`platform(Platform)` take its types), which integration tests can use directly. Fixed the spelling and made the carrick-image line conditional.
- fixed: signed_smoke.rs: `StdoutRedirect::into(&File)` is a confusing name (reads as `Into::into`) — renamed to `install`; added an explicit `std::io::stdout().flush()` before the dup2 so libtest's pending `test <name> ... ` prefix can never land in the fd-1 sink (libtest's pretty formatter does flush after every write — verified in library/test/src/formatters/pretty.rs:89-93 — but the exact-bytes assertion should not depend on that); `child.id() as i32` was a bare cast into the host-pid domain — replaced with `libc::pid_t::try_from(..)`; `unsafe { libc::kill(..) };` discarded a result without saying so — made it `let _ = …`.
- fixed: Task 25 Step 5 expected `just build` line hard-codes `(from target/release/carrick, …)`, but build-signed.sh:68 uses `${CARGO_TARGET_DIR:-target}/release/carrick`; noted the CARGO_TARGET_DIR case.
- fixed: Interfaces omitted that `run_or_fail`/the negative test format `EmbedError` with `{err}`/`{other}`, i.e. require `EmbedError: Display` (Task 23's `thiserror` derive); added to Consumes.
- fixed: Draft 'unverified' items now settled and recorded: vtool `-set-build-version macos 11.0 12.0 -replace` + ad-hoc codesign with scripts/entitlements.plist succeed on a copy of a cargo test executable (minos 11.0 / sdk 12.0, entitlement count 1); `codesign -d --entitlements -` output shape is `[Key] com.apple.security.hypervisor` (one line, grep works); libtest `--list` prints `<name>: test`; jq is at /usr/bin/jq; `hv_vm_create` failures propagate in-process as `TrapError::Hypervisor(HypervisorError.to_string())` (trap.rs:4351-4358 → hvf_error), so the `(error 0xfae94007)` marker survives both wrappers; the runtime's only stdio output outside the guest stream is `eprintln!` (engine lib.rs:350, image auth.rs/lib.rs), so CLI stdout stays `hello world\n` + envelope.
- UNVERIFIED: `cargo test --no-run --message-format=json` emitting `profile.test == true` plus `executable` only for the package's own test targets (standard cargo behaviour; not executed in this read-only session).
- UNVERIFIED: `/usr/bin/vtool -set-build-version macos 11.0 12.0 -replace` succeeding on a cargo TEST executable (it is only ever run on target/release/carrick today).
- UNVERIFIED: An ad-hoc-resigned copy without the entitlement (`codesign --force --sign - <copy>`) reaching `hv_vm_create` and failing with HV_DENIED before any other failure, and that failure propagating as a `RuntimeError` (not a process abort) through Task 23's `run_blocking`.
- UNVERIFIED: That the runtime writes nothing of its own to fd 1 of the carrier during a run (grep found zero `println!` in crates/carrick-runtime/src; `libc::write` streaming of guest fd 1 is the intended output) — the Inherit test asserts the tempfile equals exactly `hello world\n`.
- UNVERIFIED: That Captured stderr for `echo` is exactly empty (runtime diagnostics such as the apfs case-insensitivity notice go to the process's stderr, not the captured guest fd 2) — depends on Task 21/22's sink implementation.
- UNVERIFIED: The `--json` envelope keeping its shape (`exit_code`, `trap_limit_hit`) after Phase A/C edits to commands.rs; Phase A item 6 deletes the `compat-report` scaffold and `--raw`, not `--json`, per the spec text.
- UNVERIFIED: Sequential in-process guest runs (four `#[test]`s in one libtest process) — relies on Phase B Gate B; today's tree has one persistent VM per run destroyed at terminal (`destroy_persistent_vm_at_run_terminal`, trap.rs:4137) and process statics the survey lists (`namespace::pid::REGION/REQUESTED`, arena OnceLock).
- UNVERIFIED: `ContainerResult.signal`'s `Signal` type implementing Debug/PartialEq (the plan avoids depending on it: it uses `is_some()`/`is_none()`).
- UNVERIFIED: `sudo -n scripts/sudo/kill.sh` running without a password prompt on the executing machine (memory says scripts under carrick/ are NOPASSWD; conformance.rs already relies on it).

</details>


<!-- cluster C5-docs-handoff -->
## Cluster C5-docs-handoff

> **Status: RECONCILIATION PENDING.** Verifier-corrected against `39426141`; task headings were renumbered mechanically (headings renumbered 27..28 -> 33..34), but by-number cross-references inside the text still use the DRAFT numbering (see the renumber table in the index) and the cross-cluster fixes below have NOT been applied. A future session must apply each item, then remove this block.
>
> - [ ] TASK-NUMBER COLLISIONS (5) + one unnumbered cluster: A3 Task 6 (syscall-map doc row) vs A4 Task 6 (net.rs test module); A4 Task 7/8 vs A5 Task 7/8; B2 Task 14/15 vs B3 Task 14/15; C1 Task 21 (host-authority census reconcile, added in review) vs C2 Task 21 (prepare.rs). A2 carries no task number at all. FIX: renumber globally in dependency order and rewrite every cross-reference ('Task 11', 'Task 18', 'Task 19', 'Task 21/22', 'Task 23', 'Task 25/26') to the new numbers: A1=1-3, A2=4, A3=5-7, A4=8-10, A5=11-13, B1=14-15, B2=16-19, B3=20-21, B4=22-23, C1=24-27, C2=28-29, C3=30-31, C4=32-33, C5=34-35. (All consumers below are stated with the ORIGINAL numbers; the renumbering must be applied on top.)
> - [ ] C5's Gate C parity input and C3's `to_run_request` disagree on the comparison surface: C5 consumes 'Gate C parity test in crates/carrick-embed/tests/ comparing ContainerResult to the CLI RunResult for the same image/command (embed cluster)', C3 produces `to_run_request(&self)` for 'Gate C's CLI/embed RunSpec parity tests' (RunSpec equality, no guest), and C4's `just test-embed` depends on `build` because 'the CLI-parity test needs a signed target/release/carrick' (guest-running result parity). FIX: C3 records that the guest-running parity case (`carrick run --json` envelope exit_code/trap_limit_hit/stdout vs ContainerResult) lives in the signed smoke file owned by C4 Task 26, and C5 links that test by name; the RunSpec parity test stays in C3's no-HVF lib tests.
>
### Task 33: Make `carrick-embed` the active workstream in the controller and docs

**Files:**
- Modify: `handoff.md:3` (Updated line), `handoff.md:51-63` (RESTORED-objective paragraph; the "Do not divert" sentence is line 62), `handoff.md:235-244` (Current direction section; 245 is the trailing blank line)
- Modify: `docs/architecture-overview.md:286-288` (insert `## 5. Embedding` between the `---` at 286 and `## See also` at 288), `docs/architecture-overview.md:298-299` (append a See-also bullet)
- Modify: `docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md:1-13` (banner after the H1; Status line 12-13)
- Modify: `docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md:1-5` (banner after the H1; Status line 5)
- Verify-only (no edit): `AGENTS.md:773-785` ("Where to look next")
- Track (git add, if still untracked): `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md` (already committed on `feat/carrick-embed` as `41ad4da0`; untracked on `main`), `docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md`, `docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md`, `docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md`, and the Phase A–C plan `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md` (see Step 0)
- Test: grep-based assertion script (inline bash, below) — red before, green after

**Interfaces:**
- Consumes: the spec's Decisions table row `| Sequencing | Embed is the active workstream; \`handoff.md\` is updated to say so. |` (`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md:118`); the spec's Execution-model plan path `../plans/2026-08-25-carrick-embed-phase-a-c-plan.md` (spec line 542); the Phase C runtime seam `Runtime::prepare(spec: &RunSpec, launch: LaunchContext, ext: RuntimeExtensions) -> Result<PreparedRun, RuntimeError>` (quoted in the architecture text only).
- Produces: none (documentation). The assertion script below is the durable check that the controller names the workstream.

- [ ] **Step 0: Precondition — the Phase A–C plan document exists at the path the spec names**

This task (and Task 28's receipt) link `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md`. That file is THIS plan; it does not exist in the tree at HEAD `ea0dac4c`. Save the plan there before running Step 1, otherwise the handoff link dangles and Step 7's add is a no-op for it:

```bash
test -e docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md && echo plan-present
```

Expected: `plan-present`. If it prints nothing, stop and write the plan file first.

- [ ] **Step 1: Run the red assertion and confirm every line fails**

Run from the repo root:

```bash
set -u
fail=0
grep -q 'carrick-embed' handoff.md \
  || { echo 'RED: handoff.md does not name carrick-embed'; fail=1; }
grep -q 'docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md' handoff.md \
  || { echo 'RED: handoff.md does not link the governing spec'; fail=1; }
! grep -q 'Do not divert into retired API cleanup; resume the 2,127-suite core' handoff.md \
  || { echo 'RED: superseded directive still present in handoff.md'; fail=1; }
grep -q '^## 5. Embedding' docs/architecture-overview.md \
  || { echo 'RED: architecture-overview has no Embedding section'; fail=1; }
grep -q 'superpowers/specs/2026-08-25-carrick-embed-program-design.md' docs/architecture-overview.md \
  || { echo 'RED: architecture-overview does not point at the spec'; fail=1; }
grep -q '^> \*\*Superseded by' docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md \
  || { echo 'RED: reviewed-program plan has no superseded banner'; fail=1; }
grep -q '^> \*\*Superseded by' docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md \
  || { echo 'RED: versioned-capability spec has no superseded banner'; fail=1; }
exit $fail
```

Expected now: seven `RED:` lines and exit status 1. (Pre-verified on the working tree at `ea0dac4c`: `grep -n -i embed handoff.md` prints nothing; `grep -n 'docs/superpowers' docs/architecture-overview.md` prints nothing; neither 2026-08-23 document contains `Superseded by`.)

- [ ] **Step 2: Verify the AGENTS.md index does not list dated specs (no edit)**

```bash
grep -n 'docs/superpowers' AGENTS.md; echo "exit=$?"
sed -n '773,785p' AGENTS.md
```

Expected: the grep prints nothing and `exit=1`; line 773 is `## Where to look next` and the table at lines 775-785 lists only stable `docs/*.md` pages and `.agents/skills/` (rows: `README.md`, `docs/architecture-overview.md`, `docs/syscalls-emulation-map.md`, `docs/diagnostics-and-debugging.md`, `docs/conformance-testing.md`/`conformance-coverage.md`, `docs/support-matrix.md`, `docs/hal.md`, the four subsystem designs, `.agents/skills/`). The table does not index dated `docs/superpowers/` specs or plans, so AGENTS.md is NOT edited; the durable pointer is the `## 5. Embedding` section added to `docs/architecture-overview.md` in Step 4, which the AGENTS.md table already indexes.

- [ ] **Step 3: Update `handoff.md` (three edits)**

Edit (a) — `handoff.md:3`. Replace exactly:

```markdown
**Updated:** 2026-08-25 (session 8 — host-subprocess retirement closed; core roadmap restored)
```

with:

```markdown
**Updated:** 2026-08-26 (session 9 — `carrick-embed` is the active workstream; owner decision 2026-08-25)
```

Edit (b) — `handoff.md:61-63`, the tail of the RESTORED-objective paragraph. Replace exactly:

```markdown
are green, and scoped cleanup is empty. The objective below is therefore active
again. Do not divert into retired API cleanup; resume the 2,127-suite core
emulation roadmap, correctness first and performance only after exact parity.
```

with:

```markdown
are green, and scoped cleanup is empty. The objective below therefore stands as
the standing correctness-then-performance goal. It is NOT the active
workstream: on 2026-08-25 the owner decided that `carrick-embed` is (see
"Current direction" below and
`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`, Decisions
table, row "Sequencing"). Retired-API cleanup stays out of scope except for the
specific deletions the embed plan's Phase A names.
```

Edit (c) — `handoff.md:235-244`, the whole "Current direction" section. Replace exactly:

```markdown
### Current direction — core emulation roadmap resumed

The retirement receipts are green, so return to the restored core-emulation
roadmap above: freeze and execute the declared 2,127-suite surface, close exact
assertion-level parity with no skips/excuses/retry acceptance, and only then
attack the <=2x performance gate. Continue to lead diagnosis with `carrick
trace`; use `carrick debug lldb-snapshot`/cores when tracing perturbs or misses
the failure.
The retired API and legacy subprocess architecture are no longer the active
workstream.
```

with:

```markdown
### Current direction — `carrick-embed` is the active workstream (owner decision 2026-08-25)

The retirement receipts are green. The owner ruled on 2026-08-25 that the next
work is `carrick-embed`: the Rust library surface that runs a containerized
Linux workload from a host application and exposes what follows from Carrick
being the kernel — VFS injection, syscall observation, time control, fault
injection, zero-copy shared memory, in-process network mocking, resource
budgets and a self-hosted conformance framework. Carrick's own tests are the
first consumer (dog-food first), and the carrier's process statics are
de-globalized before any multi-container claim is made.

Governing documents (the two 2026-08-23 review documents are superseded and
carry a banner saying so):

- Spec: `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`
- Plan (Phases A–C): `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md`
- Source proposal (purpose and spirit):
  `docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md`

Sequencing: Phase A (narrow red-first defect commits, independent of embed) →
Phase B (`Container` as a kernel-graph object; two containers sequentially and
concurrently in ONE carrier) → Phase C (`RunRequest`, `prepare.rs`,
`carrick-embed` v1, signed `just test-embed`). Each phase closes on a dated
receipt under `docs/perf-results/` bound to one signed artifact, exactly as
session 8 did. The 2,127-suite core-emulation roadmap above remains the
standing objective and is served by Phase J (`carrick-conformance-next`); it
becomes the active workstream again when the owner says so, not by inference.

Unchanged and binding: red-first deterministic reducers, Docker bpftrace
ground truth, `carrick trace` first and `carrick debug lldb-snapshot`/cores
when tracing perturbs, guest runs never parallelized, no probe blessed, no
excuse row, no default-off mechanism, `just ci` status read from a FILE. The
retired API and legacy subprocess architecture are not a workstream.
```

- [ ] **Step 4: Add the `## 5. Embedding` section to `docs/architecture-overview.md`**

The file has numbered sections `## 1.` … `## 4.` (line 244 is `## 4. Interactive PtyRelay & Terminal Bridging`, whose `### SIGWINCH via self-pipe` subsection is at 270). Replace exactly (lines 286-288):

```markdown
---

## See also
```

with (the outer fence below is four backticks only so this plan renders; the inserted text is everything between them):

````markdown
---

## 5. Embedding

Carrick is also a library. `carrick-embed` — governed by
[superpowers/specs/2026-08-25-carrick-embed-program-design.md](superpowers/specs/2026-08-25-carrick-embed-program-design.md)
— runs a containerized Linux workload from a host Rust application through the
same seam the CLI uses:

```text
host application
  -> carrick_embed::ContainerBuilder
  -> carrick_engine::RunRequest  ->  Engine::resolve (async; tokio) -> RunSpec
  -> Runtime::prepare(&RunSpec, LaunchContext, RuntimeExtensions) -> PreparedRun
  -> PreparedRun::execute() -> RunResult          (sync; spawn_blocking for async)
  -> HVPatch kernel: ONE carrier / ONE VM / ONE kernel graph
       `- Container objects on the kernel graph (namespace trees)
```

The CLI and the library both lower into `RunRequest` and both call
`Runtime::prepare`, so there is one merge path and one execution path. A
`Container` (`crates/carrick-runtime/src/kernel/container.rs`) is a kernel-graph
object owning its PID-namespace root, rootfs and mount table, hostname, clock
domain, granted capabilities and stdio sink — and, in later phases, its observer
chain and quotas. Carrier-lifetime state (the HVF VM, the `KernelArena`, host
signal dispositions, the SIGWINCH self-pipe of §4, vCPU leases) stays
process-scoped and is never aliased to one container; every `KernelContext`
reaches its container through its task, never through a static. Extensions —
VFS mounts, observers, time control, fault injection, budgets, network
interposition, shared buffers — are installed at `prepare` time and sealed at
`execute`. Guest-running library tests are codesigned test executables run
serially by `just test-embed`; `HV_DENIED` there is a failure, never a skip.

Status: experimental, like the rest of Carrick. Phase status, gates and
non-goals live in the spec; nothing here claims a hardened trust boundary.

---

## See also
````

Then append one bullet after the last See-also bullet (lines 298-299, which end with `syscall-ABI invariant and its owning deterministic probe.`):

```markdown
* [superpowers/specs/2026-08-25-carrick-embed-program-design.md](superpowers/specs/2026-08-25-carrick-embed-program-design.md) — the
  `carrick-embed` program: library surface, `Container` on the kernel graph, and the
  per-phase gates (§5).
```

- [ ] **Step 5: Banner the two superseded 2026-08-23 documents**

`docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md` — insert directly after line 1 (`# Carrick Embed Reviewed Implementation Program`), before the existing blank line (2) and the `> **For agentic workers:**` block (3-8):

```markdown

> **Superseded by [`../specs/2026-08-25-carrick-embed-program-design.md`](../specs/2026-08-25-carrick-embed-program-design.md) (owner decision 2026-08-25).**
> Kept as the static-review record. It no longer governs implementation; do not
> execute its work packages.
```

and replace the Status lines 12-13 exactly:

```markdown
**Status:** Static review complete; proposed future program; no implementation
authorized by this document
```

with:

```markdown
**Status:** Superseded 2026-08-25 by the `carrick-embed` program design (see
banner); retained as the static-review record
```

`docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md` — insert directly after line 1 (`# Versioned Linux Capability Graph for Carrick Embedding`):

```markdown

> **Superseded by [`../specs/2026-08-25-carrick-embed-program-design.md`](../specs/2026-08-25-carrick-embed-program-design.md) (owner decision 2026-08-25).**
> Kept as the static-review record. The capability-graph vocabulary is not the
> governing design; the phases and gates in the 2026-08-25 spec are.
```

and replace line 5 exactly:

```markdown
**Status:** Approved design; awaiting written-spec review
```

with:

```markdown
**Status:** Superseded 2026-08-25 by the `carrick-embed` program design (see banner)
```

- [ ] **Step 6: Run the assertion script again and check the links resolve**

Re-run the Step 1 script. Expected: no output, exit status 0.

Then check every path introduced above exists on disk:

```bash
for f in docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md \
         docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md \
         docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md \
         crates/carrick-runtime/src/kernel/container.rs; do
  test -e "$f" && echo "ok  $f" || echo "MISSING $f"
done
```

Expected: four `ok` lines. `kernel/container.rs` is produced by the Phase B cluster (the `crates/carrick-runtime/src/kernel/` directory exists at HEAD; `container.rs` does not); if this task is executed before Phase B lands, the architecture-overview sentence still names the planned path and `MISSING` on that one line is acceptable — the other three must be `ok` (the plan path is guaranteed by Step 0).

- [ ] **Step 7: Format check and commit**

```bash
just fmt-check
for f in docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md \
         docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md \
         docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md \
         docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md \
         docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md; do
  test -e "$f" || { echo "MISSING $f — every linked document must exist before this commit"; exit 1; }
  git ls-files --error-unmatch "$f" >/dev/null 2>&1 || echo "untracked, will add: $f"
done
```

`git add` aborts on the first pathspec that matches no file and stages nothing, which is why the loop checks existence first. Any path reported `untracked, will add` is added by the command below (already-tracked, unchanged paths are a no-op). Then:

```bash
git add handoff.md docs/architecture-overview.md \
  docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md \
  docs/superpowers/specs/2026-08-23-versioned-linux-capability-embedding-design.md \
  docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md \
  docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-program.md \
  docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md
git commit -F - <<'EOF'
docs: make carrick-embed the active workstream

Why: `handoff.md` (2026-08-25, session 8) restored the 2,127-suite core
emulation roadmap and told the next session "Do not divert into retired
API cleanup; resume the 2,127-suite core emulation roadmap". The owner
decided on 2026-08-25 that `carrick-embed` is the active workstream
(spec `docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`,
Decisions table, row "Sequencing"), with Carrick's own tests as the
first consumer and de-globalization before any multi-container claim. A
controller that still points elsewhere sends the next session the wrong
way, and the two 2026-08-23 static-review documents still read as
governing designs.

What:
- `handoff.md`: session-9 `Updated` line; the RESTORED-objective paragraph
  now says the core roadmap is the standing goal but not the active
  workstream; the "Current direction" section names carrick-embed, its
  spec, the Phase A-C plan and the source proposal, the A -> B -> C
  sequencing, and restates the unchanged binding method rules
  (red-first, bpftrace ground truth, serialized guest runs, file-backed
  CI status).
- `docs/architecture-overview.md`: new `## 5. Embedding` section (the
  builder -> RunRequest -> Runtime::prepare -> PreparedRun::execute
  seam, Container as a kernel-graph object, carrier-lifetime state
  never aliased to a container, signed `just test-embed`) plus a
  See-also bullet.
- Banners on `docs/superpowers/plans/2026-08-23-carrick-embed-reviewed-
  program.md` and `docs/superpowers/specs/2026-08-23-versioned-linux-
  capability-embedding-design.md`: "Superseded by
  ../specs/2026-08-25-carrick-embed-program-design.md (owner decision
  2026-08-25)", with their Status lines updated to match.
- `AGENTS.md` "Where to look next" is deliberately unchanged: it indexes
  stable `docs/*.md` pages and lists no dated `docs/superpowers/`
  document (`grep docs/superpowers AGENTS.md` is empty); the durable
  pointer is the architecture-overview section it already indexes.
- Tracks whichever of the 2026-08-25 spec, the two 2026-08-23 review
  documents, the source proposal and the Phase A-C plan were still
  untracked on this branch, so every link above resolves in history.

Verified: the grep assertion block (seven checks: handoff names
carrick-embed and links the spec, the superseded directive sentence is
gone, architecture-overview has `## 5. Embedding` and links the spec,
both 2026-08-23 documents start with a `Superseded by` banner) exits 1
on the pre-change tree and 0 after; every linked path exists on disk;
`just fmt-check` clean.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 34: Phase C checkpoint — gates and the signed-artifact receipt

**Files:**
- Create: `docs/perf-results/${DATE}-embed-phase-c-checkpoint.md` where `DATE=$(date +%F)` on the day the gates run (the 2026-08-22 precedent is `docs/perf-results/2026-08-22-fork-closure-baseline.md`, whose `## Exact signed artifact` header at lines 12-21 this receipt mirrors)
- Modify: `handoff.md` "Current direction" section (added by Task 27) — one bullet linking the receipt
- Read-only inputs: `justfile:267-284` (`ci`), `justfile:347-364` (`conformance-probes-closure`, comment 347-349, recipe 350-364), `justfile:35-41` (`build` execs `scripts/build-signed.sh` on macOS), `scripts/build-signed.sh:53-66` (source stamping; the three `CARRICK_BUILD_SOURCE_*` env lines are 63-65) and `:82-88` (the re-sign: `cp` to `carrick.tmp.$$`, `vtool`, `codesign --force --sign -`, `mv`), `scripts/conformance/carrier-topology-gate.py:277-287` (`validate_source_binding`) and `:309-356` (`source_identity`/`artifact_receipt` — the tree's definition of the receipt fields; `dwarfdump --uuid` at 345), `handoff.md:175-211` (session 8's file-backed gate pattern and its artifact-identity note), `scripts/perf/native_go_build_abba.py:2195-2228` (`prepare-arm`/`run` argparse), `:1770-1791` (`_publish_receipt` writes `arm.json`), `:225-258` (`validate_arm_mode`, two-binary mode rules), `:1811-1935` (`prepare_arm`: runs `just build` in the source repo, requires `git status --porcelain` EMPTY including untracked files, copies the binary and records `binary_sha256`/`macho_uuid`), `:948-1012` and `:1148-1190` (`run_campaign`: `--quads` ≥ 8, output must not exist, campaign artifact keys), `:880-915` (`_campaign_decision` — an IMPROVEMENT test), `scripts/perf/native_go_build.py:26` (`DEFAULT_IMAGE`), `:37` (`VARIANT_DEFAULT`), `:58-83` (`PERFORMANCE_CONTROL_KEYS`), `:93-100` (`VARIANT_OVERLAYS`), `:355-360` (`fixed_variant_overlay`), `scripts/perf/evidence/native-go-build-abba-control-control-v1.json` (the instrument's control/control resolution: `statistics.metrics.cpu_s.median_quad_ratio` 1.0053, `bootstrap.two_sided_lower` 0.9734, `two_sided_upper` 1.0564, `decision.statistical_pass` false, `accepted` true)
- Test: the receipt-existence and status-file assertions below (red before the gates run, green after)

**Interfaces:**
- Consumes: `just test-embed` (Phase C signing cluster: `cargo test -p carrick-embed --no-run --message-format=json`, codesign each test executable with `scripts/entitlements.plist`, run with `RUST_TEST_THREADS=1`); the Gate C CLI-vs-library parity test inside `crates/carrick-embed/tests/` (embed cluster); `carrick __build-source-marker` (hidden subcommand declared at `crates/carrick-cli/src/args.rs:118`, JSON built by `build_source_marker_json` at `crates/carrick-cli/src/commands.rs:2113-2120`, emitting `{"head","schema":"carrick-build-source-v1","state","tree"}` — serde_json without `preserve_order`, so keys are alphabetical); `scripts/sudo/kill.sh <run-id>`.
- Produces: `docs/perf-results/${DATE}-embed-phase-c-checkpoint.md` — the artifact-bound receipt later phases cite as "Phase C closed on <HEAD>".

**Artifact identity — read this before Step 2.** `just build` always re-signs: `scripts/build-signed.sh:82-88` copies the linked binary to `target/release/carrick.tmp.$$`, rewrites the build version with `vtool`, ad-hoc signs THAT file (so the codesign identifier is `carrick.tmp.<pid>` — the live binary reports `Identifier=carrick.tmp.2298`, the 2026-08-22 receipt `carrick.tmp.49125`), and renames it into place. Consequently every `just build` — including the one `conformance-probes-closure: build` triggers and the one `prepare-arm` runs — changes the codesign identifier, CDHash and SHA-256 even when cargo did not relink. What identifies the LINK is the LC_UUID (set by `ld64`, untouched by `vtool`/`codesign`) plus the `__build-source-marker` head/tree. This task therefore stamps LC_UUID + marker + SHA-256 after every gate, requires LC_UUID and marker to be identical at every stamp, and records the final signing's SHA-256/CDHash/identifier as the receipt's exact artifact. (Session 8 obtained byte-identity only because its closure build was the last re-sign and its later controls did not rebuild — `handoff.md:198-211`.)

- [ ] **Step 1: Red — no Phase C receipt exists and the tree must be clean before anything is built**

```bash
find docs/perf-results -name '*embed-phase-c-checkpoint.md' | wc -l
git status --porcelain --untracked-files=no | wc -l
git status --porcelain | wc -l
git log -1 --format='%H %s'
```

Expected: receipt count `0` (the red), tracked-tree count `0` (if it is not 0, commit or discard first: a receipt taken on a dirty tree is invalid, and `validate_source_binding` in `carrier-topology-gate.py:277-287` refuses one), the untracked count also `0` (Step 7's `prepare-arm` uses plain `git status --porcelain` and refuses ANY untracked path — commit the plan/spec documents via Task 27 first, and do not create the receipt file until Step 9), and the HEAD line names the last Phase C commit.

- [ ] **Step 2: Build the signed artifact on exactly this HEAD, prove the binding, take the first stamp**

```bash
mkdir -p target/perf
: > target/perf/embed-phase-c-provenance.env
stamp() {  # stamp <TAG>: append link identity (UUID, marker) and signing identity (SHA-256) of target/release/carrick
  local B=target/release/carrick tag=$1
  {
    echo "${tag}_UUID=$(xcrun dwarfdump --uuid "$B" | awk '{print $2}')"
    echo "${tag}_MARKER='$("$B" __build-source-marker)'"
    echo "${tag}_SHA256=$(shasum -a 256 "$B" | awk '{print $1}')"
  } >> target/perf/embed-phase-c-provenance.env
}
just build
HEAD=$(git rev-parse HEAD); TREE=$(git rev-parse 'HEAD^{tree}')
expected="{\"head\":\"$HEAD\",\"schema\":\"carrick-build-source-v1\",\"state\":\"clean\",\"tree\":\"$TREE\"}"
actual=$(target/release/carrick __build-source-marker)
echo "$actual"
test "$actual" = "$expected" && echo marker-bound || { echo "MARKER MISMATCH"; exit 1; }
stamp BUILD
cat target/perf/embed-phase-c-provenance.env
```

Expected: `marker-bound`, and three `BUILD_*` lines. `scripts/build-signed.sh:53-65` stamps `CARRICK_BUILD_SOURCE_HEAD/TREE/STATE` at link time from `git diff --quiet HEAD --` (tracked tree only), so an unsigned `cargo build` prints `"unstamped"` values and a binary older than the subcommand fails with `error: unrecognized subcommand '__build-source-marker'` (that is what the stale binary in `target/release/` prints today); either stops the checkpoint here. Shell functions do not persist across separate shells: keep Steps 2-8 in ONE shell session, or re-paste `stamp` before each use.

- [ ] **Step 3: Run the full local gate, status read from a FILE (this is the end-of-Phase-C gate set)**

`just ci` (`justfile:267-284`) runs, in order: `check-frame-pointers → fmt-check → clippy → lint-domains → deny → check-matrix → check --workspace → doc → test → test-integration`. `fmt-check`, `clippy` (`-D warnings`, `--all-targets`), `lint-domains` (`scripts/lint-domains.sh`: semgrep, then `check-host-authority-escape-hatches.py`, then `check-carrier-only-process-invariant.py`; followed by `check-host-authority-transitions.py --check`) and `doc` (`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items`) are the four the brief names; the others come with the recipe and are required by `handoff.md:30-32` ("`just ci` green end to end, status read from a FILE and never from a pipe"). None of these relink the release artifact (`check` and `test` are debug-profile builds), but stamp anyway.

```bash
run_gate() { local log=$1 status=$2; shift 2; ( "$@" ) >"$log" 2>&1; echo $? >"$status"; }
run_gate target/perf/embed-phase-c-just-ci.log target/perf/embed-phase-c-just-ci.status \
  env RUSTC_WRAPPER= RUST_TEST_THREADS=1 just ci
cat target/perf/embed-phase-c-just-ci.status
stamp CI
```

Expected: the status file contains exactly `0`. If it does not, read the FULL log (`grep -a` — it carries binary bytes; never `tail` it into a verdict), fix red-first, re-run Steps 1-3 from a fresh commit (the source HEAD changes with any source change, so the receipt restarts). A `lint-domains` failure on the host-authority census is resolved by reviewing the new `carrick-embed` entries one by one — never a bulk re-bless (`handoff.md:30-32`).

- [ ] **Step 4: Run the signed embed tests, serialized, fail-closed on entitlement**

```bash
run_gate target/perf/embed-phase-c-test-embed.log target/perf/embed-phase-c-test-embed.status \
  env RUSTC_WRAPPER= RUST_TEST_THREADS=1 just test-embed
cat target/perf/embed-phase-c-test-embed.status
grep -ac 'HV_DENIED\|EmbedError::Entitlement\|0xfae94007' target/perf/embed-phase-c-test-embed.log
grep -a 'test result:' target/perf/embed-phase-c-test-embed.log
stamp EMBED
```

Expected: status `0`; the entitlement grep prints `0` (an `HV_DENIED` in this suite is a failure, never a skip, per the spec's "Signed tests" paragraph, lines 291-296); every `test result:` line shows `0 failed` and `0 ignored` for the guest-running suites, including the Gate C parity test (library `ContainerResult` vs CLI `RunResult` for the same image and command on this same binary) and the three stdio modes (`Captured`, `Inherit`, `Piped`) each proven. No Docker container may be running during this step (`docker ps -q | wc -l` → `0`). If the `test-embed` recipe depends on `build`, `EMBED_SHA256` will differ from `BUILD_SHA256` (a re-sign) — acceptable; `EMBED_UUID` must equal `BUILD_UUID` and the marker must be unchanged.

- [ ] **Step 5: Run the fail-closed probe closure on the same link (AGENTS.md: "run the full backend-specific probe set on that binary")**

```bash
run_gate target/perf/embed-phase-c-probes-closure.log target/perf/embed-phase-c-probes-closure.status \
  env RUSTC_WRAPPER= RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes-closure
cat target/perf/embed-phase-c-probes-closure.status
stamp PROBES
grep -E '_(UUID|MARKER)=' target/perf/embed-phase-c-provenance.env
```

Expected: status `0` (closure mode rejects skips, missing artifacts and an unavailable oracle — `justfile:347-349`; `CARRICK_PROBE_WORKERS` is honoured by `crates/carrick-cli/tests/conformance.rs:4249-4318`). The recipe depends on `build`, which re-signs (see "Artifact identity" above), so `PROBES_SHA256` is EXPECTED to differ from `BUILD_SHA256`; what must hold is `PROBES_UUID == BUILD_UUID` and an identical marker. A changed UUID or marker means the source moved and the receipt restarts. This step uses the Docker oracle in its own serialized phase; do not run Step 4 or any other guest concurrently.

- [ ] **Step 6: Prove scoped cleanup**

```bash
pgrep -fl 'target/release/carrick' | wc -l
pgrep -fl 'carrick-conformance' | wc -l
docker ps -q | wc -l
```

Expected: `0`, `0`, `0`. If a `carrick` survivor remains, reap it with `scripts/sudo/kill.sh <its CARRICK_RUN_ID>` (never `pkill -f carrick`) and record the survivor's run-id in the receipt: a non-empty census after reaping invalidates the receipt.

- [ ] **Step 7: No-extension ABBA (Gate C: "no-extension ABBA shows no regression")**

Control = the last pre-Phase-C commit (normally the merge-base of the embed branch with `main`), built signed in its own worktree under `.worktrees/` (never `git stash`); candidate = this HEAD. Both arms run the default path with no extensions installed, so both overlays are the harness's canonical default overlay. The harness's two-binary mode (`validate_arm_mode`) requires distinct source worktrees, roles `control`/`candidate`, and IDENTICAL overlays — exactly this shape.

Preconditions the harness enforces (fix the cause, do not bypass): `prepare-arm` refuses a source repo whose plain `git status --porcelain` is non-empty (untracked files included — `_source_status`), so `git status --porcelain | wc -l` must be `0` in `.` and `.worktrees/` must be ignored (`git check-ignore -q .worktrees && echo ignored` — on this checkout it is, via `.git/info/exclude:18`; on a fresh clone add it there first); `run` rejects an ambient `CARRICK_*` variable (`reject_ambient_carrick`), a busy host (`busy_host_reasons`), thermal pressure or battery power (`_darwin_power_preflight`; `--allow-battery` exists but records it), any foreign carrick process (`foreign_workload_census`) and any running Docker oracle (`running_docker_oracles`); it also refuses an existing `--output` and `--quads` below 8. Docker is not involved (Carrick-only arms); the go image `localhost:5005/carrick-go-conformance:1.24` (`native_go_build.DEFAULT_IMAGE`) must already be in the loopback registry (`scripts/go-conformance-image.sh`).

```bash
BASE=${EMBED_PHASE_C_BASE:-$(git merge-base HEAD main)}
test "$BASE" != "$(git rev-parse HEAD)" \
  || { echo "HEAD is on main: export EMBED_PHASE_C_BASE=<last pre-Phase-C commit> and re-run"; exit 1; }
git check-ignore -q .worktrees || { echo ".worktrees is not ignored; add it to .git/info/exclude"; exit 1; }
test "$(git status --porcelain | wc -l | tr -d ' ')" = 0 || { echo "untracked/dirty paths would fail prepare-arm"; exit 1; }
git worktree add --detach .worktrees/embed-phase-c-control "$BASE"
python3 - <<'EOF'
import json, sys
sys.path.insert(0, "scripts/perf")
import native_go_build as g
with open("target/perf/embed-phase-c-default-overlay.json", "w") as f:
    json.dump(g.fixed_variant_overlay(g.VARIANT_DEFAULT), f)
EOF
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo .worktrees/embed-phase-c-control \
  --destination target/perf/embed-phase-c-abba/control \
  --label embed-phase-c-control --role control \
  --image localhost:5005/carrick-go-conformance:1.24
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo . \
  --destination target/perf/embed-phase-c-abba/candidate \
  --label embed-phase-c-candidate --role candidate \
  --image localhost:5005/carrick-go-conformance:1.24
stamp ABBA
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo . \
  --control-receipt target/perf/embed-phase-c-abba/control/arm.json \
  --candidate-receipt target/perf/embed-phase-c-abba/candidate/arm.json \
  --control-overlay target/perf/embed-phase-c-default-overlay.json \
  --candidate-overlay target/perf/embed-phase-c-default-overlay.json \
  --quads 8 \
  --output target/perf/embed-phase-c-abba/campaign.json
git worktree remove .worktrees/embed-phase-c-control
```

Expected: both `prepare-arm` calls print an `arm.json` receipt (`_publish_receipt` writes exactly `arm.json`, read-only, under `--destination`; fields include `source_commit`, `macho_uuid`, `binary_sha256`); the candidate arm's `macho_uuid` equals `BUILD_UUID` and its `source_commit` equals `$HEAD` (the candidate `prepare-arm` runs `just build` in `.`, which re-signs — `ABBA_SHA256` differs from earlier stamps, `ABBA_UUID` and marker do not). `run` exits 0 after eight A1/B1/B2/A2 quads and writes `campaign.json` with `complete: true`, `accepted: true`, `mode: "two-binary"`.

**Gate C reading.** `campaign.json`'s `decision` is the harness's IMPROVEMENT verdict (`_campaign_decision`: median ratio < 1, one-sided upper < 1, sign test) — for a candidate that merely does not regress it reads `statistical_pass: false` with reason "total CPU statistical gates did not establish an improvement", exactly as the control/control evidence file does. That is NOT a Gate C failure. Gate C's no-regression criterion is read from `statistics.metrics.cpu_s` (primary metric `rusage-children-total-cpu-floor-v1`, i.e. `RUSAGE_CHILDREN` total CPU per quad, candidate/control): PASS iff `bootstrap.two_sided_lower <= 1.0` (the harness's own "supported regression" test, the criterion it applies to secondary metrics) AND `median_quad_ratio <= 1.0563503469116038` (the control/control campaign's `two_sided_upper` in `scripts/perf/evidence/native-go-build-abba-control-control-v1.json`, the instrument's resolution). A regression is a Phase C defect (the spec's performance rule, line 511: with no extensions installed, no heap allocation, lock, trait call or payload formatting is added to the syscall path) and the checkpoint stops until it is fixed red-first.

- [ ] **Step 8: Capture the final provenance (the artifact as it stands after the last re-sign) and prove one link across all stamps**

```bash
set -u
B=target/release/carrick
{
  echo "HEAD=$(git rev-parse HEAD)"
  echo "DIRTY=$(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
  echo "SHA256=$(shasum -a 256 "$B" | awk '{print $1}')"
  echo "IDENT=$(codesign -dvvv "$B" 2>&1 | sed -n 's/^Identifier=//p')"
  echo "CDHASH=$(codesign -dvvv "$B" 2>&1 | sed -n 's/^CDHash=//p')"
  echo "UUID=$(xcrun dwarfdump --uuid "$B" | awk '{print $2}')"
  echo "MARKER='$("$B" __build-source-marker)'"
  echo "HVENT=$(codesign -d --entitlements :- "$B" 2>/dev/null | grep -c 'com.apple.security.hypervisor')"
  echo "DOFSEG=$(otool -l "$B" | grep -A1 'sectname __dof_carrick' | sed -n 's/^ *segname //p')"
} >> target/perf/embed-phase-c-provenance.env
cat target/perf/embed-phase-c-provenance.env
echo "distinct UUIDs: $(grep -E '(^|_)UUID=' target/perf/embed-phase-c-provenance.env | cut -d= -f2 | sort -u | wc -l | tr -d ' ')"
echo "distinct markers: $(grep -E '(^|_)MARKER=' target/perf/embed-phase-c-provenance.env | cut -d= -f2- | sort -u | wc -l | tr -d ' ')"
```

Expected: `DIRTY=0`; `SHA256` is 64 hex chars; `IDENT` is `carrick.tmp.<pid>`; `CDHASH` is 40 hex chars; `UUID` is `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`; `MARKER` is the Step 2 JSON; `HVENT=1`; `DOFSEG=__TEXT` (that is the segment on the current release link — `otool -l target/release/carrick` shows `sectname __dof_carrick` / `segname __TEXT`; AGENTS.md's Rule 0 writes `__DATA,__dof_carrick`, but the receipt copies the live segment name, never the doc's; the 2026-08-22 receipt also says `__TEXT`). `distinct UUIDs: 1` and `distinct markers: 1` — every gate ran on the same link. `xcrun dwarfdump --uuid` prints `UUID: <uuid> (arm64) <path>`, so `awk '{print $2}'` is the UUID (verified on the live binary). An empty `CDHASH` or `DOFSEG`, `HVENT=0`, or more than one distinct UUID/marker invalidates the artifact: rebuild with `just build`, never with `cargo build`, and restart from Step 1.

- [ ] **Step 9: Write the receipt, mirroring the 2026-08-22 baseline header**

```bash
set -u
source target/perf/embed-phase-c-provenance.env
DATE=$(date +%F)
RECEIPT=docs/perf-results/${DATE}-embed-phase-c-checkpoint.md
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
cat > target/perf/embed-phase-c-abba-extract.py <<'PY'
import json
c = json.load(open("target/perf/embed-phase-c-abba/campaign.json"))
m = c["statistics"]["metrics"]["cpu_s"]
b = m["bootstrap"]
out = {
    "schema": c["schema"], "mode": c["mode"], "complete": c["complete"], "accepted": c["accepted"],
    "quad_count": c["statistics"]["quad_count"],
    "primary_metric": c["statistics"]["primary_metric"],
    "cpu_s": {k: m[k] for k in ("control_median", "candidate_median", "median_quad_ratio", "candidate_wins")},
    "cpu_s_bootstrap": {k: b[k] for k in ("two_sided_lower", "two_sided_upper", "one_sided_upper")},
    "decision": c["decision"],
    "gate_c_no_regression": b["two_sided_lower"] <= 1.0 and m["median_quad_ratio"] <= 1.0563503469116038,
}
print(json.dumps(out, indent=2, sort_keys=True))
PY
cat > "$RECEIPT" <<EOF
# carrick-embed Phase C checkpoint

**Date:** ${DATE}
**Lane:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Plan:** \`docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md\`
**Spec:** \`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md\` (Gate C)

This closes Phase C (\`RunRequest\`, \`prepare.rs\`, \`carrick-embed\` v1, signed
\`just test-embed\`) on one exact signed artifact. Any later change to source or
binary invalidates this receipt; Phase D starts from a fresh one. The commit
that adds this file necessarily postdates the artifact's source HEAD below and
changes no compiled input (the session-8 convention, \`handoff.md\`).

## Exact signed artifact

- source HEAD: \`${HEAD}\`
- tracked tree: clean (${DIRTY} modified paths)
- build-source marker: \`${MARKER}\` (\`carrick __build-source-marker\`; head/tree equal to the source HEAD)
- LC_UUID: \`${UUID}\` (link identity — identical at every stamp below)
- binary SHA-256: \`${SHA256}\` (final signing)
- codesign identifier: \`${IDENT}\`
- CDHash: \`${CDHASH}\`
- \`com.apple.security.hypervisor\`: present (${HVENT} occurrence in the entitlements plist)
- \`${DOFSEG},__dof_carrick\`: present

\`scripts/build-signed.sh\` ad-hoc signs a \`carrick.tmp.<pid>\` copy on every
\`just build\`, so the codesign identifier, CDHash and SHA-256 change on each
re-sign of the SAME link (\`conformance-probes-closure\` and \`prepare-arm\`
both rebuild). The link is identified by LC_UUID + source marker; the SHA-256
seen by each gate is recorded per stamp:

$(grep -E '^[A-Z]+_(UUID|SHA256)=' target/perf/embed-phase-c-provenance.env | sed 's/^/- /')

## Gates (file-backed; status never read from a pipe)

| Gate | Command | Status file | Status | Log SHA-256 |
|---|---|---|---:|---|
| \`just ci\` (check-frame-pointers, fmt-check, clippy, lint-domains, deny, check-matrix, check, doc, test, test-integration) | \`env RUSTC_WRAPPER= RUST_TEST_THREADS=1 just ci\` | \`target/perf/embed-phase-c-just-ci.status\` | $(cat target/perf/embed-phase-c-just-ci.status) | \`$(sha target/perf/embed-phase-c-just-ci.log)\` |
| signed embed tests | \`env RUSTC_WRAPPER= RUST_TEST_THREADS=1 just test-embed\` | \`target/perf/embed-phase-c-test-embed.status\` | $(cat target/perf/embed-phase-c-test-embed.status) | \`$(sha target/perf/embed-phase-c-test-embed.log)\` |
| probe closure | \`env RUSTC_WRAPPER= RUST_TEST_THREADS=1 CARRICK_PROBE_WORKERS=1 just conformance-probes-closure\` | \`target/perf/embed-phase-c-probes-closure.status\` | $(cat target/perf/embed-phase-c-probes-closure.status) | \`$(sha target/perf/embed-phase-c-probes-closure.log)\` |

Entitlement failures in the embed suite: $(grep -ac 'HV_DENIED\|EmbedError::Entitlement\|0xfae94007' target/perf/embed-phase-c-test-embed.log) (must be 0).

Embed suite results (verbatim \`test result:\` lines):

\`\`\`text
$(grep -a 'test result:' target/perf/embed-phase-c-test-embed.log)
\`\`\`

## Gate C checklist

- CLI/embed \`RunSpec\` parity tests (no HVF): inside \`just ci\` (\`just test\`).
- One signed end-to-end run comparing the library result to the CLI result for
  the same image and command on this artifact: inside \`just test-embed\`.
- \`Captured\`, \`Inherit\`, \`Piped\` each proven: inside \`just test-embed\`.
- \`just ci\` green: status above.
- No-extension ABBA: below.

## Scoped cleanup

\`pgrep -fl target/release/carrick\`, \`pgrep -fl carrick-conformance\` and
\`docker ps -q\` were all empty after the last gate (recorded at $(date -u +%FT%TZ)).

## No-extension ABBA

Control: \`$(python3 -c 'import json; print(json.load(open("target/perf/embed-phase-c-abba/control/arm.json"))["source_commit"])')\`
(last pre-Phase-C commit) built signed in \`.worktrees/embed-phase-c-control\`;
candidate: this link (arm \`macho_uuid\`
\`$(python3 -c 'import json; print(json.load(open("target/perf/embed-phase-c-abba/candidate/arm.json"))["macho_uuid"])')\`,
must equal the LC_UUID above). Both arms on the harness default overlay
(\`target/perf/embed-phase-c-default-overlay.json\`), 8 quads, campaign
\`target/perf/embed-phase-c-abba/campaign.json\`
(SHA-256 \`$(sha target/perf/embed-phase-c-abba/campaign.json)\`).
Primary metric: \`RUSAGE_CHILDREN\` total CPU per quad, candidate/control.
\`decision\` is the harness's IMPROVEMENT verdict and is expected to read
\`statistical_pass: false\` for a no-change candidate; Gate C's no-regression
reading is \`gate_c_no_regression\` (two-sided lower bound <= 1.0 and median
ratio within the control/control resolution 1.0564 of
\`scripts/perf/evidence/native-go-build-abba-control-control-v1.json\`).

\`\`\`text
$(python3 target/perf/embed-phase-c-abba-extract.py)
\`\`\`
EOF
cat "$RECEIPT"
grep -c 'gate_c_no_regression": true' "$RECEIPT"
```

Expected: the file renders with every field populated (no `unstamped`, no empty backtick pairs); all three Status cells read `0`; the entitlement count reads `0`; the candidate arm's `macho_uuid` equals the LC_UUID; the ABBA block is non-empty and the final grep prints `1`. A `KeyError` from the extract script means the campaign schema moved from `carrick.native-go-build-abba.v1`; read the actual keys with `python3 -c 'import json; print(sorted(json.load(open("target/perf/embed-phase-c-abba/campaign.json"))))'` and quote the harness's own fields — never a paraphrase.

- [ ] **Step 10: Link the receipt from the controller**

In `handoff.md`, inside the "Current direction" section from Task 27, directly after the bullet list that ends with the source-proposal path (`docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md`), add:

```markdown
- Phase C receipt (signed artifact, all gates file-backed):
  `docs/perf-results/${DATE}-embed-phase-c-checkpoint.md`
```

with `${DATE}` written out as the literal date used in Step 9. Then:

```bash
grep -n 'embed-phase-c-checkpoint.md' handoff.md
test -f "$(grep -o 'docs/perf-results/[0-9-]*-embed-phase-c-checkpoint.md' handoff.md | head -1)" && echo link-ok
```

Expected: one matching line and `link-ok`.

- [ ] **Step 11: Format check and commit**

```bash
just fmt-check
git add handoff.md docs/perf-results/*-embed-phase-c-checkpoint.md
git commit -F - <<'EOF'
docs(embed): record the phase C signed-artifact checkpoint

Why: Gate C of the carrick-embed program (spec
`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`)
closes only on one exact signed artifact, and AGENTS.md says a signed
result belongs to one artifact: source HEAD plus binary SHA-256, CDHash,
LC_UUID, hypervisor entitlement and `__dof_carrick`, with the full
backend-specific probe set run on that binary and scoped cleanup proven.
Focused tests or an earlier link's receipt do not qualify this
checkpoint; Phase D must start from a receipt it can cite.

What: `docs/perf-results/<date>-embed-phase-c-checkpoint.md`, mirroring
the header of `docs/perf-results/2026-08-22-fork-closure-baseline.md`:
the exact signed artifact (bound to source through the build-embedded
`__build-source-marker`, identified as a link by LC_UUID + marker and as
a signing by SHA-256/CDHash — `build-signed.sh` re-signs a
`carrick.tmp.<pid>` copy on every `just build`, so the per-gate SHA-256
stamps are listed and the LC_UUID/marker are proven identical across
them), the file-backed status of `just ci` (check-frame-pointers,
fmt-check, clippy, lint-domains, deny, check-matrix, check, doc, test,
test-integration), the signed serialized `just test-embed` run with
zero entitlement failures, `just conformance-probes-closure` on the
same link, the empty post-gate process census, and the no-extension
go-build ABBA (control = pre-Phase-C base commit, candidate = this
link, both on the harness default overlay, 8 quads, two-binary mode)
quoted from the campaign JSON with Gate C read as no-regression
(two-sided lower bound <= 1.0, median within the control/control
resolution), not as the harness's improvement verdict. `handoff.md`
links the receipt from the current-direction section. This commit
postdates the artifact's source HEAD and changes no compiled input.

Verified: every status file contains `0`; the entitlement grep over the
embed log is 0; one distinct LC_UUID and one distinct source marker
across the build, ci, test-embed, probe-closure and ABBA stamps; the
candidate arm's `macho_uuid` equals that LC_UUID; `pgrep` for
carrick/carrick-conformance and `docker ps` are empty after the last
gate; `gate_c_no_regression` is true against
`scripts/perf/evidence/native-go-build-abba-control-control-v1.json`;
`just fmt-check` clean.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

DRAFT'S OWN DEVIATIONS/UNVERIFIED (corrected): {"deviations":["AGENTS.md 'Where to look next' is NOT edited: verified `grep -n 'docs/superpowers' AGENTS.md` is empty and the table (AGENTS.md:775-785, heading at 773) indexes only stable docs/*.md pages plus .agents/skills/; the durable pointer is the new architecture-overview §5, which that table already indexes. Task 27 Step 2 records this verification.","The 'Superseded by' banner is written as a resolvable markdown link `[`../specs/2026-08-25-carrick-embed-program-design.md`](../specs/...)` (the brief gave bare text); from the specs/ directory `../specs/` still resolves. The two documents' `**Status:**` lines are also amended so the header does not contradict the banner.","Task 28 records `__dof_carrick` with the LIVE segment name (`otool -l` on the current release binary shows `segname __TEXT`), not the `__DATA,__dof_carrick` spelling in AGENTS.md Rule 0; the 2026-08-22 receipt and handoff.md:206 also say `__TEXT`.","Task 28 includes `check-frame-pointers`, `deny`, `check-matrix`, `check`, `test`, `test-integration` (the rest of `just ci`) and `just conformance-probes-closure` beyond the four gates the brief names, because handoff.md:30-32 requires `just ci` end-to-end with file-backed status and AGENTS.md requires the full probe set on the receipted binary.","The receipt file name carries the run date (`$(date +%F)`) rather than a fixed date, since the checkpoint date is determined when the gates run.","Task 28 identifies the artifact as a LINK (LC_UUID + `__build-source-marker`) with per-gate SHA-256 stamps, rather than claiming one SHA-256 across all gates: `scripts/build-signed.sh:82-88` signs a `carrick.tmp.$$` copy so every `just build` (which `conformance-probes-closure` and `prepare-arm` both trigger) changes identifier/CDHash/SHA-256 of an unchanged link. The final signing's SHA-256/CDHash/identifier are still recorded as AGENTS.md requires.","Gate C's ABBA is read as a no-regression test on `statistics.metrics.cpu_s` (`bootstrap.two_sided_lower <= 1.0`, `median_quad_ratio` within the control/control `two_sided_upper` 1.0564) because the harness's `decision` field is an improvement verdict that reads `statistical_pass: false` even for the control/control evidence campaign."],"unverified":["`just test-embed` and the Gate C parity test are produced by other Phase C clusters; their exact names/paths are taken from the spec (`just test-embed`, spec lines 291-296) and not from the tree. Whether that recipe depends on `build` (and so re-signs) is unknown; Step 4 tolerates either.","`docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md` does not exist in the tree at `ea0dac4c`; Task 27 Step 0 requires it to be saved (it is this plan) before execution.","The ABBA harness was not executed. `arm.json`, the campaign keys, `validate_arm_mode`'s two-binary rules and `_campaign_decision` were read from the code and from `scripts/perf/evidence/native-go-build-abba-control-control-v1.json`, not from a run.","`scripts/build-signed.sh:53-60` sets `source_state` from `git diff --quiet HEAD --` (tracked files only); `validate_source_binding` requires `state == \"clean\"`.","Line numbers cited for handoff.md (3, 51-63, 235-244), docs/architecture-overview.md (244, 270, 286-288, 298-299), AGENTS.md (773-785), the two 2026-08-23 documents (1, 5, 12-13), justfile, build-signed.sh, carrier-topology-gate.py, native_go_build_abba.py and native_go_build.py are exact at HEAD `ea0dac4c` (the brief said `3dc6cc72`, which is an ancestor 35 commits back; among the cited files only `crates/carrick-cli/src/commands.rs` differs between them). If Phase A/B tasks edit these files first, the executor must re-anchor on the quoted text, not the numbers."]}

<details><summary>Verifier problems fixed in place (14) and claims still unverified (6)</summary>

- fixed: HEAD is `ea0dac4c`, not `3dc6cc72` (3dc6cc72 is an ancestor 35 commits back). Every cited line number was checked against the working tree at ea0dac4c: handoff.md:3/51-63/62/235-244, architecture-overview.md:286-288/298-299, AGENTS.md:773-785, the two 2026-08-23 documents' line 1/5/12-13 are all exact; of the cited files only crates/carrick-cli/src/commands.rs differs between the two commits (the marker fn is at 2113 at ea0dac4c, ~2109 at 3dc6cc72). The 'unverified' note now names the real HEAD.
- fixed: Task 27 Step 4: the replacement block nests a ```text fence inside a ```markdown fence, so the plan's own rendering closes the outer block early and the engineer sees a mangled edit. Outer fence changed to four backticks.
- fixed: Task 27 Step 7: `git add` lists `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md`, which does not exist in the tree; `git add` aborts on the first unmatched pathspec and stages NOTHING, so the commit would go out without handoff.md. Added a Step 0 precondition (the plan document is this plan and must be saved at that path before execution — handoff.md and the receipt link it) and made the add a per-path existence-guarded loop.
- fixed: Task 27 commit body claims the task 'Tracks the 2026-08-25 spec'; the spec is already committed on the `feat/carrick-embed` branch (41ad4da0 'docs(embed): add carrick-embed program design spec'), so on that branch the add is a no-op. Reworded to 'tracks whichever of ... are still untracked'.
- fixed: Task 28 Step 6 (and the commit body) assert the binary SHA-256 is unchanged after `just conformance-probes-closure`. False: the recipe depends on `build`, and `scripts/build-signed.sh:82-88` copies to `carrick.tmp.$$`, runs vtool, and `codesign --force --sign -` on THAT file, so the codesign identifier is `carrick.tmp.<pid>` (the live binary shows `Identifier=carrick.tmp.2298`; the 2026-08-22 receipt records `carrick.tmp.49125`) — every `just build` changes identifier, CDHash and SHA-256 even for an unchanged link. The link-invariant identity is LC_UUID + the `__build-source-marker` head/tree. Restructured: a `stamp` helper records UUID/marker/SHA after every gate, the final SHA-256/CDHash are captured after the LAST re-sign, and the receipt states which identity is link-bound and which is signing-bound (session 8's precedent at handoff.md:198-211 got byte-identity only because its closure build was the last re-sign).
- fixed: Task 28 Step 8: `prepare-arm` publishes `arm.json` under `--destination` (`_publish_receipt`, native_go_build_abba.py:1770-1791), not `receipt.json`; the `run` invocation would fail to load the receipts. Fixed.
- fixed: Task 28 Step 8: `prepare_arm` checks cleanliness with plain `git status --porcelain` (`_source_status`, no `--untracked-files=no`), so ANY untracked file — a not-yet-committed receipt, a stray plan draft — makes the candidate arm fail with 'arm preparation requires a clean source repository'. Also `.worktrees/` is ignored only through `.git/info/exclude` on this checkout, so the control worktree itself would show as `??` on a fresh clone. Added both preconditions.
- fixed: Task 28 Step 8: `git merge-base HEAD main` degenerates to HEAD when the executor is on `main` (control == candidate, and two-binary mode then rejects identical source repos). Added a guard requiring BASE != HEAD with an explicit override.
- fixed: Task 28 Steps 8-9: the campaign JSON has no `result`/`summary`/`verdict`/`median` keys; its top level is schema/campaign_id/started_at/finished_at/complete/accepted/mode/identity/preflights/quad_membership/samples/statistics/decision/failure (verified against scripts/perf/evidence/native-go-build-abba-control-control-v1.json). More importantly `decision` is an IMPROVEMENT test (`_campaign_decision`: median<1, one-sided upper<1, sign test) — the control/control evidence file itself reads `statistical_pass=false`, `median_quad_ratio=1.0053`, two-sided CI [0.9734, 1.0564] while `accepted=true`. A no-change Phase C candidate will therefore show `statistical_pass=false`, which the draft's executor would misread as failure. Gate C's no-regression reading is now defined from `statistics.metrics.cpu_s`: `bootstrap.two_sided_lower <= 1.0` (the harness's own 'supported regression' criterion) and `median_quad_ratio <= 1.0564` (the control/control two-sided upper), and the receipt extracts exactly those fields.
- fixed: Task 28 Step 2: a stale binary that predates the hidden subcommand does not print `unstamped` — it fails with `error: unrecognized subcommand '__build-source-marker'` (observed on the current target/release/carrick). Added; also the subcommand is declared in `crates/carrick-cli/src/args.rs:118` (`#[command(name = "__build-source-marker", hide = true)]`), the JSON is built by `build_source_marker_json` at commands.rs:2113-2120, and serde_json in Cargo.lock has no `preserve_order` (deps: itoa/memchr/serde/serde_core/zmij) so the key order is alphabetical as claimed.
- fixed: Task 28 Step 1: relies on an unmatched glob reaching `ls`; replaced with `find ... | wc -l` so the red is shell-independent.
- fixed: Task 28 'Read-only inputs': `justfile:267-283` for `ci` is 267-284 (the recipe ends at `j test-integration` on 284); `justfile:350-362` for `conformance-probes-closure` is 350-364 (comment 347-349). `handoff.md:31-33` for the no-bulk-re-bless rule is 30-32. Fixed.
- fixed: Task 28 Step 4 text: `lint-domains` is `./scripts/lint-domains.sh` (semgrep, then `check-host-authority-escape-hatches.py`, then `check-carrier-only-process-invariant.py`) followed by `check-host-authority-transitions.py --check` — draft omitted the escape-hatches check; added.
- fixed: Task 28 receipt: like session 8 (handoff.md:207-211), the receipt/handoff commit necessarily postdates the artifact's source HEAD; the receipt now says so explicitly instead of implying the doc commit produced the link.
- UNVERIFIED: `just test-embed` and the Gate C parity test are produced by other Phase C clusters; their exact names/paths are taken from the spec (`just test-embed`) and not from the tree.
- UNVERIFIED: `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md` does not exist yet in the tree; the path is the one the spec's Execution model names.
- UNVERIFIED: The ABBA harness was not executed: the `prepare-arm` receipt file name under `--destination` (assumed `receipt.json`) and the top-level keys of the `run --output` campaign JSON were not read from the code; Task 28 Steps 8-9 instruct the executor to substitute the emitted names. `native_go_build.VARIANT_DEFAULT` is referenced in `VARIANT_OVERLAYS` (native_go_build.py:94-95) but its own definition line was not read.
- UNVERIFIED: `scripts/build-signed.sh` line 55-60 sets `source_state`; only that `validate_source_binding` requires `state == "clean"` was read, not every branch producing that value.
- UNVERIFIED: `xcrun dwarfdump --uuid` output shape (`UUID: <uuid> (arm64) <path>`) is assumed from the harness's use of it (`carrier-topology-gate.py:347`); the `awk '{print $2}'` extraction was not run.
- UNVERIFIED: Line numbers cited for handoff.md (3, 51-63, 235-245) and docs/architecture-overview.md (286-288, 298-299) are exact at HEAD 3dc6cc72's working tree today; if Phase A/B tasks edit those files first, the executor must re-anchor on the quoted text, not the numbers.

</details>
