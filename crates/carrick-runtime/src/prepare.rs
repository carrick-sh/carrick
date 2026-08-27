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
//! undoes its own publication: the `Arc<Container>` drops its PID namespace
//! region back to the arena; the `Arc<RuntimeNetwork>` destroys its namespace
//! lease; a fresh [`HostFsBackend`] reclaims its scratch `TempDir` (layers,
//! seeded `/etc/*` and all); [`InteractiveSession`] restores fds 0–2; bind,
//! rosetta and extension mounts live in the dispatcher's own mount table.
//! An ATTACHED overlay (`LaunchContext::exec_overlay` or a managed
//! container's `<registry>/<id>/scratch`) is never removed here — the
//! registry owns it and `carrick rm` reaps it — and its `scratch_path`
//! record is written only after the overlay exists, so a failed preparation
//! publishes nothing. Carrier-scoped statics (`publish_root_net_view`,
//! the host process title) are overwritten by the next `prepare`.

use std::path::PathBuf;
use std::sync::Arc;

use camino::Utf8PathBuf;
use carrick_spec::{FsBackendKind, PidMode, Platform, RunSpec, StdioMode};

pub use crate::dispatch::StdioSink;
use crate::dispatch::SyscallDispatcher;
use crate::execute::{
    HostRootLayout, cached_lower_enabled, detached_stable_scratch_path, effective_guest_hostname,
    entrypoint_not_executable_result, entrypoint_not_found_result, install_rosetta_mounts,
    is_entrypoint_not_executable, is_entrypoint_not_found, prepare_host_root,
    record_detached_scratch, rosetta_license_notice, seed_guest_baseline,
};
use crate::fs_backend::HostFsBackend;
use crate::interactive_supervisor::InteractiveSession;
use crate::kernel::container::LaunchContext;
use crate::network::RuntimeNetwork;
#[cfg(feature = "platform-macos")]
use crate::runtime::run_elf_from_dispatcher_debug;
use crate::runtime::{RunResult, RuntimeError};
use crate::vfs::{BindVfs, HostResolverSnapshot, Vfs};

pub struct Runtime;

/// Everything `prepare` resolves before it touches the filesystem: page
/// geometry, the host resolver snapshot, the network lease and
/// the verbatim environment. Owns the [`LaunchContext`].
pub struct ExecutionPlan {
    launch: LaunchContext,
    page: crate::page_profile::ExecutionPlan,
    host_resolver: Option<HostResolverSnapshot>,
    network: Arc<RuntimeNetwork>,
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
    observers: Vec<Arc<dyn crate::observe::SyscallObserver>>,
    time: Option<crate::kernel::container::TimeControl>,
    network_interposer: Option<crate::network::interposer::NetworkInterposer>,
}

impl RuntimeExtensions {
    /// Mount `vfs` at the absolute guest path `target` (longest prefix wins,
    /// shadowing the image and any `RunSpec` bind mount at the same point).
    pub fn vfs_mount(mut self, target: Utf8PathBuf, vfs: Box<dyn Vfs>) -> Self {
        self.vfs_mounts.push((target, vfs));
        self
    }

    /// The caller-owned sink for a `StdioMode::Piped` run. For
    /// `Inherit`/`Captured` the `RunSpec::stdio` mode alone is authoritative
    /// and supplying a sink here is a `RuntimeError::Configuration` (see
    /// `resolve_stdio`) — never a silent override of the spec.
    pub fn stdio(mut self, sink: StdioSink) -> Self {
        self.stdio = Some(sink);
        self
    }

    /// Register a syscall observer to receive lifecycle and syscall events.
    pub fn observer(mut self, observer: Arc<dyn crate::observe::SyscallObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Register multiple syscall observers.
    pub fn observers<I>(mut self, observers: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn crate::observe::SyscallObserver>>,
    {
        self.observers.extend(observers);
        self
    }

    /// Time control for the container.
    pub fn time(mut self, control: crate::kernel::container::TimeControl) -> Self {
        self.time = Some(control);
        self
    }

    /// Register a network interposer to mock or intercept outbound guest connections.
    pub fn network_interposer(
        mut self,
        interposer: crate::network::interposer::NetworkInterposer,
    ) -> Self {
        self.network_interposer = Some(interposer);
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
        (StdioMode::Piped, Some(sink @ StdioSink::Piped { .. })) => Ok(sink),
        (StdioMode::Piped, _) => Err(RuntimeError::Configuration(
            "StdioMode::Piped requires RuntimeExtensions::stdio(StdioSink::Piped { .. })"
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
    Memory {
        rootfs: crate::rootfs::RootFs,
    },
}

/// A fully built container waiting to boot. Single-use: `execute` takes
/// `self`. Field order is drop order — the dispatcher (which owns the fs
/// backend and the network lease) first, then the terminal restore.
pub struct PreparedRun {
    executable: String,
    argv: Vec<String>,
    env: Vec<String>,
    max_traps: usize,
    debug_state_path: Option<PathBuf>,
    root: RootBacking,
    dispatcher: SyscallDispatcher,
    interactive_session: Option<InteractiveSession>,
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
fn configure_identity_and_policy(
    dispatcher: &mut SyscallDispatcher,
    spec: &RunSpec,
    container: &crate::kernel::Container,
) {
    if let Some(cwd) = &spec.cwd {
        dispatcher.set_cwd(cwd.as_str());
    }
    dispatcher.set_credentials(spec.uid, spec.gid);
    // Launch-time container syscall policy (the Docker default-seccomp model,
    // or unconfined) — before boot, inherited by the whole guest process tree.
    dispatcher.apply_launch_privileges(spec.seccomp_policy, container);
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
    container: &Arc<crate::kernel::Container>,
) -> Result<SyscallDispatcher, RuntimeError> {
    let exec_overlay = container.launch().exec_overlay.as_deref();
    let managed_scratch = match exec_overlay {
        Some(_) => None,
        None => container
            .launch()
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
    dispatcher.set_container(Arc::clone(container));
    if let HostRootLayout::CachedLower(rootfs) = root_layout {
        dispatcher.set_rootfs_layer(rootfs);
    }
    let guest_hostname = effective_guest_hostname(spec);
    configure_page_and_hostname(&mut dispatcher, plan, guest_hostname.as_ref());
    // Sandboxed container fs: forbid the execve host-fs fallback so a target
    // absent from the container ENOENTs instead of escaping to the host.
    dispatcher.sandbox_exec_to_container();
    dispatcher.set_executable_path(spec.executable.clone());
    configure_identity_and_policy(&mut dispatcher, spec, container);

    let hosts_entries = plan
        .network
        .guest_hosts_entries()
        .map_err(|e| RuntimeError::Unsupported(format!("network hosts setup failed: {e}")))?;
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
    container: &Arc<crate::kernel::Container>,
) -> Result<(SyscallDispatcher, crate::rootfs::RootFs), RuntimeError> {
    let rootfs = crate::rootfs::RootFs::from_layer_paths(&layer_paths(spec))
        .map_err(|e| RuntimeError::FsBackend(anyhow::anyhow!("failed to compose rootfs: {e}")))?;
    let mut dispatcher =
        SyscallDispatcher::with_rootfs_and_executable(rootfs.clone(), spec.executable.clone());
    dispatcher.set_container(Arc::clone(container));
    if let Some(snapshot) = plan.host_resolver.as_ref() {
        dispatcher.set_host_resolver_snapshot(snapshot);
    }
    let guest_hostname = effective_guest_hostname(spec);
    configure_page_and_hostname(&mut dispatcher, plan, guest_hostname.as_ref());
    configure_identity_and_policy(&mut dispatcher, spec, container);
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
        static CARRIER_INIT: std::sync::Once = std::sync::Once::new();
        CARRIER_INIT.call_once(|| {
            crate::memory::init_alias_ipa_allocator();
            crate::fs_resolve_cache::init();
        });

        let RuntimeExtensions {
            vfs_mounts,
            stdio,
            observers,
            time,
            network_interposer,
        } = ext;
        let sink = resolve_stdio(spec, stdio)?;
        if spec.platform == Platform::Amd64 {
            rosetta_license_notice();
        }
        let ExecutionPlan {
            launch,
            page,
            host_resolver,
            network,
            env,
        } = resolve_plan(spec, launch)?;
        let network = if let Some(interposer) = network_interposer {
            let net = match Arc::try_unwrap(network) {
                Ok(net) => net.with_interposer(interposer),
                Err(_) => {
                    let net = RuntimeNetwork::create(&spec.network).map_err(|e| {
                        RuntimeError::Unsupported(format!("network setup failed: {e}"))
                    })?;
                    net.with_interposer(interposer)
                }
            };
            Arc::new(net)
        } else {
            network
        };
        let plan = ExecutionPlan {
            launch,
            page,
            host_resolver,
            network,
            env,
        };

        let mut container = crate::kernel::Container::new(plan.launch.clone())
            .with_launch_capabilities(&spec.cap_add);
        if let Some(control) = time {
            container = container.with_time_control(control);
        }
        let container = Arc::new(container);

        match spec.pid {
            PidMode::Host => {}
            PidMode::Private => {
                let region = crate::namespace::pid::NsSharedRegion::allocate(
                    carrick_kernel::arena::KernelArena::global(),
                )
                .map_err(|e| {
                    RuntimeError::Configuration(format!(
                        "all 64 arena PID namespace slots are claimed: {e:?}"
                    ))
                })?;
                container.install_pid_ns(region).map_err(|_| {
                    RuntimeError::Configuration("pid namespace already installed".into())
                })?;
            }
        }

        let (mut dispatcher, root) = match spec.fs_backend {
            FsBackendKind::Host => (
                prepare_host_backend(spec, &plan, &container)?,
                RootBacking::Host,
            ),
            #[cfg(feature = "fs-memory")]
            FsBackendKind::Memory => {
                let (dispatcher, rootfs) = prepare_memory_backend(spec, &plan, &container)?;
                (dispatcher, RootBacking::Memory { rootfs })
            }
        };

        // Extensions go in after the image, bind and rosetta mounts so an
        // embedder's mount at the same point shadows them (re-mount replaces).
        for (target, vfs) in vfs_mounts {
            dispatcher.register_mount(PathBuf::from(target.as_std_path()), vfs);
        }
        for observer in observers {
            dispatcher.install_observer(observer);
        }
        dispatcher.set_stdio_sink(sink);
        let interactive_session = if spec.tty {
            Some(InteractiveSession::start(&mut dispatcher).map_err(|e| {
                RuntimeError::FsBackend(anyhow::anyhow!(
                    "failed to create carrier-local interactive PTY: {e}"
                ))
            })?)
        } else {
            None
        };

        let ExecutionPlan { env, .. } = plan;
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
        } = self;
        #[cfg(feature = "platform-macos")]
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
        // Explicit positive predicate, not `not(platform-macos)`: the host-OS
        // and hypervisor-backend axes are distinct, and a negation silently
        // captures every future non-macOS host as well
        // (`.semgrep/typed-domains.yml::no-cfg-not-platform-macos`).
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        let run = {
            let _ = (
                executable,
                argv,
                env,
                max_traps,
                debug_state_path,
                root,
                dispatcher,
            );
            Err(RuntimeError::Unsupported(
                "Pending port to hvpatch VM carrier model".to_string(),
            ))
        };
        // The guest is gone: give the carrier its terminal back.
        drop(interactive_session);
        run
    }
}

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
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn prepare_failure_releases_pid_placement() {
        let mut spec = hvpatch_run_spec();
        spec.pid = PidMode::Private;
        spec.rootfs_layers = vec![Utf8PathBuf::from(
            "/nonexistent/carrick-prepare-test/sha256-missing-layer",
        )];
        let err = Runtime::prepare(&spec, test_launch(), RuntimeExtensions::default())
            .err()
            .expect("a missing layer must fail preparation");
        assert!(matches!(err, RuntimeError::FsBackend(_)), "{err}");
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvpatch_uses_container_entrypoint_resolution_for_every_container_in_one_carrier() {
        for round in 0..2 {
            let result = Runtime::execute(&hvpatch_run_spec())
                .expect("hvpatch container setup should classify a missing entrypoint");
            assert_eq!(result.exit_code, 127, "round {round}");
            assert!(result.stdout.is_empty());
            assert!(result.stderr.is_empty());
            assert_eq!(
                crate::carrier::live_container_count(),
                0,
                "round {round}: container must be retired at run end"
            );
        }
        crate::carrier::shutdown().expect("carrier shutdown without a VM is a no-op");
        assert!(crate::vm_lifecycle::process_snapshot().terminal.is_none());
    }
}
