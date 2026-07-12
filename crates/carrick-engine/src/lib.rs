//! Container orchestration: lowering a docker-style run request into a
//! [`carrick_spec::RunSpec`] the runtime can execute.
//!
//! # Theory of operation
//!
//! Three crates sit between the CLI and the platform-selected runtime, each owning one
//! transform. `carrick-image` answers *what bytes make up this image*
//! (ordered layer blobs + the OCI config). `carrick-runtime` answers *how do I
//! run this exact process* (it consumes a fully resolved [`RunSpec`] and knows
//! nothing about images, registries, or docker flags). This crate is the seam
//! between them: it takes a [`CliRunRequest`] — the loosely-typed, docker-CLI-
//! shaped bundle of flags and overrides the user typed — resolves the image,
//! and *merges* the two into a single, fully-specified `RunSpec`. The runtime
//! never sees a `CliRunRequest`; the CLI never builds a `RunSpec`. All
//! docker-compatibility merge semantics — the rules for which of image-config
//! vs. command-line wins — live in exactly one place: [`resolve_run_spec`].
//!
//! ## The merge is the whole job, and order matters
//!
//! [`resolve_run_spec`] is a deterministic, side-effect-light function (its only
//! reads of ambient state are `std::env` for bare-`-e KEY` import and the APFS
//! case-sensitivity probe). It reproduces docker's precedence rules:
//!
//! * **argv** = effective entrypoint ++ effective command. `--entrypoint`
//!   overrides the image `Entrypoint` (and `--entrypoint ""`, lowered by the CLI
//!   to `Some(vec![])`, *clears* it); positional `args` override the image
//!   `Cmd`. An empty result is an error — there is nothing to exec. This is the
//!   subtle docker rule that a cmd override does *not* clear the entrypoint, so
//!   `run img /bin/ls` against an `ENTRYPOINT ["/bin/sh"]` image execs
//!   `/bin/sh /bin/ls`, not `/bin/ls`.
//! * **env** is layered lowest-to-highest: image `Env`, then carrick's baseline
//!   defaults (`PATH`, `HOME`, `TERM`, `LANG`/`LC_ALL`, `DEBIAN_FRONTEND`,
//!   `PAGER`) added only where the image left a key *unset*, then `--env`
//!   overrides last-wins. A bare `-e KEY` (no `=`) imports `KEY` from the *host*
//!   environment and contributes nothing if the host has it unset — matching
//!   docker's `-e KEY` / env-file passthrough. The result is sorted for a
//!   stable, reproducible `envp`.
//! * **cwd** = `--workdir`, else image `WorkingDir`, else `/`.
//! * **user** = `--user`, else image `User`. Only *numeric* `uid[:gid]` is
//!   honored; a user/group **name** would require reading the in-image
//!   `/etc/passwd` (which this layer cannot do — the rootfs is not mounted yet),
//!   so a name resolves to root with a warning rather than a silent
//!   mis-mapping. `gid` defaults to `0` when only a uid is given, per docker.
//!
//! ## Filesystem backend: explicit, else probed
//!
//! The runtime can back the guest rootfs either in host memory or on the host's
//! APFS via cap-std. The host backend requires a **case-sensitive** volume
//! (Linux rootfs paths collide otherwise), so when `--fs` is not given,
//! [`resolve_run_spec`] probes the preferred scratch root for case sensitivity
//! and picks [`FsBackendKind::Host`] only if the probe passes, falling back to
//! the in-memory backend (only when the default-off `fs-memory` feature is
//! compiled in; otherwise host is the only choice). This is the one place the
//! function touches the filesystem.
//!
//! ## Platform and the image read-through
//!
//! [`request_platform`] canonicalises `--platform` (or, when omitted, the
//! host-native architecture) into a [`Platform`]. [`Engine::resolve`] maps that to a
//! [`carrick_image::PlatformTarget`] and calls `resolve_with_platform`, so an
//! amd64 (Rosetta) run pulls and caches the amd64 manifest without disturbing
//! the native arm64 cache (see the `carrick-image` BTS), then returns the merged
//! [`RunSpec`] to the caller. Resolving the spec is deliberately kept separate
//! from executing it: the CLI calls [`carrick_runtime::Runtime::execute`] only
//! after `resolve` has returned and the async (tokio) image-pull machinery has
//! been torn down, so no tokio runtime is ever live across the `execute` fork.
//!
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

use camino::Utf8PathBuf;
use std::collections::HashMap;

pub use carrick_image::{ImageStore, ResolvedImage};
pub use carrick_runtime::runtime::RunResult;
pub use carrick_spec::{
    BridgeId, FsBackendKind, ImageConfig, Mount, NetworkAttachmentSpec, NetworkMode,
    NetworkNamespaceId, NetworkNamespaceSpec, PidMode, Platform, PortMapping, RunSpec,
    SeccompPolicy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliNetworkAttachment {
    pub bridge_id: BridgeId,
    pub aliases: Vec<String>,
    pub ipv4: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CliRunRequest {
    pub image_ref: String,
    /// Raw OCI platform string from the CLI (`--platform linux/amd64`), or
    /// `None` to default to the host-native architecture (see
    /// [`Platform::host_native`]).
    pub platform: Option<String>,
    pub args: Vec<String>,
    pub env_overrides: Vec<String>,
    pub mounts: Vec<Mount>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    /// Docker-compatible container hostname / UTS identity.
    pub hostname: Option<String>,
    pub entrypoint_override: Option<Vec<String>>,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub name: Option<String>,
    pub max_traps: usize,
    pub debug_state_path: Option<String>,
    pub fs: Option<FsBackendKind>,
    /// Docker `--pull` policy for image resolution (`always`/`missing`/`never`).
    /// Defaults to `Missing` (pull only when the image is absent locally).
    pub pull: carrick_image::PullPolicy,
    pub exec_backend: carrick_spec::ExecBackendRequest,
    pub native_page_profile: carrick_spec::NativePageProfileRequest,
    /// PID namespace mode (`docker run --pid`). Defaults to `Private`.
    pub pid: PidMode,
    pub network: NetworkMode,
    pub network_bridge: Option<String>,
    pub network_container: Option<String>,
    pub network_namespace_id: Option<String>,
    pub network_attachments: Vec<CliNetworkAttachment>,
    pub network_ipv4: Option<String>,
    pub network_aliases: Vec<String>,
    pub extra_hosts: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_options: Vec<String>,
    pub volumes_from: Vec<String>,
    pub published_ports: Vec<PortMapping>,
    /// Raw `--stop-signal` value (e.g. `SIGQUIT`/`9`), or `None` to fall back to
    /// the image's OCI `STOPSIGNAL`. Resolved to a host signum at create time
    /// and persisted in the container's `RunConfig`; the engine itself does not
    /// consume it (stop/restart read it from the registry).
    pub stop_signal: Option<String>,
    /// `--stop-timeout` in seconds (graceful-stop window before SIGKILL), or
    /// `None` for the default. Persisted in the container's `RunConfig`.
    pub stop_timeout: Option<u64>,
    /// Raw `--security-opt` values (docker syntax). Resolved by
    /// [`resolve_seccomp_policy`] over the `carrick run` default
    /// ([`SeccompPolicy::ContainerDefault`], docker's own default); persisted
    /// in the container's `RunConfig` so start/restart/exec keep the policy.
    pub security_opts: Vec<String>,
}

/// Resolve docker-syntax `--security-opt` values (last-wins) onto a
/// [`SeccompPolicy`], starting from `default` — `ContainerDefault` for the
/// docker-compatible `carrick run`/`create` frontends, `Unconfined` for the
/// bare-ELF `run-elf` dev driver (whose opt-IN is `seccomp=default`).
///
/// Supported values: `seccomp=unconfined` (docker's opt-out) and
/// `seccomp=default`/`seccomp=builtin` (the modeled builtin profile). Anything
/// else — custom profile JSON paths, apparmor/label options — is an ERROR:
/// silently ignoring a security option the user asked for would misrepresent
/// the sandbox they believe they configured.
pub fn resolve_seccomp_policy(
    default: SeccompPolicy,
    security_opts: &[String],
) -> Result<SeccompPolicy, String> {
    let mut policy = default;
    for opt in security_opts {
        match opt.strip_prefix("seccomp=") {
            Some("unconfined") => policy = SeccompPolicy::Unconfined,
            Some("default") | Some("builtin") => policy = SeccompPolicy::ContainerDefault,
            Some(other) => {
                return Err(format!(
                    "unsupported --security-opt seccomp value {other:?}: carrick models \
                     the builtin default profile (`seccomp=default`) and `seccomp=unconfined`; \
                     custom profile files are not supported"
                ));
            }
            None => {
                return Err(format!(
                    "unsupported --security-opt {opt:?}: only `seccomp=unconfined` and \
                     `seccomp=default`/`seccomp=builtin` are supported"
                ));
            }
        }
    }
    Ok(policy)
}

/// Parse the request's `--platform` into the canonical [`Platform`], falling
/// back to the host-native architecture (see [`Platform::host_native`]) when
/// absent or unrecognised — so `carrick run <image>` with no `--platform`
/// targets the ISA this host runs without translation (arm64 on Apple Silicon,
/// amd64 on the x86_64 lanes).
pub fn request_platform(req: &CliRunRequest) -> Platform {
    req.platform
        .as_deref()
        .and_then(Platform::from_oci_str)
        .unwrap_or_default()
}

/// Verify the requested guest [`Platform`] can actually run on this host, BEFORE
/// pulling its (possibly large) image. A guest whose ISA matches the host runs
/// natively. The one cross-ISA path carrick supports is an x86_64 guest on an
/// aarch64 host via Apple Rosetta 2 — on macOS directly, or inside an
/// Apple-Silicon Linux VM (e.g. lima) that exposes Rosetta-for-Linux — so that
/// combination is allowed only when the Rosetta interpreter is accessible
/// (probed by [`carrick_runtime::rosetta_available`]); an arm64 guest on an
/// x86_64 host has no translation path and is rejected outright. The error
/// strings are user-facing (surfaced by `carrick run`/`create`), so they name
/// the actionable fix. This is a no-op on a native run, the common case.
pub fn check_platform_runnable(platform: Platform) -> Result<(), String> {
    match carrick_spec::BackendCapabilities::current().host_execution(platform) {
        carrick_spec::HostExecution::Native => Ok(()),
        carrick_spec::HostExecution::RosettaTranslated => {
            if carrick_runtime::rosetta_available() {
                Ok(())
            } else {
                Err(
                    "running an x86_64 (linux/amd64) container on an aarch64 host \
                     requires Apple Rosetta 2 for Linux, which was not found. On macOS \
                     install it with `softwareupdate --install-rosetta`; in an \
                     Apple-Silicon Linux VM (e.g. lima) enable Rosetta for the guest \
                     (lima: `rosetta.enabled: true`) or point `CARRICK_ROSETTA_PATH` at \
                     the mounted interpreter. Or omit `--platform` to run the native \
                     arm64 image."
                        .to_string(),
                )
            }
        }
        carrick_spec::HostExecution::Unsupported => Err("running an arm64 (linux/arm64) \
             container on an x86_64 host is not supported: carrick has no \
             arm64-on-x86_64 translation. Omit `--platform` to run the native amd64 image."
            .to_string()),
    }
}

pub fn resolve_run_spec(req: CliRunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
    let platform = request_platform(&req);

    // 1. Resolve argv (entrypoint + cmd overrides)
    let effective_entrypoint = match req.entrypoint_override {
        Some(overrides) => overrides,
        None => image.config.entrypoint.clone().unwrap_or_default(),
    };

    let effective_cmd = if !req.args.is_empty() {
        req.args.clone()
    } else {
        image.config.cmd.clone().unwrap_or_default()
    };

    let mut argv = Vec::new();
    argv.extend(effective_entrypoint);
    argv.extend(effective_cmd);

    if argv.is_empty() {
        return Err("no command specified".to_string());
    }

    let executable = argv[0].clone();

    // 2. Resolve env variables
    let mut env_map = HashMap::new();

    // Add image env
    for entry in &image.config.env {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    // Add baseline defaults ONLY if not already set by image config
    let baseline_defaults = [
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("HOME", "/root"),
        ("TERM", "xterm-256color"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("PAGER", "cat"),
    ];
    for (k, v) in baseline_defaults {
        env_map
            .entry(k.to_string())
            .or_insert_with(|| v.to_string());
    }

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

    let mut envp: Vec<String> = env_map
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    envp.sort();

    // 3. Resolve working directory. A relative `--workdir` resolves against the
    //    image's WorkingDir (Docker semantics), not the filesystem root —
    //    carrick's `set_cwd` silently drops a non-absolute path, so without this
    //    join a relative `-w` (e.g. `-w os`) would leave the guest cwd at `/` and
    //    break every relative-path lookup.
    let cwd = match req.workdir {
        Some(w) => {
            let p = Utf8PathBuf::from(&w);
            if p.is_absolute() {
                Some(p)
            } else {
                let base = image
                    .config
                    .working_dir
                    .clone()
                    .unwrap_or_else(|| Utf8PathBuf::from("/"));
                Some(base.join(p))
            }
        }
        None => image.config.working_dir.clone(),
    }
    .or_else(|| Some(Utf8PathBuf::from("/")));

    // 4. Resolve user (`--user` overrides image USER). Numeric `uid[:gid]` only;
    // a user/group NAME needs in-image /etc/passwd resolution (not yet
    // supported), so warn and run as root rather than silently mis-mapping.
    let (uid, gid) = match req.user.clone().or_else(|| image.config.user.clone()) {
        None => (0, 0),
        Some(s) if s.is_empty() => (0, 0),
        Some(s) => match parse_numeric_user(&s) {
            Some((u, g)) => (u, g),
            None => {
                eprintln!(
                    "carrick: --user {s:?}: name resolution is not yet supported; running as root (use a numeric uid[:gid])"
                );
                (0, 0)
            }
        },
    };

    // 5. Select fs backend: caller's `--fs`, else the shared default
    //    (host-only unless the fs-memory feature is compiled in).
    let fs_backend = req
        .fs
        .unwrap_or_else(carrick_runtime::apfs::default_writable_backend_kind);

    let debug_state_path = req.debug_state_path.map(Utf8PathBuf::from);
    let network = match req.network {
        NetworkMode::Host => NetworkNamespaceSpec::default(),
        NetworkMode::None => NetworkNamespaceSpec::none(),
        NetworkMode::Bridge => {
            let mut spec = NetworkNamespaceSpec::bridge_default(
                req.name.clone(),
                req.network_aliases.clone(),
                req.published_ports.clone(),
            );
            if let Some(bridge) = req.network_bridge.filter(|name| !name.is_empty()) {
                spec.bridge_id = BridgeId::new(bridge);
                if let Some(primary) = spec.attachments.first_mut() {
                    primary.bridge_id = spec.bridge_id.clone();
                }
            }
            if !req.network_attachments.is_empty() {
                let mut attachments = Vec::with_capacity(req.network_attachments.len());
                for attachment in req.network_attachments {
                    let ipv4 = attachment
                        .ipv4
                        .as_deref()
                        .map(|ipv4| {
                            ipv4.parse().map_err(|_| {
                                format!("invalid IPv4 address {ipv4:?} for bridge attachment")
                            })
                        })
                        .transpose()?;
                    attachments.push(NetworkAttachmentSpec::bridge_default(
                        attachment.bridge_id,
                        req.name.clone(),
                        attachment.aliases,
                        ipv4,
                    ));
                }
                if let Some(primary) = attachments.first() {
                    spec.bridge_id = primary.bridge_id.clone();
                    spec.aliases = primary.aliases.clone();
                    spec.ipv4 = primary.ipv4;
                    spec.gateway_v4 = primary.gateway_v4;
                }
                spec.attachments = attachments;
            }
            let namespace_id = req
                .network_namespace_id
                .clone()
                .or_else(|| req.network_container.clone())
                .or_else(|| req.name.clone())
                .unwrap_or_else(|| format!("anon-{}", std::process::id()));
            spec.namespace_id = Some(NetworkNamespaceId::new(namespace_id));
            spec
        }
    };
    let mut network = network;
    if !req.dns_servers.is_empty() {
        network.dns_servers = req
            .dns_servers
            .iter()
            .map(|server| {
                server
                    .parse()
                    .map_err(|_| format!("invalid DNS nameserver {server:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    network.dns_search = req.dns_search;
    network.dns_options = req.dns_options;
    if let Some(ipv4) = req.network_ipv4 {
        if network.mode != NetworkMode::Bridge {
            return Err("--ip requires bridge networking".to_string());
        }
        network.ipv4 = ipv4
            .parse()
            .map_err(|_| format!("invalid IPv4 address {ipv4:?}"))?;
    }

    // 6. Launch-time syscall policy: docker's default profile model unless
    //    `--security-opt seccomp=unconfined` opts out.
    let seccomp_policy =
        resolve_seccomp_policy(SeccompPolicy::ContainerDefault, &req.security_opts)?;

    Ok(RunSpec {
        executable,
        argv,
        envp,
        cwd,
        rootfs_layers: image.layers,
        fs_backend,
        mounts: req.mounts,
        tty: req.tty,
        raw: true,
        interactive: req.interactive,
        max_traps: req.max_traps,
        debug_state_path,
        platform,
        exec_backend: req.exec_backend,
        native_page_profile: req.native_page_profile,
        pid: req.pid,
        hostname: req.hostname,
        network,
        extra_hosts: req.extra_hosts,
        uid,
        gid,
        seccomp_policy,
    })
}

/// Parse a `docker run --user` value as numeric `uid[:gid]`. `gid` defaults to 0
/// when only a uid is given (docker's behavior for a numeric user with no passwd
/// lookup). Returns `None` for a non-numeric user/group name — carrick has no
/// in-image `/etc/passwd` resolution yet, so the caller warns and runs as root.
fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let (u, g) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid: u32 = u.parse().ok()?;
    let gid: u32 = match g {
        Some(g) => g.parse().ok()?,
        None => 0,
    };
    Some((uid, gid))
}

pub struct Engine {
    store: ImageStore,
}

impl Engine {
    pub fn new(store: ImageStore) -> Self {
        Self { store }
    }

    /// Resolve a run request to a `RunSpec`: parse the image ref, pull/resolve
    /// the image for the target platform, and merge into a fully-specified spec.
    /// This is the ONLY async part of a run — it does NOT execute, so no fork
    /// happens here and it is safe to drive inside a tokio runtime. The caller
    /// drops the runtime (joining its blocking pool in the parent) BEFORE
    /// calling `carrick_runtime::Runtime::execute`, so tokio is never alive
    /// across a fork.
    pub async fn resolve(&self, req: CliRunRequest) -> Result<RunSpec, anyhow::Error> {
        let image_ref = carrick_spec::ImageReference::parse(&req.image_ref)
            .map_err(|e| anyhow::anyhow!("invalid image reference: {}", e))?;

        // Select the OCI manifest entry for the requested platform. amd64
        // images are cached separately from the host-native arm64 so the two
        // never collide in the store, and pulling honours the platform hint.
        let platform = request_platform(&req);
        // Reject an unrunnable target (e.g. `--platform linux/amd64` on an Apple
        // Silicon host without Rosetta) BEFORE pulling its image, with an
        // actionable message. This is the authoritative gate every run path
        // funnels through (foreground `run`, `start`, the detached child).
        check_platform_runnable(platform).map_err(anyhow::Error::msg)?;
        let target = carrick_image::PlatformTarget {
            os: "linux".to_string(),
            arch: platform.oci_arch().to_string(),
            variant: None,
        };
        let resolved = self
            .store
            .resolve_with_platform_and_policy(&image_ref, &target, req.pull)
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve image: {}", e))?;

        resolve_run_spec(req, resolved).map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_image(
        entrypoint: Option<Vec<String>>,
        cmd: Option<Vec<String>>,
        env: Vec<String>,
        working_dir: Option<Utf8PathBuf>,
    ) -> ResolvedImage {
        ResolvedImage {
            layers: vec![Utf8PathBuf::from("/layer1")],
            config: ImageConfig {
                entrypoint,
                cmd,
                env,
                working_dir,
                user: Some("root".to_string()),
                exposed_ports: None,
                labels: None,
                stop_signal: None,
            },
        }
    }

    fn base_req(user: Option<&str>) -> CliRunRequest {
        CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: user.map(|s| s.to_string()),
            hostname: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        }
    }

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

    #[test]
    fn bridge_network_resolves_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.network = NetworkMode::Bridge;
        req.name = Some("web".to_string());
        req.network_aliases = vec!["api".to_string()];
        req.published_ports = vec![PortMapping {
            host_ip: None,
            host_port: Some(8080),
            container_port: 80,
            protocol: carrick_spec::PortProtocol::Tcp,
        }];

        let spec = resolve_run_spec(req, image).expect("resolve run spec");
        assert_eq!(spec.network.mode, NetworkMode::Bridge);
        assert_eq!(spec.network.container_name.as_deref(), Some("web"));
        assert_eq!(spec.network.aliases, vec!["api"]);
        assert_eq!(spec.network.bridge_id.as_str(), "carrick0");
        assert_eq!(spec.network.published_ports[0].host_port, Some(8080));
    }

    #[test]
    fn static_bridge_ipv4_resolves_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.network = NetworkMode::Bridge;
        req.network_ipv4 = Some("172.31.44.10".to_string());

        let spec = resolve_run_spec(req, image).expect("resolve run spec");

        assert_eq!(spec.network.mode, NetworkMode::Bridge);
        assert_eq!(spec.network.ipv4.to_string(), "172.31.44.10");
    }

    #[test]
    fn extra_hosts_resolve_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.extra_hosts = vec!["db.local:10.12.0.7".to_string()];

        let spec = resolve_run_spec(req, image).expect("resolve run spec");
        assert_eq!(spec.extra_hosts, vec!["db.local:10.12.0.7"]);
    }

    #[test]
    fn hostname_resolves_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.hostname = Some("api-host".to_string());

        let spec = resolve_run_spec(req, image).expect("resolve run spec");
        assert_eq!(spec.hostname.as_deref(), Some("api-host"));
    }

    #[test]
    fn dns_overrides_resolve_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.dns_servers = vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()];
        req.dns_search = vec!["example.test".to_string()];
        req.dns_options = vec!["ndots:2".to_string()];

        let spec = resolve_run_spec(req, image).expect("resolve run spec");
        assert_eq!(
            spec.network.dns_servers,
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "9.9.9.9".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
        assert_eq!(spec.network.dns_search, vec!["example.test"]);
        assert_eq!(spec.network.dns_options, vec!["ndots:2"]);
    }

    #[test]
    fn user_numeric_uid_and_gid() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(Some("1000:2000")), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (1000, 2000));
    }

    #[test]
    fn user_numeric_uid_defaults_gid_zero() {
        // docker: `--user 1000` with no group → gid 0.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(Some("1000")), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (1000, 0));
    }

    #[test]
    fn user_absent_defaults_root() {
        // No --user; the test image's USER is the name "root" (unresolved) → root.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(None), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (0, 0));
    }

    #[test]
    fn bare_env_key_imports_host_value() {
        // SAFETY: test setup; the unique key avoids racing other tests' env.
        unsafe { std::env::set_var("CARRICK_TEST_IMPORT_XYZ", "from-host") };
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.env_overrides = vec!["CARRICK_TEST_IMPORT_XYZ".to_string()];
        let spec = resolve_run_spec(req, image).unwrap();
        unsafe { std::env::remove_var("CARRICK_TEST_IMPORT_XYZ") };
        assert!(
            spec.envp
                .iter()
                .any(|e| e == "CARRICK_TEST_IMPORT_XYZ=from-host"),
            "bare `-e KEY` should import the host value; envp={:?}",
            spec.envp
        );
    }

    #[test]
    fn cleared_entrypoint_runs_cmd_only() {
        // `--entrypoint ""` (lowered to Some(vec![]) by the CLI) clears the image
        // entrypoint, leaving only the command.
        let image = make_test_image(
            Some(vec!["/bin/sh".into()]),
            Some(vec!["echo".into(), "hi".into()]),
            vec![],
            None,
        );
        let mut req = base_req(None);
        req.entrypoint_override = Some(vec![]);
        req.args = vec![];
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["echo", "hi"]);
    }

    #[test]
    fn test_merge_argv_no_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            hostname: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.executable, "/bin/sh");
        assert_eq!(spec.argv, vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_argv_cmd_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            hostname: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/sh", "/bin/ls"]);
    }

    #[test]
    fn test_merge_argv_entrypoint_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            hostname: None,
            entrypoint_override: Some(vec!["/bin/bash".to_string()]),
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_env_variables() {
        let image = make_test_image(
            None,
            None,
            vec!["PATH=/image/bin".to_string(), "CUSTOM=1".to_string()],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec!["CUSTOM=2".to_string(), "USER_VAR=yes".to_string()],
            mounts: vec![],
            workdir: None,
            user: None,
            hostname: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        };
        let spec = resolve_run_spec(req, image).unwrap();

        let env_map: HashMap<String, String> = spec
            .envp
            .iter()
            .map(|e| {
                e.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .unwrap()
            })
            .collect();

        assert_eq!(env_map.get("PATH").unwrap(), "/image/bin"); // Image env wins over baseline defaults
        assert_eq!(env_map.get("CUSTOM").unwrap(), "2"); // Override wins over image env
        assert_eq!(env_map.get("USER_VAR").unwrap(), "yes");
        assert_eq!(env_map.get("HOME").unwrap(), "/root"); // Baseline default is set
    }

    #[test]
    fn test_merge_workdir() {
        let image = make_test_image(None, None, vec![], Some(Utf8PathBuf::from("/image/app")));
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: Some("/user/app".to_string()),
            user: None,
            hostname: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Host),
            pull: carrick_image::PullPolicy::Missing,
            exec_backend: carrick_spec::ExecBackendRequest::Auto,
            native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
            pid: PidMode::default(),
            network: NetworkMode::Host,
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
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.cwd.unwrap().as_str(), "/user/app");
    }

    #[test]
    fn relative_workdir_resolves_against_image_workingdir() {
        // A RELATIVE `--workdir` joins onto the image WorkingDir (Docker
        // semantics), not `/`; an absolute one still wins verbatim.
        let mk = |img_wd: Option<&str>, wd: Option<&str>| {
            let image = make_test_image(None, None, vec![], img_wd.map(Utf8PathBuf::from));
            let req = CliRunRequest {
                image_ref: "alpine".to_string(),
                platform: None,
                args: vec!["/bin/ls".to_string()],
                env_overrides: vec![],
                mounts: vec![],
                workdir: wd.map(|s| s.to_string()),
                user: None,
                hostname: None,
                entrypoint_override: None,
                tty: false,
                interactive: false,
                rm: false,
                name: None,
                max_traps: 100,
                debug_state_path: None,
                fs: Some(FsBackendKind::Host),
                pull: carrick_image::PullPolicy::Missing,
                exec_backend: carrick_spec::ExecBackendRequest::Auto,
                native_page_profile: carrick_spec::NativePageProfileRequest::Auto,
                pid: PidMode::default(),
                network: NetworkMode::Host,
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
            };
            resolve_run_spec(req, image)
                .unwrap()
                .cwd
                .unwrap()
                .to_string()
        };
        // relative joins onto the image WorkingDir (the go-conformance case)
        assert_eq!(
            mk(Some("/usr/local/go/src"), Some("os")),
            "/usr/local/go/src/os"
        );
        // relative with no image WorkingDir is anchored at root
        assert_eq!(mk(None, Some("os")), "/os");
        // absolute --workdir still wins verbatim
        assert_eq!(mk(Some("/image/app"), Some("/user/app")), "/user/app");
    }

    #[test]
    fn run_spec_seccomp_policy_defaults_to_container_default() {
        // `carrick run` with no --security-opt models docker's default
        // launch-time seccomp profile.
        let image = make_test_image(None, None, vec![], None);
        let spec = resolve_run_spec(base_req(None), image).unwrap();
        assert_eq!(spec.seccomp_policy, SeccompPolicy::ContainerDefault);
    }

    #[test]
    fn security_opt_seccomp_unconfined_opts_out() {
        let image = make_test_image(None, None, vec![], None);
        let mut req = base_req(None);
        req.security_opts = vec!["seccomp=unconfined".to_string()];
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.seccomp_policy, SeccompPolicy::Unconfined);
    }

    #[test]
    fn resolve_seccomp_policy_is_last_wins_and_rejects_unknown_options() {
        // last-wins like docker
        assert_eq!(
            resolve_seccomp_policy(
                SeccompPolicy::ContainerDefault,
                &[
                    "seccomp=unconfined".to_string(),
                    "seccomp=default".to_string()
                ],
            ),
            Ok(SeccompPolicy::ContainerDefault)
        );
        // run-elf shape: explicit opt-IN over an Unconfined default
        assert_eq!(
            resolve_seccomp_policy(SeccompPolicy::Unconfined, &["seccomp=builtin".to_string()]),
            Ok(SeccompPolicy::ContainerDefault)
        );
        assert_eq!(
            resolve_seccomp_policy(SeccompPolicy::Unconfined, &[]),
            Ok(SeccompPolicy::Unconfined)
        );
        // Refuse (never silently ignore) security options carrick can't honor.
        assert!(
            resolve_seccomp_policy(
                SeccompPolicy::ContainerDefault,
                &["seccomp=/etc/profile.json".to_string()],
            )
            .is_err()
        );
        assert!(
            resolve_seccomp_policy(
                SeccompPolicy::ContainerDefault,
                &["apparmor=unconfined".to_string()],
            )
            .is_err()
        );
    }

    #[test]
    fn request_platform_defaults_to_host_native() {
        // No `--platform` → the host-native ISA (so a native run never needs the
        // flag), and an explicit value still parses.
        let mut req = base_req(None);
        req.platform = None;
        assert_eq!(request_platform(&req), Platform::host_native());
        req.platform = Some("linux/amd64".to_string());
        assert_eq!(request_platform(&req), Platform::Amd64);
        req.platform = Some("linux/arm64".to_string());
        assert_eq!(request_platform(&req), Platform::Aarch64);
    }

    #[test]
    fn native_platform_is_always_runnable() {
        // The host's own ISA always runs without any translation layer.
        assert!(check_platform_runnable(Platform::host_native()).is_ok());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn amd64_guest_on_arm_host_tracks_rosetta_presence() {
        // On Apple Silicon, an amd64 guest is runnable iff Rosetta is installed —
        // the gate must agree exactly with the runtime's own Rosetta probe.
        assert_eq!(
            check_platform_runnable(Platform::Amd64).is_ok(),
            carrick_runtime::rosetta_available()
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn arm64_guest_on_x86_host_is_rejected() {
        // No reverse (arm64-on-x86_64) translation exists.
        let err = check_platform_runnable(Platform::Aarch64)
            .expect_err("arm64 guest on x86_64 host must be rejected");
        assert!(err.contains("not supported"), "unexpected message: {err}");
    }
}
