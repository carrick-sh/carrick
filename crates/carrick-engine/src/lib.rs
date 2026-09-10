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
//! between them: it takes a [`RunRequest`] — the loosely-typed, docker-CLI-
//! shaped bundle of flags and overrides the user typed — resolves the image,
//! and *merges* the two into a single, fully-specified `RunSpec`. The runtime
//! never sees a `RunRequest`; the CLI never builds a `RunSpec`. All
//! docker-compatibility merge semantics — the rules for which of image-config
//! vs. command-line wins — live in exactly one place: [`resolve_run_spec`].
//!
//! ## The merge is the whole job, and order matters
//!
//! [`resolve_run_spec`] is a deterministic, pure function without reads of ambient state
//! (`host_env` snapshot for bare-`-e KEY` import is explicitly passed).
//! It reproduces docker's precedence rules:
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
//!   overrides last-wins. A bare `-e KEY` (no `=`) imports `KEY` from the supplied
//!   `host_env` snapshot and contributes nothing if unset. The result is sorted for a
//!   stable, reproducible `envp`.
//! * **cwd** = `--workdir`, else image `WorkingDir`, else `/`.
//! * **user** = `--user`, else image `User`. Numeric `uid[:gid]` bypasses
//!   the file lookup; a user/group **name** is resolved against the in-image
//!   `/etc/passwd` and `/etc/group` via `RootFs`. Unresolvable names return
//!   an error naming the user/group. `gid` defaults to `0` when only a numeric
//!   uid is given, per docker.
//!
//! ## Filesystem backend: explicit, else probed
//!
//! The runtime can back the guest rootfs either in host memory or on the host's
//! APFS via cap-std. The host backend requires a **case-sensitive** volume
//! (Linux rootfs paths collide otherwise), so when `--fs` is not given,
//! [`resolve_run_spec`] probes the preferred scratch root for case sensitivity
//! and picks [`FsBackendKind::Host`] only if the probe passes, falling back to
//! the in-memory backend (only when the default-off `fs-memory` feature is
//! compiled in; otherwise host is the only choice).
//!
//! ## Platform and the image read-through
//!
//! [`request_platform`] canonicalises `--platform` (or, when omitted, the
//! host-native architecture) into a [`Platform`]. [`Engine::resolve`] maps that to a
//! [`carrick_image::PlatformTarget`] and calls `resolve_with_platform`, so an
//! amd64 (Rosetta) run pulls and caches the amd64 manifest without disturbing
//! the native arm64 cache (see the `carrick-image` BTS), then returns the merged
//! [`Resolved`] to the caller. Resolving the spec is deliberately kept separate
//! from executing it: the CLI calls [`carrick_runtime::Runtime::execute`] only
//! after `resolve` has returned and the async (tokio) image-pull machinery has
//! been torn down, so no tokio runtime is ever live across the `execute` fork.
//!
//! ## What this layer does *not* own
//!
//! Lifecycle concerns (`rm`, `stop_signal`, `stop_timeout`, `volumes_from`) are
//! kept outside `RunRequest` in the CLI's `LaunchRequest`. Keeping the merge function
//! pure of lifecycle bookkeeping is what makes it exhaustively unit-testable
//! (see the `tests` module: argv/env/workdir/user precedence are pinned there).

use camino::Utf8PathBuf;
use std::collections::HashMap;

pub use carrick_image::{ImageStore, ResolvedImage};
pub use carrick_runtime::runtime::RunResult;
pub use carrick_spec::{
    BridgeId, FsBackendKind, ImageConfig, Mount, MountSpec, NetworkAttachmentSpec, NetworkMode,
    NetworkNamespaceId, NetworkNamespaceSpec, NetworkSpec, PidMode, Platform, PortMapping,
    ProcessSpec, ResourceSpec, RunSpec, SeccompPolicy, SecuritySpec, StdioMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliNetworkAttachment {
    pub bridge_id: BridgeId,
    pub aliases: Vec<String>,
    pub ipv4: Option<String>,
}

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
    pub image_source: carrick_spec::ImageSource,
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
            image_source: carrick_spec::ImageSource::default(),
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
pub fn request_platform(req: &RunRequest) -> Platform {
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

pub fn resolve_run_spec(req: RunRequest, image: ResolvedImage) -> Result<Resolved, String> {
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

    // 4. Resolve user (`--user` overrides image USER). Numeric `uid[:gid]`
    // bypasses the file lookup. A user/group NAME is resolved against the
    // image rootfs (/etc/passwd and /etc/group via RootFs layers). An unresolvable
    // name is a hard error naming the user/group.
    let warnings = Vec::new();
    let (uid, gid) = match req.user.as_deref().or(image.config.user.as_deref()) {
        None | Some("") => (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT),
        Some(s) => resolve_user(s, &image.layers)?,
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
                        .map(parse_bridge_ipv4)
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
        network.ipv4 = parse_bridge_ipv4(&ipv4)?;
    }

    // 6. Launch-time syscall policy: docker's default profile model unless
    //    `--security-opt seccomp=unconfined` opts out. For a host ELF, defaults
    //    to Unconfined unless opted into seccomp=default.
    let base_seccomp_policy = match req.image_source {
        carrick_spec::ImageSource::HostElf { .. } => SeccompPolicy::Unconfined,
        carrick_spec::ImageSource::Oci(_) => SeccompPolicy::ContainerDefault,
    };
    let seccomp_policy = resolve_seccomp_policy(base_seccomp_policy, &req.security_opts)?;

    let spec = RunSpec {
        process: ProcessSpec {
            executable,
            argv,
            envp,
            cwd,
            tty: req.tty,
            stdio: req.stdio,
            uid,
            gid,
            pid: req.pid,
        },
        mounts: MountSpec {
            rootfs_layers: image.layers,
            fs_backend,
            mounts: req.mounts,
        },
        network: NetworkSpec {
            namespace: network,
            extra_hosts: req.extra_hosts,
            hostname: req.hostname,
        },
        resources: ResourceSpec {
            max_traps: req.max_traps,
            debug_state_path,
        },
        security: SecuritySpec {
            seccomp_policy,
            cap_add: req.cap_add.clone(),
        },
        platform,
        exec_backend: req.exec_backend,
    };
    Ok(Resolved { spec, warnings })
}

/// Parse a user-supplied bridge address (`--ip`, or a per-attachment
/// `ipv4_address`).
///
/// `172.31.0.0/24` is refused: it is the default bridge's placeholder range,
/// holding the gateway and the address handed to a container that has no name
/// to derive one from. No name can hash into it
/// (`carrick_spec::is_bridge_placeholder_ipv4`), and the runtime relies on that
/// to scope an unnamed container's endpoint records to its own instance. An
/// address a user pinned there would be advertised in DNS but resolvable only
/// from inside its own run, so reject it up front with a reason rather than
/// hand out a half-reachable address.
fn parse_bridge_ipv4(ipv4: &str) -> Result<std::net::Ipv4Addr, String> {
    let parsed: std::net::Ipv4Addr = ipv4
        .parse()
        .map_err(|_| format!("invalid IPv4 address {ipv4:?}"))?;
    if carrick_spec::is_bridge_placeholder_ipv4(parsed) {
        return Err(format!(
            "IPv4 address {ipv4:?} is in the bridge's reserved 172.31.0.0/24 \
             (gateway and unnamed-container placeholder); pick an address in \
             172.31.1.0 - 172.31.253.255"
        ));
    }
    Ok(parsed)
}

/// Parse a `docker run --user` value as numeric `uid[:gid]`. `gid` defaults to 0
/// when only a uid is given (docker's behavior for a numeric user with no passwd
/// lookup). Returns `None` for a non-numeric user/group name.
fn parse_numeric_user(spec: &str) -> Option<(carrick_abi::NsUid, carrick_abi::NsGid)> {
    let (u, g) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid: u32 = u.parse().ok()?;
    let gid: u32 = match g {
        Some(g) => g.parse().ok()?,
        None => 0,
    };
    Some((carrick_abi::NsUid::new(uid), carrick_abi::NsGid::new(gid)))
}

fn lookup_user_in_passwd(
    passwd_content: &str,
    username: &str,
) -> Option<(carrick_abi::NsUid, carrick_abi::NsGid)> {
    for line in passwd_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pwd = fields.next()?;
        let uid_str = fields.next()?;
        let gid_str = fields.next()?;
        if name == username {
            let uid: u32 = uid_str.parse().ok()?;
            let gid: u32 = gid_str.parse().ok()?;
            return Some((carrick_abi::NsUid::new(uid), carrick_abi::NsGid::new(gid)));
        }
    }
    None
}

fn lookup_group_in_group(group_content: &str, groupname: &str) -> Option<carrick_abi::NsGid> {
    for line in group_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _pwd = fields.next()?;
        let gid_str = fields.next()?;
        if name == groupname {
            let gid: u32 = gid_str.parse().ok()?;
            return Some(carrick_abi::NsGid::new(gid));
        }
    }
    None
}

/// Resolve a user spec (`--user` or image `User`) against rootfs layers.
/// Numeric `uid[:gid]` bypasses the file lookup. A user/group name is
/// resolved against `/etc/passwd` and `/etc/group` in the image rootfs.
/// An unknown name returns a hard error naming the user/group.
fn resolve_user(
    spec: &str,
    layers: &[camino::Utf8PathBuf],
) -> Result<(carrick_abi::NsUid, carrick_abi::NsGid), String> {
    if let Some((u, g)) = parse_numeric_user(spec) {
        return Ok((u, g));
    }

    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    if user_part.is_empty() {
        return Err(format!("invalid user spec: {spec:?}"));
    }

    let rootfs = carrick_runtime::rootfs::RootFs::from_layer_paths(layers)
        .map_err(|e| format!("failed to load rootfs to resolve user '{spec}': {e}"))?;

    let (uid, default_gid) = if let Ok(numeric_uid) = user_part.parse::<u32>() {
        (carrick_abi::NsUid::new(numeric_uid), None)
    } else {
        let passwd_content = rootfs
            .read_to_string("/etc/passwd")
            .map_err(|e| format!("unknown user: {user_part} (failed to read /etc/passwd: {e})"))?;
        let (u, g) = lookup_user_in_passwd(&passwd_content, user_part)
            .ok_or_else(|| format!("unknown user: {user_part}"))?;
        (u, Some(g))
    };

    let gid = match group_part {
        Some(g) => {
            if let Ok(numeric_gid) = g.parse::<u32>() {
                carrick_abi::NsGid::new(numeric_gid)
            } else {
                let group_content = rootfs
                    .read_to_string("/etc/group")
                    .map_err(|e| format!("unknown group: {g} (failed to read /etc/group: {e})"))?;
                lookup_group_in_group(&group_content, g)
                    .ok_or_else(|| format!("unknown group: {g}"))?
            }
        }
        None => default_gid.unwrap_or(carrick_abi::NsGid::ROOT),
    };

    Ok((uid, gid))
}

pub struct Engine {
    store: ImageStore,
}

impl Engine {
    pub fn new(store: ImageStore) -> Self {
        Self { store }
    }

    /// Resolve a run request: parse the image ref, pull/resolve the image for
    /// the target platform, and merge into a fully-specified [`Resolved`]
    /// (spec + warnings). This is the ONLY async part of a run — the image
    /// store awaits `tokio::fs` and the registry client — and it does NOT
    /// execute. The CLI drives it on a throwaway current-thread runtime that it
    /// drops before `carrick_runtime::Runtime::execute` (`block_on_oci`).
    pub async fn resolve(&self, req: RunRequest) -> Result<Resolved, anyhow::Error> {
        match req.image_source.clone() {
            carrick_spec::ImageSource::HostElf {
                path,
                rootfs_layers,
            } => {
                let platform = request_platform(&req);
                check_platform_runnable(platform).map_err(anyhow::Error::msg)?;
                let canonical_path = path.canonicalize_utf8().unwrap_or_else(|_| path.clone());
                let executable_path = canonical_path.as_str().to_string();
                let mut mounts = req.mounts.clone();
                // Bind the host ELF read-only at the executable path inside the guest
                // so /proc/self/exe is resolvable and openable.
                mounts.push(carrick_spec::Mount {
                    source: canonical_path,
                    target: Utf8PathBuf::from(&executable_path),
                    readonly: true,
                });
                let mut req = req;
                req.mounts = mounts;
                if req.entrypoint_override.is_none() {
                    req.entrypoint_override = Some(vec![executable_path]);
                }
                let mut env = Vec::new();
                for key in [
                    "GODEBUG",
                    "GOMAXPROCS",
                    "GOTRACEBACK",
                    "GOGC",
                    "GODEBUGFLAGS",
                ] {
                    if let Some(host_env) = &req.host_env {
                        if let Some((_, val)) = host_env.iter().find(|(k, _)| k == key) {
                            env.push(format!("{key}={val}"));
                        }
                    } else if let Ok(val) = std::env::var(key) {
                        env.push(format!("{key}={val}"));
                    }
                }
                let image = carrick_image::ResolvedImage {
                    layers: rootfs_layers,
                    config: carrick_spec::ImageConfig {
                        env,
                        ..carrick_spec::ImageConfig::default()
                    },
                };
                resolve_run_spec(req, image).map_err(anyhow::Error::msg)
            }
            carrick_spec::ImageSource::Oci(s) => {
                let effective_ref = if !s.is_empty() {
                    s
                } else {
                    req.image_ref.clone()
                };
                let image_ref = carrick_spec::ImageReference::parse(&effective_ref)
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
    }
}

/// Run a single OCI-related future on a short-lived current-thread tokio
/// runtime. The runtime is dropped before returning, so by the time the
/// guest issues `clone(2)` and we fork the host process there is no
/// async runtime alive in the parent to corrupt the child.
pub fn block_on_oci<F: std::future::Future>(fut: F) -> F::Output {
    #[allow(clippy::expect_used)]
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build current-thread tokio runtime")
        .block_on(fut)
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
                user: None,
                exposed_ports: None,
                labels: None,
                stop_signal: None,
            },
        }
    }

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

    /// The merged spec alone, for tests that pin precedence rules and do not
    /// care about warnings.
    fn spec_of(req: RunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
        super::resolve_run_spec(req, image).map(|resolved| resolved.spec)
    }

    /// The request the parity pin merges. Every field that reaches the spec is
    /// set to a non-default value except the network mode (bridge lowering
    /// derives addresses from a name hash and is pinned by its own tests).
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

    /// Hand-derived from `resolve_run_spec` at the pre-rename revision: args
    /// override the image cmd, baseline env plus the override sorted, absolute
    /// workdir verbatim, numeric uid:gid, dns fields set on the host-mode
    /// namespace spec, `seccomp=unconfined` opting out.
    fn parity_expected() -> RunSpec {
        RunSpec {
            process: ProcessSpec {
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
                tty: false,
                stdio: StdioMode::Inherit,
                uid: carrick_abi::NsUid::new(1000),
                gid: carrick_abi::NsGid::new(2000),
                pid: PidMode::Private,
            },
            mounts: MountSpec {
                rootfs_layers: vec![Utf8PathBuf::from("/layer1")],
                fs_backend: FsBackendKind::Host,
                mounts: vec![Mount {
                    source: Utf8PathBuf::from("/h"),
                    target: Utf8PathBuf::from("/g"),
                    readonly: true,
                }],
            },
            network: NetworkSpec {
                namespace: NetworkNamespaceSpec {
                    dns_servers: vec!["1.1.1.1".parse::<std::net::IpAddr>().expect("ip")],
                    dns_search: vec!["example.test".to_string()],
                    dns_options: vec!["ndots:2".to_string()],
                    ..NetworkNamespaceSpec::default()
                },
                extra_hosts: vec!["db.local:10.12.0.7".to_string()],
                hostname: Some("api-host".to_string()),
            },
            resources: ResourceSpec {
                max_traps: 100,
                debug_state_path: Some(Utf8PathBuf::from("/tmp/state")),
            },
            security: SecuritySpec {
                seccomp_policy: SeccompPolicy::Unconfined,
                cap_add: vec!["SYS_PTRACE".to_string()],
            },
            platform: Platform::host_native(),
            exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
        }
    }

    #[test]
    fn resolve_run_spec_parity_pin() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let resolved = resolve_run_spec(parity_request(), image).expect("resolve");
        assert_eq!(resolved.spec, parity_expected());
    }

    #[test]
    fn execution_backend_flows_into_run_spec() {
        let mut req = base_req(None);
        req.exec_backend = carrick_spec::ExecBackendRequest::HvPatch;

        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = spec_of(req, image).expect("resolve run spec");

        assert_eq!(spec.exec_backend, carrick_spec::ExecBackendRequest::HvPatch);
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

        let spec = spec_of(req, image).expect("resolve run spec");
        assert_eq!(spec.network.namespace.mode, NetworkMode::Bridge);
        assert_eq!(
            spec.network.namespace.container_name.as_deref(),
            Some("web")
        );
        assert_eq!(spec.network.namespace.aliases, vec!["api"]);
        assert_eq!(spec.network.namespace.bridge_id.as_str(), "carrick0");
        assert_eq!(
            spec.network.namespace.published_ports[0].host_port,
            Some(8080)
        );
    }

    #[test]
    fn static_bridge_ipv4_resolves_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.network = NetworkMode::Bridge;
        req.network_ipv4 = Some("172.31.44.10".to_string());

        let spec = spec_of(req, image).expect("resolve run spec");

        assert_eq!(spec.network.namespace.mode, NetworkMode::Bridge);
        assert_eq!(spec.network.namespace.ipv4.to_string(), "172.31.44.10");
    }

    /// `172.31.0.0/24` holds the bridge gateway and the placeholder handed to a
    /// container with no name, and the runtime scopes endpoint records at those
    /// addresses to a single instance. An address a user pinned there would be
    /// advertised in DNS but resolvable only from inside its own run, so it is
    /// refused up front with a reason.
    #[test]
    fn a_pinned_ipv4_in_the_bridge_placeholder_range_is_rejected() {
        for pinned in ["172.31.0.2", "172.31.0.1", "172.31.0.200"] {
            let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
            let mut req = base_req(None);
            req.network = NetworkMode::Bridge;
            req.network_ipv4 = Some(pinned.to_string());

            let error = spec_of(req, image).expect_err("must reject the reserved /24");
            assert!(
                error.contains("172.31.0.0/24"),
                "error must name the reserved range: {error}"
            );
        }

        // The neighbouring /24s stay usable, and so does an invalid address's
        // original diagnostic.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.network = NetworkMode::Bridge;
        req.network_ipv4 = Some("172.31.1.2".to_string());
        assert_eq!(
            spec_of(req, image)
                .expect("172.31.1.2 is allocatable")
                .network
                .namespace
                .ipv4
                .to_string(),
            "172.31.1.2"
        );

        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.network = NetworkMode::Bridge;
        req.network_ipv4 = Some("not-an-address".to_string());
        assert!(
            spec_of(req, image)
                .expect_err("invalid address")
                .contains("invalid IPv4 address")
        );
    }

    #[test]
    fn extra_hosts_resolve_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.extra_hosts = vec!["db.local:10.12.0.7".to_string()];

        let spec = spec_of(req, image).expect("resolve run spec");
        assert_eq!(spec.network.extra_hosts, vec!["db.local:10.12.0.7"]);
    }

    #[test]
    fn hostname_resolves_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.hostname = Some("api-host".to_string());

        let spec = spec_of(req, image).expect("resolve run spec");
        assert_eq!(spec.network.hostname.as_deref(), Some("api-host"));
    }

    #[test]
    fn dns_overrides_resolve_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.dns_servers = vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()];
        req.dns_search = vec!["example.test".to_string()];
        req.dns_options = vec!["ndots:2".to_string()];

        let spec = spec_of(req, image).expect("resolve run spec");
        assert_eq!(
            spec.network.namespace.dns_servers,
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "9.9.9.9".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
        assert_eq!(spec.network.namespace.dns_search, vec!["example.test"]);
        assert_eq!(spec.network.namespace.dns_options, vec!["ndots:2"]);
    }

    #[test]
    fn user_numeric_uid_and_gid() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = spec_of(base_req(Some("1000:2000")), image).unwrap();
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(2000))
        );
    }

    #[test]
    fn user_numeric_uid_defaults_gid_zero() {
        // docker: `--user 1000` with no group → gid 0.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = spec_of(base_req(Some("1000")), image).unwrap();
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::new(1000), carrick_abi::NsGid::ROOT)
        );
    }

    #[test]
    fn user_absent_defaults_root() {
        // No --user and absent image USER defaults to root (0:0).
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = spec_of(base_req(None), image).unwrap();
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
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
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.process.argv, vec!["echo", "hi"]);
    }

    #[test]
    fn test_merge_argv_no_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let mut req = base_req(None);
        req.args = vec![];
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.process.executable, "/bin/sh");
        assert_eq!(spec.process.argv, vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_argv_cmd_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = base_req(None);
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.process.argv, vec!["/bin/sh", "/bin/ls"]);
    }

    #[test]
    fn test_merge_argv_entrypoint_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let mut req = base_req(None);
        req.args = vec![];
        req.entrypoint_override = Some(vec!["/bin/bash".to_string()]);
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.process.argv, vec!["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_env_variables() {
        let image = make_test_image(
            None,
            None,
            vec!["PATH=/image/bin".to_string(), "CUSTOM=1".to_string()],
            None,
        );
        let mut req = base_req(None);
        req.env_overrides = vec!["CUSTOM=2".to_string(), "USER_VAR=yes".to_string()];
        let spec = spec_of(req, image).unwrap();

        let env_map: HashMap<String, String> = spec
            .process
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
        let mut req = base_req(None);
        req.workdir = Some("/user/app".to_string());
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.process.cwd.unwrap().as_str(), "/user/app");
    }

    #[test]
    fn relative_workdir_resolves_against_image_workingdir() {
        // A RELATIVE `--workdir` joins onto the image WorkingDir (Docker
        // semantics), not `/`; an absolute one still wins verbatim.
        let mk = |img_wd: Option<&str>, wd: Option<&str>| {
            let image = make_test_image(None, None, vec![], img_wd.map(Utf8PathBuf::from));
            let mut req = base_req(None);
            req.workdir = wd.map(|s| s.to_string());
            spec_of(req, image)
                .unwrap()
                .process
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
        let spec = spec_of(base_req(None), image).unwrap();
        assert_eq!(
            spec.security.seccomp_policy,
            SeccompPolicy::ContainerDefault
        );
    }

    #[test]
    fn security_opt_seccomp_unconfined_opts_out() {
        let image = make_test_image(None, None, vec![], None);
        let mut req = base_req(None);
        req.security_opts = vec!["seccomp=unconfined".to_string()];
        let spec = spec_of(req, image).unwrap();
        assert_eq!(spec.security.seccomp_policy, SeccompPolicy::Unconfined);
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
        assert!(
            d.host_env.is_none(),
            "a library host imports nothing by default"
        );
        assert!(d.bridge_namespace_id.is_none());
        assert!(d.image_ref.is_empty() && d.args.is_empty());
    }

    #[test]
    fn stdio_mode_flows_from_request_into_run_spec() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.stdio = StdioMode::Captured;
        assert_eq!(
            spec_of(req, image).expect("resolve").process.stdio,
            StdioMode::Captured
        );
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
            spec.process
                .envp
                .iter()
                .any(|e| e == "CARRICK_TEST_IMPORT_XYZ=from-host"),
            "bare `-e KEY` imports from the snapshot; envp={:?}",
            spec.process.envp
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
            !spec
                .process
                .envp
                .iter()
                .any(|e| e.starts_with("CARRICK_TEST_NO_IMPORT_XYZ=")),
            "engine read std::env; envp={:?}",
            spec.process.envp
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
            spec.network
                .namespace
                .namespace_id
                .as_ref()
                .map(NetworkNamespaceId::as_str),
            Some("anon-4242")
        );
    }

    #[test]
    fn numeric_user_produces_no_warning() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let resolved = resolve_run_spec(parity_request(), image).expect("resolve");
        assert!(resolved.warnings.is_empty(), "{:?}", resolved.warnings);
    }

    #[test]
    fn named_user_resolves_against_rootfs_passwd() {
        let dir = tempfile::tempdir().unwrap();
        let layer_path = dir.path().join("layer.tar.gz");
        let passwd = b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\nalice:x:1001:1001:Alice:/home/alice:/bin/sh\n";
        let group = b"root:x:0:\nnobody:x:65534:\ndevelopers:x:1002:alice\n";
        let tar_gz = carrick_test_support::gzip_tar([
            ("etc/passwd", passwd.as_slice()),
            ("etc/group", group.as_slice()),
        ]);
        std::fs::write(&layer_path, tar_gz).unwrap();
        let image = ResolvedImage {
            layers: vec![Utf8PathBuf::from_path_buf(layer_path).unwrap()],
            config: ImageConfig {
                entrypoint: None,
                cmd: Some(vec!["/bin/ls".to_string()]),
                env: vec![],
                working_dir: None,
                user: None,
                exposed_ports: None,
                labels: None,
                stop_signal: None,
            },
        };

        // root -> (0, 0)
        let spec = spec_of(base_req(Some("root")), image.clone()).expect("root resolve");
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT)
        );

        // nobody -> (65534, 65534)
        let spec = spec_of(base_req(Some("nobody")), image.clone()).expect("nobody resolve");
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (
                carrick_abi::NsUid::new(65534),
                carrick_abi::NsGid::new(65534)
            )
        );

        // alice:developers -> (1001, 1002)
        let spec =
            spec_of(base_req(Some("alice:developers")), image.clone()).expect("alice:dev resolve");
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(1002))
        );

        // numeric uid with named group: 1001:developers -> (1001, 1002)
        let spec = spec_of(base_req(Some("1001:developers")), image.clone())
            .expect("numeric:group resolve");
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(1002))
        );

        // named user with numeric gid: alice:2000 -> (1001, 2000)
        let spec =
            spec_of(base_req(Some("alice:2000")), image.clone()).expect("user:numeric resolve");
        assert_eq!(
            (spec.process.uid, spec.process.gid),
            (carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(2000))
        );

        // unknown user must fail hard
        let err =
            spec_of(base_req(Some("nosuchuser")), image.clone()).expect_err("nosuchuser must fail");
        assert!(
            err.contains("nosuchuser"),
            "error must name the missing user: {err}"
        );

        // unknown group must fail hard
        let err =
            spec_of(base_req(Some("alice:nosuchgroup")), image).expect_err("nosuchgroup must fail");
        assert!(
            err.contains("nosuchgroup"),
            "error must name the missing group: {err}"
        );

        // image with empty layer list fails when named user is requested
        let empty_layer_img = ResolvedImage {
            layers: vec![],
            config: ImageConfig {
                entrypoint: None,
                cmd: Some(vec!["/bin/ls".to_string()]),
                env: vec![],
                working_dir: None,
                user: None,
                exposed_ports: None,
                labels: None,
                stop_signal: None,
            },
        };
        let err =
            spec_of(base_req(Some("nobody")), empty_layer_img).expect_err("empty layers must fail");
        assert!(
            err.contains("nobody"),
            "error must name the user when layers empty: {err}"
        );
    }

    #[tokio::test]
    async fn host_elf_resolves_into_run_spec() {
        let dir = tempfile::tempdir().unwrap();
        let elf_path = dir.path().join("my-elf");
        std::fs::write(&elf_path, b"fake elf").unwrap();
        let utf8_elf = Utf8PathBuf::from_path_buf(elf_path.canonicalize().unwrap()).unwrap();

        let req = RunRequest {
            image_source: carrick_spec::ImageSource::HostElf {
                path: utf8_elf.clone(),
                rootfs_layers: vec![],
            },
            args: vec!["--flag".to_string(), "arg1".to_string()],
            max_traps: 50,
            ..RunRequest::default()
        };

        let store_dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(store_dir.path());
        let engine = Engine::new(store);
        let resolved = engine.resolve(req).await.expect("resolve host elf");
        assert_eq!(resolved.spec.process.executable, utf8_elf.as_str());
        assert_eq!(
            resolved.spec.process.argv,
            vec![
                utf8_elf.as_str().to_string(),
                "--flag".to_string(),
                "arg1".to_string()
            ]
        );
        assert_eq!(
            resolved.spec.security.seccomp_policy,
            carrick_spec::SeccompPolicy::Unconfined
        );
        assert!(
            resolved
                .spec
                .mounts
                .mounts
                .iter()
                .any(|m| m.target == utf8_elf && m.readonly)
        );
    }
}
