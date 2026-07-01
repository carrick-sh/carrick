//! The carrick vocabulary crate: the plain-data nouns that every layer of the
//! runtime agrees on — OCI references, resolved image config, mounts,
//! namespaces, and the fully-resolved [`RunSpec`] that tells the runtime what
//! Linux process to launch.
//!
//! # Why this crate exists
//!
//! carrick is a multi-crate workspace whose product dependency edges flow
//! strictly downhill: `carrick-cli` → `carrick-engine` → {`carrick-image`,
//! `carrick-runtime`} → `carrick-spec`. Platform-selected VMM and host crates
//! hang below the runtime. This crate sits at the very bottom.
//! Every layer above it speaks in these types, so they are the *lingua franca*
//! that crosses every layer boundary:
//!
//! - `carrick-image` parses an OCI image's `config.json` and produces an
//!   [`ImageConfig`] (its entrypoint, cmd, env, working dir, exposed ports,
//!   stop signal). It never decides *how* to run anything; it only reports what
//!   the image declares.
//! - `carrick-cli` parses the user's `carrick run …` flags. The clap-derived
//!   enums ([`FsBackendKind`], [`PidMode`]) live here, gated behind the optional
//!   `clap` feature, so the CLI gets `--fs host`/`--pid host` parsing for free
//!   without forcing the clap dependency on `carrick-runtime` or
//!   `carrick-image`.
//! - `carrick-engine` is the only place that *merges*: it folds the CLI request
//!   and the resolved [`ImageConfig`] into a single [`RunSpec`] (image
//!   entrypoint vs. argv override, `--env` over image `ENV`, `--user` over image
//!   `USER`, working dir, mounts, namespace modes). The merge precedence lives
//!   in the engine; this crate only supplies the fields the merge writes into.
//! - `carrick-runtime` consumes the finished [`RunSpec`] and nothing else from
//!   the CLI side. It is handed a complete, self-describing launch request and
//!   does not re-read flags or image metadata.
//!
//! Keeping the vocabulary in a leaf crate of its own means these types can be
//! named in a function signature that crosses two layers without dragging in
//! either layer's machinery: `carrick-image` does not depend on the runtime,
//! the runtime does not depend on the image puller, yet both can speak
//! [`ImageConfig`] because both depend *down* on this crate. It also keeps the
//! types cheap to recompile — touching a runtime dispatch handler does not
//! rebuild the vocabulary, and adding a field here does not rebuild the
//! ~40k-line runtime until a consumer actually reads it.
//!
//! # What belongs here (and what does not)
//!
//! Strictly inert data: structs, enums, their `serde` derives, their `Default`
//! impls, and trivially pure helpers ([`ImageReference::parse`],
//! [`Platform::from_oci_str`]). There is no I/O, no syscall, no host or guest
//! state, and no dependency on any other carrick crate — only general-purpose
//! utility crates (`oci-client` for reference parsing, `camino` for
//! UTF-8-guaranteed paths, `serde`/`serde_json`, `thiserror`). Anything that
//! *acts* — pulling a layer, mapping a page, dispatching a syscall — lives in a
//! crate above this one. If a type here grows a method that touches the
//! filesystem or the network, it is in the wrong crate.
//!
//! # Invariants worth stating
//!
//! - Every type is `serde`-round-trippable: the engine serializes a [`RunSpec`]
//!   and the runtime deserializes it, and `run -d` persists an [`ImageConfig`]
//!   to disk. New fields therefore carry `#[serde(default)]` (or `Option`) so an
//!   older persisted document still loads — see the `stop_signal` and
//!   `image_config_stop_signal_round_trips_and_defaults` test for the pattern.
//! - Paths are [`Utf8PathBuf`], not `PathBuf`: a guest path that cannot be
//!   represented as UTF-8 cannot round-trip through JSON anyway, so the
//!   constraint is enforced at the type level rather than discovered at
//!   serialization time.
//! - [`NamespaceMode`] currently has exactly one variant, `Host`. The
//!   per-namespace [`NamespaceConfig`] is the seam for future private
//!   namespaces; today it documents that carrick behaves like `docker run`
//!   with every `--namespace=host`. (The one namespace that has actually grown a
//!   private mode, the PID namespace, is modeled separately by [`PidMode`],
//!   which the engine threads into the runtime.)

use camino::Utf8PathBuf;
use oci_client::Reference;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OciBootstrapError {
    #[error("invalid OCI image reference: {0}")]
    ParseReference(#[from] oci_client::ParseError),
    #[error("invalid OCI content digest: {0}")]
    InvalidDigest(String),
    #[error("OCI registry operation failed: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),
    #[error("failed to write image store: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize OCI metadata: {0}")]
    Json(#[from] serde_json::Error),
    #[error("registry authentication failed: {0}")]
    Auth(String),
    #[error("invalid registry config: {0}")]
    Config(String),
    #[error("malformed docker-archive: {0}")]
    Archive(String),
}

/// A parsed, validated OCI image reference (registry / repository / tag or
/// digest).
///
/// This is a newtype over `oci_client::Reference` rather than a re-export so
/// the rest of carrick depends on a stable surface (`registry()`,
/// `repository()`, `tag()`, `digest()`, `canonical()`) instead of the upstream
/// crate's API, and so it can carry carrick's own `serde` representation.
///
/// The serde shape is deliberately a flat *string*, not a struct of its parts:
/// `ImageReference` serializes to its canonical whole (`whole()`, e.g.
/// `docker.io/library/ubuntu:latest`) and deserializes by re-parsing that
/// string. The default-registry / default-tag normalization that
/// `oci_client` applies on parse therefore happens exactly once, on the way in;
/// a round-trip through JSON is idempotent (re-parsing an already-canonical
/// string is a no-op), which the `test_image_reference_parsing_and_serialization`
/// test pins. The constructor [`ImageReference::parse`] is the only way to make
/// one, so an `ImageReference` is always well-formed by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    inner: Reference,
}

impl ImageReference {
    pub fn parse(input: &str) -> Result<Self, OciBootstrapError> {
        Ok(Self {
            inner: input.parse()?,
        })
    }

    pub fn registry(&self) -> &str {
        self.inner.registry()
    }

    pub fn repository(&self) -> &str {
        self.inner.repository()
    }

    pub fn tag(&self) -> Option<&str> {
        self.inner.tag()
    }

    pub fn digest(&self) -> Option<&str> {
        self.inner.digest()
    }

    pub fn canonical(&self) -> String {
        self.inner.whole()
    }

    pub fn as_oci_reference(&self) -> &Reference {
        &self.inner
    }
}

impl Serialize for ImageReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.canonical().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ImageReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Vec<String>,
    pub working_dir: Option<Utf8PathBuf>,
    pub user: Option<String>,
    pub exposed_ports: Option<HashSet<String>>,
    pub labels: Option<HashMap<String, String>>,
    /// Raw OCI `StopSignal` (e.g. `SIGQUIT`), flowed into the container's stop
    /// signal at `run -d` if `--stop-signal` is not given.
    pub stop_signal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub source: Utf8PathBuf,
    pub target: Utf8PathBuf,
    pub readonly: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceMode {
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceConfig {
    pub network: NamespaceMode,
    pub pid: NamespaceMode,
    pub mount: NamespaceMode,
    pub uts: NamespaceMode,
    pub ipc: NamespaceMode,
    pub user: NamespaceMode,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            network: NamespaceMode::Host,
            pid: NamespaceMode::Host,
            mount: NamespaceMode::Host,
            uts: NamespaceMode::Host,
            ipc: NamespaceMode::Host,
            user: NamespaceMode::Host,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FsBackendKind {
    /// In-memory writable overlay. Gated behind the default-off `fs-memory`
    /// feature: silently incoherent across guest `fork` (separate host
    /// processes get private copy-on-write copies), so it is opt-in only.
    #[cfg(feature = "fs-memory")]
    Memory,
    /// Host-APFS passthrough via cap-std: the kernel is the single fork-coherent
    /// source of truth. The only backend in a default build.
    Host,
}

/// `carrick run --pid <mode>` — which PID namespace the container runs in,
/// mirroring `docker run --pid`. `Private` (the default) places the container
/// in a fresh PID namespace (its init is pid 1, ns-local child pids, ns-filtered
/// /proc — docs/namespaces-design.md §5.2). `Host` shares the host PID namespace
/// (no remap; getpid returns the real host pid), like `docker run --pid=host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum PidMode {
    /// A fresh PID namespace (default; `docker run` default).
    #[default]
    Private,
    /// Share the host PID namespace (`docker run --pid=host`).
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum NetworkMode {
    #[default]
    Host,
    Bridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkNamespaceId(String);

impl NetworkNamespaceId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BridgeId(String);

impl BridgeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn default_bridge() -> Self {
        Self("carrick0".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<IpAddr>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: PortProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkNamespaceSpec {
    pub mode: NetworkMode,
    pub namespace_id: Option<NetworkNamespaceId>,
    pub bridge_id: BridgeId,
    pub container_name: Option<String>,
    pub aliases: Vec<String>,
    pub ipv4: Ipv4Addr,
    pub gateway_v4: Ipv4Addr,
    pub dns_servers: Vec<IpAddr>,
    pub published_ports: Vec<PortMapping>,
}

impl NetworkNamespaceSpec {
    pub fn bridge_default(
        container_name: Option<String>,
        aliases: Vec<String>,
        published_ports: Vec<PortMapping>,
    ) -> Self {
        Self {
            mode: NetworkMode::Bridge,
            namespace_id: Some(NetworkNamespaceId::new("default")),
            bridge_id: BridgeId::default_bridge(),
            container_name,
            aliases,
            ipv4: Ipv4Addr::new(172, 31, 0, 2),
            gateway_v4: Ipv4Addr::new(172, 31, 0, 1),
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(172, 31, 0, 1))],
            published_ports,
        }
    }
}

impl Default for NetworkNamespaceSpec {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Host,
            namespace_id: None,
            bridge_id: BridgeId::default_bridge(),
            container_name: None,
            aliases: Vec::new(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            gateway_v4: Ipv4Addr::new(0, 0, 0, 0),
            dns_servers: Vec::new(),
            published_ports: Vec::new(),
        }
    }
}

/// The instruction-set architecture of the Linux container to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// AArch64 / arm64 — native on Apple Silicon and arm64 Linux hosts.
    Aarch64,
    /// x86_64 / amd64 — native on x86_64 hosts (the KVM/bhyve/NVMM lanes); on
    /// an aarch64 host it runs through Apple Rosetta 2 translation.
    Amd64,
}

/// How a guest [`Platform`] is executed on the host carrick was built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostExecution {
    /// Guest ISA == host ISA — runs directly, no translation.
    Native,
    /// An x86_64 guest on an aarch64 host — runs via Apple Rosetta 2 (the only
    /// cross-ISA path carrick supports), and only when Rosetta is installed.
    RosettaTranslated,
    /// No execution path exists on this host. The concrete case is an arm64
    /// guest on an x86_64 host: carrick has no arm64-on-x86_64 translation.
    Unsupported,
}

/// The host operating system carrick was built for. Fixed at compile time —
/// carrick always runs as a host-native binary — but modelled explicitly,
/// instead of left implicit in `cfg(target_os)` scattered through the
/// runnability logic, so the backend capability table can gate translators per
/// host OS (Apple Rosetta exists on macOS and Apple-Silicon Linux, but not the
/// BSD lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    /// Apple macOS (the HVF lane).
    Macos,
    /// Linux (the KVM lane); on arm64 it can expose Rosetta-for-Linux.
    Linux,
    /// FreeBSD (the bhyve lane).
    FreeBsd,
    /// NetBSD (the NVMM lane).
    NetBsd,
    /// Any other host OS carrick was not built to target.
    Other,
}

impl HostOs {
    /// The host OS this carrick binary was compiled for.
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "freebsd")]
        {
            Self::FreeBsd
        }
        #[cfg(target_os = "netbsd")]
        {
            Self::NetBsd
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd"
        )))]
        {
            Self::Other
        }
    }
}

/// What the carrick binary in front of you can actually run: the host OS and ISA
/// it was built for, and — via [`host_execution`](Self::host_execution) — which
/// guest [`Platform`]s it admits natively versus through a translator. This is
/// the "backend capability table" seam: it keeps apart the three concerns
/// `Platform::host_execution` used to fuse — the GUEST ISA ([`Platform`]), the
/// HOST build target (this descriptor), and the EXECUTION MECHANISM
/// ([`HostExecution`]). A new (host_os, host_isa, guest) execution path is a new
/// arm in [`host_execution`](Self::host_execution), not an edit scattered across
/// `Platform`.
///
/// The VMM backend (HVF/KVM/bhyve/NVMM) is a fourth dimension the audit names,
/// but today it is fixed by the compile-time `platform-*` feature and fully
/// implied by `host_os`, so it is not carried here yet — it joins this descriptor
/// when the per-VMM runtime-platform descriptor lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// The host OS this build targets.
    pub host_os: HostOs,
    /// The host CPU ISA this build runs on (the ISA a guest runs natively).
    pub host_isa: Platform,
}

impl BackendCapabilities {
    /// The capabilities of the carrick binary you are running — derived from the
    /// compile-time host OS and ISA.
    pub const fn current() -> Self {
        Self {
            host_os: HostOs::current(),
            host_isa: Platform::host_native(),
        }
    }

    /// Classify how this host would run a `guest` [`Platform`]:
    /// [`Native`](HostExecution::Native) when the guest ISA matches the host
    /// ISA; [`RosettaTranslated`](HostExecution::RosettaTranslated) for an
    /// x86_64 guest on an aarch64 host on the macOS or Linux lanes (Apple
    /// Rosetta 2 / Rosetta-for-Linux — the one cross-ISA path carrick models,
    /// and only where a translator can exist);
    /// [`Unsupported`](HostExecution::Unsupported) otherwise (an arm64 guest on
    /// an x86_64 host has no reverse translation, and the BSD arm lanes have no
    /// translator). This is the STATIC capability answer; the caller still probes
    /// that the translator is actually installed
    /// (`carrick_engine::check_platform_runnable` →
    /// `carrick_runtime::rosetta_available`).
    pub const fn host_execution(&self, guest: Platform) -> HostExecution {
        match (self.host_isa, guest) {
            (Platform::Aarch64, Platform::Aarch64) | (Platform::Amd64, Platform::Amd64) => {
                HostExecution::Native
            }
            (Platform::Aarch64, Platform::Amd64) => match self.host_os {
                HostOs::Macos | HostOs::Linux => HostExecution::RosettaTranslated,
                HostOs::FreeBsd | HostOs::NetBsd | HostOs::Other => HostExecution::Unsupported,
            },
            (Platform::Amd64, Platform::Aarch64) => HostExecution::Unsupported,
        }
    }
}

impl Platform {
    /// The host's native guest ISA — what `carrick run` targets when
    /// `--platform` is omitted. carrick always runs as a host-native binary
    /// (never itself under emulation), so the compiled-in `target_arch` *is* the
    /// host CPU architecture: aarch64 on Apple Silicon (and arm64 Linux),
    /// x86_64 on the amd64 Linux/FreeBSD/NetBSD lanes. This is the value behind
    /// [`Default`], used both for the CLI `--platform` fallback and the
    /// [`RunSpec::platform`] serde default.
    pub const fn host_native() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(target_arch = "x86_64")]
        {
            Self::Amd64
        }
        // carrick only builds for aarch64/x86_64; fall back to aarch64 so the
        // type still has a sensible default on any other host arch.
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            Self::Aarch64
        }
    }

    /// Parse from OCI platform strings ("linux/amd64", "linux/arm64", …) or
    /// bare arch tokens ("amd64", "arm64"). Returns `None` for anything we
    /// can't run, so the caller can fall back to the default.
    pub fn from_oci_str(s: &str) -> Option<Self> {
        // Accept an optional "linux/" (or other os/) prefix; we only run linux
        // guests, so the os component is advisory.
        let arch = s.rsplit('/').next().unwrap_or(s).trim();
        match arch {
            "amd64" | "x86_64" | "x86-64" => Some(Self::Amd64),
            "arm64" | "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// The OCI `architecture` token used in image-index platform matching.
    pub fn oci_arch(self) -> &'static str {
        match self {
            Self::Aarch64 => "arm64",
            Self::Amd64 => "amd64",
        }
    }
}

/// Defaults to the host-native ISA (see [`Platform::host_native`]) so a
/// `carrick run` with no `--platform` targets the architecture carrick can run
/// without translation, and a `RunSpec` deserialized without an explicit
/// `platform` field inherits that same host-native default. (Historically this
/// was hard-wired to `Aarch64`; pre-`platform` specs were only ever produced on
/// aarch64 macOS, where host-native is still `Aarch64`, so the default is
/// back-compatible there.)
impl Default for Platform {
    fn default() -> Self {
        Self::host_native()
    }
}

/// The fully-resolved launch request: everything `carrick-runtime` needs to
/// start one Linux process, with every CLI-vs-image precedence decision already
/// made.
///
/// A `RunSpec` is the hand-off point between the merge layer and the execution
/// layer. `carrick-engine::resolve_run_spec` produces it by folding the user's
/// CLI request over the resolved [`ImageConfig`]; `carrick-runtime` consumes it
/// and re-reads neither the flags nor the image metadata. Read in that light,
/// the fields split into three groups:
///
/// - *What to run*: `executable` / `argv` / `envp` / `cwd` — the resolved
///   entrypoint+cmd, environment, and working directory after the image
///   defaults and CLI overrides have been reconciled.
/// - *What it sees*: `rootfs_layers` (the OCI layer dirs to stack into the
///   guest root), `fs_backend` (in-memory overlay vs. host-APFS passthrough,
///   see [`FsBackendKind`]), and `mounts` (host bind mounts).
/// - *How it behaves*: `tty` / `raw` / `interactive` (terminal handling),
///   `platform` (native aarch64 vs. Rosetta-translated amd64), `pid`
///   (PID-namespace mode), `uid` / `gid` (initial guest credentials),
///   `max_traps` (a syscall-count guard rail for tests/debugging), and
///   `debug_state_path` (where to dump guest state).
///
/// The trailing fields carry `#[serde(default)]` so a `RunSpec` persisted by an
/// older build still deserializes — see the crate-level note on additive
/// evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    pub executable: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    pub cwd: Option<Utf8PathBuf>,
    pub rootfs_layers: Vec<Utf8PathBuf>,
    pub fs_backend: FsBackendKind,
    pub mounts: Vec<Mount>,
    pub tty: bool,
    pub raw: bool,
    pub interactive: bool,
    pub max_traps: usize,
    pub debug_state_path: Option<Utf8PathBuf>,
    /// Target ISA of the container. On an aarch64 host, `Amd64` enables Rosetta 2
    /// translation: the runtime redirects x86_64 ELF loads through Rosetta and
    /// bind-mounts the host Rosetta runtime into the guest VFS; on an x86_64 host
    /// `Amd64` is the native ISA. Defaults to the host-native architecture (see
    /// [`Platform::host_native`]).
    #[serde(default)]
    pub platform: Platform,
    /// PID namespace mode (`docker run --pid`). `Private` (default) gives the
    /// container its own pid ns (init == pid 1); `Host` shares the host pid ns.
    #[serde(default)]
    pub pid: PidMode,
    /// Network namespace mode and resolved bridge view.
    #[serde(default)]
    pub network: NetworkNamespaceSpec,
    /// Initial guest user id (`docker run --user` / image `USER`). The guest's
    /// real/effective/saved/fs uid are all seeded to this. Defaults to 0 (root).
    #[serde(default)]
    pub uid: u32,
    /// Initial guest group id. Defaults to 0 (root); for a numeric `--user UID`
    /// with no group, docker uses gid 0.
    #[serde(default)]
    pub gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_spec_network_defaults_to_host() {
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
        assert_eq!(spec.network.mode, NetworkMode::Host);
        assert!(spec.network.namespace_id.is_none());
        assert!(spec.network.published_ports.is_empty());
    }

    #[test]
    fn bridge_network_spec_round_trips() {
        let spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["api".to_string()],
            vec![PortMapping {
                host_ip: None,
                host_port: Some(8080),
                container_port: 80,
                protocol: PortProtocol::Tcp,
            }],
        );

        let encoded = serde_json::to_string(&spec).expect("serialize");
        let decoded: NetworkNamespaceSpec = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.mode, NetworkMode::Bridge);
        assert_eq!(decoded.bridge_id.as_str(), "carrick0");
        assert_eq!(decoded.ipv4.to_string(), "172.31.0.2");
        assert_eq!(decoded.gateway_v4.to_string(), "172.31.0.1");
        assert_eq!(decoded.aliases, vec!["api"]);
        assert_eq!(decoded.published_ports[0].container_port, 80);
    }

    #[test]
    fn test_image_reference_parsing_and_serialization() {
        let reference = ImageReference::parse("ubuntu:latest").expect("valid parsing");
        assert_eq!(reference.registry(), "docker.io");
        assert_eq!(reference.repository(), "library/ubuntu");
        assert_eq!(reference.tag(), Some("latest"));
        assert_eq!(reference.canonical(), "docker.io/library/ubuntu:latest");

        let serialized = serde_json::to_string(&reference).expect("serialize");
        assert_eq!(serialized, "\"docker.io/library/ubuntu:latest\"");

        let deserialized: ImageReference = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized, reference);
    }

    #[test]
    fn test_platform_from_oci_str() {
        assert_eq!(Platform::from_oci_str("linux/amd64"), Some(Platform::Amd64));
        assert_eq!(
            Platform::from_oci_str("linux/x86_64"),
            Some(Platform::Amd64)
        );
        assert_eq!(Platform::from_oci_str("amd64"), Some(Platform::Amd64));
        assert_eq!(
            Platform::from_oci_str("linux/arm64"),
            Some(Platform::Aarch64)
        );
        assert_eq!(
            Platform::from_oci_str("linux/aarch64"),
            Some(Platform::Aarch64)
        );
        assert_eq!(Platform::from_oci_str("linux/riscv64"), None);
        assert_eq!(Platform::default(), Platform::host_native());
        assert_eq!(Platform::Amd64.oci_arch(), "amd64");
    }

    #[test]
    fn test_host_native_and_execution() {
        // `Default` follows the host architecture, and the native guest always
        // runs without translation through the current backend capabilities. (The
        // full host_os × isa × guest matrix is in the backend_caps_* tests; here
        // we pin the compiled host's own defaults.)
        let caps = BackendCapabilities::current();
        assert_eq!(Platform::default(), Platform::host_native());
        assert_eq!(
            caps.host_execution(Platform::host_native()),
            HostExecution::Native
        );

        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(Platform::default(), Platform::Aarch64);
            assert_eq!(
                caps.host_execution(Platform::Aarch64),
                HostExecution::Native
            );
            // x86_64 guest on an Apple-Silicon macOS/Linux host → Rosetta path.
            assert_eq!(
                caps.host_execution(Platform::Amd64),
                HostExecution::RosettaTranslated
            );
        }

        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(Platform::default(), Platform::Amd64);
            assert_eq!(caps.host_execution(Platform::Amd64), HostExecution::Native);
            // arm64 guest on an x86_64 host → no reverse translation.
            assert_eq!(
                caps.host_execution(Platform::Aarch64),
                HostExecution::Unsupported
            );
        }
    }

    #[test]
    fn backend_caps_native_when_guest_isa_matches_host() {
        for host_os in [
            HostOs::Macos,
            HostOs::Linux,
            HostOs::FreeBsd,
            HostOs::NetBsd,
        ] {
            for isa in [Platform::Aarch64, Platform::Amd64] {
                let caps = BackendCapabilities {
                    host_os,
                    host_isa: isa,
                };
                assert_eq!(
                    caps.host_execution(isa),
                    HostExecution::Native,
                    "{host_os:?}/{isa:?} runs its own ISA natively"
                );
            }
        }
    }

    #[test]
    fn backend_caps_amd64_on_arm_is_rosetta_only_on_macos_and_linux() {
        let on = |host_os| BackendCapabilities {
            host_os,
            host_isa: Platform::Aarch64,
        };
        // Apple Rosetta 2 (macOS) and Rosetta-for-Linux translate amd64 → arm64.
        assert_eq!(
            on(HostOs::Macos).host_execution(Platform::Amd64),
            HostExecution::RosettaTranslated
        );
        assert_eq!(
            on(HostOs::Linux).host_execution(Platform::Amd64),
            HostExecution::RosettaTranslated
        );
        // The BSD arm lanes have no translator → reject, not a false "translatable".
        assert_eq!(
            on(HostOs::FreeBsd).host_execution(Platform::Amd64),
            HostExecution::Unsupported
        );
        assert_eq!(
            on(HostOs::NetBsd).host_execution(Platform::Amd64),
            HostExecution::Unsupported
        );
    }

    #[test]
    fn backend_caps_arm64_on_x86_is_unsupported_on_every_host_os() {
        for host_os in [
            HostOs::Macos,
            HostOs::Linux,
            HostOs::FreeBsd,
            HostOs::NetBsd,
        ] {
            let caps = BackendCapabilities {
                host_os,
                host_isa: Platform::Amd64,
            };
            assert_eq!(
                caps.host_execution(Platform::Aarch64),
                HostExecution::Unsupported,
                "no reverse arm64-on-x86_64 translation on {host_os:?}"
            );
        }
    }

    #[test]
    fn backend_caps_current_reflects_the_compiled_host() {
        let caps = BackendCapabilities::current();
        assert_eq!(caps.host_isa, Platform::host_native());
        assert_eq!(caps.host_os, HostOs::current());
        // Whatever host this is, it runs its own native ISA without translation.
        assert_eq!(
            caps.host_execution(Platform::host_native()),
            HostExecution::Native
        );
    }

    #[test]
    fn test_image_config_default() {
        let config = ImageConfig::default();
        assert!(config.entrypoint.is_none());
        assert!(config.cmd.is_none());
        assert!(config.env.is_empty());
        assert!(config.stop_signal.is_none());
    }

    #[test]
    fn image_config_stop_signal_round_trips_and_defaults() {
        // Additive: a config JSON without stop_signal still loads.
        let legacy: ImageConfig = serde_json::from_str("{}").expect("legacy loads");
        assert!(legacy.stop_signal.is_none());
        let c = ImageConfig {
            stop_signal: Some("SIGQUIT".to_string()),
            ..Default::default()
        };
        let round: ImageConfig = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(round.stop_signal.as_deref(), Some("SIGQUIT"));
    }
}
