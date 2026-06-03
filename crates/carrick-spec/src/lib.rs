//! The carrick vocabulary crate: the plain-data nouns that every layer of the
//! runtime agrees on — OCI references, resolved image config, mounts,
//! namespaces, and the fully-resolved [`RunSpec`] that tells the runtime what
//! Linux process to launch.
//!
//! # Why this crate exists
//!
//! carrick is a five-crate workspace whose dependency edges flow strictly
//! downhill: `carrick-cli` → `carrick-engine` → {`carrick-image`,
//! `carrick-runtime`} → `carrick-spec`. This crate sits at the very bottom.
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
    Memory,
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

/// The instruction-set architecture of the Linux container to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// AArch64 / arm64 — native on Apple Silicon. Default.
    #[default]
    Aarch64,
    /// x86_64 / amd64 — translated via Apple Rosetta 2.
    Amd64,
}

impl Platform {
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
    /// Target ISA of the container. `Amd64` enables Rosetta 2 translation:
    /// the runtime redirects x86_64 ELF loads through Rosetta and bind-mounts
    /// the host Rosetta runtime into the guest VFS. Defaults to `Aarch64`.
    #[serde(default)]
    pub platform: Platform,
    /// PID namespace mode (`docker run --pid`). `Private` (default) gives the
    /// container its own pid ns (init == pid 1); `Host` shares the host pid ns.
    #[serde(default)]
    pub pid: PidMode,
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
        assert_eq!(Platform::default(), Platform::Aarch64);
        assert_eq!(Platform::Amd64.oci_arch(), "amd64");
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
