//! Shared Carrick data model for OCI references, image config, mounts,
//! namespaces, and run specs.

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
}

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
    }
}
