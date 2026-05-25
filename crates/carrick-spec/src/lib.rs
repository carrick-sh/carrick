//! Shared Carrick data model for OCI references, image config, mounts,
//! namespaces, and run specs.

use std::collections::{HashMap, HashSet};
use camino::Utf8PathBuf;
use oci_client::Reference;
use serde::{Deserialize, Serialize};
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
    fn test_image_config_default() {
        let config = ImageConfig::default();
        assert!(config.entrypoint.is_none());
        assert!(config.cmd.is_none());
        assert!(config.env.is_empty());
    }
}
