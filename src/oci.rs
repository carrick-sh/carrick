use std::env;
use std::path::{Path, PathBuf};

use oci_client::client::ClientConfig;
use oci_client::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE, ImageIndexEntry,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageStore {
    root: PathBuf,
}

impl ImageStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn default_for_user() -> Self {
        let root = env::var_os("CARRICK_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".carrick")))
            .unwrap_or_else(|| PathBuf::from(".carrick"));
        Self::new(root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn image_dir(&self, image: &ImageReference) -> PathBuf {
        let mut path = self.root.join("images").join(image.registry());
        for component in image.repository().split('/') {
            path.push(component);
        }
        match image.tag() {
            Some(tag) => path.push(tag),
            None => {
                if let Some(digest) = image.digest() {
                    let (algorithm, encoded) = digest.split_once(':').unwrap_or((digest, ""));
                    path.push(algorithm);
                    path.push(encoded);
                }
            }
        }
        path
    }

    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, OciBootstrapError> {
        let (algorithm, encoded) = digest
            .split_once(':')
            .ok_or_else(|| OciBootstrapError::InvalidDigest(digest.to_owned()))?;
        if algorithm != "sha256"
            || encoded.is_empty()
            || !encoded.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(OciBootstrapError::InvalidDigest(digest.to_owned()));
        }
        Ok(self.root.join("blobs").join(algorithm).join(encoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullSummary {
    pub image: String,
    pub digest: Option<String>,
    pub image_dir: PathBuf,
    pub config_size: usize,
    pub layers: Vec<LayerSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerSummary {
    pub digest: String,
    pub media_type: String,
    pub size: usize,
    pub path: PathBuf,
}

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

impl ImageStore {
    pub fn image_summary_path(&self, image: &ImageReference) -> PathBuf {
        self.image_dir(image).join("carrick-image.json")
    }

    pub async fn load_pull_summary(
        &self,
        image: &ImageReference,
    ) -> Result<PullSummary, OciBootstrapError> {
        let bytes = fs::read(self.image_summary_path(image)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Environment variable used to override the platform that
/// [`pull_image`] requests when a registry returns a multi-arch image
/// index. Format: `os/arch[/variant]`, e.g. `linux/amd64` or
/// `linux/arm64/v8`. When unset, defaults to `linux/arm64` (the
/// architecture Carrick's HVF backend executes).
pub const PLATFORM_OVERRIDE_ENV: &str = "CARRICK_PULL_PLATFORM";

/// Comma-separated registry hosts (`host` or `host:port`) to contact over
/// plain HTTP instead of HTTPS. Used to pull from a local, throwaway
/// `registry:2` (e.g. the LTP conformance image) without standing up TLS.
/// `localhost` and `127.0.0.1` are always treated as insecure; this env var
/// extends the set. Never affects real registries like docker.io.
pub const INSECURE_REGISTRIES_ENV: &str = "CARRICK_INSECURE_REGISTRIES";

/// A parsed `os/arch[/variant]` platform target used to pick a manifest
/// from an OCI image index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTarget {
    pub os: String,
    pub arch: String,
    /// `None` means "match either a missing variant or any variant
    /// considered ABI-compatible by [`PlatformTarget::matches`]". A
    /// concrete `Some("v8")` requires the manifest to either declare
    /// that variant or declare no variant at all.
    pub variant: Option<String>,
}

impl PlatformTarget {
    /// The default Carrick target: linux/arm64 with no required variant.
    pub fn default_target() -> Self {
        Self {
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            variant: None,
        }
    }

    /// Parse a `os/arch[/variant]` string. Returns `None` if the value
    /// can't be split into at least two non-empty components.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('/');
        let os = parts.next()?.trim();
        let arch = parts.next()?.trim();
        if os.is_empty() || arch.is_empty() {
            return None;
        }
        let variant = parts
            .next()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Some(Self {
            os: os.to_string(),
            arch: arch.to_string(),
            variant,
        })
    }

    /// Returns true if this target should accept the given platform
    /// entry. The os and arch must match exactly. For arm64, a
    /// missing required variant accepts entries with no variant or
    /// the `v8` variant (the only ABI-compatible variant for arm64
    /// on the host); other variants are rejected. If this target
    /// declares a specific variant, the entry must either declare
    /// the same variant or no variant at all.
    pub fn matches(&self, entry_os: &str, entry_arch: &str, entry_variant: Option<&str>) -> bool {
        if entry_os != self.os || entry_arch != self.arch {
            return false;
        }
        match (&self.variant, entry_variant) {
            (None, None) => true,
            (None, Some(v)) => {
                if self.arch == "arm64" {
                    v == "v8"
                } else {
                    // For other architectures be permissive: variants
                    // beyond the bare arch are typically ABI-compatible
                    // (e.g. amd64 has no meaningful variants on Linux).
                    true
                }
            }
            (Some(required), Some(actual)) => required == actual,
            (Some(_), None) => true,
        }
    }
}

/// Read the platform target from `CARRICK_PULL_PLATFORM`, falling
/// back to [`PlatformTarget::default_target`] when unset or
/// unparseable.
pub fn platform_target_from_env() -> PlatformTarget {
    env::var(PLATFORM_OVERRIDE_ENV)
        .ok()
        .as_deref()
        .and_then(PlatformTarget::parse)
        .unwrap_or_else(PlatformTarget::default_target)
}

/// Walk an OCI image index's manifest entries and return the digest
/// of the manifest that matches `target`, or `None` if no entry
/// matches. Entries without a `platform` block are skipped.
pub fn select_manifest_digest(
    entries: &[ImageIndexEntry],
    target: &PlatformTarget,
) -> Option<String> {
    entries.iter().find_map(|entry| {
        let platform = entry.platform.as_ref()?;
        let variant = platform.variant.as_deref();
        if target.matches(&platform.os, &platform.architecture, variant) {
            Some(entry.digest.clone())
        } else {
            None
        }
    })
}

/// Build the list of registry hosts to contact over plain HTTP: the
/// always-insecure loopback hosts plus any from [`INSECURE_REGISTRIES_ENV`].
fn insecure_registries() -> Vec<String> {
    // oci-distribution matches the FULL `host:port` string, so we enumerate
    // both bare and the conventional registry:2 port (5000). Extra forms come
    // from the env var.
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "localhost:5000".to_string(),
        "127.0.0.1:5000".to_string(),
    ];
    if let Ok(extra) = env::var(INSECURE_REGISTRIES_ENV) {
        hosts.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    hosts
}

fn build_oci_client() -> Client {
    use oci_client::client::ClientProtocol;
    let target = platform_target_from_env();
    let config = ClientConfig {
        protocol: ClientProtocol::HttpsExcept(insecure_registries()),
        platform_resolver: Some(Box::new(move |entries: &[ImageIndexEntry]| {
            select_manifest_digest(entries, &target)
        })),
        ..ClientConfig::default()
    };
    Client::new(config)
}

pub async fn pull_image(
    image: &ImageReference,
    store: &ImageStore,
) -> Result<PullSummary, OciBootstrapError> {
    let client = build_oci_client();
    let data = client
        .pull(
            image.as_oci_reference(),
            &RegistryAuth::Anonymous,
            vec![
                IMAGE_LAYER_MEDIA_TYPE,
                IMAGE_LAYER_GZIP_MEDIA_TYPE,
                IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
                IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
            ],
        )
        .await?;

    fs::create_dir_all(store.root.join("blobs").join("sha256")).await?;
    let config_size = data.config.data.len();

    let mut layers = Vec::with_capacity(data.layers.len());
    for layer in data.layers {
        let digest = layer.sha256_digest();
        let path = store.blob_path(&digest)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, &layer.data).await?;
        layers.push(LayerSummary {
            digest,
            media_type: layer.media_type,
            size: layer.data.len(),
            path,
        });
    }

    let image_dir = store.image_dir(image);
    fs::create_dir_all(&image_dir).await?;
    fs::write(image_dir.join("config.json"), data.config.data).await?;
    if let Some(manifest) = data.manifest {
        fs::write(
            image_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )
        .await?;
    }

    let summary = PullSummary {
        image: image.canonical(),
        digest: data.digest,
        image_dir,
        config_size,
        layers,
    };
    fs::write(
        summary.image_dir.join("carrick-image.json"),
        serde_json::to_vec_pretty(&summary)?,
    )
    .await?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_client::manifest::{IMAGE_MANIFEST_MEDIA_TYPE, ImageIndexEntry, Platform};

    fn entry(os: &str, arch: &str, variant: Option<&str>, digest: &str) -> ImageIndexEntry {
        ImageIndexEntry {
            media_type: IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
            digest: digest.to_string(),
            size: 0,
            platform: Some(Platform {
                architecture: arch.to_string(),
                os: os.to_string(),
                os_version: None,
                os_features: None,
                variant: variant.map(|v| v.to_string()),
                features: None,
            }),
            annotations: None,
        }
    }

    #[test]
    fn picks_linux_arm64_from_multi_arch_index() {
        let entries = vec![
            entry("linux", "amd64", None, "sha256:amd64"),
            entry("linux", "arm64", None, "sha256:arm64"),
            entry("linux", "arm", Some("v7"), "sha256:armv7"),
        ];
        let target = PlatformTarget::default_target();
        assert_eq!(
            select_manifest_digest(&entries, &target),
            Some("sha256:arm64".to_string())
        );
    }

    #[test]
    fn override_selects_amd64_when_only_amd64_present() {
        let entries = vec![entry("linux", "amd64", None, "sha256:amd64")];
        let target = PlatformTarget::parse("linux/amd64").expect("parse");
        assert_eq!(
            select_manifest_digest(&entries, &target),
            Some("sha256:amd64".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_linux_arm64_present() {
        let entries = vec![
            entry("windows", "amd64", None, "sha256:win-amd64"),
            entry("windows", "arm64", None, "sha256:win-arm64"),
        ];
        let target = PlatformTarget::default_target();
        assert_eq!(select_manifest_digest(&entries, &target), None);
    }

    #[test]
    fn accepts_arm64_v8_variant() {
        let entries = vec![entry("linux", "arm64", Some("v8"), "sha256:arm64v8")];
        let target = PlatformTarget::default_target();
        assert_eq!(
            select_manifest_digest(&entries, &target),
            Some("sha256:arm64v8".to_string())
        );
    }

    #[test]
    fn rejects_arm64_v7_variant() {
        // arm64 with a non-v8 variant must NOT be selected; the ABI
        // does not match the host's arm64/v8 expectation.
        let entries = vec![entry("linux", "arm64", Some("v7"), "sha256:arm64v7")];
        let target = PlatformTarget::default_target();
        assert_eq!(select_manifest_digest(&entries, &target), None);
    }

    #[test]
    fn parse_platform_target_with_variant() {
        let target = PlatformTarget::parse("linux/arm64/v8").expect("parse");
        assert_eq!(target.os, "linux");
        assert_eq!(target.arch, "arm64");
        assert_eq!(target.variant.as_deref(), Some("v8"));
    }

    #[test]
    fn parse_platform_target_without_variant() {
        let target = PlatformTarget::parse("linux/amd64").expect("parse");
        assert_eq!(target.os, "linux");
        assert_eq!(target.arch, "amd64");
        assert_eq!(target.variant, None);
    }

    #[test]
    fn parse_platform_target_rejects_garbage() {
        assert!(PlatformTarget::parse("").is_none());
        assert!(PlatformTarget::parse("linux").is_none());
        assert!(PlatformTarget::parse("/amd64").is_none());
        assert!(PlatformTarget::parse("linux/").is_none());
    }

    #[test]
    fn override_arm64_v8_matches_unspecified_entry() {
        // If the override pins variant=v8 but the registry's entry
        // omits variant, we still accept it (a missing variant on the
        // entry side is treated as compatible).
        let entries = vec![entry("linux", "arm64", None, "sha256:arm64")];
        let target = PlatformTarget::parse("linux/arm64/v8").expect("parse");
        assert_eq!(
            select_manifest_digest(&entries, &target),
            Some("sha256:arm64".to_string())
        );
    }

    #[test]
    fn skips_entry_with_no_platform_block() {
        let mut bad = entry("linux", "arm64", None, "sha256:nope");
        bad.platform = None;
        let good = entry("linux", "arm64", None, "sha256:arm64");
        let entries = vec![bad, good];
        let target = PlatformTarget::default_target();
        assert_eq!(
            select_manifest_digest(&entries, &target),
            Some("sha256:arm64".to_string())
        );
    }
}
