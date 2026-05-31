//! OCI image resolution and layer-fetching support used by the CLI and
//! engine crates.

use std::collections::HashMap;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use oci_client::Client;
use oci_client::client::{ClientConfig, ImageLayer};
use oci_client::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE, ImageIndexEntry, OciImageManifest,
};
use oci_client::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};
use tokio::fs;

pub use carrick_spec::{ImageConfig, ImageReference, OciBootstrapError};

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

    /// Per-platform image directory. The host-native default (linux/arm64)
    /// keeps the legacy un-suffixed path so existing stores still resolve;
    /// any other platform (e.g. linux/amd64 for Rosetta) is cached in a
    /// sibling subdirectory so the two architectures never collide.
    pub fn image_dir_for(&self, image: &ImageReference, target: &PlatformTarget) -> PathBuf {
        let base = self.image_dir(image);
        if *target == PlatformTarget::default_target() {
            base
        } else {
            base.join(format!("__platform__{}_{}", target.os, target.arch))
        }
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

impl ImageStore {
    pub fn image_summary_path(&self, image: &ImageReference) -> PathBuf {
        self.image_dir(image).join("carrick-image.json")
    }

    pub fn image_summary_path_for(
        &self,
        image: &ImageReference,
        target: &PlatformTarget,
    ) -> PathBuf {
        self.image_dir_for(image, target).join("carrick-image.json")
    }

    pub async fn load_pull_summary_for(
        &self,
        image: &ImageReference,
        target: &PlatformTarget,
    ) -> Result<PullSummary, OciBootstrapError> {
        let bytes = fs::read(self.image_summary_path_for(image, target)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn load_pull_summary(
        &self,
        image: &ImageReference,
    ) -> Result<PullSummary, OciBootstrapError> {
        let bytes = fs::read(self.image_summary_path(image)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

pub const PLATFORM_OVERRIDE_ENV: &str = "CARRICK_PULL_PLATFORM";
pub const INSECURE_REGISTRIES_ENV: &str = "CARRICK_INSECURE_REGISTRIES";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTarget {
    pub os: String,
    pub arch: String,
    pub variant: Option<String>,
}

impl PlatformTarget {
    pub fn default_target() -> Self {
        Self {
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            variant: None,
        }
    }

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
                    true
                }
            }
            (Some(required), Some(actual)) => required == actual,
            (Some(_), None) => true,
        }
    }
}

pub fn platform_target_from_env() -> PlatformTarget {
    env::var(PLATFORM_OVERRIDE_ENV)
        .ok()
        .as_deref()
        .and_then(PlatformTarget::parse)
        .unwrap_or_else(PlatformTarget::default_target)
}

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

fn insecure_registries() -> Vec<String> {
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

fn build_oci_client_for(target: &PlatformTarget) -> Client {
    use oci_client::client::ClientProtocol;
    let target = target.clone();
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
    pull_image_with_platform(image, store, &platform_target_from_env()).await
}

/// Pull `image` for an explicit platform, selecting the matching OCI manifest
/// entry and caching it in the platform-keyed image directory. Layer blobs are
/// content-addressed so they share the store's blob directory regardless of
/// platform.
pub async fn pull_image_with_platform(
    image: &ImageReference,
    store: &ImageStore,
    target: &PlatformTarget,
) -> Result<PullSummary, OciBootstrapError> {
    let client = build_oci_client_for(target);
    let mut data = client
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

    let ordered_layers =
        layers_in_manifest_order(data.manifest.as_ref(), std::mem::take(&mut data.layers))?;
    let mut layers = Vec::with_capacity(ordered_layers.len());
    for layer in ordered_layers {
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

    let image_dir = store.image_dir_for(image, target);
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

fn layers_in_manifest_order(
    manifest: Option<&OciImageManifest>,
    layers: Vec<ImageLayer>,
) -> Result<Vec<ImageLayer>, OciBootstrapError> {
    let Some(manifest) = manifest else {
        return Ok(layers);
    };

    let mut by_digest: HashMap<String, Vec<ImageLayer>> = HashMap::with_capacity(layers.len());
    for layer in layers {
        by_digest
            .entry(layer.sha256_digest())
            .or_default()
            .push(layer);
    }

    let mut ordered = Vec::with_capacity(manifest.layers.len());
    for descriptor in &manifest.layers {
        let Some(mut bucket) = by_digest.remove(&descriptor.digest) else {
            return Err(OciBootstrapError::InvalidDigest(format!(
                "manifest referenced missing layer {}",
                descriptor.digest
            )));
        };
        let layer = bucket.pop().expect("non-empty layer bucket");
        if !bucket.is_empty() {
            by_digest.insert(descriptor.digest.clone(), bucket);
        }
        ordered.push(layer);
    }

    if let Some(extra) = by_digest.keys().next() {
        return Err(OciBootstrapError::InvalidDigest(format!(
            "downloaded unreferenced layer {extra}"
        )));
    }

    Ok(ordered)
}

fn layer_summaries_in_manifest_order(
    manifest: &OciImageManifest,
    layers: Vec<LayerSummary>,
) -> Result<Vec<LayerSummary>, OciBootstrapError> {
    let mut by_digest: HashMap<String, Vec<LayerSummary>> = HashMap::with_capacity(layers.len());
    for layer in layers {
        by_digest
            .entry(layer.digest.clone())
            .or_default()
            .push(layer);
    }

    let mut ordered = Vec::with_capacity(manifest.layers.len());
    for descriptor in &manifest.layers {
        let Some(mut bucket) = by_digest.remove(&descriptor.digest) else {
            return Err(OciBootstrapError::InvalidDigest(format!(
                "manifest referenced missing layer {}",
                descriptor.digest
            )));
        };
        let layer = bucket.pop().expect("non-empty layer summary bucket");
        if !bucket.is_empty() {
            by_digest.insert(descriptor.digest.clone(), bucket);
        }
        ordered.push(layer);
    }

    if let Some(extra) = by_digest.keys().next() {
        return Err(OciBootstrapError::InvalidDigest(format!(
            "cached unreferenced layer {extra}"
        )));
    }

    Ok(ordered)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedImage {
    pub layers: Vec<camino::Utf8PathBuf>,
    pub config: ImageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OciImageConfigContainer {
    config: Option<OciImageConfigInner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OciImageConfigInner {
    user: Option<String>,
    exposed_ports: Option<std::collections::HashMap<String, serde_json::Value>>,
    env: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    working_dir: Option<camino::Utf8PathBuf>,
    labels: Option<std::collections::HashMap<String, String>>,
}

impl OciImageConfigContainer {
    fn into_image_config(self) -> ImageConfig {
        if let Some(inner) = self.config {
            let exposed = inner.exposed_ports.map(|m| m.into_keys().collect());
            ImageConfig {
                entrypoint: inner.entrypoint,
                cmd: inner.cmd,
                env: inner.env.unwrap_or_default(),
                working_dir: inner.working_dir,
                user: inner.user,
                exposed_ports: exposed,
                labels: inner.labels,
            }
        } else {
            ImageConfig::default()
        }
    }
}

impl ImageStore {
    pub async fn resolve(
        &self,
        image: &ImageReference,
    ) -> Result<ResolvedImage, OciBootstrapError> {
        self.resolve_with_platform(image, &platform_target_from_env())
            .await
    }

    /// Resolve an image for an explicit platform. Looks up the platform-keyed
    /// cache first, pulling the matching manifest if absent. Used by the engine
    /// to fetch the `linux/amd64` variant for Rosetta-translated runs without
    /// clobbering the host-native arm64 cache.
    pub async fn resolve_with_platform(
        &self,
        image: &ImageReference,
        target: &PlatformTarget,
    ) -> Result<ResolvedImage, OciBootstrapError> {
        let summary = match self.load_pull_summary_for(image, target).await {
            Ok(summary) => summary,
            Err(_) => {
                eprintln!(
                    "carrick: image {} ({}/{}) not in store; pulling…",
                    image.canonical(),
                    target.os,
                    target.arch
                );
                pull_image_with_platform(image, self, target).await?
            }
        };

        let image_dir = summary.image_dir.clone();
        let layer_summaries = match fs::read(image_dir.join("manifest.json")).await {
            Ok(manifest_bytes) => {
                let manifest = serde_json::from_slice::<OciImageManifest>(&manifest_bytes)?;
                layer_summaries_in_manifest_order(&manifest, summary.layers)?
            }
            Err(err) if err.kind() == ErrorKind::NotFound => summary.layers,
            Err(err) => return Err(err.into()),
        };

        let layers: Vec<camino::Utf8PathBuf> = layer_summaries
            .iter()
            .map(|l| camino::Utf8PathBuf::from(l.path.to_string_lossy().into_owned()))
            .collect();

        let config_path = image_dir.join("config.json");
        let config = match fs::read(&config_path).await {
            Ok(config_bytes) => serde_json::from_slice::<OciImageConfigContainer>(&config_bytes)
                .map(|c| c.into_image_config())
                .unwrap_or_default(),
            Err(_) => ImageConfig::default(),
        };

        Ok(ResolvedImage { layers, config })
    }
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

    #[test]
    fn layers_are_reordered_to_manifest_order() {
        use oci_client::client::ImageLayer;
        use oci_client::manifest::{OciDescriptor, OciImageManifest};

        let first = ImageLayer::oci_v1_gzip(b"first".to_vec(), None);
        let second = ImageLayer::oci_v1_gzip(b"second".to_vec(), None);
        let third = ImageLayer::oci_v1_gzip(b"third".to_vec(), None);
        let first_digest = first.sha256_digest();
        let second_digest = second.sha256_digest();
        let third_digest = third.sha256_digest();

        let mut manifest = OciImageManifest::default();
        manifest.layers = vec![
            OciDescriptor {
                digest: first_digest,
                size: first.data.len() as i64,
                media_type: first.media_type.clone(),
                ..OciDescriptor::default()
            },
            OciDescriptor {
                digest: second_digest,
                size: second.data.len() as i64,
                media_type: second.media_type.clone(),
                ..OciDescriptor::default()
            },
            OciDescriptor {
                digest: third_digest,
                size: third.data.len() as i64,
                media_type: third.media_type.clone(),
                ..OciDescriptor::default()
            },
        ];

        let reordered = layers_in_manifest_order(Some(&manifest), vec![third, first, second])
            .expect("layers should reorder");

        assert_eq!(reordered[0].data, b"first");
        assert_eq!(reordered[1].data, b"second");
        assert_eq!(reordered[2].data, b"third");
    }

    #[test]
    fn layer_summaries_are_reordered_to_manifest_order() {
        use oci_client::manifest::{OciDescriptor, OciImageManifest};

        let first = LayerSummary {
            digest: "sha256:first".to_string(),
            media_type: IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            size: 1,
            path: PathBuf::from("/layers/first"),
        };
        let second = LayerSummary {
            digest: "sha256:second".to_string(),
            media_type: IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            size: 1,
            path: PathBuf::from("/layers/second"),
        };
        let third = LayerSummary {
            digest: "sha256:third".to_string(),
            media_type: IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            size: 1,
            path: PathBuf::from("/layers/third"),
        };

        let mut manifest = OciImageManifest::default();
        manifest.layers = vec![
            OciDescriptor {
                digest: first.digest.clone(),
                size: first.size as i64,
                media_type: first.media_type.clone(),
                ..OciDescriptor::default()
            },
            OciDescriptor {
                digest: second.digest.clone(),
                size: second.size as i64,
                media_type: second.media_type.clone(),
                ..OciDescriptor::default()
            },
            OciDescriptor {
                digest: third.digest.clone(),
                size: third.size as i64,
                media_type: third.media_type.clone(),
                ..OciDescriptor::default()
            },
        ];

        let reordered = layer_summaries_in_manifest_order(&manifest, vec![third, first, second])
            .expect("summaries should reorder");

        assert_eq!(reordered[0].digest, "sha256:first");
        assert_eq!(reordered[1].digest, "sha256:second");
        assert_eq!(reordered[2].digest, "sha256:third");
    }

    #[test]
    fn test_parse_oci_config_json() {
        let raw_json = r#"{
            "config": {
                "User": "nobody",
                "ExposedPorts": {
                    "80/tcp": {},
                    "443/tcp": {}
                },
                "Env": [
                    "PATH=/usr/bin",
                    "MY_VAR=value"
                ],
                "Entrypoint": [
                    "/init"
                ],
                "Cmd": [
                    "--arg"
                ],
                "WorkingDir": "/opt/app",
                "Labels": {
                    "maintainer": "test@example.com"
                }
            }
        }"#;

        let oci_container: OciImageConfigContainer = serde_json::from_str(raw_json).unwrap();
        let config = oci_container.into_image_config();

        assert_eq!(config.user.as_deref(), Some("nobody"));
        assert_eq!(config.entrypoint, Some(vec!["/init".to_string()]));
        assert_eq!(config.cmd, Some(vec!["--arg".to_string()]));
        assert_eq!(config.working_dir.unwrap().as_str(), "/opt/app");
        assert!(config.exposed_ports.unwrap().contains("80/tcp"));
    }
}
