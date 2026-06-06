//! OCI image acquisition and on-disk content store for the carrick runtime.
//!
//! # Theory of operation
//!
//! Carrick runs unmodified Linux ELF binaries, and those binaries come from
//! ordinary OCI/Docker images. This crate is the *supply* side: it turns an
//! image reference (`ubuntu:24.04`, `ghcr.io/x/y@sha256:…`) into a set of
//! on-disk layer tarball paths plus the image's run configuration, which the
//! engine then lowers into a [`carrick_spec::RunSpec`]. It deliberately does
//! **not** unpack layers, build a rootfs, or know anything about the guest;
//! layer extraction and overlay composition happen later, in the runtime's VFS.
//!
//! ## The store: a content-addressed blob pool plus per-tag metadata
//!
//! Everything lives under one root (`$CARRICK_HOME`, else `~/.carrick`,
//! see [`ImageStore::default_for_user`]) in two distinct namespaces:
//!
//! * `blobs/sha256/<hex>` — every layer tarball, named by its digest. Because
//!   the name *is* the content hash, identical layers shared by many images are
//!   stored exactly once. [`ImageStore::blob_path`] is the only constructor of
//!   these paths and it *validates* the digest (must be `sha256:` + lowercase
//!   hex) before touching the filesystem — a guard against a malicious manifest
//!   smuggling `../` or an alternate algorithm into a path.
//! * `images/<registry>/<repo…>/<tag>/` — per-reference metadata: the OCI
//!   `config.json`, the `manifest.json`, and carrick's own `carrick-image.json`
//!   ([`PullSummary`]). The summary is the index that ties a reference to its
//!   ordered list of blob paths, sizes, and the image digest.
//!
//! The split is the load-bearing design choice. Metadata is cheap and
//! per-reference; blobs are large and shared. `carrick rmi` deletes only the
//! metadata directory (fast, always safe); blobs outlive it and are reclaimed
//! separately by [`ImageStore::gc_blobs`], which deletes any `blobs/` file not
//! in the union of all surviving summaries' layer digests (the private
//! `referenced_blobs` helper). `docker tag` ([`ImageStore::tag_image`])
//! is therefore just a metadata copy — no blob is ever duplicated.
//!
//! ## Layer order is an invariant, not an incidental
//!
//! An overlay filesystem is order-sensitive: a later layer's whiteouts and file
//! replacements must apply *on top of* earlier layers. The OCI `manifest.json`
//! `layers` array is the authoritative bottom-to-top order. The registry client
//! ([`oci_client`]), however, returns downloaded layers in completion/arbitrary
//! order, and the store deduplicates by digest — so neither the download order
//! nor the on-disk blob set preserves it. Both `layers_in_manifest_order` (on
//! pull) and `layer_summaries_in_manifest_order` (on resolve, re-derived from
//! the persisted `manifest.json`) re-sort against the manifest and treat any
//! mismatch — a manifest layer with no downloaded blob, or a downloaded blob no
//! manifest references — as a hard [`OciBootstrapError::InvalidDigest`] rather
//! than silently producing a wrong rootfs. Duplicate digests in a manifest are
//! handled by bucketing (a digest may legitimately appear twice), popping one
//! blob per manifest slot. **If you add a code path that materialises layer
//! paths, it must go through one of these; never iterate `summary.layers`
//! raw.**
//!
//! ## Platform keying: one store, two architectures
//!
//! Apple Silicon runs `linux/arm64` natively and `linux/amd64` via Rosetta 2.
//! Both can be cached side by side. [`PlatformTarget`] (parsed from
//! `--platform` or `$CARRICK_PULL_PLATFORM`) drives manifest selection in
//! [`select_manifest_digest`] (the matcher handed to the OCI client), and
//! [`ImageStore::image_dir_for`] keys the *metadata* directory per platform: the
//! host-native default keeps the legacy un-suffixed path (so pre-existing
//! stores still resolve), and any non-default platform lands in a
//! `__platform__<os>_<arch>` sibling so the two manifests never clobber each
//! other. Blobs remain shared across platforms because they are content
//! addressed; only the manifest/config/summary differ.
//!
//! ## Resolve is the read path; pull is the write path
//!
//! [`ImageStore::resolve`]/[`ImageStore::resolve_with_platform`] is what the
//! engine calls. It loads the cached summary, re-orders the layers against the
//! persisted manifest, and parses the OCI config — pulling on a cache miss as a
//! side effect, then returning a [`ResolvedImage`] (ordered layer paths + an
//! [`ImageConfig`]). The OCI config JSON is parsed *here* (the `Config` block —
//! entrypoint/cmd/env/user/workdir/exposed-ports/labels/stop-signal) and
//! flattened into the spec crate's [`ImageConfig`]; an absent or malformed
//! config degrades to [`ImageConfig::default`] rather than failing the run.
//!
//! ## Boundaries and limits
//!
//! * Registry credentials and the `carrick login`/`logout` store live in the
//!   [`auth`] submodule; see its own theory statement.
//! * This crate is `async` only where it must do network/large file I/O
//!   (`pull`/`resolve`/summary loads use `tokio::fs`); the store-management
//!   surface (`list`/`rmi`/`gc`/`tag`/`df`) is synchronous `std::fs`, because it
//!   is called from non-async CLI paths and only touches small metadata.
//! * The arm64-`v8` variant equivalence in [`PlatformTarget::matches`] is a
//!   pragmatic special case: registries spell the native Apple-Silicon arch as
//!   plain `arm64`, `arm64/v8`, or unspecified, and all three are treated as a
//!   match; `arm64/v7` is *not* (it is a different ISA level we cannot run).

use std::collections::HashMap;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use oci_client::Client;
use oci_client::client::{ClientConfig, ImageLayer};
use oci_client::manifest::{
    IMAGE_CONFIG_MEDIA_TYPE, IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE, ImageIndexEntry, OciDescriptor,
    OciImageManifest,
};
use oci_client::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};
use tokio::fs;

pub use carrick_spec::{ImageConfig, ImageReference, OciBootstrapError};

pub mod auth;

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

/// Verify a Basic credential against `registry` via the OCI auth handshake (for
/// `carrick login`). Lives here because the OCI `Client` builder is crate-private.
/// A 404 on the probe repo AFTER a successful auth still counts as success.
pub async fn verify_login(
    registry: &str,
    username: &str,
    password: &str,
) -> Result<(), OciBootstrapError> {
    let client = build_oci_client_for(&PlatformTarget::default_target());
    let probe = format!("{}/library/hello-world", registry.trim_end_matches('/'));
    let reference: oci_client::Reference = probe
        .parse()
        .map_err(|e| OciBootstrapError::Auth(format!("invalid registry {registry:?}: {e}")))?;
    let auth = RegistryAuth::Basic(username.to_string(), password.to_string());
    client
        .auth(&reference, &auth, oci_client::RegistryOperation::Pull)
        .await
        .map(|_| ())
        .map_err(|e| OciBootstrapError::Auth(format!("login to {registry} failed: {e}")))
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
    // Resolve per-registry credentials (carrick config, then ~/.docker), keyed on
    // the image's registry; Anonymous when none. Same store the CLI writes to.
    let auth = auth::resolve_auth(store.root(), image.registry())?;
    let mut data = client
        .pull(
            image.as_oci_reference(),
            &auth,
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

/// Reorder `items` to match the layer order in `manifest`, keyed by digest.
/// `digest_of` extracts each item's digest (owned, since `ImageLayer` computes
/// it on demand); `bucket_noun`/`extra_verb` thread the two call sites' distinct
/// error wording ("layer" vs "layer summary", "downloaded" vs "cached").
fn reorder_to_manifest_order<T>(
    manifest: &OciImageManifest,
    items: Vec<T>,
    digest_of: impl Fn(&T) -> String,
    bucket_noun: &str,
    extra_verb: &str,
) -> Result<Vec<T>, OciBootstrapError> {
    let mut by_digest: HashMap<String, Vec<T>> = HashMap::with_capacity(items.len());
    for item in items {
        by_digest.entry(digest_of(&item)).or_default().push(item);
    }

    let mut ordered = Vec::with_capacity(manifest.layers.len());
    for descriptor in &manifest.layers {
        let Some(mut bucket) = by_digest.remove(&descriptor.digest) else {
            return Err(OciBootstrapError::InvalidDigest(format!(
                "manifest referenced missing layer {}",
                descriptor.digest
            )));
        };
        let Some(item) = bucket.pop() else {
            return Err(OciBootstrapError::InvalidDigest(format!(
                "manifest {bucket_noun} bucket unexpectedly empty for {}",
                descriptor.digest
            )));
        };
        if !bucket.is_empty() {
            by_digest.insert(descriptor.digest.clone(), bucket);
        }
        ordered.push(item);
    }

    if let Some(extra) = by_digest.keys().next() {
        return Err(OciBootstrapError::InvalidDigest(format!(
            "{extra_verb} unreferenced layer {extra}"
        )));
    }

    Ok(ordered)
}

fn layers_in_manifest_order(
    manifest: Option<&OciImageManifest>,
    layers: Vec<ImageLayer>,
) -> Result<Vec<ImageLayer>, OciBootstrapError> {
    let Some(manifest) = manifest else {
        return Ok(layers);
    };
    reorder_to_manifest_order(
        manifest,
        layers,
        ImageLayer::sha256_digest,
        "layer",
        "downloaded",
    )
}

fn layer_summaries_in_manifest_order(
    manifest: &OciImageManifest,
    layers: Vec<LayerSummary>,
) -> Result<Vec<LayerSummary>, OciBootstrapError> {
    reorder_to_manifest_order(
        manifest,
        layers,
        |l| l.digest.clone(),
        "layer summary",
        "cached",
    )
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
    /// OCI `StopSignal` (e.g. `SIGQUIT`) — the signal `docker stop` sends.
    stop_signal: Option<String>,
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
                stop_signal: inner.stop_signal,
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

/// One stored image (one entry per pulled platform variant), for `carrick
/// images`. Sizes are summed layer bytes + config; `id` is the short manifest
/// digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub repository: String,
    pub tag: String,
    pub id: String,
    pub size: u64,
    pub created_secs: u64,
    pub image_dir: PathBuf,
}

/// Display form of an image's repository: strip the implicit `docker.io/library/`
/// prefix for the common case (docker shows `ubuntu`, not
/// `docker.io/library/ubuntu`); otherwise `registry/repository`.
fn display_repository(image: &ImageReference) -> String {
    let (reg, repo) = (image.registry(), image.repository());
    if reg == "docker.io" {
        repo.strip_prefix("library/").unwrap_or(repo).to_string()
    } else {
        format!("{reg}/{repo}")
    }
}

impl ImageStore {
    /// List every pulled image — one entry per stored `carrick-image.json`
    /// summary (so per platform). Unreadable/partial entries are skipped;
    /// sorted newest-first by the summary's mtime.
    pub fn list_images(&self) -> Vec<ImageInfo> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.join("images")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().and_then(|n| n.to_str()) == Some("carrick-image.json")
                    && let Some(info) = self.image_info_from_summary(&path)
                {
                    out.push(info);
                }
            }
        }
        out.sort_by_key(|o| std::cmp::Reverse(o.created_secs));
        out
    }

    fn image_info_from_summary(&self, summary_path: &Path) -> Option<ImageInfo> {
        let summary: PullSummary =
            serde_json::from_slice(&std::fs::read(summary_path).ok()?).ok()?;
        let image = ImageReference::parse(&summary.image).ok()?;
        let id = summary
            .digest
            .as_deref()
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(|h| h.get(..12).unwrap_or(h).to_string())
            .unwrap_or_else(|| "<none>".to_string());
        let size =
            summary.layers.iter().map(|l| l.size as u64).sum::<u64>() + summary.config_size as u64;
        let created_secs = std::fs::metadata(summary_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Some(ImageInfo {
            repository: display_repository(&image),
            tag: image.tag().unwrap_or("<none>").to_string(),
            id,
            size,
            created_secs,
            image_dir: summary_path.parent()?.to_path_buf(),
        })
    }

    /// The set of blob digests referenced by every stored image (the union of
    /// all summaries' layer digests). Drives [`ImageStore::gc_blobs`].
    fn referenced_blobs(&self) -> std::collections::HashSet<String> {
        let mut refs = std::collections::HashSet::new();
        for info in self.list_images() {
            let summary_path = info.image_dir.join("carrick-image.json");
            if let Ok(bytes) = std::fs::read(&summary_path)
                && let Ok(summary) = serde_json::from_slice::<PullSummary>(&bytes)
            {
                for layer in summary.layers {
                    refs.insert(layer.digest);
                }
            }
        }
        refs
    }

    /// Remove a pulled image: delete its metadata directory (all platform
    /// variants of the tag). Returns `true` if it existed. Blobs are left for
    /// [`ImageStore::gc_blobs`] (they may be shared).
    pub fn remove_image(&self, image: &ImageReference) -> std::io::Result<bool> {
        let dir = self.image_dir(image);
        if !dir.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(true)
    }

    /// Remove an image identified by a reference (`name:tag`) OR a short image
    /// id (the `IMAGE ID` from `carrick images`, full or prefix). Returns the
    /// removed image's display id/ref, or `None` if nothing matched.
    pub fn remove_image_by_spec(&self, spec: &str) -> std::io::Result<Option<String>> {
        // 1. As a reference.
        if let Ok(image) = ImageReference::parse(spec)
            && self.remove_image(&image)?
        {
            return Ok(Some(image.canonical()));
        }
        // 2. As an image id (prefix of the short manifest digest).
        let matches: Vec<ImageInfo> = self
            .list_images()
            .into_iter()
            .filter(|i| !spec.is_empty() && i.id.starts_with(spec))
            .collect();
        if matches.is_empty() {
            return Ok(None);
        }
        let id = matches[0].id.clone();
        for info in matches {
            std::fs::remove_dir_all(&info.image_dir)?;
        }
        Ok(Some(id))
    }

    /// Garbage-collect blobs no longer referenced by any stored image. Returns
    /// `(count, bytes)` removed.
    pub fn gc_blobs(&self) -> (usize, u64) {
        let referenced = self.referenced_blobs();
        let blobs_dir = self.root.join("blobs").join("sha256");
        let Ok(entries) = std::fs::read_dir(&blobs_dir) else {
            return (0, 0);
        };
        let (mut count, mut bytes) = (0usize, 0u64);
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(encoded) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if referenced.contains(&format!("sha256:{encoded}")) {
                continue;
            }
            let sz = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                count += 1;
                bytes += sz;
            }
        }
        (count, bytes)
    }

    /// Total bytes of all blobs on disk, and the bytes reclaimable by
    /// [`ImageStore::gc_blobs`] (blobs not referenced by any image). Drives
    /// `system df`.
    pub fn blob_disk_usage(&self) -> (u64, u64) {
        let referenced = self.referenced_blobs();
        let blobs_dir = self.root.join("blobs").join("sha256");
        let Ok(entries) = std::fs::read_dir(&blobs_dir) else {
            return (0, 0);
        };
        let (mut total, mut reclaimable) = (0u64, 0u64);
        for entry in entries.flatten() {
            let path = entry.path();
            let sz = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            total += sz;
            if let Some(enc) = path.file_name().and_then(|n| n.to_str())
                && !referenced.contains(&format!("sha256:{enc}"))
            {
                reclaimable += sz;
            }
        }
        (total, reclaimable)
    }

    /// Tag a stored image under a new reference (`docker tag`): copy the
    /// default-platform metadata to the new ref's directory, rewriting the
    /// summary. Blobs are content-addressed and shared, so nothing is copied.
    /// Errors if `src` is not in the store.
    pub fn tag_image(
        &self,
        src: &ImageReference,
        dst: &ImageReference,
    ) -> Result<(), OciBootstrapError> {
        let src_dir = self.image_dir(src);
        let summary_bytes = std::fs::read(src_dir.join("carrick-image.json"))?;
        let mut summary: PullSummary = serde_json::from_slice(&summary_bytes)?;
        let dst_dir = self.image_dir(dst);
        std::fs::create_dir_all(&dst_dir)?;
        // Copy the OCI metadata (config + manifest) when present.
        for name in ["config.json", "manifest.json"] {
            let from = src_dir.join(name);
            if from.exists() {
                std::fs::copy(&from, dst_dir.join(name))?;
            }
        }
        summary.image = dst.canonical();
        summary.image_dir = dst_dir.clone();
        std::fs::write(
            dst_dir.join("carrick-image.json"),
            serde_json::to_vec_pretty(&summary)?,
        )?;
        Ok(())
    }
}

/// One image entry from a docker-archive `manifest.json` (`docker save` /
/// kaniko `--tar-path`). `config` and `layers` are *entry paths inside the
/// tar*, attacker-influenced; they are matched against tar entry names but
/// never used as host paths.
#[derive(Debug, Clone, Deserialize)]
struct DockerArchiveManifestEntry {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

impl ImageStore {
    /// Ingest a docker-archive image tarball (`docker save` / kaniko
    /// `--tar-path`) into the store, returning one [`PullSummary`] per
    /// `RepoTag`. This is the read/ingest counterpart to
    /// [`pull_image_with_platform`]: it performs the exact same store writes —
    /// content-addressed layer blobs under `blobs/sha256/<hex>`, the OCI
    /// `config.json` / `manifest.json` and carrick's `carrick-image.json`
    /// summary into each tag's per-platform image dir — but sources the bytes
    /// from a local tar instead of a registry pull. Once written, `carrick run
    /// <tag>` resolves WITHOUT a network round-trip ([`Self::resolve`] reads
    /// `carrick-image.json` first). Used by `carrick load` and `carrick build
    /// --no-push` to ingest kaniko's output.
    ///
    /// Tags are written for the host-native default platform (the docker-archive
    /// format carries no platform descriptor; the bytes are whatever the
    /// producer built). v1 supports the first image entry of the archive; every
    /// `RepoTag` on that entry is tagged (blobs are shared, only the per-tag
    /// metadata dir differs).
    ///
    /// # Security
    ///
    /// The `Config`/`Layers` strings from the archive's `manifest.json` are
    /// attacker-influenced. They are used ONLY to match tar entry names (string
    /// equality) and never joined onto a host path. Every host write goes
    /// through [`Self::blob_path`] (which validates the *computed* digest is
    /// `sha256:`+hex) or a fixed file name inside the validated image dir.
    pub fn load_docker_archive(
        &self,
        tar_path: &Path,
    ) -> Result<Vec<PullSummary>, OciBootstrapError> {
        let target = PlatformTarget::default_target();

        // Pass 1: index every entry name -> bytes for the entries the manifest
        // names. A docker-archive is small relative to a registry pull and the
        // `tar` crate is single-pass forward-only, so we buffer what we need.
        // (We do not know which entries we need until we've parsed manifest.json,
        // and manifest.json may appear last — so buffer everything once.)
        let file = std::fs::File::open(tar_path)?;
        let mut archive = tar::Archive::new(file);
        let mut entries_by_name: HashMap<String, Vec<u8>> = HashMap::new();
        let archive_entries = archive
            .entries()
            .map_err(|e| OciBootstrapError::Archive(format!("reading tar entries: {e}")))?;
        for entry in archive_entries {
            let mut entry =
                entry.map_err(|e| OciBootstrapError::Archive(format!("reading tar entry: {e}")))?;
            // The entry path is only ever compared (string equality) to a
            // manifest-supplied name; it is never used as a host path.
            let name = match entry.path() {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => continue,
            };
            // Only buffer regular files; skip directory/symlink/hardlink entries
            // (a manifest blob is always a regular file).
            if entry.header().entry_type().is_dir() {
                continue;
            }
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf)
                .map_err(|e| OciBootstrapError::Archive(format!("reading entry {name:?}: {e}")))?;
            entries_by_name.insert(name, buf);
        }

        let manifest_bytes = entries_by_name.get("manifest.json").ok_or_else(|| {
            OciBootstrapError::Archive("archive has no manifest.json".to_string())
        })?;
        let archive_manifest: Vec<DockerArchiveManifestEntry> =
            serde_json::from_slice(manifest_bytes).map_err(|e| {
                OciBootstrapError::Archive(format!("parsing manifest.json: {e}"))
            })?;
        let image_entry = archive_manifest.first().ok_or_else(|| {
            OciBootstrapError::Archive("manifest.json has no image entries".to_string())
        })?;

        // Layer blobs: compute the content digest over the bytes (the archive
        // file names are NOT digests we trust — kaniko names them `<hex>.tar.gz`
        // where `<hex>` is the *uncompressed* diff id, not the blob digest), then
        // write each to its content-addressed blob path, mirroring the pull.
        std::fs::create_dir_all(self.root.join("blobs").join("sha256"))?;
        let mut layers = Vec::with_capacity(image_entry.layers.len());
        for layer_name in &image_entry.layers {
            let bytes = entries_by_name.get(layer_name).ok_or_else(|| {
                OciBootstrapError::Archive(format!(
                    "manifest referenced missing layer entry {layer_name:?}"
                ))
            })?;
            let digest = sha256_digest(bytes);
            let path = self.blob_path(&digest)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, bytes)?;
            layers.push(LayerSummary {
                media_type: layer_media_type(layer_name, bytes).to_string(),
                digest,
                size: bytes.len(),
                path,
            });
        }

        // Config blob: same content-addressing. The `Config` entry name may be
        // `sha256:<hex>` (kaniko) or `<hex>.json` (docker save); either way we
        // re-derive the digest from the bytes.
        let config_bytes = entries_by_name.get(&image_entry.config).ok_or_else(|| {
            OciBootstrapError::Archive(format!(
                "manifest referenced missing config entry {:?}",
                image_entry.config
            ))
        })?;
        let config_size = config_bytes.len();
        let config_digest = sha256_digest(config_bytes);

        // Build the OCI image manifest (schemaVersion 2) from the descriptors,
        // matching what the pull path persists, so `resolve` re-orders layers
        // against it identically.
        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: None,
            config: OciDescriptor {
                media_type: IMAGE_CONFIG_MEDIA_TYPE.to_string(),
                digest: config_digest,
                size: config_size as i64,
                ..OciDescriptor::default()
            },
            layers: layers
                .iter()
                .map(|l| OciDescriptor {
                    media_type: l.media_type.clone(),
                    digest: l.digest.clone(),
                    size: l.size as i64,
                    ..OciDescriptor::default()
                })
                .collect(),
            subject: None,
            artifact_type: None,
            annotations: None,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        // The image id is the digest of the manifest JSON bytes (matches the OCI
        // notion of an image's manifest digest and the pull path's `digest`).
        let image_id = sha256_digest(&manifest_bytes);

        // No RepoTags is unusual for `load`; docker errors. Treat it the same.
        if image_entry.repo_tags.is_empty() {
            return Err(OciBootstrapError::Archive(
                "image has no RepoTags to load".to_string(),
            ));
        }

        // Write the per-tag metadata. Blobs are shared (content-addressed); only
        // the image dir differs per tag, exactly like `tag_image`.
        let mut summaries = Vec::with_capacity(image_entry.repo_tags.len());
        for tag in &image_entry.repo_tags {
            let image = ImageReference::parse(tag)?;
            let image_dir = self.image_dir_for(&image, &target);
            std::fs::create_dir_all(&image_dir)?;
            std::fs::write(image_dir.join("config.json"), config_bytes)?;
            std::fs::write(image_dir.join("manifest.json"), &manifest_bytes)?;
            let summary = PullSummary {
                image: image.canonical(),
                digest: Some(image_id.clone()),
                image_dir,
                config_size,
                layers: layers.clone(),
            };
            std::fs::write(
                summary.image_dir.join("carrick-image.json"),
                serde_json::to_vec_pretty(&summary)?,
            )?;
            summaries.push(summary);
        }

        Ok(summaries)
    }
}

/// `sha256:<lowercase-hex>` over `bytes`, the digest form the store's blob
/// paths and OCI descriptors use.
fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

/// Pick the OCI layer media type for a docker-archive layer blob. The archive
/// carries no per-layer media type, so we infer gzip from the gzip magic bytes
/// (`1f 8b`) — falling back to the file extension — and otherwise treat it as a
/// plain tar.
fn layer_media_type(name: &str, bytes: &[u8]) -> &'static str {
    let gzip = bytes.starts_with(&[0x1f, 0x8b]) || name.ends_with(".gz") || name.ends_with(".tgz");
    if gzip {
        IMAGE_LAYER_GZIP_MEDIA_TYPE
    } else {
        IMAGE_LAYER_MEDIA_TYPE
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
    #[allow(clippy::field_reassign_with_default)]
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
    #[allow(clippy::field_reassign_with_default)]
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
                },
                "StopSignal": "SIGQUIT"
            }
        }"#;

        let oci_container: OciImageConfigContainer = serde_json::from_str(raw_json).unwrap();
        let config = oci_container.into_image_config();

        assert_eq!(config.user.as_deref(), Some("nobody"));
        assert_eq!(config.entrypoint, Some(vec!["/init".to_string()]));
        assert_eq!(config.cmd, Some(vec!["--arg".to_string()]));
        assert_eq!(config.working_dir.unwrap().as_str(), "/opt/app");
        assert!(config.exposed_ports.unwrap().contains("80/tcp"));
        // OCI `StopSignal` flows through to the resolved config so `carrick stop`
        // can honor the image's preferred stop signal.
        assert_eq!(config.stop_signal.as_deref(), Some("SIGQUIT"));
    }

    #[test]
    fn oci_config_without_stop_signal_is_none() {
        // Absent StopSignal must parse to None (additive field), not error.
        let raw_json = r#"{"config":{"Cmd":["sh"]}}"#;
        let config = serde_json::from_str::<OciImageConfigContainer>(raw_json)
            .unwrap()
            .into_image_config();
        assert!(config.stop_signal.is_none());
    }

    /// Lay down a fake stored image: a `carrick-image.json` summary plus a blob
    /// file of the given size for each layer.
    fn fake_image(store: &ImageStore, ref_str: &str, digest: &str, layers: &[(&str, usize)]) {
        let image = ImageReference::parse(ref_str).unwrap();
        let dir = store.image_dir(&image);
        std::fs::create_dir_all(&dir).unwrap();
        let layer_summaries: Vec<LayerSummary> = layers
            .iter()
            .map(|(d, sz)| {
                let path = store.blob_path(d).unwrap();
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, vec![0u8; *sz]).unwrap();
                LayerSummary {
                    digest: d.to_string(),
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                    size: *sz,
                    path,
                }
            })
            .collect();
        let summary = PullSummary {
            image: image.canonical(),
            digest: Some(digest.to_string()),
            image_dir: dir.clone(),
            config_size: 10,
            layers: layer_summaries,
        };
        std::fs::write(
            store.image_summary_path(&image),
            serde_json::to_vec(&summary).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn list_images_reports_repo_tag_id_and_size() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        fake_image(
            &store,
            "docker.io/library/ubuntu:24.04",
            "sha256:aabbccddeeff00112233",
            &[("sha256:11", 100), ("sha256:22", 200)],
        );
        let imgs = store.list_images();
        assert_eq!(imgs.len(), 1);
        assert_eq!(imgs[0].repository, "ubuntu"); // docker.io/library/ stripped
        assert_eq!(imgs[0].tag, "24.04");
        assert_eq!(imgs[0].id, "aabbccddeeff"); // 12-hex short digest
        assert_eq!(imgs[0].size, 100 + 200 + 10); // layers + config
    }

    #[test]
    fn remove_image_then_gc_reclaims_unreferenced_blobs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        // Two images sharing one blob (l_shared) and each with a private blob.
        fake_image(
            &store,
            "docker.io/library/a:1",
            "sha256:a",
            &[("sha256:5ed", 50), ("sha256:0a", 10)],
        );
        fake_image(
            &store,
            "docker.io/library/b:1",
            "sha256:b",
            &[("sha256:5ed", 50), ("sha256:0b", 20)],
        );
        assert_eq!(store.list_images().len(), 2);

        // Remove image a: its private blob `la` becomes unreferenced; `lshared`
        // is still held by b.
        let a = ImageReference::parse("docker.io/library/a:1").unwrap();
        assert!(store.remove_image(&a).unwrap());
        assert_eq!(store.list_images().len(), 1);
        let (count, _bytes) = store.gc_blobs();
        assert_eq!(count, 1, "only a's private blob should be collected");
        // lshared + lb remain (referenced by b); la is gone.
        assert!(store.blob_path("sha256:5ed").unwrap().exists());
        assert!(store.blob_path("sha256:0b").unwrap().exists());
        assert!(!store.blob_path("sha256:0a").unwrap().exists());
    }

    #[test]
    fn tag_image_creates_a_new_ref_sharing_blobs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        fake_image(
            &store,
            "docker.io/library/ubuntu:24.04",
            "sha256:abcdef012345",
            &[("sha256:1111", 100)],
        );
        let src = ImageReference::parse("docker.io/library/ubuntu:24.04").unwrap();
        let dst = ImageReference::parse("myubuntu:dev").unwrap();
        store.tag_image(&src, &dst).unwrap();
        // Both refs now list; the tag points at the same image id; blobs not duplicated.
        let imgs = store.list_images();
        assert_eq!(imgs.len(), 2);
        assert!(
            imgs.iter()
                .any(|i| i.repository == "myubuntu" && i.tag == "dev")
        );
        assert!(imgs.iter().all(|i| i.id == "abcdef012345"));
        let (count, _) = store.gc_blobs();
        assert_eq!(count, 0, "the shared blob is still referenced by both refs");
    }

    #[test]
    fn remove_image_by_spec_accepts_ref_or_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        fake_image(
            &store,
            "docker.io/library/ubuntu:24.04",
            "sha256:abcdef012345",
            &[("sha256:1111", 100)],
        );
        // By short image id (prefix of the 12-hex digest).
        assert_eq!(
            store.remove_image_by_spec("abcdef").unwrap().as_deref(),
            Some("abcdef012345")
        );
        assert!(store.list_images().is_empty());

        // By reference.
        fake_image(
            &store,
            "docker.io/library/alpine:3",
            "sha256:99887766",
            &[("sha256:2222", 50)],
        );
        assert_eq!(
            store.remove_image_by_spec("alpine:3").unwrap().as_deref(),
            Some("docker.io/library/alpine:3")
        );
        assert!(store.list_images().is_empty());

        // Unknown.
        assert_eq!(store.remove_image_by_spec("nope:latest").unwrap(), None);
    }

    /// gzip a single-file tar, the layer-blob shape a docker-archive carries.
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
        std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a minimal docker-archive tar in-process: `manifest.json`, a config
    /// blob entry, and one gzipped layer. `config_entry`/`layer_entry` are the
    /// entry *names* recorded in `manifest.json` (so we can exercise both the
    /// kaniko `sha256:<hex>` and `docker save` `<hex>.json` naming).
    fn docker_archive(
        repo_tags: &[&str],
        config_entry: &str,
        config_bytes: &[u8],
        layer_entry: &str,
        layer_bytes: &[u8],
    ) -> Vec<u8> {
        let manifest = serde_json::json!([{
            "Config": config_entry,
            "RepoTags": repo_tags,
            "Layers": [layer_entry],
        }]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, data) in [
                ("manifest.json", manifest_bytes.as_slice()),
                (config_entry, config_bytes),
                (layer_entry, layer_bytes),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, data).unwrap();
            }
            builder.finish().unwrap();
        }
        tar_bytes
    }

    #[test]
    fn load_docker_archive_ingests_blobs_and_summary() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());

        let layer = gzip_layer("hello.txt", b"hello from the layer");
        let config = br#"{"architecture":"arm64","os":"linux","config":{"Cmd":["/bin/sh"]}}"#;
        // kaniko-style naming: Config is `sha256:<hex>`, layer is `<hex>.tar.gz`.
        let layer_hex = "3f26bc2dec0b515f1c2818f6e13a8f1da1f88179a008445d4e587233386bff78";
        let archive = docker_archive(
            &["trivial:latest"],
            "sha256:1e30add214cb8e39df246287c1ab81d6b8fcb7ba210822086c04078df9d1144a",
            config,
            &format!("{layer_hex}.tar.gz"),
            &layer,
        );
        let tar_path = tmp.path().join("out.tar");
        std::fs::write(&tar_path, &archive).unwrap();

        let summaries = store.load_docker_archive(&tar_path).unwrap();
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.image, "docker.io/library/trivial:latest");
        assert_eq!(summary.config_size, config.len());
        assert_eq!(summary.layers.len(), 1);

        // The layer blob is content-addressed: its digest is the sha256 of the
        // gzip bytes, and it lives at blob_path(digest).
        let expected_digest = sha256_digest(&layer);
        assert_eq!(summary.layers[0].digest, expected_digest);
        assert_eq!(
            summary.layers[0].media_type,
            IMAGE_LAYER_GZIP_MEDIA_TYPE,
            "gzip magic bytes => gzip media type"
        );
        let blob_path = store.blob_path(&expected_digest).unwrap();
        assert!(blob_path.exists(), "layer blob written to blob_path");
        assert_eq!(std::fs::read(&blob_path).unwrap(), layer);

        // The image id is the sha256 of the persisted manifest bytes.
        assert!(
            summary
                .digest
                .as_deref()
                .is_some_and(|d| d.starts_with("sha256:"))
        );

        // carrick-image.json parses back to the same summary; config.json and
        // manifest.json sit beside it.
        let image = ImageReference::parse("trivial:latest").unwrap();
        let summary_path = store.image_summary_path(&image);
        assert!(summary_path.exists());
        let reloaded: PullSummary =
            serde_json::from_slice(&std::fs::read(&summary_path).unwrap()).unwrap();
        assert_eq!(&reloaded, summary);
        let image_dir = store.image_dir(&image);
        assert_eq!(std::fs::read(image_dir.join("config.json")).unwrap(), config);
        assert!(image_dir.join("manifest.json").exists());

        // The store now resolves the tag with no further work, and the layer
        // ordering re-derived from manifest.json matches.
        assert_eq!(store.list_images().len(), 1);
    }

    #[test]
    fn load_docker_archive_tags_every_repo_tag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());

        let layer = gzip_layer("f", b"x");
        let config = br#"{"config":{}}"#;
        // docker-save-style config naming: `<hex>.json`.
        let archive = docker_archive(
            &["myapp:latest", "myapp:1.0"],
            "abc123.json",
            config,
            "abc123/layer.tar.gz",
            &layer,
        );
        let tar_path = tmp.path().join("save.tar");
        std::fs::write(&tar_path, &archive).unwrap();

        let summaries = store.load_docker_archive(&tar_path).unwrap();
        assert_eq!(summaries.len(), 2);
        // Both tags share the same image id (one set of content-addressed blobs).
        assert_eq!(summaries[0].digest, summaries[1].digest);
        let imgs = store.list_images();
        assert_eq!(imgs.len(), 2);
        assert!(imgs.iter().any(|i| i.tag == "latest"));
        assert!(imgs.iter().any(|i| i.tag == "1.0"));
        // The shared layer blob is referenced by both tags, so GC keeps it.
        let (count, _) = store.gc_blobs();
        assert_eq!(count, 0);
    }

    #[test]
    fn load_docker_archive_plain_tar_layer_gets_tar_media_type() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());

        // A plain (un-gzipped) tar layer — no gzip magic, no `.gz` suffix.
        let mut plain_tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut plain_tar);
            let mut header = tar::Header::new_gnu();
            let contents = b"plain";
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "f", &contents[..]).unwrap();
            builder.finish().unwrap();
        }
        let archive = docker_archive(
            &["plain:latest"],
            "cfg.json",
            br#"{"config":{}}"#,
            "layer.tar",
            &plain_tar,
        );
        let tar_path = tmp.path().join("plain.tar");
        std::fs::write(&tar_path, &archive).unwrap();

        let summaries = store.load_docker_archive(&tar_path).unwrap();
        assert_eq!(summaries[0].layers[0].media_type, IMAGE_LAYER_MEDIA_TYPE);
    }

    #[test]
    fn load_docker_archive_missing_manifest_is_an_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        // A tar with no manifest.json.
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "junk", &b"abc"[..]).unwrap();
            builder.finish().unwrap();
        }
        let tar_path = tmp.path().join("bad.tar");
        std::fs::write(&tar_path, &bytes).unwrap();
        let err = store.load_docker_archive(&tar_path).unwrap_err();
        assert!(matches!(err, OciBootstrapError::Archive(_)), "got {err:?}");
    }

    /// Real fixture: a kaniko-built docker-archive at the spike path, if present.
    /// Guarded on existence so CI (where it is absent) skips it.
    #[test]
    fn load_real_kaniko_archive_if_present() {
        let path = Path::new("/tmp/carrick-kaniko-spike/out.tar");
        if !path.exists() {
            return;
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let store = ImageStore::new(tmp.path());
        let summaries = store.load_docker_archive(path).unwrap();
        // RepoTags `trivial:latest`, 3 gz layers.
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.image, "docker.io/library/trivial:latest");
        assert_eq!(summary.layers.len(), 3, "kaniko built 3 layers");
        for layer in &summary.layers {
            assert!(store.blob_path(&layer.digest).unwrap().exists());
        }
        assert!(summary.config_size > 0);
        assert!(summary.digest.as_deref().is_some_and(|d| d.starts_with("sha256:")));
    }
}
