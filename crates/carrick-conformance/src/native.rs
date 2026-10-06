//! Native Linux oracle envelope and fail-closed probe provenance.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const BACKEND_ID: &str = "native-unshare-v1";
pub const UNSHARE_FLAGS: &[&str] = &[
    "--mount",
    "--pid",
    "--fork",
    "--uts",
    "--ipc",
    "--mount-proc",
    "--kill-child=KILL",
];
pub const SOURCE_HASH_SCHEME: &str = "sha256-bin-lib-cargo-manifest-lock-v1";

pub fn kernel_release() -> anyhow::Result<String> {
    anyhow::ensure!(cfg!(target_os = "linux"), "native oracle requires Linux");
    Ok(std::fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string())
}

pub fn kernel_major_minor(release: &str) -> anyhow::Result<String> {
    let mut parts = release.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    anyhow::ensure!(
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor.bytes().all(|b| b.is_ascii_digit()),
        "invalid kernel release {release:?}"
    );
    Ok(format!("{major}.{minor}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeProvenance {
    pub oracle_backend: String,
    pub kernel: String,
    pub distro: String,
    pub unshare_flags: Vec<String>,
    pub source_hash_scheme: String,
    pub rootfs_extractor: String,
    pub rootfs_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
}

impl ProbeProvenance {
    pub fn new(kernel: String, distro: String) -> Self {
        Self {
            oracle_backend: BACKEND_ID.into(),
            kernel,
            distro,
            unshare_flags: UNSHARE_FLAGS.iter().map(|s| (*s).into()).collect(),
            source_hash_scheme: SOURCE_HASH_SCHEME.into(),
            rootfs_extractor: carrick_spec::OCI_NATIVE_EXTRACTOR_ID.into(),
            rootfs_flags: carrick_spec::OCI_NATIVE_EXTRACTOR_FLAGS
                .iter()
                .map(|flag| (*flag).into())
                .collect(),
            image_digest: None,
        }
    }
    pub fn current() -> anyhow::Result<Self> {
        Ok(Self::new(
            kernel_release()?,
            std::fs::read_to_string("/etc/os-release")?,
        ))
    }
}

pub fn validate_probe_provenance(provenance: &ProbeProvenance, kernel: &str) -> Result<(), String> {
    if provenance.kernel != kernel
        || provenance.oracle_backend != BACKEND_ID
        || provenance.source_hash_scheme != SOURCE_HASH_SCHEME
        || provenance.unshare_flags != UNSHARE_FLAGS
        || provenance.rootfs_extractor != carrick_spec::OCI_NATIVE_EXTRACTOR_ID
        || provenance.rootfs_flags != carrick_spec::OCI_NATIVE_EXTRACTOR_FLAGS
    {
        return Err(format!(
            "native probe oracle provenance mismatch: recorded kernel {:?}, host {:?}; re-bless on this native host",
            provenance.kernel, kernel
        ));
    }
    Ok(())
}

pub fn validate_probe_oracle_dir(dir: &Path) -> Result<(), String> {
    let provenance: ProbeProvenance = serde_json::from_slice(
        &std::fs::read(dir.join("PROVENANCE.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    validate_probe_provenance(&provenance, &kernel_release().map_err(|e| e.to_string())?)
}

/// JSON emitted by `carrick rootfs export`. The lower is immutable; every
/// execution gets a private writable copy before namespace admission.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeRootfs {
    pub root: PathBuf,
    pub image_digest: String,
    #[serde(default)]
    pub extractor: String,
    #[serde(default)]
    pub extractor_flags: Vec<String>,
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub workdir: Option<String>,
    #[serde(skip)]
    pub probe_binary: Option<PathBuf>,
}

pub fn export_image(carrick: &Path, image: &str) -> anyhow::Result<NativeRootfs> {
    let out = Command::new(carrick)
        .args(["rootfs", "export", image, "--platform", "linux/amd64"])
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "rootfs export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rootfs: NativeRootfs = serde_json::from_slice(&out.stdout)?;
    anyhow::ensure!(
        rootfs.image_digest.starts_with("sha256:")
            && rootfs.root.is_dir()
            && rootfs.extractor == carrick_spec::OCI_NATIVE_EXTRACTOR_ID
            && rootfs.extractor_flags == carrick_spec::OCI_NATIVE_EXTRACTOR_FLAGS,
        "rootfs export missing image identity or root"
    );
    Ok(rootfs)
}

/// Identical static ELF, in a fresh chroot with the suite oracle's namespace
/// and device envelope. No guest runtime, Docker client, or dynamic loader.
pub fn run_probe(probe: &Path) -> anyhow::Result<String> {
    let root = tempfile::tempdir()?;
    let lower = NativeRootfs {
        root: root.path().into(),
        ..Default::default()
    };
    run_probe_in_root(probe, &lower)
}

/// GNU helpers use an OCI rootfs loader, never the host's accidental libc.
pub fn run_probe_in_root(probe: &Path, lower: &NativeRootfs) -> anyhow::Result<String> {
    anyhow::ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "native probe bless requires x86_64 Linux"
    );
    let status = std::fs::read_to_string("/proc/self/status")?;
    anyhow::ensure!(
        status.lines().any(|line| line == "Seccomp:\t0"),
        "native probe requires a seccomp-unconfined process"
    );
    let bytes = std::fs::read(probe)?;
    anyhow::ensure!(
        bytes.starts_with(b"\x7fELF") && bytes.get(18..20) == Some(&[62, 0]),
        "probe must be an x86_64 ELF"
    );
    let manifest = crate::manifest::Manifest::from_toml(
        r#"
        [[suite]]
        name = "static-probe"
        ecosystem = "go"
        image = "static-probe"
        cmd = ["/tmp/p"]
        verdict = "shell"
        tier = "smoke"
        weight = "light"
        timeout_s = 45
        workdir = "/"
        [suite.entrypoint]
        both = ""
    "#,
    )?;
    let suite = manifest
        .suite
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing probe declaration"))?;
    let rootfs = NativeRootfs {
        probe_binary: Some(probe.into()),
        ..lower.clone()
    };
    let run_id = format!(
        "native-probe-{}-{}",
        std::process::id(),
        probe.file_name().unwrap_or_default().to_string_lossy()
    );
    let out = crate::engine::run_native(suite, &run_id, &rootfs)?;
    anyhow::ensure!(
        !out.timed_out && out.exit_code == 0,
        "native probe failed (exit {}, timeout {}): {}",
        out.exit_code,
        out.timed_out,
        out.raw().stderr
    );
    let raw = out.raw();
    Ok(format!("{}{}", raw.stdout, raw.stderr))
}

/// Native cache freshness includes shared probe helpers and dependency inputs.
/// Historical Docker entries keep their original source-only scheme.
pub fn probe_source_hash(repo: &Path, name: &str) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    for relative in [
        format!("src/bin/{name}.rs"),
        "src/lib.rs".into(),
        "Cargo.toml".into(),
        "Cargo.lock".into(),
    ] {
        let bytes = std::fs::read(repo.join("conformance-probes").join(&relative))?;
        hash.update(relative.as_bytes());
        hash.update([0]);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}
