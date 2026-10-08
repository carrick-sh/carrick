//! Native Linux oracle envelope and fail-closed probe provenance.
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
pub const INIT_POLICY: &str = "chroot-shell-pid1-v1";

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
struct NativeStartTicks(u64);

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
struct NativeInitIdentity {
    pid: carrick_kernel_arena::domains::HostPid,
    start: NativeStartTicks,
}

impl NativeInitIdentity {
    fn from_stat(stat: &str) -> anyhow::Result<Self> {
        let (pid, _) = stat
            .split_once(' ')
            .ok_or_else(|| anyhow::anyhow!("init stat missing pid"))?;
        let (_, fields) = stat
            .rsplit_once(')')
            .ok_or_else(|| anyhow::anyhow!("init stat missing comm"))?;
        let fields: Vec<_> = fields.split_whitespace().collect();
        let pid: u32 = pid.parse()?;
        anyhow::ensure!(pid > 1, "native init must belong to a child namespace");
        let start = fields
            .get(19)
            .ok_or_else(|| anyhow::anyhow!("init stat missing start time"))?
            .parse()?;
        Ok(Self {
            pid: carrick_kernel_arena::domains::HostPid::new(pid),
            start: NativeStartTicks(start),
        })
    }
}

/// Kill only namespace init. Unshare and sudo stay alive to reap it, and the
/// harness then reaps its direct child. A group kill creates orphaned zombies.
pub(crate) fn kill_init(record: &Path) -> anyhow::Result<()> {
    let recorded = NativeInitIdentity::from_stat(&std::fs::read_to_string(record)?)?;
    let current = match std::fs::read_to_string(format!("/proc/{}/stat", recorded.pid.raw())) {
        Ok(stat) => NativeInitIdentity::from_stat(&stat)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        recorded == current,
        "refusing to signal a recycled native init pid"
    );
    let status = Command::new("sudo")
        .args(["-n", "kill", "-KILL", "--", &recorded.pid.raw().to_string()])
        .status()?;
    anyhow::ensure!(status.success(), "native namespace init cleanup failed");
    Ok(())
}

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

#[derive(::core::clone::Clone, ::core::fmt::Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct ProbeProvenance {
    pub oracle_backend: String,
    pub kernel: String,
    pub distro: String,
    pub unshare_flags: Vec<String>,
    pub source_hash_scheme: String,
    pub rootfs_extractor: String,
    pub rootfs_flags: Vec<String>,
    pub init_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_init_inputs: Option<std::collections::BTreeMap<String, String>>,
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
            init_policy: INIT_POLICY.into(),
            static_init_inputs: None,
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
        || provenance.init_policy != INIT_POLICY
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
        &::std::fs::read(dir.join("PROVENANCE.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    validate_probe_provenance(&provenance, &kernel_release().map_err(|e| e.to_string())?)?;
    if let Some(inputs) = &provenance.static_init_inputs {
        let current = static_init_inputs().map_err(|e| e.to_string())?;
        if inputs != &current {
            return Err(
                "native static init inputs changed; re-bless the entire oracle directory".into(),
            );
        }
    }
    Ok(())
}

/// JSON emitted by `carrick rootfs export`. The lower is immutable; every
/// execution gets a private writable copy before namespace admission.
#[derive(
    ::core::clone::Clone,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::serde::Serialize,
    ::serde::Deserialize,
)]
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
/// and device envelope. The tested ELF remains static; only its init shell
/// uses a loader. No guest runtime or Docker client is involved.
pub fn run_probe(probe: &Path) -> anyhow::Result<String> {
    let inputs = static_init_inputs()?;
    let (_root, lower) = static_probe_root(&inputs)?;
    run_probe_in_root(probe, &lower)
}

/// The static ELF needs no guest libc; the waiting PID-1 shell still needs its
/// own loader closure. These host inputs are fingerprinted in probe provenance.
pub fn static_init_inputs() -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let out = Command::new("ldd").arg("/bin/sh").output()?;
    anyhow::ensure!(
        out.status.success(),
        "cannot resolve native init shell loader closure"
    );
    let text = String::from_utf8(out.stdout)?;
    anyhow::ensure!(
        !text.contains("not found"),
        "native init loader library missing"
    );
    let mut paths = std::collections::BTreeSet::from(["/bin/sh".to_string()]);
    for line in text.lines() {
        if let Some(path) = line.split_whitespace().find(|part| part.starts_with('/')) {
            paths.insert(path.into());
        }
    }
    paths
        .into_iter()
        .map(|path| {
            let hash = crate::shard::hash(&::std::fs::read(&path)?);
            Ok((path, hash))
        })
        .collect()
}

pub fn static_probe_root(
    inputs: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<(tempfile::TempDir, NativeRootfs)> {
    let root = tempfile::tempdir()?;
    for (source, expected_hash) in inputs {
        let relative = source
            .strip_prefix('/')
            .ok_or_else(|| anyhow::anyhow!("init path must be absolute"))?;
        let destination = root.path().join(relative);
        std::fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("init path missing parent"))?,
        )?;
        std::fs::copy(source, &destination)?;
        let copied_bytes = ::std::fs::read(destination)?;
        anyhow::ensure!(
            crate::shard::hash(&copied_bytes) == *expected_hash,
            "native init input changed while copying"
        );
    }
    let lower = NativeRootfs {
        root: root.path().into(),
        ..Default::default()
    };
    Ok((root, lower))
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
    let bytes = ::std::fs::read(probe)?;
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
        let bytes = ::std::fs::read(repo.join("conformance-probes").join(&relative))?;
        hash.update(relative.as_bytes());
        hash.update([0]);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_identity_binds_pid_and_start_ticks() -> anyhow::Result<()> {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "12345";
        let original =
            NativeInitIdentity::from_stat(&format!("42 (init with spaces) {}", fields.join(" ")))?;
        assert_eq!(original.pid.raw(), 42);
        fields[19] = "12346";
        let reused =
            NativeInitIdentity::from_stat(&format!("42 (different init) {}", fields.join(" ")))?;
        assert_ne!(original, reused);
        assert!(
            NativeInitIdentity::from_stat(&format!("1 (host init) {}", fields.join(" "))).is_err()
        );
        assert!(NativeInitIdentity::from_stat("42 (truncated) S").is_err());
        Ok(())
    }
}
