//! Immutable, exact-commit guest artifacts. No guest execution or Docker.
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use thiserror::Error;

use crate::{command, probe_inventory, provision};

pub mod archive;
pub mod build_code;
pub mod dep_info;
mod environment;
mod inputs;
pub mod linker;
use environment::BuildEnvironment;
pub use environment::BuildPolicy;
pub use inputs::{current_build_code, source_hashes};

const SCHEMA: &str = "carrick.fixtures.v3";
pub const INSTALLED_MANIFEST: &str = "target/fixtures/installed.json";
/// Shell builders run by the publisher; their bytes are fixture inputs.
const BUILD_SCRIPTS: &[&str] = &[
    "scripts/build-linux-fixtures.sh",
    "scripts/build-embed-interceptor-probe.sh",
    "scripts/build-embed-zone-readers.sh",
    "scripts/build-embed-icache-reuse.sh",
    "scripts/build-embed-copyout.sh",
    "scripts/build-embed-el1-sched.sh",
];
const EMBED: &[(&str, &str)] = &[
    ("embed-interceptor-probe", "interceptor-probe"),
    ("embed-zone-readers", "zone-readers"),
    ("embed-icache-reuse", "icache-reuse"),
    ("embed-copyout", "copyout"),
    ("embed-el1-sched", "el1-sched"),
];

#[derive(clap::Args, Debug)]
pub struct FixturesArgs {
    #[command(subcommand)]
    pub action: FixturesAction,
}

#[derive(Subcommand, Debug)]
pub enum FixturesAction {
    /// Build and publish a mode-preserving bundle artifact for Actions.
    Publish {
        #[arg(long)]
        sha: String,
    },
    /// Build in a fresh exact-SHA snapshot on Linux (native ARM or cross).
    Build {
        #[arg(long)]
        sha: String,
        #[arg(long, help = "Bundle store (default: target/fixtures/bundles)")]
        output: Option<PathBuf>,
    },
    /// Validate the entire bundle before installing any executable.
    Restore {
        #[arg(long, required_unless_present = "bundle", conflicts_with = "bundle")]
        manifest: Option<PathBuf>,
        #[arg(
            long,
            required_unless_present = "manifest",
            conflicts_with = "manifest"
        )]
        bundle: Option<PathBuf>,
        #[arg(long, help = "Expected commit (default: checkout HEAD)")]
        sha: Option<String>,
    },
    /// Capture, verify and restore a bundle with durable remote-run provenance.
    Prepare {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        run_dir: PathBuf,
        #[arg(long, value_enum)]
        source: crate::remote_accept::FixtureBundleSource,
    },
    /// Print the build scripts and proc-macros in the fixture graphs in the
    /// reviewed-list format, for review before updating the committed list.
    BuildCode,
    /// Check a bundle or, by default, every installed signed-tier fixture.
    Verify {
        #[arg(long, conflicts_with = "bundle")]
        manifest: Option<PathBuf>,
        #[arg(long, conflicts_with = "manifest")]
        bundle: Option<PathBuf>,
        #[arg(long, help = "Expected commit (default: checkout HEAD)")]
        sha: Option<String>,
        #[arg(
            long,
            help = "Write fresh input-identity verification evidence as JSON"
        )]
        receipt: Option<PathBuf>,
    },
}

#[derive(Debug, Error)]
pub enum FixturesError {
    #[error("fixture validation failed: {0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Inventory(#[from] probe_inventory::InventoryError),
    #[error("fixture restore gate admission: {0}")]
    HostLease(#[from] crate::host_lease::HostLeaseError),
}

type Result<T> = std::result::Result<T, FixturesError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitSha(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentHash(String);

/// Git tree object naming the checkout's working state (tracked and
/// untracked, gitignored outputs excluded) when evidence was produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitTreeId(String);

fn hex_identity(value: &str, len: usize) -> Result<()> {
    if value.len() != len
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FixturesError::Invalid(format!(
            "invalid {len}-digit identity: {value}"
        )));
    }
    Ok(())
}

impl TryFrom<String> for CommitSha {
    type Error = FixturesError;
    fn try_from(value: String) -> Result<Self> {
        hex_identity(&value, 40)?;
        Ok(Self(value))
    }
}
impl From<CommitSha> for String {
    fn from(value: CommitSha) -> Self {
        value.0
    }
}
impl TryFrom<String> for ContentHash {
    type Error = FixturesError;
    fn try_from(value: String) -> Result<Self> {
        hex_identity(&value, 64)?;
        Ok(Self(value))
    }
}
impl From<ContentHash> for String {
    fn from(value: ContentHash) -> Self {
        value.0
    }
}
impl TryFrom<String> for GitTreeId {
    type Error = FixturesError;
    fn try_from(value: String) -> Result<Self> {
        hex_identity(&value, 40)?;
        Ok(Self(value))
    }
}
impl From<GitTreeId> for String {
    fn from(value: GitTreeId) -> Self {
        value.0
    }
}
impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestTarget {
    #[serde(rename = "aarch64-unknown-linux-musl")]
    Musl,
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    Gnu,
}
impl GuestTarget {
    fn triple(self) -> &'static str {
        match self {
            Self::Musl => "aarch64-unknown-linux-musl",
            Self::Gnu => "aarch64-unknown-linux-gnu",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    pub path: String,
    pub target: GuestTarget,
    pub sha256: ContentHash,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub rustc: String,
    pub cargo: String,
    pub gnu_linker: String,
}
/// A bundle is admitted by its fixture input identity, never by commit:
/// `source_head` is the publisher's provenance, not an admission key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub source_head: CommitSha,
    /// Checkout files the compiler reported reading (dep-info) when the
    /// publisher built these executables, sorted. Admission hashes them in
    /// addition to the Cargo-graph closure.
    pub compiler_inputs: Vec<String>,
    pub sources: BTreeMap<String, ContentHash>,
    pub build_policy: BuildPolicy,
    pub toolchain: Toolchain,
    pub executables: Vec<Executable>,
}

impl Manifest {
    /// SHA-256 over the scoped source inventory, recorded compiler inputs and
    /// build policy. The compiler pin is a source input; the toolchain record
    /// is checked against it. Canonical JSON frames every path and digest
    /// (quoted, escaped strings), so entries cannot run together.
    pub fn input_identity(&self) -> Result<ContentHash> {
        input_identity(&self.sources, &self.compiler_inputs, &self.build_policy)
    }
}

fn input_identity(
    sources: &BTreeMap<String, ContentHash>,
    compiler_inputs: &[String],
    policy: &BuildPolicy,
) -> Result<ContentHash> {
    Ok(hash_bytes(&serde_json::to_vec(&(
        sources,
        compiler_inputs,
        policy,
    ))?))
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    validation: ValidationReceipt,
    manifest_sha256: ContentHash,
    manifest: Manifest,
}

/// Fixture evidence is scoped to input bytes, never a claim of full-tree equality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReceipt {
    pub validation_method: ValidationMethod,
    pub checkout_head: CommitSha,
    pub checkout_tree: GitTreeId,
    pub bundle_source_head: CommitSha,
    pub checkout_dirty: bool,
    pub manifest_sha256: ContentHash,
    /// Fixture input identity shared by the bundle and this checkout.
    pub inputs_sha256: ContentHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMethod {
    InputIdentity,
}

fn validation_receipt(root: &Path, manifest: &Manifest) -> Result<ValidationReceipt> {
    Ok(ValidationReceipt {
        validation_method: ValidationMethod::InputIdentity,
        checkout_head: expected_head(root, None)?,
        checkout_tree: working_tree(root)?,
        bundle_source_head: manifest.source_head.clone(),
        checkout_dirty: !git(root, &["status", "--porcelain", "--untracked-files=all"])?
            .trim()
            .is_empty(),
        manifest_sha256: hash_bytes(&manifest_bytes(manifest)?),
        inputs_sha256: manifest.input_identity()?,
    })
}

/// Name the exact working state without touching the real index: stage the
/// worktree into a private copy of the index and write its tree object.
fn working_tree(root: &Path) -> Result<GitTreeId> {
    let index = PathBuf::from(
        git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", "index"],
        )?
        .trim(),
    );
    let scratch = tempfile::tempdir()?;
    let private = scratch.path().join("index");
    if index.is_file() {
        // The copy keeps Git's stat cache, so only changed files are rehashed.
        fs::copy(&index, &private)?;
    }
    let run = |args: &[&str]| -> Result<String> {
        let output = Command::new("git")
            .current_dir(root)
            .env("GIT_INDEX_FILE", &private)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(fail(format!(
                "working tree identity: git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        String::from_utf8(output.stdout).map_err(|e| fail(e.to_string()))
    };
    run(&["add", "--all", "--", "."])?;
    GitTreeId::try_from(run(&["write-tree"])?.trim().to_owned())
}

/// Revalidate all installed bytes before generating evidence for this invocation.
pub fn verify_installed_receipt(root: &Path) -> Result<ValidationReceipt> {
    validation_receipt(root, &verify_installed(root)?)
}

fn hash_bytes(bytes: &[u8]) -> ContentHash {
    ContentHash(format!("{:x}", Sha256::digest(bytes)))
}
fn hash_file(path: &Path) -> Result<ContentHash> {
    Ok(ContentHash(provision::compute_sha256(path)?))
}

/// Domain of a source entry digest: the entry's type and its length-prefixed
/// bytes. Only regular files are source inputs.
const SOURCE_DOMAIN: &[u8] = b"carrick.fixtures.source.v1\0regular\0";

/// Hash one source input as a typed, length-framed regular file. A symlink
/// is refused rather than hashed: its link text could equal a regular file's
/// bytes, and its referent could be anything.
pub fn hash_source(root: &Path, relative: &str) -> Result<ContentHash> {
    let relative_path = Path::new(relative);
    let parent = match relative_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => safe_path(root, &parent.to_string_lossy())?,
        None => root.to_path_buf(),
    };
    let name = relative_path
        .file_name()
        .ok_or_else(|| fail("empty source path"))?;
    hash_regular_file(&parent.join(name))
}

/// The typed, length-framed digest of one regular file; links are refused.
fn hash_regular_file(path: &Path) -> Result<ContentHash> {
    let file_type = fs::symlink_metadata(path)?.file_type();
    if !file_type.is_file() {
        return Err(fail(format!(
            "fixture source input is not a regular file (symlinks are refused): {}",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    let length = u64::try_from(bytes.len()).map_err(|e| fail(e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(SOURCE_DOMAIN);
    digest.update(length.to_be_bytes());
    digest.update(&bytes);
    Ok(ContentHash(format!("{:x}", digest.finalize())))
}
fn fail(message: impl Into<String>) -> FixturesError {
    FixturesError::Invalid(message.into())
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(fail(format!("unsafe fixture path: {relative}")));
        };
        path.push(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(fail(format!("symlink fixture path: {}", path.display())));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if path == root {
        return Err(fail("empty fixture path"));
    }
    Ok(path)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    Ok(command::run_checked("git", args, Some(root))?.stdout)
}
pub(crate) fn expected_head(root: &Path, sha: Option<&str>) -> Result<CommitSha> {
    let head = CommitSha::try_from(git(root, &["rev-parse", "HEAD"])?.trim().to_owned())?;
    if let Some(sha) = sha {
        let requested = CommitSha::try_from(sha.to_owned())?;
        if requested != head {
            return Err(fail(format!(
                "wrong SHA: expected {}, checkout is {}",
                requested.0, head.0
            )));
        }
    }
    Ok(head)
}

fn probe_names(root: &Path) -> Result<Vec<String>> {
    let inventory =
        probe_inventory::load_inventory(&root.join("conformance-probes/probe-inventory.json"))?;
    probe_inventory::validate_source_membership(
        &inventory.keys().cloned().collect(),
        &probe_inventory::read_probe_source_names(&root.join("conformance-probes/src/bin"))?,
    )?;
    let names: Vec<_> = inventory
        .into_iter()
        .filter(|(_, row)| !row.excluded && matches!(row.class.as_str(), "conformance" | "helper"))
        .map(|(name, _)| name)
        .collect();
    if !names.iter().any(|n| n == "probeinit") {
        return Err(fail("probeinit missing from fixture inventory"));
    }
    for name in &names {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(fail(format!("invalid probe name: {name}")));
        }
    }
    Ok(names)
}

pub fn executable_inventory(root: &Path) -> Result<BTreeMap<String, GuestTarget>> {
    let mut paths = BTreeMap::new();
    let names = probe_names(root)?;
    for target in [GuestTarget::Musl, GuestTarget::Gnu] {
        for name in &names {
            paths.insert(
                format!(
                    "conformance-probes/target/{}/release/{name}",
                    target.triple()
                ),
                target,
            );
        }
    }
    let script = fs::read_to_string(root.join("scripts/build-linux-fixtures.sh"))?;
    let declarations = provision::parse_fixture_declarations(&script);
    if declarations.is_empty() {
        return Err(fail("empty Linux fixture declarations"));
    }
    for declaration in declarations {
        let relative = format!(
            "fixtures/linux-aarch64-hello/target/{}/release/{}",
            GuestTarget::Musl.triple(),
            declaration.name
        );
        safe_path(root, &relative)?;
        if paths.insert(relative, GuestTarget::Musl).is_some() {
            return Err(fail("duplicate Linux fixture"));
        }
    }
    for (_, name) in EMBED {
        paths.insert(
            format!("target/embed-fixtures/{name}-aarch64"),
            GuestTarget::Musl,
        );
    }
    Ok(paths)
}

fn validate_executable(path: &Path, executable: &Executable) -> Result<()> {
    if hash_file(path)? != executable.sha256 {
        return Err(fail(format!(
            "executable hash mismatch: {}",
            executable.path
        )));
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(fail(format!(
            "not a regular executable: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(fail(format!("not executable: {}", path.display())));
        }
    }
    let elf = provision::inspect_elf(&fs::read(path)?).map_err(fail)?;
    if !elf.is_64bit || !elf.is_little_endian || !elf.is_arm64 {
        return Err(fail(format!("not an ARM64 ELF: {}", executable.path)));
    }
    match executable.target {
        GuestTarget::Musl if elf.has_interpreter => {
            return Err(fail(format!(
                "musl fixture has an interpreter: {}",
                executable.path
            )));
        }
        GuestTarget::Gnu if elf.interpreter.as_deref() != Some("/lib/ld-linux-aarch64.so.1") => {
            return Err(fail(format!(
                "GNU fixture lacks the ARM64 glibc interpreter: {}",
                executable.path
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Admission is exact on fixture inputs and independent of unrelated files:
/// the bundle's input identity must equal the checkout's current one.
fn validate_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    if manifest.schema != SCHEMA {
        return Err(fail("unknown fixture manifest schema"));
    }
    if manifest.build_policy != BuildPolicy::default() {
        return Err(fail("fixture build policy mismatch"));
    }
    let mut sorted = manifest.compiler_inputs.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != manifest.compiler_inputs {
        return Err(fail("noncanonical fixture compiler input list"));
    }
    let current = source_hashes(root, &manifest.compiler_inputs)?;
    if manifest.sources != current {
        let changed: Vec<_> = manifest
            .sources
            .keys()
            .chain(current.keys())
            .filter(|path| manifest.sources.get(*path) != current.get(*path))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .take(8)
            .cloned()
            .collect();
        return Err(fail(format!(
            "fixture input identity mismatch (source hashes or inventory mismatch): bundle {} built at {}, checkout {}; differing inputs include {}",
            manifest.input_identity()?,
            manifest.source_head.0,
            input_identity(&current, &manifest.compiler_inputs, &BuildPolicy::default())?,
            changed.join(", ")
        )));
    }
    let pin = fs::read_to_string(root.join("rust-toolchain.toml"))?;
    let release = manifest
        .toolchain
        .rustc
        .lines()
        .find_map(|l| l.strip_prefix("release: "))
        .ok_or_else(|| fail("missing rustc release identity"))?;
    if !pin
        .lines()
        .any(|l| l.trim() == format!("channel = \"{release}\""))
        || manifest.toolchain.cargo.trim().is_empty()
        || manifest.toolchain.gnu_linker.trim().is_empty()
    {
        return Err(fail("missing or mismatched fixture toolchain identity"));
    }
    let expected_paths = executable_inventory(root)?;
    let actual: BTreeMap<_, _> = manifest
        .executables
        .iter()
        .map(|e| (e.path.clone(), e.target))
        .collect();
    if actual.len() != manifest.executables.len() || actual != expected_paths {
        return Err(fail(
            "incomplete, duplicate, or unexpected fixture executable inventory",
        ));
    }
    Ok(())
}

fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(manifest)?)
}

fn read_bundle_manifest(path: &Path) -> Result<Manifest> {
    let bytes = fs::read(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("manifest has no bundle directory"))?;
    if parent.file_name().and_then(|n| n.to_str()) != Some(&hash_bytes(&bytes).0) {
        return Err(fail("manifest content address mismatch"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest_bytes(&manifest)? != bytes {
        return Err(fail("noncanonical fixture manifest"));
    }
    if manifest.schema != SCHEMA {
        return Err(fail("unknown fixture manifest schema"));
    }
    Ok(manifest)
}

fn check_bundle_objects(path: &Path, manifest: &Manifest) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| fail("manifest has no bundle directory"))?;
    for executable in &manifest.executables {
        validate_executable(
            &safe_path(parent, &format!("objects/{}", executable.sha256.0))?,
            executable,
        )?;
    }
    Ok(())
}

fn inspect_bundle(path: &Path) -> Result<Manifest> {
    let manifest = read_bundle_manifest(path)?;
    check_bundle_objects(path, &manifest)?;
    Ok(manifest)
}

/// `sha`, when given, asserts the checkout's HEAD; the bundle itself is
/// admitted by input identity whichever commit published it.
pub fn verify_bundle(root: &Path, path: &Path, sha: Option<&str>) -> Result<Manifest> {
    expected_head(root, sha)?;
    let manifest = read_bundle_manifest(path)?;
    validate_manifest(root, &manifest)?;
    check_bundle_objects(path, &manifest)?;
    Ok(manifest)
}

/// Select one unambiguous bundle for `sha`, never mutable probe caches.
/// A bundle published from `sha` itself wins. Otherwise, when the local
/// checkout is at `sha`, select by its current fixture input identity so an
/// unrelated commit reuses the previous bundle. The receiver re-verifies.
pub fn resolve_bundle(root: &Path, sha: &str, explicit: Option<&Path>) -> Result<PathBuf> {
    let expected = CommitSha::try_from(sha.to_owned())?;
    if let Some(path) = explicit {
        inspect_bundle(path)?;
        return Ok(path.to_path_buf());
    }
    let store = root.join("target/fixtures/bundles");
    let manifests_in = |directory: &Path| -> Result<Vec<PathBuf>> {
        let mut manifests = Vec::new();
        if directory.is_dir() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path().join("manifest.json");
                if path.is_file() {
                    manifests.push(path);
                }
            }
        }
        manifests.sort();
        Ok(manifests)
    };
    let mut manifests = manifests_in(&store.join(&expected.0))?;
    if manifests.is_empty() && expected_head(root, Some(sha)).is_ok() {
        // Each bundle names its own compiler inputs, so the checkout's
        // identity is computed per candidate. Any error is a non-match.
        let matches = |manifest: &Manifest| {
            manifest.build_policy == BuildPolicy::default()
                && source_hashes(root, &manifest.compiler_inputs)
                    .is_ok_and(|current| current == manifest.sources)
        };
        if store.is_dir() {
            let mut directories: Vec<_> = fs::read_dir(&store)?
                .map(|entry| entry.map(|e| e.path()))
                .collect::<io::Result<_>>()?;
            directories.sort();
            for directory in directories {
                for path in manifests_in(&directory)? {
                    if matches(&read_bundle_manifest(&path)?) {
                        manifests.push(path);
                    }
                }
            }
        }
    }
    if manifests.len() != 1 {
        return Err(fail(format!(
            "expected one fixture bundle for {} or its fixture input identity, found {}; publish it on Linux or supply --fixture-manifest",
            expected.0,
            manifests.len()
        )));
    }
    let path = manifests.remove(0);
    inspect_bundle(&path)?;
    Ok(path)
}

pub fn verify_installed(root: &Path) -> Result<Manifest> {
    let installed: Installed =
        serde_json::from_slice(&fs::read(safe_path(root, INSTALLED_MANIFEST)?)?)?;
    if hash_bytes(&manifest_bytes(&installed.manifest)?) != installed.manifest_sha256 {
        return Err(fail("installed manifest hash mismatch"));
    }
    validate_manifest(root, &installed.manifest)?;
    for executable in &installed.manifest.executables {
        validate_executable(&safe_path(root, &executable.path)?, executable)?;
    }
    Ok(installed.manifest)
}

#[derive(Debug, Default)]
pub struct RestoreWork {
    pub executable_publications: usize,
    pub durability_flushes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationKind {
    Executable,
    Receipt,
}

fn publish_file(path: &Path, bytes: &[u8], kind: PublicationKind) -> Result<usize> {
    let parent = path.parent().ok_or_else(|| fail("output has no parent"))?;
    fs::create_dir_all(parent)?;
    if kind == PublicationKind::Receipt {
        crate::atomic_file::write(path, bytes)?;
        return Ok(1);
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    #[cfg(unix)]
    if kind == PublicationKind::Executable {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    temp.persist(path).map_err(|e| e.error)?;
    Ok(0)
}

pub fn restore(root: &Path, path: &Path, sha: Option<&str>) -> Result<RestoreWork> {
    let _gate = crate::host_lease::HostLease::acquire(crate::host_lease::HostLeaseMode::Gate)?;
    let manifest = verify_bundle(root, path, sha)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("manifest has no parent"))?;
    let stage = tempfile::tempdir()?;
    // Capture and revalidate before changing destinations; a changed bundle
    // cannot confer acceptance via a previously verified path.
    for (index, executable) in manifest.executables.iter().enumerate() {
        let from = safe_path(parent, &format!("objects/{}", executable.sha256.0))?;
        let to = stage.path().join(index.to_string());
        fs::copy(from, &to)?;
        validate_executable(&to, executable)?;
        safe_path(root, &executable.path)?;
    }
    let installed_path = safe_path(root, INSTALLED_MANIFEST)?;
    match fs::remove_file(&installed_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut work = RestoreWork::default();
    for (index, executable) in manifest.executables.iter().enumerate() {
        work.durability_flushes += publish_file(
            &safe_path(root, &executable.path)?,
            &fs::read(stage.path().join(index.to_string()))?,
            PublicationKind::Executable,
        )?;
        work.executable_publications += 1;
    }
    let installed = Installed {
        validation: validation_receipt(root, &manifest)?,
        manifest_sha256: hash_bytes(&manifest_bytes(&manifest)?),
        manifest,
    };
    work.durability_flushes += publish_file(
        &installed_path,
        &serde_json::to_vec_pretty(&installed)?,
        PublicationKind::Receipt,
    )?;
    verify_installed(root)?;
    Ok(work)
}

fn run_build(command: &mut Command) -> Result<()> {
    // Never capture a many-bin build into memory; errors retain their full log.
    let status = command.status()?;
    if !status.success() {
        return Err(fail(format!(
            "fixture build command failed: {command:?} ({status})"
        )));
    }
    Ok(())
}

pub fn build(root: &Path, sha: &str, output: Option<&Path>) -> Result<PathBuf> {
    if std::env::consts::OS != "linux" {
        return Err(fail("fixtures build requires Linux; restore on cloudmac"));
    }
    let expected = expected_head(root, Some(sha))?;
    source_hashes(root, &[])?;
    let environment = BuildEnvironment::new(root)?;
    let snapshot = tempfile::tempdir_in(environment.scratch_root())?;
    let archive = snapshot.path().join("source.tar");
    run_build(
        environment
            .configure(Command::new("git").current_dir(root))
            .args(["archive", "--format=tar", "--output"])
            .arg(&archive)
            .arg(&expected.0),
    )?;
    let source = snapshot.path().join("source");
    fs::create_dir(&source)?;
    run_build(
        environment
            .configure(&mut Command::new("tar"))
            .args(["-xf"])
            .arg(&archive)
            .arg("-C")
            .arg(&source),
    )?;
    // Git metadata is deliberately separate; source_hashes is captured from
    // the original clean checkout again after builds to reject source races.
    let rustc = environment
        .output(environment.configure(Command::new("rustc").current_dir(root).arg("-vV")))?;
    let cargo = environment
        .output(environment.configure(Command::new("cargo").current_dir(root).arg("--version")))?;
    let host = rustc
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or_else(|| fail("missing compiler host"))?;
    let sysroot = environment.output(
        environment.configure(
            Command::new("rustc")
                .current_dir(root)
                .args(["--print", "sysroot"]),
        ),
    )?;
    let lld = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/rust-lld");
    let linker = if std::env::consts::ARCH == "aarch64" {
        "cc"
    } else {
        "aarch64-linux-gnu-gcc"
    };
    let gnu_linker = environment
        .output(environment.configure(Command::new(linker).current_dir(root).arg("--version")))?;
    let toolchain = Toolchain {
        rustc,
        cargo,
        gnu_linker,
    };
    let names = probe_names(&source)?;
    for target in [GuestTarget::Musl, GuestTarget::Gnu] {
        let mut command = Command::new("cargo");
        environment
            .configure(&mut command)
            .current_dir(source.join("conformance-probes"))
            .args([
                "build",
                "--locked",
                "--release",
                "--target",
                target.triple(),
            ]);
        match target {
            GuestTarget::Musl => {
                command.env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", &lld);
            }
            GuestTarget::Gnu => {
                command.env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", linker);
            }
        }
        for name in &names {
            command.args(["--bin", name]);
        }
        run_build(&mut command)?;
    }
    for script in BUILD_SCRIPTS {
        run_build(
            environment
                .configure(Command::new("bash").current_dir(&source).arg(script))
                .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", &lld),
        )?;
    }
    if expected_head(root, Some(sha))? != expected {
        return Err(fail("checkout changed during fixture build"));
    }
    // Record what the compiler actually read: every executable's dep-info.
    let mut dep_info_files = Vec::new();
    for path in executable_inventory(&source)?.keys() {
        dep_info_files.push(source.join(dep_info::dep_info_path(path, EMBED)?));
    }
    let mut external = environment.cargo_cache_roots();
    external.push(PathBuf::from(sysroot.trim()));
    let compiler_inputs = dep_info::classify(&source, &dep_info_files, &external)?;
    let sources = source_hashes(root, &compiler_inputs)?;
    linker::check_build_script_outputs(&source, inputs::FIXTURES)?;
    // Match the build snapshot byte-for-byte with the recorded source inputs.
    for (path, hash) in &sources {
        if &hash_source(&source, path)? != hash {
            return Err(fail(format!("build snapshot source mismatch: {path}")));
        }
    }
    let mut executables = Vec::new();
    for (path, target) in executable_inventory(&source)? {
        let executable = Executable {
            sha256: hash_file(&source.join(&path))?,
            path,
            target,
        };
        validate_executable(&source.join(&executable.path), &executable)?;
        executables.push(executable);
    }
    let manifest = Manifest {
        schema: SCHEMA.into(),
        source_head: expected.clone(),
        compiler_inputs,
        sources,
        build_policy: BuildPolicy::default(),
        toolchain,
        executables,
    };
    validate_manifest(root, &manifest)?;
    let bytes = manifest_bytes(&manifest)?;
    let store = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("target/fixtures/bundles"));
    let sha_dir = store.join(&expected.0);
    fs::create_dir_all(&sha_dir)?;
    let stage = tempfile::tempdir_in(&sha_dir)?;
    fs::create_dir(stage.path().join("objects"))?;
    for executable in &manifest.executables {
        let to = stage.path().join("objects").join(&executable.sha256.0);
        if !to.exists() {
            fs::copy(source.join(&executable.path), to)?;
        }
    }
    fs::write(stage.path().join("manifest.json"), &bytes)?;
    let bundle = sha_dir.join(&hash_bytes(&bytes).0);
    if bundle.exists() {
        verify_bundle(root, &bundle.join("manifest.json"), Some(sha))?;
    } else {
        fs::rename(stage.path(), &bundle)?;
    }
    let path = bundle.join("manifest.json");
    verify_bundle(root, &path, Some(sha))?;
    Ok(path)
}

pub fn run(root: &Path, action: FixturesAction, writer: &mut dyn Write) -> Result<()> {
    match action {
        FixturesAction::Publish { sha } => {
            let manifest = build(root, &sha, None)?;
            let artifact = archive::pack(&manifest, &root.join("target/fixtures/published"))?;
            writeln!(
                writer,
                "fixtures: published artifact {}",
                artifact.display()
            )?;
        }
        FixturesAction::Build { sha, output } => {
            let path = build(root, &sha, output.as_deref())?;
            writeln!(writer, "fixtures: bundle manifest {}", path.display())?;
        }
        FixturesAction::Restore {
            manifest,
            bundle,
            sha,
        } => {
            let work = match (manifest, bundle) {
                (Some(manifest), None) => restore(root, &manifest, sha.as_deref())?,
                (None, Some(bundle)) => archive::restore(root, &bundle, sha.as_deref())?,
                _ => return Err(fail("supply exactly one of --manifest or --bundle")),
            };
            writeln!(
                writer,
                "fixtures: restored and verified {} executables; durability_flushes={}",
                work.executable_publications, work.durability_flushes
            )?;
        }
        FixturesAction::Prepare {
            bundle,
            run_dir,
            source,
        } => {
            let provenance =
                crate::remote_accept::capture_fixture_bundle(root, &bundle, &run_dir, source)?;
            writeln!(
                writer,
                "fixtures: verified captured bundle {}; identity={} archive_sha256={}",
                provenance.captured_path, provenance.identity, provenance.archive_sha256
            )?;
            archive::restore(root, Path::new(&provenance.captured_path), None)?;
        }
        FixturesAction::BuildCode => {
            write!(
                writer,
                "{}",
                build_code::render(&current_build_code(root)?)?
            )?;
        }
        FixturesAction::Verify {
            manifest,
            bundle,
            sha,
            receipt,
        } => {
            let expected = expected_head(root, sha.as_deref())?;
            let manifest = if let Some(bundle_path) = bundle {
                let (manifest, identity) = archive::verify(root, &bundle_path, &expected.0)?;
                let archive_sha256 = provision::compute_sha256(&bundle_path)?;
                writeln!(
                    writer,
                    "fixtures: verified {} executables built at {}; identity={} archive_sha256={}",
                    manifest.executables.len(),
                    manifest.source_head.0,
                    identity,
                    archive_sha256,
                )?;
                manifest
            } else {
                match manifest {
                    Some(path) => verify_bundle(root, &path, sha.as_deref())?,
                    None => verify_installed(root)?,
                }
            };
            if let Some(path) = receipt {
                crate::atomic_file::write(
                    &path,
                    &serde_json::to_vec_pretty(&validation_receipt(root, &manifest)?)?,
                )?;
            }
            writeln!(
                writer,
                "fixtures: verified {} executables for {} by input_identity {} (bundle built at {})",
                manifest.executables.len(),
                expected.0,
                manifest.input_identity()?,
                manifest.source_head.0
            )?;
        }
    }
    Ok(())
}
