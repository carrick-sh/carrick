//! Added conformance probes built from candidate code (owner decision #1980).
//!
//! The Signed queue gate restores main's trusted bundle for the merge base.
//! A candidate that only adds probes differs from that bundle by exactly the
//! new sources and their inventory rows, so the gate builds those probes from
//! candidate code under the publisher's build code and policy and serves them
//! beside the trusted bundle. Every other fixture input difference keeps the
//! input identity refusal.
use super::{
    BuildPolicy, CommitSha, ContentHash, Executable, GuestTarget, Manifest, Result, Toolchain,
    expected_head, fail, git, hash_bytes, hash_file, hash_source, hash_source_bytes, safe_path,
    source_hashes,
};
use crate::probe_inventory::{ProbeInventoryRow, load_inventory_from_str};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const CANDIDATE_SCHEMA: &str = "carrick.fixtures.candidate-probes.v1";
/// The probe inventory: a fixture input and the source of `probe_names`.
pub const PROBE_INVENTORY: &str = "conformance-probes/probe-inventory.json";
const PROBE_SOURCES: &str = "conformance-probes/src/bin/";
/// Inventory classes the publisher builds (see `probe_names`).
const BUILT_CLASSES: &[&str] = &["conformance", "helper", "performance"];

/// A conformance probe binary name: `conformance-probes/src/bin/<name>.rs`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProbeName(String);

impl TryFrom<String> for ProbeName {
    type Error = super::FixturesError;
    fn try_from(value: String) -> Result<Self> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(fail(format!("invalid probe name: {value}")));
        }
        Ok(Self(value))
    }
}
impl From<ProbeName> for String {
    fn from(value: ProbeName) -> Self {
        value.0
    }
}
impl ProbeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// The probe's checkout-relative source path.
    pub fn source(&self) -> String {
        format!("{PROBE_SOURCES}{}.rs", self.0)
    }
    /// The checkout-relative executable path the publisher builds for `target`.
    pub fn executable(&self, target: GuestTarget) -> String {
        format!(
            "conformance-probes/target/{}/release/{}",
            target.triple(),
            self.0
        )
    }
    fn from_source(path: &str) -> Option<Self> {
        let name = path.strip_prefix(PROBE_SOURCES)?.strip_suffix(".rs")?;
        Self::try_from(name.to_owned()).ok()
    }
}

/// One candidate-built probe, named with the source digest it was built from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddedProbe {
    pub name: ProbeName,
    /// `hash_source` digest of `conformance-probes/src/bin/<name>.rs`.
    pub source_sha256: ContentHash,
}

/// How a checkout's fixture inputs differ from a bundle's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDifference {
    /// Equal inputs: the bundle serves the checkout as it is.
    None,
    /// Only added probes; see [`classify_inputs`].
    AddedProbes(Vec<AddedProbe>),
    /// Anything else: the input identity refusal stands.
    Other,
}

/// The admission predicate. `base` is the bundle manifest's source inventory
/// (main's bundle) and `current` the checkout's, computed over the same
/// compiler inputs; "added" is relative to `base`, never to git history.
/// `base_inventory` and `current_inventory` are the bytes of
/// [`PROBE_INVENTORY`] each side hashed; a pair whose bytes do not hash to
/// its own inventory entry is `Other`.
///
/// The difference is `AddedProbes` exactly when all of these hold:
/// - every `base` path is present in `current` (nothing removed);
/// - at least one path is new, and every new path is
///   `conformance-probes/src/bin/<name>.rs` with a valid probe name;
/// - the only path whose digest changed is [`PROBE_INVENTORY`];
/// - the current inventory equals the base inventory plus one row per added
///   probe, row for row (no modified, removed or extra rows), and each added
///   row is one the publisher builds (a built class, not excluded).
///
/// So an edited probe, a lockfile, the toolchain pin, a builder, a build
/// policy input or any other source keeps today's refusal.
pub fn classify_inputs(
    base: &BTreeMap<String, ContentHash>,
    current: &BTreeMap<String, ContentHash>,
    base_inventory: &[u8],
    current_inventory: &[u8],
) -> InputDifference {
    if base == current {
        return InputDifference::None;
    }
    if base.keys().any(|path| !current.contains_key(path)) {
        return InputDifference::Other;
    }
    let mut added = Vec::new();
    for (path, digest) in current {
        match base.get(path) {
            Some(old) if old == digest => {}
            Some(_) if path == PROBE_INVENTORY => {}
            Some(_) => return InputDifference::Other,
            None => match ProbeName::from_source(path) {
                Some(name) => added.push(AddedProbe {
                    name,
                    source_sha256: digest.clone(),
                }),
                None => return InputDifference::Other,
            },
        }
    }
    if added.is_empty()
        || base.get(PROBE_INVENTORY) != hash_source_bytes(base_inventory).ok().as_ref()
        || current.get(PROBE_INVENTORY) != hash_source_bytes(current_inventory).ok().as_ref()
    {
        return InputDifference::Other;
    }
    let parse = |bytes: &[u8]| {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| load_inventory_from_str(text).ok())
    };
    let (Some(old_rows), Some(mut new_rows)) = (parse(base_inventory), parse(current_inventory))
    else {
        return InputDifference::Other;
    };
    for probe in &added {
        let built =
            |row: &ProbeInventoryRow| !row.excluded && BUILT_CLASSES.contains(&row.class.as_str());
        match new_rows.remove(probe.name.as_str()) {
            Some(row) if built(&row) && !old_rows.contains_key(probe.name.as_str()) => {}
            _ => return InputDifference::Other,
        }
    }
    if new_rows != old_rows {
        return InputDifference::Other;
    }
    added.sort();
    InputDifference::AddedProbes(added)
}

/// A content-addressed supplement to one trusted bundle: the candidate-built
/// executables of its added probes. Laid out like a bundle (`manifest.json`
/// in a directory named by its digest, executables under `objects/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProbeSet {
    pub schema: String,
    /// The commit whose sources were built; provenance, like `source_head`.
    pub candidate_head: CommitSha,
    /// `content_identity` of the trusted bundle this set extends.
    pub base_content_sha256: ContentHash,
    /// That bundle's probe inventory, authenticated by its source digest, so
    /// admission needs no git history.
    pub base_inventory: String,
    pub probes: Vec<AddedProbe>,
    pub toolchain: Toolchain,
    pub executables: Vec<Executable>,
}

/// What a receipt records about the candidate-built probes it admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProbeEvidence {
    /// Digest of the set's canonical manifest (binds its executables).
    pub set_sha256: ContentHash,
    pub probes: Vec<AddedProbe>,
}

impl CandidateProbeSet {
    pub fn evidence(&self) -> Result<CandidateProbeEvidence> {
        Ok(CandidateProbeEvidence {
            set_sha256: hash_bytes(&set_bytes(self)?),
            probes: self.probes.clone(),
        })
    }
}

pub(super) fn set_bytes(set: &CandidateProbeSet) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(set)?)
}

/// Read a set's manifest; its directory must be named by its digest.
pub fn read_set(path: &Path) -> Result<CandidateProbeSet> {
    let bytes = fs::read(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("candidate probe set has no directory"))?;
    if parent.file_name().and_then(|n| n.to_str()) != Some(&String::from(hash_bytes(&bytes))) {
        return Err(fail("candidate probe set content address mismatch"));
    }
    let set: CandidateProbeSet = serde_json::from_slice(&bytes)?;
    if set_bytes(&set)? != bytes {
        return Err(fail("noncanonical candidate probe set"));
    }
    if set.schema != CANDIDATE_SCHEMA {
        return Err(fail("unknown candidate probe set schema"));
    }
    Ok(set)
}

/// Read a set and check every object against its recorded executable.
pub fn inspect_set(path: &Path) -> Result<CandidateProbeSet> {
    let set = read_set(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| fail("candidate probe set has no directory"))?;
    for executable in &set.executables {
        super::validate_executable(
            &safe_path(parent, &format!("objects/{}", executable.sha256))?,
            executable,
        )?;
    }
    Ok(set)
}

/// Admit `set` for this checkout beside `manifest`. `Ok(false)` means the
/// checkout's difference from the bundle is not only added probes, and the
/// caller reports the input identity refusal; a set that does not match its
/// bundle, the checkout's added probes or the bundle's toolchain is an error.
pub(super) fn admit(
    root: &Path,
    manifest: &Manifest,
    current: &BTreeMap<String, ContentHash>,
    set: &CandidateProbeSet,
) -> Result<bool> {
    if set.schema != CANDIDATE_SCHEMA {
        return Err(fail("unknown candidate probe set schema"));
    }
    if set.base_content_sha256 != manifest.content_identity()? {
        return Err(fail(
            "candidate probe set extends a different fixture bundle",
        ));
    }
    let current_inventory = fs::read(safe_path(root, PROBE_INVENTORY)?)?;
    let probes = match classify_inputs(
        &manifest.sources,
        current,
        set.base_inventory.as_bytes(),
        &current_inventory,
    ) {
        InputDifference::AddedProbes(probes) => probes,
        InputDifference::None => {
            return Err(fail(
                "candidate probe set supplied, but the checkout adds no probes",
            ));
        }
        InputDifference::Other => return Ok(false),
    };
    if probes != set.probes {
        return Err(fail(
            "candidate probe set does not match the checkout's added probes",
        ));
    }
    if set.toolchain != manifest.toolchain {
        return Err(fail(
            "candidate probes were built with a toolchain other than the bundle's",
        ));
    }
    let expected: BTreeMap<String, GuestTarget> = expected_executables(&probes).collect();
    let actual: BTreeMap<String, GuestTarget> = set
        .executables
        .iter()
        .map(|e| (e.path.clone(), e.target))
        .collect();
    if actual.len() != set.executables.len() || actual != expected {
        return Err(fail(
            "candidate probe set executables are not exactly the added probes for both ARM libc sets",
        ));
    }
    Ok(true)
}

fn expected_executables(probes: &[AddedProbe]) -> impl Iterator<Item = (String, GuestTarget)> {
    probes.iter().flat_map(|probe| {
        [GuestTarget::Musl, GuestTarget::Gnu].map(|t| (probe.name.executable(t), t))
    })
}

/// What [`build`] compiles: each added probe for both ARM libc sets.
#[derive(Debug, Clone)]
pub struct BuildPlan {
    pub base: Manifest,
    pub base_inventory: String,
    pub probes: Vec<AddedProbe>,
}

impl BuildPlan {
    /// `(target, bin)` in the order the publisher's commands build them.
    pub fn bins(&self) -> Vec<(GuestTarget, ProbeName)> {
        [GuestTarget::Musl, GuestTarget::Gnu]
            .into_iter()
            .flat_map(|t| self.probes.iter().map(move |p| (t, p.name.clone())))
            .collect()
    }
}

/// What a candidate build found and did.
#[derive(Debug)]
pub enum CandidateBuild<T> {
    /// Fixture inputs equal the bundle's; the bundle serves the checkout.
    Equal,
    /// A difference other than added probes, or an added probe that could
    /// read unlisted files (see [`unlisted_reader`]): nothing is built, and
    /// the receiver reports the input identity refusal (the error says why).
    Refused(super::FixturesError),
    /// The added probes to build, or the set they were built into.
    Build(T),
}

/// Plan a candidate build: compare the checkout at `root` with the trusted
/// bundle manifest at `base`. Main's inventory bytes come from the bundle's
/// publishing commit and are admitted only if they hash to the manifest's
/// entry.
pub fn plan(root: &Path, base: &Path) -> Result<CandidateBuild<BuildPlan>> {
    let manifest = super::inspect_bundle(base)?;
    if manifest.build_policy != BuildPolicy::default() {
        return Err(fail("fixture build policy mismatch"));
    }
    let current = source_hashes(root, &manifest.compiler_inputs)?;
    if current == manifest.sources {
        return Ok(CandidateBuild::Equal);
    }
    let base_inventory = git(
        root,
        &[
            "show",
            &format!(
                "{}:{PROBE_INVENTORY}",
                String::from(manifest.source_head.clone())
            ),
        ],
    )
    .unwrap_or_default();
    let current_inventory = fs::read(safe_path(root, PROBE_INVENTORY)?)?;
    match classify_inputs(
        &manifest.sources,
        &current,
        base_inventory.as_bytes(),
        &current_inventory,
    ) {
        InputDifference::AddedProbes(probes) => {
            for probe in &probes {
                let text = fs::read(safe_path(root, &probe.name.source())?)?;
                if let Some(token) = unlisted_reader(&String::from_utf8_lossy(&text)) {
                    return Ok(CandidateBuild::Refused(fail(format!(
                        "added probe {} uses `{token}`: assembly or link-attribute probes can \
                         read files the compiler's dep-info does not list, so they go through a \
                         normal fixture republish, not a candidate build",
                        probe.name.source()
                    ))));
                }
            }
            Ok(CandidateBuild::Build(BuildPlan {
                base: manifest,
                base_inventory,
                probes,
            }))
        }
        InputDifference::None => Ok(CandidateBuild::Equal),
        InputDifference::Other => Ok(CandidateBuild::Refused(super::identity_mismatch(
            &manifest, &current,
        )?)),
    }
}

/// The first assembly or link-attribute token in an added probe's source,
/// or `None`.
///
/// [`build`] admits a compiler input only if dep-info lists it, but the
/// assembler (`.incbin` and `.include` in `asm!`, `global_asm!` or
/// `naked_asm!`) and the linker (`#[link(...)]`, `link_args`) read files
/// dep-info never names. Rather than read assembly, an added probe is
/// refused outright, failing closed on text (Rust parsing is out of reach
/// here):
/// - the identifiers `asm`, `global_asm` and `naked_asm` anywhere, whatever
///   their path or `!` spacing (a `use .. as` rename still names them);
/// - `link_args` anywhere;
/// - the identifier `link` in attribute position: after `[` or `,` and
///   before `(`, spacing and comments included (`#[link(`, `# [ link (`,
///   `#[/**/link(`, `cfg_attr(.., link(..))`); and, in a source defining
///   `macro_rules` (which can paste `link` into an attribute), any `link`
///   that is not a path segment or method (`libc::link(`, `.link(`).
///
/// Files the compiler reads through `include_str!`, `include_bytes!`,
/// `include!` or `#[path]` are in dep-info, which [`build`] checks.
pub fn unlisted_reader(source: &str) -> Option<&'static str> {
    let ident = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
    let bytes = source.as_bytes();
    let macros = source.contains("macro_rules");
    let mut at = 0;
    while at < bytes.len() {
        if !ident(&bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && ident(&bytes[at]) {
            at += 1;
        }
        let word = &source[start..at];
        match word {
            "asm" => return Some("asm"),
            "global_asm" => return Some("global_asm"),
            "naked_asm" => return Some("naked_asm"),
            "link_args" => return Some("link_args"),
            "link" => {
                let before = bytes[..start]
                    .iter()
                    .rev()
                    .find(|b| !b.is_ascii_whitespace());
                let after = bytes[at..].iter().find(|b| !b.is_ascii_whitespace());
                let attribute = matches!(before, Some(b'[' | b',' | b'/'))
                    && matches!(after, Some(b'(' | b'/'));
                let path = matches!(before, Some(b':' | b'.'));
                if attribute || (macros && !path) {
                    return Some("link");
                }
            }
            _ => {}
        }
    }
    None
}

/// Build the added probes of the checkout at `root` (exactly `sha`) with the
/// publisher's snapshot, environment and probe build commands, then write
/// the set's manifest and objects under `output`.
pub fn build(
    root: &Path,
    base: &Path,
    sha: &str,
    output: &Path,
) -> Result<CandidateBuild<PathBuf>> {
    let expected = expected_head(root, Some(sha))?;
    // Resolution below is offline; populate the Cargo cache first.
    super::fetch_dependencies(root)?;
    let plan = match plan(root, base)? {
        CandidateBuild::Build(plan) => plan,
        CandidateBuild::Equal => return Ok(CandidateBuild::Equal),
        CandidateBuild::Refused(error) => return Ok(CandidateBuild::Refused(error)),
    };
    let snapshot = super::Snapshot::new(root, &expected)?;
    let names: Vec<String> = plan
        .probes
        .iter()
        .map(|p| p.name.as_str().to_owned())
        .collect();
    snapshot.build_probes(&names)?;
    if expected_head(root, Some(sha))? != expected {
        return Err(fail("checkout changed during candidate probe build"));
    }
    if snapshot.toolchain != plan.base.toolchain {
        return Err(fail(format!(
            "candidate probe toolchain differs from the bundle's publisher: {:?} vs {:?}",
            snapshot.toolchain, plan.base.toolchain
        )));
    }
    // What the compiler read for the added probes must already be a bundle
    // input with unchanged bytes, or be an added probe source itself.
    let source = &snapshot.checkout;
    let mut dep_info = Vec::new();
    for (path, _) in expected_executables(&plan.probes) {
        dep_info.push(source.join(format!("{path}.d")));
    }
    let added: BTreeSet<String> = plan.probes.iter().map(|p| p.name.source()).collect();
    for input in super::dep_info::classify(source, &dep_info, &snapshot.external_roots())? {
        let admitted = plan
            .base
            .sources
            .get(&input)
            .is_some_and(|hash| hash_source(source, &input).is_ok_and(|now| &now == hash));
        if !admitted && !added.contains(&input) {
            return Err(fail(format!(
                "added probe reads {input}, which is not an unchanged fixture input"
            )));
        }
    }
    for probe in &plan.probes {
        if hash_source(source, &probe.name.source())? != probe.source_sha256 {
            return Err(fail(format!(
                "build snapshot source mismatch: {}",
                probe.name.source()
            )));
        }
    }
    let mut executables = Vec::new();
    for (path, target) in expected_executables(&plan.probes) {
        let executable = Executable {
            sha256: hash_file(&source.join(&path))?,
            path,
            target,
        };
        super::validate_executable(&source.join(&executable.path), &executable)?;
        snapshot.reject_embedded_path(&executable.path)?;
        executables.push(executable);
    }
    let set = CandidateProbeSet {
        schema: CANDIDATE_SCHEMA.into(),
        candidate_head: expected,
        base_content_sha256: plan.base.content_identity()?,
        base_inventory: plan.base_inventory.clone(),
        probes: plan.probes.clone(),
        toolchain: snapshot.toolchain.clone(),
        executables,
    };
    let current = source_hashes(root, &plan.base.compiler_inputs)?;
    if !admit(root, &plan.base, &current, &set)? {
        return Err(super::identity_mismatch(&plan.base, &current)?);
    }
    let bytes = set_bytes(&set)?;
    let directory = output.join(String::from(hash_bytes(&bytes)));
    fs::create_dir_all(directory.join("objects"))?;
    for executable in &set.executables {
        fs::copy(
            source.join(&executable.path),
            directory
                .join("objects")
                .join(executable.sha256.to_string()),
        )?;
    }
    let path = directory.join("manifest.json");
    fs::write(&path, &bytes)?;
    inspect_set(&path)?;
    Ok(CandidateBuild::Build(path))
}
