//! Position-free authoring debt. Compiler spans are consumed in memory only;
//! accepted identities are closed operation/owner/lane cohorts and ceilings.
use crate::authority_source::SourceCensus;
use crate::command;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const CEILINGS_PATH: &str = "scripts/migrate/authority-debt-ceilings.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    BuildTime,
    RawLock,
    K1CreateInstall,
    K1EpollWait,
    K1InspectMisc,
    K1Lifecycle,
    K1MappingRing,
    K1ReadAttempt,
    K1SlotDescriptionMutation,
    K1StreamTransfer,
    K1WriteAttempt,
    HostSubstrate,
    HostBacking,
    HostForbiddenSemantic,
    FatalCarrierFault,
    FatalTypedErrorDebt,
    GlobalCarrierInfra,
    GlobalHostKernelObject,
    GlobalMonotonicAllocator,
    GlobalConfigDebug,
    GlobalTestOnly,
    GlobalContainerDebt,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    BuildTime,
    Shared,
    Hvf,
    X86,
    Kvm,
    Bhyve,
    Nvmm,
    Linux,
    Bsd,
    Darwin,
    MacosCliDefault,
    MacosRuntimeDefault,
    MacosHvfDefault,
    LinuxCli,
    LinuxRuntime,
    FreebsdCli,
    FreebsdRuntime,
    NetbsdCli,
    NetbsdRuntime,
}

impl Lane {
    pub fn module(krate: &str, modules: &[String]) -> Self {
        if krate == "carrick_vmm_hvf" {
            Self::Hvf
        } else if krate == "carrick_vmm_kvm" {
            Self::Kvm
        } else if krate == "carrick_vmm_bhyve" {
            Self::Bhyve
        } else if krate == "carrick_vmm_nvmm" {
            Self::Nvmm
        } else if krate == "carrick_x86" || modules.iter().any(|module| module.starts_with("x86_"))
        {
            Self::X86
        } else if krate == "carrick_host_linux" {
            Self::Linux
        } else if krate == "carrick_host_bsd" {
            Self::Bsd
        } else if krate == "carrick_host_darwin" {
            Self::Darwin
        } else {
            Self::Shared
        }
    }
    pub fn profile(profile: &str) -> Result<Self, DebtError> {
        serde_json::from_value(Value::String(profile.replace('-', "_"))).map_err(DebtError::Json)
    }
    fn is_profile(self) -> bool {
        matches!(
            self,
            Self::MacosCliDefault
                | Self::MacosRuntimeDefault
                | Self::MacosHvfDefault
                | Self::LinuxCli
                | Self::LinuxRuntime
                | Self::FreebsdCli
                | Self::FreebsdRuntime
                | Self::NetbsdCli
                | Self::NetbsdRuntime
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counter {
    pub family: Family,
    pub operation: String,
    pub owner: String,
    pub lane: Lane,
    pub ceiling: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDebtCeilings {
    pub schema: u32,
    pub counters: Vec<Counter>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    family: Family,
    operation: String,
    owner: String,
    lane: Lane,
}
impl Counter {
    fn key(&self) -> Key {
        Key {
            family: self.family,
            operation: self.operation.clone(),
            owner: self.owner.clone(),
            lane: self.lane,
        }
    }
}

#[derive(Debug, Error)]
pub enum DebtError {
    #[error("authority debt: {0}")]
    Policy(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Command(#[from] command::CommandError),
    #[error(transparent)]
    Syntax(#[from] syn::Error),
}
fn fail<T>(message: impl Into<String>) -> Result<T, DebtError> {
    Err(DebtError::Policy(message.into()))
}
impl AuthorityDebtCeilings {
    pub fn validate(&self) -> Result<(), DebtError> {
        if self.schema != 1 {
            return fail("unknown ceiling schema");
        }
        let mut keys = BTreeSet::new();
        let mut cohorts = BTreeSet::new();
        for counter in &self.counters {
            if counter.operation.is_empty() || counter.owner.is_empty() {
                return fail("empty operation/owner cohort");
            }
            if counter.owner != unsalt(&counter.owner) {
                return fail(
                    "source fingerprints and occurrence ordinals are not authority owners",
                );
            }
            if !keys.insert(counter.key())
                || !cohorts.insert((&counter.operation, &counter.owner, counter.lane))
            {
                return fail(format!("duplicate or reclassified cohort: {counter:?}"));
            }
            if counter.family == Family::GlobalContainerDebt && counter.ceiling != 0 {
                return fail("ambient guest-state debt must be zero unconditionally");
            }
            let host = matches!(
                counter.family,
                Family::HostSubstrate | Family::HostBacking | Family::HostForbiddenSemantic
            );
            if counter.family == Family::BuildTime
                && counter.lane != Lane::BuildTime
                && !counter.lane.is_profile()
            {
                return fail(
                    "build-time cohorts require the build-time boundary or a compiled profile",
                );
            }
            if counter.family != Family::BuildTime
                && (counter.lane == Lane::BuildTime || host != counter.lane.is_profile())
            {
                return fail(
                    "host cohorts require a real compiled profile; source cohorts require a source lane",
                );
            }
        }
        Ok(())
    }
    pub fn ratchet(&self, base: &Self) -> Result<(), DebtError> {
        self.validate()?;
        base.validate()?;
        let old: BTreeMap<_, _> = base.counters.iter().map(|c| (c.key(), c.ceiling)).collect();
        let new: BTreeMap<_, _> = self.counters.iter().map(|c| (c.key(), c.ceiling)).collect();
        for (key, ceiling) in &old {
            if *ceiling != 0 && !new.contains_key(key) {
                return fail(format!("removed nonzero counter: {key:?} = {ceiling}"));
            }
        }
        for (key, ceiling) in &new {
            match old.get(key) {
                Some(previous) if ceiling <= previous => {}
                Some(previous) => {
                    return fail(format!(
                        "ceiling increase: {key:?}: {previous} -> {ceiling}"
                    ));
                }
                None => return fail(format!("unknown family/owner cohort in head: {key:?}")),
            }
        }
        Ok(())
    }
    fn assign(
        &self,
        allowed: &[Family],
        operation: &str,
        owner: &str,
        lane: Lane,
    ) -> Result<Family, DebtError> {
        self.counters
            .iter()
            .find(|c| {
                allowed.contains(&c.family)
                    && c.operation == operation
                    && c.owner == owner
                    && c.lane == lane
            })
            .map(|c| c.family)
            .ok_or_else(|| {
                DebtError::Policy(format!(
                    "unknown authority API/owner cohort: {operation} at {owner} ({lane:?})"
                ))
            })
    }
    fn check_counts(&self, actual: &BTreeMap<Key, u64>) -> Result<(), DebtError> {
        let ceilings: BTreeMap<_, _> = self.counters.iter().map(|c| (c.key(), c.ceiling)).collect();
        for (key, count) in actual {
            let ceiling = ceilings
                .get(key)
                .ok_or_else(|| DebtError::Policy(format!("unknown authority cohort: {key:?}")))?;
            if count > ceiling {
                return fail(format!("{key:?}: {count} exceeds ceiling {ceiling}"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, clap::Args)]
pub struct AuthorityDebtArgs {
    /// Actual change-range base. Absent/empty skips only the delta ratchet.
    #[arg(long)]
    pub base: Option<String>,
    /// Run source and ratchet checks only. Live compiler coverage is still pending.
    #[arg(long)]
    pub source_only: bool,
    /// Explicit BSD compile target; requires the complete C cross toolchain.
    #[arg(long, requires_all = ["cross_cc", "cross_cflags", "cross_ar"], conflicts_with = "source_only")]
    pub cross_target: Option<String>,
    #[arg(long, requires = "cross_target")]
    pub cross_cc: Option<String>,
    #[arg(long, requires = "cross_target", allow_hyphen_values = true)]
    pub cross_cflags: Option<String>,
    #[arg(long, requires = "cross_target")]
    pub cross_ar: Option<String>,
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, DebtError> {
    value[field]
        .as_str()
        .ok_or_else(|| DebtError::Policy(format!("missing string {field}")))
}
fn rows(value: &Value) -> Result<&Vec<Value>, DebtError> {
    value
        .as_array()
        .ok_or_else(|| DebtError::Policy("expected discovery array".into()))
}
fn read_json(path: &Path) -> Result<Value, DebtError> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
fn unsalt(symbol: &str) -> String {
    symbol
        .split("::")
        .map(|part| {
            let symbol = part.split('@').next().unwrap_or(part);
            if let Some((owner, ordinal)) = symbol.rsplit_once('#')
                && !ordinal.is_empty()
                && ordinal.chars().all(|c| c.is_ascii_digit())
            {
                owner
            } else {
                symbol
            }
        })
        .collect::<Vec<_>>()
        .join("::")
}
fn finding_owner(source: &SourceCensus, row: &Value) -> Result<String, DebtError> {
    let line = row["line"]
        .as_u64()
        .ok_or_else(|| DebtError::Policy("missing ephemeral symbol diagnostic line".into()))?
        as usize;
    let mut owner = source.owner_at(
        text(row, "file")?,
        line,
        row["column"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("missing ephemeral symbol diagnostic column".into()))?
            as usize,
    )?;
    if let Some(argument) = row["argument"].as_str() {
        owner.push_str("::");
        owner.push_str(argument);
    }
    Ok(owner)
}
fn add(actual: &mut BTreeMap<Key, u64>, family: Family, operation: &str, owner: &str, lane: Lane) {
    *actual
        .entry(Key {
            family,
            operation: operation.into(),
            owner: owner.into(),
            lane,
        })
        .or_default() += 1;
}
fn discover(
    root: &Path,
    checker: &str,
    tools: &Path,
    source: &SourceCensus,
) -> Result<Value, DebtError> {
    // External test modules carry their proof in a parsed parent declaration.
    // Share the strict census result, after genuine production reachability has
    // taken precedence; lexical scanners must not infer this from file names.
    let script = r#"
import dataclasses, importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location('working_source', sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
root = pathlib.Path(sys.argv[2])
m_verdict = m.census_verdict.CensusVerdict(json.loads(pathlib.Path(sys.argv[3]).read_text()))
m_verdict.validate_tree(root)
if hasattr(m, 'scan_sources'):
    errors = m.validate_sysv_lock_authority_rules(root, verdict=m_verdict)
    if errors: raise ValueError('\n'.join(errors))
    findings = m.scan_sources(root, verdict=m_verdict)
elif hasattr(m, 'discover_runtime_aborts'):
    findings = m.discover_runtime_aborts(root, verdict=m_verdict)
    raw = [f for f in findings if f.sink == 'raw' and not m_verdict.is_build_file(f.file)]
    if raw: raise ValueError('raw termination forbidden: ' + raw[0].file + '::' + raw[0].function)
else:
    m.validate_concurrent_tree(root, verdict=m_verdict)
    findings = m.discover(root, verdict=m_verdict)
print(json.dumps([dataclasses.asdict(f) for f in findings]))
"#;
    let proof = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(proof.as_file(), &source.verdict(root)?)?;
    let output = command::run_checked(
        "python3",
        [
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(script),
            tools
                .join(format!("scripts/migrate/{checker}.py"))
                .as_os_str(),
            root.as_os_str(),
            proof.path().as_os_str(),
        ],
        Some(root),
    )?;
    Ok(serde_json::from_str(&output.stdout)?)
}
const GLOBAL_FAMILIES: &[Family] = &[
    Family::GlobalCarrierInfra,
    Family::GlobalHostKernelObject,
    Family::GlobalMonotonicAllocator,
    Family::GlobalConfigDebug,
    Family::GlobalTestOnly,
    Family::GlobalContainerDebt,
];
const FATAL_FAMILIES: &[Family] = &[Family::FatalCarrierFault, Family::FatalTypedErrorDebt];
const HOST_FAMILIES: &[Family] = &[
    Family::HostSubstrate,
    Family::HostBacking,
    Family::HostForbiddenSemantic,
];
pub(crate) const K1_FAMILIES: &[Family] = &[
    Family::K1CreateInstall,
    Family::K1EpollWait,
    Family::K1InspectMisc,
    Family::K1Lifecycle,
    Family::K1MappingRing,
    Family::K1ReadAttempt,
    Family::K1SlotDescriptionMutation,
    Family::K1StreamTransfer,
    Family::K1WriteAttempt,
];
fn source_counts(
    root: &Path,
    tools: &Path,
    policy: &AuthorityDebtCeilings,
    source: &SourceCensus,
) -> Result<BTreeMap<Key, u64>, DebtError> {
    source.verify_task_rules()?;
    let mut actual = BTreeMap::new();
    for row in rows(&discover(
        root,
        "check-dispatch-lock-authority",
        tools,
        source,
    )?)? {
        let file = text(row, "file")?;
        if source.is_outside_production_at(
            file,
            row["line"].as_u64().unwrap_or(0) as usize,
            row["column"].as_u64().unwrap_or(0) as usize,
        ) {
            continue;
        }
        let line = row["line"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("missing lock diagnostic line".into()))?
            as usize;
        let owner = source.owner_at(
            file,
            line,
            row["column"]
                .as_u64()
                .ok_or_else(|| DebtError::Policy("missing lock diagnostic column".into()))?
                as usize,
        )?;
        let operation = text(row, "category")?;
        let lane = source.lane(&owner)?;
        let family = if source.is_build_file(file) {
            Family::BuildTime
        } else {
            Family::RawLock
        };
        policy.assign(&[family], operation, &owner, lane)?;
        add(&mut actual, family, operation, &owner, lane);
    }
    for site in &source.k1 {
        let family = policy.assign(
            if source.is_build_file(&site.file) {
                &[Family::BuildTime]
            } else {
                K1_FAMILIES
            },
            &site.operation,
            &site.owner,
            site.lane,
        )?;
        add(&mut actual, family, &site.operation, &site.owner, site.lane);
    }
    for row in rows(&discover(
        root,
        "check-runtime-global-state",
        tools,
        source,
    )?)? {
        let file = text(row, "file")?;
        if source.is_outside_production_at(
            file,
            row["line"].as_u64().unwrap_or(0) as usize,
            row["column"].as_u64().unwrap_or(0) as usize,
        ) {
            continue;
        }
        let owner = finding_owner(source, row)?;
        let operation = format!("global:{}", text(row, "kind")?);
        let lane = source.lane(&owner)?;
        let family = policy.assign(
            if source.is_build_file(file) {
                &[Family::BuildTime]
            } else {
                GLOBAL_FAMILIES
            },
            &operation,
            &owner,
            lane,
        )?;
        add(&mut actual, family, &operation, &owner, lane);
    }
    for row in rows(&discover(root, "check-runtime-aborts", tools, source)?)? {
        let owner = finding_owner(source, row)?;
        let operation = format!("fatal:{}", text(row, "domain")?);
        let lane = source.lane(&owner)?;
        let family = policy.assign(
            if source.is_build_file(text(row, "file")?) {
                &[Family::BuildTime]
            } else {
                FATAL_FAMILIES
            },
            &operation,
            &owner,
            lane,
        )?;
        add(&mut actual, family, &operation, &owner, lane);
    }
    Ok(actual)
}
fn host_counts(
    result: &Value,
    policy: &AuthorityDebtCeilings,
    source: &SourceCensus,
) -> Result<BTreeMap<Key, u64>, DebtError> {
    let mut actual = BTreeMap::new();
    for row in rows(&result["rows"])? {
        let point = if row["expansion"].is_object() {
            &row["expansion"]
        } else {
            &row["source"]
        };
        let file = text(point, "file")?;
        let line = point["line_start"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("missing compiler diagnostic line".into()))?
            as usize;
        let column = point["column_start"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("missing compiler diagnostic column".into()))?
            as usize;
        let owner = source.owner_at(file, line, column.saturating_sub(1))?;
        let operation = text(row, "operation")?;
        for profile in rows(&row["profiles"])? {
            let lane = Lane::profile(
                profile
                    .as_str()
                    .ok_or_else(|| DebtError::Policy("unknown profile".into()))?,
            )?;
            let family = if source.is_build_file(file) {
                policy.assign(&[Family::BuildTime], operation, &owner, lane)?
            } else {
                policy.assign(HOST_FAMILIES, operation, &owner, lane)?
            };
            add(&mut actual, family, operation, &owner, lane);
        }
    }
    Ok(actual)
}
fn comparison_base(root: &Path, explicit: Option<&str>) -> Result<Option<String>, DebtError> {
    let environment = std::env::var("CARRICK_AUTHORITY_BASE").ok();
    let Some(base) = explicit
        .filter(|base| !base.trim().is_empty())
        .or_else(|| {
            environment
                .as_deref()
                .filter(|base| !base.trim().is_empty())
        })
        .map(str::trim)
    else {
        return Ok(None);
    };
    let base = command::run_checked(
        "git",
        ["rev-parse", "--verify", &format!("{base}^{{commit}}")],
        Some(root),
    )?
    .stdout
    .trim()
    .to_string();
    let head = command::run_checked("git", ["rev-parse", "HEAD"], Some(root))?;
    if base == head.stdout.trim() {
        return fail("cannot compare HEAD to itself; provide the actual change-range base");
    }
    Ok(Some(base))
}
fn base_policy(root: &Path, base: &str) -> Result<AuthorityDebtCeilings, DebtError> {
    let path = format!("{base}:{CEILINGS_PATH}");
    // Only a genuinely absent new schema uses legacy migration. Corrupt policy
    // is an error; it cannot fall back to a more permissive baseline.
    let exists = command::run_checked("git", ["ls-tree", base, "--", CEILINGS_PATH], Some(root))?;
    if !exists.stdout.trim().is_empty() {
        let output = command::run_checked("git", ["show", &path], Some(root))?;
        return Ok(serde_json::from_str(&output.stdout)?);
    }
    let output = std::process::Command::new("git")
        .args(["archive", base])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return fail("cannot read PR-base source for initial migration");
    }
    let temporary = tempfile::tempdir()?;
    tar::Archive::new(output.stdout.as_slice()).unpack(temporary.path())?;
    initial_base_policy(temporary.path(), base, root)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialBaseCounts {
    schema: u32,
    source_commit: String,
    platforms: Vec<String>,
    policy: AuthorityDebtCeilings,
}

fn initial_base_policy(
    base_root: &Path,
    base: &str,
    tools: &Path,
) -> Result<AuthorityDebtCeilings, DebtError> {
    if base_root.join(CEILINGS_PATH).exists() {
        return fail("initial bootstrap is unreachable with the ceilings schema");
    }
    let snapshot: InitialBaseCounts = serde_json::from_value(read_json(
        &tools.join("scripts/migrate/authority-initial-base-counts.json"),
    )?)?;
    let expected = BTreeSet::from(["linux", "macos", "freebsd", "netbsd"]);
    let platforms = snapshot
        .platforms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if snapshot.schema != 1 || snapshot.platforms.len() != expected.len() || platforms != expected {
        return fail("invalid audited initial symbolic bootstrap metadata");
    }
    snapshot.policy.validate()?;
    // This is a one-time schema cutover, not a receipt for one Git identity.
    // The actual merged tree still passes the complete restricted census,
    // absolute ceilings and zero rules; a schema-bearing base uses the ratchet.
    println!(
        "authority debt initial bootstrap: schema-absent base {base}; informational census provenance {}",
        snapshot.source_commit
    );
    Ok(snapshot.policy)
}

pub fn verify_source(
    root: &Path,
    tools: &Path,
    policy: &AuthorityDebtCeilings,
) -> Result<(), DebtError> {
    policy.validate()?;
    let source = SourceCensus::load(root)?;
    policy.check_counts(&source_counts(root, tools, policy, &source)?)
}

pub fn verify_host(
    result: &Value,
    policy: &AuthorityDebtCeilings,
    source: &SourceCensus,
) -> Result<(), DebtError> {
    policy.validate()?;
    policy.check_counts(&host_counts(result, policy, source)?)
}

pub fn run(root: &Path, args: &AuthorityDebtArgs) -> Result<(), DebtError> {
    let root = root.canonicalize()?;
    let base = comparison_base(&root, args.base.as_deref())?;
    let policy: AuthorityDebtCeilings =
        serde_json::from_slice(&std::fs::read(root.join(CEILINGS_PATH))?)?;
    policy.validate()?;
    if let Some(base) = &base {
        policy.ratchet(&base_policy(&root, base)?)?;
    } else {
        println!(
            "authority debt delta: no change range (no base provided); delta ratchet not applicable"
        );
    }
    let source = SourceCensus::load(&root)?;
    let counts = source_counts(&root, &root, &policy, &source)?;
    policy.check_counts(&counts)?;
    if !args.source_only {
        let mut discovery_args = vec![
            root.join("scripts/migrate/check-host-authority-transitions.py")
                .into_os_string(),
            "--root".into(),
            root.as_os_str().to_owned(),
        ];
        if let Some(target) = &args.cross_target {
            let profile = match target.as_str() {
                "x86_64-unknown-freebsd" => "freebsd-*",
                "x86_64-unknown-netbsd" => "netbsd-*",
                _ => return fail("unsupported explicit cross-discovery target"),
            };
            for (flag, value) in [
                ("--profiles", Some(profile)),
                ("--cross-target", Some(target.as_str())),
                ("--cross-cc", args.cross_cc.as_deref()),
                ("--cross-cflags", args.cross_cflags.as_deref()),
                ("--cross-ar", args.cross_ar.as_deref()),
            ] {
                let value = value
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| DebtError::Policy(format!("missing explicit {flag}")))?;
                discovery_args.push(format!("{flag}={value}").into());
            }
        }
        let output = command::run_checked("python3", discovery_args, Some(&root))?;
        let result: Value = serde_json::from_str(&output.stdout)?;
        policy.check_counts(&host_counts(&result, &policy, &source)?)?;
        println!(
            "live host discovery passed; executed: {}; pending: {}",
            result["executed_profiles"], result["pending_profiles"]
        );
    }
    if let Some(base) = base {
        println!("authority debt PR-base ratchet passed ({base})");
    }
    println!(
        "authority debt ceilings passed; source counters: {}",
        counts.len()
    );
    Ok(())
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    #[test]
    fn schema_absent_base_accepts_a_different_informational_sha() {
        let base = tempfile::tempdir().unwrap();
        let tools = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        assert!(initial_base_policy(base.path(), "test-only-main-advance", tools).is_ok());
    }

    #[test]
    fn initial_bootstrap_refuses_schema_base() -> Result<(), DebtError> {
        let tools = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| DebtError::Policy("missing tool root".into()))?;
        let base = tempfile::tempdir()?;
        let path = base.path().join(CEILINGS_PATH);
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| DebtError::Policy("missing parent".into()))?,
        )?;
        std::fs::write(path, "{\"schema\":1,\"counters\":[]}")?;
        let snapshot =
            read_json(&tools.join("scripts/migrate/authority-initial-base-counts.json"))?;
        let result = initial_base_policy(base.path(), text(&snapshot, "source_commit")?, tools);
        assert!(
            matches!(result, Err(DebtError::Policy(message)) if message.contains("bootstrap is unreachable"))
        );
        Ok(())
    }
}
