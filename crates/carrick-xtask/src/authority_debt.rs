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
    pub fn source(file: &str) -> Self {
        if file.contains("carrick-vmm-hvf/") {
            Self::Hvf
        } else if file.contains("carrick-vmm-kvm/") {
            Self::Kvm
        } else if file.contains("carrick-vmm-bhyve/") {
            Self::Bhyve
        } else if file.contains("carrick-vmm-nvmm/") {
            Self::Nvmm
        } else if file.contains("carrick-x86/") || file.contains("/x86_") {
            Self::X86
        } else if file.contains("carrick-host-linux/") {
            Self::Linux
        } else if file.contains("carrick-host-bsd/") {
            Self::Bsd
        } else if file.contains("carrick-host-darwin/") {
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
            if host != counter.lane.is_profile() {
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
    /// Actual PR comparison base, supplied by CI or resolved against github/main.
    #[arg(long)]
    pub base: Option<String>,
    /// Run source and ratchet checks only. Live compiler coverage is still pending.
    #[arg(long)]
    pub source_only: bool,
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
fn symbol_owner(file: &str, symbol: &str) -> Result<String, DebtError> {
    let krate = file
        .split('/')
        .nth(1)
        .ok_or_else(|| DebtError::Policy("missing crate owner".into()))?;
    Ok(format!("{}::{}", krate.replace('-', "_"), unsalt(symbol)))
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
fn discover(root: &Path, checker: &str, tools: &Path) -> Result<Value, DebtError> {
    let output = command::run_checked(
        "python3",
        [
            tools
                .join(format!("scripts/migrate/{checker}.py"))
                .as_os_str(),
            std::ffi::OsStr::new("--root"),
            root.as_os_str(),
            std::ffi::OsStr::new("--discover"),
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
    let mut actual = BTreeMap::new();
    for row in rows(&discover(root, "check-dispatch-lock-authority", tools)?)? {
        let file = text(row, "file")?;
        let line = row["line"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("missing lock diagnostic line".into()))?
            as usize;
        let owner = source.owner_at(file, line, 0)?;
        let operation = text(row, "category")?;
        let lane = Lane::source(file);
        policy.assign(&[Family::RawLock], operation, &owner, lane)?;
        add(&mut actual, Family::RawLock, operation, &owner, lane);
    }
    for site in &source.k1 {
        let family = policy.assign(K1_FAMILIES, &site.operation, &site.owner, site.lane)?;
        add(&mut actual, family, &site.operation, &site.owner, site.lane);
    }
    for row in rows(&discover(root, "check-runtime-global-state", tools)?)? {
        let file = text(row, "file")?;
        if source.is_test_file(file) {
            continue;
        }
        let owner = symbol_owner(file, text(row, "symbol")?)?;
        let operation = format!("global:{}", text(row, "kind")?);
        let lane = Lane::source(file);
        let family = policy.assign(GLOBAL_FAMILIES, &operation, &owner, lane)?;
        add(&mut actual, family, &operation, &owner, lane);
    }
    for row in rows(&discover(root, "check-runtime-aborts", tools)?)? {
        let file = text(row, "file")?;
        let owner = symbol_owner(file, text(row, "function")?)?;
        let operation = format!("fatal:{}", text(row, "domain")?);
        let lane = Lane::source(file);
        let family = policy.assign(FATAL_FAMILIES, &operation, &owner, lane)?;
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
            let family = policy.assign(HOST_FAMILIES, operation, &owner, lane)?;
            add(&mut actual, family, operation, &owner, lane);
        }
    }
    Ok(actual)
}
fn comparison_base(root: &Path, explicit: Option<&str>) -> Result<String, DebtError> {
    let environment = std::env::var("CARRICK_AUTHORITY_BASE").ok();
    let base = if let Some(base) = explicit.or(environment.as_deref()) {
        base.to_string()
    } else {
        command::run_checked("git", ["merge-base", "HEAD", "github/main"], Some(root))?
            .stdout
            .trim()
            .to_string()
    };
    Ok(command::run_checked(
        "git",
        ["rev-parse", "--verify", &format!("{base}^{{commit}}")],
        Some(root),
    )?
    .stdout
    .trim()
    .to_string())
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
        .args(["archive", base, "crates", "scripts/migrate"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return fail("cannot read PR-base source for initial migration");
    }
    let temporary = tempfile::tempdir()?;
    tar::Archive::new(output.stdout.as_slice()).unpack(temporary.path())?;
    legacy_policy_with_tools(temporary.path(), root)
}
// One-time transition from the actual PR-base ledgers. Their locations serve
// only to recover symbolic cohorts from that revision, never as head identity.
fn legacy_policy_with_tools(root: &Path, tools: &Path) -> Result<AuthorityDebtCeilings, DebtError> {
    let canonical = root.canonicalize()?;
    let root = canonical.as_path();
    let source = SourceCensus::load(root)?;
    let mut counters = BTreeMap::<Key, u64>::new();
    for row in rows(&discover(root, "check-dispatch-lock-authority", tools)?)? {
        let file = text(row, "file")?;
        let line = row["line"]
            .as_u64()
            .ok_or_else(|| DebtError::Policy("invalid historical lock diagnostic".into()))?
            as usize;
        add(
            &mut counters,
            Family::RawLock,
            text(row, "category")?,
            &source.owner_at(file, line, 0)?,
            Lane::source(file),
        );
    }
    let taxonomy =
        read_json(&root.join("scripts/migrate/k1-file-authority-callsite-taxonomy.json"))?;
    // Use the old taxonomy solely to assign a closed migration family to each
    // owner/API. Actual counts come from production AST calls, not line text.
    for site in &source.k1 {
        let entries = rows(&taxonomy["entries"])?;
        let exact = entries.iter().find(|r| {
            r["file"].as_str() == Some(&site.file)
                && r["line"].as_u64() == Some(site.line as u64)
                && r["scope_kind"] == "production_callsite"
        });
        let candidates: Vec<_> = entries
            .iter()
            .filter(|r| {
                r["file"].as_str() == Some(&site.file) && r["scope_kind"] == "production_callsite"
            })
            .filter(|r| {
                r["line"].as_u64().is_some_and(|line| {
                    source
                        .owner_at(&site.file, line as usize, 0)
                        .is_ok_and(|owner| owner == site.owner)
                })
            })
            .collect();
        let same_api: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|r| {
                r["text"]
                    .as_str()
                    .is_some_and(|text| text.contains(&site.operation))
            })
            .collect();
        let cohort = if same_api.is_empty() {
            &candidates
        } else {
            &same_api
        };
        let families: BTreeSet<_> = cohort
            .iter()
            .filter_map(|r| r["migration_family"].as_str())
            .collect();
        let row = if let Some(row) = exact {
            row
        } else if families.len() == 1 {
            cohort[0]
        } else if families.is_empty()
            && ["read_for_io", "write_for_io", "inspect", "try_inspect"]
                .contains(&site.operation.as_str())
        {
            // Multiline description accesses were omitted by the retired
            // same-line regex. Classify their actual API effect directly.
            let family = match site.operation.as_str() {
                "read_for_io" => Family::K1ReadAttempt,
                "write_for_io" => Family::K1WriteAttempt,
                _ => Family::K1InspectMisc,
            };
            add(
                &mut counters,
                family,
                &site.operation,
                &site.owner,
                site.lane,
            );
            continue;
        } else {
            return fail(format!(
                "base K1 API lacks unambiguous reviewed family: {}:{} {} ({families:?})",
                site.file, site.line, site.operation
            ));
        };
        let family: Family = serde_json::from_value(Value::String(format!(
            "k1_{}",
            text(row, "migration_family")?
        )))?;
        add(
            &mut counters,
            family,
            &site.operation,
            &site.owner,
            site.lane,
        );
    }
    // The old "test_only" label included unconditional production failpoints.
    // Filter real test scopes, rather than trusting those labels as scope.
    // The stronger zero rule applies to head, not to this historical census.
    let output = command::run_checked(
        "python3",
        [
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(
                "import importlib.util,json,pathlib,sys; s=importlib.util.spec_from_file_location('globals',sys.argv[1]); m=importlib.util.module_from_spec(s); sys.modules[s.name]=m; s.loader.exec_module(m); print(json.dumps([{'file':f.file,'kind':f.kind,'symbol':f.symbol} for f in m.discover(pathlib.Path(sys.argv[2]))]))",
            ),
            tools
                .join("scripts/migrate/check-runtime-global-state.py")
                .as_os_str(),
            root.as_os_str(),
        ],
        Some(root),
    )?;
    let production: Value = serde_json::from_str(&output.stdout)?;
    let production: BTreeSet<_> = rows(&production)?
        .iter()
        .map(|row| {
            Ok((
                text(row, "file")?.to_owned(),
                text(row, "kind")?.to_owned(),
                unsalt(text(row, "symbol")?),
            ))
        })
        .collect::<Result<_, DebtError>>()?;
    for row in rows(&read_json(&root.join("scripts/migrate/runtime-global-state.json"))?["rows"])? {
        if source.is_test_file(text(row, "file")?)
            || !production.contains(&(
                text(row, "file")?.to_owned(),
                text(row, "kind")?.to_owned(),
                unsalt(text(row, "symbol")?),
            ))
        {
            continue;
        }
        let file = text(row, "file")?;
        let family: Family = serde_json::from_value(Value::String(format!(
            "global_{}",
            text(row, "classification")?
        )))?;
        add(
            &mut counters,
            family,
            &format!("global:{}", text(row, "kind")?),
            &symbol_owner(file, text(row, "symbol")?)?,
            Lane::source(file),
        );
    }
    for shard in ["hvf", "runtime", "vcpu-loop", "other"] {
        for row in rows(
            &read_json(&root.join(format!("scripts/migrate/runtime-aborts/{shard}.json")))?["rows"],
        )? {
            let file = text(row, "file")?;
            let family: Family =
                serde_json::from_value(Value::String(format!("fatal_{}", text(row, "verdict")?)))?;
            add(
                &mut counters,
                family,
                &format!("fatal:{}", text(row, "domain")?),
                &symbol_owner(file, text(row, "function")?)?,
                Lane::source(file),
            );
        }
    }
    for row in rows(&read_json(
        &root.join("scripts/migrate/host-authority-transition-inventory.json"),
    )?)? {
        let point = if row["expansion"].is_object() {
            &row["expansion"]
        } else {
            &row["source"]
        };
        let owner = source.owner_at(
            text(point, "file")?,
            point["line_start"]
                .as_u64()
                .ok_or_else(|| DebtError::Policy("invalid legacy host line".into()))?
                as usize,
            point["column_start"]
                .as_u64()
                .unwrap_or(1)
                .saturating_sub(1) as usize,
        )?;
        let family = match text(row, "classification")? {
            "declared_substrate" => Family::HostSubstrate,
            "declared_backing" => Family::HostBacking,
            "forbidden_semantic" => Family::HostForbiddenSemantic,
            unknown => return fail(format!("unknown host classification {unknown}")),
        };
        for profile in rows(&row["profiles"])? {
            add(
                &mut counters,
                family,
                text(row, "operation")?,
                &owner,
                Lane::profile(
                    profile
                        .as_str()
                        .ok_or_else(|| DebtError::Policy("invalid profile".into()))?,
                )?,
            );
        }
    }
    // A mixed cohort retains the stronger semantic/error debt classification.
    // No per-site locations are needed to distinguish calls within that owner.
    let mut combined: BTreeMap<(String, String, Lane), (Family, u64)> = BTreeMap::new();
    for (key, count) in counters {
        let entry = combined
            .entry((key.operation, key.owner, key.lane))
            .or_insert((key.family, 0));
        entry.1 += count;
        if key.family > entry.0 {
            entry.0 = key.family;
        }
    }
    let policy = AuthorityDebtCeilings {
        schema: 1,
        counters: combined
            .into_iter()
            .map(|((operation, owner, lane), (family, ceiling))| Counter {
                family,
                operation,
                owner,
                lane,
                ceiling,
            })
            .collect(),
    };
    policy.validate()?;
    Ok(policy)
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
    policy.ratchet(&base_policy(&root, &base)?)?;
    let source = SourceCensus::load(&root)?;
    let counts = source_counts(&root, &root, &policy, &source)?;
    policy.check_counts(&counts)?;
    if !args.source_only {
        let output = command::run_checked(
            "python3",
            [
                root.join("scripts/migrate/check-host-authority-transitions.py")
                    .as_os_str(),
                std::ffi::OsStr::new("--root"),
                root.as_os_str(),
            ],
            Some(&root),
        )?;
        let result: Value = serde_json::from_str(&output.stdout)?;
        policy.check_counts(&host_counts(&result, &policy, &source)?)?;
        println!(
            "live host discovery passed; executed: {}; pending: {}",
            result["executed_profiles"], result["pending_profiles"]
        );
    }
    println!(
        "authority debt ceilings and PR-base ratchet passed ({base}); source counters: {}",
        counts.len()
    );
    Ok(())
}
