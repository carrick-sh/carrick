//! `carrick debug discover`: full-depth diagnosis of parity rows.
//!
//! A parity row (go build, pip, npm, a dev shell) dies at its first failure,
//! so each landing buys one new stop. This command runs every row's stages N
//! times through `carrick run`, each stage from a fresh container so a stage
//! that dies early never hides a later stage's failures, and records every
//! failure each run produced, not only the first:
//!
//! - every counted refusal from the run's EL1 census (`refusal_evidence`),
//!   with the arguments of the refused calls the census kept
//!   (`refused_calls`, #2690);
//! - every carrier fatal site (`carrick fatal [<domain>]: <message>`), Rust
//!   panic location and carrier error (`carrick: <error chain>`, the
//!   rc-125 refusals such as `physical fork source residency capacity`) on
//!   the carrier's stderr;
//! - every errno the guest itself reported on its streams (`Function not
//!   implemented`, `... (38)`), a wrong-errno candidate;
//! - every contention leave the census counted (`anonymous_leaves`,
//!   `ipc_leaves`);
//! - a timeout, a nonzero exit, or a missing success marker;
//! - for a run past its timeout, what the hung carrier was doing: its live
//!   `carrick debug zonedump` (parked records' saved syscalls, vCPUs and
//!   tasks holding unserved host work) and its syscall census so far
//!   (`zonedump --census-out`), both read before the kill, since a killed
//!   carrier publishes no census: a hung stage keeps its refusals and their
//!   arguments;
//! - with `--oracle`, each stage that passes at 5x the native Docker
//!   oracle's time or more (`pathological_time`);
//! - with `--venue-profile <row>=<file>`, each call shape the row makes on
//!   the native oracle that Carrick's static route answers ENOSYS, on either
//!   ISA (`venue_gap`, from `crate::venue_gaps`): the stops past the ones the
//!   runs reached. Each gap is joined with the runs' counted refusals: it is
//!   `reached` when a run of its row on its ISA refused that call for that
//!   caller, `not yet reached` when every run of the row wrote a census
//!   and none refused it, and `no evidence` when a run of the row wrote no
//!   census, so nothing says whether it made the call.
//!
//! The output is one ranked table (instance, ISA, row, stage, kind, site,
//! count, runs, real values) in `<out>/table.md` and `<out>/table.json`, and
//! one JSON line per run in `<out>/runs.jsonl`. `--report <out>` re-renders
//! the table from a finished directory without running anything.
//!
//! Diagnostics only: nothing here changes what a guest sees, and the census
//! it reads is the same opt-in `CARRICK_EL1_CENSUS` every run can write.

use anyhow::{Context, Result, bail, ensure};
use carrick_guest_arch::GuestIsa;
use carrick_runtime::el1_census::{Census, RefusalRank};
use carrick_spec::syscall_census::{CallerClass, CensusIsa};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

mod soft;

/// Where `discover` runs the rows: carrick carriers on this host's ISA, or
/// each row's first single process on the soft AArch64 CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub(crate) enum Provider {
    /// `carrick run` on this host's hypervisor.
    #[default]
    Hardware,
    /// `carrick debug soft-run` from the row's arm64 image (Linux arm64 hosts).
    SoftA64,
}

/// The ISA a row runs on: the host's, since a carrier runs its own ISA.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RowIsa {
    Arm64,
    X86_64,
}

impl RowIsa {
    pub(crate) fn host() -> Result<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Ok(Self::Arm64),
            "x86_64" => Ok(Self::X86_64),
            other => bail!("no parity rows for host architecture {other}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X86_64 => "x86_64",
        }
    }
}

impl From<CensusIsa> for RowIsa {
    fn from(isa: CensusIsa) -> Self {
        match isa {
            CensusIsa::Aarch64 => Self::Arm64,
            CensusIsa::X86_64 => Self::X86_64,
        }
    }
}

/// A rows file: `{"rows": [...]}`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowsFile {
    pub(crate) rows: Vec<RowSpec>,
}

/// One parity row: an image per ISA and the stages to run in it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowSpec {
    pub(crate) name: String,
    /// The pinned image reference for each ISA the row runs on.
    pub(crate) image: BTreeMap<RowIsa, String>,
    /// A stage's timeout unless the stage names its own.
    pub(crate) timeout_secs: u64,
    pub(crate) stages: Vec<StageSpec>,
}

/// One independently runnable step of a row, started in a fresh container.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageSpec {
    pub(crate) name: String,
    /// The guest argv (`carrick run <image> <command...>`).
    pub(crate) command: Vec<String>,
    /// A line the guest prints on success; absent means exit 0 is success.
    #[serde(default)]
    pub(crate) expect: Option<String>,
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
    /// Known answers by ISA: each must be a substring of some finding's
    /// key (`<kind> <site>`) in every run on that ISA, or the command fails.
    /// The known-answer rows use them to prove the tool before anything
    /// relies on it.
    #[serde(default)]
    pub(crate) known_answer: BTreeMap<RowIsa, Vec<String>>,
}

pub(crate) fn load_rows(path: &Path) -> Result<RowsFile> {
    let bytes = std::fs::read(path).with_context(|| format!("read rows {}", path.display()))?;
    let rows: RowsFile =
        serde_json::from_slice(&bytes).with_context(|| format!("parse rows {}", path.display()))?;
    let mut names = BTreeSet::new();
    for row in &rows.rows {
        ensure!(names.insert(&row.name), "row {} is listed twice", row.name);
        ensure!(!row.stages.is_empty(), "row {} has no stages", row.name);
        let mut stages = BTreeSet::new();
        for stage in &row.stages {
            ensure!(
                stages.insert(&stage.name),
                "row {} lists stage {} twice",
                row.name,
                stage.name
            );
            ensure!(
                !stage.command.is_empty(),
                "row {} stage {} has an empty command",
                row.name,
                stage.name
            );
            ensure!(
                is_label(&row.name) && is_label(&stage.name),
                "row and stage names are [A-Za-z0-9_.-]+ (they name files and run ids): {}/{}",
                row.name,
                stage.name
            );
        }
    }
    Ok(rows)
}

fn is_label(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        && name != "."
        && name != ".."
}

/// What a finding is. Ordered by how much it says about the row: a carrier
/// fatal first, contention leaves last.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingKind {
    Fatal,
    Panic,
    CarrierError,
    Timeout,
    /// What a carrier past its stage timeout was doing: its scheduler zone,
    /// read live through `carrick debug zonedump` before the kill.
    Hang,
    /// A stage that passes, but at a pathological multiple of the native
    /// Docker oracle's time (`--oracle`): structurally wrong work.
    Pathological,
    Refused,
    /// A call shape the row makes on the native oracle that Carrick's static
    /// route answers ENOSYS (`--venue-profile`). No run produced it: it is a
    /// stop past the ones the runs reached.
    VenueGap,
    GuestErrno,
    Exit,
    MissingMarker,
    NoCensus,
    AnonymousLeave,
    IpcLeave,
}

impl FindingKind {
    fn name(self) -> &'static str {
        match self {
            Self::Fatal => "fatal",
            Self::Panic => "panic",
            Self::CarrierError => "carrier_error",
            Self::Timeout => "timeout",
            Self::Hang => "hang",
            Self::Pathological => "pathological_time",
            Self::Refused => "refused",
            Self::VenueGap => "venue_gap",
            Self::GuestErrno => "guest_errno",
            Self::Exit => "exit",
            Self::MissingMarker => "missing_marker",
            Self::NoCensus => "no_census",
            Self::AnonymousLeave => "anonymous_leave",
            Self::IpcLeave => "ipc_leave",
        }
    }
}

/// One failure site one run produced, with how often and the real values
/// behind it (refused-call registers, the fatal message, the guest's line).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Finding {
    pub(crate) kind: FindingKind,
    pub(crate) site: String,
    pub(crate) count: u64,
    #[serde(default)]
    pub(crate) values: Vec<String>,
}

impl Finding {
    fn new(kind: FindingKind, site: impl Into<String>, count: u64) -> Self {
        Self {
            kind,
            site: site.into(),
            count,
            values: Vec::new(),
        }
    }

    fn key(&self) -> String {
        format!("{} {}", self.kind.name(), self.site)
    }
}

/// One run of one stage.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RunRecord {
    pub(crate) instance: String,
    pub(crate) isa: RowIsa,
    pub(crate) row: String,
    pub(crate) stage: String,
    pub(crate) run: u32,
    pub(crate) run_id: String,
    pub(crate) image: String,
    /// The carrier's exit code; `None` when a signal ended it.
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) secs: f64,
    pub(crate) passed: bool,
    pub(crate) findings: Vec<Finding>,
}

const MAX_VALUES: usize = 3;

fn push_value(values: &mut Vec<String>, value: String) {
    if values.len() < MAX_VALUES && !values.contains(&value) {
        values.push(value);
    }
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// Replace runs of digits and hex literals so one site keys the same in
/// every run (pids, addresses and timings differ run to run).
fn shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            out.push_str("0x#");
            continue;
        }
        if bytes[i].is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            out.push('#');
            continue;
        }
        let c = line[i..].chars().next().unwrap_or(' ');
        out.push(c);
        i += c.len_utf8();
    }
    let mut trimmed: String = out.trim().chars().take(160).collect();
    trimmed = trimmed.replace('|', "/");
    trimmed
}

/// Errnos a guest program names on its streams: libc's strerror text, or a
/// failure that prints the number in parentheses (apt's `Select has failed
/// (38)`). Only errnos a Carrick gap plausibly causes; ENOENT and EACCES are
/// left out because programs print them on correct paths all the time.
const ERRNO_TEXT: &[(&str, &str)] = &[
    ("function not implemented", "ENOSYS"),
    ("operation not permitted", "EPERM"),
    ("bad file descriptor", "EBADF"),
    ("invalid argument", "EINVAL"),
    ("cannot allocate memory", "ENOMEM"),
    ("resource temporarily unavailable", "EAGAIN"),
    ("operation not supported", "EOPNOTSUPP"),
    ("function not supported", "EOPNOTSUPP"),
    ("protocol not available", "ENOPROTOOPT"),
    ("address family not supported", "EAFNOSUPPORT"),
    ("inappropriate ioctl for device", "ENOTTY"),
    ("no such device", "ENODEV"),
    ("bad address", "EFAULT"),
    ("interrupted system call", "EINTR"),
    ("too many open files", "EMFILE"),
    ("broken pipe", "EPIPE"),
    ("enosys", "ENOSYS"),
    ("errno 38", "ENOSYS"),
    ("errno=38", "ENOSYS"),
    ("(38)", "ENOSYS"),
    ("errno 22", "EINVAL"),
    ("errno=22", "EINVAL"),
];

fn guest_errno(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    ERRNO_TEXT
        .iter()
        .find(|(text, _)| lower.contains(text))
        .map(|(_, errno)| *errno)
}

/// Findings from a carrier's stderr and the guest's streams: carrier fatal
/// sites, Rust panic locations and guest-reported errnos.
pub(crate) fn stream_findings(stderr: &str, stdout: &str) -> Vec<Finding> {
    let mut by_key: BTreeMap<(FindingKind, String), Finding> = BTreeMap::new();
    let mut add = |kind: FindingKind, site: String, value: String| {
        let entry = by_key
            .entry((kind, site.clone()))
            .or_insert_with(|| Finding::new(kind, site, 0));
        entry.count += 1;
        push_value(&mut entry.values, value);
    };
    let mut lines = stderr.lines().map(strip_ansi).peekable();
    while let Some(line) = lines.next() {
        if let Some(rest) = line.split("carrick fatal [").nth(1)
            && let Some((domain, message)) = rest.split_once("]: ")
        {
            add(
                FindingKind::Fatal,
                format!("[{domain}] {}", shape(message)),
                message.trim().chars().take(300).collect(),
            );
            continue;
        }
        if let Some(rest) = line.split("panicked at ").nth(1) {
            // `thread 'x' panicked at <file>:<line>:<col>:` then the message.
            let location = rest.trim_end_matches(':').to_owned();
            let message = lines.peek().cloned().unwrap_or_default();
            add(
                FindingKind::Panic,
                location,
                message.trim().chars().take(300).collect(),
            );
            continue;
        }
        if let Some(error) = carrier_error(&line) {
            add(
                FindingKind::CarrierError,
                shape(error),
                error.trim().chars().take(300).collect(),
            );
            continue;
        }
        if let Some(errno) = guest_errno(&line) {
            add(
                FindingKind::GuestErrno,
                format!("{errno}: {}", shape(&line)),
                line.trim().chars().take(300).collect(),
            );
        }
    }
    for line in stdout.lines().map(strip_ansi) {
        if let Some(errno) = guest_errno(&line) {
            add(
                FindingKind::GuestErrno,
                format!("{errno}: {}", shape(&line)),
                line.trim().chars().take(300).collect(),
            );
        }
    }
    by_key.into_values().collect()
}

/// The carrier's own terminal error: `carrick: <error chain>` on its stderr
/// (anyhow's chain, such as `configuration refused: hypervisor operation
/// failed: physical fork source residency capacity`). Progress lines the
/// carrier prints with the same prefix (`carrick: image ... pulling`) are
/// not errors.
fn carrier_error(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("carrick: ")?;
    const ERROR_WORDS: &[&str] = &[
        "failed",
        "refused",
        "error",
        "denied",
        "invalid",
        "unexpected",
    ];
    let lower = rest.to_ascii_lowercase();
    ERROR_WORDS
        .iter()
        .any(|word| lower.contains(word))
        .then_some(rest)
}

fn caller_name(caller: CallerClass) -> &'static str {
    match caller {
        CallerClass::Root => "root",
        CallerClass::NativeChild => "child",
    }
}

/// Findings from one run's censuses: every refusal with its recorded calls'
/// arguments, and every contention leave.
pub(crate) fn census_findings(censuses: &[Census]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if censuses.is_empty() {
        findings.push(Finding::new(FindingKind::NoCensus, "no census file", 1));
        return findings;
    }
    if let Ok(ranking) = carrick_runtime::el1_census::rank_refusals(censuses) {
        if !ranking.complete {
            findings.push(Finding::new(
                FindingKind::NoCensus,
                "incomplete refusal evidence",
                ranking.incomplete_runs as u64,
            ));
        }
        for rank in &ranking.rows {
            for (venue, count) in [("ring", rank.unrouted), ("carrier", rank.carrier)] {
                if count == 0 {
                    continue;
                }
                let mut finding =
                    Finding::new(FindingKind::Refused, refusal_site(rank, venue), count);
                for census in censuses {
                    for call in &census.refused_calls {
                        if call.nr == rank.native_nr
                            && call.caller == rank.caller
                            && call.venue == venue
                        {
                            push_value(&mut finding.values, call.line());
                        }
                    }
                }
                findings.push(finding);
            }
        }
    }
    let dropped: u64 = censuses.iter().map(|c| c.refused_calls_dropped).sum();
    if dropped != 0 {
        findings.push(Finding::new(
            FindingKind::NoCensus,
            "refused-call records dropped",
            dropped,
        ));
    }
    let mut anonymous: BTreeMap<&str, u64> = BTreeMap::new();
    let mut ipc: BTreeMap<&str, u64> = BTreeMap::new();
    for census in censuses {
        for (name, count) in &census.anonymous_leaves {
            *anonymous.entry(name).or_default() += count;
        }
        for (name, count) in &census.ipc_leaves {
            *ipc.entry(name).or_default() += count;
        }
    }
    for (name, count) in anonymous {
        findings.push(Finding::new(FindingKind::AnonymousLeave, name, count));
    }
    for (name, count) in ipc {
        findings.push(Finding::new(FindingKind::IpcLeave, name, count));
    }
    findings
}

fn refusal_site(rank: &RefusalRank, venue: &str) -> String {
    format!(
        "{}(nr={}) caller={} venue={}{}",
        rank.name,
        rank.native_nr,
        caller_name(rank.caller),
        venue,
        if rank.allowlisted { " allowlisted" } else { "" }
    )
}

/// The call and caller a refusal site (`refusal_site`) or a venue-gap site
/// (`venue_gap_rows`) names: the text before the first `(` or space, and the
/// `caller=` token.
fn site_call(site: &str) -> Option<(&str, &str)> {
    let name = &site[..site.find(['(', ' '])?];
    Some((name, token(site, "caller")?))
}

/// Read every census JSON a run wrote into its census directory.
fn load_censuses(directory: &Path) -> Result<Vec<Census>> {
    let mut censuses = Vec::new();
    let Ok(entries) = crate::debug_el1_census::collect(directory) else {
        return Ok(censuses);
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let bytes =
            std::fs::read(&path).with_context(|| format!("read census {}", path.display()))?;
        censuses.push(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parse census {}", path.display()))?,
        );
    }
    Ok(censuses)
}

/// How one carrier process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ending {
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) timed_out: bool,
}

/// The value of `key=` in a zonedump line: up to the next space, or up to
/// the closing bracket of a `[...]` list.
fn token<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(" {key}=");
    let start = if let Some(rest) = line.strip_prefix(&needle[1..]) {
        line.len() - rest.len()
    } else {
        line.find(&needle)? + needle.len()
    };
    let rest = &line[start..];
    let end = if rest.starts_with('[') {
        rest.find(']').map_or(rest.len(), |i| i + 1)
    } else {
        rest.find(' ').unwrap_or(rest.len())
    };
    Some(&rest[..end])
}

/// Findings from a hung carrier's zonedump (`carrick debug zonedump
/// --run-id`, taken at the stage timeout before the kill): every parked
/// record's saved syscall, every vCPU and task that holds host work nobody
/// served. A dump that read no zone is one site, so a hang never reads as
/// "no evidence" silently.
pub(crate) fn hang_findings(isa: RowIsa, zonedump: &str) -> Vec<Finding> {
    let census_isa = match isa {
        RowIsa::Arm64 => CensusIsa::Aarch64,
        RowIsa::X86_64 => CensusIsa::X86_64,
    };
    let mut by_site: BTreeMap<String, Finding> = BTreeMap::new();
    let mut add = |site: String, value: String| {
        let entry = by_site
            .entry(site.clone())
            .or_insert_with(|| Finding::new(FindingKind::Hang, site, 0));
        entry.count += 1;
        push_value(&mut entry.values, value);
    };
    let mut read_zone = false;
    for line in zonedump.lines().map(str::trim) {
        read_zone |= line.starts_with("zone slot ");
        if line.starts_with("zone record ") && line.contains(" parked: ") {
            let Some(nr) = token(line, "saved_nr").and_then(|n| n.parse::<u64>().ok()) else {
                continue;
            };
            add(
                format!(
                    "parked in {}(nr={nr}) resume={}",
                    carrick_runtime::el1_census::refusal_name(census_isa, nr),
                    token(line, "resume").unwrap_or("?")
                ),
                format!(
                    "saved_args={} saved_pc={}",
                    token(line, "saved_args").unwrap_or("?"),
                    token(line, "saved_pc").unwrap_or("?")
                ),
            );
        } else if line.starts_with("vcpu:") && token(line, "pending_host_work") == Some("true") {
            add(
                "vcpu holds unserved host work".to_owned(),
                format!(
                    "cpu={} phase={} served_with_work={} last_stopped_rip={}",
                    token(line, "cpu").unwrap_or("?"),
                    token(line, "phase").unwrap_or("?"),
                    token(line, "served_with_work").unwrap_or("?"),
                    token(line, "last_stopped_rip")
                        .or_else(|| token(line, "last_stopped_pc"))
                        .unwrap_or("?")
                ),
            );
        } else if line.starts_with("el1 task slot ")
            && token(line, "pending_host_work").is_some_and(|n| n != "0")
        {
            add(
                "task holds unserved host work".to_owned(),
                format!(
                    "tid={} pid={} mm={} pending_host_work={} service_notice={}",
                    token(line, "tid").unwrap_or("?"),
                    token(line, "pid").unwrap_or("?"),
                    token(line, "mm").unwrap_or("?"),
                    token(line, "pending_host_work").unwrap_or("?"),
                    token(line, "service_notice").unwrap_or("?")
                ),
            );
        }
    }
    if !read_zone {
        let first = zonedump
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("(empty)");
        add(
            "zonedump read no zone".to_owned(),
            first.trim().chars().take(300).collect(),
        );
    }
    by_site.into_values().collect()
}

/// Whether the stage's success marker is a line of its stdout (always, when
/// it names none).
fn marker_seen(stage: &StageSpec, stdout: &str) -> bool {
    stage
        .expect
        .as_deref()
        .is_none_or(|marker| stdout.lines().any(|line| line.trim() == marker))
}

/// A passing stage at this multiple of the native oracle's median time or
/// more is pathological: AGENTS.md counts a 5x ratio as structurally wrong
/// work, a correctness bug, not a performance gap (the perf bar is 2x).
pub(crate) const PATHOLOGICAL_RATIO: f64 = 5.0;

/// The smallest oracle time a ratio divides by, so a stage the oracle runs
/// in a few milliseconds is not flagged for carrick's fixed start cost.
const MIN_ORACLE_SECS: f64 = 0.25;

/// One run of one stage on the native Docker oracle (`--oracle`), in the
/// Docker-only phase before any carrick run.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OracleRecord {
    pub(crate) isa: RowIsa,
    pub(crate) row: String,
    pub(crate) stage: String,
    pub(crate) run: u32,
    pub(crate) image: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) secs: f64,
    pub(crate) passed: bool,
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

type StageKey = (RowIsa, String, String);

/// Each stage's median time over its passing oracle runs.
fn oracle_medians(oracle: &[OracleRecord]) -> BTreeMap<StageKey, f64> {
    let mut by_stage: BTreeMap<StageKey, Vec<f64>> = BTreeMap::new();
    for record in oracle.iter().filter(|r| r.passed) {
        by_stage
            .entry((record.isa, record.row.clone(), record.stage.clone()))
            .or_default()
            .push(record.secs);
    }
    by_stage
        .into_iter()
        .filter_map(|(key, secs)| median(secs).map(|m| (key, m)))
        .collect()
}

/// The pathological-time rows: for each stage the oracle passed, the
/// passing carrick runs at `PATHOLOGICAL_RATIO` times its median or more.
/// A failing run's time says nothing about cost (it stopped early), and a
/// run past its timeout is already a timeout row.
fn pathological_rows(records: &[RunRecord], oracle: &[OracleRecord]) -> Vec<TableRow> {
    let medians = oracle_medians(oracle);
    let mut groups: BTreeMap<(String, RowIsa, String, String), Vec<&RunRecord>> = BTreeMap::new();
    for record in records {
        groups
            .entry((
                record.instance.clone(),
                record.isa,
                record.row.clone(),
                record.stage.clone(),
            ))
            .or_default()
            .push(record);
    }
    let mut rows = Vec::new();
    for ((instance, isa, row, stage), runs) in groups {
        let Some(&oracle_secs) = medians.get(&(isa, row.clone(), stage.clone())) else {
            continue;
        };
        let floor = oracle_secs.max(MIN_ORACLE_SECS);
        let slow: Vec<&RunRecord> = runs
            .iter()
            .copied()
            .filter(|r| r.passed && r.secs >= PATHOLOGICAL_RATIO * floor)
            .collect();
        if slow.is_empty() {
            continue;
        }
        let mut values = Vec::new();
        for run in &slow {
            push_value(
                &mut values,
                format!(
                    "run {}: carrick {:.1}s vs oracle median {:.2}s ({:.0}x)",
                    run.run,
                    run.secs,
                    oracle_secs,
                    run.secs / floor
                ),
            );
        }
        rows.push(TableRow {
            instance,
            isa,
            row,
            stage,
            kind: FindingKind::Pathological,
            site: format!("passes at >= {PATHOLOGICAL_RATIO}x the native oracle's time"),
            count: slow.len() as u64,
            runs: slow.len(),
            of_runs: runs.len(),
            values,
        });
    }
    rows
}

/// Judge one run from how it ended, its streams and its censuses.
pub(crate) fn judge(
    stage: &StageSpec,
    ending: Ending,
    stdout: &str,
    stderr: &str,
    censuses: &[Census],
) -> (bool, Vec<Finding>) {
    let mut findings = stream_findings(stderr, stdout);
    findings.extend(census_findings(censuses));
    if ending.timed_out {
        findings.push(Finding::new(FindingKind::Timeout, "stage timeout", 1));
    }
    let exited_zero = ending.exit_code == Some(0);
    if !exited_zero && !ending.timed_out {
        let site = match (ending.exit_code, ending.signal) {
            (Some(code), _) => format!("rc={code}"),
            (None, Some(signal)) => format!("signal={signal}"),
            (None, None) => "unknown".to_owned(),
        };
        let mut finding = Finding::new(FindingKind::Exit, site, 1);
        if let Some(last) = stderr
            .lines()
            .map(strip_ansi)
            .rfind(|line| !line.trim().is_empty())
        {
            push_value(&mut finding.values, last.trim().chars().take(300).collect());
        }
        findings.push(finding);
    }
    let marker_seen = marker_seen(stage, stdout);
    if !marker_seen {
        findings.push(Finding::new(
            FindingKind::MissingMarker,
            stage.expect.clone().unwrap_or_default(),
            1,
        ));
    }
    (exited_zero && marker_seen && !ending.timed_out, findings)
}

/// One aggregated row of the ranked table.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct TableRow {
    pub(crate) instance: String,
    pub(crate) isa: RowIsa,
    pub(crate) row: String,
    pub(crate) stage: String,
    pub(crate) kind: FindingKind,
    pub(crate) site: String,
    pub(crate) count: u64,
    /// Runs of this stage that produced the site.
    pub(crate) runs: usize,
    /// Runs of this stage in the input.
    pub(crate) of_runs: usize,
    pub(crate) values: Vec<String>,
}

/// The ranked table over every run: one line per (instance, ISA, row, stage,
/// site), most telling kind first, then the most runs, then the most counts.
/// With oracle runs, a stage that passes at a pathological multiple of the
/// oracle's time is a row too.
pub(crate) fn rank(records: &[RunRecord], oracle: &[OracleRecord]) -> Vec<TableRow> {
    type Key = (String, RowIsa, String, String, FindingKind, String);
    let mut of_runs: BTreeMap<(String, RowIsa, String, String), usize> = BTreeMap::new();
    let mut by_key: BTreeMap<Key, TableRow> = BTreeMap::new();
    for record in records {
        *of_runs
            .entry((
                record.instance.clone(),
                record.isa,
                record.row.clone(),
                record.stage.clone(),
            ))
            .or_default() += 1;
        for finding in &record.findings {
            let key = (
                record.instance.clone(),
                record.isa,
                record.row.clone(),
                record.stage.clone(),
                finding.kind,
                finding.site.clone(),
            );
            let entry = by_key.entry(key).or_insert_with(|| TableRow {
                instance: record.instance.clone(),
                isa: record.isa,
                row: record.row.clone(),
                stage: record.stage.clone(),
                kind: finding.kind,
                site: finding.site.clone(),
                count: 0,
                runs: 0,
                of_runs: 0,
                values: Vec::new(),
            });
            entry.count = entry.count.saturating_add(finding.count);
            entry.runs += 1;
            for value in &finding.values {
                push_value(&mut entry.values, value.clone());
            }
        }
    }
    let mut rows: Vec<TableRow> = by_key
        .into_values()
        .map(|mut row| {
            row.of_runs = of_runs
                .get(&(
                    row.instance.clone(),
                    row.isa,
                    row.row.clone(),
                    row.stage.clone(),
                ))
                .copied()
                .unwrap_or(0);
            row
        })
        .collect();
    rows.extend(pathological_rows(records, oracle));
    sort_rows(&mut rows);
    rows
}

/// The table's order: most telling kind first, then the most runs, then the
/// most counts.
fn sort_rows(rows: &mut [TableRow]) {
    rows.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(b.runs.cmp(&a.runs))
            .then(b.count.cmp(&a.count))
            .then(a.row.cmp(&b.row))
            .then(a.stage.cmp(&b.stage))
            .then(a.isa.cmp(&b.isa))
            .then(a.site.cmp(&b.site))
    });
}

/// The stage column of a venue-gap row: the oracle's profile, not a stage.
const VENUE_STAGE: &str = "oracle-profile";
/// The instance column of a venue-gap row: Carrick's static route, which no
/// host ran.
const VENUE_INSTANCE: &str = "static-route";

fn venue_dir(out: &Path) -> PathBuf {
    out.join("venue")
}

/// Admit each `--venue-profile <row>=<file>`: the row is one of the rows
/// file's and the profile parses. The profile is kept at
/// `<out>/venue/<row>/profile.txt`, so `--report` ranks it again.
fn admit_venue_profiles(rows: &RowsFile, specs: &[String], out: &Path) -> Result<()> {
    for spec in specs {
        let (row, file) = spec
            .split_once('=')
            .with_context(|| format!("--venue-profile {spec}: want <row>=<file>"))?;
        ensure!(
            rows.rows.iter().any(|known| known.name == row),
            "--venue-profile: no row named {row}"
        );
        let text =
            std::fs::read_to_string(file).with_context(|| format!("read venue profile {file}"))?;
        crate::venue_gaps::parse_profile(&text)
            .and_then(|profile| crate::venue_gaps::gap_rows(&profile).map(drop))
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("venue profile {file}"))?;
        let dir = venue_dir(out).join(row);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        std::fs::write(dir.join("profile.txt"), text)
            .with_context(|| format!("write {}", dir.join("profile.txt").display()))?;
    }
    Ok(())
}

/// One row's venue gaps: a table row per call shape and ISA whose static
/// route is a gap (`Route::is_gap`), counted by the oracle's calls.
pub(crate) fn venue_gap_rows(
    row: &str,
    profile: &crate::venue_gaps::Profile,
) -> Result<Vec<TableRow>> {
    let mut rows = Vec::new();
    for gap in crate::venue_gaps::gap_rows(profile).map_err(anyhow::Error::msg)? {
        let shape = if gap.shape.is_empty() {
            String::new()
        } else {
            format!(" [{}]", gap.shape)
        };
        for (isa, route) in &gap.routes {
            if !route.is_gap() {
                continue;
            }
            rows.push(TableRow {
                instance: VENUE_INSTANCE.to_owned(),
                isa: match isa {
                    GuestIsa::X86_64 => RowIsa::X86_64,
                    GuestIsa::Aarch64 => RowIsa::Arm64,
                },
                row: row.to_owned(),
                stage: VENUE_STAGE.to_owned(),
                kind: FindingKind::VenueGap,
                site: format!(
                    "{}{shape} caller={} route={}",
                    gap.name,
                    caller_name(gap.key.caller()),
                    route.label().replace("**", "")
                ),
                count: gap.counts.calls,
                runs: 0,
                of_runs: 0,
                values: vec![format!(
                    "native oracle nr={}: calls={} enosys={} errors={}",
                    gap.key.nr, gap.counts.calls, gap.counts.enosys, gap.counts.errors
                )],
            });
        }
    }
    Ok(rows)
}

/// Join each venue gap with the runs' counted refusals. A gap is a static
/// route; a run reaches it only if the row gets as far as making the call.
/// The gap's runs column becomes the runs of its row, on its ISA, that
/// refused the call for the same caller, out of the runs of that row, so
/// reached gaps rank first. Its values say which: `reached` with the refusal
/// count and stages, `not yet reached` when every run of the row wrote a
/// census and none refused it, `no evidence` when none refused it but a run
/// wrote no census (it may have made the call), `not run` when no run of
/// the row was on that ISA. A counted refusal
/// carries no argument shape, so a shaped gap (a socket family, say) also
/// takes the refused calls' recorded arguments.
pub(crate) fn mark_reached(venue: &mut [TableRow], records: &[RunRecord]) {
    for gap in venue
        .iter_mut()
        .filter(|row| row.kind == FindingKind::VenueGap)
    {
        let Some((name, caller)) = site_call(&gap.site) else {
            continue;
        };
        let shaped = gap.site.contains(" [");
        let (name, caller) = (name.to_owned(), caller.to_owned());
        let mut refused = 0u64;
        let mut stages = BTreeSet::new();
        let mut recorded = Vec::new();
        let mut blind = 0usize;
        gap.runs = 0;
        gap.of_runs = 0;
        for record in records {
            if record.isa != gap.isa || record.row != gap.row {
                continue;
            }
            gap.of_runs += 1;
            let mut hit = false;
            for finding in &record.findings {
                blind += usize::from(finding.kind == FindingKind::NoCensus);
                if finding.kind == FindingKind::Refused
                    && site_call(&finding.site) == Some((name.as_str(), caller.as_str()))
                {
                    hit = true;
                    refused = refused.saturating_add(finding.count);
                    for value in &finding.values {
                        push_value(&mut recorded, value.clone());
                    }
                }
            }
            if hit {
                gap.runs += 1;
                stages.insert(record.stage.as_str());
            }
        }
        let isa = gap.isa.name();
        gap.values.push(if gap.of_runs == 0 {
            format!("not run: no run of this row on {isa}")
        } else if gap.runs == 0 && blind != 0 {
            format!(
                "no evidence: {blind} of {} {isa} stage runs of this row wrote no census",
                gap.of_runs
            )
        } else if gap.runs == 0 {
            format!("not yet reached: no {isa} run of this row refused it")
        } else {
            format!(
                "reached: refused {refused} times in stage {}{}",
                stages.into_iter().collect::<Vec<_>>().join(", "),
                if shaped {
                    " (counted per call, not per shape; recorded arguments follow)"
                } else {
                    ""
                }
            )
        });
        if shaped {
            gap.values.extend(recorded);
        }
    }
}

/// The venue-gap rows of every profile a directory holds (`<out>/venue/`);
/// none when it has none.
fn venue_rows(out: &Path) -> Result<Vec<TableRow>> {
    let dir = venue_dir(out);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", dir.display())),
    };
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    let mut rows = Vec::new();
    for row in names {
        let path = dir.join(&row).join("profile.txt");
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let profile = crate::venue_gaps::parse_profile(&text)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("venue profile {}", path.display()))?;
        rows.extend(venue_gap_rows(&row, &profile)?);
    }
    Ok(rows)
}

/// The table as Markdown, with a per-stage verdict line first: passes, the
/// median carrick time, and with oracle runs the oracle's median and the
/// ratio of the passing runs' median to it.
pub(crate) fn render(
    records: &[RunRecord],
    oracle: &[OracleRecord],
    rows: &[TableRow],
    limit: usize,
) -> String {
    #[derive(Default)]
    struct Verdict {
        passed: usize,
        runs: usize,
        secs: Vec<f64>,
        passing_secs: Vec<f64>,
    }
    let mut out = String::new();
    let mut verdicts: BTreeMap<(String, RowIsa, String, String), Verdict> = BTreeMap::new();
    for record in records {
        let entry = verdicts
            .entry((
                record.instance.clone(),
                record.isa,
                record.row.clone(),
                record.stage.clone(),
            ))
            .or_default();
        entry.runs += 1;
        entry.secs.push(record.secs);
        if record.passed {
            entry.passed += 1;
            entry.passing_secs.push(record.secs);
        }
    }
    let medians = oracle_medians(oracle);
    out.push_str(
        "| instance | isa | row | stage | passed | median secs | oracle secs | ratio |\n\
         |---|---|---|---|---:|---:|---:|---:|\n",
    );
    for ((instance, isa, row, stage), verdict) in verdicts {
        let secs = median(verdict.secs).map_or_else(|| "-".to_owned(), |s| format!("{s:.1}"));
        let oracle_secs = medians.get(&(isa, row.clone(), stage.clone())).copied();
        let ratio = match (median(verdict.passing_secs), oracle_secs) {
            (Some(passing), Some(oracle)) => {
                format!("{:.1}x", passing / oracle.max(MIN_ORACLE_SECS))
            }
            _ => "-".to_owned(),
        };
        out.push_str(&format!(
            "| {instance} | {} | {row} | {stage} | {}/{} | {secs} | {} | {ratio} |\n",
            isa.name(),
            verdict.passed,
            verdict.runs,
            oracle_secs.map_or_else(|| "-".to_owned(), |s| format!("{s:.2}")),
        ));
    }
    out.push_str(&format!(
        "\n{} sites ({} shown)\n\n| rank | instance | isa | row | stage | kind | site | count | runs | values |\n|---:|---|---|---|---|---|---|---:|---:|---|\n",
        rows.len(),
        rows.len().min(limit)
    ));
    for (index, row) in rows.iter().take(limit).enumerate() {
        let values = row
            .values
            .iter()
            .map(|v| format!("`{}`", v.replace('|', "/").replace('`', "'")))
            .collect::<Vec<_>>()
            .join("<br>");
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {}/{} | {} |\n",
            index + 1,
            row.instance,
            row.isa.name(),
            row.row,
            row.stage,
            row.kind.name(),
            row.site.replace('|', "/"),
            row.count,
            row.runs,
            row.of_runs,
            values
        ));
    }
    out
}

/// Known-answer failures: each stage's `known_answer` keys every run of it
/// must have produced.
pub(crate) fn known_answer_misses(rows: &RowsFile, records: &[RunRecord]) -> Vec<String> {
    let mut misses = Vec::new();
    for row in &rows.rows {
        for stage in &row.stages {
            for (isa, answers) in &stage.known_answer {
                for record in records
                    .iter()
                    .filter(|r| r.row == row.name && r.stage == stage.name && r.isa == *isa)
                {
                    for answer in answers {
                        if !record.findings.iter().any(|f| f.key().contains(answer)) {
                            misses.push(format!(
                                "{}/{} run {}: no finding matches known answer {answer:?}",
                                row.name, stage.name, record.run
                            ));
                        }
                    }
                }
            }
        }
    }
    misses
}

/// Wait for `child` at most `timeout`; on expiry run `at_deadline` (the
/// child still alive, so it can be inspected) and then kill exactly that
/// process.
fn wait_bounded(
    mut child: std::process::Child,
    timeout: Duration,
    at_deadline: &mut dyn FnMut(),
) -> Result<Ending> {
    use std::os::unix::process::ExitStatusExt;
    let pid = child.id();
    let (sender, receiver) = std::sync::mpsc::channel();
    // The waiter only observes the exit (`WNOWAIT`): the child stays
    // unreaped until `child.wait()` below, so its pid cannot be recycled
    // while the deadline hook runs or the kill is sent.
    let waiter = std::thread::spawn(move || {
        // SAFETY: an all-zero `siginfo_t` is a valid output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: `info` is valid writable storage; `pid` is our child.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
        let _ = sender.send(());
    });
    let timed_out = receiver.recv_timeout(timeout).is_err();
    if timed_out {
        at_deadline();
        if receiver.try_recv().is_err() {
            // SAFETY: `pid` is our own child, still unreaped (only
            // `child.wait()` below reaps it), so it names this process.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
    let status = child.wait().context("wait for carrier")?;
    waiter
        .join()
        .map_err(|_| anyhow::anyhow!("carrier waiter panicked"))?;
    Ok(Ending {
        exit_code: status.code(),
        signal: status.signal(),
        timed_out,
    })
}

/// How long a hung carrier's zonedump may take before it is abandoned.
const ZONEDUMP_SECS: u64 = 60;

/// Read a live carrier's scheduler zone (`<carrick> debug zonedump
/// --run-id <run_id>`, through the run's debug endpoint, without stopping
/// it) into `path`, and the same capture's syscall census so far into
/// `census`. Best effort: a dump that fails leaves its error there, and
/// `hang_findings` reports a dump that read no zone; a capture without a
/// census leaves no census file, and the run reads `no_census`.
fn capture_zonedump(carrick: &Path, run_id: &str, path: &Path, census: &Path) {
    let Ok(file) = std::fs::File::create(path) else {
        return;
    };
    let Ok(err) = file.try_clone() else {
        return;
    };
    let Ok(child) = std::process::Command::new(carrick)
        .args(["debug", "zonedump", "--run-id", run_id, "--census-out"])
        .arg(census)
        .stdin(std::process::Stdio::null())
        .stdout(file)
        .stderr(err)
        .spawn()
    else {
        return;
    };
    let _ = wait_bounded(child, Duration::from_secs(ZONEDUMP_SECS), &mut || {});
}

/// Options for one discovery run.
pub(crate) struct DiscoverOptions<'a> {
    pub(crate) rows: &'a Path,
    pub(crate) only: &'a [String],
    pub(crate) runs: u32,
    pub(crate) out: &'a Path,
    pub(crate) carrick: Option<&'a Path>,
    pub(crate) instance: Option<&'a str>,
    pub(crate) label: &'a str,
    pub(crate) reap: Option<&'a Path>,
    pub(crate) limit: usize,
    /// The docker CLI for the native-oracle timing phase (`--oracle`).
    pub(crate) oracle: Option<&'a Path>,
    /// Stop after the oracle phase (`--oracle-only`).
    pub(crate) oracle_only: bool,
    /// Native-oracle syscall profiles, `<row>=<file>` (`--venue-profile`).
    pub(crate) venue_profiles: &'a [String],
    /// Where the rows run (`--provider`).
    pub(crate) provider: Provider,
}

fn instance_name(explicit: Option<&str>) -> String {
    if let Some(name) = explicit {
        return name.to_owned();
    }
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid writable storage of the given length.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        if let Ok(name) = std::str::from_utf8(&buf[..end])
            && !name.is_empty()
        {
            return name.to_owned();
        }
    }
    "unknown".to_owned()
}

fn write_outputs(
    out: &Path,
    records: &[RunRecord],
    oracle: &[OracleRecord],
    limit: usize,
) -> Result<String> {
    let mut rows = rank(records, oracle);
    let mut venue = venue_rows(out)?;
    mark_reached(&mut venue, records);
    rows.extend(venue);
    sort_rows(&mut rows);
    let table = render(records, oracle, &rows, limit);
    std::fs::write(out.join("table.md"), &table)
        .with_context(|| format!("write {}", out.join("table.md").display()))?;
    std::fs::write(out.join("table.json"), serde_json::to_vec_pretty(&rows)?)
        .with_context(|| format!("write {}", out.join("table.json").display()))?;
    Ok(table)
}

fn read_records(out: &Path) -> Result<Vec<RunRecord>> {
    let path = out.join("runs.jsonl");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).with_context(|| format!("parse run {line}")))
        .collect()
}

/// The oracle runs of a directory (`oracle.jsonl`); none when it has none.
fn read_oracle(out: &Path) -> Result<Vec<OracleRecord>> {
    let path = out.join("oracle.jsonl");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).with_context(|| format!("parse oracle {line}")))
        .collect()
}

/// `carrick debug discover --report <out>`: re-rank a finished directory.
pub(crate) fn report(out: &Path, limit: usize) -> Result<()> {
    let records = read_records(out)?;
    ensure!(!records.is_empty(), "{} holds no runs", out.display());
    print!(
        "{}",
        write_outputs(out, &records, &read_oracle(out)?, limit)?
    );
    Ok(())
}

/// The Docker-only phase: time every selected stage `runs` times on the
/// native oracle (`docker run --rm <image> <command...>`), each image
/// pulled once first and untimed. It runs before any carrick run and never
/// beside one (AGENTS.md: never carrick and Docker at once). A stage past
/// its timeout has its container removed by name, since killing the docker
/// CLI leaves the container running.
fn run_oracle(
    docker: &Path,
    selected: &[&RowSpec],
    isa: RowIsa,
    runs: u32,
    label: &str,
    out: &Path,
) -> Result<Vec<OracleRecord>> {
    use std::io::Write;
    let quiet = std::process::Stdio::null;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out.join("oracle.jsonl"))?;
    for row in selected {
        if let Some(image) = row.image.get(&isa) {
            let _ = std::process::Command::new(docker)
                .args(["pull", "-q", image])
                .stdout(quiet())
                .stderr(quiet())
                .status();
        }
    }
    let mut records = Vec::new();
    for run in 1..=runs {
        for row in selected {
            let Some(image) = row.image.get(&isa) else {
                continue;
            };
            for stage in &row.stages {
                let name = format!("discover-oracle-{label}-{}-{}-{run}", row.name, stage.name);
                let base = out.join(format!("oracle-{}-{}-{run}", row.name, stage.name));
                let stdout_path = base.with_extension("out");
                let started = std::time::Instant::now();
                let child = std::process::Command::new(docker)
                    .args(["run", "--rm", "--name", &name])
                    .arg(image)
                    .args(&stage.command)
                    .stdin(quiet())
                    .stdout(std::fs::File::create(&stdout_path)?)
                    .stderr(std::fs::File::create(base.with_extension("err"))?)
                    .spawn()
                    .with_context(|| format!("start {}", docker.display()))?;
                let timeout = Duration::from_secs(stage.timeout_secs.unwrap_or(row.timeout_secs));
                let ending = wait_bounded(child, timeout, &mut || {})?;
                let secs = started.elapsed().as_secs_f64();
                if ending.timed_out {
                    let _ = std::process::Command::new(docker)
                        .args(["rm", "-f", &name])
                        .stdout(quiet())
                        .stderr(quiet())
                        .status();
                }
                let stdout = String::from_utf8_lossy(&std::fs::read(&stdout_path)?).into_owned();
                let passed =
                    ending.exit_code == Some(0) && !ending.timed_out && marker_seen(stage, &stdout);
                eprintln!(
                    "discover: oracle {}/{} run {run}: {} in {secs:.2}s",
                    row.name,
                    stage.name,
                    if passed { "pass" } else { "FAIL" }
                );
                let record = OracleRecord {
                    isa,
                    row: row.name.clone(),
                    stage: stage.name.clone(),
                    run,
                    image: image.clone(),
                    exit_code: ending.exit_code,
                    timed_out: ending.timed_out,
                    secs,
                    passed,
                };
                writeln!(file, "{}", serde_json::to_string(&record)?)?;
                file.flush()?;
                records.push(record);
            }
        }
    }
    Ok(records)
}

/// `carrick debug discover --rows <file> --out <dir>`: run every selected
/// row's stages `runs` times and rank every failure they produced.
pub(crate) fn discover(options: DiscoverOptions<'_>) -> Result<()> {
    use std::io::Write;
    let rows = load_rows(options.rows)?;
    ensure!(options.runs > 0, "--runs must be at least 1");
    for name in options.only {
        ensure!(
            rows.rows.iter().any(|row| &row.name == name),
            "no row named {name} in {}",
            options.rows.display()
        );
    }
    ensure!(is_label(options.label), "--label is [A-Za-z0-9_.-]+");
    if options.provider == Provider::SoftA64 {
        ensure!(
            options.oracle.is_none() && !options.oracle_only,
            "--provider soft-a64 takes no --oracle phase"
        );
        let carrick = match options.carrick {
            Some(path) => path.to_path_buf(),
            None => std::env::current_exe().context("locate this carrick binary")?,
        };
        std::fs::create_dir_all(options.out)
            .with_context(|| format!("create {}", options.out.display()))?;
        let selected: Vec<&RowSpec> = rows
            .rows
            .iter()
            .filter(|row| options.only.is_empty() || options.only.contains(&row.name))
            .collect();
        return soft::discover(
            &options,
            &selected,
            &carrick,
            &instance_name(options.instance),
        );
    }
    let isa = RowIsa::host()?;
    let carrick = match options.carrick {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe().context("locate this carrick binary")?,
    };
    let instance = instance_name(options.instance);
    std::fs::create_dir_all(options.out)
        .with_context(|| format!("create {}", options.out.display()))?;
    admit_venue_profiles(&rows, options.venue_profiles, options.out)?;
    let mut runs_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(options.out.join("runs.jsonl"))?;
    let mut run_ids = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(options.out.join("run-ids.txt"))?;
    let selected: Vec<&RowSpec> = rows
        .rows
        .iter()
        .filter(|row| options.only.is_empty() || options.only.contains(&row.name))
        .collect();
    // The oracle phase finishes before the first carrick run starts.
    let oracle = match options.oracle {
        Some(docker) => run_oracle(
            docker,
            &selected,
            isa,
            options.runs,
            options.label,
            options.out,
        )?,
        None => read_oracle(options.out)?,
    };
    if options.oracle_only {
        let passed = oracle.iter().filter(|record| record.passed).count();
        eprintln!(
            "discover: oracle-only: {passed}/{} oracle runs passed; {} holds the oracle for a later carrick run",
            oracle.len(),
            options.out.join("oracle.jsonl").display()
        );
        return Ok(());
    }
    let mut records = Vec::new();
    // First runs of every stage come first, so a short budget still sees
    // every stage once; repeats follow.
    for run in 1..=options.runs {
        for row in &selected {
            let Some(image) = row.image.get(&isa) else {
                eprintln!(
                    "discover: row {} has no {} image; skipped",
                    row.name,
                    isa.name()
                );
                continue;
            };
            for stage in &row.stages {
                let run_id = format!(
                    "discover-{}-{}-{}-{run}",
                    options.label, row.name, stage.name
                );
                writeln!(run_ids, "{run_id}")?;
                let base = options
                    .out
                    .join(format!("{}-{}-{run}", row.name, stage.name));
                let census = base.with_extension("census");
                let _ = std::fs::remove_dir_all(&census);
                let stdout_path = base.with_extension("out");
                let stderr_path = base.with_extension("err");
                let started = std::time::Instant::now();
                let child = std::process::Command::new(&carrick)
                    .arg("run")
                    .arg(image)
                    .args(&stage.command)
                    .env("CARRICK_RUN_ID", &run_id)
                    .env("CARRICK_EL1_CENSUS", &census)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::fs::File::create(&stdout_path)?)
                    .stderr(std::fs::File::create(&stderr_path)?)
                    .spawn()
                    .with_context(|| format!("start {}", carrick.display()))?;
                let timeout = Duration::from_secs(stage.timeout_secs.unwrap_or(row.timeout_secs));
                let zonedump_path = base.with_extension("zonedump");
                let _ = std::fs::remove_file(&zonedump_path);
                // Beside the census directory, never in it: a carrier that
                // exits by itself during the capture publishes its own.
                let kill_census_path = base.with_extension("census-at-kill.json");
                let _ = std::fs::remove_file(&kill_census_path);
                let mut dump_zone =
                    || capture_zonedump(&carrick, &run_id, &zonedump_path, &kill_census_path);
                let ending = wait_bounded(child, timeout, &mut dump_zone)?;
                let secs = started.elapsed().as_secs_f64();
                if let Some(reap) = options.reap {
                    // The repo's run-id reaper (`scripts/sudo/kill.sh`), the
                    // same reap parity-rows.sh does after every run.
                    let _ = std::process::Command::new("sudo")
                        .arg("-n")
                        .arg(reap)
                        .arg(&run_id)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
                let stdout = String::from_utf8_lossy(&std::fs::read(&stdout_path)?).into_owned();
                let stderr = String::from_utf8_lossy(&std::fs::read(&stderr_path)?).into_owned();
                let mut censuses = load_censuses(&census)?;
                let mut census_at_kill = false;
                if ending.timed_out
                    && censuses.is_empty()
                    && let Ok(at_kill) = crate::debug_el1_census::load(&kill_census_path)
                {
                    censuses.push(at_kill);
                    census_at_kill = true;
                }
                let (passed, mut findings) = judge(stage, ending, &stdout, &stderr, &censuses);
                if census_at_kill
                    && let Some(timeout) = findings
                        .iter_mut()
                        .find(|finding| finding.kind == FindingKind::Timeout)
                {
                    push_value(
                        &mut timeout.values,
                        "census read at the kill (refusals up to the deadline)".to_owned(),
                    );
                }
                if ending.timed_out {
                    let zonedump = std::fs::read(&zonedump_path).unwrap_or_default();
                    findings.extend(hang_findings(isa, &String::from_utf8_lossy(&zonedump)));
                }
                let record = RunRecord {
                    instance: instance.clone(),
                    isa,
                    row: row.name.clone(),
                    stage: stage.name.clone(),
                    run,
                    run_id,
                    image: image.clone(),
                    exit_code: ending.exit_code,
                    signal: ending.signal,
                    timed_out: ending.timed_out,
                    secs,
                    passed,
                    findings,
                };
                eprintln!(
                    "discover: {}/{} run {run}: {} in {secs:.1}s, {} findings",
                    row.name,
                    stage.name,
                    if passed { "pass" } else { "FAIL" },
                    record.findings.len()
                );
                writeln!(runs_file, "{}", serde_json::to_string(&record)?)?;
                runs_file.flush()?;
                records.push(record);
            }
        }
    }
    print!(
        "{}",
        write_outputs(options.out, &records, &oracle, options.limit)?
    );
    let misses = known_answer_misses(&rows, &records);
    if !misses.is_empty() {
        for miss in &misses {
            eprintln!("discover: known answer missed: {miss}");
        }
        bail!("{} known-answer checks failed", misses.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(expect: Option<&str>) -> StageSpec {
        StageSpec {
            name: "s".to_owned(),
            command: vec!["true".to_owned()],
            expect: expect.map(str::to_owned),
            timeout_secs: None,
            known_answer: BTreeMap::new(),
        }
    }

    fn census_with(isa: CensusIsa, record: impl FnOnce(&carrick_el1_abi::Counters)) -> Census {
        let counters = carrick_el1_abi::Counters::new();
        record(&counters);
        carrick_runtime::el1_census::census_of_counters(&counters, isa)
    }

    fn ok() -> Ending {
        Ending {
            exit_code: Some(0),
            signal: None,
            timed_out: false,
        }
    }

    #[test]
    fn fatal_panic_and_guest_errno_lines_become_sites() {
        let stderr = "\u{1b}[31mcarrick fatal [hvpatch.mm]: owner 0x7f00 generation 12 stale\u{1b}[0m\n\
            thread 'vcpu-3' panicked at crates/carrick-x/src/a.rs:10:5:\n\
            index out of bounds\n\
            E: Select has failed (38)\n\
            E: Select has failed (38)\n\
            go: open /tmp/x: no such file or directory\n\
            carrick: image docker.io/library/node:22 (linux/amd64) pulling\n\
            carrick: configuration refused: hypervisor operation failed: physical fork source residency capacity\n";
        let findings = stream_findings(stderr, "pip: [Errno 38] Function not implemented\n");
        let keys: Vec<String> = findings.iter().map(Finding::key).collect();
        assert!(
            keys.contains(&"fatal [hvpatch.mm] owner 0x# generation # stale".to_owned()),
            "{keys:?}"
        );
        let fatal = findings
            .iter()
            .find(|f| f.kind == FindingKind::Fatal)
            .unwrap();
        assert_eq!(fatal.values, ["owner 0x7f00 generation 12 stale"]);
        let panic = findings
            .iter()
            .find(|f| f.kind == FindingKind::Panic)
            .unwrap();
        assert_eq!(panic.site, "crates/carrick-x/src/a.rs:10:5");
        assert_eq!(panic.values, ["index out of bounds"]);
        let select = findings
            .iter()
            .find(|f| f.site == "ENOSYS: E: Select has failed (#)")
            .unwrap();
        assert_eq!(select.count, 2);
        assert_eq!(select.values, ["E: Select has failed (38)"]);
        assert!(
            keys.iter()
                .any(|k| k.starts_with("guest_errno ENOSYS: pip: [Errno #]"))
        );
        // The carrier's rc-125 error chain is its own site; a progress line
        // with the same prefix is not.
        let carrier = findings
            .iter()
            .find(|f| f.kind == FindingKind::CarrierError)
            .unwrap();
        assert_eq!(
            carrier.site,
            "configuration refused: hypervisor operation failed: physical fork source residency capacity"
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.kind == FindingKind::CarrierError)
                .count(),
            1
        );
        // ENOENT is left out: correct programs print it all the time.
        assert!(!keys.iter().any(|k| k.contains("no such file")), "{keys:?}");
    }

    #[test]
    fn every_refusal_of_a_run_is_a_site_with_its_recorded_arguments() {
        use carrick_runtime::el1_census::RefusedCallRecord;
        use carrick_spec::syscall_census::RefusalRow;
        // A native child refuses pselect6 twice and the root refuses mremap
        // once, as an x86 census file records them: both are sites, not
        // only the first.
        let mut census = census_with(CensusIsa::X86_64, |_| {});
        census.refusal_evidence.rows = vec![
            RefusalRow {
                nr: 270,
                caller: CallerClass::NativeChild,
                refused: 2,
                venue_refused: 0,
                allowlisted: false,
            },
            RefusalRow {
                nr: 25,
                caller: CallerClass::Root,
                refused: 0,
                venue_refused: 1,
                allowlisted: false,
            },
        ];
        let pselect = RefusedCallRecord {
            nr: 270,
            name: Some("pselect6".to_owned()),
            caller: CallerClass::NativeChild,
            venue: "ring".to_owned(),
            arguments: Some([4, 0x7000, 0, 0, 0x7100, 0x7200]),
        };
        census.refused_calls = vec![
            pselect.clone(),
            pselect,
            RefusedCallRecord {
                nr: 25,
                name: Some("mremap".to_owned()),
                caller: CallerClass::Root,
                venue: "carrier".to_owned(),
                arguments: None,
            },
        ];
        census.anonymous_leaves = [("root_declined".to_owned(), 5)].into();
        // The census file is the input: judge what a reader decodes.
        let census: Census =
            serde_json::from_str(&serde_json::to_string(&census).unwrap()).unwrap();
        let (passed, findings) = judge(&stage(None), ok(), "", "", &[census]);
        assert!(passed);
        let pselect = findings
            .iter()
            .find(|f| f.site == "pselect6(nr=270) caller=child venue=ring")
            .unwrap();
        assert_eq!(pselect.count, 2);
        assert_eq!(
            pselect.values,
            [
                "REFUSE nr=270(pselect6) caller=child venue=ring a0=0x4 a1=0x7000 a2=0x0 a3=0x0 a4=0x7100 a5=0x7200 nfds=4"
            ]
        );
        let mremap = findings
            .iter()
            .find(|f| f.site == "mremap(nr=25) caller=root venue=carrier")
            .unwrap();
        assert_eq!(
            mremap.values,
            ["REFUSE nr=25(mremap) caller=root venue=carrier args=unretained"]
        );
        let leave = findings
            .iter()
            .find(|f| f.kind == FindingKind::AnonymousLeave)
            .unwrap();
        assert_eq!((leave.site.as_str(), leave.count), ("root_declined", 5));
    }

    #[test]
    fn a_run_with_no_census_timeout_exit_or_missing_marker_says_so() {
        let (passed, findings) = judge(
            &stage(Some("PIP_OK")),
            Ending {
                exit_code: None,
                signal: Some(9),
                timed_out: true,
            },
            "partial\n",
            "",
            &[],
        );
        assert!(!passed);
        let kinds: Vec<FindingKind> = findings.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&FindingKind::Timeout));
        assert!(kinds.contains(&FindingKind::NoCensus));
        assert!(kinds.contains(&FindingKind::MissingMarker));
        // A timeout is not also an exit finding.
        assert!(!kinds.contains(&FindingKind::Exit));
        let (passed, findings) = judge(
            &stage(Some("PIP_OK")),
            Ending {
                exit_code: Some(1),
                signal: None,
                timed_out: false,
            },
            "PIP_OK\n",
            "boom\nlast words\n\n",
            &[],
        );
        assert!(!passed);
        let exit = findings
            .iter()
            .find(|f| f.kind == FindingKind::Exit)
            .unwrap();
        assert_eq!(
            (exit.site.as_str(), exit.values.as_slice()),
            ("rc=1", &["last words".to_owned()][..])
        );
        // The marker on its own line passes a zero exit.
        let (passed, _) = judge(
            &stage(Some("PIP_OK")),
            ok(),
            "x\nPIP_OK\n",
            "",
            &[census_with(CensusIsa::X86_64, |_| {})],
        );
        assert!(passed);
    }

    fn record(row: &str, run: u32, passed: bool, findings: Vec<Finding>) -> RunRecord {
        RunRecord {
            instance: "hz-vm".to_owned(),
            isa: RowIsa::X86_64,
            row: row.to_owned(),
            stage: "build".to_owned(),
            run,
            run_id: format!("r{run}"),
            image: "img".to_owned(),
            exit_code: Some(i32::from(!passed)),
            signal: None,
            timed_out: false,
            secs: 1.0,
            passed,
            findings,
        }
    }

    #[test]
    fn ranking_orders_by_kind_then_runs_then_count_and_keeps_values() {
        let refused = |count, value: &str| Finding {
            kind: FindingKind::Refused,
            site: "mmap(nr=9) caller=child venue=ring".to_owned(),
            count,
            values: vec![value.to_owned()],
        };
        let records = vec![
            record(
                "go",
                1,
                false,
                vec![
                    refused(6, "a"),
                    Finding::new(FindingKind::IpcLeave, "restart", 100),
                ],
            ),
            record(
                "go",
                2,
                false,
                vec![
                    refused(4, "b"),
                    Finding::new(FindingKind::Fatal, "[mm] x", 1),
                ],
            ),
            record("go", 3, true, vec![]),
        ];
        let rows = rank(&records, &[]);
        assert_eq!(rows[0].kind, FindingKind::Fatal);
        assert_eq!((rows[1].count, rows[1].runs, rows[1].of_runs), (10, 2, 3));
        assert_eq!(rows[1].values, ["a", "b"]);
        assert_eq!(rows[2].kind, FindingKind::IpcLeave);
        let table = render(&records, &[], &rows, 10);
        assert!(
            table.contains("| hz-vm | x86_64 | go | build | 1/3 |"),
            "{table}"
        );
        assert!(
            table.contains("| 2 | hz-vm | x86_64 | go | build | refused | mmap(nr=9) caller=child venue=ring | 10 | 2/3 | `a`<br>`b` |"),
            "{table}"
        );
    }

    fn oracle(stage: &str, run: u32, secs: f64, passed: bool) -> OracleRecord {
        OracleRecord {
            isa: RowIsa::X86_64,
            row: "pip".to_owned(),
            stage: stage.to_owned(),
            run,
            image: "img".to_owned(),
            exit_code: Some(i32::from(!passed)),
            timed_out: false,
            secs,
            passed,
        }
    }

    #[test]
    fn a_passing_stage_at_five_times_the_oracle_is_a_pathological_row() {
        // pip's stdlib stage as the x86 rows measured it: about 102 s on
        // carrick, about 0.47 s on the native Docker oracle. Run 3 failed,
        // so its time is no cost evidence; the vet stage is under 5x.
        let at = |stage: &str, run, secs, passed| RunRecord {
            row: "pip".to_owned(),
            stage: stage.to_owned(),
            secs,
            ..record("pip", run, passed, vec![])
        };
        let records = vec![
            at("stdlib", 1, 102.2, true),
            at("stdlib", 2, 101.4, true),
            at("stdlib", 3, 300.0, false),
            at("vet", 1, 2.0, true),
        ];
        let oracle = vec![
            oracle("stdlib", 1, 0.48, true),
            oracle("stdlib", 2, 0.44, true),
            oracle("stdlib", 3, 9.0, false),
            oracle("vet", 1, 0.5, true),
        ];
        let rows = rank(&records, &oracle);
        let slow: Vec<&TableRow> = rows
            .iter()
            .filter(|r| r.kind == FindingKind::Pathological)
            .collect();
        assert_eq!(slow.len(), 1, "{rows:?}");
        assert_eq!(
            (slow[0].stage.as_str(), slow[0].runs, slow[0].of_runs),
            ("stdlib", 2, 3)
        );
        assert_eq!(
            slow[0].values[0],
            "run 1: carrick 102.2s vs oracle median 0.46s (222x)"
        );
        let table = render(&records, &oracle, &rows, 10);
        assert!(
            table.contains("| hz-vm | x86_64 | pip | stdlib | 2/3 | 102.2 | 0.46 | 221.3x |"),
            "{table}"
        );
        assert!(
            table.contains("| hz-vm | x86_64 | pip | vet | 1/1 | 2.0 | 0.50 | 4.0x |"),
            "{table}"
        );
        assert!(
            table.contains("| pathological_time | passes at >= 5x"),
            "{table}"
        );
        // Without oracle runs nothing is pathological and the columns say so.
        assert!(
            !rank(&records, &[])
                .iter()
                .any(|r| r.kind == FindingKind::Pathological)
        );
        assert!(
            render(&records, &[], &rank(&records, &[]), 10).contains("| 2/3 | 102.2 | - | - |")
        );
    }

    #[test]
    fn the_oracle_phase_times_each_stage_before_any_carrick_run() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("order.log");
        let script = |path: &Path, body: &str| {
            std::fs::write(path, body).unwrap();
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        };
        // Stand-ins (cfg(test) only): a docker CLI that answers at once, and
        // a carrier that is slow on the `slow` stage. Both log their calls.
        let docker = dir.path().join("docker");
        script(
            &docker,
            &format!(
                "#!/bin/sh\necho \"docker $1\" >> {log}\n[ \"$1\" = run ] && echo OK\nexit 0\n",
                log = log.display()
            ),
        );
        let fake = dir.path().join("carrick");
        script(
            &fake,
            &format!(
                "#!/bin/sh\necho \"carrick $3\" >> {log}\n[ \"$3\" = slow ] && sleep 1.5\necho OK\nexit 0\n",
                log = log.display()
            ),
        );
        let rows = dir.path().join("rows.json");
        std::fs::write(
            &rows,
            r#"{"rows":[{"name":"r","image":{"x86_64":"u","arm64":"u"},"timeout_secs":20,
                "stages":[{"name":"fast","command":["fast"],"expect":"OK"},
                          {"name":"slow","command":["slow"],"expect":"OK"}]}]}"#,
        )
        .unwrap();
        let out = dir.path().join("out");
        discover(DiscoverOptions {
            rows: &rows,
            only: &[],
            runs: 1,
            out: &out,
            carrick: Some(&fake),
            instance: Some("unit"),
            label: "t",
            reap: None,
            limit: 50,
            oracle: Some(&docker),
            oracle_only: false,
            venue_profiles: &[],
            provider: Provider::Hardware,
        })
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "docker pull\ndocker run\ndocker run\ncarrick fast\ncarrick slow\n"
        );
        let oracle = read_oracle(&out).unwrap();
        assert_eq!(oracle.len(), 2);
        assert!(oracle.iter().all(|r| r.passed), "{oracle:?}");
        let table = std::fs::read_to_string(out.join("table.md")).unwrap();
        assert!(
            table.contains(
                "| pathological_time | passes at >= 5x the native oracle's time | 1 | 1/1 |"
            ),
            "{table}"
        );
        assert!(!table.contains("| fast | pathological_time"), "{table}");
        // --report keeps the oracle's columns and rows.
        std::fs::remove_file(out.join("table.md")).unwrap();
        report(&out, 50).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("table.md")).unwrap(),
            table
        );

        // Two windows: --oracle-only runs Docker alone and no carrick stage;
        // a later carrick-only run in the same directory ranks against it.
        let split = dir.path().join("split");
        std::fs::write(&log, "").unwrap();
        let options = |oracle, oracle_only| DiscoverOptions {
            rows: &rows,
            only: &[],
            runs: 1,
            out: &split,
            carrick: Some(&fake),
            instance: Some("unit"),
            label: "t",
            reap: None,
            limit: 50,
            oracle,
            oracle_only,
            venue_profiles: &[],
            provider: Provider::Hardware,
        };
        discover(options(Some(&docker), true)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "docker pull\ndocker run\ndocker run\n"
        );
        assert!(!split.join("runs.jsonl").exists() || read_records(&split).unwrap().is_empty());
        assert_eq!(read_oracle(&split).unwrap().len(), 2);
        discover(options(None, false)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "docker pull\ndocker run\ndocker run\ncarrick fast\ncarrick slow\n"
        );
        let table = std::fs::read_to_string(split.join("table.md")).unwrap();
        assert!(
            table.contains(
                "| pathological_time | passes at >= 5x the native oracle's time | 1 | 1/1 |"
            ),
            "{table}"
        );
    }

    #[test]
    fn a_hung_carriers_zonedump_names_its_parked_calls_and_unserved_host_work() {
        // Lines of the live zonedump of x86 npm/row run 2 on the round-2
        // union (a1f8dbe05), 787 s into its 900 s stage, 4 s of CPU.
        let zonedump = "run: discover-x86u3-npm-row-2\n\
            zone slot 0: state=IdleWfi driver=1 away=false mm=1 installed=0\n\
            zone record 1: claim=Parked { seq: 7 } handback=None tid=233966 serial=6 mm=7 gen=2\n\
            zone record 1 parked: first_wait_mm=1 first_wait_address=0xffffffffa80009a0 resume=OwnerContinuation(Syscall) saved_pc=0x60000d7bd3 saved_nr=61 saved_args=[ffffffff, fffffef70c, 0, 0, 3, 1]\n\
            el1 task slot 0: tid=233966 serial=6 mm=7 pending_host_work=0 served_with_work=0 generation=2 pid=233966 service_notice=empty\n\
            el1 task slot 1: tid=233969 serial=18 mm=11 pending_host_work=1 served_with_work=0 generation=2 pid=4 service_notice=empty\n\
            vcpu: cpu=0 phase=running bound_task_serial=5 last_stopped_rip=0xffffffff8000ab74 pending_host_work=false served_with_work=0\n\
            vcpu: cpu=1 phase=running bound_task_serial=0 last_stopped_rip=0xffffffff8000372d last_stopped_rflags=0x2 actual_guest_run=true pending_host_work=true served_with_work=0\n";
        let findings = hang_findings(RowIsa::X86_64, zonedump);
        let keys: Vec<String> = findings.iter().map(Finding::key).collect();
        assert_eq!(
            keys,
            [
                "hang parked in wait4(nr=61) resume=OwnerContinuation(Syscall)",
                "hang task holds unserved host work",
                "hang vcpu holds unserved host work",
            ],
        );
        assert_eq!(
            findings[0].values,
            ["saved_args=[ffffffff, fffffef70c, 0, 0, 3, 1] saved_pc=0x60000d7bd3"]
        );
        assert_eq!(
            findings[1].values,
            ["tid=233969 pid=4 mm=11 pending_host_work=1 service_notice=empty"]
        );
        assert_eq!(
            findings[2].values,
            ["cpu=1 phase=running served_with_work=0 last_stopped_rip=0xffffffff8000372d"]
        );
        // The same parked number names the ISA's own call.
        let arm = hang_findings(
            RowIsa::Arm64,
            "zone slot 0: state=IdleWfi\nzone record 1 parked: resume=OwnerContinuation(Syscall) saved_nr=260 saved_args=[0]\n",
        );
        assert_eq!(
            arm[0].site,
            "parked in wait4(nr=260) resume=OwnerContinuation(Syscall)"
        );
        // A dump that read no zone is a site of its own.
        let failed = hang_findings(RowIsa::X86_64, "\nError: no debug endpoint for run x\n");
        assert_eq!(failed[0].site, "zonedump read no zone");
        assert_eq!(failed[0].values, ["Error: no debug endpoint for run x"]);
    }

    #[test]
    fn known_answers_must_appear_in_every_run() {
        let rows: RowsFile = serde_json::from_str(
            r#"{"rows":[{"name":"go","image":{"x86_64":"img"},"timeout_secs":5,
                 "stages":[{"name":"build","command":["true"],"known_answer":{"x86_64":["refused mmap"],"arm64":["never"]}}]}]}"#,
        )
        .unwrap();
        let hit = Finding::new(
            FindingKind::Refused,
            "mmap(nr=9) caller=child venue=ring",
            1,
        );
        let records = vec![
            record("go", 1, false, vec![hit]),
            record("go", 2, false, vec![]),
        ];
        let misses = known_answer_misses(&rows, &records);
        assert_eq!(misses.len(), 1);
        assert!(misses[0].contains("go/build run 2"), "{misses:?}");
    }

    #[test]
    fn rows_files_refuse_duplicates_empty_stages_and_path_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rows.json");
        for (body, needle) in [
            (
                r#"{"rows":[{"name":"a","image":{},"timeout_secs":1,"stages":[]}]}"#,
                "no stages",
            ),
            (
                r#"{"rows":[{"name":"a","image":{},"timeout_secs":1,"stages":[{"name":"s","command":["x"]},{"name":"s","command":["x"]}]}]}"#,
                "twice",
            ),
            (
                r#"{"rows":[{"name":"../a","image":{},"timeout_secs":1,"stages":[{"name":"s","command":["x"]}]}]}"#,
                "names are",
            ),
            (
                r#"{"rows":[{"name":"a","image":{"riscv":"x"},"timeout_secs":1,"stages":[]}]}"#,
                "parse rows",
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            let err = format!("{:#}", load_rows(&path).unwrap_err());
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn the_shipped_rows_files_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/parity");
        for name in ["parity-rows.json", "known-answer-rows.json"] {
            let rows = load_rows(&root.join(name)).unwrap();
            assert!(!rows.rows.is_empty(), "{name}");
            for row in &rows.rows {
                assert!(
                    row.image.contains_key(&RowIsa::Arm64),
                    "{name}: {}",
                    row.name
                );
                assert!(
                    row.image.contains_key(&RowIsa::X86_64),
                    "{name}: {}",
                    row.name
                );
            }
        }
    }

    #[test]
    fn a_stage_past_its_timeout_is_killed_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        // A stand-in carrier (cfg(test) only): it ignores `run <image>` and sleeps.
        let fake = dir.path().join("carrick");
        std::fs::write(&fake, "#!/bin/sh\nexec sleep 30\n").unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let child = std::process::Command::new(&fake).spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        let started = std::time::Instant::now();
        // The deadline hook sees the hung child still alive.
        let mut alive_at_deadline = None;
        let ending = wait_bounded(child, Duration::from_millis(200), &mut || {
            // SAFETY: signal 0 only probes that our unreaped child exists.
            alive_at_deadline = Some(unsafe { libc::kill(pid, 0) } == 0);
        })
        .unwrap();
        assert_eq!(alive_at_deadline, Some(true));
        assert!(ending.timed_out);
        assert_eq!(ending.signal, Some(libc::SIGKILL));
        assert!(started.elapsed() < Duration::from_secs(10));
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .spawn()
            .unwrap();
        let mut hook_ran = false;
        let ending = wait_bounded(child, Duration::from_secs(10), &mut || hook_ran = true).unwrap();
        assert_eq!((ending.exit_code, ending.timed_out), (Some(3), false));
        assert!(!hook_ran);
    }

    #[test]
    fn a_stage_killed_at_its_timeout_keeps_the_refusals_of_its_census_at_the_kill() {
        use carrick_runtime::el1_census::RefusedCallRecord;
        use carrick_spec::syscall_census::RefusalRow;
        let dir = tempfile::tempdir().unwrap();
        // What the live capture of the hung carrier would hand back.
        let mut census = census_with(CensusIsa::X86_64, |_| {});
        census.refusal_evidence.rows = vec![RefusalRow {
            nr: 41,
            caller: CallerClass::NativeChild,
            refused: 2,
            venue_refused: 0,
            allowlisted: false,
        }];
        census.refused_calls = vec![RefusedCallRecord {
            nr: 41,
            name: Some("socket".to_owned()),
            caller: CallerClass::NativeChild,
            venue: "ring".to_owned(),
            arguments: Some([1, 0x80001, 0, 0, 0, 0]),
        }];
        let at_kill = dir.path().join("at-kill.json");
        std::fs::write(&at_kill, serde_json::to_vec(&census).unwrap()).unwrap();
        // A stand-in carrier (cfg(test) only): `run` hangs and publishes no
        // census; `debug zonedump --run-id <id> --census-out <file>` answers
        // with a zone line and that census. `nocensus` stages get no file.
        let fake = dir.path().join("carrick");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nif [ \"$1\" = run ]; then exec sleep 30; fi\n\
                 echo 'zone slot 0: state=IdleWfi'\n\
                 case \"$4\" in *nocensus*) exit 1;; esac\n\
                 cp {} \"$6\"\n",
                at_kill.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let rows = dir.path().join("rows.json");
        std::fs::write(
            &rows,
            r#"{"rows":[{"name":"shell","image":{"x86_64":"u","arm64":"u"},"timeout_secs":1,
                "stages":[{"name":"hang","command":["x"]},{"name":"nocensus","command":["x"]}]}]}"#,
        )
        .unwrap();
        let out = dir.path().join("out");
        discover(DiscoverOptions {
            rows: &rows,
            only: &[],
            runs: 1,
            out: &out,
            carrick: Some(&fake),
            instance: Some("unit"),
            label: "t",
            reap: None,
            limit: 50,
            oracle: None,
            oracle_only: false,
            venue_profiles: &[],
            provider: Provider::Hardware,
        })
        .unwrap();
        let records = read_records(&out).unwrap();
        assert_eq!(records.len(), 2);
        let kinds = |record: &RunRecord| {
            record
                .findings
                .iter()
                .map(|finding| finding.kind)
                .collect::<Vec<_>>()
        };
        // The killed stage's refusal survives with its arguments.
        let hang = &records[0];
        assert!(hang.timed_out && hang.signal == Some(libc::SIGKILL));
        assert!(!kinds(hang).contains(&FindingKind::NoCensus), "{hang:?}");
        let refused = hang
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::Refused)
            .expect("the refusal read at the kill");
        assert_eq!(refused.count, 2);
        assert!(refused.site.starts_with("socket(nr=41)"), "{refused:?}");
        assert!(
            refused.values.iter().any(|value| value.contains("0x80001")),
            "{refused:?}"
        );
        let timeout = hang
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::Timeout)
            .unwrap();
        assert_eq!(
            timeout.values,
            ["census read at the kill (refusals up to the deadline)"]
        );
        // The capture's file sits beside the census directory, never in it.
        assert!(out.join("shell-hang-1.census-at-kill.json").is_file());
        // A capture that carried no census leaves the run saying so.
        let blind = &records[1];
        assert!(blind.timed_out);
        assert!(kinds(blind).contains(&FindingKind::NoCensus), "{blind:?}");
        assert!(!kinds(blind).contains(&FindingKind::Refused), "{blind:?}");
    }

    #[test]
    fn discover_runs_each_stage_and_report_rerenders_the_table() {
        let dir = tempfile::tempdir().unwrap();
        // A stand-in carrier (cfg(test) only): it writes the census
        // directory the real one would leave empty and prints a guest errno.
        let fake = dir.path().join("carrick");
        std::fs::write(
            &fake,
            "#!/bin/sh\nmkdir -p \"$CARRICK_EL1_CENSUS\"\necho \"$CARRICK_RUN_ID\" >&2\necho 'E: Select has failed (38)' >&2\nexit 100\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let rows = dir.path().join("rows.json");
        std::fs::write(
            &rows,
            r#"{"rows":[{"name":"shell","image":{"x86_64":"u","arm64":"u"},"timeout_secs":20,
                "stages":[{"name":"update","command":["apt-get","update"],"known_answer":{"x86_64":["guest_errno ENOSYS"],"arm64":["guest_errno ENOSYS"]}},
                          {"name":"cc","command":["gcc"],"expect":"OK"}]}]}"#,
        )
        .unwrap();
        let out = dir.path().join("out");
        discover(DiscoverOptions {
            rows: &rows,
            only: &[],
            runs: 2,
            out: &out,
            carrick: Some(&fake),
            instance: Some("unit"),
            label: "t",
            reap: None,
            limit: 50,
            oracle: None,
            oracle_only: false,
            venue_profiles: &[],
            provider: Provider::Hardware,
        })
        .unwrap();
        let records = read_records(&out).unwrap();
        // Both stages ran both times, the second although the first failed.
        assert_eq!(records.len(), 4);
        assert_eq!(
            records
                .iter()
                .map(|r| (r.stage.as_str(), r.run))
                .collect::<Vec<_>>(),
            [("update", 1), ("cc", 1), ("update", 2), ("cc", 2)]
        );
        assert_eq!(records[1].run_id, "discover-t-shell-cc-1");
        let stderr = std::fs::read_to_string(out.join("shell-cc-1.err")).unwrap();
        assert!(stderr.contains("discover-t-shell-cc-1"));
        let table = std::fs::read_to_string(out.join("table.md")).unwrap();
        assert!(
            table.contains("| unit | x86_64 | shell | cc | 0/2 |")
                || table.contains("| unit | arm64 | shell | cc | 0/2 |"),
            "{table}"
        );
        assert!(
            table.contains("ENOSYS: E: Select has failed (#)"),
            "{table}"
        );
        std::fs::remove_file(out.join("table.md")).unwrap();
        report(&out, 50).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("table.md")).unwrap(),
            table
        );
    }

    /// A recorder-format profile: the root's `socket(AF_INET, SOCK_DGRAM)`
    /// and a forked child's two calls of an unknown syscall number, which no
    /// route serves.
    const VENUE_PROFILE: &str = "VENUEPROFILE1|ready|root=7|isa=0
VENUEPROFILE1|complete|root=7

@calls[0, 41, 2, 2]: 1
@calls[1, 510, 0, 0]: 2
@enosys[1, 510, 0, 0]: 2
";

    #[test]
    fn a_venue_gap_is_reached_only_by_a_run_that_refused_its_call() {
        let gap = |isa, row: &str, site: &str| TableRow {
            instance: VENUE_INSTANCE.to_owned(),
            isa,
            row: row.to_owned(),
            stage: VENUE_STAGE.to_owned(),
            kind: FindingKind::VenueGap,
            site: site.to_owned(),
            count: 4,
            runs: 0,
            of_runs: 0,
            values: vec!["native oracle".to_owned()],
        };
        let refused = |site: &str, count, value: &str| Finding {
            kind: FindingKind::Refused,
            site: site.to_owned(),
            count,
            values: vec![value.to_owned()],
        };
        let socket = "REFUSE nr=41(socket) caller=child venue=ring a0=0x1 a1=0x80001";
        let records = [
            record(
                "go",
                1,
                false,
                vec![
                    refused("socket(nr=41) caller=child venue=ring", 3, socket),
                    refused("pidfd_open(nr=434) caller=root venue=ring", 1, "x"),
                ],
            ),
            record("go", 2, false, vec![]),
            // Another row's refusal reaches nothing of this row's.
            record(
                "pip",
                1,
                false,
                vec![refused(
                    "copy_file_range(nr=326) caller=child venue=carrier",
                    9,
                    "x",
                )],
            ),
        ];
        let mut venue = [
            gap(
                RowIsa::X86_64,
                "go",
                "socket [AF_UNIX type=1] caller=child route=ENOSYS (unrouted)",
            ),
            // The same call from the other caller, and a call no run made.
            gap(
                RowIsa::X86_64,
                "go",
                "pidfd_open caller=child route=ENOSYS (unrouted)",
            ),
            gap(
                RowIsa::X86_64,
                "go",
                "copy_file_range caller=child route=ENOSYS (unrouted)",
            ),
            gap(
                RowIsa::Arm64,
                "go",
                "pidfd_open caller=root route=ENOSYS (unrouted)",
            ),
        ];
        mark_reached(&mut venue, &records);
        assert_eq!((venue[0].runs, venue[0].of_runs), (1, 2));
        assert_eq!(
            venue[0].values[1..],
            [
                "reached: refused 3 times in stage build (counted per call, not per shape; recorded arguments follow)",
                socket
            ]
        );
        for unreached in &venue[1..3] {
            assert_eq!((unreached.runs, unreached.of_runs), (0, 2), "{unreached:?}");
            assert_eq!(
                unreached.values[1],
                "not yet reached: no x86_64 run of this row refused it"
            );
        }
        // A run that wrote no census (a killed stage) may have made the
        // call: an unreached gap of its row is unknown, a reached one stays
        // reached.
        let mut blind = records.to_vec();
        blind[1]
            .findings
            .push(Finding::new(FindingKind::NoCensus, "no census file", 1));
        let mut again = venue.clone();
        for gap in &mut again {
            gap.values.truncate(1);
        }
        mark_reached(&mut again, &blind);
        assert!(again[0].values[1].starts_with("reached: "), "{again:?}");
        for unknown in &again[1..3] {
            assert_eq!(
                unknown.values[1],
                "no evidence: 1 of 2 x86_64 stage runs of this row wrote no census"
            );
        }
        assert_eq!(again[3].values[1], "not run: no run of this row on arm64");
        assert_eq!((venue[3].runs, venue[3].of_runs), (0, 0));
        assert_eq!(venue[3].values[1], "not run: no run of this row on arm64");
        // A reached gap ranks before an unreached one.
        sort_rows(&mut venue);
        assert!(venue[0].site.starts_with("socket "), "{:?}", venue[0].site);
    }

    #[test]
    fn a_venue_profiles_gaps_rank_as_rows_and_survive_report() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("carrick");
        std::fs::write(&fake, "#!/bin/sh\necho OK\n").unwrap();
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let rows = dir.path().join("rows.json");
        std::fs::write(
            &rows,
            r#"{"rows":[{"name":"go","image":{"x86_64":"u","arm64":"u"},"timeout_secs":20,
                "stages":[{"name":"row","command":["go"],"expect":"OK"}]}]}"#,
        )
        .unwrap();
        let profile = dir.path().join("go.profile.txt");
        std::fs::write(&profile, VENUE_PROFILE).unwrap();
        let out = dir.path().join("out");
        let run = |specs: &[String], out: &Path| {
            discover(DiscoverOptions {
                rows: &rows,
                only: &[],
                runs: 1,
                out,
                carrick: Some(&fake),
                instance: Some("unit"),
                label: "t",
                reap: None,
                limit: 50,
                oracle: None,
                oracle_only: false,
                venue_profiles: specs,
                provider: Provider::Hardware,
            })
        };
        run(&[format!("go={}", profile.display())], &out).unwrap();
        let table = std::fs::read_to_string(out.join("table.md")).unwrap();
        // The unknown call is a gap on the profile's own ISA, with the
        // oracle's counts.
        let gap = table
            .lines()
            .find(|line| line.contains("| venue_gap |") && line.contains("| x86_64 |"))
            .unwrap_or_else(|| panic!("no x86_64 venue_gap row in\n{table}"));
        assert!(
            gap.contains("| static-route | x86_64 | go | oracle-profile | venue_gap |"),
            "{gap}"
        );
        assert!(gap.contains("caller=child route=ENOSYS"), "{gap}");
        assert!(
            gap.contains("`native oracle nr=510: calls=2 enosys=2 errors=0`"),
            "{gap}"
        );
        // Every venue row is one of `venue_gaps::gap_rows`'s gaps.
        let parsed = crate::venue_gaps::parse_profile(VENUE_PROFILE).unwrap();
        let gaps: usize = crate::venue_gaps::gap_rows(&parsed)
            .unwrap()
            .iter()
            .map(|row| {
                row.routes
                    .iter()
                    .filter(|(_, route)| route.is_gap())
                    .count()
            })
            .sum();
        assert_eq!(table.matches("| venue_gap |").count(), gaps, "{table}");
        // The profile is kept beside the runs, so a report ranks it again.
        std::fs::remove_file(out.join("table.md")).unwrap();
        report(&out, 50).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("table.md")).unwrap(),
            table
        );
        // A profile for a row the rows file lacks, a spec with no `=`, and a
        // file that is no profile are refused before anything runs.
        let other = dir.path().join("other");
        for (spec, want) in [
            (format!("npm={}", profile.display()), "no row named npm"),
            (profile.display().to_string(), "want <row>=<file>"),
            (format!("go={}", rows.display()), "venue profile"),
        ] {
            let error = run(&[spec], &other).expect_err(want);
            assert!(format!("{error:#}").contains(want), "{error:#}");
            assert!(!other.join("runs.jsonl").exists());
        }
    }
}
