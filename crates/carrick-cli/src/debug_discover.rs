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
//! - every carrier fatal site (`carrick fatal [<domain>]: <message>`) and
//!   Rust panic location on the carrier's stderr;
//! - every errno the guest itself reported on its streams (`Function not
//!   implemented`, `... (38)`), a wrong-errno candidate;
//! - every contention leave the census counted (`anonymous_leaves`,
//!   `ipc_leaves`);
//! - a timeout, a nonzero exit, or a missing success marker.
//!
//! The output is one ranked table (instance, ISA, row, stage, kind, site,
//! count, runs, real values) in `<out>/table.md` and `<out>/table.json`, and
//! one JSON line per run in `<out>/runs.jsonl`. `--report <out>` re-renders
//! the table from a finished directory without running anything.
//!
//! Diagnostics only: nothing here changes what a guest sees, and the census
//! it reads is the same opt-in `CARRICK_EL1_CENSUS` every run can write.

use anyhow::{Context, Result, bail, ensure};
use carrick_runtime::el1_census::{Census, RefusalRank};
use carrick_spec::syscall_census::{CallerClass, CensusIsa};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    Timeout,
    Refused,
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
            Self::Timeout => "timeout",
            Self::Refused => "refused",
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
    let marker_seen = stage
        .expect
        .as_deref()
        .is_none_or(|marker| stdout.lines().any(|line| line.trim() == marker));
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
pub(crate) fn rank(records: &[RunRecord]) -> Vec<TableRow> {
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
    rows.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(b.runs.cmp(&a.runs))
            .then(b.count.cmp(&a.count))
            .then(a.row.cmp(&b.row))
            .then(a.stage.cmp(&b.stage))
            .then(a.site.cmp(&b.site))
    });
    rows
}

/// The table as Markdown, with a per-stage verdict line first.
pub(crate) fn render(records: &[RunRecord], rows: &[TableRow], limit: usize) -> String {
    let mut out = String::new();
    let mut verdicts: BTreeMap<(String, RowIsa, String, String), (usize, usize)> = BTreeMap::new();
    for record in records {
        let entry = verdicts
            .entry((
                record.instance.clone(),
                record.isa,
                record.row.clone(),
                record.stage.clone(),
            ))
            .or_default();
        entry.1 += 1;
        if record.passed {
            entry.0 += 1;
        }
    }
    out.push_str("| instance | isa | row | stage | passed |\n|---|---|---|---|---:|\n");
    for ((instance, isa, row, stage), (passed, runs)) in &verdicts {
        out.push_str(&format!(
            "| {instance} | {} | {row} | {stage} | {passed}/{runs} |\n",
            isa.name()
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

/// Wait for `child` at most `timeout`; on expiry kill exactly that process.
fn wait_bounded(mut child: std::process::Child, timeout: Duration) -> Result<Ending> {
    use std::os::unix::process::ExitStatusExt;
    let pid = child.id();
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let status = child.wait();
        let _ = sender.send(());
        status
    });
    let timed_out = receiver.recv_timeout(timeout).is_err();
    if timed_out {
        // SAFETY: `pid` is our own unreaped child: the waiter thread has not
        // returned, so the pid cannot have been recycled.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    let status = waiter
        .join()
        .map_err(|_| anyhow::anyhow!("carrier waiter panicked"))?
        .context("wait for carrier")?;
    Ok(Ending {
        exit_code: status.code(),
        signal: status.signal(),
        timed_out,
    })
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

fn write_outputs(out: &Path, records: &[RunRecord], limit: usize) -> Result<String> {
    let rows = rank(records);
    let table = render(records, &rows, limit);
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

/// `carrick debug discover --report <out>`: re-rank a finished directory.
pub(crate) fn report(out: &Path, limit: usize) -> Result<()> {
    let records = read_records(out)?;
    ensure!(!records.is_empty(), "{} holds no runs", out.display());
    print!("{}", write_outputs(out, &records, limit)?);
    Ok(())
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
    let isa = RowIsa::host()?;
    let carrick = match options.carrick {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe().context("locate this carrick binary")?,
    };
    let instance = instance_name(options.instance);
    std::fs::create_dir_all(options.out)
        .with_context(|| format!("create {}", options.out.display()))?;
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
                let ending = wait_bounded(child, timeout)?;
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
                let censuses = load_censuses(&census)?;
                let (passed, findings) = judge(stage, ending, &stdout, &stderr, &censuses);
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
    print!("{}", write_outputs(options.out, &records, options.limit)?);
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
            go: open /tmp/x: no such file or directory\n";
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
        let rows = rank(&records);
        assert_eq!(rows[0].kind, FindingKind::Fatal);
        assert_eq!((rows[1].count, rows[1].runs, rows[1].of_runs), (10, 2, 3));
        assert_eq!(rows[1].values, ["a", "b"]);
        assert_eq!(rows[2].kind, FindingKind::IpcLeave);
        let table = render(&records, &rows, 10);
        assert!(
            table.contains("| hz-vm | x86_64 | go | build | 1/3 |"),
            "{table}"
        );
        assert!(
            table.contains("| 2 | hz-vm | x86_64 | go | build | refused | mmap(nr=9) caller=child venue=ring | 10 | 2/3 | `a`<br>`b` |"),
            "{table}"
        );
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
        let started = std::time::Instant::now();
        let ending = wait_bounded(child, Duration::from_millis(200)).unwrap();
        assert!(ending.timed_out);
        assert_eq!(ending.signal, Some(libc::SIGKILL));
        assert!(started.elapsed() < Duration::from_secs(10));
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .spawn()
            .unwrap();
        let ending = wait_bounded(child, Duration::from_secs(10)).unwrap();
        assert_eq!((ending.exit_code, ending.timed_out), (Some(3), false));
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
}
