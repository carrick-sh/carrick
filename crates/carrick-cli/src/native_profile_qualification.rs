use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use carrick_runtime::dtrace_consumer::DTraceRunReport;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TerminalScope {
    Thread,
    Process,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct QualifiedTerminalCall {
    pub(crate) provider: String,
    pub(crate) function: String,
    pub(crate) scope: TerminalScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct BirthQualification {
    pub(crate) parent_pid: u32,
    pub(crate) parent_sec: i64,
    pub(crate) parent_usec: i32,
    pub(crate) child_pid: u32,
    pub(crate) child_sec: i64,
    pub(crate) child_usec: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalQualification {
    pub(crate) calls: BTreeSet<QualifiedTerminalCall>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct NativeProfileQualification {
    schema: &'static str,
    os_build: String,
    birth: BirthQualification,
    terminals: BTreeSet<QualifiedTerminalCall>,
    birth_program_sha256: String,
    terminal_program_sha256: String,
    birth_raw_sha256: String,
    terminal_thread_raw_sha256: String,
    terminal_process_raw_sha256: String,
    pub(crate) birth_receipt_sha256: String,
    pub(crate) terminal_receipt_sha256: String,
}

pub(crate) fn validate_qualification_paths(
    birth_path: &Path,
    thread_path: &Path,
    process_path: &Path,
) -> Result<NativeProfileQualification> {
    let birth_raw = fs::read_to_string(birth_path)
        .with_context(|| format!("read birth qualification {}", birth_path.display()))?;
    let thread_raw = fs::read_to_string(thread_path)
        .with_context(|| format!("read thread qualification {}", thread_path.display()))?;
    let process_raw = fs::read_to_string(process_path)
        .with_context(|| format!("read process qualification {}", process_path.display()))?;
    let os_build = command_output("/usr/sbin/sysctl", &["-n", "kern.osversion"])
        .ok_or_else(|| anyhow!("read Darwin kern.osversion"))?;
    build_qualification(
        &birth_raw,
        &thread_raw,
        &process_raw,
        DTraceRunReport::default(),
        DTraceRunReport::default(),
        DTraceRunReport::default(),
        &os_build,
    )
}

impl NativeProfileQualification {
    pub(crate) fn render_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize native-profile qualification")
    }
}

#[allow(clippy::too_many_arguments)]
fn build_qualification(
    birth_raw: &str,
    thread_raw: &str,
    process_raw: &str,
    birth_report: DTraceRunReport,
    thread_report: DTraceRunReport,
    process_report: DTraceRunReport,
    os_build: &str,
) -> Result<NativeProfileQualification> {
    if os_build.is_empty() {
        bail!("Darwin OS build must not be empty");
    }
    validate_token(os_build, "Darwin OS build")?;
    let birth = parse_birth_qualification(birth_raw, birth_report)?;
    let thread = parse_terminal_qualification(thread_raw, TerminalScope::Thread, thread_report)?;
    let process =
        parse_terminal_qualification(process_raw, TerminalScope::Process, process_report)?;
    let terminals = thread
        .calls
        .into_iter()
        .chain(process.calls)
        .collect::<BTreeSet<_>>();
    let birth_program_sha256 =
        sha256_hex(carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_BIRTH_QUALIFY_D.as_bytes());
    let terminal_program_sha256 =
        sha256_hex(carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_TERMINAL_QUALIFY_D.as_bytes());
    let birth_raw_sha256 = sha256_hex(birth_raw.as_bytes());
    let terminal_thread_raw_sha256 = sha256_hex(thread_raw.as_bytes());
    let terminal_process_raw_sha256 = sha256_hex(process_raw.as_bytes());
    let birth_receipt_sha256 = sha256_hex(
        &serde_json::to_vec(&serde_json::json!({
            "schema": "carrick.native-profile-birth-qualification.v1",
            "os_build": os_build,
            "program_sha256": birth_program_sha256,
            "raw_sha256": birth_raw_sha256,
            "birth": birth,
        }))
        .context("serialize birth qualification receipt")?,
    );
    let terminal_receipt_sha256 = sha256_hex(
        &serde_json::to_vec(&serde_json::json!({
            "schema": "carrick.native-profile-terminal-qualification.v1",
            "os_build": os_build,
            "program_sha256": terminal_program_sha256,
            "thread_raw_sha256": terminal_thread_raw_sha256,
            "process_raw_sha256": terminal_process_raw_sha256,
            "terminals": terminals,
        }))
        .context("serialize terminal qualification receipt")?,
    );
    Ok(NativeProfileQualification {
        schema: "carrick.native-profile-qualification.v1",
        os_build: os_build.to_owned(),
        birth,
        terminals,
        birth_program_sha256,
        terminal_program_sha256,
        birth_raw_sha256,
        terminal_thread_raw_sha256,
        terminal_process_raw_sha256,
        birth_receipt_sha256,
        terminal_receipt_sha256,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

pub(crate) fn parse_birth_qualification(
    raw: &str,
    report: DTraceRunReport,
) -> Result<BirthQualification> {
    require_lossless(report, "birth")?;
    let lines = raw
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        bail!("birth qualification must contain exactly one receipt record");
    }
    let record = QualificationRecord::parse(lines[0], "BIRTHQUAL1", false)?;
    record.exact_fields(&[
        "child_context_sec",
        "child_context_seen",
        "child_context_usec",
        "child_create_sec",
        "child_create_usec",
        "child_exit_reason",
        "child_pid",
        "create_seen",
        "marker_seen",
        "parent_observations",
        "parent_pid",
        "parent_sec",
        "parent_usec",
        "schema",
        "target_exit_reason",
        "timed_out",
        "violations",
    ])?;
    require_exact_u64(&record, "schema", 1)?;
    require_exact_u64(&record, "parent_observations", 2)?;
    require_exact_u64(&record, "create_seen", 1)?;
    require_exact_u64(&record, "child_context_seen", 2)?;
    require_exact_u64(&record, "marker_seen", 1)?;
    require_exact_u64(&record, "child_exit_reason", 1)?;
    require_exact_u64(&record, "target_exit_reason", 1)?;
    require_exact_u64(&record, "timed_out", 0)?;
    require_exact_u64(&record, "violations", 0)?;

    let parent_pid = record.u32("parent_pid")?;
    let child_pid = record.u32("child_pid")?;
    let parent_sec = record.i64("parent_sec")?;
    let parent_usec = record.i32("parent_usec")?;
    let child_create_sec = record.i64("child_create_sec")?;
    let child_create_usec = record.i32("child_create_usec")?;
    let child_context_sec = record.i64("child_context_sec")?;
    let child_context_usec = record.i32("child_context_usec")?;
    validate_birth_tuple(parent_pid, parent_sec, parent_usec, "parent")?;
    validate_birth_tuple(child_pid, child_create_sec, child_create_usec, "child")?;
    if (child_create_sec, child_create_usec) != (child_context_sec, child_context_usec) {
        bail!("child create and child-context birth tuples differ");
    }
    if (parent_pid, parent_sec, parent_usec) == (child_pid, child_create_sec, child_create_usec) {
        bail!("parent and child birth tuples are identical");
    }
    Ok(BirthQualification {
        parent_pid,
        parent_sec,
        parent_usec,
        child_pid,
        child_sec: child_create_sec,
        child_usec: child_create_usec,
    })
}

pub(crate) fn parse_terminal_qualification(
    raw: &str,
    expected_scope: TerminalScope,
    report: DTraceRunReport,
) -> Result<TerminalQualification> {
    require_lossless(report, "terminal")?;
    let lines = raw
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 2 {
        bail!("terminal qualification must contain one candidate and one summary");
    }
    let candidate = QualificationRecord::parse(lines[0], "TERMINALQUAL1", true)?;
    if candidate.tag.as_deref() != Some("candidate") {
        bail!("terminal qualification candidate must be first");
    }
    candidate.exact_fields(&["function", "provider", "schema", "scope"])?;
    require_exact_u64(&candidate, "schema", 1)?;
    let provider = candidate.required("provider")?.to_owned();
    if !matches!(provider.as_str(), "syscall" | "mach_trap") {
        bail!("unknown terminal provider {provider:?}");
    }
    let function = candidate.required("function")?.to_owned();
    validate_token(&function, "terminal function")?;
    let scope = TerminalScope::parse(candidate.required("scope")?)?;
    if scope != expected_scope {
        bail!("terminal candidate scope differs from requested fixture mode");
    }

    let summary = QualificationRecord::parse(lines[1], "TERMINALQUAL1", true)?;
    if summary.tag.as_deref() != Some("summary") {
        bail!("terminal qualification summary must be final");
    }
    summary.exact_fields(&[
        "candidate_count",
        "lwp_exit_seen",
        "mode",
        "process_armed_seen",
        "process_exit_reason",
        "returning_controls",
        "schema",
        "thread_armed_seen",
        "thread_ok_seen",
        "timed_out",
        "violations",
    ])?;
    require_exact_u64(&summary, "schema", 1)?;
    require_exact_u64(&summary, "candidate_count", 1)?;
    require_exact_u64(&summary, "process_exit_reason", 1)?;
    require_exact_u64(&summary, "timed_out", 0)?;
    require_exact_u64(&summary, "violations", 0)?;
    if summary.u64("returning_controls")? == 0 {
        bail!("terminal qualification has no returning-call negative control");
    }
    match expected_scope {
        TerminalScope::Thread => {
            if summary.required("mode")? != "thread" {
                bail!("thread terminal receipt has wrong mode");
            }
            require_exact_u64(&summary, "thread_armed_seen", 1)?;
            require_exact_u64(&summary, "thread_ok_seen", 1)?;
            require_exact_u64(&summary, "process_armed_seen", 0)?;
            require_exact_u64(&summary, "lwp_exit_seen", 1)?;
        }
        TerminalScope::Process => {
            if summary.required("mode")? != "process" {
                bail!("process terminal receipt has wrong mode");
            }
            require_exact_u64(&summary, "thread_armed_seen", 0)?;
            require_exact_u64(&summary, "thread_ok_seen", 0)?;
            require_exact_u64(&summary, "process_armed_seen", 1)?;
            require_exact_u64(&summary, "lwp_exit_seen", 0)?;
        }
    }
    Ok(TerminalQualification {
        calls: BTreeSet::from([QualifiedTerminalCall {
            provider,
            function,
            scope,
        }]),
    })
}

impl TerminalScope {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "thread" => Ok(Self::Thread),
            "process" => Ok(Self::Process),
            other => bail!("unknown terminal scope {other:?}"),
        }
    }
}

#[derive(Debug)]
struct QualificationRecord {
    tag: Option<String>,
    fields: BTreeMap<String, String>,
}

impl QualificationRecord {
    fn parse(line: &str, prefix: &str, tagged: bool) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(prefix) {
            bail!("unknown qualification prefix");
        }
        let tag = if tagged {
            Some(
                parts
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("qualification record is missing its tag"))?
                    .to_owned(),
            )
        } else {
            None
        };
        let mut fields = BTreeMap::new();
        for field in parts {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| anyhow!("qualification field lacks '='"))?;
            if key.is_empty() || value.is_empty() {
                bail!("qualification field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate qualification field {key:?}"),
            }
        }
        Ok(Self { tag, fields })
    }

    fn exact_fields(&self, expected: &[&str]) -> Result<()> {
        let actual = self
            .fields
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
            bail!("qualification field mismatch: missing={missing:?}, extra={extra:?}");
        }
        Ok(())
    }

    fn required(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("qualification record is missing {field:?}"))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        let value = self.required(field)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("qualification field {field:?} is not unsigned decimal");
        }
        value
            .parse::<u64>()
            .with_context(|| format!("qualification field {field:?} exceeds u64"))
    }

    fn u32(&self, field: &str) -> Result<u32> {
        u32::try_from(self.u64(field)?)
            .with_context(|| format!("qualification field {field:?} exceeds u32"))
    }

    fn i64(&self, field: &str) -> Result<i64> {
        let value = self.required(field)?;
        let digits = value.strip_prefix('-').unwrap_or(value);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("qualification field {field:?} is not signed decimal");
        }
        value
            .parse::<i64>()
            .with_context(|| format!("qualification field {field:?} exceeds i64"))
    }

    fn i32(&self, field: &str) -> Result<i32> {
        i32::try_from(self.i64(field)?)
            .with_context(|| format!("qualification field {field:?} exceeds i32"))
    }
}

fn require_exact_u64(record: &QualificationRecord, field: &str, expected: u64) -> Result<()> {
    let actual = record.u64(field)?;
    if actual != expected {
        bail!("qualification field {field:?} is {actual}, expected {expected}");
    }
    Ok(())
}

fn validate_birth_tuple(pid: u32, sec: i64, usec: i32, label: &str) -> Result<()> {
    if pid == 0 || sec <= 0 || !(0..1_000_000).contains(&usec) {
        bail!("{label} birth tuple is invalid");
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} is empty");
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    bail!("{label} contains an invalid percent escape");
                }
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':') => {
                index += 1;
            }
            _ => bail!("{label} contains an unescaped byte"),
        }
    }
    Ok(())
}

fn require_lossless(report: DTraceRunReport, label: &str) -> Result<()> {
    if report.principal_drops != 0
        || report.aggregation_drops != 0
        || report.dynamic_drops != 0
        || report.other_drops != 0
        || report.interrupted
    {
        bail!(
            "{label} qualification was lossy: drops={}/{}/{}/{}, interrupted={}",
            report.principal_drops,
            report.aggregation_drops,
            report.dynamic_drops,
            report.other_drops,
            report.interrupted
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIRTH: &str = "BIRTHQUAL1|schema=1|parent_pid=56364|parent_sec=1785512598|parent_usec=386633|parent_observations=2|child_pid=56367|child_create_sec=1785512598|child_create_usec=636374|child_context_sec=1785512598|child_context_usec=636374|create_seen=1|child_context_seen=2|marker_seen=1|child_exit_reason=1|target_exit_reason=1|timed_out=0|violations=0\n";
    const THREAD: &str = concat!(
        "TERMINALQUAL1|candidate|schema=1|provider=syscall|function=bsdthread_terminate|scope=thread\n",
        "TERMINALQUAL1|summary|schema=1|mode=thread|thread_armed_seen=1|thread_ok_seen=1|process_armed_seen=0|returning_controls=3|candidate_count=1|lwp_exit_seen=1|process_exit_reason=1|timed_out=0|violations=0\n",
    );
    const PROCESS: &str = concat!(
        "TERMINALQUAL1|candidate|schema=1|provider=syscall|function=exit|scope=process\n",
        "TERMINALQUAL1|summary|schema=1|mode=process|thread_armed_seen=0|thread_ok_seen=0|process_armed_seen=1|returning_controls=1|candidate_count=1|lwp_exit_seen=0|process_exit_reason=1|timed_out=0|violations=0\n",
    );

    #[test]
    fn accepts_exact_birth_and_terminal_receipts() {
        let birth = parse_birth_qualification(BIRTH, DTraceRunReport::default())
            .unwrap_or_else(|error| unreachable!("valid birth receipt: {error}"));
        assert_eq!(birth.parent_pid, 56364);
        assert_eq!(birth.child_pid, 56367);
        assert_ne!(birth.parent_usec, birth.child_usec);

        let thread =
            parse_terminal_qualification(THREAD, TerminalScope::Thread, DTraceRunReport::default())
                .unwrap_or_else(|error| unreachable!("valid thread receipt: {error}"));
        let process = parse_terminal_qualification(
            PROCESS,
            TerminalScope::Process,
            DTraceRunReport::default(),
        )
        .unwrap_or_else(|error| unreachable!("valid process receipt: {error}"));
        assert!(thread.calls.contains(&QualifiedTerminalCall {
            provider: "syscall".to_owned(),
            function: "bsdthread_terminate".to_owned(),
            scope: TerminalScope::Thread,
        }));
        assert!(process.calls.contains(&QualifiedTerminalCall {
            provider: "syscall".to_owned(),
            function: "exit".to_owned(),
            scope: TerminalScope::Process,
        }));

        let authority = build_qualification(
            BIRTH,
            THREAD,
            PROCESS,
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            "26A123",
        )
        .unwrap_or_else(|error| unreachable!("valid combined authority: {error}"));
        assert_eq!(authority.schema, "carrick.native-profile-qualification.v1");
        assert_eq!(authority.terminals.len(), 2);
        assert_eq!(authority.birth_receipt_sha256.len(), 64);
        assert_eq!(authority.terminal_receipt_sha256.len(), 64);
    }

    #[test]
    fn rejects_corrupted_qualification_receipts() {
        for raw in [
            BIRTH.replacen("parent_observations=2", "parent_observations=1", 1),
            BIRTH.replacen("child_context_usec=636374", "child_context_usec=636375", 1),
            BIRTH.replacen("marker_seen=1", "marker_seen=0", 1),
            BIRTH.replacen("violations=0", "violations=1", 1),
            BIRTH.replacen("target_exit_reason=1", "target_exit_reason=2", 1),
        ] {
            assert!(parse_birth_qualification(&raw, DTraceRunReport::default()).is_err());
        }
        assert!(
            parse_birth_qualification(
                BIRTH,
                DTraceRunReport {
                    principal_drops: 1,
                    ..DTraceRunReport::default()
                },
            )
            .is_err()
        );

        for raw in [
            THREAD.replacen("scope=thread", "scope=process", 1),
            THREAD.replacen("returning_controls=3", "returning_controls=0", 1),
            THREAD.replacen("candidate_count=1", "candidate_count=2", 1),
            THREAD.replacen("function=bsdthread_terminate", "function=bad%token", 1),
            THREAD.replacen("violations=0", "violations=1", 1),
            format!("{THREAD}TERMINALQUAL1|unknown|schema=1\n"),
        ] {
            assert!(
                parse_terminal_qualification(
                    &raw,
                    TerminalScope::Thread,
                    DTraceRunReport::default(),
                )
                .is_err()
            );
        }
        assert!(
            parse_terminal_qualification(
                PROCESS,
                TerminalScope::Thread,
                DTraceRunReport::default(),
            )
            .is_err()
        );
    }
}
