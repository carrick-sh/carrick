use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use carrick_runtime::dtrace_consumer::DTraceRunReport;
use serde::Serialize;
use sha2::{Digest, Sha256};

const DSRPROF2_HEADER_PLACEHOLDER: &str = "/* CARRICK_DSRPROF2_HEADER */";
const DSRPROF2_TERMINALS_PLACEHOLDER: &str = "/* CARRICK_DSRPROF2_TERMINALS */";
const NFAULT2_HEADER_PLACEHOLDER: &str = "/* CARRICK_NFAULT2_HEADER */";
const NFAULT2_TERMINALS_PLACEHOLDER: &str = "/* CARRICK_NFAULT2_TERMINALS */";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct QualificationTraceReport {
    principal_drops: u64,
    aggregation_drops: u64,
    dynamic_drops: u64,
    dynamic_rinse_drops: u64,
    dynamic_dirty_drops: u64,
    other_drops: u64,
    interrupted: bool,
}

impl From<DTraceRunReport> for QualificationTraceReport {
    fn from(report: DTraceRunReport) -> Self {
        Self {
            principal_drops: report.principal_drops,
            aggregation_drops: report.aggregation_drops,
            dynamic_drops: report.dynamic_drops,
            dynamic_rinse_drops: report.dynamic_rinse_drops,
            dynamic_dirty_drops: report.dynamic_dirty_drops,
            other_drops: report.other_drops,
            interrupted: report.interrupted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct NativeProfileQualification {
    schema: &'static str,
    os_build: String,
    birth: BirthQualification,
    terminals: BTreeSet<QualifiedTerminalCall>,
    birth_program_sha256: String,
    terminal_program_sha256: String,
    birth_raw: String,
    terminal_thread_raw: String,
    terminal_process_raw: String,
    birth_raw_sha256: String,
    terminal_thread_raw_sha256: String,
    terminal_process_raw_sha256: String,
    birth_trace_report: QualificationTraceReport,
    terminal_thread_trace_report: QualificationTraceReport,
    terminal_process_trace_report: QualificationTraceReport,
    pub(crate) birth_receipt_sha256: String,
    pub(crate) terminal_receipt_sha256: String,
}

#[cfg(target_os = "macos")]
pub(crate) struct RenderedNativeProfileProgram {
    pub(crate) program: String,
    pub(crate) authority: crate::trace_profile::V2ProfileAuthority,
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

    #[cfg(target_os = "macos")]
    pub(crate) fn birth_receipt_sha256(&self) -> &str {
        &self.birth_receipt_sha256
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn terminal_receipt_sha256(&self) -> &str {
        &self.terminal_receipt_sha256
    }

    #[cfg(target_os = "macos")]
    fn profile_authority(
        &self,
        profile: crate::trace_profile::TraceProfileKind,
        profile_program: &str,
    ) -> Result<crate::trace_profile::V2ProfileAuthority> {
        crate::trace_profile::V2ProfileAuthority::new_for_profile(
            profile,
            &self.os_build,
            &sha256_hex(profile_program.as_bytes()),
            &self.birth_receipt_sha256,
            &self.terminal_receipt_sha256,
            self.terminals.iter().map(|terminal| {
                (
                    terminal.provider.clone(),
                    terminal.function.clone(),
                    terminal.scope.as_str().to_owned(),
                )
            }),
        )
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn render_v2_profile_program(
        &self,
        profile_template: &str,
    ) -> Result<RenderedNativeProfileProgram> {
        self.render_profile_program(
            crate::trace_profile::TraceProfileKind::NativeWall,
            profile_template,
            DSRPROF2_HEADER_PLACEHOLDER,
            DSRPROF2_TERMINALS_PLACEHOLDER,
        )
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn render_native_fault_profile_program(
        &self,
        profile_template: &str,
    ) -> Result<RenderedNativeProfileProgram> {
        self.render_profile_program(
            crate::trace_profile::TraceProfileKind::NativeFault,
            profile_template,
            NFAULT2_HEADER_PLACEHOLDER,
            NFAULT2_TERMINALS_PLACEHOLDER,
        )
    }

    #[cfg(target_os = "macos")]
    fn render_profile_program(
        &self,
        profile: crate::trace_profile::TraceProfileKind,
        profile_template: &str,
        header_placeholder: &str,
        terminals_placeholder: &str,
    ) -> Result<RenderedNativeProfileProgram> {
        let placeholder_count = profile_template.match_indices(header_placeholder).count();
        if placeholder_count != 1 {
            bail!(
                "{} profile template must contain exactly one header placeholder, found {placeholder_count}",
                profile.as_str(),
            );
        }
        let terminal_placeholder_count = profile_template
            .match_indices(terminals_placeholder)
            .count();
        if terminal_placeholder_count != 1 {
            bail!(
                "{} profile template must contain exactly one terminal placeholder, found {terminal_placeholder_count}",
                profile.as_str(),
            );
        }
        // The authority names the immutable bundled template. Hashing the
        // receipt-substituted program would make the header self-referential.
        let authority = self.profile_authority(profile, profile_template)?;
        let header_action = format!("printf(\"{}\\n\");", authority.header_record());
        let terminal_actions = self
            .terminals
            .iter()
            .map(|terminal| {
                let scope = match terminal.scope {
                    TerminalScope::Thread => 1,
                    TerminalScope::Process => 2,
                };
                format!(
                    "terminal_scope[\"{}\", \"{}\"] = {scope};",
                    terminal.provider, terminal.function
                )
            })
            .collect::<Vec<_>>()
            .join("\n\t");
        let program = profile_template
            .replacen(header_placeholder, &header_action, 1)
            .replacen(terminals_placeholder, &terminal_actions, 1);
        Ok(RenderedNativeProfileProgram { program, authority })
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn run_native_profile_qualifications(
    executable: &Path,
    drop_credentials: Option<carrick_runtime::dtrace_consumer::TraceDropCredentials>,
) -> Result<NativeProfileQualification> {
    let os_build = command_output("/usr/sbin/sysctl", &["-n", "kern.osversion"])
        .ok_or_else(|| anyhow!("read Darwin kern.osversion"))?;
    run_native_profile_qualifications_with(
        executable,
        drop_credentials,
        &os_build,
        |child_path, child_argv, options| {
            carrick_runtime::dtrace_consumer::run_child_under_dtrace(
                child_path, child_argv, options,
            )
            .map_err(|error| anyhow!("qualification trace failed: {error}"))
        },
    )
}

#[cfg(target_os = "macos")]
fn run_native_profile_qualifications_with<F>(
    executable: &Path,
    drop_credentials: Option<carrick_runtime::dtrace_consumer::TraceDropCredentials>,
    os_build: &str,
    mut run_trace: F,
) -> Result<NativeProfileQualification>
where
    F: FnMut(
        &Path,
        &[String],
        &carrick_runtime::dtrace_consumer::TraceOptions,
    ) -> Result<DTraceRunReport>,
{
    let (birth_raw, birth_report) = run_qualification_trace(
        executable,
        &[
            "__native-profile-birth-fixture".to_owned(),
            "--hold-ms".to_owned(),
            "500".to_owned(),
            "--quiet".to_owned(),
        ],
        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_BIRTH_QUALIFY_D,
        drop_credentials.clone(),
        "birth",
        &mut run_trace,
    )?;
    parse_birth_qualification(&birth_raw, birth_report)
        .context("validate automatic birth qualification")?;

    let (thread_raw, thread_report) = run_qualification_trace(
        executable,
        &[
            "__native-profile-terminal-fixture".to_owned(),
            "--mode".to_owned(),
            "thread".to_owned(),
            "--quiet".to_owned(),
        ],
        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_TERMINAL_QUALIFY_D,
        drop_credentials.clone(),
        "terminal-thread",
        &mut run_trace,
    )?;
    parse_terminal_qualification(&thread_raw, TerminalScope::Thread, thread_report)
        .context("validate automatic thread-terminal qualification")?;

    let (process_raw, process_report) = run_qualification_trace(
        executable,
        &[
            "__native-profile-terminal-fixture".to_owned(),
            "--mode".to_owned(),
            "process".to_owned(),
            "--quiet".to_owned(),
        ],
        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_TERMINAL_QUALIFY_D,
        drop_credentials,
        "terminal-process",
        &mut run_trace,
    )?;
    parse_terminal_qualification(&process_raw, TerminalScope::Process, process_report)
        .context("validate automatic process-terminal qualification")?;

    build_qualification(
        &birth_raw,
        &thread_raw,
        &process_raw,
        birth_report,
        thread_report,
        process_report,
        os_build,
    )
}

#[cfg(target_os = "macos")]
fn run_qualification_trace<F>(
    executable: &Path,
    command: &[String],
    script: &str,
    drop_credentials: Option<carrick_runtime::dtrace_consumer::TraceDropCredentials>,
    label: &str,
    run_trace: &mut F,
) -> Result<(String, DTraceRunReport)>
where
    F: FnMut(
        &Path,
        &[String],
        &carrick_runtime::dtrace_consumer::TraceOptions,
    ) -> Result<DTraceRunReport>,
{
    let output = tempfile::NamedTempFile::new()
        .with_context(|| format!("create {label} qualification output"))?;
    let options = carrick_runtime::dtrace_consumer::TraceOptions {
        flowindent: false,
        script: Some(script.to_owned()),
        out_path: Some(output.path().to_string_lossy().into_owned()),
        drop_credentials,
        print_remaining_aggregates: false,
    };
    let report = run_trace(executable, command, &options)
        .with_context(|| format!("run {label} qualification"))?;
    let raw = fs::read_to_string(output.path())
        .with_context(|| format!("read {label} qualification output"))?;
    Ok((raw, report))
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
    let birth_trace_report = birth_report.into();
    let terminal_thread_trace_report = thread_report.into();
    let terminal_process_trace_report = process_report.into();
    let birth_receipt_sha256 = sha256_hex(
        &serde_json::to_vec(&serde_json::json!({
            "schema": "carrick.native-profile-birth-qualification.v1",
            "os_build": os_build,
            "program_sha256": birth_program_sha256,
            "raw_sha256": birth_raw_sha256,
            "trace_report": birth_trace_report,
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
            "thread_trace_report": terminal_thread_trace_report,
            "process_trace_report": terminal_process_trace_report,
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
        birth_raw: birth_raw.to_owned(),
        terminal_thread_raw: thread_raw.to_owned(),
        terminal_process_raw: process_raw.to_owned(),
        birth_raw_sha256,
        terminal_thread_raw_sha256,
        terminal_process_raw_sha256,
        birth_trace_report,
        terminal_thread_trace_report,
        terminal_process_trace_report,
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
    const fn as_str(self) -> &'static str {
        match self {
            Self::Thread => "thread",
            Self::Process => "process",
        }
    }

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
        || report.dynamic_rinse_drops != 0
        || report.dynamic_dirty_drops != 0
        || report.other_drops != 0
        || report.interrupted
    {
        bail!(
            "{label} qualification was lossy: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            report.principal_drops,
            report.aggregation_drops,
            report.dynamic_drops,
            report.dynamic_rinse_drops,
            report.dynamic_dirty_drops,
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
        let rendered = authority
            .render_json()
            .unwrap_or_else(|error| unreachable!("render qualification: {error}"));
        let json: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|error| unreachable!("parse qualification JSON: {error}"));
        let lossless = serde_json::json!({
            "principal_drops": 0,
            "aggregation_drops": 0,
            "dynamic_drops": 0,
            "dynamic_rinse_drops": 0,
            "dynamic_dirty_drops": 0,
            "other_drops": 0,
            "interrupted": false,
        });
        assert_eq!(json["birth_trace_report"], lossless);
        assert_eq!(json["terminal_thread_trace_report"], lossless);
        assert_eq!(json["terminal_process_trace_report"], lossless);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rendered_profile_binds_receipts_without_self_referential_program_hash() {
        const TEMPLATE: &str = concat!(
            "dtrace:::BEGIN\n{\n",
            "\t/* CARRICK_DSRPROF2_HEADER */\n",
            "\t/* CARRICK_DSRPROF2_TERMINALS */\n",
            "}\n",
        );
        const TEMPLATE_SHA256: &str =
            "0165d2911bb8ac98c4295e66beed1a34742ca0d6fcaac6f15894c3545a838c6e";

        let first = build_qualification(
            BIRTH,
            THREAD,
            PROCESS,
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            "26A123",
        )
        .unwrap_or_else(|error| unreachable!("valid first qualification: {error}"));
        let second_birth = BIRTH.replacen("parent_usec=386633", "parent_usec=386634", 1);
        let second = build_qualification(
            &second_birth,
            THREAD,
            PROCESS,
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            "26A123",
        )
        .unwrap_or_else(|error| unreachable!("valid second qualification: {error}"));

        let first_rendered = first
            .render_v2_profile_program(TEMPLATE)
            .unwrap_or_else(|error| unreachable!("render first profile: {error}"));
        let second_rendered = second
            .render_v2_profile_program(TEMPLATE)
            .unwrap_or_else(|error| unreachable!("render second profile: {error}"));

        assert_eq!(first_rendered.authority.program_sha256(), TEMPLATE_SHA256);
        assert_eq!(second_rendered.authority.program_sha256(), TEMPLATE_SHA256);
        assert_ne!(
            first_rendered.authority.header_record(),
            second_rendered.authority.header_record()
        );
        assert_eq!(
            first_rendered.program,
            format!(
                concat!(
                    "dtrace:::BEGIN\n{{\n",
                    "\tprintf(\"{}\\n\");\n",
                    "\tterminal_scope[\"syscall\", \"bsdthread_terminate\"] = 1;\n",
                    "\tterminal_scope[\"syscall\", \"exit\"] = 2;\n",
                    "}}\n",
                ),
                first_rendered.authority.header_record()
            )
        );

        for malformed in [
            "dtrace:::BEGIN { }",
            "/* CARRICK_DSRPROF2_HEADER */\n/* CARRICK_DSRPROF2_HEADER */\n",
            "/* CARRICK_DSRPROF2_HEADER */\n",
            concat!(
                "/* CARRICK_DSRPROF2_HEADER */\n",
                "/* CARRICK_DSRPROF2_TERMINALS */\n",
                "/* CARRICK_DSRPROF2_TERMINALS */\n",
            ),
        ] {
            assert!(first.render_v2_profile_program(malformed).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_fault_render_has_one_authenticated_header_and_terminal_map() {
        const TEMPLATE: &str = concat!(
            "dtrace:::BEGIN\n{\n",
            "\t/* CARRICK_NFAULT2_HEADER */\n",
            "\t/* CARRICK_NFAULT2_TERMINALS */\n",
            "}\n",
        );
        let qualification = build_qualification(
            BIRTH,
            THREAD,
            PROCESS,
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            DTraceRunReport::default(),
            "26A123",
        )
        .expect("valid qualification");

        let rendered = qualification
            .render_native_fault_profile_program(TEMPLATE)
            .expect("render native-fault profile");
        assert_eq!(rendered.program.matches("NFAULT2|header|").count(), 1);
        assert!(rendered.program.contains(
            "profile=native-fault|raw_schema=carrick.native-fault.raw.v2|os_build=26A123|"
        ));
        assert_eq!(
            rendered.program.matches("terminal_scope[").count(),
            qualification.terminals.len()
        );
        assert!(
            rendered
                .program
                .contains("terminal_scope[\"syscall\", \"bsdthread_terminate\"] = 1;")
        );
        assert!(
            rendered
                .program
                .contains("terminal_scope[\"syscall\", \"exit\"] = 2;")
        );
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

    #[cfg(target_os = "macos")]
    #[test]
    fn automatic_suite_runs_exact_quiet_fixtures_and_retains_raw_evidence() {
        let credentials = carrick_runtime::dtrace_consumer::TraceDropCredentials {
            uid: 501,
            gid: 20,
            groups: vec![20, 12],
        };
        let mut calls = Vec::new();
        let qualification = run_native_profile_qualifications_with(
            Path::new("/tmp/carrick"),
            Some(credentials.clone()),
            "26A123",
            |executable, command, options| {
                assert_eq!(executable, Path::new("/tmp/carrick"));
                assert_eq!(options.drop_credentials, Some(credentials.clone()));
                assert!(!options.flowindent);
                assert!(!options.print_remaining_aggregates);
                let command = command.join(" ");
                let (expected_script, raw) = match command.as_str() {
                    "__native-profile-birth-fixture --hold-ms 500 --quiet" => (
                        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_BIRTH_QUALIFY_D,
                        BIRTH,
                    ),
                    "__native-profile-terminal-fixture --mode thread --quiet" => (
                        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_TERMINAL_QUALIFY_D,
                        THREAD,
                    ),
                    "__native-profile-terminal-fixture --mode process --quiet" => (
                        carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_TERMINAL_QUALIFY_D,
                        PROCESS,
                    ),
                    other => unreachable!("unexpected qualification command {other:?}"),
                };
                assert_eq!(options.script.as_deref(), Some(expected_script));
                let output = options
                    .out_path
                    .as_deref()
                    .unwrap_or_else(|| unreachable!("qualification output path"));
                std::fs::write(output, raw)
                    .unwrap_or_else(|error| unreachable!("write qualification output: {error}"));
                calls.push(command);
                Ok(DTraceRunReport::default())
            },
        )
        .unwrap_or_else(|error| unreachable!("automatic qualification: {error}"));

        assert_eq!(
            calls,
            [
                "__native-profile-birth-fixture --hold-ms 500 --quiet",
                "__native-profile-terminal-fixture --mode thread --quiet",
                "__native-profile-terminal-fixture --mode process --quiet",
            ]
        );
        let rendered = qualification
            .render_json()
            .unwrap_or_else(|error| unreachable!("render automatic qualification: {error}"));
        let json: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|error| unreachable!("parse automatic qualification JSON: {error}"));
        assert_eq!(json["birth_raw"], BIRTH);
        assert_eq!(json["terminal_thread_raw"], THREAD);
        assert_eq!(json["terminal_process_raw"], PROCESS);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn automatic_suite_stops_at_the_first_lossy_consumer_report() {
        let mut calls = 0_usize;
        let error = run_native_profile_qualifications_with(
            Path::new("/tmp/carrick"),
            None,
            "26A123",
            |_executable, command, options| {
                calls += 1;
                let raw = if command.get(2).map(String::as_str) == Some("thread") {
                    THREAD
                } else if command.first().map(String::as_str)
                    == Some("__native-profile-birth-fixture")
                {
                    BIRTH
                } else {
                    PROCESS
                };
                std::fs::write(
                    options
                        .out_path
                        .as_deref()
                        .unwrap_or_else(|| unreachable!("qualification output path")),
                    raw,
                )
                .unwrap_or_else(|write_error| {
                    unreachable!("write qualification output: {write_error}")
                });
                Ok(DTraceRunReport {
                    principal_drops: u64::from(calls == 2),
                    ..DTraceRunReport::default()
                })
            },
        )
        .expect_err("lossy terminal qualification must fail before process fixture");
        assert!(error.chain().any(|cause| {
            cause
                .to_string()
                .contains("terminal qualification was lossy")
        }));
        assert_eq!(calls, 2);
    }
}
