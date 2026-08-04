use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufWriter, Write};
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use carrick_image::ImageReference;
use carrick_spec::ExecBackendRequest;
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::args::{Cli, Commands};
use crate::jit_shape_snapshot::{SnapshotManifest, SnapshotSet};
use crate::trace_profile::TraceProfileKind;

pub(crate) const CAPTURE_SCHEMA: &str = "carrick.native-shape-capture.v1";
pub(crate) const RAW_SCHEMA: &str = "carrick.native-shape.raw.v2";
pub(crate) const SAMPLING_HZ: u64 = 997;
const AUTHORITY_SCHEMA: &str = "carrick.native-shape-authority.v1";
const PROFILE: &str = "native-shape";
const NORMAL_TARGET_EXIT_REASON: i32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeShapeTarget {
    pub(crate) image: String,
    pub(crate) image_digest: String,
    pub(crate) argv: Vec<String>,
    pub(crate) argv_sha256: String,
}

impl NativeShapeTarget {
    pub(crate) fn parse(command: &[String]) -> Result<Self> {
        if command.is_empty() {
            bail!("native-shape target command is empty");
        }

        let mut argv = Vec::<OsString>::with_capacity(command.len() + 1);
        argv.push(OsString::from("carrick"));
        argv.extend(command.iter().map(OsString::from));
        let matches = Cli::command()
            .try_get_matches_from(argv)
            .context("parse native-shape target command")?;
        let Some((subcommand, run_matches)) = matches.subcommand() else {
            bail!("native-shape target must be a run subcommand");
        };
        if subcommand != "run" {
            bail!("native-shape target must be a run subcommand");
        }
        if run_matches.value_source("exec_backend") != Some(ValueSource::CommandLine) {
            bail!("native-shape target requires explicit command-line --exec-backend native");
        }

        let parsed = Cli::from_arg_matches(&matches).context("decode native-shape target")?;
        let Commands::Run {
            image,
            exec_backend,
            command: target_command,
            ..
        } = parsed.command
        else {
            bail!("native-shape target must be a run subcommand");
        };
        if exec_backend != ExecBackendRequest::Native {
            bail!("native-shape target requires explicit command-line --exec-backend native");
        }
        if target_command.is_empty() {
            bail!("native-shape run target command is empty");
        }

        if let Some((_, digest)) = image.rsplit_once('@') {
            validate_image_digest(digest).context("validate native-shape image digest")?;
        }
        let reference = ImageReference::parse(&image).context("parse native-shape image")?;
        let image_digest = reference
            .digest()
            .context("native-shape image must be digest-pinned")?
            .to_owned();
        validate_image_digest(&image_digest)?;
        let target = Self {
            image: reference.canonical(),
            image_digest,
            argv: command.to_vec(),
            argv_sha256: argv_sha256(command)?,
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<()> {
        validate_image_digest(&self.image_digest)?;
        let image = ImageReference::parse(&self.image).context("validate native-shape image")?;
        if image.canonical() != self.image || image.digest() != Some(self.image_digest.as_str()) {
            bail!("native-shape image identity is not canonical and digest-consistent");
        }
        if self.argv.is_empty() || self.argv_sha256 != argv_sha256(&self.argv)? {
            bail!("native-shape target argv identity is inconsistent");
        }
        Ok(())
    }
}

fn validate_image_digest(digest: &str) -> Result<()> {
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .context("native-shape image digest must use sha256")?;
    validate_lower_hex(hexadecimal, 64, "native-shape image digest")
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureIdentity {
    pub(crate) git_head: String,
    pub(crate) git_dirty: bool,
    pub(crate) executable_sha256: String,
    pub(crate) host: String,
    pub(crate) host_arch: String,
    pub(crate) os_build: String,
}

impl CaptureIdentity {
    pub(crate) fn capture(executable: &Path) -> Result<Self> {
        let git_head = required_command_text("git", &["rev-parse", "HEAD"], "Git HEAD")?;
        let git_status = command_stdout("git", &["status", "--porcelain"], "Git status")?;
        let git_dirty = !git_status.is_empty();
        let executable_bytes = fs::read(executable)
            .with_context(|| format!("read capture executable {}", executable.display()))?;
        let identity = Self {
            git_head,
            git_dirty,
            executable_sha256: format!("{:x}", Sha256::digest(executable_bytes)),
            host: required_command_text("hostname", &[], "hostname")?,
            host_arch: std::env::consts::ARCH.to_owned(),
            os_build: required_command_text(
                "/usr/sbin/sysctl",
                &["-n", "kern.osversion"],
                "Darwin kern.osversion",
            )?,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_lower_hex(&self.git_head, 40, "capture Git HEAD")?;
        if self.git_dirty {
            bail!("native-shape capture requires a clean Git worktree");
        }
        validate_sha256(&self.executable_sha256, "capture executable_sha256")?;
        for (value, field) in [
            (&self.host, "capture hostname"),
            (&self.host_arch, "capture host architecture"),
            (&self.os_build, "capture OS build"),
        ] {
            if value.is_empty() {
                bail!("{field} is unknown or empty");
            }
        }
        validate_percent_token(&self.os_build, "capture OS build")?;
        Ok(())
    }

    pub(crate) fn require_exact_match(&self, observed: &Self) -> Result<()> {
        self.validate().context("validate pre-capture identity")?;
        observed
            .validate()
            .context("validate post-capture identity")?;
        if self != observed {
            bail!("native-shape capture identity drifted");
        }
        Ok(())
    }

    pub(crate) fn recapture_and_require_exact_match(&self, executable: &Path) -> Result<Self> {
        let observed = Self::capture(executable)?;
        self.require_exact_match(&observed)?;
        Ok(observed)
    }
}

fn command_stdout(program: &str, arguments: &[&str], label: &str) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("run {label} command"))?;
    if !output.status.success() {
        bail!("{label} command failed with {}", output.status);
    }
    Ok(output.stdout)
}

fn required_command_text(program: &str, arguments: &[&str], label: &str) -> Result<String> {
    let bytes = command_stdout(program, arguments, label)?;
    let output = String::from_utf8(bytes).with_context(|| format!("decode {label} output"))?;
    let output = output.trim();
    if output.is_empty() {
        bail!("{label} is unknown or empty");
    }
    Ok(output.to_owned())
}

pub(crate) fn validate_native_shape_host(os: &str, arch: &str) -> Result<()> {
    if os != "macos" || arch != "aarch64" {
        bail!("native-shape requires a Darwin/AArch64 host");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_native_shape_trace_arguments(
    profile: Option<TraceProfileKind>,
    script: Option<&Path>,
    trace_out: Option<&Path>,
    summary_jsonl: Option<&Path>,
    snapshot_directory: Option<&Path>,
    current_directory: &Path,
) -> Result<()> {
    if profile != Some(TraceProfileKind::NativeShape) {
        if snapshot_directory.is_some() {
            bail!("--native-shape-snapshots requires --profile native-shape");
        }
        return Ok(());
    }
    if script.is_some() {
        bail!("--profile native-shape cannot be combined with --script");
    }

    let trace_out = trace_out.context("native-shape requires --trace-out")?;
    let summary_jsonl = summary_jsonl.context("native-shape requires --summary-jsonl")?;
    let snapshot_directory =
        snapshot_directory.context("native-shape requires --native-shape-snapshots")?;
    let raw = lexical_absolute(trace_out, current_directory)?;
    let receipt = lexical_absolute(summary_jsonl, current_directory)?;
    let snapshots = lexical_absolute(snapshot_directory, current_directory)?;
    if raw == receipt {
        bail!("--trace-out and --summary-jsonl must name different files");
    }
    if raw == snapshots || receipt == snapshots {
        bail!("native-shape output file must not alias the snapshot directory");
    }
    Ok(())
}

fn lexical_absolute(path: &Path, current_directory: &Path) -> Result<PathBuf> {
    if !current_directory.is_absolute() {
        bail!("native-shape current directory is not absolute");
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        current_directory.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    if !normalized.is_absolute() {
        bail!("native-shape path did not normalize to an absolute path");
    }
    Ok(normalized)
}

pub(crate) fn require_native_shape_snapshot_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "native-shape snapshot path already exists: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect native-shape snapshot path {}", path.display())),
    }
}

#[cfg(unix)]
pub(crate) fn claim_native_shape_snapshot_directory(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    fs::create_dir(path)
        .with_context(|| format!("create native-shape snapshot directory {}", path.display()))?;
    let created_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect native-shape snapshot directory {}", path.display()))?;
    if !created_metadata.is_dir() || created_metadata.file_type().is_symlink() {
        bail!("native-shape snapshot path is not a real directory");
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open native-shape snapshot directory {}", path.display()))?;
    let opened_metadata = directory
        .metadata()
        .with_context(|| format!("inspect opened snapshot directory {}", path.display()))?;
    if !opened_metadata.is_dir() {
        bail!("opened native-shape snapshot path is not a directory");
    }
    let result = unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("set native-shape snapshot directory owner");
    }
    let final_metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "reinspect native-shape snapshot directory {} after ownership",
            path.display()
        )
    })?;
    validate_snapshot_claim_metadata(
        &created_metadata,
        &opened_metadata,
        &final_metadata,
        uid,
        gid,
    )?;
    Ok(())
}

#[cfg(unix)]
fn validate_snapshot_claim_metadata(
    created: &fs::Metadata,
    opened: &fs::Metadata,
    final_path: &fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    for (label, metadata) in [
        ("post-create", created),
        ("opened", opened),
        ("final pathname", final_path),
    ] {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("native-shape snapshot {label} object is not a real directory");
        }
    }
    let created_identity = (created.dev(), created.ino());
    if (opened.dev(), opened.ino()) != created_identity {
        bail!("native-shape snapshot opened directory differs from created directory");
    }
    if (final_path.dev(), final_path.ino()) != created_identity {
        bail!("native-shape snapshot final pathname differs from created directory");
    }
    if final_path.uid() != expected_uid || final_path.gid() != expected_gid {
        bail!("native-shape snapshot final owner does not match trace uid/gid");
    }
    Ok(())
}

pub(crate) fn resolve_native_shape_run_id(
    existing: Option<&OsStr>,
    utc_timestamp: &str,
    pid: u32,
) -> Result<String> {
    if let Some(existing) = existing {
        let value = existing
            .to_str()
            .context("CARRICK_RUN_ID must be valid UTF-8")?;
        if value.is_empty() {
            bail!("CARRICK_RUN_ID must not be empty");
        }
        return Ok(value.to_owned());
    }
    if utc_timestamp.is_empty() {
        bail!("native-shape UTC timestamp is empty");
    }
    Ok(format!("native-shape-{utc_timestamp}-{pid}"))
}

pub(crate) fn establish_native_shape_run_id() -> Result<String> {
    let existing = std::env::var_os("CARRICK_RUN_ID");
    let run_id = resolve_native_shape_run_id(
        existing.as_deref(),
        &chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string(),
        std::process::id(),
    )?;
    if existing.is_none() {
        // SAFETY: callers establish the run ID in the single-threaded CLI
        // preflight, before qualification or traced-child work begins.
        unsafe { std::env::set_var("CARRICK_RUN_ID", &run_id) };
    }
    Ok(run_id)
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeAuthority {
    pub(crate) schema: String,
    pub(crate) profile: String,
    pub(crate) raw_schema: String,
    pub(crate) git_head: String,
    pub(crate) git_dirty: bool,
    pub(crate) executable_sha256: String,
    pub(crate) host: String,
    pub(crate) host_arch: String,
    pub(crate) os_build: String,
    pub(crate) image: String,
    pub(crate) target_argv: Vec<String>,
    pub(crate) target_argv_sha256: String,
    pub(crate) run_id: String,
    pub(crate) program_template_sha256: String,
    pub(crate) birth_qualification_sha256: String,
    pub(crate) terminal_qualification_sha256: String,
    pub(crate) sampling_hz: u64,
}

impl NativeShapeAuthority {
    pub(crate) fn new(
        identity: &CaptureIdentity,
        target: &NativeShapeTarget,
        run_id: &str,
        program_template: &str,
        birth_qualification_sha256: &str,
        terminal_qualification_sha256: &str,
    ) -> Result<Self> {
        identity.validate()?;
        target.validate()?;
        if run_id.is_empty() {
            bail!("native-shape run ID must not be empty");
        }
        let authority = Self {
            schema: AUTHORITY_SCHEMA.to_owned(),
            profile: PROFILE.to_owned(),
            raw_schema: RAW_SCHEMA.to_owned(),
            git_head: identity.git_head.clone(),
            git_dirty: identity.git_dirty,
            executable_sha256: identity.executable_sha256.clone(),
            host: identity.host.clone(),
            host_arch: identity.host_arch.clone(),
            os_build: identity.os_build.clone(),
            image: target.image.clone(),
            target_argv: target.argv.clone(),
            target_argv_sha256: target.argv_sha256.clone(),
            run_id: run_id.to_owned(),
            program_template_sha256: format!("{:x}", Sha256::digest(program_template.as_bytes())),
            birth_qualification_sha256: birth_qualification_sha256.to_owned(),
            terminal_qualification_sha256: terminal_qualification_sha256.to_owned(),
            sampling_hz: SAMPLING_HZ,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub(crate) fn sha256(&self) -> Result<String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).context("serialize native-shape authority")?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }

    pub(crate) fn header_record(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "NSHAPE2|header|profile={}|raw_schema={}|os_build={}|program_template_sha256={}|birth_qualification_sha256={}|terminal_qualification_sha256={}|sampling_hz={}|authority_sha256={}",
            self.profile,
            self.raw_schema,
            self.os_build,
            self.program_template_sha256,
            self.birth_qualification_sha256,
            self.terminal_qualification_sha256,
            self.sampling_hz,
            self.sha256()?,
        ))
    }

    fn validate(&self) -> Result<()> {
        if self.schema != AUTHORITY_SCHEMA {
            bail!("native-shape authority schema is not {AUTHORITY_SCHEMA}");
        }
        if self.profile != PROFILE {
            bail!("native-shape authority profile is not {PROFILE}");
        }
        if self.raw_schema != RAW_SCHEMA {
            bail!("native-shape authority raw schema is not {RAW_SCHEMA}");
        }
        if self.git_dirty {
            bail!("native-shape authority requires a clean Git tree");
        }
        validate_lower_hex(&self.git_head, 40, "authority git_head")?;
        for (value, field) in [
            (&self.executable_sha256, "authority executable_sha256"),
            (&self.target_argv_sha256, "authority target_argv_sha256"),
            (
                &self.program_template_sha256,
                "authority program_template_sha256",
            ),
            (
                &self.birth_qualification_sha256,
                "authority birth_qualification_sha256",
            ),
            (
                &self.terminal_qualification_sha256,
                "authority terminal_qualification_sha256",
            ),
        ] {
            validate_sha256(value, field)?;
        }
        for (value, field) in [
            (&self.profile, "authority profile"),
            (&self.raw_schema, "authority raw_schema"),
            (&self.os_build, "authority os_build"),
        ] {
            validate_percent_token(value, field)?;
        }
        for (value, field) in [
            (&self.host, "authority host"),
            (&self.host_arch, "authority host_arch"),
            (&self.image, "authority image"),
            (&self.run_id, "authority run_id"),
        ] {
            if value.is_empty() {
                bail!("{field} must not be empty");
            }
        }
        if self.host_arch != "aarch64" {
            bail!("native-shape authority host_arch must be aarch64");
        }
        let target = NativeShapeTarget::parse(&self.target_argv)
            .context("native-shape authority target argv is invalid")?;
        if self.target_argv_sha256 != target.argv_sha256 {
            bail!("authority target_argv_sha256 does not match target_argv");
        }
        if self.image != target.image {
            bail!("native-shape authority image does not match canonical target argv image");
        }
        if self.sampling_hz != SAMPLING_HZ {
            bail!("native-shape authority sampling frequency is not {SAMPLING_HZ}");
        }
        Ok(())
    }
}

pub(crate) fn argv_sha256(argv: &[String]) -> Result<String> {
    let mut hasher = Sha256::new();
    let count = u64::try_from(argv.len()).context("target argv count exceeds u64")?;
    hasher.update(count.to_be_bytes());
    for argument in argv {
        let bytes = argument.as_bytes();
        let length = u64::try_from(bytes.len()).context("target argv byte length exceeds u64")?;
        hasher.update(length.to_be_bytes());
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PcSample {
    pub(crate) pid: u32,
    pub(crate) pc: u64,
    pub(crate) count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeLifecycle {
    pub(crate) bounded: bool,
    pub(crate) target_completed: bool,
    pub(crate) target_exit_reason: i32,
    pub(crate) target_pid: u32,
    pub(crate) admitted: u64,
    pub(crate) exited: u64,
    pub(crate) live_at_end: u64,
    pub(crate) probe_errors: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CaptureOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeDrops {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) dynamic_rinse_drops: u64,
    pub(crate) dynamic_dirty_drops: u64,
    pub(crate) other_drops: u64,
    pub(crate) interrupted: bool,
}

impl NativeShapeDrops {
    fn evidence_errors(self) -> Vec<String> {
        let mut errors = Vec::new();
        for (label, count) in [
            ("principal", self.principal_drops),
            ("aggregation", self.aggregation_drops),
            ("dynamic", self.dynamic_drops),
            ("dynamic rinse", self.dynamic_rinse_drops),
            ("dynamic dirty", self.dynamic_dirty_drops),
            ("other", self.other_drops),
        ] {
            if count != 0 {
                errors.push(format!("DTrace {label} drops: {count}"));
            }
        }
        if self.interrupted {
            errors.push("DTrace interrupted".to_owned());
        }
        errors
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl From<carrick_runtime::dtrace_consumer::DTraceRunReport> for NativeShapeDrops {
    fn from(report: carrick_runtime::dtrace_consumer::DTraceRunReport) -> Self {
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeCounts {
    pub(crate) all_cpu: u64,
    pub(crate) user_cpu: u64,
    pub(crate) kernel_cpu: u64,
    pub(crate) invalid_cpu: u64,
    pub(crate) jit_user: u64,
    pub(crate) non_jit_user: u64,
    pub(crate) pc_rows: u64,
    pub(crate) pc_samples: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeShapeCaptureReceipt {
    pub(crate) schema: String,
    pub(crate) outcome: CaptureOutcome,
    pub(crate) evidence_errors: Vec<String>,
    pub(crate) authority: Option<NativeShapeAuthority>,
    pub(crate) authority_sha256: Option<String>,
    pub(crate) raw_trace_sha256: Option<String>,
    pub(crate) snapshot_manifest: Option<SnapshotManifest>,
    pub(crate) counts: Option<NativeShapeCounts>,
    pub(crate) lifecycle: Option<NativeShapeLifecycle>,
    pub(crate) drops: NativeShapeDrops,
}

pub(crate) struct NativeShapeFinalizeRequest<'a> {
    pub(crate) authority: &'a NativeShapeAuthority,
    pub(crate) raw_path: &'a Path,
    pub(crate) snapshot_directory: &'a Path,
    pub(crate) drops: NativeShapeDrops,
    pub(crate) post_identity: Result<CaptureIdentity>,
    pub(crate) trace_error: Option<String>,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[derive(Debug)]
pub(crate) struct NativeShapeObservedRun {
    pub(crate) drops: NativeShapeDrops,
    pub(crate) trace_error: Option<String>,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn classify_native_shape_observation(
    observed: Result<
        carrick_runtime::dtrace_consumer::DTraceRunReport,
        carrick_runtime::dtrace_consumer::DTraceObservedFailure,
    >,
) -> Result<NativeShapeObservedRun> {
    match observed {
        Ok(report) => Ok(NativeShapeObservedRun {
            drops: report.into(),
            trace_error: None,
        }),
        Err(failure) if failure.child_launched => Ok(NativeShapeObservedRun {
            drops: failure.report.into(),
            trace_error: Some(failure.error.to_string()),
        }),
        Err(failure) => Err(anyhow!(
            "trace failed before child launch: {}",
            failure.error
        )),
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_native_shape_capture<TraceRun, PostIdentity>(
    authority: &NativeShapeAuthority,
    raw_path: &Path,
    snapshot_directory: &Path,
    receipt_path: &Path,
    owner: Option<(u32, u32)>,
    trace_run: TraceRun,
    post_identity: PostIdentity,
) -> Result<NativeShapeCaptureReceipt>
where
    TraceRun: FnOnce() -> Result<
        carrick_runtime::dtrace_consumer::DTraceRunReport,
        carrick_runtime::dtrace_consumer::DTraceObservedFailure,
    >,
    PostIdentity: FnOnce() -> Result<CaptureIdentity>,
{
    prepare_capture_output(receipt_path, owner).context("preflight native-shape capture output")?;
    let observed = classify_native_shape_observation(trace_run())?;
    let receipt = finalize_capture(NativeShapeFinalizeRequest {
        authority,
        raw_path,
        snapshot_directory,
        drops: observed.drops,
        post_identity: post_identity(),
        trace_error: observed.trace_error,
    })?;
    write_capture_atomic(receipt_path, &receipt, owner)?;
    eprintln!(
        "carrick trace: native-shape capture {} (errors={})",
        match receipt.outcome {
            CaptureOutcome::Accepted => "accepted",
            CaptureOutcome::Rejected => "rejected",
        },
        receipt.evidence_errors.len()
    );
    if receipt.outcome == CaptureOutcome::Rejected {
        bail!(
            "native-shape capture rejected; receipt published at {}",
            receipt_path.display()
        );
    }
    Ok(receipt)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeShapeRaw {
    pub(crate) all_cpu: u64,
    pub(crate) user_cpu: u64,
    pub(crate) kernel_cpu: u64,
    pub(crate) invalid_cpu: u64,
    pub(crate) jit_user: u64,
    pub(crate) non_jit_user: u64,
    pub(crate) pc_samples: Vec<PcSample>,
    pub(crate) parents: BTreeMap<u32, u32>,
    pub(crate) exits: BTreeMap<u32, i32>,
    pub(crate) lifecycle: NativeShapeLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseState {
    Header,
    LifecycleOrModeSection,
    ModeRows { seen: u8 },
    RegionSection,
    RegionRows { seen: u8 },
    PcSection,
    PcRows,
    Complete,
    Finished,
}

#[derive(Default)]
struct RawBuilder {
    all_cpu: Option<u64>,
    user_cpu: Option<u64>,
    kernel_cpu: Option<u64>,
    invalid_cpu: Option<u64>,
    jit_user: Option<u64>,
    non_jit_user: Option<u64>,
    pc_samples: Vec<PcSample>,
    pc_keys: BTreeSet<(u32, u64)>,
    parents: BTreeMap<u32, u32>,
    exits: BTreeMap<u32, i32>,
    lifecycle: Option<NativeShapeLifecycle>,
}

impl NativeShapeRaw {
    pub(crate) fn parse(bytes: &[u8], authority: &NativeShapeAuthority) -> Result<Self> {
        let evidence = std::str::from_utf8(bytes).context("native-shape evidence is not UTF-8")?;
        let expected_header = authority.header_record()?;
        let mut state = ParseState::Header;
        let mut builder = RawBuilder::default();

        for (index, line) in evidence.split('\n').enumerate() {
            let line_number = index + 1;
            if line.is_empty() {
                continue;
            }
            if !line.starts_with("NSHAPE2|") {
                bail!("line {line_number}: non-NSHAPE2 content in native-shape evidence");
            }

            let mut pending = Some(line);
            while let Some(current) = pending.take() {
                match state {
                    ParseState::Header => {
                        if current != expected_header {
                            bail!(
                                "line {line_number}: native-shape header does not match authority"
                            );
                        }
                        state = ParseState::LifecycleOrModeSection;
                    }
                    ParseState::LifecycleOrModeSection => {
                        if current == "NSHAPE2|section=mode" {
                            state = ParseState::ModeRows { seen: 0 };
                        } else if current.starts_with("NSHAPE2|fork|") {
                            let fields = exact_fields(current, "fork", &["parent", "child"])?;
                            let parent = parse_u32(fields[0], "fork parent")?;
                            let child = parse_u32(fields[1], "fork child")?;
                            add_parent(&mut builder.parents, parent, child)?;
                        } else if current.starts_with("NSHAPE2|exit|") {
                            let fields = exact_fields(current, "exit", &["pid", "reason"])?;
                            let pid = parse_u32(fields[0], "exit pid")?;
                            let reason = parse_i32(fields[1], "exit reason")?;
                            if builder.exits.insert(pid, reason).is_some() {
                                bail!("line {line_number}: duplicate exit row");
                            }
                        } else {
                            bail!("line {line_number}: expected lifecycle row or mode section");
                        }
                    }
                    ParseState::ModeRows { seen } => {
                        let expected_kind = match seen {
                            0 => "all",
                            1 => "user",
                            2 => "kernel",
                            3 => "invalid",
                            _ => unreachable!("mode state advances after four rows"),
                        };
                        let fields = exact_fields(current, "mode", &["kind", "count"])?;
                        if fields[0] != expected_kind {
                            bail!("line {line_number}: expected {expected_kind} mode row");
                        }
                        let count = parse_u64(fields[1], "mode count")?;
                        match seen {
                            0 => builder.all_cpu = Some(count),
                            1 => builder.user_cpu = Some(count),
                            2 => builder.kernel_cpu = Some(count),
                            3 => builder.invalid_cpu = Some(count),
                            _ => unreachable!(),
                        }
                        state = if seen == 3 {
                            ParseState::RegionSection
                        } else {
                            ParseState::ModeRows { seen: seen + 1 }
                        };
                    }
                    ParseState::RegionSection => {
                        if current != "NSHAPE2|section=region" {
                            bail!("line {line_number}: expected region section");
                        }
                        state = ParseState::RegionRows { seen: 0 };
                    }
                    ParseState::RegionRows { seen } => {
                        let expected_kind = match seen {
                            0 => "jit",
                            1 => "non-jit",
                            _ => unreachable!("region state advances after two rows"),
                        };
                        let fields = exact_fields(current, "region", &["kind", "count"])?;
                        if fields[0] != expected_kind {
                            bail!("line {line_number}: expected {expected_kind} region row");
                        }
                        let count = parse_u64(fields[1], "region count")?;
                        match seen {
                            0 => builder.jit_user = Some(count),
                            1 => builder.non_jit_user = Some(count),
                            _ => unreachable!(),
                        }
                        state = if seen == 1 {
                            ParseState::PcSection
                        } else {
                            ParseState::RegionRows { seen: 1 }
                        };
                    }
                    ParseState::PcSection => {
                        if current != "NSHAPE2|section=pc" {
                            bail!("line {line_number}: expected PC section");
                        }
                        state = ParseState::PcRows;
                    }
                    ParseState::PcRows => {
                        if current.starts_with("NSHAPE2|pc|") {
                            let fields = exact_fields(current, "pc", &["pid", "pc", "count"])?;
                            let pid = parse_u32(fields[0], "PC pid")?;
                            let pc = parse_hex_u64(fields[1], "PC address")?;
                            let count = parse_u64(fields[2], "PC count")?;
                            if pc == 0 || count == 0 {
                                bail!("line {line_number}: PC address and count must be nonzero");
                            }
                            if !builder.pc_keys.insert((pid, pc)) {
                                bail!("line {line_number}: duplicate PC row");
                            }
                            builder.pc_samples.push(PcSample { pid, pc, count });
                        } else {
                            if builder.pc_samples.is_empty() {
                                bail!("line {line_number}: completion precedes every PC row");
                            }
                            state = ParseState::Complete;
                            pending = Some(current);
                        }
                    }
                    ParseState::Complete => {
                        let fields = exact_fields(
                            current,
                            "complete",
                            &[
                                "bounded",
                                "target_completed",
                                "target_exit_reason",
                                "target_pid",
                                "admitted",
                                "exited",
                                "live_at_end",
                                "probe_errors",
                            ],
                        )?;
                        builder.lifecycle = Some(NativeShapeLifecycle {
                            bounded: parse_bool(fields[0], "completion bounded")?,
                            target_completed: parse_bool(fields[1], "completion target_completed")?,
                            target_exit_reason: parse_i32(
                                fields[2],
                                "completion target_exit_reason",
                            )?,
                            target_pid: parse_u32(fields[3], "completion target_pid")?,
                            admitted: parse_u64(fields[4], "completion admitted")?,
                            exited: parse_u64(fields[5], "completion exited")?,
                            live_at_end: parse_u64(fields[6], "completion live_at_end")?,
                            probe_errors: parse_u64(fields[7], "completion probe_errors")?,
                        });
                        state = ParseState::Finished;
                    }
                    ParseState::Finished => {
                        bail!("line {line_number}: record appears after native-shape completion");
                    }
                }
            }
        }

        if state != ParseState::Finished {
            bail!("native-shape evidence ended in incomplete state {state:?}");
        }
        builder.finish()
    }
}

impl RawBuilder {
    fn finish(self) -> Result<NativeShapeRaw> {
        let all_cpu = self.all_cpu.context("missing all CPU count")?;
        let user_cpu = self.user_cpu.context("missing user CPU count")?;
        let kernel_cpu = self.kernel_cpu.context("missing kernel CPU count")?;
        let invalid_cpu = self.invalid_cpu.context("missing invalid CPU count")?;
        let jit_user = self.jit_user.context("missing JIT user count")?;
        let non_jit_user = self.non_jit_user.context("missing non-JIT user count")?;
        let lifecycle = self.lifecycle.context("missing completion record")?;
        if lifecycle.target_pid == 0 {
            bail!("native-shape target PID must be nonzero");
        }

        let classified_cpu = user_cpu
            .checked_add(kernel_cpu)
            .and_then(|subtotal| subtotal.checked_add(invalid_cpu))
            .context("total CPU sample count overflow")?;
        if classified_cpu != all_cpu {
            bail!("all CPU count does not reconcile with classified modes");
        }
        if invalid_cpu != 0 {
            bail!("invalid CPU sample count is nonzero");
        }
        let regions = jit_user
            .checked_add(non_jit_user)
            .context("user region sample count overflow")?;
        if regions != user_cpu {
            bail!("user CPU count does not reconcile with JIT and non-JIT regions");
        }
        if jit_user == 0 {
            bail!("JIT user sample count is zero");
        }
        let pc_total = self.pc_samples.iter().try_fold(0_u64, |total, sample| {
            total
                .checked_add(sample.count)
                .ok_or_else(|| anyhow!("PC sample count overflow"))
        })?;
        if pc_total != jit_user {
            bail!("JIT user count does not reconcile with PC rows");
        }

        let expected_live = lifecycle
            .admitted
            .checked_sub(lifecycle.exited)
            .context("exited process count exceeds admitted process count")?;
        if lifecycle.live_at_end != expected_live {
            bail!("live process count does not reconcile with admitted minus exited");
        }

        let admitted_vertices = rooted_vertices(lifecycle.target_pid, &self.parents)?;
        let expected_admitted = u64::try_from(admitted_vertices.len())
            .context("admitted process vertex count exceeds u64")?;
        if lifecycle.admitted != expected_admitted {
            bail!("admitted process count does not reconcile with rooted process tree");
        }

        for pid in self.exits.keys() {
            if !admitted_vertices.contains(pid) {
                bail!("exit PID is not admitted by the rooted process tree");
            }
        }
        for pid in &admitted_vertices {
            if !self.exits.contains_key(pid) {
                bail!("admitted PID is missing an exit row");
            }
        }
        let unique_exits = u64::try_from(self.exits.len()).context("exit row count exceeds u64")?;
        if lifecycle.exited != unique_exits {
            bail!("exited process count does not reconcile with unique exit rows");
        }

        if lifecycle.live_at_end != 0 {
            bail!("native-shape processes remain live at completion");
        }

        for sample in &self.pc_samples {
            if !admitted_vertices.contains(&sample.pid) {
                bail!("PC PID is not admitted by the rooted process tree");
            }
        }
        if lifecycle.bounded {
            bail!("native-shape capture reached its time bound");
        }
        if !lifecycle.target_completed {
            bail!("native-shape target did not complete");
        }
        if lifecycle.target_exit_reason != NORMAL_TARGET_EXIT_REASON {
            bail!("native-shape target exit reason is not normal");
        }
        let target_exit_reason = self
            .exits
            .get(&lifecycle.target_pid)
            .context("native-shape target is missing an exit row")?;
        if *target_exit_reason != lifecycle.target_exit_reason {
            bail!("target exit reason does not agree with the target exit row");
        }
        if lifecycle.probe_errors != 0 {
            bail!("native-shape DTrace probe errors are nonzero");
        }

        Ok(NativeShapeRaw {
            all_cpu,
            user_cpu,
            kernel_cpu,
            invalid_cpu,
            jit_user,
            non_jit_user,
            pc_samples: self.pc_samples,
            parents: self.parents,
            exits: self.exits,
            lifecycle,
        })
    }
}

impl NativeShapeCaptureReceipt {
    fn validate_for_publication(&self) -> Result<()> {
        if self.schema != CAPTURE_SCHEMA {
            bail!("native-shape capture schema is not {CAPTURE_SCHEMA}");
        }
        if self.evidence_errors.iter().any(String::is_empty) {
            bail!("native-shape capture contains an empty evidence error");
        }
        match self.outcome {
            CaptureOutcome::Accepted => {
                if !self.evidence_errors.is_empty() {
                    bail!("accepted native-shape capture has evidence errors");
                }
                if !self.drops.evidence_errors().is_empty() {
                    bail!("accepted native-shape capture has DTrace loss or interruption");
                }
                let authority = self
                    .authority
                    .as_ref()
                    .context("accepted native-shape capture has null authority")?;
                let authority_sha256 = self
                    .authority_sha256
                    .as_deref()
                    .context("accepted native-shape capture has null authority_sha256")?;
                if authority.sha256()? != authority_sha256 {
                    bail!("native-shape capture authority digest does not match authority");
                }
                validate_sha256(
                    self.raw_trace_sha256
                        .as_deref()
                        .context("accepted native-shape capture has null raw_trace_sha256")?,
                    "capture raw_trace_sha256",
                )?;
                let manifest = self
                    .snapshot_manifest
                    .as_ref()
                    .context("accepted native-shape capture has null snapshot_manifest")?;
                validate_sha256(&manifest.sha256, "capture snapshot manifest SHA-256")?;
                let counts = self
                    .counts
                    .as_ref()
                    .context("accepted native-shape capture has null counts")?;
                let classified = counts
                    .user_cpu
                    .checked_add(counts.kernel_cpu)
                    .and_then(|value| value.checked_add(counts.invalid_cpu))
                    .context("capture CPU count overflow")?;
                if classified != counts.all_cpu
                    || counts.invalid_cpu != 0
                    || counts.jit_user.checked_add(counts.non_jit_user) != Some(counts.user_cpu)
                    || counts.pc_samples != counts.jit_user
                    || counts.pc_rows == 0
                    || counts.pc_samples < counts.pc_rows
                {
                    bail!("accepted native-shape capture counts do not reconcile");
                }
                let lifecycle = self
                    .lifecycle
                    .as_ref()
                    .context("accepted native-shape capture has null lifecycle")?;
                if lifecycle.bounded
                    || !lifecycle.target_completed
                    || lifecycle.target_exit_reason != NORMAL_TARGET_EXIT_REASON
                    || lifecycle.target_pid == 0
                    || lifecycle.admitted == 0
                    || lifecycle.exited == 0
                    || lifecycle.live_at_end != 0
                    || lifecycle.probe_errors != 0
                    || lifecycle.admitted != lifecycle.exited
                {
                    bail!("accepted native-shape capture lifecycle is not complete");
                }
            }
            CaptureOutcome::Rejected => {
                if self.evidence_errors.is_empty() {
                    bail!("rejected native-shape capture has no evidence errors");
                }
                if self.authority.is_some()
                    || self.authority_sha256.is_some()
                    || self.raw_trace_sha256.is_some()
                    || self.snapshot_manifest.is_some()
                    || self.counts.is_some()
                    || self.lifecycle.is_some()
                {
                    bail!("rejected native-shape capture retains partially trusted evidence");
                }
            }
        }
        Ok(())
    }
}

/// Parse the exact canonical one-line receipt emitted by Task 4 and require
/// that it represents accepted evidence. Offline consumers must not grow a
/// second, weaker interpretation of the receipt schema.
pub(crate) fn parse_accepted_capture_receipt(bytes: &[u8]) -> Result<NativeShapeCaptureReceipt> {
    if bytes.last() != Some(&b'\n') || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        bail!("native-shape capture receipt must be exactly one newline-terminated JSON object");
    }
    let receipt: NativeShapeCaptureReceipt = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .context("parse native-shape capture receipt")?;
    receipt.validate_for_publication()?;
    if receipt.outcome != CaptureOutcome::Accepted {
        bail!("native-shape capture receipt is rejected");
    }
    let mut canonical = serde_json::to_vec(&receipt).context("serialize native-shape capture")?;
    canonical.push(b'\n');
    if canonical != bytes {
        bail!("native-shape capture receipt is not canonical Task 4 output");
    }
    Ok(receipt)
}

pub(crate) fn finalize_capture(
    request: NativeShapeFinalizeRequest<'_>,
) -> Result<NativeShapeCaptureReceipt> {
    let mut evidence_errors = Vec::new();

    if let Some(error) = request.trace_error {
        evidence_errors.push(format!("trace execution: {error}"));
    }
    evidence_errors.extend(request.drops.evidence_errors());

    let expected_identity = CaptureIdentity {
        git_head: request.authority.git_head.clone(),
        git_dirty: request.authority.git_dirty,
        executable_sha256: request.authority.executable_sha256.clone(),
        host: request.authority.host.clone(),
        host_arch: request.authority.host_arch.clone(),
        os_build: request.authority.os_build.clone(),
    };
    match request.post_identity {
        Ok(identity) => {
            if let Err(error) = expected_identity.require_exact_match(&identity) {
                evidence_errors.push(format!("post-capture identity: {error:#}"));
            }
        }
        Err(error) => evidence_errors.push(format!("post-capture identity: {error:#}")),
    }

    let mut raw_trace_sha256 = None;
    let mut raw = None;
    match fs::read(request.raw_path) {
        Ok(bytes) => {
            raw_trace_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
            match NativeShapeRaw::parse(&bytes, request.authority) {
                Ok(parsed) => raw = Some(parsed),
                Err(error) => evidence_errors.push(format!("raw trace parse: {error:#}")),
            }
        }
        Err(error) => evidence_errors.push(format!(
            "raw trace read: read {}: {error}",
            request.raw_path.display()
        )),
    }

    let snapshots = match load_snapshot_set_from_real_directory(request.snapshot_directory) {
        Ok(snapshots) => Some(snapshots),
        Err(error) => {
            evidence_errors.push(format!("snapshot load: {error:#}"));
            None
        }
    };

    let mut resolved_samples = 0_u64;
    if let (Some(raw), Some(snapshots)) = (raw.as_ref(), snapshots.as_ref()) {
        for sample in &raw.pc_samples {
            match snapshots.resolve(sample.pid, sample.pc, &raw.parents) {
                Ok(_instruction) => match resolved_samples.checked_add(sample.count) {
                    Some(value) => resolved_samples = value,
                    None => evidence_errors.push("PC resolution: sample count overflow".to_owned()),
                },
                Err(error) => evidence_errors.push(format!(
                    "PC resolution: pid={} pc={:#x} count={}: {error:#}",
                    sample.pid, sample.pc, sample.count
                )),
            }
        }
    }

    let receipt = if evidence_errors.is_empty() {
        let raw = raw.context("accepted capture lost parsed raw evidence")?;
        let snapshots = snapshots.context("accepted capture lost snapshot evidence")?;
        let pc_rows = u64::try_from(raw.pc_samples.len()).context("PC row count exceeds u64")?;
        NativeShapeCaptureReceipt {
            schema: CAPTURE_SCHEMA.to_owned(),
            outcome: CaptureOutcome::Accepted,
            evidence_errors,
            authority: Some(request.authority.clone()),
            authority_sha256: Some(request.authority.sha256()?),
            raw_trace_sha256,
            snapshot_manifest: Some(snapshots.manifest().clone()),
            counts: Some(NativeShapeCounts {
                all_cpu: raw.all_cpu,
                user_cpu: raw.user_cpu,
                kernel_cpu: raw.kernel_cpu,
                invalid_cpu: raw.invalid_cpu,
                jit_user: raw.jit_user,
                non_jit_user: raw.non_jit_user,
                pc_rows,
                pc_samples: resolved_samples,
            }),
            lifecycle: Some(raw.lifecycle),
            drops: request.drops,
        }
    } else {
        NativeShapeCaptureReceipt {
            schema: CAPTURE_SCHEMA.to_owned(),
            outcome: CaptureOutcome::Rejected,
            evidence_errors,
            authority: None,
            authority_sha256: None,
            raw_trace_sha256: None,
            snapshot_manifest: None,
            counts: None,
            lifecycle: None,
            drops: request.drops,
        }
    };
    receipt.validate_for_publication()?;
    Ok(receipt)
}

pub(crate) fn load_snapshot_set_from_real_directory(directory: &Path) -> Result<SnapshotSet> {
    use std::os::unix::fs::MetadataExt;

    let before = fs::symlink_metadata(directory)
        .with_context(|| format!("inspect snapshot root {}", directory.display()))?;
    if !before.is_dir() || before.file_type().is_symlink() {
        bail!("snapshot root is not a real non-symlink directory");
    }
    let snapshots = SnapshotSet::load(directory)?;
    let after = fs::symlink_metadata(directory)
        .with_context(|| format!("reinspect snapshot root {}", directory.display()))?;
    if !after.is_dir()
        || after.file_type().is_symlink()
        || (before.dev(), before.ino()) != (after.dev(), after.ino())
    {
        bail!("snapshot root changed while loading evidence");
    }
    Ok(snapshots)
}

fn capture_output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn set_temporary_owner(temporary: &NamedTempFile, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some((uid, gid)) = owner {
        let result = unsafe { libc::fchown(temporary.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("set native-shape capture owner");
        }
    }
    Ok(())
}

pub(crate) fn prepare_capture_output(path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "native-shape capture receipt already exists: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect capture output {}", path.display()));
        }
    }
    let parent = capture_output_parent(path);
    fs::create_dir_all(parent)
        .with_context(|| format!("create capture output directory {}", parent.display()))?;
    let temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary capture in {}", parent.display()))?;
    set_temporary_owner(&temporary, owner)
}

pub(crate) fn write_capture_atomic(
    path: &Path,
    receipt: &NativeShapeCaptureReceipt,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    receipt.validate_for_publication()?;
    let parent = capture_output_parent(path);
    fs::create_dir_all(parent)
        .with_context(|| format!("create capture output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary capture in {}", parent.display()))?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        serde_json::to_writer(&mut writer, receipt).context("serialize native-shape capture")?;
        writer
            .write_all(b"\n")
            .context("terminate native-shape capture JSON line")?;
        writer
            .flush()
            .context("flush native-shape capture JSON line")?;
    }
    temporary
        .as_file()
        .sync_all()
        .context("sync native-shape capture JSON line")?;
    set_temporary_owner(&temporary, owner)?;
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!(
                "native-shape capture receipt already exists: {}",
                path.display()
            )
        } else {
            anyhow!(
                "publish native-shape capture {} without clobbering: {}",
                path.display(),
                error.error
            )
        }
    })?;
    Ok(())
}

fn rooted_vertices(target_pid: u32, parents: &BTreeMap<u32, u32>) -> Result<BTreeSet<u32>> {
    if parents.contains_key(&target_pid) {
        bail!("target PID appears as a fork child");
    }

    let mut all_vertices = BTreeSet::from([target_pid]);
    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    for (&child, &parent) in parents {
        all_vertices.insert(parent);
        all_vertices.insert(child);
        children.entry(parent).or_default().push(child);
    }

    let mut rooted = BTreeSet::from([target_pid]);
    let mut pending = vec![target_pid];
    while let Some(parent) = pending.pop() {
        for child in children.get(&parent).into_iter().flatten() {
            if rooted.insert(*child) {
                pending.push(*child);
            }
        }
    }
    if rooted != all_vertices {
        bail!("fork graph contains a component disconnected from target PID");
    }
    Ok(rooted)
}

fn exact_fields<'a>(line: &'a str, record: &str, names: &[&str]) -> Result<Vec<&'a str>> {
    let mut parts = line.split('|');
    if parts.next() != Some("NSHAPE2") || parts.next() != Some(record) {
        bail!("expected exact NSHAPE2 {record} record");
    }
    let mut values = Vec::with_capacity(names.len());
    for name in names {
        let field = parts
            .next()
            .with_context(|| format!("{record} record is missing field {name}"))?;
        let prefix = format!("{name}=");
        let value = field
            .strip_prefix(&prefix)
            .with_context(|| format!("{record} record expected field {name}"))?;
        if value.is_empty() {
            bail!("{record} field {name} is empty");
        }
        values.push(value);
    }
    if parts.next().is_some() {
        bail!("{record} record contains trailing or duplicate fields");
    }
    Ok(values)
}

fn add_parent(parents: &mut BTreeMap<u32, u32>, parent: u32, child: u32) -> Result<()> {
    if parent == child {
        bail!("fork child is its own parent");
    }
    if parents.contains_key(&child) {
        bail!("fork child has duplicate parent rows");
    }

    let mut cursor = parent;
    let mut visited = BTreeSet::new();
    loop {
        if cursor == child {
            bail!("fork ancestry contains a cycle");
        }
        if !visited.insert(cursor) {
            bail!("existing fork ancestry contains a cycle");
        }
        let Some(next) = parents.get(&cursor) else {
            break;
        };
        cursor = *next;
    }
    parents.insert(child, parent);
    Ok(())
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    if !is_canonical_decimal(value) {
        bail!("{field} is not canonical unsigned decimal");
    }
    value
        .parse()
        .with_context(|| format!("{field} exceeds u64"))
}

fn parse_u32(value: &str, field: &str) -> Result<u32> {
    let parsed = parse_u64(value, field)?;
    let parsed = u32::try_from(parsed).with_context(|| format!("{field} exceeds u32"))?;
    if parsed == 0 {
        bail!("{field} must be nonzero");
    }
    Ok(parsed)
}

fn parse_i32(value: &str, field: &str) -> Result<i32> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if !is_canonical_decimal(digits) || value == "-0" {
        bail!("{field} is not canonical signed decimal");
    }
    value
        .parse()
        .with_context(|| format!("{field} exceeds i32"))
}

fn parse_hex_u64(value: &str, field: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .with_context(|| format!("{field} is not 0x-prefixed hexadecimal"))?;
    if !digits
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{field} is not lowercase hexadecimal");
    }
    if digits.len() > 1 && digits.starts_with('0') {
        bail!("{field} is not canonical hexadecimal");
    }
    u64::from_str_radix(digits, 16).with_context(|| format!("{field} exceeds u64"))
}

fn parse_bool(value: &str, field: &str) -> Result<bool> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => bail!("{field} must be literal 0 or 1"),
    }
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    validate_lower_hex(value, 64, field)
}

fn validate_lower_hex(value: &str, length: usize, field: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{field} must be an exact lowercase hexadecimal digest");
    }
    Ok(())
}

fn validate_percent_token(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{field} token must not be empty");
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
                    bail!("{field} contains an invalid percent escape");
                }
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':') => {
                index += 1;
            }
            _ => bail!("{field} contains an unescaped byte"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jit_shape_snapshot::write_v4_test_snapshot;
    use std::ffi::OsStr;
    use std::path::Path;

    const ARGV_SHA256: &str = "0963ca356c238c24a4e5fe8644feafc07941d94b0cc9e9118a312821b8584f65";
    const AUTHORITY_SHA256: &str =
        "97c2468f4384acb3f176ecbc30a45a3d1aa8f2112213f7059d59424149cb731a";
    const FIXTURE_HEADER: &str = concat!(
        "NSHAPE2|header|profile=native-shape|raw_schema=carrick.native-shape.raw.v2",
        "|os_build=26A5388g",
        "|program_template_sha256=2222222222222222222222222222222222222222222222222222222222222222",
        "|birth_qualification_sha256=3333333333333333333333333333333333333333333333333333333333333333",
        "|terminal_qualification_sha256=4444444444444444444444444444444444444444444444444444444444444444",
        "|sampling_hz=997",
        "|authority_sha256=97c2468f4384acb3f176ecbc30a45a3d1aa8f2112213f7059d59424149cb731a"
    );

    fn fixture_authority() -> NativeShapeAuthority {
        NativeShapeAuthority {
            schema: "carrick.native-shape-authority.v1".to_owned(),
            profile: "native-shape".to_owned(),
            raw_schema: "carrick.native-shape.raw.v2".to_owned(),
            git_head: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_dirty: false,
            executable_sha256: "1".repeat(64),
            host: "test-host".to_owned(),
            host_arch: "aarch64".to_owned(),
            os_build: "26A5388g".to_owned(),
            image: "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            target_argv: vec![
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "native".to_owned(),
                "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "/bin/true".to_owned(),
            ],
            target_argv_sha256: ARGV_SHA256.to_owned(),
            run_id: "native-shape-test".to_owned(),
            program_template_sha256: "2".repeat(64),
            birth_qualification_sha256: "3".repeat(64),
            terminal_qualification_sha256: "4".repeat(64),
            sampling_hz: 997,
        }
    }

    fn valid_raw() -> String {
        concat!(
            "NSHAPE2|header|profile=native-shape|raw_schema=carrick.native-shape.raw.v2",
            "|os_build=26A5388g",
            "|program_template_sha256=2222222222222222222222222222222222222222222222222222222222222222",
            "|birth_qualification_sha256=3333333333333333333333333333333333333333333333333333333333333333",
            "|terminal_qualification_sha256=4444444444444444444444444444444444444444444444444444444444444444",
            "|sampling_hz=997",
            "|authority_sha256=97c2468f4384acb3f176ecbc30a45a3d1aa8f2112213f7059d59424149cb731a\n",
            "NSHAPE2|fork|parent=10|child=11\n",
            "NSHAPE2|exit|pid=11|reason=1\n",
            "NSHAPE2|exit|pid=10|reason=1\n",
            "NSHAPE2|section=mode\n",
            "NSHAPE2|mode|kind=all|count=100\n",
            "NSHAPE2|mode|kind=user|count=70\n",
            "NSHAPE2|mode|kind=kernel|count=30\n",
            "NSHAPE2|mode|kind=invalid|count=0\n",
            "NSHAPE2|section=region\n",
            "NSHAPE2|region|kind=jit|count=40\n",
            "NSHAPE2|region|kind=non-jit|count=30\n",
            "NSHAPE2|section=pc\n",
            "NSHAPE2|pc|pid=10|pc=0x1000|count=15\n",
            "NSHAPE2|pc|pid=11|pc=0x2000|count=25\n",
            "NSHAPE2|complete|bounded=0|target_completed=1|target_exit_reason=1|target_pid=10|admitted=2|exited=2|live_at_end=0|probe_errors=0\n"
        )
        .to_owned()
    }

    fn parse_rejected(raw: impl AsRef<[u8]>) {
        let authority = fixture_authority();
        assert!(NativeShapeRaw::parse(raw.as_ref(), &authority).is_err());
    }

    fn parse_rejected_for(raw: impl AsRef<[u8]>, expected: &str) {
        let authority = fixture_authority();
        let error = NativeShapeRaw::parse(raw.as_ref(), &authority).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    fn replace_once(raw: &str, from: &str, to: &str) -> String {
        assert_eq!(raw.matches(from).count(), 1, "fixture mutation source");
        raw.replacen(from, to, 1)
    }

    fn fixture_identity() -> CaptureIdentity {
        CaptureIdentity {
            git_head: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_dirty: false,
            executable_sha256: "1".repeat(64),
            host: "test-host".to_owned(),
            host_arch: "aarch64".to_owned(),
            os_build: "26A5388g".to_owned(),
        }
    }

    fn write_valid_capture_evidence(root: &Path) -> (PathBuf, PathBuf) {
        let raw_path = root.join("capture.raw");
        fs::write(&raw_path, valid_raw()).expect("write raw capture fixture");
        let snapshot_directory = root.join("snapshots");
        fs::create_dir(&snapshot_directory).expect("create snapshot fixture directory");
        write_v4_test_snapshot(&snapshot_directory, "10-1", 10, 0x1000, &[0xd503_201f]);
        write_v4_test_snapshot(&snapshot_directory, "11-1", 11, 0x2000, &[0xd65f_03c0]);
        (raw_path, snapshot_directory)
    }

    fn rejected_fixture(errors: Vec<String>) -> NativeShapeCaptureReceipt {
        NativeShapeCaptureReceipt {
            schema: CAPTURE_SCHEMA.to_owned(),
            outcome: CaptureOutcome::Rejected,
            evidence_errors: errors,
            authority: None,
            authority_sha256: None,
            raw_trace_sha256: None,
            snapshot_manifest: None,
            counts: None,
            lifecycle: None,
            drops: NativeShapeDrops::default(),
        }
    }

    fn accepted_fixture(root: &Path) -> NativeShapeCaptureReceipt {
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(root);
        finalize_capture(NativeShapeFinalizeRequest {
            authority: &fixture_authority(),
            raw_path: &raw_path,
            snapshot_directory: &snapshot_directory,
            drops: NativeShapeDrops::default(),
            post_identity: Ok(fixture_identity()),
            trace_error: None,
        })
        .expect("finalize valid capture fixture")
    }

    #[test]
    fn native_shape_capture_serialization_is_one_deterministic_json_line() {
        let fixture = tempfile::tempdir().expect("receipt fixture directory");
        let first_path = fixture.path().join("first.jsonl");
        let second_path = fixture.path().join("second.jsonl");
        let receipt = rejected_fixture(vec![
            "trace execution: failed".to_owned(),
            "raw trace parse: invalid".to_owned(),
        ]);
        write_capture_atomic(&first_path, &receipt, None).expect("write first rejected receipt");
        write_capture_atomic(&second_path, &receipt, None).expect("write second rejected receipt");
        let first = fs::read(&first_path).expect("read first receipt");
        let second = fs::read(&second_path).expect("read second receipt");
        let expected = concat!(
            "{\"schema\":\"carrick.native-shape-capture.v1\",",
            "\"outcome\":\"rejected\",",
            "\"evidence_errors\":[\"trace execution: failed\",\"raw trace parse: invalid\"],",
            "\"authority\":null,\"authority_sha256\":null,\"raw_trace_sha256\":null,",
            "\"snapshot_manifest\":null,\"counts\":null,\"lifecycle\":null,",
            "\"drops\":{\"principal_drops\":0,\"aggregation_drops\":0,",
            "\"dynamic_drops\":0,\"dynamic_rinse_drops\":0,",
            "\"dynamic_dirty_drops\":0,\"other_drops\":0,\"interrupted\":false}}\n"
        )
        .as_bytes();
        assert_eq!(first, expected);
        assert_eq!(second, expected);
        assert_eq!(first.iter().filter(|byte| **byte == b'\n').count(), 1);

        let unknown = String::from_utf8(first)
            .expect("receipt is UTF-8")
            .replacen("\"schema\":", "\"unknown\":0,\"schema\":", 1);
        assert!(
            serde_json::from_str::<NativeShapeCaptureReceipt>(&unknown).is_err(),
            "unknown receipt fields must fail closed"
        );
    }

    #[test]
    fn native_shape_capture_write_never_clobbers_preexisting_accepted_receipt() {
        let fixture = tempfile::tempdir().expect("receipt fixture directory");
        let receipt_path = fixture.path().join("capture.jsonl");
        let accepted = accepted_fixture(fixture.path());
        write_capture_atomic(&receipt_path, &accepted, None).expect("write accepted receipt");
        let accepted_bytes = fs::read(&receipt_path).expect("read accepted receipt");

        let rejected = rejected_fixture(vec!["trace execution: failed".to_owned()]);
        let error = write_capture_atomic(&receipt_path, &rejected, None)
            .expect_err("rejected receipt must not replace accepted evidence");
        assert!(format!("{error:#}").contains("already exists"));
        assert_eq!(
            fs::read(&receipt_path).expect("reread accepted receipt"),
            accepted_bytes
        );
    }

    #[test]
    fn native_shape_capture_rejects_structurally_impossible_accepted_receipts() {
        type Mutation = fn(&mut NativeShapeCaptureReceipt);
        let mutations: [(&str, Mutation); 4] = [
            ("zero PC rows", |receipt| {
                receipt.counts.as_mut().expect("counts").pc_rows = 0;
            }),
            ("fewer PC samples than rows", |receipt| {
                receipt.counts.as_mut().expect("counts").pc_rows = 41;
            }),
            ("zero target PID", |receipt| {
                receipt.lifecycle.as_mut().expect("lifecycle").target_pid = 0;
            }),
            ("zero admitted and exited", |receipt| {
                let lifecycle = receipt.lifecycle.as_mut().expect("lifecycle");
                lifecycle.admitted = 0;
                lifecycle.exited = 0;
            }),
        ];

        for (label, mutate) in mutations {
            let fixture = tempfile::tempdir().expect("receipt fixture directory");
            let mut receipt = accepted_fixture(fixture.path());
            mutate(&mut receipt);
            let receipt_path = fixture.path().join("capture.jsonl");
            assert!(
                write_capture_atomic(&receipt_path, &receipt, None).is_err(),
                "accepted impossible state published: {label}"
            );
            assert!(!receipt_path.exists(), "partial receipt for {label}");
        }
    }

    #[test]
    fn native_shape_raw_builder_rejects_zero_target_pid_even_when_tree_reconciles() {
        let builder = RawBuilder {
            all_cpu: Some(100),
            user_cpu: Some(70),
            kernel_cpu: Some(30),
            invalid_cpu: Some(0),
            jit_user: Some(40),
            non_jit_user: Some(30),
            pc_samples: vec![
                PcSample {
                    pid: 0,
                    pc: 0x1000,
                    count: 15,
                },
                PcSample {
                    pid: 11,
                    pc: 0x2000,
                    count: 25,
                },
            ],
            pc_keys: BTreeSet::from([(0, 0x1000), (11, 0x2000)]),
            parents: BTreeMap::from([(11, 0)]),
            exits: BTreeMap::from([(0, 1), (11, 1)]),
            lifecycle: Some(NativeShapeLifecycle {
                bounded: false,
                target_completed: true,
                target_exit_reason: 1,
                target_pid: 0,
                admitted: 2,
                exited: 2,
                live_at_end: 0,
                probe_errors: 0,
            }),
        };
        let error = builder
            .finish()
            .expect_err("zero target PID must fail at the semantic builder layer");
        assert!(error.to_string().contains("target PID must be nonzero"));

        parse_rejected_for(
            replace_once(&valid_raw(), "target_pid=10", "target_pid=0"),
            "completion target_pid must be nonzero",
        );
    }

    #[test]
    fn native_shape_capture_accepts_only_complete_resolved_evidence() {
        let fixture = tempfile::tempdir().expect("capture fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let authority = fixture_authority();
        let receipt = finalize_capture(NativeShapeFinalizeRequest {
            authority: &authority,
            raw_path: &raw_path,
            snapshot_directory: &snapshot_directory,
            drops: NativeShapeDrops::default(),
            post_identity: Ok(fixture_identity()),
            trace_error: None,
        })
        .expect("finalize valid capture");

        assert_eq!(receipt.outcome, CaptureOutcome::Accepted);
        assert!(receipt.evidence_errors.is_empty());
        assert_eq!(receipt.authority.as_ref(), Some(&authority));
        assert_eq!(
            receipt.counts,
            Some(NativeShapeCounts {
                all_cpu: 100,
                user_cpu: 70,
                kernel_cpu: 30,
                invalid_cpu: 0,
                jit_user: 40,
                non_jit_user: 30,
                pc_rows: 2,
                pc_samples: 40,
            })
        );
        assert_eq!(
            receipt.lifecycle,
            Some(NativeShapeLifecycle {
                bounded: false,
                target_completed: true,
                target_exit_reason: 1,
                target_pid: 10,
                admitted: 2,
                exited: 2,
                live_at_end: 0,
                probe_errors: 0,
            })
        );
        let manifest = receipt
            .snapshot_manifest
            .as_ref()
            .expect("accepted snapshot manifest");
        assert_eq!(
            (
                manifest.pairs,
                manifest.pids,
                manifest.blocks,
                manifest.bytes
            ),
            (2, 2, 2, 8)
        );
        assert!(receipt.authority_sha256.is_some());
        assert!(receipt.raw_trace_sha256.is_some());
        let encoded = serde_json::to_string(&receipt).expect("serialize accepted receipt");
        assert!(!encoded.contains(":null"), "{encoded}");

        let invalid_path = fixture.path().join("invalid-accepted.jsonl");
        let mut incomplete = receipt.clone();
        incomplete.lifecycle = None;
        assert!(write_capture_atomic(&invalid_path, &incomplete, None).is_err());
        assert!(!invalid_path.exists());

        let invalid_path = fixture.path().join("invalid-rejected.jsonl");
        let mut partially_trusted = receipt;
        partially_trusted.outcome = CaptureOutcome::Rejected;
        partially_trusted.evidence_errors = vec!["trace execution: failed".to_owned()];
        assert!(write_capture_atomic(&invalid_path, &partially_trusted, None).is_err());
        assert!(!invalid_path.exists());
    }

    #[test]
    fn native_shape_capture_each_dtrace_loss_and_interruption_rejects_independently() {
        let fixture = tempfile::tempdir().expect("capture fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let authority = fixture_authority();
        let cases = [
            (
                NativeShapeDrops {
                    principal_drops: 1,
                    ..NativeShapeDrops::default()
                },
                "DTrace principal drops: 1",
            ),
            (
                NativeShapeDrops {
                    aggregation_drops: 2,
                    ..NativeShapeDrops::default()
                },
                "DTrace aggregation drops: 2",
            ),
            (
                NativeShapeDrops {
                    dynamic_drops: 3,
                    ..NativeShapeDrops::default()
                },
                "DTrace dynamic drops: 3",
            ),
            (
                NativeShapeDrops {
                    dynamic_rinse_drops: 4,
                    ..NativeShapeDrops::default()
                },
                "DTrace dynamic rinse drops: 4",
            ),
            (
                NativeShapeDrops {
                    dynamic_dirty_drops: 5,
                    ..NativeShapeDrops::default()
                },
                "DTrace dynamic dirty drops: 5",
            ),
            (
                NativeShapeDrops {
                    other_drops: 6,
                    ..NativeShapeDrops::default()
                },
                "DTrace other drops: 6",
            ),
            (
                NativeShapeDrops {
                    interrupted: true,
                    ..NativeShapeDrops::default()
                },
                "DTrace interrupted",
            ),
        ];

        for (drops, expected_error) in cases {
            let receipt = finalize_capture(NativeShapeFinalizeRequest {
                authority: &authority,
                raw_path: &raw_path,
                snapshot_directory: &snapshot_directory,
                drops,
                post_identity: Ok(fixture_identity()),
                trace_error: None,
            })
            .expect("finalize lossy capture");
            assert_eq!(receipt.outcome, CaptureOutcome::Rejected);
            assert_eq!(receipt.evidence_errors, [expected_error]);
            assert!(receipt.authority.is_none());
            assert!(receipt.raw_trace_sha256.is_none());
            assert!(receipt.snapshot_manifest.is_none());
            assert!(receipt.counts.is_none());
            assert!(receipt.lifecycle.is_none());
        }
    }

    #[test]
    fn native_shape_capture_accumulates_safe_errors_in_authoritative_order() {
        let fixture = tempfile::tempdir().expect("capture fixture directory");
        let raw_path = fixture.path().join("capture.raw");
        fs::write(&raw_path, b"not an NSHAPE2 stream\n").expect("write malformed raw capture");
        let snapshot_directory = fixture.path().join("snapshots");
        fs::create_dir(&snapshot_directory).expect("create invalid snapshot directory");
        fs::write(snapshot_directory.join("unknown"), b"unknown")
            .expect("write invalid snapshot entry");
        let authority = fixture_authority();
        let mut drifted = fixture_identity();
        drifted.host = "other-host".to_owned();

        let receipt = finalize_capture(NativeShapeFinalizeRequest {
            authority: &authority,
            raw_path: &raw_path,
            snapshot_directory: &snapshot_directory,
            drops: NativeShapeDrops {
                principal_drops: 2,
                interrupted: true,
                ..NativeShapeDrops::default()
            },
            post_identity: Ok(drifted),
            trace_error: Some("work failed".to_owned()),
        })
        .expect("finalize rejected capture");

        assert_eq!(receipt.outcome, CaptureOutcome::Rejected);
        assert_eq!(receipt.evidence_errors.len(), 6);
        assert_eq!(receipt.evidence_errors[0], "trace execution: work failed");
        assert_eq!(receipt.evidence_errors[1], "DTrace principal drops: 2");
        assert_eq!(receipt.evidence_errors[2], "DTrace interrupted");
        assert!(receipt.evidence_errors[3].starts_with("post-capture identity: "));
        assert!(receipt.evidence_errors[4].starts_with("raw trace parse: "));
        assert!(receipt.evidence_errors[5].starts_with("snapshot load: "));
        assert!(receipt.authority.is_none());
        assert!(receipt.authority_sha256.is_none());
        assert!(receipt.raw_trace_sha256.is_none());
        assert!(receipt.snapshot_manifest.is_none());
        assert!(receipt.counts.is_none());
        assert!(receipt.lifecycle.is_none());
    }

    #[test]
    fn native_shape_capture_rejects_unresolved_pc_and_symlink_snapshot_root() {
        let fixture = tempfile::tempdir().expect("capture fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        fs::remove_file(snapshot_directory.join("11-1.json")).expect("remove child metadata");
        fs::remove_file(snapshot_directory.join("11-1.bin")).expect("remove child payload");
        let authority = fixture_authority();
        let unresolved = finalize_capture(NativeShapeFinalizeRequest {
            authority: &authority,
            raw_path: &raw_path,
            snapshot_directory: &snapshot_directory,
            drops: NativeShapeDrops::default(),
            post_identity: Ok(fixture_identity()),
            trace_error: None,
        })
        .expect("finalize unresolved capture");
        assert_eq!(unresolved.outcome, CaptureOutcome::Rejected);
        assert_eq!(unresolved.evidence_errors.len(), 1);
        assert!(unresolved.evidence_errors[0].starts_with("PC resolution: "));

        let real_snapshots = fixture.path().join("real-snapshots");
        fs::rename(&snapshot_directory, &real_snapshots).expect("move real snapshots");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_snapshots, &snapshot_directory)
            .expect("create snapshot root symlink");
        let substituted = finalize_capture(NativeShapeFinalizeRequest {
            authority: &authority,
            raw_path: &raw_path,
            snapshot_directory: &snapshot_directory,
            drops: NativeShapeDrops::default(),
            post_identity: Ok(fixture_identity()),
            trace_error: None,
        })
        .expect("finalize substituted snapshot root");
        assert_eq!(substituted.outcome, CaptureOutcome::Rejected);
        assert!(substituted.evidence_errors[0].starts_with("snapshot load: "));
        assert!(substituted.evidence_errors[0].contains("real non-symlink directory"));
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_observed_boundary_skips_only_prelaunch_receipts() {
        use carrick_runtime::dtrace_consumer::{
            DTraceError, DTraceObservedFailure, DTraceRunReport,
        };

        let prelaunch = classify_native_shape_observation(Err(DTraceObservedFailure {
            error: DTraceError::Compile("bad program".to_owned()),
            report: DTraceRunReport::default(),
            child_launched: false,
        }))
        .expect_err("prelaunch failure must not reach receipt finalization");
        assert!(prelaunch.to_string().contains("bad program"));

        let report = DTraceRunReport {
            principal_drops: 7,
            interrupted: true,
            ..DTraceRunReport::default()
        };
        let postlaunch = classify_native_shape_observation(Err(DTraceObservedFailure {
            error: DTraceError::Work("consume failed".to_owned()),
            report,
            child_launched: true,
        }))
        .expect("postlaunch failure must retain finalizable evidence");
        assert_eq!(postlaunch.drops, NativeShapeDrops::from(report));
        assert_eq!(
            postlaunch.trace_error.as_deref(),
            Some("dtrace_work failed: consume failed")
        );

        let completed = classify_native_shape_observation(Ok(report))
            .expect("completed trace must reach finalization");
        assert_eq!(completed.drops, NativeShapeDrops::from(report));
        assert!(completed.trace_error.is_none());
    }

    #[test]
    fn native_shape_capture_output_preflight_creates_no_receipt() {
        let fixture = tempfile::tempdir().expect("output fixture directory");
        let path = fixture.path().join("nested/capture.jsonl");
        prepare_capture_output(&path, None).expect("preflight writable receipt output");
        assert!(path.parent().expect("receipt parent").is_dir());
        assert!(!path.exists(), "preflight must not claim a receipt");

        let blocked_parent = fixture.path().join("blocked");
        fs::write(&blocked_parent, b"not a directory").expect("write blocking parent");
        let blocked = blocked_parent.join("capture.jsonl");
        assert!(prepare_capture_output(&blocked, None).is_err());
        assert!(!blocked.exists());

        let existing = fixture.path().join("existing.jsonl");
        fs::write(&existing, b"existing receipt\n").expect("write existing receipt");
        let existing_bytes = fs::read(&existing).expect("read existing receipt");
        assert!(prepare_capture_output(&existing, None).is_err());
        assert_eq!(
            fs::read(&existing).expect("reread existing receipt"),
            existing_bytes
        );
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_preflight_failure_does_not_run_or_publish() {
        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let blocked_parent = fixture.path().join("blocked");
        fs::write(&blocked_parent, b"not a directory").expect("write blocking parent");
        let receipt_path = blocked_parent.join("capture.jsonl");
        let error = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || panic!("trace must not run after receipt output preflight failure"),
            || panic!("identity must not run before a trace"),
        )
        .expect_err("preflight failure must return nonzero");
        assert!(error.to_string().contains("capture output"));
        assert!(!receipt_path.exists());
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_prelaunch_failure_publishes_no_receipt() {
        use carrick_runtime::dtrace_consumer::{
            DTraceError, DTraceObservedFailure, DTraceRunReport,
        };

        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let receipt_path = fixture.path().join("capture.jsonl");
        let error = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || {
                Err(DTraceObservedFailure {
                    error: DTraceError::Compile("bad program".to_owned()),
                    report: DTraceRunReport::default(),
                    child_launched: false,
                })
            },
            || panic!("identity must not run for a prelaunch failure"),
        )
        .expect_err("prelaunch failure must return nonzero");
        assert!(error.to_string().contains("before child launch"));
        assert!(!receipt_path.exists());
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_postlaunch_failure_publishes_rejection() {
        use carrick_runtime::dtrace_consumer::{
            DTraceError, DTraceObservedFailure, DTraceRunReport,
        };

        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let receipt_path = fixture.path().join("capture.jsonl");
        let error = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || {
                Err(DTraceObservedFailure {
                    error: DTraceError::Work("consume failed".to_owned()),
                    report: DTraceRunReport::default(),
                    child_launched: true,
                })
            },
            || Ok(fixture_identity()),
        )
        .expect_err("postlaunch failure must return nonzero");
        assert!(error.to_string().contains("capture rejected"));
        let receipt: NativeShapeCaptureReceipt = serde_json::from_slice(
            &fs::read(&receipt_path).expect("read rejected capture receipt"),
        )
        .expect("parse rejected capture receipt");
        assert_eq!(receipt.outcome, CaptureOutcome::Rejected);
        assert_eq!(
            receipt.evidence_errors[0],
            "trace execution: dtrace_work failed: consume failed"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_publish_race_never_clobbers_winner() {
        use carrick_runtime::dtrace_consumer::{
            DTraceError, DTraceObservedFailure, DTraceRunReport,
        };

        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let receipt_path = fixture.path().join("capture.jsonl");
        let winner = b"race winner remains authoritative\n";
        let error = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || {
                fs::write(&receipt_path, winner).expect("publish racing winner");
                Err(DTraceObservedFailure {
                    error: DTraceError::Work("consume failed".to_owned()),
                    report: DTraceRunReport::default(),
                    child_launched: true,
                })
            },
            || Ok(fixture_identity()),
        )
        .expect_err("racing receipt must make no-clobber publication fail");
        assert!(format!("{error:#}").contains("already exists"));
        assert_eq!(fs::read(&receipt_path).expect("read racing winner"), winner);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_normal_invalid_evidence_publishes_rejection() {
        use carrick_runtime::dtrace_consumer::DTraceRunReport;

        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        fs::write(&raw_path, b"invalid\n").expect("corrupt raw capture");
        let receipt_path = fixture.path().join("capture.jsonl");
        let error = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || Ok(DTraceRunReport::default()),
            || Ok(fixture_identity()),
        )
        .expect_err("invalid completed evidence must return nonzero");
        assert!(error.to_string().contains("capture rejected"));
        let receipt: NativeShapeCaptureReceipt = serde_json::from_slice(
            &fs::read(&receipt_path).expect("read rejected capture receipt"),
        )
        .expect("parse rejected capture receipt");
        assert_eq!(receipt.outcome, CaptureOutcome::Rejected);
        assert!(receipt.evidence_errors[0].starts_with("raw trace parse: "));
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_shape_capture_command_valid_evidence_publishes_acceptance() {
        use carrick_runtime::dtrace_consumer::DTraceRunReport;

        let fixture = tempfile::tempdir().expect("command fixture directory");
        let (raw_path, snapshot_directory) = write_valid_capture_evidence(fixture.path());
        let receipt_path = fixture.path().join("capture.jsonl");
        let receipt = run_native_shape_capture(
            &fixture_authority(),
            &raw_path,
            &snapshot_directory,
            &receipt_path,
            None,
            || Ok(DTraceRunReport::default()),
            || Ok(fixture_identity()),
        )
        .expect("valid completed evidence must succeed");
        assert_eq!(receipt.outcome, CaptureOutcome::Accepted);
        assert_eq!(
            fs::read(&receipt_path).expect("read accepted capture receipt"),
            {
                let mut encoded = serde_json::to_vec(&receipt).expect("encode accepted receipt");
                encoded.push(b'\n');
                encoded
            }
        );
    }

    #[test]
    fn native_shape_paths_require_dedicated_outputs_and_do_not_alias() {
        let cwd = Path::new("/tmp/native-shape-cwd");
        let raw = Path::new("capture.raw");
        let receipt = Path::new("capture.jsonl");
        let snapshots = Path::new("capture.snapshots");

        for missing in 0..3 {
            let (raw, receipt, snapshots) = match missing {
                0 => (None, Some(receipt), Some(snapshots)),
                1 => (Some(raw), None, Some(snapshots)),
                2 => (Some(raw), Some(receipt), None),
                _ => unreachable!(),
            };
            assert!(
                validate_native_shape_trace_arguments(
                    Some(crate::trace_profile::TraceProfileKind::NativeShape),
                    None,
                    raw,
                    receipt,
                    snapshots,
                    cwd,
                )
                .is_err()
            );
        }

        assert!(
            validate_native_shape_trace_arguments(
                Some(crate::trace_profile::TraceProfileKind::NativeShape),
                None,
                Some(Path::new("nested/../same")),
                Some(Path::new("same")),
                Some(snapshots),
                cwd,
            )
            .unwrap_err()
            .to_string()
            .contains("different")
        );
        for (raw, receipt, snapshots) in [
            ("snapshots/../capture.raw", "receipt", "./capture.raw"),
            ("raw", "nested/../capture.jsonl", "capture.jsonl"),
        ] {
            assert!(
                validate_native_shape_trace_arguments(
                    Some(crate::trace_profile::TraceProfileKind::NativeShape),
                    None,
                    Some(Path::new(raw)),
                    Some(Path::new(receipt)),
                    Some(Path::new(snapshots)),
                    cwd,
                )
                .unwrap_err()
                .to_string()
                .contains("snapshot")
            );
        }

        validate_native_shape_trace_arguments(
            Some(crate::trace_profile::TraceProfileKind::NativeShape),
            None,
            Some(raw),
            Some(receipt),
            Some(snapshots),
            cwd,
        )
        .unwrap();
    }

    #[test]
    fn native_shape_snapshot_option_is_exclusive_to_native_shape() {
        let cwd = Path::new("/tmp/native-shape-cwd");
        for profile in [
            None,
            Some(crate::trace_profile::TraceProfileKind::Dsr),
            Some(crate::trace_profile::TraceProfileKind::DsrIndirect),
            Some(crate::trace_profile::TraceProfileKind::DsrFork),
            Some(crate::trace_profile::TraceProfileKind::NativeFault),
            Some(crate::trace_profile::TraceProfileKind::NativeWall),
        ] {
            assert!(
                validate_native_shape_trace_arguments(
                    profile,
                    None,
                    None,
                    None,
                    Some(Path::new("snapshots")),
                    cwd,
                )
                .is_err()
            );
            validate_native_shape_trace_arguments(profile, None, None, None, None, cwd).unwrap();
        }

        assert!(
            validate_native_shape_trace_arguments(
                None,
                Some(Path::new("custom.d")),
                None,
                None,
                Some(Path::new("snapshots")),
                cwd,
            )
            .is_err()
        );
    }

    #[test]
    fn native_shape_requires_darwin_aarch64_host() {
        validate_native_shape_host("macos", "aarch64").unwrap();
        for (os, arch) in [
            ("linux", "aarch64"),
            ("freebsd", "x86_64"),
            ("macos", "x86_64"),
        ] {
            assert!(validate_native_shape_host(os, arch).is_err());
        }
    }

    #[test]
    fn native_shape_requires_command_line_native_and_digest_image() {
        let accepted_argv = [
            "run".to_owned(),
            "--exec-backend".to_owned(),
            "native".to_owned(),
            "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "/bin/true".to_owned(),
        ];
        let accepted = NativeShapeTarget::parse(&accepted_argv).unwrap();
        assert_eq!(
            accepted.image,
            "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            accepted.image_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(accepted.argv, accepted_argv);
        assert_eq!(accepted.argv_sha256, argv_sha256(&accepted_argv).unwrap());

        let defaulted = [
            "run".to_owned(),
            "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "/bin/true".to_owned(),
        ];
        assert!(
            NativeShapeTarget::parse(&defaulted)
                .unwrap_err()
                .to_string()
                .contains("explicit")
        );
    }

    #[test]
    fn native_shape_rejects_non_run_vmm_unpinned_and_empty_targets() {
        let digest = "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for argv in [
            vec!["pull".to_owned(), digest.to_owned()],
            vec![
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "vmm".to_owned(),
                digest.to_owned(),
                "/bin/true".to_owned(),
            ],
            vec![
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "native".to_owned(),
                "ubuntu:24.04".to_owned(),
                "/bin/true".to_owned(),
            ],
            vec![
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "native".to_owned(),
                "ubuntu@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_owned(),
                "/bin/true".to_owned(),
            ],
            vec![
                "run".to_owned(),
                "--exec-backend".to_owned(),
                "native".to_owned(),
                digest.to_owned(),
            ],
            Vec::new(),
        ] {
            assert!(
                NativeShapeTarget::parse(&argv).is_err(),
                "accepted {argv:?}"
            );
        }
    }

    #[test]
    fn native_shape_identity_is_strict_and_exactly_comparable() {
        let expected = fixture_identity();
        expected.validate().unwrap();
        expected.require_exact_match(&expected).unwrap();

        for mutation in 0..6 {
            let mut observed = expected.clone();
            match mutation {
                0 => observed.git_head = "f".repeat(40),
                1 => observed.git_dirty = true,
                2 => observed.executable_sha256 = "2".repeat(64),
                3 => observed.host = "other-host".to_owned(),
                4 => observed.host_arch = "x86_64".to_owned(),
                5 => observed.os_build = "26A999".to_owned(),
                _ => unreachable!(),
            }
            assert!(expected.require_exact_match(&observed).is_err());
        }

        let mut unknown = expected;
        unknown.host.clear();
        assert!(unknown.validate().is_err());
    }

    #[test]
    fn native_shape_run_id_is_nonempty_and_stable() {
        assert_eq!(
            resolve_native_shape_run_id(
                Some(OsStr::new("caller-selected")),
                "20260804T120000.000Z",
                42,
            )
            .unwrap(),
            "caller-selected"
        );
        assert_eq!(
            resolve_native_shape_run_id(None, "20260804T120000.000Z", 42).unwrap(),
            "native-shape-20260804T120000.000Z-42"
        );
        assert!(
            resolve_native_shape_run_id(Some(OsStr::new("")), "20260804T120000.000Z", 42).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_shape_snapshot_claim_requires_a_fresh_real_directory() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let fixture = tempfile::tempdir().unwrap();
        let snapshots = fixture.path().join("snapshots");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        claim_native_shape_snapshot_directory(&snapshots, uid, gid).unwrap();
        let metadata = std::fs::symlink_metadata(&snapshots).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
        assert!(claim_native_shape_snapshot_directory(&snapshots, uid, gid).is_err());

        let target = fixture.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = fixture.path().join("snapshot-link");
        symlink(&target, &link).unwrap();
        assert!(claim_native_shape_snapshot_directory(&link, uid, gid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_shape_snapshot_claim_rejects_opened_or_final_inode_substitution() {
        let fixture = tempfile::tempdir().unwrap();
        let claimed = fixture.path().join("claimed");
        let substituted = fixture.path().join("substituted");
        std::fs::create_dir(&claimed).unwrap();
        std::fs::create_dir(&substituted).unwrap();
        let claimed_metadata = std::fs::symlink_metadata(&claimed).unwrap();
        let substituted_metadata = std::fs::symlink_metadata(&substituted).unwrap();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        validate_snapshot_claim_metadata(
            &claimed_metadata,
            &claimed_metadata,
            &claimed_metadata,
            uid,
            gid,
        )
        .unwrap();
        assert!(
            validate_snapshot_claim_metadata(
                &claimed_metadata,
                &substituted_metadata,
                &claimed_metadata,
                uid,
                gid,
            )
            .is_err()
        );
        assert!(
            validate_snapshot_claim_metadata(
                &claimed_metadata,
                &claimed_metadata,
                &substituted_metadata,
                uid,
                gid,
            )
            .is_err()
        );
    }

    #[test]
    fn authority_hashes_use_canonical_json_and_length_delimited_argv() {
        let authority = fixture_authority();
        assert_eq!(argv_sha256(&authority.target_argv).unwrap(), ARGV_SHA256);
        assert_eq!(authority.sha256().unwrap(), AUTHORITY_SHA256);
        assert_eq!(authority.header_record().unwrap(), FIXTURE_HEADER);

        let joined = vec!["go".to_owned(), "build./cmd".to_owned()];
        assert_ne!(argv_sha256(&joined).unwrap(), ARGV_SHA256);
    }

    #[test]
    fn authority_rejects_noncanonical_or_substituted_determinants() {
        let mut mutations = Vec::new();

        let mut wrong = fixture_authority();
        wrong.schema = "carrick.native-shape-authority.v2".to_owned();
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.profile = "native-wall".to_owned();
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.raw_schema = "carrick.native-shape.raw.v1".to_owned();
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.git_dirty = true;
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.git_head = "a".repeat(39);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.executable_sha256 = "g".repeat(64);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.program_template_sha256 = "a".repeat(63);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.birth_qualification_sha256 = "A".repeat(64);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.terminal_qualification_sha256 = "z".repeat(64);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.target_argv_sha256 = "0".repeat(64);
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.os_build = "26 A".to_owned();
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.os_build = "26%G0".to_owned();
        mutations.push(wrong);
        let mut wrong = fixture_authority();
        wrong.sampling_hz = 998;
        mutations.push(wrong);

        for mutation in mutations {
            assert!(mutation.header_record().is_err(), "{mutation:?}");
            assert!(mutation.sha256().is_err(), "{mutation:?}");
        }
    }

    #[test]
    fn authority_rejects_self_consistent_target_and_arch_substitutions() {
        const IMAGE: &str = "docker.io/library/ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        fn substituted(argv: &[&str], image: &str) -> NativeShapeAuthority {
            let mut authority = fixture_authority();
            authority.target_argv = argv.iter().map(|value| (*value).to_owned()).collect();
            authority.target_argv_sha256 = argv_sha256(&authority.target_argv).unwrap();
            authority.image = image.to_owned();
            authority
        }

        let mut cases = vec![
            (
                "defaulted native",
                substituted(&["run", IMAGE, "/bin/true"], IMAGE),
                "explicit",
            ),
            (
                "explicit VMM",
                substituted(&["run", "--exec-backend", "vmm", IMAGE, "/bin/true"], IMAGE),
                "explicit",
            ),
            (
                "non-run command",
                substituted(&["pull", IMAGE], IMAGE),
                "run subcommand",
            ),
            (
                "tag-only image",
                substituted(
                    &[
                        "run",
                        "--exec-backend",
                        "native",
                        "ubuntu:24.04",
                        "/bin/true",
                    ],
                    "docker.io/library/ubuntu:24.04",
                ),
                "digest-pinned",
            ),
            (
                "malformed digest image",
                substituted(
                    &[
                        "run",
                        "--exec-backend",
                        "native",
                        "ubuntu@sha256:aaaa",
                        "/bin/true",
                    ],
                    "docker.io/library/ubuntu@sha256:aaaa",
                ),
                "digest",
            ),
            (
                "empty guest command",
                substituted(&["run", "--exec-backend", "native", IMAGE], IMAGE),
                "target command is empty",
            ),
            (
                "image differs from argv",
                substituted(
                    &["run", "--exec-backend", "native", IMAGE, "/bin/true"],
                    "docker.io/library/ubuntu@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
                "image does not match",
            ),
        ];
        let mut wrong_arch = fixture_authority();
        wrong_arch.host_arch = "x86_64".to_owned();
        cases.push(("wrong host architecture", wrong_arch, "aarch64"));

        for (label, authority, expected) in cases {
            let sha_error = authority
                .sha256()
                .expect_err("self-consistent substituted authority was accepted");
            assert!(
                format!("{sha_error:#}").contains(expected),
                "{label}: {sha_error:#}"
            );
            let header_error = authority
                .header_record()
                .expect_err("substituted authority rendered an authenticated header");
            assert!(
                format!("{header_error:#}").contains(expected),
                "{label}: {header_error:#}"
            );
        }
    }

    #[test]
    fn nshape2_reconciles_one_cpu_population() {
        let authority = fixture_authority();
        let raw = NativeShapeRaw::parse(valid_raw().as_bytes(), &authority).unwrap();
        assert_eq!(raw.all_cpu, 100);
        assert_eq!(raw.user_cpu, 70);
        assert_eq!(raw.kernel_cpu, 30);
        assert_eq!(raw.invalid_cpu, 0);
        assert_eq!(raw.jit_user, 40);
        assert_eq!(raw.non_jit_user, 30);
        assert_eq!(raw.pc_samples.iter().map(|row| row.count).sum::<u64>(), 40);
        assert_eq!(raw.parents, [(11, 10)].into_iter().collect());
        assert_eq!(raw.exits, [(10, 1), (11, 1)].into_iter().collect());
        assert_eq!(
            raw.lifecycle,
            NativeShapeLifecycle {
                bounded: false,
                target_completed: true,
                target_exit_reason: 1,
                target_pid: 10,
                admitted: 2,
                exited: 2,
                live_at_end: 0,
                probe_errors: 0,
            }
        );
    }

    #[test]
    fn nshape2_rejects_shape1_and_authority_substitution() {
        let authority = fixture_authority();
        assert!(NativeShapeRaw::parse(b"SHAPE1|samples=1\n", &authority).is_err());
        let mut other = authority.clone();
        other.run_id = "different-run".to_owned();
        assert!(NativeShapeRaw::parse(valid_raw().as_bytes(), &other).is_err());
    }

    #[test]
    fn nshape2_requires_header_first_with_exact_fields_and_order() {
        let raw = valid_raw();
        let header = FIXTURE_HEADER;

        parse_rejected(replace_once(
            &raw,
            &format!("{header}\nNSHAPE2|fork|parent=10|child=11"),
            &format!("NSHAPE2|fork|parent=10|child=11\n{header}"),
        ));
        parse_rejected(replace_once(
            &raw,
            "|raw_schema=carrick.native-shape.raw.v2|os_build=",
            "|os_build=26A5388g|raw_schema=carrick.native-shape.raw.v2|ignored=",
        ));
        parse_rejected(replace_once(
            &raw,
            "|sampling_hz=997|authority_sha256=",
            "|sampling_hz=997|sampling_hz=997|authority_sha256=",
        ));
        parse_rejected(replace_once(&raw, "|sampling_hz=997", ""));
        parse_rejected(format!("junk\n{raw}"));
        parse_rejected(replace_once(&raw, &format!("{header}\n"), ""));
        parse_rejected(replace_once(&raw, header, &format!("{header}\n{header}")));
    }

    #[test]
    fn nshape2_rejects_unknown_duplicate_missing_and_reordered_records() {
        let raw = valid_raw();

        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|mode|kind=all|count=100",
            "NSHAPE2|mode|kind=all|count=100\nNSHAPE2|mode|kind=all|count=100",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|mode|kind=kernel|count=30\n",
            "",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|mode|kind=user|count=70\nNSHAPE2|mode|kind=kernel|count=30",
            "NSHAPE2|mode|kind=kernel|count=30\nNSHAPE2|mode|kind=user|count=70",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|section=region",
            "NSHAPE2|unknown|count=0\nNSHAPE2|section=region",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|section=region\nNSHAPE2|region|kind=jit|count=40",
            "NSHAPE2|region|kind=jit|count=40\nNSHAPE2|section=region",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|region|kind=non-jit|count=30\n",
            "",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|pc|pid=10|pc=0x1000|count=15",
            "NSHAPE2|pc|pc=0x1000|pid=10|count=15",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|exit|pid=11|reason=1",
            "NSHAPE2|exit|reason=1|pid=11",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|pc|pid=10|pc=0x1000|count=15",
            "NSHAPE2|pc|pid=10|pc=0x1000|count=15\nNSHAPE2|pc|pid=10|pc=0x1000|count=15",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|complete|bounded=0",
            "NSHAPE2|complete|bounded=false",
        ));
        parse_rejected(replace_once(&raw, "pc=0x1000", "pc=0xA000"));
        parse_rejected(replace_once(&raw, "count=15", "count=015"));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|complete|bounded=0|target_completed=1|target_exit_reason=1|target_pid=10|admitted=2|exited=2|live_at_end=0|probe_errors=0\n",
            "",
        ));
        parse_rejected(format!("{raw}NSHAPE2|section=pc\n"));
        let mut non_utf8 = raw.into_bytes();
        non_utf8.push(0xff);
        parse_rejected(non_utf8);
    }

    #[test]
    fn nshape2_rejects_invalid_fork_graphs() {
        let raw = valid_raw();
        let fork = "NSHAPE2|fork|parent=10|child=11";

        parse_rejected(replace_once(
            &raw,
            fork,
            &format!("{fork}\nNSHAPE2|fork|parent=12|child=11"),
        ));
        parse_rejected(replace_once(&raw, fork, "NSHAPE2|fork|parent=11|child=11"));
        parse_rejected(replace_once(
            &raw,
            fork,
            "NSHAPE2|fork|parent=10|child=11\nNSHAPE2|fork|parent=11|child=10",
        ));
        parse_rejected(replace_once(&raw, "parent=10", "parent=0"));
        parse_rejected(replace_once(&raw, "child=11", "child=4294967296"));
    }

    #[test]
    fn nshape2_rejects_disconnected_or_unadmitted_process_evidence() {
        let raw = valid_raw();
        let disconnected = replace_once(
            &replace_once(
                &replace_once(
                    &raw,
                    "NSHAPE2|fork|parent=10|child=11",
                    "NSHAPE2|fork|parent=10|child=11\nNSHAPE2|fork|parent=20|child=21",
                ),
                "NSHAPE2|exit|pid=11|reason=1",
                "NSHAPE2|exit|pid=11|reason=1\nNSHAPE2|exit|pid=21|reason=1\nNSHAPE2|exit|pid=20|reason=1",
            ),
            "|admitted=2|exited=2|",
            "|admitted=4|exited=4|",
        );
        parse_rejected_for(disconnected, "disconnected");

        parse_rejected_for(
            replace_once(
                &raw,
                "NSHAPE2|pc|pid=11|pc=0x2000",
                "NSHAPE2|pc|pid=12|pc=0x2000",
            ),
            "PC PID is not admitted",
        );
        parse_rejected_for(
            replace_once(
                &raw,
                "NSHAPE2|exit|pid=11|reason=1",
                "NSHAPE2|exit|pid=12|reason=1",
            ),
            "exit PID is not admitted",
        );
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|exit|pid=11|reason=1",
            "NSHAPE2|exit|pid=11|reason=1\nNSHAPE2|exit|pid=11|reason=1",
        ));
        parse_rejected(replace_once(&raw, "NSHAPE2|exit|pid=11|reason=1\n", ""));
        parse_rejected_for(
            replace_once(
                &raw,
                "NSHAPE2|exit|pid=10|reason=1",
                "NSHAPE2|exit|pid=10|reason=2",
            ),
            "target exit reason",
        );
    }

    #[test]
    fn nshape2_rejects_zero_or_inconsistent_sample_populations() {
        let raw = valid_raw();

        parse_rejected(replace_once(&raw, "pc=0x1000", "pc=0x0"));
        parse_rejected(replace_once(&raw, "count=15", "count=0"));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|pc|pid=10|pc=0x1000|count=15\nNSHAPE2|pc|pid=11|pc=0x2000|count=25\n",
            "",
        ));
        parse_rejected(replace_once(&raw, "kind=jit|count=40", "kind=jit|count=0"));
        parse_rejected_for(
            replace_once(&raw, "kind=all|count=100", "kind=all|count=101"),
            "all CPU count does not reconcile",
        );
        let invalid = replace_once(
            &replace_once(&raw, "kind=all|count=100", "kind=all|count=101"),
            "kind=invalid|count=0",
            "kind=invalid|count=1",
        );
        parse_rejected_for(invalid, "invalid CPU sample count is nonzero");
        let regions = replace_once(
            &replace_once(&raw, "kind=all|count=100", "kind=all|count=101"),
            "kind=user|count=70",
            "kind=user|count=71",
        );
        parse_rejected_for(regions, "user CPU count does not reconcile");
        let pcs = replace_once(
            &replace_once(&raw, "kind=jit|count=40", "kind=jit|count=41"),
            "kind=non-jit|count=30",
            "kind=non-jit|count=29",
        );
        parse_rejected_for(pcs, "JIT user count does not reconcile");
    }

    #[test]
    fn nshape2_rejects_every_population_addition_overflow() {
        let raw = valid_raw();
        let max = u64::MAX;

        let total_overflow = replace_once(
            &replace_once(
                &replace_once(
                    &raw,
                    "kind=user|count=70",
                    &format!("kind=user|count={max}"),
                ),
                "kind=kernel|count=30",
                "kind=kernel|count=1",
            ),
            "kind=jit|count=40",
            &format!("kind=jit|count={max}"),
        );
        let total_overflow = replace_once(
            &replace_once(
                &total_overflow,
                "kind=non-jit|count=30",
                "kind=non-jit|count=0",
            ),
            "count=15\nNSHAPE2|pc|pid=11|pc=0x2000|count=25",
            &format!("count={max}\n"),
        );
        parse_rejected_for(total_overflow, "total CPU sample count overflow");

        let invalid_overflow = replace_once(
            &replace_once(
                &replace_once(
                    &replace_once(
                        &replace_once(&raw, "kind=all|count=100", &format!("kind=all|count={max}")),
                        "kind=user|count=70",
                        &format!("kind=user|count={}", max - 1),
                    ),
                    "kind=kernel|count=30",
                    "kind=kernel|count=1",
                ),
                "kind=invalid|count=0",
                "kind=invalid|count=1",
            ),
            "kind=jit|count=40",
            &format!("kind=jit|count={}", max - 1),
        );
        let invalid_overflow = replace_once(
            &replace_once(
                &invalid_overflow,
                "kind=non-jit|count=30",
                "kind=non-jit|count=0",
            ),
            "count=15\nNSHAPE2|pc|pid=11|pc=0x2000|count=25",
            &format!("count={}\n", max - 1),
        );
        parse_rejected_for(invalid_overflow, "total CPU sample count overflow");

        let region_overflow = replace_once(
            &replace_once(
                &replace_once(
                    &replace_once(
                        &replace_once(&raw, "kind=all|count=100", &format!("kind=all|count={max}")),
                        "kind=user|count=70",
                        &format!("kind=user|count={max}"),
                    ),
                    "kind=kernel|count=30",
                    "kind=kernel|count=0",
                ),
                "kind=jit|count=40",
                &format!("kind=jit|count={max}"),
            ),
            "kind=non-jit|count=30",
            "kind=non-jit|count=1",
        );
        parse_rejected_for(region_overflow, "user region sample count overflow");

        let pc_overflow = replace_once(
            &replace_once(
                &replace_once(
                    &replace_once(
                        &replace_once(
                            &replace_once(
                                &raw,
                                "kind=all|count=100",
                                &format!("kind=all|count={max}"),
                            ),
                            "kind=user|count=70",
                            &format!("kind=user|count={max}"),
                        ),
                        "kind=kernel|count=30",
                        "kind=kernel|count=0",
                    ),
                    "kind=jit|count=40",
                    &format!("kind=jit|count={max}"),
                ),
                "kind=non-jit|count=30",
                "kind=non-jit|count=0",
            ),
            "count=15\nNSHAPE2|pc|pid=11|pc=0x2000|count=25",
            &format!("count={max}\nNSHAPE2|pc|pid=11|pc=0x2000|count=1"),
        );
        parse_rejected_for(pc_overflow, "PC sample count overflow");
    }

    #[test]
    fn nshape2_rejects_non_authoritative_completion() {
        let raw = valid_raw();

        for (from, to) in [
            ("bounded=0", "bounded=1"),
            ("target_completed=1", "target_completed=0"),
            ("target_exit_reason=1", "target_exit_reason=2"),
            ("target_pid=10", "target_pid=12"),
            ("admitted=2", "admitted=3"),
            ("exited=2", "exited=1"),
            ("live_at_end=0", "live_at_end=1"),
            ("probe_errors=0", "probe_errors=1"),
        ] {
            parse_rejected(replace_once(&raw, from, to));
        }

        parse_rejected(replace_once(
            &raw,
            "|admitted=2|exited=2",
            "|exited=2|admitted=2",
        ));
        parse_rejected_for(
            replace_once(&raw, "|exited=2|", "|exited=3|"),
            "exited process count exceeds admitted",
        );
        parse_rejected_for(
            replace_once(&raw, "|admitted=2|exited=2|", "|admitted=3|exited=3|"),
            "admitted process count does not reconcile",
        );
        let exited_rows = replace_once(
            &replace_once(&raw, "|exited=2|", "|exited=1|"),
            "|live_at_end=0|",
            "|live_at_end=1|",
        );
        parse_rejected_for(exited_rows, "exited process count does not reconcile");
        parse_rejected(replace_once(
            &raw,
            "|probe_errors=0",
            "|probe_errors=0|unknown=0",
        ));
        parse_rejected(replace_once(
            &raw,
            "NSHAPE2|complete|",
            "NSHAPE2|complete|bounded=0|NSHAPE2|complete|",
        ));
    }
}
