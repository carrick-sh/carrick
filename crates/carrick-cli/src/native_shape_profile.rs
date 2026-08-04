use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use carrick_image::ImageReference;
use carrick_spec::ExecBackendRequest;
use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::args::{Cli, Commands};
use crate::trace_profile::TraceProfileKind;

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
