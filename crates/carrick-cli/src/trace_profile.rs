use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::io::{BufWriter, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::perf_stats::{Summary, summarize};
#[cfg(target_os = "macos")]
use carrick_runtime::dtrace_symbols::SampledKernelSymbolOverlay;

const PROTOCOL_PREFIX: &str = "DSRPROF1";
const JSON_SCHEMA: &str = "carrick.dsr-profile.v1";
const V2_PROTOCOL_PREFIX: &str = "DSRPROF2";
const V2_STACK_PREFIX: &str = "DSRSTACK2";
const V2_ERROR_PREFIX: &str = "DSRERROR2";
const V2_RAW_SCHEMA: &str = "carrick.dsrprof.raw.v2";
const NATIVE_FAULT_RAW_SCHEMA: &str = "carrick.native-fault.raw.v2";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessBirthKey {
    pid: u32,
    start_sec: i64,
    start_usec: i32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawProcessImageKey {
    birth: ProcessBirthKey,
    image_generation: u64,
    runtime_epoch: u64,
}

#[derive(Debug)]
struct V2Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl V2Record {
    fn parse(line: &str, prefix: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(prefix) {
            bail!("unknown profile protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated {prefix} record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw_field in parts {
            let (key, value) = raw_field
                .split_once('=')
                .ok_or_else(|| anyhow!("{prefix} field lacks '=': {raw_field:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("{prefix} field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate {prefix} field {key:?}"),
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
            bail!(
                "{V2_PROTOCOL_PREFIX} {:?} field contract mismatch: missing={missing:?}, extra={extra:?}",
                self.tag
            );
        }
        Ok(())
    }

    fn required(&self, key: &str) -> Result<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{} record is missing {key:?}", self.tag))
    }

    fn decimal_u64(&self, key: &str) -> Result<u64> {
        parse_decimal_u64(self.required(key)?)
            .with_context(|| format!("invalid {} field {key:?}", self.tag))
    }

    fn decimal_u32(&self, key: &str) -> Result<u32> {
        let value = self.decimal_u64(key)?;
        u32::try_from(value).with_context(|| format!("{} field {key:?} exceeds u32", self.tag))
    }

    fn signed_i64(&self, key: &str) -> Result<i64> {
        parse_signed_i64(self.required(key)?)
            .with_context(|| format!("invalid {} field {key:?}", self.tag))
    }

    fn signed_i32(&self, key: &str) -> Result<i32> {
        let value = self.signed_i64(key)?;
        i32::try_from(value).with_context(|| format!("{} field {key:?} exceeds i32", self.tag))
    }

    fn address(&self, key: &str) -> Result<u64> {
        parse_v2_address(self.required(key)?)
            .with_context(|| format!("invalid {} address {key:?}", self.tag))
    }

    fn birth(&self, pid: &str, sec: &str, usec: &str) -> Result<ProcessBirthKey> {
        let birth = ProcessBirthKey {
            pid: self.decimal_u32(pid)?,
            start_sec: self.signed_i64(sec)?,
            start_usec: self.signed_i32(usec)?,
        };
        if birth.pid == 0 {
            bail!("{} process pid must be positive", self.tag);
        }
        if !(0..1_000_000).contains(&birth.start_usec) {
            bail!("{} start_usec is outside timeval range", self.tag);
        }
        Ok(birth)
    }

    fn image_key(&self) -> Result<RawProcessImageKey> {
        let key = RawProcessImageKey {
            birth: self.birth("pid", "start_sec", "start_usec")?,
            image_generation: self.decimal_u64("image")?,
            runtime_epoch: self.decimal_u64("epoch")?,
        };
        if key.image_generation == 0 {
            bail!("{} image generation must be positive", self.tag);
        }
        Ok(key)
    }
}

fn parse_decimal_u64(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("expected unsigned decimal integer, got {value:?}");
    }
    value
        .parse::<u64>()
        .with_context(|| format!("decimal integer {value:?} exceeds u64"))
}

fn parse_signed_i64(value: &str) -> Result<i64> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("expected signed decimal integer, got {value:?}");
    }
    value
        .parse::<i64>()
        .with_context(|| format!("signed integer {value:?} exceeds i64"))
}

fn parse_v2_address(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .ok_or_else(|| anyhow!("address {value:?} is not 0x-prefixed hexadecimal"))?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("address {value:?} contains a non-hexadecimal digit");
    }
    u64::from_str_radix(digits, 16).with_context(|| format!("address {value:?} exceeds u64"))
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must be an exact hexadecimal SHA-256 digest");
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum V2RangeKind {
    Private,
    Shared { unit_id: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct V2Range {
    sequence: u64,
    start: u64,
    end: u64,
    kind: V2RangeKind,
}

#[derive(Clone, Debug, Default)]
struct V2EpochState {
    reset_observed: bool,
    ranges: Vec<V2Range>,
    ready_frontier: Option<u64>,
    replay_expected: Option<Vec<V2Range>>,
    host_image_base: Option<u64>,
    host_image_catalog: Option<Vec<HostImageRangeRecord>>,
    guest_image_base: Option<u64>,
}

impl V2EpochState {
    fn is_ready(&self) -> bool {
        let catalog_len = u64::try_from(self.ranges.len()).ok();
        self.reset_observed
            && self.replay_expected.is_none()
            && self
                .ready_frontier
                .zip(catalog_len)
                .is_some_and(|(ready, current)| ready > 0 && ready <= current)
            && !self.ranges.is_empty()
    }
}

#[derive(Debug)]
struct V2ProcessState {
    current: RawProcessImageKey,
    alive: bool,
    exec_attempt: Option<RawProcessImageKey>,
    exit_reason: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct V2KernelFrame {
    key: RawProcessImageKey,
    provider: String,
    function: String,
    class: String,
    timestamp_ns: u64,
}

#[derive(Clone, Debug)]
struct V2OffcpuEpisode {
    key: RawProcessImageKey,
    episode: u64,
    kind: String,
    pc: u64,
    timestamp_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct V2ProfileAuthority {
    profile: TraceProfileKind,
    os_build: String,
    program_sha256: String,
    birth_qualification_sha256: String,
    terminal_qualification_sha256: String,
    terminal_qualifications: BTreeSet<(String, String, String)>,
}

impl V2ProfileAuthority {
    #[cfg(test)]
    pub(crate) fn new(
        os_build: &str,
        program_sha256: &str,
        birth_qualification_sha256: &str,
        terminal_qualification_sha256: &str,
        terminal_qualifications: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self> {
        Self::new_for_profile(
            TraceProfileKind::NativeWall,
            os_build,
            program_sha256,
            birth_qualification_sha256,
            terminal_qualification_sha256,
            terminal_qualifications,
        )
    }

    pub(crate) fn new_for_profile(
        profile: TraceProfileKind,
        os_build: &str,
        program_sha256: &str,
        birth_qualification_sha256: &str,
        terminal_qualification_sha256: &str,
        terminal_qualifications: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self> {
        if !matches!(
            profile,
            TraceProfileKind::NativeFault | TraceProfileKind::NativeWall
        ) {
            bail!("profile {:?} does not use native launch authority", profile);
        }
        validate_percent_token(os_build, "authority os_build")?;
        for (value, field) in [
            (program_sha256, "authority program_sha256"),
            (
                birth_qualification_sha256,
                "authority birth_qualification_sha256",
            ),
            (
                terminal_qualification_sha256,
                "authority terminal_qualification_sha256",
            ),
        ] {
            validate_sha256(value, field)?;
        }
        let mut terminals = BTreeSet::new();
        for (provider, function, scope) in terminal_qualifications {
            if !matches!(provider.as_str(), "syscall" | "mach_trap") {
                bail!("authority contains unknown terminal provider {provider:?}");
            }
            validate_percent_token(&function, "authority terminal function")?;
            if !matches!(scope.as_str(), "thread" | "process") {
                bail!("authority contains unknown terminal scope {scope:?}");
            }
            if !terminals.insert((provider, function, scope)) {
                bail!("authority contains a duplicate terminal qualification");
            }
        }
        if !terminals.iter().any(|(_, _, scope)| scope == "thread")
            || !terminals.iter().any(|(_, _, scope)| scope == "process")
        {
            bail!("authority must qualify both thread and process termination");
        }
        Ok(Self {
            profile,
            os_build: os_build.to_owned(),
            program_sha256: program_sha256.to_owned(),
            birth_qualification_sha256: birth_qualification_sha256.to_owned(),
            terminal_qualification_sha256: terminal_qualification_sha256.to_owned(),
            terminal_qualifications: terminals,
        })
    }

    pub(crate) fn program_sha256(&self) -> &str {
        &self.program_sha256
    }

    pub(crate) fn os_build(&self) -> &str {
        &self.os_build
    }

    pub(crate) fn birth_qualification_sha256(&self) -> &str {
        &self.birth_qualification_sha256
    }

    pub(crate) fn terminal_qualification_sha256(&self) -> &str {
        &self.terminal_qualification_sha256
    }

    pub(crate) fn header_record(&self) -> String {
        match self.profile {
            TraceProfileKind::NativeWall => format!(
                "DSRPROF2|header|profile=native-wall|raw_schema={V2_RAW_SCHEMA}|os_build={}|program_sha256={}|birth_qualification_sha256={}|terminal_qualification_sha256={}|wall_hz=197|cpu_hz=499",
                self.os_build,
                self.program_sha256(),
                self.birth_qualification_sha256,
                self.terminal_qualification_sha256,
            ),
            TraceProfileKind::NativeFault => format!(
                "NFAULT2|header|profile=native-fault|raw_schema={NATIVE_FAULT_RAW_SCHEMA}|os_build={}|program_sha256={}|birth_qualification_sha256={}|terminal_qualification_sha256={}|page_sample_modulus=64",
                self.os_build,
                self.program_sha256(),
                self.birth_qualification_sha256,
                self.terminal_qualification_sha256,
            ),
            TraceProfileKind::Dsr | TraceProfileKind::DsrFork | TraceProfileKind::DsrIndirect => {
                unreachable!("non-native profile cannot construct V2ProfileAuthority")
            }
        }
    }
}

#[derive(Debug, Default)]
struct V2Validator {
    authority: Option<V2ProfileAuthority>,
    header_seen: bool,
    wall_hz: Option<u64>,
    cpu_hz: Option<u64>,
    elapsed_ns: Option<u64>,
    target: Option<ProcessBirthKey>,
    complete: bool,
    processes: BTreeMap<ProcessBirthKey, V2ProcessState>,
    active_pids: BTreeMap<u32, ProcessBirthKey>,
    known_keys: BTreeSet<RawProcessImageKey>,
    epochs: BTreeMap<RawProcessImageKey, V2EpochState>,
    pending_inherit: BTreeMap<ProcessBirthKey, (RawProcessImageKey, RawProcessImageKey)>,
    kernel_stacks: BTreeMap<(ProcessBirthKey, u64), Vec<V2KernelFrame>>,
    offcpu_open: BTreeMap<(ProcessBirthKey, u64), V2OffcpuEpisode>,
    offcpu_last_episode: BTreeMap<(ProcessBirthKey, u64), u64>,
    offcpu_closed: BTreeMap<(RawProcessImageKey, String, u64), (u64, u64)>,
    offcpu_summary: BTreeMap<(RawProcessImageKey, String, u64), (u64, u64)>,
    wall_state: BTreeMap<String, u64>,
    cpu_user_summary: BTreeMap<(RawProcessImageKey, u64), u64>,
    cpu_kernel_summary: BTreeMap<(RawProcessImageKey, String, u64), u64>,
    cpu_samples: u64,
    dtrace_errors: u64,
    transition_events_seen: bool,
    terminal_qualifications: BTreeSet<(String, String, String)>,
    open_stack: Option<V2StackRecord>,
    stacks: Vec<V2StackRecord>,
}

impl V2Validator {
    fn with_authority(authority: V2ProfileAuthority) -> Self {
        Self {
            terminal_qualifications: authority.terminal_qualifications.clone(),
            authority: Some(authority),
            ..Self::default()
        }
    }
}

#[derive(Debug)]
struct V2StackRecord {
    key: RawProcessImageKey,
    kind: String,
    count: u64,
    total_ns: u64,
    frames: Vec<String>,
    leading_separator_seen: bool,
}

pub(crate) fn validate_v2_path(path: &Path, capture_status: ProfileCaptureStatus) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read DSRPROF2 stream {}", path.display()))?;
    validate_v2_lines(contents.lines(), capture_status)
}

pub(crate) fn path_has_v2_header(path: &Path) -> Result<bool> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read profile stream header {}", path.display()))?;
    Ok(contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.starts_with("DSRPROF2|header|")))
}

fn validate_v2_lines<I, S>(lines: I, capture_status: ProfileCaptureStatus) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    validate_v2_lines_with_validator(lines, capture_status, V2Validator::default())
}

fn validate_v2_lines_with_validator<I, S>(
    lines: I,
    capture_status: ProfileCaptureStatus,
    validator: V2Validator,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_v2_lines_with_validator(lines, capture_status, validator).map(|_| ())
}

fn parse_v2_lines_with_validator<I, S>(
    lines: I,
    capture_status: ProfileCaptureStatus,
    mut validator: V2Validator,
) -> Result<V2Validator>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if capture_status.principal_drops != 0
        || capture_status.aggregation_drops != 0
        || capture_status.dynamic_drops != 0
        || capture_status.dynamic_rinse_drops != 0
        || capture_status.dynamic_dirty_drops != 0
        || capture_status.other_drops != 0
        || capture_status.interrupted
    {
        bail!(
            "DSRPROF2 capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            capture_status.principal_drops,
            capture_status.aggregation_drops,
            capture_status.dynamic_drops,
            capture_status.dynamic_rinse_drops,
            capture_status.dynamic_dirty_drops,
            capture_status.other_drops,
            capture_status.interrupted
        );
    }

    for (index, raw_line) in lines.into_iter().enumerate() {
        let raw_line = raw_line.as_ref();
        if validator.open_stack.is_some() {
            if raw_line == "DSRSTACK2|end" {
                validator
                    .finish_stack()
                    .with_context(|| format!("invalid stack end at line {}", index + 1))?;
            } else {
                if raw_line.is_empty() {
                    let stack = validator
                        .open_stack
                        .as_mut()
                        .ok_or_else(|| anyhow!("DSRSTACK2 state disappeared"))?;
                    if stack.frames.is_empty() && !stack.leading_separator_seen {
                        stack.leading_separator_seen = true;
                        continue;
                    }
                    bail!("empty DSRSTACK2 frame at line {}", index + 1);
                }
                if raw_line.starts_with("DSRPROF") || raw_line.starts_with("DSRSTACK") {
                    bail!(
                        "profile marker interrupted DSRSTACK2 block at line {}",
                        index + 1
                    );
                }
                let stack = validator
                    .open_stack
                    .as_mut()
                    .ok_or_else(|| anyhow!("DSRSTACK2 state disappeared"))?;
                stack.frames.push(raw_line.to_owned());
            }
            continue;
        }

        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if validator.complete {
            bail!(
                "DSRPROF2 record appears after completion at line {}",
                index + 1
            );
        }
        if line.starts_with("DSRPROF1|")
            || line.starts_with("NWSTACK1|")
            || line.starts_with("NWIMAGES1|")
        {
            bail!("mixed v1/v2 profile stream at line {}", index + 1);
        }
        if line.starts_with("DSRSTACK2|") {
            let record = V2Record::parse(line, V2_STACK_PREFIX)
                .with_context(|| format!("invalid stack record at line {}", index + 1))?;
            if record.tag != "begin" {
                bail!(
                    "unknown DSRSTACK2 tag {:?} at line {}",
                    record.tag,
                    index + 1
                );
            }
            validator
                .begin_stack(record)
                .with_context(|| format!("invalid stack begin at line {}", index + 1))?;
            continue;
        }
        if line.starts_with("DSRERROR2|") {
            let record = V2Record::parse(line, V2_ERROR_PREFIX)
                .with_context(|| format!("invalid DTrace error at line {}", index + 1))?;
            validator
                .dtrace_error(&record)
                .with_context(|| format!("invalid DTrace error at line {}", index + 1))?;
            continue;
        }
        if !line.starts_with("DSRPROF2|") {
            bail!("unknown raw profile line {}: {line:?}", index + 1);
        }
        let record = V2Record::parse(line, V2_PROTOCOL_PREFIX)
            .with_context(|| format!("invalid profile record at line {}", index + 1))?;
        validator
            .apply(record)
            .with_context(|| format!("invalid DSRPROF2 record at line {}", index + 1))?;
    }

    if validator.open_stack.is_some() {
        bail!("DSRPROF2 stream ended inside a stack block");
    }
    if !validator.complete {
        bail!("DSRPROF2 stream is missing its completion record");
    }
    Ok(validator)
}

impl V2Validator {
    fn dtrace_error(&mut self, record: &V2Record) -> Result<()> {
        if record.tag != "fault" {
            bail!("unknown DSRERROR2 tag {:?}", record.tag);
        }
        record.exact_fields(&["action", "epid", "fault", "offset", "value"])?;
        let _epid = record.decimal_u64("epid")?;
        let _action = record.decimal_u64("action")?;
        let _offset = record.decimal_u64("offset")?;
        let _fault = record.decimal_u64("fault")?;
        let _value = record.address("value")?;
        self.dtrace_errors = self
            .dtrace_errors
            .checked_add(1)
            .ok_or_else(|| anyhow!("DTrace error count overflow"))?;
        Ok(())
    }

    fn apply(&mut self, record: V2Record) -> Result<()> {
        if !self.header_seen && record.tag != "header" {
            bail!("DSRPROF2 header must be the first record");
        }
        if self.header_seen && self.target.is_none() && record.tag != "target-birth" {
            bail!("DSRPROF2 target-birth must follow the header");
        }
        if matches!(
            record.tag.as_str(),
            "kernel-enter"
                | "kernel-return"
                | "kernel-terminal-close"
                | "offcpu-block"
                | "offcpu-wake"
        ) {
            self.transition_events_seen = true;
        }
        match record.tag.as_str() {
            "header" => self.header(&record),
            "target-birth" => self.target_birth(&record),
            "process-create" => self.process_create(&record),
            "fork-inherit" => self.fork_inherit(&record),
            "exec-attempt" => self.exec_attempt(&record),
            "exec-failure" => self.exec_failure(&record),
            "exec-success" => self.exec_success(&record),
            "range-reset" => self.range_reset(&record),
            "range-private" => self.range_add(&record, false),
            "range-shared" => self.range_add(&record, true),
            "range-ready" => self.range_ready(&record),
            "host-image-base" => self.host_image_base(&record),
            "host-image-catalog" => self.host_image_catalog(&record),
            "guest-image-base" => self.guest_image_base(&record),
            "cpu-user" => self.cpu_user(&record),
            "kernel-enter" => self.kernel_transition(&record, KernelTransition::Enter),
            "kernel-return" => self.kernel_transition(&record, KernelTransition::Return),
            "kernel-terminal-close" => {
                self.kernel_transition(&record, KernelTransition::TerminalClose)
            }
            "cpu-kernel" => self.cpu_kernel(&record),
            "offcpu-block" => self.offcpu_block(&record),
            "offcpu-wake" => self.offcpu_wake(&record),
            "offcpu" => self.offcpu_summary(&record),
            "process-exit" => self.process_exit(&record),
            "wall-state" => self.wall_state(&record),
            "complete" => self.completion(&record),
            other => bail!("unknown DSRPROF2 tag {other:?}"),
        }
    }

    fn begin_stack(&mut self, record: V2Record) -> Result<()> {
        record.exact_fields(&[
            "count",
            "epoch",
            "image",
            "kind",
            "pid",
            "start_sec",
            "start_usec",
            "total_ns",
        ])?;
        let key = record.image_key()?;
        self.require_known_key(key)?;
        let kind = record.required("kind")?.to_owned();
        validate_percent_token(&kind, "stack kind")?;
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("DSRSTACK2 count must be positive");
        }
        self.open_stack = Some(V2StackRecord {
            key,
            kind,
            count,
            total_ns: record.decimal_u64("total_ns")?,
            frames: Vec::new(),
            leading_separator_seen: false,
        });
        Ok(())
    }

    fn finish_stack(&mut self) -> Result<()> {
        let stack = self
            .open_stack
            .take()
            .ok_or_else(|| anyhow!("DSRSTACK2 end without begin"))?;
        if stack.frames.is_empty() {
            bail!("DSRSTACK2 block has no frames");
        }
        self.stacks.push(stack);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum KernelTransition {
    Enter,
    Return,
    TerminalClose,
}

impl V2Validator {
    fn header(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "birth_qualification_sha256",
            "cpu_hz",
            "os_build",
            "profile",
            "program_sha256",
            "raw_schema",
            "terminal_qualification_sha256",
            "wall_hz",
        ])?;
        if self.header_seen {
            bail!("duplicate DSRPROF2 header");
        }
        if record.required("profile")? != "native-wall" {
            bail!("DSRPROF2 header profile must be native-wall");
        }
        if record.required("raw_schema")? != V2_RAW_SCHEMA {
            bail!("unknown DSRPROF2 raw schema");
        }
        let os_build = record.required("os_build")?;
        validate_percent_token(os_build, "os_build")?;
        for field in [
            "program_sha256",
            "birth_qualification_sha256",
            "terminal_qualification_sha256",
        ] {
            validate_sha256(record.required(field)?, field)?;
        }
        if let Some(authority) = self.authority.as_ref() {
            for (field, expected) in [
                ("os_build", authority.os_build.as_str()),
                ("program_sha256", authority.program_sha256.as_str()),
                (
                    "birth_qualification_sha256",
                    authority.birth_qualification_sha256.as_str(),
                ),
                (
                    "terminal_qualification_sha256",
                    authority.terminal_qualification_sha256.as_str(),
                ),
            ] {
                let actual = record.required(field)?;
                if actual != expected {
                    bail!(
                        "DSRPROF2 header {field} does not match launch authority: actual={actual:?}, expected={expected:?}"
                    );
                }
            }
        }
        let wall_hz = record.decimal_u64("wall_hz")?;
        let cpu_hz = record.decimal_u64("cpu_hz")?;
        if wall_hz == 0 || cpu_hz == 0 {
            bail!("DSRPROF2 sampling frequencies must be positive");
        }
        self.wall_hz = Some(wall_hz);
        self.cpu_hz = Some(cpu_hz);
        self.header_seen = true;
        Ok(())
    }

    fn target_birth(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["epoch", "image", "pid", "start_sec", "start_usec"])?;
        if self.target.is_some() {
            bail!("duplicate DSRPROF2 target birth");
        }
        let key = record.image_key()?;
        if key.image_generation != 1 || key.runtime_epoch != 0 {
            bail!("target birth must begin at image=1, epoch=0");
        }
        self.admit_process(key)?;
        self.target = Some(key.birth);
        Ok(())
    }

    fn admit_process(&mut self, key: RawProcessImageKey) -> Result<()> {
        if self.processes.contains_key(&key.birth) {
            bail!("duplicate process birth key {key:?}");
        }
        if let Some(existing) = self.active_pids.get(&key.birth.pid) {
            bail!(
                "pid {} is already live under birth key {existing:?}",
                key.birth.pid
            );
        }
        if !self.known_keys.insert(key) {
            bail!("raw process-image key {key:?} was already admitted");
        }
        self.active_pids.insert(key.birth.pid, key.birth);
        self.processes.insert(
            key.birth,
            V2ProcessState {
                current: key,
                alive: true,
                exec_attempt: None,
                exit_reason: None,
            },
        );
        Ok(())
    }

    fn require_known_key(&self, key: RawProcessImageKey) -> Result<()> {
        if !self.known_keys.contains(&key) {
            bail!("record references unknown process-image key {key:?}");
        }
        Ok(())
    }

    fn require_current_key(&self, key: RawProcessImageKey) -> Result<()> {
        let process = self
            .processes
            .get(&key.birth)
            .ok_or_else(|| anyhow!("unknown process birth key {:?}", key.birth))?;
        if !process.alive {
            bail!("record references exited process birth key {:?}", key.birth);
        }
        if process.current != key {
            bail!(
                "record key {key:?} does not equal current key {:?}",
                process.current
            );
        }
        Ok(())
    }

    fn require_attribution_key(&self, key: RawProcessImageKey) -> Result<()> {
        self.require_current_key(key)?;
        if self.pending_inherit.contains_key(&key.birth) {
            bail!("child attribution appeared before fork inheritance");
        }
        let epoch = self
            .epochs
            .get(&key)
            .ok_or_else(|| anyhow!("process-image key {key:?} has no range reset"))?;
        if !epoch.is_ready() {
            bail!("process-image key {key:?} is not range-ready");
        }
        Ok(())
    }

    fn process_create(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "child_epoch",
            "child_image",
            "child_pid",
            "child_sec",
            "child_usec",
            "parent_epoch",
            "parent_image",
            "parent_pid",
            "parent_sec",
            "parent_usec",
        ])?;
        let parent = RawProcessImageKey {
            birth: record.birth("parent_pid", "parent_sec", "parent_usec")?,
            image_generation: record.decimal_u64("parent_image")?,
            runtime_epoch: record.decimal_u64("parent_epoch")?,
        };
        if parent.image_generation == 0 {
            bail!("process-create parent image must be positive");
        }
        self.require_attribution_key(parent)?;
        let child = RawProcessImageKey {
            birth: record.birth("child_pid", "child_sec", "child_usec")?,
            image_generation: record.decimal_u64("child_image")?,
            runtime_epoch: record.decimal_u64("child_epoch")?,
        };
        if child.image_generation != 1 || child.runtime_epoch != 0 {
            bail!("new child must begin at image=1, epoch=0");
        }
        if child.birth == parent.birth {
            bail!("process-create parent and child birth keys must differ");
        }
        self.admit_process(child)?;
        if self
            .pending_inherit
            .insert(child.birth, (parent, child))
            .is_some()
        {
            bail!("duplicate pending fork inheritance for child");
        }
        Ok(())
    }

    fn fork_inherit(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "child_pid",
            "child_sec",
            "child_usec",
            "mapping_frontier",
            "parent_epoch",
            "parent_image",
            "parent_pid",
            "parent_sec",
            "parent_usec",
            "range_frontier",
        ])?;
        let child_birth = record.birth("child_pid", "child_sec", "child_usec")?;
        let parent = RawProcessImageKey {
            birth: record.birth("parent_pid", "parent_sec", "parent_usec")?,
            image_generation: record.decimal_u64("parent_image")?,
            runtime_epoch: record.decimal_u64("parent_epoch")?,
        };
        if parent.image_generation == 0 {
            bail!("fork-inherit parent image must be positive");
        }
        self.require_current_key(parent)?;
        let (_, child) = self
            .pending_inherit
            .get(&child_birth)
            .copied()
            .ok_or_else(|| anyhow!("fork-inherit has no matching process-create"))?;
        let expected = self
            .pending_inherit
            .get(&child_birth)
            .copied()
            .ok_or_else(|| anyhow!("fork-inherit pending state disappeared"))?;
        if expected != (parent, child) {
            bail!("fork-inherit does not match its process-create relation");
        }
        if record.decimal_u64("mapping_frontier")? != 0 {
            bail!("M2 mapping_frontier must be zero");
        }
        let range_frontier = record.decimal_u64("range_frontier")?;
        let parent_epoch = self
            .epochs
            .get(&parent)
            .ok_or_else(|| anyhow!("fork parent has no translated-range catalog"))?;
        let parent_len = u64::try_from(parent_epoch.ranges.len())
            .context("fork parent range frontier exceeds u64")?;
        if range_frontier != parent_len || !parent_epoch.is_ready() {
            bail!(
                "fork range frontier {range_frontier} does not equal active parent frontier {parent_len}"
            );
        }
        let mut child_epoch = parent_epoch.clone();
        child_epoch.ranges.truncate(
            usize::try_from(range_frontier).context("fork range frontier exceeds usize")?,
        );
        child_epoch.ready_frontier = Some(range_frontier);
        child_epoch.replay_expected = None;
        if self.epochs.insert(child, child_epoch).is_some() {
            bail!("child inherited catalog already exists");
        }
        self.pending_inherit.remove(&child_birth);
        Ok(())
    }

    fn exec_attempt(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["epoch", "image", "pid", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        self.require_current_key(key)?;
        let existing = self
            .processes
            .get(&key.birth)
            .ok_or_else(|| anyhow!("exec process state disappeared"))?
            .exec_attempt;
        match existing {
            Some(open) if open == key => return Ok(()),
            Some(open) => {
                bail!("exec attempt {key:?} conflicts with open image {open:?}")
            }
            None => {}
        }
        self.require_attribution_key(key)?;
        // The runtime announces an attempt from inside the host `execve`
        // syscall. That exact kernel frame, plus unrelated frames on sibling
        // threads, may remain open until the attempt returns. Only a successful
        // exec retires the process image, so enforce a clean boundary there.
        let process = self
            .processes
            .get_mut(&key.birth)
            .ok_or_else(|| anyhow!("exec process state disappeared"))?;
        process.exec_attempt = Some(key);
        Ok(())
    }

    fn exec_failure(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["epoch", "image", "pid", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        self.require_current_key(key)?;
        let process = self
            .processes
            .get_mut(&key.birth)
            .ok_or_else(|| anyhow!("exec process state disappeared"))?;
        if process.exec_attempt != Some(key) {
            bail!("exec-failure does not match one open exec attempt");
        }
        process.exec_attempt = None;
        Ok(())
    }

    fn exec_success(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "new_epoch",
            "new_image",
            "pid",
            "retired_epoch",
            "retired_image",
            "start_sec",
            "start_usec",
        ])?;
        let birth = record.birth("pid", "start_sec", "start_usec")?;
        let retired = RawProcessImageKey {
            birth,
            image_generation: record.decimal_u64("retired_image")?,
            runtime_epoch: record.decimal_u64("retired_epoch")?,
        };
        if retired.image_generation == 0 {
            bail!("exec-success retired image must be positive");
        }
        self.require_current_key(retired)?;
        self.require_no_open_thread_state(birth, "exec success")?;
        let new_image = record.decimal_u64("new_image")?;
        let new_epoch = record.decimal_u64("new_epoch")?;
        if new_image
            != retired
                .image_generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("exec image generation overflow"))?
            || new_epoch != 0
        {
            bail!("exec-success must advance one image generation and reset epoch to zero");
        }
        let replacement = RawProcessImageKey {
            birth,
            image_generation: new_image,
            runtime_epoch: new_epoch,
        };
        if self.known_keys.contains(&replacement) {
            bail!("exec-success reuses retired process-image key {replacement:?}");
        }
        let process = self
            .processes
            .get_mut(&birth)
            .ok_or_else(|| anyhow!("exec process state disappeared"))?;
        if process.exec_attempt != Some(retired) {
            bail!("exec-success does not match one open exec attempt");
        }
        process.exec_attempt = None;
        process.current = replacement;
        self.known_keys.insert(replacement);
        Ok(())
    }

    fn range_reset(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["epoch", "image", "pid", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        let current = self
            .processes
            .get(&key.birth)
            .filter(|process| process.alive)
            .ok_or_else(|| anyhow!("range-reset references unknown or exited process"))?
            .current;
        if self.pending_inherit.contains_key(&key.birth) {
            bail!("range-reset appeared before fork inheritance");
        }
        if key == current {
            if self.epochs.contains_key(&key) {
                bail!("duplicate range-reset for process-image key {key:?}");
            }
            self.epochs.insert(
                key,
                V2EpochState {
                    reset_observed: true,
                    ..V2EpochState::default()
                },
            );
            return Ok(());
        }
        if key.birth != current.birth
            || key.image_generation != current.image_generation
            || key.runtime_epoch
                != current
                    .runtime_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("runtime epoch overflow"))?
        {
            bail!("range-reset does not name the current or next runtime epoch");
        }
        // Runtime repair can publish its replacement range catalog from
        // inside a host syscall. Exact kernel frames retain their old epoch
        // key until return, but an off-CPU episode cannot cross the epoch
        // because its wake observes the new key.
        self.require_no_open_offcpu_state(key.birth, "runtime epoch reset")?;
        let prior = self
            .epochs
            .get(&current)
            .filter(|epoch| epoch.is_ready())
            .ok_or_else(|| anyhow!("prior runtime epoch is not ready before reset"))?
            .clone();
        if self.epochs.contains_key(&key) || self.known_keys.contains(&key) {
            bail!("range-reset reuses a previously admitted runtime epoch");
        }
        self.epochs.insert(
            key,
            V2EpochState {
                reset_observed: true,
                replay_expected: Some(prior.ranges),
                ..V2EpochState::default()
            },
        );
        self.known_keys.insert(key);
        let process = self
            .processes
            .get_mut(&key.birth)
            .ok_or_else(|| anyhow!("range-reset process state disappeared"))?;
        process.current = key;
        Ok(())
    }

    fn range_add(&mut self, record: &V2Record, shared: bool) -> Result<()> {
        let expected = if shared {
            &[
                "end",
                "epoch",
                "image",
                "pid",
                "sequence",
                "start",
                "start_sec",
                "start_usec",
                "unit_id",
            ][..]
        } else {
            &[
                "end",
                "epoch",
                "image",
                "pid",
                "sequence",
                "start",
                "start_sec",
                "start_usec",
            ][..]
        };
        record.exact_fields(expected)?;
        let key = record.image_key()?;
        self.require_current_key(key)?;
        let sequence = record.decimal_u64("sequence")?;
        let start = record.address("start")?;
        let end = record.address("end")?;
        if start >= end || start % 4 != 0 || end % 4 != 0 {
            bail!("translated range must be nonempty and four-byte aligned");
        }
        let kind = if shared {
            let unit_id = record.decimal_u64("unit_id")?;
            if unit_id == 0 {
                bail!("shared translated unit id must be positive");
            }
            V2RangeKind::Shared { unit_id }
        } else {
            V2RangeKind::Private
        };
        let range = V2Range {
            sequence,
            start,
            end,
            kind,
        };
        let epoch = self
            .epochs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("range addition appeared before reset"))?;
        let expected_sequence = u64::try_from(epoch.ranges.len())
            .context("translated range count exceeds u64")?
            .checked_add(1)
            .ok_or_else(|| anyhow!("translated range sequence overflow"))?;
        if sequence != expected_sequence {
            bail!(
                "translated range sequence {sequence} is not contiguous; expected {expected_sequence}"
            );
        }
        if (!shared && sequence != 1) || (shared && sequence == 1) {
            bail!("private range must be sequence one and shared ranges must follow it");
        }
        if epoch
            .ranges
            .iter()
            .any(|existing| range.start < existing.end && existing.start < range.end)
        {
            bail!("translated range overlaps an existing catalog range");
        }
        if let V2RangeKind::Shared { unit_id } = range.kind
            && epoch.ranges.iter().any(|existing| {
                matches!(existing.kind, V2RangeKind::Shared { unit_id: old } if old == unit_id)
            })
        {
            bail!("shared translated unit id {unit_id} is duplicated");
        }
        if let Some(replay) = epoch.replay_expected.as_ref() {
            let index = epoch.ranges.len();
            let expected_range = replay
                .get(index)
                .ok_or_else(|| anyhow!("runtime replay added beyond its inherited frontier"))?;
            if expected_range != &range {
                bail!("runtime replay differs from the inherited translated catalog");
            }
        }
        epoch.ranges.push(range);
        Ok(())
    }

    fn range_ready(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "epoch",
            "final_sequence",
            "image",
            "pid",
            "start_sec",
            "start_usec",
        ])?;
        let key = record.image_key()?;
        self.require_current_key(key)?;
        let final_sequence = record.decimal_u64("final_sequence")?;
        let epoch = self
            .epochs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("range-ready appeared before reset"))?;
        let actual =
            u64::try_from(epoch.ranges.len()).context("translated range count exceeds u64")?;
        if final_sequence == 0 || final_sequence != actual {
            bail!("range-ready frontier {final_sequence} does not match catalog frontier {actual}");
        }
        if let Some(initial) = epoch.ready_frontier {
            bail!(
                "duplicate range-ready frontier {final_sequence} after initial activation {initial}"
            );
        }
        if let Some(expected) = epoch.replay_expected.as_ref()
            && expected != &epoch.ranges
        {
            bail!("range-ready closed an incomplete runtime replay");
        }
        epoch.replay_expected = None;
        epoch.ready_frontier = Some(final_sequence);
        Ok(())
    }

    fn require_summary_key(&self, key: RawProcessImageKey) -> Result<()> {
        self.require_known_key(key)?;
        let epoch = self
            .epochs
            .get(&key)
            .ok_or_else(|| anyhow!("summary references key without a translated catalog"))?;
        if !epoch.is_ready() {
            bail!("summary references non-ready process-image key {key:?}");
        }
        Ok(())
    }

    fn host_image_base(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["base", "epoch", "image", "pid", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        self.require_attribution_key(key)?;
        let base = record.address("base")?;
        if base == 0 {
            bail!("host image base must be nonzero");
        }
        let epoch = self
            .epochs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("host image epoch disappeared"))?;
        if epoch.host_image_base.replace(base).is_some() {
            bail!("duplicate host image base for process-image key {key:?}");
        }
        Ok(())
    }

    fn host_image_catalog(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "catalog_pid",
            "epoch",
            "image",
            "payload",
            "pid",
            "start_sec",
            "start_usec",
        ])?;
        let key = record.image_key()?;
        self.require_attribution_key(key)?;
        let payload: HostImageCatalogEnvelope =
            serde_json::from_str(record.required("payload")?)
                .context("invalid DSRPROF2 host image catalog JSON")?;
        let payload = match payload {
            HostImageCatalogEnvelope::Ok { ok } => ok,
            HostImageCatalogEnvelope::Err { err } => {
                bail!("DSRPROF2 host image catalog probe failed: {err}")
            }
        };
        let catalog_pid = record.decimal_u32("catalog_pid")?;
        if payload.pid != u64::from(catalog_pid) {
            bail!(
                "DSRPROF2 host image catalog pid {} does not match canonical catalog pid {}",
                payload.pid,
                catalog_pid
            );
        }
        if payload.ranges.is_empty() {
            bail!("host image catalog has no ranges");
        }
        let mut prior_end = None;
        for range in &payload.ranges {
            if range.start >= range.end || range.path.is_empty() {
                bail!("host image catalog contains an invalid range");
            }
            if prior_end.is_some_and(|end| range.start < end) {
                bail!("host image catalog ranges overlap or are unsorted");
            }
            prior_end = Some(range.end);
        }
        let epoch = self
            .epochs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("host image epoch disappeared"))?;
        if epoch.host_image_catalog.replace(payload.ranges).is_some() {
            bail!("duplicate host image catalog for process-image key {key:?}");
        }
        Ok(())
    }

    fn guest_image_base(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["base", "epoch", "image", "pid", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        self.require_attribution_key(key)?;
        let base = record.address("base")?;
        if base == 0 {
            bail!("guest image base must be nonzero");
        }
        let epoch = self
            .epochs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("guest image epoch disappeared"))?;
        if epoch.guest_image_base.replace(base).is_some() {
            bail!("duplicate guest image base for process-image key {key:?}");
        }
        Ok(())
    }

    fn cpu_user(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "count",
            "epoch",
            "image",
            "pc",
            "pid",
            "start_sec",
            "start_usec",
        ])?;
        let key = record.image_key()?;
        self.require_summary_key(key)?;
        let pc = record.address("pc")?;
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("cpu-user count must be positive");
        }
        if self.cpu_user_summary.insert((key, pc), count).is_some() {
            bail!("duplicate cpu-user summary identity");
        }
        self.cpu_samples = self
            .cpu_samples
            .checked_add(count)
            .ok_or_else(|| anyhow!("CPU sample population overflow"))?;
        Ok(())
    }

    fn cpu_kernel(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "class",
            "count",
            "epoch",
            "image",
            "pc",
            "pid",
            "start_sec",
            "start_usec",
        ])?;
        let key = record.image_key()?;
        self.require_summary_key(key)?;
        let pc = record.address("pc")?;
        let class = record.required("class")?.to_owned();
        match class.as_str() {
            "kernel-named-syscall" | "kernel-mach-trap" | "kernel-non-syscall" => {}
            other => bail!("unknown cpu-kernel class {other:?}"),
        }
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("cpu-kernel count must be positive");
        }
        if self
            .cpu_kernel_summary
            .insert((key, class, pc), count)
            .is_some()
        {
            bail!("duplicate cpu-kernel summary identity");
        }
        self.cpu_samples = self
            .cpu_samples
            .checked_add(count)
            .ok_or_else(|| anyhow!("CPU sample population overflow"))?;
        Ok(())
    }

    fn require_no_open_kernel_state(&self, birth: ProcessBirthKey, boundary: &str) -> Result<()> {
        if self
            .kernel_stacks
            .iter()
            .any(|((owner, _), stack)| *owner == birth && !stack.is_empty())
        {
            bail!("{boundary} crossed an open kernel transition stack");
        }
        Ok(())
    }

    fn require_no_open_offcpu_state(&self, birth: ProcessBirthKey, boundary: &str) -> Result<()> {
        if self.offcpu_open.keys().any(|(owner, _)| *owner == birth) {
            bail!("{boundary} crossed an open off-CPU episode");
        }
        Ok(())
    }

    fn require_no_open_thread_state(&self, birth: ProcessBirthKey, boundary: &str) -> Result<()> {
        self.require_no_open_kernel_state(birth, boundary)?;
        self.require_no_open_offcpu_state(birth, boundary)
    }

    fn kernel_transition(&mut self, record: &V2Record, transition: KernelTransition) -> Result<()> {
        let expected = match transition {
            KernelTransition::Enter | KernelTransition::Return => &[
                "class",
                "epoch",
                "function",
                "image",
                "pid",
                "provider",
                "start_sec",
                "start_usec",
                "tid",
                "timestamp_ns",
            ][..],
            KernelTransition::TerminalClose => &[
                "class",
                "epoch",
                "function",
                "image",
                "pid",
                "provider",
                "scope",
                "start_sec",
                "start_usec",
                "tid",
                "timestamp_ns",
            ][..],
        };
        record.exact_fields(expected)?;
        let key = record.image_key()?;
        match transition {
            KernelTransition::Enter => self.require_attribution_key(key)?,
            KernelTransition::Return | KernelTransition::TerminalClose => {
                // A frame opened before `proc:::exec` can close while image
                // attribution is disarmed, and runtime repair can advance the
                // epoch before the containing syscall returns. Its exact
                // stack entry remains the authority, so the key must remain
                // known rather than current.
                self.require_known_key(key)?;
            }
        }
        let tid = record.decimal_u64("tid")?;
        if tid == 0 {
            bail!("kernel transition tid must be positive");
        }
        let provider = record.required("provider")?.to_owned();
        let function = record.required("function")?.to_owned();
        let class = record.required("class")?.to_owned();
        validate_percent_token(&function, "kernel function")?;
        match (provider.as_str(), class.as_str()) {
            ("syscall", "named-syscall") | ("mach_trap", "mach-trap") => {}
            _ => bail!("kernel provider/class contract is invalid"),
        }
        let timestamp_ns = record.decimal_u64("timestamp_ns")?;
        let stack_key = (key.birth, tid);
        match transition {
            KernelTransition::Enter => {
                self.kernel_stacks
                    .entry(stack_key)
                    .or_default()
                    .push(V2KernelFrame {
                        key,
                        provider,
                        function,
                        class,
                        timestamp_ns,
                    });
            }
            KernelTransition::Return | KernelTransition::TerminalClose => {
                let terminal_scope = if matches!(transition, KernelTransition::TerminalClose) {
                    let scope = record.required("scope")?;
                    match scope {
                        "thread" | "process" => {}
                        other => bail!("unknown terminal-close scope {other:?}"),
                    }
                    if !self.terminal_qualifications.contains(&(
                        provider.clone(),
                        function.clone(),
                        scope.to_owned(),
                    )) {
                        bail!("kernel terminal-close is absent from launch qualification");
                    }
                    Some(scope)
                } else {
                    None
                };
                let stack = self
                    .kernel_stacks
                    .get_mut(&stack_key)
                    .ok_or_else(|| anyhow!("kernel close has no matching entry stack"))?;
                let top = stack
                    .last()
                    .ok_or_else(|| anyhow!("kernel close has no matching entry"))?;
                if top.key != key
                    || top.provider != provider
                    || top.function != function
                    || top.class != class
                {
                    bail!("kernel close does not match the exact top entry");
                }
                if timestamp_ns < top.timestamp_ns {
                    bail!("kernel close timestamp precedes its entry");
                }
                stack.pop();
                if stack.is_empty() {
                    self.kernel_stacks.remove(&stack_key);
                }
                match terminal_scope {
                    Some("thread") => {
                        // A qualified non-returning thread syscall is the last
                        // observable event for this TID. Any lower kernel frame
                        // or sleeping episode is right-censored by thread death.
                        self.kernel_stacks.remove(&stack_key);
                        self.offcpu_open.remove(&stack_key);
                    }
                    Some("process") => {
                        // Darwin reports the exiting caller, not every sibling
                        // it terminates. Process scope is therefore the explicit
                        // authority to retire all right-censored sibling state.
                        self.kernel_stacks
                            .retain(|(birth, _), _| *birth != key.birth);
                        self.offcpu_open.retain(|(birth, _), _| *birth != key.birth);
                    }
                    None => {}
                    Some(_) => unreachable!("terminal scope was validated above"),
                }
            }
        }
        Ok(())
    }

    fn offcpu_block(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "episode",
            "epoch",
            "image",
            "kind",
            "pc",
            "pid",
            "start_sec",
            "start_usec",
            "tid",
            "timestamp_ns",
        ])?;
        let key = record.image_key()?;
        self.require_attribution_key(key)?;
        let tid = record.decimal_u64("tid")?;
        let episode = record.decimal_u64("episode")?;
        if tid == 0 || episode == 0 {
            bail!("off-CPU tid and episode must be positive");
        }
        let thread_key = (key.birth, tid);
        if self.offcpu_open.contains_key(&thread_key) {
            bail!("duplicate off-CPU block for one thread");
        }
        let expected_episode = self
            .offcpu_last_episode
            .get(&thread_key)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("off-CPU episode overflow"))?;
        if episode != expected_episode {
            bail!("off-CPU episode {episode} is not contiguous; expected {expected_episode}");
        }
        let kind = record.required("kind")?.to_owned();
        validate_percent_token(&kind, "off-CPU kind")?;
        let episode_state = V2OffcpuEpisode {
            key,
            episode,
            kind,
            pc: record.address("pc")?,
            timestamp_ns: record.decimal_u64("timestamp_ns")?,
        };
        self.offcpu_open.insert(thread_key, episode_state);
        self.offcpu_last_episode.insert(thread_key, episode);
        Ok(())
    }

    fn offcpu_wake(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "episode",
            "epoch",
            "image",
            "observed_epoch",
            "observed_image",
            "observed_pid",
            "observed_sec",
            "observed_usec",
            "pid",
            "start_sec",
            "start_usec",
            "tid",
            "timestamp_ns",
        ])?;
        let key = record.image_key()?;
        // `sched:::on-cpu` closes episodes that began before `proc:::exec`
        // even while new attribution is disarmed. The latched open episode
        // supplies the exact image authority; it must still be current.
        self.require_current_key(key)?;
        let observed = RawProcessImageKey {
            birth: record.birth("observed_pid", "observed_sec", "observed_usec")?,
            image_generation: record.decimal_u64("observed_image")?,
            runtime_epoch: record.decimal_u64("observed_epoch")?,
        };
        if observed.image_generation == 0 || observed != key {
            bail!("off-CPU wake observed a different process-image key");
        }
        let tid = record.decimal_u64("tid")?;
        let episode = record.decimal_u64("episode")?;
        let thread_key = (key.birth, tid);
        let open = self
            .offcpu_open
            .remove(&thread_key)
            .ok_or_else(|| anyhow!("off-CPU wake has no matching block"))?;
        if open.key != key || open.episode != episode {
            bail!("off-CPU wake does not match the latched episode identity");
        }
        let timestamp_ns = record.decimal_u64("timestamp_ns")?;
        let duration = timestamp_ns
            .checked_sub(open.timestamp_ns)
            .ok_or_else(|| anyhow!("off-CPU wake timestamp precedes block"))?;
        let aggregate = self
            .offcpu_closed
            .entry((key, open.kind, open.pc))
            .or_default();
        aggregate.0 = aggregate
            .0
            .checked_add(1)
            .ok_or_else(|| anyhow!("off-CPU episode count overflow"))?;
        aggregate.1 = aggregate
            .1
            .checked_add(duration)
            .ok_or_else(|| anyhow!("off-CPU duration overflow"))?;
        Ok(())
    }

    fn offcpu_summary(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "count",
            "epoch",
            "image",
            "kind",
            "pc",
            "pid",
            "start_sec",
            "start_usec",
            "total_ns",
        ])?;
        let key = record.image_key()?;
        self.require_summary_key(key)?;
        let kind = record.required("kind")?.to_owned();
        validate_percent_token(&kind, "off-CPU kind")?;
        let pc = record.address("pc")?;
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("off-CPU summary count must be positive");
        }
        let value = (count, record.decimal_u64("total_ns")?);
        if self.offcpu_summary.insert((key, kind, pc), value).is_some() {
            bail!("duplicate off-CPU summary identity");
        }
        Ok(())
    }

    fn process_exit(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["epoch", "image", "pid", "reason", "start_sec", "start_usec"])?;
        let key = record.image_key()?;
        self.require_current_key(key)?;
        if self.pending_inherit.contains_key(&key.birth) {
            bail!("process exited before fork inheritance completed");
        }
        self.require_no_open_thread_state(key.birth, "process exit")?;
        self.require_all_birth_epochs_ready(key.birth)?;
        let reason = record.decimal_u64("reason")?;
        if reason != 1 {
            bail!("gating DSRPROF2 process exit must be natural (reason=1)");
        }
        let process = self
            .processes
            .get_mut(&key.birth)
            .ok_or_else(|| anyhow!("exit process state disappeared"))?;
        // Darwin does not guarantee `proc:::exec-failure` for every failed
        // attempt. An observation that never reaches exec-success belongs to
        // the retiring image and ends with the process.
        process.exec_attempt = None;
        process.alive = false;
        process.exit_reason = Some(reason);
        match self.active_pids.remove(&key.birth.pid) {
            Some(active) if active == key.birth => {}
            _ => bail!("active PID identity disappeared at process exit"),
        }
        Ok(())
    }

    fn require_all_birth_epochs_ready(&self, birth: ProcessBirthKey) -> Result<()> {
        let mut found = false;
        for (key, epoch) in &self.epochs {
            if key.birth == birth {
                found = true;
                if !epoch.is_ready() {
                    bail!("process birth {birth:?} has a non-ready DSR epoch {key:?}");
                }
            }
        }
        if !found {
            bail!("process birth {birth:?} has no translated-range epoch");
        }
        Ok(())
    }

    fn wall_state(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&["count", "kind"])?;
        let kind = record.required("kind")?.to_owned();
        validate_percent_token(&kind, "wall-state kind")?;
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("wall-state count must be positive");
        }
        if self.wall_state.insert(kind, count).is_some() {
            bail!("duplicate wall-state bucket");
        }
        Ok(())
    }

    fn completion(&mut self, record: &V2Record) -> Result<()> {
        record.exact_fields(&[
            "bounded",
            "elapsed_ns",
            "identity_violations",
            "kernel_violations",
            "lifecycle_violations",
            "live_at_end",
            "offcpu_violations",
            "probe_errors",
            "profile",
            "range_violations",
            "target_exit_reason",
            "timed_out",
        ])?;
        if record.required("profile")? != "native-wall" {
            bail!("DSRPROF2 completion profile must be native-wall");
        }
        let elapsed_ns = record.decimal_u64("elapsed_ns")?;
        if elapsed_ns == 0 {
            bail!("DSRPROF2 completion elapsed_ns must be positive");
        }

        let bounded = record.decimal_u64("bounded")?;
        if bounded > 1 {
            bail!("DSRPROF2 completion bounded field must be 0 or 1");
        }
        let timed_out = record.decimal_u64("timed_out")?;
        if timed_out > 1 {
            bail!("DSRPROF2 completion timed_out field must be 0 or 1");
        }
        let probe_errors = record.decimal_u64("probe_errors")?;
        if probe_errors != self.dtrace_errors {
            bail!(
                "DSRPROF2 completion probe_errors={probe_errors} disagrees with {} DSRERROR2 records",
                self.dtrace_errors
            );
        }
        let violations = [
            (
                "identity_violations",
                record.decimal_u64("identity_violations")?,
            ),
            (
                "lifecycle_violations",
                record.decimal_u64("lifecycle_violations")?,
            ),
            ("range_violations", record.decimal_u64("range_violations")?),
            (
                "kernel_violations",
                record.decimal_u64("kernel_violations")?,
            ),
            (
                "offcpu_violations",
                record.decimal_u64("offcpu_violations")?,
            ),
            ("probe_errors", probe_errors),
        ];
        let expected_bounded = timed_out != 0 || violations.iter().any(|(_, count)| *count != 0);
        if bounded != u64::from(expected_bounded) {
            bail!(
                "DSRPROF2 completion bounded={bounded} disagrees with timeout and integrity counters"
            );
        }
        if timed_out != 0 {
            bail!("gating DSRPROF2 capture timed out");
        }
        if let Some((name, count)) = violations.into_iter().find(|(_, count)| *count != 0) {
            bail!("gating DSRPROF2 capture reports {name}={count}");
        }
        if record.decimal_u64("live_at_end")? != 0 {
            bail!("DSRPROF2 completion reports live processes");
        }
        let target_exit_reason = record.decimal_u64("target_exit_reason")?;
        if target_exit_reason != 1 {
            bail!("DSRPROF2 target did not exit naturally");
        }
        let target = self
            .target
            .ok_or_else(|| anyhow!("DSRPROF2 stream has no target birth"))?;
        let target_state = self
            .processes
            .get(&target)
            .ok_or_else(|| anyhow!("DSRPROF2 target process state disappeared"))?;
        if target_state.alive || target_state.exit_reason != Some(target_exit_reason) {
            bail!("target completion does not match its process-exit record");
        }
        if self.processes.values().any(|process| process.alive) || !self.active_pids.is_empty() {
            bail!("DSRPROF2 completed with live process state");
        }
        if self
            .processes
            .values()
            .any(|process| process.exec_attempt.is_some())
        {
            bail!("DSRPROF2 completed with an open exec attempt");
        }
        if !self.pending_inherit.is_empty() {
            bail!("DSRPROF2 completed with pending fork inheritance");
        }
        if self.kernel_stacks.values().any(|stack| !stack.is_empty()) {
            bail!("DSRPROF2 completed with an open kernel transition stack");
        }
        if !self.offcpu_open.is_empty() {
            bail!("DSRPROF2 completed with an open off-CPU episode");
        }
        if self.transition_events_seen && self.offcpu_closed != self.offcpu_summary {
            bail!("off-CPU transition and aggregate populations disagree");
        }
        for birth in self.processes.keys().copied() {
            self.require_all_birth_epochs_ready(birth)?;
        }
        if self.wall_state.is_empty() {
            bail!("DSRPROF2 stream has no wall-state population");
        }
        if self.cpu_samples == 0 {
            bail!("DSRPROF2 stream has no resolved CPU samples");
        }
        for stack in &self.stacks {
            self.require_summary_key(stack.key)?;
            if stack.kind.is_empty() || stack.count == 0 || stack.frames.is_empty() {
                bail!("DSRSTACK2 summary is empty");
            }
            let _ = stack.total_ns;
        }
        let _presentation_instances = self.presentation_instances()?;
        self.elapsed_ns = Some(elapsed_ns);
        self.complete = true;
        Ok(())
    }

    fn presentation_instances(&self) -> Result<BTreeMap<ProcessBirthKey, u64>> {
        let target = self
            .target
            .ok_or_else(|| anyhow!("cannot assign identities without target birth"))?;
        let mut children = self
            .processes
            .keys()
            .copied()
            .filter(|birth| *birth != target)
            .collect::<Vec<_>>();
        children.sort_by_key(|birth| (birth.start_sec, birth.start_usec, birth.pid));
        let mut instances = BTreeMap::new();
        instances.insert(target, 1);
        for (index, birth) in children.into_iter().enumerate() {
            let instance = u64::try_from(index)
                .context("process instance index exceeds u64")?
                .checked_add(2)
                .ok_or_else(|| anyhow!("process instance identity overflow"))?;
            instances.insert(birth, instance);
        }
        Ok(instances)
    }

    fn into_profile_summary(self, capture_status: ProfileCaptureStatus) -> Result<ProfileSummary> {
        build_v2_profile_summary(self, capture_status)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordType {
    Count,
    Total,
    Minimum,
    Maximum,
    Sample,
    Incomplete,
    HighWater,
    Complete,
}

impl RecordType {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "count" => Ok(Self::Count),
            "total" => Ok(Self::Total),
            "minimum" => Ok(Self::Minimum),
            "maximum" => Ok(Self::Maximum),
            "sample" => Ok(Self::Sample),
            "incomplete" => Ok(Self::Incomplete),
            "high-water" => Ok(Self::HighWater),
            "complete" => Ok(Self::Complete),
            other => bail!("unknown {PROTOCOL_PREFIX} record type {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TraceProfileKind {
    Dsr,
    DsrIndirect,
    DsrFork,
    NativeFault,
    NativeWall,
}

impl TraceProfileKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dsr => "dsr",
            Self::DsrIndirect => "dsr-indirect",
            Self::DsrFork => "dsr-fork",
            Self::NativeFault => "native-fault",
            Self::NativeWall => "native-wall",
        }
    }

    pub(crate) const fn requires_runtime_profile(self) -> bool {
        matches!(self, Self::Dsr | Self::DsrFork | Self::NativeWall)
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) fn bundled_script(self) -> &'static str {
        match self {
            Self::Dsr => carrick_runtime::dtrace_consumer::BUNDLED_DSR_PROFILE_D,
            Self::DsrIndirect => carrick_runtime::dtrace_consumer::BUNDLED_DSR_INDIRECT_D,
            Self::DsrFork => carrick_runtime::dtrace_consumer::BUNDLED_DSR_FORK_D,
            Self::NativeFault => carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_FAULT_D,
            Self::NativeWall => carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_WALL_D,
        }
    }

    fn parse_protocol(value: &str) -> Result<Self> {
        match value {
            "dsr" => Ok(Self::Dsr),
            "dsr-indirect" => Ok(Self::DsrIndirect),
            "dsr-fork" => Ok(Self::DsrFork),
            "native-fault" => Ok(Self::NativeFault),
            "native-wall" => Ok(Self::NativeWall),
            other => bail!("unknown DSR profile {other:?}"),
        }
    }
}

#[derive(Debug)]
struct ProfileRecord {
    record_type: RecordType,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StackTraceValue {
    Count(u64),
    DurationNs(u64),
}

#[derive(Debug)]
struct StackTraceRecord {
    state: String,
    pid: Option<u64>,
    value: StackTraceValue,
    frames: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostImageRangeRecord {
    start: u64,
    end: u64,
    path: String,
}

#[derive(Debug, Deserialize)]
struct HostImageCatalogRecord {
    pid: u64,
    ranges: Vec<HostImageRangeRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HostImageCatalogEnvelope {
    Ok { ok: HostImageCatalogRecord },
    Err { err: String },
}

impl HostImageCatalogRecord {
    fn parse(line: &str) -> Result<Self> {
        let payload = line
            .strip_prefix("NWIMAGES1|")
            .ok_or_else(|| anyhow!("invalid native-wall image catalog prefix"))?;
        let envelope: HostImageCatalogEnvelope =
            serde_json::from_str(payload).context("invalid image catalog JSON")?;
        let catalog = match envelope {
            HostImageCatalogEnvelope::Ok { ok } => ok,
            HostImageCatalogEnvelope::Err { err } => {
                bail!("image catalog probe serialization failed: {err}")
            }
        };
        if catalog.ranges.is_empty() {
            bail!("image catalog for pid {} has no ranges", catalog.pid);
        }
        for range in &catalog.ranges {
            if range.start >= range.end {
                bail!(
                    "image catalog for pid {} has invalid range {:#x}..{:#x}",
                    catalog.pid,
                    range.start,
                    range.end
                );
            }
        }
        Ok(catalog)
    }
}

impl StackTraceRecord {
    fn begin(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some("NWSTACK1") || parts.next() != Some("begin") {
            bail!("invalid native-wall stack header");
        }
        let mut fields = BTreeMap::new();
        for raw_field in parts {
            let (key, value) = raw_field
                .split_once('=')
                .ok_or_else(|| anyhow!("stack field lacks '=': {raw_field:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("stack field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate stack field {key:?}"),
            }
        }
        let required = |key: &str| {
            fields
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| anyhow!("stack record is missing {key:?}"))
        };
        let state = required("state")?.to_owned();
        let (pid, value) = match state.as_str() {
            "kernel-oncpu" if fields.keys().map(String::as_str).eq(["state", "value"]) => (
                None,
                StackTraceValue::Count(
                    parse_u64(required("value")?).context("invalid stack count")?,
                ),
            ),
            "voluntary"
                if fields
                    .keys()
                    .map(String::as_str)
                    .eq(["pid", "state", "value_ns"]) =>
            {
                (
                    Some(parse_u64(required("pid")?).context("invalid stack pid")?),
                    StackTraceValue::DurationNs(
                        parse_u64(required("value_ns")?).context("invalid stack duration")?,
                    ),
                )
            }
            _ => bail!("stack record has an invalid state/field/value contract"),
        };
        if pid == Some(0) {
            bail!("stack pid must be positive");
        }
        match value {
            StackTraceValue::Count(0) => bail!("stack count must be positive"),
            StackTraceValue::DurationNs(0) => bail!("stack duration must be positive"),
            StackTraceValue::Count(_) | StackTraceValue::DurationNs(_) => {}
        }
        Ok(Self {
            state,
            pid,
            value,
            frames: Vec::new(),
        })
    }
}

impl ProfileRecord {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        let prefix = parts
            .next()
            .ok_or_else(|| anyhow!("empty profile record"))?;
        if prefix != PROTOCOL_PREFIX {
            bail!("unknown profile protocol prefix {prefix:?}");
        }
        let record_type = RecordType::parse(
            parts
                .next()
                .ok_or_else(|| anyhow!("truncated {PROTOCOL_PREFIX} record"))?,
        )?;
        let mut fields = BTreeMap::new();
        for raw_field in parts {
            let (key, value) = raw_field
                .split_once('=')
                .ok_or_else(|| anyhow!("profile field lacks '=': {raw_field:?}"))?;
            if key.is_empty() {
                bail!("profile field has an empty key");
            }
            if value.is_empty() {
                bail!("profile field {key:?} has an empty value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate profile field {key:?}"),
            }
        }

        let record = Self {
            record_type,
            fields,
        };
        record.validate_integer_fields()?;
        Ok(record)
    }

    fn validate_integer_fields(&self) -> Result<()> {
        for key in [
            "pid",
            "tid",
            "source_pc",
            "target_pc",
            "duration_ns",
            "interval",
            "value",
            "value_ns",
            "used",
            "capacity",
            "bounded",
        ] {
            if let Some(value) = self.fields.get(key) {
                parse_u64(value).with_context(|| format!("invalid integer field {key:?}"))?;
            }
        }
        Ok(())
    }

    fn required(&self, key: &str) -> Result<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("profile record is missing required field {key:?}"))
    }

    fn required_u64(&self, key: &str) -> Result<u64> {
        parse_u64(self.required(key)?)
            .with_context(|| format!("invalid required integer field {key:?}"))
    }

    fn optional_u64(&self, key: &str) -> Result<Option<u64>> {
        self.fields
            .get(key)
            .map(|value| parse_u64(value))
            .transpose()
            .with_context(|| format!("invalid optional integer field {key:?}"))
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hexadecimal integer {value:?}"))
    } else {
        value
            .parse::<u64>()
            .with_context(|| format!("invalid decimal integer {value:?}"))
    }
}

#[cfg(target_os = "macos")]
fn raw_kernel_address(frame: &str) -> Result<u64> {
    let digits = frame
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .ok_or_else(|| anyhow!("kernel stack frame {frame:?} is not raw hexadecimal"))?;
    if !digits.bytes().all(|value| value.is_ascii_hexdigit()) {
        bail!("kernel stack frame {frame:?} is not raw hexadecimal");
    }
    u64::from_str_radix(digits, 16)
        .with_context(|| format!("kernel stack frame {frame:?} is outside u64"))
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct KernelSampleAddresses {
    pub(crate) requested: Vec<u64>,
    pub(crate) weighted_leaves: BTreeSet<u64>,
}

#[cfg(target_os = "macos")]
pub(crate) fn kernel_sample_addresses_from_path(
    path: &Path,
    v2_authority: Option<&V2ProfileAuthority>,
    capture_status: ProfileCaptureStatus,
) -> Result<KernelSampleAddresses> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read native-wall raw stream {}", path.display()))?;
    if contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.starts_with("DSRPROF2|header|"))
    {
        let authority = v2_authority
            .cloned()
            .ok_or_else(|| anyhow!("DSRPROF2 kernel symbol lookup has no launch authority"))?;
        validate_v2_lines_with_validator(
            contents.lines(),
            capture_status,
            V2Validator::with_authority(authority),
        )
        .context("validate authoritative DSRPROF2 stream before kernel symbol lookup")?;
        return kernel_sample_addresses_from_v2_lines(contents.lines());
    }
    let summary = ProfileSummary::from_lines(contents.lines(), capture_status)
        .context("validate native-wall raw stream before kernel symbol lookup")?;
    summary.require_profile(TraceProfileKind::NativeWall)?;
    kernel_sample_addresses_from_lines(contents.lines())
}

#[cfg(target_os = "macos")]
fn kernel_sample_addresses_from_v2_lines<I, S>(lines: I) -> Result<KernelSampleAddresses>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut addresses = BTreeSet::new();
    let mut kernel_pc_leaves = BTreeMap::<u64, u64>::new();
    let mut kernel_stack_leaves = BTreeMap::<u64, u64>::new();
    let mut open_stack = None::<(String, u64, Vec<String>, bool)>;

    for (index, raw_line) in lines.into_iter().enumerate() {
        let line = raw_line.as_ref().trim();
        if let Some((_, _, frames, leading_separator_seen)) = open_stack.as_mut() {
            if line == "DSRSTACK2|end" {
                let (kind, count, frames, _) = open_stack
                    .take()
                    .ok_or_else(|| anyhow!("DSRSTACK2 extraction state disappeared"))?;
                if frames.is_empty() {
                    bail!("DSRSTACK2 block at line {} has no frames", index + 1);
                }
                if matches!(
                    kind.as_str(),
                    "kernel-named-syscall" | "kernel-mach-trap" | "kernel-non-syscall"
                ) {
                    let leaf = raw_kernel_address(
                        frames
                            .first()
                            .ok_or_else(|| anyhow!("DSRSTACK2 kernel stack lost its leaf"))?,
                    )?;
                    let population = kernel_stack_leaves.entry(leaf).or_default();
                    *population = population
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("DSRPROF2 kernel stack leaf population overflow"))?;
                    for frame in frames {
                        addresses.insert(raw_kernel_address(&frame)?);
                    }
                } else if !kind.starts_with("offcpu-") {
                    bail!("unknown DSRSTACK2 attribution kind {kind:?}");
                }
            } else if line.is_empty() {
                if frames.is_empty() && !*leading_separator_seen {
                    *leading_separator_seen = true;
                    continue;
                }
                bail!("empty DSRSTACK2 frame at line {}", index + 1);
            } else if line.starts_with("DSRPROF") || line.starts_with("DSRSTACK") {
                bail!(
                    "profile marker interrupted DSRSTACK2 block at line {}",
                    index + 1
                );
            } else {
                frames.push(line.to_owned());
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }
        if line.starts_with("DSRSTACK2|") {
            let record = V2Record::parse(line, V2_STACK_PREFIX)
                .with_context(|| format!("invalid DSRSTACK2 record at line {}", index + 1))?;
            if record.tag != "begin" {
                bail!("DSRSTACK2 end without begin at line {}", index + 1);
            }
            record.exact_fields(&[
                "count",
                "epoch",
                "image",
                "kind",
                "pid",
                "start_sec",
                "start_usec",
                "total_ns",
            ])?;
            let _key = record.image_key()?;
            let kind = record.required("kind")?.to_owned();
            validate_percent_token(&kind, "stack kind")?;
            let count = record.decimal_u64("count")?;
            if count == 0 {
                bail!("DSRSTACK2 count must be positive");
            }
            let _total_ns = record.decimal_u64("total_ns")?;
            open_stack = Some((kind, count, Vec::new(), false));
            continue;
        }
        if !line.starts_with("DSRPROF2|") {
            bail!("unknown DSRPROF2 extraction line {}: {line:?}", index + 1);
        }
        let record = V2Record::parse(line, V2_PROTOCOL_PREFIX)
            .with_context(|| format!("invalid DSRPROF2 record at line {}", index + 1))?;
        if record.tag != "cpu-kernel" {
            continue;
        }
        record.exact_fields(&[
            "class",
            "count",
            "epoch",
            "image",
            "pc",
            "pid",
            "start_sec",
            "start_usec",
        ])?;
        let _key = record.image_key()?;
        match record.required("class")? {
            "kernel-named-syscall" | "kernel-mach-trap" | "kernel-non-syscall" => {}
            other => bail!("unknown cpu-kernel class {other:?}"),
        }
        let leaf = record.address("pc")?;
        let count = record.decimal_u64("count")?;
        if count == 0 {
            bail!("cpu-kernel count must be positive");
        }
        addresses.insert(leaf);
        let population = kernel_pc_leaves.entry(leaf).or_default();
        *population = population
            .checked_add(count)
            .ok_or_else(|| anyhow!("DSRPROF2 kernel PC population overflow"))?;
    }

    if open_stack.is_some() {
        bail!("DSRPROF2 stream ended inside a DSRSTACK2 block");
    }
    if addresses.is_empty() {
        bail!("DSRPROF2 stream has no raw kernel stack addresses");
    }
    if kernel_pc_leaves != kernel_stack_leaves {
        bail!("DSRPROF2 kernel PC and exact stack leaf populations differ");
    }
    Ok(KernelSampleAddresses {
        requested: addresses.into_iter().collect(),
        weighted_leaves: kernel_pc_leaves.into_keys().collect(),
    })
}

#[cfg(target_os = "macos")]
fn kernel_sample_addresses_from_lines<I, S>(lines: I) -> Result<KernelSampleAddresses>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut addresses = std::collections::BTreeSet::new();
    let mut kernel_pc_leaves = BTreeMap::<u64, u64>::new();
    let mut kernel_stack_leaves = BTreeMap::<u64, u64>::new();
    let mut open_stack = None::<StackTraceRecord>;
    for (index, raw_line) in lines.into_iter().enumerate() {
        let line = raw_line.as_ref().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(stack) = open_stack.as_mut() {
            if line == "NWSTACK1|end" {
                if stack.frames.is_empty() {
                    bail!("native-wall stack at line {} has no frames", index + 1);
                }
                let stack = open_stack
                    .take()
                    .ok_or_else(|| anyhow!("native-wall stack state disappeared"))?;
                if stack.state == "kernel-oncpu" {
                    let samples = match stack.value {
                        StackTraceValue::Count(samples) => samples,
                        StackTraceValue::DurationNs(_) => {
                            bail!("kernel-oncpu stack lost its count")
                        }
                    };
                    let leaf = raw_kernel_address(
                        stack
                            .frames
                            .first()
                            .ok_or_else(|| anyhow!("kernel-oncpu stack lost its leaf"))?,
                    )?;
                    let count = kernel_stack_leaves.entry(leaf).or_default();
                    *count = count
                        .checked_add(samples)
                        .ok_or_else(|| anyhow!("native-wall stack leaf population overflow"))?;
                    for frame in stack.frames {
                        addresses.insert(raw_kernel_address(&frame)?);
                    }
                }
            } else if line.starts_with("NWSTACK1|begin") {
                bail!("nested native-wall stack at line {}", index + 1);
            } else if line.starts_with("NWSTACK1|") {
                bail!(
                    "unrecognized native-wall stack marker at line {}",
                    index + 1
                );
            } else if line.starts_with("DSRPROF1|") || line.starts_with("NWIMAGES1|") {
                bail!(
                    "profile record interrupted native-wall stack at line {}",
                    index + 1
                );
            } else {
                stack.frames.push(line.to_owned());
            }
            continue;
        }
        if line.starts_with("NWSTACK1|begin") {
            open_stack = Some(
                StackTraceRecord::begin(line)
                    .with_context(|| format!("invalid stack at line {}", index + 1))?,
            );
        } else if line == "NWSTACK1|end" {
            bail!("native-wall stack end without begin at line {}", index + 1);
        } else if line.starts_with("NWSTACK1|") {
            bail!(
                "unrecognized native-wall stack marker at line {}",
                index + 1
            );
        } else if line.starts_with("DSRPROF1|") {
            let record = ProfileRecord::parse(line)
                .with_context(|| format!("invalid profile record at line {}", index + 1))?;
            if record.record_type == RecordType::Count
                && record.fields.get("phase").map(String::as_str) == Some("cpu-kernel-pc")
            {
                let leaf = record.required_u64("source_pc")?;
                let samples = record.required_u64("value")?;
                addresses.insert(leaf);
                let count = kernel_pc_leaves.entry(leaf).or_default();
                *count = count
                    .checked_add(samples)
                    .ok_or_else(|| anyhow!("native-wall kernel PC population overflow"))?;
            }
        }
    }
    if open_stack.is_some() {
        bail!("profile stream ended inside a native-wall stack");
    }
    if addresses.is_empty() {
        bail!("native-wall stream has no raw kernel stack addresses");
    }
    if kernel_pc_leaves != kernel_stack_leaves {
        bail!("native-wall kernel PC and exact stack leaf populations differ");
    }
    Ok(KernelSampleAddresses {
        requested: addresses.into_iter().collect(),
        weighted_leaves: kernel_pc_leaves.into_keys().collect(),
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ProfileCaptureStatus {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) dynamic_rinse_drops: u64,
    pub(crate) dynamic_dirty_drops: u64,
    pub(crate) other_drops: u64,
    pub(crate) interrupted: bool,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl From<carrick_runtime::dtrace_consumer::DTraceRunReport> for ProfileCaptureStatus {
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileProvenance {
    pub(crate) run_id: String,
    pub(crate) git_sha: String,
    pub(crate) git_dirty: Option<bool>,
    pub(crate) binary_sha256: String,
    pub(crate) command: Vec<String>,
    pub(crate) host: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ProfileScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_pc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_pc: Option<u64>,
}

impl ProfileScope {
    fn from_record(record: &ProfileRecord) -> Result<Self> {
        Ok(Self {
            phase: record.fields.get("phase").cloned(),
            pid: record.optional_u64("pid")?,
            tid: record.optional_u64("tid")?,
            kind: record.fields.get("kind").cloned(),
            source_pc: record.optional_u64("source_pc")?,
            target_pc: record.optional_u64("target_pc")?,
        })
    }
}

#[derive(Default)]
struct MetricBuilder {
    count: Option<u64>,
    total_ns: Option<u64>,
    minimum_ns: Option<u64>,
    maximum_ns: Option<u64>,
    samples_ns: Vec<f64>,
    sampling_interval: Option<u64>,
    incomplete: u64,
}

fn add_v2_exact_metric(
    grouped: &mut BTreeMap<ProfileScope, MetricBuilder>,
    scope: ProfileScope,
    count: Option<u64>,
    total_ns: Option<u64>,
) -> Result<()> {
    let builder = grouped.entry(scope).or_default();
    if let Some(value) = count {
        builder.count = Some(
            builder
                .count
                .unwrap_or(0)
                .checked_add(value)
                .ok_or_else(|| anyhow!("DSRPROF2 summary count overflow"))?,
        );
    }
    if let Some(value) = total_ns {
        builder.total_ns = Some(
            builder
                .total_ns
                .unwrap_or(0)
                .checked_add(value)
                .ok_or_else(|| anyhow!("DSRPROF2 summary duration overflow"))?,
        );
    }
    Ok(())
}

fn v2_profile_scope(
    phase: impl Into<String>,
    pid: Option<u64>,
    kind: Option<String>,
    source_pc: Option<u64>,
) -> ProfileScope {
    ProfileScope {
        phase: Some(phase.into()),
        pid,
        tid: None,
        kind,
        source_pc,
        target_pc: None,
    }
}

fn build_v2_profile_summary(
    mut validator: V2Validator,
    capture_status: ProfileCaptureStatus,
) -> Result<ProfileSummary> {
    if !validator.complete {
        bail!("cannot summarize an incomplete DSRPROF2 stream");
    }
    let instances = validator.presentation_instances()?;
    let instance_for = |key: RawProcessImageKey| {
        instances
            .get(&key.birth)
            .copied()
            .ok_or_else(|| anyhow!("DSRPROF2 summary lost a process presentation identity"))
    };
    let target = validator
        .target
        .ok_or_else(|| anyhow!("DSRPROF2 summary lost its target birth"))?;
    let wall_hz = validator
        .wall_hz
        .ok_or_else(|| anyhow!("DSRPROF2 summary lost wall_hz"))?;
    let cpu_hz = validator
        .cpu_hz
        .ok_or_else(|| anyhow!("DSRPROF2 summary lost cpu_hz"))?;
    let elapsed_ns = validator
        .elapsed_ns
        .ok_or_else(|| anyhow!("DSRPROF2 summary lost elapsed_ns"))?;

    let mut grouped = BTreeMap::<ProfileScope, MetricBuilder>::new();
    let mut wall_samples = 0_u64;
    for (kind, count) in &validator.wall_state {
        wall_samples = wall_samples
            .checked_add(*count)
            .ok_or_else(|| anyhow!("DSRPROF2 wall-state population overflow"))?;
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope("wall-state", None, Some(kind.clone()), None),
            Some(*count),
            None,
        )?;
    }
    add_v2_exact_metric(
        &mut grouped,
        v2_profile_scope("wall-samples", None, None, None),
        Some(wall_samples),
        None,
    )?;
    add_v2_exact_metric(
        &mut grouped,
        v2_profile_scope("elapsed", None, None, None),
        None,
        Some(elapsed_ns),
    )?;

    let child_count = validator
        .processes
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow!("DSRPROF2 summary has no target process"))?;
    let child_count = u64::try_from(child_count).context("DSRPROF2 child count exceeds u64")?;
    for (kind, count) in [
        ("create", child_count),
        ("exit", child_count),
        ("live-at-end", 0),
    ] {
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope("process-lifecycle", None, Some(kind.to_owned()), None),
            Some(count),
            None,
        )?;
    }

    for ((key, pc), count) in &validator.cpu_user_summary {
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope("cpu-user-pc", Some(instance_for(*key)?), None, Some(*pc)),
            Some(*count),
            None,
        )?;
    }
    let mut kernel_pc_samples = 0_u64;
    for ((key, class, pc), count) in &validator.cpu_kernel_summary {
        kernel_pc_samples = kernel_pc_samples
            .checked_add(*count)
            .ok_or_else(|| anyhow!("DSRPROF2 kernel PC population overflow"))?;
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope(
                "cpu-kernel-pc",
                Some(instance_for(*key)?),
                Some(class.clone()),
                Some(*pc),
            ),
            Some(*count),
            None,
        )?;
    }

    let mut offcpu_population = BTreeMap::<String, (u64, u64)>::new();
    for ((key, kind, pc), (count, total_ns)) in &validator.offcpu_summary {
        let phase = format!("offcpu-{kind}-pc");
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope(phase, Some(instance_for(*key)?), None, Some(*pc)),
            Some(*count),
            Some(*total_ns),
        )?;
        let population = offcpu_population.entry(kind.clone()).or_default();
        population.0 = population
            .0
            .checked_add(*count)
            .ok_or_else(|| anyhow!("DSRPROF2 off-CPU count overflow"))?;
        population.1 = population
            .1
            .checked_add(*total_ns)
            .ok_or_else(|| anyhow!("DSRPROF2 off-CPU duration overflow"))?;
    }
    for (kind, (_, total_ns)) in &offcpu_population {
        add_v2_exact_metric(
            &mut grouped,
            v2_profile_scope(format!("offcpu-{kind}-total"), None, None, None),
            None,
            Some(*total_ns),
        )?;
    }

    for (key, epoch) in &validator.epochs {
        let pid = Some(instance_for(*key)?);
        for range in &epoch.ranges {
            let kind = match range.kind {
                V2RangeKind::Private => "private",
                V2RangeKind::Shared { .. } => "shared",
            };
            add_v2_exact_metric(
                &mut grouped,
                ProfileScope {
                    phase: Some("jit-range".to_owned()),
                    pid,
                    tid: None,
                    kind: Some(kind.to_owned()),
                    source_pc: Some(range.start),
                    target_pc: Some(range.end),
                },
                Some(1),
                None,
            )?;
        }
        for (kind, base) in [
            ("host", epoch.host_image_base),
            ("guest", epoch.guest_image_base),
        ] {
            if let Some(base) = base {
                add_v2_exact_metric(
                    &mut grouped,
                    v2_profile_scope("image-base", pid, Some(kind.to_owned()), Some(base)),
                    Some(1),
                    None,
                )?;
            }
        }
    }

    let mut metrics = Vec::new();
    for (scope, builder) in grouped {
        metrics.push(ProfileOutputMetric {
            scope,
            metric: ProfileMetric::Exact {
                count: builder.count,
                total_ns: builder.total_ns,
                minimum_ns: None,
                maximum_ns: None,
            },
            sampling_interval: None,
        });
    }

    for (key, epoch) in &validator.epochs {
        if let Some(ranges) = epoch.host_image_catalog.as_ref() {
            let pid = instance_for(*key)?;
            metrics.push(ProfileOutputMetric {
                scope: v2_profile_scope(
                    "image-catalog",
                    Some(pid),
                    Some(format!(
                        "image-{}-epoch-{}",
                        key.image_generation, key.runtime_epoch
                    )),
                    None,
                ),
                metric: ProfileMetric::ImageCatalog {
                    pid,
                    ranges: ranges.clone(),
                },
                sampling_interval: None,
            });
        }
    }

    validator.stacks.sort_by(|left, right| {
        (
            left.key,
            left.kind.as_str(),
            left.count,
            left.total_ns,
            &left.frames,
        )
            .cmp(&(
                right.key,
                right.kind.as_str(),
                right.count,
                right.total_ns,
                &right.frames,
            ))
    });
    let mut kernel_stack_samples = 0_u64;
    let mut offcpu_stack_population = BTreeMap::<String, (u64, u64)>::new();
    let mut raw_stack_keys = BTreeSet::<(RawProcessImageKey, String, Vec<String>)>::new();
    let mut presented_stacks =
        BTreeMap::<(String, u64, String, Vec<String>), (u64, Option<u64>)>::new();
    for stack in validator.stacks {
        if !raw_stack_keys.insert((stack.key, stack.kind.clone(), stack.frames.clone())) {
            bail!("duplicate DSRSTACK2 record for one process-image key");
        }
        let pid = instance_for(stack.key)?;
        let (phase, value_ns) = if let Some(kind) = stack.kind.strip_prefix("offcpu-") {
            let population = offcpu_stack_population.entry(kind.to_owned()).or_default();
            population.0 = population
                .0
                .checked_add(stack.count)
                .ok_or_else(|| anyhow!("DSRPROF2 off-CPU stack count overflow"))?;
            population.1 = population
                .1
                .checked_add(stack.total_ns)
                .ok_or_else(|| anyhow!("DSRPROF2 off-CPU stack duration overflow"))?;
            (format!("offcpu-{kind}-stack"), Some(stack.total_ns))
        } else {
            if !matches!(
                stack.kind.as_str(),
                "kernel-named-syscall" | "kernel-mach-trap" | "kernel-non-syscall"
            ) {
                bail!("unknown DSRPROF2 kernel stack kind {:?}", stack.kind);
            }
            if stack.total_ns != 0 {
                bail!("DSRPROF2 kernel stack unexpectedly carries duration");
            }
            kernel_stack_samples = kernel_stack_samples
                .checked_add(stack.count)
                .ok_or_else(|| anyhow!("DSRPROF2 kernel stack population overflow"))?;
            ("cpu-kernel-stack".to_owned(), None)
        };
        let presented = presented_stacks
            .entry((phase, pid, stack.kind, stack.frames))
            .or_insert((0, value_ns.map(|_| 0)));
        presented.0 = presented
            .0
            .checked_add(stack.count)
            .ok_or_else(|| anyhow!("DSRPROF2 presented stack count overflow"))?;
        match (&mut presented.1, value_ns) {
            (Some(total_ns), Some(value_ns)) => {
                *total_ns = total_ns
                    .checked_add(value_ns)
                    .ok_or_else(|| anyhow!("DSRPROF2 presented stack duration overflow"))?;
            }
            (None, None) => {}
            _ => bail!("DSRPROF2 presented stack changed metric shape"),
        }
    }
    for ((phase, pid, kind, frames), (count, value_ns)) in presented_stacks {
        metrics.push(ProfileOutputMetric {
            scope: v2_profile_scope(phase, Some(pid), Some(kind.clone()), None),
            metric: ProfileMetric::StackTrace {
                state: kind,
                pid: Some(pid),
                count: Some(count),
                value_ns,
                frames,
            },
            sampling_interval: None,
        });
    }
    if kernel_stack_samples != kernel_pc_samples {
        bail!(
            "DSRPROF2 kernel stack population {kernel_stack_samples} does not match kernel PC population {kernel_pc_samples}"
        );
    }
    if offcpu_stack_population != offcpu_population {
        bail!("DSRPROF2 off-CPU stack and PC populations disagree");
    }

    metrics.push(ProfileOutputMetric {
        scope: v2_profile_scope("sampling-configuration", None, None, None),
        metric: ProfileMetric::SamplingConfiguration { wall_hz, cpu_hz },
        sampling_interval: None,
    });
    metrics.push(ProfileOutputMetric {
        scope: ProfileScope {
            phase: None,
            pid: None,
            tid: None,
            kind: None,
            source_pc: None,
            target_pc: None,
        },
        metric: ProfileMetric::Completion,
        sampling_interval: None,
    });

    let target_exit_reason = validator
        .processes
        .get(&target)
        .and_then(|process| process.exit_reason)
        .ok_or_else(|| anyhow!("DSRPROF2 summary lost target exit status"))?;
    Ok(ProfileSummary {
        profile: TraceProfileKind::NativeWall,
        completion: CompletionState {
            complete: true,
            bounded: false,
            target_exit_reason,
            high_cardinality_overflow: false,
            incomplete_pairs: 0,
            cardinality: ProfileCardinality::default(),
            drops: capture_status,
        },
        metrics,
        provenance: ProfileProvenance::default(),
    })
}

fn summed_count(
    grouped: &BTreeMap<ProfileScope, MetricBuilder>,
    phase: &str,
    kind: Option<&str>,
) -> Result<Option<u64>> {
    let mut found = false;
    let mut total = 0_u64;
    for (scope, metric) in grouped {
        if scope.phase.as_deref() == Some(phase)
            && kind.is_none_or(|expected| scope.kind.as_deref() == Some(expected))
            && let Some(value) = metric.count
        {
            found = true;
            total = total
                .checked_add(value)
                .ok_or_else(|| anyhow!("native-wall {phase} count population overflow"))?;
        }
    }
    Ok(found.then_some(total))
}

fn summed_total_ns(grouped: &BTreeMap<ProfileScope, MetricBuilder>, phase: &str) -> Option<u64> {
    let mut found = false;
    let mut total = 0_u64;
    for (scope, metric) in grouped {
        if scope.phase.as_deref() == Some(phase)
            && let Some(value) = metric.total_ns
        {
            found = true;
            total = total.saturating_add(value);
        }
    }
    found.then_some(total)
}

fn validate_native_wall_metrics(
    grouped: &BTreeMap<ProfileScope, MetricBuilder>,
    stack_traces: &[StackTraceRecord],
) -> Result<()> {
    let wall_samples = summed_count(grouped, "wall-samples", None)?
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("native-wall profile has no wall samples"))?;
    let wall_buckets = summed_count(grouped, "wall-state", None)?
        .ok_or_else(|| anyhow!("native-wall profile has no wall-state buckets"))?;
    if wall_buckets != wall_samples {
        bail!("native-wall wall-state buckets sum to {wall_buckets}, expected {wall_samples}");
    }
    summed_total_ns(grouped, "elapsed")
        .filter(|value| *value != 0)
        .ok_or_else(|| anyhow!("native-wall profile has no elapsed duration"))?;
    let live_at_end = summed_count(grouped, "process-lifecycle", Some("live-at-end"))?
        .ok_or_else(|| anyhow!("native-wall profile has no live-at-end count"))?;
    if live_at_end != 0 {
        bail!("native-wall profile ended with {live_at_end} tracked process(es)");
    }
    let kernel_samples = summed_count(grouped, "cpu-kernel-pc", None)?.unwrap_or(0);
    let mut kernel_stack_samples = 0_u64;
    let mut has_kernel_stacks = false;
    let mut has_voluntary_stacks = false;
    for stack in stack_traces {
        match stack.value {
            StackTraceValue::Count(value) => {
                has_kernel_stacks = true;
                kernel_stack_samples = kernel_stack_samples
                    .checked_add(value)
                    .ok_or_else(|| anyhow!("native-wall kernel stack population overflow"))?;
            }
            StackTraceValue::DurationNs(_) => {
                has_voluntary_stacks = true;
            }
        }
    }
    if has_kernel_stacks && kernel_stack_samples != kernel_samples {
        bail!(
            "native-wall kernel stack samples total {kernel_stack_samples}, expected {kernel_samples}"
        );
    }
    if summed_count(grouped, "cpu-user-pc", None)?.unwrap_or(0) == 0 && kernel_samples == 0 {
        bail!("native-wall profile has no CPU samples");
    }
    let voluntary_ns = summed_total_ns(grouped, "offcpu-voluntary-total").unwrap_or(0);
    if voluntary_ns != 0 && !has_voluntary_stacks {
        bail!("native-wall profile has voluntary off-CPU time but no blocking stacks");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum ProfileMetric {
    Exact {
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        total_ns: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        minimum_ns: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        maximum_ns: Option<u64>,
    },
    SampledDuration {
        summary: Summary,
    },
    IncompletePair {
        value: u64,
    },
    HighWater {
        metric: String,
        used: u64,
        capacity: u64,
    },
    ImageCatalog {
        pid: u64,
        ranges: Vec<HostImageRangeRecord>,
    },
    SamplingConfiguration {
        wall_hz: u64,
        cpu_hz: u64,
    },
    #[cfg(target_os = "macos")]
    SampledKernelSymbols {
        overlay: SampledKernelSymbolOverlay,
    },
    StackTrace {
        state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_ns: Option<u64>,
        frames: Vec<String>,
    },
    Completion,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct CompletionState {
    complete: bool,
    bounded: bool,
    target_exit_reason: u64,
    high_cardinality_overflow: bool,
    incomplete_pairs: u64,
    cardinality: ProfileCardinality,
    drops: ProfileCaptureStatus,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct ProfileCardinality {
    indirect_sources: u64,
    indirect_pairs: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProfileJsonRow {
    schema: &'static str,
    profile: TraceProfileKind,
    run_id: String,
    git_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_dirty: Option<bool>,
    binary_sha256: String,
    command: Vec<String>,
    host: String,
    scope: ProfileScope,
    metric: ProfileMetric,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampling_interval: Option<u64>,
    completion: CompletionState,
}

#[derive(Clone, Debug)]
struct ProfileOutputMetric {
    scope: ProfileScope,
    metric: ProfileMetric,
    sampling_interval: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ProfileSummary {
    profile: TraceProfileKind,
    completion: CompletionState,
    metrics: Vec<ProfileOutputMetric>,
    provenance: ProfileProvenance,
}

impl ProfileSummary {
    pub(crate) fn from_path(path: &Path, capture_status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read DSR profile stream {}", path.display()))?;
        Self::from_lines(contents.lines(), capture_status)
    }

    pub(crate) fn from_v2_path_with_authority(
        path: &Path,
        capture_status: ProfileCaptureStatus,
        authority: V2ProfileAuthority,
    ) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read authoritative DSRPROF2 stream {}", path.display()))?;
        let validator = parse_v2_lines_with_validator(
            contents.lines(),
            capture_status,
            V2Validator::with_authority(authority),
        )?;
        validator.into_profile_summary(capture_status)
    }

    pub(crate) fn from_lines<I, S>(lines: I, capture_status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let lines = lines
            .into_iter()
            .map(|line| line.as_ref().to_owned())
            .collect::<Vec<_>>();
        if lines
            .iter()
            .map(|line| line.trim())
            .find(|line| !line.is_empty())
            .is_some_and(|line| line.starts_with("DSRPROF2|"))
        {
            let validator = parse_v2_lines_with_validator(
                lines.iter().map(String::as_str),
                capture_status,
                V2Validator::default(),
            )?;
            return validator.into_profile_summary(capture_status);
        }

        if capture_status.principal_drops != 0 {
            bail!(
                "DTrace principal buffer dropped {} record(s); profile stream is truncated",
                capture_status.principal_drops
            );
        }

        let mut grouped = BTreeMap::<ProfileScope, MetricBuilder>::new();
        let mut high_water = BTreeMap::<(ProfileScope, String), (u64, u64)>::new();
        let mut stack_traces = Vec::<StackTraceRecord>::new();
        let mut image_catalogs = BTreeMap::<u64, Vec<HostImageRangeRecord>>::new();
        let mut open_stack = None::<StackTraceRecord>;
        let mut completion = None;

        for (index, raw_line) in lines.iter().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if completion.is_some() {
                bail!(
                    "profile record appears after completion at line {}",
                    index + 1
                );
            }
            if let Some(stack) = open_stack.as_mut() {
                if line == "NWSTACK1|end" {
                    let stack = open_stack
                        .take()
                        .ok_or_else(|| anyhow!("native-wall stack state disappeared"))?;
                    if stack.frames.is_empty() {
                        bail!("native-wall stack at line {} has no frames", index + 1);
                    }
                    stack_traces.push(stack);
                } else if line.starts_with("NWSTACK1|begin") {
                    bail!("nested native-wall stack at line {}", index + 1);
                } else if line.starts_with("DSRPROF1|") {
                    bail!(
                        "profile record interrupted native-wall stack at line {}",
                        index + 1
                    );
                } else {
                    stack.frames.push(line.to_owned());
                }
                continue;
            }
            if line.starts_with("NWSTACK1|begin") {
                open_stack = Some(
                    StackTraceRecord::begin(line)
                        .with_context(|| format!("invalid stack at line {}", index + 1))?,
                );
                continue;
            }
            if line == "NWSTACK1|end" {
                bail!("native-wall stack end without begin at line {}", index + 1);
            }
            if line.starts_with("NWIMAGES1|") {
                let catalog = HostImageCatalogRecord::parse(line)
                    .with_context(|| format!("invalid image catalog at line {}", index + 1))?;
                match image_catalogs.entry(catalog.pid) {
                    Entry::Vacant(slot) => {
                        slot.insert(catalog.ranges);
                    }
                    Entry::Occupied(_) => {
                        bail!("duplicate image catalog for pid {}", catalog.pid);
                    }
                }
                continue;
            }
            let record = ProfileRecord::parse(line)
                .with_context(|| format!("invalid profile record at line {}", index + 1))?;
            if record.record_type == RecordType::Complete {
                let profile = TraceProfileKind::parse_protocol(record.required("profile")?)?;
                let bounded = match record.required_u64("bounded")? {
                    0 => false,
                    1 => true,
                    other => bail!("completion bounded field must be 0 or 1, got {other}"),
                };
                // macOS proc:::exit arg0 is the CLD_* reason. CLD_EXITED is 1;
                // signal termination (for example an interrupted trace) is not
                // a successful profile completion. Default old DSRPROF1 streams
                // to CLD_EXITED so checked-in pre-field evidence remains readable.
                let target_exit_reason = record.optional_u64("target_exit_reason")?.unwrap_or(1);
                completion = Some((profile, bounded, target_exit_reason));
                continue;
            }

            let scope = ProfileScope::from_record(&record)?;
            match record.record_type {
                RecordType::Count => {
                    let value = record.required_u64("value")?;
                    let phase = scope.phase.as_deref().unwrap_or("<unscoped>").to_owned();
                    let builder = grouped.entry(scope).or_default();
                    let previous = builder.count.unwrap_or(0);
                    builder.count = Some(previous.checked_add(value).ok_or_else(|| {
                        anyhow!(
                            "profile count population overflow for phase {phase:?} at line {}",
                            index + 1
                        )
                    })?);
                }
                RecordType::Total => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.total_ns = Some(builder.total_ns.unwrap_or(0).saturating_add(value));
                }
                RecordType::Minimum => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.minimum_ns =
                        Some(builder.minimum_ns.map_or(value, |old| old.min(value)));
                }
                RecordType::Maximum => {
                    let value = record.required_u64("value_ns")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.maximum_ns =
                        Some(builder.maximum_ns.map_or(value, |old| old.max(value)));
                }
                RecordType::Sample => {
                    let duration = record.required_u64("duration_ns")?;
                    let interval = record.optional_u64("interval")?;
                    let builder = grouped.entry(scope).or_default();
                    if let (Some(previous), Some(current)) = (builder.sampling_interval, interval)
                        && previous != current
                    {
                        bail!(
                            "sample group mixes intervals {previous} and {current} at line {}",
                            index + 1
                        );
                    }
                    if interval.is_some() {
                        builder.sampling_interval = interval;
                    }
                    builder.samples_ns.push(duration as f64);
                }
                RecordType::Incomplete => {
                    let value = record.required_u64("value")?;
                    let builder = grouped.entry(scope).or_default();
                    builder.incomplete = builder.incomplete.saturating_add(value);
                }
                RecordType::HighWater => {
                    let metric = record.required("metric")?.to_owned();
                    let used = record.required_u64("used")?;
                    let capacity = record.required_u64("capacity")?;
                    high_water
                        .entry((scope, metric))
                        .and_modify(|current| {
                            current.0 = current.0.max(used);
                            current.1 = current.1.max(capacity);
                        })
                        .or_insert((used, capacity));
                }
                RecordType::Complete => unreachable!("completion handled above"),
            }
        }
        if open_stack.is_some() {
            bail!("profile stream ended inside a native-wall stack");
        }

        let (profile, bounded, target_exit_reason) =
            completion.ok_or_else(|| anyhow!("profile stream is missing its completion record"))?;
        if !stack_traces.is_empty() && profile != TraceProfileKind::NativeWall {
            bail!("stack records are valid only for the native-wall profile");
        }
        if !image_catalogs.is_empty() && profile != TraceProfileKind::NativeWall {
            bail!("image catalogs are valid only for the native-wall profile");
        }
        if profile == TraceProfileKind::NativeWall {
            validate_native_wall_metrics(&grouped, &stack_traces)?;
        }
        for (scope, builder) in &grouped {
            let exact_fields = [
                builder.count.is_some(),
                builder.total_ns.is_some(),
                builder.minimum_ns.is_some(),
                builder.maximum_ns.is_some(),
            ];
            if scope.phase.as_deref() == Some("translation-subphase")
                && exact_fields.iter().any(|present| *present)
                && !exact_fields.iter().all(|present| *present)
            {
                bail!(
                    "translation subphase aggregate is truncated for pid={:?} kind={:?}",
                    scope.pid,
                    scope.kind
                );
            }
        }
        let incomplete_pairs = grouped.values().fold(0_u64, |total, builder| {
            total.saturating_add(builder.incomplete)
        });
        let has_metrics = !grouped.is_empty() || !high_water.is_empty();
        let cardinality = ProfileCardinality {
            indirect_sources: u64::try_from(
                grouped
                    .keys()
                    .filter(|scope| {
                        scope.phase.as_deref() == Some("indirect-source")
                            && scope.source_pc.is_some()
                    })
                    .count(),
            )
            .unwrap_or(u64::MAX),
            indirect_pairs: u64::try_from(
                grouped
                    .keys()
                    .filter(|scope| {
                        scope.phase.as_deref() == Some("indirect-pair")
                            && scope.source_pc.is_some()
                            && scope.target_pc.is_some()
                    })
                    .count(),
            )
            .unwrap_or(u64::MAX),
        };
        let completion = CompletionState {
            complete: !bounded
                && target_exit_reason == 1
                && has_metrics
                && !capture_status.interrupted
                && incomplete_pairs == 0
                && capture_status.aggregation_drops == 0
                && capture_status.dynamic_drops == 0
                && capture_status.dynamic_rinse_drops == 0
                && capture_status.dynamic_dirty_drops == 0
                && capture_status.other_drops == 0,
            bounded,
            target_exit_reason,
            high_cardinality_overflow: capture_status.aggregation_drops != 0
                || capture_status.dynamic_drops != 0
                || capture_status.dynamic_rinse_drops != 0
                || capture_status.dynamic_dirty_drops != 0,
            incomplete_pairs,
            cardinality,
            drops: capture_status,
        };

        let mut metrics = Vec::new();
        for (scope, builder) in grouped {
            if builder.count.is_some()
                || builder.total_ns.is_some()
                || builder.minimum_ns.is_some()
                || builder.maximum_ns.is_some()
            {
                metrics.push(ProfileOutputMetric {
                    scope: scope.clone(),
                    metric: ProfileMetric::Exact {
                        count: builder.count,
                        total_ns: builder.total_ns,
                        minimum_ns: builder.minimum_ns,
                        maximum_ns: builder.maximum_ns,
                    },
                    sampling_interval: None,
                });
            }
            if let Some(summary) = summarize(&builder.samples_ns) {
                metrics.push(ProfileOutputMetric {
                    scope: scope.clone(),
                    metric: ProfileMetric::SampledDuration { summary },
                    sampling_interval: builder.sampling_interval,
                });
            }
            if builder.incomplete != 0 {
                metrics.push(ProfileOutputMetric {
                    scope,
                    metric: ProfileMetric::IncompletePair {
                        value: builder.incomplete,
                    },
                    sampling_interval: None,
                });
            }
        }
        for ((scope, metric), (used, capacity)) in high_water {
            metrics.push(ProfileOutputMetric {
                scope,
                metric: ProfileMetric::HighWater {
                    metric,
                    used,
                    capacity,
                },
                sampling_interval: None,
            });
        }
        for (pid, ranges) in image_catalogs {
            metrics.push(ProfileOutputMetric {
                scope: ProfileScope {
                    phase: Some("image-catalog".to_owned()),
                    pid: Some(pid),
                    tid: None,
                    kind: None,
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::ImageCatalog { pid, ranges },
                sampling_interval: None,
            });
        }
        for stack in stack_traces {
            let (phase, scope_pid, metric_pid, count, value_ns) = match stack.value {
                StackTraceValue::Count(samples) => {
                    ("cpu-kernel-stack", None, None, Some(samples), None)
                }
                StackTraceValue::DurationNs(duration_ns) => {
                    let pid = stack
                        .pid
                        .ok_or_else(|| anyhow!("voluntary stack lost its pid"))?;
                    (
                        "offcpu-voluntary-stack",
                        Some(pid),
                        Some(pid),
                        None,
                        Some(duration_ns),
                    )
                }
            };
            metrics.push(ProfileOutputMetric {
                scope: ProfileScope {
                    phase: Some(phase.to_owned()),
                    pid: scope_pid,
                    tid: None,
                    kind: Some(stack.state.clone()),
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::StackTrace {
                    state: stack.state,
                    pid: metric_pid,
                    count,
                    value_ns,
                    frames: stack.frames,
                },
                sampling_interval: None,
            });
        }
        metrics.push(ProfileOutputMetric {
            scope: ProfileScope {
                phase: None,
                pid: None,
                tid: None,
                kind: None,
                source_pc: None,
                target_pc: None,
            },
            metric: ProfileMetric::Completion,
            sampling_interval: None,
        });

        Ok(Self {
            profile,
            completion,
            metrics,
            provenance: ProfileProvenance::default(),
        })
    }

    pub(crate) fn set_provenance(&mut self, provenance: ProfileProvenance) {
        self.provenance = provenance;
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn attach_sampled_kernel_overlay(
        &mut self,
        overlay: SampledKernelSymbolOverlay,
    ) -> Result<()> {
        if self.profile != TraceProfileKind::NativeWall {
            bail!("sampled kernel symbols are valid only for native-wall profiles");
        }
        let completion_indices = self
            .metrics
            .iter()
            .enumerate()
            .filter_map(|(index, metric)| {
                matches!(metric.metric, ProfileMetric::Completion).then_some(index)
            })
            .collect::<Vec<_>>();
        if completion_indices.as_slice() != [self.metrics.len().saturating_sub(1)] {
            bail!("profile summary completion row is missing, duplicated, or not final");
        }
        for metric in &self.metrics {
            if let ProfileMetric::SampledKernelSymbols { overlay: existing } = &metric.metric {
                if existing.identity != overlay.identity {
                    bail!("sampled kernel symbol overlays have a kernel or boot identity mismatch");
                }
                bail!("sampled kernel symbol overlay is already attached");
            }
        }

        overlay
            .validate()
            .context("invalid sampled kernel symbol overlay")?;
        let resolved = overlay
            .symbols
            .iter()
            .map(|symbol| symbol.address)
            .collect::<BTreeSet<_>>();
        let unresolved = overlay
            .unresolved
            .iter()
            .map(|address| address.address)
            .collect::<BTreeSet<_>>();
        let actual_requested = resolved
            .union(&unresolved)
            .copied()
            .collect::<BTreeSet<_>>();

        let mut expected_requested = BTreeSet::new();
        for metric in &self.metrics {
            if metric.scope.phase.as_deref() == Some("cpu-kernel-pc")
                && let Some(address) = metric.scope.source_pc
            {
                expected_requested.insert(address);
            }
            if let ProfileMetric::StackTrace { state, frames, .. } = &metric.metric
                && matches!(
                    state.as_str(),
                    "kernel-oncpu"
                        | "kernel-named-syscall"
                        | "kernel-mach-trap"
                        | "kernel-non-syscall"
                )
            {
                for frame in frames {
                    expected_requested.insert(raw_kernel_address(frame)?);
                }
            }
        }
        if actual_requested != expected_requested {
            let missing = expected_requested
                .difference(&actual_requested)
                .copied()
                .collect::<Vec<_>>();
            let extra = actual_requested
                .difference(&expected_requested)
                .copied()
                .collect::<Vec<_>>();
            bail!(
                "sampled overlay does not match raw kernel address population: missing={missing:#x?}, extra={extra:#x?}"
            );
        }
        for address in &overlay.unresolved {
            if address.status != -1 || address.dtrace_errno != 1015 {
                bail!(
                    "unresolved kernel address {:#x} has status ({}, {}), expected (-1, 1015)",
                    address.address,
                    address.status,
                    address.dtrace_errno
                );
            }
        }
        for symbol in &overlay.symbols {
            if raw_kernel_address(&symbol.symbol).is_ok() {
                bail!(
                    "resolved kernel address {:#x} retained raw-address symbol {:?}",
                    symbol.address,
                    symbol.symbol
                );
            }
        }

        let completion_index = completion_indices[0];
        self.metrics.insert(
            completion_index,
            ProfileOutputMetric {
                scope: ProfileScope {
                    phase: None,
                    pid: None,
                    tid: None,
                    kind: None,
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::SampledKernelSymbols { overlay },
                sampling_interval: None,
            },
        );
        Ok(())
    }

    pub(crate) fn require_profile(&self, expected: TraceProfileKind) -> Result<()> {
        if self.profile != expected {
            bail!(
                "profile stream completed as {}, expected {}",
                self.profile.as_str(),
                expected.as_str()
            );
        }
        Ok(())
    }

    pub(crate) fn render_human(&self) -> String {
        format!(
            "DSR profile {}: {} metric row(s), complete={}, bounded={}, interrupted={}, target_exit_reason={}, incomplete_pairs={}, drops=principal:{},aggregation:{},dynamic:{},dynamic_rinse:{},dynamic_dirty:{},other:{}",
            self.profile.as_str(),
            self.metrics.len().saturating_sub(1),
            self.completion.complete,
            self.completion.bounded,
            self.completion.drops.interrupted,
            self.completion.target_exit_reason,
            self.completion.incomplete_pairs,
            self.completion.drops.principal_drops,
            self.completion.drops.aggregation_drops,
            self.completion.drops.dynamic_drops,
            self.completion.drops.dynamic_rinse_drops,
            self.completion.drops.dynamic_dirty_drops,
            self.completion.drops.other_drops,
        )
    }

    fn json_rows(&self) -> Vec<ProfileJsonRow> {
        self.metrics
            .iter()
            .map(|output| ProfileJsonRow {
                schema: JSON_SCHEMA,
                profile: self.profile,
                run_id: self.provenance.run_id.clone(),
                git_sha: self.provenance.git_sha.clone(),
                git_dirty: self.provenance.git_dirty,
                binary_sha256: self.provenance.binary_sha256.clone(),
                command: self.provenance.command.clone(),
                host: self.provenance.host.clone(),
                scope: output.scope.clone(),
                metric: output.metric.clone(),
                sampling_interval: output.sampling_interval,
                completion: self.completion,
            })
            .collect()
    }
}

pub(crate) fn capture_provenance(binary: &Path, command: &[String]) -> Result<ProfileProvenance> {
    let binary_bytes =
        fs::read(binary).with_context(|| format!("read traced binary {}", binary.display()))?;
    let binary_sha256 = format!("{:x}", Sha256::digest(binary_bytes));
    let git_sha = command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_dirty = git_dirty();
    let host = command_output("hostname", &[]).unwrap_or_else(|| "unknown".into());
    let run_id = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        format!(
            "dsr-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
            std::process::id()
        )
    });
    Ok(ProfileProvenance {
        run_id,
        git_sha,
        git_dirty,
        binary_sha256,
        command: command.to_vec(),
        host,
    })
}

fn git_dirty() -> Option<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    output.status.success().then_some(!output.stdout.is_empty())
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

pub(crate) fn write_summary_atomic(
    path: &Path,
    summary: &ProfileSummary,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create profile output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary profile in {}", parent.display()))?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        for row in summary.json_rows() {
            serde_json::to_writer(&mut writer, &row).context("serialize DSR profile row")?;
            writer
                .write_all(b"\n")
                .context("terminate DSR profile row")?;
        }
        writer.flush().context("flush buffered DSR profile JSONL")?;
    }
    temporary
        .as_file()
        .sync_all()
        .context("sync DSR profile JSONL")?;
    if let Some((uid, gid)) = owner {
        let result = unsafe { libc::fchown(temporary.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("set DSR profile owner");
        }
    }
    temporary
        .persist(path)
        .map_err(|error| anyhow!("publish DSR profile {}: {}", path.display(), error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn native_fault_profile_selection_is_bundled_and_runtime_profile_free() {
        let profile = TraceProfileKind::parse_protocol("native-fault")
            .expect("native-fault profile spelling");
        assert_eq!(profile, TraceProfileKind::NativeFault);
        assert_eq!(profile.as_str(), "native-fault");
        assert!(!profile.requires_runtime_profile());
        assert_eq!(
            profile.bundled_script(),
            carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_FAULT_D
        );
        let script = profile.bundled_script();
        for record in [
            "NFAULT2|process-create|",
            "fork_id=%d",
            "NFAULT2|prebirth-page|",
            "NFAULT2|prebirth-total|",
            "NFAULT2|prebirth-rejected|",
            "pending_forks=%d",
        ] {
            assert!(
                script.contains(record),
                "missing NFAULT2 fork-window record {record}"
            );
        }
        assert!(!script.contains("NFAULT2|prebirth|"));
        for line in script.lines().filter(|line| {
            line.contains("arg2")
                && (line.contains("0x0001000000000000")
                    || line.contains("0x3fff")
                    || line.contains(", arg2]"))
        }) {
            assert!(
                line.contains("(uint64_t)arg2"),
                "NFAULT2 uses signed vminfo address: {line}"
            );
        }
    }

    #[test]
    fn dsrprof2_summary_preserves_birth_keyed_metrics() {
        let summary = ProfileSummary::from_lines(
            include_str!("../tests/fixtures/dsrprof2-valid.raw").lines(),
            ProfileCaptureStatus::default(),
        )
        .expect("DSRPROF2 summary");
        assert_eq!(summary.profile, TraceProfileKind::NativeWall);
        assert!(summary.completion.complete);

        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize DSRPROF2 summary row"))
            .collect::<Vec<_>>();
        let exact = |phase: &str, pid: Option<u64>, source_pc: Option<u64>| {
            rows.iter().find(|row| {
                row["scope"]["phase"] == phase
                    && pid.is_none_or(|value| row["scope"]["pid"] == value)
                    && source_pc.is_none_or(|value| row["scope"]["source_pc"] == value)
                    && row["metric"]["type"] == "exact"
            })
        };
        assert_eq!(
            exact("wall-samples", None, None).unwrap()["metric"]["count"],
            11
        );
        assert_eq!(
            exact("cpu-user-pc", Some(1), Some(0x1100)).unwrap()["metric"]["count"],
            3
        );
        let offcpu = exact("offcpu-voluntary-pc", Some(1), Some(0x1150)).unwrap();
        assert_eq!(offcpu["metric"]["count"], 1);
        assert_eq!(offcpu["metric"]["total_ns"], 500);
        assert_eq!(
            exact("elapsed", None, None).unwrap()["metric"]["total_ns"],
            60_000_000
        );
        let private_range = rows
            .iter()
            .find(|row| {
                row["scope"]["phase"] == "jit-range"
                    && row["scope"]["pid"] == 1
                    && row["scope"]["kind"] == "private"
                    && row["scope"]["source_pc"] == 0x1000
                    && row["scope"]["target_pc"] == 0x2000
            })
            .expect("private translated range");
        assert_eq!(private_range["metric"]["count"], 1);
        assert!(rows.iter().any(|row| {
            row["scope"]["phase"] == "jit-range"
                && row["scope"]["pid"] == 1
                && row["scope"]["kind"] == "shared"
                && row["scope"]["source_pc"] == 0x3000
                && row["scope"]["target_pc"] == 0x3800
        }));
        assert!(rows.iter().any(|row| {
            row["scope"]["phase"] == "offcpu-voluntary-stack"
                && row["scope"]["pid"] == 1
                && row["metric"]["value_ns"] == 500
        }));
        assert!(rows.iter().any(|row| {
            row["scope"]["phase"] == "image-catalog"
                && row["scope"]["pid"] == 1
                && row["metric"]["pid"] == 1
        }));
        assert_eq!(rows.last().unwrap()["metric"]["type"], "completion");
    }

    #[test]
    fn dsrprof2_host_catalog_can_replay_a_canonical_process_payload() {
        let raw = include_str!("../tests/fixtures/dsrprof2-valid.raw").replacen(
            "catalog_pid=100|payload={\"ok\":{\"pid\":100",
            "catalog_pid=999|payload={\"ok\":{\"pid\":999",
            1,
        );
        ProfileSummary::from_lines(raw.lines(), ProfileCaptureStatus::default())
            .expect("a canonical dyld catalog can be replayed for another process image");
    }

    #[test]
    fn dsrprof2_fault_diagnostic_reaches_integrity_failure() {
        let raw = include_str!("../tests/fixtures/dsrprof2-valid.raw")
            .replacen(
                "DSRPROF2|process-create|",
                concat!(
                    "DSRERROR2|fault|epid=3484|action=7|offset=12|fault=1|value=0x1234\n",
                    "DSRPROF2|process-create|"
                ),
                1,
            )
            .replacen("bounded=0", "bounded=1", 1)
            .replacen("probe_errors=0", "probe_errors=1", 1);

        let error = ProfileSummary::from_lines(raw.lines(), ProfileCaptureStatus::default())
            .expect_err("a DTrace fault must fail closed after its diagnostic is parsed");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("probe_errors=1"),
            "unexpected error: {rendered}"
        );
    }

    #[test]
    fn dsrprof2_summary_coalesces_identical_stacks_across_exec_images() {
        let mut lines = include_str!("../tests/fixtures/dsrprof2-valid.raw")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let completion = lines
            .iter()
            .position(|line| line.starts_with("DSRPROF2|complete|"))
            .expect("completion row");
        lines.splice(
            completion..completion,
            [
                "DSRPROF2|cpu-kernel|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|class=kernel-named-syscall|pc=0xfffffe0010030030|count=1",
                "DSRSTACK2|begin|pid=101|start_sec=11|start_usec=21|image=1|epoch=1|kind=kernel-named-syscall|count=1|total_ns=0",
                "",
                "0xfffffe0010030030",
                "0xfffffe0010040040",
                "DSRSTACK2|end",
                "DSRPROF2|cpu-kernel|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|class=kernel-named-syscall|pc=0xfffffe0010030030|count=1",
                "DSRSTACK2|begin|pid=101|start_sec=11|start_usec=21|image=2|epoch=0|kind=kernel-named-syscall|count=1|total_ns=0",
                "",
                "0xfffffe0010030030",
                "0xfffffe0010040040",
                "DSRSTACK2|end",
            ]
            .into_iter()
            .map(str::to_owned),
        );

        let summary = ProfileSummary::from_lines(lines, ProfileCaptureStatus::default())
            .expect("DSRPROF2 summary");
        let matching = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize DSRPROF2 summary row"))
            .filter(|row| {
                row["scope"]["phase"] == "cpu-kernel-stack"
                    && row["scope"]["pid"] == 2
                    && row["metric"]["frames"]
                        == serde_json::json!(["0xfffffe0010030030", "0xfffffe0010040040"])
            })
            .collect::<Vec<_>>();

        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0]["metric"]["count"], 2);
    }

    #[test]
    fn dsrprof2_summary_rejects_duplicate_stack_within_one_image() {
        let raw = include_str!("../tests/fixtures/dsrprof2-valid.raw")
            .replacen(
                "class=kernel-named-syscall|pc=0xfffffe0010010010|count=2",
                "class=kernel-named-syscall|pc=0xfffffe0010010010|count=3",
                1,
            )
            .replacen(
                "DSRPROF2|process-create|",
                concat!(
                    "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=kernel-named-syscall|count=1|total_ns=0\n",
                    "\n",
                    "0xfffffe0010010010\n",
                    "0xfffffe0010020020\n",
                    "DSRSTACK2|end\n",
                    "DSRPROF2|process-create|"
                ),
                1,
            );

        let error = ProfileSummary::from_lines(raw.lines(), ProfileCaptureStatus::default())
            .expect_err("an exact raw stack duplicate must fail closed");
        assert!(
            error
                .to_string()
                .contains("duplicate DSRSTACK2 record for one process-image key")
        );
    }

    #[test]
    fn dsrprof2_authoritative_summary_reconciles_process_terminal_scope() {
        let terminal = concat!(
            "DSRPROF2|kernel-enter|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=101|provider=syscall|function=kevent|class=named-syscall|timestamp_ns=1850\n",
            "DSRPROF2|offcpu-block|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=101|episode=1|kind=voluntary|pc=0x1150|timestamp_ns=1875\n",
            "DSRPROF2|kernel-enter|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=exit|class=named-syscall|timestamp_ns=1900\n",
            "DSRPROF2|kernel-terminal-close|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|tid=100|provider=syscall|function=exit|class=named-syscall|scope=process|timestamp_ns=2000\n",
        );
        let raw = include_str!("../tests/fixtures/dsrprof2-valid.raw").replacen(
            "DSRPROF2|process-exit|pid=100",
            &format!("{terminal}DSRPROF2|process-exit|pid=100"),
            1,
        );
        let input = tempfile::NamedTempFile::new().expect("temporary DSRPROF2 stream");
        std::fs::write(input.path(), raw).expect("write temporary DSRPROF2 stream");
        let authority = V2ProfileAuthority::new(
            "26A123",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            [
                (
                    "syscall".to_owned(),
                    "bsdthread_terminate".to_owned(),
                    "thread".to_owned(),
                ),
                (
                    "syscall".to_owned(),
                    "exit".to_owned(),
                    "process".to_owned(),
                ),
            ],
        )
        .expect("valid launch authority");

        let summary = ProfileSummary::from_v2_path_with_authority(
            input.path(),
            ProfileCaptureStatus::default(),
            authority,
        )
        .expect("authoritative DSRPROF2 summary");

        assert_eq!(summary.profile, TraceProfileKind::NativeWall);
        assert!(summary.completion.complete);
    }

    #[test]
    fn dsrprof2_header_must_match_exact_launch_authority() {
        let authority = V2ProfileAuthority::new(
            "26A123",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            [
                (
                    "syscall".to_owned(),
                    "bsdthread_terminate".to_owned(),
                    "thread".to_owned(),
                ),
                (
                    "syscall".to_owned(),
                    "exit".to_owned(),
                    "process".to_owned(),
                ),
            ],
        )
        .expect("valid launch authority");
        let header = "DSRPROF2|header|profile=native-wall|raw_schema=carrick.dsrprof.raw.v2|os_build=26A123|program_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|birth_qualification_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|terminal_qualification_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc|wall_hz=197|cpu_hz=499";

        let mut validator = V2Validator::with_authority(authority.clone());
        validator
            .header(&V2Record::parse(header, V2_PROTOCOL_PREFIX).expect("exact header"))
            .expect("matching authority");

        for corrupt in [
            header.replacen("os_build=26A123", "os_build=26A124", 1),
            header.replacen(
                "program_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "program_sha256=daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                1,
            ),
            header.replacen(
                "birth_qualification_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "birth_qualification_sha256=dbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1,
            ),
            header.replacen(
                "terminal_qualification_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "terminal_qualification_sha256=dccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1,
            ),
        ] {
            let mut validator = V2Validator::with_authority(authority.clone());
            let record = V2Record::parse(&corrupt, V2_PROTOCOL_PREFIX)
                .expect("syntactically valid corrupt header");
            assert!(validator.header(&record).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    use carrick_runtime::dtrace_symbols::{
        KernelIdentity, SampledKernelSymbol, SampledKernelSymbolOverlay, UnresolvedKernelAddress,
    };

    #[cfg(target_os = "macos")]
    fn kernel_identity() -> KernelIdentity {
        KernelIdentity {
            osversion: "26A5388g".to_owned(),
            version: "Darwin Kernel Version 26.0.0".to_owned(),
            uuid: "01234567-89AB-CDEF-0123-456789ABCDEF".to_owned(),
            machine: "arm64".to_owned(),
            bootsessionuuid: "FEDCBA98-7654-3210-FEDC-BA9876543210".to_owned(),
        }
    }

    #[cfg(target_os = "macos")]
    fn sampled_kernel_overlay(
        resolved: &[u64],
        unresolved: &[(u64, i32, i32)],
    ) -> SampledKernelSymbolOverlay {
        let requested = resolved
            .iter()
            .copied()
            .chain(unresolved.iter().map(|(address, _, _)| *address))
            .collect::<Vec<_>>();
        SampledKernelSymbolOverlay::from_parts(
            kernel_identity(),
            requested,
            resolved
                .iter()
                .map(|address| SampledKernelSymbol {
                    address: *address,
                    symbol: format!("fn_{address:x}"),
                    symbol_start: *address,
                    symbol_size: 1,
                    offset: 0,
                })
                .collect(),
            unresolved
                .iter()
                .map(|(address, status, dtrace_errno)| UnresolvedKernelAddress {
                    address: *address,
                    status: *status,
                    dtrace_errno: *dtrace_errno,
                })
                .collect(),
        )
        .expect("sampled overlay")
    }

    #[cfg(target_os = "macos")]
    fn raw_native_wall_lines() -> Vec<&'static str> {
        vec![
            "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=3",
            "DSRPROF1|count|phase=wall-samples|value=3",
            "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0x1018|value=3",
            "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
            "DSRPROF1|total|phase=elapsed|value_ns=1000000",
            "NWSTACK1|begin|state=kernel-oncpu|value=2",
            "0x1018",
            "0x1028",
            "NWSTACK1|end",
            "NWSTACK1|begin|state=kernel-oncpu|value=1",
            "0x1018",
            "0x1038",
            "NWSTACK1|end",
            "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
        ]
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_accepts_resolved_leaf_and_public_unresolved_caller() {
        let lines = raw_native_wall_lines();
        let mut summary =
            ProfileSummary::from_lines(&lines, ProfileCaptureStatus::default()).expect("summary");
        let raw_stacks_before = summary
            .metrics
            .iter()
            .filter_map(|metric| match &metric.metric {
                ProfileMetric::StackTrace { frames, .. } => Some(frames.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        summary
            .attach_sampled_kernel_overlay(sampled_kernel_overlay(
                &[0x1018, 0x1028],
                &[(0x1038, -1, 1015)],
            ))
            .expect("attach sampled overlay");

        let metric_types = summary
            .json_rows()
            .into_iter()
            .map(|row| {
                serde_json::to_value(row).expect("serialize")["metric"]["type"]
                    .as_str()
                    .expect("metric type")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            &metric_types[metric_types.len() - 2..],
            ["sampled-kernel-symbols", "completion"]
        );
        assert_eq!(
            summary
                .metrics
                .iter()
                .filter(|metric| {
                    matches!(metric.metric, ProfileMetric::SampledKernelSymbols { .. })
                })
                .count(),
            1
        );
        assert_eq!(
            summary
                .metrics
                .iter()
                .filter_map(|metric| match &metric.metric {
                    ProfileMetric::StackTrace { frames, .. } => Some(frames.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            raw_stacks_before
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dsrprof2_summary_overlay_accepts_v2_kernel_stack_kinds() {
        let mut summary = ProfileSummary::from_lines(
            include_str!("../tests/fixtures/dsrprof2-valid.raw").lines(),
            ProfileCaptureStatus::default(),
        )
        .expect("DSRPROF2 summary");

        summary
            .attach_sampled_kernel_overlay(sampled_kernel_overlay(
                &[0xfffffe0010010010, 0xfffffe0010020020],
                &[],
            ))
            .expect("attach sampled overlay to DSRPROF2 summary");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_accepts_libdtrace_nosym_leaf() {
        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");

        summary
            .attach_sampled_kernel_overlay(sampled_kernel_overlay(
                &[0x1028, 0x1038],
                &[(0x1018, -1, 1015)],
            ))
            .expect("attach exact unresolved kernel leaf");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_rejects_nonpublic_lookup_status() {
        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");

        assert!(
            summary
                .attach_sampled_kernel_overlay(sampled_kernel_overlay(
                    &[0x1018, 0x1028],
                    &[(0x1038, -2, 999)],
                ))
                .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_rejects_address_set_drift_and_duplicate_attachment() {
        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");
        assert!(
            summary
                .attach_sampled_kernel_overlay(sampled_kernel_overlay(&[0x1018, 0x1028], &[]))
                .is_err()
        );

        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");
        let overlay = sampled_kernel_overlay(&[0x1018, 0x1028, 0x1038], &[]);
        summary
            .attach_sampled_kernel_overlay(overlay.clone())
            .expect("first attachment");
        assert!(summary.attach_sampled_kernel_overlay(overlay).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_rejects_rows_after_completion_and_boot_identity_mismatch() {
        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");
        let late_overlay = sampled_kernel_overlay(&[0x1018, 0x1028, 0x1038], &[]);
        summary.metrics.push(ProfileOutputMetric {
            scope: ProfileScope {
                phase: None,
                pid: None,
                tid: None,
                kind: None,
                source_pc: None,
                target_pc: None,
            },
            metric: ProfileMetric::SampledKernelSymbols {
                overlay: late_overlay,
            },
            sampling_interval: None,
        });
        assert!(
            summary
                .attach_sampled_kernel_overlay(sampled_kernel_overlay(
                    &[0x1018, 0x1028, 0x1038],
                    &[]
                ))
                .is_err()
        );

        let mut summary =
            ProfileSummary::from_lines(raw_native_wall_lines(), ProfileCaptureStatus::default())
                .expect("summary");
        let overlay = sampled_kernel_overlay(&[0x1018, 0x1028, 0x1038], &[]);
        let mut mismatched_identity = overlay.identity.clone();
        mismatched_identity.bootsessionuuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_owned();
        let mut existing = overlay.clone();
        existing.identity = mismatched_identity;
        let completion = summary.metrics.len() - 1;
        summary.metrics.insert(
            completion,
            ProfileOutputMetric {
                scope: ProfileScope {
                    phase: None,
                    pid: None,
                    tid: None,
                    kind: None,
                    source_pc: None,
                    target_pc: None,
                },
                metric: ProfileMetric::SampledKernelSymbols { overlay: existing },
                sampling_interval: None,
            },
        );
        assert!(summary.attach_sampled_kernel_overlay(overlay).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sampled_kernel_overlay_rejects_raw_symbol_ranges_and_hash_drift() {
        let valid = sampled_kernel_overlay(&[0x1018, 0x1028, 0x1038], &[]);
        let mut invalid = Vec::new();
        let mut raw_symbol = valid.clone();
        raw_symbol.symbols[0].symbol = "0x1018".to_owned();
        invalid.push(raw_symbol);
        let mut zero_size = valid.clone();
        zero_size.symbols[0].symbol_size = 0;
        invalid.push(zero_size);
        let mut bad_range = valid.clone();
        bad_range.symbols[0].symbol_start = 0x2000;
        invalid.push(bad_range);
        let mut bad_offset = valid.clone();
        bad_offset.symbols[0].offset = 1;
        invalid.push(bad_offset);
        let mut bad_hash = valid;
        bad_hash.requested_sha256 = "0".repeat(64);
        invalid.push(bad_hash);

        for overlay in invalid {
            let mut summary = ProfileSummary::from_lines(
                raw_native_wall_lines(),
                ProfileCaptureStatus::default(),
            )
            .expect("summary");
            assert!(summary.attach_sampled_kernel_overlay(overlay).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_includes_all_frames_and_deduplicates() {
        let addresses =
            kernel_sample_addresses_from_lines(raw_native_wall_lines()).expect("addresses");
        assert_eq!(addresses.requested, [0x1018, 0x1028, 0x1038]);
        assert_eq!(addresses.weighted_leaves, BTreeSet::from([0x1018]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dsrprof2_kernel_address_extraction_ignores_user_offcpu_stacks() {
        let lines = [
            "DSRPROF2|cpu-kernel|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|class=kernel-named-syscall|pc=0xfffffe0010010010|count=2",
            "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=kernel-named-syscall|count=2|total_ns=0",
            "",
            "0xfffffe0010010010",
            "0xfffffe0010020020",
            "DSRSTACK2|end",
            "DSRSTACK2|begin|pid=100|start_sec=10|start_usec=20|image=1|epoch=0|kind=offcpu-runnable|count=1|total_ns=50",
            "",
            "0x100001018",
            "0x100001028",
            "DSRSTACK2|end",
        ];

        let addresses = kernel_sample_addresses_from_v2_lines(lines).expect("DSRPROF2 addresses");
        assert_eq!(
            addresses.requested,
            [0xfffffe0010010010, 0xfffffe0010020020]
        );
        assert_eq!(
            addresses.weighted_leaves,
            BTreeSet::from([0xfffffe0010010010])
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_rejects_exact_leaf_population_mismatch() {
        let lines = [
            "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0x1018|value=3",
            "NWSTACK1|begin|state=kernel-oncpu|value=2",
            "0x1018",
            "0x1028",
            "NWSTACK1|end",
            "NWSTACK1|begin|state=kernel-oncpu|value=1",
            "0x2018",
            "0x1038",
            "NWSTACK1|end",
        ];
        let error = kernel_sample_addresses_from_lines(lines)
            .expect_err("kernel PC rows must match exact weighted stack leaves");
        assert!(error.to_string().contains("leaf populations"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_rejects_missing_malformed_and_symbolic_frames() {
        for lines in [
            vec![
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`symbol",
                "NWSTACK1|end",
            ],
            vec![
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0xnothex",
                "NWSTACK1|end",
            ],
            vec!["NWSTACK1|begin|state=kernel-oncpu|value=1", "0x1018"],
            vec!["NWSTACK1|end"],
            vec![
                "NWSTACK1|begin|state=voluntary|pid=1|value_ns=1",
                "0x1018",
                "NWSTACK1|end",
            ],
        ] {
            assert!(kernel_sample_addresses_from_lines(lines).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_wall_raw_address_extraction_rejects_unknown_stack_markers() {
        for lines in [
            vec![
                "NWSTACK1|unknown",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0x1018",
                "NWSTACK1|end",
            ],
            vec![
                "NWSTACK1|begin|state=voluntary|pid=1|value_ns=1",
                "NWSTACK1|unknown",
                "0x1018",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "0x1018",
                "NWSTACK1|end",
            ],
        ] {
            assert!(kernel_sample_addresses_from_lines(lines).is_err());
        }
    }

    #[test]
    fn parses_sample_and_completion() {
        let sample = ProfileRecord::parse(
            "DSRPROF1|sample|phase=run|pid=42|tid=7|kind=3|duration_ns=9000|interval=1024",
        )
        .expect("sample");
        assert_eq!(sample.record_type, RecordType::Sample);
        assert_eq!(sample.required_u64("duration_ns").expect("duration"), 9000);
        ProfileRecord::parse("DSRPROF1|complete|profile=dsr|bounded=0").expect("complete");
    }

    #[test]
    fn profiles_requiring_runtime_metadata_enable_runtime_instrumentation() {
        assert!(TraceProfileKind::Dsr.requires_runtime_profile());
        assert!(!TraceProfileKind::DsrIndirect.requires_runtime_profile());
        assert!(TraceProfileKind::DsrFork.requires_runtime_profile());
        assert!(TraceProfileKind::NativeWall.requires_runtime_profile());
    }

    #[test]
    fn native_wall_profile_parses_reconciled_samples_and_blocking_stack() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=120",
                "DSRPROF1|count|phase=wall-state|kind=runnable-descheduled|value=40",
                "DSRPROF1|count|phase=wall-state|kind=all-sleeping|value=35",
                "DSRPROF1|count|phase=wall-state|kind=transition|value=2",
                "DSRPROF1|count|phase=wall-samples|value=197",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=499",
                "DSRPROF1|total|phase=offcpu-voluntary-pc|pid=42|source_pc=0x2000|value_ns=1000",
                "DSRPROF1|total|phase=offcpu-voluntary-total|value_ns=1000",
                "NWSTACK1|begin|state=voluntary|pid=42|value_ns=900",
                "0x2000",
                "0x3000",
                "NWSTACK1|end",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        summary
            .require_profile(TraceProfileKind::NativeWall)
            .expect("matching profile");
        assert!(summary.completion.complete);
        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize row"))
            .collect::<Vec<_>>();
        let voluntary = rows
            .iter()
            .find(|row| row["scope"]["phase"] == "offcpu-voluntary-stack")
            .expect("voluntary stack row");
        assert_eq!(voluntary["scope"]["pid"], 42);
        assert_eq!(voluntary["metric"]["state"], "voluntary");
        assert_eq!(voluntary["metric"]["pid"], 42);
        assert_eq!(voluntary["metric"]["value_ns"], 900);
        assert_eq!(voluntary["metric"].get("count"), None);
        assert_eq!(
            voluntary["metric"]["frames"],
            serde_json::json!(["0x2000", "0x3000"])
        );
    }

    #[test]
    fn native_wall_kernel_stacks_serialize_as_reconciled_counts() {
        // Catches rejecting count-valued kernel stacks or serializing pid/value_ns on them.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=2",
                "kernel`foo",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`bar",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        let rows = summary
            .json_rows()
            .into_iter()
            .map(|row| serde_json::to_value(row).expect("serialize row"))
            .collect::<Vec<_>>();
        let kernel = rows
            .iter()
            .filter(|row| row["scope"]["phase"] == "cpu-kernel-stack")
            .collect::<Vec<_>>();
        assert_eq!(kernel.len(), 2);
        assert_eq!(kernel[0]["scope"].get("pid"), None);
        assert_eq!(kernel[0]["metric"].get("pid"), None);
        assert_eq!(kernel[0]["metric"]["count"], 2);
        assert_eq!(kernel[0]["metric"].get("value_ns"), None);
        assert_eq!(kernel[1]["metric"]["count"], 1);
    }

    #[test]
    fn native_wall_kernel_stacks_must_reconcile_with_kernel_pcs() {
        // Catches accepting a kernel stack population (2) unlike the kernel PC population (3).
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=2",
                "kernel`foo",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel PC/stack mismatch must reject");
        assert!(
            error.to_string().contains("kernel stack samples"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_stack_headers_enforce_state_dependent_fields() {
        let cases = [
            (
                "accepts both value and value_ns",
                "NWSTACK1|begin|state=kernel-oncpu|value=1|value_ns=1",
                true,
            ),
            (
                "accepts neither value nor value_ns",
                "NWSTACK1|begin|state=kernel-oncpu",
                true,
            ),
            (
                "accepts a pid on kernel-oncpu",
                "NWSTACK1|begin|state=kernel-oncpu|pid=42|value=1",
                true,
            ),
            (
                "accepts an unknown field",
                "NWSTACK1|begin|state=kernel-oncpu|unknown=1|value=1",
                true,
            ),
            (
                "accepts a duplicate field",
                "NWSTACK1|begin|state=kernel-oncpu|value=1|value=1",
                true,
            ),
            ("accepts a missing state", "NWSTACK1|begin|value=1", true),
            (
                "accepts zero kernel samples",
                "NWSTACK1|begin|state=kernel-oncpu|value=0",
                true,
            ),
            (
                "accepts voluntary stack without pid",
                "NWSTACK1|begin|state=voluntary|value_ns=1",
                true,
            ),
            (
                "accepts count-valued voluntary stack",
                "NWSTACK1|begin|state=voluntary|pid=42|value=1",
                true,
            ),
            (
                "accepts zero voluntary pid",
                "NWSTACK1|begin|state=voluntary|pid=0|value_ns=1",
                true,
            ),
            (
                "accepts zero voluntary duration",
                "NWSTACK1|begin|state=voluntary|pid=42|value_ns=0",
                true,
            ),
            (
                "accepts empty kernel frames",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                false,
            ),
        ];

        for (mutation, header, include_frame) in cases {
            let mut lines = vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                header,
            ];
            if include_frame {
                lines.push("kernel`foo");
            }
            lines.extend([
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ]);
            assert!(
                ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err(),
                "production mutation {mutation:?} was not caught"
            );
        }
    }

    #[test]
    fn native_wall_historical_kernel_pcs_without_stacks_remain_valid() {
        // Catches requiring new kernel stack rows in historical profile streams.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=3",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("historical kernel-only native wall profile");
        assert!(
            summary
                .json_rows()
                .iter()
                .all(|row| row.scope.phase.as_deref() != Some("cpu-kernel-stack"))
        );
    }

    #[test]
    fn native_wall_zero_kernel_historical_input_remains_valid() {
        // Catches treating absent kernel samples/stacks as an evidence mismatch.
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("historical user-only native wall profile");
        assert!(
            summary
                .json_rows()
                .iter()
                .all(|row| row.scope.phase.as_deref() != Some("cpu-kernel-stack"))
        );
    }

    #[test]
    fn native_wall_kernel_pc_population_overflow_rejects() {
        // Catches saturating or wrapping u64::MAX + 1 while accumulating kernel PCs.
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel PC overflow must reject");
        assert!(
            error.to_string().contains("overflow"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_kernel_stack_population_overflow_rejects() {
        // Catches saturating, wrapping, or panicking on u64::MAX + 1 kernel stacks.
        let error = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-kernel-pc|source_pc=0xfffffe0012345000|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "NWSTACK1|begin|state=kernel-oncpu|value=18446744073709551615",
                "kernel`foo",
                "NWSTACK1|end",
                "NWSTACK1|begin|state=kernel-oncpu|value=1",
                "kernel`bar",
                "NWSTACK1|end",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect_err("kernel stack overflow must reject");
        assert!(
            error.to_string().contains("overflow"),
            "unexpected error: {error:#}"
        );
    }

    fn assert_native_wall_count_overflow(lines: Vec<&str>, phase: &str, mutation: &str) {
        let error = ProfileSummary::from_lines(lines, ProfileCaptureStatus::default())
            .expect_err("validation count overflow must reject");
        let message = error.to_string();
        assert!(
            message.contains(phase) && message.contains("overflow"),
            "production mutation {mutation:?} produced unexpected error: {error:#}"
        );
    }

    #[test]
    fn native_wall_cpu_user_pc_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "cpu-user-pc",
            "saturates one cpu-user-pc scope",
        );
    }

    #[test]
    fn native_wall_wall_samples_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-samples",
            "saturates one wall-samples scope",
        );
    }

    #[test]
    fn native_wall_wall_state_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-state",
            "saturates one wall-state scope",
        );
    }

    #[test]
    fn native_wall_process_lifecycle_per_scope_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=1",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "process-lifecycle",
            "saturates one process-lifecycle scope",
        );
    }

    #[test]
    fn native_wall_cpu_user_pc_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=43|source_pc=0x2000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "cpu-user-pc",
            "saturates the cpu-user-pc population across scopes",
        );
    }

    #[test]
    fn native_wall_wall_samples_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|kind=first|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-samples|kind=second|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-samples",
            "saturates the wall-samples population across scopes",
        );
    }

    #[test]
    fn native_wall_wall_state_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=18446744073709551615",
                "DSRPROF1|count|phase=wall-state|kind=transition|value=1",
                "DSRPROF1|count|phase=wall-samples|value=18446744073709551615",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "wall-state",
            "saturates the wall-state population across scopes",
        );
    }

    #[test]
    fn native_wall_process_lifecycle_population_overflow_rejects() {
        assert_native_wall_count_overflow(
            vec![
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=1",
                "DSRPROF1|count|phase=wall-samples|value=1",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=1",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|pid=42|value=18446744073709551615",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|pid=43|value=1",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            "process-lifecycle",
            "saturates the process-lifecycle population across scopes",
        );
    }

    #[test]
    fn native_wall_profile_parses_host_image_catalog() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=120",
                "DSRPROF1|count|phase=wall-samples|value=120",
                "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=499",
                "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                "DSRPROF1|total|phase=elapsed|value_ns=1000000000",
                "NWIMAGES1|{\"ok\":{\"pid\":42,\"ranges\":[{\"start\":32768,\"end\":40960,\"path\":\"/usr/lib/libSystem.B.dylib\"}]}}",
                "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete native wall profile");

        assert!(summary.metrics.iter().any(|output| matches!(
            &output.metric,
            ProfileMetric::ImageCatalog { pid: 42, ranges }
                if ranges.len() == 1
                    && ranges[0].start == 32_768
                    && ranges[0].end == 40_960
                    && ranges[0].path == "/usr/lib/libSystem.B.dylib"
        )));
    }

    #[test]
    fn native_wall_profile_rejects_unreconciled_populations() {
        let cases = [
            (
                "missing elapsed duration",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "wall bucket mismatch",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=9",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "live process at end",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=1",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "missing CPU sample",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
            (
                "voluntary time without stack",
                vec![
                    "DSRPROF1|count|phase=wall-state|kind=on-cpu|value=10",
                    "DSRPROF1|count|phase=wall-samples|value=10",
                    "DSRPROF1|count|phase=cpu-user-pc|pid=42|source_pc=0x1000|value=5",
                    "DSRPROF1|count|phase=process-lifecycle|kind=live-at-end|value=0",
                    "DSRPROF1|total|phase=elapsed|value_ns=1000",
                    "DSRPROF1|total|phase=offcpu-voluntary-total|value_ns=500",
                    "DSRPROF1|complete|profile=native-wall|bounded=0|target_exit_reason=1",
                ],
            ),
        ];

        for (case, lines) in cases {
            assert!(
                ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err(),
                "{case} was accepted"
            );
        }
    }

    #[test]
    fn rejects_unknown_duplicate_and_truncated_protocol() {
        assert!(ProfileRecord::parse("DSRPROF2|complete").is_err());
        assert!(ProfileRecord::parse("DSRPROF1|count|kind=1|kind=2").is_err());
        assert!(ProfileRecord::parse("DSRPROF1|count|pid=not-a-number").is_err());
        assert!(
            ProfileSummary::from_lines(
                ["DSRPROF1|count|phase=run|pid=1|kind=3|value=9"],
                ProfileCaptureStatus::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn empty_profile_stream_cannot_be_complete() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=1"],
            ProfileCaptureStatus::default(),
        )
        .expect("syntactically valid empty profile");
        assert!(!summary.completion.complete);
    }

    #[test]
    fn rejects_duplicate_completion_and_records_after_completion() {
        for lines in [
            vec![
                "DSRPROF1|complete|profile=dsr|bounded=0",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            vec![
                "DSRPROF1|complete|profile=dsr|bounded=0",
                "DSRPROF1|count|phase=run|value=1",
            ],
        ] {
            assert!(ProfileSummary::from_lines(lines, ProfileCaptureStatus::default()).is_err());
        }
    }

    #[test]
    fn aggregates_exact_samples_incomplete_and_high_water() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=run|pid=10|kind=3|value=9",
                "DSRPROF1|count|phase=run|pid=10|kind=3|value=2",
                "DSRPROF1|total|phase=run|pid=10|kind=3|value_ns=90000",
                "DSRPROF1|minimum|phase=run|pid=10|kind=3|value_ns=7000",
                "DSRPROF1|maximum|phase=run|pid=10|kind=3|value_ns=15000",
                "DSRPROF1|sample|phase=run|pid=10|kind=3|duration_ns=9000|interval=1024",
                "DSRPROF1|incomplete|phase=prepare|pid=10|kind=overwrite|value=1",
                "DSRPROF1|high-water|metric=cache-bytes|pid=10|used=4096|capacity=67108864",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("profile summary");
        let rows = summary.json_rows();
        assert!(!summary.completion.complete);
        assert_eq!(summary.completion.incomplete_pairs, 1);
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().any(|row| matches!(
            row.metric,
            ProfileMetric::Exact {
                count: Some(11),
                total_ns: Some(90_000),
                minimum_ns: Some(7_000),
                maximum_ns: Some(15_000)
            }
        )));
        assert!(
            rows.iter()
                .any(|row| matches!(row.metric, ProfileMetric::IncompletePair { value: 1 }))
        );
        assert!(rows.iter().any(|row| matches!(
            row.metric,
            ProfileMetric::HighWater {
                used: 4_096,
                capacity: 67_108_864,
                ..
            }
        )));
    }

    #[test]
    fn translation_subphase_aggregates_fail_closed_when_truncated() {
        assert!(
            ProfileSummary::from_lines(
                [
                    "DSRPROF1|count|phase=translation-subphase|pid=10|kind=1|value=9",
                    "DSRPROF1|complete|profile=dsr|bounded=0",
                ],
                ProfileCaptureStatus::default(),
            )
            .is_err()
        );

        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=translation-subphase|pid=10|kind=1|value=9",
                "DSRPROF1|total|phase=translation-subphase|pid=10|kind=1|value_ns=90000",
                "DSRPROF1|minimum|phase=translation-subphase|pid=10|kind=1|value_ns=7000",
                "DSRPROF1|maximum|phase=translation-subphase|pid=10|kind=1|value_ns=15000",
                "DSRPROF1|complete|profile=dsr|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("complete translation subphase");
        assert!(summary.completion.complete);
    }

    #[test]
    fn parses_hex_guest_pcs_and_marks_aggregation_loss_incomplete() {
        let status = ProfileCaptureStatus {
            aggregation_drops: 2,
            ..ProfileCaptureStatus::default()
        };
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|count|phase=indirect-source|pid=10|source_pc=0x4000|value=12",
                "DSRPROF1|count|phase=indirect-pair|pid=10|source_pc=0x4000|target_pc=0x8000|value=7",
                "DSRPROF1|complete|profile=dsr-indirect|bounded=0",
            ],
            status,
        )
        .expect("profile summary");
        assert!(!summary.completion.complete);
        assert!(summary.completion.high_cardinality_overflow);
        assert_eq!(summary.completion.cardinality.indirect_sources, 1);
        assert_eq!(summary.completion.cardinality.indirect_pairs, 1);
        assert!(summary.metrics.iter().any(|metric| {
            metric.scope.source_pc == Some(0x4000) && metric.scope.target_pc.is_none()
        }));
        assert!(summary.metrics.iter().any(|metric| {
            metric.scope.source_pc == Some(0x4000) && metric.scope.target_pc == Some(0x8000)
        }));
    }

    #[test]
    fn principal_drops_are_a_truncated_stream_error() {
        let status = ProfileCaptureStatus {
            principal_drops: 1,
            ..ProfileCaptureStatus::default()
        };
        assert!(
            ProfileSummary::from_lines(["DSRPROF1|complete|profile=dsr|bounded=0"], status)
                .is_err()
        );
    }

    #[test]
    fn signaled_target_exit_cannot_complete_a_profile() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=2"],
            ProfileCaptureStatus::default(),
        )
        .expect("signaled profile summary");
        assert!(!summary.completion.complete);
        assert_eq!(summary.completion.target_exit_reason, 2);
    }

    #[test]
    fn interrupted_capture_cannot_complete_a_profile() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr|bounded=0|target_exit_reason=1"],
            ProfileCaptureStatus {
                interrupted: true,
                ..ProfileCaptureStatus::default()
            },
        )
        .expect("interrupted profile summary");
        assert!(!summary.completion.complete);
        assert!(summary.completion.drops.interrupted);
    }

    #[test]
    fn requested_profile_must_match_stream_completion() {
        let summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr-fork|bounded=0"],
            ProfileCaptureStatus::default(),
        )
        .expect("summary");
        assert!(summary.require_profile(TraceProfileKind::Dsr).is_err());
        summary
            .require_profile(TraceProfileKind::DsrFork)
            .expect("matching profile");
    }

    #[test]
    fn fork_lifecycle_samples_and_open_pair_survive_parsing() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=fork-child-repair|pid=21|tid=21|duration_ns=1200",
                "DSRPROF1|sample|phase=first-prepare-after-fork|pid=21|tid=21|duration_ns=800",
                "DSRPROF1|sample|phase=host-self-reexec|pid=21|tid=21|duration_ns=1100",
                "DSRPROF1|sample|phase=exec-reset|pid=21|tid=21|duration_ns=900",
                "DSRPROF1|sample|phase=first-prepare-after-exec|pid=21|tid=21|duration_ns=700",
                "DSRPROF1|incomplete|phase=exec-reset|pid=21|tid=21|kind=open|value=1",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("fork profile");
        assert_eq!(
            summary
                .metrics
                .iter()
                .filter(|metric| matches!(metric.metric, ProfileMetric::SampledDuration { .. }))
                .count(),
            5
        );
        assert_eq!(summary.completion.incomplete_pairs, 1);
        assert!(!summary.completion.complete);
    }

    #[test]
    fn prepared_self_reexec_lifecycle_survives_parsing_without_legacy_load() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=host-self-reexec-prepared-build|pid=21|tid=21|duration_ns=1200",
                "DSRPROF1|sample|phase=host-self-reexec-prepared-validate|pid=21|tid=21|duration_ns=800",
                "DSRPROF1|sample|phase=host-self-reexec-prepared-map|pid=21|tid=21|duration_ns=700",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("prepared profile");
        let phases = summary
            .metrics
            .iter()
            .filter_map(|metric| metric.scope.phase.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            [
                "host-self-reexec-prepared-build",
                "host-self-reexec-prepared-map",
                "host-self-reexec-prepared-validate",
            ]
        );
        assert!(!phases.contains(&"host-self-reexec-image-load"));
        assert!(summary.completion.complete);
    }

    #[test]
    fn fallback_self_reexec_lifecycle_survives_parsing_without_prepared_map() {
        let summary = ProfileSummary::from_lines(
            [
                "DSRPROF1|sample|phase=host-self-reexec-prepared-build|pid=21|tid=21|duration_ns=900",
                "DSRPROF1|sample|phase=host-self-reexec-image-load|pid=21|tid=21|duration_ns=1700",
                "DSRPROF1|complete|profile=dsr-fork|bounded=0|target_exit_reason=1",
            ],
            ProfileCaptureStatus::default(),
        )
        .expect("fallback profile");
        let phases = summary
            .metrics
            .iter()
            .filter_map(|metric| metric.scope.phase.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            [
                "host-self-reexec-image-load",
                "host-self-reexec-prepared-build",
            ]
        );
        assert!(!phases.contains(&"host-self-reexec-prepared-map"));
        assert_eq!(summary.completion.incomplete_pairs, 0);
        assert!(summary.completion.complete);
    }

    #[test]
    fn writes_provenance_rich_jsonl_atomically() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("profile.jsonl");
        let mut summary = ProfileSummary::from_lines(
            ["DSRPROF1|complete|profile=dsr-fork|bounded=0"],
            ProfileCaptureStatus::default(),
        )
        .expect("summary");
        summary.set_provenance(ProfileProvenance {
            run_id: "test-run".to_owned(),
            git_sha: "abc123".to_owned(),
            git_dirty: Some(true),
            binary_sha256: "def456".to_owned(),
            command: vec!["run-elf".to_owned(), "fixture".to_owned()],
            host: "test-host".to_owned(),
        });
        write_summary_atomic(&path, &summary, None).expect("write summary");
        let contents = fs::read_to_string(path).expect("read summary");
        let row: serde_json::Value = serde_json::from_str(contents.trim()).expect("JSON row");
        assert_eq!(row["schema"], JSON_SCHEMA);
        assert_eq!(row["run_id"], "test-run");
        assert_eq!(row["git_dirty"], true);
        assert_eq!(row["metric"]["type"], "completion");
    }
}
