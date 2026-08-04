use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::trace_profile::{ProfileCaptureStatus, ProfileProvenance, V2ProfileAuthority};

const JSON_SCHEMA: &str = "carrick.native-fault-attribution.v3";
const PAGE_SIZE: u64 = 16_384;
const PAGE_SAMPLE_MODULUS: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct BirthKey {
    pid: u32,
    start_sec: u64,
    start_usec: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ImageKey {
    #[serde(flatten)]
    birth: BirthKey,
    image: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForkLink {
    child: ImageKey,
    child_epoch: u64,
    fork_id: u64,
    parent: ImageKey,
    parent_epoch: u64,
    frontier: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedRange {
    start: u64,
    end: u64,
}

#[derive(Debug)]
struct CatalogBuilder {
    epoch: u64,
    ranges: Vec<OwnedRange>,
    ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Outcome {
    AsFault,
    Zfod,
    CowFault,
}

impl Outcome {
    fn parse(value: &str, addressed_only: bool) -> Result<Self> {
        let outcome = match value {
            "as_fault" => Self::AsFault,
            "zfod" => Self::Zfod,
            "cow_fault" if !addressed_only => Self::CowFault,
            _ => bail!("unknown native-fault outcome {value:?}"),
        };
        Ok(outcome)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::AsFault => "as_fault",
            Self::Zfod => "zfod",
            Self::CowFault => "cow_fault",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Ownership {
    GuestOwned,
    HostOther,
}

impl Ownership {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GuestOwned => "guest-owned",
            Self::HostOther => "host-other",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PageSample {
    outcome: Outcome,
    key: ImageKey,
    page: u64,
    count: u64,
}

#[derive(Clone, Debug)]
struct MemoryIntentRecord {
    key: ImageKey,
    tid: u64,
    sequence: u64,
    number: u64,
    entry_ns: u64,
    return_ns: u64,
    args: [u64; 6],
    retval: i64,
    errno: u32,
    completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryFaultScope {
    ActiveMemory,
    GuestArena,
}

#[derive(Clone, Debug)]
struct MemoryFaultEvent {
    key: ImageKey,
    tid: u64,
    timestamp_ns: u64,
    page: u64,
    active_number: u64,
    active_sequence: u64,
    scope: MemoryFaultScope,
}

#[derive(Clone, Copy, Debug)]
struct ProcessState {
    image: u64,
    epoch: u64,
    alive: bool,
    exec_attempt: Option<(u64, u64)>,
    image_map_pending: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct NativeFaultCompletion {
    bounded: bool,
    timed_out: bool,
    target_exit: bool,
    target_exit_reason: u64,
    identity_violations: u64,
    lifecycle_violations: u64,
    catalog_violations: u64,
    probe_errors: u64,
    live_at_end: u64,
    pending_forks: u64,
    elapsed_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultExactTotal {
    outcome: &'static str,
    count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultRejectedTotal {
    outcome: &'static str,
    count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultSampleCoverage {
    outcome: &'static str,
    exact_events: u64,
    sampled_events: u64,
    distinct_process_pages: u64,
    sample_modulus: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultOwnershipBucket {
    outcome: &'static str,
    ownership: &'static str,
    pub(crate) sampled_events: u64,
    pub(crate) distinct_process_pages: u64,
    pub(crate) repeat_excess: u64,
    repeat_factor: f64,
    pub(crate) sample_share: f64,
    pub(crate) scaled_event_estimate: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultProcessSummary {
    #[serde(flatten)]
    birth: BirthKey,
    exact_as_fault: u64,
    exact_zfod: u64,
    exact_cow_fault: u64,
    rejected_as_fault: u64,
    rejected_zfod: u64,
    sampled_as_fault: u64,
    sampled_zfod: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultHotPage {
    outcome: &'static str,
    ownership: &'static str,
    #[serde(flatten)]
    key: ImageKey,
    page: u64,
    count: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct NativeMemoryCensus {
    total_zfod: u64,
    exported_zfod: u64,
    unexported_zfod: u64,
    intent_records: u64,
    completed_intents: u64,
    aborted_intents: u64,
    active_memory_faults: u64,
    guest_arena_faults: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeMemoryOperationBucket {
    operation: &'static str,
    shape: String,
    calls: u64,
    requested_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeMemoryFaultBucket {
    phase: &'static str,
    semantic_sequence: String,
    mapping_provenance: String,
    exact_zfod: u64,
    share_of_all_zfod: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct NativeFaultProvenance {
    run_id: String,
    git_sha: String,
    git_dirty: Option<bool>,
    binary_sha256: String,
    command: Vec<String>,
    host: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NativeFaultSummary {
    pub(crate) schema: &'static str,
    profile: &'static str,
    pub(crate) gating_eligible: bool,
    perturbation: &'static str,
    raw_sha256: String,
    authority_header: String,
    os_build: String,
    program_sha256: String,
    birth_qualification_sha256: String,
    terminal_qualification_sha256: String,
    page_sample_modulus: u64,
    capture: ProfileCaptureStatus,
    completion: NativeFaultCompletion,
    exact_totals: Vec<NativeFaultExactTotal>,
    rejected_totals: Vec<NativeFaultRejectedTotal>,
    sample_coverage: Vec<NativeFaultSampleCoverage>,
    ownership: Vec<NativeFaultOwnershipBucket>,
    processes: Vec<NativeFaultProcessSummary>,
    hot_pages: Vec<NativeFaultHotPage>,
    memory_census: NativeMemoryCensus,
    memory_operations: Vec<NativeMemoryOperationBucket>,
    memory_faults: Vec<NativeMemoryFaultBucket>,
    pub(crate) excluded_processes: u64,
    provenance: NativeFaultProvenance,
}

#[derive(Debug)]
struct RawRecord {
    kind: String,
    fields: BTreeMap<String, String>,
}

impl RawRecord {
    fn parse(line: &str, line_number: usize) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some("NFAULT2") {
            bail!("line {line_number}: expected NFAULT2 record prefix");
        }
        let kind = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("line {line_number}: missing NFAULT2 record kind"))?;
        let mut fields = BTreeMap::new();
        for field in parts {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| anyhow!("line {line_number}: malformed field {field:?}"))?;
            if name.is_empty() || value.is_empty() {
                bail!("line {line_number}: empty NFAULT2 field name or value");
            }
            if fields.insert(name.to_owned(), value.to_owned()).is_some() {
                bail!("line {line_number}: duplicate field {name:?}");
            }
        }
        Ok(Self {
            kind: kind.to_owned(),
            fields,
        })
    }

    fn require_fields(&self, expected: &[&str], line_number: usize) -> Result<()> {
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
                "line {line_number}: {} field set mismatch: missing={missing:?}, extra={extra:?}",
                self.kind
            );
        }
        Ok(())
    }

    fn text(&self, name: &str) -> Result<&str> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{} record lacks field {name:?}", self.kind))
    }

    fn number(&self, name: &str) -> Result<u64> {
        let value = self.text(name)?;
        if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
                .with_context(|| format!("{} field {name} is not hexadecimal", self.kind))
        } else {
            value
                .parse::<u64>()
                .with_context(|| format!("{} field {name} is not unsigned decimal", self.kind))
        }
    }

    fn boolean(&self, name: &str) -> Result<bool> {
        match self.text(name)? {
            "0" => Ok(false),
            "1" => Ok(true),
            value => bail!("{} field {name} is not 0 or 1: {value:?}", self.kind),
        }
    }

    fn signed_number(&self, name: &str) -> Result<i64> {
        self.text(name)?
            .parse::<i64>()
            .with_context(|| format!("{} field {name} is not signed decimal", self.kind))
    }
}

#[derive(Default)]
struct NativeFaultValidator {
    header_seen: bool,
    completion: Option<NativeFaultCompletion>,
    births: BTreeSet<BirthKey>,
    birth_by_pid: BTreeMap<u32, BTreeSet<BirthKey>>,
    target: Option<ImageKey>,
    states: BTreeMap<BirthKey, ProcessState>,
    creates: BTreeMap<ImageKey, ForkLink>,
    inherits: BTreeMap<ImageKey, ForkLink>,
    catalogs: BTreeMap<ImageKey, CatalogBuilder>,
    exits: BTreeMap<BirthKey, (ImageKey, u64, u64)>,
    pages: BTreeMap<(Outcome, ImageKey, u64), u64>,
    totals: BTreeMap<(BirthKey, Outcome), u64>,
    rejected: BTreeMap<(BirthKey, Outcome), u64>,
    prebirth_pages: BTreeMap<(Outcome, u64, u64), u64>,
    prebirth_totals: BTreeMap<(u64, Outcome), u64>,
    prebirth_rejected: BTreeMap<(u64, Outcome), u64>,
    last_memory_sequence: BTreeMap<BirthKey, u64>,
    memory_intents: u64,
    fault_events: u64,
    active_memory_faults: u64,
    guest_arena_faults: u64,
    memory_counts: BTreeMap<String, u64>,
    memory_intent_records: Vec<MemoryIntentRecord>,
    memory_fault_events: Vec<MemoryFaultEvent>,
    completed_memory_intents: u64,
    aborted_memory_intents: u64,
}

impl NativeFaultValidator {
    fn require_birth(&self, birth: BirthKey, context: &str) -> Result<()> {
        if !self.births.contains(&birth) {
            let same_pid = self
                .birth_by_pid
                .get(&birth.pid)
                .cloned()
                .unwrap_or_default();
            bail!(
                "{context} identity does not match a published birth: requested={birth:?}, same_pid={same_pid:?}"
            );
        }
        Ok(())
    }

    fn add_birth(&mut self, record: &RawRecord) -> Result<()> {
        let birth = birth_from(record, "pid", "start_sec", "start_usec")?;
        if !self.births.insert(birth) {
            bail!("duplicate birth record for {birth:?}");
        }
        self.birth_by_pid
            .entry(birth.pid)
            .or_default()
            .insert(birth);
        Ok(())
    }

    fn add_target(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "target-birth")?;
        if key.image != 1 {
            bail!("target-birth initial image must be 1");
        }
        if self.target.replace(key).is_some() {
            bail!("duplicate target-birth record");
        }
        if self
            .states
            .insert(
                key.birth,
                ProcessState {
                    image: key.image,
                    epoch: 0,
                    alive: true,
                    exec_attempt: None,
                    image_map_pending: None,
                },
            )
            .is_some()
        {
            bail!("duplicate target process state");
        }
        Ok(())
    }

    fn add_create(&mut self, record: &RawRecord, inherited: bool) -> Result<()> {
        let child = image_from(
            record,
            "child_pid",
            "child_sec",
            "child_usec",
            "child_image",
        )?;
        let parent = image_from(
            record,
            "parent_pid",
            "parent_sec",
            "parent_usec",
            "parent_image",
        )?;
        self.require_birth(child.birth, "fork child")?;
        self.require_birth(parent.birth, "fork parent")?;
        let parent_state = active_state(&mut self.states, parent.birth, "fork parent")?;
        let parent_epoch = nonzero(record.number("parent_epoch")?, "parent_epoch")?;
        if parent_state.image != parent.image || parent_state.epoch != parent_epoch {
            bail!("fork parent lifecycle identity drift");
        }
        let link = ForkLink {
            child,
            child_epoch: nonzero(record.number("child_epoch")?, "child_epoch")?,
            fork_id: nonzero(record.number("fork_id")?, "fork_id")?,
            parent,
            parent_epoch,
            frontier: inherited
                .then(|| record.number("range_frontier"))
                .transpose()?,
        };
        if child.image != 1 {
            bail!("fork child initial image must be 1");
        }
        let links = if inherited {
            &mut self.inherits
        } else {
            &mut self.creates
        };
        if links.insert(child, link).is_some() {
            bail!("duplicate parent declaration for fork child {child:?}");
        }
        if !inherited {
            if self.states.contains_key(&child.birth)
                && self
                    .target
                    .is_some_and(|target| target.birth != child.birth)
            {
                bail!("duplicate parent process state for fork child {child:?}");
            }
            self.states.entry(child.birth).or_insert(ProcessState {
                image: child.image,
                epoch: link.child_epoch,
                alive: true,
                exec_attempt: None,
                image_map_pending: None,
            });
        }
        Ok(())
    }

    fn add_catalog_reset(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "catalog-reset")?;
        let epoch = nonzero(record.number("epoch")?, "catalog epoch")?;
        let state = self
            .states
            .get_mut(&key.birth)
            .ok_or_else(|| anyhow!("catalog-reset identity has no tracked process state"))?;
        if !state.alive || state.image != key.image || (state.epoch != 0 && state.epoch != epoch) {
            bail!("catalog-reset identity drift from active process state");
        }
        state.epoch = epoch;
        if self
            .catalogs
            .insert(
                key,
                CatalogBuilder {
                    epoch,
                    ranges: Vec::new(),
                    ready: false,
                },
            )
            .is_some()
        {
            bail!("duplicate catalog reset for {key:?}");
        }
        Ok(())
    }

    fn add_catalog_range(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "catalog-range")?;
        let epoch = nonzero(record.number("epoch")?, "catalog epoch")?;
        let sequence = nonzero(record.number("sequence")?, "catalog sequence")?;
        let range = OwnedRange {
            start: record.number("start")?,
            end: record.number("end")?,
        };
        if range.start >= range.end
            || !range.start.is_multiple_of(PAGE_SIZE)
            || !range.end.is_multiple_of(PAGE_SIZE)
        {
            bail!("catalog range is empty, reversed, or not page aligned");
        }
        let catalog = self
            .catalogs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("catalog range has no reset for {key:?}"))?;
        if catalog.epoch != epoch || catalog.ready {
            bail!("catalog range identity or ready-state drift");
        }
        let expected = u64::try_from(catalog.ranges.len())?
            .checked_add(1)
            .ok_or_else(|| anyhow!("catalog sequence overflow"))?;
        if sequence != expected {
            bail!("catalog sequence {sequence} does not match expected {expected}");
        }
        if let Some(previous) = catalog.ranges.last()
            && range.start < previous.end
        {
            bail!("catalog ranges overlap or are not sorted");
        }
        catalog.ranges.push(range);
        Ok(())
    }

    fn add_catalog_ready(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "catalog-ready")?;
        let epoch = nonzero(record.number("epoch")?, "catalog epoch")?;
        let final_sequence = nonzero(record.number("final_sequence")?, "final_sequence")?;
        let catalog = self
            .catalogs
            .get_mut(&key)
            .ok_or_else(|| anyhow!("catalog-ready has no reset for {key:?}"))?;
        if catalog.ready || catalog.epoch != epoch {
            bail!("catalog-ready identity drift or duplicate ready record");
        }
        if u64::try_from(catalog.ranges.len())? != final_sequence {
            bail!("catalog-ready frontier does not match complete range sequence");
        }
        catalog.ready = true;
        Ok(())
    }

    fn add_exec_attempt(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "exec-attempt")?;
        let epoch = nonzero(record.number("epoch")?, "exec epoch")?;
        let state = active_state(&mut self.states, key.birth, "exec-attempt")?;
        if state.image != key.image || state.epoch != epoch || state.exec_attempt.is_some() {
            bail!("exec-attempt lifecycle identity drift");
        }
        state.exec_attempt = Some((key.image, epoch));
        Ok(())
    }

    fn add_exec_failure(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "exec-failure")?;
        let epoch = nonzero(record.number("epoch")?, "exec epoch")?;
        let state = active_state(&mut self.states, key.birth, "exec-failure")?;
        if state.exec_attempt != Some((key.image, epoch)) {
            bail!("exec-failure does not close its exec-attempt");
        }
        state.exec_attempt = None;
        Ok(())
    }

    fn add_exec_success(&mut self, record: &RawRecord) -> Result<()> {
        let birth = birth_from(record, "pid", "start_sec", "start_usec")?;
        self.require_birth(birth, "exec-success")?;
        let retired_image = nonzero(record.number("retired_image")?, "retired_image")?;
        let retired_epoch = nonzero(record.number("retired_epoch")?, "retired_epoch")?;
        let new_image = nonzero(record.number("new_image")?, "new_image")?;
        if new_image
            != retired_image
                .checked_add(1)
                .ok_or_else(|| anyhow!("image overflow"))?
        {
            bail!("exec-success image generation is not consecutive");
        }
        let state = active_state(&mut self.states, birth, "exec-success")?;
        if state.exec_attempt != Some((retired_image, retired_epoch)) {
            bail!("exec-success does not close its exec-attempt");
        }
        state.image = new_image;
        state.epoch = 0;
        state.exec_attempt = None;
        Ok(())
    }

    fn add_image_map_begin(&mut self, record: &RawRecord) -> Result<()> {
        let birth = birth_from(record, "pid", "start_sec", "start_usec")?;
        self.require_birth(birth, "image-map-begin")?;
        let retired_image = nonzero(record.number("retired_image")?, "retired_image")?;
        let retired_epoch = nonzero(record.number("retired_epoch")?, "retired_epoch")?;
        let new_image = nonzero(record.number("new_image")?, "new_image")?;
        if new_image
            != retired_image
                .checked_add(1)
                .ok_or_else(|| anyhow!("image overflow"))?
        {
            bail!("image-map-begin image generation is not consecutive");
        }
        let state = active_state(&mut self.states, birth, "image-map-begin")?;
        if state.image != retired_image
            || state.epoch != retired_epoch
            || state.image_map_pending.is_some()
        {
            bail!("image-map-begin lifecycle identity drift");
        }
        state.image = new_image;
        state.epoch = 0;
        state.image_map_pending = Some(new_image);
        Ok(())
    }

    fn add_image_map_end(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "image-map-end")?;
        let state = active_state(&mut self.states, key.birth, "image-map-end")?;
        if state.image_map_pending != Some(key.image) || state.image != key.image {
            bail!("image-map-end lifecycle identity drift");
        }
        state.image_map_pending = None;
        Ok(())
    }

    fn add_exit(&mut self, record: &RawRecord) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "process-exit")?;
        let epoch = nonzero(record.number("epoch")?, "exit epoch")?;
        let reason = nonzero(record.number("reason")?, "exit reason")?;
        let state = active_state(&mut self.states, key.birth, "process-exit")?;
        if state.image != key.image
            || state.epoch != epoch
            || state.exec_attempt.is_some()
            || state.image_map_pending.is_some()
        {
            bail!("process-exit lifecycle identity drift");
        }
        state.alive = false;
        if self.exits.insert(key.birth, (key, epoch, reason)).is_some() {
            bail!("duplicate process-exit record");
        }
        Ok(())
    }

    fn add_page(&mut self, record: &RawRecord) -> Result<()> {
        let outcome = Outcome::parse(record.text("outcome")?, true)?;
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "page sample")?;
        let page = record.number("page")?;
        if page == 0 || page >= 0x0001_0000_0000_0000 || !page.is_multiple_of(PAGE_SIZE) {
            bail!("sampled page is zero, noncanonical, or not page aligned");
        }
        let count = nonzero(record.number("count")?, "page sample count")?;
        if self.pages.insert((outcome, key, page), count).is_some() {
            bail!("duplicate sampled process-page record");
        }
        Ok(())
    }

    fn add_total(&mut self, record: &RawRecord, rejected: bool) -> Result<()> {
        let outcome = Outcome::parse(record.text("outcome")?, rejected)?;
        let birth = birth_from(record, "pid", "start_sec", "start_usec")?;
        self.require_birth(
            birth,
            if rejected {
                "rejected total"
            } else {
                "exact total"
            },
        )?;
        let count = nonzero(
            record.number("count")?,
            if rejected {
                "rejected count"
            } else {
                "exact total count"
            },
        )?;
        let totals = if rejected {
            &mut self.rejected
        } else {
            &mut self.totals
        };
        if totals.insert((birth, outcome), count).is_some() {
            bail!(
                "duplicate {} record",
                if rejected { "rejected" } else { "total" }
            );
        }
        Ok(())
    }

    fn add_prebirth_page(&mut self, record: &RawRecord) -> Result<()> {
        let outcome = Outcome::parse(record.text("outcome")?, true)?;
        let fork_id = nonzero(record.number("fork_id")?, "prebirth fork_id")?;
        let page = record.number("page")?;
        if page == 0 || page >= 0x0001_0000_0000_0000 || !page.is_multiple_of(PAGE_SIZE) {
            bail!("prebirth sampled page is zero, noncanonical, or not page aligned");
        }
        let count = nonzero(record.number("count")?, "prebirth page count")?;
        if self
            .prebirth_pages
            .insert((outcome, fork_id, page), count)
            .is_some()
        {
            bail!("duplicate prebirth sampled page record");
        }
        Ok(())
    }

    fn add_prebirth_total(&mut self, record: &RawRecord, rejected: bool) -> Result<()> {
        let outcome = Outcome::parse(record.text("outcome")?, rejected)?;
        let fork_id = nonzero(record.number("fork_id")?, "prebirth fork_id")?;
        let count = nonzero(record.number("count")?, "prebirth total count")?;
        let totals = if rejected {
            &mut self.prebirth_rejected
        } else {
            &mut self.prebirth_totals
        };
        if totals.insert((fork_id, outcome), count).is_some() {
            bail!("duplicate prebirth total record");
        }
        Ok(())
    }

    fn add_memory_intent(&mut self, record: &RawRecord, completed: bool) -> Result<()> {
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "memory-intent")?;
        let state = active_state(&mut self.states, key.birth, "memory-intent")?;
        if state.image != key.image {
            bail!("memory-intent image drift from active process state");
        }
        let tid = nonzero(record.number("tid")?, "memory-intent tid")?;
        let sequence = nonzero(record.number("sequence")?, "memory-intent sequence")?;
        let expected = self
            .last_memory_sequence
            .get(&key.birth)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("memory-intent sequence overflow"))?;
        if sequence != expected {
            bail!("memory-intent sequence {sequence} does not match expected {expected}");
        }
        self.last_memory_sequence.insert(key.birth, sequence);
        let number = record.number("number")?;
        if !matches!(number, 215 | 222 | 226 | 233) {
            bail!("unknown memory-intent syscall number {number}");
        }
        let entry_ns = nonzero(record.number("entry_ns")?, "memory-intent entry_ns")?;
        let end_field = if completed {
            "return_ns"
        } else {
            "terminal_ns"
        };
        let return_ns = nonzero(record.number(end_field)?, "memory-intent end timestamp")?;
        if return_ns < entry_ns {
            bail!("memory-intent return precedes entry");
        }
        let args = [
            record.number("arg0")?,
            record.number("arg1")?,
            record.number("arg2")?,
            record.number("arg3")?,
            record.number("arg4")?,
            record.number("arg5")?,
        ];
        let (retval, errno) = if completed {
            let retval = record.signed_number("retval")?;
            let errno = record.number("errno")?;
            let Ok(errno) = u32::try_from(errno) else {
                bail!("memory-intent errno exceeds u32");
            };
            (retval, errno)
        } else {
            match record.text("reason")? {
                "thread-exit" | "process-exit" => {}
                other => bail!("unknown memory-intent abort reason {other:?}"),
            }
            (-1, 0)
        };
        self.memory_intent_records.push(MemoryIntentRecord {
            key,
            tid,
            sequence,
            number,
            entry_ns,
            return_ns,
            args,
            retval,
            errno,
            completed,
        });
        self.memory_intents = self
            .memory_intents
            .checked_add(1)
            .ok_or_else(|| anyhow!("memory-intent record count overflow"))?;
        let counter = if completed {
            &mut self.completed_memory_intents
        } else {
            &mut self.aborted_memory_intents
        };
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("memory-intent outcome count overflow"))?;
        Ok(())
    }

    fn add_fault_event(&mut self, record: &RawRecord) -> Result<()> {
        if Outcome::parse(record.text("outcome")?, true)? != Outcome::Zfod {
            bail!("memory fault-event outcome must be zfod");
        }
        let key = image_from(record, "pid", "start_sec", "start_usec", "image")?;
        self.require_birth(key.birth, "fault-event")?;
        let state = active_state(&mut self.states, key.birth, "fault-event")?;
        if state.image != key.image {
            bail!("fault-event image drift from active process state");
        }
        let tid = nonzero(record.number("tid")?, "fault-event tid")?;
        let timestamp_ns = nonzero(record.number("timestamp_ns")?, "fault-event timestamp_ns")?;
        let page = record.number("page")?;
        if page == 0 || page >= 0x0001_0000_0000_0000 || !page.is_multiple_of(PAGE_SIZE) {
            bail!("fault-event page is zero, noncanonical, or not page aligned");
        }
        let active_number = record.number("active_number")?;
        let active_sequence = record.number("active_sequence")?;
        let scope = record.text("scope")?;
        let scope = match scope {
            "active-memory" => {
                if !matches!(active_number, 215 | 222 | 226 | 233) || active_sequence == 0 {
                    bail!("active-memory fault lacks a valid memory intent");
                }
                self.active_memory_faults = self
                    .active_memory_faults
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("active memory fault count overflow"))?;
                MemoryFaultScope::ActiveMemory
            }
            "guest-arena" => {
                if active_number != 0 || active_sequence != 0 {
                    bail!("guest-arena fault unexpectedly names an active memory intent");
                }
                self.guest_arena_faults = self
                    .guest_arena_faults
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("guest arena fault count overflow"))?;
                MemoryFaultScope::GuestArena
            }
            other => bail!("unknown fault-event scope {other:?}"),
        };
        self.memory_fault_events.push(MemoryFaultEvent {
            key,
            tid,
            timestamp_ns,
            page,
            active_number,
            active_sequence,
            scope,
        });
        self.fault_events = self
            .fault_events
            .checked_add(1)
            .ok_or_else(|| anyhow!("fault-event count overflow"))?;
        Ok(())
    }

    fn add_memory_count(&mut self, record: &RawRecord) -> Result<()> {
        let kind = record.text("kind")?;
        if !matches!(
            kind,
            "total-zfod"
                | "exported-zfod"
                | "unexported-zfod"
                | "intent-entries"
                | "intent-returns"
                | "intent-aborts"
        ) {
            bail!("unknown memory-count kind {kind:?}");
        }
        let count = nonzero(record.number("count")?, "memory-count")?;
        if self.memory_counts.insert(kind.to_owned(), count).is_some() {
            bail!("duplicate memory-count record for {kind}");
        }
        Ok(())
    }

    fn add_completion(&mut self, record: &RawRecord) -> Result<()> {
        if record.text("profile")? != "native-fault" {
            bail!("completion profile is not native-fault");
        }
        let completion = NativeFaultCompletion {
            bounded: record.boolean("bounded")?,
            timed_out: record.boolean("timed_out")?,
            target_exit: record.boolean("target_exit")?,
            target_exit_reason: record.number("target_exit_reason")?,
            identity_violations: record.number("identity_violations")?,
            lifecycle_violations: record.number("lifecycle_violations")?,
            catalog_violations: record.number("catalog_violations")?,
            probe_errors: record.number("probe_errors")?,
            live_at_end: record.number("live_at_end")?,
            pending_forks: record.number("pending_forks")?,
            elapsed_ns: record.number("elapsed_ns")?,
        };
        if self.completion.replace(completion).is_some() {
            bail!("duplicate completion record");
        }
        Ok(())
    }
}

impl NativeFaultSummary {
    pub(crate) fn from_path(
        path: &Path,
        capture: ProfileCaptureStatus,
        authority: V2ProfileAuthority,
    ) -> Result<Self> {
        require_lossless_capture(capture)?;
        let raw = fs::read(path)
            .with_context(|| format!("read native-fault stream {}", path.display()))?;
        let raw_sha256 = format!("{:x}", Sha256::digest(&raw));
        let reader = BufReader::new(
            File::open(path)
                .with_context(|| format!("open native-fault stream {}", path.display()))?,
        );
        let expected_header = authority.header_record();
        let mut validator = NativeFaultValidator::default();
        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line.with_context(|| format!("read native-fault line {line_number}"))?;
            if line.is_empty() {
                continue;
            }
            if validator.completion.is_some() {
                bail!("line {line_number}: record appears after completion");
            }
            let record = RawRecord::parse(&line, line_number)?;
            match record.kind.as_str() {
                "header" => {
                    record.require_fields(
                        &[
                            "profile",
                            "raw_schema",
                            "os_build",
                            "program_sha256",
                            "birth_qualification_sha256",
                            "terminal_qualification_sha256",
                            "page_sample_modulus",
                        ],
                        line_number,
                    )?;
                    if validator.header_seen {
                        bail!("duplicate native-fault header");
                    }
                    if line != expected_header {
                        bail!("native-fault header does not match launch authority");
                    }
                    validator.header_seen = true;
                }
                kind if !validator.header_seen => {
                    bail!("line {line_number}: {kind} record precedes authenticated header")
                }
                "birth" => {
                    record.require_fields(&["pid", "start_sec", "start_usec"], line_number)?;
                    validator.add_birth(&record)?;
                }
                "target-birth" => {
                    record.require_fields(
                        &["pid", "start_sec", "start_usec", "image"],
                        line_number,
                    )?;
                    validator.add_target(&record)?;
                }
                "process-create" => {
                    record.require_fields(
                        &[
                            "child_pid",
                            "child_sec",
                            "child_usec",
                            "child_image",
                            "child_epoch",
                            "fork_id",
                            "parent_pid",
                            "parent_sec",
                            "parent_usec",
                            "parent_image",
                            "parent_epoch",
                        ],
                        line_number,
                    )?;
                    validator.add_create(&record, false)?;
                }
                "fork-inherit" => {
                    record.require_fields(
                        &[
                            "child_pid",
                            "child_sec",
                            "child_usec",
                            "child_image",
                            "child_epoch",
                            "fork_id",
                            "parent_pid",
                            "parent_sec",
                            "parent_usec",
                            "parent_image",
                            "parent_epoch",
                            "range_frontier",
                        ],
                        line_number,
                    )?;
                    validator.add_create(&record, true)?;
                }
                "catalog-reset" => {
                    record.require_fields(
                        &["pid", "start_sec", "start_usec", "image", "epoch"],
                        line_number,
                    )?;
                    validator.add_catalog_reset(&record)?;
                }
                "catalog-range" => {
                    record.require_fields(
                        &[
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "epoch",
                            "sequence",
                            "start",
                            "end",
                        ],
                        line_number,
                    )?;
                    validator.add_catalog_range(&record)?;
                }
                "catalog-ready" => {
                    record.require_fields(
                        &[
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "epoch",
                            "final_sequence",
                        ],
                        line_number,
                    )?;
                    validator.add_catalog_ready(&record)?;
                }
                "exec-attempt" | "exec-failure" => {
                    record.require_fields(
                        &["pid", "start_sec", "start_usec", "image", "epoch"],
                        line_number,
                    )?;
                    if record.kind == "exec-attempt" {
                        validator.add_exec_attempt(&record)?;
                    } else {
                        validator.add_exec_failure(&record)?;
                    }
                }
                "exec-success" | "image-map-begin" => {
                    record.require_fields(
                        &[
                            "pid",
                            "start_sec",
                            "start_usec",
                            "retired_image",
                            "retired_epoch",
                            "new_image",
                        ],
                        line_number,
                    )?;
                    if record.kind == "exec-success" {
                        validator.add_exec_success(&record)?;
                    } else {
                        validator.add_image_map_begin(&record)?;
                    }
                }
                "image-map-end" => {
                    record.require_fields(
                        &["pid", "start_sec", "start_usec", "image"],
                        line_number,
                    )?;
                    validator.add_image_map_end(&record)?;
                }
                "process-exit" => {
                    record.require_fields(
                        &["pid", "start_sec", "start_usec", "image", "epoch", "reason"],
                        line_number,
                    )?;
                    validator.add_exit(&record)?;
                }
                "page" => {
                    record.require_fields(
                        &[
                            "outcome",
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "page",
                            "count",
                        ],
                        line_number,
                    )?;
                    validator.add_page(&record)?;
                }
                "total" | "rejected" => {
                    record.require_fields(
                        &["outcome", "pid", "start_sec", "start_usec", "count"],
                        line_number,
                    )?;
                    validator.add_total(&record, record.kind == "rejected")?;
                }
                "prebirth-page" => {
                    record.require_fields(&["outcome", "fork_id", "page", "count"], line_number)?;
                    validator.add_prebirth_page(&record)?;
                }
                "prebirth-total" | "prebirth-rejected" => {
                    record.require_fields(&["outcome", "fork_id", "count"], line_number)?;
                    validator.add_prebirth_total(&record, record.kind == "prebirth-rejected")?;
                }
                "memory-intent" => {
                    record.require_fields(
                        &[
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "tid",
                            "sequence",
                            "number",
                            "entry_ns",
                            "return_ns",
                            "arg0",
                            "arg1",
                            "arg2",
                            "arg3",
                            "arg4",
                            "arg5",
                            "retval",
                            "errno",
                        ],
                        line_number,
                    )?;
                    validator.add_memory_intent(&record, true)?;
                }
                "memory-intent-abort" => {
                    record.require_fields(
                        &[
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "tid",
                            "sequence",
                            "number",
                            "entry_ns",
                            "terminal_ns",
                            "arg0",
                            "arg1",
                            "arg2",
                            "arg3",
                            "arg4",
                            "arg5",
                            "reason",
                        ],
                        line_number,
                    )?;
                    validator.add_memory_intent(&record, false)?;
                }
                "fault-event" => {
                    record.require_fields(
                        &[
                            "outcome",
                            "pid",
                            "start_sec",
                            "start_usec",
                            "image",
                            "tid",
                            "timestamp_ns",
                            "page",
                            "active_number",
                            "active_sequence",
                            "scope",
                        ],
                        line_number,
                    )?;
                    validator.add_fault_event(&record)?;
                }
                "memory-count" => {
                    record.require_fields(&["kind", "count"], line_number)?;
                    validator.add_memory_count(&record)?;
                }
                "complete" => {
                    record.require_fields(
                        &[
                            "profile",
                            "bounded",
                            "timed_out",
                            "target_exit",
                            "target_exit_reason",
                            "identity_violations",
                            "lifecycle_violations",
                            "catalog_violations",
                            "probe_errors",
                            "live_at_end",
                            "pending_forks",
                            "elapsed_ns",
                        ],
                        line_number,
                    )?;
                    validator.add_completion(&record)?;
                }
                kind => bail!("line {line_number}: unknown NFAULT2 record kind {kind:?}"),
            }
        }
        Self::finish(validator, capture, authority, expected_header, raw_sha256)
    }

    fn finish(
        mut validator: NativeFaultValidator,
        capture: ProfileCaptureStatus,
        authority: V2ProfileAuthority,
        authority_header: String,
        raw_sha256: String,
    ) -> Result<Self> {
        if !validator.header_seen {
            bail!("native-fault stream has no authenticated header");
        }
        let completion = validator
            .completion
            .ok_or_else(|| anyhow!("native-fault stream has no completion record"))?;
        require_natural_completion(completion)?;
        let target = validator
            .target
            .ok_or_else(|| anyhow!("native-fault stream has no target-birth"))?;
        validate_fork_links(&validator)?;
        bind_prebirth_records(&mut validator)?;
        let reachable = reachable_births(target.birth, &validator.creates)?;
        validate_catalogs_and_exits(&validator, target, &reachable, completion)?;
        let memory_count = |kind: &str| validator.memory_counts.get(kind).copied().unwrap_or(0);
        let total_zfod = memory_count("total-zfod");
        let exported_zfod = memory_count("exported-zfod");
        let unexported_zfod = memory_count("unexported-zfod");
        let intent_entries = memory_count("intent-entries");
        let intent_returns = memory_count("intent-returns");
        let intent_aborts = memory_count("intent-aborts");
        if intent_entries != validator.memory_intents {
            bail!(
                "memory intent entry count {intent_entries} does not match {} exported records",
                validator.memory_intents
            );
        }
        if intent_returns != validator.completed_memory_intents {
            bail!(
                "memory intent return count {intent_returns} does not match {} completed records",
                validator.completed_memory_intents
            );
        }
        if intent_aborts != validator.aborted_memory_intents {
            bail!(
                "memory intent abort count {intent_aborts} does not match {} terminal records",
                validator.aborted_memory_intents
            );
        }
        if intent_entries
            != intent_returns
                .checked_add(intent_aborts)
                .ok_or_else(|| anyhow!("memory intent closure count overflow"))?
        {
            bail!("memory intent entries do not reconcile returns plus terminal aborts");
        }
        if exported_zfod != validator.fault_events {
            bail!(
                "exported zfod count {exported_zfod} does not match {} fault events",
                validator.fault_events
            );
        }
        let reconciled_total = exported_zfod
            .checked_add(unexported_zfod)
            .ok_or_else(|| anyhow!("memory census zfod count overflow"))?;
        if total_zfod != reconciled_total {
            bail!("memory census total zfod does not reconcile exported and unexported counts");
        }
        let exact_zfod = validator
            .totals
            .iter()
            .filter(|((_, outcome), _)| *outcome == Outcome::Zfod)
            .try_fold(0u64, |sum, (_, count)| sum.checked_add(*count))
            .ok_or_else(|| anyhow!("exact zfod total overflow"))?;
        if total_zfod != exact_zfod {
            bail!("memory census total zfod {total_zfod} does not match exact total {exact_zfod}");
        }
        let memory_census = NativeMemoryCensus {
            total_zfod,
            exported_zfod,
            unexported_zfod,
            intent_records: validator.memory_intents,
            completed_intents: validator.completed_memory_intents,
            aborted_intents: validator.aborted_memory_intents,
            active_memory_faults: validator.active_memory_faults,
            guest_arena_faults: validator.guest_arena_faults,
        };
        let (memory_operations, memory_faults) = summarize_memory_intent(
            &validator.memory_intent_records,
            &validator.memory_fault_events,
            total_zfod,
            unexported_zfod,
        )?;

        let mut classified = Vec::new();
        let mut sampled_by_process_outcome = BTreeMap::<(BirthKey, Outcome), u64>::new();
        for (&(outcome, mut key, page), &count) in &validator.pages {
            if !reachable.contains(&key.birth) {
                continue;
            }
            if key.image == 0 {
                if key.birth != target.birth {
                    bail!("sampled image zero has no catalog join outside the target process");
                }
                key.image = target.image;
            }
            let ranges = resolve_catalog_ranges(key, &validator, &mut BTreeSet::new())?;
            let ownership = classify_page(page, ranges)?;
            classified.push(PageSample {
                outcome,
                key,
                page,
                count,
            });
            let total = sampled_by_process_outcome
                .entry((key.birth, outcome))
                .or_default();
            *total = total
                .checked_add(count)
                .ok_or_else(|| anyhow!("sample count overflow"))?;
            if ownership == Ownership::GuestOwned {
                // Classification is recomputed below while building rows. This branch
                // deliberately forces the fallible join to happen for every page here.
            }
        }

        for (&key, &sampled) in &sampled_by_process_outcome {
            let exact =
                validator.totals.get(&key).copied().ok_or_else(|| {
                    anyhow!("sampled {} events have no exact total", key.1.as_str())
                })?;
            if sampled > exact {
                bail!(
                    "sample count {sampled} exceeds exact total {exact} for {:?} {}",
                    key.0,
                    key.1.as_str()
                );
            }
        }
        for (&key, &rejected) in &validator.rejected {
            if !reachable.contains(&key.0) {
                continue;
            }
            let exact =
                validator.totals.get(&key).copied().ok_or_else(|| {
                    anyhow!("rejected {} events have no exact total", key.1.as_str())
                })?;
            if rejected > exact {
                bail!("rejected event count exceeds exact total");
            }
        }

        let exact_totals = aggregate_exact(&validator.totals, &reachable)?;
        for required in [Outcome::AsFault, Outcome::Zfod] {
            if exact_totals.get(&required).copied().unwrap_or(0) == 0 {
                bail!(
                    "native-fault stream has zero exact {} totals",
                    required.as_str()
                );
            }
        }
        let rejected_totals = aggregate_exact(&validator.rejected, &reachable)?;
        let ownership = build_ownership(&classified, &validator)?;
        let sample_coverage = build_coverage(&classified, &exact_totals)?;
        let processes = build_processes(
            &reachable,
            &validator.totals,
            &validator.rejected,
            &sampled_by_process_outcome,
        );
        let hot_pages = build_hot_pages(&classified, &validator)?;
        let excluded_processes = u64::try_from(validator.births.len() - reachable.len())?;

        Ok(Self {
            schema: JSON_SCHEMA,
            profile: "native-fault",
            gating_eligible: false,
            perturbation: "high; traced elapsed time is diagnostic only",
            raw_sha256,
            authority_header,
            os_build: authority.os_build().to_owned(),
            program_sha256: authority.program_sha256().to_owned(),
            birth_qualification_sha256: authority.birth_qualification_sha256().to_owned(),
            terminal_qualification_sha256: authority.terminal_qualification_sha256().to_owned(),
            page_sample_modulus: PAGE_SAMPLE_MODULUS,
            capture,
            completion,
            exact_totals: exact_totals
                .into_iter()
                .map(|(outcome, count)| NativeFaultExactTotal {
                    outcome: outcome.as_str(),
                    count,
                })
                .collect(),
            rejected_totals: rejected_totals
                .into_iter()
                .map(|(outcome, count)| NativeFaultRejectedTotal {
                    outcome: outcome.as_str(),
                    count,
                })
                .collect(),
            sample_coverage,
            ownership,
            processes,
            hot_pages,
            memory_census,
            memory_operations,
            memory_faults,
            excluded_processes,
            provenance: NativeFaultProvenance::default(),
        })
    }

    pub(crate) fn set_provenance(&mut self, provenance: ProfileProvenance) {
        self.provenance = NativeFaultProvenance {
            run_id: provenance.run_id,
            git_sha: provenance.git_sha,
            git_dirty: provenance.git_dirty,
            binary_sha256: provenance.binary_sha256,
            command: provenance.command,
            host: provenance.host,
        };
    }

    pub(crate) fn render_human(&self) -> String {
        let zfod = self.exact_total("zfod").unwrap_or(0);
        let guest = self
            .ownership_bucket("zfod", "guest-owned")
            .map(|bucket| bucket.sample_share * 100.0)
            .unwrap_or(0.0);
        format!(
            "native-fault: exact_zfod={zfod}, sampled_guest_owned_zfod={guest:.2}%, excluded_processes={}, natural=true, gating_eligible=false",
            self.excluded_processes
        )
    }

    pub(crate) fn write_atomic(&self, path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).with_context(|| {
            format!("create native-fault output directory {}", parent.display())
        })?;
        let mut temporary = NamedTempFile::new_in(parent).with_context(|| {
            format!(
                "create temporary native-fault report in {}",
                parent.display()
            )
        })?;
        {
            let mut writer = BufWriter::new(temporary.as_file_mut());
            serde_json::to_writer(&mut writer, self).context("serialize native-fault report")?;
            writer
                .write_all(b"\n")
                .context("terminate native-fault report")?;
            writer.flush().context("flush native-fault report")?;
        }
        temporary
            .as_file()
            .sync_all()
            .context("sync native-fault report")?;
        if let Some((uid, gid)) = owner {
            let result = unsafe { libc::fchown(temporary.as_raw_fd(), uid, gid) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("set native-fault report owner");
            }
        }
        temporary.persist(path).map_err(|error| {
            anyhow!(
                "publish native-fault report {}: {}",
                path.display(),
                error.error
            )
        })?;
        Ok(())
    }

    fn exact_total(&self, outcome: &str) -> Option<u64> {
        self.exact_totals
            .iter()
            .find(|row| row.outcome == outcome)
            .map(|row| row.count)
    }

    fn ownership_bucket(
        &self,
        outcome: &str,
        ownership: &str,
    ) -> Option<&NativeFaultOwnershipBucket> {
        self.ownership
            .iter()
            .find(|row| row.outcome == outcome && row.ownership == ownership)
    }
}

fn require_lossless_capture(capture: ProfileCaptureStatus) -> Result<()> {
    if capture.interrupted
        || capture.principal_drops != 0
        || capture.aggregation_drops != 0
        || capture.dynamic_drops != 0
        || capture.dynamic_rinse_drops != 0
        || capture.dynamic_dirty_drops != 0
        || capture.other_drops != 0
    {
        bail!("native-fault capture was interrupted or has DTrace drops: {capture:?}");
    }
    Ok(())
}

fn require_natural_completion(completion: NativeFaultCompletion) -> Result<()> {
    for (name, count) in [
        ("identity_violations", completion.identity_violations),
        ("lifecycle_violations", completion.lifecycle_violations),
        ("catalog_violations", completion.catalog_violations),
        ("probe_errors", completion.probe_errors),
        ("live_at_end", completion.live_at_end),
        ("pending_forks", completion.pending_forks),
    ] {
        if count != 0 {
            bail!("native-fault completion has nonzero {name}={count}");
        }
    }
    if completion.bounded
        || completion.timed_out
        || !completion.target_exit
        || completion.target_exit_reason == 0
        || completion.elapsed_ns == 0
    {
        bail!("native-fault completion is not natural and bounded-lossless: {completion:?}");
    }
    Ok(())
}

fn birth_from(record: &RawRecord, pid: &str, sec: &str, usec: &str) -> Result<BirthKey> {
    let pid = record.number(pid)?;
    let start_sec = nonzero(record.number(sec)?, "birth start_sec")?;
    let start_usec = record.number(usec)?;
    if pid == 0 || pid > u64::from(u32::MAX) || start_usec >= 1_000_000 {
        bail!("invalid process birth identity");
    }
    Ok(BirthKey {
        pid: u32::try_from(pid)?,
        start_sec,
        start_usec: u32::try_from(start_usec)?,
    })
}

fn image_from(
    record: &RawRecord,
    pid: &str,
    sec: &str,
    usec: &str,
    image: &str,
) -> Result<ImageKey> {
    Ok(ImageKey {
        birth: birth_from(record, pid, sec, usec)?,
        image: record.number(image)?,
    })
}

fn nonzero(value: u64, name: &str) -> Result<u64> {
    if value == 0 {
        bail!("{name} is zero");
    }
    Ok(value)
}

fn active_state<'a>(
    states: &'a mut BTreeMap<BirthKey, ProcessState>,
    birth: BirthKey,
    context: &str,
) -> Result<&'a mut ProcessState> {
    let state = states
        .get_mut(&birth)
        .ok_or_else(|| anyhow!("{context} has no tracked process state"))?;
    if !state.alive {
        bail!("{context} refers to an exited process");
    }
    Ok(state)
}

fn validate_fork_links(validator: &NativeFaultValidator) -> Result<()> {
    if validator.creates.len() != validator.inherits.len() {
        bail!("process-create and fork-inherit populations differ");
    }
    for (&child, create) in &validator.creates {
        let inherit = validator
            .inherits
            .get(&child)
            .ok_or_else(|| anyhow!("fork child {child:?} lacks fork-inherit record"))?;
        let mut comparable = *inherit;
        comparable.frontier = None;
        if create != &comparable {
            bail!("fork child {child:?} create/inherit identity drift");
        }
        if inherit.frontier == Some(0) {
            bail!("fork child {child:?} inherits an empty catalog");
        }
    }

    let mut fork_ids = BTreeMap::new();
    for link in validator.creates.values() {
        if let Some(previous) = fork_ids.insert(link.fork_id, link.child)
            && previous != link.child
        {
            bail!(
                "fork_id {} aliases children {previous:?} and {:?}",
                link.fork_id,
                link.child
            );
        }
    }

    for child in validator.creates.keys() {
        let mut seen = BTreeSet::new();
        let mut cursor = child.birth;
        while let Some(link) = validator
            .creates
            .values()
            .find(|candidate| candidate.child.birth == cursor)
        {
            if !seen.insert(cursor) || link.parent.birth == child.birth {
                bail!("fork parent graph contains a cycle at {cursor:?}");
            }
            cursor = link.parent.birth;
        }
    }
    Ok(())
}

fn bind_prebirth_records(validator: &mut NativeFaultValidator) -> Result<()> {
    let by_id = validator
        .inherits
        .values()
        .map(|link| (link.fork_id, *link))
        .collect::<BTreeMap<_, _>>();

    let mut sampled_by_fork_outcome = BTreeMap::<(u64, Outcome), u64>::new();
    for (&(outcome, fork_id, _), &count) in &validator.prebirth_pages {
        if !by_id.contains_key(&fork_id) {
            bail!("prebirth page names unknown fork_id {fork_id}");
        }
        let total = sampled_by_fork_outcome
            .entry((fork_id, outcome))
            .or_default();
        *total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("prebirth sample count overflow"))?;
    }
    for (&key, &sampled) in &sampled_by_fork_outcome {
        let exact = validator
            .prebirth_totals
            .get(&key)
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "sampled prebirth {} events for fork_id {} lack an exact total",
                    key.1.as_str(),
                    key.0
                )
            })?;
        if sampled > exact {
            bail!(
                "prebirth sample count exceeds exact total for fork_id {}",
                key.0
            );
        }
    }
    for (&key, &rejected) in &validator.prebirth_rejected {
        if !by_id.contains_key(&key.0) {
            bail!("prebirth rejected total names unknown fork_id {}", key.0);
        }
        let exact = validator
            .prebirth_totals
            .get(&key)
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "rejected prebirth {} events for fork_id {} lack an exact total",
                    key.1.as_str(),
                    key.0
                )
            })?;
        if rejected > exact {
            bail!(
                "prebirth rejected count exceeds exact total for fork_id {}",
                key.0
            );
        }
    }

    for (&(outcome, fork_id, page), &count) in &validator.prebirth_pages {
        let link = by_id
            .get(&fork_id)
            .ok_or_else(|| anyhow!("prebirth page names unknown fork_id {fork_id}"))?;
        let total = validator
            .pages
            .entry((outcome, link.child, page))
            .or_default();
        *total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("bound prebirth page count overflow"))?;
    }
    for (&(fork_id, outcome), &count) in &validator.prebirth_totals {
        let link = by_id
            .get(&fork_id)
            .ok_or_else(|| anyhow!("prebirth total names unknown fork_id {fork_id}"))?;
        let total = validator
            .totals
            .entry((link.child.birth, outcome))
            .or_default();
        *total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("bound prebirth exact total overflow"))?;
    }
    for (&(fork_id, outcome), &count) in &validator.prebirth_rejected {
        let link = by_id
            .get(&fork_id)
            .ok_or_else(|| anyhow!("prebirth rejected total names unknown fork_id {fork_id}"))?;
        let total = validator
            .rejected
            .entry((link.child.birth, outcome))
            .or_default();
        *total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("bound prebirth rejected total overflow"))?;
    }
    Ok(())
}

fn reachable_births(
    root: BirthKey,
    creates: &BTreeMap<ImageKey, ForkLink>,
) -> Result<BTreeSet<BirthKey>> {
    let mut reachable = BTreeSet::from([root]);
    loop {
        let before = reachable.len();
        for link in creates.values() {
            if reachable.contains(&link.parent.birth) {
                reachable.insert(link.child.birth);
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    for link in creates.values() {
        if reachable.contains(&link.child.birth) && !reachable.contains(&link.parent.birth) {
            bail!("reachable fork child has an unreachable parent");
        }
    }
    Ok(reachable)
}

fn validate_catalogs_and_exits(
    validator: &NativeFaultValidator,
    target: ImageKey,
    reachable: &BTreeSet<BirthKey>,
    completion: NativeFaultCompletion,
) -> Result<()> {
    for (key, catalog) in &validator.catalogs {
        if !catalog.ready || catalog.ranges.is_empty() {
            bail!("incomplete catalog for {key:?}");
        }
    }
    resolve_catalog_ranges(target, validator, &mut BTreeSet::new())?;
    for birth in reachable {
        let (exit_key, exit_epoch, reason) = validator
            .exits
            .get(birth)
            .ok_or_else(|| anyhow!("reachable process {birth:?} has no process-exit"))?;
        let resolved = resolve_catalog(exit_key.to_owned(), validator, &mut BTreeSet::new())?;
        if resolved.epoch != *exit_epoch {
            bail!("process-exit catalog identity drift");
        }
        if *birth == target.birth && *reason != completion.target_exit_reason {
            bail!("target process-exit reason differs from completion");
        }
        let state = validator
            .states
            .get(birth)
            .ok_or_else(|| anyhow!("reachable process has no lifecycle state"))?;
        if state.alive || state.exec_attempt.is_some() || state.image_map_pending.is_some() {
            bail!("reachable process lifecycle did not close naturally");
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ResolvedCatalog<'a> {
    epoch: u64,
    ranges: &'a [OwnedRange],
}

fn resolve_catalog_ranges<'a>(
    key: ImageKey,
    validator: &'a NativeFaultValidator,
    visiting: &mut BTreeSet<ImageKey>,
) -> Result<&'a [OwnedRange]> {
    Ok(resolve_catalog(key, validator, visiting)?.ranges)
}

fn resolve_catalog<'a>(
    key: ImageKey,
    validator: &'a NativeFaultValidator,
    visiting: &mut BTreeSet<ImageKey>,
) -> Result<ResolvedCatalog<'a>> {
    if !visiting.insert(key) {
        bail!("catalog inheritance contains a cycle at {key:?}");
    }
    let result = if let Some(catalog) = validator.catalogs.get(&key) {
        if !catalog.ready || catalog.ranges.is_empty() {
            bail!("incomplete catalog join for {key:?}");
        }
        ResolvedCatalog {
            epoch: catalog.epoch,
            ranges: &catalog.ranges,
        }
    } else if let Some(link) = validator.inherits.get(&key) {
        let parent = resolve_catalog(link.parent, validator, visiting)
            .with_context(|| format!("catalog join failed for inherited child {key:?}"))?;
        let frontier = link
            .frontier
            .ok_or_else(|| anyhow!("fork inheritance lacks catalog frontier"))?;
        if parent.epoch != link.parent_epoch
            || link.child_epoch != link.parent_epoch
            || u64::try_from(parent.ranges.len())? != frontier
        {
            bail!("inherited catalog identity drift for {key:?}");
        }
        ResolvedCatalog {
            epoch: link.child_epoch,
            ranges: parent.ranges,
        }
    } else {
        bail!("missing catalog join for {key:?}");
    };
    visiting.remove(&key);
    Ok(result)
}

fn classify_page(page: u64, ranges: &[OwnedRange]) -> Result<Ownership> {
    let end = page
        .checked_add(PAGE_SIZE)
        .ok_or_else(|| anyhow!("sampled page end overflow"))?;
    let intersections = ranges
        .iter()
        .filter(|range| range.start < end && page < range.end)
        .collect::<Vec<_>>();
    match intersections.as_slice() {
        [] => Ok(Ownership::HostOther),
        [range] if range.start <= page && range.end >= end => Ok(Ownership::GuestOwned),
        [_] => bail!("sampled page is only partially covered by an owned range"),
        _ => bail!("sampled page intersects multiple owned ranges"),
    }
}

fn aggregate_exact(
    input: &BTreeMap<(BirthKey, Outcome), u64>,
    reachable: &BTreeSet<BirthKey>,
) -> Result<BTreeMap<Outcome, u64>> {
    let mut output = BTreeMap::<Outcome, u64>::new();
    for (&(birth, outcome), &count) in input {
        if !reachable.contains(&birth) {
            continue;
        }
        let total = output.entry(outcome).or_default();
        *total = total
            .checked_add(count)
            .ok_or_else(|| anyhow!("native-fault exact total overflow"))?;
    }
    Ok(output)
}

fn build_ownership(
    samples: &[PageSample],
    validator: &NativeFaultValidator,
) -> Result<Vec<NativeFaultOwnershipBucket>> {
    let mut grouped = BTreeMap::<(Outcome, Ownership), (u64, BTreeSet<(ImageKey, u64)>)>::new();
    let mut outcome_totals = BTreeMap::<Outcome, u64>::new();
    for sample in samples {
        let ranges = resolve_catalog_ranges(sample.key, validator, &mut BTreeSet::new())?;
        let ownership = classify_page(sample.page, ranges)?;
        let (events, pages) = grouped.entry((sample.outcome, ownership)).or_default();
        *events = events
            .checked_add(sample.count)
            .ok_or_else(|| anyhow!("ownership sample overflow"))?;
        pages.insert((sample.key, sample.page));
        let total = outcome_totals.entry(sample.outcome).or_default();
        *total = total
            .checked_add(sample.count)
            .ok_or_else(|| anyhow!("outcome sample overflow"))?;
    }
    grouped
        .into_iter()
        .map(|((outcome, ownership), (events, pages))| {
            let distinct = u64::try_from(pages.len())?;
            let denominator = outcome_totals.get(&outcome).copied().unwrap_or(0);
            Ok(NativeFaultOwnershipBucket {
                outcome: outcome.as_str(),
                ownership: ownership.as_str(),
                sampled_events: events,
                distinct_process_pages: distinct,
                repeat_excess: events.checked_sub(distinct).ok_or_else(|| {
                    anyhow!("sample events are below distinct process-page population")
                })?,
                repeat_factor: events as f64 / distinct as f64,
                sample_share: events as f64 / denominator as f64,
                scaled_event_estimate: events
                    .checked_mul(PAGE_SAMPLE_MODULUS)
                    .ok_or_else(|| anyhow!("scaled sample estimate overflow"))?,
            })
        })
        .collect()
}

fn build_coverage(
    samples: &[PageSample],
    exact: &BTreeMap<Outcome, u64>,
) -> Result<Vec<NativeFaultSampleCoverage>> {
    let mut grouped = BTreeMap::<Outcome, (u64, BTreeSet<(ImageKey, u64)>)>::new();
    for sample in samples {
        let (events, pages) = grouped.entry(sample.outcome).or_default();
        *events = events
            .checked_add(sample.count)
            .ok_or_else(|| anyhow!("sample coverage overflow"))?;
        pages.insert((sample.key, sample.page));
    }
    grouped
        .into_iter()
        .map(|(outcome, (sampled_events, pages))| {
            Ok(NativeFaultSampleCoverage {
                outcome: outcome.as_str(),
                exact_events: exact.get(&outcome).copied().unwrap_or(0),
                sampled_events,
                distinct_process_pages: u64::try_from(pages.len())?,
                sample_modulus: PAGE_SAMPLE_MODULUS,
            })
        })
        .collect()
}

fn build_processes(
    reachable: &BTreeSet<BirthKey>,
    totals: &BTreeMap<(BirthKey, Outcome), u64>,
    rejected: &BTreeMap<(BirthKey, Outcome), u64>,
    sampled: &BTreeMap<(BirthKey, Outcome), u64>,
) -> Vec<NativeFaultProcessSummary> {
    reachable
        .iter()
        .map(|&birth| NativeFaultProcessSummary {
            birth,
            exact_as_fault: totals.get(&(birth, Outcome::AsFault)).copied().unwrap_or(0),
            exact_zfod: totals.get(&(birth, Outcome::Zfod)).copied().unwrap_or(0),
            exact_cow_fault: totals
                .get(&(birth, Outcome::CowFault))
                .copied()
                .unwrap_or(0),
            rejected_as_fault: rejected
                .get(&(birth, Outcome::AsFault))
                .copied()
                .unwrap_or(0),
            rejected_zfod: rejected.get(&(birth, Outcome::Zfod)).copied().unwrap_or(0),
            sampled_as_fault: sampled
                .get(&(birth, Outcome::AsFault))
                .copied()
                .unwrap_or(0),
            sampled_zfod: sampled.get(&(birth, Outcome::Zfod)).copied().unwrap_or(0),
        })
        .collect()
}

fn build_hot_pages(
    samples: &[PageSample],
    validator: &NativeFaultValidator,
) -> Result<Vec<NativeFaultHotPage>> {
    let mut rows = samples
        .iter()
        .map(|sample| {
            let ranges = resolve_catalog_ranges(sample.key, validator, &mut BTreeSet::new())?;
            Ok(NativeFaultHotPage {
                outcome: sample.outcome.as_str(),
                ownership: classify_page(sample.page, ranges)?.as_str(),
                key: sample.key,
                page: sample.page,
                count: sample.count,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.outcome.cmp(right.outcome))
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.page.cmp(&right.page))
    });
    Ok(rows)
}

#[derive(Clone, Debug)]
struct ObservedPageState {
    semantic_sequence: String,
    mapping_provenance: String,
}

fn memory_operation_name(number: u64) -> Result<&'static str> {
    match number {
        215 => Ok("munmap"),
        222 => Ok("mmap"),
        226 => Ok("mprotect"),
        233 => Ok("madvise"),
        other => bail!("unknown memory syscall number {other}"),
    }
}

fn mmap_provenance(flags: u64) -> String {
    let backing = if flags & 0x20 != 0 { "anon" } else { "file" };
    let sharing = if flags & 0x01 != 0 {
        "shared"
    } else if flags & 0x02 != 0 {
        "private"
    } else {
        "unknown-sharing"
    };
    format!("{backing}-{sharing}")
}

fn memory_operation_shape(intent: &MemoryIntentRecord) -> Result<String> {
    Ok(match intent.number {
        215 => "unmap".to_owned(),
        222 => mmap_provenance(intent.args[3]),
        226 => format!("prot-{:#x}", intent.args[2]),
        233 => match intent.args[2] {
            4 => "dontneed".to_owned(),
            8 => "free".to_owned(),
            advice => format!("advice-{advice}"),
        },
        other => bail!("unknown memory syscall number {other}"),
    })
}

fn host_page_bounds(start: u64, len: u64) -> Result<Option<(u64, u64)>> {
    if len == 0 {
        return Ok(None);
    }
    let start = start & !(PAGE_SIZE - 1);
    let raw_end = start
        .checked_add(len)
        .ok_or_else(|| anyhow!("memory intent range overflow"))?;
    let end = raw_end
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or_else(|| anyhow!("memory intent page rounding overflow"))?;
    Ok((start < end).then_some((start, end)))
}

fn summarize_memory_intent(
    intents: &[MemoryIntentRecord],
    faults: &[MemoryFaultEvent],
    total_zfod: u64,
    unexported_zfod: u64,
) -> Result<(
    Vec<NativeMemoryOperationBucket>,
    Vec<NativeMemoryFaultBucket>,
)> {
    let mut operation_counts = BTreeMap::<(&'static str, String), (u64, u64)>::new();
    let mut intent_by_sequence = BTreeMap::<(BirthKey, u64), &MemoryIntentRecord>::new();
    for intent in intents {
        let operation = memory_operation_name(intent.number)?;
        let shape = memory_operation_shape(intent)?;
        let bucket = operation_counts.entry((operation, shape)).or_insert((0, 0));
        bucket.0 = bucket
            .0
            .checked_add(1)
            .ok_or_else(|| anyhow!("memory operation count overflow"))?;
        bucket.1 = bucket
            .1
            .checked_add(intent.args[1])
            .ok_or_else(|| anyhow!("memory operation byte count overflow"))?;
        if intent_by_sequence
            .insert((intent.key.birth, intent.sequence), intent)
            .is_some()
        {
            bail!("duplicate memory intent sequence during summary");
        }
    }

    let mut fault_counts = BTreeMap::<(&'static str, String, String), u64>::new();
    let mut add_fault = |phase: &'static str, semantic: String, provenance: String| -> Result<()> {
        let count = fault_counts
            .entry((phase, semantic, provenance))
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("memory fault bucket overflow"))?;
        Ok(())
    };

    for fault in faults
        .iter()
        .filter(|fault| fault.scope == MemoryFaultScope::ActiveMemory)
    {
        let intent = intent_by_sequence
            .get(&(fault.key.birth, fault.active_sequence))
            .copied()
            .ok_or_else(|| anyhow!("active fault has no completed memory intent"))?;
        if intent.key != fault.key
            || intent.tid != fault.tid
            || intent.number != fault.active_number
        {
            bail!("active fault identity does not match its memory intent");
        }
        if fault.timestamp_ns < intent.entry_ns || fault.timestamp_ns > intent.return_ns {
            bail!("active fault timestamp falls outside its memory intent");
        }
        let operation = memory_operation_name(intent.number)?;
        let shape = memory_operation_shape(intent)?;
        let provenance = if intent.number == 222 {
            shape.clone()
        } else {
            "existing-mapping".to_owned()
        };
        add_fault(
            "during-operation",
            format!("{operation}-{shape}"),
            provenance,
        )?;
    }

    let mut intents_by_image = BTreeMap::<ImageKey, Vec<&MemoryIntentRecord>>::new();
    for intent in intents {
        intents_by_image.entry(intent.key).or_default().push(intent);
    }
    let mut faults_by_image = BTreeMap::<ImageKey, Vec<&MemoryFaultEvent>>::new();
    for fault in faults
        .iter()
        .filter(|fault| fault.scope == MemoryFaultScope::GuestArena)
    {
        faults_by_image.entry(fault.key).or_default().push(fault);
    }

    for (key, image_faults) in faults_by_image {
        #[derive(Clone, Copy)]
        enum TimelineEvent {
            Begin(usize),
            Fault(usize),
            End(usize),
        }

        let image_intents = intents_by_image.get(&key).cloned().unwrap_or_default();
        let candidate_pages = image_faults
            .iter()
            .map(|fault| fault.page)
            .collect::<BTreeSet<_>>();
        let mut timeline = Vec::<(u64, u8, TimelineEvent)>::new();
        for (index, intent) in image_intents.iter().enumerate() {
            timeline.push((intent.entry_ns, 0, TimelineEvent::Begin(index)));
            timeline.push((intent.return_ns, 2, TimelineEvent::End(index)));
        }
        for (index, fault) in image_faults.iter().enumerate() {
            timeline.push((fault.timestamp_ns, 1, TimelineEvent::Fault(index)));
        }
        timeline.sort_by_key(|(timestamp, order, _)| (*timestamp, *order));

        let mut active = BTreeSet::<(u64, u64)>::new();
        let mut page_state = BTreeMap::<u64, ObservedPageState>::new();
        for (_, _, event) in timeline {
            match event {
                TimelineEvent::Begin(index) => {
                    let intent = image_intents[index];
                    active.insert((intent.tid, intent.sequence));
                }
                TimelineEvent::Fault(index) => {
                    let fault = image_faults[index];
                    if !active.is_empty() {
                        add_fault(
                            "subsequent-touch",
                            "concurrent-memory-operation".to_owned(),
                            "mixed-or-transitioning".to_owned(),
                        )?;
                    } else if let Some(state) = page_state.get(&fault.page) {
                        add_fault(
                            "subsequent-touch",
                            state.semantic_sequence.clone(),
                            state.mapping_provenance.clone(),
                        )?;
                    } else {
                        add_fault(
                            "subsequent-touch",
                            "initial-exec-brk-or-fork".to_owned(),
                            "not-created-by-observed-mmap".to_owned(),
                        )?;
                    }
                }
                TimelineEvent::End(index) => {
                    let intent = image_intents[index];
                    if !active.remove(&(intent.tid, intent.sequence)) {
                        bail!("memory intent timeline ended an inactive operation");
                    }
                    if !intent.completed || intent.errno != 0 || intent.retval < 0 {
                        continue;
                    }
                    let operation = memory_operation_name(intent.number)?;
                    let start = if intent.number == 222 {
                        u64::try_from(intent.retval)
                            .map_err(|_| anyhow!("successful mmap returned a negative address"))?
                    } else {
                        intent.args[0]
                    };
                    let Some((start, end)) = host_page_bounds(start, intent.args[1])? else {
                        continue;
                    };
                    let affected = candidate_pages
                        .range(start..end)
                        .copied()
                        .collect::<Vec<_>>();
                    for page in affected {
                        let prior = page_state.get(&page).cloned();
                        let provenance = if intent.number == 222 {
                            mmap_provenance(intent.args[3])
                        } else {
                            prior
                                .as_ref()
                                .map(|state| state.mapping_provenance.clone())
                                .unwrap_or_else(|| "preexisting-or-unknown".to_owned())
                        };
                        let semantic_sequence = match intent.number {
                            215 => "munmap".to_owned(),
                            222 => {
                                if prior
                                    .as_ref()
                                    .is_some_and(|state| state.semantic_sequence == "munmap")
                                {
                                    "mmap-reuse".to_owned()
                                } else {
                                    "mmap-fresh".to_owned()
                                }
                            }
                            226 if intent.args[2] == 0 => "mprotect-none".to_owned(),
                            226 if prior.as_ref().is_some_and(|state| {
                                state.semantic_sequence == "mprotect-none"
                            }) =>
                            {
                                "mprotect-reenable".to_owned()
                            }
                            226 => "mprotect-other".to_owned(),
                            233 if intent.args[2] == 4 => "madvise-dontneed".to_owned(),
                            233 if intent.args[2] == 8 => "madvise-free".to_owned(),
                            233 => format!("madvise-{}", intent.args[2]),
                            _ => format!("{operation}-unknown"),
                        };
                        page_state.insert(
                            page,
                            ObservedPageState {
                                semantic_sequence,
                                mapping_provenance: provenance,
                            },
                        );
                    }
                }
            }
        }
        if !active.is_empty() {
            bail!("memory intent timeline ended with active operations");
        }
    }

    if unexported_zfod != 0 {
        fault_counts.insert(
            (
                "unexported",
                "outside-active-memory-and-native-arenas".to_owned(),
                "host-other-or-untracked".to_owned(),
            ),
            unexported_zfod,
        );
    }
    let reconciled_faults = fault_counts
        .values()
        .try_fold(0u64, |sum, count| sum.checked_add(*count))
        .ok_or_else(|| anyhow!("memory fault summary overflow"))?;
    if reconciled_faults != total_zfod {
        bail!(
            "memory fault buckets total {reconciled_faults} does not match exact zfod {total_zfod}"
        );
    }

    let memory_operations = operation_counts
        .into_iter()
        .map(
            |((operation, shape), (calls, requested_bytes))| NativeMemoryOperationBucket {
                operation,
                shape,
                calls,
                requested_bytes,
            },
        )
        .collect();
    let mut memory_faults = fault_counts
        .into_iter()
        .map(
            |((phase, semantic_sequence, mapping_provenance), exact_zfod)| {
                NativeMemoryFaultBucket {
                    phase,
                    semantic_sequence,
                    mapping_provenance,
                    exact_zfod,
                    share_of_all_zfod: if total_zfod == 0 {
                        0.0
                    } else {
                        exact_zfod as f64 / total_zfod as f64
                    },
                }
            },
        )
        .collect::<Vec<_>>();
    memory_faults.sort_by(|left, right| {
        right
            .exact_zfod
            .cmp(&left.exact_zfod)
            .then_with(|| left.phase.cmp(right.phase))
            .then_with(|| left.semantic_sequence.cmp(&right.semantic_sequence))
            .then_with(|| left.mapping_provenance.cmp(&right.mapping_provenance))
    });
    Ok((memory_operations, memory_faults))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_profile::{
        ProfileCaptureStatus, ProfileProvenance, TraceProfileKind, V2ProfileAuthority,
    };
    use std::fs;

    const PROGRAM_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const BIRTH_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TERMINAL_SHA256: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";

    fn authority() -> V2ProfileAuthority {
        V2ProfileAuthority::new_for_profile(
            TraceProfileKind::NativeFault,
            "26A5388g",
            PROGRAM_SHA256,
            BIRTH_SHA256,
            TERMINAL_SHA256,
            [
                ("syscall".to_owned(), "exit".to_owned(), "thread".to_owned()),
                (
                    "syscall".to_owned(),
                    "exit_group".to_owned(),
                    "process".to_owned(),
                ),
            ],
        )
        .expect("fixture authority")
    }

    fn fixture() -> String {
        format!(
            "{}\
\nNFAULT2|birth|pid=9|start_sec=90|start_usec=9\
\nNFAULT2|birth|pid=10|start_sec=100|start_usec=20\
\nNFAULT2|target-birth|pid=10|start_sec=100|start_usec=20|image=1\
\nNFAULT2|catalog-reset|pid=10|start_sec=100|start_usec=20|image=1|epoch=7\
\nNFAULT2|catalog-range|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|sequence=1|start=0x10000|end=0x18000\
\nNFAULT2|catalog-ready|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|final_sequence=1\
\nNFAULT2|memory-intent|pid=10|start_sec=100|start_usec=20|image=1|tid=10|sequence=1|number=222|entry_ns=100|return_ns=200|arg0=0|arg1=16384|arg2=3|arg3=34|arg4=18446744073709551615|arg5=0|retval=65536|errno=0\
\nNFAULT2|fault-event|outcome=zfod|pid=10|start_sec=100|start_usec=20|image=1|tid=10|timestamp_ns=250|page=0x10000|active_number=0|active_sequence=0|scope=guest-arena\
\nNFAULT2|birth|pid=11|start_sec=101|start_usec=21\
\nNFAULT2|process-create|child_pid=11|child_sec=101|child_usec=21|child_image=1|child_epoch=7|fork_id=41|parent_pid=10|parent_sec=100|parent_usec=20|parent_image=1|parent_epoch=7\
\nNFAULT2|fork-inherit|child_pid=11|child_sec=101|child_usec=21|child_image=1|child_epoch=7|fork_id=41|parent_pid=10|parent_sec=100|parent_usec=20|parent_image=1|parent_epoch=7|range_frontier=1\
\nNFAULT2|process-exit|pid=11|start_sec=101|start_usec=21|image=1|epoch=7|reason=1\
\nNFAULT2|process-exit|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|reason=1\
\nNFAULT2|page|outcome=zfod|pid=9|start_sec=90|start_usec=9|image=0|page=0x30000|count=20\
\nNFAULT2|page|outcome=zfod|pid=10|start_sec=100|start_usec=20|image=0|page=0x10000|count=3\
\nNFAULT2|page|outcome=zfod|pid=10|start_sec=100|start_usec=20|image=1|page=0x20000|count=2\
\nNFAULT2|page|outcome=zfod|pid=11|start_sec=101|start_usec=21|image=1|page=0x14000|count=4\
\nNFAULT2|page|outcome=as_fault|pid=10|start_sec=100|start_usec=20|image=1|page=0x10000|count=3\
\nNFAULT2|total|outcome=as_fault|pid=9|start_sec=90|start_usec=9|count=100\
\nNFAULT2|total|outcome=zfod|pid=9|start_sec=90|start_usec=9|count=80\
\nNFAULT2|total|outcome=cow_fault|pid=9|start_sec=90|start_usec=9|count=2\
\nNFAULT2|total|outcome=as_fault|pid=10|start_sec=100|start_usec=20|count=5\
\nNFAULT2|total|outcome=zfod|pid=10|start_sec=100|start_usec=20|count=10\
\nNFAULT2|total|outcome=cow_fault|pid=10|start_sec=100|start_usec=20|count=1\
\nNFAULT2|total|outcome=as_fault|pid=11|start_sec=101|start_usec=21|count=1\
\nNFAULT2|total|outcome=zfod|pid=11|start_sec=101|start_usec=21|count=6\
\nNFAULT2|total|outcome=cow_fault|pid=11|start_sec=101|start_usec=21|count=1\
\nNFAULT2|rejected|outcome=zfod|pid=10|start_sec=100|start_usec=20|count=2\
\nNFAULT2|memory-count|kind=total-zfod|count=96\
\nNFAULT2|memory-count|kind=exported-zfod|count=1\
\nNFAULT2|memory-count|kind=unexported-zfod|count=95\
\nNFAULT2|memory-count|kind=intent-entries|count=1\
\nNFAULT2|memory-count|kind=intent-returns|count=1\
\nNFAULT2|complete|profile=native-fault|bounded=0|timed_out=0|target_exit=1|target_exit_reason=1|identity_violations=0|lifecycle_violations=0|catalog_violations=0|probe_errors=0|live_at_end=0|pending_forks=0|elapsed_ns=9000000\n",
            authority().header_record()
        )
    }

    fn parse(raw: &str) -> anyhow::Result<NativeFaultSummary> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("raw.trace");
        fs::write(&path, raw)?;
        NativeFaultSummary::from_path(&path, ProfileCaptureStatus::default(), authority())
    }

    fn assert_rejected(raw: String, needle: &str) {
        let error = parse(&raw).expect_err("fixture must be rejected");
        assert!(
            format!("{error:#}").contains(needle),
            "expected {needle:?} in {error:#}"
        );
    }

    fn insert_before(raw: &str, marker: &str, addition: &str) -> String {
        raw.replacen(marker, &format!("{addition}\n{marker}"), 1)
    }

    #[test]
    fn accepts_parent_catalog_target_image_zero_fork_inheritance_and_host_other() {
        let summary = parse(&fixture()).expect("valid fixture");
        assert_eq!(summary.schema, "carrick.native-fault-attribution.v3");
        assert!(!summary.gating_eligible);
        assert_eq!(summary.exact_total("zfod"), Some(16));
        assert_eq!(summary.excluded_processes, 1);
        let json = serde_json::to_value(&summary).expect("serialize summary");
        assert_eq!(json["os_build"], "26A5388g");
        assert_eq!(json["program_sha256"], PROGRAM_SHA256);
        assert_eq!(json["birth_qualification_sha256"], BIRTH_SHA256);
        assert_eq!(json["terminal_qualification_sha256"], TERMINAL_SHA256);
        assert_eq!(json["page_sample_modulus"], 64);
        assert_eq!(json["memory_census"]["total_zfod"], 96);
        assert_eq!(json["memory_census"]["exported_zfod"], 1);
        assert_eq!(json["memory_census"]["unexported_zfod"], 95);
        assert_eq!(json["memory_census"]["intent_records"], 1);
        assert_eq!(json["memory_census"]["completed_intents"], 1);
        assert_eq!(json["memory_census"]["aborted_intents"], 0);
        assert_eq!(json["memory_operations"][0]["operation"], "mmap");
        assert_eq!(json["memory_operations"][0]["shape"], "anon-private");
        assert_eq!(json["memory_operations"][0]["calls"], 1);
        assert_eq!(json["memory_operations"][0]["requested_bytes"], 16_384);
        let subsequent = json["memory_faults"]
            .as_array()
            .expect("memory fault rows")
            .iter()
            .find(|row| row["phase"] == "subsequent-touch")
            .expect("subsequent mmap fault row");
        assert_eq!(subsequent["semantic_sequence"], "mmap-fresh");
        assert_eq!(subsequent["mapping_provenance"], "anon-private");
        assert_eq!(subsequent["exact_zfod"], 1);

        let guest = summary
            .ownership_bucket("zfod", "guest-owned")
            .expect("guest bucket");
        assert_eq!(guest.sampled_events, 7);
        assert_eq!(guest.distinct_process_pages, 2);
        assert_eq!(guest.repeat_excess, 5);
        assert_eq!(guest.scaled_event_estimate, 448);
        assert!((guest.sample_share - (7.0 / 9.0)).abs() < f64::EPSILON);

        let host = summary
            .ownership_bucket("zfod", "host-other")
            .expect("host bucket");
        assert_eq!(host.sampled_events, 2);
        assert_eq!(host.distinct_process_pages, 1);
        assert_eq!(host.repeat_excess, 1);
        assert_eq!(host.scaled_event_estimate, 128);
    }

    #[test]
    fn rejects_unreconciled_memory_intent_export() {
        assert_rejected(
            fixture().replace("kind=exported-zfod|count=1", "kind=exported-zfod|count=2"),
            "exported zfod",
        );
        assert_rejected(
            fixture().replace("kind=intent-returns|count=1", "kind=intent-returns|count=2"),
            "intent return",
        );
        assert_rejected(
            fixture().replace("kind=intent-entries|count=1", "kind=intent-entries|count=2"),
            "entry count",
        );
    }

    #[test]
    fn joins_active_fault_to_the_exact_memory_operation_window() {
        let active = fixture().replace(
            "timestamp_ns=250|page=0x10000|active_number=0|active_sequence=0|scope=guest-arena",
            "timestamp_ns=150|page=0x10000|active_number=222|active_sequence=1|scope=active-memory",
        );
        let summary = parse(&active).expect("active fault joins its mmap");
        let json = serde_json::to_value(&summary).expect("serialize active summary");
        let row = json["memory_faults"]
            .as_array()
            .expect("memory fault rows")
            .iter()
            .find(|row| row["phase"] == "during-operation")
            .expect("during-operation row");
        assert_eq!(row["semantic_sequence"], "mmap-anon-private");
        assert_eq!(row["mapping_provenance"], "anon-private");
        assert_eq!(row["exact_zfod"], 1);

        assert_rejected(
            active.replace("timestamp_ns=150", "timestamp_ns=250"),
            "outside its memory intent",
        );
    }

    #[test]
    fn closes_a_terminal_memory_operation_without_mutating_mapping_state() {
        let aborted = fixture()
            .replace(
                "NFAULT2|memory-intent|pid=10|start_sec=100|start_usec=20|image=1|tid=10|sequence=1|number=222|entry_ns=100|return_ns=200|arg0=0|arg1=16384|arg2=3|arg3=34|arg4=18446744073709551615|arg5=0|retval=65536|errno=0",
                "NFAULT2|memory-intent-abort|pid=10|start_sec=100|start_usec=20|image=1|tid=10|sequence=1|number=222|entry_ns=100|terminal_ns=200|arg0=0|arg1=16384|arg2=3|arg3=34|arg4=18446744073709551615|arg5=0|reason=process-exit",
            )
            .replace(
                "kind=intent-returns|count=1",
                "kind=intent-aborts|count=1",
            );
        let summary = parse(&aborted).expect("terminal operation closes exactly");
        let json = serde_json::to_value(&summary).expect("serialize terminal summary");
        assert_eq!(json["memory_census"]["completed_intents"], 0);
        assert_eq!(json["memory_census"]["aborted_intents"], 1);
        let subsequent = json["memory_faults"]
            .as_array()
            .expect("memory fault rows")
            .iter()
            .find(|row| row["phase"] == "subsequent-touch")
            .expect("post-terminal fault row");
        assert_eq!(subsequent["semantic_sequence"], "initial-exec-brk-or-fork");
    }

    #[test]
    fn rejects_duplicate_header_and_completion() {
        let raw = fixture();
        assert_rejected(format!("{}\n{raw}", authority().header_record()), "header");
        let completion = raw
            .lines()
            .find(|line| line.starts_with("NFAULT2|complete|"))
            .expect("completion");
        assert_rejected(format!("{raw}{completion}\n"), "completion");
    }

    #[test]
    fn rejects_missing_birth_and_identity_drift() {
        assert_rejected(
            fixture().replace("NFAULT2|birth|pid=10|start_sec=100|start_usec=20\n", ""),
            "birth",
        );
        assert_rejected(
            fixture().replace(
                "catalog-ready|pid=10|start_sec=100|start_usec=20",
                "catalog-ready|pid=10|start_sec=100|start_usec=22",
            ),
            "identity",
        );
    }

    #[test]
    fn rejects_invalid_page_zero_total_and_sample_above_total() {
        assert_rejected(
            fixture().replace(
                "image=0|page=0x10000|count=3",
                "image=0|page=0x10001|count=3",
            ),
            "aligned",
        );
        assert_rejected(
            fixture().replace(
                "outcome=zfod|pid=11|start_sec=101|start_usec=21|count=6",
                "outcome=zfod|pid=11|start_sec=101|start_usec=21|count=0",
            ),
            "zero",
        );
        assert_rejected(
            fixture()
                .replace(
                    "outcome=zfod|pid=10|start_sec=100|start_usec=20|count=10",
                    "outcome=zfod|pid=10|start_sec=100|start_usec=20|count=4",
                )
                .replace("kind=total-zfod|count=96", "kind=total-zfod|count=90")
                .replace(
                    "kind=unexported-zfod|count=95",
                    "kind=unexported-zfod|count=89",
                ),
            "exceed",
        );
    }

    #[test]
    fn rejects_fork_cycle_and_duplicate_parent() {
        let cycle = "NFAULT2|process-create|child_pid=10|child_sec=100|child_usec=20|child_image=1|child_epoch=7|fork_id=42|parent_pid=11|parent_sec=101|parent_usec=21|parent_image=1|parent_epoch=7\
\nNFAULT2|fork-inherit|child_pid=10|child_sec=100|child_usec=20|child_image=1|child_epoch=7|fork_id=42|parent_pid=11|parent_sec=101|parent_usec=21|parent_image=1|parent_epoch=7|range_frontier=1";
        assert_rejected(
            insert_before(&fixture(), "NFAULT2|process-exit|pid=11", cycle),
            "cycle",
        );

        let duplicate = "NFAULT2|process-create|child_pid=11|child_sec=101|child_usec=21|child_image=1|child_epoch=7|fork_id=43|parent_pid=10|parent_sec=100|parent_usec=20|parent_image=1|parent_epoch=7\
\nNFAULT2|fork-inherit|child_pid=11|child_sec=101|child_usec=21|child_image=1|child_epoch=7|fork_id=43|parent_pid=10|parent_sec=100|parent_usec=20|parent_image=1|parent_epoch=7|range_frontier=1";
        assert_rejected(
            insert_before(&fixture(), "NFAULT2|process-exit|pid=11", duplicate),
            "duplicate parent",
        );
    }

    #[test]
    fn rejects_incomplete_overlapping_and_missing_catalogs() {
        assert_rejected(
            fixture().replace(
                "NFAULT2|catalog-ready|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|final_sequence=1\n",
                "",
            ),
            "incomplete catalog",
        );
        assert_rejected(
            fixture().replace(
                "NFAULT2|catalog-ready|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|final_sequence=1",
                "NFAULT2|catalog-range|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|sequence=2|start=0x14000|end=0x1c000\nNFAULT2|catalog-ready|pid=10|start_sec=100|start_usec=20|image=1|epoch=7|final_sequence=2",
            ),
            "overlap",
        );
        assert_rejected(
            fixture().replace(
                "pid=10|start_sec=100|start_usec=20|image=1|page=0x20000|count=2",
                "pid=10|start_sec=100|start_usec=20|image=2|page=0x20000|count=2",
            ),
            "catalog join",
        );
    }

    #[test]
    fn rejects_nonzero_violation_drop_and_pending_fork_counts() {
        assert_rejected(
            fixture().replace("identity_violations=0", "identity_violations=1"),
            "identity_violations",
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("raw.trace");
        fs::write(&path, fixture()).expect("write fixture");
        let status = ProfileCaptureStatus {
            principal_drops: 1,
            ..ProfileCaptureStatus::default()
        };
        let error = NativeFaultSummary::from_path(&path, status, authority())
            .expect_err("drops must reject");
        assert!(format!("{error:#}").contains("drops"));

        assert_rejected(
            fixture().replace("pending_forks=0", "pending_forks=1"),
            "pending_forks",
        );
    }

    #[test]
    fn binds_prebirth_totals_and_pages_through_the_unique_fork_id() {
        let raw = insert_before(
            &fixture(),
            "NFAULT2|complete|",
            "NFAULT2|prebirth-page|outcome=zfod|fork_id=41|page=0x10000|count=2\nNFAULT2|prebirth-total|outcome=zfod|fork_id=41|count=2",
        )
        .replace(
            "kind=total-zfod|count=96",
            "kind=total-zfod|count=98",
        )
        .replace(
            "kind=unexported-zfod|count=95",
            "kind=unexported-zfod|count=97",
        );
        let summary = parse(&raw).expect("prebirth records bind to child");
        assert_eq!(summary.exact_total("zfod"), Some(18));
        let guest = summary
            .ownership_bucket("zfod", "guest-owned")
            .expect("guest bucket");
        assert_eq!(guest.sampled_events, 9);
        assert_eq!(guest.distinct_process_pages, 3);
        assert_eq!(guest.repeat_excess, 6);

        assert_rejected(
            raw.replace("fork_id=41|page=0x10000", "fork_id=99|page=0x10000"),
            "fork_id",
        );
    }

    #[test]
    fn rejects_unknown_fields_and_authority_mismatch() {
        assert_rejected(
            fixture().replace(
                "NFAULT2|birth|pid=10|start_sec=100|start_usec=20",
                "NFAULT2|birth|pid=10|start_sec=100|start_usec=20|extra=1",
            ),
            "field",
        );
        assert_rejected(
            fixture().replace(PROGRAM_SHA256, &"a".repeat(64)),
            "authority",
        );
    }

    #[test]
    fn rejects_page_partially_intersecting_an_owned_range() {
        let error = classify_page(
            0x10000,
            &[OwnedRange {
                start: 0x12000,
                end: 0x18000,
            }],
        )
        .expect_err("partial coverage must reject");
        assert!(format!("{error:#}").contains("partially"));
    }

    #[test]
    fn writes_one_provenance_rich_jsonl_record_atomically() {
        let mut summary = parse(&fixture()).expect("valid fixture");
        summary.set_provenance(ProfileProvenance {
            run_id: "fault-run".to_owned(),
            git_sha: "abc123".to_owned(),
            git_dirty: Some(false),
            binary_sha256: "f".repeat(64),
            command: vec!["run".to_owned(), "ubuntu:24.04".to_owned()],
            host: "fixture-host".to_owned(),
        });
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("summary.jsonl");
        summary.write_atomic(&path, None).expect("write report");
        let contents = fs::read_to_string(path).expect("read report");
        assert_eq!(contents.lines().count(), 1);
        let json: serde_json::Value = serde_json::from_str(contents.trim()).expect("parse report");
        assert_eq!(json["schema"], "carrick.native-fault-attribution.v3");
        assert_eq!(json["provenance"]["run_id"], "fault-run");
        assert_eq!(json["provenance"]["git_dirty"], false);
        assert_eq!(json["gating_eligible"], false);
    }
}
