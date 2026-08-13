//! Strict reader for the bundled HVPatch K1 lifecycle DTrace profile.
//!
//! This is deliberately not the process-wide VM ledger or the K1 evidence
//! manifest. It validates only the complete raw stream produced by
//! `scripts/dtrace/hvpatch-k1-lifecycle.d` plus libdtrace's out-of-band loss
//! report.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPATCHK1";
const VERSION: u64 = 2;
const EXPECTED_ROOTS: u64 = 1;
const EXPECTED_FORKS: u64 = 68;
const EXPECTED_EXECS: u64 = 67;
const EXPECTED_BIRTHS: u64 = EXPECTED_ROOTS + EXPECTED_FORKS;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessKey {
    pid: i32,
    asid: u32,
}

#[derive(Clone, Copy, Debug)]
struct Birth {
    kind: BirthKind,
    ppid: i32,
    tid: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BirthKind {
    Root,
    Fork,
}

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(PREFIX) {
            bail!("unknown HVPatch K1 protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated HVPatch K1 record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("HVPatch K1 field lacks '=': {raw:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("HVPatch K1 field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate HVPatch K1 field {key:?}"),
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
                "HVPatch K1 {:?} field contract mismatch: missing={missing:?}, extra={extra:?}",
                self.tag
            );
        }
        Ok(())
    }

    fn value(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("HVPatch K1 {:?} record is missing {field:?}", self.tag))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        parse_u64(self.value(field)?).with_context(|| format!("invalid {:?} {field}", self.tag))
    }

    fn u32(&self, field: &str) -> Result<u32> {
        u32::try_from(self.u64(field)?)
            .with_context(|| format!("HVPatch K1 {:?} {field} exceeds u32", self.tag))
    }

    fn i64(&self, field: &str) -> Result<i64> {
        parse_i64(self.value(field)?).with_context(|| format!("invalid {:?} {field}", self.tag))
    }

    fn i32(&self, field: &str) -> Result<i32> {
        i32::try_from(self.i64(field)?)
            .with_context(|| format!("HVPatch K1 {:?} {field} exceeds i32", self.tag))
    }

    fn process_identity(&self) -> Result<(ProcessKey, i32)> {
        let key = ProcessKey {
            pid: self.i32("pid")?,
            asid: self.u32("asid")?,
        };
        let tid = self.i32("tid")?;
        if key.pid <= 0 || tid <= 0 || key.asid == 0 {
            bail!("HVPatch K1 guest pid/tid/ASID must be positive");
        }
        Ok((key, tid))
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    let canonical = value == "0"
        || value
            .as_bytes()
            .first()
            .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
            && value.bytes().all(|byte| byte.is_ascii_digit());
    if !canonical {
        bail!("expected canonical unsigned decimal integer, got {value:?}");
    }
    value
        .parse()
        .with_context(|| format!("unsigned integer {value:?} exceeds u64"))
}

fn parse_i64(value: &str) -> Result<i64> {
    let canonical = if let Some(digits) = value.strip_prefix('-') {
        digits
            .as_bytes()
            .first()
            .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        value == "0"
            || value
                .as_bytes()
                .first()
                .is_some_and(|first| first.is_ascii_digit() && *first != b'0')
                && value.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !canonical {
        bail!("expected canonical signed decimal integer, got {value:?}");
    }
    value
        .parse()
        .with_context(|| format!("signed integer {value:?} exceeds i64"))
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status != ProfileCaptureStatus::default() {
        bail!(
            "HVPatch K1 capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            status.principal_drops,
            status.aggregation_drops,
            status.dynamic_drops,
            status.dynamic_rinse_drops,
            status.dynamic_dirty_drops,
            status.other_drops,
            status.interrupted,
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct EndRecord {
    roots: u64,
    forks: u64,
    execs: u64,
    exits: u64,
    births: u64,
    live: i64,
    bounded: u64,
    errors: u64,
    target_exit_seen: u64,
    target_exit_code: i64,
    target_exit_reason: u64,
}

/// Validated counts from one complete K1 lifecycle capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchK1LifecycleSummary {
    pub(crate) roots: u64,
    pub(crate) forks: u64,
    pub(crate) execs: u64,
    pub(crate) exits: u64,
    pub(crate) unique_births: u64,
    pub(crate) final_live: i64,
    pub(crate) vm_creates: u64,
    pub(crate) vm_destroys: u64,
}

impl HvpatchK1LifecycleSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read HVPatch K1 lifecycle stream {}", path.display()))?;
        Self::from_lines(contents.lines(), status)
    }

    fn from_lines<I, S>(lines: I, status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        require_lossless(status)?;

        let mut header_seen = false;
        let mut end = None;
        let mut births = BTreeMap::<ProcessKey, Birth>::new();
        // Serials seen across births, and the serials execs claimed. Every
        // exec must name a task that was actually born in this capture.
        let mut birth_serials = BTreeSet::<u64>::new();
        let mut exec_serials = Vec::<u64>::new();
        let mut birth_pids = BTreeSet::new();
        let mut execs = BTreeMap::<ProcessKey, (i32, u64)>::new();
        let mut terminals = BTreeMap::<ProcessKey, (i32, i64, u64)>::new();
        let mut vm = BTreeMap::<(u32, i32), u64>::new();

        for (index, raw_line) in lines.into_iter().enumerate() {
            let line = raw_line.as_ref();
            if line.is_empty() {
                continue;
            }
            if line.trim() != line {
                bail!("HVPatch K1 record has noncanonical surrounding whitespace");
            }
            if end.is_some() {
                bail!("HVPatch K1 record appears after end at line {}", index + 1);
            }
            let record = Record::parse(line)
                .with_context(|| format!("invalid HVPatch K1 record at line {}", index + 1))?;
            if !header_seen && record.tag != "header" {
                bail!("HVPatch K1 header must be the first record");
            }
            match record.tag.as_str() {
                "header" => {
                    record.exact_fields(&["version"])?;
                    if header_seen {
                        bail!("duplicate HVPatch K1 header");
                    }
                    if record.u64("version")? != VERSION {
                        bail!("unsupported HVPatch K1 protocol version");
                    }
                    header_seen = true;
                }
                "birth" => {
                    record.exact_fields(&[
                        "asid",
                        "count",
                        "kind",
                        "mm",
                        "parent_serial",
                        "pid",
                        "ppid",
                        "task_serial",
                        "tid",
                    ])?;
                    let kind = match record.u64("kind")? {
                        0 => BirthKind::Root,
                        1 => BirthKind::Fork,
                        other => bail!("unknown HVPatch K1 birth kind {other}"),
                    };
                    if record.u64("count")? != 1 {
                        bail!("every HVPatch K1 birth identity must occur exactly once");
                    }
                    let (key, tid) = record.process_identity()?;
                    let ppid = record.i32("ppid")?;
                    if ppid < 0 {
                        bail!("HVPatch K1 parent pid must be nonnegative");
                    }
                    if !birth_pids.insert(key.pid) {
                        bail!("duplicate HVPatch K1 guest pid {}", key.pid);
                    }
                    // The serial is what makes an identity unambiguous: a pid
                    // and an ASID are both recycled within a run, so neither
                    // can prove two births are different tasks. A `TaskSerial`
                    // is never reused by one Kernel, so a repeat means the
                    // capture conflated two generations.
                    let task_serial = record.u64("task_serial")?;
                    let parent_serial = record.u64("parent_serial")?;
                    if task_serial == 0 || record.u64("mm")? == 0 {
                        bail!("HVPatch K1 birth identity must carry a task serial and an mm");
                    }
                    if (ppid == 0) != (parent_serial == 0) {
                        bail!(
                            "HVPatch K1 birth parent pid and parent serial disagree about a parent"
                        );
                    }
                    if !birth_serials.insert(task_serial) {
                        bail!("duplicate HVPatch K1 task serial {task_serial}");
                    }
                    if births.insert(key, Birth { kind, ppid, tid }).is_some() {
                        bail!("duplicate HVPatch K1 birth identity");
                    }
                }
                "exec" => {
                    record.exact_fields(&["asid", "count", "mm", "pid", "task_serial", "tid"])?;
                    if record.u64("task_serial")? == 0 || record.u64("mm")? == 0 {
                        bail!("HVPatch K1 exec identity must carry a task serial and an mm");
                    }
                    exec_serials.push(record.u64("task_serial")?);
                    let count = record.u64("count")?;
                    if count == 0 {
                        bail!("HVPatch K1 exec count must be positive");
                    }
                    let (key, tid) = record.process_identity()?;
                    if execs.insert(key, (tid, count)).is_some() {
                        bail!("duplicate HVPatch K1 exec aggregate");
                    }
                }
                "terminal" => {
                    record.exact_fields(&["asid", "count", "pid", "status", "tid"])?;
                    let (key, tid) = record.process_identity()?;
                    let terminal = (tid, record.i64("status")?, record.u64("count")?);
                    if terminal.2 != 1 {
                        bail!("every HVPatch K1 terminal identity must occur exactly once");
                    }
                    if terminals.insert(key, terminal).is_some() {
                        bail!("duplicate HVPatch K1 terminal aggregate");
                    }
                }
                "vm" => {
                    record.exact_fields(&["admission", "count", "operation"])?;
                    let operation = record.u32("operation")?;
                    if operation > 3 {
                        bail!("unknown HVPatch K1 VM operation {operation}");
                    }
                    let key = (operation, record.i32("admission")?);
                    let count = record.u64("count")?;
                    if count == 0 {
                        bail!("HVPatch K1 VM operation count must be positive");
                    }
                    if vm.insert(key, count).is_some() {
                        bail!("duplicate HVPatch K1 VM operation aggregate");
                    }
                }
                "end" => {
                    record.exact_fields(&[
                        "births",
                        "bounded",
                        "errors",
                        "execs",
                        "exits",
                        "forks",
                        "live",
                        "roots",
                        "target_exit_code",
                        "target_exit_reason",
                        "target_exit_seen",
                        "version",
                    ])?;
                    if record.u64("version")? != VERSION {
                        bail!("unsupported HVPatch K1 end-record version");
                    }
                    end = Some(EndRecord {
                        roots: record.u64("roots")?,
                        forks: record.u64("forks")?,
                        execs: record.u64("execs")?,
                        exits: record.u64("exits")?,
                        births: record.u64("births")?,
                        live: record.i64("live")?,
                        bounded: record.u64("bounded")?,
                        errors: record.u64("errors")?,
                        target_exit_seen: record.u64("target_exit_seen")?,
                        target_exit_code: record.i64("target_exit_code")?,
                        target_exit_reason: record.u64("target_exit_reason")?,
                    });
                }
                other => bail!("unknown HVPatch K1 record tag {other:?}"),
            }
        }

        if !header_seen {
            bail!("HVPatch K1 stream is missing its header");
        }
        let end = end.ok_or_else(|| anyhow!("HVPatch K1 stream is missing its end record"))?;
        // Every exec must name a task generation this capture actually saw
        // born. Joining on pid alone could not catch an exec attributed to a
        // recycled number; the serial can.
        for serial in &exec_serials {
            if !birth_serials.contains(serial) {
                bail!("HVPatch K1 exec names task serial {serial}, which no birth record declares");
            }
        }
        validate_capture(&births, &execs, &terminals, &vm, end)
    }

    pub(crate) fn render_human(self) -> String {
        format!(
            "HVPatch K1 lifecycle: roots={}, forks={}, execs={}, exits={}, unique_births={}, final_live={}, VM creates={}, VM destroys={}, complete=true",
            self.roots,
            self.forks,
            self.execs,
            self.exits,
            self.unique_births,
            self.final_live,
            self.vm_creates,
            self.vm_destroys,
        )
    }
}

fn checked_sum<'a>(values: impl IntoIterator<Item = &'a u64>, what: &str) -> Result<u64> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| anyhow!("HVPatch K1 {what} count overflow"))
    })
}

fn validate_capture(
    births: &BTreeMap<ProcessKey, Birth>,
    execs: &BTreeMap<ProcessKey, (i32, u64)>,
    terminals: &BTreeMap<ProcessKey, (i32, i64, u64)>,
    vm: &BTreeMap<(u32, i32), u64>,
    end: EndRecord,
) -> Result<HvpatchK1LifecycleSummary> {
    if end.bounded != 0 {
        bail!("HVPatch K1 capture hit its time bound");
    }
    if end.errors != 0 {
        bail!("HVPatch K1 capture reported {} DTrace error(s)", end.errors);
    }
    if end.target_exit_seen != 1 || end.target_exit_code != 0 || end.target_exit_reason != 1 {
        bail!(
            "HVPatch K1 trace target did not exit zero (seen={}, code={}, reason={})",
            end.target_exit_seen,
            end.target_exit_code,
            end.target_exit_reason
        );
    }
    if end.live != 0 {
        bail!("HVPatch K1 final live set is {}, expected zero", end.live);
    }

    let roots = births
        .values()
        .filter(|birth| birth.kind == BirthKind::Root)
        .count() as u64;
    let forks = births
        .values()
        .filter(|birth| birth.kind == BirthKind::Fork)
        .count() as u64;
    let unique_births = u64::try_from(births.len()).context("birth cardinality exceeds u64")?;
    let exec_count = checked_sum(execs.values().map(|(_, count)| count), "exec")?;
    let terminal_count = checked_sum(terminals.values().map(|(_, _, count)| count), "terminal")?;

    if roots != EXPECTED_ROOTS || end.roots != EXPECTED_ROOTS {
        bail!(
            "HVPatch K1 requires exactly {EXPECTED_ROOTS} root, observed records={roots}, end={}",
            end.roots
        );
    }
    if forks != EXPECTED_FORKS || end.forks != EXPECTED_FORKS {
        bail!(
            "HVPatch K1 requires exactly {EXPECTED_FORKS} forks, observed records={forks}, end={}",
            end.forks
        );
    }
    if unique_births != EXPECTED_BIRTHS || end.births != EXPECTED_BIRTHS {
        bail!(
            "HVPatch K1 requires exactly {EXPECTED_BIRTHS} unique births, observed records={unique_births}, end={}",
            end.births
        );
    }
    if exec_count != EXPECTED_EXECS || end.execs != EXPECTED_EXECS {
        bail!(
            "HVPatch K1 requires exactly {EXPECTED_EXECS} execs, observed records={exec_count}, end={}",
            end.execs
        );
    }
    if terminal_count != EXPECTED_BIRTHS || end.exits != EXPECTED_BIRTHS {
        bail!(
            "HVPatch K1 requires exactly {EXPECTED_BIRTHS} exits, observed terminals={terminal_count}, end={}",
            end.exits
        );
    }

    let root = births
        .iter()
        .find(|(_, birth)| birth.kind == BirthKind::Root)
        .ok_or_else(|| anyhow!("HVPatch K1 root birth disappeared"))?;
    if root.1.ppid != 0 {
        bail!("HVPatch K1 root parent pid must be zero");
    }
    let births_by_pid = births
        .iter()
        .map(|(key, birth)| (key.pid, birth))
        .collect::<BTreeMap<_, _>>();
    for (key, birth) in births {
        if birth.tid != key.pid {
            bail!(
                "HVPatch K1 process birth {} used nonleader tid {}",
                key.pid,
                birth.tid
            );
        }
        if birth.kind == BirthKind::Fork
            && (birth.ppid == key.pid || !births_by_pid.contains_key(&birth.ppid))
        {
            bail!(
                "HVPatch K1 fork {} has an unknown or self parent {}",
                key.pid,
                birth.ppid
            );
        }
        let mut lineage = BTreeSet::new();
        let mut ancestor = key.pid;
        while ancestor != root.0.pid {
            if !lineage.insert(ancestor) {
                bail!("HVPatch K1 parent graph contains a cycle at pid {ancestor}");
            }
            let parent = births_by_pid
                .get(&ancestor)
                .ok_or_else(|| anyhow!("HVPatch K1 parent graph lost pid {ancestor}"))?
                .ppid;
            if parent == 0 {
                bail!(
                    "HVPatch K1 pid {} reaches parent zero before root {}",
                    key.pid,
                    root.0.pid
                );
            }
            ancestor = parent;
        }
        if !terminals.contains_key(key) {
            bail!("HVPatch K1 birth {} has no terminal exit", key.pid);
        }
    }
    for key in execs.keys().chain(terminals.keys()) {
        if !births.contains_key(key) {
            bail!(
                "HVPatch K1 lifecycle record for pid {} has no matching birth",
                key.pid
            );
        }
    }
    if terminals.get(root.0).map(|(_, status, _)| *status) != Some(0) {
        bail!("HVPatch K1 root terminal status must be zero");
    }

    let mut operations = [0_u64; 4];
    let mut create_admission = [None; 2];
    for (&(operation, admission), &count) in vm {
        let slot = operations
            .get_mut(operation as usize)
            .ok_or_else(|| anyhow!("HVPatch K1 VM operation escaped validated range"))?;
        *slot = slot
            .checked_add(count)
            .ok_or_else(|| anyhow!("HVPatch K1 VM operation count overflow"))?;
        match operation {
            0 | 1 => create_admission[operation as usize] = Some(admission),
            2 | 3 if admission != -1 => {
                bail!("HVPatch K1 destroy operation must use admission=-1")
            }
            2 | 3 => {}
            _ => bail!("HVPatch K1 VM operation escaped validated range"),
        }
    }
    if operations != [1, 1, 1, 1] {
        bail!(
            "HVPatch K1 requires one VM create/destroy attempt and success, observed {operations:?}"
        );
    }
    if create_admission[0] != create_admission[1] {
        bail!("HVPatch K1 VM create admission changed between attempt and success");
    }

    Ok(HvpatchK1LifecycleSummary {
        roots,
        forks,
        execs: exec_count,
        exits: terminal_count,
        unique_births,
        final_live: end.live,
        vm_creates: operations[1],
        vm_destroys: operations[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_stream() -> String {
        let mut lines = vec!["HVPATCHK1|header|version=2".to_owned()];
        // Serial 1 is the root; each fork takes the next serial. Serials are
        // deliberately independent of the recycled pid/ASID numbering.
        lines.push(
            "HVPATCHK1|birth|kind=0|pid=100|ppid=0|tid=100|asid=1|task_serial=1|parent_serial=0|mm=1|count=1"
                .to_owned(),
        );
        for index in 0..68 {
            let pid = 101 + index;
            let serial = index + 2;
            lines.push(format!(
                "HVPATCHK1|birth|kind=1|pid={pid}|ppid=100|tid={pid}|asid={}|task_serial={serial}|parent_serial=1|mm={serial}|count=1",
                index + 2
            ));
            if index < 67 {
                lines.push(format!(
                    "HVPATCHK1|exec|pid={pid}|tid={pid}|asid={}|task_serial={serial}|mm={serial}|count=1",
                    index + 2
                ));
            }
            let terminal_tid = if index == 0 { 900 } else { pid };
            lines.push(format!(
                "HVPATCHK1|terminal|pid={pid}|tid={terminal_tid}|asid={}|status=0|count=1",
                index + 2
            ));
        }
        lines.push("HVPATCHK1|terminal|pid=100|tid=100|asid=1|status=0|count=1".to_owned());
        for (operation, admission) in [(0, 7), (1, 7), (2, -1), (3, -1)] {
            lines.push(format!(
                "HVPATCHK1|vm|operation={operation}|admission={admission}|count=1"
            ));
        }
        lines.push("HVPATCHK1|end|version=2|roots=1|forks=68|execs=67|exits=69|births=69|live=0|bounded=0|errors=0|target_exit_seen=1|target_exit_code=0|target_exit_reason=1".to_owned());
        lines.join("\n")
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn profile_selection_embeds_the_strict_k1_program() {
        let profile = crate::trace_profile::TraceProfileKind::HvpatchK1Lifecycle;
        assert_eq!(profile.as_str(), "hvpatch-k1-lifecycle");
        assert!(!profile.requires_runtime_profile());
        let source = profile.bundled_script();
        assert_eq!(
            source,
            carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_K1_LIFECYCLE_D
        );
        for required in [
            "HVPATCHK1|header|version=2",
            "carrick*:::hvpatch-guest-lifecycle",
            "carrick*:::hvpatch-guest-lifecycle-identity",
            "task_serial",
            "carrick*:::hvpatch-guest-exit",
            "carrick*:::vm-lifecycle",
            "syscall::exit:entry",
            "target_exit_code",
            "dtrace:::ERROR",
            "profile:::tick-1sec",
            "HVPATCHK1|end|version=2",
        ] {
            assert!(
                source.contains(required),
                "missing K1 profile source {required}"
            );
        }
    }

    #[test]
    fn accepts_exact_k1_lifecycle() {
        let summary = HvpatchK1LifecycleSummary::from_lines(
            valid_stream().lines(),
            ProfileCaptureStatus::default(),
        )
        .expect("valid K1 lifecycle");
        assert_eq!(summary.roots, 1);
        assert_eq!(summary.forks, 68);
        assert_eq!(summary.execs, 67);
        assert_eq!(summary.exits, 69);
        assert_eq!(summary.unique_births, 69);
        assert_eq!(summary.final_live, 0);
        assert_eq!(summary.vm_creates, 1);
        assert_eq!(summary.vm_destroys, 1);
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        for corrupt in [
            valid_stream().replace("version=2\n", "version=2|extra=1\n"),
            valid_stream().replacen("version=2", "version=3", 1),
            valid_stream().replacen("version=2", "version=02", 1),
            format!(" {}", valid_stream()),
        ] {
            assert!(
                HvpatchK1LifecycleSummary::from_lines(
                    corrupt.lines(),
                    ProfileCaptureStatus::default()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_birth_terminal_and_count_corruption() {
        for corrupt in [
            valid_stream().replace(
                "HVPATCHK1|terminal|pid=101|tid=900|asid=2|status=0|count=1\n",
                "",
            ),
            valid_stream().replace("forks=68", "forks=67"),
            valid_stream().replace("births=69", "births=68"),
            valid_stream().replace("live=0", "live=1"),
            valid_stream().replace("status=0|count=1", "status=0|count=2"),
            valid_stream()
                .replace("pid=101|ppid=100", "pid=101|ppid=102")
                .replace("pid=102|ppid=100", "pid=102|ppid=101"),
        ] {
            assert!(
                HvpatchK1LifecycleSummary::from_lines(
                    corrupt.lines(),
                    ProfileCaptureStatus::default()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_vm_timeout_error_drop_and_interruption_evidence() {
        for corrupt in [
            valid_stream().replace(
                "operation=3|admission=-1|count=1",
                "operation=3|admission=-1|count=2",
            ),
            valid_stream().replace("bounded=0", "bounded=1"),
            valid_stream().replace("errors=0", "errors=1"),
            valid_stream().replace("target_exit_seen=1", "target_exit_seen=0"),
            valid_stream().replace("target_exit_code=0", "target_exit_code=7"),
        ] {
            assert!(
                HvpatchK1LifecycleSummary::from_lines(
                    corrupt.lines(),
                    ProfileCaptureStatus::default()
                )
                .is_err()
            );
        }
        for status in [
            ProfileCaptureStatus {
                principal_drops: 1,
                ..ProfileCaptureStatus::default()
            },
            ProfileCaptureStatus {
                interrupted: true,
                ..ProfileCaptureStatus::default()
            },
        ] {
            assert!(HvpatchK1LifecycleSummary::from_lines(valid_stream().lines(), status).is_err());
        }
    }
}
