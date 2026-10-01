//! Strict reader for the HVPatch exit-attribution profile
//! (`scripts/dtrace/hvpatch-exit-attribution.d`).
//!
//! The profile answers, for one real workload, where the guest leaves to the
//! host: host exits by [`HostExitClass`] (folded into the syscall, fault,
//! kick/idle and other buckets), on-CPU guest time against on-CPU host service
//! time on the executor threads, and the host-forwarded syscall histogram by
//! Linux number. The capture fails closed: a lossy or bounded stream, a DTrace
//! error, or a probe family that never fired is an error, never an empty
//! census.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use carrick_el1_abi::HostExitClass;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPEXIT1";
pub(crate) const PROGRAM_SHA256_PLACEHOLDER: &str = "/* CARRICK_HVPEXIT_PROGRAM_SHA256 */";
/// The capture-bound placeholder slot, substituted by
/// `render_profile_capture_bound` for `--profile-bound-seconds`.
pub(crate) const BOUND_PLACEHOLDER: &str = "/* CARRICK_HVPEXIT_BOUND */";
/// `host-after-exit` keys at or above this are `64 + EL0 EC` of a non-svc
/// `hvc #2` exit (the D program re-keys the thread's pending host time).
const NOT_SVC_KEY_BASE: u32 = 64;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn bundled_template() -> &'static str {
    carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_EXIT_ATTRIBUTION_D
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
fn bundled_template() -> &'static str {
    include_str!("../../../scripts/dtrace/hvpatch-exit-attribution.d")
}

/// Render the bundled template's immutable digest into the raw-stream header.
pub(crate) fn render_profile_script(template: &str) -> Result<String> {
    let slots = template.match_indices(PROGRAM_SHA256_PLACEHOLDER).count();
    if slots != 1 {
        bail!(
            "{PREFIX} profile template must contain exactly one program-SHA-256 placeholder, found {slots}"
        );
    }
    Ok(template.replacen(PROGRAM_SHA256_PLACEHOLDER, &program_sha256(), 1))
}

pub(crate) fn program_sha256() -> String {
    format!("{:x}", Sha256::digest(bundled_template().as_bytes()))
}

/// The four buckets the EL1 work ranking reads exits in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExitBucket {
    Syscall,
    Fault,
    KickIdle,
    Other,
}

impl ExitBucket {
    pub(crate) const fn of(class: HostExitClass) -> Self {
        match class {
            HostExitClass::Syscall => Self::Syscall,
            HostExitClass::Fault => Self::Fault,
            HostExitClass::Canceled | HostExitClass::Idle | HostExitClass::Kick => Self::KickIdle,
            HostExitClass::Metadata | HostExitClass::Maintenance | HostExitClass::Other => {
                Self::Other
            }
        }
    }

    /// A non-svc EL0 exception the EL1 vector forwarded through `hvc #2`:
    /// instruction/data aborts are faults; everything else (sys64 MRS
    /// emulation, ...) is other.
    pub(crate) const fn of_el0_exception(ec: u32) -> Self {
        match ec {
            0x20 | 0x21 | 0x24 | 0x25 => Self::Fault,
            _ => Self::Other,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Syscall => "syscall",
            Self::Fault => "fault",
            Self::KickIdle => "kick-idle",
            Self::Other => "other",
        }
    }
}

/// One exit class (or bucket) row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct ExitRow {
    pub(crate) exits: u64,
    /// On-CPU time inside the `hv_vcpu_run` calls that ended in this class.
    pub(crate) guest_oncpu_ns: u64,
    /// Wall time inside those `hv_vcpu_run` calls.
    pub(crate) guest_wall_ns: u64,
    /// On-CPU host time from an exit of this class to the same thread's next
    /// `hv_vcpu_run`.
    pub(crate) host_oncpu_ns: u64,
}

impl ExitRow {
    fn add(&mut self, other: ExitRow) {
        self.exits += other.exits;
        self.guest_oncpu_ns += other.guest_oncpu_ns;
        self.guest_wall_ns += other.guest_wall_ns;
        self.host_oncpu_ns += other.host_oncpu_ns;
    }
}

/// One host-forwarded Linux syscall number.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ForwardedRow {
    pub(crate) nr: u64,
    pub(crate) name: Option<&'static str>,
    pub(crate) count: u64,
    pub(crate) ended: u64,
    /// Sum of the service's own monotonic durations (includes blocking).
    pub(crate) wall_ns: u64,
    /// Services that closed on the thread that began them.
    pub(crate) paired: u64,
    /// On-CPU host time of the paired services.
    pub(crate) oncpu_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct HvpatchExitAttributionSummary {
    pub(crate) schema: &'static str,
    pub(crate) program_sha256: String,
    pub(crate) bound_s: u64,
    pub(crate) enters: u64,
    pub(crate) unpaired_exits: u64,
    pub(crate) exits_total: u64,
    /// Raw `HostExitClass` census, exactly as the carrier counters see it.
    pub(crate) by_class: BTreeMap<&'static str, ExitRow>,
    /// Class-3 (`hvc #2`) exits that carried a non-svc EL0 exception, keyed
    /// by its exception class (`ec=0x24`, ...). Guest time stays on class 3.
    pub(crate) hvc_not_svc: BTreeMap<String, ExitRow>,
    /// The ranking view: `by_class` with `hvc_not_svc` moved out of syscall
    /// into fault (EL0 aborts) or other (sys64 emulation and the rest).
    pub(crate) by_bucket: BTreeMap<&'static str, ExitRow>,
    pub(crate) guest_oncpu_ns: u64,
    pub(crate) host_oncpu_ns: u64,
    pub(crate) forwarded_total: u64,
    /// Sorted by descending count, then number.
    pub(crate) forwarded: Vec<ForwardedRow>,
}

impl HvpatchExitAttributionSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read {PREFIX} stream {}", path.display()))?;
        Self::from_lines(contents.lines(), status, &program_sha256())
    }

    fn from_lines<I, S>(
        lines: I,
        status: ProfileCaptureStatus,
        expected_sha256: &str,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        require_lossless(status)?;
        let mut header_sha = None;
        let mut summary = None;
        let mut ended = false;
        let mut enters = None;
        let mut unpaired = None;
        let mut classes: BTreeMap<u32, ExitRow> = BTreeMap::new();
        let mut host_after: BTreeMap<u32, u64> = BTreeMap::new();
        let mut not_svc: BTreeMap<u32, ExitRow> = BTreeMap::new();
        let mut forwarded: BTreeMap<u64, ForwardedRow> = BTreeMap::new();
        for raw in lines {
            let line = raw.as_ref().trim();
            if line.is_empty() {
                continue;
            }
            if ended {
                bail!("{PREFIX} record after the end marker: {line:?}");
            }
            let record = Record::parse(line)?;
            match record.tag.as_str() {
                "header" => {
                    record.exact_fields(&["version", "program_sha256"])?;
                    if header_sha.is_some() || record.u64("version")? != 1 {
                        bail!("duplicate or unsupported {PREFIX} header");
                    }
                    header_sha = Some(record.value("program_sha256")?.to_owned());
                }
                "error" => bail!("{PREFIX} capture hit a DTrace error: {line}"),
                "summary" => {
                    if header_sha.is_none() || summary.is_some() {
                        bail!("{PREFIX} summary without a header, or duplicated");
                    }
                    record.exact_fields(&[
                        "status",
                        "root_exited",
                        "bounded",
                        "errors",
                        "saw_enter",
                        "saw_exit",
                        "saw_service",
                        "bound_s",
                    ])?;
                    summary = Some(record);
                }
                "enters" => {
                    record.exact_fields(&["count"])?;
                    if enters.replace(record.u64("count")?).is_some() {
                        bail!("duplicate {PREFIX} enters record");
                    }
                }
                "unpaired-exits" => {
                    record.exact_fields(&["count"])?;
                    if unpaired.replace(record.u64("count")?).is_some() {
                        bail!("duplicate {PREFIX} unpaired-exits record");
                    }
                }
                "exit" => {
                    record.exact_fields(&["class", "count", "guest_vns", "guest_wall_ns"])?;
                    let ordinal = record.u32("class")?;
                    decode_class(ordinal)?;
                    let row = ExitRow {
                        exits: record.u64("count")?,
                        guest_oncpu_ns: record.u64("guest_vns")?,
                        guest_wall_ns: record.u64("guest_wall_ns")?,
                        host_oncpu_ns: 0,
                    };
                    if classes.insert(ordinal, row).is_some() {
                        bail!("duplicate {PREFIX} exit class {ordinal}");
                    }
                }
                "hvc-not-svc" => {
                    record.exact_fields(&["ec", "count"])?;
                    let ec = record.u32("ec")?;
                    if ec >= 64 {
                        bail!("{PREFIX} hvc-not-svc exception class {ec} is not a 6-bit EC");
                    }
                    let row = ExitRow {
                        exits: record.u64("count")?,
                        ..ExitRow::default()
                    };
                    if not_svc.insert(ec, row).is_some() {
                        bail!("duplicate {PREFIX} hvc-not-svc ec {ec}");
                    }
                }
                "host-after-exit" => {
                    record.exact_fields(&["class", "vns"])?;
                    let ordinal = record.u32("class")?;
                    if !(NOT_SVC_KEY_BASE..NOT_SVC_KEY_BASE + 64).contains(&ordinal) {
                        decode_class(ordinal)?;
                    }
                    if host_after.insert(ordinal, record.u64("vns")?).is_some() {
                        bail!("duplicate {PREFIX} host-after-exit class {ordinal}");
                    }
                }
                "forwarded" => {
                    record.exact_fields(&[
                        "nr",
                        "count",
                        "ended",
                        "wall_ns",
                        "paired",
                        "oncpu_vns",
                    ])?;
                    let nr = record.u64("nr")?;
                    let row = ForwardedRow {
                        nr,
                        name: carrick_runtime::syscall::lookup_aarch64(nr).map(|s| s.name),
                        count: record.u64("count")?,
                        ended: record.u64("ended")?,
                        wall_ns: record.u64("wall_ns")?,
                        paired: record.u64("paired")?,
                        oncpu_ns: record.u64("oncpu_vns")?,
                    };
                    if row.paired > row.count || row.paired > row.ended {
                        bail!(
                            "{PREFIX} forwarded nr {nr} pairs more services than it began or ended"
                        );
                    }
                    if forwarded.insert(nr, row).is_some() {
                        bail!("duplicate {PREFIX} forwarded nr {nr}");
                    }
                }
                "end" => {
                    record.exact_fields(&[])?;
                    ended = true;
                }
                other => bail!("unknown {PREFIX} record tag {other:?}"),
            }
        }
        let program_sha256 = header_sha.ok_or_else(|| anyhow!("{PREFIX} stream has no header"))?;
        if program_sha256 != expected_sha256 {
            bail!(
                "{PREFIX} stream was produced by program {program_sha256}, not the bundled {expected_sha256}"
            );
        }
        let record = summary.ok_or_else(|| anyhow!("{PREFIX} stream has no summary"))?;
        if !ended {
            bail!("{PREFIX} stream has no end marker (truncated aggregation output)");
        }
        let bound_s = record.u64("bound_s")?;
        // Name each failure: "zero events" must say WHICH probe never fired.
        let flags = [
            (
                "root_exited",
                1,
                "the traced CLI never exited inside the capture",
            ),
            (
                "bounded",
                0,
                "the capture hit its bound before the workload ended",
            ),
            ("errors", 0, "DTrace reported errors"),
            (
                "saw_enter",
                1,
                "vcpu-run-enter never fired: the binary predates the probe or no guest ran",
            ),
            (
                "saw_exit",
                1,
                "vcpu-run-exit never fired: the binary predates the probe or no guest ran",
            ),
            (
                "saw_service",
                1,
                "hvpatch-syscall-service-begin never fired: no host-forwarded syscall was observed",
            ),
        ];
        for (field, expected, reason) in flags {
            if record.u64(field)? != expected {
                bail!(
                    "{PREFIX} capture refused: {reason} ({field}={})",
                    record.value(field)?
                );
            }
        }
        if record.value("status")? != "ok" {
            bail!("{PREFIX} capture status is not ok");
        }

        for (ordinal, vns) in host_after {
            let row = if ordinal >= NOT_SVC_KEY_BASE {
                not_svc.get_mut(&(ordinal - NOT_SVC_KEY_BASE))
            } else {
                classes.get_mut(&ordinal)
            };
            let row = row.ok_or_else(|| {
                anyhow!("{PREFIX} host time charged to exit key {ordinal} that never exited")
            })?;
            row.host_oncpu_ns = vns;
        }
        let not_svc_total: u64 = not_svc.values().map(|row| row.exits).sum();
        let syscall_exits = classes
            .get(&HostExitClass::Syscall.ordinal())
            .map_or(0, |row| row.exits);
        if not_svc_total > syscall_exits {
            bail!(
                "{PREFIX} {not_svc_total} non-svc hvc #2 exits exceed the {syscall_exits} class-3 exits they refine"
            );
        }
        let exits_total: u64 = classes.values().map(|row| row.exits).sum();
        let enters = enters.unwrap_or(0);
        if exits_total == 0 || enters == 0 {
            bail!("{PREFIX} capture refused: zero paired guest exits");
        }
        // Each paired exit consumed one enter; the remainder is runs still in
        // flight when the stream closed (at most one per vCPU thread).
        if enters < exits_total {
            bail!("{PREFIX} counted {exits_total} paired exits for only {enters} enters");
        }
        let forwarded_total: u64 = forwarded.values().map(|row| row.count).sum();
        if forwarded_total == 0 {
            bail!("{PREFIX} capture refused: zero host-forwarded syscalls");
        }

        let mut by_class = BTreeMap::new();
        let mut by_bucket: BTreeMap<&'static str, ExitRow> = BTreeMap::new();
        for class in HostExitClass::ALL {
            let row = classes.get(&class.ordinal()).copied().unwrap_or_default();
            by_class.insert(class.name(), row);
            let mut bucket_row = row;
            if class == HostExitClass::Syscall {
                bucket_row.exits -= not_svc_total;
            }
            by_bucket
                .entry(ExitBucket::of(class).as_str())
                .or_default()
                .add(bucket_row);
        }
        let mut hvc_not_svc = BTreeMap::new();
        for (ec, row) in &not_svc {
            by_bucket
                .entry(ExitBucket::of_el0_exception(*ec).as_str())
                .or_default()
                .add(*row);
            hvc_not_svc.insert(format!("ec={ec:#04x}"), *row);
        }
        let guest_oncpu_ns = classes.values().map(|row| row.guest_oncpu_ns).sum();
        let host_oncpu_ns = classes
            .values()
            .chain(not_svc.values())
            .map(|row| row.host_oncpu_ns)
            .sum();
        let mut forwarded: Vec<ForwardedRow> = forwarded.into_values().collect();
        forwarded.sort_by(|a, b| b.count.cmp(&a.count).then(a.nr.cmp(&b.nr)));
        Ok(Self {
            schema: "carrick.hvpatch-exit-attribution.v1",
            program_sha256,
            bound_s,
            enters,
            unpaired_exits: unpaired.unwrap_or(0),
            exits_total,
            by_class,
            hvc_not_svc,
            by_bucket,
            guest_oncpu_ns,
            host_oncpu_ns,
            forwarded_total,
            forwarded,
        })
    }

    pub(crate) fn render_human(&self) -> String {
        let pct = |part: u64, whole: u64| {
            if whole == 0 {
                0.0
            } else {
                100.0 * part as f64 / whole as f64
            }
        };
        let executor = self.guest_oncpu_ns + self.host_oncpu_ns;
        let mut out = format!(
            "HVPatch exit attribution (instrumented run; counts citable, times inflated): exits={} forwarded_syscalls={} guest_oncpu_ms={:.1} ({:.1}%) host_oncpu_ms={:.1} ({:.1}%)\n",
            self.exits_total,
            self.forwarded_total,
            self.guest_oncpu_ns as f64 / 1e6,
            pct(self.guest_oncpu_ns, executor),
            self.host_oncpu_ns as f64 / 1e6,
            pct(self.host_oncpu_ns, executor),
        );
        for (bucket, row) in &self.by_bucket {
            out.push_str(&format!(
                "  bucket {bucket:<10} exits={:>10} ({:>5.1}%) host_oncpu_ms={:>10.1}\n",
                row.exits,
                pct(row.exits, self.exits_total),
                row.host_oncpu_ns as f64 / 1e6,
            ));
        }
        for (class, row) in &self.by_class {
            if row.exits != 0 {
                out.push_str(&format!(
                    "    class {class:<12} exits={:>10} host_oncpu_ms={:>10.1}\n",
                    row.exits,
                    row.host_oncpu_ns as f64 / 1e6,
                ));
            }
        }
        for (ec, row) in &self.hvc_not_svc {
            out.push_str(&format!(
                "    hvc#2 not-svc {ec:<10} exits={:>10} host_oncpu_ms={:>10.1}\n",
                row.exits,
                row.host_oncpu_ns as f64 / 1e6,
            ));
        }
        for row in self.forwarded.iter().take(15) {
            out.push_str(&format!(
                "  forwarded nr={:<4} {:<20} count={:>10} wall_ms={:>10.1} oncpu_ms={:>10.1}\n",
                row.nr,
                row.name.unwrap_or("?"),
                row.count,
                row.wall_ns as f64 / 1e6,
                row.oncpu_ns as f64 / 1e6,
            ));
        }
        out.trim_end().to_owned()
    }
}

fn decode_class(ordinal: u32) -> Result<HostExitClass> {
    HostExitClass::from_ordinal(ordinal)
        .ok_or_else(|| anyhow!("{PREFIX} exit class ordinal {ordinal} names no HostExitClass"))
}

struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(PREFIX) {
            bail!("unknown {PREFIX} protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated {PREFIX} record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("{PREFIX} field lacks '=': {raw:?}"))?;
            if key.is_empty()
                || value.is_empty()
                || fields.insert(key.to_owned(), value.to_owned()).is_some()
            {
                bail!("empty or duplicate {PREFIX} field {key:?}");
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
            bail!("{PREFIX} {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, name: &str) -> Result<&str> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{PREFIX} {:?} lacks {name}", self.tag))
    }

    fn u64(&self, name: &str) -> Result<u64> {
        self.value(name)?
            .parse()
            .with_context(|| format!("{PREFIX} {:?} {name} is not a u64", self.tag))
    }

    fn u32(&self, name: &str) -> Result<u32> {
        self.value(name)?
            .parse()
            .with_context(|| format!("{PREFIX} {:?} {name} is not a u32", self.tag))
    }
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status.principal_drops != 0
        || status.aggregation_drops != 0
        || status.dynamic_drops != 0
        || status.dynamic_rinse_drops != 0
        || status.dynamic_dirty_drops != 0
        || status.other_drops != 0
        || status.interrupted
    {
        bail!("{PREFIX} capture is lossy or interrupted: {status:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "ab";

    fn stream(summary: &str, body: &[&str]) -> String {
        let mut lines = vec![
            format!("{PREFIX}|header|version=1|program_sha256={SHA}"),
            summary.to_owned(),
        ];
        lines.extend(body.iter().map(|line| (*line).to_owned()));
        lines.push(format!("{PREFIX}|end"));
        lines.join("\n")
    }

    const OK: &str = "HVPEXIT1|summary|status=ok|root_exited=1|bounded=0|errors=0|saw_enter=1|saw_exit=1|saw_service=1|bound_s=90";
    const BODY: &[&str] = &[
        "HVPEXIT1|enters|count=12",
        "HVPEXIT1|exit|class=3|count=7|guest_vns=700|guest_wall_ns=900",
        "HVPEXIT1|exit|class=6|count=3|guest_vns=300|guest_wall_ns=310",
        "HVPEXIT1|exit|class=0|count=1|guest_vns=10|guest_wall_ns=11",
        "HVPEXIT1|hvc-not-svc|ec=36|count=2",
        "HVPEXIT1|hvc-not-svc|ec=24|count=1",
        "HVPEXIT1|host-after-exit|class=3|vns=5000",
        "HVPEXIT1|host-after-exit|class=100|vns=400",
        "HVPEXIT1|host-after-exit|class=88|vns=50",
        "HVPEXIT1|host-after-exit|class=6|vns=2000",
        "HVPEXIT1|forwarded|nr=63|count=4|ended=4|wall_ns=4000|paired=4|oncpu_vns=3000",
        "HVPEXIT1|forwarded|nr=98|count=5|ended=5|wall_ns=90000|paired=5|oncpu_vns=1000",
    ];

    fn parse(text: &str) -> Result<HvpatchExitAttributionSummary> {
        HvpatchExitAttributionSummary::from_lines(
            text.lines(),
            ProfileCaptureStatus::default(),
            SHA,
        )
    }

    #[test]
    fn accepts_a_complete_census_and_folds_buckets() {
        let summary = parse(&stream(OK, BODY)).expect("valid census");
        assert_eq!(summary.exits_total, 11);
        assert_eq!(summary.forwarded_total, 9);
        assert_eq!(summary.by_class.len(), HostExitClass::COUNT);
        assert_eq!(summary.by_class["syscall"].exits, 7, "raw census untouched");
        assert_eq!(
            summary.by_bucket["syscall"].exits, 4,
            "7 hvc #2 minus 3 non-svc"
        );
        assert_eq!(
            summary.by_bucket["fault"].exits, 5,
            "3 direct + 2 EL0 data aborts"
        );
        assert_eq!(summary.by_bucket["fault"].host_oncpu_ns, 2400);
        assert_eq!(summary.by_bucket["kick-idle"].exits, 1);
        assert_eq!(summary.by_bucket["other"].exits, 1, "one sys64 trap");
        assert_eq!(summary.by_bucket["other"].host_oncpu_ns, 50);
        assert_eq!(summary.hvc_not_svc["ec=0x24"].exits, 2);
        assert_eq!(
            summary.by_bucket.values().map(|row| row.exits).sum::<u64>(),
            summary.exits_total
        );
        assert_eq!(summary.guest_oncpu_ns, 1010);
        assert_eq!(summary.host_oncpu_ns, 7450);
        assert_eq!(summary.forwarded[0].nr, 98, "sorted by count");
        assert_eq!(summary.forwarded[0].name, Some("futex"));
        assert_eq!(summary.forwarded[1].name, Some("read"));
        assert!(summary.render_human().contains("bucket syscall"));
    }

    #[test]
    fn zero_event_probes_fail_closed_and_name_the_probe() {
        for (field, needle) in [
            ("saw_enter", "vcpu-run-enter never fired"),
            ("saw_exit", "vcpu-run-exit never fired"),
            ("saw_service", "hvpatch-syscall-service-begin never fired"),
        ] {
            let summary = OK
                .replace(&format!("{field}=1"), &format!("{field}=0"))
                .replace("status=ok", "status=error");
            let error = parse(&stream(&summary, BODY)).expect_err(field);
            assert!(format!("{error:#}").contains(needle), "{field}: {error:#}");
        }
        let error = parse(&stream(OK, &["HVPEXIT1|enters|count=1"])).expect_err("no exits");
        assert!(
            format!("{error:#}").contains("zero paired guest exits"),
            "{error:#}"
        );
        let error = parse(&stream(OK, &BODY[..BODY.len() - 2])).expect_err("no forwarded");
        assert!(
            format!("{error:#}").contains("zero host-forwarded"),
            "{error:#}"
        );
    }

    #[test]
    fn refuses_bounded_lossy_errored_or_truncated_captures() {
        let bounded = OK.replace("bounded=0", "bounded=1");
        assert!(parse(&stream(&bounded, BODY)).is_err());
        let not_exited = OK.replace("root_exited=1", "root_exited=0");
        assert!(parse(&stream(&not_exited, BODY)).is_err());
        let lossy = ProfileCaptureStatus {
            aggregation_drops: 1,
            ..ProfileCaptureStatus::default()
        };
        assert!(
            HvpatchExitAttributionSummary::from_lines(stream(OK, BODY).lines(), lossy, SHA)
                .is_err()
        );
        let mut errored = BODY.to_vec();
        errored.push("HVPEXIT1|error|epid=1|action=2|offset=3|fault=4|value=0x0");
        assert!(parse(&stream(OK, &errored)).is_err());
        let truncated = stream(OK, BODY).replace("HVPEXIT1|end", "");
        assert!(format!("{:#}", parse(&truncated).expect_err("no end")).contains("end marker"));
        assert!(
            format!(
                "{:#}",
                HvpatchExitAttributionSummary::from_lines(
                    stream(OK, BODY).lines(),
                    ProfileCaptureStatus::default(),
                    "cd",
                )
                .expect_err("foreign program")
            )
            .contains("not the bundled")
        );
    }

    #[test]
    fn refuses_unknown_classes_and_inconsistent_rows() {
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|exit|class=8|count=1|guest_vns=1|guest_wall_ns=1");
        assert!(parse(&stream(OK, &body)).is_err());
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|host-after-exit|class=4|vns=1");
        assert!(
            parse(&stream(OK, &body)).is_err(),
            "host time for a class that never exited"
        );
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|hvc-not-svc|ec=1|count=5");
        assert!(
            parse(&stream(OK, &body)).is_err(),
            "more non-svc than class-3 exits"
        );
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|host-after-exit|class=65|vns=1");
        assert!(
            parse(&stream(OK, &body)).is_err(),
            "host time for an unseen non-svc EC"
        );
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|host-after-exit|class=128|vns=1");
        assert!(parse(&stream(OK, &body)).is_err());
        let mut body = BODY.to_vec();
        body[0] = "HVPEXIT1|enters|count=5";
        assert!(parse(&stream(OK, &body)).is_err(), "more exits than enters");
        let mut body = BODY.to_vec();
        body.push("HVPEXIT1|forwarded|nr=1|count=1|ended=1|wall_ns=1|paired=2|oncpu_vns=1");
        assert!(parse(&stream(OK, &body)).is_err());
        assert!(parse(&format!("{}\nstray", stream(OK, BODY))).is_err());
    }

    #[test]
    fn bundled_template_renders_its_digest_and_bound() {
        let template = bundled_template();
        assert_eq!(template.matches(PROGRAM_SHA256_PLACEHOLDER).count(), 1);
        assert_eq!(template.matches(BOUND_PLACEHOLDER).count(), 1);
        assert!(template.contains("bound_limit_s = (uint64_t)90;"));
        let rendered = render_profile_script(template).expect("render");
        assert!(rendered.contains(&format!("program_sha256={}", program_sha256())));
        assert!(!rendered.contains(PROGRAM_SHA256_PLACEHOLDER));
    }
}
