//! Reader for the `AMP1` Darwin kernel amplification ledger stream
//! (`scripts/dtrace/native-amplification.d`).
//!
//! This is the fail-closed half of the instrument: it decides whether a capture
//! is admissible evidence at all, before anything computes a ratio from it. The
//! four named refusals it owns are the ones a plausible-looking summary would
//! otherwise hide:
//!
//! * **wrong backend** — `carrick*:::native-syscall-service-*` never fires under
//!   the VMM backend, so every host call lands in `carrick-only` and the guest
//!   denominator is zero. That is an error, not an empty ledger.
//! * **truncated** — the declared capture bound fired mid-census.
//! * **unauthenticated program** — the header must name the digest of the
//!   BUNDLED template, so a `--script` capture or an edited program cannot
//!   authenticate its own stream.
//! * **drops** — DTrace drops silently, and on this instrument a silent drop
//!   reads as *lower* amplification and would be banked as good news. Both
//!   halves are enforced: the program-owned counters in `section=drops`, and
//!   libdtrace's own counters (principal / aggregation / dynamic / rinse /
//!   dirty), which are not readable from D and arrive through the run report. A
//!   MISSING drop section is itself a refusal — absent is not zero.
//!
//! Deliberately **not** here, and left for the typed ledger analyzer that
//! consumes this type: cross-section closure arithmetic (per-op sums against
//! the independent totals), the `probable_instrument` sub-bucket, guest-op name
//! resolution through `carrick_abi::syscall`, and every derived ratio. This
//! module answers "is this stream admissible", not "what does it say".

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::trace_profile::{AMPLIFICATION_RAW_SCHEMA, ProfileCaptureStatus};

const AMP1_PREFIX: &str = "AMP1";
const AMP1_PROFILE: &str = "native-amplification";

/// The bundled AMP1 program.
///
/// `carrick-runtime`'s `dtrace_consumer` bundles the same file for the CAPTURE
/// side, but that module is `cfg`-gated to hosts with libdtrace while this
/// reader has to authenticate a stream on every host the gate runs on. Both are
/// `include_str!` of one path; a `cfg`'d test asserts they stay byte-identical.
pub(crate) const BUNDLED_NATIVE_AMPLIFICATION_D: &str =
    include_str!("../../../scripts/dtrace/native-amplification.d");

/// The declared buffer headroom, echoed into the stream header so a capture
/// that ran at different sizes is a different instrument and can be refused
/// rather than silently compared.
const DECLARED_JOINS: &str = "syscall,mach,fault";
const DECLARED_BUFFERS: [(&str, &str); 3] = [
    ("aggsize", "aggsize=64m"),
    ("dynvarsize", "dynvarsize=256m"),
    ("bufsize", "bufsize=32m"),
];

const REQUIRED_SECTIONS: [&str; 12] = [
    "terminal-calls",
    "totals",
    "fault-totals",
    "guest-syscalls",
    "host-syscalls",
    "host-syscall-cpu",
    "host-syscall-returns",
    "mach-traps",
    "mach-trap-cpu",
    "mach-trap-returns",
    "faults",
    "drops",
];

const REQUIRED_METRICS: [&str; 7] = [
    "guest-syscall-total",
    "host-syscall-entry-total",
    "host-syscall-return-total",
    "host-syscall-cpu-ns",
    "mach-trap-entry-total",
    "mach-trap-return-total",
    "mach-trap-cpu-ns",
];

const FAULT_KINDS: [&str; 3] = ["as_fault", "zfod", "cow_fault"];

const REQUIRED_DROP_SOURCES: [&str; 3] = [
    "dtrace-error",
    "service-window-reentry",
    "service-end-unmatched",
];

/// A guest-op key as it appears on the wire.
///
/// The D program cannot name a Linux syscall, so it emits an ENCODED slot and
/// this is the one place allowed to decode it. `1` is `carrick-only`; a guest op
/// is `canonical_nr + 2`. The `+2` bias is not decoration: canonical number 0 is
/// a real syscall (`io_setup`), and DTrace deallocates an associative entry the
/// moment it is assigned zero, so the idle sentinel has to be nonzero too.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GuestSlot {
    /// Host work outside any guest service window: image setup, supervision,
    /// teardown, park/wake, and the tracer's own `kdebug_trace*` calls. Real
    /// cost, but NOT amplification of any guest op — it must never enter a
    /// per-op ratio, which is why it is a distinct variant and not a number.
    CarrickOnly,
    /// A canonical AArch64 Linux syscall number.
    Guest(u64),
}

impl GuestSlot {
    fn decode(raw: u64) -> Result<Self> {
        match raw {
            0 => bail!(
                "AMP1 guest_slot 0 is unreachable by construction (1 is carrick-only, a guest op is nr+2); the stream's slot encoding drifted"
            ),
            1 => Ok(Self::CarrickOnly),
            other => Ok(Self::Guest(other - 2)),
        }
    }
}

/// One admissible AMP1 capture.
///
/// Every field is exactly what the stream carried; nothing here is derived.
/// The capture path reads a few of them for its acceptance receipt; the rest
/// are the typed ledger analyzer's input, which is why the whole surface is
/// parsed and validated here rather than left for a second reader to re-derive.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct Amp1Capture {
    pub(crate) os_build: String,
    pub(crate) program_sha256: String,
    pub(crate) birth_qualification_sha256: String,
    pub(crate) terminal_qualification_sha256: String,
    pub(crate) joins: String,
    pub(crate) terminal_calls: BTreeSet<(String, String, String)>,
    pub(crate) totals: BTreeMap<String, u64>,
    pub(crate) fault_totals: BTreeMap<String, u64>,
    pub(crate) guest_syscalls: BTreeMap<GuestSlot, u64>,
    pub(crate) host_syscalls: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) host_syscall_cpu_ns: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) host_syscall_max_ns: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) host_syscall_returns: BTreeMap<String, u64>,
    pub(crate) mach_traps: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) mach_trap_cpu_ns: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) mach_trap_returns: BTreeMap<String, u64>,
    pub(crate) faults: BTreeMap<(GuestSlot, String), u64>,
    pub(crate) drops: BTreeMap<String, u64>,
    pub(crate) bound_limit_s: u64,
    pub(crate) target_exit_reason: i64,
    /// Traced elapsed nanoseconds. DIAGNOSTIC METADATA ONLY: four probe
    /// families in one program perturb wall by an expected 2–4x, so counts and
    /// same-instrument ratios are citable and wall never is.
    pub(crate) elapsed_ns: u64,
}

pub(crate) fn amp1_program_sha256() -> String {
    let digest = Sha256::digest(BUNDLED_NATIVE_AMPLIFICATION_D.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a stream is an AMP1 capture, from its first non-empty line.
pub(crate) fn is_amp1_stream(contents: &str) -> bool {
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.starts_with("AMP1|header|"))
}

pub(crate) fn validate_amp1_path(
    path: &Path,
    capture_status: ProfileCaptureStatus,
) -> Result<Amp1Capture> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("read AMP1 stream {}", path.display()))?;
    validate_amp1_lines(contents.lines(), capture_status)
}

pub(crate) fn validate_amp1_lines<I, S>(
    lines: I,
    capture_status: ProfileCaptureStatus,
) -> Result<Amp1Capture>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut reader = Amp1Reader::default();
    for (index, line) in lines.into_iter().enumerate() {
        let line = line.as_ref().trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            continue;
        }
        reader
            .absorb(line)
            .with_context(|| format!("AMP1 line {}", index + 1))?;
    }
    reader.finish(capture_status)
}

/// A `k=v|k=v` record body, order preserved so a section can pin the exact
/// field sequence its `printa` emits.
struct Fields<'a> {
    entries: Vec<(&'a str, &'a str)>,
}

impl<'a> Fields<'a> {
    fn parse(parts: &[&'a str]) -> Result<Self> {
        let mut entries = Vec::with_capacity(parts.len());
        let mut seen = BTreeSet::new();
        for part in parts {
            let Some((name, value)) = part.split_once('=') else {
                bail!("AMP1 field {part:?} is not name=value");
            };
            if name.is_empty() || value.is_empty() {
                bail!("AMP1 field {part:?} has an empty name or value");
            }
            if !seen.insert(name) {
                bail!("AMP1 record repeats field {name:?}");
            }
            entries.push((name, value));
        }
        Ok(Self { entries })
    }

    fn shape(&self) -> Vec<&'a str> {
        self.entries.iter().map(|(name, _)| *name).collect()
    }

    fn require(&self, name: &str) -> Result<&'a str> {
        self.entries
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| *value)
            .ok_or_else(|| anyhow::anyhow!("AMP1 record is missing field {name:?}"))
    }

    fn require_u64(&self, name: &str) -> Result<u64> {
        let raw = self.require(name)?;
        raw.parse::<u64>()
            .with_context(|| format!("AMP1 field {name}={raw:?} is not an unsigned integer"))
    }

    fn require_i64(&self, name: &str) -> Result<i64> {
        let raw = self.require(name)?;
        raw.parse::<i64>()
            .with_context(|| format!("AMP1 field {name}={raw:?} is not an integer"))
    }
}

#[derive(Default)]
struct Amp1Reader {
    header: Option<HeaderRecord>,
    section: Option<String>,
    seen_sections: BTreeSet<String>,
    truncated: Option<String>,
    complete: Option<CompleteRecord>,
    terminal_calls: BTreeSet<(String, String, String)>,
    totals: BTreeMap<String, u64>,
    fault_totals: BTreeMap<String, u64>,
    guest_syscalls: BTreeMap<GuestSlot, u64>,
    host_syscalls: BTreeMap<(GuestSlot, String), u64>,
    host_syscall_cpu_ns: BTreeMap<(GuestSlot, String), u64>,
    host_syscall_max_ns: BTreeMap<(GuestSlot, String), u64>,
    host_syscall_returns: BTreeMap<String, u64>,
    mach_traps: BTreeMap<(GuestSlot, String), u64>,
    mach_trap_cpu_ns: BTreeMap<(GuestSlot, String), u64>,
    mach_trap_returns: BTreeMap<String, u64>,
    faults: BTreeMap<(GuestSlot, String), u64>,
    drops: BTreeMap<String, u64>,
}

struct HeaderRecord {
    os_build: String,
    program_sha256: String,
    birth_qualification_sha256: String,
    terminal_qualification_sha256: String,
    joins: String,
}

struct CompleteRecord {
    timed_out: u64,
    target_exit_reason: i64,
    probe_errors: u64,
    bound_limit_s: u64,
    elapsed_ns: u64,
}

fn insert_unique<K: Ord + std::fmt::Debug>(
    map: &mut BTreeMap<K, u64>,
    key: K,
    value: u64,
) -> Result<()> {
    match map.entry(key) {
        Entry::Vacant(slot) => {
            slot.insert(value);
            Ok(())
        }
        Entry::Occupied(slot) => bail!("AMP1 repeats aggregation row {:?}", slot.key()),
    }
}

impl Amp1Reader {
    fn absorb(&mut self, line: &str) -> Result<()> {
        let mut parts = line.split('|');
        if parts.next() != Some(AMP1_PREFIX) {
            bail!("expected an {AMP1_PREFIX} record prefix: {line:?}");
        }
        let rest: Vec<&str> = parts.collect();
        let Some((kind, body)) = rest.split_first() else {
            bail!("truncated {AMP1_PREFIX} record: {line:?}");
        };

        if *kind == "header" {
            if self.header.is_some() {
                bail!("AMP1 stream carries a second header");
            }
            return self.absorb_header(body);
        }
        if self.header.is_none() {
            bail!("the first {AMP1_PREFIX} record must be the stream header, got {kind:?}");
        }
        if let Some(name) = kind.strip_prefix("section=") {
            return self.absorb_section(name, body);
        }
        match *kind {
            "terminal-call" => self.absorb_terminal_call(body),
            "drop" => self.absorb_drop(body),
            "complete" => self.absorb_complete(body),
            _ => self.absorb_row(kind, body),
        }
    }

    fn absorb_section(&mut self, name: &str, body: &[&str]) -> Result<()> {
        if name == "truncated" {
            let fields = Fields::parse(body)?;
            self.truncated = Some(fields.require("reason")?.to_owned());
            return Ok(());
        }
        if !body.is_empty() {
            bail!("AMP1 section marker {name:?} carries unexpected fields");
        }
        if !REQUIRED_SECTIONS.contains(&name) {
            bail!("unknown AMP1 section {name:?}");
        }
        if !self.seen_sections.insert(name.to_owned()) {
            bail!("AMP1 stream repeats section {name:?}");
        }
        self.section = Some(name.to_owned());
        Ok(())
    }

    fn absorb_terminal_call(&mut self, body: &[&str]) -> Result<()> {
        self.require_section("terminal-calls")?;
        let fields = Fields::parse(body)?;
        let provider = fields.require("provider")?;
        if !matches!(provider, "syscall" | "mach_trap") {
            bail!("AMP1 terminal call names an unknown provider {provider:?}");
        }
        let scope = fields.require("scope")?;
        if !matches!(scope, "thread" | "process") {
            bail!("AMP1 terminal call names an unknown scope {scope:?}");
        }
        let call = (
            provider.to_owned(),
            fields.require("function")?.to_owned(),
            scope.to_owned(),
        );
        if !self.terminal_calls.insert(call) {
            bail!("AMP1 stream repeats a terminal-call row");
        }
        Ok(())
    }

    fn absorb_drop(&mut self, body: &[&str]) -> Result<()> {
        self.require_section("drops")?;
        let fields = Fields::parse(body)?;
        let source = fields.require("source")?;
        if !REQUIRED_DROP_SOURCES.contains(&source) {
            bail!("AMP1 stream declares an unknown drop source {source:?}");
        }
        insert_unique(
            &mut self.drops,
            source.to_owned(),
            fields.require_u64("count")?,
        )
    }

    fn absorb_complete(&mut self, body: &[&str]) -> Result<()> {
        if self.complete.is_some() {
            bail!("AMP1 stream carries a second completion record");
        }
        let fields = Fields::parse(body)?;
        let profile = fields.require("profile")?;
        if profile != AMP1_PROFILE {
            bail!("AMP1 completion record names profile {profile:?}");
        }
        self.complete = Some(CompleteRecord {
            timed_out: fields.require_u64("timed_out")?,
            target_exit_reason: fields.require_i64("target_exit_reason")?,
            probe_errors: fields.require_u64("probe_errors")?,
            bound_limit_s: fields.require_u64("bound_limit_s")?,
            elapsed_ns: fields.require_u64("elapsed_ns")?,
        });
        Ok(())
    }

    fn absorb_row(&mut self, kind: &str, body: &[&str]) -> Result<()> {
        // A data row's meaning comes from the section it sits in, exactly as
        // the D program's `printa` order defines it. A row outside a section,
        // or with the wrong field sequence, is a refusal rather than a guess.
        let mut parts = Vec::with_capacity(body.len() + 1);
        parts.push(kind);
        parts.extend_from_slice(body);
        let fields = Fields::parse(&parts)?;
        let Some(section) = self.section.clone() else {
            bail!("AMP1 data row appears before any section marker");
        };
        let shape = fields.shape();
        match (section.as_str(), shape.as_slice()) {
            ("totals", ["metric", "count"]) => insert_unique(
                &mut self.totals,
                fields.require("metric")?.to_owned(),
                fields.require_u64("count")?,
            ),
            ("fault-totals", ["kind", "count"]) => insert_unique(
                &mut self.fault_totals,
                fields.require("kind")?.to_owned(),
                fields.require_u64("count")?,
            ),
            ("guest-syscalls", ["guest_slot", "count"]) => insert_unique(
                &mut self.guest_syscalls,
                GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                fields.require_u64("count")?,
            ),
            ("host-syscalls", ["guest_slot", "host", "count"]) => insert_unique(
                &mut self.host_syscalls,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("host")?.to_owned(),
                ),
                fields.require_u64("count")?,
            ),
            ("host-syscall-cpu", ["guest_slot", "host", "cpu_ns"]) => insert_unique(
                &mut self.host_syscall_cpu_ns,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("host")?.to_owned(),
                ),
                fields.require_u64("cpu_ns")?,
            ),
            ("host-syscall-cpu", ["guest_slot", "host", "max_ns"]) => insert_unique(
                &mut self.host_syscall_max_ns,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("host")?.to_owned(),
                ),
                fields.require_u64("max_ns")?,
            ),
            ("host-syscall-returns", ["host", "count"]) => insert_unique(
                &mut self.host_syscall_returns,
                fields.require("host")?.to_owned(),
                fields.require_u64("count")?,
            ),
            ("mach-traps", ["guest_slot", "trap", "count"]) => insert_unique(
                &mut self.mach_traps,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("trap")?.to_owned(),
                ),
                fields.require_u64("count")?,
            ),
            ("mach-trap-cpu", ["guest_slot", "trap", "cpu_ns"]) => insert_unique(
                &mut self.mach_trap_cpu_ns,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("trap")?.to_owned(),
                ),
                fields.require_u64("cpu_ns")?,
            ),
            ("mach-trap-returns", ["trap", "count"]) => insert_unique(
                &mut self.mach_trap_returns,
                fields.require("trap")?.to_owned(),
                fields.require_u64("count")?,
            ),
            ("faults", ["guest_slot", "kind", "count"]) => insert_unique(
                &mut self.faults,
                (
                    GuestSlot::decode(fields.require_u64("guest_slot")?)?,
                    fields.require("kind")?.to_owned(),
                ),
                fields.require_u64("count")?,
            ),
            (section, shape) => {
                bail!("AMP1 section {section:?} does not define a row shaped {shape:?}")
            }
        }
    }

    fn require_section(&self, expected: &str) -> Result<()> {
        match self.section.as_deref() {
            Some(active) if active == expected => Ok(()),
            Some(active) => bail!("AMP1 {expected:?} row appeared inside section {active:?}"),
            None => bail!("AMP1 {expected:?} row appeared before any section marker"),
        }
    }

    fn absorb_header(&mut self, body: &[&str]) -> Result<()> {
        let fields = Fields::parse(body)?;
        let profile = fields.require("profile")?;
        if profile != AMP1_PROFILE {
            bail!("AMP1 header names profile {profile:?}, not {AMP1_PROFILE:?}");
        }
        let schema = fields.require("raw_schema")?;
        if schema != AMPLIFICATION_RAW_SCHEMA {
            bail!("AMP1 header names raw schema {schema:?}, not {AMPLIFICATION_RAW_SCHEMA:?}");
        }
        let program_sha256 = fields.require("program_sha256")?;
        let expected = amp1_program_sha256();
        if program_sha256 != expected {
            bail!(
                "AMP1 header program_sha256 {program_sha256} does not name the bundled native-amplification program ({expected}); a --script capture or an edited program cannot authenticate its own stream"
            );
        }
        let joins = fields.require("joins")?;
        if joins != DECLARED_JOINS {
            bail!("AMP1 header declares joins {joins:?}, not {DECLARED_JOINS:?}");
        }
        // The buffer headroom is a capture determinant, so the header's copy
        // must agree with the pragmas the bundled program actually ran with.
        for (field, pragma) in DECLARED_BUFFERS {
            let declared = fields.require(field)?;
            let value = pragma
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap_or_default();
            if declared != value {
                bail!("AMP1 header declares {field}={declared}, not {value}");
            }
            if !BUNDLED_NATIVE_AMPLIFICATION_D.contains(&format!("#pragma D option {pragma}")) {
                bail!("the bundled AMP1 program no longer declares `{pragma}`");
            }
        }
        self.header = Some(HeaderRecord {
            os_build: fields.require("os_build")?.to_owned(),
            program_sha256: program_sha256.to_owned(),
            birth_qualification_sha256: fields.require("birth_qualification_sha256")?.to_owned(),
            terminal_qualification_sha256: fields
                .require("terminal_qualification_sha256")?
                .to_owned(),
            joins: joins.to_owned(),
        });
        Ok(())
    }

    fn finish(mut self, capture_status: ProfileCaptureStatus) -> Result<Amp1Capture> {
        let Some(header) = self.header.take() else {
            bail!("AMP1 stream carries no header record");
        };
        if let Some(reason) = &self.truncated {
            bail!(
                "AMP1 capture is truncated (reason={reason}); a partial census can never be read as a complete one"
            );
        }
        for section in REQUIRED_SECTIONS {
            if !self.seen_sections.contains(section) {
                bail!(
                    "AMP1 stream is missing required section {section:?}; a section that printed nothing is not a section that printed zero"
                );
            }
        }
        let Some(complete) = self.complete.take() else {
            bail!("AMP1 stream never reached its completion record");
        };
        if complete.timed_out != 0 {
            bail!(
                "AMP1 capture hit its declared bound of {}s",
                complete.bound_limit_s
            );
        }
        if complete.probe_errors != 0 {
            bail!(
                "AMP1 capture recorded {} D action faults; the exact stream is not authoritative",
                complete.probe_errors
            );
        }
        for metric in REQUIRED_METRICS {
            if !self.totals.contains_key(metric) {
                bail!("AMP1 totals section is missing required metric {metric:?}");
            }
        }
        for kind in FAULT_KINDS {
            if !self.fault_totals.contains_key(kind) {
                bail!("AMP1 fault totals are missing required kind {kind:?}");
            }
        }
        for source in REQUIRED_DROP_SOURCES {
            match self.drops.get(source) {
                None => {
                    bail!("AMP1 drop section is missing counter {source:?}; absent is not zero")
                }
                Some(0) => {}
                Some(count) => bail!(
                    "AMP1 capture recorded {count} {source} drops; a dropped event reads as LOWER amplification and must never be banked"
                ),
            }
        }
        // libdtrace's own drop counters are not readable from D, so the run
        // report is the only place they can be enforced.
        require_no_consumer_drops(capture_status)?;

        let guest_total = self.totals.get("guest-syscall-total").copied().unwrap_or(0);
        if guest_total == 0 {
            bail!(
                "AMP1 capture recorded no guest syscalls (wrong-backend): `native-syscall-service-*` never fires under the VMM backend, so every host call would land in `carrick-only`. Re-run with `--exec-backend native`."
            );
        }

        Ok(Amp1Capture {
            os_build: header.os_build,
            program_sha256: header.program_sha256,
            birth_qualification_sha256: header.birth_qualification_sha256,
            terminal_qualification_sha256: header.terminal_qualification_sha256,
            joins: header.joins,
            terminal_calls: self.terminal_calls,
            totals: self.totals,
            fault_totals: self.fault_totals,
            guest_syscalls: self.guest_syscalls,
            host_syscalls: self.host_syscalls,
            host_syscall_cpu_ns: self.host_syscall_cpu_ns,
            host_syscall_max_ns: self.host_syscall_max_ns,
            host_syscall_returns: self.host_syscall_returns,
            mach_traps: self.mach_traps,
            mach_trap_cpu_ns: self.mach_trap_cpu_ns,
            mach_trap_returns: self.mach_trap_returns,
            faults: self.faults,
            drops: self.drops,
            bound_limit_s: complete.bound_limit_s,
            target_exit_reason: complete.target_exit_reason,
            elapsed_ns: complete.elapsed_ns,
        })
    }
}

fn require_no_consumer_drops(status: ProfileCaptureStatus) -> Result<()> {
    let counters = [
        ("principal", status.principal_drops),
        ("aggregation", status.aggregation_drops),
        ("dynamic", status.dynamic_drops),
        ("dynamic_rinse", status.dynamic_rinse_drops),
        ("dynamic_dirty", status.dynamic_dirty_drops),
        ("other", status.other_drops),
    ];
    if counters.iter().any(|(_, count)| *count != 0) {
        let rendered = counters
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("AMP1 capture lost events to libdtrace drops ({rendered})");
    }
    if status.interrupted {
        bail!("AMP1 capture was interrupted before its census completed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_slot_decodes_carrick_only_and_canonical_numbers() {
        assert_eq!(GuestSlot::decode(1).unwrap(), GuestSlot::CarrickOnly);
        // Canonical number 0 (`io_setup`) round-trips, which is the whole
        // reason the encoding is biased by two rather than by one.
        assert_eq!(GuestSlot::decode(2).unwrap(), GuestSlot::Guest(0));
        assert_eq!(GuestSlot::decode(58).unwrap(), GuestSlot::Guest(56));
        assert!(
            format!("{:#}", GuestSlot::decode(0).unwrap_err()).contains("slot encoding drifted")
        );
    }

    #[test]
    fn bundled_amplification_program_matches_the_capture_side_copy() {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        assert_eq!(
            BUNDLED_NATIVE_AMPLIFICATION_D,
            carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_AMPLIFICATION_D,
            "the reader's authority anchor and the capture-side bundle are the same file"
        );
    }

    /// The fixture is the reader's, but the header the CAPTURE path renders is
    /// the authority's. Nothing else in the tree closes that loop without a
    /// live dtrace run, and a header/reader mismatch would otherwise surface
    /// only on the first armed capture.
    #[test]
    fn the_capture_paths_own_header_is_accepted_by_this_reader() {
        let authority = crate::trace_profile::V2ProfileAuthority::new_for_profile(
            crate::trace_profile::TraceProfileKind::NativeAmplification,
            "27A5295i",
            &amp1_program_sha256(),
            &"11".repeat(32),
            &"22".repeat(32),
            [
                (
                    "syscall".to_owned(),
                    "exit".to_owned(),
                    "process".to_owned(),
                ),
                (
                    "syscall".to_owned(),
                    "bsdthread_terminate".to_owned(),
                    "thread".to_owned(),
                ),
            ],
        )
        .expect("native-amplification launch authority");

        let fixture = include_str!("../tests/fixtures/amp1-valid.raw")
            .replace("@PROGRAM_SHA256@", &amp1_program_sha256());
        let fixture_header = fixture.lines().next().expect("fixture header");
        let rendered = authority.header_record();
        assert_eq!(
            rendered, fixture_header,
            "the rendered capture header and the reader's fixture must be the same record"
        );

        let stream = fixture.replacen(fixture_header, &rendered, 1);
        let capture = validate_amp1_lines(stream.lines(), ProfileCaptureStatus::default())
            .expect("the capture path's own header must authenticate");
        assert_eq!(capture.os_build, "27A5295i");
        assert_eq!(capture.joins, DECLARED_JOINS);
        assert_eq!(capture.terminal_calls.len(), 2);
        assert_eq!(capture.guest_syscalls[&GuestSlot::Guest(56)], 4);
        assert_eq!(
            capture.host_syscalls[&(GuestSlot::CarrickOnly, "kdebug_trace64".to_owned())],
            5
        );
    }

    #[test]
    fn program_digest_is_the_digest_of_the_bundled_template() {
        let digest = amp1_program_sha256();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
