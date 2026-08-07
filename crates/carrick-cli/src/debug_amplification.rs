//! The typed Darwin kernel amplification ledger — `carrick debug
//! amplification-ledger`.
//!
//! This is the half of the instrument that says what a capture MEANS.
//! `amplification_profile.rs` decides whether an `AMP1` stream is admissible at
//! all; everything here is derived, and the derivation is fail-closed in three
//! specific ways that the fs-census entry could only argue in prose:
//!
//! * **Closure is asserted, not reported.** The per-guest-op sums must equal
//!   the program's own independent, ungrouped totals — every host syscall,
//!   every nanosecond of host syscall CPU, every mach trap, every fault. A
//!   mismatch is a named failure, so a partial capture cannot yield a
//!   plausible-looking ledger with quietly smaller numbers. Smaller numbers on
//!   this instrument read as LOWER amplification, i.e. as good news, which is
//!   exactly why they may never be inferred.
//! * **`carrick-only` is a first-class bucket that cannot carry a ratio.**
//!   Host work outside any guest service window — image setup, supervision,
//!   teardown, park/wake — is real CPU but is not amplification of anything.
//!   [`CarrickOnly`] has no amplification field, so the rule is held by the
//!   compiler rather than by a reviewer. Its `probable_instrument` sub-bucket
//!   (libdtrace's own `kdebug_trace*`) is subtracted out of the budget rather
//!   than left for a reader to discover, and an instrument call observed
//!   INSIDE a guest service window is a named refusal, not a rounding error.
//! * **A `--script` capture cannot produce a ledger.** The stream header must
//!   name the digest of the bundled `native-amplification.d`, re-checked here
//!   and again on every parse of a published ledger. That is the whole point
//!   of moving this census under `--profile`.
//!
//! **What closure CANNOT see, and what closes it.** Closure sums across ALL
//! slots, so it is blind to MISATTRIBUTION: move a `(guest_op, host_call)` row
//! from a guest slot into `carrick-only` and every sum is unchanged, every
//! closure pair still holds, and the guest op's amplification simply falls.
//! That is not a hypothetical shape — it is exactly what a libdtrace DYNAMIC
//! drop produces when the `service_slot[pid, tid]` entry is lost, and its
//! symptom is an amplification that IMPROVED. The only detector is the
//! consumer-side drop counters, which are not readable from D (the D header's
//! fact 10). They used to exist only in the live `DTraceRunReport`, which meant
//! a raw file left behind by a FAILED capture could launder a lower
//! amplification past every offline check; `carrick trace` now writes them into
//! the stream as an `AMP1|consumer-drops|…` record, so an archived raw carries
//! its own drop verdict and this analyzer refuses it here as well as at
//! capture. `authority.consumer_drops` is that verdict, published with the
//! ledger.
//!
//! **The instrument sub-bucket is `kdebug_trace*` and nothing else.** That is
//! libdtrace's buffer traffic, which is the dominant term, but the in-process
//! consumer also opens and pumps the dtrace device: those `ioctl` and `read`
//! calls stay charged to carrick in `carrick_only`, unseparated. A reading that
//! quotes `carrick_only.excluding_probable_instrument` as "carrick's own
//! supervision cost" is therefore quoting an upper bound.
//!
//! **Two deliberate departures from the plan's schema sketch, both toward
//! exactness.** Ratios are exact integer [`LedgerFraction`]s (`host_calls` over
//! `guest_count`), never floats, following the `debug_jit_shape` census's
//! determinant-locked arithmetic — a float would make byte-identical re-runs a
//! platform question. And the budget block reports the capture's own measured
//! decomposition instead of a `share_of_kernel_budget_gap` against the plan's
//! 7.555 CPU-s figure: that denominator has already been superseded once
//! (`2026-08-06-post-arena-default-refresh.md` moved the ratio from 10.1776x to
//! 10.8586x) and baking a drifting number into a standing instrument would let
//! every future ledger quote a stale gap with no way to see that it was stale.
//! The document that cites a gap is where a gap belongs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use carrick_runtime::linux_abi::CanonicalNr;
use carrick_runtime::syscall::lookup_aarch64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::amplification_profile::{
    Amp1Capture, CONSUMER_DROP_COUNTERS, GuestSlot, amp1_program_sha256,
    validate_archived_amp1_path,
};
use crate::quiet_host::QuietHostReceipt;
use crate::trace_profile::{AMPLIFICATION_RAW_SCHEMA, ProfileProvenance, capture_provenance};

pub(crate) const LEDGER_SCHEMA: &str = "carrick.amplification-ledger.v1";

/// The tracer's own host syscalls.
///
/// `carrick trace` runs libdtrace IN-PROCESS, so its `kdebug_trace*` traffic is
/// captured by the very program it is carrying — the fs census found 3,182 of
/// them, 6.4% of that run. They land in `carrick-only` (the consumer thread
/// never has a guest service window open), where this list splits them into a
/// named sub-bucket so the instrument's cost is identifiable instead of hidden
/// inside carrick's own supervision traffic.
///
/// This is buffer traffic ONLY. The in-process consumer also opens and pumps
/// the dtrace device, and those `ioctl`/`read` calls are indistinguishable by
/// name from carrick's own, so they stay charged to `carrick-only`. Anything
/// quoting the remainder as carrick's supervision cost is quoting an upper
/// bound; naming a wider set here would need a way to tell the two apart.
const PROBABLE_INSTRUMENT_CALLS: [&str; 3] =
    ["kdebug_trace", "kdebug_trace64", "kdebug_trace_string"];

const FAULT_AS_FAULT: &str = "as_fault";
const FAULT_ZFOD: &str = "zfod";
const FAULT_COW_FAULT: &str = "cow_fault";

const METRIC_GUEST_SYSCALLS: &str = "guest-syscall-total";
const METRIC_HOST_SYSCALL_ENTRIES: &str = "host-syscall-entry-total";
const METRIC_HOST_SYSCALL_RETURNS: &str = "host-syscall-return-total";
const METRIC_HOST_SYSCALL_CPU_NS: &str = "host-syscall-cpu-ns";
const METRIC_MACH_TRAP_ENTRIES: &str = "mach-trap-entry-total";
const METRIC_MACH_TRAP_RETURNS: &str = "mach-trap-return-total";
const METRIC_MACH_TRAP_CPU_NS: &str = "mach-trap-cpu-ns";

const WINDOW_INHERITED_END: &str = "inherited-end";

/// An exact ratio, kept as its two integers.
///
/// The ledger's headline quantities — host calls per guest op, host CPU-ns per
/// guest op — are ratios that get compared across captures, so they are carried
/// as the arithmetic that produced them rather than as a rounded quotient. This
/// mirrors `debug_jit_shape`'s `CensusFraction`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerFraction {
    pub(crate) numerator: u64,
    pub(crate) denominator: u64,
}

impl LedgerFraction {
    fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    fn require(&self, numerator: u64, denominator: u64, label: &str) -> Result<()> {
        if self.numerator != numerator || self.denominator != denominator {
            bail!("amplification ledger {label} is not the exact ratio of its own fields");
        }
        if self.denominator == 0 {
            bail!("amplification ledger {label} has a zero denominator");
        }
        Ok(())
    }
}

/// A guest operation, named ONLY by the canonical AArch64 syscall table.
///
/// There is no constructor from a bare string and none from a name/number pair:
/// the sole way to obtain one is [`GuestOp::resolve`] from a [`CanonicalNr`],
/// which fails by name for a number the table does not define. That is the
/// typed-domain rule applied to this boundary — the D program deliberately
/// carries the NUMBER (no `copyinstr`), and a ledger row for an op carrick
/// cannot name is a corrupt stream, not a row to print with a placeholder.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestOp {
    // PRIVATE, like `HostCall`/`MachTrap`: public fields would let a struct
    // literal elsewhere in the crate assemble a number/name pair that the
    // table never agreed to. Deserialization can still build one, which is why
    // `validate` re-resolves every row on parse.
    canonical_nr: CanonicalNr,
    name: String,
}

impl GuestOp {
    fn canonical_nr(&self) -> CanonicalNr {
        self.canonical_nr
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn resolve(canonical_nr: CanonicalNr) -> Result<Self> {
        let entry = lookup_aarch64(canonical_nr.raw()).ok_or_else(|| {
            anyhow!(
                "AMP1 attributes host work to guest op {} which the canonical aarch64 syscall table does not define; the capture's slot encoding or the guest ISA disagrees with `carrick_abi::syscall`",
                canonical_nr.raw()
            )
        })?;
        Ok(Self {
            canonical_nr,
            name: entry.name.to_owned(),
        })
    }

    fn validate(&self) -> Result<()> {
        let resolved = Self::resolve(self.canonical_nr)?;
        if resolved.name != self.name {
            bail!(
                "amplification ledger names guest op {} {:?}, but the canonical aarch64 table calls it {:?}",
                self.canonical_nr.raw(),
                self.name,
                resolved.name
            );
        }
        Ok(())
    }
}

/// A Darwin syscall name as `probefunc` reported it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct HostCall(String);

/// A Mach trap name. A DISTINCT domain from [`HostCall`]: mach traps are not
/// syscalls, which is the whole reason this instrument joins both — a
/// `syscall:::`-only census missed two thirds of the large-zone allocation mass
/// because libmalloc reaches the kernel through `mach_vm_allocate`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct MachTrap(String);

fn validate_probe_function(raw: &str, label: &str) -> Result<()> {
    if raw.is_empty() {
        bail!("amplification ledger {label} is empty");
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'|')
    {
        bail!("amplification ledger {label} {raw:?} is not a bare probe function name");
    }
    Ok(())
}

impl HostCall {
    fn parse(raw: &str) -> Result<Self> {
        validate_probe_function(raw, "host call")?;
        Ok(Self(raw.to_owned()))
    }

    fn is_probable_instrument(&self) -> bool {
        PROBABLE_INSTRUMENT_CALLS.contains(&self.0.as_str())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl MachTrap {
    fn parse(raw: &str) -> Result<Self> {
        validate_probe_function(raw, "mach trap")?;
        Ok(Self(raw.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FaultCounts {
    pub(crate) as_fault: u64,
    pub(crate) zfod: u64,
    pub(crate) cow_fault: u64,
}

impl FaultCounts {
    fn add(&mut self, kind: &str, count: u64) -> Result<()> {
        let slot = match kind {
            FAULT_AS_FAULT => &mut self.as_fault,
            FAULT_ZFOD => &mut self.zfod,
            FAULT_COW_FAULT => &mut self.cow_fault,
            other => bail!("AMP1 fault join names unknown kind {other:?}"),
        };
        *slot = slot
            .checked_add(count)
            .context("amplification ledger fault count overflow")?;
        Ok(())
    }

    fn accumulate(&mut self, other: &Self) -> Result<()> {
        self.add(FAULT_AS_FAULT, other.as_fault)?;
        self.add(FAULT_ZFOD, other.zfod)?;
        self.add(FAULT_COW_FAULT, other.cow_fault)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerProvenance {
    pub(crate) binary_sha256: String,
    pub(crate) git_sha: String,
    pub(crate) git_dirty: Option<bool>,
    pub(crate) run_id: String,
    pub(crate) host: String,
    pub(crate) command: Vec<String>,
}

impl From<ProfileProvenance> for LedgerProvenance {
    fn from(value: ProfileProvenance) -> Self {
        Self {
            binary_sha256: value.binary_sha256,
            git_sha: value.git_sha,
            git_dirty: value.git_dirty,
            run_id: value.run_id,
            host: value.host,
            command: value.command,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalCall {
    pub(crate) provider: String,
    pub(crate) function: String,
    pub(crate) scope: String,
}

/// What makes the capture evidence rather than output.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerAuthority {
    pub(crate) program_sha256: String,
    pub(crate) raw_schema: String,
    pub(crate) joins: String,
    /// The `aggsize` / `dynvarsize` / `bufsize` the capture declared. Recorded
    /// rather than merely checked, because a ledger that cannot say what
    /// headroom it ran at cannot be refused a comparison against one that ran
    /// at another.
    pub(crate) declared_buffers: BTreeMap<String, String>,
    pub(crate) os_build: String,
    /// The canonical, digest-pinned image, and the digest of the traced `run`
    /// argv: together, the fixture this ledger is about.
    pub(crate) image: String,
    pub(crate) target_argv_sha256: String,
    /// The quiet-host preflight receipt, when the capture demanded one. `None`
    /// means the capture never asked — which is exactly what a reader needs to
    /// know before quoting its CPU-ns.
    pub(crate) preflight: Option<QuietHostReceipt>,
    pub(crate) birth_qualification_sha256: String,
    pub(crate) terminal_qualification_sha256: String,
    pub(crate) bound_limit_s: u64,
    pub(crate) truncated: bool,
    pub(crate) target_exit_reason: i64,
    /// The counters the D PROGRAM owns, every one of which must be zero.
    pub(crate) program_drops: BTreeMap<String, u64>,
    /// libdtrace's own principal / aggregation / dynamic / rinse / dirty
    /// counters plus its interrupted flag — the ones that are NOT readable from
    /// D and used to exist only in the live run report.
    ///
    /// They are here because they are the sole detector of the one corruption
    /// closure cannot see: a dynamic drop that loses a `service_slot` entry
    /// moves host work from a guest op into `carrick-only` WITHOUT changing any
    /// sum, so every closure pair still holds and the guest op's amplification
    /// simply FALLS. `carrick trace` writes them into the stream as an
    /// `AMP1|consumer-drops|…` record after libdtrace finishes, so an archived
    /// raw carries its own drop verdict and a raw left behind by a FAILED
    /// capture can no longer launder a lower amplification past an offline
    /// analyzer.
    pub(crate) consumer_drops: BTreeMap<String, u64>,
    pub(crate) consumer_drop_enforcement: String,
    pub(crate) terminal_calls: Vec<TerminalCall>,
}

const CONSUMER_DROP_ENFORCEMENT: &str = "in-band-consumer-drops-record";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerTotals {
    pub(crate) guest_syscalls: u64,
    pub(crate) host_syscalls: u64,
    pub(crate) host_syscall_returns: u64,
    pub(crate) host_syscall_cpu_ns: u64,
    pub(crate) mach_traps: u64,
    pub(crate) mach_trap_returns: u64,
    pub(crate) mach_trap_cpu_ns: u64,
    pub(crate) faults: FaultCounts,
    /// Expected service-window control flow: one per guest `clone(CLONE_THREAD)`
    /// and per fork, because the child closes a span the parent opened. Zero on
    /// a threaded build means the inherited close never reached the probe.
    pub(crate) inherited_service_ends: u64,
    /// Always true. Four probe families in one program perturb wall by an
    /// expected 2-4x, so counts and same-instrument ratios are citable and wall
    /// never is; `traced_elapsed_ns` is diagnostic metadata only.
    pub(crate) wall_is_not_authority: bool,
    pub(crate) traced_elapsed_ns: u64,
}

/// The single host call that cost this guest op the most kernel CPU.
///
/// Ranked by CPU-ns, then by count, then by name — CPU because that is the
/// currency the budget is denominated in, and the two tie-breaks because a
/// published artifact has to be byte-reproducible.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DominantHostCall {
    pub(crate) name: HostCall,
    pub(crate) count: u64,
    pub(crate) cpu_ns: u64,
    pub(crate) max_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestOpRow {
    pub(crate) guest_op: GuestOp,
    pub(crate) guest_count: u64,
    pub(crate) host_calls: u64,
    /// Host syscalls per guest op. The number every entry drives toward 1.
    pub(crate) host_call_amplification: LedgerFraction,
    pub(crate) host_cpu_ns: u64,
    /// Host kernel CPU-ns per guest op. The number the budget is ranked on.
    pub(crate) host_cpu_ns_per_guest_op: LedgerFraction,
    pub(crate) mach_traps: u64,
    pub(crate) mach_trap_cpu_ns: u64,
    pub(crate) faults: FaultCounts,
    pub(crate) dominant_host_call: Option<DominantHostCall>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCallRow {
    pub(crate) name: HostCall,
    pub(crate) count: u64,
    pub(crate) cpu_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachTrapRow {
    pub(crate) trap: MachTrap,
    pub(crate) count: u64,
    pub(crate) cpu_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BucketTotals {
    pub(crate) host_calls: u64,
    pub(crate) host_cpu_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstrumentBucket {
    pub(crate) host_calls: u64,
    pub(crate) host_cpu_ns: u64,
    pub(crate) by_host_call: Vec<HostCallRow>,
}

/// Host work that belongs to no guest operation.
///
/// **This struct deliberately has no amplification field, and that absence is
/// the enforcement mechanism.** The fs-census entry stated "carrick-only is
/// never a ratio" in prose; here there is no cell to put one in, so the rule
/// cannot be forgotten by a later editor, only removed on purpose.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarrickOnly {
    pub(crate) host_calls: u64,
    pub(crate) host_cpu_ns: u64,
    pub(crate) mach_traps: u64,
    pub(crate) mach_trap_cpu_ns: u64,
    pub(crate) faults: FaultCounts,
    pub(crate) probable_instrument: InstrumentBucket,
    /// `carrick-only` minus the instrument. This, not the gross bucket, is what
    /// the budget charges to carrick.
    pub(crate) excluding_probable_instrument: BucketTotals,
    pub(crate) by_host_call: Vec<HostCallRow>,
    pub(crate) by_mach_trap: Vec<MachTrapRow>,
}

/// One asserted equality between the per-op sums and the program's own
/// independent, ungrouped total. Both sides are published because the receipt
/// is the point; they are equal by construction, and a published ledger whose
/// two sides disagree is refused on parse.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClosureCheck {
    pub(crate) per_op_sum: u64,
    pub(crate) independent_total: u64,
}

/// A host call whose entries outnumber its returns.
///
/// NOT a refusal, and the reason is in the D program: the census ends on the
/// target's own `proc:::exit`, so every syscall in flight on a sibling thread
/// at that instant is an entry that never records a return. Terminal calls
/// (`exit`, `bsdthread_terminate`) do the same by design and are marked. What
/// IS asserted is the sum: the per-call return counts must equal the program's
/// independent return total.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnreturnedHostCall {
    pub(crate) name: HostCall,
    pub(crate) entries: u64,
    pub(crate) returns: u64,
    pub(crate) qualified_terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnreturnedMachTrap {
    pub(crate) trap: MachTrap,
    pub(crate) entries: u64,
    pub(crate) returns: u64,
    pub(crate) qualified_terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerClosure {
    pub(crate) guest_syscalls: ClosureCheck,
    pub(crate) host_syscalls: ClosureCheck,
    pub(crate) host_syscall_returns: ClosureCheck,
    pub(crate) host_syscall_cpu_ns: ClosureCheck,
    pub(crate) mach_traps: ClosureCheck,
    /// Unlike the other nine, the two `*_returns` checks are re-derived from
    /// the stream at BUILD time only: the ledger publishes no per-call return
    /// roster to re-sum, so on parse they are checked for self-consistency and
    /// against `totals`, not recomputed.
    pub(crate) mach_trap_returns: ClosureCheck,
    pub(crate) mach_trap_cpu_ns: ClosureCheck,
    pub(crate) as_faults: ClosureCheck,
    pub(crate) zfods: ClosureCheck,
    pub(crate) cow_faults: ClosureCheck,
    pub(crate) unreturned_host_calls: Vec<UnreturnedHostCall>,
    pub(crate) unreturned_mach_traps: Vec<UnreturnedMachTrap>,
}

/// The capture's own kernel-CPU decomposition, in exact nanoseconds.
///
/// No external denominator appears here on purpose — see this module's header.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerBudget {
    /// Host syscall + mach trap CPU inside some guest service window.
    pub(crate) guest_attributed_cpu_ns: u64,
    /// Host syscall + mach trap CPU outside every guest window, WITHOUT the
    /// instrument's own calls.
    pub(crate) carrick_only_cpu_ns: u64,
    pub(crate) probable_instrument_cpu_ns: u64,
    /// The sum of the three, and of the program's two independent CPU totals.
    pub(crate) measured_kernel_cpu_ns: u64,
    pub(crate) guest_attributed_share: LedgerFraction,
    pub(crate) carrick_only_share: LedgerFraction,
    pub(crate) probable_instrument_share: LedgerFraction,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AmplificationLedgerV1 {
    pub(crate) schema: String,
    pub(crate) provenance: LedgerProvenance,
    pub(crate) authority: LedgerAuthority,
    pub(crate) totals: LedgerTotals,
    pub(crate) ledger: Vec<GuestOpRow>,
    pub(crate) carrick_only: CarrickOnly,
    pub(crate) closure: LedgerClosure,
    pub(crate) budget: LedgerBudget,
}

fn checked_add(total: u64, value: u64, label: &str) -> Result<u64> {
    total
        .checked_add(value)
        .ok_or_else(|| anyhow!("amplification ledger {label} overflow"))
}

fn require_equal(observed: u64, expected: u64, label: &str) -> Result<()> {
    if observed != expected {
        bail!(
            "amplification ledger closure failed: {label} per-op sum {observed} does not equal the capture's independent total {expected}; a partial census must never be read as a complete one"
        );
    }
    Ok(())
}

fn closure(per_op_sum: u64, independent_total: u64, label: &str) -> Result<ClosureCheck> {
    require_equal(per_op_sum, independent_total, label)?;
    Ok(ClosureCheck {
        per_op_sum,
        independent_total,
    })
}

fn require_metric(capture: &Amp1Capture, metric: &str) -> Result<u64> {
    capture
        .totals
        .get(metric)
        .copied()
        .ok_or_else(|| anyhow!("AMP1 totals section is missing metric {metric:?}"))
}

fn require_fault_total(capture: &Amp1Capture, kind: &str) -> Result<u64> {
    capture
        .fault_totals
        .get(kind)
        .copied()
        .ok_or_else(|| anyhow!("AMP1 fault totals are missing kind {kind:?}"))
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("amplification ledger {label} is not a 64-character SHA-256 digest");
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("amplification ledger {label} is not lowercase");
    }
    Ok(())
}

/// Everything one guest slot's four joins carried.
#[derive(Default)]
struct SlotJoin {
    host_calls: BTreeMap<HostCall, u64>,
    host_call_cpu_ns: BTreeMap<HostCall, u64>,
    host_call_max_ns: BTreeMap<HostCall, u64>,
    mach_traps: BTreeMap<MachTrap, u64>,
    mach_trap_cpu_ns: BTreeMap<MachTrap, u64>,
    faults: FaultCounts,
}

impl SlotJoin {
    fn host_call_total(&self) -> Result<u64> {
        self.host_calls.values().try_fold(0_u64, |total, count| {
            checked_add(total, *count, "host calls")
        })
    }

    fn host_cpu_total(&self) -> Result<u64> {
        self.host_call_cpu_ns
            .values()
            .try_fold(0_u64, |total, ns| checked_add(total, *ns, "host call CPU"))
    }

    fn mach_trap_total(&self) -> Result<u64> {
        self.mach_traps.values().try_fold(0_u64, |total, count| {
            checked_add(total, *count, "mach traps")
        })
    }

    fn mach_cpu_total(&self) -> Result<u64> {
        self.mach_trap_cpu_ns
            .values()
            .try_fold(0_u64, |total, ns| checked_add(total, *ns, "mach trap CPU"))
    }

    /// The host call that cost the most kernel CPU, with deterministic
    /// tie-breaks. `None` only when this guest op made no host syscall at all.
    fn dominant_host_call(&self) -> Result<Option<DominantHostCall>> {
        let mut best: Option<DominantHostCall> = None;
        for (name, count) in &self.host_calls {
            let cpu_ns = self.host_call_cpu_ns.get(name).copied().unwrap_or_default();
            let max_ns = self.host_call_max_ns.get(name).copied().unwrap_or_default();
            let candidate = DominantHostCall {
                name: name.clone(),
                count: *count,
                cpu_ns,
                max_ns,
            };
            let wins = match &best {
                None => true,
                Some(current) => {
                    (candidate.cpu_ns, candidate.count) > (current.cpu_ns, current.count)
                        || ((candidate.cpu_ns, candidate.count) == (current.cpu_ns, current.count)
                            && candidate.name < current.name)
                }
            };
            if wins {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    /// A per-key sanity pass that closure sums alone cannot catch: CPU is
    /// accumulated at RETURN under the slot captured at ENTRY, so a CPU or
    /// max-ns key with no matching entry key, or a max that exceeds the whole
    /// sum for the same key, means the two clauses disagreed.
    ///
    /// The `max_ns` roster gets an EXACT key-set equality rather than a subset
    /// check, because `@host_cpu_by_slot` and `@host_cpu_max_by_slot` are
    /// written unconditionally in the same clause on the same key: their key
    /// sets are identical by construction. That equality is the only closure
    /// `max_ns` has — unlike every other quantity it has no independent
    /// ungrouped total in the stream — so a truncated max roster (a lost row in
    /// the END flush) would otherwise zero `dominant_host_call.max_ns` in
    /// silence.
    fn validate_keys(&self, label: &str) -> Result<()> {
        for name in self.host_call_cpu_ns.keys() {
            if !self.host_calls.contains_key(name) {
                bail!(
                    "AMP1 records host CPU for {}'s {:?} with no matching syscall entry",
                    label,
                    name.as_str()
                );
            }
            if !self.host_call_max_ns.contains_key(name) {
                bail!(
                    "AMP1 records a host CPU sum for {}'s {:?} with no matching maximum; the two aggregations are written in one clause and their key sets cannot differ",
                    label,
                    name.as_str()
                );
            }
        }
        for (name, max_ns) in &self.host_call_max_ns {
            let Some(sum) = self.host_call_cpu_ns.get(name) else {
                bail!(
                    "AMP1 records a host CPU maximum for {}'s {:?} with no matching CPU sum",
                    label,
                    name.as_str()
                );
            };
            if max_ns > sum {
                bail!(
                    "AMP1 host CPU maximum for {}'s {:?} exceeds its own sum",
                    label,
                    name.as_str()
                );
            }
        }
        for trap in self.mach_trap_cpu_ns.keys() {
            if !self.mach_traps.contains_key(trap) {
                bail!(
                    "AMP1 records mach trap CPU for {}'s {:?} with no matching trap entry",
                    label,
                    trap.as_str()
                );
            }
        }
        Ok(())
    }
}

fn slot_label(slot: GuestSlot) -> String {
    match slot {
        GuestSlot::CarrickOnly => "carrick-only".to_owned(),
        GuestSlot::Guest(nr) => match lookup_aarch64(nr.raw()) {
            Some(entry) => format!("guest op {}", entry.name),
            None => format!("guest op {}", nr.raw()),
        },
    }
}

fn partition_joins(capture: &Amp1Capture) -> Result<BTreeMap<GuestSlot, SlotJoin>> {
    let mut joins: BTreeMap<GuestSlot, SlotJoin> = BTreeMap::new();
    for ((slot, name), count) in &capture.host_syscalls {
        joins
            .entry(*slot)
            .or_default()
            .host_calls
            .insert(HostCall::parse(name)?, *count);
    }
    for ((slot, name), cpu_ns) in &capture.host_syscall_cpu_ns {
        joins
            .entry(*slot)
            .or_default()
            .host_call_cpu_ns
            .insert(HostCall::parse(name)?, *cpu_ns);
    }
    for ((slot, name), max_ns) in &capture.host_syscall_max_ns {
        joins
            .entry(*slot)
            .or_default()
            .host_call_max_ns
            .insert(HostCall::parse(name)?, *max_ns);
    }
    for ((slot, trap), count) in &capture.mach_traps {
        joins
            .entry(*slot)
            .or_default()
            .mach_traps
            .insert(MachTrap::parse(trap)?, *count);
    }
    for ((slot, trap), cpu_ns) in &capture.mach_trap_cpu_ns {
        joins
            .entry(*slot)
            .or_default()
            .mach_trap_cpu_ns
            .insert(MachTrap::parse(trap)?, *cpu_ns);
    }
    for ((slot, kind), count) in &capture.faults {
        joins.entry(*slot).or_default().faults.add(kind, *count)?;
    }
    for (slot, join) in &joins {
        join.validate_keys(&slot_label(*slot))?;
    }
    Ok(joins)
}

pub(crate) fn build_ledger(
    capture: &Amp1Capture,
    provenance: LedgerProvenance,
) -> Result<AmplificationLedgerV1> {
    let joins = partition_joins(capture)?;

    // The `carrick-only` slot is set by the syscall/mach/fault clauses when no
    // window is open; the entry probe never assigns it, so a guest denominator
    // for it would be a corrupted stream rather than an odd row.
    if capture.guest_syscalls.contains_key(&GuestSlot::CarrickOnly) {
        bail!(
            "AMP1 guest-syscalls section counts the carrick-only slot; only `native-syscall-service-entry` writes a guest slot and it never writes 1"
        );
    }
    // Conversely, a join can only name a guest slot that an entry probe wrote,
    // so a join naming an op with no service-window entry means the slot table
    // and the denominator disagree -- and the denominator is what every ratio
    // below divides by.
    for slot in joins.keys() {
        if matches!(slot, GuestSlot::Guest(_)) && !capture.guest_syscalls.contains_key(slot) {
            bail!(
                "AMP1 attributes host work to {} with no service-window entry; the amplification denominator is missing",
                slot_label(*slot)
            );
        }
    }

    let empty = SlotJoin::default();
    let mut rows = Vec::with_capacity(capture.guest_syscalls.len());
    let mut guest_sum = 0_u64;
    let mut guest_host_calls = 0_u64;
    let mut guest_host_cpu_ns = 0_u64;
    let mut guest_mach_traps = 0_u64;
    let mut guest_mach_cpu_ns = 0_u64;
    let mut guest_faults = FaultCounts::default();
    for (slot, guest_count) in &capture.guest_syscalls {
        let GuestSlot::Guest(canonical_nr) = slot else {
            continue;
        };
        let guest_op = GuestOp::resolve(*canonical_nr)?;
        if *guest_count == 0 {
            bail!(
                "AMP1 counts zero service-window entries for guest op {}; the row's amplification denominator would be zero",
                guest_op.name()
            );
        }
        let join = joins.get(slot).unwrap_or(&empty);
        // The instrument's own calls must never sit inside a guest window: a
        // per-op ratio containing them is contaminated with the cost of asking
        // the question, and there is no honest way to subtract it after the
        // fact.
        for name in join.host_calls.keys() {
            if name.is_probable_instrument() {
                bail!(
                    "AMP1 attributes the instrument's own {:?} to guest op {}; per-op ratios cannot be corrected for the tracer's cost after the join",
                    name.as_str(),
                    guest_op.name()
                );
            }
        }

        let host_calls = join.host_call_total()?;
        let host_cpu_ns = join.host_cpu_total()?;
        let mach_traps = join.mach_trap_total()?;
        let mach_trap_cpu_ns = join.mach_cpu_total()?;

        guest_sum = checked_add(guest_sum, *guest_count, "guest syscall total")?;
        guest_host_calls = checked_add(guest_host_calls, host_calls, "guest host calls")?;
        guest_host_cpu_ns = checked_add(guest_host_cpu_ns, host_cpu_ns, "guest host CPU")?;
        guest_mach_traps = checked_add(guest_mach_traps, mach_traps, "guest mach traps")?;
        guest_mach_cpu_ns = checked_add(guest_mach_cpu_ns, mach_trap_cpu_ns, "guest mach CPU")?;
        guest_faults.accumulate(&join.faults)?;

        rows.push(GuestOpRow {
            guest_op,
            guest_count: *guest_count,
            host_calls,
            host_call_amplification: LedgerFraction::new(host_calls, *guest_count),
            host_cpu_ns,
            host_cpu_ns_per_guest_op: LedgerFraction::new(host_cpu_ns, *guest_count),
            mach_traps,
            mach_trap_cpu_ns,
            faults: join.faults.clone(),
            dominant_host_call: join.dominant_host_call()?,
        });
    }

    let carrick_join = joins.get(&GuestSlot::CarrickOnly).unwrap_or(&empty);
    let carrick_only = build_carrick_only(carrick_join)?;

    let totals = LedgerTotals {
        guest_syscalls: require_metric(capture, METRIC_GUEST_SYSCALLS)?,
        host_syscalls: require_metric(capture, METRIC_HOST_SYSCALL_ENTRIES)?,
        host_syscall_returns: require_metric(capture, METRIC_HOST_SYSCALL_RETURNS)?,
        host_syscall_cpu_ns: require_metric(capture, METRIC_HOST_SYSCALL_CPU_NS)?,
        mach_traps: require_metric(capture, METRIC_MACH_TRAP_ENTRIES)?,
        mach_trap_returns: require_metric(capture, METRIC_MACH_TRAP_RETURNS)?,
        mach_trap_cpu_ns: require_metric(capture, METRIC_MACH_TRAP_CPU_NS)?,
        faults: FaultCounts {
            as_fault: require_fault_total(capture, FAULT_AS_FAULT)?,
            zfod: require_fault_total(capture, FAULT_ZFOD)?,
            cow_fault: require_fault_total(capture, FAULT_COW_FAULT)?,
        },
        inherited_service_ends: capture
            .window_events
            .get(WINDOW_INHERITED_END)
            .copied()
            .ok_or_else(|| {
                anyhow!("AMP1 window-events section is missing {WINDOW_INHERITED_END:?}")
            })?,
        wall_is_not_authority: true,
        traced_elapsed_ns: capture.elapsed_ns,
    };

    let closure = build_closure(
        capture,
        &totals,
        &GuestSums {
            guest_syscalls: guest_sum,
            host_calls: checked_add(guest_host_calls, carrick_only.host_calls, "host syscalls")?,
            host_cpu_ns: checked_add(
                guest_host_cpu_ns,
                carrick_only.host_cpu_ns,
                "host syscall CPU",
            )?,
            mach_traps: checked_add(guest_mach_traps, carrick_only.mach_traps, "mach traps")?,
            mach_trap_cpu_ns: checked_add(
                guest_mach_cpu_ns,
                carrick_only.mach_trap_cpu_ns,
                "mach trap CPU",
            )?,
            faults: {
                let mut faults = guest_faults;
                faults.accumulate(&carrick_only.faults)?;
                faults
            },
        },
    )?;

    let budget = build_budget(
        checked_add(guest_host_cpu_ns, guest_mach_cpu_ns, "guest attributed CPU")?,
        &carrick_only,
        &totals,
    )?;

    let ledger = AmplificationLedgerV1 {
        schema: LEDGER_SCHEMA.to_owned(),
        provenance,
        authority: LedgerAuthority {
            program_sha256: capture.program_sha256.clone(),
            raw_schema: AMPLIFICATION_RAW_SCHEMA.to_owned(),
            joins: capture.joins.clone(),
            declared_buffers: capture.declared_buffers.clone(),
            os_build: capture.os_build.clone(),
            image: capture.image.clone(),
            target_argv_sha256: capture.target_argv_sha256.clone(),
            preflight: capture.preflight.clone(),
            consumer_drops: capture.consumer_drops.clone(),
            birth_qualification_sha256: capture.birth_qualification_sha256.clone(),
            terminal_qualification_sha256: capture.terminal_qualification_sha256.clone(),
            bound_limit_s: capture.bound_limit_s,
            truncated: false,
            target_exit_reason: capture.target_exit_reason,
            program_drops: capture.drops.clone(),
            consumer_drop_enforcement: CONSUMER_DROP_ENFORCEMENT.to_owned(),
            terminal_calls: capture
                .terminal_calls
                .iter()
                .map(|(provider, function, scope)| TerminalCall {
                    provider: provider.clone(),
                    function: function.clone(),
                    scope: scope.clone(),
                })
                .collect(),
        },
        totals,
        ledger: rows,
        carrick_only,
        closure,
        budget,
    };
    ledger.validate()?;
    ledger.require_bundled_program()?;
    Ok(ledger)
}

struct GuestSums {
    guest_syscalls: u64,
    host_calls: u64,
    host_cpu_ns: u64,
    mach_traps: u64,
    mach_trap_cpu_ns: u64,
    faults: FaultCounts,
}

fn build_carrick_only(join: &SlotJoin) -> Result<CarrickOnly> {
    let mut by_host_call = Vec::with_capacity(join.host_calls.len());
    let mut instrument_rows = Vec::new();
    let mut instrument_calls = 0_u64;
    let mut instrument_cpu_ns = 0_u64;
    for (name, count) in &join.host_calls {
        let cpu_ns = join.host_call_cpu_ns.get(name).copied().unwrap_or_default();
        let row = HostCallRow {
            name: name.clone(),
            count: *count,
            cpu_ns,
        };
        if name.is_probable_instrument() {
            instrument_calls = checked_add(instrument_calls, *count, "instrument host calls")?;
            instrument_cpu_ns = checked_add(instrument_cpu_ns, cpu_ns, "instrument host CPU")?;
            instrument_rows.push(row.clone());
        }
        by_host_call.push(row);
    }
    let by_mach_trap = join
        .mach_traps
        .iter()
        .map(|(trap, count)| MachTrapRow {
            trap: trap.clone(),
            count: *count,
            cpu_ns: join.mach_trap_cpu_ns.get(trap).copied().unwrap_or_default(),
        })
        .collect();

    let host_calls = join.host_call_total()?;
    let host_cpu_ns = join.host_cpu_total()?;
    Ok(CarrickOnly {
        host_calls,
        host_cpu_ns,
        mach_traps: join.mach_trap_total()?,
        mach_trap_cpu_ns: join.mach_cpu_total()?,
        faults: join.faults.clone(),
        excluding_probable_instrument: BucketTotals {
            host_calls: host_calls
                .checked_sub(instrument_calls)
                .context("instrument host calls exceed the carrick-only bucket")?,
            host_cpu_ns: host_cpu_ns
                .checked_sub(instrument_cpu_ns)
                .context("instrument host CPU exceeds the carrick-only bucket")?,
        },
        probable_instrument: InstrumentBucket {
            host_calls: instrument_calls,
            host_cpu_ns: instrument_cpu_ns,
            by_host_call: instrument_rows,
        },
        by_host_call,
        by_mach_trap,
    })
}

fn build_closure(
    capture: &Amp1Capture,
    totals: &LedgerTotals,
    sums: &GuestSums,
) -> Result<LedgerClosure> {
    let mut host_entries: BTreeMap<HostCall, u64> = BTreeMap::new();
    for ((_, name), count) in &capture.host_syscalls {
        let entry = host_entries.entry(HostCall::parse(name)?).or_default();
        *entry = checked_add(*entry, *count, "host call entries")?;
    }
    let mut mach_entries: BTreeMap<MachTrap, u64> = BTreeMap::new();
    for ((_, trap), count) in &capture.mach_traps {
        let entry = mach_entries.entry(MachTrap::parse(trap)?).or_default();
        *entry = checked_add(*entry, *count, "mach trap entries")?;
    }

    let terminal_syscalls: BTreeSet<&str> = capture
        .terminal_calls
        .iter()
        .filter(|(provider, _, _)| provider == "syscall")
        .map(|(_, function, _)| function.as_str())
        .collect();
    let terminal_traps: BTreeSet<&str> = capture
        .terminal_calls
        .iter()
        .filter(|(provider, _, _)| provider == "mach_trap")
        .map(|(_, function, _)| function.as_str())
        .collect();

    let mut host_returns = 0_u64;
    let mut unreturned_host_calls = Vec::new();
    for (name, returns) in &capture.host_syscall_returns {
        let name = HostCall::parse(name)?;
        let entries = host_entries.get(&name).copied().unwrap_or_default();
        if *returns > entries {
            bail!(
                "AMP1 records {returns} returns for host call {:?} against {entries} entries; a return without an entry cannot be attributed to any slot",
                name.as_str()
            );
        }
        host_returns = checked_add(host_returns, *returns, "host call returns")?;
    }
    for (name, entries) in &host_entries {
        let returns = capture
            .host_syscall_returns
            .get(name.as_str())
            .copied()
            .unwrap_or_default();
        if returns < *entries {
            unreturned_host_calls.push(UnreturnedHostCall {
                name: name.clone(),
                entries: *entries,
                returns,
                qualified_terminal: terminal_syscalls.contains(name.as_str()),
            });
        }
    }

    let mut mach_returns = 0_u64;
    let mut unreturned_mach_traps = Vec::new();
    for (trap, returns) in &capture.mach_trap_returns {
        let trap = MachTrap::parse(trap)?;
        let entries = mach_entries.get(&trap).copied().unwrap_or_default();
        if *returns > entries {
            bail!(
                "AMP1 records {returns} returns for mach trap {:?} against {entries} entries; a return without an entry cannot be attributed to any slot",
                trap.as_str()
            );
        }
        mach_returns = checked_add(mach_returns, *returns, "mach trap returns")?;
    }
    for (trap, entries) in &mach_entries {
        let returns = capture
            .mach_trap_returns
            .get(trap.as_str())
            .copied()
            .unwrap_or_default();
        if returns < *entries {
            unreturned_mach_traps.push(UnreturnedMachTrap {
                trap: trap.clone(),
                entries: *entries,
                returns,
                qualified_terminal: terminal_traps.contains(trap.as_str()),
            });
        }
    }

    Ok(LedgerClosure {
        guest_syscalls: closure(sums.guest_syscalls, totals.guest_syscalls, "guest syscalls")?,
        host_syscalls: closure(sums.host_calls, totals.host_syscalls, "host syscalls")?,
        host_syscall_returns: closure(
            host_returns,
            totals.host_syscall_returns,
            "host syscall returns",
        )?,
        host_syscall_cpu_ns: closure(
            sums.host_cpu_ns,
            totals.host_syscall_cpu_ns,
            "host syscall CPU-ns",
        )?,
        mach_traps: closure(sums.mach_traps, totals.mach_traps, "mach traps")?,
        mach_trap_returns: closure(mach_returns, totals.mach_trap_returns, "mach trap returns")?,
        mach_trap_cpu_ns: closure(
            sums.mach_trap_cpu_ns,
            totals.mach_trap_cpu_ns,
            "mach trap CPU-ns",
        )?,
        as_faults: closure(sums.faults.as_fault, totals.faults.as_fault, "as_fault")?,
        zfods: closure(sums.faults.zfod, totals.faults.zfod, "zfod")?,
        cow_faults: closure(sums.faults.cow_fault, totals.faults.cow_fault, "cow_fault")?,
        unreturned_host_calls,
        unreturned_mach_traps,
    })
}

fn build_budget(
    guest_attributed_cpu_ns: u64,
    carrick_only: &CarrickOnly,
    totals: &LedgerTotals,
) -> Result<LedgerBudget> {
    let measured_kernel_cpu_ns = checked_add(
        totals.host_syscall_cpu_ns,
        totals.mach_trap_cpu_ns,
        "measured kernel CPU",
    )?;
    let probable_instrument_cpu_ns = carrick_only.probable_instrument.host_cpu_ns;
    let carrick_only_gross = checked_add(
        carrick_only.host_cpu_ns,
        carrick_only.mach_trap_cpu_ns,
        "carrick-only CPU",
    )?;
    let carrick_only_cpu_ns = carrick_only_gross
        .checked_sub(probable_instrument_cpu_ns)
        .context("instrument CPU exceeds the carrick-only bucket")?;
    require_equal(
        checked_add(
            guest_attributed_cpu_ns,
            carrick_only_gross,
            "kernel CPU decomposition",
        )?,
        measured_kernel_cpu_ns,
        "kernel CPU decomposition",
    )?;
    Ok(LedgerBudget {
        guest_attributed_cpu_ns,
        carrick_only_cpu_ns,
        probable_instrument_cpu_ns,
        measured_kernel_cpu_ns,
        guest_attributed_share: LedgerFraction::new(
            guest_attributed_cpu_ns,
            measured_kernel_cpu_ns,
        ),
        carrick_only_share: LedgerFraction::new(carrick_only_cpu_ns, measured_kernel_cpu_ns),
        probable_instrument_share: LedgerFraction::new(
            probable_instrument_cpu_ns,
            measured_kernel_cpu_ns,
        ),
    })
}

impl AmplificationLedgerV1 {
    /// The program digest must name the CURRENTLY BUNDLED `AMP1` program.
    ///
    /// Deliberately NOT part of [`AmplificationLedgerV1::validate`], and the
    /// distinction is what keeps published ledgers readable. `validate` runs on
    /// every parse; the bundled digest changes on every edit of
    /// `native-amplification.d`. Folding this into `validate` would make every
    /// previously published ledger unparseable the moment the D program is
    /// touched — including by the Task-3 in-band drop record this plan now
    /// requires — silently destroying the archive this instrument exists to
    /// build.
    ///
    /// So: BUILDING a ledger from a fresh capture requires the bundled digest
    /// (this is where "a `--script` capture cannot produce a ledger" is
    /// enforced, backing up the reader's own header check), READING one back
    /// requires only that the recorded digest is well formed, and refusing to
    /// COMPARE two ledgers whose digests differ is `amplification-compare`'s
    /// job. A ledger always names the program that produced it, so a version
    /// crossing stays detectable without being retroactive.
    fn require_bundled_program(&self) -> Result<()> {
        let expected = amp1_program_sha256();
        if self.authority.program_sha256 != expected {
            bail!(
                "amplification ledger names program digest {} rather than the bundled native-amplification program ({expected}); a --script capture cannot produce a ledger",
                self.authority.program_sha256
            );
        }
        Ok(())
    }

    /// Everything a published ledger must still be true about ITSELF.
    ///
    /// Run on build and again on every parse, so a hand-edited artifact is
    /// refused rather than compared: the closure equalities, the well-formed
    /// authority, and the instrument's separation from every per-op ratio.
    /// The one check that is deliberately NOT here is the bundled program
    /// digest — see [`AmplificationLedgerV1::require_bundled_program`].
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != LEDGER_SCHEMA {
            bail!("amplification ledger schema is not {LEDGER_SCHEMA}");
        }
        self.validate_authority()?;
        if !self.totals.wall_is_not_authority {
            bail!(
                "amplification ledger claims its traced wall is authoritative; four probe families perturb this workload 2-4x"
            );
        }

        let mut guest_sum = 0_u64;
        let mut host_calls = self.carrick_only.host_calls;
        let mut host_cpu_ns = self.carrick_only.host_cpu_ns;
        let mut mach_traps = self.carrick_only.mach_traps;
        let mut mach_trap_cpu_ns = self.carrick_only.mach_trap_cpu_ns;
        let mut faults = self.carrick_only.faults.clone();
        let mut previous: Option<CanonicalNr> = None;
        for row in &self.ledger {
            row.guest_op.validate()?;
            if previous.is_some_and(|previous| previous >= row.guest_op.canonical_nr()) {
                bail!("amplification ledger rows are duplicate or not ordered by canonical number");
            }
            previous = Some(row.guest_op.canonical_nr());
            if row.guest_count == 0 {
                bail!(
                    "amplification ledger row {} has a zero guest denominator",
                    row.guest_op.name()
                );
            }
            row.host_call_amplification.require(
                row.host_calls,
                row.guest_count,
                "host call amplification",
            )?;
            row.host_cpu_ns_per_guest_op.require(
                row.host_cpu_ns,
                row.guest_count,
                "host CPU per guest op",
            )?;
            if let Some(dominant) = &row.dominant_host_call {
                validate_probe_function(dominant.name.as_str(), "dominant host call")?;
                if dominant.name.is_probable_instrument() {
                    bail!(
                        "amplification ledger charges the instrument's own {:?} to guest op {}",
                        dominant.name.as_str(),
                        row.guest_op.name()
                    );
                }
                if dominant.count > row.host_calls
                    || dominant.cpu_ns > row.host_cpu_ns
                    || dominant.max_ns > dominant.cpu_ns
                {
                    bail!(
                        "amplification ledger dominant host call for {} exceeds its own row",
                        row.guest_op.name()
                    );
                }
            } else if row.host_calls != 0 {
                bail!(
                    "amplification ledger row {} names no dominant host call despite {} host calls",
                    row.guest_op.name(),
                    row.host_calls
                );
            }
            guest_sum = checked_add(guest_sum, row.guest_count, "guest syscall total")?;
            host_calls = checked_add(host_calls, row.host_calls, "host syscalls")?;
            host_cpu_ns = checked_add(host_cpu_ns, row.host_cpu_ns, "host syscall CPU")?;
            mach_traps = checked_add(mach_traps, row.mach_traps, "mach traps")?;
            mach_trap_cpu_ns =
                checked_add(mach_trap_cpu_ns, row.mach_trap_cpu_ns, "mach trap CPU")?;
            faults.accumulate(&row.faults)?;
        }

        self.validate_carrick_only()?;

        for (check, sum, total, label) in [
            (
                &self.closure.guest_syscalls,
                guest_sum,
                self.totals.guest_syscalls,
                "guest syscalls",
            ),
            (
                &self.closure.host_syscalls,
                host_calls,
                self.totals.host_syscalls,
                "host syscalls",
            ),
            (
                &self.closure.host_syscall_cpu_ns,
                host_cpu_ns,
                self.totals.host_syscall_cpu_ns,
                "host syscall CPU-ns",
            ),
            (
                &self.closure.mach_traps,
                mach_traps,
                self.totals.mach_traps,
                "mach traps",
            ),
            (
                &self.closure.mach_trap_cpu_ns,
                mach_trap_cpu_ns,
                self.totals.mach_trap_cpu_ns,
                "mach trap CPU-ns",
            ),
            (
                &self.closure.as_faults,
                faults.as_fault,
                self.totals.faults.as_fault,
                "as_fault",
            ),
            (
                &self.closure.zfods,
                faults.zfod,
                self.totals.faults.zfod,
                "zfod",
            ),
            (
                &self.closure.cow_faults,
                faults.cow_fault,
                self.totals.faults.cow_fault,
                "cow_fault",
            ),
        ] {
            require_equal(check.per_op_sum, sum, label)?;
            require_equal(check.independent_total, total, label)?;
            require_equal(check.per_op_sum, check.independent_total, label)?;
        }
        for (check, total, label) in [
            (
                &self.closure.host_syscall_returns,
                self.totals.host_syscall_returns,
                "host syscall returns",
            ),
            (
                &self.closure.mach_trap_returns,
                self.totals.mach_trap_returns,
                "mach trap returns",
            ),
        ] {
            require_equal(check.per_op_sum, check.independent_total, label)?;
            require_equal(check.independent_total, total, label)?;
        }
        if guest_sum == 0 {
            bail!(
                "amplification ledger has a zero guest denominator; `native-syscall-service-*` never fires under the VMM backend"
            );
        }

        self.validate_budget()
    }

    fn validate_authority(&self) -> Result<()> {
        let authority = &self.authority;
        if authority.raw_schema != AMPLIFICATION_RAW_SCHEMA {
            bail!("amplification ledger raw schema is not {AMPLIFICATION_RAW_SCHEMA}");
        }
        for (value, label) in [
            (&authority.program_sha256, "program digest"),
            (
                &authority.birth_qualification_sha256,
                "birth qualification digest",
            ),
            (
                &authority.terminal_qualification_sha256,
                "terminal qualification digest",
            ),
        ] {
            validate_sha256(value, label)?;
        }
        if authority.truncated {
            bail!("amplification ledger is marked truncated; a partial census is not a ledger");
        }
        if authority.consumer_drop_enforcement != CONSUMER_DROP_ENFORCEMENT {
            bail!(
                "amplification ledger names consumer drop enforcement {:?}, not {CONSUMER_DROP_ENFORCEMENT:?}",
                authority.consumer_drop_enforcement
            );
        }
        if authority.program_drops.is_empty() {
            bail!(
                "amplification ledger carries no program drop counters; a missing drop section is a refusal, because absent is not zero"
            );
        }
        for (source, count) in &authority.program_drops {
            if *count != 0 {
                bail!(
                    "amplification ledger carries {count} {source} drops; a dropped event reads as LOWER amplification and must never be banked"
                );
            }
        }
        // The in-band consumer counters, carried through from the capture and
        // re-checked here so a hand-edited artifact is refused rather than
        // read: this is the only detector of a drop whose symptom is an
        // amplification that improved.
        for counter in CONSUMER_DROP_COUNTERS {
            match authority.consumer_drops.get(counter).copied() {
                None => bail!(
                    "amplification ledger is missing libdtrace's {counter:?} counter; absent is not zero"
                ),
                Some(0) => {}
                Some(count) => bail!(
                    "amplification ledger carries {count} libdtrace {counter} drops; a consumer-side drop moves host work out of the guest op that caused it and reads as LOWER amplification"
                ),
            }
        }
        if authority.consumer_drops.len() != CONSUMER_DROP_COUNTERS.len() {
            bail!(
                "amplification ledger names libdtrace counters outside {CONSUMER_DROP_COUNTERS:?}"
            );
        }
        if !authority.image.contains("@sha256:") {
            bail!(
                "amplification ledger names image {:?}, which is not digest-pinned",
                authority.image
            );
        }
        validate_sha256(&authority.target_argv_sha256, "target argv digest")?;
        if authority.declared_buffers.is_empty() {
            bail!(
                "amplification ledger records no declared buffer headroom; a capture taken at different `aggsize`/`dynvarsize`/`bufsize` is a different instrument"
            );
        }
        if let Some(preflight) = &authority.preflight {
            preflight
                .validate()
                .context("validate the ledger's quiet-host preflight receipt")?;
        }
        for scope in ["thread", "process"] {
            if !authority
                .terminal_calls
                .iter()
                .any(|call| call.scope == scope)
            {
                bail!("amplification ledger terminal roster qualifies no {scope}-terminating call");
            }
        }
        Ok(())
    }

    fn validate_carrick_only(&self) -> Result<()> {
        let bucket = &self.carrick_only;
        let mut host_calls = 0_u64;
        let mut host_cpu_ns = 0_u64;
        let mut previous: Option<&HostCall> = None;
        for row in &bucket.by_host_call {
            validate_probe_function(row.name.as_str(), "carrick-only host call")?;
            if previous.is_some_and(|previous| previous >= &row.name) {
                bail!("amplification ledger carrick-only host calls are duplicate or unordered");
            }
            previous = Some(&row.name);
            host_calls = checked_add(host_calls, row.count, "carrick-only host calls")?;
            host_cpu_ns = checked_add(host_cpu_ns, row.cpu_ns, "carrick-only host CPU")?;
        }
        require_equal(host_calls, bucket.host_calls, "carrick-only host calls")?;
        require_equal(host_cpu_ns, bucket.host_cpu_ns, "carrick-only host CPU-ns")?;

        let mut mach_traps = 0_u64;
        let mut mach_cpu_ns = 0_u64;
        let mut previous_trap: Option<&MachTrap> = None;
        for row in &bucket.by_mach_trap {
            validate_probe_function(row.trap.as_str(), "carrick-only mach trap")?;
            if previous_trap.is_some_and(|previous| previous >= &row.trap) {
                bail!("amplification ledger carrick-only mach traps are duplicate or unordered");
            }
            previous_trap = Some(&row.trap);
            mach_traps = checked_add(mach_traps, row.count, "carrick-only mach traps")?;
            mach_cpu_ns = checked_add(mach_cpu_ns, row.cpu_ns, "carrick-only mach trap CPU")?;
        }
        require_equal(mach_traps, bucket.mach_traps, "carrick-only mach traps")?;
        require_equal(
            mach_cpu_ns,
            bucket.mach_trap_cpu_ns,
            "carrick-only mach trap CPU-ns",
        )?;

        let mut instrument_calls = 0_u64;
        let mut instrument_cpu_ns = 0_u64;
        for row in &bucket.probable_instrument.by_host_call {
            if !row.name.is_probable_instrument() {
                bail!(
                    "amplification ledger files {:?} under the instrument sub-bucket; only {PROBABLE_INSTRUMENT_CALLS:?} belong there",
                    row.name.as_str()
                );
            }
            if !bucket.by_host_call.contains(row) {
                bail!(
                    "amplification ledger instrument row {:?} is not part of the carrick-only decomposition it is subtracted from",
                    row.name.as_str()
                );
            }
            instrument_calls = checked_add(instrument_calls, row.count, "instrument host calls")?;
            instrument_cpu_ns = checked_add(instrument_cpu_ns, row.cpu_ns, "instrument host CPU")?;
        }
        for row in &bucket.by_host_call {
            if row.name.is_probable_instrument()
                && !bucket.probable_instrument.by_host_call.contains(row)
            {
                bail!(
                    "amplification ledger leaves the instrument's own {:?} inside the carrick-only bucket it charges to carrick",
                    row.name.as_str()
                );
            }
        }
        require_equal(
            instrument_calls,
            bucket.probable_instrument.host_calls,
            "instrument host calls",
        )?;
        require_equal(
            instrument_cpu_ns,
            bucket.probable_instrument.host_cpu_ns,
            "instrument host CPU-ns",
        )?;
        require_equal(
            checked_add(
                bucket.excluding_probable_instrument.host_calls,
                instrument_calls,
                "carrick-only host calls",
            )?,
            bucket.host_calls,
            "carrick-only host calls excluding the instrument",
        )?;
        require_equal(
            checked_add(
                bucket.excluding_probable_instrument.host_cpu_ns,
                instrument_cpu_ns,
                "carrick-only host CPU",
            )?,
            bucket.host_cpu_ns,
            "carrick-only host CPU-ns excluding the instrument",
        )
    }

    fn validate_budget(&self) -> Result<()> {
        let budget = &self.budget;
        let measured = checked_add(
            self.totals.host_syscall_cpu_ns,
            self.totals.mach_trap_cpu_ns,
            "measured kernel CPU",
        )?;
        require_equal(
            budget.measured_kernel_cpu_ns,
            measured,
            "measured kernel CPU-ns",
        )?;
        require_equal(
            budget.probable_instrument_cpu_ns,
            self.carrick_only.probable_instrument.host_cpu_ns,
            "instrument CPU-ns",
        )?;
        let carrick_gross = checked_add(
            self.carrick_only.host_cpu_ns,
            self.carrick_only.mach_trap_cpu_ns,
            "carrick-only CPU",
        )?;
        require_equal(
            checked_add(
                budget.carrick_only_cpu_ns,
                budget.probable_instrument_cpu_ns,
                "carrick-only CPU",
            )?,
            carrick_gross,
            "carrick-only CPU-ns",
        )?;
        require_equal(
            checked_add(
                budget.guest_attributed_cpu_ns,
                carrick_gross,
                "kernel CPU decomposition",
            )?,
            measured,
            "kernel CPU decomposition",
        )?;
        budget.guest_attributed_share.require(
            budget.guest_attributed_cpu_ns,
            measured,
            "guest attributed share",
        )?;
        budget.carrick_only_share.require(
            budget.carrick_only_cpu_ns,
            measured,
            "carrick-only share",
        )?;
        budget.probable_instrument_share.require(
            budget.probable_instrument_cpu_ns,
            measured,
            "instrument share",
        )
    }
}

fn serialize_ledger(ledger: &AmplificationLedgerV1) -> Result<Vec<u8>> {
    ledger.validate()?;
    let mut bytes = serde_json::to_vec(ledger).context("serialize amplification ledger v1")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn parse_ledger_v1(bytes: &[u8]) -> Result<AmplificationLedgerV1> {
    if bytes.last() != Some(&b'\n') || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        bail!("an amplification ledger is exactly one newline-terminated JSON object");
    }
    let ledger: AmplificationLedgerV1 = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .context("parse amplification ledger v1")?;
    ledger.validate()?;
    if serialize_ledger(&ledger)? != bytes {
        bail!("amplification ledger is not canonical v1 output");
    }
    Ok(ledger)
}

fn publish_ledger(
    ledger: &AmplificationLedgerV1,
    output_path: Option<&Path>,
    stdout: &mut impl Write,
) -> Result<()> {
    let bytes = serialize_ledger(ledger)?;
    parse_ledger_v1(&bytes).context("self-validate the published amplification ledger")?;
    publish_noclobber(&bytes, output_path, stdout, "amplification ledger")
}

fn publish_noclobber(
    bytes: &[u8],
    output_path: Option<&Path>,
    stdout: &mut impl Write,
    artifact: &str,
) -> Result<()> {
    let Some(path) = output_path else {
        stdout
            .write_all(bytes)
            .with_context(|| format!("write {artifact} to stdout"))?;
        stdout
            .flush()
            .with_context(|| format!("flush {artifact} stdout"))?;
        return Ok(());
    };

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create {artifact} output directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary {artifact} in {}", parent.display()))?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        writer
            .write_all(bytes)
            .with_context(|| format!("write {artifact} artifact"))?;
        writer
            .flush()
            .with_context(|| format!("flush {artifact} artifact"))?;
    }
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("sync {artifact} artifact"))?;
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!("{artifact} output already exists: {}", path.display())
        } else {
            anyhow!(
                "publish {artifact} {} without clobbering: {}",
                path.display(),
                error.error
            )
        }
    })?;
    Ok(())
}

pub(crate) fn run_amplification_ledger(trace: &Path, output: Option<&Path>) -> Result<()> {
    let executable = std::env::current_exe().context("resolve running ledger executable")?;
    let command: Vec<String> = std::env::args().collect();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    run_amplification_ledger_with_provenance(trace, output, &mut stdout, || {
        Ok(capture_provenance(&executable, &command)?.into())
    })
}

fn run_amplification_ledger_with_provenance(
    trace: &Path,
    output: Option<&Path>,
    stdout: &mut impl Write,
    provenance: impl FnOnce() -> Result<LedgerProvenance>,
) -> Result<()> {
    let capture = validate_archived_amp1_path(trace)
        .with_context(|| format!("admit AMP1 capture {}", trace.display()))?;
    let ledger = build_ledger(&capture, provenance()?)?;
    publish_ledger(&ledger, output, stdout)
}

// ---------------------------------------------------------------------------
// `carrick debug amplification-compare` — the determinant-locked A/B.
// ---------------------------------------------------------------------------

/// The comparison artifact's schema.
///
/// A separate schema from the ledger's, deliberately: a comparison is not a
/// census and must never be mistaken for one by a reader looking for absolute
/// numbers.
pub(crate) const COMPARISON_SCHEMA: &str = "carrick.amplification-comparison.v1";

/// An exact signed difference, kept as its two sides plus the arithmetic.
///
/// `i128` because both sides are `u64` and the difference is signed; publishing
/// the operands next to the result is what lets a reader check the subtraction
/// without the original ledgers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CountDelta {
    pub(crate) a: u64,
    pub(crate) b: u64,
    pub(crate) delta: i128,
}

impl CountDelta {
    fn new(a: u64, b: u64) -> Self {
        Self {
            a,
            b,
            delta: i128::from(b) - i128::from(a),
        }
    }

    fn require(&self) -> Result<()> {
        if self.delta != i128::from(self.b) - i128::from(self.a) {
            bail!("amplification comparison delta is not the difference of its own operands");
        }
        Ok(())
    }
}

/// An exact signed difference of two ratios, `b/d − a/c`, as one fraction.
///
/// Never a float. The ledger's headline quantities are ratios that get compared
/// across captures, and a rounded quotient would make "did this lever move the
/// `mmap` row" a question about the host's floating-point unit. This mirrors
/// `debug_jit_shape`'s `ComparisonFraction`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFraction {
    pub(crate) numerator: i128,
    pub(crate) denominator: u128,
}

fn fraction_delta(a: &LedgerFraction, b: &LedgerFraction) -> Result<SignedFraction> {
    if a.denominator == 0 || b.denominator == 0 {
        bail!("amplification comparison ratio has a zero denominator");
    }
    let a_scaled = i128::from(a.numerator)
        .checked_mul(i128::from(b.denominator))
        .context("amplification comparison A ratio cross multiplication overflow")?;
    let b_scaled = i128::from(b.numerator)
        .checked_mul(i128::from(a.denominator))
        .context("amplification comparison B ratio cross multiplication overflow")?;
    let denominator = u128::from(a.denominator)
        .checked_mul(u128::from(b.denominator))
        .context("amplification comparison ratio denominator overflow")?;
    Ok(SignedFraction {
        numerator: b_scaled - a_scaled,
        denominator,
    })
}

/// Everything two ledgers must agree on before a difference between them means
/// anything.
///
/// Published as ONE copy of each field, because they are equal by
/// construction — a drifted determinant is a refusal, not a row.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComparisonDeterminants {
    pub(crate) ledger_schema: String,
    pub(crate) raw_schema: String,
    /// The D program that produced BOTH captures. Refusing to cross a version
    /// is the comparator's job — the ledger parser deliberately does not do it,
    /// or editing `native-amplification.d` would make every published ledger
    /// unparseable and destroy the archive.
    pub(crate) program_sha256: String,
    pub(crate) joins: String,
    pub(crate) declared_buffers: BTreeMap<String, String>,
    pub(crate) os_build: String,
    pub(crate) image: String,
    pub(crate) target_argv_sha256: String,
    /// The guest operations both censuses measured, in canonical order.
    pub(crate) guest_ops: Vec<GuestOp>,
    /// Whether both captures demanded a quiet host. The VALUES differ per run
    /// and are reported below; what is locked is that a preflighted arm is not
    /// differenced against an unverified one.
    pub(crate) quiet_host_preflighted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComparisonSides<T> {
    pub(crate) a: T,
    pub(crate) b: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotalsComparison {
    pub(crate) guest_syscalls: CountDelta,
    pub(crate) host_syscalls: CountDelta,
    pub(crate) host_syscall_cpu_ns: CountDelta,
    pub(crate) mach_traps: CountDelta,
    pub(crate) mach_trap_cpu_ns: CountDelta,
    pub(crate) as_faults: CountDelta,
    pub(crate) zfods: CountDelta,
    pub(crate) cow_faults: CountDelta,
}

/// `carrick-only` differences its own bucket and NEVER acquires a ratio here
/// either: the struct has no amplification field for the same reason
/// [`CarrickOnly`] has none.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarrickOnlyComparison {
    pub(crate) host_calls: CountDelta,
    pub(crate) host_cpu_ns: CountDelta,
    pub(crate) mach_traps: CountDelta,
    pub(crate) mach_trap_cpu_ns: CountDelta,
    pub(crate) zfods: CountDelta,
    /// The instrument's own `kdebug_trace*` cost on each side, differenced so a
    /// reader can see whether the two captures paid the same tracing tax.
    pub(crate) probable_instrument_cpu_ns: CountDelta,
    pub(crate) excluding_probable_instrument_cpu_ns: CountDelta,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BudgetComparison {
    pub(crate) guest_attributed_cpu_ns: CountDelta,
    pub(crate) carrick_only_cpu_ns: CountDelta,
    pub(crate) measured_kernel_cpu_ns: CountDelta,
    pub(crate) guest_attributed_share: ComparisonSides<LedgerFraction>,
    pub(crate) guest_attributed_share_delta: SignedFraction,
}

/// One guest operation, on both sides, with the two ratios the whole instrument
/// exists to move.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestOpComparison {
    pub(crate) guest_op: GuestOp,
    pub(crate) guest_count_delta: i128,
    pub(crate) host_calls_delta: i128,
    pub(crate) host_cpu_ns_delta: i128,
    pub(crate) mach_traps_delta: i128,
    pub(crate) zfods_delta: i128,
    pub(crate) guest_count: ComparisonSides<u64>,
    pub(crate) host_calls: ComparisonSides<u64>,
    pub(crate) host_cpu_ns: ComparisonSides<u64>,
    pub(crate) host_call_amplification: ComparisonSides<LedgerFraction>,
    /// The number every entry drives toward 1, differenced exactly.
    pub(crate) host_call_amplification_delta: SignedFraction,
    pub(crate) host_cpu_ns_per_guest_op: ComparisonSides<LedgerFraction>,
    /// The number the kernel budget is ranked on, differenced exactly.
    pub(crate) host_cpu_ns_per_guest_op_delta: SignedFraction,
    pub(crate) dominant_host_call: ComparisonSides<Option<DominantHostCall>>,
}

/// A determinant-locked A/B of two amplification ledgers.
///
/// **Wall never appears here.** Four probe families perturb the traced run
/// 2–4x, so a wall difference between two captures is a difference between two
/// perturbations. Counts, CPU-ns and same-instrument ratios are the citable
/// quantities and are the only ones differenced.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AmplificationComparisonV1 {
    pub(crate) schema: String,
    pub(crate) a_sha256: String,
    pub(crate) b_sha256: String,
    pub(crate) determinants: ComparisonDeterminants,
    pub(crate) provenance: ComparisonSides<LedgerProvenance>,
    pub(crate) preflight: ComparisonSides<Option<QuietHostReceipt>>,
    pub(crate) totals: TotalsComparison,
    pub(crate) carrick_only: CarrickOnlyComparison,
    pub(crate) budget: BudgetComparison,
    pub(crate) ledger_rows: Vec<GuestOpComparison>,
}

fn require_same<T: PartialEq + std::fmt::Debug>(a: &T, b: &T, label: &str) -> Result<()> {
    if a != b {
        bail!(
            "amplification comparison refuses a {label} crossing: A is {a:?} and B is {b:?}. Two captures that disagree on this were never measuring the same thing, so their difference is not a result"
        );
    }
    Ok(())
}

fn lock_determinants(
    a: &AmplificationLedgerV1,
    b: &AmplificationLedgerV1,
) -> Result<ComparisonDeterminants> {
    require_same(&a.schema, &b.schema, "ledger schema")?;
    require_same(
        &a.authority.raw_schema,
        &b.authority.raw_schema,
        "raw schema",
    )?;
    require_same(
        &a.authority.program_sha256,
        &b.authority.program_sha256,
        "program digest",
    )?;
    require_same(&a.authority.joins, &b.authority.joins, "joins")?;
    require_same(
        &a.authority.declared_buffers,
        &b.authority.declared_buffers,
        "declared buffer headroom",
    )?;
    require_same(&a.authority.os_build, &b.authority.os_build, "os build")?;
    require_same(&a.authority.image, &b.authority.image, "image")?;
    require_same(
        &a.authority.target_argv_sha256,
        &b.authority.target_argv_sha256,
        "target argv digest",
    )?;
    require_same(
        &a.authority.preflight.is_some(),
        &b.authority.preflight.is_some(),
        "quiet-host preflight",
    )?;

    let guest_ops: Vec<GuestOp> = a.ledger.iter().map(|row| row.guest_op.clone()).collect();
    let other: Vec<GuestOp> = b.ledger.iter().map(|row| row.guest_op.clone()).collect();
    if guest_ops != other {
        bail!(
            "amplification comparison refuses a guest operation set crossing: A measured {:?} and B measured {:?}. A row-wise difference needs both sides to have the same rows",
            guest_ops.iter().map(GuestOp::name).collect::<Vec<_>>(),
            other.iter().map(GuestOp::name).collect::<Vec<_>>()
        );
    }

    Ok(ComparisonDeterminants {
        ledger_schema: a.schema.clone(),
        raw_schema: a.authority.raw_schema.clone(),
        program_sha256: a.authority.program_sha256.clone(),
        joins: a.authority.joins.clone(),
        declared_buffers: a.authority.declared_buffers.clone(),
        os_build: a.authority.os_build.clone(),
        image: a.authority.image.clone(),
        target_argv_sha256: a.authority.target_argv_sha256.clone(),
        guest_ops,
        quiet_host_preflighted: a.authority.preflight.is_some(),
    })
}

fn compare_rows(
    a: &AmplificationLedgerV1,
    b: &AmplificationLedgerV1,
) -> Result<Vec<GuestOpComparison>> {
    a.ledger
        .iter()
        .zip(&b.ledger)
        .map(|(left, right)| {
            Ok(GuestOpComparison {
                guest_op: left.guest_op.clone(),
                guest_count_delta: i128::from(right.guest_count) - i128::from(left.guest_count),
                host_calls_delta: i128::from(right.host_calls) - i128::from(left.host_calls),
                host_cpu_ns_delta: i128::from(right.host_cpu_ns) - i128::from(left.host_cpu_ns),
                mach_traps_delta: i128::from(right.mach_traps) - i128::from(left.mach_traps),
                zfods_delta: i128::from(right.faults.zfod) - i128::from(left.faults.zfod),
                guest_count: ComparisonSides {
                    a: left.guest_count,
                    b: right.guest_count,
                },
                host_calls: ComparisonSides {
                    a: left.host_calls,
                    b: right.host_calls,
                },
                host_cpu_ns: ComparisonSides {
                    a: left.host_cpu_ns,
                    b: right.host_cpu_ns,
                },
                host_call_amplification_delta: fraction_delta(
                    &left.host_call_amplification,
                    &right.host_call_amplification,
                )?,
                host_call_amplification: ComparisonSides {
                    a: left.host_call_amplification.clone(),
                    b: right.host_call_amplification.clone(),
                },
                host_cpu_ns_per_guest_op_delta: fraction_delta(
                    &left.host_cpu_ns_per_guest_op,
                    &right.host_cpu_ns_per_guest_op,
                )?,
                host_cpu_ns_per_guest_op: ComparisonSides {
                    a: left.host_cpu_ns_per_guest_op.clone(),
                    b: right.host_cpu_ns_per_guest_op.clone(),
                },
                dominant_host_call: ComparisonSides {
                    a: left.dominant_host_call.clone(),
                    b: right.dominant_host_call.clone(),
                },
            })
        })
        .collect()
}

fn build_comparison(a_bytes: &[u8], b_bytes: &[u8]) -> Result<AmplificationComparisonV1> {
    let a = parse_ledger_v1(a_bytes).context("parse amplification ledger A")?;
    let b = parse_ledger_v1(b_bytes).context("parse amplification ledger B")?;
    let determinants = lock_determinants(&a, &b)?;
    let report = AmplificationComparisonV1 {
        schema: COMPARISON_SCHEMA.to_owned(),
        a_sha256: format!("{:x}", Sha256::digest(a_bytes)),
        b_sha256: format!("{:x}", Sha256::digest(b_bytes)),
        determinants,
        provenance: ComparisonSides {
            a: a.provenance.clone(),
            b: b.provenance.clone(),
        },
        preflight: ComparisonSides {
            a: a.authority.preflight.clone(),
            b: b.authority.preflight.clone(),
        },
        totals: TotalsComparison {
            guest_syscalls: CountDelta::new(a.totals.guest_syscalls, b.totals.guest_syscalls),
            host_syscalls: CountDelta::new(a.totals.host_syscalls, b.totals.host_syscalls),
            host_syscall_cpu_ns: CountDelta::new(
                a.totals.host_syscall_cpu_ns,
                b.totals.host_syscall_cpu_ns,
            ),
            mach_traps: CountDelta::new(a.totals.mach_traps, b.totals.mach_traps),
            mach_trap_cpu_ns: CountDelta::new(a.totals.mach_trap_cpu_ns, b.totals.mach_trap_cpu_ns),
            as_faults: CountDelta::new(a.totals.faults.as_fault, b.totals.faults.as_fault),
            zfods: CountDelta::new(a.totals.faults.zfod, b.totals.faults.zfod),
            cow_faults: CountDelta::new(a.totals.faults.cow_fault, b.totals.faults.cow_fault),
        },
        carrick_only: CarrickOnlyComparison {
            host_calls: CountDelta::new(a.carrick_only.host_calls, b.carrick_only.host_calls),
            host_cpu_ns: CountDelta::new(a.carrick_only.host_cpu_ns, b.carrick_only.host_cpu_ns),
            mach_traps: CountDelta::new(a.carrick_only.mach_traps, b.carrick_only.mach_traps),
            mach_trap_cpu_ns: CountDelta::new(
                a.carrick_only.mach_trap_cpu_ns,
                b.carrick_only.mach_trap_cpu_ns,
            ),
            zfods: CountDelta::new(a.carrick_only.faults.zfod, b.carrick_only.faults.zfod),
            probable_instrument_cpu_ns: CountDelta::new(
                a.carrick_only.probable_instrument.host_cpu_ns,
                b.carrick_only.probable_instrument.host_cpu_ns,
            ),
            excluding_probable_instrument_cpu_ns: CountDelta::new(
                a.carrick_only.excluding_probable_instrument.host_cpu_ns,
                b.carrick_only.excluding_probable_instrument.host_cpu_ns,
            ),
        },
        budget: BudgetComparison {
            guest_attributed_cpu_ns: CountDelta::new(
                a.budget.guest_attributed_cpu_ns,
                b.budget.guest_attributed_cpu_ns,
            ),
            carrick_only_cpu_ns: CountDelta::new(
                a.budget.carrick_only_cpu_ns,
                b.budget.carrick_only_cpu_ns,
            ),
            measured_kernel_cpu_ns: CountDelta::new(
                a.budget.measured_kernel_cpu_ns,
                b.budget.measured_kernel_cpu_ns,
            ),
            guest_attributed_share_delta: fraction_delta(
                &a.budget.guest_attributed_share,
                &b.budget.guest_attributed_share,
            )?,
            guest_attributed_share: ComparisonSides {
                a: a.budget.guest_attributed_share.clone(),
                b: b.budget.guest_attributed_share.clone(),
            },
        },
        ledger_rows: compare_rows(&a, &b)?,
    };
    report.validate()?;
    Ok(report)
}

impl AmplificationComparisonV1 {
    /// Re-derive every published difference from its own operands.
    ///
    /// Run on build and again on every parse, so a hand-edited comparison is
    /// refused rather than read. The determinants are re-validated too: they
    /// are the claim that the difference means anything.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != COMPARISON_SCHEMA {
            bail!("amplification comparison schema is not {COMPARISON_SCHEMA}");
        }
        for (digest, label) in [(&self.a_sha256, "A"), (&self.b_sha256, "B")] {
            validate_sha256(digest, &format!("comparison {label} ledger digest"))?;
        }
        if self.determinants.ledger_schema != LEDGER_SCHEMA {
            bail!("amplification comparison compares artifacts that are not {LEDGER_SCHEMA}");
        }
        if self.determinants.raw_schema != AMPLIFICATION_RAW_SCHEMA {
            bail!("amplification comparison raw schema is not {AMPLIFICATION_RAW_SCHEMA}");
        }
        validate_sha256(
            &self.determinants.program_sha256,
            "comparison program digest",
        )?;
        validate_sha256(
            &self.determinants.target_argv_sha256,
            "comparison target argv digest",
        )?;
        if !self.determinants.image.contains("@sha256:") {
            bail!("amplification comparison names an image that is not digest-pinned");
        }
        if self.determinants.declared_buffers.is_empty() {
            bail!("amplification comparison records no declared buffer headroom");
        }
        match (
            self.determinants.quiet_host_preflighted,
            &self.preflight.a,
            &self.preflight.b,
        ) {
            (true, Some(a), Some(b)) => {
                a.validate()?;
                b.validate()?;
            }
            (false, None, None) => {}
            _ => bail!(
                "amplification comparison disagrees with itself about whether both captures were preflighted"
            ),
        }

        if self.determinants.guest_ops.len() != self.ledger_rows.len() {
            bail!("amplification comparison rows do not cover its own guest operation set");
        }
        let mut previous: Option<CanonicalNr> = None;
        for (guest_op, row) in self.determinants.guest_ops.iter().zip(&self.ledger_rows) {
            guest_op.validate()?;
            if guest_op != &row.guest_op {
                bail!("amplification comparison row does not name its own guest operation");
            }
            if previous.is_some_and(|previous| previous >= row.guest_op.canonical_nr()) {
                bail!(
                    "amplification comparison rows are duplicate or not ordered by canonical number"
                );
            }
            previous = Some(row.guest_op.canonical_nr());
            row.validate()?;
        }

        for delta in [
            &self.totals.guest_syscalls,
            &self.totals.host_syscalls,
            &self.totals.host_syscall_cpu_ns,
            &self.totals.mach_traps,
            &self.totals.mach_trap_cpu_ns,
            &self.totals.as_faults,
            &self.totals.zfods,
            &self.totals.cow_faults,
            &self.carrick_only.host_calls,
            &self.carrick_only.host_cpu_ns,
            &self.carrick_only.mach_traps,
            &self.carrick_only.mach_trap_cpu_ns,
            &self.carrick_only.zfods,
            &self.carrick_only.probable_instrument_cpu_ns,
            &self.carrick_only.excluding_probable_instrument_cpu_ns,
            &self.budget.guest_attributed_cpu_ns,
            &self.budget.carrick_only_cpu_ns,
            &self.budget.measured_kernel_cpu_ns,
        ] {
            delta.require()?;
        }
        require_equal_fraction_delta(
            &self.budget.guest_attributed_share,
            &self.budget.guest_attributed_share_delta,
            "guest attributed share",
        )
    }
}

fn require_equal_fraction_delta(
    sides: &ComparisonSides<LedgerFraction>,
    published: &SignedFraction,
    label: &str,
) -> Result<()> {
    if fraction_delta(&sides.a, &sides.b)? != *published {
        bail!("amplification comparison {label} delta is not the difference of its own operands");
    }
    Ok(())
}

impl GuestOpComparison {
    fn validate(&self) -> Result<()> {
        for (sides, delta, label) in [
            (&self.guest_count, self.guest_count_delta, "guest count"),
            (&self.host_calls, self.host_calls_delta, "host calls"),
            (&self.host_cpu_ns, self.host_cpu_ns_delta, "host CPU-ns"),
        ] {
            if delta != i128::from(sides.b) - i128::from(sides.a) {
                bail!(
                    "amplification comparison {} {label} delta is not the difference of its own operands",
                    self.guest_op.name()
                );
            }
        }
        if self.guest_count.a == 0 || self.guest_count.b == 0 {
            bail!(
                "amplification comparison row {} has a zero amplification denominator",
                self.guest_op.name()
            );
        }
        self.host_call_amplification.a.require(
            self.host_calls.a,
            self.guest_count.a,
            "A host calls",
        )?;
        self.host_call_amplification.b.require(
            self.host_calls.b,
            self.guest_count.b,
            "B host calls",
        )?;
        self.host_cpu_ns_per_guest_op.a.require(
            self.host_cpu_ns.a,
            self.guest_count.a,
            "A host CPU",
        )?;
        self.host_cpu_ns_per_guest_op.b.require(
            self.host_cpu_ns.b,
            self.guest_count.b,
            "B host CPU",
        )?;
        require_equal_fraction_delta(
            &self.host_call_amplification,
            &self.host_call_amplification_delta,
            "host call amplification",
        )?;
        require_equal_fraction_delta(
            &self.host_cpu_ns_per_guest_op,
            &self.host_cpu_ns_per_guest_op_delta,
            "host CPU per guest op",
        )
    }
}

fn serialize_comparison(report: &AmplificationComparisonV1) -> Result<Vec<u8>> {
    report.validate()?;
    let mut bytes = serde_json::to_vec(report).context("serialize amplification comparison v1")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn parse_comparison_v1(bytes: &[u8]) -> Result<AmplificationComparisonV1> {
    if bytes.last() != Some(&b'\n') || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        bail!("an amplification comparison is exactly one newline-terminated JSON object");
    }
    let report: AmplificationComparisonV1 = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .context("parse amplification comparison v1")?;
    report.validate()?;
    if serialize_comparison(&report)? != bytes {
        bail!("amplification comparison is not canonical v1 output");
    }
    Ok(report)
}

pub(crate) fn run_amplification_compare(
    a_path: &Path,
    b_path: &Path,
    output: Option<&Path>,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    run_amplification_compare_to(a_path, b_path, output, &mut stdout)
}

fn run_amplification_compare_to(
    a_path: &Path,
    b_path: &Path,
    output: Option<&Path>,
    stdout: &mut impl Write,
) -> Result<()> {
    // Identical inputs are NOT refused, unlike `jit-shape-compare`'s: a
    // ledger differenced against itself must report exact zeros, and that is
    // the cheapest available check that the arithmetic is exact.
    let a_bytes = fs::read(a_path)
        .with_context(|| format!("read amplification ledger A {}", a_path.display()))?;
    let b_bytes = fs::read(b_path)
        .with_context(|| format!("read amplification ledger B {}", b_path.display()))?;
    let report = build_comparison(&a_bytes, &b_bytes)?;
    let bytes = serialize_comparison(&report)?;
    parse_comparison_v1(&bytes).context("self-validate the published amplification comparison")?;
    publish_noclobber(&bytes, output, stdout, "amplification comparison")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader's own fixture, so the analyzer and the admissibility half
    /// cannot drift onto different notions of a valid stream. Its header
    /// carries placeholders rather than literals: the program digest is the
    /// bundled D program's and changes whenever the program is edited, and the
    /// image and argv digests come from the same parser the capture path uses,
    /// so a literal would make "stale fixture" indistinguishable from
    /// "rejected stream".
    use crate::amplification_profile::fixture_stream;

    fn stream() -> String {
        fixture_stream()
    }

    fn provenance() -> LedgerProvenance {
        LedgerProvenance {
            binary_sha256: "aa".repeat(32),
            git_sha: "bb".repeat(20),
            git_dirty: Some(false),
            run_id: "amp-fixture".to_owned(),
            host: "fixture-host".to_owned(),
            command: vec!["carrick".to_owned(), "run".to_owned()],
        }
    }

    fn ledger_from(contents: &str) -> Result<AmplificationLedgerV1> {
        let capture = crate::amplification_profile::validate_amp1_lines(
            contents.lines(),
            crate::trace_profile::ProfileCaptureStatus::default(),
        )?;
        build_ledger(&capture, provenance())
    }

    fn ledger() -> AmplificationLedgerV1 {
        ledger_from(&stream()).expect("the reader's own fixture must produce a ledger")
    }

    fn error(result: Result<AmplificationLedgerV1>) -> String {
        format!("{:#}", result.expect_err("expected a named ledger refusal"))
    }

    fn row<'a>(ledger: &'a AmplificationLedgerV1, name: &str) -> &'a GuestOpRow {
        ledger
            .ledger
            .iter()
            .find(|row| row.guest_op.name() == name)
            .unwrap_or_else(|| panic!("ledger has no {name} row"))
    }

    #[test]
    fn amplification_ledger_resolves_every_guest_op_through_the_canonical_table() {
        let ledger = ledger();
        // Slots 58 and 224 on the wire are canonical 56 and 222: openat and
        // mmap. The names come from `carrick_abi::syscall`, never from the
        // stream -- the D program deliberately copies no strings.
        assert_eq!(
            ledger
                .ledger
                .iter()
                .map(|row| (row.guest_op.canonical_nr().raw(), row.guest_op.name()))
                .collect::<Vec<_>>(),
            vec![(56, "openat"), (222, "mmap")]
        );

        let openat = row(&ledger, "openat");
        assert_eq!(openat.guest_count, 4);
        assert_eq!(openat.host_calls, 10);
        assert_eq!(
            openat.host_call_amplification,
            LedgerFraction::new(10, 4),
            "four guest opens cost ten host calls; the ledger's job is to drive that to one"
        );
        assert_eq!(openat.host_cpu_ns, 7_900);
        assert_eq!(
            openat.host_cpu_ns_per_guest_op,
            LedgerFraction::new(7_900, 4)
        );
        let dominant = openat
            .dominant_host_call
            .as_ref()
            .expect("openat's dominant host call");
        assert_eq!(dominant.name.as_str(), "openat");
        assert_eq!((dominant.count, dominant.cpu_ns), (7, 7_000));

        let mmap = row(&ledger, "mmap");
        assert_eq!((mmap.mach_traps, mmap.mach_trap_cpu_ns), (3, 3_300));
        assert_eq!(mmap.faults.zfod, 12);
        // Ranked by CPU, not by count: `mmap` and `pread` fire twice each, and
        // `pread` is the one that costs the kernel more.
        assert_eq!(
            mmap.dominant_host_call
                .as_ref()
                .map(|call| call.name.as_str().to_owned()),
            Some("pread".to_owned())
        );
    }

    #[test]
    fn amplification_ledger_refuses_a_guest_op_the_canonical_table_does_not_define() {
        // Canonical 4000 is not an aarch64 syscall. A ledger row naming it
        // would be a plausible-looking line about an operation carrick cannot
        // name, which is exactly what the typed domain exists to prevent.
        let foreign = stream()
            .replace("AMP1|guest_slot=58|count=4", "AMP1|guest_slot=4002|count=4")
            .replace("AMP1|guest_slot=58|host=", "AMP1|guest_slot=4002|host=");
        assert!(
            error(ledger_from(&foreign))
                .contains("canonical aarch64 syscall table does not define")
        );
    }

    #[test]
    fn amplification_ledger_refuses_a_per_op_sum_that_misses_the_independent_total() {
        // A per-op row silently missing -- the shape a partial census actually
        // takes. Lost events make the ledger's numbers SMALLER, which reads as
        // lower amplification, i.e. as good news.
        for (row, needle) in [
            (
                "AMP1|guest_slot=1|trap=mach_msg2_trap|cpu_ns=700\n",
                "mach trap CPU-ns",
            ),
            ("AMP1|guest_slot=224|kind=zfod|count=12\n", "zfod"),
            ("AMP1|guest_slot=1|kind=cow_fault|count=2\n", "cow_fault"),
            ("AMP1|guest_slot=224|kind=as_fault|count=4\n", "as_fault"),
        ] {
            let partial = stream().replacen(row, "", 1);
            let message = error(ledger_from(&partial));
            assert!(
                message.contains("closure failed") && message.contains(needle),
                "dropping {row:?} must be a named closure failure, got {message}"
            );
        }

        // ... and the same disagreement from the other side, for every currency
        // the instrument measures: the program's own independent, ungrouped
        // total no longer equals what the per-op rows add up to. The guest
        // denominator is in this list because a wrong denominator inflates every
        // ratio in the ledger at once.
        for (metric, corrupt, needle) in [
            (
                "AMP1|metric=guest-syscall-total|count=6",
                "AMP1|metric=guest-syscall-total|count=9",
                "guest syscalls",
            ),
            (
                "AMP1|metric=host-syscall-entry-total|count=20",
                "AMP1|metric=host-syscall-entry-total|count=21",
                "host syscalls",
            ),
            (
                "AMP1|metric=host-syscall-return-total|count=20",
                "AMP1|metric=host-syscall-return-total|count=19",
                "host syscall returns",
            ),
            (
                "AMP1|metric=host-syscall-cpu-ns|count=18500",
                "AMP1|metric=host-syscall-cpu-ns|count=18501",
                "host syscall CPU-ns",
            ),
            (
                "AMP1|metric=mach-trap-entry-total|count=5",
                "AMP1|metric=mach-trap-entry-total|count=6",
                "mach traps",
            ),
            (
                "AMP1|metric=mach-trap-return-total|count=5",
                "AMP1|metric=mach-trap-return-total|count=4",
                "mach trap returns",
            ),
            (
                "AMP1|metric=mach-trap-cpu-ns|count=4000",
                "AMP1|metric=mach-trap-cpu-ns|count=3999",
                "mach trap CPU-ns",
            ),
            ("AMP1|kind=zfod|count=18", "AMP1|kind=zfod|count=19", "zfod"),
        ] {
            let skewed = stream().replacen(metric, corrupt, 1);
            let message = error(ledger_from(&skewed));
            assert!(
                message.contains("closure failed") && message.contains(needle),
                "skewing {metric:?} must be a named closure failure, got {message}"
            );
        }
    }

    #[test]
    fn amplification_ledger_subtracts_the_instruments_own_calls_from_the_primary_ratios() {
        let ledger = ledger();
        let bucket = &ledger.carrick_only;
        // The gross bucket carries everything outside a guest window ...
        assert_eq!((bucket.host_calls, bucket.host_cpu_ns), (6, 600));
        // ... of which libdtrace's own kdebug_trace64 is most of it ...
        assert_eq!(
            (
                bucket.probable_instrument.host_calls,
                bucket.probable_instrument.host_cpu_ns
            ),
            (5, 500)
        );
        assert_eq!(
            bucket
                .probable_instrument
                .by_host_call
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["kdebug_trace64"]
        );
        // ... and what carrick is actually charged excludes it.
        assert_eq!(
            bucket.excluding_probable_instrument,
            BucketTotals {
                host_calls: 1,
                host_cpu_ns: 100
            }
        );
        assert_eq!(ledger.budget.probable_instrument_cpu_ns, 500);
        // carrick-only gross CPU is 600 syscall + 700 mach = 1300; the primary
        // figure is that minus the 500 the instrument cost.
        assert_eq!(ledger.budget.carrick_only_cpu_ns, 800);
        assert_eq!(ledger.budget.guest_attributed_cpu_ns, 21_200);
        assert_eq!(ledger.budget.measured_kernel_cpu_ns, 22_500);

        // The instrument may never appear inside a guest window: a per-op ratio
        // containing the cost of asking the question cannot be corrected later.
        let contaminated = stream().replace(
            "AMP1|guest_slot=1|host=kdebug_trace64",
            "AMP1|guest_slot=58|host=kdebug_trace64",
        );
        assert!(error(ledger_from(&contaminated)).contains("instrument's own"));
    }

    #[test]
    fn amplification_ledger_refuses_a_dropped_capture_and_a_missing_drop_section() {
        for source in [
            "dtrace-error",
            "service-window-reentry",
            "service-end-unmatched",
        ] {
            let line = format!("AMP1|drop|source={source}|count=0");
            let dropped = stream().replacen(&line, &line.replace("count=0", "count=4"), 1);
            let message = error(ledger_from(&dropped));
            assert!(
                message.contains(source),
                "a nonzero {source} counter must be named, got {message}"
            );
        }

        // Absent is not zero: a stream with no drop section at all is refused
        // rather than read as a clean one.
        let without = stream()
            .lines()
            .filter(|line| !line.starts_with("AMP1|drop|") && *line != "AMP1|section=drops")
            .collect::<Vec<_>>()
            .join("\n");
        assert!(error(ledger_from(&without)).contains("drops"));

        // And a published ledger cannot be edited into one either.
        let mut ledger = ledger();
        ledger.authority.program_drops.clear();
        assert!(format!("{:#}", ledger.validate().unwrap_err()).contains("absent is not zero"));
    }

    #[test]
    fn amplification_ledger_round_trips_byte_identically() {
        let ledger = ledger();
        let first = serialize_ledger(&ledger).expect("serialize");
        let parsed = parse_ledger_v1(&first).expect("parse the ledger back");
        let second = serialize_ledger(&parsed).expect("re-serialize");
        assert_eq!(first, second, "canonical output must be byte-identical");
        assert_eq!(parsed, ledger);

        // One object, one trailing newline -- anything else is not the
        // canonical artifact.
        let mut pretty = serde_json::to_vec_pretty(&ledger).expect("pretty");
        pretty.push(b'\n');
        assert!(parse_ledger_v1(&pretty).is_err());
        assert!(parse_ledger_v1(&first[..first.len() - 1]).is_err());
    }

    #[test]
    fn amplification_ledger_refuses_an_unauthenticated_program() {
        // A `--script` capture, or an edited D program, cannot authenticate its
        // own stream, so it cannot become a ledger.
        let foreign = stream().replace(&amp1_program_sha256(), &"3".repeat(64));
        assert!(error(ledger_from(&foreign)).contains("does not name the bundled"));

        // Building one from a capture requires the CURRENTLY bundled program ...
        let mut ledger = ledger();
        ledger.authority.program_sha256 = "4".repeat(64);
        assert!(
            format!("{:#}", ledger.require_bundled_program().unwrap_err())
                .contains("--script capture cannot produce a ledger")
        );
    }

    #[test]
    fn a_ledger_from_an_older_program_still_parses() {
        // ... but READING one back must not, or every previously published
        // ledger becomes unparseable the moment `native-amplification.d` is
        // edited -- including by the Task-3 in-band drop record -- destroying
        // the archive this instrument exists to build. The recorded digest is
        // what makes a version crossing detectable; refusing it retroactively
        // is `amplification-compare`'s job, not the parser's.
        let mut ledger = ledger();
        ledger.authority.program_sha256 = "5".repeat(64);
        let bytes = serialize_ledger(&ledger).expect("an older program's ledger still serializes");
        let parsed = parse_ledger_v1(&bytes).expect("an older program's ledger still parses");
        assert_eq!(parsed.authority.program_sha256, "5".repeat(64));
        assert!(parsed.require_bundled_program().is_err());

        // A malformed digest is still refused on parse: the FORM is structural.
        let mut malformed = ledger.clone();
        malformed.authority.program_sha256 = "not-a-digest".to_owned();
        assert!(
            format!("{:#}", malformed.validate().unwrap_err())
                .contains("not a 64-character SHA-256 digest")
        );
    }

    #[test]
    fn amplification_ledger_refuses_a_declared_join_that_never_armed() {
        // The shape a reviewer constructed to walk through closure: a join that
        // never armed prints its section markers, no rows at all, and a legal
        // zero total -- because ZDEFS silences a provider that matches nothing
        // and the D BEGIN seeds every total `sum(0)`. Per-op closure then holds
        // at 0 == 0 and the ledger quietly loses exactly the mass that join
        // exists to catch, which reads as LOWER amplification.
        let unarmed_mach = stream()
            .lines()
            .filter(|line| !line.contains("|trap="))
            .map(|line| {
                line.replace(
                    "|metric=mach-trap-entry-total|count=5",
                    "|metric=mach-trap-entry-total|count=0",
                )
                .replace(
                    "|metric=mach-trap-return-total|count=5",
                    "|metric=mach-trap-return-total|count=0",
                )
                .replace(
                    "|metric=mach-trap-cpu-ns|count=4000",
                    "|metric=mach-trap-cpu-ns|count=0",
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let message = error(ledger_from(&unarmed_mach));
        assert!(
            message.contains("mach-trap-entry-total") && message.contains("never armed"),
            "an unarmed mach join must be named, got {message}"
        );

        // Every seeded total, one at a time -- including the two CPU totals,
        // whose zero is `vtimestamp` failing to advance rather than a missing
        // provider (the D header's own unqualified question about
        // `mach_trap:::`).
        for (rows, metric, zeroed) in [
            (
                "|host=",
                "host-syscall-entry-total|count=20",
                "host-syscall-entry-total|count=0",
            ),
            (
                "|host=",
                "host-syscall-return-total|count=20",
                "host-syscall-return-total|count=0",
            ),
            (
                "|cpu_ns=",
                "host-syscall-cpu-ns|count=18500",
                "host-syscall-cpu-ns|count=0",
            ),
            (
                "|trap=",
                "mach-trap-return-total|count=5",
                "mach-trap-return-total|count=0",
            ),
        ] {
            let unarmed = stream()
                .lines()
                .filter(|line| !line.contains(rows))
                .map(|line| line.replace(metric, zeroed))
                .collect::<Vec<_>>()
                .join("\n");
            let message = error(ledger_from(&unarmed));
            assert!(
                message.contains("never armed") || message.contains("closure failed"),
                "zeroing {metric} must be a named refusal, got {message}"
            );
        }

        // The fault join is three independent probe descriptions, so ZDEFS can
        // silence one of them on its own.
        for (kind, total) in [
            ("as_fault", "AMP1|kind=as_fault|count=4"),
            ("zfod", "AMP1|kind=zfod|count=18"),
            ("cow_fault", "AMP1|kind=cow_fault|count=2"),
        ] {
            let unarmed = stream()
                .lines()
                .filter(|line| {
                    !(line.contains("|kind=")
                        && line.contains("guest_slot=")
                        && line.contains(&format!("kind={kind}")))
                })
                .map(|line| {
                    if line == total {
                        format!("AMP1|kind={kind}|count=0")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let message = error(ledger_from(&unarmed));
            assert!(
                message.contains(kind) && message.contains("never armed"),
                "an unarmed {kind} probe must be named, got {message}"
            );
        }
    }

    #[test]
    fn amplification_ledger_refuses_a_truncated_maximum_roster() {
        // `max_ns` is the one quantity with no independent ungrouped total, so
        // its only closure is that its key set equals the CPU sum's -- the two
        // aggregations are written in one clause on one key. Without that, a
        // lost row in the END flush silently zeroes `dominant_host_call.max_ns`.
        let truncated = stream().replacen("AMP1|guest_slot=58|host=openat|max_ns=1200\n", "", 1);
        assert!(error(ledger_from(&truncated)).contains("no matching maximum"));
    }

    #[test]
    fn amplification_ledger_reports_the_expected_service_window_control_flow() {
        let ledger = ledger();
        assert_eq!(ledger.totals.inherited_service_ends, 3);
        assert!(ledger.totals.wall_is_not_authority);
        assert_eq!(ledger.totals.traced_elapsed_ns, 123_456_789);
        assert_eq!(
            ledger.authority.consumer_drop_enforcement,
            CONSUMER_DROP_ENFORCEMENT
        );
        // Every host call in the fixture returns, so nothing is unreturned and
        // the terminal roster is carried for the case where something is.
        assert!(ledger.closure.unreturned_host_calls.is_empty());
        assert_eq!(ledger.authority.terminal_calls.len(), 2);
    }

    #[test]
    fn amplification_ledger_refuses_host_work_attributed_to_an_op_with_no_service_window() {
        // Only the entry probe writes a guest slot, so a join naming an op the
        // denominator has never seen means the slot table and the denominator
        // disagree. Slot 100 is canonical 98 (`futex`) -- a real syscall, so the
        // refusal is about the missing denominator and not about the table.
        let orphan = stream().replace(
            "AMP1|guest_slot=58|host=close",
            "AMP1|guest_slot=100|host=close",
        );
        assert!(error(ledger_from(&orphan)).contains("no service-window entry"));

        // And the carrick-only slot can never carry a guest denominator.
        let counted =
            stream().replacen("AMP1|guest_slot=58|count=4", "AMP1|guest_slot=1|count=4", 1);
        assert!(error(ledger_from(&counted)).contains("carrick-only slot"));
    }

    #[test]
    fn amplification_ledger_publishes_without_clobbering() {
        let directory = tempfile::tempdir().expect("output directory");
        let raw = directory.path().join("amp1.raw");
        std::fs::write(&raw, stream()).expect("write fixture stream");
        let output = directory.path().join("nested").join("ledger.json");

        let mut sink = Vec::new();
        run_amplification_ledger_with_provenance(&raw, Some(&output), &mut sink, || {
            Ok(provenance())
        })
        .expect("publish the ledger");
        assert!(
            sink.is_empty(),
            "a published artifact does not also go to stdout"
        );
        let published = std::fs::read(&output).expect("read the published ledger");
        assert_eq!(
            parse_ledger_v1(&published).expect("parse").provenance,
            provenance()
        );

        let error =
            run_amplification_ledger_with_provenance(&raw, Some(&output), &mut Vec::new(), || {
                Ok(provenance())
            })
            .expect_err("a second publish must not overwrite an artifact");
        assert!(format!("{error:#}").contains("already exists"));
    }
    // -----------------------------------------------------------------------
    // `amplification-compare`
    // -----------------------------------------------------------------------

    /// The candidate arm: one more host `close` inside the `openat` window, and
    /// the capture's own independent totals moved to match. Everything else --
    /// image, argv, program, joins, buffers, os build, guest-op set -- is held,
    /// which is what makes the difference mean something.
    fn candidate_stream() -> String {
        stream()
            .replacen(
                "AMP1|guest_slot=58|host=close|count=3",
                "AMP1|guest_slot=58|host=close|count=4",
                1,
            )
            .replacen("AMP1|host=close|count=3", "AMP1|host=close|count=4", 1)
            .replacen(
                "AMP1|metric=host-syscall-entry-total|count=20",
                "AMP1|metric=host-syscall-entry-total|count=21",
                1,
            )
            .replacen(
                "AMP1|metric=host-syscall-return-total|count=20",
                "AMP1|metric=host-syscall-return-total|count=21",
                1,
            )
    }

    fn compare(
        a: &AmplificationLedgerV1,
        b: &AmplificationLedgerV1,
    ) -> Result<AmplificationComparisonV1> {
        build_comparison(&serialize_ledger(a)?, &serialize_ledger(b)?)
    }

    fn comparison_row<'a>(
        report: &'a AmplificationComparisonV1,
        name: &str,
    ) -> &'a GuestOpComparison {
        report
            .ledger_rows
            .iter()
            .find(|row| row.guest_op.name() == name)
            .unwrap_or_else(|| panic!("comparison has no {name} row"))
    }

    #[test]
    fn amplification_comparison_differences_two_ledgers_in_exact_integers() {
        let baseline = ledger();
        let candidate = ledger_from(&candidate_stream()).expect("candidate ledger");
        let report = compare(&baseline, &candidate).expect("compare two comparable ledgers");

        assert_eq!(report.schema, COMPARISON_SCHEMA);
        assert_eq!(report.totals.host_syscalls.delta, 1);
        assert_eq!(report.totals.host_syscall_cpu_ns.delta, 0);

        let openat = comparison_row(&report, "openat");
        assert_eq!(openat.host_calls_delta, 1);
        // 11/4 - 10/4, kept as the arithmetic that produced it rather than as
        // 0.25: a rounded quotient would make "did this lever move the row" a
        // question about the host's floating-point unit.
        assert_eq!(
            openat.host_call_amplification_delta,
            SignedFraction {
                numerator: 4,
                denominator: 16
            }
        );
        assert_eq!(openat.host_cpu_ns_per_guest_op_delta.numerator, 0);
        assert_eq!(openat.host_calls, ComparisonSides { a: 10, b: 11 });

        // An untouched row is exactly zero, not approximately zero.
        let mmap = comparison_row(&report, "mmap");
        for delta in [
            mmap.host_calls_delta,
            mmap.host_cpu_ns_delta,
            mmap.mach_traps_delta,
            mmap.zfods_delta,
        ] {
            assert_eq!(delta, 0);
        }
        assert_eq!(mmap.host_call_amplification_delta.numerator, 0);

        // Reversing the arms negates every difference and nothing else.
        let reversed = compare(&candidate, &baseline).expect("compare in reverse");
        assert_eq!(reversed.totals.host_syscalls.delta, -1);
        assert_eq!(
            comparison_row(&reversed, "openat")
                .host_call_amplification_delta
                .numerator,
            -4
        );
        assert_eq!(reversed.determinants, report.determinants);
    }

    /// A ledger differenced against itself is the cheapest available check that
    /// the arithmetic is exact, so identical inputs are ACCEPTED here (unlike
    /// `jit-shape-compare`, which refuses them) and must report zeros.
    #[test]
    fn amplification_comparison_of_identical_ledgers_is_exactly_zero() {
        let ledger = ledger();
        let report = compare(&ledger, &ledger).expect("a ledger differences against itself");
        assert_eq!(report.a_sha256, report.b_sha256);
        for row in &report.ledger_rows {
            assert_eq!(row.host_calls_delta, 0);
            assert_eq!(row.host_cpu_ns_delta, 0);
            assert_eq!(row.host_call_amplification_delta.numerator, 0);
            assert_eq!(row.host_cpu_ns_per_guest_op_delta.numerator, 0);
        }
        assert_eq!(report.totals.zfods.delta, 0);
        assert_eq!(report.carrick_only.host_cpu_ns.delta, 0);
        assert_eq!(report.budget.measured_kernel_cpu_ns.delta, 0);
        assert_eq!(report.budget.guest_attributed_share_delta.numerator, 0);
    }

    /// A comparator that will cross a determinant is worse than none: it
    /// produces a plausible delta between two numbers that were never
    /// comparable. `program_sha256` is on this list deliberately -- the ledger
    /// PARSER does not check it, because folding it in would make every
    /// published ledger unparseable the moment `native-amplification.d` is
    /// edited, so refusing to cross a version is this command's job.
    #[test]
    fn amplification_comparison_refuses_every_determinant_crossing() {
        let baseline = ledger();
        for (mutate, needle) in [
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.program_sha256 = "9".repeat(64);
                }) as Box<dyn Fn(&mut AmplificationLedgerV1)>,
                "program digest",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.joins = "syscall,mach".to_owned();
                }),
                "joins",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger
                        .authority
                        .declared_buffers
                        .insert("aggsize".to_owned(), "32m".to_owned());
                }),
                "declared buffer headroom",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.os_build = "27A5295j".to_owned();
                }),
                "os build",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.image =
                        format!("docker.io/library/debian@sha256:{}", "bb".repeat(32));
                }),
                "image",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.target_argv_sha256 = "8".repeat(64);
                }),
                "target argv digest",
            ),
            (
                Box::new(|ledger: &mut AmplificationLedgerV1| {
                    ledger.authority.preflight = Some(
                        crate::quiet_host::QuietHostReceipt::from_header_fields(5, 900).unwrap(),
                    );
                }),
                "quiet-host preflight",
            ),
        ] {
            let mut candidate = baseline.clone();
            mutate(&mut candidate);
            let message = format!(
                "{:#}",
                compare(&baseline, &candidate).expect_err("a crossed determinant must be refused")
            );
            assert!(message.contains(needle), "unnamed refusal: {message}");
        }

        // The guest-op SET is a determinant too: two censuses that measured
        // different operations have no row-wise difference to report. Slot 66
        // is canonical 64, a different real syscall, so closure still holds.
        let other_ops = ledger_from(&stream().replace("guest_slot=224", "guest_slot=66"))
            .expect("a census of other guest ops");
        assert!(
            format!("{:#}", compare(&baseline, &other_ops).unwrap_err())
                .contains("guest operation set")
        );
    }

    #[test]
    fn amplification_comparison_is_canonical_and_self_validating() {
        let report = compare(&ledger(), &ledger_from(&candidate_stream()).unwrap()).unwrap();
        let first = serialize_comparison(&report).expect("serialize");
        let parsed = parse_comparison_v1(&first).expect("parse the comparison back");
        assert_eq!(parsed, report);
        assert_eq!(serialize_comparison(&parsed).expect("re-serialize"), first);

        let mut pretty = serde_json::to_vec_pretty(&report).expect("pretty");
        pretty.push(b'\n');
        assert!(parse_comparison_v1(&pretty).is_err());

        // A hand-edited difference is refused rather than read: the operands
        // are published next to the result precisely so the subtraction can be
        // re-derived without the original ledgers.
        let mut forged = report.clone();
        forged.totals.host_syscalls.delta += 5;
        assert!(
            format!("{:#}", forged.validate().unwrap_err())
                .contains("not the difference of its own operands")
        );

        let mut forged = report.clone();
        forged.ledger_rows[0]
            .host_call_amplification_delta
            .numerator += 1;
        assert!(
            format!("{:#}", forged.validate().unwrap_err())
                .contains("not the difference of its own operands")
        );
    }

    #[test]
    fn amplification_comparison_publishes_without_clobbering() {
        let directory = tempfile::tempdir().expect("output directory");
        let a = directory.path().join("a.json");
        let b = directory.path().join("b.json");
        std::fs::write(&a, serialize_ledger(&ledger()).unwrap()).unwrap();
        std::fs::write(
            &b,
            serialize_ledger(&ledger_from(&candidate_stream()).unwrap()).unwrap(),
        )
        .unwrap();
        let output = directory.path().join("nested").join("comparison.json");

        let mut sink = Vec::new();
        run_amplification_compare_to(&a, &b, Some(&output), &mut sink)
            .expect("publish the comparison");
        assert!(sink.is_empty());
        let published = std::fs::read(&output).expect("read the published comparison");
        assert_eq!(
            parse_comparison_v1(&published)
                .expect("parse")
                .totals
                .host_syscalls
                .delta,
            1
        );

        let error = run_amplification_compare_to(&a, &b, Some(&output), &mut Vec::new())
            .expect_err("a second publish must not overwrite an artifact");
        assert!(format!("{error:#}").contains("already exists"));
    }
}
