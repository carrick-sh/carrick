//! EL1 census: where one run's syscalls were served.
//!
//! Stage 0 of `docs/superpowers/specs/2026-09-24-zone-the-workloads.md`. For
//! every canonical syscall number it records, for one carrier:
//!
//! - `el1_served` / `el1_forwarded`: EL1's own counters (served in-guest, or
//!   forwarded to the host);
//! - `host_services` / `host_cpu_ns`: host services of a trapped syscall and
//!   the host thread CPU time they took (thread CPU, so a blocking wait is not
//!   counted as work);
//! - `redispatches` / `redispatch_cpu_ns`: continuation resumptions of a
//!   suspended syscall and their thread CPU time;
//! - `el1_boundaries`: syscalls EL1 served that still returned through the
//!   host to deliver pending work;
//! - `refused` / `venue_refused`: counted ENOSYS answered in ring (unrouted,
//!   or refused by the crossing table) and refusals by the carrier venue, with
//!   their native-child subsets `refused_child` / `venue_refused_child`.
//!
//! `refusal_evidence` keeps the same counters by native ordinal and caller;
//! [`rank_refusals`] ranks them across runs (`carrick debug el1-census
//! --refusals`), so a row that ends on ENOSYS names its syscall.
//!
//! Emission is opt-in through a nonempty `CARRICK_EL1_CENSUS` destination.
//! Unset, empty, or exact `0` emits no census and enables no timing hooks.
//! `CARRICK_EL1_CENSUS=<directory>` selects another destination for
//! `<directory>/<CARRICK_RUN_ID or "run">-<pid>-<unique>.json` before terminal
//! delivery, while EL1 is still mapped. Disabled, each hook costs one relaxed load.
//! Counts are exact (no sampling); timing uses the per-thread CPU clock.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SLOTS: usize = 512;

struct Table {
    host_services: [AtomicU64; SLOTS],
    host_cpu_ns: [AtomicU64; SLOTS],
    redispatches: [AtomicU64; SLOTS],
    redispatch_cpu_ns: [AtomicU64; SLOTS],
    el1_boundaries: [AtomicU64; SLOTS],
}

static TABLE: Table = Table {
    host_services: [const { AtomicU64::new(0) }; SLOTS],
    host_cpu_ns: [const { AtomicU64::new(0) }; SLOTS],
    redispatches: [const { AtomicU64::new(0) }; SLOTS],
    redispatch_cpu_ns: [const { AtomicU64::new(0) }; SLOTS],
    el1_boundaries: [const { AtomicU64::new(0) }; SLOTS],
};

static DIRECTORY: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
static STARTED: OnceLock<std::time::Instant> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

fn census_requested(setting: Option<&std::ffi::OsStr>) -> bool {
    setting.is_some_and(|value| !value.is_empty() && value != "0")
}

/// Read the environment once; later calls are one relaxed load.
pub fn init_from_env() {
    DIRECTORY.get_or_init(|| {
        let setting = std::env::var_os("CARRICK_EL1_CENSUS");
        ENABLED.store(census_requested(setting.as_deref()), Ordering::Relaxed);
        setting
            .filter(|value| !value.is_empty() && value != "0")
            .map(std::path::PathBuf::from)
    });
    let _ = STARTED.get_or_init(std::time::Instant::now);
}

/// The carrier process's user and system CPU so far, in nanoseconds.
fn process_cpu_ns() -> (u64, u64) {
    // SAFETY: `usage` is valid storage for one rusage.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (0, 0);
    }
    let ns = |tv: libc::timeval| {
        (tv.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(tv.tv_usec as u64 * 1_000)
    };
    (ns(usage.ru_utime), ns(usage.ru_stime))
}

#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// This thread's CPU time in nanoseconds.
#[inline]
pub fn thread_cpu_ns() -> u64 {
    if !DIRECTORY.get().is_some_and(Option::is_some) {
        return 0;
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is valid storage for one timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[inline]
fn slot(nr: u64) -> Option<usize> {
    let index = nr as usize;
    (index < SLOTS).then_some(index)
}

/// A host service of syscall `nr` that started at thread CPU `start_ns`.
#[inline]
pub fn record_host_service(nr: u64, start_ns: u64) {
    if let Some(index) = slot(nr) {
        TABLE.host_services[index].fetch_add(1, Ordering::Relaxed);
        TABLE.host_cpu_ns[index]
            .fetch_add(thread_cpu_ns().saturating_sub(start_ns), Ordering::Relaxed);
    }
}

/// A continuation resumption of syscall `nr` that started at `start_ns`.
#[inline]
pub fn record_redispatch(nr: u64, start_ns: u64) {
    if let Some(index) = slot(nr) {
        TABLE.redispatches[index].fetch_add(1, Ordering::Relaxed);
        TABLE.redispatch_cpu_ns[index]
            .fetch_add(thread_cpu_ns().saturating_sub(start_ns), Ordering::Relaxed);
    }
}

/// EL1 served syscall `nr` but returned through the host for pending work.
#[inline]
pub fn record_el1_boundary(nr: u64) {
    if let Some(index) = slot(nr) {
        TABLE.el1_boundaries[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// One row of the census.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CensusRow {
    pub nr: u64,
    pub name: String,
    pub el1_served: u64,
    pub el1_forwarded: u64,
    pub refused: u64,
    pub venue_refused: u64,
    /// The native-child subsets of `refused` and `venue_refused` (absent in
    /// older files).
    #[serde(default)]
    pub refused_child: u64,
    #[serde(default)]
    pub venue_refused_child: u64,
    pub host_services: u64,
    pub host_cpu_ns: u64,
    pub redispatches: u64,
    pub redispatch_cpu_ns: u64,
    pub el1_boundaries: u64,
}

/// The census of one carrier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Census {
    pub refusal_evidence: carrick_spec::syscall_census::RefusalEvidence,
    pub schema: u32,
    pub run_id: Option<String>,
    pub pid: u32,
    /// Whether the EL1 counters were readable (EL1 enabled and mapped).
    pub el1_counters: bool,
    /// The carrier's user CPU for the whole run (guest execution included).
    #[serde(default)]
    pub process_user_ns: u64,
    /// The carrier's system CPU for the whole run.
    #[serde(default)]
    pub process_sys_ns: u64,
    /// Wall time from EL1 setup to terminal publication.
    #[serde(default)]
    pub wall_ns: u64,
    /// Calls EL1 left for the host after starting to serve them, by
    /// `IpcLeave` name (nonzero only; absent in older files).
    #[serde(default)]
    pub ipc_leaves: std::collections::BTreeMap<String, u64>,
    /// Delegated anonymous mm calls the ring left for the host, by
    /// `AnonymousLeave` name (nonzero only; absent in older files). In a
    /// native child each one is a refused call.
    #[serde(default)]
    pub anonymous_leaves: std::collections::BTreeMap<String, u64>,
    pub rows: Vec<CensusRow>,
    /// The last counted refusals with what each refused call asked for
    /// (`Counters::refused_calls`), oldest first; absent in older files.
    #[serde(default)]
    pub refused_calls: Vec<RefusedCallRecord>,
    /// Refused-call records claimed but never written because a lapped or
    /// concurrent writer held their row (`Counters::refused_call_dropped`).
    #[serde(default)]
    pub refused_calls_dropped: u64,
}

/// One counted refusal's typed record, as the census file keeps it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefusedCallRecord {
    pub nr: u64,
    pub name: Option<String>,
    pub caller: carrick_spec::syscall_census::CallerClass,
    pub venue: String,
    /// The six argument registers; `None` when the venue did not retain them.
    pub arguments: Option<[u64; 6]>,
}

impl RefusedCallRecord {
    fn new(
        call: carrick_el1_abi::RefusedCall,
        isa: carrick_spec::syscall_census::CensusIsa,
    ) -> Self {
        let nr = call.ordinal.raw();
        let name = match isa {
            carrick_spec::syscall_census::CensusIsa::Aarch64 => {
                carrick_abi::syscall::lookup_aarch64(nr).map(|s| s.name)
            }
            carrick_spec::syscall_census::CensusIsa::X86_64 => {
                carrick_syscall_abi::syscall_x86_64::lookup_x86_64(nr).map(|s| s.name)
            }
        };
        Self {
            nr,
            name: name.map(str::to_owned),
            caller: match call.origin {
                carrick_core_abi::service::ServiceOrigin::Initial => {
                    carrick_spec::syscall_census::CallerClass::Root
                }
                carrick_core_abi::service::ServiceOrigin::Descendant => {
                    carrick_spec::syscall_census::CallerClass::NativeChild
                }
            },
            venue: match call.venue {
                carrick_el1_abi::RefusalVenue::Ring => "ring",
                carrick_el1_abi::RefusalVenue::Carrier => "carrier",
            }
            .to_owned(),
            arguments: match call.arguments {
                carrick_el1_abi::RefusalArguments::Registers(arguments) => Some(arguments),
                carrick_el1_abi::RefusalArguments::Unretained => None,
            },
        }
    }

    /// `REFUSE nr=<n>(<name>) caller=<root|child> venue=<ring|carrier> a0..a5`,
    /// the same line `carrick eventring` prints. For the select and poll
    /// families it adds `nfds`; the descriptor sets stay in guest memory.
    pub fn line(&self) -> String {
        let mut line = format!(
            "REFUSE nr={}({}) caller={} venue={}",
            self.nr,
            self.name.as_deref().unwrap_or("?"),
            match self.caller {
                carrick_spec::syscall_census::CallerClass::Root => "root",
                carrick_spec::syscall_census::CallerClass::NativeChild => "child",
            },
            self.venue
        );
        let Some(arguments) = self.arguments else {
            line.push_str(" args=unretained");
            return line;
        };
        for (index, argument) in arguments.iter().enumerate() {
            line.push_str(&format!(" a{index}={argument:#x}"));
        }
        match self.name.as_deref() {
            Some("select" | "pselect6") => line.push_str(&format!(" nfds={}", arguments[0])),
            Some("poll" | "ppoll") => line.push_str(&format!(" nfds={}", arguments[1])),
            _ => {}
        }
        line
    }
}

fn snapshot(run_id: Option<&carrick_kernel::kernel::CarrierScopeId>) -> Census {
    snapshot_counters(
        run_id,
        crate::read_el1_counters().as_ref(),
        carrick_spec::syscall_census::CensusIsa::Aarch64,
    )
}

fn snapshot_counters(
    run_id: Option<&carrick_kernel::kernel::CarrierScopeId>,
    counters: Option<&carrick_el1_abi::Counters>,
    isa: carrick_spec::syscall_census::CensusIsa,
) -> Census {
    // Legacy service rows use canonical ordinals. Refusal evidence below is
    // native-indexed; remap only the diagnostic totals when joining these rows.
    let mut refused_by_canonical = vec![0u64; SLOTS];
    let mut venue_by_canonical = vec![0u64; SLOTS];
    let mut refused_child_by_canonical = vec![0u64; SLOTS];
    let mut venue_child_by_canonical = vec![0u64; SLOTS];
    if let Some(counters) = counters {
        for native in 0..SLOTS {
            let canonical = match isa {
                carrick_spec::syscall_census::CensusIsa::Aarch64 => {
                    Some(carrick_abi::CanonicalNr::new(native as u64))
                }
                carrick_spec::syscall_census::CensusIsa::X86_64 => {
                    carrick_syscall_abi::syscall_x86_64::canonical_x86_64(carrick_abi::NativeNr(
                        native as u64,
                    ))
                }
            };
            if let Some(canonical) = canonical
                .and_then(|nr| usize::try_from(nr.raw()).ok())
                .filter(|nr| *nr < SLOTS)
            {
                refused_by_canonical[canonical] += counters.refused[native].load(Ordering::Relaxed);
                venue_by_canonical[canonical] +=
                    counters.venue_refused[native].load(Ordering::Relaxed);
                refused_child_by_canonical[canonical] +=
                    counters.refused_child[native].load(Ordering::Relaxed);
                venue_child_by_canonical[canonical] +=
                    counters.venue_refused_child[native].load(Ordering::Relaxed);
            }
        }
    }
    let mut rows = Vec::new();
    for index in 0..SLOTS {
        let (served, forwarded) = counters.as_ref().map_or((0, 0), |c| {
            (
                c.served[index].load(Ordering::Relaxed),
                c.forwarded[index].load(Ordering::Relaxed),
            )
        });
        let row = CensusRow {
            nr: index as u64,
            name: carrick_abi::syscall::lookup_aarch64(index as u64)
                .map_or_else(|| format!("nr{index}"), |s| s.name.to_owned()),
            el1_served: served,
            el1_forwarded: forwarded,
            refused: refused_by_canonical[index],
            venue_refused: venue_by_canonical[index],
            refused_child: refused_child_by_canonical[index],
            venue_refused_child: venue_child_by_canonical[index],
            host_services: TABLE.host_services[index].load(Ordering::Relaxed),
            host_cpu_ns: TABLE.host_cpu_ns[index].load(Ordering::Relaxed),
            redispatches: TABLE.redispatches[index].load(Ordering::Relaxed),
            redispatch_cpu_ns: TABLE.redispatch_cpu_ns[index].load(Ordering::Relaxed),
            el1_boundaries: TABLE.el1_boundaries[index].load(Ordering::Relaxed),
        };
        if row.el1_served
            + row.el1_forwarded
            + row.refused
            + row.venue_refused
            + row.host_services
            + row.redispatches
            + row.el1_boundaries
            > 0
        {
            rows.push(row);
        }
    }
    let (process_user_ns, process_sys_ns) = process_cpu_ns();
    Census {
        refusal_evidence: refusal_evidence(counters, isa),
        schema: 2,
        run_id: run_id.map(|id| id.as_str().to_owned()),
        pid: std::process::id(),
        el1_counters: counters.is_some(),
        process_user_ns,
        process_sys_ns,
        wall_ns: STARTED
            .get()
            .map_or(0, |start| start.elapsed().as_nanos() as u64),
        ipc_leaves: counters.map_or_else(Default::default, |c| {
            carrick_el1_abi::IpcLeave::ALL
                .into_iter()
                .filter_map(|why| {
                    let count = c.ipc_leaves[why as usize].load(Ordering::Relaxed);
                    (count != 0).then(|| (why.name().to_owned(), count))
                })
                .collect()
        }),
        anonymous_leaves: counters.map_or_else(Default::default, |c| {
            carrick_el1_abi::AnonymousLeave::ALL
                .into_iter()
                .filter_map(|why| {
                    let count = c.anonymous_leaves[why as usize].load(Ordering::Relaxed);
                    (count != 0).then(|| (why.name().to_owned(), count))
                })
                .collect()
        }),
        rows,
        refused_calls: counters.map_or_else(Vec::new, |counters| {
            counters
                .refused_calls()
                .map(|call| RefusedCallRecord::new(call, isa))
                .collect()
        }),
        refused_calls_dropped: counters.map_or(0, |counters| {
            counters.refused_call_dropped.load(Ordering::Acquire)
        }),
    }
}

fn refusal_evidence(
    counters: Option<&carrick_el1_abi::Counters>,
    isa: carrick_spec::syscall_census::CensusIsa,
) -> carrick_spec::syscall_census::RefusalEvidence {
    use carrick_personality_linux::crossing::{AllowedHostCrossing, HostCrossingKind};
    use carrick_spec::syscall_census::{
        CallerClass, CensusIsa, RefusalEvidence, RefusalRow, SCHEMA,
    };
    let mut evidence = RefusalEvidence {
        schema: SCHEMA,
        isa,
        complete: counters.is_some(),
        rows: Vec::new(),
    };
    let Some(counters) = counters else {
        return evidence;
    };
    for nr in 0..=512 {
        let refused = counters.refused[nr].load(Ordering::Relaxed);
        let child = counters.refused_child[nr].load(Ordering::Relaxed);
        let venue = counters.venue_refused[nr].load(Ordering::Relaxed);
        let child_venue = counters.venue_refused_child[nr].load(Ordering::Relaxed);
        if child > refused || child_venue > venue {
            evidence.complete = false;
            continue;
        }
        let canonical = match isa {
            CensusIsa::Aarch64 => Some(carrick_abi::CanonicalNr::new(nr as u64)),
            CensusIsa::X86_64 => carrick_syscall_abi::syscall_x86_64::canonical_x86_64(
                carrick_abi::NativeNr(nr as u64),
            ),
        };
        let crossing = canonical.and_then(|canonical| match isa {
            CensusIsa::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical),
            CensusIsa::X86_64 => AllowedHostCrossing::from_canonical_x86(canonical),
        });
        let allowlisted = crossing.is_some_and(|crossing| {
            matches!(
                crossing.kind(),
                Some(HostCrossingKind::Permanent | HostCrossingKind::Temporary)
            )
        });
        for (caller, refused, venue_refused) in [
            (CallerClass::Root, refused - child, venue - child_venue),
            (CallerClass::NativeChild, child, child_venue),
        ] {
            if refused != 0 || venue_refused != 0 {
                evidence.rows.push(RefusalRow {
                    nr: nr as u64,
                    caller,
                    refused,
                    venue_refused,
                    allowlisted,
                });
            }
        }
    }
    evidence
}

/// Persist the mapped census before handing the terminal result to the caller.
/// Publication failures fail the run instead of delivering unqualified success.
pub fn publish_terminal(
    run_id: Option<&carrick_kernel::kernel::CarrierScopeId>,
) -> std::io::Result<()> {
    init_from_env();
    if !enabled() {
        return Ok(());
    }
    publish(snapshot(run_id), destination())
}

/// Persist an ISA's exact mapped counters before terminal delivery.
pub fn publish_counters_terminal(
    run_id: Option<&carrick_kernel::kernel::CarrierScopeId>,
    counters: &carrick_el1_abi::Counters,
    isa: carrick_spec::syscall_census::CensusIsa,
) -> std::io::Result<()> {
    init_from_env();
    if !enabled() {
        return Ok(());
    }
    publish(
        snapshot_counters(run_id, Some(counters), isa),
        destination(),
    )
}

fn destination() -> std::path::PathBuf {
    DIRECTORY
        .get()
        .and_then(Option::as_ref)
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("target/carrick-census"))
}

fn publish(census: Census, directory: std::path::PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    // The artifact owner requires a non-writable parent. Choose private
    // permissions at creation instead of inheriting a permissive host umask
    // or changing an existing directory's permissions.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    // Readers admit only .json files. Reserve a unique final name, but keep
    // the unpublished body under a different extension until it is durable.
    let name = format!(
        "{}-{}-",
        census.run_id.as_deref().unwrap_or("run"),
        census.pid
    );
    let reservation = tempfile::Builder::new()
        .prefix(&name)
        .suffix(".pending")
        .tempfile_in(&directory)?;
    let body = serde_json::to_vec_pretty(&census).map_err(std::io::Error::other)?;
    let final_path = reservation.path().with_extension("json");
    // Keep the name reserved until the existing artifact owner has durably
    // published the complete body. Readers never admit the .pending file.
    carrick_observability::vm_lifecycle::publish_artifact_bytes(&final_path, &body)
        .map_err(std::io::Error::other)
}

/// One syscall class summed over several censuses.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct AggregateRow {
    pub nr: u64,
    pub name: String,
    pub el1_served: u64,
    pub el1_forwarded: u64,
    pub refused: u64,
    pub venue_refused: u64,
    pub refused_child: u64,
    pub venue_refused_child: u64,
    pub host_services: u64,
    pub host_cpu_ns: u64,
    pub redispatches: u64,
    pub redispatch_cpu_ns: u64,
    pub el1_boundaries: u64,
}

impl AggregateRow {
    /// Host thread CPU spent on this class, services plus resumptions.
    pub fn host_total_ns(&self) -> u64 {
        self.host_cpu_ns.saturating_add(self.redispatch_cpu_ns)
    }
}

/// The aggregate of several censuses, ranked by host CPU descending.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Aggregate {
    pub runs: usize,
    pub runs_with_el1_counters: usize,
    pub host_total_ns: u64,
    /// Summed carrier CPU (user + system) across the runs.
    pub process_cpu_ns: u64,
    pub wall_ns: u64,
    /// `IpcLeave` counts summed across the runs, keyed by variant name.
    pub ipc_leaves: std::collections::BTreeMap<String, u64>,
    /// `AnonymousLeave` counts summed across the runs, keyed by variant name.
    pub anonymous_leaves: std::collections::BTreeMap<String, u64>,
    pub rows: Vec<AggregateRow>,
}

/// Sum censuses by syscall number and rank by host CPU. Fails closed on an
/// empty input or an unknown schema.
pub fn aggregate(censuses: &[Census]) -> Result<Aggregate, String> {
    if censuses.is_empty() {
        return Err("no census inputs".to_owned());
    }
    let mut by_nr: std::collections::BTreeMap<u64, AggregateRow> = Default::default();
    let mut ipc_leaves: std::collections::BTreeMap<String, u64> = Default::default();
    let mut anonymous_leaves: std::collections::BTreeMap<String, u64> = Default::default();
    for census in censuses {
        for (name, count) in &census.ipc_leaves {
            *ipc_leaves.entry(name.clone()).or_default() += count;
        }
        for (name, count) in &census.anonymous_leaves {
            *anonymous_leaves.entry(name.clone()).or_default() += count;
        }
        if census.schema != 2 {
            return Err(format!("unknown census schema {}", census.schema));
        }
        for row in &census.rows {
            let entry = by_nr.entry(row.nr).or_insert_with(|| AggregateRow {
                nr: row.nr,
                name: row.name.clone(),
                ..AggregateRow::default()
            });
            entry.el1_served += row.el1_served;
            entry.el1_forwarded += row.el1_forwarded;
            entry.refused += row.refused;
            entry.venue_refused += row.venue_refused;
            entry.refused_child += row.refused_child;
            entry.venue_refused_child += row.venue_refused_child;
            entry.host_services += row.host_services;
            entry.host_cpu_ns += row.host_cpu_ns;
            entry.redispatches += row.redispatches;
            entry.redispatch_cpu_ns += row.redispatch_cpu_ns;
            entry.el1_boundaries += row.el1_boundaries;
        }
    }
    let mut rows: Vec<AggregateRow> = by_nr.into_values().collect();
    rows.sort_by(|a, b| {
        b.host_total_ns()
            .cmp(&a.host_total_ns())
            .then(b.host_services.cmp(&a.host_services))
            .then(a.nr.cmp(&b.nr))
    });
    if rows.is_empty() {
        return Err("census inputs contain no syscalls".to_owned());
    }
    Ok(Aggregate {
        runs: censuses.len(),
        runs_with_el1_counters: censuses.iter().filter(|c| c.el1_counters).count(),
        host_total_ns: rows.iter().map(AggregateRow::host_total_ns).sum(),
        process_cpu_ns: censuses
            .iter()
            .map(|c| c.process_user_ns + c.process_sys_ns)
            .sum(),
        wall_ns: censuses.iter().map(|c| c.wall_ns).sum(),
        ipc_leaves,
        anonymous_leaves,
        rows,
    })
}

/// A Markdown table of the top `limit` rows.
pub fn render_table(aggregate: &Aggregate, limit: usize) -> String {
    let share_of_process = if aggregate.process_cpu_ns == 0 {
        0.0
    } else {
        aggregate.host_total_ns as f64 * 100.0 / aggregate.process_cpu_ns as f64
    };
    let mut out = format!(
        "runs: {} ({} with EL1 counters); host syscall CPU: {:.1} ms = {:.1}% of carrier CPU {:.1} ms; wall {:.1} ms\n\n",
        aggregate.runs,
        aggregate.runs_with_el1_counters,
        aggregate.host_total_ns as f64 / 1e6,
        share_of_process,
        aggregate.process_cpu_ns as f64 / 1e6,
        aggregate.wall_ns as f64 / 1e6
    );
    out.push_str("| syscall | nr | host services | host CPU ms | share | redispatches | EL1 served | EL1 forwarded | EL1 boundaries | refused | venue refused |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in aggregate.rows.iter().take(limit) {
        let share = if aggregate.host_total_ns == 0 {
            0.0
        } else {
            row.host_total_ns() as f64 * 100.0 / aggregate.host_total_ns as f64
        };
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {:.1}% | {} | {} | {} | {} | {} | {} |\n",
            row.name,
            row.nr,
            row.host_services,
            row.host_total_ns() as f64 / 1e6,
            share,
            row.redispatches,
            row.el1_served,
            row.el1_forwarded,
            row.el1_boundaries,
            row.refused,
            row.venue_refused
        ));
    }
    if !aggregate.ipc_leaves.is_empty() {
        let leaves: Vec<_> = aggregate
            .ipc_leaves
            .iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect();
        out.push_str(&format!("\nIPC leaves: {}\n", leaves.join(", ")));
    }
    if !aggregate.anonymous_leaves.is_empty() {
        let leaves: Vec<_> = aggregate
            .anonymous_leaves
            .iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect();
        out.push_str(&format!("\nanonymous leaves: {}\n", leaves.join(", ")));
    }
    out
}

/// One refused syscall for one caller class, summed over several censuses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RefusalRank {
    pub isa: carrick_spec::syscall_census::CensusIsa,
    /// Native ordinal; 512 is the overflow bucket (>= 512 or undecodable).
    pub native_nr: u64,
    /// The canonical (asm-generic) number, when the native one maps to one.
    pub canonical_nr: Option<u64>,
    pub name: String,
    pub caller: carrick_spec::syscall_census::CallerClass,
    /// Counted ENOSYS answered in ring: unrouted, or refused by the
    /// crossing table.
    pub unrouted: u64,
    /// Refusals by the carrier venue.
    pub carrier: u64,
    pub allowlisted: bool,
    /// Runs that refused it.
    pub runs: usize,
}

impl RefusalRank {
    pub fn total(&self) -> u64 {
        self.unrouted.saturating_add(self.carrier)
    }
}

/// Every refusal of several censuses, most refused first.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RefusalRanking {
    pub runs: usize,
    /// Runs whose refusal evidence was unreadable or inconsistent; their
    /// counts are missing, so a short ranking is not a clean one.
    pub incomplete_runs: usize,
    /// Every input run had complete refusal evidence.
    pub complete: bool,
    pub rows: Vec<RefusalRank>,
}

fn refusal_name(isa: carrick_spec::syscall_census::CensusIsa, native: u64) -> String {
    use carrick_spec::syscall_census::CensusIsa;
    let name = match isa {
        CensusIsa::Aarch64 => carrick_abi::syscall::lookup_aarch64(native).map(|s| s.name),
        CensusIsa::X86_64 => {
            carrick_syscall_abi::syscall_x86_64::lookup_x86_64(native).map(|s| s.name)
        }
    };
    match name {
        Some(name) => name.to_owned(),
        None if native >= 512 => "overflow".to_owned(),
        None => format!("nr{native}"),
    }
}

/// Rank the refusal evidence of `censuses` by count, per ISA, native
/// number and caller class. Fails closed on an empty input.
pub fn rank_refusals(censuses: &[Census]) -> Result<RefusalRanking, String> {
    use carrick_spec::syscall_census::{CallerClass, CensusIsa};
    if censuses.is_empty() {
        return Err("no census inputs".to_owned());
    }
    let isa_key = |isa: CensusIsa| match isa {
        CensusIsa::Aarch64 => 0u8,
        CensusIsa::X86_64 => 1,
    };
    let caller_key = |caller: CallerClass| match caller {
        CallerClass::Root => 0u8,
        CallerClass::NativeChild => 1,
    };
    let mut by_key: std::collections::BTreeMap<(u8, u64, u8), RefusalRank> = Default::default();
    let mut incomplete_runs = 0;
    for census in censuses {
        let evidence = &census.refusal_evidence;
        if !evidence.complete {
            incomplete_runs += 1;
        }
        for row in &evidence.rows {
            let key = (isa_key(evidence.isa), row.nr, caller_key(row.caller));
            let entry = by_key.entry(key).or_insert_with(|| RefusalRank {
                isa: evidence.isa,
                native_nr: row.nr,
                canonical_nr: match evidence.isa {
                    CensusIsa::Aarch64 => (row.nr < 512).then_some(row.nr),
                    CensusIsa::X86_64 => carrick_syscall_abi::syscall_x86_64::canonical_x86_64(
                        carrick_abi::NativeNr(row.nr),
                    )
                    .map(|nr| nr.raw()),
                },
                name: refusal_name(evidence.isa, row.nr),
                caller: row.caller,
                unrouted: 0,
                carrier: 0,
                allowlisted: row.allowlisted,
                runs: 0,
            });
            entry.unrouted = entry.unrouted.saturating_add(row.refused);
            entry.carrier = entry.carrier.saturating_add(row.venue_refused);
            entry.allowlisted |= row.allowlisted;
            entry.runs += 1;
        }
    }
    let mut rows: Vec<RefusalRank> = by_key.into_values().collect();
    // Stable within equal totals: ISA, native number, then root before child.
    rows.sort_by_key(|row| std::cmp::Reverse(row.total()));
    Ok(RefusalRanking {
        runs: censuses.len(),
        incomplete_runs,
        complete: incomplete_runs == 0,
        rows,
    })
}

/// A Markdown table of the top `limit` refusals.
pub fn render_refusals(ranking: &RefusalRanking, limit: usize) -> String {
    let mut out = format!(
        "runs: {} ({} with incomplete refusal evidence); refused syscalls: {}\n\n",
        ranking.runs,
        ranking.incomplete_runs,
        ranking.rows.len()
    );
    out.push_str("| rank | syscall | isa | native nr | canonical nr | caller | unrouted ENOSYS | carrier refused | total | allowlisted |\n");
    out.push_str("|---:|---|---|---:|---:|---|---:|---:|---:|---|\n");
    for (index, row) in ranking.rows.iter().take(limit).enumerate() {
        let isa = match row.isa {
            carrick_spec::syscall_census::CensusIsa::Aarch64 => "aarch64",
            carrick_spec::syscall_census::CensusIsa::X86_64 => "x86_64",
        };
        let caller = match row.caller {
            carrick_spec::syscall_census::CallerClass::Root => "root",
            carrick_spec::syscall_census::CallerClass::NativeChild => "native_child",
        };
        out.push_str(&format!(
            "| {} | {} | {isa} | {} | {} | {caller} | {} | {} | {} | {} |\n",
            index + 1,
            row.name,
            row.native_nr,
            row.canonical_nr
                .map_or_else(|| "-".to_owned(), |nr| nr.to_string()),
            row.unrouted,
            row.carrier,
            row.total(),
            if row.allowlisted { "yes" } else { "no" },
        ));
    }
    out
}

/// One run's census, summarised.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RunSummary {
    pub host_syscall_ns: u64,
    pub process_cpu_ns: u64,
    pub wall_ns: u64,
    pub el1_served: u64,
    pub host_services: u64,
    /// The forwarded class with the most host CPU, with its CPU.
    pub top_class: Option<(String, u64)>,
}

impl RunSummary {
    /// Host syscall CPU as a share of carrier CPU, when carrier CPU is known.
    pub fn syscall_share(&self) -> Option<f64> {
        (self.process_cpu_ns > 0)
            .then(|| self.host_syscall_ns as f64 * 100.0 / self.process_cpu_ns as f64)
    }
}

/// Summarise one census.
pub fn summarize(census: &Census) -> RunSummary {
    let mut top: Option<(String, u64)> = None;
    let mut host = 0u64;
    let mut served = 0u64;
    let mut services = 0u64;
    for row in &census.rows {
        let cpu = row.host_cpu_ns.saturating_add(row.redispatch_cpu_ns);
        host = host.saturating_add(cpu);
        served = served.saturating_add(row.el1_served);
        services = services.saturating_add(row.host_services);
        if top.as_ref().is_none_or(|(_, best)| cpu > *best) {
            top = Some((row.name.clone(), cpu));
        }
    }
    RunSummary {
        host_syscall_ns: host,
        process_cpu_ns: census.process_user_ns + census.process_sys_ns,
        wall_ns: census.wall_ns,
        el1_served: served,
        host_services: services,
        top_class: top,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(nr: u64, services: u64, cpu: u64) -> CensusRow {
        CensusRow {
            nr,
            name: format!("s{nr}"),
            el1_served: 0,
            el1_forwarded: services,
            refused: 0,
            venue_refused: 0,
            refused_child: 0,
            venue_refused_child: 0,
            host_services: services,
            host_cpu_ns: cpu,
            redispatches: 0,
            redispatch_cpu_ns: 0,
            el1_boundaries: 0,
        }
    }

    fn census(rows: Vec<CensusRow>) -> Census {
        Census {
            refusal_evidence: refusal_evidence(
                None,
                carrick_spec::syscall_census::CensusIsa::Aarch64,
            ),
            schema: 2,
            run_id: None,
            pid: 1,
            el1_counters: true,
            process_user_ns: 20_000,
            process_sys_ns: 4_000,
            wall_ns: 30_000,
            ipc_leaves: Default::default(),
            anonymous_leaves: Default::default(),
            rows,
            refused_calls: Vec::new(),
            refused_calls_dropped: 0,
        }
    }

    #[test]
    fn census_names_each_refused_calls_arguments_per_isa() {
        use carrick_spec::syscall_census::CensusIsa;
        let counters = carrick_el1_abi::Counters::new();
        for (nr, origin, venue, arguments) in [
            (
                270,
                carrick_core_abi::service::ServiceOrigin::Descendant,
                carrick_el1_abi::RefusalVenue::Ring,
                carrick_el1_abi::RefusalArguments::Registers([4, 0x7000, 0, 0, 0x7100, 0x7200]),
            ),
            (
                59,
                carrick_core_abi::service::ServiceOrigin::Initial,
                carrick_el1_abi::RefusalVenue::Carrier,
                carrick_el1_abi::RefusalArguments::Unretained,
            ),
        ] {
            counters.record_refusal(
                carrick_guest_arch::NativeOrdinal::new(nr),
                origin,
                venue,
                arguments,
            );
        }
        let x86 = snapshot_counters(None, Some(&counters), CensusIsa::X86_64);
        assert_eq!(
            x86.refused_calls
                .iter()
                .map(RefusedCallRecord::line)
                .collect::<Vec<_>>(),
            [
                "REFUSE nr=270(pselect6) caller=child venue=ring a0=0x4 a1=0x7000 a2=0x0 a3=0x0 a4=0x7100 a5=0x7200 nfds=4",
                "REFUSE nr=59(execve) caller=root venue=carrier args=unretained",
            ]
        );
        // The same native ordinals name ARM's calls on an ARM census.
        let arm = snapshot_counters(None, Some(&counters), CensusIsa::Aarch64);
        assert_eq!(arm.refused_calls[1].name.as_deref(), Some("pipe2"));
        let file: Census = serde_json::from_str(&serde_json::to_string(&x86).unwrap()).unwrap();
        assert_eq!(file.refused_calls, x86.refused_calls);
        // Records a lapped writer dropped are counted in the census file.
        assert_eq!(x86.refused_calls_dropped, 0);
        counters
            .refused_call_dropped
            .store(3, std::sync::atomic::Ordering::Relaxed);
        let dropped = snapshot_counters(None, Some(&counters), CensusIsa::X86_64);
        let file: Census = serde_json::from_str(&serde_json::to_string(&dropped).unwrap()).unwrap();
        assert_eq!(file.refused_calls_dropped, 3);
    }

    #[test]
    fn census_emission_requires_an_explicit_destination() {
        use std::ffi::OsStr;
        assert!(!census_requested(None));
        assert!(!census_requested(Some(OsStr::new(""))));
        assert!(!census_requested(Some(OsStr::new("0"))));
        assert!(census_requested(Some(OsStr::new("/tmp/census"))));
        assert!(census_requested(Some(OsStr::new("00"))));
    }

    #[test]
    fn serial_host_terminal_census_is_off_without_a_destination() {
        use wait_timeout::ChildExt;

        const CHILD: &str = "CARRICK_CENSUS_POLICY_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            publish_terminal(None).unwrap();
            assert!(!enabled());
            return;
        }
        for setting in [None, Some(""), Some("0")] {
            let directory = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "el1_census::tests::serial_host_terminal_census_is_off_without_a_destination",
                ])
                .env(CHILD, "1")
                .env_remove("CARRICK_EL1_CENSUS")
                .current_dir(directory.path());
            if let Some(setting) = setting {
                command.env("CARRICK_EL1_CENSUS", setting);
            }
            let mut child = command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            if child
                .wait_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .is_none()
            {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("census policy witness exceeded its five-second bound");
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "the fresh-process policy witness must actually run"
            );
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn sequential_carriers_with_one_grouping_id_preserve_every_census() {
        use carrick_spec::syscall_census::{CensusIsa, MARKER};
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("census");
        let refused = carrick_el1_abi::Counters::new();
        refused.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(34),
            carrick_core_abi::service::ServiceOrigin::Descendant,
            carrick_el1_abi::RefusalVenue::Carrier,
            carrick_el1_abi::RefusalArguments::Unretained,
        );
        let clean = carrick_el1_abi::Counters::new();
        publish(
            snapshot_counters(None, Some(&refused), CensusIsa::Aarch64),
            destination.clone(),
        )
        .unwrap();
        publish(
            snapshot_counters(None, Some(&clean), CensusIsa::Aarch64),
            destination.clone(),
        )
        .unwrap();
        let evidence = carrick_conformance::census::read_directory(&destination).unwrap();
        assert_eq!(
            evidence
                .lines()
                .filter(|line| line.starts_with(MARKER))
                .count(),
            2
        );
        assert!(
            carrick_spec::syscall_census::check_log(&evidence, None)
                .unwrap_err()
                .contains("allowlisted")
        );
    }

    #[test]
    fn terminal_publication_returns_a_complete_file_and_propagates_io_failure() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("new-census");
        publish(census(vec![row(34, 1, 0)]), destination.clone()).unwrap();
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "new census destinations must be private regardless of the host creation mask"
        );
        let paths: Vec<_> = std::fs::read_dir(destination)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].extension().unwrap(), "json");
        let decoded: Census = serde_json::from_slice(&std::fs::read(&paths[0]).unwrap()).unwrap();
        assert_eq!(decoded.rows, vec![row(34, 1, 0)]);
        // A regular file cannot serve as a destination directory. The terminal
        // owner must receive this failure, rather than an unqualified success.
        assert!(publish(census(vec![]), paths[0].clone()).is_err());
    }

    #[test]
    fn mapped_refused_child_mkdirat_reaches_the_shared_gate() {
        use carrick_spec::syscall_census::{CallerClass, CensusIsa};
        let counters = carrick_el1_abi::Counters::new();
        counters.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(34),
            carrick_core_abi::service::ServiceOrigin::Descendant,
            carrick_el1_abi::RefusalVenue::Ring,
            carrick_el1_abi::RefusalArguments::Unretained,
        );
        counters.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(34),
            carrick_core_abi::service::ServiceOrigin::Descendant,
            carrick_el1_abi::RefusalVenue::Carrier,
            carrick_el1_abi::RefusalArguments::Unretained,
        );
        let snapshot = snapshot_counters(None, Some(&counters), CensusIsa::Aarch64);
        assert!(snapshot.refusal_evidence.complete);
        assert_eq!(snapshot.refusal_evidence.rows.len(), 1);
        assert_eq!(
            snapshot.refusal_evidence.rows[0].caller,
            CallerClass::NativeChild
        );
        let log = format!(
            "{}{}",
            carrick_spec::syscall_census::MARKER,
            serde_json::to_string(&snapshot).unwrap()
        );
        assert!(
            carrick_spec::syscall_census::check_log(&log, None)
                .unwrap_err()
                .contains("allowlisted")
        );
        let empty = carrick_el1_abi::Counters::new();
        let next = snapshot_counters(None, Some(&empty), CensusIsa::X86_64);
        assert!(next.refusal_evidence.rows.is_empty());
        assert!(next.refusal_evidence.check(None).is_ok());
    }

    fn refuse(
        counters: &carrick_el1_abi::Counters,
        native: u64,
        origin: carrick_core_abi::service::ServiceOrigin,
        venue: carrick_el1_abi::RefusalVenue,
        times: usize,
    ) {
        for _ in 0..times {
            counters.record_refusal(
                carrick_guest_arch::NativeOrdinal::new(native),
                origin,
                venue,
            );
        }
    }

    #[test]
    fn refusal_ranking_names_a_native_child_unrouted_call_first_on_arm() {
        use carrick_core_abi::service::ServiceOrigin;
        use carrick_el1_abi::RefusalVenue;
        use carrick_spec::syscall_census::{CallerClass, CensusIsa};
        // The ARM HVF lane publishes these same mapped counters; a native
        // child's unrouted io_pgetevents (292) outranks a root carrier refusal.
        let first = carrick_el1_abi::Counters::new();
        refuse(
            &first,
            292,
            ServiceOrigin::Descendant,
            RefusalVenue::Ring,
            2,
        );
        refuse(&first, 34, ServiceOrigin::Initial, RefusalVenue::Carrier, 1);
        let second = carrick_el1_abi::Counters::new();
        refuse(
            &second,
            292,
            ServiceOrigin::Descendant,
            RefusalVenue::Ring,
            1,
        );
        let censuses = [
            snapshot_counters(None, Some(&first), CensusIsa::Aarch64),
            snapshot_counters(None, Some(&second), CensusIsa::Aarch64),
        ];
        // The canonical rows carry the child split too.
        let row = censuses[0].rows.iter().find(|row| row.nr == 292).unwrap();
        assert_eq!((row.refused, row.refused_child), (2, 2));
        let ranking = rank_refusals(&censuses).unwrap();
        assert!(ranking.complete);
        assert_eq!(ranking.rows.len(), 2);
        let top = &ranking.rows[0];
        assert_eq!(top.name, "io_pgetevents");
        assert_eq!(top.caller, CallerClass::NativeChild);
        assert_eq!((top.unrouted, top.carrier, top.runs), (3, 0, 2));
        assert_eq!(top.canonical_nr, Some(292));
        assert_eq!(ranking.rows[1].name, "mkdirat");
        assert_eq!(ranking.rows[1].caller, CallerClass::Root);
        assert_eq!(ranking.rows[1].carrier, 1);
        let table = render_refusals(&ranking, 10);
        assert!(
            table.contains(
                "| 1 | io_pgetevents | aarch64 | 292 | 292 | native_child | 3 | 0 | 3 | no |"
            ),
            "{table}"
        );
    }

    #[test]
    fn refusal_ranking_maps_x86_natives_and_flags_incomplete_runs() {
        use carrick_core_abi::service::ServiceOrigin;
        use carrick_el1_abi::RefusalVenue;
        use carrick_spec::syscall_census::CensusIsa;
        let counters = carrick_el1_abi::Counters::new();
        refuse(
            &counters,
            197,
            ServiceOrigin::Descendant,
            RefusalVenue::Ring,
            2,
        );
        let mut broken = snapshot_counters(None, None, CensusIsa::X86_64);
        assert!(!broken.refusal_evidence.complete);
        broken.rows = vec![row(1, 1, 1)];
        let ranking = rank_refusals(&[
            snapshot_counters(None, Some(&counters), CensusIsa::X86_64),
            broken,
        ])
        .unwrap();
        assert!(!ranking.complete);
        assert_eq!(ranking.incomplete_runs, 1);
        assert_eq!(ranking.rows[0].name, "removexattr");
        assert_eq!(ranking.rows[0].native_nr, 197);
        assert_eq!(ranking.rows[0].canonical_nr, Some(14));
        assert!(rank_refusals(&[]).is_err());
    }

    #[test]
    fn refused_child_mkdirat_survives_census_transport() {
        let mut value = serde_json::to_value(row(34, 0, 0)).unwrap();
        value["refused"] = serde_json::json!(1);
        value["venue_refused"] = serde_json::json!(2);
        let transported: CensusRow = serde_json::from_value(value).unwrap();
        let encoded = serde_json::to_value(transported).unwrap();
        assert_eq!(encoded["refused"], 1);
        assert_eq!(encoded["venue_refused"], 2);
    }

    #[test]
    fn census_json_names_each_nonzero_ipc_leave() {
        use carrick_el1_abi::IpcLeave;
        let counters = carrick_el1_abi::Counters::new();
        counters.ipc_leaves[IpcLeave::EpollNotZone as usize].store(3, Ordering::Relaxed);
        counters.ipc_leaves[IpcLeave::Restart as usize].store(1, Ordering::Relaxed);
        let census = snapshot_counters(
            None,
            Some(&counters),
            carrick_spec::syscall_census::CensusIsa::Aarch64,
        );
        let encoded = serde_json::to_value(&census).unwrap();
        assert_eq!(
            encoded["ipc_leaves"],
            serde_json::json!({"epoll_not_zone": 3, "restart": 1})
        );
        // Older files carry no such field and still load.
        let mut legacy = encoded.clone();
        legacy.as_object_mut().unwrap().remove("ipc_leaves");
        let legacy: Census = serde_json::from_value(legacy).unwrap();
        assert!(legacy.ipc_leaves.is_empty());
        // Aggregation sums them across carriers.
        let other = Census {
            ipc_leaves: [("epoll_not_zone".to_owned(), 2)].into(),
            ..census.clone()
        };
        let mut a = census;
        a.rows = vec![row(56, 1, 1)];
        let mut b = other;
        b.rows = vec![row(56, 1, 1)];
        let aggregate = aggregate(&[a, b]).unwrap();
        assert_eq!(aggregate.ipc_leaves["epoll_not_zone"], 5);
        assert!(render_table(&aggregate, 10).contains("epoll_not_zone: 5"));
    }

    /// #2748 step 0: a census names why the ring left each delegated
    /// anonymous mm call for the host, so one run names the arm behind a
    /// native child's refused `mmap`, `munmap`, `mprotect` or `madvise`.
    /// The counters are shared by both ISAs' rings.
    #[test]
    fn census_json_names_each_nonzero_anonymous_leave() {
        use carrick_el1_abi::AnonymousLeave;
        use carrick_spec::syscall_census::CensusIsa;
        for isa in [CensusIsa::Aarch64, CensusIsa::X86_64] {
            let counters = carrick_el1_abi::Counters::new();
            counters.anonymous_leaves[AnonymousLeave::RootDeclined as usize]
                .store(3, Ordering::Relaxed);
            counters.anonymous_leaves[AnonymousLeave::RootUnavailableBusy as usize]
                .store(1, Ordering::Relaxed);
            let census = snapshot_counters(None, Some(&counters), isa);
            let encoded = serde_json::to_value(&census).unwrap();
            assert_eq!(
                encoded["anonymous_leaves"],
                serde_json::json!({"root_declined": 3, "root_unavailable_busy": 1})
            );
            // Older files carry no such field and still load.
            let mut legacy = encoded.clone();
            legacy.as_object_mut().unwrap().remove("anonymous_leaves");
            let legacy: Census = serde_json::from_value(legacy).unwrap();
            assert_eq!(legacy.pid, census.pid);
            // Aggregation sums them across carriers.
            let mut a = census.clone();
            a.rows = vec![row(56, 1, 1)];
            let mut b = census;
            b.rows = vec![row(56, 1, 1)];
            let aggregate = aggregate(&[a, b]).unwrap();
            let summed = serde_json::to_value(&aggregate).unwrap();
            assert_eq!(
                summed["anonymous_leaves"],
                serde_json::json!({"root_declined": 6, "root_unavailable_busy": 2})
            );
            let table = render_table(&aggregate, 10);
            assert!(
                table.contains("anonymous leaves: root_declined: 6, root_unavailable_busy: 2"),
                "{table}"
            );
        }
        // Every variant is named once, in ordinal order.
        for (index, why) in AnonymousLeave::ALL.into_iter().enumerate() {
            assert_eq!(why as usize, index);
        }
        let names: std::collections::BTreeSet<_> =
            AnonymousLeave::ALL.map(AnonymousLeave::name).into();
        assert_eq!(names.len(), AnonymousLeave::COUNT);
    }

    #[test]
    fn aggregate_sums_by_number_and_ranks_by_host_cpu() {
        let a = census(vec![row(56, 10, 1_000), row(79, 5, 9_000)]);
        let b = census(vec![row(56, 10, 2_000)]);
        let agg = aggregate(&[a, b]).unwrap();
        assert_eq!(agg.runs, 2);
        assert_eq!(agg.host_total_ns, 12_000);
        assert_eq!(agg.process_cpu_ns, 48_000);
        assert_eq!(agg.rows[0].nr, 79);
        assert_eq!(agg.rows[1].nr, 56);
        assert_eq!(agg.rows[1].host_services, 20);
        assert_eq!(agg.rows[1].host_cpu_ns, 3_000);
        let table = render_table(&agg, 10);
        assert!(table.contains("| s79 | 79 | 5 | 0.0 | 75.0% |"), "{table}");
    }

    #[test]
    fn summarize_names_the_top_class_and_the_syscall_share() {
        let summary = summarize(&census(vec![row(56, 10, 1_000), row(79, 5, 9_000)]));
        assert_eq!(summary.host_syscall_ns, 10_000);
        assert_eq!(summary.top_class, Some(("s79".to_owned(), 9_000)));
        assert_eq!(summary.syscall_share(), Some(10_000.0 * 100.0 / 24_000.0));
    }

    #[test]
    fn aggregate_fails_closed_on_empty_or_unknown_input() {
        assert!(aggregate(&[]).is_err());
        assert!(aggregate(&[census(vec![])]).is_err());
        let mut odd = census(vec![row(1, 1, 1)]);
        odd.schema = 3;
        assert!(aggregate(&[odd]).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod launch_identity_tests {
    #[test]
    fn snapshot_uses_the_supplied_launch_identity() {
        let alpha = carrick_kernel::kernel::CarrierScopeId::new("alpha").expect("alpha scope");
        let beta = carrick_kernel::kernel::CarrierScopeId::new("beta").expect("beta scope");
        assert_eq!(
            super::snapshot(Some(&alpha)).run_id.as_deref(),
            Some("alpha")
        );
        assert_eq!(super::snapshot(Some(&beta)).run_id.as_deref(), Some("beta"));
        assert_eq!(super::snapshot(None).run_id, None);
    }
}
