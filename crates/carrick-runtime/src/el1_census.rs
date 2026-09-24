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
//!   host to deliver pending work.
//!
//! Enabled by `CARRICK_EL1_CENSUS=<directory>`; the carrier writes
//! `<directory>/<CARRICK_RUN_ID or "run">-<pid>.json` at teardown, while the
//! EL1 region is still mapped. Disabled, each hook costs one relaxed load.
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
static WRITTEN: AtomicBool = AtomicBool::new(false);

/// Read the environment once; later calls are one relaxed load.
pub fn init_from_env() {
    let directory = DIRECTORY.get_or_init(|| {
        std::env::var_os("CARRICK_EL1_CENSUS")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
    });
    ENABLED.store(directory.is_some(), Ordering::Relaxed);
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
    pub host_services: u64,
    pub host_cpu_ns: u64,
    pub redispatches: u64,
    pub redispatch_cpu_ns: u64,
    pub el1_boundaries: u64,
}

/// The census of one carrier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Census {
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
    /// Wall time from EL1 setup to teardown.
    #[serde(default)]
    pub wall_ns: u64,
    pub rows: Vec<CensusRow>,
}

fn snapshot() -> Census {
    let counters = crate::read_el1_counters();
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
            host_services: TABLE.host_services[index].load(Ordering::Relaxed),
            host_cpu_ns: TABLE.host_cpu_ns[index].load(Ordering::Relaxed),
            redispatches: TABLE.redispatches[index].load(Ordering::Relaxed),
            redispatch_cpu_ns: TABLE.redispatch_cpu_ns[index].load(Ordering::Relaxed),
            el1_boundaries: TABLE.el1_boundaries[index].load(Ordering::Relaxed),
        };
        if row.el1_served
            + row.el1_forwarded
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
        schema: 1,
        run_id: std::env::var("CARRICK_RUN_ID").ok(),
        pid: std::process::id(),
        el1_counters: counters.is_some(),
        process_user_ns,
        process_sys_ns,
        wall_ns: STARTED
            .get()
            .map_or(0, |start| start.elapsed().as_nanos() as u64),
        rows,
    }
}

/// Write the census once, at carrier teardown while the EL1 region is still
/// mapped. A failure to write is reported, never silently dropped.
pub fn write_at_teardown() {
    let Some(Some(directory)) = DIRECTORY.get() else {
        return;
    };
    if WRITTEN.swap(true, Ordering::AcqRel) {
        return;
    }
    let census = snapshot();
    let name = format!(
        "{}-{}.json",
        census.run_id.as_deref().unwrap_or("run"),
        census.pid
    );
    let path = directory.join(name);
    let result = std::fs::create_dir_all(directory).and_then(|()| {
        let body = serde_json::to_vec_pretty(&census).map_err(std::io::Error::other)?;
        std::fs::write(&path, body)
    });
    if let Err(error) = result {
        tracing::error!(path = %path.display(), %error, "EL1 census write failed");
        eprintln!(
            "carrick: EL1 census write to {} failed: {error}",
            path.display()
        );
    }
}

/// One syscall class summed over several censuses.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct AggregateRow {
    pub nr: u64,
    pub name: String,
    pub el1_served: u64,
    pub el1_forwarded: u64,
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
    pub rows: Vec<AggregateRow>,
}

/// Sum censuses by syscall number and rank by host CPU. Fails closed on an
/// empty input or an unknown schema.
pub fn aggregate(censuses: &[Census]) -> Result<Aggregate, String> {
    if censuses.is_empty() {
        return Err("no census inputs".to_owned());
    }
    let mut by_nr: std::collections::BTreeMap<u64, AggregateRow> = Default::default();
    for census in censuses {
        if census.schema != 1 {
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
    out.push_str("| syscall | nr | host services | host CPU ms | share | redispatches | EL1 served | EL1 forwarded | EL1 boundaries |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in aggregate.rows.iter().take(limit) {
        let share = if aggregate.host_total_ns == 0 {
            0.0
        } else {
            row.host_total_ns() as f64 * 100.0 / aggregate.host_total_ns as f64
        };
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {:.1}% | {} | {} | {} | {} |\n",
            row.name,
            row.nr,
            row.host_services,
            row.host_total_ns() as f64 / 1e6,
            share,
            row.redispatches,
            row.el1_served,
            row.el1_forwarded,
            row.el1_boundaries
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
            host_services: services,
            host_cpu_ns: cpu,
            redispatches: 0,
            redispatch_cpu_ns: 0,
            el1_boundaries: 0,
        }
    }

    fn census(rows: Vec<CensusRow>) -> Census {
        Census {
            schema: 1,
            run_id: None,
            pid: 1,
            el1_counters: true,
            process_user_ns: 20_000,
            process_sys_ns: 4_000,
            wall_ns: 30_000,
            rows,
        }
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
        odd.schema = 2;
        assert!(aggregate(&[odd]).is_err());
    }
}
