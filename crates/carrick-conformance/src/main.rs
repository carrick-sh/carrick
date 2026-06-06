//! `carrick-conformance` — the unified differential conformance harness.
//!
//! Runs each suite in `scripts/conformance/suites.toml` under `carrick run` AND
//! `docker run` (the Linux oracle), parses both with a per-ecosystem verdict
//! parser, classifies the diff against a committed baseline, writes per-suite
//! JSONL, and (on `--bless`/`--render-matrix`) renders the canonical
//! `docs/support-matrix.md`. A pure orchestrator — it links none of the guest
//! stack; it shells out to the signed `carrick` binary and the `docker` CLI.
//!
//! Design contract: docs/superpowers/specs/2026-06-03-conformance-harness-design.md.
//! Invariants: identical trailing argv to both engines; carrick‖docker never
//! overlap (two-phase); every kill is SCOPED to one run-id (no unscoped reap).

mod engine;
mod generate;
mod images;
mod manifest;
mod matrix;
mod oracle;
mod parsers;
mod verdict;

use crate::manifest::{Ecosystem, Manifest, Suite, Tier, Weight};
use crate::verdict::{Baseline, SideSummary, SuiteReport, Verdict, classify};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// Runtime crates whose change should out-date the signed binary (the soft
/// freshness backstop — §4.5). Deliberately NOT all of `crates/`.
const RUNTIME_CRATES: &[&str] = &[
    "carrick-runtime",
    "carrick-hvf",
    "carrick-host",
    "carrick-abi",
    "carrick-mem",
    "carrick-guest-mem",
    "carrick-cli",
];

#[derive(Parser, Debug)]
#[command(about = "Differential conformance harness (carrick vs docker)")]
struct Args {
    /// Which tier to run: `smoke` (fast gate) or `full` (everything).
    #[arg(long, default_value = "full")]
    tier: String,
    /// Filter to these ecosystems (repeatable): cpython|go|node|ltp.
    #[arg(long)]
    ecosystem: Vec<String>,
    /// Filter to these suite names (repeatable).
    #[arg(long)]
    suite: Vec<String>,
    #[arg(long, default_value = "scripts/conformance/suites.toml")]
    manifest: PathBuf,
    #[arg(long, default_value = "scripts/conformance/baseline.jsonl")]
    baseline: PathBuf,
    #[arg(long, default_value = "target/conformance/results.jsonl")]
    jsonl: PathBuf,
    /// Rewrite baseline.jsonl + support-matrix.md from this run (guarded).
    #[arg(long)]
    bless: bool,
    /// Render docs/support-matrix.md from the latest results.jsonl and exit.
    #[arg(long)]
    render_matrix: bool,
    /// Print the planned carrick + docker argv for each suite, run nothing.
    #[arg(long)]
    dry_run: bool,
    /// Regenerate the manifest (suites.toml) for full coverage by enumerating
    /// every module per ecosystem via docker, then exit. With --dry-run, print
    /// counts only and do not write.
    #[arg(long)]
    generate_suites: bool,
    /// Total suite worker threads. Defaults to host parallelism minus two,
    /// capped at eight for unattended runs; explicit values are honored.
    #[arg(long, env = "CARRICK_CONFORMANCE_WORKERS")]
    workers: Option<usize>,
    /// Maximum concurrent CPython suites marked `weight = "heavy"`. Defaults
    /// to min(workers, 4); other heavy ecosystems remain serialized.
    #[arg(long, env = "CARRICK_CONFORMANCE_CPYTHON_WORKERS")]
    cpython_workers: Option<usize>,
    #[arg(long, default_value = "target/release/carrick")]
    carrick_bin: PathBuf,
    /// Committed docker-oracle cache (parsed results, one JSONL line per suite).
    /// Docker is run only for suites whose determinant key is absent here — so a
    /// routine gate executes ONLY carrick and diffs against the cached oracle.
    #[arg(long, default_value = "scripts/conformance/oracle-cache.jsonl")]
    oracle_cache: PathBuf,
    /// Ignore the oracle cache: re-run docker for every selected suite and
    /// overwrite their cached results (use after rebuilding an image's contents).
    #[arg(long)]
    refresh_oracle: bool,
    /// Skip the pre-run image-freshness guard (which re-pulls carrick's copy of
    /// any image whose registry digest moved, so carrick and docker run the same
    /// bytes). Use offline or when you deliberately want carrick's cached image.
    #[arg(long)]
    no_image_refresh: bool,
    /// Seed the oracle cache from a completed gate's results.jsonl (reconstructs
    /// each suite's docker side from its recorded per-id pairs) and exit —
    /// capturing a finished run's docker work without re-running any container.
    #[arg(long)]
    seed_oracle: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("carrick-conformance: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let args = Args::parse();

    if args.render_matrix {
        let reports = read_reports(&args.jsonl)?;
        let md = matrix::render(&reports);
        write_matrix(&md)?;
        eprintln!(
            "rendered docs/support-matrix.md from {}",
            args.jsonl.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    if args.generate_suites {
        generate::generate_suites(&args.manifest, args.dry_run)?;
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(results) = &args.seed_oracle {
        seed_oracle(&args.manifest, results, &args.oracle_cache)?;
        return Ok(ExitCode::SUCCESS);
    }

    let manifest = Manifest::from_toml(&std::fs::read_to_string(&args.manifest)?)?;
    let errs = manifest.validate();
    if !errs.is_empty() {
        for e in &errs {
            eprintln!("manifest error: {e}");
        }
        anyhow::bail!("{} manifest validation error(s)", errs.len());
    }

    let tier = parse_tier(&args.tier)?;
    let selected = select(&manifest.suite, tier, &args.ecosystem, &args.suite);
    if selected.is_empty() {
        eprintln!("no suites match the selection");
        return Ok(ExitCode::SUCCESS);
    }

    if args.dry_run {
        for s in &selected {
            let c = engine::carrick_dry_run(
                s,
                &args.carrick_bin.to_string_lossy(),
                &format!("conf-{}-cN", std::process::id()),
            );
            let d = engine::docker_dry_run(s, &format!("conf-{}-dN", std::process::id()));
            println!("# {} [{}, {:?}]", s.name, s.ecosystem.as_str(), s.tier);
            println!("  carrick: {}", c.join(" "));
            println!("  docker:  {}", d.join(" "));
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Binary preflight (abort on unsigned/missing; warn on stale).
    preflight(&args.carrick_bin)?;

    let baseline = load_baseline(&args.baseline);

    let pid = std::process::id();
    let carrick_bin = args.carrick_bin.to_string_lossy().into_owned();

    // Image-freshness guard: re-pull carrick's copy of any selected image whose
    // registry digest moved, SERIALLY before the parallel carrick phase, so
    // carrick and docker run identical bytes (see images.rs). Skipped on request.
    if !args.no_image_refresh {
        let imgs: Vec<String> = selected.iter().map(|s| s.image.clone()).collect();
        let refreshed = images::refresh_stale_images(&imgs, &carrick_bin);
        if refreshed > 0 {
            eprintln!("image-guard: re-pulled {refreshed} stale image(s)");
        }
    }

    let n = selected.len();
    let workers = worker_count(args.workers);
    let cpython_workers = cpython_worker_count(args.cpython_workers, workers);
    let lanes = SchedulerLanes::new(cpython_workers);

    // ---- Phase 1: ALL carrick (weight-aware; never overlapping docker). ----
    eprintln!("phase 1/3: {n} carrick runs (workers={workers}, cpython-workers={cpython_workers})");
    let carrick_outs = fan_out(n, workers, |i| {
        let s = &selected[i];
        let _lane = lanes.acquire(s);
        // Zero-pad the index so no run-id is a prefix of another (c01 vs c10);
        // kill.sh anchors on the proctitle "carrick:<id>:" delimiter too, but a
        // collision-free id is defense in depth against any unanchored grep.
        let run_id = format!("conf-{pid}-c{i:02}");
        let out = engine::run_carrick(s, &carrick_bin, &run_id);
        eprintln!("  [carrick] {}", s.name);
        out
    });

    // ---- Phase 2: docker — but ONLY for suites whose oracle is not already
    // cached. The docker oracle for a deterministic suite is stable, so it needs
    // to run once, ever; a cached suite contributes its committed result and
    // runs no container. Strictly after phase 1 (carrick ‖ docker never overlap).
    let mut cache = oracle::OracleCache::load(&args.oracle_cache);
    let cached: Vec<Option<parsers::SuiteResult>> = if args.refresh_oracle {
        vec![None; n]
    } else {
        selected.iter().map(|s| cache.get(s)).collect()
    };
    let need_docker: Vec<usize> = (0..n).filter(|&i| cached[i].is_none()).collect();
    eprintln!(
        "phase 2/3: {} docker run(s), {} cached oracle(s){} (workers={workers}, cpython-workers={cpython_workers})",
        need_docker.len(),
        n - need_docker.len(),
        if args.refresh_oracle {
            " [--refresh-oracle]"
        } else {
            ""
        },
    );
    let fresh_outs = fan_out(need_docker.len(), workers, |j| {
        let i = need_docker[j];
        let s = &selected[i];
        let _lane = lanes.acquire(s);
        let run_id = format!("conf-{pid}-d{i:02}");
        let out = engine::run_docker(s, &run_id);
        eprintln!("  [docker]  {}", s.name);
        out
    });

    // Parse fresh docker runs, fold comparable ones into the cache, key them back
    // by suite index for phase 3.
    let mut fresh: std::collections::BTreeMap<usize, DockerSide> =
        std::collections::BTreeMap::new();
    for (j, out) in fresh_outs.into_iter().enumerate() {
        let i = need_docker[j];
        let s = &selected[i];
        let side = match out.and_then(|r| r.ok()) {
            Some(o) => {
                let res = parsers::parse(verdict_kind(s), &o.raw());
                cache.insert(s, res.clone()); // refuses to cache a non-comparable oracle
                DockerSide {
                    result: res,
                    run_id: o.run_id,
                    argv: o.argv,
                }
            }
            None => DockerSide {
                result: parsers::SuiteResult::empty(),
                run_id: String::new(),
                argv: engine::docker_dry_run(s, "spawn-failed"),
            },
        };
        fresh.insert(i, side);
    }
    if cache.dirty() {
        cache.save()?;
        eprintln!(
            "oracle cache: updated {} ({} new)",
            args.oracle_cache.display(),
            need_docker.len()
        );
    }

    // ---- Phase 3: classify (runs neither engine). ----
    eprintln!("phase 3/3: classify");
    let mut reports = Vec::with_capacity(n);
    for (i, (s, cout)) in selected.iter().zip(&carrick_outs).enumerate() {
        let cout = cout.as_ref().and_then(|r| r.as_ref().ok());
        let docker = match &cached[i] {
            Some(res) => DockerSide {
                result: res.clone(),
                run_id: "<cached>".to_string(),
                argv: engine::docker_dry_run(s, "<cached>"),
            },
            None => fresh
                .remove(&i)
                .expect("every non-cached suite has a fresh docker side"),
        };
        reports.push(build_report(s, cout, &docker, &baseline));
    }

    write_reports(&args.jsonl, &reports)?;
    print_summary(&reports);

    let gating = reports.iter().filter(|r| r.gating).count();

    if args.bless {
        bless(&args, &selected, tier, &reports)?;
    }

    if gating > 0 {
        eprintln!("\nFAIL: {gating} gating verdict(s) (REGRESSION / unexcused CRASH or TIMEOUT)");
        Ok(ExitCode::from(1))
    } else {
        eprintln!("\nOK: no regressions");
        Ok(ExitCode::SUCCESS)
    }
}

/// The docker (oracle) side of one suite, already parsed — sourced either from a
/// fresh `docker run` or the committed oracle cache (so phase 3 is agnostic to
/// which).
struct DockerSide {
    result: parsers::SuiteResult,
    run_id: String,
    argv: Vec<String>,
}

fn build_report(
    s: &Suite,
    cout: Option<&engine::RunOutput>,
    docker: &DockerSide,
    baseline: &Baseline,
) -> SuiteReport {
    let (c_raw, c_timed, c_runid, c_argv) = match cout {
        Some(o) => (o.raw(), o.timed_out, o.run_id.clone(), o.argv.clone()),
        None => (
            parsers::Raw {
                stdout: String::new(),
                stderr: "carrick run failed to spawn".into(),
                exit_code: -1,
                timed_out: false,
            },
            false,
            String::new(),
            vec![],
        ),
    };

    let c_res = parsers::parse(verdict_kind(s), &c_raw);
    let d_res = &docker.result;
    let cl = classify(s, &c_res, c_timed, d_res, baseline);

    SuiteReport {
        name: s.name.clone(),
        ecosystem: s.ecosystem.as_str().to_string(),
        tier: tier_str(s.tier).to_string(),
        verdict: cl.verdict,
        gating: cl.gating,
        carrick: SideSummary {
            result: c_res.result,
            totals: c_res.totals,
        },
        docker: SideSummary {
            result: d_res.result,
            totals: d_res.totals.clone(),
        },
        new_diffs: cl.new_diffs,
        known_diffs: cl.known_diffs,
        carrick_run_id: c_runid,
        docker_run_id: docker.run_id.clone(),
        carrick_argv: c_argv,
        docker_argv: docker.argv.clone(),
        pairs: cl.pairs,
    }
}

fn verdict_kind(s: &Suite) -> manifest::VerdictKind {
    s.verdict
}

/// Import a completed gate's docker side into the oracle cache, reconstructing
/// each suite's docker `SuiteResult` from the per-id pairs recorded in
/// `results.jsonl` — so the (expensive) docker work of a finished run is captured
/// without re-running a single container. Suites whose report has no comparable
/// docker data (crash/timeout/oracle-fail) are skipped: they must be re-run.
fn seed_oracle(manifest_path: &Path, results: &Path, cache_path: &Path) -> anyhow::Result<()> {
    // Operator-controlled CLI paths in a local dev tool — same trust model as the
    // other IO helpers below; not untrusted/network input.
    let manifest = Manifest::from_toml(&std::fs::read_to_string(manifest_path)?)?; // nosemgrep
    let by_name: std::collections::HashMap<&str, &Suite> = manifest
        .suite
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let reports = read_reports(results)?;
    let mut cache = oracle::OracleCache::load(cache_path);
    let (mut seeded, mut skipped, mut unknown) = (0usize, 0usize, 0usize);
    for r in &reports {
        let Some(s) = by_name.get(r.name.as_str()) else {
            unknown += 1;
            continue;
        };
        match oracle::docker_result_from_report(r) {
            Some(res) => {
                if cache.insert(s, res) {
                    seeded += 1;
                } else {
                    skipped += 1;
                }
            }
            None => skipped += 1,
        }
    }
    cache.save()?;
    eprintln!(
        "seeded {seeded} oracle(s) into {} from {} ({skipped} non-comparable skipped, {unknown} not in manifest)",
        cache_path.display(),
        results.display(),
    );
    Ok(())
}

fn bless(
    args: &Args,
    selected: &[Suite],
    tier: Tier,
    reports: &[SuiteReport],
) -> anyhow::Result<()> {
    if tier != Tier::Full || !args.ecosystem.is_empty() || !args.suite.is_empty() {
        anyhow::bail!(
            "--bless requires a full-tier, unfiltered run (no --tier smoke / --ecosystem / --suite)"
        );
    }
    let bad: Vec<&str> = reports
        .iter()
        .filter(|r| {
            matches!(
                r.verdict,
                Verdict::OracleFail | Verdict::Timeout | Verdict::CarrickCrash
            )
        })
        .map(|r| r.name.as_str())
        .collect();
    if !bad.is_empty() {
        anyhow::bail!(
            "--bless refused: resolve or known_gap-annotate these ORACLE_FAIL/TIMEOUT/CARRICK_CRASH suites first: {}",
            bad.join(", ")
        );
    }
    let _ = selected; // (kept for symmetry / future per-suite bless)
    write_reports(&args.baseline, reports)?;
    let md = matrix::render(reports);
    write_matrix(&md)?;
    eprintln!(
        "blessed: wrote {} and docs/support-matrix.md",
        args.baseline.display()
    );
    Ok(())
}

/// Hand-rolled work-stealing pool (std only; mirrors conformance.rs::fan_out_indexed
/// but returns Option<T> to stay clear of the no-panic gate). Each `f(i)` may
/// acquire the shared heavy-lock itself to serialize heavy suites within a phase.
fn fan_out<T: Send>(n: usize, workers: usize, f: impl Fn(usize) -> T + Sync) -> Vec<Option<T>> {
    let slots: Vec<Mutex<Option<T>>> = (0..n).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    let v = f(i);
                    *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
        .collect()
}

fn worker_count(configured: Option<usize>) -> usize {
    configured.unwrap_or_else(default_worker_count).max(1)
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|c| c.get().saturating_sub(2).clamp(1, 8))
        .unwrap_or(4)
}

fn cpython_worker_count(configured: Option<usize>, workers: usize) -> usize {
    configured
        .unwrap_or_else(|| workers.clamp(1, 4))
        .min(workers.max(1))
}

struct SchedulerLanes {
    generic_heavy: Semaphore,
    cpython_heavy: Semaphore,
}

impl SchedulerLanes {
    fn new(cpython_workers: usize) -> Self {
        Self {
            generic_heavy: Semaphore::new(1),
            cpython_heavy: Semaphore::new(cpython_workers.max(1)),
        }
    }

    fn acquire(&self, suite: &Suite) -> Option<SchedulerPermit<'_>> {
        if suite.weight != Weight::Heavy {
            return None;
        }
        let semaphore = if suite.ecosystem == Ecosystem::Cpython {
            &self.cpython_heavy
        } else {
            &self.generic_heavy
        };
        Some(SchedulerPermit {
            _permit: semaphore.acquire(),
        })
    }
}

struct SchedulerPermit<'a> {
    _permit: SemaphorePermit<'a>,
}

struct Semaphore {
    max: usize,
    active: Mutex<usize>,
    changed: Condvar,
}

impl Semaphore {
    fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            active: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    fn acquire(&self) -> SemaphorePermit<'_> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        while *active >= self.max {
            active = self.changed.wait(active).unwrap_or_else(|e| e.into_inner());
        }
        *active += 1;
        SemaphorePermit { semaphore: self }
    }

    fn release(&self) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        *active = active.saturating_sub(1);
        self.changed.notify_one();
    }
}

struct SemaphorePermit<'a> {
    semaphore: &'a Semaphore,
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        self.semaphore.release();
    }
}

fn select(suites: &[Suite], tier: Tier, ecos: &[String], names: &[String]) -> Vec<Suite> {
    suites
        .iter()
        .filter(|s| tier == Tier::Full || s.tier == Tier::Smoke)
        .filter(|s| ecos.is_empty() || ecos.iter().any(|e| e == s.ecosystem.as_str()))
        .filter(|s| names.is_empty() || names.iter().any(|nm| nm == &s.name))
        .cloned()
        .collect()
}

fn parse_tier(s: &str) -> anyhow::Result<Tier> {
    match s {
        "smoke" => Ok(Tier::Smoke),
        "full" => Ok(Tier::Full),
        other => anyhow::bail!("--tier must be smoke|full, got {other:?}"),
    }
}

fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Smoke => "smoke",
        Tier::Full => "full",
    }
}

fn print_summary(reports: &[SuiteReport]) {
    eprintln!("\n=== summary ===");
    for r in reports {
        let mark = if r.gating { "FAIL" } else { "ok  " };
        eprintln!(
            "  {mark} {:14} {:40} carrick[{}] oracle[{}]",
            r.verdict.as_str(),
            r.name,
            side(&r.carrick),
            side(&r.docker),
        );
    }
}

fn side(s: &SideSummary) -> String {
    if s.totals.n > 0 {
        format!("{}/{}", s.totals.passed, s.totals.n)
    } else {
        format!("{:?}", s.result)
    }
}

// ---- IO helpers ----
//
// Every path here comes from a CLI flag (operator-controlled, in a local dev
// tool) — not untrusted/network input — and reading/writing result files at
// operator-chosen locations IS the harness's job. The `// nosemgrep` markers
// acknowledge the path-traversal rule as a false positive in this context.

fn read_reports(path: &Path) -> anyhow::Result<Vec<SuiteReport>> {
    let text =
        std::fs::read_to_string(path) // nosemgrep
            .map_err(|e| {
                anyhow::anyhow!("cannot read {} ({e}) — run a pass first", path.display())
            })?;
    let mut v = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            v.push(serde_json::from_str::<SuiteReport>(line)?);
        }
    }
    Ok(v)
}

fn write_reports(path: &Path, reports: &[SuiteReport]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?; // nosemgrep
    }
    let mut s = String::new();
    for r in reports {
        s.push_str(&serde_json::to_string(r)?);
        s.push('\n');
    }
    std::fs::write(path, s)?; // nosemgrep
    Ok(())
}

fn write_matrix(md: &str) -> anyhow::Result<()> {
    std::fs::write("docs/support-matrix.md", md)?; // nosemgrep
    Ok(())
}

fn load_baseline(path: &Path) -> Baseline {
    match std::fs::read_to_string(path) {
        // nosemgrep
        Ok(t) => Baseline::from_jsonl(&t),
        Err(_) => Baseline::default(), // absent -> first run, everything NEW
    }
}

// ---- binary preflight (§4.5) ----

fn preflight(bin: &Path) -> anyhow::Result<()> {
    let meta = match std::fs::metadata(bin) {
        Ok(m) => m,
        Err(_) => anyhow::bail!(
            "{} is missing — run `just build` (./scripts/build-signed.sh) first",
            bin.display()
        ),
    };
    // Signed-binary check: an unsigned binary makes every guest run HV_DENIED.
    let signed = Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
        .map(|o| {
            let s = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            s.contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false);
    if !signed {
        anyhow::bail!(
            "{} is not signed with com.apple.security.hypervisor — run `just build` \
             (cargo build strips the entitlement; every guest run would be HV_DENIED)",
            bin.display()
        );
    }
    // Soft freshness backstop: WARN (never abort) if the binary looks older than
    // the newest runtime-crate source. Incremental cargo legitimately leaves an
    // unchanged artifact's mtime, so a strict abort would false-fire; warn only.
    if let (Ok(bin_t), Some(src_t)) = (meta.modified(), newest_runtime_src_mtime())
        && bin_t < src_t
    {
        eprintln!(
            "WARNING: {} looks STALE (older than a runtime-crate source) — \
             run `just build` to be sure you are testing HEAD. Continuing.",
            bin.display()
        );
    }
    Ok(())
}

fn newest_runtime_src_mtime() -> Option<std::time::SystemTime> {
    let mut newest: Option<std::time::SystemTime> = None;
    for c in RUNTIME_CRATES {
        walk_newest(&PathBuf::from("crates").join(c).join("src"), &mut newest);
    }
    newest
}

fn walk_newest(dir: &Path, newest: &mut Option<std::time::SystemTime>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_newest(&p, newest);
        } else if p.extension().is_some_and(|x| x == "rs")
            && let Ok(t) = e.metadata().and_then(|m| m.modified())
            && newest.is_none_or(|n| t > n)
        {
            *newest = Some(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn args_accept_explicit_worker_controls() {
        let args = Args::try_parse_from([
            "carrick-conformance",
            "--workers",
            "6",
            "--cpython-workers",
            "3",
        ])
        .expect("worker controls should parse");

        assert_eq!(args.workers, Some(6));
        assert_eq!(args.cpython_workers, Some(3));
    }

    #[test]
    fn explicit_worker_count_is_not_auto_clamped() {
        assert_eq!(worker_count(Some(12)), 12);
    }

    #[test]
    fn cpython_workers_default_to_bounded_worker_subset() {
        assert_eq!(cpython_worker_count(None, 2), 2);
        assert_eq!(cpython_worker_count(None, 8), 4);
        assert_eq!(cpython_worker_count(Some(9), 4), 4);
    }

    #[test]
    fn cpython_heavy_suites_use_bounded_parallel_lanes() {
        let lanes = SchedulerLanes::new(2);
        let suites: Vec<Suite> = (0..4)
            .map(|i| suite(&format!("cpython-{i}"), Ecosystem::Cpython, Weight::Heavy))
            .collect();

        assert_eq!(max_observed_concurrency(&suites, &lanes, 4), 2);
    }

    #[test]
    fn non_cpython_heavy_suites_remain_serialized() {
        let lanes = SchedulerLanes::new(4);
        let suites: Vec<Suite> = (0..4)
            .map(|i| suite(&format!("go-{i}"), Ecosystem::Go, Weight::Heavy))
            .collect();

        assert_eq!(max_observed_concurrency(&suites, &lanes, 4), 1);
    }

    fn max_observed_concurrency(suites: &[Suite], lanes: &SchedulerLanes, workers: usize) -> usize {
        let active = AtomicUsize::new(0);
        let max_active = AtomicUsize::new(0);

        let _ = fan_out(suites.len(), workers, |i| {
            let _lane = lanes.acquire(&suites[i]);
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            active.fetch_sub(1, Ordering::SeqCst);
        });

        max_active.load(Ordering::SeqCst)
    }

    fn suite(name: &str, ecosystem: Ecosystem, weight: Weight) -> Suite {
        Suite {
            name: name.to_string(),
            ecosystem,
            image: "localhost:5050/test:latest".to_string(),
            cmd: vec!["/bin/true".to_string()],
            verdict: crate::manifest::VerdictKind::Shell,
            tier: Tier::Full,
            weight,
            timeout_s: 1,
            known_gaps: Vec::new(),
            carrick_flags: Vec::new(),
            docker_flags: Vec::new(),
            bind_mounts: Vec::new(),
            env: Vec::new(),
            env_carrick: Vec::new(),
            env_docker: Vec::new(),
            workdir: None,
            entrypoint: None,
        }
    }
}
