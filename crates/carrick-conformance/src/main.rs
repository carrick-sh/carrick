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
mod manifest;
mod matrix;
mod parsers;
mod verdict;

use crate::manifest::{Manifest, Suite, Tier, Weight};
use crate::verdict::{Baseline, SideSummary, SuiteReport, Verdict, classify};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    #[arg(long, default_value = "target/release/carrick")]
    carrick_bin: PathBuf,
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
            let c = engine::carrick_dry_run(s, &args.carrick_bin.to_string_lossy());
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
    let n = selected.len();
    let workers = std::thread::available_parallelism()
        .map(|c| c.get().saturating_sub(2).clamp(1, 8))
        .unwrap_or(4);
    let heavy = Mutex::new(());

    // ---- Phase 1: ALL carrick (weight-aware; never overlapping docker). ----
    eprintln!("phase 1/3: {n} carrick runs (workers={workers})");
    let carrick_outs = fan_out(n, workers, |i| {
        let s = &selected[i];
        let _g =
            (s.weight == Weight::Heavy).then(|| heavy.lock().unwrap_or_else(|e| e.into_inner()));
        // Zero-pad the index so no run-id is a prefix of another (c01 vs c10);
        // kill.sh anchors on the proctitle "carrick:<id>:" delimiter too, but a
        // collision-free id is defense in depth against any unanchored grep.
        let run_id = format!("conf-{pid}-c{i:02}");
        let out = engine::run_carrick(s, &carrick_bin, &run_id);
        eprintln!("  [carrick] {}", s.name);
        out
    });

    // ---- Phase 2: ALL docker, strictly after phase 1. ----
    eprintln!("phase 2/3: {n} docker runs (workers={workers})");
    let docker_outs = fan_out(n, workers, |i| {
        let s = &selected[i];
        let _g =
            (s.weight == Weight::Heavy).then(|| heavy.lock().unwrap_or_else(|e| e.into_inner()));
        let run_id = format!("conf-{pid}-d{i:02}");
        let out = engine::run_docker(s, &run_id);
        eprintln!("  [docker]  {}", s.name);
        out
    });

    // ---- Phase 3: classify (runs neither engine). ----
    eprintln!("phase 3/3: classify");
    let mut reports = Vec::with_capacity(n);
    for ((s, cout), dout) in selected.iter().zip(&carrick_outs).zip(&docker_outs) {
        let cout = cout.as_ref().and_then(|r| r.as_ref().ok());
        let dout = dout.as_ref().and_then(|r| r.as_ref().ok());
        reports.push(build_report(s, cout, dout, &baseline));
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

fn build_report(
    s: &Suite,
    cout: Option<&engine::RunOutput>,
    dout: Option<&engine::RunOutput>,
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
    let (d_raw, d_runid, d_argv) = match dout {
        Some(o) => (o.raw(), o.run_id.clone(), o.argv.clone()),
        None => (
            parsers::Raw {
                stdout: String::new(),
                stderr: "docker run failed to spawn".into(),
                exit_code: -1,
                timed_out: false,
            },
            String::new(),
            vec![],
        ),
    };

    let c_res = parsers::parse(verdict_kind(s), &c_raw);
    let d_res = parsers::parse(verdict_kind(s), &d_raw);
    let cl = classify(s, &c_res, c_timed, &d_res, baseline);

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
            totals: d_res.totals,
        },
        new_diffs: cl.new_diffs,
        known_diffs: cl.known_diffs,
        carrick_run_id: c_runid,
        docker_run_id: d_runid,
        carrick_argv: c_argv,
        docker_argv: d_argv,
        pairs: cl.pairs,
    }
}

fn verdict_kind(s: &Suite) -> manifest::VerdictKind {
    s.verdict
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
