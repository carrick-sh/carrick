//! `carrick-conformance` — the unified differential conformance harness.
//!
//! Runs each suite in `scripts/conformance/suites.toml` under `carrick run` AND
//! `docker run` (the Linux oracle), parses both with a per-ecosystem verdict
//! parser, classifies the diff against a committed baseline, writes per-suite
//! JSONL, and (on `--bless`/`--render-matrix`) renders the canonical
//! `docs/support-matrix.md`. A pure orchestrator — it links none of the guest
//! stack; it shells out to the signed `carrick` binary and the `docker` CLI.
//!
//! Invariants: identical trailing argv to both engines; carrick‖docker never
//! overlap (two-phase); every kill is SCOPED to one run-id (no unscoped reap).

mod closure;
mod engine;
mod generate;
mod images;
mod lane;
mod manifest;
mod matrix;
mod oracle;
mod parsers;
mod verdict;

use crate::closure::{ClosurePolicy, validate_closure_reports};
use crate::manifest::{Ecosystem, Manifest, Suite, Tier, Weight};
use crate::verdict::{
    Baseline, PerfSummary, SideSummary, SuiteReport, Verdict, classify, classify_closure,
};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// Runtime crates whose change should out-date the signed binary (the soft
/// freshness backstop — §4.5). Deliberately NOT all of `crates/`.
const RUNTIME_CRATES: &[&str] = &[
    "carrick-runtime",
    "carrick-vmm-hvf",
    "carrick-vmm-kvm",
    "carrick-vmm-bhyve",
    "carrick-vmm-nvmm",
    "carrick-x86",
    "carrick-host",
    "carrick-host-bsd",
    "carrick-host-linux",
    "carrick-abi",
    "carrick-mem",
    "carrick-guest-mem",
    "carrick-cli",
];

const DEFAULT_MAX_GATING: usize = 50;
const PERF_WARN_RATIO: f64 = 10.0;
const PERF_CRITICAL_RATIO: f64 = 100.0;

#[derive(Parser, Debug)]
#[command(about = "Differential conformance harness (carrick vs docker)")]
struct Args {
    /// Which tier to run: `smoke` (fast gate) or `full` (everything).
    #[arg(long, default_value = "full")]
    tier: String,
    /// Run the strict, baseline-free closure gate: full unfiltered HVF coverage
    /// with no retries or waivers, where every selected suite must MATCH.
    #[arg(long)]
    closure: bool,
    /// WHERE the carrick side runs — not which backend it uses; carrick has one
    /// (HVPatch) and no lane selects it. `hvf` (the local signed binary on this
    /// mac, the default, and the owner of the shared baseline), `kvm` (carrick
    /// in the lima guest), `kvm-local` (direct platform-linux carrick on this
    /// host), `bhyve-local` (direct platform-freebsd carrick on this host), or
    /// `nvmm-local` (direct platform-netbsd carrick on this host).
    #[arg(long, default_value = "hvf")]
    lane: String,
    /// lima VM name for `--lane kvm`.
    #[arg(long, default_value = "carrick", env = "LIMA_INSTANCE")]
    lima_vm: String,
    /// Host the lima guest resolves to the mac (for the conformance registry).
    #[arg(long, default_value = "host.lima.internal")]
    lima_gateway: String,
    /// Timeout multiplier for CARRICK runs on the kvm lane (docker oracles and
    /// the hvf lane keep the unscaled suite budget). Nested KVM roughly
    /// doubles toolchain-heavy suites — go-build straddles its 180 s budget at
    /// 1.0, which makes the gate flaky.
    #[arg(long, default_value_t = 2.0)]
    lima_timeout_scale: f64,
    /// Timeout multiplier for direct local x86_64 lanes (`kvm-local`,
    /// `bhyve-local`, `nvmm-local`). Defaults to 1.0: on same-host x86_64,
    /// Carrick should be close to Docker; a timeout is a bug signal, not
    /// expected nested overhead.
    #[arg(
        long,
        default_value_t = 1.0,
        env = "CARRICK_CONFORMANCE_LOCAL_TIMEOUT_SCALE"
    )]
    local_timeout_scale: f64,
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
    /// Additional baseline UNIONed onto `--baseline` before classification: a
    /// divergence is excused iff it matches the shared baseline OR this overlay.
    /// DEFAULT IS LANE-DERIVED (`baseline.<lane>.jsonl` next to `--baseline`):
    /// the kvm/bhyve/nvmm bring-up lanes each carry their OWN overlay (starts
    /// empty) so every lane-only divergence is a gap until proven environmental,
    /// and the mature hvf lane carries NO overlay (it IS the shared ground
    /// truth). Pass an explicit path to override the lane-derived default;
    /// absent/empty -> no-op.
    #[arg(long)]
    baseline_overlay: Option<PathBuf>,
    /// Where to write this run's per-suite results. Defaults to a path derived
    /// from lane/tier/filtering (see [`default_results_path`]) so a cheap run
    /// cannot destroy an expensive one's data.
    #[arg(long)]
    jsonl: Option<PathBuf>,
    /// Rewrite baseline.jsonl + support-matrix.md from this run (guarded).
    #[arg(long)]
    bless: bool,
    /// Render docs/support-matrix.md from the latest results.jsonl and exit.
    #[arg(long)]
    render_matrix: bool,
    /// Verify docs/support-matrix.md matches a fresh render of the checked-in
    /// `--baseline`, exiting non-zero if it has drifted. Writes nothing to disk.
    /// Deterministic and fast (no conformance run) — the `just ci` drift gate
    /// that keeps the committed matrix in sync with the blessed baseline.
    #[arg(long)]
    check_matrix: bool,
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
    /// Retry-on-flake: re-run each gating suite up to N times (carrick only,
    /// reusing the cached oracle), adopting the first non-gating attempt. This is
    /// opt-in for targeted flaky-suite investigations; a broad red gate should be
    /// triaged, not retried suite-by-suite. 0 disables.
    #[arg(long, default_value = "0", env = "CARRICK_CONFORMANCE_FLAKE_RETRIES")]
    flake_retries: usize,
    /// Abort once MORE than this many gating verdicts are observed. Cached
    /// oracle verdicts can stop phase 1 early; uncached/refresh runs check after
    /// classification. Use --force for an exhaustive run.
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_GATING,
        env = "CARRICK_CONFORMANCE_MAX_GATING"
    )]
    max_gating: usize,
    /// Force an exhaustive run even when the fail-fast threshold is exceeded.
    #[arg(long)]
    force: bool,
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
    /// Bless even though these suites TIMED OUT or CRASHED (repeatable).
    ///
    /// A timeout normally blocks a bless because there is no measured result to
    /// bless. This is the deliberate, named exception for a KNOWN hang that we
    /// are choosing to carry rather than let it hold the whole lane hostage.
    ///
    /// An allow-listed suite is NOT written to the baseline/overlay: recording
    /// its timeout as the expected verdict would make a future run's identical
    /// hang compare MATCH and silently stop gating. Leaving it unblessed means
    /// it keeps failing against the shared baseline until it is actually fixed,
    /// so every subsequent bless must name it again — the acknowledgement is
    /// explicit and repeated, never inherited silently.
    #[arg(long = "allow-hang", value_name = "SUITE")]
    allow_hang: Vec<String>,
    /// Bless from a COMPLETED run's results jsonl instead of re-running the gate.
    ///
    /// The bless is a pure function of a full run's reports, so a finished run
    /// should not have to be repeated (hours) just to record it. Every
    /// full-tier suite must be present in the file, otherwise a truncated or
    /// filtered run would silently bless a subset.
    #[arg(long, value_name = "PATH")]
    bless_from: Option<PathBuf>,
    /// Require every selected suite to have a cached oracle, and FAIL UP FRONT
    /// naming the misses instead of falling back to docker.
    ///
    /// For docker-less runners (a GitHub-hosted macOS runner has no Docker).
    /// There, a cache miss would otherwise surface as a confusing mid-run docker
    /// failure, or as a determinant-field change silently invalidating every key
    /// and triggering a full fresh docker pass. Failing early, naming the
    /// uncached suites, keeps the lane deterministic.
    #[arg(long)]
    require_cached_oracle: bool,
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

    if let Err(errors) = ClosurePolicy::validate_args(&args) {
        for error in errors {
            eprintln!("closure invocation error: {error}");
        }
        return Ok(ExitCode::from(2));
    }

    // A scale < 1.0 (or NaN/inf) silently shrinks every carrick deadline to ~0
    // via the f64->u64 cast — refuse it up front instead.
    if !args.lima_timeout_scale.is_finite() || args.lima_timeout_scale < 1.0 {
        anyhow::bail!(
            "--lima-timeout-scale must be finite and >= 1.0 (got {})",
            args.lima_timeout_scale
        );
    }
    if !args.local_timeout_scale.is_finite() || args.local_timeout_scale < 1.0 {
        anyhow::bail!(
            "--local-timeout-scale must be finite and >= 1.0 (got {})",
            args.local_timeout_scale
        );
    }

    // WHERE the carrick side runs, built from the CLI args. `hvf` (the default)
    // runs the local signed binary with its own default backend and nothing
    // added; `kvm` wraps carrick in the lima guest.
    let lane = lane::lane_from_args(
        &args.lane,
        &args.lima_vm,
        &args.lima_gateway,
        args.lima_timeout_scale,
        args.local_timeout_scale,
    )
    .map_err(|error| anyhow::anyhow!(error))?;

    if args.render_matrix {
        let reports = read_reports(&args.results_path())?;
        let md = matrix::render(&reports);
        write_matrix(&md)?;
        eprintln!(
            "rendered docs/support-matrix.md from {}",
            args.results_path().display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    if args.check_matrix {
        // Render from the CHECKED-IN baseline (the blessed ground truth), never a
        // transient results.jsonl, so the check is deterministic and needs no
        // conformance run. A mismatch means the committed matrix was hand-edited,
        // or the baseline / render logic changed without re-rendering.
        let reports = read_reports(&args.baseline)?;
        let expected = matrix::render(&reports);
        let committed = std::fs::read_to_string("docs/support-matrix.md") // nosemgrep
            .map_err(|e| anyhow::anyhow!("cannot read docs/support-matrix.md ({e})"))?;
        if committed == expected {
            eprintln!(
                "docs/support-matrix.md is in sync with {}",
                args.baseline.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
        eprintln!(
            "docs/support-matrix.md is STALE vs {} — regenerate it with:\n  \
             cargo run -p carrick-conformance -- --render-matrix --jsonl {}",
            args.baseline.display(),
            args.baseline.display()
        );
        return Ok(ExitCode::FAILURE);
    }

    if args.generate_suites {
        generate::generate_suites(&args.manifest, args.dry_run)?;
        return Ok(ExitCode::SUCCESS);
    }

    let docker_platform = lane.docker_platform();

    if let Some(results) = &args.seed_oracle {
        seed_oracle(&args.manifest, results, &args.oracle_cache, docker_platform)?;
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
    let skip_key = amd64_bringup_key(docker_platform, &args.lane);
    let selected = select(
        &manifest.suite,
        tier,
        &args.ecosystem,
        &args.suite,
        skip_key,
    );
    // Transparency: a bring-up lane silently dropping not-yet-applicable
    // ecosystems could be misread as full coverage, so name what was scoped out.
    // Only on an unfiltered run — an explicit --ecosystem/--suite already ran it.
    if let Some(key) = skip_key
        && args.ecosystem.is_empty()
        && args.suite.is_empty()
    {
        let skipped: Vec<&Suite> = manifest
            .suite
            .iter()
            .filter(|s| {
                (tier == Tier::Full || s.tier == Tier::Smoke) && !applies_to_lane(s, Some(key))
            })
            .collect();
        if !skipped.is_empty() {
            let mut ecos: Vec<&str> = skipped.iter().map(|s| s.ecosystem.as_str()).collect();
            ecos.sort_unstable();
            ecos.dedup();
            eprintln!(
                "lane {}: scoped out {} not-yet-applicable suite(s) ({}) — not brought up on \
                 this amd64 lane yet; override with --ecosystem/--suite",
                args.lane,
                skipped.len(),
                ecos.join(", ")
            );
        }
    }
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
                &lane,
            );
            let d = engine::docker_dry_run(
                s,
                &format!("conf-{}-dN", std::process::id()),
                docker_platform,
            );
            println!("# {} [{}, {:?}]", s.name, s.ecosystem.as_str(), s.tier);
            println!("  carrick: {}", c.join(" "));
            println!("  docker:  {}", d.join(" "));
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Binary preflight (abort on unsigned/missing; warn on stale). The local-binary
    // checks (codesign, exists) are HVF-only — the KVM binary lives in the guest and
    // is validated by the lima preflight instead.
    if lane.is_lima_kvm() {
        preflight_kvm(&lane, &args.carrick_bin)?;
    } else if matches!(lane, lane::Lane::KvmLocal(_)) {
        preflight_kvm_local(&args.carrick_bin)?;
    } else if matches!(lane, lane::Lane::BhyveLocal(_)) {
        preflight_bhyve_local(&args.carrick_bin)?;
    } else if matches!(lane, lane::Lane::NvmmLocal(_)) {
        preflight_nvmm_local(&args.carrick_bin)?;
    } else {
        preflight(&args.carrick_bin)?;
    }

    // Load the shared baseline, then UNION the lane's overlay onto it (a no-op
    // when the overlay is absent/empty). A divergence is "expected" iff it
    // matches the shared baseline OR the overlay. The overlay path is LANE-
    // DERIVED by default (`baseline.<lane>.jsonl` beside `--baseline`): each
    // bring-up lane (kvm/bhyve/nvmm) carries its OWN initially-empty overlay so
    // every lane-only divergence is a gap until proven environmental, while the
    // mature hvf lane carries none. An explicit `--baseline-overlay` overrides.
    let overlay_path = args
        .baseline_overlay
        .clone()
        .or_else(|| lane_overlay_path(&args.baseline, &args.lane));
    let baseline = if args.closure {
        None
    } else {
        Some(match &overlay_path {
            Some(p) => load_baseline(&args.baseline).with_overlay(load_baseline(p)),
            None => load_baseline(&args.baseline),
        })
    };
    let classification = if args.closure {
        ClassificationPolicy::Closure
    } else {
        ClassificationPolicy::Baseline(
            baseline
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("regular run requires a baseline"))?,
        )
    };

    let pid = std::process::id();
    let carrick_bin = args.carrick_bin.to_string_lossy().into_owned();

    // Image-freshness guard: re-pull carrick's copy of any selected image whose
    // registry digest moved, SERIALLY before the parallel carrick phase, so
    // carrick and docker run identical bytes (see images.rs). Skipped on request.
    if !args.no_image_refresh {
        let imgs: Vec<String> = selected.iter().map(|s| s.image.clone()).collect();
        let refreshed = images::refresh_stale_images(&imgs, &carrick_bin, &lane);
        if refreshed > 0 {
            eprintln!("image-guard: re-pulled {refreshed} stale image(s)");
        }
    }

    // Bless a FINISHED run without repeating it: the bless is a pure function of
    // a full run's reports. Guarded by a completeness check so a truncated or
    // filtered results file cannot silently bless a subset of the tier.
    if let Some(path) = args.bless_from.clone() {
        if !args.bless {
            eprintln!("--bless-from requires --bless");
            return Ok(ExitCode::from(2));
        }
        let text = std::fs::read_to_string(&path)?; // nosemgrep
        let reports: Vec<SuiteReport> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("{}: malformed report line: {e}", path.display()))?;
        let have: std::collections::BTreeSet<&str> =
            reports.iter().map(|r| r.name.as_str()).collect();
        let missing: Vec<&str> = selected
            .iter()
            .map(|s| s.name.as_str())
            .filter(|name| !have.contains(name))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "--bless-from refused: {} of {} selected suite(s) are absent from {} — blessing a \
                 partial run would drop them from the artifact. Finish the run first.",
                missing.len(),
                selected.len(),
                path.display()
            );
            for name in missing.iter().take(20) {
                eprintln!("  missing: {name}");
            }
            if missing.len() > 20 {
                eprintln!("  ... and {} more", missing.len() - 20);
            }
            return Ok(ExitCode::from(2));
        }
        eprintln!(
            "bless-from: {} report(s) loaded from {}",
            reports.len(),
            path.display()
        );
        bless(&args, &selected, tier, &reports)?;
        return Ok(ExitCode::SUCCESS);
    }

    let n = selected.len();
    let workers = worker_count(args.workers);
    let cpython_workers = cpython_worker_count(args.cpython_workers, workers);
    let lanes = SchedulerLanes::new(cpython_workers);
    let fail_fast = FailFast::new(args.force, args.max_gating);
    if !fail_fast.force {
        eprintln!(
            "fail-fast: abort after more than {} gating verdict(s) (use --force for exhaustive)",
            fail_fast.max_gating
        );
    }

    // The oracle is cached for routine runs, so a suite's verdict is fully known
    // the moment its carrick run finishes — no docker needed. Load the cache +
    // per-suite cached oracle side UP FRONT so Phase 1 can STREAM a report line
    // per suite as it completes: the jsonl then grows during the long carrick
    // phase (live progress instead of a 0-byte file), and a crashed/killed run
    // leaves partial results behind. The authoritative file is still rewritten
    // in full at the end (after flake-retries), so this is purely additive.
    let mut cache = oracle::OracleCache::load(&args.oracle_cache);
    let (cached, cached_elapsed): (Vec<Option<parsers::SuiteResult>>, Vec<Option<u64>>) =
        if args.refresh_oracle {
            (vec![None; n], vec![None; n])
        } else {
            selected
                .iter()
                .map(|s| {
                    (
                        cache.get(s, docker_platform),
                        cache.get_elapsed_ms(s, docker_platform),
                    )
                })
                .unzip()
        };

    // Docker-less lanes: refuse to start rather than fall back to docker
    // mid-run. Naming every miss at once makes a determinant-field change
    // (which invalidates the whole cache) obvious instead of looking like a
    // broken runner.
    if args.require_cached_oracle {
        if args.refresh_oracle {
            eprintln!("--require-cached-oracle conflicts with --refresh-oracle");
            std::process::exit(2);
        }
        let missing: Vec<&str> = selected
            .iter()
            .zip(&cached)
            .filter(|(_, hit)| hit.is_none())
            .map(|(suite, _)| suite.name.as_str())
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "--require-cached-oracle: {} of {n} selected suite(s) have no cached oracle for \
                 platform {docker_platform:?}; this lane cannot run docker. Re-bless the cache on \
                 a box with the images (`--refresh-oracle`) and commit it.",
                missing.len()
            );
            for id in &missing {
                eprintln!("  uncached: {id}");
            }
            std::process::exit(2);
        }
        eprintln!("oracle: all {n} selected suite(s) cached; running carrick-only");
    }

    let stream = Mutex::new(std::fs::File::create(args.results_path()).ok());
    let streamed_reports = Mutex::new(Vec::new());
    let fail_fast_stop = AtomicBool::new(false);
    let phase1_gating = AtomicUsize::new(0);

    // ---- Phase 1: ALL carrick (weight-aware; never overlapping docker). ----
    eprintln!("phase 1/3: {n} carrick runs (workers={workers}, cpython-workers={cpython_workers})");
    let all_indices: Vec<usize> = (0..n).collect();
    let carrick_outs = fan_out_scheduled_with_stop(
        &all_indices,
        &selected,
        workers,
        &lanes,
        || fail_fast_stop.load(Ordering::SeqCst),
        |i| {
            let s = &selected[i];
            // Zero-pad the index so no run-id is a prefix of another (c01 vs c10);
            // kill.sh anchors on the proctitle "carrick:<id>:" delimiter too, but a
            // collision-free id is defense in depth against any unanchored grep.
            let run_id = format!("conf-{pid}-c{i:02}");
            let out = engine::run_carrick(s, &carrick_bin, &run_id, &lane);
            eprintln!("  [carrick] {}", s.name);
            // Stream this suite's report NOW if its oracle is cached (the common
            // case). Un-cached suites still need docker (Phase 2) and are emitted
            // only by the final authoritative write.
            if let Some(res) = cached.get(i).and_then(|c| c.as_ref()) {
                let docker = DockerSide {
                    result: res.clone(),
                    run_id: "<cached>".to_string(),
                    argv: engine::docker_dry_run(s, "<cached>", docker_platform),
                    elapsed_ms: cached_elapsed[i],
                };
                let cout = out.as_ref().ok();
                let rep = build_report(s, cout, &docker, classification);
                if rep.gating {
                    let gating = phase1_gating.fetch_add(1, Ordering::SeqCst) + 1;
                    if fail_fast.should_abort(gating)
                        && !fail_fast_stop.swap(true, Ordering::SeqCst)
                    {
                        eprintln!(
                            "fail-fast: stopping phase 1 after {gating} gating verdict(s) \
                         (max {}, use --force for exhaustive)",
                            fail_fast.max_gating
                        );
                    }
                }
                if let Ok(line) = serde_json::to_string(&rep)
                    && let Ok(mut guard) = stream.lock()
                    && let Some(f) = guard.as_mut()
                {
                    use std::io::Write as _;
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }
                streamed_reports
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(rep);
            }
            out
        },
    );
    drop(stream);
    if fail_fast_stop.load(Ordering::SeqCst) {
        let reports = streamed_reports
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        write_reports(&args.results_path(), &reports)?;
        print_summary(&reports);
        eprintln!(
            "\nFAIL-FAST: {} cached-oracle gating verdict(s) exceeded max {} \
             before all suites were scheduled; use --force for an exhaustive run",
            phase1_gating.load(Ordering::SeqCst),
            fail_fast.max_gating
        );
        return Ok(ExitCode::from(1));
    }

    // ---- Phase 2: docker — but ONLY for suites whose oracle is not already
    // cached. The docker oracle for a deterministic suite is stable, so it needs
    // to run once, ever; a cached suite contributes its committed result and
    // runs no container. Strictly after phase 1 (carrick ‖ docker never overlap).
    // (`cache`/`cached` were loaded before Phase 1 for the live-stream above.)
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
    let fresh_outs = fan_out_scheduled(&need_docker, &selected, workers, &lanes, |i| {
        let s = &selected[i];
        let run_id = format!("conf-{pid}-d{i:02}");
        let out = engine::run_docker(s, &run_id, docker_platform);
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
                cache.insert(s, docker_platform, res.clone(), Some(o.elapsed_ms)); // refuses to cache a non-comparable oracle
                DockerSide {
                    result: res,
                    run_id: o.run_id,
                    argv: o.argv,
                    elapsed_ms: Some(o.elapsed_ms),
                }
            }
            None => DockerSide {
                result: parsers::SuiteResult::empty(),
                run_id: String::new(),
                argv: engine::docker_dry_run(s, "spawn-failed", docker_platform),
                elapsed_ms: None,
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
    // Assemble each suite's docker side (cached or fresh) into an index-keyed vec
    // first, so the retry pass can re-classify against it without re-running docker.
    eprintln!("phase 3/3: classify");
    let mut docker_sides: Vec<DockerSide> = Vec::with_capacity(n);
    for (i, s) in selected.iter().enumerate() {
        let docker = match &cached[i] {
            Some(res) => DockerSide {
                result: res.clone(),
                run_id: "<cached>".to_string(),
                argv: engine::docker_dry_run(s, "<cached>", docker_platform),
                elapsed_ms: cached_elapsed[i],
            },
            None => fresh.remove(&i).ok_or_else(|| {
                anyhow::anyhow!("every non-cached suite has a fresh docker side (suite {i})")
            })?,
        };
        docker_sides.push(docker);
    }
    let mut reports: Vec<SuiteReport> = selected
        .iter()
        .zip(&carrick_outs)
        .enumerate()
        .map(|(i, (s, cout))| {
            let cout = cout.as_ref().and_then(|r| r.as_ref().ok());
            build_report(s, cout, &docker_sides[i], classification)
        })
        .collect();

    // ---- Phase 3b: retry-on-flake. Re-run carrick (only) for any gating suite;
    // adopt the first non-gating attempt. The oracle side is reused from phase 3
    // (no docker re-run), so this never overlaps docker. ----
    let retries = args.flake_retries;
    let gating_before = reports.iter().filter(|r| r.gating).count();
    if fail_fast.should_abort(gating_before) {
        write_reports(&args.results_path(), &reports)?;
        print_summary(&reports);
        eprintln!(
            "\nFAIL-FAST: {gating_before} gating verdict(s) exceeded max {}; \
             use --force for retries/bless/exhaustive classification",
            fail_fast.max_gating
        );
        return Ok(ExitCode::from(1));
    }
    if retries > 0 && gating_before > 0 {
        eprintln!(
            "phase 3b: retry-on-flake — {gating_before} gating suite(s), up to {retries} retr{} each",
            if retries == 1 { "y" } else { "ies" }
        );
        let recovered = apply_flake_retries(
            &mut reports,
            retries,
            |r| r.gating,
            |i, attempt| {
                let s = &selected[i];
                let run_id = format!("conf-{pid}-r{i:02}-a{attempt}");
                let cout = engine::run_carrick(s, &carrick_bin, &run_id, &lane).ok();
                let rep = build_report(s, cout.as_ref(), &docker_sides[i], classification);
                eprintln!(
                    "  [retry] {} attempt {attempt}/{retries} -> {}{}",
                    s.name,
                    rep.verdict.as_str(),
                    if rep.gating { "" } else { " (recovered)" }
                );
                rep
            },
        );
        let still = reports.iter().filter(|r| r.gating).count();
        eprintln!("retry-on-flake: {recovered} flake(s) recovered, {still} still gating");
    }

    write_reports(&args.results_path(), &reports)?;
    print_summary(&reports);

    if args.closure {
        match validate_closure_reports(&selected, &reports) {
            Ok(()) => {
                eprintln!("\nOK: closure has complete MATCH coverage");
                return Ok(ExitCode::SUCCESS);
            }
            Err(error) => {
                eprintln!("\nFAIL: closure is incomplete: {error:#}");
                return Ok(ExitCode::from(1));
            }
        }
    }

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
    elapsed_ms: Option<u64>,
}

#[derive(Clone, Copy)]
enum ClassificationPolicy<'a> {
    Closure,
    Baseline(&'a Baseline),
}

fn build_report(
    s: &Suite,
    cout: Option<&engine::RunOutput>,
    docker: &DockerSide,
    policy: ClassificationPolicy<'_>,
) -> SuiteReport {
    let (c_raw, c_timed, c_runid, c_argv, c_elapsed_ms) = match cout {
        Some(o) => (
            o.raw(),
            o.timed_out,
            o.run_id.clone(),
            o.argv.clone(),
            Some(o.elapsed_ms),
        ),
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
            None,
        ),
    };

    let c_res = parsers::parse(verdict_kind(s), &c_raw);
    let d_res = &docker.result;
    let cl = match policy {
        ClassificationPolicy::Closure => classify_closure(s, &c_res, c_timed, d_res),
        ClassificationPolicy::Baseline(baseline) => classify(s, &c_res, c_timed, d_res, baseline),
    };

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
        perf: c_elapsed_ms.map(|elapsed_ms| perf_summary(elapsed_ms, docker.elapsed_ms)),
        // Only meaningful on a TIMEOUT, and only when the host answered.
        timeout_kind: cout.and_then(|o| {
            o.timeout_evidence
                .map(|e| engine::classify_timeout(e.cpu_ms, o.elapsed_ms, e.loadavg_1m, e.ncpu))
        }),
        new_diffs: cl.new_diffs,
        known_diffs: cl.known_diffs,
        carrick_run_id: c_runid,
        docker_run_id: docker.run_id.clone(),
        carrick_argv: c_argv,
        docker_argv: docker.argv.clone(),
        pairs: cl.pairs,
    }
}

fn perf_summary(carrick_ms: u64, oracle_ms: Option<u64>) -> PerfSummary {
    PerfSummary {
        carrick_ms,
        oracle_ms,
        carrick_to_oracle_ratio: oracle_ms.and_then(|ms| {
            if ms == 0 {
                return None;
            }
            let ratio = carrick_ms as f64 / ms as f64;
            if ratio.is_finite() {
                Some((ratio * 100.0).round() / 100.0)
            } else {
                None
            }
        }),
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
fn seed_oracle(
    manifest_path: &Path,
    results: &Path,
    cache_path: &Path,
    docker_platform: lane::DockerPlatform,
) -> anyhow::Result<()> {
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
                let oracle_ms = r.perf.as_ref().and_then(|p| p.oracle_ms);
                if cache.insert(s, docker_platform, res, oracle_ms) {
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

/// What a `--bless` on a given lane is permitted to rewrite. The mature `hvf`
/// lane rewrites the SHARED baseline + `support-matrix.md` (the ground truth); a
/// kvm/bhyve/nvmm bring-up lane rewrites ONLY its own overlay
/// (`baseline.<key>.jsonl`) — never the shared baseline, never the matrix — so a
/// lane's observations can never overwrite the hvf ground truth. An unrecognized
/// lane is refused outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlessTarget {
    /// hvf: rewrite the shared `baseline.jsonl` + `docs/support-matrix.md`.
    SharedBaseline,
    /// kvm/bhyve/nvmm: rewrite ONLY `baseline.<key>.jsonl` (the overlay).
    LaneOverlay(&'static str),
}

/// Pure bless-guard decision (no IO): which artifact `--bless` may rewrite on
/// `lane`. Unit-tested directly — the side-effecting `bless` dispatches on this.
fn bless_target(lane: &str) -> Result<BlessTarget, String> {
    if lane == "hvf" {
        return Ok(BlessTarget::SharedBaseline);
    }
    match lane_overlay_key(lane) {
        Some(key) => Ok(BlessTarget::LaneOverlay(key)),
        None => Err(format!(
            "--bless: unrecognized lane {lane:?} — bless is the hvf lane (shared \
             baseline + matrix) or a kvm/bhyve/nvmm lane (its overlay only)"
        )),
    }
}

/// Whether `verdict` must block a `--bless` on `target`. TIMEOUT/CARRICK_CRASH are
/// genuine carrick failures and block on EVERY lane. ORACLE_FAIL (Docker produced
/// nothing comparable for this arch) blocks ONLY the mature hvf shared-baseline
/// bless: hvf runs the native arm64 oracle, which should always exist, so a missing
/// one is a broken oracle to fix before re-blessing. A kvm/bhyve/nvmm lane
/// blesses only its OWN overlay and runs an amd64 oracle that legitimately cannot
/// cover every suite yet, so ORACLE_FAIL there is an expected coverage gap, not a
/// bless blocker. Pure (no IO) so the guard is unit-tested directly.
impl Args {
    /// This run's results path: `--jsonl` when given, else a default keyed on
    /// lane/tier/filtering so runs cannot clobber each other.
    fn results_path(&self) -> PathBuf {
        self.jsonl.clone().unwrap_or_else(|| {
            let tier = parse_tier(&self.tier).unwrap_or(Tier::Full);
            let filtered = !self.ecosystem.is_empty() || !self.suite.is_empty();
            default_results_path(&self.lane, tier, filtered)
        })
    }
}

/// Where a run's results land when `--jsonl` is not given.
///
/// This used to be a single fixed `results.jsonl`, which meant ANY later run
/// destroyed the previous one's data — and the cheap runs are exactly the ones
/// you fire while investigating an expensive one. A 2-suite reproduction
/// silently wiped the per-suite records of a 1175-suite full-tier run mid-triage
/// here, and only the 23 outlier lines that had already been echoed to a log
/// survived.
///
/// Keying the default on lane + tier + whether the run was filtered keeps runs
/// from overwriting each other in the ways that actually happen: a filtered
/// reproduction against an unfiltered gate, a smoke gate against a full one, and
/// one lane against another. `--jsonl` still points anywhere explicitly.
fn default_results_path(lane: &str, tier: Tier, filtered: bool) -> PathBuf {
    let lane = lane
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let suffix = if filtered { ".filtered" } else { "" };
    PathBuf::from(format!(
        "target/conformance/results.{lane}.{}{suffix}.jsonl",
        tier_str(tier)
    ))
}

/// A STARVED timeout measured the BOX, not carrick: the suite got little CPU
/// while the machine was oversubscribed, so the run proves nothing either way.
/// It must not block a bless (that would let an unrelated noisy neighbour veto
/// a baseline), and it must not be silently swallowed either — the summary
/// prints starved suites explicitly so a run whose measurements were invalid
/// is visible rather than quietly "fine".
fn timeout_blocks_bless(kind: Option<crate::engine::TimeoutKind>) -> bool {
    !kind.is_some_and(crate::engine::TimeoutKind::is_measurement_failure)
}

fn bless_blocks(target: BlessTarget, verdict: Verdict) -> bool {
    match verdict {
        Verdict::Incomplete | Verdict::Timeout | Verdict::CarrickCrash => true,
        Verdict::OracleFail => matches!(target, BlessTarget::SharedBaseline),
        Verdict::Match | Verdict::Diff | Verdict::Regression | Verdict::New => false,
    }
}

/// How a run's reports partition against the bless gate. Pure (no IO) so the
/// policy is unit-tested directly; the side-effecting [`bless`] only prints and
/// writes what this decides.
#[derive(Debug, Default, PartialEq, Eq)]
struct BlessGate<'a> {
    /// Suites that must be resolved before this target can be blessed.
    blocking: Vec<&'a str>,
    /// Suites whose hang is deliberately carried via `--allow-hang`. Waived from
    /// `blocking` AND withheld from the written artifact.
    carried: Vec<&'a str>,
    /// `--allow-hang` names that did not actually block — a stale allowlist.
    stale: Vec<&'a str>,
    /// Timeouts that measured an oversubscribed box rather than carrick.
    starved: Vec<&'a str>,
}

fn bless_gate<'a>(
    target: BlessTarget,
    reports: &'a [SuiteReport],
    allow_hang: &'a [String],
) -> BlessGate<'a> {
    let allowed: std::collections::BTreeSet<&str> = allow_hang.iter().map(String::as_str).collect();
    let carried: Vec<&str> = reports
        .iter()
        .filter(|r| bless_blocks(target, r.verdict) && allowed.contains(r.name.as_str()))
        .map(|r| r.name.as_str())
        .collect();
    BlessGate {
        blocking: reports
            .iter()
            .filter(|r| bless_blocks(target, r.verdict) && timeout_blocks_bless(r.timeout_kind))
            .map(|r| r.name.as_str())
            .filter(|name| !allowed.contains(name))
            .collect(),
        // A name that no longer blocks is stale: report it so the list gets
        // pruned once the hang is fixed, instead of waiving a suite forever.
        stale: allowed
            .iter()
            .copied()
            .filter(|name| !carried.contains(name))
            .collect(),
        carried,
        starved: reports
            .iter()
            .filter(|r| !timeout_blocks_bless(r.timeout_kind))
            .map(|r| r.name.as_str())
            .collect(),
    }
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
    // The shared baseline.jsonl + support-matrix.md are the hvf-lane ground
    // truth; a bring-up-lane bless writes ONLY that lane's overlay instead, so it
    // can never overwrite them with lane-specific observations.
    let target = bless_target(&args.lane).map_err(|e| anyhow::anyhow!(e))?;
    // Deliberately-carried hangs (--allow-hang). Named, warned, and left OUT of
    // the written artifact so the hang keeps gating until it is really fixed.
    let BlessGate {
        blocking: bad,
        carried,
        stale,
        starved,
    } = bless_gate(target, reports, &args.allow_hang);
    if !stale.is_empty() {
        eprintln!(
            "warning: --allow-hang named {} suite(s) that did NOT time out or crash; drop them \
             from the invocation: {}",
            stale.len(),
            stale.join(", ")
        );
    }
    if !carried.is_empty() {
        eprintln!(
            "warning: --allow-hang: blessing WITHOUT {} unresolved hang(s): {}. They are left \
             UNBLESSED (absent from the written artifact), so they keep failing against the \
             shared baseline and every future bless must name them again.",
            carried.len(),
            carried.join(", ")
        );
    }

    // Starved suites do not block, but they are NOT a clean bill of health:
    // their measurements were invalid, so say so loudly rather than let a
    // degraded box pass for a green one.
    if !starved.is_empty() {
        eprintln!(
            "warning: {} suite(s) TIMED OUT while the box was oversubscribed (STARVED) — their \
             results measured the machine, not carrick, and are being blessed as-is. Re-run on a \
             quiet box to get a real verdict for: {}",
            starved.len(),
            starved.join(", ")
        );
    }
    if !bad.is_empty() {
        // A shared-baseline (hvf) bless additionally blocks on ORACLE_FAIL; a
        // bring-up-lane overlay bless does not, so name only the verdicts that
        // actually block on this target.
        let blockers = match target {
            BlessTarget::SharedBaseline => "ORACLE_FAIL/TIMEOUT/CARRICK_CRASH",
            BlessTarget::LaneOverlay(_) => "TIMEOUT/CARRICK_CRASH",
        };
        anyhow::bail!(
            "--bless refused: resolve these {blockers} suites first: {}",
            bad.join(", ")
        );
    }
    let _ = selected; // (kept for symmetry / future per-suite bless)
    // Drop the carried hangs: a timeout has no measured result, so writing one
    // would bless "it hangs" as the expectation and retire the signal.
    let written: Vec<SuiteReport> = if carried.is_empty() {
        reports.to_vec()
    } else {
        reports
            .iter()
            .filter(|r| !carried.contains(&r.name.as_str()))
            .cloned()
            .collect()
    };
    let reports: &[SuiteReport] = &written;
    match target {
        BlessTarget::SharedBaseline => {
            write_baseline_reports(&args.baseline, reports)?;
            let md = matrix::render(reports);
            write_matrix(&md)?;
            eprintln!(
                "blessed: wrote {} and docs/support-matrix.md",
                args.baseline.display()
            );
        }
        BlessTarget::LaneOverlay(key) => {
            // ONLY the lane overlay — the shared baseline + matrix stay untouched.
            let overlay = overlay_path_for_key(&args.baseline, key);
            write_baseline_reports(&overlay, reports)?;
            eprintln!(
                "blessed {key} lane overlay: wrote {} (shared baseline + matrix left untouched)",
                overlay.display()
            );
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct FailFast {
    force: bool,
    max_gating: usize,
}

impl FailFast {
    fn new(force: bool, max_gating: usize) -> Self {
        Self { force, max_gating }
    }

    fn should_abort(self, gating: usize) -> bool {
        !self.force && gating > self.max_gating
    }
}

/// Hand-rolled work-stealing pool (std only; mirrors conformance.rs::fan_out_indexed
/// but returns `Option<T>` to stay clear of the no-panic gate). Lane permits are
/// acquired before dispatch so blocked heavy suites do not monopolize workers
/// while other suites are runnable.
fn fan_out_scheduled<T: Send>(
    indices: &[usize],
    suites: &[Suite],
    workers: usize,
    lanes: &SchedulerLanes,
    f: impl Fn(usize) -> T + Sync,
) -> Vec<Option<T>> {
    fan_out_scheduled_with_stop(indices, suites, workers, lanes, || false, f)
}

fn fan_out_scheduled_with_stop<T: Send>(
    indices: &[usize],
    suites: &[Suite],
    workers: usize,
    lanes: &SchedulerLanes,
    should_stop: impl Fn() -> bool + Sync,
    f: impl Fn(usize) -> T + Sync,
) -> Vec<Option<T>> {
    let slots: Vec<Mutex<Option<T>>> = (0..indices.len()).map(|_| Mutex::new(None)).collect();
    let state = Mutex::new(ScheduleState {
        claimed: vec![false; indices.len()],
        completed: 0,
    });
    let changed = Condvar::new();
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1) {
            scope.spawn(|| {
                loop {
                    let job = {
                        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                        loop {
                            if state.completed == indices.len() || should_stop() {
                                break None;
                            }

                            let mut selected = None;
                            for (slot, suite_index) in indices.iter().copied().enumerate() {
                                if state.claimed[slot] {
                                    continue;
                                }
                                let suite = &suites[suite_index];
                                let Some(permit) = lanes.try_acquire(suite) else {
                                    if suite_requires_exclusive_lane(suite) {
                                        break;
                                    }
                                    continue;
                                };
                                state.claimed[slot] = true;
                                selected = Some((slot, suite_index, permit));
                                break;
                            }
                            if selected.is_some() {
                                break selected;
                            }

                            state = changed.wait(state).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    let Some((slot, suite_index, permit)) = job else {
                        break;
                    };

                    let v = f(suite_index);
                    *slots[slot].lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
                    drop(permit);

                    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                    state.completed += 1;
                    changed.notify_all();
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
        .collect()
}

struct ScheduleState {
    claimed: Vec<bool>,
    completed: usize,
}

/// Retry-on-flake. A gating verdict on a suite that flips between identical-binary
/// runs (the Go-runtime-under-HVF races) is a flake, not a real regression —
/// empirically NOT fixable by serializing (see the flakiness note in memory). So
/// re-run each currently-gating item up to `retries` times; the FIRST attempt that
/// is non-gating is adopted (the representative good observation) and the item is
/// counted as recovered. If every attempt still gates, the original report is kept
/// (a consistent gate = a real regression). Generic over the item type so the
/// decision logic is unit-testable without the carrick binary; `rerun(i, attempt)`
/// produces a fresh report for item `i`. Returns the count recovered.
fn apply_flake_retries<T>(
    items: &mut [T],
    retries: usize,
    is_gating: impl Fn(&T) -> bool,
    mut rerun: impl FnMut(usize, usize) -> T,
) -> usize {
    let mut recovered = 0;
    for (i, item) in items.iter_mut().enumerate() {
        if !is_gating(item) {
            continue;
        }
        for attempt in 1..=retries {
            let fresh = rerun(i, attempt);
            if !is_gating(&fresh) {
                *item = fresh;
                recovered += 1;
                break;
            }
        }
    }
    recovered
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
    state: Mutex<SchedulerLaneState>,
    cpython_heavy_limit: usize,
    generic_heavy_limit: usize,
}

#[derive(Default)]
struct SchedulerLaneState {
    active_total: usize,
    active_cpython_heavy: usize,
    active_generic_heavy: usize,
    exclusive_active: bool,
}

#[derive(Clone, Copy)]
enum SchedulerLaneKind {
    Light,
    CpythonHeavy,
    GenericHeavy,
    Exclusive,
}

impl SchedulerLanes {
    fn new(cpython_workers: usize) -> Self {
        Self {
            state: Mutex::new(SchedulerLaneState::default()),
            cpython_heavy_limit: cpython_workers.max(1),
            generic_heavy_limit: 1,
        }
    }

    fn try_acquire(&self, suite: &Suite) -> Option<Option<SchedulerPermit<'_>>> {
        let kind = if suite_requires_exclusive_lane(suite) {
            SchedulerLaneKind::Exclusive
        } else if suite.weight != Weight::Heavy {
            SchedulerLaneKind::Light
        } else if suite.ecosystem == Ecosystem::Cpython {
            SchedulerLaneKind::CpythonHeavy
        } else {
            SchedulerLaneKind::GenericHeavy
        };

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.exclusive_active {
            return None;
        }
        match kind {
            SchedulerLaneKind::Exclusive => {
                if state.active_total > 0 {
                    return None;
                }
                state.exclusive_active = true;
                state.active_total += 1;
            }
            SchedulerLaneKind::Light => {
                state.active_total += 1;
            }
            SchedulerLaneKind::CpythonHeavy => {
                if state.active_cpython_heavy >= self.cpython_heavy_limit {
                    return None;
                }
                state.active_cpython_heavy += 1;
                state.active_total += 1;
            }
            SchedulerLaneKind::GenericHeavy => {
                if state.active_generic_heavy >= self.generic_heavy_limit {
                    return None;
                }
                state.active_generic_heavy += 1;
                state.active_total += 1;
            }
        }
        Some(Some(SchedulerPermit { lanes: self, kind }))
    }

    fn release(&self, kind: SchedulerLaneKind) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_total = state.active_total.saturating_sub(1);
        match kind {
            SchedulerLaneKind::Exclusive => {
                state.exclusive_active = false;
            }
            SchedulerLaneKind::Light => {}
            SchedulerLaneKind::CpythonHeavy => {
                state.active_cpython_heavy = state.active_cpython_heavy.saturating_sub(1);
            }
            SchedulerLaneKind::GenericHeavy => {
                state.active_generic_heavy = state.active_generic_heavy.saturating_sub(1);
            }
        }
    }
}

struct SchedulerPermit<'a> {
    lanes: &'a SchedulerLanes,
    kind: SchedulerLaneKind,
}

impl Drop for SchedulerPermit<'_> {
    fn drop(&mut self) {
        self.lanes.release(self.kind);
    }
}

fn suite_requires_exclusive_lane(suite: &Suite) -> bool {
    // These suites are reliable when run alone but can make little progress
    // when co-scheduled under HVF. Keep this as scheduling isolation, not a
    // timeout escape hatch: the underlying performance outliers still show up
    // in the per-suite timing ratios.
    const EXCLUSIVE_SUITES: &[&str] = &[
        "go-net_http",
        "ltp-execve05",
        "ltp-inotify09",
        "ltp-openat03",
        "ltp-select02",
    ];
    EXCLUSIVE_SUITES.contains(&suite.name.as_str())
}

/// Whether `suite` is applicable on the lane identified by `overlay_key` — the
/// amd64 bring-up lane's key from [`amd64_bringup_key`], or `None` for any arm64
/// lane (hvf, the lima `kvm` lane), where everything applies. The x86 bring-up
/// lanes (kvm/bhyve/nvmm) replay the arm64 manifest under `--platform
/// linux/amd64`; ecosystems carrick cannot yet run on x86 only yield ORACLE_FAIL
/// (no amd64 oracle) or CARRICK_CRASH (die at guest init), so an unfiltered run
/// skips them rather than waste a full fresh Docker pass and clutter the lane
/// overlay. This is a scope boundary (which ecosystems are brought up on x86),
/// not a per-testcase excuse — grep here to widen coverage as bring-up lands:
///   - CPython: no native x86 run exists yet (arm64/HVF-only) -> skip on EVERY
///     bring-up lane.
///   - Go / Node: run on kvm for discovery, but die at guest init on bhyve/nvmm
///     (Go's large pageAlloc PROT_NONE reservation) -> skip there until it lands.
///
/// LTP is the mature x86 ecosystem and ALWAYS applies; a missing amd64 LTP oracle
/// surfaces as a non-blocking ORACLE_FAIL (see `bless_blocks`), never a skip.
fn applies_to_lane(suite: &Suite, overlay_key: Option<&str>) -> bool {
    let Some(key) = overlay_key else {
        return true; // hvf: byte-for-byte the pre-filter behavior
    };
    match suite.ecosystem {
        Ecosystem::Ltp => true,
        Ecosystem::Cpython => false,
        Ecosystem::Go | Ecosystem::Node => key == "kvm",
    }
}

/// The lane-applicability skip key `select` should use: the bring-up lane's
/// overlay key (kvm/bhyve/nvmm) ONLY when the lane runs an amd64 guest — the x86
/// bring-up lanes that replay the arm64 manifest under `--platform linux/amd64`.
/// Every arm64 lane returns `None` (skip nothing). This is keyed on the guest
/// ARCH, not the overlay key, precisely because the arm64 lima `kvm` lane and the
/// amd64 `kvm-local` lane SHARE the "kvm" overlay key but must scope differently:
/// cpython/go/node run fine on the arm64 lima lane and must not be skipped there.
fn amd64_bringup_key(
    docker_platform: lane::DockerPlatform,
    lane_str: &str,
) -> Option<&'static str> {
    match docker_platform {
        lane::DockerPlatform::LinuxAmd64 => lane_overlay_key(lane_str),
        lane::DockerPlatform::LinuxArm64 => None,
    }
}

fn select(
    suites: &[Suite],
    tier: Tier,
    ecos: &[String],
    names: &[String],
    overlay_key: Option<&str>,
) -> Vec<Suite> {
    // An explicit --ecosystem/--suite is a deliberate opt-in (e.g. manual x86
    // discovery of a not-yet-applicable ecosystem), so it OVERRIDES the lane
    // applicability skip. An unfiltered run — every gate, including --bless —
    // gets the skip.
    let explicit = !ecos.is_empty() || !names.is_empty();
    let mut out: Vec<Suite> = suites
        .iter()
        .filter(|s| tier == Tier::Full || s.tier == Tier::Smoke)
        .filter(|s| ecos.is_empty() || ecos.iter().any(|e| e == s.ecosystem.as_str()))
        .filter(|s| names.is_empty() || names.iter().any(|nm| nm == &s.name))
        .filter(|s| explicit || applies_to_lane(s, overlay_key))
        .cloned()
        .collect();
    // Dispatch order = list order (fan_out hands out ascending indices), so sort
    // by ecosystem run-priority to control which suites START first. LTP (light,
    // ~40s, the syscall oracle we want feedback on first) leads; CPython (heavy,
    // ~300s, noisy) trails. A STABLE sort preserves the manifest's within-
    // ecosystem order so matrix rows / oracle-cache keys never churn. The
    // generated suites.toml stays untouched — this is the single authority on run
    // order, so it survives `--generate-suites` regeneration.
    out.sort_by_key(|s| eco_run_priority(s.ecosystem));
    out
}

/// Run-order rank for an ecosystem: lower dispatches first. LTP first, CPython
/// last (the user-requested ordering); go/node fill the middle.
fn eco_run_priority(eco: Ecosystem) -> u8 {
    match eco {
        Ecosystem::Ltp => 0,
        Ecosystem::Go => 1,
        Ecosystem::Node => 2,
        Ecosystem::Cpython => 3,
    }
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
        // Spec §error-handling: an image-pull/extract/disk failure must surface
        // as an INFRA problem, not read as a parity divergence. Still gating
        // (parity is unproven) — the annotation tells the operator where to look.
        let infra = if r.gating {
            infra_signature(&r.carrick_run_id)
                .map(|sig| format!("  [infra: {sig}]"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let perf = perf_annotation(r);
        // A bare TIMEOUT is not a diagnosis. Say WHY the deadline was missed so
        // the reader can tell "carrick hung" (blocked/spinning) from "this box
        // was too busy to measure anything" (starved) without re-running it.
        let why = r
            .timeout_kind
            .map(|k| format!(" [{}]", k.as_str()))
            .unwrap_or_default();
        eprintln!(
            "  {mark} {:14} {:40} carrick[{}] oracle[{}]{infra}{why}{perf}",
            r.verdict.as_str(),
            r.name,
            side(&r.carrick),
            side(&r.docker),
        );
    }
    print_perf_outliers(reports);
}

fn perf_annotation(r: &SuiteReport) -> String {
    let Some(perf) = &r.perf else {
        return String::new();
    };
    let Some(ratio) = perf.carrick_to_oracle_ratio else {
        return String::new();
    };
    if ratio < PERF_WARN_RATIO {
        return String::new();
    }
    let class = if ratio >= PERF_CRITICAL_RATIO {
        "critical"
    } else {
        "slow"
    };
    match perf.oracle_ms {
        Some(oracle_ms) => format!(
            "  [perf:{class} {:.2}x {}ms/{}ms]",
            ratio, perf.carrick_ms, oracle_ms
        ),
        None => format!("  [perf:{class} {:.2}x {}ms/?]", ratio, perf.carrick_ms),
    }
}

fn print_perf_outliers(reports: &[SuiteReport]) {
    let mut outliers: Vec<(&str, &PerfSummary)> = reports
        .iter()
        .filter_map(|r| {
            let perf = r.perf.as_ref()?;
            let ratio = perf.carrick_to_oracle_ratio?;
            if ratio >= PERF_WARN_RATIO {
                Some((r.name.as_str(), perf))
            } else {
                None
            }
        })
        .collect();
    outliers.sort_by(|a, b| {
        let ar = a.1.carrick_to_oracle_ratio.unwrap_or_default();
        let br = b.1.carrick_to_oracle_ratio.unwrap_or_default();
        br.total_cmp(&ar).then_with(|| a.0.cmp(b.0))
    });
    if outliers.is_empty() {
        return;
    }
    eprintln!("\n=== performance outliers (carrick/oracle >= {PERF_WARN_RATIO:.0}x) ===");
    for (name, perf) in outliers.into_iter().take(10) {
        let ratio = perf.carrick_to_oracle_ratio.unwrap_or_default();
        let oracle_ms = perf
            .oracle_ms
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "?".to_string());
        eprintln!(
            "  {:40} {:.2}x carrick={}ms oracle={}ms",
            name, ratio, perf.carrick_ms, oracle_ms
        );
    }
}

/// Scan a gating carrick run's captured stderr for known ENVIRONMENT failure
/// signatures (registry pull, layer extraction, disk). Returns the matching
/// line (trimmed) so the summary can label the failure as infra rather than a
/// behavioral divergence.
fn infra_signature(carrick_run_id: &str) -> Option<String> {
    const PATTERNS: &[&str] = &[
        "extract OCI layers",
        "No space left on device",
        "failed to resolve image",
        "failed to pull",
        "Connection refused",
        "connection refused",
    ];
    let path = engine::raw_dir().join(format!("{carrick_run_id}.err"));
    let text = std::fs::read_to_string(path).ok()?; // nosemgrep
    text.lines()
        .rev()
        .find(|l| PATTERNS.iter().any(|p| l.contains(p)))
        .map(|l| {
            let l = l.trim();
            // Keep the summary line readable (char-safe truncation).
            if l.chars().count() > 100 {
                format!("{}…", l.chars().take(100).collect::<String>())
            } else {
                l.to_string()
            }
        })
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

fn write_baseline_reports(path: &Path, reports: &[SuiteReport]) -> anyhow::Result<()> {
    let mut sanitized = reports.to_vec();
    for report in &mut sanitized {
        report.perf = None;
    }
    write_reports(path, &sanitized)
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

// ---- lane-derived baseline overlays (§4.4) ----
//
// Each carrick VMM bring-up lane carries its OWN baseline overlay so a
// lane-only divergence is a tracked gap in that lane, not a regression smuggled
// into the shared (hvf) ground truth. The overlay file is named
// `baseline.<key>.jsonl` and lives beside the shared `baseline.jsonl`.

/// The overlay KEY for a lane string (the `<key>` in `baseline.<key>.jsonl`).
/// kvm/bhyve/nvmm each map to their own overlay; the mature `hvf` lane (and any
/// unknown string) has NONE, because hvf IS the shared baseline ground truth.
///
/// The KVM backend runs under two guest arches whose results DIVERGE, so they
/// must get SEPARATE overlay files — sharing one would let an amd64 bless clobber
/// the arm64 lane's blessed entries (and cross-excuse arm64 regressions against
/// amd64 pairs, and vice versa). The amd64 native lane (`kvm-local`/`linux-kvm`)
/// keeps `baseline.kvm.jsonl` (the x86 bring-up excuse home, per AGENTS.md); the
/// arm64 lima lane (`kvm`) gets its own `baseline.kvm-arm64.jsonl`. bhyve/nvmm are
/// amd64-only (no arm64 sibling), so they need no arch suffix.
fn lane_overlay_key(lane: &str) -> Option<&'static str> {
    match lane {
        "kvm-local" | "linux-kvm" => Some("kvm"),
        "kvm" => Some("kvm-arm64"),
        "bhyve-local" | "freebsd-bhyve" => Some("bhyve"),
        "nvmm-local" | "netbsd-nvmm" => Some("nvmm"),
        _ => None,
    }
}

/// Build the overlay path for a key beside the shared baseline:
/// `<baseline-dir>/baseline.<key>.jsonl`.
fn overlay_path_for_key(baseline: &Path, key: &str) -> PathBuf {
    let dir = baseline.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("baseline.{key}.jsonl"))
}

/// The lane-derived overlay path for a lane, or `None` for hvf/unknown (no
/// overlay). Derived from the shared baseline's directory so it tracks
/// `--baseline` if the operator relocates it.
fn lane_overlay_path(baseline: &Path, lane: &str) -> Option<PathBuf> {
    lane_overlay_key(lane).map(|key| overlay_path_for_key(baseline, key))
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

/// Local Linux/KVM preflight: the binary is built for platform-linux and runs
/// on this host, so macOS codesign is irrelevant. Validate only the local
/// executable and `/dev/kvm` before the suite fan-out starts.
fn preflight_kvm_local(bin: &Path) -> anyhow::Result<()> {
    let meta = match std::fs::metadata(bin) {
        Ok(m) => m,
        Err(_) => anyhow::bail!(
            "{} is missing — build carrick-cli with `--no-default-features --features platform-linux` first",
            bin.display()
        ),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            meta.permissions().mode() & 0o111 != 0,
            "{} exists but is not executable",
            bin.display()
        );
    }
    anyhow::ensure!(
        std::path::Path::new("/dev/kvm").exists(),
        "/dev/kvm is missing — `--lane kvm-local` must run on a Linux host with KVM"
    );
    if let (Ok(bin_t), Some(src_t)) = (meta.modified(), newest_runtime_src_mtime())
        && bin_t < src_t
    {
        eprintln!(
            "WARNING: {} looks STALE (older than a runtime-crate source) — \
             rebuild the platform-linux carrick binary to be sure you are testing HEAD. Continuing.",
            bin.display()
        );
    }
    Ok(())
}

/// Local FreeBSD/bhyve preflight: the binary is built for platform-freebsd and
/// runs on this host, so macOS codesign is irrelevant. Validate only the local
/// executable and bhyve device before the suite fan-out starts.
fn preflight_bhyve_local(bin: &Path) -> anyhow::Result<()> {
    let meta = match std::fs::metadata(bin) {
        Ok(m) => m,
        Err(_) => anyhow::bail!(
            "{} is missing — build carrick-cli with `--no-default-features --features platform-freebsd` first",
            bin.display()
        ),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            meta.permissions().mode() & 0o111 != 0,
            "{} exists but is not executable",
            bin.display()
        );
    }
    anyhow::ensure!(
        bhyve_device_available(Path::new("/dev/vmm"), Path::new("/dev/vmmctl")),
        "/dev/vmm or /dev/vmmctl is missing — `--lane bhyve-local` must run on a FreeBSD host with bhyve"
    );
    if let (Ok(bin_t), Some(src_t)) = (meta.modified(), newest_runtime_src_mtime())
        && bin_t < src_t
    {
        eprintln!(
            "WARNING: {} looks STALE (older than a runtime-crate source) — \
             rebuild the platform-freebsd carrick binary to be sure you are testing HEAD. Continuing.",
            bin.display()
        );
    }
    Ok(())
}

fn bhyve_device_available(vmm_dir: &Path, vmmctl: &Path) -> bool {
    vmm_dir.exists() || vmmctl.exists()
}

/// Local NetBSD/NVMM preflight: the binary is built for platform-netbsd and runs
/// on this host, so macOS codesign is irrelevant. Validate only the local
/// executable and NVMM device before the suite fan-out starts.
fn preflight_nvmm_local(bin: &Path) -> anyhow::Result<()> {
    let meta = match std::fs::metadata(bin) {
        Ok(m) => m,
        Err(_) => anyhow::bail!(
            "{} is missing — build carrick-cli with `--no-default-features --features platform-netbsd` first",
            bin.display()
        ),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            meta.permissions().mode() & 0o111 != 0,
            "{} exists but is not executable",
            bin.display()
        );
    }
    anyhow::ensure!(
        std::path::Path::new("/dev/nvmm").exists(),
        "/dev/nvmm is missing — `--lane nvmm-local` must run on a NetBSD host with NVMM"
    );
    if let (Ok(bin_t), Some(src_t)) = (meta.modified(), newest_runtime_src_mtime())
        && bin_t < src_t
    {
        eprintln!(
            "WARNING: {} looks STALE (older than a runtime-crate source) — \
             rebuild the platform-netbsd carrick binary to be sure you are testing HEAD. Continuing.",
            bin.display()
        );
    }
    Ok(())
}

/// KVM-lane preflight: the local-binary checks do not apply (carrick lives in the
/// guest), so this validates the lima wiring instead — the VM is reachable, the
/// in-guest carrick binary exists, and the conformance registry is reachable from
/// the guest. The first two are FATAL (with actionable fixes); registry
/// unreachability is a WARNING (the pull may still resolve, or be a transient).
fn preflight_kvm(lane: &lane::Lane, carrick_in_guest: &Path) -> anyhow::Result<()> {
    let lane::Lane::Kvm(cfg) = lane else {
        return Ok(());
    };
    // 1. VM reachable.
    let ok = Command::new("limactl")
        .args(["shell", &cfg.vm, "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    anyhow::ensure!(
        ok,
        "lima VM '{}' not reachable — run `just lima-up` (or set --lima-vm).",
        cfg.vm
    );
    // 2. carrick-in-guest present (build it with scripts/conformance/build-carrick-in-lima.sh).
    let present = Command::new("limactl")
        .args(["shell", &cfg.vm, "--", "test", "-x"])
        .arg(carrick_in_guest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    anyhow::ensure!(
        present,
        "carrick not built in guest at {} — run scripts/conformance/build-carrick-in-lima.sh and pass its output as --carrick-bin.",
        carrick_in_guest.display()
    );
    // 3. registry reachable from the guest (best-effort: curl the v2 API).
    let reg = format!("{}:5005", cfg.gateway);
    let reachable = Command::new("limactl")
        .args([
            "shell",
            &cfg.vm,
            "--",
            "bash",
            "-lc",
            &format!("curl -fsS http://{reg}/v2/ >/dev/null 2>&1"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !reachable {
        eprintln!(
            "WARNING: conformance registry {reg} not reachable from the guest; \
             image pulls may fail. Ensure the mac registry is published (-p 5005:5000) \
             and {} resolves to the mac.",
            cfg.gateway
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
    /// A cheap run must never destroy an expensive one's data. This is not
    /// hypothetical: a 2-suite reproduction wiped the per-suite records of a
    /// 1175-suite full-tier run mid-triage, and only the handful of lines
    /// already echoed to a log survived.
    #[test]
    fn results_paths_do_not_collide_across_runs() {
        use super::default_results_path;
        let full = default_results_path("kvm-local", Tier::Full, false);
        let filtered = default_results_path("kvm-local", Tier::Full, true);
        let smoke = default_results_path("kvm-local", Tier::Smoke, false);
        let other_lane = default_results_path("hvf", Tier::Full, false);

        // The three ways runs actually clobbered each other, all now distinct.
        assert_ne!(
            full, filtered,
            "a filtered reproduction must not overwrite a gate"
        );
        assert_ne!(full, smoke, "a smoke gate must not overwrite a full one");
        assert_ne!(full, other_lane, "lanes must not overwrite each other");
        assert_ne!(filtered, smoke);

        assert!(full.to_string_lossy().contains("kvm-local"));
        assert!(full.to_string_lossy().contains("full"));
        assert!(filtered.to_string_lossy().contains("filtered"));
        assert!(!full.to_string_lossy().contains("filtered"));
    }

    #[test]
    fn results_path_sanitizes_lane_into_a_filename() {
        use super::default_results_path;
        // A lane string reaches the filesystem; anything path-ish in it must not
        // escape target/conformance/.
        let p = default_results_path("../../etc/passwd", Tier::Full, false);
        let s = p.to_string_lossy();
        assert!(!s.contains(".."), "lane must not traverse: {s}");
        assert!(s.starts_with("target/conformance/"), "{s}");
    }

    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn select_dispatches_ltp_first_cpython_last() {
        use Ecosystem::*;
        // Deliberately interleaved input — the manifest's natural order is
        // go-build/node/cpython/go/ltp, which we must NOT inherit.
        let suites = vec![
            suite("cpython-a", Cpython, Weight::Heavy),
            suite("go-a", Go, Weight::Heavy),
            suite("ltp-a", Ltp, Weight::Light),
            suite("node-a", Node, Weight::Heavy),
            suite("cpython-b", Cpython, Weight::Heavy),
            suite("ltp-b", Ltp, Weight::Light),
            suite("go-b", Go, Weight::Heavy),
        ];
        let out = select(&suites, Tier::Full, &[], &[], None);

        // LTP dispatched first, CPython last; ecosystem blocks are contiguous
        // and in run-priority order (ltp < go < node < cpython).
        let order: Vec<&str> = out.iter().map(|s| s.ecosystem.as_str()).collect();
        assert_eq!(
            order,
            ["ltp", "ltp", "go", "go", "node", "cpython", "cpython"]
        );

        // The sort is STABLE: within an ecosystem the manifest order survives
        // (so the matrix rows and oracle-cache keys do not churn).
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ltp-a",
                "ltp-b",
                "go-a",
                "go-b",
                "node-a",
                "cpython-a",
                "cpython-b"
            ]
        );
    }

    #[test]
    fn applies_to_lane_scopes_ecosystems_per_bringup_lane() {
        use Ecosystem::*;
        let ltp = suite("ltp-x", Ltp, Weight::Light);
        let go = suite("go-x", Go, Weight::Heavy);
        let node = suite("node-x", Node, Weight::Heavy);
        let cpy = suite("cpython-x", Cpython, Weight::Heavy);

        // hvf (None): everything applies — the mature lane is unchanged.
        for s in [&ltp, &go, &node, &cpy] {
            assert!(applies_to_lane(s, None), "{} on hvf", s.name);
        }

        // kvm: CPython is not brought up on x86 yet -> skipped; Go/Node run for
        // discovery; LTP (the mature x86 ecosystem) always applies.
        assert!(applies_to_lane(&ltp, Some("kvm")));
        assert!(applies_to_lane(&go, Some("kvm")));
        assert!(applies_to_lane(&node, Some("kvm")));
        assert!(!applies_to_lane(&cpy, Some("kvm")));

        // bhyve / nvmm: only LTP — Go/Node die at guest init, CPython unbuilt.
        for key in ["bhyve", "nvmm"] {
            assert!(applies_to_lane(&ltp, Some(key)), "ltp on {key}");
            assert!(!applies_to_lane(&go, Some(key)), "go on {key}");
            assert!(!applies_to_lane(&node, Some(key)), "node on {key}");
            assert!(!applies_to_lane(&cpy, Some(key)), "cpython on {key}");
        }
    }

    #[test]
    fn amd64_bringup_key_guards_on_guest_arch() {
        use lane::DockerPlatform::*;
        // amd64 bring-up lanes (and their aliases) resolve to their overlay key,
        // which drives the skip. Note `linux-kvm` is an alias of the amd64
        // `kvm-local` lane, NOT the arm64 lima lane.
        assert_eq!(amd64_bringup_key(LinuxAmd64, "kvm-local"), Some("kvm"));
        assert_eq!(amd64_bringup_key(LinuxAmd64, "linux-kvm"), Some("kvm"));
        assert_eq!(amd64_bringup_key(LinuxAmd64, "bhyve-local"), Some("bhyve"));
        assert_eq!(amd64_bringup_key(LinuxAmd64, "nvmm-local"), Some("nvmm"));
        // arm64 lanes skip NOTHING. The lima `kvm` lane is the collision case: it
        // is arm64 yet SHARES the "kvm" overlay key with the amd64 `kvm-local`
        // lane, so keying on arch (not the key) is what stops cpython/go/node being
        // wrongly skipped on it.
        assert_eq!(amd64_bringup_key(LinuxArm64, "kvm"), None);
        assert_eq!(amd64_bringup_key(LinuxArm64, "hvf"), None);
    }

    #[test]
    fn select_drops_nonapplicable_ecosystems_on_bringup_lanes() {
        use Ecosystem::*;
        let suites = vec![
            suite("ltp-a", Ltp, Weight::Light),
            suite("go-a", Go, Weight::Heavy),
            suite("node-a", Node, Weight::Heavy),
            suite("cpython-a", Cpython, Weight::Heavy),
        ];

        // hvf runs everything (byte-for-byte the pre-filter behavior).
        let hvf: Vec<&str> = select(&suites, Tier::Full, &[], &[], None)
            .iter()
            .map(|s| s.ecosystem.as_str())
            .collect();
        assert_eq!(hvf, ["ltp", "go", "node", "cpython"]);

        // kvm drops CPython only.
        let kvm: Vec<&str> = select(&suites, Tier::Full, &[], &[], Some("kvm"))
            .iter()
            .map(|s| s.ecosystem.as_str())
            .collect();
        assert_eq!(kvm, ["ltp", "go", "node"]);

        // bhyve / nvmm keep LTP only.
        for key in ["bhyve", "nvmm"] {
            let got: Vec<&str> = select(&suites, Tier::Full, &[], &[], Some(key))
                .iter()
                .map(|s| s.ecosystem.as_str())
                .collect();
            assert_eq!(got, ["ltp"], "lane {key}");
        }

        // An explicit --ecosystem OVERRIDES the skip (manual x86 discovery): asking
        // for cpython on bhyve still selects it, despite it being non-applicable.
        let forced: Vec<&str> = select(
            &suites,
            Tier::Full,
            &["cpython".to_string()],
            &[],
            Some("bhyve"),
        )
        .iter()
        .map(|s| s.ecosystem.as_str())
        .collect();
        assert_eq!(forced, ["cpython"]);
    }

    #[test]
    fn lane_overlay_path_is_lane_derived() {
        let baseline = Path::new("scripts/conformance/baseline.jsonl");
        // Each bring-up lane (and its aliases) derives its OWN overlay file
        // beside the shared baseline. The KVM backend's two guest arches get
        // SEPARATE files: amd64 native (`kvm-local`/`linux-kvm`) -> baseline.kvm,
        // arm64 lima (`kvm`) -> baseline.kvm-arm64, so neither clobbers the other.
        for (lane, want) in [
            ("kvm", "scripts/conformance/baseline.kvm-arm64.jsonl"),
            ("kvm-local", "scripts/conformance/baseline.kvm.jsonl"),
            ("linux-kvm", "scripts/conformance/baseline.kvm.jsonl"),
            ("bhyve-local", "scripts/conformance/baseline.bhyve.jsonl"),
            ("freebsd-bhyve", "scripts/conformance/baseline.bhyve.jsonl"),
            ("nvmm-local", "scripts/conformance/baseline.nvmm.jsonl"),
            ("netbsd-nvmm", "scripts/conformance/baseline.nvmm.jsonl"),
        ] {
            assert_eq!(
                lane_overlay_path(baseline, lane).as_deref(),
                Some(Path::new(want)),
                "lane {lane} overlay path"
            );
        }
        // hvf (the shared ground truth) and any unknown lane have NO overlay —
        // including the retired local spellings, which are no longer lanes.
        for lane in ["hvf", "bogus", "hvpatch", "macos-hvpatch", "native-dsr"] {
            assert_eq!(lane_overlay_path(baseline, lane), None, "lane {lane}");
        }
    }

    #[test]
    fn lane_overlay_path_tracks_baseline_directory() {
        // The overlay lives beside whatever `--baseline` points at, not a
        // hard-coded scripts/conformance prefix.
        assert_eq!(
            lane_overlay_path(Path::new("/tmp/custom/baseline.jsonl"), "bhyve-local").as_deref(),
            Some(Path::new("/tmp/custom/baseline.bhyve.jsonl"))
        );
    }

    #[test]
    fn bless_target_guards_per_lane() {
        // hvf rewrites the shared baseline + matrix.
        assert_eq!(bless_target("hvf"), Ok(BlessTarget::SharedBaseline));
        // Each bring-up lane writes ONLY its own overlay key, never the shared
        // baseline. The two KVM guest arches write SEPARATE overlays: arm64 lima
        // `kvm` -> "kvm-arm64", amd64 native `kvm-local` -> "kvm".
        assert_eq!(
            bless_target("kvm"),
            Ok(BlessTarget::LaneOverlay("kvm-arm64"))
        );
        assert_eq!(
            bless_target("kvm-local"),
            Ok(BlessTarget::LaneOverlay("kvm"))
        );
        assert_eq!(
            bless_target("bhyve-local"),
            Ok(BlessTarget::LaneOverlay("bhyve"))
        );
        assert_eq!(
            bless_target("nvmm-local"),
            Ok(BlessTarget::LaneOverlay("nvmm"))
        );
        // An unrecognized lane is refused outright (no silent shared-baseline
        // write) — including the retired local lane spellings. `hvf` is the ONE
        // local macOS lane, so blessing the shared baseline has to be spelled
        // that way and cannot be reached under an old name.
        for lane in ["rosetta", "hvpatch", "macos-hvpatch", "native-dsr"] {
            assert!(bless_target(lane).is_err(), "lane {lane}");
        }
    }

    #[test]
    fn bless_blocks_scopes_oracle_fail_to_shared_baseline() {
        use Verdict::*;
        let overlay = BlessTarget::LaneOverlay("kvm");
        let shared = BlessTarget::SharedBaseline;

        // TIMEOUT / CARRICK_CRASH are genuine carrick failures: they block on
        // EVERY lane, mature or bring-up.
        for target in [shared, overlay] {
            assert!(
                bless_blocks(target, Timeout),
                "TIMEOUT must block {target:?}"
            );
            assert!(
                bless_blocks(target, CarrickCrash),
                "CARRICK_CRASH must block {target:?}"
            );
        }

        // ORACLE_FAIL blocks the mature hvf shared-baseline bless (the arm64
        // oracle should always exist)...
        assert!(bless_blocks(shared, OracleFail));
        // ...but NOT a bring-up lane's overlay bless, where the amd64 oracle
        // legitimately can't cover every suite yet.
        assert!(!bless_blocks(overlay, OracleFail));

        // Comparison verdicts never block a bless on any target.
        for target in [shared, overlay] {
            for v in [Match, Diff, Regression, New] {
                assert!(!bless_blocks(target, v), "{v:?} must not block {target:?}");
            }
        }
    }

    #[test]
    fn flake_retry_adopts_first_nongating_attempt() {
        // (name, gating): i0 clean, i1 flaky (recovers on 2nd attempt), i2 hard.
        let mut items = vec![("clean", false), ("flaky", true), ("hard", true)];
        let mut calls: Vec<(usize, usize)> = Vec::new();
        let recovered = apply_flake_retries(
            &mut items,
            2,
            |x| x.1,
            |i, attempt| {
                calls.push((i, attempt));
                if i == 1 && attempt >= 2 {
                    ("flaky", false) // recovers on the 2nd attempt
                } else if i == 1 {
                    ("flaky", true) // 1st attempt still gating
                } else {
                    ("hard", true) // i2 never recovers
                }
            },
        );

        // Clean (non-gating) item is never retried.
        assert!(!calls.iter().any(|(i, _)| *i == 0));
        // Flaky item: retried twice, adopted the recovered (non-gating) attempt.
        assert_eq!(items[1], ("flaky", false));
        assert_eq!(calls.iter().filter(|(i, _)| *i == 1).count(), 2);
        // Hard item: retried up to the cap, never recovered, original kept gating.
        assert_eq!(items[2], ("hard", true));
        assert_eq!(calls.iter().filter(|(i, _)| *i == 2).count(), 2);
        assert_eq!(recovered, 1);
    }

    #[test]
    fn flake_retry_zero_retries_is_a_noop() {
        let mut items = vec![("a", true), ("b", false)];
        let mut called = false;
        let recovered = apply_flake_retries(
            &mut items,
            0,
            |x| x.1,
            |_, _| {
                called = true;
                ("x", false)
            },
        );
        assert!(!called, "retries=0 must run nothing");
        assert_eq!(recovered, 0);
        assert_eq!(items, vec![("a", true), ("b", false)]);
    }

    #[test]
    fn perf_summary_rounds_and_omits_zero_oracle_ratios() {
        let with_oracle = perf_summary(12_345, Some(1_000));
        assert_eq!(with_oracle.carrick_ms, 12_345);
        assert_eq!(with_oracle.oracle_ms, Some(1_000));
        assert_eq!(with_oracle.carrick_to_oracle_ratio, Some(12.35));

        let zero_oracle = perf_summary(12_345, Some(0));
        assert_eq!(zero_oracle.carrick_to_oracle_ratio, None);

        let cached_without_timing = perf_summary(12_345, None);
        assert_eq!(cached_without_timing.oracle_ms, None);
        assert_eq!(cached_without_timing.carrick_to_oracle_ratio, None);
    }

    fn gate_report(
        name: &str,
        verdict: Verdict,
        timeout_kind: Option<crate::engine::TimeoutKind>,
    ) -> SuiteReport {
        SuiteReport {
            name: name.to_string(),
            ecosystem: "ltp".to_string(),
            tier: "full".to_string(),
            verdict,
            gating: false,
            carrick: SideSummary {
                result: parsers::SuiteOutcome::Success,
                totals: parsers::Totals::default(),
            },
            docker: SideSummary {
                result: parsers::SuiteOutcome::Success,
                totals: parsers::Totals::default(),
            },
            perf: None,
            timeout_kind,
            new_diffs: Vec::new(),
            known_diffs: Vec::new(),
            carrick_run_id: "conf-test-c00".to_string(),
            docker_run_id: "<cached>".to_string(),
            carrick_argv: vec!["carrick".to_string()],
            docker_argv: vec!["docker".to_string()],
            pairs: Default::default(),
        }
    }

    /// `--allow-hang` waives a named hang from the bless gate WITHOUT turning it
    /// into a blessed expectation: the suite lands in `carried` (withheld from the
    /// written artifact by `bless`) rather than merely dropping out of `blocking`.
    /// Blessing "it times out" would make the next identical hang compare MATCH.
    #[test]
    fn allow_hang_carries_named_hangs_and_still_blocks_the_rest() {
        use crate::engine::TimeoutKind;
        let target = BlessTarget::LaneOverlay("kvm");
        let reports = [
            gate_report(
                "ltp-epoll-ltp",
                Verdict::Timeout,
                Some(TimeoutKind::Blocked),
            ),
            gate_report("ltp-select04", Verdict::Timeout, Some(TimeoutKind::Blocked)),
            gate_report("ltp-other", Verdict::Timeout, Some(TimeoutKind::Blocked)),
            gate_report("ltp-fine", Verdict::Match, None),
        ];

        let allow = vec!["ltp-epoll-ltp".to_string(), "ltp-select04".to_string()];
        let gate = bless_gate(target, &reports, &allow);
        assert_eq!(gate.carried, vec!["ltp-epoll-ltp", "ltp-select04"]);
        // An un-named hang still blocks: the waiver is per-suite, not a blanket
        // "ignore timeouts" switch.
        assert_eq!(gate.blocking, vec!["ltp-other"]);
        assert!(gate.stale.is_empty());

        // With no allowlist every hang blocks and nothing is carried.
        let gate = bless_gate(target, &reports, &[]);
        assert_eq!(
            gate.blocking,
            vec!["ltp-epoll-ltp", "ltp-select04", "ltp-other"]
        );
        assert!(gate.carried.is_empty());
    }

    /// An allowlist entry that no longer hangs is reported as stale, so a fixed
    /// suite's waiver gets pruned instead of silently exempting it forever.
    #[test]
    fn allow_hang_reports_stale_entries_and_leaves_starved_unblocking() {
        use crate::engine::TimeoutKind;
        let target = BlessTarget::LaneOverlay("kvm");
        let reports = [
            gate_report("ltp-fixed", Verdict::Match, None),
            gate_report("ltp-noisy", Verdict::Timeout, Some(TimeoutKind::Starved)),
        ];

        let allow = vec!["ltp-fixed".to_string(), "ltp-never-ran".to_string()];
        let gate = bless_gate(target, &reports, &allow);
        // Neither name is carried: one passed, the other is not in the run at all.
        assert!(gate.carried.is_empty());
        assert_eq!(gate.stale, vec!["ltp-fixed", "ltp-never-ran"]);
        // A STARVED timeout measured the box, so it neither blocks nor is carried
        // — it is surfaced separately.
        assert!(gate.blocking.is_empty());
        assert_eq!(gate.starved, vec!["ltp-noisy"]);
    }

    #[test]
    fn baseline_writer_strips_non_deterministic_perf_observations() {
        let report = SuiteReport {
            name: "suite".to_string(),
            ecosystem: "ltp".to_string(),
            tier: "full".to_string(),
            verdict: Verdict::Match,
            gating: false,
            carrick: SideSummary {
                result: parsers::SuiteOutcome::Success,
                totals: parsers::Totals::default(),
            },
            docker: SideSummary {
                result: parsers::SuiteOutcome::Success,
                totals: parsers::Totals::default(),
            },
            perf: Some(perf_summary(10_000, Some(1_000))),
            timeout_kind: None,
            new_diffs: Vec::new(),
            known_diffs: Vec::new(),
            carrick_run_id: "conf-test-c00".to_string(),
            docker_run_id: "<cached>".to_string(),
            carrick_argv: vec!["carrick".to_string()],
            docker_argv: vec!["docker".to_string()],
            pairs: Default::default(),
        };
        let path = std::env::temp_dir().join(format!(
            "carrick-conformance-baseline-perf-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        write_baseline_reports(&path, &[report]).expect("write sanitized baseline");

        let text = std::fs::read_to_string(&path).expect("read sanitized baseline");
        assert!(
            !text.contains("\"perf\""),
            "baseline must not carry wall-clock observations: {text}"
        );
        std::fs::remove_file(path).expect("remove temp baseline");
    }

    #[test]
    fn flake_retries_are_opt_in_by_default() {
        let default = Args::parse_from(["carrick-conformance"]);
        assert_eq!(default.flake_retries, 0);

        let explicit = Args::parse_from(["carrick-conformance", "--flake-retries", "2"]);
        assert_eq!(explicit.flake_retries, 2);
    }

    #[test]
    fn fail_fast_trips_only_after_limit_unless_forced() {
        let normal = FailFast::new(false, 2);
        assert!(!normal.should_abort(0));
        assert!(!normal.should_abort(2));
        assert!(normal.should_abort(3));

        let forced = FailFast::new(true, 2);
        assert!(!forced.should_abort(3));
        assert!(!forced.should_abort(300));
    }

    #[test]
    fn scheduled_fanout_stops_claiming_new_jobs_after_stop() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let suites: Vec<Suite> = (0..12)
            .map(|i| suite(&format!("suite-{i}"), Ecosystem::Ltp, Weight::Light))
            .collect();
        let indices: Vec<usize> = (0..suites.len()).collect();
        let lanes = SchedulerLanes::new(4);
        let stop = AtomicBool::new(false);
        let ran = AtomicUsize::new(0);

        let out = fan_out_scheduled_with_stop(
            &indices,
            &suites,
            1,
            &lanes,
            || stop.load(Ordering::SeqCst),
            |i| {
                let n = ran.fetch_add(1, Ordering::SeqCst) + 1;
                if n == 3 {
                    stop.store(true, Ordering::SeqCst);
                }
                i
            },
        );

        assert_eq!(ran.load(Ordering::SeqCst), 3);
        assert_eq!(out.iter().filter(|x| x.is_some()).count(), 3);
        assert!(out.iter().skip(3).all(Option::is_none));
    }

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
    fn bhyve_preflight_accepts_control_node_or_vm_directory() {
        let root =
            std::env::temp_dir().join(format!("carrick-bhyve-device-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let vmm_dir = root.join("vmm");
        let vmmctl = root.join("vmmctl");

        assert!(!bhyve_device_available(&vmm_dir, &vmmctl));

        std::fs::write(&vmmctl, b"").expect("create vmmctl stand-in");
        assert!(bhyve_device_available(&vmm_dir, &vmmctl));

        std::fs::remove_file(&vmmctl).expect("remove vmmctl stand-in");
        std::fs::create_dir(&vmm_dir).expect("create vmm dir stand-in");
        assert!(bhyve_device_available(&vmm_dir, &vmmctl));

        std::fs::remove_dir_all(&root).expect("cleanup temp root");
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

    #[test]
    fn blocked_generic_heavy_suites_do_not_starve_cpython_lane() {
        let lanes = SchedulerLanes::new(2);
        let mut suites: Vec<Suite> = (0..4)
            .map(|i| suite(&format!("go-{i}"), Ecosystem::Go, Weight::Heavy))
            .collect();
        suites.extend(
            (0..2).map(|i| suite(&format!("cpython-{i}"), Ecosystem::Cpython, Weight::Heavy)),
        );

        let first_generic_done = AtomicBool::new(false);
        let cpython_started_before_generic_finished = AtomicBool::new(false);

        let indices: Vec<usize> = (0..suites.len()).collect();
        let _ = fan_out_scheduled(&indices, &suites, 4, &lanes, |i| {
            if suites[i].ecosystem == Ecosystem::Cpython {
                if !first_generic_done.load(Ordering::SeqCst) {
                    cpython_started_before_generic_finished.store(true, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(10));
            } else {
                std::thread::sleep(Duration::from_millis(150));
                first_generic_done.store(true, Ordering::SeqCst);
            }
        });

        assert!(
            cpython_started_before_generic_finished.load(Ordering::SeqCst),
            "blocked generic-heavy suites should not stop eligible CPython-heavy suites from starting"
        );
    }

    #[test]
    fn load_sensitive_suites_run_without_overlap() {
        let lanes = SchedulerLanes::new(2);
        let suites = vec![
            suite("go-net_http", Ecosystem::Go, Weight::Heavy),
            suite("ltp-execve05", Ecosystem::Ltp, Weight::Light),
            suite("ltp-openat03", Ecosystem::Ltp, Weight::Light),
            suite("ltp-inotify09", Ecosystem::Ltp, Weight::Light),
            suite("ltp-select02", Ecosystem::Ltp, Weight::Light),
            suite("cpython-tarfile", Ecosystem::Cpython, Weight::Heavy),
            suite("ltp-gettid01", Ecosystem::Ltp, Weight::Light),
        ];

        let active = AtomicUsize::new(0);
        let exclusive_active = AtomicBool::new(false);
        let overlapped = AtomicBool::new(false);
        let indices: Vec<usize> = (0..suites.len()).collect();
        let _ = fan_out_scheduled(&indices, &suites, 3, &lanes, |i| {
            let is_exclusive = suite_requires_exclusive_lane(&suites[i]);
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            if is_exclusive {
                exclusive_active.store(true, Ordering::SeqCst);
                if now != 1 {
                    overlapped.store(true, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(100));
                exclusive_active.store(false, Ordering::SeqCst);
            } else {
                if exclusive_active.load(Ordering::SeqCst) {
                    overlapped.store(true, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });

        assert!(
            !overlapped.load(Ordering::SeqCst),
            "load-sensitive suites must not overlap with other suites"
        );
    }

    fn max_observed_concurrency(suites: &[Suite], lanes: &SchedulerLanes, workers: usize) -> usize {
        let active = AtomicUsize::new(0);
        let max_active = AtomicUsize::new(0);

        let indices: Vec<usize> = (0..suites.len()).collect();
        let _ = fan_out_scheduled(&indices, suites, workers, lanes, |_i| {
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
