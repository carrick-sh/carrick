//! Route the signed gate job to the Mac that holds the merge base's sealed receipt (#2335).
//!
//! A reusable base receipt is admissible only on the Mac that produced it (#1884, #1918): its
//! [`super::reuse::BaseReuseKey`] carries that Mac's host identity. With two gate Macs sharing one
//! runner label, a merge group landed on the other Mac about half the time and re-ran its base in
//! full (#2335: run 43611538719 on `cloudmac-gate` missed the `d0622ff` receipt that
//! `carrick-m4` published). `route` runs in `authorize`, before any Mac is chosen: it finds the
//! base's `signed-base-reuse-<base>-*` artifacts from trusted main runs, reads each seal's
//! `host_identity.runner_name`, and routes the gate to that Mac's own label
//! (`carrick-signed-gate-<runner name>`), listed in [`RUNNERS_FILE`]. Anything else, including any
//! lookup failure, routes to the shared label exactly as before: routing only saves time, and
//! `reuse-lookup` on the Mac still verifies everything.
//!
//! A per-Mac route must never strand the required gate (#2341 review): the workflow token can't
//! list runners, so a Mac is routable only with evidence it can read. It served a `gate` job within
//! [`LIVE_WINDOW_SECS`], and no gate job on its own label has sat queued for longer than
//! [`STRANDED_AFTER_SECS`] or ended without starting within that window (which catches an offline
//! Mac and a missing label alike).
//!
//! Recovery for a gate already routed when its Mac goes away (#2341 re-review): GitHub can't move a
//! queued job, so `watchdog` (a hosted job beside the gate) cancels the run when a routed gate hasn't
//! started within [`WATCHDOG_SECS`]. The group fails in minutes instead of waiting out GitHub's 24 h
//! queue limit, and its never-started job is the evidence that sends the re-queued group to the
//! shared label.
use super::{Request, RequestKind};
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::path::Path;

/// The labels every gate Mac carries: the shared route.
pub const SHARED_LABELS: [&str; 4] = ["self-hosted", "macOS", "ARM64", "carrick-signed-gate"];
/// Runner names that carry their own `carrick-signed-gate-<name>` label, one per line.
pub const RUNNERS_FILE: &str = ".github/signed-gate-runners.txt";
/// A Mac is live when it started a gate job this recently.
pub const LIVE_WINDOW_SECS: u64 = 12 * 3600;
/// A gate job queued this long on a per-Mac label means that label isn't being served.
pub const STRANDED_AFTER_SECS: u64 = 15 * 60;
/// How long `watchdog` lets a routed gate wait for its Mac before cancelling the run.
pub const WATCHDOG_SECS: u64 = 20 * 60;

/// `secs` since the Unix epoch as GitHub's `YYYY-MM-DDTHH:MM:SSZ`, so timestamps compare as strings.
pub fn iso_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Whether `runner` may receive a routed gate, judged from recent `gate` jobs (`runner_name`,
/// `status`, `started_at`, `created_at`, `labels`): `Err(reason)` when it can't be shown to be served.
pub fn availability(runner: &str, gate_jobs: &[Value], now: u64) -> Result<(), String> {
    let label = format!("carrick-signed-gate-{runner}");
    let stranded_before = iso_utc(now.saturating_sub(STRANDED_AFTER_SECS));
    let live_since = iso_utc(now.saturating_sub(LIVE_WINDOW_SECS));
    let stranded = gate_jobs.iter().any(|job| {
        let on_label = job["labels"]
            .as_array()
            .is_some_and(|labels| labels.iter().any(|l| l.as_str() == Some(label.as_str())));
        let waited = job["status"] == "queued"
            && job["created_at"]
                .as_str()
                .is_some_and(|t| t < stranded_before.as_str());
        // A routed gate the watchdog cancelled (or that ended any other way) before it started.
        let never_started = job["status"] == "completed" && job["started_at"].as_str().is_none();
        on_label && (waited || never_started)
    });
    if stranded {
        return Err(format!(
            "a gate job for {label} waited over {} min or ended unstarted: that label isn't being served",
            STRANDED_AFTER_SECS / 60
        ));
    }
    let live = gate_jobs.iter().any(|job| {
        job["runner_name"].as_str() == Some(runner)
            && job["started_at"]
                .as_str()
                .is_some_and(|t| t >= live_since.as_str())
    });
    if live {
        Ok(())
    } else {
        Err(format!(
            "{runner} started no gate job in the last {} h",
            LIVE_WINDOW_SECS / 3600
        ))
    }
}

/// Where the gate job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The Mac whose sealed base receipt run `run_id` published.
    Mac { runner: String, run_id: u64 },
    /// The shared label, and why.
    Shared(String),
}

impl Route {
    /// The job's `runs-on` labels.
    pub fn labels(&self) -> Vec<String> {
        let mut labels: Vec<String> = SHARED_LABELS.iter().map(|s| (*s).to_owned()).collect();
        if let Route::Mac { runner, .. } = self {
            labels.pop();
            labels.push(format!("carrick-signed-gate-{runner}"));
        }
        labels
    }
}

/// Runner names in [`RUNNERS_FILE`] (`#` comments and blank lines ignored).
pub fn routable_runners(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| valid_runner(l))
        .map(str::to_owned)
        .collect()
}

fn valid_runner(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}

/// Decide the route. `runs` are signed-gate workflow runs for the base SHA; `artifacts` lists a
/// run's artifacts; `seal_runner` downloads one artifact and returns its seal's runner name.
pub fn decide(
    request: &Request,
    runs: &[Value],
    routable: &[String],
    mut artifacts: impl FnMut(u64) -> Result<Vec<Value>, String>,
    mut seal_runner: impl FnMut(u64, &str) -> Result<String, String>,
    mut available: impl FnMut(&str) -> Result<(), String>,
) -> Route {
    if request.kind == RequestKind::Main {
        return Route::Shared("a main request runs no base side".into());
    }
    let Ok(base) = super::sha(&request.base) else {
        return Route::Shared("the request's base is not a full SHA".into());
    };
    let prefix = format!("signed-base-reuse-{base}-");
    let mut trusted: Vec<&Value> = runs
        .iter()
        .filter(|run| run["conclusion"] == "success" && super::reuse::trusted_reuse_run(run, &base))
        .collect();
    trusted.sort_by_key(|run| std::cmp::Reverse(run["id"].as_u64().unwrap_or(0)));
    let mut last = format!("no trusted main run published a sealed receipt for {base}");
    for run in trusted {
        let Some(run_id) = run["id"].as_u64().filter(|id| *id > 0) else {
            continue;
        };
        let listed = match artifacts(run_id) {
            Ok(listed) => listed,
            Err(e) => {
                last = format!("cannot list run {run_id}'s artifacts: {e}");
                continue;
            }
        };
        for artifact in listed {
            let Some(name) = artifact["name"].as_str().filter(|n| n.starts_with(&prefix)) else {
                continue;
            };
            if artifact["expired"].as_bool() != Some(false) {
                last = format!("run {run_id}'s {name} has expired");
                continue;
            }
            match seal_runner(run_id, name) {
                Ok(runner) if valid_runner(&runner) && routable.contains(&runner) => {
                    match available(&runner) {
                        Ok(()) => return Route::Mac { runner, run_id },
                        Err(why) => last = why,
                    }
                }
                Ok(runner) => {
                    last = format!(
                        "run {run_id}'s receipt is from runner {runner:?}, which has no routable label in {RUNNERS_FILE}"
                    );
                }
                Err(e) => last = format!("cannot read run {run_id}'s {name} seal: {e}"),
            }
        }
    }
    Route::Shared(last)
}

/// What the watchdog does about a run's `gate` job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Watch {
    /// Nothing to watch: it started, ended, or runs on the shared label.
    Done(String),
    /// A routed gate is still queued, within the limit.
    Wait,
    /// A routed gate waited past the limit: cancel the run.
    Cancel(String),
}

/// The watchdog's decision for `gate` (a jobs-API row, or `None` before GitHub lists it).
pub fn watch_decision(gate: Option<&Value>, now: u64, limit_secs: u64) -> Watch {
    let Some(job) = gate else {
        return Watch::Wait;
    };
    let routed = job["labels"].as_array().and_then(|labels| {
        labels
            .iter()
            .filter_map(Value::as_str)
            .find(|l| l.starts_with("carrick-signed-gate-"))
            .map(str::to_owned)
    });
    let Some(label) = routed else {
        return Watch::Done("the gate runs on the shared label".into());
    };
    if job["status"] != "queued" || job["started_at"].as_str().is_some() {
        return Watch::Done(format!("the gate on {label} has started"));
    }
    let deadline = iso_utc(now.saturating_sub(limit_secs));
    match job["created_at"].as_str() {
        Some(created) if created < deadline.as_str() => Watch::Cancel(format!(
            "the gate has waited over {} min for {label}, which no runner is serving; cancelling the run so the \
             group fails now and the re-queued group routes to the shared label",
            limit_secs / 60
        )),
        _ => Watch::Wait,
    }
}

/// `signed-gate watchdog`: watch run `run_id`'s `gate` job; cancel the run when a routed gate hasn't
/// started within `limit_secs`. Exits non-zero after cancelling.
pub fn watchdog(run_id: u64, limit_secs: u64, poll_secs: u64) -> Result<(), super::ReceiptError> {
    let repo = crate::ci_scaler::REPOSITORY;
    let started = std::time::Instant::now();
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let jobs = super::api(&format!(
            "repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"
        ));
        let gate = jobs
            .as_ref()
            .ok()
            .and_then(|v| v["jobs"].as_array().cloned())
            .and_then(|jobs| jobs.into_iter().find(|job| job["name"] == "gate"));
        match watch_decision(gate.as_ref(), now, limit_secs) {
            Watch::Done(why) => {
                eprintln!("signed-gate watchdog: {why}");
                return Ok(());
            }
            Watch::Cancel(why) => {
                eprintln!("signed-gate watchdog: {why}");
                super::checked(
                    "gh",
                    &["run", "cancel", &run_id.to_string(), "--repo", repo],
                    None,
                )?;
                return Err(super::fail(why));
            }
            Watch::Wait => {}
        }
        // A gate GitHub never lists, or a jobs API that keeps failing, ends the watch too.
        if started.elapsed().as_secs() > limit_secs + 600 {
            eprintln!(
                "signed-gate watchdog: no routed gate to watch after {} min; stopping",
                started.elapsed().as_secs() / 60
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(poll_secs.max(1)));
    }
}

/// The runner name a downloaded reuse package's `base-seal.json` records.
pub fn seal_runner_name(dir: &Path) -> Result<String, String> {
    let seal: super::BaseSeal = super::read_json(&dir.join(super::BASE_SEAL))
        .and_then(|v| serde_json::from_value(v).map_err(|e| super::fail(e.to_string())))
        .map_err(|e| e.to_string())?;
    seal.reuse
        .map(|reuse| reuse.key.host_identity.runner_name)
        .ok_or_else(|| "the seal has no reuse block".to_owned())
}

/// `signed-gate route`: decide the gate's runner and write `runs_on=<json labels>` to
/// `github_output` (and stdout). It never fails on a lookup: any doubt is the shared route.
pub fn route(
    root: &Path,
    request_path: &Path,
    github_output: Option<&Path>,
) -> Result<(), super::ReceiptError> {
    let request: Request = serde_json::from_value(super::read_json(request_path)?)
        .map_err(|e| super::fail(e.to_string()))?;
    let routable = fs::read_to_string(root.join(RUNNERS_FILE))
        .map(|text| routable_runners(&text))
        .unwrap_or_default();
    let repo = crate::ci_scaler::REPOSITORY;
    let listing = |query: &str| -> Result<Vec<Value>, String> {
        super::api(&format!(
            "repos/{repo}/actions/workflows/signed-gate.yml/runs?{query}"
        ))
        .map_err(|e| e.to_string())
        .map(|v| v["workflow_runs"].as_array().cloned().unwrap_or_default())
    };
    // Producers: pushes of the base itself, and owner dispatches on main (which may seal an older
    // main ancestor as the base; `trusted_reuse_run` admits both, #2341 review).
    let runs = super::sha(&request.base)
        .map_err(|e| e.to_string())
        .and_then(|base| {
            let mut runs = listing(&format!("head_sha={base}&per_page=100"))?;
            runs.extend(listing("event=workflow_dispatch&branch=main&per_page=50")?);
            Ok(runs)
        });
    // Availability evidence: the gate jobs of recent signed-gate runs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let gate_jobs = || -> Result<Vec<Value>, String> {
        let since = iso_utc(now.saturating_sub(LIVE_WINDOW_SECS));
        let mut jobs = Vec::new();
        for run in listing("per_page=50")? {
            if run["created_at"]
                .as_str()
                .is_none_or(|t| t < since.as_str())
            {
                continue;
            }
            let Some(id) = run["id"].as_u64() else {
                continue;
            };
            let listed = super::api(&format!("repos/{repo}/actions/runs/{id}/jobs?per_page=100"))
                .map_err(|e| e.to_string())?;
            jobs.extend(
                listed["jobs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|job| job["name"] == "gate")
                    .cloned(),
            );
        }
        Ok(jobs)
    };
    let mut evidence: Option<Result<Vec<Value>, String>> = None;
    let route = match runs {
        Err(e) => Route::Shared(format!("cannot list the base's signed-gate runs: {e}")),
        Ok(runs) => decide(
            &request,
            &runs,
            &routable,
            |run_id| {
                super::pages(
                    &format!("repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"),
                    Some("artifacts"),
                )
                .map_err(|e| e.to_string())
            },
            |run_id, name| {
                let temp = tempfile::tempdir().map_err(|e| e.to_string())?;
                let dir = temp.path().join("downloaded");
                super::checked(
                    "gh",
                    &[
                        "run",
                        "download",
                        &run_id.to_string(),
                        "--repo",
                        repo,
                        "--name",
                        name,
                        "--dir",
                        &dir.to_string_lossy(),
                    ],
                    None,
                )
                .map_err(|e| e.to_string())?;
                seal_runner_name(&dir)
            },
            |runner| match evidence.get_or_insert_with(gate_jobs) {
                Ok(jobs) => availability(runner, jobs, now),
                Err(e) => Err(format!("cannot read recent gate jobs: {e}")),
            },
        ),
    };
    let labels = serde_json::to_string(&route.labels()).map_err(|e| super::fail(e.to_string()))?;
    match &route {
        Route::Mac { runner, run_id } => eprintln!(
            "signed-gate: routing the gate to {runner} (carrick-signed-gate-{runner}): run {run_id} sealed the base receipt there"
        ),
        Route::Shared(why) => {
            eprintln!("signed-gate: routing the gate to the shared label ({why})")
        }
    }
    println!("runs_on={labels}");
    if let Some(path) = github_output {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| super::fail(format!("{}: {e}", path.display())))?;
        writeln!(file, "runs_on={labels}")
            .map_err(|e| super::fail(format!("{}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASE: &str = "d0622ff95b9c8fa936a53e4c3882d09cd06f499c";

    fn request(kind: RequestKind) -> Request {
        Request {
            kind,
            prs: vec![2301],
            sha: "f15bdc068f55dca98af003ae0806c928bc5de8ba".into(),
            base: BASE.into(),
        }
    }

    fn push_run(id: u64, sha: &str) -> Value {
        json!({"id": id, "conclusion": "success", "path": super::super::reuse::SIGNED_GATE_WORKFLOW,
            "head_branch": "main", "event": "push", "head_sha": sha,
            "repository": {"full_name": crate::ci_scaler::REPOSITORY},
            "head_repository": {"full_name": crate::ci_scaler::REPOSITORY}})
    }

    fn reuse_artifact(expired: bool) -> Value {
        json!({"name": format!("signed-base-reuse-{BASE}-8031528402cd"), "expired": expired})
    }

    fn routable() -> Vec<String> {
        routable_runners(
            "# gate Macs with their own label\ncarrick-m4\ncloudmac-gate\n\nbad name\n",
        )
    }

    fn live(_: &str) -> Result<(), String> {
        Ok(())
    }

    /// `decide` for a merge group with one push producer, `artifacts`, a sealed `runner` and `available`.
    fn decide_one(
        artifacts: Result<Vec<Value>, String>,
        runner: Result<String, String>,
        available: impl FnMut(&str) -> Result<(), String>,
    ) -> Route {
        decide(
            &request(RequestKind::MergeGroup),
            &[push_run(1, BASE)],
            &routable(),
            |_| artifacts.clone(),
            |_, _| runner.clone(),
            available,
        )
    }

    #[test]
    fn a_group_goes_to_the_mac_that_sealed_its_base() {
        // #2335: run 43606507691 (push, d0622ff) sealed its receipt on carrick-m4.
        let route = decide(
            &request(RequestKind::MergeGroup),
            &[push_run(43606507691, BASE)],
            &routable(),
            |_| {
                Ok(vec![
                    json!({"name": "signed-baseline-x", "expired": false}),
                    reuse_artifact(false),
                ])
            },
            |run, name| {
                assert_eq!(run, 43606507691);
                assert!(name.starts_with("signed-base-reuse-"));
                Ok("carrick-m4".into())
            },
            live,
        );
        assert_eq!(
            route,
            Route::Mac {
                runner: "carrick-m4".into(),
                run_id: 43606507691
            }
        );
        assert_eq!(
            route.labels(),
            [
                "self-hosted",
                "macOS",
                "ARM64",
                "carrick-signed-gate-carrick-m4"
            ]
        );
    }

    #[test]
    fn the_newest_trusted_run_wins() {
        let route = decide(
            &request(RequestKind::PullRequest),
            &[push_run(10, BASE), push_run(20, BASE)],
            &routable(),
            |_| Ok(vec![reuse_artifact(false)]),
            |run, _| {
                Ok(if run == 20 {
                    "cloudmac-gate".into()
                } else {
                    "carrick-m4".into()
                })
            },
            live,
        );
        assert_eq!(
            route,
            Route::Mac {
                runner: "cloudmac-gate".into(),
                run_id: 20
            }
        );
    }

    #[test]
    fn every_doubt_routes_to_the_shared_label() {
        let shared = |route: Route| matches!(route, Route::Shared(_));
        let good = || Ok(vec![reuse_artifact(false)]);
        let m4 = || Ok("carrick-m4".to_owned());
        // A main request has no base side.
        assert!(shared(decide(
            &request(RequestKind::Main),
            &[push_run(1, BASE)],
            &routable(),
            |_| good(),
            |_, _| m4(),
            live
        )));
        // An untrusted producer: a merge group, a push of another SHA, a failed run.
        let mut group = push_run(1, BASE);
        group["event"] = json!("merge_group");
        let mut failed = push_run(2, BASE);
        failed["conclusion"] = json!("failure");
        for run in [group, push_run(3, "c".repeat(40).as_str()), failed] {
            assert!(shared(decide(
                &request(RequestKind::MergeGroup),
                &[run],
                &routable(),
                |_| good(),
                |_, _| m4(),
                live
            )));
        }
        // An expired artifact, a runner with no listed label, malformed runners, failed reads.
        assert!(shared(decide_one(
            Ok(vec![reuse_artifact(true)]),
            m4(),
            live
        )));
        for runner in ["some-new-mac", "carrick m4", "-x", ""] {
            assert!(shared(decide_one(good(), Ok(runner.into()), live)));
        }
        assert!(shared(decide_one(
            good(),
            Err("download failed".into()),
            live
        )));
        assert!(shared(decide_one(Err("api".into()), m4(), live)));
        // A reuse artifact for another base is not this one.
        assert!(shared(decide_one(
            Ok(vec![
                json!({"name": "signed-base-reuse-cccc-1", "expired": false})
            ]),
            m4(),
            live
        )));
        assert_eq!(
            Route::Shared("x".into()).labels(),
            ["self-hosted", "macOS", "ARM64", "carrick-signed-gate"]
        );
    }

    #[test]
    fn an_unserved_mac_is_never_routed_to() {
        // #2341 review: an offline Mac or one that lost its label must not strand the gate.
        let now = 1_794_700_000;
        let job = |runner: &str, status: &str, started: Option<u64>, created: u64, label: &str| {
            json!({"name": "gate", "runner_name": runner, "status": status,
                "started_at": started.map(iso_utc), "created_at": iso_utc(created), "labels": [label]})
        };
        let m4 = "carrick-signed-gate-carrick-m4";
        // Live: started a gate job 2 h ago.
        let recent = job("carrick-m4", "completed", Some(now - 7200), now - 7300, "x");
        assert_eq!(
            availability("carrick-m4", std::slice::from_ref(&recent), now),
            Ok(())
        );
        // Not live: its last gate job started 13 h ago, or never.
        let old = job(
            "carrick-m4",
            "completed",
            Some(now - 13 * 3600),
            now - 13 * 3600,
            "x",
        );
        assert!(availability("carrick-m4", &[old], now).is_err());
        assert!(availability("carrick-m4", &[], now).is_err());
        // Stranded: a gate job has waited 20 min on its own label, though it was live earlier.
        let jobs = [recent.clone(), job("", "queued", None, now - 1200, m4)];
        assert!(
            availability("carrick-m4", &jobs, now)
                .unwrap_err()
                .contains("isn't being served")
        );
        // A job queued for only 5 min is not yet a stranding.
        let jobs = [recent, job("", "queued", None, now - 300, m4)];
        assert_eq!(availability("carrick-m4", &jobs, now), Ok(()));
        // decide() falls back to the shared label when the Mac isn't available.
        let route = decide_one(
            Ok(vec![reuse_artifact(false)]),
            Ok("carrick-m4".into()),
            |_| Err("carrick-m4 started no gate job in the last 12 h".into()),
        );
        assert!(
            matches!(route, Route::Shared(ref why) if why.contains("no gate job")),
            "{route:?}"
        );
    }

    #[test]
    fn a_routed_gate_that_never_started_makes_its_mac_unroutable() {
        // The watchdog cancelled it (or it ended some other way) before any runner took it.
        let now = 1_794_700_000;
        let jobs = [
            json!({"name": "gate", "runner_name": "carrick-m4", "status": "completed",
                "started_at": iso_utc(now - 3600), "created_at": iso_utc(now - 3700), "labels": ["x"]}),
            json!({"name": "gate", "runner_name": "", "status": "completed", "conclusion": "cancelled",
                "started_at": null, "created_at": iso_utc(now - 1800),
                "labels": ["carrick-signed-gate-carrick-m4"]}),
        ];
        assert!(availability("carrick-m4", &jobs, now).is_err());
        assert_eq!(
            availability(
                "cloudmac-gate",
                &[json!({"name": "gate", "runner_name": "cloudmac-gate",
            "status": "completed", "started_at": iso_utc(now - 60), "created_at": iso_utc(now - 90), "labels": ["x"]})],
                now
            ),
            Ok(())
        );
    }

    #[test]
    fn the_watchdog_cancels_only_a_routed_gate_past_its_limit() {
        let now = 1_794_700_000;
        let gate = |labels: &[&str], status: &str, started: Option<u64>, created: u64| {
            json!({"name": "gate", "status": status, "labels": labels,
                "started_at": started.map(iso_utc), "created_at": iso_utc(created)})
        };
        let routed = [
            "self-hosted",
            "macOS",
            "ARM64",
            "carrick-signed-gate-carrick-m4",
        ];
        assert_eq!(watch_decision(None, now, WATCHDOG_SECS), Watch::Wait);
        assert!(matches!(
            watch_decision(
                Some(&gate(&SHARED_LABELS, "queued", None, now - 3600)),
                now,
                WATCHDOG_SECS
            ),
            Watch::Done(_)
        ));
        assert!(matches!(
            watch_decision(
                Some(&gate(&routed, "in_progress", Some(now - 60), now - 3600)),
                now,
                WATCHDOG_SECS
            ),
            Watch::Done(_)
        ));
        assert_eq!(
            watch_decision(
                Some(&gate(&routed, "queued", None, now - 600)),
                now,
                WATCHDOG_SECS
            ),
            Watch::Wait
        );
        assert!(matches!(
            watch_decision(
                Some(&gate(&routed, "queued", None, now - 1500)),
                now,
                WATCHDOG_SECS
            ),
            Watch::Cancel(_)
        ));
    }

    #[test]
    fn an_owner_dispatch_that_sealed_an_older_ancestor_is_a_producer() {
        // #2341 review (P2): a dispatch on main may seal an older main ancestor as the base.
        let mut dispatch = push_run(7, "e".repeat(40).as_str());
        dispatch["event"] = json!("workflow_dispatch");
        dispatch["actor"] = json!({"login": "tjfontaine"});
        dispatch["triggering_actor"] = json!({"login": "tjfontaine"});
        let route = decide(
            &request(RequestKind::MergeGroup),
            &[dispatch],
            &routable(),
            |_| Ok(vec![reuse_artifact(false)]),
            |_, _| Ok("cloudmac-gate".into()),
            live,
        );
        assert_eq!(
            route,
            Route::Mac {
                runner: "cloudmac-gate".into(),
                run_id: 7
            }
        );
    }

    #[test]
    fn iso_utc_matches_github_timestamps() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_794_660_725), "2026-11-14T12:52:05Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn a_real_seal_names_its_runner() {
        let dir = tempfile::tempdir().unwrap();
        let seal = json!({"base": BASE, "files": {}, "reuse": {"key": {"schema_version": 1, "base_sha": BASE,
            "host_identity": {"runner_name": "carrick-m4", "hardware_model": "Mac16,10", "product_build": "25B78"},
            "fixture_archive_sha256": "a", "fixture_manifest_sha256": "b", "fixture_inputs_sha256": "c",
            "fixture_content_sha256": "d", "rust_toolchain_sha256": "e", "entitlements_sha256": "f",
            "hypervisor_entitlement": true, "dof_present": true, "profile": "signed", "phase": "signed"},
            "key_sha256": "k", "source_run_id": 1}});
        std::fs::write(dir.path().join(super::super::BASE_SEAL), seal.to_string()).unwrap();
        assert_eq!(seal_runner_name(dir.path()), Ok("carrick-m4".into()));
        std::fs::write(
            dir.path().join(super::super::BASE_SEAL),
            json!({"base": BASE, "files": {}}).to_string(),
        )
        .unwrap();
        assert!(seal_runner_name(dir.path()).is_err());
    }

    #[test]
    fn the_runners_file_lists_only_valid_names() {
        assert_eq!(routable(), ["carrick-m4", "cloudmac-gate"]);
    }
}
