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
use super::{Request, RequestKind};
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::path::Path;

/// The labels every gate Mac carries: the shared route.
pub const SHARED_LABELS: [&str; 4] = ["self-hosted", "macOS", "ARM64", "carrick-signed-gate"];
/// Runner names that carry their own `carrick-signed-gate-<name>` label, one per line.
pub const RUNNERS_FILE: &str = ".github/signed-gate-runners.txt";

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
                    return Route::Mac { runner, run_id };
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
    let runs = super::sha(&request.base)
        .ok()
        .map(|base| {
            super::pages(
                &format!(
                    "repos/{}/actions/workflows/signed-gate.yml/runs?head_sha={base}&per_page=100",
                    crate::ci_scaler::REPOSITORY
                ),
                Some("workflow_runs"),
            )
        })
        .transpose();
    let route = match runs {
        Err(e) => Route::Shared(format!("cannot list the base's signed-gate runs: {e}")),
        Ok(runs) => decide(
            &request,
            &runs.unwrap_or_default(),
            &routable,
            |run_id| {
                super::pages(
                    &format!(
                        "repos/{}/actions/runs/{run_id}/artifacts?per_page=100",
                        crate::ci_scaler::REPOSITORY
                    ),
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
                        crate::ci_scaler::REPOSITORY,
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
        let ok_artifacts = |_| Ok(vec![reuse_artifact(false)]);
        // A main request has no base side.
        assert!(shared(decide(
            &request(RequestKind::Main),
            &[push_run(1, BASE)],
            &routable(),
            ok_artifacts,
            |_, _| Ok("carrick-m4".into())
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
                ok_artifacts,
                |_, _| Ok("carrick-m4".into())
            )));
        }
        // An expired artifact, a runner with no label, a malformed runner, unreadable seal and listing.
        assert!(shared(decide(
            &request(RequestKind::MergeGroup),
            &[push_run(1, BASE)],
            &routable(),
            |_| Ok(vec![reuse_artifact(true)]),
            |_, _| Ok("carrick-m4".into())
        )));
        for runner in ["some-new-mac", "carrick m4", "-x", ""] {
            assert!(shared(decide(
                &request(RequestKind::MergeGroup),
                &[push_run(1, BASE)],
                &routable(),
                ok_artifacts,
                |_, _| Ok(runner.into())
            )));
        }
        assert!(shared(decide(
            &request(RequestKind::MergeGroup),
            &[push_run(1, BASE)],
            &routable(),
            ok_artifacts,
            |_, _| Err("download failed".into())
        )));
        assert!(shared(decide(
            &request(RequestKind::MergeGroup),
            &[push_run(1, BASE)],
            &routable(),
            |_| Err("api".into()),
            |_, _| Ok("carrick-m4".into())
        )));
        // A reuse artifact for another base is not this one.
        assert!(shared(decide(
            &request(RequestKind::MergeGroup),
            &[push_run(1, BASE)],
            &routable(),
            |_| Ok(vec![
                json!({"name": "signed-base-reuse-cccc-1", "expired": false})
            ]),
            |_, _| Ok("carrick-m4".into())
        )));
        assert_eq!(
            Route::Shared("x".into()).labels(),
            ["self-hosted", "macOS", "ARM64", "carrick-signed-gate"]
        );
    }

    #[test]
    fn the_runners_file_lists_only_valid_names() {
        assert_eq!(routable(), ["carrick-m4", "cloudmac-gate"]);
    }
}
