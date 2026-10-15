//! GitHub REST access through the director-authenticated `gh` CLI, shared by
//! the Willow and cloudmac controllers. Output is parsed, never logged.
use super::*;
use serde_json::{Value, json};

const MERGE_QUEUE_QUERY: &str = "query { repository(owner: \"carrick-sh\", name: \"carrick\") { mergeQueue(branch: \"main\") { entries(first: 100) { pageInfo { hasNextPage } nodes { position headCommit { oid } pullRequest { number headRepository { nameWithOwner } } } } } } }";

pub(super) struct Github;
impl Github {
    pub(super) fn request(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError> {
        let mut cmd = Command::new("gh");
        cmd.args(["api", "--method", method, endpoint]);
        if paginate {
            cmd.args(["--paginate", "--slurp"]);
        }
        let input = if let Some(body) = body {
            cmd.args(["--input", "-"]);
            serde_json::to_vec(&body)?
        } else {
            vec![]
        };
        let output = execute(&mut cmd, &input, Duration::from_secs(60))?;
        if method == "DELETE"
            || (method == "POST" && endpoint.ends_with("/cancel") && output.is_empty())
        {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&output)?)
    }
    /// Runs of one workflow file only: demand never lists every run.
    pub(super) fn workflow_runs(
        &self,
        admission: &Admission,
        status: &str,
    ) -> Result<Vec<Value>, ScalerError> {
        let data = self.request(
            "GET",
            &format!(
                "repos/{REPOSITORY}/actions/workflows/{}/runs?status={status}&per_page=100",
                admission.workflow_file()
            ),
            None,
            true,
        )?;
        pages(&data, "workflow_runs")
    }
    pub(super) fn jobs(&self, run: &Value) -> Result<Vec<Value>, ScalerError> {
        let id = run["id"].as_u64().ok_or(ScalerError::External("run id"))?;
        let attempt = run["run_attempt"]
            .as_u64()
            .ok_or(ScalerError::External("run attempt"))?;
        let data = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{id}/attempts/{attempt}/jobs?per_page=100"),
            None,
            true,
        )?;
        pages(&data, "jobs")
    }
    /// Queued jobs with exactly `labels` in runs `admission` serves.
    pub(super) fn demand(
        &self,
        admission: &Admission,
        labels: &[&str],
    ) -> Result<Vec<JobKey>, ScalerError> {
        let mut demand: Vec<_> = self
            .queued_demand(admission, labels)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        demand.sort_by_key(|key| key.job.0);
        demand.dedup();
        Ok(demand)
    }
    /// Retain the admitted event for cloudmac scheduling; no wider admission.
    pub(super) fn mac_demand(&self) -> Result<Vec<(JobKey, String)>, ScalerError> {
        self.queued_demand(&Admission::Standing, &HVF_LABELS)
    }
    fn queued_demand(
        &self,
        admission: &Admission,
        labels: &[&str],
    ) -> Result<Vec<(JobKey, String)>, ScalerError> {
        let mut demand = Vec::new();
        for status in ["queued", "in_progress"] {
            for run in self.workflow_runs(admission, status)? {
                if !admission.admits_run(&run) {
                    continue;
                }
                for job in self.jobs(&run)? {
                    let job_labels: Vec<&str> = job["labels"]
                        .as_array()
                        .ok_or(ScalerError::External("job labels"))?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    if job["status"] == "queued" && labels_match(labels, &job_labels) {
                        demand.push((
                            JobKey {
                                run: RunId(
                                    run["id"].as_u64().ok_or(ScalerError::External("run id"))?,
                                ),
                                attempt: run["run_attempt"]
                                    .as_u64()
                                    .and_then(|n| u32::try_from(n).ok())
                                    .ok_or(ScalerError::External("attempt"))?,
                                job: JobId(
                                    job["id"].as_u64().ok_or(ScalerError::External("job id"))?,
                                ),
                            },
                            run["event"]
                                .as_str()
                                .ok_or(ScalerError::External("run event"))?
                                .to_owned(),
                        ));
                    }
                }
            }
        }
        demand.sort_by_key(|(key, _)| key.job.0);
        demand.dedup();
        Ok(demand)
    }
    /// Mint one-use JIT material for `name`. The returned encoded config is
    /// the only GitHub-derived secret a runner host ever receives.
    pub(super) fn generate_jit(
        &self,
        name: &str,
        group: u64,
        labels: &[&str],
    ) -> Result<(RunnerId, String), ScalerError> {
        let config = self.request(
            "POST",
            &format!("repos/{REPOSITORY}/actions/runners/generate-jitconfig"),
            Some(
                json!({"name":name,"runner_group_id":group,"labels":labels,"work_folder":"_work"}),
            ),
            false,
        )?;
        let id = RunnerId(
            config["runner"]["id"]
                .as_u64()
                .ok_or(ScalerError::External("JIT runner ID"))?,
        );
        let jit = config["encoded_jit_config"]
            .as_str()
            .ok_or(ScalerError::External("JIT config"))?
            .to_owned();
        Ok((id, jit))
    }
    /// Re-read the reserved run immediately before minting a runner and
    /// return the policy its hook enforces: the same admission, the same
    /// attempt, and for a merge group only pull requests whose heads live in
    /// this repository. The runner is bound to this exact run and SHA.
    pub(super) fn vet(&self, admission: &Admission, key: JobKey) -> Result<JobPolicy, ScalerError> {
        Self::vet_inner(admission, key, true, |method, endpoint, body, paginate| {
            self.request(method, endpoint, body, paginate)
        })
    }

    /// Assigned hooks cannot defer without failing their job. Keep all normal
    /// admission checks, but serve them regardless of queue depth.
    pub(super) fn vet_assignment(&self, key: JobKey) -> Result<JobPolicy, ScalerError> {
        Self::vet_inner(
            &Admission::Standing,
            key,
            false,
            |method, endpoint, body, paginate| self.request(method, endpoint, body, paginate),
        )
    }

    fn vet_inner(
        admission: &Admission,
        key: JobKey,
        supersession: bool,
        mut request: impl FnMut(&str, &str, Option<Value>, bool) -> Result<Value, ScalerError>,
    ) -> Result<JobPolicy, ScalerError> {
        let run = request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{}", key.run.0),
            None,
            false,
        )?;
        if !admission.admits_run(&run)
            || run["id"].as_u64() != Some(key.run.0)
            || run["run_attempt"].as_u64() != Some(u64::from(key.attempt))
        {
            return Err(ScalerError::Guard("reserved run is no longer admitted"));
        }
        let sha = run["head_sha"]
            .as_str()
            .ok_or(ScalerError::External("run head SHA"))?
            .to_ascii_lowercase();
        if run["event"] == "merge_group" {
            let mut queue = Value::Null;
            confirm_merge_group(&sha, || {
                queue = request(
                    "POST",
                    "graphql",
                    Some(json!({ "query": MERGE_QUEUE_QUERY })),
                    false,
                )?;
                Ok(queue.clone())
            })?;
            // One page and at most five comparisons per reservation vet.
            // Missing/failed observations disable supersession only.
            if !supersession {
                return Ok(JobPolicy::Bound(RunBinding {
                    run: key.run,
                    attempt: key.attempt,
                    sha,
                }));
            }
            let observed = request(
                "GET",
                &format!(
                    "repos/{REPOSITORY}/actions/workflows/{}/runs?event=merge_group&per_page=100",
                    admission.workflow_file()
                ),
                None,
                false,
            );
            if let Ok(observed) = observed
                && let Some(runs) = observed["workflow_runs"].as_array()
                && let Some(successor) = superseded_group(&run, &queue, runs, |base, head| {
                    request(
                        "GET",
                        &format!("repos/{REPOSITORY}/compare/{base}...{head}"),
                        None,
                        false,
                    )
                })
            {
                return Err(ScalerError::SupersededMergeGroup { successor });
            }
        }
        Ok(match admission {
            Admission::Pilot { sha } => JobPolicy::Pilot { sha: sha.clone() },
            Admission::Standing => JobPolicy::Bound(RunBinding {
                run: key.run,
                attempt: key.attempt,
                sha,
            }),
        })
    }
    pub(super) fn cancel_run(&self, run: RunId) -> Result<(), ScalerError> {
        self.request(
            "POST",
            &format!("repos/{REPOSITORY}/actions/runs/{}/cancel", run.0),
            None,
            false,
        )?;
        Ok(())
    }
    pub(super) fn job(&self, id: JobId) -> Result<Value, ScalerError> {
        self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/jobs/{}", id.0),
            None,
            false,
        )
    }
    pub(super) fn assignment(
        &self,
        row: &mut impl RunnerRegistration,
    ) -> Result<Assignment, ScalerError> {
        if row.runner().is_none() {
            let data = self.request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
                None,
                true,
            )?;
            let recovered = recover_registration(&*row, &pages(&data, "runners")?)?;
            row.set_runner(recovered);
        }
        let Some(runner) = row.runner() else {
            return Ok(Assignment::Unassigned);
        };
        // Only the reserved job is examined: the hook binds the runner to
        // its vetted run, so any other assignment is killed before a step.
        let job = self.job(row.assigned().unwrap_or(row.key().job))?;
        if job["runner_id"].as_u64() == Some(runner.0) {
            row.set_assigned(JobId(
                job["id"]
                    .as_u64()
                    .ok_or(ScalerError::External("assigned id"))?,
            ));
            return Ok(if job["status"] == "completed" {
                Assignment::Completed
            } else {
                Assignment::Busy
            });
        }
        let runners = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
            None,
            true,
        )?;
        for registered in pages(&runners, "runners")? {
            if registered["id"].as_u64() == Some(runner.0) {
                return Ok(if registered["busy"] == true {
                    Assignment::Busy
                } else {
                    Assignment::Unassigned
                });
            }
        }
        // Registration gone and the reserved job never ran on it: the runner
        // ended (rejected, killed or exited). The caller confirms the runner
        // process is gone before destroying anything.
        Ok(Assignment::Unknown)
    }
    pub(super) fn remove_runner(&self, row: &impl RunnerRegistration) -> Result<(), ScalerError> {
        let runners = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
            None,
            true,
        )?;
        let runners = pages(&runners, "runners")?;
        let Some(id) = row.runner().or(recover_registration(row, &runners)?) else {
            return Ok(());
        };
        if let Some(runner) = runners.into_iter().find(|r| r["id"].as_u64() == Some(id.0)) {
            if runner["name"] != row.name() || runner["busy"] != false {
                return Err(ScalerError::Guard(
                    "runner identity changed or still busy; defer removal",
                ));
            }
            self.request(
                "DELETE",
                &format!("repos/{REPOSITORY}/actions/runners/{}", id.0),
                None,
                false,
            )?;
        }
        Ok(())
    }
}

fn confirm_merge_group(
    sha: &str,
    mut observe: impl FnMut() -> Result<Value, ScalerError>,
) -> Result<(), ScalerError> {
    match vet_merge_group(&observe()?, sha) {
        Err(ScalerError::StaleMergeGroup) => vet_merge_group(&observe()?, sha),
        result => result,
    }
}

fn vet_merge_group(queue: &Value, sha: &str) -> Result<(), ScalerError> {
    if queue.get("errors").is_some() {
        return Err(ScalerError::External("merge queue GraphQL errors"));
    }
    let entries = &queue["data"]["repository"]["mergeQueue"]["entries"];
    let nodes = entries["nodes"]
        .as_array()
        .ok_or(ScalerError::External("merge queue entries"))?;
    if !nodes.iter().any(|node| node["headCommit"]["oid"] == sha) {
        return match entries["pageInfo"]["hasNextPage"].as_bool() {
            Some(false) => Err(ScalerError::StaleMergeGroup),
            Some(true) => Err(ScalerError::External(
                "merge group is outside the visible queue",
            )),
            None => Err(ScalerError::External("merge queue pagination")),
        };
    }
    if !merge_group_heads_trusted(queue, sha) {
        return Err(ScalerError::Guard(
            "merge group contains a pull request from another repository, or is not queued",
        ));
    }
    Ok(())
}
pub(super) fn recover_registration(
    row: &impl RunnerRegistration,
    runners: &[Value],
) -> Result<Option<RunnerId>, ScalerError> {
    let matches: Vec<&Value> = runners.iter().filter(|r| r["name"] == row.name()).collect();
    match matches.as_slice() {
        [] => Ok(None),
        [runner] => Ok(Some(RunnerId(
            runner["id"]
                .as_u64()
                .ok_or(ScalerError::External("recovered runner ID"))?,
        ))),
        _ => Err(ScalerError::Guard(
            "duplicate registration identity; quarantine",
        )),
    }
}
fn pages(data: &Value, field: &str) -> Result<Vec<Value>, ScalerError> {
    let mut result = Vec::new();
    for page in data
        .as_array()
        .ok_or(ScalerError::External("API pagination"))?
    {
        result.extend(
            page[field]
                .as_array()
                .ok_or(ScalerError::External("API page"))?
                .iter()
                .cloned(),
        );
    }
    Ok(result)
}

/// Conservative supersession proof; API ambiguity preserves ordinary service.
fn superseded_group(
    run: &Value,
    queue: &Value,
    runs: &[Value],
    mut compare: impl FnMut(&str, &str) -> Result<Value, ScalerError>,
) -> Option<String> {
    if run["event"] != "merge_group" || queue.get("errors").is_some() {
        return None;
    }
    let entries = &queue["data"]["repository"]["mergeQueue"]["entries"];
    if entries["pageInfo"]["hasNextPage"] != false {
        return None;
    }
    let nodes = entries["nodes"].as_array()?;
    // A malformed or non-contiguous queue is not depth evidence.
    let mut ordered: Vec<_> = nodes.iter().collect();
    ordered.sort_by_key(|node| node["position"].as_u64());
    for (index, node) in ordered.iter().enumerate() {
        if node["position"].as_u64()? != u64::try_from(index).ok()? + 1
            || !node["headCommit"]["oid"].as_str().is_some_and(full_sha)
        {
            return None;
        }
    }
    let base = run["head_sha"].as_str()?.to_ascii_lowercase();
    let depth = ordered.iter().position(|node| {
        node["headCommit"]["oid"]
            .as_str()
            .is_some_and(|sha| sha.eq_ignore_ascii_case(&base))
    })?;
    let mut candidates = Vec::new();
    for node in ordered.iter().skip(depth + 1).rev() {
        let head = node["headCommit"]["oid"].as_str()?.to_ascii_lowercase();
        if !merge_group_heads_trusted(queue, node["headCommit"]["oid"].as_str()?) {
            continue;
        }
        // Use the latest run/attempt for a SHA: an older pass cannot hide
        // a newer failure. Incomplete status information never suppresses work.
        if runs
            .iter()
            .filter(|r| {
                r["head_sha"]
                    .as_str()
                    .is_some_and(|sha| sha.eq_ignore_ascii_case(&head))
            })
            .any(|r| {
                r["id"].as_u64().is_none()
                    || r["run_attempt"].as_u64().is_none()
                    || r.get("conclusion").is_none()
            })
        {
            return None;
        }
        let latest = runs
            .iter()
            .filter(|r| {
                r["head_sha"]
                    .as_str()
                    .is_some_and(|sha| sha.eq_ignore_ascii_case(&head))
            })
            .max_by_key(|r| (r["id"].as_u64(), r["run_attempt"].as_u64()));
        if let Some(latest) = latest
            && Admission::Standing.admits_run(latest)
            && latest["event"] == "merge_group"
            && ((matches!(
                latest["status"].as_str(),
                Some("queued" | "in_progress" | "waiting" | "pending")
            ) && latest["conclusion"].is_null())
                || (latest["status"] == "completed" && latest["conclusion"] == "success"))
        {
            candidates.push(head);
        }
    }
    if candidates.len() > 5 {
        return None;
    }
    for head in candidates {
        let proof = compare(&base, &head).ok()?;
        if proof["status"] == "ahead"
            && proof["merge_base_commit"]["sha"]
                .as_str()
                .is_some_and(|sha| sha.eq_ignore_ascii_case(&base))
            && proof["base_commit"]["sha"]
                .as_str()
                .is_some_and(|sha| sha.eq_ignore_ascii_case(&base))
        {
            return Some(head.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cumulative() -> (Value, Vec<Value>) {
        let nodes: Vec<_> = (1..=3)
            .map(|n| {
                json!({"position":n,
            "headCommit":{"oid":format!("{n:040x}")},
            "pullRequest":{"headRepository":{"nameWithOwner":REPOSITORY}}})
            })
            .collect();
        let queue = json!({"data":{"repository":{"mergeQueue":{"entries":{
            "pageInfo":{"hasNextPage":false}, "nodes":nodes}}}}});
        let runs = (1..=3)
            .map(|n| {
                json!({"id":n,"run_attempt":1,"event":"merge_group",
            "head_sha":format!("{n:040x}"),"head_branch":format!("gh-readonly-queue/main/pr-{n}"),
            "status":"queued","conclusion":null,
            "path":".github/workflows/kernel-runtime.yml",
            "repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY}})
            })
            .collect();
        (queue, runs)
    }
    fn ancestry(base: &str, head: &str) -> Result<Value, ScalerError> {
        Ok(json!({"status":"ahead","merge_base_commit":{"sha":base},
            "base_commit":{"sha":base},"commits":[{"sha":head}]}))
    }
    #[test]
    fn deepest_pending_cumulative_group_only() {
        let (queue, runs) = cumulative();
        assert_eq!(
            superseded_group(&runs[0], &queue, &runs, ancestry),
            Some(format!("{:040x}", 3))
        );
        assert_eq!(
            superseded_group(&runs[1], &queue, &runs, ancestry),
            Some(format!("{:040x}", 3))
        );
        assert_eq!(superseded_group(&runs[2], &queue, &runs, ancestry), None);
    }
    #[test]
    fn failed_or_ejected_successor_restores_next_deepest() {
        let (mut queue, mut runs) = cumulative();
        runs[2]["status"] = json!("completed");
        runs[2]["conclusion"] = json!("failure");
        assert_eq!(
            superseded_group(&runs[0], &queue, &runs, ancestry),
            Some(format!("{:040x}", 2))
        );
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
        runs[2]["status"] = json!("queued");
        runs[2]["conclusion"] = Value::Null;
        queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
    }
    #[test]
    fn standing_assignment_ignores_depth_and_retains_admission() {
        let (mut queue, runs) = cumulative();
        let key = JobKey {
            run: RunId(2),
            attempt: 1,
            job: JobId(2),
        };
        for trusted in [true, false] {
            if !trusted {
                queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"][0]["pullRequest"]["headRepository"]
                    ["nameWithOwner"] = json!("fork/carrick");
            }
            let policy = Github::vet_inner(
                &Admission::Standing,
                key,
                false,
                |method, endpoint, _, _| match (method, endpoint) {
                    ("GET", "repos/carrick-sh/carrick/actions/runs/2") => Ok(runs[1].clone()),
                    ("POST", "graphql") => Ok(queue.clone()),
                    _ => panic!("actual assignment must not observe supersession: {endpoint}"),
                },
            );
            if trusted {
                assert_eq!(
                    policy.unwrap(),
                    JobPolicy::Bound(RunBinding {
                        run: key.run,
                        attempt: key.attempt,
                        sha: format!("{:040x}", 2),
                    })
                );
            } else {
                assert!(matches!(policy, Err(ScalerError::Guard(_))));
            }
        }
    }

    #[test]
    fn failed_successor_after_skip_serves_same_shallower_job() {
        let (queue, mut runs) = cumulative();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = Ledger::default();
        let keys: Vec<_> = (2..=3)
            .map(|n| JobKey {
                run: RunId(n),
                attempt: 1,
                job: JobId(n),
            })
            .collect();
        let mut select = |runs: &[Value]| {
            assignment::admit_demand(
                &mut ledger,
                &path,
                keys.clone(),
                |key| {
                    let run = &runs[usize::try_from(key.run.0 - 1).unwrap()];
                    match superseded_group(run, &queue, runs, ancestry) {
                        Some(successor) => Err(ScalerError::SupersededMergeGroup { successor }),
                        None => Ok(key),
                    }
                },
                |_| panic!("supersession must never cancel"),
            )
            .unwrap()
        };
        assert_eq!(select(&runs), Some(keys[1]));
        runs[2]["status"] = json!("completed");
        runs[2]["conclusion"] = json!("failure");
        assert_eq!(select(&runs), Some(keys[0]));
        assert!(!path.exists(), "no durable refusal during the skip");
    }

    #[test]
    fn cancelled_and_rebuilt_queue_restore_service() {
        let (mut queue, mut runs) = cumulative();
        runs[2]["status"] = json!("completed");
        runs[2]["conclusion"] = json!("cancelled");
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
        // A replacement head has no qualifying workflow yet.
        queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"][2]["headCommit"]["oid"] =
            json!("a".repeat(40));
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
    }

    #[test]
    fn supersession_normalizes_sha_case() {
        let (mut queue, mut runs) = cumulative();
        let base = "a".repeat(40);
        let head = "b".repeat(40);
        queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"][1]["headCommit"]["oid"] =
            json!(base.to_uppercase());
        queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"][2]["headCommit"]["oid"] =
            json!(head.to_uppercase());
        runs[1]["head_sha"] = json!(base);
        runs[2]["head_sha"] = json!(head);
        assert_eq!(
            superseded_group(&runs[1], &queue, &runs, |base, head| {
                assert_eq!(base, "a".repeat(40));
                assert_eq!(head, "b".repeat(40));
                Ok(
                    json!({"status":"ahead", "base_commit":{"sha":base.to_uppercase()},
                "merge_base_commit":{"sha":base.to_uppercase()}}),
                )
            }),
            Some("b".repeat(40))
        );
    }

    #[test]
    fn main_and_ambiguous_depth_are_served_normally() {
        let (mut queue, runs) = cumulative();
        let mut main = runs[0].clone();
        main["event"] = json!("push");
        main["head_branch"] = json!("main");
        assert_eq!(superseded_group(&main, &queue, &runs, ancestry), None);
        assert_eq!(
            superseded_group(&runs[0], &queue, &runs, |_, _| Ok(
                json!({"status":"diverged"})
            )),
            None
        );
        assert_eq!(
            superseded_group(&runs[0], &queue, &runs, |_, _| Err(ScalerError::External(
                "fixture"
            ))),
            None
        );
        queue["data"]["repository"]["mergeQueue"]["entries"]["pageInfo"]["hasNextPage"] =
            json!(true);
        assert_eq!(superseded_group(&runs[0], &queue, &runs, ancestry), None);
    }
    #[test]
    fn passing_successor_and_newer_failure_are_distinguished() {
        let (queue, mut runs) = cumulative();
        runs[2]["status"] = json!("completed");
        runs[2]["conclusion"] = json!("success");
        assert_eq!(
            superseded_group(&runs[1], &queue, &runs, ancestry),
            Some(format!("{:040x}", 3))
        );
        let mut failed = runs[2].clone();
        failed["run_attempt"] = json!(2);
        failed["conclusion"] = json!("failure");
        runs.push(failed);
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
        runs[3].as_object_mut().unwrap().remove("conclusion");
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
    }

    #[test]
    fn malformed_queue_and_untrusted_successor_never_suppress() {
        let (mut queue, runs) = cumulative();
        let nodes = &mut queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"];
        nodes[2]["position"] = json!(2);
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
        let (mut queue, runs) = cumulative();
        queue["data"]["repository"]["mergeQueue"]["entries"]["nodes"][2]["pullRequest"]["headRepository"]
            ["nameWithOwner"] = json!("fork/carrick");
        assert_eq!(superseded_group(&runs[1], &queue, &runs, ancestry), None);
        assert_eq!(
            superseded_group(&runs[1], &queue, &runs, |_, _| panic!(
                "untrusted successor must not be compared"
            )),
            None
        );
    }

    fn queue() -> Value {
        json!({"data":{"repository":{"mergeQueue":{"entries":{
            "pageInfo":{"hasNextPage":false},
            "nodes":[{"position":1,"headCommit":{"oid":"live"},
                "pullRequest":{"headRepository":{"nameWithOwner":REPOSITORY}}}]
        }}}}})
    }

    #[test]
    fn ci_scaler_stale_group_requires_two_consecutive_complete_observations() {
        let absent = queue();
        let mut live = queue();
        live["data"]["repository"]["mergeQueue"]["entries"]["nodes"][0]["headCommit"]["oid"] =
            json!("new");
        let mut observations = [absent.clone(), live.clone()].into_iter();
        assert!(confirm_merge_group("new", || Ok(observations.next().unwrap())).is_ok());
        let mut count = 0;
        assert!(matches!(
            confirm_merge_group("new", || {
                count += 1;
                Ok(absent.clone())
            }),
            Err(ScalerError::StaleMergeGroup)
        ));
        assert_eq!(count, 2);
        let mut truncated = absent.clone();
        truncated["data"]["repository"]["mergeQueue"]["entries"]["pageInfo"]["hasNextPage"] =
            json!(true);
        let mut observations = [absent, truncated].into_iter();
        assert!(matches!(
            confirm_merge_group("new", || Ok(observations.next().unwrap())),
            Err(ScalerError::External(_))
        ));
    }

    #[test]
    fn ci_scaler_merge_group_refusal_distinguishes_stale_from_untrusted() {
        let mut response = queue();
        assert!(vet_merge_group(&response, "live").is_ok());
        assert!(matches!(
            vet_merge_group(&response, "merged"),
            Err(ScalerError::StaleMergeGroup)
        ));
        response["data"]["repository"]["mergeQueue"]["entries"]["nodes"][0]["pullRequest"]["headRepository"]
            ["nameWithOwner"] = json!("fork/carrick");
        assert!(matches!(
            vet_merge_group(&response, "live"),
            Err(ScalerError::Guard(_))
        ));
    }

    #[test]
    fn ci_scaler_partial_or_failed_queue_response_never_cancels_a_group() {
        let mut response = queue();
        response["data"]["repository"]["mergeQueue"]["entries"]["pageInfo"]["hasNextPage"] =
            json!(true);
        assert!(matches!(
            vet_merge_group(&response, "unseen"),
            Err(ScalerError::External(_))
        ));
        response["errors"] = json!([{"message":"fixture"}]);
        assert!(matches!(
            vet_merge_group(&response, "live"),
            Err(ScalerError::External(_))
        ));
        assert!(matches!(
            vet_merge_group(&json!({}), "live"),
            Err(ScalerError::External(_))
        ));
        response = queue();
        response["data"]["repository"]["mergeQueue"]["entries"]["pageInfo"] = Value::Null;
        assert!(matches!(
            vet_merge_group(&response, "unseen"),
            Err(ScalerError::External(_))
        ));
    }
}
