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
        let run = self.request(
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
            confirm_merge_group(&sha, || {
                self.request(
                    "POST",
                    "graphql",
                    Some(json!({ "query": MERGE_QUEUE_QUERY })),
                    false,
                )
            })?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
