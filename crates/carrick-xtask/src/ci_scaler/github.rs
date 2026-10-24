//! GitHub REST access through the director-authenticated `gh` CLI, shared by
//! the Willow and cloudmac controllers. Output is parsed, never logged.
use super::*;
use serde_json::{Value, json};

#[derive(Clone)]
pub(super) struct QueuedJob {
    pub key: JobKey,
    pub event: String,
    pub sha: String,
}

#[derive(Default)]
struct AdmissionNotices(std::collections::BTreeSet<(RunId, u32)>);
impl AdmissionNotices {
    fn key(run: &Value) -> (RunId, u32) {
        (
            RunId(run["id"].as_u64().unwrap_or_default()),
            run["run_attempt"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or_default(),
        )
    }
    fn record(&mut self, run: &Value, reason: &str) -> Option<String> {
        self.0.insert(Self::key(run)).then(|| {
            format!(
                "dispatch review run={} attempt={} refused: {reason}",
                run["id"], run["run_attempt"]
            )
        })
    }
}
fn admission_notices() -> &'static std::sync::Mutex<AdmissionNotices> {
    static NOTICES: std::sync::OnceLock<std::sync::Mutex<AdmissionNotices>> =
        std::sync::OnceLock::new();
    NOTICES.get_or_init(Default::default)
}
fn admission_refused(run: &Value, reason: &str) {
    if let Some(message) = admission_notices()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .record(run, reason)
    {
        eprintln!("{message}");
    }
}

pub(super) struct Github;
impl Github {
    pub(super) fn request(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError> {
        Self::request_command(Command::new("gh"), method, endpoint, body, paginate)
    }
    fn request_command(
        mut cmd: Command,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError> {
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
        let output = execute_with_failure(&mut cmd, &input, Duration::from_secs(60), |bytes| {
            let body: Value = serde_json::from_slice(bytes).ok()?;
            (body["status"] == "404" || body["status"] == 404).then_some(ScalerError::GithubGone)
        })?;
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
            .map(|job| job.key)
            .collect();
        demand.sort_by_key(|key| key.job.0);
        demand.dedup();
        Ok(demand)
    }
    pub(super) fn coalesced_demand(
        &self,
        ledger: &mut impl assignment::Refusals,
        path: &Path,
        labels: &[&str],
    ) -> Result<Vec<JobKey>, ScalerError> {
        let demand = self.queued_demand(&Admission::Standing, labels)?;
        assignment::coalesce_demand(ledger, demand, path, |entry| {
            Self::cancel_superseded_with(entry, |method, endpoint, body, paginate| {
                self.request(method, endpoint, body, paginate)
            })
        })
    }
    fn queued_demand(
        &self,
        admission: &Admission,
        labels: &[&str],
    ) -> Result<Vec<QueuedJob>, ScalerError> {
        let mut runs = Vec::new();
        for status in ["queued", "in_progress"] {
            runs.extend(self.workflow_runs(admission, status)?);
        }
        if matches!(admission, Admission::Agent) {
            let active: std::collections::BTreeSet<_> =
                runs.iter().map(AdmissionNotices::key).collect();
            admission_notices()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .0
                .retain(|key| active.contains(key));
        }
        Self::queued_jobs(
            admission,
            labels,
            &runs,
            |run| self.jobs(run),
            |run| {
                Self::admits_run(admission, run, &mut |method, endpoint, body, paginate| {
                    self.request(method, endpoint, body, paginate)
                })
            },
        )
    }
    fn queued_jobs(
        admission: &Admission,
        labels: &[&str],
        runs: &[Value],
        mut jobs: impl FnMut(&Value) -> Result<Vec<Value>, ScalerError>,
        mut admitted: impl FnMut(&Value) -> Result<bool, ScalerError>,
    ) -> Result<Vec<QueuedJob>, ScalerError> {
        let mut demand = Vec::new();
        for run in runs {
            if !admission.identifies_run(run) {
                continue;
            }
            let pending = (|| -> Result<Vec<QueuedJob>, ScalerError> {
                let run_jobs = jobs(run)?;
                if !guard_ready(admission, &run_jobs) {
                    return Ok(Vec::new());
                }
                let mut candidates = Vec::new();
                for job in run_jobs {
                    let job_labels: Vec<&str> = job["labels"]
                        .as_array()
                        .ok_or(ScalerError::External("job labels"))?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    if job["status"] != "queued"
                        || job["runner_id"].as_u64().unwrap_or_default() != 0
                        || !labels_match(labels, &job_labels)
                    {
                        continue;
                    }
                    candidates.push(QueuedJob {
                        key: JobKey {
                            run: RunId(run["id"].as_u64().ok_or(ScalerError::External("run id"))?),
                            attempt: run["run_attempt"]
                                .as_u64()
                                .and_then(|n| u32::try_from(n).ok())
                                .ok_or(ScalerError::External("attempt"))?,
                            job: JobId(job["id"].as_u64().ok_or(ScalerError::External("job id"))?),
                        },
                        event: run["event"]
                            .as_str()
                            .ok_or(ScalerError::External("run event"))?
                            .into(),
                        sha: run["head_sha"]
                            .as_str()
                            .ok_or(ScalerError::External("run SHA"))?
                            .into(),
                    });
                }
                if candidates.is_empty() || !admitted(run)? {
                    return Ok(Vec::new());
                }
                Ok(candidates)
            })();
            match pending {
                Ok(pending) => demand.extend(pending),
                Err(error) if matches!(admission, Admission::Agent) => {
                    admission_refused(run, &error.to_string())
                }
                Err(error) => return Err(error),
            }
        }
        demand.sort_by_key(|job| job.key.job.0);
        demand.dedup_by_key(|job| job.key.job.0);
        Ok(demand)
    }
    fn cancel_superseded_with(
        entry: &assignment::SupersededPush,
        mut request: impl FnMut(&str, &str, Option<Value>, bool) -> Result<Value, ScalerError>,
    ) -> Result<assignment::CancellationOutcome, ScalerError> {
        use assignment::CancellationOutcome::{Cancelled, Deferred, NotCancelled};
        let result = (|| {
            let run = request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs/{}", entry.key.run.0),
                None,
                false,
            )?;
            if !Admission::Standing.identifies_run(&run)
                || run["event"] != "push"
                || run["id"].as_u64() != Some(entry.key.run.0)
                || run["head_sha"] != entry.sha
            {
                return Ok(NotCancelled);
            }
            if run["status"] == "completed" {
                return Ok(assignment::CancellationOutcome::Completed);
            }
            let attempt = run["run_attempt"]
                .as_u64()
                .ok_or(ScalerError::External("run attempt"))?;
            if attempt > u64::from(entry.key.attempt) {
                return Ok(assignment::CancellationOutcome::Completed);
            }
            if attempt < u64::from(entry.key.attempt) {
                return Ok(Deferred);
            }
            if !matches!(
                run["status"].as_str(),
                Some("queued" | "waiting" | "in_progress")
            ) {
                return Ok(Deferred);
            }
            if entry.outcome == Some(Cancelled) {
                return Ok(Cancelled);
            }
            let data = request(
                "GET",
                &format!(
                    "repos/{REPOSITORY}/actions/runs/{}/attempts/{}/jobs?per_page=100",
                    entry.key.run.0, entry.key.attempt
                ),
                None,
                true,
            )?;
            let jobs = pages(&data, "jobs")?;
            if !jobs.iter().any(|job| {
                job["id"].as_u64() == Some(entry.key.job.0)
                    && matches!(job["status"].as_str(), Some("queued" | "waiting"))
            }) {
                return Ok(NotCancelled);
            }
            // A queued KVM job may share a run with an already running HVF job,
            // and vice versa.
            for job in &jobs {
                if job["status"] == "in_progress" {
                    return Ok(Deferred);
                }
                let Some(labels) = job["labels"].as_array() else {
                    return Ok(NotCancelled);
                };
                let hardware = labels.iter().any(|label| label == "self-hosted");
                if hardware
                    && job["status"] != "completed"
                    && !matches!(job["status"].as_str(), Some("queued" | "waiting"))
                {
                    return Ok(Deferred);
                }
            }
            request(
                "POST",
                &format!("repos/{REPOSITORY}/actions/runs/{}/cancel", entry.key.run.0),
                None,
                false,
            )?;
            Ok(Cancelled)
        })();
        match result {
            Err(ScalerError::GithubGone) => Ok(assignment::CancellationOutcome::Gone),
            result => result,
        }
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
    /// Re-read admission and attempt immediately before minting a runner.
    /// The hook's policy is bound to this exact run and SHA.
    pub(super) fn vet(&self, admission: &Admission, key: JobKey) -> Result<JobPolicy, ScalerError> {
        Self::vet_inner(admission, key, |method, endpoint, body, paginate| {
            self.request(method, endpoint, body, paginate)
        })
    }

    pub(super) fn vet_assignment(&self, key: JobKey) -> Result<JobPolicy, ScalerError> {
        let run = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{}", key.run.0),
            None,
            false,
        )?;
        self.vet(
            &if run["path"] == DISPATCH_WORKFLOW {
                Admission::Agent
            } else {
                Admission::Standing
            },
            key,
        )
    }

    /// issue_comment runs use main, so their REST run has no issue/PR mapping.
    /// Successful trusted-main guard steps expose only the webhook IDs and
    /// observed head. Fetch the authoritative objects before admitting demand.
    fn admits_comment(
        run: &Value,
        request: &mut impl FnMut(&str, &str, Option<Value>, bool) -> Result<Value, ScalerError>,
    ) -> Result<bool, ScalerError> {
        let id = run["id"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing run id"))?;
        let attempt = run["run_attempt"]
            .as_u64()
            .ok_or(ScalerError::Guard("missing run attempt"))?;
        let data = request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{id}/attempts/{attempt}/jobs?per_page=100"),
            None,
            true,
        )?;
        let jobs = pages(&data, "jobs")?;
        if !guard_ready(&Admission::Agent, &jobs) {
            return Ok(false);
        }
        let guard = jobs
            .iter()
            .find(|j| j["name"] == "guard")
            .ok_or(ScalerError::Guard("missing guard"))?;
        let steps: Vec<_> = guard["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| s["conclusion"] == "success")
            .collect();
        let markers: Vec<_> = steps
            .iter()
            .filter_map(|s| s["name"].as_str()?.strip_prefix("Dispatch comment "))
            .collect();
        if markers.len() != 1 {
            return Ok(false);
        }
        let numbers: Vec<_> = markers[0]
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()
            .map_err(|_| ScalerError::Guard("invalid comment marker"))?;
        let [number, comment_id] = numbers.as_slice() else {
            return Ok(false);
        };
        let comment = request(
            "GET",
            &format!("repos/{REPOSITORY}/issues/comments/{comment_id}"),
            None,
            false,
        )?;
        if comment["id"].as_u64() != Some(*comment_id)
            || comment["issue_url"]
                != format!("https://api.github.com/repos/{REPOSITORY}/issues/{number}")
            || !crate::dispatch_worker::agent_comment(&comment)
        {
            return Ok(false);
        }
        let mut issue = request(
            "GET",
            &format!("repos/{REPOSITORY}/issues/{number}"),
            None,
            false,
        )?;
        if issue.get("pull_request").is_some() {
            let pr = request(
                "GET",
                &format!("repos/{REPOSITORY}/pulls/{number}"),
                None,
                false,
            )?;
            let branch = pr["head"]["ref"].as_str().unwrap_or_default();
            let Some(issue_number) = crate::dispatch_worker::dispatch_branch(branch) else {
                return Ok(false);
            };
            let original_id = crate::dispatch_worker::branch_run(issue_number, branch)?;
            let original = request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs/{original_id}"),
                None,
                false,
            )?;
            let heads: Vec<_> = steps
                .iter()
                .filter_map(|s| s["name"].as_str()?.strip_prefix("Dispatch head "))
                .collect();
            if heads.len() != 1
                || !full_sha(heads[0])
                || pr["head"]["sha"] != heads[0]
                || pr["state"] != "open"
                || !crate::dispatch_worker::owned_pr(&pr, &original, issue_number, branch)
            {
                return Ok(false);
            }
            issue = request(
                "GET",
                &format!("repos/{REPOSITORY}/issues/{issue_number}"),
                None,
                false,
            )?;
        }
        Ok(issue["user"]["login"] == "tjfontaine"
            && issue["user"]["type"] == "User"
            && issue["state"] == "open")
    }

    /// Both queued demand and the final pre-clone/reassignment vet use this
    /// API-backed admission. A successful PR-supplied guard is insufficient.
    fn admits_run(
        admission: &Admission,
        run: &Value,
        request: &mut impl FnMut(&str, &str, Option<Value>, bool) -> Result<Value, ScalerError>,
    ) -> Result<bool, ScalerError> {
        let checked = (|| -> Result<bool, ScalerError> {
            if !admission.identifies_run(run) {
                return Ok(false);
            }
            if matches!(admission, Admission::Agent) && run["event"] == "issue_comment" {
                return Self::admits_comment(run, request);
            }
            if !matches!(admission, Admission::Agent) || run["event"] != "pull_request_review" {
                return Ok(true);
            }
            // REST runs carry no review payload. Main's guard condition and
            // driver admission enforce changes_requested; PR workflow changes
            // are refused below so the merge uses main's policy.
            let branch = run["head_branch"]
                .as_str()
                .ok_or(ScalerError::Guard("review branch missing"))?;
            let Some(issue) = crate::dispatch_worker::dispatch_branch(branch) else {
                return Ok(false);
            };
            let id = crate::dispatch_worker::branch_run(issue, branch)?;
            let original = request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs/{id}"),
                None,
                false,
            )?;
            let prs = request(
                "GET",
                &format!("repos/{REPOSITORY}/pulls?state=open&base=main&head=carrick-sh:{branch}"),
                None,
                false,
            )?;
            if !prs.as_array().into_iter().flatten().any(|pr| {
                pr["head"]["sha"] == run["head_sha"]
                    && crate::dispatch_worker::owned_pr(pr, &original, issue, branch)
            }) {
                return Ok(false);
            }
            let head = run["head_sha"]
                .as_str()
                .ok_or(ScalerError::Guard("review SHA missing"))?;
            let comparison = request(
                "GET",
                &format!("repos/{REPOSITORY}/compare/main...{head}"),
                None,
                false,
            )?;
            let files = comparison["files"]
                .as_array()
                .ok_or(ScalerError::External("comparison files"))?;
            if files.iter().any(|f| {
                f["filename"] == DISPATCH_WORKFLOW || f["previous_filename"] == DISPATCH_WORKFLOW
            }) {
                return Ok(false);
            }
            // GitHub caps comparison files at 300; absence in a capped list
            // is not evidence. Compare head with the merge base in that case.
            // https://docs.github.com/en/rest/commits/commits#compare-two-commits
            if files.len() < 300 {
                return Ok(true);
            }
            let base = comparison["merge_base_commit"]["sha"]
                .as_str()
                .filter(|s| full_sha(s))
                .ok_or(ScalerError::External("comparison merge base"))?;
            let mut blobs = Vec::new();
            for reference in [head, base] {
                let blob = request(
                    "GET",
                    &format!("repos/{REPOSITORY}/contents/{DISPATCH_WORKFLOW}?ref={reference}"),
                    None,
                    false,
                )?;
                if blob["type"] != "file" || !blob["sha"].as_str().is_some_and(full_sha) {
                    return Ok(false);
                }
                blobs.push(blob["sha"].clone());
            }
            Ok(blobs[0] == blobs[1])
        })();
        match checked {
            Ok(true) => Ok(true),
            result if matches!(admission, Admission::Agent) => {
                let reason = result
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "PR head/ownership or workflow check refused".into());
                admission_refused(run, &reason);
                Ok(false)
            }
            result => result,
        }
    }

    fn vet_inner(
        admission: &Admission,
        key: JobKey,
        mut request: impl FnMut(&str, &str, Option<Value>, bool) -> Result<Value, ScalerError>,
    ) -> Result<JobPolicy, ScalerError> {
        let run = request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{}", key.run.0),
            None,
            false,
        )?;
        if !Self::admits_run(admission, &run, &mut request)?
            || run["id"].as_u64() != Some(key.run.0)
            || run["run_attempt"].as_u64() != Some(u64::from(key.attempt))
        {
            return Err(ScalerError::Guard("reserved run is no longer admitted"));
        }
        if matches!(admission, Admission::Agent) {
            let data = request(
                "GET",
                &format!(
                    "repos/{REPOSITORY}/actions/runs/{}/attempts/{}/jobs?per_page=100",
                    key.run.0, key.attempt
                ),
                None,
                true,
            )?;
            if !guard_ready(admission, &pages(&data, "jobs")?) {
                return Err(ScalerError::Guard("dispatch guard has not succeeded"));
            }
        }
        let sha = run["head_sha"]
            .as_str()
            .ok_or(ScalerError::External("run head SHA"))?
            .to_ascii_lowercase();
        Ok(match admission {
            Admission::Pilot { sha } => JobPolicy::Pilot { sha: sha.clone() },
            Admission::Agent => JobPolicy::Agent(RunBinding {
                run: key.run,
                attempt: key.attempt,
                sha,
            }),
            Admission::Standing => JobPolicy::Bound(RunBinding {
                run: key.run,
                attempt: key.attempt,
                sha,
            }),
        })
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

/// A blocked `needs: guard` job must never consume a credentialed clone.
/// Demand and the final pre-JIT/reassignment vet both check this attempt.
fn guard_ready(admission: &Admission, jobs: &[Value]) -> bool {
    !matches!(admission, Admission::Agent)
        || jobs.iter().any(|job| {
            job["name"] == "guard" && job["status"] == "completed" && job["conclusion"] == "success"
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn agent_comment_controller_rechecks_owner_unedited_comment_and_owned_pr() {
        let mut run = review_run(99);
        run["event"] = "issue_comment".into();
        run["head_branch"] = "main".into();
        let mut original = review_run(42);
        original["event"] = "issues".into();
        original["head_branch"] = "main".into();
        for (case, allowed) in [
            ("issue", true),
            ("pr", true),
            ("outsider", false),
            ("edited", false),
            ("wrong_command", false),
            ("unowned", false),
            ("stale", false),
            ("other_issue_author", false),
            ("no_guard", false),
            ("wrong_issue", false),
        ] {
            let mut comment = json!({"id":123,"issue_url":format!("https://api.github.com/repos/{REPOSITORY}/issues/800"),"user":{"login":"tjfontaine","type":"User"},"created_at":"2026-10-24T00:00:00Z","updated_at":"2026-10-24T00:00:00Z","body":"/agent resolve the conflict"});
            if case == "outsider" {
                comment["user"]["login"] = "outsider".into();
            }
            if case == "edited" {
                comment["updated_at"] = "2026-10-24T00:01:00Z".into();
            }
            if case == "wrong_command" {
                comment["body"] = "/agentish".into();
            }
            if case == "wrong_issue" {
                comment["issue_url"] =
                    "https://api.github.com/repos/outsider/repo/issues/800".into();
            }
            let pr_case = ["pr", "unowned", "stale"].contains(&case);
            let issue = json!({"state":"open","number":799,"user":{"login":if case == "other_issue_author" { "outsider" } else { "tjfontaine" },"type":"User"}});
            let mut pr = json!({"state":"open","number":800,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"ref":"work/dispatch-799-42","sha":"a".repeat(40),"repo":{"full_name":REPOSITORY}},"base":{"ref":"main"},"draft":true,"body":format!("Closes #799\nDispatch run: https://github.com/{REPOSITORY}/actions/runs/42")});
            if case == "unowned" {
                pr["user"]["login"] = "outsider".into();
            }
            if case == "stale" {
                pr["head"]["sha"] = "b".repeat(40).into();
            }
            let mut calls = Vec::new();
            let admitted = Github::admits_run(&Admission::Agent, &run, &mut |_, endpoint, _, _| {
                calls.push(endpoint.to_owned());
                Ok(if endpoint.contains("/jobs?") {
                    json!([{"jobs":[{"name":"guard","status":"completed","conclusion":if case=="no_guard" {"failure"} else {"success"},"steps":[{"name":"Dispatch comment 800 123","conclusion":"success"},{"name":format!("Dispatch head {}","a".repeat(40)),"conclusion":"success"}]}]}])
                } else if endpoint.ends_with("/issues/comments/123") { comment.clone() }
                else if endpoint.ends_with("/issues/800") { if pr_case { json!({"pull_request":{}}) } else { issue.clone() } }
                else if endpoint.ends_with("/pulls/800") { pr.clone() }
                else if endpoint.ends_with("/actions/runs/42") { original.clone() }
                else if endpoint.ends_with("/issues/799") { issue.clone() }
                else { panic!("unexpected endpoint {endpoint}") })
            }).unwrap();
            assert_eq!(admitted, allowed, "controller case {case}; {calls:?}");
        }
    }
    #[test]
    fn dispatch_review_refusals_log_once_per_active_attempt() {
        let mut notices = AdmissionNotices::default();
        let mut run = review_run(99);
        assert!(
            notices
                .record(&run, "API unavailable")
                .unwrap()
                .contains("run=99")
        );
        assert!(
            notices.record(&run, "still unavailable").is_none(),
            "duplicate refusal log"
        );
        run["run_attempt"] = 2.into();
        assert!(notices.record(&run, "new attempt").is_some());
    }
    fn review_run(id: u64) -> Value {
        json!({"id":id,"run_attempt":1,"head_sha":"a".repeat(40),"head_branch":"work/dispatch-799-42","event":"pull_request_review",
            "path":DISPATCH_WORKFLOW,"repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY},
            "actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"}})
    }
    fn review_jobs(id: u64) -> Vec<Value> {
        vec![
            json!({"name":"guard","status":"completed","conclusion":"success","labels":[]}),
            json!({"id":id,"name":"worker","status":"queued","runner_id":0,"labels":["carrick-agent"]}),
        ]
    }
    #[test]
    fn dispatch_review_vet_checks_pr_changes_instead_of_main_workflow_changes() {
        let mut original = review_run(42);
        original["event"] = "issues".into();
        original["head_branch"] = "main".into();
        let mut failures = Vec::new();
        for (bot, changed, head_blob, allowed) in [
            ("github-actions[bot]", false, "b", true), // main advanced; PR kept its original workflow
            ("github-actions[bot]", true, "c", false), // PR changed workflow to match today's main
            ("outsider", false, "c", false),
            ("github-actions[bot]", false, "c", true),
        ] {
            let run = review_run(99);
            let pr = json!({"number":800,"user":{"login":bot,"type":"Bot"},"draft":true,
                "head":{"ref":"work/dispatch-799-42","sha":"a".repeat(40),"repo":{"full_name":REPOSITORY}},
                "base":{"ref":"main"},"body":"Closes #799\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"});
            let key = JobKey {
                run: RunId(99),
                attempt: 1,
                job: JobId(9),
            };
            let result = Github::vet_inner(&Admission::Agent, key, |method, endpoint, _, _| {
                assert_eq!(method, "GET");
                if endpoint.ends_with("/99") {
                    Ok(run.clone())
                } else if endpoint.ends_with("/42") {
                    Ok(original.clone())
                } else if endpoint.contains("/pulls?") {
                    Ok(json!([pr.clone()]))
                } else if endpoint.contains("/compare/main...") {
                    assert!(endpoint.ends_with(&"a".repeat(40)));
                    Ok(
                        json!({"merge_base_commit":{"sha":"b".repeat(40)},"files":[{"filename":if changed { DISPATCH_WORKFLOW } else { "source.rs" }}]}),
                    )
                } else if endpoint.contains("/contents/") {
                    Ok(
                        json!({"type":"file","sha":if endpoint.ends_with("ref=main") { "c".repeat(40) } else { head_blob.repeat(40) }}),
                    )
                } else if endpoint.ends_with("/jobs?per_page=100") {
                    Ok(json!([{"jobs":review_jobs(9)}]))
                } else {
                    panic!("unexpected API endpoint: {endpoint}")
                }
            });
            if result.is_ok() != allowed {
                failures.push(format!(
                    "bot={bot}, PR changed={changed}, head blob={head_blob}: admitted={}",
                    result.is_ok()
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "workflow admission errors: {failures:?}"
        );
    }
    #[test]
    fn dispatch_review_capped_comparison_requires_merge_base_blob_equality() {
        for (head_blob, allowed) in [("b", true), ("c", false)] {
            let run = review_run(99);
            let mut original = review_run(42);
            original["event"] = "issues".into();
            original["head_branch"] = "main".into();
            let pr = json!({"number":800,"user":{"login":"github-actions[bot]","type":"Bot"},"draft":true,
                "head":{"ref":"work/dispatch-799-42","sha":"a".repeat(40),"repo":{"full_name":REPOSITORY}},"base":{"ref":"main"},
                "body":"Closes #799\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"});
            let mut blobs = Vec::new();
            let admitted = Github::admits_run(&Admission::Agent, &run, &mut |_, endpoint, _, _| {
                if endpoint.ends_with("/42") { Ok(original.clone()) }
                else if endpoint.contains("/pulls?") { Ok(json!([pr.clone()])) }
                else if endpoint.contains("/compare/") { Ok(json!({"files":vec![json!({"filename":"source.rs"});300],"merge_base_commit":{"sha":"b".repeat(40)}})) }
                else if endpoint.contains("/contents/") {
                    blobs.push(endpoint.to_owned());
                    Ok(json!({"type":"file","sha":if endpoint.ends_with(&"a".repeat(40)) {head_blob.repeat(40)} else {"b".repeat(40)}}))
                } else { panic!("unexpected endpoint {endpoint}") }
            }).unwrap();
            assert_eq!(admitted, allowed);
            assert_eq!(blobs.len(), 2);
            assert!(blobs[1].ends_with(&format!("ref={}", "b".repeat(40))));
        }
    }
    #[test]
    fn dispatch_review_expensive_checks_wait_for_unassigned_eligible_jobs() {
        let runs: Vec<_> = (99..104).map(review_run).collect();
        let mut checks = Vec::new();
        let demand = Github::queued_jobs(
            &Admission::Agent,
            &["carrick-agent"],
            &runs,
            |run| {
                let id = run["id"].as_u64().unwrap();
                let mut jobs = review_jobs(id);
                match id {
                    99 => jobs[0]["status"] = "queued".into(),
                    100 => {
                        jobs[1]["status"] = "in_progress".into();
                        jobs[1]["runner_id"] = 55.into();
                    }
                    101 => jobs[1]["labels"] = json!(["other-lane"]),
                    103 => jobs[1]["runner_id"] = 55.into(),
                    _ => {}
                }
                Ok(jobs)
            },
            |run| {
                checks.push(run["id"].as_u64().unwrap());
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(checks, vec![102], "API checks ran before cheap job filters");
        assert_eq!(demand.len(), 1);
        assert_eq!(demand[0].key.run, RunId(102));
    }
    #[test]
    fn dispatch_review_api_failure_does_not_hide_other_demand() {
        let runs = vec![review_run(99), review_run(100)];
        let demand = Github::queued_jobs(
            &Admission::Agent,
            &["carrick-agent"],
            &runs,
            |run| Ok(review_jobs(run["id"].as_u64().unwrap())),
            |run| {
                if run["id"] == 99 {
                    Github::admits_run(&Admission::Agent, run, &mut |_, _, _, _| {
                        Err(ScalerError::GithubGone)
                    })
                } else {
                    Ok(true)
                }
            },
        );
        assert!(demand.is_ok(), "one missing review run blocked all demand");
        let demand = demand.unwrap();
        assert_eq!(demand.len(), 1);
        assert_eq!(demand[0].key.run, RunId(100));
        let key = JobKey {
            run: RunId(99),
            attempt: 1,
            job: JobId(9),
        };
        assert!(
            Github::vet_inner(&Admission::Agent, key, |_, endpoint, _, _| {
                if endpoint.ends_with("/99") {
                    Ok(review_run(99))
                } else {
                    Err(ScalerError::GithubGone)
                }
            })
            .is_err()
        );
    }
    #[test]
    fn dispatch_vet_requires_this_attempts_successful_hosted_guard() {
        let run = json!({"id":42,"run_attempt":2,"head_sha":"a".repeat(40), "head_branch":"main", "event":"issues",
            "path":DISPATCH_WORKFLOW,"repository":{"full_name":REPOSITORY}, "head_repository":{"full_name":REPOSITORY},
            "actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"}});
        let key = JobKey {
            run: RunId(42),
            attempt: 2,
            job: JobId(9),
        };
        for (status, conclusion, permitted) in [
            ("queued", "success", false),
            ("completed", "failure", false),
            ("completed", "success", true),
        ] {
            let policy = Github::vet_inner(&Admission::Agent, key, |_, endpoint, _, paginated| {
                if endpoint.ends_with("/42") {
                    return Ok(run.clone());
                }
                assert_eq!(
                    endpoint,
                    "repos/carrick-sh/carrick/actions/runs/42/attempts/2/jobs?per_page=100"
                );
                assert!(paginated);
                Ok(json!([{"jobs":[{"name":"guard", "status":status,"conclusion":conclusion}]}]))
            });
            assert_eq!(policy.is_ok(), permitted);
            if permitted {
                assert!(matches!(policy.unwrap(), JobPolicy::Agent(_)));
            }
        }
    }
    #[test]
    fn reservations_and_assignments_accept_main_push_and_dispatch_only() {
        let key = JobKey {
            run: RunId(1),
            attempt: 1,
            job: JobId(2),
        };
        for (event, branch, admitted) in [
            ("push", "main", true),
            ("workflow_dispatch", "main", true),
            ("merge_group", "gh-readonly-queue/main/pr-1-abc", false),
            ("pull_request", "main", false),
            ("workflow_dispatch", "work/x", false),
        ] {
            let run = json!({"id":1,"run_attempt":1,"event":event,
                "head_sha":"a".repeat(40),"head_branch":branch,
                "path":KERNEL_RUNTIME_WORKFLOW,
                "repository":{"full_name":REPOSITORY},
                "head_repository":{"full_name":REPOSITORY},
                "actor":{"login":"tjfontaine"},
                "triggering_actor":{"login":"tjfontaine"}});
            let result = Github::vet_inner(&Admission::Standing, key, |method, endpoint, _, _| {
                assert_eq!(method, "GET");
                assert!(endpoint.ends_with("/runs/1"), "{endpoint}");
                Ok(run.clone())
            });
            assert_eq!(result.is_ok(), admitted, "{event} {branch}");
            if let Ok(policy) = result {
                assert!(
                    policy
                        .authorize(&JobContext {
                            repository: REPOSITORY.into(),
                            actor: "tjfontaine".into(),
                            triggering_actor: "tjfontaine".into(),
                            event: event.into(),
                            workflow_ref: format!(
                                "{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@refs/heads/{branch}"
                            ),
                            git_ref: format!("refs/heads/{branch}"),
                            sha: "a".repeat(40),
                            run_id: 1,
                            run_attempt: 1,
                        })
                        .is_ok()
                );
            }
        }
    }
    fn push_run(n: u64) -> Value {
        json!({"id":n,"run_attempt":1,"event":"push","status":"in_progress",
            "head_sha":format!("{n:040x}"),"head_branch":"main","path":KERNEL_RUNTIME_WORKFLOW,
            "repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY}})
    }
    fn hardware_job(n: u64, labels: &[&str], status: &str) -> Value {
        json!({"id":n,"name":"hardware","labels":labels,"status":status,
            "started_at":if status=="queued" {Value::Null} else {json!("2026-10-18T00:00:00Z")},
            "conclusion":Value::Null})
    }
    #[test]
    fn three_queued_pushes_cancel_two_with_durable_reason_and_running_push_is_untouched() {
        use super::super::assignment::{CancellationOutcome, coalesce_demand};
        for labels in [&HVF_LABELS[..], &LABELS[..]] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger.json");
            let mut ledger = Ledger::default();
            let runs: Vec<_> = (1..=4).map(push_run).collect();
            let demand = Github::queued_jobs(
                &Admission::Standing,
                labels,
                &runs,
                |run| {
                    let n = run["id"].as_u64().unwrap();
                    Ok(vec![hardware_job(
                        n,
                        labels,
                        if n == 4 { "in_progress" } else { "queued" },
                    )])
                },
                |_| Ok(true),
            )
            .unwrap();
            let mut cancelled = Vec::new();
            let ordered = coalesce_demand(&mut ledger, demand.clone(), &path, |entry| {
                // Intent and its cause must reach disk before any GitHub mutation.
                let durable: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert!(
                    durable["superseded"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r["key"]["run"] == entry.key.run.0 && r["reason"] == entry.reason)
                );
                assert_eq!(entry.reason, format!("superseded by {:040x}", 3));
                Github::cancel_superseded_with(entry, |method, endpoint, _, _| {
                    if method == "GET" && endpoint.ends_with("/jobs?per_page=100") {
                        return Ok(
                            json!([{"jobs":[hardware_job(entry.key.run.0,labels,"queued")]}]),
                        );
                    }
                    if method == "GET" {
                        return Ok(push_run(entry.key.run.0));
                    }
                    assert_eq!(method, "POST");
                    assert!(endpoint.ends_with("/cancel"));
                    cancelled.push(entry.key.run.0);
                    Ok(Value::Null)
                })
            })
            .unwrap();
            assert_eq!(ordered.iter().map(|k| k.run.0).collect::<Vec<_>>(), vec![3]);
            assert_eq!(cancelled, vec![1, 2]);
            assert!(!cancelled.contains(&4));
            let durable = Ledger::load(&path).unwrap().superseded;
            assert!(
                durable
                    .iter()
                    .all(|entry| entry.outcome == Some(CancellationOutcome::Cancelled))
            );
            assert_eq!(
                coalesce_demand(&mut ledger, demand, &path, |entry| {
                    Github::cancel_superseded_with(entry, |method, _, _, _| {
                        assert_eq!(method, "GET", "do not repeat an accepted cancellation POST");
                        Ok(push_run(entry.key.run.0))
                    })
                })
                .unwrap(),
                ordered
            );
        }
    }
    #[test]
    fn coalescing_rechecks_started_hardware_in_both_lanes_and_never_cancels_dispatch() {
        use super::super::assignment::{CancellationOutcome, SupersededPush};
        let entry = SupersededPush {
            key: JobKey {
                run: RunId(1),
                attempt: 1,
                job: JobId(1),
            },
            sha: format!("{:040x}", 1),
            reason: format!("superseded by {:040x}", 3),
            outcome: None,
            created: now().unwrap(),
        };
        for started in [
            hardware_job(1, &HVF_LABELS, "in_progress"),
            hardware_job(2, &LABELS, "in_progress"),
            json!({"id":3,"name":"Signed fixtures","labels":["ubuntu-latest"],"status":"in_progress","started_at":"now"}),
        ] {
            let result = Github::cancel_superseded_with(&entry, |method, endpoint, _, _| {
                assert_eq!(
                    method, "GET",
                    "running jobs must never receive cancellation"
                );
                if endpoint.ends_with("/jobs?per_page=100") {
                    Ok(json!([{"jobs":[hardware_job(1,&HVF_LABELS,"queued"),started]}]))
                } else {
                    Ok(push_run(1))
                }
            })
            .unwrap();
            assert_eq!(result, CancellationOutcome::Deferred);
        }
        let result = Github::cancel_superseded_with(&entry, |method, _, _, _| {
            assert_eq!(method, "GET");
            let mut dispatch = push_run(1);
            dispatch["event"] = "workflow_dispatch".into();
            dispatch["actor"] = json!({"login":"tjfontaine"});
            dispatch["triggering_actor"] = json!({"login":"tjfontaine"});
            Ok(dispatch)
        })
        .unwrap();
        assert_eq!(result, CancellationOutcome::NotCancelled);
    }
    #[test]
    fn cancel_error_does_not_block_newest_admission_and_is_retried_after_restart() {
        use super::super::assignment::{CancellationOutcome, coalesce_demand};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = Ledger::default();
        let demand = (1..=3)
            .map(|n| QueuedJob {
                key: JobKey {
                    run: RunId(n),
                    attempt: 1,
                    job: JobId(n),
                },
                event: "push".into(),
                sha: format!("{n:040x}"),
            })
            .collect::<Vec<_>>();
        let ordered = coalesce_demand(&mut ledger, demand.clone(), &path, |_| {
            Err(ScalerError::External("Actions unavailable"))
        })
        .unwrap();
        let admitted = assignment::admit_demand(&mut ledger, &path, ordered, Ok)
            .unwrap()
            .unwrap();
        assert_eq!(admitted.run, RunId(3));
        assert!(ledger.reserve(admitted, &[], 100, Concurrency::ONE).is_ok());
        let pending: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            pending["superseded"][0]["reason"],
            format!("superseded by {:040x}", 3)
        );
        assert!(
            pending["superseded"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["outcome"] == "Deferred")
        );
        let mut checked = Vec::new();
        let mut ledger = Ledger::load(&path).unwrap();
        let selected = coalesce_demand(&mut ledger, demand, &path, |entry| {
            checked.push(entry.key.run.0);
            Ok(if entry.key.run.0 == 1 {
                CancellationOutcome::NotCancelled
            } else {
                CancellationOutcome::Cancelled
            })
        })
        .unwrap();
        assert_eq!(checked, vec![1, 2]);
        assert_eq!(
            selected.iter().map(|k| k.run.0).collect::<Vec<_>>(),
            vec![3]
        );
    }
    #[test]
    fn completed_opposite_lane_does_not_strand_superseded_queued_hardware() {
        use super::super::assignment::{CancellationOutcome, SupersededPush};
        let entry = SupersededPush {
            key: JobKey {
                run: RunId(1),
                attempt: 1,
                job: JobId(1),
            },
            sha: format!("{:040x}", 1),
            reason: format!("superseded by {:040x}", 3),
            outcome: None,
            created: now().unwrap(),
        };
        for (target, other) in [
            (&HVF_LABELS[..], &LABELS[..]),
            (&LABELS[..], &HVF_LABELS[..]),
        ] {
            let mut posted = false;
            let result = Github::cancel_superseded_with(&entry, |method, endpoint, _, _| {
                if method == "GET" && endpoint.ends_with("/jobs?per_page=100") {
                    let mut finished = hardware_job(2, other, "completed");
                    finished["conclusion"] = "success".into();
                    Ok(json!([{"jobs":[hardware_job(1,target,"queued"),finished]}]))
                } else if method == "GET" {
                    Ok(push_run(1))
                } else {
                    assert_eq!(method, "POST");
                    posted = true;
                    Ok(Value::Null)
                }
            })
            .unwrap();
            assert_eq!(result, CancellationOutcome::Cancelled);
            assert!(posted);
        }
    }
    #[test]
    fn observed_running_lane_defers_cleanup_across_restart_until_it_finishes() {
        use super::super::assignment::{CancellationOutcome, coalesce_demand};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let demand = [1, 3].map(|n| QueuedJob {
            key: JobKey {
                run: RunId(n),
                attempt: 1,
                job: JobId(n),
            },
            event: "push".into(),
            sha: format!("{n:040x}"),
        });
        let mut checks = 0;
        let mut posts = 0;
        for round in 0..2 {
            let mut ledger = Ledger::load(&path).unwrap();
            let ordered = coalesce_demand(&mut ledger, demand.to_vec(), &path, |entry| {
                checks += 1;
                Github::cancel_superseded_with(entry, |method, endpoint, _, _| {
                    if method == "GET" && endpoint.ends_with("/jobs?per_page=100") {
                        Ok(json!([{"jobs":[hardware_job(1,&LABELS,"queued"),
                            hardware_job(2,&HVF_LABELS,if round==0 {"in_progress"} else {"completed"})]}]))
                    } else if method == "GET" {
                        Ok(push_run(1))
                    } else {
                        assert_eq!(round,1,"never cancel observed running work");
                        assert_eq!(method,"POST");
                        posts += 1;
                        Ok(Value::Null)
                    }
                })
            }).unwrap();
            assert_eq!(
                ordered.iter().map(|key| key.run.0).collect::<Vec<_>>(),
                vec![3]
            );
        }
        assert_eq!(
            checks, 2,
            "deferred cleanup must survive restart and be rechecked"
        );
        assert_eq!(posts, 1);
        assert_eq!(
            Ledger::load(&path).unwrap().superseded[0].outcome,
            Some(CancellationOutcome::Cancelled)
        );
    }
    fn cleanup_entry() -> assignment::SupersededPush {
        assignment::SupersededPush {
            key: JobKey {
                run: RunId(1),
                attempt: 1,
                job: JobId(1),
            },
            sha: format!("{:040x}", 1),
            reason: format!("superseded by {:040x}", 3),
            outcome: None,
            created: now().unwrap(),
        }
    }
    #[test]
    fn queued_or_waiting_job_with_started_at_populated_is_cancelled_by_status() {
        for status in ["queued", "waiting"] {
            let mut posted = false;
            let outcome =
                Github::cancel_superseded_with(&cleanup_entry(), |method, endpoint, _, _| {
                    if method == "GET" && endpoint.ends_with("/jobs?per_page=100") {
                        let mut job = hardware_job(1, &HVF_LABELS, status);
                        job["started_at"] = "2026-10-18T00:00:00Z".into();
                        Ok(json!([{"jobs":[job]}]))
                    } else if method == "GET" {
                        Ok(push_run(1))
                    } else {
                        assert_eq!(method, "POST");
                        posted = true;
                        Ok(Value::Null)
                    }
                })
                .unwrap();
            assert_eq!(outcome, assignment::CancellationOutcome::Cancelled);
            assert!(posted, "status={status} must permit cancellation");
        }
    }
    #[test]
    fn serial_host_github_404_settles_cleanup_as_gone_without_leaking_response_body() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gh = dir.path().join("gh");
        for status in ["404", "403"] {
            std::fs::write(&gh,format!("#!/bin/sh\nprintf '%s' '{{\"message\":\"sensitive-body\",\"status\":\"{status}\"}}'\nexit 1\n")).unwrap();
            std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
            let decision = Github::cancel_superseded_with(
                &cleanup_entry(),
                |method, endpoint, body, paginate| {
                    Github::request_command(Command::new(&gh), method, endpoint, body, paginate)
                },
            );
            if status == "404" {
                assert!(decision.is_ok(), "{decision:?}");
                assert_eq!(
                    serde_json::to_value(decision.unwrap()).unwrap(),
                    json!("Gone")
                );
            } else {
                let error = decision.unwrap_err().to_string();
                assert!(!error.contains("sensitive-body"), "{error}");
            }
        }
    }
    #[test]
    fn completed_or_cancelled_run_is_pruned_after_an_accepted_cancel_request() {
        for conclusion in ["success", "cancelled"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger");
            let mut entry = cleanup_entry();
            entry.outcome = Some(assignment::CancellationOutcome::Cancelled);
            let mut ledger = Ledger {
                superseded: vec![entry],
                ..Ledger::default()
            };
            let mut queries = 0;
            assignment::coalesce_demand(&mut ledger, vec![], &path, |entry| {
                Github::cancel_superseded_with(entry, |method, _, _, _| {
                    assert_eq!(method, "GET");
                    queries += 1;
                    let mut run = push_run(1);
                    run["status"] = "completed".into();
                    run["conclusion"] = conclusion.into();
                    Ok(run)
                })
            })
            .unwrap();
            assert_eq!(queries, 1);
            assert!(ledger.superseded.is_empty());
        }
    }
    #[test]
    fn unknown_or_older_attempt_metadata_cannot_retire_live_supersession() {
        for attempt in [Value::Null, json!(0)] {
            let outcome = Github::cancel_superseded_with(&cleanup_entry(), |method, _, _, _| {
                assert_eq!(method, "GET");
                let mut run = push_run(1);
                run["run_attempt"] = attempt.clone();
                Ok(run)
            });
            assert!(
                !matches!(outcome, Ok(assignment::CancellationOutcome::Completed)),
                "{outcome:?}"
            );
        }
    }
}
