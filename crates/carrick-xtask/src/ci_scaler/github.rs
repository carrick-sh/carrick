//! GitHub REST access through the director-authenticated `gh` CLI, shared by
//! the Willow and cloudmac controllers. Output is parsed, never logged.
use super::*;
use serde_json::{Value, json};

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
        if method == "DELETE" {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&output)?)
    }
    pub(super) fn runs(&self, status: &str) -> Result<Vec<Value>, ScalerError> {
        let data = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs?status={status}&per_page=100"),
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
        let mut demand = Vec::new();
        for status in ["queued", "in_progress"] {
            for run in self.runs(status)? {
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
                        demand.push(JobKey {
                            run: RunId(run["id"].as_u64().ok_or(ScalerError::External("run id"))?),
                            attempt: run["run_attempt"]
                                .as_u64()
                                .and_then(|n| u32::try_from(n).ok())
                                .ok_or(ScalerError::External("attempt"))?,
                            job: JobId(job["id"].as_u64().ok_or(ScalerError::External("job id"))?),
                        });
                    }
                }
            }
        }
        demand.sort_by_key(|key| key.job.0);
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
        // The reservation is demand, never a job binding. Prefer the recorded
        // actual assignment; inspect all active runs if GitHub assigned another.
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
        for status in ["in_progress", "completed"] {
            for run in self.runs(status)? {
                if let Some(assignment) = observed_assignment(row, &self.jobs(&run)?) {
                    return Ok(assignment);
                }
            }
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
        // An absent ephemeral registration can mean a completed job missed by
        // polling. Never infer unassigned from absence and destroy live work.
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
pub(super) fn observed_assignment(
    row: &mut impl RunnerRegistration,
    jobs: &[Value],
) -> Option<Assignment> {
    let runner = row.runner()?;
    let job = jobs
        .iter()
        .find(|job| job["runner_id"].as_u64() == Some(runner.0))?;
    row.set_assigned(JobId(job["id"].as_u64()?));
    Some(if job["status"] == "completed" {
        Assignment::Completed
    } else {
        Assignment::Busy
    })
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
