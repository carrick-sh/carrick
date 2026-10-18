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
        Self::queued_jobs(admission, labels, &runs, |run| self.jobs(run))
    }
    fn queued_jobs(
        admission: &Admission,
        labels: &[&str],
        runs: &[Value],
        mut jobs: impl FnMut(&Value) -> Result<Vec<Value>, ScalerError>,
    ) -> Result<Vec<QueuedJob>, ScalerError> {
        let mut demand = Vec::new();
        for run in runs {
            if !admission.admits_run(run) {
                continue;
            }
            for job in jobs(run)? {
                let job_labels: Vec<&str> = job["labels"]
                    .as_array()
                    .ok_or(ScalerError::External("job labels"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if job["status"] != "queued" || !labels_match(labels, &job_labels) {
                    continue;
                }
                demand.push(QueuedJob {
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
        let run = request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{}", entry.key.run.0),
            None,
            false,
        )?;
        if !Admission::Standing.admits_run(&run)
            || run["event"] != "push"
            || run["id"].as_u64() != Some(entry.key.run.0)
            || run["run_attempt"].as_u64() != Some(u64::from(entry.key.attempt))
            || run["head_sha"] != entry.sha
            || !matches!(run["status"].as_str(), Some("queued" | "in_progress"))
        {
            return Ok(NotCancelled);
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
                && job["status"] == "queued"
                && job.get("started_at") == Some(&Value::Null)
        }) {
            return Ok(NotCancelled);
        }
        // A queued KVM job may share a run with an already running HVF job,
        // and vice versa. Include hosted GCP KVM, not only JIT runner labels.
        for job in &jobs {
            if job["status"] == "in_progress" {
                return Ok(Deferred);
            }
            let Some(labels) = job["labels"].as_array() else {
                return Ok(NotCancelled);
            };
            let hardware = labels.iter().any(|label| label == "self-hosted")
                || job["name"] == "KVM · x86 kvm-lane tests";
            if hardware
                && job["status"] != "completed"
                && (job["status"] != "queued" || job.get("started_at") != Some(&Value::Null))
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
        self.vet(&Admission::Standing, key)
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
        Ok(match admission {
            Admission::Pilot { sha } => JobPolicy::Pilot { sha: sha.clone() },
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

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
            let demand = Github::queued_jobs(&Admission::Standing, labels, &runs, |run| {
                let n = run["id"].as_u64().unwrap();
                Ok(vec![hardware_job(
                    n,
                    labels,
                    if n == 4 { "in_progress" } else { "queued" },
                )])
            })
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
                coalesce_demand(&mut ledger, demand, &path, |_| panic!(
                    "durable cancellations must not repeat"
                ))
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
        };
        for started in [
            hardware_job(1, &HVF_LABELS, "in_progress"),
            hardware_job(2, &LABELS, "in_progress"),
            json!({"id":2,"name":"KVM · x86 kvm-lane tests","labels":["ubuntu-latest"],"status":"in_progress","started_at":"now"}),
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
    fn cancellation_intent_survives_api_failure_and_restart_rechecks_running_state() {
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
        assert!(
            coalesce_demand(&mut ledger, demand.clone(), &path, |_| Err(
                ScalerError::External("Actions unavailable")
            ))
            .is_err()
        );
        let pending: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            pending["superseded"][0]["reason"],
            format!("superseded by {:040x}", 3)
        );
        assert!(pending["superseded"][0]["outcome"].is_null());
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
}
