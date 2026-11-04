//! Trusted Hosted CI observer. Never executes code or downloads artifacts from a PR.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, io::Write, path::PathBuf, process::Command, time::Duration};

#[derive(Debug, Args)]
pub struct FairnessArgs {
    #[command(subcommand)]
    pub command: FairnessCommand,
}

#[derive(Debug, Subcommand)]
pub enum FairnessCommand {
    /// Offline classifier, also used to witness the live observer's decisions.
    Classify { issues: PathBuf, log: PathBuf },
    /// Cancel active Hosted CI runs belonging to this closed PR.
    Closed { repo: String, pr: u64 },
    /// Classify one completed workflow_job webhook (or forwarded client_payload).
    Completed { repo: String, event: PathBuf },
}

#[derive(Debug, Deserialize)]
pub struct Defect {
    pub number: u64,
    pub state: String,
    pub labels: Vec<Label>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Label {
    pub name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Match {
    pub issue: u64,
    pub test: String,
}

/// Only complete Cargo/libtest failure records count; mentions and substrings do not.
/// Actions prefixes each log line with an ISO timestamp, which is stripped first.
pub fn classify(issues: &[Defect], log: &str) -> Vec<Match> {
    // Cargo's color output is enabled in CI; discard SGR without changing names.
    let mut clean = String::with_capacity(log.len());
    let mut escape = false;
    for ch in log.chars() {
        if ch == '\u{1b}' {
            escape = true;
        } else if escape {
            if ch == 'm' {
                escape = false;
            }
        } else {
            clean.push(ch);
        }
    }
    let failed: BTreeSet<_> = clean
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = if line.as_bytes().get(10) == Some(&b'T') {
                line.split_once(' ').map_or(line, |(_, rest)| rest.trim())
            } else {
                line
            };
            let test = line.strip_prefix("test ")?.strip_suffix(" ... FAILED")?;
            valid_test(test).then_some(test)
        })
        .collect();
    let mut matches = Vec::new();
    for issue in issues {
        if issue.state != "open" || !issue.labels.iter().any(|label| label.name == "main-defect") {
            continue;
        }
        for line in issue.body.as_deref().unwrap_or_default().lines() {
            let Some(test) = line.trim().strip_prefix("Failing test:") else {
                continue;
            };
            let test = test.trim().trim_matches('`');
            if failed.contains(test)
                && !matches
                    .iter()
                    .any(|m: &Match| m.issue == issue.number && m.test == test)
            {
                matches.push(Match {
                    issue: issue.number,
                    test: test.to_owned(),
                });
            }
        }
    }
    matches
}

fn valid_test(test: &str) -> bool {
    !test.is_empty()
        && test
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | ':' | '-' | '.'))
}

fn hosted_pr_run(run: &Value) -> bool {
    run["event"] == "pull_request"
        && run["path"]
            .as_str()
            .is_some_and(|path| path.split('@').next() == Some(".github/workflows/ci.yml"))
}

pub fn closed_candidate(run: &Value, pr: u64) -> bool {
    hosted_pr_run(run)
        && matches!(
            run["status"].as_str(),
            Some("queued" | "in_progress" | "waiting" | "pending" | "requested")
        )
        && run["pull_requests"]
            .as_array()
            .is_some_and(|prs| prs.iter().any(|p| p["number"].as_u64() == Some(pr)))
}

// All jobs except the explicitly non-required cache publisher feed ci-ok. Match
// only completed failures; skipped/cancelled jobs and timeout messages prove no test.
fn failed_job(job: &Value) -> bool {
    job["status"] == "completed"
        && job["conclusion"] == "failure"
        && job["name"]
            .as_str()
            .is_some_and(|name| !name.starts_with("cache-warm"))
}

/// Event qualification is deliberately independent of untrusted log contents.
pub fn completed_candidate(event: &Value) -> Option<(u64, u64)> {
    let job = &event["workflow_job"];
    if event["action"] != "completed" || !failed_job(job) {
        return None;
    }
    Some((job["run_id"].as_u64()?, job["id"].as_u64()?))
}

fn macos_remaining(jobs: &[Value]) -> bool {
    jobs.iter().any(|job| {
        job["status"] != "completed"
            && job["labels"]
                .as_array()
                .is_some_and(|labels| labels.iter().any(|label| label == "carrick-macos-ci"))
    })
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn api(repo: &str, endpoint: &str, method: &str) -> Result<Vec<u8>> {
    Ok(crate::ci_scaler::execute(
        Command::new("gh").args([
            "api",
            "--method",
            method,
            &format!("repos/{repo}/{endpoint}"),
        ]),
        &[],
        Duration::from_secs(60),
    )?)
}

fn json(repo: &str, endpoint: &str) -> Result<Value> {
    Ok(crate::ci_scaler::github::Github.request(
        "GET",
        &format!("repos/{repo}/{endpoint}"),
        None,
        false,
    )?)
}

fn pages(repo: &str, endpoint: &str, field: Option<&str>) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    for page in 1..=100 {
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        let value = json(
            repo,
            &format!("{endpoint}{separator}per_page=100&page={page}"),
        )?;
        let rows = field
            .map_or(&value, |key| &value[key])
            .as_array()
            .ok_or("GitHub response is not an array")?;
        all.extend(rows.iter().cloned());
        if rows.len() < 100 {
            return Ok(all);
        }
    }
    Err("GitHub pagination exceeded 100 pages; refusing incomplete evidence".into())
}

fn id(value: &Value) -> Result<u64> {
    value["id"]
        .as_u64()
        .ok_or_else(|| "missing GitHub id".into())
}

fn cancel(repo: &str, run: u64, reason: &str, writer: &mut dyn Write) -> Result<()> {
    // Persist the reason before cancellation, including the linked main defect.
    writeln!(writer, "Cancelling Hosted CI run {run}: {reason}")?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(
            file,
            "Cancelling [Hosted CI run {run}](https://github.com/{repo}/actions/runs/{run}): {reason}"
        )?;
    }
    if let Err(error) = api(repo, &format!("actions/runs/{run}/cancel"), "POST") {
        // Completion can win the race with cancellation. Verify terminal state
        // rather than aborting the closure census and leaving other runs alive.
        if json(repo, &format!("actions/runs/{run}"))?["status"] != "completed" {
            return Err(error);
        }
        writeln!(writer, "Hosted CI run {run} already completed")?;
    }
    Ok(())
}

pub fn run(args: FairnessArgs, writer: &mut dyn Write) -> Result<()> {
    match args.command {
        FairnessCommand::Classify { issues, log } => {
            let issues: Vec<Defect> = serde_json::from_slice(&fs::read(issues)?)?;
            serde_json::to_writer(&mut *writer, &classify(&issues, &fs::read_to_string(log)?))?;
            writeln!(writer)?;
        }
        FairnessCommand::Closed { repo, pr } => {
            // Recheck live state: a delayed close event must not kill reopened PRs.
            if json(&repo, &format!("pulls/{pr}"))?["state"] != "closed" {
                return Ok(());
            }
            for status in ["queued", "in_progress", "waiting", "pending", "requested"] {
                let runs = pages(
                    &repo,
                    &format!("actions/workflows/ci.yml/runs?event=pull_request&status={status}"),
                    Some("workflow_runs"),
                )?;
                for run in runs.iter().filter(|run| closed_candidate(run, pr)) {
                    if json(&repo, &format!("pulls/{pr}"))?["state"] != "closed" {
                        return Ok(());
                    }
                    cancel(&repo, id(run)?, &format!("PR #{pr} is closed"), writer)?;
                }
            }
        }
        FairnessCommand::Completed { repo, event } => {
            let payload: Value = serde_json::from_slice(&fs::read(event)?)?;
            let payload = payload.get("client_payload").unwrap_or(&payload);
            let Some((run, job_id)) = completed_candidate(payload) else {
                return Ok(());
            };
            let current = json(&repo, &format!("actions/runs/{run}"))?;
            if !hosted_pr_run(&current) || current["status"] == "completed" {
                return Ok(());
            }
            let attempt = current["run_attempt"]
                .as_u64()
                .ok_or("missing run attempt")?;
            let jobs = pages(
                &repo,
                &format!("actions/runs/{run}/attempts/{attempt}/jobs"),
                Some("jobs"),
            )?;
            // Membership in the current attempt authenticates forwarded IDs and
            // rejects delayed failure events from an earlier rerun attempt.
            if !jobs
                .iter()
                .any(|job| job["id"].as_u64() == Some(job_id) && failed_job(job))
                || !macos_remaining(&jobs)
            {
                return Ok(());
            }
            let issues: Vec<Defect> = serde_json::from_value(Value::Array(pages(
                &repo,
                "issues?state=open&labels=main-defect",
                None,
            )?))?;
            let log = api(&repo, &format!("actions/jobs/{job_id}/logs"), "GET")?;
            if let Some(found) = classify(&issues, &String::from_utf8(log)?).first() {
                cancel(
                    &repo,
                    run,
                    &format!(
                        "`{}` failed; open main defect https://github.com/{repo}/issues/{}",
                        found.test, found.issue,
                    ),
                    writer,
                )?;
            }
        }
    }
    Ok(())
}
