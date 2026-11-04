//! Cross-host job claims (#1597): two standing controllers on different
//! Proxmox hosts may serve the same runner labels without each booting a
//! clone for one queued job.
//!
//! A claim is a create-only GitHub ref, `refs/ci-claims/job/<run>-<attempt>-<job>`.
//! `POST /git/refs` refuses an existing ref with HTTP 422, so exactly one
//! host's create succeeds. The ref points at an empty-tree commit whose
//! message names the claiming host and the creation time, so a claim left by
//! a crashed controller expires after [`CLAIM_TTL`].
//!
//! A claim only has to cover reservation to assignment (minutes): once
//! GitHub assigns the job it is no longer queued, so neither host sees it as
//! demand. A JIT runner may still take a different queued job with the same
//! labels; the existing assignment re-vet (#333) covers that, and the claim
//! keeps the clone count across hosts matched to queued jobs. The one
//! residual race (two hosts reclaiming the same expired claim in the same
//! second) costs one surplus clone, which reaps unassigned; it is never a
//! wrong assignment.
//!
//! The leader takes jobs as soon as it sees them; a follower takes a job only
//! after it has seen it queued for [`FOLLOWER_GRACE`], so the leader gets
//! first pick and the follower absorbs overflow.
use super::{JobKey, ScalerError};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// Git's well-known empty tree; claim commits carry no content.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
/// A claim older than this no longer blocks another host.
pub(super) const CLAIM_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a follower waits after first seeing a queued job.
pub(super) const FOLLOWER_GRACE: Duration = Duration::from_secs(90);

/// Which standing controller gets first pick of shared demand.
#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum Role {
    Leader,
    Follower,
}

/// `POST/GET/DELETE` against the repository's REST API, as
/// `Github::request` does (`method`, `endpoint`, `body`).
pub(super) trait Api {
    fn call(
        &mut self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, ScalerError>;
}
impl<F> Api for F
where
    F: FnMut(&str, &str, Option<Value>) -> Result<Value, ScalerError>,
{
    fn call(
        &mut self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, ScalerError> {
        self(method, endpoint, body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// This host holds the claim (new, reclaimed after expiry, or its own).
    Won,
    /// Another host holds a live claim.
    HeldElsewhere,
}

fn ref_name(key: JobKey) -> String {
    format!("ci-claims/job/{}-{}-{}", key.run.0, key.attempt, key.job.0)
}

/// The holder recorded in a claim commit message.
#[derive(Debug, PartialEq, Eq)]
struct Holder {
    host: String,
    created: u64,
}
fn message(host: &str, created: u64) -> String {
    format!("ci-claim v1 host={host} created={created}")
}
fn parse(message: &str) -> Option<Holder> {
    let rest = message.trim().strip_prefix("ci-claim v1 ")?;
    let mut host = None;
    let mut created = None;
    for field in rest.split_ascii_whitespace() {
        match field.split_once('=')? {
            ("host", value) if !value.is_empty() => host = Some(value.to_owned()),
            ("created", value) => created = value.parse().ok(),
            _ => return None,
        }
    }
    Some(Holder {
        host: host?,
        created: created?,
    })
}

fn create(api: &mut impl Api, key: JobKey, host: &str, now: u64) -> Result<bool, ScalerError> {
    let commit = api.call(
        "POST",
        &format!("repos/{}/git/commits", super::REPOSITORY),
        Some(json!({"message": message(host, now), "tree": EMPTY_TREE, "parents": []})),
    )?;
    let sha = commit["sha"]
        .as_str()
        .ok_or(ScalerError::External("claim commit sha"))?;
    match api.call(
        "POST",
        &format!("repos/{}/git/refs", super::REPOSITORY),
        Some(json!({"ref": format!("refs/{}", ref_name(key)), "sha": sha})),
    ) {
        Ok(_) => Ok(true),
        Err(ScalerError::GithubConflict) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The current holder, or `None` when the ref is gone.
fn holder(api: &mut impl Api, key: JobKey) -> Result<Option<Holder>, ScalerError> {
    let reference = match api.call(
        "GET",
        &format!("repos/{}/git/ref/{}", super::REPOSITORY, ref_name(key)),
        None,
    ) {
        Ok(reference) => reference,
        Err(ScalerError::GithubGone) => return Ok(None),
        Err(error) => return Err(error),
    };
    let sha = reference["object"]["sha"]
        .as_str()
        .ok_or(ScalerError::External("claim ref sha"))?;
    let commit = api.call(
        "GET",
        &format!("repos/{}/git/commits/{sha}", super::REPOSITORY),
        None,
    )?;
    // An unparseable claim is never ours and never expires by our clock;
    // treat it as held so a foreign ref in the namespace never admits.
    Ok(Some(commit["message"].as_str().and_then(parse).unwrap_or(
        Holder {
            host: String::new(),
            created: u64::MAX,
        },
    )))
}

fn delete(api: &mut impl Api, key: JobKey) -> Result<(), ScalerError> {
    match api.call(
        "DELETE",
        &format!("repos/{}/git/refs/{}", super::REPOSITORY, ref_name(key)),
        None,
    ) {
        Ok(_) | Err(ScalerError::GithubGone) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Claim `key` for `host` at unix time `now`.
pub(super) fn claim(
    api: &mut impl Api,
    key: JobKey,
    host: &str,
    now: u64,
) -> Result<Outcome, ScalerError> {
    if create(api, key, host, now)? {
        return Ok(Outcome::Won);
    }
    let Some(current) = holder(api, key)? else {
        // Released between our create and our read: one more create.
        return Ok(if create(api, key, host, now)? {
            Outcome::Won
        } else {
            Outcome::HeldElsewhere
        });
    };
    if current.host == host {
        // Our own claim, e.g. from before a controller restart.
        return Ok(Outcome::Won);
    }
    if now.saturating_sub(current.created) < CLAIM_TTL.as_secs() || current.created > now {
        return Ok(Outcome::HeldElsewhere);
    }
    delete(api, key)?;
    Ok(if create(api, key, host, now)? {
        Outcome::Won
    } else {
        Outcome::HeldElsewhere
    })
}

/// Release `key` if `host` holds it; another host's claim is left alone.
pub(super) fn release(api: &mut impl Api, key: JobKey, host: &str) -> Result<(), ScalerError> {
    match holder(api, key)? {
        Some(current) if current.host == host => delete(api, key),
        _ => Ok(()),
    }
}

/// Per-controller claim policy: role, host identity and, for a follower,
/// when each queued job was first seen.
pub(super) struct Claims {
    pub role: Role,
    pub host: &'static str,
    /// (job, first seen, seen in the current admission pass). Demand is a
    /// handful of jobs, so a vector suffices.
    first_seen: Vec<(JobKey, Instant, bool)>,
}
impl Claims {
    pub(super) fn new(role: Role, host: &'static str) -> Self {
        Self {
            role,
            host,
            first_seen: Vec::new(),
        }
    }
    /// Whether this controller may take `job` now. The leader always may; a
    /// follower only once the job has been queued in its view for the grace.
    pub(super) fn ready(&mut self, job: JobKey, now: Instant) -> bool {
        if self.role == Role::Leader {
            return true;
        }
        let first = match self.first_seen.iter_mut().find(|(key, ..)| *key == job) {
            Some(entry) => {
                entry.2 = true;
                entry.1
            }
            None => {
                self.first_seen.push((job, now, true));
                now
            }
        };
        now.duration_since(first) >= FOLLOWER_GRACE
    }
    /// End of an admission pass: forget jobs this pass never evaluated (no
    /// longer queued or already served), so the record stays bounded.
    pub(super) fn end_pass(&mut self) {
        self.first_seen.retain(|(.., seen)| *seen);
        for entry in &mut self.first_seen {
            entry.2 = false;
        }
    }
}

/// The claiming host of this process's claim-enabled controller, set once
/// at start-up; unset (tests, the pilot, `CARRICK_JOB_CLAIMS=0`) means
/// row teardown releases nothing.
static ACTIVE_HOST: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
pub(super) fn activate(host: &'static str) {
    let _ = ACTIVE_HOST.set(host);
}
/// The live repository API, through the controller's `gh` client.
pub(super) fn github_api() -> impl FnMut(&str, &str, Option<Value>) -> Result<Value, ScalerError> {
    |method, endpoint, body| super::github::Github.request(method, endpoint, body, false)
}
/// Best effort: a closed row drops its job's claim if this host holds it.
/// A failure only delays the other host until [`CLAIM_TTL`].
pub(super) fn release_on_close(key: JobKey) {
    if let Some(host) = ACTIVE_HOST.get()
        && let Err(error) = release(&mut github_api(), key, host)
    {
        eprintln!(
            "run={} attempt={} job={} claim release failed: {error}; it expires",
            key.run.0, key.attempt, key.job.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::{JobId, RunId};
    use super::*;
    use std::collections::BTreeMap as Map;

    fn key(n: u64) -> JobKey {
        JobKey {
            run: RunId(n),
            attempt: 1,
            job: JobId(n),
        }
    }

    /// One GitHub repository's refs and commits, shared by every host's
    /// view: the 422-on-existing-ref rule is the only atomicity relied on.
    #[derive(Default)]
    struct Repo {
        commits: Map<String, String>,
        refs: Map<String, String>,
        calls: Vec<String>,
    }
    impl Repo {
        fn api(
            &mut self,
        ) -> impl FnMut(&str, &str, Option<Value>) -> Result<Value, ScalerError> + '_ {
            move |method: &str, endpoint: &str, body: Option<Value>| {
                self.calls.push(format!("{method} {endpoint}"));
                let path = endpoint
                    .strip_prefix(&format!("repos/{}/git/", super::super::REPOSITORY))
                    .ok_or(ScalerError::External("endpoint"))?;
                match (method, path) {
                    ("POST", "commits") => {
                        let body = body.ok_or(ScalerError::External("body"))?;
                        let sha = format!("{:040x}", self.commits.len() + 1);
                        self.commits
                            .insert(sha.clone(), body["message"].as_str().unwrap_or("").into());
                        Ok(json!({"sha": sha}))
                    }
                    ("POST", "refs") => {
                        let body = body.ok_or(ScalerError::External("body"))?;
                        let name = body["ref"].as_str().unwrap_or("").to_owned();
                        if self.refs.contains_key(&name) {
                            return Err(ScalerError::GithubConflict);
                        }
                        self.refs
                            .insert(name, body["sha"].as_str().unwrap_or("").into());
                        Ok(json!({}))
                    }
                    ("GET", path) if path.starts_with("ref/") => {
                        let name = format!("refs/{}", &path[4..]);
                        let sha = self.refs.get(&name).ok_or(ScalerError::GithubGone)?;
                        Ok(json!({"object": {"sha": sha}}))
                    }
                    ("GET", path) if path.starts_with("commits/") => {
                        let message = self
                            .commits
                            .get(&path[8..])
                            .ok_or(ScalerError::GithubGone)?;
                        Ok(json!({"message": message}))
                    }
                    ("DELETE", path) if path.starts_with("refs/") => {
                        let name = format!("refs/{}", &path[5..]);
                        self.refs.remove(&name).ok_or(ScalerError::GithubGone)?;
                        Ok(Value::Null)
                    }
                    _ => Err(ScalerError::External("unexpected call")),
                }
            }
        }
    }

    #[test]
    fn two_hosts_claiming_one_job_yield_exactly_one_winner() {
        let mut repo = Repo::default();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap(),
            Outcome::Won
        );
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 1001).unwrap(),
            Outcome::HeldElsewhere
        );
        // A different job is independent.
        assert_eq!(
            claim(&mut repo.api(), key(2), "carrick-ctb", 1002).unwrap(),
            Outcome::Won
        );
        assert_eq!(repo.refs.len(), 2);
    }

    #[test]
    fn a_restarted_holder_keeps_its_own_claim() {
        let mut repo = Repo::default();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap(),
            Outcome::Won
        );
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1060).unwrap(),
            Outcome::Won
        );
        assert_eq!(repo.refs.len(), 1);
    }

    #[test]
    fn an_expired_claim_is_reclaimed_and_a_live_one_is_not() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        let ttl = CLAIM_TTL.as_secs();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 1000 + ttl - 1).unwrap(),
            Outcome::HeldElsewhere
        );
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 1000 + ttl).unwrap(),
            Outcome::Won
        );
        // The original holder now sees the new holder's live claim.
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1000 + ttl + 1).unwrap(),
            Outcome::HeldElsewhere
        );
    }

    #[test]
    fn a_claim_from_a_future_clock_or_unknown_writer_blocks() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 5000).unwrap();
        // The other host's clock is behind: the claim looks newer than now.
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 10).unwrap(),
            Outcome::HeldElsewhere
        );
        // A ref in the namespace that is not a claim commit never admits.
        repo.commits.insert("f".repeat(40), "not a claim".into());
        repo.refs
            .insert(format!("refs/{}", ref_name(key(2))), "f".repeat(40));
        assert_eq!(
            claim(&mut repo.api(), key(2), "carrick-ctb", u64::MAX / 2).unwrap(),
            Outcome::HeldElsewhere
        );
    }

    #[test]
    fn release_deletes_only_the_hosts_own_claim() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        release(&mut repo.api(), key(1), "carrick-ctb").unwrap();
        assert_eq!(repo.refs.len(), 1, "another host's claim survives");
        release(&mut repo.api(), key(1), "carrick-hz").unwrap();
        assert!(repo.refs.is_empty());
        // Releasing an absent claim is a no-op.
        release(&mut repo.api(), key(1), "carrick-hz").unwrap();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 1001).unwrap(),
            Outcome::Won
        );
    }

    #[test]
    fn a_follower_waits_out_the_grace_and_the_leader_never_does() {
        let start = Instant::now();
        let mut leader = Claims::new(Role::Leader, "carrick-hz");
        assert!(leader.ready(key(1), start));
        let mut follower = Claims::new(Role::Follower, "carrick-ctb");
        assert!(!follower.ready(key(1), start));
        assert!(!follower.ready(key(1), start + FOLLOWER_GRACE - Duration::from_secs(1)));
        assert!(follower.ready(key(1), start + FOLLOWER_GRACE));
        // A pass that evaluates the job keeps its first-seen time...
        follower.end_pass();
        assert!(follower.ready(key(1), start + FOLLOWER_GRACE));
        // ...and one that never sees it (left demand) forgets it, so a
        // returning job starts its grace again.
        follower.end_pass();
        follower.end_pass();
        assert!(!follower.ready(key(1), start + FOLLOWER_GRACE * 2));
    }

    #[test]
    fn claim_messages_round_trip_and_reject_garbage() {
        assert_eq!(
            parse(&message("carrick-hz", 42)),
            Some(Holder {
                host: "carrick-hz".into(),
                created: 42
            })
        );
        for bad in [
            "",
            "ci-claim v1",
            "ci-claim v1 host= created=1",
            "ci-claim v2 host=a created=1",
            "ci-claim v1 host=a created=x",
            "ci-claim v1 host=a created=1 extra=2",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
