//! Cross-host job claims (#1597): two standing controllers on different
//! Proxmox hosts may serve the same runner labels without each booting a
//! clone for one queued job.
//!
//! A claim is a create-only GitHub ref,
//! `refs/ci-claims/job/<run>-<attempt>-<job>/g<N>`. `POST /git/refs` refuses
//! an existing ref with HTTP 422, so exactly one host's create of a given
//! name succeeds. Each ref points at an empty-tree commit whose message names
//! the claiming host and the creation time.
//!
//! **Generations make every transition a create-only race.** The live claim
//! is the highest generation. A claim older than [`CLAIM_TTL`] (a crashed
//! holder) is taken over by creating generation `N + 1`, never by deleting
//! `N` first, so two hosts taking over at once still produce one winner.
//! A host only ever deletes generations it created itself (its own release),
//! plus expired generations below the one it just won, which nobody can
//! create again.
//!
//! A claim only has to cover reservation to assignment (minutes): once
//! GitHub assigns the job it is no longer queued, so neither host sees it as
//! demand. A JIT runner may still take a different queued job with the same
//! labels; the existing assignment re-vet (#333) covers that, and the claim
//! keeps the clone count across hosts matched to queued jobs.
//!
//! The leader takes jobs as soon as it sees them; a follower takes a job only
//! after it has seen it queued for [`FOLLOWER_GRACE`], so the leader gets
//! first pick and the follower absorbs overflow.
//!
//! Expiry compares the holder's recorded time with the reader's clock, so
//! hosts must keep their clocks in step (both run NTP); a claim stamped in
//! the reader's future blocks until the reader's clock passes it plus the TTL.
//! A ref in this namespace that isn't a claim commit blocks its job for good:
//! nothing but a controller should write here.
use super::{JobKey, ScalerError};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// Git's well-known empty tree; claim commits carry no content.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
/// A claim older than this no longer blocks another host.
pub(super) const CLAIM_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a follower waits after first seeing a queued job.
pub(super) const FOLLOWER_GRACE: Duration = Duration::from_secs(90);
/// A follower forgets a job it hasn't seen queued for this long.
const FORGET_AFTER: Duration = Duration::from_secs(10 * 60);

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
    /// This host holds the claim (new, taken over after expiry, or its own).
    Won,
    /// Another host holds a live claim.
    HeldElsewhere,
}

/// `ci-claims/job/<run>-<attempt>-<job>/`: every generation of one job.
fn prefix(key: JobKey) -> String {
    format!("ci-claims/job/{}-{}-{}/", key.run.0, key.attempt, key.job.0)
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

/// Every generation of `key`'s claim as `(generation, commit sha)`,
/// ascending. A ref under the prefix that isn't `g<N>` is reported as
/// generation `u32::MAX` so it reads as a permanent foreign holder.
fn generations(api: &mut impl Api, key: JobKey) -> Result<Vec<(u32, String)>, ScalerError> {
    let listed = match api.call(
        "GET",
        &format!(
            "repos/{}/git/matching-refs/{}",
            super::REPOSITORY,
            prefix(key)
        ),
        None,
    ) {
        Ok(listed) => listed,
        Err(ScalerError::GithubGone) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let full = format!("refs/{}", prefix(key));
    let mut found = Vec::new();
    for entry in listed
        .as_array()
        .ok_or(ScalerError::External("claim ref list"))?
    {
        let name = entry["ref"]
            .as_str()
            .ok_or(ScalerError::External("claim ref name"))?;
        let Some(rest) = name.strip_prefix(&full) else {
            continue;
        };
        let generation = rest
            .strip_prefix('g')
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        let sha = entry["object"]["sha"]
            .as_str()
            .ok_or(ScalerError::External("claim ref sha"))?
            .to_owned();
        found.push((generation, sha));
    }
    found.sort();
    Ok(found)
}

/// The holder of one generation. An unreadable or unparseable commit is a
/// foreign holder that never expires.
fn holder(api: &mut impl Api, sha: &str) -> Result<Holder, ScalerError> {
    let foreign = Holder {
        host: String::new(),
        created: u64::MAX,
    };
    match api.call(
        "GET",
        &format!("repos/{}/git/commits/{sha}", super::REPOSITORY),
        None,
    ) {
        Ok(commit) => Ok(commit["message"]
            .as_str()
            .and_then(parse)
            .unwrap_or(foreign)),
        Err(ScalerError::GithubGone) => Ok(foreign),
        Err(error) => Err(error),
    }
}

/// Create generation `generation` for `host`; `false` if it already exists.
fn create(
    api: &mut impl Api,
    key: JobKey,
    generation: u32,
    host: &str,
    now: u64,
) -> Result<bool, ScalerError> {
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
        Some(json!({"ref": format!("refs/{}g{generation}", prefix(key)), "sha": sha})),
    ) {
        Ok(_) => Ok(true),
        Err(ScalerError::GithubConflict) => Ok(false),
        Err(error) => Err(error),
    }
}

fn delete(api: &mut impl Api, key: JobKey, generation: u32) -> Result<(), ScalerError> {
    match api.call(
        "DELETE",
        &format!(
            "repos/{}/git/refs/{}g{generation}",
            super::REPOSITORY,
            prefix(key)
        ),
        None,
    ) {
        Ok(_) | Err(ScalerError::GithubGone) => Ok(()),
        Err(error) => Err(error),
    }
}

fn expired(holder: &Holder, now: u64) -> bool {
    holder.created <= now && now - holder.created >= CLAIM_TTL.as_secs()
}

/// Claim `key` for `host` at unix time `now`.
pub(super) fn claim(
    api: &mut impl Api,
    key: JobKey,
    host: &str,
    now: u64,
) -> Result<Outcome, ScalerError> {
    let existing = generations(api, key)?;
    let next = match existing.last() {
        None => 0,
        Some((generation, sha)) => {
            let current = holder(api, sha)?;
            if current.host == host {
                // Our own claim, e.g. from before a controller restart.
                return Ok(Outcome::Won);
            }
            if *generation == u32::MAX || !expired(&current, now) {
                return Ok(Outcome::HeldElsewhere);
            }
            generation + 1
        }
    };
    if !create(api, key, next, host, now)? {
        // Another host created this generation first.
        return Ok(Outcome::HeldElsewhere);
    }
    // Generations below the one just won are expired and can never be
    // created again; removing them is housekeeping, so a failure is fine.
    for (generation, _) in existing {
        let _ = delete(api, key, generation);
    }
    Ok(Outcome::Won)
}

/// Release every generation of `key` that `host` created. Another host's
/// generations are never touched: no one else can create a name this host
/// created, so deleting it can't remove someone else's claim.
pub(super) fn release(api: &mut impl Api, key: JobKey, host: &str) -> Result<(), ScalerError> {
    for (generation, sha) in generations(api, key)? {
        if generation != u32::MAX && holder(api, &sha)?.host == host {
            delete(api, key, generation)?;
        }
    }
    Ok(())
}

/// Start-up check that this controller's credential can create and delete
/// claim refs, so a missing permission fails loudly at start instead of at
/// the first queued job.
pub(super) fn probe(api: &mut impl Api, host: &str, now: u64) -> Result<(), ScalerError> {
    let name = format!("ci-claims/probe/{host}");
    match api.call(
        "DELETE",
        &format!("repos/{}/git/refs/{name}", super::REPOSITORY),
        None,
    ) {
        Ok(_) | Err(ScalerError::GithubGone) => {}
        Err(error) => return Err(error),
    }
    let commit = api.call(
        "POST",
        &format!("repos/{}/git/commits", super::REPOSITORY),
        Some(json!({"message": message(host, now), "tree": EMPTY_TREE, "parents": []})),
    )?;
    let sha = commit["sha"]
        .as_str()
        .ok_or(ScalerError::External("claim probe sha"))?;
    api.call(
        "POST",
        &format!("repos/{}/git/refs", super::REPOSITORY),
        Some(json!({"ref": format!("refs/{name}"), "sha": sha})),
    )?;
    api.call(
        "DELETE",
        &format!("repos/{}/git/refs/{name}", super::REPOSITORY),
        None,
    )?;
    Ok(())
}

/// Per-controller claim policy: role, host identity and, for a follower,
/// when each queued job was first and last seen.
pub(super) struct Claims {
    pub role: Role,
    pub host: &'static str,
    /// (job, first seen, last seen). Demand is a handful of jobs, so a
    /// vector suffices.
    seen: Vec<(JobKey, Instant, Instant)>,
}
impl Claims {
    pub(super) fn new(role: Role, host: &'static str) -> Self {
        Self {
            role,
            host,
            seen: Vec::new(),
        }
    }
    /// Whether this controller may take `job` now. The leader always may; a
    /// follower only once the job has been queued in its view for the grace.
    pub(super) fn ready(&mut self, job: JobKey, now: Instant) -> bool {
        if self.role == Role::Leader {
            return true;
        }
        let first = match self.seen.iter_mut().find(|(key, ..)| *key == job) {
            Some(entry) => {
                entry.2 = now;
                entry.1
            }
            None => {
                self.seen.push((job, now, now));
                now
            }
        };
        now.duration_since(first) >= FOLLOWER_GRACE
    }
    /// Forget jobs not seen for [`FORGET_AFTER`]. Time-based, so a pass that
    /// stops early or fails to read demand doesn't restart anyone's grace.
    pub(super) fn forget_stale(&mut self, now: Instant) {
        self.seen
            .retain(|(_, _, last)| now.duration_since(*last) < FORGET_AFTER);
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
    if let Some(host) = ACTIVE_HOST.get() {
        release_logged(&mut github_api(), key, host);
    }
}
fn release_logged(api: &mut impl Api, key: JobKey, host: &str) {
    if let Err(error) = release(api, key, host) {
        eprintln!(
            "run={} attempt={} job={} claim release failed: {error}; it expires",
            key.run.0, key.attempt, key.job.0
        );
    }
}

/// After a claimed job's reservation attempt: release the claim unless this
/// host now serves the job (`served`), so a job this host won't serve goes
/// back at once instead of blocking the other host until it expires. A
/// reservation that returned nothing because the job is already served
/// (a live row exists) keeps its claim.
pub(super) fn settle_unreserved(
    api: &mut impl Api,
    key: JobKey,
    host: &str,
    reserved: bool,
    served: bool,
) {
    if !reserved && !served {
        release_logged(api, key, host);
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
        writes: usize,
    }
    impl Repo {
        fn api(
            &mut self,
        ) -> impl FnMut(&str, &str, Option<Value>) -> Result<Value, ScalerError> + '_ {
            move |method: &str, endpoint: &str, body: Option<Value>| {
                let path = endpoint
                    .strip_prefix(&format!("repos/{}/git/", super::super::REPOSITORY))
                    .ok_or(ScalerError::External("endpoint"))?;
                if method != "GET" {
                    self.writes += 1;
                }
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
                    ("GET", path) if path.starts_with("matching-refs/") => {
                        let wanted = format!("refs/{}", &path["matching-refs/".len()..]);
                        Ok(Value::Array(
                            self.refs
                                .iter()
                                .filter(|(name, _)| name.starts_with(&wanted))
                                .map(|(name, sha)| json!({"ref": name, "object": {"sha": sha}}))
                                .collect(),
                        ))
                    }
                    ("GET", path) if path.starts_with("commits/") => {
                        let message = self
                            .commits
                            .get(&path["commits/".len()..])
                            .ok_or(ScalerError::GithubGone)?;
                        Ok(json!({"message": message}))
                    }
                    ("DELETE", path) if path.starts_with("refs/") => {
                        let name = format!("refs/{}", &path["refs/".len()..]);
                        self.refs.remove(&name).ok_or(ScalerError::GithubGone)?;
                        Ok(Value::Null)
                    }
                    _ => Err(ScalerError::External("unexpected call")),
                }
            }
        }
        fn generation_names(&self, key: JobKey) -> Vec<String> {
            let full = format!("refs/{}", prefix(key));
            self.refs
                .keys()
                .filter_map(|name| name.strip_prefix(&full).map(str::to_owned))
                .collect()
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
        // A different job is independent, and a job whose key is a prefix
        // of another's (job 1 vs 11) never reads the other's claims.
        assert_eq!(
            claim(&mut repo.api(), key(11), "carrick-ctb", 1002).unwrap(),
            Outcome::Won
        );
        assert_eq!(repo.refs.len(), 2);
    }

    #[test]
    fn a_held_job_costs_reads_only() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        let writes = repo.writes;
        for t in 1..5 {
            claim(&mut repo.api(), key(1), "carrick-ctb", 1000 + t).unwrap();
        }
        assert_eq!(repo.writes, writes, "no orphan commits or ref attempts");
    }

    #[test]
    fn a_restarted_holder_keeps_its_own_claim() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1060).unwrap(),
            Outcome::Won
        );
        assert_eq!(repo.generation_names(key(1)), vec!["g0"]);
    }

    #[test]
    fn an_expired_claim_is_taken_over_by_the_next_generation_only() {
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
        // The winner holds g1, and the expired g0 is cleaned up.
        assert_eq!(repo.generation_names(key(1)), vec!["g1"]);
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1000 + ttl + 1).unwrap(),
            Outcome::HeldElsewhere
        );
    }

    #[test]
    fn two_hosts_taking_over_one_expired_claim_yield_one_winner() {
        // Both hosts read g0 as expired before either acts: the old
        // delete-then-create let the second delete the first's fresh claim.
        // With generations, both race to create g1 and one gets 422.
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-old", 0).unwrap();
        let late = CLAIM_TTL.as_secs() + 5;
        let existing = generations(&mut repo.api(), key(1)).unwrap();
        assert_eq!(existing.len(), 1);
        let a = create(&mut repo.api(), key(1), 1, "carrick-hz", late).unwrap();
        let b = create(&mut repo.api(), key(1), 1, "carrick-ctb", late).unwrap();
        assert!(a && !b, "exactly one creates the next generation");
        // Through the public path the loser now reads a live g1 held by
        // the winner.
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", late).unwrap(),
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
        // A ref under the prefix that is not a claim commit never admits,
        // nor does a non-generation name.
        repo.commits.insert("f".repeat(40), "not a claim".into());
        repo.refs
            .insert(format!("refs/{}g0", prefix(key(2))), "f".repeat(40));
        assert_eq!(
            claim(&mut repo.api(), key(2), "carrick-ctb", u64::MAX / 2).unwrap(),
            Outcome::HeldElsewhere
        );
        repo.refs
            .insert(format!("refs/{}other", prefix(key(3))), "f".repeat(40));
        assert_eq!(
            claim(&mut repo.api(), key(3), "carrick-ctb", u64::MAX / 2).unwrap(),
            Outcome::HeldElsewhere
        );
    }

    #[test]
    fn release_deletes_only_the_hosts_own_generations() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        release(&mut repo.api(), key(1), "carrick-ctb").unwrap();
        assert_eq!(repo.refs.len(), 1, "another host's claim survives");
        release(&mut repo.api(), key(1), "carrick-hz").unwrap();
        assert!(repo.refs.is_empty());
        // Releasing an absent claim is a no-op, and the job is free again.
        release(&mut repo.api(), key(1), "carrick-hz").unwrap();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-ctb", 1001).unwrap(),
            Outcome::Won
        );
        // A stale releaser never removes a newer holder's generation.
        let ttl = CLAIM_TTL.as_secs();
        assert_eq!(
            claim(&mut repo.api(), key(1), "carrick-hz", 1001 + ttl).unwrap(),
            Outcome::Won
        );
        release(&mut repo.api(), key(1), "carrick-ctb").unwrap();
        assert_eq!(repo.generation_names(key(1)), vec!["g1"]);
    }

    #[test]
    fn an_unserved_claim_goes_back_and_a_served_one_stays() {
        let mut repo = Repo::default();
        claim(&mut repo.api(), key(1), "carrick-hz", 1000).unwrap();
        // Already served (a live row raced in): keep the claim.
        settle_unreserved(&mut repo.api(), key(1), "carrick-hz", false, true);
        assert_eq!(repo.refs.len(), 1);
        // Reserved: keep it.
        settle_unreserved(&mut repo.api(), key(1), "carrick-hz", true, true);
        assert_eq!(repo.refs.len(), 1);
        // Not reserved and not served (refused, CPU ceiling, error): release.
        settle_unreserved(&mut repo.api(), key(1), "carrick-hz", false, false);
        assert!(repo.refs.is_empty());
    }

    #[test]
    fn the_startup_probe_creates_and_removes_its_ref() {
        let mut repo = Repo::default();
        // A probe ref left by a crash is cleared first.
        repo.refs
            .insert("refs/ci-claims/probe/carrick-hz".into(), "0".repeat(40));
        probe(&mut repo.api(), "carrick-hz", 1000).unwrap();
        assert!(repo.refs.is_empty());
        // A credential that can't write fails the probe.
        let mut denied = |_: &str, _: &str, _: Option<Value>| -> Result<Value, ScalerError> {
            Err(ScalerError::CommandFailed("gh exited 1".into()))
        };
        assert!(probe(&mut denied, "carrick-hz", 1000).is_err());
    }

    #[test]
    fn a_follower_waits_out_the_grace_and_the_leader_never_does() {
        let start = Instant::now();
        let mut leader = Claims::new(Role::Leader, "carrick-hz");
        assert!(leader.ready(key(1), start));
        let mut follower = Claims::new(Role::Follower, "carrick-ctb");
        assert!(!follower.ready(key(1), start));
        assert!(!follower.ready(key(1), start + FOLLOWER_GRACE - Duration::from_secs(1)));
        // A pass that never evaluates the job (admission stopped early, or
        // demand failed to read) doesn't reset its grace.
        follower.forget_stale(start + FOLLOWER_GRACE);
        assert!(follower.ready(key(1), start + FOLLOWER_GRACE));
        // A job unseen for FORGET_AFTER is forgotten; on return its grace
        // starts again.
        let later = start + FOLLOWER_GRACE + FORGET_AFTER;
        follower.forget_stale(later);
        assert!(!follower.ready(key(1), later));
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
