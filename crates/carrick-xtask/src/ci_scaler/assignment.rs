//! Re-vetting a JIT runner's **actual** assignment, shared by cloudmac HVF
//! runners (`mac-jit`, #256) and standing KVM clones (`standing`, #333).
//!
//! GitHub does not bind a JIT registration to the run its controller reserved
//! it for: any queued job with the runner's labels may be assigned to it. The
//! job-start hook therefore publishes the actual run through a credential-free
//! rendezvous (`assignment.json` in the runner's state directory) and waits.
//! The credential-holding controller authenticates the request by runner id,
//! re-vets that run exactly as it vets demand (same main admission and
//! attempt), records the actual
//! job durably and only then publishes a root-owned `approved-policy` bound to
//! the actual run, attempt and SHA. A refused assignment is recorded once and
//! gets no approval: the hook's deadline kills the session before any step.
//!
//! Only the transport differs per controller ([`AssignmentExchange`]): SSH to
//! the root-only `mac-quiesce --assignment` on cloudmac, or the scoped PVE
//! guest agent for a KVM clone.
use super::github::Github;
use super::*;
use serde_json::Value;

/// In-process ledger publication. The assignment worker never owns a lifecycle
/// transition, and the lifecycle loop never overwrites an assignment decision.
#[derive(Debug, Clone)]
pub(super) struct Publication<T> {
    committed: std::sync::Arc<std::sync::Mutex<T>>,
    assignments_only: bool,
    admission: std::sync::Arc<std::sync::Mutex<()>>,
}
impl<T: Clone> Publication<T> {
    pub(super) fn new(value: T) -> Self {
        Self {
            committed: std::sync::Arc::new(std::sync::Mutex::new(value)),
            assignments_only: false,
            admission: std::sync::Arc::new(std::sync::Mutex::new(())),
        }
    }
    pub(super) fn admission_lock(&self) -> std::sync::Arc<std::sync::Mutex<()>> {
        self.admission.clone()
    }
    pub(super) fn snapshot(&self) -> Result<T, ScalerError> {
        self.committed
            .lock()
            .map(|value| value.clone())
            .map_err(|_| ScalerError::Guard("ledger publication poisoned"))
    }
    pub(super) fn worker(&self) -> Self {
        Self {
            committed: self.committed.clone(),
            assignments_only: true,
            admission: self.admission.clone(),
        }
    }
    pub(super) fn commit(
        &self,
        candidate: &T,
        path: &Path,
        merge: impl FnOnce(&mut T, &T),
    ) -> Result<(), ScalerError>
    where
        T: Serialize,
    {
        let mut committed = self
            .committed
            .lock()
            .map_err(|_| ScalerError::Guard("ledger publication poisoned"))?;
        let mut next = if self.assignments_only {
            committed.clone()
        } else {
            candidate.clone()
        };
        let source = if self.assignments_only {
            candidate
        } else {
            &committed
        };
        merge(&mut next, source);
        save_json(&next, path)?;
        *committed = next;
        Ok(())
    }
}

/// Publish matching records without scanning the source population per row.
/// First occurrence wins, matching the ledger's existing identity lookup.
pub(super) fn merge_records<R, K: Ord>(
    target: &mut [R],
    source: &[R],
    mut key: impl FnMut(&R) -> K,
    mut merge: impl FnMut(&mut R, &R),
) {
    let mut records = std::collections::BTreeMap::new();
    for row in source {
        records.entry(key(row)).or_insert(row);
    }
    for row in target {
        if let Some(other) = records.get(&key(row)) {
            merge(row, other);
        }
    }
}

/// A separately scheduled rendezvous worker. Shutdown wakes its timer and
/// joins it; no detached worker survives the controller's ledger lock.
pub(super) struct AssignmentService {
    stop: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl AssignmentService {
    pub(super) fn start(mut pass: impl FnMut() + Send + 'static) -> Self {
        let (stop, wake) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            loop {
                pass();
                if wake.recv_timeout(Duration::from_secs(1))
                    != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                {
                    break;
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for AssignmentService {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Literal hook command in `scripts/ci/admit-job.sh` (the KVM guest path).
pub(super) const HOOK_COMMAND: &str = "/usr/local/bin/carrick-xtask ci-scaler admit-job";
/// How long a hook waits for the controller's approval before it fails closed.
pub(super) const APPROVAL_LIMIT: Duration = Duration::from_secs(240);
/// Retain a bounded cache of recent refusal decisions. Eviction only removes
/// a scheduling cache entry: every later assignment still undergoes full vetting.
pub(super) fn bound_refusals(keys: &mut Vec<JobKey>) {
    keys.sort_by_key(|key| key.job.0);
    let excess = keys.len().saturating_sub(4096);
    keys.drain(..excess);
}

/// Upper bound of one hook request; a larger one is refused unread.
pub(super) const REQUEST_LIMIT: usize = 8192;

/// The shared terminal job-start hook with `command` substituted for its
/// single policy decision. Everything else (the session kill) is unchanged.
pub(super) fn hook_script(command: &str) -> Result<String, ScalerError> {
    let source = include_str!("../../../../scripts/ci/admit-job.sh");
    if source.matches(HOOK_COMMAND).count() != 1 {
        return Err(ScalerError::Guard("job-start hook command is not unique"));
    }
    Ok(source.replace(HOOK_COMMAND, command))
}

/// Every standing KVM assignment, including the reserved run, rendezvouses
/// with the controller so a durable supersession can withhold approval.
pub fn standing_hook_script() -> Result<String, ScalerError> {
    hook_script(&format!("{HOOK_COMMAND} --controller"))
}

/// Credential-free rendezvous: publish the actual context, then wait for a
/// root-owned policy produced by the controller's GitHub re-vetting.
pub fn admit_assigned(
    state: &Path,
    context: &JobContext,
    owner: u32,
    limit: Duration,
) -> Result<(), ScalerError> {
    authorize_context(context)?;
    if context.run_id == 0 || context.run_attempt == 0 {
        return Err(ScalerError::Guard("invalid assigned run identity"));
    }
    {
        let _lock = admission_lock(state)?;
        if state.join("draining").exists() {
            return Err(ScalerError::Guard("runner is draining"));
        }
        let mut request = OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join("assignment.json"))?;
        request.write_all(&serde_json::to_vec(context)?)?;
        request.sync_all()?;
    }
    let deadline = Instant::now() + limit;
    loop {
        if state.join("approved-policy").exists() {
            return read_policy(&state.join("approved-policy"), Some(owner))?.authorize(context);
        }
        if state.join("draining").exists() || Instant::now() >= deadline {
            return Err(ScalerError::Guard("assigned run approval unavailable"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Parse one hook request. Empty means the hook has not asked (yet).
pub(super) fn parse_request(bytes: &[u8]) -> Result<Option<JobContext>, ScalerError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > REQUEST_LIMIT {
        return Err(ScalerError::Guard("assignment request too large"));
    }
    let context = serde_json::from_slice(bytes)?;
    authorize_context(&context)?;
    Ok(Some(context))
}

/// Read only the pre-created file beneath the fixed, root-owned state root.
/// A job can request an identity; it cannot write approval or choose paths.
pub fn pending_assignment(state: &Path) -> Result<Option<JobContext>, ScalerError> {
    let _lock = admission_lock(state)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join("assignment.json"))?;
    let mut bytes = Vec::new();
    file.take(REQUEST_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    parse_request(&bytes)
}

pub fn publish_assignment(state: &Path, policy: &JobPolicy) -> Result<(), ScalerError> {
    let _lock = admission_lock(state)?;
    if state.join("draining").exists() {
        return Err(ScalerError::Guard("runner is draining"));
    }
    // Idempotent on controller restart; never replace approval with another run.
    let path = state.join("approved-policy");
    if path.exists() {
        if read_policy(&path, Some(unsafe { libc::geteuid() }))? == *policy {
            return Ok(());
        }
        return Err(ScalerError::Guard("assignment approval changed"));
    }
    let temp = state.join("approved-policy.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    file.write_all(policy.render().as_bytes())?;
    file.sync_all()?;
    std::fs::rename(temp, path)?;
    File::open(state)?.sync_all()?;
    Ok(())
}

/// Authenticate a hook request against GitHub job metadata for this runner:
/// exactly one job of the requested run/attempt runs on `runner`, with
/// exactly the runner's `labels`.
pub fn assigned_job_key(
    context: &JobContext,
    runner: RunnerId,
    labels: &[&str],
    jobs: &[Value],
) -> Result<JobKey, ScalerError> {
    authorize_context(context)?;
    let jobs: Vec<_> = jobs
        .iter()
        .filter(|job| job["runner_id"].as_u64() == Some(runner.0))
        .collect();
    let [job] = jobs.as_slice() else {
        return Err(ScalerError::Guard(
            "actual assignment is not uniquely visible on GitHub",
        ));
    };
    let actual: Vec<_> = job["labels"]
        .as_array()
        .ok_or(ScalerError::External("assigned labels"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if !labels_match(labels, &actual) {
        return Err(ScalerError::Guard("actual job has incompatible labels"));
    }
    Ok(JobKey {
        run: RunId(context.run_id),
        attempt: context.run_attempt,
        job: JobId(
            job["id"]
                .as_u64()
                .ok_or(ScalerError::External("actual job id"))?,
        ),
    })
}

/// A cancellation intent reaches disk before the remote mutation. Pending
/// intents are revalidated after restart. Observed started hardware blocks
/// the POST; another controller can still start it between GET and POST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum CancellationOutcome {
    /// Cancellation was accepted; retain until GitHub confirms completion.
    Cancelled,
    NotCancelled,
    Deferred,
    Gone,
    Completed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SupersededPush {
    pub key: JobKey,
    pub sha: String,
    pub reason: String,
    pub outcome: Option<CancellationOutcome>,
    #[serde(default)]
    pub created: u64,
}

pub(super) fn prioritize_demand(mut demand: Vec<super::github::QueuedJob>) -> Vec<JobKey> {
    let newest = demand
        .iter()
        .filter(|job| job.event == "push")
        .map(|job| job.key.run.0)
        .max();
    demand.retain(|job| job.event != "push" || Some(job.key.run.0) == newest);
    demand.sort_by_key(|job| {
        (
            job.event != "push",
            std::cmp::Reverse(job.key.run.0),
            job.key.job.0,
        )
    });
    demand.dedup_by_key(|job| job.key.job.0);
    demand.into_iter().map(|job| job.key).collect()
}

pub(super) fn run_superseded(entries: &[SupersededPush], key: JobKey) -> bool {
    entries
        .iter()
        .any(|entry| entry.key.run == key.run && entry.key.attempt == key.attempt)
}
/// Keep only records whose attempt can still be queued. Missing timestamps
/// acquire a durable first-observed time, never a guessed expiry.
fn prune_superseded(entries: &mut Vec<SupersededPush>, time: u64) {
    for entry in entries.iter_mut() {
        if entry.created == 0 {
            entry.created = time;
        }
    }
    entries.retain(|entry| {
        !matches!(
            entry.outcome,
            Some(CancellationOutcome::Gone | CancellationOutcome::Completed)
        ) && time.saturating_sub(entry.created) <= SUPERSESSION_MAX_AGE
    });
}
pub(super) const SUPERSESSION_LIMIT: usize = 4096;
const SUPERSESSION_MAX_AGE: u64 = 25 * 60 * 60;
pub(super) fn supersession_capacity(entries: &[SupersededPush]) -> Result<(), ScalerError> {
    if entries.len() > SUPERSESSION_LIMIT {
        Err(ScalerError::SupersessionCapacity {
            live: entries.len(),
            limit: SUPERSESSION_LIMIT,
        })
    } else {
        Ok(())
    }
}

/// Persist local denial before API cleanup. Cleanup errors cannot poison new
/// demand; only lost durability or an over-cap live journal stops admission.
pub(super) fn coalesce_demand(
    ledger: &mut impl Refusals,
    mut demand: Vec<super::github::QueuedJob>,
    path: &Path,
    mut cancel: impl FnMut(&SupersededPush) -> Result<CancellationOutcome, ScalerError>,
) -> Result<Vec<JobKey>, ScalerError> {
    let admission = ledger.admission_lock();
    let journal = {
        let _guard = admission
            .as_ref()
            .map(|lock| {
                lock.lock()
                    .map_err(|_| ScalerError::Guard("controller admission poisoned"))
            })
            .transpose()?;
        ledger.refresh()?;
        let time = now()?;
        prune_superseded(ledger.superseded_mut(), time);
        let mut journal = ledger.superseded().to_vec();
        let mut added = Vec::new();
        if let Some(newest) = demand
            .iter()
            .filter(|job| job.event == "push")
            .max_by_key(|job| job.key.run.0)
        {
            for job in demand
                .iter()
                .filter(|job| job.event == "push" && job.key.run.0 < newest.key.run.0)
            {
                if ledger.has_approved_run(job.key) || run_superseded(&journal, job.key) {
                    continue;
                }
                let entry = SupersededPush {
                    key: job.key,
                    sha: job.sha.clone(),
                    reason: format!("superseded by {}", newest.sha),
                    outcome: None,
                    created: time,
                };
                added.push(entry.clone());
                journal.push(entry);
            }
        }
        *ledger.superseded_mut() = journal.clone();
        ledger.set_supersession_error(supersession_capacity(&journal).err().map(|e| e.to_string()));
        ledger.persist(path)?;
        for entry in added {
            eprintln!(
                "run={} attempt={} {}; local admission durably closed",
                entry.key.run.0, entry.key.attempt, entry.reason
            );
        }
        journal
    };
    let mut outcomes = std::collections::BTreeMap::new();
    for entry in &journal {
        let outcome = match cancel(entry) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!(
                    "run={} attempt={} {}; cleanup Deferred: {error}",
                    entry.key.run.0, entry.key.attempt, entry.reason
                );
                CancellationOutcome::Deferred
            }
        };
        eprintln!(
            "run={} attempt={} {}; {outcome:?}",
            entry.key.run.0, entry.key.attempt, entry.reason
        );
        outcomes.insert((entry.key.run.0, entry.key.attempt), outcome);
    }
    {
        let _guard = admission
            .as_ref()
            .map(|lock| {
                lock.lock()
                    .map_err(|_| ScalerError::Guard("controller admission poisoned"))
            })
            .transpose()?;
        ledger.refresh()?;
        for entry in ledger.superseded_mut() {
            if let Some(outcome) = outcomes.remove(&(entry.key.run.0, entry.key.attempt)) {
                entry.outcome = Some(outcome);
            }
        }
        prune_superseded(ledger.superseded_mut(), now()?);
        ledger.set_supersession_error(
            supersession_capacity(ledger.superseded())
                .err()
                .map(|e| e.to_string()),
        );
        ledger.persist(path)?;
    }
    supersession_capacity(ledger.superseded())?;
    demand.retain(|job| !run_superseded(ledger.superseded(), job.key));
    Ok(prioritize_demand(demand))
}

/// A controller ledger that records per-job refusals durably.
pub(super) trait Refusals {
    fn served(&self, key: JobKey) -> bool;
    fn refused(&self) -> &[JobKey];
    fn refused_mut(&mut self) -> &mut Vec<JobKey>;
    fn superseded(&self) -> &[SupersededPush];
    fn superseded_mut(&mut self) -> &mut Vec<SupersededPush>;
    fn set_supersession_error(&mut self, error: Option<String>);
    fn has_approved_run(&self, key: JobKey) -> bool;
    fn mark_approved(&mut self, key: JobKey, path: &Path) -> Result<(), ScalerError>;
    fn admission_lock(&self) -> Option<std::sync::Arc<std::sync::Mutex<()>>>;
    fn refresh(&mut self) -> Result<(), ScalerError>;
    fn persist(&self, path: &Path) -> Result<(), ScalerError>;
}

/// One admission decision for both controller ledgers. Per-job refusals are
/// skipped in-pass; external failures retain the controller's backoff policy.
pub(super) fn admit_demand<T>(
    ledger: &mut impl Refusals,
    path: &Path,
    demand: Vec<JobKey>,
    mut admit: impl FnMut(JobKey) -> Result<T, ScalerError>,
) -> Result<Option<T>, ScalerError> {
    for job in demand {
        if ledger.served(job) {
            continue;
        }
        match admit(job) {
            Ok(vetted) => return Ok(Some(vetted)),
            Err(error @ ScalerError::Guard(_)) => {
                refuse(ledger, job, &error, path)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// Record and log a per-job refusal once; a new attempt has a new key.
pub(super) fn refuse(
    ledger: &mut impl Refusals,
    key: JobKey,
    error: &ScalerError,
    path: &Path,
) -> Result<(), ScalerError> {
    if ledger.refused().contains(&key) {
        return Ok(());
    }
    let previous = ledger.refused().to_vec();
    ledger.refused_mut().push(key);
    bound_refusals(ledger.refused_mut());
    if let Err(error) = ledger.persist(path) {
        *ledger.refused_mut() = previous;
        return Err(error);
    }
    eprintln!(
        "run={} attempt={} job={} refused: {error}; skipping",
        key.run.0, key.attempt, key.job.0
    );
    Ok(())
}

/// The hook's request as the controller's transport reports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AssignmentRequest {
    pub(super) context: JobContext,
    /// Approval already published (a restarted controller republishes nothing).
    pub(super) approved: bool,
    /// The one-use runner already exited.
    pub(super) finished: bool,
}

/// The per-controller half of the rendezvous.
pub(super) trait AssignmentExchange {
    fn read(&mut self) -> Result<Option<AssignmentRequest>, ScalerError>;
    fn approve(&mut self, policy: &JobPolicy) -> Result<(), ScalerError>;
}

/// The GitHub reads the re-vet needs; [`Github`] in production.
pub(super) trait AssignmentApi {
    fn run_jobs(&self, run: RunId, attempt: u32) -> Result<Vec<Value>, ScalerError>;
    /// The same standing vet that admits demand.
    fn revet(&self, key: JobKey) -> Result<JobPolicy, ScalerError>;
}
impl AssignmentApi for Github {
    fn run_jobs(&self, run: RunId, attempt: u32) -> Result<Vec<Value>, ScalerError> {
        self.jobs(&serde_json::json!({"id": run.0, "run_attempt": attempt}))
    }
    fn revet(&self, key: JobKey) -> Result<JobPolicy, ScalerError> {
        self.vet_assignment(key)
    }
}

/// What one rendezvous step decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Revetted {
    /// No request: the hook has not asked (or its runner was admitted by
    /// its reservation).
    Idle,
    /// Recorded; already approved, or the runner already exited.
    Recorded(JobKey),
    /// Re-vetted and approved with the actual run's own policy.
    Approved(JobKey, JobPolicy),
    /// Refused (recorded once); approval withheld, so the hook kills the job.
    Refused(JobKey),
}

/// One rendezvous step for one runner. `record` makes the actual job key
/// durable in the controller's ledger before any approval is published.
/// Per-job refusals never fail the step; API/transport failures do.
pub(super) fn serve_assignment<L: Refusals>(
    api: &impl AssignmentApi,
    exchange: &mut impl AssignmentExchange,
    labels: &[&str],
    runner: Option<RunnerId>,
    ledger: &mut L,
    path: &Path,
    record: impl FnOnce(&mut L, JobKey) -> Result<(), ScalerError>,
) -> Result<Revetted, ScalerError> {
    let admission = ledger.admission_lock();
    let _guard = admission
        .as_ref()
        .map(|lock| {
            lock.lock()
                .map_err(|_| ScalerError::Guard("controller admission poisoned"))
        })
        .transpose()?;
    ledger.refresh()?;
    let Some(request) = exchange.read()? else {
        return Ok(Revetted::Idle);
    };
    let context = request.context;
    authorize_context(&context)?;
    let runner = runner.ok_or(ScalerError::Guard("assignment has no registered runner"))?;
    let jobs = api.run_jobs(RunId(context.run_id), context.run_attempt)?;
    let key = assigned_job_key(&context, runner, labels, &jobs)?;
    record(ledger, key)?; // True assignment is durable BEFORE steps may run.
    if run_superseded(ledger.superseded(), key) {
        refuse(
            ledger,
            key,
            &ScalerError::Guard("run superseded before admission"),
            path,
        )?;
        return Ok(Revetted::Refused(key));
    }
    if request.approved {
        ledger.mark_approved(key, path)?;
    }
    if request.approved || request.finished {
        return Ok(Revetted::Recorded(key));
    }
    supersession_capacity(ledger.superseded())?;
    if ledger.refused().contains(&key) {
        return Ok(Revetted::Refused(key)); // Withhold approval.
    }
    let policy = match api.revet(key) {
        Ok(policy) => policy,
        Err(error @ ScalerError::Guard(_)) => {
            refuse(ledger, key, &error, path)?;
            return Ok(Revetted::Refused(key));
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = policy.authorize(&context) {
        refuse(ledger, key, &error, path)?;
        return Ok(Revetted::Refused(key));
    }
    ledger.mark_approved(key, path)?;
    exchange.approve(&policy)?;
    Ok(Revetted::Approved(key, policy))
}

fn authorize_context(context: &JobContext) -> Result<(), ScalerError> {
    if context.workflow_ref == format!("{REPOSITORY}/{DISPATCH_WORKFLOW}@refs/heads/main") {
        Admission::Agent.authorize(context)
    } else {
        Admission::Standing.authorize(context)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    const RUNNER: RunnerId = RunnerId(700);

    fn queued(context: &JobContext, job: u64) -> super::super::github::QueuedJob {
        super::super::github::QueuedJob {
            key: key(context, job),
            event: context.event.clone(),
            sha: context.sha.clone(),
        }
    }

    #[test]
    fn newer_main_push_coalesces_older_queued_work() {
        let newer_context = context(30, "push", "refs/heads/main", &"c".repeat(40));
        let newer = key(&newer_context, 31);
        assert_eq!(
            prioritize_demand(vec![queued(&newer_context, 31), queued(&run_a(), 11)]),
            vec![newer]
        );
    }

    fn context(run: u64, event: &str, git_ref: &str, sha: &str) -> JobContext {
        JobContext {
            repository: REPOSITORY.into(),
            actor: "tjfontaine".into(),
            triggering_actor: "tjfontaine".into(),
            event: event.into(),
            workflow_ref: format!("{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@{git_ref}"),
            git_ref: git_ref.into(),
            sha: sha.into(),
            run_id: run,
            run_attempt: 1,
        }
    }
    /// Run A: the push to main the clone was minted for.
    fn run_a() -> JobContext {
        context(10, "push", "refs/heads/main", &"a".repeat(40))
    }
    /// Run B: an owner dispatch GitHub assigned to that clone instead.
    fn run_b() -> JobContext {
        context(20, "workflow_dispatch", "refs/heads/main", &"b".repeat(40))
    }
    fn key(context: &JobContext, job: u64) -> JobKey {
        JobKey {
            run: RunId(context.run_id),
            attempt: context.run_attempt,
            job: JobId(job),
        }
    }
    fn bound(context: &JobContext) -> JobPolicy {
        JobPolicy::Bound(RunBinding {
            run: RunId(context.run_id),
            attempt: context.run_attempt,
            sha: context.sha.clone(),
        })
    }

    /// GitHub for the fixture: B's KVM job runs on this clone's runner.
    struct FakeGithub {
        vet: RefCell<Option<Result<JobPolicy, ScalerError>>>,
    }
    impl FakeGithub {
        fn vetting(result: Result<JobPolicy, ScalerError>) -> Self {
            Self {
                vet: RefCell::new(Some(result)),
            }
        }
    }
    impl AssignmentApi for FakeGithub {
        fn run_jobs(&self, run: RunId, attempt: u32) -> Result<Vec<Value>, ScalerError> {
            assert_eq!(
                (run, attempt),
                (RunId(20), 1),
                "jobs of the actual run only"
            );
            Ok(vec![
                json!({"id":21,"runner_id":RUNNER.0,"labels":LABELS}),
                json!({"id":22,"runner_id":701,"labels":LABELS}),
            ])
        }
        fn revet(&self, key: JobKey) -> Result<JobPolicy, ScalerError> {
            assert_eq!(key, key_b(), "the actual assignment is re-vetted, not A");
            self.vet
                .borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("re-vetted twice"))
        }
    }
    fn key_b() -> JobKey {
        key(&run_b(), 21)
    }

    /// The clone's rendezvous: the hook asked for `request`.
    struct FakeGuest {
        request: Option<AssignmentRequest>,
        approved: Vec<JobPolicy>,
    }
    impl AssignmentExchange for FakeGuest {
        fn read(&mut self) -> Result<Option<AssignmentRequest>, ScalerError> {
            Ok(self.request.clone())
        }
        fn approve(&mut self, policy: &JobPolicy) -> Result<(), ScalerError> {
            self.approved.push(policy.clone());
            Ok(())
        }
    }
    fn guest_asking(context: JobContext) -> FakeGuest {
        FakeGuest {
            request: Some(AssignmentRequest {
                context,
                approved: false,
                finished: false,
            }),
            approved: Vec::new(),
        }
    }

    /// The standing ledger with one clone reserved for A's KVM job.
    fn minted_for_a(dir: &Path) -> (Ledger, Record, PathBuf) {
        let path = dir.join("ledger.json");
        let mut ledger = Ledger::default();
        let mut row = ledger
            .reserve(key(&run_a(), 11), &[], 100, Concurrency::ONE)
            .unwrap();
        row.state = State::Running;
        row.runner = Some(RUNNER);
        ledger.rows[0] = row.clone();
        ledger.save(&path).unwrap();
        (ledger, row, path)
    }
    fn serve(
        gh: &FakeGithub,
        guest: &mut FakeGuest,
        ledger: &mut Ledger,
        row: &mut Record,
        path: &Path,
    ) -> Result<Revetted, ScalerError> {
        serve_assignment(
            gh,
            guest,
            &LABELS,
            row.runner,
            ledger,
            path,
            |ledger, key| {
                row.assigned = Some(key.job);
                row.assigned_key = Some(key);
                ledger.rows[0] = row.clone();
                ledger.save(path)
            },
        )
    }

    #[derive(Clone)]
    struct CountedName {
        name: String,
        comparisons: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl PartialEq for CountedName {
        fn eq(&self, other: &Self) -> bool {
            self.cmp(other).is_eq()
        }
    }
    impl Eq for CountedName {}
    impl PartialOrd for CountedName {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for CountedName {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.comparisons.set(self.comparisons.get() + 1);
            self.name.cmp(&other.name)
        }
    }

    #[test]
    fn ci_scaler_assignment_publication_work_scales_with_ledger_population() {
        for population in [64_usize, 512, 4096] {
            let comparisons = std::rc::Rc::new(std::cell::Cell::new(0));
            // Mixed widths and a large population expose repeated name scans.
            let mut source: Vec<_> = (0..population)
                .map(|n| (format!("{}-{n}", "x".repeat((n % 3) * 127)), Some(n)))
                .collect();
            let mut target: Vec<_> = source
                .iter()
                .map(|(name, _)| (name.clone(), None))
                .collect();
            // Duplicate source identities preserve the first observation;
            // unmatched target rows preserve their own assignment.
            source.push((source[0].0.clone(), Some(population + 1)));
            target.push(("unmatched".into(), Some(population + 2)));
            merge_records(
                &mut target,
                &source,
                |row| CountedName {
                    name: row.0.clone(),
                    comparisons: comparisons.clone(),
                },
                |target, source| target.1 = source.1,
            );
            for (n, (_, assigned)) in target[..population].iter().enumerate() {
                assert_eq!(*assigned, Some(n));
            }
            assert_eq!(target[population].1, Some(population + 2));
            // B-tree insert + lookup do O((source + target) log(source))
            // name comparisons, including mixed-width keys and duplicate rows.
            let budget = 16 * (source.len() + target.len()) * (source.len().ilog2() as usize + 1);
            assert!(comparisons.get() > 0);
            assert!(
                comparisons.get() <= budget,
                "ledger population {population}: {} name comparisons exceed budget {budget}",
                comparisons.get()
            );
        }
    }

    #[test]
    fn ci_scaler_refusal_history_is_bounded_and_newest_decision_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = Ledger {
            refused: (1..=4096)
                .map(|n| JobKey {
                    run: RunId(n),
                    attempt: 1,
                    job: JobId(n),
                })
                .collect(),
            ..Ledger::default()
        };
        let newest = JobKey {
            run: RunId(5000),
            attempt: 1,
            job: JobId(5000),
        };
        refuse(
            &mut ledger,
            newest,
            &ScalerError::Guard("fixture refusal"),
            &path,
        )
        .unwrap();
        let restored = Ledger::load(&path).unwrap();
        assert_eq!(restored.refused.len(), 4096);
        assert!(restored.refused.contains(&newest));
        assert!(!restored.refused.contains(&JobKey {
            run: RunId(1),
            attempt: 1,
            job: JobId(1)
        }));
    }

    #[test]
    fn ci_scaler_diverted_assignment_is_approved_during_provision_and_backoff() {
        // The lifecycle controller deliberately makes no progress until the
        // worker has approved B; neither a provision nor a backoff may own
        // the rendezvous scheduler or the ledger publication lock.
        for blocked_phase in ["provision", "backoff"] {
            let dir = tempfile::tempdir().unwrap();
            let (mut lifecycle, row, path) = minted_for_a(dir.path());
            let publication = Publication::new(lifecycle.clone());
            lifecycle.publication = Some(publication.clone());
            let worker_publication = publication.worker();
            let worker_path = path.clone();
            let (approved, approval) = std::sync::mpsc::channel();
            let (first_pass, first_pass_complete) = std::sync::mpsc::channel();
            let requested = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_requested = requested.clone();
            let mut first_pass = Some(first_pass);
            let mut served = false;
            let service = AssignmentService::start(move || {
                if served {
                    return;
                }
                let mut ledger = worker_publication.snapshot().unwrap();
                ledger.publication = Some(worker_publication.clone());
                let mut row = row.clone();
                let api = FakeGithub::vetting(Ok(bound(&run_b())));
                let mut guest = guest_asking(run_b());
                if !worker_requested.load(std::sync::atomic::Ordering::Acquire) {
                    guest.request = None;
                    assert_eq!(
                        serve(&api, &mut guest, &mut ledger, &mut row, &worker_path).unwrap(),
                        Revetted::Idle
                    );
                    if let Some(first_pass) = first_pass.take() {
                        first_pass.send(()).unwrap();
                    }
                    return;
                }
                let outcome = serve(&api, &mut guest, &mut ledger, &mut row, &worker_path).unwrap();
                assert_eq!(outcome, Revetted::Approved(key_b(), bound(&run_b())));
                assert_eq!(
                    Ledger::load(&worker_path).unwrap().rows[0].assigned_key,
                    Some(key_b())
                );
                approved.send(()).unwrap();
                served = true;
            });
            first_pass_complete
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            // The hook asks only AFTER the controller's original assignment
            // pass, exactly when it has entered provision/backoff.
            requested.store(true, std::sync::atomic::Ordering::Release);
            approval
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("assignment stalled during {blocked_phase}"));
            // A lifecycle write made from the pre-approval snapshot must not
            // erase the durable assignment; a worker write cannot roll back
            // a lifecycle transition either.
            lifecycle.rows[0].state = State::Destroyed;
            lifecycle.save(&path).unwrap();
            lifecycle.refresh().unwrap();
            assert_eq!(lifecycle.rows[0].assigned_key, Some(key_b()));
            let worker = worker_publication_for_test(&publication);
            worker.save(&path).unwrap();
            assert_eq!(Ledger::load(&path).unwrap().rows[0].state, State::Destroyed);
            drop(service);
        }
    }

    fn worker_publication_for_test(publication: &Publication<Ledger>) -> Ledger {
        let mut ledger = publication.snapshot().unwrap();
        ledger.publication = Some(publication.worker());
        ledger.rows[0].state = State::Running;
        ledger
    }

    #[test]
    fn ci_scaler_standing_clone_for_run_a_admits_admissible_run_b_with_its_own_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, path) = minted_for_a(dir.path());
        // The reservation's bound policy refuses B: the #333 failure.
        let reservation = bound(&run_a());
        assert!(reservation.authorize(&run_b()).is_err());
        let gh = FakeGithub::vetting(Ok(bound(&run_b())));
        let mut guest = guest_asking(run_b());
        let outcome = serve(&gh, &mut guest, &mut ledger, &mut row, &path).unwrap();
        assert_eq!(outcome, Revetted::Approved(key_b(), bound(&run_b())));
        // B is admitted with its own policy, which still refuses A.
        assert_eq!(guest.approved, vec![bound(&run_b())]);
        assert!(guest.approved[0].authorize(&run_b()).is_ok());
        assert!(guest.approved[0].authorize(&run_a()).is_err());
        // B is durable before steps; A is still demand for another clone.
        let ledger = Ledger::load(&path).unwrap();
        assert_eq!(ledger.rows[0].assigned_key, Some(key_b()));
        assert!(ledger.served(key_b()));
        assert!(!ledger.served(key(&run_a(), 11)));
    }

    #[test]
    fn ci_scaler_standing_refuses_inadmissible_run_b_and_re_serves_run_a() {
        for refusal in [
            ScalerError::Guard("run event is not admitted"),
            ScalerError::Guard("run is from another repository"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (mut ledger, mut row, path) = minted_for_a(dir.path());
            let gh = FakeGithub::vetting(Err(refusal));
            let mut guest = guest_asking(run_b());
            let outcome = serve(&gh, &mut guest, &mut ledger, &mut row, &path).unwrap();
            assert_eq!(outcome, Revetted::Refused(key_b()));
            // No approval: the hook's deadline kills B before any step.
            assert!(guest.approved.is_empty());
            // A restart re-reads the request but never re-vets or approves B.
            let mut ledger = Ledger::load(&path).unwrap();
            assert_eq!(
                serve(&gh, &mut guest, &mut ledger, &mut row, &path).unwrap(),
                Revetted::Refused(key_b())
            );
            assert!(guest.approved.is_empty());
            assert!(ledger.served(key_b()), "refused B is never served");
            // A is re-served: with the clone still up (if budget allows) ...
            let a = key(&run_a(), 11);
            assert!(!ledger.served(a));
            // ... and once the refused clone is gone, within budget one.
            ledger.rows[0].state = State::Destroyed;
            let again = ledger.reserve(a, &[], 200, Concurrency::ONE).unwrap();
            assert_eq!(again.key, a);
        }
    }

    #[test]
    fn ci_scaler_assignment_api_failure_fails_the_step_without_refusing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, path) = minted_for_a(dir.path());
        let gh = FakeGithub::vetting(Err(ScalerError::External("GitHub unavailable")));
        let mut guest = guest_asking(run_b());
        assert!(serve(&gh, &mut guest, &mut ledger, &mut row, &path).is_err());
        assert!(guest.approved.is_empty());
        assert!(ledger.refused.is_empty(), "a transient failure is retried");
    }

    #[test]
    fn ci_scaler_assignment_is_authenticated_by_runner_and_never_widens_admission() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, path) = minted_for_a(dir.path());
        let gh = FakeGithub::vetting(Ok(bound(&run_b())));
        // Untrusted events and other repositories never reach GitHub.
        for (field, value) in [("event", "pull_request"), ("repository", "fork/carrick")] {
            let mut untrusted = run_b();
            match field {
                "event" => untrusted.event = value.into(),
                _ => untrusted.repository = value.into(),
            }
            let mut guest = guest_asking(untrusted);
            assert!(serve(&gh, &mut guest, &mut ledger, &mut row, &path).is_err());
            assert!(guest.approved.is_empty());
        }
        // A job of B on another runner is not this clone's assignment.
        row.runner = Some(RunnerId(999));
        let mut guest = guest_asking(run_b());
        assert!(serve(&gh, &mut guest, &mut ledger, &mut row, &path).is_err());
        assert!(guest.approved.is_empty());
        assert_eq!(row.assigned, None);
        // A vetted policy for another SHA than the hook reported is refused.
        row.runner = Some(RUNNER);
        let mut moved = run_b();
        moved.sha = "c".repeat(40);
        let mut guest = guest_asking(moved);
        assert_eq!(
            serve(&gh, &mut guest, &mut ledger, &mut row, &path).unwrap(),
            Revetted::Refused(key_b())
        );
        assert!(guest.approved.is_empty());
    }

    #[test]
    fn ci_scaler_recorded_or_finished_request_is_not_re_approved() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, path) = minted_for_a(dir.path());
        let gh = FakeGithub {
            vet: RefCell::new(None),
        };
        for (approved, finished) in [(true, false), (false, true)] {
            let mut guest = guest_asking(run_b());
            if let Some(request) = guest.request.as_mut() {
                request.approved = approved;
                request.finished = finished;
            }
            assert_eq!(
                serve(&gh, &mut guest, &mut ledger, &mut row, &path).unwrap(),
                Revetted::Recorded(key_b())
            );
            assert!(guest.approved.is_empty());
        }
        let mut idle = FakeGuest {
            request: None,
            approved: Vec::new(),
        };
        assert_eq!(
            serve(&gh, &mut idle, &mut ledger, &mut row, &path).unwrap(),
            Revetted::Idle
        );
    }

    #[test]
    fn ci_scaler_request_parsing_is_bounded_and_standing_only() {
        assert_eq!(parse_request(b"").unwrap().map(|c| c.run_id), None);
        let request = serde_json::to_vec(&run_b()).unwrap();
        assert_eq!(parse_request(&request).unwrap().unwrap().run_id, 20);
        assert!(parse_request(&vec![b' '; REQUEST_LIMIT + 1]).is_err());
        let mut untrusted = run_b();
        untrusted.event = "pull_request".into();
        assert!(parse_request(&serde_json::to_vec(&untrusted).unwrap()).is_err());
        assert!(parse_request(b"{").is_err());
    }
    fn push_demand(context: &JobContext, job: u64) -> super::super::github::QueuedJob {
        super::super::github::QueuedJob {
            key: key(context, job),
            event: "push".into(),
            sha: context.sha.clone(),
        }
    }
    #[test]
    fn ci_scaler_supersession_refuses_only_its_attempt_in_both_ledgers() {
        let dir = tempfile::tempdir().unwrap();
        let older = context(10, "push", "refs/heads/main", &"a".repeat(40));
        let newer = context(30, "push", "refs/heads/main", &"c".repeat(40));
        let demand = vec![push_demand(&older, 11), push_demand(&newer, 31)];
        let mut kvm = Ledger::default();
        let path = dir.path().join("kvm.json");
        coalesce_demand(&mut kvm, demand.clone(), &path, |_| {
            Ok(CancellationOutcome::Cancelled)
        })
        .unwrap();
        assert!(
            Ledger::load(&path)
                .unwrap()
                .reserve(key(&older, 11), &[], 100, Concurrency::ONE)
                .is_err()
        );
        assert!(
            Ledger::load(&path)
                .unwrap()
                .reserve(
                    JobKey {
                        attempt: 2,
                        ..key(&older, 11)
                    },
                    &[],
                    100,
                    Concurrency::ONE
                )
                .is_ok()
        );
        let mut mac = super::super::mac::MacLedger::default();
        let path = dir.path().join("mac.json");
        coalesce_demand(&mut mac, demand, &path, |_| {
            // Observing started work prevents API cancellation, but does not
            // reopen local admission for the already superseded run.
            Ok(CancellationOutcome::NotCancelled)
        })
        .unwrap();
        assert!(
            super::super::mac::MacLedger::load(&path)
                .unwrap()
                .reserve(key(&older, 11), 100)
                .is_err()
        );
        assert!(
            super::super::mac::MacLedger::load(&path)
                .unwrap()
                .reserve(
                    JobKey {
                        attempt: 2,
                        job: JobId(12),
                        ..key(&older, 11)
                    },
                    100
                )
                .is_ok()
        );
    }

    #[test]
    fn ci_scaler_superseded_assignment_is_refused_even_from_a_stale_worker_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (mut lifecycle, mut row, path) = minted_for_a(dir.path());
        let publication = Publication::new(lifecycle.clone());
        lifecycle.publication = Some(publication.clone());
        let mut worker = publication.snapshot().unwrap();
        worker.publication = Some(publication.worker());
        let b = context(20, "push", "refs/heads/main", &"b".repeat(40));
        let newer = context(30, "push", "refs/heads/main", &"c".repeat(40));
        let admission = publication.admission_lock();
        coalesce_demand(
            &mut lifecycle,
            vec![push_demand(&b, 21), push_demand(&newer, 31)],
            &path,
            |_| {
                assert!(
                    admission.try_lock().is_ok(),
                    "network cleanup must not hold admission"
                );
                Ok(CancellationOutcome::Cancelled)
            },
        )
        .unwrap();
        let gh = FakeGithub {
            vet: RefCell::new(None),
        };
        let mut guest = guest_asking(b);
        assert_eq!(
            serve(&gh, &mut guest, &mut worker, &mut row, &path).unwrap(),
            Revetted::Refused(key_b())
        );
        assert!(guest.approved.is_empty());
        assert!(Ledger::load(&path).unwrap().served(key_b()));
    }
    #[test]
    fn ci_scaler_approval_is_durable_and_excludes_a_run_from_later_supersession() {
        let dir = tempfile::tempdir().unwrap();
        let (mut worker, mut row, path) = minted_for_a(dir.path());
        let publication = Publication::new(worker.clone());
        worker.publication = Some(publication.worker());
        let mut stale = publication.snapshot().unwrap();
        stale.publication = Some(publication.clone());
        let b = context(20, "push", "refs/heads/main", &"b".repeat(40));
        struct LockedGuest {
            inner: FakeGuest,
            admission: std::sync::Arc<std::sync::Mutex<()>>,
            path: PathBuf,
        }
        impl AssignmentExchange for LockedGuest {
            fn read(&mut self) -> Result<Option<AssignmentRequest>, ScalerError> {
                self.inner.read()
            }
            fn approve(&mut self, policy: &JobPolicy) -> Result<(), ScalerError> {
                assert!(
                    self.admission.try_lock().is_err(),
                    "approval must hold the supersession admission lock"
                );
                assert!(
                    Ledger::load(&self.path).unwrap().rows[0].approved,
                    "approval must already be durable before hook release"
                );
                self.inner.approve(policy)
            }
        }
        let mut guest = LockedGuest {
            inner: guest_asking(b.clone()),
            admission: publication.admission_lock(),
            path: path.clone(),
        };
        let gh = FakeGithub::vetting(Ok(bound(&b)));
        serve_assignment(
            &gh,
            &mut guest,
            &LABELS,
            row.runner,
            &mut worker,
            &path,
            |ledger, key| {
                row.assigned = Some(key.job);
                row.assigned_key = Some(key);
                ledger.rows[0] = row.clone();
                ledger.save(&path)
            },
        )
        .unwrap();
        let newer = context(30, "push", "refs/heads/main", &"c".repeat(40));
        coalesce_demand(
            &mut stale,
            vec![push_demand(&b, 21), push_demand(&newer, 31)],
            &path,
            |_| panic!("an already approved run is never cancelled by this controller"),
        )
        .unwrap();
        assert!(Ledger::load(&path).unwrap().superseded.is_empty());
        assert_eq!(guest.inner.approved.len(), 1);
    }
    #[test]
    fn ci_scaler_owner_rerun_of_superseded_attempt_can_receive_hook_approval() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, mut row, path) = minted_for_a(dir.path());
        let old = context(20, "push", "refs/heads/main", &"b".repeat(40));
        let newer = context(30, "push", "refs/heads/main", &"c".repeat(40));
        coalesce_demand(
            &mut ledger,
            vec![push_demand(&old, 21), push_demand(&newer, 31)],
            &path,
            |_| Ok(CancellationOutcome::Deferred),
        )
        .unwrap();
        let mut rerun = old;
        rerun.run_attempt = 2;
        struct RerunApi(JobContext);
        impl AssignmentApi for RerunApi {
            fn run_jobs(&self, run: RunId, attempt: u32) -> Result<Vec<Value>, ScalerError> {
                assert_eq!((run, attempt), (RunId(20), 2));
                Ok(vec![json!({"id":25,"runner_id":RUNNER.0,"labels":LABELS})])
            }
            fn revet(&self, actual: JobKey) -> Result<JobPolicy, ScalerError> {
                assert_eq!(
                    actual,
                    JobKey {
                        run: RunId(20),
                        attempt: 2,
                        job: JobId(25)
                    }
                );
                Ok(bound(&self.0))
            }
        }
        let mut guest = guest_asking(rerun.clone());
        let result = serve_assignment(
            &RerunApi(rerun),
            &mut guest,
            &LABELS,
            row.runner,
            &mut ledger,
            &path,
            |ledger, key| {
                row.assigned = Some(key.job);
                row.assigned_key = Some(key);
                ledger.rows[0] = row.clone();
                ledger.save(&path)
            },
        )
        .unwrap();
        assert!(
            matches!(result, Revetted::Approved(JobKey { attempt: 2, .. }, _)),
            "{result:?}"
        );
        assert_eq!(guest.approved.len(), 1);
    }
    fn superseded_at(run: u64, created: u64, outcome: &str) -> SupersededPush {
        serde_json::from_value(json!({"key":{"run":run,"attempt":1,"job":run},
            "sha":format!("{run:040x}"),"reason":"superseded by newer main push",
            "outcome":outcome,"created":created}))
        .unwrap()
    }
    #[test]
    fn ci_scaler_prunes_only_gone_or_expired_supersessions_in_both_ledgers() {
        fn verify(mut ledger: impl Refusals, path: &Path) {
            let time = now().unwrap();
            ledger.superseded_mut().extend([
                superseded_at(1, 1, "Deferred"),
                superseded_at(2, time, "Gone"),
                superseded_at(3, time, "Deferred"),
            ]);
            let mut checked = Vec::new();
            coalesce_demand(&mut ledger, vec![], path, |entry| {
                checked.push(entry.key.run.0);
                Ok(CancellationOutcome::Deferred)
            })
            .unwrap();
            assert_eq!(
                checked,
                vec![3],
                "retired entries must not trigger network cleanup"
            );
            assert_eq!(
                ledger
                    .superseded()
                    .iter()
                    .map(|e| e.key.run.0)
                    .collect::<Vec<_>>(),
                vec![3]
            );
        }
        let dir = tempfile::tempdir().unwrap();
        verify(Ledger::default(), &dir.path().join("kvm"));
        verify(
            super::super::mac::MacLedger::default(),
            &dir.path().join("mac"),
        );
    }
    #[test]
    fn ci_scaler_live_supersession_overflow_blocks_admission_without_eviction() {
        fn verify(ledger: &mut impl Refusals, path: &Path) {
            let time = now().unwrap();
            ledger
                .superseded_mut()
                .extend((1..=4097).map(|n| superseded_at(n, time, "Cancelled")));
            let error =
                coalesce_demand(ledger, vec![], path, |_| Ok(CancellationOutcome::Cancelled))
                    .unwrap_err();
            assert!(error.to_string().contains("capacity"), "{error}");
            assert_eq!(ledger.superseded().len(), 4097);
            let disk: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(disk["superseded"].as_array().unwrap().len(), 4097);
            assert!(
                disk["supersession_error"]
                    .as_str()
                    .is_some_and(|s| s.contains("4097"))
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let fresh = JobKey {
            run: RunId(5000),
            attempt: 1,
            job: JobId(5000),
        };
        let mut kvm = Ledger::default();
        let path = dir.path().join("kvm");
        verify(&mut kvm, &path);
        assert!(kvm.reserve(fresh, &[], 100, Concurrency::ONE).is_err());
        coalesce_demand(&mut kvm, vec![], &path, |entry| {
            Ok(if entry.key.run.0 == 1 {
                CancellationOutcome::Gone
            } else {
                CancellationOutcome::Cancelled
            })
        })
        .unwrap();
        assert_eq!(kvm.superseded.len(), 4096);
        assert!(kvm.reserve(fresh, &[], 100, Concurrency::ONE).is_ok());
        let mut mac = super::super::mac::MacLedger::default();
        let path = dir.path().join("mac");
        verify(&mut mac, &path);
        assert!(mac.reserve(fresh, 100).is_err());
    }
    #[test]
    fn ci_scaler_assignment_publication_cannot_resurrect_pruned_supersessions() {
        let dir = tempfile::tempdir().unwrap();
        macro_rules! verify {
            ($ledger:expr,$name:literal) => {{
                let path = dir.path().join($name);
                let mut lifecycle = $ledger;
                lifecycle
                    .superseded
                    .push(superseded_at(1, now().unwrap(), "Deferred"));
                let publication = Publication::new(lifecycle.clone());
                lifecycle.publication = Some(publication.clone());
                let mut stale = publication.snapshot().unwrap();
                stale.publication = Some(publication.worker());
                coalesce_demand(&mut lifecycle, vec![], &path, |_| {
                    Ok(CancellationOutcome::Gone)
                })
                .unwrap();
                assert!(lifecycle.superseded.is_empty());
                stale.persist(&path).unwrap();
                let disk: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert!(disk["superseded"].as_array().unwrap().is_empty());
            }};
        }
        verify!(Ledger::default(), "kvm");
    }
}
