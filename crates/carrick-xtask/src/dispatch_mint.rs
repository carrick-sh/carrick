//! The dispatch tool server's half of on-demand App tokens (#1012).
//!
//! Before a publication or board write, the runner-uid tool server writes a
//! `publish` or `board` request into the runner state directory and waits,
//! bounded, for the standing controller's answer (see
//! `ci_scaler::mint`). It erases the answer as soon as it has read it and
//! keeps the token only in memory, for at most [`FRESH`]. A refusal, a
//! timeout or a missing channel is returned as a [`MintFailure`]; callers
//! record it and fall back to the job token (publication) or report the board
//! unavailable. Bootstrap (#1034) has no fallback: it fails the step.
use crate::ci_scaler::mint::{
    AppToken, MintNonce, MintRefusal, MintRequest, MintResponse, MintScope, REQUEST_FILE,
    RESPONSE_FILE, RESPONSE_LIMIT,
};
use crate::ci_scaler::{JobPolicy, ScalerError};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long one request waits for the controller's answer.
const WAIT: Duration = Duration::from_secs(60);
/// A minted token lives an hour; reuse it for at most 45 minutes.
const FRESH: Duration = Duration::from_secs(45 * 60);
/// A timeout or failed mint is asked again only after this long, so a down
/// controller costs one bounded wait per interval, not one per board read.
const RETRY: Duration = Duration::from_secs(5 * 60);

/// Why no answer arrived. Fixed markers, safe for artifacts and comments.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MintUnavailable {
    /// This runner has no request/response files (not a ctb agent clone, or
    /// a controller that predates #1012).
    NoChannel,
    /// No root-owned `agent` approved policy names this job.
    NoAssignment,
    /// The controller did not answer within the bounded wait.
    Timeout,
    /// The answer was unreadable.
    Malformed,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MintFailure {
    Refused(MintRefusal),
    Unavailable(MintUnavailable),
}
impl MintFailure {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Refused(reason) => reason.describe(),
            Self::Unavailable(MintUnavailable::NoChannel) => "no controller mint channel",
            Self::Unavailable(MintUnavailable::NoAssignment) => "no approved dispatch assignment",
            Self::Unavailable(MintUnavailable::Timeout) => "controller did not answer in time",
            Self::Unavailable(MintUnavailable::Malformed) => "controller answer was unreadable",
        }
    }
}

struct Cached {
    scope: MintScope,
    at: Instant,
    result: Result<AppToken, MintFailure>,
}
/// The process-wide token cache. `entries` is what redaction reads and is
/// never held across a wait; `requests` serializes exchanges, because two
/// concurrent requests through the one request/response file pair would
/// overwrite and erase each other's answers.
struct TokenCache {
    entries: std::sync::Mutex<Vec<Cached>>,
    requests: std::sync::Mutex<()>,
}
impl TokenCache {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
            requests: std::sync::Mutex::new(()),
        }
    }
    fn cached(
        &self,
        scope: MintScope,
    ) -> Result<Option<Result<AppToken, MintFailure>>, MintFailure> {
        let mut entries = self.entries.lock().map_err(|_| POISONED)?;
        entries.retain(|c| c.at.elapsed() < if transient(&c.result) { RETRY } else { FRESH });
        Ok(entries
            .iter()
            .find(|c| c.scope == scope)
            .map(|c| c.result.clone()))
    }
    fn get(
        &self,
        scope: MintScope,
        fetch: impl FnOnce() -> Result<AppToken, MintFailure>,
    ) -> Result<AppToken, MintFailure> {
        if let Some(result) = self.cached(scope)? {
            return result;
        }
        let _request = self.requests.lock().map_err(|_| POISONED)?;
        // Another caller may have fetched this scope while we waited.
        if let Some(result) = self.cached(scope)? {
            return result;
        }
        let result = fetch();
        self.entries.lock().map_err(|_| POISONED)?.push(Cached {
            scope,
            at: Instant::now(),
            result: result.clone(),
        });
        result
    }
    fn secrets(&self) -> Vec<String> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|c| c.result.as_ref().ok().map(|t| t.secret().to_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }
}
const POISONED: MintFailure = MintFailure::Unavailable(MintUnavailable::Malformed);
static CACHE: TokenCache = TokenCache::new();

/// Every token this process minted, for diagnostic redaction and the
/// artifact scan. Real installation tokens are also caught by their `ghs_`
/// shape in later processes.
pub(crate) fn minted_secrets() -> Vec<String> {
    CACHE.secrets()
}

/// A token for `scope`, minted on demand. A refusal that cannot change during
/// the job is remembered for [`FRESH`]; an unavailable channel, a failed mint
/// or an unconfigured controller is asked again after [`RETRY`].
pub(crate) fn app_token(scope: MintScope) -> Result<AppToken, MintFailure> {
    CACHE.get(scope, || request_token(scope))
}
fn transient(result: &Result<AppToken, MintFailure>) -> bool {
    matches!(
        result,
        Err(MintFailure::Unavailable(_)
            | MintFailure::Refused(MintRefusal::MintFailed | MintRefusal::Unconfigured))
    )
}

#[cfg(not(test))]
fn request_token(scope: MintScope) -> Result<AppToken, MintFailure> {
    // The controller writes root-owned approval; the policy must be root's.
    request(
        Path::new(crate::ci_scaler::GUEST_STATE),
        scope,
        WAIT,
        Some(0),
    )
}
/// Test double: `CARRICK_TEST_MINT_<SCOPE>` is `refused:<reason>` or token
/// bytes; unset or empty uses the real channel in `CARRICK_TEST_MINT_STATE`.
#[cfg(test)]
fn request_token(scope: MintScope) -> Result<AppToken, MintFailure> {
    let name = format!("CARRICK_TEST_MINT_{}", scope.label().to_ascii_uppercase());
    match std::env::var(name).unwrap_or_default().as_str() {
        "" => {
            let state = std::env::var_os("CARRICK_TEST_MINT_STATE")
                .map_or_else(|| PathBuf::from("/nonexistent/carrick-ci"), PathBuf::from);
            request(&state, scope, Duration::from_secs(2), None)
        }
        value => match value.strip_prefix("refused:") {
            Some(reason) => Err(MintFailure::Refused(
                serde_json::from_value(reason.into()).unwrap_or(MintRefusal::MintFailed),
            )),
            None => Ok(AppToken::for_test(value)),
        },
    }
}

fn lock(file: &File) -> Result<(), MintFailure> {
    // SAFETY: flock on a descriptor this function's caller owns for the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(MintFailure::Unavailable(MintUnavailable::NoChannel));
    }
    Ok(())
}
fn open(path: PathBuf) -> Result<File, MintFailure> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| MintFailure::Unavailable(MintUnavailable::NoChannel))
}
fn erase(file: &mut File) -> Result<(), MintFailure> {
    let io = |_| MintFailure::Unavailable(MintUnavailable::NoChannel);
    file.set_len(0).map_err(io)?;
    file.rewind().map_err(io)?;
    file.sync_all().map_err(io)
}

/// One request/answer exchange through `state`. `owner` is the uid the
/// approved policy must belong to (root in production).
pub(crate) fn request(
    state: &Path,
    scope: MintScope,
    wait: Duration,
    owner: Option<u32>,
) -> Result<AppToken, MintFailure> {
    let unavailable = MintFailure::Unavailable;
    // Fail fast without a channel; each poll reopens the answer so its lock
    // is released (on close) between polls and the controller can write.
    drop(open(state.join(RESPONSE_FILE))?);
    let binding = match crate::ci_scaler::read_policy(&state.join("approved-policy"), owner) {
        Ok(JobPolicy::Agent(binding)) => binding,
        _ => return Err(unavailable(MintUnavailable::NoAssignment)),
    };
    let nonce = MintNonce::random().map_err(|_| unavailable(MintUnavailable::NoChannel))?;
    let body = serde_json::to_vec(&MintRequest {
        nonce: nonce.clone(),
        scope: scope.label().into(),
        run_id: binding.run.0,
        run_attempt: binding.attempt,
        sha: binding.sha,
    })
    .map_err(|_| unavailable(MintUnavailable::Malformed))?;
    {
        let mut request = open(state.join(REQUEST_FILE))?;
        lock(&request)?;
        erase(&mut request)?;
        request
            .write_all(&body)
            .and_then(|()| request.sync_all())
            .map_err(|_| unavailable(MintUnavailable::NoChannel))?;
    }
    let deadline = Instant::now() + wait;
    loop {
        if let Some(answer) = take_answer(&state.join(RESPONSE_FILE), &nonce)? {
            return answer.into_result().map_err(MintFailure::Refused);
        }
        if Instant::now() >= deadline {
            // Withdraw the request; a late answer is erased as stale later.
            if let Ok(mut request) = open(state.join(REQUEST_FILE)) {
                let _ = lock(&request).and_then(|()| erase(&mut request));
            }
            return Err(unavailable(MintUnavailable::Timeout));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
/// Read and erase the answer under its lock; `None` until ours arrives.
fn take_answer(path: &Path, nonce: &MintNonce) -> Result<Option<MintResponse>, MintFailure> {
    let file = &mut open(path.to_owned())?;
    lock(file)?;
    let mut bytes = Vec::new();
    file.rewind()
        .and_then(|()| {
            Read::by_ref(file)
                .take(RESPONSE_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map(drop)
        })
        .map_err(|_| MintFailure::Unavailable(MintUnavailable::NoChannel))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let answer = serde_json::from_slice::<MintResponse>(&bytes);
    erase(file)?;
    drop(bytes);
    match answer {
        Ok(answer) if answer.nonce() == nonce => Ok(Some(answer)),
        Ok(_) => Ok(None),
        Err(_) => Err(MintFailure::Unavailable(MintUnavailable::Malformed)),
    }
}

impl From<MintFailure> for ScalerError {
    fn from(failure: MintFailure) -> Self {
        ScalerError::Guard(match failure {
            MintFailure::Refused(_) => "the controller refused the token request",
            MintFailure::Unavailable(_) => "the controller token channel is unavailable",
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn channel() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("approved-policy"),
            format!("agent run=41 attempt=2 sha={SHA}\n"),
        )
        .unwrap();
        std::fs::set_permissions(
            dir.path().join("approved-policy"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        for file in [REQUEST_FILE, RESPONSE_FILE] {
            std::fs::write(dir.path().join(file), "").unwrap();
        }
        dir
    }
    /// The controller's half, as the guest scripts perform it.
    fn answer(state: &Path, respond: impl FnOnce(MintNonce) -> MintResponse) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let request = loop {
            let bytes = std::fs::read(state.join(REQUEST_FILE)).unwrap();
            if let Ok(request) = serde_json::from_slice::<MintRequest>(&bytes) {
                break request;
            }
            assert!(Instant::now() < deadline, "no request written");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(request.run_id, 41);
        assert_eq!(request.run_attempt, 2);
        assert_eq!(request.sha, SHA);
        // Same order and locks as the guest scripts: clear, then answer.
        let mut file = open(state.join(REQUEST_FILE)).unwrap();
        lock(&file).unwrap();
        erase(&mut file).unwrap();
        drop(file);
        let mut file = open(state.join(RESPONSE_FILE)).unwrap();
        lock(&file).unwrap();
        erase(&mut file).unwrap();
        file.write_all(&serde_json::to_vec(&respond(request.nonce)).unwrap())
            .unwrap();
    }

    #[test]
    fn concurrent_callers_share_one_request_per_scope() {
        let cache = std::sync::Arc::new(TokenCache::new());
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let callers: Vec<_> = (0..4)
            .map(|_| {
                let (cache, fetches) = (cache.clone(), fetches.clone());
                std::thread::spawn(move || {
                    cache
                        .get(MintScope::Board, || {
                            fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(100));
                            Ok(AppToken::for_test("ghs_sharedFixture0123456789"))
                        })
                        .ok()
                        .map(|t| t.secret().to_owned())
                })
            })
            .collect();
        for caller in callers {
            assert_eq!(
                caller.join().unwrap().as_deref(),
                Some("ghs_sharedFixture0123456789")
            );
        }
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(cache.secrets(), vec!["ghs_sharedFixture0123456789"]);
    }

    #[test]
    fn concurrent_scopes_are_serialized_through_the_one_channel() {
        let dir = channel();
        let cache = std::sync::Arc::new(TokenCache::new());
        let state = dir.path().to_owned();
        let controller = std::thread::spawn(move || {
            for _ in 0..2 {
                answer(&state, |nonce| MintResponse::Minted {
                    token: format!("ghs_{}", nonce.as_str()),
                    nonce,
                });
            }
        });
        let callers: Vec<_> = [MintScope::Board, MintScope::Publish]
            .into_iter()
            .map(|scope| {
                let (cache, state) = (cache.clone(), dir.path().to_owned());
                std::thread::spawn(move || {
                    cache
                        .get(scope, || {
                            request(&state, scope, Duration::from_secs(5), None)
                        })
                        .err()
                })
            })
            .collect();
        for caller in callers {
            assert_eq!(
                caller.join().unwrap(),
                None,
                "a concurrent request was lost"
            );
        }
        controller.join().unwrap();
        assert_eq!(cache.secrets().len(), 2);
    }

    #[test]
    fn unavailable_and_failed_mints_retry_but_decided_refusals_stay() {
        for failure in [
            MintFailure::Unavailable(MintUnavailable::NoChannel),
            MintFailure::Unavailable(MintUnavailable::NoAssignment),
            MintFailure::Unavailable(MintUnavailable::Timeout),
            MintFailure::Refused(MintRefusal::MintFailed),
            MintFailure::Refused(MintRefusal::Unconfigured),
        ] {
            assert!(transient(&Err(failure)), "{failure:?}");
        }
        for reason in [
            MintRefusal::IdentityMismatch,
            MintRefusal::NotAssigned,
            MintRefusal::ScopeNotAllowed,
            MintRefusal::InvalidRequest,
            MintRefusal::JobNotInProgress,
            MintRefusal::BudgetExhausted,
        ] {
            assert!(!transient(&Err(MintFailure::Refused(reason))), "{reason:?}");
        }
    }

    #[test]
    fn minted_answer_is_used_once_and_erased() {
        let dir = channel();
        let state = dir.path().to_owned();
        let controller = std::thread::spawn(move || {
            answer(&state, |nonce| MintResponse::Minted {
                nonce,
                token: "ghs_onDemandFixture0123456789".into(),
            });
        });
        let token = request(dir.path(), MintScope::Publish, Duration::from_secs(5), None)
            .ok()
            .unwrap();
        controller.join().unwrap();
        assert_eq!(token.secret(), "ghs_onDemandFixture0123456789");
        assert!(
            std::fs::read(dir.path().join(RESPONSE_FILE))
                .unwrap()
                .is_empty(),
            "token bytes stayed on disk"
        );
    }

    #[test]
    fn refusal_and_stale_answers_are_reported_not_used() {
        let dir = channel();
        // A stale answer for another request is erased and ignored.
        std::fs::write(
            dir.path().join(RESPONSE_FILE),
            serde_json::to_vec(&MintResponse::Minted {
                nonce: MintNonce::try_from("f".repeat(32)).unwrap(),
                token: "ghs_staleFixture0123456789".into(),
            })
            .unwrap(),
        )
        .unwrap();
        let state = dir.path().to_owned();
        let controller = std::thread::spawn(move || {
            answer(&state, |nonce| MintResponse::Refused {
                nonce,
                reason: MintRefusal::JobNotInProgress,
            });
        });
        let failure = request(dir.path(), MintScope::Board, Duration::from_secs(5), None).err();
        controller.join().unwrap();
        assert_eq!(
            failure,
            Some(MintFailure::Refused(MintRefusal::JobNotInProgress))
        );
    }

    #[test]
    fn silent_controller_times_out_and_withdraws_the_request() {
        let dir = channel();
        let failure = request(
            dir.path(),
            MintScope::Publish,
            Duration::from_millis(300),
            None,
        )
        .err();
        assert_eq!(
            failure,
            Some(MintFailure::Unavailable(MintUnavailable::Timeout))
        );
        assert!(
            std::fs::read(dir.path().join(REQUEST_FILE))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn missing_channel_or_assignment_is_unavailable() {
        let dir = channel();
        std::fs::remove_file(dir.path().join(RESPONSE_FILE)).unwrap();
        assert_eq!(
            request(dir.path(), MintScope::Publish, WAIT, None).err(),
            Some(MintFailure::Unavailable(MintUnavailable::NoChannel))
        );
        let dir = channel();
        std::fs::write(
            dir.path().join("approved-policy"),
            format!("standing run=41 attempt=2 sha={SHA}\n"),
        )
        .unwrap();
        assert_eq!(
            request(dir.path(), MintScope::Publish, WAIT, None).err(),
            Some(MintFailure::Unavailable(MintUnavailable::NoAssignment))
        );
        // A planted symlink is never followed.
        let dir = channel();
        std::fs::remove_file(dir.path().join(REQUEST_FILE)).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("approved-policy"),
            dir.path().join(REQUEST_FILE),
        )
        .unwrap();
        assert_eq!(
            request(dir.path(), MintScope::Publish, WAIT, None).err(),
            Some(MintFailure::Unavailable(MintUnavailable::NoChannel))
        );
    }
}
