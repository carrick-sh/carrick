//! On-demand dispatch App tokens (#1012), minted by the standing controller.
//!
//! A dispatch tool server on an agent clone asks for a `publish` or `board`
//! token right before it writes. It writes a request into the runner state
//! directory beside the assignment rendezvous. The controller reads it through
//! the scoped PVE guest agent and checks it against the run it assigned that
//! runner, against GitHub's live job state and against a per-job mint budget.
//! Only then does it sign an App JWT and mint an installation token with the
//! fixed grant for that scope. The grant never comes from the request.
//!
//! The answer goes back through the same guest agent, as stdin of a root
//! shell, into a runner-owned 0600 file in the root-owned state directory.
//! Model accounts run as other uids, so only the tool server's uid can read
//! it. The tool server erases the file once it has read it.
use super::github::Github;
use super::*;
use base64::Engine as _;
use serde_json::{Value, json};

/// The `carrick-workers` App and its carrick-sh installation.
pub(super) const APP_ID: u64 = 5364291;
pub(super) const INSTALLATION: u64 = 172574456;
/// The systemd credential name of the App private key (PEM).
pub(super) const KEY_CREDENTIAL: &str = "dispatch-app-key";
/// The clone-written request and controller-written response, both runner
/// 0600 regular files the controller pre-creates in the root-owned state dir.
pub(crate) const REQUEST_FILE: &str = "token-request";
pub(crate) const RESPONSE_FILE: &str = "token-response";
pub(crate) const REQUEST_LIMIT: usize = 4096;
pub(crate) const RESPONSE_LIMIT: usize = 8192;
/// Successful mints per scope for one assigned job. A publication or board
/// operation reuses its token for up to 45 minutes, so a normal job mints at
/// most two or three of each.
pub(super) const MINTS_PER_SCOPE: usize = 6;
/// Answered requests (minted or refused) recorded per clone. A full log
/// refuses every later request, so the ledger row stays bounded.
pub(super) const LOG_LIMIT: usize = 32;

/// The only two grants the controller mints. Each maps to a fixed,
/// controller-owned permission body.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintScope {
    Publish,
    Board,
}
impl MintScope {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "publish" => Some(Self::Publish),
            "board" => Some(Self::Board),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Board => "board",
        }
    }
    /// Exactly what `agent-secrets.sh` mints today for the same secrets.
    pub(super) fn grant(self) -> Value {
        match self {
            Self::Publish => json!({"repositories":["carrick"],
                "permissions":{"contents":"write","pull_requests":"write"}}),
            Self::Board => json!({"permissions":{"organization_projects":"write"}}),
        }
    }
}

/// A request identity: 32 lowercase hex digits from the clone's urandom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MintNonce(String);
impl TryFrom<String> for MintNonce {
    type Error = ScalerError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err(ScalerError::Guard(
                "mint nonce must be 32 lowercase hex digits",
            ))
        }
    }
}
impl From<MintNonce> for String {
    fn from(nonce: MintNonce) -> Self {
        nonce.0
    }
}
impl MintNonce {
    pub fn random() -> Result<Self, ScalerError> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }
}

/// What the tool server writes. `scope` stays a string so an unknown scope is
/// refused with its own reason instead of failing the whole parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRequest {
    pub nonce: MintNonce,
    pub scope: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub sha: String,
}

/// Why the controller refused. Fixed markers, safe for artifacts and comments.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintRefusal {
    InvalidRequest,
    ScopeNotAllowed,
    /// The runner has no approved `dispatch-worker.yml` assignment.
    NotAssigned,
    /// Run, attempt, SHA, runner or job name differs from the assignment.
    IdentityMismatch,
    /// GitHub no longer reports the assigned job in progress.
    JobNotInProgress,
    BudgetExhausted,
    /// The controller has no App key credential.
    Unconfigured,
    MintFailed,
}
impl MintRefusal {
    pub fn describe(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid request",
            Self::ScopeNotAllowed => "scope not allowed",
            Self::NotAssigned => "runner has no approved dispatch assignment",
            Self::IdentityMismatch => "request does not match the assigned job",
            Self::JobNotInProgress => "assigned job is no longer in progress",
            Self::BudgetExhausted => "per-job mint budget exhausted",
            Self::Unconfigured => "controller has no App key",
            Self::MintFailed => "GitHub mint failed",
        }
    }
}

/// One-hour installation token bytes. No `Debug` or `Display`: it is only
/// ever handed to a subprocess environment or written to the response file.
#[derive(Clone)]
pub struct AppToken(String);
impl AppToken {
    pub fn secret(&self) -> &str {
        &self.0
    }
    #[cfg(test)]
    pub fn for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// The controller's answer, keyed by the request nonce.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MintResponse {
    Minted {
        nonce: MintNonce,
        token: String,
    },
    Refused {
        nonce: MintNonce,
        reason: MintRefusal,
    },
}
impl MintResponse {
    pub fn nonce(&self) -> &MintNonce {
        match self {
            Self::Minted { nonce, .. } | Self::Refused { nonce, .. } => nonce,
        }
    }
    pub fn into_result(self) -> Result<AppToken, MintRefusal> {
        match self {
            Self::Minted { token, .. } => Ok(AppToken(token)),
            Self::Refused { reason, .. } => Err(reason),
        }
    }
}

/// One answered request in the clone's ledger row. Durable before any mint,
/// so a controller restart cannot reset the budget or mint a nonce twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintEntry {
    pub nonce: MintNonce,
    pub scope: Option<MintScope>,
    pub job: Option<JobId>,
    pub refused: Option<MintRefusal>,
}

/// The GitHub side of a mint; [`AppMinter`] in production.
pub(super) trait MintApi {
    fn job(&self, job: JobId) -> Result<Value, ScalerError>;
    fn run(&self, run: RunId, attempt: u32) -> Result<Value, ScalerError>;
    fn configured(&self) -> bool;
    fn mint(&self, scope: MintScope) -> Result<AppToken, ScalerError>;
}

/// The per-clone transport: the PVE guest agent in production.
pub(super) trait MintExchange {
    /// The raw request, or `None` while the request file is empty.
    fn read(&mut self) -> Result<Option<Vec<u8>>, ScalerError>;
    fn respond(&mut self, response: &MintResponse) -> Result<(), ScalerError>;
    fn clear(&mut self) -> Result<(), ScalerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MintServed {
    Idle,
    /// Unparseable or already answered; cleared without a response.
    Ignored,
    Minted(MintScope),
    Refused(MintRefusal),
}

/// Serve one pending token request for ledger row `name`.
pub(super) fn serve_mint(
    api: &impl MintApi,
    exchange: &mut impl MintExchange,
    name: &str,
    ledger: &mut Ledger,
    path: &Path,
) -> Result<MintServed, ScalerError> {
    let admission = assignment::Refusals::admission_lock(ledger);
    let _guard = admission
        .as_ref()
        .map(|lock| {
            lock.lock()
                .map_err(|_| ScalerError::Guard("controller admission poisoned"))
        })
        .transpose()?;
    ledger.refresh()?;
    let Some(bytes) = exchange.read()? else {
        return Ok(MintServed::Idle);
    };
    let value: Option<Value> = (bytes.len() <= REQUEST_LIMIT)
        .then(|| serde_json::from_slice(&bytes).ok())
        .flatten();
    let nonce = value
        .as_ref()
        .and_then(|v| v["nonce"].as_str())
        .and_then(|n| MintNonce::try_from(n.to_owned()).ok());
    let index = ledger
        .rows
        .iter()
        .position(|r| r.name == name)
        .ok_or(ScalerError::Guard("mint request has no ledger row"))?;
    let (Some(value), Some(nonce)) = (value, nonce) else {
        exchange.clear()?;
        return Ok(MintServed::Ignored);
    };
    if ledger.rows[index].mints.iter().any(|m| m.nonce == nonce) {
        exchange.clear()?;
        return Ok(MintServed::Ignored);
    }
    let row = ledger.rows[index].clone();
    let decision = if row.mints.len() >= LOG_LIMIT {
        Err(MintRefusal::BudgetExhausted)
    } else {
        decide(api, &row, value)?
    };
    let refused = match decision {
        Err(reason) => Some(reason),
        Ok(_) if !api.configured() => Some(MintRefusal::Unconfigured),
        Ok(_) => None,
    };
    if row.mints.len() < LOG_LIMIT {
        ledger.rows[index].mints.push(MintEntry {
            nonce: nonce.clone(),
            scope: decision.ok().map(|(scope, _)| scope),
            job: decision.ok().map(|(_, job)| job),
            refused,
        });
        // Durable before the mint: a crash afterwards cannot reset the budget.
        ledger.save(path)?;
    }
    let outcome = match (decision, refused) {
        (Ok((scope, _)), None) => match api.mint(scope) {
            Ok(token) => Ok((scope, token)),
            Err(error) => {
                eprintln!("vm row={name} {} mint failed: {error}", scope.label());
                if let Some(entry) = ledger.rows[index].mints.last_mut() {
                    entry.refused = Some(MintRefusal::MintFailed);
                }
                ledger.save(path)?;
                Err(MintRefusal::MintFailed)
            }
        },
        (_, Some(reason)) | (Err(reason), None) => Err(reason),
    };
    let (response, served) = match outcome {
        Ok((scope, token)) => (
            MintResponse::Minted {
                nonce,
                token: token.0,
            },
            MintServed::Minted(scope),
        ),
        Err(reason) => (
            MintResponse::Refused { nonce, reason },
            MintServed::Refused(reason),
        ),
    };
    exchange.respond(&response)?;
    exchange.clear()?;
    Ok(served)
}

/// Every check except configuration. GitHub transport errors propagate (the
/// request stays pending and is retried); a decided refusal is returned.
fn decide(
    api: &impl MintApi,
    row: &Record,
    value: Value,
) -> Result<Result<(MintScope, JobId), MintRefusal>, ScalerError> {
    let Ok(request) = serde_json::from_value::<MintRequest>(value) else {
        return Ok(Err(MintRefusal::InvalidRequest));
    };
    let Some(scope) = MintScope::parse(&request.scope) else {
        return Ok(Err(MintRefusal::ScopeNotAllowed));
    };
    let (Some(key), Some(runner)) = (row.assigned_key, row.runner) else {
        return Ok(Err(MintRefusal::NotAssigned));
    };
    if row.lane != CloneLane::Agent || !row.approved || row.state != State::Running {
        return Ok(Err(MintRefusal::NotAssigned));
    }
    let sha = request.sha.to_ascii_lowercase();
    if key.run.0 != request.run_id || key.attempt != request.run_attempt || !full_sha(&sha) {
        return Ok(Err(MintRefusal::IdentityMismatch));
    }
    let minted = row
        .mints
        .iter()
        .filter(|m| m.refused.is_none() && m.scope == Some(scope) && m.job == Some(key.job))
        .count();
    if minted >= MINTS_PER_SCOPE {
        return Ok(Err(MintRefusal::BudgetExhausted));
    }
    let job = api.job(key.job)?;
    if job["id"].as_u64() != Some(key.job.0)
        || job["run_id"].as_u64() != Some(key.run.0)
        || job["run_attempt"].as_u64() != Some(u64::from(key.attempt))
        || job["runner_id"].as_u64() != Some(runner.0)
        || job["name"] != "worker"
        || job["head_sha"].as_str() != Some(sha.as_str())
    {
        return Ok(Err(MintRefusal::IdentityMismatch));
    }
    if job["status"] != "in_progress" {
        return Ok(Err(MintRefusal::JobNotInProgress));
    }
    let run = api.run(key.run, key.attempt)?;
    if run["id"].as_u64() != Some(key.run.0)
        || run["run_attempt"].as_u64() != Some(u64::from(key.attempt))
        || run["head_sha"].as_str() != Some(sha.as_str())
        || !Admission::Agent.identifies_run(&run)
    {
        return Ok(Err(MintRefusal::IdentityMismatch));
    }
    Ok(Ok((scope, key.job)))
}

/// The App private key, loaded once from the controller's systemd credential.
pub(super) struct AppKey(ring::rsa::KeyPair);
impl AppKey {
    pub(super) fn from_pem(pem: &str) -> Result<Self, ScalerError> {
        let invalid = || ScalerError::Guard("dispatch App key is not an RSA private key PEM");
        let pem = pem.trim();
        let (pkcs1, body) = if let Some(rest) = pem.strip_prefix("-----BEGIN RSA PRIVATE KEY-----")
        {
            (true, rest.strip_suffix("-----END RSA PRIVATE KEY-----"))
        } else if let Some(rest) = pem.strip_prefix("-----BEGIN PRIVATE KEY-----") {
            (false, rest.strip_suffix("-----END PRIVATE KEY-----"))
        } else {
            return Err(invalid());
        };
        let body: String = body.ok_or_else(invalid)?.split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| invalid())?;
        let pair = if pkcs1 {
            ring::rsa::KeyPair::from_der(&der)
        } else {
            ring::rsa::KeyPair::from_pkcs8(&der)
        };
        pair.map(Self).map_err(|_| invalid())
    }
    /// `$CREDENTIALS_DIRECTORY/dispatch-app-key`, or `None` when the unit
    /// does not load it (minting is then refused as `unconfigured`).
    pub(super) fn load() -> Result<Option<Self>, ScalerError> {
        let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        match std::fs::read_to_string(Path::new(&dir).join(KEY_CREDENTIAL)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(pem) => Self::from_pem(&pem).map(Some),
        }
    }
    /// RS256 App JWT, valid from a minute ago for nine minutes.
    pub(super) fn jwt(&self, now: u64) -> Result<String, ScalerError> {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = encode(
            json!({"iat": now.saturating_sub(60), "exp": now + 540, "iss": APP_ID.to_string()})
                .to_string()
                .as_bytes(),
        );
        let input = format!("{header}.{claims}");
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| ScalerError::Guard("App JWT signing failed"))?;
        Ok(format!("{input}.{}", encode(&signature)))
    }
}

/// Production [`MintApi`]: job and run reads through the scaler's `gh`, and
/// the mint itself through curl with the JWT only on stdin.
pub(super) struct AppMinter<'a> {
    pub(super) gh: &'a Github,
    pub(super) key: Option<AppKey>,
}
impl MintApi for AppMinter<'_> {
    fn job(&self, job: JobId) -> Result<Value, ScalerError> {
        self.gh.job(job)
    }
    fn run(&self, run: RunId, attempt: u32) -> Result<Value, ScalerError> {
        self.gh.request(
            "GET",
            &format!(
                "repos/{REPOSITORY}/actions/runs/{}/attempts/{attempt}",
                run.0
            ),
            None,
            false,
        )
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }
    fn mint(&self, scope: MintScope) -> Result<AppToken, ScalerError> {
        let key = self
            .key
            .as_ref()
            .ok_or(ScalerError::Guard("dispatch App key unavailable"))?;
        let config = mint_config(&key.jwt(now()?)?, scope)?;
        let mut command = Command::new("curl");
        command.args([
            "--disable",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "30",
            "--config",
            "-",
            "--request",
            "POST",
            &format!("https://api.github.com/app/installations/{INSTALLATION}/access_tokens"),
        ]);
        parse_minted(
            &execute(&mut command, config.as_bytes(), Duration::from_secs(40))?,
            scope,
        )
    }
}
fn mint_config(jwt: &str, scope: MintScope) -> Result<String, ScalerError> {
    Ok(format!(
        "header = {}\nheader = \"Accept: application/vnd.github+json\"\nheader = \"X-GitHub-Api-Version: 2022-11-28\"\ndata = {}\n",
        serde_json::to_string(&format!("Authorization: Bearer {jwt}"))?,
        serde_json::to_string(&scope.grant().to_string())?
    ))
}
/// Accept only an installation token whose granted permissions and
/// repositories are exactly the fixed grant.
fn parse_minted(bytes: &[u8], scope: MintScope) -> Result<AppToken, ScalerError> {
    let response: Value =
        serde_json::from_slice(bytes).map_err(|_| ScalerError::External("App mint response"))?;
    let token = response["token"]
        .as_str()
        .filter(|t| {
            t.starts_with("ghs_") && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .ok_or(ScalerError::External("App mint token"))?;
    let grant = scope.grant();
    let repositories: Option<Vec<&str>> = response["repositories"]
        .as_array()
        .map(|repos| repos.iter().filter_map(|r| r["name"].as_str()).collect());
    let expected: Option<Vec<&str>> = grant["repositories"]
        .as_array()
        .map(|repos| repos.iter().filter_map(Value::as_str).collect());
    if response["permissions"] != grant["permissions"] || repositories != expected {
        return Err(ScalerError::Guard(
            "minted token scope differs from the fixed grant",
        ));
    }
    Ok(AppToken(token.to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const NONCE: &str = "00112233445566778899aabbccddeeff";
    const SECRET: &str = "ghs_fixtureMintedTokenBytes0123456789";

    fn row() -> Record {
        let key = JobKey {
            run: RunId(41),
            attempt: 2,
            job: JobId(77),
        };
        Record {
            lane: CloneLane::Agent,
            key,
            vm: CloneId::try_from(310).unwrap(),
            name: "carrick-ci-41-2-77-1".into(),
            created: 1,
            state: State::Running,
            task: None,
            runner: Some(RunnerId(900)),
            assigned: Some(key.job),
            ip: None,
            failure: None,
            assigned_key: Some(key),
            approved: true,
            mints: vec![],
        }
    }
    fn request(scope: &str, run: u64) -> Vec<u8> {
        json!({"nonce":NONCE,"scope":scope,"run_id":run,"run_attempt":2,"sha":SHA})
            .to_string()
            .into_bytes()
    }

    struct Api {
        job_status: &'static str,
        configured: bool,
        mints: RefCell<Vec<MintScope>>,
        reads: RefCell<u32>,
    }
    impl Api {
        fn new() -> Self {
            Self {
                job_status: "in_progress",
                configured: true,
                mints: RefCell::new(vec![]),
                reads: RefCell::new(0),
            }
        }
    }
    impl MintApi for Api {
        fn job(&self, job: JobId) -> Result<Value, ScalerError> {
            *self.reads.borrow_mut() += 1;
            Ok(
                json!({"id":job.0,"run_id":41,"run_attempt":2,"runner_id":900,
                "name":"worker","head_sha":SHA,"status":self.job_status}),
            )
        }
        fn run(&self, run: RunId, attempt: u32) -> Result<Value, ScalerError> {
            Ok(
                json!({"id":run.0,"run_attempt":attempt,"head_sha":SHA,"head_branch":"main",
                "event":"issues","path":DISPATCH_WORKFLOW,
                "repository":{"full_name":REPOSITORY},"head_repository":{"full_name":REPOSITORY},
                "actor":{"login":DISPATCH_OWNER,"type":"User"},
                "triggering_actor":{"login":DISPATCH_OWNER,"type":"User"}}),
            )
        }
        fn configured(&self) -> bool {
            self.configured
        }
        fn mint(&self, scope: MintScope) -> Result<AppToken, ScalerError> {
            self.mints.borrow_mut().push(scope);
            Ok(AppToken(SECRET.into()))
        }
    }

    #[derive(Default)]
    struct Exchange {
        request: Option<Vec<u8>>,
        responses: Vec<String>,
        cleared: u32,
    }
    impl MintExchange for Exchange {
        fn read(&mut self) -> Result<Option<Vec<u8>>, ScalerError> {
            Ok(self.request.clone())
        }
        fn respond(&mut self, response: &MintResponse) -> Result<(), ScalerError> {
            self.responses.push(serde_json::to_string(response)?);
            Ok(())
        }
        fn clear(&mut self) -> Result<(), ScalerError> {
            self.request = None;
            self.cleared += 1;
            Ok(())
        }
    }

    fn serve(api: &Api, row: Record, bytes: Vec<u8>) -> (MintServed, Exchange, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger {
            rows: vec![row],
            ..Ledger::default()
        };
        let mut exchange = Exchange {
            request: Some(bytes),
            ..Exchange::default()
        };
        let served = serve_mint(
            api,
            &mut exchange,
            "carrick-ci-41-2-77-1",
            &mut ledger,
            &dir.path().join("ledger.json"),
        )
        .unwrap();
        (served, exchange, ledger)
    }

    #[test]
    fn assigned_in_progress_dispatch_job_gets_the_fixed_scope() {
        let api = Api::new();
        let (served, exchange, ledger) = serve(&api, row(), request("publish", 41));
        assert_eq!(served, MintServed::Minted(MintScope::Publish));
        assert_eq!(*api.mints.borrow(), vec![MintScope::Publish]);
        assert_eq!(exchange.responses.len(), 1);
        assert!(exchange.responses[0].contains(SECRET));
        assert_eq!(exchange.cleared, 1);
        assert_eq!(ledger.rows[0].mints[0].scope, Some(MintScope::Publish));
        // The durable ledger row records the request, never the token.
        assert!(!serde_json::to_string(&ledger).unwrap().contains(SECRET));
    }

    #[test]
    fn runner_bound_to_another_run_is_refused() {
        let api = Api::new();
        let (served, exchange, _) = serve(&api, row(), request("publish", 40));
        assert_eq!(served, MintServed::Refused(MintRefusal::IdentityMismatch));
        assert!(api.mints.borrow().is_empty());
        assert!(!exchange.responses[0].contains(SECRET));
        assert!(exchange.responses[0].contains("identity_mismatch"));
        // A row assigned another run, asked with that run's id, still fails
        // GitHub's runner binding.
        let mut other = row();
        other.runner = Some(RunnerId(901));
        let (served, _, _) = serve(&api, other, request("board", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::IdentityMismatch));
        assert!(api.mints.borrow().is_empty());
    }

    #[test]
    fn request_after_the_job_finished_is_refused() {
        let mut api = Api::new();
        api.job_status = "completed";
        let (served, exchange, _) = serve(&api, row(), request("board", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::JobNotInProgress));
        assert!(api.mints.borrow().is_empty());
        assert!(!exchange.responses[0].contains(SECRET));
        let mut reaped = row();
        reaped.state = State::Reaping;
        let (served, _, _) = serve(&Api::new(), reaped, request("board", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::NotAssigned));
    }

    #[test]
    fn exhausted_budget_is_refused_without_a_github_mint() {
        let api = Api::new();
        let mut spent = row();
        for n in 0..MINTS_PER_SCOPE {
            spent.mints.push(MintEntry {
                nonce: MintNonce::try_from(format!("{n:032x}")).unwrap(),
                scope: Some(MintScope::Publish),
                job: Some(JobId(77)),
                refused: None,
            });
        }
        let (served, exchange, _) = serve(&api, spent.clone(), request("publish", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::BudgetExhausted));
        assert!(api.mints.borrow().is_empty());
        assert_eq!(*api.reads.borrow(), 0, "budget checked before GitHub");
        assert!(exchange.responses[0].contains("budget_exhausted"));
        // The other scope keeps its own budget.
        let (served, _, _) = serve(&api, spent.clone(), request("board", 41));
        assert_eq!(served, MintServed::Minted(MintScope::Board));
        // A full request log refuses everything and stops growing.
        while spent.mints.len() < LOG_LIMIT {
            let n = spent.mints.len();
            spent.mints.push(MintEntry {
                nonce: MintNonce::try_from(format!("{n:032x}")).unwrap(),
                scope: None,
                job: None,
                refused: Some(MintRefusal::InvalidRequest),
            });
        }
        let (served, _, ledger) = serve(&api, spent, request("board", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::BudgetExhausted));
        assert_eq!(ledger.rows[0].mints.len(), LOG_LIMIT);
    }

    #[test]
    fn scope_outside_publish_and_board_is_refused() {
        for scope in ["admin", "contents", "Publish", ""] {
            let api = Api::new();
            let (served, exchange, _) = serve(&api, row(), request(scope, 41));
            assert_eq!(served, MintServed::Refused(MintRefusal::ScopeNotAllowed));
            assert!(api.mints.borrow().is_empty());
            assert!(!exchange.responses[0].contains(SECRET));
        }
        // A request cannot smuggle its own permission body.
        let mut value: Value = serde_json::from_slice(&request("publish", 41)).unwrap();
        value["permissions"] = json!({"administration":"write"});
        let api = Api::new();
        let (served, _, _) = serve(&api, row(), value.to_string().into_bytes());
        assert_eq!(served, MintServed::Refused(MintRefusal::InvalidRequest));
        assert!(api.mints.borrow().is_empty());
    }

    #[test]
    fn unconfigured_controller_refuses_and_answered_nonces_are_not_reminted() {
        let mut api = Api::new();
        api.configured = false;
        let (served, _, _) = serve(&api, row(), request("publish", 41));
        assert_eq!(served, MintServed::Refused(MintRefusal::Unconfigured));
        let api = Api::new();
        let mut answered = row();
        answered.mints.push(MintEntry {
            nonce: MintNonce::try_from(NONCE.to_owned()).unwrap(),
            scope: Some(MintScope::Publish),
            job: Some(JobId(77)),
            refused: None,
        });
        let (served, exchange, _) = serve(&api, answered, request("publish", 41));
        assert_eq!(served, MintServed::Ignored);
        assert!(exchange.responses.is_empty() && exchange.cleared == 1);
        assert!(api.mints.borrow().is_empty());
        let (served, _, _) = serve(&api, row(), b"{\"nonce\":\"short\"}".to_vec());
        assert_eq!(served, MintServed::Ignored);
    }

    #[test]
    fn minted_response_must_match_the_fixed_grant() {
        let ok = json!({"token":SECRET,"permissions":{"contents":"write","pull_requests":"write"},
            "repositories":[{"name":"carrick"}]});
        assert_eq!(
            parse_minted(ok.to_string().as_bytes(), MintScope::Publish)
                .unwrap()
                .secret(),
            SECRET
        );
        let mut wider = ok.clone();
        wider["permissions"]["administration"] = "write".into();
        assert!(parse_minted(wider.to_string().as_bytes(), MintScope::Publish).is_err());
        let board = json!({"token":SECRET,"permissions":{"organization_projects":"write"}});
        assert!(parse_minted(board.to_string().as_bytes(), MintScope::Board).is_ok());
        assert!(parse_minted(board.to_string().as_bytes(), MintScope::Publish).is_err());
        let config = mint_config("header.claims.signature", MintScope::Board).unwrap();
        assert!(config.contains(r#"organization_projects\"#));
        assert!(config.contains("Bearer header.claims.signature"));
    }

    #[test]
    fn app_jwt_is_rs256_with_the_app_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let pkcs1 = dir.path().join("key.pem");
        let status = Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&pkcs1)
            .arg("2048")
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl genrsa failed");
        let pkcs8 = dir.path().join("key8.pem");
        let status = Command::new("openssl")
            .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
            .arg(&pkcs1)
            .arg("-out")
            .arg(&pkcs8)
            .status()
            .unwrap();
        assert!(status.success(), "openssl pkcs8 failed");
        for path in [&pkcs1, &pkcs8] {
            let key = AppKey::from_pem(&std::fs::read_to_string(path).unwrap()).unwrap();
            let jwt = key.jwt(1_000_000).unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            assert_eq!(parts.len(), 3);
            let decode = |s: &str| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap()
            };
            let header: Value = serde_json::from_slice(&decode(parts[0])).unwrap();
            let claims: Value = serde_json::from_slice(&decode(parts[1])).unwrap();
            assert_eq!(header, json!({"alg":"RS256","typ":"JWT"}));
            assert_eq!(
                claims,
                json!({"iat":999_940,"exp":1_000_540,"iss":"5364291"})
            );
            let public = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                key.0.public().as_ref().to_vec(),
            );
            public
                .verify(
                    format!("{}.{}", parts[0], parts[1]).as_bytes(),
                    &decode(parts[2]),
                )
                .unwrap();
        }
        assert!(AppKey::from_pem("not a key").is_err());
    }
}
