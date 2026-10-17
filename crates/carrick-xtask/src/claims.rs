//! Git-protocol leases. Custom refs must never be updated with REST PATCH:
//! GitHub does not enforce fast-forward there (#572).
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const MAX_LEASE_TTL_SECS: u64 = 45 * 60;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("{0}")]
    Refused(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("lease JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("git {operation} failed ({status}): {details}; no successful claim is implied")]
    Git {
        operation: String,
        status: std::process::ExitStatus,
        details: String,
    },
}

fn refuse(message: &str) -> ClaimError {
    ClaimError::Refused(message.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClaimRef(String);

impl TryFrom<String> for ClaimRef {
    type Error = ClaimError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let rest = value
            .strip_prefix("refs/claims/")
            .ok_or_else(|| refuse("ref must be under refs/claims/"))?;
        let (kind, name) = rest
            .split_once('/')
            .ok_or_else(|| refuse("claim needs a name"))?;
        if !["issue", "hot", "stack", "review", "gate", "probe"].contains(&kind)
            || name.is_empty()
            || !rest.split('/').all(|part| {
                !part.is_empty()
                    && !part.starts_with('.')
                    && !part.ends_with('.')
                    && !part.ends_with(".lock")
                    && !part.contains("..")
                    && part.bytes().all(|c| {
                        c.is_ascii_digit() || c.is_ascii_alphabetic() || b"._-".contains(&c)
                    })
            })
        {
            return Err(refuse("invalid claim namespace or name"));
        }
        Ok(Self(value))
    }
}
impl From<ClaimRef> for String {
    fn from(value: ClaimRef) -> Self {
        value.0
    }
}
impl std::str::FromStr for ClaimRef {
    type Err = ClaimError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.to_owned().try_into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitId(String);
impl TryFrom<String> for CommitId {
    type Error = ClaimError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(refuse("expected a full lowercase SHA-1 commit id"));
        }
        Ok(Self(value))
    }
}
impl From<CommitId> for String {
    fn from(value: CommitId) -> Self {
        value.0
    }
}
impl std::str::FromStr for CommitId {
    type Err = ClaimError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.to_owned().try_into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseUntil(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseState {
    Active,
    Reclaim,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub host: String,
    pub slot: String,
    pub lane: String,
    pub issue: String,
    pub backend: String,
    pub conversation: String,
    pub lease_until: LeaseUntil,
    pub workorder_sha256: String,
    pub state: LeaseState,
}

impl Lease {
    fn validate(&self) -> Result<(), ClaimError> {
        if [
            &self.host,
            &self.slot,
            &self.lane,
            &self.issue,
            &self.backend,
            &self.conversation,
        ]
        .iter()
        .any(|s| s.trim().is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || self.workorder_sha256.len() != 64
            || !self
                .workorder_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(refuse("invalid lease identity or work-order digest"));
        }
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct ClaimsArgs {
    #[arg(long, default_value = "origin", global = true)]
    pub remote: String,
    /// Test-only clock override (requires CARRICK_XTASK_TEST_NOW=1).
    #[arg(long, global = true, hide = true)]
    pub now: Option<u64>,
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Args, Debug)]
pub struct ClaimSet {
    pub reference: ClaimRef,
    /// CODEOWNERS lock names, sorted before acquisition.
    #[arg(long)]
    pub hot: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    Acquire {
        #[command(flatten)]
        set: ClaimSet,
        #[arg(long)]
        lease: PathBuf,
    },
    Heartbeat {
        #[command(flatten)]
        set: ClaimSet,
        #[arg(long)]
        expected: CommitId,
        #[arg(long)]
        lease_until: u64,
    },
    Reclaim {
        #[command(flatten)]
        set: ClaimSet,
        #[arg(long)]
        expected: CommitId,
        #[arg(long)]
        lease: PathBuf,
    },
    Release {
        #[command(flatten)]
        set: ClaimSet,
        #[arg(long)]
        expected: CommitId,
    },
    List,
}

#[derive(Debug, Serialize)]
pub struct Claim {
    pub reference: ClaimRef,
    pub sha: CommitId,
    pub lease: Lease,
}

pub struct Remote<'a> {
    root: &'a Path,
    remote: &'a str,
}
impl<'a> Remote<'a> {
    pub fn new(root: &'a Path, remote: &'a str) -> Result<Self, ClaimError> {
        if remote.is_empty() || remote.starts_with('-') || remote.chars().any(char::is_control) {
            return Err(refuse("invalid remote"));
        }
        Ok(Self { root, remote })
    }

    fn git(&self, args: &[&str], input: &[u8]) -> Result<String, ClaimError> {
        // Spool stdin: no pipe writer can deadlock on git's output.
        let mut file = tempfile::tempfile()?;
        file.write_all(input)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let out = Command::new("git")
            .current_dir(self.root)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::from(file))
            .output()?;
        if !out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let details = format!("{} {}", stdout.trim(), stderr.trim())
                .trim()
                .to_owned();
            return Err(ClaimError::Git {
                operation: args[0].into(),
                status: out.status,
                details,
            });
        }
        String::from_utf8(out.stdout).map_err(|_| refuse("non-UTF8 git output"))
    }

    fn heads(&self) -> Result<Vec<(ClaimRef, CommitId)>, ClaimError> {
        let mut result = Vec::new();
        for line in self
            .git(&["ls-remote", "--refs", self.remote, "refs/claims/*"], b"")?
            .lines()
        {
            let Some((sha, reference)) = line.split_once('\t') else {
                eprintln!("claims: skipping malformed ls-remote line: {line}");
                continue;
            };
            match (reference.parse::<ClaimRef>(), sha.parse::<CommitId>()) {
                (Ok(reference), Ok(sha)) => result.push((reference, sha)),
                (Err(err), _) | (_, Err(err)) => {
                    eprintln!("claims: skipping invalid ref {reference}: {err}");
                }
            }
        }
        Ok(result)
    }

    fn read(&self, reference: &ClaimRef, expected: &CommitId) -> Result<Lease, ClaimError> {
        self.git(
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                self.remote,
                &reference.0,
            ],
            b"",
        )?;
        let text = self.git(&["show", "-s", "--format=%B", &expected.0, "--"], b"")?;
        let lease: Lease = serde_json::from_str(&text)?;
        lease.validate()?;
        Ok(lease)
    }

    fn commit(&self, lease: &Lease, parent: Option<&CommitId>) -> Result<CommitId, ClaimError> {
        let tree = self.git(&["hash-object", "-w", "-t", "tree", "--stdin"], b"")?;
        // Unique identity prevents git's "already up to date" optimization
        // from accepting a stale expectation when two payloads are identical.
        let nonce = tempfile::tempdir()?;
        let identity = format!(
            "carrick-claims-{}",
            nonce
                .path()
                .file_name()
                .ok_or_else(|| refuse("nonce"))?
                .to_string_lossy()
        );
        let mut cmd = Command::new("git");
        cmd.current_dir(self.root)
            .args(["-c", "commit.gpgsign=false", "commit-tree", tree.trim()]);
        if let Some(parent) = parent {
            cmd.args(["-p", &parent.0]);
        }
        let out = cmd
            .args(["-m", &serde_json::to_string(lease)?])
            .env("GIT_AUTHOR_NAME", &identity)
            .env("GIT_COMMITTER_NAME", &identity)
            .env("GIT_AUTHOR_EMAIL", "noreply@carrick.sh")
            .env("GIT_COMMITTER_EMAIL", "noreply@carrick.sh")
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            let details = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return Err(ClaimError::Git {
                operation: "commit-tree".into(),
                status: out.status,
                details,
            });
        }
        String::from_utf8_lossy(&out.stdout).trim().parse()
    }

    fn push(
        &self,
        refs: &[ClaimRef],
        expected: Option<&CommitId>,
        new: Option<&CommitId>,
    ) -> Result<(), ClaimError> {
        let mut args = vec!["push".to_owned(), "--porcelain".into(), "--atomic".into()];
        for reference in refs {
            args.push(format!(
                "--force-with-lease={}:{}",
                reference.0,
                expected.map_or("", |id| &id.0)
            ));
        }
        args.push(self.remote.into());
        for reference in refs {
            args.push(format!("{}:{}", new.map_or("", |id| &id.0), reference.0));
        }
        self.git(&args.iter().map(String::as_str).collect::<Vec<_>>(), b"")?;
        Ok(())
    }

    fn cohort(&self, set: &ClaimSet, expected: &CommitId) -> Result<Vec<ClaimRef>, ClaimError> {
        let heads = self.heads()?;
        if !heads
            .iter()
            .any(|(r, s)| r == &set.reference && s == expected)
        {
            return Err(refuse("stale expected SHA or missing claim"));
        }
        let refs: Vec<_> = heads
            .into_iter()
            .filter(|(_, s)| s == expected)
            .map(|(r, _)| r)
            .collect();
        if !set.references()?.iter().all(|r| refs.contains(r)) {
            return Err(refuse("hot set does not belong to expected claim"));
        }
        Ok(refs)
    }
}

impl ClaimSet {
    fn references(&self) -> Result<Vec<ClaimRef>, ClaimError> {
        let mut refs = vec![self.reference.clone()];
        for name in &self.hot {
            refs.push(format!("refs/claims/hot/{name}").parse()?);
        }
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        refs.dedup();
        Ok(refs)
    }
}

fn now(override_now: Option<u64>) -> Result<LeaseUntil, ClaimError> {
    if let Some(secs) = override_now {
        if std::env::var_os("CARRICK_XTASK_TEST_NOW").as_deref() != Some(std::ffi::OsStr::new("1"))
        {
            return Err(refuse(
                "--now is test-only and requires CARRICK_XTASK_TEST_NOW=1",
            ));
        }
        return Ok(LeaseUntil(secs));
    }
    Ok(LeaseUntil(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refuse("clock predates Unix epoch"))?
            .as_secs(),
    ))
}
fn load(path: &Path, time: LeaseUntil) -> Result<Lease, ClaimError> {
    let lease: Lease = serde_json::from_slice(&std::fs::read(path)?)?;
    lease.validate()?;
    if lease.lease_until.0 <= time.0
        || lease.lease_until.0 > time.0.saturating_add(MAX_LEASE_TTL_SECS)
    {
        return Err(refuse(
            "new lease must expire in the future within the 45-minute policy TTL",
        ));
    }
    Ok(lease)
}
fn records(refs: Vec<ClaimRef>, sha: CommitId, lease: Lease) -> Vec<Claim> {
    refs.into_iter()
        .map(|reference| Claim {
            reference,
            sha: sha.clone(),
            lease: lease.clone(),
        })
        .collect()
}

pub fn run(root: &Path, args: ClaimsArgs, writer: &mut impl Write) -> Result<(), ClaimError> {
    let remote = Remote::new(root, &args.remote)?;
    let time = now(args.now)?;
    let result = match args.action {
        Action::List => {
            let mut result = Vec::new();
            for (reference, sha) in remote.heads()? {
                match remote.read(&reference, &sha) {
                    Ok(lease) => result.push(Claim {
                        reference,
                        sha,
                        lease,
                    }),
                    Err(err) => {
                        eprintln!("claims: skipping unreadable claim {}: {err}", reference.0);
                    }
                }
            }
            result
        }
        Action::Acquire { set, lease } => {
            let mut lease = load(&lease, time)?;
            lease.state = LeaseState::Active;
            let refs = set.references()?;
            let sha = remote.commit(&lease, None)?;
            remote.push(&refs, None, Some(&sha))?;
            records(refs, sha, lease)
        }
        Action::Heartbeat {
            set,
            expected,
            lease_until,
        } => {
            let refs = remote.cohort(&set, &expected)?;
            let mut lease = remote.read(&set.reference, &expected)?;
            if lease.lease_until.0 <= time.0
                || lease_until <= lease.lease_until.0
                || lease_until > time.0.saturating_add(MAX_LEASE_TTL_SECS)
            {
                return Err(refuse(
                    "heartbeat requires an unexpired lease and a later deadline within the 45-minute policy TTL",
                ));
            }
            lease.lease_until = LeaseUntil(lease_until);
            let new = remote.commit(&lease, Some(&expected))?;
            remote.push(&refs, Some(&expected), Some(&new))?;
            records(refs, new, lease)
        }
        Action::Reclaim {
            set,
            expected,
            lease,
        } => {
            let refs = remote.cohort(&set, &expected)?;
            let old = remote.read(&set.reference, &expected)?;
            let mut lease = load(&lease, time)?;
            if old.lease_until.0 > time.0 {
                return Err(refuse("lease has not expired"));
            }
            if lease.issue != old.issue || lease.workorder_sha256 != old.workorder_sha256 {
                return Err(refuse("reclaim cannot change issue or work order"));
            }
            lease.state = LeaseState::Reclaim;
            let new = remote.commit(&lease, Some(&expected))?;
            remote.push(&refs, Some(&expected), Some(&new))?;
            records(refs, new, lease)
        }
        Action::Release { set, expected } => {
            let refs = remote.cohort(&set, &expected)?;
            remote.push(&refs, Some(&expected), None)?;
            Vec::new()
        }
    };
    serde_json::to_writer_pretty(&mut *writer, &result)?;
    writeln!(writer)?;
    Ok(())
}
