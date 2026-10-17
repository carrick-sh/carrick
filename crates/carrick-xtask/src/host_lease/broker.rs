//! SSH carries only a bounded lease request and admission acknowledgement.
//! The forced command never interprets SSH_ORIGINAL_COMMAND or executes work.
use super::*;
use std::io::Read;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

pub const LOCK_PATH: &str = "/run/carrick/host-lease.lock";
const CONFIG_PATH: &str = "/etc/carrick/host-lease.toml";
pub(super) const CONFIG_ENV: &str = "CARRICK_HOST_LEASE_CONFIG";

#[derive(clap::Args, Clone, Debug)]
pub struct BrokerArgs {
    /// Fixed by the forced command, never selected by an SSH client.
    #[arg(long, default_value = LOCK_PATH)]
    lock_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    broker: String,
    identity_file: PathBuf,
    known_hosts_file: PathBuf,
}

impl Config {
    pub(super) fn load() -> io::Result<Option<Self>> {
        let explicit = std::env::var_os(CONFIG_ENV);
        let path = explicit
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| CONFIG_PATH.into());
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound && explicit.is_none() => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let config: Self = toml::from_str(&text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if config.broker.starts_with('-')
            || !config.broker.contains('@')
            || !config
                .broker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@.-_".contains(&b))
            || !config.identity_file.is_absolute()
            || !config.known_hosts_file.is_absolute()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "broker must be user@host; key and known_hosts paths must be absolute",
            ));
        }
        Ok(Some(config))
    }

    fn command(&self) -> Command {
        let mut command = Command::new("ssh");
        command.args([
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=2",
            "-o",
            "ServerAliveCountMax=3",
            "-i",
        ]);
        command.arg(&self.identity_file).arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            self.known_hosts_file.display()
        ));
        command.arg(&self.broker);
        // Isolate SSH custody in its own session so group-directed signals to
        // the supervisor's process group cannot drop broker custody before
        // workload cancellation and reaping complete.
        // SAFETY: setsid is async-signal-safe before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: HostLeaseMode,
    wait_ms: u64,
}

fn ready(fd: libc::c_int, timeout: Duration) -> io::Result<bool> {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the caller retains the descriptor for the whole bounded poll.
    let result = unsafe {
        libc::poll(
            &mut event,
            1,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if event.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    Ok(result > 0)
}

fn read_line(
    input: &mut (impl Read + AsRawFd),
    limit: Duration,
    mut cancelled: impl FnMut(Duration) -> io::Result<bool>,
) -> io::Result<Vec<u8>> {
    let start = Instant::now();
    let mut bytes = Vec::new();
    loop {
        if cancelled(Duration::ZERO)? {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "lease owner exited",
            ));
        }
        if !bytes.is_empty() && start.elapsed() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lease message deadline expired",
            ));
        }
        // Even a zero wait permits an already queued acknowledgement.
        if ready(input.as_raw_fd(), Duration::ZERO)? {
            let mut byte = [0];
            // Avoid Stdin's read-ahead buffer: readiness and consumption must
            // observe the same descriptor, including partial request deadlines.
            let count = unsafe { libc::read(input.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if count != 1 {
                return Err(if count == 0 {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "broker connection closed")
                } else {
                    io::Error::last_os_error()
                });
            }
            if byte[0] == b'\n' {
                return Ok(bytes);
            }
            bytes.push(byte[0]);
            if bytes.len() > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lease message too large",
                ));
            }
        } else {
            if start.elapsed() >= limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HOST_LEASE_WAIT_LIMIT expired",
                ));
            }
            match ready(
                input.as_raw_fd(),
                Duration::from_millis(100).min(limit.saturating_sub(start.elapsed())),
            ) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

pub fn run(args: BrokerArgs) -> Result<(), HostLeaseError> {
    let operation = || -> Result<(), HostLeaseError> {
        let mut input = io::stdin();
        let bytes = read_line(&mut input, VALIDATION_LIMIT, |_| Ok(false))
            .map_err(HostLeaseError::ChildWait)?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|e| {
            HostLeaseError::ChildWait(io::Error::new(io::ErrorKind::InvalidData, e))
        })?;
        let limit = Duration::from_millis(request.wait_ms);
        if limit > HOST_LEASE_WAIT_LIMIT {
            return Err(HostLeaseError::ChildWait(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requested wait exceeds HOST_LEASE_WAIT_LIMIT",
            )));
        }
        let mut output = io::stdout();
        let mut waiting = false;
        let lease = HostLease::acquire_broker_path(&args.lock_path, request.mode, limit, |delay| {
            if !waiting {
                output.write_all(b"waiting\n")?;
                output.flush()?;
                waiting = true;
            }
            ready(input.as_raw_fd(), delay)
        });
        // Zero-wait contention still acknowledges that it reached the lock
        // and reports wait expiry explicitly before closing.
        if matches!(lease, Err(HostLeaseError::Timeout { .. })) {
            if !waiting {
                output
                    .write_all(b"waiting\n")
                    .map_err(HostLeaseError::ChildWait)?;
            }
            output
                .write_all(b"timeout\n")
                .map_err(HostLeaseError::ChildWait)?;
            output.flush().map_err(HostLeaseError::ChildWait)?;
        }
        let _lease = lease?;
        output
            .write_all(b"acquired\n")
            .map_err(HostLeaseError::ChildWait)?;
        output.flush().map_err(HostLeaseError::ChildWait)?;
        let mut byte = [0];
        match input.read(&mut byte).map_err(HostLeaseError::ChildWait)? {
            0 => Ok(()),
            _ => Err(HostLeaseError::ChildWait(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected data after lease request",
            ))),
        }
    };
    operation()
}

pub(super) struct Session {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    reaped: AtomicBool,
}

impl Session {
    pub(super) fn connect(
        config: &Config,
        mode: HostLeaseMode,
        limit: Duration,
        mut wait: impl FnMut(Duration) -> io::Result<bool>,
    ) -> Result<Self, HostLeaseError> {
        let mut child = config
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(HostLeaseError::ChildWait)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| HostLeaseError::ChildWait(io::Error::other("broker stdin")))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| HostLeaseError::ChildWait(io::Error::other("broker stdout")))?;
        let mut session = Self {
            child,
            input: Some(input),
            output,
            reaped: AtomicBool::new(false),
        };
        let mut request = serde_json::to_vec(&Request {
            mode,
            wait_ms: limit.as_millis().min(u64::MAX as u128) as u64,
        })
        .map_err(|e| HostLeaseError::ChildWait(io::Error::other(e)))?;
        request.push(b'\n');
        session
            .input
            .as_mut()
            .ok_or_else(|| HostLeaseError::ChildWait(io::Error::other("broker stdin")))?
            .write_all(&request)
            .map_err(HostLeaseError::ChildWait)?;
        let mut waiting_since: Option<Instant> = None;
        loop {
            let reply_limit = match waiting_since {
                Some(start) => limit
                    .saturating_sub(start.elapsed())
                    .saturating_add(VALIDATION_LIMIT),
                None => VALIDATION_LIMIT,
            };
            let reply = match read_line(&mut session.output, reply_limit, &mut wait) {
                Ok(reply) => reply,
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut && waiting_since.is_some() =>
                {
                    return Err(HostLeaseError::Timeout {
                        path: PathBuf::from(&config.broker),
                        mode,
                        limit,
                    });
                }
                Err(error) => return Err(HostLeaseError::ChildWait(error)),
            };
            match reply.as_slice() {
                b"acquired" => break,
                b"waiting" => {
                    waiting_since.get_or_insert_with(Instant::now);
                    eprintln!(
                        "host-lease: waiting for {mode} at {} (HOST_LEASE_WAIT_LIMIT: {limit:?})",
                        config.broker
                    );
                }
                b"timeout" => {
                    return Err(HostLeaseError::Timeout {
                        path: PathBuf::from(&config.broker),
                        mode,
                        limit,
                    });
                }
                _ => {
                    return Err(HostLeaseError::ChildWait(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid broker reply",
                    )));
                }
            }
        }
        eprintln!("host-lease: acquired {mode} at {}", config.broker);
        Ok(session)
    }

    pub(super) fn fd(&self) -> libc::c_int {
        self.output.as_raw_fd()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn custody(&self) -> (libc::pid_t, &AtomicBool) {
        (self.child.id() as libc::pid_t, &self.reaped)
    }

    pub(super) fn check(&self) -> io::Result<()> {
        if ready(self.fd(), Duration::ZERO)? {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "host lease broker connection lost; run failed",
            ));
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.input.take());
        if !self.reaped.load(Ordering::Acquire) {
            // Do not leave a multiplexed/background SSH connection holding custody.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
