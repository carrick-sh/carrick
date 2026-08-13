//! The live kernel debug server.
//!
//! One background thread owns a `UnixListener` for the run's endpoint and
//! answers one snapshot request per connection. It never holds a kernel-object
//! lock: it calls [`Kernel::snapshot`], which is itself deadline-aware and
//! `try_lock`-based, so a wedged guest produces a named `Busy`/`TimedOut`
//! response instead of wedging the debugger too.
//!
//! Authentication is the peer's effective uid, read through the fallible
//! `peer_credentials` primitive. A host that cannot answer authoritatively is
//! a refusal, never a best-effort zero.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::dto::{
    KERNEL_DEBUG_RESPONSE_SCHEMA, KernelDebugRequest, KernelDebugSnapshot, KernelDebugTable,
};
use super::endpoint::{DebugEndpoint, EndpointError};
use super::wire::{
    self, DEADLINE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, WireError, encode_canonical,
};
use crate::kernel::core::Kernel;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("kernel debug endpoint unavailable: {0}")]
    Endpoint(#[from] EndpointError),
    #[error("kernel debug listener failed: {0}")]
    Io(#[from] io::Error),
}

/// Process-wide slot holding the run's server so it lives as long as the run.
///
/// A server parked in a local would be dropped at the end of the bootstrap
/// function and the socket would vanish immediately — the exact "live mechanism
/// doing nothing" shape this project treats as abandoned.
static INSTALLED: std::sync::OnceLock<parking_lot::Mutex<Option<KernelDebugServer>>> =
    std::sync::OnceLock::new();

/// Exact opt-out. The server is ON by default.
const DISABLE_ENV: &str = "CARRICK_KERNEL_DEBUG";

/// A running server. Dropping it unbinds the socket and releases the endpoint,
/// so a run never leaves a live-looking socket behind.
#[derive(Debug)]
pub struct KernelDebugServer {
    endpoint: DebugEndpoint,
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    /// PID that bound the socket. Carrick forks real host processes for
    /// `clone(2)` on other backends, and a forked child inherits this struct
    /// while inheriting none of its threads. Without this guard the child's
    /// `Drop` would unlink the PARENT's live socket.
    owner_pid: u32,
}

impl KernelDebugServer {
    /// Bind and serve snapshots of `kernel` for the ambient `CARRICK_RUN_ID`.
    ///
    /// Returns `Ok(None)` when no run ID is set — an ungated ad-hoc invocation
    /// has no stable identity to publish under, and inventing one would create
    /// an endpoint no tool could find. Every other failure is reported.
    pub fn start(kernel: Arc<Kernel>) -> Result<Option<Self>, ServerError> {
        let endpoint = match DebugEndpoint::for_current_run() {
            Ok(endpoint) => endpoint,
            Err(EndpointError::MissingRunId) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Self::start_at(kernel, endpoint).map(Some)
    }

    /// Bind and serve at an exact endpoint. Used by tests and by callers that
    /// already resolved the run identity.
    pub fn start_at(kernel: Arc<Kernel>, endpoint: DebugEndpoint) -> Result<Self, ServerError> {
        let nonce = server_nonce();
        endpoint.claim(nonce)?;
        let listener = UnixListener::bind(endpoint.socket_path())?;
        endpoint.secure_socket()?;
        endpoint.write_owner(nonce)?;

        // A bounded accept timeout lets the thread notice shutdown promptly
        // without a self-pipe.
        listener.set_nonblocking(false)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_endpoint = endpoint.clone();
        let join = std::thread::Builder::new()
            .name("carrick-kernel-debug".to_owned())
            .spawn(move || {
                serve_loop(&listener, &kernel, &thread_shutdown);
                drop(listener);
                thread_endpoint.release();
            })?;

        Ok(Self {
            endpoint,
            shutdown,
            join: Some(join),
            owner_pid: std::process::id(),
        })
    }

    /// Start the run's server and retain it for the process lifetime.
    ///
    /// Default ON; `CARRICK_KERNEL_DEBUG=0` is the exact opt-out. A failure to
    /// publish the endpoint is reported and the run continues: the guest
    /// workload is the product, and losing the debugger must not lose the run.
    /// The failure is never silent.
    pub fn install(kernel: Arc<Kernel>) {
        if std::env::var_os(DISABLE_ENV).is_some_and(|value| value == "0") {
            return;
        }
        match Self::start(kernel) {
            Ok(Some(server)) => {
                let slot = INSTALLED.get_or_init(|| parking_lot::Mutex::new(None));
                *slot.lock() = Some(server);
            }
            Ok(None) => {
                // No CARRICK_RUN_ID: no stable identity to publish under.
            }
            Err(error) => {
                tracing::warn!(
                    target: "carrick::kernel::debug",
                    %error,
                    "kernel debug endpoint not published; `carrick debug hvpatch-kernel` is unavailable for this run"
                );
            }
        }
    }

    /// Path of the installed server, when one is running.
    pub fn installed_socket_path() -> Option<std::path::PathBuf> {
        let slot = INSTALLED.get()?;
        let guard = slot.lock();
        guard
            .as_ref()
            .map(|server| server.socket_path().to_path_buf())
    }

    pub fn socket_path(&self) -> &std::path::Path {
        self.endpoint.socket_path()
    }

    /// Stop serving and unbind. Idempotent.
    ///
    /// A host-fork child never tears down its parent's endpoint.
    pub fn shutdown(&mut self) {
        if std::process::id() != self.owner_pid {
            return;
        }
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        // Unblock a thread parked in `accept` by connecting to ourselves. The
        // loop re-checks the shutdown flag before handling a connection.
        let _ = UnixStream::connect(self.endpoint.socket_path());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.endpoint.release();
    }
}

impl Drop for KernelDebugServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn server_nonce() -> u64 {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // A nonce collision only weakens stale-owner reclamation, and the PID
        // check still fails closed, so a degraded source is survivable here.
        return std::process::id() as u64;
    }
    u64::from_le_bytes(bytes)
}

fn serve_loop(listener: &UnixListener, kernel: &Arc<Kernel>, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::SeqCst) {
        let Ok((stream, _address)) = listener.accept() else {
            continue;
        };
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        // A failed connection is that peer's problem, never the run's.
        let _ = handle_connection(stream, kernel);
    }
}

fn handle_connection(mut stream: UnixStream, kernel: &Arc<Kernel>) -> Result<(), WireError> {
    let deadline = Instant::now() + DEADLINE;
    authenticate(&stream)?;

    let payload = wire::read_frame(&mut stream, MAX_REQUEST_BYTES, deadline, "server-read")?;
    let request: KernelDebugRequest = wire::decode_exact(&payload)?;
    let response = build_response(&request, kernel, deadline);
    let encoded = encode_canonical(&response)?;
    wire::write_frame(
        &mut stream,
        &encoded,
        MAX_RESPONSE_BYTES,
        deadline,
        "server-write",
    )
}

/// Only a peer running as the runtime's own uid may read kernel state.
fn authenticate(stream: &UnixStream) -> Result<(), WireError> {
    let credentials = carrick_portable::peer_credentials(stream.as_raw_fd()).map_err(|error| {
        WireError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer credentials unavailable: {error}"),
        ))
    })?;
    // SAFETY: `geteuid` is always safe and cannot fail.
    let runtime_uid = unsafe { libc::geteuid() };
    if credentials.uid != runtime_uid {
        return Err(WireError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "kernel debug peer uid {} does not match runtime uid {runtime_uid}",
                credentials.uid
            ),
        )));
    }
    Ok(())
}

/// Build the response, turning a refused request or a busy kernel into a
/// schema-tagged error response rather than a dropped connection: the CLI must
/// be able to distinguish "runtime said no" from "runtime is wedged".
fn build_response(
    request: &KernelDebugRequest,
    kernel: &Arc<Kernel>,
    deadline: Instant,
) -> ServerResponse {
    if let Err(error) = request.check_schema() {
        return ServerResponse::Error {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            error: error.to_string(),
        };
    }
    let selected = request.selected();
    match kernel.snapshot(deadline) {
        Ok(snapshot) => {
            let projected = KernelDebugSnapshot::project(&snapshot, &selected);
            ServerResponse::Snapshot(Box::new(projected))
        }
        Err(error) => ServerResponse::Error {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            error: error.to_string(),
        },
    }
}

/// Wire union. Untagged so a successful snapshot decodes directly into
/// [`KernelDebugSnapshot`] on the client, while an error carries the same
/// schema tag and a named reason.
#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum ServerResponse {
    Snapshot(Box<KernelDebugSnapshot>),
    Error { schema: String, error: String },
}

/// The set of tables a bare (unfiltered) request selects. Exposed so tests and
/// the CLI agree on the default without duplicating the list.
pub fn default_tables() -> Vec<KernelDebugTable> {
    KernelDebugTable::ALL.to_vec()
}
