//! The live kernel debug server.
//!
//! One background thread owns a `UnixListener` for the run's endpoint and
//! admits bounded workers, each serving one snapshot request per connection.
//! It never holds a kernel-object lock: it calls [`Kernel::snapshot`], which is itself deadline-aware and
//! `try_lock`-based, so a wedged guest produces a named `Busy`/`TimedOut`
//! response instead of wedging the debugger too.
//!
//! Authentication is the peer's effective uid, read through the fallible
//! `peer_credentials` primitive. A host that cannot answer authoritatively is
//! a refusal, never a best-effort zero.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::dto::{
    KERNEL_DEBUG_RESPONSE_SCHEMA, KernelDebugDegraded, KernelDebugRequest, KernelDebugSnapshot,
    KernelDebugTable,
};
use super::endpoint::{DebugEndpoint, EndpointError};
use super::wire::{
    self, DEGRADED_BUDGET, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, STRICT_SNAPSHOT_BUDGET,
    WireError, encode_canonical,
};
use crate::kernel::core::Kernel;
use crate::kernel::socket_rpc::{self, Cancellation, Connection, ConnectionSlots};

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
    cancellation: Arc<Cancellation>,
    join: Option<std::thread::JoinHandle<()>>,
    /// PID that bound the socket. Carrick forks real host processes for
    /// `clone(2)` on other backends, and a forked child inherits this struct
    /// while inheriting none of its threads. Without this guard the child's
    /// `Drop` would unlink the PARENT's live socket.
    owner_pid: u32,
    /// Exact endpoint incarnation. Release is conditional on this nonce.
    nonce: u64,
}

impl KernelDebugServer {
    /// Bind and serve snapshots for the carrier's immutable cleanup scope.
    pub fn start(kernel: Arc<Kernel>, carrier_scope: &str) -> Result<Self, ServerError> {
        Self::start_at(kernel, DebugEndpoint::for_run_id(carrier_scope)?)
    }

    /// Bind and serve at an exact endpoint. Used by tests and by callers that
    /// already resolved the run identity.
    pub fn start_at(kernel: Arc<Kernel>, endpoint: DebugEndpoint) -> Result<Self, ServerError> {
        let cancellation = Arc::new(Cancellation::new()?);
        let nonce = server_nonce();
        endpoint.claim(nonce)?;
        let listener = UnixListener::bind(endpoint.socket_path())?;
        endpoint.secure_socket()?;
        endpoint.write_owner(nonce)?;

        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_endpoint = endpoint.clone();
        let thread_cancellation = Arc::clone(&cancellation);
        let join = std::thread::Builder::new()
            .name("carrick-kernel-debug".to_owned())
            .spawn(move || {
                serve_loop(&listener, &kernel, &thread_shutdown, &thread_cancellation);
                drop(listener);
                thread_endpoint.release(nonce);
            })?;

        Ok(Self {
            endpoint,
            shutdown,
            cancellation,
            join: Some(join),
            owner_pid: std::process::id(),
            nonce,
        })
    }

    /// Start the run's server and retain it for the process lifetime.
    ///
    /// Default ON; `CARRICK_KERNEL_DEBUG=0` is the exact opt-out. A failure to
    /// publish the endpoint is reported and the run continues: the guest
    /// workload is the product, and losing the debugger must not lose the run.
    /// The failure is never silent.
    pub fn install(kernel: Arc<Kernel>, carrier_scope: &str) {
        if std::env::var_os(DISABLE_ENV).is_some_and(|value| value == "0") {
            return;
        }
        match Self::start(kernel, carrier_scope) {
            Ok(server) => {
                let slot = INSTALLED.get_or_init(|| parking_lot::Mutex::new(None));
                *slot.lock() = Some(server);
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
        // The same sticky pipe wakes accept and every blocked handler.
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.endpoint.release(self.nonce);
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

fn serve_loop(
    listener: &UnixListener,
    kernel: &Arc<Kernel>,
    shutdown: &AtomicBool,
    cancellation: &Arc<Cancellation>,
) {
    let slots = Arc::new(ConnectionSlots::default());
    let mut handlers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if cancellation.wait(listener.as_fd(), libc::POLLIN).is_err() {
                    break;
                }
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let mut index = 0;
        while index < handlers.len() {
            if handlers[index].is_finished() {
                let _ = handlers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        let Some(permit) = slots.try_acquire() else {
            continue;
        };
        let Ok(connection) = Connection::new(stream, Arc::clone(cancellation)) else {
            continue;
        };
        let kernel = Arc::clone(kernel);
        if let Ok(handler) = std::thread::Builder::new()
            .name("carrick-debug-conn".to_owned())
            .spawn(move || {
                // Permit drops last, after the socket and kernel context, also
                // on unwind or a failed spawn.
                let _permit = permit;
                let mut connection = connection;
                let kernel = kernel;
                let _ = handle_connection(&mut connection, &kernel);
            })
        {
            handlers.push(handler);
        }
    }
    cancellation.cancel();
    for handler in handlers {
        let _ = handler.join();
    }
}

fn handle_connection(stream: &mut Connection, kernel: &Arc<Kernel>) -> Result<(), WireError> {
    authenticate(stream)?;
    let payload = socket_rpc::read_frame(stream, MAX_REQUEST_BYTES)?;
    let request: KernelDebugRequest = wire::decode_exact(&payload)?;
    let response = build_response(&request, kernel, Instant::now());
    let encoded = encode_canonical(&response)?;
    socket_rpc::write_frame(stream, &encoded, MAX_RESPONSE_BYTES)?;
    Ok(())
}

/// Only a peer running as the runtime's own uid may read kernel state.
fn authenticate(stream: &impl AsRawFd) -> Result<(), WireError> {
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
    started: Instant,
) -> ServerResponse {
    if let Err(error) = request.check_schema() {
        return ServerResponse::Error {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            error: error.to_string(),
        };
    }
    if let super::dto::KernelDebugAction::Abort { run_id } = &request.action {
        super::post_mortem::request_abort(super::post_mortem::AbortReason::DebugRequest {
            run_id: run_id.clone(),
        });
        return ServerResponse::Aborting {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            run_id: run_id.clone(),
            post_mortem_dir: super::post_mortem::PostMortem::configured_dir()
                .map(|dir| dir.display().to_string()),
        };
    }
    let selected = request.selected();
    match kernel.snapshot(started + STRICT_SNAPSHOT_BUDGET) {
        Ok(snapshot) => {
            let aux = kernel.debug_aux_provider();
            let projected =
                KernelDebugSnapshot::project_with_aux(&snapshot, &selected, aux.as_deref(), &[]);
            ServerResponse::Snapshot(Box::new(projected))
        }
        // A held authority (a wedge's MM coordinator) refuses the coherent
        // graph. Say what can still be read without waiting on it, and who
        // holds it, instead of failing wholesale.
        Err(
            error @ (super::super::KernelSnapshotError::Busy
            | super::super::KernelSnapshotError::TimedOut),
        ) => {
            let degraded = kernel.degraded_snapshot(Instant::now() + DEGRADED_BUDGET);
            ServerResponse::Degraded(Box::new(KernelDebugDegraded::project(
                error.to_string(),
                &degraded,
            )))
        }
        // The strict, served projection refuses a graph that violates an
        // invariant — right for a caller that must trust what it gets. But
        // `carrick debug hvpatch-kernel` querying a LIVE, still-hung carrier
        // is the opposite contract: the graph is already known to be wrong,
        // and the violated invariant is the most valuable row in the
        // capture. Turning it into a bare error string discarded the whole
        // kernel graph exactly when the post-mortem needed it (a cpython
        // process-pool hang refused this way). Forensic capture never
        // refuses; report the violation IN the projection instead of hiding
        // the graph behind it.
        Err(super::super::KernelSnapshotError::InvariantViolation(message)) => {
            match kernel.forensic_snapshot(Instant::now() + STRICT_SNAPSHOT_BUDGET) {
                Ok(forensic) => {
                    let aux = kernel.debug_aux_provider();
                    let projected = KernelDebugSnapshot::project_with_aux(
                        &forensic.snapshot,
                        &selected,
                        aux.as_deref(),
                        &forensic.findings,
                    );
                    ServerResponse::Snapshot(Box::new(projected))
                }
                // The forensic path only ever fails on the same
                // Busy/TimedOut/AuthorityUnavailable grounds as the strict
                // one (it audits instead of refusing, so it cannot itself
                // raise a NEW invariant violation) — a live double failure is
                // rare enough that naming both refusals plainly is the
                // honest answer, not a guess at which one to hide.
                Err(forensic_error) => ServerResponse::Error {
                    schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
                    error: format!(
                        "kernel snapshot invariant violated: {message}; forensic capture also failed: {forensic_error}"
                    ),
                },
            }
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
    /// The coherent snapshot was refused by a busy authority; this is the
    /// non-coherent per-object view plus the busy coordinators.
    Degraded(Box<KernelDebugDegraded>),
    /// An abort was latched. The runtime performs the ONE capture at its next
    /// runner boundary; this response is the acknowledgement, not the
    /// artifact, so an abort never produces two answers to the same question.
    Aborting {
        schema: String,
        run_id: String,
        post_mortem_dir: Option<String>,
    },
    Error {
        schema: String,
        error: String,
    },
}

/// The set of tables a bare (unfiltered) request selects. Exposed so tests and
/// the CLI agree on the default without duplicating the list.
pub fn default_tables() -> Vec<KernelDebugTable> {
    KernelDebugTable::ALL.to_vec()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::num::NonZeroU64;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::*;
    use crate::kernel::{Asid, MmBackend, MmBackendSnapshot, RootBootstrap, SnapshotError};

    const COMPLETION_FAILURE_BOUND: Duration = Duration::from_secs(30);

    #[test]
    fn a_partial_request_does_not_block_a_complete_frame_or_shutdown() {
        let (_temp, endpoint) = super::super::endpoint::tests::scoped_endpoint("debug-partial");
        let bootstrap = RootBootstrap::for_reference_model(
            4242,
            carrick_hal::ThreadId::synthetic_for_tests(4242),
            "debug-partial".to_owned(),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let mut server = KernelDebugServer::start_at(kernel, endpoint.clone()).expect("server");
        let mut stalled = UnixStream::connect(endpoint.socket_path()).expect("stalled peer");
        stalled.write_all(&64_u32.to_be_bytes()).expect("prefix");
        stalled.write_all(b"x").expect("partial payload");
        assert!(
            server
                .cancellation
                .wait_for_handlers(1, COMPLETION_FAILURE_BOUND),
            "handler never reached the cancellable socket wait"
        );

        let mut complete = UnixStream::connect(endpoint.socket_path()).expect("second peer");
        let request = encode_canonical(&KernelDebugRequest::for_tables(None)).expect("request");
        // Deliberately do not half-close: the complete frame alone authorizes
        // a response, while the first handler remains blocked on its payload.
        complete
            .write_all(&u32::try_from(request.len()).expect("length").to_be_bytes())
            .expect("prefix");
        complete.write_all(&request).expect("payload");
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(socket_rpc::read_frame(&mut complete, MAX_RESPONSE_BYTES));
        });
        let response = rx
            .recv_timeout(COMPLETION_FAILURE_BOUND)
            .expect("second request stalled behind the first")
            .expect("response");
        let response: serde_json::Value = wire::decode_exact(&response).expect("JSON response");
        assert_eq!(response["schema"], KERNEL_DEBUG_RESPONSE_SCHEMA);
        reader.join().expect("reader");
        assert!(
            server
                .cancellation
                .wait_for_handlers(1, COMPLETION_FAILURE_BOUND)
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let shutdown = std::thread::spawn(move || {
            server.shutdown();
            let _ = tx.send(());
        });
        rx.recv_timeout(COMPLETION_FAILURE_BOUND)
            .expect("shutdown did not cancel and join the partial-frame handler");
        shutdown.join().expect("shutdown");
        // The partial sender stayed alive until shutdown had joined its handler.
        drop(stalled);
        assert!(!endpoint.socket_path().exists());
    }

    /// An `Mm` backend that reports a mapping id the frame inventory never
    /// recorded — the same class of alias-registry/backend disagreement as
    /// the 2026-09-07 exit wedge, where `carrick debug hvpatch-kernel`
    /// answered only a bare invariant string and nothing else.
    /// `validate_snapshot` still refuses this graph (right for the strict,
    /// served path), but `forensic_snapshot`'s audit re-judges it and never
    /// refuses, carrying the violation forward as a finding instead.
    #[derive(Debug)]
    struct DanglingMappingBackend;

    impl MmBackend for DanglingMappingBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            let root = crate::kernel::Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(0x1000))
                .expect("aligned stage-1 root");
            let asid = Asid::from_registry_allocation(
                std::num::NonZeroU16::new(1).expect("nonzero test ASID"),
            );
            Ok(MmBackendSnapshot {
                revision: 1,
                binding: crate::kernel::MmBinding {
                    asid,
                    stage1_root: root,
                    ttbr0: crate::kernel::Ttbr0::for_aarch64(asid, root),
                },
                vmas: Vec::new(),
                vma_revision: None,
                mapping_ids: vec![carrick_hal::MappingId::from_kernel_allocation(
                    NonZeroU64::new(99).expect("mapping"),
                )],
                frame_inventory_revision: None,
            })
        }

        fn revision(&self) -> u64 {
            1
        }
    }

    /// A live carrier whose served graph violates an invariant must not turn
    /// into a bare refusal: `carrick debug hvpatch-kernel` is exactly the
    /// tool reached for mid-hang, and dropping the whole kernel graph on top
    /// of an already-known problem loses the investigation, not just the one
    /// row (this is the named `build_response` gap: a cpython
    /// `multiprocessing` process-pool hang carried a legitimate zombie
    /// process-group member, and the strict `InvariantViolation` branch
    /// answered with only an error string). The server must fall back to the
    /// never-refusing forensic capture and report the violation IN the
    /// projection instead of hiding the graph behind it.
    #[test]
    fn a_live_invariant_violation_still_serves_the_graph_with_findings() {
        let bootstrap = RootBootstrap::with_mm_backend(
            4345,
            carrick_hal::ThreadId::synthetic_for_tests(4345),
            Arc::new(DanglingMappingBackend),
            "invariant-root".to_owned(),
            Arc::new(carrick_hal::NullHostSignalBridge::default()),
        )
        .expect("root bootstrap input");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("root kernel");

        // Confirm the strict path really does refuse this graph, so the
        // fallback below is exercised for the reason this test claims.
        assert!(matches!(
            kernel.snapshot(Instant::now() + STRICT_SNAPSHOT_BUDGET),
            Err(super::super::super::KernelSnapshotError::InvariantViolation(_))
        ));

        let request = KernelDebugRequest::for_tables(None);
        let response = build_response(&request, &kernel, Instant::now());
        let snapshot = match response {
            ServerResponse::Snapshot(snapshot) => *snapshot,
            other => panic!(
                "a violated invariant must still serve the graph, not just refuse it: {other:?}"
            ),
        };
        assert_eq!(snapshot.schema, KERNEL_DEBUG_RESPONSE_SCHEMA);
        assert!(
            !snapshot.findings.is_empty(),
            "the violation must be reported in the projection, never silently hidden"
        );
        assert!(
            snapshot
                .findings
                .iter()
                .any(|finding| finding.contains("mapping")),
            "findings: {:?}",
            snapshot.findings
        );
        assert!(
            snapshot.tasks.as_ref().is_some_and(|tasks| tasks
                .iter()
                .any(|task| task.diagnostic_name.as_deref() == Some("invariant-root"))),
            "the graph itself must remain usable alongside the finding"
        );
    }
}
