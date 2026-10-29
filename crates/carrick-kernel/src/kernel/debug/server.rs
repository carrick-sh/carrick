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
use super::post_mortem::{AbortReason, PhysicalCaptureProvider, PostMortem};
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
        Self::start_with_physical(kernel, carrier_scope, None)
    }

    /// Bind the ordinary kernel endpoint with a backend-owned physical census.
    pub fn start_with_physical(
        kernel: Arc<Kernel>,
        carrier_scope: &str,
        physical: Option<Arc<dyn PhysicalCaptureProvider>>,
    ) -> Result<Self, ServerError> {
        Self::start_at(kernel, DebugEndpoint::for_run_id(carrier_scope)?, physical)
    }

    /// Bind and serve at an exact endpoint. Used by tests and by callers that
    /// already resolved the run identity.
    pub fn start_at(
        kernel: Arc<Kernel>,
        endpoint: DebugEndpoint,
        physical: Option<Arc<dyn PhysicalCaptureProvider>>,
    ) -> Result<Self, ServerError> {
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
        let carrier_scope = endpoint.run_id().to_owned();
        let thread_cancellation = Arc::clone(&cancellation);
        let join = std::thread::Builder::new()
            .name("carrick-kernel-debug".to_owned())
            .spawn(move || {
                serve_loop(
                    &listener,
                    &kernel,
                    physical,
                    &thread_shutdown,
                    &thread_cancellation,
                    &carrier_scope,
                );
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

    /// Start the carrier's server and return its owned lifetime handle.
    ///
    /// The carrier must retain the handle until retirement, then drop it before
    /// admitting a replacement carrier under the same cleanup scope. A host
    /// process can outlive many carriers; retaining a process-global server
    /// would keep serving a retired kernel and prevent the next bind.
    ///
    /// Default ON; `CARRICK_KERNEL_DEBUG=0` is the exact opt-out. A failure to
    /// publish the endpoint is reported and the run continues: the guest
    /// workload is the product, and losing the debugger must not lose the run.
    /// The failure is never silent.
    pub fn install(
        kernel: Arc<Kernel>,
        carrier_scope: &str,
        physical: Option<Arc<dyn PhysicalCaptureProvider>>,
    ) -> Option<Self> {
        if std::env::var_os(DISABLE_ENV).is_some_and(|value| value == "0") {
            return None;
        }
        match Self::start_with_physical(kernel, carrier_scope, physical) {
            Ok(server) => Some(server),
            Err(error) => {
                tracing::warn!(
                    target: "carrick::kernel::debug",
                    %error,
                    "kernel debug endpoint not published; `carrick debug hvpatch-kernel` is unavailable for this run"
                );
                None
            }
        }
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
    physical: Option<Arc<dyn PhysicalCaptureProvider>>,
    shutdown: &AtomicBool,
    cancellation: &Arc<Cancellation>,
    carrier_scope: &str,
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
        let physical = physical.clone();
        let carrier_scope = carrier_scope.to_owned();
        if let Ok(handler) = std::thread::Builder::new()
            .name("carrick-debug-conn".to_owned())
            .spawn(move || {
                // Permit drops last, after the socket and kernel context, also
                // on unwind or a failed spawn.
                let _permit = permit;
                let mut connection = connection;
                let kernel = kernel;
                let _ = handle_connection(
                    &mut connection,
                    &kernel,
                    physical.as_deref(),
                    &carrier_scope,
                );
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

fn handle_connection(
    stream: &mut Connection,
    kernel: &Arc<Kernel>,
    physical: Option<&dyn PhysicalCaptureProvider>,
    carrier_scope: &str,
) -> Result<(), WireError> {
    authenticate(stream)?;
    let payload = socket_rpc::read_frame(stream, MAX_REQUEST_BYTES)?;
    let request: KernelDebugRequest = wire::decode_exact(&payload)?;
    let mut response = build_response(&request, kernel, physical, carrier_scope, Instant::now());
    let encoded = encode_bounded_response(&mut response, MAX_RESPONSE_BYTES)?;
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
    physical: Option<&dyn PhysicalCaptureProvider>,
    carrier_scope: &str,
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
    if let super::dto::KernelDebugAction::Capture { .. } = &request.action {
        let mut capture = PostMortem::capture(
            Some(kernel),
            AbortReason::LiveCapture {
                run_id: carrier_scope.to_owned(),
            },
            Some(carrier_scope.to_owned()),
        );
        capture.physical = physical.map(PhysicalCaptureProvider::capture);
        return ServerResponse::Capture(Box::new(capture));
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
    Capture(Box<PostMortem>),
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

/// Headroom reserved when computing a target section budget so the added
/// truncation metadata (`truncated`, `unavailable`, `findings`) fits inside
/// the same pass.
const TRUNCATION_METADATA_MARGIN: usize = 1024;

/// Serialize `response` to canonical JSON within `cap` bytes, deterministically
/// bounding or truncating the largest ring/auxiliary payloads and recording the
/// truncation in `truncated` / `unavailable` / degraded metadata instead of
/// failing the frame writer with [`WireError::FrameTooLarge`].
///
/// If even the minimum response envelope cannot fit within `cap`, returns
/// [`WireError::FrameTooLarge`].
fn encode_bounded_response(
    response: &mut ServerResponse,
    cap: usize,
) -> Result<Vec<u8>, WireError> {
    let encoded = encode_canonical(response)?;
    if encoded.len() <= cap {
        return Ok(encoded);
    }
    match response {
        ServerResponse::Capture(capture) => bound_capture_response(capture, encoded, cap),
        ServerResponse::Snapshot(_) => bound_snapshot_response(response, encoded, cap),
        ServerResponse::Degraded(degraded) => bound_degraded_response(degraded, encoded, cap),
        ServerResponse::Aborting { .. } | ServerResponse::Error { .. } => {
            Err(WireError::FrameTooLarge {
                declared: encoded.len(),
                cap,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CaptureAuxSection {
    EventRingHighRate = 0,
    EventRing = 1,
    PhysicalHostThreads = 2,
    PhysicalZoneCensus = 3,
    PhysicalVcpus = 4,
    ZoneCensus = 5,
    SchedulerAuxExecutorReceipts = 6,
    SchedulerAuxRunQueue = 7,
    SchedulerAuxExecutors = 8,
    SchedulerAuxScheduler = 9,
    KernelExecutorReceipts = 10,
    KernelRunQueue = 11,
    KernelExecutors = 12,
    KernelSchedulerAux = 13,
}

impl CaptureAuxSection {
    const ALL: [Self; 14] = [
        Self::EventRingHighRate,
        Self::EventRing,
        Self::PhysicalHostThreads,
        Self::PhysicalZoneCensus,
        Self::PhysicalVcpus,
        Self::ZoneCensus,
        Self::SchedulerAuxExecutorReceipts,
        Self::SchedulerAuxRunQueue,
        Self::SchedulerAuxExecutors,
        Self::SchedulerAuxScheduler,
        Self::KernelExecutorReceipts,
        Self::KernelRunQueue,
        Self::KernelExecutors,
        Self::KernelSchedulerAux,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

fn reducible_vec_bytes<T: serde::Serialize>(rows: &[T]) -> usize {
    if rows.is_empty() {
        return 0;
    }
    encode_canonical(&rows).map_or(0, |bytes| bytes.len().saturating_sub(2))
}

fn reducible_str_bytes(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    encode_canonical(&text).map_or(0, |bytes| bytes.len().saturating_sub(2))
}

fn reducible_scheduler_aux_bytes(rows: &[super::dto::DebugSchedulerRow]) -> usize {
    let mut total = 0_usize;
    for row in rows {
        if let Some(residencies) = &row.residencies {
            total = total.saturating_add(encode_canonical(residencies).map_or(0, |b| b.len()));
        }
        if let Some(zone_held) = &row.zone_held {
            total = total.saturating_add(encode_canonical(zone_held).map_or(0, |b| b.len()));
        }
        if let Some(host_wait) = &row.host_wait {
            total = total.saturating_add(encode_canonical(host_wait).map_or(0, |b| b.len()));
        }
    }
    total
}

fn capture_section_reducible_bytes(capture: &PostMortem, section: CaptureAuxSection) -> usize {
    match section {
        CaptureAuxSection::EventRingHighRate => reducible_vec_bytes(&capture.event_ring_high_rate),
        CaptureAuxSection::EventRing => reducible_vec_bytes(&capture.event_ring),
        CaptureAuxSection::PhysicalHostThreads => capture
            .physical
            .as_ref()
            .map_or(0, |p| reducible_vec_bytes(&p.host_threads)),
        CaptureAuxSection::PhysicalZoneCensus => capture
            .physical
            .as_ref()
            .map_or(0, |p| reducible_str_bytes(&p.zone_census)),
        CaptureAuxSection::PhysicalVcpus => capture
            .physical
            .as_ref()
            .map_or(0, |p| reducible_vec_bytes(&p.vcpus)),
        CaptureAuxSection::ZoneCensus => capture
            .zone_census
            .as_deref()
            .map_or(0, reducible_str_bytes),
        CaptureAuxSection::SchedulerAuxExecutorReceipts => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| reducible_vec_bytes(&s.executor_receipts)),
        CaptureAuxSection::SchedulerAuxRunQueue => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| reducible_vec_bytes(&s.run_queue)),
        CaptureAuxSection::SchedulerAuxExecutors => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| reducible_vec_bytes(&s.executors)),
        CaptureAuxSection::SchedulerAuxScheduler => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| reducible_vec_bytes(&s.scheduler)),
        CaptureAuxSection::KernelExecutorReceipts => capture
            .kernel
            .as_ref()
            .and_then(|k| k.executor_receipts.as_deref())
            .map_or(0, reducible_vec_bytes),
        CaptureAuxSection::KernelRunQueue => capture
            .kernel
            .as_ref()
            .and_then(|k| k.run_queue.as_deref())
            .map_or(0, reducible_vec_bytes),
        CaptureAuxSection::KernelExecutors => capture
            .kernel
            .as_ref()
            .and_then(|k| k.executors.as_deref())
            .map_or(0, reducible_vec_bytes),
        CaptureAuxSection::KernelSchedulerAux => capture
            .kernel
            .as_ref()
            .and_then(|k| k.scheduler.as_deref())
            .map_or(0, reducible_scheduler_aux_bytes),
    }
}

fn capture_section_initial_count(capture: &PostMortem, section: CaptureAuxSection) -> usize {
    match section {
        CaptureAuxSection::EventRingHighRate => capture.event_ring_high_rate.len(),
        CaptureAuxSection::EventRing => capture.event_ring.len(),
        CaptureAuxSection::PhysicalHostThreads => capture
            .physical
            .as_ref()
            .map_or(0, |p| p.host_threads.len()),
        CaptureAuxSection::PhysicalZoneCensus => {
            capture.physical.as_ref().map_or(0, |p| p.zone_census.len())
        }
        CaptureAuxSection::PhysicalVcpus => capture.physical.as_ref().map_or(0, |p| p.vcpus.len()),
        CaptureAuxSection::ZoneCensus => capture.zone_census.as_ref().map_or(0, String::len),
        CaptureAuxSection::SchedulerAuxExecutorReceipts => {
            capture.scheduler_aux.as_ref().map_or(0, |s| {
                s.executor_receipt_summary
                    .as_ref()
                    .map_or(s.executor_receipts.len(), |sum| sum.total)
            })
        }
        CaptureAuxSection::SchedulerAuxRunQueue => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| s.run_queue.len()),
        CaptureAuxSection::SchedulerAuxExecutors => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| s.executors.len()),
        CaptureAuxSection::SchedulerAuxScheduler => capture
            .scheduler_aux
            .as_ref()
            .map_or(0, |s| s.scheduler.len()),
        CaptureAuxSection::KernelExecutorReceipts => capture.kernel.as_ref().map_or(0, |k| {
            k.executor_receipt_summary.as_ref().map_or_else(
                || k.executor_receipts.as_ref().map_or(0, Vec::len),
                |sum| sum.total,
            )
        }),
        CaptureAuxSection::KernelRunQueue => capture
            .kernel
            .as_ref()
            .and_then(|k| k.run_queue.as_ref())
            .map_or(0, Vec::len),
        CaptureAuxSection::KernelExecutors => capture
            .kernel
            .as_ref()
            .and_then(|k| k.executors.as_ref())
            .map_or(0, Vec::len),
        CaptureAuxSection::KernelSchedulerAux => 0,
    }
}

fn target_section_budget(current_encoded_len: usize, cap: usize, section_bytes: usize) -> usize {
    let excess = current_encoded_len.saturating_sub(cap);
    let needed = excess.saturating_add(TRUNCATION_METADATA_MARGIN);
    section_bytes.saturating_sub(needed)
}

fn proportional_keep_count(len: usize, target_bytes: usize, section_bytes: usize) -> usize {
    if len <= 1 || target_bytes == 0 || section_bytes == 0 {
        return 0;
    }
    let scaled = (len as u128).saturating_mul(target_bytes as u128) / (section_bytes as u128);
    usize::try_from(scaled)
        .unwrap_or(0)
        .min(len.saturating_sub(1))
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut boundary = index;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn upsert_truncated(
    truncated: &mut Vec<super::post_mortem::Truncated>,
    section: &str,
    reason: String,
) {
    if let Some(existing) = truncated.iter_mut().find(|entry| entry.section == section) {
        if existing.reason == reason {
            return;
        }
        if reason.contains("response cap") {
            if let Some((original, tail)) = existing.reason.rsplit_once("; ")
                && tail.contains("response cap")
            {
                existing.reason = format!("{original}; {reason}");
                return;
            }
            if existing.reason.contains("response cap") {
                existing.reason = reason;
                return;
            }
        }
        existing.reason = format!("{}; {reason}", existing.reason);
    } else {
        truncated.push(super::post_mortem::Truncated {
            section: section.to_owned(),
            reason,
        });
    }
}

fn upsert_prefixed_note(notes: &mut Vec<String>, prefix: &str, note: String) {
    if let Some(existing) = notes.iter_mut().find(|entry| entry.starts_with(prefix)) {
        *existing = note;
    } else {
        notes.push(note);
    }
}

fn truncate_tail_vec<T>(rows: &mut Vec<T>, target_bytes: usize, section_bytes: usize) -> usize {
    let before = rows.len();
    let keep = proportional_keep_count(before, target_bytes, section_bytes);
    rows.drain(..before.saturating_sub(keep));
    rows.len()
}

fn truncate_prefix_vec<T>(rows: &mut Vec<T>, target_bytes: usize, section_bytes: usize) -> usize {
    let before = rows.len();
    let keep = proportional_keep_count(before, target_bytes, section_bytes);
    rows.truncate(keep);
    rows.len()
}

fn update_receipt_summary(
    summary: &mut Option<super::dto::DebugExecutorReceiptSummary>,
    total: usize,
    kept: usize,
    cap: usize,
) {
    *summary = Some(super::dto::DebugExecutorReceiptSummary {
        total,
        returned: kept,
        message: format!(
            "showing last {kept} of {total} receipts (truncated to fit {cap}-byte response cap)"
        ),
    });
}

fn bound_capture_response(
    capture: &mut PostMortem,
    mut encoded: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, WireError> {
    let initial_aux_counts =
        CaptureAuxSection::ALL.map(|section| capture_section_initial_count(capture, section));
    let mut aux_bytes =
        CaptureAuxSection::ALL.map(|section| capture_section_reducible_bytes(capture, section));
    let mut kernel_non_aux_bytes = capture.kernel.as_ref().map_or(0, |snapshot| {
        let kernel_aux_bytes = aux_bytes[CaptureAuxSection::KernelExecutorReceipts.index()]
            .saturating_add(aux_bytes[CaptureAuxSection::KernelRunQueue.index()])
            .saturating_add(aux_bytes[CaptureAuxSection::KernelExecutors.index()])
            .saturating_add(aux_bytes[CaptureAuxSection::KernelSchedulerAux.index()]);
        encode_canonical(snapshot)
            .map_or(0, |bytes| bytes.len())
            .saturating_sub(kernel_aux_bytes)
    });
    let initial_findings_count = capture.findings.len();
    let mut initial_degraded_tasks = capture
        .degraded_kernel
        .as_ref()
        .map_or(0, |d| d.tasks.len());
    let mut initial_degraded_mms = capture
        .degraded_kernel
        .as_ref()
        .map_or(0, |d| d.mm_coordinators.len());

    while encoded.len() > cap {
        let largest = CaptureAuxSection::ALL
            .into_iter()
            .map(|section| (section, aux_bytes[section.index()]))
            .filter(|(_, bytes)| *bytes > 0)
            .max_by(|(a_sec, a_bytes), (b_sec, b_bytes)| {
                a_bytes.cmp(b_bytes).then_with(|| b_sec.cmp(a_sec))
            });
        let largest_aux_bytes = largest.map_or(0, |(_, bytes)| bytes);
        let should_degrade_kernel = capture.kernel.is_some()
            && (kernel_non_aux_bytes > cap || kernel_non_aux_bytes >= largest_aux_bytes);

        if should_degrade_kernel && let Some(snapshot) = capture.kernel.take() {
            kernel_non_aux_bytes = 0;
            aux_bytes[CaptureAuxSection::KernelExecutorReceipts.index()] = 0;
            aux_bytes[CaptureAuxSection::KernelRunQueue.index()] = 0;
            aux_bytes[CaptureAuxSection::KernelExecutors.index()] = 0;
            aux_bytes[CaptureAuxSection::KernelSchedulerAux.index()] = 0;
            let reason = format!(
                "kernel snapshot exceeded {cap}-byte wire response cap; degraded to task summary"
            );
            if capture.degraded_kernel.is_none() {
                let degraded = degrade_oversized_snapshot(&snapshot, cap);
                initial_degraded_tasks = degraded.tasks.len();
                initial_degraded_mms = degraded.mm_coordinators.len();
                capture.degraded_kernel = Some(degraded);
            } else if let Some(degraded) = &mut capture.degraded_kernel {
                upsert_prefixed_note(
                    &mut degraded.unreadable,
                    "kernel snapshot exceeded",
                    reason.clone(),
                );
            }
            upsert_truncated(&mut capture.truncated, "kernel", reason);
            encoded = encode_canonical(capture)?;
            continue;
        }

        if let Some((section, section_bytes)) = largest {
            let target_bytes = target_section_budget(encoded.len(), cap, section_bytes);
            let initial_total = initial_aux_counts[section.index()];
            truncate_capture_aux_section(
                capture,
                section,
                initial_total,
                target_bytes,
                section_bytes,
                cap,
            );
            aux_bytes[section.index()] = capture_section_reducible_bytes(capture, section);
            encoded = encode_canonical(capture)?;
            continue;
        }

        if let Some(degraded) = &mut capture.degraded_kernel
            && truncate_degraded_step(
                degraded,
                initial_degraded_tasks,
                initial_degraded_mms,
                encoded.len(),
                cap,
            )
        {
            upsert_truncated(
                &mut capture.truncated,
                "degraded_kernel",
                format!("degraded_kernel truncated to fit {cap}-byte response cap"),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        let findings_bytes = reducible_vec_bytes(&capture.findings);
        if findings_bytes > 0 {
            let target_bytes = target_section_budget(encoded.len(), cap, findings_bytes);
            let kept = truncate_prefix_vec(&mut capture.findings, target_bytes, findings_bytes);
            upsert_truncated(
                &mut capture.truncated,
                "findings",
                format!(
                    "retained {kept} of {initial_findings_count} findings to fit {cap}-byte response cap"
                ),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        if capture.physical.take().is_some() {
            upsert_truncated(
                &mut capture.truncated,
                "physical",
                format!("physical capture omitted to fit {cap}-byte response cap"),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        if capture.scheduler_aux.take().is_some() {
            upsert_truncated(
                &mut capture.truncated,
                "scheduler_aux",
                format!("scheduler_aux omitted to fit {cap}-byte response cap"),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        if capture.degraded_kernel.take().is_some() {
            upsert_truncated(
                &mut capture.truncated,
                "degraded_kernel",
                format!("degraded_kernel omitted to fit {cap}-byte response cap"),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        if capture.zone_census.take().is_some() {
            upsert_truncated(
                &mut capture.truncated,
                "zone_census",
                format!("zone_census omitted to fit {cap}-byte response cap"),
            );
            encoded = encode_canonical(capture)?;
            continue;
        }

        if capture.truncated.len() > 1 {
            capture.truncated = vec![super::post_mortem::Truncated {
                section: "post_mortem".to_owned(),
                reason: format!("truncated to minimum envelope to fit {cap}-byte response cap"),
            }];
            encoded = encode_canonical(capture)?;
            continue;
        }

        break;
    }

    if encoded.len() > cap {
        return Err(WireError::FrameTooLarge {
            declared: encoded.len(),
            cap,
        });
    }
    Ok(encoded)
}

fn truncate_capture_aux_section(
    capture: &mut PostMortem,
    section: CaptureAuxSection,
    initial_total: usize,
    target_bytes: usize,
    section_bytes: usize,
    cap: usize,
) {
    match section {
        CaptureAuxSection::EventRingHighRate => {
            let kept = truncate_tail_vec(
                &mut capture.event_ring_high_rate,
                target_bytes,
                section_bytes,
            );
            upsert_truncated(
                &mut capture.truncated,
                "event_ring_high_rate",
                format!(
                    "retained {kept} of {initial_total} records to fit {cap}-byte response cap"
                ),
            );
        }
        CaptureAuxSection::EventRing => {
            let kept = truncate_tail_vec(&mut capture.event_ring, target_bytes, section_bytes);
            upsert_truncated(
                &mut capture.truncated,
                "event_ring",
                format!(
                    "retained {kept} of {initial_total} records to fit {cap}-byte response cap"
                ),
            );
        }
        CaptureAuxSection::PhysicalHostThreads => {
            if let Some(physical) = &mut capture.physical {
                let kept =
                    truncate_prefix_vec(&mut physical.host_threads, target_bytes, section_bytes);
                let reason = format!(
                    "host_threads truncated (retained {kept} of {initial_total} entries to fit {cap}-byte response cap)"
                );
                upsert_prefixed_note(
                    &mut physical.unavailable,
                    "host_threads truncated",
                    reason.clone(),
                );
                upsert_truncated(&mut capture.truncated, "physical.host_threads", reason);
            }
        }
        CaptureAuxSection::PhysicalZoneCensus => {
            if let Some(physical) = &mut capture.physical {
                let before = physical.zone_census.len();
                let keep = floor_char_boundary(
                    &physical.zone_census,
                    proportional_keep_count(before, target_bytes, section_bytes),
                );
                physical.zone_census.truncate(keep);
                let reason = format!(
                    "zone_census truncated (retained {keep} of {initial_total} bytes to fit {cap}-byte response cap)"
                );
                upsert_prefixed_note(
                    &mut physical.unavailable,
                    "zone_census truncated",
                    reason.clone(),
                );
                upsert_truncated(&mut capture.truncated, "physical.zone_census", reason);
            }
        }
        CaptureAuxSection::PhysicalVcpus => {
            if let Some(physical) = &mut capture.physical {
                let kept = truncate_prefix_vec(&mut physical.vcpus, target_bytes, section_bytes);
                let reason = format!(
                    "vcpus truncated (retained {kept} of {initial_total} entries to fit {cap}-byte response cap)"
                );
                upsert_prefixed_note(&mut physical.unavailable, "vcpus truncated", reason.clone());
                upsert_truncated(&mut capture.truncated, "physical.vcpus", reason);
            }
        }
        CaptureAuxSection::ZoneCensus => {
            if let Some(census) = &mut capture.zone_census {
                let before = census.len();
                let keep = floor_char_boundary(
                    census,
                    proportional_keep_count(before, target_bytes, section_bytes),
                );
                if keep == 0 {
                    capture.zone_census = None;
                } else {
                    census.truncate(keep);
                }
                upsert_truncated(
                    &mut capture.truncated,
                    "zone_census",
                    format!(
                        "retained {keep} of {initial_total} bytes to fit {cap}-byte response cap"
                    ),
                );
            }
        }
        CaptureAuxSection::SchedulerAuxExecutorReceipts => {
            if let Some(aux) = &mut capture.scheduler_aux {
                let kept =
                    truncate_tail_vec(&mut aux.executor_receipts, target_bytes, section_bytes);
                update_receipt_summary(&mut aux.executor_receipt_summary, initial_total, kept, cap);
                upsert_truncated(
                    &mut capture.truncated,
                    "executor_receipts",
                    format!(
                        "retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                    ),
                );
            }
        }
        CaptureAuxSection::SchedulerAuxRunQueue => {
            if let Some(aux) = &mut capture.scheduler_aux {
                let kept = truncate_prefix_vec(&mut aux.run_queue, target_bytes, section_bytes);
                upsert_truncated(
                    &mut capture.truncated,
                    "run_queue",
                    format!(
                        "retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                    ),
                );
            }
        }
        CaptureAuxSection::SchedulerAuxExecutors => {
            if let Some(aux) = &mut capture.scheduler_aux {
                let kept = truncate_prefix_vec(&mut aux.executors, target_bytes, section_bytes);
                upsert_truncated(
                    &mut capture.truncated,
                    "executors",
                    format!(
                        "retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                    ),
                );
            }
        }
        CaptureAuxSection::SchedulerAuxScheduler => {
            if let Some(aux) = &mut capture.scheduler_aux {
                let kept = truncate_prefix_vec(&mut aux.scheduler, target_bytes, section_bytes);
                upsert_truncated(
                    &mut capture.truncated,
                    "scheduler",
                    format!(
                        "retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                    ),
                );
            }
        }
        CaptureAuxSection::KernelExecutorReceipts => {
            if let Some(kernel) = &mut capture.kernel
                && let Some(rows) = &mut kernel.executor_receipts
            {
                let kept = truncate_tail_vec(rows, target_bytes, section_bytes);
                update_receipt_summary(
                    &mut kernel.executor_receipt_summary,
                    initial_total,
                    kept,
                    cap,
                );
                let note = format!(
                    "executor_receipts truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                );
                upsert_prefixed_note(
                    &mut kernel.findings,
                    "executor_receipts truncated:",
                    note.clone(),
                );
                upsert_truncated(&mut capture.truncated, "kernel.executor_receipts", note);
            }
        }
        CaptureAuxSection::KernelRunQueue => {
            if let Some(kernel) = &mut capture.kernel
                && let Some(rows) = &mut kernel.run_queue
            {
                let kept = truncate_prefix_vec(rows, target_bytes, section_bytes);
                let note = format!(
                    "run_queue truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                );
                upsert_prefixed_note(&mut kernel.findings, "run_queue truncated:", note.clone());
                upsert_truncated(&mut capture.truncated, "kernel.run_queue", note);
            }
        }
        CaptureAuxSection::KernelExecutors => {
            if let Some(kernel) = &mut capture.kernel
                && let Some(rows) = &mut kernel.executors
            {
                let kept = truncate_prefix_vec(rows, target_bytes, section_bytes);
                let note = format!(
                    "executors truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                );
                upsert_prefixed_note(&mut kernel.findings, "executors truncated:", note.clone());
                upsert_truncated(&mut capture.truncated, "kernel.executors", note);
            }
        }
        CaptureAuxSection::KernelSchedulerAux => {
            if let Some(kernel) = &mut capture.kernel
                && let Some(rows) = &mut kernel.scheduler
            {
                for row in rows {
                    row.residencies = None;
                    row.zone_held = None;
                    row.host_wait = None;
                }
                let note =
                    format!("scheduler auxiliary censuses omitted to fit {cap}-byte response cap");
                upsert_prefixed_note(
                    &mut kernel.findings,
                    "scheduler auxiliary censuses omitted",
                    note.clone(),
                );
                upsert_truncated(&mut capture.truncated, "kernel.scheduler", note);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SnapshotAuxSection {
    ExecutorReceipts = 0,
    RunQueue = 1,
    Executors = 2,
    SchedulerAux = 3,
}

impl SnapshotAuxSection {
    const ALL: [Self; 4] = [
        Self::ExecutorReceipts,
        Self::RunQueue,
        Self::Executors,
        Self::SchedulerAux,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

fn snapshot_section_reducible_bytes(
    snapshot: &KernelDebugSnapshot,
    section: SnapshotAuxSection,
) -> usize {
    match section {
        SnapshotAuxSection::ExecutorReceipts => snapshot
            .executor_receipts
            .as_deref()
            .map_or(0, reducible_vec_bytes),
        SnapshotAuxSection::RunQueue => {
            snapshot.run_queue.as_deref().map_or(0, reducible_vec_bytes)
        }
        SnapshotAuxSection::Executors => {
            snapshot.executors.as_deref().map_or(0, reducible_vec_bytes)
        }
        SnapshotAuxSection::SchedulerAux => snapshot
            .scheduler
            .as_deref()
            .map_or(0, reducible_scheduler_aux_bytes),
    }
}

fn snapshot_section_initial_count(
    snapshot: &KernelDebugSnapshot,
    section: SnapshotAuxSection,
) -> usize {
    match section {
        SnapshotAuxSection::ExecutorReceipts => {
            snapshot.executor_receipt_summary.as_ref().map_or_else(
                || snapshot.executor_receipts.as_ref().map_or(0, Vec::len),
                |sum| sum.total,
            )
        }
        SnapshotAuxSection::RunQueue => snapshot.run_queue.as_ref().map_or(0, Vec::len),
        SnapshotAuxSection::Executors => snapshot.executors.as_ref().map_or(0, Vec::len),
        SnapshotAuxSection::SchedulerAux => 0,
    }
}

fn bound_snapshot_response(
    response: &mut ServerResponse,
    mut encoded: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, WireError> {
    let (initial_counts, mut aux_bytes, kernel_non_aux_bytes) = match response {
        ServerResponse::Snapshot(snapshot) => {
            let counts = SnapshotAuxSection::ALL
                .map(|section| snapshot_section_initial_count(snapshot, section));
            let aux = SnapshotAuxSection::ALL
                .map(|section| snapshot_section_reducible_bytes(snapshot, section));
            let aux_total: usize = aux.iter().sum();
            (counts, aux, encoded.len().saturating_sub(aux_total))
        }
        _ => ([0; 4], [0; 4], 0),
    };

    while encoded.len() > cap {
        let ServerResponse::Snapshot(snapshot) = response else {
            break;
        };
        let largest = SnapshotAuxSection::ALL
            .into_iter()
            .map(|section| (section, aux_bytes[section.index()]))
            .filter(|(_, bytes)| *bytes > 0)
            .max_by(|(a_sec, a_bytes), (b_sec, b_bytes)| {
                a_bytes.cmp(b_bytes).then_with(|| b_sec.cmp(a_sec))
            });
        let largest_aux_bytes = largest.map_or(0, |(_, bytes)| bytes);
        let should_degrade_kernel =
            kernel_non_aux_bytes > cap || kernel_non_aux_bytes >= largest_aux_bytes;

        if !should_degrade_kernel && let Some((section, section_bytes)) = largest {
            let target_bytes = target_section_budget(encoded.len(), cap, section_bytes);
            let initial_total = initial_counts[section.index()];
            match section {
                SnapshotAuxSection::ExecutorReceipts => {
                    if let Some(rows) = &mut snapshot.executor_receipts {
                        let kept = truncate_tail_vec(rows, target_bytes, section_bytes);
                        update_receipt_summary(
                            &mut snapshot.executor_receipt_summary,
                            initial_total,
                            kept,
                            cap,
                        );
                        upsert_prefixed_note(
                            &mut snapshot.findings,
                            "executor_receipts truncated:",
                            format!(
                                "executor_receipts truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                            ),
                        );
                    }
                }
                SnapshotAuxSection::RunQueue => {
                    if let Some(rows) = &mut snapshot.run_queue {
                        let kept = truncate_prefix_vec(rows, target_bytes, section_bytes);
                        upsert_prefixed_note(
                            &mut snapshot.findings,
                            "run_queue truncated:",
                            format!(
                                "run_queue truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                            ),
                        );
                    }
                }
                SnapshotAuxSection::Executors => {
                    if let Some(rows) = &mut snapshot.executors {
                        let kept = truncate_prefix_vec(rows, target_bytes, section_bytes);
                        upsert_prefixed_note(
                            &mut snapshot.findings,
                            "executors truncated:",
                            format!(
                                "executors truncated: retained {kept} of {initial_total} rows to fit {cap}-byte response cap"
                            ),
                        );
                    }
                }
                SnapshotAuxSection::SchedulerAux => {
                    if let Some(rows) = &mut snapshot.scheduler {
                        for row in rows {
                            row.residencies = None;
                            row.zone_held = None;
                            row.host_wait = None;
                        }
                        upsert_prefixed_note(
                            &mut snapshot.findings,
                            "scheduler auxiliary censuses omitted",
                            format!(
                                "scheduler auxiliary censuses omitted to fit {cap}-byte response cap"
                            ),
                        );
                    }
                }
            }
            aux_bytes[section.index()] = snapshot_section_reducible_bytes(snapshot, section);
            encoded = encode_canonical(&**snapshot)?;
            continue;
        }

        // Core coherent tables account for the excess (or exceed the largest
        // auxiliary section); degrade to the per-task summary view rather than
        // failing with FrameTooLarge or emptying smaller auxiliary sections
        // first.
        let mut degraded = Box::new(degrade_oversized_snapshot(snapshot, cap));
        let degraded_encoded = encode_canonical(&*degraded)?;
        let bounded = bound_degraded_response(&mut degraded, degraded_encoded, cap)?;
        *response = ServerResponse::Degraded(degraded);
        return Ok(bounded);
    }

    if encoded.len() > cap {
        return Err(WireError::FrameTooLarge {
            declared: encoded.len(),
            cap,
        });
    }
    Ok(encoded)
}

fn degrade_oversized_snapshot(snapshot: &KernelDebugSnapshot, cap: usize) -> KernelDebugDegraded {
    let reason = format!(
        "coherent kernel snapshot exceeded {cap}-byte wire response cap; degraded to task summary"
    );
    let tasks = snapshot
        .tasks
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|task| {
            let threads = snapshot.threads.as_ref().map(|all_threads| {
                all_threads
                    .iter()
                    .filter(|thread| thread.task == task.key)
                    .map(|thread| super::dto::DegradedThreadDto {
                        key: thread.key,
                        execution: Some(thread.execution.clone()),
                    })
                    .collect()
            });
            super::dto::DegradedTaskDto {
                key: task.key,
                diagnostic_name: task.diagnostic_name.clone().unwrap_or_default(),
                lifecycle: Some(task.lifecycle.clone()),
                mm: task.mm,
                threads,
            }
        })
        .collect();
    KernelDebugDegraded {
        schema: super::dto::KERNEL_DEBUG_DEGRADED_SCHEMA.to_owned(),
        strict_error: reason.clone(),
        tasks,
        mm_coordinators: Vec::new(),
        unreadable: vec![reason],
    }
}

fn truncate_degraded_step(
    degraded: &mut KernelDebugDegraded,
    initial_tasks: usize,
    initial_mms: usize,
    current_encoded_len: usize,
    cap: usize,
) -> bool {
    let tasks_bytes = reducible_vec_bytes(&degraded.tasks);
    let mm_bytes = reducible_vec_bytes(&degraded.mm_coordinators);
    if tasks_bytes == 0 && mm_bytes == 0 {
        return false;
    }
    if tasks_bytes >= mm_bytes {
        let target_bytes = target_section_budget(current_encoded_len, cap, tasks_bytes);
        let kept = truncate_prefix_vec(&mut degraded.tasks, target_bytes, tasks_bytes);
        upsert_prefixed_note(
            &mut degraded.unreadable,
            "tasks truncated",
            format!(
                "tasks truncated (retained {kept} of {initial_tasks} rows to fit {cap}-byte response cap)"
            ),
        );
    } else {
        let target_bytes = target_section_budget(current_encoded_len, cap, mm_bytes);
        let kept = truncate_prefix_vec(&mut degraded.mm_coordinators, target_bytes, mm_bytes);
        upsert_prefixed_note(
            &mut degraded.unreadable,
            "mm_coordinators truncated",
            format!(
                "mm_coordinators truncated (retained {kept} of {initial_mms} rows to fit {cap}-byte response cap)"
            ),
        );
    }
    true
}

fn bound_degraded_response(
    degraded: &mut KernelDebugDegraded,
    mut encoded: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, WireError> {
    let initial_tasks = degraded.tasks.len();
    let initial_mms = degraded.mm_coordinators.len();
    while encoded.len() > cap {
        if truncate_degraded_step(degraded, initial_tasks, initial_mms, encoded.len(), cap) {
            encoded = encode_canonical(degraded)?;
            continue;
        }
        if degraded.unreadable.len() > 1 {
            degraded.unreadable = vec![degraded.strict_error.clone()];
            encoded = encode_canonical(degraded)?;
            continue;
        }
        break;
    }
    if encoded.len() > cap {
        return Err(WireError::FrameTooLarge {
            declared: encoded.len(),
            cap,
        });
    }
    Ok(encoded)
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

    fn request_capture_at(endpoint: &DebugEndpoint, run_id: &str) -> PostMortem {
        let mut stream = UnixStream::connect(endpoint.socket_path()).expect("connect debug socket");
        let request =
            encode_canonical(&KernelDebugRequest::capture(run_id)).expect("encode capture request");
        socket_rpc::write_frame(&mut stream, &request, MAX_REQUEST_BYTES)
            .expect("write capture request");
        let payload = socket_rpc::read_frame(&mut stream, MAX_RESPONSE_BYTES)
            .expect("read bounded capture response");
        wire::decode_exact(&payload).expect("decode PostMortem")
    }

    #[test]
    fn installed_server_retires_with_its_owner_before_scope_reuse() {
        let scope = format!("debug-owned-{}", std::process::id());
        for pid in [4242, 4343] {
            let bootstrap = RootBootstrap::for_reference_model(
                pid,
                carrick_hal::ThreadId::synthetic_for_tests(pid),
                format!("owned-root-{pid}"),
            )
            .expect("bootstrap");
            let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
            {
                let _server = KernelDebugServer::install(kernel, &scope, None)
                    .expect("debug server must be installed before connecting");
                let endpoint = DebugEndpoint::for_run_id(&scope).expect("endpoint");
                UnixStream::connect(endpoint.socket_path()).expect("installed listener");
            }
            assert!(matches!(
                super::super::client::fetch(&scope, None),
                Err(super::super::client::ClientError::NotListening { .. })
            ));
        }
    }

    #[test]
    fn capture_with_held_registry_fits_client_deadline_and_reports_degradation() {
        let bootstrap = RootBootstrap::for_reference_model(
            437,
            carrick_hal::ThreadId::synthetic_for_tests(437),
            "registry-held".to_owned(),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let _held = kernel.registry().settled().write();
        let request = KernelDebugRequest::capture("untrusted-wire-id");
        let started = Instant::now();
        let response = build_response(&request, &kernel, None, "carrier-owned-id", started);
        let encoded = encode_canonical(&response).expect("encode post-mortem");
        assert!(
            started.elapsed() < wire::DEADLINE,
            "capture outlasted the client's two-second deadline"
        );
        let capture: PostMortem = wire::decode_exact(&encoded).expect("post-mortem");
        assert_eq!(capture.run_id.as_deref(), Some("carrier-owned-id"));
        assert!(matches!(
            capture.reason,
            AbortReason::LiveCapture { ref run_id } if run_id == "carrier-owned-id"
        ));
        assert!(capture.kernel.is_none());
        assert!(capture.degraded_kernel.is_some());
        assert!(
            capture
                .degraded_kernel
                .as_ref()
                .is_some_and(|view| view.unreadable.iter().any(|row| row == "task registry"))
        );
    }

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
        let mut server =
            KernelDebugServer::start_at(kernel, endpoint.clone(), None).expect("server");
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
            let root =
                crate::kernel::Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa::new(0x1000))
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
        let response = build_response(&request, &kernel, None, "invariant-root", Instant::now());
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

    struct UnderLimitPhysicalCaptureProvider;

    impl PhysicalCaptureProvider for UnderLimitPhysicalCaptureProvider {
        fn capture(&self) -> super::super::post_mortem::PhysicalCapture {
            super::super::post_mortem::PhysicalCapture {
                zone_census: "cpl0-zone: cpu0=idle cpu1=parked".to_owned(),
                vcpus: vec![
                    "vcpu0 rip=0xffffffff81000000".to_owned(),
                    "vcpu1 rip=0xffffffff81000010".to_owned(),
                ],
                host_threads: vec![
                    "tid=0 stack=frame0".to_owned(),
                    "tid=1 stack=frame1".to_owned(),
                ],
                unavailable: Vec::new(),
            }
        }
    }

    #[test]
    fn under_limit_capture_is_returned_unchanged() {
        let (_temp, endpoint) =
            super::super::endpoint::tests::scoped_endpoint("debug-under-limit-capture");
        let bootstrap = RootBootstrap::with_mm_backend(
            4399,
            carrick_hal::ThreadId::synthetic_for_tests(4399),
            Arc::new(DanglingMappingBackend),
            "under-limit-capture-root".to_owned(),
            Arc::new(carrick_hal::NullHostSignalBridge::default()),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let physical: Arc<dyn PhysicalCaptureProvider> =
            Arc::new(UnderLimitPhysicalCaptureProvider);
        let mut server =
            KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone(), Some(physical))
                .expect("debug server");

        let capture = request_capture_at(&endpoint, "debug-under-limit-capture");
        let encoded = encode_canonical(&capture).expect("encode capture");
        assert!(encoded.len() < MAX_RESPONSE_BYTES);
        assert!(
            capture.truncated.is_empty(),
            "under-limit capture must not record truncation: {:?}",
            capture.truncated
        );
        let physical = capture
            .physical
            .as_ref()
            .expect("physical capture retained");
        assert_eq!(physical.zone_census, "cpl0-zone: cpu0=idle cpu1=parked");
        assert_eq!(physical.vcpus.len(), 2);
        assert_eq!(physical.host_threads.len(), 2);
        assert!(physical.unavailable.is_empty());
        assert!(capture.kernel.is_some());

        // Direct unit check on `encode_bounded_response`: an under-limit capture
        // is returned byte-for-byte identical without mutating any field.
        let mut response = ServerResponse::Capture(Box::new(capture));
        let bounded =
            encode_bounded_response(&mut response, MAX_RESPONSE_BYTES).expect("bounded encode");
        assert_eq!(bounded, encoded);

        server.shutdown();
    }

    struct OversizedPhysicalCaptureProvider;

    impl PhysicalCaptureProvider for OversizedPhysicalCaptureProvider {
        fn capture(&self) -> super::super::post_mortem::PhysicalCapture {
            // 18 MiB across 36 host thread stack entries (> MAX_RESPONSE_BYTES = 16 MiB),
            // while vcpus and zone_census stay small and should be preserved when
            // the largest section (host_threads) is truncated.
            let chunk = "k".repeat(512 * 1024);
            super::super::post_mortem::PhysicalCapture {
                zone_census: "cpl0-zone: cpu0=idle cpu1=parked".to_owned(),
                vcpus: vec![
                    "vcpu0 rip=0xffffffff81000000".to_owned(),
                    "vcpu1 rip=0xffffffff81000010".to_owned(),
                ],
                host_threads: (0..36)
                    .map(|index| format!("tid={index} stack={chunk}"))
                    .collect(),
                unavailable: Vec::new(),
            }
        }
    }

    #[test]
    fn oversized_live_capture_truncates_largest_auxiliary_payload_instead_of_failing_frame_too_large()
     {
        let (_temp, endpoint) =
            super::super::endpoint::tests::scoped_endpoint("debug-oversized-capture");
        let bootstrap = RootBootstrap::with_mm_backend(
            4400,
            carrick_hal::ThreadId::synthetic_for_tests(4400),
            Arc::new(DanglingMappingBackend),
            "oversized-capture-root".to_owned(),
            Arc::new(carrick_hal::NullHostSignalBridge::default()),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let physical: Arc<dyn PhysicalCaptureProvider> = Arc::new(OversizedPhysicalCaptureProvider);
        let mut server = KernelDebugServer::start_at(kernel, endpoint.clone(), Some(physical))
            .expect("debug server");

        let capture = request_capture_at(&endpoint, "debug-oversized-capture");

        let encoded = encode_canonical(&capture).expect("re-encode capture");
        assert!(
            encoded.len() <= MAX_RESPONSE_BYTES,
            "encoded capture {} exceeds MAX_RESPONSE_BYTES {}",
            encoded.len(),
            MAX_RESPONSE_BYTES
        );
        assert!(
            capture
                .truncated
                .iter()
                .any(|entry| entry.section == "physical.host_threads"
                    && entry.reason.contains("of 36 entries")),
            "truncation must be recorded in post_mortem.truncated with original total: {:?}",
            capture.truncated
        );
        let physical = capture.physical.expect("physical capture retained");
        assert!(
            physical.host_threads.len() < 36,
            "largest payload (host_threads) must be truncated"
        );
        assert!(
            physical.host_threads.len() > (36 * 4) / 5,
            "18 MiB section against 16 MiB cap must keep >80% of rows (got {} of 36)",
            physical.host_threads.len()
        );
        assert!(
            physical
                .unavailable
                .iter()
                .any(|reason| reason.contains("host_threads") && reason.contains("of 36 entries")),
            "truncation must be recorded in physical.unavailable: {:?}",
            physical.unavailable
        );
        // Smaller sibling sections must survive intact.
        assert_eq!(physical.vcpus.len(), 2);
        assert_eq!(physical.zone_census, "cpl0-zone: cpu0=idle cpu1=parked");
        assert!(
            capture.kernel.is_some(),
            "kernel snapshot must survive when truncating physical.host_threads fits the cap"
        );

        server.shutdown();
    }

    #[test]
    fn oversized_event_ring_retains_newest_records_and_refuses_when_minimum_cannot_fit() {
        let mut capture = PostMortem::capture(
            None,
            AbortReason::LiveCapture {
                run_id: "ring-truncation-test".to_owned(),
            },
            Some("ring-truncation-test".to_owned()),
        );
        capture.truncated.clear();
        capture.event_ring = (0..200_u64)
            .map(|idx| super::super::post_mortem::EventRingRecord {
                logical_index: idx,
                kind: Some(1),
                a: Some(10),
                b: Some(20),
                c: Some(30),
                unreadable: None,
            })
            .collect();
        capture.event_ring_high_rate = (0..400_u64)
            .map(|idx| super::super::post_mortem::EventRingRecord {
                logical_index: idx,
                kind: Some(2),
                a: Some(1),
                b: Some(2),
                c: Some(3),
                unreadable: None,
            })
            .collect();

        let full_encoded = encode_canonical(&capture).expect("encode full capture");
        let target_cap = full_encoded.len() / 2;
        let mut response = ServerResponse::Capture(Box::new(capture.clone()));
        let bounded =
            encode_bounded_response(&mut response, target_cap).expect("fit within target_cap");
        assert!(bounded.len() <= target_cap);
        let decoded: PostMortem = wire::decode_exact(&bounded).expect("decode bounded capture");
        assert!(
            decoded
                .truncated
                .iter()
                .any(|entry| entry.section == "event_ring_high_rate"
                    && entry.reason.contains("of 400 records")),
            "largest ring section (event_ring_high_rate) must be truncated first: {:?}",
            decoded.truncated
        );
        if !decoded.event_ring_high_rate.is_empty() {
            assert_eq!(
                decoded.event_ring_high_rate.last().map(|r| r.logical_index),
                Some(399),
                "tail (newest) ring records must be retained"
            );
        }

        // Deterministic repeatability: running the same input produces identical bytes.
        let mut second_response = ServerResponse::Capture(Box::new(capture.clone()));
        let second_bounded =
            encode_bounded_response(&mut second_response, target_cap).expect("second bounded");
        assert_eq!(bounded, second_bounded);

        // Pre-existing capture-time truncation reasons (e.g. `bounded_rows` on
        // `executor_receipts`) must be preserved alongside the wire-cap reason
        // instead of overwritten.
        let mut with_existing_note = capture.clone();
        with_existing_note.event_ring.clear();
        with_existing_note.event_ring_high_rate.clear();
        with_existing_note.scheduler_aux = Some(super::super::post_mortem::SchedulerAuxCapture {
            scheduler: Vec::new(),
            run_queue: Vec::new(),
            executors: Vec::new(),
            executor_receipts: (0..200_u64)
                .map(|seq| super::super::dto::DebugExecutorReceiptRow {
                    sequence: seq + 1,
                    executor: 1,
                    event: "Dispatched".to_owned(),
                    thread: None,
                    generation: Some(1),
                    observed_state: Some("runnable".to_owned()),
                    reason: Some("r".repeat(256)),
                })
                .collect(),
            executor_receipt_summary: Some(super::super::dto::DebugExecutorReceiptSummary {
                total: 1500,
                returned: 200,
                message: "showing last 200 of 1500 receipts".to_owned(),
            }),
        });
        with_existing_note.truncated = vec![super::super::post_mortem::Truncated {
            section: "executor_receipts".to_owned(),
            reason: "1500 rows exceed the 1024-row capture limit".to_owned(),
        }];
        let aux_full = encode_canonical(&with_existing_note).expect("encode aux capture");
        let aux_cap = (aux_full.len() * 9) / 10;
        let mut aux_response = ServerResponse::Capture(Box::new(with_existing_note));
        let aux_bounded =
            encode_bounded_response(&mut aux_response, aux_cap).expect("bound aux capture");
        let aux_decoded: PostMortem = wire::decode_exact(&aux_bounded).expect("decode aux capture");
        let receipt_truncation = aux_decoded
            .truncated
            .iter()
            .find(|entry| entry.section == "executor_receipts")
            .expect("executor_receipts truncation entry");
        assert!(
            receipt_truncation
                .reason
                .contains("1500 rows exceed the 1024-row capture limit"),
            "capture-time reason must be preserved: {:?}",
            receipt_truncation.reason
        );
        assert!(
            receipt_truncation.reason.contains("of 1500 rows to fit"),
            "wire-cap reason must be added alongside original reason: {:?}",
            receipt_truncation.reason
        );

        // When cap is smaller than even the minimum PostMortem envelope, a typed
        // WireError::FrameTooLarge error is returned.
        let mut unachievable = ServerResponse::Capture(Box::new(capture));
        let err = encode_bounded_response(&mut unachievable, 64)
            .expect_err("cap smaller than minimum envelope must fail with FrameTooLarge");
        assert!(
            matches!(err, WireError::FrameTooLarge { declared, cap: 64 } if declared > 64),
            "expected WireError::FrameTooLarge, got {err:?}"
        );
    }

    struct OversizedReceiptAuxProvider;

    impl super::super::dto::KernelDebugAuxProvider for OversizedReceiptAuxProvider {
        fn scheduler_rows(&self) -> Vec<super::super::dto::DebugSchedulerRow> {
            vec![super::super::dto::DebugSchedulerRow {
                host_wait: None,
                lifecycle: "open".to_owned(),
                queued_len: 0,
                claimed: 0,
                waiters: Some(0),
                run_queue_locked: false,
                control_epoch: 1,
                need_resched: false,
                snapshot_count: 1,
                residencies: None,
                host_queued: Some(0),
                zone_held: None,
            }]
        }

        fn run_queue_rows(&self) -> Vec<super::super::dto::DebugRunQueueRow> {
            Vec::new()
        }

        fn executor_rows(&self) -> Vec<super::super::dto::DebugExecutorRow> {
            Vec::new()
        }

        fn executor_receipt_rows(
            &self,
        ) -> (
            Vec<super::super::dto::DebugExecutorReceiptRow>,
            Option<super::super::dto::DebugExecutorReceiptSummary>,
        ) {
            let reason = "r".repeat(64 * 1024);
            let total = 300;
            let rows = (0..total)
                .map(|seq| super::super::dto::DebugExecutorReceiptRow {
                    sequence: (seq + 1) as u64,
                    executor: 1,
                    event: "Dispatched".to_owned(),
                    thread: None,
                    generation: Some(1),
                    observed_state: Some("runnable".to_owned()),
                    reason: Some(reason.clone()),
                })
                .collect();
            (
                rows,
                Some(super::super::dto::DebugExecutorReceiptSummary {
                    total,
                    returned: total,
                    message: format!("showing last {total} of {total} receipts"),
                }),
            )
        }
    }

    #[test]
    fn oversized_snapshot_truncates_auxiliary_receipts_and_remains_valid() {
        let (_temp, endpoint) =
            super::super::endpoint::tests::scoped_endpoint("debug-oversized-snapshot");
        let bootstrap = RootBootstrap::with_mm_backend(
            4401,
            carrick_hal::ThreadId::synthetic_for_tests(4401),
            Arc::new(DanglingMappingBackend),
            "oversized-snapshot-root".to_owned(),
            Arc::new(carrick_hal::NullHostSignalBridge::default()),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let aux: Arc<dyn super::super::dto::KernelDebugAuxProvider> =
            Arc::new(OversizedReceiptAuxProvider);
        kernel
            .register_debug_aux_provider(&aux)
            .expect("register aux provider");
        let mut server =
            KernelDebugServer::start_at(kernel, endpoint.clone(), None).expect("debug server");

        let snapshot = super::super::client::fetch_at_with_wait(
            &endpoint,
            None,
            super::super::client::ResponseWait::Completion,
        )
        .expect("oversized snapshot must truncate auxiliary receipts and remain valid");

        let encoded = encode_canonical(&snapshot).expect("re-encode snapshot");
        assert!(
            encoded.len() <= MAX_RESPONSE_BYTES,
            "encoded snapshot {} exceeds MAX_RESPONSE_BYTES {}",
            encoded.len(),
            MAX_RESPONSE_BYTES
        );
        let receipts = snapshot
            .executor_receipts
            .as_ref()
            .expect("receipts table present");
        assert!(receipts.len() < 300, "receipts must be truncated");
        assert!(
            receipts.len() > (300 * 4) / 5,
            "receipts slightly over cap must keep >80% of rows (got {} of 300)",
            receipts.len()
        );
        assert_eq!(
            receipts.last().map(|row| row.sequence),
            Some(300),
            "newest receipts must be retained"
        );
        let summary = snapshot
            .executor_receipt_summary
            .as_ref()
            .expect("summary present");
        assert_eq!(summary.total, 300);
        assert_eq!(summary.returned, receipts.len());
        assert!(
            snapshot
                .findings
                .iter()
                .any(|finding| finding.contains("executor_receipts")),
            "findings must record the truncation: {:?}",
            snapshot.findings
        );

        server.shutdown();
    }

    #[derive(Debug)]
    struct OversizedVmaBackend;

    impl MmBackend for OversizedVmaBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            let root =
                crate::kernel::Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa::new(0x1000))
                    .expect("aligned stage-1 root");
            let asid = Asid::from_registry_allocation(
                std::num::NonZeroU16::new(1).expect("nonzero test ASID"),
            );
            let vmas = (0..420_000_u64)
                .map(|index| {
                    let start = 0x1000_0000 + index * 0x2000;
                    crate::kernel::VmaSummary {
                        start: carrick_guest_mem::GuestVa::new(start),
                        end: carrick_guest_mem::GuestVa::new(start + 0x1000),
                        access: crate::kernel::VmaAccess {
                            readable: true,
                            writable: true,
                            executable: false,
                            kernel_visible: true,
                        },
                    }
                })
                .collect();
            Ok(MmBackendSnapshot {
                revision: 1,
                binding: crate::kernel::MmBinding {
                    asid,
                    stage1_root: root,
                    ttbr0: crate::kernel::Ttbr0::for_aarch64(asid, root),
                },
                vmas,
                vma_revision: None,
                mapping_ids: Vec::new(),
                frame_inventory_revision: None,
            })
        }

        fn revision(&self) -> u64 {
            1
        }
    }

    #[test]
    fn oversized_core_snapshot_degrades_with_metadata_instead_of_failing_frame_too_large() {
        crate::event_ring::rec(crate::event_ring::FORK, 4402, 1, 0);
        crate::event_ring::rec(crate::event_ring::SCHED_DISPATCH, 4402, 1, 0);
        let (_temp, endpoint) =
            super::super::endpoint::tests::scoped_endpoint("debug-oversized-core");
        let bootstrap = RootBootstrap::with_mm_backend(
            4402,
            carrick_hal::ThreadId::synthetic_for_tests(4402),
            Arc::new(OversizedVmaBackend),
            "oversized-vma-root".to_owned(),
            Arc::new(carrick_hal::NullHostSignalBridge::default()),
        )
        .expect("bootstrap");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("kernel");
        let physical: Arc<dyn PhysicalCaptureProvider> =
            Arc::new(UnderLimitPhysicalCaptureProvider);
        let mut server = KernelDebugServer::start_at(kernel, endpoint.clone(), Some(physical))
            .expect("debug server");

        let degraded = match super::super::client::fetch_at_with_wait(
            &endpoint,
            None,
            super::super::client::ResponseWait::Completion,
        ) {
            Err(super::super::client::ClientError::Degraded(degraded)) => *degraded,
            other => {
                panic!("expected degraded snapshot when core tables exceed cap, got {other:?}")
            }
        };
        let encoded = encode_canonical(&degraded).expect("re-encode degraded");
        assert!(encoded.len() <= MAX_RESPONSE_BYTES);
        assert!(
            degraded.strict_error.contains("response cap"),
            "strict_error: {}",
            degraded.strict_error
        );
        assert!(
            degraded
                .unreadable
                .iter()
                .any(|entry| entry.contains("response cap")),
            "unreadable: {:?}",
            degraded.unreadable
        );
        assert!(
            degraded
                .tasks
                .iter()
                .any(|task| task.diagnostic_name == "oversized-vma-root"),
            "tasks: {:?}",
            degraded.tasks
        );

        let capture = request_capture_at(&endpoint, "debug-oversized-core");
        assert!(capture.kernel.is_none());
        assert!(
            capture
                .truncated
                .iter()
                .any(|entry| entry.section == "kernel"),
            "truncated: {:?}",
            capture.truncated
        );
        assert!(
            !capture.event_ring.is_empty(),
            "event_ring must survive untruncated when core kernel tables alone caused the overflow"
        );
        assert!(
            !capture.event_ring_high_rate.is_empty(),
            "event_ring_high_rate must survive untruncated when core kernel tables alone caused the overflow"
        );
        let physical = capture.physical.as_ref().expect(
            "physical capture must survive when core kernel tables alone caused the overflow",
        );
        assert_eq!(physical.zone_census, "cpl0-zone: cpu0=idle cpu1=parked");
        assert_eq!(physical.vcpus.len(), 2);
        assert_eq!(physical.host_threads.len(), 2);
        assert!(
            physical.unavailable.is_empty(),
            "physical.unavailable must stay empty when core kernel tables alone caused the overflow: {:?}",
            physical.unavailable
        );
        assert!(
            capture
                .truncated
                .iter()
                .all(|entry| entry.section == "kernel"),
            "only kernel must be recorded in truncated when core tables alone overflowed: {:?}",
            capture.truncated
        );
        assert!(capture.degraded_kernel.as_ref().is_some_and(|view| {
            view.tasks
                .iter()
                .any(|t| t.diagnostic_name == "oversized-vma-root")
        }));

        server.shutdown();
    }
}
