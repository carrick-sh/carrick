//! Authenticated host-operator control for one managed HVPatch carrier.

mod archive;
mod endpoint;
mod exec;

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub use archive::{
    ArchiveAdmissionInstallError, ArchiveAdmissionSlot, ArchiveCapability, ArchiveChunk,
    ArchiveControlError, ArchiveMetadata, ArchiveReadStart, ArchiveRequest, ArchiveRuntime,
    CarrierArchiveControl, MAX_ARCHIVE_CHUNK_BYTES,
};
pub use endpoint::{ControlEndpoint, EndpointError};
pub use exec::{
    CarrierExecAdmission, ExecAdmissionError, ExecAdmissionInstallError, ExecAdmissionSlot,
    ExecAttach, ExecCapability, ExecEnvVar, ExecRequest, ExecResult, ExecRuntime, ExecStatus,
    ExecUser, ExecWakerInstallError, ExecWork, ExecWorkError,
};

const REQUEST_SCHEMA: &str = "carrick.carrier-control-request.v1";
const RESPONSE_SCHEMA: &str = "carrick.carrier-control-response.v1";
pub const CARRIER_CONTROL_STATE_SCHEMA: &str = "carrick.carrier-control-state.v1";
// Exec strings retain Linux's only hard string exclusion (NUL), so JSON may
// encode one accepted control byte as a six-byte `\u00xx` escape. This bound
// covers the DTO's 3 KiB aggregate string budget plus maximum collection and
// envelope overhead while remaining a small, fixed allocation ceiling.
const MAX_CONTROL_FRAME: usize = 24 * 1024;
const DEADLINE: Duration = Duration::from_secs(2);
const EXEC_ADMISSION_RESPONSE_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ControlNonce([u8; 16]);

impl ControlNonce {
    pub fn fresh() -> std::io::Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| {
            std::io::Error::other(format!("generate carrier control nonce: {error:?}"))
        })?;
        Ok(Self(bytes))
    }

    pub(super) fn hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTaskKey {
    pub pid: i32,
    pub serial: u64,
}

impl From<super::TaskKey> for ControlTaskKey {
    fn from(value: super::TaskKey) -> Self {
        Self {
            pid: value.id.raw(),
            serial: value.serial.raw(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlOperation {
    Status,
    Signal {
        linux_signal: i32,
    },
    Exec {
        request: ExecRequest,
    },
    ExecStatus {
        capability: ExecCapability,
    },
    ExecWait {
        capability: ExecCapability,
    },
    ArchiveBeginRead {
        request: ArchiveRequest,
    },
    ArchiveMetadata {
        request: ArchiveRequest,
    },
    ArchiveReadChunk {
        capability: ArchiveCapability,
    },
    ArchiveBeginWrite {
        request: ArchiveRequest,
    },
    ArchiveWriteChunk {
        capability: ArchiveCapability,
        bytes: Vec<u8>,
        eof: bool,
    },
    ArchiveAbort {
        capability: ArchiveCapability,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    schema: String,
    request_id: ControlNonce,
    owner_nonce: ControlNonce,
    expected_init: ControlTaskKey,
    operation: ControlOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOutcome {
    Alive,
    Signalled,
    AcceptedProtectedInit,
    NotRunning,
    StaleIncarnation,
    StaleTask,
    InvalidSignal,
    InvalidSchema,
    InvalidExec,
    ExecUnavailable,
    ExecRejected,
    ExecAccepted {
        capability: ExecCapability,
    },
    ExecPending,
    ExecRunning,
    ExecComplete {
        result: ExecResult,
    },
    UnknownExecCapability,
    ArchiveAccepted {
        capability: ArchiveCapability,
    },
    ArchiveReadAccepted {
        capability: ArchiveCapability,
        metadata: ArchiveMetadata,
    },
    ArchiveMetadata {
        metadata: ArchiveMetadata,
    },
    ArchiveChunk {
        chunk: ArchiveChunk,
    },
    ArchiveWriteReady,
    ArchiveComplete,
    ArchiveError {
        error: ArchiveControlError,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlResponse {
    schema: String,
    request_id: ControlNonce,
    owner_nonce: ControlNonce,
    init: ControlTaskKey,
    outcome: ControlOutcome,
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error("carrier control I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("carrier control protocol failed: {0}")]
    Protocol(String),
}

#[derive(Debug)]
pub struct CarrierControlServer {
    endpoint: ControlEndpoint,
    nonce: ControlNonce,
    init: super::TaskKey,
    exec_slot: Option<Arc<ExecAdmissionSlot>>,
    archive_slot: Option<Arc<ArchiveAdmissionSlot>>,
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// Run-lifetime guard for one managed carrier. Terminal state is persisted
/// before the authenticated endpoint is released on every path.
#[derive(Debug)]
pub struct ManagedCarrierControl {
    container_id: String,
    state: crate::container::CarrierControlState,
    server: Option<CarrierControlServer>,
    completed: bool,
}

impl CarrierControlServer {
    pub fn start(
        kernel: Arc<super::Kernel>,
        init: super::TaskKey,
        container_id: &str,
    ) -> Result<Self, ControlError> {
        let endpoint = ControlEndpoint::for_container_id(container_id)?;
        Self::start_at(kernel, init, endpoint)
    }

    pub fn start_at(
        kernel: Arc<super::Kernel>,
        init: super::TaskKey,
        endpoint: ControlEndpoint,
    ) -> Result<Self, ControlError> {
        let exec_slot = Arc::new(ExecAdmissionSlot::default());
        let archive_slot = Arc::new(ArchiveAdmissionSlot::default());
        Self::start_at_inner(
            kernel,
            init,
            endpoint,
            exec_slot.clone(),
            Some(exec_slot),
            archive_slot.clone(),
            Some(archive_slot),
        )
    }

    pub fn start_at_with_exec(
        kernel: Arc<super::Kernel>,
        init: super::TaskKey,
        endpoint: ControlEndpoint,
        exec: Arc<dyn CarrierExecAdmission>,
    ) -> Result<Self, ControlError> {
        let archive_slot = Arc::new(ArchiveAdmissionSlot::default());
        Self::start_at_inner(
            kernel,
            init,
            endpoint,
            exec,
            None,
            archive_slot.clone(),
            Some(archive_slot),
        )
    }

    fn start_at_inner(
        kernel: Arc<super::Kernel>,
        init: super::TaskKey,
        endpoint: ControlEndpoint,
        exec: Arc<dyn CarrierExecAdmission>,
        exec_slot: Option<Arc<ExecAdmissionSlot>>,
        archive: Arc<dyn CarrierArchiveControl>,
        archive_slot: Option<Arc<ArchiveAdmissionSlot>>,
    ) -> Result<Self, ControlError> {
        let nonce = ControlNonce::fresh()?;
        endpoint.claim(nonce)?;
        let listener = UnixListener::bind(endpoint.socket_path())?;
        if let Err(error) = endpoint.publish_bound_owner(nonce) {
            endpoint.rollback_unpublished_socket();
            return Err(error.into());
        }
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_endpoint = endpoint.clone();
        let thread_exec = Arc::clone(&exec);
        let thread_archive = Arc::clone(&archive);
        let join = match std::thread::Builder::new()
            .name("carrick-carrier-control".to_owned())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        continue;
                    };
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(_error) = handle(
                        &mut stream,
                        &kernel,
                        init,
                        nonce,
                        thread_exec.as_ref(),
                        thread_archive.as_ref(),
                    ) {
                        #[cfg(test)]
                        eprintln!("carrier control test connection failed: {_error}");
                    }
                }
                thread_endpoint.release_if_owner(nonce);
            }) {
            Ok(join) => join,
            Err(error) => {
                endpoint.release_if_owner(nonce);
                return Err(error.into());
            }
        };
        Ok(Self {
            endpoint,
            nonce,
            init,
            exec_slot,
            archive_slot,
            shutdown,
            join: Some(join),
        })
    }

    pub fn state(&self) -> crate::container::CarrierControlState {
        crate::container::CarrierControlState {
            schema: CARRIER_CONTROL_STATE_SCHEMA.to_owned(),
            owner_nonce: self.nonce,
            init: self.init.into(),
        }
    }

    pub fn exec_admission_slot(&self) -> Option<Arc<ExecAdmissionSlot>> {
        self.exec_slot.clone()
    }

    pub fn archive_admission_slot(&self) -> Option<Arc<ArchiveAdmissionSlot>> {
        self.archive_slot.clone()
    }

    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = UnixStream::connect(self.endpoint.socket_path());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.endpoint.release_if_owner(self.nonce);
    }
}

impl Drop for CarrierControlServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl ManagedCarrierControl {
    pub fn start(
        kernel: Arc<super::Kernel>,
        init: super::TaskKey,
        container_id: &str,
        launch_authorization: &str,
    ) -> Result<Self, ControlError> {
        let server = CarrierControlServer::start(kernel, init, container_id)?;
        let control_state = server.state();
        let mut state = crate::container::ContainerState::load(container_id)?;
        if state.status != crate::container::ContainerStatus::Created
            || state.control.is_some()
            || state.terminal_control.is_some()
            || state.launch_ticket.as_deref() != Some(launch_authorization)
        {
            return Err(ControlError::Protocol(
                "carrier launch authorization no longer owns Created state".to_owned(),
            ));
        }
        let carrier_pid = std::process::id() as i32;
        state.status = crate::container::ContainerStatus::Running;
        state.supervisor_pid = carrier_pid;
        state.init_pid = carrier_pid;
        state.control = Some(control_state.clone());
        state.terminal_control = None;
        state.launch_ticket = None;
        state.persist()?;
        Ok(Self {
            container_id: container_id.to_owned(),
            state: control_state,
            server: Some(server),
            completed: false,
        })
    }

    pub fn complete(&mut self, exit_code: i32) -> Result<(), ControlError> {
        if !crate::container::mark_control_owner_exited(&self.container_id, &self.state, exit_code)?
        {
            return Err(ControlError::Protocol(
                "carrier lost its persisted control incarnation before terminal publication"
                    .to_owned(),
            ));
        }
        self.completed = true;
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
        Ok(())
    }

    /// Stop admission, join the synchronous control worker, and drop every
    /// installed exec/archive authority without publishing terminal state.
    /// Container teardown uses this after guest executors join and before its
    /// mount table is destroyed; [`Self::complete`] records the exact outcome
    /// once teardown itself has succeeded or failed.
    pub(crate) fn quiesce(&mut self) {
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
    }

    /// Install the live HVPatch scheduler bridge after the persistent executor
    /// directory is ready. Until installation, authenticated exec requests are
    /// refused by name and cannot fall back to another runtime or process.
    pub fn exec_admission_slot(&self) -> Option<Arc<ExecAdmissionSlot>> {
        self.server
            .as_ref()
            .and_then(CarrierControlServer::exec_admission_slot)
    }

    /// Install the carrier-owned VFS archive authority. Until installation,
    /// archive requests fail closed and cannot fall back to a process or host
    /// filesystem path.
    pub fn archive_admission_slot(&self) -> Option<Arc<ArchiveAdmissionSlot>> {
        self.server
            .as_ref()
            .and_then(CarrierControlServer::archive_admission_slot)
    }
}

impl Drop for ManagedCarrierControl {
    fn drop(&mut self) {
        if !self.completed {
            let _ =
                crate::container::mark_control_owner_exited(&self.container_id, &self.state, 125);
        }
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
    }
}

pub fn send(
    container_id: &str,
    state: &crate::container::CarrierControlState,
    operation: ControlOperation,
) -> Result<ControlOutcome, ControlError> {
    let endpoint = ControlEndpoint::for_container_id(container_id)?;
    send_at(&endpoint, state, operation)
}

pub fn send_at(
    endpoint: &ControlEndpoint,
    state: &crate::container::CarrierControlState,
    operation: ControlOperation,
) -> Result<ControlOutcome, ControlError> {
    if state.schema != CARRIER_CONTROL_STATE_SCHEMA {
        return Err(ControlError::Protocol(format!(
            "unknown carrier control state schema {}",
            state.schema
        )));
    }
    let owner = match endpoint.current_owner(state.owner_nonce) {
        Ok(owner) => owner,
        Err(EndpointError::StaleOwnerNonce) => return Ok(ControlOutcome::StaleIncarnation),
        Err(error) => return Err(error.into()),
    };
    let mut stream = UnixStream::connect(endpoint.socket_path())?;
    let peer = carrick_portable::peer_credentials(stream.as_raw_fd())?;
    let uid = unsafe { libc::geteuid() };
    if peer.uid != uid || peer.pid.is_some_and(|pid| pid != owner.pid) {
        return Err(ControlError::Protocol(
            "connected carrier does not match the authenticated owner record".to_owned(),
        ));
    }
    if endpoint.current_owner(state.owner_nonce)? != owner {
        return Err(ControlError::Protocol(
            "carrier control owner changed during connect".to_owned(),
        ));
    }
    let response_deadline = operation_response_deadline(&operation);
    stream.set_read_timeout(Some(response_deadline))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let request = ControlRequest {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: ControlNonce::fresh()?,
        owner_nonce: state.owner_nonce,
        expected_init: state.init,
        operation,
    };
    write_frame(
        &mut stream,
        &serde_json::to_vec(&request).map_err(protocol)?,
    )?;
    let request_id = request.request_id;
    let response: ControlResponse =
        serde_json::from_slice(&read_frame_with_deadline(&mut stream, response_deadline)?)
            .map_err(protocol)?;
    if response.schema != RESPONSE_SCHEMA || response.request_id != request_id {
        return Err(ControlError::Protocol(
            "response authority does not match requested incarnation".to_owned(),
        ));
    }
    if matches!(
        &response.outcome,
        ControlOutcome::StaleIncarnation | ControlOutcome::StaleTask
    ) {
        return Ok(response.outcome);
    }
    if response.owner_nonce != state.owner_nonce || response.init != state.init {
        return Err(ControlError::Protocol(
            "response authority does not match requested incarnation".to_owned(),
        ));
    }
    Ok(response.outcome)
}

fn operation_response_deadline(operation: &ControlOperation) -> Duration {
    if matches!(operation, ControlOperation::Exec { .. }) {
        EXEC_ADMISSION_RESPONSE_DEADLINE
    } else {
        DEADLINE
    }
}

fn handle(
    stream: &mut UnixStream,
    kernel: &Arc<super::Kernel>,
    init: super::TaskKey,
    nonce: ControlNonce,
    exec: &dyn CarrierExecAdmission,
    archive: &dyn CarrierArchiveControl,
) -> Result<(), ControlError> {
    authenticate(stream)?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let request: ControlRequest = serde_json::from_slice(&read_frame(stream)?).map_err(protocol)?;
    let request_id = request.request_id;
    let exact = ControlTaskKey::from(init);
    let outcome = if request.schema != REQUEST_SCHEMA {
        ControlOutcome::InvalidSchema
    } else if request.owner_nonce != nonce {
        ControlOutcome::StaleIncarnation
    } else if request.expected_init != exact {
        ControlOutcome::StaleTask
    } else {
        match request.operation {
            ControlOperation::Status => {
                if kernel.task_key_is_live(init) {
                    ControlOutcome::Alive
                } else {
                    ControlOutcome::NotRunning
                }
            }
            ControlOperation::Signal { linux_signal } => {
                let Ok(signal) = super::LinuxSignal::for_signal_number(linux_signal) else {
                    return write_response(
                        stream,
                        request.request_id,
                        nonce,
                        exact,
                        ControlOutcome::InvalidSignal,
                    );
                };
                match kernel.post_carrier_control_signal(init, signal) {
                    super::operations::CarrierControlSignalPost::Posted => {
                        ControlOutcome::Signalled
                    }
                    super::operations::CarrierControlSignalPost::AcceptedProtectedInit => {
                        ControlOutcome::AcceptedProtectedInit
                    }
                    super::operations::CarrierControlSignalPost::Missing => {
                        ControlOutcome::NotRunning
                    }
                }
            }
            ControlOperation::Exec { request } => {
                if !request.validate() {
                    ControlOutcome::InvalidExec
                } else {
                    match exec.admit(request_id.into(), request) {
                        Ok(capability) => ControlOutcome::ExecAccepted { capability },
                        Err(ExecAdmissionError::Unavailable) => ControlOutcome::ExecUnavailable,
                        Err(ExecAdmissionError::Rejected) => ControlOutcome::ExecRejected,
                    }
                }
            }
            ControlOperation::ExecStatus { capability } => {
                exec_status_outcome(exec.query(capability))
            }
            ControlOperation::ExecWait { capability } => exec_status_outcome(exec.wait(capability)),
            ControlOperation::ArchiveBeginRead { request } => {
                archive_outcome(archive.begin_read(request_id.into(), request), |start| {
                    ControlOutcome::ArchiveReadAccepted {
                        capability: start.capability,
                        metadata: start.metadata,
                    }
                })
            }
            ControlOperation::ArchiveMetadata { request } => {
                archive_outcome(archive.metadata(request), |metadata| {
                    ControlOutcome::ArchiveMetadata { metadata }
                })
            }
            ControlOperation::ArchiveReadChunk { capability } => {
                archive_outcome(archive.read_chunk(capability), |chunk| {
                    ControlOutcome::ArchiveChunk { chunk }
                })
            }
            ControlOperation::ArchiveBeginWrite { request } => archive_outcome(
                archive.begin_write(request_id.into(), request),
                |capability| ControlOutcome::ArchiveAccepted { capability },
            ),
            ControlOperation::ArchiveWriteChunk {
                capability,
                bytes,
                eof,
            } => archive_outcome(archive.write_chunk(capability, bytes, eof), |complete| {
                if complete {
                    ControlOutcome::ArchiveComplete
                } else {
                    ControlOutcome::ArchiveWriteReady
                }
            }),
            ControlOperation::ArchiveAbort { capability } => {
                archive_outcome(archive.abort(capability), |()| {
                    ControlOutcome::ArchiveComplete
                })
            }
        }
    };
    write_response(stream, request_id, nonce, exact, outcome)
}

fn archive_outcome<T>(
    result: Result<T, ArchiveControlError>,
    success: impl FnOnce(T) -> ControlOutcome,
) -> ControlOutcome {
    match result {
        Ok(value) => success(value),
        Err(error) => ControlOutcome::ArchiveError { error },
    }
}

fn exec_status_outcome(status: ExecStatus) -> ControlOutcome {
    match status {
        ExecStatus::Unknown => ControlOutcome::UnknownExecCapability,
        ExecStatus::Pending => ControlOutcome::ExecPending,
        ExecStatus::Running => ControlOutcome::ExecRunning,
        ExecStatus::Complete(result) => ControlOutcome::ExecComplete { result },
    }
}

fn write_response(
    stream: &mut UnixStream,
    request_id: ControlNonce,
    nonce: ControlNonce,
    init: ControlTaskKey,
    outcome: ControlOutcome,
) -> Result<(), ControlError> {
    let response = ControlResponse {
        schema: RESPONSE_SCHEMA.to_owned(),
        request_id,
        owner_nonce: nonce,
        init,
        outcome,
    };
    write_frame(stream, &serde_json::to_vec(&response).map_err(protocol)?)
}

fn authenticate(stream: &UnixStream) -> Result<(), ControlError> {
    let peer = carrick_portable::peer_credentials(stream.as_raw_fd())?;
    let uid = unsafe { libc::geteuid() };
    if peer.uid != uid {
        return Err(ControlError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "carrier control peer uid mismatch",
        )));
    }
    Ok(())
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), ControlError> {
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err(ControlError::Protocol("frame too large".to_owned()));
    }
    let len = u32::try_from(bytes.len()).map_err(|_| protocol("frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ControlError> {
    read_frame_with_deadline(stream, DEADLINE)
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    deadline: Duration,
) -> Result<Vec<u8>, ControlError> {
    let started = Instant::now();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_CONTROL_FRAME {
        return Err(ControlError::Protocol("frame too large".to_owned()));
    }
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes)?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing)? != 0 {
        return Err(ControlError::Protocol("trailing bytes".to_owned()));
    }
    if started.elapsed() > deadline {
        return Err(ControlError::Protocol("deadline exceeded".to_owned()));
    }
    Ok(bytes)
}

fn protocol(error: impl ToString) -> ControlError {
    ControlError::Protocol(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn kernel_with_init() -> (Arc<super::super::Kernel>, super::super::KernelContext) {
        let bootstrap = super::super::RootBootstrap::for_reference_model(
            carrick_abi::LINUX_BOOTSTRAP_PID as i32,
            carrick_hal::ThreadId::synthetic_for_tests(carrick_abi::LINUX_BOOTSTRAP_PID as i32),
            "control-init".to_owned(),
        )
        .expect("bootstrap");
        super::super::Kernel::bootstrap_root(bootstrap).expect("kernel")
    }

    #[test]
    fn status_and_signal_use_the_exact_control_incarnation() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-status-signal");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
        )
        .expect("server");
        let state = server.state();

        assert_eq!(
            send_at(&endpoint, &state, ControlOperation::Status).expect("status"),
            ControlOutcome::Alive,
        );
        assert_eq!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::Signal {
                    linux_signal: carrick_abi::LINUX_SIGKILL,
                },
            )
            .expect("signal"),
            ControlOutcome::Signalled,
        );
        assert!(
            init.shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGKILL)
        );
        server.shutdown();
    }

    #[derive(Debug)]
    struct AcceptingExecAdmission;

    impl CarrierExecAdmission for AcceptingExecAdmission {
        fn admit(
            &self,
            request_id: ExecCapability,
            request: ExecRequest,
        ) -> Result<ExecCapability, ExecAdmissionError> {
            if request.argv.first().map(String::as_str) != Some("/bin/true") {
                return Err(ExecAdmissionError::Rejected);
            }
            Ok(request_id)
        }
    }

    fn minimal_exec_request() -> ExecRequest {
        ExecRequest {
            argv: vec!["/bin/true".to_owned()],
            env: vec![ExecEnvVar {
                key: "PATH".to_owned(),
                value: "/usr/bin:/bin".to_owned(),
            }],
            workdir: Some("/work".to_owned()),
            user: Some(ExecUser {
                uid: 1_000,
                gid: 1_000,
                supplementary_gids: vec![10, 20],
            }),
            tty: false,
            attach: ExecAttach::Capture,
        }
    }

    #[test]
    fn every_validate_true_exec_request_fits_the_wire_frame() {
        let request = ExecRequest {
            argv: vec!["\u{1}".repeat(32); 32],
            env: vec![
                ExecEnvVar {
                    key: "A".to_owned(),
                    value: "\u{1}".repeat(31),
                };
                64
            ],
            workdir: None,
            user: None,
            tty: false,
            attach: ExecAttach::Capture,
        };
        assert!(
            request.validate(),
            "fixture must exercise the accepted bound"
        );
        let wire = serde_json::to_vec(&ControlRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: ControlNonce([1; 16]),
            owner_nonce: ControlNonce([2; 16]),
            expected_init: ControlTaskKey { pid: 1, serial: 1 },
            operation: ControlOperation::Exec { request },
        })
        .expect("serialize request");
        assert!(
            wire.len() <= MAX_CONTROL_FRAME,
            "validate-true request encoded to {} bytes above {MAX_CONTROL_FRAME}",
            wire.len(),
        );
    }

    #[test]
    fn authoritative_exec_admission_has_a_bounded_transport_deadline_beyond_polling() {
        let exec = ControlOperation::Exec {
            request: minimal_exec_request(),
        };
        assert_eq!(
            operation_response_deadline(&exec),
            EXEC_ADMISSION_RESPONSE_DEADLINE
        );
        assert!(EXEC_ADMISSION_RESPONSE_DEADLINE > DEADLINE);
        assert_eq!(
            operation_response_deadline(&ControlOperation::ExecWait {
                capability: ExecCapability::from(ControlNonce([0x72; 16])),
            }),
            DEADLINE,
        );
    }

    #[test]
    fn exec_capability_is_returned_only_after_consumer_admission_and_tracks_result() {
        let runtime = Arc::new(ExecRuntime::new(2));
        runtime
            .install_waker(Arc::new(|| {}))
            .expect("install waker");
        let submit = Arc::clone(&runtime);
        let request = minimal_exec_request();
        let capability = ExecCapability::from(ControlNonce([0x33; 16]));
        let submitter = std::thread::spawn(move || submit.admit(capability, request));

        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert_eq!(runtime.query(capability), ExecStatus::Pending);
        work.admit(ControlTaskKey { pid: 22, serial: 7 });
        assert_eq!(submitter.join().expect("submitter"), Ok(capability));
        assert_eq!(runtime.query(capability), ExecStatus::Running);

        work.complete(ExecResult {
            exit_code: 4,
            terminating_signal: None,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            output_truncated: false,
        })
        .expect("complete admitted work");
        assert_eq!(
            runtime.query(capability),
            ExecStatus::Complete(ExecResult {
                exit_code: 4,
                terminating_signal: None,
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
                output_truncated: false,
            })
        );
        assert!(matches!(runtime.wait(capability), ExecStatus::Complete(_)));
        assert_eq!(runtime.query(capability), ExecStatus::Unknown);
    }

    #[test]
    fn maximum_captured_exec_result_fits_one_control_frame() {
        let response = ControlResponse {
            schema: RESPONSE_SCHEMA.to_owned(),
            request_id: ControlNonce([3; 16]),
            owner_nonce: ControlNonce([4; 16]),
            init: ControlTaskKey { pid: 1, serial: 1 },
            outcome: ControlOutcome::ExecComplete {
                result: ExecResult {
                    exit_code: 0,
                    terminating_signal: None,
                    stdout: vec![u8::MAX; exec::MAX_CAPTURE_BYTES],
                    stderr: vec![u8::MAX; exec::MAX_CAPTURE_BYTES],
                    output_truncated: false,
                },
            },
        };
        let encoded = serde_json::to_vec(&response).expect("serialize maximum result");
        assert!(
            encoded.len() <= MAX_CONTROL_FRAME,
            "maximum captured result encoded to {} bytes above {MAX_CONTROL_FRAME}",
            encoded.len(),
        );
    }

    #[test]
    fn timed_out_exec_work_cannot_admit_or_complete_later() {
        let runtime = Arc::new(ExecRuntime::new_for_test(
            2,
            std::time::Duration::from_millis(10),
        ));
        runtime
            .install_waker(Arc::new(|| {}))
            .expect("install waker");
        let submit = Arc::clone(&runtime);
        let capability = ExecCapability::from(ControlNonce([0x44; 16]));
        let submitter =
            std::thread::spawn(move || submit.admit(capability, minimal_exec_request()));
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            submitter.join().expect("submitter"),
            Err(ExecAdmissionError::Unavailable)
        );
        assert!(runtime.try_take().is_none());
        assert_eq!(runtime.query(capability), ExecStatus::Unknown);
    }

    #[test]
    fn exec_table_capacity_refuses_new_admission() {
        let runtime = Arc::new(ExecRuntime::new_for_test(
            1,
            std::time::Duration::from_millis(50),
        ));
        runtime
            .install_waker(Arc::new(|| {}))
            .expect("install waker");
        let first_runtime = Arc::clone(&runtime);
        let first = ExecCapability::from(ControlNonce([0x51; 16]));
        let first_submitter =
            std::thread::spawn(move || first_runtime.admit(first, minimal_exec_request()));
        while runtime.query(first) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let second = ExecCapability::from(ControlNonce([0x52; 16]));
        assert_eq!(
            runtime.admit(second, minimal_exec_request()),
            Err(ExecAdmissionError::Unavailable),
        );
        drop(runtime.try_take());
        assert_eq!(
            first_submitter.join().expect("first submitter"),
            Err(ExecAdmissionError::Rejected),
        );
    }

    #[test]
    fn authenticated_exec_returns_an_opaque_same_carrier_capability() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-exec-admission");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at_with_exec(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
            Arc::new(AcceptingExecAdmission),
        )
        .expect("server");
        let state = server.state();

        assert!(matches!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::Exec {
                    request: minimal_exec_request(),
                },
            )
            .expect("exec admission"),
            ControlOutcome::ExecAccepted { .. },
        ));
        server.shutdown();
    }

    #[test]
    fn invalid_exec_is_rejected_before_same_carrier_admission() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-exec-invalid");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at_with_exec(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
            Arc::new(AcceptingExecAdmission),
        )
        .expect("server");
        let state = server.state();
        let mut request = minimal_exec_request();
        request.argv.clear();

        assert_eq!(
            send_at(&endpoint, &state, ControlOperation::Exec { request }).expect("named refusal"),
            ControlOutcome::InvalidExec,
        );
        server.shutdown();
    }

    #[test]
    fn exec_without_scheduler_admission_fails_closed() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-exec-unavailable");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
        )
        .expect("server");
        let state = server.state();

        assert_eq!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::Exec {
                    request: minimal_exec_request(),
                },
            )
            .expect("named unavailable"),
            ControlOutcome::ExecUnavailable,
        );
        server
            .exec_admission_slot()
            .expect("default server owns an installable admission slot")
            .install(Arc::new(AcceptingExecAdmission))
            .expect("install scheduler admission");
        assert!(matches!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::Exec {
                    request: minimal_exec_request(),
                },
            )
            .expect("installed admission"),
            ControlOutcome::ExecAccepted { .. },
        ));
        server.shutdown();
    }

    #[test]
    fn exec_status_and_wait_return_and_consume_exact_terminal_result() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-exec-result");
        let (kernel, init) = kernel_with_init();
        let runtime = Arc::new(ExecRuntime::new(2));
        runtime
            .install_waker(Arc::new(|| {}))
            .expect("install waker");
        let mut server = CarrierControlServer::start_at_with_exec(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
            runtime.clone(),
        )
        .expect("server");
        let state = server.state();
        let submit_endpoint = endpoint.clone();
        let submit_state = state.clone();
        let submitter = std::thread::spawn(move || {
            send_at(
                &submit_endpoint,
                &submit_state,
                ControlOperation::Exec {
                    request: minimal_exec_request(),
                },
            )
        });
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.admit(ControlTaskKey { pid: 44, serial: 9 }));
        let capability = match submitter.join().expect("submitter").expect("admitted") {
            ControlOutcome::ExecAccepted { capability } => capability,
            other => panic!("unexpected admission outcome: {other:?}"),
        };
        assert_eq!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::ExecStatus { capability },
            )
            .expect("running status"),
            ControlOutcome::ExecRunning,
        );
        work.complete(ExecResult {
            exit_code: 7,
            terminating_signal: None,
            stdout: b"seven".to_vec(),
            stderr: Vec::new(),
            output_truncated: false,
        })
        .expect("terminal result");
        assert!(matches!(
            send_at(&endpoint, &state, ControlOperation::ExecWait { capability },)
                .expect("wait result"),
            ControlOutcome::ExecComplete {
                result: ExecResult { exit_code: 7, .. }
            },
        ));
        assert_eq!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::ExecStatus { capability },
            )
            .expect("consumed status"),
            ControlOutcome::UnknownExecCapability,
        );
        server.shutdown();
    }

    #[test]
    fn running_exec_wait_poll_does_not_monopolize_status_connection() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-exec-wait-poll");
        let (kernel, init) = kernel_with_init();
        let runtime = Arc::new(ExecRuntime::new_for_test(
            2,
            std::time::Duration::from_millis(250),
        ));
        runtime
            .install_waker(Arc::new(|| {}))
            .expect("install waker");
        let capability = ExecCapability::from(ControlNonce([0x71; 16]));
        let submit = Arc::clone(&runtime);
        let submitter =
            std::thread::spawn(move || submit.admit(capability, minimal_exec_request()));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.admit(ControlTaskKey { pid: 71, serial: 1 }));
        assert_eq!(submitter.join().expect("submitter"), Ok(capability));

        let mut server = CarrierControlServer::start_at_with_exec(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
            runtime,
        )
        .expect("server");
        let state = server.state();
        let wait_endpoint = endpoint.clone();
        let wait_state = state.clone();
        let waiter = std::thread::spawn(move || {
            send_at(
                &wait_endpoint,
                &wait_state,
                ControlOperation::ExecWait { capability },
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        let started = std::time::Instant::now();
        assert_eq!(
            send_at(&endpoint, &state, ControlOperation::Status).expect("status"),
            ControlOutcome::Alive,
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(200),
            "a running ExecWait monopolized the serial control endpoint",
        );
        assert_eq!(
            waiter.join().expect("waiter").expect("wait response"),
            ControlOutcome::ExecRunning,
        );
        drop(work);
        server.shutdown();
    }

    #[test]
    fn stale_nonce_cannot_mutate_the_kernel() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-stale-nonce");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
        )
        .expect("server");
        let mut stale = server.state();
        stale.owner_nonce = ControlNonce([0x5a; 16]);

        assert_eq!(
            send_at(
                &endpoint,
                &stale,
                ControlOperation::Signal {
                    linux_signal: carrick_abi::LINUX_SIGKILL,
                },
            )
            .expect("named stale response"),
            ControlOutcome::StaleIncarnation,
        );
        assert!(
            !init
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGKILL)
        );
        server.shutdown();
    }

    #[test]
    fn stale_task_is_reported_by_name_before_authority_echo_validation() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-stale-task");
        let (kernel, init) = kernel_with_init();
        let mut server = CarrierControlServer::start_at(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
        )
        .expect("server");
        let mut stale = server.state();
        stale.init.serial = stale.init.serial.saturating_add(1);

        assert_eq!(
            send_at(&endpoint, &stale, ControlOperation::Status).expect("named stale task"),
            ControlOutcome::StaleTask,
        );
        server.shutdown();
    }

    #[test]
    fn unknown_persisted_state_schema_is_refused_before_connect() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-state-schema");
        let state = crate::container::CarrierControlState {
            schema: "carrick.carrier-control-state.v2".to_owned(),
            owner_nonce: ControlNonce([1; 16]),
            init: ControlTaskKey { pid: 1, serial: 1 },
        };
        let error =
            send_at(&endpoint, &state, ControlOperation::Status).expect_err("unknown state schema");
        assert!(
            error
                .to_string()
                .contains("unknown carrier control state schema")
        );
    }

    #[test]
    fn endpoint_is_private_and_does_not_embed_container_id() {
        let (_temp, endpoint) = endpoint::test_endpoint("secret-container-identity");
        let nonce = ControlNonce([7; 16]);
        endpoint.claim(nonce).expect("claim");
        assert!(
            !endpoint
                .socket_path()
                .display()
                .to_string()
                .contains("secret")
        );
        assert_eq!(
            std::fs::metadata(endpoint.directory())
                .expect("directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn endpoint_refuses_a_preplanted_symlink_directory() {
        let temp = tempfile::Builder::new()
            .prefix("cc-link")
            .tempdir_in("/tmp")
            .expect("tempdir");
        let target = temp.path().join("target");
        std::fs::create_dir(&target).expect("target");
        let base = temp.path().join("base");
        std::os::unix::fs::symlink(&target, &base).expect("symlink");
        let endpoint = ControlEndpoint::in_base(base, "symlink-refusal").expect("resolve");

        assert!(matches!(
            endpoint.claim(ControlNonce([9; 16])),
            Err(EndpointError::InvalidOwner(_))
        ));
    }

    fn managed_state(id: String) -> crate::container::ContainerState {
        crate::container::ContainerState {
            id,
            name: None,
            image: "test".to_owned(),
            command: vec!["/bin/true".to_owned()],
            status: crate::container::ContainerStatus::Created,
            supervisor_pid: 0,
            init_pid: 0,
            created_secs: 0,
            exit_code: None,
            auto_remove: false,
            api_auto_remove: false,
            labels: std::collections::HashMap::new(),
            control: None,
            launch_ticket: Some("launch-authorization:77".to_owned()),
            terminal_control: None,
            config: crate::container::RunConfig::default(),
        }
    }

    #[test]
    fn managed_guard_publishes_fail_closed_terminal_before_release() {
        let id = format!("control-guard-drop-{}", std::process::id());
        let _ = crate::container::ContainerState::remove(&id);
        managed_state(id.clone()).create().expect("created state");
        let (kernel, init) = kernel_with_init();
        {
            let _guard = ManagedCarrierControl::start(
                kernel,
                init.task().key(),
                &id,
                "launch-authorization:77",
            )
            .expect("managed control");
            let running = crate::container::ContainerState::load(&id).expect("running state");
            assert_eq!(running.status, crate::container::ContainerStatus::Running);
            assert!(running.control.is_some());
        }
        let exited = crate::container::ContainerState::load(&id).expect("terminal state");
        assert_eq!(exited.status, crate::container::ContainerStatus::Exited);
        assert_eq!(exited.exit_code, Some(125));
        assert!(exited.control.is_none());
        let _ = crate::container::ContainerState::remove(&id);
    }

    #[test]
    fn managed_guard_publishes_exact_normal_exit() {
        let id = format!("control-guard-complete-{}", std::process::id());
        let _ = crate::container::ContainerState::remove(&id);
        managed_state(id.clone()).create().expect("created state");
        let (kernel, init) = kernel_with_init();
        {
            let mut guard = ManagedCarrierControl::start(
                kernel,
                init.task().key(),
                &id,
                "launch-authorization:77",
            )
            .expect("managed control");
            guard.complete(42).expect("complete");
        }
        let exited = crate::container::ContainerState::load(&id).expect("terminal state");
        assert_eq!(exited.status, crate::container::ContainerStatus::Exited);
        assert_eq!(exited.exit_code, Some(42));
        assert!(exited.control.is_none());
        let _ = crate::container::ContainerState::remove(&id);
    }

    #[test]
    fn managed_guard_quiesces_before_publishing_the_terminal_outcome() {
        let id = format!("control-guard-quiesce-{}", std::process::id());
        let _ = crate::container::ContainerState::remove(&id);
        managed_state(id.clone()).create().expect("created state");
        let (kernel, init) = kernel_with_init();
        let mut guard =
            ManagedCarrierControl::start(kernel, init.task().key(), &id, "launch-authorization:77")
                .expect("managed control");
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        let mut mounts = dispatcher.prepare_mount_retirement();
        let expected_mounts = mounts.mount_count();
        guard
            .archive_admission_slot()
            .expect("archive slot")
            .install(Arc::new(ArchiveRuntime::new(
                dispatcher.archive_authority(),
                1,
            )))
            .expect("install archive authority");
        drop(dispatcher);
        assert!(
            mounts.prepare().is_err(),
            "the live control server must retain its archive mount authority"
        );

        guard.quiesce();
        mounts.prepare().expect("quiesce releases archive owner");
        assert_eq!(mounts.clear(), expected_mounts);
        let draining = crate::container::ContainerState::load(&id).expect("draining state");
        assert_eq!(draining.status, crate::container::ContainerStatus::Running);
        assert_eq!(draining.exit_code, None);

        guard.complete(42).expect("complete after quiesce");
        let exited = crate::container::ContainerState::load(&id).expect("terminal state");
        assert_eq!(exited.status, crate::container::ContainerStatus::Exited);
        assert_eq!(exited.exit_code, Some(42));
        assert!(exited.control.is_none());
        let _ = crate::container::ContainerState::remove(&id);
    }

    #[test]
    fn managed_control_refuses_to_overwrite_a_terminal_state() {
        let id = format!("control-stale-launch-{}", std::process::id());
        let _ = crate::container::ContainerState::remove(&id);
        let mut state = managed_state(id.clone());
        state.status = crate::container::ContainerStatus::Exited;
        state.exit_code = Some(125);
        state.create().expect("terminal state");
        let (kernel, init) = kernel_with_init();

        ManagedCarrierControl::start(kernel, init.task().key(), &id, "launch-authorization:77")
            .expect_err("stale boot must not overwrite terminal state");

        let preserved = crate::container::ContainerState::load(&id).expect("preserved state");
        assert_eq!(preserved.status, crate::container::ContainerStatus::Exited);
        assert_eq!(preserved.exit_code, Some(125));
        assert!(preserved.control.is_none());
        let _ = crate::container::ContainerState::remove(&id);
    }

    #[test]
    fn archive_paths_are_guest_absolute_and_lexically_contained() {
        assert!(ArchiveRequest::new("/var/lib/app").is_ok());
        assert!(ArchiveRequest::new("relative/path").is_err());
        assert!(ArchiveRequest::new("/var/../etc").is_err());
        assert!(ArchiveRequest::new("/var/./lib").is_err());
        assert!(ArchiveRequest::new("/tmp/\0escape").is_err());
    }

    #[test]
    fn maximum_archive_chunk_fits_one_control_frame() {
        let request = ControlRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: ControlNonce([1; 16]),
            owner_nonce: ControlNonce([2; 16]),
            expected_init: ControlTaskKey { pid: 1, serial: 1 },
            operation: ControlOperation::ArchiveWriteChunk {
                capability: ArchiveCapability::from(ControlNonce([3; 16])),
                bytes: vec![0_u8; MAX_ARCHIVE_CHUNK_BYTES],
                eof: false,
            },
        };
        let encoded = serde_json::to_vec(&request).expect("serialize maximum archive chunk");
        assert!(
            encoded.len() <= MAX_CONTROL_FRAME,
            "maximum archive chunk encoded to {} bytes above {MAX_CONTROL_FRAME}",
            encoded.len(),
        );
    }

    #[test]
    fn authenticated_archive_chunks_mutate_only_the_carrier_vfs() {
        let (_temp, endpoint) = endpoint::test_endpoint("control-archive");
        let (kernel, init) = kernel_with_init();
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        let mut fixture = tar::Builder::new(Vec::new());
        let mut dest = tar::Header::new_gnu();
        dest.set_size(0);
        dest.set_mode(0o755);
        dest.set_entry_type(tar::EntryType::Directory);
        dest.set_cksum();
        fixture
            .append_data(&mut dest, "dest", std::io::empty())
            .expect("destination");
        dispatcher
            .archive_import_tar("/", &fixture.into_inner().expect("fixture"))
            .expect("seed destination");
        let archive_runtime = Arc::new(ArchiveRuntime::new(dispatcher.archive_authority(), 4));
        let mut server = CarrierControlServer::start_at(
            Arc::clone(&kernel),
            init.task().key(),
            endpoint.clone(),
        )
        .expect("server");
        server
            .archive_admission_slot()
            .expect("archive slot")
            .install(archive_runtime)
            .expect("install archive runtime");
        let state = server.state();
        let accepted = send_at(
            &endpoint,
            &state,
            ControlOperation::ArchiveBeginWrite {
                request: ArchiveRequest::new("/dest").expect("request"),
            },
        )
        .expect("begin write");
        let ControlOutcome::ArchiveAccepted { capability } = accepted else {
            panic!("unexpected archive admission: {accepted:?}");
        };

        let mut payload = tar::Builder::new(Vec::new());
        let mut file = tar::Header::new_gnu();
        file.set_size(7);
        file.set_mode(0o600);
        file.set_entry_type(tar::EntryType::Regular);
        file.set_cksum();
        payload
            .append_data(&mut file, "payload", &b"archive"[..])
            .expect("payload");
        let payload = payload.into_inner().expect("payload bytes");
        assert!(payload.len() <= MAX_ARCHIVE_CHUNK_BYTES);
        assert_eq!(
            send_at(
                &endpoint,
                &state,
                ControlOperation::ArchiveWriteChunk {
                    capability,
                    bytes: payload,
                    eof: true,
                },
            )
            .expect("complete upload"),
            ControlOutcome::ArchiveComplete,
        );
        assert_eq!(
            dispatcher.read_exec_file("/dest/payload").as_deref(),
            Some(&b"archive"[..])
        );
        server.shutdown();
    }
}
