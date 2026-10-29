//! Client for the kernel debug socket, shared by `carrick debug
//! hvpatch-kernel` and by the in-process tests.
//!
//! The client's contract is that a wedged runtime produces a named timeout,
//! never a hang: the connect and both frame halves run under one deadline.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use socket2::{Domain, SockAddr, Socket, Type};

use super::dto::{
    KERNEL_DEBUG_DEGRADED_SCHEMA, KERNEL_DEBUG_RESPONSE_SCHEMA, KernelDebugDegraded,
    KernelDebugDtoError, KernelDebugRequest, KernelDebugSnapshot, KernelDebugTable,
};
use super::endpoint::{DebugEndpoint, EndpointError};
use super::post_mortem::{POST_MORTEM_SCHEMA, PostMortem};
use super::wire::{self, DEADLINE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, WireError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("kernel debug endpoint unavailable: {0}")]
    Endpoint(#[from] EndpointError),
    #[error(
        "no kernel debug socket at {path}; the run may have exited or was started without CARRICK_RUN_ID"
    )]
    NotListening { path: String },
    #[error("kernel debug request timed out ({}s request budget); the runtime may be wedged", DEADLINE.as_secs())]
    TimedOut,
    #[error("kernel debug transport failed: {0}")]
    Wire(#[from] WireError),
    #[error("kernel debug response is invalid: {0}")]
    Dto(#[from] KernelDebugDtoError),
    #[error("runtime refused the kernel debug request: {0}")]
    Refused(String),
    /// The runtime could not produce a coherent snapshot and answered with
    /// its degraded per-object view instead. The payload is evidence, not a
    /// snapshot: callers must keep it apart from a validated graph.
    #[error("kernel snapshot degraded ({}); per-task state and busy coordinators attached", .0.strict_error)]
    Degraded(Box<KernelDebugDegraded>),
}

/// Fetch one coherent snapshot for `run_id`, restricted to `tables` when given.
pub fn fetch(
    run_id: &str,
    tables: Option<Vec<KernelDebugTable>>,
) -> Result<KernelDebugSnapshot, ClientError> {
    let endpoint = DebugEndpoint::for_run_id(run_id)?;
    fetch_at(&endpoint, tables)
}

/// Fetch the existing bounded post-mortem shape without aborting a live run.
pub fn capture(run_id: &str) -> Result<PostMortem, ClientError> {
    let endpoint = DebugEndpoint::for_run_id(run_id)?;
    let payload = exchange_at(
        &endpoint,
        &KernelDebugRequest::capture(run_id),
        ResponseWait::Deadline(Instant::now() + DEADLINE),
    )?;
    if let Ok(refusal) = wire::decode_exact::<ServerRefusal>(&payload)
        && refusal.schema == KERNEL_DEBUG_RESPONSE_SCHEMA
    {
        return Err(ClientError::Refused(refusal.error));
    }
    let capture: PostMortem = wire::decode_exact(&payload)?;
    if capture.schema != POST_MORTEM_SCHEMA || capture.run_id.as_deref() != Some(run_id) {
        return Err(ClientError::Refused(
            "capture schema or run identity mismatch".to_owned(),
        ));
    }
    Ok(capture)
}

/// Ask the run identified by `run_id` to abort its kernel.
///
/// Returns the acknowledgement: the run id the runtime stamped and the
/// directory it will write the post-mortem into, when one is configured. The
/// capture itself is produced by the runtime's own runner boundary and
/// travels to the embedding caller as `EmbedError::KernelAborted`.
pub fn kernel_debug_abort(run_id: &str) -> Result<AbortAck, ClientError> {
    let endpoint = DebugEndpoint::for_run_id(run_id)?;
    abort_at(&endpoint, run_id)
}

pub fn abort_at(endpoint: &DebugEndpoint, run_id: &str) -> Result<AbortAck, ClientError> {
    abort_at_with_wait(
        endpoint,
        run_id,
        ResponseWait::Deadline(Instant::now() + DEADLINE),
    )
}

pub(super) fn abort_at_with_wait(
    endpoint: &DebugEndpoint,
    run_id: &str,
    wait: ResponseWait,
) -> Result<AbortAck, ClientError> {
    let payload = exchange_at(
        endpoint,
        &crate::kernel::debug::dto::KernelDebugRequest::abort(run_id),
        wait,
    )?;
    if let Ok(refusal) = wire::decode_exact::<ServerRefusal>(&payload)
        && refusal.schema == KERNEL_DEBUG_RESPONSE_SCHEMA
    {
        return Err(ClientError::Refused(refusal.error));
    }
    let ack: AbortAck = wire::decode_exact(&payload)?;
    if ack.schema != KERNEL_DEBUG_RESPONSE_SCHEMA {
        return Err(ClientError::Refused(format!(
            "unknown abort response schema {}",
            ack.schema
        )));
    }
    Ok(ack)
}

/// The runtime accepted an abort request.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortAck {
    pub schema: String,
    pub run_id: String,
    #[serde(default)]
    pub post_mortem_dir: Option<String>,
}

fn connect(endpoint: &DebugEndpoint, deadline: Instant) -> Result<UnixStream, ClientError> {
    let result = (|| -> io::Result<UnixStream> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let address = SockAddr::unix(endpoint.socket_path())?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&address) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Linux AF_UNIX backlog saturation does not admit a pending
                // connection. Polling this socket would report HUP, not wait
                // for admission. Fail closed without retrying the request.
                return Err(io::ErrorKind::TimedOut.into());
            }
            Err(error)
                if error.raw_os_error() == Some(libc::EINPROGRESS)
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                wait_connected(&socket, deadline)?;
            }
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        socket.set_nonblocking(false)?;
        Ok(socket.into())
    })();
    result.map_err(|error| match error.kind() {
        io::ErrorKind::TimedOut => ClientError::TimedOut,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ClientError::NotListening {
            path: endpoint.socket_path().display().to_string(),
        },
        _ => ClientError::Wire(WireError::Io(error)),
    })
}

fn wait_connected(socket: &Socket, deadline: Instant) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // Round up to a positive millisecond and recheck the absolute budget
        // after every wake, including EINTR. No fresh timeout per attempt.
        let milliseconds = remaining.as_millis().saturating_add(1);
        let timeout = milliseconds.min(libc::c_int::MAX as u128) as libc::c_int;
        // SAFETY: descriptor is one initialized pollfd; socket owns its fd
        // for this entire call. poll does not retain the pointer.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        if let Some(error) = socket.take_error()? {
            return Err(error);
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "debug connect poll failed",
            ));
        }
        if descriptor.revents & libc::POLLOUT != 0 {
            return Ok(());
        }
    }
}

/// Fetch from an exact endpoint.
pub fn fetch_at(
    endpoint: &DebugEndpoint,
    tables: Option<Vec<KernelDebugTable>>,
) -> Result<KernelDebugSnapshot, ClientError> {
    fetch_at_with_wait(
        endpoint,
        tables,
        ResponseWait::Deadline(Instant::now() + DEADLINE),
    )
}

pub(super) fn fetch_at_with_wait(
    endpoint: &DebugEndpoint,
    tables: Option<Vec<KernelDebugTable>>,
    wait: ResponseWait,
) -> Result<KernelDebugSnapshot, ClientError> {
    let request = KernelDebugRequest::for_tables(tables);
    let requested = request.selected();
    let payload = exchange_at(endpoint, &request, wait)?;

    // An error response shares the schema tag but has no tables, so try the
    // refusal shape first and report the runtime's own reason.
    if let Ok(refusal) = wire::decode_exact::<ServerRefusal>(&payload)
        && refusal.schema == KERNEL_DEBUG_RESPONSE_SCHEMA
    {
        return Err(ClientError::Refused(refusal.error));
    }
    if let Ok(degraded) = wire::decode_exact::<KernelDebugDegraded>(&payload)
        && degraded.schema == KERNEL_DEBUG_DEGRADED_SCHEMA
    {
        return Err(ClientError::Degraded(Box::new(degraded)));
    }

    let snapshot: KernelDebugSnapshot = wire::decode_exact(&payload)?;
    snapshot.validate(&requested)?;
    Ok(snapshot)
}

pub(super) enum ResponseWait {
    Deadline(Instant),
    #[cfg(test)]
    Completion,
}

// Production and completion-observing semantic tests use one protocol path.
// Connection admission always has a dead-peer guard; Completion observes
// frame completion without imposing the operator's response deadline.
fn exchange_at(
    endpoint: &DebugEndpoint,
    request: &KernelDebugRequest,
    wait: ResponseWait,
) -> Result<Vec<u8>, ClientError> {
    let connect_deadline = match &wait {
        ResponseWait::Deadline(deadline) => *deadline,
        #[cfg(test)]
        ResponseWait::Completion => Instant::now() + DEADLINE,
    };
    let mut stream = connect(endpoint, connect_deadline)?;
    let encoded = wire::encode_canonical(request)?;
    match wait {
        ResponseWait::Deadline(deadline) => {
            timeout_aware(wire::write_frame(
                &mut stream,
                &encoded,
                MAX_REQUEST_BYTES,
                deadline,
                "client-write",
            ))?;
            timeout_aware(wire::read_frame(
                &mut stream,
                MAX_RESPONSE_BYTES,
                deadline,
                "client-read",
            ))
        }
        #[cfg(test)]
        ResponseWait::Completion => {
            super::super::socket_rpc::write_frame(&mut stream, &encoded, MAX_REQUEST_BYTES)
                .map_err(WireError::from)?;
            super::super::socket_rpc::read_frame(&mut stream, MAX_RESPONSE_BYTES)
                .map_err(WireError::from)
                .map_err(ClientError::from)
        }
    }
}

fn timeout_aware<T>(result: Result<T, WireError>) -> Result<T, ClientError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if error.is_timeout() => Err(ClientError::TimedOut),
        Err(error) => Err(ClientError::Wire(error)),
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRefusal {
    schema: String,
    error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn expired_deadline_does_not_connect() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let endpoint = DebugEndpoint::in_base(directory.path().to_owned(), "expired")?;
        std::fs::create_dir_all(endpoint.directory())?;
        let listener = std::os::unix::net::UnixListener::bind(endpoint.socket_path())?;
        listener.set_nonblocking(true)?;
        assert!(matches!(
            connect(&endpoint, Instant::now()),
            Err(ClientError::TimedOut)
        ));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    }

    #[test]
    fn connect_poll_obeys_deadline() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;

        // Exercise the pending-connect poll on every host, including Linux
        // where AF_UNIX backlog overflow never starts a pending connection.
        let (mut writer, reader) = UnixStream::pair()?;
        writer.set_nonblocking(true)?;
        let mut saturated = false;
        for _ in 0..1024 {
            match writer.write(&[0; 16384]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(saturated, "socket must remain unwritable");
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = wait_connected(&writer.into(), Instant::now() + Duration::from_millis(25));
            let _ = send.send(result);
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        // Release even a regressed unbounded poll before reporting failure.
        drop(reader);
        assert!(matches!(result, Ok(Err(error)) if error.kind() == io::ErrorKind::TimedOut));
        assert!(worker.join().is_ok(), "poll worker panicked");
        Ok(())
    }

    // BSD Unix sockets reject backlog overflow with ECONNREFUSED immediately.
    // Linux is the host where the old blocking connect waits for admission.
    #[cfg(target_os = "linux")]
    #[test]
    fn full_listen_backlog_returns_typed_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let endpoint = DebugEndpoint::in_base(directory.path().to_owned(), "backlog")?;
        std::fs::create_dir_all(endpoint.directory())?;
        let address = SockAddr::unix(endpoint.socket_path())?;
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        listener.bind(&address)?;
        listener.listen(1)?;
        let mut pending = Vec::new();
        let mut saturated = false;
        for _ in 0..16 {
            let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            socket.set_nonblocking(true)?;
            let result = socket.connect(&address);
            pending.push(socket);
            match result {
                Ok(()) => {}
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EINPROGRESS) =>
                {
                    saturated = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(saturated, "listener backlog must be full");
        let (send, receive) = mpsc::channel();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let result = fetch_at_with_wait(
                &endpoint,
                None,
                ResponseWait::Deadline(started + Duration::from_millis(100)),
            );
            let _ = send.send(result);
        });
        // The receive bounds the test even when the production connect regresses.
        let result = receive.recv_timeout(Duration::from_secs(2));
        // Closing the listener also releases a regressed blocking connect.
        drop(listener);
        drop(pending);
        assert!(
            matches!(result, Ok(Err(ClientError::TimedOut))),
            "{result:?}"
        );
        assert!(worker.join().is_ok(), "client worker panicked");
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }
}
