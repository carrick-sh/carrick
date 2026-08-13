//! Client for the kernel debug socket, shared by `carrick debug
//! hvpatch-kernel` and by the in-process tests.
//!
//! The client's contract is that a wedged runtime produces a named timeout,
//! never a hang: the connect and both frame halves run under one deadline.

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::dto::{
    KERNEL_DEBUG_RESPONSE_SCHEMA, KernelDebugDtoError, KernelDebugRequest, KernelDebugSnapshot,
    KernelDebugTable,
};
use super::endpoint::{DebugEndpoint, EndpointError};
use super::wire::{self, DEADLINE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, WireError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("kernel debug endpoint unavailable: {0}")]
    Endpoint(#[from] EndpointError),
    #[error(
        "no kernel debug socket at {path}; the run may have exited or was started without CARRICK_RUN_ID"
    )]
    NotListening { path: String },
    #[error("kernel debug request timed out after {}s; the runtime may be wedged", DEADLINE.as_secs())]
    TimedOut,
    #[error("kernel debug transport failed: {0}")]
    Wire(#[from] WireError),
    #[error("kernel debug response is invalid: {0}")]
    Dto(#[from] KernelDebugDtoError),
    #[error("runtime refused the kernel debug request: {0}")]
    Refused(String),
}

/// Fetch one coherent snapshot for `run_id`, restricted to `tables` when given.
pub fn fetch(
    run_id: &str,
    tables: Option<Vec<KernelDebugTable>>,
) -> Result<KernelDebugSnapshot, ClientError> {
    let endpoint = DebugEndpoint::for_run_id(run_id)?;
    fetch_at(&endpoint, tables)
}

/// Fetch from an exact endpoint.
pub fn fetch_at(
    endpoint: &DebugEndpoint,
    tables: Option<Vec<KernelDebugTable>>,
) -> Result<KernelDebugSnapshot, ClientError> {
    let deadline = Instant::now() + DEADLINE;
    let mut stream = UnixStream::connect(endpoint.socket_path()).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ) {
            ClientError::NotListening {
                path: endpoint.socket_path().display().to_string(),
            }
        } else {
            ClientError::Wire(WireError::Io(error))
        }
    })?;

    let request = KernelDebugRequest::for_tables(tables);
    let requested = request.selected();
    let encoded = wire::encode_canonical(&request)?;
    timeout_aware(wire::write_frame(
        &mut stream,
        &encoded,
        MAX_REQUEST_BYTES,
        deadline,
        "client-write",
    ))?;

    let payload = timeout_aware(wire::read_frame(
        &mut stream,
        MAX_RESPONSE_BYTES,
        deadline,
        "client-read",
    ))?;

    // An error response shares the schema tag but has no tables, so try the
    // refusal shape first and report the runtime's own reason.
    if let Ok(refusal) = wire::decode_exact::<ServerRefusal>(&payload)
        && refusal.schema == KERNEL_DEBUG_RESPONSE_SCHEMA
    {
        return Err(ClientError::Refused(refusal.error));
    }

    let snapshot: KernelDebugSnapshot = wire::decode_exact(&payload)?;
    snapshot.validate(&requested)?;
    Ok(snapshot)
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
