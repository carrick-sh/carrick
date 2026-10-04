//! Length-prefixed framing for the kernel debug socket.
//!
//! The declared length is authoritative. Writers half-close for teardown;
//! readers never wait for EOF after a complete frame. Both protocols share
//! framing and the server's cancellation-aware socket transport.
//!
//! Only clients impose a transport deadline, to bound a dead peer. Snapshot
//! collection retains its own authority budgets and named refusals.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

/// Requests are tiny; anything larger is a protocol abuse, not a big query.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Canonical JSON responses are capped so one wedged reader cannot be made to
/// allocate without bound.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// The production client uses a two-second request budget.
pub const DEADLINE: Duration = Duration::from_secs(2);
/// How long the server lets the coherent snapshot wait for its authorities.
/// Strictly inside [`DEADLINE`]: a snapshot allowed the whole budget made a
/// wedged carrier's named `Busy`/`TimedOut` reply lose the race to the
/// client's own deadline, so the client could only report "timed out".
pub const STRICT_SNAPSHOT_BUDGET: Duration = Duration::from_millis(900);
/// How long the degraded capture that follows a refused strict snapshot may
/// spend on try-locks. [`STRICT_SNAPSHOT_BUDGET`] + this leaves the rest of
/// [`DEADLINE`] to encode and write the reply.
pub const DEGRADED_BUDGET: Duration = Duration::from_millis(400);

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("kernel debug {side} timed out after {}ms", .elapsed.as_millis())]
    TimedOut {
        side: &'static str,
        elapsed: Duration,
    },
    #[error("kernel debug frame declares {declared} bytes, over the {cap}-byte cap")]
    FrameTooLarge { declared: usize, cap: usize },
    #[error("kernel debug frame ended after {read} of {declared} bytes")]
    Truncated { declared: usize, read: usize },
    #[error("kernel debug payload is not valid JSON: {0}")]
    Json(String),
    #[error("kernel debug transport failed: {0}")]
    Io(#[from] std::io::Error),
}

impl WireError {
    /// A deadline expiry the CLI must surface as a timeout even when the
    /// runtime is wedged and never answers.
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::TimedOut { .. })
    }
}

/// Remaining budget, or a timeout error once the deadline has passed.
fn remaining(
    deadline: Instant,
    side: &'static str,
    started: Instant,
) -> Result<Duration, WireError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(WireError::TimedOut {
            side,
            elapsed: now.saturating_duration_since(started),
        });
    }
    Ok(deadline - now)
}

fn classify(error: std::io::Error, side: &'static str, started: Instant) -> WireError {
    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        return WireError::TimedOut {
            side,
            elapsed: started.elapsed(),
        };
    }
    WireError::Io(error)
}

use super::super::socket_rpc::{self, FrameError, FrameStream};

impl From<FrameError> for WireError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::TooLarge { declared, cap } => Self::FrameTooLarge { declared, cap },
            FrameError::Truncated { declared, read } => Self::Truncated { declared, read },
            FrameError::Io(error) => Self::Io(error),
        }
    }
}

// A client deadline decorates I/O, not the framing protocol. The server uses
// the same framer directly with a cancellation-aware Connection, without this
// decorator or a wall-clock transport deadline.
struct DeadlineIo<'a, S> {
    stream: &'a mut S,
    deadline: Instant,
    started: Instant,
    side: &'static str,
}

impl<S> DeadlineIo<'_, S> {
    fn check(&self) -> std::io::Result<()> {
        remaining(self.deadline, self.side, self.started)
            .map(|_| ())
            .map_err(|error| std::io::Error::new(ErrorKind::TimedOut, error))
    }

    fn classify(&self, error: FrameError) -> WireError {
        match error {
            FrameError::Io(error) => classify(error, self.side, self.started),
            error => error.into(),
        }
    }
}

impl<S: Read> Read for DeadlineIo<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.check()?;
        self.stream.read(bytes)
    }
}

impl<S: Write> Write for DeadlineIo<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl<S: Write + SocketDeadline> FrameStream for DeadlineIo<'_, S> {
    fn finish_frame(&mut self) -> std::io::Result<()> {
        self.stream.shutdown_write().map_err(|error| match error {
            WireError::Io(error) => error,
            error => std::io::Error::other(error),
        })
    }
}

/// Write one authoritative frame under the client's existing request budget.
pub fn write_frame<S: Write + SocketDeadline>(
    stream: &mut S,
    payload: &[u8],
    cap: usize,
    deadline: Instant,
    side: &'static str,
) -> Result<(), WireError> {
    let started = Instant::now();
    stream.set_write_deadline(Some(remaining(deadline, side, started)?))?;
    let mut bounded = DeadlineIo {
        stream,
        deadline,
        started,
        side,
    };
    socket_rpc::write_frame(&mut bounded, payload, cap).map_err(|error| bounded.classify(error))
}

/// Read one authoritative frame under the client's existing request budget.
pub fn read_frame<S: Read + SocketDeadline>(
    stream: &mut S,
    cap: usize,
    deadline: Instant,
    side: &'static str,
) -> Result<Vec<u8>, WireError> {
    let started = Instant::now();
    stream.set_read_deadline(Some(remaining(deadline, side, started)?))?;
    let mut bounded = DeadlineIo {
        stream,
        deadline,
        started,
        side,
    };
    socket_rpc::read_frame(&mut bounded, cap).map_err(|error| bounded.classify(error))
}

/// Deadline control over a stream. Implemented for `UnixStream`; the in-memory
/// test double implements it as a no-op so framing can be tested without a
/// socket.
///
/// Read and write deadlines are set independently and never together. Darwin
/// rejects `setsockopt(SO_SNDTIMEO)` with `EINVAL` once the write half has
/// been shut down, so a combined setter would fail on every response read —
/// the reader always runs after its own `shutdown(SHUT_WR)`.
pub trait SocketDeadline {
    fn set_read_deadline(&mut self, budget: Option<Duration>) -> Result<(), WireError>;
    fn set_write_deadline(&mut self, budget: Option<Duration>) -> Result<(), WireError>;
    fn shutdown_write(&mut self) -> Result<(), WireError>;
}

impl SocketDeadline for std::os::unix::net::UnixStream {
    fn set_read_deadline(&mut self, budget: Option<Duration>) -> Result<(), WireError> {
        let budget = budget.map(|d| d.max(Duration::from_micros(1)));
        if let Err(error) = self.set_read_timeout(budget) {
            // Darwin / BSD returns EINVAL from `setsockopt(SO_RCVTIMEO)` when
            // the socket has already been shut down or its peer has closed.
            // Any data previously written by the peer is already buffered and
            // readable without blocking; once drained, read returns EOF.
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(WireError::Io(error));
            }
        }
        Ok(())
    }

    fn set_write_deadline(&mut self, budget: Option<Duration>) -> Result<(), WireError> {
        let budget = budget.map(|d| d.max(Duration::from_micros(1)));
        if let Err(error) = self.set_write_timeout(budget) {
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(WireError::Io(error));
            }
        }
        Ok(())
    }

    fn shutdown_write(&mut self) -> Result<(), WireError> {
        self.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }
}

/// Encode canonical JSON. `serde_json`'s compact form over structs with fixed
/// field order is deterministic, so the same snapshot always yields the same
/// bytes and can be hashed as evidence.
pub fn encode_canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(value).map_err(|error| WireError::Json(error.to_string()))
}

/// Decode, refusing unknown fields (the DTOs are `deny_unknown_fields`) and
/// any trailing bytes inside the JSON payload itself.
pub fn decode_exact<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, WireError> {
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let value =
        T::deserialize(&mut deserializer).map_err(|error| WireError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| WireError::Json(error.to_string()))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep the peer's write side open after a complete frame. No EOF can
    // arrive: completion must be determined by the declared length alone.
    fn complete_frame_without_eof(side: &'static str) {
        let (mut peer, mut reader) = std::os::unix::net::UnixStream::pair().expect("pair");
        peer.write_all(&framed(b"complete")).expect("write frame");
        let result = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            side,
        );
        assert_eq!(
            result.expect("complete frame must not wait for EOF"),
            b"complete"
        );
        drop(peer);
    }

    #[test]
    fn server_read_completes_before_the_peer_half_closes() {
        complete_frame_without_eof("server-read");
    }

    #[test]
    fn client_read_completes_before_the_peer_half_closes() {
        complete_frame_without_eof("client-read");
    }

    /// In-memory duplex that records what was written and replays a scripted
    /// read stream, so framing rules are testable without a real socket.
    struct Duplex {
        incoming: std::io::Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
        shutdown: bool,
    }

    impl Duplex {
        fn reading(bytes: Vec<u8>) -> Self {
            Self {
                incoming: std::io::Cursor::new(bytes),
                outgoing: Vec::new(),
                shutdown: false,
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.incoming.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.outgoing.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SocketDeadline for Duplex {
        fn set_read_deadline(&mut self, _budget: Option<Duration>) -> Result<(), WireError> {
            Ok(())
        }

        fn set_write_deadline(&mut self, _budget: Option<Duration>) -> Result<(), WireError> {
            Ok(())
        }

        fn shutdown_write(&mut self) -> Result<(), WireError> {
            self.shutdown = true;
            Ok(())
        }
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn round_trip_frame_preserves_payload_and_half_closes() {
        let mut stream = Duplex::reading(Vec::new());
        write_frame(
            &mut stream,
            b"payload",
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect("write frame");
        assert_eq!(stream.outgoing, framed(b"payload"));
        assert!(
            stream.shutdown,
            "writer half-close is optional teardown after frame completion"
        );

        let mut reader = Duplex::reading(framed(b"payload"));
        let payload = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect("read frame");
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn bytes_beyond_the_authoritative_frame_are_not_read_or_dispatched() {
        let mut bytes = framed(b"payload");
        bytes.extend_from_slice(&framed(b"another request"));
        let mut reader = Duplex::reading(bytes);
        let payload = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect("complete first frame");
        assert_eq!(payload, b"payload");
        assert_eq!(
            reader.incoming.position() as usize,
            framed(b"payload").len()
        );
    }

    #[test]
    fn a_frame_over_the_cap_is_refused_before_allocating() {
        let declared = (MAX_REQUEST_BYTES + 1) as u32;
        let mut reader = Duplex::reading(declared.to_be_bytes().to_vec());
        let error = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect_err("oversized frame must be refused");
        assert!(
            matches!(error, WireError::FrameTooLarge { cap, .. } if cap == MAX_REQUEST_BYTES),
            "expected cap rejection, got {error:?}"
        );
    }

    #[test]
    fn a_truncated_payload_is_refused_rather_than_returned_short() {
        let mut bytes = (8_u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut reader = Duplex::reading(bytes);
        let error = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect_err("truncated payload must be refused");
        assert!(
            matches!(
                error,
                WireError::Truncated {
                    declared: 8,
                    read: 3
                }
            ),
            "expected truncation rejection, got {error:?}"
        );
    }

    #[test]
    fn an_expired_deadline_reports_a_timeout_not_an_io_error() {
        let mut reader = Duplex::reading(framed(b"payload"));
        let error = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() - Duration::from_millis(1),
            "client",
        )
        .expect_err("expired deadline must fail");
        assert!(
            error.is_timeout(),
            "expected a named timeout, got {error:?}"
        );
    }

    /// Framing over a REAL socket pair, not the in-memory double. The double
    /// cannot catch platform `setsockopt`/`shutdown` ordering rules, and those
    /// are exactly what broke the first live server.
    #[test]
    fn framing_round_trips_over_a_real_socket_pair() {
        let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let deadline = Instant::now() + DEADLINE;

        let worker = std::thread::spawn(move || {
            let request = read_frame(&mut server, MAX_REQUEST_BYTES, deadline, "server-read")
                .expect("server reads the request");
            assert_eq!(request, b"ping");
            write_frame(
                &mut server,
                b"pong",
                MAX_RESPONSE_BYTES,
                deadline,
                "server-write",
            )
            .expect("server writes the response");
        });

        write_frame(
            &mut client,
            b"ping",
            MAX_REQUEST_BYTES,
            deadline,
            "client-write",
        )
        .expect("client writes the request");
        // The server worker thread is joined before the client reads the response.
        // This makes deterministic the worst-case timing race observed under
        // heavy host load: the server thread exits and closes its socket half
        // before the client calls `read_frame`. On Darwin, calling `setsockopt(SO_RCVTIMEO)`
        // on a socket whose write half was shut down and whose peer is already
        // closed returns `EINVAL`, but the client must still read the buffered
        // response bytes without aborting.
        worker.join().expect("server thread");
        let response = read_frame(&mut client, MAX_RESPONSE_BYTES, deadline, "client-read")
            .expect("client reads the response");

        assert_eq!(response, b"pong");
    }

    #[test]
    fn an_expired_deadline_over_a_real_socket_reports_a_timeout_not_an_io_error() {
        let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        drop(server);

        // Expired deadline with peer closed must report a named timeout, not an IO error.
        let error = read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            Instant::now() - Duration::from_millis(1),
            "client-read",
        )
        .expect_err("expired deadline must fail");
        assert!(
            error.is_timeout(),
            "expected a named timeout, got {error:?}"
        );

        // Explicit zero budget must be clamped to a non-zero timeout rather than
        // rejected as InvalidInput by the runtime.
        client
            .set_read_deadline(Some(Duration::ZERO))
            .expect("zero read deadline must be clamped");
        client
            .set_write_deadline(Some(Duration::ZERO))
            .expect("zero write deadline must be clamped");
    }

    #[test]
    fn decode_rejects_json_with_trailing_content() {
        let error =
            decode_exact::<serde_json::Value>(b"{} {}").expect_err("trailing JSON must be refused");
        assert!(matches!(error, WireError::Json(_)), "got {error:?}");
    }
}
