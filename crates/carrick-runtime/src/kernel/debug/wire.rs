//! Length-prefixed framing for the kernel debug socket.
//!
//! Exactly one frame travels in each direction, and the sender half-closes
//! afterwards. That makes "trailing bytes" a detectable protocol violation
//! rather than an ambiguity: after the declared payload the reader must see
//! EOF, so a peer that appends anything is refused by name.
//!
//! Both sides run under a deadline. A wedged guest must never wedge the
//! debugger, so every socket read/write carries a timeout derived from the
//! remaining budget and expiry is reported as a named timeout.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

/// Requests are tiny; anything larger is a protocol abuse, not a big query.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Canonical JSON responses are capped so one wedged reader cannot be made to
/// allocate without bound.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Both sides use the same two-second budget.
pub const DEADLINE: Duration = Duration::from_secs(2);

const LENGTH_PREFIX_BYTES: usize = 4;

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
    #[error("kernel debug frame carried {0} trailing byte(s) after the declared payload")]
    TrailingBytes(usize),
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
    if matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    ) {
        return WireError::TimedOut {
            side,
            elapsed: started.elapsed(),
        };
    }
    WireError::Io(error)
}

/// Write one length-prefixed frame and half-close the write side.
pub fn write_frame<S>(
    stream: &mut S,
    payload: &[u8],
    cap: usize,
    deadline: Instant,
    side: &'static str,
) -> Result<(), WireError>
where
    S: Write + SocketDeadline,
{
    if payload.len() > cap {
        return Err(WireError::FrameTooLarge {
            declared: payload.len(),
            cap,
        });
    }
    let started = Instant::now();
    // The cap check above already bounds this, but the conversion carries the
    // proof rather than asserting it: a frame length that cannot be encoded is
    // a refusal, never a panic in a diagnostic path.
    let length = u32::try_from(payload.len()).map_err(|_| WireError::FrameTooLarge {
        declared: payload.len(),
        cap,
    })?;
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);

    // Set the socket timeout ONCE. Re-setting it per iteration is what broke
    // the first live server: on Darwin, `setsockopt` on an `AF_UNIX` socket
    // whose peer has closed AND whose write half is shut down returns
    // `EINVAL`, which turned every successfully completed exchange into a
    // transport failure on the final read. The absolute `deadline` check below
    // is the real bound; the socket timeout only stops one blocking call.
    stream.set_write_deadline(Some(remaining(deadline, side, started)?))?;
    let mut written = 0;
    while written < framed.len() {
        remaining(deadline, side, started)?;
        match stream.write(&framed[written..]) {
            Ok(0) => {
                return Err(WireError::Truncated {
                    declared: framed.len(),
                    read: written,
                });
            }
            Ok(count) => written += count,
            Err(error) => return Err(classify(error, side, started)),
        }
    }
    stream
        .flush()
        .map_err(|error| classify(error, side, started))?;
    stream.shutdown_write()?;
    Ok(())
}

/// Read exactly one length-prefixed frame, then require EOF.
pub fn read_frame<S>(
    stream: &mut S,
    cap: usize,
    deadline: Instant,
    side: &'static str,
) -> Result<Vec<u8>, WireError>
where
    S: Read + SocketDeadline,
{
    let started = Instant::now();
    // One `setsockopt` for the whole exchange — see `write_frame`.
    stream.set_read_deadline(Some(remaining(deadline, side, started)?))?;
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    read_exact(stream, &mut prefix, deadline, side, started)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > cap {
        return Err(WireError::FrameTooLarge { declared, cap });
    }

    let mut payload = vec![0_u8; declared];
    read_exact(stream, &mut payload, deadline, side, started)?;

    // The peer must be done. Any further byte means the frame was not the
    // whole message, which we refuse rather than silently ignore.
    remaining(deadline, side, started)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(payload),
        Ok(count) => Err(WireError::TrailingBytes(count)),
        Err(error) => Err(classify(error, side, started)),
    }
}

fn read_exact<S>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
    side: &'static str,
    started: Instant,
) -> Result<(), WireError>
where
    S: Read,
{
    let declared = buffer.len();
    let mut filled = 0;
    while filled < declared {
        remaining(deadline, side, started)?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(WireError::Truncated {
                    declared,
                    read: filled,
                });
            }
            Ok(count) => filled += count,
            Err(error) => return Err(classify(error, side, started)),
        }
    }
    Ok(())
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
        self.set_read_timeout(budget)?;
        Ok(())
    }

    fn set_write_deadline(&mut self, budget: Option<Duration>) -> Result<(), WireError> {
        self.set_write_timeout(budget)?;
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
            "writer must half-close so the peer can detect end of frame"
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
    fn trailing_bytes_after_the_declared_payload_are_refused() {
        let mut bytes = framed(b"payload");
        bytes.push(b'!');
        let mut reader = Duplex::reading(bytes);
        let error = read_frame(
            &mut reader,
            MAX_REQUEST_BYTES,
            Instant::now() + DEADLINE,
            "test",
        )
        .expect_err("trailing bytes must be refused");
        assert!(
            matches!(error, WireError::TrailingBytes(1)),
            "expected trailing-byte rejection, got {error:?}"
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
        let response = read_frame(&mut client, MAX_RESPONSE_BYTES, deadline, "client-read")
            .expect("client reads the response");
        assert_eq!(response, b"pong");
        worker.join().expect("server thread");
    }

    #[test]
    fn decode_rejects_json_with_trailing_content() {
        let error =
            decode_exact::<serde_json::Value>(b"{} {}").expect_err("trailing JSON must be refused");
        assert!(matches!(error, WireError::Json(_)), "got {error:?}");
    }
}
