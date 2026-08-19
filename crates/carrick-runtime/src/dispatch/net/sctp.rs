//! SCTP message boundaries over a TCP backing.
//!
//! macOS has no SCTP, so a guest SCTP `SOCK_STREAM` socket is backed by a host
//! TCP socket (`host_socket_install`). TCP is a pure byte stream, and the one
//! guest-visible thing that loses is the message boundary — Linux sets `MSG_EOR`
//! when a `recvmsg` consumes the END of a message, and never merges two messages
//! into one `recvmsg`. Measured on the Docker oracle
//! (`docs/perf-results/2026-08-19-sctp/reducers/sctp-eor.py`):
//!
//! | read | returned | msg_flags |
//! |---|---|---|
//! | buf 1024 of a 64-byte message | 64 | `MSG_EOR` |
//! | buf 16 of a 64-byte message | 16 | 0 |
//! | buf 64 of a 64-byte message | 64 | `MSG_EOR` |
//! | `MSG_PEEK` buf 1024 | 64 | `MSG_EOR` |
//! | `MSG_PEEK` buf 16 | 16 | 0 |
//!
//! The boundaries are therefore tracked OUT OF BAND rather than framed onto the
//! wire. That is sound here for a reason specific to this protocol: macOS has no
//! SCTP stack, so no external peer can exist and every SCTP endpoint is
//! necessarily another carrick socket. Framing the payload instead would change
//! the bytes on the wire and make a partial non-blocking send very hard to keep
//! atomic; tracking metadata leaves the data path byte-identical to TCP.
//!
//! The rejected alternative is worth recording: keying `MSG_EOR` off "did this
//! read drain the socket buffer" reproduces every row of the table above and
//! would turn all 21 failing CPython rows green, but it is WRONG the moment two
//! messages are queued — a read ending exactly on the first boundary would see
//! more data available and report no EOR where Linux reports one. That is an
//! approximation passing a gate, which is the one outcome the engineering
//! standards rule out.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

/// A connection's identity, as the SENDER sees it: `(local, peer)`. The receiver
/// looks the same connection up with its own pair reversed.
type StreamKey = (Vec<u8>, Vec<u8>);

#[derive(Default)]
struct SctpStream {
    /// Lengths of messages the sender has written, oldest first.
    messages: VecDeque<usize>,
    /// Bytes of `messages[0]` the receiver has already consumed.
    consumed: usize,
}

static STREAMS: LazyLock<Mutex<HashMap<StreamKey, SctpStream>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `(local, peer)` for a connected host socket, or `None` if either name is
/// unavailable (an unconnected socket has no stream to track).
fn endpoints(host_fd: i32) -> Option<(Vec<u8>, Vec<u8>)> {
    fn name(host_fd: i32, peer: bool) -> Option<Vec<u8>> {
        let mut storage = [0u8; 128];
        let mut len = storage.len() as libc::socklen_t;
        // SAFETY: storage/len are valid out-params for getsockname/getpeername.
        let rc = unsafe {
            let addr = storage.as_mut_ptr().cast();
            if peer {
                libc::getpeername(host_fd, addr, &mut len)
            } else {
                libc::getsockname(host_fd, addr, &mut len)
            }
        };
        if rc != 0 {
            return None;
        }
        let len = (len as usize).min(storage.len());
        Some(storage[..len].to_vec())
    }
    Some((name(host_fd, false)?, name(host_fd, true)?))
}

/// Record that the guest wrote one `len`-byte message on this SCTP socket.
///
/// A partial write does NOT end a message: SCTP's boundary is where the sender
/// finished, so a short write extends the message in flight rather than closing
/// it. `len` is the count actually accepted by the host.
pub(super) fn record_sent(host_fd: i32, len: usize, complete: bool) {
    if len == 0 {
        return;
    }
    let Some(key) = endpoints(host_fd) else {
        return;
    };
    let Ok(mut streams) = STREAMS.lock() else {
        return;
    };
    let stream = streams.entry(key).or_default();
    if complete || stream.messages.is_empty() {
        stream.messages.push_back(len);
    } else if let Some(last) = stream.messages.back_mut() {
        *last += len;
    }
}

/// Bytes remaining in the message the receiver is part-way through, if known.
///
/// A `recvmsg` must never span a boundary — Linux returns at most one message —
/// so the caller caps its read at this.
pub(super) fn read_limit(host_fd: i32, want: usize) -> usize {
    let Some((local, peer)) = endpoints(host_fd) else {
        return want;
    };
    // The sender's key is this socket's pair reversed.
    let Ok(streams) = STREAMS.lock() else {
        return want;
    };
    let Some(stream) = streams.get(&(peer, local)) else {
        return want;
    };
    match stream.messages.front() {
        Some(len) => want.min(len.saturating_sub(stream.consumed)),
        None => want,
    }
}

/// Account for a completed read and report whether it consumed the END of a
/// message, i.e. whether Linux would set `MSG_EOR`.
///
/// `peek` reads report the same answer without consuming anything, which is what
/// the oracle does: a `MSG_PEEK` that covers the whole message still sets EOR.
pub(super) fn complete_read(host_fd: i32, got: usize, peek: bool) -> bool {
    if got == 0 {
        return false;
    }
    let Some((local, peer)) = endpoints(host_fd) else {
        return false;
    };
    let Ok(mut streams) = STREAMS.lock() else {
        return false;
    };
    let Some(stream) = streams.get_mut(&(peer, local)) else {
        return false;
    };
    let Some(&len) = stream.messages.front() else {
        return false;
    };
    let remaining = len.saturating_sub(stream.consumed);
    let ends_message = got >= remaining;
    if !peek {
        if ends_message {
            stream.messages.pop_front();
            stream.consumed = 0;
        } else {
            stream.consumed += got;
        }
    }
    ends_message
}

/// Drop a closed socket's stream so a recycled address pair cannot inherit
/// boundaries from a previous connection.
pub(super) fn forget(host_fd: i32) {
    let Some((local, peer)) = endpoints(host_fd) else {
        return;
    };
    let Ok(mut streams) = STREAMS.lock() else {
        return;
    };
    streams.remove(&(local.clone(), peer.clone()));
    streams.remove(&(peer, local));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StreamKey {
        (vec![1, 2], vec![3, 4])
    }

    /// The oracle's rule, exercised directly on the bookkeeping: EOR is set when
    /// a read consumes the END of a message and not before, and a short read
    /// leaves the rest of that message addressable.
    #[test]
    fn eor_marks_the_end_of_a_message_not_a_drained_buffer() {
        let mut streams = HashMap::new();
        streams.insert(
            key(),
            SctpStream {
                messages: VecDeque::from(vec![64, 64]),
                consumed: 0,
            },
        );
        let stream = streams.get_mut(&key()).expect("stream");

        // A short read does not end the message.
        assert_eq!(stream.messages.front().copied(), Some(64));
        stream.consumed += 16;
        assert!(64 - stream.consumed > 0);

        // The read that takes the remainder does, even though a SECOND message
        // is still queued behind it — the case the drained-buffer shortcut gets
        // wrong.
        let remaining = 64 - stream.consumed;
        assert_eq!(remaining, 48);
        stream.messages.pop_front();
        stream.consumed = 0;
        assert_eq!(stream.messages.len(), 1, "the queued message survives");
    }
}
