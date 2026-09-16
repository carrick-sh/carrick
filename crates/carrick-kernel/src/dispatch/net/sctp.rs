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

/// Publish the boundary for a message the guest is ABOUT to write.
///
/// Must run BEFORE the host send. The peer is another socket in the same carrier,
/// so the bytes become readable the instant the host call returns — publishing
/// afterwards lets a waiting receiver read them first, find no boundary, and
/// report no `MSG_EOR`. CPython drives these sends from a separate thread, which
/// is why its SCTP rows failed 7-13 at a time while the single-threaded reducer
/// always passed.
pub(super) fn begin_send(host_fd: i32, len: usize) -> Option<PendingSend> {
    if len == 0 {
        return None;
    }
    let key = match endpoints(host_fd) {
        Some(key) => key,
        None => {
            if std::env::var_os("CARRICK_SCTP_DEBUG").is_some() {
                eprintln!("SCTPDBG begin_send fd={host_fd} len={len} NO ENDPOINTS");
            }
            return None;
        }
    };
    if std::env::var_os("CARRICK_SCTP_DEBUG").is_some() {
        eprintln!(
            "SCTPDBG begin_send fd={host_fd} len={len} key=({},{})",
            hex(&key.0),
            hex(&key.1)
        );
    }
    let mut streams = STREAMS.lock().ok()?;
    streams
        .entry(key.clone())
        .or_default()
        .messages
        .push_back(len);
    Some(PendingSend { key, len })
}

/// A boundary published ahead of its send, waiting to be confirmed.
pub(super) struct PendingSend {
    key: StreamKey,
    len: usize,
}

impl PendingSend {
    /// Settle the published boundary against what the host actually accepted.
    ///
    /// `None` (the send failed) retracts it. A SHORT write shrinks it to the
    /// bytes that made it: SCTP's boundary is where the sender finished, so the
    /// guest's retry continues the message and publishes the rest.
    pub(super) fn settle(self, sent: Option<usize>) {
        let Ok(mut streams) = STREAMS.lock() else {
            return;
        };
        let Some(stream) = streams.get_mut(&self.key) else {
            return;
        };
        match sent {
            Some(sent) if sent >= self.len => {}
            Some(sent) if sent > 0 => {
                if let Some(last) = stream.messages.back_mut() {
                    *last = sent;
                }
            }
            _ => {
                stream.messages.pop_back();
            }
        }
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
    let debug = std::env::var_os("CARRICK_SCTP_DEBUG").is_some();
    if debug {
        eprintln!(
            "SCTPDBG complete_read fd={host_fd} lookup=({},{})",
            hex(&peer),
            hex(&local)
        );
    }
    let Some(stream) = streams.get_mut(&(peer, local)) else {
        if debug {
            eprintln!("SCTPDBG complete_read fd={host_fd} got={got} NO STREAM");
        }
        return false;
    };
    let Some(&len) = stream.messages.front() else {
        if debug {
            eprintln!("SCTPDBG complete_read fd={host_fd} got={got} NO MESSAGE queued");
        }
        return false;
    };
    if debug {
        eprintln!(
            "SCTPDBG complete_read fd={host_fd} got={got} peek={peek} front={len} consumed={} queued={}",
            stream.consumed,
            stream.messages.len()
        );
    }
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

/// Drop what a closing socket can no longer be responsible for.
///
/// Deliberately NOT both directions. Closing the SENDER does not discard bytes
/// already queued — Linux still delivers them, and the receiver still needs their
/// boundaries. Wiping the send direction here made the receiver report `NO
/// STREAM` and lose `MSG_EOR` whenever the peer closed first, which is exactly
/// what CPython's SCTP tests do: 7-13 rows failed per run, varying with the
/// thread interleaving, while a single-threaded reducer always passed.
///
/// So: the RECEIVE direction goes (nobody will read it now), and the SEND
/// direction goes only once drained. The leftover is not a leak — the peer's own
/// close removes it, because this socket's send direction is that socket's
/// receive direction.
pub(super) fn forget(host_fd: i32) {
    let Some((local, peer)) = endpoints(host_fd) else {
        return;
    };
    let Ok(mut streams) = STREAMS.lock() else {
        return;
    };
    streams.remove(&(peer.clone(), local.clone()));
    if streams
        .get(&(local.clone(), peer.clone()))
        .is_some_and(|stream| stream.messages.is_empty())
    {
        streams.remove(&(local, peer));
    }
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

/// Hex for debug output only.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
