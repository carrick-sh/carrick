//! Linux's UDP error queue (`IP_RECVERR` / `IPV6_RECVERR`) on Darwin.
//!
//! # Why this exists
//!
//! Linux reports an ICMP error (typically port-unreachable) on an
//! **unconnected** datagram socket only if the socket asked, via `IP_RECVERR`,
//! and then delivers it twice: once as the next `recvmsg`'s errno, and once as
//! an entry on a per-socket ERROR QUEUE readable with `recvmsg(MSG_ERRQUEUE)`
//! carrying a `sock_extended_err` cmsg plus the offending peer's address.
//!
//! Darwin has neither the option nor the queue, and measured on macOS 27 it
//! reports nothing at all for an unconnected socket:
//!
//! ```text
//! unconnected: sendto -> ok; SO_ERROR 0; poll 0 revents; recv -> EAGAIN
//! connected:   send   -> ok; recv -> ECONNREFUSED
//! ```
//!
//! Only a CONNECTED socket learns about it. So Carrick sends through a
//! **shadow** socket bound to the same local `addr:port` as the guest's socket
//! and connected to the destination. The wire is unchanged — same source
//! address, same single packet — the guest's real socket keeps receiving from
//! anyone, and the ICMP error lands on the shadow, where Darwin will report it.
//! Measured: the shadow reads `ECONNREFUSED` while the real socket still
//! receives a third party's datagram and the shadow does not steal it.
//!
//! # The `SO_REUSEPORT` prerequisite, and how the divergence it would cause is
//! prevented
//!
//! The shadow can only share the port if the REAL socket also carries host
//! `SO_REUSEPORT` — measured: with the real socket bound plain, the shadow's
//! bind fails `EADDRINUSE`. Carrick therefore sets host `SO_REUSEPORT` on a
//! socket that enabled `IP_RECVERR`, which is safe to do because libuv (and the
//! `IP_RECVERR` idiom generally) sets the option BEFORE `bind`.
//!
//! That host-side flag would otherwise let a SECOND error-queue socket bind the
//! same `addr:port`, which Linux refuses. [`reserve_bind`] closes that hole by
//! keeping the set of bound error-queue addresses and answering `EADDRINUSE`
//! itself. A socket that did NOT enable `IP_RECVERR` still has no
//! `SO_REUSEPORT`, so Darwin keeps refusing it the ordinary way.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};

/// One queued error-queue entry: the errno Linux would report, and the
/// offending peer's address as raw host `sockaddr` bytes (`SO_EE_OFFENDER`).
#[derive(Debug, Clone)]
pub(super) struct ErrEntry {
    pub(super) errno: i32,
    pub(super) offender: Vec<u8>,
    pub(super) is_ipv6: bool,
}

#[derive(Debug, Default)]
struct State {
    /// True once the guest set `IP_RECVERR`/`IPV6_RECVERR`.
    enabled: bool,
    is_ipv6: bool,
    /// The shadow socket and the destination it is currently connected to.
    shadow: Option<(i32, Vec<u8>)>,
    /// Address this socket bound, so `close` can release the reservation.
    bound: Option<Vec<u8>>,
    /// Entries waiting for `recvmsg(MSG_ERRQUEUE)`.
    queue: VecDeque<ErrEntry>,
    /// Retained for the readiness predicate only: an error has been observed
    /// even if the queue entry has since been consumed. The ordinary read
    /// NEVER reports it — with `IP_RECVERR` the error belongs to the queue,
    /// which is the whole point of the option, and `udp_send_unreachable` fails
    /// outright if a plain read returns a negative nread without the
    /// `UV_UDP_LINUX_RECVERR` flag.
    seen: Option<i32>,
}

/// CARRIER-WIDE, keyed by the guest socket's host fd. Sockets are host kernel
/// objects, so this is the host's own scope; entries are removed EXPLICITLY on
/// close because host fds are reused.
static STATE: LazyLock<Mutex<HashMap<i32, State>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Host `addr:port`s currently bound by an error-queue socket. See the module
/// header: this is what keeps the host `SO_REUSEPORT` from letting two of them
/// share a port that Linux would not.
static BOUND: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<i32, State>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The guest set `IP_RECVERR`/`IPV6_RECVERR` on this socket.
pub(super) fn enable(host_fd: i32, is_ipv6: bool) {
    let mut state = lock();
    let entry = state.entry(host_fd).or_default();
    entry.enabled = true;
    entry.is_ipv6 = is_ipv6;
}

/// Whether this socket opted into the error queue.
pub(super) fn is_enabled(host_fd: i32) -> bool {
    lock().get(&host_fd).is_some_and(|s| s.enabled)
}

/// Reserve `host_addr` for this error-queue socket, or report that another one
/// already holds it. Linux answers `EADDRINUSE` for the second bind; Darwin
/// would allow it, because Carrick had to set `SO_REUSEPORT` to make the shadow
/// possible.
pub(super) fn reserve_bind(host_fd: i32, host_addr: &[u8]) -> bool {
    let mut bound = BOUND.lock().unwrap_or_else(|e| e.into_inner());
    if !bound.insert(host_addr.to_vec()) {
        return false;
    }
    lock().entry(host_fd).or_default().bound = Some(host_addr.to_vec());
    true
}

/// Create this socket's shadow at BIND time, bound to the same local address
/// but not yet connected.
///
/// It has to exist this early because `epoll_ctl(ADD)` registers it alongside
/// the real socket (see `dispatch::net`), and libuv registers before it sends.
/// A shadow created lazily at first send would never be in the epoll set, so
/// the ICMP error — which arrives asynchronously, after the send returns —
/// would have nothing to wake the loop with, and the guest would sit in
/// `epoll_wait` with a queued error it is never told about.
pub(super) fn create_shadow_at_bind(host_fd: i32, local: &[u8]) {
    let mut state = lock();
    let Some(entry) = state.get_mut(&host_fd) else {
        return;
    };
    if !entry.enabled || entry.shadow.is_some() {
        return;
    }
    if let Some(fd) = bind_shadow(local) {
        entry.shadow = Some((fd, Vec::new()));
    }
}

/// This socket's shadow fd, for epoll registration.
pub(super) fn shadow_fd(host_fd: i32) -> Option<i32> {
    lock().get(&host_fd)?.shadow.as_ref().map(|(fd, _)| *fd)
}

/// The shadow to send this datagram through, creating or re-pointing it as
/// needed. `None` when this socket has no error queue, or when the shadow
/// cannot be established — in which case the caller must send normally, since
/// losing the datagram would be far worse than losing the error report.
pub(super) fn shadow_for_send(host_fd: i32, local: &[u8], dest: &[u8]) -> Option<i32> {
    let mut state = lock();
    let entry = state.get_mut(&host_fd)?;
    if !entry.enabled {
        return None;
    }
    if let Some((fd, connected)) = &entry.shadow {
        if !connected.is_empty() && connected == dest {
            return Some(*fd);
        }
        // Re-point an existing shadow at the new destination; a datagram socket
        // may be re-connected freely.
        let fd = *fd;
        // SAFETY: `dest` is a sockaddr Carrick just handed the host.
        let rc = unsafe { libc::connect(fd, dest.as_ptr() as *const _, dest.len() as u32) };
        if rc == 0 {
            entry.shadow = Some((fd, dest.to_vec()));
            return Some(fd);
        }
        return None;
    }
    let fd = create_shadow(local, dest)?;
    entry.shadow = Some((fd, dest.to_vec()));
    Some(fd)
}

/// Bind a shadow to `local` without connecting it yet.
fn bind_shadow(local: &[u8]) -> Option<i32> {
    if local.len() < 2 {
        return None;
    }
    let family = i32::from(local[1]);
    // SAFETY: plain socket creation with constant arguments.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    let one: i32 = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        // SAFETY: `one` outlives the call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &one as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );
        }
    }
    // SAFETY: `local` is the sockaddr the host itself reported for the socket.
    if unsafe { libc::bind(fd, local.as_ptr() as *const _, local.len() as u32) } != 0 {
        // SAFETY: closing a socket this function just created.
        unsafe { libc::close(fd) };
        return None;
    }
    set_nonblocking(fd);
    Some(fd)
}

fn create_shadow(local: &[u8], dest: &[u8]) -> Option<i32> {
    if local.is_empty() || dest.len() < 2 {
        return None;
    }
    let family = i32::from(local[1]);
    // SAFETY: plain socket creation with constant arguments.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    let one: i32 = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        // SAFETY: `one` outlives the call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &one as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );
        }
    }
    // Bind to the SAME local address so the datagram leaves with the guest's
    // source address and the returning ICMP matches the guest's 4-tuple.
    // SAFETY: `local` is the sockaddr the host itself reported for the socket.
    let bound = unsafe { libc::bind(fd, local.as_ptr() as *const _, local.len() as u32) };
    // SAFETY: `dest` is a sockaddr Carrick just handed the host.
    let connected = unsafe { libc::connect(fd, dest.as_ptr() as *const _, dest.len() as u32) };
    if bound != 0 || connected != 0 {
        // SAFETY: closing a socket this function just created.
        unsafe { libc::close(fd) };
        return None;
    }
    set_nonblocking(fd);
    Some(fd)
}

fn set_nonblocking(fd: i32) {
    // SAFETY: plain fcntl on a socket this module owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// Drain any ICMP error Darwin has reported on the shadow into the queue.
/// Cheap and idempotent; callers run it before answering readiness or a recv.
pub(super) fn poll_errors(host_fd: i32) {
    let mut state = lock();
    let Some(entry) = state.get_mut(&host_fd) else {
        return;
    };
    let Some((shadow, dest)) = entry.shadow.clone() else {
        return;
    };
    let mut scratch = [0u8; 64];
    loop {
        // SAFETY: the shadow is O_NONBLOCK, so this never blocks.
        let n = unsafe {
            libc::recv(
                shadow,
                scratch.as_mut_ptr() as *mut _,
                scratch.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            // A real datagram from the connected peer — not an error, and not
            // this socket's data (the guest reads its own socket). Discard.
            continue;
        }
        let Err(linux) = crate::dispatch::HostSyscallResult::host_syscall_errno(n as i32) else {
            return;
        };
        if linux == crate::linux_abi::LINUX_EAGAIN {
            return;
        }
        let errno = linux.get();
        entry.queue.push_back(ErrEntry {
            errno,
            offender: dest.clone(),
            is_ipv6: entry.is_ipv6,
        });
        if entry.seen.is_none() {
            entry.seen = Some(errno);
        }
    }
}

/// Whether anything is waiting — used to report `EPOLLIN | EPOLLERR`, which is
/// what makes libuv run both its plain and its `MSG_ERRQUEUE` read.
pub(super) fn has_pending(host_fd: i32) -> bool {
    lock().get(&host_fd).is_some_and(|s| !s.queue.is_empty())
}

/// The last observed error, consumed. Used by tests to assert the error was
/// actually noticed; the ordinary read path deliberately does NOT consult it.
#[cfg(test)]
pub(super) fn take_seen(host_fd: i32) -> Option<i32> {
    lock().get_mut(&host_fd)?.seen.take()
}

/// The next error-queue entry, consumed. `None` means `MSG_ERRQUEUE` answers
/// `EAGAIN`, exactly as a drained Linux queue does.
pub(super) fn pop(host_fd: i32) -> Option<ErrEntry> {
    lock().get_mut(&host_fd)?.queue.pop_front()
}

/// Release everything this socket owned. Host fds are reused, so a membership
/// that outlived its socket would misroute a later unrelated one.
pub(super) fn close(host_fd: i32) {
    let Some(entry) = lock().remove(&host_fd) else {
        return;
    };
    if let Some((shadow, _)) = entry.shadow {
        // SAFETY: closing a socket this module created and owns.
        unsafe { libc::close(shadow) };
    }
    if let Some(bound) = entry.bound {
        BOUND
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&bound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[1] = libc::AF_INET as u8;
        v[2..4].copy_from_slice(&port.to_be_bytes());
        v[4..8].copy_from_slice(&[127, 0, 0, 1]);
        v
    }

    /// A socket that never asked for the error queue must be untouched: no
    /// state, no shadow, no readiness contribution.
    #[test]
    fn a_socket_without_recverr_is_untouched() {
        close(900);
        assert!(!is_enabled(900));
        assert!(!has_pending(900));
        assert!(take_seen(900).is_none());
        assert!(pop(900).is_none());
        assert!(shadow_for_send(900, &addr(1), &addr(2)).is_none());
    }

    /// Linux refuses a second bind to the same addr:port. Carrick has to
    /// enforce that itself here, because it set host `SO_REUSEPORT` to make the
    /// shadow possible and Darwin would therefore allow it.
    #[test]
    fn a_second_error_queue_socket_cannot_share_the_address() {
        close(901);
        close(902);
        let a = addr(19199);
        assert!(reserve_bind(901, &a), "first bind reserves");
        assert!(!reserve_bind(902, &a), "second bind must be EADDRINUSE");
        close(901);
        assert!(reserve_bind(902, &a), "released once the first closed");
        close(902);
    }

    /// The error goes to the QUEUE, and readiness follows the queue alone.
    /// A drained queue is EAGAIN, which is what ends libuv's errqueue loop.
    #[test]
    fn an_error_is_delivered_to_the_queue_and_drains_to_eagain() {
        close(903);
        {
            let mut state = lock();
            let entry = state.entry(903).or_default();
            entry.enabled = true;
            entry.queue.push_back(ErrEntry {
                errno: 111,
                offender: addr(19198),
                is_ipv6: false,
            });
            entry.seen = Some(111);
        }
        assert!(has_pending(903));
        assert_eq!(take_seen(903), Some(111));
        let popped = pop(903).expect("queued entry");
        assert_eq!(popped.errno, 111);
        assert!(pop(903).is_none(), "a drained queue is EAGAIN");
        assert!(!has_pending(903));
        close(903);
    }
}
