//! Pure in-memory stream and message socket implementation.
//!
//! Provides bidirectional byte streams (`SOCK_STREAM`), message queues
//! (`SOCK_DGRAM`, `SOCK_SEQPACKET`), the Linux abstract namespace (`@name` /
//! `\0...`), autobind, zero-copy file descriptor passing (`SCM_RIGHTS`),
//! peer credential queries (`SO_PEERCRED` / `SCM_CREDENTIALS`), and mocked
//! `AF_INET`/`AF_INET6` streams within the Carrick runtime without creating
//! host Darwin sockets or host temporary files.

#![allow(dead_code)]

use parking_lot::{Condvar, Mutex};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::dispatch::OpenFile;
use crate::linux_abi::{
    LINUX_AF_UNIX, LINUX_EADDRINUSE, LINUX_EAGAIN, LINUX_ECONNREFUSED, LINUX_EDESTADDRREQ,
    LINUX_EINVAL, LINUX_EISCONN, LINUX_ENOTCONN, LINUX_EOPNOTSUPP, LINUX_EPIPE, LINUX_EPOLLERR,
    LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_EPOLLPRI, LINUX_EPOLLRDHUP,
    LINUX_SOCK_DGRAM, LINUX_SOCK_SEQPACKET, LINUX_SOCK_STREAM, LinuxErrno,
};
use crate::network::interposer::{ConnectionRecordState, MockService};
use carrick_abi::{LINUX_AF_INET, LINUX_AF_INET6, LINUX_IPPROTO_SCTP, LINUX_IPPROTO_TCP};

pub const LINUX_SHUT_RD: i32 = 0;
pub const LINUX_SHUT_WR: i32 = 1;
pub const LINUX_SHUT_RDWR: i32 = 2;

/// Default capacity for stream socket ring buffers (matches Linux default ~208 KiB).
pub const DEFAULT_STREAM_BUFFER_CAPACITY: usize = 212_992;
/// TCP autotuning maximum send buffer size (matches advertised /proc/sys/net/ipv4/tcp_wmem max 4 MiB).
pub const TCP_AUTOTUNE_MAX_WMEM: usize = 4_194_304;
/// TCP autotuning maximum receive buffer size (matches advertised /proc/sys/net/ipv4/tcp_rmem max 6 MiB).
pub const TCP_AUTOTUNE_MAX_RMEM: usize = 6_291_456;
/// Max queued datagrams before backpressure/drop.
pub const DEFAULT_DGRAM_QUEUE_LIMIT: usize = 256;

/// Copy a byte prefix out of a `VecDeque` with at most two bulk copies.
///
/// Stream receive used to index or `pop_front` one byte at a time. Large
/// in-zone TCP transfers therefore spent their time in per-byte deque
/// bookkeeping even when `splice(2)` moved MiB-sized chunks. The deque's two
/// physical slices are already contiguous, so preserve the logical stream
/// order without that amplification.
fn copy_deque_prefix(bytes: &VecDeque<u8>, dest: &mut [u8], len: usize) {
    debug_assert!(len <= bytes.len());
    debug_assert!(len <= dest.len());

    let (front, back) = bytes.as_slices();
    let front_len = len.min(front.len());
    dest[..front_len].copy_from_slice(&front[..front_len]);
    let back_len = len - front_len;
    if back_len > 0 {
        dest[front_len..len].copy_from_slice(&back[..back_len]);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxUcred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl Default for LinuxUcred {
    fn default() -> Self {
        Self {
            pid: 1,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Debug)]
pub struct UnixDatagram {
    pub payload: Vec<u8>,
    pub sender_addr: Option<Vec<u8>>,
    pub sender_creds: Option<LinuxUcred>,
    pub rights: Vec<Arc<OpenFile>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpPeerTerminal {
    Open,
    Fin,
    Reset,
}

pub struct PureSocketState {
    pub bound_addr: Option<Vec<u8>>,
    pub local_sockaddr: Option<SocketAddr>,
    pub peer_sockaddr: Option<SocketAddr>,
    pub peer: Option<Weak<PureSocketInner>>,
    pub listening: bool,
    pub backlog_limit: usize,
    pub accept_queue: VecDeque<Arc<PureSocketInner>>,
    pub stream_buf: VecDeque<u8>,
    pub stream_rights: VecDeque<Arc<OpenFile>>,
    pub sctp_messages: VecDeque<usize>,
    pub sctp_consumed: usize,
    pub dgram_queue: VecDeque<UnixDatagram>,
    pub creds: LinuxUcred,
    pub peer_creds: Option<LinuxUcred>,
    pub shutdown_read: bool,
    pub shutdown_write: bool,
    tcp_pair: bool,
    tcp_peer_terminal: TcpPeerTerminal,
    tcp_send_terminal: bool,
    pub so_passcred: bool,
    pub so_error: Option<i32>,
    pub so_rcvtimeo: Option<Duration>,
    pub so_sndtimeo: Option<Duration>,
    pub so_rcvbuf: usize,
    pub so_sndbuf: usize,
    pub so_rcvbuf_explicit: Option<usize>,
    pub so_sndbuf_explicit: Option<usize>,
    pub tcp_nodelay: bool,
    pub so_keepalive: bool,
    pub tcp_keepidle: i32,
    pub tcp_keepintvl: i32,
    pub tcp_keepcnt: i32,
    pub so_linger: (i32, i32),
    /// Offset in `stream_buf` of the current TCP urgent mark, relative to the
    /// unread cursor.  The mark remains at zero after MSG_OOB consumption so
    /// SIOCATMARK can report it until a normal read crosses it.
    pub oob_mark: Option<usize>,
    pub oob_data: Option<u8>,
    pub so_oobinline: bool,
    pub mock_service: Option<Arc<dyn MockService>>,
    pub mock_peer_closed: bool,
    pub connection_record: Option<Arc<Mutex<ConnectionRecordState>>>,
    pub request_buf: Vec<u8>,
    pub inzone_cleanup: Option<Arc<dyn crate::dispatch::fd_table::InZoneCleanup>>,
    pub phase: PureSocketPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PureSocketPhase {
    Unbound,
    Bound,
    Connected,
    DisconnectedRebindable,
    Listening,
}

pub struct PureSocketInner {
    pub(crate) family: std::sync::atomic::AtomicI32,
    pub(crate) socket_type: i32,
    pub(crate) protocol: i32,
    pub(crate) state: Mutex<PureSocketState>,
    pub(crate) changed: Condvar,
    pub(crate) wait_queue: Arc<crate::kernel::WaitQueue>,
}

impl std::fmt::Debug for PureSocketInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PureSocketInner")
            .field("family", &self.family())
            .field("socket_type", &self.socket_type)
            .field("protocol", &self.protocol)
            .finish()
    }
}

pub type UnixSocketState = PureSocketState;
pub type UnixSocketInner = PureSocketInner;

impl PureSocketInner {
    pub(crate) fn family(&self) -> i32 {
        self.family.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn set_family(&self, family: i32) {
        self.family
            .store(family, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn phase(&self) -> PureSocketPhase {
        self.state.lock().phase
    }

    pub(crate) fn set_phase(&self, phase: PureSocketPhase) {
        self.state.lock().phase = phase;
    }

    pub(crate) fn notify_waiters(&self) {
        self.changed.notify_all();
        self.wait_queue.wake_all();
    }

    pub(crate) fn new(socket_type: i32, creds: LinuxUcred) -> Arc<Self> {
        Self::new_with_family(LINUX_AF_UNIX, socket_type, 0, creds)
    }

    pub(crate) fn new_with_family(
        family: i32,
        socket_type: i32,
        protocol: i32,
        creds: LinuxUcred,
    ) -> Arc<Self> {
        Arc::new(Self {
            family: std::sync::atomic::AtomicI32::new(family),
            socket_type,
            protocol,
            state: Mutex::new(PureSocketState {
                bound_addr: None,
                local_sockaddr: None,
                peer_sockaddr: None,
                peer: None,
                listening: false,
                phase: PureSocketPhase::Unbound,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                stream_buf: VecDeque::new(),
                stream_rights: VecDeque::new(),
                sctp_messages: VecDeque::new(),
                sctp_consumed: 0,
                dgram_queue: VecDeque::new(),
                creds,
                peer_creds: None,
                shutdown_read: false,
                shutdown_write: false,
                tcp_pair: false,
                tcp_peer_terminal: TcpPeerTerminal::Open,
                tcp_send_terminal: false,
                so_passcred: false,
                so_error: None,
                so_rcvtimeo: None,
                so_sndtimeo: None,
                so_rcvbuf: DEFAULT_STREAM_BUFFER_CAPACITY,
                so_sndbuf: DEFAULT_STREAM_BUFFER_CAPACITY,
                so_rcvbuf_explicit: None,
                so_sndbuf_explicit: None,
                tcp_nodelay: false,
                so_keepalive: false,
                tcp_keepidle: 7200,
                tcp_keepintvl: 75,
                tcp_keepcnt: 9,
                so_linger: (0, 0),
                oob_mark: None,
                oob_data: None,
                so_oobinline: false,
                mock_service: None,
                mock_peer_closed: false,
                connection_record: None,
                request_buf: Vec::new(),
                inzone_cleanup: None,
            }),
            changed: Condvar::new(),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
        })
    }

    pub(crate) fn new_mock(
        family: i32,
        socket_type: i32,
        protocol: i32,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
        mock: Arc<dyn MockService>,
        record: Option<Arc<Mutex<ConnectionRecordState>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            family: std::sync::atomic::AtomicI32::new(family),
            socket_type,
            protocol,
            state: Mutex::new(PureSocketState {
                bound_addr: None,
                local_sockaddr: local_addr,
                peer_sockaddr: peer_addr,
                peer: None,
                listening: false,
                phase: PureSocketPhase::Connected,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                stream_buf: VecDeque::new(),
                stream_rights: VecDeque::new(),
                sctp_messages: VecDeque::new(),
                sctp_consumed: 0,
                dgram_queue: VecDeque::new(),
                creds: LinuxUcred::default(),
                peer_creds: None,
                shutdown_read: false,
                shutdown_write: false,
                tcp_pair: false,
                tcp_peer_terminal: TcpPeerTerminal::Open,
                tcp_send_terminal: false,
                so_passcred: false,
                so_error: None,
                so_rcvtimeo: None,
                so_sndtimeo: None,
                so_rcvbuf: DEFAULT_STREAM_BUFFER_CAPACITY,
                so_sndbuf: DEFAULT_STREAM_BUFFER_CAPACITY,
                so_rcvbuf_explicit: None,
                so_sndbuf_explicit: None,
                tcp_nodelay: false,
                so_keepalive: false,
                tcp_keepidle: 7200,
                tcp_keepintvl: 75,
                tcp_keepcnt: 9,
                so_linger: (0, 0),
                oob_mark: None,
                oob_data: None,
                so_oobinline: false,
                mock_service: Some(mock),
                mock_peer_closed: false,
                connection_record: record,
                request_buf: Vec::new(),
                inzone_cleanup: None,
            }),
            changed: Condvar::new(),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
        })
    }

    /// Create an interconnected pair of pure in-memory sockets (`socketpair(AF_UNIX)`).
    pub(crate) fn pair(
        socket_type: i32,
        creds1: LinuxUcred,
        creds2: LinuxUcred,
    ) -> (Arc<Self>, Arc<Self>) {
        Self::pair_with_family(LINUX_AF_UNIX, socket_type, 0, creds1, creds2)
    }

    pub(crate) fn pair_with_family(
        family: i32,
        socket_type: i32,
        protocol: i32,
        creds1: LinuxUcred,
        creds2: LinuxUcred,
    ) -> (Arc<Self>, Arc<Self>) {
        let first = Self::new_with_family(family, socket_type, protocol, creds1);
        let second = Self::new_with_family(family, socket_type, protocol, creds2);

        {
            let mut s1 = first.state.lock();
            let mut s2 = second.state.lock();
            // SCTP currently uses this byte-stream transport too. Preserve its
            // logical protocol and track record boundaries out of band while
            // sharing the TCP-shaped transport lifecycle.
            let tcp_pair = socket_type == LINUX_SOCK_STREAM
                && matches!(protocol, LINUX_IPPROTO_TCP | LINUX_IPPROTO_SCTP)
                && matches!(family, LINUX_AF_INET | LINUX_AF_INET6);
            s1.tcp_pair = tcp_pair;
            s2.tcp_pair = tcp_pair;
            s1.phase = PureSocketPhase::Connected;
            s2.phase = PureSocketPhase::Connected;
            s1.peer = Some(Arc::downgrade(&second));
            s1.peer_creds = Some(creds2);
            s2.peer = Some(Arc::downgrade(&first));
            s2.peer_creds = Some(creds1);
        }

        (first, second)
    }

    pub(crate) fn mock_on_connect(&self) -> Option<Vec<u8>> {
        let state = self.state.lock();
        if let Some(mock) = &state.mock_service
            && let Some(peer_addr) = state.peer_sockaddr
        {
            mock.on_connect(peer_addr)
        } else {
            None
        }
    }

    pub(crate) fn queue_mock_response(&self, bytes: &[u8]) {
        let mut state = self.state.lock();
        state.stream_buf.extend(bytes);
        if self.protocol == LINUX_IPPROTO_SCTP && !bytes.is_empty() {
            state.sctp_messages.push_back(bytes.len());
        }
        if let Some(rec_ref) = &state.connection_record {
            let mut rec = rec_ref.lock();
            rec.bytes_received += bytes.len();
            if rec.capture_payload {
                if let Some(payload) = &mut rec.received_payload {
                    payload.extend_from_slice(bytes);
                }
            }
        }
        self.notify_waiters();
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.state.lock().stream_buf.len()
    }

    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.state.lock().local_sockaddr
    }

    pub(crate) fn peer_addr(&self) -> Option<SocketAddr> {
        self.state.lock().peer_sockaddr
    }

    pub(crate) fn getpeername_addr(&self) -> Option<SocketAddr> {
        let state = self.state.lock();
        if state.tcp_pair && state.tcp_peer_terminal == TcpPeerTerminal::Reset {
            None
        } else {
            state.peer_sockaddr
        }
    }

    pub(crate) fn disconnect_tcp_reset(&self) -> Result<(), LinuxErrno> {
        if self.socket_type != LINUX_SOCK_STREAM
            || !matches!(self.protocol, LINUX_IPPROTO_TCP | LINUX_IPPROTO_SCTP)
            || !matches!(self.family(), LINUX_AF_INET | LINUX_AF_INET6)
        {
            return Err(LINUX_EINVAL);
        }
        let peer = self.peer_half().ok_or(LINUX_ENOTCONN)?;
        let (mut state, mut peer_state) = self.lock_with_peer(&peer);
        let self_points_to_peer = state
            .peer
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|live| Arc::ptr_eq(&live, &peer));
        let peer_points_to_self = peer_state
            .peer
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|live| std::ptr::eq(Arc::as_ptr(&live), self));
        if !self_points_to_peer || !peer_points_to_self {
            return Err(LINUX_ENOTCONN);
        }
        state.peer = None;
        state.peer_sockaddr = None;
        state.peer_creds = None;
        state.stream_buf.clear();
        state.stream_rights.clear();
        state.sctp_messages.clear();
        state.sctp_consumed = 0;
        state.shutdown_read = false;
        state.shutdown_write = false;
        state.tcp_peer_terminal = TcpPeerTerminal::Open;
        state.tcp_send_terminal = false;
        state.so_error = None;
        state.phase = PureSocketPhase::DisconnectedRebindable;
        peer_state.peer = None;
        peer_state.inzone_cleanup = None;
        peer_state.tcp_peer_terminal = TcpPeerTerminal::Reset;
        peer_state.tcp_send_terminal = true;
        peer_state.so_error = Some(carrick_abi::LINUX_ECONNRESET.get());
        peer_state.sctp_messages.clear();
        peer_state.sctp_consumed = 0;
        drop(peer_state);
        drop(state);
        peer.notify_waiters();
        self.notify_waiters();
        Ok(())
    }

    pub(crate) fn new_inet_peer(
        &self,
        creds: LinuxUcred,
    ) -> Result<Arc<PureSocketInner>, LinuxErrno> {
        if self.socket_type != LINUX_SOCK_STREAM
            || !matches!(self.protocol, LINUX_IPPROTO_TCP | LINUX_IPPROTO_SCTP)
            || !matches!(self.family(), LINUX_AF_INET | LINUX_AF_INET6)
        {
            return Err(LINUX_EINVAL);
        }
        Ok(Self::new_with_family(
            self.family(),
            self.socket_type,
            self.protocol,
            creds,
        ))
    }

    pub(crate) fn attach_inet_peer_with(
        self: &Arc<Self>,
        peer: &Arc<PureSocketInner>,
        commit: impl FnOnce() -> Result<(), LinuxErrno>,
    ) -> Result<(), LinuxErrno> {
        let (mut state, mut peer_state) = self.lock_with_peer(peer);
        if state.peer.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(LINUX_EISCONN);
        }
        commit()?;
        state.peer = Some(Arc::downgrade(peer));
        state.peer_creds = Some(peer_state.creds);
        state.tcp_pair = true;
        state.phase = PureSocketPhase::Connected;
        state.tcp_peer_terminal = TcpPeerTerminal::Open;
        state.tcp_send_terminal = false;
        state.shutdown_read = false;
        state.shutdown_write = false;
        state.so_error = None;
        peer_state.peer = Some(Arc::downgrade(self));
        peer_state.peer_creds = Some(state.creds);
        peer_state.tcp_pair = true;
        peer_state.phase = PureSocketPhase::Connected;
        Ok(())
    }

    pub(crate) fn take_so_error(&self) -> Option<i32> {
        self.state.lock().so_error.take()
    }

    pub(crate) fn set_so_error(&self, err: i32) {
        let mut state = self.state.lock();
        state.so_error = Some(err);
        if state.tcp_pair && err == carrick_abi::LINUX_ECONNRESET.get() {
            state.tcp_peer_terminal = TcpPeerTerminal::Reset;
            state.tcp_send_terminal = true;
        }
        drop(state);
        self.notify_waiters();
    }

    pub(crate) fn set_rcvtimeo(&self, dur: Option<Duration>) {
        self.state.lock().so_rcvtimeo = dur;
    }

    pub(crate) fn get_rcvtimeo(&self) -> Option<Duration> {
        self.state.lock().so_rcvtimeo
    }

    pub(crate) fn set_sndtimeo(&self, dur: Option<Duration>) {
        self.state.lock().so_sndtimeo = dur;
    }

    pub(crate) fn get_sndtimeo(&self) -> Option<Duration> {
        self.state.lock().so_sndtimeo
    }

    pub(crate) fn so_sndbuf(&self) -> usize {
        self.state.lock().so_sndbuf
    }

    pub(crate) fn set_so_sndbuf(&self, val: usize) {
        let mut state = self.state.lock();
        state.so_sndbuf = val;
        state.so_sndbuf_explicit = Some(val);
    }

    pub(crate) fn so_sndbuf_explicit(&self) -> Option<usize> {
        self.state.lock().so_sndbuf_explicit
    }

    pub(crate) fn so_rcvbuf(&self) -> usize {
        self.state.lock().so_rcvbuf
    }

    pub(crate) fn set_so_rcvbuf(&self, val: usize) {
        let mut state = self.state.lock();
        state.so_rcvbuf = val;
        state.so_rcvbuf_explicit = Some(val);
    }

    pub(crate) fn so_rcvbuf_explicit(&self) -> Option<usize> {
        self.state.lock().so_rcvbuf_explicit
    }

    pub(crate) fn is_tcp(&self) -> bool {
        self.socket_type == LINUX_SOCK_STREAM
            && self.protocol == LINUX_IPPROTO_TCP
            && matches!(self.family(), LINUX_AF_INET | LINUX_AF_INET6)
    }

    pub(crate) fn effective_send_capacity(
        &self,
        sender_state: &PureSocketState,
        receiver_state: Option<&PureSocketState>,
    ) -> usize {
        if self.is_tcp() && sender_state.tcp_pair {
            let sender_cap = sender_state
                .so_sndbuf_explicit
                .unwrap_or(TCP_AUTOTUNE_MAX_WMEM);
            let receiver_cap = receiver_state
                .and_then(|r| r.so_rcvbuf_explicit)
                .unwrap_or(TCP_AUTOTUNE_MAX_RMEM);
            sender_cap.min(receiver_cap)
        } else {
            sender_state.so_sndbuf
        }
    }

    pub(crate) fn is_listening(&self) -> bool {
        self.state.lock().listening
    }

    pub(crate) fn tcp_nodelay(&self) -> bool {
        self.state.lock().tcp_nodelay
    }

    pub(crate) fn set_tcp_nodelay(&self, val: bool) {
        self.state.lock().tcp_nodelay = val;
    }

    pub(crate) fn so_keepalive(&self) -> bool {
        self.state.lock().so_keepalive
    }

    pub(crate) fn set_so_keepalive(&self, val: bool) {
        self.state.lock().so_keepalive = val;
    }

    pub(crate) fn tcp_keepidle(&self) -> i32 {
        self.state.lock().tcp_keepidle
    }

    pub(crate) fn set_tcp_keepidle(&self, val: i32) {
        self.state.lock().tcp_keepidle = val;
    }

    pub(crate) fn tcp_keepintvl(&self) -> i32 {
        self.state.lock().tcp_keepintvl
    }

    pub(crate) fn set_tcp_keepintvl(&self, val: i32) {
        self.state.lock().tcp_keepintvl = val;
    }

    pub(crate) fn tcp_keepcnt(&self) -> i32 {
        self.state.lock().tcp_keepcnt
    }

    pub(crate) fn set_tcp_keepcnt(&self, val: i32) {
        self.state.lock().tcp_keepcnt = val;
    }

    pub(crate) fn so_linger(&self) -> (i32, i32) {
        self.state.lock().so_linger
    }

    pub(crate) fn set_so_linger(&self, val: (i32, i32)) {
        self.state.lock().so_linger = val;
    }

    /// The live peer half, if any (own lock taken and released here).
    fn peer_half(&self) -> Option<Arc<PureSocketInner>> {
        self.state.lock().peer.as_ref().and_then(|p| p.upgrade())
    }

    /// Lock this half's state together with its peer's in one global order
    /// (lower object address first). Every reader that needs both halves
    /// (readiness, EOF, queued-output) goes through here: "self, then peer"
    /// from both sides at once is an ABBA deadlock, and two guest threads
    /// polling the two ends of one connection do exactly that.
    fn lock_with_peer<'a>(
        &'a self,
        peer: &'a Arc<PureSocketInner>,
    ) -> (
        parking_lot::MutexGuard<'a, PureSocketState>,
        parking_lot::MutexGuard<'a, PureSocketState>,
    ) {
        let me = self as *const Self as usize;
        let them = Arc::as_ptr(peer) as usize;
        debug_assert_ne!(me, them, "a stream half is never its own peer");
        if me < them {
            let mine = self.state.lock();
            let theirs = peer.state.lock();
            (mine, theirs)
        } else {
            let theirs = peer.state.lock();
            let mine = self.state.lock();
            (mine, theirs)
        }
    }

    pub(crate) fn outq_bytes(&self) -> usize {
        let Some(peer) = self.peer_half() else {
            let state = self.state.lock();
            return if state.mock_service.is_some() {
                state.request_buf.len()
            } else {
                0
            };
        };
        let (state, peer_state) = self.lock_with_peer(&peer);
        if state.mock_service.is_some() {
            state.request_buf.len()
        } else {
            peer_state.stream_buf.len()
        }
    }

    pub(crate) fn bind(
        self: &Arc<Self>,
        sun_path: &[u8],
        registry: &UnixSocketRegistry,
    ) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        if state.bound_addr.is_some() {
            return Err(LINUX_EINVAL);
        }

        let bound = if sun_path.is_empty() {
            let auto = registry.autobind_abstract_name();
            registry.register_abstract(auto.clone(), Arc::clone(self))?;
            auto
        } else if sun_path[0] == 0 {
            registry.register_abstract(sun_path.to_vec(), Arc::clone(self))?;
            sun_path.to_vec()
        } else {
            let nul = sun_path
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(sun_path.len());
            let path_str = String::from_utf8_lossy(&sun_path[..nul]).into_owned();
            registry.register_pathname(path_str, Arc::clone(self))?;
            sun_path[..nul].to_vec()
        };

        state.bound_addr = Some(bound);
        self.notify_waiters();
        Ok(())
    }

    pub(crate) fn listen(self: &Arc<Self>, backlog: i32) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        if self.socket_type != LINUX_SOCK_STREAM && self.socket_type != LINUX_SOCK_SEQPACKET {
            return Err(LINUX_EOPNOTSUPP);
        }
        state.listening = true;
        state.backlog_limit = backlog.max(0) as usize;
        self.notify_waiters();
        Ok(())
    }

    pub(crate) fn connect(
        self: &Arc<Self>,
        sun_path: &[u8],
        registry: &UnixSocketRegistry,
    ) -> Result<(), LinuxErrno> {
        if sun_path.is_empty() {
            return Err(LINUX_EINVAL);
        }

        let target = if sun_path[0] == 0 {
            registry.lookup_abstract(sun_path)
        } else {
            let nul = sun_path
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(sun_path.len());
            let path_str = String::from_utf8_lossy(&sun_path[..nul]);
            registry.lookup_pathname(&path_str)
        };

        let Some(target) = target else {
            return Err(LINUX_ECONNREFUSED);
        };

        if self.socket_type == LINUX_SOCK_DGRAM {
            let mut state = self.state.lock();
            state.peer = Some(Arc::downgrade(&target));
            state.peer_creds = Some(target.state.lock().creds);
            return Ok(());
        }

        let mut target_state = target.state.lock();
        if !target_state.listening {
            return Err(LINUX_ECONNREFUSED);
        }

        if target_state.accept_queue.len() >= target_state.backlog_limit.max(128) {
            return Err(LINUX_EAGAIN);
        }

        let server_side = Self::new_with_family(
            self.family(),
            self.socket_type,
            self.protocol,
            target_state.creds,
        );
        {
            let mut server_state = server_side.state.lock();
            let mut client_state = self.state.lock();

            server_state.peer = Some(Arc::downgrade(self));
            server_state.peer_creds = Some(client_state.creds);

            client_state.peer = Some(Arc::downgrade(&server_side));
            client_state.peer_creds = Some(target_state.creds);
        }

        target_state.accept_queue.push_back(server_side);
        target.notify_waiters();
        Ok(())
    }

    pub(crate) fn accept(self: &Arc<Self>) -> Result<Arc<PureSocketInner>, LinuxErrno> {
        let mut state = self.state.lock();
        if !state.listening {
            return Err(LINUX_EINVAL);
        }

        if let Some(conn) = state.accept_queue.pop_front() {
            Ok(conn)
        } else {
            Err(LINUX_EAGAIN)
        }
    }

    pub(crate) fn send_stream(
        &self,
        data: &[u8],
        rights: Vec<Arc<OpenFile>>,
    ) -> Result<usize, LinuxErrno> {
        let mut state = self.state.lock();
        // A pending socket error is reported once, by whichever of `send`,
        // `recv` or `SO_ERROR` asks first; after that a send on the dead
        // connection is EPIPE.
        if let Some(err) = state.so_error.take() {
            return Err(LinuxErrno::new(err));
        }
        if state.shutdown_write {
            return Err(LINUX_EPIPE);
        }
        if state.tcp_pair && state.tcp_send_terminal {
            return Err(LINUX_EPIPE);
        }

        // Mock Service Interception Path
        if let Some(mock) = state.mock_service.clone() {
            if state.mock_peer_closed {
                return Err(LINUX_EPIPE);
            }
            let send_cap = self.effective_send_capacity(&state, None);
            let available = send_cap.saturating_sub(state.request_buf.len());
            if available == 0 && !data.is_empty() {
                return Err(LINUX_EAGAIN);
            }
            let to_write = data.len().min(available);
            state.request_buf.extend_from_slice(&data[..to_write]);

            if let Some(rec_ref) = &state.connection_record {
                let mut rec = rec_ref.lock();
                rec.bytes_sent += to_write;
                if rec.capture_payload {
                    if let Some(payload) = &mut rec.sent_payload {
                        payload.extend_from_slice(&data[..to_write]);
                    }
                }
            }

            let response_bytes = mock.handle(&state.request_buf);
            if !response_bytes.is_empty() {
                state.stream_buf.extend(&response_bytes);
                if self.protocol == LINUX_IPPROTO_SCTP {
                    state.sctp_messages.push_back(response_bytes.len());
                }
                if let Some(rec_ref) = &state.connection_record {
                    let mut rec = rec_ref.lock();
                    rec.bytes_received += response_bytes.len();
                    if rec.capture_payload {
                        if let Some(payload) = &mut rec.received_payload {
                            payload.extend_from_slice(&response_bytes);
                        }
                    }
                }
                state.request_buf.clear();
                if mock.should_close() {
                    state.mock_peer_closed = true;
                }
            }

            drop(state);
            self.notify_waiters();
            return Ok(to_write);
        }

        // Interconnected Peer Path
        let peer_arc = {
            let Some(peer_weak) = &state.peer else {
                return Err(LINUX_ENOTCONN);
            };
            let Some(peer) = peer_weak.upgrade() else {
                if state.tcp_pair
                    && state.tcp_peer_terminal == TcpPeerTerminal::Fin
                    && data.is_empty()
                {
                    return Ok(0);
                }
                if state.tcp_pair
                    && state.tcp_peer_terminal == TcpPeerTerminal::Fin
                    && !data.is_empty()
                {
                    let send_cap = self.effective_send_capacity(&state, None);
                    let admitted = data.len().min(send_cap);
                    if admitted == 0 {
                        return Err(LINUX_EAGAIN);
                    }
                    state.tcp_send_terminal = true;
                    state.so_error = Some(LINUX_EPIPE.get());
                    return Ok(admitted);
                }
                return Err(LINUX_EPIPE);
            };
            peer
        };
        drop(state);

        let (mut state, mut peer_state) = self.lock_with_peer(&peer_arc);
        if let Some(err) = state.so_error.take() {
            return Err(LinuxErrno::new(err));
        }
        if state.shutdown_write || state.tcp_send_terminal {
            return Err(LINUX_EPIPE);
        }
        let send_cap = self.effective_send_capacity(&state, Some(&peer_state));
        if peer_state.shutdown_read {
            if state.tcp_pair && data.is_empty() {
                return Ok(0);
            }
            if state.tcp_pair && !data.is_empty() {
                let admitted = data.len().min(send_cap);
                if admitted == 0 {
                    return Err(LINUX_EAGAIN);
                }
                state.tcp_send_terminal = true;
                state.so_error = Some(LINUX_EPIPE.get());
                peer_state.so_error = Some(carrick_abi::LINUX_ECONNRESET.get());
                peer_state.tcp_peer_terminal = TcpPeerTerminal::Reset;
                peer_state.stream_buf.clear();
                peer_state.stream_rights.clear();
                peer_state.sctp_messages.clear();
                peer_state.sctp_consumed = 0;
                drop(peer_state);
                drop(state);
                peer_arc.notify_waiters();
                self.notify_waiters();
                return Ok(admitted);
            }
            return Err(LINUX_EPIPE);
        }

        let available = send_cap.saturating_sub(peer_state.stream_buf.len());
        if available == 0 && !data.is_empty() {
            return Err(LINUX_EAGAIN);
        }

        let to_write = data.len().min(available);
        peer_state.stream_buf.extend(&data[..to_write]);
        if !rights.is_empty() {
            peer_state.stream_rights.extend(rights);
        }
        if self.protocol == LINUX_IPPROTO_SCTP && to_write > 0 {
            peer_state.sctp_messages.push_back(to_write);
        }
        peer_arc.notify_waiters();
        Ok(to_write)
    }

    pub(crate) fn recv_stream(
        &self,
        buf: &mut [u8],
        max_rights: usize,
    ) -> Result<(usize, Vec<Arc<OpenFile>>), LinuxErrno> {
        self.recv_stream_flags(buf, max_rights, false)
    }

    pub(crate) fn recv_stream_flags(
        &self,
        buf: &mut [u8],
        max_rights: usize,
        peek: bool,
    ) -> Result<(usize, Vec<Arc<OpenFile>>), LinuxErrno> {
        self.recv_stream_record(buf, max_rights, peek)
            .map(|(len, rights, _)| (len, rights))
    }

    pub(crate) fn recv_stream_record(
        &self,
        buf: &mut [u8],
        max_rights: usize,
        peek: bool,
    ) -> Result<(usize, Vec<Arc<OpenFile>>, bool), LinuxErrno> {
        // The EOF answer needs the peer's shutdown state, so both halves are
        // locked in the global pair order (never "self, then peer").
        let peer = self.peer_half();
        let (mut state, peer_state) = match &peer {
            Some(peer) => {
                let (mine, theirs) = self.lock_with_peer(peer);
                (mine, Some(theirs))
            }
            None => (self.state.lock(), None),
        };
        if state.shutdown_read {
            if state.tcp_pair
                && let Some(err) = state.so_error.take()
            {
                return Err(LinuxErrno::new(err));
            }
            return Ok((0, Vec::new(), false));
        }
        if buf.is_empty() {
            return Ok((0, Vec::new(), false));
        }

        // A normal MSG_PEEK at the urgent mark must not cross it.  Without
        // SO_OOBINLINE it exposes the suffix after the separately-readable
        // urgent byte; with SO_OOBINLINE that byte is virtual stream data and
        // therefore prefixes the suffix.  Neither form consumes the mark.
        if peek && state.oob_mark == Some(0) {
            if state.so_oobinline
                && let Some(byte) = state.oob_data
            {
                buf[0] = byte;
                let suffix_len = state.stream_buf.len().min(buf.len().saturating_sub(1));
                copy_deque_prefix(&state.stream_buf, &mut buf[1..], suffix_len);
                return Ok((suffix_len + 1, Vec::new(), false));
            }

            let suffix_len = state.stream_buf.len().min(buf.len());
            copy_deque_prefix(&state.stream_buf, buf, suffix_len);
            return Ok((suffix_len, Vec::new(), false));
        }

        // TCP urgent data has a cursor separate from its optional out-of-band
        // byte.  A normal read that *starts* at the mark crosses it: with
        // SO_OOBINLINE it first returns the urgent byte; otherwise it discards
        // that byte and makes MSG_OOB subsequently fail.  A prior MSG_OOB read
        // leaves the zero-width mark here for SIOCATMARK, with `oob_data=None`.
        let mut inline_byte = None;
        if state.oob_mark == Some(0) && !peek {
            if state.so_oobinline {
                inline_byte = state.oob_data.take();
            } else {
                state.oob_data = None;
            }
            state.oob_mark = None;
        }

        if state.stream_buf.is_empty() && inline_byte.is_none() {
            // Linux reports a pending socket error (a reset while the
            // connection sat in a closed listener's queue) from the first
            // `recv` that finds no data, before EOF; the error is consumed by
            // that report, exactly like `SO_ERROR`, so the next call sees EOF.
            if let Some(err) = state.so_error {
                // A write after a received TCP FIN queues EPIPE for SO_ERROR
                // (or the next send), while reads continue to report EOF.
                if !(state.tcp_pair
                    && state.tcp_peer_terminal == TcpPeerTerminal::Fin
                    && err == LINUX_EPIPE.get())
                {
                    state.so_error = None;
                    return Err(LinuxErrno::new(err));
                }
            }
            if state.mock_service.is_some() {
                if state.mock_peer_closed {
                    return Ok((0, Vec::new(), false));
                }
                return Err(LINUX_EAGAIN);
            }

            if state.tcp_pair && state.tcp_peer_terminal != TcpPeerTerminal::Open {
                return Ok((0, Vec::new(), false));
            }

            let is_peer_alive = peer_state.as_ref().is_some_and(|p| !p.shutdown_write);
            if !is_peer_alive {
                return Ok((0, Vec::new(), false));
            }
            return Err(LINUX_EAGAIN);
        }
        drop(peer_state);

        let mark_limit = state.oob_mark.unwrap_or(state.stream_buf.len());
        let sctp_limit = if self.protocol == LINUX_IPPROTO_SCTP {
            state
                .sctp_messages
                .front()
                .map(|&len| len.saturating_sub(state.sctp_consumed))
                .unwrap_or(state.stream_buf.len())
        } else {
            state.stream_buf.len()
        };
        let stream_capacity = buf.len().saturating_sub(usize::from(inline_byte.is_some()));
        let to_read = stream_capacity
            .min(state.stream_buf.len())
            .min(mark_limit)
            .min(sctp_limit);
        if peek {
            copy_deque_prefix(&state.stream_buf, buf, to_read);
            let ends_message = if self.protocol == LINUX_IPPROTO_SCTP
                && to_read > 0
                && let Some(&len) = state.sctp_messages.front()
            {
                state.sctp_consumed + to_read >= len
            } else {
                false
            };
            return Ok((to_read, Vec::new(), ends_message));
        }

        let mut written = 0;
        if let Some(byte) = inline_byte {
            if !buf.is_empty() {
                buf[0] = byte;
                written = 1;
            }
        }
        copy_deque_prefix(&state.stream_buf, &mut buf[written..], to_read);
        drop(state.stream_buf.drain(..to_read));
        written += to_read;
        if let Some(mark) = &mut state.oob_mark {
            *mark = mark.saturating_sub(to_read);
        }

        let ends_message = if self.protocol == LINUX_IPPROTO_SCTP
            && to_read > 0
            && let Some(&len) = state.sctp_messages.front()
        {
            let remaining = len.saturating_sub(state.sctp_consumed);
            if to_read >= remaining {
                state.sctp_messages.pop_front();
                state.sctp_consumed = 0;
                true
            } else {
                state.sctp_consumed += to_read;
                false
            }
        } else {
            false
        };

        let mut rights = Vec::new();
        while rights.len() < max_rights && !state.stream_rights.is_empty() {
            if let Some(right) = state.stream_rights.pop_front() {
                rights.push(right);
            }
        }

        if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
            peer.notify_waiters();
        }

        Ok((written, rights, ends_message))
    }

    pub(crate) fn send_dgram(
        &self,
        target_addr: Option<&[u8]>,
        data: Vec<u8>,
        rights: Vec<Arc<OpenFile>>,
        registry: &UnixSocketRegistry,
    ) -> Result<usize, LinuxErrno> {
        let (target, sender_addr, sender_creds) = {
            let state = self.state.lock();
            if state.shutdown_write {
                return Err(LINUX_EPIPE);
            }

            let target = match target_addr {
                Some(addr) if !addr.is_empty() => {
                    if addr[0] == 0 {
                        registry.lookup_abstract(addr)
                    } else {
                        let nul = addr.iter().position(|&b| b == 0).unwrap_or(addr.len());
                        let path_str = String::from_utf8_lossy(&addr[..nul]);
                        registry.lookup_pathname(&path_str)
                    }
                }
                _ => state.peer.as_ref().and_then(|p| p.upgrade()),
            };

            let Some(target) = target else {
                return Err(LINUX_EDESTADDRREQ);
            };

            (target, state.bound_addr.clone(), state.creds)
        };

        let mut target_state = target.state.lock();
        if target_state.shutdown_read {
            return Err(LINUX_ECONNREFUSED);
        }

        if target_state.dgram_queue.len() >= DEFAULT_DGRAM_QUEUE_LIMIT {
            return Err(LINUX_EAGAIN);
        }

        let len = data.len();
        target_state.dgram_queue.push_back(UnixDatagram {
            payload: data,
            sender_addr,
            sender_creds: Some(sender_creds),
            rights,
        });

        target.notify_waiters();
        Ok(len)
    }

    pub(crate) fn recv_dgram(&self) -> Result<UnixDatagram, LinuxErrno> {
        let mut state = self.state.lock();
        if state.shutdown_read {
            return Err(LINUX_EAGAIN);
        }

        if let Some(dgram) = state.dgram_queue.pop_front() {
            Ok(dgram)
        } else {
            Err(LINUX_EAGAIN)
        }
    }

    pub(crate) fn shutdown(&self, how: i32) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        let peer = state.peer.as_ref().and_then(Weak::upgrade);
        let tcp_pair = state.tcp_pair;
        let publishes_fin = matches!(how, LINUX_SHUT_WR | LINUX_SHUT_RDWR);
        match how {
            LINUX_SHUT_RD => state.shutdown_read = true,
            LINUX_SHUT_WR => state.shutdown_write = true,
            LINUX_SHUT_RDWR => {
                state.shutdown_read = true;
                state.shutdown_write = true;
            }
            _ => return Err(LINUX_EINVAL),
        }
        drop(state);

        if tcp_pair && publishes_fin {
            if let Some(peer) = &peer {
                let mut peer_state = peer.state.lock();
                if peer_state.tcp_peer_terminal == TcpPeerTerminal::Open {
                    peer_state.tcp_peer_terminal = TcpPeerTerminal::Fin;
                }
            }
        }
        if let Some(peer) = peer {
            peer.notify_waiters();
        }
        self.notify_waiters();
        Ok(())
    }

    pub(crate) fn so_oobinline(&self) -> bool {
        self.state.lock().so_oobinline
    }

    pub(crate) fn set_so_oobinline(&self, inline: bool) {
        let mut state = self.state.lock();
        state.so_oobinline = inline;
    }

    pub(crate) fn at_oob_mark(&self) -> bool {
        self.state.lock().oob_mark == Some(0)
    }

    pub(crate) fn send_oob(&self, data: &[u8]) -> Result<usize, LinuxErrno> {
        if data.is_empty() {
            return Err(LINUX_EINVAL);
        }
        let peer_arc = {
            let state = self.state.lock();
            let Some(peer_weak) = &state.peer else {
                return Err(LINUX_ENOTCONN);
            };
            let Some(peer) = peer_weak.upgrade() else {
                return Err(LINUX_EPIPE);
            };
            peer
        };

        let (mut state, mut peer_state) = self.lock_with_peer(&peer_arc);
        if let Some(err) = state.so_error.take() {
            return Err(LinuxErrno::new(err));
        }
        if state.shutdown_write {
            return Err(LINUX_EPIPE);
        }
        if peer_state.shutdown_read {
            return Err(LINUX_EPIPE);
        }

        let send_cap = self.effective_send_capacity(&state, Some(&peer_state));
        let urgent_byte = data[data.len() - 1];
        let stream_part = &data[..data.len() - 1];
        // Linux has one active urgent indication.  A later MSG_OOB makes the
        // previous urgent byte ordinary stream data at its old mark, then
        // installs the new mark after its ordinary prefix.
        let materialized_old = usize::from(peer_state.oob_data.is_some());
        let needed = stream_part.len().saturating_add(materialized_old);
        let available = send_cap.saturating_sub(peer_state.stream_buf.len());
        if available < needed {
            return Err(LINUX_EAGAIN);
        }
        if let (Some(mark), Some(old_byte)) =
            (peer_state.oob_mark.take(), peer_state.oob_data.take())
        {
            let insertion = mark.min(peer_state.stream_buf.len());
            peer_state.stream_buf.insert(insertion, old_byte);
        }
        peer_state.stream_buf.extend(stream_part);
        peer_state.oob_mark = Some(peer_state.stream_buf.len());
        peer_state.oob_data = Some(urgent_byte);
        drop(peer_state);
        drop(state);
        peer_arc.notify_waiters();
        Ok(data.len())
    }

    pub(crate) fn recv_oob(&self, buf: &mut [u8], peek: bool) -> Result<usize, LinuxErrno> {
        let mut state = self.state.lock();
        if let Some(err) = state.so_error.take() {
            return Err(LinuxErrno::new(err));
        }
        if state.so_oobinline {
            return Err(LINUX_EINVAL);
        }
        let Some(byte) = (if peek {
            state.oob_data
        } else {
            state.oob_data.take()
        }) else {
            return Err(LINUX_EINVAL);
        };
        // Preserve the historical zero-length behavior (the selected urgent
        // indication is consumed for a non-PEEK call) while avoiding a guest
        // reachable empty-slice panic.  The probe records Linux's exact rule.
        if buf.is_empty() {
            let consumed = !peek;
            drop(state);
            if consumed {
                self.notify_waiters();
            }
            return Ok(0);
        }
        buf[0] = byte;
        drop(state);
        self.notify_waiters();
        Ok(1)
    }

    pub(crate) fn poll_mask(&self) -> u32 {
        // Readiness of a stream half depends on the peer's state as well, so
        // both halves are locked in the global pair order (never "self, then
        // peer": two threads polling the two ends of one connection would
        // deadlock).
        let peer = self.peer_half();
        let (state, peer_state) = match &peer {
            Some(peer) => {
                let (mine, theirs) = self.lock_with_peer(peer);
                (mine, Some(theirs))
            }
            None => (self.state.lock(), None),
        };
        let mut mask = 0;

        if state.listening {
            if !state.accept_queue.is_empty() {
                mask |= LINUX_EPOLLIN;
            }
            return mask;
        }

        if self.socket_type == LINUX_SOCK_STREAM || self.socket_type == LINUX_SOCK_SEQPACKET {
            let has_mock = state.mock_service.is_some();
            let tcp_terminal = state.tcp_pair && state.tcp_peer_terminal != TcpPeerTerminal::Open;
            let (peer_shut_wr, peer_shut_rd, peer_dropped) = if has_mock {
                (state.mock_peer_closed, state.mock_peer_closed, false)
            } else if state.peer.is_none() {
                (false, false, false)
            } else if let Some(p) = peer_state.as_ref() {
                (p.shutdown_write, p.shutdown_read, false)
            } else {
                (true, true, true)
            };
            let peer_shut_wr = peer_shut_wr || tcp_terminal;

            if !state.stream_buf.is_empty()
                || (state.so_oobinline && state.oob_data.is_some())
                || state.shutdown_read
                || peer_shut_wr
            {
                mask |= LINUX_EPOLLIN;
            }
            if !state.shutdown_write && !state.tcp_send_terminal {
                let send_cap = self.effective_send_capacity(&state, peer_state.as_deref());
                if let Some(p) = peer_state.as_ref() {
                    if (!peer_shut_rd && p.stream_buf.len() < send_cap)
                        || (state.tcp_pair && peer_shut_rd)
                    {
                        mask |= LINUX_EPOLLOUT;
                    }
                } else if has_mock {
                    if !peer_shut_rd && state.request_buf.len() < send_cap {
                        mask |= LINUX_EPOLLOUT;
                    }
                } else if state.tcp_pair
                    && state.tcp_peer_terminal == TcpPeerTerminal::Fin
                    && peer_dropped
                {
                    mask |= LINUX_EPOLLOUT;
                }
            }
            if peer_shut_wr || state.shutdown_read {
                mask |= LINUX_EPOLLRDHUP;
            }
            let tcp_hup = state.tcp_pair
                && (state.tcp_peer_terminal == TcpPeerTerminal::Reset
                    || (state.stream_buf.is_empty()
                        && (state.tcp_send_terminal
                            || (state.shutdown_write && (peer_dropped || peer_shut_wr)))));
            let generic_hup = !state.tcp_pair && (peer_dropped || (peer_shut_wr && peer_shut_rd));
            if tcp_hup || generic_hup {
                mask |= LINUX_EPOLLHUP;
            }
            if state.oob_data.is_some() {
                mask |= LINUX_EPOLLPRI;
            }
        } else {
            if !state.dgram_queue.is_empty() {
                mask |= LINUX_EPOLLIN;
            }
            if !state.shutdown_write {
                mask |= LINUX_EPOLLOUT;
            }
        }

        if state.so_error.is_some() {
            mask |= LINUX_EPOLLERR;
        }

        mask
    }

    pub(crate) fn peer_creds(&self) -> Result<LinuxUcred, LinuxErrno> {
        let state = self.state.lock();
        state.peer_creds.ok_or(LINUX_ENOTCONN)
    }
}

impl Drop for PureSocketInner {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        let peer = state.peer.as_ref().and_then(Weak::upgrade);
        let tcp_pair = state.tcp_pair;
        let unread_receive = !state.stream_buf.is_empty() || !state.stream_rights.is_empty();
        let abortive_tcp =
            tcp_pair && ((state.so_linger.0 != 0 && state.so_linger.1 == 0) || unread_receive);
        state.shutdown_read = true;
        state.shutdown_write = true;
        state.mock_peer_closed = true;
        state.stream_buf.clear();
        state.stream_rights.clear();
        if let Some(rec_ref) = &state.connection_record {
            let mut rec = rec_ref.lock();
            rec.completed = true;
        }
        drop(state);

        if let Some(peer) = peer {
            if tcp_pair {
                let mut peer_state = peer.state.lock();
                if abortive_tcp {
                    peer_state.tcp_peer_terminal = TcpPeerTerminal::Reset;
                    peer_state.tcp_send_terminal = true;
                    peer_state.so_error = Some(carrick_abi::LINUX_ECONNRESET.get());
                } else if peer_state.tcp_peer_terminal == TcpPeerTerminal::Open {
                    peer_state.tcp_peer_terminal = TcpPeerTerminal::Fin;
                }
            }
            peer.notify_waiters();
        }
    }
}

#[derive(Default, Debug)]
pub struct UnixSocketRegistry {
    pub(crate) abstract_sockets: Mutex<HashMap<Vec<u8>, Arc<PureSocketInner>>>,
    pub(crate) pathname_sockets: Mutex<HashMap<String, Arc<PureSocketInner>>>,
    pub(crate) autobind_counter: AtomicU32,
}

impl UnixSocketRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register_abstract(
        &self,
        name: Vec<u8>,
        sock: Arc<PureSocketInner>,
    ) -> Result<(), LinuxErrno> {
        let mut map = self.abstract_sockets.lock();
        if map.contains_key(&name) {
            return Err(LINUX_EADDRINUSE);
        }
        map.insert(name, sock);
        Ok(())
    }

    pub(crate) fn unregister_abstract(&self, name: &[u8]) {
        self.abstract_sockets.lock().remove(name);
    }

    pub(crate) fn lookup_abstract(&self, name: &[u8]) -> Option<Arc<PureSocketInner>> {
        self.abstract_sockets.lock().get(name).cloned()
    }

    pub(crate) fn register_pathname(
        &self,
        path: String,
        sock: Arc<PureSocketInner>,
    ) -> Result<(), LinuxErrno> {
        let mut map = self.pathname_sockets.lock();
        if map.contains_key(&path) {
            return Err(LINUX_EADDRINUSE);
        }
        map.insert(path, sock);
        Ok(())
    }

    pub(crate) fn unregister_pathname(&self, path: &str) {
        self.pathname_sockets.lock().remove(path);
    }

    pub(crate) fn lookup_pathname(&self, path: &str) -> Option<Arc<PureSocketInner>> {
        self.pathname_sockets.lock().get(path).cloned()
    }

    pub(crate) fn autobind_abstract_name(&self) -> Vec<u8> {
        let n = self.autobind_counter.fetch_add(1, Ordering::Relaxed);
        let mut name = vec![0u8];
        name.extend_from_slice(format!("{:05x}", n & 0xf_ffff).as_bytes());
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_abi::{LINUX_AF_INET, LINUX_IPPROTO_TCP};
    use crate::network::interposer::HttpMock;

    #[test]
    fn socketpair_stream_round_trip() {
        let creds1 = LinuxUcred {
            pid: 100,
            uid: 1000,
            gid: 1000,
        };
        let creds2 = LinuxUcred {
            pid: 200,
            uid: 1000,
            gid: 1000,
        };
        let (s1, s2) = PureSocketInner::pair(LINUX_SOCK_STREAM, creds1, creds2);

        assert_eq!(s1.peer_creds(), Ok(creds2));
        assert_eq!(s2.peer_creds(), Ok(creds1));

        let sent = s1.send_stream(b"hello unix socket", Vec::new()).unwrap();
        assert_eq!(sent, 17);

        let mut buf = [0u8; 32];
        let (read, rights) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read, 17);
        assert_eq!(&buf[..read], b"hello unix socket");
        assert!(rights.is_empty());
    }

    #[test]
    fn abstract_namespace_bind_connect() {
        let registry = UnixSocketRegistry::new();
        let creds = LinuxUcred {
            pid: 100,
            uid: 0,
            gid: 0,
        };

        let server = PureSocketInner::new(LINUX_SOCK_STREAM, creds);
        let abstract_name = b"\0test_service";
        server.bind(abstract_name, &registry).unwrap();
        server.listen(10).unwrap();

        let client = PureSocketInner::new(LINUX_SOCK_STREAM, creds);
        client.connect(abstract_name, &registry).unwrap();

        let accepted = server.accept().unwrap();

        client.send_stream(b"ping", Vec::new()).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = accepted.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn dgram_socket_round_trip() {
        let registry = UnixSocketRegistry::new();
        let creds = LinuxUcred {
            pid: 100,
            uid: 0,
            gid: 0,
        };

        let server = PureSocketInner::new(LINUX_SOCK_DGRAM, creds);
        let server_name = b"\0dgram_server";
        server.bind(server_name, &registry).unwrap();

        let client = PureSocketInner::new(LINUX_SOCK_DGRAM, creds);
        client
            .send_dgram(
                Some(server_name),
                b"dgram msg".to_vec(),
                Vec::new(),
                &registry,
            )
            .unwrap();

        let dgram = server.recv_dgram().unwrap();
        assert_eq!(dgram.payload, b"dgram msg");
        assert_eq!(dgram.sender_creds, Some(creds));
    }

    #[test]
    fn in_memory_mock_http_round_trip() {
        let mock = Arc::new(HttpMock::new().route("GET /test", 200, "mock reply"));
        let peer_addr = "198.18.0.1:80".parse().unwrap();
        let sock = PureSocketInner::new_mock(
            crate::linux_abi::LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            0,
            Some("127.0.0.1:49152".parse().unwrap()),
            Some(peer_addr),
            mock,
            None,
        );

        assert_eq!(sock.poll_mask() & LINUX_EPOLLOUT, LINUX_EPOLLOUT);

        // Send HTTP request
        let n = sock
            .send_stream(b"GET /test HTTP/1.1\r\n\r\n", Vec::new())
            .unwrap();
        assert_eq!(n, 22);

        // Socket is now readable with response
        assert_eq!(sock.poll_mask() & LINUX_EPOLLIN, LINUX_EPOLLIN);

        let mut buf = [0u8; 128];
        let (read_len, _) = sock.recv_stream(&mut buf, 0).unwrap();
        assert!(read_len > 0);
        let resp = String::from_utf8_lossy(&buf[..read_len]);
        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains("mock reply"));

        // Subsequent read on EOF returns 0
        let (eof_len, _) = sock.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(eof_len, 0);
    }

    #[test]
    fn inet_stream_peer_shut_wr_poll_mask_epollrdhup_and_recv_buffered_then_eof() {
        let (s1, s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        let sent = s1.send_stream(b"in-flight", Vec::new()).unwrap();
        assert_eq!(sent, 9);
        s1.shutdown(LINUX_SHUT_WR).unwrap();

        let mask = s2.poll_mask();
        assert_eq!(mask & LINUX_EPOLLIN, LINUX_EPOLLIN, "must be readable");
        assert_eq!(
            mask & LINUX_EPOLLRDHUP,
            LINUX_EPOLLRDHUP,
            "must report peer shutdown(SHUT_WR)"
        );
        assert_eq!(
            mask & LINUX_EPOLLHUP,
            0,
            "peer shutdown(SHUT_WR) is half-close, not HUP"
        );

        let mut buf = [0u8; 16];
        let (read, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read, 9);
        assert_eq!(&buf[..read], b"in-flight");

        let (read_eof, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(
            read_eof, 0,
            "subsequent read after draining buffer must return 0 (EOF)"
        );
    }

    #[test]
    fn inet_stream_local_shut_rd_poll_mask_epollrdhup() {
        let (s1, _s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        s1.shutdown(LINUX_SHUT_RD).unwrap();
        let mask = s1.poll_mask();
        assert_eq!(mask & LINUX_EPOLLIN, LINUX_EPOLLIN, "must be readable");
        assert_eq!(
            mask & LINUX_EPOLLRDHUP,
            LINUX_EPOLLRDHUP,
            "must report local shutdown(SHUT_RD)"
        );
        assert_eq!(
            mask & LINUX_EPOLLHUP,
            0,
            "local shutdown(SHUT_RD) is half-close, not HUP"
        );
    }

    #[test]
    fn unix_stream_local_shut_rd_poll_mask_epollrdhup() {
        let (s1, _s2) = PureSocketInner::pair(
            LINUX_SOCK_STREAM,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        s1.shutdown(LINUX_SHUT_RD).unwrap();
        let mask = s1.poll_mask();
        assert_eq!(mask & LINUX_EPOLLIN, LINUX_EPOLLIN, "must be readable");
        assert_eq!(
            mask & LINUX_EPOLLRDHUP,
            LINUX_EPOLLRDHUP,
            "must report local shutdown(SHUT_RD)"
        );
        assert_eq!(
            mask & LINUX_EPOLLHUP,
            0,
            "local shutdown(SHUT_RD) is half-close, not HUP"
        );
    }

    #[test]
    fn inet_stream_peer_close_poll_mask_preserves_data_then_reports_hup_after_drain_and_send() {
        let (s1, s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        let sent = s1.send_stream(b"trailing-data", Vec::new()).unwrap();
        assert_eq!(sent, 13);
        drop(s1);

        // Remote closed while receiver still has unread data: receiver must see
        // EPOLLIN | EPOLLRDHUP, permitted write (EPOLLOUT), and NO EPOLLHUP yet.
        let mask_pre = s2.poll_mask();
        assert_eq!(
            mask_pre & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "buffered data is readable"
        );
        assert_eq!(
            mask_pre & LINUX_EPOLLRDHUP,
            LINUX_EPOLLRDHUP,
            "peer is closed"
        );
        assert_eq!(
            mask_pre & LINUX_EPOLLHUP,
            0,
            "unread data suppresses EPOLLHUP"
        );
        assert_eq!(
            mask_pre & LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            "single write permitted before terminal"
        );

        // Client writes trailing data: admitted once, entering send terminal with pending EPIPE.
        let sent_tail = s2.send_stream(b"more", Vec::new()).unwrap();
        assert_eq!(sent_tail, 4);

        // Before draining receive buffer, EPOLLHUP is still suppressed.
        let mask_mid = s2.poll_mask();
        assert_eq!(
            mask_mid & LINUX_EPOLLHUP,
            0,
            "unread data still suppresses EPOLLHUP"
        );
        assert_eq!(
            mask_mid & LINUX_EPOLLOUT,
            0,
            "send terminal clears EPOLLOUT"
        );
        assert_eq!(
            mask_mid & LINUX_EPOLLERR,
            LINUX_EPOLLERR,
            "pending EPIPE reports ERR"
        );

        // Drain the receive buffer to EOF.
        let mut buf = [0u8; 32];
        let (read, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read, 13);
        assert_eq!(&buf[..read], b"trailing-data");

        let (read_eof, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read_eof, 0);

        // After drain, receiver reports EPOLLHUP along with IN, RDHUP, ERR.
        let mask_post = s2.poll_mask();
        assert_eq!(
            mask_post & LINUX_EPOLLHUP,
            LINUX_EPOLLHUP,
            "drained terminal connection reports HUP"
        );
        assert_eq!(mask_post & LINUX_EPOLLIN, LINUX_EPOLLIN);
        assert_eq!(mask_post & LINUX_EPOLLRDHUP, LINUX_EPOLLRDHUP);
        assert_eq!(mask_post & LINUX_EPOLLERR, LINUX_EPOLLERR);
    }

    #[test]
    fn inet_stream_reset_is_reported_once_by_recv_then_eof_and_epipe() {
        let (client, server) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        // The listener closed with this connection still queued: the server
        // half is torn down and the client carries ECONNRESET.
        client.set_so_error(carrick_abi::LINUX_ECONNRESET.get());
        server.shutdown(LINUX_SHUT_RDWR).unwrap();

        let mask = client.poll_mask();
        assert_eq!(
            mask & LINUX_EPOLLERR,
            LINUX_EPOLLERR,
            "pending error polls ERR"
        );

        let mut buf = [0u8; 8];
        assert_eq!(
            client.recv_stream(&mut buf, 0).unwrap_err(),
            carrick_abi::LINUX_ECONNRESET,
            "the first recv reports the pending error"
        );
        assert_eq!(
            client.recv_stream(&mut buf, 0).unwrap().0,
            0,
            "the error is consumed; the next recv is EOF"
        );
        assert_eq!(
            client.send_stream(b"x", Vec::new()).unwrap_err(),
            LINUX_EPIPE,
            "a send after the reported reset is EPIPE"
        );
    }

    fn tcp_pair() -> (Arc<PureSocketInner>, Arc<PureSocketInner>) {
        PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        )
    }

    #[test]
    fn tcp_final_close_preserves_data_fin_and_write_error_transition() {
        let (client, server) = tcp_pair();
        let peer = "127.0.0.1:1234".parse().unwrap();
        client.state.lock().peer_sockaddr = Some(peer);
        assert_eq!(server.send_stream(b"data", Vec::new()), Ok(4));
        drop(server);

        assert_eq!(client.getpeername_addr(), Some(peer));

        let mut buf = [0; 8];
        assert_eq!(
            client.poll_mask() & LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            "TCP FIN before poll preserves writable connect completion"
        );
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 4);
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
        assert_eq!(client.send_stream(b"x", Vec::new()), Ok(1));
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
        assert_eq!(client.take_so_error(), Some(LINUX_EPIPE.get()));
        assert_eq!(client.send_stream(b"y", Vec::new()), Err(LINUX_EPIPE));
    }

    #[test]
    fn tcp_shutdown_rdwr_keeps_peer_alive_for_reset_transition() {
        let (client, server) = tcp_pair();
        server.shutdown(LINUX_SHUT_RDWR).unwrap();

        let mut buf = [0; 8];
        let mask = client.poll_mask();
        assert_eq!(mask & LINUX_EPOLLIN, LINUX_EPOLLIN);
        assert_eq!(mask & LINUX_EPOLLOUT, LINUX_EPOLLOUT);
        assert_eq!(mask & LINUX_EPOLLRDHUP, LINUX_EPOLLRDHUP);
        assert_eq!(mask & LINUX_EPOLLHUP, 0, "TCP FIN is not connection HUP");
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
        assert_eq!(client.send_stream(b"x", Vec::new()), Ok(1));
        assert_eq!(
            server.recv_stream(&mut buf, 0).unwrap_err(),
            carrick_abi::LINUX_ECONNRESET
        );
        assert_eq!(client.take_so_error(), Some(LINUX_EPIPE.get()));
        assert_eq!(client.send_stream(b"y", Vec::new()), Err(LINUX_EPIPE));
    }

    #[test]
    fn tcp_abortive_final_close_preserves_delivered_data_then_reports_reset() {
        let (client, server) = tcp_pair();
        client.state.lock().peer_sockaddr = Some("127.0.0.1:1234".parse().unwrap());
        assert_eq!(server.send_stream(b"discard", Vec::new()), Ok(7));
        server.set_so_linger((1, 0));
        drop(server);

        assert_eq!(
            client.getpeername_addr(),
            None,
            "Linux getpeername reports ENOTCONN after an abortive reset even while data remains"
        );

        let mut buf = [0; 8];
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 7);
        assert_eq!(&buf[..7], b"discard");
        assert_eq!(
            client.recv_stream(&mut buf, 0).unwrap_err(),
            carrick_abi::LINUX_ECONNRESET
        );
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
        assert_eq!(client.send_stream(b"x", Vec::new()), Err(LINUX_EPIPE));
    }

    #[test]
    fn tcp_final_close_with_unread_receive_data_reports_reset() {
        let (client, server) = tcp_pair();
        assert_eq!(client.send_stream(b"unread", Vec::new()), Ok(6));
        drop(server);

        let mut buf = [0; 8];
        assert_eq!(
            client.recv_stream(&mut buf, 0).unwrap_err(),
            carrick_abi::LINUX_ECONNRESET
        );
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
        assert_eq!(client.send_stream(b"x", Vec::new()), Err(LINUX_EPIPE));
    }

    #[test]
    fn tcp_abortive_close_error_can_be_consumed_by_send_first() {
        let (client, server) = tcp_pair();
        server.set_so_linger((1, 0));
        drop(server);

        assert_eq!(
            client.send_stream(b"x", Vec::new()),
            Err(carrick_abi::LINUX_ECONNRESET)
        );
        assert_eq!(client.send_stream(b"y", Vec::new()), Err(LINUX_EPIPE));
        let mut buf = [0; 1];
        assert_eq!(client.recv_stream(&mut buf, 0).unwrap().0, 0);
    }

    #[test]
    fn tcp_empty_send_after_fin_does_not_consume_the_admitted_write() {
        let (client, server) = tcp_pair();
        drop(server);

        assert_eq!(client.send_stream(&[], Vec::new()), Ok(0));
        assert_eq!(client.take_so_error(), None);
        assert_eq!(client.send_stream(b"x", Vec::new()), Ok(1));
        assert_eq!(client.take_so_error(), Some(LINUX_EPIPE.get()));
    }

    #[test]
    fn unix_stream_final_close_keeps_existing_epipe_semantics() {
        let (client, server) = PureSocketInner::pair(
            LINUX_SOCK_STREAM,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        drop(server);
        assert_eq!(client.send_stream(b"x", Vec::new()), Err(LINUX_EPIPE));
    }

    /// Two guest threads polling the two halves of one connection at once
    /// (a Go server and its client in the same process, each in
    /// `epoll_wait`) must never deadlock: readiness on one half needs the
    /// other half's shutdown and buffer state, and taking the two state
    /// locks in "self, then peer" order from both sides is an ABBA. Caught
    /// live on go-net_http with the in-zone pairing (executors 2 and 4
    /// parked in `poll_mask` for ever). Bounded: a wedge is a failure.
    #[test]
    fn concurrent_poll_recv_on_both_halves_never_deadlocks() {
        let (a, b) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mut handles = Vec::new();
        for (mine, other) in [
            (Arc::clone(&a), Arc::clone(&b)),
            (Arc::clone(&b), Arc::clone(&a)),
        ] {
            let done_tx = done_tx.clone();
            handles.push(std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                for i in 0..20_000u32 {
                    let _ = mine.poll_mask();
                    let _ = other.outq_bytes();
                    if i % 8 == 0 {
                        let _ = mine.send_stream(b"ping", Vec::new());
                    }
                    let _ = mine.recv_stream(&mut buf, 0);
                }
                let _ = done_tx.send(());
            }));
        }
        drop(done_tx);
        for _ in 0..2 {
            done_rx
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("both halves must finish: a timeout is the ABBA deadlock");
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn inet_stream_so_sndbuf_bounds_send_and_clears_epollout() {
        let (s1, s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        assert_eq!(s1.so_sndbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);

        // Cap send buffer to 4096 bytes
        s1.set_so_sndbuf(4096);
        assert_eq!(s1.so_sndbuf(), 4096);
        assert_eq!(s1.poll_mask() & LINUX_EPOLLOUT, LINUX_EPOLLOUT);

        // Fill buffer to capacity
        let data = vec![0x42u8; 4096];
        let sent = s1.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, 4096);

        // Buffer full: EPOLLOUT cleared, send returns EAGAIN
        assert_eq!(
            s1.poll_mask() & LINUX_EPOLLOUT,
            0,
            "full send buffer must clear EPOLLOUT"
        );
        assert_eq!(s1.send_stream(b"overflow", Vec::new()), Err(LINUX_EAGAIN));

        // Drain 1024 bytes from peer
        let mut buf = [0u8; 1024];
        let (read, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read, 1024);

        // Space freed: EPOLLOUT restored, send succeeds
        assert_eq!(
            s1.poll_mask() & LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            "draining buffer must restore EPOLLOUT"
        );
        assert_eq!(s1.send_stream(b"more", Vec::new()).unwrap(), 4);
    }

    #[test]
    fn inet_stream_oob_urgent_data_round_trip() {
        let (s1, s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        // Initially no OOB data and not ready for EPOLLPRI
        assert_eq!(s2.poll_mask() & LINUX_EPOLLPRI, 0);
        let mut buf = [0u8; 1];
        assert_eq!(s2.recv_oob(&mut buf, false), Err(LINUX_EINVAL));

        // s1 sends 1 byte OOB
        let sent = s1.send_oob(b"!").unwrap();
        assert_eq!(sent, 1);

        // s2 has EPOLLPRI asserted
        assert_eq!(s2.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);

        // Peek does not consume
        assert_eq!(s2.recv_oob(&mut buf, true), Ok(1));
        assert_eq!(buf[0], b'!');
        assert_eq!(s2.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);

        // Recv consumes
        assert_eq!(s2.recv_oob(&mut buf, false), Ok(1));
        assert_eq!(buf[0], b'!');
        assert_eq!(s2.poll_mask() & LINUX_EPOLLPRI, 0);

        // Subsequent recv without new OOB is EINVAL
        assert_eq!(s2.recv_oob(&mut buf, false), Err(LINUX_EINVAL));
    }

    #[test]
    fn inet_stream_oob_mark_caps_then_normal_read_crosses_it() {
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"hello").unwrap();
        sender.send_stream(b"world", Vec::new()).unwrap();

        let mut buf = [0u8; 8];
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 4);
        assert_eq!(&buf[..4], b"hell");
        assert!(receiver.at_oob_mark());
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);

        // A normal read at the mark crosses it, making separate MSG_OOB
        // unavailable and exposing only the ordinary suffix.
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 5);
        assert_eq!(&buf[..5], b"world");
        assert!(!receiver.at_oob_mark());
        assert_eq!(receiver.recv_oob(&mut buf, false), Err(LINUX_EINVAL));
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, 0);
    }

    #[test]
    fn inet_stream_repeated_oob_supersedes_and_materializes_old_byte() {
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"one!").unwrap();
        sender.send_oob(b"two?").unwrap();
        sender.send_stream(b"tail", Vec::new()).unwrap();

        let mut buf = [0u8; 16];
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 7);
        assert_eq!(&buf[..7], b"one!two");
        assert!(receiver.at_oob_mark());
        assert_eq!(receiver.recv_oob(&mut buf, false), Ok(1));
        assert_eq!(buf[0], b'?');
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, 0);
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 4);
        assert_eq!(&buf[..4], b"tail");
    }

    #[test]
    fn inet_stream_oob_peek_and_inline_toggle_preserve_the_mark() {
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"hello").unwrap();
        sender.send_stream(b"world", Vec::new()).unwrap();

        let mut buf = [0u8; 8];
        assert_eq!(receiver.recv_stream_flags(&mut buf, 0, true).unwrap().0, 4);
        assert_eq!(&buf[..4], b"hell");
        assert!(!receiver.at_oob_mark());
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 4);
        assert!(receiver.at_oob_mark());
        assert_eq!(receiver.recv_stream_flags(&mut buf, 0, true).unwrap().0, 5);
        assert_eq!(&buf[..5], b"world");
        assert!(receiver.at_oob_mark());
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);
        assert_eq!(receiver.recv_oob(&mut buf, true), Ok(1));
        assert_eq!(buf[0], b'o');
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);

        // OOBINLINE is evaluated when consuming pending urgent data, not when
        // it was sent.  MSG_OOB becomes EINVAL but the priority indication
        // survives until the normal read consumes the inline byte.
        receiver.set_so_oobinline(true);
        assert_eq!(receiver.recv_oob(&mut buf, false), Err(LINUX_EINVAL));
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 6);
        assert_eq!(&buf[..6], b"oworld");
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, 0);
    }

    #[test]
    fn inet_stream_inline_oob_peek_at_mark_is_non_mutating() {
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"hello").unwrap();
        sender.send_stream(b"world", Vec::new()).unwrap();

        let mut buf = [0u8; 8];
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 4);
        receiver.set_so_oobinline(true);
        assert_eq!(receiver.recv_stream_flags(&mut buf, 0, true).unwrap().0, 6);
        assert_eq!(&buf[..6], b"oworld");
        assert!(receiver.at_oob_mark());
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);
        assert_eq!(receiver.recv_stream(&mut buf, 0).unwrap().0, 6);
        assert_eq!(&buf[..6], b"oworld");

        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"!").unwrap();
        receiver.set_so_oobinline(true);
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLIN, LINUX_EPOLLIN);

        // Zero-length normal reads observe no bytes and must not cross a fresh mark.
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"!").unwrap();
        let mut empty = [];
        assert_eq!(receiver.recv_stream(&mut empty, 0).unwrap().0, 0);
        assert!(receiver.at_oob_mark());

        // A zero-length MSG_OOB PEEK retains readiness; its consuming form
        // clears the urgent indication and wakes observers just like a
        // non-empty consuming receive.
        let (sender, receiver) = tcp_pair();
        sender.send_oob(b"!").unwrap();
        assert_eq!(receiver.recv_oob(&mut empty, true), Ok(0));
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, LINUX_EPOLLPRI);
        assert_eq!(receiver.recv_oob(&mut empty, false), Ok(0));
        assert_eq!(receiver.poll_mask() & LINUX_EPOLLPRI, 0);
    }

    fn sctp_pair() -> (Arc<PureSocketInner>, Arc<PureSocketInner>) {
        PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_SCTP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        )
    }

    #[test]
    fn sctp_stream_message_boundaries_and_eor() {
        let (sender, receiver) = sctp_pair();
        assert_eq!(sender.send_stream(b"hello", Vec::new()), Ok(5));
        assert_eq!(sender.send_stream(b"world!", Vec::new()), Ok(6));

        let mut buf = [0u8; 16];
        // Reading with 16-byte buffer returns only the first 5-byte message and reports EOR = true
        let (n, _, eor) = receiver.recv_stream_record(&mut buf, 0, false).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
        assert!(eor);

        // Peek with 3-byte buffer on the second 6-byte message returns 3 bytes and reports EOR = false
        let (n, _, eor) = receiver.recv_stream_record(&mut buf[..3], 0, true).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], b"wor");
        assert!(!eor);

        // Peek with 16-byte buffer on the second 6-byte message returns 6 bytes and reports EOR = true
        let (n, _, eor) = receiver.recv_stream_record(&mut buf, 0, true).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf[..6], b"world!");
        assert!(eor);

        // Partial non-peek read of 2 bytes returns 2 bytes and reports EOR = false
        let (n, _, eor) = receiver
            .recv_stream_record(&mut buf[..2], 0, false)
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"wo");
        assert!(!eor);

        // Consuming the remaining 4 bytes reports EOR = true
        let (n, _, eor) = receiver.recv_stream_record(&mut buf, 0, false).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"rld!");
        assert!(eor);
    }

    #[test]
    fn inet_tcp_stream_default_autotunes_send_capacity_above_visible_so_buf() {
        let (s1, s2) = tcp_pair();
        assert_eq!(s1.so_sndbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);
        assert_eq!(s2.so_rcvbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);
        assert_eq!(s1.so_sndbuf_explicit(), None);
        assert_eq!(s2.so_rcvbuf_explicit(), None);

        // A default TCP stream pair must admit at least 1 MiB in one send while visible getters
        // remain 212,992.
        let one_mib = 1024 * 1024;
        let data = vec![0x5a; one_mib];
        let sent = s1
            .send_stream(&data, Vec::new())
            .expect("send 1 MiB on default TCP pair");
        assert_eq!(sent, one_mib);
        assert_eq!(s1.so_sndbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);
        assert_eq!(s2.so_rcvbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);
    }

    #[test]
    fn inet_tcp_stream_explicit_so_rcvbuf_caps_send_and_clears_epollout() {
        let (s1, s2) = tcp_pair();
        assert_eq!(s2.so_rcvbuf(), DEFAULT_STREAM_BUFFER_CAPACITY);

        // Cap receiver buffer to 4096 bytes on s2
        s2.set_so_rcvbuf(4096);
        assert_eq!(s2.so_rcvbuf(), 4096);
        assert_eq!(s1.poll_mask() & LINUX_EPOLLOUT, LINUX_EPOLLOUT);

        // Sender s1 fills receiver buffer to capacity
        let data = vec![0x42u8; 4096];
        let sent = s1.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, 4096);

        // Buffer full: EPOLLOUT cleared on sender, send returns EAGAIN
        assert_eq!(
            s1.poll_mask() & LINUX_EPOLLOUT,
            0,
            "full receiver buffer must clear sender EPOLLOUT"
        );
        assert_eq!(s1.send_stream(b"overflow", Vec::new()), Err(LINUX_EAGAIN));

        // Drain 1024 bytes from receiver s2
        let mut buf = [0u8; 1024];
        let (read, _) = s2.recv_stream(&mut buf, 0).unwrap();
        assert_eq!(read, 1024);

        // Space freed: sender EPOLLOUT restored, send succeeds
        assert_eq!(
            s1.poll_mask() & LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            "draining receiver buffer must restore sender EPOLLOUT"
        );
        assert_eq!(s1.send_stream(b"more", Vec::new()).unwrap(), 4);
    }

    #[test]
    fn inet_tcp_stream_explicit_sender_and_receiver_caps_constrained_by_both() {
        // Sender explicit 8192, receiver explicit 4096 -> effective cap 4096
        let (s1, s2) = tcp_pair();
        s1.set_so_sndbuf(8192);
        s2.set_so_rcvbuf(4096);
        let data = vec![0x42u8; 8192];
        let sent = s1.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, 4096);
        assert_eq!(s1.poll_mask() & LINUX_EPOLLOUT, 0);

        // Sender explicit 4096, receiver explicit 8192 -> effective cap 4096
        let (s3, s4) = tcp_pair();
        s3.set_so_sndbuf(4096);
        s4.set_so_rcvbuf(8192);
        let sent = s3.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, 4096);
        assert_eq!(s3.poll_mask() & LINUX_EPOLLOUT, 0);
    }

    #[test]
    fn unix_stream_does_not_autotune_beyond_default_buffer() {
        let (s1, _s2) = PureSocketInner::pair(
            LINUX_SOCK_STREAM,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );
        let data = vec![0x42u8; DEFAULT_STREAM_BUFFER_CAPACITY + 1024];
        let sent = s1.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, DEFAULT_STREAM_BUFFER_CAPACITY);
        assert_eq!(s1.poll_mask() & LINUX_EPOLLOUT, 0);
        assert_eq!(s1.send_stream(b"overflow", Vec::new()), Err(LINUX_EAGAIN));
    }

    #[test]
    fn sctp_stream_does_not_autotune_beyond_default_buffer() {
        let (s1, _s2) = sctp_pair();
        let data = vec![0x42u8; DEFAULT_STREAM_BUFFER_CAPACITY + 1024];
        let sent = s1.send_stream(&data, Vec::new()).unwrap();
        assert_eq!(sent, DEFAULT_STREAM_BUFFER_CAPACITY);
        assert_eq!(s1.poll_mask() & LINUX_EPOLLOUT, 0);
        assert_eq!(s1.send_stream(b"overflow", Vec::new()), Err(LINUX_EAGAIN));
    }
}
