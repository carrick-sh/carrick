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
    LINUX_EINVAL, LINUX_ENOTCONN, LINUX_EOPNOTSUPP, LINUX_EPIPE, LINUX_EPOLLERR, LINUX_EPOLLHUP,
    LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_EPOLLRDHUP, LINUX_SOCK_DGRAM, LINUX_SOCK_SEQPACKET,
    LINUX_SOCK_STREAM, LinuxErrno,
};
use crate::network::interposer::{ConnectionRecordState, MockService};

pub const LINUX_SHUT_RD: i32 = 0;
pub const LINUX_SHUT_WR: i32 = 1;
pub const LINUX_SHUT_RDWR: i32 = 2;

/// Default capacity for stream socket ring buffers (matches Linux default ~208 KiB).
pub const DEFAULT_STREAM_BUFFER_CAPACITY: usize = 212_992;
/// Max queued datagrams before backpressure/drop.
pub const DEFAULT_DGRAM_QUEUE_LIMIT: usize = 256;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinuxUcred {
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
pub(crate) struct UnixDatagram {
    pub payload: Vec<u8>,
    pub sender_addr: Option<Vec<u8>>,
    pub sender_creds: Option<LinuxUcred>,
    pub rights: Vec<Arc<OpenFile>>,
}

pub(crate) struct PureSocketState {
    pub bound_addr: Option<Vec<u8>>,
    pub local_sockaddr: Option<SocketAddr>,
    pub peer_sockaddr: Option<SocketAddr>,
    pub peer: Option<Weak<PureSocketInner>>,
    pub listening: bool,
    pub backlog_limit: usize,
    pub accept_queue: VecDeque<Arc<PureSocketInner>>,
    pub stream_buf: VecDeque<u8>,
    pub stream_rights: VecDeque<Arc<OpenFile>>,
    pub dgram_queue: VecDeque<UnixDatagram>,
    pub creds: LinuxUcred,
    pub peer_creds: Option<LinuxUcred>,
    pub shutdown_read: bool,
    pub shutdown_write: bool,
    pub so_passcred: bool,
    pub so_error: Option<i32>,
    pub so_rcvtimeo: Option<Duration>,
    pub so_sndtimeo: Option<Duration>,
    pub mock_service: Option<Arc<dyn MockService>>,
    pub mock_peer_closed: bool,
    pub connection_record: Option<Arc<Mutex<ConnectionRecordState>>>,
    pub request_buf: Vec<u8>,
}

pub struct PureSocketInner {
    pub(crate) family: i32,
    pub(crate) socket_type: i32,
    pub(crate) protocol: i32,
    pub(crate) state: Mutex<PureSocketState>,
    pub(crate) changed: Condvar,
}

impl std::fmt::Debug for PureSocketInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PureSocketInner")
            .field("family", &self.family)
            .field("socket_type", &self.socket_type)
            .field("protocol", &self.protocol)
            .finish()
    }
}

pub(crate) type UnixSocketState = PureSocketState;
pub(crate) type UnixSocketInner = PureSocketInner;

impl PureSocketInner {
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
            family,
            socket_type,
            protocol,
            state: Mutex::new(PureSocketState {
                bound_addr: None,
                local_sockaddr: None,
                peer_sockaddr: None,
                peer: None,
                listening: false,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                stream_buf: VecDeque::new(),
                stream_rights: VecDeque::new(),
                dgram_queue: VecDeque::new(),
                creds,
                peer_creds: None,
                shutdown_read: false,
                shutdown_write: false,
                so_passcred: false,
                so_error: None,
                so_rcvtimeo: None,
                so_sndtimeo: None,
                mock_service: None,
                mock_peer_closed: false,
                connection_record: None,
                request_buf: Vec::new(),
            }),
            changed: Condvar::new(),
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
            family,
            socket_type,
            protocol,
            state: Mutex::new(PureSocketState {
                bound_addr: None,
                local_sockaddr: local_addr,
                peer_sockaddr: peer_addr,
                peer: None,
                listening: false,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                stream_buf: VecDeque::new(),
                stream_rights: VecDeque::new(),
                dgram_queue: VecDeque::new(),
                creds: LinuxUcred::default(),
                peer_creds: None,
                shutdown_read: false,
                shutdown_write: false,
                so_passcred: false,
                so_error: None,
                so_rcvtimeo: None,
                so_sndtimeo: None,
                mock_service: Some(mock),
                mock_peer_closed: false,
                connection_record: record,
                request_buf: Vec::new(),
            }),
            changed: Condvar::new(),
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
        if let Some(rec_ref) = &state.connection_record {
            let mut rec = rec_ref.lock();
            rec.bytes_received += bytes.len();
            if rec.capture_payload {
                if let Some(payload) = &mut rec.received_payload {
                    payload.extend_from_slice(bytes);
                }
            }
        }
        self.changed.notify_all();
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

    pub(crate) fn take_so_error(&self) -> Option<i32> {
        self.state.lock().so_error.take()
    }

    pub(crate) fn set_so_error(&self, err: i32) {
        self.state.lock().so_error = Some(err);
        self.changed.notify_all();
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
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn listen(self: &Arc<Self>, backlog: i32) -> Result<(), LinuxErrno> {
        let mut state = self.state.lock();
        if self.socket_type != LINUX_SOCK_STREAM && self.socket_type != LINUX_SOCK_SEQPACKET {
            return Err(LINUX_EOPNOTSUPP);
        }
        state.listening = true;
        state.backlog_limit = backlog.max(0) as usize;
        self.changed.notify_all();
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
            self.family,
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
        target.changed.notify_all();
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
        if state.shutdown_write {
            return Err(LINUX_EPIPE);
        }

        // Mock Service Interception Path
        if let Some(mock) = state.mock_service.clone() {
            if state.mock_peer_closed {
                return Err(LINUX_EPIPE);
            }
            let available = DEFAULT_STREAM_BUFFER_CAPACITY.saturating_sub(state.request_buf.len());
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
            self.changed.notify_all();
            return Ok(to_write);
        }

        // Interconnected Peer Path
        let peer_arc = {
            let Some(peer_weak) = &state.peer else {
                return Err(LINUX_ENOTCONN);
            };
            let Some(peer) = peer_weak.upgrade() else {
                return Err(LINUX_EPIPE);
            };
            peer
        };
        drop(state);

        let mut peer_state = peer_arc.state.lock();
        if peer_state.shutdown_read {
            return Err(LINUX_EPIPE);
        }

        let available = DEFAULT_STREAM_BUFFER_CAPACITY.saturating_sub(peer_state.stream_buf.len());
        if available == 0 && !data.is_empty() {
            return Err(LINUX_EAGAIN);
        }

        let to_write = data.len().min(available);
        peer_state.stream_buf.extend(&data[..to_write]);
        if !rights.is_empty() {
            peer_state.stream_rights.extend(rights);
        }
        peer_arc.changed.notify_all();
        Ok(to_write)
    }

    pub(crate) fn recv_stream(
        &self,
        buf: &mut [u8],
        max_rights: usize,
    ) -> Result<(usize, Vec<Arc<OpenFile>>), LinuxErrno> {
        let mut state = self.state.lock();
        if state.shutdown_read {
            return Ok((0, Vec::new()));
        }

        if state.stream_buf.is_empty() {
            if state.mock_service.is_some() {
                if state.mock_peer_closed {
                    return Ok((0, Vec::new()));
                }
                return Err(LINUX_EAGAIN);
            }

            let is_peer_alive = state
                .peer
                .as_ref()
                .and_then(|p| p.upgrade())
                .is_some_and(|p| !p.state.lock().shutdown_write);
            if !is_peer_alive {
                return Ok((0, Vec::new()));
            }
            return Err(LINUX_EAGAIN);
        }

        let to_read = buf.len().min(state.stream_buf.len());
        for slot in buf.iter_mut().take(to_read) {
            *slot = state.stream_buf.pop_front().unwrap_or(0);
        }

        let mut rights = Vec::new();
        while rights.len() < max_rights && !state.stream_rights.is_empty() {
            if let Some(right) = state.stream_rights.pop_front() {
                rights.push(right);
            }
        }

        if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
            peer.changed.notify_all();
        }

        Ok((to_read, rights))
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

        target.changed.notify_all();
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
        match how {
            LINUX_SHUT_RD => state.shutdown_read = true,
            LINUX_SHUT_WR => state.shutdown_write = true,
            LINUX_SHUT_RDWR => {
                state.shutdown_read = true;
                state.shutdown_write = true;
            }
            _ => return Err(LINUX_EINVAL),
        }

        if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
            peer.changed.notify_all();
        }
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn poll_mask(&self) -> u32 {
        let state = self.state.lock();
        let mut mask = 0;

        if state.listening {
            if !state.accept_queue.is_empty() {
                mask |= LINUX_EPOLLIN;
            }
            return mask;
        }

        if self.socket_type == LINUX_SOCK_STREAM || self.socket_type == LINUX_SOCK_SEQPACKET {
            let has_mock = state.mock_service.is_some();
            let peer_alive = if has_mock {
                !state.mock_peer_closed
            } else {
                state
                    .peer
                    .as_ref()
                    .and_then(|p| p.upgrade())
                    .is_some_and(|p| !p.state.lock().shutdown_write)
            };

            if !state.stream_buf.is_empty() || state.shutdown_read || !peer_alive {
                mask |= LINUX_EPOLLIN;
            }
            if !state.shutdown_write && peer_alive {
                if has_mock {
                    mask |= LINUX_EPOLLOUT;
                } else if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
                    let peer_used = peer.state.lock().stream_buf.len();
                    if peer_used < DEFAULT_STREAM_BUFFER_CAPACITY {
                        mask |= LINUX_EPOLLOUT;
                    }
                }
            }
            if !peer_alive {
                mask |= LINUX_EPOLLHUP | LINUX_EPOLLRDHUP;
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
        state.shutdown_read = true;
        state.shutdown_write = true;
        state.mock_peer_closed = true;
        if let Some(rec_ref) = &state.connection_record {
            let mut rec = rec_ref.lock();
            rec.completed = true;
        }
        if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
            peer.changed.notify_all();
        }
    }
}

#[derive(Default, Debug)]
pub(crate) struct UnixSocketRegistry {
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
}
