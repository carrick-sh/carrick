//! Pure in-memory AF_UNIX socket implementation.
//!
//! Provides bidirectional byte streams (`SOCK_STREAM`), message queues
//! (`SOCK_DGRAM`, `SOCK_SEQPACKET`), the Linux abstract namespace (`@name` /
//! `\0...`), autobind, zero-copy file descriptor passing (`SCM_RIGHTS`),
//! and peer credential queries (`SO_PEERCRED` / `SCM_CREDENTIALS`) within
//! the Carrick runtime without creating host Darwin sockets or host temporary
//! files.

#![allow(dead_code)]

use parking_lot::{Condvar, Mutex};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};

use crate::dispatch::OpenFile;
use crate::linux_abi::{
    LINUX_EADDRINUSE, LINUX_EAGAIN, LINUX_ECONNREFUSED, LINUX_EDESTADDRREQ, LINUX_EINVAL,
    LINUX_ENOTCONN, LINUX_EOPNOTSUPP, LINUX_EPIPE, LINUX_EPOLLERR, LINUX_EPOLLHUP, LINUX_EPOLLIN,
    LINUX_EPOLLOUT, LINUX_EPOLLRDHUP, LINUX_SOCK_DGRAM, LINUX_SOCK_SEQPACKET, LINUX_SOCK_STREAM,
    LinuxErrno,
};

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

#[derive(Debug)]
pub(crate) struct UnixSocketState {
    pub bound_addr: Option<Vec<u8>>,
    pub peer: Option<Weak<UnixSocketInner>>,
    pub listening: bool,
    pub backlog_limit: usize,
    pub accept_queue: VecDeque<Arc<UnixSocketInner>>,
    pub stream_buf: VecDeque<u8>,
    pub stream_rights: VecDeque<Arc<OpenFile>>,
    pub dgram_queue: VecDeque<UnixDatagram>,
    pub creds: LinuxUcred,
    pub peer_creds: Option<LinuxUcred>,
    pub shutdown_read: bool,
    pub shutdown_write: bool,
    pub so_passcred: bool,
    pub so_error: Option<i32>,
}

#[derive(Debug)]
pub(crate) struct UnixSocketInner {
    pub socket_type: i32,
    pub state: Mutex<UnixSocketState>,
    pub changed: Condvar,
}

impl UnixSocketInner {
    pub(crate) fn new(socket_type: i32, creds: LinuxUcred) -> Arc<Self> {
        Arc::new(Self {
            socket_type,
            state: Mutex::new(UnixSocketState {
                bound_addr: None,
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
        let first = Self::new(socket_type, creds1);
        let second = Self::new(socket_type, creds2);

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
            // Autobind: assign unique abstract name \0xxxxx
            let auto = registry.autobind_abstract_name();
            registry.register_abstract(auto.clone(), Arc::clone(self))?;
            auto
        } else if sun_path[0] == 0 {
            // Abstract socket
            registry.register_abstract(sun_path.to_vec(), Arc::clone(self))?;
            sun_path.to_vec()
        } else {
            // Pathname socket
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

        // Stream / SeqPacket connection
        let mut target_state = target.state.lock();
        if !target_state.listening {
            return Err(LINUX_ECONNREFUSED);
        }

        if target_state.accept_queue.len() >= target_state.backlog_limit.max(128) {
            return Err(LINUX_EAGAIN);
        }

        let server_side = Self::new(self.socket_type, target_state.creds);
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

    pub(crate) fn accept(self: &Arc<Self>) -> Result<Arc<UnixSocketInner>, LinuxErrno> {
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
        let peer_arc = {
            let state = self.state.lock();
            if state.shutdown_write {
                return Err(LINUX_EPIPE);
            }
            let Some(peer_weak) = &state.peer else {
                return Err(LINUX_ENOTCONN);
            };
            let Some(peer) = peer_weak.upgrade() else {
                return Err(LINUX_EPIPE);
            };
            peer
        };

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
            let peer_alive = state
                .peer
                .as_ref()
                .and_then(|p| p.upgrade())
                .is_some_and(|p| !p.state.lock().shutdown_write);

            if !state.stream_buf.is_empty() || state.shutdown_read || !peer_alive {
                mask |= LINUX_EPOLLIN;
            }
            if !state.shutdown_write && peer_alive {
                if let Some(peer) = state.peer.as_ref().and_then(|p| p.upgrade()) {
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
            // Datagram
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

#[derive(Default, Debug)]
pub(crate) struct UnixSocketRegistry {
    pub(crate) abstract_sockets: Mutex<HashMap<Vec<u8>, Arc<UnixSocketInner>>>,
    pub(crate) pathname_sockets: Mutex<HashMap<String, Arc<UnixSocketInner>>>,
    pub(crate) autobind_counter: AtomicU32,
}

impl UnixSocketRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register_abstract(
        &self,
        name: Vec<u8>,
        sock: Arc<UnixSocketInner>,
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

    pub(crate) fn lookup_abstract(&self, name: &[u8]) -> Option<Arc<UnixSocketInner>> {
        self.abstract_sockets.lock().get(name).cloned()
    }

    pub(crate) fn register_pathname(
        &self,
        path: String,
        sock: Arc<UnixSocketInner>,
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

    pub(crate) fn lookup_pathname(&self, path: &str) -> Option<Arc<UnixSocketInner>> {
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
        let (s1, s2) = UnixSocketInner::pair(LINUX_SOCK_STREAM, creds1, creds2);

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

        let server = UnixSocketInner::new(LINUX_SOCK_STREAM, creds);
        let abstract_name = b"\0test_service";
        server.bind(abstract_name, &registry).unwrap();
        server.listen(10).unwrap();

        let client = UnixSocketInner::new(LINUX_SOCK_STREAM, creds);
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

        let server = UnixSocketInner::new(LINUX_SOCK_DGRAM, creds);
        let server_name = b"\0dgram_server";
        server.bind(server_name, &registry).unwrap();

        let client = UnixSocketInner::new(LINUX_SOCK_DGRAM, creds);
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
}
