//! Host-constructible fixtures for every [`WaitQueueKind`].
//!
//! [`OpenDescription`] is private to `crate::dispatch`, so the enrollment-gap
//! property in `vcpu_loop::continuation::tests::wait_enrollment_gap` cannot
//! build its own descriptions. This module is the seam: one fixture per kind,
//! each carrying the description, the poll interest its producer satisfies,
//! and the producer itself.
//!
//! Every fixture starts NOT ready for its interest and becomes ready when the
//! producer runs, so the test can fire the producer in the window between the
//! syscall's own readiness check and the wait service's enrollment.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use carrick_abi::{LinuxEpollEvent, LinuxPollEvents};
use parking_lot::RwLock;

use crate::dispatch::fd_table::{
    EventFdState, HostFdRef, OpenDescription, OpenDescriptionBase, TimerFdState, WaitQueueKind,
    kernel_file_description,
};
use crate::dispatch::net::unix_pure::{LinuxUcred, PureSocketInner};
use crate::kernel::FileDescription;
use crate::network::GuestSocketAddr;
use crate::network::inzone::{InZoneListener, InZoneListenerKey, InZoneScope};

/// One description plus the producer edge that makes it ready.
pub(crate) struct WaitQueueFixture {
    description: Arc<FileDescription>,
    interest: LinuxPollEvents,
    producer: Box<dyn FnMut() + Send>,
    /// Host resources (a listening socket, the in-zone registry entry the
    /// description only holds weakly) that must outlive the fixture.
    _guards: Vec<Guard>,
}

enum Guard {
    Listener(#[allow(dead_code)] Arc<InZoneListener>),
    HostFds(Arc<Mutex<Vec<i32>>>),
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Self::HostFds(fds) = self {
            for fd in fds.lock().unwrap_or_else(|p| p.into_inner()).drain(..) {
                unsafe { libc::close(fd) };
            }
        }
    }
}

impl WaitQueueFixture {
    pub(crate) fn description(&self) -> &Arc<FileDescription> {
        &self.description
    }

    pub(crate) fn interest(&self) -> LinuxPollEvents {
        self.interest
    }

    /// Fire the producer edge. Called with NO wait-queue enrollment live, so
    /// the wake itself is lost by construction and only a post-enrollment
    /// readiness probe can recover it.
    pub(crate) fn fire_producer(&mut self) {
        (self.producer)();
    }
}

fn install(open: OpenDescription) -> Arc<FileDescription> {
    kernel_file_description(Arc::new(RwLock::new(open)), 0)
}

fn listener_key(port: u16) -> InZoneListenerKey {
    InZoneListenerKey {
        scope: InZoneScope::CarrierHost,
        addr: GuestSocketAddr(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
    }
}

fn loopback_sockaddr(port: u16) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    addr
}

/// A bound, listening host TCP socket on loopback, plus the port it got.
fn host_listen_socket() -> (i32, u16) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "host listen socket");
    let addr = loopback_sockaddr(0);
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    assert_eq!(
        unsafe { libc::bind(fd, std::ptr::addr_of!(addr).cast(), len) },
        0,
        "bind loopback"
    );
    assert_eq!(unsafe { libc::listen(fd, 16) }, 0, "listen");
    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut bound_len = len;
    assert_eq!(
        unsafe { libc::getsockname(fd, std::ptr::addr_of_mut!(bound).cast(), &mut bound_len) },
        0,
        "getsockname"
    );
    (fd, u16::from_be(bound.sin_port))
}

/// Build the fixture for `kind`.
pub(crate) fn fixture(kind: WaitQueueKind) -> WaitQueueFixture {
    match kind {
        WaitQueueKind::PipeReader => pipe_reader(),
        WaitQueueKind::PipeWriter => pipe_writer(),
        WaitQueueKind::EventFd => eventfd(),
        WaitQueueKind::TimerFd => timerfd(),
        WaitQueueKind::InMemorySocket => in_memory_socket(),
        WaitQueueKind::InZoneListenerSocket => inzone_listener_socket(),
        WaitQueueKind::Epoll => epoll(),
        WaitQueueKind::Netlink => netlink(),
        WaitQueueKind::Packet => packet(),
        WaitQueueKind::InZoneListenerHostSocket => inzone_listener_host_socket(false),
    }
}

/// The in-zone listener's second producer: a HOST client connecting to the
/// Darwin listen socket, rather than an in-zone `connect` pairing in memory.
/// Both must survive the enrollment gap, which is why the source is dual.
pub(crate) fn inzone_listener_host_socket_with_host_client() -> WaitQueueFixture {
    inzone_listener_host_socket(true)
}

fn new_pipe() -> crate::dispatch::fd_table::PipeRef {
    Arc::new(crate::dispatch::fs::pipe::PipeInner::new(
        crate::dispatch::fs::pipe::next_pipe_id(),
        crate::dispatch::fs::pipe::DEFAULT_PIPE_CAPACITY,
    ))
}

fn pipe_reader() -> WaitQueueFixture {
    let pipe = new_pipe();
    {
        let mut state = pipe.state.lock();
        state.readers = 1;
        state.writers = 1;
    }
    let producer_pipe = Arc::clone(&pipe);
    WaitQueueFixture {
        description: install(OpenDescription::PipeReader {
            base: OpenDescriptionBase::new(0),
            pipe,
        }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            let mut state = producer_pipe.state.lock();
            state.buffer.extend(b"gap".iter().copied());
            drop(state);
            producer_pipe.wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn pipe_writer() -> WaitQueueFixture {
    let pipe = new_pipe();
    {
        let mut state = pipe.state.lock();
        state.readers = 1;
        state.writers = 1;
        // A full pipe is the only state in which a writer is NOT already
        // writable, so it is the only one with a real producer edge.
        let capacity = state.capacity;
        assert!(capacity > 0, "pipe capacity");
        state.buffer.extend(std::iter::repeat_n(0u8, capacity));
    }
    let producer_pipe = Arc::clone(&pipe);
    WaitQueueFixture {
        description: install(OpenDescription::PipeWriter {
            base: OpenDescriptionBase::new(0),
            pipe,
        }),
        interest: LinuxPollEvents::OUT,
        producer: Box::new(move || {
            let mut state = producer_pipe.state.lock();
            state.buffer.clear();
            drop(state);
            producer_pipe.wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn eventfd() -> WaitQueueFixture {
    let state = Arc::new(EventFdState::new(0));
    let producer_state = Arc::clone(&state);
    WaitQueueFixture {
        description: install(OpenDescription::EventFd {
            base: OpenDescriptionBase::new(0),
            state,
            semaphore: false,
        }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            producer_state
                .counter_ref()
                .store(1, std::sync::atomic::Ordering::SeqCst);
            producer_state.wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn timerfd() -> WaitQueueFixture {
    let clock = Arc::new(crate::kernel::container::ClockDomain::new(
        crate::kernel::container::TimeControl::System,
    ));
    let state = Arc::new(TimerFdState::new(clock, carrick_abi::LINUX_CLOCK_MONOTONIC));
    let producer_state = Arc::clone(&state);
    WaitQueueFixture {
        description: install(OpenDescription::TimerFd {
            base: OpenDescriptionBase::new(0),
            state,
        }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            // An already-elapsed deadline is what an armed timer looks like
            // once it fires; `timerfd_ready_count` then reports the expiration.
            producer_state.inner.lock().deadline = Some(std::time::Duration::ZERO);
            producer_state.wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn pure_stream_socket() -> Arc<PureSocketInner> {
    PureSocketInner::new(
        carrick_abi::LINUX_SOCK_STREAM,
        LinuxUcred {
            pid: 1,
            uid: 0,
            gid: 0,
        },
    )
}

fn in_memory_socket() -> WaitQueueFixture {
    let socket = pure_stream_socket();
    let producer_socket = Arc::clone(&socket);
    WaitQueueFixture {
        description: install(OpenDescription::InMemorySocket {
            base: OpenDescriptionBase::new(0),
            socket,
        }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            producer_socket
                .state
                .lock()
                .stream_buf
                .extend(b"gap".iter().copied());
            producer_socket.notify_waiters();
        }),
        _guards: Vec::new(),
    }
}

fn inzone_listener_socket() -> WaitQueueFixture {
    let socket = pure_stream_socket();
    socket.state.lock().listening = true;
    let listener = Arc::new(InZoneListener::new(listener_key(4100), 16, false, false));
    let mut base = OpenDescriptionBase::new(0);
    base.set_listening(true);
    base.set_inzone_listener(Some(Arc::downgrade(&listener)));
    let producer_listener = Arc::clone(&listener);
    WaitQueueFixture {
        description: install(OpenDescription::InMemorySocket { base, socket }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            producer_listener.enqueue(pure_stream_socket());
        }),
        _guards: vec![Guard::Listener(listener)],
    }
}

fn epoll() -> WaitQueueFixture {
    let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
    mux.register_user(0).expect("register user wake");
    let wait_queue = Arc::new(crate::kernel::WaitQueue::new());
    let description = install(OpenDescription::Epoll {
        base: OpenDescriptionBase::new(0),
        interest: std::collections::HashMap::new(),
        synthetic_interest_count: 0,
        pending_ready: VecDeque::new(),
        kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
            mux,
            crate::dispatch::new_epoll_wake_registry(),
        )),
        wait_queue: Arc::clone(&wait_queue),
    });
    let producer_description = Arc::clone(&description);
    WaitQueueFixture {
        description,
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            // An event the instance already observed but has not handed to the
            // guest (the `maxevents` remainder) is what makes an epoll fd
            // readable without re-polling its targets.
            if let Some(mut open) = producer_description.write()
                && let OpenDescription::Epoll { pending_ready, .. } = &mut *open
            {
                pending_ready.push_back((
                    7,
                    LinuxEpollEvent {
                        events: carrick_abi::LINUX_EPOLLIN,
                        _pad: 0,
                        data: 7,
                    },
                ));
            }
            wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn netlink() -> WaitQueueFixture {
    let wait_queue = Arc::new(crate::kernel::WaitQueue::new());
    let description = install(OpenDescription::Netlink {
        base: OpenDescriptionBase::new(0),
        protocol: 0,
        sock_type: carrick_abi::LINUX_SOCK_DGRAM,
        pid: 0,
        groups: 0,
        recv_queue: VecDeque::new(),
        wait_queue: Arc::clone(&wait_queue),
    });
    let producer_description = Arc::clone(&description);
    WaitQueueFixture {
        description,
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            if let Some(mut open) = producer_description.write()
                && let OpenDescription::Netlink { recv_queue, .. } = &mut *open
            {
                recv_queue.extend(std::iter::repeat_n(0xAAu8, 32));
            }
            wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn packet() -> WaitQueueFixture {
    let socket = Arc::new(crate::dispatch::net::packet::PacketSocket::new(
        carrick_abi::LINUX_SOCK_RAW,
        0,
    ));
    let producer_socket = Arc::clone(&socket);
    WaitQueueFixture {
        description: install(OpenDescription::Packet {
            base: OpenDescriptionBase::new(0),
            socket,
        }),
        interest: LinuxPollEvents::IN,
        producer: Box::new(move || {
            producer_socket.raw_queue.lock().push_back(vec![0xAA; 16]);
            producer_socket
                .has_pending
                .store(true, std::sync::atomic::Ordering::Release);
            producer_socket.wait_queue.wake_all();
        }),
        _guards: Vec::new(),
    }
}

fn inzone_listener_host_socket(host_client: bool) -> WaitQueueFixture {
    let (listen_fd, port) = host_listen_socket();
    let owned = Arc::new(Mutex::new(vec![listen_fd]));
    let listener = Arc::new(InZoneListener::new(listener_key(port), 16, false, false));
    let mut base = OpenDescriptionBase::new(0);
    base.set_listening(true);
    base.set_inzone_listener(Some(Arc::downgrade(&listener)));
    let host_fd = unsafe { libc::dup(listen_fd) };
    assert!(host_fd >= 0, "dup listen fd");
    let description = install(OpenDescription::HostSocket {
        base,
        host_fd: HostFdRef::new(host_fd),
        family: carrick_abi::LINUX_AF_INET,
        type_: carrick_abi::LINUX_SOCK_STREAM,
        protocol: 0,
        mcast_memberships: Vec::new(),
        synthetic_recv: VecDeque::new(),
    });
    let producer_listener = Arc::clone(&listener);
    let producer_owned = Arc::clone(&owned);
    let producer: Box<dyn FnMut() + Send> = if host_client {
        Box::new(move || {
            let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(client >= 0, "host client socket");
            producer_owned
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(client);
            let addr = loopback_sockaddr(port);
            let rc = unsafe {
                libc::connect(
                    client,
                    std::ptr::addr_of!(addr).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "host client connect");
            // The connection must be QUEUED on the Darwin listener before the
            // probe runs, or the test measures scheduling, not the gap.
            let mut pfd = libc::pollfd {
                fd: client,
                events: libc::POLLOUT,
                revents: 0,
            };
            assert!(
                unsafe { libc::poll(&mut pfd, 1, 5_000) } > 0,
                "host client connect did not complete within 5s"
            );
        })
    } else {
        Box::new(move || {
            producer_listener.enqueue(pure_stream_socket());
        })
    };
    WaitQueueFixture {
        description,
        interest: LinuxPollEvents::IN,
        producer,
        _guards: vec![Guard::Listener(listener), Guard::HostFds(owned)],
    }
}

/// The kind a fixture's description classifies as. `OpenDescription` is
/// private to `crate::dispatch`, so the property test reaches the classifier
/// through here.
pub(crate) fn classify(description: &Arc<FileDescription>) -> Option<WaitQueueKind> {
    description.read().and_then(|open| open.wait_queue_kind())
}
