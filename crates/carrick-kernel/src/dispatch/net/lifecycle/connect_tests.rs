//! Hold connect inside its listener wake while accept arms an RDHUP wait.
//! No host scheduling, sleeps, or readiness reactor is needed for this ordering.

#[cfg(test)]
#[cfg(feature = "loom")]
mod loom_models;

use super::*;
use crate::compat::{CompatReporter, SyscallArgs};
use crate::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
use carrick_abi::syscall::nr;
use carrick_abi::{CanonicalNr, LINUX_EPOLLOUT, LINUX_EPOLLRDHUP};
use carrick_guest_mem::GuestMemory;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

struct Peer {
    dispatcher: SyscallDispatcher,
    memory: LinearMemory,
    accepted: Option<(u64, u64)>,
}

impl Peer {
    fn call(&mut self, nr: CanonicalNr, args: [u64; 6]) -> DispatchOutcome {
        self.dispatcher
            .dispatch(
                &self.dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(nr.raw(), SyscallArgs::from(args)),
                &mut self.memory,
                &CompatReporter::default(),
            )
            .unwrap()
    }

    fn returned(&mut self, nr: CanonicalNr, args: [u64; 6]) -> u64 {
        match self.call(nr, args) {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("{nr:?}: {other:?}"),
        }
    }

    fn epoll(&mut self, fd: u64, events: u32) -> u64 {
        let epfd = self.returned(nr::EPOLL_CREATE1, [0; 6]);
        let mut event = [0; 16];
        event[..4].copy_from_slice(&events.to_ne_bytes());
        event[8..].copy_from_slice(&0x8765_4321_u64.to_ne_bytes());
        self.memory.write_bytes(0x1100, &event).unwrap();
        assert_eq!(self.returned(nr::EPOLL_CTL, [epfd, 1, fd, 0x1100, 0, 0]), 0);
        epfd
    }
}

#[test]
fn connect_publication_does_not_wake_a_newly_accepted_rdhup_wait() {
    // Linux authority: man 2 connect, man 2 shutdown, man 7 epoll. Connection
    // establishment does not close the peer's write half. Structural contract:
    // the accepted RDHUP wait needs only its initial and FIN dispatches.
    let mut parent = Peer {
        dispatcher: SyscallDispatcher::new(),
        memory: LinearMemory::new(0x1000, vec![0; 0x1000]),
        accepted: None,
    };
    let listener_fd = parent.returned(nr::SOCKET, [2, 1, 0, 0, 0, 0]);
    let mut addr = [0; 16];
    addr[..2].copy_from_slice(&2_u16.to_ne_bytes());
    addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    parent.memory.write_bytes(0x1000, &addr).unwrap();
    assert_eq!(
        parent.returned(nr::BIND, [listener_fd, 0x1000, 16, 0, 0, 0]),
        0
    );
    assert_eq!(parent.returned(nr::LISTEN, [listener_fd, 1, 0, 0, 0, 0]), 0);
    parent
        .memory
        .write_bytes(0x1020, &16_u32.to_ne_bytes())
        .unwrap();
    assert_eq!(
        parent.returned(nr::GETSOCKNAME, [listener_fd, 0x1000, 0x1020, 0, 0, 0]),
        0
    );
    let addr = parent.memory.read_bytes(0x1000, 16).unwrap();
    let client_fd = parent.returned(nr::SOCKET, [2, 1, 0, 0, 0, 0]);
    // A pre-connect watcher must still receive the client's writable change.
    let client_epfd = parent.epoll(client_fd, LINUX_EPOLLOUT);
    parent.returned(nr::EPOLL_PWAIT, [client_epfd, 0x1200, 1, 0, 0, 0]);

    let context = parent.dispatcher.capture_one_task_context().unwrap();
    let tid = context.thread().registry_id();
    let child_context = context
        .kernel()
        .reserve_fork(
            &context,
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).unwrap(),
            "connect-wake-child".into(),
            None,
        )
        .unwrap()
        .prepare_reference(crate::thread::ThreadId::from_guest_supplied_tid(2))
        .unwrap()
        .commit()
        .unwrap()
        .into_parts()
        .unwrap()
        .0;
    let child =
        parent
            .dispatcher
            .fork_clone_in_process(tid, child_context.thread().registry_id(), 1, 2);
    *child.kernel_binding.write() = child_context.task_binding();
    let mut child = Peer {
        dispatcher: child,
        memory: LinearMemory::new(0x1000, vec![0; 0x1000]),
        accepted: None,
    };
    child.memory.write_bytes(0x1000, &addr).unwrap();

    let listener = parent
        .dispatcher
        .open_file(listener_fd as i32)
        .unwrap()
        .description
        .inspect_kind(|open| match open {
            OpenDescription::HostSocket { base, .. } => base.inzone_listener(),
            _ => None,
        })
        .flatten()
        .unwrap();
    let parent = Arc::new(Mutex::new(parent));
    let accepting = Arc::clone(&parent);
    let once = AtomicBool::new(false);
    let _enrollment = listener.wait_queue().enroll_callback(move |_| {
        // accept's dequeue also wakes this queue; only handle the enqueue.
        if once.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut peer = accepting.lock();
        let accepted = peer.returned(nr::ACCEPT, [listener_fd, 0, 0, 0, 0, 0]);
        let epfd = peer.epoll(accepted, LINUX_EPOLLRDHUP);
        assert!(matches!(
            peer.call(nr::EPOLL_PWAIT, [epfd, 0x1200, 1, u64::MAX, 0, 0]),
            DispatchOutcome::WaitOnFds { .. }
        ));
        peer.accepted = Some((accepted, epfd));
        // Returning releases connect to finish its notification, AFTER this
        // epoll has drained its ctl wake, checked RDHUP, and built its wait.
    });
    assert_eq!(
        child.returned(nr::CONNECT, [client_fd, 0x1000, 16, 0, 0, 0]),
        0
    );

    let mut peer = parent.lock();
    let (accepted, epfd) = peer.accepted.unwrap();
    let kqueue = peer
        .dispatcher
        .open_file(epfd as i32)
        .unwrap()
        .description
        .inspect_kind(|open| match open {
            OpenDescription::Epoll { kqueue, .. } => Some(Arc::clone(kqueue)),
            _ => None,
        })
        .flatten()
        .unwrap();
    let mut pollfd = libc::pollfd {
        fd: kqueue.poll_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut pollfd, 1, 0) },
        0,
        "late connect notification must not cause a third RDHUP dispatch"
    );
    assert_eq!(
        peer.returned(nr::EPOLL_PWAIT, [client_epfd, 0x1300, 1, 0, 0, 0]),
        1,
        "client's pre-connect epoll registration must still become writable"
    );
    assert_eq!(child.returned(nr::SHUTDOWN, [client_fd, 1, 0, 0, 0, 0]), 0);
    assert_eq!(
        peer.returned(nr::EPOLL_PWAIT, [epfd, 0x1200, 1, u64::MAX, 0, 0]),
        1
    );
    let event = peer.memory.read_bytes(0x1200, 16).unwrap();
    assert_ne!(
        u32::from_ne_bytes(event[..4].try_into().unwrap()) & LINUX_EPOLLRDHUP,
        0
    );
    assert_eq!(
        u64::from_ne_bytes(event[8..].try_into().unwrap()),
        0x8765_4321
    );
    assert_eq!(
        peer.returned(nr::READ, [accepted, 0x1400, 16, 0, 0, 0]),
        0,
        "EOF while the child retains the half-closed client"
    );
}
