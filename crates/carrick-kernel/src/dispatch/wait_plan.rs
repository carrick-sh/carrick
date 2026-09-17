//! One assembly for every wait-shaped syscall.
//!
//! `ppoll` and `pselect6` each carried their own four-arm body: an all-host
//! arm that batched one `libc::poll(.., 0)`, a mixed arm that ran the per-fd
//! `poll_ready_events` loop, and two park constructions. The two bodies
//! answered the same question — "is this guest fd ready, and if not what does
//! the wait park on?" — and drifted apart while doing it (only `ppoll`
//! reconstructs `POLLRDHUP`, strips a spurious `POLLPRI`, and refuses
//! `POLLOUT` on a listening socket).
//!
//! [`NetView::assemble_wait`] is the single answer. It classifies every
//! requested fd through `wait_source_for`, batches ONE non-blocking host poll
//! over the host halves, samples the description where the host descriptor
//! cannot answer, and hands back per-fd revents in REQUEST order plus the
//! typed park. What is left in the syscalls is ABI marshalling: `fd_set`
//! bitmaps and `clear_on_timeout` for select, `pollfd` writeback for poll.
//!
//! Where the two ABIs genuinely disagree, the disagreement is an INPUT to the
//! one assembly rather than a second body: [`InvalidFdPolicy`] carries what
//! the caller owes the guest for an fd naming no open description.

use carrick_abi::{LINUX_EBADF, LinuxErrno, LinuxPollEvents};

use crate::dispatch::WaitFds;
use crate::dispatch::abi_args::Fd;
use crate::dispatch::dispatcher::NetView;
use crate::dispatch::wait_source::{HostProxyCoverage, WaitRegistration, WaitSource, WatchedSlot};
use carrick_vfs::errno::HostSyscallResult;

/// One guest fd a wait names, with the events the guest asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::dispatch) struct WaitRequestFd {
    pub fd: Fd,
    pub requested: LinuxPollEvents,
}

/// What a wait names when one of its guest fds has no open description.
///
/// The answer is a property of the CALLING ABI, not of the fd, so it is an
/// input to the ONE assembly rather than a second code path: `poll(2)` and
/// `ppoll(2)` report an invalid fd `>= 0` per entry as `POLLNVAL` and return
/// normally, while `select(2)`/`pselect6(2)` fail the whole call with `EBADF`.
/// A NEGATIVE pollfd is ignored under either policy — `wait_source_for`
/// answers `Ok(None)` for it before any policy applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::dispatch) enum InvalidFdPolicy {
    /// `poll`/`ppoll`: `POLLNVAL` in that entry's revents. The fd is never
    /// registered as a wait source, and the entry counts toward the ready
    /// total, so a set mixing ready fds with a closed one still returns a
    /// count rather than an error.
    ReportPollNval,
    /// `select`/`pselect6`: `EBADF` for the whole call.
    FailEbadf,
}

/// One wait-shaped syscall's whole question: which fds, what the ABI does with
/// an invalid one, whether the caller may park, and which slots are advisory.
pub(in crate::dispatch) struct WaitRequest<'a> {
    /// The guest fds and their requested events, in REQUEST order — the order
    /// [`WaitAssembly`]'s revents come back in.
    pub fds: &'a [WaitRequestFd],
    /// What this ABI does with an fd naming no open description.
    pub invalid_fd: InvalidFdPolicy,
    /// Whether the caller may block; `false` turns an otherwise-park into
    /// [`WaitAssembly::NotReady`].
    pub may_block: bool,
    /// Advisory fds: they force a re-dispatch when their slot is replaced and
    /// are never probed, which is what `epoll_pwait`'s interest targets are
    /// for.
    pub watched: &'a [Fd],
}

/// How a park must be re-evaluated when it wakes.
///
/// This is a lowering choice, not a second classification: the assembly has
/// already decided every fd's source, and this only says whether the reactor's
/// own pollfd array can see all of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::dispatch) enum ParkSampling {
    /// Every fd's readiness is a host descriptor the reactor already polls, so
    /// a wake can simply re-dispatch the syscall.
    HostDescriptors,
    /// At least one fd's readiness lives in a carrick-owned description the
    /// reactor's pollfd array cannot see, so the park must retain the exact
    /// descriptions and re-evaluate them itself.
    RetainedDescriptions,
}

/// What one wait-shaped syscall's fds say right now.
#[derive(Debug)]
pub(in crate::dispatch) enum WaitAssembly {
    /// Per-fd guest-visible revents in request order; at least one non-empty.
    Ready {
        revents: Vec<LinuxPollEvents>,
    },
    /// Nothing ready and the caller may block.
    Park {
        revents: Vec<LinuxPollEvents>,
        wait: WaitFds,
        sampling: ParkSampling,
    },
    /// Nothing ready and the caller may not block.
    NotReady {
        revents: Vec<LinuxPollEvents>,
    },
    Errno(LinuxErrno),
}

/// What one requested fd turned out to be.
#[derive(Clone, Copy, Debug)]
enum RequestedSource {
    /// The fd names a live description. `None` inside means it takes no part
    /// in the wait: a negative pollfd, or a description asked for no events.
    Live(Option<WaitRegistration>),
    /// The fd names no open description and the calling ABI reports that in
    /// the entry ([`InvalidFdPolicy::ReportPollNval`]) instead of failing.
    Invalid,
}

impl<'a> NetView<'a> {
    /// Classify, probe and (if nothing is ready) park every fd of one wait.
    pub(in crate::dispatch) fn assemble_wait(
        &self,
        files: &crate::kernel::FileTable,
        request: &WaitRequest<'_>,
    ) -> WaitAssembly {
        let WaitRequest {
            fds: requested_fds,
            invalid_fd,
            may_block,
            watched,
        } = *request;
        let mut registrations: Vec<RequestedSource> = Vec::with_capacity(requested_fds.len());
        for entry in requested_fds {
            match self.wait_source_for(files, entry.fd, entry.requested) {
                Ok(registration) => registrations.push(RequestedSource::Live(registration)),
                // An fd with no open description. `poll` owes the guest a
                // per-entry POLLNVAL; `select` owes it EBADF for the call.
                Err(errno)
                    if errno == LINUX_EBADF && invalid_fd == InvalidFdPolicy::ReportPollNval =>
                {
                    registrations.push(RequestedSource::Invalid);
                }
                Err(errno) => return WaitAssembly::Errno(errno),
            }
        }

        // ONE non-blocking host poll for the whole wait. The array is
        // COMPACTED — a description-backed fd contributes no entry — so each
        // request position remembers where its host half landed.
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(requested_fds.len());
        let mut host_slot: Vec<Option<usize>> = Vec::with_capacity(requested_fds.len());
        for registration in &registrations {
            let host = match registration {
                RequestedSource::Live(registration) => {
                    registration.and_then(|registration| registration.source().host())
                }
                // An invalid fd is never registered as a wait source: there is
                // no description to probe and no host half to poll.
                RequestedSource::Invalid => None,
            };
            match host {
                Some(host) => {
                    host_slot.push(Some(pollfds.len()));
                    pollfds.push(libc::pollfd {
                        fd: host.fd().get(),
                        events: host.events().bits(),
                        revents: 0,
                    });
                }
                None => host_slot.push(None),
            }
        }
        if !pollfds.is_empty() {
            let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0) };
            if let Err(errno) = rc.host_syscall_errno() {
                return WaitAssembly::Errno(errno);
            }
        }

        let host_revents = |index: usize| {
            host_slot[index].map_or(LinuxPollEvents::empty(), |slot| {
                LinuxPollEvents::from_bits_retain(pollfds[slot].revents)
            })
        };
        let sample = |entry: &WaitRequestFd| {
            LinuxPollEvents::from_bits_retain(
                self.poll_ready_events(entry.fd.0, entry.requested.bits()),
            )
        };
        let live_source = |index: usize| match registrations[index] {
            RequestedSource::Live(registration) => registration.map(|r| r.source()),
            RequestedSource::Invalid => None,
        };
        let revents: Vec<LinuxPollEvents> = requested_fds
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                // An fd naming no open description: the ABI already said this
                // is reported per entry, and POLLNVAL COUNTS as ready, so the
                // call returns a count rather than an error.
                if matches!(registrations[index], RequestedSource::Invalid) {
                    return LinuxPollEvents::NVAL;
                }
                match live_source(index) {
                    // A host descriptor's revents ARE the guest's answer.
                    Some(WaitSource::Host { .. }) => host_revents(index),
                    // No host object, or a host descriptor that only observes host
                    // peers: the description decides.
                    Some(WaitSource::Description { .. })
                    | Some(WaitSource::Dual {
                        coverage: HostProxyCoverage::HostPeersOnly,
                        ..
                    }) => sample(entry),
                    // A readiness pipe only says "something changed"; translate
                    // that edge back through the description it mirrors.
                    Some(WaitSource::Dual {
                        coverage: HostProxyCoverage::LatchedLevelTriggered,
                        ..
                    }) => {
                        if host_revents(index).intersects(
                            LinuxPollEvents::IN | LinuxPollEvents::HUP | LinuxPollEvents::ERR,
                        ) {
                            sample(entry)
                        } else {
                            LinuxPollEvents::empty()
                        }
                    }
                    // No source: a negative pollfd, which poll(2) ignores, or a
                    // description the guest asked no events of.
                    None if entry.fd.0 < 0 => LinuxPollEvents::empty(),
                    None => sample(entry),
                }
            })
            .collect();

        if revents.iter().any(|revents| !revents.is_empty()) {
            return WaitAssembly::Ready { revents };
        }
        if !may_block {
            return WaitAssembly::NotReady { revents };
        }

        // Only a source the reactor's own pollfd array can see may be
        // re-evaluated by re-dispatching; a negative fd has nothing to see.
        // An invalid fd never reaches here — its POLLNVAL is ready above.
        let sampling =
            if requested_fds
                .iter()
                .zip(registrations.iter())
                .all(|(entry, registration)| match registration {
                    RequestedSource::Live(Some(registration)) => {
                        registration.source().host().is_some()
                    }
                    RequestedSource::Live(None) => entry.fd.0 < 0,
                    RequestedSource::Invalid => false,
                })
            {
                ParkSampling::HostDescriptors
            } else {
                ParkSampling::RetainedDescriptions
            };
        let watched: Vec<WatchedSlot> = watched
            .iter()
            .filter_map(|fd| crate::kernel::FileSlotNumber::for_open_fd(fd.0).ok())
            .filter_map(|number| files.capture_slot_or_stdio_authority(number))
            .map(WatchedSlot::new)
            .collect();
        let registrations: Vec<WaitRegistration> = registrations
            .iter()
            .filter_map(|registration| match registration {
                RequestedSource::Live(registration) => *registration,
                RequestedSource::Invalid => None,
            })
            .collect();
        // A wait that named no source at all is a pure timeout wait.
        let wait = if registrations.is_empty() && watched.is_empty() {
            WaitFds::empty()
        } else {
            match WaitFds::from_registrations(registrations, watched) {
                Ok(wait) => wait,
                Err(errno) => return WaitAssembly::Errno(errno),
            }
        };
        WaitAssembly::Park {
            revents,
            wait,
            sampling,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use crate::dispatch::fd_table::{
        HostFdRef, HostWriteKind, OpenDescription, OpenDescriptionBase, OpenFile, WaitQueueKind,
    };
    use crate::dispatch::wait_queue_fixture::{self, WaitQueueFixture};

    fn install(dispatcher: &SyscallDispatcher, open: OpenDescription, status_flags: u64) -> i32 {
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(open)),
            status_flags,
            0,
        );
        dispatcher
            .install_fd_at_or_above(3, open_file)
            .expect("install fd")
    }

    /// A real host pipe installed at a guest fd, plus its write end.
    fn host_pipe(dispatcher: &SyscallDispatcher) -> (i32, i32) {
        let mut host = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(host.as_mut_ptr()) }, 0, "host pipe");
        let pipe_id = crate::dispatch::fs::pipe::next_pipe_id();
        let fd = install(
            dispatcher,
            OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host[0]),
                is_read_end: true,
                pipe_id,
                base: OpenDescriptionBase::new(0),
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            },
            carrick_abi::LINUX_O_RDONLY,
        );
        (fd, host[1])
    }

    fn fixture_fd(dispatcher: &SyscallDispatcher, kind: WaitQueueKind) -> (WaitQueueFixture, i32) {
        let fixture = wait_queue_fixture::fixture(kind);
        let open_file = OpenFile::new(Arc::clone(fixture.description()), 0);
        let fd = dispatcher
            .install_fd_at_or_above(3, open_file)
            .expect("install fixture fd");
        (fixture, fd)
    }

    fn pollin(fds: &[i32]) -> Vec<WaitRequestFd> {
        fds.iter()
            .map(|fd| WaitRequestFd {
                fd: Fd(*fd),
                requested: LinuxPollEvents::IN,
            })
            .collect()
    }

    fn assemble_with_policy(
        dispatcher: &SyscallDispatcher,
        request: &[WaitRequestFd],
        may_block: bool,
        invalid_fd: InvalidFdPolicy,
    ) -> WaitAssembly {
        let view = dispatcher.net_view();
        let files = view.captured_file_table();
        view.assemble_wait(
            &files,
            &WaitRequest {
                fds: request,
                invalid_fd,
                may_block,
                watched: &[],
            },
        )
    }

    /// The `poll`/`ppoll` ABI.
    fn assemble(
        dispatcher: &SyscallDispatcher,
        request: &[WaitRequestFd],
        may_block: bool,
    ) -> WaitAssembly {
        assemble_with_policy(
            dispatcher,
            request,
            may_block,
            InvalidFdPolicy::ReportPollNval,
        )
    }

    fn revents_of(assembly: &WaitAssembly) -> &[LinuxPollEvents] {
        match assembly {
            WaitAssembly::Ready { revents }
            | WaitAssembly::Park { revents, .. }
            | WaitAssembly::NotReady { revents } => revents,
            WaitAssembly::Errno(errno) => panic!("expected an assembly, got {errno:?}"),
        }
    }

    /// Every host-backed fd goes into ONE reactor list and ONE host poll; the
    /// park needs nothing retained because the reactor can see all of them.
    #[test]
    fn assemble_batches_all_host_sources_into_one_poll() {
        let dispatcher = SyscallDispatcher::new();
        let (first, first_writer) = host_pipe(&dispatcher);
        let (second, _second_writer) = host_pipe(&dispatcher);
        let request = pollin(&[first, second]);

        match assemble(&dispatcher, &request, true) {
            WaitAssembly::Park {
                revents,
                wait,
                sampling,
            } => {
                assert_eq!(revents, vec![LinuxPollEvents::empty(); 2]);
                assert_eq!(wait.len(), 2, "one reactor entry per host descriptor");
                assert_eq!(sampling, ParkSampling::HostDescriptors);
            }
            other => panic!("expected a park over two idle host pipes, got {other:?}"),
        }

        assert_eq!(
            unsafe { libc::write(first_writer, c"x".as_ptr().cast(), 1) },
            1
        );
        let assembly = assemble(&dispatcher, &request, true);
        assert!(matches!(assembly, WaitAssembly::Ready { .. }));
        assert_eq!(
            revents_of(&assembly),
            [LinuxPollEvents::IN, LinuxPollEvents::empty()]
        );
    }

    /// An in-zone listener's Darwin listen socket never sees a connection
    /// paired IN ZONE, so its description is sampled on every assembly even
    /// though the host descriptor reports nothing.
    #[test]
    fn assemble_samples_description_for_dual_host_peers_only_even_when_host_is_idle() {
        let dispatcher = SyscallDispatcher::new();
        let (mut fixture, fd) = fixture_fd(&dispatcher, WaitQueueKind::InZoneListenerHostSocket);
        let request = pollin(&[fd]);
        assert!(
            matches!(
                assemble(&dispatcher, &request, true),
                WaitAssembly::Park { .. }
            ),
            "an idle in-zone listener parks"
        );

        fixture.fire_producer();
        let assembly = assemble(&dispatcher, &request, true);
        assert!(
            matches!(assembly, WaitAssembly::Ready { .. }),
            "an in-zone connect must be seen through the description, not the \
             Darwin listen socket"
        );
        assert_eq!(revents_of(&assembly), [LinuxPollEvents::IN]);
    }

    /// A readiness pipe is a LEVEL-TRIGGERED mirror: the description is
    /// sampled only when the host edge fired, so the latch — not a second
    /// unconditional description sweep — is what reports the change.
    #[test]
    fn assemble_samples_description_for_latched_dual_only_when_the_host_edge_fired() {
        let dispatcher = SyscallDispatcher::new();
        let pipe: crate::dispatch::fd_table::PipeRef =
            Arc::new(crate::dispatch::fs::pipe::PipeInner::new(
                crate::dispatch::fs::pipe::next_pipe_id(),
                crate::dispatch::fs::pipe::DEFAULT_PIPE_CAPACITY,
            ));
        {
            let mut state = pipe.state.lock();
            state.readers = 1;
            state.writers = 1;
        }
        let fd = install(
            &dispatcher,
            OpenDescription::PipeReader {
                base: OpenDescriptionBase::new(0),
                pipe: Arc::clone(&pipe),
            },
            carrick_abi::LINUX_O_RDONLY,
        );
        let request = pollin(&[fd]);
        assert!(
            matches!(
                assemble(&dispatcher, &request, true),
                WaitAssembly::Park { .. }
            ),
            "an empty pipe parks"
        );

        // Bytes arrive BEHIND the readiness pipe's back: the host edge has not
        // fired, so the latched source reports nothing.
        pipe.state.lock().buffer.extend(b"gap".iter().copied());
        assert_eq!(
            revents_of(&assemble(&dispatcher, &request, true)),
            [LinuxPollEvents::empty()],
            "a latched dual is gated on its host edge"
        );

        // The pipe publishes the level, which is what a real write does.
        {
            let state = pipe.state.lock();
            pipe.update_readiness_locked(&state);
        }
        let assembly = assemble(&dispatcher, &request, true);
        assert!(matches!(assembly, WaitAssembly::Ready { .. }));
        assert_eq!(revents_of(&assembly), [LinuxPollEvents::IN]);
    }

    /// A caller that may not block gets the revents and no park.
    #[test]
    fn assemble_returns_not_ready_when_may_block_is_false() {
        let dispatcher = SyscallDispatcher::new();
        let (fd, _writer) = host_pipe(&dispatcher);
        match assemble(&dispatcher, &pollin(&[fd]), false) {
            WaitAssembly::NotReady { revents } => {
                assert_eq!(revents, [LinuxPollEvents::empty()]);
            }
            other => panic!("expected NotReady for a non-blocking caller, got {other:?}"),
        }
    }

    /// The host poll array is compacted — description-backed fds contribute no
    /// entry — so revents must be indexed by REQUEST position, not by the
    /// position an fd happens to take in the host array.
    #[test]
    fn assemble_orders_revents_by_request_index() {
        let dispatcher = SyscallDispatcher::new();
        let (mut ready_socket, socket_fd) = fixture_fd(&dispatcher, WaitQueueKind::InMemorySocket);
        let (_idle_socket, idle_socket_fd) = fixture_fd(&dispatcher, WaitQueueKind::InMemorySocket);
        let (pipe_fd, pipe_writer) = host_pipe(&dispatcher);
        ready_socket.fire_producer();
        assert_eq!(
            unsafe { libc::write(pipe_writer, c"x".as_ptr().cast(), 1) },
            1
        );

        let request = pollin(&[idle_socket_fd, socket_fd, pipe_fd]);
        let assembly = assemble(&dispatcher, &request, true);
        assert!(matches!(assembly, WaitAssembly::Ready { .. }));
        assert_eq!(
            revents_of(&assembly),
            [
                LinuxPollEvents::empty(),
                LinuxPollEvents::IN,
                LinuxPollEvents::IN
            ],
            "the host pipe is the only host entry, yet it must report at index 2"
        );
    }

    /// `poll(2)`: a pollfd naming a CLOSED fd is not an error. The entry
    /// reports `POLLNVAL`, the entry COUNTS toward the ready total, and the
    /// call returns normally — the `pollevent` probe's `poll_invalid_nval` and
    /// `poll_multi_ready_count=3` / `poll_multi_bad_nval` lines.
    #[test]
    fn poll_reports_pollnval_for_a_closed_fd_and_counts_it_ready() {
        let dispatcher = SyscallDispatcher::new();
        let (ready_fd, ready_writer) = host_pipe(&dispatcher);
        let (closed_fd, _closed_writer) = host_pipe(&dispatcher);
        assert_eq!(
            unsafe { libc::write(ready_writer, c"x".as_ptr().cast(), 1) },
            1
        );
        dispatcher.close_fd_for_internal_rollback(closed_fd);

        let request = pollin(&[ready_fd, closed_fd]);
        let assembly = assemble(&dispatcher, &request, true);
        assert!(
            matches!(assembly, WaitAssembly::Ready { .. }),
            "a closed fd is reported per entry, never as a failed poll, got \
             {assembly:?}"
        );
        assert_eq!(
            revents_of(&assembly),
            [LinuxPollEvents::IN, LinuxPollEvents::NVAL]
        );
        assert_eq!(
            revents_of(&assembly)
                .iter()
                .filter(|revents| !revents.is_empty())
                .count(),
            2,
            "POLLNVAL counts toward poll's ready total"
        );
    }

    /// `select(2)`: the SAME closed fd fails the whole call with `EBADF`. The
    /// invalid-fd answer is a property of the calling ABI, so one assembly
    /// gives two answers from one classification.
    #[test]
    fn select_fails_with_ebadf_for_a_closed_fd() {
        let dispatcher = SyscallDispatcher::new();
        let (ready_fd, ready_writer) = host_pipe(&dispatcher);
        let (closed_fd, _closed_writer) = host_pipe(&dispatcher);
        assert_eq!(
            unsafe { libc::write(ready_writer, c"x".as_ptr().cast(), 1) },
            1
        );
        dispatcher.close_fd_for_internal_rollback(closed_fd);

        let request = pollin(&[ready_fd, closed_fd]);
        match assemble_with_policy(&dispatcher, &request, true, InvalidFdPolicy::FailEbadf) {
            WaitAssembly::Errno(errno) => assert_eq!(errno, LINUX_EBADF),
            other => panic!("select must reject a closed fd with EBADF, got {other:?}"),
        }
    }

    /// A mixed set cannot be re-evaluated from the reactor's pollfd array
    /// alone, so its park retains the exact descriptions.
    #[test]
    fn assemble_parks_a_mixed_set_with_retained_descriptions() {
        let dispatcher = SyscallDispatcher::new();
        let (_socket, socket_fd) = fixture_fd(&dispatcher, WaitQueueKind::InMemorySocket);
        let (pipe_fd, _writer) = host_pipe(&dispatcher);
        match assemble(&dispatcher, &pollin(&[socket_fd, pipe_fd]), true) {
            WaitAssembly::Park { wait, sampling, .. } => {
                assert_eq!(sampling, ParkSampling::RetainedDescriptions);
                assert_eq!(
                    wait.len(),
                    1,
                    "the in-memory socket contributes no reactor entry"
                );
                assert_eq!(
                    wait.authority().strict_slots().len(),
                    2,
                    "both fds are still strictly authorised"
                );
            }
            other => panic!("expected a retained-description park, got {other:?}"),
        }
    }
}
