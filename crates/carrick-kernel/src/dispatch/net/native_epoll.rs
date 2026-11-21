//! Host readiness producer for a native ring epoll. The shared IPC record
//! owns delivery, one-shot state and the wait. The carrier multiplexes only
//! real host sockets, always in edge mode so a level-ready socket cannot
//! spin the reactor. The ring reapplies its own level/edge policy.
//!
//! A task's HOST SET (the epoll a select set nests for its host members,
//! #2621) is enrolled through the same registrations: a socket as for
//! `epoll_ctl`, every class edge-triggered, and a regular file as an item
//! whose level is always readable and writable (select(2) on a file with
//! no poll method), retired at that file's last close. Any other host kind
//! is refused, so the ring leaves the whole call unrouted.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::{Arc, Weak};
use std::time::Duration;

use carrick_abi::{
    LINUX_EBADF, LINUX_EEXIST, LINUX_EINVAL, LINUX_EIO, LINUX_ENOENT, LINUX_ENOSPC, LINUX_EPERM,
    LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LinuxEpollEvents, LinuxErrno,
};
use carrick_el1_abi::ipc::epoll::{EpollCtlError, EpollItemRef, EpollReport};
use carrick_el1_abi::ipc::{IpcBacking, IpcError, IpcObjectHandle, fd};
use carrick_hal::event::{EventMultiplexer, TriggerMode};
use parking_lot::Mutex;

use crate::el1_ipc::{HostIpc, PinnedHostResourceError};
use crate::el1_zone::HostLockWait;
use crate::host_readiness::{
    HostEventSource, HostReadinessReactor, HostReadinessSource, HostReadinessToken,
};
use crate::kernel::{FileDescription, NO_READINESS_CONTEXT, WaitCallbackEnrollment};

use super::native::NativeNetFile;

pub(crate) struct NativeSocketEpolls {
    owner: Weak<HostIpc>,
    reactor: Arc<HostReadinessReactor>,
    source: HostReadinessToken,
    poll_fd: RawFd,
    state: Mutex<State>,
    pending: Mutex<HashSet<u64>>,
}

impl std::fmt::Debug for NativeSocketEpolls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSocketEpolls").finish_non_exhaustive()
    }
}

/// What one registration observes: a socket's readiness source, or a host
/// regular file (by its resource token) that a host set reads as always
/// ready.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum MemberSource {
    Socket(HostReadinessSource),
    File(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Membership {
    epoll: IpcObjectHandle,
    source: MemberSource,
    number: fd::Fd,
}

impl std::hash::Hash for Membership {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.epoll.hash(state);
        self.source.hash(state);
        self.number.0.hash(state);
    }
}

/// A host set member the carrier can enrol (see the module docs).
pub(in crate::dispatch) enum HostSetMember<'a> {
    Socket(&'a NativeNetFile),
    /// A regular file: its resource token and description.
    File(u64, Arc<FileDescription>),
}

/// The level a host set reports for a regular file: select(2) finds a file
/// without a poll method always readable and writable.
const FILE_LEVEL: u32 = carrick_el1_abi::ipc::epoll::events::IN
    | carrick_el1_abi::ipc::epoll::events::RDNORM
    | carrick_el1_abi::ipc::epoll::events::OUT
    | carrick_el1_abi::ipc::epoll::events::WRNORM;

/// What a host set item requests: every class, edge-triggered. The select
/// set reads the sampled level; only a host edge queues the item and wakes
/// the set it is nested in.
const HOST_SET_EVENTS: u32 =
    carrick_el1_abi::ipc::epoll::events::LEVEL_MASK | carrick_el1_abi::ipc::epoll::events::ET;

struct Registration {
    key: Membership,
    item: EpollItemRef,
    description: Arc<FileDescription>,
    watch: Watch,
    events: LinuxEpollEvents,
}

struct Watch {
    host: Option<OwnedFd>,
    _zone: Option<WaitCallbackEnrollment>,
}

struct State {
    mux: Box<dyn EventMultiplexer>,
    registrations: HashMap<u64, Registration>,
    keys: HashMap<Membership, u64>,
    sources: HashMap<MemberSource, HashSet<u64>>,
    epolls: HashMap<IpcObjectHandle, HashSet<u64>>,
    next: u64,
}

impl State {
    fn generation(&mut self) -> Result<u64, LinuxErrno> {
        // The platform multiplexer reserves the high bit for user events.
        if self.next == 1 << 63 {
            return Err(LINUX_ENOSPC);
        }
        let token = self.next;
        self.next += 1;
        Ok(token)
    }

    fn bind(&mut self, fd: RawFd, token: u64, events: LinuxEpollEvents) -> Result<(), LinuxErrno> {
        let interest = super::support::epoll_interest_for(events);
        self.mux
            .register_io(fd, token, interest, TriggerMode::Edge)
            .map_err(|error| crate::host_to_linux_errno(error.errno))
    }

    fn insert(&mut self, token: u64, registration: Registration) {
        let key = registration.key;
        self.keys.insert(key, token);
        self.sources.entry(key.source).or_default().insert(token);
        self.epolls.entry(key.epoll).or_default().insert(token);
        self.registrations.insert(token, registration);
    }

    fn take(&mut self, token: u64) -> Option<Registration> {
        let registration = self.registrations.remove(&token)?;
        let key = registration.key;
        self.keys.remove(&key);
        remove_index(&mut self.sources, key.source, token);
        remove_index(&mut self.epolls, key.epoll, token);
        Some(registration)
    }

    fn retire(&mut self, token: u64) -> Option<Registration> {
        let registration = self.take(token)?;
        if let Some(fd) = &registration.watch.host {
            let _ = self.mux.deregister(fd.as_raw_fd());
        }
        Some(registration)
    }

    fn sample(
        &self,
        owner: &HostIpc,
        registration: &Registration,
        edge: bool,
    ) -> Option<carrick_el1_abi::ipc::IpcWake> {
        let level = registration
            .description
            .readiness(registration.events, NO_READINESS_CONTEXT);
        match owner.socket_epoll_region().and_then(|region| {
            region.epoll_publish_host_socket(
                registration.key.epoll,
                registration.item,
                level.bits(),
                edge,
                &HostLockWait,
            )
        }) {
            Ok(wake) => wake,
            Err(IpcError::Stale) => None,
            Err(error) => {
                let _ = ctl_errno(error.into());
                None
            }
        }
    }

    fn drain(
        &mut self,
        owner: &HostIpc,
        initial: Option<u64>,
        pending: HashSet<u64>,
    ) -> Vec<carrick_el1_abi::ipc::IpcWake> {
        let mut events = Vec::new();
        match self.mux.wait(&mut events, Some(Duration::ZERO)) {
            Ok(_) => {}
            Err(error) if error.errno == libc::EINTR => {}
            Err(_) => {
                let _ = ctl_errno(IpcError::Corrupt.into());
            }
        }
        // Kqueue can return both directional filters for one registration.
        // Probe it once, in order of first appearance in the host batch.
        let mut seen = HashSet::new();
        let mut wakes: Vec<_> = events
            .into_iter()
            .map(|event| event.token)
            .chain(pending)
            .filter(|token| seen.insert(*token))
            .filter_map(|token| self.registrations.get(&token))
            .filter_map(|registration| self.sample(owner, registration, true))
            .collect();
        if let Some(token) = initial
            && !seen.contains(&token)
            && let Some(registration) = self.registrations.get(&token)
            && let Some(wake) = self.sample(owner, registration, registration.watch.host.is_none())
        {
            wakes.push(wake);
        }
        wakes
    }
}

fn remove_index<K: Copy + Eq + std::hash::Hash>(
    index: &mut HashMap<K, HashSet<u64>>,
    key: K,
    token: u64,
) {
    if let std::collections::hash_map::Entry::Occupied(mut entry) = index.entry(key) {
        entry.get_mut().remove(&token);
        if entry.get().is_empty() {
            entry.remove();
        }
    }
}

impl NativeSocketEpolls {
    pub(crate) fn new(
        owner: &Arc<HostIpc>,
        reactor: &Arc<HostReadinessReactor>,
    ) -> Result<Arc<Self>, LinuxErrno> {
        let mux = crate::event_mux::make_event_multiplexer()
            .map_err(|error| crate::host_to_linux_errno(error.errno))?;
        let producer = Arc::new(Self {
            owner: Arc::downgrade(owner),
            reactor: reactor.clone(),
            source: HostReadinessToken::new(),
            poll_fd: mux.poll_fd(),
            pending: Mutex::new(HashSet::new()),
            state: Mutex::new(State {
                mux,
                registrations: HashMap::new(),
                keys: HashMap::new(),
                sources: HashMap::new(),
                epolls: HashMap::new(),
                next: 1,
            }),
        });
        if !producer
            .reactor
            .watch_events(producer.source.source(), producer.clone())
        {
            return Err(LINUX_EIO);
        }
        Ok(producer)
    }

    fn watch(
        self: &Arc<Self>,
        state: &mut State,
        token: u64,
        description: &Arc<FileDescription>,
        events: LinuxEpollEvents,
    ) -> Result<Watch, LinuxErrno> {
        let host = duplicate_host_socket(description)?;
        let zone = description.wait_queue().map(|queue| {
            let producer = Arc::downgrade(self);
            queue.enroll_callback(move |_| {
                if let Some(producer) = producer.upgrade() {
                    producer.pending.lock().insert(token);
                    producer.reactor.schedule_event(producer.source.source());
                }
            })
        });
        if let Some(fd) = &host {
            state.bind(fd.as_raw_fd(), token, events)?;
        } else if zone.is_none() {
            return Err(LINUX_EPERM);
        }
        Ok(Watch { host, _zone: zone })
    }

    fn unwatch(state: &mut State, watch: &Watch) {
        if let Some(fd) = &watch.host {
            let _ = state.mux.deregister(fd.as_raw_fd());
        }
    }

    fn drain_zone(&self, state: &State, owner: &HostIpc) -> Vec<carrick_el1_abi::ipc::IpcWake> {
        std::mem::take(&mut *self.pending.lock())
            .into_iter()
            .filter_map(|token| state.registrations.get(&token))
            .filter_map(|registration| state.sample(owner, registration, true))
            .collect()
    }

    fn control(
        self: &Arc<Self>,
        owner: &HostIpc,
        key: Membership,
        socket: &NativeNetFile,
        file: fd::OfdKey,
        op: u64,
        report: EpollReport,
    ) -> Result<(), LinuxErrno> {
        let region = owner
            .socket_epoll_region()
            .map_err(|error| ctl_errno(error.into()))?;
        let mut state = self.state.lock();
        let existing = state.keys.get(&key).copied();
        let events = LinuxEpollEvents::from_bits_retain(report.events);
        match op {
            LINUX_EPOLL_CTL_ADD => events.validate_add(false)?,
            LINUX_EPOLL_CTL_MOD => {
                events.validate_modify(existing.map_or_else(LinuxEpollEvents::empty, |token| {
                    state.registrations[&token].events
                }))?
            }
            _ => {}
        }
        let new = match (op, existing) {
            (LINUX_EPOLL_CTL_ADD, Some(_)) => return Err(LINUX_EEXIST),
            (LINUX_EPOLL_CTL_ADD, None) => {
                owner
                    .bind_socket_epoll_lock(key.epoll)
                    .map_err(|error| ctl_errno(error.into()))?;
                let token = state.generation()?;
                let description = socket.description();
                let watch = self.watch(&mut state, token, &description, events)?;
                let file_key =
                    (u64::from(file.index) << 32) | (file.generation & u64::from(u32::MAX));
                let item = match region.epoll_add_host_socket(
                    key.epoll,
                    key.number,
                    file_key,
                    report,
                    0,
                    &HostLockWait,
                ) {
                    Ok((item, _)) => item,
                    Err(error) => {
                        Self::unwatch(&mut state, &watch);
                        return Err(ctl_errno(error));
                    }
                };
                state.insert(
                    token,
                    Registration {
                        key,
                        item,
                        events,
                        description,
                        watch,
                    },
                );
                Some(token)
            }
            (LINUX_EPOLL_CTL_MOD, Some(old)) => {
                let token = state.generation()?;
                let description = socket.description();
                let watch = self.watch(&mut state, token, &description, events)?;
                let item = state.registrations[&old].item;
                let item = match region.epoll_modify_host_socket(
                    key.epoll,
                    item,
                    report,
                    0,
                    &HostLockWait,
                ) {
                    Ok((item, _)) => item,
                    Err(error) => {
                        Self::unwatch(&mut state, &watch);
                        return Err(ctl_errno(error));
                    }
                };
                state.retire(old);
                state.insert(
                    token,
                    Registration {
                        key,
                        item,
                        events,
                        description,
                        watch,
                    },
                );
                Some(token)
            }
            (LINUX_EPOLL_CTL_DEL, Some(token)) => {
                let registration = &state.registrations[&token];
                region
                    .epoll_delete_host_socket(key.epoll, registration.item, &HostLockWait)
                    .map_err(ctl_errno)?;
                state.retire(token);
                None
            }
            (LINUX_EPOLL_CTL_MOD | LINUX_EPOLL_CTL_DEL, None) => return Err(LINUX_ENOENT),
            _ => return Err(LINUX_EINVAL),
        };
        let wakes = new.map_or_else(Vec::new, |token| {
            state.drain(
                owner,
                Some(token),
                std::mem::take(&mut *self.pending.lock()),
            )
        });
        drop(state);
        owner.deliver_socket_epoll_wakes(wakes);
        Ok(())
    }

    /// Enrol one host member of a select set in the task's host set `set`
    /// (#2621). The ring asks only for a descriptor and open file the host
    /// set has no item for, so a registration of the same member number
    /// is an earlier open file's: it is replaced.
    pub(in crate::dispatch) fn enrol_host_set(
        self: &Arc<Self>,
        owner: &HostIpc,
        set: IpcObjectHandle,
        number: fd::Fd,
        file: fd::OfdKey,
        member: HostSetMember<'_>,
    ) -> Result<(), LinuxErrno> {
        let report = EpollReport {
            events: HOST_SET_EVENTS,
            data: number.0 as u32 as u64,
        };
        let socket = match member {
            HostSetMember::Socket(socket) => socket,
            HostSetMember::File(token, description) => {
                return self.enrol_host_set_file(
                    owner,
                    set,
                    number,
                    file,
                    token,
                    description,
                    report,
                );
            }
        };
        let key = Membership {
            epoll: set,
            source: MemberSource::Socket(socket.source()),
            number,
        };
        if self.state.lock().keys.contains_key(&key) {
            self.control(owner, key, socket, file, LINUX_EPOLL_CTL_DEL, report)?;
        }
        self.control(owner, key, socket, file, LINUX_EPOLL_CTL_ADD, report)
    }

    #[allow(clippy::too_many_arguments)]
    fn enrol_host_set_file(
        &self,
        owner: &HostIpc,
        set: IpcObjectHandle,
        number: fd::Fd,
        file: fd::OfdKey,
        token: u64,
        description: Arc<FileDescription>,
        report: EpollReport,
    ) -> Result<(), LinuxErrno> {
        let region = owner
            .socket_epoll_region()
            .map_err(|error| ctl_errno(error.into()))?;
        let key = Membership {
            epoll: set,
            source: MemberSource::File(token),
            number,
        };
        let mut state = self.state.lock();
        if let Some(stale) = state.keys.get(&key).copied()
            && let Some(registration) = state.retire(stale)
        {
            region
                .epoll_delete_host_socket(set, registration.item, &HostLockWait)
                .map_err(ctl_errno)?;
        }
        owner
            .bind_socket_epoll_lock(set)
            .map_err(|error| ctl_errno(error.into()))?;
        let token = state.generation()?;
        let file_key = (u64::from(file.index) << 32) | (file.generation & u64::from(u32::MAX));
        let (item, wake) = region
            .epoll_add_host_socket(set, number, file_key, report, FILE_LEVEL, &HostLockWait)
            .map_err(ctl_errno)?;
        state.insert(
            token,
            Registration {
                key,
                item,
                events: LinuxEpollEvents::from_bits_retain(report.events),
                description,
                watch: Watch {
                    host: None,
                    _zone: None,
                },
            },
        );
        drop(state);
        owner.deliver_socket_epoll_wakes(wake);
        Ok(())
    }

    pub(crate) fn forget_epoll(&self, epoll: IpcObjectHandle) {
        let mut state = self.state.lock();
        let Some(tokens) = state.epolls.remove(&epoll) else {
            return;
        };
        for token in tokens {
            state.retire(token);
        }
    }

    pub(crate) fn forget_socket(&self, owner: &HostIpc, socket: HostReadinessSource) {
        self.forget(owner, MemberSource::Socket(socket));
    }

    /// A host regular file's last close: retire its host set items.
    pub(crate) fn forget_file(
        &self,
        owner: &HostIpc,
        token: carrick_el1_abi::ipc::HostResourceToken,
    ) {
        self.forget(owner, MemberSource::File(token.get()));
    }

    fn forget(&self, owner: &HostIpc, source: MemberSource) {
        let mut state = self.state.lock();
        let Some(tokens) = state.sources.remove(&source) else {
            return;
        };
        let Ok(region) = owner.socket_epoll_region() else {
            let _ = ctl_errno(IpcError::Corrupt.into());
            return;
        };
        for token in tokens {
            if let Some(registration) = state.retire(token) {
                let _ = region.epoll_delete_host_socket(
                    registration.key.epoll,
                    registration.item,
                    &HostLockWait,
                );
            }
        }
    }

    pub(super) fn socket_changed(self: &Arc<Self>, owner: &HostIpc, socket: &NativeNetFile) {
        let mut state = self.state.lock();
        let Some(tokens) = state.sources.get(&MemberSource::Socket(socket.source())) else {
            return;
        };
        let description = socket.description();
        let tokens = tokens.iter().copied().collect::<Vec<_>>();
        let mut wakes = Vec::new();
        for token in tokens {
            let registration = &state.registrations[&token];
            let replaced = !Arc::ptr_eq(&registration.description, &description);
            let token = if replaced {
                let events = registration.events;
                let Ok(next) = state.generation() else {
                    continue;
                };
                let Ok(watch) = self.watch(&mut state, next, &description, events) else {
                    continue;
                };
                let Some(mut registration) = state.retire(token) else {
                    Self::unwatch(&mut state, &watch);
                    continue;
                };
                registration.description = description.clone();
                registration.watch = watch;
                state.insert(next, registration);
                next
            } else {
                token
            };
            let registration = &state.registrations[&token];
            if let Some(wake) = state.sample(
                owner,
                registration,
                replaced && registration.watch.host.is_none(),
            ) {
                wakes.push(wake);
            }
        }
        drop(state);
        owner.deliver_socket_epoll_wakes(wakes);
    }
}

impl HostEventSource for NativeSocketEpolls {
    fn poll_fd(&self) -> RawFd {
        self.poll_fd
    }

    fn host_event(&self, fd_ready: bool) {
        if let Some(owner) = self.owner.upgrade() {
            let wakes = {
                let mut state = self.state.lock();
                if fd_ready {
                    state.drain(&owner, None, std::mem::take(&mut *self.pending.lock()))
                } else {
                    self.drain_zone(&state, &owner)
                }
            };
            owner.deliver_socket_epoll_wakes(wakes);
        }
    }
}

impl Drop for NativeSocketEpolls {
    fn drop(&mut self) {
        self.reactor.forget_events(self.source.source());
    }
}

fn io_errno(error: std::io::Error) -> LinuxErrno {
    error
        .raw_os_error()
        .map_or(LINUX_EIO, crate::host_to_linux_errno)
}

fn duplicate_host_socket(
    description: &Arc<FileDescription>,
) -> Result<Option<OwnedFd>, LinuxErrno> {
    description
        .inspect_kind(|open| {
            let super::OpenDescription::HostSocket { host_fd, .. } = open else {
                return Ok(None);
            };
            // The open-description guard retains the fd until the clone completes.
            unsafe { BorrowedFd::borrow_raw(host_fd.raw()) }
                .try_clone_to_owned()
                .map(Some)
                .map_err(io_errno)
        })
        .ok_or(LINUX_EBADF)?
}

fn ctl_errno(error: EpollCtlError) -> LinuxErrno {
    use super::epoll_zone::{ZoneCtl, ZoneEpoll};
    if matches!(error, EpollCtlError::Ipc(IpcError::ZoneLimit)) {
        return LINUX_ENOSPC;
    }
    match ZoneEpoll::ctl(Err(error), |_| {}) {
        ZoneCtl::Exists => LINUX_EEXIST,
        ZoneCtl::NotFound => LINUX_ENOENT,
        ZoneCtl::Invalid => LINUX_EINVAL,
        ZoneCtl::HostHalf(_) => LINUX_ENOSPC,
        ZoneCtl::Done => LINUX_EIO,
    }
}

impl super::SyscallDispatcher {
    pub(in crate::dispatch) fn serve_native_epoll_ctl(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: carrick_core_abi::host_file::HostFileHeader,
    ) -> Result<(), LinuxErrno> {
        let [op, target, data, _] = header.args;
        let target = fd::Fd(target as i32);
        let epfd = fd::Fd(header.fd);
        let report = EpollReport {
            events: header.flags,
            data,
        };
        owner
            .with_pinned_ofd(table, epfd, |_, epoll| {
                let Some(IpcBacking::Epoll { object }) = IpcBacking::decode(epoll.backing) else {
                    return Err(LINUX_EINVAL);
                };
                owner
                    .with_pinned_ofd(table, target, |file, description| {
                        let Some(IpcBacking::Host(token)) = IpcBacking::decode(description.backing)
                        else {
                            return Err(LINUX_EPERM);
                        };
                        let resource = owner.host_resource(token).ok_or(LINUX_EBADF)?;
                        let socket = resource
                            .downcast_ref::<NativeNetFile>()
                            .ok_or(LINUX_EPERM)?;
                        let reactor =
                            Arc::clone(self.kernel_binding.read().kernel().host_readiness());
                        let epolls = owner.native_socket_epolls(&reactor)?;
                        let key = Membership {
                            epoll: object,
                            source: MemberSource::Socket(socket.source()),
                            number: target,
                        };
                        epolls.control(owner, key, socket, file, op, report)
                    })
                    .map_err(pin_errno)?
            })
            .map_err(pin_errno)?
    }
}

impl super::SyscallDispatcher {
    /// Enrol a select set's host member in the caller's host set, which the
    /// record names by handle ([`carrick_core_abi::host_file::EpollSocketSet::HostSet`]).
    /// `None`: a member kind no host set holds (the ring leaves the whole
    /// call unrouted).
    pub(in crate::dispatch) fn serve_native_host_set_enrol(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: carrick_core_abi::host_file::HostFileHeader,
        set: u64,
    ) -> Option<Result<(), LinuxErrno>> {
        let set = IpcObjectHandle::from_word(set);
        // Only a live epoll is a host set.
        if let Err(error) = owner
            .socket_epoll_region()
            .and_then(|region| region.epoll_zone_items(set, &HostLockWait))
        {
            return Some(Err(ctl_errno(error.into())));
        }
        let target = fd::Fd(header.args[1] as i32);
        let enrolled = owner.with_pinned_ofd(table, target, |file, description| {
            let Some(IpcBacking::Host(token)) = IpcBacking::decode(description.backing) else {
                return None;
            };
            let Some(resource) = owner.host_resource(token) else {
                return Some(Err(LINUX_EBADF));
            };
            let member = if let Some(socket) = resource.downcast_ref::<NativeNetFile>() {
                HostSetMember::Socket(socket)
            } else {
                HostSetMember::File(
                    token.get(),
                    super::super::native_files::regular_file(&resource)?,
                )
            };
            let reactor = Arc::clone(self.kernel_binding.read().kernel().host_readiness());
            Some(
                owner
                    .native_socket_epolls(&reactor)
                    .and_then(|epolls| epolls.enrol_host_set(owner, set, target, file, member)),
            )
        });
        match enrolled {
            Ok(enrolled) => enrolled,
            Err(error) => Some(Err(pin_errno(error))),
        }
    }
}

fn pin_errno(error: PinnedHostResourceError) -> LinuxErrno {
    match error {
        PinnedHostResourceError::BadFd => LINUX_EBADF,
        PinnedHostResourceError::InZone => LINUX_EINVAL,
        PinnedHostResourceError::Unavailable => LINUX_EIO,
    }
}
