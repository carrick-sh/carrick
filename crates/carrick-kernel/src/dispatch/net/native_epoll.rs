//! Host readiness producer for a native ring epoll. The shared IPC record
//! owns delivery, one-shot state and the wait. The carrier multiplexes only
//! real host sockets, always in edge mode so a level-ready socket cannot
//! spin the reactor. The ring reapplies its own level/edge policy.

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Membership {
    epoll: IpcObjectHandle,
    socket: HostReadinessSource,
    number: fd::Fd,
}

impl std::hash::Hash for Membership {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.epoll.hash(state);
        self.socket.hash(state);
        self.number.0.hash(state);
    }
}

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
    sockets: HashMap<HostReadinessSource, HashSet<u64>>,
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
        self.sockets.entry(key.socket).or_default().insert(token);
        self.epolls.entry(key.epoll).or_default().insert(token);
        self.registrations.insert(token, registration);
    }

    fn take(&mut self, token: u64) -> Option<Registration> {
        let registration = self.registrations.remove(&token)?;
        let key = registration.key;
        self.keys.remove(&key);
        remove_index(&mut self.sockets, key.socket, token);
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

    /// Probe every registration the host batch or the zone queue names,
    /// then each `initial` (freshly added) registration not already probed.
    /// A fresh ADD publishes its sampled level as an edge whatever backs the
    /// socket: Linux queues an already-ready descriptor at `EPOLL_CTL_ADD`
    /// exactly once (the item's `QUEUED` bit keeps it from queueing twice).
    fn drain(
        &mut self,
        owner: &HostIpc,
        initial: &[u64],
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
        for token in initial {
            if !seen.contains(token)
                && let Some(registration) = self.registrations.get(token)
                && let Some(wake) = self.sample(owner, registration, true)
            {
                wakes.push(wake);
            }
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
                sockets: HashMap::new(),
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
                let file_key =
                    (u64::from(file.index) << 32) | (file.generation & u64::from(u32::MAX));
                Some(self.add(owner, &mut state, &region, key, socket, file_key, report)?)
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
            state.drain(owner, &[token], std::mem::take(&mut *self.pending.lock()))
        });
        drop(state);
        owner.deliver_socket_epoll_wakes(wakes);
        Ok(())
    }

    /// `EPOLL_CTL_ADD` of one carrier socket: enrol its host descriptor and
    /// its wait queue, then link its item. The one body a guest epoll's
    /// [`HostFileOp::EpollSocketCtl`] and a readiness set's
    /// [`HostFileOp::ReadinessSetCtl`] share; the caller drains the new
    /// registration's initial level as an edge.
    ///
    /// [`HostFileOp::EpollSocketCtl`]: carrick_core_abi::host_file::HostFileOp::EpollSocketCtl
    /// [`HostFileOp::ReadinessSetCtl`]: carrick_core_abi::host_file::HostFileOp::ReadinessSetCtl
    #[allow(clippy::too_many_arguments)]
    fn add(
        self: &Arc<Self>,
        owner: &HostIpc,
        state: &mut State,
        region: &carrick_el1_abi::ipc::IpcRegion<'_>,
        key: Membership,
        socket: &NativeNetFile,
        file_key: u64,
        report: EpollReport,
    ) -> Result<u64, LinuxErrno> {
        if state.keys.contains_key(&key) {
            return Err(LINUX_EEXIST);
        }
        owner
            .bind_socket_epoll_lock(key.epoll)
            .map_err(|error| ctl_errno(error.into()))?;
        let events = LinuxEpollEvents::from_bits_retain(report.events);
        let token = state.generation()?;
        let description = socket.description();
        let watch = self.watch(state, token, &description, events)?;
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
                Self::unwatch(state, &watch);
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
        Ok(token)
    }

    /// Register every carrier socket of a ring readiness set on its
    /// transient epoll, all or nothing, then publish each one's initial
    /// level as an edge. A failure retires the registrations this call made
    /// and unlinks their items, so the set's epoll holds no partial host
    /// half.
    fn register_set(
        self: &Arc<Self>,
        owner: &HostIpc,
        epoll: IpcObjectHandle,
        sockets: &[(
            &NativeNetFile,
            carrick_core_abi::host_file::ReadinessSetEntry,
        )],
    ) -> Result<(), LinuxErrno> {
        let region = owner
            .socket_epoll_region()
            .map_err(|error| ctl_errno(error.into()))?;
        let mut state = self.state.lock();
        let mut added = Vec::new();
        added
            .try_reserve_exact(sockets.len())
            .map_err(|_| carrick_abi::LINUX_ENOMEM)?;
        for (socket, entry) in sockets {
            let key = Membership {
                epoll,
                socket: socket.source(),
                number: fd::Fd(entry.fd),
            };
            let report = EpollReport {
                events: entry.events,
                data: entry.data,
            };
            match self.add(
                owner,
                &mut state,
                &region,
                key,
                socket,
                entry.file_key,
                report,
            ) {
                Ok(token) => added.push(token),
                Err(errno) => {
                    for token in added {
                        if let Some(registration) = state.retire(token) {
                            let _ = region.epoll_delete_host_socket(
                                epoll,
                                registration.item,
                                &HostLockWait,
                            );
                        }
                    }
                    return Err(errno);
                }
            }
        }
        let wakes = state.drain(owner, &added, std::mem::take(&mut *self.pending.lock()));
        drop(state);
        owner.deliver_socket_epoll_wakes(wakes);
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
        let mut state = self.state.lock();
        let Some(tokens) = state.sockets.remove(&socket) else {
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
        let Some(tokens) = state.sockets.get(&socket.source()) else {
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
                    state.drain(&owner, &[], std::mem::take(&mut *self.pending.lock()))
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
                            socket: socket.source(),
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
    /// A ring readiness set's carrier sockets
    /// ([`carrick_core_abi::host_file::HostFileOp::ReadinessSetCtl`]). Each
    /// entry names its socket by the host resource token the ring pinned at
    /// enrolment, so a descriptor number is never resolved again here. A
    /// token retired since (its last descriptor closed) registers nothing:
    /// its item never reports. A host resource that is not a carrier socket
    /// (a host file or terminal) is not this set's to serve: ENOSYS, with
    /// nothing registered.
    pub(in crate::dispatch) fn serve_native_readiness_set_ctl(
        &self,
        owner: &Arc<HostIpc>,
        header: carrick_core_abi::host_file::HostFileHeader,
        input: &[u8],
    ) -> Result<(), LinuxErrno> {
        use carrick_core_abi::host_file::ReadinessSetEntry;
        use carrick_el1_abi::ipc::{HostResourceToken, RawIpcObject};
        let [raw_epoll, count, ..] = header.args;
        let epoll = IpcObjectHandle::from_raw(RawIpcObject {
            index: raw_epoll as u32,
            generation: (raw_epoll >> 32) as u32,
        });
        let entries = ReadinessSetEntry::decode_all(input, count).ok_or(LINUX_EINVAL)?;
        let mut resources = Vec::new();
        for entry in entries {
            let token = HostResourceToken::new(entry.token).ok_or(LINUX_EINVAL)?;
            let Some(resource) = owner.host_resource(token) else {
                continue;
            };
            if resource.downcast_ref::<NativeNetFile>().is_none() {
                return Err(carrick_abi::LINUX_ENOSYS);
            }
            resources.push((resource, entry));
        }
        let sockets = resources
            .iter()
            .filter_map(|(resource, entry)| {
                Some((resource.downcast_ref::<NativeNetFile>()?, *entry))
            })
            .collect::<Vec<_>>();
        if sockets.is_empty() {
            return Ok(());
        }
        let reactor = Arc::clone(self.kernel_binding.read().kernel().host_readiness());
        owner
            .native_socket_epolls(&reactor)?
            .register_set(owner, epoll, &sockets)
    }
}

fn pin_errno(error: PinnedHostResourceError) -> LinuxErrno {
    match error {
        PinnedHostResourceError::BadFd => LINUX_EBADF,
        PinnedHostResourceError::InZone => LINUX_EINVAL,
        PinnedHostResourceError::Unavailable => LINUX_EIO,
    }
}
