use crate::el1_zone::HostLockWait;
use carrick_abi::*;
use carrick_el1_abi::ipc::{IpcBacking, IpcObjectGuard, IpcObjectHandle, pipe as core_pipe};
use carrick_guest_mem::CurrentMmMemory;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use super::*;
use crate::dispatch::fd_table::{HostFdRef, make_readiness_pipe};
use crate::dispatch::{FdWaitCompletion, WaitFds};

pub(crate) const DEFAULT_PIPE_CAPACITY: usize = 65536; // 64 KiB = 16 Linux pages
pub(crate) const MAX_PIPE_CAPACITY: usize = 1048576; // 1 MiB (/proc/sys/fs/pipe-max-size)
pub(crate) const PIPE_BUF: usize = 4096;

static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_pipe_id() -> u64 {
    NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed)
}

/// A readiness snapshot, never mutable pipe storage.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PipeSnapshot {
    pub(crate) unread: usize,
    pub(crate) capacity: usize,
    pub(crate) readers: usize,
    pub(crate) writers: usize,
    pub(crate) writable: bool,
}

/// Host binding of one shared PipeRecord. Bytes, endpoint counts and capacity
/// live exclusively in the IPC region. Each anonymous endpoint has one shared
/// OFD. Host functional references retain its host pin; guest slots/operations
/// retain the same OFD, so host close cannot retire their endpoint.
pub struct PipeInner {
    owner: Arc<crate::el1_ipc::HostIpc>,
    object: IpcObjectHandle,
    pipe_id: u64,
    endpoints: [Mutex<HostEndpointOwnership>; 2],
    #[cfg(test)]
    fixture: [Option<core_pipe::End>; 2],
    resize: Mutex<()>,
    readiness: Arc<Mutex<(bool, bool)>>,
    read_pipe_ready: Arc<OnceLock<Option<(HostFdRef, HostFdRef)>>>,
    write_pipe_ready: Arc<OnceLock<Option<(HostFdRef, HostFdRef)>>>,
    _readiness_publisher: Arc<dyn Fn() + Send + Sync>,
    pub(crate) wait_queue: Arc<crate::kernel::WaitQueue>,
}

struct HostEndpointOwnership {
    description: Option<crate::el1_ipc::HostDescription>,
    refs: usize,
    initial: bool,
}

impl HostEndpointOwnership {
    fn new(description: crate::el1_ipc::HostDescription) -> Mutex<Self> {
        Mutex::new(Self {
            description: Some(description),
            refs: 1,
            initial: true,
        })
    }
}

impl std::fmt::Debug for PipeInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeInner")
            .field("object", &self.object)
            .field("pipe_id", &self.pipe_id)
            .finish_non_exhaustive()
    }
}

pub type PipeRef = Arc<PipeInner>;

/// Functional endpoint ownership for a captured splice/tee/vmsplice operand.
/// The shared object cannot retire while the operation uses its captured bytes.
pub(crate) struct PipeEndpointLease {
    pipe: PipeRef,
    _description: crate::kernel::objects::FileDescriptionFdLease,
}
impl PipeEndpointLease {
    pub(crate) fn new(
        pipe: PipeRef,
        description: crate::kernel::objects::FileDescriptionFdLease,
    ) -> Self {
        Self {
            pipe,
            _description: description,
        }
    }
}
impl std::ops::Deref for PipeEndpointLease {
    type Target = PipeRef;
    fn deref(&self) -> &Self::Target {
        &self.pipe
    }
}

/// Exact publication authority captured before a write parks. It avoids
/// resolving a numeric guest fd after close or reuse.
pub struct PipeWriteNotification {
    kind: PipeWriteNotificationKind,
}

impl PipeWriteNotification {
    pub(crate) fn new(
        epoll_wake: crate::dispatch::EpollWakeHandle,
        kernel: Arc<crate::kernel::Kernel>,
        source_fd: i32,
    ) -> Self {
        Self {
            kind: PipeWriteNotificationKind::Live {
                epoll_wake,
                kernel,
                source_fd,
            },
        }
    }

    fn publish(&self, pipe: &PipeInner, bytes: usize) {
        match &self.kind {
            PipeWriteNotificationKind::Live {
                epoll_wake,
                kernel,
                source_fd,
            } => {
                epoll_wake.notify();
                crate::dispatch::fs::locks::fasync_notify_pipe_write(
                    kernel,
                    pipe.pipe_id(),
                    *source_fd,
                    bytes,
                );
            }
            #[cfg(test)]
            PipeWriteNotificationKind::Test => {}
        }
    }

    #[cfg(test)]
    fn for_tests() -> Self {
        Self {
            kind: PipeWriteNotificationKind::Test,
        }
    }
}

enum PipeWriteNotificationKind {
    Live {
        epoll_wake: crate::dispatch::EpollWakeHandle,
        kernel: Arc<crate::kernel::Kernel>,
        source_fd: i32,
    },
    #[cfg(test)]
    Test,
}

/// Functional writer-end ownership retained while a blocked large write is
/// driven by the continuation reactor. Holding only [`PipeRef`] is not enough:
/// a concurrent final `close(2)` would otherwise drop the writer description's
/// fd reference and publish EOF before this syscall finished its bytes.
pub struct PipeWriteEndpointLease {
    _description_lease: crate::kernel::objects::FileDescriptionFdLease,
    pipe: PipeRef,
    readiness_fd: HostFdRef,
    notification: PipeWriteNotification,
}

impl PipeWriteEndpointLease {
    pub(crate) fn retain(
        description_lease: crate::kernel::objects::FileDescriptionFdLease,
        pipe: PipeRef,
        readiness_fd: HostFdRef,
        notification: PipeWriteNotification,
    ) -> Arc<Self> {
        Arc::new(Self {
            _description_lease: description_lease,
            pipe,
            readiness_fd,
            notification,
        })
    }

    pub(crate) fn pipe(&self) -> &PipeRef {
        &self.pipe
    }

    pub(crate) fn readiness_fd(&self) -> &HostFdRef {
        &self.readiness_fd
    }

    pub(crate) fn publish_progress(&self, bytes: usize) {
        self.notification.publish(&self.pipe, bytes);
    }
}

pub(crate) fn pipe_writer_is_writable(state: &PipeSnapshot) -> bool {
    state.writable
}

fn object_error(error: core_pipe::Error) -> LinuxErrno {
    match error {
        core_pipe::Error::WouldBlock(_) => LINUX_EAGAIN,
        core_pipe::Error::BrokenPipe => LINUX_EPIPE,
        core_pipe::Error::Fault => LINUX_EFAULT,
        core_pipe::Error::Busy => LINUX_EBUSY,
        core_pipe::Error::Permission => LINUX_EPERM,
        core_pipe::Error::Storage => LINUX_ENOMEM,
        core_pipe::Error::Invalid => LINUX_EINVAL,
        _ => carrick_fatal::carrick_fatal!("ipc::pipe", "invalid shared pipe state"),
    }
}

impl PipeInner {
    pub(crate) fn create(
        owner: Arc<crate::el1_ipc::HostIpc>,
        pipe_id: u64,
        capacity: usize,
    ) -> Result<Self, crate::el1_ipc::CreateError> {
        use crate::el1_ipc::CreateError;
        let object = owner
            .create_pipe(capacity)
            .map_err(CreateError::from_admission)?;
        let description = |end, access| {
            carrick_el1_abi::ipc::fd::Description::new(
                IpcBacking::Pipe { object, end }.encode(),
                access,
                carrick_el1_abi::ipc::fd::StatusFlags::default(),
            )
        };
        let reader = match owner.admit_description(description(
            core_pipe::End::Reader,
            carrick_el1_abi::ipc::fd::AccessMode::ReadOnly,
        )) {
            Ok(reader) => reader,
            Err(error) => {
                for end in [core_pipe::End::Reader, core_pipe::End::Writer] {
                    owner
                        .release(IpcBacking::Pipe { object, end }.encode())
                        .unwrap_or_else(|_| {
                            carrick_fatal::carrick_fatal!(
                                "ipc::pipe",
                                "reader admission rollback failed"
                            )
                        });
                }
                return Err(CreateError::from_admission(error));
            }
        };
        let writer = match owner.admit_description(description(
            core_pipe::End::Writer,
            carrick_el1_abi::ipc::fd::AccessMode::WriteOnly,
        )) {
            Ok(writer) => writer,
            Err(error) => {
                owner
                    .release(
                        IpcBacking::Pipe {
                            object,
                            end: core_pipe::End::Writer,
                        }
                        .encode(),
                    )
                    .unwrap_or_else(|_| {
                        carrick_fatal::carrick_fatal!(
                            "ipc::pipe",
                            "writer admission rollback failed"
                        )
                    });
                drop(reader);
                return Err(CreateError::from_admission(error));
            }
        };
        let wait_queue = owner.wait_queue(object);
        let readiness = Arc::new(Mutex::new((false, false)));
        let read_pipe_ready = Arc::new(OnceLock::new());
        let write_pipe_ready = Arc::new(OnceLock::new());
        let readiness_primer: Arc<dyn Fn() + Send + Sync> = {
            let owner = Arc::clone(&owner);
            let state = Arc::clone(&readiness);
            let read = Arc::clone(&read_pipe_ready);
            let write = Arc::clone(&write_pipe_ready);
            Arc::new(move || {
                Self::publish_readiness(&owner, object, &state, &read, &write);
            })
        };
        let readiness_publisher: Arc<dyn Fn() + Send + Sync> = {
            let prime = Arc::clone(&readiness_primer);
            let queue = Arc::clone(&wait_queue);
            Arc::new(move || {
                prime();
                queue.wake_all();
            })
        };
        owner.register_host_waker(object, &readiness_publisher, &readiness_primer);
        Ok(Self {
            owner,
            object,
            pipe_id,
            endpoints: [
                HostEndpointOwnership::new(reader),
                HostEndpointOwnership::new(writer),
            ],
            #[cfg(test)]
            fixture: [None, None],
            resize: Mutex::new(()),
            readiness,
            read_pipe_ready,
            write_pipe_ready,
            _readiness_publisher: readiness_publisher,
            wait_queue,
        })
    }
    #[cfg(test)]
    pub(crate) fn new(pipe_id: u64, capacity: usize) -> Self {
        Self::create(
            Arc::new(crate::el1_ipc::HostIpc::new(1 << 23).unwrap()),
            pipe_id,
            capacity,
        )
        .unwrap()
    }
    #[cfg(test)]
    pub(crate) fn new_connected(pipe_id: u64, capacity: usize) -> Self {
        let mut pipe = Self::new(pipe_id, capacity);
        pipe.fixture = [Some(core_pipe::End::Reader), Some(core_pipe::End::Writer)];
        for endpoint in &mut pipe.endpoints {
            endpoint.get_mut().initial = false;
        }
        pipe
    }
    #[cfg(test)]
    pub(crate) fn retire_fixture_endpoint(&mut self, end: core_pipe::End) {
        let index = usize::from(end == core_pipe::End::Writer);
        if let Some(end) = self.fixture[index].take() {
            self.release_endpoint(end);
        }
    }
    #[cfg(test)]
    pub(crate) fn is_retired(&self) -> bool {
        self.owner
            .region()
            .lock(self.object, &HostLockWait)
            .is_err()
    }
    #[cfg(test)]
    pub(crate) fn guest_write_for_test(&self, bytes: &[u8]) {
        self.ensure_ring().unwrap();
        let mut guard = self.lock();
        let step = guard.pipe().unwrap().try_write(bytes);
        assert_eq!(step.result, Ok(bytes.len()));
        guard.publish(step.wake);
    }
    #[cfg(test)]
    pub(crate) fn ipc_object(&self) -> IpcObjectHandle {
        self.object
    }
    fn lock(&self) -> IpcObjectGuard<'_> {
        self.owner
            .region()
            .lock(self.object, &HostLockWait)
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::pipe", "stale live pipe binding")
            })
    }
    fn snapshot_locked(guard: &mut IpcObjectGuard<'_>) -> PipeSnapshot {
        let pipe = guard
            .pipe()
            .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong object kind"));
        PipeSnapshot {
            unread: pipe.unread_bytes(),
            capacity: pipe.capacity(),
            readers: pipe.references(core_pipe::End::Reader),
            writers: pipe.references(core_pipe::End::Writer),
            writable: pipe.readiness(core_pipe::End::Writer).writable,
        }
    }
    pub(crate) fn snapshot(&self) -> PipeSnapshot {
        Self::snapshot_locked(&mut self.lock())
    }
    pub(crate) fn pipe_id(&self) -> u64 {
        self.pipe_id
    }
    /// The reader-wake sequence of this pipe incarnation: advanced under the
    /// object lock by every write and writer release, from either venue. An
    /// ET interest compares it across samples because a byte count cannot
    /// see a drain served in EL1 followed by a refill. `None` once retired.
    pub(crate) fn read_arrival_generation(&self) -> Option<u64> {
        self.owner
            .region()
            .observe(self.object)
            .ok()
            .map(|seqs| seqs.read)
    }
    pub(crate) fn buffered_bytes(&self) -> usize {
        // Epoll can retain an observation after the last functional endpoint
        // closes. Authenticate the incarnation without retaining it or reading
        // the successor's bytes after this directory slot is reused.
        match self.owner.region().lock(self.object, &HostLockWait) {
            Ok(mut guard) => Self::snapshot_locked(&mut guard).unread,
            Err(carrick_el1_abi::ipc::IpcError::Stale) => 0,
            Err(_) => carrick_fatal::carrick_fatal!("ipc::pipe", "invalid observation"),
        }
    }
    pub(crate) fn get_capacity(&self) -> usize {
        self.snapshot().capacity
    }

    fn finish<T>(
        &self,
        mut guard: IpcObjectGuard<'_>,
        step: core_pipe::Step<T>,
    ) -> Result<T, LinuxErrno> {
        let wake = guard.publish(step.wake);
        let mut delivery = crate::el1_zone::ObjectWakeDelivery::new();
        delivery.collect(wake);
        drop(guard);
        delivery.deliver();
        self.owner.service_wake(&wake);
        step.result.map_err(object_error)
    }
    /// Give the pipe its ring (at its first write). ENOMEM only when the
    /// IPC pool itself is exhausted, as a failed pipe page allocation is.
    fn ensure_ring(&self) -> Result<(), LinuxErrno> {
        match self.owner.ensure_pipe_storage(self.object) {
            Ok(()) => Ok(()),
            Err(crate::el1_ipc::AdmissionError::NoMemory) => Err(LINUX_ENOMEM),
            Err(_) => carrick_fatal::carrick_fatal!("ipc::pipe", "live pipe ring provision"),
        }
    }
    pub(crate) fn write_bytes(&self, bytes: &[u8]) -> Result<usize, LinuxErrno> {
        loop {
            let mut guard = self.lock();
            let step = guard
                .pipe()
                .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong object kind"))
                .try_write(bytes);
            if step.result == Err(core_pipe::Error::Storage) {
                // An unbacked pipe (EPIPE was already decided): its first
                // write provides the ring outside the object lock.
                drop(guard);
                self.ensure_ring()?;
                continue;
            }
            return self.finish(guard, step);
        }
    }
    pub(crate) fn read_with(
        &self,
        count: usize,
        copy: impl FnMut(&[u8]) -> usize,
    ) -> Result<usize, LinuxErrno> {
        let mut guard = self.lock();
        let step = guard
            .pipe()
            .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong object kind"))
            .read_with(count, copy);
        self.finish(guard, step)
    }
    #[cfg(test)]
    fn install_endpoint_for_test(
        &self,
        end: core_pipe::End,
        table: carrick_el1_abi::ipc::fd::TableId,
        fd: carrick_el1_abi::ipc::fd::Fd,
    ) -> Result<(), carrick_el1_abi::ipc::fd::Error> {
        self.endpoints[usize::from(end == core_pipe::End::Writer)]
            .lock()
            .description
            .as_ref()
            .ok_or(carrick_el1_abi::ipc::fd::Error::StalePin)?
            .install(table, fd, false)
    }

    /// One end of this pipe as a zone epoll member (its object, side and
    /// OFD identity), while that end's description is live.
    pub(crate) fn zone_member(
        &self,
        end: core_pipe::End,
    ) -> Option<crate::dispatch::net::epoll_zone::ZoneMember> {
        let file_key = self.endpoint_status_flags(end)?.ofd_key()?;
        Some(crate::dispatch::net::epoll_zone::ZoneMember {
            owner: Arc::clone(&self.owner),
            object: self.object,
            kind: match end {
                core_pipe::End::Reader => carrick_el1_abi::ipc::epoll::EpollMember::PipeReader,
                core_pipe::End::Writer => carrick_el1_abi::ipc::epoll::EpollMember::PipeWriter,
            },
            file_key,
        })
    }

    pub(crate) fn endpoint_status_flags(
        &self,
        end: core_pipe::End,
    ) -> Option<Arc<crate::el1_ipc::HostDescriptionFlags>> {
        self.endpoints[usize::from(end == core_pipe::End::Writer)]
            .lock()
            .description
            .as_ref()
            .map(crate::el1_ipc::HostDescription::flags)
    }

    pub(crate) fn retain_endpoint(&self, end: core_pipe::End) {
        let mut endpoint = self.endpoints[usize::from(end == core_pipe::End::Writer)].lock();
        if endpoint.description.is_none() {
            carrick_fatal::carrick_fatal!("ipc::pipe", "retaining a closed host endpoint");
        }
        if endpoint.initial {
            endpoint.initial = false;
        } else {
            endpoint.refs = endpoint.refs.checked_add(1).unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!("ipc::pipe", "endpoint reference overflow")
            });
        }
    }

    pub(crate) fn release_endpoint(&self, end: core_pipe::End) {
        let description = {
            let mut endpoint = self.endpoints[usize::from(end == core_pipe::End::Writer)].lock();
            if endpoint.initial {
                carrick_fatal::carrick_fatal!("ipc::pipe", "releasing an unadmitted endpoint");
            }
            endpoint.refs = endpoint.refs.checked_sub(1).unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!("ipc::pipe", "endpoint reference underflow")
            });
            if endpoint.refs == 0 {
                endpoint.description.take()
            } else {
                None
            }
        };
        // Final pin release can notify host callbacks. No endpoint lock may
        // be held while the shared core publishes EOF/EPIPE readiness.
        drop(description);
    }
    pub(crate) fn set_capacity(&self, capacity: usize) -> Result<usize, LinuxErrno> {
        let _resize = self.resize.lock();
        self.owner
            .resize_pipe(self.object, capacity, MAX_PIPE_CAPACITY)
            .map_err(|error| match error {
                crate::el1_ipc::AdmissionError::Shared(carrick_el1_abi::ipc::IpcError::Object(
                    error,
                )) => object_error(error),
                _ => LINUX_ENOMEM,
            })?;
        self.owner.service_host_wake(self.object);
        Ok(self.get_capacity())
    }
    #[cfg(test)]
    pub(crate) fn readiness_pipes_initialized(&self) -> (bool, bool) {
        (
            self.read_pipe_ready.get().is_some(),
            self.write_pipe_ready.get().is_some(),
        )
    }
    fn prime_channel(
        channel: &OnceLock<Option<(HostFdRef, HostFdRef)>>,
        notified: &mut bool,
        ready: bool,
    ) {
        if let Some((r, w)) = channel.get().and_then(Option::as_ref) {
            if ready && !*notified {
                let _ = unsafe { libc::write(w.raw(), [1u8].as_ptr().cast(), 1) };
            } else if !ready && *notified {
                let mut bytes = [0u8; 32];
                let _ = unsafe { libc::read(r.raw(), bytes.as_mut_ptr().cast(), bytes.len()) };
            }
            *notified = ready;
        }
    }
    pub(crate) fn update_readiness(&self) {
        Self::publish_readiness(
            &self.owner,
            self.object,
            &self.readiness,
            &self.read_pipe_ready,
            &self.write_pipe_ready,
        );
    }
    fn publish_readiness(
        owner: &crate::el1_ipc::HostIpc,
        object: IpcObjectHandle,
        readiness: &Mutex<(bool, bool)>,
        read: &OnceLock<Option<(HostFdRef, HostFdRef)>>,
        write: &OnceLock<Option<(HostFdRef, HostFdRef)>>,
    ) {
        if read.get().is_none() && write.get().is_none() {
            return;
        }
        let mut notified = readiness.lock();
        let region = owner.region();
        let snapshot = region
            .lock(object, &HostLockWait)
            .ok()
            .map(|mut guard| Self::snapshot_locked(&mut guard));
        let read_ready = snapshot.is_none_or(|s| s.unread != 0 || s.writers == 0);
        let write_ready = snapshot.is_none_or(|s| s.readers == 0 || s.writable);
        Self::prime_channel(read, &mut notified.0, read_ready);
        Self::prime_channel(write, &mut notified.1, write_ready);
    }
    fn poll_fd(&self, channel: &OnceLock<Option<(HostFdRef, HostFdRef)>>) -> Option<HostFdRef> {
        let subscription = self.owner.subscribe_host(self.object).ok()?;
        let needs_prime = channel.get().is_none()
            || self
                .owner
                .region()
                .lock(self.object, &HostLockWait)
                .ok()
                .is_none_or(|guard| guard.host_subscribers() == 1);
        let ready = channel.get_or_init(make_readiness_pipe);
        if needs_prime {
            self.update_readiness();
        }
        ready
            .as_ref()
            .map(|(r, _)| r.clone().with_ipc_subscription(subscription))
    }
    pub(crate) fn read_poll_fd(&self) -> Option<HostFdRef> {
        self.poll_fd(&self.read_pipe_ready)
    }
    pub(crate) fn write_poll_fd(&self) -> Option<HostFdRef> {
        self.poll_fd(&self.write_pipe_ready)
    }
    pub(crate) fn initialized_read_poll_fd(&self) -> Option<HostFdRef> {
        self.read_pipe_ready.get().and_then(|_| self.read_poll_fd())
    }
    pub(crate) fn initialized_write_poll_fd(&self) -> Option<HostFdRef> {
        self.write_pipe_ready
            .get()
            .and_then(|_| self.write_poll_fd())
    }
}
pub(crate) fn read_pipe<M: CurrentMmMemory>(
    memory: &mut M,
    address: u64,
    length: usize,
    pipe: &PipeRef,
    status_flags: u64,
    _fd: i32,
    authority: super::WaitFdAuthority,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    let mut offset = 0usize;
    let result = pipe.read_with(length, |bytes| {
        if memory.write_bytes(address + offset as u64, bytes).is_err() {
            return 0;
        }
        offset += bytes.len();
        bytes.len()
    });
    match result {
        Ok(count) => DispatchOutcome::returned_len_or_errno(count),
        Err(LINUX_EAGAIN) if !nonblocking => wait_for_pipe_readable(pipe, authority),
        Err(errno) => DispatchOutcome::errno(errno),
    }
}

pub(crate) fn wait_for_pipe_readable(
    pipe: &PipeRef,
    authority: super::WaitFdAuthority,
) -> DispatchOutcome {
    if let Some(host_fd) = pipe.read_poll_fd() {
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::retained_one(host_fd, libc::POLLIN, authority),
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd {
                on_timeout: LINUX_EAGAIN.guest_retval(),
            },
        }
    } else {
        DispatchOutcome::errno(LINUX_EMFILE)
    }
}

#[allow(dead_code)]
pub(crate) fn read_pipe_bytes(
    buf: &mut [u8],
    pipe: &PipeRef,
    _status_flags: u64,
    _tid: crate::thread::ThreadId,
) -> Result<usize, LinuxErrno> {
    let mut offset = 0;
    pipe.read_with(buf.len(), |bytes| {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        bytes.len()
    })
}

/// A splice read holds the source object until its delivered prefix commits.
/// A failed destination never removes bytes or needs a second pushback store.
pub struct PipeRead<'a> {
    pipe: &'a PipeInner,
    guard: IpcObjectGuard<'a>,
    bytes: Vec<u8>,
}
impl std::ops::Deref for PipeRead<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl PipeRead<'_> {
    pub(crate) fn commit(mut self, count: usize) {
        let step = self
            .guard
            .pipe()
            .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong object kind"))
            .consume(count);
        self.pipe
            .finish(self.guard, step)
            .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "invalid read commit"));
    }
}
pub enum PipeDrain<'a> {
    Bytes(PipeRead<'a>),
    Eof,
    WouldBlock,
}

pub(crate) fn take_pipe_bytes(pipe: &PipeRef, length: usize) -> PipeDrain<'_> {
    // Bound admission work by observed source bytes, including the empty case.
    let snapshot = pipe.snapshot();
    if snapshot.unread == 0 {
        return if snapshot.writers == 0 {
            PipeDrain::Eof
        } else {
            PipeDrain::WouldBlock
        };
    }
    // Staging allocation precedes the shared object lock. Another reader can
    // consume this snapshot; peek rechecks the same authoritative record.
    let mut bytes = vec![0; length.min(snapshot.unread)];
    let mut guard = pipe.lock();
    let mut copied = 0;
    let result = guard
        .pipe()
        .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong object kind"))
        .peek_with(bytes.len(), |chunk| {
            bytes[copied..copied + chunk.len()].copy_from_slice(chunk);
            copied += chunk.len();
            chunk.len()
        });
    match result {
        Ok(0) => PipeDrain::Eof,
        Ok(count) => {
            bytes.truncate(count);
            PipeDrain::Bytes(PipeRead { pipe, guard, bytes })
        }
        Err(core_pipe::Error::WouldBlock(_)) => PipeDrain::WouldBlock,
        Err(_) => carrick_fatal::carrick_fatal!("ipc::pipe", "invalid shared read"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InMemoryTeeOutcome {
    SamePipe,
    BrokenPipe,
    /// The destination's ring could not be provided (IPC pool exhausted).
    NoMemory,
    Eof,
    SourceWouldBlock,
    DestWouldBlock,
    Transferred(usize),
}

pub(crate) fn tee_in_memory_pipes(
    source: &PipeRef,
    dest: &PipeRef,
    count: usize,
) -> InMemoryTeeOutcome {
    transfer_in_memory_pipes(source, dest, count, false)
}

pub(crate) fn transfer_in_memory_pipes(
    source: &PipeRef,
    dest: &PipeRef,
    count: usize,
    consume: bool,
) -> InMemoryTeeOutcome {
    if Arc::ptr_eq(source, dest) {
        return InMemoryTeeOutcome::SamePipe;
    }
    if count == 0 {
        return InMemoryTeeOutcome::Transferred(0);
    }
    // The destination's ring comes with its first write, provided before
    // either object lock is taken (only when there is something to move).
    if source.snapshot().unread != 0 && dest.ensure_ring().is_err() {
        return if dest.snapshot().readers == 0 {
            InMemoryTeeOutcome::BrokenPipe
        } else {
            InMemoryTeeOutcome::NoMemory
        };
    }
    // One stable order for every host operation touching two pipe objects.
    let (mut src, mut dst) = if Arc::as_ptr(source) < Arc::as_ptr(dest) {
        let src = source.lock();
        (src, dest.lock())
    } else {
        let dst = dest.lock();
        (source.lock(), dst)
    };
    if PipeInner::snapshot_locked(&mut dst).readers == 0 {
        return InMemoryTeeOutcome::BrokenPipe;
    }
    let mut wakes = core_pipe::WakeSet::default();
    let mut copied = 0;
    let result = src
        .pipe()
        .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong source kind"))
        .peek_with(count, |chunk| {
            let mut pipe = dst.pipe().unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::pipe", "wrong destination kind")
            });
            let room = pipe.capacity().saturating_sub(pipe.unread_bytes());
            if room == 0 {
                return 0;
            }
            let step = pipe.try_write(&chunk[..chunk.len().min(room)]);
            wakes.readers |= step.wake.readers;
            wakes.writers |= step.wake.writers;
            let written = step.result.unwrap_or(0);
            copied += written;
            written
        });
    let source_wake = if consume && copied > 0 {
        src.pipe()
            .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("ipc::pipe", "wrong source kind"))
            .consume(copied)
            .wake
    } else {
        core_pipe::WakeSet::default()
    };
    let mut delivery = crate::el1_zone::ObjectWakeDelivery::new();
    let source_wake = src.publish(source_wake);
    let dest_wake = dst.publish(wakes);
    delivery.collect(source_wake);
    delivery.collect(dest_wake);
    drop(src);
    drop(dst);
    delivery.deliver();
    if copied > 0 {
        dest.owner.service_wake(&dest_wake);
        source.owner.service_wake(&source_wake);
        return InMemoryTeeOutcome::Transferred(copied);
    }
    match result {
        Ok(0) => InMemoryTeeOutcome::Eof,
        Err(core_pipe::Error::WouldBlock(_)) => InMemoryTeeOutcome::SourceWouldBlock,
        _ => InMemoryTeeOutcome::DestWouldBlock,
    }
}

/// Exact operation authority admitted before the pipe state lock. A parked
/// large write transfers this authority to its continuation; a non-parked
/// write drops it when the syscall returns.
pub struct PipeWriteOperation<I> {
    pub(crate) writer_lease: crate::kernel::objects::FileDescriptionFdLease,
    pub(crate) tid: crate::thread::ThreadId,
    pub(crate) authority: super::WaitFdAuthority,
    pub(crate) is_interrupted: I,
    /// Present only for syscall paths that can publish a parked continuation.
    /// Transfer helpers deliberately pass `None` and return their partial count.
    pub(crate) notification: Option<PipeWriteNotification>,
}

/// Perform the one synchronous in-memory pipe write step. A write can either
/// complete, return a partial count, wait before copying, or transfer its exact
/// operation authority to a continuation; it never retries synchronously.
pub(crate) fn write_pipe<I: Fn() -> bool>(
    bytes: &[u8],
    pipe: &PipeRef,
    status_flags: u64,
    operation: PipeWriteOperation<I>,
) -> DispatchOutcome {
    let nonblocking = status_flags & LINUX_O_NONBLOCK != 0;
    if bytes.is_empty() {
        return DispatchOutcome::Returned { value: 0 };
    }

    let written = match pipe.write_bytes(bytes) {
        Ok(written) => written,
        Err(LINUX_EAGAIN) => {
            if nonblocking {
                return DispatchOutcome::errno(LINUX_EAGAIN);
            }
            if (operation.is_interrupted)() {
                return DispatchOutcome::errno(LINUX_EINTR);
            }
            let Some(host_fd) = pipe.write_poll_fd() else {
                return DispatchOutcome::errno(LINUX_EMFILE);
            };
            return DispatchOutcome::WaitOnFds {
                fds: WaitFds::retained_one(host_fd, libc::POLLIN, operation.authority)
                    .with_description_lease(operation.writer_lease),
                timeout: None,
                sig_mask: carrick_abi::WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd {
                    on_timeout: LINUX_EAGAIN.guest_retval(),
                },
            };
        }
        Err(errno) => return DispatchOutcome::errno(errno),
    };

    if written == bytes.len() || nonblocking || (operation.is_interrupted)() {
        return DispatchOutcome::returned_len_or_errno(written);
    }
    let Some(readiness_fd) = pipe.write_poll_fd() else {
        return DispatchOutcome::returned_len_or_errno(written);
    };
    let Some(notification) = operation.notification else {
        return DispatchOutcome::returned_len_or_errno(written);
    };
    let endpoint = PipeWriteEndpointLease::retain(
        operation.writer_lease,
        Arc::clone(pipe),
        readiness_fd,
        notification,
    );
    endpoint.publish_progress(written);
    DispatchOutcome::BlockingWrite(crate::dispatch::BlockingWrite::in_memory_pipe(
        endpoint,
        bytes.to_vec(),
        written,
        operation.tid,
        true,
    ))
}

impl<'a> FsView<'a> {
    define_syscall! {
        fn pipe2(this, cx, pipefd: GuestPtr, flags: u64) {
            let address = pipefd.0;
            let memory = &mut *cx.memory;
            if super::LinuxPipe2Flags::from_bits(flags).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let nonblock = flags & LINUX_O_NONBLOCK;
            let fd_flags = linux_fd_flags_from_open_flags(flags);

            let pipe_id = next_pipe_id();
            // Only the authority's own host memory is ENOMEM; creation
            // refusals are typed Linux limits (ENFILE), never a table size.
            let owner = cx.kernel.kernel().ipc().map_err(|_| DispatchError::Errno(LINUX_ENOMEM))?;
            let pipe = Arc::new(PipeInner::create(owner, pipe_id, DEFAULT_PIPE_CAPACITY)
                .map_err(|error| DispatchError::Errno(error.errno()))?);

            let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY | nonblock)
                .with_fs_identity(carrick_vfs::FsIdentity::Pipe);
            read_base.set_shared_pipe(Arc::clone(&pipe));
            let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY | nonblock)
                .with_fs_identity(carrick_vfs::FsIdentity::Pipe);
            write_base.set_shared_pipe(Arc::clone(&pipe));

            let read_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeReader {
                    base: read_base,
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_RDONLY | nonblock,
                fd_flags,
            );
            let write_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: write_base,
                    pipe,
                })),
                LINUX_O_WRONLY | nonblock,
                fd_flags,
            );
            let Ok((read_fd, write_fd)) = this.install_fd_pair_at_or_above(3, read_open, write_open)
            else {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, address, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value: 0 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{InternalWaitKind, WaitFdAuthority};

    #[test]
    fn red_until_step3_m2_shared_close_still_needs_host_endpoint_release() {
        use carrick_el1_abi::ipc::fd;
        for pairs in [1, 8, 64] {
            let owner = Arc::new(crate::el1_ipc::HostIpc::new(1 << 20).unwrap());
            let parent = owner.create_table(256, 256).unwrap();
            let peer = owner.create_table(256, 256).unwrap();
            let region = owner.region();
            let authority = region.fd(HostLockWait);
            let mut retained = 0;
            for index in 0..pairs {
                let pipe = PipeInner::create(Arc::clone(&owner), index as u64, PIPE_BUF).unwrap();
                pipe.retain_endpoint(core_pipe::End::Reader);
                pipe.retain_endpoint(core_pipe::End::Writer);
                pipe.install_endpoint_for_test(core_pipe::End::Reader, parent, fd::Fd(index))
                    .unwrap();
                pipe.install_endpoint_for_test(core_pipe::End::Writer, peer, fd::Fd(index))
                    .unwrap();
                assert!(authority.close(peer, fd::Fd(index)).unwrap().is_none());
                retained += pipe.snapshot().writers;
                // Explicit host release is still necessary after the final
                // guest writer slot closes. The live reader sees EOF only then.
                pipe.release_endpoint(core_pipe::End::Writer);
                assert_eq!(pipe.snapshot().writers, 0);
                assert_eq!(pipe.read_with(1, |_| panic!("EOF copies nothing")), Ok(0));
                assert!(authority.close(parent, fd::Fd(index)).unwrap().is_none());
                pipe.release_endpoint(core_pipe::End::Reader);
                assert!(pipe.is_retired());
            }
            assert_eq!(retained, pairs as usize);
            let result = if retained == 0 {
                Ok(())
            } else {
                Err("final shared writer close retains host endpoint pin")
            };
            assert_eq!(
                result.expect_err("flips at M2 cutover"),
                "final shared writer close retains host endpoint pin"
            );
            for table in [parent, peer] {
                owner.reclaim_descriptors(
                    authority
                        .destroy_table(table, |_| panic!("empty table"))
                        .unwrap(),
                );
            }
        }
    }

    #[test]
    fn serial_host_el1_ipc_pipe_flags_are_shared_per_endpoint() {
        use carrick_el1_abi::ipc::fd;
        let owner = Arc::new(crate::el1_ipc::HostIpc::new(1 << 20).unwrap());
        let pipe = Arc::new(PipeInner::create(Arc::clone(&owner), 1, 65536).unwrap());
        let reader = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(OpenDescription::PipeReader {
                base: OpenDescriptionBase::new(LINUX_O_RDONLY | LINUX_O_NONBLOCK),
                pipe: Arc::clone(&pipe),
            })),
            LINUX_O_RDONLY | LINUX_O_NONBLOCK,
        );
        let writer = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                pipe: Arc::clone(&pipe),
            })),
            LINUX_O_WRONLY,
        );
        let table = owner.create_table(64, 4).unwrap();
        pipe.install_endpoint_for_test(core_pipe::End::Reader, table, fd::Fd(0))
            .unwrap();
        pipe.install_endpoint_for_test(core_pipe::End::Writer, table, fd::Fd(1))
            .unwrap();
        let region = owner.region();
        let authority = region.fd(HostLockWait);
        assert!(authority.getfl(table, fd::Fd(0)).unwrap().1.nonblock);
        assert!(!authority.getfl(table, fd::Fd(1)).unwrap().1.nonblock);
        authority
            .setfl(table, fd::Fd(0), fd::StatusFlags::default())
            .unwrap();
        writer
            .common()
            .set_status_flags(LINUX_O_WRONLY | LINUX_O_NONBLOCK);
        assert_eq!(reader.common().status_flags(), LINUX_O_RDONLY);
        assert_eq!(
            writer.common().status_flags(),
            LINUX_O_WRONLY | LINUX_O_NONBLOCK
        );
        assert!(authority.getfl(table, fd::Fd(1)).unwrap().1.nonblock);
        assert_eq!(
            authority.getfl(table, fd::Fd(1)).unwrap().0,
            fd::AccessMode::WriteOnly
        );
        assert!(authority.close(table, fd::Fd(0)).unwrap().is_none());
        assert!(authority.close(table, fd::Fd(1)).unwrap().is_none());
        let extent = authority
            .destroy_table(table, |_| panic!("empty table"))
            .unwrap();
        owner.reclaim_descriptors(extent);
    }

    #[test]
    fn serial_host_el1_ipc_pipe_second_description_refusal_rolls_back() {
        use carrick_el1_abi::ipc::{
            IPC_OBJECT_SEGMENT as IPC_OBJECTS, IPC_OFD_SEGMENT as IPC_OFDS, fd, pipe::EventMode,
        };
        // A zone whose file table is one segment of each store.
        let owner = Arc::new(
            crate::el1_ipc::HostIpc::with_limits(
                1 << 20,
                crate::el1_ipc::IpcLimits {
                    objects: IPC_OBJECTS,
                    descriptions: IPC_OFDS,
                },
            )
            .unwrap(),
        );
        let descriptions: Vec<_> = (0..IPC_OFDS - 1)
            .map(|_| {
                let token = owner.retain_host_resource(Box::new(())).unwrap();
                owner
                    .admit_description(fd::Description::new(
                        IpcBacking::Host(token).encode(),
                        fd::AccessMode::ReadWrite,
                        fd::StatusFlags::default(),
                    ))
                    .unwrap()
            })
            .collect();
        for _ in 0..4 {
            assert!(matches!(
                PipeInner::create(Arc::clone(&owner), 1, 65536),
                Err(crate::el1_ipc::CreateError::FileTableFull)
            ));
        }
        // Both raw endpoints and the first OFD must be returned on refusal.
        let objects: Vec<_> = (0..IPC_OBJECTS)
            .map(|_| owner.create_eventfd(0, EventMode::Counter).unwrap())
            .collect();
        for object in objects {
            owner
                .release(IpcBacking::EventFd { object }.encode())
                .unwrap();
        }
        drop(descriptions);
        // Repeated failures also must not strand the pipe's backing extent.
        for _ in 0..32 {
            drop(PipeInner::create(Arc::clone(&owner), 1, 65536).unwrap());
        }
    }

    /// Work budget `pipe(2)`/`close(2)`: creating and closing N pipes
    /// costs O(N). Store growth initializes each object and description
    /// record once (a segment at a time, never a rescan), an idle pipe takes
    /// no pool bytes, re-creating after the closes grows nothing, and one
    /// create next to many live pipes costs the same as next to none: no
    /// growth at all unless it crosses a segment, then exactly one segment.
    #[test]
    fn serial_host_el1_ipc_pipe_create_close_work_is_linear() {
        use carrick_el1_abi::ipc::{IPC_OBJECT_SEGMENT, IPC_OFD_SEGMENT};
        let growth_for = |n: usize| crate::el1_ipc::IpcGrowth {
            object_records: n.next_multiple_of(IPC_OBJECT_SEGMENT) - IPC_OBJECT_SEGMENT,
            description_records: (2 * n).next_multiple_of(IPC_OFD_SEGMENT) - IPC_OFD_SEGMENT,
        };
        for n in [1_000usize, 8_192, 65_536] {
            let owner = Arc::new(crate::el1_ipc::HostIpc::new(1 << 20).unwrap());
            let pipes: Vec<_> = (0..n)
                .map(|id| PipeInner::create(Arc::clone(&owner), id as u64, 65536).unwrap())
                .collect();
            assert_eq!(
                owner.growth(),
                growth_for(n),
                "n={n}: each record initialized once"
            );
            drop(pipes);
            let pipes: Vec<_> = (0..n)
                .map(|id| PipeInner::create(Arc::clone(&owner), id as u64, 65536).unwrap())
                .collect();
            assert_eq!(
                owner.growth(),
                growth_for(n),
                "n={n}: re-creation reuses records"
            );
            // Adversarial rows: one more pipe beside n live ones.
            let before = owner.growth();
            let one = PipeInner::create(Arc::clone(&owner), 0, 65536).unwrap();
            let delta = crate::el1_ipc::IpcGrowth {
                object_records: owner.growth().object_records - before.object_records,
                description_records: owner.growth().description_records
                    - before.description_records,
            };
            assert_eq!(
                delta,
                crate::el1_ipc::IpcGrowth {
                    object_records: if n.is_multiple_of(IPC_OBJECT_SEGMENT) {
                        IPC_OBJECT_SEGMENT
                    } else {
                        0
                    },
                    description_records: if (2 * n).is_multiple_of(IPC_OFD_SEGMENT) {
                        IPC_OFD_SEGMENT
                    } else {
                        0
                    },
                },
                "n={n}: one create costs at most one segment, independent of n"
            );
            drop(one);
            drop(pipes);
            // The first write of one pipe takes one ring, whatever n.
            let pipe = PipeInner::create(Arc::clone(&owner), 0, 65536).unwrap();
            assert_eq!(pipe.write_bytes(b"x"), Ok(1));
            assert_eq!(pipe.snapshot().unread, 1);
        }
    }

    #[test]
    fn serial_host_el1_ipc_guest_writer_pin_delays_eof_after_host_close() {
        use carrick_el1_abi::ipc::fd;
        let owner = Arc::new(crate::el1_ipc::HostIpc::new(1 << 20).unwrap());
        let pipe = PipeInner::create(Arc::clone(&owner), 1, 65536).unwrap();
        pipe.retain_endpoint(core_pipe::End::Reader);
        pipe.retain_endpoint(core_pipe::End::Writer);
        let table = owner.create_table(64, 4).unwrap();
        pipe.install_endpoint_for_test(core_pipe::End::Writer, table, fd::Fd(0))
            .expect("pipe writer must install its shared description");
        let region = owner.region();
        let authority = region.fd(HostLockWait);
        let (pin, _) = authority.pin(table, fd::Fd(0)).unwrap();
        assert!(authority.close(table, fd::Fd(0)).unwrap().is_none());
        pipe.release_endpoint(core_pipe::End::Writer);
        assert_eq!(authority.holds(&pin).unwrap(), (0, 1));
        assert_eq!(
            pipe.snapshot().writers,
            1,
            "guest operation must prevent premature EOF"
        );
        {
            // A guest write after the host's first write gave the ring.
            pipe.ensure_ring().unwrap();
            let mut guard = region.lock(pipe.object, &HostLockWait).unwrap();
            assert_eq!(guard.pipe().unwrap().try_write(b"guest").result, Ok(5));
        }
        let mut bytes = [0; 5];
        assert_eq!(
            pipe.read_with(5, |source| {
                bytes.copy_from_slice(source);
                5
            }),
            Ok(5)
        );
        assert_eq!(&bytes, b"guest");
        let description = authority.unpin(pin).unwrap().expect("final guest pin");
        owner.release(description.backing).unwrap();
        assert_eq!(pipe.snapshot().writers, 0);
        assert_eq!(pipe.read_with(5, |_| panic!("EOF copies no bytes")), Ok(0));
        pipe.release_endpoint(core_pipe::End::Reader);
        assert!(pipe.is_retired());
        let extent = authority
            .destroy_table(table, |_| panic!("empty table"))
            .unwrap();
        owner.reclaim_descriptors(extent);
    }

    #[test]
    fn serial_host_el1_ipc_pipe_proxy_subscription_ends_with_lease() {
        let pipe = PipeInner::new_connected(next_pipe_id(), DEFAULT_PIPE_CAPACITY);
        let subscribers = || pipe.lock().host_subscribers();
        assert_eq!(subscribers(), 0);
        let lease = pipe.read_poll_fd().unwrap();
        assert_eq!(subscribers(), 1);
        drop(lease);
        assert_eq!(
            subscribers(),
            0,
            "cached proxy is not a live host subscriber"
        );
        pipe.ensure_ring().unwrap();
        let mut guard = pipe.lock();
        let step = guard.pipe().unwrap().try_write(b"guest");
        assert!(!guard.publish(step.wake).host_owed);
        drop(guard);
        let resumed = pipe.read_poll_fd().unwrap();
        let mut ready = libc::pollfd {
            fd: resumed.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut ready, 1, 0) },
            1,
            "a new subscriber samples changes made during the unsubscribed interval"
        );
    }

    #[test]
    fn serial_host_el1_ipc_pipe_guest_write_host_read_and_reverse() {
        let owner = Arc::new(crate::el1_ipc::HostIpc::new(1 << 20).unwrap());
        let pipe = Arc::new(PipeInner::create(Arc::clone(&owner), 1, 65536).unwrap());
        let region = owner.region();
        // EL1 forwards a write to an unbacked pipe; the host gives the ring.
        assert_eq!(
            region
                .lock(pipe.ipc_object(), &crate::el1_zone::HostLockWait)
                .unwrap()
                .pipe()
                .unwrap()
                .try_write(b"guest")
                .result,
            Err(core_pipe::Error::Storage)
        );
        pipe.ensure_ring().unwrap();
        let mut guest = region
            .lock(pipe.ipc_object(), &crate::el1_zone::HostLockWait)
            .unwrap();
        assert_eq!(guest.pipe().unwrap().try_write(b"guest").result, Ok(5));
        drop(guest);
        let mut bytes = [0; 5];
        assert_eq!(
            read_pipe_bytes(
                &mut bytes,
                &pipe,
                0,
                crate::thread::ThreadId::synthetic_for_tests(1)
            ),
            Ok(5)
        );
        assert_eq!(&bytes, b"guest");
        assert_eq!(pipe.write_bytes(b"host"), Ok(4));
        let mut guest = region
            .lock(pipe.ipc_object(), &crate::el1_zone::HostLockWait)
            .unwrap();
        assert_eq!(guest.pipe().unwrap().try_read(&mut bytes).result, Ok(4));
        assert_eq!(&bytes[..4], b"host");
        assert_eq!(guest.host_subscribers(), 0);
        assert_eq!(pipe.readiness_pipes_initialized(), (false, false));
    }

    fn write_pipe_for_test(
        bytes: &[u8],
        pipe: &PipeRef,
        status_flags: u64,
        fd: i32,
        authority: WaitFdAuthority,
        is_interrupted: impl Fn() -> bool,
    ) -> DispatchOutcome {
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY | status_flags),
                    pipe: Arc::clone(pipe),
                })),
                LINUX_O_WRONLY | status_flags,
            )
            .expect("test pipe writer description"),
        );
        description.retain_fd_ref();
        let lease = description
            .retain_fd_lease()
            .expect("test writer has an fd reference");
        let outcome = write_pipe(
            bytes,
            pipe,
            status_flags,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(fd),
                authority,
                is_interrupted,
                notification: None,
            },
        );
        description.release_fd_ref();
        outcome
    }

    fn write_readiness_is_signaled(pipe: &PipeInner) -> bool {
        let fd = pipe.write_poll_fd().expect("write readiness fd");
        let mut pollfd = libc::pollfd {
            fd: fd.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pollfd, 1, 0) > 0 && pollfd.revents & libc::POLLIN != 0 }
    }

    #[test]
    fn in_memory_pipe_basic_read_write() {
        let pipe = Arc::new(PipeInner::new_connected(1, 65536));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        let data = b"hello, in-memory pipe!";
        let out = write_pipe_for_test(
            data,
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::returned_len_or_errno(data.len()));

        let mut buf = vec![0u8; data.len()];
        let read_n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(read_n, data.len());
        assert_eq!(&buf[..], data);
    }

    #[test]
    fn in_memory_pipe_write_readiness_requires_pipe_buf_room() {
        let pipe = Arc::new(PipeInner::new_connected(5, PIPE_BUF));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let tid = crate::thread::ThreadId::synthetic_for_tests(5);
        let payload = vec![0x55; PIPE_BUF];

        assert!(write_readiness_is_signaled(&pipe));
        assert_eq!(
            write_pipe_for_test(&payload, &pipe, LINUX_O_NONBLOCK, 4, authority, || false),
            DispatchOutcome::returned_len_or_errno(PIPE_BUF)
        );
        assert!(!write_readiness_is_signaled(&pipe));

        let mut half = vec![0; PIPE_BUF / 2];
        assert_eq!(
            read_pipe_bytes(&mut half, &pipe, LINUX_O_NONBLOCK, tid),
            Ok(PIPE_BUF / 2)
        );
        assert!(
            !write_readiness_is_signaled(&pipe),
            "free space below PIPE_BUF must not be writable"
        );

        assert_eq!(
            read_pipe_bytes(&mut half, &pipe, LINUX_O_NONBLOCK, tid),
            Ok(PIPE_BUF / 2)
        );
        assert!(
            write_readiness_is_signaled(&pipe),
            "PIPE_BUF free bytes must be writable"
        );
    }

    #[test]
    fn in_memory_pipe_capacity_and_resize() {
        let pipe = Arc::new(PipeInner::new_connected(2, 4096));

        assert_eq!(pipe.get_capacity(), 4096);
        assert_eq!(pipe.set_capacity(8192), Ok(8192));
        assert_eq!(pipe.get_capacity(), 8192);

        // Fill 5000 bytes
        let data = vec![0x42u8; 5000];
        let out = write_pipe_for_test(
            &data,
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::Returned { value: 5000 });

        // Shrinking below buffered bytes must return EBUSY
        assert_eq!(pipe.set_capacity(4096), Err(LINUX_EBUSY));

        // Growing capacity succeeds
        assert_eq!(pipe.set_capacity(16384), Ok(16384));
    }

    #[test]
    fn in_memory_pipe_broken_pipe_and_eof() {
        let mut pipe = Arc::new(PipeInner::new_connected(3, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Close all readers
        Arc::get_mut(&mut pipe)
            .unwrap()
            .retire_fixture_endpoint(core_pipe::End::Reader);
        let out = write_pipe_for_test(
            b"test",
            &pipe,
            0,
            4,
            WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
            || false,
        );
        assert_eq!(out, DispatchOutcome::errno(LINUX_EPIPE));

        // Restore reader, close all writers
        let mut pipe = Arc::new(PipeInner::new_connected(6, 4096));
        Arc::get_mut(&mut pipe)
            .unwrap()
            .retire_fixture_endpoint(core_pipe::End::Writer);
        let mut buf = [0u8; 10];
        let n = read_pipe_bytes(&mut buf, &pipe, 0, tid).expect("read");
        assert_eq!(n, 0); // EOF
    }

    #[test]
    fn in_memory_pipe_nonblocking_eagain() {
        let pipe = Arc::new(PipeInner::new_connected(4, 4096));
        let tid = crate::thread::ThreadId::synthetic_for_tests(1);

        // Read from empty nonblocking pipe -> EAGAIN
        let mut buf = [0u8; 10];
        assert_eq!(
            read_pipe_bytes(&mut buf, &pipe, LINUX_O_NONBLOCK, tid),
            Err(LINUX_EAGAIN)
        );

        // Fill pipe to capacity
        let data = vec![0xaa; 4096];
        assert_eq!(
            write_pipe_for_test(
                &data,
                &pipe,
                LINUX_O_NONBLOCK,
                4,
                WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                || false,
            ),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Write to full nonblocking pipe -> EAGAIN
        assert_eq!(
            write_pipe_for_test(
                b"more",
                &pipe,
                LINUX_O_NONBLOCK,
                4,
                WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                || false,
            ),
            DispatchOutcome::errno(LINUX_EAGAIN)
        );
    }

    #[test]
    fn in_memory_pipe_blocking_write_to_full_parks_on_readiness() {
        let pipe = Arc::new(PipeInner::new_connected(10, 65536));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let fill = vec![0x33; 65536];
        assert_eq!(
            write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 65536 }
        );

        // Pipe is now completely full (65536 bytes). A blocking write of 65536 bytes
        // must park via WaitOnFds rather than spinning or returning 0.
        let out = write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false);
        let host_fd = pipe.write_poll_fd().expect("write poll fd");
        assert_eq!(
            out,
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::retained_one(host_fd, libc::POLLIN, authority),
                timeout: None,
                sig_mask: carrick_abi::WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd {
                    on_timeout: LINUX_EAGAIN.guest_retval(),
                },
            }
        );
    }

    #[test]
    fn in_memory_pipe_interrupted_write_returns_eintr_when_unwritten() {
        let pipe = Arc::new(PipeInner::new_connected(11, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        let fill = vec![0x44; 4096];
        assert_eq!(
            write_pipe_for_test(&fill, &pipe, 0, 4, authority.clone(), || false),
            DispatchOutcome::Returned { value: 4096 }
        );

        // Pipe is full; write interrupted immediately must return EINTR, not 0.
        let out = write_pipe_for_test(b"blocked", &pipe, 0, 4, authority, || true);
        assert_eq!(out, DispatchOutcome::errno(LINUX_EINTR));
    }

    #[test]
    fn parked_large_write_keeps_writer_functional_after_numeric_close() {
        let pipe = Arc::new(PipeInner::new(14, PIPE_BUF));
        // The reader end is live independently of the writer description
        // constructed below.
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description
            .retain_fd_lease()
            .expect("admit live writer before pipe lock");

        let payload = vec![0x7c; PIPE_BUF * 2];
        let mut blocked = match write_pipe(
            &payload,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(14),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => write,
            other => panic!("expected parked partial write, got {other:?}"),
        };

        // The numeric fd closes while the continuation is parked. Its exact
        // functional lease keeps the writer endpoint live, so the reader must
        // not observe EOF before the staged suffix lands.
        description.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 1);
        assert_eq!(pipe.snapshot().writers, 1);

        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(14),
            ),
            Ok(PIPE_BUF)
        );
        assert_eq!(first, vec![0x7c; PIPE_BUF]);
        match crate::dispatch::drive_blocking_write(
            &mut blocked,
            &carrick_hal::NullHostSignalBridge::default(),
        ) {
            crate::dispatch::BlockingWriteStep::Done(DispatchOutcome::Returned { value }) => {
                assert_eq!(value, payload.len() as i64);
            }
            _ => panic!("expected completed blocked write"),
        }
        drop(blocked);
        assert_eq!(description.fd_ref_count(), 0);
        assert_eq!(pipe.snapshot().writers, 0);
    }

    #[test]
    fn aggregate_fault_truncates_staged_current_suffix_at_copy_boundary() {
        let pipe = Arc::new(PipeInner::new(16, PIPE_BUF));
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description.retain_fd_lease().expect("live writer");
        let current = vec![0x6b; PIPE_BUF + 1];
        let mut blocked = match write_pipe(
            &current,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(16),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => {
                // A 32-byte valid next iovec followed by EFAULT has a 4KiB
                // aggregate boundary: the uncommitted byte of `current` and
                // all staged tail bytes are excluded.
                write.with_in_memory_pipe_writev_boundary(vec![0x6c; 32], 0, PIPE_BUF)
            }
            other => panic!("expected parked write, got {other:?}"),
        };
        description.release_fd_ref();
        // If the aggregate boundary falls below bytes already copied into the
        // pipe, the continuation cannot retract them.
        let irreversible =
            blocked
                .clone()
                .with_in_memory_pipe_writev_boundary(Vec::new(), 1, PIPE_BUF);
        assert_eq!(irreversible.offset, PIPE_BUF);
        assert_eq!(irreversible.bytes.len(), PIPE_BUF);
        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(16),
            ),
            Ok(PIPE_BUF)
        );
        assert_eq!(first, vec![0x6b; PIPE_BUF]);
        match crate::dispatch::drive_blocking_write(
            &mut blocked,
            &carrick_hal::NullHostSignalBridge::default(),
        ) {
            crate::dispatch::BlockingWriteStep::Done(DispatchOutcome::Returned { value }) => {
                assert_eq!(value, PIPE_BUF as i64);
            }
            _ => panic!("expected copy-boundary completion"),
        }
    }

    #[test]
    fn aggregate_blocking_write_excludes_unadmitted_later_vectors() {
        let pipe = Arc::new(PipeInner::new(15, PIPE_BUF));
        let description = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(OpenDescription::PipeWriter {
                    base: OpenDescriptionBase::new(LINUX_O_WRONLY),
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_WRONLY,
            )
            .expect("writer description"),
        );
        description.retain_fd_ref();
        let lease = description.retain_fd_lease().expect("live writer");
        let current = vec![0x41; PIPE_BUF * 2];
        let mut blocked = match write_pipe(
            &current,
            &pipe,
            0,
            PipeWriteOperation {
                writer_lease: lease,
                tid: crate::thread::ThreadId::synthetic_for_tests(15),
                authority: WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                is_interrupted: || false,
                notification: Some(PipeWriteNotification::for_tests()),
            },
        ) {
            DispatchOutcome::BlockingWrite(write) => {
                // Three bytes preceded this current iovec. A later fault
                // retains only complete aggregate copy blocks.
                write.with_in_memory_pipe_writev_boundary(Vec::new(), 3, PIPE_BUF * 2)
            }
            other => panic!("expected parked write, got {other:?}"),
        };
        description.release_fd_ref();

        let mut first = vec![0; PIPE_BUF];
        assert_eq!(
            read_pipe_bytes(
                &mut first,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Ok(PIPE_BUF)
        );
        let crate::dispatch::BlockingWriteStep::Done(outcome) =
            crate::dispatch::drive_blocking_write(
                &mut blocked,
                &carrick_hal::NullHostSignalBridge::default(),
            )
        else {
            panic!("second pipe progress must complete the admitted aggregate");
        };
        assert_eq!(
            outcome,
            // The current vector's final three bytes belong to the incomplete
            // aggregate copy block after the later fault and are not visible.
            DispatchOutcome::returned_len_or_errno(PIPE_BUF * 2)
        );
        let mut second = vec![0; PIPE_BUF - 3];
        assert_eq!(
            read_pipe_bytes(
                &mut second,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Ok(PIPE_BUF - 3)
        );
        assert_eq!(second, vec![0x41; PIPE_BUF - 3]);
        // The physical pipe has only the retained current-vector bytes;
        // the logical prefix of three came from an earlier writev vector.
        assert_eq!(3 + first.len() + second.len(), PIPE_BUF * 2);
        let mut tail = [0; 1];
        assert_eq!(
            read_pipe_bytes(
                &mut tail,
                &pipe,
                LINUX_O_NONBLOCK,
                crate::thread::ThreadId::synthetic_for_tests(15),
            ),
            Err(LINUX_EAGAIN)
        );
    }

    #[test]
    fn in_memory_pipe_write_with_room_ignores_pending_interrupt() {
        let pipe = Arc::new(PipeInner::new_connected(13, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        // Room for the whole write: a pending signal must not turn it into
        // EINTR (a signal handler writing one wake-up byte while a second
        // signal is pending is exactly this case).
        assert_eq!(
            write_pipe_for_test(b"x", &pipe, 0, 4, authority.clone(), || true),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(pipe.buffered_bytes(), 1);
    }

    #[test]
    fn in_memory_pipe_zero_length_write_returns_zero() {
        let pipe = Arc::new(PipeInner::new_connected(12, 4096));
        let authority = WaitFdAuthority::internal(InternalWaitKind::CarrierControl);
        assert_eq!(
            write_pipe_for_test(&[], &pipe, 0, 4, authority, || false),
            DispatchOutcome::Returned { value: 0 }
        );
    }
}
