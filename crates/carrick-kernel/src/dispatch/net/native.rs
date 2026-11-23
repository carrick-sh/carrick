//! Carrier half of the native host network venue (#231).
//!
//! A native (ring-owned) process has no host task and no host fd table: its
//! descriptors live in its ring namespace. An AF_INET/AF_INET6 socket is a
//! real host object, so a native call on one crosses as a
//! [`HostFileOp::NetSyscall`](carrick_core_abi::host_file::HostFileOp) record:
//! the canonical syscall, its arguments and the user memory the ring staged.
//!
//! The carrier serves it with its one socket implementation, the same
//! handlers the run root's socket calls reach. The call runs against a
//! scratch descriptor table that holds only the caller's socket, under
//! [`NATIVE_SOCKET_FD`], and against the staged memory; the network model
//! (address rewriting, the in-zone loopback, the DNS gateway, per-description
//! option state) is therefore the root's, exactly. A socket the call creates
//! (`socket`, `accept`) leaves the scratch table for the caller's own ring
//! namespace. A call that would block answers an owner wait on the member's
//! host-readiness queue, sampled before the call, and the host descriptor is
//! enrolled with the carrier's one wait reactor; the member publishes the
//! call's record again when it is ready.

use std::sync::Arc;

use carrick_core_abi::host_file::{HostFileHeader, NetCall, NetSegment};
use carrick_el1_abi::ipc::fd;

use crate::dispatch::{DispatchOutcome, SyscallDispatcher};
use crate::el1_ipc::{HostIpc, InstallHostDescriptionError, PinnedHostResourceError};
use crate::host_readiness::HostReadinessReactor;

/// The number the caller's socket has in its call's scratch table. The
/// caller's own number never leaves its ring namespace.
const NATIVE_SOCKET_FD: i32 = 3;

/// A host network socket behind a native ring descriptor: the carrier's own
/// socket description, with one functional reference for the ring's
/// descriptors, as a host fd slot holds one.
pub(in crate::dispatch) struct NativeNetFile {
    description: parking_lot::Mutex<Arc<crate::kernel::FileDescription>>,
    ipc: std::sync::Weak<HostIpc>,
    token: crate::host_readiness::HostReadinessToken,
    /// The reactor this socket's waits enrol in, which forgets them when the
    /// ring releases the socket.
    readiness: Arc<HostReadinessReactor>,
}

impl NativeNetFile {
    fn new(
        description: Arc<crate::kernel::FileDescription>,
        readiness: Arc<HostReadinessReactor>,
        owner: &Arc<HostIpc>,
    ) -> Self {
        description.retain_fd_ref();
        Self {
            description: parking_lot::Mutex::new(description),
            token: crate::host_readiness::HostReadinessToken::new(),
            readiness,
            ipc: Arc::downgrade(owner),
        }
    }

    pub(in crate::dispatch) fn description(&self) -> Arc<crate::kernel::FileDescription> {
        Arc::clone(&self.description.lock())
    }

    /// The readiness identity of this socket's enrolments.
    pub(in crate::dispatch) fn source(&self) -> crate::host_readiness::HostReadinessSource {
        self.token.source()
    }

    /// A call replaced the socket's description (a loopback connect becomes
    /// an in-zone pair): the ring's descriptors now name the new one.
    fn replace(&self, next: &Arc<crate::kernel::FileDescription>) {
        let mut held = self.description.lock();
        if Arc::ptr_eq(&held, next) {
            return;
        }
        next.retain_fd_ref();
        let previous = std::mem::replace(&mut *held, Arc::clone(next));
        drop(held);
        previous.release_fd_ref();
    }
}

impl Drop for NativeNetFile {
    fn drop(&mut self) {
        // The ring released the last descriptor naming this socket.
        self.readiness.forget(self.token.source());
        if let Some(owner) = self.ipc.upgrade()
            && let Some(epolls) = owner.existing_native_socket_epolls()
        {
            epolls.forget_socket(&owner, self.source());
        }
        self.description.get_mut().release_fd_ref();
    }
}

/// The identity one native network call runs under (#231): the calling
/// member's own, as its ring stamped it in the record. Every credential,
/// capability and pid read of the call answers these, never the identity of
/// the context whose resources the call borrows.
pub(in crate::dispatch) struct NativeNetCaller {
    /// The member's ring task; `None` for an unstamped socket transfer
    /// ([`NativeNetCaller::unstamped`]).
    task: Option<carrick_sched_core::process::TaskKey>,
    pid: crate::dispatch::NsPid,
    credentials: Arc<crate::kernel::Credentials>,
    cap_effective: u64,
}

impl std::fmt::Debug for NativeNetCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeNetCaller")
            .field("task", &self.task)
            .field("pid", &self.pid)
            .field("euid", &self.credentials.euid)
            .field("cap_effective", &format_args!("{:#x}", self.cap_effective))
            .finish()
    }
}

impl NativeNetCaller {
    fn stamped(
        caller: &carrick_core_abi::host_file::NetCaller,
        ids: &crate::kernel::ObjectIdRegistry,
    ) -> Option<Self> {
        let id = caller.ids;
        Some(Self {
            task: Some(caller.task),
            pid: crate::dispatch::NsPid(i32::try_from(caller.ns_pid.get()).ok()?),
            credentials: Arc::new(crate::kernel::Credentials::from_values(
                crate::kernel::CredentialsValues {
                    id: ids.credentials_id().ok()?,
                    ruid: carrick_abi::NsUid::new(id.ruid),
                    euid: carrick_abi::NsUid::new(id.euid),
                    suid: carrick_abi::NsUid::new(id.suid),
                    rgid: carrick_abi::NsGid::new(id.rgid),
                    egid: carrick_abi::NsGid::new(id.egid),
                    sgid: carrick_abi::NsGid::new(id.sgid),
                    fsuid: carrick_abi::NsUid::new(id.fsuid),
                    fsgid: carrick_abi::NsGid::new(id.fsgid),
                    umask: 0o022,
                },
            )),
            cap_effective: caller.cap_effective,
        })
    }

    #[cfg(test)]
    pub(in crate::dispatch) fn for_test(
        caller: &carrick_core_abi::host_file::NetCaller,
        ids: &crate::kernel::ObjectIdRegistry,
    ) -> Option<Self> {
        Self::stamped(caller, ids)
    }

    /// `read(2)`, `write(2)` and `fstat(2)` of a socket descriptor, whose
    /// records carry no caller (the ring stages them before it knows the
    /// descriptor is a socket). On an inet socket Linux's calls consult no
    /// caller identity (no ancillary data, no capability check); were one
    /// read, it answers the overflow ids with no capability and no pid,
    /// never the run root's.
    fn unstamped(ids: &crate::kernel::ObjectIdRegistry) -> Option<Self> {
        const OVERFLOW: u32 = 65_534;
        Some(Self {
            task: None,
            pid: crate::dispatch::NsPid(0),
            credentials: Arc::new(crate::kernel::Credentials::from_values(
                crate::kernel::CredentialsValues {
                    id: ids.credentials_id().ok()?,
                    ruid: carrick_abi::NsUid::new(OVERFLOW),
                    euid: carrick_abi::NsUid::new(OVERFLOW),
                    suid: carrick_abi::NsUid::new(OVERFLOW),
                    rgid: carrick_abi::NsGid::new(OVERFLOW),
                    egid: carrick_abi::NsGid::new(OVERFLOW),
                    sgid: carrick_abi::NsGid::new(OVERFLOW),
                    fsuid: carrick_abi::NsUid::new(OVERFLOW),
                    fsgid: carrick_abi::NsGid::new(OVERFLOW),
                    umask: 0o022,
                },
            )),
            cap_effective: 0,
        })
    }

    pub(in crate::dispatch) fn credentials(&self) -> Arc<crate::kernel::Credentials> {
        Arc::clone(&self.credentials)
    }

    /// The caller's pid as its own pid namespace sees it.
    pub(in crate::dispatch) fn pid(&self) -> crate::dispatch::NsPid {
        self.pid
    }

    pub(in crate::dispatch) fn has_capability(&self, capability: u32) -> bool {
        self.cap_effective & (1_u64 << capability) != 0
    }
}

/// What each native network handler's scope answers for its caller's
/// identity, recorded on the serving thread as the handler starts: a
/// witness reads what the production scope answers, not a constructor.
#[cfg(test)]
pub(in crate::dispatch) mod observed_caller {
    use std::cell::RefCell;

    /// The identity reads one handler's scope answered.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::dispatch) struct Seen {
        pub(in crate::dispatch) pid: u32,
        pub(in crate::dispatch) ruid: u32,
        pub(in crate::dispatch) euid: u32,
        pub(in crate::dispatch) suid: u32,
        pub(in crate::dispatch) fsuid: u32,
        pub(in crate::dispatch) egid: u32,
        /// The capabilities `has_effective_capability` grants, as a mask.
        pub(in crate::dispatch) capabilities: u64,
    }

    thread_local! {
        static SEEN: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(
        dispatcher: &crate::dispatch::SyscallDispatcher,
        context: &crate::kernel::KernelContext,
    ) {
        let credentials = dispatcher.cred_snapshot();
        let capabilities = (0..64)
            .filter(|&cap| crate::dispatch::creds::has_effective_capability(context, cap))
            .fold(0_u64, |mask, cap| mask | 1 << cap);
        let seen = Seen {
            pid: dispatcher.identity_pid(),
            ruid: credentials.ruid.raw(),
            euid: credentials.euid.raw(),
            suid: credentials.suid.raw(),
            fsuid: credentials.fsuid.raw(),
            egid: credentials.egid.raw(),
            capabilities,
        };
        SEEN.with(|seen_list| seen_list.borrow_mut().push(seen));
    }

    /// The scopes this thread's handlers answered since the last take.
    pub(in crate::dispatch) fn take() -> Vec<Seen> {
        SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
}

/// Staged user memory of one call: exactly the ranges the ring staged.
/// Any other access faults, as the caller's own memory would for a range
/// Linux's call does not touch. A write lands in a range the call may write
/// and records exactly what it wrote (#2418 review P0-5): each range's
/// writes are one run, so its copy-back is only bytes the call wrote, never
/// the snapshot staging took of the rest.
pub(in crate::dispatch) struct StagedMemory {
    segments: Vec<StagedSegment>,
}

struct StagedSegment {
    segment: NetSegment,
    bytes: Vec<u8>,
    /// The bytes the call wrote, `[start, end)`: one run.
    written: Option<(usize, usize)>,
}

impl StagedMemory {
    fn new(call: &NetCall<'_>) -> Self {
        Self {
            segments: call
                .staged()
                .map(|(segment, bytes)| StagedSegment {
                    segment,
                    bytes: bytes.map_or_else(|| vec![0; segment.len as usize], <[u8]>::to_vec),
                    written: None,
                })
                .collect(),
        }
    }

    /// The segment holding `[address, address + len)` whole, and its
    /// offset there: among the ranges the call may write when `output`.
    fn find(&self, address: u64, len: usize, output: bool) -> Option<(usize, usize)> {
        self.segments
            .iter()
            .enumerate()
            .filter(|(_, held)| !output || held.segment.output)
            .find_map(|(index, held)| {
                let offset = usize::try_from(address.checked_sub(held.segment.address)?).ok()?;
                (offset.checked_add(len)? <= held.bytes.len()).then_some((index, offset))
            })
    }

    /// The call's `facts` and the written extent of each output range, in
    /// segment order.
    fn written(&self, facts: carrick_core_abi::host_file::NetTransferFacts) -> Vec<u8> {
        let extents: Vec<(u32, &[u8])> = self
            .segments
            .iter()
            .filter(|held| held.segment.output)
            .map(|held| match held.written {
                Some((start, end)) => (start as u32, &held.bytes[start..end]),
                None => (0, &held.bytes[..0]),
            })
            .collect();
        NetCall::encode_written(facts, &extents)
    }
}

impl carrick_guest_mem::GuestMemory for StagedMemory {
    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.find(address, length, true).is_some()
    }

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let (index, offset) = self
            .find(address, length, false)
            .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })?;
        Ok(self.segments[index].bytes[offset..offset + length].to_vec())
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let length = bytes.len();
        if length == 0 {
            return Ok(());
        }
        let out_of_bounds = || carrick_guest_mem::MemoryError::OutOfBounds { address, length };
        let (index, offset) = self.find(address, length, true).ok_or_else(out_of_bounds)?;
        let end = offset + length;
        let held = &mut self.segments[index];
        held.written = Some(match held.written {
            None => (offset, end),
            Some((start, previous)) if offset <= previous && end >= start => {
                (start.min(offset), previous.max(end))
            }
            // Apart from the call's earlier write, the copy-back would
            // carry the unwritten bytes between them.
            Some(_) => return Err(out_of_bounds()),
        });
        held.bytes[offset..end].copy_from_slice(bytes);
        // Every other staged copy of these bytes reads what the call wrote,
        // as the caller's own memory would.
        let stop = address + length as u64;
        for (other, held) in self.segments.iter_mut().enumerate() {
            let first = held.segment.address;
            let start = address.max(first);
            let last = stop.min(first.saturating_add(held.bytes.len() as u64));
            if other == index || start >= last {
                continue;
            }
            let (from, to) = ((start - address) as usize, (start - first) as usize);
            let len = (last - start) as usize;
            held.bytes[to..to + len].copy_from_slice(&bytes[from..from + len]);
        }
        Ok(())
    }
}

impl carrick_guest_mem::CurrentMmMemory for StagedMemory {}

/// The Linux type of a native socket's description (`SOCK_STREAM`,
/// `SOCK_DGRAM`, ...), whatever backs it.
fn native_socket_type(description: &crate::kernel::FileDescription) -> Option<i32> {
    use crate::dispatch::fd_table::OpenDescription;
    description
        .inspect_kind(|open| match open {
            OpenDescription::HostSocket { type_, .. } => Some(*type_ & 0xf),
            OpenDescription::InMemorySocket { socket, .. } => Some(socket.socket_type),
            OpenDescription::Netlink { sock_type, .. } => Some(*sock_type & 0xf),
            _ => None,
        })
        .flatten()
}

/// Fit a `send` or `recv` to the range its record staged (#2414 review
/// P0-1). The record keeps the call's whole extent in `args[2]` and stages
/// at most one record's range of it at `args[1]`, a range every inet
/// datagram fits:
/// - a stream transfer moves at most that range, and the ring continues
///   it with the call's next record;
/// - a receive's datagram fits the range whole, so the range is its buffer;
/// - a datagram send larger than the range is larger than any datagram the
///   socket can carry (an IP datagram's length is 16 bits): EMSGSIZE, and
///   nothing is transmitted.
///
/// `Some` is the call's answer before any handler runs.
fn native_transfer_extent(
    call: &NetCall<'_>,
    kind: Option<i32>,
    args: &mut [u64; 6],
) -> Option<NetServed> {
    use carrick_abi::syscall::nr;
    let send = call.canonical == nr::SENDTO.raw();
    if !send && call.canonical != nr::RECVFROM.raw() {
        return None;
    }
    let range = call
        .segments()
        .first()
        .filter(|segment| segment.address == call.args[1])
        .map_or(0, |segment| u64::from(segment.len));
    if args[2] <= range {
        return None;
    }
    if send {
        match kind {
            Some(carrick_abi::LINUX_SOCK_STREAM) => {}
            Some(carrick_abi::LINUX_SOCK_DGRAM | carrick_abi::LINUX_SOCK_RAW) => {
                return Some(NetServed::Reply(
                    carrick_abi::LINUX_EMSGSIZE.guest_retval(),
                    Vec::new(),
                ));
            }
            // A message larger than one record on another socket type
            // has no exact answer here: a counted ENOSYS, never a guess.
            _ => return Some(NetServed::Refused),
        }
    }
    args[2] = range;
    None
}

/// Admit a message call (`sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`;
/// #2418) to the handler, whose user ranges the ring staged. `Some` is the
/// call's answer before any handler runs:
/// - a `sendmsg` whose data the ring did not stage
///   ([`carrick_core_abi::host_file::NET_MESSAGE_UNSTAGED`]) is larger than
///   one record, so larger than any datagram: EMSGSIZE on a datagram socket,
///   and refused on any other;
/// - a send that may stop part way on a blocking stream socket, and a
///   `MSG_WAITALL` receive on one, are refused: Linux completes them whole,
///   and a message call has no transfer continuation across records yet;
/// - a blocking `recvmmsg` of more than one message without
///   `MSG_WAITFORONE` (Linux waits for them all) or with a timeout (Linux
///   checks it between datagrams and writes it back) is refused: no
///   continuation waits for the rest or keeps the deadline (#2418 review
///   P0-4);
/// - a `sendmmsg` of more than one message on a socket that is not a
///   datagram socket is refused: Linux raises SIGPIPE for a later
///   message's EPIPE while it answers the count sent, and the ring raises
///   it only for an EPIPE answer.
fn native_message_admission(
    call: &NetCall<'_>,
    kind: Option<i32>,
    nonblock: bool,
    args: &mut [u64; 6],
) -> Option<NetServed> {
    use carrick_abi::syscall::nr;
    use carrick_core_abi::host_file::{NET_MESSAGE_UNSTAGED, NET_MESSAGE_UNSTAGED_ARG};
    let (send, flags) = match call.canonical {
        c if c == nr::SENDMSG.raw() => (true, args[2]),
        c if c == nr::RECVMSG.raw() => (false, args[2]),
        c if c == nr::SENDMMSG.raw() => (true, args[3]),
        c if c == nr::RECVMMSG.raw() => (false, args[3]),
        _ => return None,
    };
    let datagram = matches!(
        kind,
        Some(carrick_abi::LINUX_SOCK_DGRAM | carrick_abi::LINUX_SOCK_RAW)
    );
    if call.canonical == nr::SENDMSG.raw() && args[NET_MESSAGE_UNSTAGED_ARG] != 0 {
        if args[NET_MESSAGE_UNSTAGED_ARG] != NET_MESSAGE_UNSTAGED || !datagram {
            return Some(NetServed::Refused);
        }
        return Some(NetServed::Reply(
            carrick_abi::LINUX_EMSGSIZE.guest_retval(),
            Vec::new(),
        ));
    }
    let blocking = !nonblock && flags & carrick_abi::LINUX_MSG_DONTWAIT as u64 == 0;
    let whole = send || flags & carrick_abi::LINUX_MSG_WAITALL as u64 != 0;
    if blocking && whole && !datagram {
        return Some(NetServed::Refused);
    }
    if call.canonical == nr::RECVMMSG.raw()
        && (args[4] != 0
            || blocking && args[2] > 1 && flags & carrick_abi::LINUX_MSG_WAITFORONE as u64 == 0)
    {
        return Some(NetServed::Refused);
    }
    if call.canonical == nr::SENDMMSG.raw() && args[2] > 1 && !datagram {
        return Some(NetServed::Refused);
    }
    None
}

/// The readiness a wait entry's host poll bits name, as the socket's
/// in-zone part reports it.
fn zone_events(events: i16) -> carrick_abi::LinuxEpollEvents {
    let mut zone = carrick_abi::LinuxEpollEvents::empty();
    if events & libc::POLLIN != 0 {
        zone |= carrick_abi::LinuxEpollEvents::IN;
    }
    if events & libc::POLLOUT != 0 {
        zone |= carrick_abi::LinuxEpollEvents::OUT;
    }
    zone
}

/// The socket one native network call runs on.
enum NetSocket<'a> {
    /// A socket a native call created ([`NativeNetFile`]).
    Native(&'a NativeNetFile),
    /// A host socket the run root's host table created, which the caller's
    /// ring descriptor names through a physical hold: the root's own
    /// description, inherited across a fork, or the root's own descriptor
    /// once its table is the ring's (#2867). The lease pins the
    /// description for the call.
    Inherited {
        lease: crate::kernel::objects::FileDescriptionFdLease,
        hold: &'a crate::kernel::objects::IpcPhysicalHold,
    },
}

impl NetSocket<'_> {
    fn description(&self) -> Arc<crate::kernel::FileDescription> {
        match self {
            Self::Native(socket) => socket.description(),
            Self::Inherited { lease, .. } => Arc::clone(lease.description()),
        }
    }

    /// The readiness identity a wait on this socket enrols under.
    fn source(
        &self,
        reactor: &Arc<HostReadinessReactor>,
    ) -> crate::host_readiness::HostReadinessSource {
        match self {
            Self::Native(socket) => socket.source(),
            Self::Inherited { hold, .. } => hold.net_readiness_source(reactor),
        }
    }
}

/// One served network call.
pub(in crate::dispatch) enum NetServed {
    /// The call's result and the reply output (written extents).
    Reply(i64, Vec<u8>),
    /// The call would block: the member waits on its host-readiness queue
    /// from this sampled revision.
    Wait(u64),
    /// Not served: the ring answers a counted ENOSYS.
    Refused,
}

/// The result of one handler run against the scratch table.
enum Ran {
    Outcome(DispatchOutcome),
    Refused,
}

impl SyscallDispatcher {
    /// Serve one [`NetCall`] for a native member of this run. `waiter` is the
    /// authenticated requesting member, whose host-readiness queue a call
    /// that would block waits on; without one such a call is refused.
    pub(in crate::dispatch) fn serve_native_net_call(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        input: &[u8],
        waiter: Option<carrick_el1_abi::RecordRef>,
    ) -> NetServed {
        // The ring stamps every socket call with its caller; an unstamped
        // one is refused, never run under the run root's identity.
        let Some((caller, call)) = carrick_core_abi::host_file::NetCaller::split(input) else {
            return NetServed::Refused;
        };
        let Some(call) = NetCall::decode(call) else {
            return NetServed::Refused;
        };
        let Some(caller) =
            NativeNetCaller::stamped(&caller, self.kernel_binding.read().kernel().object_ids())
        else {
            return NetServed::Refused;
        };
        let caller = Arc::new(caller);
        // Sample before the call's own probe: a readiness notification after
        // this point reruns the member's park at once.
        let revision = waiter.and_then(|record| owner.host_ready_revision(record));
        if header.fd < 0 {
            return self.run_native_net_call(owner, table, &call, &caller, None, waiter, revision);
        }
        match owner.with_pinned_host_description(table, fd::Fd(header.fd), |resource, flags| {
            let socket = if let Some(socket) = resource.downcast_ref::<NativeNetFile>() {
                NetSocket::Native(socket)
            } else {
                // A host file or stdio stream is not a socket, never a
                // fabricated ENOTSOCK for a socket its `fstat` (S_IFSOCK)
                // names. A socket the run root's host table created is
                // served through its physical hold (#2867).
                match crate::dispatch::native_files::native_resource_is_socket(resource) {
                    Some(false) => {
                        return NetServed::Reply(
                            carrick_abi::LINUX_ENOTSOCK.guest_retval(),
                            Vec::new(),
                        );
                    }
                    Some(true) => {
                        match resource
                            .downcast_ref::<crate::kernel::objects::IpcPhysicalHold>()
                            .and_then(|hold| Some((hold.retain_io()?, hold)))
                        {
                            Some((lease, hold)) => NetSocket::Inherited { lease, hold },
                            None => return NetServed::Refused,
                        }
                    }
                    None => return NetServed::Refused,
                }
            };
            self.run_native_net_call(
                owner,
                table,
                &call,
                &caller,
                Some((socket, flags.nonblock)),
                waiter,
                revision,
            )
        }) {
            Ok(served) => served,
            Err(PinnedHostResourceError::BadFd) => {
                NetServed::Reply(carrick_abi::LINUX_EBADF.guest_retval(), Vec::new())
            }
            Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) => {
                NetServed::Refused
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_native_net_call(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        call: &NetCall<'_>,
        caller: &Arc<NativeNetCaller>,
        socket: Option<(NetSocket<'_>, bool)>,
        waiter: Option<carrick_el1_abi::RecordRef>,
        revision: Option<u64>,
    ) -> NetServed {
        // The handlers borrow the run's container and network namespace
        // through this context; its identity never answers (`caller`).
        let Ok(context) = self.capture_one_task_context() else {
            return NetServed::Refused;
        };
        let Ok(scratch_id) = self
            .kernel_binding
            .read()
            .kernel()
            .object_ids()
            .file_table_id()
        else {
            return NetServed::Refused;
        };
        let mut args = call.args;
        let kind = socket
            .as_ref()
            .and_then(|(socket, _)| native_socket_type(&socket.description()));
        let nonblock = socket.as_ref().is_some_and(|(_, nonblock)| *nonblock);
        if let Some(answer) = native_transfer_extent(call, kind, &mut args)
            .or_else(|| native_message_admission(call, kind, nonblock, &mut args))
        {
            return answer;
        }
        // A loopback connect replaces its socket's description with an
        // in-zone pair, which only a native socket's descriptors follow
        // (`NativeNetFile::replace`): a held description is the root's.
        if matches!(socket, Some((NetSocket::Inherited { .. }, _)))
            && call.canonical == carrick_abi::syscall::nr::CONNECT.raw()
        {
            return NetServed::Refused;
        }
        // What the ring's transfer continuation needs of this socket.
        let facts = carrick_core_abi::host_file::NetTransferFacts {
            stream: kind == Some(carrick_abi::LINUX_SOCK_STREAM),
            blocking: socket.is_some()
                && !nonblock
                && args[3] & carrick_abi::LINUX_MSG_DONTWAIT as u64 == 0,
        };
        let scratch = Arc::new(crate::kernel::FileTable::new(scratch_id));
        if let Some((socket, nonblock)) = &socket {
            let nonblock = *nonblock;
            let description = socket.description();
            // The guest's O_NONBLOCK lives in its ring description, which
            // `fcntl` and `ioctl(FIONBIO)` change in ring.
            let status = description.common().status_flags();
            let next = if nonblock {
                status | carrick_abi::LINUX_O_NONBLOCK
            } else {
                status & !carrick_abi::LINUX_O_NONBLOCK
            };
            if next != status {
                description.common().set_status_flags(next);
            }
            let Ok(reservation) = scratch.reserve_slot_at_or_above(NATIVE_SOCKET_FD, i32::MAX)
            else {
                return NetServed::Refused;
            };
            if reservation.fd() != NATIVE_SOCKET_FD
                || reservation
                    .commit(crate::kernel::FileSlot::new(description, 0))
                    .is_err()
            {
                return NetServed::Refused;
            }
            args[0] = NATIVE_SOCKET_FD as u64;
        }
        // The ring raises the caller's own SIGPIPE on EPIPE: the dispatcher's
        // would reach the task whose context the call borrows.
        let flags = match call.canonical {
            c if c == carrick_abi::syscall::nr::SENDTO.raw()
                || c == carrick_abi::syscall::nr::SENDMMSG.raw() =>
            {
                Some(3)
            }
            c if c == carrick_abi::syscall::nr::SENDMSG.raw() => Some(2),
            _ => None,
        };
        if let Some(flags) = flags {
            args[flags] |= carrick_abi::LINUX_MSG_NOSIGNAL as u64;
        }
        let mut memory = StagedMemory::new(call);
        let ran = self.run_native_net_handler(
            &context,
            &scratch,
            caller,
            call.canonical,
            args,
            &mut memory,
        );
        // The socket's description may have been replaced in the scratch
        // table (an in-zone loopback pair); every other slot is a socket the
        // call created, which moves to the caller's ring namespace.
        let mut created = None;
        // Retire the scratch table as a task's table retires at exit: its
        // slots' references pass to this call.
        let slots = scratch.drain_functional_refs();
        for (number, slot) in &slots {
            match &socket {
                Some((NetSocket::Native(socket), _)) if *number == NATIVE_SOCKET_FD => {
                    socket.replace(&slot.description);
                }
                Some((NetSocket::Inherited { .. }, _)) if *number == NATIVE_SOCKET_FD => {}
                _ => created = Some((*number, slot.clone())),
            }
        }
        if let Some((NetSocket::Native(socket), _)) = &socket
            && let Some(epolls) = owner.existing_native_socket_epolls()
        {
            epolls.socket_changed(owner, socket);
        }
        let served = match ran {
            Ran::Refused => NetServed::Refused,
            Ran::Outcome(DispatchOutcome::Returned { value }) => {
                match created
                    .as_ref()
                    .filter(|(number, _)| value as i32 == *number)
                {
                    Some((_, slot)) => {
                        let reply = self.install_native_socket(owner, table, slot);
                        NetServed::Reply(reply, memory.written(facts))
                    }
                    None => NetServed::Reply(value as i64, memory.written(facts)),
                }
            }
            Ran::Outcome(DispatchOutcome::Errno { errno }) => {
                NetServed::Reply(errno.guest_retval(), Vec::new())
            }
            Ran::Outcome(DispatchOutcome::WaitOnFds {
                fds, timeout: None, ..
            }) => match (&socket, waiter, revision) {
                (Some((socket, _)), Some(record), Some(revision)) if !fds.fds.is_empty() => {
                    let reactor = Arc::clone(self.kernel_binding.read().kernel().host_readiness());
                    let source = socket.source(&reactor);
                    let description = socket.description();
                    // A wait entry with no host descriptor is the socket's
                    // in-zone part (#2867): a listener's loopback arrivals,
                    // or an in-zone pair's peer. It enrols on the socket's
                    // own wait queue; a socket with none has no venue.
                    let mut interests = Vec::with_capacity(fds.fds.len());
                    let mut zone = Vec::new();
                    for wait in fds.fds.iter() {
                        if wait.fd() >= 0 {
                            interests.push(crate::host_readiness::HostReadinessInterest {
                                source,
                                // SAFETY: the scratch slot and the ring's
                                // descriptor retain this description's host
                                // fd until the reactor holds its own
                                // duplicate.
                                fd: unsafe { std::os::fd::BorrowedFd::borrow_raw(wait.fd()) },
                                events: wait.events(),
                            });
                            continue;
                        }
                        let Some(queue) = description.wait_queue() else {
                            return NetServed::Refused;
                        };
                        zone.push(crate::host_readiness::HostReadinessZoneInterest {
                            source,
                            description: Arc::clone(&description),
                            queue,
                            events: zone_events(wait.events()),
                        });
                    }
                    if owner.watch_host_ready_with_zone(&reactor, record, &interests, zone) {
                        NetServed::Wait(revision)
                    } else {
                        NetServed::Refused
                    }
                }
                _ => NetServed::Refused,
            },
            // A timed wait, an in-zone wait or a retained continuation has no
            // native venue yet: never a guessed result.
            Ran::Outcome(_) => NetServed::Refused,
        };
        // The scratch table's references: a moved socket now has its ring's.
        for (_, slot) in slots {
            slot.description.release_fd_ref();
        }
        served
    }

    /// `read`, `write` or `fstat` of a native socket descriptor, staged as a
    /// [`carrick_core_abi::host_file::HostFileOp::Read`]/`Write`/`Fstat`
    /// record: the same call on the socket, through the same handlers. The
    /// reply is the record's own (raw data or `struct stat`), not a
    /// [`NetCall`] frame. `None` for any other operation.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::dispatch) fn serve_native_socket_file_op(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        socket: &NativeNetFile,
        nonblock: bool,
        input: &[u8],
        capacity: usize,
        waiter: Option<carrick_el1_abi::RecordRef>,
    ) -> Option<NetServed> {
        use carrick_core_abi::host_file::HostFileOp;
        // An address no staged record names: the call's only user range.
        const STAGE: u64 = 0x1000;
        let (canonical, args, segment, staged): (u64, [u64; 6], NetSegment, Option<&[u8]>) =
            match header.op {
                // read(2) and write(2) of a socket are recv and send with
                // no flags (the carrier never raises the caller's SIGPIPE).
                HostFileOp::Read => (
                    carrick_abi::syscall::nr::RECVFROM.raw(),
                    [0, STAGE, capacity as u64, 0, 0, 0],
                    NetSegment {
                        address: STAGE,
                        len: capacity as u32,
                        input: false,
                        output: true,
                    },
                    None,
                ),
                HostFileOp::Write => (
                    carrick_abi::syscall::nr::SENDTO.raw(),
                    [0, STAGE, input.len() as u64, 0, 0, 0],
                    NetSegment {
                        address: STAGE,
                        len: input.len() as u32,
                        input: true,
                        output: false,
                    },
                    Some(input),
                ),
                HostFileOp::Fstat => (
                    carrick_abi::syscall::nr::FSTAT.raw(),
                    [0, STAGE, 0, 0, 0, 0],
                    NetSegment {
                        address: STAGE,
                        len: capacity as u32,
                        input: false,
                        output: true,
                    },
                    None,
                ),
                _ => return None,
            };
        let encoded = NetCall::encode(canonical, args, &[segment], staged.as_slice())?;
        let call = NetCall::decode(&encoded)?;
        let revision = waiter.and_then(|record| owner.host_ready_revision(record));
        let caller = Arc::new(NativeNetCaller::unstamped(
            self.kernel_binding.read().kernel().object_ids(),
        )?);
        Some(
            match self.run_native_net_call(
                owner,
                table,
                &call,
                &caller,
                Some((NetSocket::Native(socket), nonblock)),
                waiter,
                revision,
            ) {
                NetServed::Reply(result, framed) if result >= 0 => {
                    let output = NetCall::decode_written(call.segments(), &framed)
                        .and_then(|(_, written)| written.into_iter().next())
                        .map_or_else(Vec::new, |(_, bytes)| bytes.to_vec());
                    NetServed::Reply(result, output)
                }
                NetServed::Reply(result, _) => NetServed::Reply(result, Vec::new()),
                served => served,
            },
        )
    }

    fn run_native_net_handler(
        &self,
        context: &crate::kernel::KernelContext,
        scratch: &Arc<crate::kernel::FileTable>,
        caller: &Arc<NativeNetCaller>,
        canonical: u64,
        args: [u64; 6],
        memory: &mut StagedMemory,
    ) -> Ran {
        let Some(handler) = crate::dispatch::routing::resolve_handler::<StagedMemory>(canonical)
        else {
            return Ran::Refused;
        };
        let reporter = crate::dispatch::CompatReporter::default();
        let mut cx = crate::dispatch::SyscallCtx {
            host_wait: None,
            kernel: context,
            request: crate::dispatch::SyscallRequest::new(
                canonical,
                crate::compat::SyscallArgs::from(args),
            ),
            memory,
            reporter: &reporter,
            thread: None,
            execution_lease: None,
            mm_executor: None,
        };
        match crate::dispatch::resources::with_native_net_scope(
            context,
            Arc::clone(scratch),
            Arc::clone(caller),
            || {
                #[cfg(test)]
                observed_caller::record(self, context);
                handler(self, &mut cx)
            },
        ) {
            Ok(outcome) => Ran::Outcome(outcome),
            Err(_) => Ran::Refused,
        }
    }

    /// Move a socket the call created into the caller's ring namespace at
    /// its lowest free number, with the creation's `O_NONBLOCK` and
    /// close-on-exec. Returns the call's result: the new descriptor, or the
    /// errno Linux reports for a full table.
    fn install_native_socket(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        slot: &crate::kernel::FileSlot,
    ) -> i64 {
        let status = slot.description.common().status_flags();
        let flags = fd::StatusFlags {
            append: false,
            nonblock: status & carrick_abi::LINUX_O_NONBLOCK != 0,
            asynchronous: false,
            direct: false,
            noatime: false,
            dsync: false,
            sync: false,
            immutable: 0,
        };
        match owner.install_host_description(
            table,
            Box::new(NativeNetFile::new(
                slot.description(),
                Arc::clone(self.kernel_binding.read().kernel().host_readiness()),
                owner,
            )),
            fd::AccessMode::ReadWrite,
            flags,
            // A socket has no file identity for record locks.
            None,
            slot.close_on_exec(),
        ) {
            Ok(number) => i64::from(number.0),
            Err(InstallHostDescriptionError::TooManyFiles) => {
                carrick_abi::LINUX_EMFILE.guest_retval()
            }
            Err(InstallHostDescriptionError::FileTableFull) => {
                carrick_abi::LINUX_ENFILE.guest_retval()
            }
            Err(
                InstallHostDescriptionError::NoMemory | InstallHostDescriptionError::Unavailable,
            ) => carrick_abi::LINUX_ENOMEM.guest_retval(),
        }
    }
}
