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
//! enrolled with the carrier's one wait reactor; the member reruns the call
//! when it is ready.

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
    token: crate::host_readiness::HostReadinessToken,
    /// The reactor this socket's waits enrol in, which forgets them when the
    /// ring releases the socket.
    readiness: Arc<HostReadinessReactor>,
}

impl NativeNetFile {
    fn new(
        description: Arc<crate::kernel::FileDescription>,
        readiness: Arc<HostReadinessReactor>,
    ) -> Self {
        description.retain_fd_ref();
        Self {
            description: parking_lot::Mutex::new(description),
            token: crate::host_readiness::HostReadinessToken::new(),
            readiness,
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
        self.description.get_mut().release_fd_ref();
    }
}

/// Staged user memory of one call: exactly the ranges the ring staged.
/// Any other access faults, as the caller's own memory would for a range
/// Linux's call does not touch. Writes record each range's written extent.
pub(in crate::dispatch) struct StagedMemory {
    segments: Vec<StagedSegment>,
}

struct StagedSegment {
    segment: NetSegment,
    bytes: Vec<u8>,
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

    fn find(&self, address: u64, len: usize) -> Option<(usize, usize)> {
        self.segments.iter().enumerate().find_map(|(index, held)| {
            let offset = usize::try_from(address.checked_sub(held.segment.address)?).ok()?;
            (offset.checked_add(len)? <= held.bytes.len()).then_some((index, offset))
        })
    }

    /// The written extent of each output range, in segment order.
    fn written(&self) -> Vec<u8> {
        let extents: Vec<(u32, &[u8])> = self
            .segments
            .iter()
            .filter(|held| held.segment.output)
            .map(|held| match held.written {
                Some((start, end)) => (start as u32, &held.bytes[start..end]),
                None => (0, &held.bytes[..0]),
            })
            .collect();
        NetCall::encode_written(&extents)
    }
}

impl carrick_guest_mem::GuestMemory for StagedMemory {
    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.find(address, length)
            .is_some_and(|(index, _)| self.segments[index].segment.output)
    }

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let (index, offset) = self
            .find(address, length)
            .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })?;
        Ok(self.segments[index].bytes[offset..offset + length].to_vec())
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let length = bytes.len();
        let (index, offset) = self
            .find(address, length)
            .filter(|(index, _)| self.segments[*index].segment.output)
            .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })?;
        let held = &mut self.segments[index];
        held.bytes[offset..offset + length].copy_from_slice(bytes);
        let end = offset + length;
        held.written = Some(match held.written {
            Some((start, previous)) => (start.min(offset), previous.max(end)),
            None => (offset, end),
        });
        Ok(())
    }
}

impl carrick_guest_mem::CurrentMmMemory for StagedMemory {}

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
        let Some(call) = NetCall::decode(input) else {
            return NetServed::Refused;
        };
        // Sample before the call's own probe: a readiness notification after
        // this point reruns the member's park at once.
        let revision = waiter.and_then(|record| owner.host_ready_revision(record));
        if header.fd < 0 {
            return self.run_native_net_call(owner, table, &call, None, waiter, revision);
        }
        match owner.with_pinned_host_description(table, fd::Fd(header.fd), |resource, flags| {
            let Some(socket) = resource.downcast_ref::<NativeNetFile>() else {
                // A host file or stdio stream is not a socket.
                return NetServed::Reply(carrick_abi::LINUX_ENOTSOCK.guest_retval(), Vec::new());
            };
            self.run_native_net_call(
                owner,
                table,
                &call,
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
        socket: Option<(&NativeNetFile, bool)>,
        waiter: Option<carrick_el1_abi::RecordRef>,
        revision: Option<u64>,
    ) -> NetServed {
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
        let scratch = Arc::new(crate::kernel::FileTable::new(scratch_id));
        let mut args = call.args;
        if let Some((socket, nonblock)) = socket {
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
        if call.canonical == carrick_abi::syscall::nr::SENDTO.raw() {
            args[3] |= carrick_abi::LINUX_MSG_NOSIGNAL as u64;
        }
        let mut memory = StagedMemory::new(call);
        let ran =
            self.run_native_net_handler(&context, &scratch, call.canonical, args, &mut memory);
        // The socket's description may have been replaced in the scratch
        // table (an in-zone loopback pair); every other slot is a socket the
        // call created, which moves to the caller's ring namespace.
        let mut created = None;
        // Retire the scratch table as a task's table retires at exit: its
        // slots' references pass to this call.
        let slots = scratch.drain_functional_refs();
        for (number, slot) in &slots {
            match socket {
                Some((socket, _)) if *number == NATIVE_SOCKET_FD => {
                    socket.replace(&slot.description);
                }
                _ => created = Some((*number, slot.clone())),
            }
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
                        NetServed::Reply(reply, memory.written())
                    }
                    None => NetServed::Reply(value as i64, memory.written()),
                }
            }
            Ran::Outcome(DispatchOutcome::Errno { errno }) => {
                NetServed::Reply(errno.guest_retval(), Vec::new())
            }
            Ran::Outcome(DispatchOutcome::WaitOnFds {
                fds, timeout: None, ..
            }) => match (socket, waiter, revision) {
                (Some((socket, _)), Some(record), Some(revision))
                    if !fds.fds.is_empty() && fds.fds.iter().all(|wait| wait.fd() >= 0) =>
                {
                    let interests: Vec<_> = fds
                        .fds
                        .iter()
                        .map(|wait| crate::host_readiness::HostReadinessInterest {
                            source: socket.source(),
                            // SAFETY: the scratch slot and the ring's
                            // descriptor retain this description's host fd
                            // until the reactor holds its own duplicate.
                            fd: unsafe { std::os::fd::BorrowedFd::borrow_raw(wait.fd()) },
                            events: wait.events(),
                        })
                        .collect();
                    let reactor = Arc::clone(self.kernel_binding.read().kernel().host_readiness());
                    if owner.watch_host_ready(&reactor, record, &interests, None) {
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
        Some(
            match self.run_native_net_call(
                owner,
                table,
                &call,
                Some((socket, nonblock)),
                waiter,
                revision,
            ) {
                NetServed::Reply(result, framed) if result >= 0 => {
                    let output = NetCall::decode_written(call.segments(), &framed)
                        .and_then(|written| written.into_iter().next())
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
            || handler(self, &mut cx),
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
            )),
            fd::AccessMode::ReadWrite,
            flags,
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
