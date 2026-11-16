//! Staging and completion of the host network socket family (#231).
//!
//! An AF_INET or AF_INET6 socket is a host object: the network is a real
//! host crossing. A native process's socket descriptor lives in its ring
//! namespace as a host-backed description, and every call on one crosses as
//! one [`HostFileOp::NetSyscall`] record that the carrier serves with its one
//! socket implementation, the same one the run root's calls reach. User
//! memory stays the ring's: staging copies in exactly the ranges Linux's
//! call reads and declares the ranges it may write, and completion copies
//! back only the extents the carrier's call wrote.
//!
//! A `send` or `recv` keeps its caller's whole extent (#2414 review P0-1).
//! One record stages at most [`NET_TRANSFER_MAX_BYTES`] of its data, which
//! every inet datagram fits, so a datagram is always one transfer: the
//! carrier answers EMSGSIZE for a larger datagram send before it transmits
//! anything. A stream transfer larger than one record continues record by
//! record in the ring's owned continuation ([`NetTransfer`]), which keeps
//! the bytes already moved and the call's completion authority.
//!
//! AF_UNIX and every other family keep their own route: a `socket` call of
//! another domain is not decoded here, and a call on an in-zone descriptor
//! stays with its ring owner.

use super::{
    Access, HostFileOp, HostFileOutput, HostFileStage, HostFileUser, NativeDescriptor,
    OutputLayout, Staging, errno, gather_user,
};
use crate::abi::entry::SyscallResult;
use alloc::boxed::Box;
use alloc::vec::Vec;
use carrick_core_abi::host_file::{
    self, NET_TRANSFER_MAX_BYTES, NetCall, NetCaller, NetSegment, record_len,
};
use carrick_syscall_abi::CanonicalNr;

/// Largest socket address a call reads or writes (Linux
/// `sizeof(struct sockaddr_storage)`).
const SOCKET_ADDRESS_MAX: usize = 128;
/// Largest option value staged for `getsockopt`/`setsockopt`.
const SOCKET_OPTION_MAX: usize = 4096;
/// Largest byte count one `send` or `recv` moves: Linux clamps a larger
/// length to `INT_MAX`.
const TRANSFER_LEN_MAX: u64 = i32::MAX as u64;
/// Linux `MSG_PEEK`.
const LINUX_MSG_PEEK: u64 = 0x2;
/// Linux `MSG_WAITALL`.
const LINUX_MSG_WAITALL: u64 = 0x100;

/// A decoded call of the host network family: its canonical number and
/// argument words. Pointers in them are still untrusted user addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketCall {
    pub canonical: CanonicalNr,
    pub args: [u64; 6],
}

impl SocketCall {
    /// Decode a canonical syscall of the family. `None` for every other
    /// call, and for a `socket` of a family that is not a host network.
    pub fn decode(canonical: CanonicalNr, args: &[u64; 6]) -> Option<Self> {
        use crate::crossing::nr;
        let family = [
            nr::SOCKET,
            nr::CONNECT,
            nr::BIND,
            nr::LISTEN,
            nr::ACCEPT,
            nr::ACCEPT4,
            nr::SENDTO,
            nr::RECVFROM,
            nr::GETSOCKOPT,
            nr::SETSOCKOPT,
            nr::GETSOCKNAME,
            nr::GETPEERNAME,
            nr::SHUTDOWN,
        ];
        if !family.contains(&canonical) {
            return None;
        }
        if canonical == nr::SOCKET {
            let domain = args[0] as i32;
            if domain != carrick_syscall_abi::LINUX_AF_INET
                && domain != carrick_syscall_abi::LINUX_AF_INET6
            {
                return None;
            }
        }
        Some(Self {
            canonical,
            args: *args,
        })
    }

    /// The descriptor the call operates on, if any.
    fn fd(self) -> Option<i32> {
        (self.canonical != crate::crossing::nr::SOCKET).then_some(self.args[0] as i32)
    }
}

/// Accumulates the staged user ranges of one call.
#[derive(Default)]
struct Plan {
    segments: Vec<NetSegment>,
    inputs: Vec<Vec<u8>>,
}

impl Plan {
    /// Stage `len` user bytes at `address` the call reads (`output`: and may
    /// write back).
    fn read(
        &mut self,
        user: &mut dyn HostFileUser,
        address: u64,
        len: usize,
        output: bool,
    ) -> Result<(), HostFileStage> {
        let mut bytes = Vec::new();
        gather_user(user, &mut bytes, address, len).map_err(|address| HostFileStage::Fault {
            address,
            access: Access::Read,
        })?;
        if output {
            self.writable(user, address, len)?;
        }
        self.segments.push(NetSegment {
            address,
            len: len as u32,
            input: true,
            output,
        });
        self.inputs.push(bytes);
        Ok(())
    }

    /// Declare `len` user bytes at `address` the call may write. The ring
    /// supplies them before the crossing: the reply's copy-out cannot fault.
    fn write(
        &mut self,
        user: &mut dyn HostFileUser,
        address: u64,
        len: usize,
    ) -> Result<(), HostFileStage> {
        self.writable(user, address, len)?;
        self.segments.push(NetSegment {
            address,
            len: len as u32,
            input: false,
            output: true,
        });
        Ok(())
    }

    fn writable(
        &self,
        user: &mut dyn HostFileUser,
        address: u64,
        len: usize,
    ) -> Result<(), HostFileStage> {
        let writable = user.writable(address, len);
        if writable < len {
            return Err(HostFileStage::Fault {
                address: address.saturating_add(writable as u64),
                access: Access::Write,
            });
        }
        Ok(())
    }

    /// Prove the rest of a transfer's extent, past its first record's
    /// range, readable now: the continuation's later records copy it in
    /// without a fault supply of their own.
    fn readable(
        &self,
        user: &mut dyn HostFileUser,
        address: u64,
        len: usize,
    ) -> Result<(), HostFileStage> {
        let readable = user.readable(address, len);
        if readable < len {
            return Err(HostFileStage::Fault {
                address: address.saturating_add(readable as u64),
                access: Access::Read,
            });
        }
        Ok(())
    }

    /// A value-result socket address (`accept`, `getsockname`, `recvfrom`):
    /// the `socklen_t` the call reads and rewrites, and the address bytes it
    /// may write. Linux reads the length first; a negative one is EINVAL.
    fn address_result(
        &mut self,
        user: &mut dyn HostFileUser,
        address: u64,
        length: u64,
    ) -> Result<(), HostFileStage> {
        let mut word = [0u8; 4];
        if !user.copy_in(&mut word, length) {
            return Err(HostFileStage::Fault {
                address: length,
                access: Access::Read,
            });
        }
        let capacity = i32::from_le_bytes(word);
        if capacity < 0 {
            return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
        }
        self.read(user, length, 4, true)?;
        let capacity = (capacity as usize).min(SOCKET_ADDRESS_MAX);
        if capacity > 0 {
            self.write(user, address, capacity)?;
        }
        Ok(())
    }
}

pub(super) fn stage(
    call: SocketCall,
    staging: &mut Staging<'_, '_>,
    user: &mut dyn HostFileUser,
) -> Option<HostFileStage> {
    use crate::crossing::nr;
    if let Some(fd) = call.fd() {
        match staging.descriptor(fd)? {
            NativeDescriptor::Absent => return Some(errno(carrick_syscall_abi::LINUX_EBADF)),
            // A ring object stays with its ring owner (and its counted
            // refusal), never a guessed ENOTSOCK.
            NativeDescriptor::InZone(_) => return Some(HostFileStage::InRing),
            NativeDescriptor::HostBacked { .. } => {}
        }
    }
    let mut args = call.args;
    let mut plan = Plan::default();
    let staged = (|| {
        let c = call.canonical;
        if c == nr::CONNECT || c == nr::BIND {
            // Linux refuses a negative length or one larger than
            // `struct sockaddr_storage` before reading the address.
            let len = args[2] as i32;
            if len < 0 || len as usize > SOCKET_ADDRESS_MAX {
                return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            if len > 0 {
                plan.read(user, args[1], len as usize, false)?;
            }
        } else if c == nr::ACCEPT
            || c == nr::ACCEPT4
            || c == nr::GETSOCKNAME
            || c == nr::GETPEERNAME
        {
            if args[1] != 0 {
                plan.address_result(user, args[1], args[2])?;
            }
        } else if c == nr::SENDTO {
            // The call keeps its whole extent in `args[2]`; this record
            // stages its first range. A stream send continues in the ring
            // (`NetTransfer`), whose later records copy in the rest, proven
            // readable now; the carrier refuses a datagram larger than the
            // range with EMSGSIZE.
            args[2] = args[2].min(TRANSFER_LEN_MAX);
            let len = args[2] as usize;
            let first = len.min(NET_TRANSFER_MAX_BYTES);
            if first > 0 {
                plan.read(user, args[1], first, false)?;
                plan.readable(user, args[1].saturating_add(first as u64), len - first)?;
            }
            if args[4] != 0 {
                let alen = args[5] as i32;
                if alen < 0 || alen as usize > SOCKET_ADDRESS_MAX {
                    return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
                }
                if alen > 0 {
                    plan.read(user, args[4], alen as usize, false)?;
                }
            }
        } else if c == nr::RECVFROM {
            // The call keeps its whole extent in `args[2]`; this record
            // receives into its first range, which holds any datagram. A
            // MSG_WAITALL stream receive continues in the ring
            // (`NetTransfer`) into the rest, proven writable now.
            args[2] = args[2].min(TRANSFER_LEN_MAX);
            let len = args[2] as usize;
            let first = len.min(NET_TRANSFER_MAX_BYTES);
            if first > 0 {
                plan.write(user, args[1], first)?;
                if args[3] & LINUX_MSG_WAITALL != 0 && args[3] & LINUX_MSG_PEEK == 0 {
                    plan.writable(user, args[1].saturating_add(first as u64), len - first)?;
                }
            }
            if args[4] != 0 {
                plan.address_result(user, args[4], args[5])?;
            }
        } else if c == nr::GETSOCKOPT {
            let mut word = [0u8; 4];
            if !user.copy_in(&mut word, args[4]) {
                return Err(HostFileStage::Fault {
                    address: args[4],
                    access: Access::Read,
                });
            }
            let capacity = i32::from_le_bytes(word);
            if capacity < 0 {
                return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            plan.read(user, args[4], 4, true)?;
            let capacity = (capacity as usize).min(SOCKET_OPTION_MAX);
            if args[3] != 0 && capacity > 0 {
                plan.write(user, args[3], capacity)?;
            }
        } else if c == nr::SETSOCKOPT {
            let len = args[4] as i32;
            if len < 0 {
                return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let len = (len as usize).min(SOCKET_OPTION_MAX);
            if args[3] != 0 && len > 0 {
                plan.read(user, args[3], len, false)?;
            }
        }
        Ok(())
    })();
    if let Err(stage) = staged {
        return Some(stage);
    }
    let inputs: Vec<&[u8]> = plan.inputs.iter().map(Vec::as_slice).collect();
    let Some(input) = NetCall::encode(call.canonical.raw(), args, &plan.segments, &inputs) else {
        return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
    };
    // The record's own segment table names every destination; completion
    // reads it back from the replied record.
    let output = HostFileOutput {
        address: 0,
        len: NetCall::output_capacity(&plan.segments),
        layout: OutputLayout::Net,
    };
    Some(staging.request(
        HostFileOp::NetSyscall,
        call.fd().unwrap_or(-1),
        0,
        [0; 4],
        &input,
        Some(output),
    ))
}

/// Copy a served call's written extents back to the caller's memory, as its
/// staged segment table (`input`) names them. `None` when the reply does not
/// match its staged segments.
pub(super) fn complete(
    result: i64,
    input: &[u8],
    reply: &[u8],
    copy_out: &mut dyn FnMut(u64, &[u8]) -> bool,
) -> Option<SyscallResult> {
    let call = staged_call(input)?;
    for (address, bytes) in NetCall::decode_written(call.segments(), reply)?.1 {
        if !bytes.is_empty() && !copy_out(address, bytes) {
            return Some(SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT));
        }
    }
    Some(SyscallResult::new(result))
}

/// The calling member of a socket call, from its own ring task row: its
/// task, its pid as its pid namespace sees it, and its credentials. `None`
/// for a pid of 0, which no live process has.
pub fn net_caller(
    task: carrick_sched_core::process::TaskKey,
    ns_pid: u32,
    credentials: &crate::identity::TaskCredentials,
) -> Option<NetCaller> {
    Some(NetCaller {
        task,
        ns_pid: core::num::NonZeroU32::new(ns_pid)?,
        ids: host_file::AccessIds {
            ruid: credentials.ruid.raw(),
            euid: credentials.euid.raw(),
            suid: credentials.suid.raw(),
            fsuid: credentials.fsuid.raw(),
            rgid: credentials.rgid.raw(),
            egid: credentials.egid.raw(),
            sgid: credentials.sgid.raw(),
            fsgid: credentials.fsgid.raw(),
        },
        cap_effective: credentials.cap_effective.bits(),
    })
}

/// Re-stage a socket call's record with its caller leading the input: the
/// carrier runs the call under the caller's own identity, which only the
/// ring owner holds. Any other record is returned as staged. `None` when
/// the record is not a well-formed unserved request or the caller and call
/// do not fit one record.
pub fn stamp_net_caller(record: &[u8], caller: &NetCaller) -> Option<Box<[u8]>> {
    let (header, input, output_cap) = host_file::request_parts(record)?;
    if header.op != HostFileOp::NetSyscall {
        return Some(record.into());
    }
    let mut staged = Vec::new();
    staged
        .try_reserve_exact(host_file::NET_CALLER_BYTES + input.len())
        .ok()?;
    staged.extend_from_slice(&caller.encode());
    staged.extend_from_slice(input);
    let len = record_len(staged.len(), output_cap)?;
    let mut restaged = alloc::vec![0u8; len].into_boxed_slice();
    host_file::encode(&mut restaged, header, &staged, output_cap).ok()?;
    Some(restaged)
}

/// The call of a stamped socket record's input.
pub(super) fn staged_call(input: &[u8]) -> Option<NetCall<'_>> {
    NetCall::decode(NetCaller::split(input)?.1)
}

/// A `send` or `recv` in progress across records (#2414 review P0-1): the
/// ring's owned continuation of one call, which keeps the bytes its earlier
/// records moved. Linux's blocking stream send completes its whole buffer,
/// and a MSG_WAITALL stream receive fills its whole buffer, unless a signal,
/// an error or the end of the stream stops them: then the call returns the
/// bytes already moved, and an error only when none moved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetTransfer {
    done: u64,
}

impl NetTransfer {
    /// The bytes the call's earlier records moved.
    pub const fn done(self) -> u64 {
        self.done
    }

    /// The call's answer once it stops: the bytes moved, or `result` (an
    /// interruption or error) when none moved.
    pub fn stopped(self, result: SyscallResult) -> SyscallResult {
        if self.done == 0 {
            result
        } else {
            SyscallResult::new(self.done as i64)
        }
    }
}

/// What a served socket record's call does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetTransferStep {
    /// The call's result.
    Complete(SyscallResult),
    /// The call continues with its next record over `len` bytes at
    /// `address` ([`net_transfer_record`]); a send's bytes are copied in
    /// from there first.
    Next {
        transfer: NetTransfer,
        address: u64,
        len: usize,
        send: bool,
    },
}

/// Whether the served `record` is a socket `send` or `recv`, whose
/// completion is the ring's transfer continuation ([`net_transfer_step`]).
pub fn is_net_transfer(record: &[u8]) -> bool {
    use crate::crossing::nr;
    host_file::replied_parts(record).is_some_and(|(header, input, _)| {
        header.op == HostFileOp::NetSyscall
            && staged_call(input).is_some_and(|call| {
                call.canonical == nr::SENDTO.raw() || call.canonical == nr::RECVFROM.raw()
            })
    })
}

/// The next step of the socket transfer whose record (`record`, served,
/// its user output already copied back) answered `chunk`. `interrupted`: a
/// signal cancelled the service, so the call stops with what it moved.
/// `None` for a record that is not a `send` or `recv`.
///
/// The call continues, from the byte after the last one moved, only while
/// it moved bytes and has more to move, never past a signal, and:
/// - a send on a stream socket: a blocking one until it moved them all (a
///   short record means the host's send buffer was full: the next record
///   waits for room); a non-blocking one while each record moves its whole
///   range (the next one moves what fits, or nothing);
/// - a MSG_WAITALL receive on a blocking stream socket, never a peek;
/// - never a datagram, which one record always holds whole.
pub fn net_transfer_step(
    record: &[u8],
    chunk: SyscallResult,
    transfer: NetTransfer,
    interrupted: bool,
) -> Option<NetTransferStep> {
    use crate::crossing::nr;
    let (header, input, _) = host_file::replied_parts(record)?;
    if header.op != HostFileOp::NetSyscall {
        return None;
    }
    let call = staged_call(input)?;
    let send = call.canonical == nr::SENDTO.raw();
    if !send && call.canonical != nr::RECVFROM.raw() {
        return None;
    }
    let moved = match u64::try_from(chunk.raw()) {
        Ok(moved) => moved,
        Err(_) => return Some(NetTransferStep::Complete(transfer.stopped(chunk))),
    };
    let done = NetTransfer {
        done: transfer.done.saturating_add(moved),
    };
    let complete = Some(NetTransferStep::Complete(SyscallResult::new(
        done.done as i64,
    )));
    // The facts lead the reply output of every served record.
    let facts = host_file::reply(record)
        .and_then(|reply| NetCall::decode_written(call.segments(), reply.output))
        .map_or_else(Default::default, |(facts, _)| facts);
    // The record's own range: the call's next bytes (`args[1]`), at most
    // one record's worth of the `args[2]` the call still has to move.
    let range = call
        .segments()
        .first()
        .filter(|segment| segment.address == call.args[1])
        .map_or(0, |segment| u64::from(segment.len));
    let flags = call.args[3];
    let continues = !interrupted
        && facts.stream
        && moved > 0
        && moved <= range
        && call.args[2] > moved
        && if send {
            facts.blocking || moved == range
        } else {
            facts.blocking && flags & LINUX_MSG_WAITALL != 0 && flags & LINUX_MSG_PEEK == 0
        };
    if !continues {
        return complete;
    }
    let left = call.args[2] - moved;
    Some(NetTransferStep::Next {
        transfer: done,
        address: call.args[1].checked_add(moved)?,
        len: (left as usize).min(NET_TRANSFER_MAX_BYTES),
        send,
    })
}

/// The next record of the socket transfer whose previous record is
/// `record`: the same caller, descriptor and flags over the call's next
/// `len` bytes at `address` (a send's `bytes`, a receive's buffer), with
/// the bytes the call still has to move. The destination address of a
/// stream send's first record does not repeat. `None` for a record that is
/// not a `send` or `recv`, or bytes that do not match `len`.
pub fn net_transfer_record(
    record: &[u8],
    address: u64,
    len: usize,
    bytes: Option<&[u8]>,
) -> Option<(Box<[u8]>, HostFileOutput)> {
    use crate::crossing::nr;
    let (header, input, _) = host_file::replied_parts(record)?;
    if header.op != HostFileOp::NetSyscall {
        return None;
    }
    let (caller, call) = NetCaller::split(input)?;
    let call = NetCall::decode(call)?;
    let send = call.canonical == nr::SENDTO.raw();
    if (!send && call.canonical != nr::RECVFROM.raw())
        || bytes.is_some() != send
        || bytes.is_some_and(|bytes| bytes.len() != len)
        || len == 0
        || len > NET_TRANSFER_MAX_BYTES
    {
        return None;
    }
    let range = call
        .segments()
        .first()
        .filter(|segment| segment.address == call.args[1])
        .map_or(0, |segment| u64::from(segment.len));
    let moved = address.checked_sub(call.args[1])?;
    if moved == 0 || moved > range {
        return None;
    }
    let left = call.args[2].checked_sub(moved)?;
    let segments = [NetSegment {
        address,
        len: len as u32,
        input: send,
        output: !send,
    }];
    let inputs: &[&[u8]] = match bytes {
        Some(bytes) => &[bytes],
        None => &[],
    };
    let encoded = NetCall::encode(
        call.canonical,
        [call.args[0], address, left, call.args[3], 0, 0],
        &segments,
        inputs,
    )?;
    let mut staged = Vec::new();
    staged
        .try_reserve_exact(host_file::NET_CALLER_BYTES + encoded.len())
        .ok()?;
    staged.extend_from_slice(&caller.encode());
    staged.extend_from_slice(&encoded);
    let output_cap = NetCall::output_capacity(&segments);
    let mut next = alloc::vec![0u8; record_len(staged.len(), output_cap)?].into_boxed_slice();
    host_file::encode(&mut next, header, &staged, output_cap).ok()?;
    Some((
        next,
        HostFileOutput {
            address: 0,
            len: output_cap,
            layout: OutputLayout::Net,
        },
    ))
}
