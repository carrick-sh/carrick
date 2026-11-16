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
            // A transfer crosses at most one record's data range: a larger
            // send returns the short count of that range.
            let len = (args[2] as usize).min(NET_TRANSFER_MAX_BYTES);
            args[2] = len as u64;
            if len > 0 {
                plan.read(user, args[1], len, false)?;
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
            let len = (args[2] as usize).min(NET_TRANSFER_MAX_BYTES);
            args[2] = len as u64;
            if len > 0 {
                plan.write(user, args[1], len)?;
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
    for (address, bytes) in NetCall::decode_written(call.segments(), reply)? {
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
