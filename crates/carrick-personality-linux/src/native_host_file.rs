//! Linux routing and staging for a native process's host-file crossings.
//!
//! A ring-owned (native) process has one descriptor namespace, the ring's.
//! Calls on in-zone objects (pipes, eventfds, epoll, guest sockets) are
//! served in ring and never leave it. A call whose descriptor names a
//! host-backed open description genuinely crosses: the ring stages a typed
//! [`carrick_core_abi::host_file`] record and the carrier serves it with the
//! caller's authority. This module is the single routing decision and the
//! single staging step for both ISAs; transports only carry the record.
extern crate alloc;

use crate::abi::entry::SyscallResult;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use carrick_core_abi::host_file::{
    self, HOST_FILE_CHUNK_BYTES, HostFileHeader, HostFileOp, record_len,
};
use carrick_guest_arch::Access;
use carrick_syscall_abi::{CanonicalNr, LinuxErrno};

/// Size of the aarch64 Linux `struct stat` (`asm-generic/stat.h`).
pub const LINUX_STAT_BYTES: usize = 128;
/// Linux `UIO_MAXIOV`.
pub const LINUX_UIO_MAXIOV: u64 = 1024;
const IOVEC_BYTES: usize = 16;

/// Access mode of the open description a descriptor names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptionAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    /// `O_PATH`: no data access.
    Path,
}

impl DescriptionAccess {
    const fn writable(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }
}

/// What the caller's descriptor names, resolved in its own ring table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDescriptor {
    /// An in-zone object; the ring owns every operation on it.
    InZone,
    /// A host-backed open description in ring table `table`.
    HostBacked {
        table: [u64; 3],
        access: DescriptionAccess,
    },
    /// No open descriptor with this number.
    Absent,
}

/// A host-file call the native venue knows, decoded from canonical
/// arguments. Pointers are still untrusted user addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFileCall {
    Write { fd: i32, buf: u64, count: u64 },
    Writev { fd: i32, iov: u64, iovcnt: u64 },
    Fstat { fd: i32, statbuf: u64 },
}

impl HostFileCall {
    /// Decode a canonical syscall the venue may serve. `None` for every
    /// other call, which keeps its existing in-ring or unrouted handling.
    pub fn decode(canonical: CanonicalNr, args: &[u64; 6]) -> Option<Self> {
        use crate::crossing::nr;
        let fd = args[0] as i32;
        Some(if canonical == nr::WRITE {
            Self::Write {
                fd,
                buf: args[1],
                count: args[2],
            }
        } else if canonical == nr::WRITEV {
            Self::Writev {
                fd,
                iov: args[1],
                iovcnt: args[2],
            }
        } else if canonical == nr::FSTAT {
            Self::Fstat {
                fd,
                statbuf: args[1],
            }
        } else {
            return None;
        })
    }

    pub const fn fd(self) -> i32 {
        match self {
            Self::Write { fd, .. } | Self::Writev { fd, .. } | Self::Fstat { fd, .. } => fd,
        }
    }
}

/// User memory as the staging step needs it. Output is copied back after
/// the reply through the owner's user-write path, which resolves COW and
/// reports a genuinely unwritable buffer as EFAULT, as Linux does.
pub trait HostFileUser {
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool;
}

/// User output the ring copies back after the carrier replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFileOutput {
    pub address: u64,
    pub len: usize,
}

/// The ring's routing decision for one decoded call.
#[derive(Debug, Eq, PartialEq)]
pub enum HostFileStage {
    /// An in-zone object: the call stays with its ring owner and never
    /// builds a host request.
    InRing,
    /// Answered in ring without crossing.
    Returned(SyscallResult),
    /// A user page must be supplied before staging can continue; the ring
    /// retries the exact call afterwards.
    Fault { address: u64, access: Access },
    /// A host crossing: the staged record and where its output goes.
    Request {
        record: Box<[u8]>,
        output: Option<HostFileOutput>,
    },
}

fn errno(errno: LinuxErrno) -> HostFileStage {
    HostFileStage::Returned(SyscallResult::from_errno(errno))
}

fn request(header: HostFileHeader, input: &[u8], output: Option<HostFileOutput>) -> HostFileStage {
    let output_cap = output.map_or(0, |output| output.len);
    let Some(len) = record_len(input.len(), output_cap) else {
        return errno(carrick_syscall_abi::LINUX_EINVAL);
    };
    let mut record = vec![0u8; len].into_boxed_slice();
    if host_file::encode(&mut record, header, input, output_cap).is_err() {
        return errno(carrick_syscall_abi::LINUX_EINVAL);
    }
    HostFileStage::Request { record, output }
}

/// Route and stage one decoded call against what its descriptor names.
pub fn stage(
    call: HostFileCall,
    descriptor: NativeDescriptor,
    user: &mut dyn HostFileUser,
) -> HostFileStage {
    let (table, access) = match descriptor {
        NativeDescriptor::InZone => return HostFileStage::InRing,
        NativeDescriptor::Absent => return errno(carrick_syscall_abi::LINUX_EBADF),
        NativeDescriptor::HostBacked { table, access } => (table, access),
    };
    let header = |op| HostFileHeader {
        op,
        table,
        fd: call.fd(),
        flags: 0,
        args: [0; 4],
    };
    match call {
        HostFileCall::Write { buf, count, .. } => {
            if !access.writable() {
                return errno(carrick_syscall_abi::LINUX_EBADF);
            }
            if count == 0 {
                return HostFileStage::Returned(SyscallResult::new(0));
            }
            let len = (count as usize).min(HOST_FILE_CHUNK_BYTES);
            let mut input = vec![0u8; len];
            if !user.copy_in(&mut input, buf) {
                return HostFileStage::Fault {
                    address: buf,
                    access: Access::Read,
                };
            }
            request(header(HostFileOp::Write), &input, None)
        }
        HostFileCall::Writev { iov, iovcnt, .. } => {
            if !access.writable() {
                return errno(carrick_syscall_abi::LINUX_EBADF);
            }
            if iovcnt > LINUX_UIO_MAXIOV {
                return errno(carrick_syscall_abi::LINUX_EINVAL);
            }
            let mut vectors = vec![0u8; iovcnt as usize * IOVEC_BYTES];
            if !vectors.is_empty() && !user.copy_in(&mut vectors, iov) {
                return HostFileStage::Fault {
                    address: iov,
                    access: Access::Read,
                };
            }
            // Linux rejects a negative total before any transfer.
            let mut total: u64 = 0;
            let mut segments = Vec::with_capacity(iovcnt as usize);
            for vector in vectors.chunks_exact(IOVEC_BYTES) {
                let base = u64::from_le_bytes(vector[0..8].try_into().unwrap_or([0; 8]));
                let len = u64::from_le_bytes(vector[8..16].try_into().unwrap_or([0; 8]));
                if len > i64::MAX as u64 {
                    return errno(carrick_syscall_abi::LINUX_EINVAL);
                }
                total = match total.checked_add(len) {
                    Some(total) if total <= i64::MAX as u64 => total,
                    _ => return errno(carrick_syscall_abi::LINUX_EINVAL),
                };
                segments.push((base, len));
            }
            if total == 0 {
                return HostFileStage::Returned(SyscallResult::new(0));
            }
            let mut input = Vec::with_capacity((total as usize).min(HOST_FILE_CHUNK_BYTES));
            for (base, len) in segments {
                let room = HOST_FILE_CHUNK_BYTES - input.len();
                if room == 0 {
                    break;
                }
                let take = (len as usize).min(room);
                let start = input.len();
                input.resize(start + take, 0);
                if !user.copy_in(&mut input[start..], base) {
                    // Supply first and retry the exact call; a refused supply
                    // completes as EFAULT.
                    return HostFileStage::Fault {
                        address: base,
                        access: Access::Read,
                    };
                }
            }
            request(header(HostFileOp::Write), &input, None)
        }
        HostFileCall::Fstat { statbuf, .. } => request(
            header(HostFileOp::Fstat),
            &[],
            Some(HostFileOutput {
                address: statbuf,
                len: LINUX_STAT_BYTES,
            }),
        ),
    }
}

/// Map the carrier's reply to the syscall result, copying any output back
/// through the ring's own user copy.
pub fn complete(
    record: &[u8],
    output: Option<HostFileOutput>,
    copy_out: &mut dyn FnMut(u64, &[u8]) -> bool,
) -> SyscallResult {
    let Some(reply) = host_file::reply(record) else {
        return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
    };
    if reply.result < 0 {
        return SyscallResult::new(reply.result);
    }
    if let Some(output) = output {
        if reply.output.len() != output.len {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
        }
        if !copy_out(output.address, reply.output) {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT);
        }
    }
    SyscallResult::new(reply.result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::host_file::HostFileRequestView;

    struct Memory {
        base: u64,
        bytes: Vec<u8>,
    }
    impl HostFileUser for Memory {
        fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
            let Some(start) = src.checked_sub(self.base) else {
                return false;
            };
            let start = start as usize;
            match self.bytes.get(start..start + dst.len()) {
                Some(bytes) => {
                    dst.copy_from_slice(bytes);
                    true
                }
                None => false,
            }
        }
    }

    fn memory(bytes: &[u8]) -> Memory {
        Memory {
            base: 0x1000,
            bytes: bytes.to_vec(),
        }
    }

    const STDOUT: NativeDescriptor = NativeDescriptor::HostBacked {
        table: [9, 1, 2],
        access: DescriptionAccess::ReadWrite,
    };

    #[test]
    fn in_zone_pipe_write_never_builds_a_host_request() {
        let mut user = memory(b"hello");
        for call in [
            HostFileCall::Write {
                fd: 4,
                buf: 0x1000,
                count: 5,
            },
            HostFileCall::Writev {
                fd: 4,
                iov: 0x1000,
                iovcnt: 1,
            },
            HostFileCall::Fstat {
                fd: 4,
                statbuf: 0x1000,
            },
        ] {
            assert_eq!(
                stage(call, NativeDescriptor::InZone, &mut user),
                HostFileStage::InRing,
                "{call:?} on an in-zone object must stay in ring"
            );
        }
    }

    #[test]
    fn host_backed_write_stages_the_callers_bytes_and_table() {
        let mut user = memory(b"hello");
        let HostFileStage::Request { mut record, output } = stage(
            HostFileCall::Write {
                fd: 1,
                buf: 0x1000,
                count: 5,
            },
            STDOUT,
            &mut user,
        ) else {
            panic!("a host-backed write crosses");
        };
        assert_eq!(output, None);
        let view = HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(view.header().op, HostFileOp::Write);
        assert_eq!(view.header().table, [9, 1, 2]);
        assert_eq!(view.header().fd, 1);
        assert_eq!(view.input(), b"hello");
    }

    #[test]
    fn writev_gathers_vectors_and_absent_or_readonly_fds_stay_in_ring() {
        // Two iovecs at 0x1000 pointing at "ab" (0x1020) and "cde" (0x1022).
        let mut bytes = vec![0u8; 0x30];
        bytes[0..8].copy_from_slice(&0x1020u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x1022u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&3u64.to_le_bytes());
        bytes[0x20..0x25].copy_from_slice(b"abcde");
        let mut user = memory(&bytes);
        let call = HostFileCall::Writev {
            fd: 1,
            iov: 0x1000,
            iovcnt: 2,
        };
        let HostFileStage::Request { mut record, .. } = stage(call, STDOUT, &mut user) else {
            panic!("a host-backed writev crosses");
        };
        assert_eq!(
            HostFileRequestView::parse(&mut record).unwrap().input(),
            b"abcde"
        );
        assert_eq!(
            stage(call, NativeDescriptor::Absent, &mut user),
            errno(carrick_syscall_abi::LINUX_EBADF)
        );
        assert_eq!(
            stage(
                call,
                NativeDescriptor::HostBacked {
                    table: [9, 1, 2],
                    access: DescriptionAccess::ReadOnly
                },
                &mut user
            ),
            errno(carrick_syscall_abi::LINUX_EBADF)
        );
        assert_eq!(
            stage(
                HostFileCall::Writev {
                    fd: 1,
                    iov: 0x1000,
                    iovcnt: LINUX_UIO_MAXIOV + 1
                },
                STDOUT,
                &mut user
            ),
            errno(carrick_syscall_abi::LINUX_EINVAL)
        );
    }

    #[test]
    fn unreadable_input_requests_fault_supply_first() {
        let mut user = memory(b"");
        assert_eq!(
            stage(
                HostFileCall::Write {
                    fd: 1,
                    buf: 0x9000,
                    count: 1
                },
                STDOUT,
                &mut user
            ),
            HostFileStage::Fault {
                address: 0x9000,
                access: Access::Read
            }
        );
    }

    #[test]
    fn completion_copies_output_only_on_success() {
        let mut user = memory(&[0u8; LINUX_STAT_BYTES]);
        let HostFileStage::Request {
            mut record,
            output: Some(output),
        } = stage(
            HostFileCall::Fstat {
                fd: 1,
                statbuf: 0x1000,
            },
            STDOUT,
            &mut user,
        )
        else {
            panic!("fstat of a host-backed descriptor crosses with output");
        };
        let stat = [7u8; LINUX_STAT_BYTES];
        HostFileRequestView::parse(&mut record)
            .unwrap()
            .reply(0, &stat)
            .unwrap();
        let mut copied = Vec::new();
        let result = complete(&record, Some(output), &mut |address, bytes| {
            copied.push((address, bytes.to_vec()));
            true
        });
        assert_eq!(result, SyscallResult::new(0));
        assert_eq!(copied, vec![(0x1000, stat.to_vec())]);
        // No reply (refused or cancelled service) never copies anything.
        let HostFileStage::Request { record, output } = stage(
            HostFileCall::Fstat {
                fd: 1,
                statbuf: 0x1000,
            },
            STDOUT,
            &mut user,
        ) else {
            panic!("fstat crosses");
        };
        let result = complete(&record, output, &mut |_, _| panic!("no output"));
        assert_eq!(
            result,
            SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO)
        );
    }
}
