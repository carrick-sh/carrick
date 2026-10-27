//! Carrier half of the native host-file venue (#894).
//!
//! A ring-owned (native) process has no host task and no host fd table. Its
//! descriptors live in its ring namespace; a host-backed descriptor there is
//! an `IpcBacking::Host` token naming one host resource. When the ring stages
//! a [`carrick_core_abi::host_file`] record, the carrier pins the exact
//! description the caller's table names, serves the operation on its host
//! resource through the same code the dispatcher uses for that resource, and
//! writes the reply in place. Nothing here owns a descriptor number.
//!
//! Slice 1 serves the run's implicit stdio streams (write and fstat); other
//! host resources are refused exactly (counted ENOSYS in the ring).
use std::sync::Arc;

use carrick_core_abi::host_file::{HostFileOp, HostFileRequestView};
use carrick_el1_abi::ipc::fd;
use zerocopy::IntoBytes;

use super::fs::state::NativeStdio;
use super::{DispatchOutcome, SyscallDispatcher};
use crate::el1_ipc::{HostIpc, HostResource, PinnedHostResourceError};
use crate::kernel::objects::ImplicitHostStdio;

const _: () = assert!(
    core::mem::size_of::<carrick_abi::LinuxStat>()
        == carrick_personality_linux::native_host_file::LINUX_STAT_BYTES
);

/// The carrier refused a staged record; the ring answers counted ENOSYS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHostFileRefusal;

/// Retained host-file authority of one native process tree.
pub struct NativeHostFiles {
    ipc: Arc<HostIpc>,
    stdio: NativeStdio,
    pty_table: Arc<parking_lot::Mutex<crate::vfs::PtyTable>>,
}

impl std::fmt::Debug for NativeHostFiles {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHostFiles")
            .finish_non_exhaustive()
    }
}

enum Served {
    Reply(i64, Vec<u8>),
    Refused,
}

fn outcome_result(outcome: DispatchOutcome) -> i64 {
    match outcome {
        DispatchOutcome::Returned { value } => value,
        DispatchOutcome::Errno { errno } => errno.guest_retval(),
        _ => carrick_abi::LINUX_EIO.guest_retval(),
    }
}

impl SyscallDispatcher {
    /// Capture the host-file authority native processes of this run use:
    /// the run's shared descriptor objects and its stdio route.
    pub fn native_host_files(&self) -> Result<NativeHostFiles, carrick_abi::LinuxErrno> {
        let ipc = self
            .kernel_binding
            .read()
            .kernel()
            .ipc()
            .map_err(|_| carrick_abi::LINUX_ENOMEM)?;
        Ok(NativeHostFiles {
            ipc,
            stdio: self.io.native_stdio(),
            pty_table: Arc::clone(&self.fs.pty_table),
        })
    }
}

impl NativeHostFiles {
    /// Serve one staged record in place. The descriptor is resolved and
    /// pinned in the caller's own ring table now, as Linux resolves it for
    /// an in-progress call.
    pub fn serve(&self, record: &mut [u8]) -> Result<(), NativeHostFileRefusal> {
        let view = HostFileRequestView::parse(record).map_err(|_| NativeHostFileRefusal)?;
        let header = view.header();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: header.table[0],
            index: header.table[1],
            generation: header.table[2],
        });
        let served = self
            .ipc
            .with_pinned_host_resource(table, fd::Fd(header.fd), |resource| {
                self.serve_resource(header.op, resource, view.input())
            });
        let (result, output) = match served {
            Ok(Served::Reply(result, output)) => (result, output),
            Ok(Served::Refused) => return Err(NativeHostFileRefusal),
            // Closed after the ring staged the call: the descriptor is gone.
            Err(PinnedHostResourceError::BadFd) => {
                (carrick_abi::LINUX_EBADF.guest_retval(), Vec::new())
            }
            // Replaced by an in-zone object, or contended: never guess.
            Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) => {
                return Err(NativeHostFileRefusal);
            }
        };
        view.reply(result, &output)
            .map_err(|_| NativeHostFileRefusal)
    }

    fn serve_resource(&self, op: HostFileOp, resource: &HostResource, input: &[u8]) -> Served {
        let Some(stdio) = resource.downcast_ref::<ImplicitHostStdio>() else {
            return Served::Refused;
        };
        let fd = stdio.fd.0;
        match op {
            HostFileOp::Write => match fd {
                1 | 2 => Served::Reply(outcome_result(self.stdio.write(fd, input)), Vec::new()),
                // Writing the run's stdin stream is not served yet.
                _ => Served::Refused,
            },
            HostFileOp::Fstat => {
                let record = super::fs::implicit_stdio_stat_record(&self.pty_table, fd);
                Served::Reply(
                    0,
                    super::format_stat::linux_stat(&record).as_bytes().to_vec(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ids::ObjectIdRegistry;
    use crate::kernel::{FileDescription, FileSlotNumber, FileTable};
    use carrick_core_abi::host_file::{self, HostFileHeader};
    use carrick_el1_abi::ipc_tables::IpcTableMap;

    fn map() -> &'static IpcTableMap {
        // SAFETY: zero-initialized atomics, alive for the test process, used
        // only through their synchronized API.
        unsafe {
            &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<IpcTableMap>())
                .cast::<IpcTableMap>()
        }
    }

    struct Fixture {
        files: NativeHostFiles,
        io: super::super::fs::state::RuntimeIo,
        table: [u64; 3],
        _owner_table: Arc<FileTable>,
    }

    /// A published root namespace: implicit stdio plus a regular host file
    /// at fd 3, as a native fork child inherits it.
    fn fixture() -> Fixture {
        let ids = ObjectIdRegistry::new();
        let ipc = Arc::new(HostIpc::new(1 << 20).unwrap());
        let map = map();
        let table = Arc::new(FileTable::new(ids.file_table_id().unwrap()));
        let regular = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        regular.retain_fd_ref();
        table.install(FileSlotNumber::for_open_fd(3).unwrap(), regular, false);
        table.publish_ipc(Arc::clone(&ipc), map).unwrap();
        let raw = map.lookup(table.id().raw()).unwrap();
        let io = super::super::fs::state::RuntimeIo::new();
        Fixture {
            files: NativeHostFiles {
                ipc,
                stdio: io.native_stdio(),
                pty_table: Arc::new(parking_lot::Mutex::new(crate::vfs::PtyTable::new())),
            },
            io,
            table: [raw.authority, raw.index, raw.generation],
            _owner_table: table,
        }
    }

    fn record(table: [u64; 3], op: HostFileOp, fd: i32, input: &[u8], output: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; host_file::record_len(input.len(), output).unwrap()];
        host_file::encode(
            &mut bytes,
            HostFileHeader {
                op,
                table,
                fd,
                flags: 0,
                args: [0; 4],
            },
            input,
            output,
        )
        .unwrap();
        bytes
    }

    #[test]
    fn native_stdout_write_reaches_the_runs_stdio_route() {
        let fixture = fixture();
        let mut bytes = record(fixture.table, HostFileOp::Write, 1, b"bin\nboot\n", 0);
        fixture.files.serve(&mut bytes).unwrap();
        let reply = host_file::reply(&bytes).unwrap();
        assert_eq!(reply.result, 9);
        assert_eq!(&*fixture.io.stdout.lock(), b"bin\nboot\n");
        assert!(fixture.io.stderr.lock().is_empty());
    }

    #[test]
    fn native_stdio_fstat_is_the_dispatchers_implicit_stdio_record() {
        let fixture = fixture();
        let mut bytes = record(
            fixture.table,
            HostFileOp::Fstat,
            2,
            &[],
            carrick_personality_linux::native_host_file::LINUX_STAT_BYTES,
        );
        fixture.files.serve(&mut bytes).unwrap();
        let reply = host_file::reply(&bytes).unwrap();
        assert_eq!(reply.result, 0);
        let expected = super::super::format_stat::linux_stat(
            &super::super::fs::implicit_stdio_stat_record(&fixture.files.pty_table, 2),
        );
        assert_eq!(reply.output, expected.as_bytes());
    }

    #[test]
    fn closed_descriptor_replies_ebadf_and_unserved_resources_refuse() {
        let fixture = fixture();
        let mut closed = record(fixture.table, HostFileOp::Write, 9, b"x", 0);
        fixture.files.serve(&mut closed).unwrap();
        assert_eq!(
            host_file::reply(&closed).unwrap().result,
            carrick_abi::LINUX_EBADF.guest_retval()
        );
        // A regular host file is a later slice: refused exactly, no reply.
        let mut regular = record(fixture.table, HostFileOp::Write, 3, b"x", 0);
        assert_eq!(
            fixture.files.serve(&mut regular),
            Err(NativeHostFileRefusal)
        );
        assert_eq!(host_file::reply(&regular), None);
        // The run's stdin stream is not written through this venue yet.
        let mut stdin = record(fixture.table, HostFileOp::Write, 0, b"x", 0);
        assert_eq!(fixture.files.serve(&mut stdin), Err(NativeHostFileRefusal));
        assert!(fixture.io.stdout.lock().is_empty());
    }
}
