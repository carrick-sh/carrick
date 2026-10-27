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
use carrick_core_abi::host_file::{HostFileOp, HostFileRequestView};
use carrick_el1_abi::ipc::fd;
use zerocopy::IntoBytes;

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
    /// Serve one ring-staged host-file record in place for a native process
    /// of this run. The descriptor is resolved and pinned in the caller's own
    /// ring table now, as Linux resolves it for an in-progress call. No host
    /// task, fd table or credential of this dispatcher's task is consulted.
    pub fn serve_native_host_file(&self, record: &mut [u8]) -> Result<(), NativeHostFileRefusal> {
        let Some(owner) = self.kernel_binding.read().kernel().existing_ipc() else {
            return Err(NativeHostFileRefusal);
        };
        self.serve_native_host_file_in(&owner, record)
    }

    fn serve_native_host_file_in(
        &self,
        owner: &HostIpc,
        record: &mut [u8],
    ) -> Result<(), NativeHostFileRefusal> {
        let view = HostFileRequestView::parse(record).map_err(|_| NativeHostFileRefusal)?;
        let header = view.header();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: header.table[0],
            index: header.table[1],
            generation: header.table[2],
        });
        let served = owner.with_pinned_host_resource(table, fd::Fd(header.fd), |resource| {
            self.serve_native_resource(header.op, resource, view.input())
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

    fn serve_native_resource(
        &self,
        op: HostFileOp,
        resource: &HostResource,
        input: &[u8],
    ) -> Served {
        let Some(stdio) = resource.downcast_ref::<ImplicitHostStdio>() else {
            return Served::Refused;
        };
        let fd = stdio.fd.0;
        match op {
            // The run's own stdio route: the code the root's implicit stdio
            // write runs.
            HostFileOp::Write => match fd {
                1 | 2 => Served::Reply(
                    outcome_result(self.fs_view().write_stdio_sink(fd, input)),
                    Vec::new(),
                ),
                // Writing the run's stdin stream is not served yet.
                _ => Served::Refused,
            },
            HostFileOp::Fstat => {
                let record = super::fs::implicit_stdio_stat_record(&self.fs.pty_table, fd);
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
    use crate::kernel::{FileDescription, FileSlotNumber};
    use carrick_core_abi::host_file::{self, HostFileHeader};
    use carrick_el1_abi::ipc_tables::IpcTableMap;
    use std::sync::Arc;

    fn map() -> &'static IpcTableMap {
        // SAFETY: zero-initialized atomics, alive for the test process, used
        // only through their synchronized API.
        unsafe {
            &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<IpcTableMap>())
                .cast::<IpcTableMap>()
        }
    }

    struct Fixture {
        dispatcher: SyscallDispatcher,
        owner: Arc<HostIpc>,
        table: [u64; 3],
    }

    /// The root's published namespace (implicit stdio plus a regular host
    /// file at fd 3), as a native fork child inherits it.
    fn fixture() -> Fixture {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let files = context.resources().files();
        let ids = ObjectIdRegistry::new();
        let regular = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        regular.retain_fd_ref();
        files.install(FileSlotNumber::for_open_fd(3).unwrap(), regular, false);
        let map = map();
        files.publish_ipc(Arc::clone(&owner), map).unwrap();
        let raw = map.lookup(files.id().raw()).unwrap();
        Fixture {
            dispatcher,
            owner,
            table: [raw.authority, raw.index, raw.generation],
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
        fixture
            .dispatcher
            .serve_native_host_file_in(&fixture.owner, &mut bytes)
            .unwrap();
        assert_eq!(host_file::reply(&bytes).unwrap().result, 9);
        assert_eq!(fixture.dispatcher.stdout(), b"bin\nboot\n");
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
        fixture
            .dispatcher
            .serve_native_host_file_in(&fixture.owner, &mut bytes)
            .unwrap();
        let reply = host_file::reply(&bytes).unwrap();
        assert_eq!(reply.result, 0);
        let expected = super::super::format_stat::linux_stat(
            &super::super::fs::implicit_stdio_stat_record(&fixture.dispatcher.fs.pty_table, 2),
        );
        assert_eq!(reply.output, expected.as_bytes());
    }

    #[test]
    fn closed_descriptor_replies_ebadf_and_unserved_resources_refuse() {
        let fixture = fixture();
        let serve = |bytes: &mut Vec<u8>| {
            fixture
                .dispatcher
                .serve_native_host_file_in(&fixture.owner, bytes)
        };
        let mut closed = record(fixture.table, HostFileOp::Write, 9, b"x", 0);
        serve(&mut closed).unwrap();
        assert_eq!(
            host_file::reply(&closed).unwrap().result,
            carrick_abi::LINUX_EBADF.guest_retval()
        );
        // A regular host file is a later slice: refused exactly, no reply.
        let mut regular = record(fixture.table, HostFileOp::Write, 3, b"x", 0);
        assert_eq!(serve(&mut regular), Err(NativeHostFileRefusal));
        assert_eq!(host_file::reply(&regular), None);
        // The run's stdin stream is not written through this venue yet.
        let mut stdin = record(fixture.table, HostFileOp::Write, 0, b"x", 0);
        assert_eq!(serve(&mut stdin), Err(NativeHostFileRefusal));
        assert!(fixture.dispatcher.stdout().is_empty());
    }
}
