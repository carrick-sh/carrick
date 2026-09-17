//! Retained completion state for blocking open operations (such as named FIFOs).
//!
//! Owns the exact slot reservation, open flags, pathname, and peer coordination token.
//! A wake never re-dispatches from guest memory: it completes the retained open directly
//! or re-parks with its uncommitted reservation held continuously.

use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use carrick_abi::{LINUX_O_ACCMODE, LINUX_O_CLOEXEC, LINUX_O_RDWR, LINUX_O_WRONLY};

use super::fd_table::{HostFdRef, HostWriteKind};
use super::fs::host_inode_pipe_id;
use super::{
    DispatchOutcome, OpenDescription, OpenDescriptionBase, OpenFile, SyscallDispatcher,
    linux_fd_flags_from_open_flags,
};
use crate::kernel::objects::FileSlotReservation;

#[derive(Debug)]
pub enum BlockingOpenKind {
    FifoReader {
        id: (u64, u64),
        path: String,
        flags: u64,
        access_idx: u32,
        token: crate::dispatch::fifo_beacon::ParkedOpenerToken,
    },
    FifoWriter {
        id: (u64, u64),
        path: String,
        flags: u64,
        access_idx: u32,
        token: crate::dispatch::fifo_beacon::ParkedOpenerToken,
    },
}

#[derive(Debug)]
struct BlockingOpenInner {
    reservation: Option<FileSlotReservation>,
    kind: BlockingOpenKind,
}

#[derive(Clone, Debug)]
pub struct BlockingOpen {
    identity: Arc<()>,
    inner: Arc<Mutex<BlockingOpenInner>>,
    registration_fd: i32,
}

impl PartialEq for BlockingOpen {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl Eq for BlockingOpen {}

#[derive(Debug)]
pub enum BlockingOpenStep {
    Done(DispatchOutcome),
    Wait(BlockingOpen),
}

impl BlockingOpen {
    pub(crate) fn new_fifo_reader(
        reservation: FileSlotReservation,
        id: (u64, u64),
        path: String,
        flags: u64,
        access_idx: u32,
        token: crate::dispatch::fifo_beacon::ParkedOpenerToken,
        registration_fd: i32,
    ) -> Self {
        Self {
            identity: Arc::new(()),
            inner: Arc::new(Mutex::new(BlockingOpenInner {
                reservation: Some(reservation),
                kind: BlockingOpenKind::FifoReader {
                    id,
                    path,
                    flags,
                    access_idx,
                    token,
                },
            })),
            registration_fd,
        }
    }

    pub(crate) fn new_fifo_writer(
        reservation: FileSlotReservation,
        id: (u64, u64),
        path: String,
        flags: u64,
        access_idx: u32,
        token: crate::dispatch::fifo_beacon::ParkedOpenerToken,
        registration_fd: i32,
    ) -> Self {
        Self {
            identity: Arc::new(()),
            inner: Arc::new(Mutex::new(BlockingOpenInner {
                reservation: Some(reservation),
                kind: BlockingOpenKind::FifoWriter {
                    id,
                    path,
                    flags,
                    access_idx,
                    token,
                },
            })),
            registration_fd,
        }
    }

    pub(crate) fn registration_fd(&self) -> i32 {
        self.registration_fd
    }

    pub fn complete(&self, dispatcher: &SyscallDispatcher) -> BlockingOpenStep {
        let mut inner = self.inner.lock();
        let BlockingOpenInner {
            ref mut reservation,
            ref mut kind,
        } = *inner;
        match kind {
            BlockingOpenKind::FifoReader {
                id,
                path,
                flags,
                access_idx,
                token,
            } => {
                if !crate::dispatch::fifo_beacon::is_writer_present(*id) {
                    return BlockingOpenStep::Wait(self.clone());
                }
                let Some(host_fd) = token.take_reader_host_fd() else {
                    return BlockingOpenStep::Wait(self.clone());
                };
                crate::dispatch::fifo_beacon::register_open(host_fd, *access_idx);
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let description = OpenDescription::HostPipe {
                    pipe_id: host_inode_pipe_id(host_fd),
                    host_fd: HostFdRef::new(host_fd),
                    is_read_end: (*flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY,
                    base: OpenDescriptionBase::new(*flags & !LINUX_O_CLOEXEC)
                        .with_fs_identity(carrick_vfs::FsIdentity::Overlay),
                    pty: None,
                    bidirectional: (*flags & LINUX_O_ACCMODE) == LINUX_O_RDWR,
                    write_kind: HostWriteKind::PipeLike,
                    stdio_stream: None,
                };
                let status = *flags & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(description)),
                    status,
                    linux_fd_flags_from_open_flags(*flags),
                );
                let Some(res) = reservation.take() else {
                    return BlockingOpenStep::Wait(self.clone());
                };
                let table = Arc::clone(res.table());
                let Ok(fd) = dispatcher.install_reserved_fd(res, open_file) else {
                    return BlockingOpenStep::Done(DispatchOutcome::errno(
                        carrick_abi::LINUX_EBADF,
                    ));
                };
                table.record_fd_open_path(fd, path.clone());
                BlockingOpenStep::Done(DispatchOutcome::returned_i32(fd))
            }
            BlockingOpenKind::FifoWriter {
                path,
                flags,
                access_idx,
                ..
            } => {
                let host_fd_opt = dispatcher.open_fifo_nonblock(path, *access_idx);
                let Some(host_fd) = host_fd_opt else {
                    return BlockingOpenStep::Wait(self.clone());
                };
                crate::dispatch::fifo_beacon::register_open(host_fd, *access_idx);
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let description = OpenDescription::HostPipe {
                    pipe_id: host_inode_pipe_id(host_fd),
                    host_fd: HostFdRef::new(host_fd),
                    is_read_end: false,
                    base: OpenDescriptionBase::new(*flags & !LINUX_O_CLOEXEC)
                        .with_fs_identity(carrick_vfs::FsIdentity::Overlay),
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                    stdio_stream: None,
                };
                let status = *flags & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(description)),
                    status,
                    linux_fd_flags_from_open_flags(*flags),
                );
                let Some(res) = reservation.take() else {
                    return BlockingOpenStep::Wait(self.clone());
                };
                let table = Arc::clone(res.table());
                let Ok(fd) = dispatcher.install_reserved_fd(res, open_file) else {
                    return BlockingOpenStep::Done(DispatchOutcome::errno(
                        carrick_abi::LINUX_EBADF,
                    ));
                };
                table.record_fd_open_path(fd, path.clone());
                BlockingOpenStep::Done(DispatchOutcome::returned_i32(fd))
            }
        }
    }
}
