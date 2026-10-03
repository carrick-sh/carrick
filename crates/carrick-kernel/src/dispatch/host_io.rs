//! Injectable external host operations. Implementations must not access guest
//! memory. Dispatch with an authenticated host-wait context releases MM
//! admission and CPU ownership first; off-executor callers run inline.

use carrick_abi::LinuxErrno;
use carrick_vfs::errno::HostSyscallResult;
use std::os::fd::{AsRawFd, BorrowedFd};

/// Host filesystem durability operations, shared across guest fork. This
/// replaces the actual host call rather than observing a test-only event.
pub trait HostIo: Send + Sync {
    fn sync(&self);
    fn flush(&self, fd: BorrowedFd<'_>) -> Result<(), LinuxErrno>;
    /// Stage owned regular-file bytes without changing its shared cursor.
    /// The caller releases execution capacity before entering this method.
    fn read_at(
        &self,
        fd: BorrowedFd<'_>,
        offset: HostFileOffset,
        limit: HostReadLimit,
    ) -> Result<Vec<u8>, LinuxErrno> {
        let mut bytes = vec![0; limit.get()];
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                offset.get(),
            )
        }
        .host_syscall_errno()?;
        bytes.truncate(count as usize);
        Ok(bytes)
    }
}

/// Nonnegative position in a regular host file, distinct from guest addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostFileOffset(i64);
impl HostFileOffset {
    pub fn new(offset: i64) -> Option<Self> {
        (offset >= 0).then_some(Self(offset))
    }
    pub fn get(self) -> i64 {
        self.0
    }
    pub fn checked_advance(self, count: usize) -> Option<Self> {
        self.0
            .checked_add(i64::try_from(count).ok()?)
            .and_then(Self::new)
    }
}

/// One bounded regular-file transfer chunk. Large vectors stage successive
/// chunks so a destination fault commits exactly the delivered prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReadLimit(usize);
impl HostReadLimit {
    pub const MAX: usize = carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize;
    pub fn new(len: usize) -> Option<Self> {
        (len != 0 && len <= Self::MAX).then_some(Self(len))
    }
    pub fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct SystemHostIo;

impl HostIo for SystemHostIo {
    fn sync(&self) {
        unsafe {
            libc::sync();
        }
    }

    fn flush(&self, fd: BorrowedFd<'_>) -> Result<(), LinuxErrno> {
        unsafe { libc::fsync(fd.as_raw_fd()) }.host_syscall_errno()?;
        #[cfg(target_os = "macos")]
        if std::env::var_os("CARRICK_STRICT_DURABILITY").is_some_and(|value| value != "0") {
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_FULLFSYNC) }.host_syscall_errno()?;
        }
        Ok(())
    }
}

/// Inactive staging prerequisite: production dispatch does not call this yet.
/// Owned recall/capacity lowering, exact resource-lifetime admission and all
/// competing current-offset callers must be integrated before activation.
/// No guest address or memory permit is stored in this owned staging state.
#[derive(Debug)]
pub struct OwnedHostFileCursor {
    reservation: crate::kernel::objects::FileCursorReservation,
    fd: super::fd_table::HostFdRef,
    offset: HostFileOffset,
}
impl OwnedHostFileCursor {
    pub fn recall_and_capture(
        reservation: crate::kernel::objects::FileCursorReservation,
    ) -> Result<Self, LinuxErrno> {
        let description = reservation.description();
        crate::el1_delegation::recall(description)?;
        let fd = {
            let open = description.inspect().ok_or(carrick_abi::LINUX_EBADF)?;
            match &*open {
                super::OpenDescription::HostFile {
                    host_fd, metadata, ..
                } if metadata.kind == carrick_vfs::rootfs::RootFsEntryKind::File => host_fd.clone(),
                _ => return Err(carrick_abi::LINUX_EINVAL),
            }
        };
        let raw_offset =
            unsafe { libc::lseek(fd.raw(), 0, libc::SEEK_CUR) }.host_syscall_errno()?;
        let offset = HostFileOffset::new(raw_offset).ok_or(carrick_abi::LINUX_EINVAL)?;
        Ok(Self {
            reservation,
            fd,
            offset,
        })
    }
    pub fn offset(&self) -> HostFileOffset {
        self.offset
    }
    pub fn stage_read(
        self,
        io: &dyn HostIo,
        limit: HostReadLimit,
    ) -> Result<StagedFileRead, LinuxErrno> {
        use std::os::fd::AsFd;
        // Validate the largest possible offset before any guest delivery.
        self.offset
            .checked_advance(limit.get())
            .ok_or(carrick_abi::LINUX_EOVERFLOW)?;
        let bytes = io.read_at(self.fd.as_fd(), self.offset, limit)?;
        if bytes.len() > limit.get() {
            carrick_fatal::carrick_fatal!(
                "dispatch::file_cursor",
                "host read exceeded owned staging bound"
            );
        }
        Ok(StagedFileRead {
            cursor: self,
            bytes,
        })
    }
    fn advance(&mut self, copied: usize) {
        if copied == 0 {
            return;
        }
        let next = self.offset.checked_advance(copied).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "dispatch::file_cursor",
                "prepared cursor offset overflow"
            )
        });
        let actual = unsafe { libc::lseek(self.fd.raw(), next.get(), libc::SEEK_SET) };
        if actual != next.get() {
            // Bytes may already be delivered. Never report an ordinary EFAULT
            // or resume/replay that prefix after an impossible retained-fd loss.
            carrick_fatal::carrick_fatal!(
                "dispatch::file_cursor",
                "retained regular-file cursor failed exact offset commit"
            );
        }
        self.fd.record_absolute_offset(actual);
        self.offset = next;
    }
    pub fn description(&self) -> &std::sync::Arc<crate::kernel::FileDescription> {
        self.reservation.description()
    }
}

/// File bytes are staged without moving f_pos. PREPARE may therefore suspend
/// while this owned reservation and byte buffer remain in a continuation.
#[derive(Debug)]
pub struct StagedFileRead {
    cursor: OwnedHostFileCursor,
    bytes: Vec<u8>,
}
impl StagedFileRead {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Commit only bytes successfully delivered; zero leaves f_pos unchanged.
    /// Returns the cursor so a vectored read can retain its single operation
    /// authority across bounded chunks and preserve Linux shared-f_pos ordering.
    pub fn commit(mut self, copied: usize) -> OwnedHostFileCursor {
        if copied > self.bytes.len() {
            carrick_fatal::carrick_fatal!(
                "dispatch::file_cursor",
                "copy exceeded prepared file prefix"
            );
        }
        self.cursor.advance(copied);
        self.cursor
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use crate::dispatch::LinearMemory;
    use crate::dispatch::fd_table::{HostFdRef, OpenDescriptionBase, OpenFile};
    use crate::dispatch::{
        DispatchOutcome, OpenDescription, SyscallArgs, SyscallDispatcher, SyscallRequest,
    };
    use carrick_guest_mem::GuestMemory;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::sync::Arc;
    fn description(bytes: &[u8]) -> (Arc<crate::kernel::FileDescription>, i32) {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        let fd = file.into_raw_fd();
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);
        let description = super::super::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDWR),
                host_fd: HostFdRef::new(fd),
                metadata: carrick_vfs::rootfs::RootFsMetadata {
                    path: "/tmp/cursor-fixture".into(),
                    kind: carrick_vfs::rootfs::RootFsEntryKind::File,
                    mode: 0o600,
                    size: bytes.len(),
                },
                writable: true,
            })),
            carrick_abi::LINUX_O_RDWR,
        );
        (description, fd)
    }
    #[test]
    fn legacy_dispatch_file_fault_count_matches_shared_offset() {
        for available in [0, 4096] {
            let (description, fd) = description(&vec![0x73; 8192]);
            let mut dispatcher = SyscallDispatcher::new();
            let installed = dispatcher
                .install_fd_at_or_above(3, OpenFile::new(description.clone(), 0))
                .unwrap();
            let context = dispatcher.capture_one_task_context().unwrap();
            let mut memory = LinearMemory::new(0x4000, vec![0; available]);
            let result = dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(63, SyscallArgs([installed as u64, 0x4000, 8192, 0, 0, 0])),
                    &mut memory,
                    &crate::compat::CompatReporter::default(),
                )
                .unwrap();
            let expected = if available == 0 {
                DispatchOutcome::errno(carrick_abi::LINUX_EFAULT)
            } else {
                DispatchOutcome::Returned {
                    value: available as i64,
                }
            };
            assert_eq!(result, expected);
            assert_eq!(
                unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
                available as i64
            );
            if available > 0 {
                assert_eq!(
                    memory.read_bytes(0x4000, available).unwrap(),
                    vec![0x73; available]
                );
            }
        }
    }
    struct ObservedCopy {
        memory: LinearMemory,
        fd: i32,
        offsets: Vec<i64>,
    }
    impl GuestMemory for ObservedCopy {
        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.memory.read_bytes_raw(address, length)
        }
        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.offsets
                .push(unsafe { libc::lseek(self.fd, 0, libc::SEEK_CUR) });
            self.memory.write_bytes_raw(address, bytes)
        }
    }
    impl carrick_guest_mem::CurrentMmMemory for ObservedCopy {}
    #[test]
    fn file_cursor_is_unconsumed_during_guest_copy() {
        // Core-level successor to the legacy-dispatch red. Dispatch remains
        // on its old path until the separately reviewed consumer cutover.
        for available in [0, 4096] {
            let (description, fd) = description(&vec![0x73; 8192]);
            let mut cursor =
                OwnedHostFileCursor::recall_and_capture(description.try_reserve_cursor().unwrap())
                    .unwrap();
            let mut memory = ObservedCopy {
                memory: LinearMemory::new(0x4000, vec![0; available]),
                fd,
                offsets: Vec::new(),
            };
            let mut copied = 0;
            for _ in 0..2 {
                let staged = cursor
                    .stage_read(&SystemHostIo, HostReadLimit::new(4096).unwrap())
                    .unwrap();
                let len = staged.bytes().len();
                let result = memory.write_bytes(0x4000 + copied as u64, staged.bytes());
                assert_eq!(
                    *memory.offsets.last().unwrap(),
                    copied as i64,
                    "f_pos must equal only previously committed bytes during copy"
                );
                if result.is_err() {
                    cursor = staged.commit(0);
                    break;
                }
                copied += len;
                cursor = staged.commit(len);
            }
            assert_eq!(copied, available);
            assert_eq!(cursor.offset().get(), available as i64);
            assert_eq!(
                unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
                available as i64
            );
        }
    }

    #[test]
    fn staged_file_cursor_commits_only_copied_prefix_and_zero_cancels() {
        let (description, fd) = description(&vec![0x5a; 8192]);
        for copied in [0, 23, 4096] {
            let cursor =
                OwnedHostFileCursor::recall_and_capture(description.try_reserve_cursor().unwrap())
                    .unwrap();
            let start = cursor.offset().get();
            let staged = cursor
                .stage_read(&SystemHostIo, HostReadLimit::new(4096).unwrap())
                .unwrap();
            assert_eq!(staged.bytes().len(), 4096);
            assert_eq!(
                unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
                start,
                "staging cannot consume shared f_pos"
            );
            let cursor = staged.commit(copied);
            assert_eq!(cursor.offset().get(), start + copied as i64);
            assert_eq!(
                unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
                start + copied as i64
            );
        }
    }
    #[test]
    fn shared_description_staged_readers_deliver_file_exactly_once() {
        let bytes: Vec<_> = (0..8192).map(|i| (i / 4096) as u8 + 1).collect();
        let (description, fd) = description(&bytes);
        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let (commit_tx, commit_rx) = std::sync::mpsc::channel();
        let peer = description.clone();
        let first = std::thread::spawn(move || {
            let cursor =
                OwnedHostFileCursor::recall_and_capture(peer.try_reserve_cursor().unwrap())
                    .unwrap();
            let staged = cursor
                .stage_read(&SystemHostIo, HostReadLimit::new(4096).unwrap())
                .unwrap();
            let bytes = staged.bytes().to_vec();
            staged_tx.send(()).unwrap();
            commit_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            drop(staged.commit(bytes.len()));
            bytes
        });
        staged_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let wait = description.try_reserve_cursor().unwrap_err();
        let (wake_tx, wake_rx) = std::sync::mpsc::channel();
        let (subscription, ready) = wait.subscribe(move || {
            let _ = wake_tx.send(());
        });
        assert!(!ready);
        commit_tx.send(()).unwrap();
        wake_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        drop(subscription);
        let cursor =
            OwnedHostFileCursor::recall_and_capture(wait.take_reservation().unwrap()).unwrap();
        let staged = cursor
            .stage_read(&SystemHostIo, HostReadLimit::new(4096).unwrap())
            .unwrap();
        let mut actual = first.join().unwrap();
        actual.extend_from_slice(staged.bytes());
        drop(staged.commit(4096));
        assert_eq!(actual, bytes);
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 8192);
    }
}
