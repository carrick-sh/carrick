//! Zero-copy shared memory primitive between host application and guest container.
//!
//! [`SharedBuffer`] allocates a host-fd-backed, page-aligned shared memory object.
//! During `prepare`, it is surfaced at a VFS path (`/dev/carrick/shm/<name>`) through
//! a host-fd-backed [`crate::vfs::InMemoryFileVfs`] entry. The guest maps it with
//! `mmap(MAP_SHARED, fd)` through Carrick's `GlobalShared` lane, allowing both
//! host and guest to see and mutate the identical underlying physical pages with zero copies.
//!
//! Synchronization across the boundary is provided via [`SharedFutexLocation`] and the
//! carrier-wide shared futex table.

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use carrick_guest_mem::{HostVa, SharedFutexLocation};
use carrick_runtime::kernel::container::{Container, ContainerId, RunId};

/// Errors encountered during [`SharedBuffer`] or [`SharedBufferLease`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SharedBufferError {
    #[error("buffer length must be greater than zero")]
    ZeroLength,
    #[error("failed to allocate or resize host shared memory file: {0}")]
    Allocation(std::io::Error),
    #[error("failed to mmap host shared memory: {0}")]
    Mmap(std::io::Error),
    #[error("offset {offset} + length {len} exceeds buffer size {buffer_size}")]
    OutOfBounds {
        offset: usize,
        len: usize,
        buffer_size: usize,
    },
    #[error("futex word at offset {0} is not 4-byte aligned")]
    Misaligned(usize),
    #[error("container {container_id:?} (generation {generation}) has retired")]
    Retired {
        container_id: ContainerId,
        generation: u64,
    },
    #[error("lease container generation mismatch: expected {expected}, actual {actual}")]
    GenerationMismatch { expected: u64, actual: u64 },
    #[error("futex wait timed out")]
    TimedOut,
    #[error("futex wait was interrupted")]
    Interrupted,
    #[error("shared buffer {0:?} was not found")]
    NotFound(String),
}

/// A host-created, page-aligned shared memory buffer backed by a real host file descriptor.
#[derive(Clone, Debug)]
pub struct SharedBuffer {
    inner: Arc<SharedBufferInner>,
}

#[derive(Debug)]
struct SharedBufferInner {
    file: File,
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: SharedBufferInner owns a page-aligned host mapping of an anonymous file.
// The memory can be accessed concurrently across threads/processes via atomic/volatile operations.
unsafe impl Send for SharedBufferInner {}
unsafe impl Sync for SharedBufferInner {}

impl Drop for SharedBufferInner {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.len);
        }
    }
}

impl SharedBuffer {
    /// Allocate a new page-aligned shared memory buffer of at least `len` bytes.
    pub fn new(len: usize) -> Result<Self, SharedBufferError> {
        if len == 0 {
            return Err(SharedBufferError::ZeroLength);
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let aligned_len = (len + page_size - 1) & !(page_size - 1);

        let file = tempfile::tempfile().map_err(SharedBufferError::Allocation)?;
        file.set_len(aligned_len as u64)
            .map_err(SharedBufferError::Allocation)?;

        let fd = file.as_raw_fd();
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(SharedBufferError::Mmap(std::io::Error::last_os_error()));
        }
        let ptr = NonNull::new(ptr as *mut u8).ok_or_else(|| {
            SharedBufferError::Mmap(std::io::Error::from_raw_os_error(libc::ENOMEM))
        })?;
        Ok(Self {
            inner: Arc::new(SharedBufferInner {
                file,
                ptr,
                len: aligned_len,
            }),
        })
    }

    /// The length in bytes of the shared buffer (page-aligned).
    pub fn len(&self) -> usize {
        self.inner.len
    }

    /// Whether the shared buffer is empty (always false for a valid buffer).
    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
    }

    /// The underlying raw host file descriptor.
    pub fn host_fd(&self) -> RawFd {
        self.inner.file.as_raw_fd()
    }

    /// Raw pointer to the host mapping.
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.ptr.as_ptr()
    }

    /// Raw mutable pointer to the host mapping.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.inner.ptr.as_ptr()
    }

    /// Safe host-side slice view of the shared buffer.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.inner.ptr.as_ptr(), self.inner.len) }
    }

    /// Safe host-side mutable slice view of the shared buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.inner.ptr.as_ptr(), self.inner.len) }
    }

    /// Mint a lease scoped to a container and execution generation.
    pub fn lease(
        &self,
        run_id: RunId,
        container_id: ContainerId,
        generation: u64,
    ) -> SharedBufferLease {
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            run_id,
            container_id,
            generation,
            retired: Arc::new(AtomicBool::new(false)),
            current_generation: Arc::new(AtomicU64::new(generation)),
        }
    }

    /// Mint a lease bound to a live [`Container`] kernel object.
    pub fn lease_for_container(&self, container: &Arc<Container>) -> SharedBufferLease {
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            run_id: container.run_id().clone(),
            container_id: container.id(),
            generation: container.generation(),
            retired: container.retirement_token(),
            current_generation: Arc::new(AtomicU64::new(container.generation())),
        }
    }

    /// Mint a lease with explicit retirement witness and generation handles (for testing).
    pub fn lease_with_witness(
        &self,
        run_id: RunId,
        container_id: ContainerId,
        generation: u64,
        retired: Arc<AtomicBool>,
        current_generation: Arc<AtomicU64>,
    ) -> SharedBufferLease {
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            run_id,
            container_id,
            generation,
            retired,
            current_generation,
        }
    }
}

/// An authenticated, generation-stamped capability lease for a [`SharedBuffer`].
///
/// The lease carries the exact container identity (`RunId`, `ContainerId`) and
/// execution `generation`. Access to the buffer through this lease is authenticated:
/// if the container has retired or the generation has drifted, access is refused
/// and fails closed. Dropping the lease after container retirement also safely fails closed.
#[derive(Clone, Debug)]
pub struct SharedBufferLease {
    inner: Arc<SharedBufferInner>,
    run_id: RunId,
    container_id: ContainerId,
    generation: u64,
    retired: Arc<AtomicBool>,
    current_generation: Arc<AtomicU64>,
}

impl SharedBufferLease {
    /// The run id this lease was minted for.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// The container id this lease was minted for.
    pub fn container_id(&self) -> ContainerId {
        self.container_id
    }

    /// The stamped container generation this lease belongs to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The byte length of the leased shared buffer.
    pub fn len(&self) -> usize {
        self.inner.len
    }

    /// Whether the leased buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
    }

    /// Whether the owning container has retired.
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// The current generation reported by the container authority.
    pub fn current_container_generation(&self) -> u64 {
        self.current_generation.load(Ordering::Acquire)
    }

    /// Raw pointer to the host mapping.
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.ptr.as_ptr()
    }

    /// Raw mutable pointer to the host mapping.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.inner.ptr.as_ptr()
    }

    /// Validate that the lease is still live and generation-coherent. Fails closed if retired.
    pub fn validate_access(&self) -> Result<(), SharedBufferError> {
        if self.is_retired() {
            return Err(SharedBufferError::Retired {
                container_id: self.container_id,
                generation: self.generation,
            });
        }
        let cur_gen = self.current_container_generation();
        if cur_gen != self.generation {
            return Err(SharedBufferError::GenerationMismatch {
                expected: self.generation,
                actual: cur_gen,
            });
        }
        Ok(())
    }

    /// Safe slice access to the shared buffer, authenticated against container retirement.
    pub fn as_slice(&self) -> Result<&[u8], SharedBufferError> {
        self.validate_access()?;
        Ok(unsafe { std::slice::from_raw_parts(self.inner.ptr.as_ptr(), self.inner.len) })
    }

    /// Safe mutable slice access to the shared buffer, authenticated against container retirement.
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8], SharedBufferError> {
        self.validate_access()?;
        Ok(unsafe { std::slice::from_raw_parts_mut(self.inner.ptr.as_ptr(), self.inner.len) })
    }

    /// Read bytes from the shared buffer at `offset` into `buf`.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, SharedBufferError> {
        self.validate_access()?;
        if offset
            .checked_add(buf.len())
            .is_none_or(|end| end > self.inner.len)
        {
            return Err(SharedBufferError::OutOfBounds {
                offset,
                len: buf.len(),
                buffer_size: self.inner.len,
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.inner.ptr.as_ptr().add(offset),
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
        Ok(buf.len())
    }

    /// Write bytes into the shared buffer at `offset` from `data`.
    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<usize, SharedBufferError> {
        self.validate_access()?;
        if offset
            .checked_add(data.len())
            .is_none_or(|end| end > self.inner.len)
        {
            return Err(SharedBufferError::OutOfBounds {
                offset,
                len: data.len(),
                buffer_size: self.inner.len,
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.inner.ptr.as_ptr().add(offset),
                data.len(),
            );
        }
        Ok(data.len())
    }

    /// Derive the unified [`SharedFutexLocation`] for a 4-byte futex word at `offset`.
    pub fn shared_futex_location(
        &self,
        offset: usize,
    ) -> Result<SharedFutexLocation, SharedBufferError> {
        self.validate_access()?;
        if offset.checked_add(4).is_none_or(|end| end > self.inner.len) {
            return Err(SharedBufferError::OutOfBounds {
                offset,
                len: 4,
                buffer_size: self.inner.len,
            });
        }
        if !offset.is_multiple_of(4) {
            return Err(SharedBufferError::Misaligned(offset));
        }
        let word = HostVa(unsafe { self.inner.ptr.as_ptr().add(offset) } as usize);
        let base = carrick_host::futex_key::shared_file_key_base(self.inner.file.as_raw_fd());
        let waiter_key = carrick_host::futex_key::shared_futex_waiter_key(base, offset as u64);
        Ok(SharedFutexLocation::Direct { word, waiter_key })
    }

    /// Wait on the futex word at `offset` while its value equals `expected`.
    pub fn futex_wait(
        &self,
        offset: usize,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<(), SharedBufferError> {
        let location = self.shared_futex_location(offset)?;
        let word_ptr = location.wait_addr().raw() as *const AtomicU32;
        let table = carrick_thread::platform_futex::carrier_shared_futex_table();
        let tid = carrick_hal::ThreadId::main_from_host_pid();

        let outcome = unsafe {
            table.wait_while_word_equals(
                location.waiter_key() as u64,
                word_ptr,
                expected,
                timeout,
                tid,
                &|| false,
            )
        };
        match outcome {
            carrick_thread::thread::FutexWaitOutcome::Woken => Ok(()),
            carrick_thread::thread::FutexWaitOutcome::TimedOut => Err(SharedBufferError::TimedOut),
            carrick_thread::thread::FutexWaitOutcome::Interrupted => {
                Err(SharedBufferError::Interrupted)
            }
        }
    }

    /// Wake up to `count` waiters parked on the futex word at `offset`.
    pub fn futex_wake(&self, offset: usize, count: u32) -> Result<u32, SharedBufferError> {
        let location = self.shared_futex_location(offset)?;
        let table = carrick_thread::platform_futex::carrier_shared_futex_table();
        let woken = table.wake(location.waiter_key() as u64, count);
        Ok(woken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn test_shared_buffer_creation_and_bounds() {
        assert!(matches!(
            SharedBuffer::new(0),
            Err(SharedBufferError::ZeroLength)
        ));

        let mut buf = SharedBuffer::new(1024).expect("allocate shared buffer");
        assert!(buf.len() >= 1024);
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(buf.len() % page_size, 0);

        let data = b"hello shared world";
        buf.as_mut_slice()[..data.len()].copy_from_slice(data);
        assert_eq!(&buf.as_slice()[..data.len()], data);

        let mut read_back = vec![0u8; data.len()];
        let run_id = RunId::new("test-run");
        let container_id = ContainerId::allocate();
        let lease = buf.lease(run_id, container_id, 1);

        assert_eq!(lease.read_at(0, &mut read_back).unwrap(), data.len());
        assert_eq!(&read_back, data);

        // Out of bounds checks
        let mut out_buf = vec![0u8; 10];
        assert!(matches!(
            lease.read_at(buf.len() - 5, &mut out_buf),
            Err(SharedBufferError::OutOfBounds { .. })
        ));
        assert!(matches!(
            lease.write_at(buf.len() - 5, &out_buf),
            Err(SharedBufferError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn test_shared_buffer_lease_lifecycle_and_fail_closed_retirement() {
        let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
        let run_id = RunId::new("lifecycle-run");
        let container_id = ContainerId::allocate();
        let retired = Arc::new(AtomicBool::new(false));
        let cur_gen = Arc::new(AtomicU64::new(1));

        let mut lease = buf.lease_with_witness(
            run_id.clone(),
            container_id,
            1,
            Arc::clone(&retired),
            Arc::clone(&cur_gen),
        );

        // Initial access succeeds
        assert!(lease.validate_access().is_ok());
        lease.write_at(0, b"data-generation-1").unwrap();
        let mut check = [0u8; 17];
        lease.read_at(0, &mut check).unwrap();
        assert_eq!(&check, b"data-generation-1");

        // 1. Generation drift / mismatch fails closed
        cur_gen.store(2, Ordering::Release);
        assert!(matches!(
            lease.validate_access(),
            Err(SharedBufferError::GenerationMismatch {
                expected: 1,
                actual: 2
            })
        ));
        assert!(matches!(
            lease.as_slice(),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.as_mut_slice(),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.read_at(0, &mut check),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.write_at(0, b"unauthorized"),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));

        // Restore generation
        cur_gen.store(1, Ordering::Release);
        assert!(lease.validate_access().is_ok());

        // 2. Container retirement fails closed
        retired.store(true, Ordering::Release);
        assert!(lease.is_retired());
        assert!(matches!(
            lease.validate_access(),
            Err(SharedBufferError::Retired {
                container_id: cid,
                generation: 1
            }) if cid == container_id
        ));
        assert!(matches!(
            lease.as_slice(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.as_mut_slice(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.read_at(0, &mut check),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.write_at(0, b"unauthorized"),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.shared_futex_location(0),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.futex_wait(0, 0, None),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.futex_wake(0, 1),
            Err(SharedBufferError::Retired { .. })
        ));

        // 3. Dropping the retired lease succeeds cleanly without panics or leaks
        drop(lease);
    }

    #[test]
    fn test_shared_futex_wait_and_wake() {
        let buf = SharedBuffer::new(4096).expect("allocate buffer");
        let run_id = RunId::new("futex-run");
        let container_id = ContainerId::allocate();
        let lease = buf.lease(run_id, container_id, 1);

        // Word alignment checks
        assert!(lease.shared_futex_location(0).is_ok());
        assert!(lease.shared_futex_location(4).is_ok());
        assert!(matches!(
            lease.shared_futex_location(1),
            Err(SharedBufferError::Misaligned(1))
        ));
        assert!(matches!(
            lease.shared_futex_location(2),
            Err(SharedBufferError::Misaligned(2))
        ));
        assert!(matches!(
            lease.shared_futex_location(3),
            Err(SharedBufferError::Misaligned(3))
        ));

        // Initialize futex word at offset 0 to 0
        lease.write_at(0, &0u32.to_ne_bytes()).unwrap();

        let lease_clone = lease.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            // Simulate guest updating futex word and waking host
            let word_ptr = lease_clone.as_ptr() as *mut AtomicU32;
            unsafe {
                (*word_ptr).store(42, Ordering::Release);
            }
            let woken = lease_clone.futex_wake(0, 1).expect("futex wake");
            assert_eq!(woken, 1);
        });

        // Host waits for futex word at offset 0 while it equals 0
        let wait_res = lease.futex_wait(0, 0, Some(Duration::from_secs(2)));
        assert!(wait_res.is_ok());
        handle.join().expect("thread join");

        // Timeout test: wait for value 42 (which it is) with small timeout
        let to_res = lease.futex_wait(0, 42, Some(Duration::from_millis(10)));
        assert!(matches!(to_res, Err(SharedBufferError::TimedOut)));
    }

    #[test]
    fn test_two_containers_buffer_isolation() {
        let buf_a = SharedBuffer::new(4096).expect("buffer a");
        let buf_b = SharedBuffer::new(4096).expect("buffer b");

        let run_a = RunId::new("run-a");
        let run_b = RunId::new("run-b");
        let cid_a = ContainerId::allocate();
        let cid_b = ContainerId::allocate();
        assert_ne!(cid_a, cid_b);

        let lease_a = buf_a.lease(run_a, cid_a, 1);
        let lease_b = buf_b.lease(run_b, cid_b, 1);

        lease_a.write_at(0, &[0xAA; 32]).unwrap();
        lease_b.write_at(0, &[0xBB; 32]).unwrap();

        let mut read_a = [0u8; 32];
        let mut read_b = [0u8; 32];
        lease_a.read_at(0, &mut read_a).unwrap();
        lease_b.read_at(0, &mut read_b).unwrap();

        assert_eq!(read_a, [0xAA; 32]);
        assert_eq!(read_b, [0xBB; 32]);
    }

    #[test]
    fn test_in_memory_vfs_host_file_mounting() {
        use crate::vfs::Vfs;
        let vfs = crate::vfs::InMemoryFileVfs::new();
        let mut buf = SharedBuffer::new(4096).expect("buffer");
        buf.as_mut_slice()[..5].copy_from_slice(b"shbuf");

        vfs.add_host_file("/test_buf", buf.host_fd(), 4096)
            .expect("add host file");

        let bytes = vfs.read_file_bytes("/test_buf").expect("read bytes");
        assert_eq!(&bytes[..5], b"shbuf");

        let handle = vfs
            .open(
                "/test_buf",
                crate::vfs::OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
                &crate::vfs::OpenContext::default(),
            )
            .expect("open vfs handle");

        assert!(matches!(handle, crate::vfs::VfsHandle::HostFd { .. }));
    }
}
