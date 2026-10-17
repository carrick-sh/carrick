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
use carrick_kernel::kernel::container::{ContainerId, RunId};

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
///
/// One [`SharedBuffer`] is bound to at most one [`crate::PreparedContainer`] at
/// a time; preparing a new container with the same buffer advances its binding
/// generation and invalidates leases minted for earlier bindings.
///
/// Byte-range copies ([`Self::read_into`], [`Self::write_from`]) use `Relaxed`
/// 32-bit atomic word operations, so callers must publish and observe payload
/// updates through [`SharedAtomicU32`] `Release`/`Acquire` operations (or futex
/// synchronization).
///
/// Removal note: `as_slice`, `as_mut_slice`, and `AsRef<[u8]>` are intentionally
/// absent because clones share the same `MAP_SHARED` mapping:
/// ```compile_fail
/// use carrick_embed::SharedBuffer;
/// let buf = SharedBuffer::new(4096).unwrap();
/// let slice: &[u8] = buf.as_ref();
/// ```
#[derive(Clone, Debug)]
pub struct SharedBuffer {
    inner: Arc<SharedBufferInner>,
}

#[derive(Debug)]
struct SharedBufferInner {
    file: File,
    ptr: NonNull<u8>,
    len: usize,
    generation: Arc<AtomicU64>,
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

impl SharedBufferInner {
    fn check_range(&self, offset: usize, len: usize) -> Result<(), SharedBufferError> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(SharedBufferError::OutOfBounds {
                offset,
                len,
                buffer_size: self.len,
            });
        }
        Ok(())
    }

    fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<usize, SharedBufferError> {
        self.check_range(offset, buf.len())?;
        let mut copied = 0;
        while copied < buf.len() {
            let position = offset + copied;
            let word_offset = position & !3;
            let byte_in_word = position & 3;
            let count = (4 - byte_in_word).min(buf.len() - copied);
            let word = self
                .word_at(word_offset)
                .load(Ordering::Relaxed)
                .to_ne_bytes();
            buf[copied..copied + count].copy_from_slice(&word[byte_in_word..byte_in_word + count]);
            copied += count;
        }
        Ok(buf.len())
    }

    fn write_from(&self, offset: usize, data: &[u8]) -> Result<usize, SharedBufferError> {
        self.check_range(offset, data.len())?;
        let mut copied = 0;
        while copied < data.len() {
            let position = offset + copied;
            let word_offset = position & !3;
            let byte_in_word = position & 3;
            let count = (4 - byte_in_word).min(data.len() - copied);
            let word = self.word_at(word_offset);
            if byte_in_word == 0 && count == 4 {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(&data[copied..copied + 4]);
                word.store(u32::from_ne_bytes(bytes), Ordering::Relaxed);
            } else {
                let _ = word.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                    let mut bytes = old.to_ne_bytes();
                    bytes[byte_in_word..byte_in_word + count]
                        .copy_from_slice(&data[copied..copied + count]);
                    Some(u32::from_ne_bytes(bytes))
                });
            }
            copied += count;
        }
        Ok(data.len())
    }

    fn word_at(&self, aligned_offset: usize) -> &AtomicU32 {
        // SAFETY: callers checked their byte range; the buffer is page-sized,
        // so the containing word is mapped. The base and offset are aligned,
        // and every safe host access uses the same atomic width.
        unsafe { &*self.ptr.as_ptr().add(aligned_offset).cast::<AtomicU32>() }
    }

    fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn bind_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }
}

impl SharedBuffer {
    /// Allocate a new page-aligned shared memory buffer of at least `len` bytes.
    pub fn new(len: usize) -> Result<Self, SharedBufferError> {
        if len == 0 {
            return Err(SharedBufferError::ZeroLength);
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let aligned_len = len
            .checked_add(page_size - 1)
            .ok_or(SharedBufferError::Allocation(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )))?
            & !(page_size - 1);

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
                generation: Arc::new(AtomicU64::new(0)),
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

    /// Copy bytes from shared memory using `Relaxed` 32-bit atomic loads.
    ///
    /// Callers must synchronize with concurrent writers via [`SharedAtomicU32`]
    /// `Release`/`Acquire` operations or futex waits.
    pub fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<usize, SharedBufferError> {
        self.inner.read_into(offset, buf)
    }

    /// Copy bytes into shared memory using `Relaxed` 32-bit atomic writes.
    ///
    /// Callers must publish written bytes to concurrent readers via
    /// [`SharedAtomicU32`] `Release`/`Acquire` operations or futex wakes.
    pub fn write_from(&self, offset: usize, data: &[u8]) -> Result<usize, SharedBufferError> {
        self.inner.write_from(offset, data)
    }

    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn bind_generation(&self) -> u64 {
        self.inner.bind_generation()
    }

    /// Mint a lease scoped to a container and the buffer's current binding generation.
    pub fn lease(
        &self,
        run_id: RunId,
        container_id: ContainerId,
        shared_futex: carrick_thread::platform_futex::SharedFutexTable,
    ) -> SharedBufferLease {
        let generation = self.inner.current_generation();
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            shared_futex,
            run_id,
            container_id,
            generation,
            retired: Arc::new(AtomicBool::new(false)),
            current_generation: Arc::clone(&self.inner.generation),
        }
    }

    pub(crate) fn lease_for_prepared(
        &self,
        run_id: RunId,
        container_id: ContainerId,
        generation: u64,
        retired: Arc<AtomicBool>,
        shared_futex: carrick_thread::platform_futex::SharedFutexTable,
    ) -> SharedBufferLease {
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            shared_futex,
            run_id,
            container_id,
            generation,
            retired,
            current_generation: Arc::clone(&self.inner.generation),
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
        shared_futex: carrick_thread::platform_futex::SharedFutexTable,
    ) -> SharedBufferLease {
        SharedBufferLease {
            inner: Arc::clone(&self.inner),
            shared_futex,
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
    shared_futex: carrick_thread::platform_futex::SharedFutexTable,
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

    /// Raw pointer to the host mapping, after validating this lease.
    /// Dereferencing the pointer is unsafe; callers must synchronize guest
    /// access and revalidate after a lifecycle transition.
    pub fn as_ptr(&self) -> Result<*const u8, SharedBufferError> {
        self.validate_access()?;
        Ok(self.inner.ptr.as_ptr())
    }

    /// Raw mutable pointer to the host mapping, after validating this lease.
    /// Dereferencing the pointer is unsafe; callers must synchronize guest
    /// access and revalidate after a lifecycle transition.
    pub fn as_mut_ptr(&self) -> Result<*mut u8, SharedBufferError> {
        self.validate_access()?;
        Ok(self.inner.ptr.as_ptr())
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

    /// Read bytes into `buf` with `Relaxed` 32-bit atomic loads.
    ///
    /// Callers must synchronize with concurrent writers via [`SharedAtomicU32`]
    /// `Release`/`Acquire` operations or futex waits.
    pub fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<usize, SharedBufferError> {
        self.validate_access()?;
        self.inner.read_into(offset, buf)
    }

    /// Write bytes from `data` with `Relaxed` 32-bit atomic writes.
    ///
    /// Callers must publish written bytes to concurrent readers via
    /// [`SharedAtomicU32`] `Release`/`Acquire` operations or futex wakes.
    pub fn write_from(&self, offset: usize, data: &[u8]) -> Result<usize, SharedBufferError> {
        self.validate_access()?;
        self.inner.write_from(offset, data)
    }

    /// A generation-checked atomic 32-bit word in shared memory.
    pub fn atomic_u32(&self, offset: usize) -> Result<SharedAtomicU32, SharedBufferError> {
        self.shared_futex_location(offset)?;
        Ok(SharedAtomicU32 {
            lease: self.clone(),
            offset,
        })
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
        let location = if let Some(identity) =
            carrick_host::futex_key::shared_file_key_base(self.inner.file.as_raw_fd())
        {
            let offset = offset as u64;
            SharedFutexLocation::File {
                word,
                identity,
                offset,
                waiter_key: carrick_host::futex_key::shared_futex_waiter_key(identity, offset),
            }
        } else {
            SharedFutexLocation::Direct {
                word,
                waiter_key: word.raw(),
            }
        };
        Ok(location)
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
        let table = self.shared_futex.table();
        let tid = carrick_hal::ThreadId::main_from_host_pid();

        let outcome = unsafe {
            table.wait_while_word_equals(
                carrick_thread::platform_futex::carrier_shared_futex_key(location),
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
        let table = self.shared_futex.table();
        let woken = table.wake(
            carrick_thread::platform_futex::carrier_shared_futex_key(location),
            count,
        );
        Ok(woken)
    }
}

/// A checked atomic word view that revalidates its lease on every operation.
#[derive(Clone, Debug)]
pub struct SharedAtomicU32 {
    lease: SharedBufferLease,
    offset: usize,
}

impl SharedAtomicU32 {
    fn word(&self) -> Result<&AtomicU32, SharedBufferError> {
        self.lease.validate_access()?;
        Ok(self.lease.inner.word_at(self.offset))
    }

    pub fn load(&self, ordering: Ordering) -> Result<u32, SharedBufferError> {
        Ok(self.word()?.load(ordering))
    }

    pub fn store(&self, value: u32, ordering: Ordering) -> Result<(), SharedBufferError> {
        self.word()?.store(value, ordering);
        Ok(())
    }

    pub fn fetch_or(&self, value: u32, ordering: Ordering) -> Result<u32, SharedBufferError> {
        Ok(self.word()?.fetch_or(value, ordering))
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

        let buf = SharedBuffer::new(1024).expect("allocate shared buffer");
        assert!(buf.len() >= 1024);
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(buf.len() % page_size, 0);

        let data = b"hello shared world";
        buf.write_from(0, data).unwrap();
        let mut direct_read = vec![0; data.len()];
        buf.read_into(0, &mut direct_read).unwrap();
        assert_eq!(&direct_read, data);

        let mut read_back = vec![0u8; data.len()];
        let run_id = RunId::new("test-run");
        let container_id = ContainerId::allocate();
        let lease = buf.lease(
            run_id,
            container_id,
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );

        assert_eq!(lease.read_into(0, &mut read_back).unwrap(), data.len());
        assert_eq!(&read_back, data);

        // Out of bounds checks
        let mut out_buf = vec![0u8; 10];
        assert!(matches!(
            lease.read_into(buf.len() - 5, &mut out_buf),
            Err(SharedBufferError::OutOfBounds { .. })
        ));
        assert!(matches!(
            lease.write_from(buf.len() - 5, &out_buf),
            Err(SharedBufferError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn unaligned_copy_preserves_the_other_bytes_of_atomic_words() {
        let buf = SharedBuffer::new(8).unwrap();
        buf.write_from(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        buf.write_from(1, &[9, 10, 11, 12, 13]).unwrap();
        let mut result = [0; 8];
        buf.read_into(0, &mut result).unwrap();
        assert_eq!(result, [1, 9, 10, 11, 12, 13, 7, 8]);
    }

    #[test]
    fn concurrent_partial_write_from_and_atomic_u32_preserve_neighboring_bytes() {
        let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
        let lease = buf.lease(
            RunId::new("concurrent-word"),
            ContainerId::allocate(),
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );
        let word = lease.atomic_u32(0).expect("atomic word at 0");
        word.store(0, Ordering::Relaxed).unwrap();

        let writer_buf = buf.clone();
        let writer = thread::spawn(move || {
            for i in 0..500u16 {
                let b = (i & 0xFF) as u8;
                // Write only byte 1 of word 0 (preserving bytes 0, 2, 3).
                writer_buf.write_from(1, &[b]).unwrap();
            }
        });

        let atomic_worker = word.clone();
        let bit_setter = thread::spawn(move || {
            for i in 0..500u32 {
                let mask = if cfg!(target_endian = "little") {
                    ((i & 0x7F) << 24) | 0x01
                } else {
                    (i & 0x7F) | (0x01 << 24)
                };
                atomic_worker.fetch_or(mask, Ordering::AcqRel).unwrap();
            }
        });

        writer.join().expect("writer join");
        bit_setter.join().expect("bit_setter join");

        // Final write of known value into byte 1, and known bit into byte 3 / byte 0.
        buf.write_from(1, &[0x5A]).unwrap();
        let final_mask = u32::from_ne_bytes([0x01, 0x00, 0x00, 0x80]);
        word.fetch_or(final_mask, Ordering::AcqRel).unwrap();

        let mut bytes = [0u8; 4];
        buf.read_into(0, &mut bytes).unwrap();
        assert_eq!(bytes[1], 0x5A, "partial write_from byte must be preserved");
        assert_eq!(bytes[2], 0x00, "untouched byte 2 must remain zero");
        assert_ne!(
            bytes[0] & 0x01,
            0,
            "atomic_u32 bit in byte 0 must be preserved"
        );
        assert_ne!(
            bytes[3] & 0x80,
            0,
            "atomic_u32 bit in byte 3 must be preserved"
        );
    }

    #[test]
    fn test_shared_buffer_lease_lifecycle_and_fail_closed_retirement() {
        let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
        let run_id = RunId::new("lifecycle-run");
        let container_id = ContainerId::allocate();
        let retired = Arc::new(AtomicBool::new(false));
        let cur_gen = Arc::new(AtomicU64::new(1));

        let lease = buf.lease_with_witness(
            run_id.clone(),
            container_id,
            1,
            Arc::clone(&retired),
            Arc::clone(&cur_gen),
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );

        // Initial access succeeds
        assert!(lease.validate_access().is_ok());
        lease.write_from(0, b"data-generation-1").unwrap();
        let word = lease.atomic_u32(0).unwrap();
        let mut check = [0u8; 17];
        lease.read_into(0, &mut check).unwrap();
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
            lease.read_into(0, &mut check),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.write_from(0, b"no"),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.read_into(0, &mut check),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            lease.write_from(0, b"unauthorized"),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            word.load(Ordering::Acquire),
            Err(SharedBufferError::GenerationMismatch { .. })
        ));

        // Restore generation
        cur_gen.store(1, Ordering::Release);
        assert!(lease.validate_access().is_ok());

        // 2. Container retirement fails closed
        retired.store(true, Ordering::Release);
        assert!(lease.is_retired());
        assert!(matches!(
            lease.as_ptr(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.as_mut_ptr(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.validate_access(),
            Err(SharedBufferError::Retired {
                container_id: cid,
                generation: 1
            }) if cid == container_id
        ));
        assert!(matches!(
            lease.as_ptr(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.as_mut_ptr(),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.read_into(0, &mut check),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            lease.write_from(0, b"unauthorized"),
            Err(SharedBufferError::Retired { .. })
        ));
        assert!(matches!(
            word.load(Ordering::Acquire),
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
    fn minting_leases_observes_generation_and_only_binding_advances_it() {
        let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
        let futex = carrick_thread::platform_futex::SharedFutexTable::new();
        let first_gen = buf.bind_generation();
        assert_eq!(first_gen, 1);

        let lease_a = buf.lease(RunId::new("first"), ContainerId::allocate(), futex.clone());
        let lease_b = buf.lease(RunId::new("second"), ContainerId::allocate(), futex.clone());
        assert_eq!(lease_a.generation(), 1);
        assert_eq!(lease_b.generation(), 1);
        assert!(lease_a.validate_access().is_ok());
        assert!(lease_b.validate_access().is_ok());

        // A new container binding advances the generation and invalidates earlier leases.
        let next_gen = buf.bind_generation();
        assert_eq!(next_gen, 2);
        let next = buf.lease(RunId::new("next"), ContainerId::allocate(), futex);
        assert_eq!(next.generation(), 2);
        assert!(next.validate_access().is_ok());
        assert!(matches!(
            lease_a.validate_access(),
            Err(SharedBufferError::GenerationMismatch {
                expected: 1,
                actual: 2
            })
        ));
        assert!(matches!(
            lease_b.validate_access(),
            Err(SharedBufferError::GenerationMismatch {
                expected: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn test_shared_futex_wait_and_wake() {
        let buf = SharedBuffer::new(4096).expect("allocate buffer");
        let run_id = RunId::new("futex-run");
        let container_id = ContainerId::allocate();
        let lease = buf.lease(
            run_id,
            container_id,
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );

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
        lease.write_from(0, &0u32.to_ne_bytes()).unwrap();

        let lease_clone = lease.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            // Simulate guest updating futex word and waking host
            lease_clone
                .atomic_u32(0)
                .unwrap()
                .store(42, Ordering::Release)
                .unwrap();
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

        let lease_a = buf_a.lease(
            run_a,
            cid_a,
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );
        let lease_b = buf_b.lease(
            run_b,
            cid_b,
            carrick_thread::platform_futex::SharedFutexTable::new(),
        );

        lease_a.write_from(0, &[0xAA; 32]).unwrap();
        lease_b.write_from(0, &[0xBB; 32]).unwrap();

        let mut read_a = [0u8; 32];
        let mut read_b = [0u8; 32];
        lease_a.read_into(0, &mut read_a).unwrap();
        lease_b.read_into(0, &mut read_b).unwrap();

        assert_eq!(read_a, [0xAA; 32]);
        assert_eq!(read_b, [0xBB; 32]);
    }

    #[test]
    fn test_in_memory_vfs_host_file_mounting() {
        use crate::vfs::Vfs;
        let vfs = crate::vfs::InMemoryFileVfs::new();
        let buf = SharedBuffer::new(4096).expect("buffer");
        buf.write_from(0, b"shbuf").unwrap();

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
