//! Copy-only adapter for the bounded research syscall whitelist. This does
//! not implement an MM engine, mapping syscalls, or raw host I/O pointers.
use carrick_guest_mem::{CurrentMmMemory, GuestMemory, GuestVa, MemoryError, RepointPrivateError};
use carrick_kernel::kernel::mm_access::{CurrentReadCache, MmAccessTarget};
use carrick_kernel::kernel::{KernelContext, MmAccessError, objects::ThreadExecutionLease};
use std::cell::RefCell;
use std::{marker::PhantomData, rc::Rc};

/// A host checkpoint view. Construction authenticates without taking a mapping
/// snapshot. Actual memory access lazily uses the current carrier authority;
/// invalid-fd syscalls therefore incur no speculative buffer preparation.
/// The lease borrow prevents handoff and native re-entry while this view lives.
pub struct CarrierCopyMemory<'a> {
    context: &'a KernelContext,
    execution: &'a ThreadExecutionLease,
    read_cache: Option<&'a RefCell<CurrentReadCache>>,
    _thread: PhantomData<Rc<()>>,
}
impl<'a> CarrierCopyMemory<'a> {
    pub fn with_read_cache(
        context: &'a KernelContext,
        execution: &'a ThreadExecutionLease,
        cache: &'a RefCell<CurrentReadCache>,
    ) -> Result<Self, MmAccessError> {
        let mut view = Self::new(context, execution)?;
        view.read_cache = Some(cache);
        Ok(view)
    }

    pub fn new(
        context: &'a KernelContext,
        execution: &'a ThreadExecutionLease,
    ) -> Result<Self, MmAccessError> {
        context.validate_current_execution_mm(execution)?;
        Ok(Self {
            context,
            execution,
            read_cache: None,
            _thread: PhantomData,
        })
    }
}
impl GuestMemory for CarrierCopyMemory<'_> {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if length != 0 {
            // Reject an invalid/overflowing guest range before allocating a
            // guest-controlled-sized Vec. Fixed-size callers use read_into.
            self.context
                .current_mm(self.execution)
                .and_then(|mm| {
                    mm.access_token()
                        .read_range(GuestVa(address), length)
                        .map(|_| ())
                })
                .map_err(|_| MemoryError::OutOfBounds { address, length })?;
        }
        let mut bytes = vec![0; length];
        self.read_into_raw(address, &mut bytes)?;
        Ok(bytes)
    }
    fn read_into_raw(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        let result = if let Some(cache) = self.read_cache {
            self.context.copy_current_into_cached(
                self.execution,
                GuestVa(address),
                dst,
                &mut cache.borrow_mut(),
            )
        } else {
            self.context
                .copy_current_into(self.execution, GuestVa(address), dst)
        };
        result.map_err(|_| MemoryError::OutOfBounds {
            address,
            length: dst.len(),
        })
    }
    fn write_bytes_raw(&mut self, address: u64, src: &[u8]) -> Result<(), MemoryError> {
        self.context
            .copy_current_from(self.execution, GuestVa(address), src)
            .map_err(|_| MemoryError::OutOfBounds {
                address,
                length: src.len(),
            })
    }
    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.context
            .current_mm(self.execution)
            .and_then(|mm| mm.write_range(GuestVa(address), length).map(|_| ()))
            .is_ok()
    }
    fn protect_range(&mut self, _: u64, _: usize, _: u64) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
    fn unmap_range(&mut self, _: u64, _: usize) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
    fn repoint_private(
        &mut self,
        _: u64,
        _: u64,
        _: usize,
        _: &[u8],
    ) -> Result<(), RepointPrivateError> {
        Err(RepointPrivateError::Clean(MemoryError::Unsupported))
    }
    fn repoint_shared_leaf(&mut self, _: u64, _: u64, _: usize) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
    fn restore_shared_identity(&mut self, _: u64, _: usize) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
    fn zero_backing(&mut self, _: u64, _: usize) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }
}
impl CurrentMmMemory for CarrierCopyMemory<'_> {}
