//! Bump-allocated linear guest memory for a task.

use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_kernel::dispatch::LinearMemory;

/// The base address of the task's guest memory.
pub const GUEST_BASE: u64 = 0x1000_0000;
/// The length of the task's guest memory (1 MiB).
pub const GUEST_LEN: usize = 1 << 20;

/// Task guest memory: a `LinearMemory` plus a 16-byte aligned bump allocator.
#[derive(Debug, Clone)]
pub struct TaskMemory {
    /// The underlying `LinearMemory` implementing `GuestMemory`.
    pub linear: LinearMemory,
    cursor: u64,
}

impl TaskMemory {
    /// Create a new 1 MiB task memory arena.
    pub fn new() -> Self {
        Self {
            linear: LinearMemory::new(GUEST_BASE, vec![0; GUEST_LEN]),
            cursor: GUEST_BASE,
        }
    }

    /// Allocate `n` bytes aligned to 16 bytes.
    pub fn alloc(&mut self, n: usize) -> Result<u64, MemoryError> {
        let addr = (self.cursor + 15) & !15;
        let next_cursor = addr + n as u64;
        if next_cursor > GUEST_BASE + GUEST_LEN as u64 {
            return Err(MemoryError::OutOfBounds {
                address: addr,
                length: n,
            });
        }
        self.cursor = next_cursor;
        Ok(addr)
    }

    /// Allocate `n` bytes zeroed.
    pub fn alloc_zeroed(&mut self, n: usize) -> Result<u64, MemoryError> {
        let a = self.alloc(n)?;
        let zeroes = vec![0u8; n];
        self.linear.write_bytes_raw(a, &zeroes)?;
        Ok(a)
    }

    /// Materialise `bytes` in task memory and return its guest virtual address.
    pub fn put(&mut self, bytes: &[u8]) -> Result<u64, MemoryError> {
        let a = self.alloc(bytes.len())?;
        self.linear.write_bytes_raw(a, bytes)?;
        Ok(a)
    }

    /// Read `n` bytes from `addr` in task memory.
    pub fn read(&self, addr: u64, n: usize) -> Result<Vec<u8>, MemoryError> {
        self.linear.read_bytes_raw(addr, n)
    }
}

impl Default for TaskMemory {
    fn default() -> Self {
        Self::new()
    }
}
