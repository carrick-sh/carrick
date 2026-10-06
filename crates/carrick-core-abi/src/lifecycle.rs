//! Neutral thread lifecycle notification authority.

use core::sync::atomic::{AtomicU64, Ordering};

/// One retained notification authority for a kernel graph's thread ledger.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct ThreadLedgerActivity {
    pending: AtomicU64,
}

impl ThreadLedgerActivity {
    pub const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
        }
    }
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }
    pub fn announce(&self) {
        self.pending.fetch_add(1, Ordering::Release);
    }
    pub fn complete(&self, count: u64) -> Result<(), u64> {
        self.pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_sub(count)
            })
            .map(|_| ())
    }
}

impl Default for ThreadLedgerActivity {
    fn default() -> Self {
        Self::new()
    }
}
