//! Host allocation and invariant reporting for the neutral fasync table.
pub use carrick_signal_core::fasync::FasyncOwner;
use carrick_signal_core::fasync::{self, FasyncTable};
use std::sync::atomic::{AtomicPtr, Ordering};

#[cfg(test)]
static TABLE_POINTER_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

static FASYNC_TABLE: AtomicPtr<FasyncTable> = AtomicPtr::new(std::ptr::null_mut());

/// Allocate the shared FASYNC table once (`MAP_SHARED|MAP_ANON`, inherited
/// across fork). Idempotent — a non-null pointer (the child inherited the
/// mapping) is a no-op, so every process shares ONE table. Best-effort: a failed
/// mmap leaves the table absent and arm/lookup become no-ops (FASYNC delivery
/// silently degrades, never crashes).
pub fn fasync_init() {
    if !FASYNC_TABLE.load(Ordering::Acquire).is_null() {
        return;
    }
    let size = std::mem::size_of::<FasyncTable>();
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return;
    }
    // mmap zero-fills, so every slot's `used` is 0 (free) already.
    FASYNC_TABLE.store(p.cast::<FasyncTable>(), Ordering::Release);
}

fn table() -> Option<&'static FasyncTable> {
    #[cfg(test)]
    TABLE_POINTER_LOADS.fetch_add(1, Ordering::Relaxed);
    let p = FASYNC_TABLE.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: a non-null FASYNC_TABLE points at a live MAP_SHARED mapping of
        // exactly one FasyncTable, allocated by fasync_init and never unmapped.
        Some(unsafe { &*p })
    }
}

fn invariant_failure(message: core::fmt::Arguments<'_>) -> ! {
    carrick_fatal::carrick_fatal!("signal::fasync", "{message}")
}

pub fn any_armed() -> bool {
    table().is_some_and(fasync::any_armed)
}
pub fn arm(pipe_id: u64, owner: FasyncOwner) {
    if let Some(t) = table() {
        fasync::arm(t, pipe_id, owner, invariant_failure);
    }
}
pub fn disarm(pipe_id: u64, registration_id: u64) {
    if let Some(t) = table() {
        fasync::disarm(t, pipe_id, registration_id, invariant_failure);
    }
}
pub fn lookup(pipe_id: u64) -> Option<FasyncOwner> {
    fasync::lookup(table()?, pipe_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_is_idempotent() {
        fasync_init();
        let first = FASYNC_TABLE.load(Ordering::Acquire);
        assert!(!first.is_null());
        fasync_init();
        assert_eq!(first, FASYNC_TABLE.load(Ordering::Acquire));
        TABLE_POINTER_LOADS.store(0, Ordering::Relaxed);
        assert!(!any_armed());
        assert_eq!(TABLE_POINTER_LOADS.load(Ordering::Relaxed), 1);
    }
}
