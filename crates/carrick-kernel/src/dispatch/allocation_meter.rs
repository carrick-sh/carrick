//! Test counting allocator for deterministic allocation budgets.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static BYTES: Cell<Option<u64>> = const { Cell::new(None) };
}

pub struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record(bytes: usize) {
    let _ = BYTES.try_with(|count| {
        if let Some(total) = count.get() {
            count.set(Some(total.saturating_add(bytes as u64)));
        }
    });
    super::budget_meter::record_allocation(bytes);
}

// SAFETY: every call is forwarded unchanged to `System`; the const TLS
// counter allocates nothing and observes only the current thread.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Host-heap bytes requested by this thread while `run` executes.
pub fn measure<T>(run: impl FnOnce() -> T) -> (T, u64) {
    BYTES.with(|count| count.set(Some(0)));
    let value = run();
    let bytes = BYTES.with(|count| count.replace(None)).unwrap_or(0);
    (value, bytes)
}
