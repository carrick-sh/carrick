//! Allocation observation only. Never use this binary for timing claims.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! {static COUNT:Cell<Option<u64>>=const {Cell::new(None)};}
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
fn note() {
    let _ = COUNT.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
            native_slice_active_allocation();
        }
    });
}
/// Stable debugger breakpoint, reached only while a measurement is armed.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn native_slice_active_allocation() {
    std::hint::black_box(0u64);
}
// SAFETY: forwards layout, pointers and sizes unchanged to System.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        note();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
pub fn begin() {
    assert!(COUNT.get().is_none());
    COUNT.set(Some(0));
}
pub fn end() -> u64 {
    COUNT.replace(None).expect("active allocation observation")
}
pub fn positive_control() {
    begin();
    let v = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
    assert!(end() > 0, "allocation positive control did not fire");
    drop(v);
}
