//! `carrick-native-darwin` — the macOS host layer for the native (DSR)
//! backend.
//!
//! The single-mapping MAP_JIT W^X JIT backend (M0.6) lives here: [`jit`]
//! provides `DarwinHostJit` (the real Apple-Silicon MAP_JIT /
//! `pthread_jit_write_protect_np` implementation) plus [`active_host_jit`],
//! moved byte-for-byte out of the transitional
//! `carrick-runtime/src/native_darwin/darwin_jit.rs` shim (which becomes a
//! thin re-export of this crate). The C trap/kick shim
//! (`csrc/native_darwin.c`) moved with it — `build.rs` compiles it under the
//! same target gate it always used.
//!
//! The whole crate is macOS-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-native-freebsd`). Within
//! that macOS gate, [`jit`] narrows further to aarch64 for the real
//! implementation — Apple Silicon is the only hardware `MAP_JIT`'s
//! per-thread write-protect toggle exists on — with a fail-closed fallback
//! for any other macOS arch, mirroring the runtime shim's own "unsupported"
//! arm.

#![cfg(target_os = "macos")]

pub mod aot_cache;
/// Tier D: run guest code directly, patching only `svc`/x18/`tpidr_el0`.
/// aarch64-only — the whole premise is same-ISA execution.
#[cfg(target_arch = "aarch64")]
pub mod direct;
pub mod jit;

#[cfg(target_arch = "aarch64")]
pub use jit::DarwinHostJit;
pub use jit::active_host_jit;

#[cfg(test)]
pub(crate) mod test_allocations {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    pub(crate) struct CountingSystem;

    std::thread_local! {
        static ENABLED: Cell<bool> = const { Cell::new(false) };
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    fn record_allocation() {
        ENABLED.with(|enabled| {
            if enabled.get() {
                ALLOCATIONS.with(|count| count.set(count.get() + 1));
            }
        });
    }

    unsafe impl GlobalAlloc for CountingSystem {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            // SAFETY: this allocator is a counting wrapper over System and
            // forwards the caller's unchanged layout.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            // SAFETY: same forwarding contract as `alloc`.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` came from this wrapper's System allocation with
            // the same layout.
            unsafe { System.dealloc(ptr, layout) };
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record_allocation();
            // SAFETY: `ptr` and `layout` came from System; `new_size` is the
            // caller's requested replacement extent.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static TEST_ALLOCATOR: CountingSystem = CountingSystem;

    pub(crate) fn count_current_thread<T>(work: impl FnOnce() -> T) -> (T, usize) {
        ALLOCATIONS.with(|count| count.set(0));
        ENABLED.with(|enabled| enabled.set(true));
        let result = work();
        ENABLED.with(|enabled| enabled.set(false));
        let count = ALLOCATIONS.with(Cell::get);
        (result, count)
    }
}

/// The Darwin half of a native lane (`carrick_dsr::lane::NativeHost`):
/// hands the lane wiring this crate's JIT authority.
pub struct DarwinHost;

impl carrick_dsr::lane::NativeHost for DarwinHost {
    const NAME: &'static str = "darwin";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn darwin_host_name_and_jit_are_wired() {
        assert_eq!(DarwinHost::NAME, "darwin");
        // Must not panic regardless of arch (aarch64 real impl vs the
        // fail-closed fallback on any other macOS arch).
        let _ = DarwinHost::active_jit().supported();
    }
}
