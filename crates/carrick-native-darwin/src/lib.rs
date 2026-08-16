//! `carrick-native-darwin` — macOS host-level primitives for OS-integrated
//! execution.
//!
//! **Status: preserved for future optimisation, not actively wired into the
//! HVPatch execution path.**
//!
//! This crate contains the Darwin-specific building blocks that exploit
//! host-OS primitives for guest performance optimisation:
//!
//! - **[`jit`]** — the Apple Silicon `MAP_JIT` / `pthread_jit_write_protect_np`
//!   W^X JIT backend (`DarwinHostJit`, implementing
//!   [`carrick_dsr::host::NativeHostJit`]). This is the concrete Darwin
//!   implementor of the host JIT trait. The C support shim
//!   (`csrc/native_darwin.c`) provides `sys_icache_invalidate` and
//!   signal/kick plumbing.
//!
//! - **[`direct`]** (aarch64-only) — Tier-D binary patching: same-ISA
//!   execution by patching `svc #0` → island trampolines, virtualising
//!   Darwin-reserved `x18` and guest `TPIDR_EL0`, and proving unallocated
//!   opcode safety. Does not require a hypervisor or JIT translation.
//!
//! - **[`aot_cache`]** — persistent on-disk translation cache
//!   (`~/.carrick`), SHA-256-verified, `flock`-elected, LRU-evicted.
//!
//! The whole crate is macOS-only by construction (`#![cfg(target_os =
//! "macos")]`). Within that gate, [`jit`] and [`direct`] narrow further to
//! `target_arch = "aarch64"` — Apple Silicon is the only hardware where
//! `MAP_JIT`'s per-thread write-protect toggle exists.

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
