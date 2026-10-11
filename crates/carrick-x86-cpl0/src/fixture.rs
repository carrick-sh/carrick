//! Fixture image with synthetic observation syscalls.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
extern crate alloc as rust_alloc;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod cpl0_scheduler {
    pub(crate) use carrick_el1::isa::x86::context::scheduler::*;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod cpl0_entry {
    pub use carrick_el1::isa::x86::context::native::*;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[path = "fixture_personality.rs"]
mod fixture_personality;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod process;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod progress;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod kernel {
    pub use crate::fixture_personality::lifecycle_invariant_error;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[path = "../../carrick-x86/src/cpl0_lifecycle.rs"]
mod lifecycle;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
carrick_x86_carrier::export_carrier!(fixture_personality::FixturePersonality);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
// SAFETY: hardware symbol retained in linked fixture image.
#[unsafe(no_mangle)]
pub static CARRICK_X86_FIXTURE_DISPATCH_WITNESSES: [u64; 2] =
    [0x7bd6_8a91_c4e2_5f03, 0xa239_4c7d_8e15_b6f0];

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
// SAFETY: hardware entry for fixture dispatch witness.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn carrick_x86_fixture_dispatch_witness() -> bool {
    // SAFETY: volatile read keeps the fixture-only witness in the linked image.
    (unsafe {
        core::ptr::read_volatile(
            core::ptr::addr_of!(CARRICK_X86_FIXTURE_DISPATCH_WITNESSES).cast::<u64>(),
        )
    }) == 0x7bd6_8a91_c4e2_5f03
}

#[allow(dead_code)]
fn main() {}
