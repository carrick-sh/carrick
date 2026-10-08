//! Fixture image with synthetic observation syscalls.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

macro_rules! fixture_items { ($($item:item)*) => { $($item)* }; }
#[cfg(target_os = "none")]
macro_rules! fixture_stmt { ($($tt:tt)*) => { $($tt)* }; }
#[cfg(target_os = "none")]
macro_rules! fixture_expr { ($($tt:tt)*) => { $($tt)* }; }

#[cfg(target_os = "none")]
mod process;
#[cfg(target_os = "none")]
mod progress;
#[cfg(target_os = "none")]
mod cpl0_scheduler {
    pub(crate) use carrick_el1::isa::x86::context::scheduler::*;
}
#[cfg(target_os = "none")]
mod cpl0_entry {
    pub use carrick_el1::isa::x86::context::native::*;
}
#[cfg(target_os = "none")]
#[path = "../../carrick-x86/src/cpl0_lifecycle.rs"]
mod lifecycle;
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
static CARRICK_X86_FIXTURE_DISPATCH_WITNESSES: [u64; 2] =
    [0x7bd6_8a91_c4e2_5f03, 0xa239_4c7d_8e15_b6f0];

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
#[inline(never)]
fn carrick_x86_fixture_dispatch_witness() -> bool {
    // A volatile read keeps the fixture-only witness in the linked image.
    (unsafe {
        core::ptr::read_volatile(
            core::ptr::addr_of!(CARRICK_X86_FIXTURE_DISPATCH_WITNESSES).cast::<u64>(),
        )
    }) == 0x7bd6_8a91_c4e2_5f03
}
include!("entry.rs");

#[cfg(target_os = "none")]
fn fixture_handled(
    frame: &mut carrick_el1::isa::x86::context::native::NativeFrame,
    binding: &carrick_el1::isa::x86::context::native::CpuBinding,
    task: &carrick_el1_abi::CurrentTask,
    counters: &carrick_el1_abi::Counters,
    call: &carrick_personality_linux::entry::CanonicalCall,
) -> bool {
    use crate::kernel::{doorbell, halt};
    use carrick_el1::isa::x86::context::native::{FATAL_PORT, FORWARD_PORT, WORK_PORT};
    use core::sync::atomic::Ordering;

    let lifecycle_address = binding.scheduler_witness.load(Ordering::Acquire);
    if lifecycle_address == crate::lifecycle::LIFECYCLE_LANE
        || lifecycle_address
            == crate::lifecycle::LIFECYCLE_LANE + crate::lifecycle::LIFECYCLE_STRIDE
    {
        // SAFETY: stopped-host bootstrap published and retains the aligned
        // native lane/zone/page custody for this exact CPU binding.
        let Some(mut lane) =
            (unsafe { crate::lifecycle::acquire(frame, binding, task, counters, call.args) })
        else {
            doorbell(FATAL_PORT, frame);
            halt();
        };
        match carrick_personality_linux::dispatch::dispatch(
            call.canonical.raw(),
            u64::MAX,
            &mut lane,
        ) {
            carrick_personality_linux::dispatch::CompletionRoute::Served => {}
            carrick_personality_linux::dispatch::CompletionRoute::WithWork => {
                doorbell(WORK_PORT, frame);
            }
            carrick_personality_linux::dispatch::CompletionRoute::Forward => {
                doorbell(FORWARD_PORT, frame);
            }
            _ => {
                doorbell(FATAL_PORT, frame);
                halt();
            }
        }
        true
    } else {
        false
    }
}
