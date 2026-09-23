//! Carrick in-guest EL1 kernel entry point, header, and panic handler.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

/// In-guest syscall entry point called from the EL1 exception vector.
///
/// Invoked with `frame` pointing to a [`carrick_el1_abi::TrapFrame`] allocated
/// on the per-vCPU EL1 kernel stack.
/// Returns [`carrick_el1_abi::Action`] encoded as `u64`:
/// - 0 (`Action::Served`): The syscall was fully handled in-guest; restore registers
///   and issue `eret` back to guest EL0 with `x0` set to the return value.
/// - 1 (`Action::Forward`): The syscall must be forwarded to the host; restore all
///   guest registers and branch to `mailbox_capture`.
///
/// # Safety
///
/// If `frame` is non-null, it must point to a valid, aligned, and mutable
/// [`carrick_el1_abi::TrapFrame`] on the calling vCPU's kernel stack.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carrick_el1_syscall(frame: *mut carrick_el1_abi::TrapFrame) -> u64 {
    if frame.is_null() {
        return carrick_el1_abi::Action::Forward as u64;
    }
    let frame_ref = unsafe { &mut *frame };
    let counters_ref =
        unsafe { &mut *(carrick_el1_abi::EL1_COUNTERS_BASE as *mut carrick_el1_abi::Counters) };
    carrick_el1::dispatch_syscall(frame_ref, counters_ref) as u64
}

/// Observable bare-metal panic handler.
///
/// When running in-guest at EL1 (`target_os = "none"`), standard output facilities
/// are unavailable. To ensure a panic is observable by the host, this handler writes
/// [`carrick_el1_abi::PANIC_SENTINEL`] (`0xDEAD_CAFE_DEAD_BEEF`) into the last counter
/// slot (`carrick_el1_abi::PANIC_SENTINEL_SYSCALL_NR` = 511) of both `served` and
/// `forwarded` counters in the shared `Counters` page.
///
/// Host diagnostic tools (`carrick trace`, `carrick-lldb`, test assertions) inspecting
/// the `Counters` page can immediately detect this distinctive sentinel rather than
/// mistaking a panic for an unresponsive hang.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let counters_ptr = carrick_el1_abi::EL1_COUNTERS_BASE as *mut carrick_el1_abi::Counters;
    unsafe {
        (*counters_ptr).served[carrick_el1_abi::PANIC_SENTINEL_SYSCALL_NR] =
            carrick_el1_abi::PANIC_SENTINEL;
        (*counters_ptr).forwarded[carrick_el1_abi::PANIC_SENTINEL_SYSCALL_NR] =
            carrick_el1_abi::PANIC_SENTINEL;
    }
    loop {
        core::hint::spin_loop();
    }
}
