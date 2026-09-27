//! Carrick in-guest EL1 kernel entry point, header, and panic handler.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

/// In-guest syscall entry point called from the EL1 exception vector.
///
/// Invoked with `frame` pointing to a [`carrick_el1_abi::TrapFrame`] allocated
/// on the per-vCPU EL1 kernel stack.
/// Also the entry of the vector's EL0 IRQ hook, which saves the same
/// [`carrick_el1_abi::TrapFrame`] with `esr == 0`.
///
/// Returns [`carrick_el1_abi::Action`] encoded as `u64`:
/// - 0 (`Action::Served`): The syscall was fully handled in-guest (or the
///   interrupt was); restore registers and issue `eret` back to guest EL0.
/// - 1 (`Action::Forward`): The syscall must be forwarded to the host; restore all
///   guest registers and branch to `mailbox_capture` (an interrupt: `hvc #4`).
/// - 2 (`Action::ServedWithWork`): served, and host work is pending.
/// - 3 (`Action::Idle`): the thread parked and the idle vCPU leaves for the
///   host with no thread on it (`hvc #5`).
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
        unsafe { &*(carrick_el1_abi::EL1_COUNTERS_BASE as *const carrick_el1_abi::Counters) };
    carrick_el1::dispatch_entry(frame_ref, counters_ref) as u64
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
fn panic(info: &core::panic::PanicInfo) -> ! {
    let counters =
        unsafe { &*(carrick_el1_abi::EL1_COUNTERS_BASE as *const carrick_el1_abi::Counters) };
    counters.served[carrick_el1_abi::PANIC_SENTINEL_SYSCALL_NR].store(
        carrick_el1_abi::PANIC_SENTINEL,
        core::sync::atomic::Ordering::Relaxed,
    );
    counters.forwarded[carrick_el1_abi::PANIC_SENTINEL_SYSCALL_NR].store(
        carrick_el1_abi::PANIC_SENTINEL,
        core::sync::atomic::Ordering::Relaxed,
    );
    let (line, column) = info.location().map_or((0, 0), |location| {
        (u64::from(location.line()), u64::from(location.column()))
    });
    let detail = carrick_el1::fault::panic_publication_detail();
    unsafe {
        core::arch::asm!(
            "hvc #3",
            in("x0") carrick_el1_abi::PANIC_SENTINEL,
            in("x1") line,
            in("x2") column,
            in("x3") detail,
        );
    }
    loop {
        core::hint::spin_loop();
    }
}
