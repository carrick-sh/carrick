//! Example non-Linux test personality composition root.
//!
//! Demonstrates a minimal bare-metal guest image composition root representing
//! an out-of-tree / non-Linux test personality without in-tree kernel assumptions.
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Syscall/entry symbol in the supervisor address space.
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_syscall() -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    loop {}
}
