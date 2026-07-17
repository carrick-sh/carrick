#![no_std]
#![no_main]
use core::arch::asm;
#[inline(always)]
unsafe fn exit_group(code: usize) -> ! {
    asm!("syscall", in("rax") 231usize, in("rdi") code, options(noreturn));
}
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // A big pure-compute loop: NO syscall inside — it must chain to be fast.
    let mut sum: u64 = 0;
    let mut i: u64 = 0;
    while i < 50_000_000 {
        sum = sum.wrapping_add(i.wrapping_mul(3).wrapping_add(1));
        i += 1;
    }
    // exit_group(sum & 0xff)
    unsafe { exit_group((sum & 0xff) as usize) }
}
#[panic_handler]
fn p(_: &core::panic::PanicInfo) -> ! { loop {} }
