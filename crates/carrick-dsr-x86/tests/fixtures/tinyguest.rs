#![no_std]
#![no_main]

// A real compiler-generated static Linux x86_64 guest with NO libc: _start
// does the work directly. Exercises real LLVM codegen (a computed loop, a
// RIP-relative rodata string) plus Linux syscalls, so it drives the DSR
// pipeline against genuine compiler output rather than hand-assembly.

use core::arch::asm;

#[inline(always)]
unsafe fn sys3(nr: usize, a: usize, b: usize, c: usize) -> usize {
    let ret;
    asm!("syscall", inlateout("rax") nr => ret,
         in("rdi") a, in("rsi") b, in("rdx") c,
         lateout("rcx") _, lateout("r11") _, options(nostack));
    ret
}

const MSG: &[u8] = b"native-elf ok\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // A real loop the compiler lowers to dec/jnz-style control flow.
    let mut sum: u64 = 0;
    let mut i: u64 = 0;
    while i < 7 {
        sum = sum.wrapping_add(i);
        i += 1;
    }
    // write(1, MSG, len) — MSG is reached RIP-relatively in PIC codegen.
    unsafe { sys3(1, 1, MSG.as_ptr() as usize, MSG.len()); }
    // exit_group(sum)  => 0+1+..+6 = 21
    unsafe { sys3(231, sum as usize, 0, 0); }
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
