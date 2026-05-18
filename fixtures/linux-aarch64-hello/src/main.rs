#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x0, #1
    adrp x1, message
    add x1, x1, :lo12:message
    mov x2, #19
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

1:
    b 1b

    .section .rodata
message:
    .ascii "hello from carrick\n"
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
