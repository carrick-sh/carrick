#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x21, sp
    ldr x0, [x21]
    cmp x0, #2
    b.lt exit_error

    ldr x19, [x21, #16]
    mov x0, x19
    bl strlen
    mov x20, x0

    mov x0, #1
    mov x1, x19
    mov x2, x20
    mov x8, #64
    svc #0

    mov x0, #1
    adrp x1, newline
    add x1, x1, :lo12:newline
    mov x2, #1
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

exit_error:
    mov x0, #1
    mov x8, #93
    svc #0

strlen:
    mov x1, x0
    mov x0, #0
1:
    ldrb w2, [x1, x0]
    cbz w2, 2f
    add x0, x0, #1
    b 1b
2:
    ret

    .section .rodata
newline:
    .ascii "\n"
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
