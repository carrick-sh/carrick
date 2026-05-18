#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x0, #-100
    adrp x1, path
    add x1, x1, :lo12:path
    mov x2, #0
    mov x8, #56
    svc #0

    cmp x0, #0
    b.lt exit_error
    mov x19, x0

read_loop:
    mov x0, x19
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, #256
    mov x8, #63
    svc #0

    cmp x0, #0
    b.lt exit_error
    cbz x0, close_file
    mov x20, x0

    mov x0, #1
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, x20
    mov x8, #64
    svc #0

    cmp x0, #0
    b.lt exit_error
    b read_loop

close_file:
    mov x0, x19
    mov x8, #57
    svc #0

    mov x0, #0
    mov x8, #93
    svc #0

exit_error:
    mov x0, #1
    mov x8, #93
    svc #0

1:
    b 1b

    .section .rodata
path:
    .asciz "/etc/motd"

    .bss
    .balign 16
buffer:
    .skip 256
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
