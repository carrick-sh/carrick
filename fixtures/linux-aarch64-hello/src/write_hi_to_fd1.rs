// Minimal exec target: write "hi" to fd 1, exit 0. Used as the
// child's execve destination in pipe_dup3_exec.rs.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov w0, #1
    adr x1, msg
    mov x2, #2
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

msg: .ascii "hi"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
