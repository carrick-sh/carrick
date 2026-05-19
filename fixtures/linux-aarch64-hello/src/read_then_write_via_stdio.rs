// Execve target: read up to 16 bytes from stdin, then write "got:"
// followed by what was read to stdout. Mimics the apt http method's
// startup pattern (read URI request via stdin, write response via
// stdout) without any glibc.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    sub sp, sp, #32

    // read(0, sp+0, 16)
    mov w0, #0
    mov x1, sp
    mov x2, #16
    mov x8, #63
    svc #0

    // x0 holds bytes read. Stash in w19.
    mov w19, w0

    // write(1, "got:", 4)
    mov w0, #1
    adr x1, prefix
    mov x2, #4
    mov x8, #64
    svc #0

    // write(1, sp, w19)
    mov w0, #1
    mov x1, sp
    mov w2, w19
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

prefix: .ascii "got:"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
