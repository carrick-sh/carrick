// Adds dup3 to the pipe+fork+poll pattern. If pipe_fork_poll prints
// "P" but pipe_dup3 hangs, the bug is in dup3 of pipe ends.
//
// Pattern:
//   pipe2 -> (read_fd, write_fd)
//   clone
//   parent: close write_fd; ppoll(read_fd); read; write 'P'; exit 0
//   child:  dup3(write_fd, 1); close write_fd; write(1, "hi", 2); exit 0

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    sub sp, sp, #64

    // pipe2(sp, 0)
    mov x0, sp
    mov x1, #0
    mov x8, #59
    svc #0

    ldr w19, [sp]        // read_fd
    ldr w20, [sp, #4]    // write_fd

    // clone(SIGCHLD)
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220
    svc #0
    cmp x0, #0
    b.eq child

parent:
    // close write end
    mov w0, w20
    mov x8, #57
    svc #0

    // ppoll pollfd at sp+8
    str w19, [sp, #8]
    mov w0, #1
    strh w0, [sp, #12]
    mov w0, #0
    strh w0, [sp, #14]
    add x0, sp, #8
    mov x1, #1
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #73
    svc #0

    // read(read_fd, sp+24, 16)
    mov w0, w19
    add x1, sp, #24
    mov x2, #16
    mov x8, #63
    svc #0

    // write(1, "P", 1)
    mov w0, #1
    adr x1, msg_p
    mov x2, #1
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

child:
    // close read end
    mov w0, w19
    mov x8, #57
    svc #0

    // dup3(write_fd, 1, 0) — replace stdout with the pipe write end
    mov w0, w20
    mov w1, #1
    mov w2, #0
    mov x8, #24
    svc #0

    // close the original write_fd (we kept it as fd 1)
    mov w0, w20
    mov x8, #57
    svc #0

    // write(1, "hi", 2)
    mov w0, #1
    adr x1, msg_hi
    mov x2, #2
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

msg_p: .ascii "P"
msg_hi: .ascii "hi"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
