// Minimal smoke fixture for nested shell-style pipe plumbing:
//
//   ( writer 2>&1 | reader )
//
// The pipe is created inside an outer forked "subshell"; the inner writer
// redirects stdout to the pipe, redirects stderr to stdout, and writes "hi" to
// fd 2. Expected output on real Linux: "hi".

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    sub sp, sp, #128

    // outer clone(SIGCHLD) - the subshell
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220
    svc #0
    cmp x0, #0
    b.eq subshell

outer_parent:
    // wait4(-1, NULL, 0, NULL)
    mov x0, #-1
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x8, #260
    svc #0
    mov x0, #0
    mov x8, #94
    svc #0

subshell:
    // pipe2(sp, 0)
    mov x0, sp
    mov x1, #0
    mov x8, #59
    svc #0
    ldr w19, [sp]        // read_fd
    ldr w20, [sp, #4]    // write_fd

    // inner clone(SIGCHLD) - the writer stage
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220
    svc #0
    cmp x0, #0
    b.eq writer

reader:
    // close write end
    mov w0, w20
    mov x8, #57
    svc #0

    // read(read_fd, sp+32, 16)
    mov w0, w19
    add x1, sp, #32
    mov x2, #16
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le reader_wait
    mov x21, x0

    // write(1, sp+32, n)
    mov w0, #1
    add x1, sp, #32
    mov x2, x21
    mov x8, #64
    svc #0

reader_wait:
    // wait4(-1) for the writer, then exit.
    mov x0, #-1
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x8, #260
    svc #0
    mov x0, #0
    mov x8, #94
    svc #0

writer:
    // close read end
    mov w0, w19
    mov x8, #57
    svc #0

    // dup3(write_fd, 1, 0)
    mov w0, w20
    mov w1, #1
    mov w2, #0
    mov x8, #24
    svc #0

    // close original write_fd
    mov w0, w20
    mov x8, #57
    svc #0

    // close(2); dup3(1, 2, 0) - shell-style 2>&1.
    mov w0, #2
    mov x8, #57
    svc #0
    mov w0, #1
    mov w1, #2
    mov w2, #0
    mov x8, #24
    svc #0

    // write(2, "hi", 2)
    mov w0, #2
    adr x1, msg_hi
    mov x2, #2
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

msg_hi: .ascii "hi"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
