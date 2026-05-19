// The full apt-style pattern: pipe + fork + child dup3 + child
// execve. If pipe_dup3 prints "P" but this one hangs, the bug is in
// dup3 surviving an execve.
//
// Path to the execve target comes from argv[1] so the test harness
// can pass the host-absolute path of carrick-linux-aarch64-write-hi-to-fd1.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // argv layout at sp:  sp+0:argc, sp+8:argv[0], sp+16:argv[1], ...
    // Save argv[1] (the execve target path) for the child branch.
    ldr x21, [sp, #16]   // argv[1] pointer

    sub sp, sp, #128

    // pipe2(sp, 0)
    mov x0, sp
    mov x1, #0
    mov x8, #59
    svc #0

    ldr w19, [sp]
    ldr w20, [sp, #4]

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

    // ppoll on read end
    str w19, [sp, #16]
    mov w0, #1
    strh w0, [sp, #20]
    mov w0, #0
    strh w0, [sp, #22]
    add x0, sp, #16
    mov x1, #1
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #73
    svc #0

    // read into sp+32
    mov w0, w19
    add x1, sp, #32
    mov x2, #16
    mov x8, #63
    svc #0

    // write "P" to stdout
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

    // dup3(write_fd, 1, 0)
    mov w0, w20
    mov w1, #1
    mov w2, #0
    mov x8, #24
    svc #0

    // close the original write_fd
    mov w0, w20
    mov x8, #57
    svc #0

    // execve(argv[1], argv, NULL)
    mov x0, x21          // path = argv[1]
    add x1, sp, #112     // we'll build argv array there
    str x21, [sp, #112]  // argv[0] = path
    str xzr, [sp, #120]  // argv[1] = NULL
    mov x2, #0           // envp = NULL
    mov x8, #221         // SYS_execve
    svc #0

    // execve failed: write "X" to fd 1 then exit nonzero
    mov w0, #1
    adr x1, msg_fail
    mov x2, #1
    mov x8, #64
    svc #0
    mov x0, #1
    mov x8, #94
    svc #0

msg_p: .ascii "P"
msg_fail: .ascii "X"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
