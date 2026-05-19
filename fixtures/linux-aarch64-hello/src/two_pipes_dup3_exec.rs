// The full apt-method launch pattern in fixture form:
//
//   pipe_p2c (parent writes "U", child reads via stdin)
//   pipe_c2p (child writes via stdout, parent reads "got:U")
//   clone(SIGCHLD)
//   child: dup3(c2p_write, 1); dup3(p2c_read, 0); execve(reader_writer)
//   parent: write "U" to pipe_p2c_write; ppoll pipe_c2p_read; read; print
//
// If this hangs, we have the EXACT apt deadlock in a 200-line repro
// with NO glibc, NO buffering complexity, just the syscalls.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // Save argv[1] (path to read_then_write_via_stdio)
    ldr x21, [sp, #16]

    sub sp, sp, #256

    // pipe2(sp, 0)  -- parent->child pipe
    mov x0, sp
    mov x1, #0
    mov x8, #59
    svc #0

    // pipe2(sp+8, 0)  -- child->parent pipe
    add x0, sp, #8
    mov x1, #0
    mov x8, #59
    svc #0

    ldr w19, [sp]        // p2c_read
    ldr w20, [sp, #4]    // p2c_write
    ldr w22, [sp, #8]    // c2p_read
    ldr w23, [sp, #12]   // c2p_write

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
    // Parent closes p2c_read and c2p_write (only child needs those).
    mov w0, w19
    mov x8, #57
    svc #0
    mov w0, w23
    mov x8, #57
    svc #0

    // write(p2c_write, "URI-REQUEST", 11)
    mov w0, w20
    adr x1, msg_uri
    mov x2, #11
    mov x8, #64
    svc #0

    // ppoll(c2p_read, POLLIN, NULL)
    str w22, [sp, #16]
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

    // read(c2p_read, sp+32, 32)
    mov w0, w22
    add x1, sp, #32
    mov x2, #32
    mov x8, #63
    svc #0

    // write(1, response, bytes_read)
    mov w19, w0
    mov w0, #1
    add x1, sp, #32
    mov w2, w19
    mov x8, #64
    svc #0

    mov w0, #1
    adr x1, msg_nl
    mov x2, #1
    mov x8, #64
    svc #0

    mov x0, #0
    mov x8, #94
    svc #0

child:
    // Child closes p2c_write and c2p_read.
    mov w0, w20
    mov x8, #57
    svc #0
    mov w0, w22
    mov x8, #57
    svc #0

    // dup3(c2p_write, 1, 0)
    mov w0, w23
    mov w1, #1
    mov w2, #0
    mov x8, #24
    svc #0

    // dup3(p2c_read, 0, 0)
    mov w0, w19
    mov w1, #0
    mov w2, #0
    mov x8, #24
    svc #0

    // close the original fds
    mov w0, w23
    mov x8, #57
    svc #0
    mov w0, w19
    mov x8, #57
    svc #0

    // execve(argv[1], argv, NULL)
    mov x0, x21
    add x1, sp, #200
    str x21, [sp, #200]
    str xzr, [sp, #208]
    mov x2, #0
    mov x8, #221
    svc #0

    // execve failed
    mov x0, #1
    mov x8, #94
    svc #0

msg_uri: .ascii "URI-REQUEST"
msg_nl: .ascii "\n"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
