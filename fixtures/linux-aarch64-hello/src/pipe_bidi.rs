// Reproducer for apt's pipe pattern:
//
//   parent: pipe_p2c (parent writes -> child reads)
//   parent: pipe_c2p (child writes -> parent reads)
//   parent: fork; child:
//       writes greeting "G" to pipe_c2p_write
//       ppoll(pipe_p2c_read, POLLIN)        <- blocks until parent sends
//       reads pipe_p2c_read
//       writes ack "K" to pipe_c2p_write
//       exit_group(0)
//   parent:
//       ppoll(pipe_c2p_read, POLLIN)       <- blocks until child's greeting
//       reads pipe_c2p_read -> "G"
//       writes "U" to pipe_p2c_write        <- the URI equivalent
//       ppoll(pipe_c2p_read, POLLIN)       <- blocks until child's ack
//       reads pipe_c2p_read -> "K"
//       writes "OK" to stdout
//       exit_group(0)
//
// If the parent's ppoll never sees POLLIN despite the child writing,
// we have the same deadlock as apt update and can debug it in
// isolation (no glibc, no execve, ~200 lines of asm).

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // Frame layout sp+0..127 (128 bytes total, 16-byte aligned):
    //  sp+0:   pipe_p2c fds  (read i32, write i32)
    //  sp+8:   pipe_c2p fds  (read i32, write i32)
    //  sp+16:  pollfd p2c_read   (fd i32, events i16, revents i16)
    //  sp+24:  pollfd c2p_read   (fd i32, events i16, revents i16)
    //  sp+32:  scratch read buffer
    sub sp, sp, #128

    // pipe2(sp+0, 0) — parent->child pipe
    mov x0, sp
    mov x1, #0
    mov x8, #59
    svc #0

    // pipe2(sp+8, 0) — child->parent pipe
    add x0, sp, #8
    mov x1, #0
    mov x8, #59
    svc #0

    // Cache the four fds in callee-saved regs.
    ldr w19, [sp]        // p2c_read
    ldr w20, [sp, #4]    // p2c_write
    ldr w21, [sp, #8]    // c2p_read
    ldr w22, [sp, #12]   // c2p_write

    // clone(SIGCHLD=17, 0, 0, 0, 0)
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
    // close unused ends.
    mov w0, w20          // close p2c_write... no wait parent NEEDS p2c_write
    // Actually parent NEEDS p2c_write (to send U) and c2p_read (to recv).
    // Close p2c_read and c2p_write in parent.
    mov w0, w19
    mov x8, #57
    svc #0
    mov w0, w22
    mov x8, #57
    svc #0

    // Build pollfd at sp+24: fd = c2p_read, events = POLLIN
    str w21, [sp, #24]
    mov w0, #1
    strh w0, [sp, #28]
    mov w0, #0
    strh w0, [sp, #30]

    // ppoll(fds=sp+24, 1, NULL, NULL, 0)
    add x0, sp, #24
    mov x1, #1
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #73
    svc #0

    // read(c2p_read, sp+32, 16)
    mov w0, w21
    add x1, sp, #32
    mov x2, #16
    mov x8, #63
    svc #0

    // write(p2c_write, "U", 1)
    mov w0, w20
    adr x1, msg_u
    mov x2, #1
    mov x8, #64
    svc #0

    // ppoll again — wait for child's ack
    str w21, [sp, #24]
    mov w0, #1
    strh w0, [sp, #28]
    mov w0, #0
    strh w0, [sp, #30]
    add x0, sp, #24
    mov x1, #1
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #73
    svc #0

    // read second message
    mov w0, w21
    add x1, sp, #32
    mov x2, #16
    mov x8, #63
    svc #0

    // write(1, "OK\n", 3)
    mov w0, #1
    adr x1, msg_ok
    mov x2, #3
    mov x8, #64
    svc #0

    // exit_group(0)
    mov x0, #0
    mov x8, #94
    svc #0

child:
    // close unused ends in child.
    mov w0, w20          // close p2c_write
    mov x8, #57
    svc #0
    mov w0, w21          // close c2p_read
    mov x8, #57
    svc #0

    // write(c2p_write, "G", 1) — greeting
    mov w0, w22
    adr x1, msg_g
    mov x2, #1
    mov x8, #64
    svc #0

    // ppoll(p2c_read, POLLIN) — wait for "U"
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

    // read(p2c_read, sp+32, 16)
    mov w0, w19
    add x1, sp, #32
    mov x2, #16
    mov x8, #63
    svc #0

    // write(c2p_write, "K", 1) — ack
    mov w0, w22
    adr x1, msg_k
    mov x2, #1
    mov x8, #64
    svc #0

    // exit_group(0)
    mov x0, #0
    mov x8, #94
    svc #0

msg_u: .ascii "U"
msg_g: .ascii "G"
msg_k: .ascii "K"
msg_ok: .ascii "OK\n"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
