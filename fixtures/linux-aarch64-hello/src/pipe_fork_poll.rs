// Minimal reproducer for apt update's pipe deadlock.
//
// 1. pipe2(0)              -> (read_fd, write_fd)
// 2. clone(SIGCHLD)        -> parent and child diverge
// 3. parent: ppoll(read_fd, POLLIN, timeout=NULL); read; write 'P'+exit 0
// 4. child:  write(write_fd, "hi", 2); exit 0
//
// Expected: parent's ppoll fires POLLIN as soon as the child writes,
// parent reads "hi", writes "P" to stdout, exits. Total output: "P".
//
// If carrick's pipe-poll-across-fork is broken at the kernel level
// (which is the v1 apt-update blocker), parent's ppoll will block
// forever and we'll time out without ever seeing "P".

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // Layout: sp is 16-byte aligned. We need a small scratch area.
    // Use [sp, #-64]! as our frame:
    //   sp + 0:   pipe2 fds[0] (read end, i32)
    //   sp + 4:   pipe2 fds[1] (write end, i32)
    //   sp + 8:   pollfd  fd:i32 + events:i16 + revents:i16  = 8 bytes
    //   sp + 16:  scratch
    stp xzr, xzr, [sp, #-64]!

    // pipe2(fds, 0)
    mov x0, sp
    mov x1, #0
    mov x8, #59             // SYS_pipe2
    svc #0

    // Load read/write fds.
    ldr w19, [sp]           // read_fd
    ldr w20, [sp, #4]       // write_fd

    // clone(SIGCHLD=17, 0, 0, 0, 0)
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220            // SYS_clone
    svc #0

    cmp x0, #0
    b.eq child

parent:
    // Close write end of pipe — only the child should write.
    mov w0, w20
    mov x8, #57             // SYS_close
    svc #0

    // Build pollfd at sp+8: fd=read_fd, events=POLLIN(1), revents=0
    str w19, [sp, #8]       // pollfd.fd
    mov w0, #1              // POLLIN
    strh w0, [sp, #12]      // pollfd.events
    mov w0, #0
    strh w0, [sp, #14]      // pollfd.revents

    // ppoll(fds=sp+8, nfds=1, timeout=NULL, sigmask=NULL, sigsetsize=0)
    add x0, sp, #8
    mov x1, #1
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #73             // SYS_ppoll
    svc #0

    // Read up to 16 bytes into sp+16 from the read fd.
    mov w0, w19
    add x1, sp, #16
    mov x2, #16
    mov x8, #63             // SYS_read
    svc #0

    // write(1, "P", 1)
    mov w0, #1
    adr x1, msg_p
    mov x2, #1
    mov x8, #64             // SYS_write
    svc #0

    // exit_group(0)
    mov x0, #0
    mov x8, #94
    svc #0

child:
    // Close read end of pipe in the child.
    mov w0, w19
    mov x8, #57             // SYS_close
    svc #0

    // write(write_fd, "hi", 2)
    mov w0, w20
    adr x1, msg_hi
    mov x2, #2
    mov x8, #64             // SYS_write
    svc #0

    // exit_group(0)
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
