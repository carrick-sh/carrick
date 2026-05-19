// Smallest possible fork(2) probe.
//
// Calls clone(SIGCHLD, 0, 0, 0, 0) — the encoding musl's fork() uses
// — then both parent and child write a single byte to stdout and
// exit_group. Parent prints 'P'+exit_code 42; child prints 'C'+exit
// 17.
//
// We do NOT call wait4 yet. The parent process exits while the child
// is still alive; the host's carrick process for the child will then
// be reparented and continue independently. The carrick runner sees
// the *parent* host process's stdout + exit. The child host process's
// output appears either interleaved or as orphaned bytes; either way
// the simple existence of a non-crashing run with both 'P' and 'C'
// arriving somewhere is the win.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    // clone(flags=SIGCHLD=17, child_stack=0, parent_tid=0, tls=0, child_tid=0)
    mov x0, #17        // SIGCHLD
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220       // SYS_clone
    svc #0

    // x0 now holds the clone return value: 0 in child, pid in parent.
    cmp x0, #0
    b.eq child

parent:
    // write(1, "P\n", 2)
    mov x0, #1
    adrp x1, parent_msg
    add x1, x1, :lo12:parent_msg
    mov x2, #2
    mov x8, #64
    svc #0

    // exit_group(42)
    mov x0, #42
    mov x8, #94
    svc #0

child:
    // write(1, "C\n", 2)
    mov x0, #1
    adrp x1, child_msg
    add x1, x1, :lo12:child_msg
    mov x2, #2
    mov x8, #64
    svc #0

    // exit_group(17)
    mov x0, #17
    mov x8, #94
    svc #0

1:
    b 1b

    .section .rodata
parent_msg:
    .ascii "P\n"
child_msg:
    .ascii "C\n"
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
