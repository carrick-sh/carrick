//! One-carrier boundedness probe: clone(SIGCHLD) 10,000 times, parent wait4s
//! each child, child exit_group(0)s immediately. This intentionally mirrors
//! `fork_bench.rs` while leaving the historical 1,000-cycle latency fixture
//! unchanged. No libc, filesystem, dynamic linker, or rootfs is involved.
#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x19, #10000
.Lloop:
    cbz x19, .Ldone
    mov x0, #17        // clone(SIGCHLD)
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220
    svc #0
    tbnz x0, #63, .Lfail
    cbz x0, .Lchild
    // parent: wait4(pid=x0, status=NULL, options=0, rusage=NULL)
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x8, #260
    svc #0
    tbnz x0, #63, .Lfail
    sub x19, x19, #1
    b .Lloop
.Lchild:
    mov x0, #0
    mov x8, #94        // exit_group(0)
    svc #0
.Ldone:
    mov x0, #0
    mov x8, #94
    svc #0
.Lfail:
    mov x0, #1
    mov x8, #94        // exit_group(1)
    svc #0
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
