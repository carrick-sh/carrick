//! Pure fork(2) latency probe: clone(SIGCHLD) 1000x, parent wait4s each child,
//! child exit_group(0) immediately. No libc, no fs, no dynamic linker, no
//! rootfs needed — run via `carrick run-elf` to measure carrick's REAL
//! per-fork+wait cost with zero confounders. Exit code = 0.
#![no_main]
#![no_std]
use core::arch::global_asm;
use core::panic::PanicInfo;
global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x19, #1000
.Lloop:
    cbz x19, .Ldone
    mov x0, #17        // clone(SIGCHLD)
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, #220
    svc #0
    cbz x0, .Lchild    // x0==0 -> child
    // parent: wait4(pid=x0, status=NULL, options=0, rusage=NULL)
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x8, #260
    svc #0
    sub x19, x19, #1
    b .Lloop
.Lchild:
    mov x0, #0
    mov x8, #94         // exit_group(0)
    svc #0
.Ldone:
    mov x0, #0
    mov x8, #94
    svc #0
"#
);
#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
