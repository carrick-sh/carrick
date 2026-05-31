#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .equ SYS_WRITE, 64
    .equ SYS_EXIT, 93
    .equ SYS_MUNMAP, 215
    .equ SYS_MMAP, 222
    .equ SYS_MADVISE, 233

    .equ PROT_READ_WRITE, 3
    .equ MAP_PRIVATE_ANON, 0x22
    .equ MADV_DONTFORK, 10

    .global _start
    .type _start, %function
_start:
    // mmap(0x7c1000000, 0x7f000, PROT_READ|PROT_WRITE,
    //      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    //
    // This is the high-end hint from the V8 reservation pattern that surfaced
    // during Node startup. Linux may ignore the hint, but it must not report
    // 0xffffffff as a successful address.
    movz x0, #0xc100, lsl #16
    movk x0, #0x7, lsl #32
    movz x1, #0xf000
    movk x1, #0x7, lsl #16
    mov x2, #PROT_READ_WRITE
    mov x3, #MAP_PRIVATE_ANON
    mov x4, #-1
    mov x5, #0
    mov x8, #SYS_MMAP
    svc #0
    mov x19, x0

    tbnz x19, #63, mmap_negative

    movz x20, #0xffff
    movk x20, #0xffff, lsl #16
    cmp x19, x20
    b.eq mmap_low32

    // madvise(mapped, 0x7f000, MADV_DONTFORK)
    mov x0, x19
    movz x1, #0xf000
    movk x1, #0x7, lsl #16
    mov x2, #MADV_DONTFORK
    mov x8, #SYS_MADVISE
    svc #0
    cbnz x0, madvise_failed

    // munmap(mapped, 0x7f000)
    mov x0, x19
    movz x1, #0xf000
    movk x1, #0x7, lsl #16
    mov x8, #SYS_MUNMAP
    svc #0
    cbnz x0, munmap_failed

    adrp x1, msg_ok
    add x1, x1, :lo12:msg_ok
    mov x2, #3
    mov x0, #1
    mov x8, #SYS_WRITE
    svc #0
    mov x0, #0
    mov x8, #SYS_EXIT
    svc #0

mmap_negative:
    adrp x1, msg_mmap_negative
    add x1, x1, :lo12:msg_mmap_negative
    mov x2, #14
    b write_and_exit_10

mmap_low32:
    adrp x1, msg_mmap_low32
    add x1, x1, :lo12:msg_mmap_low32
    mov x2, #11
    b write_and_exit_11

madvise_failed:
    adrp x1, msg_madvise_failed
    add x1, x1, :lo12:msg_madvise_failed
    mov x2, #15
    b write_and_exit_12

munmap_failed:
    adrp x1, msg_munmap_failed
    add x1, x1, :lo12:msg_munmap_failed
    mov x2, #14
    b write_and_exit_13

write_and_exit_10:
    bl write_msg
    mov x0, #10
    b exit
write_and_exit_11:
    bl write_msg
    mov x0, #11
    b exit
write_and_exit_12:
    bl write_msg
    mov x0, #12
    b exit
write_and_exit_13:
    bl write_msg
    mov x0, #13
    b exit

write_msg:
    mov x0, #1
    mov x8, #SYS_WRITE
    svc #0
    ret

exit:
    mov x8, #SYS_EXIT
    svc #0

1:
    b 1b

    .section .rodata
msg_ok:
    .ascii "ok\n"
msg_mmap_negative:
    .ascii "mmap-negative\n"
msg_mmap_low32:
    .ascii "mmap-low32\n"
msg_madvise_failed:
    .ascii "madvise-failed\n"
msg_munmap_failed:
    .ascii "munmap-failed\n"
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
