#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .equ SYS_WRITE, 64
    .equ SYS_OPENAT, 56
    .equ SYS_CLOSE, 57
    .equ SYS_READ, 63
    .equ SYS_NEWFSTATAT, 79
    .equ SYS_EXIT, 93
    .equ SYS_EXIT_GROUP, 94
    .equ SYS_FUTEX, 98
    .equ SYS_SCHED_YIELD, 124
    .equ SYS_CLONE, 220
    .equ SYS_UNKNOWN_STRESS, 9999
    .equ FUTEX_WAIT_PRIVATE, 128

    .global _start
    .type _start, %function
_start:
    bl spawn_worker0
    bl spawn_worker1
    bl spawn_worker2
    bl spawn_worker3

    adrp x19, child_tids
    add x19, x19, :lo12:child_tids
    mov x20, #0

.Ljoin_next:
    cmp x20, #4
    b.eq .Ldone
    add x21, x19, x20, lsl #2

.Ljoin_one:
    ldr w2, [x21]
    cbz w2, .Ljoined
    mov x0, x21
    mov x1, #FUTEX_WAIT_PRIVATE
    mov x3, #0
    mov x8, #SYS_FUTEX
    svc #0
    b .Ljoin_one

.Ljoined:
    add x20, x20, #1
    b .Ljoin_next

.Ldone:
    mov x0, #1
    adrp x1, done_msg
    add x1, x1, :lo12:done_msg
    mov x2, #7
    mov x8, #SYS_WRITE
    svc #0
    mov x0, #0
    mov x8, #SYS_EXIT_GROUP
    svc #0

spawn_worker0:
    adrp x1, stack0_end
    add x1, x1, :lo12:stack0_end
    b spawn_common
spawn_worker1:
    adrp x1, stack1_end
    add x1, x1, :lo12:stack1_end
    b spawn_common
spawn_worker2:
    adrp x1, stack2_end
    add x1, x1, :lo12:stack2_end
    b spawn_common
spawn_worker3:
    adrp x1, stack3_end
    add x1, x1, :lo12:stack3_end
    b spawn_common

spawn_common:
    adrp x4, next_tid_slot
    add x4, x4, :lo12:next_tid_slot
    ldr w5, [x4]
    adrp x6, child_tids
    add x6, x6, :lo12:child_tids
    add x4, x6, x5, lsl #2
    add w5, w5, #1
    adrp x6, next_tid_slot
    add x6, x6, :lo12:next_tid_slot
    str w5, [x6]
    mov w6, #1
    str w6, [x4]

    mov x0, #0x0f00
    movk x0, #0x21, lsl #16
    mov x2, #0
    mov x3, #0
    mov x8, #SYS_CLONE
    svc #0
    cbz x0, worker_main
    ret

worker_main:
    mov x19, #32

.Lworker_loop:
    mov x0, #-100
    adrp x1, path
    add x1, x1, :lo12:path
    mov x2, #0
    mov x3, #0
    mov x8, #SYS_OPENAT
    svc #0
    cmp x0, #0
    b.lt .Lafter_read
    mov x20, x0
    adrp x1, io_buf
    add x1, x1, :lo12:io_buf
    mov x2, #16
    mov x8, #SYS_READ
    svc #0
    mov x0, x20
    mov x8, #SYS_CLOSE
    svc #0

.Lafter_read:
    mov x0, #-100
    adrp x1, slash_path
    add x1, x1, :lo12:slash_path
    adrp x2, stat_buf
    add x2, x2, :lo12:stat_buf
    mov x3, #0
    mov x8, #SYS_NEWFSTATAT
    svc #0

    mov x8, #SYS_UNKNOWN_STRESS
    svc #0

    mov x8, #SYS_SCHED_YIELD
    svc #0

    subs x19, x19, #1
    b.ne .Lworker_loop

    mov x0, #0
    mov x8, #SYS_EXIT
    svc #0

    .section .rodata
path:
    .asciz "/etc/motd"
slash_path:
    .asciz "/"
done_msg:
    .ascii "stress\n"

    .bss
    .align 4
child_tids:
    .skip 16
next_tid_slot:
    .word 0
io_buf:
    .skip 64
stat_buf:
    .skip 256
    .align 12
stack0:
    .skip 8192
stack0_end:
stack1:
    .skip 8192
stack1_end:
stack2:
    .skip 8192
stack2_end:
stack3:
    .skip 8192
stack3_end:
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
