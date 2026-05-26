// Concurrent stage-1 page-table churn across threads.
//
// Four worker threads each loop: mmap a RW page, store a sentinel, mprotect it
// PROT_NONE then back to RW, verify the sentinel survived, and munmap. This
// hammers carrick's runtime stage-1 page-table editor (split/coalesce + EL1
// TLBI) from multiple vCPUs at once. With the per-engine page-table manager,
// two threads splitting blocks concurrently can hand out the SAME spare table
// page -> a clobbered sub-table -> a wrong/invalid mapping, which surfaces here
// as a sentinel-readback mismatch (exit_group 99) or an unexpected fault
// (carrick reports 139). A clean run is exit 0 ("churn\n").

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .equ SYS_WRITE, 64
    .equ SYS_EXIT, 93
    .equ SYS_EXIT_GROUP, 94
    .equ SYS_FUTEX, 98
    .equ SYS_SCHED_YIELD, 124
    .equ SYS_MUNMAP, 215
    .equ SYS_CLONE, 220
    .equ SYS_MMAP, 222
    .equ SYS_MPROTECT, 226
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
    mov x2, #6
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

    // clone(CLONE_VM|CLONE_THREAD|... , child_stack=x1)
    mov x0, #0x0f00
    movk x0, #0x21, lsl #16
    mov x2, #0
    mov x3, #0
    mov x8, #SYS_CLONE
    svc #0
    cbz x0, worker_main
    ret

worker_main:
    mov x19, #200          // iterations

.Lloop:
    // p = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
    mov x0, #0
    mov x1, #4096
    mov x2, #3             // PROT_READ|PROT_WRITE
    mov x3, #0x22          // MAP_PRIVATE|MAP_ANONYMOUS
    mov x4, #-1
    mov x5, #0
    mov x8, #SYS_MMAP
    svc #0
    cmp x0, #0
    b.lt .Lnext            // mmap failed (pool/arena pressure): skip, not a bug
    mov x22, x0

    movz w9, #0xBEEF
    movk w9, #0xDEAD, lsl #16
    str w9, [x22]          // sentinel

    // mprotect(p, 4096, PROT_NONE)
    mov x0, x22
    mov x1, #4096
    mov x2, #0
    mov x8, #SYS_MPROTECT
    svc #0

    // mprotect(p, 4096, PROT_READ|PROT_WRITE)
    mov x0, x22
    mov x1, #4096
    mov x2, #3
    mov x8, #SYS_MPROTECT
    svc #0

    // verify the sentinel survived the protect round-trip
    ldr w10, [x22]
    movz w11, #0xBEEF
    movk w11, #0xDEAD, lsl #16
    cmp w10, w11
    b.ne .Lcorrupt

    // munmap(p, 4096)
    mov x0, x22
    mov x1, #4096
    mov x8, #SYS_MUNMAP
    svc #0

.Lnext:
    mov x8, #SYS_SCHED_YIELD
    svc #0
    subs x19, x19, #1
    b.ne .Lloop

    mov x0, #0
    mov x8, #SYS_EXIT
    svc #0

.Lcorrupt:
    // Concurrent edit corrupted this thread's mapping: kill the process so the
    // harness sees a distinctive non-zero code.
    mov x0, #99
    mov x8, #SYS_EXIT_GROUP
    svc #0

    .section .rodata
done_msg:
    .ascii "churn\n"

    .bss
    .align 4
child_tids:
    .skip 16
next_tid_slot:
    .word 0
    .align 12
stack0:
    .skip 16384
stack0_end:
stack1:
    .skip 16384
stack1_end:
stack2:
    .skip 16384
stack2_end:
stack3:
    .skip 16384
stack3_end:
"#
);

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
