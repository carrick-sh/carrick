// Independently authored Linux AArch64 fixture, MIT OR Apache-2.0.
// Identical ELF on native Linux, HVF and the bounded native executor.
// PHASE: 0 invalid, 1 unchanged, 2 fresh churn, 3 integer, 4 memory.
#ifndef N
#define N 65536
#endif
#ifndef SAMPLES
#define SAMPLES 10
#endif
.global _start
.text
_start:
    adr x24, path
    mov x0, #-100
    mov x1, x24
    mov x2, #66
    mov x3, #384
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt fail
    mov x8, #57
    svc #0
    mov x21, #SAMPLES
sample:
    mov x0, #2048
    mov x8, #26
    svc #0
    cmp x0, #0
    b.lt fail
    mov x22, x0
#if PHASE == 1
    mov x1, x24
    mov x2, #2
    mov x8, #27
    svc #0
    cmp x0, #0
    b.le fail
    mov x23, x0
#endif
    mov x0, #1
    adr x1, start_time
    mov x8, #113
    svc #0
    cbnz x0, fail
    mov x20, #N
    mov x25, #0
loop:
#if PHASE == 0
    mov x0, #-1
    mov x1, x24
    mov x2, #2
    mov x8, #27
    svc #0
    cmn x0, #9
    b.ne fail
    mov x0, #-1
    mov x1, #0
    mov x8, #28
    svc #0
    cmn x0, #9
    b.ne fail
#elif PHASE == 1
    mov x0, x22
    mov x1, x24
    mov x2, #2
    mov x8, #27
    svc #0
    cmp x0, x23
    b.ne fail
    mov x0, x22
    mov x1, x24
    mov x2, #2
    mov x8, #27
    svc #0
    cmp x0, x23
    b.ne fail
#elif PHASE == 2
    mov x0, x22
    mov x1, x24
    mov x2, #2
    mov x8, #27
    svc #0
    cmp x0, #0
    b.le fail
    mov x1, x0
    mov x0, x22
    mov x8, #28
    svc #0
    cbnz x0, fail
#elif PHASE == 3
    add x25, x25, #7
    sub x25, x25, #6
#elif PHASE == 4
    adr x26, counter
    ldr x25, [x26]
    add x25, x25, #1
    str x25, [x26]
#endif
    sub x20, x20, #1
    cbnz x20, loop
    mov x0, #1
    adr x1, end_time
    mov x8, #113
    svc #0
    cbnz x0, fail
#if PHASE == 3
    mov x0, #N
    cmp x25, x0
    b.ne fail
#elif PHASE == 4
    adr x26, counter
    ldr x25, [x26]
    mov x0, #N
    cmp x25, x0
    b.ne fail
    str xzr, [x26]
#endif
    mov x0, x22
    mov x1, #0x541b
    adr x2, queue_bytes
    mov x8, #29
    svc #0
    cbnz x0, fail
    adr x26, queue_bytes
    ldr w25, [x26]
#if PHASE == 2
#if N <= 16384
    mov x0, #(N * 16)
#else
    mov x0, #16
    movk x0, #4, lsl #16
#endif
    cmp x25, x0
    b.ne fail
    mov x0, x22
    adr x1, events
    mov x2, #16
    movk x2, #4, lsl #16
    mov x8, #63
    svc #0
    cmp x0, x25
    b.ne fail
    adr x26, events
    mov x19, #1
drain:
    ldr w0, [x26]
    ldr w1, [x26, #4]
    mov x2, #0x4000
    cmp x1, x2
    b.eq overflow
    cmp x0, x19
    b.ne fail
    mov x2, #0x8000
    cmp x1, x2
    b.ne fail
    b drained_event
overflow:
    mov w2, #-1
    cmp w0, w2
    b.ne fail
    cmp x25, #16
    b.ne fail
drained_event:
    ldr x0, [x26, #8]
    cbnz x0, fail
    add x26, x26, #16
    add x19, x19, #1
    sub x25, x25, #16
    cbnz x25, drain
#else
    cbnz x25, fail
#endif
    mov x0, #1
    adr x1, record
    mov x2, #56
    mov x8, #64
    svc #0
    cmp x0, #56
    b.ne fail
    mov x0, x22
    mov x8, #57
    svc #0
    cbnz x0, fail
    sub x21, x21, #1
    cbnz x21, sample
    mov x0, #0
    mov x8, #93
    svc #0
fail:
    mov x0, #99
    mov x8, #93
    svc #0
.data
.balign 16
record:
    .quad PHASE, N
start_time: .quad 0, 0
end_time: .quad 0, 0
queue_bytes: .quad 0
counter: .quad 0
path: .asciz "/data"
.balign 16
events: .space 262160
