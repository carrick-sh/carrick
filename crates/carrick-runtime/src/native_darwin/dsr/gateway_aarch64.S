.text
.p2align 2

.equ SNAP_SP, 248
.equ SNAP_PC, 256
.equ SNAP_PSTATE, 264
.equ SNAP_V0, 272
.equ SNAP_FPSR, 784
.equ SNAP_FPCR, 788
.equ CTX_HOST_SP, 832
.equ CTX_HOST_X19, 840
.equ CTX_HOST_V8, 944
.equ CTX_ENTRY, 1072
.equ CTX_EXIT_RESUME, 1080

.globl _carrick_dsr_enter_raw
_carrick_dsr_enter_raw:
    // Physical x18 is the translated-thread context pointer. Guest x18 stays
    // virtualized in snapshot.x[18] for the entire translated interval.
    mov x9, sp
    str x9, [x0, #CTX_HOST_SP]
    add x10, x0, #CTX_HOST_X19
    stp x19, x20, [x10, #0]
    stp x21, x22, [x10, #16]
    stp x23, x24, [x10, #32]
    stp x25, x26, [x10, #48]
    stp x27, x28, [x10, #64]
    stp x29, x30, [x10, #80]
    add x10, x0, #CTX_HOST_V8
    stp q8, q9, [x10, #0]
    stp q10, q11, [x10, #32]
    stp q12, q13, [x10, #64]
    stp q14, q15, [x10, #96]

    mov x19, x0
    bl _carrick_native_dsr_enter_guest_abi
    cbnz w0, 9f
    mov x18, x19

    ldr x9, [x18, #SNAP_PSTATE]
    msr nzcv, x9
    ldr w9, [x18, #SNAP_FPSR]
    msr fpsr, x9
    ldr w9, [x18, #SNAP_FPCR]
    msr fpcr, x9
    ldp q0, q1, [x18, #(SNAP_V0 + 0)]
    ldp q2, q3, [x18, #(SNAP_V0 + 32)]
    ldp q4, q5, [x18, #(SNAP_V0 + 64)]
    ldp q6, q7, [x18, #(SNAP_V0 + 96)]
    ldp q8, q9, [x18, #(SNAP_V0 + 128)]
    ldp q10, q11, [x18, #(SNAP_V0 + 160)]
    ldp q12, q13, [x18, #(SNAP_V0 + 192)]
    ldp q14, q15, [x18, #(SNAP_V0 + 224)]
    ldp q16, q17, [x18, #(SNAP_V0 + 256)]
    ldp q18, q19, [x18, #(SNAP_V0 + 288)]
    ldp q20, q21, [x18, #(SNAP_V0 + 320)]
    ldp q22, q23, [x18, #(SNAP_V0 + 352)]
    ldp q24, q25, [x18, #(SNAP_V0 + 384)]
    ldp q26, q27, [x18, #(SNAP_V0 + 416)]
    ldp q28, q29, [x18, #(SNAP_V0 + 448)]
    ldp q30, q31, [x18, #(SNAP_V0 + 480)]

    ldp x0, x1, [x18, #0]
    ldp x2, x3, [x18, #16]
    ldp x4, x5, [x18, #32]
    ldp x6, x7, [x18, #48]
    ldp x8, x9, [x18, #64]
    ldp x10, x11, [x18, #80]
    ldp x12, x13, [x18, #96]
    ldp x14, x15, [x18, #112]
    ldr x16, [x18, #128]
    ldp x19, x20, [x18, #152]
    ldp x21, x22, [x18, #168]
    ldp x23, x24, [x18, #184]
    ldp x25, x26, [x18, #200]
    ldp x27, x28, [x18, #216]
    ldp x29, x30, [x18, #232]
    ldr x17, [x18, #SNAP_SP]
    mov sp, x17
    ldr x17, [x18, #CTX_ENTRY]
    br x17

9:
    mov x9, x19
    add x10, x9, #CTX_HOST_V8
    ldp q8, q9, [x10, #0]
    ldp q10, q11, [x10, #32]
    ldp q12, q13, [x10, #64]
    ldp q14, q15, [x10, #96]
    add x10, x9, #CTX_HOST_X19
    ldp x19, x20, [x10, #0]
    ldp x21, x22, [x10, #16]
    ldp x23, x24, [x10, #32]
    ldp x25, x26, [x10, #48]
    ldp x27, x28, [x10, #64]
    ldp x29, x30, [x10, #80]
    mov w0, #-1
    ret

.p2align 2
.globl _carrick_dsr_exit_syscall
_carrick_dsr_exit_syscall:
    // The emitted stub saved guest x17 through physical x18 before branching.
    stp x0, x1, [x18, #0]
    stp x2, x3, [x18, #16]
    stp x4, x5, [x18, #32]
    stp x6, x7, [x18, #48]
    stp x8, x9, [x18, #64]
    stp x10, x11, [x18, #80]
    stp x12, x13, [x18, #96]
    stp x14, x15, [x18, #112]
    str x16, [x18, #128]
    stp x19, x20, [x18, #152]
    stp x21, x22, [x18, #168]
    stp x23, x24, [x18, #184]
    stp x25, x26, [x18, #200]
    stp x27, x28, [x18, #216]
    stp x29, x30, [x18, #232]
    mov x17, sp
    str x17, [x18, #SNAP_SP]
    ldr x17, [x18, #CTX_EXIT_RESUME]
    str x17, [x18, #SNAP_PC]
    mrs x17, nzcv
    str x17, [x18, #SNAP_PSTATE]
    mrs x17, fpsr
    str w17, [x18, #SNAP_FPSR]
    mrs x17, fpcr
    str w17, [x18, #SNAP_FPCR]
    stp q0, q1, [x18, #(SNAP_V0 + 0)]
    stp q2, q3, [x18, #(SNAP_V0 + 32)]
    stp q4, q5, [x18, #(SNAP_V0 + 64)]
    stp q6, q7, [x18, #(SNAP_V0 + 96)]
    stp q8, q9, [x18, #(SNAP_V0 + 128)]
    stp q10, q11, [x18, #(SNAP_V0 + 160)]
    stp q12, q13, [x18, #(SNAP_V0 + 192)]
    stp q14, q15, [x18, #(SNAP_V0 + 224)]
    stp q16, q17, [x18, #(SNAP_V0 + 256)]
    stp q18, q19, [x18, #(SNAP_V0 + 288)]
    stp q20, q21, [x18, #(SNAP_V0 + 320)]
    stp q22, q23, [x18, #(SNAP_V0 + 352)]
    stp q24, q25, [x18, #(SNAP_V0 + 384)]
    stp q26, q27, [x18, #(SNAP_V0 + 416)]
    stp q28, q29, [x18, #(SNAP_V0 + 448)]
    stp q30, q31, [x18, #(SNAP_V0 + 480)]

    mov x19, x18
    ldr x17, [x19, #CTX_HOST_SP]
    mov sp, x17
    bl _carrick_native_dsr_enter_host_abi
    mov x9, x19
    add x10, x9, #CTX_HOST_V8
    ldp q8, q9, [x10, #0]
    ldp q10, q11, [x10, #32]
    ldp q12, q13, [x10, #64]
    ldp q14, q15, [x10, #96]
    add x10, x9, #CTX_HOST_X19
    ldp x19, x20, [x10, #0]
    ldp x21, x22, [x10, #16]
    ldp x23, x24, [x10, #32]
    ldp x25, x26, [x10, #48]
    ldp x27, x28, [x10, #64]
    ldp x29, x30, [x10, #80]
    mov w0, #1
    ret
