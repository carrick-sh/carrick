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
.equ CTX_EXIT_TARGET, 1080
.equ CTX_EXIT_SOURCE, 1088
.equ CTX_EXIT_STATUS, 1096
.equ CTX_GATEWAY_PHASE, 1152

.globl _carrick_dsr_enter_raw
_carrick_dsr_enter_raw:
    // Physical x28 is the translated-thread context pointer. Guest x18 and
    // guest x28 stay virtualized in snapshot.x[] throughout translation.
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
    mov x28, x19

    ldr x9, [x28, #SNAP_PSTATE]
    msr nzcv, x9
    ldr w9, [x28, #SNAP_FPSR]
    msr fpsr, x9
    ldr w9, [x28, #SNAP_FPCR]
    msr fpcr, x9
    ldp q0, q1, [x28, #(SNAP_V0 + 0)]
    ldp q2, q3, [x28, #(SNAP_V0 + 32)]
    ldp q4, q5, [x28, #(SNAP_V0 + 64)]
    ldp q6, q7, [x28, #(SNAP_V0 + 96)]
    ldp q8, q9, [x28, #(SNAP_V0 + 128)]
    ldp q10, q11, [x28, #(SNAP_V0 + 160)]
    ldp q12, q13, [x28, #(SNAP_V0 + 192)]
    ldp q14, q15, [x28, #(SNAP_V0 + 224)]
    ldp q16, q17, [x28, #(SNAP_V0 + 256)]
    ldp q18, q19, [x28, #(SNAP_V0 + 288)]
    ldp q20, q21, [x28, #(SNAP_V0 + 320)]
    ldp q22, q23, [x28, #(SNAP_V0 + 352)]
    ldp q24, q25, [x28, #(SNAP_V0 + 384)]
    ldp q26, q27, [x28, #(SNAP_V0 + 416)]
    ldp q28, q29, [x28, #(SNAP_V0 + 448)]
    ldp q30, q31, [x28, #(SNAP_V0 + 480)]

    ldp x0, x1, [x28, #0]
    ldp x2, x3, [x28, #16]
    ldp x4, x5, [x28, #32]
    ldp x6, x7, [x28, #48]
    ldp x8, x9, [x28, #64]
    ldp x10, x11, [x28, #80]
    ldp x12, x13, [x28, #96]
    ldp x14, x15, [x28, #112]
    ldr x16, [x28, #128]
    ldp x19, x20, [x28, #152]
    ldp x21, x22, [x28, #168]
    ldp x23, x24, [x28, #184]
    ldp x25, x26, [x28, #200]
    ldr x27, [x28, #216]
    ldp x29, x30, [x28, #232]
    ldr x17, [x28, #SNAP_SP]
    mov sp, x17
    // Physical x18 is reserved by the custom-x18 ABI and guest x18 is
    // virtualized, so it is the only scratch register that does not destroy
    // guest state at the first translated instruction. Restore guest x17
    // before entering the generation guard; the guard may then snapshot the
    // current x16/x17 state uniformly for initial and directly linked blocks.
    ldr x18, [x28, #CTX_ENTRY]
    ldr x17, [x28, #136]
    br x18

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
.globl _carrick_dsr_exit_direct
.globl _carrick_dsr_exit_indirect
.globl _carrick_dsr_exit_sensitive
.globl _carrick_dsr_exit_unsupported
.globl _carrick_dsr_exit_signal
_carrick_dsr_exit_signal:
    // The signal handler already captured the full guest state. It switches
    // to a 16-byte recovery slot below the saved host SP and writes the active
    // context pointer there, avoiding Darwin's unreliable custom-x28 register
    // restoration on signal return.
    ldr x9, [sp]
    ldr x17, [x9, #CTX_HOST_SP]
    mov sp, x17
    mov x19, x9
    mov w10, #2
    str w10, [x19, #CTX_GATEWAY_PHASE]
    bl _carrick_native_dsr_enter_host_abi
    mov x9, x19
    b carrick_dsr_restore_host

_carrick_dsr_exit_syscall:
_carrick_dsr_exit_direct:
_carrick_dsr_exit_indirect:
_carrick_dsr_exit_sensitive:
_carrick_dsr_exit_unsupported:
.globl _carrick_dsr_exit_common_start
_carrick_dsr_exit_common_start:
carrick_dsr_exit_common:
    // The emitted stub saved guest x17 through physical x28 before branching.
    stp x0, x1, [x28, #0]
    stp x2, x3, [x28, #16]
    stp x4, x5, [x28, #32]
    stp x6, x7, [x28, #48]
    stp x8, x9, [x28, #64]
    stp x10, x11, [x28, #80]
    stp x12, x13, [x28, #96]
    stp x14, x15, [x28, #112]
    str x16, [x28, #128]
    stp x19, x20, [x28, #152]
    stp x21, x22, [x28, #168]
    stp x23, x24, [x28, #184]
    stp x25, x26, [x28, #200]
    str x27, [x28, #216]
    stp x29, x30, [x28, #232]
    mov x17, sp
    str x17, [x28, #SNAP_SP]
    ldr x17, [x28, #CTX_EXIT_TARGET]
    str x17, [x28, #SNAP_PC]
    mrs x17, nzcv
    str x17, [x28, #SNAP_PSTATE]
    mrs x17, fpsr
    str w17, [x28, #SNAP_FPSR]
    mrs x17, fpcr
    str w17, [x28, #SNAP_FPCR]
    stp q0, q1, [x28, #(SNAP_V0 + 0)]
    stp q2, q3, [x28, #(SNAP_V0 + 32)]
    stp q4, q5, [x28, #(SNAP_V0 + 64)]
    stp q6, q7, [x28, #(SNAP_V0 + 96)]
    stp q8, q9, [x28, #(SNAP_V0 + 128)]
    stp q10, q11, [x28, #(SNAP_V0 + 160)]
    stp q12, q13, [x28, #(SNAP_V0 + 192)]
    stp q14, q15, [x28, #(SNAP_V0 + 224)]
    stp q16, q17, [x28, #(SNAP_V0 + 256)]
    stp q18, q19, [x28, #(SNAP_V0 + 288)]
    stp q20, q21, [x28, #(SNAP_V0 + 320)]
    stp q22, q23, [x28, #(SNAP_V0 + 352)]
    stp q24, q25, [x28, #(SNAP_V0 + 384)]
    stp q26, q27, [x28, #(SNAP_V0 + 416)]
    stp q28, q29, [x28, #(SNAP_V0 + 448)]
    stp q30, q31, [x28, #(SNAP_V0 + 480)]

    // Phase 2 means the complete guest snapshot and typed exit are stable.
    // A kick during the following host-mask transition may therefore abandon
    // its interrupted host frame through carrick_dsr_exit_signal.
    mov w17, #2
    str w17, [x28, #CTX_GATEWAY_PHASE]
    mov x19, x28
    ldr x17, [x19, #CTX_HOST_SP]
    mov sp, x17
    bl _carrick_native_dsr_enter_host_abi
.globl _carrick_dsr_exit_common_end
_carrick_dsr_exit_common_end:
    mov x9, x19
carrick_dsr_restore_host:
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
    ldr w0, [x9, #CTX_EXIT_STATUS]
    ret
