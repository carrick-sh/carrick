/*
 * Native-x86 xstate ownership reducer.
 *
 * First, xstate_fpu_target runs through a full Rust entry so its translation is
 * cached and guest xmm0=37 is materialized. Its fallthrough performs getpid and
 * resumes at the integer-only source. That source can then take an already-
 * patched direct edge back into the cached FPU target. Local-only gating skips
 * the restore and exposes physical host xmm0; a selected cold-edge barrier
 * returns through Rust and lets the target's own FPU classification restore G.
 */
.global _start
.type _start,@function
_start:
    movabs $37, %rax
    movq %rax, %xmm0
    xor %ebx, %ebx
    mov $39, %eax                  /* Linux x86_64 getpid */
    syscall

.global xstate_fpu_target
.type xstate_fpu_target,@function
xstate_fpu_target:
    movq %xmm0, %rcx
    test %ebx, %ebx
    jne xstate_consume

xstate_warm_fallthrough:
    mov $1, %ebx
    mov $39, %eax                  /* return through Rust once */
    syscall

.global xstate_integer_source
.type xstate_integer_source,@function
xstate_integer_source:
    xor %eax, %eax                 /* integer-only source body */
    jmp xstate_fpu_target

xstate_consume:
    mov %ecx, %edi
    mov $231, %eax                 /* Linux x86_64 exit_group */
    syscall
.size _start, .-_start
