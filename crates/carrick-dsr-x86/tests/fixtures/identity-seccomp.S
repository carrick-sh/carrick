// Install an allow-all seccomp filter, then issue identity syscalls. The live
// JIT gate must fall back so every getpid/gettid is visible to seccomp.
.global _start
.section .text
_start:
    mov $157, %rax                  // prctl(PR_SET_NO_NEW_PRIVS, 1)
    mov $38, %rdi
    mov $1, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    syscall
    test %rax, %rax
    jne fail

    mov $317, %rax                  // seccomp(SET_MODE_FILTER, 0, &prog)
    mov $1, %rdi
    xor %rsi, %rsi
    lea program(%rip), %rdx
    syscall
    test %rax, %rax
    jne fail

    mov $10, %r12
1:
    mov $39, %rax                   // getpid (must dispatch)
    syscall
    mov $186, %rax                  // gettid (must dispatch)
    syscall
    dec %r12
    jnz 1b
    xor %rdi, %rdi
    mov $231, %rax
    syscall
fail:
    mov $99, %rdi
    mov $231, %rax
    syscall

.section .data
.align 8
filter:
    .short 0x06                     // BPF_RET | BPF_K
    .byte 0, 0
    .long 0x7fff0000                // SECCOMP_RET_ALLOW
program:
    .short 1
    .zero 6
    .quad filter
