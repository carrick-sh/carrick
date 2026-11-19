// Snapshot RFLAGS and the fifteen non-RSP GPRs before modifying them.
// The write exposes every full-width value to the host test.
.global _start
.text
_start:
    pushfq
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    push %rbp
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rbx
    push %rax

    mov $1, %eax
    mov $1, %edi
    mov %rsp, %rsi
    mov $128, %edx
    syscall

    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
