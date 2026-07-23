/*
 * A blocked synchronous instruction-fetch SIGSEGV must terminate without
 * entering its handler. A two-byte NOP starts at the final executable byte and
 * crosses into a readable non-executable page, producing SEGV_ACCERR.
 */
.global _start
.type _start,@function
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000000, action+8(%rip)  /* SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $13, %eax                    /* rt_sigaction(SIGSEGV) */
    mov $11, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed

    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js setup_failed
    mov %rax, mapping(%rip)
    movb $0x66, 4095(%rax)
    movb $0x90, 4096(%rax)
    movb $0xc3, 4097(%rax)

    mov %rax, %rdi
    mov $4096, %esi
    mov $5, %edx                     /* first page RX */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_failed
    mov mapping(%rip), %rdi
    add $4096, %rdi
    mov $4096, %esi
    mov $1, %edx                     /* continuation readable but non-exec */
    mov $10, %eax
    syscall
    test %rax, %rax
    jne setup_failed

    movq $0x400, blocked_mask(%rip)  /* sigmask bit SIGSEGV-1 */
    mov $14, %eax                    /* rt_sigprocmask(SIG_BLOCK, ...) */
    xor %edi, %edi
    lea blocked_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed

    mov mapping(%rip), %rax
    add $4095, %rax
blocked_fetch:
    call *%rax

    mov $78, %edi                    /* blocked fetch unexpectedly resumed */
    jmp exit_group

handler:
    mov $77, %edi                    /* blocked fetch incorrectly entered handler */
    jmp exit_group

restorer:
    mov $15, %eax
    syscall
    ud2

setup_failed:
    mov $79, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .data
.balign 8
action:
    .quad 0, 0, 0, 0
blocked_mask:
    .quad 0
mapping:
    .quad 0

.section .note.GNU-stack,"",@progbits
