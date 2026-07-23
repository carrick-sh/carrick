/*
 * Invalid RDPKRU/WRPKRU operands raise Linux-visible #GP as
 * SIGSEGV/SI_KERNEL/address 0. The SA_SIGINFO handler repairs saved ECX/EDX;
 * rt_sigreturn retries the still-unexecuted instruction.
 */
.global _start
.type _start,@function
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000004, action+8(%rip) /* SA_RESTORER | SA_SIGINFO */
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
    jne fail

    movl $0, handled(%rip)

    mov $1, %ecx                     /* invalid RDPKRU ECX */
retry_rdpkru:
    rdpkru
    test %eax, %eax                  /* initial virtual PKRU */
    jne fail
    test %edx, %edx
    jne fail

    mov $3, %eax
    xor %ecx, %ecx
    mov $1, %edx                     /* invalid WRPKRU EDX */
retry_wrpkru:
    wrpkru

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne fail_reset
    test %edx, %edx
    jne fail_reset
    cmpl $2, handled(%rip)
    jne fail_reset

    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    mov $0, %edi
    mov $231, %eax                   /* exit_group */
    syscall

fail_reset:
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
fail:
    mov $1, %edi
    mov $231, %eax
    syscall
.size _start, .-_start

.type handler,@function
handler:
    cmp $11, %edi                    /* SIGSEGV */
    jne handler_bad
    cmpl $128, 8(%rsi)               /* SI_KERNEL */
    jne handler_bad
    cmpq $0, 16(%rsi)                /* si_addr */
    jne handler_bad
    incl handled(%rip)
    movq $0, 152(%rdx)               /* uc_mcontext.rcx */
    movq $0, 136(%rdx)               /* uc_mcontext.rdx */
    ret
handler_bad:
    movl $99, handled(%rip)
    addq $3, 168(%rdx)               /* avoid an endless retry on bad siginfo */
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
    syscall
.size restorer, .-restorer

.section .data
.balign 8
action:
    .quad 0, 0, 0, 0
handled:
    .long 0

.section .note.GNU-stack,"",@progbits
