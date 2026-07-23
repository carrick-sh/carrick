/*
 * ARCH_SET_FS(0) isolation. A nonzero guest TLS base must serve copied fs:
 * reads, then setting FS to zero must make the same copied access fault at
 * guest address zero rather than reading Carrick's host TLS.
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

    mov $158, %eax                   /* arch_prctl(ARCH_SET_FS, tls) */
    mov $0x1002, %edi
    lea guest_tls(%rip), %rsi
    syscall
    test %rax, %rax
    jne fail
    mov %fs:0, %rax
    movabs $0x1122334455667788, %rcx
    cmp %rcx, %rax
    jne fail

    mov $158, %eax                   /* arch_prctl(ARCH_SET_FS, 0) */
    mov $0x1002, %edi
    xor %esi, %esi
    syscall
    test %rax, %rax
    jne fail

zero_fs_access:
    mov %fs:0, %rax                  /* must deliver SEGV_MAPERR at address 0 */
after_zero_fs_access:
    cmpl $1, handled(%rip)
    jne fail
    xor %edi, %edi
    mov $231, %eax                   /* exit_group */
    syscall

fail:
    mov $1, %edi
    mov $231, %eax
    syscall
.size _start, .-_start

.type handler,@function
handler:
    cmp $11, %edi
    jne handler_bad
    cmpl $1, 8(%rsi)                 /* SEGV_MAPERR */
    jne handler_bad
    cmpq $0, 16(%rsi)                /* si_addr */
    jne handler_bad
    incl handled(%rip)
    lea after_zero_fs_access(%rip), %rax
    mov %rax, 168(%rdx)              /* uc_mcontext.rip */
    ret
handler_bad:
    movl $99, handled(%rip)
    lea after_zero_fs_access(%rip), %rax
    mov %rax, 168(%rdx)
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax
    syscall
.size restorer, .-restorer

.section .data
.balign 8
action:
    .quad 0, 0, 0, 0
handled:
    .long 0
.balign 8
guest_tls:
    .quad 0x1122334455667788

.section .note.GNU-stack,"",@progbits
