// A blocked synchronous SIGSEGV must take its fatal default action without
// entering an installed handler. The fault is a direct translated-code load
// from unmapped address zero; success is the runner-observed exit status 139.
.global _start
.section .text
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000000, action+8(%rip)  // SA_RESTORER
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)

    mov $13, %eax                    // rt_sigaction(SIGSEGV, &action, NULL, 8)
    mov $11, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed

    movq $0x400, blocked_mask(%rip)  // sigmask bit SIGSEGV-1
    mov $14, %eax                    // rt_sigprocmask(SIG_BLOCK, &mask, NULL, 8)
    xor %edi, %edi                   // SIG_BLOCK
    lea blocked_mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne setup_failed

    xor %eax, %eax
faulting_load:
    mov (%rax), %rbx                 // translated-code SIGSEGV at address zero

    mov $78, %edi                    // fault unexpectedly resumed
    jmp exit_group

handler:
    mov $77, %edi                    // blocked signal incorrectly entered handler
    jmp exit_group

restorer:
    mov $15, %eax                    // rt_sigreturn
    syscall
    ud2

setup_failed:
    mov $79, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .data
.align 8
action:
    .quad 0, 0, 0, 0
blocked_mask:
    .quad 0
