// A detached guest thread created after fork inherits fork-descendant process
// semantics. Its default synchronous SIGSEGV must kill the host child by signal
// so the guest parent observes WIFSIGNALED/SIGSEGV rather than WIFEXITED(139).
.global _start
.section .text
_start:
    mov $57, %eax                    // fork
    syscall
    test %rax, %rax
    js setup_failed
    jz fork_child

    mov %rax, %r12
    mov %r12, %rdi
    lea child_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                    // wait4(child, &status, 0, NULL)
    syscall
    cmp %r12, %rax
    jne setup_failed
    mov child_status(%rip), %eax
    and $0x7f, %eax                  // WTERMSIG(status)
    cmp $11, %eax                    // SIGSEGV
    jne wrong_wait_status
    xor %edi, %edi
    jmp exit_group

fork_child:
    lea detached_stack_end(%rip), %rsi
    mov $0x50f00, %edi              // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax                    // clone
    syscall
    test %rax, %rax
    js child_setup_failed
    jz detached_fault

child_spin:
    jmp child_spin                   // exit request must asynchronously kick this thread

detached_fault:
    xor %eax, %eax
    mov (%rax), %rbx                 // default translated-code SIGSEGV
    mov $82, %edi
    jmp exit_group

child_setup_failed:
    mov $83, %edi
    jmp exit_group
wrong_wait_status:
    mov $84, %edi
    jmp exit_group
setup_failed:
    mov $85, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2

.section .bss
.align 8
child_status:
    .long 0
.align 16
detached_stack:
    .skip 65536
detached_stack_end:
