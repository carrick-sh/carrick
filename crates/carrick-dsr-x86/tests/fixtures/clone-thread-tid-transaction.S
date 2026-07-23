// CLONE_THREAD TID outputs must remain untouched when host pthread spawn fails.
// The native runtime's test-only injection forces clone(2) to return -EAGAIN.
.section .text
.global _start
.type _start,@function
_start:
    movl $0x11223344, parent_tid(%rip)
    movl $0x55667788, child_tid(%rip)

    movq $56, %rax                    // __NR_clone
    movq $0x01110f00, %rdi            // VM|FS|FILES|SIGHAND|THREAD|PARENT_SETTID|CHILD_SETTID
    leaq child_stack_end(%rip), %rsi
    leaq parent_tid(%rip), %rdx
    leaq child_tid(%rip), %r10
    xorq %r8, %r8
    syscall

    cmpq $-11, %rax                   // -EAGAIN from injected host spawn failure
    jne .Lfail_clone
    cmpl $0x11223344, parent_tid(%rip)
    jne .Lfail_parent
    cmpl $0x55667788, child_tid(%rip)
    jne .Lfail_child

    movq $231, %rax                   // __NR_exit_group
    xorq %rdi, %rdi
    syscall

.Lfail_clone:
    movq $1, %rdi
    jmp .Lexit_fail
.Lfail_parent:
    movq $2, %rdi
    jmp .Lexit_fail
.Lfail_child:
    movq $3, %rdi
.Lexit_fail:
    movq $231, %rax
    syscall

.section .bss
.align 16
parent_tid:
    .long 0
child_tid:
    .long 0
.align 16
child_stack:
    .skip 4096
child_stack_end:
.section .note.GNU-stack,"",@progbits
