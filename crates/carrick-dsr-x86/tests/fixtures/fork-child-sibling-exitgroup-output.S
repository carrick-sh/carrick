// A fork child buffers stdout, then a sibling thread calls exit_group while
// the child's initial thread is parked. The child's process-exit rendezvous
// must use the full fork lifecycle helper so buffered output reaches its parent.
.global _start
.section .text
_start:
    mov $57, %rax                   // fork
    syscall
    test %rax, %rax
    jz fork_child

    mov %rax, %r12                  // child pid
    mov %r12, %rdi
    lea wait_status(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax                   // wait4(child, &status, 0, NULL)
    syscall
    cmp %r12, %rax
    jne fail
    cmpl $0, wait_status(%rip)
    jne fail
    xor %rdi, %rdi
    mov $231, %rax
    syscall

fork_child:
    mov $1, %rdi                    // write buffered marker
    lea marker(%rip), %rsi
    mov $marker_end-marker, %rdx
    mov $1, %rax
    syscall
    mov $1, %rdi
    lea output_padding(%rip), %rsi
    mov $131072, %rdx               // exceed a host pipe's one-write capacity
    mov $1, %rax
    syscall

    lea child_stack_end(%rip), %rsi
    mov $0x50f00, %rdi              // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    mov $56, %rax                   // clone thread
    syscall
    test %rax, %rax
    jz sibling

    lea futex_word(%rip), %rdi
    mov $128, %rsi                  // FUTEX_WAIT_PRIVATE
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    xor %r9, %r9
    mov $202, %rax
    syscall
    jmp fail

sibling:
    lea delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // nanosleep, let initial thread park
    syscall
    xor %rdi, %rdi
    mov $231, %rax                  // exit_group(0)
    syscall

fail:
    mov $99, %rdi
    mov $231, %rax
    syscall

.section .rodata
marker:
    .ascii "fork-child-output\n"
marker_end:
.align 8
delay:
    .quad 0, 100000000

.section .bss
.align 4
futex_word:
    .long 0
wait_status:
    .long 0
output_padding:
    .skip 131072
.align 16
.skip 65536
child_stack_end:
