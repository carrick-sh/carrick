/* #2142: a non-leader thread of the run root's group execs EXEC_PATH while
 * the leader waits for it in a sched_yield loop. Linux ends the leader, and
 * the exec'ing thread takes over the leader's TID: the successor runs alone.
 * If the exec returns, the thread publishes its errno and exits alone; the
 * leader then exits with that errno. Exit 100 + errno: the clone failed.
 */
.global _start
.text
_start:
    xor %edi, %edi
    mov $0x2000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    mov %rax, %r12
    movl $0, 0x0(%r12)
    /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM */
    mov $0x00050f00, %edi
    lea 0x1ff0(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz thread
    jns leader
    neg %rax
    lea 100(%rax), %rdi
    mov $231, %eax
    syscall
leader:
    cmpl $0, 0x0(%r12)
    jne returned
    mov $24, %eax           /* sched_yield */
    syscall
    jmp leader
returned:
    mov 0x4(%r12), %edi
    mov $231, %eax
    syscall
    ud2
thread:
    lea path(%rip), %rdi
    lea argv(%rip), %rsi
    lea envp(%rip), %rdx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, 0x4(%r12)
    movl $1, 0x0(%r12)
    xor %edi, %edi
    mov $60, %eax           /* exit: this thread only */
    syscall
    ud2
.section .rodata
path: .asciz EXEC_PATH
.balign 8
argv: .quad path, 0
envp: .quad 0
