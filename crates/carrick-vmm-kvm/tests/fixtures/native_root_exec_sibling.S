/* #2142: the run root execs while a second thread of its group is still
 * running in user mode. The sibling publishes that it started and then
 * spins without a syscall; the root waits for that word, then execs EXEC_PATH.
 * Linux ends every other thread of the group at exec: the successor runs
 * alone. Exit 100 + errno: the clone failed. Exit with the errno: the exec
 * returned.
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
    jz sibling
    jns wait_started
    neg %rax
    lea 100(%rax), %rdi
    mov $231, %eax
    syscall
wait_started:
    cmpl $0, 0x0(%r12)
    jne exec
    mov $24, %eax           /* sched_yield */
    syscall
    jmp wait_started
exec:
    lea path(%rip), %rdi
    lea argv(%rip), %rsi
    lea envp(%rip), %rdx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    mov $231, %eax
    syscall
    ud2
sibling:
    movl $1, 0x0(%r12)
spin:
    pause
    jmp spin
.section .rodata
path: .asciz EXEC_PATH
.balign 8
argv: .quad path, 0
envp: .quad 0
