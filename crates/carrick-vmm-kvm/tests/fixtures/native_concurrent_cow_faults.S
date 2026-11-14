/* #2141: two threads of one forked MM fault distinct private pages together.
 * The worker observes the main thread's real clear_child_tid before ending
 * the process; this never depends on exit_group retiring a live sibling. */
.global _start
.text
_start:
    movb $1, first(%rip)
    movb $2, second(%rip)
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %r12
    movl $0, (%r12)
    movl $0, 4(%r12)
    mov $57, %eax
    syscall
    test %rax, %rax
    jz child
    js failure
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    js failure
    cmpl $1792, status(%rip)
    jne failure
    mov $7, %edi
    jmp exit_group
child:
    /* Break sync-page COW before the threads exist; retain a nonzero tid
     * until the main thread's raw exit actually clears it. */
    movl $1, (%r12)
    mov %r12, %rdi
    mov $218, %eax
    syscall
    test %rax, %rax
    js failure
    mov $0x50f00, %edi
    lea 0x4000(%r12), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    mov $100000, %r13d
5:
    cmpl $1, 8(%r12)
    je 6f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 5b
6:
    movl $1, 4(%r12)
    movb $0x51, first(%rip)
    /* Finish both accesses before testing raw exit/clear_child_tid. */
    mov $100000, %r13d
7:
    cmpl $1, 12(%r12)
    je 8f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 7b
8:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
worker:
    movl $1, 8(%r12)
    mov $100000, %r13d
1:
    cmpl $1, 4(%r12)
    je 2f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 1b
2:
    movb $0x52, second(%rip)
    movl $1, 12(%r12)
    mov $100000, %r13d
3:
    cmpl $0, (%r12)
    je 4f
    dec %r13d
    jz failure
    mov $24, %eax
    syscall
    jmp 3b
4:
    cmpb $0x51, first(%rip)
    jne failure
    cmpb $0x52, second(%rip)
    jne failure
    mov $7, %edi
    jmp exit_group
failure:
    mov $91, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2
.data
.balign 4096
first: .byte 0
.balign 4096
second: .byte 0
.bss
.balign 4096
status: .space 8
