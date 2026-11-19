/* Production fork-child exec witness. The successor is a real static ELF.
 * Exit with the exec errno if replacement returns; parent propagates status. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    mov status(%rip), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
#ifdef EXEC_FD_PATH
    /* Open with the child's ring table and give the path a fixed fd. */
    mov $-100, %edi
    lea successor(%rip), %rsi
    xor %edx, %edx
    mov $257, %eax
    syscall
    test %eax, %eax
    js failure
    mov %eax, %edi
    mov $43, %esi
    cmp %esi, %edi
    je have_fd
    mov $292, %eax
    syscall
    cmp $43, %eax
    jne failure
have_fd:
    lea fd_path(%rip), %rdi
#else
    lea successor(%rip), %rdi
#endif
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
successor: .asciz SUCCESSOR_PATH
#ifdef EXEC_FD_PATH
fd_path: .asciz "/proc/self/fd/43"
#endif
.balign 8
argv: .quad successor, 0
.section .bss
.balign 4
status: .space 4
