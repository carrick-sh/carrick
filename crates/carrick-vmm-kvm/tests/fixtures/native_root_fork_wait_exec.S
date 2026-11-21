/* #2142: the shell's `sh -c 'cmd; exec prog'` shape. The run root forks a
 * child that exits at once, parks in wait4 until it is reaped, then replaces
 * itself with EXEC_PATH. The wait may resume the root on either CPU its
 * affinity allows. Exit 91: fork or wait failed. Exit with the errno: the
 * exec returned.
 */
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
    test %edi, %edi
    jnz failure
    lea path(%rip), %rdi
    lea argv(%rip), %rsi
    lea envp(%rip), %rdx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit
child:
    xor %edi, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
path: .asciz EXEC_PATH
.balign 8
argv: .quad path, 0
envp: .quad 0
.section .bss
.balign 4
status: .space 4
