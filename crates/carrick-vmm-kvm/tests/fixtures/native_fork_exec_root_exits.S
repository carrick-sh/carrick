/* #2799 lead 2 witness. The run root forks a child that execs a real static
 * ELF, and exits its whole group without waiting for it. The child writes one
 * pipe byte immediately before execve, so the root, blocked in read, becomes
 * runnable as the exec starts; it then spins PARENT_SPIN pause iterations and
 * exits. The test sweeps PARENT_SPIN so the exit lands before, inside and
 * after the child's exec service. */
#ifndef PARENT_SPIN
#define PARENT_SPIN 0
#endif
.global _start
.text
_start:
    lea pipefd(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    jnz failure
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov pipefd(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %eax
    jne failure
    mov $PARENT_SPIN, %ecx
    test %ecx, %ecx
    jz leave
spin:
    pause
    dec %ecx
    jnz spin
leave:
    xor %edi, %edi
    jmp exit
child:
    mov pipefd+4(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    lea successor(%rip), %rdi
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
.balign 8
argv: .quad successor, 0
.section .bss
.balign 4
pipefd: .space 8
byte: .space 1
