/* Two live fork children: one holds its MM while the other execs. The parent
 * collects the exec child before releasing the holder. CANCEL_PARKED kills
 * the exec child while its stock request is outstanding. */
.global _start
.text
_start:
    mov $14, %eax
    xor %edi, %edi
    lea blocked(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz failure
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz holder
    mov %eax, %r12d
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz exec_child
    mov %eax, %r13d
    lea ready(%rip), %rdi
    xor %esi, %esi
    lea long_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $10, %eax
    jne failure
    /* One bounded wait gives the child time to cross into Exec service. */
    lea release_signal(%rip), %rdi
    xor %esi, %esi
    lea short_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
#ifdef CANCEL_PARKED
    mov %r13d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
#else
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov %r13d, %edi
    lea exec_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne failure
#ifdef CANCEL_PARKED
    mov exec_status(%rip), %eax
    and $127, %eax
    cmp $9, %eax
    jne failure
    /* The holder must still be alive when wait4 of the killed exec returns. */
    mov %r12d, %edi
    lea holder_status(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    jnz failure
#else
    mov exec_status(%rip), %eax
    test %eax, %eax
    jnz failure
#endif
#ifdef CANCEL_PARKED
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov %r12d, %edi
    lea holder_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    xor %edi, %edi
    jmp exit
holder:
    lea release_signal(%rip), %rdi
    xor %esi, %esi
    lea long_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $12, %eax
    jne failure
    xor %edi, %edi
    jmp exit
exec_child:
    mov $110, %eax
    syscall
    mov %eax, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
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
blocked: .quad (1 << 9) | (1 << 11)
ready: .quad (1 << 9)
release_signal: .quad (1 << 11)
short_bound: .quad 0, 100000000
long_bound: .quad 5, 0
.section .bss
.balign 4
exec_status: .space 4
holder_status: .space 4
