/* Two live fork children: one holds its MM while the other execs. The parent
 * collects the exec child before releasing the holder. CANCEL_PARKED kills
 * the exec child while its stock request is outstanding. */
.global _start
.text
_start:
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
#ifdef CANCEL_PARKED
    lea short_sleep(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    mov %r13d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
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
#else
    mov exec_status(%rip), %eax
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
    lea hold_sleep(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    xor %edi, %edi
    jmp exit
exec_child:
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
short_sleep: .quad 0, 100000000
hold_sleep: .quad 2, 0
.section .bss
.balign 4
exec_status: .space 4
holder_status: .space 4
