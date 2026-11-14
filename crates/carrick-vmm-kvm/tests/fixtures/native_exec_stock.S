/* Two fork children: one retains fork tables until released, the other execs.
 * Host rendezvous writes let the witness stop both CPUs before each phase. */
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
    mov %eax, %r13d
    mov %eax, %r12d
    lea first(%rip), %rsi
    call marker
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz exec_child
    mov %eax, %r12d
    lea second(%rip), %rsi
    call marker
#ifdef KILL_PARKED
    mov %r12d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
    mov %r12d, %edi
    call wait_child
    cmpl $9, status(%rip)
    jne failure
    lea third(%rip), %rsi
    call marker
#endif
    mov %r13d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#ifndef KILL_PARKED
    mov %r12d, %edi
    call wait_child
    cmpl $0, status(%rip)
    jne failure
#endif
    mov %r13d, %edi
    call wait_child
    cmpl $0, status(%rip)
    jne failure
    lea fourth(%rip), %rsi
    call marker
    xor %edi, %edi
    jmp exit
holder:
    lea blocked(%rip), %rdi
    xor %esi, %esi
    lea bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $12, %eax
    jne failure
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
wait_child:
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    ret
marker:
    mov $1, %eax
    mov $1, %edi
    mov $1, %edx
    syscall
    ret
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
first: .byte 1
second: .byte 2
third: .byte 3
fourth: .byte 4
.balign 8
blocked: .quad (1 << 11)
bound: .quad 20, 0
successor: .asciz "/stock-successor"
.balign 8
argv: .quad successor, 0
.section .bss
.balign 4
status: .space 4
