/* Block both handshake signals before fork. The exec successor announces
 * itself with SIGUSR1, waits for SIGUSR2, then exits. Only after observing
 * the successor does the parent acknowledge it and collect wait4 status.
 * Timed signal waits bound a broken replacement without polling. */
.global _start
.text
_start:
    /* A replacement must not overwrite its still-live parent's stack. */
    movabs $0x706172656e742d73, %rax
    mov %rax, (%rsp)
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
    jz child
    mov %eax, %r12d
    xor %r13d, %r13d
    lea ready(%rip), %rdi
    xor %esi, %esi
    lea bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $10, %eax
    je received
    mov %r12d, %edi
    mov $9, %esi
    mov $62, %eax
    syscall
    jmp reap
received:
    movabs $0x706172656e742d73, %rax
    cmp %rax, (%rsp)
    jne failure
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
    mov $1, %r13d
reap:
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov status(%rip), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jnz exit
    test %r13d, %r13d
    jz failure
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $13, %edx
    mov $1, %eax
    syscall
    cmp $13, %eax
    jne failure
    xor %edi, %edi
    jmp exit
child:
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
bound: .quad 5, 0
marker: .ascii "live-exec-ok\n"
.section .bss
.balign 4
status: .space 4
