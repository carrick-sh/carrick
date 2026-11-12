/* #1714: cwd inheritance and isolation, production CPL0. */
.global _start
.text
_start:
    lea base(%rip), %r12
    mov $10, %r14d
    call change
    call check
#ifdef CONCURRENT
    lea pipes(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jne fail
    lea pipes+8(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jne fail
#endif
#ifdef CHILD
    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    jz child
    mov %rax, %r15
#ifdef CONCURRENT
    /* Both processes may change cwd on separate vCPUs. Neither exits
       until the peer has changed cwd and published its close. */
    mov $13, %r14d
    mov pipes+4(%rip), %edi
    call close
    lea parent(%rip), %r12
    inc %r14d
    call change
    mov pipes+12(%rip), %edi
    call close
    mov pipes(%rip), %edi
    call wait_close
    call check
#endif
    mov $12, %r14d
    mov %r15, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail
    cmpl $0, status(%rip)
    je 4f
    mov status(%rip), %edi
    test $0x7f, %edi
    jz 5f
    and $0x7f, %edi
    add $128, %edi
    jmp exit
5:  shr $8, %edi
    jmp exit
4:
    call check
    jmp success
child:
    mov $30, %r14d
    call check
    lea childdir(%rip), %r12
    inc %r14d
    call change
    call check
#ifdef CONCURRENT
    mov pipes+12(%rip), %edi
    call close
    mov pipes+4(%rip), %edi
    call close
    mov pipes+8(%rip), %edi
    call wait_close
    call check
#endif
#endif
success:
    xor %edi, %edi
    jmp exit
#ifdef CONCURRENT
close:
    mov $3, %eax
    syscall
    test %rax, %rax
    jne fail
    ret
wait_close:
    mov %edi, pollfd(%rip)
    movl $1, pollfd+4(%rip)
    lea pollfd(%rip), %rdi
    mov $1, %esi
    mov $-1, %edx
    mov $7, %eax
    syscall
    cmp $1, %rax
    jne fail
    testw $16, pollfd+6(%rip)
    jz fail
    ret
#endif
change:
    mov %r12, %rdi
    mov $80, %eax
    syscall
    test %rax, %rax
    jne fail
    ret
check:
    lea buf(%rip), %rdi
    mov $4096, %esi
    mov $79, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r13
    xor %ecx, %ecx
    lea buf(%rip), %rdi
    mov %r12, %rsi
1:  movb (%rsi), %al
    cmpb %al, (%rdi)
    jne fail
    inc %rsi
    inc %rdi
    inc %rcx
    test %al, %al
    jne 1b
    cmp %r13, %rcx             /* getcwd returns bytes including NUL */
    jne fail
    mov $-100, %edi
    lea relative(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js fail
    mov %rax, %rbx
    mov %rax, %rdi
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail
    /* Each directory's marker differs; a stale cwd cannot pass. */
    movb (%r12), %al
    mov %r12, %rsi
2:  cmpb $0, (%rsi)
    je 3f
    movb (%rsi), %al
    inc %rsi
    jmp 2b
3:  cmpb %al, byte(%rip)
    jne fail
    mov %rbx, %rdi
    mov $3, %eax
    syscall
    ret
fail:
    mov %r14d, %edi
    test %rax, %rax
    jns exit
    mov %eax, %edi
    neg %edi
    add $100, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
base: .asciz BASE_PATH
parent: .asciz PARENT_PATH
childdir: .asciz CHILD_PATH
relative: .asciz "marker"
.section .bss
.balign 64
status: .skip 8
pipes: .skip 16
pollfd: .skip 8
byte: .skip 1
.balign 64
buf: .skip 4096
.section .note.GNU-stack,"",@progbits
