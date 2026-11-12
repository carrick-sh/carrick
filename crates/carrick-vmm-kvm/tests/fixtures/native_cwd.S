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
    /* Child has changed cwd and remains blocked until our own change. */
    mov pipes(%rip), %edi
    call receive
    lea parent(%rip), %r12
    inc %r14d
    call change
    call check
    mov pipes+12(%rip), %edi
    call send
#endif
    mov %r15, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r15, %rax
    jne fail
    cmpl $0, status(%rip)
    jne fail
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
    mov pipes+4(%rip), %edi
    call send
    mov pipes+8(%rip), %edi
    call receive
    call check
#endif
#endif
success:
    xor %edi, %edi
    jmp exit
#ifdef CONCURRENT
send:
    mov $1, %eax
    jmp exchange
receive:
    xor %eax, %eax
exchange:
    lea token(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne fail
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
    lea buf(%rip), %rdi
    mov %r12, %rsi
1:  movb (%rsi), %al
    cmpb %al, (%rdi)
    jne fail
    inc %rsi
    inc %rdi
    test %al, %al
    jne 1b
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
buf: .skip 4096
byte: .skip 1
status: .skip 8
pipes: .skip 16
token: .skip 1
.section .note.GNU-stack,"",@progbits
