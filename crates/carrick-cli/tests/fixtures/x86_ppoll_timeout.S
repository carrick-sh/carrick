# ppoll sleeps on an empty set, then rejects an invalid nanosecond field.
.equ SYS_ppoll, 271
.equ SYS_write, 1
.equ SYS_exit_group, 231
.global _start
.text
_start:
    sub $16, %rsp
    movq $0, 0(%rsp)
    movq $100000000, 8(%rsp)
    lea begin(%rip), %rsi
    call marker
    mov $SYS_ppoll, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    mov %rsp, %rdx
    xor %r10, %r10
    mov $8, %r8
    syscall
    test %rax, %rax
    jne bad_wait
    lea done(%rip), %rsi
    call marker
    movq $1000000000, 8(%rsp)
    mov $SYS_ppoll, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    mov %rsp, %rdx
    xor %r10, %r10
    mov $8, %r8
    syscall
    cmp $-22, %rax
    jne bad_nsec
    mov $7, %rdi
    jmp exit
bad_wait:
    mov $91, %rdi
    jmp exit
bad_nsec:
    mov $92, %rdi
    jmp exit
marker:
    mov $SYS_write, %rax
    mov $1, %rdi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail
    ret
fail:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
begin: .ascii "B\n"
done: .ascii "T\n"
