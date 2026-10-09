# Both zero descriptors and all-negative descriptors must wait for a timeout.
.equ SYS_poll, 7
.equ SYS_write, 1
.equ SYS_exit_group, 231
.global _start
.text
_start:
    lea begin(%rip), %rsi
    call marker
    mov $SYS_poll, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    mov $100, %rdx
    syscall
    test %rax, %rax
    jne fail
    lea negative(%rip), %rsi
    call marker
    sub $8, %rsp
    movl $-1, 0(%rsp)
    movw $1, 4(%rsp)
    movw $0, 6(%rsp)
    mov $SYS_poll, %rax
    mov %rsp, %rdi
    mov $1, %rsi
    mov $100, %rdx
    syscall
    test %rax, %rax
    jne fail
    cmpw $0, 6(%rsp)
    jne fail
    lea done(%rip), %rsi
    call marker
    mov $7, %rdi
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
negative: .ascii "N\n"
done: .ascii "T\n"
