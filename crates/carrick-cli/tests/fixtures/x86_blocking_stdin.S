# Same-source native/KVM witness for an open stdin pipe with no data.
# The parent keeps the write end open until it sees R, then supplies one byte.
.equ SYS_read, 0
.equ SYS_write, 1
.equ SYS_exit_group, 231
.global _start
.text
_start:
    mov $SYS_write, %rax
    mov $1, %rdi
    lea ready(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail

    mov $SYS_read, %rax
    xor %rdi, %rdi
    lea byte(%rip), %rsi
    mov $1, %rdx
    syscall
    cmp $1, %rax
    jne fail
    cmpb $'X', byte(%rip)
    jne fail

    mov $SYS_write, %rax
    mov $1, %rdi
    lea success(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
ready: .ascii "R\n"
success: .ascii "B\n"
.bss
byte: .byte 0
