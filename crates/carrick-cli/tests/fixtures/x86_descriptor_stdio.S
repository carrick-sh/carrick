.equ SYS_read, 0
.equ SYS_write, 1
.equ SYS_close, 3
.equ SYS_dup, 32
.equ SYS_dup2, 33
.equ SYS_exit_group, 231
.global _start
.text
_start:
    mov $SYS_dup2, %rax
    mov $1, %rdi
    mov $5, %rsi
    syscall
    cmp $5, %rax
    jne fail_dup2
    mov $SYS_close, %rax
    mov $1, %rdi
    syscall
    test %rax, %rax
    jne fail_close_stdout
    mov $SYS_write, %rax
    mov $1, %rdi
    lea out(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $-9, %rax
    jne fail_closed_write
    mov $SYS_close, %rax
    xor %rdi, %rdi
    syscall
    test %rax, %rax
    jne fail_close_stdin
    mov $SYS_dup, %rax
    mov $5, %rdi
    syscall
    test %rax, %rax
    jne fail_dup_reuse
    mov $SYS_close, %rax
    xor %rdi, %rdi
    syscall
    test %rax, %rax
    jne fail_close_reused_stdin
    mov $SYS_read, %rax
    xor %rdi, %rdi
    lea scratch(%rip), %rsi
    mov $1, %rdx
    syscall
    cmp $-9, %rax
    jne fail_closed_read
    mov $SYS_dup2, %rax
    mov $2, %rdi
    mov $1, %rsi
    syscall
    cmp $1, %rax
    jne fail_redirect_stdout
    mov $SYS_write, %rax
    mov $5, %rdi
    lea out(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $2, %rax
    jne fail_write_saved
    mov $7, %rdi
    jmp exit
fail_dup2: mov $91, %rdi; jmp exit
fail_close_stdout: mov $92, %rdi; jmp exit
fail_closed_write: mov $93, %rdi; jmp exit
fail_close_stdin: mov $94, %rdi; jmp exit
fail_dup_reuse: mov $95, %rdi; jmp exit
fail_close_reused_stdin: mov $96, %rdi; jmp exit
fail_closed_read: mov $97, %rdi; jmp exit
fail_redirect_stdout: mov $98, %rdi; jmp exit
fail_write_saved: mov $100, %rdi
exit:
    mov $SYS_exit_group, %rax
    syscall
    ud2
.section .rodata
out: .ascii "D\n"
.bss
scratch: .skip 1
