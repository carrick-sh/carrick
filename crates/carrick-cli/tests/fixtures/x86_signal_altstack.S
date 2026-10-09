# sigaltstack(2)/sigaction(2): recover on an alternate stack after stack fault.
.global _start
.text
_start:
    lea alt_base(%rip), %rax
    mov %rax, stack_record(%rip)
    movq $8192, stack_record+16(%rip)
    mov $131, %rax
    lea stack_record(%rip), %rdi
    xor %rsi, %rsi
    syscall
    test %rax, %rax
    jnz fail
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x0c000004, action+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    mov $13, %rax
    mov $11, %rdi
    lea action(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    syscall
    test %rax, %rax
    jnz fail
    mov $0x1000, %rsp
    push %rax
    jmp fail
handler:
    lea alt_base(%rip), %rax
    cmp %rax, %rsp
    jb fail
    cmp %rax, 16(%rdx)       # uc_stack.ss_sp
    jne fail
    lea alt_end(%rip), %rax
    cmp %rax, %rsp
    jae fail
    cmpq $8192, 32(%rdx)     # uc_stack.ss_size
    jne fail
    cmpq $0x1000, 160(%rdx)  # uc_mcontext.rsp before fault
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea message(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
restorer:
    mov $15, %rax
    syscall
    ud2
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.data
.balign 8
stack_record:
    .zero 24
action:
    .zero 32
message:
    .ascii "S\n"
.bss
.balign 16
alt_base:
    .zero 8192
alt_end:
