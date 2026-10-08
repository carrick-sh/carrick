/* Native Linux and shared-CPL0 TLS return-lane witness. Constants are supplied
 * from Carrick's single x86 ABI table by the CLI test, not Linux headers. */
.global _start
.text
_start:
    mov $NR_ARCH_PRCTL, %eax
    mov $SET_FS, %edi
    lea tls(%rip), %rsi
    syscall
    test %rax, %rax
    jnz fail
    mov %fs:0, %rax
    cmpq $0x12345678, %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $GET_FS, %edi
    lea observed(%rip), %rsi
    syscall
    test %rax, %rax
    jnz fail
    lea tls(%rip), %rax
    cmp observed(%rip), %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $SET_GS, %edi
    lea tls(%rip), %rsi
    syscall
    test %rax, %rax
    jnz fail
    mov %gs:0, %rax
    cmpq $0x12345678, %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $GET_GS, %edi
    lea observed(%rip), %rsi
    syscall
    test %rax, %rax
    jnz fail
    lea tls(%rip), %rax
    cmp observed(%rip), %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $GET_FS, %edi
    xor %esi, %esi
    syscall
    cmp $-14, %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $SET_FS, %edi
    movabs $0x800000000000, %rsi
    syscall
    cmp $-1, %rax
    jne fail
    mov %fs:0, %rax
    cmpq $0x12345678, %rax
    jne fail
    /* Linux's reserved final lower-half page is not a legal TLS base. */
    mov $NR_ARCH_PRCTL, %eax
    mov $SET_FS, %edi
    movabs $0x7ffffffff000, %rsi
    syscall
    cmp $-1, %rax
    jne fail
    mov %fs:0, %rax
    cmpq $0x12345678, %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $SET_GS, %edi
    movabs $0x7ffffffff000, %rsi
    syscall
    cmp $-1, %rax
    jne fail
    mov %gs:0, %rax
    cmpq $0x12345678, %rax
    jne fail
    mov $NR_ARCH_PRCTL, %eax
    mov $0xffff, %edi
    xor %esi, %esi
    syscall
    cmp $-22, %rax
    jne fail
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $7, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
fail:
    mov $60, %eax
    mov $1, %edi
    syscall
.data
.align 8
tls: .quad 0x12345678
observed: .quad 0
message: .ascii "tls-ok\n"
.section .note.GNU-stack,"",@progbits
