/*
 * Disabled-CET RDSSPD/RDSSPQ compatibility regression.
 *
 * Carrick masks CET_SS from guest CPUID and exposes no shadow-stack state.
 * Architecturally RDSSP is then a no-op: it preserves the complete destination
 * register and RFLAGS. Correct sensitive emulation exits 37.
 */
.global _start
.type _start,@function
_start:
    movabs $0x1122334455667788, %rax
    mov $0x8d5, %r10d
    push %r10
    popfq
    pushfq
    pop %r11
rdsspq_site:
    .byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8 /* rdsspq %rax */
    pushfq
    pop %r12
    movabs $0x1122334455667788, %r13
    cmp %r13, %rax
    jne fail_qword
    cmp %r11, %r12
    jne fail_qword_flags

    movabs $0x8877665544332211, %rcx
    pushfq
    pop %r11
rdsspd_site:
    .byte 0xf3, 0x0f, 0x1e, 0xc9       /* rdsspd %ecx */
    pushfq
    pop %r12
    movabs $0x8877665544332211, %r13
    cmp %r13, %rcx
    jne fail_dword
    cmp %r11, %r12
    jne fail_dword_flags

    mov $37, %edi
    jmp exit_group
fail_qword:
    mov $1, %edi
    jmp exit_group
fail_qword_flags:
    mov $2, %edi
    jmp exit_group
fail_dword:
    mov $3, %edi
    jmp exit_group
fail_dword_flags:
    mov $4, %edi
exit_group:
    mov $231, %eax
    syscall

.section .note.GNU-stack,"",@progbits
