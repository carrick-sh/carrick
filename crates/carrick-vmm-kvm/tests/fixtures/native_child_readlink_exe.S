/* Production fork in the raw carrier fixture, which has no executable
 * authority. The child exits 218 for -ENOSYS with its buffer untouched,
 * 92 if a refusal wrote its buffer, or 91 for another answer. The parent
 * reaps the child and exits with its status.
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov %eax, %edi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
    mov $-100, %rdi
    lea exe_path(%rip), %rsi
    lea link_buffer(%rip), %rdx
    mov $64, %r10d
    mov $267, %eax
    syscall
    cmp $-38, %rax
    jne failure
    xor %eax, %eax
    cmp link_buffer(%rip), %rax
    jne written
    mov $218, %edi
    jmp exit
written:
    mov $92, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
exe_path: .asciz "/proc/self/exe"
.bss
.balign 4096
link_buffer: .space 4096
.section .note.GNU-stack,"",@progbits
