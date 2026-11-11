/* Production fork; the child asks readlinkat(AT_FDCWD, "/proc/self/exe")
 * (x86 nr 267). x86 MM custody retains no executable yet (#1903), so the
 * CPL0 lane refuses the native executable-link service as a counted ENOSYS. The child exits 218 for -ENOSYS with its buffer
 * untouched, 92 if the refusal wrote the buffer, 91 for any other answer;
 * the parent reaps it and exits with the child's status.
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
    movq $0x5a5a5a5a5a5a5a5a, %rax
    mov %rax, link_buffer(%rip)
    mov $-100, %rdi
    lea exe_path(%rip), %rsi
    lea link_buffer(%rip), %rdx
    mov $64, %r10d
    mov $267, %eax
    syscall
    cmp $-38, %rax
    jne failure
    movq $0x5a5a5a5a5a5a5a5a, %rax
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
