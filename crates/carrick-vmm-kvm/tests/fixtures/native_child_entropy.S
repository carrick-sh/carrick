/* Production fork, child getrandom, and parent wait. The exit status reports
 * 8 for exactly eight bytes, 218 for -ENOSYS, 91 for any other answer. No test service
 * supplies the child's answer. Parent and child remain live during the call.
 */
#ifndef ENTROPY_FLAGS
#define ENTROPY_FLAGS 0
#endif
.global _start
.text
_start:
#ifdef ENTROPY_LAZY
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %r15
#endif
#ifdef ENTROPY_ROOT
    jmp child
#endif
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
#ifdef ENTROPY_COW
    cmpq $0x12345678, entropy_buffer(%rip)
    jne failure
#endif
#ifdef ENTROPY_LAZY
    cmpq $0, (%r15)
    jne failure
#endif
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
    sub $16, %rsp
    mov %rsp, %rdi
#ifdef ENTROPY_READONLY
    lea readonly_buffer(%rip), %rdi
#endif
#ifdef ENTROPY_COW
    lea entropy_buffer(%rip), %rdi
#endif
#ifdef ENTROPY_LAZY
    mov %r15, %rdi
#endif
#ifdef ENTROPY_PREFIX
    lea prefix_buffer(%rip), %rdi
    mov $16, %esi
#else
    mov $8, %esi
#endif
    mov $ENTROPY_FLAGS, %edx
    mov $318, %eax
    syscall
#ifdef ENTROPY_READONLY
    cmp $-14, %rax
#else
    cmp $8, %rax
#endif
    je success
    cmp $-38, %rax
    jne failure
    mov $218, %edi
    jmp exit
success:
    mov $8, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
.balign 4096
readonly_buffer:
    .quad 0x12345678
.data
.balign 4096
entropy_buffer:
    .quad 0x12345678
#ifdef ENTROPY_PREFIX
.balign 4096
    .skip 4088
prefix_buffer:
    .quad 0x12345678
#endif
.section .note.GNU-stack,"",@progbits
