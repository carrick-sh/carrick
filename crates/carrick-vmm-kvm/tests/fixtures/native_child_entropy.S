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
    sub $16, %rsp
    mov %rsp, %rdi
    mov $8, %esi
    mov $ENTROPY_FLAGS, %edx
    mov $318, %eax
    syscall
    cmp $8, %rax
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
.section .note.GNU-stack,"",@progbits
