/* The native child owns its ring sleep. The root reaps and relays its status. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %edi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    jle failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $1, %edx
    syscall
    mov $35, %eax
    lea request(%rip), %rdi
    xor %esi, %esi
    syscall
    mov %eax, %r12d
    mov $1, %eax
    mov $1, %edi
    lea marker+1(%rip), %rsi
    mov $1, %edx
    syscall
    mov %r12d, %edi
    jmp exit
failure:
    mov $1, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
.balign 8
request:
    .quad 0, 200000000
marker:
    .ascii "SE"
.section .note.GNU-stack,"",@progbits
