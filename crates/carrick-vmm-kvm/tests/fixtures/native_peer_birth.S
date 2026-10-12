/* A child forks on the idle peer. Its child then migrates to CPU 0 and
 * first-touches private memory, forcing physical service on the root executor.
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    mov %eax, %r12d
    mov $1, %r13d
    call marker
    mov %r12d, %edi
    call wait_child
    mov $2, %r13d
    call marker
    mov $7, %edi
    jmp exit
child:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz grandchild
    js failure
    mov %eax, %r12d
    /* Stop on CPU 1 so the host can place the real newborn on CPU 0. */
    mov $2, %r13d
    call marker
    mov %r12d, %edi
    call wait_child
    mov $19, %edi
    jmp exit
grandchild:
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    movb $0x5a, (%rax)
    cmpb $0x5a, (%rax)
    jne failure
    mov $19, %edi
    jmp exit
wait_child:
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    cmpl $(19 << 8), -24(%rsp)
    jne failure
    ret
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
marker:
    mov %r13b, marker_byte(%rip)
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

/* Ordinary zero-fill ELF storage for the actors' persistent witness state. */
.bss
.balign 4096
marker_byte: .space 65536
