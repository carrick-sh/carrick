/* Temporary page-table shortage (#3017 review P0-1): when returnable custody
 * holds the remaining page tables, neither a user-mode fault nor an in-ring
 * syscall copyout may fail or kill the carrier. Both park on the stock's
 * release, wake when the holder returns its tables, and complete the
 * unchanged access.
 */
#define PARENT_SPARSE_VA 0x10000000000
#define CHILD_SPARSE_VA  0x20000000000
.global _start
.text
_start:
    lea pipe_fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    jnz failure

    mov pipe_fds+4(%rip), %edi
    lea pipe_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne failure

    mov $57, %eax
    syscall
    test %rax, %rax
    js failure
    jz child
    mov %eax, %r12d

    movabs $PARENT_SPARSE_VA, %r13
    mov %r13, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp %r13, %rax
    jne failure

    movb $1, marker_byte(%rip)
    call marker

    /* Touch while the host holds the fork stock's tables: parks and reruns. */
    movb $0x41, (%r13)
    cmpb $0x41, (%r13)
    jne failure

    movb $2, marker_byte(%rip)
    call marker

    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne failure
    mov status(%rip), %edi
    test %edi, %edi
    jnz failure
    cmpb $0x41, (%r13)
    jne failure
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2

child:
    movabs $CHILD_SPARSE_VA, %r13
    mov %r13, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp %r13, %rax
    jne child_fail

    /* In-ring pipe read copyout into an unbacked sparse slot while tables are held. */
    mov pipe_fds(%rip), %edi
    mov %r13, %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne child_fail
    cmpb $0x5b, (%r13)
    jne child_fail
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2

child_fail:
    mov $91, %edi
    mov $231, %eax
    syscall
    ud2

failure:
    mov $92, %edi
    mov $231, %eax
    syscall
    ud2

marker:
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

.section .rodata
pipe_byte: .byte 0x5b
.bss
.balign 8
pipe_fds: .quad 0
status: .quad 0
marker_byte: .space 1
.section .note.GNU-stack,"",@progbits
