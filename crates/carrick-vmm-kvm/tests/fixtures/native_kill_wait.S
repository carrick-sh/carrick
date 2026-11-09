/* Non-exit process-channel publication: parent blocks SIGWINCH and waits
 * for its live child. The child sends SIGWINCH without retiring its MM.
 */
.global _start
.text
_start:
    mov $14, %eax
    xor %edi, %edi
    lea mask(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz failure
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    movb $1, marker_byte(%rip)
    call marker
    mov %r12d, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    jmp failure
child:
    mov $110, %eax
    syscall
    mov %eax, %edi
    mov $28, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
    /* The old consumer reaches this write without marking the doorbell. */
    movb $2, marker_byte(%rip)
    call marker
failure:
    ud2
marker:
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret
.section .rodata
.balign 8
mask: .quad (1 << 27)
.bss
marker_byte: .space 1
