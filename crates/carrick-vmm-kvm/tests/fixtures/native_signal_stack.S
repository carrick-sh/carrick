/* A never-touched anonymous alternate stack requires signal-frame backing.
 * Handler count and the saved tkill result detect replay across that service.
 */
.global _start
.text
_start:
    mov $13, %eax
    mov $10, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    js failure
    mov $9, %eax
    xor %edi, %edi
    mov $16384, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js failure
    mov %rax, alternate(%rip)
    mov $131, %eax
    lea alternate(%rip), %rdi
    xor %esi, %esi
    syscall
    test %rax, %rax
    js failure
    mov $186, %eax
    syscall
    mov %eax, %edi
    mov $10, %esi
    mov $200, %eax
    syscall
    test %rax, %rax
    jne failure
    cmpl $1, calls(%rip)
    jne failure
    mov $7, %edi
    jmp exit
handler:
    incl calls(%rip)
    ret
restorer:
    mov $15, %eax
    syscall
    ud2
failure:
    mov $99, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 8
action:
    .quad handler, 0x0c000000, restorer, 0
alternate:
    .quad 0, 0, 16384
calls:
    .long 0
.section .note.GNU-stack,"",@progbits
