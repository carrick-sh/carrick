/* The parent waits in wait4 while its forked child writes one byte to
 * stdout. The child's write is a host forward from a task that is not the
 * run's root, so it must be served under the child's authenticated identity
 * on whichever executor lane it runs on. Expected stdout: "E"; exit: 7. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    cmpl $0, status(%rip)
    jne failure
    mov $7, %edi
    jmp exit

child:
    mov $1, %edi
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    xor %edi, %edi
    jmp exit

child_failure:
    mov $92, %edi
    jmp exit

failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
message: .ascii "E"

.section .bss
.balign 4
status: .space 4
