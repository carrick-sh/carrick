/* #2418: the run's injected /etc/resolv.conf read by the production root.
 * It opens the file, reads it, writes the bytes it read to stdout, and a
 * second read is end of file (the description's offset advanced). Each
 * failed step exits with its number. */
.global _start
.text
_start:
    mov $-100, %edi                 /* openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY) */
    lea name(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov $10, %edi
    test %rax, %rax
    js report
    mov %rax, %r12

    mov %r12, %rdi                  /* read(fd, buf, 4096) > 0 */
    lea buf(%rip), %rsi
    mov $4096, %edx
    xor %eax, %eax
    syscall
    mov $11, %edi
    test %rax, %rax
    jle report
    mov %rax, %r13

    mov $1, %edi                    /* write(1, buf, n) == n */
    lea buf(%rip), %rsi
    mov %r13, %rdx
    mov $1, %eax
    syscall
    mov $12, %edi
    cmp %r13, %rax
    jne report

    mov %r12, %rdi                  /* read(fd, buf, 4096) == 0: end of file */
    lea buf(%rip), %rsi
    mov $4096, %edx
    xor %eax, %eax
    syscall
    mov $13, %edi
    test %rax, %rax
    jne report
    xor %edi, %edi
    jmp exit
report:                             /* stderr gets the failed step's result */
    mov %edi, %ebx
    mov %rax, result(%rip)
    mov $2, %edi
    lea result(%rip), %rsi
    mov $8, %edx
    mov $1, %eax
    syscall
    mov %ebx, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
name: .asciz "/etc/resolv.conf"
.section .bss
.balign 64
result: .skip 8
buf: .skip 4096
.section .note.GNU-stack,"",@progbits
