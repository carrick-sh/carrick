/* Root save/redirect/restore: exit 7 on exact pipe byte and flag roundtrips.
 * 100+errno identifies failed fcntl save; other exits name stages. */
.global _start
.text
_start:
    mov $1, %edi
    xor %esi, %esi                 /* F_DUPFD */
    mov $10, %edx
    mov $72, %eax
    syscall
    test %rax, %rax
    js fail_save
    mov %eax, %r12d
    mov %r12d, %edi
    mov $2, %esi                   /* F_SETFD(FD_CLOEXEC) */
    mov $1, %edx
    mov $72, %eax
    syscall
    test %rax, %rax
    jnz fail_flags
    mov %r12d, %edi
    mov $1, %esi                   /* F_GETFD */
    mov $72, %eax
    syscall
    cmp $1, %rax
    jne fail_flags
    lea fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz fail_pipe
    mov fds+4(%rip), %edi
    mov $3, %esi                   /* F_GETFL */
    mov $72, %eax
    syscall
    test %rax, %rax
    js fail_flags
    mov %rax, %rdx
    or $0x800, %edx                /* O_NONBLOCK */
    mov fds+4(%rip), %edi
    mov $4, %esi                   /* F_SETFL */
    mov $72, %eax
    syscall
    test %rax, %rax
    jnz fail_flags
    mov fds+4(%rip), %edi
    mov $3, %esi
    mov $72, %eax
    syscall
    test $0x800, %eax
    jz fail_flags
    mov fds+4(%rip), %edi
    mov $1, %esi
    xor %edx, %edx
    mov $292, %eax                 /* dup3(pipe writer, stdout, 0) */
    syscall
    cmp $1, %rax
    jne fail_dup
    mov $1, %edi
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne fail_write
    mov %r12d, %edi
    mov $1, %esi
    xor %edx, %edx
    mov $292, %eax                 /* restore stdout */
    syscall
    cmp $1, %rax
    jne fail_dup
    mov %r12d, %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz fail_dup
    mov fds(%rip), %edi
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail_read
    cmpb $'R', received(%rip)
    jne fail_read
    mov $7, %edi
    jmp exit
fail_save:
    neg %eax
    lea 100(%eax), %edi
    jmp exit
fail_flags:
    mov $80, %edi
    jmp exit
fail_pipe:
    mov $81, %edi
    jmp exit
fail_dup:
    mov $82, %edi
    jmp exit
fail_write:
    mov $83, %edi
    jmp exit
fail_read:
    mov $84, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
fds: .long -1, -1
message: .byte 'R'
received: .byte 0
