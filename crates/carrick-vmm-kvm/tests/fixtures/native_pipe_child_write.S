/* #1671: a forked child's write(2) to an in-ring pipe uses shared
 * IPC execution custody. The parent reaps the child and exits with
 * the child's status. Child exit 0 = the write returned 1; otherwise the
 * child exits with the negated errno its write returned (38 = ENOSYS).
 * 90 pipe2 failed, 91 fork/wait failed. */
.global _start
.text
_start:
    lea fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax                 /* pipe2(fds, 0) */
    syscall
    test %rax, %rax
    jnz fail_pipe
    mov $57, %eax                  /* fork */
    syscall
    test %eax, %eax
    js fail_wait
    jz child
#ifdef READ_CHILD
    mov %eax, %r12d
    mov fds(%rip), %edi
#ifdef READV_CHILD
    lea vectors(%rip), %rsi
    mov $2, %edx
    mov $19, %eax
#else
    lea received(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax                 /* read while child is alive */
#endif
    syscall
#ifdef READV_CHILD
    cmp $2, %rax
    jne fail_read
    cmpb $'Q', received_second(%rip)
    jne fail_read
#else
    cmp $1, %rax
    jne fail_read
#endif
    cmpb $'P', received(%rip)
    jne fail_read
    mov %r12d, %eax
#endif
    mov %eax, %edi                 /* wait4(child, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js fail_wait
    movzbl status+1(%rip), %edi    /* WEXITSTATUS */
    jmp exit
child:
    mov fds+4(%rip), %edi          /* write(fds[1], "P", 1) */
    lea message(%rip), %rsi
#ifdef READV_CHILD
    mov $2, %edx
#else
    mov $1, %edx
#endif
    mov $1, %eax
    syscall
#ifdef READV_CHILD
    cmp $2, %rax
#else
    cmp $1, %rax
#endif
    je child_ok
    neg %rax
    mov %eax, %edi
    jmp exit
child_ok:
    xor %edi, %edi
    jmp exit
fail_read:
    mov $92, %edi
    jmp exit
fail_pipe:
    mov $90, %edi
    jmp exit
fail_wait:
    mov $91, %edi
exit:
    mov $231, %eax                 /* exit_group */
    syscall
    ud2

.data
fds: .long -1, -1
status: .long 0
received: .byte 0
message: .ascii "PQ"
received_second: .byte 0
.balign 8
vectors: .quad received, 1, received_second, 1
