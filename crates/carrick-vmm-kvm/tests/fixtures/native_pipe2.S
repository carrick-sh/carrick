/* Native x86 pipe2 through the production CPL0 lane: pipe2(fds, O_CLOEXEC),
 * then both ends closed. The exit status is 7 on success, the positive errno
 * when pipe2 fails (38 for ENOSYS), 90 for a pair other than (3, 4) and 94
 * for a failed close. Bytes through the pair are #1756's x86 ring I/O.
 */
.global _start
.text
_start:
    lea pipefd(%rip), %rdi
    mov $0x80000, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js errno
    cmpl $3, pipefd(%rip)
    jne bad_pair
    cmpl $4, pipefd+4(%rip)
    jne bad_pair
    mov pipefd(%rip), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz close_failed
    mov pipefd+4(%rip), %edi
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz close_failed
    mov $7, %edi
    jmp exit
errno:
    neg %rax
    mov %eax, %edi
    jmp exit
bad_pair:
    mov $90, %edi
    jmp exit
close_failed:
    mov $94, %edi
exit:
    mov $231, %eax
    syscall
    hlt

.data
pipefd: .long -1, -1
