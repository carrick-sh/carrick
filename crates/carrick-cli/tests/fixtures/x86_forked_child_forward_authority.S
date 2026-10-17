/* Forward authority of a forked in-zone child (#542 ruling 2). The parent
 * forks and waits in wait4; the child's forward is a crossing from a task
 * that is not the run's root, so it must never run under the root's host
 * KernelContext, never park on the root's lease and never publish the run's
 * exit. One variant per -D flag:
 *
 *   CHILD_EXIT_STATUS     child exit_group(3); the parent reaps status 3<<8
 *                         and the run exits 7 (the child's exit is not the
 *                         run's exit).
 *   CHILD_STDIN_READ      child read(0); a host read needs a host task
 *                         context the child does not have, so the run is
 *                         refused.
 *   CHILD_POLL_WAIT       child ppoll({1, POLLIN}, 50 ms): stdout never
 *                         becomes readable, so the host readiness crossing
 *                         must wait, and a wait needs the child's own
 *                         execution lease; the run is refused.
 *   CHILD_STDOUT_REDIRECT child dup2(2, 1) then write(1, "P"): fd 1 resolves
 *                         through the child's own table to the stderr
 *                         binding, so "P" reaches stderr and host stdout
 *                         stays empty. Exit 7.
 *   CHILD_PIPE_DUP2_STDOUT parent pipe2(p, 0) then fork; child dup2(p[1], 1)
 *                         then write(1, "P", 1); parent reads p[0], writes
 *                         what it read to stdout, and reaps the child in
 *                         wait4 before exiting 7.
 *
 * Failure codes: 91 parent wait/status, 92 child syscall. */
.global _start
.text
_start:
#ifdef CHILD_PIPE_DUP2_STDOUT
    lea pipefd(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
#ifdef CHILD_PIPE_UNFAULTED_COW
    jnz failure
#else
    jz 1f
    cmp $-38, %eax
    jne failure
1:
#endif
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
#ifdef CHILD_PIPE_DUP2_STDOUT
    mov %eax, %ebx
#ifndef CHILD_PIPE_UNFAULTED_COW
    movb $0, buffer(%rip)
#endif
    mov pipefd(%rip), %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne failure
    cmpb $'P', buffer(%rip)
    jne failure
    mov $1, %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne failure
    mov %ebx, %eax
#endif
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
#ifdef CHILD_EXIT_STATUS
    cmpl $0x300, status(%rip)
#else
    cmpl $0, status(%rip)
#endif
    jne failure
    mov $7, %edi
    jmp exit

child:
#ifdef CHILD_EXIT_STATUS
    mov $3, %edi
    jmp exit
#endif
#ifdef CHILD_STDIN_READ
    xor %edi, %edi
    lea buffer(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    test %rax, %rax
    js child_failure
#endif
#ifdef CHILD_POLL_WAIT
    lea pollfd(%rip), %rdi
    mov $1, %esi
    lea timeout(%rip), %rdx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $271, %eax
    syscall
    test %rax, %rax
    js child_failure
#endif
#ifdef CHILD_STDOUT_REDIRECT
    mov $2, %edi
    mov $1, %esi
    mov $33, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    mov $1, %edi
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
#endif
#ifdef CHILD_PIPE_DUP2_STDOUT
    mov pipefd+4(%rip), %edi
    mov $1, %esi
    mov $33, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    mov $1, %edi
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
#endif
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
message: .ascii "P"
.balign 8
timeout: .quad 0, 50000000

.section .data
.balign 8
pollfd: .long 1
        .short 1, 0
.balign 4
pipefd: .long 3, 4
status: .long 0
buffer: .long 0
