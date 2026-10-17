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
 *
 * Failure codes: 91 parent wait/status, 92 child syscall. */
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

.section .bss
.balign 4
status: .space 4
buffer: .space 4
