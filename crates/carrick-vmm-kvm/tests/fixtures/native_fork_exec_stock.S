/* Two live fork children: one holds its MM while the other execs. The parent
 * collects the exec child before releasing the holder. CANCEL_PARKED kills
 * the exec child while its stock request is outstanding. */
.global _start
.text
_start:
#if defined(CAUGHT_PARKED) || defined(IGNORED_PARKED) || defined(TWO_SIGNALS_PARKED)
    lea signal_action(%rip), %rsi
    mov $10, %edi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov $14, %eax
    xor %edi, %edi
    lea blocked(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz failure
    mov $57, %eax
    syscall
    test %eax, %eax
    js fork_failure
    jz holder
    mov %eax, %r12d
    mov $57, %eax
    syscall
    test %eax, %eax
    js fork_failure
    jz exec_child
    mov %eax, %r13d
    lea ready(%rip), %rdi
    xor %esi, %esi
    lea long_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $10, %eax
    jne signal_failure
    /* One bounded wait gives the child time to cross into Exec service. */
    lea release_signal(%rip), %rdi
    xor %esi, %esi
    lea short_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
#if defined(CANCEL_PARKED) || defined(TERM_PARKED) || defined(CAUGHT_PARKED) || defined(IGNORED_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    mov %r13d, %edi
#ifdef TWO_SIGNALS_PARKED
    mov $10, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov %r13d, %edi
#if defined(TERM_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    mov $15, %esi
#elif defined(CAUGHT_PARKED) || defined(IGNORED_PARKED)
    mov $10, %esi
#else
    mov $9, %esi
#endif
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#if defined(CAUGHT_PARKED) || defined(IGNORED_PARKED)
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
#else
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov %r13d, %edi
    lea exec_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r13d, %eax
    jne wait_child_failure
#if defined(CANCEL_PARKED) || defined(TERM_PARKED) || defined(CAUGHT_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    mov exec_status(%rip), %eax
    and $127, %eax
#if defined(TERM_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    cmp $15, %eax
#elif defined(CAUGHT_PARKED)
    cmp $10, %eax
#else
    cmp $9, %eax
#endif
    jne signal_status_failure
#if defined(CANCEL_PARKED) || defined(TERM_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    /* The holder must still be alive when wait4 of the killed exec returns. */
    mov %r12d, %edi
    lea holder_status(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    jnz holder_liveness_failure
#endif
#else
    mov exec_status(%rip), %eax
    test %eax, %eax
    jnz failure
#endif
#if defined(CANCEL_PARKED) || defined(TERM_PARKED) || defined(TWO_SIGNALS_PARKED) || defined(TWO_THREAD_TERM_PARKED)
    mov %r12d, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#endif
    mov %r12d, %edi
    lea holder_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    xor %edi, %edi
    jmp exit
holder:
    lea release_signal(%rip), %rdi
    xor %esi, %esi
    lea long_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $12, %eax
    jne signal_failure
    xor %edi, %edi
    jmp exit
exec_child:
    mov $110, %eax
    syscall
    mov %eax, %edi
    mov $10, %esi
    mov $62, %eax
    syscall
    test %eax, %eax
    jnz failure
#ifdef TWO_THREAD_TERM_PARKED
    mov $0x50f00, %edi
    lea thread_stack_top(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %eax, %eax
    js clone_failure
    jz sibling
wait_sibling_ready:
    cmpl $1, sibling_ready(%rip)
    je sibling_ready_for_exec
    mov $24, %eax
    syscall
    jmp wait_sibling_ready
sibling_ready_for_exec:
#endif
#if defined(CAUGHT_PARKED) || defined(IGNORED_PARKED) || defined(TWO_SIGNALS_PARKED)
    /* Leave SIGUSR2 blocked for the holder handshake, but allow SIGUSR1
     * to reach the parked exec service. */
    mov $14, %eax
    mov $2, %edi
    lea release_signal(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz failure
#endif
    lea successor(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
#ifdef TWO_THREAD_TERM_PARKED
    mov %eax, %r14d
    mov $1, %eax
    mov $1, %edi
    lea old_exec_return_marker(%rip), %rsi
    mov $2, %edx
    syscall
    mov %r14d, %eax
#endif
    neg %eax
    mov %eax, %edi
    jmp exit
#ifdef TWO_THREAD_TERM_PARKED
sibling:
    mov $14, %eax
    xor %esi, %esi
    lea term_mask(%rip), %rsi
    mov $0, %edi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %eax, %eax
    jnz clone_failure
    movl $1, sibling_ready(%rip)
    lea term_mask(%rip), %rdi
    xor %esi, %esi
    lea long_bound(%rip), %rdx
    mov $8, %r10d
    mov $128, %eax
    syscall
    cmp $15, %eax
    jne clone_failure
    mov $1, %eax
    mov $1, %edi
    lea sibling_consumed_marker(%rip), %rsi
    mov $2, %edx
    syscall
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
clone_failure:
    mov $95, %edi
    jmp exit
#endif
failure:
    mov $91, %edi
    jmp exit
wait_child_failure:
    mov $94, %edi
    jmp exit
signal_status_failure:
    mov exec_status(%rip), %edi
    mov %edi, %eax
    and $127, %eax
    test %eax, %eax
    jz exited_status
    mov %eax, %edi
    add $128, %edi
    jmp exit
exited_status:
    shr $8, %edi
    jmp exit
holder_liveness_failure:
    cmp $-10, %eax
    je holder_echild
    test %eax, %eax
    js holder_other_errno
    mov $96, %edi
    jmp exit
holder_echild:
    mov $97, %edi
    jmp exit
holder_other_errno:
    mov $98, %edi
    jmp exit
fork_failure:
    mov $92, %edi
    jmp exit
signal_failure:
    mov $93, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
successor: .asciz SUCCESSOR_PATH
.balign 8
argv: .quad successor, 0
blocked: .quad (1 << 9) | (1 << 11)
#if defined(CAUGHT_PARKED) || defined(IGNORED_PARKED) || defined(TWO_SIGNALS_PARKED)
.balign 8
signal_action:
#if defined(CAUGHT_PARKED) || defined(TWO_SIGNALS_PARKED)
    .quad caught_handler, 0x04000000, signal_restorer, 0
#else
    .quad 1, 0, 0, 0
#endif
#endif
ready: .quad (1 << 9)
release_signal: .quad (1 << 11)
short_bound: .quad 0, 100000000
long_bound: .quad 5, 0
.section .bss
.balign 4
exec_status: .space 4
holder_status: .space 4
#if defined(CAUGHT_PARKED) || defined(TWO_SIGNALS_PARKED)
.text
caught_handler:
#ifdef TWO_SIGNALS_PARKED
    mov $1, %eax
    mov $1, %edi
    lea old_handler_marker(%rip), %rsi
    mov $2, %edx
    syscall
#endif
    ret
signal_restorer:
    mov $15, %eax
    syscall
    ud2
#endif
#ifdef TWO_SIGNALS_PARKED
.section .rodata
old_handler_marker: .ascii "H\n"
#endif
#ifdef TWO_THREAD_TERM_PARKED
.section .rodata
old_exec_return_marker: .ascii "R\n"
sibling_consumed_marker: .ascii "S\n"
term_mask: .quad (1 << 14)
#endif
#ifdef TWO_THREAD_TERM_PARKED
.section .bss
.balign 16
thread_stack: .space 16384
thread_stack_top:
.balign 4
sibling_ready: .space 4
#endif
