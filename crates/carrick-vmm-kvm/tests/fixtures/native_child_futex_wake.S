/* #1961 review P0-1: a fork child's thread on CPU 1 wakes the child's
 * main thread, which may run only on CPU 0. The woken thread exits the
 * child with 19; the parent reaps it and exits 7.
 * Writes are host rendezvous points; no fixture completes a guest
 * lifecycle.
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    movb $1, marker_byte(%rip)
    call marker
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure_wait4
    /* The child's own status, if not 19 (each failure path exits with
     * its own code). */
    mov status(%rip), %edi
    shr $8, %edi
    cmpl $(19 << 8), status(%rip)
    jne exit
    mov $7, %edi
    jmp exit
child:
    /* glibc's thread flags: VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID. The new thread runs first. */
    mov $0x3d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz thread
    js failure
    /* The waiter. The host has moved it to CPU 0, the only CPU it may
     * run on, while the new thread is stopped on CPU 1. */
    movl $1, ready(%rip)
    /* FUTEX_WAIT_PRIVATE on go == 0. */
    lea go(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    test %eax, %eax
    jnz failure_wait
    mov $19, %edi
    jmp exit
thread:
    /* Stop CPU 1 with the main thread queued behind this one. */
    movb $2, marker_byte(%rip)
    call marker
    /* The host resumes this thread only once the main thread has parked
     * on CPU 0. */
    cmpl $1, ready(%rip)
    jne failure_ready
    movl $1, go(%rip)
    /* FUTEX_WAKE_PRIVATE of the main thread, parked on go. */
    lea go(%rip), %rdi
    mov $129, %esi
    mov $1, %edx
    mov $202, %eax
    syscall
    cmp $1, %eax
    jne failure_wake
    /* Raw exit: only this thread ends; the woken thread ends the child. */
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
failure_wait4:
    mov $92, %edi
    jmp exit
failure_wait:
    mov $93, %edi
    jmp exit
failure_ready:
    mov $94, %edi
    jmp exit
failure_wake:
    /* 100 + the wake's result, mod 256 (a result left as the syscall
     * number 202 reads 46). */
    lea 100(%rax), %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
marker:
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

/* Ordinary zero-fill ELF storage. */
.bss
.balign 4096
marker_byte: .space 8
status: .space 8
go: .space 8
ready: .space 8
parent_tid: .space 8
child_tid: .space 8
tls: .space 256
.balign 16
thread_stack: .space 16384
thread_stack_top:
