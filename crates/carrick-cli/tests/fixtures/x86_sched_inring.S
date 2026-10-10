# In-ring scheduling calls and deterministic error paths.
# Tests sched_get_priority_min/max with valid and invalid policies,
# and sched_rr_get_interval with negative pid (-EINVAL), null pointer (-EFAULT),
# unknown pid (-ESRCH), and valid self pid (success, tv_sec=0, tv_nsec>0).
# Expected stdout: S\n; expected exit: 7.
.global _start
.text
_start:
    # 1. sched_get_priority_min(SCHED_OTHER=0) -> 0
    xor %rdi, %rdi
    mov $147, %rax
    syscall
    test %rax, %rax
    jnz fail

    # 2. sched_get_priority_max(SCHED_OTHER=0) -> 0
    xor %rdi, %rdi
    mov $146, %rax
    syscall
    test %rax, %rax
    jnz fail

    # 3. sched_get_priority_min(SCHED_FIFO=1) -> 1
    mov $1, %rdi
    mov $147, %rax
    syscall
    cmp $1, %rax
    jne fail

    # 4. sched_get_priority_max(SCHED_FIFO=1) -> 99
    mov $1, %rdi
    mov $146, %rax
    syscall
    cmp $99, %rax
    jne fail

    # 5. sched_get_priority_min(-1) -> -EINVAL (-22)
    mov $-1, %rdi
    mov $147, %rax
    syscall
    cmp $-22, %rax
    jne fail

    # 6. sched_get_priority_max(4) -> -EINVAL (-22)
    mov $4, %rdi
    mov $146, %rax
    syscall
    cmp $-22, %rax
    jne fail

    # 7. sched_rr_get_interval(-1, NULL) -> -EINVAL (-22) (pid check precedes ptr)
    mov $-1, %rdi
    xor %rsi, %rsi
    mov $148, %rax
    syscall
    cmp $-22, %rax
    jne fail

    # 8. sched_rr_get_interval(0, NULL) -> -EFAULT (-14)
    xor %rdi, %rdi
    xor %rsi, %rsi
    mov $148, %rax
    syscall
    cmp $-14, %rax
    jne fail

    # 9. sched_rr_get_interval(999999, &ts) -> -ESRCH (-3)
    mov $999999, %rdi
    lea ts(%rip), %rsi
    mov $148, %rax
    syscall
    cmp $-3, %rax
    jne fail

    # 10. sched_rr_get_interval(0, &ts) -> 0, tv_sec=0, tv_nsec>0
    xor %rdi, %rdi
    lea ts(%rip), %rsi
    mov $148, %rax
    syscall
    test %rax, %rax
    jnz fail
    cmpq $0, ts(%rip)
    jne fail
    cmpq $0, ts+8(%rip)
    jle fail

    # Fork leaves a visible child (including an unreaped zombie).
    mov $57, %rax
    syscall
    test %rax, %rax
    js fail
    jz child_exit
    mov %rax, %r12
    # Fault the parent's data page writable after fork before the exact copy.
    movq $0, ts(%rip)
    movq $0, ts+8(%rip)
    mov %r12, %rdi
    lea ts(%rip), %rsi
    mov $148, %rax
    syscall
    test %rax, %rax
    jnz fail
    cmpq $0, ts+8(%rip)
    jle fail
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp %r12, %rax
    jne fail

    # Write "S\n" to stdout
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child_exit:
    xor %rdi, %rdi
    jmp exit

fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2

.data
.balign 8
ts:
    .quad 0
    .quad 0

.section .rodata
ok: .ascii "S\n"
