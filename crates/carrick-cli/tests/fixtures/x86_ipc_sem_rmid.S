# Native x86 Linux oracle for SysV semaphore IPC_RMID with blocked waiter.
# Tests:
# - Waiter process blocks on semaphore (semop -1 on 0)
# - Parent removes the semaphore via IPC_RMID while waiter is blocked
# - Blocked waiter wakes up and receives -EIDRM
# Expected stdout: R\n; expected exit: 7.
.global _start
.text
_start:
    # 1. semget(IPC_PRIVATE, 1, IPC_CREAT | 0666)
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $1, %rsi                # nsems = 1
    mov $950, %rdx              # semflg = IPC_CREAT | 0666
    mov $64, %rax               # SYS_semget
    syscall
    test %rax, %rax
    js fail_semget
    mov %rax, %r12              # r12 = semid

    sub $256, %rsp

    # 2. Initial value is 0
    mov %r12, %rdi
    xor %rsi, %rsi              # semnum = 0
    mov $16, %rdx               # SETVAL
    xor %r10, %r10              # val = 0
    mov $66, %rax               # SYS_semctl
    syscall
    test %rax, %rax
    js fail_semctl

    # 3. fork() child that will block in semop
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child_waiter

    # Parent: wait until child is parked (GETNCNT == 1)
    mov $1000000, %r15
wait_child_parked:
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $14, %rdx               # GETNCNT
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $1, %rax
    je child_is_ready
    dec %r15
    jz fail_child_timeout
    mov $24, %rax               # SYS_sched_yield
    syscall
    jmp wait_child_parked

child_is_ready:
    # Now that child is guaranteed blocked in semop, remove the sem set!
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx              # IPC_RMID = 0
    xor %r10, %r10
    mov $66, %rax
    syscall
    test %rax, %rax
    js fail_semctl

    # Reap child (child verifies it received -EIDRM)
    mov $-1, %rdi
    lea 32(%rsp), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    test %rax, %rax
    js fail_wait
    cmpl $0, 32(%rsp)
    jne fail_child_exit

    # Success: write "R\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child_waiter:
    # Touch stack to break COW
    movq $0, 0(%rsp)
    # Child blocks on semval 0 with semtimedop(-1, 5s timeout)
    movw $0, 0(%rsp)
    movw $-1, 2(%rsp)
    movw $0, 4(%rsp)
    movq $5, 16(%rsp)           # tv_sec = 5s
    movq $0, 24(%rsp)           # tv_nsec = 0
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $1, %rdx
    lea 16(%rsp), %r10
    mov $220, %rax              # SYS_semtimedop
    syscall
    cmp $-43, %rax              # -EIDRM = -43
    jne child_fail
    xor %rdi, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

child_fail:
    mov $81, %rdi
    mov $231, %rax
    syscall
    ud2

fail_semget:
    mov $91, %rdi
    jmp exit
fail_semctl:
    mov $92, %rdi
    jmp fail_exit
fail_fork:
    mov $93, %rdi
    jmp fail_exit
fail_child_timeout:
    mov $94, %rdi
    jmp fail_exit
fail_wait:
    mov $95, %rdi
    jmp fail_exit
fail_child_exit:
    mov $96, %rdi
    jmp fail_exit

fail_exit:
    push %rdi
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx              # IPC_RMID = 0
    xor %r10, %r10
    mov $66, %rax               # SYS_semctl
    syscall
    pop %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "R\n"
