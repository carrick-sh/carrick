# Native x86 Linux oracle for SysV semaphore.
# Tests:
# - Cumulative multi-op semop & atomic rollback
# - semtimedop timeout gives EAGAIN
# - Deterministic blocked receiver woken across fork (bounded wait via semtimedop & GETNCNT)
# Expected stdout: S\n; expected exit: 7.
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

    sub $512, %rsp

    # ---------------------------------------------------------
    # Test 1: Cumulative multi-op semop & atomic rollback
    # ---------------------------------------------------------
    # semctl(semid, 0, SETVAL=16, 0)
    mov %r12, %rdi
    xor %rsi, %rsi              # semnum = 0
    mov $16, %rdx               # SETVAL
    xor %r10, %r10              # val = 0
    mov $66, %rax               # SYS_semctl
    syscall
    test %rax, %rax
    js fail_semctl

    # Case A: [(0, +1), (0, -1)] on 0 succeeds
    movw $0, 0(%rsp)            # sem_num = 0
    movw $1, 2(%rsp)            # sem_op = +1
    movw $0, 4(%rsp)            # sem_flg = 0
    movw $0, 6(%rsp)            # sem_num = 0
    movw $-1, 8(%rsp)           # sem_op = -1
    movw $0, 10(%rsp)           # sem_flg = 0

    mov %r12, %rdi
    mov %rsp, %rsi
    mov $2, %rdx                # nsops = 2
    mov $65, %rax               # SYS_semop
    syscall
    test %rax, %rax
    jnz fail_multi_op

    # Check semval == 0
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $12, %rdx               # GETVAL
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $0, %rax
    jne fail_getval

    # Case B: Set val = 1; [(0, -1, 0), (0, -1, IPC_NOWAIT=2048)] fails with EAGAIN (-11)
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $16, %rdx               # SETVAL
    mov $1, %r10                # val = 1
    mov $66, %rax
    syscall
    test %rax, %rax
    js fail_semctl

    movw $0, 0(%rsp)            # sem_num = 0
    movw $-1, 2(%rsp)           # sem_op = -1
    movw $0, 4(%rsp)            # sem_flg = 0
    movw $0, 6(%rsp)            # sem_num = 0
    movw $-1, 8(%rsp)           # sem_op = -1
    movw $2048, 10(%rsp)        # sem_flg = IPC_NOWAIT (2048)

    mov %r12, %rdi
    mov %rsp, %rsi
    mov $2, %rdx                # nsops = 2
    mov $65, %rax               # SYS_semop
    syscall
    cmp $-11, %rax              # -EAGAIN = -11
    jne fail_eagain

    # Atomic rollback: semval must still be 1!
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $12, %rdx               # GETVAL
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $1, %rax
    jne fail_rollback

    # ---------------------------------------------------------
    # Test 2: semtimedop timeout gives EAGAIN
    # ---------------------------------------------------------
    # Set val = 0
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $16, %rdx
    xor %r10, %r10
    mov $66, %rax
    syscall

    # semtimedop(semid, sops={0, -1, 0}, 1, &timespec{tv_sec=0, tv_nsec=1_000_000})
    movw $0, 0(%rsp)
    movw $-1, 2(%rsp)
    movw $0, 4(%rsp)
    movq $0, 16(%rsp)           # tv_sec = 0
    movq $1000000, 24(%rsp)     # tv_nsec = 1ms
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $1, %rdx                # nsops = 1
    lea 16(%rsp), %r10          # timeout
    mov $220, %rax              # SYS_semtimedop
    syscall
    cmp $-11, %rax              # -EAGAIN = -11
    jne fail_timedop

    # ---------------------------------------------------------
    # Test 3: Deterministic blocked receiver woken across fork
    # ---------------------------------------------------------
    # Semval is 0
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child_wake_test

    # Parent: blocks on semtimedop with bounded 5s timeout until child wakes it
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
    test %rax, %rax
    jnz fail_semop

    # wait4(-1, &status, 0, NULL)
    mov $-1, %rdi
    lea 32(%rsp), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax               # SYS_wait4
    syscall
    test %rax, %rax
    js fail_wait
    cmpl $0, 32(%rsp)
    jne fail_child_exit

    # Clean up sem set
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx              # IPC_RMID = 0
    xor %r10, %r10
    mov $66, %rax
    syscall

    # Success: write "S\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child_wake_test:
    # Touch stack to break COW
    movq $0, 0(%rsp)
    # Child: bounded wait until parent is blocked in semop (GETNCNT == 1)
    mov $1000, %r15             # bounded retry count
wait_parent_wake:
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $14, %rdx               # GETNCNT
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $1, %rax
    je parent_is_parked
    dec %r15
    jz child_fail
    mov $24, %rax               # SYS_sched_yield
    syscall
    jmp wait_parent_wake

parent_is_parked:
    # Wake parent with semop(+1)
    movw $0, 0(%rsp)
    movw $1, 2(%rsp)
    movw $0, 4(%rsp)
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $1, %rdx
    mov $65, %rax
    syscall
    test %rax, %rax
    jnz child_fail
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
    jmp fail_exit
fail_semctl:
    mov $92, %rdi
    jmp fail_exit
fail_multi_op:
    mov $93, %rdi
    jmp fail_exit
fail_getval:
    mov $94, %rdi
    jmp fail_exit
fail_eagain:
    mov $95, %rdi
    jmp fail_exit
fail_rollback:
    mov $96, %rdi
    jmp fail_exit
fail_timedop:
    mov $97, %rdi
    jmp fail_exit
fail_fork:
    mov $98, %rdi
    jmp fail_exit
fail_wait:
    mov $99, %rdi
    jmp fail_exit
fail_child_exit:
    mov $100, %rdi
    jmp fail_exit
fail_semop:
    mov $101, %rdi
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
ok: .ascii "S\n"
