# Native x86 Linux oracle for SEM_UNDO on process exit.
# Tests:
# - Process acquires semaphore with SEM_UNDO
# - On process exit, the kernel undoes the semaphore adjustments
# - Parent observes the restored semaphore value
# Expected stdout: U\n; expected exit: 7.
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

    # 2. Set initial value to 10
    mov %r12, %rdi
    xor %rsi, %rsi              # semnum = 0
    mov $16, %rdx               # SETVAL
    mov $10, %r10               # val = 10
    mov $66, %rax               # SYS_semctl
    syscall
    test %rax, %rax
    js fail_semctl

    # 3. fork() child that modifies sem with SEM_UNDO and exits
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child

    # Parent: wait for child
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

    # With SEM_UNDO on child exit, semval must be restored to 10!
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $12, %rdx               # GETVAL
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $10, %rax
    jne fail_undo

    # Clean up sem set
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx              # IPC_RMID = 0
    xor %r10, %r10
    mov $66, %rax
    syscall

    # Success: write "U\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child:
    # Touch stack to break COW
    movq $0, 0(%rsp)
    # Child modifies sem with SEM_UNDO: sem_op = -5, sem_flg = SEM_UNDO (4096)
    movw $0, 0(%rsp)
    movw $-5, 2(%rsp)
    movw $4096, 4(%rsp)         # SEM_UNDO = 4096
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $1, %rdx
    mov $65, %rax               # SYS_semop
    syscall
    test %rax, %rax
    jnz child_fail

    # Verify semval is now 5
    mov %r12, %rdi
    xor %rsi, %rsi
    mov $12, %rdx               # GETVAL
    xor %r10, %r10
    mov $66, %rax
    syscall
    cmp $5, %rax
    jne child_fail

    # Child exits normally (triggers kernel SEM_UNDO cleanup)
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
fail_wait:
    mov $94, %rdi
    jmp fail_exit
fail_child_exit:
    mov $95, %rdi
    jmp fail_exit
fail_undo:
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
ok: .ascii "U\n"
