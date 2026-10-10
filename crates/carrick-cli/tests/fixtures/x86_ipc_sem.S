# Native x86 Linux oracle for SysV semaphore with blocked waiter woken by other process.
# Expected stdout: S\n; expected exit: 7.
.global _start
.text
_start:
    # 1. semget(IPC_PRIVATE, 1, IPC_CREAT | 0666)
    # IPC_PRIVATE = 0, IPC_CREAT = 01000 = 512, 0666 = 438 -> 01666 = 950
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $1, %rsi                # nsems = 1
    mov $950, %rdx              # semflg = IPC_CREAT | 0666
    mov $64, %rax               # SYS_semget
    syscall
    test %rax, %rax
    js fail_semget
    mov %rax, %r12              # r12 = semid

    # 2. semctl(semid, 0, SETVAL=16, 0)
    mov %r12, %rdi              # semid
    xor %rsi, %rsi              # semnum = 0
    mov $16, %rdx               # cmd = SETVAL
    xor %r10, %r10              # val = 0
    mov $66, %rax               # SYS_semctl
    syscall
    test %rax, %rax
    js fail_semctl

    # 3. fork()
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child

    # Parent: blocks on semop(sem_op = -1) until child wakes it
    sub $32, %rsp
    movw $0, 0(%rsp)            # sem_num = 0
    movw $-1, 2(%rsp)           # sem_op = -1
    movw $0, 4(%rsp)            # sem_flg = 0
    mov %r12, %rdi              # semid
    mov %rsp, %rsi              # sops
    mov $1, %rdx                # nsops = 1
    mov $65, %rax               # SYS_semop
    syscall
    test %rax, %rax
    jnz fail_semop

    # wait4(-1, &status, 0, NULL)
    mov $-1, %rdi
    lea 16(%rsp), %rsi          # status buffer
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax               # SYS_wait4
    syscall
    test %rax, %rax
    js fail_wait
    cmpl $0, 16(%rsp)
    jne fail_child_exit

    # semctl(semid, 0, IPC_RMID=0, 0)
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx              # IPC_RMID = 0
    xor %r10, %r10
    mov $66, %rax               # SYS_semctl
    syscall
    test %rax, %rax
    js fail_rmid

    # Success: write "S\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child:
    # Child: wakes parent with semop(sem_op = +1)
    sub $32, %rsp
    movw $0, 0(%rsp)            # sem_num = 0
    movw $1, 2(%rsp)            # sem_op = 1
    movw $0, 4(%rsp)            # sem_flg = 0
    mov %r12, %rdi              # semid
    mov %rsp, %rsi              # sops
    mov $1, %rdx                # nsops = 1
    mov $65, %rax               # SYS_semop
    syscall
    test %rax, %rax
    jnz child_fail_semop

    # Child exits 0
    xor %rdi, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

child_fail_semop:
    mov $81, %rdi
    mov $231, %rax
    syscall
    ud2

fail_semget:
    mov $91, %rdi
    jmp exit
fail_semctl:
    mov $92, %rdi
    jmp exit
fail_fork:
    mov $93, %rdi
    jmp exit
fail_semop:
    mov $94, %rdi
    jmp exit
fail_wait:
    mov $95, %rdi
    jmp exit
fail_child_exit:
    mov $96, %rdi
    jmp exit
fail_rmid:
    mov $97, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "S\n"
