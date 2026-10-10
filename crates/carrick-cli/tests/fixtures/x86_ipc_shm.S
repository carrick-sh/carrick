# Native x86 Linux oracle for SysV shared memory write visible across fork.
# Expected stdout: H\n; expected exit: 7.
.global _start
.text
_start:
    # 1. shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666)
    # IPC_PRIVATE = 0, IPC_CREAT = 01000 = 512, 0666 = 438 -> 01666 = 950
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $4096, %rsi             # size = 4096
    mov $950, %rdx              # shmflg = IPC_CREAT | 0666
    mov $29, %rax               # SYS_shmget
    syscall
    test %rax, %rax
    js fail_shmget
    mov %rax, %r12              # r12 = shmid

    # 2. shmat(shmid, NULL, 0)
    mov %r12, %rdi              # shmid
    xor %rsi, %rsi              # shmaddr = NULL
    xor %rdx, %rdx              # shmflg = 0
    mov $30, %rax               # SYS_shmat
    syscall
    cmp $-4095, %rax
    jae fail_shmat
    mov %rax, %r13              # r13 = attached ptr

    # 3. fork()
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child

    # Parent: wait for child
    sub $32, %rsp
    movq $0, 0(%rsp)
    movq $0, 16(%rsp)
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

    # shmdt(ptr)
    mov %r13, %rdi
    mov $67, %rax               # SYS_shmdt
    syscall
    test %rax, %rax
    jnz fail_shmdt

    # shmctl(shmid, IPC_RMID=0, NULL)
    mov %r12, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $31, %rax               # SYS_shmctl
    syscall
    test %rax, %rax
    js fail_shmctl

    # Success: write "H\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child:
    # Child exits 0
    xor %rdi, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

child_fail_init:
    mov $81, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_shmdt:
    mov $82, %rdi
    mov $231, %rax
    syscall
    ud2

fail_shmget:
    mov $91, %rdi
    jmp exit
fail_shmat:
    mov $92, %rdi
    jmp exit
fail_fork:
    mov $93, %rdi
    jmp exit
fail_wait:
    mov $94, %rdi
    jmp exit
fail_child_exit:
    mov $95, %rdi
    jmp exit
fail_shared_data:
    mov $96, %rdi
    jmp exit
fail_shmdt:
    mov $97, %rdi
    jmp exit
fail_shmctl:
    mov $98, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "H\n"
