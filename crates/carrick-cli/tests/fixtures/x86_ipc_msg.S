# Native x86 Linux oracle for SysV message queue round trip across fork.
# Expected stdout: M\n; expected exit: 7.
.global _start
.text
_start:
    # 1. msgget(IPC_PRIVATE, IPC_CREAT | 0666)
    # IPC_PRIVATE = 0, IPC_CREAT = 01000 = 512, 0666 = 438 -> 01666 = 950
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $950, %rsi              # msgflg = IPC_CREAT | 0666
    mov $68, %rax               # SYS_msgget
    syscall
    test %rax, %rax
    js fail_msgget
    mov %rax, %r12              # r12 = msqid

    # 2. fork()
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child

    # Parent: msgrcv(msqid, &buf, 4, 1, 0)
    sub $32, %rsp
    movq $0, 0(%rsp)
    movq $0, 8(%rsp)
    mov %r12, %rdi              # msqid
    mov %rsp, %rsi              # msgp
    mov $4, %rdx                # msgsz = 4
    mov $1, %r10                # msgtyp = 1
    xor %r8, %r8                # msgflg = 0
    mov $70, %rax               # SYS_msgrcv
    syscall
    cmp $4, %rax
    jne fail_msgrcv

    # Verify received content: mtype == 1, mtext == "MSG!"
    cmpq $1, 0(%rsp)
    jne fail_mtype
    cmpl $0x2147534d, 8(%rsp)   # 'M', 'S', 'G', '!' (little endian: 0x2147534d)
    jne fail_mtext

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

    # msgctl(msqid, IPC_RMID, NULL)
    mov %r12, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall
    test %rax, %rax
    js fail_msgctl

    # Success: write "M\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child:
    # Child: msgsnd(msqid, &buf, 4, 0)
    sub $32, %rsp
    movq $1, 0(%rsp)            # mtype = 1
    movl $0x2147534d, 8(%rsp)   # "MSG!"
    mov %r12, %rdi              # msqid
    mov %rsp, %rsi              # msgp
    mov $4, %rdx                # msgsz = 4
    xor %r10, %r10              # msgflg = 0
    mov $69, %rax               # SYS_msgsnd
    syscall
    test %rax, %rax
    jnz child_fail_msgsnd

    # Child exits 0
    xor %rdi, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

child_fail_msgsnd:
    mov $81, %rdi
    mov $231, %rax
    syscall
    ud2

fail_msgget:
    mov $91, %rdi
    jmp exit
fail_fork:
    mov $92, %rdi
    jmp exit
fail_msgrcv:
    mov $93, %rdi
    jmp exit
fail_mtype:
    mov $94, %rdi
    jmp exit
fail_mtext:
    mov $95, %rdi
    jmp exit
fail_wait:
    mov $96, %rdi
    jmp exit
fail_child_exit:
    mov $97, %rdi
    jmp exit
fail_msgctl:
    mov $98, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "M\n"
