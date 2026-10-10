# Native x86 Linux oracle for IPC DAC permission enforcement returning EACCES.
# Expected stdout: P\n; expected exit: 7.
.global _start
.text
_start:
    mov $-1, %r12
    # 1. Drop/ensure uid 1000: setresuid(1000, 1000, 1000)
    # (On native Linux running as uid 1000, this succeeds; inside Carrick starting as root, this succeeds).
    mov $1000, %rdi
    mov $1000, %rsi
    mov $1000, %rdx
    mov $117, %rax              # SYS_setresuid
    syscall
    test %rax, %rax
    jne fail_drop

    # 2. msgget(IPC_PRIVATE, IPC_CREAT | 0600)
    # IPC_PRIVATE = 0, IPC_CREAT = 01000 = 512, 0600 = 384 -> 01600 = 896
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $896, %rsi              # msgflg = IPC_CREAT | 0600
    mov $68, %rax               # SYS_msgget
    syscall
    test %rax, %rax
    js fail_msgget
    mov %rax, %r12              # r12 = msqid

    # 3. Successful msgsnd by owner
    sub $256, %rsp
    movq $1, 0(%rsp)            # mtype = 1
    movl $0x4b4f5359, 8(%rsp)   # "YSOK"
    mov %r12, %rdi              # msqid
    mov %rsp, %rsi              # msgp
    mov $4, %rdx                # msgsz = 4
    xor %r10, %r10              # msgflg = 0
    mov $69, %rax               # SYS_msgsnd
    syscall
    test %rax, %rax
    jnz fail_owner_send

    # 4. Successful msgrcv by owner
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10              # msgtyp = 0
    xor %r8, %r8
    mov $70, %rax               # SYS_msgrcv
    syscall
    cmp $4, %rax
    jne fail_owner_rcv

    # 5. IPC_STAT
    mov %r12, %rdi
    mov $2, %rsi                # cmd = IPC_STAT
    mov %rsp, %rdx              # msqid_ds buffer
    mov $71, %rax               # SYS_msgctl
    syscall
    test %rax, %rax
    js fail_stat

    # 6. Change mode to 0000 (no permissions) via IPC_SET
    movw $0, 20(%rsp)           # mode offset 20 = 0
    mov %r12, %rdi
    mov $1, %rsi                # cmd = IPC_SET
    mov %rsp, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall
    test %rax, %rax
    js fail_set

    # 7. Attempt msgsnd with mode 0000 -> must fail with -EACCES (-13)
    movq $1, 0(%rsp)
    movl $0x4b4f5359, 8(%rsp)
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax               # SYS_msgsnd
    syscall
    cmp $-13, %rax              # -EACCES = -13
    jne fail_eacces

    # 8. Clean up queue with IPC_RMID
    mov %r12, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall
    test %rax, %rax
    js fail_rmid

    # Success: write "P\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

fail_drop:
    mov $91, %rdi
    jmp exit
fail_msgget:
    mov $92, %rdi
    jmp exit
fail_owner_send:
    mov $93, %rdi
    jmp fail_cleanup
fail_owner_rcv:
    mov $94, %rdi
    jmp fail_cleanup
fail_stat:
    mov $95, %rdi
    jmp fail_cleanup
fail_set:
    mov $96, %rdi
    jmp fail_cleanup
fail_eacces:
    mov $97, %rdi
    jmp fail_cleanup
fail_rmid:
    mov $98, %rdi
    jmp fail_cleanup

fail_cleanup:
    push %rdi
    cmp $0, %r12
    jl 1f
    mov %r12, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall
1:  pop %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "P\n"
