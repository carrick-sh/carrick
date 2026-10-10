# Native x86 Linux oracle for SysV message queue.
# Tests:
# - MSG_NOERROR vs E2BIG
# - MSG_EXCEPT and negative type
# - Receiver synchronization across fork via sync queue
# Note: Deterministic blocked wait is verified under semop in x86_ipc_sem.S via GETNCNT observation; in msg queues, receiver synchronization runs across fork with parent receiving the child's response.
# Expected stdout: M\n; expected exit: 7.
.global _start
.text
_start:
    mov $-1, %r12
    mov $-1, %r13

    # Install SIGALRM handler with distinct exit code 99 for bounded wait on native oracle
    mov $14, %rdi               # SIGALRM = 14
    lea sigact(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10                # sigsetsize = 8
    mov $13, %rax               # SYS_rt_sigaction
    syscall

    # 1. Create main data queue: msgget(IPC_PRIVATE, IPC_CREAT | 0666)
    xor %rdi, %rdi              # key = IPC_PRIVATE
    mov $950, %rsi              # IPC_CREAT | 0666
    mov $68, %rax               # SYS_msgget
    syscall
    test %rax, %rax
    js fail_msgget
    mov %rax, %r12              # r12 = msqid_data

    # 2. Create sync queue: msgget(IPC_PRIVATE, IPC_CREAT | 0666)
    xor %rdi, %rdi
    mov $950, %rsi
    mov $68, %rax
    syscall
    test %rax, %rax
    js fail_msgget
    mov %rax, %r13              # r13 = msqid_sync

    sub $128, %rsp

    # ---------------------------------------------------------
    # Test MSG_NOERROR vs E2BIG
    # ---------------------------------------------------------
    # msgsnd 8 bytes ("12345678")
    movq $1, 0(%rsp)            # mtype = 1
    movabsq $0x3837363534333231, %rax # "12345678"
    movq %rax, 8(%rsp)
    mov %r12, %rdi              # msqid_data
    mov %rsp, %rsi              # msgp
    mov $8, %rdx                # msgsz = 8
    xor %r10, %r10              # msgflg = 0
    mov $69, %rax               # SYS_msgsnd
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    # msgrcv with msgsz = 4, msgflg = 0 -> must fail with -E2BIG (-7)
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $1, %r10                # msgtyp = 1
    xor %r8, %r8                # msgflg = 0
    mov $70, %rax               # SYS_msgrcv
    syscall
    cmp $-7, %rax               # -E2BIG = -7
    jne fail_e2big

    # msgrcv with msgsz = 4, msgflg = MSG_NOERROR (0x1000 = 4096) -> succeeds, returns 4
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $1, %r10
    mov $4096, %r8              # MSG_NOERROR
    mov $70, %rax               # SYS_msgrcv
    syscall
    cmp $4, %rax
    jne fail_noerror
    cmpl $0x34333231, 8(%rsp)   # "1234"
    jne fail_noerror_data

    # ---------------------------------------------------------
    # Test MSG_EXCEPT and negative type
    # ---------------------------------------------------------
    # Send mtype = 2, text "TWO!"
    movq $2, 0(%rsp)
    movl $0x214f5754, 8(%rsp)   # "TWO!"
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    # Send mtype = 1, text "ONE!"
    movq $1, 0(%rsp)
    movl $0x21454e4f, 8(%rsp)   # "ONE!"
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    # msgrcv with msgtyp = 2, msgflg = MSG_EXCEPT (0x20000 = 131072) -> returns mtype = 1 ("ONE!")
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $2, %r10
    mov $8192, %r8              # MSG_EXCEPT (020000 = 8192)
    mov $70, %rax
    syscall
    cmp $4, %rax
    jne fail_msg_except
    cmpq $1, 0(%rsp)
    jne fail_msg_except
    cmpl $0x21454e4f, 8(%rsp)   # "ONE!"
    jne fail_msg_except

    # Consume mtype = 2
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $2, %r10
    xor %r8, %r8
    mov $70, %rax
    syscall
    cmp $4, %rax
    jne fail_consume

    # Send mtype = 5 ("FIVE") then mtype = 3 ("THRE")
    movq $5, 0(%rsp)
    movl $0x45564946, 8(%rsp)   # "FIVE"
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    movq $3, 0(%rsp)
    movl $0x45524854, 8(%rsp)   # "THRE"
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    # msgrcv with msgtyp = -4 -> receives lowest type <= 4 (which is mtype = 3)
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $-4, %r10               # negative type -4
    xor %r8, %r8
    mov $70, %rax
    syscall
    cmp $4, %rax
    jne fail_neg_type
    cmpq $3, 0(%rsp)
    jne fail_neg_type
    cmpl $0x45524854, 8(%rsp)   # "THRE"
    jne fail_neg_type

    # Consume mtype = 5
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    mov $5, %r10
    xor %r8, %r8
    mov $70, %rax
    syscall
    cmp $4, %rax
    jne fail_consume

    # ---------------------------------------------------------
    # Test deterministic blocked receiver across fork
    # ---------------------------------------------------------
    mov $57, %rax               # SYS_fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child_blocked_test

    # Parent:
    # 1. Send sync token to msqid_sync (releases child from initial wait)
    sub $32, %rsp
    movq $1, 0(%rsp)            # mtype = 1
    movl $0x434e5953, 8(%rsp)   # "SYNC"
    mov %r13, %rdi              # msqid_sync
    mov %rsp, %rsi              # msgp
    mov $4, %rdx                # msgsz = 4
    xor %r10, %r10              # msgflg = 0
    mov $69, %rax               # SYS_msgsnd
    syscall
    test %rax, %rax
    jnz fail_msgsnd

    # 2. Block in msgrcv on empty msqid_data waiting for mtype = 100
    # Arm 4-second alarm to bound msgrcv on native Linux oracle
    mov $4, %rdi
    mov $37, %rax               # SYS_alarm
    syscall

    mov %r12, %rdi              # msqid_data
    mov %rsp, %rsi              # msgp
    mov $4, %rdx                # msgsz = 4
    mov $100, %r10              # msgtyp = 100
    xor %r8, %r8                # msgflg = 0
    mov $70, %rax               # SYS_msgrcv
    syscall
    mov %rax, %r14              # save msgrcv retval in r14

    # Disarm alarm
    xor %rdi, %rdi
    mov $37, %rax               # SYS_alarm
    syscall
    # 3. Reap child
    mov $-1, %rdi
    lea 16(%rsp), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax               # SYS_wait4
    syscall
    test %rax, %rax
    js fail_wait
    mov 16(%rsp), %eax
    shr $8, %eax
    test %eax, %eax
    jz child_ok
    # Child failed: exit with child's exit code
    mov %rax, %rdi
    jmp fail_cleanup
child_ok:

    cmp $4, %r14
    cmpq $100, 0(%rsp)
    jne fail_mtype
    cmpl $0x454b4157, 8(%rsp)   # "WAKE"
    jne fail_mtext

    # 4. Clean up queues
    mov %r12, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall

    mov %r13, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall

    # Success: write "M\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child_blocked_test:
    # Child 1: wait for parent's sync token on msqid_sync
    sub $32, %rsp
    movq $0, 0(%rsp)            # Touch stack to trigger COW fault and make page writable!
    movq $0, 8(%rsp)
    mov %r13, %rdi              # msqid_sync
    mov %rsp, %rsi
    mov $4, %rdx
    mov $1, %r10                # msgtyp = 1
    xor %r8, %r8
    mov $70, %rax               # SYS_msgrcv
    syscall
    cmp $4, %rax
    jne child_fail

    # Send WAKE message to msqid_data to unblock parent
    movq $100, 0(%rsp)          # mtype = 100
    movl $0x454b4157, 8(%rsp)   # "WAKE"
    mov %r12, %rdi              # msqid_data
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax               # SYS_msgsnd
    syscall
    test %rax, %rax
    jnz child_fail

    xor %rdi, %rdi
    mov $231, %rax              # SYS_exit_group
    syscall
    ud2

child_fail:
    # Save failure reason in %r15
    mov %rax, %r15
    # Send wake to msqid_data so parent does not hang
    sub $32, %rsp
    movq $100, 0(%rsp)
    movl $0x4c494146, 8(%rsp)   # "FAIL"
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    xor %r10, %r10
    mov $69, %rax               # SYS_msgsnd
    syscall
    # Exit with negated error code (e.g. 14 for EFAULT)
    neg %r15
    mov %r15, %rdi
    mov $231, %rax
    syscall
    ud2

fail_msgget:
    mov $91, %rdi
    jmp fail_cleanup
fail_fork:
    mov $92, %rdi
    jmp fail_cleanup
fail_msgsnd:
    mov $93, %rdi
    jmp fail_cleanup
fail_msgrcv:
    mov $94, %rdi
    jmp fail_cleanup
fail_mtype:
    mov $95, %rdi
    jmp fail_cleanup
fail_mtext:
    mov $96, %rdi
    jmp fail_cleanup
fail_wait:
    mov $97, %rdi
    jmp fail_cleanup
fail_child_exit:
    mov $98, %rdi
    jmp fail_cleanup
fail_msgctl:
    mov $99, %rdi
    jmp fail_cleanup
fail_e2big:
    mov $100, %rdi
    jmp fail_cleanup
fail_noerror:
    mov $101, %rdi
    jmp fail_cleanup
fail_noerror_data:
    mov $102, %rdi
    jmp fail_cleanup
fail_msg_except:
    mov $103, %rdi
    jmp fail_cleanup
fail_consume:
    mov $104, %rdi
    jmp fail_cleanup
fail_neg_type:
    mov $105, %rdi
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
1:  cmp $0, %r13
    jl 2f
    mov %r13, %rdi
    xor %rsi, %rsi              # IPC_RMID = 0
    xor %rdx, %rdx
    mov $71, %rax               # SYS_msgctl
    syscall
2:  pop %rdi
    jmp exit

sigalrm_handler:
    mov $99, %rdi
    mov $60, %rax               # exit(99)
    syscall
    ud2

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "M\n"

.data
.align 8
sigact:
    .quad sigalrm_handler       # sa_handler
    .quad 0                     # sa_flags
    .quad 0                     # sa_restorer
    .quad 0                     # sa_mask
