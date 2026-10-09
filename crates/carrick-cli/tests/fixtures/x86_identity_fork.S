# Native x86 Linux oracle for credential and rlimit inheritance across fork.
# Expected stdout: K\n; expected exit: 7.
.global _start
.text
_start:
    # 1. Set RLIMIT_NOFILE to (1000, 2000) on parent
    sub $32, %rsp
    movq $1000, 0(%rsp)
    movq $2000, 8(%rsp)
    xor %rdi, %rdi              # pid 0 (self)
    mov $7, %rsi                # RLIMIT_NOFILE
    mov %rsp, %rdx              # new_limit
    lea 16(%rsp), %r10          # old_limit
    mov $302, %rax              # prlimit64
    syscall
    test %rax, %rax
    jnz fail_prlimit

    # 2. Query current uid and gid
    mov $102, %rax              # getuid
    syscall
    mov %rax, %r12
    mov $104, %rax              # getgid
    syscall
    mov %rax, %r13

    # 3. fork()
    mov $57, %rax               # fork
    syscall
    test %rax, %rax
    js fail_fork
    jz child

    # Parent: wait4(child_pid, &status, 0, NULL)
    mov %rax, %r14              # child pid
    mov %r14, %rdi
    mov %rsp, %rsi              # status buffer
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax               # wait4
    syscall
    cmp %r14, %rax
    jne fail_wait
    cmpl $0, (%rsp)
    jne fail_status

    # Write "K\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

child:
    # Child checks getuid() == %r12
    mov $102, %rax              # getuid
    syscall
    cmp %r12, %rax
    jne child_fail_uid

    # Child checks geteuid() == %r12
    mov $107, %rax              # geteuid
    syscall
    cmp %r12, %rax
    jne child_fail_euid

    # Child checks getgid() == %r13
    mov $104, %rax              # getgid
    syscall
    cmp %r13, %rax
    jne child_fail_gid

    # Child checks getegid() == %r13
    mov $108, %rax              # getegid
    syscall
    cmp %r13, %rax
    jne child_fail_egid

    # Child checks inherited RLIMIT_NOFILE == (1000, 2000)
    xor %rdi, %rdi              # addr = NULL
    mov $4096, %rsi             # length = 4096
    mov $3, %rdx                # PROT_READ | PROT_WRITE
    mov $0x22, %r10             # MAP_PRIVATE | MAP_ANONYMOUS
    mov $-1, %r8                # fd = -1
    xor %r9, %r9                # offset = 0
    mov $9, %rax                # SYS_mmap
    syscall
    test %rax, %rax
    js child_fail_mmap
    mov %rax, %r15              # r15 = mmapped page
    movq $0, 0(%r15)            # touch to fault-in PTE
    movq $0, 8(%r15)

    xor %rdi, %rdi              # pid 0
    mov $7, %rsi                # RLIMIT_NOFILE
    xor %rdx, %rdx              # new_limit = NULL
    mov %r15, %r10              # old_limit = r15
    mov $302, %rax              # prlimit64
    syscall
    test %rax, %rax
    jnz child_fail_prlimit

    cmpq $1000, 0(%r15)
    jne child_fail_cur

    cmpq $2000, 8(%r15)
    jne child_fail_max

    # Exit 0
    xor %rdi, %rdi
    mov $231, %rax              # exit_group
    syscall
    ud2

child_fail_uid:
    mov $81, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_euid:
    mov $82, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_gid:
    mov $83, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_egid:
    mov $84, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_mmap:
    mov $88, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_prlimit:
    neg %rax
    mov %rax, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_cur:
    mov $86, %rdi
    mov $231, %rax
    syscall
    ud2
child_fail_max:
    mov $87, %rdi
    mov $231, %rax
    syscall
    ud2

fail_prlimit:
    mov $93, %rdi
    jmp exit
fail_fork:
    mov $94, %rdi
    jmp exit
fail_wait:
    mov $95, %rdi
    jmp exit
fail_status:
    movl (%rsp), %edi
    shr $8, %edi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "K\n"
