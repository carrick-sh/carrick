/*
 * Native CPU-time clocks (CLOCK_PROCESS_CPUTIME_ID = 2,
 * CLOCK_THREAD_CPUTIME_ID = 3) and times(2) witness across:
 *   1. Root times(NULL), times(1) -> -EFAULT, times(&tms), clock_getres(2/3),
 *      clock_gettime(2/3, NULL) -> -EFAULT, and raw vs vDSO ordering.
 *   2. Two live threads: a clone worker burns >= 35 ms of CPU and exits via
 *      raw exit(60) while the root waits in FUTEX_WAIT; process CPU folds the
 *      retired thread and exceeds the parked root thread's CPU.
 *   3. Two live processes: parent and fork child sample concurrently; child
 *      starts with fresh CPU counters, burns >= 40 ms user CPU plus a raw
 *      getpid syscall burst until ru_stime > 0, and exits 8; parent reaps via
 *      wait4(&rusage) and verifies nonzero user/system rusage and children
 *      tms_cutime + tms_cstime without absorbing the child burn into self.
 *
 * Exit codes: 8 success, 38 ENOSYS, 90..95 failed invariant, 218 missing auxv.
 */
.global _start
.text
_start:
    mov (%rsp), %rcx
    lea 16(%rsp,%rcx,8), %rax
skip_env:
    add $8, %rax
    cmpq $0, -8(%rax)
    jne skip_env
aux:
    mov (%rax), %rcx
    test %rcx, %rcx
    jz missing
    cmp $33, %ecx
    je found_vdso
    add $16, %rax
    jmp aux
found_vdso:
    mov 8(%rax), %r15
    test %r15, %r15
    jz missing
    cmpl $0x464c457f, (%r15)
    jne fail_90
    cmpw $62, 18(%r15)
    jne fail_90
    lea gettime_symbol(%rip), %r10
    mov $21, %r11d
    call find_symbol
    mov %rax, %r14

    /* Map 0x4000 bytes of private anonymous scratch + worker stack. */
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_90
    mov %rax, %r12
    movl $0, 0x000(%r12)
    movl $0, 0x1000(%r12)
    movl $0, 0x2000(%r12)
    movl $0, 0x3000(%r12)

    /* 1. Root times(NULL), times(unmapped) -> -EFAULT, times(&tms). */
    xor %edi, %edi
    mov $100, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $0, %rax
    jle fail_90
    mov %rax, %r13

    mov $1, %edi
    mov $100, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $-14, %rax
    jne fail_90

    lea 0x020(%r12), %rdi
    mov $100, %eax
    syscall
    cmp %r13, %rax
    jl fail_90
    cmpq $0, 0x020(%r12)
    jl fail_90
    cmpq $0, 0x028(%r12)
    jl fail_90
    cmpq $0, 0x030(%r12)
    jne fail_90
    cmpq $0, 0x038(%r12)
    jne fail_90

    call compare_cputime_clocks

    /* 2. Spawn worker thread (CLONE_VM|...|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID). */
    mov $0x00350f00, %edi
    lea 0x2000(%r12), %rsi
    lea 0x3000(%r12), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_92
    jz worker_thread

join_worker:
    mov 0x3000(%r12), %edx
    test %edx, %edx
    jz worker_joined
    lea 0x3000(%r12), %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp join_worker

worker_joined:
    /* Read root thread CPU first, then process CPU (which folded the retired worker). */
    mov $3, %edi
    call read_clock_ns
    mov %rax, %rbx
    mov $2, %edi
    call read_clock_ns
    cmp $35000000, %rax
    jb fail_92
    sub %rbx, %rax
    cmp $15000000, %rax
    jb fail_92

    lea 0x020(%r12), %rdi
    mov $100, %eax
    syscall
    cmp $0, %rax
    jle fail_92
    mov 0x020(%r12), %rax
    add 0x028(%r12), %rax
    cmp $2, %rax
    jl fail_92
    cmpq $0, 0x030(%r12)
    jne fail_92
    cmpq $0, 0x038(%r12)
    jne fail_92
    mov %rax, %r13

    /* 3. Fork a child process; parent and child sample concurrently. */
    mov $57, %eax
    syscall
    test %rax, %rax
    js fail_93
    jz fork_child

    mov %eax, %ebx
    call compare_cputime_clocks

    mov %ebx, %edi
    lea 0x000(%r12), %rsi
    xor %edx, %edx
    lea 0x100(%r12), %r10
    mov $61, %eax
    syscall
    cmp %ebx, %eax
    jne fail_95
    mov 0x000(%r12), %edi
    test $0x7f, %edi
    jnz fail_95
    shr $8, %edi
    cmp $8, %edi
    jne exit_code

    /* wait4 rusage must report both user and system CPU > 0 for the reaped child. */
    imul $1000000, 0x100(%r12), %rax
    add 0x108(%r12), %rax
    cmp $0, %rax
    jle fail_95
    imul $1000000, 0x110(%r12), %rax
    add 0x118(%r12), %rax
    cmp $0, %rax
    jle fail_95

    /* getrusage(RUSAGE_CHILDREN = -1) must match nonzero user and system CPU. */
    mov $-1, %edi
    lea 0x100(%r12), %rsi
    mov $98, %eax
    syscall
    test %rax, %rax
    jnz fail_95
    imul $1000000, 0x100(%r12), %rax
    add 0x108(%r12), %rax
    cmp $0, %rax
    jle fail_95
    imul $1000000, 0x110(%r12), %rax
    add 0x118(%r12), %rax
    cmp $0, %rax
    jle fail_95

    /* times(&tms) must report child ticks >= 2 without charging child burn to parent self. */
    lea 0x020(%r12), %rdi
    mov $100, %eax
    syscall
    cmp $0, %rax
    jle fail_95
    mov 0x030(%r12), %rcx
    add 0x038(%r12), %rcx
    cmp $2, %rcx
    jl fail_95
    mov 0x020(%r12), %rax
    add 0x028(%r12), %rax
    cmp %r13, %rax
    jl fail_95
    sub %r13, %rax
    cmp %rcx, %rax
    jge fail_95

    mov $8, %edi
    jmp exit_code

worker_thread:
    mov $3, %edi
    call read_clock_ns
    mov %rax, %r13
worker_spin:
    mov $0x10000, %ecx
1:
    pause
    dec %ecx
    jnz 1b
    mov $3, %edi
    call read_clock_ns
    mov %rax, %rbx
    sub %r13, %rax
    cmp $35000000, %rax
    jb worker_spin
    mov $2, %edi
    call read_clock_ns
    cmp %rbx, %rax
    jb fail_92
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fork_child:
    /* Freshly forked child starts with its own zeroed CPU and children ledgers. */
    mov $2, %edi
    call read_clock_ns
    cmp $20000000, %rax
    jae fail_93
    lea 0x020(%r12), %rdi
    mov $100, %eax
    syscall
    cmp $0, %rax
    jle fail_93
    cmpq $0, 0x030(%r12)
    jne fail_93
    cmpq $0, 0x038(%r12)
    jne fail_93
    mov 0x020(%r12), %rax
    add 0x028(%r12), %rax
    cmp $2, %rax
    jge fail_93

    call compare_cputime_clocks

child_user_spin:
    mov $0x10000, %ecx
2:
    pause
    dec %ecx
    jnz 2b
    mov $2, %edi
    call read_clock_ns
    cmp $40000000, %rax
    jb child_user_spin

    /* Burn raw getpid(39) syscalls in batches until RUSAGE_SELF ru_stime > 0. */
    mov $128, %ebx
child_sys_batch:
    mov $4096, %ebp
3:
    mov $39, %eax
    syscall
    dec %ebp
    jnz 3b
    xor %edi, %edi
    lea 0x100(%r12), %rsi
    mov $98, %eax
    syscall
    test %rax, %rax
    jnz fail_94
    imul $1000000, 0x110(%r12), %rax
    add 0x118(%r12), %rax
    cmp $0, %rax
    jg child_done
    dec %ebx
    jnz child_sys_batch
    jmp fail_94

child_done:
    mov $8, %edi
    jmp exit_code

compare_cputime_clocks:
    /* Null output pointer on clocks 2 and 3 must reach -EFAULT, not -ENOSYS. */
    mov $2, %edi
    xor %esi, %esi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $-14, %rax
    jne fail_91

    mov $3, %edi
    xor %esi, %esi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $-14, %rax
    jne fail_91

    mov $2, %edi
    call compare_clock
    mov $3, %edi
    call compare_clock
    ret

compare_clock:
    push %rbp
    mov %rsp, %rbp
    sub $64, %rsp
    and $-16, %rsp
    mov %edi, 48(%rsp)

    /* clock_getres(clk, &ts) == {0, 1}. */
    mov %rsp, %rsi
    mov $229, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jnz fail_91
    cmpq $0, (%rsp)
    jne fail_91
    cmpq $1, 8(%rsp)
    jne fail_91

    /* raw0 <= vdso <= raw1. */
    mov 48(%rsp), %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jnz fail_91

    mov 48(%rsp), %edi
    lea 16(%rsp), %rsi
    call *%r14
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jnz fail_91

    mov 48(%rsp), %edi
    lea 32(%rsp), %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jnz fail_91

    cmpq $999999999, 8(%rsp)
    ja fail_91
    cmpq $999999999, 24(%rsp)
    ja fail_91
    cmpq $999999999, 40(%rsp)
    ja fail_91

    mov 16(%rsp), %rax
    cmp (%rsp), %rax
    jb fail_91
    ja 1f
    mov 24(%rsp), %rdx
    cmp 8(%rsp), %rdx
    jb fail_91
1:
    cmp 32(%rsp), %rax
    ja fail_91
    jb 2f
    mov 24(%rsp), %rdx
    cmp 40(%rsp), %rdx
    ja fail_91
2:
    mov %rbp, %rsp
    pop %rbp
    ret

read_clock_ns:
    sub $24, %rsp
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jnz fail_91
    cmpq $0, (%rsp)
    jl fail_91
    cmpq $999999999, 8(%rsp)
    ja fail_91
    imul $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    add $24, %rsp
    ret

find_symbol:
    mov 40(%r15), %r8
    add %r15, %r8
    movzwl 58(%r15), %r9d
    cmp $64, %r9d
    jne fail_90
    movzwl 60(%r15), %ecx
    mov %r8, %rdx
next_section:
    test %ecx, %ecx
    jz fail_90
    cmpl $11, 4(%rdx)
    je have_symtab
    add %r9, %rdx
    dec %ecx
    jmp next_section
have_symtab:
    cmpq $24, 56(%rdx)
    jne fail_90
    mov 40(%rdx), %eax
    shl $6, %rax
    add %r8, %rax
    mov 24(%rax), %r8
    add %r15, %r8
    mov 24(%rdx), %rax
    add %r15, %rax
    mov 32(%rdx), %r9
    add %rax, %r9
next_symbol:
    cmp %r9, %rax
    jae fail_90
    mov (%rax), %esi
    add %r8, %rsi
    mov %r10, %rdi
    mov %r11d, %ecx
    repe cmpsb
    je have_symbol
    add $24, %rax
    jmp next_symbol
have_symbol:
    mov 8(%rax), %rax
    add %r15, %rax
    ret

missing:
    mov $218, %edi
    jmp exit_code
clock_unserved:
    mov $38, %edi
    jmp exit_code
fail_90:
    mov $90, %edi
    jmp exit_code
fail_91:
    mov $91, %edi
    jmp exit_code
fail_92:
    mov $92, %edi
    jmp exit_code
fail_93:
    mov $93, %edi
    jmp exit_code
fail_94:
    mov $94, %edi
    jmp exit_code
fail_95:
    mov $95, %edi
exit_code:
    mov $231, %eax
    syscall
    ud2

.section .rodata
gettime_symbol:
    .asciz "__vdso_clock_gettime"
