/*
 * Read AT_SYSINFO_EHDR from the initial stack and resolve __vdso_clock_gettime
 * by name. The root and native fork child each bracket a vDSO monotonic
 * sample and a MONOTONIC_RAW sample between raw syscall samples.
 * Realtime mode also compares the calibration across fork and exec.
 * Exit values: 8 success, 38 ENOSYS, 91 malformed clock, 218 missing auxv.
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
    je found
    add $16, %rax
    jmp aux
found:
#ifdef CLOCK_REALTIME_WITNESS
    /* Hold REALTIME - MONOTONIC constant across the fork. */
    movabs $0x2e00000010, %rdx
    mov (%rdx), %r13
    sub 16(%rdx), %r13
#ifdef EXEC_SUCCESSOR
    /* The fork child passed the inherited offset as sixteen nonzero nibbles. */
    mov 16(%rsp), %rdx
    push %rax
    xor %r8d, %r8d
    xor %ecx, %ecx
read_offset:
    movzbl (%rdx), %eax
    dec %eax
    shl %cl, %rax
    or %rax, %r8
    add $4, %ecx
    inc %rdx
    cmp $64, %ecx
    jne read_offset
    pop %rax
    cmp %r13, %r8
    jne failure
#endif
#endif
    mov 8(%rax), %r15
    cmp $0, %r15
    je missing
    cmpl $0x464c457f, (%r15)
    jne failure
    cmpw $62, 18(%r15)
    jne failure
    lea gettime_symbol(%rip), %r10
    mov $21, %r11d
    call find_symbol
    mov %rax, %r14
    lea getres_symbol(%rip), %r10
    mov $20, %r11d
    call find_symbol
    mov %rax, %rbx
#ifdef EXEC_SUCCESSOR
    jmp child
#endif
    mov $57, %eax
    syscall
    test %rax, %rax
    js failure
    jz child
    mov %eax, %r12d
    call compare_samples
#ifdef TIMES_WITNESS
    sub $208, %rsp
    mov %rsp, %rdi
    xor %eax, %eax
    mov $26, %ecx
    rep stosq
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    lea 16(%rsp), %r10
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    cmp $8, %edi
    jne exit
    /* wait4 rusage: ru_utime + ru_stime >= 20,000 us. */
    imulq $1000000, 16(%rsp), %rax
    add 24(%rsp), %rax
    imulq $1000000, 32(%rsp), %rdx
    add 40(%rsp), %rdx
    add %rdx, %rax
    cmp $20000, %rax
    jb failure
    /* Parent times(2) after reap: tms_cutime + tms_cstime >= 2 ticks. */
    lea 160(%rsp), %rdi
    mov $100, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jle failure
    mov 176(%rsp), %rax
    add 184(%rsp), %rax
    cmp $2, %rax
    jl failure
    mov $8, %edi
    jmp exit
#else
    sub $16, %rsp
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
#endif
child:
    call compare_samples
#ifdef SUCCESSOR_PATH
    lea encoded_offset(%rip), %rdx
    mov %r13, %rax
    mov $16, %ecx
write_offset:
    mov %al, %r8b
    and $15, %r8b
    inc %r8b
    mov %r8b, (%rdx)
    inc %rdx
    shr $4, %rax
    loop write_offset
    lea successor(%rip), %rdi
    lea successor_argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit
#endif
    mov $8, %edi
    jmp exit
missing:
    mov $218, %edi
    jmp exit
clock_unserved:
    mov $38, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

find_symbol:
    mov 40(%r15), %r8
    add %r15, %r8
    movzwl 58(%r15), %r9d
    cmp $64, %r9d
    jne failure
    movzwl 60(%r15), %ecx
    mov %r8, %rdx
next_section:
    test %ecx, %ecx
    jz failure
    cmpl $11, 4(%rdx)
    je have_symtab
    add %r9, %rdx
    dec %ecx
    jmp next_section
have_symtab:
    cmpq $24, 56(%rdx)
    jne failure
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
    jae failure
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

compare_samples:
    mov $1, %edi
    call compare_counter
    mov $4, %edi
    call compare_counter
#ifdef CLOCK_REALTIME_WITNESS
    xor %edi, %edi
    call compare_counter
    mov $5, %edi
    call compare_counter
    call compare_realtime_offset
#endif
#ifdef REALTIME_ALIASES_WITNESS
    call compare_realtime_aliases
#endif
#ifdef CPUTIME_WITNESS
    call compare_cputime
#endif
#ifdef TIMES_WITNESS
    call compare_times
#endif
    jmp compare_realtime_and_resolution

compare_counter:
    sub $56, %rsp
    mov %edi, 48(%rsp)
    mov %rsp, %rsi
    call raw_counter
    mov 48(%rsp), %edi
    lea 16(%rsp), %rsi
    call *%r14
    test %rax, %rax
    jne failure
    mov 48(%rsp), %edi
    lea 32(%rsp), %rsi
    call raw_counter
    mov 16(%rsp), %rax
    cmp (%rsp), %rax
    jb failure
    ja after_first
    mov 24(%rsp), %rdx
    cmp 8(%rsp), %rdx
    jb failure
after_first:
    cmp 32(%rsp), %rax
    ja failure
    jb ordered
    mov 24(%rsp), %rdx
    cmp 40(%rsp), %rdx
    ja failure
ordered:
    add $56, %rsp
    ret

compare_realtime_and_resolution:
    sub $56, %rsp
    xor %edi, %edi
    mov %rsp, %rsi
    call *%r14
    test %rax, %rax
    jne failure
    cmpq $1600000000, (%rsp)
    jb failure
    cmpq $999999999, 8(%rsp)
    ja failure
    mov $1, %edi
    mov %rsp, %rsi
    call *%rbx
    test %rax, %rax
    jne failure
    mov $1, %edi
    lea 16(%rsp), %rsi
    mov $229, %eax
    syscall
    test %rax, %rax
    jne failure
    mov (%rsp), %rax
    cmp 16(%rsp), %rax
    jne failure
    mov 8(%rsp), %rax
    cmp 24(%rsp), %rax
    jne failure
    add $56, %rsp
    ret
#ifdef CLOCK_REALTIME_WITNESS
compare_realtime_offset:
    movabs $0x2e00000010, %rdx
    mov (%rdx), %rax
    sub 16(%rdx), %rax
    cmp %r13, %rax
    jne failure
    /* With the common calibration, subtracting the exact offset from a
     * raw realtime result puts it between the surrounding raw mono samples. */
    sub $56, %rsp
    mov $1, %edi
    mov %rsp, %rsi
    call raw_counter
    xor %edi, %edi
    lea 16(%rsp), %rsi
    call raw_counter
    mov $1, %edi
    lea 32(%rsp), %rsi
    call raw_counter
    imulq $1000000000, 16(%rsp), %rax
    add 24(%rsp), %rax
    sub %r13, %rax
    imulq $1000000000, (%rsp), %rdx
    add 8(%rsp), %rdx
    cmp %rdx, %rax
    jb failure
    imulq $1000000000, 32(%rsp), %rdx
    add 40(%rsp), %rdx
    cmp %rdx, %rax
    ja failure
    /* The COARSE result lies between the surrounding realtime samples
     * after their nanosecond fields are rounded down to milliseconds. */
    xor %edi, %edi
    mov %rsp, %rsi
    call raw_counter
    mov $5, %edi
    lea 16(%rsp), %rsi
    call raw_counter
    xor %edi, %edi
    lea 32(%rsp), %rsi
    call raw_counter
    mov $1000000, %ecx
    mov 24(%rsp), %rax
    xor %edx, %edx
    div %rcx
    test %rdx, %rdx
    jne failure
    imulq $1000, 16(%rsp), %r8
    add %rax, %r8
    mov 8(%rsp), %rax
    xor %edx, %edx
    div %rcx
    imulq $1000, (%rsp), %r9
    add %rax, %r9
    cmp %r9, %r8
    jb failure
    mov 40(%rsp), %rax
    xor %edx, %edx
    div %rcx
    imulq $1000, 32(%rsp), %r9
    add %rax, %r9
    cmp %r9, %r8
    ja failure
    add $56, %rsp
    ret
#endif
#ifdef REALTIME_ALIASES_WITNESS
compare_realtime_aliases:
    sub $56, %rsp
#ifndef LEGACY_TIME_WITNESS
    lea gettimeofday_symbol(%rip), %r10
    mov $20, %r11d
    call find_symbol
    mov %rax, 48(%rsp)
    mov %rsp, %rdi
    lea 16(%rsp), %rsi
    movq $-1, (%rsi)
    mov $96, %eax
    syscall
    call check_raw_result
    cmpq $0, 16(%rsp)
    jne failure
    cmpq $999999, 8(%rsp)
    ja failure
    lea 16(%rsp), %rdi
    xor %esi, %esi
    call *48(%rsp)
    test %rax, %rax
    jne failure
    lea 32(%rsp), %rdi
    xor %esi, %esi
    mov $96, %eax
    syscall
    call check_raw_result
    imulq $1000000, (%rsp), %rax
    add 8(%rsp), %rax
    imulq $1000000, 16(%rsp), %rdx
    add 24(%rsp), %rdx
    cmp %rax, %rdx
    jb failure
    imulq $1000000, 32(%rsp), %rax
    add 40(%rsp), %rax
    cmp %rax, %rdx
    ja failure
#else
    lea time_symbol(%rip), %r10
    mov $12, %r11d
    call find_symbol
    mov %rax, 48(%rsp)
    mov %rsp, %rdi
    mov $201, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp $1600000000, %rax
    jb failure
    cmp (%rsp), %rax
    jne failure
    xor %edi, %edi
    call *48(%rsp)
    mov %rax, 16(%rsp)
    xor %edi, %edi
    mov $201, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    cmp (%rsp), %rax
    jb failure
    mov 16(%rsp), %rdx
    cmp (%rsp), %rdx
    jb failure
    cmp %rax, %rdx
    ja failure
#endif
    add $56, %rsp
    ret
#endif
#ifdef CPUTIME_WITNESS
compare_cputime:
    mov $2, %edi
    call compare_counter
    mov $3, %edi
    call compare_counter
    mov $2, %edi
    xor %esi, %esi
    mov $228, %eax
    syscall
    cmp $-14, %rax
    jne failure
    mov $3, %edi
    xor %esi, %esi
    mov $228, %eax
    syscall
    cmp $-14, %rax
    jne failure
    push %rbp
    sub $64, %rsp
    mov $2, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    mov %rax, 16(%rsp)
    mov $3, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    mov %rax, 24(%rsp)
    movl $400000, 32(%rsp)
    mov $1, %r8
cputime_leader_spin:
    mov $2048, %ecx
1:  imul $1664525, %r8, %r8
    add $1013904223, %r8
    dec %ecx
    jnz 1b
    mov $3, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    cmp 24(%rsp), %rax
    jb failure
    sub 24(%rsp), %rax
    cmp $5000000, %rax
    jae cputime_leader_advanced
    decl 32(%rsp)
    jnz cputime_leader_spin
    jmp failure
cputime_leader_advanced:
    mov $2, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    cmp 16(%rsp), %rax
    jb failure
    sub 16(%rsp), %rax
    cmp $5000000, %rax
    jb failure
    /* Spawn a thread that spins >= 20ms and calls raw SYS_exit(60). */
    xor %edi, %edi
    mov $0x3000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %rbp
    mov $2, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    mov %rax, 16(%rsp)
    mov $3, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    mov %rax, 24(%rsp)
    movl $1, 0x2000(%rbp)
    mov $0x00350f00, %edi
    lea 0x1ff0(%rbp), %rsi
    lea 0x2000(%rbp), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    js failure
    jz cputime_worker
cputime_join:
    mov 0x2000(%rbp), %edx
    test %edx, %edx
    jz cputime_joined
    lea 0x2000(%rbp), %rdi
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp cputime_join
cputime_joined:
    mov $3, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %r8
    add 8(%rsp), %r8
    cmp 24(%rsp), %r8
    jb failure
    sub 24(%rsp), %r8
    mov $2, %edi
    mov %rsp, %rsi
    call raw_counter
    imulq $1000000000, (%rsp), %r9
    add 8(%rsp), %r9
    cmp 16(%rsp), %r9
    jb failure
    sub 16(%rsp), %r9
    lea 15000000(%r8), %rax
    cmp %rax, %r9
    jb failure
    mov %rbp, %rdi
    mov $0x3000, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    jne failure
    add $64, %rsp
    pop %rbp
    ret
cputime_worker:
    sub $32, %rsp
    mov $3, %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    test %rax, %rax
    jne worker_fail
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    cmp $10000000, %rax
    ja worker_fail
    mov %rax, 16(%rsp)
    movl $500000, 24(%rsp)
    mov $1, %r8
cputime_worker_spin:
    mov $2048, %ecx
2:  imul $1664525, %r8, %r8
    add $1013904223, %r8
    dec %ecx
    jnz 2b
    mov $3, %edi
    mov %rsp, %rsi
    mov $228, %eax
    syscall
    test %rax, %rax
    jne worker_fail
    imulq $1000000000, (%rsp), %rax
    add 8(%rsp), %rax
    cmp 16(%rsp), %rax
    jb worker_fail
    sub 16(%rsp), %rax
    cmp $20000000, %rax
    jae cputime_worker_done
    decl 24(%rsp)
    jnz cputime_worker_spin
worker_fail:
    mov $91, %edi
    mov $231, %eax
    syscall
    ud2
cputime_worker_done:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
#endif
#ifdef TIMES_WITNESS
compare_times:
    sub $80, %rsp
    xor %edi, %edi
    mov $100, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jle failure
    mov $-1, %rdi
    mov $100, %eax
    syscall
    cmp $-14, %rax
    jne failure
    mov %rsp, %rdi
    mov $100, %eax
    syscall
    test %rax, %rax
    jle failure
    mov %rax, 64(%rsp)
    cmpq $0, 16(%rsp)
    jne failure
    cmpq $0, 24(%rsp)
    jne failure
    movl $600000, 72(%rsp)
    mov $1, %r9
times_spin:
    mov $4096, %ecx
3:  imul $1664525, %r9, %r9
    add $1013904223, %r9
    dec %ecx
    jnz 3b
    lea 32(%rsp), %rdi
    mov $100, %eax
    syscall
    test %rax, %rax
    jle failure
    cmp 64(%rsp), %rax
    jl failure
    mov 32(%rsp), %rdx
    cmp 0(%rsp), %rdx
    jl failure
    mov 40(%rsp), %rcx
    cmp 8(%rsp), %rcx
    jl failure
    add %rcx, %rdx
    mov 0(%rsp), %r8
    add 8(%rsp), %r8
    sub %r8, %rdx
    cmp $3, %rdx
    jge times_advanced
    decl 72(%rsp)
    jnz times_spin
    jmp failure
times_advanced:
    add $80, %rsp
    ret
#endif
raw_counter:
    mov $228, %eax
    syscall
check_raw_result:
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jne failure
    ret
.section .rodata
gettime_symbol:
    .asciz "__vdso_clock_gettime"
getres_symbol:
    .asciz "__vdso_clock_getres"
#ifdef REALTIME_ALIASES_WITNESS
gettimeofday_symbol:
    .asciz "__vdso_gettimeofday"
time_symbol:
    .asciz "__vdso_time"
#endif
#ifdef SUCCESSOR_PATH
successor: .asciz SUCCESSOR_PATH
.balign 8
successor_argv: .quad successor, encoded_offset, 0
.section .bss
encoded_offset: .space 17
#endif
.section .note.GNU-stack,"",@progbits
