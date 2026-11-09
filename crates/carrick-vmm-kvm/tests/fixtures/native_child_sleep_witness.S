/* Production fork; the child sleeps and the parent waits, so parent and
 * child stay live during the call (#1808). The exit status reports 8 for
 * the expected answer, 100 + errno for an unexpected error, 91 otherwise.
 *   SLEEP_CLOCK_TABLE  clock_nanosleep({0, 0}) for each clock/flag row; a
 *                      wrong row exits 100 + its row index instead
 *   SLEEP_CROSSING     (injection image) nanosleep({0, 1 ms}, NULL) while
 *                      the second signal-clock read lags behind the
 *                      deadline: the woken sleep re-parks and returns 0
 *   SLEEP_EINTR        (injection image) SIGUSR1 is caught and published
 *                      once nanosleep({1, 0}, rem) has parked, so it returns
 *                      EINTR with the unslept interval in rem. By default
 *                      rem is an anonymous page the parent mapped before
 *                      fork and the child wrote before sleeping.
 *   SLEEP_BUSY         with SLEEP_EINTR: that rem copy is Busy once
 *   SLEEP_REM_LAZY     with SLEEP_EINTR: nobody touched the rem page (#1984)
 *   SLEEP_REM_COW      with SLEEP_EINTR: rem is a .data page the parent
 *                      wrote before fork; the parent's copy must survive
 */
#define INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ -487 /* 0x...fe19 */
#define INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK -486      /* 0x...fe1a */
#define INJECT_OWNED_COPY_BUSY_ONCE -485            /* 0x...fe1b */
.global _start
.text
_start:
#ifdef SLEEP_EINTR
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    mov %rax, %r15
#ifdef SLEEP_REM_COW
    lea cow_rem(%rip), %r15
    movq $0x5a5a, (%r15)
#endif
    mov $10, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %rax, %rax
    jnz failure
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov %eax, %edi
    sub $16, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
#ifdef SLEEP_REM_COW
    cmpq $0x5a5a, (%r15)
    jne failure
#endif
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
#if defined(SLEEP_CLOCK_TABLE)
    lea table(%rip), %rbx
    mov $100, %r13d
row:
    lea table_end(%rip), %rax
    cmp %rax, %rbx
    je success
    mov (%rbx), %rdi
    mov 8(%rbx), %rsi
    lea zero_timespec(%rip), %rdx
    xor %r10d, %r10d
    mov $230, %eax
    syscall
    cmp 16(%rbx), %rax
    jne row_failed
    add $24, %rbx
    inc %r13d
    jmp row
row_failed:
    mov %r13d, %edi
    jmp exit
#elif defined(SLEEP_CROSSING)
    mov $INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ, %rax
    syscall
    test %rax, %rax
    jnz failure
    sub $16, %rsp
    movq $0, (%rsp)
    movq $1000000, 8(%rsp)
    mov %rsp, %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    test %rax, %rax
    je success
    jmp errno_exit
#elif defined(SLEEP_EINTR)
#ifdef SLEEP_BUSY
    mov $INJECT_OWNED_COPY_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz failure
#endif
    mov $INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK, %rax
    syscall
    test %rax, %rax
    jnz failure
    sub $16, %rsp
    movq $1, (%rsp)
    movq $0, 8(%rsp)
#if !defined(SLEEP_REM_LAZY) && !defined(SLEEP_REM_COW)
    movq $0, (%r15)
#endif
    mov %rsp, %rdi
    mov %r15, %rsi
    mov $35, %eax
    syscall
    cmp $-4, %rax
    jne errno_exit
    /* The caught handler ran at this EINTR return. */
    cmpb $1, handled(%rip)
    jne failure
    /* rem = 1 s less the moments before the signal: 0 s and at least
     * 0.5 s of nanoseconds, a valid timespec. A sleep that ran to its
     * deadline returns 0 and exits 91 above. */
    cmpq $0, (%r15)
    jne failure
    mov 8(%r15), %rax
    cmp $500000000, %rax
    jl failure
    cmp $1000000000, %rax
    jge failure
    jmp success
handler:
    movb $1, handled(%rip)
    ret
restorer:
    mov $15, %eax
    syscall
    ud2
#else
#error "select a sleep witness"
#endif
errno_exit:
    test %rax, %rax
    jns failure
    neg %rax
    cmp $155, %rax
    ja failure
    lea 100(%rax), %edi
    jmp exit
success:
    mov $8, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 8
zero_timespec:
    .quad 0, 0
#ifdef SLEEP_EINTR
.balign 4096
cow_rem:
    .quad 0, 0
handled:
    .byte 0
.balign 8
action:
    .quad handler
    .quad 0x04000000 /* SA_RESTORER */
    .quad restorer
    .quad 0
#endif
#ifdef SLEEP_CLOCK_TABLE
/* Rows: clock, flags, expected rax. The register's upper half is not part
 * of clockid_t; Linux reads only TIMER_ABSTIME. x86 CPL0 has no guest
 * monotonic epoch, so every absolute deadline keeps the counted ENOSYS
 * refusal (-38), as do clocks the ring cannot measure (process and
 * per-thread CPU clocks, ALARM). */
table:
    .quad 0, 0, 0
    .quad 1, 0, 0
    .quad 7, 0, 0
    .quad 11, 0, 0
    .quad 0x100000001, 0, 0
    .quad 1, 2, 0
    .quad 1, 0xfffffffe, 0
    .quad 1, 1, -38
    .quad 7, 1, -38
    .quad 1, 3, -38
    .quad 0, 1, -38
    .quad 11, 1, -38
    .quad 2, 0, -38
    .quad 0xfffffff2, 0, -38 /* process CPU clock of pid 1 */
    .quad 8, 0, -38
    .quad 9, 0, -38
    .quad 3, 0, -95
    .quad 4, 0, -95
    .quad 5, 0, -95
    .quad 6, 0, -95
    .quad 0x100000004, 0, -95
    .quad 0xffffffe3, 0, -95 /* posix-clock fd 3 */
    .quad 0xfffffff6, 0, -38 /* thread CPU clock of tid 1: Linux reads the request first */
    .quad 10, 0, -22
    .quad 12, 0, -22
table_end:
#endif
.section .note.GNU-stack,"",@progbits
