/* #2321: blocking wait4 on a production fork child that is already a zombie,
 * with its one output write contended once. The parent first waits for the
 * zombie with waitid(P_ALL, WEXITED|WNOWAIT), so the contended write is the
 * wait4 output itself, never the child's exit. Exit 7 is success; 100 + n
 * reports errno n (114 = EFAULT, 111 = EAGAIN); 90..96 a wrong answer.
 *   WAIT_STATUS   wait4(-1, &status, 0, NULL): the pre-reap status copy
 *   WAIT_RUSAGE   wait4(-1, NULL, 0, &rusage): the post-reap rusage copy
 *   WAIT_EDITOR   the copy's MM editor is held once (an owner wait): the
 *                 caller must park exactly once
 *   WAIT_BUSY     the copy is Busy once; the injected-copy census must show
 *                 one refusal, and for rusage one owned rerun of the
 *                 retained answer
 * Either way the guest then sees the child's pid and status, and a second
 * wait4 reports ECHILD: the zombie was reaped exactly once.
 */
#define INJECT_EDITOR_BUSY_ONCE -495     /* 0x...fe11 */
#define INJECT_WAIT_PARK_CENSUS -493     /* 0x...fe13 */
#define INJECT_OWNED_COPY_BUSY_ONCE -485 /* 0x...fe1b */
#define INJECT_OWNED_COPY_CENSUS -484    /* 0x...fe1c */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %rax, %rax
    js errno_exit
    jz child
    mov %rax, %r12
    /* Make both output pages resident in this MM before contention. */
    movl $0, status(%rip)
    movq $-1, rusage(%rip)
    movq $0, info(%rip)
    /* waitid(P_ALL, 0, &info, WEXITED | WNOWAIT, NULL) */
    xor %edi, %edi
    xor %esi, %esi
    lea info(%rip), %rdx
    mov $0x01000004, %r10d
    xor %r8d, %r8d
    mov $247, %eax
    syscall
    test %rax, %rax
    jnz errno_exit
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    mov %rax, %r13
#if defined(WAIT_EDITOR)
    mov $INJECT_EDITOR_BUSY_ONCE, %rax
#elif defined(WAIT_BUSY)
    mov $INJECT_OWNED_COPY_BUSY_ONCE, %rax
#else
#error "WAIT_EDITOR or WAIT_BUSY"
#endif
    syscall
    test %rax, %rax
    jnz fail_inject
    mov $-1, %rdi
    xor %edx, %edx
#if defined(WAIT_STATUS)
    lea status(%rip), %rsi
    xor %r10d, %r10d
#elif defined(WAIT_RUSAGE)
    xor %esi, %esi
    lea rusage(%rip), %r10
#else
#error "WAIT_STATUS or WAIT_RUSAGE"
#endif
    mov $61, %eax
    syscall
    test %rax, %rax
    js errno_exit
    cmp %r12, %rax
    jne fail_pid
#if defined(WAIT_STATUS)
    cmpl $0x500, status(%rip)
    jne fail_output
#else
    /* The retained answer was written over the sentinel ru_utime.tv_sec. */
    cmpq $-1, rusage(%rip)
    je fail_output
#endif
#if defined(WAIT_EDITOR)
    mov $INJECT_WAIT_PARK_CENSUS, %rax
    syscall
    sub %r13, %rax
    cmp $1, %rax
    jne fail_census
#else
    mov $INJECT_OWNED_COPY_CENSUS, %rax
    syscall
#if defined(WAIT_STATUS)
    mov $0x0000000100000000, %rcx
#else
    mov $0x0000000100000001, %rcx
#endif
    cmp %rcx, %rax
    jne fail_census
#endif
    /* The zombie was consumed exactly once. */
    mov $-1, %rdi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp $-10, %rax
    jne fail_reaped
    mov $7, %edi
    jmp exit
child:
    mov $5, %edi
    mov $231, %eax
    syscall
    ud2
errno_exit:
    neg %rax
    lea 100(%rax), %rdi
    jmp exit
fail_inject:
    mov $90, %edi
    jmp exit
fail_pid:
    mov $91, %edi
    jmp exit
fail_output:
    mov $92, %edi
    jmp exit
fail_census:
    mov $93, %edi
    jmp exit
fail_reaped:
    mov $94, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 4096
status:
    .skip 8
.balign 64
info:
    .skip 128
.balign 64
rusage:
    .skip 144
