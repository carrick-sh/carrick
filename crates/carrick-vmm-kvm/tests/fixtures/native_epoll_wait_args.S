/* #2900 acceptance guard: Go's netpoller, in assembly. The root blocks in
 * epoll_pwait through the argument shuffle of Go's
 * internal/runtime/syscall.Syscall6 (`mov %rsi,%r10; mov %rdi,%rdx;
 * mov %rcx,%rsi; mov %rbx,%rdi; syscall`) with a timeout and an events
 * buffer on its stack, ROUNDS times, while a peer thread on the other CPU
 * interrupts it with SIGUSR1 (an SA_RESTART handler, as Go's SIGURG) and
 * wakes it through an eventfd. Every return must leave every argument
 * register as the call entered with it: #2900 saw `events` (rsi) hold the
 * call's own return RIP, which a resume at the `mov %rcx,%rsi` produces.
 * Exit status names the first step that differs from Linux:
 *   2 setup failed       3 epoll_pwait failed (other than EINTR)
 *   4 rdi, 5 rsi, 6 rdx, 7 r10, 8 r8, 9 r9 was not the call's argument
 *   10 the eventfd read failed      11 the handler never ran
 *   0 every step matched Linux */
#ifndef ROUNDS
#define ROUNDS 200
#endif
#define SIGUSR1 10
#define TIMEOUT_MS 1000
#define MAX_EVENTS 128
.global _start
.text
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x14000000, action+8(%rip)    /* SA_RESTART | SA_RESTORER */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)
    mov $SIGUSR1, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax                       /* rt_sigaction */
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit

    xor %edi, %edi
    xor %esi, %esi
    mov $290, %eax                      /* eventfd2 */
    syscall
    mov $2, %edi
    test %rax, %rax
    js exit
    mov %eax, efd(%rip)
    xor %edi, %edi
    mov $291, %eax                      /* epoll_create1 */
    syscall
    mov $2, %edi
    test %rax, %rax
    js exit
    mov %eax, epfd(%rip)
    movl $1, event(%rip)                /* EPOLLIN */
    mov efd(%rip), %eax
    mov %rax, event+4(%rip)
    mov epfd(%rip), %edi
    mov $1, %esi                        /* EPOLL_CTL_ADD */
    mov efd(%rip), %edx
    lea event(%rip), %r10
    mov $233, %eax                      /* epoll_ctl */
    syscall
    mov $2, %edi
    test %rax, %rax
    jnz exit

    mov $39, %eax                       /* getpid: the root's tid */
    syscall
    mov %eax, pid(%rip)
    mov $0x50f00, %edi                  /* a thread: VM FS FILES SIGHAND THREAD SYSVSEM */
    lea peer_stack_top(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax                       /* clone */
    syscall
    test %rax, %rax
    jz peer
    mov $2, %edi
    js exit

    sub $(MAX_EVENTS * 12 + 16), %rsp
    mov %rsp, %r12                      /* the events buffer, on the stack */
    xor %r13d, %r13d                    /* eventfd counts consumed */
wait:
    mov $281, %eax                      /* epoll_pwait */
    mov epfd(%rip), %ebx
    mov %r12, %rcx
    mov $MAX_EVENTS, %edi
    mov $TIMEOUT_MS, %esi
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov %rsi, %r10
    mov %rdi, %rdx
    mov %rcx, %rsi
    mov %rbx, %rdi
    syscall
    mov %rdi, %r14
    mov epfd(%rip), %r15d
    mov $4, %edi
    cmp %r15, %r14
    jne exit
    mov $5, %edi
    cmp %r12, %rsi
    jne exit
    mov $6, %edi
    cmp $MAX_EVENTS, %rdx
    jne exit
    mov $7, %edi
    cmp $TIMEOUT_MS, %r10
    jne exit
    mov $8, %edi
    test %r8, %r8
    jnz exit
    mov $9, %edi
    test %r9, %r9
    jnz exit
    cmp $-4, %rax                       /* EINTR: Go polls again */
    je wait
    mov $3, %edi
    test %rax, %rax
    js exit
    jz wait                             /* timed out */
    mov efd(%rip), %edi
    lea counter(%rip), %rsi
    mov $8, %edx
    xor %eax, %eax                      /* read */
    syscall
    mov $10, %edi
    cmp $8, %rax
    jne exit
    add counter(%rip), %r13
    cmp $ROUNDS, %r13
    jb wait
    /* The peer's first SIGUSR1 precedes its first wake. */
    mov $11, %edi
    cmpq $0, signals(%rip)
    je exit
    xor %edi, %edi
exit:
    mov $231, %eax                      /* exit_group */
    syscall
    ud2

/* The peer interrupts the root, then wakes it, ROUNDS times. */
peer:
    mov $ROUNDS, %r15d
interrupt:
    mov pid(%rip), %edi
    mov %edi, %esi
    mov $SIGUSR1, %edx
    mov $234, %eax                      /* tgkill */
    syscall
    mov efd(%rip), %edi
    lea one(%rip), %rsi
    mov $8, %edx
    mov $1, %eax                        /* write */
    syscall
    mov $24, %eax                       /* sched_yield */
    syscall
    dec %r15d
    jnz interrupt
    xor %edi, %edi
    mov $60, %eax                       /* exit: this thread only */
    syscall
    ud2

handler:
    incq signals(%rip)
    ret
restorer:
    mov $15, %eax                       /* rt_sigreturn */
    syscall
    ud2

.data
.balign 4096
action: .space 32
event: .space 12
.balign 8
pid: .long 0
efd: .long 0
epfd: .long 0
.balign 8
counter: .quad 0
one: .quad 1
signals: .quad 0
.balign 16
peer_stack: .space 16384
peer_stack_top:
.section .note.GNU-stack,"",@progbits
