/* Two live child members; only exit_group (or a fatal SIGABRT) may retire
   the worker. ROOT_ABORT runs the same members as the root process.
   EPOLL_WORKER (#2620) parks the worker in epoll_pwait(-1) on a ring epoll
   watching an eventfd nobody writes, and adds a third member parked in a
   futex wait; EXEC_SUCCESSOR has the fork child exec SUCCESSOR_PATH, this
   fixture built with -DSUCCESSOR, which runs the members as its own. */
.global _start
.text
_start:
#if defined(ROOT_ABORT) || defined(SUCCESSOR)
    jmp child
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
#ifdef EXEC_SUCCESSOR
    jz exec_successor
#else
    jz child
#endif
    js failure
    mov %eax, %r12d
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
#ifdef ABORT_SIGNAL
    mov status(%rip), %eax
    and $0x7f, %eax
    cmp $6, %eax
#else
    cmpl $(5 << 8), status(%rip)
#endif
    jne failure
    xor %edi, %edi
    jmp exit
#ifdef EXEC_SUCCESSOR
exec_successor:
    lea successor_path(%rip), %rdi
    lea successor_argv(%rip), %rsi
    lea successor_envp(%rip), %rdx
    mov $59, %eax
    syscall
    jmp failure
#endif
child:
#ifdef EPOLL_WORKER
    /* epoll_create1(0), eventfd2(0, 0), epoll_ctl(ADD, eventfd, EPOLLIN):
       the cloned workers inherit r14 (epoll) and r15 (eventfd). */
    xor %edi, %edi
    mov $291, %eax
    syscall
    test %eax, %eax
    js failure
    mov %eax, %r14d
    xor %edi, %edi
    xor %esi, %esi
    mov $290, %eax
    syscall
    test %eax, %eax
    js failure
    mov %eax, %r15d
    mov %r14d, %edi
    mov $1, %esi
    mov %r15d, %edx
    lea epoll_interest(%rip), %r10
    mov $233, %eax
    syscall
    test %eax, %eax
    jnz failure
    /* The futex member: it parks on `go` like the default worker. */
    mov $0x3d0f00, %edi
    lea futex_stack_top(%rip), %rsi
    lea futex_parent_tid(%rip), %rdx
    lea futex_child_tid(%rip), %r10
    lea futex_tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz futex_worker
    js failure
#endif
    mov $0x3d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
wait_ready:
    cmpl $1, ready(%rip)
#ifdef EPOLL_WORKER
    jne wait_ready_yield
    cmpl $1, futex_ready(%rip)
#endif
    je settle
wait_ready_yield:
    mov $24, %eax
    syscall
    jmp wait_ready
settle:
#ifdef EPOLL_WORKER
    /* Hand the CPU over until both members have entered their waits. */
    mov $64, %ebx
settle_yield:
    mov $24, %eax
    syscall
    dec %ebx
    jnz settle_yield
#endif
terminate:
#ifdef ABORT_SIGNAL
    /* abort(): tgkill(getpid(), gettid(), SIGABRT) with the worker parked. */
    mov $39, %eax
    syscall
    mov %eax, %r13d
    mov $186, %eax
    syscall
    mov %eax, %esi
    mov %r13d, %edi
    mov $6, %edx
    mov $234, %eax
    syscall
    mov $92, %edi
    jmp exit
#endif
#ifdef WORKER_EXITS
    movl $1, go(%rip)
#ifdef LEADER_PARKED
leader_park:
    lea hold(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp leader_park
#else
leader_compute:
    pause
    jmp leader_compute
#endif
#endif
#ifdef COMPUTING_WORKER
    movl $1, go(%rip)
wait_computing:
    cmpl $1, computing(%rip)
    je computing_ready
    mov $24, %eax
    syscall
    jmp wait_computing
computing_ready:
#endif
    mov $5, %edi
    jmp exit
#ifdef EPOLL_WORKER
futex_worker:
    movl $1, futex_ready(%rip)
futex_worker_loop:
    lea go(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp futex_worker_loop
#endif
worker:
    movl $1, ready(%rip)
#ifdef EPOLL_WORKER
epoll_worker_loop:
    /* epoll_pwait(epoll, events, 1, -1, NULL, 8): nothing ever wakes it. */
    mov %r14d, %edi
    lea epoll_events(%rip), %rsi
    mov $1, %edx
    mov $-1, %r10
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
    syscall
    jmp epoll_worker_loop
#endif
#ifdef WORKER_EXITS
worker_wait_go:
    cmpl $1, go(%rip)
    je worker_exit_group
    mov $24, %eax
    syscall
    jmp worker_wait_go
worker_exit_group:
    mov $5, %edi
    jmp exit
#endif
worker_loop:
#ifdef COMPUTING_WORKER
    cmpl $1, go(%rip)
    je compute
    mov $24, %eax
    syscall
    jmp worker_loop
compute:
    movl $1, computing(%rip)
    pause
    jmp compute
#endif
#ifdef RUNNABLE_WORKER
    mov $24, %eax
#else
    lea go(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
#endif
    syscall
    jmp worker_loop
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
#ifdef EXEC_SUCCESSOR
.section .rodata
successor_path: .asciz SUCCESSOR_PATH
.data
.balign 8
successor_argv: .quad successor_path, 0
successor_envp: .quad 0
#endif
#ifdef EPOLL_WORKER
.data
.balign 8
/* struct epoll_event { u32 events; u64 data; } __packed: EPOLLIN. */
epoll_interest: .long 1
    .quad 0x2620
#endif
.bss
.balign 4096
status: .space 8
ready: .space 8
go: .space 8
computing: .space 8
hold: .space 8
parent_tid: .space 8
child_tid: .space 8
tls: .space 256
.balign 16
thread_stack: .space 16384
thread_stack_top:
#ifdef EPOLL_WORKER
futex_ready: .space 8
futex_parent_tid: .space 8
futex_child_tid: .space 8
futex_tls: .space 256
epoll_events: .space 64
.balign 16
futex_stack: .space 16384
futex_stack_top:
#endif
