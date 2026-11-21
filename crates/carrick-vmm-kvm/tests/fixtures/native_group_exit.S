/* Two live child members; only exit_group (or a fatal SIGABRT) may retire
   the worker. ROOT_ABORT runs the same members as the root process. */
.global _start
.text
_start:
#ifdef ROOT_ABORT
    jmp child
#endif
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
#ifdef WAIT_ANY_CHILD
    mov $-1, %rdi
#else
    mov %eax, %edi
#endif
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
child:
#ifdef EXEC_SUCCESSOR_PATH
    lea successor_path(%rip), %rdi
    lea successor_argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    jmp failure
#endif
#ifdef EPOLL_WORKER
    lea pipe_fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    js failure
    xor %edi, %edi
    mov $291, %eax
    syscall
    test %eax, %eax
    js failure
    mov %eax, epfd_var(%rip)
    mov %eax, %edi
    mov $1, %esi
    mov pipe_fds(%rip), %edx
    lea epoll_ev(%rip), %r10
    mov $233, %eax
    syscall
    test %eax, %eax
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
    je terminate
    mov $24, %eax
    syscall
    jmp wait_ready
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
worker:
    movl $1, ready(%rip)
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
#elif defined(EPOLL_WORKER)
    mov epfd_var(%rip), %edi
    lea epoll_out(%rip), %rsi
    mov $1, %edx
    mov $-1, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    mov $281, %eax
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
#if defined(EXEC_SUCCESSOR_PATH) || defined(EPOLL_WORKER)
.section .rodata
#ifdef EXEC_SUCCESSOR_PATH
successor_path: .asciz EXEC_SUCCESSOR_PATH
.balign 8
successor_argv: .quad successor_path, 0
#endif
#ifdef EPOLL_WORKER
.balign 8
epoll_ev:
    .long 1
    .space 12
#endif
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
pipe_fds: .space 8
epfd_var: .space 8
epoll_out: .space 32
tls: .space 256
.balign 16
thread_stack: .space 16384
thread_stack_top:
