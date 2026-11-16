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
child:
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
