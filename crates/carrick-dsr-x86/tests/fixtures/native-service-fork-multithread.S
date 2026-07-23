// Production native service_fork regression.
//
// The initial guest thread repeatedly forks while a CLONE_THREAD sibling
// alternates between a real syscall and a blocking nanosleep. Every fork child
// exercises dispatcher state (getpid, pipe2, write/read/close, nanosleep) before
// exit_group(0); the parent reaps and validates all children, then waits for the
// worker to retire. Any inherited runtime mutex or false ForkParked authority
// turns this into a nonzero exit or a bounded integration-test timeout.
.global _start
.section .text
_start:
    lea worker_stack_end(%rip), %rsi
    mov $0x50f00, %rdi              // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
    xor %rdx, %rdx                  // parent_tid
    xor %r10, %r10                  // child_tid
    xor %r8, %r8                    // tls
    mov $56, %rax                   // clone
    syscall
    test %rax, %rax
    js clone_failed
    jz worker

    mov $32, %r12                   // enough repetitions to expose inheritance
wait_worker_ready:
    cmpl $1, ready(%rip)
    je fork_loop
    lea short_delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // nanosleep
    syscall
    jmp wait_worker_ready

fork_loop:
    mov $57, %rax                   // fork
    syscall
    test %rax, %rax
    js fork_failed
    jz fork_child

    mov %rax, %r13                  // exact child pid
    mov %r13, %rdi
    lea child_status(%rip), %rsi
    xor %rdx, %rdx                  // options
    xor %r10, %r10                  // rusage
    mov $61, %rax                   // wait4
    syscall
    cmp %r13, %rax
    jne wait_failed
    cmpl $0, child_status(%rip)
    jne child_failed
    dec %r12
    jnz fork_loop

    movl $1, stop(%rip)
wait_worker_done:
    cmpl $1, done(%rip)
    je success
    lea short_delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // nanosleep
    syscall
    jmp wait_worker_done

success:
    mov $1, %rdi                    // stdout
    lea success_message(%rip), %rsi
    mov $success_message_len, %rdx
    mov $1, %rax                    // write
    syscall
    xor %rdi, %rdi
    mov $231, %rax                  // exit_group(0)
    syscall

fork_child:
    mov $39, %rax                   // getpid: runtime identity operation
    syscall
    lea child_pipe(%rip), %rdi
    xor %rsi, %rsi                  // flags
    mov $293, %rax                  // pipe2
    syscall
    test %rax, %rax
    js child_runtime_failed

    mov child_pipe+4(%rip), %edi
    lea child_byte(%rip), %rsi
    mov $1, %rdx
    mov $1, %rax                    // write pipe
    syscall
    cmp $1, %rax
    jne child_runtime_failed

    mov child_pipe(%rip), %edi
    lea child_read_byte(%rip), %rsi
    mov $1, %rdx
    xor %rax, %rax                  // read pipe
    syscall
    cmp $1, %rax
    jne child_runtime_failed
    cmpb $0x5a, child_read_byte(%rip)
    jne child_runtime_failed

    mov child_pipe(%rip), %edi
    mov $3, %rax                    // close read end
    syscall
    mov child_pipe+4(%rip), %edi
    mov $3, %rax                    // close write end
    syscall
    lea child_delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // child host wait before exit
    syscall
    xor %rdi, %rdi
    mov $231, %rax                  // exit_group(0)
    syscall

worker:
    movl $1, ready(%rip)
worker_loop:
    mov $39, %rax                   // getpid syscall/fast boundary
    syscall
    lea worker_delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // real blocking host wait
    syscall
    cmpl $0, stop(%rip)
    je worker_loop
    movl $1, done(%rip)
    xor %rdi, %rdi
    mov $60, %rax                   // exit this guest thread
    syscall

clone_failed:
    mov $101, %rdi
    jmp fatal
fork_failed:
    mov $102, %rdi
    jmp fatal
wait_failed:
    mov $103, %rdi
    jmp fatal
child_failed:
    mov $104, %rdi
    jmp fatal
child_runtime_failed:
    mov $105, %rdi
fatal:
    mov $231, %rax
    syscall

.section .rodata
.align 8
short_delay:
    .quad 0, 100000                 // 100 us
worker_delay:
    .quad 0, 250000                 // 250 us
child_delay:
    .quad 0, 1000                   // 1 us
child_byte:
    .byte 0x5a
success_message:
    .ascii "native-service-fork-multithread ok\n"
.set success_message_len, . - success_message

.section .bss
.align 8
ready:
    .long 0
stop:
    .long 0
done:
    .long 0
child_status:
    .long 0
child_pipe:
    .long 0, 0
child_read_byte:
    .byte 0
.align 16
.skip 65536
worker_stack_end:

.section .note.GNU-stack,"",@progbits
