// A nonleader thread execs this same static image while the original leader
// remains live. Stage 2 creates a fresh thread before checking gettid==getpid,
// so a live-count-only identity alias cannot pass.
.section .text
.global _start
.type _start,@function
_start:
    movq 16(%rsp), %rax
    testq %rax, %rax
    jnz .Lstage2                     // stage 1 has no argv[1]

.Lstage1:
    movq 8(%rsp), %rax
    movq %rax, saved_argv0(%rip)
    movq %rax, exec_argv(%rip)
    leaq stage2_arg(%rip), %rax
    movq %rax, exec_argv+8(%rip)

    movq $56, %rax                    // __NR_clone
    movq $0x00010f00, %rdi            // VM|FS|FILES|SIGHAND|THREAD
    leaq worker_stack_end(%rip), %rsi
    xorq %rdx, %rdx
    xorq %r10, %r10
    xorq %r8, %r8
    syscall
    testq %rax, %rax
    jz .Lexec_worker
    js .Lfail_clone

.Lleader_loop:
    movq $24, %rax                    // __NR_sched_yield
    syscall
    jmp .Lleader_loop

.Lexec_worker:
    movq $35, %rax                    // __NR_nanosleep
    leaq worker_delay(%rip), %rdi
    xorq %rsi, %rsi
    syscall
    movq $59, %rax                    // __NR_execve
    movq saved_argv0(%rip), %rdi
    leaq exec_argv(%rip), %rsi
    leaq empty_env(%rip), %rdx
    syscall
    movq $10, %rdi
    jmp .Lexit_group

.Lstage2:
    movq $39, %rax                    // __NR_getpid
    syscall
    movq %rax, stage2_pid(%rip)
    movq $186, %rax                   // __NR_gettid
    syscall
    cmpq stage2_pid(%rip), %rax
    jne .Lfail_initial_identity

    movq $56, %rax                    // create a stage-2 sibling
    movq $0x00010f00, %rdi
    leaq stage2_stack_end(%rip), %rsi
    xorq %rdx, %rdx
    xorq %r10, %r10
    xorq %r8, %r8
    syscall
    testq %rax, %rax
    jz .Lstage2_child
    js .Lfail_clone

    // This is the decisive query: with two live threads, gettid must still be
    // the tgid rather than the pre-exec worker registry key.
    movq $186, %rax
    syscall
    cmpq stage2_pid(%rip), %rax
    jne .Lfail_rethread

    movq $1, %rax                     // __NR_write
    movq $1, %rdi
    leaq success(%rip), %rsi
    movq $success_len, %rdx
    syscall
    xorq %rdi, %rdi
    jmp .Lexit_group

.Lstage2_child:
    movq $34, %rax                    // __NR_pause; parent exit_group retires us
    syscall
    jmp .Lstage2_child

.Lfail_clone:
    movq $11, %rdi
    jmp .Lexit_group
.Lfail_initial_identity:
    movq $12, %rdi
    jmp .Lexit_group
.Lfail_rethread:
    movq $13, %rdi
.Lexit_group:
    movq $231, %rax
    syscall

.section .rodata
stage2_arg:
    .asciz "stage2"
worker_delay:
    .quad 0
    .quad 50000000
success:
    .ascii "exec_from_thread_stage2_reached=true\n"
    .ascii "exec_from_thread_count_is_one=true\n"
    .ascii "exec_from_thread_survivor_gettid_is_getpid=true\n"
.set success_len, .-success

.section .data
.align 8
saved_argv0:
    .quad 0
exec_argv:
    .quad 0, 0, 0
empty_env:
    .quad 0
stage2_pid:
    .quad 0

.section .bss
.align 16
worker_stack:
    .skip 16384
worker_stack_end:
.align 16
stage2_stack:
    .skip 16384
stage2_stack_end:
.section .note.GNU-stack,"",@progbits
