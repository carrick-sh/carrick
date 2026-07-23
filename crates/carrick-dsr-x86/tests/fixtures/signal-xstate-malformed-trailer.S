/*
 * A handler corrupts the Carrick-private xstate trailer in its Linux-advertised
 * fpstate extent. rt_sigreturn must reject the frame and force guest SIGSEGV
 * instead of resuming or aborting the host runtime.
 */
.global _start
.type _start,@function
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000004, action+8(%rip) /* SA_RESTORER | SA_SIGINFO */
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)

    mov $13, %eax                    /* rt_sigaction(SIGUSR1) */
    mov $10, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne fail

    mov $39, %eax                    /* getpid */
    syscall
    mov %eax, %edi
    mov $186, %eax                   /* gettid */
    syscall
    mov %eax, %esi
    mov $10, %edx
    mov $234, %eax                   /* tgkill */
    syscall

    /* A successful rt_sigreturn would be a failure. */
fail:
    mov $1, %edi
    mov $231, %eax
    syscall
.size _start, .-_start

.type handler,@function
handler:
    mov 224(%rdx), %rax              /* uc_mcontext.fpstate */
    mov 480(%rax), %ecx              /* fpx_sw_bytes.xstate_size */
    movb $0, (%rax,%rcx)             /* corrupt private trailer magic */
    ret
.size handler, .-handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
    syscall
.size restorer, .-restorer

.section .data
.balign 8
action:
    .quad 0, 0, 0, 0

.section .note.GNU-stack,"",@progbits
