# CPL0 must not report success for guest-owned effects it cannot publish.
# Linux native succeeds on these calls; this fixture checks the explicit
# temporary ENOSYS contract of Carrick's incomplete CPL0 service.
.global _start
.text
_start:
    mov %rsp, %rdi
    and $-4096, %rdi
    mov $4096, %rsi
    xor %rdx, %rdx              # PROT_NONE
    mov $10, %rax               # mprotect
    syscall
    cmp $-38, %rax              # ENOSYS
    jne fail
    mov $10, %rdi               # SIGUSR1
    lea action(%rip), %rsi
    xor %rdx, %rdx
    mov $8, %r10
    mov $13, %rax               # rt_sigaction
    syscall
    cmp $-38, %rax
    jne fail
    sub $16, %rsp
    movl $3, (%rsp)             # non-host descriptor 3
    movw $4, 4(%rsp)            # POLLOUT
    movw $0, 6(%rsp)
    mov %rsp, %rdi
    mov $1, %rsi                # nfds = 1
    xor %rdx, %rdx              # timeout = 0
    mov $7, %rax                # poll
    syscall
    cmp $1, %rax                # absent fd reports POLLNVAL
    jne fail
    cmpw $32, 6(%rsp)           # POLLNVAL, independent of requested events
    jne fail
    add $16, %rsp
    mov $39, %rax               # getpid: guest-owned and served
    syscall
    test %rax, %rax
    jle fail
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
handler:
    ret
.data
.balign 8
action:
    .quad handler                 # sa_handler
    .quad 0                       # sa_flags
    .quad 0                       # sa_restorer
    .quad 0                       # sa_mask (x86_64 kernel sigset size 8)
.section .rodata
ok: .ascii "R\n"
