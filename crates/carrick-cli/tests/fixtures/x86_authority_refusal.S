# CPL0 must not report success for guest-owned effects it cannot publish.
# Linux native succeeds on these calls; this fixture checks the explicit
# temporary ENOSYS contract for unported effects, and signal ownership.
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
    mov $13, %rax               # rt_sigaction is now guest-owned and served
    syscall
    test %rax, %rax
    jne fail
    mov $10, %rdi
    xor %rsi, %rsi
    lea old_action(%rip), %rdx
    mov $8, %r10
    mov $13, %rax
    syscall
    test %rax, %rax
    jne fail
    lea handler(%rip), %rax
    cmp %rax, old_action(%rip)
    jne fail
    cmpq $0, old_action+8(%rip)
    jne fail
    cmpq $0, old_action+24(%rip)
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
    cmp $-38, %rax              # ENOSYS
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
old_action: .zero 32
.section .rodata
ok: .ascii "R\n"
