# Native x86 Linux oracle for glibc startup sequence:
# set_tid_address, set_robust_list, prlimit64, getuid, geteuid, getgid, getegid, uname, getppid.
# Expected stdout: S\n; expected exit: 7.
.global _start
.text
_start:
    # 1. set_tid_address(&clear_tid)
    lea clear_tid(%rip), %rdi
    mov $218, %rax
    syscall
    test %rax, %rax
    jle fail_tid

    # 2. set_robust_list(&robust_head, 24)
    lea robust_head(%rip), %rdi
    mov $24, %rsi
    mov $273, %rax
    syscall
    test %rax, %rax
    jne fail_robust

    # 3. prlimit64(0, 3, 0, &rlim) [RLIMIT_STACK = 3]
    xor %rdi, %rdi
    mov $3, %rsi
    xor %rdx, %rdx
    lea rlim(%rip), %r10
    mov $302, %rax
    syscall
    test %rax, %rax
    jne fail_rlimit

    # 4. getuid()
    mov $102, %rax
    syscall
    test %rax, %rax
    js fail_uid
    mov %rax, %r12

    # 5. geteuid() == getuid()
    mov $107, %rax
    syscall
    cmp %r12, %rax
    jne fail_euid

    # 6. getgid()
    mov $104, %rax
    syscall
    test %rax, %rax
    js fail_gid
    mov %rax, %r13

    # 7. getegid() == getgid()
    mov $108, %rax
    syscall
    cmp %r13, %rax
    jne fail_egid

    # 8. uname(&uts)
    lea uts(%rip), %rdi
    mov $63, %rax
    syscall
    test %rax, %rax
    jne fail_uname

    # 9. getppid()
    mov $110, %rax
    syscall
    test %rax, %rax
    js fail_ppid

    # Write "S\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

fail_tid:
    mov $91, %rdi
    jmp exit
fail_robust:
    mov $92, %rdi
    jmp exit
fail_rlimit:
    mov $93, %rdi
    jmp exit
fail_uid:
    mov $94, %rdi
    jmp exit
fail_euid:
    mov $95, %rdi
    jmp exit
fail_gid:
    mov $96, %rdi
    jmp exit
fail_egid:
    mov $97, %rdi
    jmp exit
fail_uname:
    mov $98, %rdi
    jmp exit
fail_ppid:
    mov $99, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.data
.balign 8
clear_tid:
    .quad 0
robust_head:
    .quad 0
    .quad 0
    .quad 0
rlim:
    .quad 0
    .quad 0
uts:
    .zero 512

.section .rodata
ok: .ascii "S\n"
