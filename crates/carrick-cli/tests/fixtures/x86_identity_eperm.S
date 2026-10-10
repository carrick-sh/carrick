# Native x86 Linux oracle for setresuid unprivileged EPERM.
# Expected stdout: P\n; expected exit: 7.
.global _start
.text
_start:
    # Retain the native caller's uid; root drops all uid roles to nobody.
    # This also drops Carrick's initial root identity without assuming a host uid.
    mov $102, %rax
    syscall
    test %rax, %rax
    jne have_uid
    mov $65534, %rax
have_uid:
    mov %rax, %rdi
    mov %rax, %rsi
    mov %rax, %rdx
    mov $117, %rax
    syscall
    test %rax, %rax
    jne fail_drop

    # 2. Attempt unprivileged privilege elevation: setresuid(0, -1, -1)
    # On Linux, error return in %rax is -errno (-1 for EPERM).
    xor %rdi, %rdi
    mov $-1, %rsi
    mov $-1, %rdx
    mov $117, %rax
    syscall
    cmp $-1, %rax
    jne fail_perm

    # Success: write "P\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

fail_drop:
    mov $91, %rdi
    jmp exit
fail_perm:
    mov $92, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
ok: .ascii "P\n"
