# Native x86 Linux oracle for #2226: the first write after fork to a page
# that was prepared but never touched before the fork.
# Build: cc -nostdlib -static -no-pie -Wl,--build-id=none \
#   -o /tmp/carrick-x86-fork-prepared-cow-write x86_fork_prepared_cow_write.S
# Expected stdout: C\n then P\n; expected exit: 7.
# The parent touches only page 0 of a fresh anonymous mapping, so its
# neighbours are prepared but not present when it forks. Both processes are
# live while each takes its first write to a different untouched neighbour:
# the child page 1, the parent page 2. Each write must stay private.
# C: the child saw its own write and neither the parent's nor a lost page 0.
# P: the parent reaped status 3 and still sees page 1 untouched.
.global _start
.text
_start:
    xor %rdi, %rdi
    mov $65536, %rsi
    mov $3, %rdx
    mov $0x22, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r13
    movb $0x70, (%r13)
    mov $57, %rax
    syscall
    test %rax, %rax
    js fail
    je child
    mov %rax, %r12
    movb $0x50, 8192(%r13)
    cmpb $0x50, 8192(%r13)
    jne fail
    mov %r12, %rdi
    lea wait_status(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp %r12, %rax
    jne fail
    mov wait_status(%rip), %eax
    cmp $0x300, %eax
    jne fail
    cmpb $0, 4096(%r13)
    jne fail
    cmpb $0x70, (%r13)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea parent_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child:
    movb $0x63, 4096(%r13)
    cmpb $0x63, 4096(%r13)
    jne child_fail
    cmpb $0x70, (%r13)
    jne child_fail
    cmpb $0, 8192(%r13)
    jne child_fail
    mov $1, %rax
    mov $1, %rdi
    lea child_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $3, %rdi
    jmp exit
child_fail:
    mov $98, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
child_ok: .ascii "C\n"
parent_ok: .ascii "P\n"
.bss
.align 4
wait_status: .skip 4
