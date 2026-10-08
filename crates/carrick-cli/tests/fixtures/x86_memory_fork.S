# Native x86 Linux oracle for the second shared-kernel run milestone.
# Build: cc -nostdlib -static -no-pie -Wl,--build-id=none \
#   -o /tmp/carrick-x86-memory-fork x86_memory_fork.S
# Expected stdout: M\n, C\n, P\n (in that order); expected exit: 7.
# M means brk growth/restoration and anonymous mmap/munmap succeeded.
# C is the fork child; P means the parent reaped its exit status 3.
.global _start
.text
_start:
    mov $12, %rax
    xor %rdi, %rdi
    syscall
    mov %rax, %r12
    lea 4096(%r12), %rdi
    mov $12, %rax
    syscall
    cmp %rdi, %rax
    jne fail
    mov %r12, %rdi
    mov $12, %rax
    syscall
    xor %rdi, %rdi
    mov $4096, %rsi
    mov $3, %rdx
    mov $0x22, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r13
    movb $0x5a, (%r13)
    mov %r13, %rdi
    mov $4096, %rsi
    mov $11, %rax
    syscall
    test %rax, %rax
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea memory_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $57, %rax
    syscall
    test %rax, %rax
    je child
    mov %rax, %rdi
    lea wait_status(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp $0, %rax
    jle fail
    mov wait_status(%rip), %eax
    cmp $0x300, %eax
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea parent_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child:
    mov $1, %rax
    mov $1, %rdi
    lea child_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $3, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
memory_ok: .ascii "M\n"
child_ok: .ascii "C\n"
parent_ok: .ascii "P\n"
.bss
.align 4
wait_status: .skip 4
