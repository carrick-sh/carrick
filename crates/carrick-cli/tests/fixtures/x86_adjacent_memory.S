# Native x86 Linux oracle for the production CPL0 anonymous-memory lane.
# Build: cc -nostdlib -static -no-pie -Wl,--build-id=none \
#   -o /tmp/carrick-x86-adjacent-memory x86_adjacent_memory.S
# Expected stdout: A\n; expected exit: 7.
.global _start
.text
_start:
    mov $0x50001000, %rdi
    mov $4096, %rsi
    mov $3, %rdx
    mov $0x32, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r13
    movb $0x5a, (%r13)
    cmpb $0x5a, (%r13)
    jne fail
    lea -4096(%r13), %rdi
    mov $4096, %rsi
    mov $3, %rdx
    mov $0x32, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    lea -4096(%r13), %r14
    cmp %r14, %rax
    jne fail
    movb $0xa5, (%r14)
    cmpb $0xa5, (%r14)
    jne fail
    cmpb $0x5a, (%r13)
    jne fail
    mov $1, %rax
    mov $1, %rdi
    lea adjacent_ok(%rip), %rsi
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
.section .rodata
adjacent_ok: .ascii "A\n"
