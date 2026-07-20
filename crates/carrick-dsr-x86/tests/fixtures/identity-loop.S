// Repeated immutable identity syscalls. The native x86 JIT should answer
// getpid/gettid from its typed context stamp; only exit_group reaches Rust.
.global _start
.section .text
_start:
    mov $1000, %r12
    movabs $0x5a17c0de5a17c0de, %r13
    mov %r13, -8(%rsp)
1:
    cmp %r12, %r12                  // ZF=1 must survive the syscall
    mov $39, %rax                   // getpid
    syscall
    jne fail
    cmp %r13, -8(%rsp)              // syscall must not touch the red zone
    jne fail
    test %rax, %rax
    jle fail
    cmp %r12, %r12                  // ZF=1 must survive the syscall
    mov $186, %rax                  // gettid
    syscall
    jne fail
    cmp %r13, -8(%rsp)
    jne fail
    test %rax, %rax
    jle fail
    dec %r12
    jnz 1b
    xor %rdi, %rdi
    mov $231, %rax                  // exit_group(0)
    syscall
fail:
    mov $99, %rdi
    mov $231, %rax
    syscall
