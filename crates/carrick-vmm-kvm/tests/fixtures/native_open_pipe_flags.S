/* Raw x86-64 openat and pipe2 on the run root or its fork child. Reports
 * errno bytes for opens and pipe2, followed by descriptor/status checks. */
.global _start
.text
.equ O_DIRECTORY, 0x10000
.equ O_NOFOLLOW, 0x20000
.equ O_DIRECT, 0x4000
.equ O_CLOEXEC, 0x80000
.equ O_NONBLOCK, 0x800

.macro openat path, flags
    mov $257, %eax
    mov $-100, %rdi                /* AT_FDCWD */
    lea \path(%rip), %rsi
    mov $\flags, %edx
    xor %r10d, %r10d
    syscall
.endm

/* Turn a descriptor or other success into zero, and errors into errno. */
.macro record_status
    test %rax, %rax
    js 1f
    xor %eax, %eax
    jmp 2f
1:  neg %rax
2:  mov %al, (%r15)
    inc %r15
.endm

.macro close_if_open
    test %r12, %r12
    js 1f
    mov %r12, %rdi
    mov $3, %eax
    syscall
1:
.endm

_start:
#ifdef CHILD
    mov $57, %eax
    syscall
    test %rax, %rax
    js failed
    jz steps
    mov %rax, %rbx
    mov %rax, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                  /* wait4 */
    syscall
    cmp %rbx, %rax
    jne failed
    cmpl $0, status(%rip)
    jne failed
    jmp passed
#endif

steps:
    lea report(%rip), %r15
    openat file, O_DIRECTORY
    mov %rax, %r12
    record_status
    close_if_open

    openat symlink, O_NOFOLLOW
    mov %rax, %r12
    record_status
    close_if_open

    openat dir, O_DIRECTORY
    mov %rax, %r12
    record_status
    mov %r12, %rdi
    mov $3, %esi                   /* F_GETFL */
    mov $72, %eax
    syscall
    test %rax, %rax
    js 1f
    and $O_DIRECT, %eax
    setne %al
    movzbl %al, %eax
1:  mov %al, (%r15)
    inc %r15
    close_if_open

    lea pipefds(%rip), %rdi
    mov $(O_CLOEXEC | O_NONBLOCK), %esi
    mov $293, %eax
    syscall
    mov %rax, %r12
    record_status
    test %r12, %r12
    js write_report

    xor %ebx, %ebx
    lea pipefds(%rip), %r13
end_flags:
    mov (%r13,%rbx,4), %edi
    mov $1, %esi                   /* F_GETFD */
    mov $72, %eax
    syscall
    mov %al, (%r15)
    inc %r15

    mov $3, %esi                   /* F_GETFL */
    mov $72, %eax
    syscall
    test %rax, %rax
    js 1f
    and $(O_NONBLOCK | O_DIRECT), %eax
    cmp $O_NONBLOCK, %eax
    sete %al
1:  mov %al, (%r15)
    inc %r15
    inc %ebx
    cmp $2, %ebx
    jne end_flags

write_report:
    mov $1, %edi
    lea report(%rip), %rsi
    mov %r15, %rdx
    sub %rsi, %rdx
    mov $1, %eax
    syscall
    cmp %rdx, %rax
    jne failed
passed:
    xor %edi, %edi
    jmp exit
failed:
    mov $100, %edi
exit:
    mov $231, %eax
    syscall

.section .rodata
dir: .asciz DIR_PATH
file: .asciz FILE_PATH
symlink: .asciz LINK_PATH

.bss
.balign 4
status: .zero 4
pipefds: .zero 8
report: .zero 9
.section .note.GNU-stack,"",@progbits
