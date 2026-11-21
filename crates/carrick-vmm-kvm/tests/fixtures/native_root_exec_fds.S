/* #2142: the run root holds one descriptor close-on-exec (fd 30) and one
 * without (fd 31), then execs EXEC_PATH, whose successor checks that exec
 * closed only the first. Exit 100 + errno: an open or dup failed. Exit with
 * the errno: the exec returned.
 */
#define O_CLOEXEC 0x80000
.global _start
.text
_start:
    mov $-100, %edi
    lea null(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax          /* openat */
    syscall
    test %rax, %rax
    js failed
    mov %rax, %r12
    mov %r12, %rdi
    mov $30, %esi
    mov $O_CLOEXEC, %edx
    mov $292, %eax          /* dup3 */
    syscall
    test %rax, %rax
    js failed
    mov %r12, %rdi
    mov $31, %esi
    xor %edx, %edx
    mov $292, %eax
    syscall
    test %rax, %rax
    js failed
    lea path(%rip), %rdi
    lea argv(%rip), %rsi
    lea envp(%rip), %rdx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    mov $231, %eax
    syscall
failed:
    neg %rax
    lea 100(%rax), %rdi
    mov $231, %eax
    syscall
    ud2
.section .rodata
null: .asciz "/dev/null"
path: .asciz EXEC_PATH
.balign 8
argv: .quad path, 0
envp: .quad 0
