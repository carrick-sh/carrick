/* Shared scaffolding for the #2157 B1 host-crossing witnesses. Every
 * fixture runs the same script natively and under carrick, in a scratch
 * working directory the harness supplies, and prints "F\n" and exits 7 only
 * when every step returned its Linux result. A wrong result exits with the
 * step number instead, so a red run names the first call that differed.
 *
 * Under -DCHILD the script runs in a forked child instead: the ring answers
 * a fork child's host crossing with a counted ENOSYS (it owns no host task),
 * except a descriptor it closed, which is EBADF. The parent reaps the child
 * and checks that the child left no host effect. */
.equ AT_FDCWD, -100
.equ SYS_write, 1
.equ SYS_close, 3
.equ SYS_lseek, 8
.equ SYS_fork, 57
.equ SYS_wait4, 61
.equ SYS_exit_group, 231
.equ ENOSYS, 38

/* syscall with the number in %eax, arguments already in place. */
.macro SYS nr
    mov $\nr, %eax
    syscall
.endm

/* Fail the script with `step` unless %rax == val. */
.macro EXPECT step, val
    cmp $\val, %rax
    je 9f
    mov $\step, %edi
    jmp fail
9:
.endm

/* Fail the script with `step` unless %rax >= 0. */
.macro EXPECT_OK step
    test %rax, %rax
    jns 9f
    mov $\step, %edi
    jmp fail
9:
.endm

.macro PATH reg, sym
    lea \sym(%rip), \reg
.endm

.text
.global _start
_start:
#ifdef CHILD
    SYS SYS_fork
    test %eax, %eax
    js start_failed
    jz child_script
    mov %eax, %edi
    PATH %rsi, status
    xor %edx, %edx
    xor %r10d, %r10d
    SYS SYS_wait4
    test %eax, %eax
    js start_failed
    mov status(%rip), %edi
    test %edi, %edi
    jz parent_script
    shr $8, %edi
    jmp fail
#else
    jmp root_script
#endif
start_failed:
    mov $91, %edi
fail:
    SYS SYS_exit_group
    ud2

pass:
    mov $1, %edi
    PATH %rsi, done_message
    mov $2, %edx
    SYS SYS_write
    mov $7, %edi
    SYS SYS_exit_group
    ud2

/* A child that matched every expectation. */
child_done:
    xor %edi, %edi
    SYS SYS_exit_group
    ud2

.section .rodata
done_message: .ascii "F\n"

.section .bss
.balign 16
status: .skip 8
scratch: .skip 1024

.text
