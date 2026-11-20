/* One byte per raw syscall: errno on failure, or a normalized result.
 * WORK_PATH contains "file" (regular) and "sym" (points to "file").
 * CHILD runs the same calls after fork.
 * Set unused argument registers to nonzero values to exercise ABI lowering. */
.global _start
.text

.macro legacy number, arg0=0, arg1=0, arg2=0
    mov $\number, %eax
    mov $\arg0, %rdi
    mov $\arg1, %rsi
    mov $\arg2, %rdx
    mov $-1, %r10
    mov $-1, %r8
    mov $-1, %r9
    syscall
.endm

.macro record
    test %rax, %rax
    jns 1f
    neg %rax
1:  mov %al, (%r15)
    inc %r15
.endm

_start:
#ifdef CHILD
    mov $57, %eax                   /* fork */
    syscall
    test %rax, %rax
    js failed
    jz steps
    mov %rax, %rbx
    mov %rax, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                   /* wait4 */
    syscall
    cmp %rbx, %rax
    jne failed
    cmpl $0, status(%rip)
    jne failed
    xor %edi, %edi
    jmp exit
#endif

steps:
    mov $80, %eax                   /* chdir */
    lea work(%rip), %rdi
    syscall
    test %rax, %rax
    jne failed
    lea report(%rip), %r15

    legacy 83, dir, 0700            /* mkdir */
    record
    legacy 84, dir                  /* rmdir */
    record
    legacy 86, file, hard           /* link */
    record
    legacy 82, hard, moved          /* rename */
    record
    legacy 87, moved                /* unlink */
    record
    legacy 88, file, new_sym        /* symlink */
    record
    legacy 89, sym, buf, 16         /* readlink */
    cmp $4, %rax
    jne 1f
    cmpl $0x656c6966, buf(%rip)     /* "file" in little-endian order */
    je 1f
    mov $99, %eax
1:  record

    mov $1, %eax                    /* write the entire report */
    mov $1, %edi
    lea report(%rip), %rsi
    mov %r15, %rdx
    sub %rsi, %rdx
    syscall
    cmp %rdx, %rax
    jne failed
    xor %edi, %edi
    jmp exit

failed:
    mov $100, %edi
exit:
    mov $231, %eax
    syscall

.section .rodata
work:    .asciz WORK_PATH
file:    .asciz "file"
sym:     .asciz "sym"
dir:     .asciz "dir"
hard:    .asciz "hard"
moved:   .asciz "moved"
new_sym: .asciz "new-sym"

.bss
.balign 8
status: .zero 4
report: .zero 16
.balign 8
buf: .zero 144
