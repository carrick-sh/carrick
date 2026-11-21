/* One byte per raw syscall: errno on failure, or a normalized result.
 * WORK_PATH contains "file" (regular) and "sym" (points to "file").
 * CHILD runs the same calls after fork; NAMESPACE and IPC select the batch.
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

#ifdef NAMESPACE
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
#ifdef CHILD
    /* The child's canonical readlinkat owner serves this call. */
    mov $267, %eax
    mov $-100, %rdi
    lea sym(%rip), %rsi
    lea buf(%rip), %rdx
    mov $16, %r10d
    syscall
    record
#endif
    legacy 133, fifo, 0010600, 0   /* mknod creates a FIFO */
    record
#ifdef CHILD
    mov $259, %eax                 /* mknodat canonical control */
    mov $-100, %rdi
    lea fifo_at(%rip), %rsi
    mov $0010600, %edx
    xor %r10d, %r10d
    syscall
    record
#endif
#elif defined(IPC)
    legacy 22, buf, -1              /* pipe must ignore the second register */
    record
    test %rax, %rax
    jne 1f
    mov buf(%rip), %eax
    cmp buf+4(%rip), %eax
    je failed
    mov buf+4(%rip), %edi          /* write a byte to the pipe */
    mov $1, %eax
    lea file(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    mov buf(%rip), %edi            /* read it using the returned read end */
    xor %eax, %eax
    lea buf+8(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failed
    movzbl buf+8(%rip), %eax
    record
1:
    legacy 284, 3, -1               /* eventfd must ignore the second register */
    test %rax, %rax
    js 1f
    mov %eax, %edi
    xor %eax, %eax
    lea buf(%rip), %rsi
    mov $8, %edx
    syscall
    cmp $8, %rax
    jne failed
    mov buf(%rip), %rax
1:  record
#else
    legacy 2, sym, 0x20000          /* open: O_NOFOLLOW */
    record
    legacy 2, file, 0x10000        /* O_DIRECTORY rejects a regular file */
    call close_and_record
    legacy 2, dot, 0x10000          /* open: O_DIRECTORY */
    call close_and_record
    legacy 85, created, 0600       /* creat */
    call close_and_record
    legacy 4, sym, buf              /* stat follows the link */
    record
    mov buf+24(%rip), %eax          /* x86 st_mode, S_IFMT >> 12 */
    shr $12, %eax
    and $15, %eax
    record
    legacy 6, sym, buf              /* lstat reports the link */
    record
    mov buf+24(%rip), %eax
    shr $12, %eax
    and $15, %eax
    record
    legacy 111, -1                  /* getpgrp() == getpgid(0) */
    test %rax, %rax
    js 1f
    mov %rax, %rbx
    mov $121, %eax
    xor %edi, %edi
    syscall
    cmp %rbx, %rax
    setne %al
    movzbl %al, %eax
1:  record
#endif

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

#if !defined(NAMESPACE) && !defined(IPC)
close_and_record:
    test %rax, %rax
    js 1f
    mov %rax, %rdi
    mov $3, %eax
    syscall
1:  record
    ret
#endif

failed:
    mov $100, %edi
exit:
    mov $231, %eax
    syscall

.section .rodata
work:    .asciz WORK_PATH
dot:     .asciz "."
file:    .asciz "file"
sym:     .asciz "sym"
dir:     .asciz "dir"
hard:    .asciz "hard"
moved:   .asciz "moved"
new_sym: .asciz "new-sym"
created: .asciz "created"
fifo:    .asciz "fifo"
fifo_at: .asciz "fifo-at"

.bss
.balign 8
status: .zero 4
report: .zero 16
.balign 8
buf: .zero 144
