/* #2157 B0 T2: one root call per fd-operand class of an x86-allowed host
 * crossing. The run exits with the low byte of the negated result (a
 * Linux errno number), or with the stage code below.
 *
 *   STDIO_OBJECT  dup2(2, 5); write(5, "S", 1): fd 5 is the stderr host
 *                 object under another number. Exit 1 (bytes written),
 *                 and "S" reaches stderr.
 *   HOST_BACKED   pread64(PREOPENED_FD, buf, 4, 0) on a host file seeded
 *                 before entry. Exit 4 when the four bytes are "ABCD",
 *                 70 when the bytes differ.
 *   IN_ZONE       pipe2(fds, 0); lseek(fds[0], 0, SEEK_CUR): a pipe is an
 *                 in-zone object and never reaches the host. Linux
 *                 answers ESPIPE (29); never a host lseek on another fd.
 *   ABSENT        close(0); lseek(0, 0, SEEK_CUR): EBADF (9).
 *   DUP_STDIN     dup2(0, 5); read(5, buf, 0): fd 5 is the stdin host
 *                 object under another number, so the read uses that
 *                 object. Exit 0; never the host's own fd 5.
 *
 * 90 = a setup call failed. */
.global _start
.text
_start:
#ifdef STDIO_OBJECT
    mov $2, %edi                   /* dup2(2, 5) */
    mov $5, %esi
    mov $33, %eax
    syscall
    cmp $5, %rax
    jne setup_failed
    mov $5, %edi                   /* write(5, "S", 1) */
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    jmp result
#endif
#ifdef HOST_BACKED
    mov $PREOPENED_FD, %edi        /* pread64(fd, buf, 4, 0) */
    lea buffer(%rip), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $17, %eax
    syscall
    cmp $4, %rax
    jne result
    cmpl $0x44434241, buffer(%rip) /* "ABCD" */
    jne bytes_differ
    jmp result
#endif
#ifdef IN_ZONE
    lea fds(%rip), %rdi            /* pipe2(fds, 0) */
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    jnz setup_failed
    mov fds(%rip), %edi            /* lseek(fds[0], 0, SEEK_CUR) */
    xor %esi, %esi
    mov $1, %edx
    mov $8, %eax
    syscall
    jmp result
#endif
#ifdef ABSENT
    xor %edi, %edi                 /* close(0) */
    mov $3, %eax
    syscall
    test %rax, %rax
    jnz setup_failed
    xor %edi, %edi                 /* lseek(0, 0, SEEK_CUR) */
    xor %esi, %esi
    mov $1, %edx
    mov $8, %eax
    syscall
    jmp result
#endif
#ifdef DUP_STDIN
    xor %edi, %edi                 /* dup2(0, 5) */
    mov $5, %esi
    mov $33, %eax
    syscall
    cmp $5, %rax
    jne setup_failed
    mov $5, %edi                   /* read(5, buf, 0) */
    lea buffer(%rip), %rsi
    xor %edx, %edx
    xor %eax, %eax
    syscall
    jmp result
#endif
    jmp setup_failed

result:
    test %rax, %rax
    jns 1f
    neg %rax
1:
    mov %eax, %edi
    jmp exit
bytes_differ:
    mov $70, %edi
    jmp exit
setup_failed:
    mov $90, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
message: .ascii "S"

.section .data
.balign 8
fds: .long -1, -1
buffer: .quad 0
