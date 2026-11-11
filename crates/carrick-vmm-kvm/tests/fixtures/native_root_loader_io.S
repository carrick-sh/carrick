/* #1714: glibc's loader as the run root. It opens a library in the ring
 * namespace, reads, preads, seeks and stats it there, reports through
 * writev, narrows its own RELRO page with mprotect, and writes a file it
 * creates under its own RLIMIT_FSIZE. Each failed step
 * exits with its number; the native oracle exits 0. */
.global _start
.text
_start:
    mov $-100, %edi                 /* openat(AT_FDCWD, path, O_RDONLY|O_CLOEXEC) */
    lea name(%rip), %rsi
    mov $0x80000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov $10, %edi
    test %rax, %rax
    js exit
    mov %rax, %r12

    mov %r12, %rdi                  /* read(fd, buf, 64) == 14 */
    lea buf(%rip), %rsi
    mov $64, %edx
    xor %eax, %eax
    syscall
    mov $11, %edi
    cmp $14, %rax
    jne exit

    mov %r12, %rdi                  /* pread64(fd, buf, 6, 7) == 6, "librar" */
    lea buf(%rip), %rsi
    mov $6, %edx
    mov $7, %r10d
    mov $17, %eax
    syscall
    mov $12, %edi
    cmp $6, %rax
    jne exit
    mov $13, %edi
    cmpb $0x6c, buf(%rip)
    jne exit

    mov %r12, %rdi                  /* lseek(fd, 0, SEEK_END) == 14 */
    xor %esi, %esi
    mov $2, %edx
    mov $8, %eax
    syscall
    mov $14, %edi
    cmp $14, %rax
    jne exit

    mov %r12, %rdi                  /* fstat(fd, &st): x86 st_size@48, st_mode@24 */
    lea st(%rip), %rsi
    mov $5, %eax
    syscall
    mov $15, %edi
    test %rax, %rax
    jne exit
    cmpq $14, st+48(%rip)
    jne exit
    mov $16, %edi
    mov st+24(%rip), %eax
    and $0170000, %eax
    cmp $0100000, %eax
    jne exit

    movq $0, st+48(%rip)            /* newfstatat(fd, "", &st, AT_EMPTY_PATH) */
    mov %r12, %rdi
    lea empty(%rip), %rsi
    lea st(%rip), %rdx
    mov $0x1000, %r10d
    mov $262, %eax
    syscall
    mov $17, %edi
    test %rax, %rax
    jne exit
    cmpq $14, st+48(%rip)
    jne exit

    mov $1, %edi                    /* writev(1, iov, 2) == 6 */
    lea iov(%rip), %rsi
    mov $2, %edx
    mov $20, %eax
    syscall
    mov $18, %edi
    cmp $6, %rax
    jne exit

    movb $7, relro(%rip)            /* relocate, then mprotect(relro, 4096, PROT_READ) */
    lea relro(%rip), %rdi
    mov $4096, %esi
    mov $1, %edx
    mov $10, %eax
    syscall
    mov $19, %edi
    test %rax, %rax
    jne exit

    mov %r12, %rdi                  /* close(fd) */
    mov $3, %eax
    syscall
    mov $20, %edi
    test %rax, %rax
    jne exit

    mov $-100, %edi                 /* openat(AT_FDCWD, out, O_RDWR|O_CREAT|O_TRUNC, 0600) */
    lea out(%rip), %rsi
    mov $0x242, %edx
    mov $0600, %r10d
    mov $257, %eax
    syscall
    mov $21, %edi
    test %rax, %rax
    js exit
    mov %rax, %r12

    mov %r12, %rdi                  /* write(fd, "data", 4) == 4: the root's RLIMIT_FSIZE */
    lea data(%rip), %rsi
    mov $4, %edx
    mov $1, %eax
    syscall
    mov $22, %edi
    cmp $4, %rax
    jne exit

    mov %r12, %rdi                  /* pread64(fd, buf, 4, 0) == 4, "data" */
    lea buf(%rip), %rsi
    mov $4, %edx
    xor %r10d, %r10d
    mov $17, %eax
    syscall
    mov $23, %edi
    cmp $4, %rax
    jne exit
    cmpb $0x64, buf(%rip)
    jne exit
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
name: .asciz FILE_PATH
out: .asciz OUT_PATH
data: .ascii "data"
empty: .asciz ""
wv0: .ascii "wv-"
wv1: .ascii "ok\n"
.section .data
.balign 16
iov: .quad wv0, 3, wv1, 3
.balign 4096
relro: .fill 4096, 1, 1
.section .bss
.balign 64
buf: .skip 64
st: .skip 256
.section .note.GNU-stack,"",@progbits
