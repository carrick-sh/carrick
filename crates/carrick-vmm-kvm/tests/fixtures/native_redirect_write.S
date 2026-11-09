/* Native host-file write to a redirected stdout (#1954). The caller exits
 * with the low byte of the write result: 12 for the vector, 100 for the
 * untouched-page write, 218 for ENOSYS and 242 for EFAULT.
 *   default       fork; the child writev(1, iov, 2)s "hello" " world\n".
 *   -DUNTOUCHED   fork; the child writes 100 bytes from an untouched
 *                 PROT_READ anonymous page, which must supply zeros.
 *   -DROOT_WRITE  the initial task itself write(1, "hello world\n", 12)s.
 *   -DPREFIX      fork; the child writes 0x100001 bytes starting 16 bytes
 *                 before an unmapped page: Linux returns the 16-byte prefix.
 *   -DPREFIXV     as PREFIX through writev: "hello" then a vector that
 *                 starts on the unmapped page returns 5. */
.global _start
.text
_start:
#ifdef ROOT_WRITE
    mov $1, %edi
    lea message(%rip), %rsi
    mov $12, %edx
    mov $1, %eax
    syscall
    mov %eax, %edi
    jmp exit
#else
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    mov %r12d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov -24(%rsp), %edi
    shr $8, %edi
    and $0xff, %edi
    jmp exit
child:
#if defined(PREFIX) || defined(PREFIXV)
    /* Two writable pages; fill the first's last 16 bytes, unmap the second. */
    xor %edi, %edi
    mov $8192, %esi
    mov $3, %edx           /* PROT_READ | PROT_WRITE */
    mov $0x22, %r10d       /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4095, %rax
    jae failure
    mov %rax, %r13
    movabs $0x3736353433323130, %rax
    mov %rax, 4080(%r13)
    movabs $0x6665646362613938, %rax
    mov %rax, 4088(%r13)
    lea 4096(%r13), %rdi
    mov $4096, %esi
    mov $11, %eax          /* munmap */
    syscall
    test %rax, %rax
    jnz failure
#ifdef PREFIX
    mov $1, %edi
    lea 4080(%r13), %rsi
    mov $0x100001, %edx
    mov $1, %eax
    syscall
#else
    lea message(%rip), %rax
    mov %rax, -32(%rsp)
    movq $5, -24(%rsp)
    lea 4096(%r13), %rax
    mov %rax, -16(%rsp)
    movq $4, -8(%rsp)
    mov $1, %edi
    lea -32(%rsp), %rsi
    mov $2, %edx
    mov $20, %eax
    syscall
#endif
#elif defined(UNTOUCHED)
    xor %edi, %edi
    mov $4096, %esi
    mov $1, %edx           /* PROT_READ */
    mov $0x22, %r10d       /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp $-4095, %rax
    jae failure
    mov %rax, %rsi
    mov $1, %edi
    mov $100, %edx
    mov $1, %eax
    syscall
#else
    mov $1, %edi
    lea iov(%rip), %rsi
    mov $2, %edx
    mov $20, %eax
    syscall
#endif
    mov %eax, %edi
    jmp exit
failure:
    mov $91, %edi
#endif
exit:
    mov $231, %eax
    syscall
    ud2
.data
message: .ascii "hello world\n"
.balign 16
iov:
    .quad message, 5
    .quad message + 5, 7
