/* Linux man-page ABI only. Untouched anonymous outputs on production CPL0. */
.global _start
.section .text
_start:
    mov $9, %eax
    xor %edi, %edi
    mov $32768, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js fail
    mov %rax, %r12
#ifdef STATX_OUTPUT
    mov $332, %eax
    mov $-100, %rdi
    lea path(%rip), %rsi
    xor %edx, %edx
    mov $0x7ff, %r10d
    mov %r12, %r8
    syscall
    test %rax, %rax
    jne fail
    movzwl 28(%r12), %eax
    and $0xf000, %eax
    cmp $0x4000, %eax
    jne fail
#elif defined(DIRECT_FILES)
    /* Each destination is a different, previously untouched anonymous page. */
    mov $262, %eax
    mov $-100, %rdi
    lea file_path(%rip), %rsi
    lea 4096(%r12), %rdx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    jne fail
    mov 4096+24(%r12), %eax
    and $0xf000, %eax
    cmp $0x8000, %eax
    jne fail
    mov $257, %eax
    mov $-100, %rdi
    lea file_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r13d
    mov $5, %eax
    mov %r13d, %edi
    lea 8192(%r12), %rsi
    syscall
    test %rax, %rax
    jne fail
    mov 8192+24(%r12), %eax
    and $0xf000, %eax
    cmp $0x8000, %eax
    jne fail
    xor %eax, %eax
    mov %r13d, %edi
    lea 12288(%r12), %rsi
    mov $4, %edx
    syscall
    cmp $4, %rax
    jne fail
    cmpl $0x65726964, 12288(%r12) /* "dire" */
    jne fail
    mov $17, %eax
    mov %r13d, %edi
    lea 16384(%r12), %rsi
    mov $4, %edx
    mov $7, %r10d
    syscall
    cmp $4, %rax
    jne fail
    cmpl $0x676e6172, 16384(%r12) /* "rang" */
    jne fail
    mov $257, %eax
    mov $-100, %rdi
    lea directory_path(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js fail
    mov %eax, %edi
    mov $217, %eax
    lea 20480(%r12), %rsi
    mov $1024, %edx
    syscall
    test %rax, %rax
    jle fail
    lea 20480(%r12), %rsi
    lea (%rsi,%rax), %rdi
.Lentry:
    cmp %rdi, %rsi
    jae fail
    movzwl 16(%rsi), %eax
    cmp $24, %eax
    jb fail
    cmpl $0x61746164, 19(%rsi) /* "data" */
    jne .Lnext
    cmpb $0, 23(%rsi)
    je .Lfound
.Lnext:
    add %rax, %rsi
    jmp .Lentry
.Lfound:
#elif defined(DIRECT_STDIO)
    /* Delegated fd 0 crosses to the host dispatcher, not native file staging. */
    xor %eax, %eax
    xor %edi, %edi
    mov %r12, %rsi
    mov $4, %edx
    syscall
    cmp $4, %rax
    jne fail
    cmpl $0x65726964, (%r12)
    jne fail
    mov $17, %eax
    xor %edi, %edi
    lea 4096(%r12), %rsi
    mov $4, %edx
    mov $7, %r10d
    syscall
    cmp $4, %rax
    jne fail
    cmpl $0x676e6172, 4096(%r12)
    jne fail
#else
    /* eventfd2(1, EFD_NONBLOCK), then epoll_create1(0). */
    mov $290, %eax
    mov $1, %edi
    mov $0x800, %esi
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r13d
    mov $291, %eax
    xor %edi, %edi
    syscall
    test %rax, %rax
    js fail
    mov %eax, %r14d
    mov $233, %eax
    mov %r14d, %edi
    mov $1, %esi
    mov %r13d, %edx
    lea event(%rip), %r10
    syscall
    test %rax, %rax
    jne fail
    mov $281, %eax
    mov %r14d, %edi
    mov %r12, %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $8, %r9d
    syscall
    cmp $1, %rax
    jne fail
    cmpl $1, (%r12)
    jne fail
    movabs $0x123456789abcdef, %rax
    cmp %rax, 4(%r12)
    jne fail
#endif
    xor %edi, %edi
    jmp done
fail:
    mov $31, %edi
done:
    mov $231, %eax
    syscall
    ud2
.section .rodata
path: .asciz "/"
#ifdef DIRECT_FILES
file_path: .asciz FILE_PATH
directory_path: .asciz DIR_PATH
#endif
event:
    .long 1
    .quad 0x123456789abcdef
.section .note.GNU-stack,"",@progbits
