/*
 * The x86 root samples CLOCK_REALTIME through a raw syscall(228). With
 * UNMAPPED_VVAR it then unmaps its vvar page, samples again, and forks a
 * native child that samples without the page. The syscall clock must not
 * read user memory: every later sample stays within a minute of the first.
 * (The ring leaves an anonymous MAP_FIXED at the vvar address unrouted, so a
 * guest cannot place a forged page there.)
 * Exit values: 8 success, 38 ENOSYS, 91 wrong clock, 100+errno unmap refused.
 */
#define VVAR 0x2e00000000
.global _start
.text
_start:
    sub $32, %rsp
    xor %edi, %edi
    mov %rsp, %rsi
    call raw_realtime
    cmpq $1600000000, (%rsp)
    jb failure
    cmpq $999999999, 8(%rsp)
    ja failure
#ifdef UNMAPPED_VVAR
    movabs $VVAR, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
    test %rax, %rax
    jne unmap_refused
    call check_later
    mov $57, %eax
    syscall
    test %rax, %rax
    js failure
    jz child
    mov %eax, %r12d
    sub $16, %rsp
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
    call check_later
#endif
    mov $8, %edi
    jmp exit
unmap_refused:
    neg %eax
    lea 100(%rax), %edi
    jmp exit
clock_unserved:
    mov $38, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

#ifdef UNMAPPED_VVAR
/* The first sample is at 8(%rsp) for this frame; sample again above it. */
check_later:
    xor %edi, %edi
    lea 24(%rsp), %rsi
    call raw_realtime
    mov 24(%rsp), %rax
    cmp 8(%rsp), %rax
    jb failure
    sub 8(%rsp), %rax
    cmp $60, %rax
    ja failure
    cmpq $999999999, 32(%rsp)
    ja failure
    ret
#endif

raw_realtime:
    mov $228, %eax
    syscall
    cmp $-38, %rax
    je clock_unserved
    test %rax, %rax
    jne failure
    ret
.section .note.GNU-stack,"",@progbits
