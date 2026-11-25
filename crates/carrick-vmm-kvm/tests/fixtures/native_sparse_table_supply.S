/* A sparse address space needs page tables beyond the image's (#3017). V8
 * scatters its reservations across the 47-bit space, so each touched page
 * can need a fresh PDPT, PD and PT. The root touches one page in each of
 * COUNT (64) 512 GiB slots (192 tables: one 512-page reserve draw), creates a
 * gate pipe, and forks TWO live children before releasing the gate: child 1's
 * ~200-page fork loan leaves ~176 stock pages, so ForkStock::loan for child 2
 * must draw a second 512-page run from the reserve itself. Once released, both
 * children touch COUNT more slots (384 tables together: drawing a third
 * 512-page run) and rewrite every inherited page (copy-on-write) while the
 * parent waits live, then the parent checks that its pages still hold 1.
 * Exit: the mmap errno, 92 when a hint is placed elsewhere, 91 when a page
 * reads back wrong, 93 when wait/pipe fails or a child dies by a signal,
 * 94 when fork fails, else the child's status (0).
 */
#define ROOT_BASE 0x10000000000
#define CHILD_BASE 0x410000000000
#define STRIDE 0x8000000000
#define COUNT 64
.global _start
.text
_start:
    /* pipe2(pipefd, 0) */
    lea pipefd(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js parent_failure

    movabs $ROOT_BASE, %rbx
    mov $1, %r13d
    call touch_slots

    /* Fork child 1; it blocks on pipefd[0] so its ~200 tables stay committed. */
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_errno
    jz child
    mov %rax, %rbp

    /* Fork child 2 while child 1 still holds its tables: ForkStock::loan draws
     * a second 512-page run from the table reserve. */
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_errno
    jz child
    mov %rax, %r14

    /* Close both pipe fds in parent; closing pipefd[1] wakes both children. */
    mov pipefd(%rip), %edi
    mov $3, %eax
    syscall
    mov pipefd+4(%rip), %edi
    mov $3, %eax
    syscall

    /* Reap child 1 (%rbp) and child 2 (%r14). */
    mov %rbp, %rdi
    call reap_one
    mov %r14, %rdi
    call reap_one

    /* Parent byte isolation: child COW rewrites never mutate the root's pages. */
    movabs $ROOT_BASE, %r12
    mov $COUNT, %r15d
verify_parent:
    cmpb $1, (%r12)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %r12
    dec %r15d
    jnz verify_parent
    xor %edi, %edi
    jmp exit

reap_one:
    mov %rdi, %r12
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne parent_failure
    mov status(%rip), %edi
    test $0x7f, %edi
    jnz parent_failure
    shr $8, %edi
    and $0xff, %edi
    test %edi, %edi
    jnz exit
    ret

child:
    /* Close write end, wait for EOF on read end so both forks exist live first. */
    mov pipefd+4(%rip), %edi
    mov $3, %eax
    syscall
    mov pipefd(%rip), %edi
    lea gate_byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    test %rax, %rax
    jnz failure
    mov pipefd(%rip), %edi
    mov $3, %eax
    syscall

    movabs $CHILD_BASE, %rbx
    mov $2, %r13d
    call touch_slots
    /* The inherited pages still read the root's byte; then write them. */
    movabs $ROOT_BASE, %r12
    mov $COUNT, %r15d
rewrite:
    cmpb $1, (%r12)
    jne failure
    movb $3, (%r12)
    cmpb $3, (%r12)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %r12
    dec %r15d
    jnz rewrite
    xor %edi, %edi
    jmp exit

/* Map and touch one page in each of COUNT slots from %rbx, storing %r13b. */
touch_slots:
    mov %rbx, %r12
    mov $COUNT, %r15d
next_slot:
    mov %r12, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js mmap_errno
    cmp %r12, %rax
    jne elsewhere
    cmpb $0, (%r12)
    jne failure
    mov %r13b, (%r12)
    cmp %r13b, (%r12)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %r12
    dec %r15d
    jnz next_slot
    ret

exit:
    mov $231, %eax
    syscall
    ud2
elsewhere:
    mov $92, %edi
    jmp exit
failure:
    mov $91, %edi
    jmp exit
parent_failure:
    mov $93, %edi
    jmp exit
fork_errno:
    mov $94, %edi
    jmp exit
mmap_errno:
    neg %eax
    mov %eax, %edi
    jmp exit
.bss
.balign 8
status: .quad 0
pipefd: .long 0, 0
gate_byte: .byte 0
.section .note.GNU-stack,"",@progbits
