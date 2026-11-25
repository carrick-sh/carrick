/* A sparse address space needs page tables beyond the image's (#3017). V8
 * scatters its reservations across the 47-bit space, so each touched page
 * can need a fresh PDPT, PD and PT. The root touches one page in each of
 * COUNT 512 GiB slots, then forks: the child touches COUNT more slots at
 * another base while the parent waits live, and then rewrites every
 * inherited page (copy-on-write). Linux serves all of it: page tables come
 * from ordinary memory, never from a pool sized by the executable.
 * Exit: the mmap errno, 92 when a hint is placed elsewhere, 91 when a page
 * reads back wrong, 93 when the parent's wait fails or the child dies by a
 * signal, 94 when fork fails, else the child's status (0).
 */
#define ROOT_BASE 0x10000000000
#define CHILD_BASE 0x410000000000
#define STRIDE 0x8000000000
#define COUNT 64
.global _start
.text
_start:
    movabs $ROOT_BASE, %rbx
    mov $1, %r13d
    call touch_slots
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_errno
    jz child
    mov %rax, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %rdi, %rax
    jne parent_failure
    mov status(%rip), %edi
    test $0x7f, %edi
    jnz parent_failure
    shr $8, %edi
    and $0xff, %edi
    jmp exit
child:
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
.section .note.GNU-stack,"",@progbits
