/* #3030: a fault whose only returnable page-table custody is a retired fork
 * child that is still installed on its slot. The child touches CHILD_COUNT
 * separate 512 GiB slots (its own committed tables) and exits: its retire
 * crossing quarantines those tables while its CPU still runs it. The harness
 * holds that CPU stopped there, then runs the parent, which touches
 * PARENT_COUNT slots: more than the carrier's window holds without the
 * child's tables, so one touch parks on the stock's release, and the child's
 * slot vacate must return them and wake it. In the harness's 2 MiB carrier
 * ~259 tables remain once the child has retired and the child holds ~200, so
 * 118 slots (354 tables) miss either bound by ~95 tables.
 * Exit: the mmap errno, 92 when a hint is placed elsewhere, 91 when a page
 * reads back wrong, 93 when the wait fails or the child dies, 94 when fork
 * fails, else 0.
 */
#define PARENT_BASE 0x10000000000
#define CHILD_BASE 0x410000000000
#define STRIDE 0x8000000000
#ifndef CHILD_COUNT
#define CHILD_COUNT 64
#endif
#ifndef PARENT_COUNT
#define PARENT_COUNT 118
#endif
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %rax, %rax
    js fork_errno
    jz child
    mov %rax, %r14

    /* Marker 1: forked (the harness checks the child pid in %r12). */
    mov %r14, %r12
    movb $1, marker_byte(%rip)
    call marker

    /* One of these touches finds the window spent while only the retired,
     * still-installed child holds returnable tables: it parks and reruns. */
    movabs $PARENT_BASE, %rbx
    mov $1, %r13d
    mov $PARENT_COUNT, %r15d
    call touch_slots

    mov %r14, %r12
    movb $2, marker_byte(%rip)
    call marker

    mov %r14, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r14, %rax
    jne parent_failure
    mov status(%rip), %edi
    test %edi, %edi
    jnz parent_failure

    movabs $PARENT_BASE, %rbp
    mov $PARENT_COUNT, %r15d
verify_parent:
    cmpb $1, (%rbp)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %rbp
    dec %r15d
    jnz verify_parent
    xor %edi, %edi
    jmp exit

child:
    movabs $CHILD_BASE, %rbx
    mov $2, %r13d
    mov $CHILD_COUNT, %r15d
    call touch_slots
    xor %edi, %edi
    jmp exit

/* Map and touch one page in each of %r15d slots from %rbx, storing %r13b. */
touch_slots:
    mov %rbx, %rbp
next_slot:
    mov %rbp, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js mmap_errno
    cmp %rbp, %rax
    jne elsewhere
    cmpb $0, (%rbp)
    jne failure
    mov %r13b, (%rbp)
    cmp %r13b, (%rbp)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %rbp
    dec %r15d
    jnz next_slot
    ret

marker:
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
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
marker_byte: .byte 0
.section .note.GNU-stack,"",@progbits
