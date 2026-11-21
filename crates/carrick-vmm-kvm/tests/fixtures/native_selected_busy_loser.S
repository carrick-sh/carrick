/* #2579: two live threads on two CPUs, one 2 MiB grant window. The leader
 * is the Busy loser of its owner-selected window serve; it must fault again,
 * on unserved pages of that window, and every access must complete. The
 * sibling stays live in user mode on the other CPU, then faults in the same
 * window: neither CPU's grant slot may still hold the loser's window.
 * Exit 7 is success; 80, 81 and 90-99 name the failed step.
 */
.global _start
.text
_start:
    /* Control + worker stack: 0x4000 bytes RW anonymous, prefaulted. */
    xor %edi, %edi
    mov $0x4000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_ctrl_mmap
    mov %rax, %r12
    movq $0, 0x0000(%r12)
    movq $0, 0x1000(%r12)
    movq $0, 0x2000(%r12)
    movq $0, 0x3000(%r12)
    movq $5, 0x20(%r12)
    movq $0, 0x28(%r12)

    /* Lazy 4 MiB arena; %r14 is its 2 MiB-aligned grant window. */
    xor %edi, %edi
    mov $0x400000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_arena_mmap
    lea 0x1fffff(%rax), %r14
    and $-0x200000, %r14

    /* Park census baseline -> %r15. */
    mov $-493, %rax /* INJECT_WAIT_PARK_CENSUS */
    syscall
    mov %rax, %r15

    /* This member's next selected-window serve finds the editor held. */
    mov $-448, %rax /* INJECT_SELECTED_SERVE_BUSY_ONCE */
    syscall
    test %rax, %rax
    jnz fail_arm

    /* Clone the sibling (CLONE_VM..CLONE_CHILD_CLEARTID|SETTID). */
    mov $0x013d0f00, %edi
    lea 0x3ff0(%r12), %rsi
    mov %r12, %rdx
    mov %r12, %r10
    lea 0x100(%r12), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    js fail_clone
    jz worker
    mov %rax, %rbx

    /* Both members fault in the window together (bounded barrier). */
    lock incl 0x08(%r12)
    movabs $0x100000000, %rcx
1:
    cmpl $2, 0x08(%r12)
    je 2f
    pause
    dec %rcx
    jnz 1b
    jmp fail_barrier
2:
    /* Loser: first touch serves Busy after the window was submitted. */
    movq $0x11, (%r14)
    /* Same CPU, same window: an unserved page must still be supplied. */
    movq $0x22, 0x101000(%r14)
    movq $0x33, 0x1ff000(%r14)
    cmpq $0x11, (%r14)
    jne fail_value
    cmpq $0x22, 0x101000(%r14)
    jne fail_value
    cmpq $0x33, 0x1ff000(%r14)
    jne fail_value
    /* Release the live sibling into the same window. */
    movl $1, 0x18(%r12)

    /* The hold met exactly this serve, and the loser parked on it. */
    mov $-447, %rax /* INJECT_SELECTED_SERVE_BUSY_CENSUS */
    syscall
    cmp $1, %rax
    jne fail_busy_census
    mov $-493, %rax
    syscall
    cmp %r15, %rax
    jbe fail_park_census

    /* Join on CHILD_CLEARTID: at most four bounded waits. */
    mov $4, %r13d
3:
    mov (%r12), %edx
    test %edx, %edx
    jz 4f
    mov %r12, %rdi
    xor %esi, %esi
    lea 0x20(%r12), %r10
    mov $202, %eax
    syscall
    dec %r13d
    jnz 3b
    jmp fail_join
4:
    cmpl $1, 0x10(%r12)
    jne fail_worker
    cmpq $0x44, 0x80000(%r14)
    jne fail_worker
    cmpq $0x55, 0x180000(%r14)
    jne fail_worker
    mov $7, %edi
    jmp die

worker:
    lock incl 0x08(%r12)
    movabs $0x100000000, %rcx
5:
    cmpl $2, 0x08(%r12)
    je 6f
    pause
    dec %rcx
    jnz 5b
    mov $80, %edi
    jmp die
6:
    /* Stay live on the other CPU, in user mode, until the loser re-faulted. */
    movabs $0x100000000, %rcx
7:
    cmpl $1, 0x18(%r12)
    je 8f
    pause
    dec %rcx
    jnz 7b
    mov $81, %edi
    jmp die
8:
    movq $0x44, 0x80000(%r14)
    movq $0x55, 0x180000(%r14)
    movl $1, 0x10(%r12)
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2

fail_ctrl_mmap:   mov $90, %edi; jmp die
fail_arena_mmap:  mov $91, %edi; jmp die
fail_arm:         mov $92, %edi; jmp die
fail_clone:       mov $93, %edi; jmp die
fail_barrier:     mov $94, %edi; jmp die
fail_value:       mov $95, %edi; jmp die
fail_busy_census: mov $96, %edi; jmp die
fail_park_census: mov $97, %edi; jmp die
fail_join:        mov $98, %edi; jmp die
fail_worker:      mov $99, %edi; jmp die

die:
    mov $231, %eax
    syscall
    ud2
