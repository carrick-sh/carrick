# Native x86 Linux oracle for #3099: a fork child takes PAGES copy-on-write
# faults, one per page of an inherited private mapping.
# Build: cc -nostdlib -static -no-pie -Wl,--build-id=none -DPAGES=4096 \
#   -o /tmp/carrick-x86-fork-cow-pages x86_fork_cow_pages.S
# Expected stdout: A\n; expected exit: 7.
# The parent touches every page (byte 1), then forks. The child stores 2
# into every page and checks each store, so each page is one COW supply,
# and exits 3. The parent reaps status 3 and still reads 1 in every page.
# 98: a child store was lost; 97: the parent saw a child store; 99: a
# syscall failed.
# -DGRANDCHILD: the parent is a child subreaper. After its stores the child
# forks a grandchild, which inherits every replaced page, and exits first.
# The grandchild waits for EOF on a pipe the parent closes once it has
# reaped the child, checks one inherited page (2), and exits 4; the parent
# reaps it as the subreaper. So the MM that owned the replacements retires
# before the last MM that maps them.
#ifndef PAGES
#define PAGES 4096
#endif
.global _start
.text
_start:
#ifdef GRANDCHILD
    mov $36, %rdi
    mov $1, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    xor %r8, %r8
    mov $157, %rax
    syscall
    test %rax, %rax
    jnz fail
    lea pipe_fds(%rip), %rdi
    mov $22, %rax
    syscall
    test %rax, %rax
    jnz fail
#endif
    xor %rdi, %rdi
    mov $(PAGES * 4096), %rsi
    mov $3, %rdx
    mov $0x22, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r13
    xor %rcx, %rcx
touch:
    movb $1, (%r13, %rcx)
    add $4096, %rcx
    cmp $(PAGES * 4096), %rcx
    jb touch
    mov $57, %rax
    syscall
    test %rax, %rax
    js fail
    je child
    mov %rax, %r12
    mov %r12, %rdi
    lea wait_status(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp %r12, %rax
    jne fail
    mov wait_status(%rip), %eax
    cmp $0x300, %eax
    jne fail
#ifdef GRANDCHILD
    movslq pipe_fds+4(%rip), %rdi
    mov $3, %rax
    syscall
    test %rax, %rax
    jnz fail
    mov $-1, %rdi
    lea wait_status(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    test %rax, %rax
    jle fail
    mov wait_status(%rip), %eax
    cmp $0x400, %eax
    jne fail
#endif
    xor %rcx, %rcx
parent_check:
    cmpb $1, (%r13, %rcx)
    jne parent_saw_child
    add $4096, %rcx
    cmp $(PAGES * 4096), %rcx
    jb parent_check
    mov $1, %rax
    mov $1, %rdi
    lea parent_ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child:
    xor %rcx, %rcx
child_store:
    movb $2, (%r13, %rcx)
    cmpb $2, (%r13, %rcx)
    jne child_fail
    add $4096, %rcx
    cmp $(PAGES * 4096), %rcx
    jb child_store
#ifdef GRANDCHILD
    mov $57, %rax
    syscall
    test %rax, %rax
    js fail
    je grandchild
#endif
    mov $3, %rdi
    jmp exit
#ifdef GRANDCHILD
grandchild:
    movslq pipe_fds+4(%rip), %rdi
    mov $3, %rax
    syscall
    test %rax, %rax
    jnz fail
    movslq pipe_fds(%rip), %rdi
    lea read_byte(%rip), %rsi
    mov $1, %rdx
    xor %rax, %rax
    syscall
    test %rax, %rax
    jnz fail
    cmpb $2, (%r13)
    jne child_fail
    mov $4, %rdi
    jmp exit
#endif
child_fail:
    mov $98, %rdi
    jmp exit
parent_saw_child:
    mov $97, %rdi
    jmp exit
fail:
    mov $99, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
.section .rodata
parent_ok: .ascii "A\n"
.bss
.align 4
wait_status: .skip 4
pipe_fds: .skip 8
read_byte: .skip 1
