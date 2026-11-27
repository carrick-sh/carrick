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
#ifndef PAGES
#define PAGES 4096
#endif
.global _start
.text
_start:
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
    mov $3, %rdi
    jmp exit
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
