# Linux fork isolation witness. Both live tasks first-touch the same fresh
# anonymous VA; no page in that range is populated before fork. The KVM
# receipt additionally requires an overlap of the two production CPU lanes.
# Signal rendezvous keeps the peer busy while each mm touches its pages;
# both touch phases run concurrently; neither actor exits before the other
# acknowledges completing its own stores. Distinct signals for each phase
# avoid standard-signal coalescing; first-phase waits allow later progress.
# Exit 91 identifies fork refusal separately from grant/leaf failures.
.global _start
.text
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    movq $0x04000000, action+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    mov $13, %eax
    mov $10, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne wait_fail
    mov $13, %eax
    mov $12, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne wait_fail
    mov $39, %eax
    syscall
    mov %rax, %rbp
    mov $57, %rax
    syscall
    cmp $-4095, %rax
    jae fork_fail
    mov %rax, %r12
    mov $0x51, %r13
    test %r12, %r12
    jz child_ready
parent_ready_wait:
    cmpq $1, ready(%rip)
    jb parent_ready_wait
    mov $62, %eax
    mov %r12, %rdi
    mov $12, %esi
    syscall
    test %rax, %rax
    jne wait_fail
    jmp map
child_ready:
    mov $0xa2, %r13
    mov $62, %eax
    mov %rbp, %rdi
    mov $10, %esi
    syscall
    test %rax, %rax
    jne wait_fail
child_go_wait:
    cmpq $1, ready(%rip)
    jb child_go_wait
map:
    mov $0x40000000, %rdi
    mov $65536, %rsi
    mov $3, %rdx
    mov $0x32, %r10
    mov $-1, %r8
    xor %r9, %r9
    mov $9, %rax
    syscall
    cmp $0x40000000, %rax
    jne map_fail
    mov %rax, %r14
    xor %r15, %r15
touch:
    cmpq $0, (%r14,%r15)
    jne leaf_fail
    mov %r13, (%r14,%r15)
    add $4096, %r15
    cmp $65536, %r15
    jne touch
    xor %r15, %r15
verify:
    cmp %r13, (%r14,%r15)
    jne leaf_fail
    add $4096, %r15
    cmp $65536, %r15
    jne verify
    test %r12, %r12
    jz child_exit
    mov $62, %eax
    mov %r12, %rdi
    mov $10, %esi
    syscall
    test %rax, %rax
    jne wait_fail
parent_done_wait:
    cmpq $2, ready(%rip)
    jne parent_done_wait
    sub $16, %rsp
    mov %r12, %rdi
    mov %rsp, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    mov $61, %rax
    syscall
    cmp %r12, %rax
    jne wait_fail
    cmpl $0, (%rsp)
    jne wait_fail
    # Recheck after the child has completed all stores, too.
    xor %r15, %r15
final_verify:
    cmp %r13, (%r14,%r15)
    jne leaf_fail
    add $4096, %r15
    cmp $65536, %r15
    jne final_verify
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit
child_exit:
    mov $62, %eax
    mov %rbp, %rdi
    mov $12, %esi
    syscall
    test %rax, %rax
    jne wait_fail
child_done_wait:
    cmpq $2, ready(%rip)
    jne child_done_wait
    xor %rdi, %rdi
    jmp exit
fork_fail:
    mov $91, %rdi
    jmp exit
map_fail:
    mov $93, %rdi
    jmp exit
leaf_fail:
    mov $94, %rdi
    jmp exit
wait_fail:
    mov $95, %rdi
exit:
    mov $231, %rax
    syscall
    ud2
handler:
    incq ready(%rip)
    ret
restorer:
    mov $15, %eax
    syscall
    ud2
.section .data
.align 8
ready: .quad 0
action: .space 32
.section .rodata
ok: .ascii "Q\n"
