# Linux fork isolation witness. Both live tasks first-touch the same fresh
# anonymous VA; no parent-private page is populated before fork. The KVM
# receipt additionally requires an overlap of the two production CPU lanes.
# Exit 91 identifies fork refusal separately from grant/leaf failures.
.global _start
.text
_start:
    mov $57, %rax
    syscall
    cmp $-4095, %rax
    jae fork_fail
    mov %rax, %r12
    mov $0x51, %r13
    test %r12, %r12
    jnz map
    mov $0xa2, %r13
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
.section .rodata
ok: .ascii "Q\n"
