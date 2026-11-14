/* #2276: vfork(2) (x86 58: CLONE_VM|CLONE_VFORK|SIGCHLD, zero stack) suspends
 * the caller until the child execs or exits, so the child runs alone on the
 * caller's stack page. The child writes that page and stdout "C", then
 * exits; only then may the parent write "P\n" and reap it. A parent that ran
 * before its child prints "PC". Expected stdout: "CP\n"; exit: 7. */
.global _start
.text
_start:
    mov $58, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov $1, %edi
    lea parent_message(%rip), %rsi
    mov $2, %edx
    mov $1, %eax
    syscall
    cmp $2, %eax
    jne failure
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    cmpl $0, status(%rip)
    jne failure
    mov $7, %edi
    jmp exit

child:
    movb $0xa5, -16(%rsp)
    mov $1, %edi
    lea child_message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    xor %edi, %edi
    jmp exit

child_failure:
    mov $92, %edi
    jmp exit

failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
child_message: .ascii "C"
parent_message: .ascii "P\n"

.section .bss
.balign 4
status: .space 4
