/* #2337: a fork child breaks one COW page while its parent waits in wait4.
 * No sibling thread and no yield-count loop: the child's write is the
 * process's first COW supply crossing, so a fixture-held editor parks it
 * and only the release resumes it. Exit 7 when the child's write landed
 * and it exited 7; 91 a failed syscall, 92 a wrong byte, 93 a wrong child
 * status. */
.global _start
.text
_start:
    movb $1, page(%rip)
    mov $57, %eax
    syscall
    test %rax, %rax
    jz in_child
    js failure
    mov %rax, %r12
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne failure
    cmpl $1792, status(%rip)
    jne bad_status
    cmpb $1, page(%rip)
    jne bad_byte
    mov $7, %edi
    jmp exit_group
in_child:
    movb $0x51, page(%rip)
    cmpb $0x51, page(%rip)
    jne bad_byte
    mov $7, %edi
    jmp exit_group
bad_byte:
    mov $92, %edi
    jmp exit_group
bad_status:
    mov $93, %edi
    jmp exit_group
failure:
    mov $91, %edi
exit_group:
    mov $231, %eax
    syscall
    ud2
.data
.balign 4096
page: .byte 0
.bss
.balign 4096
status: .space 8
