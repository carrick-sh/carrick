/* rev3022c P0-2: a fork child's exec parks on the fork stock's release; the
 * harness then returns the stock outside any crossing (the parked row's wake
 * fires, nothing probes it) and runs the parent, whose first crossing is an
 * owner-grant table supply for a fresh 512 GiB slot. That crossing must
 * probe the parked exec, which reruns, seals and runs the successor.
 * Exit: the mmap errno, 92 when a hint is placed elsewhere, 91 when a page
 * reads back wrong, 93 when the wait fails or the child fails, 94 when fork
 * fails, else 0. The child exits with the exec errno if execve returns.
 */
#define PARENT_BASE 0x10000000000
#define STRIDE 0x8000000000
#define PARENT_COUNT 4
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

    movabs $PARENT_BASE, %rbp
    mov $PARENT_COUNT, %r15d
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
    movb $1, (%rbp)
    cmpb $1, (%rbp)
    jne failure
    movabs $STRIDE, %rcx
    add %rcx, %rbp
    dec %r15d
    jnz next_slot

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
    xor %edi, %edi
    jmp exit

child:
    lea successor(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit

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
.section .rodata
successor: .asciz SUCCESSOR_PATH
.balign 8
argv: .quad successor, 0
.bss
.balign 8
status: .quad 0
marker_byte: .byte 0
.section .note.GNU-stack,"",@progbits
