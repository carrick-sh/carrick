/* True terminal page-table exhaustion (#3017 review P0-1): on a carrier whose
 * table stock and reserve are spent into live committed MM custody with zero
 * returnable tables, an in-ring pipe copyout into an unbackable sparse slot
 * answers -EFAULT without consuming the pipe byte, a user-mode touch of that
 * slot delivers SIGSEGV (11) to the faulting process, and the carrier and
 * waiting parent survive cleanly.
 */
#define SPARSE_BASE 0x10000000000
#define STRIDE      0x8000000000
#define MAX_SLOTS   160
.global _start
.text
_start:
    lea pipe_fds(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    jnz parent_setup_fail

    mov $57, %eax
    syscall
    test %rax, %rax
    js parent_setup_fail
    jz child
    mov %rax, %r12

    mov %r12, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12, %rax
    jne wait_fail
    mov status(%rip), %eax
    mov %eax, %ecx
    and $0x7f, %ecx
    test %ecx, %ecx
    jz child_exited_unexpectedly
    cmp $11, %ecx
    jne wrong_signal

    /* Carrier and parent MM remain healthy after the child's exhausted fault. */
    movb $0x77, parent_check(%rip)
    cmpb $0x77, parent_check(%rip)
    jne parent_setup_fail
    xor %edi, %edi
    jmp exit

child_exited_unexpectedly:
    shr $8, %eax
    and $0xff, %eax
    test %eax, %eax
    jnz propagate_child
    mov $96, %edi
    jmp exit
propagate_child:
    mov %eax, %edi
    jmp exit
wrong_signal:
    add $100, %ecx
    mov %ecx, %edi
    jmp exit
wait_fail:
    mov $93, %edi
    jmp exit
parent_setup_fail:
    mov $94, %edi
    jmp exit

child:
    movabs $SPARSE_BASE, %r12
    mov $MAX_SLOTS, %r15d
slot_loop:
    mov %r12, %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    cmp %r12, %rax
    jne mmap_fail

    mov pipe_fds+4(%rip), %edi
    lea pipe_in(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %rax
    jne pipe_write_fail

    mov pipe_fds(%rip), %edi
    mov %r12, %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    je slot_backed
    cmp $-14, %rax
    jne unexpected_read_result

    /* Copyout faulted before delivering: the byte remains in the pipe. */
    mov pipe_fds(%rip), %edi
    lea pipe_out(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne pipe_retained_fail
    cmpb $0x5a, pipe_out(%rip)
    jne pipe_retained_fail

    /* Direct user-mode access to the same unbackable slot must raise SIGSEGV. */
    movb $1, (%r12)
    mov $95, %edi
    jmp exit

slot_backed:
    cmpb $0x5a, (%r12)
    jne byte_mismatch
    movabs $STRIDE, %rcx
    add %rcx, %r12
    dec %r15d
    jnz slot_loop
    mov $97, %edi
    jmp exit

mmap_fail:
    mov $92, %edi
    jmp exit
pipe_write_fail:
    mov $89, %edi
    jmp exit
unexpected_read_result:
    mov $90, %edi
    jmp exit
pipe_retained_fail:
    mov $88, %edi
    jmp exit
byte_mismatch:
    mov $91, %edi
    jmp exit

exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
pipe_in: .byte 0x5a
.bss
.balign 8
pipe_fds: .quad 0
status: .quad 0
pipe_out: .space 1
parent_check: .space 1
.section .note.GNU-stack,"",@progbits
