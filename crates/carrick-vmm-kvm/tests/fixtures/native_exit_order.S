/* Real native_process_runtime exit: host stops CPU 1 at child MM retirement.
 * CPU 0 probes WNOHANG, admits another fork, then enrolls a blocking wait.
 * Writes are host rendezvous points; no fixture completes a guest lifecycle.
 */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    mov %eax, %r12d
    mov $1, %r13d
    call marker
    /* The host now holds the peer's real retire_mm crossing pending. */
    mov %r12d, %edi
    xor %esi, %esi
    mov $1, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    jnz failure
    /* Retirement must not close the parent's fork admission gate. */
    mov $57, %eax
    syscall
    test %eax, %eax
    jz sibling
    js failure
    mov $2, %r13d
    call marker
    mov %r12d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    cmpl $(19 << 8), -24(%rsp)
    jne failure
    mov $3, %r13d
    call marker
    mov $7, %edi
    jmp exit
child:
    /* Retire real private backing, and verify the parent's marker is isolated. */
    lea marker_byte(%rip), %rbx
    mov $16, %ecx
touch:
    cmpb $0, (%rbx)
    jne failure
    movb $19, (%rbx)
    add $4096, %rbx
    dec %ecx
    jnz touch
    mov $19, %edi
    jmp exit
sibling:
    mov $20, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
marker:
    mov %r13b, marker_byte(%rip)
    mov $1, %edi
    lea marker_byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

/* Private exit payload: sixteen demand-zero pages and the parent's marker. */
.bss
.balign 4096
marker_byte: .space 65536
