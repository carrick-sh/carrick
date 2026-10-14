/* Production fd venue: parent and child dup stdout; child exits while
 * parent's independent table stays live. Writes are stopped-host rendezvous. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    call duplicate
    mov $1, %r13d
    call marker
    mov %r12d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    cmpl $(3 << 8), -24(%rsp)
    jne failure
    mov $2, %r13d
    call marker
    ud2
child:
    call duplicate
    mov $3, %edi
    jmp exit
duplicate:
    mov $1, %edi
    mov $32, %eax
    syscall
    cmp $3, %eax
    jne failure
    ret
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
.bss
.balign 4096
marker_byte: .space 4096
