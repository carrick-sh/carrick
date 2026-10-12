/* Real native autoreap exit: wait(-1) must retain every pending MM. */
.global _start
.text
_start:
    /* Linux x86 rt_sigaction: handler, flags, restorer, 64-bit mask. */
    lea action(%rip), %rsi
    mov $17, %edi
    xor %edx, %edx
    mov $8, %r10d
    mov $13, %eax
    syscall
    test %eax, %eax
    jnz failure
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    mov $1, %r13d
    call marker
    /* The first child's MM retirement is now held pending by the host. */
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov $2, %r13d
    call marker
    mov $-1, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp $-10, %eax
    jne failure
    /* ECHILD must follow BOTH MM retirements. */
    mov $3, %r13d
    call marker
    /* Admission stays usable after the wait has completed. */
    mov $57, %eax
    syscall
    test %eax, %eax
    jz child
    js failure
    mov %eax, %r12d
    mov $4, %r13d
    call marker
    mov $7, %edi
    jmp exit
child:
    lea marker_byte+4096(%rip), %rbx
    mov $15, %ecx
touch:
    cmpb $0, (%rbx)
    jne failure
    movb $19, (%rbx)
    add $4096, %rbx
    dec %ecx
    jnz touch
    mov $19, %edi
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
.section .rodata
.balign 8
action:
#ifdef IGNORE_SIGCHLD
    .quad 1, 0, 0, 0
#else
    .quad 0, 2, 0, 0
#endif
.bss
.balign 4096
marker_byte: .space 65536
