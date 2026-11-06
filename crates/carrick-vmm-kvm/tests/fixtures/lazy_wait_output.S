/* wait4 must prepare a valid, untouched ELF output page in the parent MM. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    cmpl $(19 << 8), status(%rip)
    jne failure
    mov $7, %edi
    jmp exit
child:
    mov $19, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.bss
.balign 4096
status: .space 4096
