/* Dense initialized image: exercise both initial and first-fork table paths. */
.global _start
.text
_start:
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    cmpl $(7 << 8), -24(%rsp)
    jne failure
child:
    mov $7, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
    .skip 100 * 1024 * 1024, 0
