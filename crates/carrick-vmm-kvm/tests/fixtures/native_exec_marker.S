.global _start
.text
_start:
    sub $16, %rsp
    stmxcsr (%rsp)
    fnstcw 4(%rsp)
    cmpl $0x1f80, (%rsp)
    jne failure
    cmpw $0x037f, 4(%rsp)
    jne failure
    movsd one(%rip), %xmm0
    divsd three(%rip), %xmm0
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $2, %edx
    mov $1, %eax
    syscall
    cmp $2, %eax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
marker: .ascii "X\n"
.balign 8
one: .double 1.0
three: .double 3.0
