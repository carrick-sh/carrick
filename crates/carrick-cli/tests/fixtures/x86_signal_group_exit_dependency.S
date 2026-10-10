# Two threads share one mm; uncaught SIGTERM requires group exit custody.
# Native Linux terminates with SIGTERM. Carrick's named guard is temporary.
.global _start
.text
_start:
    mov $56, %eax
    mov $0x50f00, %edi
    lea child_stack_end(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    js fail
    jz child
ready_wait:
    cmpl $1, ready(%rip)
    jne ready_wait
    mov $39, %eax
    syscall
    mov %rax, %rdi
    mov $15, %esi
    mov $62, %eax
    syscall
    jmp fail
child:
    movl $1, ready(%rip)
loop:
    pause
    jmp loop
fail:
    mov $231, %eax
    mov $99, %edi
    syscall
    ud2
.bss
.align 16
ready: .space 16
child_stack: .space 65536
child_stack_end:
