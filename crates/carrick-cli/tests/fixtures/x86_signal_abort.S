# A child raises SIGABRT through its exact thread identity; no core is written.
.global _start
.text
_start:
 # Set the limit in the fixture, not only in the host oracle launcher.
 mov $160, %eax
 mov $4, %edi
 lea zero_core_limit(%rip), %rsi
 syscall
 test %rax, %rax
 jne fail
 # Both the Linux oracle and Carrick must enter the same zero-limit case.
 mov $97, %eax
 mov $4, %edi
 lea core_limit(%rip), %rsi
 syscall
 test %rax, %rax
 jne fail
 cmpq $0, core_limit(%rip)
 jne fail
 cmpq $0, core_limit+8(%rip)
 jne fail
 mov $14, %eax
 mov $2, %edi
 lea mask(%rip), %rsi
 xor %edx, %edx
 mov $8, %r10d
 syscall
 test %rax, %rax
 jne fail
 mov $57, %eax
 syscall
 test %rax, %rax
 js fail
 jz child
 mov %rax, %r13
 mov $128, %eax
 lea mask(%rip), %rdi
 lea info(%rip), %rsi
 lea timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $17, %rax
 jne fail
 cmpl $2, info+8(%rip)
 jne fail
 cmp %r13d, info+16(%rip)
 jne fail
 cmpl $6, info+24(%rip)
 jne fail
 mov $61, %eax
 mov %r13, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r13, %rax
 jne fail
 cmpl $6, status(%rip)
 jne fail
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 mov $39, %eax
 syscall
 mov %eax, %r12d
 mov $186, %eax
 syscall
 mov %eax, %esi
 mov %r12d, %edi
 mov $6, %edx
 mov $234, %eax
 syscall
 jmp fail
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
zero_core_limit: .quad 0, 0
core_limit: .quad -1, -1
mask: .quad 0x10000
timeout: .quad 1, 0
info: .zero 128
status: .quad 0
message: .ascii "A\n"
