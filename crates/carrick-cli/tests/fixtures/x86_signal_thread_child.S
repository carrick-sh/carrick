# One live child consumes three exact thread-targeted signals.
.global _start
.text
_start:
 mov $14, %eax
 mov $2, %edi
 lea mask(%rip), %rsi
 xor %edx, %edx
 mov $8, %r10d
 syscall
 mov $39, %eax
 syscall
 mov %rax, %r12
 mov $57, %eax
 syscall
 test %rax, %rax
 js fail
 jz child
 mov %rax, %r13
 mov $200, %eax
 mov %r13, %rdi
 mov $10, %esi
 syscall
 test %rax, %rax
 jne fail
 mov $234, %eax
 mov %r13, %rdi
 mov %r13, %rsi
 mov $12, %edx
 syscall
 test %rax, %rax
 jne fail
 mov $297, %eax
 mov %r13, %rdi
 mov %r13, %rsi
 mov $14, %edx
 lea queued(%rip), %r10
 syscall
 test %rax, %rax
 jne fail
 mov $61, %eax
 mov %r13, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r13, %rax
 jne fail
 cmpl $0, status(%rip)
 jne fail
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 mov $3, %r13d
wait:
 mov $128, %eax
 lea mask(%rip), %rdi
 lea info(%rip), %rsi
 lea timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $10, %rax
 je accepted
 cmp $12, %rax
 je accepted
 cmp $14, %rax
 jne fail
accepted:
 dec %r13d
 jnz wait
 xor %edi, %edi
 jmp exit
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
mask: .quad 0x2a00
timeout: .quad 1, 0
status: .quad 0
info: .zero 128
queued: .long 14, 0, -1, 0
.zero 112
message: .ascii "T\n"
