# Three sequential fork/reap cycles must reuse retired child stock.
.global _start
.text
_start:
 mov $3, %r12d
again:
 mov $57, %eax
 syscall
 test %rax, %rax
 js failed_errno
 jz child
 mov %rax, %r13
 mov $61, %eax
 mov %r13, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r13, %rax
 jne failed
 cmpl $0, status(%rip)
 jne failed
 dec %r12d
 jnz again
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 xor %edi, %edi
 jmp exit
failed_errno:
 neg %rax
 mov %rax, %rdi
 jmp exit
failed:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
status: .quad 0
message: .ascii "R\n"
