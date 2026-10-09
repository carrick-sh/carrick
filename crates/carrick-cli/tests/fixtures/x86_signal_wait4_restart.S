# A caught signal interrupts an owned wait4 before its child can exit.
.global _start
.text
_start:
 lea handler(%rip), %rax
 mov %rax, action(%rip)
 lea restorer(%rip), %rax
 mov %rax, action+16(%rip)
 mov $13, %eax
 mov $10, %edi
 lea action(%rip), %rsi
 xor %edx, %edx
 mov $8, %r10d
 syscall
 test %rax, %rax
 jne fail
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
 mov $62, %eax
 mov %r12, %rdi
 mov $10, %esi
 syscall
 mov $128, %eax
 lea mask(%rip), %rdi
 xor %esi, %esi
 lea timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $12, %rax
 jne fail
 xor %edi, %edi
 jmp exit
handler:
 mov $62, %eax
 mov %r13, %rdi
 mov $12, %esi
 syscall
 ret
restorer:
 mov $15, %eax
 syscall
 ud2
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
action: .quad 0, 0x14000000, 0, 0
mask: .quad 0x800
timeout: .quad 1, 0
status: .quad 0
message: .ascii "R\n"
