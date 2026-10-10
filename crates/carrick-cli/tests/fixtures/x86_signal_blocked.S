# Native oracle: a synchronous bad frame/fault must terminate with SIGSEGV.
.global _start
.text
_start:
 lea handler(%rip), %rax
 mov %rax, action(%rip)
 lea restorer(%rip), %rax
 mov %rax, action+16(%rip)
 mov $13, %eax
 mov $11, %edi
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
 test %rax, %rax
 jne fail
 mov $57, %eax
 syscall
 test %rax, %rax
 js fail
 jz child
 mov %rax, %r12
 mov $61, %eax
 mov %r12, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r12, %rax
 jne fail
 mov status(%rip), %eax
 and $0x7f, %eax
 cmp $11, %eax
 jne fail
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 mov $0x600000000000, %rax
 mov (%rax), %rax
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
handler:
 jmp fail
restorer:
 mov $15, %eax
 syscall
 ud2
.data
.align 8
action: .quad 0, 0x04000004, 0, 0
mask: .quad 0x400
status: .long 0
message: .ascii "F\n"
