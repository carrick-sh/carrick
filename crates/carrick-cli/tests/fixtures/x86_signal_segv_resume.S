# A SIGSEGV handler fixes RIP and returns with independent RCX/R11 intact.
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
 mov $0x12345, %ecx
 mov $0x56789, %r11d
 xor %eax, %eax
fault:
 mov (%rax), %rax
fixed:
 cmp $0x12345, %rcx
 jne fail
 cmp $0x56789, %r11
 jne fail
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
handler:
 cmpl $1, 8(%rsi)
 jne fail
 lea fixed(%rip), %rax
 mov %rax, 168(%rdx)
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
action: .quad 0, 0x04000004, 0, 0
message: .ascii "S\n"
