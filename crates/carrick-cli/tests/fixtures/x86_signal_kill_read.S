# A ready child busy loop must terminate on SIGTERM; the harness bounds waits.
.global _start
.text
_start:
 mov $293, %eax
 lea ready(%rip), %rdi
 xor %esi, %esi
 syscall
 test %rax, %rax
 jne failed_80
 mov $293, %eax
 lea blocked(%rip), %rdi
 xor %esi, %esi
 syscall
 test %rax, %rax
 jne failed_81
 mov $57, %eax
 syscall
 test %rax, %rax
 js failed_82
 jz child
 mov %rax, %r12
 mov $0, %eax
 mov ready(%rip), %edi
 lea byte(%rip), %rsi
 mov $1, %edx
 syscall
 cmp $1, %rax
 jne failed_83
 mov $62, %eax
 mov %r12, %rdi
 mov $15, %esi
 syscall
 test %rax, %rax
 jne failed_84
 mov $61, %eax
 mov %r12, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r12, %rax
 jne failed_85
 cmpl $15, status(%rip)
 jne failed_86
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 mov $1, %eax
 mov ready+4(%rip), %edi
 lea byte(%rip), %rsi
 mov $1, %edx
 syscall
 mov $0, %eax
 mov blocked(%rip), %edi
 lea byte(%rip), %rsi
 mov $1, %edx
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
ready: .long 0, 0
blocked: .long 0, 0
status: .quad 0
byte: .byte 1
message: .ascii "K\n"
.text
failed_80:
 neg %rax
 mov %rax, %rdi
 jmp exit
failed_81:
 mov $81, %edi
 jmp exit
failed_82:
 mov $82, %edi
 jmp exit
failed_83:
 mov $83, %edi
 jmp exit
failed_84:
 mov $84, %edi
 jmp exit
failed_85:
 mov $85, %edi
 jmp exit
failed_86:
 mov $86, %edi
 jmp exit
