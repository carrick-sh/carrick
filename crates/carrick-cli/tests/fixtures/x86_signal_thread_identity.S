# Native oracle: signal zero checks an existing exact thread/process pair.
.global _start
.text
_start:
 mov $39, %eax
 syscall
 mov %rax, %r12
 mov $234, %eax
 mov %r12, %rdi
 mov %r12, %rsi
 xor %edx, %edx
 syscall
 test %rax, %rax
 jne failed_80
 mov $200, %eax
 mov $0x7fffffff, %edi
 xor %esi, %esi
 syscall
 cmp $-3, %rax
 jne failed_81
 mov $234, %eax
 xor %edi, %edi
 mov %r12, %rsi
 xor %edx, %edx
 syscall
 cmp $-22, %rax
 jne failed_82
 mov $234, %eax
 mov $0x7fffffff, %edi
 mov %r12, %rsi
 xor %edx, %edx
 syscall
 cmp $-3, %rax
 jne failed_83
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
message: .ascii "T\n"
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
