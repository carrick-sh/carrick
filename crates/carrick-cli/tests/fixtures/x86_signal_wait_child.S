# Native oracle: suspension releases the executor and restores the old mask.
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
 jnz failed_80
 mov $14, %eax
 mov $2, %edi
 lea blocked(%rip), %rsi
 xor %edx, %edx
 mov $8, %r10d
 syscall
 mov $39, %eax
 syscall
 mov %rax, %r12
 mov $3, %r13d
again:
 mov $57, %eax
 syscall
 test %rax, %rax
 js failed_81
 jz child
 mov %rax, %r14
 mov $128, %eax
 lea waitset(%rip), %rdi
 lea info(%rip), %rsi
 lea timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $10, %rax
 jne wait_failed
 cmpl $10, info(%rip)
 jne failed_82
 mov $14, %eax
 xor %edi, %edi
 xor %esi, %esi
 lea observed(%rip), %rdx
 mov $8, %r10d
 syscall
 cmpq $0xa00, observed(%rip)
 jne failed_83
 mov $61, %eax
 mov %r14, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r14, %rax
 jne failed_84
 dec %r13d
 jnz again
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
 xor %edi, %edi
 jmp exit
handler:
 incq count(%rip)
 ret
restorer:
 mov $15, %eax
 syscall
 ud2
wait_failed:
 neg %rax
 mov %rax, %rdi
 jmp exit
fail:
 mov $99, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
action: .quad 0, 0x04000000, 0, 0
blocked: .quad 0xa00
temporary: .quad 0x800
observed: .quad 0
count: .quad 0
status: .quad 0
waitset: .quad 0x200
timeout: .quad 1, 0
info: .zero 128
message: .ascii "W\n"

.text
failed_80:
 mov $80, %edi
 jmp exit
failed_81:
 neg %rax
 mov %rax, %rdi
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
