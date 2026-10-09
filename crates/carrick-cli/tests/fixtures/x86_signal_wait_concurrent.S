# Native oracle: two finite waits share a serving timer. The child's earlier
# timeout queues a blocked completion signal before the parent's timeout.
.global _start
.text
_start:
 mov $14, %eax
 mov $2, %edi
 lea blocked(%rip), %rsi
 xor %edx, %edx
 mov $8, %r10d
 syscall
 test %rax, %rax
 jne fail
 mov $39, %eax
 syscall
 mov %rax, %r12
 mov $57, %eax
 syscall
 test %rax, %rax
 js fail
 jz child
 mov %rax, %r13
 # Wait for child's admission handshake, bounded to one second.
 mov $128, %eax
 lea ready_set(%rip), %rdi
 xor %esi, %esi
 lea handshake_timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $12, %rax
 jne fail
 # Child parks for 100 ms; parent must actually park for 200 ms.
 mov $128, %eax
 lea wait_set(%rip), %rdi
 xor %esi, %esi
 lea parent_timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $-11, %rax
 jne fail
 mov $127, %eax
 lea pending(%rip), %rdi
 mov $8, %esi
 syscall
 test %rax, %rax
 jne fail
 testq $0x800, pending(%rip)
 jz fail
 # Receipt proves child reached its own deadline before the parent resumed.
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
 mov $12, %esi
 syscall
 test %rax, %rax
 jne fail
 mov $128, %eax
 lea wait_set(%rip), %rdi
 xor %esi, %esi
 lea child_timeout(%rip), %rdx
 mov $8, %r10d
 syscall
 cmp $-11, %rax
 jne fail
 mov $62, %eax
 mov %r12, %rdi
 mov $12, %esi
 syscall
 test %rax, %rax
 jne fail
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
blocked: .quad 0xa00
ready_set: .quad 0x800
wait_set: .quad 0x200
handshake_timeout: .quad 1, 0
child_timeout: .quad 0, 100000000
parent_timeout: .quad 0, 200000000
pending: .quad 0
status: .long 0
message: .ascii "T\n"
