# A child raises SIGABRT through its exact thread identity.
# CORE_ENABLED selects unlimited RLIMIT_CORE and requires an x86 ELF core.
.ifdef CORE_ENABLED
.equ EXPECTED_LIMIT, -1
.equ EXPECTED_CODE, 3
.equ EXPECTED_STATUS, 0x86
.else
.equ EXPECTED_LIMIT, 0
.equ EXPECTED_CODE, 2
.equ EXPECTED_STATUS, 6
.endif
.global _start
.text
_start:
 mov $90, %r15d
 # Set the limit in the fixture, not only in the host oracle launcher.
 mov $160, %eax
 mov $4, %edi
 lea requested_core_limit(%rip), %rsi
 syscall
 test %rax, %rax
 jne fail
 mov $91, %r15d
 # Both executions must enter the explicitly requested limit case.
 mov $97, %eax
 mov $4, %edi
 lea core_limit(%rip), %rsi
 syscall
 test %rax, %rax
 jne fail
 cmpq $EXPECTED_LIMIT, core_limit(%rip)
 jne fail
 cmpq $EXPECTED_LIMIT, core_limit+8(%rip)
 jne fail
 mov $92, %r15d
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
 mov $93, %r15d
 cmpl $EXPECTED_CODE, info+8(%rip)
 jne fail
 cmp %r13d, info+16(%rip)
 jne fail
 cmpl $6, info+24(%rip)
 jne fail
 mov $94, %r15d
 mov $61, %eax
 mov %r13, %rdi
 lea status(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 cmp %r13, %rax
 jne fail
 cmpl $EXPECTED_STATUS, status(%rip)
 jne fail
.ifdef CORE_ENABLED
 mov $95, %r15d
 # A core bit alone is insufficient: inspect the published file before exit.
 mov $257, %eax
 mov $-100, %edi
 lea core_path(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 syscall
 test %rax, %rax
 js fail
 mov %eax, %r14d
 mov %eax, %edi
 xor %eax, %eax
 lea core_header(%rip), %rsi
 mov $64, %edx
 syscall
 cmp $64, %rax
 jne fail
 mov $96, %r15d
 cmpl $0x464c457f, core_header(%rip)
 jne fail
 cmpb $2, core_header+4(%rip)
 jne fail
 cmpw $4, core_header+16(%rip)
 jne fail
 cmpw $62, core_header+18(%rip)
 jne fail
 mov $3, %eax
 mov %r14d, %edi
 syscall
 test %rax, %rax
 jne fail
.endif
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $2, %edx
 syscall
 mov $7, %edi
 jmp exit
child:
 mov $97, %r15d
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
 mov %r15d, %edi
exit:
 mov $231, %eax
 syscall
 ud2
.data
.align 8
requested_core_limit: .quad EXPECTED_LIMIT, EXPECTED_LIMIT
core_limit: .quad -1, -1
mask: .quad 0x10000
timeout: .quad 1, 0
info: .zero 128
status: .quad 0
message: .ascii "A\n"

.ifdef CORE_ENABLED
core_path: .asciz "core"
core_header: .zero 64
.endif
