/* A forked child execs the mounted ELF, then reads its host-backed bytes.
 * The parent stays alive in wait4 while the forward uses child identity. */
.global _start
.text
_start:
    cmpq $1, (%rsp)
    jne reader
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz spawn_reader
    mov %eax, %edi
    call wait_child
    mov $7, %edi
    jmp exit

spawn_reader:
    lea argv(%rip), %rsi
    lea path(%rip), %rdi
    xor %edx, %edx
    mov $59, %eax
    syscall
    mov $92, %edi
    jmp exit

reader:
    lea path(%rip), %rsi
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %eax, %eax
    js failure
    mov %eax, %r8d
    xor %edi, %edi
    mov $4096, %esi
    mov $1, %edx
    mov $2, %r10d
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js failure
    cmpl $0x464c457f, (%rax)
    jne failure
    mov $1, %edi
    lea output(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne failure
    xor %edi, %edi
    jmp exit

wait_child:
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    cmpl $0, status(%rip)
    jne failure
    ret

failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
path: .asciz "/hello"
marker: .asciz "child"
.balign 8
argv: .quad path, marker, 0
output: .ascii "F"

.section .bss
.balign 4
status: .space 4
