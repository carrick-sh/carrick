/* Two live processes cross exec: successor signals its parent over an
 * inherited pipe, then waits for the parent's acknowledgement before exit.
 * The parent observes the successor, acknowledges it, and checks wait4. */
.global _start
.text
_start:
    lea ready(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    js failure
    lea ack(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %eax, %eax
    js failure
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov %eax, %r12d
    mov ready+4(%rip), %edi
    mov $3, %eax
    syscall
    test %eax, %eax
    js failure
    mov ready(%rip), %edi
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %eax
    jne failure
    cmpb $'X', byte(%rip)
    jne failure
    mov ack+4(%rip), %edi
    lea acknowledgement(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne failure
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    cmpl $0, status(%rip)
    jne failure
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $13, %edx
    mov $1, %eax
    syscall
    cmp $13, %eax
    jne failure
    xor %edi, %edi
    jmp exit
child:
    mov ready+4(%rip), %edi
    mov $9, %esi
    mov $33, %eax
    syscall
    cmp $9, %eax
    jne failure
    mov ack(%rip), %edi
    mov $8, %esi
    mov $33, %eax
    syscall
    cmp $8, %eax
    jne failure
    lea successor(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
successor: .asciz SUCCESSOR_PATH
.balign 8
argv: .quad successor, 0
acknowledgement: .ascii "A"
marker: .ascii "live-exec-ok\n"
.section .bss
.balign 4
ready: .space 8
ack: .space 8
status: .space 4
byte: .space 1
