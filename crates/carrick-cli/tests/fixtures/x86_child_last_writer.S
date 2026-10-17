/* Round 1: parent waits in wait4 while the forked child writes to stdout on the
 * idle peer. Round 2: parent exits after forking while the second child is the
 * last stdout writer. The host reader must receive the child's byte and EOF. */
.global _start
.text
_start:
    /* Round 1: fork and wait4 while the child writes on the idle peer. */
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz first_child
    mov %eax, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    cmpl $0, status(%rip)
    jne failure

    /* Round 2: fork and exit immediately while the child is the last writer. */
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz second_child
    mov $7, %edi
    jmp exit

first_child:
    mov $1, %edi
    lea message(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    xor %edi, %edi
    jmp exit

second_child:
    mov $1, %edi
    lea message + 1(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    cmp $1, %eax
    jne child_failure
    xor %edi, %edi
    jmp exit

child_failure:
    mov $92, %edi
    jmp exit

failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
message: .ascii "E\n"

.section .bss
.balign 4
status: .space 4
