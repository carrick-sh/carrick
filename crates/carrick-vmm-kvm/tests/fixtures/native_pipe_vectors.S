/* #1756 native Linux oracle: exit 0, stdout "pipe-vectors=once\n".
 * Nonblocking pipe checks bound every I/O; wait4 reaps the finite child.
 * Both processes are alive when the child publishes scalar and vector writes.
 */
.global _start
.text
_start:
    mov $90, %r15d
    mov $293, %eax
    lea pipe_fds(%rip), %rdi
    mov $2048, %esi
    syscall
    test %eax, %eax
    jne failure
    mov $91, %r15d
    mov $57, %eax
    syscall
    test %eax, %eax
    js failure
    jz child
    mov $93, %r15d
    mov %eax, %r12d
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
    mov $99, %r15d
    /* Exercise scalar read independently of the readv below. */
    xor %eax, %eax
    mov pipe_fds(%rip), %edi
    lea output(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failure
    cmpb $0x21, output(%rip)
    jne failure
    mov $94, %r15d
    mov $19, %eax
    mov pipe_fds(%rip), %edi
    lea read_vectors(%rip), %rsi
    mov $2, %edx
    syscall
    cmp $6, %rax
    jne failure
    cmpw $0x6261, output(%rip)
    jne failure
    cmpl $0x66656463, output+2(%rip)
    jne failure
    mov $95, %r15d
    /* Parent still owns the write end: a duplicate/replayed write would
     * return bytes here; exactly-once delivery must return EAGAIN (11). */
    mov $0, %eax
    mov pipe_fds(%rip), %edi
    lea output(%rip), %rsi
    mov $6, %edx
    syscall
    cmp $-11, %rax
    jne failure
    mov $96, %r15d
    mov $3, %eax
    mov pipe_fds+4(%rip), %edi
    syscall
    test %eax, %eax
    jne failure
    mov $0, %eax
    mov pipe_fds(%rip), %edi
    lea output(%rip), %rsi
    mov $6, %edx
    syscall
    test %rax, %rax
    jne failure
    mov $98, %r15d
    mov $1, %eax
    mov $1, %edi
    lea success(%rip), %rsi
    mov $(success_end-success), %edx
    syscall
    cmp $(success_end-success), %rax
    jne failure
    xor %edi, %edi
    jmp exit
child:
    mov $97, %r15d
    /* A scalar prefix makes all four transfer calls part of this witness. */
    mov $1, %eax
    mov pipe_fds+4(%rip), %edi
    lea scalar(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne failure
    mov $92, %r15d
    mov $20, %eax
    mov pipe_fds+4(%rip), %edi
    lea write_vectors(%rip), %rsi
    mov $3, %edx
    syscall
    cmp $6, %rax
    jne failure
    xor %edi, %edi
    jmp exit
failure:
    mov %r15d, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.data
.balign 8
write_vectors:
    .quad first, 1, second, 2, third, 3
read_vectors:
    .quad output, 2, output+2, 4
first: .ascii "a"
scalar: .ascii "!"
second: .ascii "bc"
third: .ascii "def"
success: .ascii "pipe-vectors=once\n"
success_end:
.bss
.balign 4096
pipe_fds: .skip 8
status: .skip 4
output: .skip 6
