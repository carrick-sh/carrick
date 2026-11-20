/* Root and fork child both run /hello; the live child then execs /successor.
 * The parent remains live in wait4 until its child's checks finish. */
.global _start
.text
_start:
#ifdef SUCCESSOR
    mov $220, %r13d
    call check_self_link
    call check_numeric_link
    mov $7, %edi
    jmp exit
#else
    mov $219, %r13d
    call check_self_link
    mov $57, %eax                 /* fork */
    syscall
    test %eax, %eax
    js process_failure
    jz child
    mov %eax, %r12d
    call check_self_link
    mov %r12d, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                 /* wait4 */
    syscall
    cmp %r12d, %eax
    jne process_failure
    mov status(%rip), %edi
    test $127, %edi
    jnz process_failure
    mov %edi, %r15d
    shr $8, %r15d
    call check_self_link
    mov %r15d, %edi
    jmp exit
child:
    mov $218, %r13d
    call check_self_link
    call check_numeric_link
    lea successor(%rip), %rdi
    lea successor_argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax                 /* execve */
    syscall
    mov $93, %edi
    jmp exit
process_failure:
    mov $92, %edi
    jmp exit
#endif

check_self_link:
    lea proc_exe(%rip), %r14
    jmp check_link

/* Write decimal getpid() backwards before the fixed "/exe" suffix. */
check_numeric_link:
    mov $39, %eax                 /* getpid */
    syscall
    test %eax, %eax
    jle wrong_link
    lea numeric_suffix(%rip), %r14
    mov $10, %ecx
1:
    xor %edx, %edx
    div %ecx
    add $'0', %dl
    dec %r14
    mov %dl, (%r14)
    test %eax, %eax
    jne 1b
    sub $6, %r14
    mov %r14, %rdi
    lea proc_exe(%rip), %rsi
    mov $6, %ecx
    rep movsb
    jmp check_link

check_link:
    lea buffer(%rip), %rdx
    movb $0x5a, expected_len(%rdx)
    mov $64, %r10d
    call readlink_exe
    cmp $expected_len, %rax
    jne wrong_link
    lea buffer(%rip), %rdi
    lea expected(%rip), %rsi
    mov $expected_len, %ecx
    repe cmpsb
    jne wrong_link
    cmpb $0x5a, (%rdi)
    jne wrong_link

    lea buffer(%rip), %rdx
    movl $0x5a5a5a5a, (%rdx)
    mov $3, %r10d
    call readlink_exe
    cmp $3, %rax
    jne wrong_truncation
    lea buffer(%rip), %rdi
    lea expected(%rip), %rsi
    mov $3, %ecx
    repe cmpsb
    jne wrong_truncation
    cmpb $0x5a, (%rdi)
    jne wrong_truncation
    ret

readlink_exe:
    mov $-100, %rdi               /* AT_FDCWD */
    mov %r14, %rsi
    mov $267, %eax                /* readlinkat */
    syscall
    cmp $-38, %rax
    je enosys
    ret
enosys:
    mov %r13d, %edi
    jmp exit
wrong_link:
    mov $94, %edi
    jmp exit
wrong_truncation:
    mov $95, %edi
exit:
    mov $231, %eax                /* exit_group */
    syscall
    ud2

.section .rodata
proc_exe: .asciz "/proc/self/exe"
#ifdef SUCCESSOR
expected: .ascii "/successor"
#else
expected: .ascii "/hello"
successor: .asciz "/successor"
.balign 8
successor_argv: .quad successor, 0
#endif
#ifdef SUCCESSOR
.set expected_len, 10
#else
.set expected_len, 6
#endif

.data
.space 16
numeric_suffix: .asciz "/exe"

.bss
.balign 4096
buffer: .space 64
status: .space 4
.section .note.GNU-stack,"",@progbits
