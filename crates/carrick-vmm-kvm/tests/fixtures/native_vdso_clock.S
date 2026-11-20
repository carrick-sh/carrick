/*
 * Read AT_SYSINFO_EHDR from the initial stack and resolve __vdso_clock_gettime
 * by name. The root and native fork child each bracket a vDSO monotonic
 * sample between two raw syscall samples.
 * Exit values: 8 success, 218 missing auxv, 91 malformed or disagreeing clock.
 */
.global _start
.text
_start:
    mov (%rsp), %rcx
    lea 16(%rsp,%rcx,8), %rax
skip_env:
    add $8, %rax
    cmpq $0, -8(%rax)
    jne skip_env
aux:
    mov (%rax), %rcx
    test %rcx, %rcx
    jz missing
    cmp $33, %ecx
    je found
    add $16, %rax
    jmp aux
found:
    mov 8(%rax), %r15
    cmp $0, %r15
    je missing
    cmpl $0x464c457f, (%r15)
    jne failure
    cmpw $62, 18(%r15)
    jne failure
    lea gettime_symbol(%rip), %r10
    mov $21, %r11d
    call find_symbol
    mov %rax, %r14
    lea getres_symbol(%rip), %r10
    mov $20, %r11d
    call find_symbol
    mov %rax, %rbx
#ifdef EXEC_SUCCESSOR
    jmp child
#endif
    mov $57, %eax
    syscall
    test %rax, %rax
    js failure
    jz child
    mov %eax, %r12d
    call compare_samples
    sub $16, %rsp
    mov %r12d, %edi
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne failure
    mov (%rsp), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jmp exit
child:
    call compare_samples
    mov $8, %edi
    jmp exit
missing:
    mov $218, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2

find_symbol:
    mov 40(%r15), %r8
    add %r15, %r8
    movzwl 58(%r15), %r9d
    cmp $64, %r9d
    jne failure
    movzwl 60(%r15), %ecx
    mov %r8, %rdx
next_section:
    test %ecx, %ecx
    jz failure
    cmpl $11, 4(%rdx)
    je have_symtab
    add %r9, %rdx
    dec %ecx
    jmp next_section
have_symtab:
    cmpq $24, 56(%rdx)
    jne failure
    mov 40(%rdx), %eax
    shl $6, %rax
    add %r8, %rax
    mov 24(%rax), %r8
    add %r15, %r8
    mov 24(%rdx), %rax
    add %r15, %rax
    mov 32(%rdx), %r9
    add %rax, %r9
next_symbol:
    cmp %r9, %rax
    jae failure
    mov (%rax), %esi
    add %r8, %rsi
    mov %r10, %rdi
    mov %r11d, %ecx
    repe cmpsb
    je have_symbol
    add $24, %rax
    jmp next_symbol
have_symbol:
    mov 8(%rax), %rax
    add %r15, %rax
    ret

compare_samples:
    sub $56, %rsp
    mov %rsp, %rsi
    call raw_monotonic
    mov $1, %edi
    lea 16(%rsp), %rsi
    call *%r14
    test %rax, %rax
    jne failure
    lea 32(%rsp), %rsi
    call raw_monotonic
    mov 16(%rsp), %rax
    cmp (%rsp), %rax
    jb failure
    ja after_first
    mov 24(%rsp), %rdx
    cmp 8(%rsp), %rdx
    jb failure
after_first:
    cmp 32(%rsp), %rax
    ja failure
    jb ordered
    mov 24(%rsp), %rdx
    cmp 40(%rsp), %rdx
    ja failure
ordered:
    xor %edi, %edi
    mov %rsp, %rsi
    call *%r14
    test %rax, %rax
    jne failure
    cmpq $1600000000, (%rsp)
    jb failure
    cmpq $999999999, 8(%rsp)
    ja failure
    mov $1, %edi
    mov %rsp, %rsi
    call *%rbx
    test %rax, %rax
    jne failure
    mov $1, %edi
    lea 16(%rsp), %rsi
    mov $229, %eax
    syscall
    test %rax, %rax
    jne failure
    mov (%rsp), %rax
    cmp 16(%rsp), %rax
    jne failure
    mov 8(%rsp), %rax
    cmp 24(%rsp), %rax
    jne failure
    add $56, %rsp
    ret
raw_monotonic:
    mov $1, %edi
    mov $228, %eax
    syscall
    test %rax, %rax
    jne failure
    ret
.section .rodata
gettime_symbol:
    .asciz "__vdso_clock_gettime"
getres_symbol:
    .asciz "__vdso_clock_getres"
.section .note.GNU-stack,"",@progbits
