/*
 * Native-x86 Linux rt_sigframe xstate ownership regression.
 *
 * The interrupted context owns distinct x87, MXCSR, YMM1, and virtual PKRU
 * values. A SIGUSR1 handler clobbers all four and returns through an explicit
 * rt_sigreturn restorer. Correct signal-frame XSAVE restoration exits 37;
 * leaking handler state exits 1.
 */
.global _start
.type _start,@function
_start:
    lea handler(%rip), %rax
    mov %rax, action(%rip)
    mov $0x04000004, %rax            /* SA_RESTORER | SA_SIGINFO */
    mov %rax, action+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, action+16(%rip)
    movq $0, action+24(%rip)

    mov $13, %eax                    /* rt_sigaction */
    mov $10, %edi                    /* SIGUSR1 */
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d                    /* kernel sigset size */
    syscall
    test %rax, %rax
    jne fail

    lea inner_handler(%rip), %rax
    mov %rax, inner_action(%rip)
    movq $0x04000004, inner_action+8(%rip)
    lea restorer(%rip), %rax
    mov %rax, inner_action+16(%rip)
    movq $0, inner_action+24(%rip)
    mov $13, %eax                    /* rt_sigaction(SIGUSR2) */
    mov $12, %edi
    lea inner_action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne fail
    movb $0, nested_failed(%rip)

    movb $0, has_avx512(%rip)
    xor %ecx, %ecx
    xgetbv
    and $0xe6, %eax                  /* XMM/YMM/opmask/ZMM state enabled */
    cmp $0xe6, %eax
    jne 1f
    mov $7, %eax
    xor %ecx, %ecx
    cpuid
    bt $16, %ebx                    /* AVX512F */
    jnc 1f
    movb $1, has_avx512(%rip)
1:
    ldmxcsr interrupted_mxcsr(%rip)
    vmovdqu interrupted_ymm1(%rip), %ymm1
    cmpb $0, has_avx512(%rip)
    je 2f
    movabs $0x1122334455667788, %r11
    kmovq %r11, %k1
    vmovdqu64 interrupted_zmm2(%rip), %zmm2
    vmovdqu64 interrupted_zmm20(%rip), %zmm20
2:
    fld1
    xor %ecx, %ecx
    xor %edx, %edx
    mov $3, %eax                     /* virtual pkey-0 deny */
    wrpkru

    mov $39, %eax                    /* getpid */
    syscall
    mov %eax, %edi
    mov $10, %esi
    mov $62, %eax                    /* kill(self, SIGUSR1) */
    syscall
    test %rax, %rax
    jne fail_reset
    cmpb $0, nested_failed(%rip)
    jne fail_reset

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne fail_reset
    test %edx, %edx
    jne fail_reset
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    stmxcsr observed_mxcsr(%rip)
    mov observed_mxcsr(%rip), %eax
    cmp interrupted_mxcsr(%rip), %eax
    jne fail

    vmovdqu %ymm1, observed_ymm1(%rip)
    lea observed_ymm1(%rip), %rsi
    lea interrupted_ymm1(%rip), %rdi
    mov $32, %ecx
compare_ymm:
    movzbl (%rsi), %eax
    cmpb (%rdi), %al
    jne fail
    inc %rsi
    inc %rdi
    dec %ecx
    jne compare_ymm
    cmpb $0, has_avx512(%rip)
    je 3f
    kmovq %k1, %r11
    movabs $0x1122334455667788, %rax
    cmp %rax, %r11
    jne fail
    vmovdqu64 %zmm2, observed_zmm2(%rip)
    lea observed_zmm2(%rip), %rsi
    lea interrupted_zmm2(%rip), %rdi
    mov $64, %ecx
compare_zmm:
    movzbl (%rsi), %eax
    cmpb (%rdi), %al
    jne fail
    inc %rsi
    inc %rdi
    dec %ecx
    jne compare_zmm
    vpcmpeqd interrupted_zmm20(%rip), %zmm20, %k3
    kmovq %k3, %r11
    and $0xffff, %r11d
    cmp $0xffff, %r11d
    jne fail
3:
    fstpl observed_x87(%rip)
    mov observed_x87(%rip), %rax
    cmp expected_one(%rip), %rax
    jne fail

    /* Repeat through a synchronous divide fault. The SA_SIGINFO handler edits
     * the saved RIP in ucontext past the two-byte `div %ecx`. */
    lea fault_handler(%rip), %rax
    mov %rax, action(%rip)
    mov $13, %eax                    /* rt_sigaction(SIGFPE) */
    mov $8, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    test %rax, %rax
    jne fail

    ldmxcsr interrupted_mxcsr(%rip)
    vmovdqu interrupted_ymm1(%rip), %ymm1
    cmpb $0, has_avx512(%rip)
    je 4f
    movabs $0x1122334455667788, %r11
    kmovq %r11, %k1
    vmovdqu64 interrupted_zmm2(%rip), %zmm2
    vmovdqu64 interrupted_zmm20(%rip), %zmm20
4:
    fld1
    xor %ecx, %ecx
    xor %edx, %edx
    mov $3, %eax
    wrpkru
    mov $1, %eax
    xor %edx, %edx
    xor %ecx, %ecx
faulting_div:
    div %ecx                          /* f7 f1 */

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne fail_reset
    test %edx, %edx
    jne fail_reset
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    stmxcsr observed_mxcsr(%rip)
    mov observed_mxcsr(%rip), %eax
    cmp interrupted_mxcsr(%rip), %eax
    jne fail
    vmovdqu %ymm1, observed_ymm1(%rip)
    lea observed_ymm1(%rip), %rsi
    lea interrupted_ymm1(%rip), %rdi
    mov $32, %ecx
compare_fault_ymm:
    movzbl (%rsi), %eax
    cmpb (%rdi), %al
    jne fail
    inc %rsi
    inc %rdi
    dec %ecx
    jne compare_fault_ymm
    cmpb $0, has_avx512(%rip)
    je 5f
    kmovq %k1, %r11
    movabs $0x1122334455667788, %rax
    cmp %rax, %r11
    jne fail
    vmovdqu64 %zmm2, observed_zmm2(%rip)
    lea observed_zmm2(%rip), %rsi
    lea interrupted_zmm2(%rip), %rdi
    mov $64, %ecx
compare_fault_zmm:
    movzbl (%rsi), %eax
    cmpb (%rdi), %al
    jne fail
    inc %rsi
    inc %rdi
    dec %ecx
    jne compare_fault_zmm
    vpcmpeqd interrupted_zmm20(%rip), %zmm20, %k3
    kmovq %k3, %r11
    and $0xffff, %r11d
    cmp $0xffff, %r11d
    jne fail
5:
    fstpl observed_x87(%rip)
    mov observed_x87(%rip), %rax
    cmp expected_one(%rip), %rax
    jne fail

    mov $38, %edi                    /* base x87/MXCSR/YMM/PKRU path */
    cmpb $0, has_avx512(%rip)
    je 8f
    mov $37, %edi                    /* also restored K1/ZMM2 */
8:
    mov $231, %eax                   /* exit_group */
    syscall

fail_reset:
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
fail:
    mov $1, %edi
    mov $231, %eax
    syscall

.type handler,@function
handler:
    /* Outer-handler state B. The nested SIGUSR2 frame must restore this after
     * its handler writes a distinct state C. */
    ldmxcsr handler_mxcsr(%rip)
    vpxor %ymm1, %ymm1, %ymm1
    cmpb $0, has_avx512(%rip)
    je outer_no_avx512_seed
    kxord %k1, %k1, %k1
    vpxord %zmm2, %zmm2, %zmm2
    vpxord %zmm20, %zmm20, %zmm20
outer_no_avx512_seed:
    fstp %st(0)
    fldz
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    mov $39, %eax                    /* nested kill(self, SIGUSR2) */
    syscall
    mov %eax, %edi
    mov $12, %esi
    mov $62, %eax
    syscall
    test %rax, %rax
    jne outer_nested_bad

    stmxcsr observed_mxcsr(%rip)
    mov observed_mxcsr(%rip), %eax
    cmp handler_mxcsr(%rip), %eax
    jne outer_nested_bad
    vptest %ymm1, %ymm1
    jne outer_nested_bad
    xor %ecx, %ecx
    rdpkru
    test %eax, %eax
    jne outer_nested_bad
    test %edx, %edx
    jne outer_nested_bad
    cmpb $0, has_avx512(%rip)
    je outer_nested_x87
    kmovq %k1, %r11
    test %r11, %r11
    jne outer_nested_bad
    vptestmd %zmm2, %zmm2, %k2
    kortestq %k2, %k2
    jne outer_nested_bad
    vptestmd %zmm20, %zmm20, %k2
    kortestq %k2, %k2
    jne outer_nested_bad
outer_nested_x87:
    fstpl observed_x87(%rip)
    cmpq $0, observed_x87(%rip)
    jne outer_nested_bad
    ret
outer_nested_bad:
    movb $1, nested_failed(%rip)
    ret
.size handler, .-handler

.type inner_handler,@function
inner_handler:
    /* Inner-handler state C: every field differs from outer state B. */
    ldmxcsr interrupted_mxcsr(%rip)
    vpcmpeqd %ymm1, %ymm1, %ymm1
    cmpb $0, has_avx512(%rip)
    je inner_no_avx512
    movabs $0x1122334455667788, %r11
    kmovq %r11, %k1
    vmovdqu64 interrupted_zmm2(%rip), %zmm2
    vmovdqu64 interrupted_zmm20(%rip), %zmm20
inner_no_avx512:
    fstp %st(0)
    fld1
    xor %ecx, %ecx
    xor %edx, %edx
    mov $3, %eax
    wrpkru
    ret
.size inner_handler, .-inner_handler

.type fault_handler,@function
fault_handler:
    addq $2, 168(%rdx)               /* uc_mcontext.rip: skip `div %ecx` */
    ldmxcsr handler_mxcsr(%rip)
    vpxor %ymm1, %ymm1, %ymm1
    cmpb $0, has_avx512(%rip)
    je 7f
    kxord %k1, %k1, %k1
    vpxord %zmm2, %zmm2, %zmm2
    vpxord %zmm20, %zmm20, %zmm20
7:
    fstp %st(0)
    fldz
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    ret
.size fault_handler, .-fault_handler

.type restorer,@function
restorer:
    mov $15, %eax                    /* rt_sigreturn */
    syscall
.size restorer, .-restorer

.section .data
.balign 32
action:
    .quad 0, 0, 0, 0
inner_action:
    .quad 0, 0, 0, 0
nested_failed:
    .byte 0
.balign 32
interrupted_ymm1:
    .quad 0x0123456789abcdef, 0xfedcba9876543210
    .quad 0x0f1e2d3c4b5a6978, 0x8877665544332211
observed_ymm1:
    .zero 32
.balign 64
interrupted_zmm2:
    .quad 0x0102030405060708, 0x1112131415161718
    .quad 0x2122232425262728, 0x3132333435363738
    .quad 0x4142434445464748, 0x5152535455565758
    .quad 0x6162636465666768, 0x7172737475767778
observed_zmm2:
    .zero 64
interrupted_zmm20:
    .quad 0x91a2b3c4d5e6f708, 0x8192a3b4c5d6e7f8
    .quad 0x718293a4b5c6d7e8, 0x61728394a5b6c7d8
    .quad 0x5162738495a6b7c8, 0x415263748596a7b8
    .quad 0x31425364758697a8, 0x2132435465768798
has_avx512:
    .byte 0
.balign 4
interrupted_mxcsr:
    .long 0x00001f80
handler_mxcsr:
    .long 0x00003f80
observed_mxcsr:
    .long 0
expected_one:
    .quad 0x3ff0000000000000
observed_x87:
    .quad 0

.section .note.GNU-stack,"",@progbits
