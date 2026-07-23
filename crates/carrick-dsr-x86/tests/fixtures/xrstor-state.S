/*
 * Checked native-x86 XRSTOR state-transfer fixture.
 *
 * The exact blocker instruction is emitted as bytes so its form cannot drift:
 *     0f ae 6c 24 40    xrstor 0x40(%rsp)
 *
 * It restores requested-present x87/YMM state from a standard image,
 * initializes requested-absent SSE state (both MXCSR and XMM), preserves
 * unrequested K/ZMM state when AVX-512 is available, and proves that
 * GPRs/RFLAGS/RSP/virtual PKRU are unchanged. Only the final exit_group enters
 * syscall dispatch. Exit 37 receipts executed AVX-512 checks; exit 38 receipts
 * the base-only path.
 */
.global _start
.type _start,@function
_start:
    /* Require the base AVX state used by this mandatory fixture. */
    mov $1, %eax
    xor %ecx, %ecx
    cpuid
    bt $27, %ecx                    /* OSXSAVE */
    jnc unsupported
    xor %ecx, %ecx
    xgetbv
    mov %eax, %r10d
    and $0x7, %r10d
    cmp $0x7, %r10d
    jne unsupported

    lea restore_image(%rip), %r12
    movq $5, 512(%r12)              /* XSTATE_BV: x87 + YMM, SSE absent */
    movq $0, 520(%r12)              /* standard format */
    movw $0x037f, 0(%r12)           /* FCW */
    movw $0, 2(%r12)                /* FSW: TOP=0 */
    movb $1, 4(%r12)                /* abridged FTW: ST0 present */
    movabs $0xc000000000000000, %rax /* 1.5 significand */
    mov %rax, 32(%r12)
    movw $0x3fff, 40(%r12)          /* 1.5 exponent/sign */

    /* Locate component 2 in the host's standard XSAVE geometry and populate
     * YMM1's upper 128 bits. */
    mov $0x0d, %eax
    mov $2, %ecx
    cpuid
    mov %ebx, %r13d
    lea (%r12,%r13), %r13
    movdqu source_ymm1_upper(%rip), %xmm0
    movdqu %xmm0, 16(%r13)

    movb $0, has_avx512(%rip)
    xor %ecx, %ecx
    xgetbv
    and $0xe6, %eax
    cmp $0xe6, %eax
    jne 1f
    mov $7, %eax
    xor %ecx, %ecx
    cpuid
    bt $16, %ebx                    /* AVX512F */
    jnc 1f
    movb $1, has_avx512(%rip)
1:
    /* Authoritative pre-XRSTOR guest state. SSE/YMM1 must be replaced or
     * initialized; K1/ZMM20 are unrequested and must survive. */
    vmovdqu current_ymm1(%rip), %ymm1
    ldmxcsr pre_xrstor_mxcsr(%rip)
    cmpb $0, has_avx512(%rip)
    je 2f
    movabs $0x1122334455667788, %r11
    kmovq %r11, %k1
    vmovdqu64 current_zmm20(%rip), %zmm20
2:
    fninit
    fldz

    /* Virtual PKRU must never be imported from the hardware XSAVE payload.
     * Value 3 would revoke host pkey-0 access if WRPKRU were executed directly. */
    mov $3, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    pushq $0xcd7
    popfq

    movabs $0x0000000000000207, %rax /* x87|SSE|YMM plus ignored PKRU request */
    movabs $0x1111111111111111, %rbx
    movabs $0x2222222222222222, %rcx
    xor %edx, %edx
    movabs $0x4444444444444444, %rsi
    movabs $0x5555555555555555, %rdi
    movabs $0x6666666666666666, %rbp
    movabs $0x8888888888888888, %r8
    movabs $0x9999999999999999, %r9
    movabs $0xaaaaaaaaaaaaaaaa, %r10
    movabs $0xbbbbbbbbbbbbbbbb, %r11
    movabs $0xcccccccccccccccc, %r12
    movabs $0xdddddddddddddddd, %r13
    movabs $0xeeeeeeeeeeeeeeee, %r14
    movabs $0xf0f0f0f0f0f0f0f0, %r15
    lea restore_image-0x40(%rip), %rsp
    pushfq
    popq expected_flags(%rip)

    mov %rax, expected_gprs+0(%rip)
    mov %rbx, expected_gprs+8(%rip)
    mov %rcx, expected_gprs+16(%rip)
    mov %rdx, expected_gprs+24(%rip)
    mov %rsi, expected_gprs+32(%rip)
    mov %rdi, expected_gprs+40(%rip)
    mov %rbp, expected_gprs+48(%rip)
    mov %rsp, expected_gprs+56(%rip)
    mov %r8, expected_gprs+64(%rip)
    mov %r9, expected_gprs+72(%rip)
    mov %r10, expected_gprs+80(%rip)
    mov %r11, expected_gprs+88(%rip)
    mov %r12, expected_gprs+96(%rip)
    mov %r13, expected_gprs+104(%rip)
    mov %r14, expected_gprs+112(%rip)
    mov %r15, expected_gprs+120(%rip)

xrstor_exact:
    .byte 0x0f,0xae,0x6c,0x24,0x40
xrstor_resume:
    mov %rax, observed_gprs+0(%rip)
    mov %rbx, observed_gprs+8(%rip)
    mov %rcx, observed_gprs+16(%rip)
    mov %rdx, observed_gprs+24(%rip)
    mov %rsi, observed_gprs+32(%rip)
    mov %rdi, observed_gprs+40(%rip)
    mov %rbp, observed_gprs+48(%rip)
    mov %rsp, observed_gprs+56(%rip)
    mov %r8, observed_gprs+64(%rip)
    mov %r9, observed_gprs+72(%rip)
    mov %r10, observed_gprs+80(%rip)
    mov %r11, observed_gprs+88(%rip)
    mov %r12, observed_gprs+96(%rip)
    mov %r13, observed_gprs+104(%rip)
    mov %r14, observed_gprs+112(%rip)
    mov %r15, observed_gprs+120(%rip)
    pushfq
    popq observed_flags(%rip)

    cld
    lea expected_gprs(%rip), %rsi
    lea observed_gprs(%rip), %rdi
    mov $16, %ecx
    repe cmpsq
    jne bad_gprs
    mov expected_flags(%rip), %rax
    cmp observed_flags(%rip), %rax
    jne bad_flags
    stmxcsr observed_mxcsr(%rip)
    cmpl $0x1f80, observed_mxcsr(%rip)
    jne bad_mxcsr

    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne bad_pkru
    test %edx, %edx
    jne bad_pkru
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    vmovdqu %ymm1, observed_ymm1(%rip)
    lea observed_ymm1(%rip), %rsi
    mov $16, %ecx
check_initialized_xmm1:
    cmpb $0, (%rsi)
    jne bad_sse
    inc %rsi
    dec %ecx
    jne check_initialized_xmm1
    lea observed_ymm1+16(%rip), %rsi
    lea source_ymm1_upper(%rip), %rdi
    mov $16, %ecx
check_restored_ymm1:
    movb (%rsi), %al
    cmpb (%rdi), %al
    jne bad_ymm
    inc %rsi
    inc %rdi
    dec %ecx
    jne check_restored_ymm1

    fstpt observed_x87(%rip)
    lea observed_x87(%rip), %rsi
    lea restore_image+32(%rip), %rdi
    mov $10, %ecx
check_restored_x87:
    movb (%rsi), %al
    cmpb (%rdi), %al
    jne bad_x87
    inc %rsi
    inc %rdi
    dec %ecx
    jne check_restored_x87

    cmpb $0, has_avx512(%rip)
    je success_base
    kmovq %k1, %r11
    movabs $0x1122334455667788, %rax
    cmp %rax, %r11
    jne bad_k
    vmovdqu64 %zmm20, observed_zmm20(%rip)
    lea observed_zmm20(%rip), %rsi
    lea current_zmm20(%rip), %rdi
    mov $64, %ecx
check_preserved_zmm20:
    movb (%rsi), %al
    cmpb (%rdi), %al
    jne bad_zmm
    inc %rsi
    inc %rdi
    dec %ecx
    jne check_preserved_zmm20

    mov $37, %edi                   /* K1/ZMM20 checks executed */
    jmp exit_group
success_base:
    mov $38, %edi                   /* host has no usable AVX-512 state */
    jmp exit_group
unsupported:
    mov $90, %edi
    jmp exit_group
bad_gprs:
    mov $101, %edi
    jmp exit_group
bad_flags:
    mov expected_flags(%rip), %rax
    xor observed_flags(%rip), %rax
    bsf %rax, %rdi
    add $120, %edi                 /* identify the first changed RFLAGS bit */
    jmp exit_group
bad_pkru:
    mov $103, %edi
    jmp reset_and_exit
bad_sse:
    mov $104, %edi
    jmp exit_group
bad_ymm:
    mov $105, %edi
    jmp exit_group
bad_x87:
    mov $106, %edi
    jmp exit_group
bad_k:
    mov $107, %edi
    jmp exit_group
bad_zmm:
    mov $108, %edi
    jmp exit_group
bad_mxcsr:
    mov $109, %edi
    jmp exit_group
reset_and_exit:
    push %rdi
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    pop %rdi
exit_group:
    mov $231, %eax
    syscall

.section .data
.balign 16
source_ymm1_upper:
    .quad 0x0123456789abcdef, 0xfedcba9876543210
current_ymm1:
    .quad 0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb
    .quad 0xcccccccccccccccc, 0xdddddddddddddddd
pre_xrstor_mxcsr:
    .long 0x3f80
observed_mxcsr:
    .long 0
.balign 64
current_zmm20:
    .quad 0x0102030405060708, 0x1112131415161718
    .quad 0x2122232425262728, 0x3132333435363738
    .quad 0x4142434445464748, 0x5152535455565758
    .quad 0x6162636465666768, 0x7172737475767778
has_avx512:
    .byte 0
.balign 8
expected_flags:
    .quad 0
observed_flags:
    .quad 0
expected_gprs:
    .zero 128
observed_gprs:
    .zero 128
.balign 32
observed_ymm1:
    .zero 32
.balign 64
observed_zmm20:
    .zero 64
.balign 16
observed_x87:
    .zero 16

.section .bss
.balign 64
restore_image:
    .skip 16384

.section .note.GNU-stack,"",@progbits
