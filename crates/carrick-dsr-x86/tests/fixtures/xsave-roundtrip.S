/*
 * Mandatory checked native-x86 XSAVE-family end-to-end fixture.
 *
 * All six user save forms are translated sensitive instructions.  The fixture
 * validates exact standard/compacted memory semantics and feeds one image of
 * each format back through translated XRSTOR64.  Exit 37 means the host's
 * CPUID+XCR0 AVX-512 path was exercised; exit 38 is the base x87/SSE/AVX path.
 * Only the final exit_group is a Linux syscall trap.
 */

.macro CAPTURE_GPRS target
    mov %rax, \target+0(%rip)
    mov %rbx, \target+8(%rip)
    mov %rcx, \target+16(%rip)
    mov %rdx, \target+24(%rip)
    mov %rsi, \target+32(%rip)
    mov %rdi, \target+40(%rip)
    mov %rbp, \target+48(%rip)
    mov %rsp, \target+56(%rip)
    mov %r8,  \target+64(%rip)
    mov %r9,  \target+72(%rip)
    mov %r10, \target+80(%rip)
    mov %r11, \target+88(%rip)
    mov %r12, \target+96(%rip)
    mov %r13, \target+104(%rip)
    mov %r14, \target+112(%rip)
    mov %r15, \target+120(%rip)
.endm

.global _start
.type _start,@function
_start:
    mov %rsp, program_rsp(%rip)

    /* XSAVE, OSXSAVE, x87/SSE/AVX, XSAVEOPT, and XSAVEC are mandatory. */
    mov $1, %eax
    xor %ecx, %ecx
    cpuid
    bt $26, %ecx
    jnc unsupported
    bt $27, %ecx
    jnc unsupported
    xor %ecx, %ecx
    xgetbv
    mov %eax, observed_xcr0(%rip)
    and $7, %eax
    cmp $7, %eax
    jne unsupported
    mov $0x0d, %eax
    mov $1, %ecx
    cpuid
    and $3, %eax
    cmp $3, %eax
    jne unsupported

    movq $7, safe_request(%rip)
    movb $0, has_avx512(%rip)
    mov observed_xcr0(%rip), %eax
    and $0xe6, %eax
    cmp $0xe6, %eax
    jne 1f
    mov $7, %eax
    xor %ecx, %ecx
    cpuid
    bt $16, %ebx                    /* AVX512F */
    jnc 1f
    movb $1, has_avx512(%rip)
    orq $0xe0, safe_request(%rip)   /* opmask + ZMM_Hi256 + Hi16_ZMM */
1:
    mov safe_request(%rip), %rax
    mov %rax, %rcx
    and $-2, %rcx                   /* keep non-REX forms portable to hosts
                                     * without FCS/FDS deprecation */
    mov %rcx, nonrex_safe_request(%rip)
    or $0x200, %rax                 /* hostile PKRU request: always ignored */
    mov %rax, hostile_request(%rip)
    or $0x200, %rcx
    mov %rcx, nonrex_hostile_request(%rip)

    /* Runtime geometry is discovered from the same virtualized CPUID surface
     * used by the checked save/restore service. */
    mov $0x0d, %eax
    mov $2, %ecx
    cpuid
    mov %ebx, standard_offset2(%rip)
    mov %eax, component_size2(%rip)
    movq $576, compact_offset2(%rip)
    mov %eax, %eax
    add $576, %rax
    mov %rax, compact_cursor(%rip)

    cmpb $0, has_avx512(%rip)
    je 2f
    mov $5, %edi
    call record_avx512_component
    mov $6, %edi
    call record_avx512_component
    mov $7, %edi
    call record_avx512_component
2:
    fxsave64 layout_probe(%rip)
    mov layout_probe+28(%rip), %eax
    test %eax, %eax
    jne 3f
    mov $0x0000ffbf, %eax           /* architectural fallback for old CPUs */
3:
    mov %eax, mxcsr_mask(%rip)
    mov %eax, %ecx
    and $0x0000a040, %ecx           /* rounding plus host-valid DAZ/FZ bits */
    mov $0x1f80, %eax
    or %ecx, %eax
    and mxcsr_mask(%rip), %eax
    mov %eax, live_mxcsr(%rip)
    cmp $0x1f80, %eax
    je unsupported                  /* live MXCSR must be observably non-default */

    /* Virtual PKRU is independent of the hardware XSAVE image.  Value 3 would
     * revoke host key-zero access if Carrick leaked it to physical PKRU. */
    mov $3, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru

    /* Standard live image: exact RSP+disp XSAVE64 form plus complete scalar
     * preservation.  The zeroed header makes this image legal XRSTOR input. */
    lea standard_roundtrip(%rip), %rdi
    mov $0xa5, %al
    call fill_image
    lea standard_roundtrip(%rip), %rdi
    call zero_header
    call seed_live_state
    lea standard_roundtrip(%rip), %rax
    mov %rax, operand_ptr(%rip)
    movq $0, expected_xcomp(%rip)
    movb $0, header_tail_fill(%rip)
    movb $0, expect_pointer_gaps(%rip)
    movb $1, expect_x87_payload(%rip)
    call prepare_preservation
    lea standard_roundtrip-0x40(%rip), %rsp
    mov %rsp, expected_gprs+56(%rip)
standard_xsave64_rsp_disp:
    xsave64 0x40(%rsp)
    CAPTURE_GPRS observed_gprs
    pushfq
    popq observed_flags(%rip)
    mov program_rsp(%rip), %rsp
    call verify_preservation
    mov safe_request(%rip), %rax
    mov %rax, expected_bv(%rip)
    lea standard_roundtrip(%rip), %r12
    call verify_standard_live
    call verify_virtual_pkru

    /* Restore that standard image after installing deliberately different
     * live state.  XRSTOR64 must preserve every scalar and virtual PKRU. */
    call clobber_live_state
    lea standard_roundtrip(%rip), %rax
    mov %rax, operand_ptr(%rip)
    call prepare_preservation
standard_xrstor64:
    xrstor64 (%r12)
    CAPTURE_GPRS observed_gprs
    pushfq
    popq observed_flags(%rip)
    call verify_preservation
    call verify_live_state
    call verify_virtual_pkru

    /* Plain non-REX XSAVE: old-XSTATE_BV read/modify/write, XCOMP and every
     * reserved/gap sentinel untouched, and hostile bit 9 retained only as an
     * unrequested old header bit (never imported from guest/host PKRU). */
    lea standard_rmw(%rip), %rdi
    mov $0xa5, %al
    call fill_image
    movq $0x200, standard_rmw+512(%rip)
    movabs $0x55aa0123456789ab, %rax
    mov %rax, standard_rmw+520(%rip)
    call seed_live_state
    mov nonrex_hostile_request(%rip), %rax
    xor %edx, %edx
    lea standard_rmw(%rip), %r12
standard_xsave:
    xsave (%r12)
    mov nonrex_safe_request(%rip), %rax
    or $0x200, %rax
    mov %rax, expected_bv(%rip)
    movabs $0x55aa0123456789ab, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0xa5, header_tail_fill(%rip)
    movb $1, expect_pointer_gaps(%rip)
    movb $0, expect_x87_payload(%rip)
    call verify_standard_live
    call verify_virtual_pkru

    /* Plain XSAVE64 must materialize architectural initial payload for every
     * requested component even though XSTATE_BV says those components are in
     * initial state. */
    lea standard_initial(%rip), %rdi
    mov $0xc7, %al
    call fill_image
    mov safe_request(%rip), %rax
    or $0x200, %rax
    mov %rax, standard_initial+512(%rip)
    movabs $0x1122334455667788, %rax
    mov %rax, standard_initial+520(%rip)
    call seed_initial_state
    mov hostile_request(%rip), %rax
    xor %edx, %edx
    lea standard_initial(%rip), %r12
standard_initial_xsave64:
    xsave64 (%r12)
    movq $0x200, expected_bv(%rip)
    movabs $0x1122334455667788, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0xc7, header_tail_fill(%rip)
    movb $0, expect_pointer_gaps(%rip)
    movb $0xc7, image_fill(%rip)
    call verify_standard_initial

    /* XSAVEOPT omits all initial x87/XMM/extended payload while still writing
     * MXCSR, MXCSR_MASK, and the standard RMW XSTATE_BV. */
    lea optimized_initial(%rip), %rdi
    mov $0xd1, %al
    call fill_image
    mov nonrex_safe_request(%rip), %rax
    or $0x200, %rax
    mov %rax, optimized_initial+512(%rip)
    movabs $0x99aabbccddeeff00, %rax
    mov %rax, optimized_initial+520(%rip)
    call seed_initial_state
    mov nonrex_hostile_request(%rip), %rax
    xor %edx, %edx
    lea optimized_initial(%rip), %r12
standard_xsaveopt:
    xsaveopt (%r12)
    movq $0x200, expected_bv(%rip)
    movabs $0x99aabbccddeeff00, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0xd1, header_tail_fill(%rip)
    movb $0xd1, image_fill(%rip)
    call verify_xsaveopt_initial_omission

    /* REX.W XSAVEOPT64 with live state supplies the second optimized form. */
    lea optimized_live(%rip), %rdi
    mov $0xb6, %al
    call fill_image
    movq $0, optimized_live+512(%rip)
    movabs $0x7766554433221100, %rax
    mov %rax, optimized_live+520(%rip)
    call seed_live_state
    mov hostile_request(%rip), %rax
    xor %edx, %edx
    lea optimized_live(%rip), %r12
standard_xsaveopt64:
    xsaveopt64 (%r12)
    mov safe_request(%rip), %rax
    mov %rax, expected_bv(%rip)
    movabs $0x7766554433221100, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0xb6, header_tail_fill(%rip)
    movb $0, expect_pointer_gaps(%rip)
    movb $1, expect_x87_payload(%rip)
    movb $0xb6, image_fill(%rip)
    call verify_standard_live

    /* Non-REX XSAVEC is exercised without requesting x87 because this host
     * does not advertise architectural FCS/FDS deprecation.  All requested
     * SSE/AVX(/AVX-512) compacted payload and layout checks still execute. */
    lea compact_roundtrip(%rip), %rdi
    mov $0xe3, %al
    call fill_image
    call seed_live_state
    mov nonrex_hostile_request(%rip), %rax
    xor %edx, %edx
    lea compact_roundtrip(%rip), %r12
compacted_xsavec:
    xsavec (%r12)
    mov nonrex_safe_request(%rip), %rax
    mov %rax, expected_bv(%rip)
    bts $63, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0xe3, header_tail_fill(%rip)
    movb $1, expect_pointer_gaps(%rip)
    movb $0, expect_x87_payload(%rip)
    movb $0xe3, image_fill(%rip)
    call verify_compacted_live

    /* REX.W XSAVEC64 carries the complete state and produces the compacted
     * image that is fed through emulated XRSTOR64. */
    lea compact_live64(%rip), %rdi
    mov $0x6d, %al
    call fill_image
    lea compact_live64(%rip), %rdi
    call zero_header_tail
    call seed_live_state
    mov hostile_request(%rip), %rax
    xor %edx, %edx
    lea compact_live64(%rip), %r12
compacted_xsavec64:
    xsavec64 (%r12)
    mov safe_request(%rip), %rax
    mov %rax, expected_bv(%rip)
    bts $63, %rax
    mov %rax, expected_xcomp(%rip)
    movb $0, header_tail_fill(%rip)
    movb $0, expect_pointer_gaps(%rip)
    movb $1, expect_x87_payload(%rip)
    movb $0x6d, image_fill(%rip)
    call verify_compacted_live

    call clobber_live_state
    lea compact_live64(%rip), %rax
    mov %rax, operand_ptr(%rip)
    call prepare_preservation
compacted_xrstor64:
    xrstor64 (%r12)
    CAPTURE_GPRS observed_gprs
    pushfq
    popq observed_flags(%rip)
    call verify_preservation
    call verify_live_state
    call verify_virtual_pkru

    cmpb $0, has_avx512(%rip)
    je success_base
    mov $37, %edi
    jmp reset_and_exit
success_base:
    mov $38, %edi
    jmp reset_and_exit

/* Record CPUID.(D,component) standard and compacted geometry. */
.type record_avx512_component,@function
record_avx512_component:
    mov $0x0d, %eax
    mov %edi, %ecx
    cpuid
    cmp $5, %edi
    je 4f
    cmp $6, %edi
    je 5f
    mov %ebx, standard_offset7(%rip)
    mov %eax, component_size7(%rip)
    jmp 6f
4:
    mov %ebx, standard_offset5(%rip)
    mov %eax, component_size5(%rip)
    jmp 6f
5:
    mov %ebx, standard_offset6(%rip)
    mov %eax, component_size6(%rip)
6:
    mov compact_cursor(%rip), %r8
    test $2, %ecx                    /* CPUID.D.n: compacted 64-byte alignment */
    je 7f
    add $63, %r8
    and $-64, %r8
7:
    cmp $5, %edi
    je 8f
    cmp $6, %edi
    je 9f
    mov %r8, compact_offset7(%rip)
    jmp 10f
8:
    mov %r8, compact_offset5(%rip)
    jmp 10f
9:
    mov %r8, compact_offset6(%rip)
10:
    mov %eax, %eax
    add %rax, %r8
    mov %r8, compact_cursor(%rip)
    ret

.type fill_image,@function
fill_image:
    mov $16384, %ecx
    cld
    rep stosb
    ret

.type zero_header,@function
zero_header:
    add $512, %rdi
    xor %eax, %eax
    mov $64, %ecx
    cld
    rep stosb
    ret

.type zero_header_tail,@function
zero_header_tail:
    add $528, %rdi
    xor %eax, %eax
    mov $48, %ecx
    cld
    rep stosb
    ret

.type seed_live_state,@function
seed_live_state:
    fninit
    fldt seed_x87(%rip)
    ldmxcsr live_mxcsr(%rip)
    vmovdqu seed_ymm1(%rip), %ymm1
    cmpb $0, has_avx512(%rip)
    je 11f
    movabs $0x1122334455667788, %rax
    kmovq %rax, %k1
    vmovdqu64 seed_zmm2(%rip), %zmm2
    vmovdqu64 seed_zmm20(%rip), %zmm20
11:
    ret

.type seed_initial_state,@function
seed_initial_state:
    /* An empty standard image initializes every requested component and clears
     * its authoritative XSTATE_BV bit.  Using the emulated restore path avoids
     * host XINUSE bookkeeping differences after FNINIT/VZEROALL. */
    mov hostile_request(%rip), %rax
    xor %edx, %edx
    lea initial_source(%rip), %r11
    xrstor64 (%r11)
    ret

.type clobber_live_state,@function
clobber_live_state:
    fninit
    fldz
    ldmxcsr initial_mxcsr(%rip)
    vpxor %ymm1, %ymm1, %ymm1
    cmpb $0, has_avx512(%rip)
    je 13f
    kxorq %k1, %k1, %k1
    vpxord %zmm2, %zmm2, %zmm2
    vpxord %zmm20, %zmm20, %zmm20
13:
    ret

/* Install distinctive scalar state.  R12 is the operand pointer; RAX/RDX are
 * necessarily the architectural request.  The call/ret pair preserves flags,
 * and expected RSP accounts for the pending return address. */
.type prepare_preservation,@function
prepare_preservation:
    mov hostile_request(%rip), %rax
    movabs $0x1111111111111111, %rbx
    movabs $0x2222222222222222, %rcx
    xor %edx, %edx
    movabs $0x4444444444444444, %rsi
    movabs $0x5555555555555555, %rdi
    movabs $0x6666666666666666, %rbp
    movabs $0x8888888888888888, %r8
    movabs $0x9999999999999999, %r9
    movabs $0xaaaaaaaaaaaaaaaa, %r10
    mov operand_ptr(%rip), %r12
    movabs $0xdddddddddddddddd, %r13
    movabs $0xeeeeeeeeeeeeeeee, %r14
    movabs $0xf0f0f0f0f0f0f0f0, %r15
    lea 8(%rsp), %r11
    mov %r11, expected_gprs+56(%rip)
    movabs $0xbbbbbbbbbbbbbbbb, %r11
    CAPTURE_GPRS expected_gprs
    /* CAPTURE stored the in-function RSP; restore the post-return expectation. */
    lea 8(%rsp), %r10
    mov %r10, expected_gprs+56(%rip)
    movabs $0xaaaaaaaaaaaaaaaa, %r10
    pushq $0xcd7
    popfq
    pushfq
    popq expected_flags(%rip)
    ret

.type verify_preservation,@function
verify_preservation:
    cld
    lea expected_gprs(%rip), %rsi
    lea observed_gprs(%rip), %rdi
    mov $16, %ecx
    repe cmpsq
    jne bad_gprs
    mov expected_flags(%rip), %rax
    cmp observed_flags(%rip), %rax
    jne bad_flags
    ret

.type compare_bytes,@function
compare_bytes:
    cld
    repe cmpsb
    ret

/* R12 names a standard-format image; expected header values and sentinel
 * policy are supplied in globals. */
.type verify_standard_live,@function
verify_standard_live:
    mov 512(%r12), %rax
    cmp expected_bv(%rip), %rax
    jne bad_standard_header
    mov 520(%r12), %rax
    cmp expected_xcomp(%rip), %rax
    jne bad_standard_xcomp
    mov 24(%r12), %eax
    cmp live_mxcsr(%rip), %eax
    jne bad_mxcsr
    mov 28(%r12), %eax
    cmp mxcsr_mask(%rip), %eax
    jne bad_mxcsr_mask
    cmpb $0, expect_x87_payload(%rip)
    je 32f
    lea 32(%r12), %rsi
    lea seed_x87(%rip), %rdi
    mov $10, %ecx
    call compare_bytes
    jne bad_x87
    jmp 33f
32:
    lea 0(%r12), %rdi
    mov $5, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_x87
    lea 32(%r12), %rdi
    mov $128, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_x87
33:
    lea 176(%r12), %rsi
    lea seed_ymm1(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_ymm
    mov standard_offset2(%rip), %rax
    lea 16(%r12,%rax), %rsi
    lea seed_ymm1+16(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_ymm
    cmpb $0, has_avx512(%rip)
    je 14f
    lea 192(%r12), %rsi
    lea seed_zmm2(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_zmm
    mov standard_offset2(%rip), %rax
    lea 32(%r12,%rax), %rsi
    lea seed_zmm2+16(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_zmm
    mov standard_offset5(%rip), %rax
    lea 8(%r12,%rax), %rax
    movabs $0x1122334455667788, %rcx
    cmp %rcx, (%rax)
    jne bad_k
    mov standard_offset6(%rip), %rax
    lea 64(%r12,%rax), %rsi
    lea seed_zmm2+32(%rip), %rdi
    mov $32, %ecx
    call compare_bytes
    jne bad_zmm
    mov standard_offset7(%rip), %rax
    lea 256(%r12,%rax), %rsi
    lea seed_zmm20(%rip), %rdi
    mov $64, %ecx
    call compare_bytes
    jne bad_zmm
14:
    call verify_legacy_and_standard_gaps
    ret

.type verify_standard_initial,@function
verify_standard_initial:
    mov 512(%r12), %rax
    cmp expected_bv(%rip), %rax
    jne bad_initial_header
    mov 520(%r12), %rax
    cmp expected_xcomp(%rip), %rax
    jne bad_standard_xcomp
    cmpw $0x037f, 0(%r12)
    jne bad_initial_payload
    cmpw $0, 2(%r12)
    jne bad_initial_payload
    cmpb $0, 4(%r12)
    jne bad_initial_payload
    lea 32(%r12), %rdi
    mov $128, %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
    cmpl $0x1f80, 24(%r12)
    jne bad_initial_payload
    mov 28(%r12), %eax
    cmp mxcsr_mask(%rip), %eax
    jne bad_mxcsr_mask
    lea 160(%r12), %rdi
    mov $256, %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
    mov standard_offset2(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size2(%rip), %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
    cmpb $0, has_avx512(%rip)
    je 15f
    mov standard_offset5(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size5(%rip), %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
    mov standard_offset6(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size6(%rip), %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
    mov standard_offset7(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size7(%rip), %ecx
    xor %eax, %eax
    call check_fill
    jne bad_initial_payload
15:
    call verify_legacy_and_standard_gaps
    ret

.type verify_xsaveopt_initial_omission,@function
verify_xsaveopt_initial_omission:
    mov 512(%r12), %rax
    cmp expected_bv(%rip), %rax
    jne bad_optimized_header
    mov 520(%r12), %rax
    cmp expected_xcomp(%rip), %rax
    jne bad_standard_xcomp
    lea 0(%r12), %rdi
    mov $5, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    lea 32(%r12), %rdi
    mov $128, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    cmpl $0x1f80, 24(%r12)
    jne bad_optimized_payload
    mov 28(%r12), %eax
    cmp mxcsr_mask(%rip), %eax
    jne bad_mxcsr_mask
    lea 160(%r12), %rdi
    mov $256, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    mov standard_offset2(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size2(%rip), %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    cmpb $0, has_avx512(%rip)
    je 16f
    mov standard_offset5(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size5(%rip), %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    mov standard_offset6(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size6(%rip), %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
    mov standard_offset7(%rip), %rax
    lea (%r12,%rax), %rdi
    mov component_size7(%rip), %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_optimized_payload
16:
    ret

.type verify_compacted_live,@function
verify_compacted_live:
    mov 512(%r12), %rax
    cmp expected_bv(%rip), %rax
    jne bad_compact_header
    mov 520(%r12), %rax
    cmp expected_xcomp(%rip), %rax
    jne bad_compact_header
    mov 24(%r12), %eax
    cmp live_mxcsr(%rip), %eax
    jne bad_mxcsr
    mov 28(%r12), %eax
    cmp mxcsr_mask(%rip), %eax
    jne bad_mxcsr_mask
    cmpb $0, expect_x87_payload(%rip)
    je 34f
    lea 32(%r12), %rsi
    lea seed_x87(%rip), %rdi
    mov $10, %ecx
    call compare_bytes
    jne bad_x87
    jmp 35f
34:
    lea 0(%r12), %rdi
    mov $5, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_x87
    lea 32(%r12), %rdi
    mov $128, %ecx
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_x87
35:
    lea 176(%r12), %rsi
    lea seed_ymm1(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_ymm
    mov compact_offset2(%rip), %rax
    lea 16(%r12,%rax), %rsi
    lea seed_ymm1+16(%rip), %rdi
    mov $16, %ecx
    call compare_bytes
    jne bad_ymm
    cmpb $0, has_avx512(%rip)
    je 17f
    mov compact_offset5(%rip), %rax
    lea 8(%r12,%rax), %rax
    movabs $0x1122334455667788, %rcx
    cmp %rcx, (%rax)
    jne bad_k
    mov compact_offset6(%rip), %rax
    lea 64(%r12,%rax), %rsi
    lea seed_zmm2+32(%rip), %rdi
    mov $32, %ecx
    call compare_bytes
    jne bad_zmm
    mov compact_offset7(%rip), %rax
    lea 256(%r12,%rax), %rsi
    lea seed_zmm20(%rip), %rdi
    mov $64, %ecx
    call compare_bytes
    jne bad_zmm
17:
    call verify_legacy_and_compacted_gaps
    ret

.type verify_live_state,@function
verify_live_state:
    stmxcsr observed_mxcsr(%rip)
    mov observed_mxcsr(%rip), %eax
    cmp live_mxcsr(%rip), %eax
    jne bad_roundtrip_state
    vmovdqu %ymm1, observed_ymm1(%rip)
    lea observed_ymm1(%rip), %rsi
    lea seed_ymm1(%rip), %rdi
    mov $32, %ecx
    call compare_bytes
    jne bad_roundtrip_state
    fstpt observed_x87(%rip)
    lea observed_x87(%rip), %rsi
    lea seed_x87(%rip), %rdi
    mov $10, %ecx
    call compare_bytes
    jne bad_roundtrip_state
    cmpb $0, has_avx512(%rip)
    je 18f
    kmovq %k1, %rax
    movabs $0x1122334455667788, %rcx
    cmp %rcx, %rax
    jne bad_roundtrip_state
    vmovdqu64 %zmm2, observed_zmm2(%rip)
    lea observed_zmm2(%rip), %rsi
    lea seed_zmm2(%rip), %rdi
    mov $64, %ecx
    call compare_bytes
    jne bad_roundtrip_state
    vmovdqu64 %zmm20, observed_zmm20(%rip)
    lea observed_zmm20(%rip), %rsi
    lea seed_zmm20(%rip), %rdi
    mov $64, %ecx
    call compare_bytes
    jne bad_roundtrip_state
18:
    ret

.type verify_virtual_pkru,@function
verify_virtual_pkru:
    xor %ecx, %ecx
    rdpkru
    cmp $3, %eax
    jne bad_pkru
    test %edx, %edx
    jne bad_pkru
    ret

/* Verify bytes that no save form owns. */
.type verify_legacy_and_standard_gaps,@function
verify_legacy_and_standard_gaps:
    movzbl image_fill(%rip), %eax
    lea 5(%r12), %rdi
    mov $1, %ecx
    call check_fill
    jne bad_reserved
    cmpb $0, expect_pointer_gaps(%rip)
    je 19f
    movzbl image_fill(%rip), %eax
    lea 14(%r12), %rdi
    mov $2, %ecx
    call check_fill
    jne bad_reserved
    movzbl image_fill(%rip), %eax
    lea 22(%r12), %rdi
    mov $2, %ecx
    call check_fill
    jne bad_reserved
19:
    movzbl image_fill(%rip), %eax
    lea 416(%r12), %rdi
    mov $96, %ecx
    call check_fill
    jne bad_reserved
    movzbl header_tail_fill(%rip), %eax
    lea 528(%r12), %rdi
    mov $48, %ecx
    call check_fill
    jne bad_reserved
    mov standard_offset2(%rip), %rax
    add component_size2(%rip), %rax
    mov %rax, %rdi
    cmpb $0, has_avx512(%rip)
    je 20f
    mov standard_offset5(%rip), %rcx
    jmp 21f
20:
    lea 32(%rax), %rcx
21:
    sub %rdi, %rcx
    jbe 22f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
22:
    cmpb $0, has_avx512(%rip)
    je 25f
    mov standard_offset5(%rip), %rdi
    add component_size5(%rip), %rdi
    mov standard_offset6(%rip), %rcx
    sub %rdi, %rcx
    jbe 23f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
23:
    mov standard_offset6(%rip), %rdi
    add component_size6(%rip), %rdi
    mov standard_offset7(%rip), %rcx
    sub %rdi, %rcx
    jbe 25f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
25:
    ret

.type verify_legacy_and_compacted_gaps,@function
verify_legacy_and_compacted_gaps:
    /* Legacy and header reserved ranges share the standard checker, but its
     * component-gap walk is not applicable to compacted destinations. */
    movzbl image_fill(%rip), %eax
    lea 5(%r12), %rdi
    mov $1, %ecx
    call check_fill
    jne bad_reserved
    cmpb $0, expect_pointer_gaps(%rip)
    je 26f
    movzbl image_fill(%rip), %eax
    lea 14(%r12), %rdi
    mov $2, %ecx
    call check_fill
    jne bad_reserved
    movzbl image_fill(%rip), %eax
    lea 22(%r12), %rdi
    mov $2, %ecx
    call check_fill
    jne bad_reserved
26:
    movzbl image_fill(%rip), %eax
    lea 416(%r12), %rdi
    mov $96, %ecx
    call check_fill
    jne bad_reserved
    movzbl header_tail_fill(%rip), %eax
    lea 528(%r12), %rdi
    mov $48, %ecx
    call check_fill
    jne bad_reserved
    cmpb $0, has_avx512(%rip)
    je 29f
    mov compact_offset2(%rip), %rdi
    add component_size2(%rip), %rdi
    mov compact_offset5(%rip), %rcx
    sub %rdi, %rcx
    jbe 27f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
27:
    mov compact_offset5(%rip), %rdi
    add component_size5(%rip), %rdi
    mov compact_offset6(%rip), %rcx
    sub %rdi, %rcx
    jbe 28f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
28:
    mov compact_offset6(%rip), %rdi
    add component_size6(%rip), %rdi
    mov compact_offset7(%rip), %rcx
    sub %rdi, %rcx
    jbe 29f
    add %r12, %rdi
    movzbl image_fill(%rip), %eax
    call check_fill
    jne bad_reserved
29:
    ret

/* RDI=start, RCX=len, AL=expected.  Returns ZF=1 iff every byte matches. */
.type check_fill,@function
check_fill:
    test %rcx, %rcx
    je 31f
30:
    cmp %al, (%rdi)
    jne 31f
    inc %rdi
    dec %rcx
    jne 30b
31:
    ret

unsupported:
    mov $90, %edi
    jmp exit_group
bad_gprs:
    mov $101, %edi
    jmp reset_and_exit
bad_flags:
    mov $102, %edi
    jmp reset_and_exit
bad_standard_header:
    mov $103, %edi
    jmp reset_and_exit
bad_standard_xcomp:
    mov $104, %edi
    jmp reset_and_exit
bad_mxcsr:
    mov $105, %edi
    jmp reset_and_exit
bad_mxcsr_mask:
    mov $106, %edi
    jmp reset_and_exit
bad_x87:
    mov $107, %edi
    jmp reset_and_exit
bad_ymm:
    mov $108, %edi
    jmp reset_and_exit
bad_k:
    mov $109, %edi
    jmp reset_and_exit
bad_zmm:
    mov $110, %edi
    jmp reset_and_exit
bad_reserved:
    mov $111, %edi
    jmp reset_and_exit
bad_initial_header:
    mov $112, %edi
    jmp reset_and_exit
bad_initial_payload:
    mov $113, %edi
    jmp reset_and_exit
bad_optimized_header:
    mov $114, %edi
    jmp reset_and_exit
bad_optimized_payload:
    mov $115, %edi
    jmp reset_and_exit
bad_compact_header:
    mov $116, %edi
    jmp reset_and_exit
bad_roundtrip_state:
    mov $117, %edi
    jmp reset_and_exit
bad_pkru:
    mov $118, %edi
reset_and_exit:
    push %rdi
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    pop %rdi
exit_group:
    mov program_rsp(%rip), %rsp
    mov $231, %eax
    syscall

.section .rodata
.balign 16
seed_x87:
    .quad 0xc000000000000000
    .word 0x3fff                     /* 1.5 in 80-bit extended precision */
.balign 32
seed_ymm1:
    .quad 0x0123456789abcdef, 0xfedcba9876543210
    .quad 0x0f1e2d3c4b5a6978, 0x8877665544332211
.balign 64
seed_zmm2:
    .quad 0x0102030405060708, 0x1112131415161718
    .quad 0x2122232425262728, 0x3132333435363738
    .quad 0x4142434445464748, 0x5152535455565758
    .quad 0x6162636465666768, 0x7172737475767778
seed_zmm20:
    .quad 0x8070605040302010, 0x8171615141312111
    .quad 0x8272625242322212, 0x8373635343332313
    .quad 0x8474645444342414, 0x8575655545352515
    .quad 0x8676665646362616, 0x8777675747372717
initial_mxcsr:
    .long 0x1f80

.section .data
.balign 8
program_rsp:          .quad 0
operand_ptr:          .quad 0
safe_request:         .quad 0
nonrex_safe_request:  .quad 0
hostile_request:      .quad 0
nonrex_hostile_request: .quad 0
expected_bv:          .quad 0
expected_xcomp:       .quad 0
expected_flags:       .quad 0
observed_flags:       .quad 0
compact_cursor:       .quad 0
compact_offset2:      .quad 0
compact_offset5:      .quad 0
compact_offset6:      .quad 0
compact_offset7:      .quad 0
standard_offset2:     .quad 0
standard_offset5:     .quad 0
standard_offset6:     .quad 0
standard_offset7:     .quad 0
component_size2:      .quad 0
component_size5:      .quad 0
component_size6:      .quad 0
component_size7:      .quad 0
expected_gprs:        .zero 128
observed_gprs:        .zero 128
observed_xcr0:        .long 0
mxcsr_mask:           .long 0
live_mxcsr:           .long 0
observed_mxcsr:       .long 0
has_avx512:           .byte 0
image_fill:           .byte 0xa5
header_tail_fill:     .byte 0
expect_pointer_gaps:  .byte 0
expect_x87_payload:   .byte 1
.balign 64
layout_probe:         .zero 512
observed_ymm1:        .zero 32
observed_x87:         .zero 16
observed_zmm2:        .zero 64
observed_zmm20:       .zero 64

.section .bss
/* Padding makes standard_roundtrip-0x40 a safe temporary guest stack. */
.balign 64
    .skip 128
standard_roundtrip:   .skip 16384
.balign 64
standard_rmw:         .skip 16384
.balign 64
standard_initial:     .skip 16384
.balign 64
optimized_initial:    .skip 16384
.balign 64
optimized_live:       .skip 16384
.balign 64
compact_roundtrip:    .skip 16384
.balign 64
compact_live64:       .skip 16384
.balign 64
initial_source:       .skip 16384

.section .note.GNU-stack,"",@progbits
