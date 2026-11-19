// Snapshot RFLAGS, the fifteen non-RSP GPRs, the 512-byte FXSAVE image, and
// all sixteen 256-bit YMM registers before modifying them.
// The write exposes every full-width value to the host test:
//   [0..512)     FXSAVE64 area (FCW, FSW, FTW, FOP, FIP, FDP, MXCSR, ST0..7, XMM0..15)
//   [512..1024)  YMM0..YMM15 (32 bytes each: low 16 = XMM, high 16 = YMM upper)
//   [1024..1152) RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8..R15, RFLAGS
.global _start
.text
_start:
    pushfq
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    push %rbp
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rbx
    push %rax

    // Entry %rsp is 16-byte aligned; pushing 16 qwords (128 bytes) and
    // subtracting 1024 bytes keeps %rsp 16-byte aligned for fxsave64.
    sub $1024, %rsp
    fxsave64 0(%rsp)
    vmovdqu %ymm0, 512(%rsp)
    vmovdqu %ymm1, 544(%rsp)
    vmovdqu %ymm2, 576(%rsp)
    vmovdqu %ymm3, 608(%rsp)
    vmovdqu %ymm4, 640(%rsp)
    vmovdqu %ymm5, 672(%rsp)
    vmovdqu %ymm6, 704(%rsp)
    vmovdqu %ymm7, 736(%rsp)
    vmovdqu %ymm8, 768(%rsp)
    vmovdqu %ymm9, 800(%rsp)
    vmovdqu %ymm10, 832(%rsp)
    vmovdqu %ymm11, 864(%rsp)
    vmovdqu %ymm12, 896(%rsp)
    vmovdqu %ymm13, 928(%rsp)
    vmovdqu %ymm14, 960(%rsp)
    vmovdqu %ymm15, 992(%rsp)

    mov $1, %eax
    mov $1, %edi
    mov %rsp, %rsi
    mov $1152, %edx
    syscall

    cmp $1152, %rax
    je 1f
    mov $1, %edi
    mov $231, %eax
    syscall
1:
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
